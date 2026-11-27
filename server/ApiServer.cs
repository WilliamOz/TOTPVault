using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace TotpVault.Server {
    internal sealed class ApiError : Exception {
        internal readonly int Status;
        internal ApiError(int status, string message) : base(message) { Status = status; }
    }

    internal sealed class Session {
        internal string Id;
        internal string Csrf;
        internal int UserId;
        internal int Version;
        internal bool Admin;
        internal DateTime Expires;
        internal DateTime DirectoryChecked;
    }

    internal sealed class SessionBook {
        private readonly object gate = new object();
        private readonly Dictionary<string, Session> sessions = new Dictionary<string, Session>(StringComparer.Ordinal);
        private readonly Dictionary<string, int> attempts = new Dictionary<string, int>();
        private DateTime nextCleanup;
        private long attemptWindow;

        internal Session Get(string id) {
            if (id == null || id.Length != 64) return null;
            lock (gate) {
                Session session;
                return sessions.TryGetValue(id, out session) && session.Expires > DateTime.UtcNow ? session : null;
            }
        }

        internal Session New(UserAccount user = null, bool admin = false) {
            lock (gate) {
                DateTime now = DateTime.UtcNow;
                if (nextCleanup <= now) {
                    foreach (string id in sessions.Where(x => x.Value.Expires <= now).Select(x => x.Key).ToArray()) sessions.Remove(id);
                    nextCleanup = now.AddMinutes(1);
                }
                if (sessions.Count >= 10000) throw new ApiError(503, "Limite de sessões atingido.");
                var record = new Session {
                    Id = RandomHex(), Csrf = RandomHex(),
                    UserId = user == null ? 0 : user.id, Version = user == null ? 0 : user.version,
                    Admin = admin, Expires = user == null ? now.AddMinutes(5) : now.AddHours(8), DirectoryChecked = now
                };
                sessions.Add(record.Id, record);
                return record;
            }
        }

        internal void Remove(Session session) {
            if (session != null) lock (gate) { sessions.Remove(session.Id); }
        }

        internal void CheckLogin(string address, string username) {
            lock (gate) {
                long window = DateTime.UtcNow.Ticks / TimeSpan.FromMinutes(5).Ticks;
                if (attemptWindow != window) {
                    attempts.Clear();
                    attemptWindow = window;
                }
                if (!Increment("ip:" + address, 60) || !Increment("user:" + username.ToUpperInvariant(), 8)) {
                    throw new ApiError(429, "Muitas tentativas. Aguarde alguns minutos.");
                }
            }
        }

        private bool Increment(string key, int limit) {
            int count;
            if (!attempts.TryGetValue(key, out count) && attempts.Count >= 30000) return false;
            if (count >= limit) return false;
            attempts[key] = count + 1;
            return true;
        }

        private static string RandomHex() {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }

    internal sealed class ApiServer : IDisposable {
        private const string CookieName = "__Host-TOTPVault";
        private readonly HttpListener listener = new HttpListener();
        private readonly SemaphoreSlim slots = new SemaphoreSlim(48);
        private readonly SessionBook sessions = new SessionBook();
        private readonly IUserDirectory directory;
        private readonly VaultStore vault;
        private readonly Action<Exception> log;

        internal ApiServer(string prefix, VaultStore vault, IUserDirectory directory, Action<Exception> log) {
            listener.Prefixes.Add(prefix);
            this.vault = vault;
            this.directory = directory;
            this.log = log;
        }

        internal void Start() {
            listener.Start();
            listener.TimeoutManager.EntityBody = TimeSpan.FromSeconds(10);
            listener.TimeoutManager.HeaderWait = TimeSpan.FromSeconds(10);
            Task.Run((Action)Listen);
        }

        private void Listen() {
            try {
                for (;;) {
                    var context = listener.GetContext();
                    if (!slots.Wait(0)) {
                        context.Response.StatusCode = 503;
                        context.Response.Close();
                        continue;
                    }
                    Task.Run(() => {
                        try { Handle(context); }
                        finally { slots.Release(); }
                    });
                }
            } catch (HttpListenerException e) {
                if (listener.IsListening) log(e);
            } catch (ObjectDisposedException) {}
        }

        private void Handle(HttpListenerContext context) {
            var response = context.Response;
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["X-Content-Type-Options"] = "nosniff";
            response.Headers["Referrer-Policy"] = "no-referrer";
            try {
                Route(context);
            } catch (ApiError e) {
                TryWrite(response, new { error = e.Message }, e.Status);
            } catch (Exception e) {
                log(e);
                TryWrite(response, new { error = "Serviço temporariamente indisponível." }, 503);
            } finally {
                response.Close();
            }
        }

        private void Route(HttpListenerContext context) {
            var req = context.Request;
            var resp = context.Response;
            if (!req.IsSecureConnection) throw new ApiError(400, "HTTPS obrigatório.");
            string path = req.Url.AbsolutePath;
            string verb = req.HttpMethod;
            if ((path == "/healthz" || path == "/") && verb == "GET") {
                Write(resp, new { service = "TOTPVault", status = "ok" });
                return;
            }
            string key = req.Cookies[CookieName] == null ? null : req.Cookies[CookieName].Value;
            Session session = sessions.Get(key);

            if (path == "/api/session" && verb == "GET") {
                if (session == null) {
                    session = sessions.New();
                    Issue(resp, session.Id);
                }
                var user = session.UserId == 0 ? null : Current(session, false);
                Write(resp, new { csrf = session.Csrf, username = user == null ? null : user.username, admin = user != null && session.Admin });
                return;
            }

            if (path == "/api/session/login" && verb == "POST") {
                CheckCsrf(req, session);
                var login = Read<Login>(req);
                if (login.username == null || !Regex.IsMatch(login.username, @"\A[^\s\p{C}@\\\/]{1,80}\z")
                    || string.IsNullOrEmpty(login.password) || login.password.Length > 1024) {
                    throw new ApiError(401, "Credenciais inválidas.");
                }
                sessions.CheckLogin(req.RemoteEndPoint.Address.ToString(), login.username);
                var identity = directory.Authenticate(login.username, login.password);
                var user = identity == null ? null : vault.SignIn(identity);
                if (user == null) throw new ApiError(401, "Credenciais ou acesso inválidos.");
                sessions.Remove(session);
                var authenticated = sessions.New(user, identity.Admin);
                Issue(resp, authenticated.Id);
                Write(resp, new { csrf = authenticated.Csrf, username = user.username, admin = authenticated.Admin });
                return;
            }

            bool adminRoute = path.StartsWith("/api/admin/", StringComparison.Ordinal);
            Current(session, adminRoute);
            int owner = session.UserId, version = session.Version;
            if (adminRoute && !session.Admin) throw new ApiError(403, "Acesso restrito a administradores.");
            if (verb != "GET") CheckCsrf(req, session);

            if (path == "/api/session" && verb == "DELETE") {
                sessions.Remove(session);
                resp.Headers.Add("Set-Cookie", CookieName + "=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict");
                resp.StatusCode = 204;
                return;
            }
            if (path == "/api/profiles") {
                if (verb == "GET") { Write(resp, vault.Tokens(owner, version)); return; }
                if (verb == "POST") {
                    int saved = vault.SaveToken(owner, version, 0, Read<VaultToken>(req));
                    Write(resp, new { id = saved }, 201);
                    return;
                }
            }
            int id;
            if (path == "/api/otp" && verb == "GET" && PositiveId(req.QueryString["id"], out id)) {
                Write(resp, Totp.Code(vault.Token(owner, version, id), DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
                return;
            }
            if (ReadId(path, "/api/profiles/", out id)) {
                if (verb == "GET") { Write(resp, vault.Token(owner, version, id).Metadata()); return; }
                if (verb == "PUT") {
                    vault.SaveToken(owner, version, id, Read<VaultToken>(req));
                    Write(resp, new { success = true });
                    return;
                }
                if (verb == "DELETE") {
                    vault.DeleteToken(owner, version, id);
                    resp.StatusCode = 204;
                    return;
                }
            }
            if (path == "/api/admin/users" && verb == "GET") {
                Write(resp, vault.Users(owner, version));
                return;
            }
            if (verb == "POST" && ReadId(path, "/api/admin/users/", out id)) {
                var update = Read<AccessUpdate>(req);
                if (!update.disabled.HasValue) throw new ApiError(400, "Informe o estado de acesso.");
                vault.SetDisabled(owner, version, id, update.disabled.Value);
                resp.StatusCode = 204;
                return;
            }
            throw new ApiError(404, "Recurso não encontrado.");
        }

        private UserAccount Current(Session session, bool fresh) {
            if (session == null || session.UserId == 0 || session.Expires <= DateTime.UtcNow) {
                throw new ApiError(401, "Sessão encerrada.");
            }
            var user = vault.Check(session.UserId, session.Version);
            lock (session) {
                DateTime now = DateTime.UtcNow;
                if (fresh || session.DirectoryChecked.AddSeconds(60) <= now) {
                    var identity = directory.Find(user.guid);
                    if (identity == null) {
                        sessions.Remove(session);
                        throw new ApiError(401, "Sua conta não tem mais acesso.");
                    }
                    session.Admin = identity.Admin;
                    session.DirectoryChecked = now;
                }
            }
            return vault.Check(session.UserId, session.Version);
        }

        private static void CheckCsrf(HttpListenerRequest request, Session session) {
            string supplied = request.Headers["X-CSRF-Token"];
            if (session == null || supplied == null || supplied.Length != session.Csrf.Length) {
                throw new ApiError(403, "Solicitação inválida.");
            }
            int diff = 0;
            for (int i = 0; i < supplied.Length; i++) diff |= supplied[i] ^ session.Csrf[i];
            if (diff != 0) throw new ApiError(403, "Solicitação inválida.");
        }

        private static T Read<T>(HttpListenerRequest request) where T : class {
            const int maximum = 16384;
            if (request.ContentType == null || !request.ContentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase)) {
                throw new ApiError(415, "Envie dados em JSON.");
            }
            if (request.ContentLength64 > maximum) throw new ApiError(413, "Dados grandes demais.");
            using (var body = new MemoryStream()) {
                byte[] buf = new byte[2048];
                try {
                    int length;
                    while ((length = request.InputStream.Read(buf, 0, buf.Length)) > 0) {
                        if (body.Length + length > maximum) throw new ApiError(413, "Dados grandes demais.");
                        body.Write(buf, 0, length);
                    }
                    var value = Serializer().Deserialize<T>(new UTF8Encoding(false, true).GetString(body.GetBuffer(), 0, (int)body.Length));
                    if (value == null) throw new ApiError(400, "Dados inválidos.");
                    return value;
                } catch (ArgumentException) {
                    throw new ApiError(400, "Dados inválidos.");
                } catch (InvalidOperationException) {
                    throw new ApiError(400, "Dados inválidos.");
                } finally {
                    Array.Clear(buf, 0, buf.Length);
                    if (body.Capacity > 0) Array.Clear(body.GetBuffer(), 0, body.Capacity);
                }
            }
        }

        private static JavaScriptSerializer Serializer() {
            return new JavaScriptSerializer { RecursionLimit = 16, MaxJsonLength = 4 * 1024 * 1024 };
        }

        private static bool PositiveId(string input, out int id) {
            return int.TryParse(input, NumberStyles.None, CultureInfo.InvariantCulture, out id) && id > 0;
        }

        private static bool ReadId(string path, string prefix, out int id) {
            id = 0;
            return path.StartsWith(prefix, StringComparison.Ordinal) && PositiveId(path.Substring(prefix.Length), out id);
        }

        private static void Issue(HttpListenerResponse response, string sessionId) {
            response.Headers.Add("Set-Cookie", CookieName + "=" + sessionId + "; Path=/; Secure; HttpOnly; SameSite=Strict");
        }

        private static void Write(HttpListenerResponse response, object payload, int status = 200) {
            byte[] bytes = Encoding.UTF8.GetBytes(Serializer().Serialize(payload));
            response.StatusCode = status;
            response.ContentType = "application/json; charset=utf-8";
            response.ContentLength64 = bytes.Length;
            response.OutputStream.Write(bytes, 0, bytes.Length);
        }

        private static void TryWrite(HttpListenerResponse response, object payload, int status) {
            try { Write(response, payload, status); } catch (HttpListenerException) { } catch (InvalidOperationException) { } catch (IOException) { }
        }

        public void Dispose() { listener.Close(); }

        public sealed class Login {
            public string username { get; set; }
            public string password { get; set; }
        }

        public sealed class AccessUpdate {
            public bool? disabled { get; set; }
        }
    }
}
