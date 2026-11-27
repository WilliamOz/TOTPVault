using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace TotpVault {
    internal sealed class VaultApi : IDisposable {
        private const string SessionCookie = "__Host-TOTPVault";
        private readonly HttpClient http;
        private readonly CookieContainer cookies = new CookieContainer();
        private readonly JavaScriptSerializer json = new JavaScriptSerializer();
        private string csrf;
        internal bool CanAdmin { get; private set; }

        internal static Uri ParseServer(string value) {
            Uri uri;
            if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out uri)
                || uri.Scheme != Uri.UriSchemeHttps || string.IsNullOrEmpty(uri.Host)
                || uri.UserInfo.Length != 0 || uri.Query.Length != 0
                || uri.Fragment.Length != 0 || uri.AbsolutePath != "/") {
                throw new ArgumentException("Informe o endereço HTTPS do cofre, sem caminho ou parâmetros.");
            }
            return uri;
        }

        internal VaultApi(Uri server, string certificateSha256 = "") {
            var handler = new HttpClientHandler {
                CookieContainer = cookies,
                AllowAutoRedirect = false,
                UseProxy = false,
                UseDefaultCredentials = false
            };
            if (!string.IsNullOrEmpty(certificateSha256)) {
                handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) =>
                    MatchesServerCertificate(server, request.RequestUri, certificate, chain, errors, certificateSha256);
            }
            http = new HttpClient(handler) {
                BaseAddress = server,
                Timeout = TimeSpan.FromSeconds(15),
                MaxResponseContentBufferSize = 4 * 1024 * 1024
            };
            http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        }

        internal static bool MatchesServerCertificate(Uri server, Uri request, X509Certificate2 certificate,
            X509Chain chain, SslPolicyErrors errors, string certificateSha256) {
            if (request == null || request.Scheme != Uri.UriSchemeHttps || request.Port != server.Port
                || !string.Equals(request.IdnHost, server.IdnHost, StringComparison.OrdinalIgnoreCase)
                || certificate == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0) {
                return false;
            }
            var now = DateTime.UtcNow;
            if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now) {
                return false;
            }
            if (errors == SslPolicyErrors.RemoteCertificateChainErrors) {
                // The verified self-signed certificate can be absent from the Windows root store.
                // Distrust, revocation and all other certificate errors still fail.
                if (chain == null || chain.ChainStatus.Length == 0) return false;
                foreach (var status in chain.ChainStatus) {
                    if ((status.Status & ~X509ChainStatusFlags.UntrustedRoot) != 0) return false;
                }
            }
            using (var sha256 = SHA256.Create()) {
                var fingerprint = BitConverter.ToString(sha256.ComputeHash(certificate.RawData)).Replace("-", "");
                return string.Equals(fingerprint, certificateSha256, StringComparison.OrdinalIgnoreCase);
            }
        }

        internal async Task<string> Login(string username, string password) {
            csrf = (await Send<SessionInfo>(HttpMethod.Get, "api/session")).csrf;
            var session = await Send<SessionInfo>(HttpMethod.Post, "api/session/login", new { username, password });
            csrf = session.csrf;
            CanAdmin = session.admin;
            return session.username;
        }

        internal string SessionToken {
            get {
                var cookie = cookies.GetCookies(http.BaseAddress)[SessionCookie];
                return cookie != null && SessionCache.IsToken(cookie.Value) ? cookie.Value : null;
            }
        }

        internal async Task<string> Restore(string token) {
            if (!SessionCache.IsToken(token)) return null;
            cookies.Add(http.BaseAddress, new Cookie(SessionCookie, token, "/") { Secure = true, HttpOnly = true });
            var session = await GetSession();
            if (string.IsNullOrEmpty(session.username) || string.IsNullOrEmpty(session.csrf)) return null;
            csrf = session.csrf;
            CanAdmin = session.admin;
            return session.username;
        }

        internal Task<SessionInfo> GetSession() {
            return Send<SessionInfo>(HttpMethod.Get, "api/session");
        }

        internal Task<TokenInfo[]> ListTokens() {
            return Send<TokenInfo[]>(HttpMethod.Get, "api/profiles");
        }

        internal Task<CodeInfo> GetCode(int id) {
            return Send<CodeInfo>(HttpMethod.Get, "api/otp?id=" + id);
        }

        internal Task<object> SaveToken(TokenInfo token, string secret) {
            var body = new {
                token.name, token.issuer, token.algorithm, token.digits, token.period, token.hide_code, secret
            };
            return token.id == 0
                ? Send<object>(HttpMethod.Post, "api/profiles", body)
                : Send<object>(HttpMethod.Put, "api/profiles/" + token.id, body);
        }

        internal Task<object> DeleteToken(int id) {
            return Send<object>(HttpMethod.Delete, "api/profiles/" + id);
        }

        internal Task<object> Logout() {
            return Send<object>(HttpMethod.Delete, "api/session");
        }

        internal Task<AccountInfo[]> ListAccounts() {
            return Send<AccountInfo[]>(HttpMethod.Get, "api/admin/users");
        }

        internal Task<object> SetDisabled(int id, bool disabled) {
            return Send<object>(HttpMethod.Post, "api/admin/users/" + id, new { disabled });
        }

        private async Task<T> Send<T>(HttpMethod method, string path, object payload = null) {
            using (var request = new HttpRequestMessage(method, path)) {
                if (method != HttpMethod.Get) {
                    if (string.IsNullOrEmpty(csrf)) throw new InvalidOperationException("Sessão inválida.");
                    request.Headers.Add("X-CSRF-Token", csrf);
                }
                if (payload != null) {
                    request.Content = new StringContent(json.Serialize(payload), Encoding.UTF8, "application/json");
                }
                using (var response = await http.SendAsync(request)) {
                    if (!response.IsSuccessStatusCode) throw new VaultException((int)response.StatusCode);
                    if (response.StatusCode == HttpStatusCode.NoContent) return default(T);
                    if (response.Content.Headers.ContentType == null
                        || response.Content.Headers.ContentType.MediaType != "application/json") {
                        throw new InvalidOperationException("O endereço informado não respondeu como servidor TOTPVault.");
                    }
                    var value = json.Deserialize<T>(await response.Content.ReadAsStringAsync());
                    if (value == null) throw new InvalidOperationException("Resposta inválida do servidor.");
                    return value;
                }
            }
        }

        public void Dispose() { http.Dispose(); }
    }

    internal sealed class VaultException : Exception {
        internal int Status { get; private set; }

        internal VaultException(int status) { Status = status; }
    }

    public sealed class SessionInfo {
        public string csrf { get; set; }
        public string username { get; set; }
        public bool admin { get; set; }
    }

    public sealed class AccountInfo {
        public int id { get; set; }
        public string username { get; set; }
        public string name { get; set; }
        public bool disabled { get; set; }
        public bool self { get; set; }
    }

    public sealed class TokenInfo {
        public int id { get; set; }
        public string name { get; set; }
        public string issuer { get; set; }
        public string algorithm { get; set; }
        public int digits { get; set; }
        public int period { get; set; }
        public int hide_code { get; set; }
        public string Title { get { return string.IsNullOrEmpty(issuer) ? name : name + "  ·  " + issuer; } }
    }

    public sealed class CodeInfo {
        public string code { get; set; }
        public int remaining { get; set; }
    }
}
