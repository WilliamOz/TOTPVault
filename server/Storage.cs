using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace TotpVault.Server {
    public sealed class UserAccount {
        public int id { get; set; }
        public string guid { get; set; }
        public string username { get; set; }
        public string name { get; set; }
        public bool disabled { get; set; }
        public int version { get; set; }
    }

    public sealed class VaultToken {
        public int id { get; set; }
        public int owner { get; set; }
        public string name { get; set; }
        public string issuer { get; set; }
        public string algorithm { get; set; }
        public int digits { get; set; }
        public int period { get; set; }
        public int hide_code { get; set; }
        public string secret { get; set; }

        internal object Metadata() {
            return new { id, name, issuer, algorithm, digits, period, hide_code };
        }

        internal void Validate(bool creating) {
            name = (name ?? "").Trim();
            issuer = (issuer ?? "").Trim();
            if (name.Length < 1 || name.Length > 255 || issuer.Length > 255
                || (algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512")
                || (digits != 6 && digits != 8 && digits != 10) || period < 15 || period > 300
                || (hide_code != 0 && hide_code != 1)) throw new ApiError(400, "Dados do token inválidos.");
            if (creating || !string.IsNullOrWhiteSpace(secret)) {
                secret = new string((secret ?? "").Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
                Totp.Decode(secret);
                secret = secret.TrimEnd('=');
            } else {
                secret = null;
            }
        }
    }

    public sealed class AuditEntry {
        public string utc { get; set; }
        public int actor { get; set; }
        public int target { get; set; }
        public bool disabled { get; set; }
    }

    public sealed class VaultData {
        public int nextUser { get; set; }
        public int nextToken { get; set; }
        public List<UserAccount> users { get; set; }
        public List<VaultToken> tokens { get; set; }
        public List<AuditEntry> audit { get; set; }

        public VaultData() {
            nextUser = nextToken = 1;
            users = new List<UserAccount>();
            tokens = new List<VaultToken>();
            audit = new List<AuditEntry>();
        }
    }

    internal sealed class VaultStore {
        private readonly object gate = new object();
        private readonly string file;
        private readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 };
        private VaultData data;

        internal VaultStore(string root) {
            Directory.CreateDirectory(root);
            file = Path.Combine(root, "cofre.dat");
            data = File.Exists(file) ? Load() : new VaultData();
        }

        private VaultData Load() {
            byte[] raw = ProtectedData.Unprotect(File.ReadAllBytes(file), null, DataProtectionScope.LocalMachine);
            try {
                var value = json.Deserialize<VaultData>(Encoding.UTF8.GetString(raw));
                if (value == null || value.tokens == null || value.users == null || value.audit == null
                    || value.nextUser < 1 || value.nextToken < 1) throw new InvalidDataException("Cofre inválido.");
                return value;
            } finally {
                Array.Clear(raw, 0, raw.Length);
            }
        }

        private T Change<T>(Func<VaultData, T> apply) {
            lock (gate) {
                var next = json.Deserialize<VaultData>(json.Serialize(data));
                T result = apply(next);
                byte[] raw = Encoding.UTF8.GetBytes(json.Serialize(next));
                string temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try {
                    byte[] encrypted = ProtectedData.Protect(raw, null, DataProtectionScope.LocalMachine);
                    using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                        stream.Write(encrypted, 0, encrypted.Length);
                        stream.Flush(true);
                    }
                    if (File.Exists(file)) File.Replace(temp, file, file + ".bak");
                    else File.Move(temp, file);
                    data = next;
                    return result;
                } finally {
                    Array.Clear(raw, 0, raw.Length);
                    if (File.Exists(temp)) File.Delete(temp);
                }
            }
        }

        internal UserAccount SignIn(DirectoryUser identity) {
            lock (gate) {
                var old = data.users.Find(u => u.guid == identity.Guid);
                if (old != null && old.disabled) return null;
                if (old != null && old.username == identity.Username && old.name == identity.Name) return old;
                return Change(next => {
                    var user = next.users.Find(u => u.guid == identity.Guid);
                    if (user == null) {
                        user = new UserAccount { id = checked(next.nextUser++), guid = identity.Guid };
                        next.users.Add(user);
                    }
                    user.username = identity.Username;
                    user.name = identity.Name;
                    return user;
                });
            }
        }

        internal UserAccount Check(int id, int version) {
            lock (gate) {
                var user = data.users.Find(u => u.id == id);
                if (user == null || user.disabled || user.version != version) throw new ApiError(401, "Sessão encerrada.");
                return user;
            }
        }

        internal object[] Tokens(int owner, int version) {
            lock (gate) {
                Check(owner, version);
                return data.tokens.Where(t => t.owner == owner).OrderBy(t => t.name).Select(t => t.Metadata()).ToArray();
            }
        }

        internal VaultToken Token(int owner, int version, int id) {
            lock (gate) {
                Check(owner, version);
                var token = data.tokens.Find(t => t.owner == owner && t.id == id);
                if (token == null) throw new ApiError(404, "Token não encontrado.");
                return token;
            }
        }

        internal int SaveToken(int owner, int version, int id, VaultToken input) {
            input.Validate(id == 0);
            return Change(next => {
                Check(owner, version);
                if (id == 0) {
                    input.owner = owner;
                    input.id = checked(next.nextToken++);
                    next.tokens.Add(input);
                    return input.id;
                }
                var token = next.tokens.Find(t => t.owner == owner && t.id == id);
                if (token == null) throw new ApiError(404, "Token não encontrado.");
                input.owner = owner;
                input.id = id;
                if (input.secret == null) input.secret = token.secret;
                next.tokens[next.tokens.IndexOf(token)] = input;
                return id;
            });
        }

        internal void DeleteToken(int owner, int version, int id) {
            Change(next => {
                Check(owner, version);
                if (next.tokens.RemoveAll(t => t.owner == owner && t.id == id) != 1) {
                    throw new ApiError(404, "Token não encontrado.");
                }
                return true;
            });
        }

        internal object[] Users(int actor, int version) {
            lock (gate) {
                Check(actor, version);
                return data.users.OrderBy(u => u.name).Select(u => (object)new {
                    u.id, u.username, u.name, u.disabled, self = u.id == actor
                }).ToArray();
            }
        }

        internal void SetDisabled(int actor, int version, int target, bool disabled) {
            if (actor == target) throw new ApiError(400, "Sua própria conta não pode ser bloqueada.");
            Change(next => {
                Check(actor, version);
                var user = next.users.Find(u => u.id == target);
                if (user == null) throw new ApiError(404, "Usuário não encontrado.");
                if (user.disabled != disabled) {
                    user.disabled = disabled;
                    user.version = checked(user.version + 1);
                    next.audit.Add(new AuditEntry { utc = DateTime.UtcNow.ToString("o"), actor = actor, target = target, disabled = disabled });
                }
                return true;
            });
        }
    }

    internal static class Totp {
        private const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        internal static byte[] Decode(string text) {
            if (text == null || !System.Text.RegularExpressions.Regex.IsMatch(text, @"\A[A-Z2-7]{2,512}={0,6}\z")) {
                throw new ApiError(400, "Informe uma chave Base32 válida.");
            }
            var bytes = new List<byte>();
            int bits = 0, buffer = 0;
            foreach (char c in text.TrimEnd('=')) {
                buffer = (buffer << 5) | alphabet.IndexOf(c);
                bits += 5;
                if (bits >= 8) {
                    bits -= 8;
                    bytes.Add((byte)(buffer >> bits));
                }
            }
            return bytes.ToArray();
        }

        internal static object Code(VaultToken token, long now) {
            byte[] key = Decode(token.secret);
            byte[] counter = BitConverter.GetBytes(now / token.period);
            if (BitConverter.IsLittleEndian) Array.Reverse(counter);
            byte[] hash;
            try {
                using (HMAC hmac = token.algorithm == "SHA256" ? (HMAC)new HMACSHA256(key)
                    : token.algorithm == "SHA512" ? (HMAC)new HMACSHA512(key) : new HMACSHA1(key)) {
                    hash = hmac.ComputeHash(counter);
                }
            } finally {
                Array.Clear(key, 0, key.Length);
            }
            int offset = hash[hash.Length - 1] & 15;
            long number = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            long modulo = token.digits == 6 ? 1000000L : token.digits == 8 ? 100000000L : 10000000000L;
            return new { code = (number % modulo).ToString().PadLeft(token.digits, '0'), remaining = (int)(token.period - now % token.period) };
        }
    }
}
