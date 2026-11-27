using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace TotpVault {
    internal sealed class StoredSession {
        internal readonly string Token;
        internal readonly DateTime ExpiresUtc;
        internal StoredSession(string token, DateTime expiresUtc) {
            Token = token;
            ExpiresUtc = expiresUtc;
        }
    }

    internal sealed class SessionCache {
        private readonly string path;
        private readonly string mutexName;
        private readonly byte[] entropy;

        internal SessionCache(string folder, string serverUrl, string certificateSha256) {
            if (string.IsNullOrWhiteSpace(folder)) throw new ArgumentException("Pasta da sessão inválida.");
            using (var sha = SHA256.Create()) {
                entropy = sha.ComputeHash(Encoding.UTF8.GetBytes("TOTPVault/session/v1\n" + serverUrl + "\n" + certificateSha256));
                string name = BitConverter.ToString(entropy).Replace("-", "");
                path = Path.Combine(folder, "sessao-" + name + ".dat");
                string lockKey = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant()))).Replace("-", "");
                mutexName = @"Local\TOTPVault-Session-" + lockKey;
            }
        }

        internal static bool IsToken(string value) {
            return value != null && Regex.IsMatch(value, @"\A[a-f0-9]{64}\z");
        }

        internal StoredSession Load() {
            return Access<StoredSession>(() => {
                var record = Read();
                if (record != null && record.ExpiresUtc > DateTime.UtcNow) return record;
                File.Delete(path);
                return null;
            }, null);
        }

        internal bool Save(StoredSession record) {
            if (record == null || !IsToken(record.Token) || record.ExpiresUtc <= DateTime.UtcNow) return false;
            return Access(() => {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                byte[] raw = new byte[72];
                Buffer.BlockCopy(BitConverter.GetBytes(record.ExpiresUtc.Ticks), 0, raw, 0, 8);
                Encoding.ASCII.GetBytes(record.Token, 0, 64, raw, 8);
                try {
                    byte[] sealedData = ProtectedData.Protect(raw, entropy, DataProtectionScope.CurrentUser);
                    using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                        stream.Write(sealedData, 0, sealedData.Length);
                        stream.Flush(true);
                    }
                    if (File.Exists(path)) File.Replace(temp, path, null);
                    else File.Move(temp, path);
                    return true;
                } finally {
                    Array.Clear(raw, 0, raw.Length);
                    File.Delete(temp);
                }
            }, false);
        }

        internal bool Clear(string token) {
            if (!IsToken(token)) return false;
            return Access(() => {
                var record = Read();
                if (record != null && !string.Equals(record.Token, token, StringComparison.Ordinal)) return true;
                File.Delete(path);
                return true;
            }, false);
        }

        private StoredSession Read() {
            var file = new FileInfo(path);
            if (!file.Exists || file.Length == 0 || file.Length > 4096) return null;
            byte[] raw = ProtectedData.Unprotect(File.ReadAllBytes(path), entropy, DataProtectionScope.CurrentUser);
            try {
                if (raw.Length != 72) return null;
                long ticks = BitConverter.ToInt64(raw, 0);
                string token = Encoding.ASCII.GetString(raw, 8, 64);
                if (!IsToken(token) || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return null;
                return new StoredSession(token, new DateTime(ticks, DateTimeKind.Utc));
            } finally {
                Array.Clear(raw, 0, raw.Length);
            }
        }

        private T Access<T>(Func<T> operation, T failure) {
            try {
                using (var mutex = new Mutex(false, mutexName)) {
                    bool acquired;
                    try { acquired = mutex.WaitOne(1500); }
                    catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) return failure;
                    try { return operation(); }
                    finally { mutex.ReleaseMutex(); }
                }
            } catch (IOException) { return failure; }
            catch (UnauthorizedAccessException) { return failure; }
            catch (CryptographicException) { return failure; }
        }
    }
}
