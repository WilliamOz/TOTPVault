using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Web.Script.Serialization;

[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace TotpVault.Server {
    internal static class Program {
        private static string root;

        private static int Main(string[] args) {
            if (args.Length == 3 && args[0] == "--health") {
                return CheckHealth(args[1], args[2]) ? 0 : 1;
            }
            if (args.Length != 2 || (args[0] != "--probe" && args[0] != "--portable")) {
                Console.WriteLine("Uso: TOTPVault-Servidor.exe --portable \"C:\\TOTPVault\\dados\"");
                return 2;
            }
            root = Path.GetFullPath(args[1]);
            bool probe = args.Length == 2 && args[0] == "--probe";
            try {
                if (probe) {
                    Console.WriteLine(new ActiveDirectory(ReadConfig()).Probe());
                } else {
                    var settings = ReadConfig();
                    using (var owner = File.Open(Path.Combine(root, "servidor.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                    using (var server = Open(settings)) {
                        Console.WriteLine("TOTPVault em execução.");
                        using (var stop = new ManualResetEvent(false)) {
                            if (Environment.UserInteractive) {
                                Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop.Set(); };
                            }
                            stop.WaitOne();
                        }
                    }
                }
                return 0;
            } catch (LdapException e) {
                if (probe) Console.Error.WriteLine("Falha no LDAPS. Código Windows LDAP: " + e.ErrorCode + ".");
                else Report(e);
                return 1;
            } catch (DirectoryOperationException e) {
                if (probe) Console.Error.WriteLine("Falha ao consultar o AD. Código LDAP: " + (e.Response == null ? "indisponível" : e.Response.ResultCode.ToString()) + ".");
                else Report(e);
                return 1;
            } catch (Exception e) {
                if (probe) Console.Error.WriteLine("Falha de configuração: " + e.GetType().Name + ".");
                else Report(e);
                return 1;
            }
        }

        private static bool CheckHealth(string endpoint, string thumbprint) {
            try {
                var request = WebRequest.CreateHttp(endpoint);
                if (request.RequestUri.Scheme != Uri.UriSchemeHttps) return false;
                request.AllowAutoRedirect = false;
                request.Proxy = null;
                request.Timeout = 3000;
                // Setup knows the exact certificate selected from the local Windows store.
                request.ServerCertificateValidationCallback = (sender, cert, chain, errors) => {
                    if (cert == null || (errors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0
                        || !string.Equals(cert.GetCertHashString(), thumbprint, StringComparison.OrdinalIgnoreCase)) return false;
                    using (var selected = new X509Certificate2(cert)) {
                        var now = DateTime.Now;
                        return selected.NotBefore <= now && selected.NotAfter > now;
                    }
                };
                using (var response = (HttpWebResponse)request.GetResponse()) {
                    return response.StatusCode == HttpStatusCode.OK && response.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase);
                }
            } catch (Exception) {
                return false;
            }
        }

        private static ServerConfig ReadConfig() {
            string path = Path.Combine(root, "servidor.json");
            var settings = new JavaScriptSerializer().Deserialize<ServerConfig>(File.ReadAllText(path));
            settings.Validate();
            return settings;
        }

        private static ApiServer Open(ServerConfig settings) {
            var directory = new ActiveDirectory(settings);
            var server = new ApiServer(settings.Prefix, new VaultStore(root), directory, Log);
            try {
                server.Start();
                return server;
            } catch {
                server.Dispose();
                throw;
            }
        }

        private static readonly object LogGate = new object();

        private static void Log(Exception exception) {
            try {
                lock (LogGate) {
                    string path = Path.Combine(root, "servico.log");
                    if (File.Exists(path) && new FileInfo(path).Length > 1024 * 1024) {
                        File.Delete(path + ".old");
                        File.Move(path, path + ".old");
                    }
                    File.AppendAllText(path, DateTime.UtcNow.ToString("o") + " " + exception.GetType().Name + "\r\n");
                }
            } catch (IOException) {} catch (UnauthorizedAccessException) {}
        }

        private static void Report(Exception failure) {
            Console.Error.WriteLine("Falha ao iniciar o TOTPVault: " + failure.GetType().Name + ". Confira dados/servico.log.");
            Log(failure);
        }
    }
}
