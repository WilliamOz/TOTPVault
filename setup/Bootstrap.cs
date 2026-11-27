using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

[assembly: TargetFramework(".NETFramework,Version=v4.8")]

internal static class Bootstrap {
    private const string Resource = "totpvault-setup.zip";

    private static int Main(string[] args) {
        try {
            if (args.Length == 1 && args[0] == "--verify-payload") {
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource))
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Read)) {
                    foreach (var name in new[] { "Instalar.ps1", "implantacao.json", "TOTPVault-Servidor.exe", "TOTPVault.exe", "LICENSE" }) {
                        var entry = zip.GetEntry(name);
                        if (entry == null || entry.Length == 0) return 1;
                        Console.WriteLine(name + " " + entry.Length);
                    }
                }
                return 0;
            }

            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) {
                using (var process = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location) {
                    Verb = "runas", UseShellExecute = true
                })) {
                    process.WaitForExit();
                    return process.ExitCode;
                }
            }

            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TOTPVaultSetup-" + Guid.NewGuid().ToString("N"));
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (string account in new[] { "S-1-5-18", "S-1-5-32-544" }) {
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(account), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }
            Directory.CreateDirectory(directory, acl);
            try {
                string archive = Path.Combine(directory, "payload.zip");
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(Resource))
                using (var file = new FileStream(archive, FileMode.CreateNew)) stream.CopyTo(file);
                string payload = Path.Combine(directory, "payload");
                ZipFile.ExtractToDirectory(archive, payload);
                string path = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                using (var process = Process.Start(new ProcessStartInfo(path, "-NoProfile -ExecutionPolicy Bypass -File \"" +
                    Path.Combine(payload, "Instalar.ps1") + "\"") { UseShellExecute = false, WorkingDirectory = payload })) {
                    process.WaitForExit();
                    return process.ExitCode;
                }
            } finally {
                try { Directory.Delete(directory, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        } catch (Exception e) {
            Console.Error.WriteLine("Não foi possível iniciar o instalador (" + e.GetType().Name + ").");
            if (!Console.IsInputRedirected) Console.ReadLine();
            return 1;
        }
    }
}
