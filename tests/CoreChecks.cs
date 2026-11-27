using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using TotpVault.Server;

internal static class CoreChecks {
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

    private static void Require(bool value, string label) {
        if (!value) throw new InvalidOperationException(label);
    }

    private static void Expect(int status, Action action) {
        try { action(); }
        catch (ApiError e) { Require(e.Status == status, "Unexpected status."); return; }
        throw new InvalidOperationException("Expected denial.");
    }

    private static DirectoryUser Identity(string id, string username) {
        return new DirectoryUser { Guid = id.PadLeft(32, '0'), Username = username, Name = username };
    }

    private static void Main(string[] args) {
        var vault = new VaultStore(args[0]);
        var alice = vault.SignIn(Identity("1", "alice"));
        var admin = vault.SignIn(Identity("2", "administrator"));
        var subject = new VaultToken { name = "conta de laboratório", issuer = "teste", secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            algorithm = "SHA1", digits = 8, period = 30 };
        int id = vault.SaveToken(alice.id, alice.version, 0, subject);
        Require(Json.Serialize(Totp.Code(subject, 59)).Contains("94287082"), "RFC 6238 vector");
        Require(!Json.Serialize(vault.Tokens(alice.id, alice.version)).Contains(subject.secret), "token metadata exposes a seed");
        Expect(404, () => vault.Token(admin.id, admin.version, id));
        Expect(404, () => vault.DeleteToken(admin.id, admin.version, id));
        Require(vault.Users(admin.id, admin.version).Length == 2, "user panel list");
        Expect(400, () => vault.SetDisabled(admin.id, admin.version, admin.id, true));
        vault.SetDisabled(admin.id, admin.version, alice.id, true);
        Expect(401, () => vault.Token(alice.id, alice.version, id));
        Require(vault.SignIn(Identity("1", "alice")) == null, "disabled account login");
        vault.SetDisabled(admin.id, admin.version, alice.id, false);
        Expect(401, () => vault.Token(alice.id, alice.version, id));
        var renamed = vault.SignIn(Identity("1", "alice-renamed"));
        Require(renamed.id == alice.id, "AD objectGUID identity");
        var fresh = new VaultStore(args[0]);
        Require(fresh.Token(renamed.id, renamed.version, id).name == subject.name, "DPAPI persist and decrypt");
        string bytes = Encoding.ASCII.GetString(File.ReadAllBytes(Path.Combine(args[0], "cofre.dat")));
        Require(!bytes.Contains(subject.secret) && !bytes.Contains(subject.name), "stored plaintext");
        var sessions = new SessionBook();
        var started = sessions.New();
        var finished = sessions.New(renamed, false);
        Require(started.Id != finished.Id && started.Csrf != finished.Csrf, "session token rotation");
        sessions.Remove(finished);
        Require(sessions.Get(finished.Id) == null, "session deletion");
        for (int i = 0; i < 8; i++) sessions.CheckLogin("127.0.0.1", "fixture");
        Expect(429, () => sessions.CheckLogin("127.0.0.1", "FIXTURE"));
        Console.WriteLine("Windows DPAPI, TOTP RFC 6238, ownership, AD GUID, disable/enable, session rotation and limits OK.");
    }
}
