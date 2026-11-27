using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TotpVault.Server {
    public sealed class ServerConfig {
        public string BindIp { get; set; }
        public int Port { get; set; }
        public string AdHost { get; set; }
        public int AdPort { get; set; }
        public string BaseDn { get; set; }
        public string BindIdentity { get; set; }
        public string ProtectedBindPassword { get; set; }
        public string AdminGroupDn { get; set; }
        public string AccessGroupDn { get; set; }

        internal void Validate() {
            IPAddress address;
            if (!IPAddress.TryParse(BindIp, out address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || Port < 1 || Port > 65535 || AdPort < 1 || AdPort > 65535
                || Uri.CheckHostName(AdHost ?? "") != UriHostNameType.Dns || !AdHost.Contains(".")
                || string.IsNullOrWhiteSpace(BindIdentity) || string.IsNullOrWhiteSpace(ProtectedBindPassword)
                || string.IsNullOrWhiteSpace(AdminGroupDn)) {
                throw new InvalidOperationException("Configuração do servidor incompleta.");
            }
        }

        internal string Prefix { get { return "https://" + BindIp + ":" + Port + "/"; } }
    }

    internal sealed class DirectoryUser {
        internal string Guid { get; set; }
        internal string Username { get; set; }
        internal string Name { get; set; }
        internal bool Admin { get; set; }
    }

    internal interface IUserDirectory {
        DirectoryUser Authenticate(string username, string password);
        DirectoryUser Find(string guid);
    }

    internal sealed class ActiveDirectory : IUserDirectory {
        private readonly ServerConfig config;
        internal ActiveDirectory(ServerConfig config) { this.config = config; }

        internal string Probe() {
            using (var ldap = ConnectService()) {
                string root = BaseDn(ldap);
                var scope = new SearchRequest(root, "(objectClass=*)", SearchScope.Base, "distinguishedName");
                if (((SearchResponse)ldap.SendRequest(scope)).Entries.Count != 1) {
                    throw new InvalidOperationException("A base do AD não é legível pela conta de serviço.");
                }
                CheckGroup(ldap, config.AdminGroupDn);
                if (!string.IsNullOrWhiteSpace(config.AccessGroupDn)) CheckGroup(ldap, config.AccessGroupDn);
                return root;
            }
        }

        public DirectoryUser Authenticate(string username, string password) {
            if (string.IsNullOrEmpty(password) || password.Length > 1024 || password.IndexOf('\0') >= 0) return null;
            using (var ldap = ConnectService()) {
                var entry = Search(ldap, "sAMAccountName", Encoding.UTF8.GetBytes(username));
                var identity = Authorize(ldap, entry);
                if (identity == null) return null;
                try {
                    using (Connect(new NetworkCredential(entry.DistinguishedName, password))) { }
                } catch (LdapException e) {
                    if (e.ErrorCode == 49) return null;
                    throw;
                }
                return identity;
            }
        }

        public DirectoryUser Find(string guid) {
            using (var ldap = ConnectService()) {
                byte[] key = Enumerable.Range(0, 16).Select(i => Convert.ToByte(guid.Substring(i * 2, 2), 16)).ToArray();
                return Authorize(ldap, Search(ldap, "objectGUID", key));
            }
        }

        private LdapConnection ConnectService() {
            byte[] password = ProtectedData.Unprotect(Convert.FromBase64String(config.ProtectedBindPassword), null,
                DataProtectionScope.LocalMachine);
            try {
                return Connect(new NetworkCredential(config.BindIdentity, Encoding.UTF8.GetString(password)));
            } finally {
                Array.Clear(password, 0, password.Length);
            }
        }

        private LdapConnection Connect(NetworkCredential credential) {
            var identifier = new LdapDirectoryIdentifier(config.AdHost, config.AdPort, true, false);
            var ldap = new LdapConnection(identifier, credential, AuthType.Basic);
            try {
                ldap.Timeout = TimeSpan.FromSeconds(6);
                ldap.SessionOptions.ProtocolVersion = 3;
                ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                // WinLDAP uses the operating system's certificate validation. No validation callback overrides it.
                ldap.SessionOptions.SecureSocketLayer = true;
                ldap.Bind();
                return ldap;
            } catch {
                ldap.Dispose();
                throw;
            }
        }

        private string BaseDn(LdapConnection ldap) {
            if (!string.IsNullOrWhiteSpace(config.BaseDn)) return config.BaseDn;
            var request = new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
            var response = (SearchResponse)ldap.SendRequest(request);
            var value = response.Entries.Count == 1 ? Text(response.Entries[0], "defaultNamingContext") : null;
            if (string.IsNullOrEmpty(value)) throw new InvalidOperationException("Base padrão do AD indisponível.");
            return value;
        }

        private static void CheckGroup(LdapConnection ldap, string dn) {
            var request = new SearchRequest(dn, "(objectClass=group)", SearchScope.Base, "distinguishedName");
            if (((SearchResponse)ldap.SendRequest(request)).Entries.Count != 1) {
                throw new InvalidOperationException("Um grupo configurado não está visível no AD.");
            }
        }

        private SearchResultEntry Search(LdapConnection ldap, string attribute, byte[] value) {
            var escaped = string.Concat(value.Select(b => "\\" + b.ToString("X2")));
            var filter = "(&(objectClass=user)(objectCategory=person)(" + attribute + "=" + escaped + "))";
            var request = new SearchRequest(BaseDn(ldap), filter, SearchScope.Subtree,
                "objectGUID", "sAMAccountName", "displayName", "userAccountControl", "accountExpires");
            request.SizeLimit = 2;
            request.TimeLimit = TimeSpan.FromSeconds(5);
            var response = (SearchResponse)ldap.SendRequest(request);
            return response.Entries.Count == 1 ? response.Entries[0] : null;
        }

        private DirectoryUser Authorize(LdapConnection ldap, SearchResultEntry entry) {
            if (entry == null || entry.Attributes["objectGUID"] == null) return null;
            var guid = entry.Attributes["objectGUID"].GetValues(typeof(byte[]))[0] as byte[];
            var name = Text(entry, "sAMAccountName");
            int flags;
            long accountExpires;
            string expires = Text(entry, "accountExpires");
            if (guid == null || guid.Length != 16 || string.IsNullOrWhiteSpace(name)
                || !int.TryParse(Text(entry, "userAccountControl"), out flags) || (flags & 2) != 0
                || (!string.IsNullOrEmpty(expires)
                    && (!long.TryParse(expires, out accountExpires)
                        || (accountExpires != 0 && accountExpires <= DateTime.UtcNow.ToFileTimeUtc())))) return null;
            if (!string.IsNullOrWhiteSpace(config.AccessGroupDn) && !Member(ldap, entry, config.AccessGroupDn)) return null;
            return new DirectoryUser {
                Guid = BitConverter.ToString(guid).Replace("-", "").ToLowerInvariant(),
                Username = name, Name = Text(entry, "displayName") ?? name,
                Admin = Member(ldap, entry, config.AdminGroupDn)
            };
        }

        private static string Text(SearchResultEntry entry, string name) {
            var value = entry.Attributes[name];
            return value == null || value.Count == 0 ? null : (string)value.GetValues(typeof(string))[0];
        }

        private static bool Member(LdapConnection ldap, SearchResultEntry entry, string group) {
            var compare = (CompareResponse)ldap.SendRequest(new CompareRequest(entry.DistinguishedName, "memberOf", group));
            return compare.ResultCode == ResultCode.CompareTrue;
        }
    }
}
