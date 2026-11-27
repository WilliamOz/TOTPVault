<?php
declare(strict_types=1);

final class ActiveDirectory {
    public function __construct(private array $config) {}

    public function authenticate(string $username, #[SensitiveParameter] string $password): ?array {
        if ($password === '' || strlen($password) > 1024 || str_contains($password, "\0")) {
            return null;
        }
        $ldap = $this->lookupConnection();
        try {
            $entry = $this->find($ldap, '(sAMAccountName=' . ldap_escape($username, '', LDAP_ESCAPE_FILTER) . ')');
            $identity = $this->identity($ldap, $entry);
            if ($identity === null) {
                return null;
            }
            if (!@ldap_bind($ldap, $entry['dn'], $password)) {
                if (ldap_errno($ldap) === 49) {
                    return null;
                }
                throw new RuntimeException('Directory user bind failed.');
            }
            return $identity;
        } finally {
            ldap_unbind($ldap);
        }
    }

    public function refresh(string $guid): ?array {
        $ldap = $this->lookupConnection();
        try {
            $binaryGuid = implode('', array_map(static fn(string $octet): string => '\\' . $octet, str_split($guid, 2)));
            return $this->identity($ldap, $this->find($ldap, "(objectGUID={$binaryGuid})"));
        } finally {
            ldap_unbind($ldap);
        }
    }

    private function lookupConnection(): LDAP\Connection {
        $host = $this->config['host'];
        $port = $this->config['port'];
        if (!extension_loaded('ldap')
            || !preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}\z/', $host)
            || $port < 1 || $port > 65535
            || $this->config['base_dn'] === '' || $this->config['bind_dn'] === ''
            || $this->config['bind_password'] === '') {
            throw new RuntimeException('Directory is not configured.');
        }
        // Set OpenLDAP's TLS policy before creating the first connection.
        if (!ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND)) {
            throw new RuntimeException('Directory TLS setup failed.');
        }
        if ($this->config['ca_file'] !== '') {
            if (!is_readable($this->config['ca_file'])
                || !ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $this->config['ca_file'])) {
                throw new RuntimeException('Directory CA setup failed.');
            }
        }
        $ldap = ldap_connect("ldaps://{$host}:{$port}");
        if (!$ldap) {
            throw new RuntimeException('Directory connection failed.');
        }
        $options = [
            LDAP_OPT_PROTOCOL_VERSION => 3,
            LDAP_OPT_REFERRALS => 0,
            LDAP_OPT_NETWORK_TIMEOUT => 4,
            LDAP_OPT_TIMEOUT => 5,
        ];
        foreach ($options as $option => $value) {
            if (!ldap_set_option($ldap, $option, $value)) {
                throw new RuntimeException('Directory connection setup failed.');
            }
        }
        if (!@ldap_bind($ldap, $this->config['bind_dn'], $this->config['bind_password'])) {
            throw new RuntimeException('Directory lookup bind failed.');
        }
        return $ldap;
    }

    private function find(LDAP\Connection $ldap, string $filter): ?array {
        $result = @ldap_search(
            $ldap, $this->config['base_dn'], '(&(objectClass=user)(objectCategory=person)' . $filter . ')',
            ['objectGUID', 'userAccountControl', 'accountExpires', 'sAMAccountName', 'displayName'],
            0, 2, 5
        );
        if (!$result || !ldap_parse_result($ldap, $result, $code) || !in_array($code, [0, 4], true)) {
            throw new RuntimeException('Directory lookup failed.');
        }
        if ($code !== 0 || ldap_count_entries($ldap, $result) !== 1) {
            return null;
        }
        return ldap_get_entries($ldap, $result)[0] ?? null;
    }

    private function identity(LDAP\Connection $ldap, ?array $entry): ?array {
        $guid = $entry['objectguid'][0] ?? '';
        $username = $entry['samaccountname'][0] ?? '';
        $flags = $entry['useraccountcontrol'][0] ?? '';
        $expiry = $entry['accountexpires'][0] ?? '';
        if (strlen($guid) !== 16 || $username === '' || !ctype_digit($flags) || ((int)$flags & 2)
            || ($expiry !== '' && (!ctype_digit($expiry)
                || ($expiry !== '0' && (int)$expiry <= (time() + 11644473600) * 10000000)))) {
            return null;
        }
        $member = fn(string $group): bool => $group !== '' && @ldap_compare($ldap, $entry['dn'], 'memberOf', $group) === true;
        if ($this->config['access_group_dn'] !== '' && !$member($this->config['access_group_dn'])) {
            return null;
        }
        return [
            'guid' => bin2hex($guid),
            'username' => $username,
            'name' => ($entry['displayname'][0] ?? '') ?: $username,
            'admin' => $member($this->config['admin_group_dn']),
        ];
    }
}
