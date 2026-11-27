<?php
declare(strict_types=1);

final class Crypto {
    private const PREFIX = 'v2:';

    public static function encrypt(string $plaintext): string {
        $cfg = require __DIR__ . '/../config/config.php';
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', self::key($cfg), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($cipher === false) {
            throw new RuntimeException('Encryption failed.');
        }
        return self::PREFIX . base64_encode($iv . $tag . $cipher);
    }

    public static function decrypt(string $encoded): string {
        $cfg = require __DIR__ . '/../config/config.php';
        $versioned = str_starts_with($encoded, self::PREFIX);
        $raw = base64_decode($versioned ? substr($encoded, strlen(self::PREFIX)) : $encoded, true);
        if ($raw === false || strlen($raw) <= 28) {
            throw new RuntimeException('Invalid encrypted token.');
        }
        $key = self::key($cfg);
        if (!$versioned) {
            $legacy = $cfg['legacy_encryption_key'] ?: $cfg['encryption_key'];
            $key = substr(str_pad($legacy, 32, "\0"), 0, 32);
        }
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
        if ($plain === false) {
            throw new RuntimeException('Decryption failed.');
        }
        return $plain;
    }

    private static function key(array $cfg): string {
        $key = base64_decode($cfg['encryption_key'], true);
        if ($key === false || strlen($key) !== 32
            || $cfg['encryption_key'] === 'K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=') {
            throw new RuntimeException('Configure a unique 32-byte encryption key encoded in Base64.');
        }
        return $key;
    }
}
