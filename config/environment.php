<?php
declare(strict_types=1);

return [
    'trust_tls_proxy' => getenv('TRUST_TLS_PROXY') === 'true',
    'allow_http_dev' => getenv('ALLOW_HTTP_DEV') === 'true',
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => (int)(getenv('DB_PORT') ?: 3306),
        'dbname' => getenv('DB_NAME') ?: 'totpvault',
        'charset' => 'utf8mb4',
        'user' => getenv('DB_USER') ?: 'totpvault',
        'password' => (string)getenv('DB_PASSWORD'),
    ],
    'encryption_key' => (string)getenv('ENCRYPTION_KEY'),
    'legacy_encryption_key' => (string)getenv('LEGACY_ENCRYPTION_KEY'),
    'session' => [
        'cookie_name' => 'totpvault_ad_session',
        'lifetime' => 28800,
    ],
    'ad' => [
        'host' => (string)getenv('AD_HOST'),
        'port' => (int)(getenv('AD_PORT') ?: 636),
        'base_dn' => (string)getenv('AD_BASE_DN'),
        'bind_dn' => (string)getenv('AD_BIND_DN'),
        'bind_password' => (string)getenv('AD_BIND_PASSWORD'),
        'ca_file' => (string)getenv('AD_CA_FILE'),
        'access_group_dn' => (string)getenv('AD_ACCESS_GROUP_DN'),
        'admin_group_dn' => (string)getenv('AD_ADMIN_GROUP_DN'),
    ],
];
