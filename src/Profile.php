<?php
declare(strict_types=1);

final class Profile {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    public function create(int $userId, array $data): int {
        $fields = $this->validatedFields($data + [
            'issuer' => '', 'algorithm' => 'SHA1', 'digits' => 6, 'period' => 30,
            'color' => '#6366f1', 'icon' => 'fa-shield-halved', 'hide_code' => 0,
        ], true);
        $fields['user_id'] = $userId;
        $columns = implode(', ', array_keys($fields));
        $placeholders = implode(', ', array_fill(0, count($fields), '?'));
        $this->db->prepare("INSERT INTO otp_profiles ({$columns}) VALUES ({$placeholders})")->execute(array_values($fields));
        return (int)$this->db->lastInsertId();
    }

    public function update(int $profileId, int $userId, array $data): bool {
        if ($this->get($profileId, $userId) === null) {
            return false;
        }
        $fields = $this->validatedFields($data, false);
        if ($fields !== []) {
            $assignments = implode(', ', array_map(static fn(string $key): string => "$key = ?", array_keys($fields)));
            $stmt = $this->db->prepare("UPDATE otp_profiles SET {$assignments} WHERE id = ? AND user_id = ?");
            $stmt->execute([...array_values($fields), $profileId, $userId]);
        }
        return true;
    }

    public function delete(int $profileId, int $userId): bool {
        $stmt = $this->db->prepare('DELETE FROM otp_profiles WHERE id = ? AND user_id = ?');
        $stmt->execute([$profileId, $userId]);
        return $stmt->rowCount() > 0;
    }

    public function get(int $profileId, int $userId): ?array {
        $stmt = $this->db->prepare('SELECT * FROM otp_profiles WHERE id = ? AND user_id = ?');
        $stmt->execute([$profileId, $userId]);
        return $stmt->fetch() ?: null;
    }

    public function listForUser(int $userId): array {
        $stmt = $this->db->prepare(
            'SELECT id, name, issuer, algorithm, digits, period, color, icon, hide_code
             FROM otp_profiles WHERE user_id = ? ORDER BY name, id'
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    public function generateOTP(int $profileId, int $userId): ?array {
        $profile = $this->get($profileId, $userId);
        if (!$profile) {
            return null;
        }
        $secret = Crypto::decrypt($profile['secret_encrypted']);
        $now = time();
        $period = (int)$profile['period'];
        return [
            'code' => TOTP::generate($secret, $profile['algorithm'], (int)$profile['digits'], $period, $now),
            'remaining' => TOTP::secondsRemaining($period, $now),
            'progress' => TOTP::progress($period, $now),
        ];
    }

    private function validatedFields(array $data, bool $creating): array {
        $fields = [];
        foreach (['name', 'issuer', 'algorithm', 'color', 'icon', 'digits', 'period', 'hide_code'] as $field) {
            if (!array_key_exists($field, $data) && (!$creating || $field !== 'name')) {
                continue;
            }
            $value = $data[$field] ?? null;
            $text = is_string($value) ? trim($value) : null;
            $int = is_int($value) || is_string($value) ? filter_var($value, FILTER_VALIDATE_INT) : false;
            $valid = match ($field) {
                'name' => $text !== null && $text !== '' && strlen($text) <= 255,
                'issuer' => $text !== null && strlen($text) <= 255,
                'algorithm' => in_array($text, ['SHA1', 'SHA256', 'SHA512'], true),
                'color' => $text !== null && preg_match('/\A#[a-f0-9]{6}\z/i', $text),
                'icon' => $text !== null && preg_match('/\Afa-[a-z0-9-]{1,47}\z/', $text),
                'digits' => in_array($int, [6, 8, 10], true),
                'period' => $int !== false && $int >= 15 && $int <= 300,
                'hide_code' => in_array($int, [0, 1], true),
            };
            if (!$valid) {
                throw new InvalidArgumentException("Campo inválido: {$field}.");
            }
            $fields[$field] = in_array($field, ['digits', 'period', 'hide_code'], true) ? $int : $text;
        }
        if ($creating || (array_key_exists('secret', $data) && $data['secret'] !== '')) {
            $raw = $data['secret'] ?? null;
            $secret = is_string($raw) ? strtoupper(preg_replace('/\s+/', '', $raw)) : '';
            if (!preg_match('/\A[A-Z2-7]{2,512}={0,6}\z/', $secret)) {
                throw new InvalidArgumentException('A chave do token deve estar em Base32.');
            }
            $fields['secret_encrypted'] = Crypto::encrypt(rtrim($secret, '='));
        }
        return $fields;
    }
}
