<?php
declare(strict_types=1);

final class Auth {
    private PDO $db;

    public function __construct(private ActiveDirectory $directory, private array $session) {
        $this->db = Database::getInstance();
    }

    public static function startSession(array $session, bool $secure): void {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_name($session['cookie_name']);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    public function currentUser(bool $requireFreshDirectoryCheck = false): ?array {
        if (!isset($_SESSION['user_id'])) {
            return null;
        }
        $stmt = $this->db->prepare('SELECT id, ad_guid, ad_username, name, disabled_at, auth_version FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();
        $now = time();
        if (!$user || $user['ad_guid'] === null || $user['disabled_at'] !== null
            || (int)$user['auth_version'] !== ($_SESSION['auth_version'] ?? null)
            || $now >= ($_SESSION['issued_at'] ?? 0) + $this->session['lifetime']) {
            $this->logout();
            return null;
        }
        if ($requireFreshDirectoryCheck || $now >= $_SESSION['directory_checked_at'] + 60) {
            $identity = $this->directory->refresh($user['ad_guid']);
            if ($identity === null) {
                $this->logout();
                return null;
            }
            $_SESSION['is_admin'] = $identity['admin'];
            $_SESSION['directory_checked_at'] = $now;
        }
        $user['is_admin'] = $_SESSION['is_admin'] ?? false;
        return $user;
    }

    public function login(array $identity): bool {
        $stmt = $this->db->prepare(
            'INSERT INTO users (ad_guid, ad_username, name) VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE ad_username = ?, name = ?'
        );
        $stmt->execute([$identity['guid'], $identity['username'], $identity['name'], $identity['username'], $identity['name']]);
        $stmt = $this->db->prepare('SELECT id, disabled_at, auth_version FROM users WHERE ad_guid = ?');
        $stmt->execute([$identity['guid']]);
        $user = $stmt->fetch();
        if (!$user || $user['disabled_at'] !== null) {
            return false;
        }
        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Session renewal failed.');
        }
        $_SESSION = [
            'user_id' => (int)$user['id'],
            'auth_version' => (int)$user['auth_version'],
            'is_admin' => $identity['admin'],
            'issued_at' => time(),
            'directory_checked_at' => time(),
        ];
        return true;
    }

    public function logout(): void {
        $params = session_get_cookie_params();
        $_SESSION = [];
        session_destroy();
        setcookie(session_name(), '', [
            'expires' => 1,
            'path' => $params['path'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'],
        ]);
    }

    public function allowLoginAttempt(string $username, string $clientAddress): bool {
        $window = intdiv(time(), 300);
        $increment = $this->db->prepare(
            'INSERT INTO login_attempts (bucket, window_id, attempts) VALUES (?, ?, 1)
             ON DUPLICATE KEY UPDATE attempts = IF(window_id = VALUES(window_id), LEAST(attempts + 1, 1000), 1),
             window_id = VALUES(window_id)'
        );
        $count = $this->db->prepare('SELECT attempts FROM login_attempts WHERE bucket = ?');
        $this->db->beginTransaction();
        try {
            $allowed = true;
            foreach (['ip:' . $clientAddress => 60, 'user:' . strtolower($username) => 10] as $key => $limit) {
                $bucket = hash('sha256', $key);
                $increment->execute([$bucket, $window]);
                $count->execute([$bucket]);
                if ((int)$count->fetchColumn() > $limit) {
                    $allowed = false;
                    break;
                }
            }
            $this->db->commit();
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
        if (random_int(1, 100) === 1) {
            $cleanup = $this->db->prepare('DELETE FROM login_attempts WHERE window_id < ? LIMIT 1000');
            $cleanup->execute([$window - 2]);
        }
        return $allowed;
    }

    public function listUsers(): array {
        return $this->db->query(
            'SELECT id, ad_username, name, disabled_at FROM users WHERE ad_guid IS NOT NULL ORDER BY name, id'
        )->fetchAll();
    }

    public function setDisabled(int $actor, int $target, bool $disabled): bool {
        if ($actor === $target) {
            return false;
        }
        // Check the actor and change the target under the same transaction as the audit event.
        $this->db->beginTransaction();
        try {
            $lock = $this->db->prepare('SELECT id, disabled_at FROM users WHERE id IN (?, ?) AND ad_guid IS NOT NULL ORDER BY id FOR UPDATE');
            $lock->execute([$actor, $target]);
            $users = array_column($lock->fetchAll(), 'disabled_at', 'id');
            if (count($users) !== 2 || $users[$actor] !== null) {
                $this->db->rollBack();
                return false;
            }
            if (($users[$target] !== null) !== $disabled) {
                $value = $disabled ? 'UTC_TIMESTAMP()' : 'NULL';
                $stmt = $this->db->prepare("UPDATE users SET disabled_at = {$value}, auth_version = auth_version + 1 WHERE id = ?");
                $stmt->execute([$target]);
                $stmt = $this->db->prepare('INSERT INTO user_access_audit (actor_id, target_id, action) VALUES (?, ?, ?)');
                $stmt->execute([$actor, $target, $disabled ? 'disabled' : 'enabled']);
            }
            $this->db->commit();
            return true;
        } catch (Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
}
