<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
define('BASE_DIR', __DIR__);

function jsonResponse(mixed $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    exit;
}

function redirect(string $path): never {
    header('Location: ' . $path, true, 303);
    exit;
}

function view(string $template, array $vars = []): never {
    extract($vars, EXTR_SKIP);
    require BASE_DIR . '/templates/' . $template . '.php';
    exit;
}

function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string {
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function verify_csrf(): void {
    $expected = $_SESSION['csrf'] ?? null;
    $received = $_POST['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
    if (!is_string($expected) || !is_string($received) || !hash_equals($expected, $received)) {
        jsonResponse(['error' => 'Solicitação inválida. Recarregue a página.'], 403);
    }
}

function requestObject(): array {
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 65536) {
        jsonResponse(['error' => 'Solicitação grande demais.'], 413);
    }
    $raw = file_get_contents('php://input', false, null, 0, 65537);
    if (strlen($raw) > 65536) {
        jsonResponse(['error' => 'Solicitação grande demais.'], 413);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        jsonResponse(['error' => 'Dados inválidos.'], 400);
    }
    return $data;
}

function loginError(string $message, int $status, bool $json): never {
    if ($json) {
        jsonResponse(['error' => $message], $status);
    }
    http_response_code($status);
    view('landing', ['error' => $message]);
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];
if ($uri === '/healthz' && $method === 'GET') {
    jsonResponse(['status' => 'ok']);
}
set_exception_handler(static function (Throwable $e): never {
    error_log('TOTPVault request failed: ' . get_class($e) . ' at ' . basename($e->getFile()) . ':' . $e->getLine());
    jsonResponse(['error' => 'Serviço temporariamente indisponível.'], 503);
});

$config = require BASE_DIR . '/config/config.php';
$secure = strtolower((string)($_SERVER['HTTPS'] ?? '')) === 'on'
    || ($config['trust_tls_proxy'] && ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
if (!$secure && !$config['allow_http_dev']) {
    jsonResponse(['error' => 'Acesse o TOTPVault por HTTPS.'], 400);
}

define('CSP_NONCE', base64_encode(random_bytes(18)));
header("Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-" . CSP_NONCE . "'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

foreach (['Database', 'Crypto', 'TOTP', 'Auth', 'ActiveDirectory', 'Profile'] as $class) {
    require_once BASE_DIR . '/src/' . $class . '.php';
}
Auth::startSession($config['session'], $secure);
$directory = new ActiveDirectory($config['ad']);
$auth = new Auth($directory, $config['session']);
$user = $auth->currentUser($uri === '/admin/users' || $uri === '/admin/users/access');

if ($uri === '/' && $method === 'GET') {
    if ($user) {
        redirect('/dashboard');
    }
    if (session_status() !== PHP_SESSION_ACTIVE) {
        redirect('/');
    }
    view('landing');
}

if ($uri === '/api/session' && $method === 'GET') {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        jsonResponse(['error' => 'Sessão encerrada. Entre novamente.'], 401);
    }
    jsonResponse(['csrf' => csrf_token(), 'username' => $user['ad_username'] ?? null]);
}

$desktopLogin = $uri === '/api/session/login';
if (($uri === '/auth/ad' || $desktopLogin) && $method === 'POST') {
    if ($user) {
        if ($desktopLogin) {
            jsonResponse(['csrf' => csrf_token(), 'username' => $user['ad_username']]);
        }
        redirect('/dashboard');
    }
    verify_csrf();
    $input = $desktopLogin ? requestObject() : $_POST;
    $username = $input['username'] ?? null;
    $password = $input['password'] ?? null;
    if (!is_string($username) || !is_string($password)
        || !preg_match('/\A[^\s\x00-\x1f\x7f@\\\\\/]{1,80}\z/u', $username)
        || $password === '' || strlen($password) > 1024) {
        loginError('Não foi possível entrar com essas credenciais.', 401, $desktopLogin);
    }
    if (!$auth->allowLoginAttempt($username, $_SERVER['REMOTE_ADDR'] ?? 'unknown')) {
        header('Retry-After: ' . (300 - time() % 300));
        loginError('Muitas tentativas. Aguarde alguns minutos antes de tentar novamente.', 429, $desktopLogin);
    }
    $identity = $directory->authenticate($username, $password);
    if ($identity !== null && $auth->login($identity)) {
        if ($desktopLogin) {
            jsonResponse(['csrf' => csrf_token(), 'username' => $identity['username']]);
        }
        redirect('/dashboard');
    }
    loginError('Não foi possível entrar com essas credenciais.', 401, $desktopLogin);
}

if (!$user) {
    if (str_starts_with((string)$uri, '/api/') || $method !== 'GET') {
        jsonResponse(['error' => 'Sessão encerrada. Entre novamente.'], 401);
    }
    redirect('/');
}

if ($uri === '/auth/logout' && $method === 'POST') {
    verify_csrf();
    $auth->logout();
    redirect('/');
}

if ($uri === '/api/session' && $method === 'DELETE') {
    verify_csrf();
    $auth->logout();
    http_response_code(204);
    exit;
}

if ($uri === '/admin/users' || $uri === '/admin/users/access') {
    if (!$user['is_admin']) {
        jsonResponse(['error' => 'Acesso restrito a administradores.'], 403);
    }
    if ($uri === '/admin/users' && $method === 'GET') {
        view('admin', ['user' => $user, 'users' => $auth->listUsers()]);
    }
    if ($uri === '/admin/users/access' && $method === 'POST') {
        verify_csrf();
        $target = filter_var($_POST['target'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $action = $_POST['action'] ?? '';
        if (!$target || !in_array($action, ['enable', 'disable'], true)
            || !$auth->setDisabled((int)$user['id'], $target, $action === 'disable')) {
            jsonResponse(['error' => 'Não foi possível alterar o acesso desta conta.'], 400);
        }
        redirect('/admin/users');
    }
}

$userId = (int)$user['id'];
if ($uri === '/dashboard' && $method === 'GET') {
    view('dashboard', ['user' => $user, 'profiles' => (new Profile())->listForUser($userId)]);
}

if ($uri === '/tools/import-google-auth' && in_array($method, ['GET', 'POST'], true)) {
    require BASE_DIR . '/tools/import-google-auth.php';
    exit;
}

try {
    if ($uri === '/api/profiles' && $method === 'GET') {
        jsonResponse((new Profile())->listForUser($userId));
    }

    if ($uri === '/api/otp' && $method === 'GET') {
        $id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $otp = $id ? (new Profile())->generateOTP($id, $userId) : null;
        if (!$otp) {
            jsonResponse(['error' => 'Token não encontrado.'], 404);
        }
        jsonResponse($otp);
    }

    if ($uri === '/api/profiles' && $method === 'POST') {
        verify_csrf();
        $id = (new Profile())->create($userId, requestObject());
        jsonResponse(['success' => true, 'id' => $id], 201);
    }

    if (preg_match('#^/api/profiles/([1-9][0-9]{0,9})$#', (string)$uri, $match)) {
        $id = (int)$match[1];
        $profiles = new Profile();
        if ($method === 'GET') {
            $profile = $profiles->get($id, $userId);
            if ($profile === null) {
                jsonResponse(['error' => 'Token não encontrado.'], 404);
            }
            unset($profile['secret_encrypted']);
            jsonResponse($profile);
        }
        if ($method === 'PUT' || $method === 'DELETE') {
            verify_csrf();
            $ok = $method === 'PUT'
                ? $profiles->update($id, $userId, requestObject())
                : $profiles->delete($id, $userId);
            jsonResponse($ok ? ['success' => true] : ['error' => 'Token não encontrado.'], $ok ? 200 : 404);
        }
    }

    if ($uri === '/api/generate-secret' && $method === 'GET') {
        jsonResponse(['secret' => TOTP::generateSecret()]);
    }
} catch (InvalidArgumentException $e) {
    jsonResponse(['error' => $e->getMessage()], 400);
}

http_response_code(404);
view('404', ['user' => $user]);
