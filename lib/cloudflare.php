<?php
declare(strict_types=1);

const APP_TIMEZONE = 'Asia/Jakarta';
const SESSION_IDLE_TIMEOUT = 1800;
const MAX_JSON_BODY_BYTES = 65536;
const MAX_CF_ERROR_DETAIL_BYTES = 1200;

date_default_timezone_set(APP_TIMEZONE);

function is_https_request(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    $forwardedProto = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
    return $forwardedProto === 'https';
}

function bootstrap_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        $secure = is_https_request();
        session_name('cfle_session');
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.gc_maxlifetime', (string) (SESSION_IDLE_TIMEOUT + 300));
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        if (!session_start()) {
            throw new RuntimeException('Unable to start PHP session.');
        }
    }

    $now = time();
    $lastActivity = isset($_SESSION['last_activity']) ? (int) $_SESSION['last_activity'] : 0;

    if ($lastActivity > 0 && ($now - $lastActivity) > SESSION_IDLE_TIMEOUT) {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['session_expired'] = true;
    }

    $_SESSION['last_activity'] = $now;

    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
    }
}

function json_response(array $payload, int $status = 200)
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function read_json_body(): array
{
    $declaredLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
    if ($declaredLength > MAX_JSON_BODY_BYTES) {
        json_response(['success' => false, 'error' => 'Request body is too large.'], 413);
    }

    $raw = file_get_contents('php://input');
    if ($raw === false) {
        json_response(['success' => false, 'error' => 'Unable to read request body.'], 400);
    }
    if (strlen($raw) > MAX_JSON_BODY_BYTES) {
        json_response(['success' => false, 'error' => 'Request body is too large.'], 413);
    }

    $data = json_decode($raw !== '' ? $raw : '{}', true);
    if (!is_array($data)) {
        json_response(['success' => false, 'error' => 'Invalid JSON body.'], 400);
    }
    return $data;
}

function require_csrf(): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf']) || !hash_equals((string) $_SESSION['csrf'], (string) $provided)) {
        json_response(['success' => false, 'error' => 'Invalid CSRF token. Refresh the page and try again.'], 403);
    }
}

function base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function base64url_decode(string $value)
{
    $padding = strlen($value) % 4;
    if ($padding !== 0) {
        $value .= str_repeat('=', 4 - $padding);
    }
    return base64_decode(strtr($value, '-_', '+/'), true);
}

function app_secret_key(): ?string
{
    static $cached = null;
    static $resolved = false;
    if ($resolved) {
        return $cached;
    }
    $resolved = true;

    $env = trim((string) (getenv('CFLE_SESSION_KEY') ?: ''));
    if ($env !== '') {
        $decoded = base64_decode($env, true);
        if (is_string($decoded) && strlen($decoded) >= 32) {
            return $cached = substr($decoded, 0, 32);
        }
        if (strlen($env) >= 32) {
            return $cached = substr(hash('sha256', $env, true), 0, 32);
        }
    }

    $path = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'cfle-session-key-v1.bin';
    $existing = @file_get_contents($path);
    if (is_string($existing) && strlen($existing) === 32) {
        return $cached = $existing;
    }

    try {
        $key = random_bytes(32);
    } catch (Throwable $e) {
        return null;
    }

    $handle = @fopen($path, 'x+b');
    if ($handle !== false) {
        @chmod($path, 0600);
        fwrite($handle, $key);
        fflush($handle);
        fclose($handle);
        return $cached = $key;
    }

    $existing = @file_get_contents($path);
    if (is_string($existing) && strlen($existing) === 32) {
        return $cached = $existing;
    }

    return null;
}

function encrypt_session_secret(string $plain): string
{
    $key = app_secret_key();
    if ($key === null) {
        return 'plain:' . base64url_encode($plain);
    }

    if (function_exists('sodium_crypto_secretbox')) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plain, $nonce, $key);
        return 'sodium:' . base64url_encode($nonce . $cipher);
    }

    if (function_exists('openssl_encrypt')) {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if (is_string($cipher)) {
            return 'gcm:' . base64url_encode($iv . $tag . $cipher);
        }
    }

    return 'plain:' . base64url_encode($plain);
}

function decrypt_session_secret(string $encoded): ?string
{
    if (strpos($encoded, ':') === false) {
        return $encoded;
    }

    [$scheme, $payload] = explode(':', $encoded, 2);
    $raw = base64url_decode($payload);
    if (!is_string($raw)) {
        return null;
    }

    if ($scheme === 'plain') {
        return $raw;
    }

    $key = app_secret_key();
    if ($key === null) {
        return null;
    }

    if ($scheme === 'sodium' && function_exists('sodium_crypto_secretbox_open')) {
        $nonceBytes = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
        if (strlen($raw) <= $nonceBytes) {
            return null;
        }
        $nonce = substr($raw, 0, $nonceBytes);
        $cipher = substr($raw, $nonceBytes);
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        return is_string($plain) ? $plain : null;
    }

    if ($scheme === 'gcm' && function_exists('openssl_decrypt')) {
        if (strlen($raw) <= 28) {
            return null;
        }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return is_string($plain) ? $plain : null;
    }

    return null;
}

function store_session_token(string $token): void
{
    $_SESSION['cf_token_enc'] = encrypt_session_secret($token);
    unset($_SESSION['cf_token']);
}

function require_token(): string
{
    $encoded = $_SESSION['cf_token_enc'] ?? null;
    if (is_string($encoded) && $encoded !== '') {
        $token = decrypt_session_secret($encoded);
        if (is_string($token) && $token !== '') {
            return $token;
        }
        $_SESSION = [];
        session_regenerate_id(true);
        json_response(['success' => false, 'error' => 'Secure session state could not be decrypted. Connect your Cloudflare API Token again.'], 401);
    }

    if (!empty($_SESSION['cf_token']) && is_string($_SESSION['cf_token'])) {
        $token = $_SESSION['cf_token'];
        store_session_token($token);
        return $token;
    }

    $expired = !empty($_SESSION['session_expired']);
    json_response([
        'success' => false,
        'error' => $expired
            ? 'Session expired after 30 minutes of inactivity. Connect your Cloudflare API Token again.'
            : 'Cloudflare session is not connected.',
    ], 401);
}

function client_ip_for_rate_limit(): string
{
    $remoteIp = trim((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    $cfIp = trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));

    if ($cfIp !== '' && filter_var($cfIp, FILTER_VALIDATE_IP)) {
        return $cfIp;
    }

    return filter_var($remoteIp, FILTER_VALIDATE_IP) ? $remoteIp : 'unknown';
}

function rate_limit_or_reject(string $bucket, int $maxAttempts, int $windowSeconds): void
{
    $maxAttempts = max(1, $maxAttempts);
    $windowSeconds = max(1, $windowSeconds);
    $sessionPart = session_status() === PHP_SESSION_ACTIVE ? session_id() : '';
    $key = hash('sha256', $bucket . '|' . client_ip_for_rate_limit() . '|' . $sessionPart);
    $path = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'cfle-rl-' . $key . '.json';
    $handle = @fopen($path, 'c+');

    if ($handle === false) {
        return;
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            return;
        }

        rewind($handle);
        $raw = stream_get_contents($handle);
        $timestamps = json_decode($raw ?: '[]', true);
        if (!is_array($timestamps)) {
            $timestamps = [];
        }

        $cutoff = time() - $windowSeconds;
        $timestamps = array_values(array_filter($timestamps, static function ($ts) use ($cutoff): bool {
            return is_int($ts) && $ts > $cutoff;
        }));

        if (count($timestamps) >= $maxAttempts) {
            header('Retry-After: ' . $windowSeconds);
            json_response(['success' => false, 'error' => 'Too many requests. Try again in a few minutes.'], 429);
        }

        $timestamps[] = time();
        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, json_encode($timestamps));
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
}

function cf_request(string $method, string $path, string $token, ?array $body = null, array $query = []): array
{
    if (!function_exists('curl_init')) {
        return [
            'ok' => false,
            'status' => 0,
            'body' => null,
            'raw' => '',
            'error' => 'PHP cURL extension is not enabled on this server.',
        ];
    }

    $url = strpos($path, 'https://') === 0
        ? $path
        : 'https://api.cloudflare.com/client/v4' . $path;

    if ($query) {
        $url .= (strpos($url, '?') !== false ? '&' : '?') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'status' => 0, 'body' => null, 'raw' => '', 'error' => 'Unable to initialize cURL.'];
    }

    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
        'User-Agent: Cloudflare-Explorer/2.0',
    ];

    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES));
    }

    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 60,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADER => true,
        CURLOPT_ENCODING => '',
    ]);

    $raw = curl_exec($ch);
    if ($raw === false) {
        $message = curl_error($ch);
        curl_close($ch);
        return ['ok' => false, 'status' => 0, 'body' => null, 'raw' => '', 'error' => $message];
    }

    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $responseBody = substr($raw, $headerSize);
    curl_close($ch);

    $decoded = json_decode($responseBody, true);

    return [
        'ok' => $status >= 200 && $status < 300,
        'status' => $status,
        'body' => is_array($decoded) ? $decoded : null,
        'raw' => $responseBody,
        'error' => null,
    ];
}

function cf_error_detail(array $response): ?string
{
    $body = $response['body'] ?? null;
    if (is_array($body)) {
        $parts = [];
        foreach (['errors', 'messages'] as $key) {
            foreach (($body[$key] ?? []) as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $code = isset($item['code']) ? trim((string) $item['code']) : '';
                $message = isset($item['message']) ? trim((string) $item['message']) : '';
                if ($message !== '') {
                    $parts[] = ($code !== '' ? '[' . $code . '] ' : '') . $message;
                }
            }
        }
        if ($parts) {
            return implode(' | ', array_slice(array_unique($parts), 0, 3));
        }
    }

    $raw = trim((string) ($response['raw'] ?? ''));
    if ($raw !== '') {
        $raw = preg_replace('/<[^>]+>/', ' ', $raw) ?? $raw;
        $raw = preg_replace('/\s+/', ' ', $raw) ?? $raw;
        $raw = trim($raw);
        if ($raw !== '') {
            return function_exists('mb_substr')
                ? mb_substr($raw, 0, MAX_CF_ERROR_DETAIL_BYTES)
                : substr($raw, 0, MAX_CF_ERROR_DETAIL_BYTES);
        }
    }

    if (!empty($response['error'])) {
        return trim((string) $response['error']);
    }

    return null;
}

function cf_error_message(array $response, string $fallback = 'Cloudflare API request failed.'): string
{
    $status = (int) ($response['status'] ?? 0);
    $detail = cf_error_detail($response);
    $statusText = $status > 0 ? ' HTTP ' . $status . '.' : '';

    if ($detail !== null && $detail !== '') {
        return rtrim($fallback) . $statusText . ' ' . $detail;
    }

    return rtrim($fallback) . ($statusText !== '' ? $statusText : '');
}

function valid_resource_id(string $value): bool
{
    return (bool) preg_match('/^[a-f0-9]{32}$/i', $value);
}

function iso_to_timestamp(string $value): ?int
{
    try {
        return (new DateTimeImmutable($value))->getTimestamp();
    } catch (Throwable $e) {
        return null;
    }
}

function json_compact($value): string
{
    if ($value === null || $value === '' || $value === []) {
        return '';
    }
    if (is_scalar($value)) {
        return (string) $value;
    }
    return (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
