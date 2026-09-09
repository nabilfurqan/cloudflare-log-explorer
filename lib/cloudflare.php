<?php
declare(strict_types=1);

const APP_TIMEZONE = 'Asia/Jakarta';
const SESSION_IDLE_TIMEOUT = 1800;
const MAX_JSON_BODY_BYTES = 65536;

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
        ini_set('session.gc_maxlifetime', (string) (SESSION_IDLE_TIMEOUT + 300));
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
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

function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
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

function require_token(): string
{
    if (empty($_SESSION['cf_token']) || !is_string($_SESSION['cf_token'])) {
        $expired = !empty($_SESSION['session_expired']);
        json_response([
            'success' => false,
            'error' => $expired
                ? 'Session expired after 30 minutes of inactivity. Connect your Cloudflare API Token again.'
                : 'Cloudflare session is not connected.',
        ], 401);
    }
    return $_SESSION['cf_token'];
}

function client_ip_for_rate_limit(): string
{
    $cfIp = trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
    if ($cfIp !== '' && filter_var($cfIp, FILTER_VALIDATE_IP)) {
        return $cfIp;
    }

    $remoteIp = trim((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    return filter_var($remoteIp, FILTER_VALIDATE_IP) ? $remoteIp : 'unknown';
}

function rate_limit_or_reject(string $bucket, int $maxAttempts, int $windowSeconds): void
{
    $maxAttempts = max(1, $maxAttempts);
    $windowSeconds = max(1, $windowSeconds);
    $key = hash('sha256', $bucket . '|' . client_ip_for_rate_limit());
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
        $timestamps = array_values(array_filter($timestamps, static fn($ts): bool => is_int($ts) && $ts > $cutoff));

        if (count($timestamps) >= $maxAttempts) {
            header('Retry-After: ' . $windowSeconds);
            json_response(['success' => false, 'error' => 'Too many connection attempts. Try again in a few minutes.'], 429);
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
    $url = str_starts_with($path, 'https://')
        ? $path
        : 'https://api.cloudflare.com/client/v4' . $path;

    if ($query) {
        $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    $ch = curl_init($url);
    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
        'User-Agent: Cloudflare-Log-Explorer/1.1',
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

function cf_error_message(array $response, string $fallback = 'Cloudflare API request failed.'): string
{
    $body = $response['body'] ?? null;
    if (is_array($body)) {
        if (!empty($body['errors'][0]['message'])) {
            return (string) $body['errors'][0]['message'];
        }
        if (!empty($body['messages'][0]['message'])) {
            return (string) $body['messages'][0]['message'];
        }
    }

    if (!empty($response['error'])) {
        return $fallback . ' Network error.';
    }

    return $fallback . ' HTTP ' . ($response['status'] ?? 'unknown') . '.';
}

function valid_resource_id(string $value): bool
{
    return (bool) preg_match('/^[a-f0-9]{32}$/i', $value);
}

function iso_to_timestamp(string $value): ?int
{
    try {
        return (new DateTimeImmutable($value))->getTimestamp();
    } catch (Throwable) {
        return null;
    }
}
