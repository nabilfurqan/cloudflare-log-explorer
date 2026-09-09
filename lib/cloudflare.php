<?php
declare(strict_types=1);

function bootstrap_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_name('cfle_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();

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
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function read_json_body(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '{}', true);
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
        json_response(['success' => false, 'error' => 'Cloudflare session is not connected.'], 401);
    }
    return $_SESSION['cf_token'];
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
        'User-Agent: Cloudflare-Log-Explorer/1.0',
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
