<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
$token = require_token();

$response = cf_request('GET', '/zones', $token, null, ['per_page' => 50, 'page' => 1]);
if (!$response['ok'] || empty($response['body']['success'])) {
    json_response(['success' => false, 'error' => cf_error_message($response, 'Unable to list zones.')], $response['status'] ?: 502);
}

$zones = array_map(static fn(array $zone): array => [
    'id' => (string) ($zone['id'] ?? ''),
    'name' => (string) ($zone['name'] ?? ''),
    'status' => (string) ($zone['status'] ?? ''),
    'accountId' => (string) ($zone['account']['id'] ?? ''),
    'accountName' => (string) ($zone['account']['name'] ?? ''),
], $response['body']['result'] ?? []);

json_response(['success' => true, 'zones' => $zones]);
