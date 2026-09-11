<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
rate_limit_or_reject('fields', 30, 60);
$token = require_token();

$zoneId = trim((string) ($_GET['zoneId'] ?? ''));
if (!valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'Invalid Zone ID.'], 422);
}

$response = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/logs/received/fields', $token);
if (!$response['ok']) {
    json_response([
        'success' => false,
        'capability' => 'logsRead',
        'status' => $response['status'] ?? 0,
        'error' => cf_error_message($response, 'Unable to list Logpull fields. Check Logs Read permission, plan availability, and Logpull access.'),
    ], $response['status'] ?: 502);
}

$fields = $response['body'];
if (!is_array($fields)) {
    json_response(['success' => false, 'error' => 'Unexpected fields response from Cloudflare.'], 502);
}

json_response(['success' => true, 'capability' => 'logsRead', 'fields' => $fields]);
