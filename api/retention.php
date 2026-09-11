<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
rate_limit_or_reject('retention', 30, 60);
$token = require_token();

$zoneId = trim((string) ($_GET['zoneId'] ?? ''));
if (!valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'Invalid Zone ID.'], 422);
}

$response = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/logs/control/retention/flag', $token);
if (!$response['ok']) {
    json_response([
        'success' => false,
        'capability' => 'logsRead',
        'status' => $response['status'] ?? 0,
        'error' => cf_error_message($response, 'Unable to read Logpull retention status.'),
    ], $response['status'] ?: 502);
}

$result = $response['body']['result'] ?? null;
$enabled = null;
if (is_bool($result)) {
    $enabled = $result;
} elseif (is_array($result)) {
    if (array_key_exists('flag', $result)) {
        $enabled = (bool) $result['flag'];
    } elseif (array_key_exists('enabled', $result)) {
        $enabled = (bool) $result['enabled'];
    }
}

json_response([
    'success' => true,
    'capability' => 'logsRead',
    'enabled' => $enabled,
    'rawResult' => $result,
    'note' => $enabled === false
        ? 'Logpull retention is disabled for this zone. Enabling it requires Logs Write permission.'
        : ($enabled === true ? 'Logpull retention is enabled.' : 'Retention status returned in an unexpected format.'),
]);
