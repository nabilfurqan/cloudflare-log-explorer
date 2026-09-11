<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
require_csrf();
rate_limit_or_reject('capabilities', 12, 60);
$token = require_token();
$data = read_json_body();

$zoneId = trim((string) ($data['zoneId'] ?? ''));
$accountId = trim((string) ($data['accountId'] ?? ''));

if ($zoneId !== '' && !valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'Invalid Zone ID.'], 422);
}
if ($accountId !== '' && !valid_resource_id($accountId)) {
    json_response(['success' => false, 'error' => 'Invalid Account ID.'], 422);
}

function capability_from_response(array $response, bool $notFoundMeansConfiguredAccess = false): array
{
    $status = (int) ($response['status'] ?? 0);
    if ($response['ok']) {
        return ['available' => true, 'status' => $status, 'detail' => 'Available'];
    }
    if ($notFoundMeansConfiguredAccess && $status === 404) {
        return ['available' => true, 'status' => 404, 'detail' => 'Available / not configured'];
    }
    return [
        'available' => false,
        'status' => $status,
        'detail' => cf_error_detail($response) ?: ($status ? 'HTTP ' . $status : 'Unavailable'),
    ];
}

$capabilities = [];

if ($zoneId !== '') {
    $logsFields = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/logs/received/fields', $token);
    $capabilities['logsRead'] = capability_from_response($logsFields);

    $retention = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/logs/control/retention/flag', $token);
    $capabilities['logRetention'] = capability_from_response($retention);
    if ($retention['ok']) {
        $result = $retention['body']['result'] ?? null;
        $enabled = is_bool($result) ? $result : (is_array($result) && array_key_exists('flag', $result) ? (bool) $result['flag'] : null);
        $capabilities['logRetention']['enabled'] = $enabled;
        $capabilities['logRetention']['detail'] = $enabled === true ? 'Enabled' : ($enabled === false ? 'Disabled' : 'Readable');
    }

    $rulesets = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/rulesets', $token, null, ['per_page' => 1]);
    $capabilities['rulesetsRead'] = capability_from_response($rulesets);

    $dns = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/dns_records', $token, null, ['per_page' => 1, 'page' => 1]);
    $capabilities['dnsRead'] = capability_from_response($dns);

    $lb = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/load_balancers', $token, null, ['per_page' => 1, 'page' => 1]);
    $capabilities['loadBalancingRead'] = capability_from_response($lb);
}

if ($accountId !== '') {
    $gateway = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/gateway', $token);
    $capabilities['zeroTrustRead'] = capability_from_response($gateway);

    $access = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/access/apps', $token, null, ['per_page' => 1, 'page' => 1]);
    $capabilities['accessRead'] = capability_from_response($access);

    $warp = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/devices/policies', $token);
    $capabilities['devicePoliciesRead'] = capability_from_response($warp);

    $posture = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/devices/posture', $token);
    $capabilities['devicePostureRead'] = capability_from_response($posture);

    $tunnels = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/cfd_tunnel', $token, null, ['per_page' => 1, 'page' => 1, 'is_deleted' => 'false']);
    $capabilities['tunnelRead'] = capability_from_response($tunnels);
}

json_response([
    'success' => true,
    'zoneId' => $zoneId,
    'accountId' => $accountId,
    'capabilities' => $capabilities,
]);
