<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
require_csrf();

$data = read_json_body();
$token = trim((string) ($data['token'] ?? ''));
$manualZoneId = trim((string) ($data['zoneId'] ?? ''));
$manualAccountId = trim((string) ($data['accountId'] ?? ''));

if ($token === '' || strlen($token) < 20 || strlen($token) > 256) {
    json_response(['success' => false, 'error' => 'Enter a valid Cloudflare API Token.'], 422);
}
if ($manualZoneId !== '' && !valid_resource_id($manualZoneId)) {
    json_response(['success' => false, 'error' => 'Zone ID must be a 32-character Cloudflare identifier.'], 422);
}
if ($manualAccountId !== '' && !valid_resource_id($manualAccountId)) {
    json_response(['success' => false, 'error' => 'Account ID must be a 32-character Cloudflare identifier.'], 422);
}

$verify = cf_request('GET', '/user/tokens/verify', $token);
if (!$verify['ok'] || empty($verify['body']['success'])) {
    json_response(['success' => false, 'error' => cf_error_message($verify, 'Token verification failed.')], 401);
}

session_regenerate_id(true);
$_SESSION['cf_token'] = $token;
$_SESSION['manual_zone_id'] = $manualZoneId;
$_SESSION['manual_account_id'] = $manualAccountId;
$_SESSION['connected_at'] = time();
$_SESSION['csrf'] = bin2hex(random_bytes(24));

$zonesResp = cf_request('GET', '/zones', $token, null, ['per_page' => 50, 'page' => 1]);
$zones = [];
$zoneRead = false;
if ($zonesResp['ok'] && !empty($zonesResp['body']['success'])) {
    $zoneRead = true;
    foreach (($zonesResp['body']['result'] ?? []) as $zone) {
        $zones[] = [
            'id' => (string) ($zone['id'] ?? ''),
            'name' => (string) ($zone['name'] ?? ''),
            'status' => (string) ($zone['status'] ?? ''),
            'accountId' => (string) ($zone['account']['id'] ?? ''),
            'accountName' => (string) ($zone['account']['name'] ?? ''),
        ];
    }
}

if ($manualZoneId !== '' && !array_filter($zones, fn(array $z): bool => $z['id'] === $manualZoneId)) {
    array_unshift($zones, [
        'id' => $manualZoneId,
        'name' => 'Manual Zone ID',
        'status' => 'unknown',
        'accountId' => $manualAccountId,
        'accountName' => $manualAccountId !== '' ? 'Manual Account ID' : '',
    ]);
}

$verifyResult = $verify['body']['result'] ?? [];
json_response([
    'success' => true,
    'csrf' => $_SESSION['csrf'],
    'token' => [
        'status' => (string) ($verifyResult['status'] ?? 'active'),
        'id' => (string) ($verifyResult['id'] ?? ''),
        'expiresOn' => $verifyResult['expires_on'] ?? null,
        'notBefore' => $verifyResult['not_before'] ?? null,
    ],
    'capabilities' => [
        'tokenVerified' => true,
        'zoneRead' => $zoneRead,
        'logsRead' => null,
        'analyticsRead' => null,
    ],
    'zones' => $zones,
    'zoneReadError' => $zoneRead ? null : cf_error_message($zonesResp, 'Unable to list zones. The token may not have Zone Read.'),
]);
