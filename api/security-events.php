<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
require_csrf();
rate_limit_or_reject('security-events', 20, 60);
$token = require_token();
$data = read_json_body();

$zoneId = trim((string) ($data['zoneId'] ?? ''));
$start = trim((string) ($data['start'] ?? ''));
$end = trim((string) ($data['end'] ?? ''));
$limit = max(1, min((int) ($data['limit'] ?? 1000), 10000));

if (!valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'Invalid Zone ID.'], 422);
}
$startTs = iso_to_timestamp($start);
$endTs = iso_to_timestamp($end);
if ($startTs === null || $endTs === null || $endTs <= $startTs) {
    json_response(['success' => false, 'error' => 'Invalid time range.'], 422);
}
if (($endTs - $startTs) > 31 * 86400) {
    json_response(['success' => false, 'error' => 'Security Events queries are limited to 31 days per request in this tool.'], 422);
}
if ($endTs > time() + 60) {
    json_response(['success' => false, 'error' => 'The end time cannot be in the future.'], 422);
}

$query = <<<'GRAPHQL'
query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(filter: $filter, limit: $limit, orderBy: [datetime_DESC]) {
        action
        clientAsn
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestPath
        datetime
        description
        kind
        originatorRayName
        ruleId
        source
        userAgent
      }
    }
  }
}
GRAPHQL;

$payload = [
    'query' => $query,
    'variables' => [
        'zoneTag' => $zoneId,
        'limit' => $limit,
        'filter' => [
            'datetime_geq' => gmdate('Y-m-d\TH:i:s\Z', $startTs),
            'datetime_leq' => gmdate('Y-m-d\TH:i:s\Z', $endTs),
        ],
    ],
];

$response = cf_request('POST', 'https://api.cloudflare.com/client/v4/graphql', $token, $payload);
if (!$response['ok']) {
    $status = (int) ($response['status'] ?? 0);
    $message = cf_error_message($response, 'Security Events query failed.');
    if ($status === 401 || $status === 403) {
        $message .= ' Check Analytics Read permission and access to this zone.';
    }
    json_response(['success' => false, 'capability' => 'analyticsRead', 'status' => $status, 'error' => $message], $status ?: 502);
}

$body = $response['body'] ?? [];
if (!empty($body['errors'])) {
    $errorResponse = ['body' => $body, 'raw' => $response['raw'] ?? '', 'status' => 200, 'error' => null];
    json_response([
        'success' => false,
        'capability' => 'analyticsRead',
        'error' => cf_error_message($errorResponse, 'Security Events GraphQL query failed.'),
    ], 403);
}

$zones = $body['data']['viewer']['zones'] ?? [];
$rows = $zones[0]['firewallEventsAdaptive'] ?? [];
json_response([
    'success' => true,
    'source' => 'security-events',
    'capability' => 'analyticsRead',
    'count' => is_array($rows) ? count($rows) : 0,
    'range' => [
        'start' => $payload['variables']['filter']['datetime_geq'],
        'end' => $payload['variables']['filter']['datetime_leq'],
    ],
    'rows' => is_array($rows) ? $rows : [],
]);
