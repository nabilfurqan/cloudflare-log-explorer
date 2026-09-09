<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
require_csrf();
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
    json_response(['success' => false, 'capability' => 'analyticsRead', 'error' => cf_error_message($response, 'Security Events query failed.')], $response['status'] ?: 502);
}

$body = $response['body'] ?? [];
if (!empty($body['errors'])) {
    $message = (string) ($body['errors'][0]['message'] ?? 'GraphQL query failed.');
    json_response(['success' => false, 'capability' => 'analyticsRead', 'error' => $message], 403);
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
