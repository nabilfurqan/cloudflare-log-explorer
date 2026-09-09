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
$fields = $data['fields'] ?? [];
$count = isset($data['count']) ? (int) $data['count'] : 1000;

if (!valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'Invalid Zone ID.'], 422);
}
if (!is_array($fields)) {
    $fields = [];
}
$fields = array_values(array_filter(array_map(static fn($v): string => preg_replace('/[^A-Za-z0-9_]/', '', (string) $v), $fields)));
if (count($fields) > 120) {
    json_response(['success' => false, 'error' => 'Too many fields selected.'], 422);
}
$count = max(1, min($count, 10000));

$startTs = iso_to_timestamp($start);
$endTs = iso_to_timestamp($end);
if ($startTs === null || $endTs === null || $endTs <= $startTs) {
    json_response(['success' => false, 'error' => 'Invalid time range.'], 422);
}
if (($endTs - $startTs) > 3600) {
    json_response(['success' => false, 'error' => 'Cloudflare Logpull allows a maximum time range of 1 hour per request.'], 422);
}
if ($endTs > (time() - 300)) {
    json_response(['success' => false, 'error' => 'For Logpull, the end time must be at least 5 minutes in the past.'], 422);
}
if ($startTs < (time() - 7 * 86400)) {
    json_response(['success' => false, 'error' => 'This tool limits Logpull to the last 7 days.'], 422);
}

$query = [
    'start' => gmdate('Y-m-d\TH:i:s\Z', $startTs),
    'end' => gmdate('Y-m-d\TH:i:s\Z', $endTs),
    'count' => $count,
    'timestamps' => 'rfc3339',
];
if ($fields) {
    $query['fields'] = implode(',', $fields);
}

$response = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/logs/received', $token, null, $query);
if (!$response['ok']) {
    json_response(['success' => false, 'error' => cf_error_message($response, 'Logpull request failed.')], $response['status'] ?: 502);
}

$rows = [];
$raw = trim((string) $response['raw']);
if ($raw !== '') {
    foreach (preg_split('/\R/', $raw) as $line) {
        $decoded = json_decode(trim($line), true);
        if (is_array($decoded)) {
            $rows[] = $decoded;
        }
    }
}

json_response([
    'success' => true,
    'source' => 'logpull',
    'count' => count($rows),
    'range' => ['start' => $query['start'], 'end' => $query['end']],
    'rows' => $rows,
]);
