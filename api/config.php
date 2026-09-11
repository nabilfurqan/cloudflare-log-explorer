<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/cloudflare.php';
bootstrap_session();
require_csrf();
rate_limit_or_reject('config', 30, 60);
$token = require_token();
$data = read_json_body();

$dataset = trim((string) ($data['dataset'] ?? ''));
$zoneId = trim((string) ($data['zoneId'] ?? ''));
$accountId = trim((string) ($data['accountId'] ?? ''));

$definitions = [
    'waf-custom' => ['scope' => 'zone', 'label' => 'WAF Custom Rules', 'phase' => 'http_request_firewall_custom'],
    'waf-managed' => ['scope' => 'zone', 'label' => 'Managed WAF', 'phase' => 'http_request_firewall_managed'],
    'rate-limiting' => ['scope' => 'zone', 'label' => 'Rate Limiting Rules', 'phase' => 'http_ratelimit'],
    'transform-request' => ['scope' => 'zone', 'label' => 'Request Transform Rules', 'phase' => 'http_request_transform'],
    'transform-response' => ['scope' => 'zone', 'label' => 'Response Header Transform Rules', 'phase' => 'http_response_headers_transform'],
    'configuration-rules' => ['scope' => 'zone', 'label' => 'Configuration Rules', 'phase' => 'http_config_settings'],
    'dns' => ['scope' => 'zone', 'label' => 'DNS Records'],
    'load-balancers' => ['scope' => 'zone', 'label' => 'Load Balancers'],
    'gateway' => ['scope' => 'account', 'label' => 'Zero Trust Gateway Policies'],
    'access' => ['scope' => 'account', 'label' => 'Zero Trust Access Policies'],
    'warp' => ['scope' => 'account', 'label' => 'WARP Device Profiles'],
    'posture' => ['scope' => 'account', 'label' => 'Device Posture Rules'],
    'gateway-lists' => ['scope' => 'account', 'label' => 'Gateway Lists'],
    'tunnels' => ['scope' => 'account', 'label' => 'Cloudflare Tunnels'],
];

if (!isset($definitions[$dataset])) {
    json_response(['success' => false, 'error' => 'Unsupported configuration dataset.'], 422);
}

$definition = $definitions[$dataset];
if ($definition['scope'] === 'zone' && !valid_resource_id($zoneId)) {
    json_response(['success' => false, 'error' => 'A valid Zone ID is required for this dataset.'], 422);
}
if ($definition['scope'] === 'account' && !valid_resource_id($accountId)) {
    json_response(['success' => false, 'error' => 'A valid Account ID is required for this Zero Trust dataset.'], 422);
}

function config_fail(array $response, string $dataset, string $label): void
{
    $status = (int) ($response['status'] ?? 0);
    $hint = '';
    if ($status === 401 || $status === 403) {
        $hint = ' Check that the API Token has the required read-only permission for this module.';
    }
    json_response([
        'success' => false,
        'dataset' => $dataset,
        'status' => $status,
        'error' => cf_error_message($response, $label . ' request failed.') . $hint,
    ], $status ?: 502);
}

function normalize_ruleset_rows(array $ruleset, string $dataset): array
{
    $rows = [];
    $rules = $ruleset['rules'] ?? [];
    if (!is_array($rules)) {
        return $rows;
    }

    foreach ($rules as $index => $rule) {
        if (!is_array($rule)) {
            continue;
        }
        $rows[] = [
            'dataset' => $dataset,
            'ruleset_name' => (string) ($ruleset['name'] ?? ''),
            'phase' => (string) ($ruleset['phase'] ?? ''),
            'kind' => (string) ($ruleset['kind'] ?? ''),
            'order' => $index + 1,
            'rule_id' => (string) ($rule['id'] ?? ''),
            'ref' => (string) ($rule['ref'] ?? ''),
            'description' => (string) ($rule['description'] ?? ''),
            'action' => (string) ($rule['action'] ?? ''),
            'enabled' => array_key_exists('enabled', $rule) ? (bool) $rule['enabled'] : true,
            'expression' => (string) ($rule['expression'] ?? ''),
            'action_parameters' => json_compact($rule['action_parameters'] ?? null),
            'ratelimit' => json_compact($rule['ratelimit'] ?? null),
            'logging' => json_compact($rule['logging'] ?? null),
            'last_updated' => (string) ($rule['last_updated'] ?? ''),
            'version' => (string) ($rule['version'] ?? ''),
        ];
    }
    return $rows;
}

function list_result(array $response): array
{
    $result = $response['body']['result'] ?? [];
    return is_array($result) ? $result : [];
}

$rows = [];
$note = null;

if (isset($definition['phase'])) {
    $path = '/zones/' . rawurlencode($zoneId) . '/rulesets/phases/' . rawurlencode((string) $definition['phase']) . '/entrypoint';
    $response = cf_request('GET', $path, $token);
    if (!$response['ok']) {
        if ((int) ($response['status'] ?? 0) === 404) {
            json_response([
                'success' => true,
                'dataset' => $dataset,
                'label' => $definition['label'],
                'scope' => 'zone',
                'rows' => [],
                'count' => 0,
                'note' => 'No entry-point ruleset is configured for this phase.',
            ]);
        }
        config_fail($response, $dataset, $definition['label']);
    }
    $ruleset = $response['body']['result'] ?? [];
    $rows = is_array($ruleset) ? normalize_ruleset_rows($ruleset, $dataset) : [];
} elseif ($dataset === 'dns') {
    $response = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/dns_records', $token, null, ['per_page' => 500, 'page' => 1]);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $record) {
        if (!is_array($record)) continue;
        $rows[] = [
            'id' => (string) ($record['id'] ?? ''),
            'type' => (string) ($record['type'] ?? ''),
            'name' => (string) ($record['name'] ?? ''),
            'content' => (string) ($record['content'] ?? ''),
            'proxied' => $record['proxied'] ?? null,
            'ttl' => $record['ttl'] ?? null,
            'comment' => (string) ($record['comment'] ?? ''),
            'tags' => json_compact($record['tags'] ?? null),
            'created_on' => (string) ($record['created_on'] ?? ''),
            'modified_on' => (string) ($record['modified_on'] ?? ''),
        ];
    }
} elseif ($dataset === 'load-balancers') {
    $response = cf_request('GET', '/zones/' . rawurlencode($zoneId) . '/load_balancers', $token, null, ['per_page' => 100, 'page' => 1]);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $item) {
        if (!is_array($item)) continue;
        $rows[] = [
            'id' => (string) ($item['id'] ?? ''),
            'name' => (string) ($item['name'] ?? ''),
            'enabled' => $item['enabled'] ?? null,
            'proxied' => $item['proxied'] ?? null,
            'steering_policy' => (string) ($item['steering_policy'] ?? ''),
            'default_pools' => json_compact($item['default_pools'] ?? null),
            'fallback_pool' => (string) ($item['fallback_pool'] ?? ''),
            'region_pools' => json_compact($item['region_pools'] ?? null),
            'country_pools' => json_compact($item['country_pools'] ?? null),
            'session_affinity' => (string) ($item['session_affinity'] ?? ''),
            'created_on' => (string) ($item['created_on'] ?? ''),
            'modified_on' => (string) ($item['modified_on'] ?? ''),
        ];
    }
} elseif ($dataset === 'gateway') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/gateway/rules', $token);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $rule) {
        if (!is_array($rule)) continue;
        $rows[] = [
            'id' => (string) ($rule['id'] ?? ''),
            'name' => (string) ($rule['name'] ?? ''),
            'action' => (string) ($rule['action'] ?? ''),
            'enabled' => $rule['enabled'] ?? null,
            'precedence' => $rule['precedence'] ?? null,
            'description' => (string) ($rule['description'] ?? ''),
            'filters' => json_compact($rule['filters'] ?? null),
            'traffic' => (string) ($rule['traffic'] ?? ''),
            'identity' => (string) ($rule['identity'] ?? ''),
            'device_posture' => (string) ($rule['device_posture'] ?? ''),
            'rule_settings' => json_compact($rule['rule_settings'] ?? null),
            'created_at' => (string) ($rule['created_at'] ?? ''),
            'updated_at' => (string) ($rule['updated_at'] ?? ''),
        ];
    }
} elseif ($dataset === 'access') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/access/apps', $token, null, ['per_page' => 100, 'page' => 1]);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    $apps = list_result($response);
    $policyCalls = 0;
    foreach ($apps as $app) {
        if (!is_array($app)) continue;
        $appId = (string) ($app['id'] ?? '');
        $policies = $app['policies'] ?? null;
        if (!is_array($policies) && $appId !== '' && $policyCalls < 50) {
            $policyCalls++;
            $policyResp = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/access/apps/' . rawurlencode($appId) . '/policies', $token, null, ['per_page' => 100, 'page' => 1]);
            if ($policyResp['ok']) {
                $policies = list_result($policyResp);
            } else {
                $policies = [];
            }
        }
        if (!is_array($policies) || !$policies) {
            $rows[] = [
                'application' => (string) ($app['name'] ?? ''),
                'domain' => (string) ($app['domain'] ?? ''),
                'type' => (string) ($app['type'] ?? ''),
                'app_id' => $appId,
                'policy' => '',
                'decision' => '',
                'precedence' => null,
                'include' => '',
                'exclude' => '',
                'require' => '',
            ];
            continue;
        }
        foreach ($policies as $policy) {
            if (!is_array($policy)) continue;
            $rows[] = [
                'application' => (string) ($app['name'] ?? ''),
                'domain' => (string) ($app['domain'] ?? ''),
                'type' => (string) ($app['type'] ?? ''),
                'app_id' => $appId,
                'policy' => (string) ($policy['name'] ?? ''),
                'policy_id' => (string) ($policy['id'] ?? ''),
                'decision' => (string) ($policy['decision'] ?? ''),
                'precedence' => $policy['precedence'] ?? null,
                'include' => json_compact($policy['include'] ?? null),
                'exclude' => json_compact($policy['exclude'] ?? null),
                'require' => json_compact($policy['require'] ?? null),
                'session_duration' => (string) ($policy['session_duration'] ?? ''),
            ];
        }
    }
    if (count($apps) > 50) {
        $note = 'Policy expansion is limited to the first 50 applications in one request.';
    }
} elseif ($dataset === 'warp') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/devices/policies', $token);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $profile) {
        if (!is_array($profile)) continue;
        $rows[] = [
            'id' => (string) ($profile['id'] ?? ''),
            'name' => (string) ($profile['name'] ?? ''),
            'description' => (string) ($profile['description'] ?? ''),
            'precedence' => $profile['precedence'] ?? null,
            'match' => (string) ($profile['match'] ?? ''),
            'default' => $profile['default'] ?? null,
            'enabled' => $profile['enabled'] ?? null,
            'service_mode_v2' => json_compact($profile['service_mode_v2'] ?? null),
            'exclude_office_ips' => $profile['exclude_office_ips'] ?? null,
            'allow_mode_switch' => $profile['allow_mode_switch'] ?? null,
            'allow_updates' => $profile['allow_updates'] ?? null,
        ];
    }
} elseif ($dataset === 'posture') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/devices/posture', $token);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $rule) {
        if (!is_array($rule)) continue;
        $rows[] = [
            'id' => (string) ($rule['id'] ?? ''),
            'name' => (string) ($rule['name'] ?? ''),
            'type' => (string) ($rule['type'] ?? ''),
            'description' => (string) ($rule['description'] ?? ''),
            'schedule' => (string) ($rule['schedule'] ?? ''),
            'expiration' => (string) ($rule['expiration'] ?? ''),
            'input' => json_compact($rule['input'] ?? null),
        ];
    }
} elseif ($dataset === 'gateway-lists') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/gateway/lists', $token);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $list) {
        if (!is_array($list)) continue;
        $rows[] = [
            'id' => (string) ($list['id'] ?? ''),
            'name' => (string) ($list['name'] ?? ''),
            'type' => (string) ($list['type'] ?? ''),
            'count' => $list['count'] ?? null,
            'description' => (string) ($list['description'] ?? ''),
            'created_at' => (string) ($list['created_at'] ?? ''),
            'updated_at' => (string) ($list['updated_at'] ?? ''),
        ];
    }
} elseif ($dataset === 'tunnels') {
    $response = cf_request('GET', '/accounts/' . rawurlencode($accountId) . '/cfd_tunnel', $token, null, ['per_page' => 100, 'page' => 1, 'is_deleted' => 'false']);
    if (!$response['ok']) {
        config_fail($response, $dataset, $definition['label']);
    }
    foreach (list_result($response) as $tunnel) {
        if (!is_array($tunnel)) continue;
        $rows[] = [
            'id' => (string) ($tunnel['id'] ?? ''),
            'name' => (string) ($tunnel['name'] ?? ''),
            'status' => (string) ($tunnel['status'] ?? ''),
            'config_src' => (string) ($tunnel['config_src'] ?? ''),
            'remote_config' => $tunnel['remote_config'] ?? null,
            'connections' => is_array($tunnel['connections'] ?? null) ? count($tunnel['connections']) : null,
            'conns_active_at' => (string) ($tunnel['conns_active_at'] ?? ''),
            'conns_inactive_at' => (string) ($tunnel['conns_inactive_at'] ?? ''),
            'created_at' => (string) ($tunnel['created_at'] ?? ''),
        ];
    }
}

json_response([
    'success' => true,
    'source' => 'configuration',
    'dataset' => $dataset,
    'label' => $definition['label'],
    'scope' => $definition['scope'],
    'count' => count($rows),
    'rows' => $rows,
    'note' => $note,
]);
