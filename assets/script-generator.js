(() => {
  'use strict';

  const API = 'https://api.cloudflare.com/client/v4';

  const datasets = {
    'waf-custom': { scope: 'zone', label: 'WAF Custom Rules', path: '/zones/{id}/rulesets/phases/http_request_firewall_custom/entrypoint' },
    'waf-managed': { scope: 'zone', label: 'Managed WAF', path: '/zones/{id}/rulesets/phases/http_request_firewall_managed/entrypoint' },
    'rate-limiting': { scope: 'zone', label: 'Rate Limiting Rules', path: '/zones/{id}/rulesets/phases/http_ratelimit/entrypoint' },
    'transform-request': { scope: 'zone', label: 'Request Transform Rules', path: '/zones/{id}/rulesets/phases/http_request_transform/entrypoint' },
    'transform-response': { scope: 'zone', label: 'Response Header Transform Rules', path: '/zones/{id}/rulesets/phases/http_response_headers_transform/entrypoint' },
    'configuration-rules': { scope: 'zone', label: 'Configuration Rules', path: '/zones/{id}/rulesets/phases/http_config_settings/entrypoint' },
    'gateway': { scope: 'account', label: 'Gateway Policies', path: '/accounts/{id}/gateway/rules' },
    'access': { scope: 'account', label: 'Access Applications & Policies', path: '/accounts/{id}/access/apps?per_page=100&page=1', note: 'The generated command lists Access applications. Per-application policies are available at /accounts/{account_id}/access/apps/{app_id}/policies.' },
    'warp': { scope: 'account', label: 'WARP Device Profiles', path: '/accounts/{id}/devices/policies' },
    'posture': { scope: 'account', label: 'Device Posture Rules', path: '/accounts/{id}/devices/posture' },
    'gateway-lists': { scope: 'account', label: 'Gateway Lists', path: '/accounts/{id}/gateway/lists' },
    'tunnels': { scope: 'account', label: 'Cloudflare Tunnels', path: '/accounts/{id}/cfd_tunnel?is_deleted=false&per_page=100&page=1' },
    'dns': { scope: 'zone', label: 'DNS Records', path: '/zones/{id}/dns_records?per_page=500&page=1' },
    'load-balancers': { scope: 'zone', label: 'Load Balancers', path: '/zones/{id}/load_balancers?per_page=100&page=1' }
  };

  const $ = (id) => document.getElementById(id);
  const datasetSelect = $('configDataset');
  const zoneSelect = $('zoneSelect');
  const accountInput = $('configAccountId');
  const permissionGuide = $('permissionGuide');

  if (!datasetSelect || !permissionGuide) return;

  let language = 'curl';
  let copyTimer = null;

  injectStyles();
  const panel = buildPanel();
  permissionGuide.insertAdjacentElement('afterend', panel);
  render();

  datasetSelect.addEventListener('change', render);
  if (zoneSelect) zoneSelect.addEventListener('change', render);
  if (accountInput) accountInput.addEventListener('input', render);

  function injectStyles() {
    if (document.querySelector('link[data-script-generator]')) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'assets/script-generator.css?v=1';
    link.dataset.scriptGenerator = '1';
    document.head.appendChild(link);
  }

  function currentDataset() {
    return datasets[datasetSelect.value] || null;
  }

  function zoneId() {
    return zoneSelect ? zoneSelect.value.trim() : '';
  }

  function accountId() {
    return accountInput ? accountInput.value.trim() : '';
  }

  function resourceId(item) {
    return item.scope === 'account' ? accountId() : zoneId();
  }

  function variableName(item) {
    return item.scope === 'account' ? 'ACCOUNT_ID' : 'ZONE_ID';
  }

  function idFallback(item) {
    const id = resourceId(item);
    return id || (item.scope === 'account' ? 'YOUR_ACCOUNT_ID' : 'YOUR_ZONE_ID');
  }

  function shellPath(item) {
    const variable = variableName(item);
    return item.path.replace('{id}', `\${${variable}}`);
  }

  function pythonPath(item) {
    const variable = item.scope === 'account' ? 'account_id' : 'zone_id';
    return item.path.replace('{id}', `{${variable}}`);
  }

  function buildPanel() {
    const wrap = document.createElement('section');
    wrap.className = 'script-generator';
    wrap.id = 'scriptGenerator';
    wrap.innerHTML = `
      <div class="script-generator-head">
        <div><span>Runnable API example</span><b id="scriptGeneratorTitle">Cloudflare API</b></div>
        <strong class="status-pill unknown">Read only</strong>
      </div>
      <p class="script-generator-intro">Generate a command for the selected dataset. The API Token is never inserted into the code; scripts read it from the <code>CF_API_TOKEN</code> environment variable.</p>
      <div class="script-steps" id="scriptSteps"></div>
      <div class="script-tabs" role="tablist">
        <button type="button" data-script-language="curl" class="active">cURL</button>
        <button type="button" data-script-language="bash">Bash</button>
        <button type="button" data-script-language="jq">Bash + jq</button>
        <button type="button" data-script-language="python">Python</button>
      </div>
      <div class="script-toolbar">
        <small id="scriptRequirement"></small>
        <div>
          <button type="button" class="ghost" id="copyEnvSetup">Copy env setup</button>
          <button type="button" class="ghost" id="copyGeneratedScript">Copy script</button>
        </div>
      </div>
      <pre class="script-code"><code id="generatedScript"></code></pre>
      <small class="script-note" id="scriptDatasetNote"></small>
    `;

    wrap.querySelectorAll('[data-script-language]').forEach((button) => {
      button.addEventListener('click', () => {
        language = button.dataset.scriptLanguage;
        wrap.querySelectorAll('[data-script-language]').forEach((b) => b.classList.toggle('active', b === button));
        render();
      });
    });

    wrap.querySelector('#copyEnvSetup').addEventListener('click', (event) => {
      const item = currentDataset();
      if (!item) return;
      copyText(envSetup(item), event.currentTarget);
    });

    wrap.querySelector('#copyGeneratedScript').addEventListener('click', (event) => {
      const item = currentDataset();
      if (!item) return;
      copyText(generateScript(item, language), event.currentTarget);
    });

    return wrap;
  }

  function envSetup(item) {
    const variable = variableName(item);
    return `export CF_API_TOKEN='YOUR_API_TOKEN'\nexport ${variable}='${idFallback(item)}'`;
  }

  function generateScript(item, type) {
    const variable = variableName(item);
    const fallback = idFallback(item);
    const path = shellPath(item);
    const url = `${API}${path}`;

    if (type === 'curl') {
      return `${envSetup(item)}\n\ncurl -sS \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n  -H "Content-Type: application/json" \\\n  "${url}"`;
    }

    if (type === 'bash') {
      return `#!/usr/bin/env bash\nset -euo pipefail\n\n: "\${CF_API_TOKEN:?Set CF_API_TOKEN first}"\n${variable}="\${${variable}:-${fallback}}"\nURL="${url}"\nTMP="$(mktemp)"\ntrap 'rm -f "$TMP"' EXIT\n\nHTTP_CODE="$(curl -sS -o "$TMP" -w '%{http_code}' \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n  -H "Content-Type: application/json" \\\n  "$URL")"\n\nif [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then\n  echo "Cloudflare API request failed. HTTP $HTTP_CODE" >&2\n  cat "$TMP" >&2\n  exit 1\nfi\n\ncat "$TMP"\necho`;
    }

    if (type === 'jq') {
      return `#!/usr/bin/env bash\nset -euo pipefail\n\ncommand -v jq >/dev/null 2>&1 || { echo 'jq is required.' >&2; exit 1; }\n: "\${CF_API_TOKEN:?Set CF_API_TOKEN first}"\n${variable}="\${${variable}:-${fallback}}"\nURL="${url}"\nTMP="$(mktemp)"\ntrap 'rm -f "$TMP"' EXIT\n\nHTTP_CODE="$(curl -sS -o "$TMP" -w '%{http_code}' \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n  -H "Content-Type: application/json" \\\n  "$URL")"\n\nif [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then\n  echo "Cloudflare API request failed. HTTP $HTTP_CODE" >&2\n  jq . "$TMP" >&2 2>/dev/null || cat "$TMP" >&2\n  exit 1\nfi\n\njq '.result // .' "$TMP"`;
    }

    const pyVar = item.scope === 'account' ? 'account_id' : 'zone_id';
    const pyEnv = variableName(item);
    const pyPath = pythonPath(item);
    return `#!/usr/bin/env python3\nimport json\nimport os\nimport sys\nimport urllib.error\nimport urllib.request\n\ntoken = os.environ.get("CF_API_TOKEN")\nif not token:\n    sys.exit("Set CF_API_TOKEN first: export CF_API_TOKEN='YOUR_API_TOKEN'")\n\n${pyVar} = os.environ.get("${pyEnv}", "${fallback}")\nurl = f"${API}${pyPath}"\nrequest = urllib.request.Request(\n    url,\n    headers={\n        "Authorization": f"Bearer {token}",\n        "Content-Type": "application/json",\n        "User-Agent": "cloudnetworklab-cloudflare-explorer/1.0",\n    },\n    method="GET",\n)\n\ntry:\n    with urllib.request.urlopen(request, timeout=30) as response:\n        data = json.load(response)\nexcept urllib.error.HTTPError as exc:\n    body = exc.read().decode("utf-8", errors="replace")\n    print(f"Cloudflare API request failed. HTTP {exc.code}", file=sys.stderr)\n    print(body, file=sys.stderr)\n    sys.exit(1)\nexcept urllib.error.URLError as exc:\n    sys.exit(f"Request failed: {exc}")\n\nprint(json.dumps(data.get("result", data), indent=2, ensure_ascii=False))`;
  }

  function requirement(type) {
    if (type === 'curl') return 'Requires: curl';
    if (type === 'bash') return 'Requires: bash + curl';
    if (type === 'jq') return 'Requires: bash + curl + jq';
    return 'Requires: Python 3 (standard library only; no pip package required)';
  }

  function renderSteps(item) {
    const steps = panel.querySelector('#scriptSteps');
    const variable = variableName(item);
    const id = idFallback(item);
    steps.innerHTML = '';
    [
      ['1', 'Prepare API Token', 'Use the read-only permission and Account/Zone resource scope shown above.'],
      ['2', 'Set token safely', "Run export CF_API_TOKEN='YOUR_API_TOKEN'. Do not save the token inside the script."],
      ['3', `Set ${variable}`, `Run export ${variable}='${id}'.`],
      ['4', 'Run the example', language === 'python' ? 'Save as cf-fetch.py, then run: python3 cf-fetch.py' : language === 'curl' ? 'Paste the generated cURL commands directly into the terminal.' : 'Save as cf-fetch.sh, run chmod +x cf-fetch.sh, then ./cf-fetch.sh.'],
      ['5', 'Verify the response', 'A successful Cloudflare response has success: true. HTTP 401/403 usually means the token permission or resource scope is missing.']
    ].forEach(([number, title, text]) => {
      const row = document.createElement('div');
      row.className = 'script-step';
      const mark = document.createElement('span');
      mark.textContent = number;
      const copy = document.createElement('div');
      const b = document.createElement('b');
      b.textContent = title;
      const small = document.createElement('small');
      small.textContent = text;
      copy.append(b, small);
      row.append(mark, copy);
      steps.appendChild(row);
    });
  }

  function render() {
    const item = currentDataset();
    if (!item) {
      panel.classList.add('hidden');
      return;
    }
    panel.classList.remove('hidden');
    panel.querySelector('#scriptGeneratorTitle').textContent = item.label;
    panel.querySelector('#scriptRequirement').textContent = requirement(language);
    panel.querySelector('#generatedScript').textContent = generateScript(item, language);
    panel.querySelector('#scriptDatasetNote').textContent = item.note || 'The example performs a read-only GET request against the selected Cloudflare API resource.';
    renderSteps(item);
  }

  async function copyText(text, button) {
    const original = button.textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        area.remove();
      }
      button.textContent = 'Copied ✓';
    } catch (_) {
      button.textContent = 'Copy failed';
    }
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { button.textContent = original; }, 1600);
  }
})();
