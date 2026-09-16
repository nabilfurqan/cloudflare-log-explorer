(() => {
  'use strict';

  const API = 'https://api.cloudflare.com/client/v4';
  const WIB_OFFSET_MS = 7 * 60 * 60 * 1000;
  const $ = (id) => document.getElementById(id);
  const runButton = $('runQueryBtn');
  const queryActions = document.querySelector('.query-actions');
  const resultsSection = $('resultsSection');
  const resultMeta = $('resultMeta');
  const exportsBox = document.querySelector('.exports');
  if (!runButton || !queryActions) return;

  let language = 'curl';
  let snapshot = null;
  let lastSuccessful = null;
  let copyTimer = null;

  const showButton = button('Show Script', 'showQueryScriptBtn');
  runButton.insertAdjacentElement('afterend', showButton);
  const panel = makePanel();
  queryActions.insertAdjacentElement('afterend', panel);

  let resultButton = null;
  if (exportsBox) {
    resultButton = button('Script', 'resultQueryScriptBtn');
    exportsBox.appendChild(resultButton);
  }

  showButton.addEventListener('click', () => openCurrent(false));
  if (resultButton) resultButton.addEventListener('click', () => {
    const snap = lastSuccessful || currentSnapshot();
    if (snap.mode === 'configuration') return openExistingConfigGenerator();
    openPanel(snap, true);
  });

  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => panel.classList.add('hidden')));

  if (resultsSection) {
    new MutationObserver(() => {
      if (!resultsSection.classList.contains('hidden') && resultMeta?.textContent.trim() && resultMeta.textContent.trim() !== '—') {
        lastSuccessful = currentSnapshot();
      }
    }).observe(resultsSection, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['class'] });
  }

  function button(text, id) {
    const el = document.createElement('button');
    el.type = 'button';
    el.id = id;
    el.className = 'ghost';
    el.textContent = text;
    return el;
  }

  function currentMode() {
    return document.querySelector('.tab.active')?.dataset.mode || 'security';
  }

  function isoFromWib(value) {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value || '');
    if (!m) return '';
    const [, y, mo, d, h, mi] = m;
    const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, 0) - WIB_OFFSET_MS;
    return new Date(ms).toISOString().replace('.000Z', 'Z');
  }

  function currentSnapshot() {
    return {
      mode: currentMode(),
      zoneId: $('zoneSelect')?.value?.trim() || 'YOUR_ZONE_ID',
      zoneLabel: $('zoneSelect')?.selectedOptions?.[0]?.textContent?.trim() || 'Selected zone',
      start: isoFromWib($('startTime')?.value || '') || 'START_UTC',
      end: isoFromWib($('endTime')?.value || '') || 'END_UTC',
      limit: Number($('rowLimit')?.value || 1000) || 1000,
      fields: [...document.querySelectorAll('#fieldsGrid input:checked')].map((x) => x.value)
    };
  }

  function openCurrent(fromResults) {
    const mode = currentMode();
    if (mode === 'configuration') return openExistingConfigGenerator();
    openPanel(currentSnapshot(), fromResults);
  }

  function openExistingConfigGenerator() {
    const old = $('scriptGenerator');
    if (!old) return;
    old.classList.remove('hidden');
    old.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function makePanel() {
    const wrap = document.createElement('section');
    wrap.className = 'script-generator hidden';
    wrap.id = 'queryScriptGenerator';
    wrap.innerHTML = `
      <div class="script-generator-head">
        <div><span id="queryScriptEyebrow">Runnable API script</span><b id="queryScriptTitle">Cloudflare API</b></div>
        <strong class="status-pill unknown">Read only</strong>
      </div>
      <p class="script-generator-intro" id="queryScriptIntro"></p>
      <div class="script-steps" id="queryScriptSteps"></div>
      <div class="script-tabs" role="tablist">
        <button type="button" data-query-script="curl" class="active">cURL</button>
        <button type="button" data-query-script="bash">Bash</button>
        <button type="button" data-query-script="jq">Bash + jq</button>
        <button type="button" data-query-script="python">Python</button>
      </div>
      <div class="script-toolbar">
        <small id="queryScriptRequirement"></small>
        <div>
          <button type="button" class="ghost" id="copyQueryEnv">Copy env setup</button>
          <button type="button" class="ghost" id="copyQueryScript">Copy script</button>
          <button type="button" class="ghost" id="downloadQueryScript">Download</button>
          <button type="button" class="ghost" id="closeQueryScript">Close</button>
        </div>
      </div>
      <pre class="script-code"><code id="queryGeneratedScript"></code></pre>
      <small class="script-note" id="queryScriptNote"></small>
    `;

    wrap.querySelectorAll('[data-query-script]').forEach((tab) => tab.addEventListener('click', () => {
      language = tab.dataset.queryScript;
      wrap.querySelectorAll('[data-query-script]').forEach((x) => x.classList.toggle('active', x === tab));
      render();
    }));
    wrap.querySelector('#copyQueryEnv').addEventListener('click', (e) => snapshot && copy(env(snapshot), e.currentTarget));
    wrap.querySelector('#copyQueryScript').addEventListener('click', (e) => snapshot && copy(generate(snapshot, language), e.currentTarget));
    wrap.querySelector('#downloadQueryScript').addEventListener('click', () => snapshot && download(generate(snapshot, language), filename(snapshot, language)));
    wrap.querySelector('#closeQueryScript').addEventListener('click', () => wrap.classList.add('hidden'));
    return wrap;
  }

  function openPanel(snap, fromResults) {
    snapshot = snap;
    panel.dataset.fromResults = fromResults ? '1' : '0';
    render();
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function env(s) {
    return `export CF_API_TOKEN='YOUR_API_TOKEN'\nexport ZONE_ID='${s.zoneId}'`;
  }

  function requirement(type) {
    if (type === 'curl') return 'Requires: curl';
    if (type === 'bash') return 'Requires: bash + curl';
    if (type === 'jq') return 'Requires: bash + curl + jq';
    return 'Requires: Python 3 standard library only';
  }

  function render() {
    if (!snapshot) return;
    const security = snapshot.mode === 'security';
    panel.querySelector('#queryScriptEyebrow').textContent = panel.dataset.fromResults === '1' ? 'Reproducible result script' : 'Runnable API script';
    panel.querySelector('#queryScriptTitle').textContent = `${security ? 'Security Events' : 'HTTP Logpull'} · ${snapshot.zoneLabel}`;
    panel.querySelector('#queryScriptIntro').textContent = `${panel.dataset.fromResults === '1' ? 'Reproduce the latest successful query.' : 'Generated from the current Explore parameters.'} The active API Token is never inserted into the code.`;
    panel.querySelector('#queryScriptRequirement').textContent = requirement(language);
    panel.querySelector('#queryGeneratedScript').textContent = generate(snapshot, language);
    panel.querySelector('#queryScriptNote').textContent = security
      ? 'Uses GraphQL firewallEventsAdaptive. WIB input times are converted to UTC automatically.'
      : 'Requires Logs Read and enabled retention. Maximum range is 1 hour; end time must be at least 5 minutes in the past. Logpull returns NDJSON.';
    steps(security);
  }

  function steps(security) {
    const box = panel.querySelector('#queryScriptSteps');
    const rows = [
      ['1', 'Prepare API Token', security ? 'Use Analytics Read access for the selected zone.' : 'Use Logs Read access and confirm Logpull retention is enabled.'],
      ['2', 'Set token safely', 'Export CF_API_TOKEN. The actual token is never embedded in this page or download.'],
      ['3', 'Set ZONE_ID', 'The selected Zone ID is prefilled in the environment setup.'],
      ['4', 'Run the script', language === 'python' ? 'Save the file and run python3 <file>.py.' : language === 'curl' ? 'Paste directly into a terminal.' : 'Save as .sh, chmod +x, then execute it.'],
      ['5', 'Check output', security ? 'HTTP 2xx returns GraphQL JSON data.' : 'Successful output is newline-delimited JSON (NDJSON).']
    ];
    box.innerHTML = '';
    rows.forEach(([n, title, text]) => {
      const row = document.createElement('div');
      row.className = 'script-step';
      const mark = document.createElement('span'); mark.textContent = n;
      const content = document.createElement('div');
      const b = document.createElement('b'); b.textContent = title;
      const small = document.createElement('small'); small.textContent = text;
      content.append(b, small); row.append(mark, content); box.appendChild(row);
    });
  }

  function generate(s, type) {
    return s.mode === 'security' ? securityScript(s, type) : logpullScript(s, type);
  }

  function gqlQuery() {
    return 'query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: Int!) { viewer { zones(filter: { zoneTag: $zoneTag }) { firewallEventsAdaptive(filter: $filter, limit: $limit, orderBy: [datetime_DESC]) { action clientAsn clientCountryName clientIP clientRequestHTTPHost clientRequestPath datetime description kind originatorRayName ruleId source userAgent } } } }';
  }

  function gqlPayload(s, zone) {
    return JSON.stringify({ query: gqlQuery(), variables: { zoneTag: zone, limit: s.limit, filter: { datetime_geq: s.start, datetime_leq: s.end } } });
  }

  function securityScript(s, type) {
    if (type === 'curl') {
      return `${env(s)}\n\ncurl -sS -X POST "${API}/graphql" \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n  -H "Content-Type: application/json" \\\n  --data '${gqlPayload(s, s.zoneId)}'`;
    }
    if (type === 'bash' || type === 'jq') {
      const output = type === 'jq' ? `jq '.data.viewer.zones[0].firewallEventsAdaptive // .' "$TMP"` : 'cat "$TMP"';
      return `#!/usr/bin/env bash\nset -euo pipefail\n${type === 'jq' ? "command -v jq >/dev/null 2>&1 || { echo 'jq is required.' >&2; exit 1; }\n" : ''}: "\${CF_API_TOKEN:?Set CF_API_TOKEN first}"\nZONE_ID="\${ZONE_ID:-${s.zoneId}}"\nTMP="$(mktemp)"\ntrap 'rm -f "$TMP"' EXIT\nPAYLOAD='${gqlPayload(s, '__ZONE_ID__')}'\nPAYLOAD="\${PAYLOAD/__ZONE_ID__/\$ZONE_ID}"\nHTTP_CODE="$(curl -sS -o "$TMP" -w '%{http_code}' -X POST "${API}/graphql" \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n  -H "Content-Type: application/json" \\\n  --data "$PAYLOAD")"\nif [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then\n  echo "Security Events request failed. HTTP $HTTP_CODE" >&2\n  cat "$TMP" >&2\n  exit 1\nfi\n${output}`;
    }
    return `#!/usr/bin/env python3\nimport json, os, sys, urllib.error, urllib.request\ntoken = os.environ.get("CF_API_TOKEN")\nif not token: sys.exit("Set CF_API_TOKEN first")\nzone_id = os.environ.get("ZONE_ID", "${s.zoneId}")\npayload = json.dumps({"query": ${JSON.stringify(gqlQuery())}, "variables": {"zoneTag": zone_id, "limit": ${s.limit}, "filter": {"datetime_geq": "${s.start}", "datetime_leq": "${s.end}"}}}).encode()\nreq = urllib.request.Request("${API}/graphql", data=payload, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")\ntry:\n    with urllib.request.urlopen(req, timeout=30) as r: data = json.load(r)\nexcept urllib.error.HTTPError as e:\n    print(e.read().decode("utf-8", errors="replace"), file=sys.stderr); sys.exit(f"HTTP {e.code}")\nrows = data.get("data", {}).get("viewer", {}).get("zones", [{}])[0].get("firewallEventsAdaptive", [])\nprint(json.dumps(rows, indent=2, ensure_ascii=False))`;
  }

  function logpullArgs(s) {
    const args = [
      `  --data-urlencode "start=${s.start}"`,
      `  --data-urlencode "end=${s.end}"`,
      `  --data-urlencode "count=${s.limit}"`,
      '  --data-urlencode "timestamps=rfc3339"'
    ];
    if (s.fields.length) args.push(`  --data-urlencode "fields=${s.fields.join(',')}"`);
    return args.join(' \\\n');
  }

  function logpullScript(s, type) {
    const fields = s.fields.join(',');
    if (type === 'curl') {
      return `${env(s)}\n\ncurl -sS -G \\\n  "${API}/zones/\${ZONE_ID}/logs/received" \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n${logpullArgs(s)}`;
    }
    if (type === 'bash' || type === 'jq') {
      const output = type === 'jq'
        ? `while IFS= read -r line; do\n  [[ -z "$line" ]] && continue\n  printf '%s\\n' "$line" | jq .\ndone < "$TMP"`
        : 'cat "$TMP"';
      return `#!/usr/bin/env bash\nset -euo pipefail\n${type === 'jq' ? "command -v jq >/dev/null 2>&1 || { echo 'jq is required.' >&2; exit 1; }\n" : ''}: "\${CF_API_TOKEN:?Set CF_API_TOKEN first}"\nZONE_ID="\${ZONE_ID:-${s.zoneId}}"\nTMP="$(mktemp)"\ntrap 'rm -f "$TMP"' EXIT\nHTTP_CODE="$(curl -sS -o "$TMP" -w '%{http_code}' -G \\\n  "${API}/zones/\${ZONE_ID}/logs/received" \\\n  -H "Authorization: Bearer \${CF_API_TOKEN}" \\\n${logpullArgs(s)})"\nif [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then\n  echo "Logpull request failed. HTTP $HTTP_CODE" >&2\n  cat "$TMP" >&2\n  exit 1\nfi\n${output}`;
    }
    return `#!/usr/bin/env python3\nimport json, os, sys, urllib.error, urllib.parse, urllib.request\ntoken = os.environ.get("CF_API_TOKEN")\nif not token: sys.exit("Set CF_API_TOKEN first")\nzone_id = os.environ.get("ZONE_ID", "${s.zoneId}")\nparams = {"start": "${s.start}", "end": "${s.end}", "count": "${s.limit}", "timestamps": "rfc3339"}${fields ? `\nparams["fields"] = "${fields}"` : ''}\nurl = "${API}/zones/{}/logs/received?{}".format(zone_id, urllib.parse.urlencode(params))\nreq = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method="GET")\ntry:\n    with urllib.request.urlopen(req, timeout=30) as r: raw = r.read().decode("utf-8", errors="replace")\nexcept urllib.error.HTTPError as e:\n    print(e.read().decode("utf-8", errors="replace"), file=sys.stderr); sys.exit(f"HTTP {e.code}")\nfor line in raw.splitlines():\n    if not line.strip(): continue\n    try: print(json.dumps(json.loads(line), indent=2, ensure_ascii=False))\n    except json.JSONDecodeError: print(line)`;
  }

  function filename(s, type) {
    const base = s.mode === 'security' ? 'cf-security-events' : 'cf-logpull';
    return type === 'python' ? `${base}.py` : type === 'curl' ? `${base}-curl.sh` : `${base}.sh`;
  }

  function download(text, name) {
    const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }

  async function copy(text, btn) {
    const original = btn.textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const area = document.createElement('textarea'); area.value = text; area.style.position = 'fixed'; area.style.opacity = '0'; document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove();
      }
      btn.textContent = 'Copied ✓';
    } catch (_) { btn.textContent = 'Copy failed'; }
    clearTimeout(copyTimer); copyTimer = setTimeout(() => { btn.textContent = original; }, 1600);
  }
})();
