(() => {
  'use strict';

  const permissions = {
    'waf-custom': {
      scope: 'Zone',
      permission: ['Zone', 'Zone WAF', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect WAF Custom Rules for the selected zone.'
    },
    'waf-managed': {
      scope: 'Zone',
      permission: ['Zone', 'Zone WAF', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect the Managed WAF entrypoint and overrides for the selected zone.'
    },
    'rate-limiting': {
      scope: 'Zone',
      permission: ['Zone', 'Zone WAF', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect rate limiting rules exposed through the Rulesets API.'
    },
    'transform-request': {
      scope: 'Zone',
      permission: ['Zone', 'Transform Rules', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect request transform rules.'
    },
    'transform-response': {
      scope: 'Zone',
      permission: ['Zone', 'Transform Rules', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect response header transform rules.'
    },
    'configuration-rules': {
      scope: 'Zone',
      permission: ['Zone', 'Config Rules / Config Settings', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Cloudflare may display this permission as Config Rules Read or Config Settings Read depending on the dashboard naming.'
    },
    'gateway': {
      scope: 'Account',
      permission: ['Account', 'Zero Trust', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Required for Gateway DNS, HTTP, and Network policies.'
    },
    'access': {
      scope: 'Account',
      permission: ['Account', 'Access: Apps and Policies', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Required to read Access applications and their policies.'
    },
    'warp': {
      scope: 'Account',
      permission: ['Account', 'Zero Trust', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Required to inspect WARP device settings profiles.'
    },
    'posture': {
      scope: 'Account',
      permission: ['Account', 'Zero Trust', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Required to inspect device posture rules.'
    },
    'gateway-lists': {
      scope: 'Account',
      permission: ['Account', 'Zero Trust', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Required to inspect Gateway lists used by Zero Trust policies.'
    },
    'tunnels': {
      scope: 'Account',
      permission: ['Account', 'Cloudflare Tunnel', 'Read'],
      resource: ['Include', 'Specific account'],
      note: 'Cloudflare may also expose an equivalent Cloudflare One Connectors / cloudflared read permission.'
    },
    'dns': {
      scope: 'Zone',
      permission: ['Zone', 'DNS', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect DNS records. Keep the token restricted to the selected zone.'
    },
    'load-balancers': {
      scope: 'Zone',
      permission: ['Zone', 'Load Balancers', 'Read'],
      resource: ['Include', 'Specific zone'],
      note: 'Required to inspect zone load balancers. Account-level pools or monitors can require additional read permissions.'
    }
  };

  const $ = (id) => document.getElementById(id);
  const dataset = $('configDataset');
  const guide = $('permissionGuide');
  const results = $('resultsSection');
  const queryMessage = $('queryMessage');
  const runButton = $('runQueryBtn');
  const zoneSelect = $('zoneSelect');
  const accountInput = $('configAccountId');

  if (!dataset || !guide || !results || !queryMessage || !runButton) return;

  let verificationState = 'unknown';
  let copyResetTimer = null;

  injectStyles();

  function injectStyles() {
    if ($('permissionAssistStyles')) return;
    const style = document.createElement('style');
    style.id = 'permissionAssistStyles';
    style.textContent = `
      .permission-assist{border:1px solid #263752;background:linear-gradient(180deg,#0d1a2e,#0a1627);border-radius:14px;padding:16px;margin-bottom:14px}
      .permission-assist-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px}
      .permission-assist-head span{display:block;color:#8fa1ba;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
      .permission-assist-head b{font-size:14px;color:#f4f7fb}
      .permission-path-label{font-size:10px;color:#8fa1ba;margin-bottom:6px}
      .permission-path{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:12px}
      .permission-choice{display:inline-flex;align-items:center;min-height:34px;padding:8px 11px;border:1px solid #334863;border-radius:9px;background:#091426;color:#e9eff8;font-size:11px;font-weight:750}
      .permission-arrow{color:#6f829d;font-size:12px}
      .permission-actions{display:flex;gap:7px;flex-wrap:wrap;margin:2px 0 14px}
      .permission-actions .ghost{padding:7px 10px;font-size:10px}
      .permission-resource{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:8px;margin-bottom:14px}
      .permission-resource-item{border:1px solid #1e2c42;border-radius:10px;background:#0b1729;padding:10px;min-width:0}
      .permission-resource-item span{display:block;color:#8093ad;font-size:9px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
      .permission-resource-item b{display:block;color:#dce6f3;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
      .permission-checklist{display:grid;gap:7px;margin-bottom:12px}
      .permission-check{display:grid;grid-template-columns:20px 1fr;gap:9px;align-items:start;border:1px solid #1e2c42;border-radius:9px;padding:9px 10px;background:#0a1627}
      .permission-check-icon{width:18px;height:18px;border-radius:5px;display:grid;place-items:center;border:1px solid #40516a;color:#8fa1ba;font-size:10px;font-weight:900;margin-top:1px}
      .permission-check.good .permission-check-icon{border-color:rgba(60,207,145,.45);background:rgba(60,207,145,.10);color:#77e0b2}
      .permission-check.bad .permission-check-icon{border-color:rgba(255,107,107,.45);background:rgba(255,107,107,.10);color:#ff9d9d}
      .permission-check b{display:block;font-size:10px;color:#d9e2ef;margin-bottom:2px}
      .permission-check small{display:block;color:#8fa1ba;font-size:9px;line-height:1.45}
      .permission-note{display:block;color:#91a5bf;font-size:10px;line-height:1.55;border-top:1px solid #1e2c42;padding-top:11px}
      .status-pill.warn{color:#ffe19a;border-color:rgba(247,201,72,.35);background:rgba(247,201,72,.08)}
      @media(max-width:700px){.permission-resource{grid-template-columns:1fr}.permission-assist-head{align-items:flex-start}.permission-choice{width:100%}.permission-arrow{display:none}}
    `;
    document.head.appendChild(style);
  }

  function configurationActive() {
    const tab = document.querySelector('.tab[data-mode="configuration"]');
    return !!tab && tab.classList.contains('active');
  }

  function selectedPermission() {
    return permissions[dataset.value] || {
      scope: 'Read only',
      permission: ['Matching resource', 'Read permission'],
      resource: ['Include', 'Specific resource'],
      note: 'Use the matching Cloudflare read permission for this dataset.'
    };
  }

  function selectedDatasetName() {
    const option = dataset.options[dataset.selectedIndex];
    return option ? option.textContent.trim() : 'Configuration';
  }

  function selectedResource() {
    const item = selectedPermission();
    if (item.scope === 'Account') {
      const id = accountInput ? accountInput.value.trim() : '';
      return id || 'Selected Account ID';
    }
    if (zoneSelect && zoneSelect.selectedIndex >= 0) {
      const text = zoneSelect.options[zoneSelect.selectedIndex].textContent.trim();
      return text || zoneSelect.value || 'Selected Zone';
    }
    return 'Selected Zone';
  }

  function permissionText(item = selectedPermission()) {
    return item.permission.join(' → ');
  }

  function resourceText(item = selectedPermission()) {
    return `${item.resource.join(' → ')} → ${selectedResource()}`;
  }

  function statusInfo() {
    if (verificationState === 'available') return { text: 'Verified', cls: 'good' };
    if (verificationState === 'missing') return { text: 'Action required', cls: 'bad' };
    return { text: 'Not verified', cls: 'warn' };
  }

  function stepClass(type) {
    if (verificationState === 'available') return 'good';
    if (verificationState === 'missing' && (type === 'permission' || type === 'resource')) return 'bad';
    return '';
  }

  function renderGuide(state = verificationState) {
    verificationState = state;
    const item = selectedPermission();
    const status = statusInfo();
    const datasetName = selectedDatasetName();
    const permission = permissionText(item);
    const resource = resourceText(item);
    const failureText = verificationState === 'missing'
      ? `The last request was rejected. Add the permission and resource scope below, save the token, reconnect, then retry.`
      : `These are the values to select when creating or editing the Cloudflare API Token.`;

    guide.className = 'permission-assist';
    guide.innerHTML = '';

    const head = document.createElement('div');
    head.className = 'permission-assist-head';
    const title = document.createElement('div');
    const eyebrow = document.createElement('span');
    eyebrow.textContent = 'Required API Token permission';
    const strong = document.createElement('b');
    strong.textContent = datasetName;
    title.append(eyebrow, strong);
    const pill = document.createElement('strong');
    pill.className = `status-pill ${status.cls}`;
    pill.textContent = status.text;
    head.append(title, pill);

    const label = document.createElement('div');
    label.className = 'permission-path-label';
    label.textContent = 'In Cloudflare API Token → Permissions, select:';

    const path = document.createElement('div');
    path.className = 'permission-path';
    item.permission.forEach((part, index) => {
      const choice = document.createElement('span');
      choice.className = 'permission-choice';
      choice.textContent = part;
      path.appendChild(choice);
      if (index < item.permission.length - 1) {
        const arrow = document.createElement('span');
        arrow.className = 'permission-arrow';
        arrow.textContent = '→';
        path.appendChild(arrow);
      }
    });

    const actions = document.createElement('div');
    actions.className = 'permission-actions';
    const copyPermission = document.createElement('button');
    copyPermission.type = 'button';
    copyPermission.className = 'ghost';
    copyPermission.textContent = 'Copy permission';
    copyPermission.addEventListener('click', () => copyText(permission, copyPermission));
    const copySetup = document.createElement('button');
    copySetup.type = 'button';
    copySetup.className = 'ghost';
    copySetup.textContent = 'Copy full setup';
    copySetup.addEventListener('click', () => copyText(`Permission: ${permission}\nResources: ${resource}`, copySetup));
    const openTokens = document.createElement('a');
    openTokens.className = 'ghost';
    openTokens.href = 'https://dash.cloudflare.com/profile/api-tokens';
    openTokens.target = '_blank';
    openTokens.rel = 'noopener noreferrer';
    openTokens.textContent = 'Open Cloudflare API Tokens';
    openTokens.style.textDecoration = 'none';
    actions.append(copyPermission, copySetup, openTokens);

    const resources = document.createElement('div');
    resources.className = 'permission-resource';
    resources.append(
      resourceCard('Permission', permission),
      resourceCard('Account / Zone Resources', resource)
    );

    const checklist = document.createElement('div');
    checklist.className = 'permission-checklist';
    checklist.append(
      checkRow(stepClass('permission'), verificationState === 'available' ? '✓' : verificationState === 'missing' ? '!' : '1', 'Permission', `Add ${permission}.`),
      checkRow(stepClass('resource'), verificationState === 'available' ? '✓' : verificationState === 'missing' ? '!' : '2', 'Resource scope', `Set ${resource}.`),
      checkRow(verificationState === 'available' ? 'good' : '', verificationState === 'available' ? '✓' : '3', 'Reconnect token', 'After saving the API Token in Cloudflare, click Disconnect & Clear Token and connect again using the updated token.'),
      checkRow(verificationState === 'available' ? 'good' : '', verificationState === 'available' ? '✓' : '4', 'Verify', verificationState === 'available' ? 'The selected dataset loaded successfully.' : 'Run Scan Access, then load this dataset. Exact access is confirmed only when the dataset request succeeds.')
    );

    const note = document.createElement('small');
    note.className = 'permission-note';
    note.textContent = `${failureText} ${item.note}`;

    guide.append(head, label, path, actions, resources, checklist, note);
  }

  function resourceCard(label, value) {
    const wrap = document.createElement('div');
    wrap.className = 'permission-resource-item';
    const span = document.createElement('span');
    span.textContent = label;
    const b = document.createElement('b');
    b.textContent = value;
    b.title = value;
    wrap.append(span, b);
    return wrap;
  }

  function checkRow(cls, icon, title, text) {
    const row = document.createElement('div');
    row.className = `permission-check ${cls}`.trim();
    const mark = document.createElement('span');
    mark.className = 'permission-check-icon';
    mark.textContent = icon;
    const copy = document.createElement('div');
    const b = document.createElement('b');
    b.textContent = title;
    const small = document.createElement('small');
    small.textContent = text;
    copy.append(b, small);
    row.append(mark, copy);
    return row;
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
    clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => { button.textContent = original; }, 1600);
  }

  function clearStaleResults() {
    results.classList.add('hidden');
    const head = document.querySelector('#resultsTable thead');
    const body = document.querySelector('#resultsTable tbody');
    if (head) head.innerHTML = '';
    if (body) body.innerHTML = '';
    if ($('visibleRows')) $('visibleRows').textContent = '0 rows';
    if ($('resultMeta')) $('resultMeta').textContent = '—';
    if ($('metricTotal')) $('metricTotal').textContent = '0';
    if ($('metricBlocked')) $('metricBlocked').textContent = '0';
    if ($('metricChallenge')) $('metricChallenge').textContent = '0';
    if ($('metricSource')) $('metricSource').textContent = '—';
  }

  dataset.addEventListener('change', () => {
    verificationState = 'unknown';
    clearStaleResults();
    renderGuide('unknown');
  });

  if (zoneSelect) {
    zoneSelect.addEventListener('change', () => renderGuide(verificationState));
  }
  if (accountInput) {
    accountInput.addEventListener('input', () => renderGuide(verificationState));
  }

  runButton.addEventListener('click', () => {
    if (!configurationActive()) return;
    clearStaleResults();
  }, true);

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      if (tab.dataset.mode === 'configuration') renderGuide(verificationState);
    });
  });

  const observer = new MutationObserver(() => {
    if (!configurationActive()) return;
    const text = queryMessage.textContent || '';
    const isError = queryMessage.classList.contains('error');
    const isSuccess = queryMessage.classList.contains('success');

    if (isError) {
      clearStaleResults();
      if (/HTTP\s*(401|403)|authentication error|permission|not authorized|unauthorized|forbidden/i.test(text)) {
        renderGuide('missing');
      }
      return;
    }

    if (isSuccess && /Query completed:/i.test(text)) {
      renderGuide('available');
    }
  });

  observer.observe(queryMessage, {
    childList: true,
    characterData: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['class']
  });

  renderGuide('unknown');
})();
