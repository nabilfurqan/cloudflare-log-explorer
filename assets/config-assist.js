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
    if (document.querySelector('link[data-permission-assist]')) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'assets/permission-assist.css?v=1';
    link.dataset.permissionAssist = '1';
    document.head.appendChild(link);
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
      ? 'The last request was rejected. Add the permission and resource scope below, save the token, reconnect, then retry.'
      : 'These are the values to select when creating or editing the Cloudflare API Token.';

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
