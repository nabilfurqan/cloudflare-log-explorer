(() => {
  'use strict';

  const permissions = {
    'waf-custom': {
      scope: 'Zone',
      permission: 'Zone → Zone WAF → Read',
      note: 'Use this for WAF Custom Rules and keep the token scoped only to the required zone.'
    },
    'waf-managed': {
      scope: 'Zone',
      permission: 'Zone → Zone WAF → Read',
      note: 'Required to inspect the zone Managed WAF entrypoint and overrides.'
    },
    'rate-limiting': {
      scope: 'Zone',
      permission: 'Zone → Zone WAF → Read',
      note: 'Required to inspect rate limiting rules exposed through the Rulesets API.'
    },
    'transform-request': {
      scope: 'Zone',
      permission: 'Zone → Transform Rules → Read',
      note: 'Required to inspect request transform rules.'
    },
    'transform-response': {
      scope: 'Zone',
      permission: 'Zone → Transform Rules → Read',
      note: 'Required to inspect response header transform rules.'
    },
    'configuration-rules': {
      scope: 'Zone',
      permission: 'Zone → Config Rules / Config Settings → Read',
      note: 'Cloudflare may display this permission as Config Rules Read or Config Settings Read depending on the dashboard/API naming.'
    },
    'gateway': {
      scope: 'Account',
      permission: 'Account → Zero Trust → Read',
      note: 'Required for Gateway DNS, HTTP, and Network policies.'
    },
    'access': {
      scope: 'Account',
      permission: 'Account → Access: Apps and Policies → Read',
      note: 'Required to read Access applications and their policies.'
    },
    'warp': {
      scope: 'Account',
      permission: 'Account → Zero Trust → Read',
      note: 'Required to inspect WARP device settings profiles.'
    },
    'posture': {
      scope: 'Account',
      permission: 'Account → Zero Trust → Read',
      note: 'Required to inspect device posture rules.'
    },
    'gateway-lists': {
      scope: 'Account',
      permission: 'Account → Zero Trust → Read',
      note: 'Required to inspect Gateway lists used by Zero Trust policies.'
    },
    'tunnels': {
      scope: 'Account',
      permission: 'Account → Cloudflare Tunnel → Read',
      note: 'Cloudflare also accepts Cloudflare One Connectors Read / cloudflared Read for tunnel listing.'
    },
    'dns': {
      scope: 'Zone',
      permission: 'Zone → DNS → Read',
      note: 'Required to inspect DNS records. Restrict the token to the selected zone.'
    },
    'load-balancers': {
      scope: 'Zone',
      permission: 'Zone → Load Balancers → Read',
      note: 'Required to inspect zone load balancers. Account-level pool/monitor data may additionally require Load Balancing: Monitors and Pools Read.'
    }
  };

  const $ = (id) => document.getElementById(id);
  const dataset = $('configDataset');
  const guide = $('permissionGuide');
  const guidePill = $('permissionGuidePill');
  const guideText = $('permissionGuideText');
  const results = $('resultsSection');
  const queryMessage = $('queryMessage');
  const runButton = $('runQueryBtn');

  if (!dataset || !guide || !guidePill || !guideText || !results || !queryMessage || !runButton) return;

  function configurationActive() {
    const tab = document.querySelector('.tab[data-mode="configuration"]');
    return !!tab && tab.classList.contains('active');
  }

  function selectedPermission() {
    return permissions[dataset.value] || {
      scope: 'Read only',
      permission: 'Use the matching Cloudflare read permission for this dataset',
      note: 'Use Scan Access before loading the dataset.'
    };
  }

  function renderGuide(actionRequired = false) {
    const item = selectedPermission();
    guidePill.className = `status-pill ${actionRequired ? 'bad' : 'unknown'}`;
    guidePill.textContent = actionRequired ? 'Action required' : item.scope;

    if (actionRequired) {
      guideText.textContent = `API Token likely does not have ${item.permission}. Edit or create the token in Cloudflare, add this read permission, scope the Account/Zone resource to the selected resource, save it, then Disconnect & reconnect here and run Scan Access before retrying. ${item.note}`;
    } else {
      guideText.textContent = `Recommended API Token permission: ${item.permission}. ${item.note}`;
    }
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
    clearStaleResults();
    renderGuide(false);
  });

  runButton.addEventListener('click', () => {
    if (!configurationActive()) return;
    clearStaleResults();
    renderGuide(false);
  }, true);

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      if (tab.dataset.mode === 'configuration') renderGuide(false);
    });
  });

  const observer = new MutationObserver(() => {
    if (!configurationActive()) return;
    const isError = queryMessage.classList.contains('error');
    if (!isError) return;

    clearStaleResults();
    const text = queryMessage.textContent || '';
    if (/HTTP\s*(401|403)|authentication error|permission|unauthorized|forbidden/i.test(text)) {
      renderGuide(true);
    }
  });

  observer.observe(queryMessage, {
    childList: true,
    characterData: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['class']
  });

  renderGuide(false);
})();
