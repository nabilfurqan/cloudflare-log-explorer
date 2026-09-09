(() => {
  'use strict';

  const state = { mode: 'security', csrf: document.querySelector('meta[name="csrf-token"]').content, zones: [], fields: {}, rows: [], filteredRows: [], resultSource: '' };
  const $ = (id) => document.getElementById(id);
  const connectForm = $('connectForm');
  const workspace = $('workspace');
  const zoneSelect = $('zoneSelect');
  const queryMessage = $('queryMessage');
  const WIB_OFFSET_MS = 7 * 60 * 60 * 1000;
  const TABLE_DISPLAY_LIMIT = 5000;

  const recommendedFields = ['RayID','ClientIP','ClientCountry','ClientRequestHost','ClientRequestMethod','ClientRequestURI','EdgeStartTimestamp','EdgeEndTimestamp','EdgeResponseStatus','EdgeResponseBytes','CacheCacheStatus','OriginResponseStatus','SecurityAction','SecurityRuleID','SecurityRuleDescription','SecuritySources','SecurityActions','SecurityRuleIDs','WAFAttackScore','WAFSQLiAttackScore','WAFXSSAttackScore','WAFRCEAttackScore'];

  function setMessage(el, text, type = 'error') {
    el.textContent = text;
    el.className = `message ${type}`;
  }
  function clearMessage(el) { el.className = 'message hidden'; el.textContent = ''; }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = state.csrf;
    if (options.body) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options, headers });
    let data;
    try { data = await res.json(); } catch { data = { success: false, error: `Unexpected server response (HTTP ${res.status}).` }; }
    if (!res.ok && !data.error) data.error = `Request failed (HTTP ${res.status}).`;
    if (res.status === 401 && path !== 'api/connect.php') {
      data.error = data.error || 'Session expired. Connect your Cloudflare API Token again.';
      $('connectionBadge').className = 'connection';
      $('connectionBadge').innerHTML = '<span></span>Session expired';
    }
    return { res, data };
  }

  function capability(index, status, detail) {
    const cap = document.querySelectorAll('.cap')[index];
    const dot = cap.querySelector('.dot');
    dot.className = `dot ${status === true ? 'good' : status === false ? 'bad' : 'unknown'}`;
    cap.querySelector('small').textContent = detail;
  }

  function wibInputValue(date) {
    const shifted = new Date(date.getTime() + WIB_OFFSET_MS);
    const pad = (n) => String(n).padStart(2, '0');
    return `${shifted.getUTCFullYear()}-${pad(shifted.getUTCMonth()+1)}-${pad(shifted.getUTCDate())}T${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}`;
  }

  function setDefaultTimes() {
    const end = new Date(Date.now() - 6 * 60 * 1000);
    end.setUTCSeconds(0,0);
    const start = new Date(end.getTime() - 60 * 60 * 1000);
    $('startTime').value = wibInputValue(start);
    $('endTime').value = wibInputValue(end);
  }

  function isoFromWibInput(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value || '');
    if (!match) return null;
    const [, y, mo, d, h, mi] = match;
    const utcMs = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), 0) - WIB_OFFSET_MS;
    const parsed = new Date(utcMs);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
  }

  function formatWibTimestamp(date = new Date()) {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Jakarta',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    }).format(date) + ' WIB';
  }

  function renderZones(zones) {
    state.zones = zones || [];
    zoneSelect.innerHTML = '';
    if (!state.zones.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No zones returned — reconnect with Zone ID manually';
      zoneSelect.appendChild(opt);
      return;
    }
    state.zones.forEach(z => {
      const opt = document.createElement('option');
      opt.value = z.id;
      opt.textContent = z.name === 'Manual Zone ID' ? `Manual · ${z.id}` : `${z.name}${z.status ? ` · ${z.status}` : ''}`;
      opt.dataset.accountId = z.accountId || '';
      zoneSelect.appendChild(opt);
    });
  }

  async function connect(event) {
    event.preventDefault();
    clearMessage($('connectMessage'));
    const btn = $('connectBtn'); btn.disabled = true; btn.textContent = 'Connecting…';
    try {
      const { data } = await api('api/connect.php', { method: 'POST', body: JSON.stringify({ token: $('apiToken').value.trim(), zoneId: $('manualZoneId').value.trim(), accountId: $('manualAccountId').value.trim() }) });
      if (!data.success) throw new Error(data.error || 'Unable to connect.');
      state.csrf = data.csrf;
      document.querySelector('meta[name="csrf-token"]').content = data.csrf;
      $('apiToken').value = '';
      $('connectionBadge').className = 'connection connected';
      $('connectionBadge').innerHTML = '<span></span>Connected';
      capability(0, true, data.token.status || 'Active');
      capability(1, !!data.capabilities.zoneRead, data.capabilities.zoneRead ? 'Available' : 'Unavailable');
      capability(2, null, 'Test on zone'); capability(3, null, 'Test on query');
      renderZones(data.zones);
      workspace.classList.remove('hidden');
      setMessage($('connectMessage'), data.capabilities.zoneRead ? 'Token verified and zones loaded. Session expires after 30 minutes of inactivity.' : 'Token verified. Zone listing is unavailable; use a manual Zone ID if needed. Session expires after 30 minutes of inactivity.', 'success');
      if (zoneSelect.value) loadFields();
    } catch (e) { setMessage($('connectMessage'), e.message); }
    finally { btn.disabled = false; btn.textContent = 'Connect'; }
  }

  async function loadFields() {
    if (!zoneSelect.value) return;
    $('fieldsGrid').innerHTML = '<span class="muted">Checking Logpull access…</span>';
    const { data } = await api(`api/fields.php?zoneId=${encodeURIComponent(zoneSelect.value)}`);
    if (!data.success) {
      capability(2, false, 'Unavailable');
      $('fieldsGrid').innerHTML = `<span class="muted"></span>`;
      $('fieldsGrid').querySelector('span').textContent = data.error || 'Logs Read unavailable.';
      state.fields = {};
      return;
    }
    capability(2, true, 'Available');
    state.fields = data.fields || {};
    renderFields();
  }

  function renderFields() {
    const grid = $('fieldsGrid'); grid.innerHTML = '';
    Object.keys(state.fields).sort().forEach(name => {
      const label = document.createElement('label'); label.className = 'field-check'; label.title = state.fields[name] || name;
      const input = document.createElement('input'); input.type = 'checkbox'; input.value = name; input.checked = recommendedFields.includes(name);
      const span = document.createElement('span'); span.textContent = name;
      label.append(input, span); grid.appendChild(label);
    });
    if (!grid.children.length) grid.innerHTML = '<span class="muted">No fields returned.</span>';
  }

  function setMode(mode) {
    state.mode = mode;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.mode === mode));
    const isLogpull = mode === 'logpull';
    $('logpullFields').classList.toggle('hidden', !isLogpull);
    $('modeLabel').textContent = isLogpull ? 'HTTP Logpull' : 'Security Events';
    $('modeHint').textContent = isLogpull ? 'Retrieves raw HTTP request logs through /logs/received.' : 'Queries firewallEventsAdaptive using GraphQL Analytics.';
    $('runQueryBtn').textContent = isLogpull ? 'Run Logpull Query' : 'Run Security Events Query';
    $('queryRule').textContent = isLogpull ? 'Logpull: maximum 1 hour; end time must be at least 5 minutes in the past. Input times are WIB (Asia/Jakarta).' : 'Security Events availability depends on your plan and Analytics Read access. Input times are WIB (Asia/Jakarta).';
    clearMessage(queryMessage);
    if (isLogpull && zoneSelect.value && !Object.keys(state.fields).length) loadFields();
  }

  function selectedFields() { return [...document.querySelectorAll('#fieldsGrid input:checked')].map(x => x.value); }

  async function runQuery() {
    clearMessage(queryMessage);
    const zoneId = zoneSelect.value;
    const start = isoFromWibInput($('startTime').value), end = isoFromWibInput($('endTime').value);
    if (!zoneId) return setMessage(queryMessage, 'Select a zone first.');
    if (!start || !end) return setMessage(queryMessage, 'Select a valid WIB time range.');
    const btn = $('runQueryBtn'); btn.disabled = true; const old = btn.textContent; btn.textContent = 'Running…';
    try {
      const payload = { zoneId, start, end, limit: Number($('rowLimit').value), count: Number($('rowLimit').value) };
      let endpoint = 'api/security-events.php';
      if (state.mode === 'logpull') { endpoint = 'api/logpull.php'; payload.fields = selectedFields(); }
      const { data } = await api(endpoint, { method: 'POST', body: JSON.stringify(payload) });
      if (!data.success) {
        if (data.capability === 'analyticsRead') capability(3, false, 'Unavailable');
        if (data.capability === 'logsRead') capability(2, false, 'Unavailable');
        throw new Error(data.error || 'Query failed.');
      }
      if (state.mode === 'security') capability(3, true, 'Available'); else capability(2, true, 'Available');
      state.rows = data.rows || []; state.filteredRows = state.rows; state.resultSource = data.source || state.mode;
      renderResults(data.range || {});
      setMessage(queryMessage, `Query completed: ${state.rows.length.toLocaleString()} rows retrieved.`, 'success');
    } catch(e) { setMessage(queryMessage, e.message); }
    finally { btn.disabled = false; btn.textContent = old; }
  }

  function preferredColumns(rows) {
    if (!rows.length) return [];
    const priority = state.resultSource === 'security-events'
      ? ['datetime','action','clientRequestHTTPHost','clientIP','clientCountryName','clientRequestPath','source','ruleId','description','kind','originatorRayName','clientAsn','userAgent']
      : ['EdgeStartTimestamp','ClientRequestHost','ClientIP','ClientCountry','ClientRequestMethod','ClientRequestURI','EdgeResponseStatus','SecurityAction','SecurityRuleID','SecurityRuleDescription','RayID','CacheCacheStatus','OriginResponseStatus'];
    const all = [...new Set(rows.flatMap(r => Object.keys(r)))];
    return [...priority.filter(c => all.includes(c)), ...all.filter(c => !priority.includes(c))];
  }

  function renderResults(range) {
    $('resultsSection').classList.remove('hidden');
    $('metricTotal').textContent = state.rows.length.toLocaleString();
    const actions = state.rows.map(r => String(r.action ?? r.SecurityAction ?? '').toLowerCase());
    $('metricBlocked').textContent = actions.filter(a => a === 'block' || a === 'blocked').length.toLocaleString();
    $('metricChallenge').textContent = actions.filter(a => a.includes('challenge')).length.toLocaleString();
    const sourceKey = state.resultSource === 'security-events' ? 'source' : 'SecuritySources';
    const counts = {}; state.rows.forEach(r => { const v = Array.isArray(r[sourceKey]) ? r[sourceKey].join(', ') : r[sourceKey]; if(v) counts[String(v)] = (counts[String(v)]||0)+1; });
    const top = Object.entries(counts).sort((a,b)=>b[1]-a[1])[0]; $('metricSource').textContent = top ? top[0] : '—';
    $('resultMeta').textContent = `${state.resultSource === 'security-events' ? 'Security Events' : 'HTTP Logpull'} · ${range.start || ''} → ${range.end || ''} (UTC API range; input was WIB)`;
    $('resultSearch').value = '';
    renderTable(state.rows);
  }

  function cellValue(v) { if (v === null || v === undefined) return ''; if (Array.isArray(v)) return v.join(', '); if (typeof v === 'object') return JSON.stringify(v); return String(v); }
  function renderTable(rows) {
    const table = $('resultsTable'), head = table.querySelector('thead'), body = table.querySelector('tbody'); head.innerHTML = ''; body.innerHTML = '';
    const cols = preferredColumns(state.rows);
    if (!cols.length) { body.innerHTML = '<tr><td>No rows returned for this query.</td></tr>'; $('visibleRows').textContent = '0 rows'; return; }
    const trh = document.createElement('tr'); cols.forEach(c => { const th = document.createElement('th'); th.textContent = c; trh.appendChild(th); }); head.appendChild(trh);
    rows.slice(0, TABLE_DISPLAY_LIMIT).forEach(r => { const tr = document.createElement('tr'); cols.forEach(c => { const td = document.createElement('td'); td.textContent = cellValue(r[c]); td.title = cellValue(r[c]); tr.appendChild(td); }); body.appendChild(tr); });
    $('visibleRows').textContent = `${Math.min(rows.length,TABLE_DISPLAY_LIMIT).toLocaleString()} displayed${rows.length>TABLE_DISPLAY_LIMIT?` (table capped at ${TABLE_DISPLAY_LIMIT.toLocaleString()})`:''}`;
  }

  function filterRows() {
    const q = $('resultSearch').value.trim().toLowerCase();
    state.filteredRows = !q ? state.rows : state.rows.filter(r => Object.values(r).some(v => cellValue(v).toLowerCase().includes(q)));
    renderTable(state.filteredRows);
  }

  function fileBase() { const zone = state.zones.find(z=>z.id===zoneSelect.value); const name = (zone?.name || zoneSelect.value || 'zone').replace(/[^a-z0-9.-]+/gi,'-'); return `cloudflare-${state.resultSource || state.mode}-${name}-${wibInputValue(new Date()).replace(/[:T]/g,'-')}-WIB`; }
  function downloadBlob(content, type, ext) { const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([content],{type})); a.download=`${fileBase()}.${ext}`; document.body.appendChild(a); a.click(); URL.revokeObjectURL(a.href); a.remove(); }
  function exportJson() { downloadBlob(JSON.stringify(state.rows,null,2),'application/json','json'); }
  function exportCsv() { const cols=preferredColumns(state.rows); const quote=v=>`"${cellValue(v).replace(/"/g,'""')}"`; const csv=[cols.map(quote).join(','),...state.rows.map(r=>cols.map(c=>quote(r[c])).join(','))].join('\r\n'); downloadBlob('\ufeff'+csv,'text/csv;charset=utf-8','csv'); }
  function exportXlsx() { if(!window.XLSX) return alert('Excel library failed to load.'); const ws=window.XLSX.utils.json_to_sheet(state.rows); const wb=window.XLSX.utils.book_new(); window.XLSX.utils.book_append_sheet(wb,ws,'Logs'); const summary=window.XLSX.utils.aoa_to_sheet([['Cloudflare Log Explorer'],['Source',state.resultSource],['Zone',zoneSelect.options[zoneSelect.selectedIndex]?.text||zoneSelect.value],['Rows',state.rows.length],['Input timezone','Asia/Jakarta (WIB, UTC+7)'],['Exported',formatWibTimestamp()]]); window.XLSX.utils.book_append_sheet(wb,summary,'Summary'); window.XLSX.writeFile(wb,`${fileBase()}.xlsx`); }
  function exportPdf() { if(!window.jspdf?.jsPDF) return alert('PDF library failed to load.'); const {jsPDF}=window.jspdf; const doc=new jsPDF({orientation:'landscape',unit:'pt',format:'a4'}); const cols=preferredColumns(state.rows).slice(0,10); doc.setFontSize(16); doc.text('Cloudflare Log Explorer Report',36,38); doc.setFontSize(9); doc.text(`Source: ${state.resultSource} | Rows: ${state.rows.length} | Exported: ${formatWibTimestamp()}`,36,56); doc.autoTable({startY:70,head:[cols],body:state.rows.slice(0,1000).map(r=>cols.map(c=>cellValue(r[c]))),styles:{fontSize:5,cellPadding:2,overflow:'linebreak'},headStyles:{fontSize:5},margin:{left:24,right:24}}); if(state.rows.length>1000){doc.setFontSize(8);doc.text('PDF export is capped at 1,000 rows. Use Excel/CSV/JSON for the full retrieved dataset.',36,doc.internal.pageSize.height-18);} doc.save(`${fileBase()}.pdf`); }

  async function disconnect() {
    try { await api('api/disconnect.php', { method:'POST', body:'{}' }); } catch {}
    window.location.reload();
  }

  connectForm.addEventListener('submit', connect);
  $('toggleToken').addEventListener('click',()=>{ const i=$('apiToken'); i.type=i.type==='password'?'text':'password'; $('toggleToken').textContent=i.type==='password'?'Show':'Hide'; });
  document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>setMode(t.dataset.mode)));
  zoneSelect.addEventListener('change',loadFields);
  $('runQueryBtn').addEventListener('click',runQuery);
  $('disconnectBtn').addEventListener('click',disconnect);
  $('selectDefaults').addEventListener('click',()=>document.querySelectorAll('#fieldsGrid input').forEach(i=>i.checked=recommendedFields.includes(i.value)));
  $('selectAllFields').addEventListener('click',()=>document.querySelectorAll('#fieldsGrid input').forEach(i=>i.checked=true));
  $('resultSearch').addEventListener('input',filterRows);
  document.querySelectorAll('[data-export]').forEach(b=>b.addEventListener('click',()=>{ if(!state.rows.length)return alert('Run a query first.'); ({xlsx:exportXlsx,pdf:exportPdf,csv:exportCsv,json:exportJson}[b.dataset.export])(); }));
  setDefaultTimes(); setMode('security');
})();
