<?php
declare(strict_types=1);
require_once __DIR__ . '/lib/cloudflare.php';
bootstrap_session();
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
if (is_https_request()) {
    header('Strict-Transport-Security: max-age=31536000');
}
$csrf = htmlspecialchars((string) $_SESSION['csrf'], ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="<?= $csrf ?>">
    <title>Cloudflare Explorer · Cloud Network Lab</title>
    <meta name="description" content="Read-only Cloudflare Logpull, Security Events, WAF, Zero Trust, DNS and configuration explorer.">
    <link rel="stylesheet" href="assets/style.css?v=3">
</head>
<body>
<div class="shell">
    <header class="topbar">
        <div class="brand">
            <div class="brand-mark">CF</div>
            <div>
                <h1>Cloudflare Explorer</h1>
                <p>Logs · Security · Configuration</p>
            </div>
        </div>
        <div class="connection" id="connectionBadge"><span></span>Not connected</div>
    </header>

    <main>
        <section class="hero">
            <div>
                <div class="eyebrow">Cloud Network Lab Tool</div>
                <h2>Inspect Cloudflare logs, policies, and configuration from one place.</h2>
                <p>Connect a scoped API Token, then inspect Security Events, HTTP Logpull, WAF rules, Zero Trust policies, DNS, tunnels, device posture, and other read-only configuration. Export retrieved datasets to Excel, PDF, CSV, or JSON.</p>
            </div>
            <div class="security-note">
                <strong>Read-only by design</strong>
                <span>The application does not expose edit or delete operations. Your API Token stays in a server-side PHP session, expires after 30 minutes of inactivity, and is cleared when you disconnect.</span>
            </div>
        </section>

        <section class="card connect-card" id="connectCard">
            <div class="card-head">
                <div>
                    <span class="step">01</span>
                    <h3>Connect Cloudflare</h3>
                </div>
                <p>Start with least-privilege read permissions. Additional modules only work when the token has their matching read permission.</p>
            </div>
            <form id="connectForm" autocomplete="off">
                <label class="field field-wide">
                    <span>API Token</span>
                    <div class="password-wrap">
                        <input id="apiToken" type="password" placeholder="Paste Cloudflare API Token" required autocomplete="off" spellcheck="false">
                        <button class="ghost mini" type="button" id="toggleToken">Show</button>
                    </div>
                </label>
                <label class="field">
                    <span>Zone ID <em>optional</em></span>
                    <input id="manualZoneId" type="text" maxlength="32" placeholder="Auto-detect when Zone Read is permitted" spellcheck="false">
                </label>
                <label class="field">
                    <span>Account ID <em>optional</em></span>
                    <input id="manualAccountId" type="text" maxlength="32" placeholder="Needed for Zero Trust account datasets" spellcheck="false">
                </label>
                <div class="form-actions field-wide">
                    <button class="primary" type="submit" id="connectBtn">Connect</button>
                    <span class="hint">The token is never written to this repository, browser storage, or a database.</span>
                </div>
            </form>
            <div id="connectMessage" class="message hidden"></div>
        </section>

        <section class="workspace hidden" id="workspace">
            <div class="capabilities" id="capabilities">
                <div class="cap" data-cap="token"><span class="dot unknown"></span><div><b>Token</b><small>Checking</small></div></div>
                <div class="cap" data-cap="zone"><span class="dot unknown"></span><div><b>Zone Read</b><small>Checking</small></div></div>
                <div class="cap" data-cap="logs"><span class="dot unknown"></span><div><b>Logs Read</b><small>Test on zone</small></div></div>
                <div class="cap" data-cap="analytics"><span class="dot unknown"></span><div><b>Analytics</b><small>Test on query</small></div></div>
                <div class="cap" data-cap="config"><span class="dot unknown"></span><div><b>Rules / DNS</b><small>Scan access</small></div></div>
                <div class="cap" data-cap="zeroTrust"><span class="dot unknown"></span><div><b>Zero Trust</b><small>Scan access</small></div></div>
            </div>

            <section class="card query-card">
                <div class="card-head">
                    <div>
                        <span class="step">02</span>
                        <h3>Explore</h3>
                    </div>
                    <button type="button" class="danger ghost" id="disconnectBtn">Disconnect & Clear Token</button>
                </div>

                <div class="tabs" role="tablist">
                    <button class="tab active" type="button" data-mode="security">Security Events</button>
                    <button class="tab" type="button" data-mode="logpull">HTTP Logpull</button>
                    <button class="tab" type="button" data-mode="configuration">Configuration</button>
                </div>

                <div class="query-grid">
                    <label class="field field-wide" id="zoneField">
                        <span>Zone</span>
                        <select id="zoneSelect"></select>
                    </label>
                    <label class="field" id="startField">
                        <span>From <em>WIB · Asia/Jakarta</em></span>
                        <input type="datetime-local" id="startTime" step="60">
                    </label>
                    <label class="field" id="endField">
                        <span>To <em>WIB · Asia/Jakarta</em></span>
                        <input type="datetime-local" id="endTime" step="60">
                    </label>
                    <label class="field" id="limitField">
                        <span>Maximum rows</span>
                        <select id="rowLimit">
                            <option value="100">100</option>
                            <option value="500">500</option>
                            <option value="1000" selected>1,000</option>
                            <option value="5000">5,000</option>
                            <option value="10000">10,000</option>
                        </select>
                    </label>
                    <div class="field mode-info" id="modeInfoField">
                        <span>Mode</span>
                        <strong id="modeLabel">Security Events</strong>
                        <small id="modeHint">Queries firewallEventsAdaptive using GraphQL Analytics.</small>
                    </div>
                </div>

                <div id="logpullFields" class="field-panel hidden">
                    <div class="field-panel-head">
                        <div><b>HTTP Logpull</b><small>Select which request fields Cloudflare should return.</small></div>
                        <div><button class="ghost mini" type="button" id="selectDefaults">Recommended</button><button class="ghost mini" type="button" id="selectAllFields">Select all</button></div>
                    </div>
                    <div class="retention-row">
                        <span>Log retention</span>
                        <strong class="status-pill unknown" id="retentionStatus">Not checked</strong>
                        <small id="retentionNote">Choose a zone to check whether Logpull retention is enabled.</small>
                    </div>
                    <div id="fieldsGrid" class="fields-grid"><span class="muted">Choose a zone to load fields.</span></div>
                </div>

                <div id="configurationPanel" class="field-panel hidden">
                    <div class="field-panel-head">
                        <div><b>Read-only configuration</b><small>Choose a dataset. The API Token must have the corresponding read permission.</small></div>
                        <div><button class="ghost mini" type="button" id="scanCapabilitiesBtn">Scan Access</button></div>
                    </div>
                    <div class="config-grid">
                        <label class="field">
                            <span>Dataset</span>
                            <select id="configDataset">
                                <optgroup label="Security / WAF">
                                    <option value="waf-custom" data-scope="zone">WAF Custom Rules</option>
                                    <option value="waf-managed" data-scope="zone">Managed WAF</option>
                                    <option value="rate-limiting" data-scope="zone">Rate Limiting Rules</option>
                                    <option value="transform-request" data-scope="zone">Request Transform Rules</option>
                                    <option value="transform-response" data-scope="zone">Response Header Transform Rules</option>
                                    <option value="configuration-rules" data-scope="zone">Configuration Rules</option>
                                </optgroup>
                                <optgroup label="Zero Trust">
                                    <option value="gateway" data-scope="account">Gateway Policies</option>
                                    <option value="access" data-scope="account">Access Applications & Policies</option>
                                    <option value="warp" data-scope="account">WARP Device Profiles</option>
                                    <option value="posture" data-scope="account">Device Posture Rules</option>
                                    <option value="gateway-lists" data-scope="account">Gateway Lists</option>
                                    <option value="tunnels" data-scope="account">Cloudflare Tunnels</option>
                                </optgroup>
                                <optgroup label="Network">
                                    <option value="dns" data-scope="zone">DNS Records</option>
                                    <option value="load-balancers" data-scope="zone">Load Balancers</option>
                                </optgroup>
                            </select>
                        </label>
                        <label class="field">
                            <span>Account ID <em>auto-filled from selected zone when available</em></span>
                            <input id="configAccountId" type="text" maxlength="32" placeholder="32-character Account ID" spellcheck="false">
                        </label>
                    </div>
                    <div class="cap-scan-grid" id="capabilityScan"><span class="muted">Use Scan Access to test read-only API capabilities for the selected Zone and Account.</span></div>
                </div>

                <div class="query-actions">
                    <button class="primary" type="button" id="runQueryBtn">Run Security Events Query</button>
                    <span id="queryRule" class="hint">Security Events availability depends on your plan and Analytics Read access.</span>
                </div>
                <div id="queryMessage" class="message hidden"></div>
            </section>

            <section class="results hidden" id="resultsSection">
                <div class="summary-grid">
                    <div class="metric"><span id="metricLabelTotal">Total rows</span><b id="metricTotal">0</b></div>
                    <div class="metric"><span id="metricLabelSecond">Blocked</span><b id="metricBlocked">0</b></div>
                    <div class="metric"><span id="metricLabelThird">Challenges</span><b id="metricChallenge">0</b></div>
                    <div class="metric"><span id="metricLabelFourth">Top source</span><b id="metricSource">—</b></div>
                </div>

                <section class="card table-card">
                    <div class="table-tools">
                        <div>
                            <span class="step">03</span>
                            <h3>Results</h3>
                            <small id="resultMeta">—</small>
                        </div>
                        <div class="exports">
                            <button class="ghost" type="button" data-export="xlsx">Excel</button>
                            <button class="ghost" type="button" data-export="pdf">PDF</button>
                            <button class="ghost" type="button" data-export="csv">CSV</button>
                            <button class="ghost" type="button" data-export="json">JSON</button>
                        </div>
                    </div>
                    <div class="filters">
                        <input type="search" id="resultSearch" placeholder="Filter displayed rows…">
                    </div>
                    <div class="table-wrap">
                        <table id="resultsTable"><thead></thead><tbody></tbody></table>
                    </div>
                    <div class="table-foot"><span id="visibleRows">0 rows</span><span>Exports use the full retrieved dataset.</span></div>
                </section>
            </section>
        </section>
    </main>

    <footer>Cloudflare Explorer · Built for Cloud Network Lab · Read-only</footer>
</div>

<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/jspdf@2.5.2/dist/jspdf.umd.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/jspdf-autotable@3.8.4/dist/jspdf.plugin.autotable.min.js" defer></script>
<script src="assets/app.js?v=3" defer></script>
</body>
</html>
