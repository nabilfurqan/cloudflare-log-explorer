<?php
declare(strict_types=1);
require_once __DIR__ . '/lib/cloudflare.php';
bootstrap_session();
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
$csrf = htmlspecialchars((string) $_SESSION['csrf'], ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="<?= $csrf ?>">
    <title>Cloudflare Log Explorer</title>
    <meta name="description" content="Secure browser-based Cloudflare Logpull and Security Events explorer.">
    <link rel="stylesheet" href="assets/style.css?v=1">
</head>
<body>
<div class="shell">
    <header class="topbar">
        <div class="brand">
            <div class="brand-mark">CF</div>
            <div>
                <h1>Cloudflare Log Explorer</h1>
                <p>Logpull & Security Events</p>
            </div>
        </div>
        <div class="connection" id="connectionBadge"><span></span>Not connected</div>
    </header>

    <main>
        <section class="hero">
            <div>
                <div class="eyebrow">Cloud Network Lab Tool</div>
                <h2>Query Cloudflare logs without handling raw API calls.</h2>
                <p>Connect with a scoped API Token, choose a zone, inspect HTTP request logs or Security Events, then export the result to Excel, PDF, CSV, or JSON.</p>
            </div>
            <div class="security-note">
                <strong>Token handling</strong>
                <span>Your token is kept only in the server-side PHP session and cleared when you disconnect.</span>
            </div>
        </section>

        <section class="card connect-card" id="connectCard">
            <div class="card-head">
                <div>
                    <span class="step">01</span>
                    <h3>Connect Cloudflare</h3>
                </div>
                <p>Recommended token permissions: <b>Zone Read</b>, <b>Logs Read</b>, and <b>Analytics Read</b>.</p>
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
                    <input id="manualZoneId" type="text" maxlength="32" placeholder="Auto-detect when permitted" spellcheck="false">
                </label>
                <label class="field">
                    <span>Account ID <em>optional</em></span>
                    <input id="manualAccountId" type="text" maxlength="32" placeholder="Optional for future account datasets" spellcheck="false">
                </label>
                <div class="form-actions field-wide">
                    <button class="primary" type="submit" id="connectBtn">Connect</button>
                    <span class="hint">The token is never written to this repository or a database.</span>
                </div>
            </form>
            <div id="connectMessage" class="message hidden"></div>
        </section>

        <section class="workspace hidden" id="workspace">
            <div class="capabilities" id="capabilities">
                <div class="cap"><span class="dot unknown"></span><div><b>Token</b><small>Checking</small></div></div>
                <div class="cap"><span class="dot unknown"></span><div><b>Zone Read</b><small>Checking</small></div></div>
                <div class="cap"><span class="dot unknown"></span><div><b>Logs Read</b><small>Test on zone</small></div></div>
                <div class="cap"><span class="dot unknown"></span><div><b>Analytics Read</b><small>Test on query</small></div></div>
            </div>

            <section class="card query-card">
                <div class="card-head">
                    <div>
                        <span class="step">02</span>
                        <h3>Build Query</h3>
                    </div>
                    <button type="button" class="danger ghost" id="disconnectBtn">Disconnect & Clear Token</button>
                </div>

                <div class="tabs" role="tablist">
                    <button class="tab active" type="button" data-mode="security">Security Events</button>
                    <button class="tab" type="button" data-mode="logpull">HTTP Logpull</button>
                </div>

                <div class="query-grid">
                    <label class="field field-wide">
                        <span>Zone</span>
                        <select id="zoneSelect"></select>
                    </label>
                    <label class="field">
                        <span>From</span>
                        <input type="datetime-local" id="startTime" step="60">
                    </label>
                    <label class="field">
                        <span>To</span>
                        <input type="datetime-local" id="endTime" step="60">
                    </label>
                    <label class="field">
                        <span>Maximum rows</span>
                        <select id="rowLimit">
                            <option value="100">100</option>
                            <option value="500">500</option>
                            <option value="1000" selected>1,000</option>
                            <option value="5000">5,000</option>
                            <option value="10000">10,000</option>
                        </select>
                    </label>
                    <div class="field mode-info">
                        <span>Mode</span>
                        <strong id="modeLabel">Security Events</strong>
                        <small id="modeHint">Queries firewallEventsAdaptive using GraphQL Analytics.</small>
                    </div>
                </div>

                <div id="logpullFields" class="field-panel hidden">
                    <div class="field-panel-head">
                        <div><b>Logpull fields</b><small>Select which HTTP request fields Cloudflare should return.</small></div>
                        <div><button class="ghost mini" type="button" id="selectDefaults">Recommended</button><button class="ghost mini" type="button" id="selectAllFields">Select all</button></div>
                    </div>
                    <div id="fieldsGrid" class="fields-grid"><span class="muted">Choose a zone to load fields.</span></div>
                </div>

                <div class="query-actions">
                    <button class="primary" type="button" id="runQueryBtn">Run Security Events Query</button>
                    <span id="queryRule" class="hint">Security Events can use a wider time range; availability depends on your plan and token scope.</span>
                </div>
                <div id="queryMessage" class="message hidden"></div>
            </section>

            <section class="results hidden" id="resultsSection">
                <div class="summary-grid">
                    <div class="metric"><span>Total rows</span><b id="metricTotal">0</b></div>
                    <div class="metric"><span>Blocked</span><b id="metricBlocked">0</b></div>
                    <div class="metric"><span>Challenges</span><b id="metricChallenge">0</b></div>
                    <div class="metric"><span>Top source</span><b id="metricSource">—</b></div>
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

    <footer>Cloudflare Log Explorer · Built for Cloud Network Lab</footer>
</div>

<script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/jspdf@2.5.2/dist/jspdf.umd.min.js" defer></script>
<script src="https://cdn.jsdelivr.net/npm/jspdf-autotable@3.8.4/dist/jspdf.plugin.autotable.min.js" defer></script>
<script src="assets/app.js?v=1" defer></script>
</body>
</html>
