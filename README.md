# Cloudflare Log Explorer

Web-based Cloudflare **Logpull** and **Security Events** explorer designed for simple deployment on cPanel/PHP hosting.

## Features

- Verify a Cloudflare API Token without storing it in the repository or database.
- Auto-detect accessible zones when the token has **Zone Read**.
- Manual Zone ID / Account ID fallback for narrowly scoped tokens.
- Query **Security Events** through Cloudflare GraphQL `firewallEventsAdaptive`.
- Query Enterprise **HTTP Logpull** through `/zones/{zone_id}/logs/received`.
- Discover Logpull fields dynamically from `/logs/received/fields`.
- Input query times explicitly in **Asia/Jakarta (WIB / UTC+7)** and convert them to UTC for Cloudflare APIs.
- Search retrieved rows in the browser.
- Display up to 5,000 rows in the browser while exports use the full retrieved dataset.
- Export results to **Excel (.xlsx)**, **PDF**, **CSV**, and **JSON**.
- Server-side PHP session for the API Token, with explicit **Disconnect & Clear Token**.
- Automatic session expiry after 30 minutes of inactivity.
- CSRF protection, connection-attempt rate limiting, request-size limits, and restrictive browser security headers.

## Recommended API Token permissions

For the full feature set, create a scoped Cloudflare API Token with:

- `Zone > Zone > Read` — list zones automatically.
- `Zone > Logs > Read` — HTTP Logpull and fields.
- `Zone > Analytics > Read` — Security Events / GraphQL Analytics.

Restrict the token to only the zones needed by the user. Avoid using the Global API Key.

## cPanel deployment

The subdomain should already exist before deployment.

Recommended production requirements:

- PHP 8.1+
- PHP cURL extension enabled
- HTTPS / AutoSSL active
- Valid origin certificate; when proxied through Cloudflare, prefer **Full (strict)** SSL/TLS mode

For deployment with cPanel Git Version Control, see [`DEPLOY_CPANEL.md`](DEPLOY_CPANEL.md).

A safe `.cpanel.yml.example` is included. It is intentionally not active until `DEPLOYPATH` is changed to the exact Document Root of the subdomain and the file is renamed to `.cpanel.yml`.

No database, Node.js runtime, or Composer install is required for this MVP. Excel and PDF exports use browser-side libraries loaded from jsDelivr.

## Cloudflare limitations

### HTTP Logpull

Cloudflare's current API reference accepts API Tokens with **Logs Read** (or Logs Write) for `/logs/received`. A single request can cover at most **1 hour**, and the `end` time must be at least **5 minutes in the past**.

This MVP limits Logpull queries to the last 7 days and up to 10,000 retrieved rows per request. Cloudflare documents Logpull retention as at least three days and up to seven days.

For larger or continuous logging workloads, prefer Cloudflare Logpush or another supported logging pipeline rather than repeatedly pulling large windows into a browser.

### Security Events

Security Events are queried from Cloudflare GraphQL Analytics using `firewallEventsAdaptive`. Availability and retention depend on the account plan, dataset, zone, and token scope.

## Security design

- API Tokens are stored only in the PHP session for the current browser session.
- Sessions automatically expire after **30 minutes of inactivity**.
- Tokens are never returned to frontend JavaScript after connection.
- Tokens are not written to files, GitHub, browser localStorage, or a database.
- State-changing API routes require a CSRF token.
- Connect attempts are rate-limited per client IP.
- JSON request bodies are limited to 64 KiB.
- API/session responses use `Cache-Control: no-store`.
- `.git` and `.env` paths are blocked by Apache rules.
- `lib/` is blocked from direct web access through `.htaccess`.
- Use a least-privilege Cloudflare API Token and HTTPS.

## Project structure

```text
.
├── index.php
├── api/
│   ├── connect.php
│   ├── disconnect.php
│   ├── fields.php
│   ├── logpull.php
│   ├── security-events.php
│   └── zones.php
├── assets/
│   ├── app.js
│   └── style.css
├── lib/
│   ├── .htaccess
│   └── cloudflare.php
├── .cpanel.yml.example
├── DEPLOY_CPANEL.md
├── .htaccess
└── README.md
```

## Notes

This project is an independent tool and is not affiliated with or endorsed by Cloudflare, Inc.
