# Cloudflare Log Explorer

Web-based Cloudflare **Logpull** and **Security Events** explorer designed for simple deployment on cPanel/PHP hosting.

## Features

- Verify a Cloudflare API Token without storing it in the repository or database.
- Auto-detect accessible zones when the token has **Zone Read**.
- Manual Zone ID / Account ID fallback for narrowly scoped tokens.
- Query **Security Events** through Cloudflare GraphQL `firewallEventsAdaptive`.
- Query Enterprise **HTTP Logpull** through `/zones/{zone_id}/logs/received`.
- Discover Logpull fields dynamically from `/logs/received/fields`.
- Search retrieved rows in the browser.
- Export results to **Excel (.xlsx)**, **PDF**, **CSV**, and **JSON**.
- Server-side PHP session for the API Token, with explicit **Disconnect & Clear Token**.
- CSRF protection and restrictive browser security headers.

## Recommended API Token permissions

For the full feature set, create a scoped Cloudflare API Token with:

- `Zone > Zone > Read` — list zones automatically.
- `Zone > Logs > Read` — HTTP Logpull and fields.
- `Zone > Analytics > Read` — Security Events / GraphQL Analytics.

Restrict the token to only the zones needed by the user. Avoid using the Global API Key.

## cPanel deployment

1. Create a subdomain, for example `logpull.example.com`.
2. Point the subdomain document root to a directory such as `public_html/logpull`.
3. Clone or upload this repository into that document root.
4. Use PHP 8.1+ and make sure the PHP **cURL** extension is enabled.
5. Enable HTTPS before entering any Cloudflare API Token.
6. Open the subdomain and connect with a scoped API Token.

No database, Node.js runtime, or Composer install is required for this MVP. Excel and PDF exports use browser-side libraries loaded from jsDelivr.

## Cloudflare limitations

### HTTP Logpull

Cloudflare Logpull is an Enterprise feature. A single `/logs/received` request can cover at most **1 hour**, and Cloudflare's API reference currently requires the `end` time to be at least **5 minutes in the past**. Logpull is a legacy feature; Cloudflare recommends Logpush or Logs Engine for larger or continuous logging workloads.

### Security Events

Security Events are queried from Cloudflare GraphQL Analytics. Availability and retention depend on the account plan, dataset, zone, and token scope.

## Security design

- API Tokens are stored only in the PHP session for the current browser session.
- Tokens are never returned to frontend JavaScript after connection.
- Tokens are not written to files, GitHub, browser localStorage, or a database.
- State-changing API routes require a CSRF token.
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
├── .htaccess
└── README.md
```

## Notes

This project is an independent tool and is not affiliated with or endorsed by Cloudflare, Inc.
