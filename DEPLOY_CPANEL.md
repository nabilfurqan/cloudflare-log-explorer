# Deploy to cPanel

This project is designed to run on standard cPanel hosting with PHP 8.1+.

## Before deploying

Confirm the subdomain already exists and note its exact **Document Root** in cPanel → Domains.

Recommended production requirements:

- PHP 8.1 or newer
- PHP cURL extension enabled
- HTTPS / AutoSSL active
- Cloudflare SSL/TLS mode: Full (strict) when the origin certificate is valid
- The Git repository itself should live outside the public document root

## Recommended cPanel Git Version Control flow

1. Open **cPanel → Files → Git Version Control**.
2. Create/clone a repository from:
   `https://github.com/nabilfurqan/cloudflare-log-explorer.git`
3. Use branch `main`.
4. Keep the cPanel-managed repository outside the public document root, for example under a repository directory in your home folder.
5. Note the exact subdomain Document Root from **cPanel → Domains**.
6. In this GitHub repository, copy `.cpanel.yml.example` to `.cpanel.yml` and edit `DEPLOYPATH` so it matches that exact Document Root.
7. In cPanel Git Version Control, select **Update from Remote**.
8. Select **Deploy HEAD Commit**.

cPanel requires a checked-in `.cpanel.yml` file before deployment controls become available.

## Why the deployment template copies selected paths

Do not deploy the repository by copying the entire working tree with a wildcard. The production directory only needs:

- `index.php`
- `.htaccess`
- `api/`
- `assets/`
- `lib/`

The deployment template intentionally does not copy `.git`, documentation, or deployment metadata into the web root.

## First production test

After deployment:

1. Open the HTTPS subdomain.
2. Confirm the page loads with no mixed-content warning.
3. Enter a least-privilege Cloudflare API Token.
4. Confirm token verification succeeds.
5. Confirm zones are listed when the token has Zone Read.
6. Run a small Security Events query first (for example 10 minutes, 100 rows).
7. If the zone is eligible for Logpull, run a short HTTP Logpull query ending at least 5 minutes in the past.
8. Test CSV/Excel/PDF export.
9. Click **Disconnect & Clear Token**.

## Cloudflare API Token

Use a scoped API Token rather than a Global API Key.

Typical permissions for the full feature set:

- Zone → Zone → Read
- Zone → Logs → Read
- Zone → Analytics → Read

Restrict resources to only the zones required.

## Timezone

The web UI treats the From/To fields explicitly as **Asia/Jakarta (WIB / UTC+7)** and converts those values to UTC before calling Cloudflare APIs.

## Security behavior

- Cloudflare API Token is stored only in the PHP session.
- Session expires after 30 minutes of inactivity.
- Connect attempts are rate-limited.
- JSON request bodies are size-limited.
- Responses containing session/API data use `Cache-Control: no-store`.
- CSRF validation is required for state-changing requests.
- `.git` and `.env` paths are blocked by Apache rules.

## Important

Do not enter real Cloudflare credentials until HTTPS is working correctly on the subdomain.
