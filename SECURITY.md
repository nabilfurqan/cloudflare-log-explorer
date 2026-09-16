# Security notes

Cloudflare Explorer accepts Cloudflare API Tokens, so production deployment should be treated as a sensitive application even though the repository is public.

## Application security

- Use read-only, least-privilege Cloudflare API Tokens.
- API Tokens are stored only in the PHP session and encrypted server-side.
- Unencrypted/base64-only token storage is rejected.
- Sessions expire after 30 minutes of inactivity.
- Do not place API Tokens, FTP credentials, session keys, or customer data in this repository.
- Prefer setting `CFLE_SESSION_KEY` in the server environment to a strong random value. A base64-encoded 32-byte key is recommended.
- Alternatively set `CFLE_SESSION_KEY_FILE` to a 32-byte key file outside the web document root with filesystem mode `0600`.
- The application trusts `CF-Connecting-IP` only when `REMOTE_ADDR` belongs to an official Cloudflare proxy CIDR.

Example key generation:

```bash
openssl rand -base64 32
```

## cPanel / FTPS requirements

The GitHub Actions deployment account must be a dedicated FTP/FTPS user whose home/root is restricted to the `logpull.cloudnetworklab.com` document root only.

Do **not** grant the deployment user access to the cPanel account home directory, all of `public_html`, or unrelated subdomains.

Recommended controls:

1. Dedicated deployment-only FTPS account.
2. Random, unique password stored only in GitHub Actions secrets/environment secrets.
3. Explicit FTPS with TLS certificate verification enabled.
4. cPanel account 2FA enabled.
5. Remove unused FTP accounts and rotate credentials after suspected exposure.
6. Keep PHP and cPanel-supported runtime versions patched.

The deployment workflow intentionally does **not** use `mirror --delete` until the FTPS root has been verified to be jailed exclusively to this application. After that verification, `--delete` can be enabled so unexpected server-side files are removed during deployment.

## GitHub requirements

Recommended repository settings for `main`:

- Require pull requests before merging.
- Require the `CI Security Checks` status check.
- Block force pushes.
- Block branch deletion.
- Require conversation resolution before merge.
- Keep GitHub Actions workflow permissions read-only by default.
- Store production credentials in the `production` GitHub Environment when available.
- Enable 2FA/passkeys on the GitHub account.

## Cloudflare edge controls

For production, also consider:

- Proxy the hostname through Cloudflare.
- Cache bypass for authenticated/API responses.
- Rate limiting for `/api/*`.
- WAF protections for the hostname.
- Cloudflare Access if the tool should only be used internally.
- Keep the origin inaccessible directly where hosting capabilities allow it.

## CDN dependency

The application currently loads version-pinned export libraries from `cdn.jsdelivr.net`. CSP permits only that CDN for external scripts and source-map/devtools connections. For maximum supply-chain isolation, vendor these exact libraries into `assets/vendor/` in a future change and then reduce `script-src` and `connect-src` to `'self'` only.
