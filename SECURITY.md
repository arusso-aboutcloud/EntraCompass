# Security

EntraCompass is designed so that your tenant data never reaches a server we operate. This page summarises the security model and how to report a vulnerability. Details: [Architecture](docs/architecture.md) and [Data security architecture](docs/data-architecture.md).

## Reporting a vulnerability

Please report privately through GitHub: **Security tab > Report a vulnerability** on this repository. Do not open a public issue.

In scope: the web app, the `/ai/ask` Pages Function, the app-registration script, and the CI workflows in this repository.
Out of scope: Microsoft Entra ID and Microsoft Graph themselves; volumetric denial of service; findings that require a compromised browser or device.

## Supported versions

Only the current `main` branch (deployed at https://entracompass.aboutcloud.io) is supported.

## Security model at a glance

| Area | Control |
|---|---|
| Authentication | Your own single-tenant app registration, authorization code flow with PKCE, no client secret |
| Authorization | Delegated, read-only Microsoft Graph scopes: `Policy.Read.All`, `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `User.Read`. The signed-in admin's role also limits what is returned |
| Data handling | Processed in the browser; stored only in `sessionStorage`; no backend, no database, no cookies |
| Network | Graph calls go straight from the browser to Microsoft. The page may only connect to itself, `login.microsoftonline.com` and `graph.microsoft.com` (CSP) |
| AI (optional) | Aggregated, name-free summary only; origin-locked; rate-limited; nothing stored |
| Supply chain | `npm ci` from lockfile, Dependabot with auto-merge for patch/minor, weekly auto-patch of transitive dependencies, Trivy scan, Actions pinned by SHA, protected `main` |

## Edge security

The hosted site runs on Cloudflare Pages behind the aboutcloud.io zone protections:

- **TLS**: TLS 1.0 and 1.1 refused; TLS 1.2 and 1.3 offered (1.3 preferred); HTTP redirected to HTTPS; HTTP/3.
- **HSTS**: `max-age=31536000; includeSubDomains; preload`.
- **Response headers** (`public/_headers`): Content-Security-Policy (`default-src 'self'; script-src 'self'`, restricted `connect-src` and `frame-src`, `frame-ancestors 'none'`, `object-src 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, restrictive `Permissions-Policy`.
- **WAF custom rules** (shared zone rules, this host included):
  - blocks known scanners and bad bots, empty user agents, and probes for sensitive paths (`/.env`, `/.git`, admin panels and similar);
  - blocks traffic from high-risk countries;
  - method enforcement: `GET` and `HEAD` only, except `POST` and `OPTIONS` on `/ai/ask`;
  - API abuse rule for `/api/` and `/ai/` paths (scanner tools, `PUT`, `PATCH`, `DELETE`).
- **Rate limiting** on `/ai/ask` at the edge, plus a per-IP limit inside the function.
- **Cloudflare managed protections** for the zone.

## Your controls as a customer

- Delete or disable the app registration when you are not assessing.
- Turn on "Assignment required" for the EntraCompass enterprise app and assign only assessors.
- Protect the app with your own Conditional Access (phishing-resistant MFA, compliant device).
- Treat downloaded reports and JSON as confidential: they describe your security controls.
- Prefer to self-host? Fork, build and deploy `dist/` on your own infrastructure.
