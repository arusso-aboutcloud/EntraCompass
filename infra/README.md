# Infrastructure

Everything EntraCompass needs outside the app code: the two PowerShell scripts customers run, how the public site is hosted, and the repository settings that keep `main` safe. There is no server, database or secret to manage.

![EntraCompass architecture](../docs/diagrams/architecture.svg)

## Scripts for customers

| Script | What it does | Needs |
|---|---|---|
| [`New-EntraCompassApp.ps1`](New-EntraCompassApp.ps1) | Creates the single-tenant app registration: Single-page application platform, redirect URI, delegated read-only Graph permissions. No secret or certificate. | `Microsoft.Graph` modules; Application Administrator (plus Privileged Role Administrator or Global Administrator for `-GrantAdminConsent`) |
| [`Export-PurviewForEntraCompass.ps1`](Export-PurviewForEntraCompass.ps1) | Read-only export of DLP policies and rules, sensitivity labels, label and auto-labeling policies, for the Purview view. Email addresses are redacted. | `ExchangeOnlineManagement` module; Compliance Administrator, Compliance Data Administrator or Global Reader |

```powershell
# App registration, with admin consent and the optional agent and Purview permissions
./New-EntraCompassApp.ps1 -GrantAdminConsent -IncludeOptional
# Your own host:
./New-EntraCompassApp.ps1 -RedirectUri https://compass.example.com -GrantAdminConsent

# Purview export, then load purview.json in the Purview view
./Export-PurviewForEntraCompass.ps1 -OutFile purview.json
```

Permissions:

| Permission | Required | Admin consent | Used for |
|---|---|---|---|
| `User.Read` | Yes | No | Sign-in |
| `Policy.Read.All` | Yes | Yes | Conditional Access policies, named locations, authentication contexts and strengths |
| `Application.Read.All` | Yes | Yes | Enterprise apps, app registrations, application permissions |
| `Directory.Read.All` | Yes | Yes | Users, groups and roles in policies, group sizes, role assignments, delegated grants, agent user accounts |
| `AuditLog.Read.All` | Yes | Yes | Application sign-in activity (Entra ID P1) |
| `AgentIdentity.Read.All` | Optional | Yes | Agent identities, blueprints, sponsors (preview). The signed-in account also needs an Agent ID role |
| `IdentityRiskyAgent.Read.All` | Optional | Yes | Agent risk from ID Protection (preview) |
| `InformationProtectionPolicy.Read` | Optional | No | Sensitivity labels published to the signed-in admin |

Optional permissions are never requested at sign-in. Once consented, Microsoft Entra adds them to the Graph token automatically, so they can be added or removed at any time without breaking sign-in.

## Hosting (entracompass.aboutcloud.io)

| Piece | Setting |
|---|---|
| Cloudflare Pages project | `entracompass`, connected to this repository through the Cloudflare Workers and Pages GitHub app (the repository must be in the app's selected repositories) |
| Build | `npm run build`, output `dist`, production branch `main`, automatic deployments on; branches and pull requests get preview deployments |
| Pages Function | `functions/ai/ask.js`, Workers AI binding `AI`; variables `ALLOWED_ORIGIN` (comma-separated origins) and optional `AI_MODEL` |
| Configuration as code | [`wrangler.toml`](../wrangler.toml) (binding and variables), [`public/_headers`](../public/_headers) (CSP and security headers) |
| Custom domain | `entracompass` CNAME to `entracompass.pages.dev`, proxied, in the `aboutcloud.io` zone |
| Edge protection | Zone WAF custom rules, rate limiting on `/ai/ask`, TLS 1.2+, HSTS preload. See [SECURITY.md](../SECURITY.md#edge-security) |

No Cloudflare API token is stored in this repository: builds run on Cloudflare from the GitHub integration.

The Content Security Policy allows scripts from the site itself only. That is why the theme bootstrap is a file (`public/theme.js`) and not an inline script.

## Repository settings

| Setting | Value |
|---|---|
| Branch protection on `main` | Pull requests only; required checks `build` (ci.yml) and `trivy-scan` (security-scan.yml), up to date before merging |
| Merging | Squash; auto-merge allowed; head branches deleted after merge |
| Actions | Default workflow token read-only; "Allow GitHub Actions to create and approve pull requests" on, so the weekly auto-patch workflow can open its PR |
| Dependabot | Grouped minor and patch npm updates, auto-merged once checks pass |
| Code scanning | Trivy results uploaded to the Security tab |

## Self-hosting

1. Fork the repository.
2. Create a Cloudflare Pages project from the fork (or host `dist/` on any static host that can send the headers in `public/_headers`).
3. Set `ALLOWED_ORIGIN` to your own origin, or leave the AI function out: the assessment works without it.
4. Run `New-EntraCompassApp.ps1 -RedirectUri https://your-host` in each tenant you assess.
