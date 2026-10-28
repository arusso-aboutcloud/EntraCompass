# Data security architecture

This document describes what data EntraCompass handles, where it lives, who can see it, and the controls around it. The short version: tenant data stays in the administrator's browser tab and is never stored by the service.

![Data lifecycle and trust boundaries](diagrams/data-flow.svg)

## Privacy contract

These are design commitments. Changes that break them will not be merged.

1. **No backend storage.** There is no database, no server-side session and no logging of scan results.
2. **Browser storage is `sessionStorage` only.** No `localStorage`, no IndexedDB, no cookies. Everything is cleared when the tab closes or on sign-out.
3. **Read-only.** Only delegated read permissions (`*.Read.All`, plus the optional `InformationProtectionPolicy.Read`); the app never writes to the tenant. The Purview export script only runs `Get-*` cmdlets.
4. **No secrets.** Public client with PKCE. There is no client secret or certificate to leak.
5. **Minimised AI.** The optional assistant receives aggregated numbers and finding titles with names removed; never identifiers.

## Data inventory

| Data | Source | Sensitivity | Where it lives | Lifetime |
|---|---|---|---|---|
| Tenant ID, client ID | Typed by the user | Low (not secret) | `sessionStorage` | Tab session |
| Access token, ID token, refresh token | Microsoft Entra ID via MSAL | High | `sessionStorage` (MSAL cache) | Tab session; token lifetime set by your tenant |
| Conditional Access policies, named locations (incl. IP ranges), auth contexts and strengths | Graph | High: describes your defences | Memory and `sessionStorage` | Tab session |
| Enterprise apps, app registrations, credential metadata (dates only, never secret values) | Graph | Medium | Memory and `sessionStorage` | Tab session |
| Names and UPNs of users, groups and service principals named in policies; group member counts | Graph | Personal data (names, UPNs) | Memory and `sessionStorage` | Tab session |
| App sign-in dates | Graph (beta report) | Medium | Memory and `sessionStorage` | Tab session |
| AI agents: agent identities, blueprints, sponsors (names), agent user accounts (names, UPNs), agent risk | Graph (beta, Entra Agent ID and ID Protection) | Medium; sponsor and agent-user names are personal data | Memory and `sessionStorage` | Tab session |
| Application permissions, delegated grants, directory role assignments (IDs and permission names) | Graph | High: shows who can change the tenant | Memory and `sessionStorage` | Tab session |
| Sensitivity label names and settings | Graph (labels published to the signed-in admin) | Medium | Memory and `sessionStorage` | Tab session |
| Purview export: DLP policy and rule names, modes, locations, actions, sensitive information type names; label names and settings | A JSON file the admin creates and opens in the page | High: describes your DLP design. Email addresses are redacted by the export script | Read with the File API, parsed in the page, kept in memory and `sessionStorage`. Never uploaded | Tab session, or until "Remove" |
| Theme choice | The user | None | `sessionStorage` | Tab session |
| Crown-jewel tags | The user | Low | `sessionStorage`; optional JSON download | Tab session / user's file |
| Analysis results, report | Computed locally | High | Memory; downloads the user makes | Tab session / user's file |
| AI question and summary | The user / computed | Low: no identifiers | Sent to `/ai/ask`, not stored | Single request |

Graph never returns secret or certificate *values* for app credentials; EntraCompass reads only their start and end dates.

## Data flows

| # | Flow | Path | Protection |
|---|---|---|---|
| 1 | Sign-in | Browser and `login.microsoftonline.com` | TLS; authorization code + PKCE; your Conditional Access applies to the administrator |
| 2 | Graph reads | Browser and `graph.microsoft.com`, **direct**, not through Cloudflare | TLS; bearer token scoped to read permissions; CSP `connect-src` limits where the page can send data |
| 3 | App delivery | Cloudflare Pages to browser | TLS 1.2+ (1.3 preferred), HSTS preload, WAF, security headers |
| 4 | Optional AI | Browser to `/ai/ask` (Cloudflare) to Workers AI | Origin allow-list, rate limits, input filters, aggregated payload only |
| 5 | Downloads | Browser to the user's disk | Explicit user action; CSV cells escaped against formula injection |
| 6 | Purview export | User's disk to the browser tab (File API) | Never leaves the browser; 5 MB cap; parsed as data (JSON), every value escaped before display |

### What the AI endpoint receives

Built in `aiSummary()` in `src/main.js`: overall and per-area scores, policy counts, user and guest totals, percentage outside MFA, app and exception counts by verdict, workload credential totals, AI agent totals and agent check statuses, Purview totals and check statuses, DLP control and baseline statuses, and up to 30 finding titles. Agent and Purview finding titles are counts, never names. Quoted names in titles are replaced with "an app"; named-location titles drop the location name. No user names, UPNs, object IDs, IP ranges, policy JSON or tokens. The function does not store requests; Workers AI processes the prompt to produce the answer.

## Trust boundaries and threats

| Threat | Mitigation |
|---|---|
| Malicious script steals tokens or data (XSS) | All Graph and user text is escaped before rendering; strict CSP (`script-src 'self'`, no inline scripts, no third-party scripts); `object-src 'none'`, `base-uri 'self'` |
| Page exfiltrates data to a third party | CSP `connect-src` allows only self, `login.microsoftonline.com` and `graph.microsoft.com` |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| Tampered build or dependency | Lockfile installs (`npm ci`), Dependabot, weekly auto-patch, Trivy in CI; `main` protected with required checks; GitHub Actions pinned by commit SHA |
| Token theft from storage | `sessionStorage` is per tab and per origin and is cleared on close; no long-lived storage |
| Over-privileged access | Read-only delegated scopes; the signed-in admin's own role further limits what Graph returns |
| Abuse of the AI endpoint (cost, prompt injection) | Origin allow-list, per-IP limit in the function, zone rate limit, WAF method rule (POST/OPTIONS only on `/ai/ask`), prompt-injection and harmful-request filters, 2,000-character question cap, 64 KB body cap |
| Malicious or malformed Purview file | 5 MB cap; parsed with `JSON.parse` only (no code evaluation); unknown shapes rejected with a readable error; every value escaped before rendering; strings truncated |
| Sensitive data in the Purview file | The export script writes configuration only (names, modes, locations, actions) and replaces email addresses with `[redacted]`; the file is never uploaded |
| Misleading output | Every source failure is shown in the UI and report; optional sources explain how to enable them; simplifications of the what-if engine are stated; AI agent results are labelled Preview because they rely on beta APIs |
| Shared or unattended computer | Sign-out clears all EntraCompass and MSAL keys; closing the tab clears `sessionStorage` |

## Customer controls

- Delete the app registration after the assessment, or disable it between assessments.
- Require assignment on the enterprise app so only named assessors can sign in.
- Apply your own Conditional Access to the EntraCompass app (for example phishing-resistant MFA and a compliant device).
- Review sign-ins to the app in the Entra sign-in logs.
- Self-host: fork the repository and deploy `dist/` anywhere; set `ALLOWED_ORIGIN` for the AI function or omit it.

## Retention

EntraCompass retains nothing. Files you download (report, CSV, JSON, tags) are yours to classify and protect: the report and JSON contain configuration details of your security controls and should be handled as confidential.
