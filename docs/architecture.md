# EntraCompass architecture

EntraCompass is a static single-page application. Everything that touches tenant data runs in the administrator's browser. Cloudflare serves the files and, optionally, a small AI endpoint. There is no application server and no database.

![EntraCompass architecture](diagrams/architecture.svg)

## Components

| Component | Where it runs | Role |
|---|---|---|
| Single-page app (`index.html`, `src/`) | Browser | UI, sign-in, data collection, analysis, what-if, report |
| MSAL Browser (`@azure/msal-browser`) | Browser | OAuth 2.0 authorization code flow with PKCE against your tenant |
| Microsoft Entra ID | Microsoft | Authenticates the administrator; your own Conditional Access applies |
| Microsoft Graph | Microsoft | Read-only source of configuration data |
| Cloudflare Pages | Cloudflare edge | Serves the built static files (`dist/`) with security headers |
| Pages Function `functions/ai/ask.js` | Cloudflare edge | Optional, stateless AI endpoint backed by Workers AI |

## Source layout

| File | Responsibility |
|---|---|
| `src/main.js` | Boot, MSAL sign-in, screens and tabs, exports, event handling |
| `src/graph.js` | Graph client: token acquisition, paging (`@odata.nextLink`), retry on 429/503/504 honouring `Retry-After`, bounded concurrency |
| `src/collect.js` | Which Graph calls are made, in what order; records success or failure of each source |
| `src/policy.js` | Pure helpers that describe one Conditional Access policy (scope, grant, session, conditions) |
| `src/analyzer.js` | Pure function `analyze(raw, options)` that produces findings, scores and answers |
| `src/whatif.js` | Pure function `evaluate(policies, scenario)`, a simplified Conditional Access evaluator |
| `src/report.js` | Builds the self-contained executive report HTML |
| `src/knowledge.js` | Well-known app IDs, privileged role IDs, documentation links |
| `src/demo-data.js` | Fictional sample tenant used by demo mode and by the unit tests |
| `functions/ai/ask.js` | AI endpoint: origin check, rate limit, input filters, prompt, streaming |
| `infra/New-EntraCompassApp.ps1` | Creates the customer's app registration |

## Scan pipeline

1. **Sign-in.** MSAL redirects to `login.microsoftonline.com/<tenant>` with PKCE. The token cache is kept in `sessionStorage`.
2. **Collect** (`collect.js`). Bulk, read-only calls. The number of calls grows with the number of result pages, not with the number of users, so the scan covers the whole tenant with no sampling:

   | Data | Graph endpoint | Permission |
   |---|---|---|
   | Tenant name | `GET /organization` | `Directory.Read.All` |
   | Conditional Access policies | `GET beta/identity/conditionalAccess/policies` (falls back to v1.0) | `Policy.Read.All` |
   | Named locations | `GET /identity/conditionalAccess/namedLocations` | `Policy.Read.All` |
   | Authentication contexts | `GET /identity/conditionalAccess/authenticationContextClassReferences` | `Policy.Read.All` |
   | Authentication strengths | `GET /policies/authenticationStrengthPolicies` | `Policy.Read.All` |
   | Role names | `GET /directoryRoleTemplates` | `Directory.Read.All` |
   | Enterprise apps | `GET /servicePrincipals?$top=999` | `Application.Read.All` |
   | App registrations | `GET /applications?$top=999` | `Application.Read.All` |
   | App sign-in activity | `GET beta/reports/servicePrincipalSignInActivities` | `AuditLog.Read.All` (Entra ID P1) |
   | User and guest counts | `GET /users/$count` | `Directory.Read.All` |
   | Users, groups and service principals named in policies | `POST /directoryObjects/getByIds` (1,000 IDs per call) | `Directory.Read.All` |
   | Group sizes | `GET /groups/{id}/transitiveMembers/$count`, only for groups referenced by policies, 4 in parallel | `Directory.Read.All` |

   Each source is recorded as succeeded or failed with a reason. A failed optional source (for example sign-in activity without P1) disables only the checks that depend on it, and the UI and report say so.
3. **Analyse** (`analyzer.js`). A pure function of the collected data plus the crown-jewel tags. It builds indexes, then:
   - classifies each enterprise app (App Proxy, SAML, password SSO, Microsoft, in-house, SaaS, managed identity) and computes its coverage from enabled policies;
   - lists every exclusion and gives it a verdict (gap, review, cleanup, stale, justified);
   - checks named locations, workload identity credentials, identity-side DLP controls and a modern baseline;
   - turns all of that into findings with severity, business impact and action;
   - scores six areas and answers nine management questions.
4. **Present.** Tabs, the what-if engine and the report are views over the analysis result. Changing crown-jewel tags re-runs the analysis locally; no new Graph calls.

## Scoring

Each area (access coverage, exceptions, data protection, workload identities, named locations, crown jewels) starts at 100 and loses points per finding: critical 30, high 15, medium 7, low 3. The overall score is a weighted average (25, 20, 20, 15, 10, 10 percent). The crown-jewel area is left out until at least one app is tagged. Ratings: 85+ Strong, 65+ Fair, 40+ Weak, below 40 At risk.

## What-if engine

`whatif.js` follows the documented evaluation model: a policy applies when every assignment and condition matches; exclusions win over inclusions; any applying block wins; otherwise every applying policy's grant must be satisfied. It evaluates users, groups, roles, guests, applications (including the Office 365 group), named and trusted locations, platforms, client app types and risk levels. Device filters, authentication flows and insider risk are reported as "not evaluated". It shows the outcome with enforced policies and, separately, with report-only policies switched on.

## Hosting and delivery

- **Cloudflare Pages** with GitHub integration: every push to `main` builds (`npm run build`) and deploys `dist/`. Pull requests get preview deployments.
- **Edge security**: see [SECURITY.md](../SECURITY.md#edge-security).
- **Optional AI**: the Pages Function has a Workers AI binding (`AI`), an origin allow-list (`ALLOWED_ORIGIN`) and an in-memory per-IP limit, behind the zone rate-limit rule.

## CI/CD

| Workflow | Purpose |
|---|---|
| `ci.yml` (required check `build`) | Unit tests for analyzer and what-if, production build, output check |
| `security-scan.yml` (required check `trivy-scan`) | Trivy filesystem scan to code scanning; fails on fixable critical dependency vulnerabilities |
| `dependabot.yml` + `dependabot-auto-merge.yml` | Weekly npm and monthly Actions updates; patch and minor auto-merge once checks pass |
| `auto-patch-deps.yml` | Weekly: overrides vulnerable transitive dependencies within their major version, opens a PR, runs CI, enables auto-merge; tracks anything needing a major upgrade in one issue |

`main` is protected: pull requests only, both required checks must pass and be up to date.

See also: [Data security architecture](data-architecture.md).
