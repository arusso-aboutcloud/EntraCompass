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
| Purview export file (optional) | Your device, then the browser | DLP and label configuration from `infra/Export-PurviewForEntraCompass.ps1`, opened in the page and parsed by `src/purview.js` |

## Source layout

| File | Responsibility |
|---|---|
| `src/main.js` | Boot, MSAL sign-in, screens and tabs, exports, event handling |
| `src/graph.js` | Graph client: token acquisition, paging (`@odata.nextLink`), retry on 429/503/504 honouring `Retry-After`, bounded concurrency |
| `src/collect.js` | Which Graph calls are made, in what order; records success or failure of each source |
| `src/policy.js` | Pure helpers that describe one Conditional Access policy (scope, grant, session, conditions) |
| `src/analyzer.js` | Pure function `analyze(raw, options)` that produces findings, scores and answers |
| `src/agents.js` | Pure analysis of AI agents (Entra Agent ID), Conditional Access for agents, agent risk, and application / delegated permissions and admin roles of agents and apps |
| `src/purview.js` | Parser for the optional Purview export, and Purview checks cross-referenced with Conditional Access |
| `src/whatif.js` | Pure function `evaluate(policies, scenario)`, a simplified Conditional Access evaluator |
| `src/report.js` | Builds the self-contained executive report HTML |
| `src/knowledge.js` | Well-known app IDs, privileged role IDs, documentation links |
| `src/demo-data.js` | Fictional sample tenant used by demo mode and by the unit tests |
| `functions/ai/ask.js` | AI endpoint: origin check, rate limit, input filters, prompt, streaming |
| `infra/New-EntraCompassApp.ps1` | Creates the customer's app registration (`-IncludeOptional` adds the agent and Purview read permissions) |
| `infra/Export-PurviewForEntraCompass.ps1` | Read-only export of DLP policies and rules, sensitivity labels and label policies, for loading in the Purview view |

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
   | Agent identities and sponsors | `GET beta/servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors` | `AgentIdentity.Read.All` (optional) |
   | Agent blueprints | `GET beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal` | `AgentIdentity.Read.All` (optional) |
   | Agent user accounts | `GET beta/users/microsoft.graph.agentUser` | `Directory.Read.All` |
   | Risky agents | `GET beta/identityProtection/riskyAgents` | `IdentityRiskyAgent.Read.All` (optional) |
   | Application permissions | `GET /servicePrincipals/{resource}/appRoleAssignedTo` for Microsoft Graph, Exchange Online and SharePoint Online (3 paged calls) | `Application.Read.All` |
   | Delegated grants | `GET /oauth2PermissionGrants` | `Directory.Read.All` |
   | Directory role assignments | `GET /roleManagement/directory/roleAssignments` | `Directory.Read.All` |
   | Sensitivity labels | `GET beta/me/security/informationProtection/sensitivityLabels` | `InformationProtectionPolicy.Read` (optional) |

   Each source is recorded as succeeded or failed with a reason. Sources marked optional (agent, risk and label APIs, sign-in activity) do not trigger the "partial data" warning; the related view explains how to enable them. A failed optional source (for example sign-in activity without P1) disables only the checks that depend on it, and the UI and report say so.
3. **Analyse** (`analyzer.js`). A pure function of the collected data plus the crown-jewel tags. It builds indexes, then:
   - classifies each enterprise app (App Proxy, SAML, password SSO, Microsoft, in-house, SaaS, managed identity) and computes its coverage from enabled policies;
   - lists every exclusion and gives it a verdict (gap, review, cleanup, stale, justified);
   - checks named locations, workload identity credentials and permissions, identity-side DLP controls and a modern baseline;
   - inventories AI agents and checks them against an agent baseline (agent policies, risk, allow-list, agent users, sponsors, least privilege);
   - checks Purview labels and, when an export is loaded, DLP locations against Conditional Access;
   - turns all of that into findings with severity, business impact and action;
   - scores seven areas and answers eleven management questions.
   Agent, agent-user and workload identity policies are kept apart from user policies, so they never count as MFA coverage for people.
4. **Present.** Tabs, the what-if engine and the report are views over the analysis result. Changing crown-jewel tags re-runs the analysis locally; no new Graph calls.

## Scoring

Each area (access coverage, exceptions, data protection and Purview, workload identities, AI agents, named locations, crown jewels) starts at 100 and loses points per finding: critical 30, high 15, medium 7, low 3. The overall score is a weighted average (22, 18, 18, 12, 12, 8, 10 percent). The crown-jewel area is left out until at least one app is tagged, and the AI agents area while no agents are found. Purview checks that need an export are "not assessed" and do not affect the score. Ratings: 85+ Strong, 65+ Fair, 40+ Weak, below 40 At risk.

## What-if engine

`whatif.js` follows the documented evaluation model: a policy applies when every assignment and condition matches; exclusions win over inclusions; any applying block wins; otherwise every applying policy's grant must be satisfied. It evaluates users, groups, roles, guests, applications (including the Office 365 group), named and trusted locations, platforms, client app types, sign-in and user risk, authentication flows (device code, authentication transfer) and insider risk. It also evaluates AI agents acting on their own (agent policies only, by agent, blueprint and agent risk) and agent user accounts (agent-user policies only). Device filters, application filters and agent attribute filters are reported as "not evaluated". It shows the outcome with enforced policies and, separately, with report-only policies switched on.

## Hosting and delivery

- **Cloudflare Pages** with GitHub integration: every push to `main` builds (`npm run build`) and deploys `dist/`; branches and pull requests get preview deployments and a "Cloudflare Pages" check. Setup details: [infra/README.md](../infra/README.md).
- **Edge security**: see [SECURITY.md](../SECURITY.md#edge-security).
- **Optional AI**: the Pages Function has a Workers AI binding (`AI`), an origin allow-list (`ALLOWED_ORIGIN`) and an in-memory per-IP limit, behind the zone rate-limit rule.

## CI/CD

| Workflow | Purpose |
|---|---|
| `ci.yml` (required check `build`) | Unit tests (analyzer, agents, Purview parser and checks, what-if, report), production build, output check |
| `security-scan.yml` (required check `trivy-scan`) | Trivy filesystem scan to code scanning; fails on fixable critical dependency vulnerabilities |
| `dependabot.yml` + `dependabot-auto-merge.yml` | Weekly npm and monthly Actions updates; patch and minor auto-merge once checks pass |
| `auto-patch-deps.yml` | Weekly: overrides vulnerable transitive dependencies within their major version, opens a PR, runs CI, enables auto-merge; tracks anything needing a major upgrade in one issue |

`main` is protected: pull requests only, both required checks must pass and be up to date. The auto-patch workflow needs the repository setting "Allow GitHub Actions to create and approve pull requests".

## Diagrams

| Diagram | Shows |
|---|---|
| [architecture.svg](diagrams/architecture.svg) | Components and the five data paths (sign-in, Graph, app files, optional AI, optional Purview file) |
| [data-flow.svg](diagrams/data-flow.svg) | Data lifecycle inside the browser trust boundary |
| [agents-access-patterns.svg](diagrams/agents-access-patterns.svg) | Which Conditional Access applies to each AI agent access pattern (preview) |
| [purview-ca.svg](diagrams/purview-ca.svg) | The Purview and Conditional Access pairs EntraCompass checks |

See also: [Data security architecture](data-architecture.md).
