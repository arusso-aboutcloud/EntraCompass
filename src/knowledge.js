// Static reference data. Kept small and conservative: only well-known,
// documented IDs. Unknown IDs are resolved from the tenant's own data.

// Microsoft's own tenants. Service principals owned by these are Microsoft
// first-party apps.
export const MICROSOFT_TENANT_IDS = new Set([
  'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
  '72f988bf-86f1-41af-91ab-2d7cd011db47',
]);

// Well-known first-party resources. `o365` marks members of the "Office 365"
// app group that Conditional Access can target as a single value.
// `exclusion` gives guidance when the app shows up as a policy exclusion.
export const KNOWN_APPS = {
  '00000002-0000-0ff1-ce00-000000000000': { name: 'Office 365 Exchange Online', o365: true, dataStore: true },
  '00000003-0000-0ff1-ce00-000000000000': { name: 'Office 365 SharePoint Online', o365: true, dataStore: true },
  'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe': { name: 'Microsoft Teams Services', o365: true, dataStore: true },
  '00000003-0000-0000-c000-000000000000': { name: 'Microsoft Graph' },
  '00000002-0000-0000-c000-000000000000': { name: 'Windows Azure Active Directory' },
  '797f4846-ba00-4fd7-ba43-dac1f8f63013': {
    name: 'Windows Azure Service Management API',
    exclusion: { verdict: 'gap', why: 'This is the Azure portal, CLI and PowerShell. Excluding it leaves the Azure admin surface outside the policy.' },
  },
  '00000012-0000-0000-c000-000000000000': {
    name: 'Microsoft Rights Management Services',
    dlp: true,
    exclusion: { verdict: 'justified', why: 'Used to open encrypted (sensitivity-labelled) content. Excluding it is sometimes needed so external recipients can open protected files. Record it as a DLP decision with an owner.' },
  },
  'd4ebce55-015a-49b5-a083-c84d1797ae8c': {
    name: 'Microsoft Intune Enrollment',
    exclusion: { verdict: 'justified', why: 'Commonly excluded from device-compliance policies so new devices can enroll before they are compliant. Keep MFA on it.' },
  },
  '0000000a-0000-0000-c000-000000000000': {
    name: 'Microsoft Intune',
    exclusion: { verdict: 'justified', why: 'Commonly excluded from device-compliance policies during enrollment. Keep MFA on it.' },
  },
  '45a330b1-b1ec-4cc1-9161-9f03992aa49f': { name: 'Windows Store for Business' },
  '9cdead84-a844-4324-93f2-b2e6bb768d07': { name: 'Azure Virtual Desktop' },
  '0af06dc6-e4b5-4f28-818e-e78e62d137a5': { name: 'Windows 365' },
  '270efc09-cd0d-444b-a71f-39af4910ec45': { name: 'Windows Cloud Login' },
  '05a65629-4c1b-48c1-a78b-804c4abdd4af': { name: 'Microsoft Defender for Cloud Apps', dlp: true },
};

// Built-in role template IDs considered privileged.
export const PRIVILEGED_ROLES = {
  '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
  'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
  '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
  '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
  '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
  'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
  '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator',
  'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
  'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
  '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
  '17315797-102d-40b4-93e0-432062caca18': 'Compliance Administrator',
  '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': 'Hybrid Identity Administrator',
};

// The directory sync service account role. Excluding it is expected.
export const DIRECTORY_SYNC_ROLE = 'd29b2b05-8046-44ba-8758-1e26182fcf32';

// Authentication methods that count as phishing-resistant in an
// authentication strength.
export const PHISHING_RESISTANT = new Set([
  'fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor',
]);

// Keyword hints used only to *suggest* crown-jewel candidates. The user
// always confirms.
export const CROWN_JEWEL_HINTS = [
  'sap', 'workday', 'salesforce', 'servicenow', 'oracle', 'dynamics', 'netsuite',
  'payroll', 'finance', 'erp', 'crm', 'hr', 'adp', 'successfactors', 'coupa',
  'concur', 'treasury', 'bank', 'swift', 'github', 'gitlab', 'jira', 'confluence',
  'aws', 'google cloud', 'snowflake', 'databricks', 'tableau', 'power bi', 'docusign',
  'box', 'dropbox', 'okta', 'cyberark', 'vault',
];

export const DOCS = {
  caOverview: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview',
  caApps: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps',
  caUsers: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups',
  namedLocations: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network',
  workloadCa: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity',
  sessionControls: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-session',
  appControl: 'https://learn.microsoft.com/en-us/defender-cloud-apps/proxy-intro-aad',
  authContext: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context',
  authStrength: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
  emergencyAccess: 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
  legacyAuth: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication',
  authFlows: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows',
  tokenProtection: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection',
  managedPolicies: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies',
  insiderRisk: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-insider-risk',
  appProxy: 'https://learn.microsoft.com/en-us/entra/identity/app-proxy/overview-what-is-app-proxy',
  samlSso: 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/plan-sso-deployment',
  purviewDlp: 'https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp',
  adaptiveProtection: 'https://learn.microsoft.com/en-us/purview/insider-risk-management-adaptive-protection',
  reportOnly: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only',
  whatIf: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool',
};
