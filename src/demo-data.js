// Sample tenant ("Contoso Ltd") used by the tests and by demo mode. Entirely fictional.
// Story: a mid-size company with good intentions and typical drift: an MFA
// policy full of exceptions, a SAML ERP excluded, agent policies still in
// report-only while AI agents go live, and DLP that has not caught up with
// Copilot.
const TENANT = '11111111-1111-1111-1111-111111111111';
const MS = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
const VENDOR = '99999999-0000-0000-0000-000000000000';
const AI_VENDOR = '77777777-0000-0000-0000-000000000000';
const GA = '62e90394-69f5-4237-9190-012177145e10';
const PRA = 'e8611ab8-c189-46e8-94e1-60213ab1f814';
const SECADMIN = '194ae4cb-b126-40b2-bd5b-6091b380977d';
const HELPDESK = '729827e3-9c14-49f7-bb1b-9608f156bbb8';
const PHISH_RES = '00000000-0000-0000-0000-000000000004';

export const IDS = {
  tenant: TENANT,
  bg1: 'aaaaaaaa-0000-0000-0000-000000000001',
  bg2: 'aaaaaaaa-0000-0000-0000-000000000002',
  contractor: 'aaaaaaaa-0000-0000-0000-000000000003',
  deletedUser: 'aaaaaaaa-0000-0000-0000-0000000000ff',
  exceptionsGroup: 'bbbbbbbb-0000-0000-0000-000000000001',
  financeGroup: 'bbbbbbbb-0000-0000-0000-000000000002',
  officeLoc: 'cccccccc-0000-0000-0000-000000000001',
  blockedCountries: 'cccccccc-0000-0000-0000-000000000002',
  sapApp: 'dddddddd-0000-0000-0000-000000000001',
  intranetApp: 'dddddddd-0000-0000-0000-000000000002',
  hrApp: 'dddddddd-0000-0000-0000-000000000003',
  deletedApp: 'dddddddd-0000-0000-0000-0000000000ff',
  batchApp: 'eeeeeeee-0000-0000-0000-000000000001',
  oldApp: 'eeeeeeee-0000-0000-0000-000000000002',
  aiConnectorApp: 'eeeeeeee-0000-0000-0000-000000000003',
  salesforceApp: 'dddddddd-0000-0000-0000-000000000004',
  githubApp: 'dddddddd-0000-0000-0000-000000000005',
  meetingNotesApp: 'dddddddd-0000-0000-0000-000000000006',
  // Entra Agent ID
  bpCopilotStudio: '12000000-0000-0000-0000-000000000001', // blueprint principal object ids
  bpFoundry: '12000000-0000-0000-0000-000000000002',
  bpVendor: '12000000-0000-0000-0000-000000000003',
  bpCopilotStudioApp: '13000000-0000-0000-0000-000000000001', // blueprint app ids
  bpFoundryApp: '13000000-0000-0000-0000-000000000002',
  bpVendorApp: '13000000-0000-0000-0000-000000000003',
  hrAgent: '14000000-0000-0000-0000-000000000001',
  invoiceAgent: '14000000-0000-0000-0000-000000000002',
  salesAgent: '14000000-0000-0000-0000-000000000003',
  helpdeskAgent: '14000000-0000-0000-0000-000000000004',
  helpdeskAgentUser: '15000000-0000-0000-0000-000000000001',
  hrDirector: 'aaaaaaaa-0000-0000-0000-000000000010',
  financeLead: 'aaaaaaaa-0000-0000-0000-000000000011',
};

const allUsersMfa = {
  id: 'p1', displayName: 'CA001 Require MFA for all users', state: 'enabled',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2, IDS.contractor, IDS.deletedUser], excludeGroups: [IDS.exceptionsGroup] },
    applications: { includeApplications: ['All'], excludeApplications: [IDS.sapApp, IDS.deletedApp, '0000000a-0000-0000-c000-000000000000'] },
    locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    clientAppTypes: ['all'],
  },
  grantControls: { operator: 'OR', builtInControls: ['mfa'] },
};

const blockLegacy = {
  id: 'p2', displayName: 'CA002 Block legacy authentication', state: 'enabled',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['All'] },
    clientAppTypes: ['exchangeActiveSync', 'other'],
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

const adminsMfa = {
  id: 'p3', displayName: 'CA003 Admins require MFA', state: 'enabled',
  conditions: {
    users: { includeRoles: ['62e90394-69f5-4237-9190-012177145e10'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['All'] },
    clientAppTypes: ['all'],
  },
  grantControls: { operator: 'OR', builtInControls: ['mfa'] },
};

const blockCountries = {
  id: 'p4', displayName: 'CA004 Block high-risk countries', state: 'enabled',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['All'] },
    locations: { includeLocations: [IDS.blockedCountries] },
    clientAppTypes: ['all'],
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

const compliantDevice = {
  id: 'p5', displayName: 'CA005 Compliant device for Office 365', state: 'enabledForReportingButNotEnforced',
  createdDateTime: '2026-01-10T00:00:00Z',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['Office365'] },
    clientAppTypes: ['mobileAppsAndDesktopClients'],
  },
  grantControls: { operator: 'OR', builtInControls: ['compliantDevice'] },
};

const sessionMda = {
  id: 'p6', displayName: 'CA006 Monitor finance sessions', state: 'enabled',
  conditions: {
    users: { includeGroups: [IDS.financeGroup] },
    applications: { includeApplications: [IDS.hrApp] },
    clientAppTypes: ['browser'],
  },
  sessionControls: { cloudAppSecurity: { isEnabled: true, cloudAppSecurityType: 'monitorOnly' } },
};

const workload = {
  id: 'p7', displayName: 'CA007 Workload identities from office only', state: 'disabled',
  conditions: {
    users: { includeUsers: ['None'] },
    applications: { includeApplications: ['All'] },
    clientApplications: { includeServicePrincipals: ['ServicePrincipalsInMyTenant'] },
    locations: { includeLocations: ['All'], excludeLocations: [IDS.officeLoc] },
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

const adminsPhishRes = {
  id: 'p8', displayName: 'CA008 Phishing-resistant MFA for highly privileged admins', state: 'enabled',
  createdDateTime: '2026-03-02T00:00:00Z',
  conditions: {
    users: { includeRoles: [GA, PRA, SECADMIN], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['All'] },
    clientAppTypes: ['all'],
  },
  grantControls: { operator: 'OR', builtInControls: [], authenticationStrength: { id: PHISH_RES, displayName: 'Phishing-resistant MFA' } },
};

const blockDeviceCode = {
  id: 'p9', displayName: 'CA009 Block device code flow', state: 'enabled',
  createdDateTime: '2026-05-11T00:00:00Z',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['All'] },
    clientAppTypes: ['all'],
    authenticationFlows: { transferMethods: 'deviceCodeFlow' },
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

// Conditional Access for agents (Graph beta schema).
const agentsHighRisk = {
  id: 'p10', displayName: 'CA010 AI agents: block high agent risk', state: 'enabledForReportingButNotEnforced',
  createdDateTime: '2026-07-20T00:00:00Z',
  conditions: {
    users: { includeUsers: ['None'] },
    applications: { includeApplications: ['All'] },
    clientApplications: { includeAgentIdServicePrincipals: ['All'] },
    agentIdRiskLevels: 'high',
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

const agentsAllowList = {
  id: 'p11', displayName: 'CA011 AI agents: approved agents only', state: 'enabledForReportingButNotEnforced',
  createdDateTime: '2026-07-20T00:00:00Z',
  conditions: {
    users: { includeUsers: ['None'] },
    applications: { includeApplications: ['All'] },
    clientApplications: { includeAgentIdServicePrincipals: ['All'], excludeAgentIdServicePrincipals: [IDS.hrAgent, IDS.invoiceAgent] },
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

const insiderRisk = {
  id: 'p12', displayName: 'CA012 Adaptive Protection: block elevated insider risk', state: 'enabledForReportingButNotEnforced',
  createdDateTime: '2026-09-01T00:00:00Z',
  conditions: {
    users: { includeUsers: ['All'], excludeUsers: [IDS.bg1, IDS.bg2] },
    applications: { includeApplications: ['Office365'] },
    clientAppTypes: ['all'],
    insiderRiskLevels: 'elevated',
  },
  grantControls: { operator: 'OR', builtInControls: ['block'] },
};

// A Purview export as produced by infra/Export-PurviewForEntraCompass.ps1.
export const purviewExport = {
  tool: 'EntraCompass', kind: 'purview-export', version: 1, exportedAt: '2026-10-27T16:00:00Z',
  dlpPolicies: [
    { Name: 'Financial data (email and files)', Mode: 'Enable', Workload: 'Exchange, SharePoint, OneDriveForBusiness', ExchangeLocation: ['All'], SharePointLocation: ['All'], OneDriveLocation: ['All'], WhenChangedUTC: '2026-04-02T10:00:00Z' },
    { Name: 'Credentials in Teams chat', Mode: 'Enable', Workload: 'Teams', TeamsLocation: ['All'], WhenChangedUTC: '2026-04-02T10:00:00Z' },
    { Name: 'Personal data on devices', Mode: 'TestWithNotifications', Workload: 'EndpointDevices', EndpointDlpLocation: ['All'], WhenChangedUTC: '2026-06-15T08:30:00Z' },
    { Name: 'Unmanaged devices: block download of confidential files', Mode: 'Enable', Workload: 'ThirdPartyApps', ThirdPartyAppDlpLocation: ['All'], WhenChangedUTC: '2026-08-21T12:00:00Z' },
  ],
  dlpRules: [
    { Name: 'Credit card numbers - external', ParentPolicyName: 'Financial data (email and files)', BlockAccess: true, ContentContainsSensitiveInformation: [{ name: 'Credit Card Number' }], NotifyUser: ['Owner'] },
    { Name: 'IBAN - external', ParentPolicyName: 'Financial data (email and files)', BlockAccess: true, ContentContainsSensitiveInformation: [{ name: 'International Banking Account Number (IBAN)' }] },
    { Name: 'Passwords in chat', ParentPolicyName: 'Credentials in Teams chat', BlockAccess: true, ContentContainsSensitiveInformation: [{ name: 'General Password' }] },
    { Name: 'National IDs to USB or cloud', ParentPolicyName: 'Personal data on devices', EndpointDlpRestrictions: [{ Setting: 'RemovableMedia', Value: 'Block' }], ContentContainsSensitiveInformation: [{ name: 'EU National Identification Number' }] },
    { Name: 'Confidential download on unmanaged', ParentPolicyName: 'Unmanaged devices: block download of confidential files', AdvancedRule: '{"Condition":{"Label":"Confidential"}}', BlockAccess: true },
  ],
  labels: [
    { Name: 'Public', DisplayName: 'Public', Guid: 'aa000000-0000-0000-0000-000000000001', EncryptionEnabled: false, ContentType: 'File, Email' },
    { Name: 'General', DisplayName: 'General', Guid: 'aa000000-0000-0000-0000-000000000002', EncryptionEnabled: false, ContentType: 'File, Email' },
    { Name: 'Confidential', DisplayName: 'Confidential', Guid: 'aa000000-0000-0000-0000-000000000003', EncryptionEnabled: false, ContentType: 'File, Email, Site, UnifiedGroup' },
    { Name: 'Highly Confidential', DisplayName: 'Highly Confidential', Guid: 'aa000000-0000-0000-0000-000000000004', EncryptionEnabled: true, ContentType: 'File, Email, Site, UnifiedGroup', Settings: ['[authenticationcontextid, c1]'] },
    { Name: 'HC-Finance', DisplayName: 'Highly Confidential / Finance', Guid: 'aa000000-0000-0000-0000-000000000005', ParentId: 'aa000000-0000-0000-0000-000000000004', EncryptionEnabled: true, ContentType: 'File, Email' },
  ],
  labelPolicies: [{ Name: 'Default label policy', Labels: ['Public', 'General', 'Confidential', 'Highly Confidential'] }],
  autoLabelPolicies: [{ Name: 'Auto-label financial data', Mode: 'TestWithoutNotifications' }],
};

export const fixture = {
  scannedAt: '2026-10-28T09:00:00Z',
  organization: { id: TENANT, displayName: 'Contoso Ltd' },
  policies: [allUsersMfa, blockLegacy, adminsMfa, blockCountries, compliantDevice, sessionMda, workload, adminsPhishRes, blockDeviceCode, agentsHighRisk, agentsAllowList, insiderRisk],
  namedLocations: [
    { '@odata.type': '#microsoft.graph.ipNamedLocation', id: IDS.officeLoc, displayName: 'Head office', isTrusted: true, ipRanges: [{ cidrAddress: '203.0.113.0/24' }, { cidrAddress: '10.0.0.0/8' }, { cidrAddress: '52.0.0.0/8' }] },
    { '@odata.type': '#microsoft.graph.countryNamedLocation', id: IDS.blockedCountries, displayName: 'Blocked countries', countriesAndRegions: ['KP', 'IR'], includeUnknownCountriesAndRegions: false },
    { '@odata.type': '#microsoft.graph.ipNamedLocation', id: 'cccccccc-0000-0000-0000-000000000003', displayName: 'Old datacenter', isTrusted: false, ipRanges: [{ cidrAddress: '198.51.100.0/24' }] },
  ],
  authContexts: [
    { id: 'c1', displayName: 'Highly confidential', isAvailable: true },
  ],
  authStrengths: [
    { id: PHISH_RES, displayName: 'Phishing-resistant MFA', policyType: 'builtIn', allowedCombinations: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'] },
  ],
  roleTemplates: [],
  servicePrincipals: [
    { id: 'sp-sap', appId: IDS.sapApp, displayName: 'SAP ERP', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-intranet', appId: IDS.intranetApp, displayName: 'Intranet portal', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application', tags: ['WindowsAzureActiveDirectoryOnPremApp'] },
    { id: 'sp-hr', appId: IDS.hrApp, displayName: 'Workday', appOwnerOrganizationId: '99999999-0000-0000-0000-000000000000', servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-spo', appId: '00000003-0000-0ff1-ce00-000000000000', displayName: 'Office 365 SharePoint Online', appOwnerOrganizationId: MS, servicePrincipalType: 'Application' },
    { id: 'sp-intune', appId: '0000000a-0000-0000-c000-000000000000', displayName: 'Microsoft Intune', appOwnerOrganizationId: MS, servicePrincipalType: 'Application' },
    { id: 'sp-batch', appId: IDS.batchApp, displayName: 'Nightly batch', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application' },
    { id: 'sp-mi', appId: 'ffffffff-0000-0000-0000-000000000001', displayName: 'func-prod', servicePrincipalType: 'ManagedIdentity' },
    { id: 'sp-salesforce', appId: IDS.salesforceApp, displayName: 'Salesforce', appOwnerOrganizationId: VENDOR, servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-github', appId: IDS.githubApp, displayName: 'GitHub Enterprise Cloud', appOwnerOrganizationId: VENDOR, servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-meetingnotes', appId: IDS.meetingNotesApp, displayName: 'Meeting Notes AI', appOwnerOrganizationId: AI_VENDOR, servicePrincipalType: 'Application', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-aiconnector', appId: IDS.aiConnectorApp, displayName: 'OpenAI SharePoint Connector', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application' },
  ],
  // Microsoft Entra Agent ID (beta)
  agentBlueprints: [
    { id: IDS.bpCopilotStudio, appId: IDS.bpCopilotStudioApp, displayName: 'Copilot Studio agents', appOwnerOrganizationId: MS, verifiedPublisher: { verifiedPublisherId: '1' } },
    { id: IDS.bpFoundry, appId: IDS.bpFoundryApp, displayName: 'Contoso Foundry agents', appOwnerOrganizationId: TENANT },
    { id: IDS.bpVendor, appId: IDS.bpVendorApp, displayName: 'Fabrikam Sales AI', appOwnerOrganizationId: AI_VENDOR, verifiedPublisher: {} },
  ],
  agentIdentities: [
    { id: IDS.hrAgent, displayName: 'HR Onboarding Agent', agentIdentityBlueprintId: IDS.bpCopilotStudioApp, accountEnabled: true, servicePrincipalType: 'ServiceIdentity', createdDateTime: '2026-08-04T00:00:00Z', sponsors: [{ id: IDS.hrDirector, displayName: 'Dana Whitfield (HR Director)' }] },
    { id: IDS.invoiceAgent, displayName: 'Invoice Triage Agent', agentIdentityBlueprintId: IDS.bpFoundryApp, accountEnabled: true, servicePrincipalType: 'ServiceIdentity', createdDateTime: '2026-08-19T00:00:00Z', sponsors: [{ id: IDS.financeLead, displayName: 'Marc Olsen (Finance Ops)' }] },
    { id: IDS.salesAgent, displayName: 'Sales Research Agent', agentIdentityBlueprintId: IDS.bpVendorApp, accountEnabled: true, servicePrincipalType: 'ServiceIdentity', createdDateTime: '2026-09-30T00:00:00Z', sponsors: [] },
    { id: IDS.helpdeskAgent, displayName: 'IT Helpdesk Agent', agentIdentityBlueprintId: IDS.bpFoundryApp, accountEnabled: true, servicePrincipalType: 'ServiceIdentity', createdDateTime: '2026-10-02T00:00:00Z', sponsors: [] },
  ],
  agentUsers: [
    { id: IDS.helpdeskAgentUser, displayName: 'IT Helpdesk Agent', userPrincipalName: 'helpdesk.agent@contoso.com', accountEnabled: true, identityParentId: IDS.helpdeskAgent },
  ],
  riskyAgents: [
    { id: IDS.invoiceAgent, agentDisplayName: 'Invoice Triage Agent', identityType: 'agentIdentity', isDeleted: false, isEnabled: true, riskLevel: 'high', riskState: 'atRisk', riskDetail: 'none', riskLastModifiedDateTime: '2026-10-26T14:12:00Z' },
  ],
  // Application permissions, read from the resource side.
  appRoleGrants: [
    { principalId: IDS.invoiceAgent, principalName: 'Invoice Triage Agent', resource: 'Microsoft Graph', permission: 'Mail.Read' },
    { principalId: IDS.invoiceAgent, principalName: 'Invoice Triage Agent', resource: 'Microsoft Graph', permission: 'Files.ReadWrite.All' },
    { principalId: IDS.salesAgent, principalName: 'Sales Research Agent', resource: 'Microsoft Graph', permission: 'Sites.Read.All' },
    { principalId: IDS.bpFoundry, principalName: 'Contoso Foundry agents', resource: 'Microsoft Graph', permission: 'User.Read.All' },
    { principalId: 'sp-aiconnector', principalName: 'OpenAI SharePoint Connector', resource: 'Microsoft Graph', permission: 'Sites.Read.All' },
    { principalId: 'sp-aiconnector', principalName: 'OpenAI SharePoint Connector', resource: 'Microsoft Graph', permission: 'Files.Read.All' },
    { principalId: 'sp-batch', principalName: 'Nightly batch', resource: 'Microsoft Graph', permission: 'Directory.ReadWrite.All' },
    { principalId: 'sp-batch', principalName: 'Nightly batch', resource: 'Microsoft Graph', permission: 'User.Read.All' },
  ],
  delegatedGrants: [
    { clientId: 'sp-meetingnotes', consentType: 'AllPrincipals', resourceId: 'sp-graph', scope: 'User.Read Mail.Read Files.Read.All Calendars.Read offline_access' },
    { clientId: IDS.hrAgent, consentType: 'AllPrincipals', resourceId: 'sp-graph', scope: 'User.Read Sites.Read.All' },
  ],
  roleAssignments: [
    { id: 'ra1', principalId: IDS.bg1, roleDefinitionId: GA, directoryScopeId: '/' },
    { id: 'ra2', principalId: IDS.bg2, roleDefinitionId: GA, directoryScopeId: '/' },
    { id: 'ra3', principalId: IDS.helpdeskAgent, roleDefinitionId: HELPDESK, directoryScopeId: '/' },
  ],
  sensitivityLabels: [
    { id: 'aa000000-0000-0000-0000-000000000001', name: 'Public', hasProtection: false, isActive: true },
    { id: 'aa000000-0000-0000-0000-000000000002', name: 'General', hasProtection: false, isActive: true },
    { id: 'aa000000-0000-0000-0000-000000000003', name: 'Confidential', hasProtection: false, isActive: true },
    { id: 'aa000000-0000-0000-0000-000000000004', name: 'Highly Confidential', hasProtection: true, isActive: true },
  ],
  applications: [
    { appId: IDS.batchApp, displayName: 'Nightly batch', signInAudience: 'AzureADMyOrg', passwordCredentials: [{ startDateTime: '2025-01-01T00:00:00Z', endDateTime: '2027-12-31T00:00:00Z' }], keyCredentials: [] },
    { appId: IDS.aiConnectorApp, displayName: 'OpenAI SharePoint Connector', signInAudience: 'AzureADMyOrg', passwordCredentials: [{ startDateTime: '2026-02-01T00:00:00Z', endDateTime: '2028-02-01T00:00:00Z' }], keyCredentials: [] },
    { appId: IDS.bpFoundryApp, displayName: 'Contoso Foundry agents', signInAudience: 'AzureADMyOrg', passwordCredentials: [], keyCredentials: [{ startDateTime: '2026-08-01T00:00:00Z', endDateTime: '2027-08-01T00:00:00Z' }] },
    { appId: IDS.oldApp, displayName: 'Old integration', signInAudience: 'AzureADMultipleOrgs', passwordCredentials: [{ startDateTime: '2026-01-01T00:00:00Z', endDateTime: '2026-11-01T00:00:00Z' }, { startDateTime: '2024-01-01T00:00:00Z', endDateTime: '2025-01-01T00:00:00Z' }], keyCredentials: [] },
  ],
  spSignIns: [
    { appId: IDS.batchApp, lastSignInActivity: { lastSignInDateTime: '2026-10-18T01:00:00Z' }, applicationAuthenticationClientSignInActivity: { lastSignInDateTime: '2026-10-18T01:00:00Z' } },
    { appId: IDS.sapApp, lastSignInActivity: { lastSignInDateTime: '2026-10-17T08:00:00Z' } },
    { appId: IDS.hrApp, lastSignInActivity: { lastSignInDateTime: '2026-10-16T08:00:00Z' } },
    { appId: IDS.salesforceApp, lastSignInActivity: { lastSignInDateTime: '2026-10-27T15:00:00Z' } },
    { appId: IDS.githubApp, lastSignInActivity: { lastSignInDateTime: '2026-10-27T16:30:00Z' } },
    { appId: IDS.aiConnectorApp, lastSignInActivity: { lastSignInDateTime: '2026-10-27T23:00:00Z' }, applicationAuthenticationClientSignInActivity: { lastSignInDateTime: '2026-10-27T23:00:00Z' } },
    { appId: IDS.bpFoundryApp, lastSignInActivity: { lastSignInDateTime: '2026-10-27T22:00:00Z' } },
  ],
  userCounts: { total: 1200, guests: 150 },
  directoryObjects: {
    [IDS.bg1]: { '@odata.type': '#microsoft.graph.user', id: IDS.bg1, displayName: 'Emergency Admin 1', userPrincipalName: 'bg1@contoso.com' },
    [IDS.bg2]: { '@odata.type': '#microsoft.graph.user', id: IDS.bg2, displayName: 'Emergency Admin 2', userPrincipalName: 'bg2@contoso.com' },
    [IDS.contractor]: { '@odata.type': '#microsoft.graph.user', id: IDS.contractor, displayName: 'Contractor Bob', userPrincipalName: 'bob@contoso.com' },
    [IDS.exceptionsGroup]: { '@odata.type': '#microsoft.graph.group', id: IDS.exceptionsGroup, displayName: 'CA - MFA exceptions' },
    [IDS.financeGroup]: { '@odata.type': '#microsoft.graph.group', id: IDS.financeGroup, displayName: 'Finance' },
  },
  groupSizes: { [IDS.exceptionsGroup]: 140, [IDS.financeGroup]: 35 },
  sources: {
    spSignIns: { ok: true }, directoryObjects: { ok: true }, agentIdentities: { ok: true }, agentBlueprints: { ok: true },
    agentUsers: { ok: true }, riskyAgents: { ok: true }, appRoleGrants: { ok: true }, sensitivityLabels: { ok: true },
  },
};
