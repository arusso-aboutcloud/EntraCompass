// Sample tenant ("Contoso Ltd") used by the tests and by demo mode. Entirely fictional.
const TENANT = '11111111-1111-1111-1111-111111111111';
const MS = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';

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

export const fixture = {
  scannedAt: '2026-10-19T09:00:00Z',
  organization: { id: TENANT, displayName: 'Contoso Ltd' },
  policies: [allUsersMfa, blockLegacy, adminsMfa, blockCountries, compliantDevice, sessionMda, workload],
  namedLocations: [
    { '@odata.type': '#microsoft.graph.ipNamedLocation', id: IDS.officeLoc, displayName: 'Head office', isTrusted: true, ipRanges: [{ cidrAddress: '203.0.113.0/24' }, { cidrAddress: '10.0.0.0/8' }, { cidrAddress: '52.0.0.0/8' }] },
    { '@odata.type': '#microsoft.graph.countryNamedLocation', id: IDS.blockedCountries, displayName: 'Blocked countries', countriesAndRegions: ['KP', 'IR'], includeUnknownCountriesAndRegions: false },
    { '@odata.type': '#microsoft.graph.ipNamedLocation', id: 'cccccccc-0000-0000-0000-000000000003', displayName: 'Old datacenter', isTrusted: false, ipRanges: [{ cidrAddress: '198.51.100.0/24' }] },
  ],
  authContexts: [
    { id: 'c1', displayName: 'Highly confidential', isAvailable: true },
  ],
  authStrengths: [],
  roleTemplates: [],
  servicePrincipals: [
    { id: 'sp-sap', appId: IDS.sapApp, displayName: 'SAP ERP', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-intranet', appId: IDS.intranetApp, displayName: 'Intranet portal', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application', tags: ['WindowsAzureActiveDirectoryOnPremApp'] },
    { id: 'sp-hr', appId: IDS.hrApp, displayName: 'Workday', appOwnerOrganizationId: '99999999-0000-0000-0000-000000000000', servicePrincipalType: 'Application', preferredSingleSignOnMode: 'saml', tags: ['WindowsAzureActiveDirectoryIntegratedApp'] },
    { id: 'sp-spo', appId: '00000003-0000-0ff1-ce00-000000000000', displayName: 'Office 365 SharePoint Online', appOwnerOrganizationId: MS, servicePrincipalType: 'Application' },
    { id: 'sp-intune', appId: '0000000a-0000-0000-c000-000000000000', displayName: 'Microsoft Intune', appOwnerOrganizationId: MS, servicePrincipalType: 'Application' },
    { id: 'sp-batch', appId: IDS.batchApp, displayName: 'Nightly batch', appOwnerOrganizationId: TENANT, servicePrincipalType: 'Application' },
    { id: 'sp-mi', appId: 'ffffffff-0000-0000-0000-000000000001', displayName: 'func-prod', servicePrincipalType: 'ManagedIdentity' },
  ],
  applications: [
    { appId: IDS.batchApp, displayName: 'Nightly batch', signInAudience: 'AzureADMyOrg', passwordCredentials: [{ startDateTime: '2025-01-01T00:00:00Z', endDateTime: '2027-12-31T00:00:00Z' }], keyCredentials: [] },
    { appId: IDS.oldApp, displayName: 'Old integration', signInAudience: 'AzureADMultipleOrgs', passwordCredentials: [{ startDateTime: '2026-01-01T00:00:00Z', endDateTime: '2026-11-01T00:00:00Z' }, { startDateTime: '2024-01-01T00:00:00Z', endDateTime: '2025-01-01T00:00:00Z' }], keyCredentials: [] },
  ],
  spSignIns: [
    { appId: IDS.batchApp, lastSignInActivity: { lastSignInDateTime: '2026-10-18T01:00:00Z' }, applicationAuthenticationClientSignInActivity: { lastSignInDateTime: '2026-10-18T01:00:00Z' } },
    { appId: IDS.sapApp, lastSignInActivity: { lastSignInDateTime: '2026-10-17T08:00:00Z' } },
    { appId: IDS.hrApp, lastSignInActivity: { lastSignInDateTime: '2026-10-16T08:00:00Z' } },
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
  sources: { spSignIns: { ok: true }, directoryObjects: { ok: true } },
};
