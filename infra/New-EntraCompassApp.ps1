<#
.SYNOPSIS
  Creates the EntraCompass app registration in your tenant (single-page app, PKCE, no secret).

.DESCRIPTION
  - Single-tenant app registration with a Single-page application (SPA) redirect URI.
  - Delegated, read-only Microsoft Graph permissions:
      User.Read, Policy.Read.All, Application.Read.All, Directory.Read.All, AuditLog.Read.All
  - Optionally grants tenant-wide admin consent for those permissions.
  No client secret or certificate is created.

.PARAMETER RedirectUri
  The URL where EntraCompass is hosted. Default: https://entracompass.aboutcloud.io

.PARAMETER GrantAdminConsent
  Grant admin consent for the delegated permissions (requires Global Administrator or
  Privileged Role Administrator).

.EXAMPLE
  ./New-EntraCompassApp.ps1 -GrantAdminConsent
#>
[CmdletBinding()]
param(
  [string]$RedirectUri = 'https://entracompass.aboutcloud.io',
  [string]$DisplayName = 'EntraCompass',
  [switch]$GrantAdminConsent
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
  Write-Host 'Installing the Microsoft.Graph PowerShell modules (current user)...'
  Install-Module Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
}

$scopes = @('Application.ReadWrite.All')
if ($GrantAdminConsent) { $scopes += 'DelegatedPermissionGrant.ReadWrite.All' }
Connect-MgGraph -Scopes $scopes -NoWelcome

$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$wanted = 'User.Read', 'Policy.Read.All', 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All'

# Resolve permission IDs from the tenant's own Graph service principal (no hardcoded GUIDs).
$access = foreach ($name in $wanted) {
  $scope = $graphSp.Oauth2PermissionScopes | Where-Object Value -eq $name
  if (-not $scope) { throw "Delegated permission $name not found on Microsoft Graph." }
  @{ Id = $scope.Id; Type = 'Scope' }
}

$app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
  -Spa @{ RedirectUris = @($RedirectUri) } `
  -RequiredResourceAccess @(@{ ResourceAppId = $graphAppId; ResourceAccess = $access }) `
  -Notes 'EntraCompass: read-only Conditional Access posture assessment (browser-only, PKCE).'

$sp = New-MgServicePrincipal -AppId $app.AppId

if ($GrantAdminConsent) {
  New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' -ResourceId $graphSp.Id `
    -Scope ($wanted -join ' ') | Out-Null
  Write-Host 'Admin consent granted.' -ForegroundColor Green
}

$tenantId = (Get-MgContext).TenantId
Write-Host ''
Write-Host 'EntraCompass app registration created.' -ForegroundColor Green
Write-Host "  Directory (tenant) ID   : $tenantId"
Write-Host "  Application (client) ID : $($app.AppId)"
Write-Host "  Redirect URI (SPA)      : $RedirectUri"
if (-not $GrantAdminConsent) {
  Write-Host ''
  Write-Host 'Next: grant admin consent in Entra admin center > App registrations > EntraCompass > API permissions.'
}
Write-Host 'When the assessment is done you can delete the app registration.'
