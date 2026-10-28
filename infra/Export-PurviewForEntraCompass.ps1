<#
.SYNOPSIS
  Exports Microsoft Purview DLP and sensitivity label configuration for EntraCompass.

.DESCRIPTION
  Read-only. Connects to Security & Compliance PowerShell and writes one JSON file with:
    - DLP policies: name, mode, locations (workloads), last change
    - DLP rules: name, parent policy, block / notify actions, sensitive information type names
    - Sensitivity labels: name, parent, scope, encryption on/off, authentication context
    - Label policies and auto-labeling policies: names and modes

  No content, no matched items, no incident data. Email addresses that appear in label
  encryption settings or locations are replaced with [redacted].

  Load the file in EntraCompass (Purview view). It is parsed in your browser and kept
  only in that browser tab (sessionStorage). It is never uploaded.

.PARAMETER OutFile
  Path of the JSON file to write. Default: .\purview-entracompass.json

.PARAMETER UserPrincipalName
  Optional UPN to sign in with.

.NOTES
  Needs the ExchangeOnlineManagement module and one of: Compliance Administrator,
  Compliance Data Administrator, Security Reader with DLP read, or Global Reader.

.EXAMPLE
  ./Export-PurviewForEntraCompass.ps1 -OutFile purview.json
#>
[CmdletBinding()]
param(
  [string]$OutFile = '.\purview-entracompass.json',
  [string]$UserPrincipalName
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
  Write-Host 'Installing the ExchangeOnlineManagement module (current user)...'
  Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement

$connect = @{ ShowBanner = $false }
if ($UserPrincipalName) { $connect.UserPrincipalName = $UserPrincipalName }
Connect-IPPSSession @connect

$emailPattern = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
function Redact([object]$value) {
  if ($null -eq $value) { return $null }
  return ([string]$value) -replace $emailPattern, '[redacted]'
}
function Names($list) {
  # Location bindings: keep the name only ("All", a site URL or a group name), emails redacted.
  @($list | Where-Object { $_ } | ForEach-Object {
    $n = if ($_.PSObject.Properties['Name']) { $_.Name } else { "$_" }
    Redact $n
  })
}
function TryRun([scriptblock]$block, [string]$what) {
  try { & $block } catch { Write-Warning "$what could not be read: $($_.Exception.Message)"; @() }
}

Write-Host 'Reading DLP policies...'
$policies = TryRun { Get-DlpCompliancePolicy } 'DLP policies' | ForEach-Object {
  [ordered]@{
    Name                         = $_.Name
    Mode                         = "$($_.Mode)"
    Enabled                      = $_.Enabled
    Workload                     = "$($_.Workload)"
    Priority                     = $_.Priority
    WhenChangedUTC               = if ($_.WhenChangedUTC) { $_.WhenChangedUTC.ToString('o') } else { $null }
    ExchangeLocation             = Names $_.ExchangeLocation
    SharePointLocation           = Names $_.SharePointLocation
    OneDriveLocation             = Names $_.OneDriveLocation
    TeamsLocation                = Names $_.TeamsLocation
    EndpointDlpLocation          = Names $_.EndpointDlpLocation
    OnPremisesScannerDlpLocation = Names $_.OnPremisesScannerDlpLocation
    ThirdPartyAppDlpLocation     = Names $_.ThirdPartyAppDlpLocation
    PowerBIDlpLocation           = Names $_.PowerBIDlpLocation
    # Newer locations (for example Microsoft 365 Copilot) are described here.
    Locations                    = Redact $_.Locations
    EnforcementPlanes            = "$($_.EnforcementPlanes)"
  }
}

Write-Host 'Reading DLP rules...'
$rules = TryRun { Get-DlpComplianceRule } 'DLP rules' | ForEach-Object {
  [ordered]@{
    Name                               = $_.Name
    ParentPolicyName                   = $_.ParentPolicyName
    Disabled                           = $_.Disabled
    Mode                               = "$($_.Mode)"
    BlockAccess                        = $_.BlockAccess
    BlockAccessScope                   = "$($_.BlockAccessScope)"
    NotifyUser                         = @($_.NotifyUser | ForEach-Object { Redact $_ })
    GenerateIncidentReport             = [bool]$_.GenerateIncidentReport
    ContentContainsSensitiveInformation = @($_.ContentContainsSensitiveInformation | ForEach-Object { @{ name = $_['name'] } })
    EndpointDlpRestrictions            = @($_.EndpointDlpRestrictions | ForEach-Object { @{ Setting = $_['Setting']; Value = $_['Value'] } })
    RestrictAccess                     = @($_.RestrictAccess | ForEach-Object { @{ Setting = $_['setting']; Value = $_['value'] } })
    AdvancedRule                       = Redact $_.AdvancedRule
  }
}

Write-Host 'Reading sensitivity labels...'
$labels = TryRun { Get-Label } 'Sensitivity labels' | ForEach-Object {
  [ordered]@{
    Guid              = "$($_.Guid)"
    Name              = $_.Name
    DisplayName       = $_.DisplayName
    ParentId          = "$($_.ParentId)"
    Priority          = $_.Priority
    ContentType       = "$($_.ContentType)"
    Disabled          = $_.Disabled
    EncryptionEnabled = $_.EncryptionEnabled
    LabelActions      = @($_.LabelActions | ForEach-Object { Redact $_ })
    Settings          = @($_.Settings | ForEach-Object { Redact $_ })
  }
}

Write-Host 'Reading label policies...'
$labelPolicies = TryRun { Get-LabelPolicy } 'Label policies' | ForEach-Object {
  [ordered]@{ Name = $_.Name; Labels = @($_.Labels); Mode = "$($_.Mode)" }
}
$autoLabel = TryRun { Get-AutoSensitivityLabelPolicy } 'Auto-labeling policies' | ForEach-Object {
  [ordered]@{ Name = $_.Name; Mode = "$($_.Mode)"; ApplySensitivityLabel = "$($_.ApplySensitivityLabel)" }
}

$export = [ordered]@{
  tool              = 'EntraCompass'
  kind              = 'purview-export'
  version           = 1
  exportedAt        = (Get-Date).ToUniversalTime().ToString('o')
  dlpPolicies       = @($policies)
  dlpRules          = @($rules)
  labels            = @($labels)
  labelPolicies     = @($labelPolicies)
  autoLabelPolicies = @($autoLabel)
}

$export | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutFile -Encoding utf8
Disconnect-ExchangeOnline -Confirm:$false | Out-Null

Write-Host ''
Write-Host "Written $OutFile" -ForegroundColor Green
Write-Host ("  {0} DLP policies, {1} rules, {2} labels" -f @($policies).Count, @($rules).Count, @($labels).Count)
Write-Host 'Load it in EntraCompass > Purview. Review the file first if you like: it is plain JSON.'
