#
# This file is used by Publish.ps1 to generate the manifest and publish PowervRNI
# to the PowerShell Gallery.
#
# Add any new cmdlets in this file, otherwise they won't get published in the module
#

# This is the version of PowervRNI. The publish script will also append ".build number",
# put this in a "major.minor" format
$PowervRNI_Version = "2.0"

$FunctionsToExport = @(
  'Connect-vRNIServer',
  'Connect-NIServer',
  'Disable-vRNIDataSource',
  'Disconnect-vRNIServer',
  'Enable-vRNIDataSource',
  'Get-vRNIAPIVersion',
  'Get-vRNIApplication',
  'Get-vRNIApplicationTier',
  'Get-vRNIDataSource',
  'Get-vRNIDatastore',
  'Get-vRNIDistributedSwitch',
  'Get-vRNIDistributedSwitchPortGroup',
  'Get-vRNIEntity',
  'Get-vRNIEntityName',
  'Get-vRNIFirewallRule',
  'Get-vRNIFlow',
  'Get-vRNIHost',
  'Get-vRNIHostVMKNic',
  'Get-vRNIIPSet',
  'Get-vRNIL2Network',
  'Get-vRNINodes',
  'Get-vRNINSXManager',
  'Get-vRNIProblem',
  'Get-vRNIRecommendedRules',
  'Get-vRNIRecommendedRulesNsxBundle',
  'Get-vRNISecurityGroup',
  'Get-vRNISecurityTag',
  'Get-vRNIService',
  'Get-vRNIServiceGroup',
  'Get-vRNIvCenter',
  'Get-vRNIvCenterCluster',
  'Get-vRNIvCenterDatacenter',
  'Get-vRNIvCenterFolder',
  'Get-vRNIVM',
  'Get-vRNIVMvNIC',
  'Get-vRNIDataSourceSNMPConfig',
  'Get-vRNISDDC',
  'Invoke-vRNIRestMethod',
  'New-vRNIApplication',
  'New-vRNIApplicationTier',
  'New-vRNIDataSource',
  'Remove-vRNIApplication',
  'Remove-vRNIApplicationTier',
  'Remove-vRNIDataSource',
  'Set-vRNIDataSourceSNMPConfig',
  'New-vRNISubnetMapping',
  'Get-vRNISubnetMapping',
  'Get-vRNIEastWestIP',
  'Add-vRNIEastWestIP',
  'Remove-vRNIEastWestIP',
  'Get-vRNINorthSouthIP',
  'Add-vRNINorthSouthIP',
  'Remove-vRNINorthSouthIP',
  'Get-vRNISettingsVIDM',
  'Set-vRNISettingsVIDM',
  'Get-vRNISettingsUserGroup',
  'Set-vRNISettingsUserGroup',
  'Remove-vRNISettingsUserGroup',
  'Get-vRNISettingsUser',
  'Set-vRNISettingsUser',
  'Remove-vRNISettingsUser',
  'Get-vRNIAuditLogs',
  'Get-vRNIApplicationMemberVM',
  'Set-vRNIUserPassword',
  'Get-vRNIKubernetesServices',
  'Update-vRNIDataSourceData',
  'Update-vRNINSXvControllerClusterPassword',
  'Get-vRNIEntityNames',
  'Invoke-vRNISearch',
  'Get-vRNILicensing',
  'Test-vRNILicensing',
  'Install-vRNILicensing',
  'Remove-vRNILicensing',
  'Get-vRNIBackup',
  'Get-vRNIBackupStatus',
  'Remove-vRNIBackup',
  'Enable-vRNIBackup',
  'Disable-vRNIBackup',
  'Set-vRNIBackup',
  'Get-vRNIDatabusSubscriber',
  'New-vRNIDatabusSubscriber',
  'Remove-vRNIDatabusSubscriber'
)

# Manifest settings
$Manifest_Common = @{
  RootModule             = 'PowervRNI.psm1'
  GUID                   = 'a34be6be-3dc1-457a-aea3-d4263481ed79'
  Author                 = 'Martijn Smit'
  CompanyName            = 'VMware'
  Copyright              = 'Copyright 2021 VMware. All rights reserved.'
  Description            = 'A PowerShell module to talk to the vRealize Network Insight API'
  DotNetFrameworkVersion = '4.0'
  FunctionsToExport      = $FunctionsToExport
  CmdletsToExport        = '*'
  VariablesToExport      = '*'
  AliasesToExport        = '*'
  LicenseUri             = 'https://github.com/PowervRNI/powervrni/blob/master/LICENSE.md'
  ProjectUri             = 'https://github.com/PowervRNI/powervrni'
  ReleaseNotes           = '### v2.0 - 2021-10-05
  - \[new] Connect-NIServer: Add support for vRNI Cloud locations by adding the -Location parameter
  - \[new] New-vRNIDataSource: Add support for Cisco ASR and ISR models (types: CISCOASRISR, CISCOASR1000, CISCOISR4000)
  - \[new] Get-vRNISDDC: New cmdlet to retrieve SDDC objects
  - \[new] Get-vRNIDatabusSubscriber: New cmdlet to retrieve all databus subscribers
  - \[new] New-vRNIDatabusSubscriber: New cmdlet to create a databus subscriber
  - \[new] Remove-vRNIDatabusSubscriber: New cmdlet to remove a databus subscriber'
}
