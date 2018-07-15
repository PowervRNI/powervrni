#
# This file is used by Publish.ps1 to generate the manifest and publish PowervRNI
# to the PowerShell Gallery.
#
# Add any new cmdlets in this file, otherwise they won't get published in the module
#

# This is the version of PowervRNI. The publish script will also append ".build number",
# put this in a "major.minor" format
$PowervRNI_Version = "1.1"

$FunctionsToExport = @(
    'Connect-vRNIServer',
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
    'Get-vRNIFirewallRule',
    'Get-vRNIFlow',
    'Get-vRNIHost',
    'Get-vRNIHostVMKNic',
    'Get-vRNIIPSet',
    'Get-vRNIL2Network',
    'Get-vRNINodes',
    'Get-vRNINSXManager',
    'Get-vRNIProblem',
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
    'New-vRNIApplication',
    'New-vRNIApplicationTier',
    'New-vRNIDataSource',
    'Remove-vRNIApplication',
    'Remove-vRNIApplicationTier',
    'Remove-vRNIDataSource'
)

# Manifest settings
$Manifest_Common = @{
    RootModule = 'PowervRNI.psm1'
    GUID = 'a34be6be-3dc1-457a-aea3-d4263481ed79'
    Author = 'Martijn Smit'
    CompanyName = 'VMware'
    Copyright = 'Copyright 2018 VMware. All rights reserved.'
    Description = 'A PowerShell module to talk to the vRealize Network Insight API'
    DotNetFrameworkVersion = '4.0'
    FunctionsToExport = $FunctionsToExport
    CmdletsToExport = '*'
    VariablesToExport = '*'
    AliasesToExport = '*'
    LicenseUri = 'https://github.com/PowervRNI/powervrni/blob/master/LICENSE.md'
    ProjectUri = 'https://github.com/PowervRNI/powervrni'

}