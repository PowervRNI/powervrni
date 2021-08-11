# PowervRNI Examples
#
# Example: Exporting network flows
#
# START Description
# This script outputs flows in a certain time range.
# END Description
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
  [parameter(Mandatory = $false, ValueFromPipeLine = $true, ValueFromPipeLineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [int]$StartTime = ([Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s")) - 60), # default to an hour window
  [parameter(Mandatory = $false, ValueFromPipeLine = $true, ValueFromPipeLineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [int]$EndTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s")),
  [parameter(Mandatory = $false, ValueFromPipeLine = $true, ValueFromPipeLineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [int]$Limit = 9999
)

if ($null -eq $defaultvRNIConnection) {
  Write-Host "Please connect to a Network Insight instance, using Connect-vRNIServer or Connect-NIServer!"
  exit;
}

$flows = Get-vRNIFlow -StartTime $StartTime -EndTime $EndTime -Limit $Limit -Debug
$flows
$flows.Count

foreach ($flow in $flows) {
}

if ($Limit -lt $flows.Count) {
  Write-Host -ForegroundColor "red" "The current limit ($Limit) is lower than the amount of flows in the system. Consider raising the limit."
}