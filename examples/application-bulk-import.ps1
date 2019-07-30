# PowervRNI Examples - Adding applications in bulk
#
# This script uses an input CSV (example: application-bulk-import.csv) to add multiple vRealize Network Insight
# Applications. Modify application-bulk-import.csv to contain your applications and application tiers, along with
# either the NSX Security Group or the VM names. Then run this script with the param -ApplicationsCSV to your CSV.
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
  [parameter(Mandatory=$true, ValueFromPipeLine=$true, ValueFromPipeLineByPropertyName=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ApplicationsCSV
)

# Test CSV existance
if (!(Test-Path $ApplicationsCSV)) {
  Write-Host "[$(Get-Date)] CSV with applications not found! ($ApplicationsCSV)" -ForegroundColor "red"
  Exit
}

# Cache for new application entity ids
$new_apps = @{}

# Read the CSV into memory (using delimiter ';' so you can use Excel to modify it)
$csvList = Import-CSV $ApplicationsCSV -Delimiter ';'
$csvLineNo = 0
foreach($csvLine in $csvList)
{
  $csvLineNo += 1

  Write-Host "[$(Get-Date)] Processing application $($csvLine.Application).." -ForegroundColor "green"

  # First, see if the application exists (otherwise create it)
  if($new_apps.ContainsKey($csvLine.Application)) {
    $application = $new_apps[$csvLine.Application]
  }
  else {
    $application = Get-vRNIApplication $csvLine.Application
  }

  if($application -eq $null) {
    Write-Host "[$(Get-Date)] Application $($csvLine.Application) not found, so creating it.." -ForegroundColor "green"
    $application = New-vRNIApplication $csvLine.Application
    $new_apps.Add($csvLine.Application, $application)
  }

  # Format the filter
  $filters = @()

  # Is there a Security Group provided? If yes, get the entity id
  if($csvLine."Security Group" -ne "") {
    $security_group_id = (Get-vRNISecurityGroup $csvLine."Security Group").entity_id
    if($security_group_id -eq $null) {
      Write-Host "[$(Get-Date)] Wanted to use Security Group $($csvLine."Security Group"), but it doesn't exist - so skipping this rule!" -ForegroundColor "yellow"
    }
    else {
      $filters += "security_groups.entity_id = '$($security_group_id)'"
    }
  }

  # Are there VM Names provided? If yes, go through them and add them to the filter
  if($csvLine."VM Names" -ne "") {
    $filter_vm = ""
    # Split VMs by comma and go through the list to add them to the filter string
    $vms = $csvLine."VM Names".Split(",")
    foreach($vm in $vms) {
      $filter_vm += "name = '$($vm)' or "
    }
    # Remove last " or "
    $filter_vm = $filter_vm.Substring(0, $filter_vm.Length - 4)
    # Add it to the filter that will be passed to New-vRNIApplicationTier
    $filters += $filter_vm
  }

  # Make sure the filters aren't empty (non existing security group and no VM names provided), otherwise skip this tier
  if($filters.Length -eq 0) {
    Write-Host "[$(Get-Date)] Skipping Tier '$($csvLine.Tier)' in application '$($csvLine.Application)' because filters are empty!" -ForegroundColor "red"
    Continue
  }

  # Add the tier!
  $tier = New-vRNIApplicationTier -Application $application -Name $csvLine.Tier -Filters $filters
  Write-Host "[$(Get-Date)] Added Tier '$($csvLine.Tier)' to application '$($csvLine.Application)' with filters: $($filters)" -ForegroundColor "green"

  # Sleep for a second, so we don't hit the API rate limiter
  Start-Sleep 1
}
