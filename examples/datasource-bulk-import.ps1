# PowervRNI Examples - Adding datasources in bulk
#
# This script uses an input CSV (example: datasource-bulk-import.csv) to add multiple vRealize Network Insight
# Data Sources. Modify datasource-bulk-import.csv to contain your own data sources (vCenters, NSX, switches, firewalls)
# and run this script with the param -DatasourcesCSV to your CSV.
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
  [parameter(Mandatory=$true, ValueFromPipeLine=$true, ValueFromPipeLineByPropertyName=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$DatasourcesCSV
)

# Test CSV existance
if (!(Test-Path $DatasourcesCSV)) {
  Write-Host "[$(Get-Date)] CSV with data sources not found! ($DatasourcesCSV)" -ForegroundColor "red"
  Exit
}

# Look up collector ID. This assumes you only have 1 collector in play
$collectorId = (Get-vRNINodes | Where {$_.node_type -eq "PROXY_VM" -And $_.ip_address -eq "10.8.20.22"} | Select -ExpandProperty id)

# Read the CSV into memory (using delimiter ';' so you can use Excel to modify it)
$csvList = Import-CSV $DatasourcesCSV -Delimiter ';'
$csvLineNo = 0
foreach($csvLine in $csvList)
{
  $csvLineNo += 1

  Write-Host "[$(Get-Date)] Adding a $($csvLine.DatasourceType) Data Source with IP $($csvLine.IP).." -ForegroundColor "green"

  # Build up the params we're going to give to New-vRNIDataSource 
  $cmdParams = @{
    "DataSourceType" = $csvLine.DatasourceType;
    "Username" = $csvLine.Username;
    "Password" = $csvLine.Password;
    "IP" = $csvLine.IP;
    "Nickname" = $csvLine.Nickname;
    "CollectorVMId" = $collectorId;
  }

  # sort out NSX-V specific parameters
  if($csvLine.DatasourceType -eq "nsxv") 
  {
    if($csvLine.NSX_ENABLE_CENTRAL_CLI -eq "TRUE") {
      $cmdParams.Add("NSXEnableCentralCLI", $True)
    }
    else {
      $cmdParams.Add("NSXEnableCentralCLI", $False)
    }
    if($csvLine.NSX_ENABLE_IPFIX -eq "TRUE") {
      $cmdParams.Add("NSXEnableIPFIX", $True)
    }
    else {
      $cmdParams.Add("NSXEnableIPFIX", $False)
    }

    # Retrieve the vCenter Entity ID by doing a lookup with it's nickname
    $vcId = (Get-vRNIDataSource | Where {$_.nickname -eq $csvLine.NSX_VCENTER_NICKNAME} | Select -ExpandProperty entity_id)
    $cmdParams.Add("NSXvCenterID", $vcId)
  }

  # add a -CiscoSwitchType param when the datasource type is a cisco switch
  if($csvLine.DatasourceType -eq "ciscoswitch") 
  {
    # Sanity check on the input
    if(($csvLine.CISCO_SWITCHTYPE -eq "CATALYST_3000") -Or 
       ($csvLine.CISCO_SWITCHTYPE -eq "CATALYST_4500") -Or 
       ($csvLine.CISCO_SWITCHTYPE -eq "CATALYST_6500") -Or 
       ($csvLine.CISCO_SWITCHTYPE -eq "NEXUS_5K") -Or 
       ($csvLine.CISCO_SWITCHTYPE -eq "NEXUS_7K") -Or 
       ($csvLine.CISCO_SWITCHTYPE -eq "NEXUS_9K")) 
    {
      $cmdParams.Add("CiscoSwitchType", $csvLine.CISCO_SWITCHTYPE)
    }
    else {
      Write-Host "[$(Get-Date)] Invalid CISCO_SWITCHTYPE ($($csvLine.CISCO_SWITCHTYPE)) given on line $($csvLineNo), skipping.." -ForegroundColor "yellow"
    }    
  }

  # add a -DellSwitchType param when the datasource type is a dell switch
  if($csvLine.DatasourceType -eq "dellswitch") 
  {
    # Sanity check on the input
    if(($csvLine.DELL_SWITCHTYPE -eq "FORCE_10_MXL_10") -Or 
       ($csvLine.DELL_SWITCHTYPE -eq "POWERCONNECT_8024") -Or 
       ($csvLine.DELL_SWITCHTYPE -eq "S4048") -Or 
       ($csvLine.DELL_SWITCHTYPE -eq "Z9100") -Or 
       ($csvLine.DELL_SWITCHTYPE -eq "S6000")) 
    {
      $cmdParams.Add("DellSwitchType", $csvLine.DELL_SWITCHTYPE)
    }
    else {
      Write-Host "[$(Get-Date)] Invalid DELL_SWITCHTYPE ($($csvLine.DELL_SWITCHTYPE)) given on line $($csvLineNo), skipping.." -ForegroundColor "yellow"
    }    
  }

  # Execute!
  New-vRNIDataSource @cmdParams
}
