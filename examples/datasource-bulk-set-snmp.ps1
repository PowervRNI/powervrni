# PowervRNI Examples - Changing SNMP configs of multiple switch devices
#
# This script uses an input CSV (example: datasource-bulk-snmp.csv) to configure multiple vRealize Network Insight
# Data Sources SNMP Values. Modify datasource-bulk-snmp.csv to contain your own data sources and run this script
# with the param -DatasourcesCSV to your CSV.  Based off Martijn Smit bulk data source import script.
#
# Martijn Smit
# msmit@vmware.com
# Version 1.0

param (
  [parameter(Mandatory = $true, ValueFromPipeLine = $true, ValueFromPipeLineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$DatasourcesCSV
)

# Test CSV existance
if (!(Test-Path $DatasourcesCSV)) {
  throw "[$(Get-Date)] CSV with data sources not found! ($DatasourcesCSV)"
}

if (!$defaultvRNIConnection) {
  throw "[$(Get-Date)] Please connect to vRealize Network Insight [Cloud] first! (Connect-vRNIServer or Connect-NIServer)"
}

# Put all datasources into a hash array first
Write-Host "[$(Get-Date)] Getting a list of all data sources first.."
$datasources = @{}
$datasources_raw = Get-vRNIDataSource -DataSourceType ciscoswitch # If you want to speed this up, add i.e. -DatasourceType ciscoswitch for only Cisco switches.
Write-Host "[$(Get-Date)] Found $($datasources_raw.Count) data sources!" -ForegroundColor "green"

# Save the datasources in a hash, using the nickname as a key to identify it against the CSV
foreach ($ds in $datasources_raw) {
  $datasources.Add($ds.nickname, $ds)
}

$updates_failed = @{}
# Read the CSV into memory (using delimiter ';' so you can use Excel to modify it)
$csvList = Import-CSV $DatasourcesCSV -Delimiter ';'
$successfully_updated = 0
Write-Host "[$(Get-Date)] The CSV has $($csvList.Count) data sources, starting to update those.."
foreach ($csvLine in $csvList) {
  Write-Host "[$(Get-Date)] Setting SNMP for Data Source with Nickname of $($csvLine.Nickname).."

  if (!$datasources.ContainsKey($csvLine.Nickname)) {
    Write-Host "Datasource with nickname $($csvLine.Nickname) not found; skipping!" -ForegroundColor "red"
    continue
  }

  # TODO: SNMPv3 support
  # Run!
  try {
    $ds = $datasources.Item($csvLine.Nickname)
    $result = ($ds | Set-vRNIDataSourceSNMPConfig -Enabled $true -Community $csvLine.NewSnmpCommunity)
    $successfully_updated++
    Write-Host "Done updating $($csvLine.Nickname)!" -ForegroundColor "green"
  }
  catch {
    Write-Host "Error updating $($csvLine.Nickname): $($_)" -ForegroundColor "red"
    $updates_failed.Add($csvLine.Nickname, $_)
  }
}

Write-Host "Sucessfully updated $($successfully_updated) data sources!" -ForegroundColor "green"
if ($updates_failed.Count -gt 0) {
  Write-Host "Error updating these datasources:" -ForegroundColor "red"
  $updates_failed.Keys | % { Write-Host " - $($_) with error: $($updates_failed.Item($_))"  -ForegroundColor "red" }
}