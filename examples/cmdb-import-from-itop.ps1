# PowervRNI Examples
#
# Example: Import Applications from iTop
#
# START Description
# Retrieves applications from the CMDB iTop, and imports them into vRNI.
# END Description
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

$CONFIG_URL = "http://itop.lab/webservices/rest.php?version=1.3"
$CONFIG_USER = "api"
$CONFIG_PASS = "VMware1!"
$CONFIG_VRNI_HOST = "network-insight.platform.lab"
$CONFIG_VRNI_USER = "admin@local"
$CONFIG_VRNI_PASS = "VMware1!"


$vrni_connection = Connect-vRNIServer -Server $CONFIG_VRNI_HOST -User $CONFIG_VRNI_USER -Password $CONFIG_VRNI_PASS
Write-Host -ForegroundColor 'Green' "Connected to Network Insight with PowervRNI!"
Write-Host "Connecting to CMDB to get a list of applications..."

# Select all applications from the iTop API
$app_request_json = @{
  'operation'     = 'core/get' ;
  'class'         = 'ApplicationSolution' ;
  'key'           = "SELECT ApplicationSolution" ;
  'output_fields' = '*'
} | ConvertTo-Json

# Format the POST payload
$postParams = @{
  auth_user = $CONFIG_USER;
  auth_pwd  = $CONFIG_PASS;
  json_data = $app_request_json;
}

# Execute web request and translate the incoming result to a PowerShell object
$res = Invoke-WebRequest -Uri $CONFIG_URL -Method POST -Body $postParams -UseBasicParsing
# The actual content is hidden is key 'Content' (surprise!)
$json = ConvertFrom-Json $res.Content

# Go through all applications
foreach ($info in $json.objects.PSObject.Properties) {
  $appName = $info.Value.fields.name
  Write-Host -ForegroundColor 'Magenta' "Found Application: $($appName)"
  $fields = $info.Value

  # First, see if the application exists (otherwise create it)
  $application = Get-vRNIApplication -Name $appName -Connection $vrni_connection

  # Application doesn't exist in vRNI, create it
  if ($null -eq $application) {
    Write-Host "Application $($appName) not found in Network Insight, so creating it.." -ForegroundColor "Yellow"
    $application = New-vRNIApplication -Name $appName
    Write-Host "Application $($appName) created!" -ForegroundColor "Green"
  }

  # Array for holding the tier/VM combo
  $appTiers = @{}

  Write-Host "Looking for VMs attached to this application..."
  # This is only going to supply us with the VM name and ID
  foreach ($field in $info.Value.fields.functionalcis_list) {
    Write-Host -ForegroundColor 'Magenta' "Found a VM attached to $($appName): "
    #Write-Host "VM: $($field.functionalci_name)"

    # ..so we need to request more details around this VM.
    $vm_request_json = @{
      'operation'     = 'core/get' ;
      'class'         = 'VirtualMachine' ;
      'key'           = "SELECT VirtualMachine WHERE id = $($field.functionalci_id)" ;
      'output_fields' = '*'
    } | ConvertTo-Json

    $postParams = @{
      auth_user = $CONFIG_USER;
      auth_pwd  = $CONFIG_PASS;
      json_data = $vm_request_json
    }
    # Execute the VM info request and translate the output to
    $res = Invoke-WebRequest -Uri $CONFIG_URL -Method POST -Body $postParams -UseBasicParsing

    $json = ConvertFrom-Json $res.Content
    foreach ($info in $json.objects.PSObject.Properties) {
      $fields = $info.Value
      $tier = $($fields.fields.description)

      if ($null -eq $appTiers.$tier) {
        $appTiers.$tier = @()
      }
      $appTiers.$tier += $fields.fields.name
      Write-Host "VM: $($fields.fields.name) - Tier: $($tier)"
      #Write-Host "OS: $($fields.fields.osfamily_name) - $($fields.fields.osversion_name)"
      #Write-Host "IP Address: $($fields.fields.managementip)"
    }
  }

  Write-Host "Adding tiers and VMs to Network Insight.."

  foreach ($tier in $appTiers.Keys) {
    $filters = @()
    $filter_vm = ""
    foreach ($vm in $appTiers.$tier) {
      $filter_vm += "name = '$($vm)' or "
    }
    $filter_vm = $filter_vm.Substring(0, $filter_vm.Length - 4)
    $filters += $filter_vm

    $vrni_tier = New-vRNIApplicationTier -Application $application -Name $tier -Filters $filters
    Write-Host "Added Tier '$($tier)' to application '$($appname)' to Network Insight!" -ForegroundColor "green"

  }
}

Write-Host "All done."
