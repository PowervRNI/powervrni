# PowervRNI Examples
#
# Example: Archiving vRealize Network Insight flows to vRealize Log Insight
#
# START Description
# This script connects to vRNI, retrieves the flows within a time window (the last time this script was run and now),
# then checks whether the flow is located in the cache (more info in comments of cache code), and if not,
# gathers metadata (VM & L2 network name), and finally sends the flow to vRLI using Send-vRLIMessage from vrealize-log-insight.ps1
# END Description
#
# Start by filling out config.json with these values:
#
# "vrni_server": "your vRNI platform IP or hostname",
# "vrni_credentials_file": "credentials.xml", <-- See below
# "vrni_domain": "local", <-- Only change this if the vRNI user is using LDAP
# "vrli_server": "your vRLI IP or hostname",
# "cache_file": "flow-cache.json", <-- Leave this
# "last_flows_ts": 1579273407 <-- leave this
#
# # credentials.xml
# In order to login to vRNI, this script needs credentials. And let's not store these in plain text, so credentials.xml is a file with
# masked credentials. Here's how to generate it:
#
# Open a PowerShell window and do this:
#
# PS > $credential = Get-Credential -Title "vRealize Network Insight Login"
# PS > $credential | Export-CliXml -Path credentials.xml
#
# After generating the credentials.xml and configuring config.json, you can run this script by running:
#
# PS > ./vrni-archive-flows-to-vrli.ps1 -Config_JSON config.json
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
  [parameter(Mandatory = $true, ValueFromPipeLine = $true, ValueFromPipeLineByPropertyName = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$Config_JSON
)

# Test config existance
if (!(Test-Path $Config_JSON)) {
  Throw "[$(Get-Date)] Configuration file not found! ($Config_JSON)"
}

# Include for Send-vRLIMessage function
. "$PSScriptRoot\vrealize-log-insight.ps1"

# Retrieve config and convert to object
$Config = Get-Content -Path $Config_JSON | ConvertFrom-Json


# Test for required params
if (([bool]$Config.vrni_server -eq $False) -Or ([bool]$Config.vrni_credentials_file -eq $False) -Or ([bool]$Config.vrli_server -eq $False) -Or ([bool]$Config.cache_file -eq $False)) {
  Throw "[$(Get-Date)] Configuration file ($Config_JSON) needs to contain keys cache_file, vrli_server, vrni_server, and vrni_credentials_file!"
}

# Figure out the last_flow_ts variable; now-1hour when the ts is 0, use the timestamp otherwise
$last_flow_ts = ([DateTimeOffset]::Now.ToUnixTimeSeconds() - 3600)
if ($Config.last_flows_ts -ne 0) {
  $last_flow_ts = $Config.last_flows_ts
}
$new_flow_ts = ([DateTimeOffset]::Now.ToUnixTimeSeconds())

# Connect to vRNI using the credentials file
$creds = Import-CliXml -Path $Config.vrni_credentials_file
Connect-vRNIServer -Server $Config.vrni_server -Credential $creds -Domain $Config.vrni_domain

# Retrieve flows for the time window we need
$max_flow_count = 250000
Write-Host "[$(Get-Date)] Gettings flows from vRNI (this could take a while)"
$raw_flows = Get-vRNIFlow -StartTime $last_flow_ts -EndTime $new_flow_ts -Limit $max_flow_count
Write-Host "[$(Get-Date)] Found $($raw_flows.count) flows"

if ($max_flow_count -eq $raw_flows.count) {
  Write-Host -ForegroundColor "yellow" "[$(Get-Date)] Warning: the number of flows returned is equal to max_flow_count $($max_flow_count). Please up the limit."
}

# Flows can exist for a long time; as long as the connection isn't shut down, or re-used, the flow record inside vRNI will stick around.
# To prevent logging the same flow over and over again, we keep a local cache file and make sure to remove any flows here that are in that
# cache file.

# See if cache file exists, otherwise we'll start with an empty cache
$flow_cache = @{}
if (Test-Path $Config.cache_file) {
  $flow_cache = Get-Content -Path $Config.cache_file | ConvertFrom-Json -AsHashtable
}

# Home of the new cache
$new_flow_cache = @{}

# This will store the flows we'll submit to vRLI
$flows = @()

# Deduplicate flows with cache in mind
foreach ($flow in $raw_flows) {
  # unique key is: src ip - dst ip - port - protocol
  # value will be the timestamp it's last seen, to be able to compare the time
  $key_name = ("{0}-{1}-{2}-{3}" -f $flow.source_ip.ip_address, $flow.destination_ip.ip_address, $flow.port.display, $flow.protocol)

  # if the flow is in the cache, check if it's older than 1 week.
  if ($flow_cache.ContainsKey($key_name)) {
    Write-Debug "Found flow in cache: $($key_name)"
    # If it is older than 1 week; don't remove it and repeat it to vRLI (safeguard)
    if (($new_flow_ts - $flow_cache[$key_name]) -gt (60 * 60 * 24 * 7)) {
      $flows += $flow
      Write-Debug " - Adding flow to queue because it's older than 1 week: $($key_name)"
    }
  }
  else {
    Write-Debug "Flow not found in cache: $($key_name)"
    # if the flow is not in the cache, it's a new one; add it!
    $flows += $flow
  }

  # update new cache
  if ($new_flow_cache.ContainsKey($key_name)) {
    $flow_cache[$key_name] = $new_flow_ts
  }
  else {
    $new_flow_cache.Add($key_name, $new_flow_ts)
  }
}

# Write new cache file
Write-Debug "Saving new cache file"
($new_flow_cache | ConvertTo-Json | Out-File $Config.cache_file)

# Go through the entity IDs related to the flows and get names for them

# Start with VMs
Write-Debug "Looking up VMs names"
$vm_names = @{}
$tmp_entity_lookup = @{}
$tmp_entity_lookup.Add("entity_ids", @())
$tmp_entity_count = 0
foreach ($flow in $flows) {
  if ([bool]$flow.source_vm -ne $False) {
    # Only add it when the VM has not been discovered before
    if (!($vm_names.ContainsKey($flow.source_vm.entity_id))) {
      # Store entity id in tmp buffer, to be looked up at 100 entities, or in the last flow
      $tmp_entity_lookup.entity_ids += $flow.source_vm
      $tmp_entity_count++
    }
  }
  if ([bool]$flow.destination_vm -ne $False) {
    # Only add it when the VM has not been discovered before
    if (!($vm_names.ContainsKey($flow.destination_vm.entity_id))) {
      # Store entity id in tmp buffer, to be looked up at 100 entities, or in the last flow
      $tmp_entity_lookup.entity_ids += $flow.destination_vm
      $tmp_entity_count++
    }
  }

  # Do entity lookup with a 100 entities, or when it's the last flow
  if ($tmp_entity_count -eq 100 -Or $flow -eq $flows[-1]) {
    # Send a request to entities/fetch in order to bulk fetch the names of the VMs
    $requestBody = ConvertTo-Json $tmp_entity_lookup
    $entity_info = Invoke-vRNIRestMethod -Method POST -URI "/api/ni/entities/fetch" -Body $requestBody
    # Go through results and store the VM names
    foreach ($entity in $entity_info.results) {
      if (!($vm_names.ContainsKey($entity.entity_id))) {
        $vm_names.Add($entity.entity_id, @{name = $entity.entity.name; vc_id = $entity.entity.vendor_id; region = $entity.entity.region; type = $entity.entity_type })
      }
    }
    # Reset the tmp buffers
    $tmp_entity_lookup = @{}
    $tmp_entity_lookup.Add("entity_ids", @())
    $tmp_entity_count = 0
  }
}

# Also resolve L2 network names
Write-Debug "Looking up L2 network names"
$l2_names = @{}
$tmp_entity_lookup = @{}
$tmp_entity_lookup.Add("entity_ids", @())
$tmp_entity_count = 0
foreach ($flow in $flows) {

  if ([bool]$flow.source_l2_network -ne $False) {
    # Only add it when the L2 network has not been discovered before
    if (!($l2_names.ContainsKey($flow.source_l2_network.entity_id))) {
      # Store entity id in tmp buffer, to be looked up at 100 entities, or in the last flow
      # Work around a bug in the vRNI API - not all L2 network types has its entity_type set (like Azure VNets)
      if ([bool]$flow.source_l2_network.entity_type -eq $True) {
        $tmp_entity_lookup.entity_ids += $flow.source_l2_network
        $tmp_entity_count++
      }
    }
  }
  if ([bool]$flow.destination_l2_network -ne $False) {
    # Only add it when the L2 network has not been discovered before
    if (!($l2_names.ContainsKey($flow.destination_l2_network.entity_id))) {
      # Store entity id in tmp buffer, to be looked up at 100 entities, or in the last flow
      # Work around a bug in the vRNI API - not all L2 network types has its entity_type set (like Azure VNets)
      if ([bool]$flow.destination_l2_network.entity_type -eq $True) {
        $tmp_entity_lookup.entity_ids += $flow.destination_l2_network
        $tmp_entity_count++
      }
    }
  }

  # Do entity lookup with a 100 entities, or when it's the last flow
  if (($tmp_entity_count -eq 100 -Or $flow -eq $flows[-1]) -And $tmp_entity_count -gt 0) {
    # Send a request to entities/fetch in order to bulk fetch the names of the VMs
    $requestBody = ConvertTo-Json $tmp_entity_lookup
    $entity_info = Invoke-vRNIRestMethod -Method POST -URI "/api/ni/entities/fetch" -Body $requestBody
    # Go through results and store the VM names
    foreach ($entity in $entity_info.results) {
      if (!($l2_names.ContainsKey($entity.entity_id))) {
        $l2_names.Add($entity.entity_id, @{name = $entity.entity.name; vlan_id = $entity.entity.vlan_id; type = $entity.entity_type })
      }
    }
    # Reset the tmp buffers
    $tmp_entity_lookup = @{}
    $tmp_entity_lookup.Add("entity_ids", @())
    $tmp_entity_count = 0
  }
}

Write-Host "[$(Get-Date)] Looping through results and sending to vRLI"
$flows_sent = 0
foreach ($flow in $flows) {
  $flowDate = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($flow.time))

  $log_message = "vRNI-FLOW $($flowDate.ToString('r')) $(($flow.firewall_action).ToUpper()) $($flow.protocol) $($flow.name)"
  $log_fields = @{}

  $log_fields.Add("__vrni_flow_firewall_action", $flow.firewall_action)
  $log_fields.Add("__vrni_flow_traffic_type", $flow.traffic_type)
  $log_fields.Add("__vrni_flow_tag", $flow.flow_tag)
  $log_fields.Add("__vrni_flow_source_ip", $flow.source_ip.ip_address)
  $log_fields.Add("__vrni_flow_destination_ip", $flow.destination_ip.ip_address)
  $log_fields.Add("__vrni_flow_port", $flow.port.display)
  $log_fields.Add("__vrni_flow_port_name", $flow.port.iana_name)
  $log_fields.Add("__vrni_flow_protocol", $flow.protocol)
  $log_fields.Add("__vrni_flow_timestamp", $flowDate)

  Write-Debug "Flow.name: $($flow.name)"
  Write-Debug "Flow.date: $($flowDate)"
  Write-Debug "Flow.firewall_action: $($flow.firewall_action)"
  Write-Debug "Flow.traffic_type: $($flow.traffic_type)"
  Write-Debug "Flow.flow_tag: $($flow.flow_tag)"
  Write-Debug "Flow.source_ip: $($flow.source_ip.ip_address)"
  Write-Debug "Flow.destination_ip: $($flow.destination_ip.ip_address)"
  Write-Debug "Flow.port: $($flow.port.display)"
  Write-Debug "Flow.port.name: $($flow.port.iana_name)"
  Write-Debug "Flow.protocol: $($flow.protocol)"

  # There are conditional fields, like when the flow contains a source or destination VM, or L2 network.
  # Below is checks whether these fields are present and adds them to the vRLI payload, if so.
  if ([bool]$flow.source_vm -ne $False) {
    $entity_id = $flow.source_vm.entity_id
    if ([bool]$vm_names[$entity_id].name -ne $False) {
      Write-Debug "Flow.source_vm: $($vm_names[$entity_id].name)"
      $log_fields.Add("__vrni_flow_source_vm", $vm_names[$entity_id].name)
    }
    if ([bool]$vm_names[$entity_id].type -ne $False) {
      Write-Debug "Flow.source_vm.type: $($vm_names[$entity_id].type)"
      $log_fields.Add("__vrni_flow_source_vm_type", $vm_names[$entity_id].type)
    }
    if ([bool]$vm_names[$entity_id].vc_id -ne $False) {
      Write-Debug "Flow.source_vm.vc_id: $($vm_names[$entity_id].vc_id)"
      $log_fields.Add("__vrni_flow_source_vm_vc_id", $vm_names[$entity_id].vc_id)
    }
    if ([bool]$vm_names[$entity_id].region -ne $False) {
      Write-Debug "Flow.source_vm.region: $($vm_names[$entity_id].region)"
      $log_fields.Add("__vrni_flow_source_vm_region", $vm_names[$entity_id].region)
    }
  }
  if ([bool]$flow.destination_vm -ne $False) {
    $entity_id = $flow.destination_vm.entity_id
    if ([bool]$vm_names[$entity_id].name -ne $False) {
      Write-Debug "Flow.destination_vm: $($vm_names[$entity_id].name)"
      $log_fields.Add("__vrni_flow_destination_vm", $vm_names[$entity_id].name)
    }
    if ([bool]$vm_names[$entity_id].type -ne $False) {
      Write-Debug "Flow.destination_vm.type: $($vm_names[$entity_id].type)"
      $log_fields.Add("__vrni_flow_destination_vm_type", $vm_names[$entity_id].type)
    }
    if ([bool]$vm_names[$entity_id].vc_id -ne $False) {
      Write-Debug "Flow.destination_vm.vc_id: $($vm_names[$entity_id].vc_id)"
      $log_fields.Add("__vrni_flow_destination_vm_vc_id", $vm_names[$entity_id].vc_id)
    }
    if ([bool]$vm_names[$entity_id].region -ne $False) {
      Write-Debug "Flow.destination_vm.region: $($vm_names[$entity_id].region)"
      $log_fields.Add("__vrni_flow_destination_vm_region", $vm_names[$entity_id].region)
    }
  }

  if ([bool]$flow.source_l2_network -ne $False) {
    $entity_id = $flow.source_l2_network.entity_id
    if ($l2_names.ContainsKey($entity_id)) {
      if ([bool]$l2_names[$entity_id].name -ne $False) {
        Write-Debug "Flow.source_l2_network.name: $($l2_names[$entity_id].name)"
        $log_fields.Add("__vrni_flow_source_l2_network", $l2_names[$entity_id].name)
      }
      if ([bool]$l2_names[$entity_id].vlan_id -ne $False) {
        Write-Debug "Flow.source_l2_network.vlan_id: $($l2_names[$entity_id].vlan_id)"
        $log_fields.Add("__vrni_flow_source_l2_network_vlan_id", $l2_names[$entity_id].vlan_id)
      }
    }
  }
  if ([bool]$flow.destination_l2_network -ne $False) {
    $entity_id = $flow.destination_l2_network.entity_id
    if ($l2_names.ContainsKey($entity_id)) {
      if ([bool]$l2_names[$entity_id].name -ne $False) {
        Write-Debug "Flow.destination_l2_network.name: $($l2_names[$entity_id].name)"
        $log_fields.Add("__vrni_flow_destination_l2_network", $l2_names[$entity_id].name)
      }
      if ([bool]$l2_names[$entity_id].vlan_id -ne $False) {
        Write-Debug "Flow.destination_l2_network.vlan_id: $($l2_names[$entity_id].vlan_id)"
        $log_fields.Add("__vrni_flow_destination_l2_network_vlan_id", $l2_names[$entity_id].vlan_id)
      }
    }
  }

  Write-Debug "================="

  # Send log message to vRLI!
  $output = Send-vRLIMessage -Server $Config.vrli_server -Message $log_message -Fields $log_fields
  $output | Out-Null
  $flows_sent++
}

# Save new timestamp to the configuration file
($Config.PSObject.Properties.Remove('last_flows_ts') | Out-Null)
($Config | Add-Member 'last_flows_ts' $new_flow_ts | Out-Null)
($Config | ConvertTo-Json | Out-File $Config_JSON)

# Disconnect from vRNI to release the auth token
Disconnect-vRNIServer

Write-Host "[$(Get-Date)] Archived $($flows_sent) flows to vRealize Log Insight"