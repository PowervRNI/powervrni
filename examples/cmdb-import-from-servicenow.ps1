# Import ServiceNow CMDB information to vRealize Network Insight
#
# More info: https://lostdomain.org/2018/11/19/integrating-servicenow-with-network-insight/
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0


## Start editing here ##

# ServiceNow configuration; login credentials & URL
$CONFIG_SNOW_USER = "admin"
$CONFIG_SNOW_PASS = "VMware!"
$CONFIG_SNOW_URL  = "https://myinstance.service-now.com" 

# vRealize Network Insight config; login credentials & URL
$CONFIG_vRNI_SERVER = "platform.networkinsight.lab.local"
$CONFIG_vRNI_USER   = "admin@local"
$CONFIG_vRNI_PASS   = "VMware1!"

# We're using a filter to find only applications in ServiceNow with this in its name
$APP_FILTER         = "VMworld"

## Stop editing here ##

# ServiceNow basic auth setup
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $CONFIG_SNOW_USER, $CONFIG_SNOW_PASS)))

# Check if PowervRNI is installed. If not, throw an error, if yes, load it.
if (!(Get-Module -ListAvailable -Name PowervRNI)) {
    throw "Please install PowervRNI (http://github.com/PowervRNI/powervrni) first by running: Install-Module PowervRNI"
}
Import-Module PowervRNI

# This function is used to discover dependancies of configuration items (CIs) and loop through them to find any virtual machines
# attached to the application. This function is called multiple times 
function get_children($outbound_relations, $depth)
{
    # Outbound relations is an array of CI IDs that SNOW returns that have a relation with the current CI. 
    foreach($relation in $outbound_relations)
    {
        # The values are the actual CI IDs that we should use to request more information on the CI (and see if it's a VM)
        foreach($val in $relation.target.value)
        {   
            # Request details of CI ID
            $url = "$($CONFIG_SNOW_URL)/api/now/cmdb/instance/cmdb_ci/$($val)"
            $info = Invoke-RestMethod -Uri $url -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -UseBasicParsing

            # Is it a VM? If yes, then save the details
            if($info.result.attributes.sys_class_name -eq "cmdb_ci_vmware_instance") 
            {
                # I'm using the first bit of the VM name as the tier name. For instance: App-VM01 will be translated to tier: App
                $vm_name = $info.result.attributes.name
                # Split the VM name on "-" and grab the second to last element (App-VM01 = App) for the tier name
                $vm_name_pieces = $vm_name.Split("-")
                $tier_name = $vm_name_pieces[-2]

                # Initialise the tier array to save the VM names to
                if($null -eq $Script:tier_list[$tier_name]) {
                    $Script:tier_list[$tier_name] = @()
                    $Script:number_of_tiers++
                }

                # If the tier does not already contain this VM (maybe from another CI relation), save it to memory
                if(!($Script:tier_list[$tier_name].Contains($vm_name))) 
                {
                    $Script:tier_list[$tier_name] += $vm_name
                    $Script:number_of_vms++

                    Write-Host -Foreground Yellow "VM '$($vm_name)' found for tier '$($tier_name)'"
                }
                
                # This is a special one; the correlation field on a CI is a text field that you can fill out in SNOW. 
                # I'm using that field to couple a load balancing IP address to the VM. That means the VM is behind a load
                # balancer with that specific IP address. Save that IP address to also put in the vRNI Application, so connections
                # to the load balancer are also put into the vRNI Application context.
                # Note: you can also put any load balancer VM (i.e. NSX Edge) into the SNOW CI as a regular VM and this script will
                #       also pick it up.
                if($info.result.attributes.correlation_id -ne "") 
                {
                    $tier_name = "LB-$($tier_name)"
                    if($null -eq $Script:tier_list[$tier_name]) {
                        $Script:tier_list[$tier_name] = @()
                        $Script:number_of_tiers++
                    }

                    $vm_name = $info.result.attributes.correlation_id
                    if(!($Script:tier_list[$tier_name].Contains($vm_name))) 
                    {
                        $Script:tier_list[$tier_name] += $vm_name
                        Write-Host -Foreground Yellow "IP Address '$($vm_name)' found for tier '$($tier_name)'"
                    }
                }
            }

            # See if the CI has outbound relations to other CIs and if so, have get_children dive into those relations.
            if($info.result.outbound_relations -ne "") {
                get_children($info.result.outbound_relations, ($depth+1))
            }
        }
    } 
}

# Connect PowervRNI 
Write-Host "Connecting PowervRNI to Network Insight.."
$conn = Connect-vRNIServer -Server $CONFIG_vRNI_SERVER -User $CONFIG_vRNI_USER -Password $CONFIG_vRNI_PASS
if(!$conn) {
    throw "Connection to Network Insight failed! Stopping."
}

# Execute a SNOW API call to get all defined application constructs
Write-Host "Connecting to ServiceNow to retrieve CMDB application list.."
$url = "$($CONFIG_SNOW_URL)/api/now/table/cmdb_ci_appl"
$result = Invoke-RestMethod -Uri $url -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -UseBasicParsing

# Go through all top-level applications that were returned
foreach($app in $result.result)
{
    # We're limiting our import by using a name filter. If you want to import everything, comment this if statement out.
    if($app.name.Contains($APP_FILTER)) 
    {
        # Initialise a couple of variables to save the application info too
        $Script:tier_list = @{}
        $Script:number_of_tiers = 0
        $Script:number_of_vms = 0

        Write-Host -ForegroundColor green "Found an application with $($APP_FILTER) in it: $($app.name)"

        # Dig into the found application by retrieving the app details and then having get_children dive into the outbound relations
        $url = "$($CONFIG_SNOW_URL)/api/now/cmdb/instance/cmdb_ci/$($app.sys_id)"
        $result = Invoke-RestMethod -Uri $url -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -UseBasicParsing
        Write-Host "Looking for CIs inside '$($app.name)'.."
        get_children($result.result.outbound_relations, 1);

        # Considering get_children loops itself until it has discovered all VMs linked to an app, by now we have fully filled variables with the tiers and VMs
        Write-Host -ForegroundColor green "Found $($Script:number_of_vms) VMs in $($Script:number_of_tiers) tiers. Adding them to Network Insight via PowervRNI.."

        # Create Application container in vRNI
        $vrniApp = New-vRNIApplication -Name $app.name
        Write-Host -ForegroundColor Magenta "New-vRNIApplication -Name '$($app.name)'"

        # Now go through the discovered tiers and VMs
        foreach($tier in $Script:tier_list.Keys)
        {
            # Get the list of VMs for this tier and go through them
            $vm_list = $($Script:tier_list.Item($tier))
            $vm_filter_list = ""
            $ip_filter_list = @()
            foreach($vm in $vm_list) 
            {
                # Test if the name is an IP address; if so, use an IP Filter instead of a VM Name filter
                if(($vm -As [IPAddress]) -As [Bool])
                {
                    $ip_filter_list += $vm
                }
                else 
                {
                    # This is a VM Name filter, add it to the VM Name filter string (and add an 'or' if this is not the first VM)
                    if($vm_filter_list -ne "") {
                        $vm_filter_list += " or "
                    }
                    $vm_filter_list += "name = '$($vm)'"
                }
            }

            # If this is a VM Name filter, add that to vRNI using PowervRNI
            if($vm_filter_list -ne "") {
                $new_tier = ($vrniApp | New-vRNIApplicationTier -Name $tier -VMFilters ("$($vm_filter_list)"))
                Write-Host -ForegroundColor Magenta "New-vRNIApplicationTier -Name $tier -VMFilters ("$($vm_filter_list)")"
            }
            else 
            {
                # This is an IP filter, add that to vRNI
                $new_tier = ($vrniApp | New-vRNIApplicationTier -Name $tier -IPFilters $ip_filter_list)
                Write-Host -ForegroundColor Magenta "New-vRNIApplicationTier -Name $($tier) -IPFilters $($ip_filter_list)"
            }
        }

        Write-Host -ForegroundColor green "Application '$($app.name)' added to Network Insight!"
        Write-Host "----------------------"
    }
}
