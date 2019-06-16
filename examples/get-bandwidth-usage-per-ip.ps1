# PowervRNI Examples - Getting a list of IPs with their respective bandwidth usage
#
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.0

param (
    [Parameter (Mandatory=$false)]
        # The epoch timestamp of when to start looking up records
        [int]$StartTime = ([Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s")) - 86400), # default to a day window
    [Parameter (Mandatory=$false)]
        # The epoch timestamp of when to stop looking up records
        [int]$EndTime = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
)

# If we want to select flows in a time slot, make sure the end time is later then the start time
if($StartTime -gt $EndTime) {
    throw "Param StartTime cannot be greater than EndTime"
}

if(!$defaultvRNIConnection) {
    throw "Use Connect-vRNIServer or Connect-NIServer to connect to Network Insight first!"
}

# Loop through these IPs and get their download/upload bytes
$IPs_to_lookup = @("10.8.20.20", "10.8.20.66")
foreach ($ip_address in $IPs_to_lookup)
{
    # Get download bytes first
    $requestBody = @{
        entity_type = 'Flow'
        filter = "destination_ip.ip_address = '$ip_address'"
        aggregations = @( @{
            field = "flow.totalBytes.delta.summation.bytes"
            aggregation_type = "SUM"
        } )
        start_time = $StartTime
        end_time = $EndTime
    }

    $listParams = @{
        Connection = $defaultvRNIConnection
        Method = 'POST'
        Uri = "/api/ni/search/aggregation"
        Body = ($requestBody | ConvertTo-Json)
    }

    $result = Invoke-vRNIRestMethod @listParams
    $download_bytes = $result.aggregations.value

    # Now get upload bytes
    $requestBody = @{
        entity_type = 'Flow'
        filter = "source_ip.ip_address = '$ip_address'"
        aggregations = @( @{
            field = "flow.totalBytes.delta.summation.bytes"
            aggregation_type = "SUM"
        } )
        start_time = $StartTime
        end_time = $EndTime
    }

    $listParams = @{
        Connection = $defaultvRNIConnection
        Method = 'POST'
        Uri = "/api/ni/search/aggregation"
        Body = ($requestBody | ConvertTo-Json)
    }

    $result = Invoke-vRNIRestMethod @listParams
    $upload_bytes = $result.aggregations.value

    Write-Host "IP: $ip_address - Download bytes: $download_bytes - Upload bytes: $upload_bytes"
}
