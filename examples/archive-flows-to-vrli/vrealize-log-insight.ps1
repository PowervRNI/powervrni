

function Send-vRLIMessage
{
<#
  .SYNOPSIS
  Sends a message to vRealize Log Insight over the CFAPI. Allows usage of fields (tags).

  .EXAMPLE
  PS C:\> Send-vRLIMessage -Server vrli.lab.local -Message "testing powershell function!"

  Sends a plain message

  .EXAMPLE
  PS C:\> Send-vRLIMessage -Server vrli.lab.local -Message "testing powershell function!" -Fields @{ tag1 = "value1"; tag2 = "value2"; }

  Sends a message, including fields/tags and their values
#>

    param (
        # Destination vRLI server that message is to be sent to.
        [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Server,
        # Destination vRLI server port that message is to be sent to. Defaults to 9543
        [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [Int]
            $Port = 9543,
        # Log/event message
        [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Message,
        # Timestamp of the message. Defaults to current time.
        [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [Int]
            $Timestamp = [DateTimeOffset]::Now.ToUnixTimeSeconds(),
        # Log/event message
        [Parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [hashtable]
            $Fields = @{}
    )


    # Build the vRLI URL
    $URL = "https://$($Server):$($Port)/api/v1/events/ingest/0"

    # Build the event message that will be passed to vRLI
    $event = @{
        text = $Message
        timestamp = $Timestamp
    }

    # Iterate through the provides fields, if any are given
    if($Fields)
    {
        $event.fields = @()
        foreach($field_name in $Fields.keys)
        {
            # Build a temporary array that can be added to the fields value.
            $field_tmp = @{
                name = $field_name
                content = $Fields[$field_name]
            }
            $event.fields += $field_tmp
        }
    }

    # Build the request body. The API call supports multiple messages/events at the same time, that's why it's a list.
    $requestBody = @{
        events = @( $event )
    }
    $jsonBody = $requestBody | ConvertTo-Json -Depth 4

    Write-Debug "$(Get-Date -format s) Sent JSON: $($jsonBody)"

    # Energize!
    try
    {
        $response = Invoke-RestMethod $URL -Method POST -Body $jsonBody -ContentType 'application/json'
    }
    # If its a webexception, we may have got a response from the server with more information...
    # Even if this happens on PoSH Core though, the ex is not a webexception and we cant get this info :(
    catch [System.Net.WebException] {
        #Check if there is a response populated in the response prop as we can return better detail.
        $response = $_.exception.response
        if ( $response ) {
            $responseStream = $response.GetResponseStream()
            $reader = New-Object system.io.streamreader($responseStream)
            $responseBody = $reader.readtoend()
            ## include ErrorDetails content in case therein lies juicy info
            $ErrorString = "$($MyInvocation.MyCommand.Name) : The API response received indicates a failure. $($response.StatusCode.value__) : $($response.StatusDescription) : Response Body: $($responseBody)`nErrorDetails: '$($_.ErrorDetails)'"

            # Log the error with response detail.
            Write-Warning -Message $ErrorString
            ## throw the actual error, so that the consumer can debug via the actuall ErrorRecord
            Throw $_
        }
        else
        {
            # No response, log and throw the underlying ex
            $ErrorString = "$($MyInvocation.MyCommand.Name) : Exception occured calling invoke-restmethod. $($_.exception.tostring())"
            Write-Warning -Message $_.exception.tostring()
            ## throw the actual error, so that the consumer can debug via the actuall ErrorRecord
            Throw $_
        }
    }
    catch {
        # Not a webexception (may be on PoSH core), log and throw the underlying ex string
        $ErrorString = "$($MyInvocation.MyCommand.Name) : Exception occured calling invoke-restmethod. $($_.exception.tostring())"
        Write-Warning -Message $ErrorString
        ## throw the actual error, so that the consumer can debug via the actuall ErrorRecord
        Throw $_
    }

    Write-Debug "$(Get-Date -format s) Invoke-RestMethod Result: $response"

    # Return result
    if($response) { $response }
}
