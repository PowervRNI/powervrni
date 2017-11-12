# vRealize Network Insight PowerShell module
# Martijn Smit
# msmit@vmware.com
# Version 0.1

# Store the authentication token globally so we can re-use it
$Global:vRNIAuthToken = ""
$Global:vRNIAuthTokenExpires = 0;

function Invoke-NIRestMethod
{

  <#
  Invoke-NIRestMethod -Method get -Uri "/api/2.0/vdn/scopes"
  #>

  [CmdletBinding(DefaultParameterSetName="ConnectionObj")]

  param (
    [Parameter (Mandatory=$true,ParameterSetName="Parameter")]
      # vRNI Platform server
      [string]$Server,
    [Parameter (Mandatory=$true,ParameterSetName="Parameter")]
    [Parameter (ParameterSetName="ConnectionObj")]
      # REST Method (GET, POST, DELETE, UPDATE)
      [string]$Method,
    [Parameter (Mandatory=$true,ParameterSetName="Parameter")]
    [Parameter (ParameterSetName="ConnectionObj")]
      # URI of API endpoint (/api/ni/endpoint)
      [string]$URI,
    [Parameter (Mandatory=$false,ParameterSetName="Parameter")]
    [Parameter (ParameterSetName="ConnectionObj")]
      # Content to be sent to server when method is PUT/POST/PATCH
      [string]$Body = "",
    [Parameter (Mandatory=$false,ParameterSetName="ConnectionObj")]
      # Pre-populated connection object as returned by Connect-vRNIServer
      [psObject]$Connection
  )

  if ($pscmdlet.ParameterSetName -eq "ConnectionObj" )
  {
    # Ensure we were either called with a connection or there is a defaultConnection (user has called Connect-vRNIServer)
    if ($connection -eq $null)
    {
      # Now we need to assume that defaultvRNIConnection does not exist...
      if ( -not (test-path variable:global:defaultvRNIConnection) ) {
        throw "Not connected. Connect to vRNI with Connect-vRNIServer first."
      }
      else {
        Write-Host "$($MyInvocation.MyCommand.Name) : Using default connection"
        $connection = $defaultvRNIConnection
      }
    }

    $authtoken = $connection.AuthToken
    $authtoken_expiry = $connection.AuthTokenExpiry
    $server = $connection.Server

    # Check if the authentication token hasn't expired yet
    if([int][double]::Parse((Get-Date -UFormat %s)) -gt $authtoken_expiry) {
      throw "The vRNI Authentication token has expired. Please login again using Connect-vRNIServer."
    }
  }

  $headerDict = @{}
  if($authtoken -ne "") {
    $headerDict.add("Authorization", "NetworkInsight $authtoken")
  }

  $URL = "https://$($Server)$($URI)"

  Write-Debug "$(Get-Date -format s)  REST Call via invoke-webrequest: Method: $Method, URI: $URL, Body: $Body"

  try
  {
    if ($Body -ne "") {
      $response = Invoke-RestMethod -SkipCertificateCheck -Method $Method -Headers $headerDict -ContentType "application/json" -Uri $URL -Body $Body
    }
    else {
      $response = Invoke-RestMethod -SkipCertificateCheck -Method $Method -Headers $headerDict -ContentType "application/json" -Uri $URL
    }
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
      $ErrorString = "$($MyInvocation.MyCommand.Name) : The API response received indicates a failure. $($response.StatusCode.value__) : $($response.StatusDescription) : Response Body: $($responseBody)"

      # Log the error with response detail.
      throw $ErrorString
    }
    else
    {
      # No response, log and throw the underlying ex
      $ErrorString = "$($MyInvocation.MyCommand.Name) : Exception occured calling invoke-restmethod. $($_.exception.tostring())"
      throw $_.exception.tostring()
    }
  }
  catch {
    # Not a webexception (may be on PoSH core), log and throw the underlying ex string
    $ErrorString = "$($MyInvocation.MyCommand.Name) : Exception occured calling invoke-restmethod. $($_.exception.tostring())"
    throw $_.exception.tostring()
  }



  # Workaround for bug in invoke-restmethod where it doesnt complete the tcp session close to our server after certain calls.
  # We end up with connectionlimit number of tcp sessions in close_wait and future calls die with a timeout failure.
  # So, we are getting and killing active sessions after each call.  Not sure of performance impact as yet - to test
  # and probably rewrite over time to use invoke-webrequest for all calls... PiTA!!!! :|

  #$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($FullURI)
  #$ServicePoint.CloseConnectionGroup("") | out-null

  # Return result
  $response
}

function Connect-vRNIServer
{
  param (
    [Parameter (Mandatory=$true)]
      # vRNI Platform hostname or IP address
      [ValidateNotNullOrEmpty()]
      [string]$Server,
    [Parameter (Mandatory=$true)]
      # Username to use to login to vRNI
      [ValidateNotNullOrEmpty()]
      [string]$Username,
    [Parameter (Mandatory=$true)]
      # Password to use to login to vRNI
      [ValidateNotNullOrEmpty()]
      [string]$Password,
    [Parameter (Mandatory=$false)]
      # Domain to use to login to vRNI (if it's not given, use LOCAL)
      [ValidateNotNullOrEmpty()]
      [string]$Domain = "LOCAL"
  )

  $requestFormat = @{
    "username" = $Username
    "password" = $Password
  }

  if($Domain -eq "LOCAL") {
    $requestFormat.domain = @{
      "domain_type" = "LOCAL"
      "value" = "local"
    };
  }
  else {
    $requestFormat.domain = @{
      "domain_type" = "LDAP"
      "value" = $Domain
    };
  }

  $requestBody = ConvertTo-Json $requestFormat

  $response = Invoke-NIRestMethod -Server $Server -Method POST -URI "/api/ni/auth/token" -Body $requestBody

  if($response)
  {
    # Setup a custom object to contain the parameters of the connection
    $connection = [pscustomObject] @{
      "Server" = $Server
      "AuthToken" = $response.token
      "AuthTokenExpiry" = $response.expiry
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRNIConnection -value $connection -scope Global

    # Return the connection
    $connection
  }
}

function Disconnect-vRNIServer
{
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $result = Invoke-NIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/auth/token"
  $result
}

function Get-vRNIDataSource
{
  param (
    [Parameter (Mandatory=$false)]
      # Which datasource type to get
      [ValidateSet ("vcenter", "nsxv", "ciscoswitch", "aristaswitch", "dellswitch", "brocadeswitch", "juniperswitch", "ciscoucs", "hponeview", "hpvcmanager", "checkpointfirewall", "panfirewall", "all")]
      [string]$DatasourceType="all",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Resolve which datasource types to retrieve
  $datasource_urls = @{}
  $datasource_urls.Add("vcenter", @("/data-sources/vcenters"))
  $datasource_urls.Add("nsxv", @("/data-sources/nsxv-managers"))
  $datasource_urls.Add("ciscoswitch", @("/data-sources/cisco-switches"))
  $datasource_urls.Add("aristaswitch", @("/data-sources/arista-switches"))
  $datasource_urls.Add("dellswitch", @("/data-sources/dell-switches"))
  $datasource_urls.Add("brocadeswitch", @("/data-sources/brocade-switches"))
  $datasource_urls.Add("juniperswitch", @("/data-sources/juniper-switches"))
  $datasource_urls.Add("ciscoucs", @("/data-sources/ucs-managers"))
  $datasource_urls.Add("hponeview", @("/data-sources/hpov-managers"))
  $datasource_urls.Add("hpvcmanager", @("/data-sources/hpvc-managers"))
  $datasource_urls.Add("checkpointfirewall", @("/data-sources/checkpoint-firewalls"))
  $datasource_urls.Add("panfirewall", @("/data-sources/panorama-firewalls"))
  $datasource_urls.Add("all", @("/data-sources/vcenters", "/data-sources/nsxv-managers", "/data-sources/cisco-switches", "/data-sources/arista-switches", "/data-sources/dell-switches", "/data-sources/brocade-switches", "/data-sources/juniper-switches", "/data-sources/ucs-managers", "/data-sources/hpov-managers", "/data-sources/hpvc-managers", "/data-sources/checkpoint-firewalls", "/data-sources/panorama-firewalls"))

  $datasources = [System.Collections.ArrayList]@()

  $datasource_types_to_get = $datasource_urls.$DatasourceType

  foreach($datasource_uri in $datasource_types_to_get)
  {
    $response = Invoke-NIRestMethod -Connection $Connection -Method GET -URI "/api/ni$($datasource_uri)"

    if($response.results -ne "")
    {
      foreach ($datasource in $response.results)
      {
        $datasource_detail = Invoke-NIRestMethod -Connection $Connection -Method GET -URI "/api/ni$($datasource_uri)/$($datasource.entity_id)"
        $datasources.Add($datasource_detail) | Out-Null
      }
    }

  }

  $datasources
}

function Get-vRNIAPIVersion
{
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $version = Invoke-NIRestMethod -Connection $Connection -Method GET -URI "/api/ni/info/version"
  $version
}


function Get-vRNINodes
{
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $nodes = Invoke-NIRestMethod -Connection $Connection -Method GET -URI "/api/ni/infra/nodes"

  $nodes_details = [System.Collections.ArrayList]@()

  foreach($node_record in $nodes.results)
  {
    $node_info = Invoke-NIRestMethod -Connection $Connection -Method GET -URI "/api/ni/infra/nodes/$($node_record.id)"
    $nodes_details.Add($node_info) | Out-Null
  }

  $nodes_details
}


Connect-vRNIServer -Server 10.126.101.221 -Username admin@local -Password admin
