# vRealize Network Insight PowerShell module
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 0.1
#
# Thanks to PowerNSX (http://github.com/vmware/powernsx) for providing the base
# functions & principles on which this module is built on.


# Keep a list handy of all data source types and the different URIs that is supposed to be called for that datasource
$Script:DatasourceURLs = @{}
$Script:DatasourceURLs.Add("vcenter", @("/data-sources/vcenters"))
$Script:DatasourceURLs.Add("nsxv", @("/data-sources/nsxv-managers"))
$Script:DatasourceURLs.Add("ciscoswitch", @("/data-sources/cisco-switches"))
$Script:DatasourceURLs.Add("aristaswitch", @("/data-sources/arista-switches"))
$Script:DatasourceURLs.Add("dellswitch", @("/data-sources/dell-switches"))
$Script:DatasourceURLs.Add("brocadeswitch", @("/data-sources/brocade-switches"))
$Script:DatasourceURLs.Add("juniperswitch", @("/data-sources/juniper-switches"))
$Script:DatasourceURLs.Add("ciscoucs", @("/data-sources/ucs-managers"))
$Script:DatasourceURLs.Add("hponeview", @("/data-sources/hpov-managers"))
$Script:DatasourceURLs.Add("hpvcmanager", @("/data-sources/hpvc-managers"))
$Script:DatasourceURLs.Add("checkpointfirewall", @("/data-sources/checkpoint-firewalls"))
$Script:DatasourceURLs.Add("panfirewall", @("/data-sources/panorama-firewalls"))
$Script:DatasourceURLs.Add("all", @("/data-sources/vcenters", "/data-sources/nsxv-managers", "/data-sources/cisco-switches", "/data-sources/arista-switches", "/data-sources/dell-switches", "/data-sources/brocade-switches", "/data-sources/juniper-switches", "/data-sources/ucs-managers", "/data-sources/hpov-managers", "/data-sources/hpvc-managers", "/data-sources/checkpoint-firewalls", "/data-sources/panorama-firewalls"))

# Keep another list handy which translates the internal vRNI Names for datasources to their relative URLs
$Script:DatasourceInternalURLs = @{}
$Script:DatasourceInternalURLs.Add("VCenterDataSource", "/data-sources/vcenters")
$Script:DatasourceInternalURLs.Add("NSXVManagerDataSource", "/data-sources/nsxv-managers")
$Script:DatasourceInternalURLs.Add("CiscoSwitchDataSource", "/data-sources/cisco-switches")
$Script:DatasourceInternalURLs.Add("AristaSwitchDataSource", "/data-sources/arista-switches")
$Script:DatasourceInternalURLs.Add("DellSwitchDataSource", "/data-sources/dell-switches")
$Script:DatasourceInternalURLs.Add("BrocadeSwitchDataSource", "/data-sources/brocade-switches")
$Script:DatasourceInternalURLs.Add("JuniperSwitchDataSource", "/data-sources/juniper-switches")
$Script:DatasourceInternalURLs.Add("UCSManagerDataSource", "/data-sources/ucs-managers")
$Script:DatasourceInternalURLs.Add("HPOneViewManagerDataSource", "/data-sources/hpov-managers")
$Script:DatasourceInternalURLs.Add("HPVCManagerDataSource", "/data-sources/hpvc-managers")
$Script:DatasourceInternalURLs.Add("CheckpointFirewallDataSource", "/data-sources/checkpoint-firewalls")
$Script:DatasourceInternalURLs.Add("PanFirewallDataSource", "/data-sources/panorama-firewalls")


function Invoke-vRNIRestMethod
{
  <#
  .SYNOPSIS
  Forms and executes a REST API call to a vRealize Network Insight Platform VM.

  .DESCRIPTION
  Invoke-vRNIRestMethod uses either a specified connection object as returned
  by Connect-vRNIServer, or the $defaultvRNIConnection global variable if
  defined to construct a REST api call to the vRNI API.

  Invoke-vRNIRestMethod constructs the appropriate request headers required by
  the vRNI API, including the authentication token (built from the connection
  object) and the content type, before making the rest call and returning the
  appropriate JSON object to the caller cmdlet.

  .EXAMPLE
  Invoke-vRNIRestMethod -Method GET -Uri "/api/ni/data-sources/vcenters"

  Performs a 'GET' against the URI /api/ni/data-sources/vcenters and returns
  the JSON object which contains the vRNI response. This call requires the
  $defaultvRNIConnection variable to exist and be populated with server and
  authentiation details as created by Connect-vRNIServer, or it fails with a
  message to first use Connect-vRNIServer

  .EXAMPLE
  $MyConnection = Connect-vRNIServer -Server vrni-platform.lab.local
  Invoke-vRNIRestMethod -Method GET -Uri "/api/ni/data-sources/vcenters" -Connection $MyConnection

  Connects to a vRNI Platform VM and stores the connection details in a
  variable, which in turn is used for the following cmdlet to retrieve
  all vCenter datasources. The JSON object containing the vRNI response
  is returned.
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

  if ($pscmdlet.ParameterSetName -eq "ConnectionObj")
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

  # Create a header option dictionary, to be used for authentication (if we have an existing session) and other RESTy stuff
  $headerDict = @{}
  $headerDict.add("Content-Type", "application/json")

  if($authtoken -ne "") {
    $headerDict.add("Authorization", "NetworkInsight $authtoken")
  }

  # Form the URL to call and write in our journal about this call
  $URL = "https://$($Server)$($URI)"
  Write-Debug "$(Get-Date -format s)  REST Call via Invoke-RestMethod: $Method $URL - with body: $Body"

  # Energize!
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
    throw $ErrorString
  }


  Write-Debug "$(Get-Date -format s) Invoke-RestMethod Result: $response"

  # Workaround for bug in invoke-restmethod where it doesnt complete the tcp session close to our server after certain calls.
  # We end up with connectionlimit number of tcp sessions in close_wait and future calls die with a timeout failure.
  # So, we are getting and killing active sessions after each call.  Not sure of performance impact as yet - to test
  # and probably rewrite over time to use invoke-webrequest for all calls... PiTA!!!! :|

  #$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($FullURI)
  #$ServicePoint.CloseConnectionGroup("") | out-null

  # Return result
  $response
}

#####################################################################################################################
#####################################################################################################################
########################################  Connection Management #####################################################
#####################################################################################################################
#####################################################################################################################

function Connect-vRNIServer
{
  <#
  .SYNOPSIS
  Connects to the specified vRealize Network Insight Platform VM and
  constructs a connection object.

  .DESCRIPTION
  The Connect-vRNIServer cmdlet returns a connection object that contains
  an authentication token which the rest of the cmdlets in this module
  use to perform authenticated REST API calls.

  The connection object contains the authentication token, the expiry
  timestamp that the token expires and the vRNI server IP.


  .EXAMPLE
  PS C:\> Connect-vRNIServer -Server vrni-platform.lab.local

  Connect to vRNI Platform VM with the hostname vrni-platform.lab.local,
  the cmdlet will prompt for credentials. Returns the connection object,
  if successful.

  .EXAMPLE
  PS C:\> Connect-vRNIServer -Server vrni-platform.lab.local -Username admin@local -Password secret

  Connect to vRNI Platform VM with the hostname vrni-platform.lab.local
  with the given local credentials. Returns the connection object, if successful.

  .EXAMPLE
  PS C:\> Connect-vRNIServer -Server vrni-platform.lab.local -Username martijn@ld.local -Password secret -Domain ld.local

  Connect to vRNI Platform VM with the hostname vrni-platform.lab.local
  with the given LDAP credentials. Returns the connection object, if successful.

  .EXAMPLE
  PS C:\> $MyConnection = Connect-vRNIServer -Server vrni-platform.lab.local -Username admin@local -Password secret
  PS C:\> Get-vRNIDataSource -Connection $MyConnection

  Connects to vRNI with the given credentials and then uses the returned
  connection object in the next cmdlet to retrieve all datasources from
  that specific vRNI instance.
  #>
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

  # Start building the hash table containing the login call we need to do
  $requestFormat = @{
    "username" = $Username
    "password" = $Password
  }

  # If no domain param is given, use the default LOCAL domain and populate the "domain" field
  if($Domain -eq "LOCAL") {
    $requestFormat.domain = @{
      "domain_type" = "LOCAL"
      "value" = "local"
    }
  }
  # Otherwise there a LDAP domain requested for credentials
  else {
    $requestFormat.domain = @{
      "domain_type" = "LDAP"
      "value" = $Domain
    }
  }

  # Convert the hash to JSON and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $response = Invoke-vRNIRestMethod -Server $Server -Method POST -URI "/api/ni/auth/token" -Body $requestBody

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
  <#
  .SYNOPSIS
  Destroys the Connection object if provided, otherwise this destroys the
  $defaultvRNIConnection global variable if it exists.

  .DESCRIPTION
  Although REST is not connection-orientated, vRNI does remember the authentication
  token which is used throughout the session. This cmdlet also invalidates the
  authentication token from vRNI, so it can no longer be used.

  .EXAMPLE
  PS C:\> Disconnect-vRNIServer

  Invalidates and removes the global default connection variable.

  .EXAMPLE
  PS C:\> Disconnect-vRNIServer -Connection $MyConnection

  Invalidates the authentication token of a specific connection object
  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Invalidate auth token from vRNI
  $result = Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/auth/token"

  # Remove the global default connection variable, if the -Connection parameter is the same as the default
  if ($Connection -eq $defaultvRNIConnection) {
    if (Get-Variable -Name defaultvRNIConnection -scope global) {
      Remove-Variable -name defaultvRNIConnection -scope global
    }
  }

  $result
}

#####################################################################################################################
#####################################################################################################################
#######################################  Infrastructure Management ##################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNINodes
{
  <#
  .SYNOPSIS
  Retrieve details of the vRealize Network Insight nodes.

  .DESCRIPTION
  Nodes within a vRealize Network Insight typically consist of two
  node types; collector VMs (or previously know as proxy VMs) and
  platform VMs. You can have multiple of each type to support your
  deployment and cluster them.

  .EXAMPLE

  PS C:\> Get-vRNINodes

  Retrieves information about all available nodes.

  .EXAMPLE

  PS C:\> Get-vRNINodes | Where {$_.node_type -eq "PROXY_VM"}

  Retrieves information about all available nodes, but filter on the collector VMs.
  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Get a list of available nodes first, this call returns a list of node IDs, which we can use
  # to retrieve more details on the specific node
  $nodes = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/infra/nodes"

  # Use this as a result container
  $nodes_details = [System.Collections.ArrayList]@()

  foreach($node_record in $nodes.results)
  {
    # Retrieve the node details and store those
    $node_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/infra/nodes/$($node_record.id)"
    $nodes_details.Add($node_info) | Out-Null
  }

  $nodes_details
}

function Get-vRNIAPIVersion
{
  <#
  .SYNOPSIS
  Retrieve the version number of the vRealize Network Insight API.

  .DESCRIPTION
  The API of vRealize Network Insight is versioned and this retrieves
  that version number.

  .EXAMPLE

  PS C:\> Get-vRNIAPIVersion

  Returns the version number of the vRNI API.
  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $version = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/info/version"
  $version
}

#####################################################################################################################
#####################################################################################################################
########################################  Datasource Management #####################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNIDataSource
{
  <#
  .SYNOPSIS
  Retrieve datasource information

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  .EXAMPLE

  PS C:\> Get-vRNIDataSource

  Retrieves the details of all datasource types.

  .EXAMPLE

  PS C:\> Get-vRNIDataSource -DataSourceType nsxv

  Retrieves the defaults of all NSX Managers added to vRNI as a datasource.
  #>
  param (
    [Parameter (Mandatory=$false)]
      # Which datasource type to get - TODO: make this a dynamic param to get the values from $Script:data
      [ValidateSet ("vcenter", "nsxv", "ciscoswitch", "aristaswitch", "dellswitch", "brocadeswitch", "juniperswitch", "ciscoucs", "hponeview", "hpvcmanager", "checkpointfirewall", "panfirewall", "all")]
      [string]$DataSourceType="all",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a return container
  $datasources = [System.Collections.ArrayList]@()

  # Because each datasource type has its unique URL (/api/ni/data-sources/vcenter, /data-sources/ucs-manager, etc),
  # and we want all the datasource information, loop through the URLs of the types we want to retrieve and
  $datasource_types_to_get = $Script:DatasourceURLs.$DataSourceType
  foreach($datasource_uri in $datasource_types_to_get)
  {
    # Energize!
    $response = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni$($datasource_uri)"

    # Process results, if there are datasources of this type. The results of the /api/ni/data-sources/$TYPE call is a
    # list of datasource IDs and not much more. We take that ID and do a call for details on that datasource
    if($response.results -ne "")
    {
      foreach ($datasource in $response.results)
      {
        # Retrieve datasource details and store it
        $datasource_detail = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni$($datasource_uri)/$($datasource.entity_id)"
        $datasources.Add($datasource_detail) | Out-Null
      }
    }
  }

  # Return all found data sources
  $datasources
}

function New-vRNIDataSource
{
  <#
  .SYNOPSIS
  Create new datasources within vRealize Network Insight to retrieve data from.

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  This cmdlet adds new datasources to vRNI, so it can retrieve data from it and
  correlate and display this data in the interfce.

  .EXAMPLE

  PS C:\> $collectorId = (Get-vRNINodes | Where {$_.node_type -eq "PROXY_VM"} | Select -ExpandProperty id)
  PS C:\> New-vRNIDataSource -DataSourceType vcenter -FDQN vc.nsx.local -Username administrator@vsphere.local -Password secret -CollectorVMId $collectorId -Nickname vc.nsx.local 

  First, get the node ID of the collector VM (assuming there's only one), then
  add a vCenter located at vc.nsx.local to vRNI. 

  .EXAMPLE

  PS C:\> $collectorId = (Get-vRNINodes | Where {$_.node_type -eq "PROXY_VM"} | Select -ExpandProperty id)
  PS C:\> $vcId = (Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Select -ExpandProperty entity_id)
  PS C:\> New-vRNIDataSource -DataSourceType nsxv -FDQN mgr.nsx.local -Username admin -Password secret -Nickname mgr.nsx.local -CollectorVMId $collectorId -Enabled $True -NSXEnableCentralCLI $True -NSXEnableIPFIX $True -NSXvCenterID $vcId

  Adds a new NSX Manager as a data source, auto select the collector ID (if
  you only have one), enable the NSX Central CLI for collecting data,
  also enable NSX IPFIX for network datastream insight from the point of view
  of NSX.
  #>

  [CmdletBinding(DefaultParameterSetName="__AllParameterSets")]

  param (
    [Parameter (Mandatory=$true)]
      # Which datasource type to create - TODO: make this a dynamic param to get the values from $Script:data
      [ValidateSet ("vcenter", "nsxv", "ciscoswitch", "aristaswitch", "dellswitch", "brocadeswitch", "juniperswitch", "ciscoucs", "hponeview", "hpvcmanager", "checkpointfirewall", "panfirewall")]
      [string]$DataSourceType,
    [Parameter (Mandatory=$true)]
      # Username to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Username,
    [Parameter (Mandatory=$true)]
      # Password to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Password,

    [Parameter (Mandatory=$false)]
      # The IP address of the datasource
      [ValidateNotNullOrEmpty()]
      [string]$IP,
    [Parameter (Mandatory=$false)]
      # The FDQN address of the datasource
      [ValidateNotNullOrEmpty()]
      [string]$FDQN,

    [Parameter (Mandatory=$true)]
      # Collector (Proxy) Node ID
      [ValidateNotNullOrEmpty()]
      [string]$CollectorVMId,

    [Parameter (Mandatory=$true)]
      # Nickname for the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Nickname="",

    [Parameter (Mandatory=$false)]
      # Whether we want to enable the datasource
      [ValidateNotNullOrEmpty()]
      [bool]$Enabled=$True,
    [Parameter (Mandatory=$false)]
      # Optional notes for the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Notes="",

    # These params are only required when adding a NSX Manager as datasource
    [Parameter (Mandatory=$true, ParameterSetName="NSXDS")]
      # Enable the central CLI collection
      [ValidateNotNullOrEmpty()]
      [bool]$NSXEnableCentralCLI,

    [Parameter (Mandatory=$true, ParameterSetName="NSXDS")]
      # Enable NSX IPFIX as a source
      [ValidateNotNullOrEmpty()]
      [bool]$NSXEnableIPFIX,

    [Parameter (Mandatory=$true, ParameterSetName="NSXDS")]
      # vCenter ID that this NSX Manager will be linked too
      [ValidateNotNullOrEmpty()]
      [string]$NSXvCenterID,

    # This params is only required when adding a cisco switch
    [Parameter (Mandatory=$true, ParameterSetName="CISCOSWITCH")]
      # Set the switch type
      [ValidateSet ("CATALYST_3000", "CATALYST_4500", "CATALYST_6500", "NEXUS_5K", "NEXUS_7K", "NEXUS_9K")]
      [string]$CiscoSwitchType,

    # This params is only required when adding a dell switch
    [Parameter (Mandatory=$true, ParameterSetName="DELLSWITCH")]
      # Set the switch type
      [ValidateSet ("FORCE_10_MXL_10", "POWERCONNECT_8024", "S4048", "Z9100", "S6000")]
      [string]$DellSwitchType,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  if($IP -ne "" -And $FDQN -ne "") {
    throw "Please only provide the FDQN or the IP address for the datasource, not both."
  }

  # Check if the NSXDS parameter set is used when adding a NSX Manager as datasource
  if($DataSourceType -eq "nsxv" -And $PSCmdlet.ParameterSetName -ne "NSXDS") {
    throw "Please provide the NSX parameters when adding a NSX Manager."
  }

  # Check if the switch type is provided, when adding a Cisco of Dell switch
  if($DataSourceType -eq "ciscoswitch" -And $PSCmdlet.ParameterSetName -ne "CISCOSWITCH") {
    throw "Please provide the -CiscoSwitchType parameter when adding a Cisco switch."
  }
  if($DataSourceType -eq "dellswitch" -And $PSCmdlet.ParameterSetName -ne "DELLSWITCH") {
    throw "Please provide the -DellSwitchType parameter when adding a Dell switch."
  }

  # Format request with all given data
  $requestFormat = @{
    "ip" = $IP
    "fqdn" = $FDQN
    "proxy_id" = $CollectorVMId
    "nickname" = $Nickname
    "notes" = $Notes
    "enabled" = $Enabled
    "credentials" = @{
      "username" = $Username
      "password" = $Password
    }
  }

  # If we're adding a NSX Manager, also add the NSX parameters to the body
  if($PSCmdlet.ParameterSetName -eq "NSXDS") {
    $requestFormat.vcenter_id = $NSXvCenterID
    $requestFormat.ipfix_enabled = $NSXEnableIPFIX
    $requestFormat.central_cli_enabled = $NSXEnableCentralCLI
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $URI = "/api/ni$($Script:DatasourceURLs.$DataSourceType[0])"

  $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI -Body $requestBody
  $response
}

function Remove-vRNIDataSource
{
  <#
  .SYNOPSIS
  Removes a datasource from vRealize Network Insight

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  This cmdlet removes a datasources from vRNI.

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Remove-vRNIDataSource

  Removes a vCenter datasource with the nickname "vc.nsx.local"

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "manager.nsx.local"} | Remove-vRNIDataSource

  Removes a NSX Manager datasource with the nickname "manager.nsx.local"

  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNIDataSource
      [ValidateNotNullOrEmpty()]
      [PSObject]$DataSource,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )


  # All we have to do is to send a DELETE request to URI /api/ni/$DataSourceType/$DatasourceId, so
  # form the URI and send the DELETE request to vRNI
  $URI = "/api/ni$($Script:DatasourceInternalURLs.$($DataSource.entity_type))/$($DataSource.entity_id)"

  $response = Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -Uri $URI
  $response
}

function Enable-vRNIDataSource
{
  <#
  .SYNOPSIS
  Enables an existing datasources within vRealize Network Insight

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  This cmdlet enables an existing datasources within vRNI.

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Enable-vRNIDataSource

  Enables a vCenter datasource with the nickname "vc.nsx.local"

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "manager.nsx.local"} | Enable-vRNIDataSource

  Enables a NSX Manager datasource with the nickname "manager.nsx.local"

  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNIDataSource
      [ValidateNotNullOrEmpty()]
      [PSObject]$DataSource,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )


  # All we have to do is to send a POST request to URI /api/ni/$DataSourceType/$DatasourceId/enable, so
  # form the URI and send the request to vRNI
  $URI = "/api/ni$($Script:DatasourceInternalURLs.$($DataSource.entity_type))/$($DataSource.entity_id)/enable"

  $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI
  $response
}

function Disable-vRNIDataSource
{
  <#
  .SYNOPSIS
  Disables an existing datasources within vRealize Network Insight

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  This cmdlet disables an existing datasources within vRNI.

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Disable-vRNIDataSource

  Disables a vCenter datasource with the nickname "vc.nsx.local"

  .EXAMPLE

  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "manager.nsx.local"} | Disable-vRNIDataSource

  Disables a NSX Manager datasource with the nickname "manager.nsx.local"

  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNIDataSource
      [ValidateNotNullOrEmpty()]
      [PSObject]$DataSource,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )


  # All we have to do is to send a POST request to URI /api/ni/$DataSourceType/$DatasourceId/disable, so
  # form the URI and send the request to vRNI
  $URI = "/api/ni$($Script:DatasourceInternalURLs.$($DataSource.entity_type))/$($DataSource.entity_id)/disable"

  $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI
  $response
}

#####################################################################################################################
#####################################################################################################################
#######################################  Application Management #####################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNIApplication
{
  <#
  .SYNOPSIS
  Get Application information from vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE

  PS C:\> Get-vRNIApplication

  Show all existing applications and their details.

  .EXAMPLE

  PS C:\> Get-vRNIApplication | Where {$_.name -eq "3 Tier App"}

  Get only the application details of the application named "3 Tier App"
  #>
  param (
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned to a specific name
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # First, get a list of all applications. This returns a list with application IDs which we can use
  # to retrieve the details of the applications
  $application_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications"

  # Use this as a results container
  $applications = [System.Collections.ArrayList]@()

  foreach($app in $application_list.results)
  {
    # Retrieve application details and store them
    $app_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($app.entity_id)"
    $applications.Add($app_info) | Out-Null

    # Don't go on if we've already found the one the user wants specifically
    if($Name -eq $app_info.name) {
      break
    }
  }

  # Filter out other applications if the user wants one specifically
  if ($Name) {
    $applications | Where-Object { $_.name -eq $Name }
  } 
  else {
    $applications
  }
}

function Get-vRNIApplicationTier
{
  <#
  .SYNOPSIS
  Get Application Tier information from vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE

  PS C:\> Get-vRNIApplication My3TierApp | Get-vRNIApplicationTier

  Show the tiers for the application container called "My3TierApp"
  #>
  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true)]
      # Application object, gotten from Get-vRNIApplication
      [ValidateNotNullOrEmpty()]
      [PSObject]$Application,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned to a specific name
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # First, get a list of all tier. This returns a list with application IDs which we can use
  # to retrieve the details of the applications
  $tier_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($Application.entity_id)/tiers"

  # Use this as a results container
  $tiers = [System.Collections.ArrayList]@()

  foreach($tier in $tier_list.results)
  {
    # Retrieve application details and store them
    $tier_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($Application.entity_id)/tiers/$($tier.entity_id)"
    $tiers.Add($tier_info) | Out-Null

    # Don't go on if we've already found the one the user wants specifically
    if($Name -eq $tier_info.name) {
      break
    }
  }

  # Filter out other application tiers if the user wants one specifically
  if ($Name) {
    $tiers | Where-Object { $_.name -eq $Name }
  } 
  else {
    $tiers
  }
}

function New-vRNIApplicationTier
{
  <#
  .SYNOPSIS
  Create a Tier in an Application container in vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.


  .EXAMPLE

  PS C:\> Get-vRNIApplication My3TierApp | New-vRNIApplicationTier -Name web-tier -Filters ("name = '3TA-Web01' or name = '3TA-Web02'")

  Create a new tier in the application 'My3TierApp' called 'web-tier' and assign the
  VMs named '3TA-Web01' and '3TA-Web02' to this tier.

  .EXAMPLE

  PS C:\> $security_group_id = (Get-vRNISecurityGroup SG-3Tier-App).entity_id
  PS C:\> Get-vRNIApplication My3TierApp | New-vRNIApplicationTier -Name app-tier -Filters ("name = '3TA-App01'", "security_groups.entity_id = '$security_group_id'")

  Create a new tier in the application 'My3TierApp' called 'web-tier' and assign the
  VMs named '3TA-Web01' and '3TA-Web02' to this tier.

  .PARAMETER Filters

  The filters within an application tier determine what VMs will be placed in that
  application. Currently, only these options are supported:

  Single VM:                   "name = '3TA-App01'"
  Multiple VMs:                "name = '3TA-App01' or name = '3TA-App02'"
  VMs with a NSX Security Tag: "security_groups.entity_id = '18230:82:604573173'"

  #>
  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true)]
      # Application object, gotten from Get-vRNIApplication
      [ValidateNotNullOrEmpty()]
      [PSObject]$Application,
    [Parameter (Mandatory=$true)]
      # The name of the new tier
      [string]$Name,
    [Parameter (Mandatory=$true)]
      # The VM filters in the new tier
      [string[]]$Filters,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = @{
    "name" = $Name
    "group_membership_criteria" = @()
  }

  # TODO: also allow custom searches based on entity_type VirtualMachine
  foreach($filter in $Filters)
  {
    $criteria_record = @{}
    $criteria_record.membership_type = "SearchMembershipCriteria"
    $criteria_record.search_membership_criteria = @{
      "entity_type" = "BaseVirtualMachine"
      "filter" = $filter
    }
    $requestFormat.group_membership_criteria += $criteria_record
  }

  Write-Debug $requestFormat

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat -Depth 5
  $result = Invoke-vRNIRestMethod -Connection $Connection -Method POST -URI "/api/ni/groups/applications/$($Application.entity_id)/tiers" -Body $requestBody

  $result

}


function Remove-vRNIApplicationTier
{
  <#
  .SYNOPSIS
  Remove a tier from an application container from vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE

  PS C:\> Get-vRNIApplication My3TierApp | Get-vRNIApplicationTier web-tier | Remove-vRNIApplicationTier

  Remove the tier 'web-tier' from the application container called "My3TierApp"
  #>
  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Application Tier object, gotten from Get-vRNIApplicationTier
      [ValidateNotNullOrEmpty()]
      [PSObject]$ApplicationTier,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Send the DELETE request and show the result
  $result = Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/groups/applications/$($ApplicationTier.application.entity_id)/tiers/$($ApplicationTier.entity_id)"

  $result
}

function New-vRNIApplication
{
  <#
  .SYNOPSIS
  Create a new Application container inside vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE

  PS C:\> New-vRNIApplication -Name My3TierApp

  Create a new application container with the name My3TierApp.

  #>
  param (
    [Parameter (Mandatory=$false, Position=1)]
      # Give the application a name
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = @{
    "name" = $Name
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/groups/applications" -Body $requestBody

  $response
}


function Remove-vRNIApplication
{
  <#
  .SYNOPSIS
  Remove an Application container from vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE

  PS C:\> Get-vRNIApplication My3TierApp | Remove-vRNIApplication

  Remove the application container called "My3TierApp"
  #>
  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Application object, gotten from Get-vRNIApplication
      [ValidateNotNullOrEmpty()]
      [PSObject]$Application,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Send the DELETE request and show the result
  $result = Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/groups/applications/$($Application.entity_id)"

  $result
}

#####################################################################################################################
#####################################################################################################################
#########################################  Entity Management ########################################################
#####################################################################################################################
#####################################################################################################################


function Get-vRNIProblem
{
  <#
  .SYNOPSIS
  Get open problems from vRealize Network Insight.

  .DESCRIPTION
  vRNI checks for problems in your environment and displays or alerts you
  about these problems. These problems can have multiple causes; for example
  latency issues with NSX Controllers, a configuration issue on the VDS, etc.
  In the end you're supposed to solve these problems and have no open ones.

  .EXAMPLE

  PS C:\> Get-vRNIProblem

  Get a list of all open problems

  .EXAMPLE

  PS C:\> Get-vRNIProblem | Where {$_.severity -eq "CRITICAL"}

  Get a list of all open problems which have the CRITICAL severity (and are
  probably important to solve quickly)

  .EXAMPLE

  PS C:\> Get-vRNIProblem -StartTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()-600) -EndTime ([DateTimeOffset]::Now.ToUnixTimeSeconds())

  Get all problems that have been open in the last 10 minutes. 

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to start looking up records
      [int]$StartTime = 0,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to stop looking up records
      [int]$EndTime = 0,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a results container
  $problems = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    $using_params = 0
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/problems"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
      $using_params++
    }

    # Check if we want to limit the results to a time window
    if($PSCmdlet.ParameterSetName -eq "TIMELIMIT") 
    {
      if($using_params -gt 0) {
        $URI += "&start_time=$($StartTime)&end_time=$($EndTime)"
        $using_params++
      }
      else {
        $URI += "?start_time=$($StartTime)&end_time=$($EndTime)"
        $using_params++
      }
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all problems
    $problem_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $problem_list.total_count
      $cursor      = $problem_list.cursor
    }
    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the problems individually and store them in the results array
    foreach($problem in $problem_list.results)
    {
      # Retrieve application details and store them
      $problem_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/problems/$($problem.entity_id)?time=$($problem.time)"
      $problems.Add($problem_info) | Out-Null
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++
      
      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }
    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
  }

  $problems
}


function Get-vRNIFlow
{
  <#
  .SYNOPSIS
  Get network flows from vRealize Network Insight.

  .DESCRIPTION
  vRNI can consume NetFlow and IPFIX data from the vSphere Distributed 
  Switch and physical switches which support NetFlow v5, v7, v9 or IPFIX.
  This cmdlet will let you export these flows 

  .EXAMPLE

  PS C:\> Get-vRNIFlow

  Get the last 100 flows (100 = default)

  .EXAMPLE

  PS C:\> Get-vRNIFlow -Limit 10

  Get the last 10 flows

  .EXAMPLE

  PS C:\> Get-vRNIFlow -StartTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()-600) -EndTime ([DateTimeOffset]::Now.ToUnixTimeSeconds())

  Get all flows that occurred in the last 10 minutes. 

  .EXAMPLE

  PS C:\> Get-vRNIFlow -StartTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()-600) -EndTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()) | Where {$_.protocol -eq "TCP"}

  Get all flows that occurred in the last 10 minutes and ignore all flows
  that are not TCP based.

  .EXAMPLE

  PS C:\> Get-vRNIFlow -StartTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()-600) -EndTime ([DateTimeOffset]::Now.ToUnixTimeSeconds()) | Where {$_.traffic_type -eq "INTERNET_TRAFFIC"}

  Get only internet-based (in or out) flows that occurred in the last 10 minutes.

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 100,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to start looking up records
      [int]$StartTime = 0,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to stop looking up records
      [int]$EndTime = 0,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # If we want to select flows in a time slot, make sure the end time is later then the start time
  if($PSCmdlet.ParameterSetName -eq "TIMELIMIT") {
    if($StartTime -gt $EndTime) {
      throw "Param StartTime cannot be greater than EndTime"
    }
  }

  # Use this as a results container
  $flows = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    $using_params = 0
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/flows"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
      $using_params++
    }

    # NOTE: The time window returns flows that have been active in that specific time window. It might be the case that
    # the flow itself was created earlier then given time window and keeps on being active by receiving new traffic. 
    # TLDR; results can contain flows with a date outside of the specified time window.
    #
    # Check if we want to limit the results to a time window
    if($PSCmdlet.ParameterSetName -eq "TIMELIMIT") {
      if($using_params -gt 0) {
        $URI += "&start_time=$($StartTime)&end_time=$($EndTime)"
        $using_params++
      }
      else {
        $URI += "?start_time=$($StartTime)&end_time=$($EndTime)"
        $using_params++
      }
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all problems
    $flow_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $flow_list.total_count
      $cursor      = $flow_list.cursor
    }

    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the problems individually and store them in the results array
    foreach($flow in $flow_list.results)
    {
      # Retrieve application details and store them
      $flow_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/flows/$($flow.entity_id)"
      #$flow_info.time = $flow.time
      $flow_info | Add-Member -Name "time" -value $flow.time -MemberType NoteProperty
      $flows.Add($flow_info) | Out-Null
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++

      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }

    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
  }

  $flows
}


function Get-vRNIVM
{
  <#
  .SYNOPSIS
  Get virtual machines from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all VMs in your environment
  and this cmdlet will help you discover these VMs.

  .EXAMPLE

  PS C:\> Get-vRNIVM

  List all VMs in your vRNI environment (note: this may take a while if you 
  have a lot of VMs)

  .EXAMPLE

  PS C:\> Get-vRNIVM -Name my-vm-name

  Retrieve only the VM object called "my-vm-name"

  .EXAMPLE

  PS C:\> $vcenter_entity_id = (Get-vRNIvCenter | Where {$_.name -eq "vcenter.lab"}).entity_id                                                                                   
  PS C:\> Get-vRNIVM | Where {$_.vcenter_manager.entity_id -eq $vcenter_entity_id}    

  Get all VMs that are attached to the vCenter named "vcenter.lab"

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a results container
  $vms = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/vms"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all problems
    $vm_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $vm_list.total_count
      $cursor      = $vm_list.cursor
    }
    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the problems individually and store them in the results array
    foreach($vm in $vm_list.results)
    {
      # Retrieve application details and store them
      $vm_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/vms/$($vm.entity_id)?time=$($vm.time)"
      $vms.Add($vm_info) | Out-Null

      if($Name -eq $vm_info.name) {
        $finished = true
        break
      }
      
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++
      
      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }
    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
    
  }

  if ($Name) {
    $vms | Where-Object { $_.name -eq $Name }
  } 
  else {
    $vms
  }
}

function Get-vRNIvCenter
{
  <#
  .SYNOPSIS
  Get configured vCenter instances from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all vCenters in your environment
  and this cmdlet will help you discover these vCenters.

  .EXAMPLE

  PS C:\> Get-vRNIvCenter

  Get all vCenters in the vRNI environment.

  .EXAMPLE

  PS C:\> Get-vRNIvCenter vcenter.lab

  Retrieve the vCenter object for the one called "vcenter.lab"

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a results container
  $vcenters = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/vcenter-managers"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all problems
    $vcenter_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $vcenter_list.total_count
      $cursor      = $vcenter_list.cursor
    }

    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the problems individually and store them in the results array
    foreach($vcenter in $vcenter_list.results)
    {
      # Retrieve application details and store them
      $vcenter_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/vcenter-managers/$($vcenter.entity_id)?time=$($vcenter.time)"
      $vcenters.Add($vcenter_info) | Out-Null

      if($Name -eq $vcenter_info.name) {
        $finished = true
        break
      }
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++
      
      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }
    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
    
  }

  if ($Name) {
    $vcenters | Where-Object { $_.name -eq $Name }
  } 
  else {
    $vcenters
  }
}

function Get-vRNIHost
{
  <#
  .SYNOPSIS
  Get available hypervisor hosts from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all hosts in your environment
  and this cmdlet will help you discover these hosts.

  .EXAMPLE

  PS C:\> Get-vRNIHost

  Get all hypervisor hosts in the vRNI environment.

  .EXAMPLE

  PS C:\> Get-vRNIHost esxi01.lab

  Retrieve the ESXi host object for the one called "esxi01.lab"

  .EXAMPLE

  PS C:\> Get-vRNIHost | Select name, service_tag

  Get a list of all hosts with their hardware service tag.

  .EXAMPLE

  PS C:\> Get-vRNIHost | Where {$_.nsx_manager -ne ""}  

  Get all hosts that are managed by a NSX Manager.

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a results container
  $hosts = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/hosts"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all problems
    $host_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $host_list.total_count
      $cursor      = $host_list.cursor
    }

    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the problems individually and store them in the results array
    foreach($host in $host_list.results)
    {
      # Retrieve host details and store them
      $host_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/hosts/$($host.entity_id)?time=$($host.time)"
      $hosts.Add($host_info) | Out-Null

      if($Name -eq $host_info.name) {
        $finished = true
        break
      }
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++
      
      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }
    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
    
  }

  if ($Name) {
    $hosts | Where-Object { $_.name -eq $Name }
  } 
  else {
    $hosts
  }
}



function Get-vRNISecurityGroup
{
  <#
  .SYNOPSIS
  Get available security groups (SG) from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all SGs in your environment
  and this cmdlet will help you discover these SGs.

  .EXAMPLE

  PS C:\> Get-vRNISecurityGroup

  Get all security groups in the vRNI environment.

  .EXAMPLE

  PS C:\> Get-vRNISecurityGroup 3TA-Management-Access

  Retrieve the security group object for the one called "3TA-Management-Access"

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned
      [string]$Name = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Use this as a results container
  $securitygroups = [System.Collections.ArrayList]@()

  # vRNI uses a paging system with (by default) 10 items per page. These vars are to keep track of the pages and retrieve what's left
  $size = 10
  $total_count = 0
  $current_count = 0
  $cursor = ""
  $finished = $false

  while(!$finished)
  {
    # This is the base URI for the problems 
    $URI = "/api/ni/entities/security-groups"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
    }

    Write-Debug "Using URI: $($URI)"

    # Get a list of all security groups
    $sg_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI $URI

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $sg_list.total_count
      $cursor      = $sg_list.cursor
    }

    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }
  
    # Go through the security groups individually and store them in the results array
    foreach($sg in $sg_list.results)
    {
      # Retrieve security group details and store them
      $sg_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/security-groups/$($sg.entity_id)?time=$($sg.time)"
      $securitygroups.Add($sg_info) | Out-Null

      if($Name -eq $sg_info.name) {
        $finished = true
        break
      }
      # Don't overload the API, pause a bit
      Start-Sleep -m 100

      $current_count++
      
      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    }
    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }
    
  }

  if ($Name) {
    $securitygroups | Where-Object { $_.name -eq $Name }
  } 
  else {
    $securitygroups
  }
}