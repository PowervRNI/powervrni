# VMware vRealize Network Insight PowerShell module
# Martijn Smit (@smitmartijn)
# msmit@vmware.com
# Version 1.6


# Keep a list handy of all data source types and the different URIs that is supposed to be called for that datasource
$Script:DatasourceURLs = @{}
$Script:DatasourceURLs.Add("vcenter", @("/data-sources/vcenters"))
$Script:DatasourceURLs.Add("nsxv", @("/data-sources/nsxv-managers"))
$Script:DatasourceURLs.Add("nsxt", @("/data-sources/nsxt-managers"))
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
$Script:DatasourceURLs.Add("infoblox", @("/data-sources/infoblox-managers"))
$Script:DatasourceURLs.Add("vmc-nsxmanager", @("/data-sources/vmc-nsxmanagers"))
$Script:DatasourceURLs.Add("f5-bigip", @("/data-sources/f5-bigip"))
$Script:DatasourceURLs.Add("huawei", @("/data-sources/huawei"))
$Script:DatasourceURLs.Add("ciscoaci", @("/data-sources/cisco-aci"))
$Script:DatasourceURLs.Add("pks", @("/data-sources/pks"))
$Script:DatasourceURLs.Add("kubernetes", @("/data-sources/kubernetes-clusters"))
$Script:DatasourceURLs.Add("openshift", @("/data-sources/openshift-clusters"))
$Script:DatasourceURLs.Add("servicenow", @("/data-sources/servicenow-instances"))
$Script:DatasourceURLs.Add("velocloud", @("/data-sources/velocloud"))
$Script:DatasourceURLs.Add("azure", @("/data-sources/azure-subscriptions"))
$Script:DatasourceURLs.Add("fortimanager", @("/data-sources/fortinet-firewalls"))

# Collect a list of all data source URLs to be used to retrieve "all" data sources
$allURLs = New-Object System.Collections.Generic.List[System.Object]
foreach ($h in $Script:DatasourceURLs.GetEnumerator()) {
  $allURLs += $h.Value
}
$Script:DatasourceURLs.Add("all", $allURLs)

# Keep another list handy which translates the internal vRNI Names for datasources to their relative URLs
$Script:DatasourceInternalURLs = @{}
$Script:DatasourceInternalURLs.Add("VCenterDataSource", "/data-sources/vcenters")
$Script:DatasourceInternalURLs.Add("NSXVManagerDataSource", "/data-sources/nsxv-managers")
$Script:DatasourceInternalURLs.Add("NSXTManagerDataSource", "/data-sources/nsxt-managers")
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
$Script:DatasourceInternalURLs.Add("InfobloxManagerDataSource", "/data-sources/infoblox-managers")
$Script:DatasourceInternalURLs.Add("PolicyManagerDataSource", "/data-sources/policy-managers")
$Script:DatasourceInternalURLs.Add("F5BIGIPDataSource", "/data-sources/f5-bigip")
$Script:DatasourceInternalURLs.Add("HuaweiSwitchDataSource", "/data-sources/huawei")
$Script:DatasourceInternalURLs.Add("CiscoACIDataSource", "/data-sources/cisco-aci")
$Script:DatasourceInternalURLs.Add("PKSDataSource", "/data-sources/pks")
$Script:DatasourceInternalURLs.Add("KubernetesDataSource", "/data-sources/kubernetes-clusters")
$Script:DatasourceInternalURLs.Add("ServiceNowDataSource", "/data-sources/servicenow-instances")
$Script:DatasourceInternalURLs.Add("VeloCloudDataSource", "/data-sources/velocloud")
$Script:DatasourceInternalURLs.Add("AzureDataSource", "/data-sources/azure-subscriptions")
$Script:DatasourceInternalURLs.Add("FortinetFirewallDataSource", "/data-sources/fortinet-firewalls")

# This list will be used in Get-vRNIEntity to map entity URLs to their IDs so we can use those IDs in /entities/fetch
$Script:EntityURLtoIdMapping = @{}
$Script:EntityURLtoIdMapping.Add("problems", "ProblemEvent")
$Script:EntityURLtoIdMapping.Add("vms", "VirtualMachine")
$Script:EntityURLtoIdMapping.Add("vnics", "Vnic")
$Script:EntityURLtoIdMapping.Add("hosts", "Host")
$Script:EntityURLtoIdMapping.Add("clusters", "Cluster")
$Script:EntityURLtoIdMapping.Add("vc-datacenters", "VCDatacenter")
$Script:EntityURLtoIdMapping.Add("datastores", "Datastore")
$Script:EntityURLtoIdMapping.Add("vmknics", "Vmknic")
$Script:EntityURLtoIdMapping.Add("layer2-networks", "VxlanLayer2Network")
$Script:EntityURLtoIdMapping.Add("ip-sets", "NSXIPSet")
$Script:EntityURLtoIdMapping.Add("flows", "Flow")
$Script:EntityURLtoIdMapping.Add("security-groups", "NSXSecurityGroup")
$Script:EntityURLtoIdMapping.Add("security-tags", "SecurityTag")
$Script:EntityURLtoIdMapping.Add("firewall-rules", "NSXFirewallRule")
$Script:EntityURLtoIdMapping.Add("firewalls", "NSXDistributedFirewall")
$Script:EntityURLtoIdMapping.Add("services", "NSXService")
$Script:EntityURLtoIdMapping.Add("service-groups", "NSXServiceGroup")
$Script:EntityURLtoIdMapping.Add("vcenter-managers", "VCenterManager")
$Script:EntityURLtoIdMapping.Add("nsx-managers", "NSXVManager")
$Script:EntityURLtoIdMapping.Add("distributed-virtual-switches", "DistributedVirtualSwitch")
$Script:EntityURLtoIdMapping.Add("distributed-virtual-portgroups", "DistributedVirtualPortgroup")
$Script:EntityURLtoIdMapping.Add("firewall-managers", "CheckpointManager")
$Script:EntityURLtoIdMapping.Add("kubernetes-services", "KubernetesService")

# Thanks to PowerNSX (http://github.com/vmware/powernsx) for providing some of the base functions &
# principles on which this module is built on.

# Run at module load time to determine a few things about the platform this module is running on.
function _PvRNI_init
{
  # $PSVersionTable.PSEdition property does not exist pre v5.  We need to do a few things in
  # exported functions to workaround some limitations of core edition, so we export
  # the global PNSXPSTarget var to reference if required.
  if(($PSVersionTable.PSVersion.Major -ge 6) -or (($PSVersionTable.PSVersion.Major -eq 5) -And ($PSVersionTable.PSVersion.Minor -ge 1))) {
    $script:PvRNI_PlatformType = $PSVersionTable.PSEdition
  }
  else {
    $script:PvRNI_PlatformType = "Desktop"
  }

  # Define class required for certificate validation override.  Version dependant.
  # For whatever reason, this does not work when contained within a function?
  $TrustAllCertsPolicy = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
      public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem)
      {
        return true;
      }
    }
"@

  if($script:PvRNI_PlatformType -eq "Desktop") {
    if (-not ("TrustAllCertsPolicy" -as [type])) {
      Add-Type $TrustAllCertsPolicy
    }
  }
}

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
  PS C:\> Invoke-vRNIRestMethod -Method GET -Uri "/api/ni/data-sources/vcenters"

  Performs a 'GET' against the URI /api/ni/data-sources/vcenters and returns
  the JSON object which contains the vRNI response. This call requires the
  $defaultvRNIConnection variable to exist and be populated with server and
  authentiation details as created by Connect-vRNIServer, or it fails with a
  message to first use Connect-vRNIServer

  .EXAMPLE
  PS C:\> $MyConnection = Connect-vRNIServer -Server vrni-platform.lab.local
  PS C:\> Invoke-vRNIRestMethod -Method GET -Uri "/api/ni/data-sources/vcenters" -Connection $MyConnection

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
    [Parameter (Mandatory=$false,ParameterSetName="Parameter")]
    [Parameter (ParameterSetName="ConnectionObj")]
      # Save content to file
      [string]$OutFile = "",
    [Parameter (Mandatory=$false,ParameterSetName="ConnectionObj")]
      # Pre-populated connection object as returned by Connect-vRNIServer
      [psObject]$Connection
  )

  if ($pscmdlet.ParameterSetName -eq "ConnectionObj")
  {
    # Ensure we were either called with a connection or there is a defaultConnection (user has called Connect-vRNIServer)
    if ($null -eq $connection)
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
    $server = $connection.Server

    # Check if the authentication token hasn't expired yet
    if((Get-Date) -gt $connection.AuthTokenExpiry) {
      throw "The vRNI Authentication token has expired (expired at '$($connection.AuthTokenExpiry.DateTime)'). Please login again using Connect-vRNIServer."
    }
  }

  # Sleep a tiny bit so we don't overload the vRNI API when using consecutive commands
  Start-Sleep -m 100

  # Create a header option dictionary, to be used for authentication (if we have an existing session) and other RESTy stuff
  $headerDict = @{}
  $headerDict.add("Content-Type", "application/json")

  # Add the auth token to the headers, if the CSPToken is not filled out
  if($authtoken -ne "") {
    $headerDict.add("Authorization", "NetworkInsight $authtoken")
  }
  # Add the Cloud Services Platform token if available (means we're using Network Insight as a Service)
  if($null -ne $connection)
  {
    if($null -ne $connection.CSPToken) {
      $headerDict.remove("Authorization")
      $headerDict.add("csp-auth-token", $connection.CSPToken)
    }
  }

  # Form the URL to call and write in our journal about this call
  $URL = "https://$($Server)$($URI)"
  Write-Debug "$(Get-Date -format s)  REST Call via Invoke-RestMethod: $Method $URL - with body: $Body"

  # Build up Invoke-RestMethod parameters, can differ per platform
  $invokeRestMethodParams = @{
    "Method" = $Method;
    "Headers" = $headerDict;
    "ContentType" = "application/json";
    "Uri" = $URL;
  }

  # If a body for a POST request has been specified, add it to the parameters for Invoke-RestMethod
  if($Body -ne "") {
    $invokeRestMethodParams.Add("Body", $body)
  }

  # If we want to save the output to a file (Get-vRNIRecommendedRulesNsxBundle uses this), specify -OutFile
  if($OutFile -ne "") {
    $invokeRestMethodParams.Add("OutFile", $OutFile)
  }

  # Add a trigger to ignore SSL certificate checks, if we're not using Network Insight as a Service (self-hosted usually have self-signed certificates)
  $SkipSSLCheck = $True
  if($null -ne $connection) {
    if($connection.CSPToken -eq "") {
      $SkipSSLCheck = $False
    }
  }

  if($SkipSSLCheck -eq $True)
  {
    if(($script:PvRNI_PlatformType -eq "Desktop"))
    {
      # Allow untrusted certificate presented by the remote system to be accepted
      if([System.Net.ServicePointManager]::CertificatePolicy.tostring() -ne 'TrustAllCertsPolicy') {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
      }
    }
    # Core (for now) uses a different mechanism to manipulating [System.Net.ServicePointManager]::CertificatePolicy
    if(($script:PvRNI_PlatformType -eq "Core")) {
      $invokeRestMethodParams.Add("SkipCertificateCheck", $true)
    }
  }

  # Only use TLS as SSL connection to vRNI
  [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

  # Energize!
  try
  {
    $response = Invoke-RestMethod @invokeRestMethodParams
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
  Write-Debug "$(Get-Date -format s) Invoke-RestMethod Results: $($response.results)"

  # Workaround for bug in invoke-restmethod where it doesnt complete the tcp session close to our server after certain calls.
  # We end up with connectionlimit number of tcp sessions in close_wait and future calls die with a timeout failure.
  # So, we are getting and killing active sessions after each call.  Not sure of performance impact as yet - to test
  # and probably rewrite over time to use invoke-webrequest for all calls... PiTA!!!! :|

  #$ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($FullURI)
  #$ServicePoint.CloseConnectionGroup("") | out-null

  # Return result
  if($response) { $response }
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
  datetime that the token expires and the vRNI server address.


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
    [Parameter (Mandatory=$false)]
      # Username to use to login to vRNI
      [ValidateNotNullOrEmpty()]
      [string]$Username,
    [Parameter (Mandatory=$false)]
      # Password to use to login to vRNI
      [ValidateNotNullOrEmpty()]
      [string]$Password,
    [Parameter (Mandatory=$false)]
      #PSCredential object containing NSX API authentication credentials
      [PSCredential]$Credential,
    [Parameter (Mandatory=$false)]
      # Domain to use to login to vRNI (if it's not given, use LOCAL)
      [ValidateNotNullOrEmpty()]
      [string]$Domain = "LOCAL"
  )

  # Make sure either -Credential is set, or both -Username and -Password
  if(($PsBoundParameters.ContainsKey("Credential")  -And $PsBoundParameters.ContainsKey("Username")) -Or
     ($PsBoundParameters.ContainsKey("Credential") -And $PsBoundParameters.ContainsKey("Password")))
  {
    throw "Specify either -Credential or -Username to authenticate (if using -Username and omitting -Password, a prompt will be given)"
  }

  # Build cred object for default auth if user specified username/pass
  $connection_credentials = ""
  if($PsBoundParameters.ContainsKey("Username"))
  {
    # Is the -Password omitted? Prompt securely
    if(!$PsBoundParameters.ContainsKey("Password")) {
      $connection_credentials = Get-Credential -UserName $Username -Message "vRealize Network Insight Platform Authentication"
    }
    # If the password has been given in cleartext,
    else {
      $connection_credentials = New-Object System.Management.Automation.PSCredential($Username, $(ConvertTo-SecureString $Password -AsPlainText -Force))
    }
  }
  # If a credential object was given as a parameter, use that
  elseif($PSBoundParameters.ContainsKey("Credential"))
  {
    $connection_credentials = $Credential
  }
  # If no -Username or -Credential was given, prompt for credentials
  elseif(!$PSBoundParameters.ContainsKey("Credential")) {
    $connection_credentials = Get-Credential -Message "vRealize Network Insight Platform Authentication"
  }

  # Start building the hash table containing the login call we need to do
  $requestFormat = @{
    "username" = $connection_credentials.Username
    "password" = $connection_credentials.GetNetworkCredential().Password
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

  # Only use TLS as SSL connection to vRNI
  [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

  # Convert the hash to JSON and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  Write-Debug "Request: $($requestBody)"
  $response = Invoke-vRNIRestMethod -Server $Server -Method POST -URI "/api/ni/auth/token" -Body $requestBody
  Write-Debug "Response: $($response)"

  if($response)
  {
    # Setup a custom object to contain the parameters of the connection
    $connection = [pscustomObject] @{
      "Server" = $Server
      "AuthToken" = $response.token
      ## the expiration of the token; currently (vRNI API v1.0), tokens are valid for five (5) hours
      "AuthTokenExpiry" = (Get-Date "01 Jan 1970").AddMilliseconds($response.expiry).ToLocalTime()
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRNIConnection -value $connection -scope Global

    # Retrieve the API version so we can use that in determining if we can use newer API endpoints
    $Script:vRNI_API_Version = [System.Version]((Get-vRNIAPIVersion).api_version)

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

function Connect-NIServer
{
  <#
  .SYNOPSIS
  Connects to the Network Insight Service on the VMware Cloud Services
  Platform and constructs a connection object.

  .DESCRIPTION
  The Connect-NIServer cmdlet returns a connection object that contains
  an authentication token which the rest of the cmdlets in this module
  use to perform authenticated REST API calls.

  The connection object contains the Cloud Services Platform token, the expiry
  datetime that the token expires and the NI server address.

  The RefreshToken can be found in your profile, here: https://console.cloud.vmware.com/csp/gateway/portal/#/user/tokens

  .EXAMPLE
  PS C:\> Connect-NIServer -RefreshToken xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Connect to the VMware Cloud Services Portal with your specified Refresh Token.
  The cmdlet will connect to the CSP, validate the token and will return an
  access token. Returns the connection object, if successful.
  #>
  param (
    [Parameter (Mandatory=$true)]
      # The Refresh Token from your VMware Cloud Services Portal
      [ValidateNotNullOrEmpty()]
      [string]$RefreshToken
  )

  # Only use TLS as SSL connection to vRNI
  [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

  $URL = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=$($RefreshToken)"
  $response = Invoke-WebRequest -URI $URL -ContentType "application/json" -Method POST -UseBasicParsing -Headers @{"csp-auth-token"="$($RefreshToken)"}
  Write-Debug "Response: $($response)"

  if($response)
  {
    $response = ($response | ConvertFrom-Json)

    # Setup a custom object to contain the parameters of the connection, including the URL to the CSP API & Access token
    $connection = [pscustomObject] @{
      "Server" = "api.mgmt.cloud.vmware.com/ni"
      "CSPToken" = $response.access_token
      ## the expiration of the token; currently (vRNI API v1.0), tokens are valid for five (5) hours
      "AuthTokenExpiry" = (Get-Date).AddSeconds($response.expires_in).ToLocalTime()
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRNIConnection -value $connection -scope Global

    # Retrieve the API version so we can use that in determining if we can use newer API endpoints
    $Script:vRNI_API_Version = [System.Version]((Get-vRNIAPIVersion).api_version)

    # Return the connection
    $connection
  }
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
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  DynamicParam
  {
    # Use a dynamic parameter to get a list of all data source names from $Script:DatasourceURLs
    $ParameterName = 'DataSourceType'

    # Form attribute parameters
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

    # Create and set the parameters' attributes
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $false
    $AttributeCollection.Add($ParameterAttribute)

    # Generate and set the ValidateSet
    # Collect a list of all data source names
    $allDS = New-Object System.Collections.Generic.List[System.Object]
    foreach ($h in $Script:DatasourceURLs.GetEnumerator()) {
      $allDS += $h.Name
    }

    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($allDS)

    # Add the ValidateSet to the attributes collection
    $AttributeCollection.Add($ValidateSetAttribute)

    # Create and return the dynamic parameter
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
    return $RuntimeParameterDictionary
  }
  Process
  {
    # Bind the parameter to a friendly variable
    if($null -ne $PSBoundParameters.Keys) {
      New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
    }

    if(!$DataSourceType) {
      $DataSourceType = "all"
    }

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

  First, get the node ID of the collector VM (assuming there's only one), then add a vCenter located at vc.nsx.local to vRNI.

  .EXAMPLE
  PS C:\> $collectorId = (Get-vRNINodes | Where {$_.node_type -eq "PROXY_VM"} | Select -ExpandProperty id)
  PS C:\> $vcId = (Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Select -ExpandProperty entity_id)
  PS C:\> New-vRNIDataSource -DataSourceType nsxv -FDQN mgr.nsx.local -Username admin -Password secret -Nickname mgr.nsx.local -CollectorVMId $collectorId -Enabled $True -NSXEnableCentralCLI $True -NSXEnableIPFIX $True -NSXvCenterID $vcId

  Adds a new NSX Manager as a data source, auto select the collector ID (if you only have one), enable the NSX Central CLI for collecting data, also enable NSX IPFIX for network datastream insight from the point of view of NSX.

  .EXAMPLE
  PS C:\> $collectorId = (Get-vRNINodes | Where {$_.ip_address -eq "10.0.0.11"} | Select -ExpandProperty id)
  PS C:\> New-vRNIDataSource -DataSourceType azure -CollectorVMId $collectorId -Nickname Azure-1 -TenantID xxx-xxx-xxx-xxx-xxx -ApplicationID xxx-xxx-xxx-xxx-xxx -SecretKey secret -SubscriptionID xxx-xxx-xxx-xxx-xxx

  Adds a new Azure subscription; first gets a specific collector appliance based on IP, and continues to add the Azure subscription based on the application registration information.
  More info on requirements can be found here: https://docs.vmware.com/en/VMware-vRealize-Network-Insight/5.0/com.vmware.vrni.using.doc/GUID-12272E1A-055F-47E9-9EA6-8693FE86AA02.html

  .EXAMPLE
  PS C:\> $nsxtId      = (Get-vRNIDataSource -DatasourceType nsxt | Where {$_.nickname -eq "my-nsxt-manager"} | Select -ExpandProperty id)
  PS C:\> $collectorId = (Get-vRNINodes | Where {$_.ip_address -eq "10.0.0.11"} | Select -ExpandProperty id)
  PS C:\> $kubeconfig  = (Get-Content ~/.kube/config | Out-String)
  PS C:\> New-vRNIDataSource -DataSourceType kubernetes -Nickname k8s-cluster-1 -CollectorVMId $collectorId -NSXTManagerID $nsxtId -KubeConfig $kubeconfig

  Add a Kubernetes cluster as a data source. First gets the entity ID of the NSX-T Manager supporting the container network, then vRNI Collector ID, then puts the kubeconfig file into a string, and finally adds the Kubernetes cluster to vRNI.
  #>

  [CmdletBinding(DefaultParameterSetName="__AllParameterSets")]

  param (
    [Parameter (Mandatory=$false)]
      # Username to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Username = "",
    [Parameter (Mandatory=$false)]
      # Password to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Password = "",

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
    [Parameter (Mandatory=$False, ParameterSetName="NSXDS")]
      # Enable the central CLI collection
      [ValidateNotNullOrEmpty()]
      [bool]$NSXEnableCentralCLI = $True,

    [Parameter (Mandatory=$False, ParameterSetName="NSXDS")]
      # Enable NSX IPFIX as a source
      [ValidateNotNullOrEmpty()]
      [bool]$NSXEnableIPFIX = $True,

    [Parameter (Mandatory=$false, ParameterSetName="NSXDS")]
      # Enable Virtual Latency (VTEP, VNIC, & PNIC) streaming from NSX to vRNI
      [ValidateNotNullOrEmpty()]
      [bool]$NSXEnableLatency = $False,

    [Parameter (Mandatory=$False, ParameterSetName="NSXDS")]
      # vCenter ID that this NSX Manager will be linked too
      [ValidateNotNullOrEmpty()]
      [string]$NSXvCenterID = "",

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

    # These params are only required when adding an Azure subscription as datasource
    [Parameter (Mandatory=$true, ParameterSetName="AZURE")]
      # Azure Tenant ID
      [ValidateNotNullOrEmpty()]
      [string]$TenantID,
    [Parameter (Mandatory=$true, ParameterSetName="AZURE")]
      # Azure Application ID
      [ValidateNotNullOrEmpty()]
      [string]$ApplicationID,
    [Parameter (Mandatory=$true, ParameterSetName="AZURE")]
      # Azure Secret Key
      [ValidateNotNullOrEmpty()]
      [string]$SecretKey,
    [Parameter (Mandatory=$true, ParameterSetName="AZURE")]
      # Azure Subscription ID
      [ValidateNotNullOrEmpty()]
      [string]$SubscriptionID,
    [Parameter (Mandatory=$false, ParameterSetName="AZURE")]
      # Retrieve Flows?
      [ValidateNotNullOrEmpty()]
      [bool]$FlowsEnabled = $True,

    [Parameter (Mandatory=$False, ParameterSetName="KUBERNETES")]
      # KubeConfig as a string
      [ValidateNotNullOrEmpty()]
      [string]$KubeConfig,
    [Parameter (Mandatory=$True, ParameterSetName="KUBERNETES")]
      # NSX-T Manager entity ID
      [ValidateNotNullOrEmpty()]
      [string]$NSXTManagerID,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )
  DynamicParam
  {
    # Use a dynamic parameter to get a list of all data source names from $Script:DatasourceURLs
    $ParameterName = 'DataSourceType'

    # Form attribute parameters
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

    # Create and set the parameters' attributes
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $ParameterAttribute.Mandatory = $true
    $AttributeCollection.Add($ParameterAttribute)

    # Generate and set the ValidateSet
    # Collect a list of all data source names
    $allDS = New-Object System.Collections.Generic.List[System.Object]
    foreach ($h in $Script:DatasourceURLs.GetEnumerator()) {
      $allDS += $h.Name
    }

    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($allDS)

    # Add the ValidateSet to the attributes collection
    $AttributeCollection.Add($ValidateSetAttribute)

    # Create and return the dynamic parameter
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
    return $RuntimeParameterDictionary
  }
  Process
  {
    # Bind the parameter to a friendly variable
    New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters

    if($IP -ne "" -And $FDQN -ne "") {
      throw "Please only provide the FDQN or the IP address for the datasource, not both."
    }

    # Require username and password for everything except Azure, K8s, and OpenShift
    if(($DataSourceType -ne "azure" -And $DataSourceType -ne "kubernetes" -And $DataSourceType -ne "openshift") -And ($Username -eq "" -Or $Password -eq "")) {
      throw "Please provide the Username and Password parameters as the credentials to connect to the data source."
    }

    # Check if the NSXDS parameter set is used when adding a NSX Manager as datasource
    if($DataSourceType -eq "nsxv" -And $PSCmdlet.ParameterSetName -ne "NSXDS") {
      throw "Please provide the NSX parameters when adding a NSX Manager."
    }
    if($DataSourceType -eq "nsxv" -And $NSXvCenterID -eq "") {
      throw "Please provide the NSXvCenterID parameter when adding a NSX-v Manager."
    }

    # Check if the KUBERNETES parameter set is used when adding K8s or OpenShift as datasource
    if(($DataSourceType -eq "kubernetes" -Or $DataSourceType -eq "openshift" -Or $DataSourceType -eq "pks") -And $PSCmdlet.ParameterSetName -ne "KUBERNETES") {
      throw "Please provide the KubeConfig and NSXTManagerID parameters when adding an OpenShift or Kubernetes data source. PKS only needs the NSXTManagerID"
    }


    # Check if the switch type is provided, when adding a Cisco of Dell switch
    if($DataSourceType -eq "ciscoswitch" -And $PSCmdlet.ParameterSetName -ne "CISCOSWITCH") {
      throw "Please provide the -CiscoSwitchType parameter when adding a Cisco switch."
    }
    if($DataSourceType -eq "dellswitch" -And $PSCmdlet.ParameterSetName -ne "DELLSWITCH") {
      throw "Please provide the -DellSwitchType parameter when adding a Dell switch."
    }
    if($DataSourceType -eq "azure" -And $PSCmdlet.ParameterSetName -ne "AZURE") {
      throw "Please provide the TenantID, ApplicationID, SecretKey, and SubscriptionID parameters when adding an Azure subscription."
    }

    # Format request with all given data
    $requestFormat = @{
      "ip" = $IP
      "fqdn" = $FDQN
      "proxy_id" = $CollectorVMId
      "nickname" = $Nickname
      "notes" = $Notes
      "enabled" = $Enabled
    }

    # For any other data source then K8s or OpenShift, use regular credentials
    if($DataSourceType -ne "kubernetes" -And $DataSourceType -ne "openshift") {
      $requestFormat.credentials = @{
        "username" = $Username
        "password" = $Password
      }
    }
    else
    {
      # Add KubeConfig and NSX-T Manager entity ID for OpenShift or K8s
      $requestFormat.manager_id = $NSXTManagerID
      $requestFormat.credentials = @{
        "kubeconfig" = $KubeConfig
      }
    }
    if($DataSourceType -eq "pks") {
      # Add NSX-T Manager entity ID for PKS
      $requestFormat.manager_id = $NSXTManagerID
    }

    # If we're adding a NSX Manager, also add the NSX parameters to the body
    if($DataSourceType -eq "nsxv") {
      $requestFormat.vcenter_id = $NSXvCenterID
      $requestFormat.ipfix_enabled = $NSXEnableIPFIX
      $requestFormat.central_cli_enabled = $NSXEnableCentralCLI
      $requestFormat.latency_enabled = $NSXEnableLatency
    }

    if($DataSourceType -eq "nsxt") {
      $requestFormat.ipfix_enabled = $NSXEnableIPFIX
      $requestFormat.latency_enabled = $NSXEnableLatency
    }

    # When adding a Cisco or Dell switch, provide the switch_type key in the body
    if($DataSourceType -eq "ciscoswitch") {
      $requestFormat.switch_type = $CiscoSwitchType
    }
    if($DataSourceType -eq "dellswitch") {
      $requestFormat.switch_type = $DellSwitchType
    }

    # Add the application registration details for Azure subscriptions
    if($DataSourceType -eq "azure") {
      $requestFormat.flows_enabled = $FlowsEnabled
      $requestFormat.credentials = @{
        "azure_client" = $ApplicationID
        "azure_key" = $SecretKey
        "azure_tenant" = $TenantID
        "azure_subscription" = $SubscriptionID
      }
    }

    # Convert the hash to JSON, form the URI and send the request to vRNI
    $requestBody = ConvertTo-Json $requestFormat
    $URI = "/api/ni$($Script:DatasourceURLs.$DataSourceType[0])"

    $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI -Body $requestBody
    $response
  }
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

  process {
    $DataSource | Foreach-Object {
      $oThisDatasource = $_
      # All we have to do is to send a DELETE request to URI /api/ni/$DataSourceType/$DatasourceId, so
      # form the URI and send the DELETE request to vRNI
      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)"

      Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -Uri $URI
    } ## end Foreach-Object
  } ## end process
}


function Update-vRNIDataSource
{
  <#
  .SYNOPSIS
  Updates the configuration of a datasource from vRealize Network Insight

  .DESCRIPTION
  Datasources within vRealize Network Insight provide the data shown in
  the UI. The vRNI Collectors periodically polls the datasources as the
  source of truth. Typically you have a vCenter, NSX Manager and physical
  switches as the datasource.

  This cmdlet updates a datasources in vRNI.

  .EXAMPLE
  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "vc.nsx.local"} | Update-vRNIDataSource -Username admin -Password 'VMware1!'
  Updates the credentials of a vCenter datasource with the nickname "vc.nsx.local"

  .EXAMPLE
  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "manager.nsx.local"} | Update-vRNIDataSource -Nickname "newnickname"
  Updates the nickname of a NSX Manager datasource with the nickname "manager.nsx.local"
  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNIDataSource
      [ValidateNotNullOrEmpty()]
      [PSObject]$DataSource,

    [Parameter (Mandatory=$false)]
      # Nickname for the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Nickname="",

    [Parameter (Mandatory=$false)]
      # Username to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Username = "",

    [Parameter (Mandatory=$false)]
      # Password to use to login to the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Password = "",

    [Parameter (Mandatory=$false)]
      # Optional notes for the datasource
      [ValidateNotNullOrEmpty()]
      [string]$Notes="",

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  process {

    if ($Nickname -eq "" -And $Username -eq "" -And $Password -eq "" -And $Notes -eq "") {
      throw "Provide at least one parameter to update!"
    }

    $DataSource | Foreach-Object {
      $oThisDatasource = $_

      # All we have to do is to send a PUT request to URI /api/ni/$DataSourceType/$DatasourceId,
      # with the modified options
      if ($Nickname -ne "") {
        $oThisDatasource.nickname = $Nickname
      }
      if ($Username -ne "") {
        $oThisDatasource.credentials.username = $Username

      }
      if ($Password -ne "") {
        $oThisDatasource.credentials.password = $Password
      }
      if ($Notes -ne "") {
        if($null -eq $oThisDatasource.notes) {
          $oThisDatasource | Add-Member -MemberType NoteProperty -Name 'notes' -Value $Notes
        }
        else {
          $oThisDatasource.notes = $Notes
        }
      }

      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)"
      $requestBody = ConvertTo-Json $oThisDatasource

      Invoke-vRNIRestMethod -Connection $Connection -Method PUT -Uri $URI -Body $requestBody
    } ## end Foreach-Object
  } ## end process
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

  process {
    $DataSource | Foreach-Object {
      $oThisDatasource = $_
      # All we have to do is to send a POST request to URI /api/ni/$DataSourceType/$DatasourceId/enable, so
      # form the URI and send the request to vRNI
      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)/enable"

      Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI
    } ## end Foreach-Object
  } ## end Process
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

  process {
    $DataSource | Foreach-Object {
      $oThisDatasource = $_
      # All we have to do is to send a POST request to URI /api/ni/$DataSourceType/$DatasourceId/disable, so
      # form the URI and send the request to vRNI
      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)/disable"

      Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri $URI
    } ## end Foreach-Object
  } ## end process
}



function Get-vRNIDataSourceSNMPConfig
{
  <#
  .SYNOPSIS
  Retrieves the SNMP configuration of a switch datasource from vRealize Network Insight

  .DESCRIPTION
  Physical devices like switches and UCS systems have SNMP options, which vRNI can
  read out to provide interface bandwidth graphs. This cmdlet allows you to retrieve
  the SNMP configuration of a specific data source.

  .EXAMPLE
  PS C:\> Get-vRNIDataSource | Where {$_.entity_type -eq "CiscoSwitchDataSource"} | Get-vRNIDataSourceSNMPConfig
  Gets the SNMP configuration for all Cisco switch data sources
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

  process {
    $DataSource | Foreach-Object {
      $oThisDatasource = $_

      # Sanity check on the data source type: only Cisco, Dell, Brocade, Juniper, Arista switches & UCS have SNMP config
      if($oThisDatasource.entity_type -ne "CiscoSwitchDataSource" -And $oThisDatasource.entity_type -ne "DellSwitchDataSource" -And
        $oThisDatasource.entity_type -ne "BrocadeSwitchDataSource" -And $oThisDatasource.entity_type -ne "JuniperSwitchDataSource" -And
        $oThisDatasource.entity_type -ne "AristaSwitchDataSource" -And $oThisDatasource.entity_type -ne "UCSManagerDataSource" -And
        $oThisDatasource.entity_type -ne "CiscoACIDataSource" -And $oThisDatasource.entity_type -ne "HuaweiSwitchDataSource" -And
        $oThisDatasource.entity_type -ne "F5BIGIPDataSource")
      {
        throw "Invalid Data Source Type ($($oThisDatasource.entity_type)) for SNMP. Only Cisco, Dell, Brocade, Juniper, Arista, F5, Huawei & UCS have SNMP configuration."
      }

      # All we have to do is to send a GET request to URI /api/ni/$DataSourceType/$DatasourceId/snmp-config
      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)/snmp-config"

      $result = Invoke-vRNIRestMethod -Connection $Connection -Method GET -Uri $URI
      $result
    } ## end Foreach-Object
  } ## end process
}

function Set-vRNIDataSourceSNMPConfig
{
  <#
  .SYNOPSIS
  Updates the SNMP configuration of a switch or UCS datasource within vRealize Network Insight

  .DESCRIPTION
  Physical devices like switches and UCS systems have SNMP options, which vRNI can
  read out to provide interface bandwidth graphs. This cmdlet allows you to set
  the SNMP configuration of a specific data source.

  .EXAMPLE
  PS C:\> $snmpOptions = @{ "Enabled" = $true; "Username" = "snmpv3user"; "ContextName" = " "; "AuthenticationType" = "MD5";  "AuthenticationPassword" = "ult1m4t3p4ss";  "PrivacyType" = "AES128";  "PrivacyPassword" = "s0pr1v4t3"; }
  PS C:\> Get-vRNIDataSource | Where {$_.nickname -eq "Core01"} | Set-vRNIDataSourceSNMPConfig @snmpOptions
  Configures SNMPv3 for a data source named 'Core01'

  .EXAMPLE
  PS C:\> Get-vRNIDataSource -DataSourceType ciscoswitch | Set-vRNIDataSourceSNMPConfig -Enabled $true -Community "qwerty1234"
  Configured SNMPv2 on all Cisco switch datasources.

  #>

  [CmdletBinding(DefaultParameterSetName="__AllParameterSets")]

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNIDataSource
      [ValidateNotNullOrEmpty()]
      [PSObject]$DataSource,

    [Parameter (Mandatory=$false)]
      # Enable SNMP?
      [ValidateNotNullOrEmpty()]
      [bool]$Enabled = $true,

    # This param is only required when configuring SNMP v2c
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv2c")]
      # SNMP v2c Community string
      [ValidateNotNullOrEmpty()]
      [string]$Community,

    # These params are only required when configuring SNMP v3
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Username
      [ValidateNotNullOrEmpty()]
      [string]$Username,
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Context name
      [ValidateNotNullOrEmpty()]
      [string]$ContextName,
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Context name
      [ValidateSet ("MD5", "SHA", "NO_AUTH")]
      [string]$AuthenticationType,
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Authentication Password
      [ValidateNotNullOrEmpty()]
      [string]$AuthenticationPassword,
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Privacy Type
      [ValidateSet ("AES", "DES", "AES128", "AES192", "AES256", "3DES", "NO_PRIV")]
      [string]$PrivacyType,
    [Parameter (Mandatory=$true, ParameterSetName="SNMPv3")]
      # SNMP v3 Privacy Password
      [ValidateNotNullOrEmpty()]
      [string]$PrivacyPassword,

    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  process {
    $DataSource | Foreach-Object {
      $oThisDatasource = $_

      # Sanity check on the data source type: only Cisco, Dell, Brocade, Juniper, Arista switches & UCS have SNMP config

      if($oThisDatasource.entity_type -ne "CiscoSwitchDataSource" -And $oThisDatasource.entity_type -ne "DellSwitchDataSource" -And
        $oThisDatasource.entity_type -ne "BrocadeSwitchDataSource" -And $oThisDatasource.entity_type -ne "JuniperSwitchDataSource" -And
        $oThisDatasource.entity_type -ne "AristaSwitchDataSource" -And $oThisDatasource.entity_type -ne "UCSManagerDataSource" -And
        $oThisDatasource.entity_type -ne "F5BIGIPDataSource" -And $oThisDatasource.entity_type -ne "HuaweiSwitchDataSource") {
        throw "Invalid Data Source Type ($($oThisDatasource.entity_type)) for SNMP. Only Cisco, Dell, Brocade, Juniper, F5, Arista switches & UCS have SNMP configuration."
      }

      # Format request with all given data
      $requestFormat = @{
        "snmp_enabled" = $Enabled
      }

      # if SNMPv2 parameters are given, build the snmp_2c var
      if ($pscmdlet.ParameterSetName -eq "SNMPv2c") {
        $requestFormat.snmp_version = "v2c"
        $requestFormat.config_snmp_2c = @{
          "community_string" = $Community
        }
      }

      # if SNMPv3 parameters are given, build the snmp_3 var
      if ($pscmdlet.ParameterSetName -eq "SNMPv3") {
        $requestFormat.snmp_version = "v3"
        $requestFormat.config_snmp_3 = @{
          "username" = $Username
          "context_name" = $ContextName
          "authentication_type" = $AuthenticationType
          "authentication_password" = $AuthenticationPassword
          "privacy_type" = $PrivacyType
          "privacy_password" = $PrivacyPassword
        }
      }

      # All we have to do now is to send a PUT request to URI /api/ni/$DataSourceType/$DatasourceId/snmp-config with the right body
      $requestBody = ConvertTo-Json $requestFormat
      $URI = "/api/ni$($Script:DatasourceInternalURLs.$($oThisDatasource.entity_type))/$($oThisDatasource.entity_id)/snmp-config"

      Invoke-vRNIRestMethod -Connection $Connection -Method PUT -Uri $URI -Body $requestBody
    } ## end Foreach-Object
  } ## end process
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

  .PARAMETER Name
  Limit the amount of records returned to a specific name

  .PARAMETER Connection
  vRNI Connection object

  .EXAMPLE
  PS C:\> Get-vRNIApplication
  Show all existing applications and their details.

  .EXAMPLE
  PS C:\> Get-vRNIApplication -Name '3 Tier App'
  Get only the application details of the application named "3 Tier App"
  #>
  param (
    [Parameter(Mandatory=$false, Position=1, ParameterSetName = 'Filter')]
      [string[]] $Name,
    [Parameter(Mandatory=$false)]
      [ValidateNotNullOrEmpty()]
      [PSCustomObject] $Connection = $defaultvRNIConnection
  )

  $applications = [System.Collections.ArrayList]@()

  $size = 50
  $listParams = @{
    Connection = $Connection
    Method = 'GET'
    Uri = "/api/ni/groups/applications?size=$size"
  }

  # If a filter has been given, use the search endpoint to more efficiently find the right applications
  if ($PSCmdlet.ParameterSetName -eq 'Filter') {
    $listParams['Method'] = 'POST'
    $listParams['Uri'] = '/api/ni/search'

    $body = @{
      entity_type = 'Application'
    }

    # Build the search filter
    $filter = @()
    # If there's an application name specified, figure out if it's a single name or an array of names
    # and format the search filter appropriately
    if ($Name) {
      # Multiple application names
      if ($Name.Count -gt 1) {
        $nameArray = @()
        foreach ($nameItem in $Name) {
          $nameArray += "'$nameItem'"
        }
        $nameSearchString = " in (" + ($nameArray -join ',') + ")"
      }
      # Single application name
      else {
        $nameSearchString = " = '$Name'"
      }

      $filter += "(Name $nameSearchString)"
    } ## end if ($Name)

    $body['filter'] = $filter -join ' and '

    $listParams['Body'] = $body | ConvertTo-Json
    Write-Verbose ('Body: ' + $listParams['Body'])
  } ## end if ($PSCmdlet.ParameterSetName -eq 'Filter')
  else
  {
    # With version 1.1.0 of the API - there's a single endpoint to retrieve all
    if($Script:vRNI_API_Version -ge [System.Version]"1.1.0")
    {
      $listParams['Uri'] = '/api/ni/groups/applications/fetch?size=2500'
      $applications = Invoke-vRNIRestMethod @listParams
      $applications.results
      return
    }
  }

  $hasMoreData = $true
  $counter = 0
  while ($hasMoreData)
  {
    $applicationResponse = Invoke-vRNIRestMethod @listParams

    Write-Verbose ("$($applicationResponse.total_count) applications to process")
    if ($applicationResponse.total_count -gt $size) {
      $listParams['Uri'] += "&cursor=$($applicationResponse.cursor)"
    }

    foreach($app in $applicationResponse.results)
    {
      # Retrieve application details and store them
      $app_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($app.entity_id)"
      $applications.Add($app_info) | Out-Null

      $counter++
    }

    $remaining = $applicationResponse.total_count - $counter
    if ($remaining -gt 0) {
      Write-Verbose "$remaining more applications to process"
      $hasMoreData = $true
    }
    else {
      $hasMoreData = $false
    }
  }

  $applications
}

function Get-vRNIApplicationMemberVM
{
  <#
  .SYNOPSIS
  Get a list of VMs in an application from vRealize Network Insight.

  .DESCRIPTION
  Within vRNI there are applications, which can be viewed as groups of VMs.
  These groups can be used to group the VMs of a certain application together,
  and filter on searches within vRNI. For instance, you can generate recommended
  firewall rules based on an application group.

  .EXAMPLE
  PS C:\> Get-vRNIApplication My3TierApp | Get-vRNIApplicationMemberVM
  Show the member VMs for the application called "My3TierApp"
  #>
  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true)]
      # Application object, gotten from Get-vRNIApplication
      [ValidateNotNullOrEmpty()]
      [PSObject]$Application,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  process
  {
    ## do Foreach-Object, so as to enable user to pass multiple Application objects for value of -Application parameter
    $Application | Foreach-Object {
      $oThisApplication = $_
      # Get a list of all VMs for this application
      $vm_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($oThisApplication.entity_id)/members/vms"
      $vm_list.results
    } ## end Foreach-Object
  } ## end process
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

  process {
    ## do Foreach-Object, so as to enable user to pass multiple Application objects for value of -Application parameter
    $Application | Foreach-Object {
      $oThisApplication = $_
      # First, get a list of all tier. This returns a list with application IDs which we can use
      # to retrieve the details of the applications
      $tier_list = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($oThisApplication.entity_id)/tiers"

      # Use this as a results container
      $tiers = [System.Collections.ArrayList]@()

      foreach($tier in $tier_list.results)
      {
        # Retrieve application details and store them
        $tier_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/groups/applications/$($oThisApplication.entity_id)/tiers/$($tier.entity_id)"
        $tiers.Add($tier_info) | Out-Null

        # Don't go on if we've already found the one the user wants specifically
        if($Name -eq $tier_info.name) {break}
      }

      # Filter out other application tiers if the user wants one specifically
      if ($Name) {$tiers | Where-Object { $_.name -eq $Name }}
      else {$tiers}
    } ## end Foreach-Object
  } ## end process
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
  PS C:\> Get-vRNIApplication My3TierApp | New-vRNIApplicationTier -Name web-tier -VMFilters ("name = '3TA-Web01' or name = '3TA-Web02'")
  Create a new tier in the application 'My3TierApp' called 'web-tier' and assign the VMs named '3TA-Web01' and '3TA-Web02' to this tier.

  .EXAMPLE
  PS C:\> $security_group_id = (Get-vRNISecurityGroup SG-3Tier-App).entity_id
  PS C:\> Get-vRNIApplication My3TierApp | New-vRNIApplicationTier -Name app-tier -VMFilters ("name = '3TA-App01'", "security_groups.entity_id = '$security_group_id'")
  Create a new tier in the application 'My3TierApp' called 'web-tier' and assign the
  VMs named '3TA-Web01' and '3TA-Web02' to this tier.

  .EXAMPLE
  PS C:\> Get-vRNIApplication IP-Network | New-vRNIApplicationTier -Name IP-Set-1 -IPFilters 100.194.0.0/24, 192.168.1.1, 192.168.10.0/27
  This retrieves the existing application called 'IP-Network' and creates a new tier
  inside it called 'IP-Set-1' with a /24 subnet, a single host and a /27 subnet.

  .EXAMPLE
  PS C:\> Get-vRNIApplication IP-Network | New-vRNIApplicationTier -Name IP-Host-2 -IPFilters 172.16.0.10
  This retrieves the existing application called 'IP-Network' and creates a new tier
  inside it called 'IP-Host-2' with a single host on the IP 172.16.0.10.

  .PARAMETER Filters
  The filters within an application tier determine what VMs will be placed in that
  application. Currently, only these options are supported:

  Single VM:                   "name = '3TA-App01'"
  Multiple VMs:                "name = '3TA-App01' or name = '3TA-App02'"
  VMs with a NSX Security Tag: "security_groups.entity_id = '18230:82:604573173'"
  #>

  # To keep backwards compatibility with 1.0
  [CmdletBinding(DefaultParameterSetName="VMFilter")]

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true)]
      # Application object, gotten from Get-vRNIApplication
      [ValidateNotNullOrEmpty()]
      [PSObject]$Application,
    [Parameter (Mandatory=$true)]
      # The name of the new tier
      [string]$Name,
    [Parameter (Mandatory=$false, ParameterSetName="VMFilter")]
      # The VM filters in the new tier
      [string[]]$Filters,
    [Parameter (Mandatory=$false, ParameterSetName="MultipleFilters")]
      # The VM filters in the new tier
      [string[]]$VMFilters,
    [Parameter (Mandatory=$false, ParameterSetName="IPFilters")]
      # The IP set filters in the new tier
      [string[]]$IPFilters,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  begin {
    if(!$Filters -And !$VMFilters -And !$IPFilters) {
      throw "Please provide at least one filter."
    }

    # Format request with all given data
    $requestFormat = @{
      "name" = $Name
      "group_membership_criteria" = @()
    }

    # Backwards compatibility with 1.0 - if the old -Filters are given, transfer it to $VMFilters
    if ($pscmdlet.ParameterSetName -eq "VMFilter") {
      $VMFilters = $Filters
    }

    # If supplied, go through the VM filters and build the call
    if($VMFilters)
    {
      foreach($filter in $VMFilters)
      {
        $criteria_record = @{}
        $criteria_record.membership_type = "SearchMembershipCriteria"
        $criteria_record.search_membership_criteria = @{
          "entity_type" = "BaseVirtualMachine"
          "filter" = $filter
        }
        $requestFormat.group_membership_criteria += $criteria_record
      }
    }

    # If supplied, go through the IP filters and build the call
    if($IPFilters)
    {
      $criteria_record = @{}
      $criteria_record.membership_type = "IPAddressMembershipCriteria"
      $criteria_record.ip_address_membership_criteria = @{}
      $criteria_record.ip_address_membership_criteria.ip_addresses = @()

      foreach($ipset in $IPFilters)
      {
        $criteria_record.ip_address_membership_criteria.ip_addresses += $ipset
      }

      $requestFormat.group_membership_criteria += $criteria_record
    }

    Write-Debug $requestFormat

    # Convert the hash to JSON, form the URI and send the request to vRNI
    $requestBody = ConvertTo-Json $requestFormat -Depth 5
  } ## end begin

  process {
    $Application | Foreach-Object {
      $oThisApplication = $_
      Invoke-vRNIRestMethod -Connection $Connection -Method POST -URI "/api/ni/groups/applications/$($oThisApplication.entity_id)/tiers" -Body $requestBody
    } ## end Foreach-Object
  } ## end process
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

  process {
    $ApplicationTier | Foreach-Object {
      $oThisApplicationTier = $_
      # Send the DELETE request and show the result
      Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/groups/applications/$($oThisApplicationTier.application.entity_id)/tiers/$($oThisApplicationTier.entity_id)"
    } ## end Foreach-Object
  } ## end process
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

  process {
    $Application | Foreach-Object {
      $oThisApplication = $_
      # Send the DELETE request and show the result
      Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -URI "/api/ni/groups/applications/$($oThisApplication.entity_id)"
    } ## end Foreach-Object
  } ## end process
}

#####################################################################################################################
#####################################################################################################################
#########################################  Entity Management ########################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNIEntity
{
  <#
  .SYNOPSIS
  Get available entities from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all kinds of entities inside
  the monitored infrastructure. This is a catch-all function to retrieve
  any entity and the objects related to that entity.

  .EXAMPLE
  PS C:\> Get-vRNIEntity -Entity_URI security-groups
  Get all security groups in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNIEntity -Entity_URI "hosts" -Name "esxi01.lab"
  Get the entity object for the hypervisor host called "esxi01.lab"
  #>
  param (
    [Parameter (Mandatory=$true)]
      # Limit the amount of records returned
      [string]$Entity_URI,
    [Parameter (Mandatory=$false)]
      # Limit the amount of records returned
      [int]$Limit = 0,
    [Parameter (Mandatory=$false, Position=1)]
      # Limit the amount of records returned
      [string]$Name = "",
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
  $entities = [System.Collections.ArrayList]@()

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
    $URI = "/api/ni/entities/$($Entity_URI)"
    if($size -gt 0 -And $cursor -ne "") {
      $URI += "?size=$($size)&cursor=$($cursor)"
      $using_params++
    }

    # Check if we want to limit the results to a time window
    if($PSCmdlet.ParameterSetName -eq "TIMELIMIT" -And ($StartTime -gt 0 -And $EndTime -gt 0)) {
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

    $listParams = @{
      Connection = $Connection
      Method = 'GET'
      URI = $URI
    }

    # support filtering by a VM by using search instead of returning all entities
    if ($PSBoundParameters.ContainsKey('Name') -and $Name -ne '') {
      $listParams['URI'] = '/api/ni/search'
      $listParams['Body'] = @{
         entity_type = $Script:EntityURLtoIdMapping.$Entity_URI
        filter = "Name = '$Name'"
      } | ConvertTo-Json
      $listParams['Method'] = 'POST'
    }

    # Get a list of all entities
    $entity_list = Invoke-vRNIRestMethod @listParams

    # If we're not finished, store information about the run for next use
    if($finished -eq $false)
    {
      $total_count = $entity_list.total_count
      $cursor      = $entity_list.cursor
    }

    # If the size is smaller than 10 (decreased by previous run), or the size is greater than the total records, finish up
    if($size -lt 10 -Or ($total_count -gt 0 -And $size -gt $total_count)) {
      $finished = $true
    }

    # If we're using version 1.1.0 or greater of the vRNI API - we can use the /entities/fetch bulk method of getting entity details. Much more efficient.
    if($Script:vRNI_API_Version -ge [System.Version]"1.1.0")
    {
      $requestFormat = @{
        "entity_ids" = $entity_list.results
      }
      $requestBody = ConvertTo-Json $requestFormat
      $entity_info = Invoke-vRNIRestMethod -Connection $Connection -Method POST -URI "/api/ni/entities/fetch" -Body $requestBody

      foreach($entity in $entity_info.results)
      {
        $entity = $entity.entity
        # If we're retrieving flows, add the time of the main flow to this specific flow record
        if($Entity_URI -eq "flows") {
          $entity | Add-Member -Name "time" -value $entity.time -MemberType NoteProperty
        }

        $entities.Add($entity) | Out-Null
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

      # continue the while(!$finished) loop
      continue
    }

    # Go through the entities individually and store them in the results array
    foreach($sg in $entity_list.results)
    {
      # Retrieve entity details and store them
      $entity_info = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/$($Entity_URI)/$($sg.entity_id)?time=$($sg.time)"

      # If we're retrieving flows, add the time of the main flow to this specific flow record
      if($Entity_URI -eq "flows") {
        $entity_info | Add-Member -Name "time" -value $entity_info.time -MemberType NoteProperty
      }

      $entities.Add($entity_info) | Out-Null
      $current_count++

      # If we are limiting the output, break from the loops and return results
      if($Limit -ne 0 -And ($Limit -lt $current_count -Or $Limit -eq $current_count)) {
        $finished = $true
        break
      }
    } ## end foreach($sg in $entity_list.results)

    # Check remaining items, if it's less than the default size, reduce the next page size
    if($size -gt ($total_count - $current_count)) {
      $size = ($total_count - $current_count)
    }

  }

  # if a single entity name was requested, filter on name
  if ($Name) {
    $entities | Where-Object { $_.name -eq $Name }
  }
  else {
    $entities
  }
}


function Get-vRNIEntityName
{
  <#
  .SYNOPSIS
  Translate an entity id to a name in vRealize Network Insight.

  .DESCRIPTION
  The internal database of vRealize Network Insight uses entity IDs
  to keep track of entities. This function translates an ID to an
  actual useable name.

  .EXAMPLE
  PS C:\> Get-vRNIEntityName -EntityID 14307:562:1274720802
  Get the name of the entity with ID 14307:562:1274720802
  #>
  param (
    [Parameter (Mandatory=$true, Position=1)]
      # The entity ID to resolve to a name
      [string]$EntityID,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Call Invoke-vRNIRestMethod with the proper URI to get the entity results
  $result = Invoke-vRNIRestMethod -Connection $Connection -Method GET -URI "/api/ni/entities/names/$($EntityID)"
  $result
}

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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "problems" -Limit $Limit -StartTime $StartTime -EndTime $EndTime
  $results
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "flows" -Limit $Limit -StartTime $StartTime -EndTime $EndTime
  $results
}


function Get-vRNIKubernetesServices
{
  <#
  .SYNOPSIS
  Get Kubernetes Services from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all Kubernetes Services in your environment
  and this cmdlet will help you discover these services.

  .EXAMPLE
  PS C:\> Get-vRNIKubernetesServices
  List all Kubernetes Services in your vRNI environment (note: this may take a while if you have a lot of services)

  .EXAMPLE
  PS C:\> Get-vRNIKubernetesServices -Name my-k8s-service
  Retrieve only the Kubernetes Service object called "my-k8s-service"
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "kubernetes-services" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#-----------------------------------------  VM Entities ---------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#

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
  List all VMs in your vRNI environment (note: this may take a while if you have a lot of VMs)

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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "vms" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIVMvNIC
{
  <#
  .SYNOPSIS
  Get virtual machine vnics from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all VM vNICs in your environment
  and this cmdlet will help you discover these VM vNICs.

  .EXAMPLE
  PS C:\> Get-vRNIVMvNIC
  List all VM vNICs in your vRNI environment (note: this may take a while if you have a lot of VMs)
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "vnics" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#--------------------------------------- vCenter Entities -------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#

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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "vcenter-managers" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIvCenterFolder
{
  <#
  .SYNOPSIS
  Get available vCenter folders from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all vCenter folders in your environment
  and this cmdlet will help you discover these folders.

  .EXAMPLE
  PS C:\> Get-vRNIvCenterFolder
  Get all vCenter folders in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "folders" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIvCenterDatacenter
{
  <#
  .SYNOPSIS
  Get available vCenter Datacenters from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all vCenter Datacenters in your
  environment and this cmdlet will help you discover these Datacenters.

  .EXAMPLE
  PS C:\> Get-vRNIvCenterDatacenter
  Get all vCenter Datacenters in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "vc-datacenters" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIvCenterCluster
{
  <#
  .SYNOPSIS
  Get available vCenter Clusters from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all vCenter Clusters in your
  environment and this cmdlet will help you discover these Clusters.

  .EXAMPLE
  PS C:\> Get-vRNIvCenterCluster
  Get all vCenter Clusters in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "clusters" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#-------------------------------------- ESXi host Entities ------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "hosts" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIHostVMKNic
{
  <#
  .SYNOPSIS
  Get available host vmknics from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all host vmknics in your
  environment and this cmdlet will help you discover these vmknids.

  .EXAMPLE
  PS C:\> Get-vRNIHostVMKNic
  Get all host vmknics in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "vmknics" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#------------------------------------------- NSX Entities -------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#

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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "security-groups" -Name $Name -Limit $Limit
  $results
}

function Get-vRNISecurityTag
{
  <#
  .SYNOPSIS
  Get available security tags (ST) from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all STs in your environment
  and this cmdlet will help you discover these STs.

  .EXAMPLE
  PS C:\> Get-vRNISecurityTag
  Get all security tags in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNISecurityTag ST-3TA-Management
  Retrieve the security tag object for the one called "ST-3TA-Management"
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "security-tags" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIIPSet
{
  <#
  .SYNOPSIS
  Get available NSX IP Sets from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all NSX IP Sets in your environment
  and this cmdlet will help you discover these IP sets.

  .EXAMPLE
  PS C:\> Get-vRNIIPSet
  Get all IP Sets in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "ip-sets" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIService
{
  <#
  .SYNOPSIS
  Get available NSX Services from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all NSX Services in your environment
  and this cmdlet will help you discover these Services.

  .EXAMPLE
  PS C:\> Get-vRNIService
  Get all NSX Services in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "services" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIServiceGroup
{
  <#
  .SYNOPSIS
  Get available NSX Service Groups from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all NSX Service Groups in your environment
  and this cmdlet will help you discover these groups.

  .EXAMPLE
  PS C:\> Get-vRNIServiceGroup
  Get all NSX Service Groups in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "service-groups" -Name $Name -Limit $Limit
  $results
}

function Get-vRNINSXManager
{
  <#
  .SYNOPSIS
  Get available NSX Managers from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all NSX Managers in your environment
  and this cmdlet will help you discover these NSX Managers.

  .EXAMPLE
  PS C:\> Get-vRNINSXManager
  Get all NSX Managers in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "nsx-managers" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#---------------------------------------- Networking Entities ---------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#

function Get-vRNIFirewallRule
{
  <#
  .SYNOPSIS
  Get available firewall rules from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all firewall rules in your environment
  and this cmdlet will help you discover these rules.

  .EXAMPLE
  PS C:\> Get-vRNIFirewallRule
  Get all firewall rules in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "firewall-rules" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIL2Network
{
  <#
  .SYNOPSIS
  Get available layer 2 networks from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all networks in your environment
  and this cmdlet will help you discover these layer 2 networks.

  .EXAMPLE
  PS C:\> Get-vRNIL2Network
  Get all layer 2 networks in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNIL2Network | Where {$_.entity_type -eq "VxlanLayer2Network"}
  Only show all VXLAN layer 2 networks.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "layer2-networks" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIDistributedSwitch
{
  <#
  .SYNOPSIS
  Get available vSphere Distributed Switches from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all VDSes in your environment
  and this cmdlet will help you discover these VDSes.

  .EXAMPLE
  PS C:\> Get-vRNIDistributedSwitch
  Get all vSphere Distributed Switches in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNIDistributedSwitch LabSwitch
  Get only the VDS called 'LabSwitch'

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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "distributed-virtual-switches" -Name $Name -Limit $Limit
  $results
}

function Get-vRNIDistributedSwitchPortGroup
{
  <#
  .SYNOPSIS
  Get available VDS Portgroups from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all VDS Portgroups in your environment
  and this cmdlet will help you discover these portgroups.

  .EXAMPLE
  PS C:\> Get-vRNIDistributedSwitchPortGroup
  Get all VDS Portgroups in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNIDistributedSwitchPortGroup Web-Tier
  Get only the portgroup called 'Web-Tier'
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "distributed-virtual-portgroups" -Name $Name -Limit $Limit
  $results
}

function Get-vRNICheckPointManagers
{
  <#
  .SYNOPSIS
  Get available CheckPoint Firewall Managers from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all CheckPoint Firewall Managers in your environment
  and this cmdlet will help you discover these managers.

  .EXAMPLE
  PS C:\> Get-vRNICheckPointManagers
  Get all CheckPoint Firewall Managers in the vRNI environment.

  .EXAMPLE
  PS C:\> Get-vRNICheckPointManagers CP01
  Get only the CheckPoint Firewall Managers called 'CP01'
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "firewall-managers" -Name $Name -Limit $Limit
  $results
}

#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------- Storage Entities -----------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------#

function Get-vRNIDatastore
{
  <#
  .SYNOPSIS
  Get available datastores from vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight has a database of all datastores in your environment
  and this cmdlet will help you discover these datastores.

  .EXAMPLE
  PS C:\> Get-vRNIDatastore
  Get all datastores in the vRNI environment.
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

  # Call Get-vRNIEntity with the proper URI to get the entity results
  $results = Get-vRNIEntity -Entity_URI "datastores" -Name $Name -Limit $Limit
  $results
}

#####################################################################################################################
#####################################################################################################################
#####################################  Recommended Firewall Rules  ##################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNIRecommendedRules
{
  <#
  .SYNOPSIS
  Retrieve the recommended firewall rules of a specific application.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  required firewall rules to implement micro-segmentation. This means
  you have a starting point when it comes to micro-segmentation and
  implementing the needed firewall rules. This function retrieves the
  recommended firewall rules for an application.

  Per default this function uses a 14 day analysis period.

  .EXAMPLE
  PS C:\> Get-vRNIRecommendedRules -ApplicationID (Get-vRNIApplication vRNI).entity_id
  This will return the recommended firewall rules for the application called 'vRNI'

  .EXAMPLE
  PS C:\> $sevenDaysAgo = (Get-Date).AddDays(-7)
  PS C:\> $start = [int][double]::Parse((Get-Date -Date $sevenDaysAgo -UFormat %s))
  PS C:\> $end = [int][double]::Parse((Get-Date -UFormat %s))
  PS C:\> Get-vRNIRecommendedRules -ApplicationID (Get-vRNIApplication vRNI).entity_id -StartTime $start -EndTime $end
  This will return the recommended firewall rules for the application
  called 'vRNI' from analysis on the last 7 days.
  #>
  param (
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to start looking up records
      [int]$StartTime = 0,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to stop looking up records
      [int]$EndTime = 0,
    [Parameter (Mandatory=$false)]
      # The application entity ID for which to retrieve the recommended rules
      [string]$ApplicationID = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  if($PSCmdlet.ParameterSetName -eq "TIMELIMIT" -And ($StartTime -gt 0 -And $EndTime -gt 0))
  {
    if($StartTime -gt $EndTime) {
      throw "StartTime cannot be greated than EndTime"
    }
  }
  else
  {
    # Use a timeframe of 14 days by default
    $twoWeeksAgo = (Get-Date).AddDays(-14)
    $StartTime = [int][double]::Parse((Get-Date -Date $twoWeeksAgo -UFormat %s))
    $EndTime = [int][double]::Parse((Get-Date -UFormat %s))
  }

  # TODO: also allow lookups between 2 application tiers

  # Format request with all given data
  $requestFormat = @{
    "group_1" = @{
      "entity" = @{
        "entity_type" = "Application"
        "entity_id" = $ApplicationID
      }
    }
    "time_range" = @{
      "start_time" = $StartTime
      "end_time" = $EndTime
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $response = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/micro-seg/recommended-rules" -Body $requestBody

  $response.results
}


function Get-vRNIRecommendedRulesNsxBundle
{
  <#
  .SYNOPSIS
  Retrieve the recommended firewall rules of a specific application bundled in the NSX-v format for
  processing with the Rules Importer Tool (more on that at a later date)

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  required firewall rules to implement micro-segmentation. This means
  you have a starting point when it comes to micro-segmentation and
  implementing the needed firewall rules. This function retrieves the
  recommended firewall rules for an application.

  Per default this function uses a 14 day analysis period.

  .EXAMPLE
  PS C:\> Get-vRNIRecommendedRulesNsxBundle -ApplicationID (Get-vRNIApplication vRNI).entity_id
  This will return the recommended firewall rules for the application called 'vRNI'

  .EXAMPLE
  PS C:\> $sevenDaysAgo = (Get-Date).AddDays(-7)
  PS C:\> $start = [int][double]::Parse((Get-Date -Date $sevenDaysAgo -UFormat %s))
  PS C:\> $end = [int][double]::Parse((Get-Date -UFormat %s))
  PS C:\> Get-vRNIRecommendedRulesNsxBundle -ApplicationID (Get-vRNIApplication vRNI).entity_id -StartTime $start -EndTime $end
  This will return the recommended firewall rules for the application
  called 'vRNI' from analysis on the last 7 days.
  #>
  param (
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to start looking up records
      [int]$StartTime = 0,
    [Parameter (Mandatory=$false, ParameterSetName="TIMELIMIT")]
      # The epoch timestamp of when to stop looking up records
      [int]$EndTime = 0,
    [Parameter (Mandatory=$false)]
      # The application entity ID for which to retrieve the recommended rules
      [string]$ApplicationID = "",
    [Parameter (Mandatory=$true)]
      # This cmdlet outputs a zip file specified by the filename here
      [string]$OutFile,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  if($PSCmdlet.ParameterSetName -eq "TIMELIMIT" -And ($StartTime -gt 0 -And $EndTime -gt 0))
  {
    if($StartTime -gt $EndTime) {
      throw "StartTime cannot be greated than EndTime"
    }
  }
  else
  {
    # Use a timeframe of 14 days by default
    $twoWeeksAgo = (Get-Date).AddDays(-14)
    $StartTime = [int][double]::Parse((Get-Date -Date $twoWeeksAgo -UFormat %s))
    $EndTime = [int][double]::Parse((Get-Date -UFormat %s))
  }

  # TODO: also allow lookups between 2 application tiers

  # Format request with all given data
  $requestFormat = @{
    "group_1" = @{
      "entity" = @{
        "entity_type" = "Application"
        "entity_id" = $ApplicationID
      }
    }
    "time_range" = @{
      "start_time" = $StartTime
      "end_time" = $EndTime
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/micro-seg/recommended-rules/nsx" -Body $requestBody -OutFile $OutFile
}

#####################################################################################################################
#####################################################################################################################
#########################################  Settings Management ######################################################
#####################################################################################################################
#####################################################################################################################


function New-vRNISubnetMapping
{
  <#
  .SYNOPSIS
  Create a new IP Subnet to VLAN ID mapping within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. When vRNI does not have full visibility on the physical
  network and can't discover the mappings between VLANs and subnets,
  you can use subnet mappings to manually determine which subnets belong
  to which VLANs.

  .EXAMPLE
  PS C:\> New-vRNISubnetMapping -VLANID 10 -CIDR 192.168.0.0/24

  .EXAMPLE
  PS C:\> New-vRNISubnetMapping -VLANID 11 -CIDR 192.168.0.0/16

  #>
  param (
    [Parameter (Mandatory=$true)]
      # The VLAN ID for this mapping
      [int]$VLANID,
    [Parameter (Mandatory=$true)]
      # The CIDR mapped to the given VLAN ID
      [string]$CIDR,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = @{
    "cidr" = $CIDR
    "vlan_id" = $VLANID
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/settings/subnet-mappings" -Body $requestBody
}

function Get-vRNISubnetMapping
{
  <#
  .SYNOPSIS
  Retrieve all IP Subnet to VLAN ID mappings within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. When vRNI does not have full visibility on the physical
  network and can't discover the mappings between VLANs and subnets,
  you can use subnet mappings to manually determine which subnets belong
  to which VLANs.

  .EXAMPLE
  PS C:\> Get-vRNISubnetMapping

  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $results = Invoke-vRNIRestMethod -Connection $Connection -Method GET -Uri "/api/ni/settings/subnet-mappings"
  return $results.results
}

function Get-vRNIEastWestIP
{
  <#
  .SYNOPSIS
  Retrieve all East-West IP mappings within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using public IPs for workloads inside
  the datacenter, you should add them to the East-West IP mappings.

  .EXAMPLE
  PS C:\> Get-vRNIEastWestIP

  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $results = Invoke-vRNIRestMethod -Connection $Connection -Method GET -Uri "/api/ni/settings/ip-tags/EAST_WEST"
  return $results
}

function Add-vRNIEastWestIP
{
  <#
  .SYNOPSIS
  Adds a new East-West IP mapping within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using public IPs for workloads inside
  the datacenter, you should add them to the East-West IP mappings.

  .EXAMPLE
  PS C:\> Add-vRNIEastWestIP -Subnet 80.182.12.0/24

  .EXAMPLE
  PS C:\> Add-vRNIEastWestIP -IP_Range_Start 90.23.12.1 -IP_Range_End 90.23.12.100

  #>
  param (
    [Parameter (Mandatory=$true, ParameterSetName="PS_Subnet")]
      # The subnet to add to the IP mappings
      [string]$Subnet,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range start to add to the IP mappings
      [string]$IP_Range_Start,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range end to add to the IP mappings
      [string]$IP_Range_End,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = ""
  if($PSCmdlet.ParameterSetName -eq "PS_Subnet")
  {
    $requestFormat = @{
      "tag_id" = "EAST_WEST"
      "subnets" = @($Subnet)
    }
  }
  if($PSCmdlet.ParameterSetName -eq "PS_IP_Range")
  {
    $requestFormat = @{
      "tag_id" = "EAST_WEST"
      "ip_address_ranges" = @( @{
        "start_ip" = $IP_Range_Start
        "end_ip" = $IP_Range_End
      } )
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $results = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/settings/ip-tags/EAST_WEST/add" -Body $requestBody
  return $results
}

function Remove-vRNIEastWestIP
{
  <#
  .SYNOPSIS
  Removes a East-West IP mapping within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using public IPs for workloads inside
  the datacenter, you should add them to the East-West IP mappings.

  .EXAMPLE
  PS C:\> Remove-vRNIEastWestIP -Subnet 80.182.12.0/24

  .EXAMPLE
  PS C:\> Remove-vRNIEastWestIP -IP_Range_Start 90.23.12.1 -IP_Range_End 90.23.12.100

  #>
  param (
    [Parameter (Mandatory=$true, ParameterSetName="PS_Subnet")]
      # The subnet to remove from the IP mappings
      [string]$Subnet,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range start to remove from the IP mappings
      [string]$IP_Range_Start,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range end to remove from the IP mappings
      [string]$IP_Range_End,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = ""
  if($PSCmdlet.ParameterSetName -eq "PS_Subnet")
  {
    $requestFormat = @{
      "tag_id" = "EAST_WEST"
      "subnets" = @($Subnet)
    }
  }
  if($PSCmdlet.ParameterSetName -eq "PS_IP_Range")
  {
    $requestFormat = @{
      "tag_id" = "EAST_WEST"
      "ip_address_ranges" = @( @{
        "start_ip" = $IP_Range_Start
        "end_ip" = $IP_Range_End
      } )
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $results = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/settings/ip-tags/EAST_WEST/remove" -Body $requestBody
  return $results
}

function Get-vRNINorthSouthIP
{
  <#
  .SYNOPSIS
  Retrieve all North-South IP mappings within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using internal IPs outside the datacenter,
  you should add them to the North-South IP mappings.

  .EXAMPLE
  PS C:\> Get-vRNINorthSouthIP

  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $results = Invoke-vRNIRestMethod -Connection $Connection -Method GET -Uri "/api/ni/settings/ip-tags/INTERNET"
  return $results
}

function Add-vRNINorthSouthIP
{
  <#
  .SYNOPSIS
  Add a new North-South IP mapping within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using internal IPs outside the datacenter,
  you should add them to the North-South IP mappings.

  .EXAMPLE
  PS C:\> Add-vRNINorthSouthIP -Subnet 80.182.12.0/24

  .EXAMPLE
  PS C:\> Add-vRNINorthSouthIP -IP_Range_Start 90.23.12.1 -IP_Range_End 90.23.12.100

  #>
  param (
    [Parameter (Mandatory=$true, ParameterSetName="PS_Subnet")]
      # The subnet to add to the IP mappings
      [string]$Subnet,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range start to add to the IP mappings
      [string]$IP_Range_Start,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range end to add to the IP mappings
      [string]$IP_Range_End,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = ""
  if($PSCmdlet.ParameterSetName -eq "PS_Subnet")
  {
    $requestFormat = @{
      "tag_id" = "INTERNET"
      "subnets" = @($Subnet)
    }
  }
  if($PSCmdlet.ParameterSetName -eq "PS_IP_Range")
  {
    $requestFormat = @{
      "tag_id" = "INTERNET"
      "ip_address_ranges" = @( @{
        "start_ip" = $IP_Range_Start
        "end_ip" = $IP_Range_End
      } )
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $results = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/settings/ip-tags/INTERNET/add" -Body $requestBody
  return $results
}

function Remove-vRNINorthSouthIP
{
  <#
  .SYNOPSIS
  Remove a North-South IP mapping within vRealize Network Insight.

  .DESCRIPTION
  vRealize Network Insight collects netflow data and analyses the
  network flows. If you are using internal IPs outside the datacenter,
  you should add them to the North-South IP mappings.

  .EXAMPLE
  PS C:\> Remove-vRNINorthSouthIP -Subnet 80.182.12.0/24

  .EXAMPLE
  PS C:\> Remove-vRNINorthSouthIP -IP_Range_Start 90.23.12.1 -IP_Range_End 90.23.12.100

  #>
  param (
    [Parameter (Mandatory=$true, ParameterSetName="PS_Subnet")]
      # The subnet to remove from the IP mappings
      [string]$Subnet,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range start to remove from the IP mappings
      [string]$IP_Range_Start,
    [Parameter (Mandatory=$true, ParameterSetName="PS_IP_Range")]
      # The IP range end to remove from the IP mappings
      [string]$IP_Range_End,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Format request with all given data
  $requestFormat = ""
  if($PSCmdlet.ParameterSetName -eq "PS_Subnet")
  {
    $requestFormat = @{
      "tag_id" = "INTERNET"
      "subnets" = @($Subnet)
    }
  }
  if($PSCmdlet.ParameterSetName -eq "PS_IP_Range")
  {
    $requestFormat = @{
      "tag_id" = "INTERNET"
      "ip_address_ranges" = @( @{
        "start_ip" = $IP_Range_Start
        "end_ip" = $IP_Range_End
      } )
    }
  }

  # Convert the hash to JSON, form the URI and send the request to vRNI
  $requestBody = ConvertTo-Json $requestFormat
  $results = Invoke-vRNIRestMethod -Connection $Connection -Method POST -Uri "/api/ni/settings/ip-tags/INTERNET/remove" -Body $requestBody
  return $results
}

function Get-vRNIAuditLogs
{
  <#
  .SYNOPSIS
  Retrieve audit logs from Network Insight

  .DESCRIPTION
  Network Insight logs the actions that are being executed on its interface,
  and this endpoint is a way to retrieve the audit log


  .EXAMPLE
  PS C:\> Get-vRNIAuditLogs

  .EXAMPLE
  PS C:\> Get-vRNIAuditLogs -Username "admin@local"

  .EXAMPLE
  PS C:\> Get-vRNIAuditLogs -Operation "LOGIN"

  #>
  param (
    [Parameter (Mandatory=$false)]
      # Filter on username
      [string]$Username = "",
    [Parameter (Mandatory=$false)]
      # Filter on a specific operation (like LOGIN, UPDATE)
      [string]$Operation = "",
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

  # A list to collect the log records in
  $logs = [System.Collections.ArrayList]@()

  # Initialise the body
  $body = @{
    size =  50
  }

  # Filter on specific details, if given via params
  if($Username -ne "") {
    $body['username'] = $Username
  }
  if($Operation -ne "") {
    $body['operation'] = $Operation
  }

  # Add a time range, if specified in the params
  if($PSCmdlet.ParameterSetName -eq "TIMELIMIT" -And ($StartTime -gt 0 -And $EndTime -gt 0)) {
    $body['time_range'] = @{
      start_time = $StartTime
      end_time = $EndTime
    }
  }

  # Initialise the RestMethod params
  $listParams = @{
    Connection = $Connection
    Method = 'POST'
    Uri = "/api/ni/logs/audit"
    Body = $body | ConvertTo-Json
  }

  # Loop through the log pages, as it uses pagination to return only a restrict set
  $hasMoreData = $true
  $counter = 0
  while ($hasMoreData)
  {
    $logsResponse = Invoke-vRNIRestMethod @listParams

    Write-Verbose ("$($logsResponse.total_count) logs to process")
    if ($logsResponse.total_count -gt $size) {
      $body['cursor'] = $logsResponse.cursor
      $listParams['Body'] = $body | ConvertTo-Json
    }

    # Save results
    foreach($log_record in $logsResponse.results)
    {
      $logs.Add($log_record) | Out-Null
      $counter++
    }

    $remaining = $logsResponse.total_count - $counter
    if ($remaining -gt 0) {
      Write-Verbose "$remaining more logs to process"
      $hasMoreData = $true
    }
    else {
      $hasMoreData = $false
    }
  }

  $logs
}



#####################################################################################################################
#####################################################################################################################
#######################################  vIDM Settings Management ###################################################
#####################################################################################################################
#####################################################################################################################

function Get-vRNISettingsVIDM
{
  <#
  .SYNOPSIS
  Retrieve vIDM settings from Network Insight

  .DESCRIPTION
  VMware Identity Manager (vIDM) can be used for authentication within
  vRNI. vIDM offers more authentication & authorization options like
  multi-factor, location dependent, etc. This cmdlet retrieves the vIDM
  settings.

  .EXAMPLE
  PS C:\> Get-vRNISettingsVIDM

  #>
  param (
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $result = Invoke-vRNIRestMethod -Connection $Connection -Method "GET" -Uri "/api/ni/settings/vidm"
  $result
}

function Set-vRNISettingsVIDM
{
  <#
  .SYNOPSIS
  Retrieve vIDM settings from Network Insight

  .DESCRIPTION
  VMware Identity Manager (vIDM) can be used for authentication within
  vRNI. vIDM offers more authentication & authorization options like
  multi-factor, location dependent, etc. This cmdlet configures the
  vIDM settings.

  .EXAMPLE
  PS C:\> Get-vRNISettingsVIDM -Appliance my-vidm-appliance -ClientID vRNI -ClientSecret longstring

  #>
  param (
    [Parameter (Mandatory=$true)]
      # vIDM Appliance hostname
      [string]$Appliance,
    [Parameter (Mandatory=$true)]
      # vIDM OAuth2 Client ID
      [string]$ClientID,
    [Parameter (Mandatory=$true)]
      # vIDM OAuth2 Client Secret
      [string]$ClientSecret,
    [Parameter (Mandatory=$false)]
      # Optional vIDM OAuth2 SHA Thumbprint
      [string]$SHA_Thumbprint = "",
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Initialise the body
  $body = @{
    vidm_appliance = $Appliance
    client_id = $ClientID
    client_secret = $ClientSecret
    sha_thumbprint = $SHA_Thumbprint
    enable = $true
  }

  # Initialise the RestMethod params
  $listParams = @{
    Connection = $Connection
    Method = 'POST'
    Uri = "/api/ni/settings/vidm"
    Body = $body | ConvertTo-Json
  }

  $result = Invoke-vRNIRestMethod @listParams
  $result
}

function Get-vRNISettingsUserGroup
{
  <#
  .SYNOPSIS
  Retrieve user groups settings from Network Insight

  .DESCRIPTION
  User groups from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet gets the
  current mappings.

  The public API currently only supports the VIDM type.

  .EXAMPLE
  PS C:\> Get-vRNISettingsUserGroups -Type VIDM

  #>
  param (
    [Parameter (Mandatory=$true)]
      [ValidateSet ("LDAP", "LOCAL", "VIDM")]
      # Group type; where is the group from?
      [string]$Type,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $result = Invoke-vRNIRestMethod -Connection $Connection -Method "GET" -Uri "/api/ni/settings/user-groups?type=$($Type)"
  $result.results
}

function Set-vRNISettingsUserGroup
{
  <#
  .SYNOPSIS
  Configure user group role mappings.

  .DESCRIPTION
  User groups from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet configures
  a group to role mapping.

  .EXAMPLE
  PS C:\> Set-vRNISettingsVIDMUserGroup -Type VIDM -Group vrni-admins -Domain mylab.local -Role ADMIN
  Map group 'vrni-admins' in vIDM to the vRNI ADMIN role

  .EXAMPLE
  PS C:\> Set-vRNISettingsVIDMUserGroup -Type VIDM -Group vrni-members -Domain mylab.local -Role MEMBER
  Map group 'vrni-members' in vIDM to the vRNI MEMBER role

  #>
  param (
    [Parameter (Mandatory=$true)]
      # Type user group (only VIDM supported for now)
      [ValidateSet ("VIDM")]
      [string]$Type,
    [Parameter (Mandatory=$true)]
      # Name of the group in vIDM
      [string]$Group,
    [Parameter (Mandatory=$true)]
      # Domain in vIDM that this group belongs to
      [string]$Domain,
    [Parameter (Mandatory=$true)]
      # Role that this group will get in vRNI
      [ValidateSet ("ADMIN", "MEMBER")]
      [string]$Role,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Initialise the body
  $body = @{
    group_name = $Group
    domain = $Domain
    role = $Role
  }

  # Initialise the RestMethod params
  $listParams = @{
    Connection = $Connection
    Method = 'POST'
    Uri = "/api/ni/settings/user-groups/vidm"
    Body = $body | ConvertTo-Json
  }

  $result = Invoke-vRNIRestMethod @listParams
  $result
}

function Remove-vRNISettingsUserGroup
{
  <#
  .SYNOPSIS
  Removes a user group mapping from vRealize Network Insight

  .DESCRIPTION
  User groups from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet removes
  a group to role mapping.

  .EXAMPLE
  PS C:\> Get-vRNISettingsUserGroup | Where {$_.group_name -eq "mygroup"} | Remove-vRNISettingsUserGroup

  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNISettingsUserGroup
      [ValidateNotNullOrEmpty()]
      [PSObject]$Group,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  process {
    $Group | Foreach-Object {
      $oThisGroup = $_
      # All we have to do is to send a DELETE request to URI /api/ni/settings/user-groups/$groupId, so
      # form the URI and send the DELETE request to vRNI
      $URI = "/api/ni/settings/user-groups/$($oThisGroup.id)"

      Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -Uri $URI
    } ## end Foreach-Object
  } ## end process
}

function Get-vRNISettingsUser
{
  <#
  .SYNOPSIS
  Retrieve users role mappings from Network Insight

  .DESCRIPTION
  Users from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet gets the
  current mappings.

  The public API currently only supports the VIDM type.

  .EXAMPLE
  PS C:\> Get-vRNISettingsUser -Type VIDM

  #>
  param (
    [Parameter (Mandatory=$true)]
      [ValidateSet ("LDAP", "LOCAL", "VIDM")]
      # User type; where is the group from?
      [string]$Type,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  $result = Invoke-vRNIRestMethod -Connection $Connection -Method "GET" -Uri "/api/ni/settings/users?type=$($Type)"
  $result.results
}

function Set-vRNISettingsUser
{
  <#
  .SYNOPSIS
  Configure a user role mapping from Network Insight

  .DESCRIPTION
  Users from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet configures
  a new mapping

  The public API currently only supports the VIDM type.

  .EXAMPLE
  PS C:\> Set-vRNISettingsUser -Type VIDM -Username martijn -Domain mylab.local -Role ADMIN

  .EXAMPLE
  PS C:\> Set-vRNISettingsUser -Type VIDM -Username visitor -Domain mylab.local -Role MEMBER

  #>
  param (
    [Parameter (Mandatory=$true)]
      # Type user group (only VIDM supported for now)
      [ValidateSet ("VIDM")]
      [string]$Type,
    [Parameter (Mandatory=$true)]
      # Username in vIDM
      [string]$Username,
    [Parameter (Mandatory=$true)]
      # Domain in vIDM that this user belongs to
      [string]$Domain,
    [Parameter (Mandatory=$true)]
      # Role that this user will get in vRNI
      [ValidateSet ("ADMIN", "MEMBER")]
      [string]$Role,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Initialise the body
  $body = @{
    username = $Username
    domain = $Domain
    role = $Role
    display_name = $Username
  }

  # Initialise the RestMethod params
  $listParams = @{
    Connection = $Connection
    Method = 'POST'
    Uri = "/api/ni/settings/users/vidm"
    Body = $body | ConvertTo-Json
  }

  $result = Invoke-vRNIRestMethod @listParams
  $result
}


function Set-vRNIUserPassword
{
  <#
  .SYNOPSIS
  Change the password of a local user to Network Insight

  .DESCRIPTION
  Local users have a password configured inside Network Insight.
  This cmdlet allows admins to set passwords of existing users, and
  allow member to set their own passwords.

  .EXAMPLE
  PS C:\> Set-vRNIUserPassword -Username admin@local -NewPassword 'mynewpassword'

  .EXAMPLE
  PS C:\> Set-vRNIUserPassword -Username admin@local
  PowerShell credential request
  Input the new password
  Password for user test@local.corp: ********

  .EXAMPLE
  PS C:\> $new_cred = Get-Credential

  PowerShell credential request
  Enter your credentials.
  User: test@local.corp
  Password for user test@local.corp: ***********
  PS C:\>  Set-vRNIUserPassword -Credentials $new_cred
  #>
  param (
    [Parameter (Mandatory=$false)]
      # Username in 'admin@local' format
      [string]$Username,
    [Parameter (Mandatory=$false)]
      # Their new password
      [string]$NewPassword,
    [Parameter (Mandatory=$false)]
      # PSCredential object containing credentials to update
      [PSCredential]$Credential,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  # Make sure either -Credential is set, or both -Username and -Password
  if(($PsBoundParameters.ContainsKey("Credential") -And $PsBoundParameters.ContainsKey("Username")) -Or
     ($PsBoundParameters.ContainsKey("Credential") -And $PsBoundParameters.ContainsKey("NewPassword")))
  {
    throw "Specify either -Credential or -Username to pass the new password (if using -Username and omitting -NewPassword, a prompt will be given)"
  }

  # Build cred object for default auth if user specified username/pass
  $user_credentials = ""
  if($PsBoundParameters.ContainsKey("Username"))
  {
    # Is the -Password omitted? Prompt securely
    if(!$PsBoundParameters.ContainsKey("NewPassword")) {
      $user_credentials = Get-Credential -UserName $Username -Message "Input the new password"
    }
    # If the password has been given in cleartext,
    else {
      $user_credentials = New-Object System.Management.Automation.PSCredential($Username, $(ConvertTo-SecureString $NewPassword -AsPlainText -Force))
    }
  }
  # If a credential object was given as a parameter, use that
  elseif($PSBoundParameters.ContainsKey("Credential"))
  {
    $user_credentials = $Credential
  }
  # If no -Username or -Credential was given, prompt for credentials
  elseif(!$PSBoundParameters.ContainsKey("Credential")) {
    $user_credentials = Get-Credential -Message "Input the username and new password"
  }

  # Initialise the body
  $body = @{
    "username" = $user_credentials.Username
    "new_password" = $user_credentials.GetNetworkCredential().Password
  }

  # Initialise the RestMethod params
  $listParams = @{
    Connection = $Connection
    Method = 'PUT'
    Uri = "/api/ni/settings/users/password"
    Body = $body | ConvertTo-Json
  }

  $result = Invoke-vRNIRestMethod @listParams
  $result
}

function Remove-vRNISettingsUser
{
  <#
  .SYNOPSIS
  Remove a user role mapping from Network Insight

  .DESCRIPTION
  Users from AD, VIDM or LOCAL can be mapped to vRNI
  member roles (ADMIN or MEMBER) and this cmdlet removes
  a mapping

  The public API currently only supports the VIDM type.

  .EXAMPLE
  PS C:\> Get-vRNISettingsUser | Where {$_.username -eq "martijn"} | Remove-vRNISettingsUser

  #>

  param (
    [Parameter (Mandatory=$true, ValueFromPipeline=$true, Position=1)]
      # Datasource object, gotten from Get-vRNISettingsUser
      [ValidateNotNullOrEmpty()]
      [PSObject]$User,
    [Parameter (Mandatory=$False)]
      # vRNI Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRNIConnection
  )

  process {
    $User | Foreach-Object {
      $oThisUser = $_
      # All we have to do is to send a DELETE request to URI /api/ni/settings/users/$userId, so
      # form the URI and send the DELETE request to vRNI
      $URI = "/api/ni/settings/users/$($oThisUser.id)"

      Invoke-vRNIRestMethod -Connection $Connection -Method DELETE -Uri $URI
    } ## end Foreach-Object
  } ## end process
}


function New-DynamicParameter {
<#
  .NOTES
  Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
      https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
      http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
      http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/

  #>
  [CmdletBinding(PositionalBinding = $false, DefaultParameterSetName = 'DynamicParameter')]
  Param
  (
      [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateNotNullOrEmpty()]
      [string]$Name,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [System.Type]$Type = [int],

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [string[]]$Alias,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$Mandatory,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [int]$Position,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [string]$HelpMessage,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$DontShow,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$ValueFromPipeline,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$ValueFromPipelineByPropertyName,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$ValueFromRemainingArguments,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [string]$ParameterSetName = '__AllParameterSets',

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$AllowNull,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$AllowEmptyString,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$AllowEmptyCollection,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$ValidateNotNull,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [switch]$ValidateNotNullOrEmpty,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateCount(2, 2)]
      [int[]]$ValidateCount,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateCount(2, 2)]
      [int[]]$ValidateRange,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateCount(2, 2)]
      [int[]]$ValidateLength,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateNotNullOrEmpty()]
      [string]$ValidatePattern,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateNotNullOrEmpty()]
      [scriptblock]$ValidateScript,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateNotNullOrEmpty()]
      [string[]]$ValidateSet,

      [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
      [ValidateNotNullOrEmpty()]
      [ValidateScript( {
              if (!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary])) {
                  Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
              }
              $true
          })]
      $Dictionary = $false,

      [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
      [switch]$CreateVariables,

      [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
      [ValidateNotNullOrEmpty()]
      [ValidateScript( {
              # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
              # so one can't use PowerShell's '-is' operator to validate type.
              if ($_.GetType().Name -ne 'PSBoundParametersDictionary') {
                  Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
              }
              $true
          })]
      $BoundParameters
  )

  Begin {
      Write-Verbose 'Creating new dynamic parameters dictionary'
      $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

      Write-Verbose 'Getting common parameters'
      function _temp { [CmdletBinding()] Param() }
      $CommonParameters = (Get-Command _temp).Parameters.Keys
  }

  Process {
      if ($CreateVariables) {
          Write-Verbose 'Creating variables from bound parameters'
          Write-Debug 'Picking out bound parameters that are not in common parameters set'
          $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }

          foreach ($Parameter in $BoundKeys) {
              Write-Debug "Setting existing variable for dynamic parameter '$Parameter' with value '$($BoundParameters.$Parameter)'"
              Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
          }
      }
      else {
          Write-Verbose 'Looking for cached bound parameters'
          Write-Debug 'More info: https://beatcracker.wordpress.com/2014/12/18/psboundparameters-pipeline-and-the-valuefrompipelinebypropertyname-parameter-attribute'
          $StaleKeys = @()
          $StaleKeys = $PSBoundParameters.GetEnumerator() |
              ForEach-Object {
              if ($_.Value.PSobject.Methods.Name -match '^Equals$') {
                  # If object has Equals, compare bound key and variable using it
                  if (!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                      $_.Key
                  }
              }
              else {
                  # If object doesn't has Equals (e.g. $null), fallback to the PowerShell's -ne operator
                  if ($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                      $_.Key
                  }
              }
          }
          if ($StaleKeys) {
              [string[]]"Found $($StaleKeys.Count) cached bound parameters:" + $StaleKeys | Write-Debug
              Write-Verbose 'Removing cached bound parameters'
              $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
          }

          # Since we rely solely on $PSBoundParameters, we don't have access to default values for unbound parameters
          Write-Verbose 'Looking for unbound parameters with default values'

          Write-Debug 'Getting unbound parameters list'
          $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
              # Find parameters that are belong to the current parameter set
          Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
              Select-Object -ExpandProperty Key |
              # Find unbound parameters in the current parameter set
                                              Where-Object { $PSBoundParameters.Keys -notcontains $_ }

          # Even if parameter is not bound, corresponding variable is created with parameter's default value (if specified)
          Write-Debug 'Trying to get variables with default parameter value and create a new bound parameter''s'
          $tmp = $null
          foreach ($Parameter in $UnboundParameters) {
              $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
              if (!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                  $PSBoundParameters.$Parameter = $DefaultValue
                  Write-Debug "Added new parameter '$Parameter' with value '$DefaultValue'"
              }
          }

          if ($Dictionary) {
              Write-Verbose 'Using external dynamic parameter dictionary'
              $DPDictionary = $Dictionary
          }
          else {
              Write-Verbose 'Using internal dynamic parameter dictionary'
              $DPDictionary = $InternalDictionary
          }

          Write-Verbose "Creating new dynamic parameter: $Name"

          # Shortcut for getting local variables
          $GetVar = {Get-Variable -Name $_ -ValueOnly -Scope 0}

          # Strings to match attributes and validation arguments
          $AttributeRegex = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
          $ValidationRegex = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
          $AliasRegex = '^Alias$'

          Write-Debug 'Creating new parameter''s attirubutes object'
          $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute

          Write-Debug 'Looping through the bound parameters, setting attirubutes...'
          switch -regex ($PSBoundParameters.Keys) {
              $AttributeRegex {
                  Try {
                      $ParameterAttribute.$_ = . $GetVar
                      Write-Debug "Added new parameter attribute: $_"
                  }
                  Catch {
                      $_
                  }
                  continue
              }
          }

          if ($DPDictionary.Keys -contains $Name) {
              Write-Verbose "Dynamic parameter '$Name' already exist, adding another parameter set to it"
              $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
          }
          else {
              Write-Verbose "Dynamic parameter '$Name' doesn't exist, creating"

              Write-Debug 'Creating new attribute collection object'
              $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]

              Write-Debug 'Looping through bound parameters, adding attributes'
              switch -regex ($PSBoundParameters.Keys) {
                  $ValidationRegex {
                      Try {
                          $ParameterOptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                          $AttributeCollection.Add($ParameterOptions)
                          Write-Debug "Added attribute: $_"
                      }
                      Catch {
                          $_
                      }
                      continue
                  }

                  $AliasRegex {
                      Try {
                          $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                          $AttributeCollection.Add($ParameterAlias)
                          Write-Debug "Added alias: $_"
                          continue
                      }
                      Catch {
                          $_
                      }
                  }
              }

              Write-Debug 'Adding attributes to the attribute collection'
              $AttributeCollection.Add($ParameterAttribute)

              Write-Debug 'Finishing creation of the new dynamic parameter'
              $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)

              Write-Debug 'Adding dynamic parameter to the dynamic parameter dictionary'
              $DPDictionary.Add($Name, $Parameter)
          }
      }
  }

  End {
      if (!$CreateVariables -and !$Dictionary) {
          Write-Verbose 'Writing dynamic parameter dictionary to the pipeline'
          $DPDictionary
      }
  }
}
# Call Init function
_PvRNI_init
