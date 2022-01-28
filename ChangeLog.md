## ChangeLog

### v6.5 - 2022-01-28

@smitmartijn:

- \[new] Match PowervRNI version to indicate support for vRNI versions
- \[new] Support for NSXALB Data Source (NSX Advanced Load Balancer)
- \[new] New message groups for the databus subscriber: flows, metrics, VMs, hosts, NICs, switchports
- \[new] Get-vRNISDDCGroup
- \[new] Get-vRNIVMCDirectConnect
- \[new] Get-vRNIVMCDirectConnectInterface
- \[new] Get-vRNISwitchPort
- \[new] Get-vRNILogicalRouter
- \[new] Get-vRNIVMwareTransitGateway
- \[new] Get-vRNINSXTIPsecVPNSessions
- \[new] Get-vRNISettingsLoginBanner
- \[new] Set-vRNISettingsLoginBanner
- \[new] Remove-vRNISettingsLoginBanner

### v2.0 - 2021-10-05

@smitmartijn:

- \[new] Connect-NIServer: Add support for vRNI Cloud locations by adding the -Location parameter
- \[new] New-vRNIDataSource: Add support for Cisco ASR and ISR models (types: CISCOASRISR, CISCOASR1000, CISCOISR4000)
- \[new] Get-vRNISDDC: New cmdlet to retrieve SDDC objects
- \[new] Get-vRNIDatabusSubscriber: New cmdlet to retrieve all databus subscribers
- \[new] New-vRNIDatabusSubscriber: New cmdlet to create a databus subscriber
- \[new] Remove-vRNIDatabusSubscriber: New cmdlet to remove a databus subscriber

### v1.9 - 2021-07-09

@smitmartijn:

- \[new] Add cmdlet Update-vRNIDataSource to update data source details (credentials, nickname, notes)
- \[new] Add cmdlet Invoke-vRNISearch to run search queries. Example: Invoke-vRNISearch -Query “VM where CPU Count > 2”
- \[new] Add data source support for: AWS, Mellanox, Cisco ASR/XR, VMware HCX, HPE Switches
- \[new] Add support for Custom polling intervals
- \[new] Add support for Enabling IPFIX on vCenter VDS when adding 
- \[new] Add support for Platform Backup Management. New cmdlets: Get-vRNIBackup, Get-vRNIBackupStatus, Remove-vRNIBackup, Enable-vRNIBackup, Disable-vRNIBackup, Set-vRNIBackup
- \[new] Add support for License Management. New cmdlets: Get-vRNILicensing, Test-vRNILicensing, Install-vRNILicensing, Remove-vRNILicensing

### v1.4 - 2018-10-13

@smitmartijn:

- \[new] Add cmdlet Get-vRNIRecommendedRulesNsxBundle to download a zip file with the recommended firewall rules which can be used by the Importer Tool to send the firewall rules to NSX
- \[bug-fix] Fix a random connection issue to on-prem vRNI by fixing the on-prem vs SaaS detection

### v1.3

@smitmartijn:

- \[new] Add Connect-NIServer to connect to the Network Insight as a Service on the VMware Cloud Services.

### v1.2

@smitmartijn:

- \[new] Add Get-vRNIDataSourceSNMPConfig and Set-vRNIDataSourceSNMPConfig to retrieve and configure SNMP settings for certain data sources
- \[fix] Fixed New-vRNIDataSource when using a Cisco or Dell switch type (it didn't add the required switch type API value)

### v1.1

@smitmartijn:

- \[new] Execute Get-vRNIAPIVersion when using Connect-vRNIServer and store API version for further use
- \[new] Use the /entities/fetch endpoint when API v1.1.0 is available to significantly speed up entity results
- \[new] Use the /groups/applications/fetch endpoint when API v1.1.0 is available to significantly speed up application results (5500% faster on 400 applications)
- \[enhancement] Use the /search endpoint when looking for a single entity (not just VMs), speeding up the execution time
- \[enhancement] Make sure Invoke-vRNIRestMethod takes a 100ms break before running to prevent API throttling (error 429)

@awickham10:

- \[enhancement] Use /search endpoint when looking for a single VM, speeding up the execution time

@mtboren:
- \[enhancement] Added a bit to some ErrorMessage output in `Invoke-vRNIRestMethod`, and updated to throw actual `ErrorRecord` object in catch situation (to enable deeper debugging by user)
- \[bugfix] Updated remaining functions that take value from pipeline to handle multiple objects from pipeline (`Remove-vRNIApplication`, `New-vRNIApplicationTier`, `Remove-vRNIApplicationTier`, `Disable-vRNIDataSource`, `Enable-vRNIDataSource`, `Remove-vRNIDataSource`)

