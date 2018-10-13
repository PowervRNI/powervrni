## ChangeLog

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

