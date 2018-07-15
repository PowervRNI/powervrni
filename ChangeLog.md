## ChangeLog

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

