## ChangeLog

### v1.0.35
- \[enhancement] added a bit to some ErrorMessage output in `Invoke-vRNIRestMethod`, and updated to throw actual `ErrorRecord` object in catch situation (to enable deeper debugging by user)
- \[bugfix] updated remaining functions that take value from pipeline to handle multiple objects from pipeline (`Remove-vRNIApplication`, `New-vRNIApplicationTier`, `Remove-vRNIApplicationTier`, `Disable-vRNIDataSource`, `Enable-vRNIDataSource`, `Remove-vRNIDataSource`)

