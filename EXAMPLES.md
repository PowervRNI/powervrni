# PowervRNI - Examples
## examples/application-bulk-import.ps1
### Adding applications in bulk
This script uses an input CSV (example: application-bulk-import.csv) to add multiple vRealize Network Insight Applications. Modify application-bulk-import.csv to contain your applications and application tiers, along with either the NSX Security Group or the VM names. Then run this script with the param -ApplicationsCSV to your CSV.
## examples/cmdb-import-from-itop.ps1
### Import Applications from iTop
Retrieves applications from the CMDB iTop, and imports them into vRNI.
## examples/cmdb-import-from-servicenow.ps1
### Import Applications from ServiceNow
Retrieves applications from the CMDB ServiceNow, and imports them into vRNI. Note: is now a native vRNI feature, the script is still here to serve as an example.
## examples/datasource-bulk-import.ps1
### Adding datasources in bulk
This script uses an input CSV (example: datasource-bulk-import.csv) to add multiple vRealize Network Insight Data Sources. Modify datasource-bulk-import.csv to contain your own data sources (vCenters, NSX, switches, firewalls) and run this script with the param -DatasourcesCSV to your CSV.
## examples/datasource-bulk-set-snmp.ps1
### Changing SNMP configs of multiple switch devices
This script uses an input CSV (example: datasource-bulk-snmp.csv) to configure multiple vRealize Network Insight Data Sources SNMP Values. Modify datasource-bulk-snmp.csv to contain your own data sources and run this script with the param -DatasourcesCSV to your CSV. Based off Martijn Smit bulk data source import script.
## examples/export-flows.ps1
### Exporting network flows
This script outputs flows in a certain time range.
## examples/get-bandwidth-usage-per-ip.ps1
### Billing Use Case
Gets a list of IPs with their respective bandwidth usage, which can be used for billing purposes (ISPs).
## examples/archive-flows-to-vrli/vrni-archive-flows-to-vrli.ps1
### Archiving vRealize Network Insight flows to vRealize Log Insight
This script connects to vRNI, retrieves the flows within a time window (the last time this script was run and now), then checks whether the flow is located in the cache (more info in comments of cache code), and if not, gathers metadata (VM & L2 network name), and finally sends the flow to vRLI using Send-vRLIMessage from vrealize-log-insight.ps1
