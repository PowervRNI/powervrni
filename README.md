# PowervRNI

*A PowerShell module for vRealize Network Insight*

Starting vRealize Network Insight (vRNI) 3.6, the platform has a public API. PowervRNI is a PowerShell module that takes advantage of those public APIs and provides you with the option to look at vRNI data using PowerShell. 


This module is _not supported_ by VMware, and comes with no warranties express or implied. Please test and validate its functionality before using this product in a production environment.

## Installing PowervRNI


There are 2 ways of installing PowervRNI. An easy one through PowerShell Gallery where everything is taken care of for you, or a slightly harder one where you download the module and load it up manually.

### PowerShell Gallery

```
PS C:\> Install-Module PowervRNI
PS C:\> Import-Module PowervRNI
```

That's it, you're off the the races.

### Manual Download

Right now, PowervRNI is a simple two-file module. To install it, download it to a PowerShell enabled machine and load it. PowervRNI is supported for PowerShell Desktop & Core, so Windows, MacOS and Linux. Here is an example on how to load it:

```
PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/powervrni/powervrni/master/PowervRNI.psm1" -OutFile "PowervRNI.psm1" 
PS C:\> Invoke-WebRequest -Uri "https://raw.githubusercontent.com/powervrni/powervrni/master/PowervRNI.psd1" -OutFile "PowervRNI.psd1" 
PS C:\> Import-Module .\PowervRNI.psd1
```

## Usage

A more elaborate usage guide will follow, but here's a quick example on how to get started.

### Connection to the vRNI Platform VM

The API of vRNI requires you to login to the Platform VM first. Here's how:

```
PS C:\> Connect-vRNIServer -Server vrni-platform.lab -Username admin@local -Password VMware1!
```

or, if you'd like the system to ask you for your credentials (and not pass them in cleartext)

```
PS C:\> Connect-vRNIServer -Server vrni-platform.lab
```

### Getting Started

After logging in and starting a session, you can start doing information calls to vRNI. To see what kind of cmdlets PowervRNI offers and what information you can get out of vRNI with it, use the following command:

```
PS C:\> Get-Command -Module PowervRNI                                                                                                                                                        ```
```

You'll see that there are a bunch of cmdlets you can use. To give you an example of what kind of output PowervRNI produces, here's an example from my lab:

```
PS C:\>  Get-vRNIHost 

entity_id        : 14207:4:204319385
name             : esxi03.lab
entity_type      : Host
vmknics          : {@{entity_id=14307:17:1822450329; entity_type=Vmknic}, @{entity_id=14307:17:1827250360; entity_type=Vmknic}, @{entity_id=14307:17:1827250298; entity_type=Vmknic}}
cluster          : @{entity_id=14307:66:1217795335; entity_type=Cluster}
vcenter_manager  : @{entity_id=14307:8:5696601749271539863; entity_type=VCenterManager}
vm_count         : 20
datastores       : {@{entity_id=14307:80:1083140774; entity_type=Datastore}, @{entity_id=14307:80:1082389334; entity_type=Datastore}, @{entity_id=14307:80:1860142552; entity_type=Datastore}}
service_tag      : 
vendor_id        : host-2921
nsx_manager      : @{entity_id=14307:7:1483719682; entity_type=NSXVManager}
maintenance_mode : NOTINMAINTENANCEMODE
connection_state : CONNECTED

entity_id        : 14307:4:1142332887
```

More examples are available in the examples/ directory and [here](https://lostdomain.org/tag/powervrni/)


## Contact

Currently, [@smitmartijn](https://twitter.com/smitmartijn) started this project and will keep maintaining it. Reach out to me via twitter or the [Issues Page](https://github.com/powervrni/powervrni/issues) here on GitHub. If you want to contribute, also get in touch with me.


## Is PowervRNI supported by VMware?

No. This is an opensource project started by [@smitmartijn](https://twitter.com/smitmartijn) and not supported by VMware. Please test and validate its functionality before using in a production environment.


## License

PowervRNI is licensed under GPL v2.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 2, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTIBILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License version 2 for more details.

You should have received a copy of the General Public License version 2 along with this program.
If not, see https://www.gnu.org/licenses/gpl-2.0.html.

The full text of the General Public License 2.0 is provided in the COPYING file.
Some files may be comprised of various open source software components, each of which
has its own license that is located in the source code of the respective component.