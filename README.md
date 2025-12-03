# VirtualGHOST

![CrowdStrike Logo](./docs/asset/cs-logo.png)

[![Twitter URL](https://img.shields.io/twitter/url?label=Follow%20%40CrowdStrike&style=social&url=https%3A%2F%2Ftwitter.com%2FCrowdStrike)](https://twitter.com/CrowdStrike)

This repository contains tools developed by the CrowdStrike Professional Services team to detect the presence of "VirtualGHOSTs" in a VMware vSphere environment. A "VirtualGHOST" (or just Ghost) is a VMware Virtual Machine on an ESXi host that has been powered on manually from the command line. CrowdStrike decided to call this particular technique VirtualGHOST since it's a Virtual Machine whose presence is nearly impossible to detect. Some of the tooling will go beyond only searching for VirtualGHOSTs and will also review vCenter events for evidence of suspicious activity.

## Tooling Compared

As CrowdStrike has continued to observe usage of the VirtualGHOST technique in the wild, multiple tools have been developed to assist with the identification of VirtualGHOST VMs. This table outlines some of the key differences of the tooling developed so far.

|Function / Feature|Detect-VirtualGHOST|GHOSTHUNTER|
|----|----|----|
|**Language**|PowerShell|Python|
|**Target System(s)**|ESXi or vCenter|vCenter Only|
|**Detect Running Ghost VMs**|:heavy_check_mark:|:wavy_dash: (Not specifically, but will see presence of it on the datastore)|
|**Detect Ghost VMs Still Present On Datastore But Not Necessarily Running**|:x:|:heavy_check_mark:|
|**Review vCenter Events for Suspicious Activity**|:x:|:heavy_check_mark:|

## Detect-VirtualGHOST (PowerShell)

The original tool in this repository, [Detect-VirtualGHOST](Detect-VirtualGHOST.ps1), is a PowerShell script leveraging [VMware PowerCLI](https://developer.broadcom.com/tools/vmware-powercli/latest) to identify unregistered VMware Virtual Machines (VMs) that are powered on by comparing the list of VMs registered in the inventory (vCenter or ESXi) vs. those that are powered on.

> [!WARNING]
> CrowdStrike has observed Threat Actors attempting to masquerade their Ghost VMs as VMware vSphere Cluster Services VMs. These have names starting with the value `vCLS` with a dash separated randomly generated string. Be aware that vCLS VMs should **not** have a network interface attached.

Detailed guidance for execution & output interpretation is available [in the Detect-VirtualGHOST documentation](./docs/Detect-VirtualGHOST.md).

## GHOSTHUNTER (Python)

CrowdStrike has developed a Python script that leverages [pyVmomi](https://github.com/vmware/pyvmomi/tree/master) (the Python SDK for the VMware vSphere Management API) to triage vCenter Servers for signs of suspicious activity. It is designed to complement the original PowerShell script that CrowdStrike previously created to identify the presence of VirtualGHOST VMs.

The script was tested using Python 3.13 against vCenter 8. It requires two Python modules which can be installed
using Python's default package manager pip:

- requests
- pyvmomi

Detailed guidance for execution & output interpretation is available [in the GHOSTHUNTER documentation](./docs/GHOSTHUNTER.md).

## Next Steps

If a VirtualGHOST is identified, the team should attempt to collect a forensic image as soon as possible. CrowdStrike has observed Threat Actors leveraging this technique to regularly delete the Ghost VM as soon as it is no longer actively being used.

### Imaging / Investigation of a VirtualGHOST

Because the VirtualGHOST is not in the VM inventory, it cannot be managed by standard VMware processes like vCenter or the ESXi web UI. To collect a forensic image and VM log files of a running VirtualGHOST, follow these steps:

- Enable SSH on the ESXi host with the VirtualGHOST VM (this is required because the Datastore browser may not allow you to copy all of the files related to the VirtualGHOST as some of them will be locked)
- Connect to the ESXi host over SSH
- Copy all files in the VirtualGHOST's directory to a different location (understanding that some files will be locked)
  - Typically there is only one Virtual Machine definition (`.vmx`) file per directory - so navigate to the parent directory of the `VMConfigFile` returned by the detection script
- Register running VirtualGHOST VM in ESXi UI using standard Create/Register VM interface ([Documentation Link](https://knowledge.broadcom.com/external/article?legacyId=1006160))
- Open newly registered VM in ESXi web UI
- Expand all VM menus and capture screenshots for investigative purposes (this can make the job of mapping back specific VM configurations easier)
- Suspend newly registered VM via ESXi web UI
- Copy all files in VM directory to a separate location (noting that this was after registration)

:bulb: The `vmware*.log` files stored in the VM directory will be **extremely** valuable for your investigation, so don't forget to grab/review them!

## Support

As free, as-is tool this software is not officially supported by CrowdStrike. As such we ask that you please refrain from sending inquiries to the CrowdStrike support team. The project maintainers will be working with active community contributors to address bugs and supply new features. If you have identified a bug please [submit an issue through GitHub](https://github.com/CrowdStrike/VirtualGHOST/issues/new).