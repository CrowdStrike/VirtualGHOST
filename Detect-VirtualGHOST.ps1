#Requires -Version 3
<#
.SYNOPSIS
    Identify unregistered VMWare Virtual Machines running on ESXi hypervisors
.DESCRIPTION
    PowerShell script to identify unregistered VMWare Virtual Machines (VMs) that are powered on by comparing the list of VMs registered in the inventory (vCenter or ESXi) vs. those that are powered on via PowerCLI. Matching is performed by examining the 128-bit SMBIOS UUID of a virtual machine. Using the identifier should prevent situations where a duplicate VM Displayname is used to blend in. This particular technique has been given the name "VirtualGHOST" since it's a Virtual Machine whose presence is nearly impossible to detect.
.PARAMETER Server
    Name/IP of vCenter or ESXi system to connect to with PowerCLI. When connecting to vCenter, the script will automatically loop through each registered hypervisor and perform the comparison. Alternatively, users can connect to a single ESXi system to check just that host.
.PARAMETER Credential
    Credential to be used when connecting to vCenter / ESXi - will prompt if not provided separately
.EXAMPLE
  PS> .\Detect-VirtualGHOST.ps1
.EXAMPLE
  PS> .\Detect-VirtualGHOST.ps1 -Server vCenter.internaldomain.local
.EXAMPLE
  PS> .\Detect-VirtualGHOST.ps1 -Server esxi1.internaldomain.local
.NOTES
  Credits: CrowdStrike, Inc. (Ian Barton, Brian Pitchford, Jackson Roussin, Dylan Watson)
.LINK
  https://github.com/CrowdStrike/VirtualGHOST
.LINK
  https://dp-downloads.broadcom.com/api-content/apis/API_VWSA_001/7.0/html/vim.vm.ConfigInfo.html
#>

Param (
    [Parameter(Mandatory = $true)]
    [String]$Server,
    [PSCredential]$Credential = (Get-Credential -Message "Input vCenter/ ESXi credentials for PowerCLI")
);


if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
    Write-Error "[!] VMware PowerCLI module is not installed. Please install it to proceed."
    exit 1
} else {
    # Importing only the Cmdlets that we need in the hopes of this finishing a bit faster (PowerCLI import is notoriously slow)
    Write-Output "[+] Importing VMWare PowerCLI module. Please wait as this might take a while..."
    $null = Import-Module VMware.PowerCLI -Cmdlet Connect-VIServer, Get-EsxCli, Get-VMHost, Get-VM
}

function Get-VirtualGHOSTDetails {
<#
.SYNOPSIS
  Collect additional information from a VM that's been detected as a VirtualGHOST
.INPUTS
  EsxCli object representing a VM
.OUTPUTS
  Custom object with the standard VM details as well as network information (if available)
#>
    param (
        [Parameter(Mandatory = $true)]
        $VM
    )
    
    try {
        # Attempt to get network information for the VM
        $VMNetworkInfo = $esxcli_v2.network.vm.list.Invoke() | Where-Object { $_.WorldId -in $VM.WorldID }
        $VMNetworkPortInfo = $esxcli_v2.network.vm.port.list.Invoke(@{"worldid" = $VM.worldid})
    }
    catch {
        Write-Verbose "[-] Error collecting network info for $($VM.DisplayName) on $($vmHost.Name)"
    }
    $ReturnObject = [PSCustomObject]@{
        Hypervisor = $vmHost.Name
        VMName = $VM.DisplayName
        VMConfigFile = $VM.ConfigFile
        VMWorldID = $VM.WorldID
        VMNetworkInfo = $VMNetworkInfo | Select-Object Networks, NumPorts
        VMNetworkPortInfo = $VMNetworkPortInfo
    }

    return $ReturnObject
}

# If there are any errors then we will want to bubble them up
$ErrorActionPreference = "Stop"

try {
    Write-Output "[+] Connecting to server: $Server"
    $VMWareConnection = Connect-VIServer -Credential $Credential -Server $Server 
}
catch {
    # Unable to connect to the server
    if ($PSBoundParameters.Debug -eq $true) {
        $DebugError = "Line: $(($_.ScriptStackTrace -split ",")[1])"
    }
    $ErrorMsg = @"

    [!] There was an error connecting to the server.
    [!] Exception: $($_.FullyQualifiedErrorId)
    $DebugError
"@
    Write-Error $ErrorMsg
    exit 1
}
# Display message indicating successful connection to the server. Includes version / product information for debugging if necessary
Write-Output "[+] Connected to server: $($VMWareConnection.Name) | Version: $($VMWareConnection.Version) | ProductLine: $($VMWareConnection.ProductLine)"

$AllvmHosts = Get-VMHost
Write-Output "[+] There are $($AllvmHosts.Length) hypervisor(s) that will be checked for evidence of VirtualGHOST VMs."

# Instantiate the object which will hold any results
$Results = New-Object System.Collections.Generic.List[System.Object]

foreach ($vmHost in $AllvmHosts) {
    try {
        Write-Verbose "[-] Connecting to hypervisor: $($VMHost.Name)"
        # Retrieve a PowerShell object that will allow us to execute funtionally equivalent esxcli commands against the host
        $esxcli_v2 = Get-EsxCli -VMHost $vmHost -V2
        # Collect the list of running VMs per esxcli VM process listing. This will be where a VirtualGHOST VM can be spotted
        $VMsFromESXCli = $esxcli_v2.vm.process.list.Invoke() | Select-Object DisplayName,
            ConfigFile,
            ProcessID,
            VMXCartelID,
            WorldID,
            @{
                Name = "UUID_Comparison";
                Exp = {
                     # This unique identifier appears to be the 128-bit SMBIOS UUID of a virtual machine represented as a hexadecimal string. We remove the dashes so it can be directly compared with the value we normalize from the VM inventory
                    $_.UUID.Replace(" ", "").Replace("-", "").ToLower() 
                }
            }
        # Collect the list of VMs that are registered and expected to be in the inventory. This could be either from the hypervisor itself (if we connected directly to ESXi) or vCenter
        $VMsFromInventory = Get-VM -Location $vmHost | Select-Object Name, 
            VMHost,
            PowerState, 
            @{
                # This unique identifier appears to be the 128-bit SMBIOS UUID of a virtual machine represented as a hexadecimal string. We remove the dashes so it can be directly compared with the UUID_Comparison value we normalized from 'esxcli vm process list'
                Name = "UUID_Comparison"; 
                Exp = { 
                    ($_.ExtensionData.Config.Uuid).Replace("-", "").ToLower() 
                } 
            }

        $GhostVMs = $VMsFromESXCli | Where-Object { 
            # This is where we compare the inventory with the running VMs to see if we have any VirtualGHOSTs
            $_.UUID_Comparison -notin $VMsFromInventory.UUID_Comparison 
        }

        if ($null -ne $GhostVMs) {        
            Write-Warning "[!] ====Unregistered VM Detected on $($VMHost.Name)===="
            foreach ($ThisGhostVM in $GhostVMs) {
                $VMInfo = Get-VirtualGHOSTDetails -VM $ThisGhostVM
                
                # Display to user immediately as well as at the conclusion of the script
                $VMInfo | Format-Table Hypervisor, VMName, VMConfigFile, VMWorldID | Out-String | Write-Warning
                
                # Display network information
                if ($null -ne $VMInfo.VMNetworkInfo) {
                    Write-Warning "This VM appears to be connected to the network(s): $($VMInfo.VMNetworkInfo.Networks -join ', ')"
                }
                if ($null -ne $VMInfo.VMNetworkPortInfo) {
                    $VMInfo.VMNetworkPortInfo | Format-Table * | Out-String | Write-Warning
                }
                
                # Add this result to the full tally
                $Results.Add($VMInfo)
            }
        }
    }
    catch {
        Write-Warning "[!] Failed to process $($vmHost.Name): $_"
    }
}

    if ($Results.Count -ne 0) {
    Write-Warning @"
[!] Unregistered VMs detected on at least one hypervisor. Please refer to the output above. There may be some false positives due to standard system lifecycles, but any results should be investigated further.
"@
}
else {
   Write-Output "[+] No unregistered VMs detected."
}