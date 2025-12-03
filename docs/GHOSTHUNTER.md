# GHOSTHUNTER Documentation

This script reviews two sources of information:

- The embedded vCenter events database
- Virtual Machine logfiles stored on accessible datastores

The script will default to writing output to the directory containing the script file, but the output directory can be specified via the `--outdir` command line switch. There are two files that will be created:

- `CrowdStrike_GHOSTHUNTER_$VCENTER_$TIMESTAMP.log`
- `CrowdStrike_GHOSTHUNTER_ReviewedEvents_$TIMESTAMP.log`

Where `$TIMESTAMP` is the time when the script was first executed & `$VCENTER` is the server the script was executed against.

## Datasources

### vCenter Events

The script leverages vCenter APIs to search the embedded database for historical events associated with suspicious activity. The events collected include:

- Any SSH activity
- Logins
- Virtual machine removal

Any events that satisfy the following criteria will be flagged for the user:

- SSH involving the vpxuser account
- SSH or web UI logins originating from the vCenter IP address

All events that were retrieved will be saved to the output directory for further review. The filename will be 

### VM Logfiles on Datastores

The script will then search all datastores for any files that appear to be virtual machine log files. For each identified log file, the script will:

- Download the log file to a temporary directory
- Perform three checks on each line of the log file:
  - Hunt for suspicious environment variables
  - Hunt for a suspicious virtual machine command line i.e., `/bin/vmx -x`
  - Hunt for references to virtual machines files in suspicious directories

Any log files that satisfy one of the above criteria will be copied to the output directory for further review. A message will additionally be shown on screen to indicate where the files were stored so that the suspicious VM can be reviewed and obtained for forensic analysis.

## Execution

Script arguments and usage is available by using the `--help` command line switch.

### Example Invocation

The following command will run the GHOSTHUNTER script against `vcenter.example.com` using the `administrator@vsphere.local` account. Full debug logging will be written to screen as well as the log file, SSL/TLS certificate checks will be disabled (required for self-signed vCenter certificates), and output will be written to `C:\Temp\CrowdStrike_GHOSTHUNTER_Results`.

```shell
python3 ./GHOSTHUNTER.py --server vcenter.example.com --user administrator@vsphere.local --log-level DEBUG --no-ssl-check --outdir C:\Temp\CrowdStrike_GHOSTHUNTER_Results
```

> [!TIP]
> You do not need to execute the script with the `administrator@vsphere.local` account specifically, but you will need to use a user account that has elevated privileges within vCenter.

## Output Interpretation

There are multiple message levels that you should be aware of:

|Level|Description|
|----|----|
|**ERROR**|General Python error or issue with script operation indicating some function was not able to be completed|
|**ALERT**|Critical message indicating suspicious activity that should be investigated immediately|
|**WARNING**|Activity that should be reviewed to ensure legitimate activities|
|**IMPORTANT**|Non-terminating unexpected occurrence that might be a bug in the script operation|
|**INFO**|General messages|
|**DEBUG**|Detailed recording of internal activities that can be helpful in troubleshooting issues|

When reviewing output from GHOSTHUNTER, the CrowdStrike team performs a few quick checks:

- Identify the database retention settings to understand how far back we can expect to have event data for. The specific line looks like this `Database retention settings: Events - 30 | Tasks - 30` (30 is the default)
- Find any **ALERT** messages as they are the highest fidelity indicators of suspicious activity
- Review the event summary looking for:
  - Anomalous usage of generic accounts like `root` or `VSPHERE.local\Administrator`
  - Any SSH usage or enablement
- Review **ERROR** and **IMPORTANT** messages to determine if the team should rerun the script again & if there are any bugs that might be causing issues

### Example True Positive Outputs

#### Events

SSH with vpxuser

```
2025-12-03T03:30:49 UTC | ALERT | alert | Event details: createdTime: 2025-10-11 03:30:09.503999+00:00 | userName:  | host.name: esx-siete.lab.sudo-tron.me | fullFormattedMessage: SSH session was opened for 'vpxuser@192.168.3.104'. | eventTypeId: esx.audit.ssh.session.opened | objectName: esx-siete.lab.sudo-tron.me | chainId: 376292
```

WebUI login from vCenter IP indicating potential tunnelling

```
2025-12-03T03:30:49 UTC | ALERT | alert | Event details: createdTime: 2025-10-11 04:48:15.614000+00:00 | userName: root | host.name: esx-siete.lab.sudo-tron.me | fullFormattedMessage: User root@192.168.122.21 logged in as Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 | chainId: 376567
```

#### VM Logfiles

Virtual Machine in hidden directory

```
2025-12-03T03:31:01 UTC | ALERT | alert | Line 1: 2025-07-16T16:13:32.764Z In(05) vmx - /vmfs/volumes/3a7d92fe-8b4c61d2-fa93-e047b82c5d19/.sdd.sf/vCLS-c4f8b2d9-5e1a-4d7c-b8f3-9a6e2d4c1b5e/vCLS-c4f8b2d9-5e1a-4d7c-b8f3-9a6e2d4c1b5e.vmx: Setup symlink /var/run/vmware/8e2b9c5f7a4d1e6b3c8f9a2d5e7b4c1a6f3e8d9b2c5a7e4f1d8b6a3c9e5f2d7b -> /var/run/vmware/0/2901320310534_2418602
```

Anomalous vmx process environment variables

```
2025-12-03T03:31:01 UTC | ALERT | alert | Line 1: 2025-06-04T03:52:10.222Z In(05) vmx - Environment: "USER=vpxuser" "SSH_CLIENT=10.0.0.2 32558 22" "SHLVL=1" "HOME=/" "TERMINFO=/usr/share/terminfo" "OLDPWD=/" "PS1=[vpxuser@\h:\w] " "LOGNAME=vpxuser" "VI_USERNAME=vpxuser" "PATH=/bin:/sbin" "LANG=en_US.UTF-8" "SHELL=/bin/sh" "LC_ALL=en_US.UTF-8" "PWD=/" "SSH_CONNECTION=10.0.0.2 32558 10.0.0.3 22" "TMOUT=0"
```

Inclusion of `-x` argument to `/bin/vmx`

```
2025-12-03T03:31:02 UTC | ALERT | alert | Line 29: 2025-10-13T21:41:53.014Z In(05) vmx - Command line: "/bin/vmx" "-x" "/vmfs/volumes/Lab-Datastore/VM1CloneClone/VM1CloneClone.vmx"
```
