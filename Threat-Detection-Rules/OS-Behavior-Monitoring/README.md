# OS Behavior & Threat Detection: Monitoring Registry Persistence and File Integrity

## Executive Overview
Understanding normal operating system behavior is critical for identifying malicious anomalies. Attackers frequently exploit native OS mechanisms—such as Windows Registry run keys for persistence or Linux configuration files for backdoor access. 

This lab operationalizes OS concepts by instrumenting endpoints to capture deep system activity. It demonstrates how to enforce advanced audit policies, simulate adversary behavior (registry manipulation and LOLBin execution), and construct Splunk SIEM queries to detect these indicators of compromise (IoCs) in real-time.

## Technical Stack
* **SIEM:** Splunk Enterprise
* **Endpoints:** Windows 11 (Universal Forwarder), Ubuntu Linux (rsyslog)
* **Telemetry Agents:** Microsoft Sysmon, Windows Event Viewer, Linux `auditd`
* **Techniques Emulated:** Boot or Logon Autostart Execution (T1547.001), System Information Discovery (T1082)

---

## Phase 1: Endpoint Instrumentation & Hardening

Before detecting threats, the endpoints must be configured to log the correct telemetry. By default, Windows and Linux do not log granular process command lines or specific file modifications.

### 1. Windows Audit Policy Configuration
A PowerShell script was executed with Administrator privileges to enable critical audit subcategories and mandate the inclusion of full command-line arguments in Process Creation events (Event ID 4688). This is essential for detecting Living-off-the-Land (LOTL) attacks.

```powershell
# Enable critical audit subcategories
$subcats = @('Process Creation', 'Registry', 'Security System Extension', 'System Integrity', 'Other Policy Change Events')
foreach ($s in $subcats) {
  auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
}

# Mandate FULL command line logging via Registry
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Note: Time synchronization (NTP) was also forced via w32tm to ensure SIEM correlation rules fire accurately based on timestamp alignment.

2. Linux File Integrity Monitoring (FIM)
To monitor critical access control configurations, the Linux auditd daemon was installed and configured to watch the SSH daemon configuration file. Any write (w) or attribute (a) changes trigger an alert tagged as sshd_config_change.

Bash
sudo apt-get install -y auditd
sudo bash -c 'cat >/etc/audit/rules.d/sshd.rules << "EOF"
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
EOF'
sudo augenrules --load
sudo systemctl restart auditd
Phase 2: Threat Emulation
To validate the telemetry pipeline, synthetic attacks were generated on both operating systems.

1. Windows Registry Persistence & LOLBins
Attackers often establish persistence by adding executables to the CurrentVersion\Run registry key. A PowerShell script injected a benign persistence key and executed suspicious processes (including a hidden PowerShell window).

PowerShell
# Inject persistence via Run key
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "CySA_Benign" -Value "notepad.exe" -Force | Out-Null

# Spawn processes for 4688 and Sysmon Event 1 telemetry
Start-Process "powershell.exe" -ArgumentList '-NoP -W Hidden -Command "Write-Output benign"'
2. Linux SSH Downgrade Attack
To simulate an adversary weakening system security, a backup of the SSH configuration was made, and password authentication was forcefully disabled via sed.

Bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
Phase 3: SIEM Detection & Validation (SPL)
With the attacks executed, Splunk was utilized to hunt for the generated telemetry.

Detection 1: Registry Persistence (Sysmon Event ID 12, 13, 14)
This query hunts for any modifications to the high-value Run key, successfully identifying the CySA_Benign injection.

Splunk SPL
index=sysmon (EventCode=13 OR EventCode=12 OR EventCode=14)
| where like(TargetObject, "%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%")
| table _time Computer User EventCode TargetObject Details
| sort 0 -_time


Detection 2: Suspicious LOLBin Execution (Event ID 4688 & Sysmon 1)
This query coalesces native Windows logs and Sysmon logs to detect the execution of commonly abused native binaries (PowerShell, mshta, rundll32) along with their full command-line arguments.

Splunk SPL
(index=wineventlog EventCode=4688) OR (index=sysmon EventCode=1)
| eval cmd=coalesce(CommandLine,ProcessCommandLine)
| where match(lower(cmd), "(powershell|mshta|rundll32|regsvr32)")
| table _time Computer Account_Name User New_Process_Name Image cmd Parent_Process_Name ParentImage
| sort 0 -_time


Detection 3: Audit Policy Tampering (Event ID 4719)
Adversaries frequently attempt to disable logging. This query detects when the system's underlying audit policy is altered.

Splunk SPL
index=wineventlog (EventCode=4719 OR EventCode=1102 OR EventCode=4739 OR EventCode=4732 OR EventCode=4735)
| table _time Computer EventCode TaskCategory Message
| sort 0 -_time
Detection 4: File Integrity Alert (Linux sshd_config)
This query searches the Linux syslog index for the auditd alert key, confirming that the sshd_config file was modified.

Splunk SPL
index=main | search sshd_config_change
| rex field=_raw "name=\"(?<file>/etc/ssh/sshd_config)\""
| table _time host file auid uid msg_type exe _raw
| sort 0 -_time

Phase 4: Remediation & Rollback
Following the successful detection, the environment was restored to its secure baseline to prevent configuration drift.

Windows Rollback:

PowerShell
Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "CySA_Benign" -ErrorAction SilentlyContinue
Remove-Item -Path HKCU:\Software\CySA -Recurse -Force -ErrorAction SilentlyContinue
Linux Rollback:

Bash
sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo systemctl restart ssh
