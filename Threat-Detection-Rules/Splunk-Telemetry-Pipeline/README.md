# Multi-Platform Telemetry Pipeline: Ingesting Windows & Linux Security Logs into Splunk Enterprise

## Executive Overview
Centralized log ingestion forms the foundation of modern Security Operations Centers (SOC). Without unified telemetry from operating systems, identity stores, and network perimeters, threat detection rules and automated incident response pipelines cannot function.

This project implements a multi-platform telemetry architecture forwarding security events from both Windows 11 and Ubuntu Linux endpoints into a centralized Splunk Enterprise SIEM instance. The pipeline captures native Windows Event Logs, enriched process telemetry via Microsoft Sysmon, and Linux system logs via `rsyslog`.

```text
               ┌────────────────────────────────────────────────────────┐
               │              Splunk Enterprise Indexer                 │
               │   - Web Interface (Port 8000)                          │
               │   - Splunk TCP Receiver (Port 9997)                    │
               │   - Syslog UDP Listener (Port 1514)                    │
               └──────────────┬──────────────────────────┬──────────────┘
                              ▲                          ▲
           TCP 9997 (Cooked)  │                          │  UDP 1514 (Syslog)
          (Encrypted + ACK)   │                          │
                              │                          │
┌─────────────────────────────┴──────┐        ┌──────────┴─────────────────────────┐
│        Windows 11 Endpoint         │        │        Ubuntu Linux Endpoint       │
│ - Universal Forwarder (LocalSystem)│        │ - Native rsyslog Daemon            │
│ - Event Viewer (Sec, App, Sys)     │        │ - Microsoft Sysmon (XML-rendered)  │
└────────────────────────────────────┘        └────────────────────────────────────┘
Phase 1: Splunk SIEM Index & Add-on Provisioning
To prevent storage contention, enforce Role-Based Access Control (RBAC), and optimize search query speeds, security telemetry must be separated into dedicated indexes rather than dumped into the default main index.

Index Isolation:

Created the sysmon index for high-volume endpoint process execution and network activity logs.

Created the wineventlog index for Windows standard Security, Application, System, and Advanced Firewall logs.

Figure 1.1: Navigating to Index configurations in Splunk Enterprise.

Figure 1.2: Configuring dedicated sysmon index.

Figure 1.3: Configuring dedicated wineventlog index.

Technology Add-on Installation:

Verified installation of the Splunk Add-on for Microsoft Windows and Splunk Add-on for Sysmon[cite: 11]. These add-ons provide field extraction and Common Information Model (CIM) normalization required for alert rule correlation.

Figure 1.4: Accessing Splunk app repository.

Figure 1.5: Verifying Splunk Add-on for Sysmon.

Figure 1.6: Verifying Splunk Add-on for Microsoft Windows[cite: 11].

Phase 2: Windows Endpoint Telemetry Configuration
Deploying the Splunk Universal Forwarder:

Executed the installer on the Windows 11 VM, accepting the default installation path and configuring it to run as a Local System account[cite: 12]. The deployment server configuration was left blank as we configure the outputs manually via script[cite: 13].

Figure 2.1: Initializing the Universal Forwarder setup[cite: 12].

Figure 2.2: Bypassing deployment server configuration for manual routing[cite: 13].

Network Connectivity Verification:

Tested transport reachability to Splunk ingestion port 9997 from PowerShell[cite: 14]:

PowerShell
Test-NetConnection -ComputerName 192.168.0.39 -Port 9997
Figure 2.3: Verifying TCP port 9997 reachability[cite: 14].

Automated Pipeline Configuration (UF.ps1):

Executed the UF.ps1 PowerShell script to dynamically build the outputs.conf (routing to 192.168.0.39:9997) and inputs.conf (monitoring XML Sysmon and WinEvent channels), followed by a service restart[cite: 15].

Figure 2.4: Executing the configuration script and restarting the Splunk daemon[cite: 15].

Forwarder Validation:

Verified the active outbound pipeline to the target indexer[cite: 16]:

PowerShell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
Figure 2.5: Confirming the forwarder is actively linked to 192.168.0.39:9997[cite: 16].

Phase 3: Linux Endpoint Ingestion via rsyslog
Rather than deploying a full forwarder agent on lightweight Linux instances, native system logging facilities (rsyslog) can stream authentication, kernel, and process logs directly over UDP/TCP.

Configuring Splunk UDP Data Input:

Navigated to Settings > Data Inputs > UDP and selected New Local UDP[cite: 18].

Configured port 1514, assigned source type syslog, and targeted the main index[cite: 19, 20].

Figure 3.1: Initiating a new UDP data input[cite: 18].

Figure 3.2: Specifying listening port 1514 on Splunk[cite: 19].

Figure 3.3: Setting source type to syslog and destination index to main[cite: 20].

Instrumenting the Linux Daemon:

Configured an export rule directing all facilities and severities (*.*) to the Splunk instance listener and restarted the service:

Bash
echo '*.* @192.168.0.39:1514' | sudo tee /etc/rsyslog.d/90-splunk-forwarding.conf
sudo systemctl restart rsyslog
systemctl status rsyslog
Figure 3.4: rsyslog operational status confirmation in Ubuntu CLI.

Verification & Detection Validation
To confirm end-to-end pipeline integrity, synthetic events were generated across both operating systems and queried in Splunk.

1. Ingestion Verification (Index Distribution)
Executed the following SPL query in the Search & Reporting application to verify data distribution across the newly created indexes[cite: 17]:

Splunk SPL
index=* | stats count by index host
Figure 4.1: Confirmed telemetry ingestion showing 2,823 Sysmon events and 305 Windows events[cite: 17].

2. Linux Syslog Validation
Injected a test log entry using the Linux logger binary:

Bash
logger "CySA+ lab test: rsyslog -> Dockerized Splunk via UDP 1514"
Queried the main index in Splunk:

Splunk SPL
index=main "CySA+ lab test"
Figure 4.2: Successful ingestion and indexing of the test syslog event.