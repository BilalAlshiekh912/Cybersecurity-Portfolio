# Enterprise SOC Infrastructure: Building a Containerized SIEM & Telemetry Lab

## Executive Overview
A mature Security Operations Center (SOC) requires a segmented, highly available, and easily restorable architecture to analyze malware, detonate payloads, and ingest telemetry without risking the host system. 

This project documents the automated provisioning and configuration of a localized threat-hunting environment. It leverages hypervisor-based virtualization to isolate a Windows 11 endpoint and containerization (Docker) to deploy Splunk Enterprise on an Ubuntu Linux server. This architecture demonstrates core CySA+ infrastructure security concepts, including shared-kernel trade-offs, image immutability, least-privilege execution, and container-escape blast radius reduction.

## Technical Stack & Topology
* **Hypervisor:** Oracle VM VirtualBox (Bridged Networking for internal VM-to-VM routing)
* **SIEM Host:** Ubuntu 24.04 LTS Server (Headless)
* **SIEM Platform:** Splunk Enterprise (Docker Containerized)
* **Endpoint:** Windows 11 Enterprise (Domain-Join / Local Account configuration)
* **Telemetry Agents:** Microsoft Sysmon (Modular Config), Native Windows Event Logs

---

## Phase 1: Linux SIEM Provisioning & Containerization

To ensure the SIEM is portable, easily updatable, and isolated from the underlying host OS, Splunk was deployed via Docker Engine on a hardened Ubuntu Server base.

### 1. Base OS Hardening & Access
* Provisioned an Ubuntu 24.04 VM with 4GB+ RAM and 2 CPUs.
* Installed OpenSSH to enable secure remote headless administration.
* Verified IP routing (via `ip a`) and established an SSH session from the host machine to facilitate terminal multiplexing and clipboard sharing.
* Updated repository caches and installed foundational utilities (`curl`, `wget`, `net-tools`, `jq`).

### 2. Docker Engine Deployment
Added the official Docker GPG keys and repository to bypass legacy `apt` packages, ensuring the latest stable release of Docker Engine, CLI, and `containerd` were installed.

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL [https://download.docker.com/linux/ubuntu/gpg](https://download.docker.com/linux/ubuntu/gpg) | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
[https://download.docker.com/linux/ubuntu](https://download.docker.com/linux/ubuntu) $(lsb_release -cs) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io
3. Containerized Splunk Instantiation
To ensure SIEM data (indexed logs, dashboards, configurations) persists if the Splunk container is destroyed or updated, Docker volumes were explicitly mapped to the /opt/splunk/etc and /opt/splunk/var directories.
# Provision persistent volumes
sudo docker volume create splunk-etc
sudo docker volume create splunk-var

# Instantiate the Splunk container with explicit port bindings
sudo docker run -d --name splunk \
  -p 8000:8000 \
  -p 8089:8089 \
  -p 9997:9997 \
  -p 1514:1514/udp \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD='<STRONG_PASSWORD>' \
  -v splunk-etc:/opt/splunk/etc \
  -v splunk-var:/opt/splunk/var \
  splunk/splunk:latest
  Port 8000: Web GUI access.

Port 8089: REST API / Management interface.

Port 9997: Splunk TCP Indexer receiving port (for Universal Forwarders).

Port 1514 (UDP): Syslog ingestion.

The container was then configured with a --restart unless-stopped policy so the SIEM automatically recovers upon Ubuntu host reboots.

Phase 2: Windows Endpoint Telemetry & Hardening
A Windows 11 Enterprise VM was deployed to serve as the primary attack surface and telemetry generation endpoint.

1. Advanced Endpoint Instrumentation (Sysmon)
Native Windows Event Viewer lacks the depth required to track process injection, network connections, and file hashing. Microsoft Sysinternals Sysmon was deployed using a customized PowerShell script to apply Olaf Hartung’s industry-standard modular XML configuration.

PowerShell#
 Bypass execution policy for local deployment
Set-ExecutionPolicy Unrestricted -Force

# Execute automated Sysmon deployment script
./Install-Sysmon-m122configv2_1.ps1
Script Workflow: The script dynamically downloads the official Sysmon binaries, pulls the modular XML configuration from GitHub, accepts the EULA silently, and registers Sysmon as an automatic boot service. It also configures permissions on the Microsoft-Windows-Sysmon/Operational channel so log readers can access the telemetry.

2. PowerShell Script Block Logging
Adversaries frequently use PowerShell to execute fileless malware or obfuscated commands. To ensure the SIEM captures the actual de-obfuscated code executed in memory, Script Block Logging was enabled via Local Group Policy:

Path: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.

Phase 3: Infrastructure Verification
Network Segmentation: Confirmed bidirectional ICMP traffic between the Windows 11 endpoint, the Ubuntu Docker host, and external WAN (8.8.8.8).

Container Health: Executed sudo docker ps on the Linux host to verify Splunk reported a HEALTHY status.

Telemetry Validation: Accessed Event Viewer on the Windows 11 endpoint (Applications and Services > Microsoft > Windows > Sysmon > Operational) and verified Event ID 1 (Process Creation) and Event ID 3 (Network Connection) logs were generating successfully.

Baseline Snapshots: Created pre-exploitation hypervisor snapshots ("Clean install") for both VMs to allow rapid rollback after detonating payloads in future labs.