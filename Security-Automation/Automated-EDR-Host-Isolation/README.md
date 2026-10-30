# End-to-End SOAR Pipeline: Automated EDR Alert Triage & Endpoint Firewall Isolation

## Executive Overview
Reducing Mean Time to Respond (MTTR) requires tightly coupling threat detection with automated containment. When an endpoint compromises high-confidence behavioral indicators—such as Living-off-the-Land Binaries (LOLBins) executing suspicious child processes—waiting for manual human intervention allows adversaries time to establish persistence or move laterally.

This project implements a functional Security Orchestration, Automation, and Response (SOAR) and Endpoint Detection and Response (EDR) proof-of-concept across a hybrid Ubuntu Linux and Windows 11 environment. A Windows endpoint generates structured JSON telemetry simulating a malicious process chain (`powershell.exe` spawning `rundll32.exe`) and transmits it to a centralized Python Flask SIEM/MCP hub. The central server evaluates the payload via an automated decision engine, queues a containment directive, and instructs a lightweight polling agent on the Windows host to dynamically enforce full network quarantine via Windows Defender Firewall rules.

```text
┌─────────────────────────────────────────┐         ┌─────────────────────────────────────────┐
│          Windows 11 Endpoint            │         │      Ubuntu Linux (SIEM / SOAR Hub)     │
│                                         │         │                                         │
│  1. EDR Telemetry Emitter               │         │  2. Flask Ingestion & Decision Engine   │
│     (send_alert.ps1)                    │         │     (app.py : Port 5000)                │
│     └─ Detects: PowerShell -> rundll32 ─┼────────►│     ├─ POST /ingest (Logs alerts.jsonl) │
│                                         │  JSON   │     ├─ Evaluates Severity & Rule Logic  │
│  4. Endpoint Enforcement Agent          │         │     └─ Enqueues 'isolate_host' Command  │
│     (win_agent.ps1)                     │         │                                         │
│     ├─ Polls GET /commands?host=... ────┼────────►│  3. Command Queue & Status Tracker      │
│     ├─ Enforces Inbound/Outbound Block  │◄────────┼─    ├─ Populates commands.json          │
│     │  via Windows Defender Firewall    │Task JSON│     └─ Renders Real-Time Web UI (GET /) │
│     └─ Reports Status (POST /report) ───┼────────►│        & Updates host_status.json       │
└─────────────────────────────────────────┘         └─────────────────────────────────────────┘
```

## Technical Stack
* **SOAR / SIEM Hub:** Python 3, Flask REST API, JSON Lines (`jsonl`) state storage (Ubuntu Linux)
* **Endpoint Agent & Emitter:** PowerShell 5.1+, `Invoke-RestMethod`, `NetSecurity` module (Windows 11)
* **Containment Mechanism:** Windows Defender Firewall (`New-NetFirewallRule`)
* **Technique Mitigated:** System Binary Proxy Execution: Rundll32 (MITRE ATT&CK T1218.011), Command and Scripting Interpreter: PowerShell (T1059.001)

---

## Phase 1: Central SIEM & SOAR Hub Deployment (Ubuntu)

The central orchestration server was built using Python and Flask to expose RESTful endpoints for alert ingestion, automated triage decisioning, command queuing, and execution telemetry reporting.

### 1. Environment Provisioning
```bash
sudo apt update
sudo apt install -y python3-flask
python3 -c "import flask; print(flask.__version__)"
```

### 2. Orchestration Server Implementation (`app.py`)
The application maintains three state files inside the `data/` directory:
* `alerts.jsonl`: Append-only log of raw incoming EDR alerts.
* `commands.json`: Per-host one-shot task queue consumed by polling endpoint agents.
* `host_status.json`: Real-time state ledger tracking the latest triage decision and remediation verification per host.

```python
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import json, os

app = Flask(__name__)

DATA_DIR = "data"
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.jsonl")
CMDQ_FILE = os.path.join(DATA_DIR, "commands.json")
HOST_STATUS_FILE = os.path.join(DATA_DIR, "host_status.json")

os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(CMDQ_FILE): json.dump({}, open(CMDQ_FILE, "w"))
if not os.path.exists(HOST_STATUS_FILE): json.dump({}, open(HOST_STATUS_FILE, "w"))

def append_alert(alert):
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")

def load_cmdq():
    return json.load(open(CMDQ_FILE))

def save_cmdq(d):
    json.dump(d, open(CMDQ_FILE, "w"))

def load_status():
    return json.load(open(HOST_STATUS_FILE))

def save_status(d):
    json.dump(d, open(HOST_STATUS_FILE, "w"))

# Automated Triage & Decision Engine
def agentic_ai_decide_and_enqueue(alert):
    host = alert.get("host", {}).get("hostname", "unknown")
    severity = (alert.get("severity") or "low").lower()
    rule = alert.get("rule", "")

    decision = "monitor"
    reason = "Benign or low signal"
    if rule == "ps_spawn_rundll32" or severity in ["high", "critical"]:
        decision = "quarantine"
        reason = "Suspicious process pattern (PowerShell -> rundll32) or high severity"

    status = load_status()
    status[host] = {
        "last_seen": datetime.utcnow().isoformat(),
        "last_alert_rule": rule,
        "decision": decision,
        "reason": reason
    }
    save_status(status)

    if decision == "quarantine":
        cmdq = load_cmdq()
        q = cmdq.get(host, [])
        q.append({
            "action": "isolate_host",
            "details": {"method": "windows_firewall_block_all_outbound"},
            "ts": datetime.utcnow().isoformat()
        })
        cmdq[host] = q
        save_cmdq(cmdq)

    return {"decision": decision, "reason": reason}

@app.post("/ingest")
def ingest():
    alert = request.get_json(force=True, silent=True) or {}
    alert["ingested_at"] = datetime.utcnow().isoformat()
    append_alert(alert)
    decision = agentic_ai_decide_and_enqueue(alert)
    return jsonify({"status": "ok", "decision": decision})

@app.get("/commands")
def commands():
    host = request.args.get("host")
    if not host:
        return jsonify({"error": "host query param required"}), 400
    cmdq = load_cmdq()
    q = cmdq.get(host, [])
    cmdq[host] = []
    save_cmdq(cmdq)
    return jsonify({"commands": q})

@app.post("/report")
def report():
    body = request.get_json(force=True, silent=True) or {}
    host = body.get("host")
    result = body.get("result", {})
    status = load_status()
    h = status.get(host, {})
    h["last_action_result"] = result
    h["last_action_ts"] = datetime.utcnow().isoformat()
    status[host] = h
    save_status(status)
    return jsonify({"status": "ok"})

DASH = """
<!doctype html>
<title>MCP / SIEM - SOC Automation Dashboard</title>
<h1>Incidents & Host Containment Status</h1>

<h2>Recent Alerts</h2>
<pre style="background:#111;color:#eee;padding:10px;border-radius:8px;">
{% for a in alerts %}
{{ a }}
{% endfor %}
</pre>

<h2>Host Status</h2>
<pre style="background:#111;color:#eee;padding:10px;border-radius:8px;">
{{ status | tojson(indent=2) }}
</pre>
"""

@app.get("/")
def index():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            for line in f.readlines()[-25:]:
                try:
                    alerts.append(json.dumps(json.loads(line), indent=2))
                except:
                    pass
    status = load_status()
    return render_template_string(DASH, alerts=alerts, status=status)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

---

## Phase 2: Endpoint Telemetry & Response Agent (Windows 11)

Two PowerShell components were engineered on the Windows 11 endpoint: an alert emitter to simulate high-severity EDR detections and an active response daemon that polls the SOAR hub for containment tasks.

### 1. EDR Alert Emitter (`send_alert.ps1`)
Generates a structured JSON payload modeling a hidden PowerShell window executing `rundll32.exe` alongside an outbound TCP connection to an external command-and-control (C2) IP address:

```powershell
$McpUrl = "http://192.168.0.112:5000/ingest"
$HostName = $env:COMPUTERNAME

$alert = @{
    vendor = "DemoEDR"
    rule = "ps_spawn_rundll32"
    severity = "high"
    host = @{
        hostname = $HostName
        ip = "192.168.56.20"
        os = "Windows 11"
    }
    process = @{
        parent = "powershell.exe"
        child  = "rundll32.exe"
        cmdline = "powershell.exe -NoP -W Hidden; rundll32.exe foo.dll,Bar"
        sha256 = "FAKEDEADBEEF0123456789"
    }
    network = @{
        dest_ip = "45.141.87.218"
        dest_port = 9000
        protocol = "tcp"
    }
    ts = (Get-Date).ToUniversalTime().ToString("o")
}

$body = $alert | ConvertTo-Json -Depth 5
try {
    $response = Invoke-RestMethod -Method Post -Uri $McpUrl -Body $body -ContentType "application/json"
    "Ingest response:`n$($response | ConvertTo-Json -Depth 5)"
} catch {
    "Error posting alert: $($_.Exception.Message)"
}
```

### 2. Automated Quarantine Agent (`win_agent.ps1`)
Polls the `/commands` endpoint every 10 seconds. Upon receiving the `isolate_host` instruction, it provisions high-priority Windows Firewall rules blocking all inbound and outbound traffic across all network profiles (`Domain`, `Private`, `Public`) and reports execution telemetry back to `/report`:

```powershell
param(
  [string]$McpBase = "http://192.168.0.112:5000",
  [int]$IntervalSec = 10
)

$HostName = $env:COMPUTERNAME

function Get-Commands {
  $url = "$McpBase/commands?host=$HostName"
  try {
    return Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 5
  } catch {
    return @{ commands = @() }
  }
}

function Report-Result($result) {
  $payload = @{
    host = $HostName
    result = $result
  } | ConvertTo-Json -Depth 5
  try {
    Invoke-RestMethod -Method Post -Uri "$McpBase/report" -Body $payload -ContentType "application/json" | Out-Null
  } catch {}
}

function Isolate-Host {
  $ruleNameOut = "DEMO-Isolate-Host-AllOutbound"
  $existingOut = Get-NetFirewallRule -DisplayName $ruleNameOut -ErrorAction SilentlyContinue
  if ($existingOut) { $existingOut | Remove-NetFirewallRule }
  New-NetFirewallRule -DisplayName $ruleNameOut -Direction Outbound -Action Block -Enabled True -Profile Any

  $ruleNameIn = "DEMO-Isolate-Host-AllInbound"
  $existingIn = Get-NetFirewallRule -DisplayName $ruleNameIn -ErrorAction SilentlyContinue
  if ($existingIn) { $existingIn | Remove-NetFirewallRule }
  New-NetFirewallRule -DisplayName $ruleNameIn -Direction Inbound -Action Block -Enabled True -Profile Any

  return @{
    action = "isolate_host"
    result = "success"
    details = "Added block-all outbound/inbound firewall rules"
    ts = (Get-Date).ToUniversalTime().ToString("o")
  }
}

Write-Host "Starting endpoint agent for $HostName. Polling $McpBase every $IntervalSec sec..."
while ($true) {
  $cmdResp = Get-Commands
  foreach ($cmd in $cmdResp.commands) {
    $action = $cmd.action
    $res = $null
    switch ($action) {
      "isolate_host" { $res = Isolate-Host }
      default {
        $res = @{
          action = $action
          result = "unknown_action"
          ts = (Get-Date).ToUniversalTime().ToString("o")
        }
      }
    }
    if ($res) { Report-Result $res }
  }
  Start-Sleep -Seconds $IntervalSec
}
```

---

## Phase 3: Execution & Containment Verification

1. **Pipeline Initialization:**
   * Started the Flask orchestration server on Ubuntu (`python3 app.py`).
   * Launched the polling agent in an elevated PowerShell console on Windows 11 (`powershell -ExecutionPolicy Bypass -File .\win_agent.ps1`).
   * Triggered the simulated detection (`powershell -ExecutionPolicy Bypass -File .\send_alert.ps1`).

2. **Automated Triage & Quarantine:**
   * The `/ingest` endpoint parsed the `ps_spawn_rundll32` rule, classified the event as requiring immediate containment, and queued the `isolate_host` action.
   * On its next 10-second polling cycle, `win_agent.ps1` retrieved the task, applied the inbound and outbound firewall block rules, and transmitted confirmation to `/report`.

3. **Containment Validation:**
   Verified that external network communications were severed and inspected the active firewall policy on the Windows 11 host:
   ```powershell
   Test-NetConnection 8.8.8.8 -Port 53
   Get-NetFirewallRule | Where-Object DisplayName -like "DEMO-Isolate-Host*"
   ```
   *Result:* Outbound connections to `8.8.8.8:53` failed as expected, and both `DEMO-Isolate-Host-AllOutbound` and `DEMO-Isolate-Host-AllInbound` were verified active.

---

## Phase 4: Remediation Rollback

To restore normal network operations following containment validation, the isolation rules and temporary server state were cleared.

**Windows Endpoint Rollback:**
```powershell
Get-NetFirewallRule | Where-Object DisplayName -like "DEMO-Isolate-Host*" | Remove-NetFirewallRule
```

**Ubuntu Hub Cleanup:**
```bash
pkill -f "python3 app.py"
rm -rf data
```

---

## Operational Security Considerations

* **Management Channel Preservation:** In this proof-of-concept, blocking *all* outbound traffic severs communication to the SOAR server immediately after the firewall rules take effect. In production EDR agents, a high-priority allow rule must be scoped specifically to the SOAR/EDR management IP and port (e.g., TCP 5000/443) prior to applying the catch-all block rule so analysts can remotely un-isolate the host or collect forensic artifacts.
* **Mutual TLS (mTLS) & API Authentication:** Polling and ingestion endpoints (`/ingest`, `/commands`, `/report`) must be hardened with mTLS and bearer token authentication in production to prevent adversaries from spoofing false-positive quarantine commands (Denial of Service) or clearing queued containment actions.