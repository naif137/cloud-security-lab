# 🛡️ Automated Cloud Security Operations & DevSecOps Monitoring System

[![Security Score](https://img.shields.io/badge/Security_Score-100%2F100_PASS-10b981?style=for-the-badge&logo=shield)](https://naif137.github.io/cloud-security-lab/)
[![OS](https://img.shields.io/badge/Platform-Ubuntu_Linux-E95420?style=for-the-badge&logo=ubuntu)](https://ubuntu.com/)
[![Language](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-GitHub_Pages-22272e?style=for-the-badge&logo=github)](https://naif137.github.io/cloud-security-lab/)

An enterprise-grade, lightweight Cloud SOC and Host Hardening pipeline for production Linux environments. Automatically audits host compliance, mitigates unauthorized access via active intrusion prevention, harvests real-time threat intelligence, and dispatches incident alerts to Discord and SIEM logs.

---

## 🏛️ System Architecture
mermaid
flowchart TD
subgraph Ingress [Inbound Traffic]
TRAFFIC[Inbound Network Traffic] --> UFW[UFW Firewall: Strict]
end
subgraph Defense [Host Defense & Access]
    UFW --> SSH[SSH Key-Only / Root Disabled]
    SSH -->|Invalid / Brute Force| F2B[Fail2ban Active Drop]
    SSH -->|Authorized Key| SHELL[Authorized Shell Access]
end

subgraph SOC [SOC Telemetry & Pipeline]
    LOGS[(Linux Auth Logs)] --> HUNTER[threat_hunter.py\nGeoIP & ISP Telemetry]
    HUNTER --> DISPATCH[alert_dispatcher.py\nSIEM Engine]
    AUDIT[security_audit.py\nCIS Hardening Audit] --> DISPATCH
end

subgraph Outputs [Live Response & Visualization]
    DISPATCH -->|Webhook Alert| DISCORD[Discord SOC Channel]
    DISPATCH -->|JSON Events| ALERTS[alerts.log]
    DISPATCH -->|HTML Telemetry| DASH[Live GitHub Pages Dashboard]
end
---

## 🚀 Core Features

* **CIS-Aligned Host Hardening:**
  * Strict packet filtering via **UFW**.
  * Enforcement of cryptographic SSH keys; absolute disabling of password authentication and direct `root` logins.
  * Active intrusion prevention via **Fail2ban**.

* **Threat Intelligence & Telemetry:**
  * Parses authentication logs to detect brute-force attacks.
  * Real-time IP resolution and enrichment (Geolocation, ASN, and ISP tracking).

* **Unified SOC Dispatcher & Alerting:**
  * Real-time incident notification webhooks dispatching payloads to **Discord**.
  * Structured JSON alerting log output (`alerts.log`) formatted for SIEM ingestion.

* **Continuous Automated Auditing:**
  * Headless cron job execution updating posture metrics periodically.
  * Automated generation of a Web Dashboard deployed via **GitHub Pages**.

---

## 📁 Project Structure
text
.
├── alert_dispatcher.py   # SOC alerting and webhook pipeline engine
├── alerts.log            # SIEM-formatted threat event log (JSON/Structured)
├── audit_report.html     # Raw HTML report generated from the audit run
├── index.html            # Public web dashboard deployed to GitHub Pages
├── README.md             # Project documentation and architecture overview
├── security_audit.py     # Hardening compliance auditor (CIS baseline checks)
├── soc_monitor.sh        # Scheduled runner and telemetry collector
└── threat_hunter.py      # Auth-log parser and threat intel investigator
---

## 📊 Live Monitoring Dashboard

Explore the live operational posture here:  
👉 [Security Operations Dashboard](https://naif137.github.io/cloud-security-lab/)

---

**Author:** Naif Albarqi  
**Focus:** Cloud Security Engineering & DevSecOps
