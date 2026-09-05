# 🛡️ Automated Cloud Security Operations & DevSecOps Monitoring System

[![Security Score](https://img.shields.io/badge/Security_Score-100%2F100_PASS-10b981?style=for-the-badge&logo=shield)](https://naif137.github.io/cloud-security-lab/)
[![OS](https://img.shields.io/badge/Platform-Ubuntu_Linux-E95420?style=for-the-badge&logo=ubuntu)](https://ubuntu.com/)
[![Language](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-GitHub_Pages-22272e?style=for-the-badge&logo=github)](https://naif137.github.io/cloud-security-lab/)

An enterprise-grade, lightweight Cloud SOC and Host Hardening pipeline for production Linux environments. Automatically audits host compliance, mitigates unauthorized access via active intrusion prevention, harvests real-time threat intelligence, and dispatches incident alerts to Discord and SIEM logs.

---

## 🏛️ System Architecture
+-----------------------------+
                  |   Inbound Network Traffic   |
                  +--------------+--------------+
                                 |
                                 v
                    [ UFW Firewall: Strict ]
                                 |
                                 v
                   [ SSH: Key-Only / No Root ]
                                 |
             +-------------------+-------------------+
             |                                       |
    (Valid SSH Key)                       (Invalid / Brute Force)
             |                                       |
             v                                       v
    [ Authorized Shell ]                   [ Fail2ban Enforcement ]
                                                     |
                                                     v
                                          [ Linux Auth Logs Engine ]
                                                     |
                                                     v
                                         [ Python Threat Hunter ]
                                         - Extracts Hostile IPs
                                         - Geolocation & ISP Enrichment
                                                     |
                             +-----------------------+-----------------------+
                             |                                               |
                             v                                               v
                 [ Automated Discord Webhook ]                  [ Static HTML Dashboard ]
                 - Instant Incident Response                    - GitHub Pages CI/CD
                 - SOC Triage Card                              - Score: 100/100 PASS
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

## 📂 Project Structure
---

## 📊 Live Monitoring Dashboard
Explore the live operational posture here:  
👉 **[Security Operations Dashboard](https://naif137.github.io/cloud-security-lab/)**

---

**Author:** Naif Albarqi  
**Focus:** Cloud Security Engineering & DevSecOps
