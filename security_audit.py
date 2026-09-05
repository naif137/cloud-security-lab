#!/usr/bin/env python3
"""
Advanced Cloud & Linux Security Audit Engine (v2.0)
Author: Naif Albarqi
Description: Audits system posture, calculates hardening score (0-100),
             and generates an interactive executive HTML report.
"""

import os
import subprocess
import socket
from datetime import datetime

# ANSI Terminal Colors
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.stdout.strip()
    except Exception:
        return ""

def main():
    banner = f"""{CYAN}{BOLD}
   ____ _                 _   ____                            _ _         
  / ___| | ___  _   _  __| | / ___|  ___  ___ _   _ _ __(_) |_ _   _ 
 | |   | |/ _ \| | | |/ _` | \___ \ / _ \/ __| | | | '__| | __| | | |
 | |___| | (_) | |_| | (_| |  ___) |  __/ (__| |_| | |  | | |_| |_| |
  \____|_|\___/ \__,_|\__,_| |____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                               |___/ 
        {YELLOW}>>> Linux Hardening & Posture Assessment Engine <<<{RESET}
    """
    print(banner)

    hostname = socket.gethostname()
    ip_output = run_cmd("hostname -I")
    ip_addr = ip_output.split()[0] if ip_output else "127.0.0.1"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    checks = []
    total_score = 100

    print(f"{BOLD}[*] Target Host:{RESET} {hostname} ({ip_addr})")
    print(f"{BOLD}[*] Started At:{RESET} {timestamp}\n")

    # 1. Firewall (UFW)
    ufw = run_cmd("sudo ufw status")
    if "active" in ufw and "inactive" not in ufw:
        checks.append(("Firewall Protection (UFW)", "ACTIVE", "PASS", "UFW is active and filtering inbound traffic."))
    else:
        checks.append(("Firewall Protection (UFW)", "INACTIVE", "FAIL", "Firewall is disabled or permissive."))
        total_score -= 25

    # 2. SSH Root Login
    ssh_root = run_cmd("grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null")
    if "no" in ssh_root.lower() or "prohibit-password" in ssh_root.lower():
        checks.append(("SSH Root Login Policy", "SECURED", "PASS", "Root login over SSH is restricted."))
    else:
        checks.append(("SSH Root Login Policy", "PERMISSIVE", "WARN", "Direct root login might be permitted over SSH."))
        total_score -= 15

    # 3. Password Authentication via SSH
    ssh_pass = run_cmd("grep -Ei '^PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null")
    if "no" in ssh_pass.lower():
        checks.append(("SSH Key-Only Auth", "ENFORCED", "PASS", "Password authentication disabled (Key-based only)."))
    else:
        checks.append(("SSH Key-Only Auth", "ALLOW_PASSWORDS", "WARN", "Password authentication enabled; susceptible to brute-force."))
        total_score -= 15

    # 4. Critical Open Ports
    open_ports = run_cmd("ss -tuln | grep LISTEN")
    unnecessary_ports = []
    for p in ["21", "23", "25", "8080"]:
        if f":{p} " in open_ports:
            unnecessary_ports.append(p)

    if not unnecessary_ports:
        checks.append(("Exposed Legacy Ports", "CLEAN", "PASS", "No risky legacy ports detected."))
    else:
        checks.append(("Exposed Legacy Ports", f"EXPOSED: {','.join(unnecessary_ports)}", "FAIL", "Risky services listening on network interfaces."))
        total_score -= 20

    # 5. Failed Authentication Spikes
    failed_auth = run_cmd("journalctl -u ssh -n 20 --no-pager 2>/dev/null | grep -i 'failed' | wc -l")
    failed_count = int(failed_auth) if failed_auth.isdigit() else 0
    if failed_count < 5:
        checks.append(("Brute-Force Monitoring", f"{failed_count} failures", "PASS", "Normal authentication activity."))
    else:
        checks.append(("Brute-Force Monitoring", f"{failed_count} failures", "WARN", "Elevated authentication failure rate detected."))
        total_score -= 10

    # 6. Security Patches
    updates = run_cmd("/usr/lib/update-notifier/apt-check 2>/dev/null")
    if updates:
        up_list = updates.split(';')
        sec_updates = int(up_list[1]) if len(up_list) > 1 and up_list[1].isdigit() else 0
        if sec_updates == 0:
            checks.append(("Security Patches", "UP-TO-DATE", "PASS", "All critical security patches are installed."))
        else:
            checks.append(("Security Patches", f"{sec_updates} pending", "WARN", "Security patches available."))
            total_score -= 15
    else:
        checks.append(("Security Patches", "CHECK_MANUAL", "INFO", "Automated patch check skipped."))

    total_score = max(0, total_score)

    # Console Output
    for title, status, res, desc in checks:
        if res == "PASS":
            badge = f"{GREEN}[ PASS ]{RESET}"
        elif res == "WARN":
            badge = f"{YELLOW}[ WARN ]{RESET}"
        elif res == "INFO":
            badge = f"{CYAN}[ INFO ]{RESET}"
        else:
            badge = f"{RED}[ FAIL ]{RESET}"
        print(f"{badge} {BOLD}{title:<30}{RESET} -> {status}")

    print("\n" + "=" * 60)
    score_color = GREEN if total_score >= 80 else (YELLOW if total_score >= 50 else RED)
    print(f"{BOLD}FINAL HARDENING SCORE: {score_color}{total_score}/100{RESET}")
    print("=" * 60)

    generate_html_report(hostname, ip_addr, timestamp, total_score, checks)
    print(f"\n{CYAN}[+] Interactive executive report generated:{RESET} {BOLD}audit_report.html{RESET}\n")

def generate_html_report(hostname, ip_addr, timestamp, score, checks):
    color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
    rows = ""
    for title, status, res, desc in checks:
        badge_bg = "#064e3b" if res == "PASS" else ("#78350f" if res == "WARN" else ("#0f2942" if res == "INFO" else "#7f1d1d"))
        badge_fg = "#34d399" if res == "PASS" else ("#fbbf24" if res == "WARN" else ("#38bdf8" if res == "INFO" else "#f87171"))
        rows += f"""
        <tr>
            <td style="font-weight:700; color:#f8fafc;">{title}</td>
            <td><span style="background:{badge_bg}; color:{badge_fg}; padding:4px 10px; border-radius:6px; font-weight:800; font-size:12px;">{res}</span></td>
            <td style="color:#cbd5e1; font-family:monospace;">{status}</td>
            <td style="color:#94a3b8; font-size:13px;">{desc}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Hardening Report - {hostname}</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }}
        body {{ background: #0b1120; color: #f8fafc; padding: 30px 20px; }}
        .wrapper {{ max-width: 900px; margin: 0 auto; }}
        .header {{ background: #131d35; border: 1px solid #1e293b; border-radius: 16px; padding: 24px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }}
        .score-box {{ text-align: center; background: #0b1120; border: 2px solid {color}; border-radius: 16px; padding: 16px 24px; }}
        .score-num {{ font-size: 40px; font-weight: 800; color: {color}; line-height: 1; }}
        .score-lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #131d35; border: 1px solid #1e293b; border-radius: 16px; overflow: hidden; }}
        th, td {{ padding: 14px 18px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 14px; }}
        th {{ background: #18233f; color: #38bdf8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        tr:last-child td {{ border-bottom: none; }}
        .meta-tag {{ display: inline-block; background: #1e293b; padding: 4px 10px; border-radius: 6px; font-size: 12px; color: #94a3b8; margin-right: 6px; margin-top: 8px; }}
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="header">
            <div>
                <h1 style="font-size:24px; font-weight:800; color:#fff; margin-bottom:4px;">Linux Hardening Audit Report</h1>
                <p style="color:#94a3b8; font-size:13px;">Automated Posture Assessment by <strong>Naif Albarqi</strong></p>
                <div>
                    <span class="meta-tag">Host: {hostname}</span>
                    <span class="meta-tag">IP: {ip_addr}</span>
                    <span class="meta-tag">Audit Date: {timestamp}</span>
                </div>
            </div>
            <div class="score-box">
                <div class="score-num">{score}</div>
                <div class="score-lbl">Security Score</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Security Control</th>
                    <th>Result</th>
                    <th>Status / Findings</th>
                    <th>Remediation & Insight</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
    with open("audit_report.html", "w") as f:
        f.write(html)

if __name__ == "__main__":
    main()
