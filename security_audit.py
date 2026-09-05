#!/usr/bin/env python3
"""
Linux Security Audit & Health Check Tool
Phase 1: Foundation Project
Author: Naif Albarqi
"""

import os
import subprocess
import socket
from datetime import datetime

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing command: {e}"

def print_section(title):
    print("\n" + "=" * 50)
    print(f"[*] {title}")
    print("=" * 50)

def main():
    print(f"\n--- System Security Audit Report ---")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. System Info
    print_section("Host & Network Identification")
    hostname = socket.gethostname()
    print(f"Hostname: {hostname}")
    ip_addrs = run_command("hostname -I")
    print(f"Local IP Addresses: {ip_addrs}")

    # 2. Open Listening Ports
    print_section("Active Listening Ports")
    ports = run_command("ss -tuln | grep LISTEN")
    if ports:
        print(ports)
    else:
        print("No active listening ports detected.")

    # 3. Firewall Status (UFW)
    print_section("Firewall (UFW) Status")
    ufw_status = run_command("sudo ufw status")
    print(ufw_status if ufw_status else "UFW not configured or root required.")

    # 4. Failed SSH Login Attempts
    print_section("Recent Failed Authentication Attempts")
    auth_log = "/var/log/auth.log"
    if os.path.exists(auth_log):
        failed_logins = run_command("grep 'Failed password' /var/log/auth.log | tail -n 5")
        print(failed_logins if failed_logins else "No recent failed password attempts found.")
    else:
        journal_check = run_command("journalctl -u ssh -n 5 --no-pager | grep -i 'failed'")
        print(journal_check if journal_check else "No failed SSH records found in systemd journal.")

    print("\n[+] Audit Complete. Evidence logged.\n")

if __name__ == "__main__":
    main()
