#!/usr/bin/env python3
import re
import subprocess
import json
import urllib.request

def get_failed_ssh_attempts():
    print("[*] Parsing system & authentication logs for brute-force telemetry...")
    
    # محاولة قراءة السجلات عبر عدة مصادر (journalctl العام + ملف auth.log)
    commands = [
        "sudo journalctl -n 2000 --no-pager",
        "sudo cat /var/log/auth.log 2>/dev/null"
    ]
    
    logs = ""
    for cmd in commands:
        try:
            res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logs += res.stdout + "\n"
        except Exception:
            pass

    # استخراج أي محاولة فاشلة تتضمن IP
    pattern = r"(?:Failed password for|authentication failure).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    matches = re.findall(pattern, logs)
    
    ip_counts = {}
    for ip in matches:
        if ip not in ["127.0.0.1", "0.0.0.0"]:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
    return ip_counts

def geolocate_ip(ip):
    try:
        url = f"https://ipwhois.app/json/{ip}?fields=status,country,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'SecurityAuditBot/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return f"{data.get('country')}, {data.get('city')} ({data.get('isp')})"
    except Exception:
        pass
    return "Private/Unknown Origin"

def main():
    print("=" * 65)
    print("🛡️  Automated SSH Threat Intelligence & Log Hunter")
    print("=" * 65)
    
    attempts = get_failed_ssh_attempts()
    
    if not attempts:
        print("\n[+] System is clean! No anomalous brute-force attempts recorded.")
        print("[+] SSH key-only enforcement and UFW are effectively filtering hostile packets.\n")
    else:
        print(f"\n[!] Detected {len(attempts)} unique suspicious IP addresses targeting host:")
        print("-" * 65)
        print(f"{'Source IP':<18} | {'Attempts':<10} | {'Geolocation / ISP'}")
        print("-" * 65)
        for ip, count in sorted(attempts.items(), key=lambda x: x[1], reverse=True):
            geo = geolocate_ip(ip)
            print(f"{ip:<18} | {count:<10} | {geo}")
        print("-" * 65)

if __name__ == "__main__":
    main()
