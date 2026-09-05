#!/usr/bin/env python3
import subprocess
import datetime
import socket
import re
import urllib.request
import json

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        return res.stdout.strip()
    except Exception:
        return ""

def audit_firewall():
    out = run_cmd("sudo ufw status")
    if "Status: active" in out:
        return "PASS", "ACTIVE", "UFW is active and filtering inbound traffic."
    return "FAIL", "INACTIVE", "Firewall is inactive. Run 'sudo ufw enable'."

def audit_ssh_root():
    out = run_cmd("sudo sshd -T 2>/dev/null | grep -i '^permitrootlogin'")
    if "permitrootlogin no" in out.lower():
        return "PASS", "ENFORCED", "Direct root SSH access is strictly disabled."
    conf_check = run_cmd("grep -ri '^PermitRootLogin no' /etc/ssh/")
    if conf_check:
        return "PASS", "ENFORCED", "Direct root SSH access is strictly disabled."
    return "WARN", "PERMISSIVE", "Direct root login might be permitted over SSH."

def audit_ssh_auth():
    out = run_cmd("sudo sshd -T 2>/dev/null | grep -i '^passwordauthentication'")
    if "passwordauthentication no" in out.lower():
        return "PASS", "KEYS_ONLY", "Cryptographic key-based authentication enforced."
    conf_check = run_cmd("grep -ri '^PasswordAuthentication no' /etc/ssh/")
    if conf_check:
        return "PASS", "KEYS_ONLY", "Cryptographic key-based authentication enforced."
    return "WARN", "ALLOW_PASSWORDS", "Password authentication enabled; susceptible to brute-force."

def audit_ports():
    out = run_cmd("ss -tuln")
    risky = [p for p in [":21 ", ":23 ", ":25 "] if p in out]
    if not risky:
        return "PASS", "CLEAN", "No risky legacy ports detected."
    return "WARN", f"EXPOSED {len(risky)}", f"High risk legacy ports found: {', '.join(risky)}"

def audit_fail2ban():
    out = run_cmd("sudo fail2ban-client status sshd 2>/dev/null")
    if "Status for the jail: sshd" in out:
        banned = "0"
        for line in out.splitlines():
            if "Currently banned:" in line:
                banned = line.split(":")[-1].strip()
        return "PASS", "ACTIVE", f"Fail2ban is actively guarding SSH. Currently banned IPs: {banned}."
    return "WARN", "INACTIVE", "Fail2ban is not active on sshd service."

def get_threat_intel():
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

    pattern = r"(?:Failed password for|authentication failure).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    matches = re.findall(pattern, logs)
    ip_counts = {}
    for ip in matches:
        if ip not in ["127.0.0.1", "0.0.0.0"]:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    threat_list = []
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        origin = "Private/Unknown Origin"
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
            req = urllib.request.Request(url, headers={'User-Agent': 'SecurityAuditBot/1.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                if data.get('status') == 'success':
                    origin = f"{data.get('country')}, {data.get('city')} ({data.get('isp')})"
        except Exception:
            pass
        threat_list.append({"ip": ip, "attempts": count, "origin": origin})

    return threat_list

def generate_report():
    checks = [
        {"name": "Firewall Protection (UFW)", "func": audit_firewall, "weight": 20},
        {"name": "SSH Root Login Policy", "func": audit_ssh_root, "weight": 20},
        {"name": "SSH Key-Only Auth", "func": audit_ssh_auth, "weight": 20},
        {"name": "Intrusion Prevention (Fail2ban)", "func": audit_fail2ban, "weight": 20},
        {"name": "Network Attack Surface", "func": audit_ports, "weight": 20}
    ]

    total_score = 0
    results = []
    print("\n--- [ 1. Running System Hardening Engine ] ---")
    for c in checks:
        status, val, desc = c["func"]()
        score = c["weight"] if status == "PASS" else (c["weight"] // 2 if status == "WARN" else 0)
        total_score += score
        results.append({
            "control": c["name"],
            "result": status,
            "status": val,
            "desc": desc
        })
        print(f"[{status}] {c['name']}: {val}")

    print("\n--- [ 2. Harvesting Threat Intelligence & Geolocation ] ---")
    threats = get_threat_intel()
    print(f"[+] Discovered {len(threats)} active threat sources in logs.")

    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    for r in results:
        badge_cls = "badge-pass" if r["result"] == "PASS" else ("badge-warn" if r["result"] == "WARN" else "badge-fail")
        rows_html += f"""
        <tr>
            <td class="bold">{r['control']}</td>
            <td><span class="badge {badge_cls}">{r['result']}</span></td>
            <td><code>{r['status']}</code></td>
            <td class="desc">{r['desc']}</td>
        </tr>
        """

    threat_rows = ""
    if threats:
        for t in threats:
            threat_rows += f"""
            <tr>
                <td class="bold"><code>{t['ip']}</code></td>
                <td><span class="badge badge-fail">{t['attempts']} Attempts</span></td>
                <td class="desc">{t['origin']}</td>
            </tr>
            """
    else:
        threat_rows = """
        <tr>
            <td colspan="3" style="text-align:center; color: #10b981; padding: 20px;">
                No unauthorized brute-force attempts detected. Host perimeter is silent.
            </td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Operations Dashboard - Naif Albarqi</title>
    <style>
        :root {{ --bg: #0b1120; --card: #0f172a; --border: #1e293b; --text: #f8fafc; --muted: #94a3b8; --green: #10b981; --warn: #f59e0b; --fail: #ef4444; --accent: #38bdf8; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 30px; margin-bottom: 24px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }}
        .title h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
        .meta {{ color: var(--muted); font-size: 14px; margin-bottom: 12px; }}
        .pills {{ display: flex; gap: 8px; font-size: 12px; }}
        .pill {{ background: #1e293b; padding: 4px 10px; border-radius: 6px; border: 1px solid #334155; }}
        .score-box {{ background: rgba(16,185,129,0.1); border: 2px solid var(--green); border-radius: 12px; padding: 18px 24px; text-align: center; min-width: 130px; }}
        .score-box .num {{ font-size: 46px; font-weight: 800; color: var(--green); line-height: 1; }}
        .score-box .lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-top: 4px; }}
        .section-title {{ font-size: 18px; margin: 32px 0 14px 0; color: var(--accent); display: flex; align-items: center; gap: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; margin-bottom: 20px; }}
        th {{ background: #162032; text-align: left; padding: 14px 18px; font-size: 12px; text-transform: uppercase; color: var(--accent); letter-spacing: 0.5px; }}
        td {{ padding: 16px 18px; border-bottom: 1px solid var(--border); font-size: 14px; }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-align: center; }}
        .badge-pass {{ background: rgba(16,185,129,0.15); color: var(--green); }}
        .badge-warn {{ background: rgba(245,158,11,0.15); color: var(--warn); }}
        .badge-fail {{ background: rgba(239,68,68,0.15); color: var(--fail); }}
        .bold {{ font-weight: 600; }}
        code {{ background: #090d16; padding: 3px 6px; border-radius: 4px; color: var(--accent); font-family: monospace; font-size: 13px; }}
        .desc {{ color: var(--muted); line-height: 1.4; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <h1>Cloud Security Operations Dashboard</h1>
                <div class="meta">Automated Hardening Engine & Threat Telemetry by <strong>Naif Albarqi</strong></div>
                <div class="pills">
                    <span class="pill">Host: {hostname}</span>
                    <span class="pill">Private IP: {ip}</span>
                    <span class="pill">Timestamp: {now_str}</span>
                </div>
            </div>
            <div class="score-box">
                <div class="num">{total_score}</div>
                <div class="lbl">Hardening Score</div>
            </div>
        </div>

        <div class="section-title">🛡️ System Security Baseline Controls</div>
        <table>
            <thead>
                <tr>
                    <th>Security Control</th>
                    <th>Result</th>
                    <th>Status / Mode</th>
                    <th>Audit Finding</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <div class="section-title">📡 Live SSH Threat Intelligence Feed (SOC Telemetry)</div>
        <table>
            <thead>
                <tr>
                    <th>Targeted IP</th>
                    <th>Volume</th>
                    <th>Geolocation & Origin Details</th>
                </tr>
            </thead>
            <tbody>
                {threat_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    with open("audit_report.html", "w") as f:
        f.write(html)
    with open("index.html", "w") as f:
        f.write(html)
    print(f"\n[+] Assessment & Threat Harvesting Complete. Score: {total_score}/100")
    print("[+] Dashboard exported to audit_report.html & index.html")

if __name__ == "__main__":
    generate_report()
