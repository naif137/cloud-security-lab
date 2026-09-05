import json
import subprocess
import urllib.request

def run_cmd(cmd_list):
    try:
        res = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return res.stdout.strip()
    except Exception:
        return ""

def audit_firewall():
    out = run_cmd(["sudo", "ufw", "status"])
    if "Status: active" in out:
        return "PASS", "ACTIVE", "UFW is active and filtering inbound traffic."
    return "FAIL", "INACTIVE", "Firewall is inactive. Run 'sudo ufw enable'."

def audit_ssh_root():
    out = run_cmd(["sudo", "sshd", "-T"])
    if "permitrootlogin no" in out.lower():
        return "PASS", "ENFORCED", "Direct root SSH access is strictly disabled."
    return "WARN", "PERMISSIVE", "Direct root login might be permitted over SSH."

def audit_ssh_auth():
    out = run_cmd(["sudo", "sshd", "-T"])
    if "passwordauthentication no" in out.lower():
        return "PASS", "KEYS_ONLY", "Cryptographic key-based authentication enforced."
    return "WARN", "ALLOW_PASSWORDS", "Password authentication enabled; susceptible to brute-force."

def audit_ports():
    out = run_cmd(["ss", "-tuln"])
    risky = [p for p in [":21 ", ":23 ", ":25 "] if p in out]
    if not risky:
        return "PASS", "CLEAN", "No risky legacy ports detected."
    return "WARN", f"EXPOSED {len(risky)}", f"High risk legacy ports found: {', '.join(risky)}"

def audit_fail2ban():
    out = run_cmd(["sudo", "fail2ban-client", "status", "sshd"])
    if "Status for the jail: sshd" in out:
        banned = "0"
        for line in out.splitlines():
            if "Currently banned:" in line:
                banned = line.split(":")[-1].strip()
        return "PASS", "ACTIVE", f"Fail2ban is actively guarding SSH. Currently banned IPs: {banned}."
    return "WARN", "INACTIVE", "Fail2ban is not active on sshd service."

def get_public_ip_intel():
    url = "https://ipwhois.app/json/"
    req = urllib.request.Request(url, headers={'User-Agent': 'CloudSecLab/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            return {
                "ip": data.get("ip", "Unknown"),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "org": data.get("isp", "Unknown")
            }
    except Exception:
        return {"ip": "Local/Isolated", "country": "N/A", "city": "N/A", "org": "Private Cloud"}

def run_full_audit():
    print("[*] Initiating CIS Baseline Hardening Audit...")
    intel = get_public_ip_intel()
    checks = [
        ("Firewall Protection (UFW)", audit_firewall()),
        ("SSH Root Login Policy", audit_ssh_root()),
        ("SSH Authentication Scheme", audit_ssh_auth()),
        ("Legacy Port Exposure", audit_ports()),
        ("Intrusion Prevention (Fail2ban)", audit_fail2ban())
    ]
    total = len(checks)
    passed = sum(1 for _, (status, _, _) in checks if status == "PASS")
    score = int((passed / total) * 100)
    print(f"[+] Audit Finished. Compliance Score: {score}% | Monitored IP: {intel['ip']}")
    return checks, score, intel

if __name__ == "__main__":
    run_full_audit()
