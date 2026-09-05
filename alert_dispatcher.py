#!/usr/bin/env python3
import os
import json
import datetime
import urllib.request
import urllib.parse

# ضع الروابط والمفاتيح هنا (إذا تُركت فارغة سيكتفي بالسجل المحلي دون أخطاء)
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

ALERT_LOG_PATH = "alerts.log"

def write_local_alert(alert_data):
    """توثيق التنبيه محلياً بصيغة SIEM-ready JSON"""
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(json.dumps(alert_data) + "\n")
    print(f"[+] Alert logged locally to {ALERT_LOG_PATH}")

def send_discord_alert(title, description, fields):
    """إرسال بطاقة تنبيه حمراء إلى Discord"""
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {
        "username": "Cloud Security SOC",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1022/1022382.png",
        "embeds": [{
            "title": f"🚨 {title}",
            "description": description,
            "color": 15158332, # أحمر تحذيري
            "fields": fields,
            "footer": {"text": "Host: cloud-security-lab | Automated Defense Engine"},
            "timestamp": datetime.datetime.utcnow().isoformat()
        }]
    }
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SecuritySOC/1.0"}
        )
        urllib.request.urlopen(req, timeout=5)
        print("[+] Discord SOC alert sent successfully.")
    except Exception as e:
        print(f"[-] Discord dispatch failed: {e}")

def send_telegram_alert(message):
    """إرسال رسالة تحذيرية إلى Telegram"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
        print("[+] Telegram SOC alert sent successfully.")
    except Exception as e:
        print(f"[-] Telegram dispatch failed: {e}")

def trigger_security_alert(alert_type, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. التوثيق في السجل المحلي
    alert_payload = {
        "timestamp": timestamp,
        "type": alert_type,
        "details": details
    }
    write_local_alert(alert_payload)
    
    # 2. تجهيز وإرسال تنبيه Discord
    discord_fields = [{"name": k, "value": str(v), "inline": True} for k, v in details.items()]
    send_discord_alert(
        title=f"SECURITY INCIDENT: {alert_type}",
        description=f"Automated threat response triggered at `{timestamp}`.",
        fields=discord_fields
    )
    
    # 3. تجهيز وإرسال تنبيه Telegram
    tg_lines = [f"🚨 *SECURITY INCIDENT: {alert_type}*", f"🕒 `{timestamp}`", ""]
    for k, v in details.items():
        tg_lines.append(f"• *{k}*: `{v}`")
    send_telegram_alert("\n".join(tg_lines))

if __name__ == "__main__":
    # محاكاة إشعار هجوم تجريبي لاختبار المنظومة
    print("--- Testing Unified Alert Dispatcher ---")
    mock_details = {
        "Attacker IP": "1.1.1.1",
        "Target Service": "SSH (Port 22)",
        "Failed Attempts": "8",
        "Geolocation": "Australia, South Brisbane",
        "Action Taken": "Blocked via Fail2ban"
    }
    trigger_security_alert("SSH Brute-Force Detected", mock_details)
