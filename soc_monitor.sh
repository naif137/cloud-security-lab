#!/bin/bash
cd /home/naif/cloud-security-lab || exit 1
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1545790865681686549/3BP1wusXgGEZFG528VbYsJCGR9XK_DgNOLODmAD-P1MSjARZcCV7-BuFYPiWfyScsV6Q"

# تشغيل التدقيق وتحديث لوحة التحكم
python3 security_audit.py > /dev/null 2>&1

# تشغيل محلل التهديدات وإرسال التنبيهات إذا وُجدت
python3 alert_dispatcher.py > /dev/null 2>&1
