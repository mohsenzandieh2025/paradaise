#!/bin/bash
# اسکریپت نصب پنل پارادایس نت
# طراحی شده توسط مهندس محسن زندیه

set -e

if [ "$EUID" -ne 0 ]; then
  echo "لطفا با کاربر روت یا با دستور sudo اجرا کنید."
  exit 1
fi

echo "════════════════════════════════════════"
echo "  در حال نصب پنل پارادایس نت (نسخه پایتون)"
echo "════════════════════════════════════════"

apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv curl ufw openssl >/dev/null

if ! command -v xray &>/dev/null; then
  echo "[۲/۶] نصب هسته Xray..."
  bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi

mkdir -p /opt/paradise-panel
cd /opt/paradise-panel
python3 -m venv venv
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q fastapi uvicorn "python-jose[cryptography]" bcrypt

echo "[۴/۶] ایجاد سرویس..."
JWT=$(openssl rand -hex 32)
ADMIN=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

cat > /opt/paradise-panel/.env << ENV
JWT_SECRET=$JWT
ADMIN_PASS=$ADMIN
ENV
chmod 600 /opt/paradise-panel/.env

cat > /etc/systemd/system/paradise-panel.service << SVC
[Unit]
Description=Paradise Panel
After=network.target xray.service

[Service]
Type=simple
WorkingDirectory=/opt/paradise-panel
EnvironmentFile=/opt/paradise-panel/.env
ExecStart=/opt/paradise-panel/venv/bin/uvicorn panel:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable paradise-panel >/dev/null
systemctl restart paradise-panel

ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 8000/tcp >/dev/null 2>&1 || true
ufw allow 8443/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

IP=$(curl -s4 --max-time 5 ifconfig.me || echo "IP-SERVER")

echo ""
echo "════════════════════════════════════════"
echo "  ✅ نصب با موفقیت انجام شد"
echo "════════════════════════════════════════"
echo "  آدرس پنل:  http://$IP:8000"
echo "  رمز عبور:  $ADMIN"
echo "  پورت پروکسی: 8443"
echo "════════════════════════════════════════"
