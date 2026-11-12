import base64
import json
import os
import secrets
import sqlite3
import subprocess
import uuid as uuidlib
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

PANEL_DIR = Path("/opt/paradise-panel")
DB_PATH = PANEL_DIR / "panel.db"
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
INBOUND_PORT = 8443
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        uuid TEXT UNIQUE NOT NULL,
        expire_at TEXT NOT NULL,
        traffic_limit INTEGER DEFAULT 0,
        traffic_used INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)
    if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
        h = bcrypt.hashpw(ADMIN_PASS.encode(), bcrypt.gensalt()).decode()
        conn.execute("INSERT INTO admins (password_hash) VALUES (?)", (h,))
    conn.commit()
    conn.close()

def write_xray_config():
    try:
        conn = db()
        rows = conn.execute("SELECT * FROM users WHERE enabled=1").fetchall()
        conn.close()
    except Exception:
        rows = []

    now = datetime.utcnow().isoformat()
    clients = []
    for u in rows:
        if u["expire_at"] < now:
            continue
        if u["traffic_limit"] > 0 and u["traffic_used"] >= u["traffic_limit"]:
            continue
        clients.append({"id": u["uuid"], "email": u["email"]})

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "vless-in", "listen": "0.0.0.0", "port": INBOUND_PORT,
            "protocol": "vless", "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "none"}
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }

    try:
        XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        XRAY_CONFIG.write_text(json.dumps(cfg, indent=2))
        subprocess.run(["systemctl", "restart", "xray"], capture_output=True, timeout=15)
    except Exception:
        pass

bearer = HTTPBearer(auto_error=False)

def make_token():
    return jwt.encode({"sub": "admin", "exp": datetime.utcnow() + timedelta(hours=24)}, JWT_SECRET, algorithm="HS256")

def require_admin(c: HTTPAuthorizationCredentials = Depends(bearer)):
    if not c:
        raise HTTPException(401, "توکن ارسال نشده")
    try:
        jwt.decode(c.credentials, JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(401, "توکن نامعتبر")

app = FastAPI(title="Paradise Panel")

@app.on_event("startup")
def startup():
    init_db()
    write_xray_config()

@app.post("/api/login")
def login(req: dict):
    conn = db()
    row = conn.execute("SELECT password_hash FROM admins WHERE id=1").fetchone()
    conn.close()
    if not row or not bcrypt.checkpw(req.get("password", "").encode(), row[0].encode()):
        raise HTTPException(401, "رمز عبور اشتباه است")
    return {"token": make_token()}

@app.get("/api/users")
def list_users(_=Depends(require_admin)):
    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/users")
def create_user(req: dict, _=Depends(require_admin)):
    email = (req.get("email") or "").strip()
    if not email:
        raise HTTPException(400, "ایمیل الزامی است")
    try:
        days = int(req.get("days") or 30)
        traffic_gb = int(req.get("traffic_gb") or 0)
    except (TypeError, ValueError):
        raise HTTPException(400, "مقادیر نامعتبر است")

    uid = str(uuidlib.uuid4())
    expire = (datetime.utcnow() + timedelta(days=days)).isoformat()
    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (email, uuid, expire_at, traffic_limit, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, uid, expire, traffic_gb * 1024**3, datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(400, "این ایمیل قبلا ثبت شده است")
    conn.close()
    write_xray_config()
    return {"uuid": uid, "email": email}

@app.delete("/api/users/{uid}")
def delete_user(uid: int, _=Depends(require_admin)):
    conn = db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    write_xray_config()
    return {"ok": True}

@app.post("/api/users/{uid}/toggle")
def toggle_user(uid: int, _=Depends(require_admin)):
    conn = db()
    conn.execute("UPDATE users SET enabled = 1 - enabled WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    write_xray_config()
    return {"ok": True}

@app.get("/sub/{uuid}")
def subscription(uuid: str, request: Request):
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE uuid=?", (uuid,)).fetchone()
    conn.close()
    if not u or not u["enabled"]:
        raise HTTPException(404)
    host = (request.headers.get("host") or "").split(":")[0]
    link = f"vless://{uuid}@{host}:{INBOUND_PORT}?encryption=none&security=none&type=tcp#{u['email']}"
    return PlainTextResponse(base64.b64encode(link.encode()).decode())

@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML

INDEX_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>پنل مدیریت پارادایس نت</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,Tahoma,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:16px;max-width:800px;margin:0 auto;line-height:1.8}
input,button{padding:10px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:14px;font-family:inherit}
input:focus{outline:none;border-color:#6366f1}
button{background:#6366f1;cursor:pointer;border:0;font-weight:500}
button:hover{background:#4f46e5}
button.danger{background:#dc2626}
.card{background:#1e293b;padding:16px;border-radius:12px;margin-bottom:16px}
h2,h3{margin:0 0 12px;color:#f1f5f9}
table{width:100%;border-collapse:collapse}
th,td{padding:8px;text-align:right;border-bottom:1px solid #334155;font-size:13px}
th{color:#94a3b8;font-weight:500}
.error{color:#f87171;font-size:13px;margin-top:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px}
.on{background:rgba(16,185,129,.2);color:#10b981}
.off{background:rgba(239,68,68,.2);color:#ef4444}
.footer{text-align:center;font-size:12px;color:#94a3b8;margin-top:40px;line-height:2;border-top:1px solid #334155;padding-top:20px}
.footer a{color:#818cf8;text-decoration:none}
.guide{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:16px;margin-top:20px;font-size:13px}
.guide summary{cursor:pointer;font-weight:bold;color:#818cf8;font-size:15px}
.guide h4{color:#f1f5f9;margin:16px 0 8px}
.guide p{margin:0 0 8px;color:#94a3b8}
.guide code{background:#1e293b;padding:2px 6px;border-radius:4px;font-family:monospace;color:#10b981}
</style>
</head>
<body>

<div id="login" class="card" style="max-width:400px;margin:80px auto">
<h2>ورود به پنل پارادایس نت</h2>
<input id="pass" type="password" placeholder="رمز عبور" style="width:100%;margin-bottom:8px">
<button onclick="doLogin()" style="width:100%">ورود</button>
<div id="loginErr" class="error"></div>
</div>

<div id="app" style="display:none">
<h2>پنل مدیریت پارادایس نت</h2>

<div class="card">
<h3>کاربر جدید</h3>
<input id="email" placeholder="ایمیل" style="width:100%;margin-bottom:6px">
<input id="days" type="number" placeholder="روز اعتبار (پیش‌فرض ۳۰)" style="width:100%;margin-bottom:6px">
<input id="gb" type="number" placeholder="حجم گیگابایت (۰ = نامحدود)" style="width:100%;margin-bottom:6px">
<button onclick="createUser()">ساخت کاربر</button>
<div id="err" class="error"></div>
</div>

<div class="card">
<h3>کاربران</h3>
<table><thead><tr>
<th>ایمیل</th><th>وضعیت</th><th>انقضا</th><th>عملیات</th>
</tr></thead><tbody id="users"></tbody></table>
</div>

<button onclick="logout()" class="danger">خروج</button>

<details class="guide">
<summary>📖 راهنمای نصب و رفع خطاها (مطالعه کنید)</summary>
<p>سلام. من محسن زندیه هستم. این پنل رو از صفر نوشتم تا کارتون راحت باشه. اگر جایی به مشکل خوردید، این راهنما رو بخونید.</p>

<h4>⚠️ خطا: پیدا نشدن آی‌پی سرور (Could not auto-detect server IP)</h4>
<p>اگر موقع نصب، اسکریپت آی‌پی داخلی مثل 172 نشون داد و گیر کرد، یعنی سرورت پشت لایه شبکه‌ست. <code>Ctrl+C</code> بزنید و دستور <code>curl -4 ifconfig.me</code> رو اجرا کنید. عددی که داد رو دستی وارد کنید.</p>

<h4>⚠️ خطا: بالا نیامدن پنل (Connection Refused)</h4>
<p>مطمئن بشید پورت ۸۰۰۰ توی فایروال باز باشه (<code>ufw allow 8000/tcp</code>). اگر بازم درست نشد، با دستور <code>systemctl status paradise-panel</code> وضعیت سرویس رو چک کنید.</p>

<h4>⚠️ خطا: پورت ۸۰۰۰ اشغال است</h4>
<p>فایل <code>install.sh</code> رو باز کنید و عدد ۸۰۰۰ رو به ۸۰۸۰ تغییر بدید و دوباره نصب کنید.</p>
</details>

</div>

<div class="footer">
طراحی شده توسط <b>مهندس محسن زندیه</b> (کارشناسی مهندسی کامپیوتر)<br>
موسس و مدیر شرکت پارادایس نت | نفر اول جشنواره جهانی خوارزمی ۱۳۸۲<br>
تماس: ۰۹۰۵۲۳۸۸۰۸۹ - ۰۹۹۱۲۱۸۱۰۲ - ۰۹۹۰۵۲۸۸۰۸۹<br>
ایمیل: zandiehm@mail.lcc.edu | netparadaise@gmail.com<br>
<a href="http://Zandieh.runhosting.com">Zandieh.runhosting.com</a> | 
<a href="http://paradaise.runhosting.com">paradaise.runhosting.com</a> | 
<a href="http://Internet.mywp.info">Internet.mywp.info</a> | 
<a href="http://king.mywp.info">king.mywp.info</a><br>
<a href="http://paradaise.run.place">paradaise.run.place</a> | 
<a href="http://zandieh.run.place">zandieh.run.place</a>
</div>

<script>
let token = localStorage.getItem('t') || '';
const $ = id => document.getElementById(id);

if (token) showApp();

async function doLogin() {
  const r = await fetch('/api/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: $('pass').value})
  });
  if (!r.ok) { $('loginErr').textContent = 'رمز اشتباه است'; return; }
  const d = await r.json();
  token = d.token;
  localStorage.setItem('t', token);
  showApp();
}

function logout() {
  token = ''; localStorage.removeItem('t');
  $('app').style.display = 'none'; $('login').style.display = 'block'; $('pass').value = '';
}

function showApp() {
  $('login').style.display = 'none'; $('app').style.display = 'block'; loadUsers();
}

async function loadUsers() {
  const r = await fetch('/api/users', {headers: {'Authorization': 'Bearer ' + token}});
  if (r.status === 401) { logout(); return; }
  const users = await r.json();
  $('users').innerHTML = users.map(u => {
    const expired = new Date(u.expire_at) < new Date();
    const status = !u.enabled ? '<span class="badge off">خاموش</span>'
                 : expired ? '<span class="badge off">منقضی</span>'
                 : '<span class="badge on">فعال</span>';
    return '<tr><td>' + u.email + '</td><td>' + status + '</td><td>' + u.expire_at.slice(0,10) + '</td><td>' +
      '<button onclick="toggle(' + u.id + ')">' + (u.enabled?'خاموش':'روشن') + '</button> ' +
      '<button onclick="showLink(\'' + u.uuid + '\')">لینک</button> ' +
      '<button class="danger" onclick="del(' + u.id + ')">حذف</button></td></tr>';
  }).join('') || '<tr><td colspan="4" style="text-align:center;color:#64748b">هنوز کاربری نساخته‌اید</td></tr>';
}

async function createUser() {
  $('err').textContent = '';
  const r = await fetch('/api/users', {
    method: 'POST', headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
    body: JSON.stringify({email: $('email').value, days: parseInt($('days').value) || 30, traffic_gb: parseInt($('gb').value) || 0})
  });
  if (!r.ok) { const d = await r.json(); $('err').textContent = d.detail || 'خطا'; return; }
  $('email').value = ''; $('days').value = ''; $('gb').value = ''; loadUsers();
}

async function toggle(id) {
  await fetch('/api/users/' + id + '/toggle', {method: 'POST', headers: {'Authorization': 'Bearer ' + token}});
  loadUsers();
}

async function del(id) {
  if (!confirm('آیا از حذف مطمئن هستید؟')) return;
  await fetch('/api/users/' + id, {method: 'DELETE', headers: {'Authorization': 'Bearer ' + token}});
  loadUsers();
}

function showLink(uuid) {
  const base = location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '');
  const link = base + '/sub/' + uuid;
  if (navigator.clipboard) { navigator.clipboard.writeText(link); alert('لینک کپی شد:\n\n' + link); } 
  else { prompt('لینک اشتراک:', link); }
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
