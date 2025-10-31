#!/bin/bash
# ZIVPN UDP Server + Web UI (Myanmar)
# Author mix: Zahid Islam (udp-zivpn) + Khaing tweaks + KHAINGUDP UI polish
# Features: apt-guard, binary fetch fallback, UFW rules, DNAT+MASQ, sysctl forward,
#           Flask 1.x-compatible Web UI (auto-refresh 120s), users.json <-> config.json mirror sync,
#           per-user Online/Offline via conntrack, expires accepts "YYYY-MM-DD" OR days "30",
#           Web UI: Header logo + title + Messenger button, Delete button per user, CLEAN MODERN styling,
#           Login UI (form-based session, logo included) with /etc/zivpn/web.env credentials.
#
# === FINAL FIX: Correctly checks command names (ip for iproute2, netstat for net-tools) ===
set -euo pipefail

# ===== Pretty =====
B="\e[1;34m"; G="\e[1;32m"; Y="\e[1;33m"; R="\e[1;31m"; C="\e[1;36m"; M="\e[1;35m"; Z="\e[0m"
LINE="${B}────────────────────────────────────────────────────────${Z}"
say(){ echo -e "$1"; }

echo -e "\n$LINE\n${G}🌟 ZIVPN UDP Server + Web UI မောင်သုည (FINAL FIXED V3)${Z}\n$LINE"

# ===== Root check & apt guards (FIXED STRUCTURE) =====
if [ "$(id -u)" -ne 0 ];
then
  echo -e "${R} script root accept (sudo -i)${Z}";
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive

# Define packages and their corresponding commands
# Format: "command_name:package_name"
REQUIRED_PACKAGES=(
  "wget:wget"
  "curl:curl"
  "ip:iproute2"  # Command 'ip', Package 'iproute2' - FOR NETWORK CONFIG
  "ufw:ufw"      # Command 'ufw', Package 'ufw' - FOR FIREWALL
)

# === Check and Install Required Packages ===
for item in "${REQUIRED_PACKAGES[@]}"; do
    CMD="${item%:*}"      # Extract command name (e.g., 'ip')
    PKG="${item#*:}"      # Extract package name (e.g., 'iproute2')

    if ! command -v "$CMD" &>/dev/null; then
        say "${R} ${PKG} (command: ${CMD}) လိုအပ်ပါသည်။ သွင်းယူနေသည်...${Z}"
        
        # 1. Update and install the package
        apt update -qq >/dev/null 2>&1 
        apt install -y "$PKG" -qq >/dev/null 2>&1
        
        # 2. Check if the command is now available
        if ! command -v "$CMD" &>/dev/null; then
            say "${R} ${PKG} သွင်းယူ၍ မရပါ။ စစ်ဆေးပါ${Z}"
            exit 1 # Still exits if the necessary command cannot be installed
        fi
    fi
done

# net-tools check (optional, but check for 'netstat' command)
if ! command -v netstat &>/dev/null; then
  say "${Y} net-tools (command: netstat) ကို ထည့်သွင်းရန် ကြိုးစားနေသည် (မရပါက ကျော်သွားမည်)...${Z}"
  apt update -qq >/dev/null 2>&1
  # Install package 'net-tools'
  apt install -y net-tools -qq >/dev/null 2>&1 || say "${Y} net-tools မရပါ။ ဆက်လက်လုပ်ဆောင်ပါမည်။${Z}"
fi

# Check and install Python & Flask
if ! command -v python3 &>/dev/null; then
  say "${R} Python 3 လိုအပ်ပါသည်။ သွင်းယူနေသည်...${Z}"
  apt update -qq >/dev/null 2>&1
  apt install -y python3 python3-pip -qq >/dev/null 2>&1
fi
if ! python3 -c "import flask" &>/dev/null; then
  say "${R} Flask လိုအပ်ပါသည်။ သွင်းယူနေသည်...${Z}"
  pip3 install flask -qq >/dev/null 2>&1
fi

# Configuration paths
CONFIG_DIR="/etc/zivpn"
CONFIG_FILE="$CONFIG_DIR/config.json"
USERS_FILE="$CONFIG_DIR/users.json"
WEB_ENV="$CONFIG_DIR/web.env"
# === NEW SESSION TRACKING FILE ===
ACTIVE_SESSIONS_FILE="$CONFIG_DIR/active_sessions.json"
# =================================

mkdir -p "$CONFIG_DIR"

# Binary check and download logic
UDP_BINARY="/usr/bin/zivpn_udp"
UDP_BIN_URL1="https://raw.githubusercontent.com/Zahid-islam02/udp-zivpn/main/zivpn_udp_amd64"
UDP_BIN_URL2="https://github.com/Zahid-islam02/udp-zivpn/raw/main/zivpn_udp_amd64"

if [ ! -f "$UDP_BINARY" ]; then
  say "${Y} ZIVPN UDP Binary ကို ဒေါင်းလုဒ်ဆွဲနေသည်...${Z}"
  if wget -q -O "$UDP_BINARY" "$UDP_BIN_URL1"; then
    say "${G} ဒေါင်းလုဒ်အောင်မြင်ပါသည် (Source 1)${Z}"
  elif wget -q -O "$UDP_BINARY" "$UDP_BIN_URL2"; then
    say "${G} ဒေါင်းလုဒ်အောင်မြင်ပါသည် (Source 2)${Z}"
  else
    say "${R} Binary ဒေါင်းလုဒ်မအောင်မြင်ပါ။ URL ကို စစ်ဆေးပါ${Z}"
    rm -f "$UDP_BINARY"
    exit 1
  fi
  chmod +x "$UDP_BINARY"
fi

# Default config.json
if [ ! -f "$CONFIG_FILE" ]; then
  say "${Y} Default config.json ကို ဖန်တီးနေသည်...${Z}"
  echo '{
  "listen": ":5667",
  "dns": "1.1.1.1",
  "log_level": "info",
  "users": {}
}' > "$CONFIG_FILE"
fi

# Default users.json
if [ ! -f "$USERS_FILE" ]; then
  say "${Y} Default users.json ကို ဖန်တီးနေသည်...${Z}"
  echo '{}' > "$USERS_FILE"
fi

# Web UI Credentials
if [ ! -f "$WEB_ENV" ]; then
  say "${Y} Web UI Admin Login အတွက် စကားဝှက်ကို သတ်မှတ်နေသည်...${Z}"
  ADMIN_USER=$(date +%s | sha256sum | base64 | head -c 8)
  ADMIN_PASS=$(date +%s | sha256sum | base64 | head -c 12)
  echo "ADMIN_USERNAME=\"$ADMIN_USER\"" > "$WEB_ENV"
  echo "ADMIN_PASSWORD=\"$ADMIN_PASS\"" >> "$WEB_ENV"
  say "${G} Admin Login သတ်မှတ်ပြီးပါပြီ။${Z}"
  say "${C} User: ${ADMIN_USER}${Z}"
  say "${C} Pass: ${ADMIN_PASS}${Z}"
fi

# ZIVPN Service file
SERVICE_FILE="/etc/systemd/system/zivpn-udp.service"
if [ ! -f "$SERVICE_FILE" ]; then
  say "${Y} systemd service ကို ဖန်တီးနေသည်...${Z}"
  echo "[Unit]
Description=ZIVPN UDP Tunnel Service
After=network.target

[Service]
ExecStart=$UDP_BINARY -c $CONFIG_FILE
Restart=always
User=root

[Install]
WantedBy=multi-user.target" > "$SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable zivpn-udp >/dev/null 2>&1
fi

# Flask Web UI Service file
FLASK_SERVICE_FILE="/etc/systemd/system/khaingudp-web.service"
if [ ! -f "$FLASK_SERVICE_FILE" ]; then
  say "${Y} Web UI systemd service ကို ဖန်တီးနေသည်...${Z}"
  echo "[Unit]
Description=KHAINGUDP Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=/etc/zivpn
EnvironmentFile=$WEB_ENV
ExecStart=/usr/bin/python3 /etc/zivpn/web_app.py
Restart=always

[Install]
WantedBy=multi-user.target" > "$FLASK_SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable khaingudp-web >/dev/null 2>&1
fi


# Function to create the Web UI Python code
KHAINGUDP_FLASK_CODE() {
  cat << 'EOF' > /etc/zivpn/web_app.py
# -*- coding: utf-8 -*-
# KHAINGUDP Flask Web Panel - Single Session Enforcement
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session
from datetime import datetime, timedelta
import json
import os
import subprocess
import time

# Flask App Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24) # Session အတွက် လိုအပ်သည်

# Configuration Paths
CONFIG_DIR = "/etc/zivpn"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
# === Session Tracking DB ===
ACTIVE_SESSIONS_FILE = os.path.join(CONFIG_DIR, "active_sessions.json")
# ===========================

# Admin Credentials (Environment File မှ ယူသည်)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password')

# --- Session Control Functions ---

def load_active_sessions():
    """ လက်ရှိ Active Session များကို ပြန်ယူသည် """
    if not os.path.exists(ACTIVE_SESSIONS_FILE):
        return {}
    try:
        with open(ACTIVE_SESSIONS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_active_sessions(sessions):
    """ Active Session များကို မှတ်တမ်းတင်သည် """
    try:
        with open(ACTIVE_SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=4)
        return True
    except Exception:
        return False

def delete_conntrack_entry(ip_address, user_port="5667"):
    """
    IPTables/Conntrack ကို သုံးပြီး အရင်ချိတ်ထားသူ၏ Session ကို ဖျက်ပစ်သည် (Force Disconnect)
    """
    try:
        # UDP 5667 port မှာ အဆိုပါ IP ၏ connection ကို ဖျက်သည်
        # '-D' (Delete) command သည် အင်မတန် ထိရောက်သည်
        command = ['sudo', 'conntrack', '-D', '--orig-src', ip_address, '-p', 'udp', '--dport', user_port]
        # output မလိုချင်ပါက stderr/stdout ကို /dev/null သို့ ပို့နိုင်သည်
        subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"INFO: Successfully deleted conntrack for old IP: {ip_address}")
    except Exception as e:
        print(f"ERROR: Failed to delete conntrack for {ip_address}: {e}")

# --- Utility Functions ---

def load_users():
    """ users.json မှ User စာရင်းကို ပြန်ယူသည် """
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(data):
    """ users.json ကို မှတ်တမ်းတင်သည် (Web UI မှ ပြောင်းလဲမှုများအတွက်) """
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        sync_config_with_users(data)
        return True
    except Exception:
        return False

def sync_config_with_users(users):
    """ users.json မှ config.json ကို စနစ်တကျ ပြန်လည်ရေးသားသည် """
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        # config.json ထဲက "users" section ကို အသစ်ရေးသည်
        config['users'] = users 
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

        subprocess.run(['systemctl', 'reload', 'zivpn-udp'], check=False) # service ကို reload လုပ်သည်
    except Exception as e:
        print(f"ERROR: Config sync failed: {e}")

def get_online_status(ip):
    """ IP တစ်ခု Active ဖြစ်နေခြင်းရှိမရှိ စစ်ဆေးသည် """
    try:
        # conntrack ကို သုံးပြီး UDP 5667 port မှာ active connection ရှိမရှိ စစ်သည်
        command = ['sudo', 'conntrack', '-L', '--orig-src', ip, '-p', 'udp', '--dport', '5667']
        result = subprocess.run(command, capture_output=True, text=True, timeout=1)
        # 'ESTABLISHED' or 'UNREPLIED' ကဲ့သို့သော စာသားများ ပါဝင်ပါက online ဖြစ်သည်
        return "ESTABLISHED" in result.stdout or "UNREPLIED" in result.stdout
    except Exception:
        return False

# --- Flask Routes ---

@app.before_request
def check_authentication():
    """ Login စစ်ဆေးခြင်း """
    if request.path.startswith('/static/'):
        return
    if 'logged_in' not in session and request.path not in ['/login', '/check']:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Admin Login Page """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="မှားယွင်းသော အသုံးပြုသူအမည် သို့မဟုတ် စကားဝှက်")
    
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    """ Admin Logout """
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    """ အသုံးပြုသူစာရင်းနှင့် စီမံခန့်ခွဲမှု UI """
    users = load_users()
    
    # နေ့စွဲများ စစ်ဆေးပြီး အခြေအနေ ပြင်ဆင်သည်
    now = datetime.now()
    online_users = 0
    
    # Active Sessions များကို ယူသည်
    active_sessions = load_active_sessions()
    
    # စာရင်း အသေးစိတ်အတွက် ပြင်ဆင်သည်
    user_details = []
    
    # စစ်ဆေးပြီးနောက် Active Sessions ကို မှတ်သားရန်
    updated_sessions = active_sessions.copy() 
    
    for password, data in users.items():
        # ၁။ သက်တမ်းကုန်ဆုံးမှု စစ်ဆေးခြင်း
        is_expired = False
        expire_date_str = data.get('expires', 'N/A')
        days_left = 'N/A'
        
        if expire_date_str != 'N/A':
            try:
                expire_date = datetime.strptime(expire_date_str, '%Y-%m-%d')
                if now > expire_date:
                    is_expired = True
                    days_left = 0
                else:
                    days_left = (expire_date - now).days
            except ValueError:
                # နေ့စွဲပုံစံ မှားယွင်းပါက
                pass

        # ၂။ Online/Offline အခြေအနေ စစ်ဆေးခြင်း
        online_status = "Offline"
        session_ip = 'N/A'
        
        if password in active_sessions:
            session_data = active_sessions[password]
            session_ip = session_data['ip']
            
            # Conntrack ကို သုံးပြီး တကယ့် Active Status ကို စစ်သည်
            if get_online_status(session_ip):
                online_status = "Online"
                online_users += 1
            else:
                # Conntrack မရှိတော့ရင် session ကို updated_sessions ကနေ ဖျက်လိုက်သည်
                if password in updated_sessions:
                    del updated_sessions[password]
                session_ip = 'N/A' # IP ကို ပြန်ဖျက်သည်

        # ၃။ Details ထဲသို့ ထည့်သွင်းသည်
        user_details.append({
            'password': password,
            'note': data.get('note', ''),
            'status': online_status,
            'ip': session_ip,
            'is_expired': is_expired,
            'days_left': days_left,
            'expire_date_str': expire_date_str
        })
        
    # Session ပြောင်းလဲမှုရှိရင် Save လုပ်သည်
    if updated_sessions != active_sessions:
        save_active_sessions(updated_sessions)
        
    # UI ပြသရန်အတွက် HTML ကို render လုပ်သည်
    return render_template_string(DASHBOARD_TEMPLATE, users=user_details, online_count=online_users)

@app.route('/add', methods=['POST'])
def add_user():
    """ အသုံးပြုသူအသစ် ထည့်သွင်းခြင်း """
    password = request.form.get('password')
    note = request.form.get('note')
    expires_in_days = request.form.get('days')

    if not password:
        return jsonify({'status': 'error', 'message': 'Password လိုအပ်ပါသည်'}), 400

    users = load_users()
    if password in users:
        return jsonify({'status': 'error', 'message': f'Password ({password}) ရှိပြီးသားဖြစ်သည်'}), 400

    # သက်တမ်းကုန်ဆုံးရက် တွက်ချက်ခြင်း
    if expires_in_days and expires_in_days.isdigit():
        expires_date = (datetime.now() + timedelta(days=int(expires_in_days))).strftime('%Y-%m-%d')
    else:
        expires_date = request.form.get('expires', 'N/A')

    # user data အသစ် ဖန်တီးသည်
    users[password] = {
        'expires': expires_date,
        'note': note
    }

    if save_users(users):
        return jsonify({'status': 'success', 'message': f'{password} အကောင့်ကို အောင်မြင်စွာ ထည့်သွင်းပြီးပါပြီ။'})
    return jsonify({'status': 'error', 'message': 'အကောင့်ထည့်သွင်းမှု မအောင်မြင်ပါ'}), 500

@app.route('/delete/<password>', methods=['POST'])
def delete_user(password):
    """ အသုံးပြုသူ ဖျက်ပစ်ခြင်း """
    users = load_users()
    if password in users:
        del users[password]
        
        # Session များကိုလည်း ဖျက်ပစ်သည်
        sessions = load_active_sessions()
        if password in sessions:
            # Session ကို delete ပြီး conntrack ကို ဖျက်ပစ်လိုက်သည်
            delete_conntrack_entry(sessions[password]['ip'])
            del sessions[password]
            save_active_sessions(sessions)
            
        if save_users(users):
            return jsonify({'status': 'success', 'message': f'{password} ကို ဖျက်ပစ်ပြီးပါပြီ။'})
        return jsonify({'status': 'error', 'message': 'ဖျက်ပစ်မှု မအောင်မြင်ပါ'}), 500
    
    return jsonify({'status': 'error', 'message': f'{password} ကို မတွေ့ရှိပါ'}), 404

# === ZIVPN UDP Authentication Endpoint ===
@app.route('/check', methods=['GET'])
def check_user():
    """
    ZIVPN App က User Authentication လုပ်ရန် လာရောက်ခေါ်ယူသည့် အပိုင်း (အရေးကြီးဆုံး)
    """
    password = request.args.get('pass')
    client_ip = request.remote_addr # ချိတ်ဆက်လာသူ၏ IP Address
    
    if not password:
        return jsonify(status="invalid"), 400

    users = load_users()
    if password not in users:
        return jsonify(status="invalid"), 403

    user_data = users[password]
    
    # ၁။ သက်တမ်းကုန်ဆုံးမှု စစ်ဆေးခြင်း
    if user_data.get('expires', 'N/A') != 'N/A':
        try:
            expire_date = datetime.strptime(user_data['expires'], '%Y-%m-%d')
            # သက်တမ်းကုန်ဆုံးရက်သည် ယနေ့ထက် စောပါက (၁ ရက် ထပ်ပေါင်းထည့်သည်)
            if datetime.now() > expire_date + timedelta(days=1): 
                return jsonify(status="expired"), 403 # သက်တမ်းကုန်ဆုံး
        except ValueError:
            pass # နေ့စွဲ မှားယွင်းပါက ခွင့်ပြုလိုက်သည်
    
    # ==========================================================
    # ၂။ === SINGLE SESSION ENFORCEMENT LOGIC (အရေးကြီးဆုံး) ===
    # ==========================================================
    sessions = load_active_sessions()
    
    if password in sessions:
        current_session_ip = sessions[password]['ip']
        
        # IP အတူတူဆိုရင် (ကိုယ်တိုင်ပဲ ပြန်ချိတ်တာ) - ခွင့်ပြုသည်
        if current_session_ip == client_ip:
            # last_seen ကို update လုပ်သည်
            sessions[password]['last_seen'] = datetime.now().isoformat()
            save_active_sessions(sessions)
            print(f"INFO: User {password} reconnected with same IP {client_ip}.")
            return jsonify(status="ok"), 200
        
        # IP မတူညီပါက (Sharing သို့မဟုတ် နေရာပြောင်းချိတ်သည့် အခြေအနေ)
        else:
            # Last-Man-Standing Policy: အရင်ချိတ်ထားတဲ့ IP ကို ဖြုတ်ပစ်ပြီး အသစ်ကို ခွင့်ပြုသည်
            print(f"WARNING: Sharing detected for {password}. Old IP: {current_session_ip} -> New IP: {client_ip}")
            
            # အရင်ချိတ်ထားတဲ့ IP ရဲ့ Conntrack ကို ချက်ချင်း ဖျက်ပစ်သည်
            delete_conntrack_entry(current_session_ip)
            
            # Session ကို IP အသစ်ဖြင့် အစားထိုးသည်။
            sessions[password] = {'ip': client_ip, 'last_seen': datetime.now().isoformat()}
            save_active_sessions(sessions)
            
            print(f"INFO: Old IP {current_session_ip} disconnected. New IP {client_ip} connected.")
            return jsonify(status="ok"), 200
    
    # ၃။ Session မရှိသေးပါက အကောင့်အသစ်အတွက် မှတ်သားလိုက်သည်
    else:
        sessions[password] = {'ip': client_ip, 'last_seen': datetime.now().isoformat()}
        save_active_sessions(sessions)
        print(f"INFO: New session started for {password} with IP {client_ip}.")
        return jsonify(status="ok"), 200
    # ==========================================================
    
    # Authentication အောင်မြင်ပါက
    return jsonify(status="ok"), 200


# --- HTML Templates ---

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="my">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KHAINGUDP | Login</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap');
        body { font-family: 'Padauk', sans-serif; background-color: #f0f4f8; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-container { background: #ffffff; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); width: 100%; max-width: 400px; text-align: center; }
        h2 { color: #1e40af; margin-bottom: 25px; font-weight: 700; }
        .logo-text { font-size: 28px; color: #1e40af; font-weight: 700; margin-bottom: 5px; }
        .logo-sub { font-size: 14px; color: #4b5563; margin-bottom: 25px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px 15px; margin-bottom: 15px; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; transition: border-color 0.3s; }
        input[type="text"]:focus, input[type="password"]:focus { border-color: #3b82f6; outline: none; }
        button { width: 100%; background-color: #3b82f6; color: white; padding: 12px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: background-color 0.3s, transform 0.1s; }
        button:hover { background-color: #2563eb; }
        button:active { transform: scale(0.99); }
        .error { color: #ef4444; margin-top: 15px; font-weight: 700; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-text">KHAINGUDP Panel</div>
        <div class="logo-sub">ZIVPN Admin Access</div>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="အသုံးပြုသူအမည်" required>
            <input type="password" name="password" placeholder="စကားဝှက်" required>
            <button type="submit">ဝင်ရောက်ပါ</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="my">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KHAINGUDP | စီမံခန့်ခွဲမှု</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap');
        body { font-family: 'Padauk', sans-serif; background-color: #f0f4f8; color: #333; margin: 0; padding: 0; }
        .header { background-color: #1e40af; color: white; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .logo { font-size: 24px; font-weight: 700; }
        .stats { font-size: 16px; font-weight: 600; }
        .stats span { margin-left: 20px; padding: 5px 10px; border-radius: 6px; background: rgba(255, 255, 255, 0.2); }
        .container { padding: 20px; max-width: 1200px; margin: 0 auto; }
        .action-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .add-form { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05); }
        .add-form input { padding: 10px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .add-form button { background-color: #10b981; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
        .add-form button:hover { background-color: #059669; }
        .table-container { overflow-x: auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        th { background-color: #e0f2fe; color: #1e40af; font-weight: 700; }
        tr:hover { background-color: #f9fafb; }
        .status-online { color: white; background-color: #10b981; padding: 3px 8px; border-radius: 4px; font-size: 14px; font-weight: 600; }
        .status-offline { color: white; background-color: #9ca3af; padding: 3px 8px; border-radius: 4px; font-size: 14px; font-weight: 600; }
        .status-expired { color: white; background-color: #ef4444; padding: 3px 8px; border-radius: 4px; font-size: 14px; font-weight: 600; }
        .delete-btn { background-color: #ef4444; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
        .delete-btn:hover { background-color: #dc2626; }
        .messenger-btn { background-color: #0084ff; color: white; padding: 10px 15px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block; transition: background-color 0.3s; }
        .messenger-btn:hover { background-color: #0066cc; }
        /* Mobile adjustments */
        @media (max-width: 768px) {
            .header { flex-direction: column; align-items: flex-start; }
            .stats { margin-top: 10px; }
            .stats span { margin-left: 0; margin-right: 10px; margin-top: 5px; display: inline-block; }
            .action-bar { flex-direction: column; align-items: stretch; }
            .add-form { display: grid; grid-template-columns: 1fr; gap: 10px; }
            .add-form button { margin-top: 5px; }
            .table-container { margin-top: 15px; }
            th, td { padding: 8px 10px; font-size: 14px; }
        }
    </style>
    <script>
        // အလိုအလျောက် ပြန်လည်စစ်ဆေးမှု (၁၂၀ စက္ကန့်)
        $(document).ready(function() {
            setTimeout(function() {
                location.reload();
            }, 120000); // 120 seconds
        });

        function addUser() {
            const password = $('#new_password').val();
            const note = $('#new_note').val();
            const days = $('#new_days').val();
            const expires = $('#new_expires').val();

            $.post("/add", { password: password, note: note, days: days, expires: expires })
                .done(function(data) {
                    alert(data.message);
                    location.reload();
                })
                .fail(function(xhr) {
                    const data = xhr.responseJSON;
                    alert("အမှား: " + (data ? data.message : "အကောင့်ထည့်သွင်းမှု မအောင်မြင်ပါ။"));
                });
        }

        function deleteUser(password) {
            if (confirm("Password " + password + " ကို ဖျက်ပစ်ရန် သေချာပါသလား။")) {
                $.post("/delete/" + password)
                    .done(function(data) {
                        alert(data.message);
                        location.reload();
                    })
                    .fail(function(xhr) {
                        const data = xhr.responseJSON;
                        alert("အမှား: " + (data ? data.message : "ဖျက်ပစ်မှု မအောင်မြင်ပါ။"));
                    });
            }
        }
    </script>
</head>
<body>
    <div class="header">
        <div class="logo">KHAINGUDP Panel</div>
        <div class="stats">
            <span>Online: {{ online_count }}</span>
            <span>Total Users: {{ users|length }}</span>
            <a href="https://m.me/your_messenger_id" target="_blank" class="messenger-btn">Messenger</a>
            <a href="/logout" style="color: white; margin-left: 20px; text-decoration: none; font-weight: 600;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        
        <div class="action-bar">
            <h2>အသုံးပြုသူများ စီမံခန့်ခွဲမှု</h2>
        </div>

        <div class="add-form">
            <form onsubmit="addUser(); return false;">
                <input type="text" id="new_password" placeholder="Password (ဥပမာ: user123)" required>
                <input type="text" id="new_note" placeholder="မှတ်ချက် (ဥပမာ: ကိုဇော်)" style="width: 150px;">
                <input type="number" id="new_days" placeholder="ရက်အရေအတွက် (သို့)" style="width: 100px;">
                <input type="text" id="new_expires" placeholder="သက်တမ်းကုန်ရက် (YYYY-MM-DD)" style="width: 150px;">
                <button type="submit">အကောင့်အသစ် ထည့်သွင်းမည်</button>
            </form>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Password</th>
                        <th>မှတ်ချက်</th>
                        <th>အခြေအနေ</th>
                        <th>ချိတ်ဆက်ထားသော IP</th>
                        <th>သက်တမ်းကုန်ဆုံးရက်</th>
                        <th>ကျန်ရှိရက်</th>
                        <th>လုပ်ဆောင်ချက်</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td style="font-weight: 700;">{{ user.password }}</td>
                        <td>{{ user.note }}</td>
                        <td>
                            {% if user.is_expired %}
                                <span class="status-expired">သက်တမ်းကုန်</span>
                            {% elif user.status == 'Online' %}
                                <span class="status-online">Online</span>
                            {% else %}
                                <span class="status-offline">Offline</span>
                            {% endif %}
                        </td>
                        <td>{{ user.ip }}</td>
                        <td>{{ user.expire_date_str }}</td>
                        <td>
                            {% if user.days_left != 'N/A' and user.days_left >= 0 %}
                                {{ user.days_left }} ရက်
                            {% else %}
                                N/A
                            {% endif %}
                        </td>
                        <td>
                            <button class="delete-btn" onclick="deleteUser('{{ user.password }}')">ဖျက်မည်</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
# Python code ကို ရေးသွင်းသည်
KHAINGUDP_FLASK_CODE

# Firewall နှင့် Network Configuration များ
say "${G} Firewall (UFW) နှင့် Network Forwarding များကို စတင်ချိန်ညှိနေပါသည်...${Z}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
IFACE=$(ip -4 route ls | awk '/default/ {print $5; exit}') # ip command ကို သုံးသည်
[ -n "${IFACE:-}" ] || IFACE=eth0
# DNAT 6000:19999/udp -> :5667
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
# MASQ out
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

ufw allow 5667/udp >/dev/null 2>&1 || true
ufw allow 6000:19999/udp >/dev/null 2>&1 || true
ufw allow 8080/tcp >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

# Service များကို ပြန်လည်စတင်သည်
say "${G} ZIVPN UDP Service နှင့် Web Panel များကို ပြန်လည်စတင်နေပါသည်...${Z}"
systemctl restart zivpn-udp
systemctl restart khaingudp-web

# စစ်ဆေးခြင်း
say "${G} အခြေအနေ စစ်ဆေးနေသည်...${Z}"
systemctl status zivpn-udp | grep -q "active (running)" && ZIVPN_STATUS="${G}RUNNING${Z}" || ZIVPN_STATUS="${R}FAILED${Z}"
systemctl status khaingudp-web | grep -q "active (running)" && WEB_STATUS="${G}RUNNING${Z}" || WEB_STATUS="${R}FAILED${Z}"

say "$LINE"
say "${C}ZIVPN UDP Service Status: $ZIVPN_STATUS"
say "${C}Web Panel Status: $WEB_STATUS"

if [[ "$ZIVPN_STATUS" == *RUNNING* && "$WEB_STATUS" == *RUNNING* ]]; then
  say "\n${G}🎉 အောင်မြင်စွာ ထည့်သွင်းပြီးပါပြီ။${Z}"
  say "${G} Single-Session စနစ်ကို စတင်အသုံးပြုနိုင်ပါပြီ။${Z}"
  say "\n${Y}Web Panel URL: http://$(curl -s icanhazip.com):8080${Z}"
  
  source "$WEB_ENV"
  say "${Y}Admin Username: ${ADMIN_USERNAME}${Z}"
  say "${Y}Admin Password: ${ADMIN_PASSWORD}${Z}"
else
  say "\n${R}🚧 ထည့်သွင်းမှု မအောင်မြင်ပါ။ အခြေအနေများကို စစ်ဆေးပါ။${Z}"
fi

say "$LINE"
# cleanup
unset DEBIAN_FRONTEND

