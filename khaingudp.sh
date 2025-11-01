#!/bin/bash
# ZIVPN UDP Server + Web UI (Myanmar) - DEVICE LIMITATION VERSION
# Author: Zahid Islam (udp-zivpn) + Khaing tweaks + KHAINGUDP UI polish + Device Limitation
# Features: One Account = One Device Only, Connection Tracking, Auto-Kick Duplicates
set -euo pipefail

# ===== Pretty =====
B="\e[1;34m"; G="\e[1;32m"; Y="\e[1;33m"; R="\e[1;31m"; C="\e[1;36m"; M="\e[1;35m"; Z="\e[0m"
LINE="${B}────────────────────────────────────────────────────────${Z}"
say(){ echo -e "$1"; }

echo -e "\n$LINE\n${G}🌟 ZIVPN UDP Server + Web UI (ONE DEVICE PER ACCOUNT) ${Z}\n$LINE"

# ===== Root check & apt guards =====
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${R} script root accept (sudo -i)${Z}";
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive

wait_for_apt() {
  echo -e "${Y}⏳ wait apt 3 min ${Z}"
  for _ in $(seq 1 60); do
    if pgrep -x apt-get >/dev/null || pgrep -x apt >/dev/null || pgrep -f 'apt.systemd.daily' >/dev/null || \
pgrep -x unattended-upgrade >/dev/null; then
      sleep 5
    else
      return 0
    fi
  done
  echo -e "${Y}⚠️ apt timers ကို ယာယီရပ်နေပါတယ်${Z}"
  systemctl stop --now unattended-upgrades.service 2>/dev/null || true
  systemctl stop --now apt-daily.service apt-daily.timer 2>/dev/null || true
  systemctl stop --now apt-daily-upgrade.service apt-daily-upgrade.timer 2>/dev/null || true
}

apt_guard_start(){
  wait_for_apt
  CNF_CONF="/etc/apt/apt.conf.d/50command-not-found"
  if [ -f "$CNF_CONF" ]; then mv "$CNF_CONF" "${CNF_CONF}.disabled"; CNF_DISABLED=1; else CNF_DISABLED=0; fi
}
apt_guard_end(){
  dpkg --configure -a >/dev/null 2>&1 || true
  apt-get -f install -y >/dev/null 2>&1 || true
  if [ "${CNF_DISABLED:-0}" = "1" ] && [ -f "${CNF_CONF}.disabled" ]; then mv "${CNF_CONF}.disabled" "$CNF_CONF"; fi
}

# ===== Packages =====
say "${Y}📦 Packages တင်နေပါတယ်...${Z}"
apt_guard_start
apt-get update -y -o APT::Update::Post-Invoke-Success::= -o APT::Update::Post-Invoke::= >/dev/null
apt-get install -y curl ufw jq python3 python3-flask python3-apt iproute2 conntrack ca-certificates >/dev/null || \
{
  apt-get install -y -o DPkg::Lock::Timeout=60 python3-apt >/dev/null || true
  apt-get install -y curl ufw jq python3 python3-flask iproute2 conntrack ca-certificates >/dev/null
}
apt_guard_end

# stop old services
systemctl stop zivpn.service 2>/dev/null || true
systemctl stop zivpn-web.service 2>/dev/null || true

# ===== Paths =====
BIN="/usr/local/bin/zivpn"
CFG="/etc/zivpn/config.json"
USERS="/etc/zivpn/users.json"
DEVICES="/etc/zivpn/devices.json"  # New: Device tracking database
ENVF="/etc/zivpn/web.env"
mkdir -p /etc/zivpn

# ===== Initialize Device Database =====
if [ ! -f "$DEVICES" ]; then
    echo '{}' > "$DEVICES"
    chmod 644 "$DEVICES"
fi

# ===== Download ZIVPN binary =====
say "${Y}⬇️ ZIVPN binary ကို ဒေါင်းနေပါတယ်...${Z}"
PRIMARY_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
FALLBACK_URL="https://github.com/zahidbd2/udp-zivpn/releases/latest/download/udp-zivpn-linux-amd64"
TMP_BIN="$(mktemp)"
if ! curl -fsSL -o "$TMP_BIN" "$PRIMARY_URL"; then
  echo -e "${Y}Primary URL မရ — latest ကို စမ်းပါတယ်...${Z}"
  curl -fSL -o "$TMP_BIN" "$FALLBACK_URL"
fi
install -m 0755 "$TMP_BIN" "$BIN"
rm -f "$TMP_BIN"

# ===== Base config =====
if [ ! -f "$CFG" ]; then
  say "${Y}🧩 config.json ဖန်တီးနေပါတယ်...${Z}"
  curl -fsSL -o "$CFG" "https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json" || echo '{}' > "$CFG"
fi

# ===== Certs =====
if [ ! -f /etc/zivpn/zivpn.crt ] || [ ! -f /etc/zivpn/zivpn.key ];
then
  say "${Y}🔐 SSL စိတျဖိုင်တွေ ဖန်တီးနေပါတယ်...${Z}"
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=MM/ST=Yangon/L=Yangon/O=KHAINGUDP/OU=Net/CN=khaingudp" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1
fi

# ===== Web Admin =====
say "${Y}🔒 Web Admin Login UI ${Z}"
read -r -p "Web Admin Username (Enter=disable): " WEB_USER
if [ -n "${WEB_USER:-}" ];
then
  read -r -s -p "Web Admin Password: " WEB_PASS; echo
  if command -v openssl >/dev/null 2>&1;
  then
    WEB_SECRET="$(openssl rand -hex 32)"
  else
    WEB_SECRET="$(python3 - <<'PY'
import secrets;print(secrets.token_hex(32))
PY
)"
  fi
  {
    echo "WEB_ADMIN_USER=${WEB_USER}"
    echo "WEB_ADMIN_PASSWORD=${WEB_PASS}"
    echo "WEB_SECRET=${WEB_SECRET}"
  } > "$ENVF"
  chmod 600 "$ENVF"
  say "${G}✅ Web login UI ON ${Z}"
else
  rm -f "$ENVF" 2>/dev/null || true
  say "${Y}ℹ️ Web login UI OFF (dev mode)${Z}"
fi

# ===== Ask initial VPN passwords =====
say "${G}🔏 VPN Password List (tutorial) eg: khaing,alice,pass1${Z}"
read -r -p "Passwords (Enter=zi): " input_pw
if [ -z "${input_pw:-}" ];
then PW_LIST='["zi"]'; else
  PW_LIST=$(echo "$input_pw" | awk -F',' '{
    printf("["); for(i=1;i<=NF;i++){gsub(/^ *| *$/,"",$i); printf("%s\"%s\"", (i>1?",":""), $i)}; printf("]")
  }')
fi

# ===== Server IP =====
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "${SERVER_IP:-}" ]; then
  SERVER_IP=$(curl -s icanhazip.com || echo "127.0.0.1")
fi

# ===== Update config.json =====
if jq . >/dev/null 2>&1 <<<'{}'; then
  TMP=$(mktemp)
  jq --argjson pw "$PW_LIST" --arg ip "$SERVER_IP" '
    .auth.mode = "passwords" |
    .auth.config = $pw |
    .listen = (."listen" // ":5667") |
    .cert = "/etc/zivpn/zivpn.crt" |
    .key  = "/etc/zivpn/zivpn.key" |
    .obfs = (."obfs" // "zivpn") |
    .server = $ip
  ' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
fi
[ -f "$USERS" ] || echo "[]" > "$USERS"
chmod 644 "$CFG" "$USERS"

# ===== Create Device Monitoring Service =====
say "${Y}🛡️ Device Limitation System ထည့်သွင်းနေပါတယ်...${Z}"

# Create device monitoring script
cat >/usr/local/bin/zivpn-monitor.sh <<'MONITOR'
#!/bin/bash
# ZIVPN Device Monitor - One Device Per Account
# Monitors and limits concurrent connections per user

DEVICES_DB="/etc/zivpn/devices.json"
LOG_FILE="/var/log/zivpn-monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

get_user_from_conn() {
    local src_ip="$1"
    local src_port="$2"
    
    # Try to find user by source IP and port in conntrack
    CONN_INFO=$(conntrack -L -p udp 2>/dev/null | grep "src=$src_ip sport=$src_port" | head -1)
    
    if [ -n "$CONN_INFO" ]; then
        # Extract destination port
        DST_PORT=$(echo "$CONN_INFO" | grep -o 'dport=[0-9]*' | cut -d= -f2)
        
        if [ -n "$DST_PORT" ]; then
            # Find user by port in users.json
            USER_INFO=$(jq -r --arg port "$DST_PORT" '.[] | select(.port == $port) | .user' /etc/zivpn/users.json 2>/dev/null)
            if [ -n "$USER_INFO" ]; then
                echo "$USER_INFO"
                return 0
            fi
        fi
    fi
    echo ""
    return 1
}

update_device_db() {
    local user="$1"
    local device_id="$2"
    local action="$3"  # connect or disconnect
    
    # Create temp file
    TMP_DB=$(mktemp)
    
    if [ "$action" = "connect" ]; then
        # Add or update device connection
        jq --arg user "$user" --arg device "$device_id" \
           '.[$user] = {
            device_id: $device,
            last_seen: (now | floor),
            connect_time: (now | floor),
            ip_address: "'"$4"'"
           }' "$DEVICES_DB" > "$TMP_DB"
    else
        # Remove device entry
        jq --arg user "$user" 'del(.[$user])' "$DEVICES_DB" > "$TMP_DB"
    fi
    
    # Atomic replace
    mv "$TMP_DB" "$DEVICES_DB"
    chmod 644 "$DEVICES_DB"
}

check_device_limit() {
    local user="$1"
    local new_device_id="$2"
    local src_ip="$3"
    
    # Read current device info
    CURRENT_DEVICE=$(jq -r --arg user "$user" '.[$user] // empty' "$DEVICES_DB")
    
    if [ -n "$CURRENT_DEVICE" ]; then
        CURRENT_DEVICE_ID=$(echo "$CURRENT_DEVICE" | jq -r '.device_id')
        LAST_SEEN=$(echo "$CURRENT_DEVICE" | jq -r '.last_seen')
        CURRENT_IP=$(echo "$CURRENT_DEVICE" | jq -r '.ip_address')
        
        # Check if this is the same device reconnecting
        if [ "$CURRENT_DEVICE_ID" = "$new_device_id" ]; then
            # Update last seen time
            update_device_db "$user" "$new_device_id" "connect" "$src_ip"
            log "Device reconnected: $user - $new_device_id"
            echo "ALLOW"
            return 0
        else
            # Different device trying to connect
            log "BLOCKED: User $user already connected from device $CURRENT_DEVICE_ID (New: $new_device_id)"
            echo "BLOCK"
            return 1
        fi
    else
        # New connection, allow it
        update_device_db "$user" "$new_device_id" "connect" "$src_ip"
        log "New connection: $user - $new_device_id"
        echo "ALLOW"
        return 0
    fi
}

cleanup_old_connections() {
    CURRENT_TIME=$(date +%s)
    TMP_DB=$(mktemp)
    
    jq --argjson now "$CURRENT_TIME" '
    with_entries(
        select(.value.last_seen > ($now - 300))  # Keep entries seen in last 5 minutes
    )' "$DEVICES_DB" > "$TMP_DB"
    
    mv "$TMP_DB" "$DEVICES_DB"
}

# Main monitoring loop
log "ZIVPN Device Monitor started"

while true; do
    # Clean up old connections every minute
    cleanup_old_connections
    
    # Monitor active connections
    conntrack -L -p udp 2>/dev/null | while read -r conn; do
        if echo "$conn" | grep -q "dport=5667"; then
            SRC_IP=$(echo "$conn" | grep -o 'src=[0-9.]*' | cut -d= -f2)
            SRC_PORT=$(echo "$conn" | grep -o 'sport=[0-9]*' | cut -d= -f2)
            
            if [ -n "$SRC_IP" ] && [ -n "$SRC_PORT" ]; then
                USER=$(get_user_from_conn "$SRC_IP" "$SRC_PORT")
                if [ -n "$USER" ]; then
                    # Generate device ID from IP and port
                    DEVICE_ID="${SRC_IP}:${SRC_PORT}"
                    
                    # Check device limit
                    RESULT=$(check_device_limit "$USER" "$DEVICE_ID" "$SRC_IP")
                    
                    if [ "$RESULT" = "BLOCK" ]; then
                        # Block duplicate connection
                        CONNTRACK_ENTRY=$(echo "$conn" | grep -o 'src=[0-9.]* sport=[0-9]* dst=[0-9.]* dport=[0-9]*')
                        if [ -n "$CONNTRACK_ENTRY" ]; then
                            conntrack -D -p udp --orig-src "$SRC_IP" --orig-sport "$SRC_PORT" 2>/dev/null
                            log "Blocked duplicate connection: $USER from $DEVICE_ID"
                        fi
                    fi
                fi
            fi
        fi
    done
    
    sleep 10
done
MONITOR

chmod +x /usr/local/bin/zivpn-monitor.sh

# ===== Create Enhanced ZIVPN Service with Device Limitation =====
say "${Y}🧰 systemd service (zivpn) ကို သွင်းနေပါတယ်...${Z}"
cat >/etc/systemd/system/zivpn.service <<'EOF'
[Unit]
Description=ZIVPN UDP Server with Device Limitation
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStartPre=/usr/local/bin/zivpn-monitor.sh &
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# ===== Enhanced Web Panel with Device Information =====
say "${Y}🖥️ Web Panel (Flask) ကို ထည့်နေပါတယ်...${Z}"
cat >/etc/zivpn/web.py <<'PY'
from flask import Flask, jsonify, render_template_string, request, redirect, url_for, session, make_response
import json, re, subprocess, os, tempfile, hmac
from datetime import datetime, timedelta

USERS_FILE = "/etc/zivpn/users.json"
DEVICES_FILE = "/etc/zivpn/devices.json"
CONFIG_FILE = "/etc/zivpn/config.json"
LISTEN_FALLBACK = "5667"
RECENT_SECONDS = 120
LOGO_URL = "https://raw.githubusercontent.com/BaeGyee9/khaing/main/logo.png"

HTML = """<!doctype html>
<html lang="my"><head><meta charset="utf-8">
<title>မောင်သုည ZIVPN Panel - One Device Per Account</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="120">
<link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg: #1e1e1e; --fg: #f0f0f0; --card: #2d2d2d; --bd: #444;
  --header-bg: #2d2d2d; --ok: #27ae60; --bad: #c0392b; --unknown: #f39c12;
  --expired: #8e44ad; --info: #3498db; --success: #1abc9c; --delete-btn: #e74c3c;
  --primary-btn: #3498db; --logout-btn: #e67e22; --telegram-btn: #0088cc;
  --input-text: #fff; --shadow: 0 4px 15px rgba(0,0,0,0.5); --radius: 8px;
  --user-icon: #f1c40f; --pass-icon: #e74c3c; --expires-icon: #9b59b6;
  --port-icon: #3498db; --device-icon: #1abc9c;
}
html,body{background:var(--bg);color:var(--fg);font-family:'Padauk',sans-serif;line-height:1.6}
body{margin:0;padding:10px}.container{max-width:1300px;margin:auto;padding:10px}

@keyframes colorful-shift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

header{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:15px;margin-bottom:25px;background:var(--header-bg);border-radius:var(--radius);box-shadow:var(--shadow)}
.header-left{display:flex;align-items:center;gap:15px}h1{margin:0;font-size:1.6em;font-weight:700}
.colorful-title, .login-card h3 {font-size:1.8em;font-weight:900;background:linear-gradient(90deg,#FF0000,#FF8000,#FFFF00,#00FF00,#00FFFF,#0000FF,#8A2BE2,#FF0000);background-size:300% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:colorful-shift 8s linear infinite;text-shadow:0 0 5px rgba(255,255,255,0.4)}
.sub{color:var(--fg);font-size:.9em}.logo{height:50px;width:auto;border-radius:10px;border:2px solid var(--fg)}
.admin-name{color:var(--user-icon);font-weight:700}

.btn{padding:10px 18px;border-radius:var(--radius);border:none;color:white;text-decoration:none;white-space:nowrap;cursor:pointer;transition:all 0.3s ease;font-weight:700;box-shadow:0 4px 6px rgba(0,0,0,0.3);display:flex;align-items:center;gap:8px}
.btn.primary{background:var(--primary-btn)}.btn.primary:hover{background:#2980b9}
.btn.save{background:var(--success)}.btn.save:hover{background:#16a085}
.btn.delete{background:var(--delete-btn)}.btn.delete:hover{background:#9e342b}
.btn.logout{background:var(--logout-btn)}.btn.logout:hover{background:#d35400}
.btn.contact{background:var(--telegram-btn);color:white}.btn.contact:hover{background:#006799}
.btn.kick{background:var(--unknown)}.btn.kick:hover{background:#e67e22}

.icon{margin-right:5px;font-size:1em;line-height:1}
.icon-user{color:var(--user-icon)}.icon-pass{color:var(--pass-icon)}
.icon-expires{color:var(--expires-icon)}.icon-port{color:var(--port-icon)}
.icon-device{color:var(--device-icon)}

.label-c1{color:#2ecc71}.label-c2{color:#f1c40f}.label-c3{color:#e74c3c}
.label-c4{color:#9b59b6}.label-c5{color:#e67e22}.label-c6{color:#1abc9c}
.label-c7{color:#3498db}

form.box{margin:25px 0;padding:25px;border-radius:var(--radius);background:var(--card);box-shadow:var(--shadow)}
h3{color:var(--fg);margin-top:0}
label{display:flex;align-items:center;margin:6px 0 4px;font-size:.95em;font-weight:700}
input{width:100%;padding:12px;border:1px solid var(--bd);border-radius:var(--radius);box-sizing:border-box;background:var(--bg);color:var(--input-text)}
input:focus{outline:none;border-color:var(--primary-btn)}
.row{display:flex;gap:20px;flex-wrap:wrap;margin-top:10px}.row>div{flex:1 1 200px}

table{border-collapse:separate;width:100%;background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
th,td{padding:14px 18px;text-align:left;border-bottom:1px solid var(--bd);border-right:1px solid var(--bd)}
th:last-child,td:last-child{border-right:none}th{background:#252525;font-weight:700;color:var(--fg);text-transform:uppercase}
tr:last-child td{border-bottom:none}tr:hover{background:#3a3a3a}

.pill{display:inline-block;padding:5px 12px;border-radius:20px;font-size:.85em;font-weight:700;text-shadow:1px 1px 2px rgba(0,0,0,0.5);box-shadow:0 2px 4px rgba(0,0,0,0.2)}
.status-ok{color:white;background:#2ecc71}.status-bad{color:white;background:#e74c3c}
.status-unk{color:white;background:#f1c40f}.status-expired{color:white;background:#9b59b6}
.pill-yellow{background:#f1c40f}.pill-red{background:#e74c3c}.pill-green{background:#2ecc71}
.pill-lightgreen{background:#1abc9c}.pill-pink{background:#f78da7}.pill-orange{background:#e67e22}
.pill-blue{background:#3498db}

.muted{color:var(--bd)}.delform{display:inline}tr.expired td{opacity:.9;background:var(--expired);color:white}tr.expired .muted{color:#ddd}
.center{display:flex;align-items:center;justify-content:center}
.login-card{max-width:400px;margin:10vh auto;padding:30px;border-radius:12px;background:var(--card);box-shadow:var(--shadow)}
.login-card h3{margin:5px 0 15px;font-size:1.8em;text-shadow:0 1px 3px rgba(0,0,0,0.5)}
.msg{margin:10px 0;padding:12px;border-radius:var(--radius);background:var(--success);color:white;font-weight:700}
.err{margin:10px 0;padding:12px;border-radius:var(--radius);background:var(--delete-btn);color:white;font-weight:700}

.device-info{font-size:0.85em;color:var(--device-icon);margin-top:5px}
.device-ip{color:var(--info)}

@media (max-width: 768px) {
  body{padding:10px}.container{padding:0}header{flex-direction:column;align-items:flex-start;padding:10px}
  .header-left{width:100%;justify-content:space-between;margin-bottom:10px}.row>div{flex:1 1 100%}
  .btn{width:100%;margin-bottom:5px;justify-content:center}table,thead,tbody,th,td,tr{display:block}
  thead tr{position:absolute;top:-9999px;left:-9999px}tr{border:1px solid var(--bd);margin-bottom:10px;border-radius:var(--radius);overflow:hidden;background:var(--card)}
  td{border:none;border-bottom:1px dotted var(--bd);position:relative;padding-left:50%;text-align:right}
  td:before{position:absolute;top:12px;left:10px;width:45%;padding-right:10px;white-space:nowrap;text-align:left;font-weight:700;color:var(--info)}
  td:nth-of-type(1):before{content:"👤 User"}td:nth-of-type(2):before{content:"🔑 Password"}td:nth-of-type(3):before{content:"⏰ Expires"}
  td:nth-of-type(4):before{content:"🔌 Port"}td:nth-of-type(5):before{content:"📱 Device"}td:nth-of-type(6):before{content:"🔎 Status"}td:nth-of-type(7):before{content:"🛠️ Actions"}
  .delform{width:100%}tr.expired td{background:var(--expired)}
}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"></head>
<body>
<div class="container">

{% if not authed %}
  <div class="login-card">
    <div class="center" style="margin-bottom:20px"><img class="logo" src="{{ logo }}" alt="မောင်သုည"></div>
    <h3 class="center">မောင်သုည Panel Login</h3>
    {% if err %}<div class="err">{{err}}</div>{% endif %}
    <form method="post" action="/login">
      <label class="label-c1"><i class="fas fa-user icon icon-user"></i>Username</label>
      <input name="u" autofocus required>
      <label class="label-c2" style="margin-top:15px"><i class="fas fa-lock icon icon-pass"></i>Password</label>
      <input name="p" type="password" required>
      <button class="btn primary" type="submit" style="margin-top:20px;width:100%">
        <i class="fas fa-sign-in-alt"></i>Login
      </button>
    </form>
  </div>
{% else %}

<header>
  <div class="header-left">
    <img src="{{ logo }}" alt="မောင်သုည" class="logo">
    <div>
      <h1>
        <span class="colorful-title">မောင်သုည ZIVPN Panel</span>
      </h1>
      <div class="sub"><span class="colorful-title" style="font-size:1em;font-weight:700;animation-duration:12s;">⊱✫⊰ One Device Per Account ⊱✫⊰</span></div>
    </div>
  </div>
  <div style="display:flex;gap:10px;align-items:center">
    <a class="btn contact" href="https://t.me/Zero_Free_Vpn" target="_blank" rel="noopener">
      <i class="fab fa-telegram-plane"></i>Contact
    </a>
    <a class="btn logout" href="/logout">
      <i class="fas fa-sign-out-alt"></i>Logout
    </a>
  </div>
</header>

<form method="post" action="/add" class="box">
  <h3 class="label-c6"><i class="fas fa-users-cog"></i> အသုံးပြုသူ အသစ်ထည့်ပါ</h3>
  {% if msg %}<div class="msg">{{msg}}</div>{% endif %}
  {% if err %}<div class="err">{{err}}</div>{% endif %}
  <div class="row">
    <div><label class="label-c1"><i class="fas fa-user icon icon-user"></i> User</label><input name="user" placeholder="User Name" required></div>
    <div><label class="label-c2"><i class="fas fa-lock icon icon-pass"></i> Password</label><input name="password" placeholder="Password" required></div>
    <div><label class="label-c3"><i class="fas fa-clock icon icon-expires"></i> Expires</label><input name="expires" placeholder="2026-01-01 or 30"></div>
    <div><label class="label-c4"><i class="fas fa-server icon icon-port"></i> Client Port</label><input name="port" placeholder="auto" type="number" min="6000" max="19999"></div>
  </div>
  <button class="btn save" type="submit" style="margin-top:20px">
    <i class="fas fa-save"></i> Save
  </button>
</form>

<table style="border:none;">
  <thead>
    <tr>
      <th><i class="fas fa-user icon-user"></i> User</th>
      <th><i class="fas fa-lock icon-pass"></i> Password</th>
      <th><i class="fas fa-clock icon-expires"></i> Expires</th>
      <th><i class="fas fa-server icon-port"></i> Port</th>
      <th><i class="fas fa-mobile-alt icon-device"></i> Device</th>
      <th><i class="fas fa-chart-line"></i> Status</th>
      <th><i class="fas fa-cogs"></i> Actions</th>
    </tr>
  </thead>
  <tbody>
  {% for u in users %}
  <tr class="{% if u.expires and u.expires < today %}expired{% endif %}">
    <td style="color:#2ecc71;"><strong>{{u.user}}</strong></td>
    <td>{{u.password}}</td>
    <td>{% if u.expires %}<span class="pill-pink">{{u.expires}}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
    <td>{% if u.port %}<span class="pill-orange">{{u.port}}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
    <td>
      {% if u.device_info %}
        <div class="device-info">
          <i class="fas fa-desktop"></i> {{u.device_info.device_id|truncate(15)}}
          <div class="device-ip">{{u.device_info.ip_address}}</div>
        </div>
      {% else %}
        <span class="muted">—</span>
      {% endif %}
    </td>
    <td>
      {% if u.status == "Online" %}<span class="pill status-ok">ONLINE</span>
      {% elif u.status == "Offline" %}<span class="pill status-bad">OFFLINE</span>
      {% elif u.expires and u.expires < today %}<span class="pill status-expired">EXPIRED</span>
      {% else %}<span class="pill status-unk">UNKNOWN</span>
      {% endif %}
    </td>
    <td style="display:flex;gap:5px;flex-wrap:wrap;">
      {% if u.device_info %}
      <form class="delform" method="post" action="/kick" onsubmit="return confirm('{{u.user}} ကို disconnect လုပ်မလား?')">
        <input type="hidden" name="user" value="{{u.user}}">
        <button type="submit" class="btn kick" style="padding:6px 12px;">
          <i class="fas fa-sign-out-alt"></i> Kick
        </button>
      </form>
      {% endif %}
      <form class="delform" method="post" action="/delete" onsubmit="return confirm('{{u.user}} ကို ဖျက်မလား?')">
        <input type="hidden" name="user" value="{{u.user}}">
        <button type="submit" class="btn delete" style="padding:6px 12px;">
          <i class="fas fa-trash-alt"></i> Delete
        </button>
      </form>
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>

{% endif %}
</div>
</body></html>"""

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET","dev-secret-change-me")
ADMIN_USER = os.environ.get("WEB_ADMIN_USER","").strip()
ADMIN_PASS = os.environ.get("WEB_ADMIN_PASSWORD","").strip()

def read_json(path, default):
  try:
    with open(path,"r") as f: return json.load(f)
  except Exception:
    return default
def write_json_atomic(path, data):
  d=json.dumps(data, ensure_ascii=False, indent=2)
  dirn=os.path.dirname(path); fd,tmp=tempfile.mkstemp(prefix=".tmp-", dir=dirn)
  try:
    with os.fdopen(fd,"w") as f: f.write(d)
    os.replace(tmp,path)
  finally:
    try: os.remove(tmp)
    except: pass
def load_users():
  v=read_json(USERS_FILE,[])
  out=[]
  for u in v:
    out.append({"user":u.get("user",""),
                "password":u.get("password",""),
                "expires":u.get("expires",""),
                "port":str(u.get("port","")) if u.get("port","")!="" else ""})
  return out
def save_users(users): write_json_atomic(USERS_FILE, users)
def get_listen_port_from_config():
  cfg=read_json(CONFIG_FILE,{})
  listen=str(cfg.get("listen","")).strip()
  m=re.search(r":(\d+)$", listen) if listen else None
  return (m.group(1) if m else LISTEN_FALLBACK)
def get_udp_listen_ports():
  out=subprocess.run("ss -uHln", shell=True, capture_output=True, text=True).stdout
  return set(re.findall(r":(\d+)\s", out))
def pick_free_port():
  used={str(u.get("port","")) for u in load_users() if str(u.get("port",""))}
  used |= get_udp_listen_ports()
  for p in range(6000,20000):
    if str(p) not in used: return str(p)
  return ""
def has_recent_udp_activity(port):
  if not port: return False
  try:
    out=subprocess.run("conntrack -L -p udp 2>/dev/null | grep 'dport=%s\\b'"%port,
                       shell=True, capture_output=True, text=True).stdout
    return bool(out)
  except Exception:
    return False
def status_for_user(u, active_ports, listen_port):
  port=str(u.get("port",""))
  check_port=port if port else listen_port
  if has_recent_udp_activity(check_port): return "Online"
  if check_port in active_ports: return "Offline"
  return "Unknown"
def get_device_info(user):
  devices = read_json(DEVICES_FILE, {})
  user_devices = devices.get(user, {})
  if user_devices:
      return {
          "device_id": user_devices.get("device_id", ""),
          "ip_address": user_devices.get("ip_address", ""),
          "last_seen": user_devices.get("last_seen", ""),
          "connect_time": user_devices.get("connect_time", "")
      }
  return None
def kick_user(user):
  devices = read_json(DEVICES_FILE, {})
  if user in devices:
    del devices[user]
    write_json_atomic(DEVICES_FILE, devices)
    # Also remove from conntrack
    subprocess.run(f"conntrack -D -p udp 2>/dev/null", shell=True)
    return True
  return False
def sync_config_passwords(mode="mirror"):
  cfg=read_json(CONFIG_FILE,{})
  users=load_users()
  users_pw=sorted({str(u["password"]) for u in users if u.get("password")})
  if mode=="merge":
    old=[]
    if isinstance(cfg.get("auth",{}).get("config",None), list):
      old=list(map(str, cfg["auth"]["config"]))
    new_pw=sorted(set(old)|set(users_pw))
  else:
    new_pw=users_pw
  if not isinstance(cfg.get("auth"),dict): cfg["auth"]={}
  cfg["auth"]["mode"]="passwords"
  cfg["auth"]["config"]=new_pw
  cfg["listen"]=cfg.get("listen") or ":5667"
  cfg["cert"]=cfg.get("cert") or "/etc/zivpn/zivpn.crt"
  cfg["key"]=cfg.get("key") or "/etc/zivpn/zivpn.key"
  cfg["obfs"]=cfg.get("obfs") or "zivpn"
  write_json_atomic(CONFIG_FILE,cfg)
  subprocess.run("systemctl restart zivpn.service", shell=True)
def login_enabled(): return bool(ADMIN_USER and ADMIN_PASS)
def is_authed(): return session.get("auth") == True
def require_login():
  if login_enabled() and not is_authed():
    return False
  return True
def build_view(msg="", err=""):
  if not require_login():
    return render_template_string(HTML, authed=False, logo=LOGO_URL, err=session.pop("login_err", None))
  users=load_users()
  active=get_udp_listen_ports()
  listen_port=get_listen_port_from_config()
  view=[]
  today_date=datetime.now().date()
  for u in users:
    expires_str=u.get("expires","")
    is_expired=False
    if expires_str:
        try:
            expires_dt=datetime.strptime(expires_str, "%Y-%m-%d").date()
            if expires_dt < today_date:
                is_expired=True
        except ValueError:
            pass
    
    status=status_for_user(u,active,listen_port)
    if is_expired and status=="Offline":
        status="Expired"
    
    device_info = get_device_info(u.get("user",""))
    
    view.append(type("U",(),{
      "user":u.get("user",""),
      "password":u.get("password",""),
      "expires":expires_str,
      "port":u.get("port",""),
      "status":status,
      "device_info": device_info
    }))
  view.sort(key=lambda x:(x.user or "").lower())
  today=today_date.strftime("%Y-%m-%d")
  return render_template_string(HTML, authed=True, logo=LOGO_URL, users=view, msg=msg, err=err, today=today)

@app.route("/login", methods=["GET","POST"])
def login():
  if not login_enabled():
    return redirect(url_for('index'))
  if request.method=="POST":
    u=(request.form.get("u") or "").strip()
    p=(request.form.get("p") or "").strip()
    if hmac.compare_digest(u, ADMIN_USER) and hmac.compare_digest(p, ADMIN_PASS):
      session["auth"]=True
      return redirect(url_for('index'))
    else:
      session["auth"]=False
      session["login_err"]="မှန်ကန်မှုမရှိပါ (username/password)"
      return redirect(url_for('login'))
  return render_template_string(HTML, authed=False, logo=LOGO_URL, err=session.pop("login_err", None))

@app.route("/logout", methods=["GET"])
def logout():
  session.pop("auth", None)
  return redirect(url_for('login') if login_enabled() else url_for('index'))

@app.route("/", methods=["GET"])
def index(): return build_view()

@app.route("/add", methods=["POST"])
def add_user():
  if not require_login(): return redirect(url_for('login'))
  user=(request.form.get("user") or "").strip()
  password=(request.form.get("password") or "").strip()
  expires=(request.form.get("expires") or "").strip()
  port=(request.form.get("port") or "").strip()
  if expires.isdigit():
    expires=(datetime.now() + timedelta(days=int(expires))).strftime("%Y-%m-%d")
  if not user or not password:
    return build_view(err="User နှင့် Password လိုအပ်သည်")
  if expires:
    try: datetime.strptime(expires,"%Y-%m-%d")
    except ValueError:
      return build_view(err="Expires format မမှန်ပါ (YYYY-MM-DD)")
  if port:
    if not re.fullmatch(r"\d{2,5}",port) or not (6000 <= int(port) <= 19999):
      return build_view(err="Port အကွာအဝေး 6000-19999")
  else:
    port=pick_free_port()
  users=load_users(); replaced=False
  for u in users:
    if u.get("user","").lower()==user.lower():
      u["password"]=password; u["expires"]=expires; u["port"]=port; replaced=True; break
  if not replaced:
    users.append({"user":user,"password":password,"expires":expires,"port":port})
  save_users(users); sync_config_passwords()
  return build_view(msg="Saved & Synced")

@app.route("/delete", methods=["POST"])
def delete_user_html():
  if not require_login(): return redirect(url_for('login'))
  user = (request.form.get("user") or "").strip()
  if not user:
    return build_view(err="User လိုအပ်သည်")
  remain = [u for u in load_users() if (u.get("user","").lower() != user.lower())]
  save_users(remain)
  # Also remove from devices database
  devices = read_json(DEVICES_FILE, {})
  if user in devices:
    del devices[user]
    write_json_atomic(DEVICES_FILE, devices)
  sync_config_passwords(mode="mirror")
  return build_view(msg=f"Deleted: {user}")

@app.route("/kick", methods=["POST"])
def kick_user_html():
  if not require_login(): return redirect(url_for('login'))
  user = (request.form.get("user") or "").strip()
  if not user:
    return build_view(err="User လိုအပ်သည်")
  if kick_user(user):
    return build_view(msg=f"Kicked: {user}")
  else:
    return build_view(err=f"User {user} not found in active devices")

@app.route("/api/user.delete", methods=["POST"])
def delete_user_api():
  if not require_login():
    return make_response(jsonify({"ok": False, "err":"login required"}), 401)
  data = request.get_json(silent=True) or {}
  user = (data.get("user") or "").strip()
  if not user:
    return jsonify({"ok": False, "err": "user required"}), 400
  remain = [u for u in load_users() if (u.get("user","").lower() != user.lower())]
  save_users(remain)
  sync_config_passwords(mode="mirror")
  return jsonify({"ok": True})

@app.route("/api/users", methods=["GET","POST"])
def api_users():
  if not require_login():
    return make_response(jsonify({"ok": False, "err":"login required"}), 401)
  if request.method=="GET":
    users=load_users(); active=get_udp_listen_ports(); listen_port=get_listen_port_from_config()
    for u in users: u["status"]=status_for_user(u,active,listen_port)
    return jsonify(users)
  data=request.get_json(silent=True) or {}
  user=(data.get("user") or "").strip()
  password=(data.get("password") or "").strip()
  expires=(data.get("expires") or "").strip()
  port=str(data.get("port") or "").strip()
  if expires.isdigit():
    expires=(datetime.now()+timedelta(days=int(expires))).strftime("%Y-%m-%d")
  if not user or not password: return jsonify({"ok":False,"err":"user/password required"}),400
  if port and (not re.fullmatch(r"\d{2,5}",port) or not (6000<=int(port)<=19999)):
    return jsonify({"ok":False,"err":"invalid port"}),400
  if not port: port=pick_free_port()
  users=load_users(); replaced=False
  for u in users:
    if u.get("user","").lower()==user.lower():
      u["password"]=password; u["expires"]=expires; u["port"]=port; replaced=True; break
  if not replaced:
    users.append({"user":user,"password":password,"expires":expires,"port":port})
  save_users(users); sync_config_passwords()
  return jsonify({"ok":True})

@app.route("/favicon.ico", methods=["GET"])
def favicon(): return ("",204)

@app.errorhandler(405)
def handle_405(e): return redirect(url_for('index'))

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=8080)
PY

# ===== Web systemd =====
cat >/etc/systemd/system/zivpn-web.service <<'EOF'
[Unit]
Description=ZIVPN Web Panel
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/zivpn/web.env
ExecStart=/usr/bin/python3 /etc/zivpn/web.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ===== Create Device Monitor Service =====
cat >/etc/systemd/system/zivpn-monitor.service <<'EOF'
[Unit]
Description=ZIVPN Device Monitor - One Device Per Account
After=network.target zivpn.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/zivpn-monitor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ===== Networking & Final steps =====
echo -e "${Y}🌐 UDP/DNAT + UFW + sysctl အပြည့်ချထားနေပါတယ်...${Z}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
IFACE=$(ip -4 route ls | awk '/default/ {print $5; exit}')
[ -n "${IFACE:-}" ] || IFACE=eth0
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

ufw allow 5667/udp >/dev/null 2>&1 || true
ufw allow 6000:19999/udp >/dev/null 2>&1 || true
ufw allow 8080/tcp >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

# ===== CRLF sanitize =====
sed -i 's/\r$//' /etc/zivpn/web.py /etc/systemd/system/zivpn.service /etc/systemd/system/zivpn-web.service /etc/systemd/system/zivpn-monitor.service /usr/local/bin/zivpn-monitor.sh || true

# ===== Enable services =====
systemctl daemon-reload
systemctl enable --now zivpn.service
systemctl enable --now zivpn-web.service
systemctl enable --now zivpn-monitor.service

IP=$(hostname -I | awk '{print $1}')
echo -e "\n$LINE\n${G}✅ ONE DEVICE PER ACCOUNT SYSTEM READY${Z}"
echo -e "${C}Web Panel   :${Z} ${Y}http://$IP:8080${Z}"
echo -e "${C}Device DB   :${Z} ${Y}/etc/zivpn/devices.json${Z}"
echo -e "${C}Monitor Log :${Z} ${Y}/var/log/zivpn-monitor.log${Z}"
echo -e "${C}Features    :${Z} ${G}• One Device Per Account${Z}"
echo -e "              ${G}• Auto-Kick Duplicate Connections${Z}"
echo -e "              ${G}• Real-time Device Tracking${Z}"
echo -e "              ${G}• Manual Kick Option in Web UI${Z}"
echo -e "$LINE"
