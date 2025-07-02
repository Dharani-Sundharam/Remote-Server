#!/bin/bash
# Curio Remote Support System - Server Setup Script
# Automated installation for VPS/Server deployment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Banner
echo -e "${BLUE}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                 CURIO REMOTE SUPPORT SYSTEM                 ║
║                    SERVER SETUP SCRIPT                      ║
║                                                              ║
║  Automated installation for VPS/Server deployment           ║
║  Enterprise-grade remote access and support management      ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   echo "Usage: sudo ./setup.sh"
   exit 1
fi

# Get current user (the one who ran sudo)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)
INSTALL_DIR=$(pwd)

log "Starting Curio Remote Support Server installation..."
log "Real user: $REAL_USER"
log "Install directory: $INSTALL_DIR"

# System information
log "Detecting system information..."
if command -v lsb_release >/dev/null 2>&1; then
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
    log "Detected OS: $OS $VER"
else
    OS=$(uname -s)
    VER=$(uname -r)
    log "Detected OS: $OS $VER"
fi

# Check system requirements
log "Checking system requirements..."

# Check available memory
MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEMORY_GB=$((MEMORY_KB / 1024 / 1024))
if [ $MEMORY_GB -lt 2 ]; then
    warning "System has only ${MEMORY_GB}GB RAM. Minimum 2GB recommended."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    success "Memory check passed: ${MEMORY_GB}GB RAM available"
fi

# Check available disk space
DISK_SPACE=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
if [ $DISK_SPACE -lt 10 ]; then
    warning "Only ${DISK_SPACE}GB disk space available. Minimum 20GB recommended."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    success "Disk space check passed: ${DISK_SPACE}GB available"
fi

# Update system packages
log "Updating system packages..."
apt update && apt upgrade -y

# Install system dependencies
log "Installing system dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    openvpn \
    easy-rsa \
    nginx \
    sqlite3 \
    ufw \
    curl \
    wget \
    git \
    htop \
    net-tools \
    iptables-persistent \
    certbot \
    python3-certbot-nginx \
    fail2ban \
    logrotate \
    cron

success "System dependencies installed"

# Setup firewall
log "Configuring firewall (UFW)..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 'Nginx Full'
ufw allow 1194/udp  # OpenVPN
ufw allow 8080/tcp  # Dashboard (temporary)
ufw --force enable

success "Firewall configured"

# Install Python dependencies
log "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r dashboard_requirements.txt

success "Python dependencies installed"

# Create necessary directories
log "Creating system directories..."
mkdir -p /etc/curio-support
mkdir -p /var/log/curio-support
mkdir -p /var/lib/curio-support
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/clients
mkdir -p /var/log/openvpn

# Set proper ownership
chown -R $REAL_USER:$REAL_USER /var/log/curio-support
chown -R $REAL_USER:$REAL_USER /var/lib/curio-support
chmod 755 /etc/curio-support

success "System directories created"

# Generate secure configurations
log "Generating secure configurations..."

# Generate API key
API_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 16)

# Create server configuration
cat > server_config.json << EOF
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": false
    },
    "database": {
        "cleanup_interval": 3600,
        "offline_timeout": 300,
        "ticket_auto_close": 86400
    },
    "ssh": {
        "base_port": 2200,
        "max_concurrent": 50,
        "timeout": 3600
    },
    "authentication": {
        "admin_username": "admin",
        "admin_password": "$ADMIN_PASSWORD",
        "session_timeout": 7200
    },
    "api": {
        "api_key": "$API_KEY",
        "rate_limit": 100
    },
    "openvpn": {
        "server_config": "/etc/openvpn/server/curio-server.conf",
        "client_config_dir": "/etc/openvpn/clients",
        "log_file": "/var/log/openvpn/server.log"
    }
}
EOF

chown $REAL_USER:$REAL_USER server_config.json
chmod 600 server_config.json

success "Server configuration created with secure credentials"

# Setup OpenVPN server
log "Setting up OpenVPN server..."

# Copy easy-rsa
cp -r /usr/share/easy-rsa /etc/openvpn/server/
cd /etc/openvpn/server/easy-rsa

# Initialize PKI
./easyrsa init-pki

# Create CA
echo "curio-ca" | ./easyrsa build-ca nopass

# Generate server certificate
./easyrsa gen-req curio-server nopass
echo "yes" | ./easyrsa sign-req server curio-server

# Generate Diffie-Hellman parameters
./easyrsa gen-dh

# Generate TLS auth key
openvpn --genkey secret ta.key

# Create OpenVPN server configuration
cat > /etc/openvpn/server/curio-server.conf << 'OVPN_EOF'
port 1194
proto udp
dev tun
ca easy-rsa/pki/ca.crt
cert easy-rsa/pki/issued/curio-server.crt
key easy-rsa/pki/private/curio-server.key
dh easy-rsa/pki/dh.pem
tls-auth easy-rsa/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/server-status.log
log-append /var/log/openvpn/server.log
verb 3
explicit-exit-notify 1
OVPN_EOF

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure iptables for NAT
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $INTERFACE -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $INTERFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Enable and start OpenVPN
systemctl enable openvpn-server@curio-server
systemctl start openvpn-server@curio-server

cd $INSTALL_DIR

success "OpenVPN server configured and started"

# Create systemd service for dashboard
log "Creating systemd service..."
cat > /etc/systemd/system/curio-dashboard.service << EOF
[Unit]
Description=Curio Support Dashboard
After=network.target openvpn-server@curio-server.service
Wants=network.target

[Service]
Type=simple
User=$REAL_USER
Group=$REAL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 dashboard_server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Environment
Environment=PYTHONPATH=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable curio-dashboard

success "Systemd service created"

# Configure Nginx reverse proxy
log "Configuring Nginx reverse proxy..."

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "your-server-ip")

cat > /etc/nginx/sites-available/curio-support << EOF
# Curio Support Dashboard - Nginx Configuration
server {
    listen 80;
    server_name $SERVER_IP _;  # Replace with your domain
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy to Flask app
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static files
    location /static {
        alias $INSTALL_DIR/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Security: Block access to sensitive files
    location ~ /\\. {
        deny all;
    }
    
    location ~ \\.(json|conf|log)\$ {
        deny all;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/curio-support /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart nginx
nginx -t && systemctl restart nginx

success "Nginx configured"

# Setup log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/curio-support << EOF
/var/log/curio-support/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    create 644 $REAL_USER $REAL_USER
}

/var/log/openvpn/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

success "Log rotation configured"

# Setup fail2ban for security
log "Configuring fail2ban for security..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
EOF

systemctl enable fail2ban
systemctl start fail2ban

success "Fail2ban configured"

# Create management scripts
log "Creating management scripts..."

# Start script
cat > start_dashboard.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting Curio Support Dashboard..."
sudo systemctl start curio-dashboard
sudo systemctl start openvpn-server@curio-server
echo "✅ Services started"
sudo systemctl status curio-dashboard --no-pager -l
EOF
chmod +x start_dashboard.sh

# Stop script
cat > stop_dashboard.sh << 'EOF'
#!/bin/bash
echo "🛑 Stopping Curio Support Dashboard..."
sudo systemctl stop curio-dashboard
echo "✅ Dashboard stopped"
EOF
chmod +x stop_dashboard.sh

# Status script
cat > check_status.sh << 'EOF'
#!/bin/bash
echo "📊 Curio Support System Status"
echo "=============================="

echo "🖥️  System Information:"
echo "----------------------"
echo "Hostname: $(hostname)"
echo "IP Address: $(curl -s ifconfig.me 2>/dev/null || echo 'Unable to detect')"
echo "Uptime: $(uptime -p)"
echo "Load: $(uptime | awk -F'load average:' '{print $2}')"

echo ""
echo "🔧 Service Status:"
echo "-----------------"
echo -n "Dashboard: "
if systemctl is-active --quiet curio-dashboard; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo -n "OpenVPN: "
if systemctl is-active --quiet openvpn-server@curio-server; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo -n "Nginx: "
if systemctl is-active --quiet nginx; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo ""
echo "📊 Database Status:"
echo "------------------"
python3 -c "
import sqlite3
import os
try:
    if os.path.exists('curio_support.db'):
        conn = sqlite3.connect('curio_support.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        devices = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM support_tickets')
        tickets = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM devices WHERE status = \"online\"')
        online = cursor.fetchone()[0]
        print(f'✅ Database accessible')
        print(f'📱 Total devices: {devices}')
        print(f'🟢 Online devices: {online}')
        print(f'🎫 Total tickets: {tickets}')
        conn.close()
    else:
        print('⚠️  Database not yet created (will be created on first run)')
except Exception as e:
    print(f'❌ Database error: {e}')
"

echo ""
echo "🌐 Network Status:"
echo "-----------------"
netstat -tlnp 2>/dev/null | grep :8080 && echo "✅ Dashboard listening on :8080" || echo "❌ Dashboard not listening"
netstat -tlnp 2>/dev/null | grep :80 && echo "✅ Nginx listening on :80" || echo "❌ Nginx not listening"
netstat -ulnp 2>/dev/null | grep :1194 && echo "✅ OpenVPN listening on :1194" || echo "❌ OpenVPN not listening"

echo ""
echo "🔒 Security Status:"
echo "------------------"
echo -n "Firewall: "
if ufw status | grep -q "Status: active"; then
    echo "✅ Active"
else
    echo "❌ Inactive"
fi

echo -n "Fail2ban: "
if systemctl is-active --quiet fail2ban; then
    echo "✅ Running"
else
    echo "❌ Stopped"
fi

echo ""
echo "💾 Disk Usage:"
echo "-------------"
df -h / | tail -1 | awk '{print "Root: " $3 "/" $2 " (" $5 " used)"}'

echo ""
echo "🔗 Access URLs:"
echo "--------------"
echo "Dashboard: http://$(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip')"
echo "Dashboard (local): http://localhost:8080"
EOF
chmod +x check_status.sh

# Logs script
cat > view_logs.sh << 'EOF'
#!/bin/bash
echo "📝 Curio Support System Logs"
echo "============================"
echo ""
echo "Choose log to view:"
echo "1) Dashboard logs (live)"
echo "2) OpenVPN logs"
echo "3) Nginx error logs"
echo "4) System logs"
echo "5) All recent logs"
echo ""
read -p "Enter choice (1-5): " choice

case $choice in
    1)
        echo "📊 Dashboard logs (press Ctrl+C to exit):"
        journalctl -u curio-dashboard -f
        ;;
    2)
        echo "🔒 OpenVPN logs:"
        tail -50 /var/log/openvpn/server.log
        ;;
    3)
        echo "🌐 Nginx error logs:"
        tail -50 /var/log/nginx/error.log
        ;;
    4)
        echo "🖥️  System logs:"
        journalctl --since "1 hour ago" | tail -50
        ;;
    5)
        echo "📋 All recent logs:"
        echo "=== Dashboard ==="
        journalctl -u curio-dashboard --since "1 hour ago" | tail -20
        echo ""
        echo "=== OpenVPN ==="
        tail -10 /var/log/openvpn/server.log
        echo ""
        echo "=== Nginx ==="
        tail -10 /var/log/nginx/error.log
        ;;
    *)
        echo "Invalid choice"
        ;;
esac
EOF
chmod +x view_logs.sh

# Client certificate generator
cat > generate_client_cert.sh << 'EOF'
#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <client_name>"
    echo "Example: $0 curio-device-01"
    exit 1
fi

CLIENT_NAME="$1"
EASYRSA_DIR="/etc/openvpn/server/easy-rsa"
CLIENTS_DIR="/etc/openvpn/clients"

echo "🔑 Generating client certificate for: $CLIENT_NAME"

cd $EASYRSA_DIR

# Generate client certificate
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Create client configuration
mkdir -p $CLIENTS_DIR/$CLIENT_NAME

cat > $CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.ovpn << OVPN_EOF
client
dev tun
proto udp
remote $(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip') 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3

<ca>
$(cat $EASYRSA_DIR/pki/ca.crt)
</ca>

<cert>
$(cat $EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(cat $EASYRSA_DIR/ta.key)
</tls-auth>
key-direction 1
OVPN_EOF

echo "✅ Client certificate generated: $CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.ovpn"
echo "📋 Copy this file to your Raspberry Pi client"
EOF
chmod +x generate_client_cert.sh

success "Management scripts created"

# Set proper ownership for all files
chown -R $REAL_USER:$REAL_USER $INSTALL_DIR
chmod +x *.sh

# Start the dashboard
log "Starting Curio Support Dashboard..."
systemctl start curio-dashboard

# Wait a moment and check status
sleep 3

# Final status check
log "Performing final status check..."
if systemctl is-active --quiet curio-dashboard && systemctl is-active --quiet openvpn-server@curio-server; then
    success "All services started successfully!"
else
    warning "Some services may not have started properly. Check status with ./check_status.sh"
fi

# Display completion message
echo ""
echo -e "${GREEN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                     INSTALLATION COMPLETE!                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo ""
echo -e "${BLUE}📋 NEXT STEPS:${NC}"
echo -e "${BLUE}==============${NC}"
echo "1. 🔐 Save your credentials:"
echo "   Username: admin"
echo "   Password: $ADMIN_PASSWORD"
echo "   API Key:  $API_KEY"
echo ""
echo "2. 🌐 Access the dashboard:"
echo "   URL: http://$SERVER_IP"
echo "   Local: http://localhost:8080"
echo ""
echo "3. 🔒 Generate client certificates:"
echo "   ./generate_client_cert.sh client-name"
echo ""
echo "4. 🛡️  Set up SSL (recommended):"
echo "   sudo certbot --nginx -d your-domain.com"
echo ""
echo -e "${BLUE}🔧 MANAGEMENT COMMANDS:${NC}"
echo -e "${BLUE}======================${NC}"
echo "• Start services:    ./start_dashboard.sh"
echo "• Stop services:     ./stop_dashboard.sh"
echo "• Check status:      ./check_status.sh"
echo "• View logs:         ./view_logs.sh"
echo "• Generate client:   ./generate_client_cert.sh <name>"
echo ""
echo -e "${BLUE}📁 IMPORTANT FILES:${NC}"
echo -e "${BLUE}==================${NC}"
echo "• Configuration:     server_config.json"
echo "• Database:          curio_support.db (created on first run)"
echo "• Client configs:    /etc/openvpn/clients/"
echo "• Logs:              /var/log/curio-support/"
echo ""
echo -e "${YELLOW}⚠️  SECURITY REMINDERS:${NC}"
echo -e "${YELLOW}=======================${NC}"
echo "• Save the admin password and API key securely"
echo "• Set up SSL certificate for production use"
echo "• Configure your domain name in nginx"
echo "• Regularly update the system packages"
echo "• Monitor logs for suspicious activity"
echo ""
echo -e "${GREEN}✅ Curio Remote Support System is ready!${NC}"

# Save credentials to file
cat > /root/curio-credentials.txt << EOF
Curio Remote Support System - Server Credentials
================================================

Admin Username: admin
Admin Password: $ADMIN_PASSWORD
API Key: $API_KEY

Server IP: $SERVER_IP
Dashboard URL: http://$SERVER_IP

Installation Date: $(date)
Installation Directory: $INSTALL_DIR

IMPORTANT: Keep this file secure and delete it after saving credentials elsewhere!
EOF

echo ""
echo -e "${YELLOW}📝 Credentials saved to: /root/curio-credentials.txt${NC}"
echo -e "${YELLOW}   Please save these credentials securely and delete the file!${NC}"

exit 0