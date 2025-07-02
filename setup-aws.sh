#!/bin/bash
# Curio Remote Support System - AWS-Specific Setup Script
# Optimized for AWS EC2 instances with dependency conflict resolution

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
║                   AWS-OPTIMIZED SETUP                       ║
║                                                              ║
║  Specialized installation for AWS EC2 instances             ║
║  Handles package conflicts and AWS-specific optimizations   ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   echo "Usage: sudo ./setup-aws.sh"
   exit 1
fi

# Get current user (the one who ran sudo)
REAL_USER=${SUDO_USER:-$USER}
INSTALL_DIR=$(pwd)

log "Starting AWS-optimized Curio Remote Support Server installation..."
log "Real user: $REAL_USER"
log "Install directory: $INSTALL_DIR"

# Verify AWS environment
log "Verifying AWS EC2 environment..."
if curl -s --max-time 3 http://169.254.169.254/latest/meta-data/instance-id >/dev/null 2>&1; then
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    success "AWS EC2 instance detected: $INSTANCE_ID in region $REGION"
else
    warning "AWS metadata service not accessible - proceeding anyway"
fi

# Configure non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Update system with AWS optimizations
log "Updating system packages with AWS optimizations..."
apt update --fix-missing
apt upgrade -y

# Pre-configure packages to avoid conflicts
log "Pre-configuring packages to avoid conflicts..."
echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | debconf-set-selections
echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections

# Remove any existing conflicting packages
log "Cleaning up potentially conflicting packages..."
apt remove -y iptables-persistent netfilter-persistent ufw 2>/dev/null || true
apt autoremove -y
apt autoclean

# Install core packages first
log "Installing core system packages..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    openvpn \
    easy-rsa \
    nginx \
    sqlite3 \
    curl \
    wget \
    git \
    htop \
    net-tools \
    certbot \
    python3-certbot-nginx \
    fail2ban \
    logrotate \
    cron \
    iptables

success "Core packages installed"

# Handle firewall packages with AWS-specific approach
log "Installing firewall packages with conflict resolution..."

# Try UFW first
if apt install -y ufw 2>/dev/null; then
    success "UFW installed successfully"
    UFW_AVAILABLE=true
else
    warning "UFW installation failed, will use direct iptables"
    UFW_AVAILABLE=false
fi

# Try netfilter-persistent
if apt install -y netfilter-persistent 2>/dev/null; then
    success "netfilter-persistent installed"
    NETFILTER_AVAILABLE=true
else
    warning "netfilter-persistent not available"
    NETFILTER_AVAILABLE=false
fi

# Try iptables-persistent
if apt install -y iptables-persistent 2>/dev/null; then
    success "iptables-persistent installed"
    IPTABLES_PERSISTENT_AVAILABLE=true
else
    warning "iptables-persistent not available, will use alternative"
    IPTABLES_PERSISTENT_AVAILABLE=false
fi

# Install Python dependencies
log "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

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
    },
    "aws": {
        "optimized": true,
        "instance_id": "$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')",
        "region": "$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo 'unknown')"
    }
}
EOF

chown $REAL_USER:$REAL_USER server_config.json
chmod 600 server_config.json

success "Server configuration created with AWS optimizations"

# Setup OpenVPN server
log "Setting up OpenVPN server..."
cp -r /usr/share/easy-rsa /etc/openvpn/server/
cd /etc/openvpn/server/easy-rsa

# Initialize PKI
./easyrsa init-pki

# Create CA (non-interactive)
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

cd $INSTALL_DIR

success "OpenVPN server configured"

# Configure firewall (AWS-optimized approach)
log "Configuring firewall for AWS environment..."

if [ "$UFW_AVAILABLE" = true ]; then
    log "Using UFW for firewall configuration..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 8080/tcp
    ufw allow 1194/udp
    ufw --force enable
    success "UFW firewall configured"
else
    log "Using direct iptables for firewall configuration..."
    # Clear existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow specific ports
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT  # Dashboard
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT  # OpenVPN
    
    success "Direct iptables firewall configured"
fi

# Configure NAT for VPN
log "Configuring NAT for VPN traffic..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $INTERFACE -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $INTERFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules
log "Saving iptables rules..."
mkdir -p /etc/iptables

if [ "$IPTABLES_PERSISTENT_AVAILABLE" = true ]; then
    iptables-save > /etc/iptables/rules.v4
    success "iptables rules saved with iptables-persistent"
else
    # Create custom save/restore mechanism
    iptables-save > /etc/iptables/rules.v4
    
    # Create restore script
    cat > /etc/systemd/system/iptables-restore.service << 'SYSTEMD_EOF'
[Unit]
Description=Restore iptables rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
    
    systemctl enable iptables-restore.service
    success "iptables rules saved with custom systemd service"
fi

# Enable and start OpenVPN
systemctl enable openvpn-server@curio-server
systemctl start openvpn-server@curio-server

success "OpenVPN server started"

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
Environment=PYTHONPATH=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable curio-dashboard

success "Systemd service created"

# Configure Nginx with AWS optimizations
log "Configuring Nginx for AWS..."

# Get AWS public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo "your-server-ip")

cat > /etc/nginx/sites-available/curio-support << EOF
# Curio Support Dashboard - AWS-Optimized Nginx Configuration
server {
    listen 80;
    server_name $PUBLIC_IP _;
    
    # AWS-specific optimizations
    client_max_body_size 10M;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Real-IP \$remote_addr;
    
    # Proxy to Flask app
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # AWS ELB health check support
        proxy_set_header X-AWS-Health-Check \$http_x_aws_health_check;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts optimized for AWS
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint for AWS ELB
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/curio-support /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart nginx
nginx -t && systemctl restart nginx

success "Nginx configured for AWS"

# Start the dashboard
log "Starting Curio Support Dashboard..."
systemctl start curio-dashboard

# Wait and check status
sleep 5

# Final status check
log "Performing final status check..."
SERVICES_OK=true

if ! systemctl is-active --quiet curio-dashboard; then
    error "Dashboard service failed to start"
    SERVICES_OK=false
fi

if ! systemctl is-active --quiet openvpn-server@curio-server; then
    error "OpenVPN service failed to start"
    SERVICES_OK=false
fi

if ! systemctl is-active --quiet nginx; then
    error "Nginx service failed to start"
    SERVICES_OK=false
fi

if [ "$SERVICES_OK" = true ]; then
    success "All services started successfully!"
else
    warning "Some services failed to start. Check logs for details."
fi

# Display completion message
echo ""
echo -e "${GREEN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                 AWS INSTALLATION COMPLETE!                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo ""
echo -e "${BLUE}📋 AWS-SPECIFIC SETUP COMPLETE:${NC}"
echo -e "${BLUE}===============================${NC}"
echo "1. 🔐 Your credentials:"
echo "   Username: admin"
echo "   Password: $ADMIN_PASSWORD"
echo "   API Key:  $API_KEY"
echo ""
echo "2. 🌐 Access URLs:"
echo "   Public: http://$PUBLIC_IP"
echo "   Local:  http://localhost:8080"
echo ""
echo "3. ☁️  AWS-specific features enabled:"
echo "   • Optimized package installation"
echo "   • AWS metadata integration"
echo "   • ELB health check support"
echo "   • Conflict-free firewall setup"
echo ""
echo -e "${BLUE}🔧 NEXT STEPS FOR AWS:${NC}"
echo -e "${BLUE}=====================${NC}"
echo "1. Configure AWS Security Group:"
echo "   • Allow port 22 (SSH)"
echo "   • Allow port 80 (HTTP)"
echo "   • Allow port 443 (HTTPS)"
echo "   • Allow port 1194 (OpenVPN UDP)"
echo ""
echo "2. Set up SSL with Let's Encrypt:"
echo "   sudo certbot --nginx -d your-domain.com"
echo ""
echo "3. Configure Elastic IP (recommended)"
echo "4. Set up Route 53 DNS (optional)"
echo "5. Configure CloudWatch monitoring (optional)"
echo ""
echo -e "${YELLOW}⚠️  AWS SECURITY REMINDERS:${NC}"
echo -e "${YELLOW}===========================${NC}"
echo "• Update Security Group rules as needed"
echo "• Enable CloudTrail for audit logging"
echo "• Consider using AWS WAF for additional protection"
echo "• Set up CloudWatch alarms for monitoring"
echo "• Regularly update AMI and packages"
echo ""
echo -e "${GREEN}✅ Curio Remote Support System is ready on AWS!${NC}"

# Save AWS-specific credentials
cat > /root/curio-aws-credentials.txt << EOF
Curio Remote Support System - AWS Deployment
============================================

Admin Username: admin
Admin Password: $ADMIN_PASSWORD
API Key: $API_KEY

AWS Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'unknown')
AWS Region: $(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo 'unknown')
Public IP: $PUBLIC_IP
Dashboard URL: http://$PUBLIC_IP

Installation Date: $(date)
Installation Directory: $INSTALL_DIR

AWS-Specific Configuration:
- Firewall: $([ "$UFW_AVAILABLE" = true ] && echo "UFW" || echo "Direct iptables")
- Persistence: $([ "$IPTABLES_PERSISTENT_AVAILABLE" = true ] && echo "iptables-persistent" || echo "systemd service")

IMPORTANT: Keep this file secure and delete it after saving credentials elsewhere!
EOF

echo ""
echo -e "${YELLOW}📝 AWS credentials saved to: /root/curio-aws-credentials.txt${NC}"

exit 0 