# Curio Remote Support System - Server

Enterprise-grade server components for the Curio Remote Support System. This server provides a complete VPN-based remote access solution with professional web dashboard for managing Raspberry Pi devices.

## 🚀 Quick Start

### One-Command Installation
```bash
sudo ./setup.sh
```

The setup script will:
- ✅ Install all system dependencies (OpenVPN, Nginx, Python, etc.)
- ✅ Configure firewall and security
- ✅ Set up OpenVPN server with certificates
- ✅ Create web dashboard with database
- ✅ Configure Nginx reverse proxy
- ✅ Generate secure credentials
- ✅ Start all services

## 📁 Server Components

### Core Files
- **`dashboard_server.py`** - Main Flask web application
- **`vpn_server_setup.py`** - OpenVPN server configuration
- **`start_dashboard.py`** - Dashboard startup script
- **`setup.sh`** - Complete automated installation
- **`requirements.txt`** - Python dependencies

### Web Interface
- **`templates/base.html`** - Responsive base template
- **`templates/dashboard.html`** - Main management dashboard
- **`templates/login.html`** - Secure login page

### Generated Files (after setup)
- **`server_config.json`** - Server configuration with credentials
- **`curio_support.db`** - SQLite database (auto-created)
- **Management scripts** - Various utility scripts

## 🔧 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 20GB minimum, 50GB recommended
- **Network**: Static IP address recommended
- **Domain**: Optional but recommended for SSL

### Recommended VPS Specifications
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 50GB SSD
- **Bandwidth**: 1TB/month
- **Provider**: DigitalOcean, Linode, AWS, etc.

## 📋 Installation Steps

### 1. Prepare VPS
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Clone or upload server files
cd /opt
sudo git clone <your-repo> curio-support
cd curio-support/Remote-Access/Server
```

### 2. Run Setup Script
```bash
# Make executable and run
sudo chmod +x setup.sh
sudo ./setup.sh
```

### 3. Save Credentials
The setup will generate secure credentials:
- **Admin Username**: admin
- **Admin Password**: (randomly generated)
- **API Key**: (randomly generated)

**⚠️ IMPORTANT**: Save these credentials securely!

### 4. Access Dashboard
- **URL**: `http://your-server-ip`
- **Local**: `http://localhost:8080`

## 🔒 Security Features

### Network Security
- **Firewall**: UFW configured with minimal open ports
- **VPN**: OpenVPN with AES-256-CBC encryption
- **SSL/TLS**: HTTPS support with Let's Encrypt
- **Fail2ban**: Intrusion prevention system

### Application Security
- **Authentication**: Session-based login system
- **API Security**: API key authentication
- **Command Whitelisting**: Safe remote command execution
- **Certificate-based**: PKI authentication for devices

### Monitoring & Logging
- **Activity Logs**: Complete audit trail
- **System Monitoring**: Real-time metrics
- **Log Rotation**: Automatic log management
- **Health Checks**: Service monitoring

## 🔧 Management Commands

After installation, use these scripts for management:

### Service Management
```bash
./start_dashboard.sh      # Start all services
./stop_dashboard.sh       # Stop dashboard
./check_status.sh         # Check system status
./view_logs.sh           # View system logs
```

### Client Management
```bash
./generate_client_cert.sh device-name    # Generate client certificate
```

### System Commands
```bash
# Check service status
sudo systemctl status curio-dashboard
sudo systemctl status openvpn-server@curio-server
sudo systemctl status nginx

# View logs
journalctl -u curio-dashboard -f
tail -f /var/log/openvpn/server.log
tail -f /var/log/nginx/error.log
```

## 🌐 Dashboard Features

### Main Dashboard
- **Real-time Statistics**: Device counts, ticket status
- **Device Management**: Live device monitoring
- **System Health**: Server performance metrics
- **Quick Actions**: One-click operations

### Device Management
- **Live Status**: Online/offline monitoring
- **System Metrics**: CPU, memory, temperature
- **SSH Access**: One-click remote access
- **Command Execution**: Safe remote commands

### Support Tickets
- **Ticket Creation**: Automatic and manual creation
- **Priority Management**: High, medium, low priorities
- **Assignment**: Ticket assignment to support staff
- **Resolution Tracking**: Complete ticket lifecycle

### User Management
- **Secure Login**: Session-based authentication
- **Role Management**: Admin and support roles
- **Activity Tracking**: User action logging
- **Session Control**: Timeout and security settings

## 🔄 Workflow

### Customer Support Process
1. **Customer**: Selects "Contact Support" on device
2. **System**: Establishes VPN connection
3. **System**: Creates support ticket automatically
4. **Dashboard**: Shows new ticket with device info
5. **Support**: Clicks "Start SSH" for remote access
6. **Support**: Troubleshoots via secure tunnel
7. **System**: Logs all activities for audit

### Device Registration
1. **Device**: Connects to VPN server
2. **Device**: Registers with API key
3. **System**: Creates device record
4. **Dashboard**: Shows device as online
5. **System**: Monitors device health

## 📊 Database Schema

### Tables
- **devices**: Device information and status
- **support_tickets**: Support ticket management
- **ssh_sessions**: SSH session tracking
- **device_metrics**: System performance data
- **activity_logs**: Complete audit trail

### Key Fields
- **Device ID**: Unique device identifier
- **Status**: Online/offline/maintenance
- **Last Seen**: Last communication timestamp
- **Metrics**: CPU, memory, temperature, uptime
- **Location**: Device physical location
- **Owner**: Device owner information

## 🔧 Configuration

### Server Configuration (`server_config.json`)
```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "debug": false
    },
    "authentication": {
        "admin_username": "admin",
        "admin_password": "your-secure-password"
    },
    "api": {
        "api_key": "your-secure-api-key"
    },
    "database": {
        "cleanup_interval": 3600,
        "offline_timeout": 300
    }
}
```

### OpenVPN Configuration
- **Port**: 1194/UDP
- **Encryption**: AES-256-CBC
- **Authentication**: SHA256
- **Network**: 10.8.0.0/24
- **DNS**: Google DNS (8.8.8.8, 8.8.4.4)

### Nginx Configuration
- **HTTP**: Port 80 (redirects to HTTPS)
- **HTTPS**: Port 443 (with SSL certificate)
- **Proxy**: Forwards to Flask app on port 8080
- **Security Headers**: XSS protection, frame options

## 🚨 Troubleshooting

### Common Issues

#### Dashboard Not Accessible
```bash
# Check service status
sudo systemctl status curio-dashboard

# Check logs
journalctl -u curio-dashboard -f

# Restart service
sudo systemctl restart curio-dashboard
```

#### VPN Connection Issues
```bash
# Check OpenVPN status
sudo systemctl status openvpn-server@curio-server

# Check logs
tail -f /var/log/openvpn/server.log

# Check firewall
sudo ufw status
```

#### Database Issues
```bash
# Check database file
ls -la curio_support.db

# Test database connection
python3 -c "import sqlite3; conn=sqlite3.connect('curio_support.db'); print('OK')"
```

#### Nginx Issues
```bash
# Test configuration
sudo nginx -t

# Check logs
tail -f /var/log/nginx/error.log

# Restart nginx
sudo systemctl restart nginx
```

### Performance Optimization

#### High CPU Usage
- Monitor with `htop`
- Check database queries
- Optimize cleanup intervals
- Consider upgrading VPS

#### Memory Issues
- Monitor with `free -h`
- Adjust database cleanup
- Check for memory leaks
- Consider upgrading RAM

#### Network Issues
- Monitor bandwidth usage
- Check VPN connection counts
- Optimize data transmission
- Consider CDN for static files

## 🔄 Backup & Recovery

### Database Backup
```bash
# Create backup
sqlite3 curio_support.db ".backup backup_$(date +%Y%m%d_%H%M%S).db"

# Restore backup
cp backup_20240101_120000.db curio_support.db
sudo systemctl restart curio-dashboard
```

### Configuration Backup
```bash
# Backup configurations
tar -czf config_backup_$(date +%Y%m%d).tar.gz \
    server_config.json \
    /etc/openvpn/server/ \
    /etc/nginx/sites-available/curio-support
```

### Full System Backup
```bash
# Create complete backup
tar -czf curio_backup_$(date +%Y%m%d).tar.gz \
    . \
    /etc/openvpn/server/ \
    /etc/nginx/sites-available/curio-support \
    /var/log/curio-support/
```

## 🔄 Updates & Maintenance

### Regular Maintenance
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python packages
pip3 install --upgrade -r requirements.txt

# Clean old logs
sudo logrotate -f /etc/logrotate.d/curio-support

# Check disk space
df -h
```

### Security Updates
```bash
# Update SSL certificates
sudo certbot renew

# Update firewall rules
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw allow 1194/udp
sudo ufw --force enable

# Check for security updates
sudo apt list --upgradable | grep security
```

## 📈 Scaling

### Multiple Servers
- Use load balancer (nginx upstream)
- Shared database (PostgreSQL)
- Redis for session storage
- Monitoring with Prometheus/Grafana

### High Availability
- Multiple VPS instances
- Database replication
- Automatic failover
- Health check monitoring

## 🆘 Support

### Emergency Contacts
- **Email**: support@curio-devices.com
- **Phone**: +1-800-CURIO-HELP
- **Emergency**: Text "URGENT" to +1-555-CURIO-911

### Documentation
- **Setup Guide**: See main documentation
- **API Reference**: Available in dashboard
- **Troubleshooting**: Check logs and status scripts

### Community
- **GitHub Issues**: Report bugs and feature requests
- **Discord**: Join our support community
- **Forums**: Community discussions and help

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

**⚠️ Security Notice**: This system provides remote access to devices. Ensure proper security measures are in place before deploying in production environments. Regularly update all components and monitor system logs for suspicious activity. 