#!/usr/bin/env python3
"""
VPS Server Setup for Curio Remote Access
Sets up OpenVPN server and REST API for remote device management
"""

import os
import sys
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CurioRemoteServer:
    def __init__(self, config_file="server_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.db_path = "curio_devices.db"
        self.app = Flask(__name__)
        CORS(self.app)
        self.setup_database()
        self.setup_routes()
        
    def load_config(self):
        """Load server configuration"""
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8443,
                "ssl_cert": "/etc/ssl/certs/curio-server.crt",
                "ssl_key": "/etc/ssl/private/curio-server.key",
                "api_key": secrets.token_urlsafe(32)
            },
            "openvpn": {
                "server_config": "/etc/openvpn/server/curio-server.conf",
                "client_config_template": "/etc/openvpn/client-template.ovpn",
                "ca_cert": "/etc/openvpn/easy-rsa/pki/ca.crt",
                "server_cert": "/etc/openvpn/easy-rsa/pki/issued/server.crt",
                "server_key": "/etc/openvpn/easy-rsa/pki/private/server.key",
                "dh_params": "/etc/openvpn/easy-rsa/pki/dh.pem",
                "ta_key": "/etc/openvpn/easy-rsa/pki/ta.key"
            },
            "database": {
                "cleanup_interval": 3600,  # 1 hour
                "offline_timeout": 300     # 5 minutes
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
            else:
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                logger.info(f"Created default config: {self.config_file}")
                return default_config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return default_config

    def setup_database(self):
        """Setup SQLite database for device management"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    platform TEXT,
                    location TEXT,
                    owner TEXT,
                    model TEXT,
                    serial_number TEXT,
                    capabilities TEXT,
                    vpn_ip TEXT,
                    status TEXT DEFAULT 'offline',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Device metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    temperature REAL,
                    uptime REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            # Support sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS support_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    session_id TEXT,
                    support_agent TEXT,
                    status TEXT DEFAULT 'active',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    notes TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            # Command logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    session_id TEXT,
                    command TEXT,
                    result TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database setup completed")
            
        except Exception as e:
            logger.error(f"Database setup error: {e}")

    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.before_request
        def verify_api_key():
            if request.endpoint and request.endpoint.startswith('api_'):
                api_key = request.headers.get('X-API-Key')
                if api_key != self.config['server']['api_key']:
                    return jsonify({"error": "Invalid API key"}), 401

        @self.app.route('/api/devices/register', methods=['POST'])
        def api_register_device():
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                device_info = data.get('device_info', {})
                capabilities = data.get('capabilities', {})
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Insert or update device
                cursor.execute('''
                    INSERT OR REPLACE INTO devices 
                    (device_id, hostname, platform, location, owner, model, serial_number, 
                     capabilities, status, last_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (
                    device_id,
                    device_info.get('hostname'),
                    device_info.get('platform'),
                    device_info.get('location'),
                    device_info.get('owner'),
                    device_info.get('model'),
                    device_info.get('serial_number'),
                    json.dumps(capabilities)
                ))
                
                conn.commit()
                conn.close()
                
                logger.info(f"Device registered: {device_id}")
                return jsonify({"status": "registered", "device_id": device_id})
                
            except Exception as e:
                logger.error(f"Device registration error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/devices/heartbeat', methods=['POST'])
        def api_device_heartbeat():
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                system_info = data.get('system_info', {})
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Update device status
                cursor.execute('''
                    UPDATE devices 
                    SET status = 'online', last_seen = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ?
                ''', (device_id,))
                
                # Insert metrics
                cursor.execute('''
                    INSERT INTO device_metrics 
                    (device_id, cpu_percent, memory_percent, disk_percent, temperature, uptime)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    system_info.get('cpu_percent'),
                    system_info.get('memory_percent'),
                    system_info.get('disk_percent'),
                    system_info.get('temperature'),
                    system_info.get('uptime')
                ))
                
                conn.commit()
                conn.close()
                
                return jsonify({"status": "received"})
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/devices', methods=['GET'])
        def api_list_devices():
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT device_id, hostname, platform, location, owner, model, 
                           serial_number, status, last_seen, created_at
                    FROM devices
                    ORDER BY last_seen DESC
                ''')
                
                devices = []
                for row in cursor.fetchall():
                    devices.append({
                        'device_id': row[0],
                        'hostname': row[1],
                        'platform': row[2],
                        'location': row[3],
                        'owner': row[4],
                        'model': row[5],
                        'serial_number': row[6],
                        'status': row[7],
                        'last_seen': row[8],
                        'created_at': row[9]
                    })
                
                conn.close()
                return jsonify({"devices": devices})
                
            except Exception as e:
                logger.error(f"List devices error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/devices/<device_id>/metrics', methods=['GET'])
        def api_device_metrics(device_id):
            try:
                hours = request.args.get('hours', 24, type=int)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT cpu_percent, memory_percent, disk_percent, temperature, uptime, timestamp
                    FROM device_metrics
                    WHERE device_id = ? AND timestamp > datetime('now', '-{} hours')
                    ORDER BY timestamp DESC
                '''.format(hours), (device_id,))
                
                metrics = []
                for row in cursor.fetchall():
                    metrics.append({
                        'cpu_percent': row[0],
                        'memory_percent': row[1],
                        'disk_percent': row[2],
                        'temperature': row[3],
                        'uptime': row[4],
                        'timestamp': row[5]
                    })
                
                conn.close()
                return jsonify({"metrics": metrics})
                
            except Exception as e:
                logger.error(f"Device metrics error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/support/session/start', methods=['POST'])
        def api_start_support_session():
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                support_agent = data.get('support_agent', 'System')
                
                session_id = secrets.token_urlsafe(16)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO support_sessions (device_id, session_id, support_agent)
                    VALUES (?, ?, ?)
                ''', (device_id, session_id, support_agent))
                
                conn.commit()
                conn.close()
                
                logger.info(f"Support session started: {session_id} for {device_id}")
                return jsonify({
                    "status": "started",
                    "session_id": session_id,
                    "device_id": device_id
                })
                
            except Exception as e:
                logger.error(f"Start support session error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/dashboard')
        def dashboard():
            """Simple web dashboard"""
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Curio Remote Access Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .device { border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
                    .online { border-color: #4CAF50; }
                    .offline { border-color: #f44336; }
                    .status { font-weight: bold; }
                    .online .status { color: #4CAF50; }
                    .offline .status { color: #f44336; }
                </style>
            </head>
            <body>
                <h1>Curio Remote Access Dashboard</h1>
                <div id="devices"></div>
                
                <script>
                    async function loadDevices() {
                        try {
                            const response = await fetch('/api/devices', {
                                headers: {'X-API-Key': '%s'}
                            });
                            const data = await response.json();
                            
                            const devicesDiv = document.getElementById('devices');
                            devicesDiv.innerHTML = '';
                            
                            data.devices.forEach(device => {
                                const div = document.createElement('div');
                                div.className = `device ${device.status}`;
                                div.innerHTML = `
                                    <h3>${device.hostname || device.device_id}</h3>
                                    <p><span class="status">Status: ${device.status}</span></p>
                                    <p>Location: ${device.location}</p>
                                    <p>Owner: ${device.owner}</p>
                                    <p>Model: ${device.model}</p>
                                    <p>Last Seen: ${device.last_seen}</p>
                                `;
                                devicesDiv.appendChild(div);
                            });
                        } catch (error) {
                            console.error('Error loading devices:', error);
                        }
                    }
                    
                    loadDevices();
                    setInterval(loadDevices, 30000); // Refresh every 30 seconds
                </script>
            </body>
            </html>
            ''' % self.config['server']['api_key']

    def cleanup_offline_devices(self):
        """Mark devices as offline if they haven't sent heartbeat"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            timeout_minutes = self.config['database']['offline_timeout'] // 60
            
            cursor.execute('''
                UPDATE devices
                SET status = 'offline'
                WHERE status = 'online' 
                AND last_seen < datetime('now', '-{} minutes')
            '''.format(timeout_minutes))
            
            affected = cursor.rowcount
            if affected > 0:
                logger.info(f"Marked {affected} devices as offline")
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def cleanup_worker(self):
        """Background worker for cleanup tasks"""
        while True:
            try:
                self.cleanup_offline_devices()
                time.sleep(self.config['database']['cleanup_interval'])
            except Exception as e:
                logger.error(f"Cleanup worker error: {e}")
                time.sleep(60)

    def generate_client_config(self, device_id):
        """Generate OpenVPN client configuration"""
        try:
            # This would generate a client certificate and config
            # For now, return a template
            config_template = f"""
client
dev tun
proto udp
remote YOUR_VPS_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert {device_id}.crt
key {device_id}.key
tls-auth ta.key 1
cipher AES-256-CBC
verb 3
"""
            return config_template
        except Exception as e:
            logger.error(f"Error generating client config: {e}")
            return None

    def run(self):
        """Run the server"""
        try:
            # Start cleanup worker
            cleanup_thread = threading.Thread(target=self.cleanup_worker, daemon=True)
            cleanup_thread.start()
            
            # Run Flask app
            ssl_context = None
            if (os.path.exists(self.config['server']['ssl_cert']) and 
                os.path.exists(self.config['server']['ssl_key'])):
                ssl_context = (
                    self.config['server']['ssl_cert'],
                    self.config['server']['ssl_key']
                )
            
            logger.info(f"Starting Curio Remote Server on {self.config['server']['host']}:{self.config['server']['port']}")
            logger.info(f"API Key: {self.config['server']['api_key']}")
            logger.info(f"Dashboard: https://localhost:{self.config['server']['port']}/dashboard")
            
            self.app.run(
                host=self.config['server']['host'],
                port=self.config['server']['port'],
                ssl_context=ssl_context,
                debug=False
            )
            
        except Exception as e:
            logger.error(f"Server error: {e}")

def setup_openvpn_server():
    """Setup OpenVPN server (run as root)"""
    print("Setting up OpenVPN server...")
    
    # This would contain the OpenVPN server setup commands
    setup_commands = [
        "apt update",
        "apt install -y openvpn easy-rsa",
        "make-cadir /etc/openvpn/easy-rsa",
        # Add more setup commands here
    ]
    
    print("OpenVPN server setup commands:")
    for cmd in setup_commands:
        print(f"  {cmd}")
    
    print("\nNote: Run these commands manually as root to setup OpenVPN server")
    print("Then configure the server with the generated certificates")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'setup-openvpn':
        setup_openvpn_server()
        return
    
    server = CurioRemoteServer()
    server.run()

if __name__ == "__main__":
    main() 