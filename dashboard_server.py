#!/usr/bin/env python3
"""
Curio Support Dashboard - Web Application
Complete ticket system with device management and SSH access
"""

import os
import sys
import json
import sqlite3
import hashlib
import secrets
import subprocess
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
import threading
import logging
import time
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CurioSupportDashboard:
    def __init__(self, config_file="dashboard_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.db_path = "curio_support.db"
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.secret_key = self.config.get('secret_key', secrets.token_hex(32))
        CORS(self.app)
        
        self.setup_database()
        self.setup_routes()
        
        # Background tasks
        self.cleanup_thread = None
        self.stop_event = threading.Event()
        
    def load_config(self):
        """Load dashboard configuration"""
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "debug": False
            },
            "database": {
                "cleanup_interval": 3600,
                "offline_timeout": 300,
                "ticket_auto_close": 86400  # 24 hours
            },
            "ssh": {
                "base_port": 2200,  # Starting port for SSH forwarding
                "max_concurrent": 50,
                "timeout": 3600  # 1 hour SSH session timeout
            },
            "authentication": {
                "admin_username": "admin",
                "admin_password": "changeme123",  # Change this!
                "session_timeout": 7200  # 2 hours
            },
            "openvpn": {
                "server_config": "/etc/openvpn/server/curio-server.conf",
                "client_config_dir": "/etc/openvpn/clients",
                "log_file": "/var/log/openvpn/server.log"
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
        """Setup SQLite database with all necessary tables"""
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
                    vpn_ip TEXT,
                    ssh_port INTEGER,
                    capabilities TEXT,
                    status TEXT DEFAULT 'offline',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Support tickets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS support_tickets (
                    ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    customer_name TEXT,
                    customer_email TEXT,
                    issue_title TEXT,
                    issue_description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    assigned_to TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    resolution_notes TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            # Support sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS support_sessions (
                    session_id TEXT PRIMARY KEY,
                    ticket_id INTEGER,
                    device_id TEXT,
                    support_agent TEXT,
                    session_type TEXT DEFAULT 'remote',
                    ssh_port INTEGER,
                    vpn_ip TEXT,
                    status TEXT DEFAULT 'active',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    duration INTEGER,
                    notes TEXT,
                    FOREIGN KEY (ticket_id) REFERENCES support_tickets (ticket_id),
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
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
                    load_avg TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            # Activity log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER,
                    device_id TEXT,
                    user TEXT,
                    action TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (ticket_id) REFERENCES support_tickets (ticket_id)
                )
            ''')
            
            # SSH sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssh_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    device_id TEXT,
                    support_agent TEXT,
                    local_port INTEGER,
                    remote_port INTEGER,
                    pid INTEGER,
                    status TEXT DEFAULT 'active',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices (device_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database setup completed")
            
        except Exception as e:
            logger.error(f"Database setup error: {e}")

    def setup_routes(self):
        """Setup all Flask routes"""
        
        # Authentication decorator
        def login_required(f):
            def decorated_function(*args, **kwargs):
                if 'logged_in' not in session:
                    return redirect(url_for('login'))
                return f(*args, **kwargs)
            decorated_function.__name__ = f.__name__
            return decorated_function
        
        @self.app.route('/')
        @login_required
        def dashboard():
            """Main dashboard page"""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get dashboard statistics
                cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
                online_devices = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM devices")
                total_devices = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status = 'open'")
                open_tickets = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM support_sessions WHERE status = 'active'")
                active_sessions = cursor.fetchone()[0]
                
                # Get recent tickets
                cursor.execute('''
                    SELECT t.ticket_id, t.device_id, t.customer_name, t.issue_title, 
                           t.priority, t.status, t.created_at, d.hostname
                    FROM support_tickets t
                    LEFT JOIN devices d ON t.device_id = d.device_id
                    ORDER BY t.created_at DESC
                    LIMIT 10
                ''')
                recent_tickets = cursor.fetchall()
                
                # Get online devices
                cursor.execute('''
                    SELECT device_id, hostname, location, owner, vpn_ip, last_seen
                    FROM devices 
                    WHERE status = 'online'
                    ORDER BY last_seen DESC
                    LIMIT 10
                ''')
                online_devices_list = cursor.fetchall()
                
                conn.close()
                
                return render_template('dashboard.html',
                    online_devices=online_devices,
                    total_devices=total_devices,
                    open_tickets=open_tickets,
                    active_sessions=active_sessions,
                    recent_tickets=recent_tickets,
                    online_devices_list=online_devices_list
                )
                
            except Exception as e:
                logger.error(f"Dashboard error: {e}")
                flash(f"Dashboard error: {e}", 'error')
                return render_template('dashboard.html')

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Login page"""
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                
                if (username == self.config['authentication']['admin_username'] and
                    password == self.config['authentication']['admin_password']):
                    session['logged_in'] = True
                    session['username'] = username
                    session['login_time'] = datetime.now().isoformat()
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid credentials!', 'error')
            
            return render_template('login.html')

        @self.app.route('/logout')
        def logout():
            """Logout"""
            session.clear()
            flash('Logged out successfully!', 'success')
            return redirect(url_for('login'))

        @self.app.route('/devices')
        @login_required
        def devices():
            """Devices management page"""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT device_id, hostname, platform, location, owner, model, 
                           serial_number, vpn_ip, status, last_seen, created_at
                    FROM devices
                    ORDER BY last_seen DESC
                ''')
                devices_list = cursor.fetchall()
                
                conn.close()
                
                return render_template('devices.html', devices=devices_list)
                
            except Exception as e:
                logger.error(f"Devices page error: {e}")
                flash(f"Error loading devices: {e}", 'error')
                return render_template('devices.html', devices=[])

        @self.app.route('/tickets')
        @login_required
        def tickets():
            """Support tickets page"""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get filter parameters
                status_filter = request.args.get('status', 'all')
                priority_filter = request.args.get('priority', 'all')
                
                query = '''
                    SELECT t.ticket_id, t.device_id, t.customer_name, t.customer_email,
                           t.issue_title, t.issue_description, t.priority, t.status,
                           t.assigned_to, t.created_at, t.updated_at, d.hostname, d.location
                    FROM support_tickets t
                    LEFT JOIN devices d ON t.device_id = d.device_id
                    WHERE 1=1
                '''
                params = []
                
                if status_filter != 'all':
                    query += ' AND t.status = ?'
                    params.append(status_filter)
                
                if priority_filter != 'all':
                    query += ' AND t.priority = ?'
                    params.append(priority_filter)
                
                query += ' ORDER BY t.created_at DESC'
                
                cursor.execute(query, params)
                tickets_list = cursor.fetchall()
                
                conn.close()
                
                return render_template('tickets.html', 
                    tickets=tickets_list,
                    status_filter=status_filter,
                    priority_filter=priority_filter
                )
                
            except Exception as e:
                logger.error(f"Tickets page error: {e}")
                flash(f"Error loading tickets: {e}", 'error')
                return render_template('tickets.html', tickets=[])

        @self.app.route('/ticket/<int:ticket_id>')
        @login_required
        def ticket_detail(ticket_id):
            """Ticket detail page"""
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get ticket details
                cursor.execute('''
                    SELECT t.*, d.hostname, d.location, d.vpn_ip, d.status as device_status
                    FROM support_tickets t
                    LEFT JOIN devices d ON t.device_id = d.device_id
                    WHERE t.ticket_id = ?
                ''', (ticket_id,))
                ticket = cursor.fetchone()
                
                if not ticket:
                    flash('Ticket not found!', 'error')
                    return redirect(url_for('tickets'))
                
                # Get support sessions for this ticket
                cursor.execute('''
                    SELECT * FROM support_sessions
                    WHERE ticket_id = ?
                    ORDER BY started_at DESC
                ''', (ticket_id,))
                sessions = cursor.fetchall()
                
                # Get activity log
                cursor.execute('''
                    SELECT * FROM activity_log
                    WHERE ticket_id = ?
                    ORDER BY timestamp DESC
                ''', (ticket_id,))
                activities = cursor.fetchall()
                
                conn.close()
                
                return render_template('ticket_detail.html',
                    ticket=ticket,
                    sessions=sessions,
                    activities=activities
                )
                
            except Exception as e:
                logger.error(f"Ticket detail error: {e}")
                flash(f"Error loading ticket: {e}", 'error')
                return redirect(url_for('tickets'))

        @self.app.route('/create_ticket', methods=['GET', 'POST'])
        def create_ticket():
            """Create new support ticket (public endpoint)"""
            if request.method == 'POST':
                try:
                    data = request.get_json() if request.is_json else request.form
                    
                    device_id = data.get('device_id')
                    customer_name = data.get('customer_name')
                    customer_email = data.get('customer_email')
                    issue_title = data.get('issue_title')
                    issue_description = data.get('issue_description')
                    priority = data.get('priority', 'medium')
                    
                    if not all([device_id, customer_name, issue_title]):
                        return jsonify({'error': 'Missing required fields'}), 400
                    
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT INTO support_tickets 
                        (device_id, customer_name, customer_email, issue_title, 
                         issue_description, priority)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (device_id, customer_name, customer_email, issue_title,
                          issue_description, priority))
                    
                    ticket_id = cursor.lastrowid
                    
                    # Log activity
                    cursor.execute('''
                        INSERT INTO activity_log (ticket_id, device_id, user, action, details)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (ticket_id, device_id, customer_name, 'TICKET_CREATED',
                          f'Ticket created: {issue_title}'))
                    
                    conn.commit()
                    conn.close()
                    
                    logger.info(f"New ticket created: {ticket_id} for device {device_id}")
                    
                    if request.is_json:
                        return jsonify({
                            'success': True,
                            'ticket_id': ticket_id,
                            'message': 'Support ticket created successfully'
                        })
                    else:
                        flash('Support ticket created successfully!', 'success')
                        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
                        
                except Exception as e:
                    logger.error(f"Create ticket error: {e}")
                    if request.is_json:
                        return jsonify({'error': str(e)}), 500
                    else:
                        flash(f'Error creating ticket: {e}', 'error')
                        return render_template('create_ticket.html')
            
            return render_template('create_ticket.html')

        @self.app.route('/start_ssh/<device_id>')
        @login_required
        def start_ssh(device_id):
            """Start SSH session to device"""
            try:
                result = self.start_ssh_session(device_id, session.get('username', 'admin'))
                
                if result['success']:
                    flash(f"SSH session started on port {result['port']}", 'success')
                    return jsonify(result)
                else:
                    flash(f"Failed to start SSH: {result['error']}", 'error')
                    return jsonify(result), 500
                    
            except Exception as e:
                logger.error(f"Start SSH error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/stop_ssh/<device_id>')
        @login_required
        def stop_ssh(device_id):
            """Stop SSH session to device"""
            try:
                result = self.stop_ssh_session(device_id)
                
                if result['success']:
                    flash("SSH session stopped", 'success')
                else:
                    flash(f"Failed to stop SSH: {result['error']}", 'error')
                
                return jsonify(result)
                
            except Exception as e:
                logger.error(f"Stop SSH error: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        # API Routes for device communication
        @self.app.route('/api/devices/register', methods=['POST'])
        def api_register_device():
            """Register device with support system"""
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                device_info = data.get('device_info', {})
                capabilities = data.get('capabilities', {})
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Assign SSH port if not exists
                cursor.execute('SELECT ssh_port FROM devices WHERE device_id = ?', (device_id,))
                existing = cursor.fetchone()
                
                if existing and existing[0]:
                    ssh_port = existing[0]
                else:
                    ssh_port = self.assign_ssh_port()
                
                # Insert or update device
                cursor.execute('''
                    INSERT OR REPLACE INTO devices 
                    (device_id, hostname, platform, location, owner, model, 
                     serial_number, ssh_port, capabilities, status, last_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (
                    device_id,
                    device_info.get('hostname'),
                    device_info.get('platform'),
                    device_info.get('location'),
                    device_info.get('owner'),
                    device_info.get('model'),
                    device_info.get('serial_number'),
                    ssh_port,
                    json.dumps(capabilities)
                ))
                
                conn.commit()
                conn.close()
                
                logger.info(f"Device registered: {device_id} (SSH port: {ssh_port})")
                return jsonify({
                    'status': 'registered',
                    'device_id': device_id,
                    'ssh_port': ssh_port
                })
                
            except Exception as e:
                logger.error(f"Device registration error: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/devices/heartbeat', methods=['POST'])
        def api_device_heartbeat():
            """Receive device heartbeat"""
            try:
                data = request.get_json()
                device_id = data.get('device_id')
                system_info = data.get('system_info', {})
                vpn_ip = data.get('vpn_ip')
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Update device status
                cursor.execute('''
                    UPDATE devices 
                    SET status = 'online', vpn_ip = ?, last_seen = CURRENT_TIMESTAMP, 
                        updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ?
                ''', (vpn_ip, device_id))
                
                # Insert metrics
                cursor.execute('''
                    INSERT INTO device_metrics 
                    (device_id, cpu_percent, memory_percent, disk_percent, 
                     temperature, uptime, load_avg)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    system_info.get('cpu_percent'),
                    system_info.get('memory_percent'),
                    system_info.get('disk_percent'),
                    system_info.get('temperature'),
                    system_info.get('uptime'),
                    json.dumps(system_info.get('load_average', []))
                ))
                
                conn.commit()
                conn.close()
                
                return jsonify({'status': 'received'})
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                return jsonify({'error': str(e)}), 500

    def assign_ssh_port(self):
        """Assign next available SSH port"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT MAX(ssh_port) FROM devices WHERE ssh_port IS NOT NULL')
            max_port = cursor.fetchone()[0]
            
            if max_port:
                next_port = max_port + 1
            else:
                next_port = self.config['ssh']['base_port']
            
            conn.close()
            return next_port
            
        except Exception as e:
            logger.error(f"Port assignment error: {e}")
            return self.config['ssh']['base_port']

    def start_ssh_session(self, device_id, support_agent):
        """Start SSH session to device via OpenVPN"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get device info
            cursor.execute('''
                SELECT vpn_ip, ssh_port, hostname, status 
                FROM devices WHERE device_id = ?
            ''', (device_id,))
            device = cursor.fetchone()
            
            if not device:
                return {'success': False, 'error': 'Device not found'}
            
            vpn_ip, ssh_port, hostname, status = device
            
            if status != 'online':
                return {'success': False, 'error': 'Device is offline'}
            
            if not vpn_ip:
                return {'success': False, 'error': 'Device VPN IP not available'}
            
            # Check if SSH session already exists
            cursor.execute('''
                SELECT local_port, pid FROM ssh_sessions 
                WHERE device_id = ? AND status = 'active'
            ''', (device_id,))
            existing = cursor.fetchone()
            
            if existing:
                local_port, pid = existing
                # Check if process is still running
                try:
                    os.kill(pid, 0)  # Check if process exists
                    return {
                        'success': True,
                        'port': local_port,
                        'message': 'SSH session already active',
                        'existing': True
                    }
                except OSError:
                    # Process doesn't exist, clean up
                    cursor.execute('''
                        UPDATE ssh_sessions SET status = 'ended', ended_at = CURRENT_TIMESTAMP
                        WHERE device_id = ? AND status = 'active'
                    ''', (device_id,))
            
            # Find available local port
            local_port = self.find_available_port()
            
            # Start SSH tunnel
            ssh_command = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-L', f'{local_port}:{vpn_ip}:22',
                '-N',  # Don't execute remote command
                '-f',  # Run in background
                f'pi@{vpn_ip}'
            ]
            
            process = subprocess.Popen(ssh_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Give it a moment to establish
            time.sleep(2)
            
            if process.poll() is None:  # Process is running
                # Record SSH session
                session_id = secrets.token_urlsafe(16)
                cursor.execute('''
                    INSERT INTO ssh_sessions 
                    (session_id, device_id, support_agent, local_port, remote_port, pid)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, device_id, support_agent, local_port, 22, process.pid))
                
                conn.commit()
                conn.close()
                
                logger.info(f"SSH session started for {device_id} on port {local_port}")
                return {
                    'success': True,
                    'port': local_port,
                    'session_id': session_id,
                    'command': f'ssh pi@localhost -p {local_port}',
                    'message': f'SSH tunnel established to {hostname}'
                }
            else:
                error_output = process.stderr.read().decode()
                return {'success': False, 'error': f'SSH tunnel failed: {error_output}'}
                
        except Exception as e:
            logger.error(f"SSH session error: {e}")
            return {'success': False, 'error': str(e)}

    def stop_ssh_session(self, device_id):
        """Stop SSH session to device"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT pid FROM ssh_sessions 
                WHERE device_id = ? AND status = 'active'
            ''', (device_id,))
            session = cursor.fetchone()
            
            if not session:
                return {'success': False, 'error': 'No active SSH session found'}
            
            pid = session[0]
            
            # Kill the SSH process
            try:
                os.kill(pid, 15)  # SIGTERM
                time.sleep(1)
                os.kill(pid, 9)   # SIGKILL if still running
            except OSError:
                pass  # Process already dead
            
            # Update session status
            cursor.execute('''
                UPDATE ssh_sessions 
                SET status = 'ended', ended_at = CURRENT_TIMESTAMP
                WHERE device_id = ? AND status = 'active'
            ''', (device_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"SSH session stopped for {device_id}")
            return {'success': True, 'message': 'SSH session stopped'}
            
        except Exception as e:
            logger.error(f"Stop SSH error: {e}")
            return {'success': False, 'error': str(e)}

    def find_available_port(self):
        """Find available local port for SSH forwarding"""
        import socket
        
        base_port = self.config['ssh']['base_port']
        max_port = base_port + self.config['ssh']['max_concurrent']
        
        for port in range(base_port, max_port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        
        raise Exception("No available ports for SSH forwarding")

    def cleanup_worker(self):
        """Background cleanup worker"""
        while not self.stop_event.is_set():
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Mark offline devices
                timeout_minutes = self.config['database']['offline_timeout'] // 60
                cursor.execute('''
                    UPDATE devices 
                    SET status = 'offline'
                    WHERE status = 'online' 
                    AND last_seen < datetime('now', '-{} minutes')
                '''.format(timeout_minutes))
                
                # Clean up old SSH sessions
                cursor.execute('''
                    UPDATE ssh_sessions 
                    SET status = 'ended', ended_at = CURRENT_TIMESTAMP
                    WHERE status = 'active' 
                    AND started_at < datetime('now', '-{} seconds')
                '''.format(self.config['ssh']['timeout']))
                
                # Auto-close old tickets
                auto_close_hours = self.config['database']['ticket_auto_close'] // 3600
                cursor.execute('''
                    UPDATE support_tickets 
                    SET status = 'auto_closed', updated_at = CURRENT_TIMESTAMP
                    WHERE status = 'open' 
                    AND created_at < datetime('now', '-{} hours')
                '''.format(auto_close_hours))
                
                conn.commit()
                conn.close()
                
                # Wait before next cleanup
                self.stop_event.wait(self.config['database']['cleanup_interval'])
                
            except Exception as e:
                logger.error(f"Cleanup worker error: {e}")
                self.stop_event.wait(60)

    def run(self):
        """Start the dashboard server"""
        try:
            # Start cleanup worker
            self.cleanup_thread = threading.Thread(target=self.cleanup_worker, daemon=True)
            self.cleanup_thread.start()
            
            logger.info(f"Starting Curio Support Dashboard on {self.config['server']['host']}:{self.config['server']['port']}")
            logger.info(f"Admin login: {self.config['authentication']['admin_username']}")
            
            self.app.run(
                host=self.config['server']['host'],
                port=self.config['server']['port'],
                debug=self.config['server']['debug']
            )
            
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop_event.set()

def main():
    dashboard = CurioSupportDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()