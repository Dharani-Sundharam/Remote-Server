#!/usr/bin/env python3
"""
Quick Start Script for Curio Support Dashboard
Creates test data and starts the dashboard for demonstration
"""

import os
import sys
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta

def create_test_data():
    """Create some test data for demonstration"""
    db_path = "curio_support.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Add test devices
        test_devices = [
            ("curio-device-001", "curio-reader-01", "linux", "New York Office", "John Doe", "Curio Reader v2.0", "CR2024001", "10.8.0.10", 2200),
            ("curio-device-002", "curio-reader-02", "linux", "Los Angeles Office", "Jane Smith", "Curio Reader v2.0", "CR2024002", "10.8.0.11", 2201),
            ("curio-device-003", "curio-reader-03", "linux", "Chicago Office", "Bob Johnson", "Curio Reader v2.0", "CR2024003", None, 2202),
        ]
        
        for device in test_devices:
            cursor.execute('''
                INSERT OR REPLACE INTO devices 
                (device_id, hostname, platform, location, owner, model, serial_number, vpn_ip, ssh_port, status, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', device + ('online' if device[7] else 'offline', datetime.now(), datetime.now(), datetime.now()))
        
        # Add test tickets
        test_tickets = [
            ("curio-device-001", "John Doe", "john@example.com", "Camera not working", "The camera appears to be blocked or not responding properly", "high", "open"),
            ("curio-device-002", "Jane Smith", "jane@example.com", "Audio issues", "TTS system is not working correctly", "medium", "in_progress"),
            ("curio-device-003", "Bob Johnson", "bob@example.com", "Grid display problem", "Hand tracking grid is not visible", "low", "resolved"),
        ]
        
        for i, ticket in enumerate(test_tickets, 1):
            cursor.execute('''
                INSERT OR REPLACE INTO support_tickets 
                (ticket_id, device_id, customer_name, customer_email, issue_title, issue_description, priority, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (i,) + ticket + (datetime.now() - timedelta(hours=i), datetime.now()))
        
        # Add test metrics
        for device_id in ["curio-device-001", "curio-device-002"]:
            for i in range(10):
                cursor.execute('''
                    INSERT INTO device_metrics 
                    (device_id, cpu_percent, memory_percent, disk_percent, temperature, uptime, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (device_id, 25.5 + i, 45.2 + i, 67.8, 42.3, 86400 + i*3600, datetime.now() - timedelta(minutes=i*10)))
        
        # Add activity log entries
        activities = [
            (1, "curio-device-001", "John Doe", "TICKET_CREATED", "Ticket created: Camera not working"),
            (1, "curio-device-001", "admin", "TICKET_ASSIGNED", "Ticket assigned to support team"),
            (2, "curio-device-002", "Jane Smith", "TICKET_CREATED", "Ticket created: Audio issues"),
            (3, "curio-device-003", "admin", "TICKET_RESOLVED", "Issue resolved: Grid display fixed"),
        ]
        
        for activity in activities:
            cursor.execute('''
                INSERT INTO activity_log (ticket_id, device_id, user, action, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', activity + (datetime.now() - timedelta(minutes=30),))
        
        conn.commit()
        conn.close()
        print("✅ Test data created successfully")
        
    except Exception as e:
        print(f"❌ Error creating test data: {e}")

def create_demo_config():
    """Create demo configuration"""
    config = {
        "server": {
            "host": "0.0.0.0",
            "port": 8080,
            "debug": True
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
            "admin_password": "demo123",
            "session_timeout": 7200
        },
        "openvpn": {
            "server_config": "/etc/openvpn/server/curio-server.conf",
            "client_config_dir": "/etc/openvpn/clients",
            "log_file": "/var/log/openvpn/server.log"
        }
    }
    
    with open("dashboard_config.json", "w") as f:
        json.dump(config, f, indent=4)
    
    print("✅ Demo configuration created")

def main():
    """Main function"""
    print("🚀 Starting Curio Support Dashboard Demo")
    print("=" * 50)
    
    # Check if dashboard_server.py exists
    if not os.path.exists("dashboard_server.py"):
        print("❌ dashboard_server.py not found!")
        print("Please make sure you're in the Remote-Access directory")
        sys.exit(1)
    
    # Create demo configuration
    create_demo_config()
    
    # Create test data
    create_test_data()
    
    print("\n📊 Dashboard Information:")
    print("URL: http://localhost:8080")
    print("Username: admin")
    print("Password: demo123")
    print("\n🔧 Test Data Includes:")
    print("• 3 test devices (2 online, 1 offline)")
    print("• 3 support tickets (various statuses)")
    print("• Device metrics and activity logs")
    print("• SSH session management")
    
    print("\n🎯 Features to Test:")
    print("• Dashboard overview with statistics")
    print("• Device management and monitoring")
    print("• Support ticket system")
    print("• SSH session management (simulated)")
    print("• Real-time charts and updates")
    
    print("\n" + "=" * 50)
    print("🚀 Starting dashboard server...")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    
    try:
        # Start the dashboard
        subprocess.run([sys.executable, "dashboard_server.py"])
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")

if __name__ == "__main__":
    main() 