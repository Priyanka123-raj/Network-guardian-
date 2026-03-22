from ping3 import ping
from pysnmp.hlapi import (SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd)
import nmap
import psutil
import sqlite3
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np
import smtplib
from email.mime.text import MIMEText

class NetworkMonitor:
    def __init__(self):
        self.conn = sqlite3.connect('network.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Initialize AI Anomaly Detector
        self.setup_ai_model()
        
        # Prevent spamming emails (cooldown of 5 minutes)
        self.last_email_time = 0

    def setup_ai_model(self):
        # IsolationForest to detect anomalies in resource usage
        self.ai_model = IsolationForest(contamination=0.1, random_state=42)
        # Some synthetic normal data to train the model ([cpu, memory, disk])
        synthetic_normal_data = np.array([
            [20, 40, 50], [25, 45, 52], [30, 42, 51], [22, 38, 49], 
            [28, 41, 55], [35, 46, 50], [15, 35, 48], [40, 50, 60]
        ])
        self.ai_model.fit(synthetic_normal_data)
        print("✅ AI Anomaly Detection Model initialized.")

    def send_admin_email(self, threat_score, metrics):
        admin_email = "ezhil106arasan@gmail.com"
        subject = f"🚨 URGENT: Network Threat Detected! ({threat_score}% Threat Level)"
        body = f"""
ALERT: High Network Threat Detected!

AI Model Threat Calculation: {threat_score}% Threat Level

Current Server Metrics:
- CPU Usage: {metrics['cpu']}%
- Memory Usage: {metrics['memory']}%
- Disk Usage: {metrics['disk']}%

Action Required:
Please login to the Network Guardian admin dashboard immediately to resolve the threats.

Automated by AI Anomaly Detection System."""

        print(f"\n📧 === NOTIFICATION: Sending Email to Admin ===")
        print(f"To: {admin_email}")
        print(f"Subject: {subject}")
        print(f"Body: {body}\n")
        
        # Real SMTP logic - Uncomment and add app password to actually send email via Gmail
        try:
            # msg = MIMEText(body)
            # msg['Subject'] = subject
            # msg['From'] = "alerts@networkguardian.local"
            # msg['To'] = admin_email
            # 
            # server = smtplib.SMTP('smtp.gmail.com', 587)
            # server.starttls()
            # server.login("YOUR_EMAIL@gmail.com", "YOUR_APP_PASSWORD")
            # server.sendmail("YOUR_EMAIL@gmail.com", admin_email, msg.as_string())
            # server.quit()
            print("✅ Admin email notification logged successfully! (Real sending requires credentials)")
        except Exception as e:
            print(f"❌ Failed to send admin email: {e}")
            
    # Calculate AI threat percentage
    def analyze_threat(self, metrics):
        data = np.array([[metrics['cpu'], metrics['memory'], metrics['disk']]])
        prediction = self.ai_model.predict(data)[0]
        
        # Base threat based on raw resource consumption
        base_threat = (metrics['cpu'] + metrics['memory'] + metrics['disk']) / 3.0
        
        # If AI detects an anomaly, boost the threat score significantly
        if prediction == -1:
            threat_percent = min(100.0, base_threat * 1.5 + 20)
        else:
            threat_percent = min(100.0, base_threat)
            
        return round(threat_percent, 2)
    
    # 1. PING - Check device online/offline
    def check_ping(self, ip):
        try:
            response = ping(ip, timeout=2)
            return "online" if response else "offline"
        except:
            return "offline"
    
    # 2. SNMP - Get device name
    def get_snmp_name(self, ip, community='public'):
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=2),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                return str(varBinds[0][1])
            return None
        except:
            return None
    
    # 3. NMAP - Scan network for devices
    def scan_network(self, network='192.168.1.0/24'):
        try:
            nm = nmap.PortScanner()
            nm.scan(network, '22-80', arguments='-sn')  # Ping scan
            return nm.all_hosts()
        except:
            return []
    
    # 4. PSUTIL - Get server metrics
    def get_server_metrics(self):
        try:
            return {
                'cpu': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory().percent,
                'disk': psutil.disk_usage('/').percent,
                'uptime': time.time() - psutil.boot_time()
            }
        except:
            return {'cpu': 0, 'memory': 0, 'disk': 0, 'uptime': 0}
    
    # 5. Update all devices status
    def update_all_devices(self):
        self.cursor.execute("SELECT id, ip FROM devices")
        devices = self.cursor.fetchall()
        
        for device in devices:
            status = self.check_ping(device[1])
            self.cursor.execute("UPDATE devices SET status = ?, last_seen = ? WHERE id = ?",
                              (status, datetime.now().strftime("%H:%M:%S"), device[0]))
        
        self.conn.commit()
        print(f"✅ {len(devices)} devices updated at {datetime.now()}")
    
    # 6. Auto-discover new devices
    def discover_devices(self, network='192.168.1.0/24'):
        hosts = self.scan_network(network)
        
        for ip in hosts:
            # Check if already exists
            self.cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
            if not self.cursor.fetchone():
                name = self.get_snmp_name(ip) or f"Device-{ip}"
                self.cursor.execute('''
                    INSERT INTO devices (name, ip, status, threat_level, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                ''', (name, ip, 'online', 'low', 'Just now'))
                print(f"✅ New device discovered: {name} ({ip})")
        
        self.conn.commit()
    
    # 7. Check for threats using AI
    def check_threats(self):
        metrics = self.get_server_metrics()
        threat_percent = self.analyze_threat(metrics)
        
        print(f"🔍 AI Threat Scan: Threat Level is {threat_percent}%")
        
        # AI Alert notification trigger
        if threat_percent >= 85.0:
            msg = f'🤖 AI ALERT: Critically High Threat Level ({threat_percent}%)'
            self.create_alert('Server', msg, 'high')
            
            # Send email, throttle to max 1 email every 5 minutes (300s)
            current_time = time.time()
            if current_time - self.last_email_time > 300:
                self.send_admin_email(threat_percent, metrics)
                self.last_email_time = current_time
                
        # Fallback to simple thresholds if AI isn't triggered
        elif metrics['cpu'] > 90:
            self.create_alert('Server', f'⚠️ High CPU: {metrics["cpu"]}%', 'high')
        elif metrics['memory'] > 95:
            self.create_alert('Server', f'⚠️ High Memory: {metrics["memory"]}%', 'high')
        elif metrics['disk'] > 90:
            self.create_alert('Server', f'⚠️ Low Disk: {metrics["disk"]}% used', 'medium')
    
    # 8. Create alert
    def create_alert(self, device, message, severity):
        self.cursor.execute('''
            INSERT INTO alerts (device_name, message, severity, timestamp, is_resolved)
            VALUES (?, ?, ?, ?, ?)
        ''', (device, message, severity, datetime.now().strftime("%I:%M %p"), 0))
        self.conn.commit()
        print(f"🚨 Alert: {message}")

# ============================================
# MAIN MONITORING LOOP
# ============================================
def start_monitoring():
    monitor = NetworkMonitor()
    
    print("🚀 Network Monitor Started!")
    
    while True:
        try:
            # 1. Update existing devices (every 60 sec)
            monitor.update_all_devices()
            
            # 2. Discover new devices (every 5 min)
            if int(time.time()) % 300 < 60:  # Every 5 minutes
                monitor.discover_devices()
            
            # 3. Check threats (every 30 sec)
            monitor.check_threats()
            
            # Wait 60 seconds
            time.sleep(60)
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    start_monitoring()
