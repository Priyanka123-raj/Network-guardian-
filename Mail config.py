import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
from datetime import datetime

class EmailAlert:
    def __init__(self):
        # ========== YOUR EMAIL CONFIGURATION ==========
        self.smtp_server = "smtp.gmail.com"
        self.port = 587
        self.sender_email = "ezhil0106arasan@gmail.com"
        self.sender_password = "xxbw wioi bvoi hyrp"  # App Password (16 digits)
        # ==============================================
        
        # Admin email list - Add admin email addresses here
        self.admin_emails = [
            "ezhil0106arasan@gmail.com",  # Send to yourself for testing
            # Add more admins: "admin2@college.edu",
        ]
    
    def send_alert(self, device_name, threat_type, root_cause, severity, traffic=None):
        """Send email alert to all admins"""
        
        subject = f"🚨 {severity} ALERT: {threat_type} on {device_name}"
        
        body = f"""
╔══════════════════════════════════════════════════════════╗
║           NETWORK GUARDIAN SECURITY ALERT                ║
╚══════════════════════════════════════════════════════════╝

📱 Device: {device_name}
⚠️ Threat: {threat_type}
🔴 Severity: {severity}
⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 ROOT CAUSE:
{root_cause}

📊 Traffic Data: {traffic if traffic else 'Abnormal traffic detected'}

🛡️ RECOMMENDED ACTION:
1. Login to Network Guardian Dashboard
2. Go to Devices section
3. Click BLOCK button for {device_name}
4. Monitor traffic for 5 minutes
5. Click UNBLOCK if resolved

🔗 Dashboard: http://localhost:5500

---
This is an automated alert from Network Guardian Security System
"""
        
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ", ".join(self.admin_emails)
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            context = ssl.create_default_context()
            server = smtplib.SMTP(self.smtp_server, self.port)
            server.starttls(context=context)
            server.login(self.sender_email, self.sender_password.replace(' ', ''))  # Remove spaces
            server.send_message(msg)
            server.quit()
            
            print(f"✅ Email sent to {len(self.admin_emails)} admin(s)")
            return True
            
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False
    
    def send_test_email(self):
        """Send a test email to verify configuration"""
        return self.send_alert(
            device_name="TEST DEVICE",
            threat_type="Test Alert",
            root_cause="This is a test email from Network Guardian",
            severity="LOW",
            traffic="Test traffic"
        )

# Create instance
email_alert = EmailAlert()

# Test email (uncomment to test)
# email_alert.send_test_email()
