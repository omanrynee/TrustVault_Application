"""
Email alert system for TrustVault
"""

import os
import json
import smtplib
import ssl
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import socket
from typing import List, Tuple, Optional

EMAIL_CONFIG_FILE = "data/email_config.json"

class EmailAlertSystem:
    """Send email alerts for critical events - Fixed Gmail Version"""

    def __init__(self, config_file: str = EMAIL_CONFIG_FILE):
        self.config_file = config_file
        self.config = self.load_config()
        self.enabled = self.config.get('enabled', False)
        self.last_error = None
        self.test_mode = False

    def load_config(self) -> dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Config load error: {e}")
                return self.get_default_config()
        return self.get_default_config()

    def get_default_config(self) -> dict:
        return {
            'enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'omanrynee@gmail.com',
            'sender_password': 'ccjw kqmm fzre zqky',
            'recipients': ['omanrynee@gmail.com'],
            'alert_levels': {'CRITICAL': True, 'WARNING': True, 'INFO': False},
            'use_ssl': False,
            'timeout': 30,
            'test_mode': False
        }

    def save_config(self) -> bool:
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Config save error: {e}")
            return False

    def configure(self, smtp_server: str, smtp_port: str, sender_email: str, 
                  sender_password: str, recipients: List[str], test_mode: bool = False) -> Tuple[bool, str]:
        self.config['smtp_server'] = smtp_server
        self.config['smtp_port'] = int(smtp_port)
        self.config['sender_email'] = sender_email
        self.config['sender_password'] = sender_password
        self.config['recipients'] = recipients if isinstance(recipients, list) else [recipients]
        self.config['use_ssl'] = (int(smtp_port) == 465)
        self.config['test_mode'] = test_mode

        self.config['enabled'] = True
        self.save_config()
        self.enabled = True
        return True, "Email configured successfully."

    def test_connection(self) -> Tuple[bool, str]:
        """Test SMTP connection and authentication"""
        if not self.config['sender_email'] or not self.config['sender_password']:
            return False, "Email or password not configured"

        sender_password = self.config['sender_password']
        if "gmail" in self.config.get('sender_email', '').lower() or "gmail" in self.config.get('smtp_server', '').lower():
            sender_password = sender_password.replace(" ", "").replace("-", "")

        try:
            if self.config['use_ssl']:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config['smtp_server'],
                    self.config['smtp_port'],
                    context=context,
                    timeout=self.config['timeout']
                ) as server:
                    server.login(self.config['sender_email'], sender_password)
            else:
                with smtplib.SMTP(
                    self.config['smtp_server'],
                    self.config['smtp_port'],
                    timeout=self.config['timeout']
                ) as server:
                    server.ehlo()
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(self.config['sender_email'], sender_password)

            return True, "SMTP connection successful!"

        except smtplib.SMTPServerDisconnected as e:
            return False, f"SMTP Connection Unexpectedly Closed: {str(e)}. This might happen if the server dropped the connection due to wrong protocol (SSL vs STARTTLS) or timeout."

        except smtplib.SMTPConnectError as e:
            return False, f"SMTP Connection Failed: {str(e)}. Unable to establish connection to the SMTP server."

        except smtplib.SMTPAuthenticationError as e:
            is_gmail = "gmail" in self.config.get('sender_email', '').lower() or "gmail" in self.config.get('smtp_server', '').lower()
            if is_gmail:
                error_msg = (
                    "Gmail SMTP Authentication Failed (535 Bad Credentials).\n\n"
                    "This error indicates that Gmail has rejected your login credentials.\n"
                    "Please ensure:\n"
                    "1. You are using a 16-character Gmail App Password (e.g. 'ccjw kqmm fzre zqky') instead of your normal account password.\n"
                    "2. Two-Factor Authentication (2FA) is enabled on your Google Account.\n"
                    "3. The App Password is configured correctly without typos.\n\n"
                    f"Detail: {str(e)}"
                )
            else:
                error_msg = f"Authentication failed. Please check credentials.\nDetail: {str(e)}"
            return False, error_msg

        except Exception as e:
            return False, f"Connection Error: {str(e)}"

    def send_alert(self, subject: str, body: str, level: str = 'INFO', 
                   attachments: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Send email alert with improved reliability"""
        if not self.enabled or not self.config['recipients']:
            return False, "Email disabled or no recipients"

        if not self.config['alert_levels'].get(level, True):
            return False, f"{level} alerts disabled"

        # Test mode: don't send actual email
        if self.config.get('test_mode', False):
            print(f"[TEST MODE] Would send email: {subject}")
            # Save test email to file
            test_file = os.path.join("logs", f"test_email_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(test_file, 'w') as f:
                f.write(f"Subject: {subject}\n\n{body}")
            return True, f"Test email saved to {test_file}"

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[TrustVault {level}] {subject}"
            msg['From'] = self.config['sender_email']
            msg['To'] = ', '.join(self.config['recipients'])
            msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
            msg['X-Priority'] = '1' if level == 'CRITICAL' else '3'

            # Plain text version
            plain_text = f"""
{subject}
{'=' * len(subject)}

{body}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Alert Level: {level}
System: TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System
            """
            msg.attach(MIMEText(plain_text, 'plain'))

            # HTML version (simplified for brevity)
            html = f"""
<!DOCTYPE html>
<html>
<body>
    <div class="container">
        <div class="header">
            <h2>{subject}</h2>
            <span class="alert-level">{level}</span>
        </div>
        <div class="content">
            <pre>{body}</pre>
            <hr>
            <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>System:</strong> TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System</p>
        </div>
    </div>
</body>
</html>
            """
            msg.attach(MIMEText(html, 'html'))

            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    with open(attachment, 'rb') as f:
                        part = MIMEApplication(f.read(), Name=os.path.basename(attachment))
                    part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment)}"'
                    msg.attach(part)

            # Send email with retry logic
            max_retries = 3
            sender_password = self.config['sender_password']
            if "gmail" in self.config.get('sender_email', '').lower() or "gmail" in self.config.get('smtp_server', '').lower():
                sender_password = sender_password.replace(" ", "").replace("-", "")

            for attempt in range(max_retries):
                try:
                    if self.config['use_ssl']:
                        context = ssl.create_default_context()
                        with smtplib.SMTP_SSL(
                            self.config['smtp_server'],
                            self.config['smtp_port'],
                            context=context,
                            timeout=self.config['timeout']
                        ) as server:
                            server.login(self.config['sender_email'], sender_password)
                            server.send_message(msg)
                    else:
                        with smtplib.SMTP(
                            self.config['smtp_server'],
                            self.config['smtp_port'],
                            timeout=self.config['timeout']
                        ) as server:
                            server.ehlo()
                            context = ssl.create_default_context()
                            server.starttls(context=context)
                            server.ehlo()
                            server.login(self.config['sender_email'], sender_password)
                            server.send_message(msg)

                    return True, "Email sent successfully!"
                    
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(2)

        except smtplib.SMTPServerDisconnected as e:
            error_msg = f"SMTP Server disconnected unexpectedly during email alert dispatch: {str(e)}"
            self.last_error = error_msg
            return False, error_msg
        except Exception as e:
            error_msg = f"Failed to send email after multiple attempts: {str(e)}"
            self.last_error = error_msg
            return False, error_msg

    def send_test_email(self) -> Tuple[bool, str]:
        """Send a test email to verify configuration works"""
        if not self.config['sender_email'] or not self.config['sender_password']:
            return False, "Email configuration incomplete"

        # First test connection
        success, message = self.test_connection()
        if not success:
            return False, f"Connection test failed: {message}"

        # Send actual test email
        subject = "TrustVault - Test Email"
        body = f"""
This is a test email from TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System.

Configuration Details:
• SMTP Server: {self.config['smtp_server']}
• SMTP Port: {self.config['smtp_port']}
• Sender Email: {self.config['sender_email']}
• Recipients: {', '.join(self.config['recipients'])}
• SSL/TLS: {'Enabled' if self.config['use_ssl'] else 'Disabled'}

If you receive this email, your email alert system is configured correctly!
        """
        
        return self.send_alert(subject, body, 'INFO')

    def send_ransomware_alert(self, details: dict) -> Tuple[bool, str]:
        subject = f"🚨 RANSOMWARE DETECTED! - {details.get('filename', 'Unknown')}"
        body = f"""
CRITICAL SECURITY ALERT - RANSOMWARE DETECTED!

Location: {details.get('location', 'Unknown')}
Detected Pattern: {details.get('pattern', 'Unknown')}
Affected Files: {details.get('encrypted_files', 'Unknown')}
Suspicious Extension: {details.get('extension', 'None')}
Ransom Note: {details.get('ransom_note', 'Not found')}
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

IMMEDIATE ACTION REQUIRED:
1. Isolate the affected system from network
2. Contact IT Security team immediately
3. Do NOT restart or power off the system
4. Preserve evidence for investigation

System Details:
• Host: {socket.gethostname()}
• IP Address: {details.get('ip_address', 'Unknown')}
• TrustVault: A PKI-Based Real-Time Cryptographic Monitoring System
        """
        return self.send_alert(subject, body, 'CRITICAL')

    def send_tampering_alert(self, tamper_info: dict) -> Tuple[bool, str]:
        subject = f"🔒 File Tampered - {tamper_info.get('filename', 'Unknown')}"
        body = f"""
FILE INTEGRITY VIOLATION DETECTED!

Filename: {tamper_info.get('filename')}
Full Path: {tamper_info.get('filepath')}

Hash Verification Failed:
• Original Hash: {tamper_info.get('original_hash')[:64]}...
• Current Hash: {tamper_info.get('current_hash')[:64]}...

Additional Details:
• File Registered: {tamper_info.get('registered')}
• Size Change: {tamper_info.get('size_change', 0)} bytes
• Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

POTENTIAL UNAUTHORIZED MODIFICATION DETECTED!
        """
        return self.send_alert(subject, body, 'CRITICAL')

    def send_anomaly_alert(self, anomaly_details: dict) -> Tuple[bool, str]:
        subject = "⚠️ Anomalous Activity Detected"
        body = f"""
UNUSUAL SYSTEM ACTIVITY DETECTED!

Type: {anomaly_details.get('type', 'Unknown')}
Confidence Level: {anomaly_details.get('confidence', 'High')}
Location: {anomaly_details.get('location', 'Unknown')}
Event Rate: {anomaly_details.get('rate', 'Unknown')} events/min
Baseline Rate: {anomaly_details.get('baseline', 'Unknown')} events/min
Standard Deviation: {anomaly_details.get('stdev', 'Unknown')}

Details:
{anomaly_details.get('details', 'No additional details')}

Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        return self.send_alert(subject, body, 'WARNING')

    def get_last_error(self) -> Optional[str]:
        return self.last_error

    def disable(self):
        self.enabled = False
        self.config['enabled'] = False
        self.save_config()

    def enable(self):
        self.enabled = True
        self.config['enabled'] = True
        self.save_config()
