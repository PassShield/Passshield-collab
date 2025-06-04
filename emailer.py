import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables from .env file
load_dotenv()

class EmailService:
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.sender_email = os.getenv('SENDER_EMAIL')
        self.sender_password = os.getenv('SENDER_PASSWORD')
        if not self.sender_email or not self.sender_password:
            raise ValueError("Email credentials not configured in environment variables")
        self.context = ssl.create_default_context()

    def send_email(
        self, 
        recipient_email: str, 
        subject: str, 
        body: str, 
        is_html: bool = False
    ) -> bool:
        """
        Core email sending function
        
        Args:
            recipient_email: Email address of the recipient
            subject: Email subject
            body: Email body content
            is_html: Whether the body contains HTML content
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not recipient_email or not subject or not body:
            print("Error: Missing required email parameters")
            return False

        try:
            message = MIMEMultipart()
            message['From'] = self.sender_email
            message['To'] = recipient_email
            message['Subject'] = subject
            
            # Attach the body with appropriate content type
            content_type = 'html' if is_html else 'plain'
            message.attach(MIMEText(body, content_type))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()
                server.starttls(context=self.context)
                server.ehlo()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(
                    self.sender_email, 
                    recipient_email, 
                    message.as_string()
                )
            return True
        except smtplib.SMTPAuthenticationError as e:
            print(f"SMTP Authentication Error: {e}")
            return False
        except smtplib.SMTPException as e:
            print(f"SMTP Error: {e}")
            return False
        except Exception as e:
            print(f"Error sending email: {e}")
            return False

def send_welcome_email(recipient_email: str, username: str) -> bool:
    """
    Send welcome email to new users
    
    Args:
        recipient_email: Email address of the new user
        username: Username of the new user
        
    Returns:
        bool: True if email was sent successfully
    """
    if not recipient_email or not username:
        print("Error: Missing required parameters for welcome email")
        return False

    subject = "Welcome to PassShield - Your Account is Ready!"
    body = f"""
    <html>
        <body>
            <h2>Welcome to PassShield, {username}!</h2>
            <p>Thank you for registering with PassShield, your trusted password manager.</p>
            
            <p>Your account has been successfully created. Here's what you can do next:</p>
            <ul>
                <li>Store and manage your passwords securely</li>
                <li>Generate strong passwords</li>
                <li>Access your passwords from anywhere</li>
            </ul>
            
            <p>If you didn't create this account, please contact our support immediately.</p>
            
            <p>Best regards,<br>
            The PassShield Team</p>
        </body>
    </html>
    """
    
    try:
        emailer = EmailService()
        return emailer.send_email(recipient_email, subject, body, is_html=True)
    except Exception as e:
        print(f"Error in send_welcome_email: {e}")
        return False

def send_password_reset_email(
    recipient_email: str, 
    username: str, 
    reset_token: str,
    reset_link: Optional[str] = None
) -> bool:
    """
    Send password reset email with token or reset link
    
    Args:
        recipient_email: User's email address
        username: User's username
        reset_token: Password reset token
        reset_link: Optional reset link (if provided, will be used instead of token)
        
    Returns:
        bool: True if email was sent successfully
    """
    if not recipient_email or not username or not reset_token:
        print("Error: Missing required parameters for password reset email")
        return False

    subject = "PassShield - Password Reset Request"
    
    if reset_link:
        reset_content = f'<a href="{reset_link}">Click here to reset your password</a>'
    else:
        reset_content = f'Your password reset token is: <strong>{reset_token}</strong>'
    
    body = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {username},</p>
            
            <p>We received a request to reset your PassShield password.</p>
            
            <p>{reset_content}</p>
            
            <p>This {'link' if reset_link else 'token'} will expire in 15 minutes. 
            If you didn't request this reset, please ignore this email.</p>
            
            <p>Best regards,<br>
            The PassShield Team</p>
        </body>
    </html>
    """
    
    try:
        emailer = EmailService()
        return emailer.send_email(recipient_email, subject, body, is_html=True)
    except Exception as e:
        print(f"Error in send_password_reset_email: {e}")
        return False

def send_password_change_notification(recipient_email: str, username: str) -> bool:
    """
    Send notification when user changes their password
    
    Args:
        recipient_email: User's email address
        username: User's username
        
    Returns:
        bool: True if email was sent successfully
    """
    if not recipient_email or not username:
        print("Error: Missing required parameters for password change notification")
        return False

    subject = "Your PassShield Password Was Changed"
    body = f"""
    <html>
        <body>
            <h2>Password Changed Successfully</h2>
            <p>Hello {username},</p>
            
            <p>This is a confirmation that your PassShield password was recently changed.</p>
            
            <p>If you didn't make this change, please contact our support immediately.</p>
            
            <p>Best regards,<br>
            The PassShield Team</p>
        </body>
    </html>
    """
    
    try:
        emailer = EmailService()
        return emailer.send_email(recipient_email, subject, body, is_html=True)
    except Exception as e:
        print(f"Error in send_password_change_notification: {e}")
        return False