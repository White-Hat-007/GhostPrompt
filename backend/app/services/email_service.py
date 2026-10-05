import os
import re
from typing import List, Dict, Any
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from app.core.config import get_settings
from pydantic import EmailStr
import logging

logger = logging.getLogger(__name__)
settings = get_settings()

conf = ConnectionConfig(
    MAIL_USERNAME=settings.SMTP_USER,
    MAIL_PASSWORD=settings.SMTP_PASSWORD or "",
    MAIL_FROM=settings.SMTP_USER,
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)

fast_mail = FastMail(conf)

def _html_to_text(html: str) -> str:
    """Fallback plain-text generator from HTML."""
    text = re.sub(r'<style.*?</style>', '', html, flags=re.DOTALL)
    text = re.sub(r'<[^>]+>', '\n', text)
    text = re.sub(r'\n\s*\n', '\n\n', text)
    return text.strip()

class EmailService:
    @staticmethod
    async def _send(subject: str, email: str, html: str):
        if not conf.MAIL_PASSWORD:
            logger.warning("SMTP_PASSWORD not set. Skipping email to %s", email)
            return

        # Attempt to send multipart if supported, or just HTML
        # In standard fastapi-mail, we pass the HTML as body and set subtype=html
        # Since we want to ensure robust delivery, some providers prefer plain text.
        # For simplicity with fastapi-mail's MessageSchema, we'll continue with HTML, 
        # but add the plain text content into the schema if supported by the version,
        # or we just rely on HTML. We will construct a multipart payload manually 
        # if needed, but fastapi-mail's standard way is via templates. 
        # For now, we will add the text fallback to the body parameter and HTML to html parameter.
        
        # Depending on fastapi-mail version:
        try:
            # Try passing both html and body (plain text fallback)
            message = MessageSchema(
                subject=subject,
                recipients=[email],
                body=_html_to_text(html),
                html=html,
                subtype=MessageType.multipart
            )
        except Exception:
            # Fallback to older fastapi-mail version
            message = MessageSchema(
                subject=subject,
                recipients=[email],
                body=html,
                subtype=MessageType.html
            )
            
        try:
            await fast_mail.send_message(message)
            logger.info("Email '%s' sent to %s", subject, email)
        except Exception as e:
            logger.error("Failed to send email '%s': %s", subject, str(e))

    @staticmethod
    async def send_verification_email(email: EmailStr, token: str):
        verification_link = f"{settings.FRONTEND_URL}/auth/verify-email?token={token}"
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
                body {{ font-family: 'Inter', -apple-system, sans-serif; background-color: #0A0E14; color: #CBD5E1; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }}
                .outer {{ background-color: #0A0E14; padding: 40px 20px; }}
                .container {{ max-width: 560px; margin: 0 auto; background: linear-gradient(135deg, #0F1419 0%, #0A0E14 50%, #0D1117 100%); border-radius: 12px; border: 1px solid #1E293B; box-shadow: 0 0 40px rgba(0, 212, 255, 0.05), 0 0 80px rgba(0, 0, 0, 0.6); overflow: hidden; }}
                
                /* Terminal header bar */
                .terminal-bar {{ background: linear-gradient(90deg, #0D1117, #131A24); padding: 12px 16px; border-bottom: 1px solid #1E293B; display: flex; align-items: center; gap: 8px; }}
                .terminal-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
                .dot-red {{ background: #FF5F56; }}
                .dot-yellow {{ background: #FFBD2E; }}
                .dot-green {{ background: #27C93F; }}
                .terminal-title {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #4B5563; margin-left: 12px; letter-spacing: 0.5px; }}

                /* Scanline effect */
                .scanline {{ height: 2px; background: linear-gradient(90deg, transparent 0%, rgba(0, 212, 255, 0.15) 50%, transparent 100%); margin: 0; }}

                .body-content {{ padding: 36px 32px; }}
                
                /* Logo */
                .logo {{ font-family: 'JetBrains Mono', monospace; font-size: 28px; font-weight: 700; text-align: center; margin-bottom: 8px; }}
                .logo-ghost {{ color: #F1F5F9; }}
                .logo-prompt {{ color: #00D4FF; }}
                .logo-cursor {{ color: #EF4444; animation: blink 1s infinite; }}
                
                .tagline {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #4B5563; text-align: center; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 32px; }}
                
                /* Status block */
                .status-block {{ background: rgba(0, 212, 255, 0.04); border: 1px solid rgba(0, 212, 255, 0.12); border-radius: 8px; padding: 20px; margin-bottom: 28px; font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.8; color: #64748B; }}
                .status-line {{ }}
                .status-ok {{ color: #27C93F; }}
                .status-pending {{ color: #FFBD2E; }}
                .status-label {{ color: #94A3B8; }}
                .status-value {{ color: #CBD5E1; }}
                
                .message {{ font-size: 14px; line-height: 1.7; color: #94A3B8; text-align: center; margin-bottom: 32px; }}
                .message strong {{ color: #F1F5F9; }}
                
                /* CTA Button */
                .cta-container {{ text-align: center; margin: 36px 0; }}
                .cta-btn {{ display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #0A0E14; background: linear-gradient(135deg, #00D4FF 0%, #00B4D8 100%); padding: 16px 36px; border-radius: 6px; text-decoration: none; box-shadow: 0 0 20px rgba(0, 212, 255, 0.25), 0 4px 12px rgba(0, 0, 0, 0.3); }}
                
                /* Fallback URL */
                .fallback {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #374151; text-align: center; word-break: break-all; margin-top: 16px; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 6px; border: 1px solid #1E293B; }}
                .fallback a {{ color: #4B5563; text-decoration: none; }}
                
                /* Footer */
                .footer {{ border-top: 1px solid #1E293B; margin-top: 32px; padding: 24px 32px; text-align: center; }}
                .footer-text {{ font-size: 11px; color: #374151; line-height: 1.6; }}
                .footer-text a {{ color: #4B5563; text-decoration: none; }}
                .security-badge {{ font-family: 'JetBrains Mono', monospace; font-size: 9px; color: #1E293B; margin-top: 12px; letter-spacing: 1px; }}
            </style>
        </head>
        <body>
            <div class="outer">
                <div class="container">
                    <!-- Terminal bar -->
                    <div class="terminal-bar">
                        <div class="terminal-dot dot-red"></div>
                        <div class="terminal-dot dot-yellow"></div>
                        <div class="terminal-dot dot-green"></div>
                        <span class="terminal-title">ghostprompt@security:~/verify</span>
                    </div>
                    
                    <div class="scanline"></div>
                    
                    <div class="body-content">
                        <!-- Logo -->
                        <div class="logo">
                            <span class="logo-ghost">Ghost</span><span class="logo-prompt">Prompt</span><span class="logo-cursor">_</span>
                        </div>
                        <div class="tagline">AI Security Firewall</div>
                        
                        <!-- Status block (terminal style) -->
                        <div class="status-block">
                            <div class="status-line"><span class="status-ok">&#x2713;</span> <span class="status-label">account.create</span> <span class="status-value">— complete</span></div>
                            <div class="status-line"><span class="status-ok">&#x2713;</span> <span class="status-label">credentials.hash</span> <span class="status-value">— bcrypt-12 stored</span></div>
                            <div class="status-line"><span class="status-pending">&#x25CF;</span> <span class="status-label">email.verify</span> <span class="status-value">— <strong style="color:#FFBD2E;">AWAITING CONFIRMATION</strong></span></div>
                            <div class="status-line"><span class="status-label">  target:</span> <span class="status-value">{email}</span></div>
                        </div>
                        
                        <!-- Message -->
                        <div class="message">
                            Your GhostPrompt account has been provisioned. Verify your email to activate the <strong>AI Firewall dashboard</strong>, threat monitoring, and all security features.
                        </div>
                        
                        <!-- CTA -->
                        <div class="cta-container">
                            <a href="{verification_link}" class="cta-btn">[ EXECUTE VERIFICATION ]</a>
                        </div>
                        
                        <!-- Fallback link -->
                        <div class="fallback">
                            If the button doesn't work, copy and paste this URL:<br>
                            <a href="{verification_link}">{verification_link}</a>
                        </div>
                    </div>
                    
                    <!-- Footer -->
                    <div class="footer">
                        <div class="footer-text">
                            &copy; 2026 GhostPrompt Security &mdash; AI Firewall Platform<br>
                            This is an automated security email. If you did not create an account, safely ignore this message.<br>
                            <a href="{settings.FRONTEND_URL}">ghostprompt.io</a>
                        </div>
                        <div class="security-badge">
                            ENCRYPTED &bull; SIGNED &bull; VERIFIED
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        await EmailService._send("Verify your GhostPrompt account", email, html)

    @staticmethod
    async def send_password_reset_email(email: EmailStr, token: str):
        reset_link = f"{settings.FRONTEND_URL}/auth/reset-password?token={token}"
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Inter', -apple-system, sans-serif; background-color: #060610; color: #f0f4ff; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 40px auto; background-color: #0d0d1a; padding: 40px; border-radius: 16px; border: 1px solid #1c1c30; box-shadow: 0 4px 24px rgba(0,0,0,0.4); }}
                .logo {{ display: flex; align-items: center; justify-content: center; margin-bottom: 30px; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff; text-align: center; }}
                .logo span {{ color: #ef4444; margin-left: 2px; }}
                .content {{ font-size: 15px; line-height: 1.6; color: #bac8ff; text-align: center; }}
                .title {{ color: #ffffff; font-size: 20px; font-weight: 600; margin-bottom: 16px; }}
                .btn-container {{ text-align: center; margin: 40px 0; }}
                .btn {{ background-color: #f0f4ff; color: #060610; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 15px; display: inline-block; transition: background-color 0.2s; }}
                .btn:hover {{ background-color: #dbe4ff; }}
                .footer {{ border-top: 1px solid #1c1c30; margin-top: 40px; padding-top: 20px; text-align: center; font-size: 12px; color: #5c7cfa; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">Ghost<span>Prompt</span></div>
                <div class="content">
                    <div class="title">Reset Your Password</div>
                    <p>We received a request to reset the password for your GhostPrompt account. Click the button below to choose a new password.</p>
                </div>
                <div class="btn-container">
                    <a href="{reset_link}" class="btn">Reset Password</a>
                </div>
                <div class="footer">
                    &copy; 2026 GhostPrompt Security. All rights reserved.<br>
                    This link will expire in 30 minutes. If you did not request this, please safely ignore this email.
                </div>
            </div>
        </body>
        </html>
        """
        await EmailService._send("GhostPrompt Password Reset", email, html)

email_service = EmailService()

# ── Extended Lifecycle Emails ──

EMAIL_TEMPLATE_STYLE = """
body { font-family: 'Inter', -apple-system, sans-serif; background-color: #060610; color: #f0f4ff; margin: 0; padding: 0; }
.container { max-width: 600px; margin: 40px auto; background-color: #0d0d1a; padding: 40px; border-radius: 16px; border: 1px solid #1c1c30; box-shadow: 0 4px 24px rgba(0,0,0,0.4); }
.logo { display: flex; align-items: center; justify-content: center; margin-bottom: 30px; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; color: #ffffff; text-align: center; }
.logo span { color: #3b82f6; margin-left: 2px; }
.content { font-size: 15px; line-height: 1.7; color: #bac8ff; }
.title { color: #ffffff; font-size: 20px; font-weight: 600; margin-bottom: 16px; text-align: center; }
.btn-container { text-align: center; margin: 32px 0; }
.btn { background: linear-gradient(135deg, #2563eb, #0891b2); color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 10px; font-weight: 700; font-size: 14px; display: inline-block; letter-spacing: 0.5px; }
.detail-row { padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
.detail-label { color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
.detail-value { color: #ffffff; font-size: 14px; font-weight: 500; }
.alert-box { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); border-radius: 8px; padding: 16px; margin: 16px 0; }
.alert-box.warning { background: rgba(251,191,36,0.08); border-color: rgba(251,191,36,0.2); }
.footer { border-top: 1px solid #1c1c30; margin-top: 40px; padding-top: 20px; text-align: center; font-size: 11px; color: #4b5563; }
"""

async def send_org_created_email(email: str, org_name: str, creator_name: str):
    html = f"""<!DOCTYPE html><html><head><style>{EMAIL_TEMPLATE_STYLE}</style></head>
    <body><div class="container">
        <div class="logo">Ghost<span>Prompt</span></div>
        <div class="content">
            <div class="title">🛡️ Organization Created</div>
            <p>Your organization <strong>{org_name}</strong> has been successfully created on GhostPrompt.</p>
            <div class="detail-row"><span class="detail-label">Organization</span><br><span class="detail-value">{org_name}</span></div>
            <div class="detail-row"><span class="detail-label">Created By</span><br><span class="detail-value">{creator_name}</span></div>
            <div class="detail-row"><span class="detail-label">Platform</span><br><span class="detail-value">GhostPrompt AI Runtime Security</span></div>
            <div class="btn-container"><a href="{settings.FRONTEND_URL}/dashboard" class="btn">Open Dashboard →</a></div>
            <p style="font-size:13px; color:#6b7280;">Your 33-engine AI firewall is now active. Configure your first policy to start protecting your AI applications.</p>
        </div>
        <div class="footer">&copy; 2026 GhostPrompt Security. All rights reserved.<br>This email was sent from {settings.SMTP_USER}</div>
    </div></body></html>"""
    await EmailService._send(f"Welcome to GhostPrompt — {org_name} is ready", email, html)

async def send_member_invited_email(email: str, org_name: str, inviter_name: str, role: str, invite_link: str):
    html = f"""<!DOCTYPE html><html><head><style>{EMAIL_TEMPLATE_STYLE}</style></head>
    <body><div class="container">
        <div class="logo">Ghost<span>Prompt</span></div>
        <div class="content">
            <div class="title">You're Invited</div>
            <p><strong>{inviter_name}</strong> has invited you to join <strong>{org_name}</strong> on GhostPrompt as a <strong>{role}</strong>.</p>
            <div class="btn-container"><a href="{invite_link}" class="btn">Accept Invitation →</a></div>
            <p style="font-size:13px; color:#6b7280;">This invitation link will expire in 7 days.</p>
        </div>
        <div class="footer">&copy; 2026 GhostPrompt Security. All rights reserved.</div>
    </div></body></html>"""
    await EmailService._send(f"You've been invited to {org_name} on GhostPrompt", email, html)

async def send_security_alert_email(email: str, org_name: str, alert_type: str, details: str, severity: str = "high"):
    severity_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6"}.get(severity, "#3b82f6")
    html = f"""<!DOCTYPE html><html><head><style>{EMAIL_TEMPLATE_STYLE}</style></head>
    <body><div class="container">
        <div class="logo">Ghost<span>Prompt</span></div>
        <div class="content">
            <div class="title">⚠️ Security Alert</div>
            <div class="alert-box" style="border-color: {severity_color}20; background: {severity_color}08;">
                <div style="color: {severity_color}; font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">{severity.upper()} — {alert_type}</div>
                <p style="color: #d1d5db; font-size: 14px; margin: 0;">{details}</p>
            </div>
            <div class="detail-row"><span class="detail-label">Organization</span><br><span class="detail-value">{org_name}</span></div>
            <div class="btn-container"><a href="{settings.FRONTEND_URL}/dashboard?section=overview" class="btn">View in Dashboard →</a></div>
        </div>
        <div class="footer">&copy; 2026 GhostPrompt Security. All rights reserved.<br>Manage alert preferences in Settings → Notifications</div>
    </div></body></html>"""
    await EmailService._send(f"[{severity.upper()}] GhostPrompt Security Alert — {alert_type}", email, html)

async def send_api_key_created_email(email: str, org_name: str, key_name: str):
    """Send notification when a new API key is generated (Security best practice)."""
    html = f"""<!DOCTYPE html><html><head><style>{EMAIL_TEMPLATE_STYLE}</style></head>
    <body><div class="container">
        <div class="logo">Ghost<span>Prompt</span></div>
        <div class="content">
            <div class="title">🔑 API Key Generated</div>
            <p>A new API key was just generated in your organization.</p>
            <div class="detail-row"><span class="detail-label">Organization</span><br><span class="detail-value">{org_name}</span></div>
            <div class="detail-row"><span class="detail-label">Key Name</span><br><span class="detail-value">{key_name}</span></div>
            <div class="btn-container"><a href="{settings.FRONTEND_URL}/settings?tab=api" class="btn">Review API Keys →</a></div>
            <p style="font-size:13px; color:#6b7280;">If you did not authorize this action, please immediately revoke the key and change your password.</p>
        </div>
        <div class="footer">&copy; 2026 GhostPrompt Security. All rights reserved.</div>
    </div></body></html>"""
    await EmailService._send(f"Security Notice: New API Key Generated for {org_name}", email, html)

async def send_password_changed_email(email: str):
    """Send confirmation when a password is changed."""
    html = f"""<!DOCTYPE html><html><head><style>{EMAIL_TEMPLATE_STYLE}</style></head>
    <body><div class="container">
        <div class="logo">Ghost<span>Prompt</span></div>
        <div class="content">
            <div class="title">🔐 Password Changed</div>
            <p>Your GhostPrompt account password was successfully updated.</p>
            <p style="font-size:13px; color:#6b7280;">If you did not authorize this change, please contact security support immediately.</p>
        </div>
        <div class="footer">&copy; 2026 GhostPrompt Security. All rights reserved.</div>
    </div></body></html>"""
    await EmailService._send("GhostPrompt Password Changed", email, html)
