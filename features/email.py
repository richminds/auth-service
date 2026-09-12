"""Outbound email — currently only password-reset messages.

Two modes, chosen by configuration alone:

* SMTP configured  → send for real over STARTTLS or implicit SSL.
* SMTP unconfigured → log the message body at WARNING and report ``False``.

That second mode is what makes the flow developable without a mail server, and
it is also what the caller keys the debug-token escape hatch off
(features/password_reset.py): a message that was never dispatched is the only
case where returning the raw token to the client is defensible.

Sending is deliberately synchronous and best-effort. Every failure path
returns ``False`` rather than raising, because a password-reset REQUEST must
not reveal — via a 500 — that the email existed. The caller responds with the
same generic message either way.

``smtplib`` is stdlib, so this adds no dependency.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from .config import auth_settings

logger = logging.getLogger(__name__)


def smtp_configured() -> bool:
    """Both a host and a From address are needed before we can send anything."""
    return bool(auth_settings.smtp_host and auth_settings.smtp_from_email)


def send_email(to_email: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    """Dispatch one message. Returns True only if SMTP actually accepted it."""
    if not smtp_configured():
        logger.warning(
            "Auth: SMTP not configured — email NOT sent.\nTO: %s\nSUBJECT: %s\nBODY:\n%s",
            to_email,
            subject,
            body_text,
        )
        return False

    msg = EmailMessage()
    msg["From"] = formataddr((auth_settings.smtp_from_name, auth_settings.smtp_from_email))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        if auth_settings.smtp_use_tls:
            with smtplib.SMTP(auth_settings.smtp_host, auth_settings.smtp_port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if auth_settings.smtp_username:
                    smtp.login(auth_settings.smtp_username, auth_settings.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP_SSL(
                auth_settings.smtp_host, auth_settings.smtp_port, timeout=15
            ) as smtp:
                if auth_settings.smtp_username:
                    smtp.login(auth_settings.smtp_username, auth_settings.smtp_password)
                smtp.send_message(msg)
        logger.info("Auth: password-reset email sent to %s", to_email)
        return True
    except Exception:  # noqa: BLE001
        # Logged, never raised — see the module docstring.
        logger.exception("Auth: failed to send email to %s", to_email)
        return False


def send_password_reset_email(
    *,
    to_email: str,
    name: str,
    app_name: str,
    reset_link: str,
    expires_minutes: int,
) -> bool:
    """The reset message itself.

    ``app_name`` is the app account's display name rather than a hardcoded
    product: one auth-service backs several applications, and a message
    naming one of them to someone resetting their password for another would
    look like a phishing attempt.
    """
    subject = f"Reset your {app_name} password"
    text_body = (
        f"Hi {name or 'there'},\n\n"
        f"We received a request to reset your {app_name} password.\n"
        f"Open the link below to choose a new password "
        f"(valid for {expires_minutes} minutes):\n\n"
        f"{reset_link}\n\n"
        f"If you did not request this, you can safely ignore this email — "
        f"your password will not change.\n\n"
        f"— {app_name}"
    )
    html_body = f"""
    <html><body style="font-family: Arial, sans-serif; color: #151523; line-height: 1.5;">
      <h2 style="color:#6366f1;">Reset your {app_name} password</h2>
      <p>Hi {name or 'there'},</p>
      <p>We received a request to reset your {app_name} password.
      Click the button below to choose a new one.
      This link is valid for <b>{expires_minutes} minutes</b>.</p>
      <p style="margin: 24px 0;">
        <a href="{reset_link}" style="background:#8b5cf6;color:#fff;padding:12px 24px;
            text-decoration:none;border-radius:8px;font-weight:600;display:inline-block;">
          Reset Password
        </a>
      </p>
      <p>Or copy &amp; paste this link into your browser:<br>
        <a href="{reset_link}">{reset_link}</a>
      </p>
      <p style="color:#676783;font-size:13px;margin-top:32px;">
        If you did not request a password reset you can safely ignore this email —
        your password will not change.
      </p>
      <p style="color:#676783;font-size:13px;">— {app_name}</p>
    </body></html>
    """
    return send_email(to_email, subject, text_body, html_body)
