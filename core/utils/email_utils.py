# core/emailing.py (or wherever you keep helpers)
import os
import traceback
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.loader import render_to_string
from django.template import TemplateDoesNotExist
from email.mime.image import MIMEImage

def send_branded_email(subject, to_email, template_name, context=None):
    """
    Renders `template_name` (which should extend emails/base_email.html)
    and sends HTML email with an inline logo via CID.
    Raises on failure with a clear error.
    """
    context = context or {}

    # Inline logo CID setup
    logo_cid = "creditjambo_logo"
    logo_path = os.path.join(settings.BASE_DIR, "templates", "pictures", "logo.png")
    context["logo_cid"] = logo_cid  # used in <img src="cid:{{ logo_cid }}">

    try:
        # Render the CHILD template (e.g. "emails/otp_code.html")
        html_content = render_to_string(template_name, context)
    except TemplateDoesNotExist as e:
        # Surface the exact missing template
        raise RuntimeError(f"Template missing: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Template render failed for '{template_name}': {e}") from e

    try:
        # Use your configured EMAIL_BACKEND
        connection = get_connection(fail_silently=False)

        msg = EmailMultiAlternatives(
            subject=subject,
            body="",  # we only send HTML part here
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            to=[to_email],
            connection=connection,
        )
        # make it a 'related' MIME so inline images work
        msg.mixed_subtype = "related"

        # HTML alternative
        msg.attach_alternative(html_content, "text/html")

        # Attach the inline logo (optional)
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo = MIMEImage(f.read())
                logo.add_header("Content-ID", f"<{logo_cid}>")
                logo.add_header("Content-Disposition", "inline", filename="logo.png")
                msg.attach(logo)

        # Send
        msg.send()
    except Exception as e:
        # Print full traceback in logs to see SMTP or other failures
        tb = traceback.format_exc()
        raise RuntimeError(f"Email send failed: {e}\n{tb}") from e
