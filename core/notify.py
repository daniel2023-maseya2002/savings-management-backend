from django.conf import settings
from django.core.mail import send_mail

def send_otp_email(destination_email, otp, expires_at):
    subject = "Your verification code"
    message = f"Your verification code is {otp}. It expires at {expires_at.isoformat()}."
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [destination_email])

# Twilio example (install twilio package if using)
def send_otp_sms(destination_phone, otp, expires_at):
    from twilio.rest import Client
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    body = f"Your verification code is {otp}. Expires in 10 minutes."
    client.messages.create(body=body, from_=settings.TWILIO_FROM_NUMBER, to=destination_phone)
