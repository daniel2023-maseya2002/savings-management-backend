import secrets
import hashlib
import hmac
import time
from django.utils import timezone
from datetime import timedelta

OTP_LENGTH = 6
OTP_TTL = timedelta(minutes=10)

def generate_otp():
    # 6-digit zero-padded number
    num = secrets.randbelow(10**OTP_LENGTH)
    return f"{num:0{OTP_LENGTH}d}"

def make_salt():
    return secrets.token_hex(8)  # 16 chars

def hash_otp(otp: str, salt: str):
    # HMAC with secret key + salt
    key = (salt + secrets.token_hex(8)).encode()  # extra randomness per call
    # you can also use settings.SECRET_KEY as HMAC key
    h = hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()
    # store salt + hashed value (salt stored separately too)
    return h

def verify_otp(provided_otp: str, stored_hash: str, stored_salt: str):
    # re-create hash using same method
    # NOTE: because we used an extra ephemeral token in make_salt above, ensure consistency:
    # Simpler: use salt + secret_key as key so verification is deterministic:
    import hashlib, hmac
    from django.conf import settings
    key = (stored_salt + settings.SECRET_KEY).encode()
    expected = hmac.new(key, provided_otp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, stored_hash)

def expires_at_now():
    return timezone.now() + OTP_TTL
