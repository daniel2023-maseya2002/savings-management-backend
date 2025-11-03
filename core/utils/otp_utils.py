# core/utils/otp_utils.py
import random
from datetime import datetime, timedelta
from django.core.cache import cache

def generate_otp(length=6):
    """
    Generate a numeric OTP and store it in cache for 5 minutes.
    """
    otp = "".join([str(random.randint(0, 9)) for _ in range(length)])
    return otp


def verify_otp(key, otp):
    """
    Verify an OTP stored in cache (if you're using caching).
    """
    stored_otp = cache.get(key)
    return stored_otp == otp
