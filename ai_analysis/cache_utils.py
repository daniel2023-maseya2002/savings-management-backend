# ai_analysis/cache_utils.py
from django.core.cache import cache

def invalidate_flag_list_cache_for_user(admin_pk):
    # If you know keys format, delete them. If not, set short CACHE_TIMEOUT and skip.
    # Example approach: store indexes of keys in cache and pop them when invalidating.
    prefix = f"tx_flags:{admin_pk}:"
    # If using Redis directly you can scan keys
    try:
        # Attempt Redis-specific approach if cache client has .client.get_client()
        client = cache.client.get_client()  # Works with django-redis
        keys = client.keys(f"{prefix}*")
        if keys:
            client.delete(*keys)
    except Exception:
        # fallback: nothing; rely on short timeout
        pass
