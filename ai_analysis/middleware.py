# ai_analysis/middleware.py
import uuid

class RequestMetaMiddleware:
    """
    Attach request_id, and ensure IP/UA are available via request.META.
    Add into settings.MIDDLEWARE (near top).
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # request id
        request.request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())
        # ensure some headers exist (REMOTE_ADDR set by Django)
        # Optionally capture forwarded for header
        return self.get_response(request)
