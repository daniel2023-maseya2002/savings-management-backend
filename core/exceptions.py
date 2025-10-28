from rest_framework.views import exception_handler
from rest_framework.response import Response 

def custom_exception_handler(exc, context):
    """
    Return a consistent JSON {"detail": "...", "status_code": ...}
    DRF will still return status_code as usual.
    """
    response = exception_handler(exc, context)
    if response is None:
        # Unhandled exceptions -> internal server error
        return Response({'detail': 'Internal server error'}, status=500)
    # Make sure response.data is serializable and has 'detail'
    data = response.data
    # Normalize common error shapes
    if isinstance(data, dict):
        # If validation errors, return them as-is but under 'errors'
        if any(k in data for k in ('non_field_errors',)) or any(isinstance(v, list) for v in data.values()):
            return Response({'errors': data}, status=response.status_code)
        # If 'detail' exists keep it
        if 'detail' in data:
            return Response({'detail': data['detail']}, status=response.status_code)
    # Fallback
    return response
