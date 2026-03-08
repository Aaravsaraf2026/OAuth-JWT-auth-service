import uuid

try:
    from logger.context import set_request_id
except ImportError:
    from context import set_request_id


async def request_id_middleware(request, call_next):
    """
    FastAPI middleware that generates a unique request_id per request
    and stores it in a contextvar so all logs are automatically tagged.

    Usage (in your FastAPI app):
        from app.middleware.request_id import request_id_middleware
        app.middleware("http")(request_id_middleware)

    Each request will then produce logs like:
        13:02:11 │ [a91bd82c] │ INFO │ auth.py:41 │ User authenticated
    """
    request_id = uuid.uuid4().hex
    set_request_id(request_id)

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    return response
