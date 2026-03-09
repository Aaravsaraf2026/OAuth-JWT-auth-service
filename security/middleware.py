from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from repo.jwt.jwt_wrapper import verify_token

from .policy_engine import PolicyEngine

policy_engine = PolicyEngine()


class SecurityMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request, call_next):

        token = request.cookies.get("access_token")

        if token:
            try:
                payload = verify_token(token, expected_type="access")
                request.state.user = payload
            except Exception:
                request.state.user = None
        else:
            request.state.user = None

        # run policy check
        result = policy_engine.check(request)

        if result:
            return result

        response = await call_next(request)

        return response

    async def dispatch(self, request, call_next):

        token = request.cookies.get("access_token")

        if token:
            try:
                payload = verify_token(token, expected_type="access")
                request.state.user = payload
            except Exception:
                request.state.user = None
        else:
            request.state.user = None

        # POLICY CHECK
        result = policy_engine.check(request)

        if result:
            return result

        response = await call_next(request)

        return response