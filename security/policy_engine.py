from fastapi.responses import JSONResponse, RedirectResponse
from .policy import ROUTE_POLICIES


class PolicyEngine:

    def check(self, request):

        path = request.url.path
        policy = ROUTE_POLICIES.get(path)

        user = getattr(request.state, "user", None)

        # PUBLIC
        if policy == "public":
            return None

        # BLOCK AUTHENTICATED
        if policy == "block_authenticated":
            if user:
                return RedirectResponse("/dashboard")

        # REQUIRE AUTH
        if policy == "require_auth":
            if not user:
                return JSONResponse({"error": "login required"}, status_code=401)

        # ADMIN ONLY



        if policy == "admin_only":

            if not user:
                return JSONResponse({"error": "login required"}, status_code=401)

            role = user.get("data", {}).get("role")

            if role != "admin":
                return JSONResponse({"error": "forbidden"}, status_code=403)


            if not user:
                return JSONResponse({"error": "login required"}, status_code=401)

            role = user.get("data", {}).get("role")

            # if role exists and not admin → deny
            if role and role != "admin":
                return JSONResponse({"error": "forbidden"}, status_code=403)