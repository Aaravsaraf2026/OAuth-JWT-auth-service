ROUTE_POLICIES = {
    "/": "public",

    "/auth/login": "public",
    "/auth/callback": "public",

    "/dashboard": "require_auth",
    "/me": "require_auth",

    "/users": "admin_only",

    "/refresh": "public",
    "/logout": "require_auth",

    "/debug-cookies": "admin_only",
    "/debug-decode": "admin_only",
}