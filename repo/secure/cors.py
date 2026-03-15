from fastapi.middleware.cors import CORSMiddleware


class CORSManager:
    """
    Centralized CORS configuration manager.

    This wrapper ensures consistent and secure CORS settings
    across all backend services.
    """

    def __init__(
        self,
        allow_origins=None,
        allow_methods=None,
        allow_headers=None,
        allow_credentials=True,
        expose_headers=None,
        max_age=600
    ):

        self.allow_origins = allow_origins or []

        self.allow_methods = allow_methods or [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS"
        ]

        self.allow_headers = allow_headers or [
            "Authorization",
            "Content-Type",
            "X-CSRF-Token"
        ]

        self.expose_headers = expose_headers or []

        self.allow_credentials = allow_credentials

        self.max_age = max_age

    def apply(self, app):
        """
        Attach CORS middleware to FastAPI application.
        """

        if not self.allow_origins:
            raise ValueError(
                "CORS allow_origins cannot be empty in production"
            )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.allow_origins,
            allow_credentials=self.allow_credentials,
            allow_methods=self.allow_methods,
            allow_headers=self.allow_headers,
            expose_headers=self.expose_headers,
            max_age=self.max_age,
        )