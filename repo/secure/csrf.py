import secrets


class CSRFManager:

    @staticmethod
    def generate():
        return secrets.token_hex(32)

    @staticmethod
    def verify(request):

        cookie_token = request.cookies.get("csrf_token")
        header_token = request.headers.get("X-CSRF-Token")

        if not cookie_token or not header_token:
            return False

        return cookie_token == header_token