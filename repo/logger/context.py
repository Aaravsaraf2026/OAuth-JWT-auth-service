import contextvars

request_id_var = contextvars.ContextVar("request_id", default=None)


def set_request_id(request_id: str):
    request_id_var.set(request_id)


def get_request_id():
    return request_id_var.get()
