"""
Taxonomia de erros do Moracle Server - cada camada produz um tipo de
erro proprio; a traducao para resposta HTTP e centralizada aqui.
"""


class MoracleServerError(Exception):
    status_code = 500

    def __init__(self, message="", **extra):
        super().__init__(message)
        self.message = message
        self.extra = extra


class HTTPProtocolError(MoracleServerError):
    status_code = 400


class RequestLineTooLargeError(HTTPProtocolError):
    status_code = 414


class HeaderTooLargeError(HTTPProtocolError):
    status_code = 431


class BodyTooLargeError(HTTPProtocolError):
    status_code = 413


class InvalidContentLengthError(HTTPProtocolError):
    status_code = 400


class ConnectionClosedError(MoracleServerError):
    status_code = None


class ConnectionTimeoutError(MoracleServerError):
    status_code = 408


class RoutingError(MoracleServerError):
    status_code = 404


class NotFoundError(RoutingError):
    status_code = 404


class MethodNotAllowedError(RoutingError):
    status_code = 405

    def __init__(self, path, allowed_methods):
        super().__init__(f"Method not allowed for {path}")
        self.path = path
        self.allowed_methods = allowed_methods


class MiddlewareError(MoracleServerError):
    status_code = 500


class ApplicationError(MoracleServerError):
    status_code = 500


class ConfigurationError(MoracleServerError):
    status_code = None


class ServerLifecycleError(MoracleServerError):
    status_code = None


class InternalError(MoracleServerError):
    status_code = 500


def error_to_status_and_body(error):
    status = getattr(error, "status_code", 500) or 500
    mensagem = error.message or error.__class__.__name__
    return status, mensagem
