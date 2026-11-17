"""
Abstracao de resposta HTTP - status, headers, body. Body pode ser
bytes fixos ou um iteravel de chunks (streaming), previsto desde ja
mesmo sem uso imediato (static files/range requests no futuro).
"""
import json as _json


class Response:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = dict(headers or {})
        self.body = body

    @classmethod
    def json(cls, data, status=200, headers=None):
        corpo = _json.dumps(data).encode("utf-8")
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/json")
        return cls(status=status, headers=h, body=corpo)

    @classmethod
    def text(cls, texto, status=200, headers=None):
        corpo = texto.encode("utf-8") if isinstance(texto, str) else texto
        h = dict(headers or {})
        h.setdefault("Content-Type", "text/plain; charset=utf-8")
        return cls(status=status, headers=h, body=corpo)

    @property
    def is_streaming(self):
        return not isinstance(self.body, (bytes, bytearray))


_STATUS_TEXT = {
    200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 413: "Payload Too Large", 414: "URI Too Long",
    431: "Request Header Fields Too Large", 500: "Internal Server Error",
    503: "Service Unavailable",
}


def status_text(status):
    return _STATUS_TEXT.get(status, "Unknown")


def _montar_cabecalho(status, headers, protocol_version):
    linhas = [f"{protocol_version} {status} {status_text(status)}"]
    for nome, valor in headers.items():
        linhas.append(f"{nome}: {valor}")
    linhas.append("")
    linhas.append("")
    return "\r\n".join(linhas).encode("utf-8")


def serialize_response(response, protocol_version="HTTP/1.1"):
    if response.is_streaming:
        headers = dict(response.headers)
        headers["Transfer-Encoding"] = "chunked"
        headers.pop("Content-Length", None)
        yield _montar_cabecalho(response.status, headers, protocol_version)
        for pedaco in response.body:
            if not pedaco:
                continue
            yield f"{len(pedaco):x}\r\n".encode("ascii") + pedaco + b"\r\n"
        yield b"0\r\n\r\n"
    else:
        headers = dict(response.headers)
        headers["Content-Length"] = str(len(response.body))
        yield _montar_cabecalho(response.status, headers, protocol_version) + response.body
