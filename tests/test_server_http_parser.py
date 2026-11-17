import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
import pytest

from server.http_parser import parse_request
from server.limits import Limits
from server.errors import HTTPProtocolError, InvalidContentLengthError, BodyTooLargeError, RequestLineTooLargeError, ConnectionClosedError


class FakeConnection:
    def __init__(self, raw, remote_address=("127.0.0.1", 12345)):
        self._buf = io.BytesIO(raw)
        self.remote_address = remote_address

    def read_line(self, max_bytes):
        linha = self._buf.readline(max_bytes + 1)
        if linha == b"":
            raise ConnectionClosedError("eof")
        if len(linha) > max_bytes:
            raise ValueError("line too large")
        if linha.endswith(b"\r\n"):
            return linha[:-2]
        if linha.endswith(b"\n"):
            return linha[:-1]
        raise ValueError("no terminator")

    def read_exact(self, n):
        dados = self._buf.read(n)
        if len(dados) < n:
            raise ConnectionClosedError("eof mid body")
        return dados


def test_valid_get_request():
    raw = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
    req = parse_request(FakeConnection(raw), Limits())
    assert req.method == "GET"
    assert req.path == "/health"
    assert req.headers["host"] == "localhost"
    assert req.body == b""


def test_valid_post_with_body():
    corpo = b'{"ip":"1.2.3.4"}'
    raw = (
        b"POST /ingest HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(corpo)).encode() + b"\r\n"
        b"\r\n" + corpo
    )
    req = parse_request(FakeConnection(raw), Limits())
    assert req.method == "POST"
    assert req.body == corpo


def test_malformed_request_line():
    raw = b"GARBAGE\r\n\r\n"
    with pytest.raises(HTTPProtocolError):
        parse_request(FakeConnection(raw), Limits())


def test_malformed_header_line():
    raw = b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n"
    with pytest.raises(HTTPProtocolError):
        parse_request(FakeConnection(raw), Limits())


def test_invalid_content_length():
    raw = b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n"
    with pytest.raises(InvalidContentLengthError):
        parse_request(FakeConnection(raw), Limits())


def test_body_exceeds_limit():
    limites = Limits(max_body_size=5)
    corpo = b"123456789"
    raw = b"POST / HTTP/1.1\r\nContent-Length: " + str(len(corpo)).encode() + b"\r\n\r\n" + corpo
    with pytest.raises(BodyTooLargeError):
        parse_request(FakeConnection(raw), limites)


def test_request_line_exceeds_limit():
    limites = Limits(max_request_line=10)
    raw = b"GET /caminho-bem-longo-demais-para-o-limite HTTP/1.1\r\n\r\n"
    with pytest.raises(RequestLineTooLargeError):
        parse_request(FakeConnection(raw), limites)


def test_chunked_body():
    raw = (
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n"
        b"5\r\nworld\r\n"
        b"0\r\n\r\n"
    )
    req = parse_request(FakeConnection(raw), Limits())
    assert req.body == b"helloworld"
