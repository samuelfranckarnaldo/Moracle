import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.response import Response, serialize_response


def test_json_response_serialization():
    r = Response.json({"ok": True}, status=200)
    bruto = b"".join(serialize_response(r, "HTTP/1.1"))
    assert bruto.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Type: application/json" in bruto
    assert b'{"ok": true}' in bruto
    assert b"Content-Length: 12" in bruto


def test_text_response_content_length_correct():
    r = Response.text("abc")
    bruto = b"".join(serialize_response(r, "HTTP/1.1"))
    assert b"Content-Length: 3" in bruto
    assert bruto.endswith(b"abc")


def test_streaming_response_uses_chunked_encoding():
    def gerador():
        yield b"hello"
        yield b"world"

    r = Response(status=200, body=gerador())
    bruto = b"".join(serialize_response(r, "HTTP/1.1"))
    assert b"Transfer-Encoding: chunked" in bruto
    assert b"5\r\nhello\r\n" in bruto
    assert b"5\r\nworld\r\n" in bruto
    assert bruto.endswith(b"0\r\n\r\n")
