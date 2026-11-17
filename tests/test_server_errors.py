import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.errors import HTTPProtocolError, NotFoundError, MethodNotAllowedError, error_to_status_and_body


def test_http_protocol_error_status_400():
    erro = HTTPProtocolError("malformed")
    status, corpo = error_to_status_and_body(erro)
    assert status == 400
    assert "malformed" in corpo


def test_not_found_status_404():
    erro = NotFoundError("/xyz")
    status, _ = error_to_status_and_body(erro)
    assert status == 404


def test_method_not_allowed_carries_allowed_methods():
    erro = MethodNotAllowedError("/x", {"GET", "POST"})
    assert erro.allowed_methods == {"GET", "POST"}
    status, _ = error_to_status_and_body(erro)
    assert status == 405
