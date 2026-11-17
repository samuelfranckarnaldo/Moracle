import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from server.router import Router
from server.errors import NotFoundError, MethodNotAllowedError


def handler_a(req, ctx): return "A"
def handler_b(req, ctx): return "B"


def test_static_route_match():
    r = Router()
    r.add_route("GET", "/health", handler_a)
    handler, params = r.match("GET", "/health")
    assert handler is handler_a
    assert params == {}


def test_route_not_found():
    r = Router()
    r.add_route("GET", "/health", handler_a)
    with pytest.raises(NotFoundError):
        r.match("GET", "/nope")


def test_method_not_allowed():
    r = Router()
    r.add_route("GET", "/health", handler_a)
    with pytest.raises(MethodNotAllowedError) as exc:
        r.match("POST", "/health")
    assert "GET" in exc.value.allowed_methods


def test_path_parameters():
    r = Router()
    r.add_route("POST", "/block/{ip}", handler_b)
    handler, params = r.match("POST", "/block/203.0.113.5")
    assert handler is handler_b
    assert params == {"ip": "203.0.113.5"}


def test_head_falls_back_to_get():
    r = Router()
    r.add_route("GET", "/health", handler_a)
    handler, params = r.match("HEAD", "/health")
    assert handler is handler_a


def test_allowed_methods_includes_options_and_head():
    r = Router()
    r.add_route("GET", "/health", handler_a)
    metodos = r.allowed_methods("/health")
    assert "GET" in metodos and "HEAD" in metodos and "OPTIONS" in metodos
