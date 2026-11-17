"""
Abstracao imutavel de uma requisicao HTTP ja parseada. Nao conhece
socket, nao conhece rotas, nao conhece aplicacao.
"""
from dataclasses import dataclass
from typing import Dict, Any


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: Dict[str, str]
    headers: Dict[str, str]
    body: bytes
    protocol_version: str
    remote_address: tuple

    def header(self, name, default=None):
        return self.headers.get(name.lower(), default)

    @property
    def content_type(self):
        return self.header("content-type")


class Context:
    """Objeto mutavel por requisicao - onde Router e Middleware anexam
    dados (request_id, route params, dados de autenticacao) sem sujar
    o Request imutavel."""

    def __init__(self, request_id):
        self.request_id = request_id
        self.route_params: Dict[str, str] = {}
        self.data: Dict[str, Any] = {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def get(self, key, default=None):
        return self.data.get(key, default)
