"""
Limites de recurso - consultados por Connection e HTTP Parser antes
de deixar uma requisicao consumir recursos sem controle.
"""
from dataclasses import dataclass


@dataclass
class Limits:
    max_request_line: int = 8192
    max_header_size: int = 16384
    max_headers_count: int = 100
    max_body_size: int = 10 * 1024 * 1024
    max_connections: int = 200
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    request_timeout: float = 30.0
