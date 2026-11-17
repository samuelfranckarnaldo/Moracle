"""
Transforma bytes (via Connection) em Request. Nao conhece rotas nem
aplicacao - so entende transporte HTTP.
"""
from urllib.parse import urlsplit, parse_qsl

from server.errors import (
    HTTPProtocolError, RequestLineTooLargeError, HeaderTooLargeError,
    BodyTooLargeError, InvalidContentLengthError,
)
from server.request import Request


def parse_request(connection, limits):
    try:
        request_line = connection.read_line(limits.max_request_line)
    except ValueError:
        raise RequestLineTooLargeError("request line exceeds limit")

    partes = request_line.decode("iso-8859-1", errors="replace").split(" ")
    if len(partes) != 3:
        raise HTTPProtocolError(f"malformed request line: {request_line!r}")
    method, target, protocol_version = partes
    if not method or not target or not protocol_version.startswith("HTTP/"):
        raise HTTPProtocolError(f"malformed request line: {request_line!r}")

    partes_url = urlsplit(target)
    path = partes_url.path or "/"
    query = dict(parse_qsl(partes_url.query, keep_blank_values=True))

    headers = {}
    tamanho_headers = 0
    contagem_headers = 0
    while True:
        try:
            linha = connection.read_line(limits.max_request_line)
        except ValueError:
            raise HeaderTooLargeError("header line exceeds limit")
        if linha == b"":
            break
        tamanho_headers += len(linha)
        if tamanho_headers > limits.max_header_size:
            raise HeaderTooLargeError("total header size exceeds limit")
        contagem_headers += 1
        if contagem_headers > limits.max_headers_count:
            raise HeaderTooLargeError("too many headers")

        texto = linha.decode("iso-8859-1", errors="replace")
        if ":" not in texto:
            raise HTTPProtocolError(f"malformed header line: {texto!r}")
        nome, _, valor = texto.partition(":")
        headers[nome.strip().lower()] = valor.strip()

    body = b""
    content_length_raw = headers.get("content-length")
    transfer_encoding = headers.get("transfer-encoding", "")

    if "chunked" in transfer_encoding.lower():
        body = _ler_corpo_chunked(connection, limits)
    elif content_length_raw is not None:
        try:
            content_length = int(content_length_raw)
            if content_length < 0:
                raise ValueError
        except ValueError:
            raise InvalidContentLengthError(f"invalid Content-Length: {content_length_raw!r}")
        if content_length > limits.max_body_size:
            raise BodyTooLargeError(f"body exceeds limit ({content_length} > {limits.max_body_size})")
        body = connection.read_exact(content_length)

    return Request(
        method=method.upper(),
        path=path,
        query=query,
        headers=headers,
        body=body,
        protocol_version=protocol_version,
        remote_address=connection.remote_address,
    )


def _ler_corpo_chunked(connection, limits):
    partes = []
    total = 0
    while True:
        linha_tamanho = connection.read_line(limits.max_request_line)
        try:
            tamanho = int(linha_tamanho.split(b";")[0], 16)
        except ValueError:
            raise HTTPProtocolError(f"invalid chunk size: {linha_tamanho!r}")
        if tamanho == 0:
            connection.read_line(limits.max_request_line)
            break
        total += tamanho
        if total > limits.max_body_size:
            raise BodyTooLargeError("chunked body exceeds limit")
        dados = connection.read_exact(tamanho)
        partes.append(dados)
        connection.read_line(limits.max_request_line)
    return b"".join(partes)
