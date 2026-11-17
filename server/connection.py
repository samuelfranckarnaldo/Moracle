"""
Dono do socket de uma conexao aceita. Le e escreve bytes crus; nunca
interpreta HTTP. Timeouts aplicados aqui, conforme Limits.
"""
import socket

from server.errors import ConnectionClosedError, ConnectionTimeoutError


class Connection:
    def __init__(self, sock, remote_address, limits):
        self.sock = sock
        self.remote_address = remote_address
        self.limits = limits
        self._rfile = sock.makefile("rb")
        self._closed = False

    def set_timeout(self, seconds):
        self.sock.settimeout(seconds)

    def read_line(self, max_bytes):
        try:
            linha = self._rfile.readline(max_bytes + 1)
        except socket.timeout:
            raise ConnectionTimeoutError("timeout reading line")
        if linha == b"":
            raise ConnectionClosedError("connection closed before any data")
        if len(linha) > max_bytes:
            raise ValueError("line too large")
        if linha.endswith(b"\r\n"):
            return linha[:-2]
        if linha.endswith(b"\n"):
            return linha[:-1]
        raise ValueError("line too large or malformed (no terminator)")

    def read_exact(self, n):
        if n == 0:
            return b""
        try:
            dados = self._rfile.read(n)
        except socket.timeout:
            raise ConnectionTimeoutError("timeout reading body")
        if dados is None or len(dados) < n:
            raise ConnectionClosedError("connection closed before body complete")
        return dados

    def sendall(self, data):
        try:
            self.sock.sendall(data)
        except socket.timeout:
            raise ConnectionTimeoutError("timeout writing response")

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._rfile.close()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
