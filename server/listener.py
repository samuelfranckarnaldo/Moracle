"""
Abre o socket do servidor: bind, listen, accept. Nao interpreta HTTP,
nao decide roteamento. TLS e aplicado aqui, na fronteira antes de
qualquer byte de aplicacao ser lido.
"""
import socket


class Listener:
    def __init__(self, host, port, backlog=128, tls_context=None):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.tls_context = tls_context
        self._sock = None

    def bind_and_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(self.backlog)
        self._sock = sock

    def accept(self):
        client_sock, addr = self._sock.accept()
        if self.tls_context is not None:
            client_sock = self.tls_context.wrap_socket(client_sock, server_side=True)
        return client_sock, addr

    def settimeout(self, seconds):
        if self._sock is not None:
            self._sock.settimeout(seconds)

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
