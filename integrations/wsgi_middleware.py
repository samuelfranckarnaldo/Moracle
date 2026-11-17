"""
Middleware WSGI generico para o Moracle - envia cada requisicao para
o servidor Moracle local, sem bloquear a resposta da aplicacao.

Uso (Flask):
    from moracle_middleware import MoracleMiddleware
    app.wsgi_app = MoracleMiddleware(app.wsgi_app, url="http://localhost:7000", api_key="...")
"""
import json
import sys
import time
import urllib.error
import urllib.request
import threading


class MoracleMiddleware:
    def __init__(self, app, url="http://localhost:7000", api_key=None, timeout=0.5):
        self.app = app
        self.url = url.rstrip("/") + "/ingest"
        self.api_key = api_key
        self.timeout = timeout
        self._lock_falhas = threading.Lock()
        self._falhas = 0
        self._ultimo_aviso = 0.0

    def __call__(self, environ, start_response):
        if self.api_key:
            self._enviar_async(environ)
        return self.app(environ, start_response)

    def _enviar_async(self, environ):
        payload = {
            "ip": environ.get("REMOTE_ADDR", "unknown"),
            "method": environ.get("REQUEST_METHOD", "GET"),
            "path": environ.get("PATH_INFO", "") + (
                "?" + environ.get("QUERY_STRING", "") if environ.get("QUERY_STRING") else ""
            ),
            "user_agent": environ.get("HTTP_USER_AGENT", "-"),
            "status_code": 0,
        }
        thread = threading.Thread(target=self._post, args=(payload,), daemon=True)
        thread.start()

    def _post(self, payload):
        try:
            dados = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url, data=dados,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            self._registrar_falha(f"HTTP {exc.code}")
        except Exception as exc:  # nunca derruba a aplicacao se o Moracle estiver offline
            self._registrar_falha(type(exc).__name__)

    def _registrar_falha(self, motivo):
        """Avisa em stderr, no maximo 1x por minuto, quantos eventos nao chegaram."""
        try:
            with self._lock_falhas:
                self._falhas += 1
                agora = time.monotonic()
                if agora - self._ultimo_aviso >= 60:
                    falhas, self._falhas = self._falhas, 0
                    self._ultimo_aviso = agora
                    print(f"[moracle] {falhas} evento(s) nao entregue(s) ao Moracle (ultimo motivo: {motivo})", file=sys.stderr)
        except Exception:
            pass
