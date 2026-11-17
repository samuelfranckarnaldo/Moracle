"""
Cliente HTTP puro (stdlib http.client) para a Admin API - usado pela
CLI para nunca mais chamar ApplicationManager/registry diretamente.
Console (quando existir) usara' exatamente o mesmo padrao de chamadas
HTTP, garantindo que CLI e Console tenham as mesmas capacidades.
"""
import http.client
import ipaddress
import json
import os
from urllib.parse import urlencode, urlsplit


class AdminAPIError(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        mensagem = body.get("error") if isinstance(body, dict) else str(body)
        super().__init__(f"Admin API error {status}: {mensagem}")


def _eh_loopback(host):
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _contexto_tls(host):
    """Contexto TLS do cliente. Loopback: sem verificacao (o servidor local usa
    certificado autoassinado e o trafego nao sai da maquina). Qualquer outro
    host: verificacao COMPLETA da cadeia e do nome, porque a chave de admin
    viaja neste canal e sem verificacao um intermediario podia le-la.
    MORACLE_CA_FILE aponta para uma CA propria (ex.: o certificado
    autoassinado do servidor)."""
    import ssl
    if _eh_loopback(host):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=os.environ.get("MORACLE_CA_FILE") or None)


class AdminAPIClient:
    def __init__(self, base_url, api_key, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, metodo, path, corpo=None, query=None):
        partes = urlsplit(self.base_url)
        host = partes.hostname
        porta = partes.port or (443 if partes.scheme == "https" else 80)
        usar_tls = partes.scheme == "https"

        if query:
            path = f"{path}?{urlencode(query)}"

        corpo_bytes = json.dumps(corpo).encode() if corpo is not None else None
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if corpo_bytes is not None:
            headers["Content-Type"] = "application/json"

        if usar_tls:
            ctx = _contexto_tls(host)
            conn = http.client.HTTPSConnection(host, porta, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, porta, timeout=self.timeout)

        try:
            conn.request(metodo, path, body=corpo_bytes, headers=headers)
            resposta = conn.getresponse()
            dados_brutos = resposta.read()
            status = resposta.status
        finally:
            conn.close()

        corpo_resposta = {}
        if dados_brutos:
            try:
                corpo_resposta = json.loads(dados_brutos)
            except json.JSONDecodeError:
                corpo_resposta = {"raw": dados_brutos.decode(errors="replace")}

        if status >= 400:
            raise AdminAPIError(status, corpo_resposta)

        return status, corpo_resposta

    # ---------- Applications ----------

    def create_app(self, name, working_directory, start_command, **kwargs):
        corpo = {"name": name, "working_directory": working_directory, "start_command": start_command}
        corpo.update(kwargs)
        _, dados = self._request("POST", "/admin/apps", corpo=corpo)
        return dados

    def list_apps(self):
        _, dados = self._request("GET", "/admin/apps")
        return dados["applications"]

    def get_app(self, name, include_env=False):
        query = {"include_env": "true"} if include_env else None
        _, dados = self._request("GET", f"/admin/apps/{name}", query=query)
        return dados

    def delete_app(self, name):
        self._request("DELETE", f"/admin/apps/{name}")

    def start_app(self, name):
        _, dados = self._request("POST", f"/admin/apps/{name}/start")
        return dados

    def stop_app(self, name):
        _, dados = self._request("POST", f"/admin/apps/{name}/stop")
        return dados

    def restart_app(self, name):
        _, dados = self._request("POST", f"/admin/apps/{name}/restart")
        return dados

    def status_app(self, name):
        _, dados = self._request("GET", f"/admin/apps/{name}/status")
        return dados

    def logs_app(self, name, lines=100):
        _, dados = self._request("GET", f"/admin/apps/{name}/logs", query={"lines": lines})
        return dados

    def deploy_app(self, name, health_check_base_url=None, health_check_tentativas=None):
        corpo = {}
        if health_check_base_url:
            corpo["health_check_base_url"] = health_check_base_url
        if health_check_tentativas:
            corpo["health_check_tentativas"] = health_check_tentativas
        _, dados = self._request("POST", f"/admin/apps/{name}/deploy", corpo=corpo or None)
        return dados

    # ---------- Deployments ----------

    def list_deployments(self, app_name=None):
        query = {"app": app_name} if app_name else None
        _, dados = self._request("GET", "/admin/deployments", query=query)
        return dados["deployments"]

    def get_deployment(self, deployment_id):
        _, dados = self._request("GET", f"/admin/deployments/{deployment_id}")
        return dados

    def rollback_deployment(self, deployment_id):
        _, dados = self._request("POST", f"/admin/deployments/{deployment_id}/rollback")
        return dados
