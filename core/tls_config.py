"""
Configuracao de TLS para o Moracle Server - gera um certificado
autoassinado local na primeira execucao (uso local/desenvolvimento;
para producao publica, o usuario deve fornecer certificado proprio
via --cert/--key).
"""
import os
import ssl
import subprocess

from core import config

CERT_DIR = os.path.join(config.RAIZ_PROJETO, ".state", "tls")
CERT_PATH = os.path.join(CERT_DIR, "cert.pem")
KEY_PATH = os.path.join(CERT_DIR, "key.pem")


def _gerar_certificado_autoassinado():
    os.makedirs(CERT_DIR, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True,
    )
    os.chmod(KEY_PATH, 0o600)


def obter_contexto_tls(cert_path=None, key_path=None):
    """Retorna um ssl.SSLContext pronto para o Listener envolver o
    socket aceito. Se cert/key nao forem fornecidos, gera (ou reusa)
    um certificado autoassinado local."""
    cert_path = cert_path or CERT_PATH
    key_path = key_path or KEY_PATH

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        if cert_path == CERT_PATH:
            _gerar_certificado_autoassinado()
        else:
            raise FileNotFoundError(f"Certificado/chave nao encontrados: {cert_path}, {key_path}")

    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(certfile=cert_path, keyfile=key_path)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    return contexto
