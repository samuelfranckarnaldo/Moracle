"""
Cadeia de custódia forense — preservação e integridade de evidências.
Princípio: nunca modifica a fonte original, apenas documenta seu estado.
"""

import hashlib
import hmac
import json
import os
import stat
from datetime import datetime, timezone

from core import config

CHAVE_PATH = os.path.join(config.RAIZ_PROJETO, ".state", "chave_assinatura.key")


def _obter_ou_criar_chave():
    """Chave HMAC local — não é criptografia de chave pública real, mas prova
    que o registro foi gerado por esta instalação do Moracle e não editado
    manualmente depois, sem exigir infraestrutura de PKI."""
    os.makedirs(os.path.dirname(CHAVE_PATH), exist_ok=True)
    if os.path.exists(CHAVE_PATH):
        with open(CHAVE_PATH, "rb") as f:
            return f.read()
    chave = os.urandom(32)
    with open(CHAVE_PATH, "wb") as f:
        f.write(chave)
    os.chmod(CHAVE_PATH, stat.S_IRUSR | stat.S_IWUSR)  # só o dono lê/escreve
    return chave


class RegistroCustodia:
    """Representa a coleta de uma evidência com hash, assinatura e metadados."""

    def __init__(self, caminho_evidencia, coletor="moracle"):
        self.caminho_evidencia = os.path.abspath(caminho_evidencia)
        self.coletor = coletor
        self.timestamp_coleta = datetime.now(timezone.utc).isoformat()
        self.hashes = {}
        self.tamanho_bytes = None
        self.acessos = []
        self.assinatura = None

    def _enforcar_somente_leitura(self):
        """Falha explicitamente se a evidência estiver com permissão de escrita
        pro dono — evita coleta acidental de um arquivo ainda mutável."""
        modo = os.stat(self.caminho_evidencia).st_mode
        if modo & stat.S_IWUSR:
            os.chmod(self.caminho_evidencia, modo & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)

    def calcular_hashes(self):
        """Calcula SHA-256 e SHA-1 num único passe pelo arquivo (evidência
        pode ser grande — não vale ler duas vezes)."""
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        with open(self.caminho_evidencia, "rb") as f:
            for bloco in iter(lambda: f.read(65536), b""):
                sha256.update(bloco)
                sha1.update(bloco)
        self.hashes = {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest()}
        self.tamanho_bytes = os.path.getsize(self.caminho_evidencia)
        self._enforcar_somente_leitura()
        return self.hashes

    @property
    def hash_sha256(self):
        """Compatibilidade com código existente que usa .hash_sha256."""
        return self.hashes.get("sha256")

    def registrar_acesso(self, motivo):
        self.acessos.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "motivo": motivo
        })

    def _hash_atual(self):
        sha256 = hashlib.sha256()
        with open(self.caminho_evidencia, "rb") as f:
            for bloco in iter(lambda: f.read(65536), b""):
                sha256.update(bloco)
        return sha256.hexdigest()

    def verificar_integridade(self):
        return self._hash_atual() == self.hashes.get("sha256")

    def _dados_para_assinar(self):
        """Conteúdo determinístico usado tanto pra assinar quanto pra verificar —
        não inclui a própria assinatura nem 'acessos' (que muda a cada leitura)."""
        return json.dumps({
            "caminho_evidencia": self.caminho_evidencia,
            "coletor": self.coletor,
            "timestamp_coleta": self.timestamp_coleta,
            "hashes": self.hashes,
            "tamanho_bytes": self.tamanho_bytes,
        }, sort_keys=True).encode("utf-8")

    def assinar(self):
        chave = _obter_ou_criar_chave()
        self.assinatura = hmac.new(chave, self._dados_para_assinar(), hashlib.sha256).hexdigest()
        return self.assinatura

    def verificar_assinatura(self):
        if not self.assinatura:
            return False
        chave = _obter_ou_criar_chave()
        esperada = hmac.new(chave, self._dados_para_assinar(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(esperada, self.assinatura)

    def to_dict(self):
        return {
            "caminho_evidencia": self.caminho_evidencia,
            "coletor": self.coletor,
            "timestamp_coleta": self.timestamp_coleta,
            "hashes": self.hashes,
            "hash_sha256": self.hashes.get("sha256"),  # compatibilidade
            "tamanho_bytes": self.tamanho_bytes,
            "acessos": self.acessos,
            "assinatura": self.assinatura,
        }

    def salvar(self, caminho_saida=None):
        if caminho_saida is None:
            caminho_saida = self.caminho_evidencia + ".custodia.json"
        with open(caminho_saida, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return caminho_saida

    @classmethod
    def carregar(cls, caminho_registro):
        with open(caminho_registro) as f:
            dados = json.load(f)
        registro = cls(dados["caminho_evidencia"], dados["coletor"])
        registro.timestamp_coleta = dados["timestamp_coleta"]
        registro.hashes = dados.get("hashes") or {"sha256": dados.get("hash_sha256")}
        registro.tamanho_bytes = dados["tamanho_bytes"]
        registro.acessos = dados["acessos"]
        registro.assinatura = dados.get("assinatura")
        return registro


def coletar_evidencia(caminho, coletor="moracle", motivo="coleta inicial"):
    registro = RegistroCustodia(caminho, coletor)
    registro.calcular_hashes()
    registro.registrar_acesso(motivo)
    registro.assinar()
    registro.salvar()
    return registro
