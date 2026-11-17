"""Apoio dos testes de auditoria de seguranca (Passo 3a)."""
import sys

from core import config as core_config


class DestinoFalso:
    """Destino que implementa a interface gravar(evento) -> bool, com
    falha sob comando. Nao toca disco."""

    def __init__(self, nome="falso", falhar=False):
        self.nome = nome
        self.falhar = falhar
        self.eventos = []
        self.tentativas = 0
        self.ultimo_erro = None

    def gravar(self, evento):
        self.tentativas += 1
        if self.falhar:
            self.ultimo_erro = "OSError"
            return False
        self.eventos.append(evento)
        self.ultimo_erro = None
        return True

    def esta_vazia(self):
        return True


class AlertadorFalso:
    def __init__(self):
        self.chamadas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.chamadas.append((mensagem, dados))
        return "stderr"


class StderrCapturado:
    def __init__(self):
        self.partes = []

    def write(self, texto):
        self.partes.append(texto)
        return len(texto)

    def flush(self):
        pass

    def texto(self):
        return "".join(self.partes)


def isolar_config(monkeypatch, tmp_path, auditoria=None):
    """Isola RAIZ_PROJETO, CONFIG_PATH e o cache de config para tmp_path:
    nenhum teste de auditoria toca o .state nem o config.json reais."""
    monkeypatch.setattr(core_config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(core_config, "CONFIG_PATH", str(tmp_path / "config.json"))
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in core_config.PADRAO.items()}
    if auditoria is not None:
        cfg["auditoria"] = auditoria
    monkeypatch.setattr(core_config, "_cache", cfg)
    return cfg
