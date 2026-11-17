"""
Contrato de access logging - uma linha por requisicao. Formato
definitivo (texto vs JSON) ainda em aberto; o contrato de dados esta
fixo, o formato de saida e trocavel (sink plugavel).

AccessLogger nao conhece filesystem nem formato de persistencia - so
sabe que existe um sink de texto (sempre) e, opcionalmente, um sink
estruturado (JsonlSink ou qualquer callable) a notificar. Quem sabe
onde/como persistir e o sink, nao o logger.

timestamp/app_name ficam no FINAL da lista de campos, com default,
de proposito: preserva compatibilidade com qualquer callsite que ainda
instancie AccessLogRecord posicionalmente com os 8 campos originais.
"""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import json
import logging
import os


def _timestamp_utc_agora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AccessLogRecord:
    request_id: str
    remote_address: str
    method: str
    path: str
    protocol_version: str
    status: int
    bytes_sent: int
    latency_ms: float
    timestamp: str = field(default_factory=_timestamp_utc_agora)
    app_name: str = ""


class JsonlSink:
    """Sink estruturado: grava um AccessLogRecord por linha em formato
    JSON Lines no caminho informado. Conhece persistencia; e o unico
    lugar do modulo que sabe que existe um arquivo em disco."""

    def __init__(self, caminho):
        self.caminho = os.path.expanduser(caminho)

    def __call__(self, record):
        linha = json.dumps(asdict(record), ensure_ascii=False)
        with open(self.caminho, "a", encoding="utf-8") as f:
            f.write(linha + "\n")


class AccessLogger:
    def __init__(self, sink=None, jsonl_sink=None):
        self._sink = sink or self._sink_padrao
        self._jsonl_sink = jsonl_sink  # None = desabilitado (comportamento anterior preservado)
        self._logger = logging.getLogger("moracle.access")

    def _sink_padrao(self, record):
        self._logger.info(
            '%s - - "%s %s %s" %d %d %.2fms rid=%s',
            record.remote_address, record.method, record.path,
            record.protocol_version, record.status, record.bytes_sent,
            record.latency_ms, record.request_id,
        )

    def log(self, record):
        self._sink(record)
        if self._jsonl_sink is not None:
            self._jsonl_sink(record)
