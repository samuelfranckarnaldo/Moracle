"""
Modelos da Platform Layer - Application, Deployment. Nao conhece
socket, nao conhece parser HTTP - so estado e regras de negocio de
deployment, independente do server/.
"""
import json
import os
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class DeploymentStatus(Enum):
    PENDING = "pending"
    STARTING = "starting"
    HEALTH_CHECK = "health_check"
    ACTIVE = "active"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class RuntimeSnapshot:
    """Imagem congelada da configuracao de execucao no momento em que
    um Deployment foi criado. E' isso que torna um rollback correto:
    ele reexecuta exatamente o que rodava naquele deployment, nao a
    configuracao atual da Application (que pode ja ter mudado)."""
    working_directory: str
    start_command: list
    environment: dict = field(default_factory=dict)
    port: Optional[int] = None
    health_check_path: str = "/health"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, dados):
        if not dados:
            return None
        campos_validos = {"working_directory", "start_command", "environment",
                           "port", "health_check_path"}
        dados_filtrados = {k: v for k, v in dados.items() if k in campos_validos}
        return cls(**dados_filtrados)


@dataclass
class Deployment:
    app_name: str
    deployment_id: str
    created_at: float
    status: str = DeploymentStatus.PENDING.value
    source_path: str = ""
    health_check_path: str = "/health"
    domain: Optional[str] = None
    error_message: Optional[str] = None
    application_id: Optional[str] = None
    process_handle_id: Optional[str] = None
    runtime_snapshot: Optional[dict] = None

    def to_dict(self):
        return asdict(self)

    def get_runtime_snapshot(self):
        return RuntimeSnapshot.from_dict(self.runtime_snapshot)

    @classmethod
    def from_dict(cls, dados):
        # Compatibilidade retroativa: dicts persistidos antes destes
        # campos existirem nao os tem - dataclass usa o default (None)
        # automaticamente para chaves ausentes. Deployments antigos
        # sem runtime_snapshot continuam carregando normalmente;
        # get_runtime_snapshot() retorna None para eles, e quem
        # consome trata isso como fallback explicito, nunca silencioso.
        campos_validos = {"app_name", "deployment_id", "created_at", "status",
                           "source_path", "health_check_path", "domain",
                           "error_message", "application_id", "process_handle_id",
                           "runtime_snapshot"}
        dados_filtrados = {k: v for k, v in dados.items() if k in campos_validos}
        return cls(**dados_filtrados)


@dataclass
class Application:
    name: str
    domain: Optional[str] = None
    current_deployment_id: Optional[str] = None
    deployment_ids: list = field(default_factory=list)
    working_directory: Optional[str] = None
    start_command: Optional[list] = None
    environment: dict = field(default_factory=dict)
    port: Optional[int] = None
    health_check_path: str = "/health"
    restart_policy_mode: str = "NEVER"
    restart_policy_max_retries: Optional[int] = None
    restart_policy_backoff_seconds: float = 5.0
    current_process_handle_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, dados):
        campos_validos = {
            "name", "domain", "current_deployment_id", "deployment_ids",
            "working_directory", "start_command", "environment", "port",
            "health_check_path", "restart_policy_mode",
            "restart_policy_max_retries", "restart_policy_backoff_seconds",
            "current_process_handle_id",
        }
        dados_filtrados = {k: v for k, v in dados.items() if k in campos_validos}
        return cls(**dados_filtrados)


@dataclass
class ProcessHandle:
    id: str
    application_id: str
    deployment_id: str
    pid: int
    starttime: Optional[str]
    started_at: float
    stdout_log_path: str
    stderr_log_path: str

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, dados):
        return cls(**dados)
