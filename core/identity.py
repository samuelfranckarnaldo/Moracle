"""
core/identity.py

Modelo de dados e persistência para autenticação/autorização baseada em
ApiKey + ServiceRole.

Escopo deste módulo (Passo 1):
    - Definição de ServiceRole e ApiKey.
    - Persistência atômica, reaproveitando core.atomic_state (FileLock
      próprio via fcntl + os.replace) — sem dependências externas.
    - Geração segura de tokens e hashing SHA-256.
    - Migração idempotente da chave legada (.state/api_key.txt) para uma
      ApiKey com role "admin".

Fora de escopo deste módulo (passos futuros):
    - Lógica de autorização (checagem de permissão / escopo).
    - Middleware, rotas /admin/keys, /admin/roles.
    - CLI `mc keys`.

Nota de contrato:
    "server.admin" é uma permissão CORINGA. Este módulo apenas declara essa
    propriedade via SERVER_ADMIN_PERMISSION/ServiceRole.is_wildcard e a
    documenta; o curto-circuito de autorização (ignorar permissions e
    scoped_app_names quando "server.admin" está presente) será
    implementado no Passo 6 (exigir_permissao()), não aqui.

Nota de atomicidade:
    Todas as operações de escrita que envolvem "ler estado atual, decidir,
    escrever" (add, revoke, touch_last_used, upsert, ensure_admin_role_exists)
    usam core.atomic_state.modificar_json_com_lock, que mantém um único
    lock cobrindo leitura+decisão+escrita. Isso evita a janela de corrida
    que existiria se load_all()/save_all() fossem chamados como duas
    operações separadas.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import FrozenSet, List, Optional, Dict, Any, Tuple

from core.atomic_state import ler_json, escrever_json, modificar_json_com_lock, FileLock


# ---------------------------------------------------------------------------
# Contrato de permissões
# ---------------------------------------------------------------------------

#: Permissão coringa. Uma ApiKey/ServiceRole que a possui tem acesso a TODAS
#: as operações, independentemente de permissions/scoped_app_names.
#: A aplicação desse curto-circuito é responsabilidade da camada de
#: autorização (Passo 6), não deste módulo.
SERVER_ADMIN_PERMISSION = "server.admin"

KNOWN_PERMISSIONS: FrozenSet[str] = frozenset({
    "app.read",
    "app.logs",
    "app.access_logs",
    "app.create",
    "app.delete",
    "app.deploy",
    "app.start_stop",
    "deployment.read",
    "deployment.rollback",
    "defense.read",
    "defense.block",
    "ingest.write",
    # Passo 4b (D3=B): permissoes proprias; a gestao de chaves e roles
    # continua a exigir server.admin.
    "config.security_write",
    "ioc.write",
    SERVER_ADMIN_PERMISSION,
})


# ---------------------------------------------------------------------------
# Erros
# ---------------------------------------------------------------------------

class IdentityError(Exception):
    """Erro base para o subsistema de identidade."""


class UnknownPermissionError(IdentityError):
    """Levantado quando uma permissão fora do contrato é declarada."""


class DuplicateApiKeyError(IdentityError):
    """Levantado ao tentar registrar uma ApiKey com id já existente."""


class DuplicateApiKeyNameError(IdentityError):
    """Levantado ao tentar registrar uma ApiKey com name já existente."""


class DuplicateRoleNameError(IdentityError):
    """Levantado ao tentar registrar um ServiceRole com name já existente."""


class LastAdminKeyError(IdentityError):
    """Levantado quando uma revogação deixaria o sistema sem nenhuma
    credencial server.admin válida (não revogada, não expirada)."""


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServiceRole:
    """
    Um papel de serviço: nome + conjunto de permissões do contrato.

    server.admin é armazenado na lista `permissions` como qualquer outra
    permissão — o dado é "burro". `is_wildcard` apenas expõe, de forma
    consultável e explícita, que este role concede acesso total. A regra
    de negócio (curto-circuitar autorização) vive no Passo 6.
    """
    name: str
    permissions: FrozenSet[str]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise IdentityError("ServiceRole.name não pode ser vazio.")
        unknown = self.permissions - KNOWN_PERMISSIONS
        if unknown:
            raise UnknownPermissionError(
                f"Permissões fora do contrato: {sorted(unknown)}"
            )

    @property
    def is_wildcard(self) -> bool:
        """Propriedade explícita do contrato: True se concede server.admin."""
        return SERVER_ADMIN_PERMISSION in self.permissions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "permissions": sorted(self.permissions),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceRole":
        return cls(
            name=data["name"],
            permissions=frozenset(data.get("permissions", [])),
            description=data.get("description", ""),
        )


@dataclass
class ApiKey:
    """
    Registro persistido de uma chave de API.

    O segredo em si NUNCA é armazenado — apenas key_hash (SHA-256 do
    token bruto). Ver generate_token()/hash_token().
    """
    id: str
    key_hash: str
    name: str
    role_name: str
    created_at: str
    expires_at: Optional[str] = None
    revoked: bool = False
    last_used_at: Optional[str] = None
    scoped_app_names: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApiKey":
        return cls(
            id=data["id"],
            key_hash=data["key_hash"],
            name=data["name"],
            role_name=data["role_name"],
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            revoked=data.get("revoked", False),
            last_used_at=data.get("last_used_at"),
            scoped_app_names=list(data.get("scoped_app_names", [])),
        )

    @property
    def is_globally_scoped(self) -> bool:
        """scoped_app_names == [] significa 'todas as aplicações'."""
        return len(self.scoped_app_names) == 0


def is_expired(api_key: "ApiKey", now: Optional[datetime] = None) -> bool:
    """
    Regra unica e reutilizavel de expiracao de uma ApiKey. Um
    expires_at ausente significa "nunca expira". Um expires_at
    malformado e tratado como expirado (falha fechado — nunca
    autentica/autoriza sobre dado corrompido).

    Esta e a UNICA implementacao desta regra no projeto — core.auth a
    reutiliza em vez de duplicar a logica (ver Passo 4B-C).
    """
    if api_key.expires_at is None:
        return False

    try:
        expires_at = datetime.fromisoformat(api_key.expires_at)
    except ValueError:
        return True

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    reference = now or datetime.now(timezone.utc)
    return reference >= expires_at


# ---------------------------------------------------------------------------
# Geração / hashing de tokens
# ---------------------------------------------------------------------------

TOKEN_PREFIX = "mk_"  # "moracle key" — só facilita reconhecimento visual


def generate_token() -> str:
    """
    Gera um token de API criptograficamente seguro. O valor bruto é
    retornado UMA VEZ ao chamador; nada neste módulo o persiste.
    """
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """SHA-256 hex digest do token bruto. É isso que é persistido."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# RoleStore
# ---------------------------------------------------------------------------

class RoleStore:
    """Persistência de ServiceRole em .state/roles.json."""

    def __init__(self, state_dir: Path):
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        self._path = str(state_dir / "roles.json")

    def load_all(self) -> Dict[str, ServiceRole]:
        raw = ler_json(self._path, padrao=[])
        return {r["name"]: ServiceRole.from_dict(r) for r in raw}

    def get(self, name: str) -> Optional[ServiceRole]:
        return self.load_all().get(name)

    def upsert(self, role: ServiceRole) -> None:
        def _mod(atual):
            roles = [r for r in (atual or []) if r["name"] != role.name]
            roles.append(role.to_dict())
            return roles
        modificar_json_com_lock(self._path, _mod, padrao=[])

    def ensure_admin_role_exists(self) -> ServiceRole:
        """
        Idempotente e atômico: garante a existência de um role 'admin' com
        server.admin. Não sobrescreve um role 'admin' já existente.
        Leitura + checagem + escrita ocorrem sob um único lock.
        """
        def _mod(atual):
            roles = atual or []
            if any(r["name"] == "admin" for r in roles):
                return roles
            admin_role = ServiceRole(
                name="admin",
                permissions=frozenset({SERVER_ADMIN_PERMISSION}),
                description="Acesso administrativo total (permissão coringa).",
            )
            roles.append(admin_role.to_dict())
            return roles
        modificar_json_com_lock(self._path, _mod, padrao=[])
        return self.get("admin")

    def add(self, role: ServiceRole) -> None:
        """
        Atômico: cria uma role nova, rejeitando nome duplicado.
        Distinto de upsert() (que sobrescreve silenciosamente) — uso
        exclusivo do endpoint POST /admin/roles, que nunca deve
        sobrescrever uma role existente.
        """
        def _mod(atual):
            roles = atual or []
            if any(r["name"] == role.name for r in roles):
                raise DuplicateRoleNameError(f"Role já existe: {role.name!r}")
            roles.append(role.to_dict())
            return roles
        modificar_json_com_lock(self._path, _mod, padrao=[])


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------

class KeyStore:
    """Persistência de ApiKey em .state/keys.json."""

    #: id fixo e determinístico da chave migrada de .state/api_key.txt.
    #: Fixar o id (em vez de gerar um uuid aleatório a cada chamada) é o que
    #: garante idempotência: reiniciar o Moracle nunca cria uma segunda
    #: chave admin, pois a migração checa a presença deste id antes de
    #: criar qualquer coisa.
    LEGACY_MIGRATION_ID = "legacy-admin-migration"

    def __init__(self, state_dir: Path):
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        self._path = str(state_dir / "keys.json")

    def load_all(self) -> Dict[str, ApiKey]:
        raw = ler_json(self._path, padrao=[])
        return {k["id"]: ApiKey.from_dict(k) for k in raw}

    def get(self, key_id: str) -> Optional[ApiKey]:
        return self.load_all().get(key_id)

    def find_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        for k in self.load_all().values():
            if k.key_hash == key_hash:
                return k
        return None

    def add(self, api_key: ApiKey) -> None:
        """
        Atômico: as checagens de id duplicado e de name duplicado, e a
        escrita, ocorrem sob o mesmo lock (keys.json.lock), fechando a
        janela de corrida entre chamadas concorrentes.

        Unicidade de name e uma invariante estrutural do Store, nao
        apenas uma regra da Admin API — vale para qualquer chamador.
        """
        def _mod(atual):
            keys = atual or []
            if any(k["id"] == api_key.id for k in keys):
                raise DuplicateApiKeyError(f"ApiKey id já existe: {api_key.id}")
            if any(k["name"] == api_key.name for k in keys):
                raise DuplicateApiKeyNameError(f"ApiKey name já existe: {api_key.name!r}")
            keys.append(api_key.to_dict())
            return keys
        modificar_json_com_lock(self._path, _mod, padrao=[])

    def revoke(self, key_id: str) -> None:
        def _mod(atual):
            keys = atual or []
            encontrada = False
            for k in keys:
                if k["id"] == key_id:
                    k["revoked"] = True
                    encontrada = True
            if not encontrada:
                raise IdentityError(f"ApiKey não encontrada: {key_id}")
            return keys
        modificar_json_com_lock(self._path, _mod, padrao=[])

    def touch_last_used(self, key_id: str) -> None:
        def _mod(atual):
            keys = atual or []
            encontrada = False
            for k in keys:
                if k["id"] == key_id:
                    k["last_used_at"] = _now_iso()
                    encontrada = True
            if not encontrada:
                raise IdentityError(f"ApiKey não encontrada: {key_id}")
            return keys
        modificar_json_com_lock(self._path, _mod, padrao=[])

    def revoke_safely(self, key_id: str, role_store: "RoleStore") -> None:
        """
        Revoga uma ApiKey, protegendo a invariante "sempre existe ao
        menos uma credencial server.admin valida e nao revogada".

        Operacao COMPOSTA (le keys.json + roles.json) — usa um lock
        dedicado (identity.lock), distinto de keys.json.lock e
        roles.json.lock. A dependencia de RoleStore e explicita
        (injetada), preservando o desacoplamento: KeyStore nunca
        conhece a localizacao nem o formato de roles.json — apenas
        chama role_store.load_all(), a interface publica existente.

        Isso NAO introduz lock aninhado: RoleStore.load_all() e uma
        operacao de LEITURA que nunca adquire roles.json.lock (so
        escritas — add/upsert/ensure_admin_role_exists — usam
        modificar_json_com_lock). Portanto ler roles via role_store
        dentro de identity.lock e seguro.

        Idempotente: revogar uma chave ja revogada e um sucesso
        silencioso, sem reavaliar a invariante.

        Levanta:
            IdentityError      se key_id nao existe.
            LastAdminKeyError  se revogar deixaria o sistema sem
                               nenhuma credencial server.admin valida
                               (nao revogada, nao expirada, com role
                               existente e wildcard).
        """
        lock_base = str(Path(self._path).parent / "identity")

        with FileLock(lock_base):
            keys = ler_json(self._path, padrao=[])
            roles_por_nome = role_store.load_all()  # Dict[str, ServiceRole]

            alvo = next((k for k in keys if k["id"] == key_id), None)
            if alvo is None:
                raise IdentityError(f"ApiKey não encontrada: {key_id}")

            if alvo.get("revoked", False):
                return  # idempotente

            def _e_admin_valida(registro):
                if registro.get("revoked", False):
                    return False
                if is_expired(ApiKey.from_dict(registro)):
                    return False
                role = roles_por_nome.get(registro["role_name"])
                if role is None:
                    return False
                return role.is_wildcard

            if not _e_admin_valida(alvo):
                alvo["revoked"] = True
                escrever_json(self._path, keys)
                return

            outra_admin_valida = any(
                _e_admin_valida(k) for k in keys if k["id"] != key_id
            )
            if not outra_admin_valida:
                raise LastAdminKeyError(
                    "Cannot revoke the last active server.admin key"
                )

            alvo["revoked"] = True
            escrever_json(self._path, keys)

    def has_legacy_migration_run(self) -> bool:
        return self.LEGACY_MIGRATION_ID in self.load_all()


# ---------------------------------------------------------------------------
# Migração da chave legada
# ---------------------------------------------------------------------------

def migrate_legacy_admin_key(
    state_dir: Path,
    key_store: Optional[KeyStore] = None,
    role_store: Optional[RoleStore] = None,
) -> Optional[ApiKey]:
    """
    Migra .state/api_key.txt (token em texto plano, formato legado) para
    uma ApiKey com role "admin" em .state/keys.json.

    Idempotente: se a migração já ocorreu (ApiKey com id
    KeyStore.LEGACY_MIGRATION_ID já existe), esta função não faz nada e
    retorna None. Reiniciar o Moracle não cria uma segunda chave admin.

    Não escreve nem apaga o arquivo legado; apenas o lê. Remover o texto
    plano legado é uma decisão operacional do usuário, fora do escopo
    deste módulo.
    """
    state_dir = Path(state_dir)
    key_store = key_store or KeyStore(state_dir)
    role_store = role_store or RoleStore(state_dir)

    if key_store.has_legacy_migration_run():
        return None

    legacy_path = state_dir / "api_key.txt"
    if not legacy_path.exists():
        return None

    raw_token = legacy_path.read_text(encoding="utf-8").strip()
    if not raw_token:
        return None

    role_store.ensure_admin_role_exists()

    api_key = ApiKey(
        id=KeyStore.LEGACY_MIGRATION_ID,
        key_hash=hash_token(raw_token),
        name="legacy-admin (migrada)",
        role_name="admin",
        created_at=_now_iso(),
        expires_at=None,
        revoked=False,
        last_used_at=None,
        scoped_app_names=[],
    )
    key_store.add(api_key)
    return api_key


# ---------------------------------------------------------------------------
# Fábrica de novas chaves
# (dado de modelo puro; usado futuramente por /admin/keys — Passo 8.)
# ---------------------------------------------------------------------------

def create_api_key(
    key_store: KeyStore,
    name: str,
    role_name: str,
    scoped_app_names: Optional[List[str]] = None,
    expires_at: Optional[str] = None,
) -> Tuple[ApiKey, str]:
    """
    Cria e persiste uma nova ApiKey. Retorna (ApiKey, token_bruto).
    O token bruto só é retornado nesta chamada — não é recuperável depois.
    """
    raw_token = generate_token()
    api_key = ApiKey(
        id=str(uuid.uuid4()),
        key_hash=hash_token(raw_token),
        name=name,
        role_name=role_name,
        created_at=_now_iso(),
        expires_at=expires_at,
        revoked=False,
        last_used_at=None,
        scoped_app_names=list(scoped_app_names or []),
    )
    key_store.add(api_key)
    return api_key, raw_token
