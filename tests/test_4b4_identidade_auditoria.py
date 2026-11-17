"""
Passo 4b-4 - auditoria da criacao e revogacao de chaves e roles (Admin API)
e da migracao da chave legada.

Os handlers importam `deploy_platform.registry` e `server.response.Response`.
Se o ambiente nao os tiver (copia parcial do repositorio), este modulo
injeta substitutos minimos APENAS para o import e depois remove-os de
sys.modules; no repositorio completo usam-se os reais.
"""
import copy
import json
import sys
import types

import pytest

from server import response as _resp

if not hasattr(_resp.Response, "json"):          # copia parcial: Response e um esboco
    class _Resp:
        def __init__(self, status=200, headers=None, body=b""):
            self.status, self.headers, self.body = status, headers or {}, body

        @classmethod
        def json(cls, dados, status=200):
            return cls(status=status, body=json.dumps(dados).encode())

    _resp.Response = _Resp

_injetou = False
try:
    import deploy_platform.registry  # noqa: F401
except ImportError:
    _dp = types.ModuleType("deploy_platform")
    _reg = types.ModuleType("deploy_platform.registry")
    _reg.listar_apps = lambda: []
    _dp.registry = _reg
    sys.modules["deploy_platform"], sys.modules["deploy_platform.registry"] = _dp, _reg
    _injetou = True

from admin_api import identity_handlers as ih  # noqa: E402

if _injetou:
    sys.modules.pop("deploy_platform", None)
    sys.modules.pop("deploy_platform.registry", None)

from core import audit, audit_ciclo, config  # noqa: E402
from core import security_audit as sa  # noqa: E402
from core import security_runtime as rt  # noqa: E402
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key  # noqa: E402


class Coletor:
    def __init__(self):
        self.alertas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.alertas.append((mensagem, dict(dados or {})))
        return "stderr"

    def esquecer(self, chave):
        pass


class Falha:
    ultimo_erro = "OSError"

    def gravar(self, evento):
        return False

    def ids_existentes(self):
        return set()


class Ctx(dict):
    def __init__(self, api_key, route_params=None):
        super().__init__(api_key=api_key)
        self.route_params = route_params or {}
        self.request_id = "req-test-1"


class Req:
    def __init__(self, corpo=None):
        self.body = json.dumps(corpo).encode() if corpo is not None else b""


def corpo(resp):
    b = resp.body
    return json.loads(b) if isinstance(b, (bytes, str)) else b


@pytest.fixture
def amb(tmp_path, monkeypatch):
    estado = tmp_path / ".state"
    estado.mkdir()
    monkeypatch.setattr(config, "RAIZ_PROJETO", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(config, "_cache", None)
    monkeypatch.setattr(config, "PADRAO", copy.deepcopy(config.PADRAO))
    monkeypatch.setattr(audit, "AUDIT_FILE", str(estado / "audit.log"))
    monkeypatch.setattr(rt, "_alertador", Coletor())
    monkeypatch.setattr(rt, "fabrica_auditor", None)
    (tmp_path / "config.json").write_text("{}")
    roles, keys = RoleStore(estado), KeyStore(estado)
    roles.upsert(ServiceRole(name="adm", permissions=frozenset({"server.admin"})))
    roles.upsert(ServiceRole(name="leitor", permissions=frozenset({"defense.read"})))
    admin, _ = create_api_key(keys, name="admin-1", role_name="adm")
    leitor, _ = create_api_key(keys, name="leitor-1", role_name="leitor")
    return types.SimpleNamespace(estado=estado, admin=admin, leitor=leitor, keys=keys, roles=roles,
                                 eventos=estado / "security_events.jsonl", ctx=Ctx(admin))


def eventos(amb, tipo=None):
    if not amb.eventos.exists():
        return []
    evs = [json.loads(l) for l in amb.eventos.read_text().splitlines() if l.strip()]
    return [e for e in evs if tipo is None or e["event_type"] == tipo]


def sem_audit(monkeypatch):
    monkeypatch.setattr(rt, "fabrica_auditor",
                        lambda: sa.Auditor(Falha(), Falha(), alertador=Coletor()))


# ------------------------------------------------------------------- roles

def test_criar_role_emite_requested_e_success(amb):
    r = ih.handler_create_role(Req({"name": "novo", "permissions": ["ioc.write"]}), amb.ctx)
    assert r.status == 201
    evs = eventos(amb, "role.created")
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[0]["payload"] == {"name": "novo", "permissions": ["ioc.write"]}
    assert evs[0]["actor"]["identity"]["key_id"] == amb.admin.id
    assert evs[0]["origin"] == "http"
    assert evs[1]["correlation_id"] == evs[0]["event_id"]


def test_role_duplicada_da_409_e_regista_failure(amb):
    ih.handler_create_role(Req({"name": "novo", "permissions": ["ioc.write"]}), amb.ctx)
    r = ih.handler_create_role(Req({"name": "novo", "permissions": ["ioc.write"]}), amb.ctx)
    assert r.status == 409
    assert [e["outcome"] for e in eventos(amb, "role.created")][-2:] == ["requested", "failure"]


def test_criar_role_sem_audit_da_503_e_nao_cria(amb, monkeypatch):
    sem_audit(monkeypatch)
    r = ih.handler_create_role(Req({"name": "novo", "permissions": ["ioc.write"]}), amb.ctx)
    assert r.status == 503
    assert amb.roles.get("novo") is None


def test_permissoes_novas_sao_validas_numa_role(amb):
    r = ih.handler_create_role(
        Req({"name": "cfg", "permissions": ["config.security_write", "ioc.write"]}), amb.ctx)
    assert r.status == 201


# -------------------------------------------------------------------- chaves

def test_criar_chave_emite_eventos_sem_segredo(amb):
    r = ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx)
    assert r.status == 201
    dados = corpo(r)
    evs = eventos(amb, "key.created")
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[1]["payload"]["target_id"] == dados["id"]
    assert evs[0]["payload"]["name"] == "k-nova" and evs[0]["payload"]["role"] == "leitor"
    bruto = amb.eventos.read_text()
    assert dados["secret"] not in bruto
    assert "key_hash" not in bruto and "hash" not in json.dumps(evs[1]["payload"])


def test_nome_de_chave_duplicado_da_409_e_regista_failure(amb):
    ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx)
    r = ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx)
    assert r.status == 409
    assert [e["outcome"] for e in eventos(amb, "key.created")][-2:] == ["requested", "failure"]


def test_criar_chave_sem_audit_da_503_e_nao_cria(amb, monkeypatch):
    antes = len(amb.keys.list_all()) if hasattr(amb.keys, "list_all") else None
    sem_audit(monkeypatch)
    r = ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx)
    assert r.status == 503
    assert "secret" not in corpo(r)
    if antes is not None:
        assert len(amb.keys.list_all()) == antes


def test_validacao_falhada_nao_emite_evento(amb):
    r = ih.handler_create_key(Req({"name": "", "role": "leitor"}), amb.ctx)
    assert r.status == 400
    assert eventos(amb) == []


def test_sem_server_admin_da_403_sem_evento(amb):
    r = ih.handler_create_key(Req({"name": "k", "role": "leitor"}), Ctx(amb.leitor))
    assert r.status == 403
    r = ih.handler_create_role(Req({"name": "x", "permissions": ["ioc.write"]}), Ctx(amb.leitor))
    assert r.status == 403
    assert eventos(amb) == []


def test_revogar_chave_emite_eventos(amb):
    nova = corpo(ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx))
    r = ih.handler_revoke_key(Req(), Ctx(amb.admin, {"id": nova["id"]}))
    assert r.status == 200
    evs = eventos(amb, "key.revoked")
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[0]["payload"] == {"target_id": nova["id"]}


def test_revogar_ultima_chave_admin_da_409_e_regista_failure(amb):
    r = ih.handler_revoke_key(Req(), Ctx(amb.admin, {"id": amb.admin.id}))
    assert r.status == 409
    assert [e["outcome"] for e in eventos(amb, "key.revoked")] == ["requested", "failure"]


def test_revogar_chave_inexistente_da_404(amb):
    r = ih.handler_revoke_key(Req(), Ctx(amb.admin, {"id": "nao-existe"}))
    assert r.status == 404
    assert [e["outcome"] for e in eventos(amb, "key.revoked")] == ["requested", "failure"]


def test_revogar_sem_audit_da_503_e_nao_revoga(amb, monkeypatch):
    nova = corpo(ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx))
    sem_audit(monkeypatch)
    r = ih.handler_revoke_key(Req(), Ctx(amb.admin, {"id": nova["id"]}))
    assert r.status == 503
    assert amb.keys.get(nova["id"]).revoked is False


def test_falha_do_evento_de_resultado_nao_reverte_a_mutacao(amb, monkeypatch):
    class Principal(sa.DestinoJsonl):
        def __init__(self, caminho):
            super().__init__(caminho)
            self.n = 0

        def gravar(self, evento):
            self.n += 1
            if self.n > 1:
                self.ultimo_erro = "OSError"
                return False
            return super().gravar(evento)

    principal = Principal(str(amb.eventos))
    monkeypatch.setattr(rt, "fabrica_auditor",
                        lambda: sa.Auditor(principal, Falha(), alertador=Coletor()))
    r = ih.handler_create_key(Req({"name": "k-nova", "role": "leitor"}), amb.ctx)
    assert r.status == 201            # a chave existe e o segredo foi devolvido
    assert amb.keys.get(corpo(r)["id"]) is not None


# ------------------------------------------------------- migracao da chave legada

def test_registar_fato_grava_evento_de_migracao(amb):
    ok = audit_ciclo.registar_fato("key.migrated", {"target_id": "legacy", "role": "admin"},
                                   rt.ator_http({}), "cli-local")
    assert ok is True
    ev = eventos(amb, "key.migrated")[0]
    assert ev["outcome"] == "success" and ev["payload"]["role"] == "admin"
    assert ev["origin"] == "cli-local"


def test_registar_fato_sem_audit_devolve_false_sem_levantar(amb, monkeypatch):
    sem_audit(monkeypatch)
    assert audit_ciclo.registar_fato("key.migrated", {"target_id": "x"}, rt.ator_http({}),
                                     "cli-local") is False
