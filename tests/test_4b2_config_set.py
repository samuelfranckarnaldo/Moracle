"""
Passo 4b-2 - `config set`: classificacao por efeito, permissao
config.security_write, validacao, escrita atomica e evento config.changed.

Isolamento: RAIZ_PROJETO, CONFIG_PATH, cache de config, PADRAO, estado, audit
e alertador apontam para tmp_path / falsos; nada toca o repositorio real.
"""
import copy
import json
import sys
import threading
from types import SimpleNamespace

import pytest

import cli
from core import atomic_state, audit, config, config_security as cs
from core import security_audit as sa
from core import security_runtime as rt
from core.identity import KeyStore, RoleStore, ServiceRole, create_api_key


class Coletor:
    def __init__(self):
        self.alertas = []

    def alertar(self, mensagem, dados=None, chave_dedup=None):
        self.alertas.append((mensagem, dict(dados or {})))
        return "stderr"

    def esquecer(self, chave):
        pass


class DestinoQueFalha:
    ultimo_erro = "OSError"

    def gravar(self, evento):
        return False

    def ids_existentes(self):
        return set()


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
    monkeypatch.delenv("MORACLE_API_KEY", raising=False)
    (tmp_path / "config.json").write_text("{}")
    return SimpleNamespace(raiz=tmp_path, estado=estado, config=tmp_path / "config.json",
                           eventos=estado / "security_events.jsonl")


def rodar(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["mc", "config", "set", *args])
    return cli.main()


def credencial(amb, monkeypatch, permissoes=("config.security_write",), role="cfg", nome="cfg-key",
               usar=True, expires_at=None):
    RoleStore(amb.estado).upsert(ServiceRole(name=role, permissions=frozenset(permissoes)))
    chave, token = create_api_key(KeyStore(amb.estado), name=nome, role_name=role,
                                  expires_at=expires_at)
    if usar:
        monkeypatch.setenv("MORACLE_API_KEY", token)
    return chave, token


def eventos(amb):
    if not amb.eventos.exists():
        return []
    return [json.loads(l) for l in amb.eventos.read_text().splitlines() if l.strip()]


def ler(amb):
    return json.loads(amb.config.read_text())


# ------------------------------------------------------------ classificacao

def _folhas(d, prefixo=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _folhas(v, prefixo + k + ".")
        else:
            yield prefixo + k


def test_toda_chave_do_PADRAO_esta_classificada_livre_ou_protegida():
    for chave in _folhas(config.PADRAO):
        assert cs.classificar(chave) in (cs.LIVRE, cs.PROTEGIDA), chave


def test_chaves_livres_sao_so_as_de_efeito_nulo():
    assert set(cs.CHAVES_LIVRES) == {"idioma", "limite_suspeitos_padrao"}


def test_chaves_de_seguranca_bloqueio_e_auditoria_sao_protegidas():
    for chave in ("webhook_url", "bloqueio_expira_horas_padrao", "defesa.limite_alerta_padrao",
                  "defesa.intervalo_padrao", "rate_limit.global_max", "auditoria.arquivo_eventos",
                  "auditoria.diretorio_fila", "diretorio_saida", "ioc_cache_validade_horas"):
        assert cs.classificar(chave) == cs.PROTEGIDA, chave


def test_chave_desconhecida_nao_e_segura_por_omissao():
    assert cs.classificar("webhook_deploy.minha_app") == cs.DESCONHECIDA
    assert cs.classificar("qualquer_coisa") == cs.DESCONHECIDA


# ------------------------------------------------------------- autorizacao

def test_sem_credencial_e_credencial_invalida_negam_sem_alterar(amb, monkeypatch, capsys):
    antes = amb.config.read_text()
    # sem credencial no ambiente
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 1
    # credencial que nao existe (ha chaves no store, mas nao esta)
    credencial(amb, monkeypatch, usar=False)
    monkeypatch.setenv("MORACLE_API_KEY", "token-que-nao-existe")
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 1
    assert amb.config.read_text() == antes
    assert eventos(amb) == []
    assert "token-que-nao-existe" not in capsys.readouterr().out


def test_sem_nenhuma_chave_no_store_nega(amb, monkeypatch):
    monkeypatch.setenv("MORACLE_API_KEY", "qualquer")
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 1


def test_role_sem_config_security_write_e_negada(amb, monkeypatch):
    credencial(amb, monkeypatch, permissoes=("defense.block",), role="so-bloqueio")
    antes = amb.config.read_text()
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 1
    assert amb.config.read_text() == antes


def test_chave_revogada_e_negada(amb, monkeypatch):
    chave, _ = credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 0  # antes de revogar
    KeyStore(amb.estado).revoke(chave.id)
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "6") == 1
    assert ler(amb)["defesa"]["limite_alerta_padrao"] == 5


def test_chave_expirada_e_negada(amb, monkeypatch):
    credencial(amb, monkeypatch, expires_at="2000-01-01T00:00:00+00:00")
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 1


def test_server_admin_tambem_pode(amb, monkeypatch):
    credencial(amb, monkeypatch, permissoes=("server.admin",), role="adm")
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "5") == 0
    assert ler(amb)["defesa"]["limite_alerta_padrao"] == 5


# ------------------------------------------------------------------- eventos

def test_evento_requested_e_success_com_identidade(amb, monkeypatch):
    chave, _ = credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "8") == 0
    evs = eventos(amb)
    assert [e["outcome"] for e in evs] == ["requested", "success"]
    assert evs[0]["event_type"] == "config.changed"
    assert evs[0]["payload"]["key"] == "defesa.limite_alerta_padrao"
    assert evs[0]["payload"]["previous_value"] == 3
    assert evs[0]["payload"]["new_value"] == 8
    assert evs[0]["actor"]["identity"]["key_id"] == chave.id
    assert evs[0]["origin"] == "cli-local"
    assert evs[1]["correlation_id"] == evs[0]["event_id"]


def test_valor_sensivel_nunca_aparece_nos_eventos_nem_no_ecra(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "webhook_url", "https://exemplo.test/segredo-123") == 0
    out = capsys.readouterr().out
    assert "segredo-123" not in out
    assert "segredo-123" not in amb.eventos.read_text()
    assert "segredo-123" not in (amb.estado / "audit.log").read_text()
    assert ler(amb)["webhook_url"] == "https://exemplo.test/segredo-123"


def test_sem_alteracao_nao_emite_evento_nem_reescreve(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "3") == 0  # ja e 3
    assert eventos(amb) == []
    assert "nada foi alterado" in capsys.readouterr().out


def test_mensagem_mostra_o_valor_realmente_gravado(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "bloqueio_expira_horas_padrao", "24")
    assert "24" in capsys.readouterr().out
    assert ler(amb)["bloqueio_expira_horas_padrao"] == 24


# ---------------------------------------------------- falha fechada da auditoria

def test_protegida_com_audit_indisponivel_nao_altera(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(DestinoQueFalha(), DestinoQueFalha(),
                                                                  alertador=Coletor()))
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "9") == 1
    assert amb.config.read_text() == antes
    assert "auditoria indisponivel" in capsys.readouterr().out


def test_protegida_com_auditor_que_nao_se_cria_nao_altera(amb, monkeypatch):
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()

    def explode():
        raise RuntimeError("config de audit invalida")

    monkeypatch.setattr(rt, "fabrica_auditor", explode)
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "9") == 1
    assert amb.config.read_text() == antes


def test_livre_com_audit_indisponivel_ainda_altera(amb, monkeypatch):
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(DestinoQueFalha(), DestinoQueFalha(),
                                                                  alertador=Coletor()))
    assert rodar(monkeypatch, "idioma", "en") == 0
    assert ler(amb)["idioma"] == "en"


def test_falha_do_evento_de_resultado_avisa_perda_de_rastreabilidade(amb, monkeypatch, capsys):
    credencial(amb, monkeypatch)

    class Principal(sa.DestinoJsonl):
        def __init__(self, caminho):
            super().__init__(caminho)
            self.n = 0

        def gravar(self, evento):
            self.n += 1
            if self.n > 1:      # o "requested" grava; o resultado falha
                self.ultimo_erro = "OSError"
                return False
            return super().gravar(evento)

    principal = Principal(str(amb.eventos))
    fila = sa.FilaDuravel(str(amb.estado / "fila" / "f.jsonl"))
    fila.gravar = lambda ev: False
    fila.ultimo_erro = "OSError"
    monkeypatch.setattr(rt, "fabrica_auditor", lambda: sa.Auditor(principal, fila, alertador=Coletor()))
    assert rodar(monkeypatch, "defesa.limite_alerta_padrao", "9") == 0   # a escrita NAO e revertida
    assert ler(amb)["defesa"]["limite_alerta_padrao"] == 9
    assert "perda de rastreabilidade" in capsys.readouterr().err


# ---------------------------------------------------------------- validacao

def test_limites_de_cada_chave_protegida(amb, monkeypatch):
    credencial(amb, monkeypatch)
    validos = [("defesa.intervalo_padrao", "1"), ("defesa.intervalo_padrao", "3600"),
               ("defesa.limite_alerta_padrao", "100000"), ("rate_limit.por_ip_max", "1"),
               ("rate_limit.por_rota_janela_segundos", "86400"),
               ("bloqueio_expira_horas_padrao", "8760"), ("bloqueio_expira_horas_padrao", "null"),
               ("ioc_cache_validade_horas", "0.5"), ("webhook_url", "null"),
               ("webhook_url", "http://h.test/x"), ("auditoria.arquivo_eventos", "eventos/novo.jsonl")]
    for chave, valor in validos:
        assert rodar(monkeypatch, chave, valor) == 0, (chave, valor)
    invalidos = [("defesa.intervalo_padrao", "0"), ("defesa.intervalo_padrao", "3601"),
                 ("defesa.limite_alerta_padrao", "100001"), ("rate_limit.por_ip_max", "0"),
                 ("rate_limit.por_ip_max", "-1"), ("rate_limit.por_rota_janela_segundos", "86401"),
                 ("bloqueio_expira_horas_padrao", "0"), ("bloqueio_expira_horas_padrao", "8761"),
                 ("ioc_cache_validade_horas", "-1"), ("ioc_cache_validade_horas", "abc"),
                 ("ioc_cache_validade_horas", "nan"), ("webhook_url", "javascript:alert(1)"),
                 ("webhook_url", "http://"), ("defesa.intervalo_padrao", "²"),
                 ("defesa.intervalo_padrao", "1e3")]
    for chave, valor in invalidos:
        antes = amb.config.read_text()
        assert rodar(monkeypatch, chave, valor) == 1, (chave, valor)
        assert amb.config.read_text() == antes, (chave, valor)


def test_diretorio_saida_recusa_escape_por_link_simbolico(amb, monkeypatch):
    credencial(amb, monkeypatch)
    fora = amb.raiz.parent / ("fora_" + amb.raiz.name)
    fora.mkdir()
    (amb.raiz / "atalho").symlink_to(fora)
    assert rodar(monkeypatch, "diretorio_saida", "atalho") == 1
    assert rodar(monkeypatch, "diretorio_saida", ".") == 1
    assert rodar(monkeypatch, "diretorio_saida", "a/../../fora") == 1


def test_auditoria_principal_e_fila_nao_podem_partilhar_diretorio(amb, monkeypatch):
    credencial(amb, monkeypatch)
    antes = amb.config.read_text()
    # fila em .state/security_audit_queue; principal no mesmo diretorio da fila
    assert rodar(monkeypatch, "auditoria.arquivo_eventos", ".state/security_audit_queue/ev.jsonl") == 1
    assert amb.config.read_text() == antes


def test_auditoria_recusa_pseudo_ficheiros(amb, monkeypatch):
    credencial(amb, monkeypatch)
    for valor in ("/dev/null", "/dev/shm/x", "/proc/self/x", "../x"):
        assert rodar(monkeypatch, "auditoria.arquivo_eventos", valor) == 1, valor


def test_nome_de_chave_invalido_e_rejeitado(amb, monkeypatch):
    credencial(amb, monkeypatch)
    for chave in ("a b", "x=y", "https://segredo", "a.b.c", "", ".x", "x."):
        assert rodar(monkeypatch, chave, "1") == 1, chave


def test_nao_cria_objetos_novos_por_chave_desconhecida(amb, monkeypatch):
    credencial(amb, monkeypatch)
    assert rodar(monkeypatch, "novo_objeto.sub", "1") == 1


# ----------------------------------------------------------------- escrita

def test_config_json_ilegivel_nao_e_sobrescrito(amb, monkeypatch):
    # (a CLI inteira ja falha ao arrancar com um config.json ilegivel; aqui
    # verifica-se o modulo: recusa e deixa o ficheiro como esta.)
    credencial(amb, monkeypatch)
    amb.config.write_text("{corrompido")
    config._cache = None
    res = cs.executar_config_set("defesa.limite_alerta_padrao", "5")
    assert res.estado == cs.INVALIDO
    assert amb.config.read_text() == "{corrompido"
    with pytest.raises(ValueError):
        config.definir("defesa.limite_alerta_padrao", 5)
    assert amb.config.read_text() == "{corrompido"


def test_carregar_recupera_raiz_estruturada_escalar_deixada_por_versao_antiga(amb, capsys):
    amb.config.write_text(json.dumps({"defesa": "abc", "rate_limit": 5}))
    config._cache = None
    cfg = config.carregar()
    assert cfg["defesa"]["limite_alerta_padrao"] == 3
    assert cfg["rate_limit"]["global_max"] == 500
    assert "CONFIG WARN" in capsys.readouterr().err


def test_carregar_junta_subchaves_em_falta_de_rate_limit(amb):
    amb.config.write_text(json.dumps({"rate_limit": {"global_max": 7}}))
    config._cache = None
    cfg = config.carregar()
    assert cfg["rate_limit"]["global_max"] == 7
    assert cfg["rate_limit"]["por_ip_max"] == 60


def test_escrita_concorrente_nao_perde_atualizacoes(amb, monkeypatch):
    credencial(amb, monkeypatch)
    erros = []

    def escrever(chave, n):
        try:
            for i in range(10):
                config.definir(chave, n * 100 + i)
        except Exception as exc:  # pragma: no cover
            erros.append(exc)

    ths = [threading.Thread(target=escrever, args=(f"k{n}", n)) for n in range(6)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert not erros
    final = ler(amb)
    for n in range(6):
        assert final[f"k{n}"] == n * 100 + 9
    assert final["defesa"]["limite_alerta_padrao"] == 3


def test_ficheiro_gravado_com_modo_restrito(amb, monkeypatch):
    import os
    import stat
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "defesa.limite_alerta_padrao", "4")
    assert stat.S_IMODE(os.stat(amb.config).st_mode) == 0o600


def test_set_nao_altera_o_PADRAO_partilhado(amb, monkeypatch):
    credencial(amb, monkeypatch)
    rodar(monkeypatch, "defesa.limite_alerta_padrao", "4")
    assert config.PADRAO["defesa"]["limite_alerta_padrao"] == 3


def test_salvar_e_atomico_e_preserva_o_ficheiro_se_a_escrita_falha(amb, monkeypatch):
    # (1.a gravacao / config.salvar direto: nao passa por definir)
    amb.config.write_text('{"idioma": "en"}')
    antes = amb.config.read_bytes()

    def falha(*a, **k):
        raise OSError("disco cheio simulado")

    monkeypatch.setattr(atomic_state, "_escrever_atomico", falha)
    with pytest.raises(OSError):
        config.salvar({"idioma": "pt"})
    assert amb.config.read_bytes() == antes
