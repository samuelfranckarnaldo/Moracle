"""
tests/conftest.py

Fixture global de isolamento de estado persistente (Passo 4C).
Fonte UNICA de verdade para isolamento de testes que exercitam
producao real com persistencia em disco — substitui a fixture
anterior identidade_isolada (Passo 4B-D), que cobria somente
identidade e se mostrou insuficiente: um incidente real durante o
4B-D revelou que outros modulos (core.defense, deploy_platform.registry,
etc.) tambem calculam caminhos de estado em tempo de import e nao
eram isolados, causando destruicao do .state/ real do projeto via
shutil.rmtree(defense.STATE_DIR) em testes de carga/observabilidade.

ESTRATEGIA: patches explicitos e auditaveis sobre um mapa fechado de
constantes conhecidas — deliberadamente SEM introspeccao automatica
(vars()/inspect/startswith dinamico), que foi avaliada e rejeitada por
risco de redirecionar variaveis que nao sao estado por coincidencia de
nome. Um teste de auditoria estatica (test_state_isolation_audit.py)
verifica que este mapa permanece exaustivo, para que uma omissao vire
falha de teste explicita em vez de silenciosa.

Perimetro coberto: core.api_key, core.defense, core.custody,
core.audit, core.tls_config, core.logging_setup, core.whitelist,
deploy_platform.registry, deploy_platform.application_manager.

core.identity NAO esta no mapa: seus Stores (KeyStore/RoleStore) ja
recebem state_dir como parametro explicito no construtor (Passo 1) —
nunca usam constante de modulo, portanto nao tem essa classe de risco.

config.json permanece FORA do escopo do 4C (divida registrada
separadamente — ver test_rate_limit_middleware.py, que escreve
config.json real via config.carregar()/config.salvar()).
"""
import importlib
from unittest.mock import patch

import pytest

from core import config as _config_module


# Mapa explicito: modulo dotted-path -> lista de nomes de constantes
# de NIVEL DE MODULO que sao (direta ou transitivamente) derivadas de
# config.RAIZ_PROJETO e portanto precisam ser redirecionadas para
# tmp_path durante os testes. Mantido em sincronia por
# test_state_isolation_audit.py::test_mapa_de_estado_permanece_exaustivo.
CAMINHOS_DE_ESTADO = {
    "core.api_key": ["KEY_PATH"],
    "core.defense": ["STATE_DIR", "STATE_FILE", "BLOCKLIST_FILE", "ALERTS_FILE"],
    "core.custody": ["CHAVE_PATH"],
    "core.audit": ["AUDIT_FILE"],
    "core.tls_config": ["CERT_DIR", "CERT_PATH", "KEY_PATH"],
    "core.logging_setup": ["LOG_DIR"],
    "core.whitelist": ["WHITELIST_PATH"],
    "deploy_platform.registry": ["PLATFORM_DIR", "APPS_FILE", "DEPLOYMENTS_FILE", "PROCESS_HANDLES_FILE"],
    "deploy_platform.application_manager": ["LOGS_DIR"],
}


@pytest.fixture
def estado_isolado(tmp_path):
    """
    Redireciona TODO caminho de estado persistente conhecido (mapa
    CAMINHOS_DE_ESTADO) + core.config.RAIZ_PROJETO para tmp_path,
    preservando a estrutura relativa original de cada caminho.

    Ordem obrigatoria (nao pode ser invertida): os valores originais
    das 17 constantes sao capturados e os sufixos calculados usando o
    RAIZ_PROJETO REAL, ANTES de qualquer patch ser aplicado — se
    RAIZ_PROJETO fosse patcheado primeiro, nao haveria mais como
    calcular corretamente o que e "relativo a raiz" a partir das
    constantes (elas ainda conteriam o caminho antigo, mas a
    referencia para calcular o sufixo ja teria mudado).

    Seguranca de setup: a Fase 1 (calculo dos patches) e pura, sem
    efeito colateral algum. A Fase 2 (ativacao) tem rollback explicito:
    se qualquer patch.start() falhar no meio da lista, todos os
    patches ja ativados sao revertidos, em ordem reversa, antes da
    excecao ser propagada — nunca fica isolamento parcial ativo.

    Escopo: function (mesmo escopo de tmp_path) — cada teste recebe
    estado proprio.
    """
    raiz_real = _config_module.RAIZ_PROJETO
    tmp_str = str(tmp_path)

    # --- Fase 1: calcular todos os patches (sem efeito colateral) ---
    patchers = []
    for modulo_nome, constantes in CAMINHOS_DE_ESTADO.items():
        modulo = importlib.import_module(modulo_nome)
        for nome_constante in constantes:
            valor_original = getattr(modulo, nome_constante)
            if not str(valor_original).startswith(raiz_real):
                raise RuntimeError(
                    f"{modulo_nome}.{nome_constante} = {valor_original!r} nao "
                    f"comeca com RAIZ_PROJETO real ({raiz_real!r}) — fixture "
                    f"nao pode calcular o redirecionamento com seguranca."
                )
            sufixo = str(valor_original)[len(raiz_real):]
            novo_valor = tmp_str + sufixo
            patchers.append(patch(f"{modulo_nome}.{nome_constante}", novo_valor))

    # RAIZ_PROJETO e o ULTIMO da lista -> ultimo a ser ativado (Fase 2)
    # e, por construcao do loop reverso, o PRIMEIRO a ser revertido no
    # teardown — ordem estritamente reversa a ativacao.
    patchers.append(patch("core.config.RAIZ_PROJETO", tmp_str))

    # --- Fase 2: ativar, com rollback se algum start() falhar ---
    ativos = []
    try:
        for p in patchers:
            p.start()
            ativos.append(p)
    except Exception:
        for p in reversed(ativos):
            p.stop()
        raise

    # --- Fase 3: teste roda ---
    try:
        yield tmp_path
    finally:
        for p in reversed(ativos):
            p.stop()
