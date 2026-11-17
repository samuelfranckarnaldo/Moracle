"""
Configuração do Moracle — carregada de config.json na raiz do projeto.
Criado automaticamente com valores padrão na primeira execução.
"""
import copy
import json
import os
import sys

from core import atomic_state

RAIZ_PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(RAIZ_PROJETO, "config.json")

PADRAO = {
    "idioma": "pt",
    "diretorio_saida": "saida",
    "limite_suspeitos_padrao": 3,
    "defesa": {
        "intervalo_padrao": 2,
        "limite_alerta_padrao": 3
    },
    "ioc_cache_validade_horas": 24,
    "webhook_url": None,
    "bloqueio_expira_horas_padrao": None,
    "rate_limit": {
        "global_max": 500, "global_janela_segundos": 60,
        "por_ip_max": 60, "por_ip_janela_segundos": 60,
        "por_rota_max": 30, "por_rota_janela_segundos": 10,
    },
    # Auditoria de seguranca (Gate #6 / Passo 3a). Caminhos relativos sao
    # resolvidos contra RAIZ_PROJETO no momento do uso. O audit principal e a
    # fila de recuperacao DEVEM ficar em caminhos distintos; em producao a fila
    # pode apontar para outro volume.
    "auditoria": {
        "arquivo_eventos": ".state/security_events.jsonl",
        "diretorio_fila": ".state/security_audit_queue",
    },
}

_cache = None

IDIOMAS_VALIDOS = {"pt", "en"}


def _validar(config):
    """Valida campos críticos; avisa e corrige em vez de falhar silenciosamente."""
    avisos = []

    if config.get("idioma") not in IDIOMAS_VALIDOS:
        avisos.append(f"idioma '{config.get('idioma')}' inválido, usando 'pt'")
        config["idioma"] = "pt"

    if not isinstance(config.get("limite_suspeitos_padrao"), int) or config["limite_suspeitos_padrao"] < 1:
        avisos.append("limite_suspeitos_padrao inválido, usando 3")
        config["limite_suspeitos_padrao"] = 3

    if not isinstance(config.get("ioc_cache_validade_horas"), (int, float)) or config["ioc_cache_validade_horas"] <= 0:
        avisos.append("ioc_cache_validade_horas inválido, usando 24")
        config["ioc_cache_validade_horas"] = 24

    webhook = config.get("webhook_url")
    if webhook and not (webhook.startswith("http://") or webhook.startswith("https://")):
        avisos.append("webhook_url não parece uma URL válida, ignorando")
        config["webhook_url"] = None

    for aviso in avisos:
        print(f"[CONFIG WARN] {aviso}", file=sys.stderr)

    return config


_RAIZES_ESTRUTURADAS = ("defesa", "auditoria", "rate_limit")


def _mesclar(dados):
    """PADRAO (copia profunda, nunca o objeto partilhado) + `dados`. Uma raiz
    estruturada que nao seja objeto no ficheiro (ex.: `"defesa": "abc"`,
    deixada por versoes antigas) e substituida pelo padrao com aviso, em vez
    de tornar a configuracao inutilizavel."""
    if not isinstance(dados, dict):
        print("[CONFIG WARN] config.json nao e um objeto; usando o padrao", file=sys.stderr)
        dados = {}
    config = {**copy.deepcopy(PADRAO), **dados}
    for raiz in _RAIZES_ESTRUTURADAS:
        padrao_raiz = PADRAO.get(raiz)
        if not isinstance(padrao_raiz, dict):
            continue
        valor = dados.get(raiz, {})
        if not isinstance(valor, dict):
            print(f"[CONFIG WARN] '{raiz}' invalido no config.json, usando o padrao", file=sys.stderr)
            valor = {}
        config[raiz] = {**copy.deepcopy(padrao_raiz), **valor}
    return config


def carregar():
    global _cache
    if _cache is not None:
        return _cache
    if not os.path.exists(CONFIG_PATH):
        novo = copy.deepcopy(PADRAO)  # 4b-2: nunca partilhar o PADRAO
        salvar(novo)
        _cache = copy.deepcopy(novo)
        return _cache
    with open(CONFIG_PATH) as f:
        dados = json.load(f)
    config = _validar(_mesclar(dados))
    _cache = config
    return config


def salvar(config):
    """Escrita atomica (temporario + fsync + replace, sob o mesmo mecanismo de
    lock do resto do estado): uma falha no meio nunca deixa o config.json
    truncado."""
    global _cache
    atomic_state.escrever_json(CONFIG_PATH, config)
    _cache = config


def definir(chave, valor):
    """Le-modifica-escreve sob lock, atomico. Nao corrige o valor em silencio:
    quem chama (core.config_security) valida antes. Um config.json ilegivel
    faz a chamada FALHAR (nunca e sobrescrito por um padrao)."""
    global _cache

    def _aplicar(atual):
        config = _mesclar(atual)
        if "." in chave:
            raiz, sub = chave.split(".", 1)
            no = config.setdefault(raiz, {})
            if not isinstance(no, dict):
                raise TypeError(f"'{raiz}' nao e um objeto")
            no[sub] = valor
        else:
            config[chave] = valor
        return config

    novo = atomic_state.modificar_json_com_lock(CONFIG_PATH, _aplicar, padrao={})
    _cache = None  # proximo carregar() revalida a partir do ficheiro
    return novo

def idioma():
    return carregar().get("idioma", "pt")

def resolver_caminho_saida(nome_arquivo, tipo):
    """tipo: 'relatorio' (.md) ou 'dados' (.json).
    Se nome_arquivo já tiver diretório embutido, respeita como está."""
    if os.path.dirname(nome_arquivo):
        return nome_arquivo
    config = carregar()
    base = os.path.join(RAIZ_PROJETO, config["diretorio_saida"])
    subpasta = "relatorios" if tipo == "relatorio" else "dados"
    destino = os.path.join(base, subpasta)
    os.makedirs(destino, exist_ok=True)
    return os.path.join(destino, nome_arquivo)
