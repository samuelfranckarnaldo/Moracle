"""
Cache local de IOCs — evita reconsultar VirusTotal/AbuseIPDB pro mesmo IP,
e permite ao modo defesa reagir na hora a um IP já conhecido como malicioso.

Integridade (Passo 4b-1):
  - Toda escrita e um ciclo ler-modificar-escrever sob UM lock de ficheiro
    (`ioc_cache.json.lock`, fcntl.flock: vale entre threads e processos) e
    usa escrita atomica (temporario sincronizado + os.replace), via
    core.atomic_state. Uma falha antes do os.replace deixa o ficheiro
    anterior byte a byte igual.
  - LIMITACAO DE DURABILIDADE (decisao 4b-1, fsync do diretorio = nao):
    nao ha fsync do diretorio apos o os.replace. Se faltar energia logo
    depois, o ficheiro pode voltar a versao anterior (a ultima escrita
    perde-se); nunca fica parcial nem corrompido.
  - Escrita sobre um cache ilegivel RECUSA e levanta: JSON invalido e erros
    de E/S propagam-se tal como saem; raiz que nao e dicionario levanta
    ValueError. Nunca se cria um cache vazio por cima, nem ha recuperacao
    destrutiva: recuperar e manual (mover o ficheiro e reimportar).
  - `consultar_malicioso` nunca levanta e distingue "ilegivel" de
    "ausente"/"expirado"; `obter` e `eh_malicioso_conhecido` mantem o
    comportamento anterior (incluindo levantar) para o whois e o import.
"""
import json
import os
from datetime import datetime, timezone

from core import config
from core.atomic_state import modificar_json_com_lock

# Estados de uma consulta.
ENCONTRADO = "encontrado"
AUSENTE = "ausente"
EXPIRADO = "expirado"
ILEGIVEL = "ilegivel"

# Vocabulario fechado de causas (so em ILEGIVEL). Estavel: usado na dedup
# de alertas e nos testes. Nunca carrega caminhos, conteudo nem mensagens.
CAUSA_JSON_INVALIDO = "json_invalido"
CAUSA_ESTRUTURA_INVALIDA = "estrutura_invalida"      # raiz nao e dicionario
CAUSA_ENTRADA_INVALIDA = "entrada_invalida"          # so o IP consultado
CAUSA_ERRO_DE_LEITURA = "erro_de_leitura"
CAUSA_CONFIGURACAO_INVALIDA = "configuracao_invalida"  # config ou caminho
CAUSA_ERRO_INESPERADO = "erro_inesperado"


class ConsultaIoc:
    """Resultado de `consultar_malicioso`. `malicioso` so e True/False em
    ENCONTRADO; nos outros estados e None (nunca se confunde "ilegivel"
    com "nao malicioso"). `erro_classe` e so o nome do tipo da excecao."""

    __slots__ = ("estado", "malicioso", "causa", "erro_classe")

    def __init__(self, estado, malicioso=None, causa=None, erro_classe=None):
        self.estado = estado
        self.malicioso = malicioso
        self.causa = causa
        self.erro_classe = erro_classe

    def __repr__(self):
        return "ConsultaIoc(estado=%r, malicioso=%r, causa=%r, erro_classe=%r)" % (
            self.estado, self.malicioso, self.causa, self.erro_classe)


def _caminho_cache():
    cfg = config.carregar()
    destino = os.path.join(config.RAIZ_PROJETO, cfg["diretorio_saida"], "ioc_cache.json")
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    return destino


def _carregar():
    caminho = _caminho_cache()
    if not os.path.exists(caminho):
        return {}
    with open(caminho) as f:
        return json.load(f)


def _modificar(funcao):
    """Ciclo ler-modificar-escrever atomico sob o lock do cache."""
    return modificar_json_com_lock(_caminho_cache(), funcao, padrao={})


def guardar_lote(entradas, mesclar=None):
    """Grava varias entradas num so lock e numa so escrita (tudo ou nada).
    `entradas`: iteravel de (ip, dados, malicioso). `mesclar` (4b-3, opcional):
    callable(entrada_atual_ou_None, dados, malicioso) -> (dados, malicioso),
    chamado SOB O LOCK para cada IP, para preservar proveniencia sem janela
    de corrida; uma excecao dele aborta o lote inteiro. O lote e materializado
    ANTES de adquirir o lock; um unico `verificado_em` por lote; em IPs
    repetidos a ultima entrada ganha; lote vazio nao faz E/S. Devolve o
    numero de entradas recebidas. Levanta sem persistir nada se o cache
    nao puder ser lido ou tiver estrutura invalida."""
    lote = list(entradas)
    if not lote:
        return 0
    agora = datetime.now(timezone.utc).isoformat()
    novas = {}
    for ip, dados, malicioso in lote:
        novas[ip] = {"dados": dados, "malicioso": malicioso, "verificado_em": agora}

    def _aplicar(cache):
        if not isinstance(cache, dict):
            raise ValueError("estrutura do cache de IOC invalida")
        resultado = dict(cache)
        for ip, entrada in novas.items():
            if mesclar is not None:
                atual = cache.get(ip)
                dados_m, mal_m = mesclar(atual if isinstance(atual, dict) else None,
                                         entrada["dados"], entrada["malicioso"])
                entrada = dict(entrada, dados=dados_m, malicioso=mal_m)
            resultado[ip] = entrada
        return resultado

    _modificar(_aplicar)
    return len(lote)


def mesclar_proveniencia(atual, dados, malicioso):
    """Regra de fusao (S1=ii, 4b-3): uma gravacao nunca rebaixa
    malicioso=True para False e nunca perde nem substitui a `fonte` ja
    registada. Campos novos (geo, virustotal...) acrescentam-se/atualizam-se;
    `fonte` fica a primeira registada e `fontes` lista todas (so quando ha
    mais de uma). `atual` None = entrada nova (so aplica os dados novos)."""
    atual_dados = atual.get("dados") if isinstance(atual, dict) else None
    atual_dados = atual_dados if isinstance(atual_dados, dict) else {}
    novo = dict(dados) if isinstance(dados, dict) else {}
    fontes = []

    def _somar(valor):
        if isinstance(valor, str) and valor and valor not in fontes:
            fontes.append(valor)

    anteriores = atual_dados.get("fontes")
    for f in (anteriores if isinstance(anteriores, list) else []):
        _somar(f)
    _somar(atual_dados.get("fonte"))
    _somar(novo.get("fonte"))

    resultado = dict(atual_dados)
    resultado.update({k: v for k, v in novo.items() if k not in ("fonte", "fontes")})
    if "fonte" in atual_dados:
        resultado["fonte"] = atual_dados["fonte"]
    elif "fonte" in novo:
        resultado["fonte"] = novo["fonte"]
    if len(fontes) > 1:
        resultado["fontes"] = fontes
    else:
        resultado.pop("fontes", None)
    anterior_malicioso = isinstance(atual, dict) and atual.get("malicioso") is True
    return resultado, bool(malicioso) or anterior_malicioso


def guardar(ip, dados, malicioso=False):
    guardar_lote([(ip, dados, malicioso)])


def obter(ip, validade_horas=None):
    cache = _carregar()
    entrada = cache.get(ip)
    if not entrada:
        return None
    if validade_horas is None:
        validade_horas = config.carregar().get("ioc_cache_validade_horas", 24)
    verificado_em = datetime.fromisoformat(entrada["verificado_em"])
    idade_horas = (datetime.now(timezone.utc) - verificado_em).total_seconds() / 3600
    if idade_horas > validade_horas:
        return None
    entrada["idade_horas"] = round(idade_horas, 1)
    return entrada


def eh_malicioso_conhecido(ip):
    entrada = obter(ip)
    return bool(entrada and entrada.get("malicioso"))


def _ilegivel(causa, exc=None):
    return ConsultaIoc(ILEGIVEL, None, causa, type(exc).__name__ if exc is not None else None)


def consultar_malicioso(ip):
    """Consulta sem levantar (so Exception e absorvida) e sem alterar
    dados. Distingue ENCONTRADO, AUSENTE, EXPIRADO e ILEGIVEL; em ILEGIVEL
    `causa` e uma das CAUSA_*. Estrito: uma entrada do IP que nao seja um
    dicionario com `malicioso` booleano e `verificado_em` ISO 8601 com fuso
    e ilegivel (corrupcao por entrada afeta so o IP dessa entrada)."""
    try:
        try:
            caminho = _caminho_cache()
            validade = config.carregar().get("ioc_cache_validade_horas", 24)
            if isinstance(validade, bool) or not isinstance(validade, (int, float)) or validade <= 0:
                raise ValueError("validade invalida")
        except Exception as exc:
            return _ilegivel(CAUSA_CONFIGURACAO_INVALIDA, exc)

        try:
            with open(caminho) as f:
                cache = json.load(f)
        except FileNotFoundError:
            return ConsultaIoc(AUSENTE)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return _ilegivel(CAUSA_JSON_INVALIDO, exc)
        except OSError as exc:
            return _ilegivel(CAUSA_ERRO_DE_LEITURA, exc)

        if not isinstance(cache, dict):
            return _ilegivel(CAUSA_ESTRUTURA_INVALIDA)
        if ip not in cache:
            return ConsultaIoc(AUSENTE)

        try:
            entrada = cache[ip]
            malicioso = entrada["malicioso"]
            if not isinstance(malicioso, bool):
                raise ValueError("malicioso nao e booleano")
            verificado_em = datetime.fromisoformat(entrada["verificado_em"])
            idade_horas = (datetime.now(timezone.utc) - verificado_em).total_seconds() / 3600
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
            return _ilegivel(CAUSA_ENTRADA_INVALIDA, exc)

        if idade_horas > validade:
            return ConsultaIoc(EXPIRADO)
        return ConsultaIoc(ENCONTRADO, malicioso)
    except Exception as exc:
        return _ilegivel(CAUSA_ERRO_INESPERADO, exc)
