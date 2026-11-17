"""
Query engine do Access Log Estruturado - le ~/.state/access_log.jsonl
por completo e aplica filtros em memoria.

Contrato (aprovado na spec de Access Log Estruturado):
- from inclusivo, to exclusivo (from <= timestamp < to)
- ordenacao: mais recente -> mais antigo
- cursor: opaco, emitido e interpretado so por este modulo - o
  cliente nunca constroi nem interpreta sua estrutura interna, so
  reutiliza o next_cursor retornado
- total_matched: quantidade de registros que satisfazem os filtros,
  exige leitura completa do arquivo (full-scan, nao e' barato)
- escopo desta versao: le apenas o arquivo ativo (access_log.jsonl).
  Arquivos rotacionados/arquivados NAO entram na busca - decisao
  explicita, fora de escopo ate autorizacao futura.

Limitacao conhecida: timestamp tem precisao de segundo (contrato ja
fechado em server/access_log.py). Registros gravados no mesmo segundo
mantem a ordem de escrita entre si (mais antigo primeiro dentro do
empate), nao ordem de mais-recente-primeiro estrita.
"""
import base64
import json
import os


def _decode_cursor(cursor):
    if cursor is None:
        return 0
    try:
        dados = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
        offset = dados.get("offset", 0)
        if not isinstance(offset, int) or offset < 0:
            return 0
        return offset
    except Exception:
        return 0


def _encode_cursor(offset):
    dados = json.dumps({"offset": offset}).encode()
    return base64.urlsafe_b64encode(dados).decode()


def _ler_registros(caminho):
    if not os.path.exists(caminho):
        return []
    registros = []
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            try:
                registros.append(json.loads(linha))
            except json.JSONDecodeError:
                continue
    return registros


def _aplicar_filtros(registros, app_name, from_ts, to_ts, status, method, path_contains):
    resultado = []
    for r in registros:
        if app_name and r.get("app_name") != app_name:
            continue
        ts = r.get("timestamp", "")
        if from_ts and ts < from_ts:
            continue
        if to_ts and ts >= to_ts:
            continue
        if status is not None and r.get("status") != status:
            continue
        if method and r.get("method") != method:
            continue
        if path_contains and path_contains not in r.get("path", ""):
            continue
        resultado.append(r)
    return resultado


def buscar(caminho_jsonl, app_name=None, from_ts=None, to_ts=None,
           status=None, method=None, path_contains=None, limit=500, cursor=None):
    """Retorna (records: list[dict], next_cursor: str|None, total_matched: int).

    path_contains e' substring simples (str.find via 'in') - nunca
    regex vinda do cliente, por design.
    """
    limit = max(1, min(int(limit), 5000))

    todos = _ler_registros(caminho_jsonl)
    filtrados = _aplicar_filtros(
        todos, app_name=app_name, from_ts=from_ts, to_ts=to_ts,
        status=status, method=method, path_contains=path_contains,
    )
    filtrados.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

    total_matched = len(filtrados)
    offset = _decode_cursor(cursor)

    pagina = filtrados[offset:offset + limit]
    proximo_offset = offset + len(pagina)
    next_cursor = _encode_cursor(proximo_offset) if proximo_offset < total_matched else None

    return pagina, next_cursor, total_matched
