"""
Testes do query engine de Access Log Estruturado: filtros, ordenacao,
paginacao por cursor opaco, total_matched.
"""
import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.access_log_query import buscar


@pytest.fixture
def arquivo_com_registros():
    fd, caminho = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)

    registros = [
        dict(request_id="r1", timestamp="2026-09-01T10:00:00Z", remote_address="1.1.1.1",
             method="GET", path="/api/a", protocol_version="HTTP/1.1", status=200,
             bytes_sent=10, latency_ms=1.0, app_name="app_a"),
        dict(request_id="r2", timestamp="2026-09-01T10:00:05Z", remote_address="1.1.1.1",
             method="POST", path="/api/b", protocol_version="HTTP/1.1", status=500,
             bytes_sent=20, latency_ms=2.0, app_name="app_a"),
        dict(request_id="r3", timestamp="2026-09-01T10:00:10Z", remote_address="1.1.1.1",
             method="GET", path="/api/c", protocol_version="HTTP/1.1", status=200,
             bytes_sent=30, latency_ms=3.0, app_name="app_b"),
        dict(request_id="r4", timestamp="2026-09-02T10:00:00Z", remote_address="1.1.1.1",
             method="GET", path="/api/admin/x", protocol_version="HTTP/1.1", status=404,
             bytes_sent=40, latency_ms=4.0, app_name=""),
    ]
    with open(caminho, "w", encoding="utf-8") as f:
        for r in registros:
            f.write(json.dumps(r) + "\n")

    yield caminho
    os.remove(caminho)


def test_arquivo_inexistente_retorna_vazio():
    records, next_cursor, total = buscar("/tmp/nao-existe-jamais.jsonl")
    assert records == []
    assert next_cursor is None
    assert total == 0


def test_sem_filtros_retorna_tudo_ordenado_mais_recente_primeiro(arquivo_com_registros):
    records, next_cursor, total = buscar(arquivo_com_registros)
    assert total == 4
    assert [r["request_id"] for r in records] == ["r4", "r3", "r2", "r1"]
    assert next_cursor is None


def test_filtro_app_name(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, app_name="app_a")
    assert total == 2
    assert {r["request_id"] for r in records} == {"r1", "r2"}


def test_filtro_status(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, status=500)
    assert total == 1
    assert records[0]["request_id"] == "r2"


def test_filtro_method(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, method="POST")
    assert total == 1
    assert records[0]["request_id"] == "r2"


def test_filtro_path_contains_substring(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, path_contains="/admin/")
    assert total == 1
    assert records[0]["request_id"] == "r4"


def test_from_inclusivo(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, from_ts="2026-09-01T10:00:05Z")
    assert total == 3
    assert {r["request_id"] for r in records} == {"r2", "r3", "r4"}


def test_to_exclusivo(arquivo_com_registros):
    records, _, total = buscar(arquivo_com_registros, to_ts="2026-09-01T10:00:10Z")
    assert total == 2
    assert {r["request_id"] for r in records} == {"r1", "r2"}


def test_from_e_to_juntos_janela_fechada(arquivo_com_registros):
    records, _, total = buscar(
        arquivo_com_registros,
        from_ts="2026-09-01T10:00:00Z", to_ts="2026-09-01T10:00:10Z",
    )
    assert total == 2
    assert {r["request_id"] for r in records} == {"r1", "r2"}


def test_paginacao_com_cursor_opaco(arquivo_com_registros):
    pagina1, cursor1, total = buscar(arquivo_com_registros, limit=2)
    assert total == 4
    assert [r["request_id"] for r in pagina1] == ["r4", "r3"]
    assert cursor1 is not None

    pagina2, cursor2, total2 = buscar(arquivo_com_registros, limit=2, cursor=cursor1)
    assert total2 == 4
    assert [r["request_id"] for r in pagina2] == ["r2", "r1"]
    assert cursor2 is None  # ultima pagina


def test_cursor_invalido_nao_quebra_cai_no_inicio(arquivo_com_registros):
    """Cliente nunca deveria construir cursor manualmente, mas se um
    valor invalido chegar, o sistema nao pode quebrar - trata como
    offset zero em vez de levantar excecao."""
    records, _, total = buscar(arquivo_com_registros, cursor="isso-nao-e-um-cursor-valido")
    assert total == 4
    assert len(records) == 4  # comporta-se como se nao houvesse cursor


def test_limit_clamped_entre_1_e_5000(arquivo_com_registros):
    records, _, _ = buscar(arquivo_com_registros, limit=0)
    assert len(records) == 1  # clamped para minimo 1

    records, _, _ = buscar(arquivo_com_registros, limit=99999)
    assert len(records) == 4  # nao ha mais que 4 registros de qualquer forma


def test_linhas_corrompidas_sao_ignoradas():
    fd, caminho = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    with open(caminho, "w", encoding="utf-8") as f:
        f.write('{"request_id": "valido", "timestamp": "2026-09-01T10:00:00Z", "app_name": ""}\n')
        f.write("isso nao e json valido\n")
        f.write("\n")  # linha vazia
        f.write('{"request_id": "valido2", "timestamp": "2026-09-01T10:00:01Z", "app_name": ""}\n')

    try:
        records, _, total = buscar(caminho)
        assert total == 2
        assert {r["request_id"] for r in records} == {"valido", "valido2"}
    finally:
        os.remove(caminho)
