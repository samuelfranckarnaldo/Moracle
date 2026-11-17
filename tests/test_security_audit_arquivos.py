"""Passo 3a - destino JSONL: durabilidade, modo 0600, concorrencia (criterio 8)."""
import json
import multiprocessing
import os
import stat
import threading

import pytest

from core import security_audit as sa


def _ev(i):
    return sa.novo_evento("t.evento", "ok", payload={"i": i})


def _modo(caminho):
    return stat.S_IMODE(os.stat(caminho).st_mode)


def test_gravar_devolve_true_cria_arquivo_0600_e_uma_linha_json(tmp_path):
    d = sa.DestinoJsonl(str(tmp_path / "sub" / "eventos.jsonl"))
    ev = _ev(1)
    assert d.gravar(ev) is True
    caminho = d.caminho()
    assert _modo(caminho) == 0o600
    linhas = open(caminho, encoding="utf-8").read().splitlines()
    assert len(linhas) == 1 and json.loads(linhas[0])["event_id"] == ev["event_id"]
    assert _modo(os.path.dirname(caminho)) == 0o700


def test_arquivo_existente_com_modo_aberto_e_corrigido_para_0600(tmp_path):
    caminho = str(tmp_path / "e.jsonl")
    open(caminho, "w").close()
    os.chmod(caminho, 0o666)
    assert sa.DestinoJsonl(caminho).gravar(_ev(1)) is True
    assert _modo(caminho) == 0o600


def test_gravar_so_confirma_depois_de_fsync(tmp_path, monkeypatch):
    ordem = []
    real_fsync = os.fsync
    real_write = os.write

    def fsync(fd):
        ordem.append("fsync")
        return real_fsync(fd)

    def write(fd, dados):
        ordem.append("write")
        return real_write(fd, dados)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "write", write)
    d = sa.DestinoJsonl(str(tmp_path / "e.jsonl"))
    assert d.gravar(_ev(1)) is True
    assert "write" in ordem and "fsync" in ordem
    assert ordem.index("write") < ordem.index("fsync")


def test_falha_de_fsync_nao_confirma_e_nao_levanta(tmp_path, monkeypatch):
    def fsync(fd):
        raise OSError("disco")
    monkeypatch.setattr(os, "fsync", fsync)
    d = sa.DestinoJsonl(str(tmp_path / "e.jsonl"))
    assert d.gravar(_ev(1)) is False
    assert d.ultimo_erro == "OSError"


def test_gravar_nunca_levanta_diretorio_impossivel_ou_evento_invalido(tmp_path):
    bloqueio = tmp_path / "arquivo"
    bloqueio.write_text("x")
    d = sa.DestinoJsonl(str(bloqueio / "dentro" / "e.jsonl"))  # pai e arquivo, nao diretorio
    assert d.gravar(_ev(1)) is False
    d2 = sa.DestinoJsonl(str(tmp_path / "ok.jsonl"))
    assert d2.gravar({"x": object()}) is False
    assert d2.gravar({"x": float("nan")}) is False


def test_caminho_pode_ser_callable_resolvido_a_cada_uso(tmp_path):
    alvo = {"p": str(tmp_path / "a.jsonl")}
    d = sa.DestinoJsonl(lambda: alvo["p"])
    d.gravar(_ev(1))
    alvo["p"] = str(tmp_path / "b.jsonl")
    d.gravar(_ev(2))
    assert os.path.exists(tmp_path / "a.jsonl") and os.path.exists(tmp_path / "b.jsonl")


def test_linha_truncada_anterior_e_isolada_na_proxima_escrita(tmp_path):
    caminho = str(tmp_path / "e.jsonl")
    d = sa.DestinoJsonl(caminho)
    d.gravar(_ev(1))
    with open(caminho, "ab") as f:
        f.write(b'{"event_id": "truncado", "x"')  # sem \n final: escrita interrompida
    ev = _ev(3)
    assert d.gravar(ev) is True
    validos = d.ler_eventos()
    ids = [e["event_id"] for e in validos]
    assert ev["event_id"] in ids and "truncado" not in ids
    assert len(validos) == 2  # a linha truncada nao contaminou a nova


def test_concorrencia_entre_threads_sem_linhas_corrompidas(tmp_path):
    d = sa.DestinoJsonl(str(tmp_path / "e.jsonl"))
    erros = []

    def trabalho(base):
        for i in range(40):
            if not d.gravar(_ev(base * 1000 + i)):
                erros.append((base, i))

    ts = [threading.Thread(target=trabalho, args=(b,)) for b in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert erros == []
    linhas = open(d.caminho(), encoding="utf-8").read().splitlines()
    assert len(linhas) == 8 * 40
    ids = {json.loads(l)["event_id"] for l in linhas}  # todas parseiam
    assert len(ids) == 8 * 40


def _filho(caminho, base):
    d = sa.DestinoJsonl(caminho)
    for i in range(25):
        assert d.gravar(sa.novo_evento("t.proc", "ok", payload={"i": base * 100 + i}))


def test_concorrencia_entre_processos_sem_linhas_corrompidas(tmp_path):
    caminho = str(tmp_path / "e.jsonl")
    ctx = multiprocessing.get_context("fork")
    ps = [ctx.Process(target=_filho, args=(caminho, b)) for b in range(4)]
    [p.start() for p in ps]
    [p.join(60) for p in ps]
    assert all(p.exitcode == 0 for p in ps)
    linhas = open(caminho, encoding="utf-8").read().splitlines()
    assert len(linhas) == 100
    assert len({json.loads(l)["event_id"] for l in linhas}) == 100
    assert _modo(caminho) == 0o600


def test_validar_caminhos_exige_principal_e_fila_distintos(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    isolar_config(monkeypatch, tmp_path)
    principal, fila = sa.validar_caminhos()
    assert principal != fila and os.path.dirname(principal) != os.path.dirname(fila)

    isolar_config(monkeypatch, tmp_path, auditoria={
        "arquivo_eventos": ".state/q/fila_eventos.jsonl", "diretorio_fila": ".state/q"})
    with pytest.raises(sa.ErroDeConfiguracaoAudit):
        sa.validar_caminhos()

    isolar_config(monkeypatch, tmp_path, auditoria={
        "arquivo_eventos": ".state/q/eventos.jsonl", "diretorio_fila": ".state/q"})
    with pytest.raises(sa.ErroDeConfiguracaoAudit):  # mesmo diretorio
        sa.validar_caminhos()

    for ruim in ("", "   ", None, 5):
        isolar_config(monkeypatch, tmp_path, auditoria={
            "arquivo_eventos": ruim, "diretorio_fila": ".state/q"})
        with pytest.raises(sa.ErroDeConfiguracaoAudit):
            sa.validar_caminhos()


def test_caminho_absoluto_de_outro_volume_e_respeitado(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    outro = tmp_path / "outro_volume"
    isolar_config(monkeypatch, tmp_path, auditoria={
        "arquivo_eventos": ".state/eventos.jsonl", "diretorio_fila": str(outro)})
    assert sa.caminho_fila() == str(outro / "fila_eventos.jsonl")
    sa.validar_caminhos()


def test_criar_auditor_padrao_grava_no_estado_isolado(tmp_path, monkeypatch):
    from tests.helpers.audit_fakes import isolar_config
    isolar_config(monkeypatch, tmp_path)
    auditor = sa.criar_auditor_padrao()
    assert auditor.emitir(_ev(1), "humano") == "principal"
    assert os.path.exists(tmp_path / ".state" / "security_events.jsonl")
