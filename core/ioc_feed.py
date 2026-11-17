"""
Import de feeds públicos de IOC (formato texto simples, um IP por linha,
ou CSV com IP na primeira coluna) para popular o cache local sem depender
só de consultas pontuais a APIs externas.
"""
import csv
import ipaddress
import re
from core import ioc_cache

IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

_REDES_INTERNAS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def ip_importavel(texto):
    """4b-3: IPv4 valido e NAO interno. Rejeita octetos fora de 0-255,
    loopback, nao especificado, link-local, multicast, reservado e redes
    privadas (um feed nao pode levar a defesa a bloquear a rede local).
    As faixas de documentacao (203.0.113.0/24 etc.) sao aceites. Devolve o
    texto normalizado ou None."""
    if not isinstance(texto, str) or not IP_RE.match(texto):
        return None
    try:
        ip = ipaddress.IPv4Address(texto)
    except ValueError:
        return None
    if (ip.is_loopback or ip.is_unspecified or ip.is_link_local
            or ip.is_multicast or ip.is_reserved
            or any(ip in rede for rede in _REDES_INTERNAS)):
        return None
    return str(ip)


def ler_candidatos(caminho, nome_fonte="feed_importado"):
    """Le e classifica o ficheiro SEM escrever nada. Devolve
    (candidatos, ignorados): candidatos = [(ip, {"fonte": nome_fonte}, True)].
    Regras de leitura (inalteradas): um IP por linha ou CSV com IP na 1a
    coluna, decidido pela 1a linha; contagens por linha (nao por IP unico).
    4b-3: so IPv4 validos e nao internos (ver ip_importavel)."""
    candidatos = []
    ignorados = 0

    with open(caminho, encoding="utf-8", errors="ignore") as f:
        primeira_linha = f.readline()
        f.seek(0)
        eh_csv = "," in primeira_linha

        if eh_csv:
            for linha in csv.reader(f):
                if not linha:
                    continue
                ip = ip_importavel(linha[0].strip())
                if ip:
                    candidatos.append((ip, {"fonte": nome_fonte}, True))
                else:
                    ignorados += 1
        else:
            for linha in f:
                texto = linha.strip()
                if not texto or texto.startswith("#"):
                    continue
                ip = ip_importavel(texto)
                if ip:
                    candidatos.append((ip, {"fonte": nome_fonte}, True))
                else:
                    ignorados += 1
    return candidatos, ignorados


def importar_arquivo(caminho, nome_fonte="feed_importado"):
    """Le um ficheiro de IOCs e grava tudo de uma vez (lote atomico sob lock;
    se a leitura ou a escrita falhar, nada e persistido). 4b-3: preserva a
    proveniencia de entradas existentes (ioc_cache.mesclar_proveniencia) e
    nunca rebaixa malicioso=True. NAO verifica autorizacao nem emite evento:
    a CLI usa core.ioc_security.executar_ioc_import, que o faz."""
    candidatos, ignorados = ler_candidatos(caminho, nome_fonte)
    importados = ioc_cache.guardar_lote(candidatos, mesclar=ioc_cache.mesclar_proveniencia)
    return {"importados": importados, "ignorados": ignorados}
