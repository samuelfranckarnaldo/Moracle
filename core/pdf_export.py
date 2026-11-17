"""
Exportação de relatório forense em PDF — usa o Markdown já gerado
como fonte, evitando duplicar a lógica de montagem de conteúdo.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors


def markdown_simples_para_pdf(texto_markdown, caminho_saida, titulo="Relatório Forense"):
    doc = SimpleDocTemplate(caminho_saida, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    estilo_h1 = ParagraphStyle("H1Custom", parent=styles["Heading1"], spaceAfter=12)
    estilo_h2 = ParagraphStyle("H2Custom", parent=styles["Heading2"], spaceAfter=8)
    estilo_corpo = styles["BodyText"]

    elementos = []
    linhas_tabela_atual = []

    def fechar_tabela():
        nonlocal linhas_tabela_atual
        if linhas_tabela_atual:
            tabela = Table(linhas_tabela_atual, hAlign="LEFT")
            tabela.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0e0e0")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elementos.append(tabela)
            elementos.append(Spacer(1, 12))
            linhas_tabela_atual = []

    for linha in texto_markdown.split("\n"):
        linha_strip = linha.strip()

        if linha_strip.startswith("# "):
            fechar_tabela()
            elementos.append(Paragraph(linha_strip[2:], estilo_h1))
        elif linha_strip.startswith("## "):
            fechar_tabela()
            elementos.append(Paragraph(linha_strip[3:], estilo_h2))
        elif linha_strip.startswith("|") and linha_strip.endswith("|"):
            if set(linha_strip.replace("|", "").replace("-", "").strip()) == set():
                continue  # linha separadora do markdown (|---|---|)
            celulas = [c.strip().replace("`", "") for c in linha_strip.strip("|").split("|")]
            linhas_tabela_atual.append(celulas)
        elif linha_strip.startswith("**") and linha_strip.endswith("**"):
            fechar_tabela()
            elementos.append(Paragraph(f"<b>{linha_strip.strip('*')}</b>", estilo_corpo))
        elif linha_strip:
            fechar_tabela()
            elementos.append(Paragraph(linha_strip, estilo_corpo))
        else:
            fechar_tabela()
            elementos.append(Spacer(1, 6))

    fechar_tabela()
    doc.build(elementos)
    return caminho_saida
