"""
Geração de relatórios forenses.
"""

import json
import os
from datetime import datetime

class ForensicsReport:
    """Gera relatórios forenses em diferentes formatos."""
    
    def __init__(self, title="Relatório Forense"):
        self.title = title
        self.sections = []
        self.metadata = {
            "created": datetime.now().isoformat(),
            "author": "Xeera Forensics"
        }
    
    def add_section(self, title, content):
        """Adiciona uma secção ao relatório."""
        self.sections.append({
            "title": title,
            "content": content
        })
    
    def add_finding(self, finding):
        """Adiciona um achado forense."""
        if "findings" not in [s["title"] for s in self.sections]:
            self.add_section("findings", [])
        for section in self.sections:
            if section["title"] == "findings":
                section["content"].append(finding)
    
    def to_json(self):
        """Exporta para JSON."""
        return json.dumps({
            "metadata": self.metadata,
            "title": self.title,
            "sections": self.sections
        }, indent=2)
    
    def to_markdown(self):
        """Exporta para Markdown."""
        lines = [
            f"# {self.title}",
            "",
            f"**Criado:** {self.metadata['created']}",
            f"**Autor:** {self.metadata['author']}",
            "",
            "---",
            ""
        ]
        
        for section in self.sections:
            lines.append(f"## {section['title'].upper()}")
            lines.append("")
            
            content = section["content"]
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        lines.append(f"- **{item.get('title', 'Item')}**")
                        for key, value in item.items():
                            if key != "title":
                                lines.append(f"  - {key}: {value}")
                        lines.append("")
                    elif isinstance(item, str):
                        lines.append(f"- {item}")
                    else:
                        lines.append(str(item))
            elif isinstance(content, dict):
                for key, value in content.items():
                    lines.append(f"- **{key}:** {value}")
                lines.append("")
            else:
                lines.append(str(content))
                lines.append("")
        
        return "\n".join(lines)
    
    def save(self, filename, format="markdown"):
        """Guarda o relatório num ficheiro."""
        if format == "json":
            content = self.to_json()
        else:
            content = self.to_markdown()
        
        with open(filename, 'w') as f:
            f.write(content)
        
        return filename
