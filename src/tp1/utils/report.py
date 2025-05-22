import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pygal
from pygal.style import LightColorizedStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from xml.sax.saxutils import escape
import os

from src.tp1.utils.config import logger


class Report:
    def __init__(self, capture, filename: str, summary: dict, summary_text: str = ""):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport IDS/IPS - TP1"
        self.summary = summary
        self.summary_text = summary_text
        self.graph_image_path = "protocol_distribution_graph.png"
        self.graph_svg_path = "protocols_chart.svg"
        self.protocol_data_for_table = []

    def generate(self, type_):
        if type_ == "graph":
            self._generate_protocol_graph()    # PNG for PDF
            self._generate_svg_graph()         # Interactive SVG
        elif type_ == "array":
            self.save()

    def _generate_protocol_graph(self):
        protocols = self.summary.get("protocols", {})
        if not protocols:
            logger.warning("Aucun protocole détecté, graphique PNG non généré.")
            self.graph_image_path = None
            return

        try:
            plt.figure(figsize=(10, 6))
            bars = plt.bar(protocols.keys(), protocols.values(),
                           color=['skyblue', 'lightcoral', 'lightgreen', 'gold', 'lightsalmon', 'cyan', 'violet'])
            plt.xlabel("Protocole")
            plt.ylabel("Nombre de paquets")
            plt.title("Distribution des protocoles")
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.bar_label(bars, fmt='%d')
            plt.savefig(self.graph_image_path)
            plt.close()
            logger.info(f"✅ Graphique PNG sauvegardé : {self.graph_image_path}")
        except Exception as e:
            logger.error(f"❌ Erreur PNG : {e}")
            self.graph_image_path = None

    def _generate_svg_graph(self):
        protocols = self.summary.get("protocols", {})
        if not protocols:
            logger.warning("Aucun protocole détecté, SVG non généré.")
            return

        try:
            chart = pygal.HorizontalBar(style=LightColorizedStyle)
            chart.title = 'Distribution des protocoles réseau'
            for proto, count in protocols.items():
                chart.add(proto, count)
            chart.render_to_file(self.graph_svg_path)
            logger.info(f"✅ Graphique SVG enregistré : {self.graph_svg_path}")
        except Exception as e:
            logger.error(f"❌ Erreur SVG : {e}")

    def _prepare_protocol_table_data(self):
        protocol_counts = self.summary.get("protocols", {})
        self.protocol_data_for_table = [["Protocole", "Nombre de paquets"]]
        for proto, count in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True):
            self.protocol_data_for_table.append([proto, str(count)])

    def save(self):
        self._prepare_protocol_table_data()

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=(8.5 * inch, 11 * inch),
            topMargin=0.5 * inch, bottomMargin=0.5 * inch,
            leftMargin=0.75 * inch, rightMargin=0.75 * inch
        )

        styles = getSampleStyleSheet()
        story = []

        # Titre
        title_style = styles["Title"]
        title_style.alignment = TA_CENTER
        story.append(Paragraph(self.title, title_style))
        story.append(Spacer(1, 0.3 * inch))

        # Résumé
        story.append(Paragraph("<b>I. Résumé de l'analyse</b>", styles["Heading2"]))
        summary_style = ParagraphStyle('summaryBody', parent=styles['Normal'], spaceBefore=6, leading=14)
        summary_text_html = escape(self.summary_text).replace("\n", "<br/>")
        story.append(Paragraph(summary_text_html, summary_style))
        story.append(Spacer(1, 0.3 * inch))

        # Tableau protocoles
        story.append(Paragraph("<b>II. Statistiques de protocoles</b>", styles["Heading2"]))
        if self.protocol_data_for_table and len(self.protocol_data_for_table) > 1:
            table = Table(self.protocol_data_for_table, colWidths=[3 * inch, 2 * inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F81BD")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#DCE6F1")),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#7F7F7F")),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("Aucune donnée de protocole disponible.", summary_style))
        story.append(Spacer(1, 0.3 * inch))

        # Graphique
        story.append(Paragraph("<b>III. Graphique des protocoles</b>", styles["Heading2"]))
        if self.graph_image_path and os.path.exists(self.graph_image_path):
            story.append(Paragraph("Répartition visuelle des protocoles capturés.", summary_style))
            story.append(Spacer(1, 0.2 * inch))
            try:
                img = Image(self.graph_image_path, width=6.5 * inch, height=3.5 * inch)
                story.append(img)
            except Exception as e:
                logger.error(f"Erreur insertion image : {e}")
                story.append(Paragraph(f"[Erreur graphique : {e}]", styles["Normal"]))
        else:
            story.append(Paragraph("Le graphique PNG n’a pas pu être généré.", summary_style))

        try:
            doc.build(story)
            logger.info(f"✅ Rapport PDF généré : {self.filename}")
        except Exception as e:
            logger.error(f"❌ Échec PDF : {e}")
            fallback = self.filename.replace(".pdf", "_fallback.txt")
            try:
                with open(fallback, "w") as f:
                    f.write(f"Titre : {self.title}\n\n")
                    f.write(self.summary_text)
                logger.info(f"✅ Fallback texte généré : {fallback}")
            except Exception as fe:
                logger.error(f"❌ Échec fallback texte : {fe}")
