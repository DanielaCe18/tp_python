from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report
from src.tp1.utils.lib import choose_interface


def main():
    logger.info("=== DÉMARRAGE TP1 : IDS/IPS MAISON ===")

    iface = choose_interface()
    if not iface:
        logger.error("Aucune interface sélectionnée. Arrêt du programme.")
        return

    capture = Capture(iface=iface, timeout=60)
    logger.info(f"Lancement de la capture sur l'interface : {iface}")
    capture.capture_trafic()
    capture.analyse("tcp")

    summary = capture.get_summary()

    logger.info(f"Nombre de paquets capturés : {summary['packet_count']}")
    logger.info(f"Protocoles détectés : {summary['protocols']}")

    if summary["attacks"]:
        logger.warning(f"{len(summary['attacks'])} attaque(s) détectée(s) !")
        for attack in summary["attacks"]:
            logger.warning(f"[{attack['type']}] {attack['description']}")
    else:
        logger.info("Aucune attaque détectée. ✅")

    # Génération d’un résumé textuel
    summary_text = f"Nombre total de paquets : {summary['packet_count']}\n"
    summary_text += "\nProtocoles détectés :\n"
    for proto, count in summary["protocols"].items():
        summary_text += f" - {proto} : {count} paquets\n"

    summary_text += "\nTop ports utilisés :\n"
    for port, count in summary.get("top_ports", []):
        summary_text += f" - Port {port} : {count} fois\n"

    summary_text += "\nTop IPs émettrices :\n"
    for ip, count in summary.get("top_ips", []):
        summary_text += f" - {ip} : {count} paquets\n"

    summary_text += "\nAttaques détectées :\n"
    if summary["attacks"]:
        for attack in summary["attacks"]:
            summary_text += f" - [{attack['type']}] {attack['description']}\n"
    else:
        summary_text += " - Aucune attaque détectée ✅\n"

    # Génération du rapport
    filename = "report.pdf"
    report = Report(capture, filename, summary, summary_text)
    report.generate("graph")
    report.generate("array")

    logger.info(f"✅ Rapport PDF généré : {filename}")


if __name__ == "__main__":
    main()
