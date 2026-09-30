import argparse
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande

    :param arguments: options à lire, None pour celles passées au programme
    :return: options (timeout et pcap)
    """
    parser = argparse.ArgumentParser(description="TP1 : capture réseau, détection d'attaques et rapport")
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"durée de la capture en secondes (défaut : {TIMEOUT})"
    )
    parser.add_argument(
        "--pcap", help="analyser un fichier pcap au lieu d'écouter le réseau (pas besoin de root)"
    )
    options = parser.parse_args(arguments)
    if options.timeout <= 0:
        parser.error("la durée de la capture doit être positive")
    if options.pcap is not None and not Path(options.pcap).is_file():
        parser.error(f"fichier introuvable : {options.pcap}")
    return options


def main(arguments: list[str] | None = None):
    logger.info("Starting TP1")
    options = parse_arguments(arguments)

    capture = Capture(options.pcap, options.timeout)
    try:
        capture.open_socket()
    except PermissionError:
        # scapy a besoin d'être root pour écouter une interface, et root ne connait pas poetry :
        # on donne le chemin complet du script à relancer avec sudo
        tp1_script = Path(sys.executable).parent / "tp1"
        logger.error(f"Pas les droits pour capturer les paquets, relancer avec : sudo {tp1_script}")
        return
    drop_privileges()

    capture.capture_traffic()
    capture.analyse()
    summary = capture.get_summary()
    logger.info(summary)

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)
    report.save_json("report.json")


if __name__ == "__main__":
    main()
