import argparse
import os
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def find_pcap_file(candidates: list[str]) -> str | None:
    files = [candidate for candidate in candidates if Path(candidate).is_file()]
    captures = [file for file in files if file.lower().endswith(PCAP_EXTENSIONS)]
    return next(iter(captures + files), None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP1 : capture réseau, détection d'attaques et rapport")
    parser.add_argument("pcap_file", nargs="?", help="fichier pcap à analyser (comme --pcap)")
    parser.add_argument(
        "--pcap", "-r", help="analyser un fichier pcap au lieu d'écouter le réseau (sans root)"
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"durée de la capture en secondes (défaut : {TIMEOUT})"
    )
    return parser


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    options, unknown_arguments = parser.parse_known_args(arguments)
    explicit_pcap = options.pcap
    candidates = [argument for argument in (options.pcap, options.pcap_file, *unknown_arguments) if argument]
    options.pcap = find_pcap_file(candidates)
    # un argument direct qui n'est pas un fichier est sûrement la valeur d'une option inconnue
    ignored_arguments = [
        arg for arg in (*unknown_arguments, options.pcap_file) if arg and arg != options.pcap
    ]
    if ignored_arguments:
        logger.warning(f"Arguments inconnus ignorés : {' '.join(ignored_arguments)}")
    if options.timeout <= 0:
        parser.error("la durée de la capture doit être positive")
    if explicit_pcap is not None and options.pcap is None:
        parser.error(f"fichier introuvable : {explicit_pcap}")
    return options


def main(arguments: list[str] | None = None):
    logger.info("Starting TP1")
    options = parse_arguments(arguments)

    capture = Capture(options.pcap, options.timeout)
    try:
        capture.open_socket()
    except PermissionError:
        # root ne connait pas poetry : on donne le chemin complet du script
        tp1_script = Path(sys.executable).parent / "tp1"
        logger.error(f"Pas les droits pour capturer les paquets, relancer avec : sudo {tp1_script}")
        return
    drop_privileges()

    capture.capture_traffic()
    capture.analyse()
    summary = capture.get_summary()
    logger.info(summary)

    # écrire les rapports à côté du pcap analysé (là où le correcteur les récupère)
    if options.pcap:
        os.chdir(Path(options.pcap).resolve().parent)

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)
    report.save_json("report.json")


if __name__ == "__main__":
    main()
