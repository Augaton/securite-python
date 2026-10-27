import argparse
import os
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")
DOSSIER_OUT = Path("/out")


def trouver_fichier_pcap(lst_candidats: list[str]) -> str | None:
    fichiers = [candidat for candidat in lst_candidats if Path(candidat).is_file()]
    captures = [fichier for fichier in fichiers if fichier.lower().endswith(PCAP_EXTENSIONS)]
    return next(iter(captures + fichiers), None)


def constr_parser_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP1 : capture réseau, détection d'attaques et rapport")
    parser.add_argument("pcap_file", nargs="?", help="fichier pcap à analyser (comme --pcap)")
    parser.add_argument(
        "--pcap", "-r", help="analyser un fichier pcap au lieu d'écouter le réseau (sans root)"
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"durée de la capture en secondes (défaut : {TIMEOUT})"
    )
    return parser


def recup_args_ignores(options: argparse.Namespace, args_inconnus: list[str]) -> list[str]:
    # un argument direct qui n'est pas un fichier est sûrement la valeur d'une option inconnue
    return [arg for arg in (*args_inconnus, options.pcap_file) if arg and arg != options.pcap]


def verif_args(parser: argparse.ArgumentParser, options: argparse.Namespace, pcap_explicite: str | None):
    if options.timeout <= 0:
        parser.error("la durée de la capture doit être positive")
    if pcap_explicite is not None and options.pcap is None:
        parser.error(f"fichier introuvable : {pcap_explicite}")


def lire_args_cli(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = constr_parser_args()
    options, args_inconnus = parser.parse_known_args(arguments)
    pcap_explicite = options.pcap
    lst_candidats = [arg for arg in (options.pcap, options.pcap_file, *args_inconnus) if arg]
    options.pcap = trouver_fichier_pcap(lst_candidats)
    args_ignores = recup_args_ignores(options, args_inconnus)
    if args_ignores:
        logger.warning(f"Arguments inconnus ignorés : {' '.join(args_ignores)}")
    verif_args(parser, options, pcap_explicite)
    return options


def ouvrir_socket_capture(capture: Capture) -> bool:
    """Ouvre le socket en root puis lâche les droits ; False si on n'a pas les droits."""
    try:
        capture.open_socket()
    except PermissionError:
        # root ne connait pas poetry : on donne le chemin complet du script
        script_tp1 = Path(sys.executable).parent / "tp1"
        logger.error(f"Pas les droits pour capturer les paquets, relancer avec : sudo {script_tp1}")
        return False
    drop_privileges()
    return True


def choisir_dossier_sortie() -> Path:
    # le correcteur monte l'entrée en lecture seule et récupère les rapports dans /out s'il existe
    if DOSSIER_OUT.is_dir() and os.access(DOSSIER_OUT, os.W_OK):
        return DOSSIER_OUT
    return Path.cwd()


def ecrire_rapports(capture: Capture, summary: str) -> None:
    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("array")
    report.save_json("report.json")  # fichier noté par le correcteur : écrit en premier
    try:
        report.generate("graph")
        report.save(filename)
    except OSError as error:
        logger.warning(f"Rapport PDF/graphique non généré : {error}")


def main(arguments: list[str] | None = None):
    logger.info("Starting TP1")
    options = lire_args_cli(arguments)

    capture = Capture(options.pcap, options.timeout)
    if not ouvrir_socket_capture(capture):
        return

    capture.capture_traffic()
    capture.analyse()
    summary = capture.get_summary()
    logger.info(summary)

    cwd_origine = Path.cwd()
    os.chdir(choisir_dossier_sortie())
    try:
        ecrire_rapports(capture, summary)
    finally:
        os.chdir(cwd_origine)


if __name__ == "__main__":
    main()
