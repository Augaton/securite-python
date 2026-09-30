import argparse
import os
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report


# Extensions des fichiers de capture, pour reconnaître le fichier à analyser parmi les arguments
PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def find_pcap_file(candidates: list[str]) -> str | None:
    """
    Retrouve le fichier de capture parmi les arguments : de préférence un fichier .pcap existant,
    sinon le premier fichier existant

    :param candidates: arguments qui peuvent désigner le fichier
    :return: chemin du fichier, None si aucun argument n'est un fichier
    """
    files = [candidate for candidate in candidates if Path(candidate).is_file()]
    captures = [file for file in files if file.lower().endswith(PCAP_EXTENSIONS)]
    return next(iter(captures + files), None)


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande. Le fichier pcap se donne directement
    (python src/tp1/main.py capture.pcap), avec --pcap ou avec -r. Une option inconnue est ignorée avec
    un avertissement au lieu d'arrêter le programme (lancement par un script de correction par exemple)

    :param arguments: options à lire, None pour celles passées au programme
    :return: options (timeout et pcap)
    """
    parser = argparse.ArgumentParser(description="TP1 : capture réseau, détection d'attaques et rapport")
    parser.add_argument("pcap_file", nargs="?", help="fichier pcap à analyser (comme --pcap)")
    parser.add_argument(
        "--pcap", "-r", help="analyser un fichier pcap au lieu d'écouter le réseau (sans root)"
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"durée de la capture en secondes (défaut : {TIMEOUT})"
    )
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
    # les rapports contiennent le marqueur unique du binôme et les adresses du réseau : ils ne sont
    # lisibles que par leur propriétaire (droits 600), pas par les autres comptes de la machine
    os.umask(0o077)
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
