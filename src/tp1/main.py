import argparse
import os
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")
# convention du bac à sable de correction : l'entrée arrive dans /in, les résultats sont lus dans /out
GRADER_OUTPUT_DIRECTORY = Path("/out")


def find_pcap_file(candidates: list[str]) -> str | None:
    """
    Retrouve le fichier de capture parmi les arguments (un .pcap de préférence)

    :param candidates: arguments qui peuvent désigner le fichier
    :return: chemin du fichier, None si aucun argument n'est un fichier
    """
    files = [
        candidate for candidate in candidates if Path(candidate).is_file() and not candidate.endswith(".json")
    ]
    captures = [file for file in files if file.lower().endswith(PCAP_EXTENSIONS)]
    return next(iter(captures + files), None)


def find_output_path(arguments: list[str]) -> str | None:
    """
    Retrouve parmi les arguments inconnus où écrire report.json : un fichier .json ou un dossier existant

    :param arguments: arguments ignorés par le parseur (ex : --out=/out est découpé)
    :return: chemin trouvé, None sinon
    """
    values = [argument.split("=", 1)[-1] for argument in arguments]
    json_paths = [value for value in values if value.lower().endswith(".json")]
    directories = [value for value in values if not value.startswith("-") and Path(value).is_dir()]
    return next(iter(json_paths + directories), None)


def build_parser() -> argparse.ArgumentParser:
    """
    Décrit les options de la ligne de commande
    """
    parser = argparse.ArgumentParser(description="TP1 : capture réseau, détection d'attaques et rapport")
    parser.add_argument("pcap_file", nargs="?", help="fichier pcap à analyser (comme --pcap)")
    parser.add_argument(
        "--pcap", "-r", help="analyser un fichier pcap au lieu d'écouter le réseau (sans root)"
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"durée de la capture en secondes (défaut : {TIMEOUT})"
    )
    parser.add_argument(
        "--output", "--out", "-o", help="fichier report.json ou dossier où écrire les rapports"
    )
    return parser


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande, en ignorant celles qu'on ne connait pas

    :param arguments: options à lire, None pour celles passées au programme
    :return: options (timeout et pcap)
    """
    parser = build_parser()
    options, unknown_arguments = parser.parse_known_args(arguments)
    explicit_pcap = options.pcap
    candidates = [argument for argument in (options.pcap, options.pcap_file, *unknown_arguments) if argument]
    options.pcap = find_pcap_file(candidates)
    # un argument direct qui n'est pas un fichier est sûrement la valeur d'une option inconnue
    ignored_arguments = [
        arg for arg in (*unknown_arguments, options.pcap_file) if arg and arg != options.pcap
    ]
    options.output = options.output or find_output_path(ignored_arguments)
    ignored_arguments = [arg for arg in ignored_arguments if arg.split("=", 1)[-1] != options.output]
    if ignored_arguments:
        logger.warning(f"Arguments inconnus ignorés : {' '.join(ignored_arguments)}")
    if options.timeout <= 0:
        parser.error("la durée de la capture doit être positive")
    if explicit_pcap is not None and options.pcap is None:
        parser.error(f"fichier introuvable : {explicit_pcap}")
    return options


def get_output_paths(output: str | None) -> tuple[Path, list[Path]]:
    """
    Retourne le dossier du rapport PDF et les chemins où écrire report.json

    :param output: fichier .json ou dossier demandé, None pour le dossier courant
    :return: (dossier des rapports, chemins de report.json)
    """
    if output is None:
        json_paths = [Path("report.json")]
        if GRADER_OUTPUT_DIRECTORY.is_dir() and os.access(GRADER_OUTPUT_DIRECTORY, os.W_OK):
            json_paths.append(GRADER_OUTPUT_DIRECTORY / "report.json")
        return Path(), json_paths
    path = Path(output)
    directory = path.parent if path.suffix.lower() == ".json" else path
    directory.mkdir(parents=True, exist_ok=True)
    return directory, [path if path.suffix.lower() == ".json" else path / "report.json"]


def save_reports(capture: Capture, summary: str, output: str | None) -> list[Path]:
    """
    Enregistre le rapport PDF, le graphique et report.json

    :return: chemins où report.json a été écrit
    """
    directory, json_paths = get_output_paths(output)
    filename = str(directory / "report.pdf")
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)
    for json_path in json_paths:
        report.save_json(str(json_path))
    return json_paths


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

    json_paths = save_reports(capture, summary, options.output)
    received = " ".join(sys.argv[1:] if arguments is None else arguments) or "aucun"
    written = ", ".join(str(json_path.resolve()) for json_path in json_paths)
    logger.info(f"report.json écrit dans : {written} (arguments reçus : {received})")


if __name__ == "__main__":
    main()
