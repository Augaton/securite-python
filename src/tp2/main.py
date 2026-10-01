import argparse
import os
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import BACKEND_CHOICES, LLMTriage
from tp2.utils.report import generate_report
from tp2.utils.scanner import DEFAULT_RULES_PATH, YaraScanner
from tp2.utils.triage import Triage

DEFAULT_OUT = "out"


def build_parser() -> argparse.ArgumentParser:
    """
    Décrit les options de la ligne de commande
    """
    parser = argparse.ArgumentParser(description="TP2 : triage automatisé de malware")
    parser.add_argument("--samples", "-s", help="dossier (ou fichier) des échantillons à analyser")
    parser.add_argument(
        "--file", "-f", action="append", default=[], help="un échantillon à analyser (option répétable)"
    )
    parser.add_argument(
        "--rules",
        "-r",
        default=DEFAULT_RULES_PATH,
        help=f"fichier ou dossier des règles YARA du cours (défaut : {DEFAULT_RULES_PATH}), nos règles sont ajoutées",
    )
    parser.add_argument(
        "--out",
        "-o",
        default=DEFAULT_OUT,
        help=f"dossier des rapports <sha256>.json et .pdf (défaut : {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--llm",
        default=os.getenv("LLM_BACKEND", "auto"),
        help="LLM du verdict : auto (OpenRouter si OPENROUTER_API_KEY, sinon Ollama, sinon verdict déterministe), "
        "openrouter, ollama ou offline (défaut : auto, ou la variable LLM_BACKEND)",
    )
    parser.add_argument("--no-pdf", action="store_true", help="n'écrire que les JSON")
    return parser


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande, en ignorant celles qu'on ne connait pas

    :param arguments: options à lire, None pour celles passées au programme
    :return: options (samples, file, rules, out, llm, no_pdf)
    """
    parser = build_parser()
    options, unknown_arguments = parser.parse_known_args(arguments)
    if unknown_arguments:
        logger.warning(f"Arguments inconnus ignorés : {' '.join(unknown_arguments)}")
    options.llm = options.llm.lower()
    if options.llm not in BACKEND_CHOICES:
        parser.error(f"backend LLM inconnu : {options.llm} (choix : {', '.join(BACKEND_CHOICES)})")
    if not options.samples and not options.file:
        parser.error("donner les échantillons avec --samples DOSSIER (ou -f FICHIER)")
    return options


def find_samples(samples: str | None, files: list[str]) -> list[Path]:
    """
    Échantillons à analyser : les fichiers donnés et ceux du dossier (sous-dossiers compris, sans les
    fichiers cachés ni les liens symboliques, qui pourraient pointer hors du dossier)

    :param samples: dossier (ou fichier) des échantillons
    :param files: fichiers donnés un par un
    :return: chemins sans doublon, ceux du dossier triés
    """
    paths = [Path(file) for file in files]
    if samples:
        root = Path(samples)
        if root.is_dir():
            paths += sorted(
                path
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink() and not path.name.startswith(".")
            )
        else:
            paths.append(root)
    return list(dict.fromkeys(paths))


def main(arguments: list[str] | None = None) -> None:
    logger.info("Starting TP2")
    options = parse_arguments(arguments)

    out_dir = Path(options.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    scanner = YaraScanner(options.rules)
    llm = LLMTriage(options.llm)

    samples = find_samples(options.samples, options.file)
    if not samples:
        logger.warning(f"Aucun échantillon à analyser dans {options.samples}")
    reports = 0
    for path in samples:
        try:
            result = Triage(str(path), options.llm, scanner=scanner, llm=llm).run()
            generate_report(result, str(out_dir), pdf=not options.no_pdf)
            reports += 1
        except OSError as error:
            logger.error(f"Échantillon illisible {path} : {error}")
        except Exception:  # un échantillon piégé ne doit pas empêcher l'analyse des suivants
            logger.exception(f"Échec du triage de {path}")
    logger.info(f"{reports}/{len(samples)} rapport(s) écrit(s) dans {out_dir}")


if __name__ == "__main__":
    main()
