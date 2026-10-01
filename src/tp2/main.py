"""Point d'entrée CLI : poetry run tp2 --samples DIR --rules DIR --out DIR."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tp2.analyzer import TriageAnalyzer
from tp2.llm import build_client

logger = logging.getLogger("tp2")


def build_parser() -> argparse.ArgumentParser:
    """Déclare les options de la ligne de commande."""
    parser = argparse.ArgumentParser(prog="tp2", description="Triage de malware")
    parser.add_argument("--samples", type=Path, required=True, help="échantillons")
    parser.add_argument("--rules", type=Path, default=None, help="règles YARA")
    parser.add_argument("--out", type=Path, required=True, help="dossier de sortie")
    parser.add_argument(
        "--llm",
        choices=["auto", "openrouter", "ollama", "offline"],
        default=None,
        help="backend LLM (défaut : variable TP2_LLM_BACKEND, sinon auto)",
    )
    parser.add_argument("--no-pdf", action="store_true", help="ne pas générer de PDF")
    parser.add_argument("-v", "--verbose", action="store_true", help="logs détaillés")
    return parser


def configure_logging(verbose: bool) -> None:
    """Configure le module logging sur la sortie d'erreur."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    """Lance le triage de tous les échantillons et renvoie un code de sortie."""
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    if not args.samples.is_dir():
        logger.error("Dossier d'échantillons introuvable : %s", args.samples)
        return 2
    analyzer = TriageAnalyzer(rules_dir=args.rules, client=build_client(args.llm))
    processed = analyzer.run(args.samples, args.out, with_pdf=not args.no_pdf)
    logger.info("%d rapport(s) écrit(s) dans %s", processed, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
