import argparse
from pathlib import Path

from src.tp2.utils.config import logger
from src.tp2.utils.llm import LLMClient
from src.tp2.utils.report import gen_rapport_triage
from src.tp2.utils.triage import triage_echantillon

# fichiers posés à côté des échantillons mais qui n'en sont pas
AUX_SUFFIXES = {".json", ".txt", ".md", ".yar", ".yaml", ".yml", ".pdf", ".lock", ".toml"}


def verif_est_echantillon(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() not in AUX_SUFFIXES and not path.name.startswith(".")


def lister_echantillons(samples_dir: str):
    for child in sorted(Path(samples_dir).iterdir()):
        if verif_est_echantillon(child):
            yield child


def constr_parser_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP2 : triage statique de malware")
    parser.add_argument("--samples", required=True, help="dossier des échantillons à analyser")
    parser.add_argument("--rules", default=None, help="dossier des règles YARA (défaut : rules/ du projet)")
    parser.add_argument("--out", required=True, help="dossier de sortie (<nom>.triage.json par échantillon)")
    parser.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    return parser


def traiter_echantillon(sample: Path, args: argparse.Namespace, client: LLMClient) -> None:
    result = triage_echantillon(str(sample), args.rules, client)
    path_json = gen_rapport_triage(result, args.out, sample.name)
    logger.info(f"{sample.name} -> {path_json.name} (score {result['score']}, drapeau {result['flag']})")


def main(argv: list[str] | None = None) -> None:
    args = constr_parser_args().parse_args(argv)
    logger.info("Starting TP2")
    client = LLMClient(args.llm)
    for sample in lister_echantillons(args.samples):
        traiter_echantillon(sample, args, client)


if __name__ == "__main__":
    main()
