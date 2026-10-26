import argparse
from pathlib import Path

from src.tp2.utils.config import logger
from src.tp2.utils.llm import LLMClient
from src.tp2.utils.report import generate_report
from src.tp2.utils.triage import triage_sample

# fichiers posés à côté des échantillons mais qui n'en sont pas
AUX_SUFFIXES = {".json", ".txt", ".md", ".yar", ".yaml", ".yml", ".pdf", ".lock", ".toml"}


def iter_samples(samples_dir: str):
    for child in sorted(Path(samples_dir).iterdir()):
        if child.is_file() and child.suffix.lower() not in AUX_SUFFIXES and not child.name.startswith("."):
            yield child


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="TP2 : triage statique de malware")
    parser.add_argument("--samples", required=True, help="dossier des échantillons à analyser")
    parser.add_argument("--rules", default=None, help="dossier des règles YARA (défaut : rules/ du projet)")
    parser.add_argument("--out", required=True, help="dossier de sortie (un <sha256>.json par échantillon)")
    parser.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = parser.parse_args(argv)

    logger.info("Starting TP2")
    client = LLMClient(args.llm)
    for sample in iter_samples(args.samples):
        result = triage_sample(str(sample), args.rules, client)
        json_path = generate_report(result, args.out)
        logger.info(f"{sample.name} -> {json_path.name} (score {result['score']}, drapeau {result['flag']})")


if __name__ == "__main__":
    main()
