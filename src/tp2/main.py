import json
import sys
from pathlib import Path

from src.tp2.utils.config import logger
from src.tp2.utils.triage import triage

# fichiers posés à côté des échantillons mais qui n'en sont pas
AUX_SUFFIXES = {".json", ".txt", ".md", ".toml", ".lock", ".log", ".yar", ".py", ".cfg", ".ini"}


def iter_samples(targets: list[str]):
    """Donne les échantillons des fichiers/dossiers fournis (en ignorant les fichiers annexes)."""
    for target in targets:
        path = Path(target)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.suffix.lower() not in AUX_SUFFIXES and not child.name.startswith("."):
                    yield child
        elif path.is_file():
            yield path


def collect_samples(targets: list[str]) -> list[Path]:
    samples = list(iter_samples(targets))
    # pratique pour le correcteur : à défaut, chercher dans un sous-dossier student/
    if not samples and Path("student").is_dir():
        samples = list(iter_samples(["student"]))
    return samples


def main(arguments: list[str] | None = None) -> None:
    logger.info("Starting TP2")
    targets = (sys.argv[1:] if arguments is None else arguments) or ["."]
    samples = collect_samples(targets)
    if not samples:
        logger.warning("Aucun échantillon à analyser")
        return

    for sample in samples:
        report = triage(sample)
        output = sample.with_name(sample.name + ".triage.json")
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"{sample.name} : drapeau={report['flag']}, yara={report['yara']} -> {output.name}")


if __name__ == "__main__":
    main()
