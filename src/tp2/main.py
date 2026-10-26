import argparse

from src.tp2.utils.config import logger
from src.tp2.utils.report import Report
from src.tp2.utils.triage import Triage


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="TP2 : triage statique de malware")
    ap.add_argument("-f", "--file", required=True, help="échantillon à analyser")
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args(argv)

    logger.info("Starting TP2")
    result = Triage(args.file, args.llm).run()

    report = Report(result)
    report.generate_json(f"{args.file}.triage.json")
    try:
        report.generate_pdf(f"{args.file}.triage.pdf")
    except Exception as error:
        logger.warning(f"PDF non généré : {error}")

    logger.info(f"{args.file} : drapeau={result['flag']}, yara={result['yara']}")


if __name__ == "__main__":
    main()
