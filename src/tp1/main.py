import sys
from pathlib import Path

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    try:
        capture.capture_traffic()
    except PermissionError:
        # scapy a besoin d'être root pour écouter une interface, et root ne connait pas poetry :
        # on donne le chemin complet du script à relancer avec sudo
        tp1_script = Path(sys.executable).parent / "tp1"
        logger.error(f"Pas les droits pour capturer les paquets, relancer avec : sudo {tp1_script}")
        return
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
