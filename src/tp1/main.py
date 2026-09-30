from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    try:
        capture.capture_traffic()
    except PermissionError:
        # scapy a besoin d'être root pour écouter une interface
        logger.error("Pas les droits pour capturer les paquets, il faut lancer le programme avec sudo")
        return
    capture.analyse()
    summary = capture.get_summary()
    logger.info(summary)

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
