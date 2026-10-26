import argparse
import sys
from pathlib import Path

from src.tp1.utils.capture import TIMEOUT, Capture
from src.tp1.utils.config import logger
from src.tp1.utils.lib import drop_privileges
from src.tp1.utils.report import Report

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def find_pcap_file(candidates: list[str]) -> str | None:
    """
    Find the capture file among the arguments (a .pcap preferably)

    :param candidates: arguments that may point to the file
    :return: path of the file, None if no argument is a file
    """
    files = [candidate for candidate in candidates if Path(candidate).is_file()]
    captures = [file for file in files if file.lower().endswith(PCAP_EXTENSIONS)]
    return next(iter(captures + files), None)


def build_parser() -> argparse.ArgumentParser:
    """
    Describe the command-line options
    """
    parser = argparse.ArgumentParser(description="TP1: network capture, attack detection and report")
    parser.add_argument("pcap_file", nargs="?", help="pcap file to analyse (same as --pcap)")
    parser.add_argument(
        "--pcap", "-r", help="analyse a pcap file instead of listening on the network (no root needed)"
    )
    parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"capture duration in seconds (default: {TIMEOUT})"
    )
    return parser


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Read the command-line options, ignoring the unknown ones

    :param arguments: options to read, None for the ones passed to the program
    :return: options (timeout and pcap)
    """
    parser = build_parser()
    options, unknown_arguments = parser.parse_known_args(arguments)
    explicit_pcap = options.pcap
    candidates = [argument for argument in (options.pcap, options.pcap_file, *unknown_arguments) if argument]
    options.pcap = find_pcap_file(candidates)
    # A positional argument that is not a file is most likely the value of an unknown option
    ignored_arguments = [
        arg for arg in (*unknown_arguments, options.pcap_file) if arg and arg != options.pcap
    ]
    if ignored_arguments:
        logger.warning(f"Unknown arguments ignored: {' '.join(ignored_arguments)}")
    if options.timeout <= 0:
        parser.error("capture duration must be positive")
    if explicit_pcap is not None and options.pcap is None:
        parser.error(f"file not found: {explicit_pcap}")
    return options


def main(arguments: list[str] | None = None):
    logger.info("Starting TP1")
    options = parse_arguments(arguments)

    capture = Capture(options.pcap, options.timeout)
    try:
        capture.open_socket()
    except PermissionError:
        # root does not know about poetry: give the full path to the script
        tp1_script = Path(sys.executable).parent / "tp1"
        logger.error(f"No permission to capture packets, rerun with: sudo {tp1_script}")
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
