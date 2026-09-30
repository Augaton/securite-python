import json
import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from src.tp1.main import get_output_paths, main, parse_arguments


@pytest.fixture(autouse=True)
def no_grader_directory(monkeypatch, tmp_path):
    """
    Le dossier /out existe dans le bac à sable de correction : sans ça les tests n'y seraient pas les mêmes
    """
    monkeypatch.setattr("src.tp1.main.GRADER_OUTPUT_DIRECTORY", tmp_path / "absent")


@patch("src.tp1.main.Report")
@patch("src.tp1.main.Capture")
def test_when_main_then_report_is_saved(mock_capture, mock_report):
    # Given
    mock_capture.return_value.get_summary.return_value = "Test summary"

    # When
    main([])

    # Then
    mock_capture.assert_called_once_with(None, 60)
    mock_capture.return_value.capture_traffic.assert_called_once()
    mock_capture.return_value.analyse.assert_called_once()
    mock_report.assert_called_once_with(mock_capture.return_value, "report.pdf", "Test summary")
    mock_report.return_value.save.assert_called_once_with("report.pdf")
    mock_report.return_value.save_json.assert_called_once_with("report.json")


@patch("src.tp1.main.Report")
@patch("src.tp1.main.Capture")
def test_given_no_root_when_main_then_no_report_and_sudo_command_is_given(mock_capture, mock_report, caplog):
    # Given
    mock_capture.return_value.open_socket.side_effect = PermissionError

    # When
    main([])

    # Then
    mock_capture.return_value.capture_traffic.assert_not_called()
    mock_capture.return_value.analyse.assert_not_called()
    mock_report.assert_not_called()
    assert f"sudo {Path(sys.executable).parent / 'tp1'}" in caplog.text


def test_given_pcap_and_timeout_when_parse_arguments_then_options_are_read(tmp_path):
    # Given
    pcap_file = tmp_path / "attaque.pcap"
    pcap_file.write_bytes(b"")

    # When
    options = parse_arguments(["--pcap", str(pcap_file), "--timeout", "120"])

    # Then
    assert (options.pcap, options.timeout) == (str(pcap_file), 120)


@pytest.mark.parametrize("arguments", [["--pcap", "fichier_absent.pcap"], ["--timeout", "0"]])
def test_given_wrong_option_when_parse_arguments_then_stop_with_error(arguments):
    # When / Then
    with pytest.raises(SystemExit):
        parse_arguments(arguments)


@patch("src.tp1.main.Report")
@patch("src.tp1.main.drop_privileges")
@patch("src.tp1.main.Capture")
def test_when_main_then_root_is_dropped_between_socket_opening_and_capture(
    mock_capture, mock_drop, _mock_report
):
    # Given
    steps = []
    mock_capture.return_value.open_socket.side_effect = lambda: steps.append("open_socket")
    mock_drop.side_effect = lambda: steps.append("drop_privileges")
    mock_capture.return_value.capture_traffic.side_effect = lambda: steps.append("capture_traffic")

    # When
    main([])

    # Then
    assert steps == ["open_socket", "drop_privileges", "capture_traffic"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["{pcap}"],
        ["-r", "{pcap}"],
        ["--output", "sortie", "{pcap}"],
        ["{pcap}", "--format", "json", "--verbose"],
    ],
)
def test_given_pcap_given_in_any_way_when_parse_arguments_then_it_is_found(arguments, tmp_path):
    # Given
    pcap_file = tmp_path / "holdout.pcap"
    pcap_file.write_bytes(b"")
    arguments = [argument.format(pcap=pcap_file) for argument in arguments]

    # When
    options = parse_arguments(arguments)

    # Then
    assert options.pcap == str(pcap_file)


def test_given_unknown_arguments_when_parse_arguments_then_warn_instead_of_stopping(caplog):
    # When
    options = parse_arguments(["--verbose", "--format", "texte"])

    # Then
    assert (options.pcap, options.output) == (None, None)
    assert "Arguments inconnus ignorés : --verbose --format texte" in caplog.text


@pytest.mark.parametrize(
    "arguments, expected_output",
    [
        (["{pcap}", "-o", "{out}/report.json"], "{out}/report.json"),
        (["{pcap}", "{out}/report.json"], "{out}/report.json"),
        (["--pcap", "{pcap}", "--dest={out}/resultat.json"], "{out}/resultat.json"),
        (["{pcap}", "--dossier", "{out}"], "{out}"),
        (["{pcap}"], None),
    ],
)
def test_given_output_given_in_any_way_when_parse_arguments_then_it_is_found(
    arguments, expected_output, tmp_path
):
    # Given
    pcap_file = tmp_path / "pcap"
    pcap_file.write_bytes(b"")
    output_directory = tmp_path / "out"
    output_directory.mkdir()
    values = {"pcap": pcap_file, "out": output_directory}

    # When
    options = parse_arguments([argument.format(**values) for argument in arguments])

    # Then
    assert options.pcap == str(pcap_file)
    assert options.output == (expected_output.format(**values) if expected_output else None)


def test_given_json_path_in_missing_directory_when_get_output_paths_then_directory_is_created(tmp_path):
    # Given
    json_path = tmp_path / "resultats" / "report.json"

    # When
    directory, json_paths = get_output_paths(str(json_path))

    # Then
    assert directory == json_path.parent
    assert directory.is_dir()
    assert json_paths == [json_path]


def test_given_no_output_and_grader_directory_when_get_output_paths_then_json_also_goes_there(tmp_path):
    # Given
    grader_directory = tmp_path / "out"
    grader_directory.mkdir()

    # When
    with patch("src.tp1.main.GRADER_OUTPUT_DIRECTORY", grader_directory):
        directory, json_paths = get_output_paths(None)

    # Then
    assert json_paths == [Path("report.json"), grader_directory / "report.json"]


def test_given_pcap_and_output_when_main_then_report_json_is_written_where_asked(
    tmp_path, monkeypatch, caplog
):
    # Given
    monkeypatch.chdir(tmp_path)
    pcap_file = tmp_path / "pcap"
    wrpcap(
        str(pcap_file), [Ether() / IP(src="10.0.0.77") / TCP() / Raw(b"GET /?id=1 OR 1=1 HTTP/1.1\r\n\r\n")]
    )
    json_path = tmp_path / "out" / "report.json"

    # When
    with caplog.at_level(logging.INFO, logger="TP1"):
        main([str(pcap_file), "--output", str(json_path)])

    # Then
    result = json.loads(json_path.read_text())
    assert result["attacks"] == [{"type": "injection_sql", "attacker": "10.0.0.77"}]
    assert (tmp_path / "out" / "report.pdf").exists()
    assert f"report.json écrit dans : {json_path}" in caplog.text
