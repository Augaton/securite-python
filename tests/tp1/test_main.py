import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src.tp1.main import main, parse_arguments


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
    options = parse_arguments(["--verbose", "--output", "sortie"])

    # Then
    assert options.pcap is None
    assert "Arguments inconnus ignorés : --verbose --output sortie" in caplog.text
