from unittest.mock import patch

from src.tp1.main import main


@patch("src.tp1.main.Report")
@patch("src.tp1.main.Capture")
def test_when_main_then_report_is_saved(mock_capture, mock_report):
    # Given
    mock_capture.return_value.get_summary.return_value = "Test summary"

    # When
    main()

    # Then
    mock_capture.return_value.capture_traffic.assert_called_once()
    mock_capture.return_value.analyse.assert_called_once()
    mock_report.assert_called_once_with(mock_capture.return_value, "report.pdf", "Test summary")
    mock_report.return_value.save.assert_called_once_with("report.pdf")


@patch("src.tp1.main.Report")
@patch("src.tp1.main.Capture")
def test_given_no_root_when_main_then_no_report(mock_capture, mock_report):
    # Given
    mock_capture.return_value.capture_traffic.side_effect = PermissionError

    # When
    main()

    # Then
    mock_capture.return_value.analyse.assert_not_called()
    mock_report.assert_not_called()
