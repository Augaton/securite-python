import logging
from unittest.mock import patch

from src.config import get_log_handlers


def test_given_writable_directory_when_get_log_handlers_then_log_to_file_and_console(tmp_path, monkeypatch):
    # Given
    monkeypatch.chdir(tmp_path)

    # When
    handlers = get_log_handlers()

    # Then
    assert [type(handler) for handler in handlers] == [logging.FileHandler, logging.StreamHandler]
    handlers[0].close()


@patch("src.config.logging.FileHandler", side_effect=PermissionError("read-only"))
def test_given_read_only_directory_when_get_log_handlers_then_log_to_console_only(mock_file_handler):
    # When
    handlers = get_log_handlers()

    # Then
    assert [type(handler) for handler in handlers] == [logging.StreamHandler]
