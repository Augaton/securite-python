from unittest.mock import patch

from src.tp3.main import main


@patch("src.tp3.main.Session")
def test_when_main_then_each_challenge_is_solved(mock_session):
    # Given
    mock_session.return_value.process_response.return_value = True
    mock_session.return_value.get_flag.return_value = "FLAG"

    # When
    main()

    # Then
    assert mock_session.call_count == 2
    assert mock_session.return_value.get_flag.call_count == 2
