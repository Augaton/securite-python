from unittest.mock import MagicMock, patch

from src.tp1.utils.lib import choose_interface, hello_world


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
def test_given_interface_number_when_choose_interface_then_return_interface(mock_get_if_list):
    # Given
    user_choice = "1"

    # When
    with patch("builtins.input", return_value=user_choice):
        result = choose_interface()

    # Then
    assert result == "eth0"


@patch("src.tp1.utils.lib.conf", MagicMock(iface="wlan0"))
@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
def test_given_wrong_choice_when_choose_interface_then_return_default_interface(mock_get_if_list):
    # Given
    user_choice = "abc"

    # When
    with patch("builtins.input", return_value=user_choice):
        result = choose_interface()

    # Then
    assert result == "wlan0"
