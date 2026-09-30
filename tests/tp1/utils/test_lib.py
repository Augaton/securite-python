import logging
from unittest.mock import MagicMock, call, patch

import pytest
from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6ND_NS,
    IPerror,
    IPv6,
    Padding,
    Raw,
    UDPerror,
)

from src.tp1.utils.lib import (
    choose_interface,
    drop_privileges,
    format_share,
    get_protocol,
    give_log_files_to,
    hello_world,
    parse_interface_choice,
)


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


@pytest.fixture
def keyboard():
    """
    Simule un terminal : sous pytest l'entrée standard n'est pas un clavier
    """
    with patch("src.tp1.utils.lib.sys.stdin") as mock_stdin:
        mock_stdin.isatty.return_value = True
        yield mock_stdin


@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
@pytest.mark.usefixtures("keyboard")
def test_given_interface_number_when_choose_interface_then_return_interface(_mock_get_if_list):
    # Given
    user_choice = "1"

    # When
    with patch("builtins.input", return_value=user_choice):
        result = choose_interface()

    # Then
    assert result == "eth0"


@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
@pytest.mark.usefixtures("keyboard")
def test_given_wrong_then_valid_choice_when_choose_interface_then_ask_again(_mock_get_if_list):
    # Given
    user_choices = ["abc", "1"]

    # When
    with patch("builtins.input", side_effect=user_choices) as mock_input:
        result = choose_interface()

    # Then
    assert result == "eth0"
    assert mock_input.call_count == len(user_choices)


@pytest.mark.parametrize(
    "choice, expected_interface", [("1", "eth0"), (" 0 ", "lo"), ("eth0", "eth0"), ("", "wlan0")]
)
@patch("src.tp1.utils.lib.conf", MagicMock(iface="wlan0"))
def test_given_valid_choice_when_parse_interface_choice_then_return_interface(choice, expected_interface):
    # When
    result = parse_interface_choice(choice, ["lo", "eth0"])

    # Then
    assert result == expected_interface


@pytest.mark.parametrize("choice", ["2", "-1", "abc"])
def test_given_invalid_choice_when_parse_interface_choice_then_return_none(choice):
    # When
    result = parse_interface_choice(choice, ["lo", "eth0"])

    # Then
    assert result is None


def test_given_dns_packet_when_get_protocol_then_return_dns():
    # Given
    packet = Ether() / IP() / UDP() / DNS()

    # When
    result = get_protocol(packet)

    # Then
    assert result == "DNS"


def test_given_tcp_packet_with_data_when_get_protocol_then_return_tcp():
    # Given
    packet = Ether() / IP() / TCP() / Raw(b"hello")

    # When
    result = get_protocol(packet)

    # Then
    assert result == "TCP"


def test_given_ipv6_packet_when_get_protocol_then_return_its_last_layer():
    # Given
    packet = Ether() / IPv6() / ICMPv6ND_NS()

    # When
    result = get_protocol(packet)

    # Then
    assert result == "ICMPv6ND_NS"


def test_given_arp_packet_with_padding_when_get_protocol_then_return_arp():
    # Given
    packet = Ether() / ARP() / Padding(b"\x00" * 18)

    # When
    result = get_protocol(packet)

    # Then
    assert result == "ARP"


def test_given_icmp_port_unreachable_when_get_protocol_then_return_icmp():
    # Given
    packet = Ether() / IP() / ICMP(type=3, code=3) / IPerror() / UDPerror()

    # When
    result = get_protocol(packet)

    # Then
    assert result == "ICMP"


def test_given_raw_data_only_when_get_protocol_then_return_autre():
    # Given
    packet = Raw(b"donnees")

    # When
    result = get_protocol(packet)

    # Then
    assert result == "Autre"


@pytest.mark.parametrize(
    "count, total, expected_share", [(1, 4, "25.0 %"), (3, 3, "100.0 %"), (0, 0, "0.0 %")]
)
def test_when_format_share_then_return_percentage(count, total, expected_share):
    # When
    result = format_share(count, total)

    # Then
    assert result == expected_share


SUDO_USER = MagicMock(pw_name="etudiant", pw_uid=1000, pw_gid=1001, pw_dir="/home/etudiant")
IDENTITY_CALLS = ("initgroups", "setgid", "setuid")


@pytest.fixture
def mock_os():
    """
    Remplace les appels système de changement d'utilisateur : les tests ne tournent pas en root
    """
    with (
        patch("src.tp1.utils.lib.get_sudo_user", return_value=SUDO_USER),
        patch("src.tp1.utils.lib.os") as mock_os,
    ):
        mock_os.environ = {"HOME": "/root"}
        mock_os.geteuid.return_value = 0
        mock_os.getresuid.return_value = (1000, 1000, 1000)
        yield mock_os


def test_given_root_launched_with_sudo_when_drop_privileges_then_become_the_sudo_user(mock_os):
    # When
    with patch("src.tp1.utils.lib.give_log_files_to") as mock_give_log_files_to:
        drop_privileges()

    # Then
    identity_calls = [method_call for method_call in mock_os.method_calls if method_call[0] in IDENTITY_CALLS]
    assert identity_calls == [call.initgroups("etudiant", 1001), call.setgid(1001), call.setuid(1000)]
    mock_give_log_files_to.assert_called_once_with(SUDO_USER)
    assert mock_os.environ["HOME"] == "/home/etudiant"


def test_given_not_root_when_drop_privileges_then_nothing_changes(mock_os):
    # Given
    mock_os.geteuid.return_value = 1000

    # When
    drop_privileges()

    # Then
    mock_os.setuid.assert_not_called()


def test_given_root_without_sudo_when_drop_privileges_then_warn_that_everything_runs_as_root(mock_os, caplog):
    # When
    with patch("src.tp1.utils.lib.get_sudo_user", return_value=None):
        drop_privileges()

    # Then
    mock_os.setuid.assert_not_called()
    assert "Lancé en root sans sudo" in caplog.text


def test_given_root_still_there_after_setuid_when_drop_privileges_then_stop(mock_os):
    # Given
    mock_os.getresuid.return_value = (1000, 1000, 0)

    # When / Then
    with patch("src.tp1.utils.lib.give_log_files_to"), pytest.raises(RuntimeError):
        drop_privileges()


def test_given_log_file_when_give_log_files_to_then_chown_without_following_links(tmp_path):
    # Given
    file_handler = logging.FileHandler(tmp_path / "app.log")
    logging.getLogger().addHandler(file_handler)

    # When
    try:
        with patch("src.tp1.utils.lib.os.chown") as mock_chown:
            give_log_files_to(SUDO_USER)
    finally:
        logging.getLogger().removeHandler(file_handler)
        file_handler.close()

    # Then
    mock_chown.assert_any_call(str(tmp_path / "app.log"), 1000, 1001, follow_symlinks=False)


@patch("src.tp1.utils.lib.conf", MagicMock(iface="wlan0"))
@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
def test_given_no_keyboard_when_choose_interface_then_default_interface_without_question(_mock_get_if_list):
    # Given
    with patch("src.tp1.utils.lib.sys.stdin") as mock_stdin, patch("builtins.input") as mock_input:
        mock_stdin.isatty.return_value = False

        # When
        result = choose_interface()

    # Then
    assert result == "wlan0"
    mock_input.assert_not_called()


@patch("src.tp1.utils.lib.conf", MagicMock(iface="wlan0"))
@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
@pytest.mark.usefixtures("keyboard")
def test_given_end_of_input_when_choose_interface_then_default_interface(_mock_get_if_list):
    # When
    with patch("builtins.input", side_effect=EOFError):
        result = choose_interface()

    # Then
    assert result == "wlan0"
