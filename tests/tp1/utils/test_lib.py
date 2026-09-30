from unittest.mock import MagicMock, patch

import pytest
from scapy.all import ARP, DNS, IP, TCP, UDP, Ether, ICMPv6ND_NS, IPv6, Padding, Raw

from src.tp1.utils.lib import choose_interface, get_protocol, hello_world, parse_interface_choice


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


@patch("src.tp1.utils.lib.get_if_list", return_value=["lo", "eth0"])
def test_given_wrong_then_valid_choice_when_choose_interface_then_ask_again(mock_get_if_list):
    # Given
    user_choices = ["abc", "1"]

    # When
    with patch("builtins.input", side_effect=user_choices) as mock_input:
        result = choose_interface()

    # Then
    assert result == "eth0"
    assert mock_input.call_count == 2


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


def test_given_raw_data_only_when_get_protocol_then_return_autre():
    # Given
    packet = Raw(b"donnees")

    # When
    result = get_protocol(packet)

    # Then
    assert result == "Autre"
