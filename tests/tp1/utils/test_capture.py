from unittest.mock import patch

import pytest
from scapy.all import ARP, DNS, IP, TCP, UDP, Ether

from src.tp1.utils.capture import Capture


# Capture() demande l'interface avec input(), on la remplace pour les tests
@pytest.fixture(autouse=True)
def mock_choose_interface():
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        yield


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == "eth0"
    assert capture.packets == []
    assert capture.protocols == {}
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_packets_are_saved():
    # Given
    capture = Capture()
    packets = [Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    with patch("src.tp1.utils.capture.sniff", return_value=packets) as mock_sniff:
        capture.capture_traffic()

    # Then
    mock_sniff.assert_called_once_with(iface="eth0", count=100, timeout=30)
    assert capture.packets == packets


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP(), Ether() / IP() / UDP() / DNS(), Ether() / IP() / TCP()]

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {"TCP": 2, "DNS": 1}


def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture.packets = [Ether() / ARP(), Ether() / IP() / TCP(), Ether() / IP() / TCP()]

    # When
    result = capture.sort_network_protocols()

    # Then
    assert list(result) == ["TCP", "ARP"]


def test_analyse():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / UDP(), Ether() / IP() / TCP(), Ether() / IP() / TCP()]

    # When
    capture.analyse()

    # Then
    assert capture.protocols == {"TCP": 2, "UDP": 1}
    assert capture.summary != ""


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()
    capture.protocols = {"TCP": 3, "DNS": 1}

    # When
    result = capture._gen_summary()

    # Then
    assert "4 paquets" in result
    assert "TCP avec 3 paquets" in result


def test_given_no_packet_when_gen_summary_then_say_no_packet():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == "Aucun paquet capturé sur eth0."
