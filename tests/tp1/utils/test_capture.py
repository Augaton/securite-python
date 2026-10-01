from unittest.mock import patch

import pytest
from scapy.all import ARP, DNS, IP, TCP, UDP, Ether, Raw, wrpcap

from src.tp1.utils.capture import Capture


def feed(capture: Capture, packets: list) -> None:
    """
    Donne les paquets à la capture un par un, comme le fait sniff pendant une vraie capture
    """
    for packet in packets:
        capture.add_packet(packet)


@pytest.fixture(autouse=True)
def mock_choose_interface():
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        yield


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == "eth0"
    assert capture.get_packet_count() == 0
    assert capture.protocols == {}
    assert capture.summary == ""


@patch("src.tp1.utils.capture.conf")
def test_given_capture_when_capture_traffic_then_packets_are_saved(mock_conf):
    # Given
    capture = Capture()
    packets = [Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    with patch(
        "src.tp1.utils.capture.sniff", side_effect=lambda **_options: feed(capture, packets)
    ) as mock_sniff:
        capture.capture_traffic()

    # Then
    mock_conf.L2listen.assert_called_once_with(iface="eth0")
    listen_socket = mock_conf.L2listen.return_value
    mock_sniff.assert_called_once_with(
        opened_socket=listen_socket, timeout=60, prn=capture.add_packet, store=False
    )
    listen_socket.close.assert_called_once()
    assert capture.get_all_protocols() == {"TCP": 1, "ARP": 1}


@patch("src.tp1.utils.capture.conf")
def test_given_error_during_capture_when_capture_traffic_then_socket_is_closed(mock_conf):
    # Given
    capture = Capture()

    # When
    with patch("src.tp1.utils.capture.sniff", side_effect=OSError), pytest.raises(OSError):
        capture.capture_traffic()

    # Then
    mock_conf.L2listen.return_value.close.assert_called_once()
    assert capture.listen_socket is None


@patch("src.tp1.utils.capture.conf")
def test_given_pcap_file_when_open_socket_then_nothing_is_opened(mock_conf, tmp_path):
    # Given
    capture = Capture(pcap_file=str(tmp_path / "attaque.pcap"))

    # When
    capture.open_socket()

    # Then
    mock_conf.L2listen.assert_not_called()


def test_get_all_protocols():
    # Given
    capture = Capture()
    feed(capture, [Ether() / IP() / TCP(), Ether() / IP() / UDP() / DNS(), Ether() / IP() / TCP()])

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {"TCP": 2, "DNS": 1}


def test_sort_network_protocols():
    # Given
    capture = Capture()
    feed(capture, [Ether() / ARP(), Ether() / IP() / TCP(), Ether() / IP() / TCP()])

    # When
    result = capture.sort_network_protocols()

    # Then
    assert list(result) == ["TCP", "ARP"]


def test_analyse():
    # Given
    capture = Capture()
    feed(capture, [Ether() / IP() / UDP(), Ether() / IP() / TCP(), Ether() / IP() / TCP()])

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
    assert result == "Aucun paquet capturé (interface eth0)."


def test_given_arp_spoofing_when_analyse_then_attack_is_noted_in_summary():
    # Given
    capture = Capture()
    real_reply = Ether(src="00:00:00:00:00:01") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:00:00:00:00:01")
    spoofed_reply = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    feed(capture, [real_reply, spoofed_reply])

    # When
    capture.analyse()

    # Then
    assert [attack.attack_type for attack in capture.attacks] == ["arp_spoofing"]
    assert "1 tentative(s) d'attaque détectée(s) : ARP spoofing." in capture.summary


def test_given_legit_traffic_when_analyse_then_summary_says_everything_is_fine():
    # Given
    capture = Capture()
    feed(capture, [Ether() / IP() / TCP()])

    # When
    capture.analyse()

    # Then
    assert capture.attacks == []
    assert capture.summary.endswith("Aucune attaque détectée, tout va bien.")


def test_given_marker_in_traffic_when_analyse_then_flag_is_kept():
    # Given
    capture = Capture()
    injection = Raw(b"GET /?id=1 OR 1=1&q=ESGI{abc123} HTTP/1.1\r\n\r\n")
    feed(capture, [Ether() / IP() / TCP() / injection])

    # When
    capture.analyse()

    # Then
    assert capture.flag == "ESGI{abc123}"


def test_given_pcap_file_when_capture_traffic_then_packets_are_read_without_asking_interface(tmp_path):
    # Given
    pcap_file = tmp_path / "attaque.pcap"
    packets = [Ether() / IP() / TCP(), Ether() / ARP()]
    wrpcap(str(pcap_file), packets)
    with patch("src.tp1.utils.capture.choose_interface") as mock_choose_interface:
        capture = Capture(pcap_file=str(pcap_file))

    # When
    capture.capture_traffic()

    # Then
    mock_choose_interface.assert_not_called()
    assert capture.get_packet_count() == len(packets)
    assert capture.get_source() == f"fichier {pcap_file}"
