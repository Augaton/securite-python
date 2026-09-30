from scapy.all import ARP, IP, TCP, Ether

from src.tp1.utils.detection import detect_arp_spoofing, detect_attacks

GATEWAY_IP, GATEWAY_MAC = "192.168.1.1", "00:00:00:00:00:01"
VICTIM_IP, VICTIM_MAC = "192.168.1.10", "00:00:00:00:00:10"
ATTACKER_IP, ATTACKER_MAC = "192.168.1.66", "aa:bb:cc:dd:ee:ff"


def arp_reply(ip: str, mac: str) -> Ether:
    """
    Réponse ARP "ip est à mac" envoyée par mac
    """
    return Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac)


def test_given_legit_arp_traffic_when_detect_attacks_then_nothing_is_found():
    # Given
    packets = [arp_reply(GATEWAY_IP, GATEWAY_MAC), arp_reply(VICTIM_IP, VICTIM_MAC)]

    # When
    result = detect_attacks(packets)

    # Then
    assert result == []


def test_given_mac_claiming_gateway_and_victim_when_detect_arp_spoofing_then_attacker_is_found():
    # Given
    packets = [arp_reply(GATEWAY_IP, ATTACKER_MAC), arp_reply(VICTIM_IP, ATTACKER_MAC)] * 3

    # When
    result = detect_arp_spoofing(packets)

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.attacker_mac) == ("arp_spoofing", "ARP", ATTACKER_MAC)
    assert attack.get_attacker() == ATTACKER_MAC
    assert attack.details == f"se fait passer pour {GATEWAY_IP}, {VICTIM_IP}"


def test_given_gateway_ip_claimed_again_by_other_mac_when_detect_arp_spoofing_then_other_mac_is_accused():
    # Given
    packets = [arp_reply(GATEWAY_IP, GATEWAY_MAC)] + [arp_reply(GATEWAY_IP, ATTACKER_MAC)] * 3

    # When
    result = detect_arp_spoofing(packets)

    # Then
    assert [attack.attacker_mac for attack in result] == [ATTACKER_MAC]


def test_given_attacker_ip_traffic_when_detect_arp_spoofing_then_its_real_ip_is_found():
    # Given
    own_traffic = Ether(src=ATTACKER_MAC) / IP(src=ATTACKER_IP) / TCP()
    packets = [own_traffic, arp_reply(ATTACKER_IP, ATTACKER_MAC), arp_reply(GATEWAY_IP, ATTACKER_MAC)]

    # When
    result = detect_arp_spoofing(packets)

    # Then
    assert result[0].attacker_ip == ATTACKER_IP
    assert result[0].details == f"se fait passer pour {GATEWAY_IP}"


def test_given_arp_probes_without_ip_when_detect_arp_spoofing_then_they_are_ignored():
    # Given
    packets = [arp_reply("0.0.0.0", VICTIM_MAC), arp_reply("0.0.0.0", ATTACKER_MAC)]

    # When
    result = detect_arp_spoofing(packets)

    # Then
    assert result == []
