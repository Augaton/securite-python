import time

import pytest
from scapy.all import ARP, IP, TCP, Ether, Raw

from src.tp1.utils.detection import analyse_packets

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
    result = analyse_packets(packets).get_attacks()

    # Then
    assert result == []


def test_given_mac_claiming_gateway_and_victim_when_detect_arp_spoofing_then_attacker_is_found():
    # Given
    real_replies = [arp_reply(GATEWAY_IP, GATEWAY_MAC), arp_reply(VICTIM_IP, VICTIM_MAC)]
    spoofed_replies = [arp_reply(GATEWAY_IP, ATTACKER_MAC), arp_reply(VICTIM_IP, ATTACKER_MAC)] * 3

    # When
    result = analyse_packets(real_replies + spoofed_replies).get_arp_spoofing_attacks()

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
    result = analyse_packets(packets).get_arp_spoofing_attacks()

    # Then
    assert [attack.attacker_mac for attack in result] == [ATTACKER_MAC]


def test_given_attacker_ip_traffic_when_detect_arp_spoofing_then_its_real_ip_is_found():
    # Given
    own_traffic = Ether(src=ATTACKER_MAC) / IP(src=ATTACKER_IP) / TCP()
    packets = [
        own_traffic,
        arp_reply(GATEWAY_IP, GATEWAY_MAC),
        arp_reply(ATTACKER_IP, ATTACKER_MAC),
        arp_reply(GATEWAY_IP, ATTACKER_MAC),
    ]

    # When
    result = analyse_packets(packets).get_arp_spoofing_attacks()

    # Then
    assert result[0].attacker_ip == ATTACKER_IP
    assert result[0].details == f"se fait passer pour {GATEWAY_IP}"


def test_given_arp_probes_without_ip_when_detect_arp_spoofing_then_they_are_ignored():
    # Given
    packets = [arp_reply("0.0.0.0", VICTIM_MAC), arp_reply("0.0.0.0", ATTACKER_MAC)]

    # When
    result = analyse_packets(packets).get_arp_spoofing_attacks()

    # Then
    assert result == []


def syn(source_ip: str, destination_ip: str, port: int, flags: str = "S") -> Ether:
    """
    Demande de connexion TCP de source_ip vers destination_ip:port
    """
    return Ether(src=ATTACKER_MAC) / IP(src=source_ip, dst=destination_ip) / TCP(dport=port, flags=flags)


def test_given_syn_to_many_ports_when_detect_syn_scan_then_scanner_is_found():
    # Given
    packets = [syn(ATTACKER_IP, VICTIM_IP, port) for port in range(1, 21)]

    # When
    result = analyse_packets(packets).get_syn_scan_attacks()

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.attacker_ip) == ("syn_scan", "TCP", ATTACKER_IP)
    assert attack.get_attacker() == ATTACKER_IP
    assert attack.attacker_mac == ATTACKER_MAC
    assert attack.details == f"20 ports visés sur {VICTIM_IP}"


def test_given_web_browsing_when_detect_syn_scan_then_nothing_is_found():
    # Given
    packets = [syn(VICTIM_IP, f"93.184.216.{server}", 443) for server in range(1, 30)]

    # When
    result = analyse_packets(packets).get_syn_scan_attacks()

    # Then
    assert result == []


def test_given_syn_ack_answers_when_detect_syn_scan_then_they_are_not_counted():
    # Given
    packets = [syn(VICTIM_IP, ATTACKER_IP, port, flags="SA") for port in range(1, 21)]

    # When
    result = analyse_packets(packets).get_syn_scan_attacks()

    # Then
    assert result == []


def test_given_few_ports_when_detect_syn_scan_then_nothing_is_found():
    # Given
    packets = [syn(ATTACKER_IP, VICTIM_IP, port) for port in range(1, 10)]

    # When
    result = analyse_packets(packets).get_syn_scan_attacks()

    # Then
    assert result == []


def http(payload: bytes, source_ip: str = ATTACKER_IP) -> Ether:
    """
    Paquet TCP vers le port 80 de la victime contenant payload
    """
    return Ether(src=ATTACKER_MAC) / IP(src=source_ip, dst=VICTIM_IP) / TCP(dport=80) / Raw(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /login?user=admin%27%20OR%20%271%27%3D%271&pass=x HTTP/1.1\r\nHost: victime\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: victime\r\n\r\nusername=admin'--&password=x",
        b"GET /article?id=1+UNION+SELECT+username,password+FROM+users HTTP/1.1\r\n\r\n",
        b"GET /article?id=1 OR 1=1 HTTP/1.1\r\n\r\n",
    ],
)
def test_given_injection_in_http_request_when_detect_sql_injection_then_attacker_is_found(payload):
    # Given
    packets = [http(payload)]

    # When
    result = analyse_packets(packets).get_sql_injection_attacks()

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.get_attacker()) == (
        "sql_injection",
        "TCP",
        ATTACKER_IP,
    )
    assert attack.attacker_mac == ATTACKER_MAC
    assert attack.details.startswith(f"requête HTTP vers {VICTIM_IP} : ")


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /index.html HTTP/1.1\r\nHost: site\r\nAccept: text/html,*/*;q=0.8\r\n\r\n",
        b'POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"color":"#ff0000","name":"andy"}',
        b"\x17\x03\x03 ' -- donnees chiffrees ' OR '1'='1",
    ],
)
def test_given_normal_or_encrypted_traffic_when_detect_sql_injection_then_nothing_is_found(payload):
    # When
    result = analyse_packets([http(payload)]).get_sql_injection_attacks()

    # Then
    assert result == []


def test_given_several_injections_from_same_attacker_when_detect_sql_injection_then_one_alert():
    # Given
    packets = [http(b"GET /?id=1' OR '1'='1 HTTP/1.1\r\n\r\n")] * 5

    # When
    result = analyse_packets(packets).get_sql_injection_attacks()

    # Then
    assert len(result) == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"GET /?id=1'+UNION+SELECT+'ESGI%7Bs3ed_b1n0me%7D'-- HTTP/1.1\r\n\r\n",
        b"POST /login HTTP/1.1\r\n\r\nuser=admin' OR '1'='1' -- ESGI{s3ed_b1n0me}",
    ],
)
def test_given_marker_in_traffic_when_find_flag_then_return_it(payload):
    # Given
    packets = [http(b"GET / HTTP/1.1\r\n\r\n"), http(payload)]

    # When
    result = analyse_packets(packets).flag

    # Then
    assert result == "ESGI{s3ed_b1n0me}"


def test_given_no_marker_when_find_flag_then_return_none():
    # When
    result = analyse_packets([http(b"GET / HTTP/1.1\r\n\r\n")]).flag

    # Then
    assert result is None


def test_given_malformed_arp_packet_when_detect_attacks_then_it_is_ignored_without_crashing():
    # Given
    # ARP avec un type de protocole inconnu : scapy donne psrc en octets bruts au lieu de texte
    malformed = Ether(bytes(Ether(src=ATTACKER_MAC) / ARP(op=2, ptype=0x1234, plen=5, hwsrc=ATTACKER_MAC)))
    packets = [arp_reply(GATEWAY_IP, ATTACKER_MAC), malformed]

    # When
    result = analyse_packets(packets).get_attacks()

    # Then
    assert result == []


def test_given_real_owner_announcing_often_when_detect_arp_spoofing_then_newcomer_is_accused():
    # Given
    packets = [arp_reply(GATEWAY_IP, GATEWAY_MAC)] * 10 + [arp_reply(GATEWAY_IP, ATTACKER_MAC)]

    # When
    result = analyse_packets(packets).get_arp_spoofing_attacks()

    # Then
    assert [attack.attacker_mac for attack in result] == [ATTACKER_MAC]


def test_given_mac_shared_by_several_hosts_when_detect_arp_spoofing_then_nothing_is_found():
    # Given
    # capture générée : plusieurs machines légitimes ont la même MAC, sans jamais se disputer une IP
    packets = [arp_reply(f"192.168.1.{host}", VICTIM_MAC) for host in (10, 11, 12, 13)]

    # When
    result = analyse_packets(packets).get_arp_spoofing_attacks()

    # Then
    assert result == []


def test_given_marker_with_control_characters_when_find_flag_then_it_is_rejected():
    # Given
    # \x1b] ... \x07 : séquence d'échappement qui changerait le titre du terminal où s'affichent les logs
    packets = [http(b"GET /?q=ESGI{\x1b]0;pwned\x07} HTTP/1.1\r\n\r\n")]

    # When
    result = analyse_packets(packets).flag

    # Then
    assert result is None


def test_given_packet_full_of_marker_starts_when_find_flag_then_search_stays_fast():
    # Given
    packets = [http(b"ESGI{" * 12000)]

    # When
    start = time.perf_counter()
    result = analyse_packets(packets).flag

    # Then
    assert result is None
    assert time.perf_counter() - start < 1
