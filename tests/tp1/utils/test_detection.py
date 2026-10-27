import time

import pytest
from scapy.all import ARP, IP, TCP, Ether, Raw

from collections import Counter

from src.tp1.utils.detection import analyser_lst_pkt, choisir_usurpateur

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
    result = analyser_lst_pkt(packets).recup_attaques()

    # Then
    assert result == []


def test_given_mac_claiming_gateway_and_victim_when_detect_arp_spoofing_then_attacker_is_found():
    # Given
    packets = [arp_reply(GATEWAY_IP, ATTACKER_MAC), arp_reply(VICTIM_IP, ATTACKER_MAC)] * 3

    # When
    result = analyser_lst_pkt(packets).recup_attaques_arp()

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.attacker_mac) == ("arp_spoofing", "ARP", ATTACKER_MAC)
    assert attack.recup_attaquant() == ATTACKER_MAC
    assert attack.details == f"se fait passer pour {GATEWAY_IP}, {VICTIM_IP}"


def test_given_gateway_claimed_by_a_flooding_mac_when_detect_arp_spoofing_then_it_is_accused():
    # Given : la vraie passerelle répond une fois, l'usurpateur inonde la victime de réponses
    packets = [arp_reply(GATEWAY_IP, ATTACKER_MAC)] * 2 + [arp_reply(GATEWAY_IP, GATEWAY_MAC)]
    packets += [arp_reply(GATEWAY_IP, ATTACKER_MAC)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_arp()

    # Then
    assert [attack.attacker_mac for attack in result] == [ATTACKER_MAC]
    assert result[0].recup_attaquant() == ATTACKER_MAC


def test_given_arp_requests_carrying_a_shared_mac_when_detect_arp_spoofing_then_nothing_is_found():
    # Given : requêtes "qui a la passerelle ?" de 4 victimes, toutes avec le même hwsrc
    requests = [
        Ether(src=VICTIM_MAC) / ARP(op=1, hwsrc=ATTACKER_MAC, psrc=f"192.168.1.1{n}", pdst=GATEWAY_IP)
        for n in range(4)
    ]

    # When
    result = analyser_lst_pkt(requests).recup_attaques_arp()

    # Then
    assert result == []


def test_given_attacker_ip_traffic_when_detect_arp_spoofing_then_its_real_ip_is_found():
    # Given
    own_traffic = Ether(src=ATTACKER_MAC) / IP(src=ATTACKER_IP) / TCP()
    packets = [own_traffic, arp_reply(ATTACKER_IP, ATTACKER_MAC), arp_reply(GATEWAY_IP, ATTACKER_MAC)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_arp()

    # Then
    assert result[0].attacker_ip == ATTACKER_IP
    assert result[0].details == f"se fait passer pour {GATEWAY_IP}"


def test_given_arp_probes_without_ip_when_detect_arp_spoofing_then_they_are_ignored():
    # Given
    packets = [arp_reply("0.0.0.0", VICTIM_MAC), arp_reply("0.0.0.0", ATTACKER_MAC)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_arp()

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
    result = analyser_lst_pkt(packets).recup_attaques_scan_syn()

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.attacker_ip) == ("port_scan", "TCP", ATTACKER_IP)
    assert attack.recup_attaquant() == ATTACKER_IP
    assert attack.attacker_mac == ATTACKER_MAC
    assert attack.details == f"20 ports visés sur {VICTIM_IP}"


def test_given_web_browsing_when_detect_syn_scan_then_nothing_is_found():
    # Given
    packets = [syn(VICTIM_IP, f"93.184.216.{server}", 443) for server in range(1, 30)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_scan_syn()

    # Then
    assert result == []


def test_given_syn_ack_answers_when_detect_syn_scan_then_they_are_not_counted():
    # Given
    packets = [syn(VICTIM_IP, ATTACKER_IP, port, flags="SA") for port in range(1, 21)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_scan_syn()

    # Then
    assert result == []


def test_given_few_ports_when_detect_syn_scan_then_nothing_is_found():
    # Given
    packets = [syn(ATTACKER_IP, VICTIM_IP, port) for port in range(1, 10)]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_scan_syn()

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
    result = analyser_lst_pkt(packets).recup_attaques_sqli()

    # Then
    assert len(result) == 1
    attack = result[0]
    assert (attack.attack_type, attack.protocol, attack.recup_attaquant()) == (
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
    result = analyser_lst_pkt([http(payload)]).recup_attaques_sqli()

    # Then
    assert result == []


def test_given_several_injections_from_same_attacker_when_detect_sql_injection_then_one_alert():
    # Given
    packets = [http(b"GET /?id=1' OR '1'='1 HTTP/1.1\r\n\r\n")] * 5

    # When
    result = analyser_lst_pkt(packets).recup_attaques_sqli()

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
    result = analyser_lst_pkt(packets).recup_flag()

    # Then
    assert result == "ESGI{s3ed_b1n0me}"


def test_given_decoy_marker_before_injection_when_find_flag_then_return_the_attackers_one():
    # Given : un marqueur leurre envoyé plus tôt par une autre machine
    decoy = Ether(src=VICTIM_MAC) / IP(src=VICTIM_IP, dst=GATEWAY_IP) / TCP() / Raw(b"ESGI{leurre}")
    injection = http(b"GET /login?user=admin' OR 1=1-- &token=ESGI{vrai} HTTP/1.1\r\n\r\n")

    # When
    result = analyser_lst_pkt([decoy, injection]).recup_flag()

    # Then
    assert result == "ESGI{vrai}"


def test_given_pcap_where_all_ip_frames_share_one_mac_when_detect_attacks_then_each_attacker_is_found():
    # Given : comme le pcap du correcteur, toutes les trames IP et les hwsrc des requêtes ARP portent
    # la MAC de la machine qui a fabriqué le pcap (ici ATTACKER_MAC) ; scanner et injecteur diffèrent
    spoofer_mac, scanner_ip = "02:51:c0:cc:4e:a0", "192.168.1.99"
    victims = [f"192.168.1.1{n}" for n in range(4)]
    requests = [
        Ether(src=VICTIM_MAC) / ARP(op=1, hwsrc=ATTACKER_MAC, psrc=ip, pdst=GATEWAY_IP) for ip in victims
    ]
    gateway_replies = [arp_reply(GATEWAY_IP, GATEWAY_MAC) for _ in victims]
    spoofed_replies = [arp_reply(GATEWAY_IP, spoofer_mac) for _ in victims] * 3
    scan = [syn(scanner_ip, VICTIM_IP, port) for port in range(1, 21)]
    injection = [http(b"GET /?id=1' OR '1'='1 HTTP/1.1\r\n\r\n")]
    packets = spoofed_replies[:2] + gateway_replies + requests + scan + spoofed_replies[2:] + injection

    # When
    result = analyser_lst_pkt(packets).recup_attaques()

    # Then
    assert {(attack.attack_type, attack.recup_attaquant()) for attack in result} == {
        ("arp_spoofing", spoofer_mac),
        ("port_scan", scanner_ip),
        ("sql_injection", ATTACKER_IP),
    }


def test_given_no_marker_when_find_flag_then_return_none():
    # When
    result = analyser_lst_pkt([http(b"GET / HTTP/1.1\r\n\r\n")]).recup_flag()

    # Then
    assert result is None


def test_given_malformed_arp_packet_when_detect_attacks_then_it_is_ignored_without_crashing():
    # Given
    # ARP avec un type de protocole inconnu : scapy donne psrc en octets bruts au lieu de texte
    malformed = Ether(bytes(Ether(src=ATTACKER_MAC) / ARP(op=2, ptype=0x1234, plen=5, hwsrc=ATTACKER_MAC)))
    packets = [arp_reply(GATEWAY_IP, ATTACKER_MAC), malformed]

    # When
    result = analyser_lst_pkt(packets).recup_attaques()

    # Then
    assert result == []


def test_given_newcomer_also_claiming_a_victim_when_detect_arp_spoofing_then_accused():
    # Given : le 2e MAC réclame la passerelle ET une victime -> il usurpe plusieurs IP, donc suspect
    packets = [arp_reply(GATEWAY_IP, GATEWAY_MAC)] * 10 + [
        arp_reply(GATEWAY_IP, ATTACKER_MAC),
        arp_reply(VICTIM_IP, ATTACKER_MAC),
    ]

    # When
    result = analyser_lst_pkt(packets).recup_attaques_arp()

    # Then
    assert [attack.attacker_mac for attack in result] == [ATTACKER_MAC]


def test_given_spoofing_before_real_reply_when_detect_attacks_then_mac_of_scanner_is_accused():
    # Given
    spoofed_replies = [arp_reply(GATEWAY_IP, ATTACKER_MAC)] * 3
    real_reply = [arp_reply(GATEWAY_IP, GATEWAY_MAC)]
    scan = [syn(ATTACKER_IP, VICTIM_IP, port) for port in range(1, 21)]

    # When
    result = analyser_lst_pkt(spoofed_replies + real_reply + scan).recup_attaques()

    # Then
    arp_attacks = [attack for attack in result if attack.attack_type == "arp_spoofing"]
    assert [attack.attacker_mac for attack in arp_attacks] == [ATTACKER_MAC]


def test_given_marker_with_control_characters_when_find_flag_then_it_is_rejected():
    # Given
    # \x1b] ... \x07 : séquence d'échappement qui changerait le titre du terminal où s'affichent les logs
    packets = [http(b"GET /?q=ESGI{\x1b]0;pwned\x07} HTTP/1.1\r\n\r\n")]

    # When
    result = analyser_lst_pkt(packets).recup_flag()

    # Then
    assert result is None


def test_given_packet_full_of_marker_starts_when_find_flag_then_search_stays_fast():
    # Given
    packets = [http(b"ESGI{" * 12000)]

    # When
    start = time.perf_counter()
    result = analyser_lst_pkt(packets).recup_flag()

    # Then
    assert result is None
    assert time.perf_counter() - start < 1


def test_given_suspect_mac_when_choisir_usurpateur_then_accuse_it_even_with_less_replies():
    # Given
    nb_rep_par_mac = Counter({GATEWAY_MAC: 5, ATTACKER_MAC: 1})

    # When
    result = choisir_usurpateur(nb_rep_par_mac, {ATTACKER_MAC})

    # Then
    assert result == ATTACKER_MAC


def test_given_same_reply_count_when_choisir_usurpateur_then_accuse_the_last_arrived():
    # Given
    nb_rep_par_mac = Counter({GATEWAY_MAC: 2, ATTACKER_MAC: 2})

    # When
    result = choisir_usurpateur(nb_rep_par_mac, set())

    # Then
    assert result == ATTACKER_MAC
