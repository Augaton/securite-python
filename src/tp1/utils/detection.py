import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

from scapy.all import ARP, IP, TCP, Ether, IPv6, Packet, Raw

from src.tp1.utils.lib import get_protocol

UNKNOWN = "unknown"
ETHERTYPE_IPV4 = 0x0800
SYN_SCAN_MIN_PORTS = 10
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")
SQL_INJECTION_PATTERN = re.compile(
    r"""["']\s*(or|and)\s*["']?\w*["']?\s*="""  # ' OR '1'='1, ' AND 1=1, ' or ''='
    r"|\b(or|and)\s+\d+\s*=\s*\d+"  # OR 1=1 (numeric field, no quotes)
    r"|\bunion\s+(all\s+)?select\b"  # UNION SELECT
    r"|;\s*(drop|delete|insert|update|select)\b"  # ; DROP TABLE
    r"""|["']\s*(--|#)(\s|&|$)|["']\s*/\*"""  # ' -- (end of the real query commented out)
    r"|\b(sleep|pg_sleep|benchmark)\s*\("  # time-based blind injection
    r"|\binformation_schema\b",
    re.IGNORECASE,
)
# Printable and bounded: no control codes in the logs, no runaway search
FLAG_PATTERN = re.compile(r"ESGI\{[\x21-\x7c\x7e]{1,100}\}")


@dataclass(frozen=True)
class Attack:
    """
    Attack attempt spotted in the traffic
    """

    attack_type: str
    name: str
    protocol: str
    attacker_ip: str
    attacker_mac: str
    details: str

    def get_attacker(self) -> str:
        """
        Address that identifies the attacker: its MAC for ARP, its IP otherwise
        """
        return self.attacker_mac if self.protocol == "ARP" else self.attacker_ip

    def describe(self) -> str:
        """
        Describe the attack on a single line
        """
        return (
            f"{self.name} ({self.protocol}) from {self.attacker_ip} / {self.attacker_mac}: {self.details}"
        )


def get_source_mac(packet: Packet) -> str:
    """
    Return a packet's source MAC address
    """
    return packet[Ether].src if packet.haslayer(Ether) else UNKNOWN


def get_source_ip(packet: Packet) -> str:
    """
    Return a packet's source IP address (IPv4 or IPv6)
    """
    for ip_layer in (IP, IPv6):
        if packet.haslayer(ip_layer):
            return packet[ip_layer].src
    return UNKNOWN


def get_destination_ip(packet: Packet) -> str:
    """
    Return a packet's destination IP address (IPv4 or IPv6)
    """
    for ip_layer in (IP, IPv6):
        if packet.haslayer(ip_layer):
            return packet[ip_layer].dst
    return UNKNOWN


def is_ipv4_arp(arp: ARP) -> bool:
    """
    Check this is IPv4 ARP over Ethernet: in a malformed ARP the addresses are raw bytes
    """
    # hwlen and plen are None in a hand-crafted packet
    return (
        arp.hwtype == 1 and arp.ptype == ETHERTYPE_IPV4 and arp.hwlen in (None, 6) and arp.plen in (None, 4)
    )


def get_http_request(packet: Packet) -> str | None:
    """
    Return a packet's cleartext HTTP request, URL-decoded (encrypted HTTPS cannot be analysed)

    :return: request text, None if the packet holds no HTTP request
    """
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    if not payload.startswith(HTTP_METHODS):
        return None
    return unquote_plus(payload.decode("latin-1"))


def find_sql_injection(packet: Packet, source_ip: str) -> Attack | None:
    """
    Look for a SQL injection in a packet's HTTP request

    :return: the attack, None if the packet holds none
    """
    request = get_http_request(packet)
    if request is None or not SQL_INJECTION_PATTERN.search(request):
        return None
    request_line = request.splitlines()[0][:100]
    # !r escapes the control characters sent by the attacker before they reach the terminal
    return Attack(
        attack_type="sql_injection",
        name="SQL injection",
        protocol=get_protocol(packet),
        attacker_ip=source_ip,
        attacker_mac=get_source_mac(packet),
        details=f"HTTP request to {get_destination_ip(packet)}: {request_line!r}",
    )


def search_flag(packet: Packet) -> str | None:
    """
    Look for the marker ESGI{...} in a packet, even when URL-encoded

    :return: the marker, None if it is not in the packet
    """
    # original = bytes received; bytes(packet) would rebuild the whole packet (much slower)
    raw_packet = packet.original or bytes(packet)
    if b"ESGI" not in raw_packet:
        return None
    match = FLAG_PATTERN.search(unquote(raw_packet.decode("latin-1")))
    return match.group(0) if match else None


class TrafficAnalyzer:
    """
    Analyse the traffic packet by packet, without keeping the packets
    """

    def __init__(self) -> None:
        self.arp_macs_by_ip = defaultdict(dict)  # {IP: {MAC: arrival rank}}
        self.arp_ips_by_mac = defaultdict(set)
        # Real IP of a MAC, seen in its IP traffic: under ARP spoofing the announced IP is the victim's
        self.ip_by_mac = {}
        self.syn_ports_by_ip = defaultdict(set)
        self.syn_targets_by_ip = defaultdict(set)
        self.syn_mac_by_ip = {}
        self.sql_injections = {}
        self.flag = None

    def add_packet(self, packet: Packet) -> None:
        """
        Take a captured packet into account
        """
        source_ip = get_source_ip(packet)
        if source_ip != UNKNOWN:
            self.ip_by_mac.setdefault(get_source_mac(packet), source_ip)
        if packet.haslayer(ARP):
            self.add_arp(packet[ARP])
        if packet.haslayer(TCP):
            self.add_tcp(packet, source_ip)
        if self.flag is None:
            self.flag = search_flag(packet)

    def add_arp(self, arp: ARP) -> None:
        """
        Record the ARP announcement "IP psrc is at MAC hwsrc" (0.0.0.0: host with no IP, ignored)
        """
        if is_ipv4_arp(arp) and arp.psrc != "0.0.0.0":
            macs = self.arp_macs_by_ip[arp.psrc]
            macs.setdefault(arp.hwsrc, len(macs))
            self.arp_ips_by_mac[arp.hwsrc].add(arp.psrc)

    def add_tcp(self, packet: Packet, source_ip: str) -> None:
        """
        Record lone SYNs (scan) and look for a SQL injection in HTTP requests
        """
        if packet[TCP].flags == "S":
            self.syn_ports_by_ip[source_ip].add(packet[TCP].dport)
            self.syn_targets_by_ip[source_ip].add(get_destination_ip(packet))
            self.syn_mac_by_ip.setdefault(source_ip, get_source_mac(packet))
        # No elif: a packet crafted with scapy is a SYN by default, even when it carries a request
        if source_ip not in self.sql_injections:
            injection = find_sql_injection(packet, source_ip)
            if injection is not None:
                self.sql_injections[source_ip] = injection

    def get_attacks(self) -> list[Attack]:
        """
        Return every attack attempt found
        """
        ip_attacks = self.get_syn_scan_attacks() + self.get_sql_injection_attacks()
        other_attacker_macs = {attack.attacker_mac for attack in ip_attacks}
        return self.get_arp_spoofing_attacks(other_attacker_macs) + ip_attacks

    def find_arp_spoofers(self, other_attacker_macs: set[str]) -> dict[str, set[str]]:
        """
        Return the MACs that spoof IPs, with the spoofed IPs:
        - a MAC that announces several IPs spoofs them all
        - for an IP announced by several MACs, we accuse the one already suspect (several IPs, or source
          of another attack), otherwise the last to arrive (like arpwatch). Not the number of
          announcements: the real gateway often makes more of them than the attacker
        """
        several_ips_macs = {mac for mac, ips in self.arp_ips_by_mac.items() if len(ips) > 1}
        suspect_macs = several_ips_macs | other_attacker_macs
        spoofed_ips_by_mac = defaultdict(set)
        for mac in several_ips_macs:
            spoofed_ips_by_mac[mac] |= self.arp_ips_by_mac[mac] - {self.ip_by_mac.get(mac)}
        for ip, macs in self.arp_macs_by_ip.items():
            if len(macs) > 1:
                spoofer = max(macs, key=lambda mac: (mac in suspect_macs, macs[mac]))
                spoofed_ips_by_mac[spoofer].add(ip)
        return spoofed_ips_by_mac

    def get_arp_spoofing_attacks(self, other_attacker_macs: set[str] | None = None) -> list[Attack]:
        """
        Return the ARP spoofing attacks: fake ARP announcements to receive another host's traffic
        """
        return [
            Attack(
                attack_type="arp_spoofing",
                name="ARP spoofing",
                protocol="ARP",
                attacker_ip=self.ip_by_mac.get(mac, UNKNOWN),
                attacker_mac=mac,
                details=f"impersonates {', '.join(sorted(spoofed_ips))}",
            )
            for mac, spoofed_ips in self.find_arp_spoofers(other_attacker_macs or set()).items()
        ]

    def get_syn_scan_attacks(self) -> list[Attack]:
        """
        Return the SYN scans: lone SYNs to at least SYN_SCAN_MIN_PORTS different ports
        """
        return [
            Attack(
                attack_type="syn_scan",
                name="SYN scan",
                protocol="TCP",
                attacker_ip=ip,
                attacker_mac=self.syn_mac_by_ip[ip],
                details=f"{len(ports)} ports targeted on {', '.join(sorted(self.syn_targets_by_ip[ip]))}",
            )
            for ip, ports in self.syn_ports_by_ip.items()
            if len(ports) >= SYN_SCAN_MIN_PORTS
        ]

    def get_sql_injection_attacks(self) -> list[Attack]:
        """
        Return the SQL injections: one per attacker, with its first suspicious request
        """
        return list(self.sql_injections.values())


def analyse_packets(packets: list[Packet]) -> TrafficAnalyzer:
    """
    Analyse already-captured packets

    :param packets: packets to analyse
    :return: the analyzer, with the attacks (get_attacks) and the marker (flag) found
    """
    analyzer = TrafficAnalyzer()
    for packet in packets:
        analyzer.add_packet(packet)
    return analyzer
