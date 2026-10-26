from collections import Counter

from scapy.all import Packet, conf, sniff

from src.tp1.utils.config import logger
from src.tp1.utils.detection import TrafficAnalyzer
from src.tp1.utils.lib import choose_interface, get_protocol

TIMEOUT = 60


class Capture:
    def __init__(self, pcap_file: str | None = None, timeout: int = TIMEOUT) -> None:
        self.pcap_file = pcap_file
        self.timeout = timeout
        self.interface = choose_interface() if pcap_file is None else ""
        self.listen_socket = None
        self.protocol_counts = Counter()
        self.analyzer = TrafficAnalyzer()
        self.protocols = {}
        self.attacks = []
        self.flag = None
        self.summary = ""

    def open_socket(self) -> None:
        """
        Open the capture socket: the only step that needs root privileges
        """
        if self.pcap_file is None:
            self.listen_socket = conf.L2listen(iface=self.interface)

    def capture_traffic(self) -> None:
        """
        Capture the traffic of an interface (or read the pcap file)
        """
        if self.pcap_file is not None:
            sniff(offline=self.pcap_file, prn=self.add_packet, store=False)
            logger.info(f"{self.get_packet_count()} packets read from {self.pcap_file}")
            return
        if self.listen_socket is None:
            self.open_socket()
        logger.info(
            f"Capturing on {self.interface} for {self.timeout} seconds (Ctrl+C to stop early)"
        )
        try:
            # sniff stops cleanly on Ctrl+C, the packets already received stay counted
            sniff(opened_socket=self.listen_socket, timeout=self.timeout, prn=self.add_packet, store=False)
        finally:
            self.listen_socket.close()
            self.listen_socket = None
        logger.info(f"{self.get_packet_count()} packets captured")

    def add_packet(self, packet: Packet) -> None:
        """
        Count and analyse a packet as soon as it arrives, without keeping it in memory
        """
        self.protocol_counts[get_protocol(packet)] += 1
        self.analyzer.add_packet(packet)

    def get_packet_count(self) -> int:
        """
        Return the number of captured packets
        """
        return sum(self.protocol_counts.values())

    def get_source(self) -> str:
        """
        Return the listened interface or the read pcap file
        """
        return f"file {self.pcap_file}" if self.pcap_file is not None else f"interface {self.interface}"

    def sort_network_protocols(self) -> dict:
        """
        Return the captured protocols, from the most used to the least used
        """
        all_protocols = self.get_all_protocols()
        return dict(sorted(all_protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return each captured protocol with its packet count
        """
        return dict(self.protocol_counts)

    def analyse(self) -> None:
        """
        Analyse the captured traffic: sort the protocols, report the attacks
        (type, protocol, attacker IP/MAC) and the marker, then build the summary
        """
        self.protocols = self.sort_network_protocols()
        for protocol, count in self.protocols.items():
            logger.info(f"{protocol}: {count} packets")

        self.attacks = self.analyzer.get_attacks()
        for attack in self.attacks:
            logger.warning(f"Attack attempt: {attack.describe()}")
        if not self.attacks:
            logger.info("No attack detected, all good")

        self.flag = self.analyzer.flag
        if self.flag is not None:
            logger.info(f"Marker found: {self.flag}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        """
        Build the capture's text summary
        """
        total = sum(self.protocols.values())
        if total == 0:
            return f"No packet captured ({self.get_source()})."

        most_used = next(iter(self.protocols))
        summary = (
            f"{total} packets were analysed ({self.get_source()}). "
            f"The most used protocol is {most_used} with {self.protocols[most_used]} packets. "
        )
        return summary + self._gen_attacks_summary()

    def _gen_attacks_summary(self) -> str:
        """
        Build the part of the summary about the traffic's legitimacy
        """
        if not self.attacks:
            return "No attack detected, all good."
        attack_names = ", ".join(attack.name for attack in self.attacks)
        return f"{len(self.attacks)} attack attempt(s) detected: {attack_names}."
