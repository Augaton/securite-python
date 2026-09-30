from scapy.all import sniff

from src.tp1.utils.config import logger
from src.tp1.utils.lib import choose_interface, get_protocol

# La capture s'arrête au bout de 100 paquets ou de 30 secondes
NB_PACKETS = 100
TIMEOUT = 30


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.protocols = {}  # {protocole: nombre de paquets}
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        logger.info(f"Capture sur {self.interface} ({NB_PACKETS} paquets max ou {TIMEOUT} secondes)")
        self.packets = sniff(iface=self.interface, count=NB_PACKETS, timeout=TIMEOUT)
        logger.info(f"{len(self.packets)} paquets capturés")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols (du plus utilisé au moins utilisé)
        """
        all_protocols = self.get_all_protocols()
        return dict(sorted(all_protocols.items(), key=lambda item: item[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        protocols = {}
        for packet in self.packets:
            protocol = get_protocol(packet)
            if protocol in protocols:
                protocols[protocol] += 1
            else:
                protocols[protocol] = 1
        return protocols

    def analyse(self) -> None:
        """
        Compte les paquets de chaque protocole et génère le résumé
        """
        self.protocols = self.sort_network_protocols()
        for protocol, count in self.protocols.items():
            logger.info(f"{protocol} : {count} paquets")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        total = sum(self.protocols.values())
        if total == 0:
            return f"Aucun paquet capturé sur {self.interface}."

        # le dictionnaire est trié donc le premier protocole est le plus utilisé
        most_used = list(self.protocols)[0]
        summary = (
            f"{total} paquets ont été capturés sur l'interface {self.interface}. "
            f"Le protocole le plus utilisé est {most_used} avec {self.protocols[most_used]} paquets."
        )
        return summary
