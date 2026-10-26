import base64
import re
import socket

from .config import logger

FLAG_RE = re.compile(rb"ESGI\{[^}]*\}")
# un jeton = un bloc base64 isole au milieu d'eventuelles invites
TOKEN_RE = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")


def _key_to_bytes(key) -> bytes:
    """La cle d'encodage, telle que revelee par la page web, en octets utf-8."""
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    return key.encode()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR octet a octet avec une cle repetee."""
    if not key:
        raise ValueError("cle vide")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode_token(token: bytes | str, key: bytes) -> bytes:
    """Decode un jeton : base64 puis XOR avec la cle (ordre du sujet)."""
    if isinstance(token, str):
        token = token.encode()
    return xor_bytes(base64.b64decode(token), key)


def _extract_token(line: bytes) -> bytes | None:
    m = TOKEN_RE.search(line)
    return m.group() if m else None


def run_network_phase(host: str, port, key, timeout: float = 5.0, max_rounds: int = 200) -> str:
    """Joue les rounds (decoder/repondre sous ~5 s) et renvoie le drapeau final."""
    key_bytes = _key_to_bytes(key)
    logger.info(f"connexion TCP a {host}:{port}")
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buffer = b""
        for round_no in range(1, max_rounds + 1):
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                raise RuntimeError(f"pas de donnees recues (round {round_no})")
            if not chunk:
                break
            buffer += chunk

            flag = FLAG_RE.search(buffer)
            if flag:
                final = flag.group().decode()
                logger.info(f"drapeau final recu apres {round_no - 1} rounds")
                return final

            # traite chaque ligne complete du tampon
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                token = _extract_token(line)
                if token is None:
                    continue
                plain = decode_token(token, key_bytes)
                sock.sendall(plain + b"\n")
                logger.info(f"round {round_no} : repondu {plain!r}")

    raise RuntimeError("drapeau final non recu (connexion fermee)")
