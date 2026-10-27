import base64
import re
import socket

from .config import logger

FLAG_RE = re.compile(rb"ESGI\{[^}]*\}")
# un jeton = un bloc base64 isole au milieu d'eventuelles invites
TOKEN_RE = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")


def _cle_en_octets(key) -> bytes:
    """La cle d'encodage, telle que revelee par la page web, en octets utf-8."""
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    return key.encode()


def xor_octets(data: bytes, key: bytes) -> bytes:
    """XOR octet a octet avec une cle repetee."""
    if not key:
        raise ValueError("cle vide")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decoder_jeton(token: bytes | str, key: bytes) -> bytes:
    """Decode un jeton : base64 puis XOR avec la cle (ordre du sujet)."""
    if isinstance(token, str):
        token = token.encode()
    return xor_octets(base64.b64decode(token), key)


def _extraire_jeton(line: bytes) -> bytes | None:
    m = TOKEN_RE.search(line)
    return m.group() if m else None


def _recevoir_morceau(sock: socket.socket, num_round: int) -> bytes:
    try:
        return sock.recv(4096)
    except TimeoutError:
        raise RuntimeError(f"pas de donnees recues (round {num_round})")


def _chercher_flag_final(buffer: bytes) -> str | None:
    m = FLAG_RE.search(buffer)
    return m.group().decode() if m else None


def _repondre_lignes(sock: socket.socket, buffer: bytes, cle: bytes, num_round: int) -> bytes:
    """Repond a chaque ligne complete du tampon et renvoie le reste (ligne pas encore finie)."""
    while b"\n" in buffer:
        line, buffer = buffer.split(b"\n", 1)
        jeton = _extraire_jeton(line)
        if jeton is None:
            continue
        plain = decoder_jeton(jeton, cle)
        sock.sendall(plain + b"\n")
        logger.info(f"round {num_round} : repondu {plain!r}")
    return buffer


def lancer_phase_reseau(host: str, port, key, timeout: float = 5.0, max_rounds: int = 200) -> str:
    """Joue les rounds (decoder/repondre sous ~5 s) et renvoie le drapeau final."""
    cle = _cle_en_octets(key)
    logger.info(f"connexion TCP a {host}:{port}")
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buffer = b""
        for num_round in range(1, max_rounds + 1):
            morceau = _recevoir_morceau(sock, num_round)
            if not morceau:
                break
            buffer += morceau

            flag = _chercher_flag_final(buffer)
            if flag is not None:
                logger.info(f"drapeau final recu apres {num_round - 1} rounds")
                return flag

            buffer = _repondre_lignes(sock, buffer, cle, num_round)

    raise RuntimeError("drapeau final non recu (connexion fermee)")
