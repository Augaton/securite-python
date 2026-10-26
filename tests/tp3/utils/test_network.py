import base64
import socket
import threading

from src.tp3.utils.network import decode_token, run_network_phase, xor_bytes

KEY = b"k3y"


def test_xor_is_involutive():
    assert xor_bytes(xor_bytes(b"hello", KEY), KEY) == b"hello"


def test_decode_token():
    plain = b"round-token"
    token = base64.b64encode(xor_bytes(plain, KEY))  # base64 puis XOR, a l'envers
    assert decode_token(token, KEY) == plain


def _serve_rounds(server: socket.socket, rounds: int, flag: bytes):
    """Serveur jouet : envoie des jetons, verifie les reponses, livre le drapeau."""
    conn, _ = server.accept()
    with conn:
        for i in range(rounds):
            plain = f"token{i}".encode()
            token = base64.b64encode(xor_bytes(plain, KEY))
            conn.sendall(token + b"\n")
            reply = b""
            while b"\n" not in reply:
                reply += conn.recv(1024)
            assert reply.strip() == plain
        conn.sendall(b"Bravo: " + flag + b"\n")


def test_run_network_phase_plays_rounds_and_returns_flag():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    flag = b"ESGI{chain_final}"
    thread = threading.Thread(target=_serve_rounds, args=(server, 3, flag))
    thread.start()

    result = run_network_phase("127.0.0.1", port, KEY, timeout=5.0)
    thread.join(timeout=5)
    server.close()

    assert result == "ESGI{chain_final}"
