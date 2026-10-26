import argparse

from .utils.config import logger
from .utils.network import run_network_phase
from .utils.session import WebPhase


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="TP3 : chaine d'attaque web (fuzzing + captcha) puis reseau")
    parser.add_argument("--target", required=True, help="URL de la cible web, ex. http://localhost:8080")
    parser.add_argument(
        "--wordlist", default=None, help="wordlist de fuzzing (defaut : wordlist.txt embarquee)"
    )
    args = parser.parse_args(argv)

    logger.info(f"cible : {args.target}")

    # Phase web -> flag1, plus l'adresse TCP et la cle d'encodage a utiliser ensuite
    web = WebPhase(args.target, wordlist=args.wordlist)
    data = web.run()
    print(f"[+] FLAG1: {data['flag1']}")

    # Phase reseau -> drapeau final
    final = run_network_phase(data["host"], data["port"], data["key"])
    print(f"[+] FLAG_FINAL: {final}")


if __name__ == "__main__":
    main()
