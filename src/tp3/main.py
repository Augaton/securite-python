import argparse

from .utils.config import logger
from .utils.network import lancer_phase_reseau
from .utils.session import WebPhase


def constr_parser_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TP3 : chaine d'attaque web (fuzzing + captcha) puis reseau")
    parser.add_argument("--target", required=True, help="URL de la cible web, ex. http://localhost:8080")
    parser.add_argument(
        "--wordlist", default=None, help="wordlist de fuzzing (defaut : wordlist.txt embarquee)"
    )
    return parser


def lancer_phase_web(target: str, wordlist: str | None) -> dict:
    """Phase web -> flag1, plus l'adresse TCP et la cle d'encodage a utiliser ensuite."""
    data = WebPhase(target, wordlist=wordlist).derouler_phase_web()
    print(f"[+] FLAG1: {data['flag1']}")
    return data


def main(argv: list[str] | None = None) -> None:
    args = constr_parser_args().parse_args(argv)
    logger.info(f"cible : {args.target}")

    data = lancer_phase_web(args.target, args.wordlist)

    # Phase reseau -> drapeau final
    final = lancer_phase_reseau(data["host"], data["port"], data["key"])
    print(f"[+] FLAG_FINAL: {final}")


if __name__ == "__main__":
    main()
