# securite-python

TP de sécurité Python (ESGI 4A), à partir du template du prof.

| TP  | Sujet                                                        | État             |
| --- | ------------------------------------------------------------ | ---------------- |
| TP1 | Capture réseau (scapy), détection d'attaques, rapport PDF    | fait             |
| TP2 | Triage statique de malwares (hash, entropie, IOC, YARA)      | fait             |
| TP3 | Captchas                                                     | pas encore fait  |

## Installation

Python 3.11+ et [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/Augaton/securite-python.git
cd securite-python
poetry lock
poetry install
```

## TP1 — Capture réseau et détection d'attaques

Écoute une interface (ou lit un `.pcap`), compte les paquets par protocole, repère des attaques et
génère un rapport.

```bash
# analyser un fichier pcap (pas besoin de root, comme le correcteur)
python src/tp1/main.py capture.pcap

# écouter le réseau en direct (root requis pour ouvrir le socket)
sudo "$(poetry env info --path)/bin/tp1"
```

Options : `--timeout 120` (durée de capture, 60 s par défaut), `--pcap fichier.pcap` / `-r fichier.pcap`.

**Sorties** (dans le dossier courant) : `report.pdf`, `report.json` (résultat du correcteur), `graph.svg`,
`app.log`.

**Détections** : ARP spoofing, scan SYN, injection SQL, et le drapeau `ESGI{...}`. Les protocoles de
chaque paquet sont relevés couche par couche (Ethernet, IP, TCP, UDP, ICMP, DNS, ARP, HTTP).

## TP2 — Triage de malwares

Pour chaque échantillon, écrit un `<échantillon>.triage.json` contenant : SHA-256 et MD5, entropie de
Shannon (repère les fichiers packés/chiffrés), type de fichier, IOC (URL, IPv4, domaines, emails), règles
YARA déclenchées et le vrai drapeau `ESGI{...}` (les faux drapeaux `..._decoy_..` sont ignorés).

```bash
python src/tp2/main.py dossier_des_echantillons
```

Sans argument, analyse le dossier courant (puis un sous-dossier `student/` s'il existe).

Les règles sont dans `src/tp2/rules/malware.yar`. YARA n'est pas obligatoire : si `yara-python` est
installé il est utilisé, sinon un moteur de repli en Python pur applique les mêmes règles.

## Tests et pre-commit

```bash
poetry run pytest
pre-commit run --all-files
```

La capture est simulée, pas besoin de root. Le `conftest.py` à la racine fait tourner les tests même si
le projet n'est pas installé ou que son dossier est en lecture seule.

## Structure

```
src/
  config.py          # logging + chargement du .env
  tp1/               # capture, détection, rapport PDF/JSON, graphique
  tp2/               # triage : hash, entropie, IOC, YARA, drapeau
tests/               # tests pytest par TP
```
