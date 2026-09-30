# securite-python

Les TP de sécu python (ESGI 4A), fait à partir du template du prof.

- TP1 : capture réseau avec scapy + graphique pygal + rapport pdf + détection d'attaques -> fait
- TP2 : pas encore fait
- TP3 : les captchas, pas encore fait

## Installation

Il faut python 3.11 minimum et poetry. Rien d'autre à installer sur la machine : le graphique du pdf
est dessiné directement avec fpdf (avant on passait par cairo, qui manquait dans le bac à sable de
correction et faisait planter le programme au démarrage).

```bash
git clone https://github.com/Augaton/securite-python.git
cd securite-python
poetry lock
poetry install
```

## TP1

Le programme écoute une interface réseau avec scapy, compte le nombre de paquets par protocole, cherche
les attaques (ARP spoofing, scan SYN, injection SQL), fait un graphique avec pygal et génère un rapport pdf
(résumé, tableau, légitimité du trafic et graphique) + un `report.json` pour le correcteur.

### Lancer le TP1

Il faut être root pour capturer des paquets, donc :

```bash
sudo "$(poetry env info --path)/bin/tp1"
```

(`sudo poetry run tp1` marche pas parce que root n'a pas poetry, d'où le chemin complet)

Pour analyser un fichier pcap au lieu d'écouter le réseau (pas besoin de sudo), on le donne directement,
c'est aussi comme ça que le correcteur lance l'outil :

```bash
python src/tp1/main.py capture.pcap
```

Options :

- `--timeout 120` : durée de la capture en secondes (60 par défaut), à mettre assez long pour que le
  conteneur attaquant ait le temps de rejouer tout son PCAP. Ctrl+C arrête la capture avant la fin.
- `--pcap fichier.pcap` ou `-r fichier.pcap` : pareil que donner le fichier directement
- `-o chemin` (ou `--output`) : où écrire `report.json` (un fichier `.json` ou un dossier), le pdf et le
  graphique vont à côté. Sans ça c'est le dossier courant, et si un dossier `/out` existe (bac à sable de
  correction) une copie de `report.json` y est aussi écrite
- une option inconnue est ignorée (avec un avertissement) au lieu de faire planter le programme, et si
  elle contient un chemin en `.json` ou un dossier qui existe, il est pris comme sortie

Ensuite :

1. la liste des interfaces s'affiche, on tape le numéro (ou le nom) de celle qu'on veut écouter, ou Entrée
   pour prendre celle par défaut (si le choix est pas bon ça redemande). S'il n'y a pas de clavier (lancé
   par un script) ça prend direct l'interface par défaut
2. ça capture pendant 60 secondes (ou le `--timeout`), sans limite de paquets
3. le nombre de paquets par protocole et les attaques trouvées s'affichent dans les logs
4. les fichiers sont créés dans le dossier où on lance le programme (ou celui du `-o`) :
   - `report.pdf` : le rapport
   - `report.json` : le résultat pour le correcteur
   - `graph.svg` : le graphique, à ouvrir dans un navigateur

Les logs sont aussi écrits dans `app.log`.

### Détection des attaques

- **ARP spoofing** : une MAC qui annonce une IP déjà annoncée par une autre MAC (comme arpwatch : la
  première MAC vue pour une IP est la vraie, les suivantes l'usurpent). Une MAC qui annonce plusieurs IP
  toute seule n'est pas accusée : dans le pcap du correcteur plein de machines ont la même MAC
- **scan SYN** : une IP qui envoie des SYN (sans ACK) vers au moins 10 ports différents
- **injection SQL** : du SQL typique d'une injection (`' OR '1'='1`, `UNION SELECT`, `'--`...) dans une
  requête HTTP. Le HTTPS est chiffré donc on peut pas regarder dedans
- le **marqueur** `ESGI{...}` est cherché dans tous les paquets (même encodé dans une URL)

Dans le pdf chaque protocole est marqué légitime ou illégitime, et chaque attaque est notée avec son
protocole et l'IP / la MAC de l'attaquant (sinon ça dit que tout va bien). Le blocage de l'attaquant
(facultatif dans la consigne) est pas fait : une fausse alerte pourrait couper la passerelle.

Le `report.json` a le format demandé, avec la MAC de l'attaquant pour l'ARP spoofing et son IP pour le
scan et l'injection :

```json
{
  "protocols": {"TCP": 105, "ARP": 13, "DNS": 5},
  "attacks": [
    {"type": "arp_spoofing", "attacker": "de:ad:be:ef:00:66"},
    {"type": "syn_scan", "attacker": "10.10.0.66"},
    {"type": "sql_injection", "attacker": "10.10.0.66"}
  ],
  "flag": "ESGI{...}"
}
```

### Comment ça marche

Les paquets sont comptés par protocole de transport (ARP, TCP, UDP, ICMP, ICMPv6) comme dans l'exemple
de la consigne (`{"TCP": 128, "ARP": 12}`) : un paquet DNS compte en UDP, une requête HTTP en TCP. Avant
on prenait la couche la plus "haute" (DNS, NBNS...) mais le correcteur compte comme ça.

Côté sécu :

- le programme a besoin de root seulement pour ouvrir le socket de capture. Juste après il repasse sous
  l'utilisateur qui a lancé sudo (comme `tcpdump -Z`), donc les paquets reçus (qui peuvent venir d'un
  attaquant) sont analysés sans les droits root. S'il est lancé direct en root sans sudo, ça prévient
- un paquet ARP malformé faisait planter l'analyse (donc un attaquant pouvait couper l'outil), il est
  ignoré maintenant
- le marqueur doit faire 100 caractères imprimables max : sinon un faux marqueur pouvait envoyer des
  codes au terminal via les logs, ou bloquer la recherche plusieurs secondes avec un paquet piégé

Côté perf, les paquets sont traités un par un pendant la capture (comptés, analysés puis oubliés) et
pas tous gardés en mémoire jusqu'à la fin. Sur un pcap de 58 700 paquets : 22 s et 125 Mo de RAM au
lieu de 34 s et 640 Mo, et la mémoire grossit plus avec la durée de la capture.

Le code est dans `src/tp1/` :

- `main.py` : lance tout (et lit les options)
- `utils/lib.py` : choix de l'interface, protocole d'un paquet, abandon des droits root
- `utils/capture.py` : capture et comptage des paquets
- `utils/detection.py` : détection des attaques et du marqueur
- `utils/graph.py` : le graphique pygal
- `utils/report.py` : le rapport pdf (fpdf2) et le report.json

## Tests et pre-commit

```bash
poetry run pytest
pre-commit run --all-files
```

Pas besoin d'être root pour les tests, la capture est simulée. Le `conftest.py` à la racine fait
marcher les tests même si le projet n'est pas installé ou que son dossier est en lecture seule (c'est ce
qui les faisait tous échouer chez le correcteur).

## Problèmes

- si des fichiers ont été créés par root avec une ancienne version (`app.log`, `report.pdf`...) on peut
  plus les modifier sans sudo, il faut faire `sudo chown $USER app.log report.pdf graph.svg`
