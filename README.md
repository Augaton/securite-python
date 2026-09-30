# securite-python

Les TP de sécu python (ESGI 4A), fait à partir du template du prof.

- TP1 : capture réseau avec scapy + graphique pygal + rapport pdf -> fait
- TP2 : pas encore fait
- TP3 : les captchas, pas encore fait

## Installation

Il faut python 3.11 minimum, poetry, et cairo (sert à transformer le graphique en png pour le pdf,
normalement il est deja installé sur linux sinon `sudo dnf install cairo` ou `sudo apt install libcairo2`).

```bash
git clone https://github.com/Augaton/securite-python.git
cd securite-python
poetry lock
poetry install
```

## TP1

Le programme écoute une interface réseau avec scapy, compte le nombre de paquets par protocole, fait un
graphique avec pygal et génère un rapport pdf avec un résumé, un tableau et le graphique.

### Lancer le TP1

Il faut être root pour capturer des paquets, donc depuis la racine du projet :

```bash
sudo "$(poetry env info --path)/bin/tp1"
```

(`sudo poetry run tp1` marche pas parce que root n'a pas poetry, d'où le chemin complet)

Ensuite :

1. la liste des interfaces s'affiche, on tape le numéro (ou le nom) de celle qu'on veut écouter, ou Entrée
   pour prendre celle par défaut (si le choix est pas bon ça redemande)
2. ça capture 100 paquets ou pendant 30 secondes max (modifiable dans `src/tp1/utils/capture.py`)
3. le nombre de paquets par protocole s'affiche dans les logs
4. les fichiers sont créés dans le dossier où on lance le programme :
   - `graph.svg` : le graphique, à ouvrir dans un navigateur
   - `graph.png` : le graphique en image (celui qui est dans le pdf)
   - `report.pdf` : le rapport

Les logs sont aussi écrits dans `app.log`.

### Comment ça marche

Pour trouver le protocole d'un paquet on prend sa couche la plus "haute" en ignorant les données brutes
(Raw) et le padding : `Ether / IP / UDP / DNS` ça donne DNS, `Ether / IP / TCP / Raw` ça donne TCP.
Comme ça on voit tous les types de paquets (IPv6, NBNS, LLMNR...) et pas juste une liste fixe.

Le code est dans `src/tp1/` :

- `main.py` : lance tout
- `utils/lib.py` : choix de l'interface + protocole d'un paquet
- `utils/capture.py` : capture et comptage des paquets
- `utils/graph.py` : le graphique pygal
- `utils/report.py` : le rapport pdf (fpdf2)

## Tests et pre-commit

```bash
poetry run pytest
pre-commit run --all-files
```

Pas besoin d'être root pour les tests, la capture est simulée.

## Problèmes

- si les fichiers ont été créés par root (`app.log`, `report.pdf`...) on peut plus les modifier sans sudo,
  il faut faire `sudo chown $USER app.log report.pdf graph.svg graph.png`
- erreur `no library called "cairo-2" was found` -> installer cairo (voir installation)
