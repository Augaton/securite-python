import logging
import sys

# Logger autonome : TP3 est lancé par `python -m tp3.main`, parfois depuis un
# répertoire de travail vide ou en lecture seule. On n'écrit donc pas de fichier
# app.log et on envoie tous les messages sur stderr, pour laisser stdout propre :
# seuls les deux drapeaux y sont imprimés (c'est ce que lit le correcteur).
logger = logging.getLogger("TP3")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
