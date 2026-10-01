"""
Configuration commune des tests, chargée par pytest avant les fichiers de test
"""

import os
import sys
import tempfile
from pathlib import Path

# le projet n'est pas forcément installé (bac à sable de correction) : les imports "src.tp1" ont besoin
# de la racine, ceux en "tp1" (comme dans le template) de src
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "src")]

# src/config.py crée app.log dans le dossier courant dès l'import, qui peut être en lecture seule
TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="tests-securite-python-")
os.chdir(TEST_DIRECTORY.name)
