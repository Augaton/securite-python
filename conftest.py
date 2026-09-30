"""
Configuration commune des tests, chargée par pytest avant les fichiers de test
"""

import os
import sys
import tempfile
from pathlib import Path

# Le projet n'est pas forcément installé (bac à sable de correction) : on rend "src" importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

# src/config.py crée app.log dans le dossier courant dès l'import : les tests tournent depuis un dossier
# temporaire, pour marcher même si le projet est en lecture seule (et sans y laisser de app.log)
TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="tests-securite-python-")
os.chdir(TEST_DIRECTORY.name)
