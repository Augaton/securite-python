"""
Configuration commune des tests, chargée par pytest avant les fichiers de test
"""

import os
import sys
import tempfile
from pathlib import Path

# le projet n'est pas forcément installé (bac à sable de correction)
sys.path.insert(0, str(Path(__file__).resolve().parent))

# src/config.py crée app.log dans le dossier courant dès l'import, qui peut être en lecture seule
TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="tests-securite-python-")
os.chdir(TEST_DIRECTORY.name)
