"""
Shared test configuration, loaded by pytest before the test files
"""

import os
import sys
import tempfile
from pathlib import Path

# the project is not necessarily installed (grading sandbox)
sys.path.insert(0, str(Path(__file__).resolve().parent))

# src/config.py creates app.log in the current folder on import, which may be read-only
TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="tests-securite-python-")
os.chdir(TEST_DIRECTORY.name)
