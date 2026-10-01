"""
Fixtures des tests du TP2
"""

import pytest

from tests.tp2.factory import DROPPER_STRINGS, build_sample


@pytest.fixture
def dropper_data() -> bytes:
    return build_sample(*DROPPER_STRINGS)


@pytest.fixture
def dropper_path(tmp_path, dropper_data):
    path = tmp_path / "dropper.bin"
    path.write_bytes(dropper_data)
    return path
