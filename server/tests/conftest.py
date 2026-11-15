import os
import shutil

import pytest

from server.config import DEFAULT_CONFIG_DIR, Config
from server.db import Database
from server.engine import Engine


@pytest.fixture
def cfg(tmp_path):
    """Salinan config asli di direktori sementara (aman untuk tes yang mengubah whitelist)."""
    d = tmp_path / "config"
    shutil.copytree(DEFAULT_CONFIG_DIR, d)
    return Config(str(d))


@pytest.fixture
def sent():
    return []


@pytest.fixture
def engine(cfg, sent):
    db = Database(":memory:")
    yield Engine(cfg, db, send_cmd=sent.append, clock=lambda: 1000.0)
    db.close()
