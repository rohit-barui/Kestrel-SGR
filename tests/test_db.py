import os
import tempfile

import pytest
from unittest.mock import patch

from core.db import get_encrypted_conn

FAKE_KEY = "test-encryption-key-32bytes!"


@patch("core.db.get_secret", return_value=FAKE_KEY)
def test_get_encrypted_conn_creates_db(mock_secret):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        conn = get_encrypted_conn(db_path)
        # Connection should be created and usable
        result = conn.execute("SELECT 1;").fetchone()
        assert result[0] == 1
        conn.close()


@patch("core.db.get_secret", return_value="")
def test_get_encrypted_conn_empty_key_raises(mock_secret):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fail.db")
        with pytest.raises(ValueError, match="not available"):
            get_encrypted_conn(db_path)
