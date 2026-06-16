import os
import sqlite3
from typing import Optional

from .vault import get_secret


def get_encrypted_conn(path: str, key_name: str = "db_encryption_key") -> sqlite3.Connection:
    """Return a SQLite connection that uses SQLCipher encryption.

    * ``path`` – filesystem path to the SQLite database file.
    * ``key_name`` – name of the secret stored in the vault that holds the
      encryption key.  The default matches the naming used in CI tests.
    """
    # Retrieve the raw key from the vault.  ``get_secret`` raises a clear
    # exception if the key is missing – this prevents the DB from opening
    # unintentionally with a blank key.
    key = get_secret(key_name)
    if not isinstance(key, str) or not key:
        raise ValueError(f"Encryption key '{key_name}' is not available in the vault")

    # Ensure the directory exists; ``sqlite3`` will create the file if it does not.
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    conn = sqlite3.connect(path, check_same_thread=False)
    # Apply the SQLCipher pragmas.  ``cipher_compatibility = 4`` matches the
    # default used by the ``pysqlcipher3`` package for modern SQLite versions.
    conn.executescript(
        f"""
        PRAGMA key = '{key}';
        PRAGMA cipher_compatibility = 4;
        """
    )
    return conn
