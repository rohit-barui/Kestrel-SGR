"""Core Gateway – Saga pattern implementation

The gateway records side‑effects performed by skills so that, if any skill fails,
the system can roll back the actions in reverse order.  For the prototype we
store the log in memory; a production version could persist to a database.
"""

from collections.abc import Callable
from typing import Any


class Gateway:
    def __init__(self):
        self._log: list[dict[str, Any]] = []
        self._committed: bool = False

    def record(self, action: str, params: dict[str, Any], rollback: Callable[[dict[str, Any]], None]):
        """Record a side‑effect.

        * ``action`` – identifier string (e.g. ``block_ip``)
        * ``params`` – parameters used for the action
        * ``rollback`` – callable that reverses the action given the same params
        """
        if self._committed:
            raise RuntimeError("Cannot record after commit")
        self._log.append({"action": action, "params": params, "rollback": rollback})

    def commit(self):
        """Mark the saga as successful – no rollback will be performed."""
        self._committed = True
        self._log.clear()

    def rollback(self):
        """Execute stored rollback callables in reverse order.

        After rollback the log is cleared and the saga is considered not
        committed.  Errors during rollback are logged (print) but do not raise.
        """
        if self._committed:
            # Already committed – nothing to do
            return
        for entry in reversed(self._log):
            try:
                entry["rollback"](entry["params"])
            except Exception as e:
                print(f"Rollback of {entry['action']} failed: {e}")
        self._log.clear()
        self._committed = False

# Example rollback functions (used by dummy skills)
def rollback_noop(params: dict[str, Any]):
    # No operation – placeholder for actions that have no side‑effect reversal
    pass

# End of core/gateway.py
