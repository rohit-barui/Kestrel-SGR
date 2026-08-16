import abc
import json
import logging
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class RemediationProvider(abc.ABC):
    @abc.abstractmethod
    def execute(self, action: str, target: str, context: dict) -> bool:
        pass


class WebhookAdapter(RemediationProvider):
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def execute(self, action: str, target: str, context: dict) -> bool:
        try:
            payload = json.dumps({"action": action, "target": target, "context": context}).encode()
            req = Request(self.endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            urlopen(req, timeout=5)
            logger.info(f"WebhookAdapter executed {action} on {target}")
            return True
        except Exception as e:
            logger.error(f"WebhookAdapter failed to execute {action}: {e}")
            return False


class MockM365Adapter(RemediationProvider):
    def execute(self, action: str, target: str, context: dict) -> bool:
        logger.info(f"[M365 Mock] Executing {action} on {target}. Context: {context}")
        return True


def get_active_adapter() -> RemediationProvider:
    # In a real system, this would read from vault.py or config
    # For demonstration, we use the Mock adapter
    return MockM365Adapter()
