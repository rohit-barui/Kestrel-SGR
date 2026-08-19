import json
import logging
import os
from urllib.request import Request, urlopen

logger = logging.getLogger("apcs")

class SplunkConnector:
    def __init__(self, hec_url=None, hec_token=None):
        self.hec_url = hec_url or os.environ.get("SPLUNK_HEC_URL")
        self.hec_token = hec_token or os.environ.get("SPLUNK_HEC_TOKEN")

    def send_alert(self, alert_data: dict) -> bool:
        if not self.hec_url or not self.hec_token:
            return False
        try:
            payload = json.dumps({
                "event": alert_data,
                "sourcetype": "_json",
                "index": "apcs",
            }).encode()
            req = Request(
                self.hec_url.rstrip("/") + "/services/collector",
                data=payload,
                headers={
                    "Authorization": f"Splunk {self.hec_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Splunk connector failed: %s", e)
            return False

class ElasticConnector:
    def __init__(self, url=None, api_key=None):
        self.url = url or os.environ.get("ELASTIC_URL")
        self.api_key = api_key or os.environ.get("ELASTIC_API_KEY")

    def send_alert(self, alert_data: dict) -> bool:
        if not self.url or not self.api_key:
            return False
        try:
            payload = json.dumps(alert_data).encode()
            req = Request(
                self.url.rstrip("/") + "/apcs-alerts/_doc",
                data=payload,
                headers={
                    "Authorization": f"ApiKey {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Elastic connector failed: %s", e)
            return False

def send_to_siem(alert_data: dict) -> bool:
    splunk = SplunkConnector()
    elastic = ElasticConnector()
    success = False
    if splunk.send_alert(alert_data):
        logger.info("SIEM alert sent to Splunk")
        success = True
    if elastic.send_alert(alert_data):
        logger.info("SIEM alert sent to Elastic")
        success = True
    return success
