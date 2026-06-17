import unittest
from unittest.mock import patch, MagicMock
from core.siem_connectors import SplunkConnector, ElasticConnector, send_to_siem

class TestSplunkConnector(unittest.TestCase):
    def test_send_alert_success(self):
        with patch("core.siem_connectors.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            conn = SplunkConnector(hec_url="http://hec:8088", hec_token="test-token")
            result = conn.send_alert({"scan_id": "abc", "risk_score": 85})
            self.assertTrue(result)
            mock_urlopen.assert_called_once()

    def test_send_alert_no_config(self):
        conn = SplunkConnector(hec_url="", hec_token="")
        result = conn.send_alert({"scan_id": "abc"})
        self.assertFalse(result)

    def test_send_alert_failure(self):
        with patch("core.siem_connectors.urlopen", side_effect=Exception("timeout")):
            conn = SplunkConnector(hec_url="http://hec:8088", hec_token="test")
            result = conn.send_alert({"scan_id": "abc"})
            self.assertFalse(result)

class TestElasticConnector(unittest.TestCase):
    def test_send_alert_success(self):
        with patch("core.siem_connectors.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            conn = ElasticConnector(url="http://es:9200", api_key="key")
            result = conn.send_alert({"scan_id": "abc", "risk_score": 85})
            self.assertTrue(result)
            mock_urlopen.assert_called_once()

    def test_send_alert_no_config(self):
        conn = ElasticConnector(url="", api_key="")
        result = conn.send_alert({"scan_id": "abc"})
        self.assertFalse(result)

    def test_send_alert_failure(self):
        with patch("core.siem_connectors.urlopen", side_effect=Exception("timeout")):
            conn = ElasticConnector(url="http://es:9200", api_key="key")
            result = conn.send_alert({"scan_id": "abc"})
            self.assertFalse(result)

class TestSendToSIEM(unittest.TestCase):
    @patch("core.siem_connectors.SplunkConnector.send_alert", return_value=True)
    @patch("core.siem_connectors.ElasticConnector.send_alert", return_value=True)
    def test_send_to_siem_both(self, mock_elastic, mock_splunk):
        result = send_to_siem({"scan_id": "abc"})
        self.assertTrue(result)
        mock_elastic.assert_called_once()
        mock_splunk.assert_called_once()

    @patch("core.siem_connectors.SplunkConnector.send_alert", return_value=False)
    @patch("core.siem_connectors.ElasticConnector.send_alert", return_value=False)
    def test_send_to_siem_none(self, mock_elastic, mock_splunk):
        result = send_to_siem({"scan_id": "abc"})
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
