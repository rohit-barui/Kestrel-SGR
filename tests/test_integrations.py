import json
import unittest
from unittest.mock import patch

from core.integrations.abuseipdb import AbuseIPDB
from core.integrations.alienvault_otx import AlienVaultOTX
from core.integrations.cisco_esa import CiscoESA
from core.integrations.defender import DefenderForEmail
from core.integrations.virustotal import VirusTotal


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = data
        self.status = status

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestVirusTotal(unittest.TestCase):
    def test_init_no_config(self):
        vt = VirusTotal({})
        self.assertEqual(vt.api_key, "")

    def test_init_with_config(self):
        vt = VirusTotal({"api_key": "abc"})
        self.assertEqual(vt.api_key, "abc")

    def test_get_no_key_returns_none(self):
        vt = VirusTotal({})
        self.assertIsNone(vt._get("/ip_addresses/1.1.1.1"))

    def test_get_exception_returns_none(self):
        vt = VirusTotal({"api_key": "k"})
        with patch("core.integrations.virustotal.urlopen", side_effect=OSError("net")):
            self.assertIsNone(vt._get("/x"))

    def test_check_ip_no_key(self):
        vt = VirusTotal({})
        result = vt.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "unknown")
        self.assertEqual(result["score"], 0)

    def test_check_ip_malicious(self):
        vt = VirusTotal({"api_key": "k"})
        body = json.dumps({
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 60, "suspicious": 0, "harmless": 40},
                "last_analysis_date": 12345,
                "country": "US",
                "asn": 12345,
            }}
        }).encode()
        with patch("core.integrations.virustotal.urlopen", return_value=FakeResponse(body)):
            result = vt.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["country"], "US")

    def test_check_ip_safe(self):
        vt = VirusTotal({"api_key": "k"})
        body = json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10}}}}).encode()
        with patch("core.integrations.virustotal.urlopen", return_value=FakeResponse(body)):
            result = vt.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "safe")
        self.assertEqual(result["score"], 0)

    def test_check_url_malicious(self):
        vt = VirusTotal({"api_key": "k"})
        body = json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 4}}}}).encode()
        with patch("core.integrations.virustotal.urlopen", return_value=FakeResponse(body)):
            result = vt.check_url("https://evil.com")
        self.assertEqual(result["reputation"], "malicious")

    def test_check_url_no_key(self):
        vt = VirusTotal({})
        result = vt.check_url("https://x.com")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_file_hash_malicious(self):
        vt = VirusTotal({"api_key": "k"})
        body = json.dumps({
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 10, "suspicious": 0, "harmless": 0},
                "type_description": "exe",
                "names": ["mal.exe"],
            }}
        }).encode()
        with patch("core.integrations.virustotal.urlopen", return_value=FakeResponse(body)):
            result = vt.check_file_hash("abc")
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["type"], "exe")

    def test_check_file_hash_no_key(self):
        vt = VirusTotal({})
        result = vt.check_file_hash("abc")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_file_hash_exception(self):
        vt = VirusTotal({"api_key": "k"})
        with patch("core.integrations.virustotal.urlopen", side_effect=OSError("boom")):
            result = vt.check_file_hash("abc")
        self.assertEqual(result["reputation"], "unknown")


class TestAbuseIPDB(unittest.TestCase):
    def test_no_key(self):
        api = AbuseIPDB({})
        result = api.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_ip_malicious(self):
        api = AbuseIPDB({"api_key": "k"})
        body = json.dumps({
            "data": {
                "abuseConfidenceScore": 80,
                "totalReports": 5,
                "lastReportedAt": "2026-01-01",
                "countryCode": "US",
                "isp": "X",
                "domain": "x.com",
                "usageType": "hosting",
            }
        }).encode()
        with patch("core.integrations.abuseipdb.urlopen", return_value=FakeResponse(body)):
            result = api.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["score"], 80)

    def test_check_ip_exception(self):
        api = AbuseIPDB({"api_key": "k"})
        with patch("core.integrations.abuseipdb.urlopen", side_effect=OSError("boom")):
            result = api.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_ip_safe(self):
        api = AbuseIPDB({"api_key": "k"})
        body = json.dumps({"data": {"abuseConfidenceScore": 0}}).encode()
        with patch("core.integrations.abuseipdb.urlopen", return_value=FakeResponse(body)):
            result = api.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "safe")


class TestAlienVaultOTX(unittest.TestCase):
    def test_no_key(self):
        otx = AlienVaultOTX({})
        self.assertIsNone(otx._get("/x"))
        self.assertEqual(otx.check_ip("1.1.1.1")["reputation"], "unknown")

    def test_get_exception(self):
        otx = AlienVaultOTX({"api_key": "k"})
        with patch("core.integrations.alienvault_otx.urlopen", side_effect=OSError("boom")):
            self.assertIsNone(otx._get("/x"))

    def test_check_ip_malicious(self):
        otx = AlienVaultOTX({"api_key": "k"})
        body = json.dumps({"pulse_info": {"count": 8}, "type": "IPv4"}).encode()
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(body)):
            result = otx.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "malicious")
        self.assertEqual(result["score"], 80)

    def test_check_ip_no_result(self):
        otx = AlienVaultOTX({"api_key": "k"})
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(b"{}")):
            result = otx.check_ip("1.1.1.1")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_domain(self):
        otx = AlienVaultOTX({"api_key": "k"})
        body = json.dumps({"pulse_info": {"count": 3}, "whois": "owner"}).encode()
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(body)):
            result = otx.check_domain("evil.com")
        self.assertEqual(result["reputation"], "suspicious")
        self.assertEqual(result["whois"], "owner")

    def test_check_domain_no_result(self):
        otx = AlienVaultOTX({"api_key": "k"})
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(b"{}")):
            result = otx.check_domain("evil.com")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_url(self):
        otx = AlienVaultOTX({"api_key": "k"})
        body = json.dumps({"pulse_info": {"count": 1}}).encode()
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(body)):
            result = otx.check_url("https://evil.com/a?b=1")
        self.assertEqual(result["reputation"], "safe")

    def test_check_url_no_result(self):
        otx = AlienVaultOTX({"api_key": "k"})
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(b"{}")):
            result = otx.check_url("https://x.com")
        self.assertEqual(result["reputation"], "unknown")

    def test_check_hash(self):
        otx = AlienVaultOTX({"api_key": "k"})
        body = json.dumps({"pulse_info": {"count": 6}}).encode()
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(body)):
            result = otx.check_hash("deadbeef")
        self.assertEqual(result["reputation"], "malicious")

    def test_check_hash_no_result(self):
        otx = AlienVaultOTX({"api_key": "k"})
        with patch("core.integrations.alienvault_otx.urlopen", return_value=FakeResponse(b"{}")):
            result = otx.check_hash("deadbeef")
        self.assertEqual(result["reputation"], "unknown")


class TestDefenderForEmail(unittest.TestCase):
    def test_missing_credentials_token_none(self):
        d = DefenderForEmail({})
        self.assertIsNone(d._get_access_token())

    def test_token_acquisition(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        body = json.dumps({"access_token": "tok"}).encode()
        with patch("core.integrations.defender.urlopen", return_value=FakeResponse(body)):
            self.assertEqual(d._get_access_token(), "tok")

    def test_token_acquisition_error(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch("core.integrations.defender.urlopen", side_effect=OSError("boom")):
            self.assertIsNone(d._get_access_token())

    def test_quarantine_no_token_uses_mock(self):
        d = DefenderForEmail({})
        self.assertTrue(d.quarantine_email("m1"))

    def test_quarantine_success(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", return_value=FakeResponse(b"", status=200)
        ):
            self.assertTrue(d.quarantine_email("m1"))

    def test_quarantine_exception_uses_mock(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", side_effect=OSError("boom")
        ):
            self.assertTrue(d.quarantine_email("m1"))

    def test_block_sender_no_token(self):
        d = DefenderForEmail({})
        self.assertTrue(d.block_sender("a@b.com"))

    def test_block_sender_success(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", return_value=FakeResponse(b"", status=200)
        ):
            self.assertTrue(d.block_sender("a@b.com"))

    def test_block_sender_exception_uses_mock(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", side_effect=OSError("boom")
        ):
            self.assertTrue(d.block_sender("a@b.com"))

    def test_get_email_verdict_no_token(self):
        d = DefenderForEmail({})
        self.assertEqual(d.get_email_verdict("m1")["source"], "mock")

    def test_get_email_verdict_success(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        body = json.dumps({"verdict": "Phish"}).encode()
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", return_value=FakeResponse(body)
        ):
            self.assertEqual(d.get_email_verdict("m1")["verdict"], "Phish")

    def test_get_email_verdict_exception(self):
        d = DefenderForEmail({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        with patch.object(d, "_get_access_token", return_value="tok"), patch(
            "core.integrations.defender.urlopen", side_effect=OSError("boom")
        ):
            self.assertEqual(d.get_email_verdict("m1")["source"], "mock")


class TestCiscoESA(unittest.TestCase):
    def test_missing_config(self):
        esa = CiscoESA({})
        self.assertIsNone(esa._request("GET", "/x"))

    def test_request_success(self):
        esa = CiscoESA({"host": "https://esa.example.com/", "api_key": "k"})
        body = json.dumps({"ok": True}).encode()
        with patch("core.integrations.cisco_esa.urlopen", return_value=FakeResponse(body)):
            result = esa._request("GET", "/messages/1/details")
        self.assertEqual(result, {"ok": True})

    def test_request_error(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch("core.integrations.cisco_esa.urlopen", side_effect=OSError("boom")):
            self.assertIsNone(esa._request("GET", "/x"))

    def test_mark_as_spam(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value={"ok": True}):
            self.assertTrue(esa.mark_as_spam("m1"))

    def test_mark_as_clean(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value={}):
            self.assertTrue(esa.mark_as_clean("m1"))

    def test_update_reputation(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value={}):
            self.assertTrue(esa.update_reputation("evil.com", 15))

    def test_update_reputation_clamps_score(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        captured = {}

        def fake_request(method, path, data=None):
            captured.update(data)
            return {}

        esa._request = fake_request
        esa.update_reputation("evil.com", 999)
        self.assertEqual(captured["score"], 10)

    def test_get_message_detail(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value={"verdict": "SPAM"}):
            self.assertEqual(esa.get_message_detail("m1")["verdict"], "SPAM")

    def test_get_message_detail_fallback(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value=None):
            self.assertEqual(esa.get_message_detail("m1")["source"], "mock")

    def test_block_sender(self):
        esa = CiscoESA({"host": "https://esa.example.com", "api_key": "k"})
        with patch.object(esa, "_request", return_value={}):
            self.assertTrue(esa.block_sender("a@b.com"))


if __name__ == "__main__":
    unittest.main()
