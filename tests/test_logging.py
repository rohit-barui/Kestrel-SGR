"""Tests for structured JSON logging (core/logging.py)."""
import io
import json
import logging
import sys
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from core.logging import JSONFormatter, setup_logging


class TestJSONFormatter:
    def test_format_basic_record(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="apcs", level=logging.INFO, pathname="x", lineno=1,
            msg="hello", args=(), exc_info=None,
        )
        out = json.loads(fmt.format(record))
        assert out["level"] == "INFO"
        assert out["logger"] == "apcs"
        assert out["message"] == "hello"
        assert "timestamp" in out

    def test_format_with_extra_attributes(self):
        fmt = JSONFormatter()
        record = logging.LogRecord(
            name="apcs", level=logging.WARNING, pathname="x", lineno=1,
            msg="warn", args=(), exc_info=None,
        )
        record.extra = {"scan_id": "abc123"}
        out = json.loads(fmt.format(record))
        assert out["scan_id"] == "abc123"

    def test_format_with_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="apcs", level=logging.ERROR, pathname="x", lineno=1,
            msg="failed", args=(), exc_info=exc_info,
        )
        out = json.loads(fmt.format(record))
        assert "exception" in out
        assert "ValueError" in out["exception"]


class TestSetupLogging:
    def test_plain_formatter_used_when_not_json(self):
        setup_logging(json_output=False)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_json_formatter_used_when_json_requested(self):
        setup_logging(json_output=True)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_verbose_sets_debug_level(self):
        setup_logging(verbose=True)
        assert logging.getLogger().level == logging.DEBUG

    def test_nonverbose_sets_info_level(self):
        setup_logging(verbose=False)
        assert logging.getLogger().level == logging.INFO

    def test_setup_clears_existing_handlers(self):
        root = logging.getLogger()
        before = len(root.handlers)
        setup_logging(json_output=False)
        assert len(root.handlers) == 1
        assert before >= 1

    def test_output_written_to_stdout(self, capsys):
        setup_logging(json_output=True)
        logging.getLogger("apcs").info("capture me")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["message"] == "capture me"
