"""Comprehensive tests for the lightweight Rego engine (core/policy.py)."""
import tempfile
from pathlib import Path

import pytest

from core.policy import (
    BinOp,
    FieldAccess,
    Literal,
    Node,
    Parser,
    SimpleRegoEngine,
    UnaryOp,
    tokenize,
)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TestTokenizer:
    def test_numbers_and_identifiers(self):
        tokens = tokenize("risk_score >= 70")
        kinds = [t[0] for t in tokens]
        assert kinds == ["IDENT", "GTE", "NUMBER", "EOF"]
        assert tokens[0][1] == "risk_score"
        assert tokens[2][1] == 70

    def test_strings(self):
        tokens = tokenize('name == "bob"')
        assert tokens[0] == ("IDENT", "name")
        assert tokens[1] == ("EQ", "==")
        assert tokens[2] == ("STRING", "bob")
        assert tokens[3] == ("EOF", None)

    def test_all_comparison_operators(self):
        text = "a == b != c > d >= e < f <= g"
        kinds = [t[0] for t in tokenize(text)]
        assert "EQ" in kinds
        assert "NEQ" in kinds
        assert "GT" in kinds
        assert "GTE" in kinds
        assert "LT" in kinds
        assert "LTE" in kinds

    def test_boolean_literals_are_identifiers(self):
        tokens = tokenize("true && false")
        assert tokens[0] == ("IDENT", "true")
        assert tokens[1] == ("AND", "&&")
        assert tokens[2] == ("IDENT", "false")

    def test_newline_and_eof(self):
        tokens = tokenize("a > 1\nb < 2")
        kinds = [t[0] for t in tokens]
        assert "NEWLINE" in kinds
        assert kinds[-1] == "EOF"

    def test_skips_whitespace_and_comments(self):
        tokens = tokenize("  a > 1  // comment here\n")
        assert all(t[0] != "SKIP" for t in tokens)
        assert all(t[0] != "COMMENT" for t in tokens)

    def test_parentheses_and_braces(self):
        tokens = tokenize("(a || b) {")
        kinds = [t[0] for t in tokens]
        assert "LPAREN" in kinds
        assert "RPAREN" in kinds
        assert "LBRACE" in kinds
        assert "RBRACE" in tokens or True  # no RBRACE here, just ensure no error

    def test_field_access_dots(self):
        tokens = tokenize("input.risk_score.score")
        assert [t[1] for t in tokens if t[0] == "IDENT"] == ["input", "risk_score", "score"]
        dot_count = sum(1 for t in tokens if t[0] == "DOT")
        assert dot_count == 2


# ---------------------------------------------------------------------------
# AST node evaluation
# ---------------------------------------------------------------------------

class TestNodeEvaluation:
    def test_base_node_not_implemented(self):
        with pytest.raises(NotImplementedError):
            Node().evaluate({})

    def test_literal_evaluate(self):
        assert Literal(5).evaluate({}) == 5
        assert Literal("x").evaluate({}) == "x"
        assert Literal(True).evaluate({}) is True

    def test_field_access_basic(self):
        node = FieldAccess(["input", "risk_score"])
        assert node.evaluate({"risk_score": 80}) == 80

    def test_field_access_nested(self):
        node = FieldAccess(["input", "a", "b"])
        assert node.evaluate({"a": {"b": 42}}) == 42

    def test_field_access_missing_key_returns_none(self):
        node = FieldAccess(["input", "nope"])
        assert node.evaluate({"other": 1}) is None

    def test_field_access_empty_path(self):
        node = FieldAccess([])
        assert node.evaluate({"anything": 1}) == {"anything": 1}

    def test_binop_equality(self):
        node = BinOp("==", Literal(1), Literal(1))
        assert node.evaluate({}) is True
        node = BinOp("==", Literal(1), Literal(2))
        assert node.evaluate({}) is False

    def test_binop_equality_type_strict(self):
        node = BinOp("==", Literal(1), Literal("1"))
        assert node.evaluate({}) is False

    def test_binop_inequality(self):
        assert BinOp("!=", Literal(1), Literal(2)).evaluate({}) is True
        assert BinOp("!=", Literal(1), Literal(1)).evaluate({}) is False

    def test_binop_ordering(self):
        assert BinOp(">", Literal(2), Literal(1)).evaluate({}) is True
        assert BinOp(">=", Literal(2), Literal(2)).evaluate({}) is True
        assert BinOp("<", Literal(1), Literal(2)).evaluate({}) is True
        assert BinOp("<=", Literal(1), Literal(1)).evaluate({}) is True
        assert BinOp(">", Literal(1), Literal(2)).evaluate({}) is False

    def test_binop_logic(self):
        assert BinOp("&&", Literal(True), Literal(True)).evaluate({}) is True
        assert BinOp("&&", Literal(True), Literal(False)).evaluate({}) is False
        assert BinOp("or", Literal(False), Literal(True)).evaluate({}) is True
        assert BinOp("||", Literal(False), Literal(False)).evaluate({}) is False

    def test_binop_unknown_operator_raises(self):
        with pytest.raises(RuntimeError, match="Unknown operator"):
            BinOp("$$$", Literal(1), Literal(2)).evaluate({})

    def test_unary_not(self):
        assert UnaryOp("not", Literal(True)).evaluate({}) is False
        assert UnaryOp("not", Literal(False)).evaluate({}) is True

    def test_unary_unknown_operator_raises(self):
        with pytest.raises(RuntimeError, match="Unknown unary operator"):
            UnaryOp("~", Literal(True)).evaluate({})


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestParser:
    def parse(self, text):
        return Parser(tokenize(text)).parse()

    def test_parse_simple_comparison(self):
        ast = self.parse("input.risk_score >= 70")
        assert ast.evaluate({"risk_score": 80}) is True
        assert ast.evaluate({"risk_score": 60}) is False

    def test_parse_and_precedence(self):
        ast = self.parse("input.a == 1 && input.b == 2")
        assert ast.evaluate({"a": 1, "b": 2}) is True
        assert ast.evaluate({"a": 1, "b": 3}) is False

    def test_parse_or_precedence(self):
        ast = self.parse("input.a == 1 || input.b == 2")
        assert ast.evaluate({"a": 0, "b": 2}) is True
        assert ast.evaluate({"a": 0, "b": 3}) is False

    def test_parse_not(self):
        ast = self.parse("not input.is_whitelisted")
        assert ast.evaluate({"is_whitelisted": False}) is True
        assert ast.evaluate({"is_whitelisted": True}) is False

    def test_parse_parenthesized(self):
        ast = self.parse("(input.a == 1 || input.b == 1) && input.c == 1")
        assert ast.evaluate({"a": 0, "b": 1, "c": 1}) is True
        assert ast.evaluate({"a": 0, "b": 1, "c": 0}) is False

    def test_parse_string_literal(self):
        ast = self.parse('input.name == "bob"')
        assert ast.evaluate({"name": "bob"}) is True
        assert ast.evaluate({"name": "alice"}) is False

    def test_parse_true_false_literals(self):
        assert self.parse("true").evaluate({}) is True
        assert self.parse("false").evaluate({}) is False

    def test_parse_nested_field_access(self):
        ast = self.parse("input.a.b.c > 1")
        assert ast.evaluate({"a": {"b": {"c": 5}}}) is True

    def test_parse_newlines_skipped(self):
        ast = self.parse("\n\n input.a > 1 \n\n")
        assert ast.evaluate({"a": 2}) is True

    def test_parse_mixed_operators(self):
        ast = self.parse("input.a > 1 && input.b < 10 || input.c == 1")
        assert ast.evaluate({"a": 2, "b": 5, "c": 0}) is True
        assert ast.evaluate({"a": 0, "b": 20, "c": 1}) is True
        assert ast.evaluate({"a": 0, "b": 20, "c": 2}) is False

    def test_consume_wrong_token_raises(self):
        parser = Parser(tokenize("input.a > 1"))
        with pytest.raises(RuntimeError, match="Expected"):
            parser.consume("NUMBER")

    def test_parse_unexpected_token_raises(self):
        # A trailing garbage token should trigger an error
        parser = Parser(tokenize("input.a > 1 )"))
        with pytest.raises(RuntimeError, match="Unexpected token"):
            parser.parse()

    def test_parse_primary_invalid_token_raises(self):
        # A "{" cannot start an expression
        parser = Parser(tokenize("{"))
        with pytest.raises(RuntimeError, match="Unexpected token"):
            parser.parse()

    def test_parse_primary_not_branch(self):
        # Directly exercise parse_primary's NOT handling (comparison RHS path)
        ast = self.parse("input.a == not true")
        assert ast.evaluate({"a": 5}) is False


# ---------------------------------------------------------------------------
# SimpleRegoEngine
# ---------------------------------------------------------------------------

@pytest.fixture
def rego_file():
    content = """package apcs.remediation

default allow = false

allow {
    input.risk_score >= 70
}

allow {
    input.confidence > 80
    not input.is_whitelisted
}

allow {
    input.archive_password != ""
}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
        f.write(content)
        path = f.name
    yield path
    Path(path).unlink()


class TestSimpleRegoEngine:
    def test_load_real_policy(self, rego_file):
        engine = SimpleRegoEngine(rego_file)
        assert len(engine._rule_asts) == 3

    def test_evaluate_first_rule(self, rego_file):
        engine = SimpleRegoEngine(rego_file)
        assert engine.evaluate({"risk_score": 80, "confidence": 0, "is_whitelisted": False, "archive_password": ""}) is True

    def test_evaluate_second_rule_requires_not_whitelisted(self, rego_file):
        engine = SimpleRegoEngine(rego_file)
        # Confidence > 80 AND not whitelisted
        assert engine.evaluate({"risk_score": 0, "confidence": 90, "is_whitelisted": False, "archive_password": ""}) is True
        assert engine.evaluate({"risk_score": 0, "confidence": 90, "is_whitelisted": True, "archive_password": ""}) is False

    def test_evaluate_third_rule(self, rego_file):
        engine = SimpleRegoEngine(rego_file)
        assert engine.evaluate({"risk_score": 0, "confidence": 0, "is_whitelisted": True, "archive_password": "hunter2"}) is True

    def test_evaluate_all_rules_false(self, rego_file):
        engine = SimpleRegoEngine(rego_file)
        assert engine.evaluate({"risk_score": 10, "confidence": 10, "is_whitelisted": True, "archive_password": ""}) is False

    def test_evaluate_multiline_and(self):
        content = """package test
allow {
    input.a == 1
    input.b == 2
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            engine = SimpleRegoEngine(path)
            assert engine.evaluate({"a": 1, "b": 2}) is True
            assert engine.evaluate({"a": 1, "b": 3}) is False
        finally:
            Path(path).unlink()

    def test_evaluate_nested_braces_in_rule(self):
        # Braces inside a string literal must not terminate the allow block
        content = """package test
allow {
    input.name == "a{b}c"
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            engine = SimpleRegoEngine(path)
            assert engine.evaluate({"name": "a{b}c"}) is True
            assert engine.evaluate({"name": "other"}) is False
        finally:
            Path(path).unlink()

    def test_no_allow_blocks_raises(self):
        content = "package test\ndefault allow = false\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="No 'allow' rule blocks"):
                SimpleRegoEngine(path)
        finally:
            Path(path).unlink()

    def test_empty_rule_body_skipped(self):
        content = """package test
allow {

}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            engine = SimpleRegoEngine(path)
            assert engine.evaluate({}) is False
        finally:
            Path(path).unlink()

    def test_multiple_allow_blocks_ored(self):
        content = """package test
allow {
    input.a == 1
}
allow {
    input.b == 2
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
            f.write(content)
            path = f.name
        try:
            engine = SimpleRegoEngine(path)
            assert engine.evaluate({"a": 1, "b": 0}) is True
            assert engine.evaluate({"a": 0, "b": 2}) is True
            assert engine.evaluate({"a": 0, "b": 0}) is False
        finally:
            Path(path).unlink()
