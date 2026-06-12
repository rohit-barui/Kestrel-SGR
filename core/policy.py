"""Core Policy – lightweight Rego evaluator with recursive-descent parser.

Supports:
  - Comparisons: ==, !=, >, >=, <, <=
  - Logical: && (and), || (or), not
  - Parenthesized sub-expressions
  - input.field access
  - Multiple allow { ... } rules (OR'd together)
  - Multi-line rule bodies (lines AND'd together)
  - No eval() — builds and evaluates an expression tree.
"""

import re
from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

TOKEN_SPEC = [
    ("NUMBER",  r"\d+"),
    ("STRING",  r'"[^"]*"'),
    ("NOT",     r"not\b"),
    ("AND",     r"&&"),
    ("OR",      r"\|\|"),
    ("IDENT",   r"[a-zA-Z_][a-zA-Z0-9_]*"),
    ("DOT",     r"\."),
    ("EQ",      r"=="),
    ("NEQ",     r"!="),
    ("GTE",     r">="),
    ("LTE",     r"<="),
    ("GT",      r">"),
    ("LT",      r"<"),
    ("LPAREN",  r"\("),
    ("RPAREN",  r"\)"),
    ("LBRACE",  r"\{"),
    ("RBRACE",  r"\}"),
    ("SKIP",    r"[ \t\r]+"),
    ("NEWLINE", r"\n"),
    ("COMMENT", r"//[^\n]*"),
]

TOKEN_RE = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPEC))


def tokenize(text: str) -> List[tuple]:
    tokens = []
    for m in TOKEN_RE.finditer(text):
        kind = m.lastgroup
        val = m.group()
        if kind in ("SKIP", "COMMENT"):
            continue
        if kind == "NUMBER":
            tokens.append(("NUMBER", int(val)))
        elif kind == "STRING":
            tokens.append(("STRING", val[1:-1]))
        elif kind == "IDENT":
            tokens.append(("IDENT", val))
        elif kind == "NEWLINE":
            tokens.append(("NEWLINE", val))
        else:
            tokens.append((kind, val))
    tokens.append(("EOF", None))
    return tokens


# ---------------------------------------------------------------------------
# AST node types
# ---------------------------------------------------------------------------

class Node:
    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        raise NotImplementedError


class BinOp(Node):
    def __init__(self, op: str, left: Node, right: Node):
        self.op = op
        self.left = left
        self.right = right

    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        l = self.left.evaluate(input_data)
        r = self.right.evaluate(input_data)
        if self.op in ("&&", "and"):
            return l and r
        elif self.op in ("||", "or"):
            return l or r
        elif self.op == "==":
            return isinstance(l, type(r)) and l == r
        elif self.op == "!=":
            return l != r
        elif self.op == ">":
            return l > r
        elif self.op == ">=":
            return l >= r
        elif self.op == "<":
            return l < r
        elif self.op == "<=":
            return l <= r
        raise RuntimeError(f"Unknown operator: {self.op}")


class UnaryOp(Node):
    def __init__(self, op: str, operand: Node):
        self.op = op
        self.operand = operand

    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        val = self.operand.evaluate(input_data)
        if self.op == "not":
            return not val
        raise RuntimeError(f"Unknown unary operator: {self.op}")


class FieldAccess(Node):
    def __init__(self, path: List[str]):
        # path e.g. ["input", "risk_score"] — skip leading "input"
        self.path = path[1:] if path and path[0] == "input" else path

    def evaluate(self, input_data: Dict[str, Any]) -> Any:
        cur = input_data
        for key in self.path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None
        return cur


class Literal(Node):
    def __init__(self, value):
        self.value = value

    def evaluate(self, input_data: Dict[str, Any]) -> Any:
        return self.value


# ---------------------------------------------------------------------------
# Recursive-descent parser
# ---------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens: List[tuple]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> tuple:
        return self.tokens[self.pos]

    def consume(self, kind: str = None):
        tok = self.tokens[self.pos]
        if kind is not None and tok[0] != kind:
            raise RuntimeError(f"Expected {kind}, got {tok[0]}")
        self.pos += 1
        return tok

    def skip_newlines(self):
        while self.peek()[0] == "NEWLINE":
            self.consume()

    # Grammar (precedence lowest → highest):
    #   or_expr     ::= and_expr ("||" and_expr)*
    #   and_expr    ::= not_expr ("&&" not_expr)*
    #   not_expr    ::= "not" not_expr | comparison
    #   comparison  ::= primary (("<=" | ">=" | "<" | ">" | "==" | "!=") primary)?
    #   primary     ::= NUMBER | STRING | "true" | "false" | field_access | "(" or_expr ")"

    def parse(self) -> Node:
        expr = self.parse_or()
        self.skip_newlines()
        if self.peek()[0] != "EOF":
            raise RuntimeError(f"Unexpected token: {self.peek()}")
        return expr

    def parse_or(self) -> Node:
        left = self.parse_and()
        while self.peek()[0] == "OR":
            self.consume("OR")
            right = self.parse_and()
            left = BinOp("||", left, right)
        return left

    def parse_and(self) -> Node:
        left = self.parse_not()
        while self.peek()[0] == "AND":
            self.consume("AND")
            right = self.parse_not()
            left = BinOp("&&", left, right)
        return left

    def parse_not(self) -> Node:
        if self.peek()[0] == "NOT":
            self.consume("NOT")
            operand = self.parse_not()
            return UnaryOp("not", operand)
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_primary()
        if self.peek()[0] in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE"):
            op = self.consume()[0]
            # Map token kind to operator string
            op_map = {"EQ": "==", "NEQ": "!=", "GT": ">", "GTE": ">=", "LT": "<", "LTE": "<="}
            right = self.parse_primary()
            return BinOp(op_map[op], left, right)
        return left

    def parse_primary(self) -> Node:
        self.skip_newlines()
        tok = self.peek()

        if tok[0] == "NUMBER":
            self.consume("NUMBER")
            return Literal(tok[1])
        elif tok[0] == "STRING":
            self.consume("STRING")
            return Literal(tok[1])
        elif tok[0] == "IDENT":
            if tok[1] == "true":
                self.consume()
                return Literal(True)
            elif tok[1] == "false":
                self.consume()
                return Literal(False)
            # Parse field access: input.field.subfield
            path = [tok[1]]
            self.consume("IDENT")
            while self.peek()[0] == "DOT":
                self.consume("DOT")
                ident = self.consume("IDENT")
                path.append(ident[1])
            return FieldAccess(path)
        elif tok[0] == "LPAREN":
            self.consume("LPAREN")
            expr = self.parse_or()
            self.consume("RPAREN")
            return expr
        elif tok[0] == "NOT":
            self.consume("NOT")
            return UnaryOp("not", self.parse_primary())
        elif tok[0] in ("NEWLINE",):
            self.skip_newlines()
            return self.parse_primary()
        raise RuntimeError(f"Unexpected token in expression: {tok}")


# ---------------------------------------------------------------------------
# SimpleRegoEngine
# ---------------------------------------------------------------------------

class SimpleRegoEngine:
    def __init__(self, rego_path: str):
        self.rego_path = rego_path
        self._rule_asts: List[Node] = []  # one AST per allow block
        self._load_rego()

    def _load_rego(self):
        with open(self.rego_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Find all allow { ... } blocks (handle nested braces)
        rules = []
        i = 0
        while True:
            idx = content.find("allow {", i)
            if idx == -1:
                break
            brace_start = content.index("{", idx)
            depth = 1
            j = brace_start + 1
            while depth > 0 and j < len(content):
                if content[j] == "{":
                    depth += 1
                elif content[j] == "}":
                    depth -= 1
                j += 1
            body = content[brace_start + 1: j - 1]
            rules.append(body.strip())
            i = j

        if not rules:
            raise ValueError("No 'allow' rule blocks found in Rego file")

        for body in rules:
            # Split body into lines and parse each non-empty line as an expression
            conditions = [line.strip() for line in body.split("\n") if line.strip()]
            if not conditions:
                continue
            # AND together all conditions in this rule block
            ast = None
            for cond_text in conditions:
                tokens = tokenize(cond_text)
                parser = Parser(tokens)
                cond_ast = parser.parse()
                if ast is None:
                    ast = cond_ast
                else:
                    ast = BinOp("&&", ast, cond_ast)
            if ast is not None:
                self._rule_asts.append(ast)

    def evaluate(self, input_data: Dict[str, Any]) -> bool:
        if not self._rule_asts:
            return False
        # OR together all rule blocks
        result = False
        for ast in self._rule_asts:
            if ast.evaluate(input_data):
                result = True
        return result
