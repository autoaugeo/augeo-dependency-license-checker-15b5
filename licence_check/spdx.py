"""SPDX licence expression tokenizer and parser.

Nodes are plain tuples:
  ("lic", id, exception_or_None)   a recognised licence id
  ("and", [nodes])                 all branches apply
  ("or", [nodes])                  the user may choose one branch
  ("unknown", raw)                 empty, ambiguous (for example "BSD") or unrecognised text

parse() never raises: text it cannot understand becomes an "unknown" node, which
the policy treats as "review".
"""

import json
import os
import re

_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "spdx_ids.json"
)


class SpdxError(ValueError):
    pass


def _load_ids():
    try:
        with open(_DATA, encoding="utf-8") as fh:
            return json.load(fh)["ids"]
    except (OSError, ValueError, KeyError):
        return {}


IDS = _load_ids()
_LOWER = {key.lower(): key for key in IDS}

# Common spellings mapped to one SPDX id. Ambiguous names such as "BSD" are
# deliberately absent: they stay unknown and go to review.
_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mit license": "MIT",
    "the mit license": "MIT",
    "expat": "MIT",
    "bsd-2": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "isc license": "ISC",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "mpl 2.0": "MPL-2.0",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "python software foundation license": "PSF-2.0",
}

_KEYWORDS = ("AND", "OR", "WITH")


def resolve_id(token):
    """Return the canonical SPDX id for a token or short name, or None."""
    low = " ".join(str(token).split()).lower()
    if not low:
        return None
    if low in _ALIASES:
        return _ALIASES[low]
    if low in _LOWER:
        return _LOWER[low]
    if low.endswith("+"):
        base = resolve_id(low[:-1])
        if base:
            return base[:-5] + "-or-later" if base.endswith("-only") else base
    return None


def category_of(lic_id):
    return IDS.get(lic_id)


def tokenize(text):
    return re.findall(r"\(|\)|[^\s()]+", text)


def _license_node(token):
    lic_id = resolve_id(token)
    if lic_id is None:
        return ("unknown", token)
    return ("lic", lic_id, None)


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def peek_kw(self):
        tok = self.peek()
        return tok.upper() if tok else None

    def parse_or(self):
        items = [self.parse_and()]
        while self.peek_kw() == "OR":
            self.i += 1
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else ("or", items)

    def parse_and(self):
        items = [self.parse_atom()]
        while self.peek_kw() == "AND":
            self.i += 1
            items.append(self.parse_atom())
        return items[0] if len(items) == 1 else ("and", items)

    def parse_atom(self):
        tok = self.peek()
        if tok is None:
            raise SpdxError("unexpected end of expression")
        self.i += 1
        if tok == "(":
            node = self.parse_or()
            if self.peek() != ")":
                raise SpdxError("missing closing parenthesis")
            self.i += 1
            return node
        if tok == ")" or tok.upper() in _KEYWORDS:
            raise SpdxError("unexpected token " + tok)
        node = _license_node(tok)
        if self.peek_kw() == "WITH":
            self.i += 1
            exc = self.peek()
            if exc is None or exc in ("(", ")") or exc.upper() in _KEYWORDS:
                raise SpdxError("WITH needs an exception id")
            self.i += 1
            if node[0] == "lic":
                return ("lic", node[1], exc)
            return ("unknown", tok + " WITH " + exc)
        return node


def parse(raw):
    """Parse a licence string into a node. Never raises."""
    if not isinstance(raw, str) or not raw.strip():
        return ("unknown", "")
    text = " ".join(raw.split())
    whole = resolve_id(text)
    if whole:
        return ("lic", whole, None)
    parser = _Parser(tokenize(text))
    try:
        node = parser.parse_or()
        if parser.i != len(parser.tokens):
            raise SpdxError("trailing tokens")
    except SpdxError:
        return ("unknown", text)
    return node


def to_string(node):
    kind = node[0]
    if kind == "lic":
        return node[1] + (" WITH " + node[2] if node[2] else "")
    if kind == "unknown":
        return "UNKNOWN(%s)" % node[1] if node[1] else "(none)"
    if kind == "and":
        return " AND ".join(
            "(%s)" % to_string(c) if c[0] == "or" else to_string(c) for c in node[1]
        )
    return " OR ".join(to_string(c) for c in node[1])
