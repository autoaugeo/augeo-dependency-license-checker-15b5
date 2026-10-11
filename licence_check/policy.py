"""Policy loading and evaluation.

Order of decision for one licence id: deny list, allow list, review list, then the
default for its category in the policy's distribution mode. For an expression:
OR takes the most permissive branch, AND the strictest, unknown -> review.
Per-package exceptions override everything.
"""

import json

from . import spdx

MODES = ("internal", "saas", "distributed-binary", "distributed-source")
DECISIONS = ("allow", "review", "deny")
_RANK = {"allow": 0, "review": 1, "deny": 2}

# category -> decision when no list mentions the licence; anything missing -> review
MODE_DEFAULTS = {
    "internal": {
        "permissive": "allow",
        "public-domain": "allow",
        "weak-copyleft": "allow",
        "strong-copyleft": "allow",
        "network-copyleft": "review",
    },
    "saas": {
        "permissive": "allow",
        "public-domain": "allow",
        "weak-copyleft": "allow",
        "strong-copyleft": "review",
        "network-copyleft": "deny",
    },
    "distributed-binary": {
        "permissive": "allow",
        "public-domain": "allow",
        "weak-copyleft": "review",
        "strong-copyleft": "deny",
        "network-copyleft": "deny",
    },
    "distributed-source": {
        "permissive": "allow",
        "public-domain": "allow",
        "weak-copyleft": "allow",
        "strong-copyleft": "review",
        "network-copyleft": "deny",
    },
}


class PolicyError(ValueError):
    pass


def _norm_entry(entry):
    text = " ".join(entry.split())
    if " with " in text.lower():
        return text.lower()
    return (spdx.resolve_id(text) or text).lower()


def _str_list(data, key):
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise PolicyError("policy field '%s' must be a list of non-empty strings" % key)
    return {_norm_entry(x) for x in value}


class Policy:
    def __init__(self, data):
        if not isinstance(data, dict):
            raise PolicyError("policy must be a JSON object")
        self.name = str(data.get("name") or "unnamed")
        project = data.get("project_licence")
        if not isinstance(project, str) or not project.strip():
            raise PolicyError("policy field 'project_licence' is required")
        self.project_licence = project.strip()
        self.mode = data.get("mode")
        if self.mode not in MODES:
            raise PolicyError("policy field 'mode' must be one of: " + ", ".join(MODES))
        self.lists = {
            "deny": _str_list(data, "deny"),
            "allow": _str_list(data, "allow"),
            "review": _str_list(data, "review"),
        }
        self.exceptions = []
        raw_exc = data.get("exceptions", [])
        if not isinstance(raw_exc, list):
            raise PolicyError("policy field 'exceptions' must be a list")
        for item in raw_exc:
            if not isinstance(item, dict) or not isinstance(item.get("package"), str):
                raise PolicyError("each exception needs a 'package' string")
            if item.get("decision") not in DECISIONS:
                raise PolicyError("exception decision must be one of: " + ", ".join(DECISIONS))
            self.exceptions.append(item)

    @classmethod
    def from_dict(cls, data):
        return cls(data)

    def _decide_lic(self, lic_id, exc):
        keys = []
        if exc:
            keys.append(("%s with %s" % (lic_id, exc), "%s WITH %s" % (lic_id, exc)))
        keys.append((lic_id.lower(), lic_id))
        for key, shown in keys:
            for list_name in ("deny", "allow", "review"):
                if key.lower() in self.lists[list_name]:
                    return list_name, "%s is on the %s list" % (shown, list_name)
        shown = keys[0][1]
        category = spdx.category_of(lic_id)
        decision = MODE_DEFAULTS[self.mode].get(category, "review")
        return decision, "%s (%s) defaults to %s in mode %s" % (
            shown,
            category or "uncategorised",
            decision,
            self.mode,
        )

    def evaluate_expression(self, node):
        kind = node[0]
        if kind == "lic":
            return self._decide_lic(node[1], node[2])
        if kind == "unknown":
            if not node[1]:
                return "review", "no licence declared"
            return "review", "licence not recognised: '%s'" % node[1]
        results = [self.evaluate_expression(c) for c in node[1]]
        if kind == "or":
            best = min(results, key=lambda r: _RANK[r[0]])
            return best[0], "OR: " + best[1]
        worst = max(results, key=lambda r: _RANK[r[0]])
        return worst[0], "AND: " + worst[1]

    def evaluate_package(self, pkg):
        node = spdx.parse(pkg.get("licence_raw"))
        decision, reason = self.evaluate_expression(node)
        for exc in self.exceptions:
            if exc["package"].lower() != pkg["name"].lower():
                continue
            if exc.get("version") and exc["version"] != pkg["version"]:
                continue
            decision = exc["decision"]
            reason = "exception: " + (exc.get("reason") or "no reason given")
            break
        return {
            "name": pkg["name"],
            "version": pkg["version"],
            "licence_raw": pkg.get("licence_raw"),
            "expression": spdx.to_string(node),
            "decision": decision,
            "reason": reason,
            "source": pkg["source"],
        }


def load_policy(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PolicyError("cannot read policy %s: %s" % (path, exc))
    return Policy(data)
