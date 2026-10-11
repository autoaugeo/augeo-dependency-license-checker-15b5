"""Text, JSON and Markdown reports."""

import json

from . import DISCLAIMER, __version__

_RANK = {"allow": 0, "review": 1, "deny": 2}


def summarize(results):
    counts = {"packages": len(results), "allow": 0, "review": 0, "deny": 0}
    for res in results:
        counts[res["decision"]] += 1
    return counts


def sort_results(results):
    return sorted(results, key=lambda r: (-_RANK[r["decision"]], r["name"].lower(), r["version"]))


def render_text(results, policy):
    counts = summarize(results)
    lines = [
        "licence-check " + __version__,
        DISCLAIMER,
        "Policy: %s | project licence: %s | mode: %s"
        % (policy.name, policy.project_licence, policy.mode),
        "Scanned %d packages: %d allow, %d review, %d deny"
        % (counts["packages"], counts["allow"], counts["review"], counts["deny"]),
        "",
    ]
    for res in sort_results(results):
        lines.append(
            "%-6s %s %s  [%s]  %s"
            % (res["decision"].upper(), res["name"], res["version"] or "-", res["expression"], res["reason"])
        )
    return "\n".join(lines)


def render_json(results, policy):
    doc = {
        "tool": "licence-check",
        "version": __version__,
        "disclaimer": DISCLAIMER,
        "policy": {
            "name": policy.name,
            "project_licence": policy.project_licence,
            "mode": policy.mode,
        },
        "summary": summarize(results),
        "results": sort_results(results),
    }
    return json.dumps(doc, indent=2)


def _cell(text):
    return str(text).replace("|", "\\|")


def render_md(results, policy):
    counts = summarize(results)
    lines = [
        "# Licence check report",
        "",
        "> " + DISCLAIMER,
        "",
        "- Policy: %s (project licence %s, mode %s)" % (policy.name, policy.project_licence, policy.mode),
        "- Packages: %d (allow %d, review %d, deny %d)"
        % (counts["packages"], counts["allow"], counts["review"], counts["deny"]),
        "",
        "| Decision | Package | Version | Licence | Reason |",
        "|---|---|---|---|---|",
    ]
    for res in sort_results(results):
        lines.append(
            "| %s | %s | %s | %s | %s |"
            % (
                res["decision"].upper(),
                _cell(res["name"]),
                _cell(res["version"] or "-"),
                _cell(res["expression"]),
                _cell(res["reason"]),
            )
        )
    return "\n".join(lines)


def render(fmt, results, policy):
    if fmt == "json":
        return render_json(results, policy)
    if fmt == "md":
        return render_md(results, policy)
    return render_text(results, policy)
