"""Plain-assert test runner: python tests/run_tests.py

Runs in-process, writes no files, needs no network.
"""

import contextlib
import io
import json
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from licence_check import cli, policy as policy_mod, readers, report, spdx  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")
NPM = os.path.join(FIX, "package-lock.json")
COMPOSER = os.path.join(FIX, "composer.lock.json")
BOM = os.path.join(FIX, "bom.json")
SPDX = os.path.join(FIX, "sbom.spdx.json")
SITE = os.path.join(FIX, "site-packages")
SAAS = os.path.join(FIX, "policy-saas.json")
BAD = os.path.join(FIX, "policy-bad.json")
DEFAULT = os.path.join(ROOT, "policies", "default.json")

CASES = []


def case(func):
    CASES.append(func)
    return func


def lic(name, exc=None):
    return ("lic", name, exc)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def pkg(raw, name="x"):
    return {"name": name, "version": "1", "licence_raw": raw, "source": "t"}


def default_policy():
    return policy_mod.load_policy(DEFAULT)


def make_policy(**kw):
    data = {"project_licence": "MIT", "mode": "internal"}
    data.update(kw)
    return policy_mod.Policy.from_dict(data)


def decision(pol, raw):
    return pol.evaluate_package(pkg(raw))["decision"]


# ---- parser ----
@case
def parse_simple_id():
    assert spdx.parse("MIT") == lic("MIT")


@case
def parse_case_insensitive():
    assert spdx.parse("apache-2.0") == lic("Apache-2.0")


@case
def parse_alias_apache():
    assert spdx.parse("Apache 2.0") == lic("Apache-2.0")


@case
def parse_or():
    assert spdx.parse("MIT OR Apache-2.0") == ("or", [lic("MIT"), lic("Apache-2.0")])


@case
def parse_and_binds_tighter_than_or():
    assert spdx.parse("MIT OR Apache-2.0 AND ISC") == ("or", [lic("MIT"), ("and", [lic("Apache-2.0"), lic("ISC")])])


@case
def parse_parentheses():
    node = spdx.parse("(MIT OR ISC) AND Apache-2.0")
    assert node == ("and", [("or", [lic("MIT"), lic("ISC")]), lic("Apache-2.0")])


@case
def parse_with_exception():
    assert spdx.parse("GPL-2.0-only WITH Classpath-exception-2.0") == lic("GPL-2.0-only", "Classpath-exception-2.0")


@case
def parse_plus_suffix():
    assert spdx.parse("GPL-2.0+") == lic("GPL-2.0-or-later")


@case
def parse_bare_gpl_is_only():
    assert spdx.parse("GPL-3.0") == lic("GPL-3.0-only")


@case
def parse_bsd_is_unknown():
    assert spdx.parse("BSD") == ("unknown", "BSD")


@case
def parse_empty_and_none():
    assert spdx.parse("") == ("unknown", "")
    assert spdx.parse(None) == ("unknown", "")


@case
def parse_dangling_operator():
    assert spdx.parse("MIT OR") == ("unknown", "MIT OR")


@case
def parse_unbalanced_parentheses():
    assert spdx.parse("(MIT OR ISC")[0] == "unknown"


@case
def parse_lowercase_keywords():
    assert spdx.parse("mit or isc") == ("or", [lic("MIT"), lic("ISC")])


@case
def parse_unknown_id():
    assert spdx.parse("Foo-1.0") == ("unknown", "Foo-1.0")


@case
def to_string_round_trip():
    text = "(MIT OR ISC) AND Apache-2.0"
    assert spdx.to_string(spdx.parse(text)) == text


@case
def category_lookup():
    assert spdx.category_of("AGPL-3.0-only") == "network-copyleft"
    assert spdx.category_of("MIT") == "permissive"
    assert len(spdx.IDS) >= 55


# ---- readers ----
def by_name(items):
    return {p["name"]: p for p in items}


@case
def npm_reader_packages():
    items = by_name(readers.read_npm(NPM))
    assert set(items) == {"alpha-mit", "beta-apache", "gamma-gpl", "delta-dual", "epsilon-nolicense"}
    assert items["delta-dual"]["licence_raw"] == "MIT OR GPL-2.0-only"
    assert items["gamma-gpl"]["version"] == "3.0.0"


@case
def npm_reader_missing_licence():
    assert by_name(readers.read_npm(NPM))["epsilon-nolicense"]["licence_raw"] is None


@case
def composer_reader():
    items = by_name(readers.read_composer(COMPOSER))
    assert len(items) == 3
    assert items["vendor/lgpl-lib"]["licence_raw"] == "LGPL-2.1-or-later"
    assert items["vendor/mit-lib"]["source"] == "composer.lock.json"


@case
def cyclonedx_reader():
    items = by_name(readers.read_cyclonedx(BOM))
    assert items["cdx-mit"]["licence_raw"] == "MIT"
    assert items["cdx-custom"]["licence_raw"] == "Acme Internal Licence 7"
    assert items["cdx-expr"]["licence_raw"] == "Apache-2.0 OR MIT"


@case
def cyclonedx_multiple_licences_are_and():
    raw = readers._cdx_license([{"license": {"id": "MIT"}}, {"expression": "A OR B"}])
    assert raw == "MIT AND (A OR B)"


@case
def python_reader_four_packages():
    items = by_name(readers.read_python_site_packages(SITE))
    assert set(items) == {"pyalpha", "pybeta", "pygamma", "pydelta"}
    assert items["pyalpha"]["licence_raw"] == "MIT"
    assert items["pyalpha"]["source"] == "pyalpha-1.0.dist-info"


@case
def python_reader_license_field_and_classifier():
    items = by_name(readers.read_python_site_packages(SITE))
    assert items["pybeta"]["licence_raw"] == "Apache 2.0"
    assert items["pygamma"]["licence_raw"] == "GPL-3.0-only"


@case
def python_reader_unknown_license_is_missing():
    assert by_name(readers.read_python_site_packages(SITE))["pydelta"]["licence_raw"] is None


@case
def read_path_sniffs_composer_and_rejects_policy_file():
    assert len(readers.read_path(COMPOSER)) == 3
    try:
        readers.read_path(SAAS)
    except readers.ReaderError:
        return
    raise AssertionError("policy file should not be read as a lock file")


@case
def spdx_detected_by_sniffing():
    items = readers.read_path(SPDX)
    assert len(items) == 6 and items[0]["source"] == "sbom.spdx.json"
    assert readers._sniff(readers._load_json(SPDX)) == "spdx"
    assert readers._sniff(readers._load_json(COMPOSER)) == "composer"


@case
def spdx_concluded_beats_declared():
    assert by_name(readers.read_path(SPDX))["spdx-mit"]["licence_raw"] == "MIT"


@case
def spdx_noassertion_falls_back_to_declared():
    items = by_name(readers.read_path(SPDX))
    assert items["spdx-fallback"]["licence_raw"] == "ISC"
    assert items["spdx-dual"]["licence_raw"] == "MIT OR GPL-3.0-only"
    assert items["spdx-unknown"]["licence_raw"] is None


@case
def spdx_root_package_skipped():
    assert "sample-app" not in by_name(readers.read_path(SPDX))
    data = {
        "spdxVersion": "SPDX-2.2",
        "packages": [{"SPDXID": "SPDXRef-Root", "name": "root", "licenseConcluded": "MIT"},
                     {"SPDXID": "SPDXRef-Dep", "name": "dep", "licenseConcluded": "MIT"}],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": "SPDXRef-Root"}],
    }
    assert [p["name"] for p in readers._spdx_from_data(data, "t")] == ["dep"]


@case
def spdx_missing_licence_goes_to_review():
    res = default_policy().evaluate_package(by_name(readers.read_path(SPDX))["spdx-unknown"])
    assert res["decision"] == "review" and res["reason"] == "no licence declared"


@case
def cli_exit_1_on_spdx_fixture_with_default_policy():
    code, out, _ = run_cli([SPDX])
    assert code == 1 and "Scanned 6 packages: 4 allow, 1 review, 1 deny" in out
    assert "DENY   spdx-agpl 0.9.0" in out


@case
def read_path_missing():
    try:
        readers.read_path(os.path.join(FIX, "nope.json"))
    except readers.ReaderError as exc:
        assert "path not found" in str(exc)
        return
    raise AssertionError("missing path should raise")


# ---- policy ----
@case
def policy_allow_and_deny_lists():
    pol = default_policy()
    assert decision(pol, "MIT") == "allow"
    assert decision(pol, "GPL-3.0-only") == "deny"
    assert decision(pol, "LGPL-2.1-or-later") == "review"


@case
def policy_or_passes_if_any_branch_allowed():
    assert decision(default_policy(), "MIT OR GPL-2.0-only") == "allow"


@case
def policy_and_needs_all_branches():
    assert decision(default_policy(), "MIT AND GPL-3.0-only") == "deny"
    assert decision(default_policy(), "MIT AND ISC") == "allow"


@case
def policy_unknown_and_missing_go_to_review():
    pol = default_policy()
    assert decision(pol, "Totally Custom Terms") == "review"
    assert decision(pol, None) == "review"
    assert decision(pol, "BSD") == "review"


@case
def policy_unknown_branch_inside_or_does_not_block():
    assert decision(default_policy(), "MIT OR Foo-1.0") == "allow"


@case
def policy_exception_overrides():
    pol = policy_mod.load_policy(SAAS)
    res = pol.evaluate_package(pkg("GPL-3.0-only", name="gamma-gpl"))
    assert res["decision"] == "allow" and "build tooling only" in res["reason"]


@case
def policy_mode_defaults_for_strong_copyleft():
    assert decision(make_policy(mode="internal"), "GPL-3.0-only") == "allow"
    assert decision(make_policy(mode="saas"), "GPL-3.0-only") == "review"
    assert decision(make_policy(mode="distributed-binary"), "GPL-3.0-only") == "deny"


@case
def policy_mode_defaults_for_network_and_proprietary():
    assert decision(make_policy(mode="internal"), "AGPL-3.0-only") == "review"
    assert decision(make_policy(mode="saas"), "AGPL-3.0-only") == "deny"
    assert decision(make_policy(mode="internal"), "BUSL-1.1") == "review"


@case
def policy_deny_beats_allow():
    assert decision(make_policy(allow=["GPL-3.0-only"], deny=["GPL-3.0-only"]), "GPL-3.0") == "deny"


@case
def policy_with_entry_is_checked_first():
    pol = make_policy(allow=["GPL-2.0-only WITH Classpath-exception-2.0"], deny=["GPL-2.0-only"])
    assert decision(pol, "GPL-2.0-only WITH Classpath-exception-2.0") == "allow"
    assert decision(pol, "GPL-2.0-only") == "deny"


@case
def policy_invalid_mode_rejected():
    try:
        policy_mod.load_policy(BAD)
    except policy_mod.PolicyError:
        return
    raise AssertionError("invalid mode should be rejected")


@case
def policy_requires_project_licence():
    try:
        policy_mod.Policy.from_dict({"mode": "saas"})
    except policy_mod.PolicyError:
        return
    raise AssertionError("project_licence is required")


@case
def policy_result_fields():
    res = default_policy().evaluate_package(pkg("MIT OR GPL-2.0-only"))
    assert res["expression"] == "MIT OR GPL-2.0-only"
    assert res["reason"] == "OR: MIT is on the allow list"
    assert set(res) == {"name", "version", "licence_raw", "expression", "decision", "reason", "source"}


# ---- report ----
def evaluated(path):
    pol = default_policy()
    return [pol.evaluate_package(p) for p in readers.read_path(path)], pol


@case
def report_text_header_has_disclaimer():
    results, pol = evaluated(NPM)
    lines = report.render_text(results, pol).splitlines()
    assert lines[0] == "licence-check 0.1.0"
    assert lines[1] == "Not legal advice; verify with qualified counsel."


@case
def report_text_sorted_deny_first():
    results, pol = evaluated(NPM)
    rows = report.render_text(results, pol).splitlines()[5:]
    assert rows[0].startswith("DENY") and rows[1].startswith("REVIEW") and rows[2].startswith("ALLOW")


@case
def report_json_valid_with_summary():
    results, pol = evaluated(NPM)
    doc = json.loads(report.render_json(results, pol))
    assert doc["summary"] == {"packages": 5, "allow": 3, "review": 1, "deny": 1}
    assert doc["disclaimer"].startswith("Not legal advice")


@case
def report_md_table():
    results, pol = evaluated(COMPOSER)
    text = report.render_md(results, pol)
    assert "| Decision | Package | Version | Licence | Reason |" in text
    assert "| DENY | vendor/agpl-lib | 1.0.0 | AGPL-3.0-only |" in text


@case
def report_md_escapes_pipes():
    assert report._cell("a|b") == "a\\|b"


@case
def report_empty_results():
    assert "Scanned 0 packages" in report.render_text([], default_policy())


# ---- CLI ----
@case
def cli_exit_1_on_deny():
    code, out, _ = run_cli([NPM])
    assert code == 1 and "DENY" in out


@case
def cli_exit_0_when_only_review_and_fail_on_deny():
    assert run_cli([BOM])[0] == 0


@case
def cli_exit_2_when_review_and_fail_on_review():
    assert run_cli([BOM, "--fail-on", "review"])[0] == 2


@case
def cli_deny_wins_over_review():
    assert run_cli([NPM, "--fail-on", "review"])[0] == 1


@case
def cli_usage_error_no_paths():
    code, _, err = run_cli([])
    assert code == 3 and "error" in err


@case
def cli_usage_error_missing_path():
    code, _, err = run_cli([os.path.join(FIX, "nope.json")])
    assert code == 3 and "path not found" in err


@case
def cli_usage_error_bad_format():
    assert run_cli([NPM, "--format", "xml"])[0] == 3


@case
def cli_usage_error_bad_policy():
    assert run_cli([NPM, "--policy", BAD])[0] == 3
    assert run_cli([NPM, "--policy", os.path.join(FIX, "nope.json")])[0] == 3


@case
def cli_version():
    code, out, _ = run_cli(["--version"])
    assert code == 0 and "0.1.0" in out


@case
def cli_help_has_disclaimer():
    code, out, _ = run_cli(["--help"])
    assert code == 0 and "Not legal advice; verify with qualified counsel." in out


@case
def cli_custom_policy_changes_exit_code():
    assert run_cli([NPM, "--policy", SAAS])[0] == 0
    assert run_cli([NPM, "--policy", SAAS, "--fail-on", "review"])[0] == 2


@case
def cli_directory_scan_finds_all_sources():
    code, out, _ = run_cli([FIX, "--format", "json"])
    assert json.loads(out)["summary"]["packages"] == 21 and code == 1


@case
def cli_json_format_parses():
    code, out, _ = run_cli([SITE, "--format", "json"])
    assert json.loads(out)["summary"]["packages"] == 4


# ---- README examples and repository rules ----
def readme_text():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


@case
def readme_examples_match_real_output():
    text = readme_text()
    runs = [
        [NPM],
        [COMPOSER, "--format", "md"],
        [BOM, "--format", "json"],
        [SPDX],
        [SITE, "--policy", SAAS, "--fail-on", "review"],
    ]
    for argv in runs:
        out = run_cli(argv)[1].strip()
        assert out in text, "README example out of date for " + " ".join(os.path.basename(a) for a in argv)


@case
def readme_required_sentences():
    text = readme_text()
    assert "This project is built and maintained by an automated agent system." in text
    assert "Not legal advice; verify with qualified counsel." in text
    assert "## Limits" in text
    for word in ("offline", "requirements.txt", "poetry.lock", "Cargo.lock", "## Team policy pack"):
        assert word in text, word


@case
def docs_have_no_link_to_unpublished_page():
    import re
    live_host = "augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev"
    allowed = ("github.com", "spdx.org", "wikipedia.org", "docs.python.org", live_host)
    md_files = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        md_files += [os.path.join(base, n) for n in files if n.endswith(".md")]
    assert md_files
    for path in md_files:
        rel = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert "gumroad.com" not in text.lower(), (rel, "gumroad.com")
        for page in re.findall(r"[\w.-]*pages\.dev", text):
            assert page == live_host, (rel, page)
        # every mention of the live host must be the full https URL
        assert text.count("pages.dev") == len(re.findall(r"https://" + re.escape(live_host) + r"(?=[/\s)>\].,;:]|$)", text)), (rel, "pages.dev")
        for url in re.findall(r"(?:https?://|www\.)([^/\s)>\]`]+)", text):
            host = url.lower()
            assert any(host == a or host.endswith("." + a) for a in allowed), (rel, host)
        assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), rel


def repo_files():
    found = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in dirs + files:
            found.append((os.path.join(base, name), os.path.isdir(os.path.join(base, name))))
    return found


@case
def repo_no_hidden_entries_or_github():
    for path, _ in repo_files():
        parts = os.path.relpath(path, ROOT).split(os.sep)
        assert not any(p.startswith(".") for p in parts), path
        assert ".github" not in parts
        assert not any("workflow" in p.lower() for p in parts), path


@case
def repo_file_count_and_size_limits():
    files = [p for p, is_dir in repo_files() if not is_dir]
    assert len(files) <= 100, len(files)
    for path in files:
        assert os.path.getsize(path) <= 200 * 1024, path


@case
def repo_allowed_extensions_only():
    allowed = {".py", ".js", ".mjs", ".ts", ".json", ".md", ".txt", ".csv", ".html", ".css",
               ".yml", ".yaml", ".toml", ".cfg"}
    for path, is_dir in repo_files():
        if is_dir:
            continue
        name = os.path.basename(path)
        assert name in ("LICENSE", ".gitignore") or os.path.splitext(name)[1].lower() in allowed, path


@case
def repo_root_files_exist():
    for name in ("README.md", "LICENSE", "CHANGELOG.md", "pyproject.toml"):
        assert os.path.isfile(os.path.join(ROOT, name)), name


@case
def repo_total_size_at_most_2mb():
    total = sum(os.path.getsize(p) for p, is_dir in repo_files() if not is_dir)
    assert total <= 2 * 1024 * 1024, total


@case
def repo_no_binaries_or_ci_files():
    ci_names = {"jenkinsfile", ".travis.yml", "azure-pipelines.yml", ".gitlab-ci.yml",
                "dependabot.yml", "funding.yml", "tox.ini", "appveyor.yml"}
    for path, is_dir in repo_files():
        if is_dir:
            continue
        assert os.path.basename(path).lower() not in ci_names, path
        with open(path, "rb") as fh:
            data = fh.read()
        assert b"\x00" not in data, "binary content: " + path
        data.decode("utf-8")


@case
def repo_no_email_or_secret_in_any_file():
    import re
    email = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
    secrets = [
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"(?i)\b(api[_-]?key|secret|token|passw(or)?d)\b\s*[:=]\s*[\"'][A-Za-z0-9/+_-]{16,}[\"']"),
        re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
    ]
    for path, is_dir in repo_files():
        if is_dir:
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert not email.search(text), "email in " + path
        for pattern in secrets:
            assert not pattern.search(text), (path, pattern.pattern)
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        assert "authors" not in fh.read()


@case
def docs_have_no_badges_or_external_images():
    import re
    for rel in ("README.md", os.path.join("policies", "README.md"), "CHANGELOG.md"):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            text = fh.read()
        assert not re.search(r"!\[[^\]]*\]\(", text), rel + ": image"
        assert "<img" not in text.lower(), rel
        assert "shields.io" not in text and "badge" not in text.lower(), rel


@case
def readme_has_no_star_counts_user_claims_or_reviews():
    import re
    text = readme_text().lower()
    assert "not legal advice; verify with qualified counsel" in text
    assert "works only where lock files or installed metadata carry licence fields" in text
    for bad in (r"\d+\s*(github\s*)?stars?\b", r"\bstarred\b", r"\btestimonial", r"\d+\s*(users|downloads|customers)\b",
                r"\btrusted by\b", r"\b\d+(\.\d)?\s*/\s*5\b", r"\bfive-star\b", r"\bcustomer reviews?\b"):
        assert not re.search(bad, text), bad


def main():
    passed = 0
    failures = []
    for func in CASES:
        try:
            func()
        except Exception as exc:  # noqa: BLE001 - report any failure and keep going
            print("FAIL %s: %r" % (func.__name__, exc))
            failures.append("%s: %r" % (func.__name__, exc))
        else:
            print("ok   %s" % func.__name__)
            passed += 1
    if failures:
        print("FAILURES:")
        for line in failures:
            print("  " + line)
    print("PASSED %d/%d" % (passed, len(CASES)))
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
