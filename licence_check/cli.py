"""Command line entry point. Exit codes: 0 clean, 1 deny, 2 review (--fail-on review), 3 usage."""

import argparse
import os
import sys

from . import DISCLAIMER, __version__, policy as policy_mod, readers, report

DEFAULT_POLICY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies", "default.json"
)


class _Usage(Exception):
    pass


class _ArgParser(argparse.ArgumentParser):
    def error(self, message):
        raise _Usage(message)


def _build_parser():
    parser = _ArgParser(
        prog="licence-check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Check dependency licences offline against a policy.\n"
            "Reads package-lock.json, composer.lock, CycloneDX JSON SBOMs and Python\n"
            "site-packages directories. No network access.\n\n" + DISCLAIMER
        ),
        epilog=(
            "exit codes: 0 clean, 1 deny found, 2 review found with --fail-on review, "
            "3 usage error\n" + DISCLAIMER
        ),
    )
    parser.add_argument("paths", nargs="*", help="lock files, SBOM files or directories")
    parser.add_argument("--policy", help="policy JSON file (default: policies/default.json)")
    parser.add_argument("--format", choices=("text", "json", "md"), default="text")
    parser.add_argument("--fail-on", dest="fail_on", choices=("deny", "review"), default="deny")
    parser.add_argument("--version", action="version", version="licence-check " + __version__)
    return parser


def _run(argv):
    args = _build_parser().parse_args(argv)
    if not args.paths:
        raise _Usage("no paths given; pass a lock file, an SBOM or a site-packages directory")
    pol = policy_mod.load_policy(args.policy or DEFAULT_POLICY)
    packages = []
    for path in args.paths:
        packages.extend(readers.read_path(path))
    results = [pol.evaluate_package(p) for p in packages]
    print(report.render(args.format, results, pol))
    counts = report.summarize(results)
    if counts["deny"]:
        return 1
    if counts["review"] and args.fail_on == "review":
        return 2
    return 0


def main(argv=None):
    try:
        return _run(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    except (_Usage, readers.ReaderError, policy_mod.PolicyError) as exc:
        print("licence-check: error: %s" % exc, file=sys.stderr)
        return 3
