# Changelog

## 0.2.0 (not yet tagged)

- New: SPDX 2.x JSON SBOM reader. A `.json` file with `spdxVersion` is detected by
  sniffing, also in directory scans. It uses `licenseConcluded`, falls back to
  `licenseDeclared` when the first is missing, `NOASSERTION` or `NONE`, and skips the
  package named by `documentDescribes` or a `DESCRIBES` relationship. Fixture
  `tests/fixtures/sbom.spdx.json`, six new tests and a README section.
- Docs: the README opening uses the American spelling people search for (dependency
  license checker, license compliance, SBOM, SPDX, CycloneDX).

## Unreleased

- Docs: the README now opens with the one command to run (`python -m licence_check <path>`)
  and points to the project's free reference page for the rule sets,
  https://augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev/ . Tests: the
  link check in every Markdown file allows exactly that host and still fails on any other
  non-reference host.
- Tests: `tests/run_tests.py` now asserts every rule of the GitHub publish rail: total
  size, no binaries or CI files, no email address or secret-like string in any file,
  link hosts limited to reference sites, no images, and no star counts,
  user claims or reviews in the README.

## 0.1.1

- Fix: a single CycloneDX licence entry holding an `OR` expression was wrapped in
  parentheses (`(Apache-2.0 OR MIT)`); parentheses are now added only when several
  licence entries are joined with `AND`. This fixes the `cyclonedx_reader` test and
  makes the README JSON example (`bom.json --format json`) match the real output.
- Tests: `tests/run_tests.py` prints a `FAILURES:` block (one line per failed test)
  right before the `PASSED n/n` line, and still exits 1 on any failure.

## 0.1.0

- First release: SPDX expression parser, offline readers (npm `package-lock.json` v2/v3,
  `composer.lock`, CycloneDX JSON, Python `*.dist-info` metadata), JSON policies with
  `allow` / `deny` / `review` lists, distribution modes and per-package exceptions,
  text / JSON / Markdown reports, CI exit codes.
