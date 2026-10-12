# licence-check

Checks the licences of your dependencies against a JSON policy and reports which ones pass, need review or fail.
Run it with one command: `python -m licence_check <path>`, where the path is a lock file, an SBOM or a folder. It works offline, with the Python standard library only, and its exit code can fail a CI job.

This project is built and maintained by an automated agent system.

Not legal advice; verify with qualified counsel.

Policies: the rule sets are explained on the project's free reference page, https://augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev/ (policies: https://augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev/policies.html).

## Install

Clone the repository and run it from its root. Python 3.8 or newer, no dependencies, no network calls.

```
git clone <this repository>
cd <the cloned folder>
python -m licence_check --help
```

## Usage

Run the examples from the repository root. The output below is what the tool prints for the bundled fixtures in `tests/fixtures/`; `tests/run_tests.py` checks that each block still matches.

### 1. npm lock file, text report (exit code 1)

```
python -m licence_check tests/fixtures/package-lock.json
```

```
licence-check 0.1.0
Not legal advice; verify with qualified counsel.
Policy: default-permissive | project licence: MIT | mode: distributed-binary
Scanned 5 packages: 3 allow, 1 review, 1 deny

DENY   gamma-gpl 3.0.0  [GPL-3.0-only]  GPL-3.0-only is on the deny list
REVIEW epsilon-nolicense 0.1.0  [(none)]  no licence declared
ALLOW  alpha-mit 1.0.0  [MIT]  MIT is on the allow list
ALLOW  beta-apache 2.1.0  [Apache-2.0]  Apache-2.0 is on the allow list
ALLOW  delta-dual 1.2.3  [MIT OR GPL-2.0-only]  OR: MIT is on the allow list
```

### 2. Composer lock file, Markdown report (exit code 1)

```
python -m licence_check tests/fixtures/composer.lock.json --format md
```

```
# Licence check report

> Not legal advice; verify with qualified counsel.

- Policy: default-permissive (project licence MIT, mode distributed-binary)
- Packages: 3 (allow 1, review 1, deny 1)

| Decision | Package | Version | Licence | Reason |
|---|---|---|---|---|
| DENY | vendor/agpl-lib | 1.0.0 | AGPL-3.0-only | AGPL-3.0-only is on the deny list |
| REVIEW | vendor/lgpl-lib | 2.0.0 | LGPL-2.1-or-later | LGPL-2.1-or-later is on the review list |
| ALLOW | vendor/mit-lib | 1.1.0 | MIT | MIT is on the allow list |
```

### 3. CycloneDX SBOM, JSON report (exit code 0; 2 with `--fail-on review`)

```
python -m licence_check tests/fixtures/bom.json --format json
```

```
{
  "tool": "licence-check",
  "version": "0.1.0",
  "disclaimer": "Not legal advice; verify with qualified counsel.",
  "policy": {
    "name": "default-permissive",
    "project_licence": "MIT",
    "mode": "distributed-binary"
  },
  "summary": {
    "packages": 3,
    "allow": 2,
    "review": 1,
    "deny": 0
  },
  "results": [
    {
      "name": "cdx-custom",
      "version": "2.0.0",
      "licence_raw": "Acme Internal Licence 7",
      "expression": "UNKNOWN(Acme Internal Licence 7)",
      "decision": "review",
      "reason": "licence not recognised: 'Acme Internal Licence 7'",
      "source": "bom.json"
    },
    {
      "name": "cdx-expr",
      "version": "3.1.0",
      "licence_raw": "Apache-2.0 OR MIT",
      "expression": "Apache-2.0 OR MIT",
      "decision": "allow",
      "reason": "OR: Apache-2.0 is on the allow list",
      "source": "bom.json"
    },
    {
      "name": "cdx-mit",
      "version": "1.0.0",
      "licence_raw": "MIT",
      "expression": "MIT",
      "decision": "allow",
      "reason": "MIT is on the allow list",
      "source": "bom.json"
    }
  ]
}
```

### 4. Python site-packages with a SaaS policy (exit code 2)

```
python -m licence_check tests/fixtures/site-packages --policy tests/fixtures/policy-saas.json --fail-on review
```

```
licence-check 0.1.0
Not legal advice; verify with qualified counsel.
Policy: saas-strict | project licence: Proprietary | mode: saas
Scanned 4 packages: 2 allow, 2 review, 0 deny

REVIEW pydelta 4.0  [(none)]  no licence declared
REVIEW pygamma 3.0  [GPL-3.0-only]  GPL-3.0-only (strong-copyleft) defaults to review in mode saas
ALLOW  pyalpha 1.0  [MIT]  MIT is on the allow list
ALLOW  pybeta 2.0  [Apache-2.0]  Apache-2.0 is on the allow list
```

You can pass several paths, or a directory: a directory is scanned for `package-lock.json`, `composer.lock`, other `.json` files that look like npm, Composer or CycloneDX files, and a `site-packages` or `dist-packages` folder.

Options: `--policy FILE`, `--format text|json|md`, `--fail-on deny|review`, `--version`, `--help`.

## Policy schema

A policy is a JSON object: `project_licence` (required, informational), `mode` (required: `internal`, `saas`, `distributed-binary` or `distributed-source`), optional `name`, `allow`, `deny` and `review` lists of SPDX ids, and optional per-package `exceptions`.

- The decision order for one licence id is: deny list, allow list, review list, then a default for its category in the chosen mode, then review.
- In an SPDX expression, `OR` passes if any branch is allowed, `AND` needs every branch, and `WITH` exceptions are matched as written.
- A missing, ambiguous (plain `BSD`) or unrecognised licence is `review`.

Full schema, mode defaults and an exception example: `policies/README.md`. The bundled `policies/default.json` is a permissive-project policy. The category table behind the mode defaults is `data/spdx_ids.json` (about 60 common ids); categories are the maintainer's interpretation and may become outdated.

## Exit codes (for CI)

| Code | Meaning |
|---|---|
| 0 | No deny result (and no review result if `--fail-on review`). |
| 1 | At least one package is denied. |
| 2 | No deny, but at least one review result with `--fail-on review`. |
| 3 | Usage error: bad arguments, unreadable path or file, invalid policy. |

Example CI step: `python -m licence_check package-lock.json --policy my-policy.json --fail-on review`.

## Limits

- Detection is offline. It works only where lock files or installed metadata carry licence fields: npm `package-lock.json` v2/v3 `license`, Composer `license`, CycloneDX `licenses`, and Python `License-Expression`, `License` or `License ::` classifiers.
- A pip `requirements.txt`, a `poetry.lock` or a `Cargo.lock` alone is not enough, because they do not carry licence fields. For Python, point the tool at an installed site-packages directory instead.
- npm lockfile v1 has no licence fields, so every package from it is reported as missing and goes to review.
- When a package lists several licences (Composer arrays, several Python classifiers) they are read as alternatives (`OR`); several CycloneDX licence entries are read as all applying (`AND`).
- Python classifiers are coarse: `BSD License` does not say which BSD, so it goes to review.
- Compatibility is judged by your policy, not by a legal analysis of how the code is combined.

Not legal advice; verify with qualified counsel.

## Team policy pack

The free reference for the rule sets is the project's page at https://augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev/policies.html (home page: https://augeo-licence-policy-pack-for-dependency-licen-15b5.pages.dev/). A maintained pack of ready-made policies for common team setups is planned and is not linked from here. The tool and this repository stay free and open source.

## Tests

```
python tests/run_tests.py
```

It runs in-process, writes no files and needs no network. It also asserts the repository rules (no hidden files, size and file-count limits, allowed extensions, required README sentences).

## Licence

MIT, see `LICENSE`.
