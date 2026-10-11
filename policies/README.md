# Policy files

A policy is one JSON object. `python -m licence_check <paths> --policy FILE` loads it.
Not legal advice; verify with qualified counsel.

## Schema

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | no | Label printed in reports (default `unnamed`). |
| `project_licence` | string | yes | Licence of your own project. Informational: it is printed in reports and does not change decisions. |
| `mode` | string | yes | One of `internal`, `saas`, `distributed-binary`, `distributed-source`. Picks the default for licences not named in any list. |
| `allow` | list of SPDX ids | no | Licences that pass. |
| `deny` | list of SPDX ids | no | Licences that fail (exit code 1). |
| `review` | list of SPDX ids | no | Licences that need a person to decide (exit code 2 with `--fail-on review`). |
| `exceptions` | list of objects | no | Per-package overrides, see below. |

List entries are case-insensitive and common aliases are accepted (`GPL-3.0` means `GPL-3.0-only`).
An entry may name an exception, for example `GPL-2.0-only WITH Classpath-exception-2.0`; the
exact `WITH` entry is checked before the plain licence id.

## Decision order for one licence id

1. `deny` list, 2. `allow` list, 3. `review` list, 4. the mode default for the licence category
(see `data/spdx_ids.json`), 5. anything else (proprietary, other, uncategorised) is `review`.

For an expression: `OR` passes if any branch is allowed (the most permissive branch wins),
`AND` needs every branch (the strictest wins). A missing, ambiguous (for example plain `BSD`)
or unrecognised licence is `review`.

## Mode defaults

| Category | internal | saas | distributed-binary | distributed-source |
|---|---|---|---|---|
| permissive, public-domain | allow | allow | allow | allow |
| weak-copyleft | allow | allow | review | allow |
| strong-copyleft | allow | review | deny | review |
| network-copyleft | review | deny | deny | deny |

These defaults are the maintainer's interpretation and may become outdated.

## Exceptions

```json
{"package": "some-package", "version": "1.2.3", "decision": "allow", "reason": "build tooling only"}
```

`package` and `decision` (`allow`, `review` or `deny`) are required. `version` is optional; without
it the exception covers every version. `reason` is printed in the report.

## Included

`default.json`: a permissive-project policy for distributed software (MIT project,
`distributed-binary` mode).
