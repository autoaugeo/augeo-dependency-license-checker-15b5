"""Offline readers. Each returns a list of {name, version, licence_raw, source}.

Nothing is fetched: a licence is only known when the file carries it.
"""

import json
import os


class ReaderError(Exception):
    pass


_CLASSIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
}


def _pkg(name, version, raw, source):
    return {
        "name": str(name or ""),
        "version": str(version or ""),
        "licence_raw": raw,
        "source": source,
    }


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReaderError("cannot read %s: %s" % (path, exc))


def _join(parts, op):
    parts = [p for p in parts if p]
    if not parts:
        return None
    if op == " AND " and len(parts) > 1:
        parts = ["(%s)" % p if " or " in p.lower() else p for p in parts]
    return op.join(parts)


def _npm_license(value):
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        kind = value.get("type")
        return kind.strip() if isinstance(kind, str) and kind.strip() else None
    if isinstance(value, list):
        return _join([_npm_license(v) for v in value], " OR ")
    return None


def _npm_from_data(data, source):
    out = []
    packages = data.get("packages") if isinstance(data, dict) else None
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if key == "" or not isinstance(entry, dict) or entry.get("link"):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append(_pkg(name, entry.get("version"), _npm_license(entry.get("license")), source))
        return out
    if isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
        # lockfile v1 carries no licence fields: every package is reported as missing
        def walk(deps):
            for name, entry in deps.items():
                if not isinstance(entry, dict):
                    continue
                out.append(_pkg(name, entry.get("version"), None, source))
                if isinstance(entry.get("dependencies"), dict):
                    walk(entry["dependencies"])

        walk(data["dependencies"])
        return out
    raise ReaderError("not an npm lock file: " + source)


def _composer_from_data(data, source):
    if not isinstance(data, dict):
        raise ReaderError("not a composer lock file: " + source)
    out = []
    for section in ("packages", "packages-dev"):
        items = data.get(section)
        for entry in items if isinstance(items, list) else []:
            if not isinstance(entry, dict):
                continue
            lic = entry.get("license")
            if isinstance(lic, list):
                raw = _join([x.strip() for x in lic if isinstance(x, str)], " OR ")
            elif isinstance(lic, str):
                raw = lic.strip() or None
            else:
                raw = None
            out.append(_pkg(entry.get("name"), entry.get("version"), raw, source))
    return out


def _cdx_license(licenses):
    if not isinstance(licenses, list):
        return None
    parts = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        expr = item.get("expression")
        if isinstance(expr, str) and expr.strip():
            parts.append(expr.strip())
            continue
        lic = item.get("license")
        if isinstance(lic, dict):
            value = lic.get("id") or lic.get("name")
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
    return _join(parts, " AND ")


def _cdx_from_data(data, source):
    if not isinstance(data, dict):
        raise ReaderError("not a CycloneDX file: " + source)
    out = []

    def walk(components):
        for comp in components if isinstance(components, list) else []:
            if not isinstance(comp, dict):
                continue
            name = comp.get("name")
            if comp.get("group") and name:
                name = "%s/%s" % (comp["group"], name)
            out.append(_pkg(name, comp.get("version"), _cdx_license(comp.get("licenses")), source))
            walk(comp.get("components"))

    walk(data.get("components"))
    return out


_SPDX_EMPTY = ("", "noassertion", "none")


def _spdx_value(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return None if value.lower() in _SPDX_EMPTY else value


def _spdx_root_ids(data):
    """SPDXIDs of the packages the document says it describes."""
    roots = set()
    described = data.get("documentDescribes")
    for ref in described if isinstance(described, list) else []:
        if isinstance(ref, str):
            roots.add(ref)
    relationships = data.get("relationships")
    for rel in relationships if isinstance(relationships, list) else []:
        if not isinstance(rel, dict):
            continue
        kind = str(rel.get("relationshipType") or "").upper()
        first, second = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        if kind == "DESCRIBES" and first == "SPDXRef-DOCUMENT" and isinstance(second, str):
            roots.add(second)
        elif kind == "DESCRIBED_BY" and second == "SPDXRef-DOCUMENT" and isinstance(first, str):
            roots.add(first)
    return roots


def _spdx_from_data(data, source):
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, list):
        raise ReaderError("not an SPDX JSON file: " + source)
    roots = _spdx_root_ids(data)
    out = []
    for entry in packages:
        if not isinstance(entry, dict) or entry.get("SPDXID") in roots:
            continue
        raw = _spdx_value(entry.get("licenseConcluded")) or _spdx_value(entry.get("licenseDeclared"))
        out.append(_pkg(entry.get("name"), entry.get("versionInfo"), raw, source))
    return out


def read_spdx(path):
    return _spdx_from_data(_load_json(path), os.path.basename(path))


def read_npm(path):
    return _npm_from_data(_load_json(path), os.path.basename(path))


def read_composer(path):
    return _composer_from_data(_load_json(path), os.path.basename(path))


def read_cyclonedx(path):
    return _cdx_from_data(_load_json(path), os.path.basename(path))


def _parse_metadata(meta_path, dist_info_name):
    with open(meta_path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    name = version = expression = lic = None
    classifiers = []
    for line in text.splitlines():
        if not line.strip():
            break
        if line[0] in " \t" or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "name":
            name = value
        elif key == "version":
            version = value
        elif key == "license-expression":
            expression = value
        elif key == "license":
            lic = value
        elif key == "classifier" and value.startswith("License ::"):
            classifiers.append(value)
    if not name:
        stem = dist_info_name[: -len(".dist-info")]
        name, _, fallback_version = stem.rpartition("-")
        name = name or stem
        version = version or fallback_version
    if lic is not None and (not lic or lic.upper() == "UNKNOWN"):
        lic = None
    ids = []
    for cls in classifiers:
        mapped = _CLASSIFIERS.get(cls) or cls.split("::")[-1].strip()
        if mapped not in ids:
            ids.append(mapped)
    if expression:
        raw = expression
    elif lic and len(lic) <= 100:
        raw = lic
    elif ids:
        raw = " OR ".join(ids)
    elif lic:
        raw = lic[:80]
    else:
        raw = None
    return _pkg(name, version, raw, dist_info_name)


def read_python_site_packages(path):
    """Scan a site-packages directory for *.dist-info/METADATA (or METADATA.txt)."""
    if not os.path.isdir(path):
        raise ReaderError("not a directory: " + path)
    out = []
    for entry in sorted(os.listdir(path)):
        if not entry.endswith(".dist-info"):
            continue
        for fname in ("METADATA", "METADATA.txt"):
            candidate = os.path.join(path, entry, fname)
            if os.path.isfile(candidate):
                out.append(_parse_metadata(candidate, entry))
                break
    return out


def _sniff(data):
    if not isinstance(data, dict):
        return None
    version = data.get("spdxVersion")
    if isinstance(version, str) and version.startswith("SPDX-2") and isinstance(data.get("packages"), list):
        return "spdx"
    if "bomFormat" in data or isinstance(data.get("components"), list):
        return "cyclonedx"
    packages = data.get("packages")
    if isinstance(packages, dict) or "lockfileVersion" in data:
        return "npm"
    if isinstance(packages, list) or isinstance(data.get("packages-dev"), list):
        return "composer"
    return None


_BY_KIND = {"npm": _npm_from_data, "composer": _composer_from_data, "cyclonedx": _cdx_from_data, "spdx": _spdx_from_data}
_BY_NAME = {"package-lock.json": "npm", "composer.lock": "composer"}


def read_file(path):
    name = os.path.basename(path)
    data = _load_json(path)
    kind = _BY_NAME.get(name) or _sniff(data)
    if kind is None:
        raise ReaderError("unrecognised file type: " + path)
    return _BY_KIND[kind](data, name)


def _has_dist_info(path):
    try:
        return any(e.endswith(".dist-info") for e in os.listdir(path))
    except OSError:
        return False


def read_dir(path):
    out = []
    found = False
    if _has_dist_info(path):
        out.extend(read_python_site_packages(path))
        found = True
    for entry in sorted(os.listdir(path)):
        full = os.path.join(path, entry)
        if os.path.isfile(full) and (entry.endswith(".json") or entry == "composer.lock"):
            try:
                data = _load_json(full)
            except ReaderError:
                continue
            kind = _BY_NAME.get(entry) or _sniff(data)
            if kind:
                out.extend(_BY_KIND[kind](data, entry))
                found = True
        elif os.path.isdir(full) and entry in ("site-packages", "dist-packages"):
            if _has_dist_info(full):
                out.extend(read_python_site_packages(full))
                found = True
    if not found:
        raise ReaderError("no supported files found in: " + path)
    return out


def read_path(path):
    if os.path.isdir(path):
        return read_dir(path)
    if os.path.isfile(path):
        return read_file(path)
    raise ReaderError("path not found: " + path)
