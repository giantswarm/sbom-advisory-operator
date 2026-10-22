#!/usr/bin/env python3
"""Compare kubescape SBOMSyft data against the eMudhra fixed-version table.

Input: JSON lines produced by jq from `kubectl get sbomsyfts -o json`, one object per image:
  {name, image, distro:{id, versionID, prettyName}, pkgs:[{name, version, type}]}
Output: one line per image with verdict per relevant component.

Fixed versions taken from https://emudhra.we-have-a-problem.com/ on 2026-10-21.
"""
import json
import re
import subprocess
import sys
from collections import Counter

# ---- fixed-version table ---------------------------------------------------
DEB_FIXED = {  # debian versionID -> fixed ca-certificates
    "12": "20250419~deb12u2",
    "13": "20250419+deb13u1",
}
UBUNTU_FIXED = {
    "22.04": "20260816ubuntu0.22.04.1",
    "24.04": "20260816ubuntu0.24.04.1",
    "26.04": "20260816ubuntu0.26.04.1",
    "26.10": "20260816ubuntu0.26.10.1",
}
ALPINE_FIXED = "20261020-r0"
WOLFI_FIXED = "20260909-r3"
CERTIFI_FIXED = "2026.10.19"
GO_FIXED = {"1.26": "1.26.10", "1.27": "1.27.3"}          # older minors: unfixed
NODE_FIXED = {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}  # other majors: unfixed
JAVA_FIXED = {"8": "8.0.511", "11": "11.0.33", "17": "17.0.21", "21": "21.0.13", "25": "25.0.5", "27": "27.0.1"}
COMPOSER_FIXED = {"1.4": "1.4.16", "1.6": "1.6.0"}


# ---- version comparators ---------------------------------------------------
def dpkg_cmp(a, b):
    """-1/0/1 using dpkg semantics (tilde sorts before everything)."""
    r = subprocess.run(["dpkg", "--compare-versions", a, "lt", b])
    if r.returncode == 0:
        return -1
    r = subprocess.run(["dpkg", "--compare-versions", a, "eq", b])
    return 0 if r.returncode == 0 else 1


def num_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def apk_cmp(a, b):
    """Good enough for ca-certificates: YYYYMMDD-rN."""
    return (num_tuple(a) > num_tuple(b)) - (num_tuple(a) < num_tuple(b))


def numeric_cmp(a, b):
    ta, tb = num_tuple(a), num_tuple(b)
    return (ta > tb) - (ta < tb)


def verdict(cmp):
    return "OLD" if cmp < 0 else "ok"


# ---- per-image evaluation --------------------------------------------------
def evaluate(entry):
    distro = entry.get("distro") or {}
    did = distro.get("id") or ""
    dver = distro.get("versionID") or ""
    findings = []   # (component, version, verdict, note)

    for p in entry.get("pkgs", []):
        n, v, t = (p.get("name") or ""), (p.get("version") or ""), (p.get("type") or "")
        nl = n.lower()

        if t == "deb" and nl == "ca-certificates":
            key = "debian" if did == "debian" else "ubuntu" if did == "ubuntu" else did
            table = DEB_FIXED if did == "debian" else UBUNTU_FIXED if did == "ubuntu" else {}
            fixed = table.get(dver) or table.get(dver.split(".")[0])
            if fixed:
                findings.append(("os-ca-certificates", v, verdict(dpkg_cmp(v, fixed)), f"{key} {dver} fixed {fixed}"))
            else:
                findings.append(("os-ca-certificates", v, "UNKNOWN", f"{key} {dver}: no fixed version in table"))

        elif t == "apk" and nl in ("ca-certificates", "ca-certificates-bundle"):
            if did in ("wolfi", "chainguard"):
                findings.append(("os-ca-certificates", v, verdict(apk_cmp(v, WOLFI_FIXED)), f"{did} - fixed {WOLFI_FIXED}"))
            else:
                findings.append(("os-ca-certificates", v, verdict(apk_cmp(v, ALPINE_FIXED)), f"alpine {dver} fixed {ALPINE_FIXED}"))

        elif t == "rpm" and nl == "ca-certificates":
            findings.append(("os-ca-certificates", v, "UNKNOWN", f"{did} {dver}: RHSB-2026-012, fixed build not in table"))

        elif t == "python" and nl == "certifi":
            findings.append(("certifi", v, verdict(numeric_cmp(v, CERTIFI_FIXED)), f"fixed {CERTIFI_FIXED}"))

        elif t == "go-module" and nl == "stdlib":
            vv = v.lstrip("go")
            minor = ".".join(vv.split(".")[:2])
            fixed = GO_FIXED.get(minor)
            if fixed:
                findings.append(("go-stdlib", vv, verdict(numeric_cmp(vv, fixed)), f"fixed {fixed}"))
            else:
                findings.append(("go-stdlib", vv, "OLD", "minor has no fixed release; rebuild on 1.26.10+/1.27.3+"))

        elif t == "binary" and nl == "node":
            major = v.split(".")[0]
            fixed = NODE_FIXED.get(major)
            if fixed:
                findings.append(("node", v, verdict(numeric_cmp(v, fixed)), f"fixed {fixed}"))
            else:
                findings.append(("node", v, "OLD", "major has no fixed release"))

        elif t == "binary" and nl in ("java", "openjdk", "java/jre", "java/jdk"):
            vv = v.split("+")[0].replace("1.8.0_", "8.0.").replace("_", ".")  # drop build number: 25+36 == 25.0.0
            major = vv.split(".")[0]
            fixed = JAVA_FIXED.get(major)
            if fixed:
                findings.append(("java", v, verdict(numeric_cmp(vv, fixed)), f"fixed {fixed} (cacerts), CVE-2026-91403"))
            else:
                findings.append(("java", v, "UNKNOWN", "major not in table"))

        elif t == "php-composer" and nl == "composer/ca-bundle":
            minor = ".".join(v.lstrip("v").split(".")[:2])
            fixed = COMPOSER_FIXED.get(minor, "1.6.0")
            findings.append(("composer-ca-bundle", v, verdict(numeric_cmp(v, fixed)), f"fixed {fixed}"))

        elif t == "rust-crate" and nl == "webpki-roots":
            findings.append(("webpki-roots", v, verdict(numeric_cmp(v, "1.0.10")), "fixed 1.0.10"))

    if not findings:
        findings.append(("none", "", "NO-TRUST-STORE-SEEN", f"distro={did or 'none'} {dver}"))
    return findings


def main():
    path = sys.argv[1]
    totals = Counter()
    rows = []
    with open(path) as fh:
        for line in fh:
            e = json.loads(line)
            for comp, ver, verd, note in evaluate(e):
                totals[(comp, verd)] += 1
                rows.append((verd, comp, e["image"], ver, note))

    order = {"OLD": 0, "UNKNOWN": 1, "NO-TRUST-STORE-SEEN": 2, "ok": 3}
    rows.sort(key=lambda r: (order[r[0]], r[1], r[2]))
    for verd, comp, image, ver, note in rows:
        print(f"{verd:20} {comp:20} {ver:28} {image}   [{note}]")
    print("\n== totals ==")
    for (comp, verd), c in sorted(totals.items()):
        print(f"{comp:20} {verd:20} {c}")


if __name__ == "__main__":
    main()
