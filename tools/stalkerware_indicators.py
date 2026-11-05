#!/usr/bin/env python3
"""Turn the Stalkerware Indicators samples.csv (AssoEchap/stalkerware-indicators)
into the text list consumed by `App <dir> -stalkerware`.

    python3 tools/stalkerware_indicators.py --input various/stalkerware.csv > raw-stalkerware/stalkerware.txt
    python3 tools/stalkerware_indicators.py --download > raw-stalkerware/stalkerware.txt

samples.csv columns (same order as the "Stalkerware" step of generate_stable.yml):
    sha256, package, certificate, version, name

Output, one indicator per line, deduplicated and sorted:
    pkg:<android package name, lowercase>
    cert:<signing certificate fingerprint, lowercase hex, SHA-1 (40) or SHA-256 (64)>

Package names that look like system/Google packages are reported on stderr so a
maintainer can review them: the app ignores package-only matches on system apps,
but a certificate match is always decisive.
"""
import argparse
import csv
import io
import re
import sys
import urllib.request

URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/refs/heads/master/samples.csv"
PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
HEX = re.compile(r"^[0-9a-f]+$")
SUSPICIOUS_PREFIXES = ("android.", "com.android.", "com.google.", "com.samsung.", "com.sec.", "com.huawei.", "com.xiaomi.")


def read_text(args):
    if args.input:
        with open(args.input, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    req = urllib.request.Request(URL, headers={"User-Agent": "HypatiaDatabases-CI"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read().decode("utf-8", "ignore")


def normalize_cert(raw):
    value = re.sub(r"[^0-9A-Fa-f]", "", raw or "").lower()
    return value if len(value) in (40, 64) and HEX.match(value) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="local samples.csv")
    group.add_argument("--download", action="store_true", help="download samples.csv from GitHub")
    args = parser.parse_args()

    packages, certs = set(), set()
    rows = bad_pkg = bad_cert = 0
    for fields in csv.reader(io.StringIO(read_text(args))):
        if len(fields) < 3:
            continue
        rows += 1
        package = fields[1].strip()
        if package:
            if PACKAGE.match(package):
                packages.add(package.lower())
            elif package.lower() != "package":  # header row
                bad_pkg += 1
        cert_raw = fields[2].strip()
        if cert_raw:
            cert = normalize_cert(cert_raw)
            if cert:
                certs.add(cert)
            elif cert_raw.lower() != "certificate":
                bad_cert += 1

    review = sorted(p for p in packages if p.startswith(SUSPICIOUS_PREFIXES))
    if review:
        print(f"REVIEW: {len(review)} package names look like system packages: {review[:20]}", file=sys.stderr)
    print(f"stalkerware indicators: {rows} rows, {len(packages)} packages, {len(certs)} certificates, "
          f"{bad_pkg} invalid packages, {bad_cert} invalid certificates", file=sys.stderr)
    if not packages and not certs:
        sys.exit("no indicator extracted: did the samples.csv layout change?")

    for p in sorted(packages):
        print(f"pkg:{p}")
    for c in sorted(certs):
        print(f"cert:{c}")


if __name__ == "__main__":
    main()
