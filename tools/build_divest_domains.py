#!/usr/bin/env python3
"""Rebuild the Divest-style domain blocklist from the living sources.

Reads divest-sources.txt (one URL per line), downloads each list, normalizes
the common formats (hosts file, plain domains, AdBlock-ish lines) and writes
a deduplicated domain list.

Usage:
    python3 tools/build_divest_domains.py [--sources FILE] [-o OUT]
    python3 tools/build_divest_domains.py --compare divest.zip

--compare divest.zip prints how much of the manual Divest snapshot the
rebuilt list reproduces (and what the snapshot has extra), so you can decide
with numbers whether to keep the manual zip as fallback.
"""
import argparse
import io
import re
import sys
import urllib.request
import zipfile

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}

IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$"
)
ADBLOCK = re.compile(r"^\|\|([a-z0-9.-]+)\^")


def normalize_line(line):
    """Return a lowercase domain from a hosts/plain/AdBlock line, else None."""
    line = line.strip()
    if not line or line.startswith(("#", "!", "[")):
        return None
    m = ADBLOCK.match(line)
    if m:
        d = m.group(1)
    elif re.match(r"^(\d{1,3}\.){3}\d{1,3}[\s|]", line) or "\t" in line or " " in line:
        # hosts format: "0.0.0.0 domain" / "127.0.0.1<TAB>domain"
        parts = line.split()
        d = parts[1] if len(parts) >= 2 and IP.match(parts[0]) else None
        if d is None:
            return None
    else:
        d = line
    d = d.lower().strip().lstrip("*.").rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if d and not IP.match(d) and DOMAIN.match(d):
        return d
    return None


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    if data[:2] == b"PK":  # zip
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = b"\n".join(z.read(n) for n in z.namelist())
    return data.decode("utf-8", "ignore")


def build(sources_file):
    ok, dead, domains = 0, [], set()
    with open(sources_file, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    for u in urls:
        try:
            text = fetch(u)
            n = 0
            for line in text.splitlines():
                d = normalize_line(line)
                if d:
                    domains.add(d)
                    n += 1
            if n == 0:
                dead.append((u, "empty/no domains parsed"))
            else:
                ok += 1
                print(f"OK   {n:7d}  {u}", file=sys.stderr)
        except Exception as e:
            dead.append((u, str(e)[:80]))
            print(f"FAIL      {u}  ({e})", file=sys.stderr)
    return ok, dead, domains


def load_zip_snapshot(path):
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.lower().endswith((".txt", ".mhtml", ".mht"))]
        text = "\n".join(z.read(n).decode("utf-8", "ignore") for n in names)
    return {d for d in (normalize_line(l) for l in text.splitlines()) if d}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="divest-sources.txt")
    ap.add_argument("-o", "--output", default="divested-rebuilt.txt")
    ap.add_argument("--compare", metavar="ZIP", help="compare against a divest.zip snapshot")
    args = ap.parse_args()

    ok, dead, domains = build(args.sources)
    with open(args.output, "w") as f:
        f.write("\n".join(sorted(domains)) + "\n")
    print(f"\n{ok}/{ok + len(dead)} sources OK, {len(domains)} unique domains -> {args.output}")
    if dead:
        print("\nDead/empty sources:")
        for u, why in dead:
            print(f"  {u}  ({why})")

    if args.compare:
        snap = load_zip_snapshot(args.compare)
        inter = domains & snap
        print(f"\nCompare with {args.compare}: snapshot={len(snap)} domains, "
              f"rebuilt={len(domains)}, common={len(inter)} "
              f"({100 * len(inter) / max(1, len(snap)):.1f}% of snapshot reproduced, "
              f"{100 * len(inter) / max(1, len(domains)):.1f}% of rebuilt in snapshot)")


if __name__ == "__main__":
  main()
