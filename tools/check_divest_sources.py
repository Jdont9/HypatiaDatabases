#!/usr/bin/env python3
"""Check that the source lists behind the Divested domain blocklist are still reachable.

The header of the divested.dev "hosts-domains" snapshot (.mhtml) lists every input list
as "#<LICENSE> - <URL>". This script extracts those URLs (or reads a plain text file with
one URL per line), downloads each one the way the CI would, and reports:

  status / final URL / size / number of domain-looking lines / flags

Flags: HTTP (error or timeout), HTML (a web page instead of a list), FEW (< --min-domains
domains parsed), HOST (redirected to another host), SLOW (> 20 s).

    python3 tools/check_divest_sources.py divest.zip
    python3 tools/check_divest_sources.py divest-sources.txt --strict

Run it from a GitHub runner (workflow "Check Divest sources"): availability from there is
what matters, not from a developer machine. Output is also appended to $GITHUB_STEP_SUMMARY.
"""
import argparse
import concurrent.futures
import email
import email.policy
import html
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

UA = "HypatiaDatabases-CI-sourcecheck/1.0"
LINE = re.compile(r"^#\s*([^\t\-][^\t]*?)\s+-\s+(https?://\S+)\s*$")
DOMAIN = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$")


def read_text(path):
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.lower().endswith((".mhtml", ".mht", ".txt")))
            raw = z.read(name)
    else:
        raw = open(path, "rb").read()
    if raw[:5] == b"From:" or b"MultipartBoundary" in raw[:2000]:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                text = part.get_content()
                m = re.search(r"<pre[^>]*>(.*?)</pre>", text, re.S | re.I)
                return html.unescape(m.group(1) if m else re.sub(r"<[^>]+>", "", text))
    return raw.decode("utf-8", "ignore")


def extract_sources(text):
    sources, seen = [], set()
    for line in text.splitlines()[:400]:
        m = LINE.match(line.strip())
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            sources.append((m.group(1).strip(), m.group(2)))
    if not sources:  # plain list: one URL per line
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("http") and line not in seen:
                seen.add(line)
                sources.append(("?", line))
    return sources


def count_domains(body):
    n = 0
    for raw in body.splitlines():
        s = raw.strip().lower()
        if not s or s[0] in "#!;[":
            continue
        s = s.split("#")[0].strip()
        parts = s.split()
        if len(parts) >= 2 and re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1?)$", parts[0]):
            s = parts[1]
        else:
            s = parts[0] if parts else ""
        s = s.lstrip("|").split("^")[0].split("/")[0].lstrip("*.")
        if DOMAIN.match(s):
            n += 1
    return n


def check(source, timeout, max_bytes, min_domains):
    license_, url = source
    start = time.time()
    res = {"license": license_, "url": url, "status": "-", "final": url, "bytes": 0, "domains": 0, "flags": []}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain,*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res["status"] = str(r.status)
            res["final"] = r.geturl()
            ctype = (r.headers.get("Content-Type") or "").lower()
            data = r.read(max_bytes)
            res["bytes"] = len(data)
            body = data.decode("utf-8", "ignore")
            res["domains"] = count_domains(body)
            if "html" in ctype or body.lstrip()[:1] == "<":
                res["flags"].append("HTML")
            if res["domains"] < min_domains:
                res["flags"].append("FEW")
            if urllib.parse.urlparse(res["final"]).netloc != urllib.parse.urlparse(url).netloc:
                res["flags"].append("HOST")
    except urllib.error.HTTPError as e:
        res["status"] = str(e.code)
        res["flags"].append("HTTP")
    except Exception as e:
        res["status"] = type(e).__name__
        res["flags"].append("HTTP")
    res["secs"] = time.time() - start
    if res["secs"] > 20:
        res["flags"].append("SLOW")
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="divest .zip/.mhtml snapshot or a text file with one URL per line")
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--max-mb", type=int, default=60)
    ap.add_argument("--min-domains", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--strict", action="store_true", help="exit 1 if any source is flagged")
    args = ap.parse_args()

    sources = extract_sources(read_text(args.source))
    if not sources:
        sys.exit("No source URL found.")
    print(f"{len(sources)} sources to check", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(lambda s: check(s, args.timeout, args.max_mb * 1048576, args.min_domains), sources))

    bad = [r for r in results if r["flags"]]
    lines = [f"### Divest sources: {len(results) - len(bad)} OK, {len(bad)} to review", "",
             "| | status | domains | size | flags | URL |", "|---|---|---:|---:|---|---|"]
    for r in sorted(results, key=lambda r: (not r["flags"], r["url"])):
        mark = "⚠️" if r["flags"] else "✅"
        shown = r["url"] if "HOST" not in r["flags"] else f'{r["url"]} → {r["final"]}'
        lines.append(f'| {mark} | {r["status"]} | {r["domains"]} | {r["bytes"] // 1024} KB | {",".join(r["flags"])} | {shown} |')
    out = "\n".join(lines)
    print(out)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(out + "\n")
    sys.exit(1 if (bad and args.strict) else 0)


if __name__ == "__main__":
    main()
