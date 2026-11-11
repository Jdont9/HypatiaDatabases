#!/usr/bin/env python3
"""Fetch the "extra" domain sources of generate_stable.yml, ONE FILE PER SOURCE.

The main workflow appends every extra source into various/domains-extra.txt, so
the origin of a domain is lost. This script mirrors the same extraction rules
but keeps the sources apart, so tools/zip_only_coverage.py can say *which*
source covers a domain that only divest.zip has.

Sources: hagezi-tif, phishing-database, openphish, phishunt, mvt, avast,
infosec, citizenlab, threatfox (needs ABUSECH_KEY), urlhaus (needs ABUSECH_KEY).

Usage:
    python3 tools/fetch_extra_domains.py OUT_DIR

Each source is best effort: a failing source is reported and skipped.
Keep the extraction rules in sync with .github/workflows/generate_stable.yml.
"""
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from urllib.parse import urlparse

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HOST = re.compile(r"([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
DOM = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
FILE_EXT_TF = re.compile(r"\.(csv|zip|txt|html?|php|aspx?|js|css|png|jpe?g|gif|svg|ico|pdf|xml|json)$")
FILE_EXT_INFOSEC = re.compile(
    r"\.(dll|exe|tmp|pdf|bin|dat|jpg|png|gif|zip|rar|7z|ps1|bat|vbs|js|hta|jar|txt|md|csv|"
    r"xls|xlsx|doc|docx|ppt|pptx|msi|scr|pif|lnk|iso|img|cab|sys)$"
)


def http_get(url, headers=None, timeout=180):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    if data[:200].lower().lstrip().startswith((b"<!doctype", b"<html")):
        raise ValueError("got an HTML page instead of a list")
    return data


def first_working(urls):
    last = None
    for u in urls:
        try:
            return http_get(u).decode("utf-8", "ignore")
        except Exception as e:  # noqa: BLE001 - best effort, report and try next
            last = e
            print(f"  mirror failed: {u} ({e})", file=sys.stderr)
    raise RuntimeError(f"all mirrors failed ({last})")


def defang(text):
    for a, b in (("hxxps", "http"), ("hxxp", "http"), ("[:]", ":"), ("[.]", "."), ("[,]", ",")):
        text = text.replace(a, b)
    return text


def hostnames(text, exclude=None):
    out = set()
    for m in HOST.finditer(text):
        h = m.group(0).lower()
        if exclude and exclude.search(h):
            continue
        out.add(h)
    return out


def plain_list(text):
    out = set()
    for l in text.replace("\r", "").splitlines():
        l = l.strip().lower()
        if not l or l[0] in "#!":
            continue
        out.add(l.lstrip("*."))
    return out


def clone(url, dest):
    subprocess.run(["git", "clone", "--depth", "1", "-q", url, dest], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def walk(root, suffix=None, name=None):
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            if name and f != name:
                continue
            if suffix and not f.lower().endswith(suffix):
                continue
            yield os.path.join(r, f)


def read(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


# ---------------------------------------------------------------- sources
def src_hagezi(_tmp):
    return plain_list(first_working([
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
    ]))


def src_phishing_database(_tmp):
    return plain_list(first_working([
        "https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "https://cdn.jsdelivr.net/gh/Phishing-Database/Phishing.Database@master/phishing-domains-ACTIVE.txt",
    ]))


def src_openphish(_tmp):
    out = set()
    for line in first_working(["https://openphish.com/feed.txt"]).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        h = (urlparse(line if "://" in line else "http://" + line).hostname or "").lower().strip(".")
        if h and not IP.match(h) and "." in h:
            out.add(h)
    return out


def src_phishunt(_tmp):
    data = json.loads(first_working(["https://phishunt.io/api/v1/domains?format=json"]))
    out = set()
    for item in data.get("results", []) or []:
        d = (item.get("domain") or "").lower().lstrip("*.")
        if re.match(r"^[a-z0-9._-]+\.[a-z0-9-]{2,}$", d):
            out.add(d)
    return out


def src_mvt(tmp):
    dest = os.path.join(tmp, "mvt")
    clone("https://github.com/mvt-project/mvt-indicators.git", dest)
    out = set()
    for p in walk(dest, name="domains.txt"):
        out |= plain_list(read(p))
    return out


def src_avast(tmp):
    dest = os.path.join(tmp, "avast")
    clone("https://github.com/avast/ioc", dest)
    text = "\n".join(read(p) for p in walk(dest, suffix=".txt"))
    return hostnames(defang(text))


def src_infosec(tmp):
    dest = os.path.join(tmp, "infosec")
    clone("https://github.com/GithubInfosec/latest-malware-IoC", dest)
    text = "\n".join(read(p) for p in walk(dest, suffix=".md") if os.path.basename(p) != "README.md")
    return hostnames(defang(text), exclude=FILE_EXT_INFOSEC)


def src_citizenlab(tmp):
    dest = os.path.join(tmp, "citizenlab")
    clone("https://github.com/citizenlab/malware-indicators.git", dest)
    out = set()
    for p in walk(dest, suffix=".csv"):
        with open(p, newline="", encoding="utf-8", errors="ignore") as fh:
            for row in csv.DictReader(fh):
                r = {k.strip().lower(): (v or "").strip() for k, v in row.items()
                     if k is not None and isinstance(v, (str, type(None)))}
                typ, val = r.get("type", "").lower(), r.get("value", "")
                if not val:
                    continue
                host = ""
                if typ in ("domain", "hostname") or typ.startswith(("domain|", "hostname|")):
                    host = val.split("|")[0]
                elif typ == "url":
                    host = urlparse(val if "://" in val else "http://" + val).hostname or ""
                host = host.lower().strip(".")
                if host and not IP.match(host) and DOM.match(host):
                    out.add(host)
    return out


def src_threatfox(_tmp):
    key = os.environ.get("ABUSECH_KEY", "")
    if not key:
        raise RuntimeError("ABUSECH_KEY not set")
    data = http_get(f"https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip", timeout=600)
    out = set()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            if n.lower().endswith(".csv"):
                out |= hostnames(z.read(n).decode("utf-8", "ignore"), exclude=FILE_EXT_TF)
    return out


def src_urlhaus(_tmp):
    key = os.environ.get("ABUSECH_KEY", "")
    if not key:
        raise RuntimeError("ABUSECH_KEY not set")
    data = http_get(f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
                    headers={"Auth-Key": key})
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = b"\n".join(z.read(n) for n in z.namelist())
    out = set()
    for line in data.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = next(csv.reader([line]), [])
        url = next((f for f in fields if re.match(r"^https?://", f, re.I)), None)
        if url:
            status = next((f.lower() for f in fields if f.lower() in ("online", "offline")), "")
            if status == "offline":  # same as URLHAUS_ONLY_ONLINE=1 in the main workflow
                continue
            h = (urlparse(url).hostname or "").lower()
        else:
            parts = line.split()
            h = parts[1].lower() if len(parts) >= 2 and IP.match(parts[0]) else ""
        if h and not IP.match(h) and "." in h:
            out.add(h)
    return out


SOURCES = {
    "hagezi-tif": src_hagezi,
    "phishing-database": src_phishing_database,
    "openphish": src_openphish,
    "phishunt": src_phishunt,
    "mvt": src_mvt,
    "avast": src_avast,
    "infosec": src_infosec,
    "citizenlab": src_citizenlab,
    "threatfox": src_threatfox,
    "urlhaus": src_urlhaus,
}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    ok = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, fn in SOURCES.items():
            try:
                domains = {d for d in fn(tmp) if d}
                if not domains:
                    raise RuntimeError("0 domains")
                with open(os.path.join(out_dir, f"{name}.txt"), "w") as f:
                    f.write("\n".join(sorted(domains)) + "\n")
                ok += 1
                print(f"OK   {len(domains):8d}  {name}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"FAIL {'':8}  {name} ({e})", file=sys.stderr)
    print(f"{ok}/{len(SOURCES)} sources fetched -> {out_dir}")
    if ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
