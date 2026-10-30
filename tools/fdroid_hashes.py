#!/usr/bin/env python3
"""Extract the SHA-256 of every APK published by F-Droid-style repos.

Reads the signed index-v2.json files (F-Droid repo, F-Droid archive,
IzzyOnDroid) and prints one lowercase SHA-256 per line on stdout:

    python3 tools/fdroid_hashes.py [--archive] [--izzy] > fdroid.sha256

In the index-v2 layout, each version entry is keyed by the SHA-256 of the
APK file and its "file" object repeats that same hash, so extracting every
64-character hex token yields exactly the set of published APK hashes
(single-APK apps are installed byte for byte as downloaded). The index is
streamed in chunks: it can be several hundred MB.
"""
import argparse
import re
import sys
import tempfile
import urllib.request

SOURCES = {
    "fdroid": "https://f-droid.org/repo/index-v2.json",
    "archive": "https://f-droid.org/archive/index-v2.json",
    "izzy": "https://apt.izzysoft.de/fdroid/repo/index-v2.json",
}

HASH = re.compile(rb"[0-9a-fA-F]{64}")


def extract(path, hashes):
    found = 0
    with open(path, "rb") as fh:
        tail = b""
        while True:
            chunk = fh.read(8 * 1024 * 1024)
            if not chunk:
                break
            data = tail + chunk
            for match in HASH.findall(data):
                hashes.add(match.decode("ascii").lower())
                found += 1
            tail = data[-63:]
    return found


def download(url, dest):
    print(f"Downloading {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "HypatiaDatabases-CI"})
    with urllib.request.urlopen(req, timeout=300) as response, open(dest, "wb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)


def main():
    parser = argparse.ArgumentParser(description="Extract APK SHA-256 hashes from F-Droid index-v2.json files")
    parser.add_argument("--archive", action="store_true", help="also read the F-Droid archive index (old versions)")
    parser.add_argument("--izzy", action="store_true", help="also read the IzzyOnDroid index")
    args = parser.parse_args()

    sources = ["fdroid"]
    if args.archive:
        sources.append("archive")
    if args.izzy:
        sources.append("izzy")

    hashes = set()
    for name in sources:
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            try:
                download(SOURCES[name], tmp.name)
                found = extract(tmp.name, hashes)
                print(f"{name}: {found} APK hashes (unique so far: {len(hashes)})", file=sys.stderr)
            except Exception as error:
                print(f"WARNING: {name} index failed: {error}", file=sys.stderr)

    for entry in sorted(hashes):
        print(entry)
    print(f"Total unique APK hashes: {len(hashes)}", file=sys.stderr)


if __name__ == "__main__":
    main()
