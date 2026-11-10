#!/usr/bin/env python3
"""Extract the SHA-256 of every APK published by F-Droid-style repos.

Reads the signed index-v2.json files (F-Droid repo, F-Droid archive,
IzzyOnDroid) and prints one lowercase SHA-256 per line on stdout:

    python3 tools/fdroid_hashes.py [--archive] [--izzy] [--cache-dir DIR] > fdroid.sha256

In the index-v2 layout, each version entry is keyed by the SHA-256 of the
APK file and its "file" object repeats that same hash, so extracting every
64-character hex token yields exactly the set of published APK hashes
(single-APK apps are installed byte for byte as downloaded). The index is
streamed in chunks: it can be several hundred MB.

With --cache-dir, the hashes extracted from each index are kept on disk next
to the ETag / Last-Modified the server sent. On the next run the index is
requested conditionally: a "304 Not Modified" reuses the cached hashes and
costs almost nothing. If a download fails, the cached hashes (if any) are
used instead of dropping the source. --max-age-days N additionally skips the
network entirely for a source whose cache is younger than N days (useful for
the archive, which almost never changes).
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

SOURCES = {
    "fdroid": "https://f-droid.org/repo/index-v2.json",
    "archive": "https://f-droid.org/archive/index-v2.json",
    "izzy": "https://apt.izzysoft.de/fdroid/repo/index-v2.json",
}

HASH = re.compile(rb"[0-9a-fA-F]{64}")
RETRIES = 3


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


class NotModified(Exception):
    pass


def download(url, dest, meta=None):
    """Download url to dest. Returns the validators (etag, last-modified).

    Raises NotModified when the server answers 304 to a conditional request.
    Retries on network errors; the transfer is verified against Content-Length.
    """
    headers = {"User-Agent": "HypatiaDatabases-CI"}
    if meta:
        if meta.get("etag"):
            headers["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = meta["last_modified"]
    last_error = None
    for attempt in range(1, RETRIES + 1):
        print(f"Downloading {url} (attempt {attempt})", file=sys.stderr)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=300) as response, open(dest, "wb") as out:
                expected = response.headers.get("Content-Length")
                size = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    size += len(chunk)
                if expected and int(expected) != size:
                    raise IOError(f"truncated download: {size} of {expected} bytes")
                return {
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                }
        except urllib.error.HTTPError as error:
            if error.code == 304:
                raise NotModified()
            last_error = error
        except Exception as error:  # network error, truncated download...
            last_error = error
        print(f"  failed: {last_error}", file=sys.stderr)
        time.sleep(attempt * 10)
    raise last_error


def load_cache(cache_dir, name):
    hashes_path = os.path.join(cache_dir, f"{name}.sha256")
    meta_path = os.path.join(cache_dir, f"{name}.meta.json")
    if not (os.path.isfile(hashes_path) and os.path.isfile(meta_path)):
        return None, None
    try:
        with open(meta_path) as fh:
            meta = json.load(fh)
        with open(hashes_path) as fh:
            hashes = {line.strip() for line in fh if line.strip()}
        return hashes, meta
    except Exception as error:
        print(f"WARNING: {name} cache unreadable: {error}", file=sys.stderr)
        return None, None


def save_cache(cache_dir, name, hashes, validators):
    os.makedirs(cache_dir, exist_ok=True)
    hashes_path = os.path.join(cache_dir, f"{name}.sha256")
    meta_path = os.path.join(cache_dir, f"{name}.meta.json")
    with open(hashes_path + ".tmp", "w") as fh:
        fh.write("\n".join(sorted(hashes)) + "\n")
    os.replace(hashes_path + ".tmp", hashes_path)
    meta = dict(validators or {})
    meta["fetched_at"] = int(time.time())
    with open(meta_path, "w") as fh:
        json.dump(meta, fh)


def fetch_source(name, cache_dir, max_age_days):
    """Return (hashes, status) for one source; status says where they came from."""
    cached, meta = (None, None)
    if cache_dir:
        cached, meta = load_cache(cache_dir, name)
        if cached and max_age_days:
            age_days = (time.time() - meta.get("fetched_at", 0)) / 86400
            if age_days < max_age_days:
                return cached, f"cache ({age_days:.1f} d old, < {max_age_days} d, no request)"
    try:
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            validators = download(SOURCES[name], tmp.name, meta if cached else None)
            hashes = set()
            found = extract(tmp.name, hashes)
        if len(hashes) == 0:
            raise ValueError("index contained no hashes")
        if cache_dir:
            save_cache(cache_dir, name, hashes, validators)
        return hashes, f"downloaded ({found} entries)"
    except NotModified:
        # Cache left untouched on purpose: nothing to re-save (keeps the CI cache entry unchanged)
        return cached, "not modified (304), cache reused"
    except Exception as error:
        if cached:
            return cached, f"download FAILED ({error}), STALE cache used"
        print(f"WARNING: {name} index failed: {error}", file=sys.stderr)
        return set(), "failed, no cache"


def main():
    parser = argparse.ArgumentParser(description="Extract APK SHA-256 hashes from F-Droid index-v2.json files")
    parser.add_argument("--archive", action="store_true", help="also read the F-Droid archive index (old versions)")
    parser.add_argument("--izzy", action="store_true", help="also read the IzzyOnDroid index")
    parser.add_argument("--cache-dir", help="keep per-source hashes + ETag here and request indexes conditionally")
    parser.add_argument("--max-age-days", type=float, default=0,
                        help="with --cache-dir, skip the network for a source whose cache is younger than this")
    parser.add_argument("--max-age-archive-days", type=float, default=None,
                        help="override --max-age-days for the archive only")
    args = parser.parse_args()

    sources = [("fdroid", args.max_age_days)]
    if args.archive:
        archive_age = args.max_age_days if args.max_age_archive_days is None else args.max_age_archive_days
        sources.append(("archive", archive_age))
    if args.izzy:
        sources.append(("izzy", args.max_age_days))

    hashes = set()
    for name, max_age in sources:
        start = time.time()
        got, status = fetch_source(name, args.cache_dir, max_age)
        hashes |= got
        print(f"{name}: {len(got)} APK hashes, {status} [{time.time() - start:.0f}s] "
              f"(unique so far: {len(hashes)})", file=sys.stderr)

    for entry in sorted(hashes):
        print(entry)
    print(f"Total unique APK hashes: {len(hashes)}", file=sys.stderr)


if __name__ == "__main__":
    main()
