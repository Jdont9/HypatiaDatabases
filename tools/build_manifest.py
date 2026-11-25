#!/usr/bin/env python3
"""Print the anti-rollback manifest for the database files found in a directory.

    python3 tools/build_manifest.py deploy/ > deploy/hypatia-manifest.txt

Output (ASCII, LF line endings, one "key=value" per line, sorted file names):

    # Hypatia database manifest. Signed with the databases key.
    version=1
    sequence=<UTC epoch seconds of generation>
    hypatia-md5-bloom.bin=<sha256 of the file>
    ...

The manifest is signed (detached, binary .sig) exactly like the databases. The app:
  * refuses a manifest whose sequence is lower than the last one it accepted
    (replay of an old, validly signed database set), and
  * refuses a database file whose SHA-256 differs from the one listed here
    (mix of old and new files).

Set MANIFEST_SEQUENCE to force the sequence number (tests only).
"""
import hashlib
import os
import sys
import time


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.exit("usage: build_manifest.py <directory with hypatia-*-bloom.bin>")
    directory = sys.argv[1]
    names = sorted(
        n for n in os.listdir(directory)
        if n.startswith("hypatia-") and n.endswith("-bloom.bin")
    )
    if not names:
        sys.exit("no hypatia-*-bloom.bin file found in " + directory)
    sequence = int(os.environ.get("MANIFEST_SEQUENCE") or time.time())
    lines = [
        "# Hypatia database manifest. Signed with the databases key.",
        "version=1",
        "sequence=%d" % sequence,
    ]
    for name in names:
        lines.append("%s=%s" % (name, sha256_of(os.path.join(directory, name))))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
