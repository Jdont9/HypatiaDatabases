# Online whitelist (known-good files)

Asclépios AV downloads an optional list of known-good files together with the signature databases.
Files on that list are never reported, which removes false positives on well-known software.

## What must be in the list

The scanner hashes **whole files** (APKs and the files of the scanned storage) with SHA-256. The list must
therefore contain the **SHA-256 of the complete APK file as it sits on the device**. It must not contain
package names, signing-certificate fingerprints or hashes of files found *inside* an APK.

A single-APK app (every F-Droid app) is installed byte for byte as downloaded, so the hash published by the
store matches `/data/app/.../base.apk`. Apps delivered as split APKs have one hash per split.

## File served to the app

| | |
|---|---|
| Name | `hypatia-whitelist-sha256-bloom.bin` (+ `.sig`, signed with the same GPG key as the other databases) |
| Format | Guava `BloomFilter<String>` serialised with `writeTo`, funnel `Funnels.stringFunnel(US_ASCII)` (the format of `hypatia-sha256-bloom.bin`) |
| Entries | lowercase hexadecimal SHA-256, 64 characters |
| False-positive rate | **1e-9 or lower**: a false positive silently whitelists a file |
| Before building | **remove every hash that is present in the malware databases**: the whitelist wins over a signature match |

The file is optional. A server that does not publish it only makes the update log a 404 for that file; the
other databases are not affected. Users can turn it off in Settings → Updates.

## Where to find the hashes

1. **F-Droid** (best source, single APKs, signed index)
   - `https://f-droid.org/repo/index-v2.json`, and `https://f-droid.org/archive/index-v2.json` for old versions.
   - Layout: `packages.<appId>.versions.<sha256 of the APK>.file.sha256`.
   - Verify the index with its `.asc` signature (`index-v2.json.asc`).
   - `python3 tools/fdroid_hashes.py [--archive] [--izzy] > fdroid.sha256` extracts them.
2. **IzzyOnDroid**: same index-v2 format (`https://apt.izzysoft.de/fdroid/repo/index-v2.json`). Check the URL before relying on it.
3. **NIST NSRL RDSv3** (National Software Reference Library): SQLite sets published on the NSRL "Current RDS Hash
   Sets" page, with an *android* set (and a minimal variant). Check the schema in the RDSv3 README, keep only the
   rows that are APK files, take the SHA-256 column, and read NIST's terms of use before redistributing.
   Entries describe files catalogued by NIST, not necessarily whole APKs: check before trusting a row.
4. **CIRCL hashlookup** (`https://hashlookup.circl.lu`): aggregates NSRL and distribution packages. Useful to
   query a hash, less to bulk-build an Android list.
5. **Your own devices / ROMs**: hash the APKs of a stock ROM or of apps you trust.
   `adb shell pm path <package>` then `adb pull <path>` then `sha256sum base.apk`.
6. **Google Play**: there is no public list of APK hashes, and bundles install split APKs that differ per
   device. This is the main gap: it has to be covered with option 5 or by users' own "Always ignore".

## Local lists

Users can also build their own list: Settings → Advanced → Trusted files → Import takes a text file with one
SHA-256 per line.
