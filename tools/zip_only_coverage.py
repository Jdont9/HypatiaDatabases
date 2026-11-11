#!/usr/bin/env python3
"""Are the domains that only divest.zip has already covered by the other sources?

Input:
  --zip-only FILE     domains in divest.zip but absent from the rebuilt Divest list
                      (reports/zip-only-domains.txt)
  --extras-dir DIR    one <source>.txt per extra source (tools/fetch_extra_domains.py)
  --allowlist FILE    optional: Tranco/MISP allowlist. The main workflow drops an
                      extra-source domain when it (or its non-www form) is in it, so
                      such a domain does NOT really cover the zip-only one.
  --out-dir DIR       where to write the results

Each zip-only domain ends up in exactly one bucket:
  covered-exact    listed by at least one extra source (and not allowlisted there)
  covered-parent   a parent domain is listed (the app matches parent domains, so
                   example.com blocks sub.example.com)
  allowlisted-only only the allowlist-filtered copies exist: the main workflow
                   would drop them, so they are effectively missing
  missing          nowhere else: this is what you would lose by dropping the zip

Outputs: coverage-report.md, covered-exact.tsv, covered-parent.tsv, missing.txt
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_divest_domains import normalize_line  # noqa: E402


def load_set(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return {l.strip().lower() for l in fh if l.strip()}


def is_allowlisted(d, allow):
    base = d[4:] if d.startswith("www.") else d
    return d in allow or base in allow


def parents(d):
    """sub.a.example.com -> a.example.com, example.com (the bare TLD is skipped)."""
    labels = d.split(".")
    for i in range(1, len(labels) - 1):
        yield ".".join(labels[i:])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip-only", required=True)
    ap.add_argument("--extras-dir", required=True)
    ap.add_argument("--allowlist")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    zip_only = sorted(load_set(args.zip_only))
    allow = set()
    if args.allowlist and os.path.exists(args.allowlist):
        allow = {l.strip().lower().lstrip("*.").rstrip(".") for l in open(args.allowlist, errors="ignore") if l.strip()}

    # domain -> set(sources), after the same allowlist filter as the main workflow
    index, dropped_index, per_source = {}, {}, {}
    for fn in sorted(os.listdir(args.extras_dir)):
        if not fn.endswith(".txt"):
            continue
        src = fn[:-4]
        n = 0
        with open(os.path.join(args.extras_dir, fn), encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = normalize_line(line) or line.strip().lower()
                if not d or "." not in d:
                    continue
                n += 1
                target = dropped_index if allow and is_allowlisted(d, allow) else index
                target.setdefault(d, set()).add(src)
        per_source[src] = n

    if not per_source:
        sys.exit("no extra source file found in " + args.extras_dir)

    exact, parent, allow_only, missing = [], [], [], []
    hits_exact, hits_parent = {s: 0 for s in per_source}, {s: 0 for s in per_source}
    for d in zip_only:
        # `normalize_line` strips a leading www. : try both forms for the exact match
        keys = [d] + ([d[4:]] if d.startswith("www.") else [])
        srcs = set().union(*(index.get(k, set()) for k in keys))
        if srcs:
            exact.append((d, srcs))
            for s in srcs:
                hits_exact[s] += 1
            continue
        psrcs, via = set(), None
        for p in parents(d):
            if p in index:
                psrcs, via = index[p], p
                break
        if psrcs:
            parent.append((d, via, psrcs))
            for s in psrcs:
                hits_parent[s] += 1
            continue
        if any(k in dropped_index for k in keys) or any(p in dropped_index for p in parents(d)):
            allow_only.append(d)
        else:
            missing.append(d)

    os.makedirs(args.out_dir, exist_ok=True)
    w = lambda name, rows: open(os.path.join(args.out_dir, name), "w").write(
        "".join(r + "\n" for r in rows))
    w("covered-exact.tsv", (f"{d}\t{','.join(sorted(s))}" for d, s in exact))
    w("covered-parent.tsv", (f"{d}\t{via}\t{','.join(sorted(s))}" for d, via, s in parent))
    w("allowlisted-only.txt", allow_only)
    w("missing.txt", missing)

    total = len(zip_only)
    pct = lambda n: f"{100 * n / total:.1f}%" if total else "n/a"
    lines = [
        "# Couverture des domaines « zip seulement » par les autres sources",
        "",
        f"- Domaines dans le zip mais pas dans les sources Divest vivantes : **{total}**",
        f"- Déjà listés tels quels par une autre source : **{len(exact)}** ({pct(len(exact))})",
        f"- Couverts via un domaine parent (l'app matche les parents) : **{len(parent)}** ({pct(len(parent))})",
        f"- Présents seulement dans une copie écartée par l'allowlist : **{len(allow_only)}** ({pct(len(allow_only))})",
        f"- **Introuvables ailleurs : {len(missing)}** ({pct(len(missing))})",
        "",
        "## Par source",
        "",
        "| Source | Domaines lus | Couvre (exact) | Couvre (parent) |",
        "|---|---:|---:|---:|",
    ]
    for s in sorted(per_source, key=lambda s: -(hits_exact[s] + hits_parent[s])):
        lines.append(f"| {s} | {per_source[s]} | {hits_exact[s]} | {hits_parent[s]} |")
    if allow:
        lines += ["", f"Allowlist appliquée : {len(allow)} entrées (mêmes règles que le workflow principal)."]
    else:
        lines += ["", "⚠️ Pas d'allowlist fournie : la couverture est surestimée."]
    lines += ["", "Détail : `covered-exact.tsv`, `covered-parent.tsv`, `allowlisted-only.txt`, `missing.txt`."]
    with open(os.path.join(args.out_dir, "coverage-report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
