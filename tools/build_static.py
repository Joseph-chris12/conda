#!/usr/bin/env python3
"""Membuat situs statis mode replay (untuk GitHub Pages / hosting apa pun) di folder `dist/`.

    python tools/build_static.py          ->  dist/index.html, app.js, style.css, samples/*.jsonl

Cukup unggah isi `dist/`. Di github.io dashboard otomatis masuk mode replay.
"""
from __future__ import annotations

import os
import shutil
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def main() -> int:
    out = os.path.join(ROOT, "dist")
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "dashboard"), out)
    samples = os.path.join(ROOT, "data", "samples")
    files = [f for f in os.listdir(samples) if f.endswith(".jsonl")] if os.path.isdir(samples) else []
    if not files:
        print("Belum ada rekaman. Jalankan dulu: python tools/make_sample.py", file=sys.stderr)
        return 1
    shutil.copytree(samples, os.path.join(out, "samples"), ignore=shutil.ignore_patterns("*.md"))
    open(os.path.join(out, ".nojekyll"), "w").close()
    print("Situs statis siap di %s (%d rekaman)" % (out, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
