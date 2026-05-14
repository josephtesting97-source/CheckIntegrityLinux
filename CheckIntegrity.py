#!/usr/bin/env python3

import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import sqlite3
import struct
import sys
import traceback
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


MAX_HEADER = 32


def read_head(path, count):
    with open(path, "rb") as f:
        return f.read(count)


def read_tail(path, count):
    size = os.path.getsize(path)

    with open(path, "rb") as f:
        f.seek(max(0, size - count))
        return f.read(count)


def sha256_file(path, max_hash_bytes):
    size = os.path.getsize(path)

    if size > max_hash_bytes:
        return f"SKIPPED_OVER_{max_hash_bytes // (1024 * 1024)}MB"

    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def test_magic_mismatch(path):
    issues = []

    ext = path.suffix.lower()

    if path.stat().st_size == 0:
        return issues

    head = read_head(path, 16)

    hexsig = head.hex().upper()

    try:
        ascii_sig = head.decode("ascii", errors="ignore")
    except Exception:
        ascii_sig = ""

    def add(msg):
        issues.append(msg)

    if ext == ".pdf":
        if not ascii_sig.startswith("%PDF-"):
            add("extension is .pdf but header is not PDF")

    elif ext in [".zip", ".docx", ".xlsx", ".pptx"]:
        if not hexsig.startswith(("504B0304", "504B0506", "504B0708")):
            add(f"extension is {ext} but header is not ZIP")

    elif ext == ".png":
        if not hexsig.startswith("89504E470D0A1A0A"):
            add("extension is .png but header is not PNG")

    elif ext in [".jpg", ".jpeg"]:
        if not hexsig.startswith("FFD8FF"):
            add("extension is JPEG but header is not JPEG")

    elif ext == ".gif":
        if not (
            ascii_sig.startswith("GIF87a")
            or ascii_sig.startswith("GIF89a")
        ):
            add("extension is .gif but header is not GIF")

    elif ext == ".gz":
        if not hexsig.startswith("1F8B"):
            add("extension is .gz but header is not gzip")

    return issues


def test_zip(path):
    issues = []

    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()

            if not names:
                issues.append("zip archive has no entries")

            for name in names:
                try:
                    with z.open(name) as f:
                        while f.read(65536):
                            pass
                except Exception as e:
                    issues.append(f"zip entry failed: {name}: {e}")

    except Exception as e:
        issues.append(f"zip validation failed: {e}")

    return issues


def test_office(path):
    issues = []

    issues.extend(test_zip(path))

    if issues:
        return issues

    required = {
        ".docx": [
            "[Content_Types].xml",
            "word/document.xml",
        ],
        ".xlsx": [
            "[Content_Types].xml",
            "xl/workbook.xml",
        ],
        ".pptx": [
            "[Content_Types].xml",
            "ppt/presentation.xml",
        ],
    }

    try:
        with zipfile.ZipFile(path, "r") as z:
            names = set(z.namelist())

            for req in required[path.suffix.lower()]:
                if req not in names:
                    issues.append(
                        f"missing required Office entry: {req}"
                    )

    except Exception as e:
        issues.append(f"Office validation failed: {e}")

    return issues


def test_pdf(path):
    issues = []

    head = read_head(path, 8).decode(
        "ascii",
        errors="ignore",
    )

    if not head.startswith("%PDF-"):
        issues.append("PDF header missing")

    tail = read_tail(path, 4096).decode(
        "ascii",
        errors="ignore",
    )

    if "%%EOF" not in tail:
        issues.append("PDF EOF marker missing")

    if "startxref" not in tail:
        issues.append("PDF startxref missing")

    return issues


def test_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return []
    except Exception as e:
        return [f"JSON parse failed: {e}"]


def test_xml(path):
    try:
        ElementTree.parse(path)
        return []
    except Exception as e:
        return [f"XML parse failed: {e}"]


def test_image(path):
    if not PIL_AVAILABLE:
        return ["Pillow not installed"]

    try:
        with Image.open(path) as img:
            img.verify()

        return []

    except Exception as e:
        return [f"image decode failed: {e}"]


def test_gzip(path):
    try:
        with gzip.open(path, "rb") as f:
            while f.read(65536):
                pass

        return []

    except Exception as e:
        return [f"gzip validation failed: {e}"]


def test_sqlite(path):
    issues = []

    try:
        with open(path, "rb") as f:
            header = f.read(100)

        if len(header) < 100:
            issues.append("SQLite file shorter than 100-byte header")
            return issues

        if header[:16] != b"SQLite format 3\x00":
            issues.append("SQLite header missing")
            return issues

        page_size = struct.unpack(">H", header[16:18])[0]

        if page_size == 1:
            page_size = 65536

        if (
            page_size < 512
            or page_size > 65536
            or (page_size & (page_size - 1)) != 0
        ):
            issues.append(f"invalid SQLite page size: {page_size}")

        size = os.path.getsize(path)

        if size % page_size != 0:
            issues.append(
                f"SQLite size not multiple of page size {page_size}"
            )

        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)

        try:
            cur = conn.execute("PRAGMA integrity_check;")
            row = cur.fetchone()

            if row and row[0].lower() != "ok":
                issues.append(
                    f"SQLite integrity check failed: {row[0]}"
                )

        finally:
            conn.close()

    except Exception as e:
        issues.append(f"SQLite validation failed: {e}")

    return issues


def check_file(path, args):
    issues = []
    suspicious = []

    sha = ""

    try:
        with open(path, "rb"):
            pass
    except Exception as e:
        return make_result(
            path,
            "Error",
            3,
            "file could not be opened",
            str(e),
            sha,
        )

    size = path.stat().st_size

    if size == 0:
        suspicious.append("file is zero bytes")

    try:
        issues.extend(test_magic_mismatch(path))
    except Exception as e:
        issues.append(f"magic inspection failed: {e}")

    if size <= args.max_deep_check_mb * 1024 * 1024:

        ext = path.suffix.lower()

        try:
            if ext == ".zip":
                issues.extend(test_zip(path))

            elif ext in [".docx", ".xlsx", ".pptx"]:
                issues.extend(test_office(path))

            elif ext == ".pdf":
                issues.extend(test_pdf(path))

            elif ext == ".json":
                issues.extend(test_json(path))

            elif ext in [".xml", ".svg"]:
                issues.extend(test_xml(path))

            elif ext in [
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".bmp",
                ".tif",
                ".tiff",
            ]:
                issues.extend(test_image(path))

            elif ext == ".gz":
                issues.extend(test_gzip(path))

            elif ext in [".sqlite", ".sqlite3", ".db"]:
                issues.extend(test_sqlite(path))

        except Exception as e:
            issues.append(f"deep validation failed: {e}")

    else:
        suspicious.append(
            f"deep checks skipped over {args.max_deep_check_mb}MB"
        )

    if args.include_hashes:
        try:
            sha = sha256_file(
                path,
                args.max_hash_mb * 1024 * 1024,
            )
        except Exception as e:
            suspicious.append(f"hash failed: {e}")

    if issues:
        return make_result(
            path,
            "Corrupt",
            3,
            "; ".join(issues),
            "; ".join(suspicious),
            sha,
        )

    if suspicious:
        return make_result(
            path,
            "Suspicious",
            1,
            "; ".join(suspicious),
            "",
            sha,
        )

    return make_result(
        path,
        "OK",
        0,
        "",
        "",
        sha,
    )


def make_result(path, status, severity, reason, details, sha):
    return {
        "Status": status,
        "Severity": severity,
        "Path": str(path.resolve()),
        "Extension": path.suffix.lower(),
        "SizeBytes": path.stat().st_size,
        "LastWriteTime": datetime.fromtimestamp(
            path.stat().st_mtime
        ).isoformat(),
        "Reason": reason,
        "Details": details,
        "SHA256": sha,
    }


def gather_files(paths, include_hidden):
    files = []

    for p in paths:
        p = Path(p)

        if p.is_file():
            files.append(p)
            continue

        if not p.is_dir():
            continue

        # root files
        for child in p.iterdir():
            if child.is_file():
                files.append(child)

        # immediate subfolders only
        for child in p.iterdir():
            if child.is_dir():
                for sub in child.iterdir():
                    if sub.is_file():
                        files.append(sub)

    out = []

    for f in files:
        if not include_hidden and f.name.startswith("."):
            continue

        out.append(f)

    return sorted(set(out))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "paths",
        nargs="+",
    )

    parser.add_argument("--csv")
    parser.add_argument("--json-report")

    parser.add_argument(
        "--include-hashes",
        action="store_true",
    )

    parser.add_argument(
        "--include-hidden",
        action="store_true",
    )

    parser.add_argument(
        "--extensions",
        nargs="*",
    )

    parser.add_argument(
        "--max-deep-check-mb",
        type=int,
        default=512,
    )

    parser.add_argument(
        "--max-hash-mb",
        type=int,
        default=2048,
    )

    args = parser.parse_args()

    files = gather_files(
        args.paths,
        args.include_hidden,
    )

    if args.extensions:
        exts = {
            x.lower()
            if x.startswith(".")
            else "." + x.lower()
            for x in args.extensions
        }

        files = [
            f for f in files
            if f.suffix.lower() in exts
        ]

    results = []

    total = len(files)

    for idx, file in enumerate(files, start=1):
        if idx == 1 or idx % 100 == 0:
            print(f"[{idx}/{total}] {file}")

        results.append(check_file(file, args))

    counts = Counter(r["Status"] for r in results)

    print()
    print(f"Checked {total} file(s)")
    print()

    for k in sorted(counts):
        print(f"{k:<12} {counts[k]:>6}")

    problems = [
        r for r in results
        if r["Status"] != "OK"
    ]

    if problems:
        print("\nFiles needing attention:\n")

        for p in problems:
            print(
                f"{p['Status']:10} "
                f"{p['Path']}\n"
                f"  Reason: {p['Reason']}"
            )

            if p["Details"]:
                print(f"  Details: {p['Details']}")

            print()

    else:
        print("\nNo obvious corruption found.")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=results[0].keys()
                if results else [],
            )

            writer.writeheader()
            writer.writerows(results)

        print(f"\nCSV report: {args.csv}")

    if args.json_report:
        with open(args.json_report, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"JSON report: {args.json_report}")


if __name__ == "__main__":
    main()
