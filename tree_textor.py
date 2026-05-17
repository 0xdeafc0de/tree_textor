#!/usr/bin/env python3
"""TreeTextor: pack/unpack a repository into a single multiline text artifact.

Design goals:
- Safe and auditable format (JSON with explicit metadata)
- Reversible reconstruction of files and folders
- Artifact remains plain multiline text (no whole-file compression)
- File payloads are individually gzip-compressed and base64-encoded
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

FORMAT_VERSION = "1"
PAYLOAD_ENCODING = "gzip+base64"
DEFAULT_EXCLUDES = {
    ".git",
    ".DS_Store",
    "__pycache__",
}
DEFAULT_BINARY_SUFFIX_EXCLUDES = {
    ".so",
    ".o",
    ".a",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".elf",
    ".obj",
    ".pyc",
    ".pyo",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chunk_text(text: str, width: int = 88) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)] or [""]


def should_skip_file(path: Path, rel_parts: tuple[str, ...]) -> bool:
    if any(part in DEFAULT_EXCLUDES for part in rel_parts):
        return True

    name_lower = path.name.lower()
    if name_lower.endswith(".so") or ".so." in name_lower:
        return True
    if path.suffix.lower() in DEFAULT_BINARY_SUFFIX_EXCLUDES:
        return True
    return False


def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink():
            continue
        rel_parts = path.relative_to(root).parts
        if should_skip_file(path, rel_parts):
            continue
        yield path


def pack(repo: Path, out_file: Path) -> None:
    repo = repo.resolve()
    if not repo.exists() or not repo.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo}")

    files = []
    for file_path in iter_files(repo):
        rel_path = file_path.relative_to(repo).as_posix()
        try:
            raw = file_path.read_bytes()
        except OSError as exc:
            print(f"Skipping unreadable file '{rel_path}': {exc}", file=sys.stderr)
            continue
        gz = gzip.compress(raw)
        b64 = base64.b64encode(gz).decode("ascii")

        files.append(
            {
                "path": rel_path,
                "size": len(raw),
                "sha256": sha256_bytes(raw),
                "encoding": PAYLOAD_ENCODING,
                "chunks": chunk_text(b64, width=88),
            }
        )

    manifest = {
        "tree_textor_version": FORMAT_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root_name": repo.name,
        "file_count": len(files),
        "files": files,
    }

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=True)
        f.write("\n")


def unpack(in_file: Path, out_repo: Path) -> None:
    in_file = in_file.resolve()
    out_repo = out_repo.resolve()

    if not in_file.exists() or not in_file.is_file():
        raise ValueError(f"Input artifact not found: {in_file}")

    with in_file.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    version = str(manifest.get("tree_textor_version", ""))
    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported format version: {version!r} (expected {FORMAT_VERSION!r})"
        )

    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("Invalid manifest: 'files' must be a list")

    out_repo.mkdir(parents=True, exist_ok=True)

    for entry in files:
        rel_path = entry.get("path")
        size = entry.get("size")
        expected_hash = entry.get("sha256")
        encoding = entry.get("encoding")
        chunks = entry.get("chunks")

        if not isinstance(rel_path, str) or not rel_path:
            raise ValueError("Invalid entry: missing/invalid path")
        if os.path.isabs(rel_path) or ".." in Path(rel_path).parts:
            raise ValueError(f"Unsafe path in manifest: {rel_path}")
        if encoding != PAYLOAD_ENCODING:
            raise ValueError(f"Unsupported payload encoding for {rel_path}: {encoding!r}")
        if not isinstance(chunks, list) or not all(isinstance(c, str) for c in chunks):
            raise ValueError(f"Invalid chunks for {rel_path}")

        b64 = "".join(chunks)
        try:
            gz = base64.b64decode(b64.encode("ascii"), validate=True)
            raw = gzip.decompress(gz)
        except Exception as exc:
            raise ValueError(f"Failed decoding payload for {rel_path}: {exc}") from exc

        actual_size = len(raw)
        actual_hash = sha256_bytes(raw)

        if size != actual_size:
            raise ValueError(
                f"Size mismatch for {rel_path}: expected {size}, got {actual_size}"
            )
        if expected_hash != actual_hash:
            raise ValueError(
                f"SHA256 mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
            )

        target = out_repo / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tree_textor.py",
        description="Pack/unpack repository trees into a reversible multiline text artifact.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_pack = sub.add_parser("pack", help="Pack repo directory into text artifact")
    p_pack.add_argument("repo", type=Path, help="Path to repository directory")
    p_pack.add_argument("out", type=Path, help="Output text file")

    p_unpack = sub.add_parser("unpack", help="Unpack text artifact into directory")
    p_unpack.add_argument("in_file", type=Path, help="Input text artifact file")
    p_unpack.add_argument("out_repo", type=Path, help="Output directory for restored repo")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "pack":
        pack(args.repo, args.out)
        print(f"Packed '{args.repo}' -> '{args.out}'")
    elif args.command == "unpack":
        unpack(args.in_file, args.out_repo)
        print(f"Unpacked '{args.in_file}' -> '{args.out_repo}'")
    else:
        parser.error("Unknown command")


if __name__ == "__main__":
    main()
