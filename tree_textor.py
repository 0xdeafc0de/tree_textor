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

K_V = "v"
K_T = "t"
K_R = "r"
K_N = "n"
K_F = "f"
K_P = "p"
K_Z = "z"
K_H = "h"
K_E = "e"
K_C = "c"
OBF_ASCII_SHIFT = 1
OBF_INT_SHIFT = 7
PB_B64_MAGIC = "TTB64V1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chunk_text(text: str, width: int = 88) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)] or [""]


def obf_str(value: str) -> str:
    out = []
    for ch in value:
        code = ord(ch)
        if 32 <= code <= 126:
            out.append(chr(32 + ((code - 32 + OBF_ASCII_SHIFT) % 95)))
        else:
            out.append(ch)
    return "".join(out)


def deobf_str(value: str) -> str:
    out = []
    for ch in value:
        code = ord(ch)
        if 32 <= code <= 126:
            out.append(chr(32 + ((code - 32 - OBF_ASCII_SHIFT) % 95)))
        else:
            out.append(ch)
    return "".join(out)


def obf_int(value: int) -> int:
    return value + OBF_INT_SHIFT


def deobf_int(value: int) -> int:
    return value - OBF_INT_SHIFT


def wrap_pb_base64(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode("ascii")
    lines = [PB_B64_MAGIC]
    lines.extend(chunk_text(b64, width=88))
    return "\n".join(lines) + "\n"


def maybe_unwrap_pb_base64(raw: bytes) -> bytes:
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    lines = txt.splitlines()
    if not lines or lines[0].strip() != PB_B64_MAGIC:
        return raw
    payload = "".join(lines[1:]).strip()
    if not payload:
        raise ValueError("Invalid base64 protobuf wrapper: empty payload")
    try:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 protobuf wrapper: {exc}") from exc


def _pb_varint_encode(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)


def _pb_varint_decode(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if pos >= len(data):
            raise ValueError("unexpected end while decoding varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _pb_key(field_no: int, wire_type: int) -> bytes:
    return _pb_varint_encode((field_no << 3) | wire_type)


def _pb_len_field(field_no: int, payload: bytes) -> bytes:
    return _pb_key(field_no, 2) + _pb_varint_encode(len(payload)) + payload


def _pb_varint_field(field_no: int, value: int) -> bytes:
    return _pb_key(field_no, 0) + _pb_varint_encode(value)


def _pb_read_len(data: bytes, pos: int) -> tuple[bytes, int]:
    ln, pos = _pb_varint_decode(data, pos)
    end = pos + ln
    if end > len(data):
        raise ValueError("length-delimited field exceeds buffer")
    return data[pos:end], end


def _encode_file_entry_pb(
    rel_path: str, raw_size: int, sha256_hex: str, encoding_name: str, gz_payload: bytes
) -> bytes:
    out = bytearray()
    out += _pb_len_field(1, obf_str(rel_path).encode("utf-8"))
    out += _pb_varint_field(2, obf_int(raw_size))
    out += _pb_len_field(3, obf_str(sha256_hex).encode("utf-8"))
    out += _pb_len_field(4, obf_str(encoding_name).encode("utf-8"))
    out += _pb_len_field(5, gz_payload)
    return bytes(out)


def _decode_file_entry_pb(data: bytes) -> dict[str, object]:
    pos = 0
    got: dict[int, object] = {}
    while pos < len(data):
        key, pos = _pb_varint_decode(data, pos)
        field_no = key >> 3
        wire_type = key & 0x07
        if field_no == 2:
            if wire_type != 0:
                raise ValueError("invalid wire type for file field 2")
            val, pos = _pb_varint_decode(data, pos)
            got[2] = val
        elif field_no in {1, 3, 4, 5}:
            if wire_type != 2:
                raise ValueError(f"invalid wire type for file field {field_no}")
            raw, pos = _pb_read_len(data, pos)
            got[field_no] = raw
        else:
            raise ValueError(f"unknown file field number: {field_no}")

    required = {1, 2, 3, 4, 5}
    if set(got.keys()) != required:
        raise ValueError("invalid file entry: missing required protobuf fields")

    return {
        "p": deobf_str(bytes(got[1]).decode("utf-8")),
        "z": deobf_int(int(got[2])),
        "h": deobf_str(bytes(got[3]).decode("utf-8")),
        "e": deobf_str(bytes(got[4]).decode("utf-8")),
        "c": bytes(got[5]),
    }


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
                K_P: obf_str(rel_path),
                K_Z: obf_int(len(raw)),
                K_H: obf_str(sha256_bytes(raw)),
                K_E: obf_str(PAYLOAD_ENCODING),
                K_C: chunk_text(b64, width=88),
            }
        )

    manifest = {
        K_V: obf_str(FORMAT_VERSION),
        K_T: obf_str(datetime.now(timezone.utc).isoformat()),
        K_R: obf_str(repo.name),
        K_N: obf_int(len(files)),
        K_F: files,
    }

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=True)
        f.write("\n")


def pack_pb(repo: Path, out_file: Path, as_base64_text: bool = False) -> None:
    repo = repo.resolve()
    if not repo.exists() or not repo.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo}")

    file_messages: list[bytes] = []
    file_count = 0
    for file_path in iter_files(repo):
        rel_path = file_path.relative_to(repo).as_posix()
        try:
            raw = file_path.read_bytes()
        except OSError as exc:
            print(f"Skipping unreadable file '{rel_path}': {exc}", file=sys.stderr)
            continue
        gz = gzip.compress(raw)
        file_messages.append(
            _encode_file_entry_pb(rel_path, len(raw), sha256_bytes(raw), PAYLOAD_ENCODING, gz)
        )
        file_count += 1

    out = bytearray()
    out += _pb_len_field(1, obf_str(FORMAT_VERSION).encode("utf-8"))
    out += _pb_len_field(
        2, obf_str(datetime.now(timezone.utc).isoformat()).encode("utf-8")
    )
    out += _pb_len_field(3, obf_str(repo.name).encode("utf-8"))
    out += _pb_varint_field(4, obf_int(file_count))
    for file_msg in file_messages:
        out += _pb_len_field(5, file_msg)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    blob = bytes(out)
    if as_base64_text:
        out_file.write_text(wrap_pb_base64(blob), encoding="utf-8", newline="\n")
    else:
        out_file.write_bytes(blob)


def unpack(in_file: Path, out_repo: Path) -> None:
    in_file = in_file.resolve()
    out_repo = out_repo.resolve()

    if not in_file.exists() or not in_file.is_file():
        raise ValueError(f"Input artifact not found: {in_file}")

    with in_file.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    version_raw = manifest.get(K_V, "")
    if not isinstance(version_raw, str):
        raise ValueError("Invalid manifest: version missing/invalid")
    version = deobf_str(version_raw)
    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported format version: {version!r} (expected {FORMAT_VERSION!r})"
        )

    files = manifest.get(K_F)
    if not isinstance(files, list):
        raise ValueError("Invalid manifest: file list missing/invalid")

    out_repo.mkdir(parents=True, exist_ok=True)

    for entry in files:
        rel_path_raw = entry.get(K_P)
        size_raw = entry.get(K_Z)
        expected_hash_raw = entry.get(K_H)
        encoding_raw = entry.get(K_E)
        chunks = entry.get(K_C)

        if not isinstance(rel_path_raw, str) or not rel_path_raw:
            raise ValueError("Invalid entry: missing/invalid path")
        if not isinstance(size_raw, int):
            raise ValueError("Invalid entry: missing/invalid size")
        if not isinstance(expected_hash_raw, str) or not expected_hash_raw:
            raise ValueError("Invalid entry: missing/invalid hash")
        if not isinstance(encoding_raw, str) or not encoding_raw:
            raise ValueError("Invalid entry: missing/invalid encoding")

        rel_path = deobf_str(rel_path_raw)
        size = deobf_int(size_raw)
        expected_hash = deobf_str(expected_hash_raw)
        encoding = deobf_str(encoding_raw)

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


def unpack_pb(in_file: Path, out_repo: Path) -> None:
    in_file = in_file.resolve()
    out_repo = out_repo.resolve()

    if not in_file.exists() or not in_file.is_file():
        raise ValueError(f"Input artifact not found: {in_file}")

    data = maybe_unwrap_pb_base64(in_file.read_bytes())
    pos = 0
    manifest_fields: dict[int, object] = {5: []}
    while pos < len(data):
        key, pos = _pb_varint_decode(data, pos)
        field_no = key >> 3
        wire_type = key & 0x07
        if field_no == 4:
            if wire_type != 0:
                raise ValueError("invalid wire type for manifest field 4")
            val, pos = _pb_varint_decode(data, pos)
            manifest_fields[4] = val
        elif field_no in {1, 2, 3, 5}:
            if wire_type != 2:
                raise ValueError(f"invalid wire type for manifest field {field_no}")
            raw, pos = _pb_read_len(data, pos)
            if field_no == 5:
                cast_list = manifest_fields[5]
                assert isinstance(cast_list, list)
                cast_list.append(raw)
            else:
                manifest_fields[field_no] = raw
        else:
            raise ValueError(f"unknown manifest field number: {field_no}")

    for required_field in (1, 2, 3, 4, 5):
        if required_field not in manifest_fields:
            raise ValueError(f"invalid manifest: missing field {required_field}")

    version = deobf_str(bytes(manifest_fields[1]).decode("utf-8"))
    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported format version: {version!r} (expected {FORMAT_VERSION!r})"
        )

    file_count = deobf_int(int(manifest_fields[4]))
    file_blobs = manifest_fields[5]
    assert isinstance(file_blobs, list)
    if file_count != len(file_blobs):
        raise ValueError(
            f"File count mismatch in manifest: declared {file_count}, got {len(file_blobs)}"
        )

    out_repo.mkdir(parents=True, exist_ok=True)
    for raw_file_msg in file_blobs:
        decoded = _decode_file_entry_pb(bytes(raw_file_msg))
        rel_path = str(decoded["p"])
        size = int(decoded["z"])
        expected_hash = str(decoded["h"])
        encoding = str(decoded["e"])
        gz_payload = bytes(decoded["c"])

        if not rel_path:
            raise ValueError("Invalid entry: missing/invalid path")
        if os.path.isabs(rel_path) or ".." in Path(rel_path).parts:
            raise ValueError(f"Unsafe path in manifest: {rel_path}")
        if encoding != PAYLOAD_ENCODING:
            raise ValueError(f"Unsupported payload encoding for {rel_path}: {encoding!r}")

        try:
            raw = gzip.decompress(gz_payload)
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

    p_pack_pb = sub.add_parser(
        "packpb", help="Pack repo directory into protobuf binary artifact"
    )
    p_pack_pb.add_argument("repo", type=Path, help="Path to repository directory")
    p_pack_pb.add_argument("out", type=Path, help="Output protobuf file")
    p_pack_pb.add_argument(
        "--base64",
        action="store_true",
        help="Write protobuf as multiline base64 text with a small wrapper header",
    )

    p_unpack_pb = sub.add_parser(
        "unpackpb", help="Unpack protobuf artifact into directory"
    )
    p_unpack_pb.add_argument("in_file", type=Path, help="Input protobuf artifact file")
    p_unpack_pb.add_argument(
        "out_repo", type=Path, help="Output directory for restored repo"
    )

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
    elif args.command == "packpb":
        pack_pb(args.repo, args.out, as_base64_text=args.base64)
        mode = "protobuf+base64" if args.base64 else "protobuf"
        print(f"Packed ({mode}) '{args.repo}' -> '{args.out}'")
    elif args.command == "unpackpb":
        unpack_pb(args.in_file, args.out_repo)
        print(f"Unpacked (protobuf) '{args.in_file}' -> '{args.out_repo}'")
    else:
        parser.error("Unknown command")


if __name__ == "__main__":
    main()
