# TreeTextor

TreeTextor converts a repository into a **single multiline text artifact** and reconstructs it back with integrity checks.

It is designed for safe, auditable transfer in text-only workflows.

## Features

- Packs a directory tree into one text file (`.txt`/`.json` style content)
- Stores each file payload as `gzip + base64` text chunks (multiline, copy/paste friendly)
- Reconstructs files and folders from the artifact
- Verifies `size` and `sha256` for every file during unpack
- Protects against unsafe paths (`..`, absolute paths)
- Skips common binary/build artifacts and symlinks

## Why this format?

- The output artifact itself is **plain text** and **multiline**
- File contents are compressed per file, then encoded as text
- You can copy/paste the artifact contents into a new file and unpack it

## Requirements

- Python 3.9+
- No third-party dependencies

## Usage

```bash
python3 tree_textor.py pack   <repo_dir> <out.txt>
python3 tree_textor.py unpack <out.txt>  <out_repo_dir>
```

### Example

```bash
python3 tree_textor.py pack ./my_repo repo_snapshot.txt
python3 tree_textor.py unpack repo_snapshot.txt ./my_repo_restored
```

## Output format (high level)

TreeTextor writes pretty JSON with metadata:

- `tree_textor_version`
- `created_at_utc`
- `source_root_name`
- `file_count`
- `files[]`

Each file entry includes:

- `path`
- `size`
- `sha256`
- `encoding` (`gzip+base64`)
- `chunks` (multiline base64 string pieces)

## Default exclusions

TreeTextor skips these by default:

- Directories/files: `.git`, `.DS_Store`, `__pycache__`
- Binary/build artifacts: `.so`, `.so.*`, `.o`, `.a`, `.dylib`, `.dll`, `.exe`, `.bin`, `.elf`, `.obj`, `.pyc`, `.pyo`
- Symlinks (including broken symlinks)

If a file becomes unreadable during packing, it is skipped with a warning.

## Notes

- Running `python3 tree_textor.py` without a subcommand will show CLI help/error (expected).
- This tool is intended for reproducible test artifacts and text-friendly transfer workflows.

## License
MIT
