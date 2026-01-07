# Torrent Integrity Checker

`check-by-torrent` is a Python CLI utility that validates downloaded torrent payloads against the hashes stored in their `.torrent` metadata. It surfaces missing files, piece-level corruption, and other issues before you seed or archive the data.

## Features

- Works with both single-file and multi-file torrents
- Detects missing files before hashing begins
- Lists or prunes orphaned payload files in multi-file torrents
- Streams data sequentially with chunked hashing for large payloads
- Uses `tqdm` to display byte-accurate progress (current file, ETA, throughput)
- Emits clear diagnostics and non-zero exit codes on failures
- Fully typed codebase targeting Python 3.10–3.12

## Requirements

- Python **3.10+**
- [`uv`](https://docs.astral.sh/uv/) for dependency management (used for all install instructions below)

## Installation

### Install from PyPI

```bash
uv pip install check-by-torrent
```

This exposes the `check-by-torrent` command on your `PATH`.

### Install from source (development)

```bash
git clone https://github.com/luni/check-by-torrent.git
cd check-by-torrent
uv sync --group dev
```

`uv sync` creates a virtual environment (default `.venv`) with the locked runtime plus the `dev` extras (pytest, ruff, pyright, etc.). Use `uv run <command>` to execute tools inside that environment without activating it manually.

If you prefer an editable install in an existing environment:

```bash
uv pip install -e ".[dev]"
```

## Usage

```bash
check-by-torrent path/to/file.torrent [download_path]
```

- `path/to/file.torrent`: required `.torrent` metadata file.
- `download_path`: optional directory or file override. If omitted, files are resolved relative to the torrent file’s directory (matching the paths stored inside the torrent).

### Examples

Verify content in the current directory:

```bash
check-by-torrent ubuntu.torrent
```

Verify content stored elsewhere (e.g., your downloads folder):

```bash
check-by-torrent archlinux.torrent /data/downloads
```

Display CLI help/arguments:

```bash
check-by-torrent --help
```

### Orphan management (multi-file torrents)

Sometimes the download directory accumulates stray files that are not described by the torrent metadata. You can list or delete those files while verifying:

```bash
# Show extra files relative to the torrent payload
check-by-torrent my_collection.torrent /data/torrents --list-orphans

# Remove (and implicitly list) the extra files
check-by-torrent my_collection.torrent /data/torrents --delete-orphans
```

`--delete-orphans` automatically implies `--list-orphans` so you always see what was removed. When either flag is provided the tool switches into "orphan-only" mode, meaning it skips the hash verification step and just inspects the target directory. For safety this feature only applies to multi-file torrents and requires the target directory to exist.

### Continue on error

To inspect every piece mismatch instead of stopping at the first failure, use:

```bash
check-by-torrent my_collection.torrent /data/torrents --continue-on-error
```

This keeps hashing after each mismatch and even after missing files are detected so you get a full list of issues (missing files are still reported up front and the command ultimately exits with failure if any remain). In orphan-only mode this flag is ignored because hashing is skipped entirely.

### Mark incomplete files

To automatically rename files that fail verification, use:

```bash
check-by-torrent my_collection.torrent /data/torrents --mark-incomplete
```

You can optionally provide a custom prefix:

```bash
check-by-torrent my_collection.torrent /data/torrents --mark-incomplete "corrupt."
```

The tool prepends the prefix to each corrupted file exactly once, avoiding name collisions. Files are renamed from `$file` to `prefix$file`. When `--continue-on-error` is active, no renaming occurs so you get a clean report of all issues. In orphan-only mode this flag is ignored.

Note: Files marked as incomplete are treated as present during verification, so they won't be reported as "missing" but will still trigger hash mismatches if the content doesn't match the torrent.

## Output

During verification the tool displays a `tqdm` progress bar containing:

- Bytes processed vs. total torrent size
- Elapsed & estimated remaining time
- Read throughput
- The current file segment being hashed

On failure, the command prints actionable diagnostics (missing files, piece number with mismatched hash, expected vs. actual digest) and exits with status code `1`. A successful verification prints `Verification successful` and exits with `0`.

## Development workflow

All tooling is invoked via `uv run …` to ensure the locked environment is used:

```bash
# Quality gates
uv run ruff check .
uv run ruff format --check .

# Test suite
uv run pytest
uv run pytest --cov=check_by_torrent --cov-report=term-missing

# Static analysis (optional targets configured in the Makefile/pyproject)
uv run pyright
uv run bandit -c pyproject.toml -r .
uv run xenon -b D -m B -a B .
```

For a one-shot validation similar to CI you can also run:

```bash
uv run make validate
```

## License

MIT

## Contributing

Issues and pull requests are welcome—see [GitHub](https://github.com/luni/check-by-torrent) to report bugs or propose enhancements.