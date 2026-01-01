# Torrent Integrity Checker

`check-by-torrent` is a Python CLI utility that validates downloaded torrent payloads against the hashes stored in their `.torrent` metadata. It surfaces missing files, piece-level corruption, and other issues before you seed or archive the data.

## Features

- Works with both single-file and multi-file torrents
- Detects missing files before hashing begins
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

## Project structure

```
check-by-torrent/
├── check_by_torrent/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── check_by_torrent.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_cli.py
│   └── test_core.py
├── README.md
├── pyproject.toml
├── uv.lock
├── Makefile
└── LICENSE
```

## License

MIT

## Contributing

Issues and pull requests are welcome—see [GitHub](https://github.com/luni/check-by-torrent) to report bugs or propose enhancements.