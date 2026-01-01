# Torrent Integrity Checker

A Python utility to verify the integrity of downloaded torrent files against their .torrent metadata.

## Features

- Verifies downloaded files against torrent hashes
- Supports both single-file and multi-file torrents
- Shows progress with a beautiful progress bar using `tqdm`
- Handles large files efficiently with memory-mapped I/O
- Provides detailed error reporting
- Works with Python 3.9+
- Type hints for better code quality and IDE support

## Installation

### Using pip

```bash
pip install check-by-torrent
```

### From source

```bash
git clone https://github.com/yourusername/check-by-torrent.git
cd check-by-torrent
uv pip install -e .
```

## Usage

Basic usage:

```bash
check-by-torrent path/to/your.torrent [download_path]
```

If `download_path` is not specified, the script will look for files in the current directory.

### Examples

Check a torrent in the current directory:

```bash
check-by-torrent example.torrent
```

Check a torrent with files in a specific directory:

```bash
check-by-torrent example.torrent /path/to/downloads
```

## Output

The script will display a progress bar showing:
- Current progress
- Transfer speed
- Estimated time remaining
- Current file being processed

If any files are missing or have incorrect hashes, the script will report the errors and exit with a non-zero status code.

## Development

This project uses:
- `uv` for dependency management and running development tasks
- `ruff` for linting and code formatting
- `pytest` for testing
- `pytest-cov` for test coverage reporting

### Setting up the development environment

1. Install `uv` (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/yourusername/check-by-torrent.git
   cd check-by-torrent
   uv pip install -e ".[dev]"
   ```

### Development tasks

- Run tests:
  ```bash
  uv run test
  ```

- Run tests with coverage:
  ```bash
  uv run test-cov
  ```

- Lint the code:
  ```bash
  uv run lint
  ```

- Format the code:
  ```bash
  uv run format
  ```

- Run all checks (lint, format, test):
  ```bash
  uv run check
  ```

## Project Structure

```
check-by-torrent/
├── check_by_torrent/       # Main package
│   ├── __init__.py         # Package initialization
│   ├── __main__.py         # Command-line entry point
│   ├── cli.py              # Command-line interface
│   └── check_by_torrent.py # Core functionality
├── tests/                  # Test files
│   ├── __init__.py
│   ├── conftest.py         # Test fixtures
│   ├── test_cli.py         # CLI tests
│   └── test_core.py        # Core functionality tests
├── .gitignore
├── LICENSE
├── pyproject.toml          # Project metadata and build configuration
└── README.md               # This file
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.