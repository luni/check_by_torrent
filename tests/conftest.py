"""Pytest configuration and fixtures."""

# Standard library imports
import hashlib
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

# Third-party imports
import bencodepy
import pytest

# Local application imports
# These imports are used in test fixtures via string evaluation
# and are required for the test environment to work correctly


@pytest.fixture(scope="module")
def temp_dir() -> Generator[Path, None, None]:
    """Create and clean up a temporary directory for tests."""
    temp_dir = Path(tempfile.mkdtemp(prefix="check_by_torrent_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def single_file_torrent(temp_dir: Path) -> tuple[Path, Path]:
    """Create a single file torrent for testing."""
    # Create a test file with known content
    file_content = b"This is a test file for torrent verification" * 1000  # ~50KB
    file_path = temp_dir / "test_file.bin"
    file_path.write_bytes(file_content)

    # Calculate piece hashes
    piece_length = 16384  # 16KB pieces
    pieces = b""
    for i in range(0, len(file_content), piece_length):
        piece = file_content[i : i + piece_length]
        pieces += hashlib.sha1(piece).digest()

    # Create a simple .torrent file
    torrent_data = {b"info": {b"name": b"test_file.bin", b"piece length": piece_length, b"length": len(file_content), b"pieces": pieces}}

    torrent_path = temp_dir / "test.torrent"
    with open(torrent_path, "wb") as f:
        f.write(bencodepy.encode(torrent_data))

    return torrent_path, file_path


@pytest.fixture
def multi_file_torrent(temp_dir: Path) -> tuple[Path, Path]:
    """Create a multi-file torrent for testing."""
    # Create test files in a directory
    download_dir = temp_dir / "downloads"
    if download_dir.exists():
        shutil.rmtree(download_dir)
    download_dir.mkdir()

    files = []
    combined = bytearray()
    piece_length = 16384  # 16KB pieces
    for i in range(3):
        file_path = download_dir / f"file_{i}.bin"
        content = (f"Test content for file {i}".encode()) * 1000
        file_path.write_bytes(content)
        files.append({b"path": [f"file_{i}.bin".encode()], b"length": len(content)})
        combined.extend(content)

    pieces = bytearray()
    for i in range(0, len(combined), piece_length):
        piece = combined[i : i + piece_length]
        pieces.extend(hashlib.sha1(piece).digest())

    # Create a simple .torrent file for multi-file torrent
    torrent_data = {
        b"info": {
            b"name": b"test_files",
            b"piece length": piece_length,
            b"files": files,
            b"pieces": bytes(pieces),
        }
    }

    torrent_path = temp_dir / "multi_file.torrent"
    with open(torrent_path, "wb") as f:
        f.write(bencodepy.encode(torrent_data))

    return torrent_path, download_dir


@pytest.fixture
def real_sample_torrent(temp_dir: Path) -> tuple[Path, Path]:
    """Provide a real torrent sample copied from the tests/data directory."""
    fixtures_dir = Path(__file__).parent / "data"
    source_torrent = fixtures_dir / "real_sample.torrent"
    source_payload = fixtures_dir / "real_sample.bin"

    target_dir = temp_dir / "real_sample"
    target_dir.mkdir(exist_ok=True)

    torrent_path = target_dir / source_torrent.name
    payload_path = target_dir / source_payload.name

    shutil.copy(source_torrent, torrent_path)
    shutil.copy(source_payload, payload_path)

    return torrent_path, payload_path
