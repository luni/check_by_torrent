"""Test core functionality of check_by_torrent."""

# Local application imports
from pathlib import Path

from check_by_torrent.check_by_torrent import (
    calculate_total_length,
    get_files,
    human_readable_size,
    verify_torrent,
)

# Constants for testing
PIECE_LENGTH = 16384  # 16KB pieces
FILE_LENGTH = 100


def test_human_readable_size() -> None:
    """Test human_readable_size function."""
    assert human_readable_size(0) == "0.0 B"
    assert human_readable_size(1023) == "1023.0 B"
    assert human_readable_size(1024) == "1.0 KB"
    assert human_readable_size(1024**2) == "1.0 MB"
    assert human_readable_size(1024**3) == "1.0 GB"
    assert human_readable_size(1024**4) == "1.0 TB"
    assert human_readable_size(1024**5) == "1.0 PB"


def test_calculate_total_length_single_file() -> None:
    """Test calculate_total_length with a single file torrent."""
    info = {
        b"name": b"test.txt",
        b"piece length": PIECE_LENGTH,
        b"pieces": b"12345678901234567890",
        b"length": FILE_LENGTH,
    }
    assert calculate_total_length(info) == FILE_LENGTH


def test_get_files_single_file(temp_dir: str) -> None:
    """Test get_files with a single file torrent."""
    info = {
        b"name": b"test_file.txt",
        b"piece length": PIECE_LENGTH,
        b"pieces": b"12345678901234567890",
        b"length": FILE_LENGTH,
    }
    files = get_files(info, temp_dir)
    assert len(files) == 1
    assert files[0][0] == temp_dir / "test_file.txt"
    assert files[0][1] == FILE_LENGTH


def test_verify_torrent_single_file(single_file_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent with a valid single file torrent."""
    torrent_path, file_path = single_file_torrent
    assert file_path.exists(), f"Test file {file_path} does not exist"
    assert verify_torrent(str(torrent_path), torrent_path.parent) is True


def test_verify_torrent_missing_file(single_file_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent with a missing file."""
    torrent_path, file_path = single_file_torrent
    file_path.unlink()  # Delete the file
    assert verify_torrent(str(torrent_path), file_path.parent) is False


def test_verify_torrent_corrupted_file(single_file_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent with a corrupted file."""
    torrent_path, file_path = single_file_torrent
    # Corrupt the file by appending some data
    with open(file_path, "ab") as f:
        f.write(b"corruption")
    assert verify_torrent(str(torrent_path), file_path.parent) is False
