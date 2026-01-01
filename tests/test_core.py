"""Test core functionality of check_by_torrent."""

# Standard library imports
import os
from collections.abc import Iterator
from pathlib import Path

# Third-party imports
import pytest

# Local application imports
from check_by_torrent import check_by_torrent as cbt
from check_by_torrent.check_by_torrent import (
    TorrentError,
    calculate_total_length,
    get_files,
    human_readable_size,
    pieces_generator,
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


def test_get_files_single_file(temp_dir: Path) -> None:
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


def test_get_files_single_file_with_alt_file(temp_dir: Path) -> None:
    """Ensure alternate file path is respected even if it does not exist yet."""
    target_file = temp_dir / "custom.bin"
    info = {b"name": b"ignored.bin", b"length": FILE_LENGTH}
    files = get_files(info, target_file)
    assert files == [(target_file, FILE_LENGTH)]


def test_get_files_multi_file_with_alt_path_bytes(temp_dir: Path) -> None:
    """Ensure multi-file torrents honor alternate root paths provided as bytes."""
    alt_root = temp_dir / "alt_root"
    alt_root.mkdir()
    info = {
        b"name": b"original",
        b"files": [
            {b"path": [b"dir", b"a.bin"], b"length": 10},
            {b"path": [b"b.bin"], b"length": 20},
        ],
    }
    files = get_files(info, os.fsencode(str(alt_root)))
    expected = [
        (alt_root / "dir" / "a.bin", 10),
        (alt_root / "b.bin", 20),
    ]
    assert files == expected


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


def test_verify_torrent_real_sample(real_sample_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent using a real torrent/ payload pair checked into the repo."""
    torrent_path, payload_path = real_sample_torrent
    assert payload_path.exists(), "Real sample payload missing"
    assert verify_torrent(str(torrent_path), payload_path.parent) is True


def test_verify_torrent_corrupted_file(single_file_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent with a corrupted file."""
    torrent_path, file_path = single_file_torrent
    # Corrupt the file by appending some data
    with open(file_path, "ab") as f:
        f.write(b"corruption")
    assert verify_torrent(str(torrent_path), file_path.parent) is False


def test_calculate_total_length_invalid_info() -> None:
    """calculate_total_length should raise for missing length details."""
    with pytest.raises(TorrentError):
        calculate_total_length({b"name": b"broken"})


def test_pieces_generator_missing_piece_length() -> None:
    """pieces_generator should raise when piece length metadata is absent."""
    info = {b"name": b"bad"}
    generator = pieces_generator(info)
    with pytest.raises(TorrentError):
        next(generator)


def test_verify_torrent_missing_torrent_file(tmp_path: Path) -> None:
    """verify_torrent should gracefully fail when the torrent file is absent."""
    assert verify_torrent(str(tmp_path / "missing.torrent")) is False


def test_verify_torrent_length_mismatch(monkeypatch: pytest.MonkeyPatch, single_file_torrent: tuple[Path, Path]) -> None:
    """If not all bytes are processed, verification should fail."""
    torrent_path, file_path = single_file_torrent
    original_generator = cbt.pieces_generator

    def limited_generator(info: cbt.TorrentInfo, alt_file: cbt.BytesOrStrPath | None = None) -> Iterator[bytes]:
        gen = original_generator(info, alt_file)
        try:
            yield next(gen)
        except StopIteration:
            return

    monkeypatch.setattr(cbt, "pieces_generator", limited_generator)
    assert verify_torrent(str(torrent_path), file_path.parent) is False


def test_verify_torrent_decode_error(monkeypatch: pytest.MonkeyPatch, single_file_torrent: tuple[Path, Path]) -> None:
    """Unexpected decode errors should be caught and reported as False."""
    torrent_path, _ = single_file_torrent

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(cbt.bencodepy, "decode", boom)
    assert verify_torrent(str(torrent_path), torrent_path.parent) is False
