"""Unit tests for core helpers in check_by_torrent."""

import hashlib
from pathlib import Path

import bencodepy
import pytest

from check_by_torrent.check_by_torrent import (
    TorrentError,
    _prepare_verification_context,
    calculate_total_length,
    get_files,
    human_readable_size,
    pieces_generator,
)

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
    files = get_files(info, str(alt_root).encode())
    expected = [
        (alt_root / "dir" / "a.bin", 10),
        (alt_root / "b.bin", 20),
    ]
    assert files == expected


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


def test_prepare_context_display_length_excludes_padding(tmp_path: Path) -> None:
    """Verification context display length should exclude BEP47 padding bytes."""

    piece_length = 8
    file0 = b"A" * 6
    padding = b"\x00" * 4
    file1 = b"B" * 6
    combined = file0 + padding + file1

    files_meta = [
        {b"path": [b"tea", b"file0.bin"], b"length": len(file0)},
        {b"path": [b"tea", b"_____padding_file_0"], b"length": len(padding), b"attr": b"p"},
        {b"path": [b"tea", b"file1.bin"], b"length": len(file1)},
    ]

    pieces = bytearray()
    for offset in range(0, len(combined), piece_length):
        pieces.extend(hashlib.sha1(combined[offset : offset + piece_length]).digest())

    info = {
        b"name": b"padding",
        b"piece length": piece_length,
        b"files": files_meta,
        b"pieces": bytes(pieces),
    }

    torrent_path = tmp_path / "padding.torrent"
    torrent_path.write_bytes(bencodepy.encode({b"info": info}))

    context = _prepare_verification_context(torrent_path, None)
    assert context.total_length == len(combined)
    assert context.display_length == len(file0) + len(file1)
    assert set(context.padding_files.keys()) == {Path("padding") / "tea" / "_____padding_file_0"}
