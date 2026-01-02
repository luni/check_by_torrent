"""Integration tests for torrent verification workflow."""

import hashlib
from collections.abc import Iterator
from pathlib import Path

import bencodepy
import pytest

from check_by_torrent import check_by_torrent as cbt
from check_by_torrent.check_by_torrent import verify_torrent


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


def _build_overlapping_piece_fixture(tmp_path: Path) -> tuple[Path, Path, list[Path]]:
    """Create a torrent whose piece spans multiple files."""
    piece_length = 8
    download_dir = tmp_path / "overlap_payload"
    download_dir.mkdir()

    file_specs = [
        ("file0.bin", b"A" * 6),
        ("file1.bin", b"B" * 6),
    ]

    files_meta: list[dict[bytes, object]] = []
    file_paths: list[Path] = []
    combined = bytearray()
    for name, content in file_specs:
        path = download_dir / name
        path.write_bytes(content)
        file_paths.append(path)
        files_meta.append({b"path": [name.encode()], b"length": len(content)})
        combined.extend(content)

    pieces = bytearray()
    for offset in range(0, len(combined), piece_length):
        pieces.extend(hashlib.sha1(combined[offset : offset + piece_length]).digest())

    info = {
        b"name": b"overlap",
        b"piece length": piece_length,
        b"files": files_meta,
        b"pieces": bytes(pieces),
    }

    torrent_path = tmp_path / "overlap.torrent"
    torrent_path.write_bytes(bencodepy.encode({b"info": info}))
    return torrent_path, download_dir, file_paths


def test_verify_torrent_reports_all_files_for_overlapping_piece(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Pieces spanning multiple files should report every affected file."""
    torrent_path, download_dir, file_paths = _build_overlapping_piece_fixture(tmp_path)
    corrupted_file = file_paths[0]
    original = corrupted_file.read_bytes()
    corrupted_file.write_bytes(b"Z" + original[1:])

    assert verify_torrent(str(torrent_path), download_dir) is False
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "Piece spans multiple files" in combined
    assert str(file_paths[0]) in combined
    assert str(file_paths[1]) in combined


def test_verify_torrent_real_sample(real_sample_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent using a real torrent/payload pair checked into the repo."""
    torrent_path, payload_path = real_sample_torrent
    assert payload_path.exists(), "Real sample payload missing"
    assert verify_torrent(str(torrent_path), payload_path.parent) is True


def test_verify_torrent_corrupted_file(single_file_torrent: tuple[Path, Path]) -> None:
    """Test verify_torrent with a corrupted file."""
    torrent_path, file_path = single_file_torrent
    with open(file_path, "ab") as f:
        f.write(b"corruption")
    assert verify_torrent(str(torrent_path), file_path.parent) is False


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
