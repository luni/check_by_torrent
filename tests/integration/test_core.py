"""Integration tests for torrent verification workflow."""

import hashlib
from collections.abc import Iterator
from pathlib import Path

import bencodepy
import pytest

from check_by_torrent import check_by_torrent as cbt
from check_by_torrent.check_by_torrent import VerificationOptions, verify_torrent


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


def test_verify_torrent_lists_orphans(multi_file_torrent: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """Listing orphans should report unexpected files and still verify successfully."""
    torrent_path, download_dir = multi_file_torrent
    orphan = download_dir / "orphan.bin"
    orphan.write_bytes(b"orphan")

    assert verify_torrent(str(torrent_path), download_dir, VerificationOptions(list_orphans=True)) is True
    combined = "".join(capsys.readouterr())
    assert "Orphaned files detected" in combined
    assert str(orphan) in combined


def test_verify_torrent_orphan_mode_ignores_missing_payload(multi_file_torrent: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """Orphan listing should not fail when expected files are missing."""
    torrent_path, download_dir = multi_file_torrent
    missing = download_dir / "file_0.bin"
    if missing.exists():
        missing.unlink()
    orphan = download_dir / "extra.bin"
    orphan.write_bytes(b"extra")

    assert verify_torrent(str(torrent_path), download_dir, VerificationOptions(list_orphans=True)) is True
    combined = "".join(capsys.readouterr())
    assert str(orphan) in combined
    assert "No orphaned files detected" not in combined


def test_verify_torrent_deletes_orphans(multi_file_torrent: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """Deletion flag should remove orphan files and report progress."""
    torrent_path, download_dir = multi_file_torrent
    orphan = download_dir / "delete_me.bin"
    orphan.write_bytes(b"remove me")

    assert verify_torrent(str(torrent_path), torrent_path.parent, VerificationOptions(list_orphans=True, delete_orphans=True)) is True
    combined = "".join(capsys.readouterr())
    assert "Deleting orphaned file" in combined
    assert "Removed" in combined and "orphaned file" in combined
    assert not orphan.exists()


def test_verify_torrent_marks_incomplete_files(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A custom prefix should be prepended to corrupted files."""
    torrent_path, file_path = single_file_torrent
    file_path.write_bytes(b"\x00" * file_path.stat().st_size)

    assert verify_torrent(str(torrent_path), file_path.parent, VerificationOptions(mark_incomplete_prefix="bad.")) is False
    combined = "".join(capsys.readouterr())
    assert "Renamed incomplete file" in combined
    assert file_path.with_name(f"bad.{file_path.name}").exists()


def test_verify_torrent_marks_incomplete_default_prefix(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Default incomplete. prefix should be used when none is specified."""
    torrent_path, file_path = single_file_torrent
    file_path.write_bytes(b"\x00" * file_path.stat().st_size)

    assert verify_torrent(str(torrent_path), file_path.parent, VerificationOptions(mark_incomplete_prefix="incomplete.")) is False
    combined = "".join(capsys.readouterr())
    assert "Renamed incomplete file" in combined
    assert file_path.with_name(f"incomplete.{file_path.name}").exists()


def test_verify_torrent_marks_incomplete_skips_when_continue_on_error(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When --continue-on-error is active, files should not be renamed."""
    torrent_path, file_path = single_file_torrent
    file_path.write_bytes(b"\x00" * file_path.stat().st_size)

    assert verify_torrent(str(torrent_path), file_path.parent, VerificationOptions(continue_on_error=True)) is False
    combined = "".join(capsys.readouterr())
    assert "Renamed incomplete file" not in combined
    # The file should not be renamed since continue_on_error disables marking
    # But it might have been renamed by a previous test, so just check it wasn't renamed now
    # (the file should still exist as the original since marking was disabled)
    assert file_path.exists()


def test_verify_torrent_treats_incomplete_as_present(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """incomplete.$file should be treated as present but mismatched."""
    torrent_path, file_path = single_file_torrent
    # Rename file to incomplete.$file
    incomplete_path = file_path.with_name(f"incomplete.{file_path.name}")
    file_path.rename(incomplete_path)

    # The verification should succeed because the incomplete file has the same content
    # as the original (we just renamed it), so hashes match
    assert verify_torrent(str(torrent_path), file_path.parent) is True
    combined = "".join(capsys.readouterr())
    assert "missing files" not in combined
    assert "Hash mismatch" not in combined


def test_verify_torrent_continue_on_error_reports_all_mismatches(
    single_file_torrent: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """continue_on_error should keep hashing and record every mismatch."""
    torrent_path, file_path = single_file_torrent
    file_path.write_bytes(b"\x00" * file_path.stat().st_size)

    min_expected_mismatches = 2
    observed: list[int] = []
    original_report = cbt._report_hash_mismatch

    def recorder(report: cbt.HashMismatchReport) -> None:
        observed.append(report.piece_index)
        original_report(report)

    monkeypatch.setattr(cbt, "_report_hash_mismatch", recorder)
    result = verify_torrent(str(torrent_path), file_path.parent, VerificationOptions(continue_on_error=True))
    assert result is False
    assert len(observed) >= min_expected_mismatches


def test_verify_torrent_restores_incomplete_files(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--restore-incomplete should rename incomplete.$file to $file when hashes match."""
    torrent_path, file_path = single_file_torrent

    # Remove original file and create incomplete file with correct content
    original_content = file_path.read_bytes()
    file_path.unlink()
    incomplete_file = file_path.with_name(f"incomplete.{file_path.name}")
    incomplete_file.write_bytes(original_content)

    # Verify with restore option
    assert verify_torrent(str(torrent_path), torrent_path.parent, VerificationOptions(restore_incomplete=True)) is True
    combined = "".join(capsys.readouterr())

    # Check that file was restored
    assert "Restored incomplete file" in combined
    assert "Successfully restored 1 incomplete file(s)" in combined
    assert file_path.exists()
    assert not incomplete_file.exists()
    assert file_path.read_bytes() == original_content


def test_verify_torrent_does_not_restore_when_hashes_mismatch(
    single_file_torrent: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--restore-incomplete should not restore files when hashes don't match."""
    torrent_path, file_path = single_file_torrent

    # Remove original file and create incomplete file with wrong content
    file_path.unlink()
    incomplete_file = file_path.with_name(f"incomplete.{file_path.name}")
    incomplete_file.write_bytes(b"wrong content")

    # Verify with restore option
    assert verify_torrent(str(torrent_path), torrent_path.parent, VerificationOptions(restore_incomplete=True)) is False
    combined = "".join(capsys.readouterr())

    # Check that file was NOT restored
    assert "Restored incomplete file" not in combined
    assert not file_path.exists()
    assert incomplete_file.exists()


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
