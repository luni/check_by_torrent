"""Unit tests for internal helper functions."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from check_by_torrent.check_by_torrent import (
    HashMismatchReport,
    PieceFileTracker,
    TorrentError,
    _collect_missing_files,
    _delete_orphan_files,
    _identify_orphan_files,
    _is_zero_piece_hash,
    _normalize_path,
    _overwrite_piece_with_zeros,
    _padding_path_set,
    _physical_length,
    _rename_incomplete_file,
    _report_hash_mismatch,
    _resolve_file_paths,
    _resolve_target_root,
    _update_progress_postfix,
)

# Test constants
PIECE_SIZE_50 = 50
PIECE_SIZE_80 = 80
PIECE_SIZE_20 = 20
FILES_BEYOND_TOTAL = 2
HASH_MISMATCH_ARGS = 5
EXPECTED_ORPHANS = 2
DELETED_FILES = 2
PADDING_LENGTH = 4
REAL_LENGTH = 6


class TestPieceFileTracker:
    """Test the PieceFileTracker class."""

    def test_advance_empty_files(self) -> None:
        """Test advance with empty files list."""
        tracker = PieceFileTracker([])
        result = tracker.advance(100)
        assert result == []

    def test_advance_zero_piece_size(self) -> None:
        """Test advance with zero piece size."""
        files = [(Path("file1.bin"), 100), (Path("file2.bin"), 200)]
        tracker = PieceFileTracker(files)
        result = tracker.advance(0)
        assert result == []

    def test_advance_single_file(self) -> None:
        """Test advance within a single file."""
        files = [(Path("file1.bin"), 100), (Path("file2.bin"), 200)]
        tracker = PieceFileTracker(files)

        # First piece within first file
        result = tracker.advance(50)
        assert result == [(Path("file1.bin"), 50)]
        assert tracker._index == 0
        assert tracker._offset == PIECE_SIZE_50

        # Second piece still within first file
        result = tracker.advance(30)
        assert result == [(Path("file1.bin"), 30)]
        assert tracker._index == 0
        assert tracker._offset == PIECE_SIZE_80

    def test_advance_across_file_boundary(self) -> None:
        """Test advance that crosses file boundaries."""
        files = [(Path("file1.bin"), 100), (Path("file2.bin"), 200)]
        tracker = PieceFileTracker(files)

        # Advance to end of first file and into second
        result = tracker.advance(120)
        assert result == [(Path("file1.bin"), 100), (Path("file2.bin"), 20)]
        assert tracker._index == 1
        assert tracker._offset == PIECE_SIZE_20

    def test_advance_beyond_total_size(self) -> None:
        """Test advance beyond total file size."""
        files = [(Path("file1.bin"), 100), (Path("file2.bin"), 200)]
        tracker = PieceFileTracker(files)

        # Advance beyond total size
        result = tracker.advance(400)
        assert result == [
            (Path("file1.bin"), 100),
            (Path("file2.bin"), 200),
        ]
        assert tracker._index == FILES_BEYOND_TOTAL  # Should be beyond all files
        assert tracker._offset == 0  # Should reset to 0 when past end


class TestCollectMissingFiles:
    """Test the _collect_missing_files function."""

    def test_all_files_present(self, temp_dir: Path) -> None:
        """Test when all files are present."""
        file1 = temp_dir / "file1.bin"
        file2 = temp_dir / "file2.bin"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        files = [(file1, 8), (file2, 8)]
        missing = _collect_missing_files(files)
        assert missing == []


class TestPaddingHelpers:
    """Tests for padding helper utilities."""

    def test_padding_path_set_handles_mapping(self) -> None:
        """Mappings should return their keys as padding paths."""
        padding_map = {Path("a"): 1, Path("b"): 2}
        result = _padding_path_set(padding_map)
        assert result == set(padding_map.keys())

    def test_padding_path_set_handles_collections(self) -> None:
        """Collections should pass through as a set."""
        paths = [Path("x"), Path("y")]
        result = _padding_path_set(paths)
        assert result == set(paths)

    def test_physical_length_ignores_padding(self) -> None:
        """Only non-padding contributions should count toward physical length."""
        padding_paths = {Path("pad.bin")}
        contributions = [
            (Path("pad.bin"), PADDING_LENGTH),
            (Path("real.bin"), REAL_LENGTH),
        ]
        assert _physical_length(contributions, padding_paths) == REAL_LENGTH

    def test_missing_files(self, temp_dir: Path) -> None:
        """Test when some files are missing."""
        # Use a unique subdirectory to avoid interference from other tests
        test_dir = temp_dir / "missing_test"
        test_dir.mkdir()

        file1 = test_dir / "file1.bin"
        file2 = test_dir / "file2.bin"
        file1.write_bytes(b"content1")
        # file2 is not created

        files = [(file1, 8), (file2, 8)]
        missing = _collect_missing_files(files)
        # file2 should be missing since it doesn't exist and no incomplete variant exists
        assert len(missing) == 1
        assert file2 in missing

    def test_missing_file_with_missing_parent_directory(self, temp_dir: Path) -> None:
        """Test that files in missing parent directories are treated as missing."""
        # Create a file path with missing parent directory
        file1 = temp_dir / "missing_dir" / "file1.bin"
        # Don't create the parent directory or the file

        files = [(file1, 8)]
        missing = _collect_missing_files(files)
        # file1 should be missing since parent directory doesn't exist
        assert len(missing) == 1
        assert file1 in missing

    def test_resolve_file_paths_with_missing_parent_directory(self, temp_dir: Path) -> None:
        """Test that files in missing parent directories are not resolved to incomplete variants."""
        # Create a file path with missing parent directory
        file1 = temp_dir / "missing_dir" / "file1.bin"

        # Create incomplete file in wrong location (parent missing)
        incomplete_file = temp_dir / "incomplete.missing_dir" / "file1.bin"
        incomplete_file.parent.mkdir(parents=True)
        incomplete_file.write_bytes(b"content")

        files = [(file1, 8)]
        resolved = _resolve_file_paths(files)

        # Should not use incomplete file since parent directory is missing
        assert len(resolved) == 1
        assert resolved[0][0] == file1  # Should keep original path, not incomplete variant

    def test_incomplete_file_treated_as_present(self, temp_dir: Path) -> None:
        """Test that incomplete.$file is treated as present."""
        file1 = temp_dir / "file1.bin"
        incomplete_file1 = temp_dir / "incomplete.file1.bin"
        incomplete_file1.write_bytes(b"content1")

        files = [(file1, 8)]
        missing = _collect_missing_files(files)
        assert missing == []


class TestUpdateProgressPostfix:
    """Test the _update_progress_postfix function."""

    def test_empty_files(self) -> None:
        """Test with empty file list."""
        mock_pbar = MagicMock()
        _update_progress_postfix(mock_pbar, [])
        mock_pbar.set_postfix.assert_called_once_with(file="")

    def test_single_file(self) -> None:
        """Test with single file."""
        mock_pbar = MagicMock()
        files = [Path("test_file.bin")]
        _update_progress_postfix(mock_pbar, files)
        mock_pbar.set_postfix.assert_called_once_with(file="test_file.bin")

    def test_long_filename_truncation(self) -> None:
        """Test filename truncation for long names."""
        mock_pbar = MagicMock()
        long_name = "a" * 30 + ".bin"
        files = [Path(long_name)]
        _update_progress_postfix(mock_pbar, files)
        # Should be truncated to SHA1_LENGTH (20) chars + "..."
        expected = "a" * 20 + "..."
        mock_pbar.set_postfix.assert_called_once_with(file=expected)

    def test_multiple_files(self) -> None:
        """Test with multiple files - should use last one."""
        mock_pbar = MagicMock()
        files = [Path("file1.bin"), Path("file2.bin"), Path("file3.bin")]
        _update_progress_postfix(mock_pbar, files)
        mock_pbar.set_postfix.assert_called_once_with(file="file3.bin")


class TestReportHashMismatch:
    """Test the _report_hash_mismatch function."""

    def test_no_piece_files(self) -> None:
        """Test when no piece files are available."""
        mock_writer = MagicMock()
        expected_hash = hashlib.sha1(b"test").digest()
        actual_hash = hashlib.sha1(b"different").digest()

        report = HashMismatchReport(
            pbar=mock_writer,
            piece_index=0,
            piece_files=[],
            expected_hash=expected_hash,
            actual_hash=actual_hash,
        )
        _report_hash_mismatch(report)

        mock_writer.write.assert_any_call("\nError: Hash mismatch at piece 0")
        mock_writer.write.assert_any_call("No file mapping available for this piece.")
        mock_writer.write.assert_any_call(f"Expected hash: {expected_hash.hex()}")
        mock_writer.write.assert_any_call(f"Actual hash:   {actual_hash.hex()}")

    def test_single_corrupted_file(self) -> None:
        """Test with single corrupted file."""
        mock_writer = MagicMock()
        files = [Path("corrupted.bin")]
        expected_hash = hashlib.sha1(b"test").digest()
        actual_hash = hashlib.sha1(b"different").digest()

        report = HashMismatchReport(
            pbar=mock_writer,
            piece_index=0,
            piece_files=files,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
        )
        _report_hash_mismatch(report)

        mock_writer.write.assert_any_call("\nError: Hash mismatch at piece 0")
        mock_writer.write.assert_any_call("Potentially corrupted file: corrupted.bin")
        mock_writer.write.assert_any_call(f"Expected hash: {expected_hash.hex()}")
        mock_writer.write.assert_any_call(f"Actual hash:   {actual_hash.hex()}")

    def test_multiple_corrupted_files(self) -> None:
        """Test with multiple corrupted files."""
        mock_writer = MagicMock()
        files = [Path("file1.bin"), Path("file2.bin")]
        expected_hash = hashlib.sha1(b"test").digest()
        actual_hash = hashlib.sha1(b"different").digest()

        report = HashMismatchReport(
            pbar=mock_writer,
            piece_index=0,
            piece_files=files,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
        )
        _report_hash_mismatch(report)

        mock_writer.write.assert_any_call("\nError: Hash mismatch at piece 0")
        mock_writer.write.assert_any_call("Piece spans multiple files; potentially corrupted files:")
        mock_writer.write.assert_any_call("  - file1.bin")
        mock_writer.write.assert_any_call("  - file2.bin")
        mock_writer.write.assert_any_call(f"Expected hash: {expected_hash.hex()}")
        mock_writer.write.assert_any_call(f"Actual hash:   {actual_hash.hex()}")

    def test_with_mark_incomplete_prefix(self) -> None:
        """Test with mark_incomplete_prefix enabled."""
        mock_writer = MagicMock()
        files = [Path("corrupted.bin")]
        expected_hash = hashlib.sha1(b"test").digest()
        actual_hash = hashlib.sha1(b"different").digest()

        with patch("check_by_torrent.check_by_torrent._rename_incomplete_file") as mock_rename:
            report = HashMismatchReport(
                pbar=mock_writer,
                piece_index=0,
                piece_files=files,
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                mark_incomplete_prefix="bad.",
            )
            _report_hash_mismatch(report)

            # Check that rename was called with correct arguments
            mock_rename.assert_called_once()
            call_args = mock_rename.call_args
            assert call_args[0][0] == Path("corrupted.bin")  # file_path
            assert call_args[0][1] == "bad."  # prefix
            assert call_args[0][2] == mock_writer  # writer
            assert len(call_args[0]) == HASH_MISMATCH_ARGS  # Should have 4 arguments


class TestRenameIncompleteFile:
    """Test the _rename_incomplete_file function."""

    def test_successful_rename(self, temp_dir: Path) -> None:
        """Test successful file renaming."""
        original_file = temp_dir / "test.bin"
        original_file.write_bytes(b"content")
        mock_writer = MagicMock()

        _rename_incomplete_file(original_file, "incomplete.", mock_writer)

        expected_target = temp_dir / "incomplete.test.bin"
        assert expected_target.exists()
        assert not original_file.exists()
        mock_writer.write.assert_called_with(f"Renamed incomplete file to: {expected_target}")

    def test_file_already_marked(self, temp_dir: Path) -> None:
        """Test file already marked as incomplete."""
        incomplete_file = temp_dir / "incomplete.test.bin"
        incomplete_file.write_bytes(b"content")
        mock_writer = MagicMock()

        _rename_incomplete_file(incomplete_file, "incomplete.", mock_writer)

        mock_writer.write.assert_called_with(f"File already marked incomplete: {incomplete_file}")

    def test_missing_file(self, temp_dir: Path) -> None:
        """Test renaming non-existent file."""
        missing_file = temp_dir / "missing.bin"
        mock_writer = MagicMock()

        _rename_incomplete_file(missing_file, "incomplete.", mock_writer)

        mock_writer.write.assert_called_with(f"Cannot rename missing file: {missing_file}")

    def test_name_collision_handling(self, temp_dir: Path) -> None:
        """Test handling of name collisions."""
        original_file = temp_dir / "test.bin"
        original_file.write_bytes(b"content")
        existing_target = temp_dir / "incomplete.test.bin"
        existing_target.write_bytes(b"existing")
        mock_writer = MagicMock()

        _rename_incomplete_file(original_file, "incomplete.", mock_writer)

        # Should create numbered version
        expected_target = temp_dir / "incomplete.test.bin.1"
        assert expected_target.exists()
        mock_writer.write.assert_called_with(f"Renamed incomplete file to: {expected_target}")

    def test_duplicate_renaming_prevented(self, temp_dir: Path) -> None:
        """Test that duplicate renaming is prevented."""
        original_file = temp_dir / "test.bin"
        original_file.write_bytes(b"content")
        mock_writer = MagicMock()
        renamed_files = set()

        # First rename should succeed
        _rename_incomplete_file(original_file, "incomplete.", mock_writer, renamed_files)
        assert len(renamed_files) == 1

        # Second rename should be skipped
        _rename_incomplete_file(original_file, "incomplete.", mock_writer, renamed_files)
        assert len(renamed_files) == 1  # Should not increase


class TestOrphanFileHandling:
    """Test orphan file handling functions."""

    def test_resolve_target_root_with_alt_path(self, temp_dir: Path) -> None:
        """Test resolving target root with alternative path."""
        info = {b"name": b"torrent_name"}
        alt_path = temp_dir / "custom_path"

        result = _resolve_target_root(info, alt_path)
        assert result == alt_path

    def test_resolve_target_root_without_alt_path(self) -> None:
        """Test resolving target root without alternative path."""
        info = {b"name": b"torrent_name"}

        result = _resolve_target_root(info, None)
        assert result == Path("torrent_name")

    def test_resolve_target_root_missing_name(self) -> None:
        """Test resolving target root with missing name."""
        info = {}

        with pytest.raises(TorrentError) as exc_info:
            _resolve_target_root(info, None)
        assert "Invalid torrent info: missing name" in str(exc_info.value)

    def test_identify_orphan_files(self, temp_dir: Path) -> None:
        """Test identifying orphan files."""
        # Use a unique subdirectory to avoid interference from other tests
        test_dir = temp_dir / "orphan_test"
        test_dir.mkdir()

        # Create expected files
        expected_file = test_dir / "expected.bin"
        expected_file.write_bytes(b"content")

        # Create orphan file
        orphan_file = test_dir / "orphan.bin"
        orphan_file.write_bytes(b"orphan content")

        # Create subdirectory with orphan
        subdir = test_dir / "subdir"
        subdir.mkdir()
        sub_orphan = subdir / "sub_orphan.bin"
        sub_orphan.write_bytes(b"sub orphan")

        files = [(expected_file, 7)]
        orphans = _identify_orphan_files(test_dir, files)

        # Filter out any incomplete.* files that might be left from other tests
        orphans = [o for o in orphans if not o.name.startswith("incomplete.")]

        assert len(orphans) == EXPECTED_ORPHANS
        assert orphan_file in orphans
        assert sub_orphan in orphans

    def test_delete_orphan_files_success(self, temp_dir: Path) -> None:
        """Test successful deletion of orphan files."""
        test_dir = temp_dir / "delete_test"
        test_dir.mkdir()

        orphan1 = test_dir / "orphan1.bin"
        orphan2 = test_dir / "orphan2.bin"
        orphan1.write_bytes(b"content1")
        orphan2.write_bytes(b"content2")

        mock_writer = MagicMock()
        deleted = _delete_orphan_files([orphan1, orphan2], mock_writer)

        assert deleted == DELETED_FILES
        assert not orphan1.exists()
        assert not orphan2.exists()
        # Check that the mock was called with the full paths
        assert any(str(orphan1) in str(call) for call in mock_writer.write.call_args_list)
        assert any(str(orphan2) in str(call) for call in mock_writer.write.call_args_list)

    def test_delete_orphan_files_partial_failure(self, temp_dir: Path) -> None:
        """Test partial failure in deleting orphan files."""
        orphan1 = temp_dir / "orphan1.bin"
        orphan2 = temp_dir / "orphan2.bin"
        orphan1.write_bytes(b"content1")
        # orphan2 is not created (will fail to delete)

        mock_writer = MagicMock()
        deleted = _delete_orphan_files([orphan1, orphan2], mock_writer)

        assert deleted == 1
        assert not orphan1.exists()
        # Check that the mock was called with the full path for the successful deletion
        assert any(str(orphan1) in str(call) for call in mock_writer.write.call_args_list)
        # Should log error for failed deletion
        assert any("Failed to delete" in str(call) for call in mock_writer.write.call_args_list)

    def test_normalize_path_success(self, temp_dir: Path) -> None:
        """Test successful path normalization."""
        test_path = temp_dir / "test" / ".." / "file.txt"
        normalized = _normalize_path(test_path)
        assert normalized == (temp_dir / "file.txt").resolve()

    def test_normalize_path_fallback(self, temp_dir: Path) -> None:
        """Test path normalization fallback when resolve fails."""
        # Create a path that might fail to resolve
        test_path = Path("/nonexistent/very/long/path/that/should/fail/to/resolve/file.txt")

        with patch("pathlib.Path.resolve", side_effect=OSError("resolve failed")):
            normalized = _normalize_path(test_path)
            assert normalized == test_path.absolute()


class TestZeroPieceHash:
    """Test the _is_zero_piece_hash function."""

    def test_zero_piece_hash_detection(self) -> None:
        """Test detection of zero piece hashes."""
        piece_length = 1024
        zero_data = b"\x00" * piece_length
        expected_hash = hashlib.sha1(zero_data).digest()

        assert _is_zero_piece_hash(expected_hash, piece_length) is True

        # Test with non-zero data
        non_zero_data = b"\x01" + b"\x00" * (piece_length - 1)
        non_zero_hash = hashlib.sha1(non_zero_data).digest()
        assert _is_zero_piece_hash(non_zero_hash, piece_length) is False

    def test_different_piece_lengths(self) -> None:
        """Test zero piece hash detection with different lengths."""
        for length in [1, 10, 100, 1024, 2048]:
            zero_data = b"\x00" * length
            expected_hash = hashlib.sha1(zero_data).digest()
            assert _is_zero_piece_hash(expected_hash, length) is True


class TestOverwritePieceWithZeros:
    """Test the _overwrite_piece_with_zeros function."""

    def test_overwrite_dry_run(self, tmp_path: Path) -> None:
        """Test dry run mode for overwriting pieces."""
        # Create a test file with some data
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello, World!")

        tracker = PieceFileTracker([(test_file, 13)])  # File size 13
        tracker._offset = 5

        mock_writer = MagicMock()

        # Test dry run
        result = _overwrite_piece_with_zeros(tracker, 8, mock_writer, dry_run=True)

        assert result is True
        mock_writer.write.assert_called()
        # File should not be modified in dry run
        assert test_file.read_bytes() == b"Hello, World!"

    def test_overwrite_actual(self, tmp_path: Path) -> None:
        """Test actual overwriting of pieces."""
        # Create a test file with some data
        test_file = tmp_path / "test.bin"
        original_data = b"Hello, World!"
        test_file.write_bytes(original_data)

        tracker = PieceFileTracker([(test_file, 13)])  # File size 13
        tracker._offset = 3  # Start at offset 3, so piece doesn't extend to end

        mock_writer = MagicMock()

        # Test actual overwrite (overwrite 5 bytes from offset 3)
        result = _overwrite_piece_with_zeros(tracker, 5, mock_writer, dry_run=False)

        assert result is True
        mock_writer.write.assert_called()
        # File should be partially overwritten with zeros
        # Original: "Hello, World!" -> overwrite from offset 3 (positions 3,4,5,6,7)
        # "Hello, World!" -> "Hel" + "\x00\x00\x00\x00\x00" + "orld!"
        expected_data = b"Hel" + b"\x00" * 5 + b"orld!"
        assert test_file.read_bytes() == expected_data

    def test_overwrite_missing_file(self, tmp_path: Path) -> None:
        """Test overwriting when file doesn't exist."""
        missing_file = tmp_path / "missing.bin"

        tracker = PieceFileTracker([(missing_file, 10)])
        mock_writer = MagicMock()

        result = _overwrite_piece_with_zeros(tracker, 10, mock_writer, dry_run=False)

        assert result is False
        mock_writer.write.assert_called()

    def test_overwrite_sparse_file_optimization(self, tmp_path: Path) -> None:
        """Test sparse file optimization for end-of-file pieces."""
        # Create a test file with some data
        test_file = tmp_path / "test.bin"
        original_data = b"Hello"
        test_file.write_bytes(original_data)

        tracker = PieceFileTracker([(test_file, 5)])  # File size 5
        tracker._offset = 3  # Overwrite from offset 3 to end (3 + 2 = 5)

        mock_writer = MagicMock()

        # Test sparse file overwrite (should use truncate)
        result = _overwrite_piece_with_zeros(tracker, 2, mock_writer, dry_run=False)

        assert result is True
        mock_writer.write.assert_called()
        # File should remain unchanged (sparse optimization)
        assert test_file.read_bytes() == original_data
        assert test_file.stat().st_size == 5

        # Check that sparse optimization was used in the log
        calls = [call[0][0] for call in mock_writer.write.call_args_list]
        sparse_calls = [call for call in calls if "sparse file optimization" in call]
        assert len(sparse_calls) == 1
