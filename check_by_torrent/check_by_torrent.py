#!/usr/bin/env python3
"""Check torrent file integrity by verifying piece hashes.

This module provides functionality to verify that the downloaded files of a torrent
match the hashes specified in the .torrent file. It supports both single-file and
multi-file torrents, with progress reporting and detailed error messages.
"""

import hashlib
import os
import sys
from collections.abc import Collection, Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeAlias, Union, cast, runtime_checkable

import bencodepy
from tqdm import tqdm


@runtime_checkable
class _ProgressBar(Protocol):
    """Protocol for progress bar implementations."""

    def update(self, n: int) -> None:
        """Update progress by n bytes."""
        ...

    def set_postfix(self, **kwargs: object) -> None:
        """Set postfix text."""
        ...

    def write(self, msg: str) -> None:
        """Write a message."""
        ...

    def __enter__(self) -> "_ProgressBar":
        """Context manager entry."""
        ...

    def __exit__(self, *args: object) -> None:
        """Context manager exit."""
        ...


# Simple progress indicator for --no-progress option
class SimpleProgress:
    def __init__(self, total: int) -> None:
        self.total = total
        self.current = 0

    def __enter__(self) -> "SimpleProgress":
        return self

    def __exit__(self, *args: object) -> None:
        _ = args  # Mark as intentionally unused
        pass

    def update(self, n: int) -> None:
        self.current += n

    def set_postfix(self, **kwargs: object) -> None:
        _ = kwargs  # Mark as intentionally unused
        pass

    def write(self, msg: str) -> None:
        print(msg)


# Constants
KB = 1024
MB = KB * 1024
GB = MB * 1024
TB = GB * 1024
PB = TB * 1024

SHA1_LENGTH = 20
MAX_DISPLAY_FILENAME_LENGTH = 20

# Type aliases

StrPath: TypeAlias = str | os.PathLike[str]
BytesOrStrPath: TypeAlias = bytes | StrPath
TorrentInfo = Mapping[bytes, Any]
FileList = list[tuple[Path, int]]


@dataclass(frozen=True)
class VerificationContext:
    """Prepared data required for verifying torrent pieces."""

    info: TorrentInfo
    piece_hashes: list[bytes]
    total_length: int  # includes padding bytes
    display_length: int  # excludes padding bytes
    display_name: str
    files: FileList
    padding_files: dict[Path, int]


class PieceFileTracker:
    """Track which files contribute to each piece as we iterate."""

    def __init__(self, files: FileList) -> None:
        self._files = files
        self._index = 0
        self._offset = 0

    def advance(self, piece_size: int) -> list[tuple[Path, int]]:
        if piece_size == 0 or not self._files:
            return []

        contributions: list[tuple[Path, int]] = []
        remaining = piece_size
        index = self._index
        offset = self._offset

        while remaining > 0 and index < len(self._files):
            file_path, file_size = self._files[index]
            available = file_size - offset
            take = min(remaining, available)

            if take > 0:
                if contributions and contributions[-1][0] == file_path:
                    prev_path, prev_size = contributions[-1]
                    contributions[-1] = (prev_path, prev_size + take)
                else:
                    contributions.append((file_path, take))

            remaining -= take
            if take == available:
                index += 1
                offset = 0
            else:
                offset += take

        self._index = index
        self._offset = offset
        return contributions


class TorrentError(Exception):
    """Base exception for torrent-related errors."""

    pass


def _is_piece_at_file_end(file_path: Path, offset: int, size: int, file_size: int) -> bool:
    """Check if a piece at the given offset and size is at the end of the file."""
    if not file_path.exists() or offset < 0 or size < 0 or file_size < 0:
        return False
    return offset + size == file_size


def _coerce_path(path_value: BytesOrStrPath) -> Path:
    """Convert bytes/str/PathLike inputs to a Path."""

    if isinstance(path_value, bytes):
        return Path(os.fsdecode(path_value))
    return Path(path_value)


def _is_padding_file(file_info: Mapping[bytes, Any]) -> bool:
    """Return True if a multi-file entry is a BEP47 padding file."""

    attrs = file_info.get(b"attr")
    if isinstance(attrs, bytes) and b"p" in attrs:
        return True
    if isinstance(attrs, str) and "p" in attrs:
        return True

    try:
        path_parts = file_info.get(b"path")
        if isinstance(path_parts, list) and path_parts:
            last = path_parts[-1]
            if isinstance(last, bytes):
                last_str = last.decode("utf-8", errors="replace")
            else:
                last_str = str(last)
            if last_str.startswith("_____padding_file_"):
                return True
    except Exception:
        return False

    return False


def _get_padding_files(info: TorrentInfo, alt_file: BytesOrStrPath | None = None) -> dict[Path, int]:
    """Return the resolved Paths and lengths for padding entries in a multi-file torrent."""

    padding: dict[Path, int] = {}
    if b"files" not in info:
        return padding

    try:
        name = info[b"name"].decode("utf-8")
        base_path = _coerce_path(alt_file) if alt_file else Path(name)
        for file_info in info[b"files"]:
            if not _is_padding_file(file_info):
                continue
            segments = [Path(p.decode("utf-8")) for p in file_info[b"path"]]
            padding_path = base_path.joinpath(*segments)
            padding[padding_path] = int(file_info[b"length"])
    except (KeyError, UnicodeDecodeError):
        return {}

    return padding


def _padding_path_set(padding_files: Mapping[Path, int] | Collection[Path] | None) -> set[Path]:
    """Return a set of padding file paths from various collection types."""

    if padding_files is None:
        return set()
    if isinstance(padding_files, Mapping):
        return set(padding_files.keys())
    return set(padding_files)


def _physical_length(contributions: list[tuple[Path, int]], padding_paths: set[Path]) -> int:
    """Return the number of bytes in contributions that belong to real files."""

    return sum(length for path, length in contributions if path not in padding_paths)


def get_files(info: TorrentInfo, alt_file: BytesOrStrPath | None = None) -> FileList:
    """Get list of files with their sizes from torrent info.

    Args:
        info: The 'info' dictionary from the torrent file
        alt_file: Alternative file or directory path to use instead of the one in the torrent

    Returns:
        List of tuples containing (file_path, file_size)

    Raises:
        TorrentError: If the torrent info is invalid

    """
    files: FileList = []
    try:
        name = info[b"name"].decode("utf-8")
        if b"files" in info:  # Multi-file torrent
            base_path = _coerce_path(alt_file) if alt_file else Path(name)
            for file_info in info[b"files"]:
                segments = [Path(p.decode("utf-8")) for p in file_info[b"path"]]
                file_path = base_path.joinpath(*segments)
                files.append((file_path, int(file_info[b"length"])))
        else:  # Single file torrent
            if alt_file is None:
                file_path = Path(name)
            else:
                alt_path = _coerce_path(alt_file)
                file_path = alt_path / name if alt_path.is_dir() else alt_path
            files.append((file_path, int(info[b"length"])))
        return files
    except (KeyError, UnicodeDecodeError) as e:
        raise TorrentError("Invalid torrent info") from e


def pieces_generator(  # noqa: PLR0912
    info: TorrentInfo, alt_file: BytesOrStrPath | None = None, resolved_files: FileList | None = None, missing_files: set[Path] | None = None
) -> Generator[bytes, None, None]:
    """Generate pieces from downloaded file(s) based on torrent info.

    Args:
        info: The 'info' dictionary from the torrent file
        alt_file: Alternative file or directory path to use instead of the one in the torrent
        resolved_files: Pre-resolved file list (if None, will use get_files to resolve)
        missing_files: Set of file paths that are missing and should be treated as zeros

    Yields:
        bytes: The next piece of data from the file(s)

    Raises:
        TorrentError: If there's an error reading the files

    """
    try:
        piece_length = int(info[b"piece length"])
        piece = bytearray()
        files = resolved_files if resolved_files is not None else get_files(info, alt_file)
        padding_files = _get_padding_files(info, alt_file)
        if missing_files is None:
            missing_files = set()

        for file_path, file_size in files:
            if file_path in padding_files:
                remaining_in_file = padding_files.get(file_path, file_size)
                while remaining_in_file > 0:
                    remaining = piece_length - len(piece)
                    chunk_len = min(remaining, remaining_in_file)
                    piece.extend(b"\x00" * chunk_len)
                    remaining_in_file -= chunk_len

                    if len(piece) == piece_length:
                        yield bytes(piece)
                        piece = bytearray()
                continue

            # Handle missing files by treating them as zero bytes
            if file_path in missing_files:
                remaining_in_file = file_size
                while remaining_in_file > 0:
                    remaining = piece_length - len(piece)
                    chunk_len = min(remaining, remaining_in_file)
                    piece.extend(b"\x00" * chunk_len)
                    remaining_in_file -= chunk_len

                    if len(piece) == piece_length:
                        yield bytes(piece)
                        piece = bytearray()
                continue

            try:
                with file_path.open("rb") as f:
                    while True:
                        remaining = piece_length - len(piece)
                        chunk = f.read(remaining)
                        if not chunk:
                            break

                        piece.extend(chunk)

                        if len(piece) == piece_length:
                            yield bytes(piece)
                            piece = bytearray()
            except OSError as e:
                raise TorrentError(f"Error reading file {file_path}: {e}") from e

        if piece:
            yield bytes(piece)
    except KeyError as e:
        raise TorrentError("Invalid torrent info: missing piece length") from e


def calculate_total_length(info: TorrentInfo) -> int:
    """Calculate the total length of all files in the torrent.

    Args:
        info: The 'info' dictionary from the torrent file

    Returns:
        int: Total size in bytes of all files in the torrent

    Raises:
        TorrentError: If the torrent info is invalid

    """
    try:
        if b"length" in info:
            return int(info[b"length"])
        return sum(int(f[b"length"]) for f in info[b"files"])
    except (KeyError, ValueError) as e:
        raise TorrentError("Invalid torrent info: missing or invalid length") from e


def human_readable_size(size: int) -> str:
    """Convert size in bytes to human readable format.

    Args:
        size: Size in bytes

    Returns:
        str: Human readable size string (e.g., "1.5 MB")

    """
    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size_float) < KB:
            return f"{size_float:3.1f} {unit}"
        size_float /= KB
    return f"{size_float:.1f} PB"


class _Writer(Protocol):
    def write(self, message: str) -> None: ...


class _PlainWriter:
    """Minimal writer proxy to reuse orphan handling without tqdm."""

    def write(self, message: str) -> None:
        print(message)


class _TqdmWriter:
    """Writer adapter for tqdm progress bars."""

    def __init__(self, pbar: tqdm | SimpleProgress) -> None:
        self.pbar = pbar

    def write(self, message: str) -> None:
        self.pbar.write(message)


@dataclass
class VerificationOptions:
    """Options for torrent verification."""

    list_orphans: bool = False
    delete_orphans: bool = False
    continue_on_error: bool = False
    mark_incomplete_prefix: str | None = None
    restore_incomplete: bool = False
    dry_run: bool = False
    no_progress: bool = False
    overwrite_empty_pieces: bool = False


@dataclass
class PieceVerificationOptions:
    """Options for piece verification."""

    continue_on_hash_mismatch: bool = False
    mark_incomplete_prefix: str | None = None
    resolved_files: list[tuple[Path, int]] | None = None
    allow_length_mismatch: bool = False
    missing_files: set[Path] | None = None
    dry_run: bool = False
    overwrite_empty_pieces: bool = False


def verify_torrent(
    torrent_path: str | os.PathLike,
    alt_path: BytesOrStrPath | None = None,
    options: VerificationOptions | None = None,
) -> bool:
    """Verify the integrity of a torrent download.

    Args:
        torrent_path: Path to the .torrent file
        alt_path: Alternative path to the downloaded files
        options: Verification options (if None, uses defaults)

    Returns:
        bool: True if verification succeeded, False otherwise

    """
    if options is None:
        options = VerificationOptions()
    try:
        context = _prepare_verification_context(torrent_path, alt_path)
        orphan_mode = options.list_orphans or options.delete_orphans
        if orphan_mode:
            return _handle_orphaned_files(
                context,
                alt_path,
                _PlainWriter(),
                options=options,
            )

        missing_detected = False

        display_total = context.display_length or context.total_length

        # Create progress bar or simple text output
        if options.no_progress:
            pbar = SimpleProgress(display_total)
        else:
            pbar = tqdm(
                total=display_total,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=f"Verifying {context.display_name[:30]}",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
            )

        with pbar:
            # Resolve file paths to use incomplete.$file variants when available
            resolved_files = _resolve_file_paths(context.files, padding_files=context.padding_files)

            # Check for truly missing files (no incomplete variant either)
            missing_files = _collect_missing_files(context.files, padding_files=context.padding_files)
            if missing_files:
                _report_missing_files(pbar, missing_files)
                if not options.continue_on_error:
                    return False
                missing_detected = True
                pbar.write("\nContinuing despite missing files (--continue-on-error).")

            piece_options = PieceVerificationOptions(
                continue_on_hash_mismatch=options.continue_on_error,
                mark_incomplete_prefix=options.mark_incomplete_prefix,
                resolved_files=resolved_files,
                allow_length_mismatch=options.continue_on_error,
                missing_files=set(missing_files) if missing_files else None,
                dry_run=options.dry_run,
                overwrite_empty_pieces=options.overwrite_empty_pieces,
            )
            hashes_ok = _verify_pieces_with_context(
                context,
                alt_path,
                pbar,
                piece_options=piece_options,
            )

            # Restore incomplete files if verification succeeded and restore option is enabled
            if hashes_ok and options.restore_incomplete:
                writer = _TqdmWriter(pbar)
                _restore_incomplete_files(resolved_files, writer, options.dry_run)

        return hashes_ok and not missing_detected
    except TorrentError as e:
        print(f"Error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"\nError during verification: {e}", file=sys.stderr)
        return False


def _prepare_verification_context(torrent_path: str | os.PathLike, alt_path: BytesOrStrPath | None) -> VerificationContext:
    torrent_file = Path(torrent_path)
    if not torrent_file.is_file():
        raise TorrentError(f"Torrent file not found: {torrent_path}")

    with torrent_file.open("rb") as f:
        metainfo = cast(dict[bytes, Any], bencodepy.decode(f.read()))

    info = cast(TorrentInfo, metainfo[b"info"])
    pieces = info[b"pieces"]
    piece_hashes = [pieces[i : i + SHA1_LENGTH] for i in range(0, len(pieces), SHA1_LENGTH)]
    total_length = calculate_total_length(info)
    name = info[b"name"].decode("utf-8", errors="replace")
    files = get_files(info, alt_path)
    padding_files = _get_padding_files(info, alt_path)
    display_length = max(total_length - sum(padding_files.values()), 0)
    return VerificationContext(
        info=info,
        piece_hashes=piece_hashes,
        total_length=total_length,
        display_length=display_length,
        display_name=name,
        files=files,
        padding_files=padding_files,
    )


def _restore_incomplete_files(resolved_files: list[tuple[Path, int]], writer: _Writer, dry_run: bool = False) -> None:
    """Restore incomplete files to their original names if hashes match."""
    restored_count = 0

    for resolved_path, _ in resolved_files:
        # Check if this is an incomplete file
        if resolved_path.name.startswith("incomplete."):
            # Find the corresponding original file path
            original_name = resolved_path.name[len("incomplete.") :]
            original_path = resolved_path.with_name(original_name)

            # Check if original file is missing and incomplete file exists
            if not original_path.exists() and resolved_path.exists():
                if dry_run:
                    writer.write(f"[DRY RUN] Would restore: {resolved_path} -> {original_path}")
                    restored_count += 1
                else:
                    try:
                        # Rename incomplete file back to original name
                        resolved_path.rename(original_path)
                        writer.write(f"Restored incomplete file: {resolved_path} -> {original_path}")
                        restored_count += 1
                    except OSError as exc:
                        writer.write(f"Failed to restore {resolved_path}: {exc}")

    if restored_count > 0:
        action = "Would restore" if dry_run else "Successfully restored"
        writer.write(f"{action} {restored_count} incomplete file(s)")
    else:
        writer.write("No incomplete files to restore")


def _collect_missing_files(
    files: list[tuple[Path, int]],
    *,
    padding_files: Mapping[Path, int] | Collection[Path] | None = None,
) -> list[Path]:
    """Return a list of missing files, checking for incomplete.$file variants."""
    missing_files = []
    padding = _padding_path_set(padding_files)
    for file_path, _ in files:
        if file_path in padding:
            continue
        if not file_path.exists():
            # Check if incomplete.$file exists instead, but only if parent directory exists
            if file_path.parent.exists():
                incomplete_path = file_path.with_name(f"incomplete.{file_path.name}")
                if incomplete_path.exists():
                    # File exists but is incomplete - report as mismatched, not missing
                    continue
            missing_files.append(file_path)
    return missing_files


def _resolve_file_paths(
    files: list[tuple[Path, int]],
    *,
    padding_files: Mapping[Path, int] | Collection[Path] | None = None,
) -> list[tuple[Path, int]]:
    """Resolve file paths, using incomplete.$file variants when original files are missing."""
    resolved_files = []
    padding = _padding_path_set(padding_files)
    for file_path, file_size in files:
        if file_path in padding:
            resolved_files.append((file_path, file_size))
            continue
        if not file_path.exists():
            # Check if parent directory exists before trying incomplete file
            if file_path.parent.exists():
                # Try to use incomplete.$file variant
                incomplete_path = file_path.with_name(f"incomplete.{file_path.name}")
                if incomplete_path.exists():
                    resolved_files.append((incomplete_path, file_size))
                else:
                    resolved_files.append((file_path, file_size))
            else:
                # Parent directory doesn't exist, keep original path (will be treated as missing)
                resolved_files.append((file_path, file_size))
        else:
            resolved_files.append((file_path, file_size))
    return resolved_files


def _report_missing_files(pbar: Union[tqdm, "SimpleProgress"], missing_files: list[Path]) -> None:
    pbar.write("\nError: The following files are missing:")
    for path in missing_files:
        pbar.write(f"  - {path}")


def _verify_pieces_with_context(  # noqa: PLR0912, PLR0915
    context: VerificationContext,
    alt_path: BytesOrStrPath | None,
    pbar: Union[tqdm, "SimpleProgress"],
    *,
    piece_options: PieceVerificationOptions,
) -> bool:
    # Use resolved files if provided, otherwise use original context files
    files_to_track = piece_options.resolved_files if piece_options.resolved_files is not None else context.files
    tracker = PieceFileTracker(files_to_track)
    padding_paths = _padding_path_set(context.padding_files)
    bytes_processed = 0
    verification_failed = False
    writer = _TqdmWriter(pbar)
    renamed_files: set[Path] = set()
    reported_hash_mismatches: set[Path] = set()  # Track files that already had hash mismatches reported
    piece_length = int(context.info[b"piece length"])
    total_pieces = len(context.piece_hashes)
    piece_data = pieces_generator(context.info, alt_path, resolved_files=files_to_track, missing_files=piece_options.missing_files)

    for i, expected_hash in enumerate(context.piece_hashes):
        expected_piece_len = _piece_length_for_index(piece_length, context.total_length, i, total_pieces)
        piece_contributions = tracker.advance(expected_piece_len)
        piece_paths = [path for path, _ in piece_contributions]
        physical_piece_len = _physical_length(piece_contributions, padding_paths)
        _update_progress_postfix(pbar, piece_paths)

        # Skip verification for pieces that involve missing files when continuing on error
        if piece_options.missing_files and piece_options.continue_on_hash_mismatch and any(path in piece_options.missing_files for path in piece_paths):
            bytes_processed += expected_piece_len
            pbar.update(physical_piece_len)
            continue

        try:
            piece = next(piece_data)
        except StopIteration:
            pbar.write("\nError: Ran out of data while hashing pieces")
            return False

        actual_len = len(piece)
        bytes_processed += actual_len
        pbar.update(physical_piece_len)

        if not piece_options.allow_length_mismatch and actual_len != expected_piece_len:
            pbar.write(
                f"\nError: Piece {i} expected {human_readable_size(expected_piece_len)} but read {human_readable_size(actual_len)}",
            )
            return False

        actual_hash = hashlib.sha1(piece).digest()

        if actual_hash != expected_hash:
            # Check if this piece should be all zeros and overwrite option is enabled
            if piece_options.overwrite_empty_pieces and _is_zero_piece_hash(expected_hash, expected_piece_len):
                # Create a copy of the tracker for this piece to overwrite
                temp_tracker = PieceFileTracker(files_to_track)
                temp_tracker._index = tracker._index
                temp_tracker._offset = tracker._offset

                writer.write(f"\nOverwriting piece {i} with zeros (should be empty but contains data)")
                overwrite_success = _overwrite_piece_with_zeros(temp_tracker, expected_piece_len, writer, piece_options.dry_run)

                if overwrite_success and not piece_options.dry_run:
                    # Re-read the piece after overwriting
                    try:
                        piece_data = pieces_generator(context.info, alt_path, resolved_files=files_to_track, missing_files=piece_options.missing_files)
                        # Skip to the current piece
                        for _ in range(i):
                            next(piece_data)
                        piece = next(piece_data)
                        actual_hash = hashlib.sha1(piece).digest()

                        if actual_hash == expected_hash:
                            writer.write(f"Piece {i} successfully overwritten and verified")
                            bytes_processed += len(piece)
                            pbar.update(physical_piece_len)
                            continue
                        else:
                            writer.write(f"Piece {i} overwrite failed - hash still doesn't match")
                    except (StopIteration, OSError) as e:
                        writer.write(f"Error re-reading piece {i} after overwrite: {e}")

            # Check if we've already reported hash mismatch for any of these files
            files_with_mismatch = [f for f in piece_paths if f not in reported_hash_mismatches]

            if files_with_mismatch:
                report = HashMismatchReport(
                    pbar=writer,
                    piece_index=i,
                    piece_files=files_with_mismatch,  # Only report files not previously reported
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                    mark_incomplete_prefix=piece_options.mark_incomplete_prefix,
                    renamed_files=renamed_files,
                    dry_run=piece_options.dry_run,
                )
                _report_hash_mismatch(report)

                # Mark all files in this piece as having reported hash mismatches
                for file_path in piece_paths:
                    reported_hash_mismatches.add(file_path)

            verification_failed = True
            if not piece_options.continue_on_hash_mismatch:
                return False
            continue

    pbar.set_postfix(file="")

    # Allow length mismatch when continuing despite missing files
    if bytes_processed != context.total_length and not piece_options.allow_length_mismatch:
        pbar.write(
            f"\nError: Expected {human_readable_size(context.total_length)} but processed {human_readable_size(bytes_processed)}",
        )
        return False

    return not verification_failed


def _piece_length_for_index(piece_length: int, total_length: int, piece_index: int, total_pieces: int) -> int:
    if total_pieces == 0:
        return 0
    if piece_index < total_pieces - 1:
        return piece_length
    remainder = total_length % piece_length
    return remainder if remainder else piece_length


def _update_progress_postfix(pbar: tqdm | SimpleProgress, piece_files: list[Path]) -> None:
    """Update the progress bar postfix with the current file name."""
    if not piece_files:
        pbar.set_postfix(file="")
        return

    display_name = piece_files[-1].name
    if len(display_name) > MAX_DISPLAY_FILENAME_LENGTH:
        display_name = f"{display_name[:MAX_DISPLAY_FILENAME_LENGTH]}..."
    pbar.set_postfix(file=display_name)


@dataclass
class HashMismatchReport:
    """Data for hash mismatch reporting."""

    pbar: _Writer
    piece_index: int
    piece_files: list[Path]
    expected_hash: bytes
    actual_hash: bytes
    mark_incomplete_prefix: str | None = None
    renamed_files: set[Path] | None = None
    dry_run: bool = False


def _is_zero_piece_hash(piece_hash: bytes, piece_length: int) -> bool:
    """Check if a piece hash corresponds to all-zero content of the given length."""
    zero_data = b"\x00" * piece_length
    return hashlib.sha1(zero_data).digest() == piece_hash


def _overwrite_piece_with_zeros(
    tracker: PieceFileTracker,
    piece_length: int,
    writer: _Writer,
    dry_run: bool = False,
) -> bool:
    """Overwrite the current piece region in files with zeros.

    Args:
        tracker: PieceFileTracker positioned at the start of the piece
        piece_length: Total length of the piece
        writer: Writer for output messages
        dry_run: If True, only report what would be done

    Returns:
        bool: True if overwrite succeeded, False otherwise
    """
    success = True

    # Save current tracker state
    original_index = tracker._index
    original_offset = tracker._offset

    # Get the contributions for this piece
    contributions = tracker.advance(piece_length)

    # Calculate offsets for each contribution
    current_index = original_index
    current_offset = original_offset

    for file_path, size in contributions:
        if not file_path.exists():
            writer.write(f"Cannot overwrite missing file: {file_path}")
            success = False
            current_index += 1
            current_offset = 0
            continue

        try:
            if dry_run:
                writer.write(f"Would overwrite {size} bytes at offset {current_offset} in {file_path} with zeros")
            else:
                with file_path.open("r+b") as f:
                    f.seek(current_offset)
                    f.write(b"\x00" * size)
                    writer.write(f"Overwrote {size} bytes at offset {current_offset} in {file_path} with zeros")
        except OSError as e:
            writer.write(f"Error overwriting file {file_path}: {e}")
            success = False

        # Move to next file if we consumed the entire remaining portion
        file_size = file_path.stat().st_size
        if current_offset + size >= file_size:
            current_index += 1
            current_offset = 0
        else:
            current_offset += size

    return success


def _report_hash_mismatch(report: HashMismatchReport) -> None:
    """Report a hash mismatch with optional file renaming."""
    report.pbar.write(f"\nError: Hash mismatch at piece {report.piece_index}")
    if not report.piece_files:
        report.pbar.write("No file mapping available for this piece.")
    elif len(report.piece_files) == 1:
        corrupted = report.piece_files[0]
        report.pbar.write(f"Potentially corrupted file: {corrupted}")
        if report.mark_incomplete_prefix:
            _rename_incomplete_file(corrupted, report.mark_incomplete_prefix, report.pbar, report.renamed_files, report.dry_run)
    else:
        report.pbar.write("Piece spans multiple files; potentially corrupted files:")
        for file_path in report.piece_files:
            report.pbar.write(f"  - {file_path}")
        if report.mark_incomplete_prefix:
            for file_path in report.piece_files:
                _rename_incomplete_file(file_path, report.mark_incomplete_prefix, report.pbar, report.renamed_files, report.dry_run)
    report.pbar.write(f"Expected hash: {report.expected_hash.hex()}")
    report.pbar.write(f"Actual hash:   {report.actual_hash.hex()}")


def _rename_incomplete_file(
    file_path: Path,
    prefix: str,
    writer: _Writer,
    renamed_files: set[Path] | None = None,
    dry_run: bool = False,
) -> None:
    if renamed_files is None:
        renamed_files = set()
    if file_path in renamed_files:
        return
    renamed_files.add(file_path)

    if not file_path.exists():
        writer.write(f"Cannot rename missing file: {file_path}")
        return

    if file_path.name.startswith(prefix):
        writer.write(f"File already marked incomplete: {file_path}")
        return

    target = file_path.with_name(f"{prefix}{file_path.name}")
    counter = 1
    while target.exists():
        target = file_path.with_name(f"{prefix}{file_path.name}.{counter}")
        counter += 1

    if dry_run:
        writer.write(f"[DRY RUN] Would rename: {file_path} -> {target}")
    else:
        try:
            file_path.rename(target)
            writer.write(f"Renamed incomplete file to: {target}")
        except OSError as exc:
            writer.write(f"Failed to rename {file_path}: {exc}")


def _handle_orphaned_files(
    context: VerificationContext,
    alt_path: BytesOrStrPath | None,
    writer: _Writer,
    *,
    options: VerificationOptions,
) -> bool:
    if not (options.list_orphans or options.delete_orphans):
        return True
    if b"files" not in context.info:
        writer.write("\nError: Orphan detection is only available for multi-file torrents.")
        return False

    root_path = _resolve_target_root(context.info, alt_path)
    if not root_path.exists():
        writer.write(f"\nWarning: Target folder '{root_path}' does not exist; skipping orphan detection.")
        return False
    if not root_path.is_dir():
        writer.write(f"\nWarning: Target path '{root_path}' is not a directory; skipping orphan detection.")
        return False

    orphans = _identify_orphan_files(root_path, context.files)
    if not orphans:
        writer.write("\nNo orphaned files detected.")
        return True

    if options.list_orphans or options.delete_orphans:
        writer.write("\nOrphaned files detected:")
        for path in orphans:
            writer.write(f"  - {path}")

    if options.delete_orphans:
        deleted = _delete_orphan_files(orphans, writer, dry_run=options.dry_run)
        if options.dry_run:
            writer.write(f"[DRY RUN] Would remove {deleted} orphaned file{'s' if deleted != 1 else ''}.")
        else:
            writer.write(f"Removed {deleted} orphaned file{'s' if deleted != 1 else ''}.")

    return True


def _resolve_target_root(info: TorrentInfo, alt_path: BytesOrStrPath | None) -> Path:
    if alt_path is not None:
        return _coerce_path(alt_path)
    try:
        return Path(info[b"name"].decode("utf-8"))
    except KeyError as e:
        raise TorrentError("Invalid torrent info: missing name") from e


def _identify_orphan_files(root_path: Path, files: FileList) -> list[Path]:
    expected_paths = {_normalize_path(file_path) for file_path, _ in files}
    orphans: list[Path] = []

    for candidate in root_path.rglob("*"):
        if not candidate.is_file():
            continue
        normalized_candidate = _normalize_path(candidate)
        if normalized_candidate not in expected_paths:
            orphans.append(candidate)
    return orphans


def _delete_orphan_files(orphans: list[Path], writer: _Writer, dry_run: bool = False) -> int:
    deleted = 0
    for path in orphans:
        try:
            if dry_run:
                writer.write(f"[DRY RUN] Would delete orphaned file: {path}")
                deleted += 1
            else:
                writer.write(f"Deleting orphaned file: {path}")
                path.unlink()
                deleted += 1
        except OSError as exc:
            writer.write(f"Failed to delete {path}: {exc}")
    return deleted


def _normalize_path(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()
