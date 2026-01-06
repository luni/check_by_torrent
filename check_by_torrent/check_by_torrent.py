#!/usr/bin/env python3
"""Check torrent file integrity by verifying piece hashes.

This module provides functionality to verify that the downloaded files of a torrent
match the hashes specified in the .torrent file. It supports both single-file and
multi-file torrents, with progress reporting and detailed error messages.
"""

import hashlib
import os
import sys
from collections.abc import Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias, cast

import bencodepy
from tqdm import tqdm

# Constants
KB = 1024
MB = KB * 1024
GB = MB * 1024
TB = GB * 1024
PB = TB * 1024

SHA1_LENGTH = 20

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
    total_length: int
    display_name: str
    files: FileList


class PieceFileTracker:
    """Track which files contribute to each piece as we iterate."""

    def __init__(self, files: FileList) -> None:
        self._files = files
        self._index = 0
        self._offset = 0

    def advance(self, piece_size: int) -> list[Path]:
        if piece_size == 0 or not self._files:
            return []

        affected: list[Path] = []
        remaining = piece_size
        index = self._index
        offset = self._offset

        while remaining > 0 and index < len(self._files):
            file_path, file_size = self._files[index]
            if not affected or affected[-1] != file_path:
                affected.append(file_path)

            available = file_size - offset
            if remaining < available:
                offset += remaining
                remaining = 0
            else:
                remaining -= available
                index += 1
                offset = 0

        self._index = index
        self._offset = offset
        return affected


class TorrentError(Exception):
    """Base exception for torrent-related errors."""

    pass


def _coerce_path(path_value: BytesOrStrPath) -> Path:
    """Convert bytes/str/PathLike inputs to a Path."""

    if isinstance(path_value, bytes):
        return Path(os.fsdecode(path_value))
    return Path(path_value)


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


def pieces_generator(info: TorrentInfo, alt_file: BytesOrStrPath | None = None) -> Generator[bytes, None, None]:
    """Generate pieces from downloaded file(s) based on torrent info.

    Args:
        info: The 'info' dictionary from the torrent file
        alt_file: Alternative file or directory path to use instead of the one in the torrent

    Yields:
        bytes: The next piece of data from the file(s)

    Raises:
        TorrentError: If there's an error reading the files

    """
    try:
        piece_length = int(info[b"piece length"])
        piece = bytearray()
        files = get_files(info, alt_file)

        for file_path, _ in files:
            if not file_path.is_file():
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


def verify_torrent(
    torrent_path: str | os.PathLike,
    alt_path: BytesOrStrPath | None = None,
    *,
    delete_orphans: bool = False,
) -> bool:
    """Verify the integrity of a torrent download.

    Args:
        torrent_path: Path to the .torrent file
        alt_path: Alternative path to the downloaded files

    Returns:
        bool: True if verification succeeded, False otherwise

    """
    try:
        context = _prepare_verification_context(torrent_path, alt_path)
        with tqdm(
            total=context.total_length,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=f"Verifying {context.display_name[:30]}",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
        ) as pbar:
            missing_files = _collect_missing_files(context.files)
            if missing_files:
                _report_missing_files(pbar, missing_files)
                return False
            if b"files" in context.info:
                _handle_orphaned_files(context, alt_path, pbar, delete_orphans)
            return _verify_pieces_with_context(context, alt_path, pbar)
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
    return VerificationContext(info=info, piece_hashes=piece_hashes, total_length=total_length, display_name=name, files=files)


def _collect_missing_files(files: FileList) -> list[str]:
    return [str(file_path) for file_path, _ in files if not file_path.is_file()]


def _report_missing_files(pbar: tqdm, missing_files: list[str]) -> None:
    pbar.write("\nError: The following files are missing:")
    for path in missing_files:
        pbar.write(f"  - {path}")


def _verify_pieces_with_context(context: VerificationContext, alt_path: BytesOrStrPath | None, pbar: tqdm) -> bool:
    tracker = PieceFileTracker(context.files)
    bytes_processed = 0

    for i, (piece, expected_hash) in enumerate(zip(pieces_generator(context.info, alt_path), context.piece_hashes, strict=False)):
        piece_len = len(piece)
        piece_files = tracker.advance(piece_len)
        _update_progress_postfix(pbar, piece_files)

        actual_hash = hashlib.sha1(piece).digest()
        if actual_hash != expected_hash:
            _report_hash_mismatch(pbar, i, piece_files, expected_hash, actual_hash)
            return False

        bytes_processed += piece_len
        pbar.update(piece_len)

    pbar.set_postfix(file="")

    if bytes_processed != context.total_length:
        pbar.write(
            f"\nError: Expected {human_readable_size(context.total_length)} but processed {human_readable_size(bytes_processed)}",
        )
        return False

    return True


def _update_progress_postfix(pbar: tqdm, piece_files: list[Path]) -> None:
    if not piece_files:
        pbar.set_postfix(file="")
        return

    display_name = piece_files[-1].name
    truncated = (display_name[:SHA1_LENGTH] + "...") if len(display_name) > SHA1_LENGTH else display_name
    pbar.set_postfix(file=truncated)


def _report_hash_mismatch(pbar: tqdm, piece_index: int, piece_files: list[Path], expected_hash: bytes, actual_hash: bytes) -> None:
    pbar.write(f"\nError: Hash mismatch at piece {piece_index}")
    if not piece_files:
        pbar.write("No file mapping available for this piece.")
    elif len(piece_files) == 1:
        pbar.write(f"Potentially corrupted file: {piece_files[0]}")
    else:
        pbar.write("Piece spans multiple files; potentially corrupted files:")
        for file_path in piece_files:
            pbar.write(f"  - {file_path}")
    pbar.write(f"Expected hash: {expected_hash.hex()}")
    pbar.write(f"Actual hash:   {actual_hash.hex()}")


def _handle_orphaned_files(
    context: VerificationContext,
    alt_path: BytesOrStrPath | None,
    pbar: tqdm,
    delete_orphans: bool,
) -> None:
    if b"files" not in context.info:
        return

    root_path = _resolve_target_root(context.info, alt_path)
    if not root_path.exists():
        pbar.write(f"\nWarning: Target folder '{root_path}' does not exist; skipping orphan detection.")
        return
    if not root_path.is_dir():
        pbar.write(f"\nWarning: Target path '{root_path}' is not a directory; skipping orphan detection.")
        return

    orphans = _identify_orphan_files(root_path, context.files)
    if not orphans:
        pbar.write("\nNo orphaned files detected.")
        return

    pbar.write("\nOrphaned files detected:")
    for path in orphans:
        pbar.write(f"  - {path}")

    if delete_orphans:
        deleted = _delete_orphan_files(orphans, pbar)
        pbar.write(f"Removed {deleted} orphaned file{'s' if deleted != 1 else ''}.")


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


def _delete_orphan_files(orphans: list[Path], pbar: tqdm) -> int:
    deleted = 0
    for path in orphans:
        try:
            pbar.write(f"Deleting orphaned file: {path}")
            path.unlink()
            deleted += 1
        except OSError as exc:
            pbar.write(f"Failed to delete {path}: {exc}")
    return deleted


def _normalize_path(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()
