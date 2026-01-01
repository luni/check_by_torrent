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


def verify_torrent(torrent_path: str | os.PathLike, alt_path: BytesOrStrPath | None = None) -> bool:
    """Verify the integrity of a torrent download.

    Args:
        torrent_path: Path to the .torrent file
        alt_path: Alternative path to the downloaded files

    Returns:
        bool: True if verification succeeded, False otherwise

    """
    try:
        # Read and parse the torrent file
        torrent_file = Path(torrent_path)
        if not torrent_file.is_file():
            print(f"Error: Torrent file not found: {torrent_path}", file=sys.stderr)
            return False

        with torrent_file.open("rb") as f:
            metainfo = cast(dict[bytes, Any], bencodepy.decode(f.read()))

        info = cast(TorrentInfo, metainfo[b"info"])
        pieces = info[b"pieces"]
        piece_hashes = [pieces[i : i + SHA1_LENGTH] for i in range(0, len(pieces), SHA1_LENGTH)]
        total_length = calculate_total_length(info)
        name = info[b"name"].decode("utf-8", errors="replace")
        files = get_files(info, alt_path)

        # Initialize progress bar
        pbar = tqdm(
            total=total_length,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=f"Verifying {name[:30]}",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]",
        )

        current_file = None
        bytes_processed = 0
        missing_files = []

        # Check for missing files first
        for file_path, _file_size in files:
            if not file_path.is_file():
                missing_files.append(str(file_path))

        if missing_files:
            pbar.write("\nError: The following files are missing:")
            for f in missing_files:
                pbar.write(f"  - {f}")
            return False

        # Track current file for progress display
        file_index = 0
        current_file = files[file_index][0] if files else None
        current_file_end = files[file_index][1] if files else 0
        current_file_pos = 0

        # Verify each piece
        for i, (piece, expected_hash) in enumerate(zip(pieces_generator(info, alt_path), piece_hashes, strict=False)):
            # Update current file for progress display
            piece_len = len(piece)
            current_file_pos += piece_len

            # Move to next file if we've passed the current one
            while file_index < len(files) - 1 and current_file_pos >= current_file_end:
                file_index += 1
                current_file = files[file_index][0]
                current_file_pos = 0
                current_file_end = files[file_index][1]

            # Update progress bar with current file
            if current_file:
                pbar.set_postfix(file=current_file.name[:SHA1_LENGTH] + "..." if len(current_file.name) > SHA1_LENGTH else current_file.name)

            actual_hash = hashlib.sha1(piece).digest()
            if actual_hash != expected_hash:
                pbar.write(f"\nError: Hash mismatch at piece {i}")
                if current_file:
                    pbar.write(f"Current file: {current_file}")
                pbar.write(f"Expected hash: {expected_hash.hex()}")
                pbar.write(f"Actual hash:   {actual_hash.hex()}")
                return False

            bytes_processed += piece_len
            pbar.update(piece_len)

        pbar.set_postfix(file="")
        pbar.close()

        # Verify we've checked all pieces
        if bytes_processed != total_length:
            pbar.write(f"\nError: Expected {human_readable_size(total_length)} but processed {human_readable_size(bytes_processed)}")
            return False

        return True

    except Exception as e:
        print(f"\nError during verification: {e}", file=sys.stderr)
        return False
