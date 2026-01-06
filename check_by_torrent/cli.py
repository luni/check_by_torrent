#!/usr/bin/env python3
"""Command-line interface for check-by-torrent."""

# Standard library imports
import argparse
import sys
from pathlib import Path

# Local application imports
from .check_by_torrent import verify_torrent


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=("Verify the integrity of downloaded torrent files against their .torrent metadata"))
    parser.add_argument("torrent_file", help="Path to the .torrent file")
    parser.add_argument("path", nargs="?", help="Path to the downloaded files (default: same as torrent file directory)")
    parser.add_argument(
        "--list-orphans",
        action="store_true",
        help="List files in the target folder that are not part of the torrent (multi-file torrents only)",
    )
    parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="Delete files in the target folder that are not part of the torrent (multi-file torrents only)",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep hashing even if a piece hash mismatch is encountered",
    )
    return parser.parse_args()


def main() -> None:
    """Parse programm arguments and run corresponding action."""
    try:
        args = parse_args()
        torrent_path = Path(args.torrent_file)
        path = Path(args.path) if args.path else None

        if not torrent_path.exists():
            print(f"Error: Torrent file '{torrent_path}' not found", file=sys.stderr)
            sys.exit(1)

        if args.delete_orphans and not args.list_orphans:
            print("Warning: --delete-orphans implies --list-orphans", file=sys.stderr)
            args.list_orphans = True

        if verify_torrent(
            torrent_path,
            path,
            list_orphans=args.list_orphans,
            delete_orphans=args.delete_orphans,
            continue_on_error=args.continue_on_error,
        ):
            print("Verification successful")
            sys.exit(0)

        print("Verification failed", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
