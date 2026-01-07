#!/usr/bin/env python3
"""Command-line interface for check-by-torrent."""

# Standard library imports
import argparse
import sys
from pathlib import Path

# Local application imports
from check_by_torrent.check_by_torrent import VerificationOptions, verify_torrent


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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually renaming files",
    )
    parser.add_argument(
        "--restore-incomplete",
        action="store_true",
        help="Automatically restore incomplete.$file to $file if hashes match",
    )
    parser.add_argument(
        "--mark-incomplete",
        nargs="?",
        const="incomplete.",
        help="Rename corrupted files with prefix (default: incomplete.$file)",
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

        orphan_mode = args.list_orphans or args.delete_orphans
        options = VerificationOptions(
            list_orphans=args.list_orphans,
            delete_orphans=args.delete_orphans,
            continue_on_error=args.continue_on_error,
            mark_incomplete_prefix=args.mark_incomplete,
            restore_incomplete=args.restore_incomplete,
            dry_run=args.dry_run,
        )
        success = verify_torrent(
            torrent_path,
            path,
            options=options,
        )
        if success:
            if not orphan_mode:
                print("Verification successful")
            sys.exit(0)

        print("Verification failed", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
