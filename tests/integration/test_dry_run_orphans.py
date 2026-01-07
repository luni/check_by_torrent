from pathlib import Path

import pytest

from check_by_torrent.check_by_torrent import VerificationOptions, verify_torrent


def test_orphan_deletion_ignores_dry_run(multi_file_torrent: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """
    Reproduce issue: --dry-run should prevent orphan deletion, but currently does not.
    """
    torrent_path, download_dir = multi_file_torrent
    orphan = download_dir / "should_survive.bin"
    orphan.write_bytes(b"I should not be deleted")

    # Run with delete_orphans=True AND dry_run=True
    options = VerificationOptions(list_orphans=True, delete_orphans=True, dry_run=True)

    # We expect verify_torrent to return True (it usually returns True for orphan operations if successful)
    verify_torrent(torrent_path, download_dir, options=options)

    # CHECK: Did it survive?
    if not orphan.exists():
        pytest.fail("Orphan file was deleted despite dry_run=True!")

    # Also check output for dry run message (optional, but good practice)
    captured = capsys.readouterr()
    assert "[DRY RUN]" in captured.out or "[DRY RUN]" in captured.err
