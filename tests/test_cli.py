"""Test command-line interface for check_by_torrent."""

from pathlib import Path
from unittest.mock import patch

import pytest
from _pytest.capture import CaptureFixture

from check_by_torrent.cli import main


def test_cli_help(capsys: CaptureFixture) -> None:
    """Test the CLI help output."""
    with patch("sys.argv", ["check-by-torrent", "--help"]):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0

    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower()


def test_cli_missing_torrent_file() -> None:
    """Test CLI with missing torrent file."""
    with patch("sys.argv", ["check-by-torrent", "nonexistent.torrent"]):
        with patch("check_by_torrent.cli.verify_torrent") as mock_verify:
            mock_verify.return_value = False
            with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                with pytest.raises(SystemExit) as excinfo:
                    main()
                assert excinfo.value.code == 1
                mock_verify.assert_not_called()
                mock_exit.assert_called_once_with(1)


def test_cli_success() -> None:
    """Test successful CLI execution."""
    with patch("sys.argv", ["check-by-torrent", "test.torrent"]):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent") as mock_verify:
                mock_verify.return_value = True
                with patch("sys.exit", side_effect=SystemExit(0)) as mock_exit:
                    with pytest.raises(SystemExit) as excinfo:
                        main()
                    assert excinfo.value.code == 0
                    mock_verify.assert_called_once_with(Path("test.torrent"), None)
                    mock_exit.assert_called_once_with(0)


def test_cli_with_path() -> None:
    """Test CLI with custom download path."""
    with patch("sys.argv", ["check-by-torrent", "test.torrent", "/custom/path"]):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent") as mock_verify:
                mock_verify.return_value = True
                with patch("sys.exit", side_effect=SystemExit(0)) as mock_exit:
                    with pytest.raises(SystemExit) as excinfo:
                        main()
                    assert excinfo.value.code == 0
                    mock_verify.assert_called_once_with(Path("test.torrent"), Path("/custom/path"))
                    mock_exit.assert_called_once_with(0)
