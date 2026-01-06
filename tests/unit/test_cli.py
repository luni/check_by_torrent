"""Unit tests for the CLI entry point."""

import runpy
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
                    mock_verify.assert_called_once_with(
                        Path("test.torrent"),
                        None,
                        list_orphans=False,
                        delete_orphans=False,
                        continue_on_error=False,
                    )
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
                    mock_verify.assert_called_once_with(
                        Path("test.torrent"),
                        Path("/custom/path"),
                        list_orphans=False,
                        delete_orphans=False,
                        continue_on_error=False,
                    )
                    mock_exit.assert_called_once_with(0)


def test_cli_verification_failure(capsys: CaptureFixture) -> None:
    """When verification fails, CLI should write to stderr and exit with status 1."""
    with patch("sys.argv", ["check-by-torrent", "test.torrent"]):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent", return_value=False):
                with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                    with pytest.raises(SystemExit):
                        main()
                    mock_exit.assert_called_once_with(1)

    captured = capsys.readouterr()
    assert "Verification failed" in captured.err


def test_cli_unexpected_exception(capsys: CaptureFixture) -> None:
    """Unexpected errors from verify_torrent should be surfaced and exit with status 1."""
    with patch("sys.argv", ["check-by-torrent", "test.torrent"]):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent", side_effect=RuntimeError("boom")):
                with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                    with pytest.raises(SystemExit):
                        main()
                    mock_exit.assert_called_once_with(1)

    captured = capsys.readouterr()
    assert "Error: boom" in captured.err


def test_cli_delete_orphans_implies_list(capsys: CaptureFixture) -> None:
    """--delete-orphans should imply listing and pass both flags to verifier."""
    with patch(
        "sys.argv",
        ["check-by-torrent", "test.torrent", "--delete-orphans"],
    ):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent") as mock_verify:
                mock_verify.return_value = True
                with patch("sys.exit", side_effect=SystemExit(0)):
                    with pytest.raises(SystemExit):
                        main()

    captured = capsys.readouterr()
    assert "implies --list-orphans" in captured.err
    mock_verify.assert_called_once_with(
        Path("test.torrent"),
        None,
        list_orphans=True,
        delete_orphans=True,
        continue_on_error=False,
    )


def test_cli_continue_on_error_flag() -> None:
    """--continue-on-error should forward flag to verifier."""
    with patch(
        "sys.argv",
        ["check-by-torrent", "test.torrent", "--continue-on-error"],
    ):
        with patch("check_by_torrent.cli.Path.exists", return_value=True):
            with patch("check_by_torrent.cli.verify_torrent") as mock_verify:
                mock_verify.return_value = True
                with patch("sys.exit", side_effect=SystemExit(0)):
                    with pytest.raises(SystemExit):
                        main()

    mock_verify.assert_called_once_with(
        Path("test.torrent"),
        None,
        list_orphans=False,
        delete_orphans=False,
        continue_on_error=True,
    )


def test_module_entrypoint_invokes_cli_main(monkeypatch: pytest.MonkeyPatch) -> None:
    """Running `python -m check_by_torrent` should delegate to the CLI main."""
    called = False

    def fake_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr("check_by_torrent.cli.main", fake_main)
    runpy.run_module("check_by_torrent", run_name="__main__")
    assert called is True
