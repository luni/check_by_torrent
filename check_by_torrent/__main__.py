#!/usr/bin/env python3
"""Command-line entry point for the check-by-torrent package.

This module provides a command-line interface for checking the integrity
of downloaded torrent files against their .torrent metadata.
"""

from .cli import main

if __name__ == "__main__":
    main()
