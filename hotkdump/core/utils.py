#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""`hotkdump` helper utilities.
"""

import os
import tempfile
import contextlib

def pretty_size(amount_bytes):
    """Get human-readable file sizes.
    simplified version of https://pypi.python.org/pypi/hurry.filesize/
    """
    units_mapping = [
        (1<<50, 'PB'),
        (1<<40, 'TB'),
        (1<<30, 'GB'),
        (1<<20, 'MB'),
        (1<<10, 'KB'),
        (1, ('byte', 'bytes')),
    ]
    for factor, suffix in units_mapping:
        if amount_bytes < factor:
            continue
        amount = amount_bytes / factor
        if isinstance(suffix, tuple):
            singular, multiple = suffix
            if amount == 1:
                suffix = singular
            else:
                suffix = multiple
        return f"{amount:.2f} {suffix}"

def mktemppath(*args):
    """Create a path to the system's temp directory."""
    return os.path.join(tempfile.gettempdir(), *args)

@contextlib.contextmanager
def switch_cwd(wd):
    """Save current working directory and temporarily
    switch current working directory to `wd`. The working
    directory will be restored back to the saved value when
    context manager exits.

    Args:
        wd (str): new working directory
    """
    curdir = os.getcwd()
    try:
        yield os.chdir(wd)
    finally:
        os.chdir(curdir)
