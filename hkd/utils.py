#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` helper utilities.
"""

def pretty_size(bytes):
    """Get human-readable file sizes.
    simplified version of https://pypi.python.org/pypi/hurry.filesize/
    """
    UNITS_MAPPING = [
        (1<<50, 'PB'),
        (1<<40, 'TB'),
        (1<<30, 'GB'),
        (1<<20, 'MB'),
        (1<<10, 'KB'),
        (1, ('byte', 'bytes')),
    ]
    for factor, suffix in UNITS_MAPPING:
        if bytes < factor:
            continue
        amount = bytes / factor
        if isinstance(suffix, tuple):
            singular, multiple = suffix
            if amount == 1:
                suffix = singular
            else:
                suffix = multiple
        return f"{amount:.2f} {suffix}"