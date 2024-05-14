#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` CLI entry point.
"""

import sys,os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),os.pardir))

from hotkdump.core.hotkdump_impl import main

if __name__ == "__main__":
    main()
