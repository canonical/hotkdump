#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` exception types.
"""

import logging


class ExceptionWithLog(Exception):
    """Exception type with automatic logging."""
    def __init__(self, msg) -> None:
        logging.error("EXCEPTION: %s", msg)
        super().__init__(msg)

class NotAKernelCrashDumpException(ExceptionWithLog):
    """Exception thrown when a file given to kdump_file_header
    is not recognized as a crash dump file."""