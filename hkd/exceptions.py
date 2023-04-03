#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` exception types.
"""

import logging


class ExceptionWithLog(Exception):

    def __init__(self, msg) -> None:
        logging.error(msg)
        super().__init__(msg)
