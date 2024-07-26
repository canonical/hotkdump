#!/usr/bin/env python3

"""
Test utility/helper types.
"""

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

import io


def fill_zeros(by, n):
    by += b"\0" * (n - len(by))
    return by


def assert_has_no_such_calls(self, *args, **kwargs):
    for call in list(*args):
        try:
            self.assert_has_calls([call])
        except AssertionError:
            continue
        raise Exception(
            f"Expected {self._format_mock_call_signature(args, kwargs)} to not have been called."
        )


class io_adapter(io.BytesIO):
    def write(self, value):
        if isinstance(value, str):
            return super().write(value.encode())
        return super().write(value)

    def peek(self, size=1):
        if self.closed:
            raise ValueError("peek on closed file")
        if size < 0:
            return self.getbuffer()[self.tell() :]
        return self.getbuffer()[self.tell() : self.tell() + size]

    def __call__(self, *args, **kwargs):
        return self


class mock_file_object(io_adapter):
    def __init__(self, bytes, name):
        super().__init__(bytes)
        self.name = name


class mock_file_ctx:
    """Poor man's mock file."""

    def init_ctx(self):
        self.io = mock_file_object(self.bytes, self.name)
        self.io.name = self.name

    def __init__(self, bytes, name) -> None:
        self.bytes = bytes
        self.name = name
        self.io = None

    def __enter__(self):
        self.init_ctx()
        return self.io

    def __exit__(self, *args, **kwargs):
        self.io = None

    def __call__(self, *args, **kwargs):
        return self

    def write(self, *args, **kwargs):
        pass


class mock_stat_obj:
    def __init__(self, name, mock_data) -> None:
        self.name = name
        self.mock_data = mock_data

    @property
    def st_atime(self):
        return self.mock_data[self.name]["atime"]

    @property
    def st_size(self):
        return self.mock_data[self.name]["size"]

    @property
    def st_mode(self):
        return 16877
