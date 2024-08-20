#!/usr/bin/env python3

"""Test utility/helper types.
"""

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

import io


def pad(by, n, pad_chr = b"\0"):
    """Fill the remaning space of a bytes array with zeros."""
    by += pad_chr * (n - len(by))
    return by


MOCK_HDR = pad(
    b"KDUMP   "  # signature
    + b"\x01\x02\x03\x04"  # header_version
    + pad(b"sys", 65)  # system
    + pad(b"node", 65)  # node
    + pad(b"release", 65)  # release
    + pad(b"#version-443", 65)  # version
    + pad(b"machine", 65)  # machine
    + pad(b"domain", 65)  # domain
    + b"\x02" * 6  # padding
    + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # timestamp_sec
    + b"\x02\x00\x00\x00\x00\x00\x00\x00"  # timestamp_usec
    + b"\x03\x00\x00\x00"  # status
    + b"\x00\x10\x00\x00",  # block_size
    4096,
) + pad(b"", 4096)


def assert_has_no_such_calls(self, *args, **kwargs):
    """Check if a mock is not called"""
    for call in list(*args):
        try:
            self.assert_has_calls([call])
        except AssertionError:
            continue
        raise AssertionError(
            # pylint: disable-next=protected-access
            f"Expected {self._format_mock_call_signature(args, kwargs)} to not have been called."
        )


class IOAdapter(io.BytesIO):
    """Mock BytesIO class."""
    def write(self, value):
        if isinstance(value, str):
            return super().write(value.encode())
        return super().write(value)

    def peek(self, size=1):
        """Read without advancing."""
        if self.closed is True:
            raise ValueError("peek on closed file")
        if size < 0:
            return self.getbuffer()[self.tell() :]
        return self.getbuffer()[self.tell() : self.tell() + size]

    def __call__(self, *args, **kwargs):
        return self


class MockFileObject(IOAdapter):
    """Mock file object."""
    def __init__(self, file_bytes, name):
        super().__init__(file_bytes)
        self.name = name


class MockFileCtx:
    """Poor man's mock file."""

    def init_ctx(self):
        """context initializer."""
        self.io = MockFileObject(self.bytes, self.name)
        self.io.name = self.name

    def __init__(self, file_bytes, name) -> None:
        self.bytes = file_bytes
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
        """no-op"""


class MockStatObj:
    """Poor man's stat object."""
    def __init__(self, name, mock_data) -> None:
        self.name = name
        self.mock_data = mock_data

    @property
    def st_atime(self):
        """mock st_atime"""
        return self.mock_data[self.name]["atime"]

    @property
    def st_size(self):
        """mock st_size"""
        return self.mock_data[self.name]["size"]

    @property
    def st_mode(self):
        """mock st_mode"""
        return 16877
