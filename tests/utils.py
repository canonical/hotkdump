#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
Test utility/helper types.
"""

import io

def assert_has_no_such_calls(self, *args, **kwargs):
    for call in list(*args):
        try:
            self.assert_has_calls([call])
        except AssertionError:
            continue
        raise Exception('Expected %s to not have been called.' %
                        self._format_mock_call_signature(args, kwargs))

class mock_file:
    """Poor man's mock file.
    """

    def init_ctx(self):
        class io_adapter(io.BytesIO):
            def write(self, value):
                if isinstance(value, str):
                    return super().write(value.encode())
                return super().write(value)

        self.io = io_adapter(self.bytes)
        self.io.name = self.name

    def __init__(self, bytes, name) -> None:
        self.bytes = bytes
        self.name = name

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