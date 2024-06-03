#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""`kdump` file header parser type impl.
"""

import os
import logging
from hotkdump.core.exceptions import NotAKernelCrashDumpException


class KdumpFileHeader():
    """Helper class for reading kdump file
    headers
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self, kdump_file_path) -> None:
        """Parse kdump file header and expose
        them as member variables

        Args:
            kdump_file_path (str): The kdump file path

        Raises:
            Exception: If the kdump_file_path is not recognized as a kdump file
        """

        with open(kdump_file_path, 'rb') as fd:

            # Let's be more forgiving about locating
            # the KDUMP signature:
            blob = fd.read(1024 * 8)
            expected_magic = b'KDUMP   '
            offset = blob.find(expected_magic)
            if offset == -1:
                raise NotAKernelCrashDumpException(
                    f"{kdump_file_path} is not a kernel crash dump file")

            # Skip the magic
            fd.seek(offset + len(expected_magic), os.SEEK_SET)

            version = int.from_bytes(fd.read(4), byteorder='little')
            self.kdump_version = version
            self.system = self.readcstr(fd)
            self.node = self.readcstr(fd)
            self.release = self.readcstr(fd)
            self.version = self.readcstr(fd)
            self.machine = self.readcstr(fd)
            self.domain = self.readcstr(fd)
            self.normalized_version = self.version.split("-", maxsplit=1)[0].lstrip("#")
            logging.debug("kdump_hdr: %s", str(self))


    @staticmethod
    def seek_to_first_non_nul(f):
        """Seek file offset to the first non-NUL character
        starting from the current offset.
        Args:
            f(file): File to seek
        """

        char_nul = b'\x00'

        pos = f.tell()
        while f.read(1) == char_nul:
            pos = f.tell()
        f.seek(pos)

    @staticmethod
    def readcstr(f):
        """Read a C-style NUL terminated string
        from a consecutive list of strings, where
        length of the individual strings are unknown.

        Args:
            f (file): File to read from

        Returns:
            str: The read string
        """
        buf = str()

        while True:
            b = f.read(1)
            if b in {b'', b'\x00'}:
                KdumpFileHeader.seek_to_first_non_nul(f)
                return str(''.join(buf))

            buf += b.decode('ascii')

    def __str__(self) -> str:

        return " | ".join(
            # Get all attributes, filter out the built-in ones
            # and stringify the rest in "name:value" format
            [f" {v}:{str(getattr(self, v))}" for v in
                [x for x in dir(self) if not x.startswith("___") and not callable(getattr(self,x))]]
        )
