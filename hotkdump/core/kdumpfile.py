#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""`kdump` file header parser type impl.
reference:
https://github.com/makedumpfile/makedumpfile/blob/bad2a7c4fa75d37a41578441468584963028bdda/IMPLEMENTATION#L11
https://github.com/makedumpfile/makedumpfile/blob/bad2a7c4fa75d37a41578441468584963028bdda/diskdump_mod.h#L44
https://github.com/makedumpfile/makedumpfile/blob/bad2a7c4fa75d37a41578441468584963028bdda/makedumpfile.c#L10947
https://github.com/makedumpfile/makedumpfile/blob/bad2a7c4fa75d37a41578441468584963028bdda/makedumpfile.c#L10933
"""

import os
import logging
from dataclasses import dataclass, field
from hotkdump.core.exceptions import NotAKernelCrashDumpException


class BinaryFileReader:
    """Utility class for reading stuff from binary files."""

    @staticmethod
    def file_size(f):
        """Get a file's size in bytes."""
        cur = f.tell()
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(cur, os.SEEK_SET)
        return size

    @staticmethod
    def seek_to_first_non_nul(f):
        """Seek file offset to the first non-NUL character
        starting from the current offset.
        Args:
            f(file): File to seek
        """

        char_nul = b"\x00"

        pos = f.tell()
        while f.read(1) == char_nul:
            pos = f.tell()
        f.seek(pos)

    @staticmethod
    def read_int32(f, off=None):
        """Read a 4-byte integer from given file."""
        if off:
            f.seek(off, os.SEEK_SET)
        return int.from_bytes(f.read(4), byteorder="little")

    @staticmethod
    def read_int64(f, off=None):
        """Read a 8-byte integer from given file."""
        if off:
            f.seek(off, os.SEEK_SET)
        return int.from_bytes(f.read(8), byteorder="little")

    @staticmethod
    def read_str(f, ln):
        """Read a fixed length string from given file."""
        return f.read(ln).decode("ascii")

    @staticmethod
    def read_cstr(f):
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
            if b in {b"", b"\x00"}:
                BinaryFileReader.seek_to_first_non_nul(f)
                return str("".join(buf))

            buf += b.decode("ascii")


@dataclass()
class NewUtsName:
    """new_utsname struct"""

    system: str
    node: str
    release: str
    version: str
    machine: str
    domain: str
    normalized_version: str = field(init=False)

    def __post_init__(self):
        self.normalized_version = self.version.split("-", maxsplit=1)[0].lstrip("#")


@dataclass()
# pylint: disable-next=too-many-instance-attributes
class DiskDumpHeader:
    """disk_dump_header struct"""

    signature: str
    header_version: int
    utsname: NewUtsName
    timestamp_sec: int
    timestamp_usec: int
    status: int
    block_size: int
    sizeof: int = 464

    @staticmethod
    def from_fd(fd):
        """Read a DiskDumpHeader from given file."""

        # Interestingly, some of the crash dump files have corrupt utsname
        # where first few characters of system is absent(x instead of Linux).
        # We should be reading 6*65 bytes of text, but in order to accommodate
        # such oddities, we rely on read_cstr and manual seeking to the
        # timestamp field's offset.
        sizeof_signature = 8
        sizeof_header_version = 4
        # 6 bytes padding at the end
        sizeof_new_utsname = (65 * 6) + 6
        timestamp_offset = fd.tell() + (
            sizeof_signature + sizeof_header_version + sizeof_new_utsname
        )
        return DiskDumpHeader(
            signature=BinaryFileReader.read_str(fd, 8),
            header_version=int.from_bytes(fd.read(4), byteorder="little"),
            utsname=NewUtsName(
                system=BinaryFileReader.read_cstr(fd),
                node=BinaryFileReader.read_cstr(fd),
                release=BinaryFileReader.read_cstr(fd),
                version=BinaryFileReader.read_cstr(fd),
                machine=BinaryFileReader.read_cstr(fd),
                domain=BinaryFileReader.read_cstr(fd),
            ),
            timestamp_sec=BinaryFileReader.read_int64(fd, timestamp_offset),
            timestamp_usec=BinaryFileReader.read_int64(fd),
            status=BinaryFileReader.read_int32(fd),
            block_size=BinaryFileReader.read_int32(fd),
        )


@dataclass()
# pylint: disable-next=too-many-instance-attributes
class KdumpSubHeader:
    """kdump_sub_header struct"""

    phys_base: int
    dump_level: int
    split: int
    start_pfn: int
    end_pfn: int
    offset_vmcoreinfo: int
    size_vmcoreinfo: int
    offset_note: int
    size_note: int
    offset_eraseinfo: int
    size_eraseinfo: int
    start_pfn_64: int
    end_pfn_64: int
    max_mapnr_64: int

    @staticmethod
    def from_fd(fd, block_size):
        """Read a KDumpSubHeader from given file."""

        disk_dump_header_blocks = 1
        offset = disk_dump_header_blocks * block_size
        fd.seek(offset, os.SEEK_SET)
        return KdumpSubHeader(
            phys_base=BinaryFileReader.read_int64(fd),
            dump_level=BinaryFileReader.read_int32(fd),
            split=BinaryFileReader.read_int32(fd),
            start_pfn=BinaryFileReader.read_int64(fd),
            end_pfn=BinaryFileReader.read_int64(fd),
            offset_vmcoreinfo=BinaryFileReader.read_int64(fd),
            size_vmcoreinfo=BinaryFileReader.read_int64(fd),
            offset_note=BinaryFileReader.read_int64(fd),
            size_note=BinaryFileReader.read_int64(fd),
            offset_eraseinfo=BinaryFileReader.read_int64(fd),
            size_eraseinfo=BinaryFileReader.read_int64(fd),
            start_pfn_64=BinaryFileReader.read_int64(fd),
            end_pfn_64=BinaryFileReader.read_int64(fd),
            max_mapnr_64=BinaryFileReader.read_int64(fd),
        )


class VMCoreInfo:
    """Class for parsing VMCoreInfo section text into a dict."""
    def __init__(self, raw):
        self.data = {}
        for line in raw.split("\n"):
            if not line or str.isspace(line):
                continue
            k, v = line.split("=")
            self.data[k.strip()] = v.strip()

    @staticmethod
    def from_fd(fd, vmcoreinfo_offset, vmcoreinfo_size):
        """Read VMCoreInfo from given file at offset with size."""

        fd.seek(vmcoreinfo_offset, os.SEEK_SET)
        return VMCoreInfo(BinaryFileReader.read_str(fd, vmcoreinfo_size))

    def get(self, key):
        """Retrieve a VMCoreInfo key's value."""
        return self.data[key]

    def __repr__(self):
        return str(self.data)


class KdumpFile:
    """Helper class for parsing headers from kernel crash
    dumps generated with kdump.
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

        with open(kdump_file_path, "rb") as fd:

            # Let's be more forgiving about locating
            # the KDUMP signature:
            blob = fd.read(1024 * 8)
            expected_magic = b"KDUMP   "
            offset = blob.find(expected_magic)
            if offset == -1:
                raise NotAKernelCrashDumpException(
                    f"{kdump_file_path} is not a kernel crash dump file"
                )

            # Seek to the KDUMP signature offset
            fd.seek(offset, os.SEEK_SET)
            self._ddhdr = DiskDumpHeader.from_fd(fd)
            self._ksubhdr = KdumpSubHeader.from_fd(fd, self.ddhdr.block_size)
            self._vmcoreinfo = VMCoreInfo.from_fd(
                fd, self.ksubhdr.offset_vmcoreinfo, self.ksubhdr.size_vmcoreinfo
            )

            logging.debug("kdump_hdr: %s", str(self.ddhdr))
            logging.debug("kdump_subhdr: %s", str(self.ddhdr))
            logging.debug("vmcore-info: %s", str(self.vmcoreinfo))

    @property
    def ddhdr(self):
        """Disk dump header."""
        return self._ddhdr

    @property
    def ksubhdr(self):
        """Kdump sub heeader."""
        return self._ksubhdr

    @property
    def vmcoreinfo(self):
        """VMCOREINFO section."""
        return self._vmcoreinfo

    def __str__(self) -> str:

        return " | ".join(
            # Get all attributes, filter out the built-in ones
            # and stringify the rest in "name:value" format
            [
                f" {v}:{str(getattr(self, v))}"
                for v in [
                    x
                    for x in dir(self)
                    if not x.startswith("___") and not callable(getattr(self, x))
                ]
            ]
        )
