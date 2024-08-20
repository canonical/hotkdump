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
import struct
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
    def read_int(f, fmt, off=None):
        """Read an integer value from binary file stream."""

        if off:
            f.seek(off, os.SEEK_SET)
        byte_cnt = struct.calcsize(fmt)
        raw_bytes = f.read(byte_cnt)

        if not raw_bytes or len(raw_bytes) != byte_cnt:
            return None

        return struct.unpack(fmt, raw_bytes)[0]

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


# TO-DO: Switch to struct.pack / struct.unpack?


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
            timestamp_sec=BinaryFileReader.read_int(fd, "<q", timestamp_offset),
            timestamp_usec=BinaryFileReader.read_int(fd, "<q"),
            status=BinaryFileReader.read_int(fd, "<i"),
            block_size=BinaryFileReader.read_int(fd, "<i"),
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
    def from_fd(fd):
        """Read a KDumpSubHeader from given file."""
        return KdumpSubHeader(
            phys_base=BinaryFileReader.read_int(fd, "<q"),
            dump_level=BinaryFileReader.read_int(fd, "<i"),
            split=BinaryFileReader.read_int(fd, "<i"),
            start_pfn=BinaryFileReader.read_int(fd, "<q"),
            end_pfn=BinaryFileReader.read_int(fd, "<q"),
            offset_vmcoreinfo=BinaryFileReader.read_int(fd, "<q"),
            size_vmcoreinfo=BinaryFileReader.read_int(fd, "<q"),
            offset_note=BinaryFileReader.read_int(fd, "<q"),
            size_note=BinaryFileReader.read_int(fd, "<q"),
            offset_eraseinfo=BinaryFileReader.read_int(fd, "<q"),
            size_eraseinfo=BinaryFileReader.read_int(fd, "<q"),
            start_pfn_64=BinaryFileReader.read_int(fd, "<q"),
            end_pfn_64=BinaryFileReader.read_int(fd, "<q"),
            max_mapnr_64=BinaryFileReader.read_int(fd, "<q"),
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

    def get(self, key, default=None):
        """Retrieve a VMCoreInfo key's value."""
        if key in self.data:
            return self.data[key]
        return default

    def __repr__(self):
        return str(self.data)


@dataclass
class MakeDumpFileHeader:
    """makedumpfile_header struct."""

    signature: str
    vtype: int
    version: int


@dataclass
class MakeDumpFileDataHeader:
    """makedumpfile_data_header struct."""

    self_offset: int
    offset: int
    buf_size: int
    sizeof: int = 16

    @staticmethod
    def from_fd(fd):
        """Read a MakeDumpFileDataHeader from given file."""
        return MakeDumpFileDataHeader(
            self_offset=fd.tell(),
            offset=BinaryFileReader.read_int(fd, ">q"),
            buf_size=BinaryFileReader.read_int(fd, ">q"),
        )

    def next(self, fd):
        """Seek the given file's offset to the next makedumpfile_header"""

        fd.seek(self.self_offset + self.sizeof + self.buf_size, os.SEEK_SET)
        return MakeDumpFileDataHeader.from_fd(fd)

    def in_range(self, offset):
        """Check whether given offset is in range of this block or not."""
        return self.offset <= offset < (self.offset + self.buf_size)

    @property
    def data_offset(self):
        """Offset to the beginning of the data."""
        return self.self_offset + self.sizeof

    def __bool__(self):
        """Check whether this header is valid."""
        return (self.offset is not None and self.offset >= 0) and (
            self.buf_size is not None and self.buf_size >= 0
        )


class KdumpFile:
    """Helper class for parsing headers from kernel crash
    dumps generated with kdump.
    """

    @classmethod
    def is_flattened_kdump_file(cls, fd):
        """Check whether file is in makedumpfile format (flat)"""
        makedumpfile_signature = b"makedumpfile\0\0\0\0"
        signature = fd.peek(len(makedumpfile_signature))[
            0 : len(makedumpfile_signature)
        ]
        return signature == makedumpfile_signature

    @classmethod
    def is_regular_kdump_file(cls, fd):
        """Check whether file is in regular kdump format."""
        kdump_hdr_signature = b"KDUMP   "

        # We're using peek() in order to avoid progressing the position
        magic = fd.peek(len(kdump_hdr_signature))[0 : len(kdump_hdr_signature)]
        return magic == kdump_hdr_signature

    def __init__(self, kdump_file_path) -> None:
        """Parse kdump file header and expose
        them as member variables

        Args:
            kdump_file_path (str): The kdump file path

        Raises:
            Exception: If the kdump_file_path is not recognized as a kdump file
        """

        self._ddhdr = None
        self._ksubhdr = None
        self._vmcoreinfo = None

        with open(kdump_file_path, "rb") as fd:
            # First check if it's flattened format
            # https://github.com/makedumpfile/makedumpfile/blob/bad2a7c4fa75d37a41578441468584963028bdda/IMPLEMENTATION#L285
            if self.is_flattened_kdump_file(fd):
                logging.debug("the file is in flattened format")
                # Skip the first 4096 bytes. It contains the makedumpfile_header
                # and it's always 4096 bytes in size.
                fd.seek(4096)
                self.parse_flattened(fd)
            elif self.is_regular_kdump_file(fd):
                self.parse_compressed(fd)
            else:
                raise NotAKernelCrashDumpException(
                    f"{kdump_file_path} is not a kernel crash dump file"
                )

            logging.debug("kdump_hdr: %s", str(self.ddhdr))
            logging.debug("kdump_subhdr: %s", str(self.ksubhdr))
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

    def parse_flattened(self, fd):
        """Parse the diskdumpfile, ksubhdr and vmcoreinfo from a
        flattened makedumpfile."""

        # Flattened header format consists of list of data chunks starting with
        # makediskdumpfile_data_header, followed by (size) bytes of data. This
        # format allows splitting a contiguous blob of N bytes to M chunks in
        # arbitrary order. The original offset of each chunk is recorded into
        # the makediskdumpfile_data_header, so reading code can reconstruct
        # the original file. This format is developed to make it possible to
        # be able to write a file that requires random access writing to a
        # remote endpoint via SSH, etc.
        # The format resembles the bittorrent protocol.

        # The first header is guaranteed to be disk_dump_header.
        mdhdr = MakeDumpFileDataHeader.from_fd(fd)
        assert mdhdr.buf_size == DiskDumpHeader.sizeof
        self._ddhdr = DiskDumpHeader.from_fd(fd)

        # The next header is kdump_sub_header, which is located at the
        # page offset. We will walk over the data chunks and try to locate
        # the data chunk that contains the `kdump_sub_header_off` offset.
        # This code currently does not support reading data that spans across
        # multiple data chunks.
        disk_dump_header_blocks = 1
        kdump_sub_header_off = disk_dump_header_blocks * self.ddhdr.block_size

        # List of chunks for back-referencing. The chunks may appear in random
        # order so we need to keep track of them.
        chunks = []
        # Fetch the next chunk.
        mdhdr = mdhdr.next(fd)
        while mdhdr:
            # If the current chunk offset is the offset for kdump_sub_header,
            # parse it.
            if mdhdr.offset == kdump_sub_header_off:
                logging.debug("found the chunk for ksubhdr: %s", mdhdr)
                self._ksubhdr = KdumpSubHeader.from_fd(fd)

            # Append it to the list of chunks we've seen
            chunks.append(mdhdr)

            # The kdump_sub_header contains the vmcoreinfo offset, so in order
            # to parse that, we must've parsed the kdump_sub_header already.
            if self.ksubhdr:
                # Search for the chunk that contains the vmcoreinfo
                for flat_block in chunks:
                    if flat_block.in_range(self.ksubhdr.offset_vmcoreinfo):
                        logging.debug("found the chunk for vmcore: %s", flat_block)
                        fd.seek(flat_block.data_offset)
                        # The offset is relative to the original file so we
                        # need to translate it to current file.
                        translated_offset = (
                            self.ksubhdr.offset_vmcoreinfo - flat_block.offset
                        )
                        self._vmcoreinfo = VMCoreInfo.from_fd(
                            fd,
                            flat_block.data_offset + translated_offset,
                            self.ksubhdr.size_vmcoreinfo,
                        )
                        # We got what we need so there's no point walking on
                        # the list any further.
                        return
            # Move to the next chunk
            mdhdr = mdhdr.next(fd)

    def parse_compressed(self, fd):
        """Parse the diskdumpfile, ksubhdr and vmcoreinfo from a
        kdump compressed file."""

        # Unlike the flat format, this format is contiguous and does not
        # contain any extra headers.

        # Read the disk_dump_header
        self._ddhdr = DiskDumpHeader.from_fd(fd)

        # disk_dump_header is always written as a block sized blob so we'll
        # progress to the end of the block.
        disk_dump_header_blocks = 1
        fd.seek(disk_dump_header_blocks * self.ddhdr.block_size, os.SEEK_SET)

        # Read the kdump_sub_header
        self._ksubhdr = KdumpSubHeader.from_fd(fd)

        # Parse vmcoreinfo
        self._vmcoreinfo = VMCoreInfo.from_fd(
            fd, self.ksubhdr.offset_vmcoreinfo, self.ksubhdr.size_vmcoreinfo
        )
