#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` class unit tests.
"""

import os
from unittest import mock, TestCase
from io import BytesIO


from hotkdump.core.exceptions import ExceptionWithLog
from hotkdump.core.kdumpfile import (
    KdumpFile,
    VMCoreInfo,
    DiskDumpHeader,
    BinaryFileReader,
    KdumpSubHeader,
)
from hotkdump.core.hotkdump import Hotkdump, HotkdumpParameters

from tests.utils import mock_file


def fill_zeros(by, n):
    by += b"\0" * (n - len(by))
    return by


MOCK_HDR = (
    b"KDUMP   \x01\x02\x03\x04sys\0node\0release\0#version-443\0machine\0domain\0\0"
)
MOCK_HDR_INVALID_NO_SIG = os.urandom(4096)
MOCK_VMCOREINFO = b"""key=value
this is a key=value value
$$=@@
"""


class TestBinaryFileReader(TestCase):
    """Test BinaryFileReader class."""

    def test_file_size(self):
        fake_file = BytesIO(b"1234567890")
        self.assertEqual(BinaryFileReader.file_size(fake_file), 10)

    def test_seek_to_first_non_nul(self):
        fake_file = BytesIO(b"\x00\x00\x00ABC")
        BinaryFileReader.seek_to_first_non_nul(fake_file)
        self.assertEqual(fake_file.read(3), b"ABC")

    def test_read_int32(self):
        fake_file = BytesIO(b"\x01\x00\x00\x00")
        self.assertEqual(BinaryFileReader.read_int32(fake_file), 1)

    def test_read_int64(self):
        fake_file = BytesIO(b"\x01\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(BinaryFileReader.read_int64(fake_file), 1)

    def test_read_str(self):
        fake_file = BytesIO(b"Hello\x00\x00")
        self.assertEqual(BinaryFileReader.read_str(fake_file, 5), "Hello")

    def test_read_cstr(self):
        fake_file = BytesIO(b"Hello\x00\x00\x00World\x00")
        self.assertEqual(BinaryFileReader.read_cstr(fake_file), "Hello")
        self.assertEqual(BinaryFileReader.read_cstr(fake_file), "World")


@mock.patch.multiple(
    "os",
    remove=lambda x: True,
    listdir=lambda x: [],
    stat=lambda x: "a",
    makedirs=lambda *a, **kw: None,
)
@mock.patch.multiple(
    "os.path", dirname=lambda x: x, realpath=lambda x: x, exists=lambda x: True
)
@mock.patch.multiple("shutil", which=lambda x: x)
class KdumpDiskDumpHeaderTest(TestCase):
    """kdump header parsing tests"""

    @mock.patch("builtins.open", mock_file(bytes=MOCK_HDR, name="name"))
    def test_kdump_hdr(self):
        """Test kdump file header parsing with
        a correct header.
        """
        with open("a", "rb") as f:
            uut = DiskDumpHeader.from_fd(f)
            self.assertEqual(uut.header_version, 67305985)
            self.assertEqual(uut.utsname.domain, "domain")
            self.assertEqual(uut.utsname.machine, "machine")
            self.assertEqual(uut.utsname.node, "node")
            self.assertEqual(uut.utsname.release, "release")
            self.assertEqual(uut.utsname.system, "sys")
            self.assertEqual(uut.utsname.version, "#version-443")
            self.assertEqual(uut.utsname.normalized_version, "version")

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data=b"")
    def test_from_bytes_io(self, mfile):
        # 6 bytes padding after utsname
        fake_file_content = (
            b"KDUMP   "  # signature
            + b"\x01\x00\x00\x00"  # header_version
            + fill_zeros(b"Linux", 65)  # system
            + fill_zeros(b"node", 65)  # node
            + fill_zeros(b"release", 65)  # release
            + fill_zeros(b"version", 65)  # version
            + fill_zeros(b"machine", 65)  # machine
            + fill_zeros(b"domain", 65)  # domain
            + b"\0" * 6  # padding
            + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # timestamp_sec
            + b"\x02\x00\x00\x00\x00\x00\x00\x00"  # timestamp_usec
            + b"\x03\x00\x00\x00"  # status
            + b"\x04\x00\x00\x00"  # block_size
        )
        fake_file = BytesIO(fake_file_content)
        mfile.return_value = fake_file

        header = DiskDumpHeader.from_fd(fake_file)
        self.assertEqual(header.signature, "KDUMP   ")
        self.assertEqual(header.header_version, 1)
        self.assertEqual(header.utsname.system, "Linux")
        self.assertEqual(header.utsname.node, "node")
        self.assertEqual(header.utsname.release, "release")
        self.assertEqual(header.utsname.version, "version")
        self.assertEqual(header.utsname.machine, "machine")
        self.assertEqual(header.utsname.domain, "domain")
        self.assertEqual(header.timestamp_sec, 1)
        self.assertEqual(header.timestamp_usec, 2)
        self.assertEqual(header.status, 3)
        self.assertEqual(header.block_size, 4)


class TestKdumpSubHeader(TestCase):

    def setUp(self):
        self.fake_file_content = (
            b"\x01\x00\x00\x00\x00\x00\x00\x00"  # phys_base
            + b"\x02\x00\x00\x00"  # dump_level
            + b"\x03\x00\x00\x00"  # split
            + b"\x04\x00\x00\x00\x00\x00\x00\x00"  # start_pfn
            + b"\x05\x00\x00\x00\x00\x00\x00\x00"  # end_pfn
            + b"\x06\x00\x00\x00\x00\x00\x00\x00"  # offset_vmcoreinfo
            + b"\x07\x00\x00\x00\x00\x00\x00\x00"  # size_vmcoreinfo
            + b"\x08\x00\x00\x00\x00\x00\x00\x00"  # offset_note
            + b"\x09\x00\x00\x00\x00\x00\x00\x00"  # size_note
            + b"\x0a\x00\x00\x00\x00\x00\x00\x00"  # offset_eraseinfo
            + b"\x0b\x00\x00\x00\x00\x00\x00\x00"  # size_eraseinfo
            + b"\x0c\x00\x00\x00\x00\x00\x00\x00"  # start_pfn_64
            + b"\x0d\x00\x00\x00\x00\x00\x00\x00"  # end_pfn_64
            + b"\x0e\x00\x00\x00\x00\x00\x00\x00"  # max_mapnr_64
        )

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data=b"")
    def test_from_fd(self, mfile):
        fake_file = BytesIO(self.fake_file_content)
        mfile.return_value = fake_file

        sub_header = KdumpSubHeader.from_fd(fake_file, 0)
        self.assertEqual(sub_header.phys_base, 1)
        self.assertEqual(sub_header.dump_level, 2)
        self.assertEqual(sub_header.split, 3)
        self.assertEqual(sub_header.start_pfn, 4)
        self.assertEqual(sub_header.end_pfn, 5)
        self.assertEqual(sub_header.offset_vmcoreinfo, 6)
        self.assertEqual(sub_header.size_vmcoreinfo, 7)
        self.assertEqual(sub_header.offset_note, 8)
        self.assertEqual(sub_header.size_note, 9)
        self.assertEqual(sub_header.offset_eraseinfo, 10)
        self.assertEqual(sub_header.size_eraseinfo, 11)
        self.assertEqual(sub_header.start_pfn_64, 12)
        self.assertEqual(sub_header.end_pfn_64, 13)
        self.assertEqual(sub_header.max_mapnr_64, 14)


class VMCoreInfoTest(TestCase):
    """VMCoreInfo class unit tests"""

    def test_vmcoreinfo_parse(self):
        """Check if VMCoreInfo class can parse the multiline
        key-value string properly."""

        data = """TEST(ABCD)=EFGHI
                  KEY=VALUE
                  
                  """
        v = VMCoreInfo(data)
        self.assertEqual(v.get("TEST(ABCD)"), "EFGHI")
        self.assertEqual(v.get("KEY"), "VALUE")

    @mock.patch("builtins.open", mock_file(bytes=MOCK_VMCOREINFO, name="name"))
    def test_vmcoreinfo_from_file(self):
        """Check if VMCoreInfo class can read from a file."""
        with open("a", "rb") as f:
            v = VMCoreInfo.from_fd(f, 0, len(MOCK_VMCOREINFO))
            self.assertEqual(v.get("key"), "value")
            self.assertEqual(v.get("this is a key"), "value value")
            self.assertEqual(v.get("$$"), "@@")


class TestKdumpFile(TestCase):
    """Unit tests for KDumpFile class."""

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data=b"")
    def test_init_valid_kdump_file_shifted(self, mfile):

        fake_vmcoreinfo = b"""key=value
this is a key=value value
$$=@@
"""
        fake_file_content = (
            fill_zeros(
                os.urandom(2048)  # preamble
                + b"KDUMP   "  # signature
                + b"\x01\x00\x00\x00"  # header_version
                + fill_zeros(b"Linux", 65)  # system
                + fill_zeros(b"node", 65)  # node
                + fill_zeros(b"release", 65)  # release
                + fill_zeros(b"version", 65)  # version
                + fill_zeros(b"machine", 65)  # machine
                + fill_zeros(b"domain", 65)  # domain
                + b"\x02" * 6  # padding
                + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # timestamp_sec
                + b"\x02\x00\x00\x00\x00\x00\x00\x00"  # timestamp_usec
                + b"\x03\x00\x00\x00"  # status
                + b"\x00\x10\x00\x00",  # block_size
                4096,
            )
            + fill_zeros(
                b"\x01\x00\x00\x00\x00\x00\x00\x00"  # phys_base
                + b"\x02\x00\x00\x00"  # dump_level
                + b"\x03\x00\x00\x00"  # split
                + b"\x04\x00\x00\x00\x00\x00\x00\x00"  # start_pfn
                + b"\x05\x00\x00\x00\x00\x00\x00\x00"  # end_pfn
                + b"\x00\x20\x00\x00\x00\x00\x00\x00"  # offset_vmcoreinfo
                + b"\x2a\x00\x00\x00\x00\x00\x00\x00"  # size_vmcoreinfo
                + b"\x08\x00\x00\x00\x00\x00\x00\x00"  # offset_note
                + b"\x09\x00\x00\x00\x00\x00\x00\x00"  # size_note
                + b"\x0a\x00\x00\x00\x00\x00\x00\x00"  # offset_eraseinfo
                + b"\x0b\x00\x00\x00\x00\x00\x00\x00"  # size_eraseinfo
                + b"\x0c\x00\x00\x00\x00\x00\x00\x00"  # start_pfn_64
                + b"\x0d\x00\x00\x00\x00\x00\x00\x00"  # end_pfn_64
                + b"\x0e\x00\x00\x00\x00\x00\x00\x00",  # max_mapnr_64
                4096,
            )
            + fake_vmcoreinfo
        )

        fake_file = BytesIO(fake_file_content)
        mfile.return_value = fake_file

        kdump_file = KdumpFile("dummy_path")

        self.assertIsInstance(kdump_file.ddhdr, DiskDumpHeader)
        self.assertIsInstance(kdump_file.ksubhdr, KdumpSubHeader)
        self.assertIsInstance(kdump_file.vmcoreinfo, VMCoreInfo)

        self.assertEqual(kdump_file.ddhdr.signature, "KDUMP   ")
        self.assertEqual(kdump_file.ddhdr.header_version, 1)
        self.assertEqual(kdump_file.ddhdr.utsname.system, "Linux")
        self.assertEqual(kdump_file.ddhdr.utsname.node, "node")
        self.assertEqual(kdump_file.ddhdr.utsname.release, "release")
        self.assertEqual(kdump_file.ddhdr.utsname.version, "version")
        self.assertEqual(kdump_file.ddhdr.utsname.machine, "machine")
        self.assertEqual(kdump_file.ddhdr.utsname.domain, "domain")
        self.assertEqual(kdump_file.ddhdr.timestamp_sec, 1)
        self.assertEqual(kdump_file.ddhdr.timestamp_usec, 2)
        self.assertEqual(kdump_file.ddhdr.status, 3)
        self.assertEqual(kdump_file.ddhdr.block_size, 4096)

        self.assertEqual(kdump_file.ksubhdr.phys_base, 1)
        self.assertEqual(kdump_file.ksubhdr.dump_level, 2)
        self.assertEqual(kdump_file.ksubhdr.split, 3)
        self.assertEqual(kdump_file.ksubhdr.start_pfn, 4)
        self.assertEqual(kdump_file.ksubhdr.end_pfn, 5)
        self.assertEqual(kdump_file.ksubhdr.offset_vmcoreinfo, 8192)
        self.assertEqual(kdump_file.ksubhdr.size_vmcoreinfo, 42)
        self.assertEqual(kdump_file.ksubhdr.offset_note, 8)
        self.assertEqual(kdump_file.ksubhdr.size_note, 9)
        self.assertEqual(kdump_file.ksubhdr.offset_eraseinfo, 10)
        self.assertEqual(kdump_file.ksubhdr.size_eraseinfo, 11)
        self.assertEqual(kdump_file.ksubhdr.start_pfn_64, 12)
        self.assertEqual(kdump_file.ksubhdr.end_pfn_64, 13)
        self.assertEqual(kdump_file.ksubhdr.max_mapnr_64, 14)

        self.assertEqual(kdump_file.vmcoreinfo.get("key"), "value")
        self.assertEqual(kdump_file.vmcoreinfo.get("this is a key"), "value value")
        self.assertEqual(kdump_file.vmcoreinfo.get("$$"), "@@")

    @mock.patch("builtins.open", mock_file(bytes=MOCK_HDR_INVALID_NO_SIG, name="name"))
    def test_kdump_hdr_no_sig(self):
        """Test kdump file header parsing with
        garbage input.
        """
        self.assertRaises(
            ExceptionWithLog, Hotkdump, HotkdumpParameters(dump_file_path="dump")
        )
