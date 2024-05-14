#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` class unit tests.
"""

import os
from unittest import mock, TestCase


from hotkdump.core.exceptions import ExceptionWithLog
from hotkdump.core.kdump_file_header import kdump_file_header
from hotkdump.core.hotkdump_impl import hotkdump

from tests.utils import mock_file


MOCK_HDR = b'KDUMP   \x01\x02\x03\x04sys\0node\0release\0#version-443\0machine\0domain\0\0'
MOCK_HDR_SHIFTED = os.urandom(8184) + MOCK_HDR
MOCK_HDR_INVALID_NO_SIG = os.urandom(4096)


@mock.patch.multiple(
    "os",
    remove=lambda x: True,
    listdir=lambda x: [],
    stat=lambda x: "a",
    makedirs=lambda *a, **kw: None
)
@mock.patch.multiple(
    "os.path",
    dirname=lambda x: x,
    realpath=lambda x: x,
    exists=lambda x: True
)
@mock.patch.multiple(
    "shutil",
    which=lambda x: x
)
class HotkdumpKdumpHdrTest(TestCase):
    """kdump header parsing tests"""

    @mock.patch('builtins.open', mock_file(bytes=MOCK_HDR, name="name"))
    def test_kdump_hdr(self):
        """Test kdump file header parsing with
        a correct header.
        """
        uut = kdump_file_header("dummy")
        self.assertEqual(uut.kdump_version, 67305985)
        self.assertEqual(uut.domain, "domain")
        self.assertEqual(uut.machine, "machine")
        self.assertEqual(uut.node, "node")
        self.assertEqual(uut.release, "release")
        self.assertEqual(uut.system, "sys")
        self.assertEqual(uut.version, "#version-443")
        self.assertEqual(uut.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=MOCK_HDR_SHIFTED, name="name"))
    def test_kdump_hdr_shifted(self):
        """Test kdump file header parsing with
        a correct header, but shifted forward.
        (i.e. to simulate makedumpfile header)
        """
        uut = kdump_file_header("dummy")
        self.assertEqual(uut.kdump_version, 67305985)
        self.assertEqual(uut.domain, "domain")
        self.assertEqual(uut.machine, "machine")
        self.assertEqual(uut.node, "node")
        self.assertEqual(uut.release, "release")
        self.assertEqual(uut.system, "sys")
        self.assertEqual(uut.version, "#version-443")
        self.assertEqual(uut.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=MOCK_HDR_INVALID_NO_SIG, name="name"))
    def test_kdump_hdr_no_sig(self):
        """Test kdump file header parsing with
        garbage input.
        """
        self.assertRaises(ExceptionWithLog,
                          hotkdump, "1", "vmcore")
