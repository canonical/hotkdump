#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
`hotkdump` class unit tests.
"""

import os
import mock
import unittest
import hkd
from utils import mock_file


mock_hdr = b'KDUMP   \x01\x02\x03\x04sys\0node\0release\0#version-443\0machine\0domain\0\0'
mock_hdr_shifted = os.urandom(8184) + mock_hdr
mock_hdr_invalid_no_sig = os.urandom(4096)


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
class HotkdumpKdumpHdrTest(unittest.TestCase):

    @mock.patch('builtins.open', mock_file(bytes=mock_hdr, name="name"))
    def test_kdump_hdr(self):
        uut = hkd.kdump_file_header("dummy")
        self.assertEqual(uut.kdump_version, 67305985)
        self.assertEqual(uut.domain, "domain")
        self.assertEqual(uut.machine, "machine")
        self.assertEqual(uut.node, "node")
        self.assertEqual(uut.release, "release")
        self.assertEqual(uut.system, "sys")
        self.assertEqual(uut.version, "#version-443")
        self.assertEqual(uut.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=mock_hdr_shifted, name="name"))
    def test_kdump_hdr_shifted(self):
        uut = hkd.kdump_file_header("dummy")
        self.assertEqual(uut.kdump_version, 67305985)
        self.assertEqual(uut.domain, "domain")
        self.assertEqual(uut.machine, "machine")
        self.assertEqual(uut.node, "node")
        self.assertEqual(uut.release, "release")
        self.assertEqual(uut.system, "sys")
        self.assertEqual(uut.version, "#version-443")
        self.assertEqual(uut.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=mock_hdr_invalid_no_sig, name="name"))
    def test_kdump_hdr_no_sig(self):
        self.assertRaises(hkd.ExceptionWithLog,
                          hkd.hotkdump, "1", "vmcore")
