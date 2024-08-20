#!/usr/bin/env python3

"""`hotkdump` class unit tests.

Copyright 2023 Canonical Limited.
SPDX-License-Identifier: GPL-3.0
"""

from unittest import mock, TestCase

import textwrap

from hotkdump.core.hotkdump import Hotkdump, HotkdumpParameters, ExceptionWithLog


from tests.utils import assert_has_no_such_calls, MockFileCtx, MockStatObj, MOCK_HDR


mock.Mock.assert_has_no_such_calls = assert_has_no_such_calls


@mock.patch.multiple(
    "os",
    remove=lambda x: True,
    listdir=lambda x: [],
    stat=lambda x, *args, **kwargs: "a",
    makedirs=lambda *a, **kw: None,
)
@mock.patch.multiple(
    "os.path", dirname=lambda x: x, realpath=lambda x: x, exists=lambda x: True
)
@mock.patch.multiple("shutil", which=lambda x: x)
@mock.patch("builtins.open", MockFileCtx(file_bytes=MOCK_HDR, name="name"))
class HotkdumpTest(TestCase):
    """test hotkdump class public api"""

    def setUp(self):
        self.patcher = mock.patch("tempfile.TemporaryDirectory")
        self.mock_temp_dir = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_default_construct(self):
        """Default-construct the class and verify
        that the class variables are initialized
        as expected.
        """
        params = HotkdumpParameters(internal_case_number="1", dump_file_path="vmcore")
        uut = Hotkdump(params)
        self.assertEqual(uut.params.internal_case_number, "1")
        self.assertEqual(uut.params.dump_file_path, "vmcore")

    def test_construct(self):
        """Explicitly construct the class with pre-determined
        values and verify that the class variables are initialized
        as expected.
        """

        params = HotkdumpParameters(
            internal_case_number="1",
            dump_file_path="vmcore",
            output_file_path="opf",
            log_file_path="log",
            ddebs_folder_path="ddebs",
            interactive=True,
        )
        uut = Hotkdump(params)
        self.assertEqual(uut.params.internal_case_number, "1")
        self.assertEqual(uut.params.dump_file_path, "vmcore")
        self.assertEqual(uut.params.output_file_path, "opf")
        self.assertEqual(uut.params.log_file_path, "log")
        self.assertEqual(uut.params.ddebs_folder_path, "ddebs")
        self.assertEqual(uut.params.interactive, True)

    def test_arch(self):
        """Test if the get_arcitecture() method returns the
        correct architecture string for different `machine`
        types.
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        uut.kdump_file.ddhdr.utsname.machine = "x86_64"
        self.assertEqual(uut.get_architecture(), "amd64")
        uut.kdump_file.ddhdr.utsname.machine = "aarch64"
        self.assertEqual(uut.get_architecture(), "arm64")
        uut.kdump_file.ddhdr.utsname.machine = "invalid"
        self.assertRaises(NotImplementedError, uut.get_architecture)

    @mock.patch("builtins.open", MockFileCtx(file_bytes=MOCK_HDR, name="name"))
    def test_kdump_hdr(self):
        """Test if the kdump_header has the correct values included
        in the MOCK_HDR after opening the fake vmcore file
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        self.assertEqual(uut.kdump_file.ddhdr.header_version, 67305985)
        self.assertEqual(uut.kdump_file.ddhdr.utsname.domain, "domain")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.machine, "machine")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.node, "node")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.release, "release")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.system, "sys")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.version, "#version-443")
        self.assertEqual(uut.kdump_file.ddhdr.utsname.normalized_version, "version")

    def test_find_crash_executable_symlink_exists(self):
        """Verify that the hotkdump uses the crash symlink on the root
        folder if exists.
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        with mock.patch.multiple(
            "os.path",
            dirname=lambda *a, **kw: "/root/dir",
            realpath=lambda *a, **kw: "rp",
            exists=lambda *a, **kw: True,
        ) as _:
            value = uut.find_crash_executable()
            self.assertEqual(value, "/root/dir/../crash")

    def test_find_crash_executable_nosymlink_but_path_exists(self):
        """Verify that the hotkdump uses the crash from PATH when
        the root-dir `crash` symlink does not exists.
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        with mock.patch.multiple(
            "os.path",
            dirname=lambda *a, **kw: "/root/dir",
            realpath=lambda *a, **kw: "rp",
            exists=lambda *a, **kw: False,
        ):
            with mock.patch("shutil.which", lambda *a, **kw: "/usr/mybin/crash"):
                value = uut.find_crash_executable()
                self.assertEqual(value, "/usr/mybin/crash")

    def test_find_crash_executable_notfound(self):
        """Verify that the hotkdump raises an exception when crash
        executable could not be found.
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        with mock.patch.multiple(
            "os.path",
            dirname=lambda *a, **kw: "/root/dir",
            realpath=lambda *a, **kw: "rp",
            exists=lambda *a, **kw: False,
        ):
            with mock.patch("shutil.which", lambda *a, **kw: None):
                self.assertRaises(ExceptionWithLog, uut.find_crash_executable)

    def test_write_crash_commands_file(self):
        """Verify that the hotkdump `write_crash_commands_file` writes the
        correct commands file.
        """
        params = HotkdumpParameters(dump_file_path="empty", output_file_path="hkd.test")
        uut = Hotkdump(params)
        uut.temp_working_dir.name = "/tmpdir"
        # pylint: disable=line-too-long
        expected_output = textwrap.dedent(
            r"""
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'sys'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        sys >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'bt'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        bt >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'log' with audit messages filtered out" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        log | grep -vi audit >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'kmem -i'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        kmem -i >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'dev -d'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        dev -d >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'mount'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        mount >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'files'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        files >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'vm'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        vm >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Output of 'net'" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        net >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Longest running blocked processes" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        ps -m | grep UN | tail >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        !echo "Top 20 memory consumers" >> hkd.test
        !echo "---------------------------------------" >> hkd.test
        ps -G | sed 's/>//g' | sort -k 8,8 -n | awk '$8 ~ /[0-9]/{ $8 = $8/1024" MB"; print }' | tail -20 | sort -r -k8,8 -g >> hkd.test
        !echo "\n!echo '---------------------------------------' >> hkd.test" >> /tmpdir/crash_commands
        !echo "\n!echo 'BT of the longest running blocked process' >> hkd.test" >> /tmpdir/crash_commands
        !echo "\n!echo '---------------------------------------' >> hkd.test" >> /tmpdir/crash_commands
        ps -m | grep UN | tail -n1 | grep -oE "PID: [0-9]+" | grep -oE "[0-9]+" | awk '{print "bt " $1 " >> hkd.test"}' >> /tmpdir/crash_commands
        !echo "\nquit >> hkd.test" >> /tmpdir/crash_commands
        !echo "" >> hkd.test
        """
        ).strip()
        # pylint: enable=line-too-long
        with mock.patch("builtins.open", new_callable=mock.mock_open()) as mo:
            contents = None

            def update_contents(c):
                nonlocal contents
                contents = c

            mo.return_value.__enter__.return_value.write = update_contents
            mo.return_value.__enter__.return_value.name = "/tmpdir/crash_commands"
            self.assertEqual("/tmpdir/crash_commands", uut.write_crash_commands_file())
            mo.assert_called_with("/tmpdir/crash_commands", "w", encoding="utf-8")
            self.assertEqual(contents, expected_output)

    def test_exec(self):
        """Verify that the hotkdump calls the subprocess.Popen
        with the correct arguments.
        """
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        with mock.patch("subprocess.Popen", mock.MagicMock()) as p:
            uut.exec("a", "args", "wd")
            p.assert_called_once_with("a args", shell=True, cwd="wd")

    def test_switch_cwd(self):
        """To be implemented later"""

    def test_strip_tags(self):
        """Verify that the hotkdump is able to remove version-specific
        suffixes and other shenanigans from the kernel version string
        to obtain the "plain" version.
        """
        test_cases_valid = [
            # Regular tags
            ("5.4.0-146-generic", "5.4.0-146"),
            ("5.4.0-146-lowlatency", "5.4.0-146"),
            ("5.4.0-146-generic-hwe", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe", "5.4.0-146"),
            ("5.4.0-146-kvm", "5.4.0-146"),
            ("5.4.0-146-aws", "5.4.0-146"),
            ("5.4.0-146-azure", "5.4.0-146"),
            ("5.4.0-146-azure-fde", "5.4.0-146"),
            ("5.4.0-146-gcp", "5.4.0-146"),
            ("5.4.0-146-gke", "5.4.0-146"),
            ("5.4.0-146-snapdragon", "5.4.0-146"),
            ("5.4.0-146-raspi2", "5.4.0-146"),
            # Tags with version-specific suffix
            ("5.4.0-146-generic-hwe-16.04", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-18.04", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-20.04", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-22.04", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-24.04", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-16.04", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-18.04", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-20.04", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-22.04", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-24.04", "5.4.0-146"),
            # Tags with version-specific suffix and '-edge' suffix
            ("5.4.0-146-generic-hwe-16.04-edge", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-18.04-edge", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-20.04-edge", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-22.04-edge", "5.4.0-146"),
            ("5.4.0-146-generic-hwe-24.04-edge", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-16.04-edge", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-18.04-edge", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-20.04-edge", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-22.04-edge", "5.4.0-146"),
            ("5.4.0-146-lowlatency-hwe-24.04-edge", "5.4.0-146"),
            ("5.4.0-146", "5.4.0-146"),
        ]

        test_cases_invalid = [
            ("5.4.0-146-generic-hwe-20.04----edge", "5.4.0-146"),
            ("5.4.0-146_generic-hwe-20.04_edge", "5.4.0-146"),
            ("5.4.0-146aws", "5.4.0-146aws"),
            ("5.4.0-146_azure", "5.4.0-146_azure"),
            ("5.4.0-146-generic-hwe-21.04", "5.4.0-146-generic-hwe-21.04"),
        ]

        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        for input_str, expected_output in test_cases_valid:
            with self.subTest(input_str=input_str):
                self.assertEqual(
                    uut.strip_release_variant_tags(input_str), expected_output
                )

        for input_str, expected_output in test_cases_invalid:
            with self.subTest(input_str=input_str):
                self.assertRaises(
                    ExceptionWithLog, uut.strip_release_variant_tags, input_str
                )

    @mock.patch("os.utime")
    @mock.patch("hotkdump.core.hotkdump.PullPkg")
    @mock.patch("hotkdump.core.hotkdump.switch_cwd")
    @mock.patch("subprocess.Popen")
    def test_maybe_download_vmlinux_ddeb(
        self,mock_popen, mock_switch_cwd, mock_pullpkg, mock_utime
    ):
        """Verify that the hotkdump:
        - calls the PullPkg when the ddeb is absent
        - does not call the PullPkg when the ddeb is present
        - raises an ExceptionWithLog when PullPkg fails
        """
        # Set up mock return values
        mock_pull = mock.MagicMock()
        mock_pullpkg.return_value.pull = mock_pull

        switch_cwd = mock.MagicMock()
        mock_switch_cwd.return_value = switch_cwd

        # mock_pull.return_value.pull
        params = HotkdumpParameters(dump_file_path="empty")
        uut = Hotkdump(params)
        uut.kdump_file.ddhdr.utsname.release = "5.15.0-1030-gcp"
        uut.kdump_file.ddhdr.utsname.machine = "x86_64"
        uut.kdump_file.ddhdr.utsname.version = (
            "#37-Ubuntu SMP Tue Feb 14 19:37:08 UTC 2023"
        )
        uut.kdump_file.ddhdr.utsname.normalized_version = "37"

        # Test downloading a new ddeb file

        expected_ddeb_path = (
            "linux-image-unsigned-5.15.0-1030-gcp-dbgsym_5.15.0-1030.37_amd64.ddeb"
        )

        with mock.patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = [False, True]
            mock_popen.return_value.__enter__.return_value.returncode = 0
            result = uut.maybe_download_vmlinux_via_pullpkg()

            mock_exists.assert_called()

            # Assert that pullpkg was invoked with the correct arguments
            mock_pull.assert_called_once_with(
                [
                    "--distro",
                    "ubuntu",
                    "--arch",
                    "amd64",
                    "--pull",
                    "ddebs",
                    "linux-image-unsigned-5.15.0-1030-gcp",
                    "5.15.0-1030.37",
                ]
            )

            # Assert that the expected ddeb file path was returned
            self.assertEqual(result, expected_ddeb_path)

        mock_pull.reset_mock()
        # Test reusing an existing ddeb file
        with mock.patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with mock.patch("time.time") as mock_time:
                mock_time.return_value = 1234567890.0

                result = uut.maybe_download_vmlinux_via_pullpkg()

                # Assert that pullpkg was not invoked
                mock_pull.assert_not_called()

                # # Assert that the file's last access time was updated
                mock_utime.assert_called_once_with(
                    expected_ddeb_path, (1234567890.0, 1234567890.0)
                )

                # Assert that the expected ddeb file path was returned
                self.assertEqual(result, expected_ddeb_path)

        # Test failing to download a new ddeb file
        mock_pull.return_value = Exception("Error")
        with mock.patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            with self.assertRaises(ExceptionWithLog):
                uut.maybe_download_vmlinux_via_pullpkg()

    def test_post_run_ddeb_count_policy(self):
        """Verify that the hotkdump executes the file
        count policy after execution as per configured.
        """

        with mock.patch("os.remove") as mock_remove, mock.patch(
            "os.listdir"
        ) as mock_listdir, mock.patch("os.stat") as mock_stat, mock.patch(
            "time.time"
        ) as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                "file1.ddeb",
                "file2.ddeb",
                "file3.txt",
                "file4.ddeb",
            ]

            mock_stat.return_value.st_atime = 3600
            mock_stat.return_value.st_size = 500000

            # Set up test data
            params = HotkdumpParameters(dump_file_path="empty")
            params.ddebs_folder_path = "/path/to/ddebs"
            params.ddeb_retention_settings.enabled = True
            params.ddeb_retention_settings.max_age_secs = None
            params.ddeb_retention_settings.size_lwm = None
            params.ddeb_retention_settings.size_hwm = None
            params.ddeb_retention_settings.max_count = 2
            uut = Hotkdump(params)
            # Call the function being tested
            uut.post_run()

            # Check if the function has removed the ddebs correctly
            mock_stat.assert_has_calls(
                [
                    mock.call("/path/to/ddebs/file1.ddeb"),
                    mock.call("/path/to/ddebs/file2.ddeb"),
                ]
            )

            mock_listdir.assert_called_once_with("/path/to/ddebs")

            expected_calls = [mock.call("/path/to/ddebs/file4.ddeb")]
            mock_remove.assert_has_calls(expected_calls)

            # Now bump the limit to 3, and re-test
            # The function must not remove any ddebs
            uut.params.ddeb_retention_settings.max_count = 3

            mock_remove.reset_mock()
            mock_listdir.reset_mock()
            mock_stat.reset_mock()

            uut.post_run()
            mock_remove.assert_not_called()

            # Disable the policy
            # The function must not remove any ddebs
            uut.params.ddeb_retention_settings.max_count = None
            mock_remove.reset_mock()
            mock_listdir.reset_mock()
            mock_stat.reset_mock()

            uut.post_run()
            mock_remove.assert_not_called()

    def test_post_run_ddeb_age_policy(self):
        """Verify that the hotkdump executes the file
        age policy after execution as per configured.
        """

        with mock.patch("os.remove") as mock_remove, mock.patch(
            "os.listdir"
        ) as mock_listdir, mock.patch("os.stat") as mock_stat, mock.patch(
            "time.time"
        ) as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                "file1.ddeb",
                "file2.ddeb",
                "file3.txt",
                "file4.ddeb",
            ]

            mock_stat.side_effect = lambda fname: MockStatObj(
                fname,
                {
                    "/path/to/ddebs/file1.ddeb": {
                        "atime": 1234567890.0 + 1,
                        "size": 3150,
                    },
                    "/path/to/ddebs/file2.ddeb": {
                        "atime": 1234567890.0 + 1,
                        "size": 3150,
                    },
                    "/path/to/ddebs/file4.ddeb": {"atime": 0, "size": 3150},
                    # 50000 bytes in total
                },
            )
            mock_listdir.reset_mock()

            # Set up test data
            params = HotkdumpParameters(dump_file_path="empty")
            params.ddebs_folder_path = "/path/to/ddebs"
            params.ddeb_retention_settings.enabled = True
            params.ddeb_retention_settings.max_age_secs = 4000
            params.ddeb_retention_settings.size_lwm = None
            params.ddeb_retention_settings.size_hwm = None
            params.ddeb_retention_settings.max_count = None
            uut = Hotkdump(params)

            uut.post_run()
            mock_listdir.assert_called_once_with("/path/to/ddebs")

            expected_calls = [mock.call("/path/to/ddebs/file4.ddeb")]

            not_expected_calls = [
                mock.call("/path/to/ddebs/file1.ddeb"),
                mock.call("/path/to/ddebs/file2.ddeb"),
                mock.call("/path/to/ddebs/file3.txt"),
            ]

            mock_remove.assert_has_calls(expected_calls, any_order=True)
            mock_remove.assert_has_no_such_calls(not_expected_calls)

    def test_post_run_ddeb_total_size_policy(self):
        """Verify that the hotkdump executes the file
        total size policy after execution as per configured.
        """

        with mock.patch("os.remove") as mock_remove, mock.patch(
            "os.listdir"
        ) as mock_listdir, mock.patch("os.stat") as mock_stat, mock.patch(
            "time.time"
        ) as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                "file1.ddeb",
                "file2.ddeb",
                "file3.txt",
                "file4.ddeb",
            ]

            mock_stat.side_effect = lambda fname: MockStatObj(
                fname,
                {
                    "/path/to/ddebs/file1.ddeb": {"atime": 0, "size": 15000},
                    "/path/to/ddebs/file2.ddeb": {"atime": 1, "size": 15000},
                    "/path/to/ddebs/file4.ddeb": {"atime": 2, "size": 20000},
                    # 50000 bytes in total
                },
            )

            # Set up test data
            params = HotkdumpParameters(dump_file_path="empty")
            params.ddebs_folder_path = "/path/to/ddebs"
            params.ddeb_retention_settings.enabled = True
            params.ddeb_retention_settings.max_age_secs = None
            params.ddeb_retention_settings.size_lwm = 25000
            params.ddeb_retention_settings.size_hwm = 50000
            params.ddeb_retention_settings.max_count = None
            uut = Hotkdump(params)
            uut.post_run()

            mock_listdir.assert_called_once_with("/path/to/ddebs")

            # file1, file2 and file4 are in total 50000 bytes in size, which exceeds
            # the high watermark. the algorithm will start removing ddebs one by one,
            # based on their last access time until total ddeb size is below low watermark.
            # file1 is the oldest and file4 is the newest, so the file1 and file2 must be
            # removed while file4 is untouched.

            expected_calls = [
                mock.call("/path/to/ddebs/file1.ddeb"),
                mock.call("/path/to/ddebs/file2.ddeb"),
            ]

            not_expected_calls = [mock.call("/path/to/ddebs/file4.ddeb")]

            mock_remove.assert_has_calls(expected_calls, any_order=True)
            mock_remove.assert_has_no_such_calls(not_expected_calls)

    def test_post_run_ddeb_retention_disabled(
        self,
    ):
        """Verify that the hotkdump removes the ddeb
        files post-run when the file retention is disabled.
        """
        with mock.patch("os.remove") as mock_remove:
            params = HotkdumpParameters(dump_file_path="empty")
            params.ddebs_folder_path = "/path/to/ddebs"
            params.ddeb_retention_settings.enabled = False
            params.ddeb_retention_settings.max_age_secs = 1
            params.ddeb_retention_settings.size_lwm = 1
            params.ddeb_retention_settings.size_hwm = 1
            params.ddeb_retention_settings.max_count = 1
            uut = Hotkdump(params)

            with mock.patch("os.listdir") as mock_listdir, mock.patch(
                "os.stat"
            ) as mock_stat, mock.patch("time.time") as mock_time:
                mock_time.return_value = 1234567890.0
                mock_listdir.return_value = [
                    "file1.ddeb",
                    "file2.ddeb",
                    "file3.txt",
                    "file4.ddeb",
                ]
                mock_stat.side_effect = lambda fname, *args, **kwargs: MockStatObj(
                    fname,
                    {
                        "/path/to/ddebs/file1.ddeb": {"atime": 0, "size": 15000},
                        "/path/to/ddebs/file2.ddeb": {"atime": 1, "size": 15000},
                        "/path/to/ddebs/file4.ddeb": {"atime": 2, "size": 20000},
                        # 50000 bytes in total
                    },
                )
                uut.post_run()

            mock_listdir.assert_called_once_with("/path/to/ddebs")
            expected_calls = [
                mock.call("/path/to/ddebs/file1.ddeb"),
                mock.call("/path/to/ddebs/file2.ddeb"),
                mock.call("/path/to/ddebs/file4.ddeb"),
            ]
        mock_remove.assert_has_calls(expected_calls, any_order=True)

    def test_debug_file_type(self):
        """
        Verify that the file type is correctly inferred 
        """
        params = HotkdumpParameters(debug_file="/path/to/a/ddeb/linux-yy.xx.ddeb",
                                    dump_file_path="empty")
        hkdump = Hotkdump(params)
        self.assertEqual(hkdump.debug_file_type(), ".ddeb")

        hkdump.params.debug_file = "/path/to/a/vmlinux/vmlinux-yy.xx"
        self.assertEqual(hkdump.debug_file_type(), "vmlinux")

        hkdump.params.debug_file = None
        self.assertEqual(hkdump.debug_file_type(), None)

        hkdump.params.debug_file = ""
        self.assertEqual(hkdump.debug_file_type(), None)
    