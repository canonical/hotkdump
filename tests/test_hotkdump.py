import unittest
import hotkdump
import mock
import io
import os
import textwrap


def assert_has_no_such_calls(self, *args, **kwargs):
    for call in list(*args):
        try:
            self.assert_has_calls([call])
        except AssertionError:
            continue
        raise Exception('Expected %s to not have been called.' %
                        self._format_mock_call_signature(args, kwargs))


mock.Mock.assert_has_no_such_calls = assert_has_no_such_calls


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
        uut = hotkdump.hotkdump("1", "vmcore")
        self.assertEqual(uut.kdump_header.kdump_version, 67305985)
        self.assertEqual(uut.kdump_header.domain, "domain")
        self.assertEqual(uut.kdump_header.machine, "machine")
        self.assertEqual(uut.kdump_header.node, "node")
        self.assertEqual(uut.kdump_header.release, "release")
        self.assertEqual(uut.kdump_header.system, "sys")
        self.assertEqual(uut.kdump_header.version, "#version-443")
        self.assertEqual(uut.kdump_header.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=mock_hdr_shifted, name="name"))
    def test_kdump_hdr_shifted(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        self.assertEqual(uut.kdump_header.kdump_version, 67305985)
        self.assertEqual(uut.kdump_header.domain, "domain")
        self.assertEqual(uut.kdump_header.machine, "machine")
        self.assertEqual(uut.kdump_header.node, "node")
        self.assertEqual(uut.kdump_header.release, "release")
        self.assertEqual(uut.kdump_header.system, "sys")
        self.assertEqual(uut.kdump_header.version, "#version-443")
        self.assertEqual(uut.kdump_header.normalized_version, "version")

    @mock.patch('builtins.open', mock_file(bytes=mock_hdr_invalid_no_sig, name="name"))
    def test_kdump_hdr_no_sig(self):
        self.assertRaises(hotkdump.ExceptionWithLog,
                          hotkdump.hotkdump, "1", "vmcore")


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
@mock.patch('builtins.open', mock_file(bytes=mock_hdr, name="name"))
class HotkdumpTest(unittest.TestCase):

    def test_default_construct(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        self.assertEqual(uut.case_number, "1")
        self.assertEqual(uut.vmcore_file, "vmcore")
        self.assertEqual(uut.output_file, hotkdump.default_output_file)
        self.assertEqual(uut.log_file, hotkdump.default_log_file)
        self.assertEqual(uut.ddebs_path, hotkdump.default_ddebs_path)

    def test_construct(self):
        uut = hotkdump.hotkdump("1", "vmcore", "opf", "log", "ddeb")
        self.assertEqual(uut.case_number, "1")
        self.assertEqual(uut.vmcore_file, "vmcore")
        self.assertEqual(uut.output_file, "opf")
        self.assertEqual(uut.log_file, "log")
        self.assertEqual(uut.ddebs_path, "ddeb")

    def test_arch(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.kdump_header.machine = "x86_64"
        self.assertEqual(uut.get_architecture(), "amd64")
        uut.kdump_header.machine = "aarch64"
        self.assertEqual(uut.get_architecture(), "arm64")
        uut.kdump_header.machine = "invalid"
        self.assertRaises(NotImplementedError, uut.get_architecture)

    def test_find_crash_executable_symlink_exists(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        with mock.patch.multiple("os.path",
                                 dirname=lambda *a, **kw: "/root/dir",
                                 realpath=lambda *a, **kw: "rp",
                                 exists=lambda *a, **kw: True) as _:
            value = uut.find_crash_executable()
            self.assertEqual(value, "/root/dir/crash")

    def test_find_crash_executable_nosymlink_but_path_exists(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        with mock.patch.multiple("os.path",
                                 dirname=lambda *a, **kw: "/root/dir",
                                 realpath=lambda *a, **kw: "rp",
                                 exists=lambda *a, **kw: False):
            with mock.patch("shutil.which", lambda *a, **kw: "/usr/mybin/crash"):
                value = uut.find_crash_executable()
                self.assertEqual(value, "/usr/mybin/crash")

    def test_find_crash_executable_notfound(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        with mock.patch.multiple("os.path",
                                 dirname=lambda *a, **kw: "/root/dir",
                                 realpath=lambda *a, **kw: "rp",
                                 exists=lambda *a, **kw: False):
            with mock.patch("shutil.which", lambda *a, **kw: None):
                self.assertRaises(hotkdump.ExceptionWithLog,
                                  uut.find_crash_executable)

    def test_write_crash_commands_file(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.output_file = "hotkdump.test"
        uut.temp_working_dir.name = "/tmpdir"
        expected_output = textwrap.dedent(r"""
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'sys'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        sys >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'bt'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        bt >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'log' with audit messages filtered out" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        log | grep -vi audit >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'kmem -i'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        kmem -i >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'dev -d'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        dev -d >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'mount'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        mount >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'files'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        files >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'vm'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        vm >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Output of 'net'" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        net >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Oldest blocked processes" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        ps -m | grep UN | tail >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        !echo "Top 20 memory consumers" >> hotkdump.test
        !echo "---------------------------------------" >> hotkdump.test
        ps -G | sed 's/>//g' | sort -k 8,8 -n |  awk '$8 ~ /[0-9]/{ $8 = $8/1024" MB"; print }' | tail -20 | sort -r -k8,8 -g >> hotkdump.test
        !echo "\n!echo '---------------------------------------' >> hotkdump.test" >> /tmpdir/crash_commands
        !echo "\n!echo 'BT of the oldest blocked process' >> hotkdump.test" >> /tmpdir/crash_commands
        !echo "\n!echo '---------------------------------------' >> hotkdump.test" >> /tmpdir/crash_commands
        ps -m | grep UN | tail -n1 | grep -oE "PID: [0-9]+" | grep -oE "[0-9]+" | awk '{print "bt " $1 " >> hotkdump.test"}' >> /tmpdir/crash_commands
        !echo "\nquit >> hotkdump.test" >> /tmpdir/crash_commands
        !echo "" >> hotkdump.test
        """).strip()
        with mock.patch("builtins.open", new_callable=mock.mock_open()) as mo:
            contents = None

            def update_contents(c):
                nonlocal contents
                contents = c
            mo.return_value.__enter__.return_value.write = update_contents
            mo.return_value.__enter__.return_value.name = "/tmpdir/crash_commands"
            self.assertEqual("/tmpdir/crash_commands",
                             uut.write_crash_commands_file())
            mo.assert_called_with("/tmpdir/crash_commands", "w")
            self.assertEqual(contents, expected_output)

    def test_exec(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        with mock.patch("subprocess.Popen", mock.MagicMock()) as p:
            uut.exec("a", "args", "wd")
            p.assert_called_once_with(
                "a args", shell=True, cwd="wd")

    def test_switch_cwd(self):
        pass

    def test_strip_tags(self):
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
            ("5.4.0-146-generic-hwe-21.04", "5.4.0-146-generic-hwe-21.04")
        ]

        uut = hotkdump.hotkdump("1", "vmcore")
        for input_str, expected_output in test_cases_valid:
            with self.subTest(input_str=input_str):
                self.assertEqual(uut.strip_release_variant_tags(
                    input_str), expected_output)

        for input_str, expected_output in test_cases_invalid:
            with self.subTest(input_str=input_str):
                self.assertRaises(hotkdump.ExceptionWithLog,
                                  uut.strip_release_variant_tags, input_str)

    @mock.patch("os.utime")
    @mock.patch("hotkdump.PullPkg")
    def test_maybe_download_vmlinux_ddeb(self, mock_pullpkg, mock_utime):
        # Set up mock return values
        mock_pull = mock.MagicMock()
        mock_pullpkg.return_value.pull = mock_pull

        # mock_pull.return_value.pull

        uut = hotkdump.hotkdump("1", "vmcore")
        uut.kdump_header.release = "5.15.0-1030-gcp"
        uut.kdump_header.machine = "x86_64"
        uut.kdump_header.version = "#37-Ubuntu SMP Tue Feb 14 19:37:08 UTC 2023"
        uut.kdump_header.normalized_version = "37"

        # Test downloading a new ddeb file

        expected_ddeb_path = "linux-image-unsigned-5.15.0-1030-gcp-dbgsym_5.15.0-1030.37_amd64.ddeb"
        with mock.patch.object(uut, "switch_cwd", mock.MagicMock()):
            with mock.patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = [False, True]
                result = uut.maybe_download_vmlinux_ddeb()

                mock_exists.assert_called()

                # Assert that pullpkg was invoked with the correct arguments
                mock_pull.assert_called_once_with(
                    ["--distro", "ubuntu", "--arch", "amd64", "--pull", "ddebs", "linux-image-unsigned-5.15.0-1030-gcp", "5.15.0-1030.37"])

                # Assert that the expected ddeb file path was returned
                self.assertEqual(result, expected_ddeb_path)

        mock_pull.reset_mock()
        # Test reusing an existing ddeb file
        with mock.patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with mock.patch("time.time") as mock_time:
                mock_time.return_value = 1234567890.0

                result = uut.maybe_download_vmlinux_ddeb()

                # Assert that pullpkg was not invoked
                mock_pull.assert_not_called()

                # # Assert that the file's last access time was updated
                mock_utime.assert_called_once_with(
                    expected_ddeb_path, (1234567890.0, 1234567890.0))

                # Assert that the expected ddeb file path was returned
                self.assertEqual(result, expected_ddeb_path)

        # Test failing to download a new ddeb file
        mock_pull.return_value = Exception("Error")
        with mock.patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            with self.assertRaises(hotkdump.ExceptionWithLog):
                uut.maybe_download_vmlinux_ddeb()

    def test_post_run_ddeb_count_policy(self):
        # Set up test data
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.ddebs_path = "/path/to/ddebs"
        uut.ddeb_retention_enabled = True
        uut.ddeb_retention_max_age_secs = None
        uut.ddeb_retention_size_low_wm_bytes = None
        uut.ddeb_retention_size_high_wm_bytes = None
        uut.ddeb_retention_max_ddeb_count = 2

        with mock.patch(
            "os.remove") as mock_remove, mock.patch(
            "os.listdir") as mock_listdir, mock.patch(
            "os.stat") as mock_stat, mock.patch(
                "time.time") as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                'file1.ddeb', 'file2.ddeb', 'file3.txt', 'file4.ddeb']

            mock_stat.return_value.st_atime = 3600
            mock_stat.return_value.st_size = 500000

            # Call the function being tested
            uut.post_run()

            # Check if the function has removed the ddebs correctly
            mock_stat.assert_has_calls([
                mock.call('/path/to/ddebs/file1.ddeb'),
                mock.call('/path/to/ddebs/file2.ddeb')
            ])

            mock_listdir.assert_called_once_with('/path/to/ddebs')

            expected_calls = [
                mock.call('/path/to/ddebs/file4.ddeb')
            ]
            mock_remove.assert_has_calls(expected_calls)

            # Now bump the limit to 3, and re-test
            # The function must not remove any ddebs
            uut.ddeb_retention_max_ddeb_count = 3
            mock_remove.reset_mock()
            mock_listdir.reset_mock()
            mock_stat.reset_mock()

            uut.post_run()
            mock_remove.assert_not_called()

            # Disable the policy
            # The function must not remove any ddebs
            uut.ddeb_retention_max_ddeb_count = None
            mock_remove.reset_mock()
            mock_listdir.reset_mock()
            mock_stat.reset_mock()

            uut.post_run()
            mock_remove.assert_not_called()

    def test_post_run_ddeb_age_policy(self):
        # Set up test data
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.ddebs_path = "/path/to/ddebs"
        uut.ddeb_retention_enabled = True
        uut.ddeb_retention_size_low_wm_bytes = None
        uut.ddeb_retention_size_high_wm_bytes = None
        uut.ddeb_retention_max_ddeb_count = None
        uut.ddeb_retention_max_age_secs = 4000
        with mock.patch(
                "os.remove") as mock_remove, mock.patch(
                "os.listdir") as mock_listdir, mock.patch(
                "os.stat") as mock_stat, mock.patch(
                "time.time") as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                'file1.ddeb', 'file2.ddeb', 'file3.txt', 'file4.ddeb']

            mock_stat.side_effect = lambda fname: mock_stat_obj(fname, {
                "/path/to/ddebs/file1.ddeb": {"atime": 1234567890.0 + 1, "size": 3150},
                "/path/to/ddebs/file2.ddeb": {"atime": 1234567890.0 + 1, "size": 3150},
                "/path/to/ddebs/file4.ddeb": {"atime": 0, "size": 3150},
                # 50000 bytes in total
            })

            uut.post_run()

            mock_listdir.assert_called_once_with('/path/to/ddebs')

            expected_calls = [
                mock.call('/path/to/ddebs/file4.ddeb')
            ]

            not_expected_calls = [
                mock.call('/path/to/ddebs/file1.ddeb'),
                mock.call('/path/to/ddebs/file2.ddeb'),
                mock.call('/path/to/ddebs/file3.txt')
            ]

            mock_remove.assert_has_calls(expected_calls, any_order=True)
            mock_remove.assert_has_no_such_calls(not_expected_calls)

    def test_post_run_ddeb_total_size_policy(self):
        # Set up test data
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.ddebs_path = "/path/to/ddebs"
        uut.ddeb_retention_enabled = True
        uut.ddeb_retention_size_low_wm_bytes = 25000
        uut.ddeb_retention_size_high_wm_bytes = 50000
        uut.ddeb_retention_max_ddeb_count = None
        uut.ddeb_retention_max_age_secs = None
        with mock.patch(
                "os.remove") as mock_remove, mock.patch(
                "os.listdir") as mock_listdir, mock.patch(
                "os.stat") as mock_stat, mock.patch(
                "time.time") as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                'file1.ddeb', 'file2.ddeb', 'file3.txt', 'file4.ddeb']

            mock_stat.side_effect = lambda fname: mock_stat_obj(fname, {
                "/path/to/ddebs/file1.ddeb": {"atime": 0, "size": 15000},
                "/path/to/ddebs/file2.ddeb": {"atime": 1, "size": 15000},
                "/path/to/ddebs/file4.ddeb": {"atime": 2, "size": 20000},
                # 50000 bytes in total
            })

            uut.post_run()

            mock_listdir.assert_called_once_with('/path/to/ddebs')

            # file1, file2 and file4 are in total 50000 bytes in size, which exceeds
            # the high watermark. the algorithm will start removing ddebs one by one,
            # based on their last access time until total ddeb size is below low watermark.
            # file1 is the oldest and file4 is the newest, so the file1 and file2 must be
            # removed while file4 is untouched.

            expected_calls = [
                mock.call('/path/to/ddebs/file1.ddeb'),
                mock.call('/path/to/ddebs/file2.ddeb')
            ]

            not_expected_calls = [
                mock.call('/path/to/ddebs/file4.ddeb')
            ]

            mock_remove.assert_has_calls(expected_calls, any_order=True)
            mock_remove.assert_has_no_such_calls(not_expected_calls)

    def test_post_run_ddeb_retention_disabled(self):
        uut = hotkdump.hotkdump("1", "vmcore")
        uut.ddebs_path = "/path/to/ddebs"
        uut.ddeb_retention_enabled = False
        with mock.patch(
                "os.remove") as mock_remove, mock.patch(
                "os.listdir") as mock_listdir, mock.patch(
                "os.stat") as mock_stat, mock.patch(
                "time.time") as mock_time:
            mock_time.return_value = 1234567890.0
            mock_listdir.return_value = [
                'file1.ddeb', 'file2.ddeb', 'file3.txt', 'file4.ddeb']
            mock_stat.side_effect = lambda fname: mock_stat_obj(fname, {
                "/path/to/ddebs/file1.ddeb": {"atime": 0, "size": 15000},
                "/path/to/ddebs/file2.ddeb": {"atime": 1, "size": 15000},
                "/path/to/ddebs/file4.ddeb": {"atime": 2, "size": 20000},
                # 50000 bytes in total
            })
            uut.post_run()
            mock_listdir.assert_called_once_with('/path/to/ddebs')
            expected_calls = [
                mock.call('/path/to/ddebs/file1.ddeb'),
                mock.call('/path/to/ddebs/file2.ddeb'),
                mock.call('/path/to/ddebs/file4.ddeb')
            ]
            mock_remove.assert_has_calls(expected_calls, any_order=True)
