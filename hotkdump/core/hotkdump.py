#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""The main `hotkdump` class implementation."""

import os
import re
import subprocess
import logging
import sys
import tempfile
import shutil
import time
import textwrap
from datetime import datetime
from dataclasses import dataclass, field
import warnings

try:
    from importlib.resources import read_text
except ModuleNotFoundError:
    from importlib_resources import read_text


try:
    from ubuntutools.pullpkg import PullPkg

    # pylint: disable-next=import-private-name
    from ubuntutools.misc import _StderrProgressBar
    from ubuntutools import getLogger as ubuntutools_GetLogger
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "\n\n`hotkdump` needs ubuntu.pullpkg to function.\n"
        "Install it via `sudo apt install ubuntu-dev-tools`"
    ) from exc

from jinja2 import Template

from hotkdump.core.exceptions import ExceptionWithLog
from hotkdump.core.kdumpfile import KdumpFile
from hotkdump.core.utils import pretty_size
from hotkdump.core.folder_retention_manager import (
    FolderRetentionManager,
    FolderRetentionManagerSettings,
)
from hotkdump.core.utils import mktemppath, switch_cwd


@dataclass()
# pylint: disable-next=too-many-instance-attributes
class HotkdumpParameters:
    """Parameters for hotkdump."""

    dump_file_path: str
    internal_case_number: str = None
    interactive: bool = False
    output_file_path: str = mktemppath("hotkdump.out")
    log_file_path: str = mktemppath("hotkdump.log")
    ddebs_folder_path: str = mktemppath("hotkdump", "ddebs")
    ddeb_retention_settings: FolderRetentionManagerSettings = field(
        default_factory=lambda: FolderRetentionManagerSettings(
            enabled=True,
            size_hwm=(1 << 30) * 10,  # 10GiB,
            size_lwm=(1 << 30) * 2,  # 2GiB,
            max_age_secs=86400 * 15,  # 15 days
            max_count=5,
        )
    )
    print_vmcoreinfo_fields: list = None
    debug_file: str = None
    no_debuginfod: bool = False
    no_pullpkg: bool = False

    def validate_sanity(self):
        """Check whether option values are not contradicting and sane."""

        if all([self.no_debuginfod, self.no_pullpkg, not self.debug_file]):
            raise ExceptionWithLog(
                "At least one download method must be enabled (debuginfod, pullpkg)!"
            )

        self.ddeb_retention_settings.validate_sanity()


class Hotkdump:
    """the hotkdump class implementation."""

    def __init__(self, parameters: HotkdumpParameters):
        """initialize a new hotkdump instance

        Args:
            parameters: HotkdumpParameters

        Raises:
            ExceptionWithLog: when ddeb retention high watermark is less than low watermark
        """
        self.params = parameters
        self.crash_executable = self.find_crash_executable()
        self.params.validate_sanity()
        self.debuginfod_find_progress = None
        self.initialize_logging()

        logging.debug("%s", self.params)
        logging.info("reading vmcore file %s", self.params.dump_file_path)

        self.touch_file(self.params.output_file_path)
        tstamp_now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        vmcore_filename = self.params.dump_file_path.rsplit("/", 1)[-1]
        with open(self.params.output_file_path, "w", encoding="utf-8") as outfile:
            outfile.write(
                f"{tstamp_now}: processing {vmcore_filename} (CASE# {self.params.internal_case_number})\n"
            )

        self.kdump_file = KdumpFile(self.params.dump_file_path)

        logging.info("kernel version: %s", self.kdump_file.ddhdr.utsname.release)
        # pylint: disable=consider-using-with
        self.temp_working_dir = tempfile.TemporaryDirectory()
        logging.debug(
            "created %s temporary directory for the intermediary files",
            self.temp_working_dir.name,
        )

        # Create the ddeb path if not exists
        os.makedirs(self.params.ddebs_folder_path, exist_ok=True)

    def get_architecture(self):
        """Translate kdump architecture string to
        ubuntu architecture string.

        Raises:
            NotImplementedError: when architecture is not supported (yet)

        Returns:
            str: ubuntu arch string
        """

        arch_mappings = {"x86_64": "amd64", "aarch64": "arm64"}

        if self.kdump_file.ddhdr.utsname.machine in arch_mappings:
            return arch_mappings[self.kdump_file.ddhdr.utsname.machine]

        # FIXME(mkg): Add other architectures as well
        raise NotImplementedError(
            f"Machine architecture {self.kdump_file.ddhdr.utsname.machine} not recognized!"
        )

    @staticmethod
    def find_debuginfod_find_executable():
        """Path to the debuginfod-find executable."""
        return shutil.which("debuginfod-find")

    @staticmethod
    def find_crash_executable():
        """Try to locate crash executable in the environment.
        If the root directory has a crash symlink,
        Returns:
            str: <root_dir>/crash if script path contains a `crash` symlink
            str: result of `which crash` otherwise
        """
        crash_symlink_path = os.path.dirname(os.path.realpath(__file__)) + "/../crash"
        crash = (
            crash_symlink_path
            if os.path.exists(crash_symlink_path)
            else shutil.which("crash")
        )
        if crash is None:
            raise ExceptionWithLog("Could not find the `crash` executable!")
        return crash

    def initialize_logging(self):
        """Initialize logging for hotkdump"""
        self.logger = logging.getLogger()
        file_logger = logging.FileHandler(filename=self.params.log_file_path)
        console_logger = logging.StreamHandler(sys.stdout)
        # Allow log level overrides from environment
        level = os.environ.get("HOTKDUMP_LOGLEVEL", "INFO").upper()

        for logger in (file_logger, console_logger, self.logger):
            logger.setLevel(level)

        for logger in (file_logger, console_logger):
            self.logger.addHandler(logger)

        # Only display error messages and the download status from ubuntutools
        for handler in ubuntutools_GetLogger().handlers:
            handler.addFilter(
                # pylint: disable=magic-value-comparison
                lambda r: "Downloading" in r.msg or r.levelno >= logging.ERROR
            )

    @staticmethod
    def touch_file(fname):
        """Create an empty file."""
        with open(fname, "w", encoding="utf-8"):
            pass

    def write_crash_commands_file(self):
        """Render and write the crash_commands file."""
        commands_file = f"{self.temp_working_dir.name}/crash_commands"
        of_path = self.params.output_file_path

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            # Read & render the template
            jinja_template_content = read_text(
                "hotkdump.templates", "crash_commands.jinja"
            )

        template = Template(jinja_template_content)
        rendered_content = template.render(
            output_file_path=of_path, commands_file_name=commands_file
        )

        with open(commands_file, "w", encoding="utf-8") as ccfile:
            final_cmdfile_contents = textwrap.dedent(rendered_content).strip()
            ccfile.write(final_cmdfile_contents)
            logging.debug(
                "command file %s rendered with contents: %s",
                commands_file,
                final_cmdfile_contents,
            )
            return ccfile.name

    @staticmethod
    def exec(command: str, args: str, working_dir=None) -> subprocess.Popen:
        """Execute a command with arguments in specified working directory (optional).
        The exec() will wait for the command to complete.

        Returns:
            Popen: Popen object representing the executed command
        """
        logging.info("Executing command: `%s %s`", command, args)
        with subprocess.Popen(f"{command} {args}", shell=True, cwd=working_dir) as p:
            p.wait()
        return p

    @staticmethod
    def strip_release_variant_tags(value):
        """Strip a version string from its' release variant tags,
        e.g. (5.4.0-146-generic -> 5.4.0-146)

        Args:
            value (_type_): Version string with release variant tags

        Raises:
            ExceptionWithLog: when stripped string does not form a valid version

        Returns:
            str: Version string without release variant tags
        """
        # see: https://ubuntu.com/kernel/variants#version-specific-kernels
        tags = sorted(
            [
                "generic",
                "lowlatency",
                "generic-hwe",
                "lowlatency-hwe",
                "kvm",
                "aws",
                "azure",
                "azure-fde",
                "gcp",
                "gke",
                "snapdragon",
                "raspi2",
            ],
            key=len,
            reverse=True,
        )
        version_specific_tags = sorted(
            [
                "generic-hwe-{}",
                "generic-hwe-{}",
                "lowlatency-hwe-{}",
                "lowlatency-hwe-{}",
            ],
            key=len,
            reverse=True,
        )
        versions = ["16.04", "18.04", "20.04", "22.04", "24.04"]

        for vtag in version_specific_tags:
            for version in versions:
                value = value.replace("-" + vtag.format(version) + "-edge", "")
                value = value.replace("-" + vtag.format(version), "")

        for tag in tags:
            value = value.replace(f"-{tag}", "")
            value = value.replace(f"-{tag}-edge", "")

        validator_regex = re.compile(r"^\d+\.\d+\.\d+-\d+$")
        if not validator_regex.match(value):
            raise ExceptionWithLog(
                f"The stripped release did not yield a valid version! ({value})"
            )

        return value

    def _digest_debuginfod_find_output(self, line):
        download_start_match = re.match("committed to url", line)
        http_match = re.match(r"header x-debuginfod-(\w+): (.*)", line)

        if download_start_match:
            logging.info("debuginfod-find: found, downloading...")

        if http_match:
            name, content = http_match.groups()

            log_fns = {
                "size": lambda: logging.info(
                    "debuginfod-find: vmlinux size: %s", pretty_size(int(content))
                ),
                "archive": lambda: logging.info(
                    "debuginfod-find: `.ddeb` file name: %s", content
                ),
                "file": lambda: logging.info(
                    "debuginfod-find: vmlinux file name: %s", content
                ),
            }

            if name in log_fns:
                log_fns[name]()

        progress_match = re.match(r"Progress ([0-9]+) \/ ([0-9]+)", line)

        if progress_match:
            if not self.debuginfod_find_progress:
                # In order to be consistent,.we're using the same
                # progress bar that PullPkg uses.
                self.debuginfod_find_progress = _StderrProgressBar(
                    os.get_terminal_size(sys.stderr.fileno()).columns
                )
            current, maximum = [int(v) for v in progress_match.groups()]
            if maximum > 0:
                pct = int((current / maximum) * 100)
                self.debuginfod_find_progress.update(pct, 100)

    def maybe_download_vmlinux_via_debuginfod(self):
        """Try downloading vmlinux image with debug information
        using debuginfod-find."""
        try:
            if not self.params.no_debuginfod:
                debuginfod_find_path = self.find_debuginfod_find_executable()
                if not debuginfod_find_path:
                    logging.debug("debuginfod-find is not present in environment.")
                    return None

                build_id = self.kdump_file.vmcoreinfo.get("BUILD-ID")
                if not build_id:
                    logging.info(
                        "cannot use debuginfod-find - BUILD-ID not found in vmcoreinfo!"
                    )
                    return None

                debuginfod_find_args = f"-vvv debuginfo {build_id}"
                logging.info(
                    "Invoking debuginfod-find with %s", str(debuginfod_find_args)
                )

                line = ""
                # $HOME/. cache/debuginfod_client/
                with subprocess.Popen(
                    args=f"{debuginfod_find_path} {debuginfod_find_args}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                ) as proc:
                    while proc.poll() is None:
                        lo = proc.stdout.readline()
                        if lo and not lo.isspace():
                            line = lo.strip()
                        self._digest_debuginfod_find_output(line)

                    result = proc.wait()

                if result == 0:
                    # line should point to the vmcore file
                    logging.info("debuginfod-find: succeeded, vmcore path: `%s`", line)
                    return line

                logging.info(
                    "debuginfod-find: download for BUILD-ID `%s` failed with `%s`",
                    build_id,
                    line,
                )
            return None
        finally:
            self.debuginfod_find_progress = None

    def maybe_download_vmlinux_via_pullpkg(self):
        """Download debug vmlinux image .ddeb for current dump file
        via pullpkg (if not already present).

        Returns:
            str: The path to the .ddeb file
        """
        if not self.params.no_pullpkg:
            # Parameters are: release, release{without -generic}, normalized version, arch
            # linux-image-unsigned-5.4.0-135-generic-dbgsym_5.4.0-135.152_amd64.ddeb
            ddeb_name_format = "linux-image-unsigned-{}-dbgsym_{}.{}_{}.ddeb"
            expected_ddeb_path = ddeb_name_format.format(
                self.kdump_file.ddhdr.utsname.release,
                self.strip_release_variant_tags(self.kdump_file.ddhdr.utsname.release),
                self.kdump_file.ddhdr.utsname.normalized_version,
                self.get_architecture(),
            )

            with switch_cwd(self.params.ddebs_folder_path):
                # Check if we already have the .ddeb
                if os.path.exists(expected_ddeb_path):
                    # Already exists, do not download again
                    # TODO(mkg): Verify SHA checksum?
                    logging.info(
                        "The .ddeb file %s already exists, re-using it",
                        expected_ddeb_path,
                    )
                    # Ensure that the file's last access time is updated
                    os.utime(expected_ddeb_path, (time.time(), time.time()))
                    extracted_vmlinux = self.extract_vmlinux_ddeb(expected_ddeb_path)
                    if extracted_vmlinux:
                        return expected_ddeb_path
                    logging.error("Failed to extract ddeb file")
                    return None

                logging.info(
                    "Downloading `vmlinux` image for kernel version %s, please be patient...",
                    self.kdump_file.ddhdr.utsname.release,
                )

                # (mkg): To force pull-lp-ddebs to use launchpadlibrarian.net for download
                # pass an empty mirror list env variable to the hotkdump, e.g.:
                # UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= python3 hotkdump.py -c 123 -d dump.dump
                pull_args = [
                    "--distro",
                    "ubuntu",
                    "--arch",
                    self.get_architecture(),
                    "--pull",
                    "ddebs",
                    f"linux-image-unsigned-{self.kdump_file.ddhdr.utsname.release}",
                    f"{self.strip_release_variant_tags(self.kdump_file.ddhdr.utsname.release)}"
                    f".{self.kdump_file.ddhdr.utsname.normalized_version}",
                ]
                logging.info("Invoking PullPkg().pull with %s", str(pull_args))

                PullPkg().pull(pull_args)
                if not os.path.exists(expected_ddeb_path):
                    raise ExceptionWithLog(f"failed to download {expected_ddeb_path}")
            extracted_vmlinux = self.extract_vmlinux_ddeb(expected_ddeb_path)
            if extracted_vmlinux:
                return expected_ddeb_path
            logging.error("Failed to extract ddeb file.")
        return None

    def extract_vmlinux_ddeb(self, ddeb_file):
        """Extract the given vmlinux ddeb file to temp_working_dir/ddeb-root

        Args:
            ddeb_file (str): .ddeb file to extract

        Returns:
            str: Path to the vmlinux file in the extracted folder
        """
        ddeb_extract_dst = f"{self.temp_working_dir.name}/ddeb-root"
        dpkg_deb_args = f"-x {ddeb_file} {ddeb_extract_dst}"
        logging.info(
            "Extracting %s to %s, please be patient...", ddeb_file, ddeb_extract_dst
        )
        with switch_cwd(self.params.ddebs_folder_path):
            result = self.exec("dpkg", dpkg_deb_args)
        if result.returncode != 0:
            raise ExceptionWithLog(
                f"failed to extract {ddeb_file}: {result.stderr.readlines()}"
            )

        return (
            self.temp_working_dir.name
            + f"/ddeb-root/usr/lib/debug/boot/vmlinux-{self.kdump_file.ddhdr.utsname.release}"
        )

    def summarize_vmcore_file(self, vmlinux_path: str):
        """Print a summary of the vmcore file to the output file"""
        logging.info(
            "Loading `vmcore` file %s into `crash`, please wait..",
            self.params.dump_file_path,
        )
        commands_file_path = self.write_crash_commands_file()
        self.exec(
            self.crash_executable,
            f"-x -i {commands_file_path} -s {self.params.dump_file_path} {vmlinux_path}",
        )
        logging.info(
            "See %s for logs, %s for outputs",
            self.params.log_file_path,
            self.params.output_file_path,
        )

    def launch_crash(self, vmlinux_path: str):
        """Launch the `crash` application with the user-given vmcore and
        downloaded vmlinux image file
        """
        logging.info(
            "Loading `vmcore` file %s into `crash`, please wait..",
            self.params.dump_file_path,
        )
        self.exec(
            self.crash_executable, f"-x {self.params.dump_file_path} {vmlinux_path}"
        )

    DBG_DDEB = ".ddeb"
    DBG_VMLINUX = "vmlinux"

    def debug_file_type(self):
        """Return the current file type by checking the extension"""
        if self.params.debug_file:
            filename = os.path.basename(self.params.debug_file).split("/")[-1]
            if filename.endswith(self.DBG_DDEB):
                return self.DBG_DDEB
            if filename.startswith(self.DBG_VMLINUX):
                return self.DBG_VMLINUX
        return None

    def maybe_get_user_specified_vmlinux(self):
        """return the vmlinux file path from the user specified debug file"""
        if self.params.debug_file:
            dbg_type = self.debug_file_type()
            vmlinux_ddeb = self.params.debug_file if dbg_type == self.DBG_DDEB else None
            extracted_vmlinux = (
                self.params.debug_file if dbg_type == self.DBG_VMLINUX else None
            )
            if vmlinux_ddeb:
                extracted_vmlinux = self.extract_vmlinux_ddeb(vmlinux_ddeb)
            if extracted_vmlinux:
                return extracted_vmlinux
            logging.error("Failed to retrieve vmlinux file")
        return None

    def run(self):
        """Run hotkdump main routine."""
        try:
            if self.params.print_vmcoreinfo_fields:
                for key in self.params.print_vmcoreinfo_fields:
                    print(f"{key}={self.kdump_file.vmcoreinfo.get(key)}")
                return

            extracted_vmlinux = (
                self.maybe_get_user_specified_vmlinux()
                or self.maybe_download_vmlinux_via_debuginfod()
                or self.maybe_download_vmlinux_via_pullpkg()
            )
            if not extracted_vmlinux:
                logging.error("vmlinux image with debug symbols not found, aborting")
                return

            if self.params.interactive:
                self.launch_crash(extracted_vmlinux)
            else:
                self.summarize_vmcore_file(extracted_vmlinux)

        finally:
            self.post_run()

    def post_run(self):
        """Perform post-run tasks"""
        retention_mgr = FolderRetentionManager(
            [self.params.ddebs_folder_path], lambda file: file.endswith(".ddeb")
        )
        retention_mgr.load_policies_from_settings(self.params.ddeb_retention_settings)
        retention_mgr.execute_policies()
