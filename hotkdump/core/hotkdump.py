#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""The main `hotkdump` class implementation.
"""

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

try:
    from ubuntutools.pullpkg import PullPkg
    from ubuntutools import getLogger as ubuntutools_GetLogger
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError("\n\n`hotkdump` needs ubuntu.pullpkg to function.\n"
                              "Install it via `sudo apt install ubuntu-dev-tools`") from exc

from hotkdump.core.exceptions import ExceptionWithLog
from hotkdump.core.kdumpfile import KdumpFile
from hotkdump.core.folder_retention_manager import(
    FolderRetentionManager,
    FolderRetentionManagerSettings
)
from hotkdump.core.utils import (
    mktemppath,
    switch_cwd
)



@dataclass()
class HotkdumpParameters:
    """Parameters for hotkdump."""
    dump_file_path: str
    sf_case_number: str = None
    interactive: bool = False
    output_file_path: str = mktemppath("hotkdump.out")
    log_file_path: str = mktemppath("hotkdump.log")
    ddebs_folder_path: str = mktemppath("hotkdump", "ddebs")
    ddeb_retention_settings: FolderRetentionManagerSettings = field(
        default_factory=lambda : FolderRetentionManagerSettings(
            enabled = True,
            size_hwm = (1<<30) * 10, # 10GiB,
            size_lwm = (1<<30) * 2, # 2GiB,
            max_age_secs = 86400 * 15, # 15 days
            max_count = 5
        ))

    def validate_sanity(self):
        """Check whether option values are not contradicting and sane."""
        self.ddeb_retention_settings.validate_sanity()

class Hotkdump:
    """the hotkdump class implementation.
    """

    def __init__(self, parameters: HotkdumpParameters):
        """initialize a new hotkdump instance

        Args:
            case_number (str): Salesforce case number
            vmcore_file (str): kdump file path
            output_file_path (str, optional): hotkdump output file path. Defaults to default_output_file.
            log_file_path (str, optional): hotkdump log output path. Defaults to default_log_file.
            ddebs_path (str, optional): the path to save the downloaded ddeb files. Defaults to default_ddebs_path.

        Raises:
            ExceptionWithLog: when ddeb retention high watermark is less than low watermark
        """
        self.params = parameters
        self.crash_executable = self.find_crash_executable()
        self.params.validate_sanity()
        self.initialize_logging()

        logging.info("reading vmcore file %s", self.params.dump_file_path)

        self.touch_file(self.params.output_file_path)
        tstamp_now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        vmcore_filename = self.params.dump_file_path.rsplit('/', 1)[-1]
        with open(self.params.output_file_path, "w", encoding="utf-8") as outfile:
            outfile.write(f"{tstamp_now}: processing {vmcore_filename} (SF# {self.params.sf_case_number})\n")

        self.kdump_file = KdumpFile(self.params.dump_file_path)

        logging.info("kernel version: %s", self.kdump_file.ddhdr.utsname.release)
        # pylint: disable=consider-using-with
        self.temp_working_dir = tempfile.TemporaryDirectory()
        logging.debug(
            "created %s temporary directory for the intermediary files", self.temp_working_dir.name)
        self.commands_file_path = self.write_crash_commands_file()

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
            f"Machine architecture {self.kdump_file.ddhdr.utsname.machine} not recognized!")

    def run(self, interactive=False):
        """Run hotkdump main routine."""
        try:
            vmlinux_ddeb = self.maybe_download_vmlinux_ddeb()
            if vmlinux_ddeb == "":
                logging.error("vmlinux ddeb dowload failed.")
                return

            extracted_vmlinux = self.extract_vmlinux_ddeb(vmlinux_ddeb)

            if interactive:
                self.launch_crash(extracted_vmlinux)
            else:
                self.summarize_vmcore_file(extracted_vmlinux)

        finally:
            self.post_run()


    @staticmethod
    def find_crash_executable():
        """Try to locate crash executable in the environment.
        If the root directory has a crash symlink,
        Returns:
            str: <root_dir>/crash if script path contains a `crash` symlink
            str: result of `which crash` otherwise
        """
        crash_symlink_path = os.path.dirname(
            os.path.realpath(__file__)) + "/../crash"
        crash = crash_symlink_path if os.path.exists(
            crash_symlink_path) else shutil.which("crash")
        if crash is None:
            raise ExceptionWithLog("Could not find the `crash` executable!")
        return crash

    def initialize_logging(self):
        """Initialize logging for hotkdump
        """
        self.logger = logging.getLogger()
        file_logger = logging.FileHandler(filename=self.params.log_file_path)
        console_logger = logging.StreamHandler(sys.stdout)
        # Allow log level overrides from environment
        level = os.environ.get('HOTKDUMP_LOGLEVEL', 'INFO').upper()

        for logger in (file_logger, console_logger, self.logger):
            logger.setLevel(level)

        for logger in (file_logger, console_logger):
            self.logger.addHandler(logger)

        # Only display error messages and the download status from ubuntutools
        for handler in ubuntutools_GetLogger().handlers:
            handler.addFilter(
                # pylint: disable=magic-value-comparison
                lambda r: "Downloading" in r.msg or r.levelno >= logging.ERROR)

    @staticmethod
    def touch_file(fname):
        """Create an empty file."""
        with open(fname, "w", encoding="utf-8"):
            pass

    def write_crash_commands_file(self):
        """The crash_commands file we generate should look like

            !echo "Output of sys\n" >> hotkdump.out
            sys >> hotkdump.out
            !echo "\nOutput of bt\n" >> hotkdump.out
            bt >> hotkdump.out
            !echo "\nOutput of log with audit messages filtered out\n" >> hotkdump.out
            log | grep -vi audit >> hotkdump.out
            !echo "\nOutput of kmem -i\n" >> hotkdump.out
            kmem -i >> hotkdump.out
            !echo "\nOutput of dev -d\n" >> hotkdump.out
            dev -d >> hotkdump.out
            !echo "\nLongest running blocked processes\n" >> hotkdump.out
            ps -m | grep UN | tail >> hotkdump.out
            quit >> hotkdump.out
        """
        commands_file = f"{self.temp_working_dir.name}/crash_commands"
        of_path = self.params.output_file_path

        # pylint
        with open(commands_file, "w", encoding="utf-8") as ccfile:
            # (mkg): the file uses self-append to evaluate commands depend on
            # the information extracted from a prior command invocation. This
            # is possible because POSIX guarantees that:
            #   "If a read() of file data can be proven (by any means) to occur
            #   after a write() of the data, it must reflect that write(), even
            #   if the calls are made by different processes."
            # pylint: disable=line-too-long
            commands_file_content = fr"""
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'sys'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            sys >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'bt'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            bt >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'log' with audit messages filtered out" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            log | grep -vi audit >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'kmem -i'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            kmem -i >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'dev -d'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            dev -d >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'mount'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            mount >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'files'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            files >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'vm'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            vm >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Output of 'net'" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            net >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Longest running blocked processes" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            ps -m | grep UN | tail >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            !echo "Top 20 memory consumers" >> {of_path}
            !echo "---------------------------------------" >> {of_path}
            ps -G | sed 's/>//g' | sort -k 8,8 -n |  awk '$8 ~ /[0-9]/{{ $8 = $8/1024" MB"; print }}' | tail -20 | sort -r -k8,8 -g >> {of_path}
            !echo "\n!echo '---------------------------------------' >> {of_path}" >> {commands_file}
            !echo "\n!echo 'BT of the longest running blocked process' >> {of_path}" >> {commands_file}
            !echo "\n!echo '---------------------------------------' >> {of_path}" >> {commands_file}
            ps -m | grep UN | tail -n1 | grep -oE "PID: [0-9]+" | grep -oE "[0-9]+" | awk '{{print "bt " $1 " >> {of_path}"}}' >> {commands_file}
            !echo "\nquit >> {of_path}" >> {commands_file}
            !echo "" >> {of_path}"""
            # (mkg): The last empty echo is important to allow
            # crash to pick up the commands appended to the command
            # file at the runtime.
            final_cmdfile_contents = textwrap.dedent(
                commands_file_content).strip()
            ccfile.write(final_cmdfile_contents)
            logging.debug(
                "command file %s rendered with contents: %s", commands_file, final_cmdfile_contents)
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
        tags = sorted(["generic", "lowlatency", "generic-hwe",
                       "lowlatency-hwe", "kvm", "aws", "azure", "azure-fde",
                       "gcp", "gke", "snapdragon", "raspi2"], key=len, reverse=True)
        version_specific_tags = sorted([
            "generic-hwe-{}", "generic-hwe-{}", "lowlatency-hwe-{}", "lowlatency-hwe-{}"], key=len, reverse=True)
        versions = ["16.04", "18.04", "20.04", "22.04", "24.04"]

        for vtag in version_specific_tags:
            for version in versions:
                value = value.replace("-" + vtag.format(version) + '-edge', '')
                value = value.replace("-" + vtag.format(version), '')

        for tag in tags:
            value = value.replace(f"-{tag}", '')
            value = value.replace(f"-{tag}-edge", '')

        validator_regex = re.compile(r"^\d+\.\d+\.\d+-\d+$")
        if not validator_regex.match(value):
            raise ExceptionWithLog(
                f"The stripped release did not yield a valid version! ({value})")

        return value

    def maybe_download_vmlinux_ddeb(self):
        """Download debug vmlinux image .ddeb for current dump file
        via pullpkg (if not already present).

        Returns:
            str: The path to the .ddeb file
        """
        # Parameters are: release, release{without -generic}, normalized version, arch
        # linux-image-unsigned-5.4.0-135-generic-dbgsym_5.4.0-135.152_amd64.ddeb
        ddeb_name_format = "linux-image-unsigned-{}-dbgsym_{}.{}_{}.ddeb"
        expected_ddeb_path = ddeb_name_format.format(
            self.kdump_file.ddhdr.utsname.release,
            self.strip_release_variant_tags(self.kdump_file.ddhdr.utsname.release),
            self.kdump_file.ddhdr.utsname.normalized_version,
            self.get_architecture()
        )

        with switch_cwd(self.params.ddebs_folder_path):
            # Check if we already have the .ddeb
            if os.path.exists(expected_ddeb_path):
                # Already exists, do not download again
                # TODO(mkg): Verify SHA checksum?
                logging.info(
                    "The .ddeb file %s already exists, re-using it", expected_ddeb_path)
                # Ensure that the file's last access time is updated
                os.utime(expected_ddeb_path, (time.time(), time.time()))
                return expected_ddeb_path

            logging.info(
                "Downloading `vmlinux` image for kernel version %s, please be patient...",
                self.kdump_file.ddhdr.utsname.release)

            # (mkg): To force pull-lp-ddebs to use launchpadlibrarian.net for download
            # pass an empty mirror list env variable to the hotkdump, e.g.:
            # UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= python3 hotkdump.py -c 123 -d dump.dump
            pull_args = ["--distro", "ubuntu", "--arch", self.get_architecture(), "--pull", "ddebs",
                         f"linux-image-unsigned-{self.kdump_file.ddhdr.utsname.release}",
                         f"{self.strip_release_variant_tags(self.kdump_file.ddhdr.utsname.release)}"
                         f".{self.kdump_file.ddhdr.utsname.normalized_version}"]
            logging.info("Invoking PullPkg().pull with %s", str(pull_args))

            PullPkg().pull(pull_args)
            if not os.path.exists(expected_ddeb_path):
                raise ExceptionWithLog(
                    f"failed to download {expected_ddeb_path}")

        return expected_ddeb_path

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
            "Extracting %s to %s, please be patient...", ddeb_file, ddeb_extract_dst)
        with switch_cwd(self.params.ddebs_folder_path):
            result = self.exec("dpkg", dpkg_deb_args)
        if result.returncode != 0:
            raise ExceptionWithLog(
                f"failed to extract {ddeb_file}: {result.stderr.readlines()}")

        return self.temp_working_dir.name + \
            f"/ddeb-root/usr/lib/debug/boot/vmlinux-{self.kdump_file.ddhdr.utsname.release}"

    def summarize_vmcore_file(self, vmlinux_path:str):
        """Print a summary of the vmcore file to the output file
        """
        logging.info("Loading `vmcore` file %s into `crash`, please wait..", self.params.dump_file_path)

        self.exec(self.crash_executable,
                  f"-i {self.commands_file_path} -s {self.params.dump_file_path} {vmlinux_path}")
        logging.info("See %s for logs, %s for outputs", self.params.log_file_path, self.params.output_file_path)

    def launch_crash(self, vmlinux_path:str):
        """Launch the `crash` application with the user-given vmcore and
        downloaded vmlinux image file
        """
        logging.info(
            "Loading `vmcore` file %s into `crash`, please wait..", self.params.dump_file_path)
        self.exec(self.crash_executable,
                  f"{self.params.dump_file_path} {vmlinux_path}")

    def post_run(self):
        """Perform post-run tasks
        """
        retention_mgr = FolderRetentionManager([self.params.ddebs_folder_path], lambda file : file.endswith(".ddeb"))
        retention_mgr.load_policies_from_settings(self.params.ddeb_retention_settings)
        retention_mgr.execute_policies()
