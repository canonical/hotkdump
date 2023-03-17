#!/usr/bin/env python3
import argparse
import os
import subprocess
import logging
import sys
import tempfile
import shutil
import time

try:
    from ubuntutools.pullpkg import PullPkg
    from ubuntutools import getLogger as ubuntutools_GetLogger
except ModuleNotFoundError:
    raise ModuleNotFoundError("\n\n`hotkdump` needs ubuntu.pullpkg to function.\n"
                              "Install it via `sudo apt install ubuntu-dev-tools`")

# am sure will need all this later
from typing import Dict, List, Tuple, Union


"""
TODOS:

1) need to figure out when a new vmcore is uploaded to files.canonical
and for which case, for automatically updating the case 

2) leverage the filemover, and think about this as a generic application or a library

3) update cases with a internal comment of a link to hotkdump.out output

"""


class ExceptionWithLog(Exception):

    def __init__(self, msg) -> None:
        logging.error(msg)
        super().__init__(msg)


class kdump_file_header(object):
    """Helper class for reading kdump file
    headers
    """

    def __init__(self, kdump_file_path) -> None:
        """Parse kdump file header and expose
        them as member variables

        Args:
            kdump_file_path (str): The kdump file path

        Raises:
            Exception: If the kdump_file_path is not recognized as a kdump file
        """
        with open(kdump_file_path, 'rb') as fd:
            magic = fd.read(8)
            if not magic == b'KDUMP   ':
                raise ExceptionWithLog(
                    f"{kdump_file_path} is not a kernel crash dump file")

            version = int.from_bytes(fd.read(4), byteorder='little')
            self.kdump_version = version
            self.system = self.readcstr(fd)
            self.node = self.readcstr(fd)
            self.release = self.readcstr(fd)
            self.version = self.readcstr(fd)
            self.machine = self.readcstr(fd)
            self.domain = self.readcstr(fd)
            self.normalized_version = self.version.split("-")[0].lstrip("#")

    @staticmethod
    def seek_to_first_non_nul(f):
        """Seek file offset to the first non-NUL character
        starting from the current offset.
        Args:
            f(file): File to seek
        """
        pos = f.tell()
        while f.read(1) == b'\x00':
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
            if (b is None) or (b == b'\x00'):
                kdump_file_header.seek_to_first_non_nul(f)
                return str(''.join(buf))
            else:
                buf += b.decode('ascii')


default_output_file = "hotkdump.out"
default_log_file = "hotkdump.log"


class hotkdump:

    def __init__(self, case_number, vmcore_file, output_file_path=default_output_file, log_file_path=default_log_file):
        self.output_file = output_file_path
        self.log_file = log_file_path
        self.case_number = case_number
        self.vmcore_file = vmcore_file
        self.crash_executable = self.find_crash_executable()
        self.initialize_logging()

        logging.info(
            f"initializing hotkdump, SF#{self.case_number}, vmcore: {self.vmcore_file}")

        with open(self.output_file, "w"):
            pass

        self.kdump_header = kdump_file_header(self.vmcore_file)

        logging.info(
            f"kernel version: {self.kdump_header.release}")
        self.temp_working_dir = tempfile.TemporaryDirectory()
        logging.info(
            f"created {self.temp_working_dir.name} temporary directory for the intermediary files")
        self.commands_file_path = self.write_crash_commands_file()

    def get_architecture(self):
        if self.kdump_header.machine == "x86_64":
            return "amd64"
        # FIXME(mkg): Add other architectures as well
        raise NotImplementedError(
            f"Machine architecture {self.kdump_header.machine} not recognized!")

    @staticmethod
    def find_crash_executable():
        """Try to locate crash executable in the environment.
        If the root directory has a crash symlink, 
        Returns:
            str: <root_dir>/crash if script path contains a `crash` symlink
            str: result of `which crash` otherwise 
        """
        crash_symlink_path = os.path.dirname(
            os.path.realpath(__file__)) + "/crash"
        crash = crash_symlink_path if os.path.exists(
            crash_symlink_path) else shutil.which("crash")
        if crash is None:
            raise ExceptionWithLog("Could not find the `crash` executable!")
        return crash

    def initialize_logging(self):
        """Initialize logging for hotkdump
        """
        self.logger = logging.getLogger()
        file_logger = logging.FileHandler(filename=self.log_file)
        file_logger.setLevel(logging.INFO)
        console_logger = logging.StreamHandler(sys.stdout)
        console_logger.setLevel(logging.DEBUG)
        self.logger.addHandler(file_logger)
        self.logger.addHandler(console_logger)
        self.logger.setLevel(logging.INFO)

        # Only display error messages and the download status from ubuntutools
        for handler in ubuntutools_GetLogger().handlers:
            handler.addFilter(
                lambda r: "Downloading" in r.msg or r.levelno >= logging.ERROR)

    def write_crash_commands_file(self):
        """
        The crash_commands file we generate should look like

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
            !echo "\nOldest blocked processes\n" >> hotkdump.out
            ps -m | grep UN | tail >> hotkdump.out
            quit >> hotkdump.out
        """
        with open("{}{}".format(self.temp_working_dir.name, "/crash_commands"), "w") as ccfile:
            # FIXME(mkg): Move this to a jinja template?
            ccfile.write(f"!echo \"Output of sys\\n\" >> {self.output_file}\n")
            ccfile.write(f"sys >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of bt\\n\" >> {self.output_file}\n")
            ccfile.write(f"bt >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of log with audit messages filtered out\\n\" >> {self.output_file}\n")
            ccfile.write(f"log | grep -vi audit >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of kmem -i\\n\" >> {self.output_file}\n")
            ccfile.write(f"kmem -i >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of dev -d\\n\" >> {self.output_file}\n")
            ccfile.write(f"dev -d >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of mount\\n\" >> {self.output_file}\n")
            ccfile.write(f"mount >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of files\\n\" >> {self.output_file}\n")
            ccfile.write(f"files >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOutput of vm\\n\" >> {self.output_file}\n")
            ccfile.write(f"vm >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nOldest blocked processes\\n\" >> {self.output_file}\n")
            ccfile.write(f"ps -m | grep UN | tail >> {self.output_file}\n")
            ccfile.write(
                f"!echo \"\\nTop 20 memory consumers\\n\" >> {self.output_file}\n")
            ccfile.write(
                "ps -G | sed 's/>//g' | sort -k 8,8 -n |  awk '$8 ~ /[0-9]/{ $8 = $8/1024\" MB\"; print }' | tail -20 | sort -r -k8,8 -g " f">> {self.output_file}\n")
            ccfile.write(f"quit >> {self.output_file}\n")
            return ccfile.name

    @staticmethod
    def exec(command: str, args: str, working_dir=None) -> subprocess.Popen:
        """Execute a command with arguments in specified working directory (optional).
        The exec() will wait for the command to complete.

        Returns:
            Popen: Popen object representing the executed command
        """
        logging.info(f"Executing command: `{command} {args}`")
        p = subprocess.Popen(f"{command} {args}", shell=True, cwd=working_dir)
        p.wait()
        return p

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
            self.kdump_header.release,
            self.kdump_header.release.replace('-generic', ''),
            self.kdump_header.normalized_version,
            self.get_architecture()
        )

        # Check if we already have the .ddeb
        if os.path.exists(expected_ddeb_path):
            # Already exists, do not download again
            # TODO(mkg): Verify SHA checksum?
            logging.info(
                f"The .ddeb file {expected_ddeb_path} already exists, re-using it")
            return expected_ddeb_path

        logging.info(
            f"Downloading `vmlinux` image for kernel version {self.kdump_header.release}, please be patient...")

        # (mkg): To force pull-lp-ddebs to use launchpadlibrarian.net for download
        # pass an empty mirror list env variable to the hotkdump, e.g.:
        # UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= python3 hotkdump.py -c 123 -d dump.dump
        pull_args = ["--distro", "ubuntu", "--arch", self.get_architecture(), "--pull", "ddebs",
                     f"linux-image-unsigned-{self.kdump_header.release}",
                     f"{self.kdump_header.release.replace('-generic', '')}.{self.kdump_header.normalized_version}"]
        logging.info(f"Invoking PullPkg().pull with {str(pull_args)}")

        PullPkg().pull(pull_args)

        if not os.path.exists(expected_ddeb_path):
            raise ExceptionWithLog(f"failed to download {expected_ddeb_path}")

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
        logging.debug(f"extracting {ddeb_file} to {ddeb_extract_dst}")
        result = self.exec("dpkg", dpkg_deb_args)
        if not (result.returncode == 0):
            raise ExceptionWithLog(
                f"failed to extract {ddeb_file}: {result.stderr.readlines()}")

        self.vmlinux_path = self.temp_working_dir.name + \
            f"/ddeb-root/usr/lib/debug/boot/vmlinux-{self.kdump_header.release}"
        return self.vmlinux_path

    def summarize_vmcore_file(self):
        """Print a summary of the vmcore file to the output file
        """
        logging.info(
            f"Loading `vmcore` file {self.vmcore_file} into `crash`, please wait..")
        self.exec(self.crash_executable,
                  f"-i {self.commands_file_path} -s {self.vmcore_file} {self.vmlinux_path}")
        logging.info("See hotkdump.log for logs")
        logging.info("See hotkdump.out for outputs")

    def launch_crash(self):
        """Launch the `crash` application with the user-given vmcore and 
        downloaded vmlinux image file
        """
        logging.info(
            f"Loading `vmcore` file {self.vmcore_file} into `crash`, please wait..")
        self.exec(self.crash_executable,
                  f"{self.vmcore_file} {self.vmlinux_path}")


def main():
    """Entry point for command-line invocations
    """
    start = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--casenum",  required=True,
                    help="SF case number")
    ap.add_argument("-d", "--dump", required=True,
                    help="name of vmcore file")
    ap.add_argument("-i", "--interactive",
                    help="start `crash` in interactive mode instead of printing summary",
                    action='store_true')
    ap.add_argument("-o", "--output-path",
                    help="output file path for the summary",
                    default=default_output_file)
    ap.add_argument("-l", "--log-file",
                    help="log file path", default=default_log_file)
    args = vars(ap.parse_args())
    hkd = hotkdump(args['casenum'], args['dump'],
                   args['output_path'], args['log_file'])
    vmlinux_ddeb = hkd.maybe_download_vmlinux_ddeb()
    if vmlinux_ddeb == "":
        print("got empty vmlinux")
        return

    hkd.extract_vmlinux_ddeb(vmlinux_ddeb)

    if args['interactive']:
        hkd.launch_crash()
    else:
        hkd.summarize_vmcore_file()

    diff = time.time() - start
    print(f"hotkdump took {round(diff, 2)} secs")


if __name__ == "__main__":
    main()
