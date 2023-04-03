#!/usr/bin/env python3
import argparse
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
import contextlib

try:
    from ubuntutools.pullpkg import PullPkg
    from ubuntutools import getLogger as ubuntutools_GetLogger
except ModuleNotFoundError:
    raise ModuleNotFoundError("\n\n`hotkdump` needs ubuntu.pullpkg to function.\n"
                              "Install it via `sudo apt install ubuntu-dev-tools`")

"""
TODOS:

1) need to figure out when a new vmcore is uploaded to files.canonical
and for which case, for automatically updating the case 

2) leverage the filemover, and think about this as a generic application or a library

3) update cases with a internal comment of a link to hotkdump.out output

"""

def pretty_size(bytes):
    """Get human-readable file sizes.
    simplified version of https://pypi.python.org/pypi/hurry.filesize/
    """
    UNITS_MAPPING = [
        (1<<50, 'PB'),
        (1<<40, 'TB'),
        (1<<30, 'GB'),
        (1<<20, 'MB'),
        (1<<10, 'KB'),
        (1, ('byte', 'bytes')),
    ]
    for factor, suffix in UNITS_MAPPING:
        if bytes < factor:
            continue
        amount = bytes / factor
        if isinstance(suffix, tuple):
            singular, multiple = suffix
            if amount == 1:
                suffix = singular
            else:
                suffix = multiple
        return f"{amount:.2f} {suffix}"

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

            # Let's be more forgiving about locating
            # the KDUMP signature:
            bytes = fd.read(1024 * 8)
            expected_magic = b'KDUMP   '

            offset = bytes.find(expected_magic)

            if offset == -1:
                raise ExceptionWithLog(
                    f"{kdump_file_path} is not a kernel crash dump file")

            # Skip the magic
            fd.seek(offset + len(expected_magic), os.SEEK_SET)

            version = int.from_bytes(fd.read(4), byteorder='little')
            self.kdump_version = version
            self.system = self.readcstr(fd)
            self.node = self.readcstr(fd)
            self.release = self.readcstr(fd)
            self.version = self.readcstr(fd)
            self.machine = self.readcstr(fd)
            self.domain = self.readcstr(fd)
            self.normalized_version = self.version.split("-")[0].lstrip("#")
            logging.debug(f"kdump_hdr: {str(self)}")

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
            if (b == b'') or (b == b'\x00'):
                kdump_file_header.seek_to_first_non_nul(f)
                return str(''.join(buf))
            else:
                buf += b.decode('ascii')

    def __str__(self) -> str:

        return " | ".join(
            # Get all attributes, filter out the built-in ones
            # and stringify the rest in "name:value" format
            [f" {v}:{str(getattr(self, v))}" for v in filter(
                lambda x: not x.startswith("__") and not callable(getattr(self, x)), dir(self))]
        )


default_output_file = "hotkdump.out"
default_log_file = "hotkdump.log"
default_ddebs_path = "/tmp/hotkdump/ddebs"


class hotkdump:

    def __init__(self, case_number, vmcore_file, output_file_path=default_output_file, log_file_path=default_log_file, ddebs_path=default_ddebs_path):
        self.output_file = output_file_path
        self.log_file = log_file_path
        self.case_number = case_number
        self.vmcore_file = vmcore_file
        self.ddebs_path = ddebs_path
        self.crash_executable = self.find_crash_executable()


        self.ddeb_retention_enabled = False
        self.ddeb_retention_size_high_wm_bytes = None # (1<<30) * 2 # 2 GiB
        self.ddeb_retention_size_low_wm_bytes = None # (1<<30) * 4 # 4 GiB
        self.ddeb_retention_max_age_secs = None # 86400 * 15 # 15 days
        self.ddeb_retention_max_ddeb_count = None # 2

        if (self.ddeb_retention_size_high_wm_bytes and self.ddeb_retention_size_low_wm_bytes) and (self.ddeb_retention_size_high_wm_bytes < self.ddeb_retention_size_low_wm_bytes):
            raise ExceptionWithLog("ddeb high watermark cannot be less than low watermark!")

        self.initialize_logging()

        logging.info(
            f"initializing hotkdump, SF#{self.case_number}, vmcore: {self.vmcore_file}")

        self.touch_file(self.output_file)
        tstamp_now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        vmcore_filename  = self.vmcore_file.rsplit('/', 1)[-1]
        with open(self.output_file, "w") as outfile:
            outfile.write("{tstamp_now}: processing {vmcore_filename} (SF# {self.case_number})\n")

        self.kdump_header = kdump_file_header(self.vmcore_file)

        logging.info(
            f"kernel version: {self.kdump_header.release}")
        self.temp_working_dir = tempfile.TemporaryDirectory()
        logging.debug(
            f"created {self.temp_working_dir.name} temporary directory for the intermediary files")
        self.commands_file_path = self.write_crash_commands_file()

        # Create the ddeb path if not exists
        os.makedirs(default_ddebs_path, exist_ok=True)

    def get_architecture(self):
        if self.kdump_header.machine == "x86_64":
            return "amd64"
        elif self.kdump_header.machine == "aarch64":
            return "arm64"
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
        console_logger = logging.StreamHandler(sys.stdout)
        # Allow log level overrides from environment
        level = os.environ.get('HOTKDUMP_LOGLEVEL', 'INFO').upper()

        for logger in [file_logger, console_logger, self.logger]:
            logger.setLevel(level)

        for logger in [file_logger, console_logger]:
            self.logger.addHandler(logger)

        # Only display error messages and the download status from ubuntutools
        for handler in ubuntutools_GetLogger().handlers:
            handler.addFilter(
                lambda r: "Downloading" in r.msg or r.levelno >= logging.ERROR)

    @staticmethod
    def touch_file(fname):
        with open(fname, "w"):
            pass

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
        commands_file = "{}{}".format(self.temp_working_dir.name, "/crash_commands")

        with open(commands_file, "w") as ccfile:
            # (mkg): the file uses self-append to evaluate commands depend on
            # the information extracted from a prior command invocation. This
            # is possible because POSIX guarantees that:
            #   "If a read() of file data can be proven (by any means) to occur
            #   after a write() of the data, it must reflect that write(), even
            #   if the calls are made by different processes."
            commands_file_content = fr"""
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'sys'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            sys >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'bt'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            bt >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'log' with audit messages filtered out" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            log | grep -vi audit >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'kmem -i'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            kmem -i >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'dev -d'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            dev -d >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'mount'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            mount >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'files'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            files >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'vm'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            vm >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Output of 'net'" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            net >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Oldest blocked processes" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            ps -m | grep UN | tail >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            !echo "Top 20 memory consumers" >> {self.output_file}
            !echo "---------------------------------------" >> {self.output_file}
            ps -G | sed 's/>//g' | sort -k 8,8 -n |  awk '$8 ~ /[0-9]/{{ $8 = $8/1024" MB"; print }}' | tail -20 | sort -r -k8,8 -g >> {self.output_file}
            !echo "\n!echo '---------------------------------------' >> {self.output_file}" >> {commands_file}
            !echo "\n!echo 'BT of the oldest blocked process' >> {self.output_file}" >> {commands_file}
            !echo "\n!echo '---------------------------------------' >> {self.output_file}" >> {commands_file}
            ps -m | grep UN | tail -n1 | grep -oE "PID: [0-9]+" | grep -oE "[0-9]+" | awk '{{print "bt " $1 " >> {self.output_file}"}}' >> {commands_file}
            !echo "\nquit >> {self.output_file}" >> {commands_file}
            !echo "" >> {self.output_file}"""
            # (mkg): The last empty echo is important to allow
            # crash to pick up the commands appended to the command
            # file at the runtime.
            final_cmdfile_contents = textwrap.dedent(commands_file_content).strip()
            ccfile.write(final_cmdfile_contents)
            logging.debug(f"command file {commands_file} rendered with contents: {final_cmdfile_contents}")
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

    @contextlib.contextmanager
    def switch_cwd(self, wd):
        curdir = os.getcwd()
        try:
            os.chdir(wd)
            yield
        finally: os.chdir(curdir)

    @staticmethod
    def strip_release_variant_tags(str):
        # see: https://ubuntu.com/kernel/variants#version-specific-kernels
        tags = sorted(["generic", "lowlatency", "generic-hwe",
                       "lowlatency-hwe", "kvm", "aws", "azure", "azure-fde",
                       "gcp", "gke", "snapdragon", "raspi2"], key=len, reverse=True)
        version_specific_tags = sorted([
            "generic-hwe-{}", "generic-hwe-{}", "lowlatency-hwe-{}", "lowlatency-hwe-{}"], key=len, reverse=True)
        versions = ["16.04", "18.04", "20.04", "22.04", "24.04"]

        for vtag in version_specific_tags:
            for version in versions:
                str = str.replace("-" + vtag.format(version) + '-edge', '')
                str = str.replace("-" + vtag.format(version), '')

        for tag in tags:
            str = str.replace(f"-{tag}", '')
            str = str.replace(f"-{tag}-edge", '')

        validator_regex = re.compile(r"^\d+\.\d+\.\d+-\d+$")
        if not validator_regex.match(str):
            raise ExceptionWithLog(f"The stripped release did not yield a valid version! ({str})")

        return str

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
            self.strip_release_variant_tags(self.kdump_header.release),
            self.kdump_header.normalized_version,
            self.get_architecture()
        )

        with self.switch_cwd(self.ddebs_path):
            # Check if we already have the .ddeb
            if os.path.exists(expected_ddeb_path):
                # Already exists, do not download again
                # TODO(mkg): Verify SHA checksum?
                logging.info(
                    f"The .ddeb file {expected_ddeb_path} already exists, re-using it")
                # Ensure that the file's last access time is updated
                os.utime(expected_ddeb_path, (time.time(), time.time()))
                return expected_ddeb_path

            logging.info(
                f"Downloading `vmlinux` image for kernel version {self.kdump_header.release}, please be patient...")

            # (mkg): To force pull-lp-ddebs to use launchpadlibrarian.net for download
            # pass an empty mirror list env variable to the hotkdump, e.g.:
            # UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= python3 hotkdump.py -c 123 -d dump.dump
            pull_args = ["--distro", "ubuntu", "--arch", self.get_architecture(), "--pull", "ddebs",
                        f"linux-image-unsigned-{self.kdump_header.release}",
                        f"{self.strip_release_variant_tags(self.kdump_header.release)}.{self.kdump_header.normalized_version}"]
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
        logging.info(f"Extracting {ddeb_file} to {ddeb_extract_dst}, please be patient...")
        with self.switch_cwd(self.ddebs_path):
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
        logging.info(f"See {self.log_file} for logs, {self.output_file} for outputs")

    def launch_crash(self):
        """Launch the `crash` application with the user-given vmcore and 
        downloaded vmlinux image file
        """
        logging.info(
            f"Loading `vmcore` file {self.vmcore_file} into `crash`, please wait..")
        self.exec(self.crash_executable,
                  f"{self.vmcore_file} {self.vmlinux_path}")

    def post_run(self):
        """Perform post-run tasks
        """
        # Retrieve all ddebs and their stat() from the ddeb folder
        ddebs = [(f"{self.ddebs_path}/{file}", os.stat(f"{self.ddebs_path}/{file}")) for file in os.listdir(self.ddebs_path) if file.endswith(".ddeb")]
        # Sort ddebs by their last access time
        ddebs.sort(key=lambda f: f[1].st_atime, reverse=True)


        # TODO(mkg): Wrap this logic into its own class
        # i.e. RetentionPolicy

        def remove_ddeb(ddeb_info, reason):
            (ddeb_path, ddeb_stat) = ddeb_info
            os.remove(ddeb_path)
            logging.debug(f"removed {ddeb_path} to reclaim {pretty_size(ddeb_stat.st_size)}. age: {(time.time() - ddeb_stat.st_atime):.2f} seconds. reason: {reason}")

        if not self.ddeb_retention_enabled:
            logging.debug(f"ddeb retention is disabled, starting cleanup.")
            for ddeb_info in ddebs:
                remove_ddeb(ddeb_info, "retention disabled")
            return

        # Prune based on count
        if self.ddeb_retention_max_ddeb_count and len(ddebs) > self.ddeb_retention_max_ddeb_count:
            ddebs_to_remove = ddebs[self.ddeb_retention_max_ddeb_count:]

            for ddeb_info in ddebs_to_remove:
                remove_ddeb(ddeb_info, "count")

            # Update the list
            ddebs = list(filter(lambda i: i not in ddebs_to_remove, ddebs))

        # Prune based on age
        if self.ddeb_retention_max_age_secs:
            ddebs_to_remove = [v for v in ddebs if (time.time() - v[1].st_atime) >= self.ddeb_retention_max_age_secs]
            for ddeb_info in ddebs_to_remove:
                remove_ddeb(ddeb_info, "old age")

            # Update the list
            ddebs = list(filter(lambda i: i not in ddebs_to_remove, ddebs))

        if self.ddeb_retention_size_low_wm_bytes and self.ddeb_retention_size_high_wm_bytes:
            # Check if size of all ddebs has reached to the high watermark
            total_ddeb_size = sum([ddeb_info[1].st_size for ddeb_info in ddebs])
            if total_ddeb_size >= self.ddeb_retention_size_high_wm_bytes:
                logging.debug(f"total ddeb size of {pretty_size(total_ddeb_size)} exceeds the high watermark {pretty_size(self.ddeb_retention_size_high_wm_bytes)}, starting cleanup.")
                # Remove .ddebs until total size is below the low watermark
                while len(ddebs) > 0:
                    total_ddeb_size = sum([ddeb_info[1].st_size for ddeb_info in ddebs])
                    if total_ddeb_size < self.ddeb_retention_size_low_wm_bytes:
                        logging.debug(f"total ddeb folder size is now below {pretty_size(self.ddeb_retention_size_low_wm_bytes)} low watermark, stopping cleanup.")
                        break
                    ddeb_info = ddebs.pop()
                    remove_ddeb(ddeb_info, "size")

        logging.debug(f"postrun-aftermath: ddeb folder final size {pretty_size(sum([ddeb_info[1].st_size for ddeb_info in ddebs]))}, {len(ddebs)} cached ddebs remain.")


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
    ap.add_argument("-p", "--ddebs-path",
                    help="ddebs path", default=default_ddebs_path)
    args = vars(ap.parse_args())

    hkd = hotkdump(args['casenum'], args['dump'],
                   args['output_path'], args['log_file'],
                args['ddebs_path'])

    try:

        vmlinux_ddeb = hkd.maybe_download_vmlinux_ddeb()
        if vmlinux_ddeb == "":
            print("got empty vmlinux")
            return

        hkd.extract_vmlinux_ddeb(vmlinux_ddeb)

        if args['interactive']:
            hkd.launch_crash()
        else:
            hkd.summarize_vmcore_file()
    finally:
        hkd.post_run()

    diff = time.time() - start
    print(f"hotkdump took {round(diff, 2)} secs")


if __name__ == "__main__":
    main()
