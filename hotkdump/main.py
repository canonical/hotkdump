#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

""" `hotkdump` CLI entry point.
"""

import sys
import os
import argparse
import time
import logging
import traceback

this_script_dir = os.path.join(
    os.path.dirname(os.path.realpath(os.path.abspath(__file__))), os.pardir
)
sys.path.append(this_script_dir)

# These are actually need to be run after the sys.path is updated, so
# we're silencing the warning.
# pylint: disable=wrong-import-position
from hotkdump.core.hotkdump import Hotkdump, HotkdumpParameters
from hotkdump.core.exceptions import NotAKernelCrashDumpException


def main():
    """The entry point of the program."""
    start = time.time()
    ap = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ap.add_argument(
        "-d",
        "--dump-file-path",
        help="Path to the Linux kernel crash dump",
        required=True,
        default=argparse.SUPPRESS
    )
    ap.add_argument(
        "-c",
        "--internal-case-number",
        help="Canonical Support internal case number",
        required=False,
        default=0,
    )
    ap.add_argument(
        "-i",
        "--interactive",
        help="Start the `crash` in interactive mode instead of printing summary",
        action="store_true",
    )
    ap.add_argument(
        "-o",
        "--output-file-path",
        help="Output file path for the summary",
        required=False,
    )
    ap.add_argument("-l", "--log-file-path", help="log file path", required=False)
    ap.add_argument(
        "-p",
        "--ddebs-folder-path",
        help="Path to save the downloaded .ddeb files. Will be created if the specified path is absent.",
        required=False,
    )
    ap.add_argument(
        "--print-vmcoreinfo-fields",
        required=False,
        help="Read and print the specified VMCOREINFO fields from the given kernel crash dump, then exit.",
        nargs="*",
        default=argparse.SUPPRESS
    )
    download_methods_group = ap.add_mutually_exclusive_group()
    download_methods_group.add_argument(
        "--no-debuginfod",
        help="Do not use debuginfod for downloads",
        default=False,
        action="store_true",
    )
    download_methods_group.add_argument(
        "--no-pullpkg",
        help="Do not use pullpkg for downloads",
        default=False,
        action="store_true",
    )

    # Convert argparse.Namespace to a dict, remove dict entries where value
    # is None
    args = {k: v for k, v in vars(ap.parse_args()).items() if v is not None}
    params = HotkdumpParameters(**args)

    try:
        hotkdump = Hotkdump(parameters=params)
        hotkdump.run()
    except FileNotFoundError:
        logging.error(
            "ERROR: Linux kernel crash dump file `%s` not found: (%s)",
            args["dump_file_path"],
            traceback.format_exc(),
        )
        sys.exit(-1)
    except NotAKernelCrashDumpException:
        # NotAKernelCrashDumpException logs to .error() by default
        sys.exit(-2)
    diff = time.time() - start
    print(f"hotkdump took {round(diff, 2)} secs to run.")


if __name__ == "__main__":
    main()
