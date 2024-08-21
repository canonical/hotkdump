<div align="center">

# hotkdump

<img src="extras/img/hotkdump-logo.png">

<i>Easily open and analyze linux kernel crash dumps.</i>
</div>

****

`hotkdump` is a tool for auto analysis of Linux kernel crash dump files generated with `kdump`. It can automatically download the correct Linux kernel image(vmlinux) with debug symbols for the crash dump's kernel version (currently only supported for Ubuntu).

`hotkdump` has two ways of automatically retrieving Linux kernel images:

- ...via debuginfod: If `debuginfod-find` is available in the environment and BUILD-ID is available in VMCOREINFO section of the crash dump
- ...via pullpkg

Both methods are enabled by default and the order of execution is: [`debuginfod`, `pullpkg`]. The methods can be disabled with `--no-debuginfod` and `--no-pullpkg` flags, respectively.

`debuginfod` is bundled into `snap` version of the application by default.

## Synopsis

```bash
hotkdump [-d/--dump-file-path] <crash-dump-file> [other-options...]
```

other-options:

```bash
usage: hotkdump [-h] -d DUMP_FILE_PATH [-c INTERNAL_CASE_NUMBER] [-i] [-o OUTPUT_FILE_PATH] [-l LOG_FILE_PATH] [-p DDEBS_FOLDER_PATH]
                [--print-vmcoreinfo-fields [PRINT_VMCOREINFO_FIELDS ...]] [--debug-file DEBUG_FILE] [--no-debuginfod | --no-pullpkg]

options:
  -h, --help            show this help message and exit
  -d DUMP_FILE_PATH, --dump-file-path DUMP_FILE_PATH
                        Path to the Linux kernel crash dump
  -c INTERNAL_CASE_NUMBER, --internal-case-number INTERNAL_CASE_NUMBER
                        Canonical Support internal case number (default: 0)
  -i, --interactive     Start the `crash` in interactive mode instead of printing summary (default: False)
  -s SUMMARY_ROOT, --summary SUMMARY_ROOT
                        Root directory for summary output (default: None)
  -l LOG_FILE_PATH, --log-file-path LOG_FILE_PATH
                        log file path (default: None)
  -p DDEBS_FOLDER_PATH, --ddebs-folder-path DDEBS_FOLDER_PATH
                        Path to save the downloaded .ddeb files. Will be created if the specified path is absent. (default: None)
  --print-vmcoreinfo-fields [PRINT_VMCOREINFO_FIELDS ...]
                        Read and print the specified VMCOREINFO fields from the given kernel crash dump, then exit.
  --debug-file DEBUG_FILE
                        Specify the debug file to use. Only ddebs and vmlinux files are supported. (default: None)
  --no-debuginfod       Do not use debuginfod for downloads (default: False)
  --no-pullpkg          Do not use pullpkg for downloads (default: False)
```

## Running

```bash
hotkdump -d /home/user/my-dump-file -i -o hotkdump.out -l hotkdump.log -p /tmp/ddebs
```

## Installing

`hotkdump` is available as a snap and can be installed as follows:

```bash
snap install hotkdump --channel=beta
```

## Building from scratch

### How to build & run with Docker

The repository contains a `Dockerfile` for running hotkdump conveniently. In order to use it, you'll need to build it first. To build the image:

```bash
docker build . -t hotkdump -f extras/Dockerfile
```

This will build a docker image named `hotkdump`. The docker image contains all the stuff needed to run `hotkdump` (e.g. crash, ubuntu-dev-tools) on a linux kernel crash dump. See `Dockerfile` for details.

To run:

```bash
# Replace <path-to-the-kdump-file> with the path of kdump file on your host
docker run --rm --mount type=bind,source=<path-to-the-kdump-file>,target=/tmp/crash-dumpv,readonly -it hotkdump bash -c "cd /tmp && UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= hotkdump -d /tmp/crash-dumpv -c 0 && cat hotkdump.out"
```

### Build & Install Snap

Building snap requires "snapcraft", which can be installed with "sudo apt install snapcraft" or "sudo snap install snapcraft".

```text
snapcraft # will produce hotkdump_<vmaj>.<vmin>_<arch>.snap file
snap install ./hotkdump_<vmaj>.<vmin>_<arch>.snap --dangerous
```

Then, `hotkdump` can be run as regular.

## How to run tests

Running `tox -e py{36,37,38,39,310,311}` in project root directory will run all unit tests, e.g.:

```bash
tox -e py310
```

## Formatting

This project uses `ruff` for formatting. To format the code, simply run `tox -e ruff-format`. Running `tox` with no arguments will automatically run the `ruff-format` environment as well.

## Versioning

The project will use `<year>.<month>.[<revision>]` as a versioning scheme.

## Diagnosing issues

### Setting the log level

`hotkdump` reads the `HOTKDUMP_LOGLEVEL` environment variable to set the logger's log level. If it is unset, the default value is `INFO`. The possible values are `[DEBUG, INFO, WARN, ERROR, CRITICAL]`.

Example usage:

```bash
HOTKDUMP_LOGLEVEL=DEBUG hotkdump -d <dump-file-path>
```

### Snap-related pecularities

Hotkdump's `snap` is strictly confined, so all data is confined to snap's own directories, such as:

- `/tmp` --> `/tmp/snap-private-tmp/snap.hotkdump/tmp`
- `$HOME` --> `/home/$USER/snap/hotkdump/current/`

[hotkdump-logo]: extras/img/hotkdump-logo.png
