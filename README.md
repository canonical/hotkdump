# hotkdump

`hotkdump` is a tool for auto analysis of Linux kernel crash dump files generated with `kdump`. It can automatically download the required debug symbols for the crash dump's kernel version (currently only supported for Ubuntu).

## Synopsis

```bash
hotkdump -d <dump-file> [other-options...]
```

other-options:

* `-c <case-number>`: Canonical Support internal case number
* `-i` : Run in interactive mode
* `-o <output-path>`: Output path for the analysis results. (*default*: `/tmp/hotkdump.out`)
* `-l <log-file-path>`: Output path for log file. (*default*: `/tmp/hotkdump.log`)
* `-p <ddebs-path>`: Path for storing `.ddeb` files. (*default*: `/tmp/hotkdump/ddebs`)

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

## Versioning

The project will use `<year>.<month>.[<revision>]` as a versioning scheme.

## Diagnosing issues

### Setting the log level

`hotkdump` reads the `HOTKDUMP_LOGLEVEL` environment variable to set the logger's log level. If it is unset, the default value is `INFO`. The possible values are `[DEBUG, INFO, WARN, ERROR, CRITICAL]`.

Example usage:

```bash
HOTKDUMP_LOGLEVEL=DEBUG hotkdump -d <dump-file-path>
```


