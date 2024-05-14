# hotkdump

hotkdump is a tool for auto analysis of vmcores.

## How to build & run with Docker

The repository contains a `Dockerfile` for running hotkdump conveniently. In order to use it, you'll need to build it first. To build the image:

```bash
    docker build . -t hotkdump
```

This will build a docker image named `hotkdump`. The docker image contains all the stuff needed to run `hotkdump` (e.g. crash, ubuntu-dev-tools) on a linux kernel crash dump. See `Dockerfile` for details.

To run:

```bash
    # Replace <path-to-the-kdump-file> with the path of kdump file on your host
    docker run --rm --mount type=bind,source=<path-to-the-kdump-file>,target=/tmp/crash-dumpv,readonly -it hotkdump bash -c "cd /tmp && UBUNTUTOOLS_UBUNTU_DDEBS_MIRROR= hotkdump -d /tmp/crash-dumpv -c 0 && cat hotkdump.out"
=======
## How to run tests

Running `tox -e py{36,37,38,39,310,311}` in project root directory will run all unit tests, e.g.:

```bash
    tox -e py310
```

## How to build and install the snap

Building snap requires "snapcraft", which can be installed with "sudo apt install snapcraft" or "sudo snap install snapcraft".

```text
snapcraft # will produce hotkdump_<vmaj>.<vmin>_<arch>.snap file
snap install ./hotkdump_<vmaj>.<vmin>_<arch>.snap --dangerous
```

## Versioning

The project will use <year>.<month>.[<revision>] as a versioning scheme.
