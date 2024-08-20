#!/usr/bin/env python3

# (mkg): This file exists because older versions of
# setuptools do not support reading optional-dependencies
# from pyproject.toml file. Drop this file when python 3.6
# support is dropped.
import toml

with open("pyproject.toml", "r") as f:
    data = toml.load(f)

# Dependencies
for line in data.get("project").get("dependencies"):
    print(line)

# Test dependencies
for line in data.get("project").get("optional-dependencies").get("testing"):
    print(line)
