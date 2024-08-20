#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""Folder retention manager and its' policies."""

import abc
import os
import logging
import time
from dataclasses import dataclass

from hotkdump.core.utils import pretty_size
from hotkdump.core.exceptions import ExceptionWithLog


class RetentionPolicyBase(abc.ABC):
    """Base class for all retention policies."""

    @property
    @abc.abstractmethod
    def name(self):
        """Name of the policy."""

    @abc.abstractmethod
    def execute(self, file_infos: list):
        """Implementation of the policy."""

    def remove_file(self, file_info):
        """Remove a file."""
        (path, stat) = file_info
        os.remove(path)
        logging.debug(
            "removed %s to reclaim %s. age: %2f seconds. reason: %s ",
            path,
            pretty_size(stat.st_size),
            (time.time() - stat.st_atime),
            self.name,
        )


class RPTotalFileCount(RetentionPolicyBase):
    """File retention policy based on maximum file count

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    def __init__(self, max_file_count) -> None:
        self.max_file_count = max_file_count

    @property
    def name(self):
        return "max file count policy"

    def execute(self, file_infos: list) -> list:
        if len(file_infos) > self.max_file_count:
            to_remove = file_infos[self.max_file_count :]

            for info in to_remove:
                self.remove_file(info)

            return [x for x in file_infos if x not in to_remove]
        return file_infos

    def __str__(self):
        return f"{self.name}: {self.max_file_count}"


class RPTotalFileSize(RetentionPolicyBase):
    """File retention policy based on total file size

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    def __init__(self, low_watermark_bytes, high_watermark_bytes) -> None:
        self.low_wm_bytes = low_watermark_bytes
        self.high_watermark_bytes = high_watermark_bytes

    @property
    def name(self):
        return "total file size policy"

    def execute(self, file_infos: list) -> list:
        def total_size():
            return sum(finfo[1].st_size for finfo in file_infos)

        if total_size() >= self.high_watermark_bytes:
            logging.debug(
                "total ddeb size of %s exceeds the high watermark %s, starting cleanup.",
                pretty_size(total_size()),
                pretty_size(self.high_watermark_bytes),
            )
            # Remove files until total size is below the low watermark
            while len(file_infos) > 0:
                if total_size() < self.low_wm_bytes:
                    logging.debug(
                        "total ddeb folder size is now below %s low watermark, stopping cleanup.",
                        pretty_size(self.low_wm_bytes),
                    )
                    break
                ddeb_info = file_infos.pop()
                self.remove_file(ddeb_info)

        return file_infos

    def __str__(self):
        return f"{self.name}: {self.low_wm_bytes}:{self.high_watermark_bytes}"


class RPAge(RetentionPolicyBase):
    """File retention policy based on file age

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    def __init__(self, max_age_secs) -> None:
        self.max_age_secs = max_age_secs

    @property
    def name(self):
        return "age policy"

    def execute(self, file_infos: list) -> list:
        to_remove = [
            v for v in file_infos if (time.time() - v[1].st_atime) >= self.max_age_secs
        ]
        for file_info in to_remove:
            self.remove_file(file_info)

        return [x for x in file_infos if x not in to_remove]

    def __str__(self):
        return f"{self.name}: {self.max_age_secs}"


class RPNoCriteria(RetentionPolicyBase):
    """File retention policy without a criteria.
    Removes all supplied files.

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    @property
    def name(self):
        return "no criteria policy"

    def execute(self, file_infos: list) -> list:
        for file_info in file_infos:
            self.remove_file(file_info)
        return []


@dataclass
class FolderRetentionManagerSettings:
    """Settings for folder retention manager."""

    enabled: bool
    size_hwm: int
    size_lwm: int
    max_age_secs: int
    max_count: int

    @property
    def _size_enabled(self):
        return self.size_hwm and self.size_lwm

    def validate_sanity(self):
        """Check whether option values are not contradicting and sane."""
        if self._size_enabled:
            if self.size_hwm < self.size_lwm:
                raise ExceptionWithLog(
                    "ddeb high watermark cannot be less than low watermark!"
                )


class FolderRetentionManager:
    """Policy-based folder retention manager."""

    def __init__(self, folder_paths, filter_function) -> None:
        self.folder_paths = folder_paths
        self.filter_function = filter_function
        self.policies = []
        self.files = self._gather_files()

    def load_policies_from_settings(self, settings: FolderRetentionManagerSettings):
        """Load policies depending on setting values."""

        if not settings.enabled:
            self.policies = []
            self.add_policy(RPNoCriteria())
            return

        if settings.max_count:
            self.add_policy(RPTotalFileCount(settings.max_count))
        if settings.max_age_secs:
            self.add_policy(RPAge(settings.max_age_secs))
            # if not self.ddeb_retention_enabled:
        if settings.size_hwm and settings.size_lwm:
            self.add_policy(RPTotalFileSize(settings.size_lwm, settings.size_hwm))

    def _gather_files(self):
        files = []
        for root in self.folder_paths:
            files += [
                (f"{root}/{file}", os.stat(f"{root}/{file}"))
                for file in os.listdir(root)
                if self.filter_function(file)
            ]
        # Sort ddebs by their last access time
        files.sort(key=lambda f: f[1].st_atime, reverse=True)
        logging.debug("gather_files: %s", str(files))
        return files

    def add_policy(self, policy):
        """Add a policy to influence folder retention."""
        self.policies.append(policy)

    def execute_policies(self):
        """Execute all available retention policies over the folder paths."""
        files = self.files

        for policy in self.policies:
            logging.debug("executing policy `%s`", policy)
            files = policy.execute(files)
        logging.debug(
            "postrun-aftermath: ddeb folder final size %s, %d cached ddebs remain.",
            pretty_size(sum(finfo[1].st_size for finfo in files)),
            len(files),
        )

        return [x for x in self.files if x not in files]
