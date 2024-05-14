#!/usr/bin/env python3

# Copyright 2023 Canonical Limited.
# SPDX-License-Identifier: GPL-3.0

"""
Folder retention manager and its' policies.
"""

import abc
import os
import logging
import time

from hotkdump.core.utils import pretty_size


class retention_policy_base(abc.ABC):

    @abc.abstractproperty
    def name(self):
        """"""

    @abc.abstractclassmethod
    def execute(self,  file_infos: list):
        """"""

    def remove_file(self, file_info):
        (path, stat) = file_info
        os.remove(path)
        logging.debug(
            f"removed {path} to reclaim {pretty_size(stat.st_size)}. age: {(time.time() - stat.st_atime):.2f} seconds. reason: {self.name}")


class rpolicy_total_file_count(retention_policy_base):
    """File retention policy based on maximum file count

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    def __init__(self, max_file_count) -> None:
        self.max_file_count = max_file_count

    @property
    def name(self):
        return "max file count policy"

    def execute(self,  file_infos: list) -> list:
        if len(file_infos) > self.max_file_count:
            to_remove = file_infos[self.max_file_count:]

            for info in to_remove:
                self.remove_file(info)

            return list(filter(lambda i: i not in to_remove, file_infos))
        return file_infos


class rpolicy_total_file_size(retention_policy_base):
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

    def execute(self,  file_infos: list) -> list:

        def total_size(): return sum(
            [finfo[1].st_size for finfo in file_infos])

        if total_size() >= self.high_watermark_bytes:
            logging.debug(
                f"total ddeb size of {pretty_size(total_size())} exceeds the high watermark {pretty_size(self.high_watermark_bytes)}, starting cleanup.")
            # Remove files until total size is below the low watermark
            while len(file_infos) > 0:
                if total_size() < self.low_wm_bytes:
                    logging.debug(
                        f"total ddeb folder size is now below {pretty_size(self.low_wm_bytes)} low watermark, stopping cleanup.")
                    break
                ddeb_info = file_infos.pop()
                self.remove_file(ddeb_info)

        return file_infos


class rpolicy_age(retention_policy_base):
    """File retention policy based on file age

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    def __init__(self, max_age_secs) -> None:
        self.max_age_secs = max_age_secs

    @property
    def name(self):
        return "age policy"

    def execute(self,  file_infos: list) -> list:
        to_remove = [v for v in file_infos if (
            time.time() - v[1].st_atime) >= self.max_age_secs]
        for file_info in to_remove:
            self.remove_file(file_info)

        return list(filter(lambda i: i not in to_remove, file_infos))


class rpolicy_no_criteria(retention_policy_base):
    """File retention policy without a criteria.
    Removes all supplied files.

    Args:
        file_infos (list): list of files to apply the retention policy
    """

    @property
    def name(self):
        return "no criteria policy"

    def execute(self,  file_infos: list) -> list:
        for file_info in file_infos:
            self.remove_file(file_info)
        return []


class folder_retention_manager(object):
    def __init__(self, folder_paths, filter_function) -> None:
        self.folder_paths = folder_paths
        self.filter_function = filter_function
        self.policies = list()
        self.files = self._gather_files()

    def _gather_files(self):
        files = []
        for root in self.folder_paths:
            files += [(f"{root}/{file}", os.stat(f"{root}/{file}"))
                      for file in os.listdir(root) if self.filter_function(file)]
        # Sort ddebs by their last access time
        files.sort(key=lambda f: f[1].st_atime, reverse=True)

        return files

    def add_policy(self, policy):
        self.policies.append(policy)

    def execute_policies(self):
        files = self.files

        for policy in self.policies:
            files = policy.execute(files)
        logging.debug(
            f"postrun-aftermath: ddeb folder final size {pretty_size(sum([finfo[1].st_size for finfo in files]))}, {len(files)} cached ddebs remain.")

        return list(filter(lambda i: i not in files, self.files))
