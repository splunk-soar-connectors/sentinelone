# File: sentinelone_utilities.py
# Copyright (c) SentinelOne, 2018-2025


#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import logging
import os
import sys
from logging import handlers


class KennyLoggins:
    """Base Class for Logging"""

    __module__ = __name__

    def __init__(self, **kwargs):
        """Construct an instance of the Logging Object"""
        pass

    def get_logger(self, app_name=None, file_name="kenny_loggins", log_level=logging.INFO, version="unknown"):
        log_location = ("{}{}").format(os.path.sep, os.path.join("var", "log", "phantom", "apps", app_name))
        _log = logging.getLogger(f"{app_name}/{file_name}")
        _log.propogate = False
        _log.setLevel(log_level)
        formatter = logging.Formatter(
            f'%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s              file="%(filename)s \
                " function="%(funcName)s" line_number="%(lineno)d" version="{version}" %(message)s'
        )
        try:
            try:
                if not os.path.isdir(log_location):
                    os.makedirs(log_location)
                output_file_name = os.path.join(log_location, (f"{file_name}.log"))
                f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
                f_handle.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(f_handle)
            except Exception as e:
                handler = logging.StreamHandler(sys.stdout)
                handler.setLevel(log_level)
                handler.setFormatter(formatter)
                if not len(_log.handlers):
                    _log.addHandler(handler)
                _log.error(f"Failed to create file-based logging. {e}")

        finally:
            return _log
