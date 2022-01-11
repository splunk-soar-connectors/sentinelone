# File: sentinelone_consts.py
# Copyright (c) SentinelOne, 2018-2022
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

SENTINELONE_24_HOUR_GAP = 86400

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# value_list contants
OS_FAMILY_LIST = [
                    "windows",
                    "osx",
                    "linux"
                ]
ACTION_LIST = [
                "kill",
                "quarantine",
                "un-quarantine",
                "remediate",
                "rollback-remediation"
            ]
TYPE_LIST = [
                "fqdn",
                "addresses",
                "cidr"
            ]
ANALYSIS_VERDICT_LIST = [
                        "undefined",
                        "true_positive",
                        "false_positive",
                        "suspicious"
                    ]
INCIDENT_STATUS_LIST = [
                        "unresolved",
                        "in_progress",
                        "resolved"
                    ]
