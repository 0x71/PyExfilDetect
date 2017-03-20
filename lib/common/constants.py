# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

from os import getcwd

APP_ROOT = getcwd()

SUPPORTED_PROTOCOLS = ["tcp", "udp", "dns","icmp"]

IP_HEADER_PROTOCOLS = { "1": "ICMP",
                        "2": "IGMP",
                        "3": "GGP",
                        "4": "IPv4", # IP encapsulation
                        "6": "TCP",
                       "17": "UDP",
                       "27": "RDP",}

VAR_THRESHOLD = 0.001

# Timeout in seconds
DNS_STREAM_TIMEOUT = 60

ICMP_STREAM_TIMEOUT = 30