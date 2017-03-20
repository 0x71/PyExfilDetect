# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

from sys import platform
from os import getenv

""" Color codes:

    black:     30
    red:       31
    green:     32
    yellow:    33
    blue:      34
    magenta    35
    cyan       36
    white      37
    bold        1
    
"""

def color(text, color_code):
    # For windows: only xterm seems to support colors
    if platform == "win32" and getenv("TERM") != "xterm":
        return text
    return "\x1b[%dm%s\x1b[0m" % (color_code, text)