# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
import logging.handlers

import os
import sys
from lib.core.meta_analyzer import MetaAnalyzer
from lib.core.sniffer import TimerClass
from lib.common.constants import APP_ROOT
from lib.common.colors import color

log = logging.getLogger()

def interrupt_handler(signal,frame):
    log.info("Fetched Ctrl+C. Shutting down.")
    MetaAnalyzer.stoprequest.set() # Stop analyzer thread
    TimerClass.stoprequest.set()
    exit(0)

def init_logging():
    """ Initializes logging. """
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    
    # File logging
    file_handler = logging.handlers.WatchedFileHandler(os.path.join(APP_ROOT, "exfil-detect.log"))
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    
    # Console logging
    console_handler = ConsoleHandler()
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    
    #log_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    #log_handler.setLevel(logging.ERROR)
    #log.addHandler(log_handler)

    # Log level
    log.setLevel(logging.INFO)
    
def check_configs():
    """ Check for existing configs. """

    configs = ("sniffer.conf", "communicator.conf")
    
    for cfg in [os.path.join(APP_ROOT,"conf", fname) for fname in list(configs)]:
        if not os.path.exists(cfg):
            sys.exit("ERROR: Missing config file: {0}".format(cfg))
    
class ConsoleHandler(logging.StreamHandler):
    """ Logging to console. """

    def emit(self, record):
        """ Rewrite each record before it is printed to the console. """
        formatted = record
        
        if record.levelname == "WARNING":
            formatted.msg = color(record.msg, 33) # yellow
        
        if record.levelname == "ERROR" or record.levelname == "CRITICAL":
            formatted.msg = color(record.msg, 31) # red
        else:
            formatted.msg = record.msg

        logging.StreamHandler.emit(self, record)