# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import struct
import logging
from sys import exit

GLOBAL_HEADER = "<IHHIIII"
RECORD_HEADER_LITTLE = "<IIII"
RECORD_HEADER_BIG = ">IIII"

log = logging.getLogger(__name__)

class PcapParser():
    def __init__(self, pcap_file=None):
        log.debug("PcapParser started.")
        self.pcap_file = pcap_file

    def __del__(self):
        log.debug("PcapParser stopped.")

    def read(self, pcap_file=None):
        if pcap_file:
            self.pcap_file = pcap_file
        log.debug("Parsing file '%s'.", self.pcap_file)

        try:
            with open(self.pcap_file,"rb") as pcap:
                # File header
                header = pcap.read(struct.calcsize(GLOBAL_HEADER))
                extracted_header = []
                extracted_header = struct.unpack(GLOBAL_HEADER, header)

                header_format = None
                if(hex(extracted_header[0]) == "0xa1b2c3d4"): # Little Endian
                    log.debug("Little Endian.")
                    header_format = RECORD_HEADER_LITTLE
                else: # Big Endian --> Change header format
                    log.warning("Big Endian. Trying to parse it properly.")
                    header_format = RECORD_HEADER_BIG

                # Packets
                packets = []

                while True:
                    record_header = pcap.read(struct.calcsize(header_format))
                    if record_header:
                        ts_sec, ts_usec, captured_length, original_length = struct.unpack(header_format, record_header)
                        ts_full = ts_sec + round((ts_usec/1000000.0),2)
                        #log.debug("Timestamp: %s, Captured length: %s, Original length: %s" % (ts_full, captured_length, original_length))

                        packet = pcap.read(captured_length)
                        packets.append((ts_full,packet))
                        #print(my_packet["eth"])
                    else:
                        break

                log.debug("File contains %s packets.", len(packets))
                return packets
        except IOError as e:
            log.error(e)
            exit(-1)

    def write(self, pcap_file):
        # To be implemented..
        pass