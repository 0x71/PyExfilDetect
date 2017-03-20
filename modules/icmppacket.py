# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
from struct import unpack, calcsize

log = logging.getLogger(__name__)

# Head
ICMP_HEADER_FORMAT = "!BBH"
ICMP_ECHO_REQUEST_HEADER_FORMAT = "!HH"

class ICMPPacket():
    """ Handling icmp packets. """
    def __init__(self):
        self.type = None
        self.code = None
        self.checksum = None
        self.sess_id = -1
        self.seq_num = None
        self.data = None
    
    def __del__(self):
        pass
    
    def __repr__(self):
        head = "================ icmp_segment ================\n"
        foot = "==============================================\n"
        body = ("type:\t\t %s\n" \
               +"code:\t\t %s (%s)\n"
               +"checksum:\t %s\n") \
              % (self.type, self.code, self.type_code_resolution(self.type, self.code), self.checksum)
        if (self.is_echo_request()) or (self.is_echo_reply()):
            body += "id:\t\t %s\n" % self.sess_id
            body += "seq:\t\t %s\n" % self.seq_num
        body += "data:\t\t %s\n" % self.data
        return head + body + foot
    
    def unpack(self, raw_data):
        try:
            # Calculate header size
            header_len = calcsize(ICMP_HEADER_FORMAT)
            
            # Extract header fields
            icmp_header = raw_data[:header_len]
            icmp_header = unpack(ICMP_HEADER_FORMAT, icmp_header)
            self.type = icmp_header[0]
            self.code = icmp_header[1]
            self.checksum = icmp_header[2]
    
            # Check for echo request/reply message
            if (self.is_echo_request()) or (self.is_echo_reply()):
                additional_header = raw_data[header_len:header_len+calcsize(ICMP_ECHO_REQUEST_HEADER_FORMAT)]
                self.sess_id, self.seq_num = unpack(ICMP_ECHO_REQUEST_HEADER_FORMAT, additional_header)

                self.data = raw_data[-32:]

        except Exception as e:
            raise Exception("ICMP unpack error: %s" % e)
    
    def type_code_resolution(self, type, code):
        type = int(type)
        code = int(code)
        if type == 0:
            if code == 0:
                return "Echo reply"
        if type == 1 or type == 2:
            return "Unassigned"
        if type == 3:
            if code == 0:
                return "Destination network unreachable"
            if code == 1:
                return "Destination host unreachable"
            if code == 2:
                return "Destination protocol unreachable"
            return "Destination unreachable"
        if type == 4:
            return "Source Quench"
        if type == 5:
            return "Redirect Message"
        if type == 6:
            return "Deprecated"
        if type == 7:
            return "Unassigned"
        if type == 8:
            if code == 0:
                return "Echo request"
        if type == 9:
            return "Router Advertisement"
        if type == 10:
            return "Router Solicitation"
        if type == 11:
            return "Time Exceeded"
        if type == 12:
            return "Parameter Problem: Bad IP header"
        if type == 13:
            return "Timestamp"
        if type == 14:
            return "Timestamp reply"
        
        return "Not defined"

    def is_echo_request(self):
        return self.type == 8 and self.code == 0

    def is_echo_reply(self):
        return self.type == 0 and self.code == 0