# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
from struct import pack, unpack, calcsize
from binascii import hexlify
from lib.common.constants import IP_HEADER_PROTOCOLS

log = logging.getLogger(__name__)

# Head (size without optional fields: 20 bytes)
IP_HEADER_FORMAT = "!BBHHHBBH4s4s"

class IPPacket():
    """ Handling ip packets. """
    def __init__(self):
        self.version = None
        self.header_length = None # ihl
        self.tos = None
        self.total_length = None
        self.identification = None
        self.flags = None
        self.fragment_offset = None
        self.ttl = None
        self.protocol = None
        self.header_checksum = None
        self.src_addr = None
        self.src_addr_raw = None
        self.dest_addr = None
        self.dest_addr_raw = None
        self.data = None
        # To Do: Skipped optional fields for now
    
    def __del__(self):
        pass
    
    def __repr__(self):
        head = "================ ip_datagram =================\n"
        foot = "==============================================\n"
        body = ("version:\t %s\n" \
               +"ihs:\t\t %s (Bytes)\n"
               +"tos:\t\t %s\n"
               +"length:\t\t %s (Bytes)\n"
               +"ident.:\t\t 0x%.4x (%s)\n"
               +"flag:\t\t %s\n"
               +"frag_offset:\t %s\n"
               +"ttl:\t\t %s\n"
               +"protocol:\t %s (%s)\n"
               +"src_addr:\t %s\n"
               +"dest_addr:\t %s\n") \
              % (self.version, self.header_length, self.tos, self.total_length, self.identification, self.identification, self.flags, self.fragment_offset, self.ttl, self.protocol, \
                 self._get_protoname(str(self.protocol)), self.src_addr, self.dest_addr)
        return head + body + foot
    
    def contains_udp(self):
        if self.protocol == 17:
            return True
        return False

    def contains_tcp(self):
        if self.protocol == 6:
            return True
        return False

    def contains_icmp(self):
        if self.protocol == 1:
            return True
        return False

    def pack(self,ip_query,ip_data):
        length = len(ip_data) + 20
        frame = "\x45" # Version + header size
        frame += "\x00" # tos
        frame += pack('!H',length) # 20 = header size
        frame += "\x00\x00" # ident.
        frame += "\x40\x00" # flags fragment offset
        frame += pack('!B',ip_query.ttl) # ttl
        frame += chr(17) # UDP protocol
        frame += "\x00\x00" # header checksum
        frame += ip_query.dest_addr_raw # src = dest
        frame += ip_query.src_addr_raw # dest = src
        checksum = self.checksum(frame)
        final_frame = frame[0:10] + checksum + frame[12:]
        final_frame += ip_data

        #log.debug("PACKED IP FRAME: %s", repr(final_frame))
        return final_frame

    def checksum(self, data):
        ''' according to http://bla.thera.be/uploads/con.py '''
        l = len(data)
        s = 0
        for i in range(0, l, 2):
            part = data[i:i+2]
            val = int(part.encode('hex'), 16)
            s = (s + val) % 0xFFFF

        s = ~s & 0xFFFF
        return pack('>H', s)

    def unpack(self, frame):
        try:
            # Calculate header size
            header_len = calcsize(IP_HEADER_FORMAT)
            #log.debug(frame)
            #log.debug("Header length: %d", header_len)
            
            # Extract header fields
            ip_header = frame[:header_len]
            #log.debug("IP HEADER: %s", repr(ip_header))
            ip_header = unpack(IP_HEADER_FORMAT, ip_header)
            self.version = (ip_header[0] >> 4)
            self.header_length = (ip_header[0] & 0b00001111) * 32 / 8 # Value is a multiple of 32
            self.tos = ip_header[1]
            self.total_length = ip_header[2]
            self.identification = ip_header[3]
            self.flags = (ip_header[4] & 0b11100000) # To Do: Working?
            self.fragment_offset = (ip_header[4] & 0b000111111) # To Do: Working?
            self.ttl = ip_header[5]
            self.protocol = ip_header[6]
            self.src_addr_raw = ip_header[8]
            self.src_addr = self._get_ipaddr(self.src_addr_raw)
            self.dest_addr_raw = ip_header[9]
            self.dest_addr = self._get_ipaddr(self.dest_addr_raw)
            self.data = frame[header_len:self.total_length]
    
            #log.debug("IP DATA: %s", repr(self.data))
        except Exception as e:
            raise Exception("IP unpack error: %s" % e)
        
    def _b2h(self, val):
        return int(hexlify(val),16)
    
    def _get_protoname(self, val):
        # All codes can be found here: https://en.wikipedia.org/wiki/EtherType
        if val in IP_HEADER_PROTOCOLS:
            return IP_HEADER_PROTOCOLS[val]
        
    def _get_ipaddr(self, addr):
        return ("%d.%d.%d.%d" % (self._b2h(addr[0]), self._b2h(addr[1]), self._b2h(addr[2]), self._b2h(addr[3])))


class PseudoHeader():
    def __init__(self):
        self.sourceIP = 0
        self.destIP = 0
        self.placeholder = 0
        self.protocol = 17
        self.length = 0
        self.format = "!LLxBH"

    def pack(self):
        """ Create a string from a pseudoheader """
        string = self.sourceIP + self.destIP
        string += pack('!x')
        string += pack('!BH', self.protocol, self.length)

        return string
