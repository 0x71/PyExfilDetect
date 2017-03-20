# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
from struct import pack, unpack, calcsize
from binascii import hexlify
from lib.common.constants import IP_HEADER_PROTOCOLS
from modules.ippacket import PseudoHeader

log = logging.getLogger(__name__)

# Head (size without optional fields: 20 bytes)
UDP_HEADER_FORMAT = "!HHHH"

class UDPPacket():
    """ Handling udp packets. """
    def __init__(self,src_port = None, dest_port = None, length = None, checksum = None, data = None):
        self.src_port = src_port
        self.dest_port = dest_port
        self.length = length
        self.cksum = checksum
        self.data = data
    
    def __del__(self):
        pass

    def __repr__(self):
        head = "================ udp_segment =================\n"
        foot = "==============================================\n"
        body = ("src_port:\t %s\n" \
               +"dest_port:\t %s\n"
               +"length:\t\t %s (%s)\n"
               +"checksum:\t %s\n") \
              % (self.src_port, self.dest_port, self.length, hex(self.length), self.cksum)
        return head + body + foot
    
    def contains_dns(self):
        if self.src_port == 53 or self.dest_port == 53:
            return True
        return False

    def pack(self, udp_data, packed_data, src_ip, dest_ip):
        if not self.src_port:
            self.src_port = udp_data.dest_port
        if not self.dest_port:
            self.dest_port = udp_data.src_port
        self.length = len(packed_data) + 8
        self.cksum = 0
        self.data = packed_data

        self.cksum = self.checksum(src_ip, dest_ip)

        tmp_data  = pack(UDP_HEADER_FORMAT,self.src_port,self.dest_port,self.length,self.cksum)
        tmp_data = tmp_data + self.data

        #log.debug("UDP_PACKED: %s", repr(tmp_data))
        return tmp_data

    def unpack(self, datagram):
        try:
            # Calculate header size
            header_len = calcsize(UDP_HEADER_FORMAT)

            # Extract header fields
            udp_header = datagram[:header_len]
            #log.debug("UDP_HEADER: %s", repr(udp_header))
            udp_header = unpack(UDP_HEADER_FORMAT, udp_header)
            self.src_port = udp_header[0]
            self.dest_port = udp_header[1]
            self.length = udp_header[2]
            self.cksum = udp_header[3]
            self.data = datagram[header_len:self.length]
            #log.debug("UDP_DATA: %s", repr(self.data))
        except Exception as e:
            raise Exception("UDP unpack error: %s" % e)
        
    def _b2h(self, val):
        return int(hexlify(val),16)
    
    def _get_protoname(self, val):
        # All codes can be found here: https://en.wikipedia.org/wiki/EtherType
        if val in IP_HEADER_PROTOCOLS:
            return IP_HEADER_PROTOCOLS[val]
        
    def _get_ipaddr(self, addr):
        return ("%d.%d.%d.%d" % (self._b2h(addr[0]), self._b2h(addr[1]), self._b2h(addr[2]), self._b2h(addr[3])))

    def checksum(self, src_ip, dest_ip):
        # Prepare IP pseudo header
        p = PseudoHeader()
        p.sourceIP = src_ip
        p.destIP = dest_ip
        p.length = self.length

        pad = ''
        if len(self.data) % 2 == 1:
            pad = '\x00'

        ip_part = p.pack()
        udp_part = pack('!HHHH',self.src_port,self.dest_port,self.length,0)
        udp_part += self.data

        # Fuse IP pseudo header + UDP header + UDP data + padding
        data = ip_part + udp_part + pad

        # Calculate checksum
        sum = 0
        for i in range(0,len(data),2):
            if i + 1 >= len(data):
                sum += ord(data[i]) & 0xFF
            else:
                w = ((ord(data[i]) << 8) & 0xFF00) + (ord(data[i+1]) & 0xFF)
                sum += w

        # take only 16 bits out of the 32 bit sum and add up the carries
        while (sum >> 16) > 0:
            sum = (sum & 0xFFFF) + (sum >> 16)

        # one's complement the result
        sum = ~sum

        return sum & 0xFFFF
