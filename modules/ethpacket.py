# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
from struct import pack, unpack, calcsize
from binascii import hexlify

log = logging.getLogger(__name__)

# Destination, Source, Type
ETH_HEADER_FORMAT = "!6s6sH"

class EthPacket():
    """ Handling ethernet packets. """
    def __init__(self):
        self.interface = None
        self.dest_addr = None
        self.src_addr = None
        self.dest_addr_raw = None
        self.src_addr_raw = None
        self.type = None
        self.data = None # Frame data
        self.size = None # Packet size
    
    def __del__(self):
        pass
    
    def __repr__(self):
        head = "================ eth_frame ===================\n"
        foot = "==============================================\n"
        body = ("dest_mac:\t%s\n"
              +"src_mac:\t%s\n"
              +"type:\t\t0x%.4x (%s)\n") % (self.dest_addr, self.src_addr, self.type, self._get_typecode(hex(self.type)))
        return head + body + foot
    
    def contains_ip(self):
        if hex(self.type) == "0x800":
            return True
        return False

    def pack(self,eth_query,packed_data):
        header = eth_query.src_addr_raw # dest = query src
        header += eth_query.dest_addr_raw # src = query dest
        header += pack('!H', eth_query.type) # type (should be IP)
        log.debug("PACKED HEADER: %s", repr(header))
        final_data = header + packed_data
        return final_data
    
    def unpack(self, frame, pcap=False):
        try:
            # Calculate header size
            header_len = calcsize(ETH_HEADER_FORMAT)
            
            if not pcap: # frame is a list as it is created by raw sockets
                # Extract interface
                self.interface = frame[1][0]
    
                # Extract header fields
                eth_header = frame[0][:header_len]
                #log.debug("ETH_HEADER: %s", repr(eth_header))
                eth_header = unpack(ETH_HEADER_FORMAT, eth_header)
                self.dest_addr_raw = eth_header[0]
                self.dest_addr = self._eth_addr(self.dest_addr_raw)
                self.src_addr_raw = eth_header[1]
                self.src_addr = self._eth_addr(self.src_addr_raw)
                self.type = eth_header[2]
                self.data = frame[0][header_len:]
                #log.debug("ETH_DATA: %s", repr(self.data))
                self.size = len(frame[0])
    
            else: # frame is no list
                # Extract interface
                self.interface = None
    
                # Extract header fields
                eth_header = frame[:header_len]
                #log.debug("ETH_HEADER: %s", repr(eth_header))
                eth_header = unpack(ETH_HEADER_FORMAT, eth_header)
                self.dest_addr_raw = eth_header[0]
                self.dest_addr = self._eth_addr(self.dest_addr_raw)
                self.src_addr_raw = eth_header[1]
                self.src_addr = self._eth_addr(self.src_addr_raw)
                self.type = eth_header[2]
                self.data = frame[header_len:]
                #log.debug("ETH_DATA: %s", repr(self.data))
                self.size = len(frame)
        except Exception as e:
            raise Exception("ETH unpack error: %s" % e)
        
    def _eth_addr(self, raw):
        return ('%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' \
            % (self._b2h(raw[0]), self._b2h(raw[1]), self._b2h(raw[2]),
               self._b2h(raw[3]), self._b2h(raw[4]), self._b2h(raw[5])))
        
    def _b2h(self, val):
        return int(hexlify(val),16)
    
    def _get_typecode(self, hexval):
        # All codes can be found here: https://en.wikipedia.org/wiki/EtherType
        if hexval == "0x800":
            return "IP"
        elif hexval == "0x806":
            return "ARP"
        