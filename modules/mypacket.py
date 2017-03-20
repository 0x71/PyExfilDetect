# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import sys

try:
    from ethpacket import EthPacket
    from ippacket import IPPacket
    from udppacket import UDPPacket
    from dnspacket import DNSPacket
    from tcppacket import TCPPacket
    from icmppacket import ICMPPacket
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
class MyPacket():
    def __init__(self):
        self.data = dict() # Holds all network layers of a packet
        self.timestamp = None
        self.internal_id = None
        
    def __getitem__(self,key):
        return self.data[key]
    
    def __setitem__(self,key,value):
        self.data[key] = value
    
    def __repr__(self):
        val = ""
        for key, value in self.data.items():
            val = val + repr(value)
        return val
            
    def add_layer(self,name):
        ''' Add a new network layer to the dictionary. '''
        if "eth" in name:
            self.data["eth"] = EthPacket()
        elif "ip" in name:
            self.data["ip"] = IPPacket()
        elif "udp" in name:
            self.data["udp"] = UDPPacket()
        elif "tcp" in name:
            self.data["tcp"] = TCPPacket()
        elif "dns" in name:
            self.data["dns"] = DNSPacket()
        elif "icmp" in name:
            self.data["icmp"] = ICMPPacket()

    def has_layer(self, name):
        ''' Check dictionary for existing network layer. '''
        if name in self.data:
            return True
        return False