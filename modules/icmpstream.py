# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.
import logging
import hashlib

log = logging.getLogger(__name__)

class ICMPStream():
    ''' ICMP packet allocation '''
    def __init__(self):
        self.src_addr = None
        self.dest_addr = None
        self.identifier = None
        self.sess_id = None
        self.packets = []
        self.packet_count = 0
        self.byte_count = 0
        self.request_count = 0
        self.response_count = 0
        self.request_byte_count = 0
        self.response_byte_count = 0
        self.first_timestamp = 0
        self.last_timestamp = 0
        self.type = "icmp"
        self.ts_all = []
        self.ts_out = []
        self.ts_in = []
        self.last_timestamps = [0,0] # outgoing, incoming
        self.unique_datafield = []
        self.active = True
        
    def __iter__(self):
        return iter(self.packets)
    
    def __getitem__(self, index):
        return self.packets[index]
    
    def index(self, packet):
        return self.packets.index(packet)
    
    def __len__(self):
        return len(self.packets)
    
    def add_packet(self, packet):
        # Add the whole packet to the icmpstream
        self.packets.append(packet)
        
        # Increment the total number of packets in stream
        self.packet_count = self.packet_count + 1
        
        # Increment the total byte number in stream
        self.byte_count = self.byte_count + packet["eth"].size

        # check for the first packet (request)
        if len(self.packets) == 1:
            # log.debug("Syn packet identified.")
            self.src_addr = packet["ip"].src_addr
            self.dest_addr = packet["ip"].dest_addr
            self.sess_id = packet["icmp"].sess_id
            
            self.last_timestamps[0] = packet.timestamp
            self.last_timestamps[1] = packet.timestamp
        else:
            self.ts_all.append(packet.timestamp)

        self.last_timestamp = packet.timestamp

        if packet["icmp"].is_echo_request(): # Outgoing
            self.request_count = self.request_count + 1
            self.request_byte_count = self.request_byte_count + packet["eth"].size

            if self.request_count > 1:
                self.ts_out.append(packet.timestamp)
                self.last_timestamps[0] = packet.timestamp
        elif packet["icmp"].is_echo_reply(): # Incoming
            self.response_count = self.response_count + 1
            self.response_byte_count = self.response_byte_count + packet["eth"].size

            if self.response_count > 1:
                self.ts_in.append(packet.timestamp)
                self.last_timestamps[1] = packet.timestamp

        if packet["icmp"].data:
            data_hash = hashlib.md5(packet["icmp"].data).hexdigest()#
            #log.info("DATA HASH: %s" % data_hash)
            if data_hash not in self.unique_datafield:
                self.unique_datafield.append(data_hash)

    def remove_packet(self,packet):
        # remove the packet
        self.packets.remove(packet)

        # decrement total number of packets in stream
        self.packet_count = self.packet_count - 1
    
    def is_equal(self, src_addr, dest_addr, id):
        # General check
        if self.src_addr == src_addr:
            if self.dest_addr == dest_addr:
                #if self.sess_id == id:
                return True   
        elif self.src_addr == dest_addr:
            if self.dest_addr == src_addr:
                #if self.sess_id == id:
                return True
        return False