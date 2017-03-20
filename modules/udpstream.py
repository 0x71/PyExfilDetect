# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging

log = logging.getLogger(__name__)

class UDPStream():
    ''' UDP packet allocation '''
    def __init__(self):
        self.src_addr = None
        self.dest_addr = None
        self.base_port = None
        self.identifier = None
        self.packets = []
        self.packet_count = 0
        self.byte_count = 0
        self.request_count = 0
        self.response_count = 0
        self.request_byte_count = 0
        self.response_byte_count = 0
        self.first_timestamp = 0 # When was the first packet seen?
        self.last_timestamp = 0
        self.dns_qname = None # Only for DNS querys
        self.ts_all = []
        self.ts_out = []
        self.ts_in = []
        self.last_timestamps = [0,0] # outgoing, incoming
        self.type = "udp"
        self.active = True
        self.unique_subdomains = []
        self.subdomain_length = []
    
    def __iter__(self):
        return iter(self.packets)
    
    def __getitem__(self, index):
        return self.packets[index]
    
    def index(self, packet):
        return self.packets.index(packet)
    
    def __len__(self):
        return len(self.packets)
    
    def add_packet(self, packet):
        # Add the whole packet to the udpstream
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
            self.base_port = packet["udp"].dest_port # e.g. 53 for UDP

            # Special case: DNS
            # Extract First DNS Qname as we are interested in requests for the same qname            
            if packet.has_layer("dns"):
                self.type = "dns"
                self.dns_qname = packet["dns"].secondlevel_qname
            else:
                log.debug("CONTAINS NO DNS")
            
            self.last_timestamps[0] = packet.timestamp
            self.last_timestamps[1] = packet.timestamp

        else:
            self.ts_all.append(packet.timestamp)
            if self.ts_all[-1] < 0:
                log.warning(self.ts_all[-1])
                log.warning(packet["dns"].query_data[0]["qname"])
                log.warning(packet.timestamp)
                log.warning(self.last_timestamp)

        self.last_timestamp = packet.timestamp
        
        # Query or Response? (DNS)
        if packet.has_layer("dns"):
            # Outgoing -> Request
            if packet["udp"].dest_port == 53:
                self.request_count = self.request_count + 1
                self.request_byte_count = self.request_byte_count + packet["eth"].size

                self.ts_out.append(packet.timestamp)
                # Update temporary timestamp
                self.last_timestamps[0] = packet.timestamp
            # Incoming -> Response
            elif packet["udp"].src_port == 53:
                self.response_count = self.response_count + 1
                self.response_byte_count = self.response_byte_count + packet["eth"].size
                
                self.ts_in.append(packet.timestamp)
                self.last_timestamps[1] = packet.timestamp

            if packet["dns"].subdomains:
                # Collect unique subdomains
                if packet["dns"].subdomains not in self.unique_subdomains:
                    self.unique_subdomains.append(packet["dns"].subdomains)

                # Collect subdomain length
                self.subdomain_length.append(len(packet["dns"].subdomains))
                #log.debug("SUBDOMAIN: %s, LENGTH: %s" % (packet["dns"].subdomains, self.subdomain_length[-1]))

    def remove_packet(self,packet):
        # remove the packet
        self.packets.remove(packet)

        # decrement total number of packets in stream
        self.packet_count = self.packet_count - 1
        
    def is_equal(self, src_addr, dest_addr, src_port, dest_port):
        # To Do: Check for DNS, ICMP
        
        # General check
        if self.src_addr == src_addr:
            if self.dest_addr == dest_addr:
                if self.base_port == dest_port:
                    return True    
        elif self.src_addr == dest_addr:
            if self.dest_addr == src_addr:
                if self.base_port == src_port:
                    return True
        return False
    
    def is_dns_equal(self, src_addr, dest_addr, src_port, dest_port):
        if self.src_addr == src_addr: # host = src
            if self.base_port == dest_port:
                return True
        elif self.src_addr == dest_addr: # server = src
            if self.base_port == src_port:
                return True
        return False

    def contains_qname(self, qname):
        # log.debug("STREAM_QNAME: %s, PACKET_QNAME: %s" % (self.dns_qname, qname))
        if qname in self.dns_qname:
            return True
        return False