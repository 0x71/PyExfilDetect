# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import ConfigParser
from time import time
from socket import *
from threading import Timer, Thread, Event

try:
    from lib.common.constants import APP_ROOT, SUPPORTED_PROTOCOLS
    from lib.common.colors import color
    from modules.mypacket import MyPacket

except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
log = logging.getLogger(__name__)

class TimerClass(Thread):
    ''' Small timer class to print current pcap parsing status. '''
    stoprequest = Event()
    def __init__(self):
        log.debug("TimerClass started.")
        Thread.__init__(self)
        self.event = Event()

    def __del__(self):
        log.debug("TimerClass stopped.")

    def run(self):
        while not TimerClass.stoprequest.is_set():
            TimerClass.stoprequest.wait(5)
            log.info("%s/%s read (%.2f%%)." % (Sniffer.packet_count, Sniffer.total_count, round((Sniffer.packet_count/float(Sniffer.total_count))*100.0,2)))
        log.info(color("Done.",32))

class Sniffer():
    packet_count = 0
    total_count = 0
    def __init__(self, sniff_sock=None, packet_data=None, protocols=None, ip=None):
        log.debug("Sniffer started.")
        # To Do: Error Handling
        self.my_socket = sniff_sock # Only set if no file is specified
        self.raw_data = None
        self.packet_data = packet_data # Only set if a pcap file is specified
        self.packet_count = 0
        self.filter_count = 0
        self.byte_count = 0
        self.protocol_filter = []
        self.ip_filter = None
        self.data_len = False
        self.limiter = 0
        self.timer = None

        if packet_data: # pcap packet list
            self.data_len = len(packet_data)
            Sniffer.total_count = self.data_len
            Sniffer.packet_count = 0
            self.timer = TimerClass()

        if self.timer:
            TimerClass.stoprequest = Event()
            self.timer.start()

        self.parse_config(protocols, ip)

        if self.my_socket:
            # start socket
            self.my_socket.start()

    def __del__(self):
        log.debug("Sniffer stopped.")
        log.debug("Total number of sniffed packets: %s (%s bytes)." % (self.packet_count, self.byte_count))
        log.debug("Total number of (IP) filtered packets: %s." % (self.filter_count))

    def parse_config(self, protocols, ips):
        cfg = ConfigParser.ConfigParser()

        try:
            cfg.read(os.path.join(APP_ROOT, "conf", "sniffer.conf"))

            # Protocols specified using the command line?
            if protocols:
                filter_list = protocols.split(",")
                for protocol in filter_list:
                    self.add_filter(protocol)
            # Protocols specified in config file?
            else:
                # Parse protocols
                protocols = cfg.get("basics", "protocols")
                if protocols:
                    for protocol in protocols.split(','):
                        self.add_filter(protocol)
                # No protocols specified at all --> Loading all supported protocols 
                else:
                    for protocol in SUPPORTED_PROTOCOLS:
                        self.add_filter(protocol)

            # Parse IPs and IP tuples that must be filtered
            self.ip_filter = []
            if ips:
                ip_list = ips.split(",")
                for ip in ip_list:
                    self.ip_filter.append(ip)

            normal = cfg.get("filter","normal")
            if normal:
                ip_list = normal.split(",")
                for ip in ip_list:
                    self.ip_filter.append(ip)

        except:
            sys.exit("ERROR: Reading 'sniffer.conf'")

        log.info("Sniffing for protocols: %s", self.protocol_filter) # All seen packets
        log.info("Filtering IPs: %s", self.ip_filter) # Packets filtered by IP filter

    def add_filter(self, protocol):
        if protocol not in self.protocol_filter:
            self.protocol_filter.append(protocol)
        
    def sniff(self):
        try:
            # Sniffing mode
            if self.my_socket:
                try:
                    raw_data = self.my_socket.recv()
                except timeout: # socket.timeout
                    return None
                t = time()
                #log.debug(data)

                return self.unpack(raw_data, t)

            # Parser mode
            elif self.packet_data:
                my_packet = self.unpack(self.packet_data[0][1], self.packet_data[0][0], pcap=True) # unpack(packed_data, timestamp)
                self.packet_data.pop(0)
                if len(self.packet_data) == 0:
                    TimerClass.stoprequest.set()
                return my_packet

            return None
        except Exception as e:
            log.error("Sniffer error: %s", e)

    def unpack(self, raw_data, time, pcap=False):
        try:
            # Create an empty packet
            my_packet = MyPacket()
            my_packet.timestamp = time
            my_packet.internal_id = self.packet_count + 1
    
            # Extract ethernet frame
            my_packet.add_layer("eth")
            my_packet["eth"].unpack(raw_data, pcap)
    
            if pcap == False and self.my_socket:
                # Check interface before unpacking
                if my_packet["eth"].interface not in self.my_socket.interfaces:
                    return None
    
            # Count all packets I see for the interfaces in scope
            self.packet_count = self.packet_count + 1 # got one!
            Sniffer.packet_count = Sniffer.packet_count +1
    
            # Count total sniffed packet bytes
            self.byte_count = self.byte_count + my_packet["eth"].size
    
            # We are just interested in IP packets for now
            if my_packet["eth"].contains_ip():
                # Extract ip frame
                my_packet.add_layer("ip")
                my_packet["ip"].unpack(my_packet["eth"].data)

                if self.ip_filter:
                    if my_packet["ip"].src_addr in self.ip_filter or my_packet["ip"].dest_addr in self.ip_filter:
                        self.filter_count = self.filter_count + 1
                        return None
    
                if my_packet["ip"].contains_udp() and (("udp" in self.protocol_filter) or ("dns" in self.protocol_filter)): # UDP
                    my_packet.add_layer("udp")
                    my_packet["udp"].unpack(my_packet["ip"].data)
    
                    if my_packet["udp"].contains_dns() and "dns" in self.protocol_filter: # DNS
    
                        my_packet.add_layer("dns")
                        my_packet["dns"].unpack(my_packet["udp"].data)
    
                        # Additional filter to ignore SOA packets for the moment
                        if my_packet["dns"].flags == 0x2800 or my_packet["dns"].flags == 0xa800: # dynamic update query or response
                            return None

                        return my_packet

                    if "udp" in self.protocol_filter:
                        return my_packet
    
                elif my_packet["ip"].contains_tcp() and "tcp" in self.protocol_filter: # TCP
                    my_packet.add_layer("tcp")
                    my_packet["tcp"].unpack(my_packet["ip"].data)
    
                    return my_packet
    
                elif my_packet["ip"].contains_icmp() and "icmp" in self.protocol_filter: # ICMP
                    my_packet.add_layer("icmp")
                    my_packet["icmp"].unpack(my_packet["ip"].data)
    
                    return my_packet
            return None
        except Exception as e:
            log.error("Cannot parse packet %s (%s). Skipping" % (self.packet_count, e))
            return None