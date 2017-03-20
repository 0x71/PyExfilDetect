# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging

try:
    from lib.common.constants import DNS_STREAM_TIMEOUT, ICMP_STREAM_TIMEOUT
    from modules.tcpstream import TCPStream
    from modules.udpstream import UDPStream
    from modules.icmpstream import ICMPStream
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))

log = logging.getLogger(__name__)

class Host():
    ''' Host-based stream identification. '''
    
    def __init__(self):
        log.debug("Host created.")
        self.ip_addr = 0
        self.host_identifier = 0
        self.streams = []
    
    def __del__(self):
        log.debug("Host destroyed.")
        
    def __getitem__(self,index):
        return self.streams[index]

    def set_addr(self, ip):
        self.ip_addr = ip
        log.debug("IP %s set.", ip)
        
    def create_stream(self, protocol, first_packet, identifier):
        log.debug("[Host %s]: Adding stream (%s).", self.host_identifier, identifier)
        if protocol == "tcp":
            # Add tcp stream
            self.streams.append(TCPStream())
        elif protocol == "udp" or protocol == "dns":
            # Add udp stream
            self.streams.append(UDPStream())
        elif protocol == "icmp":
            # Add icmp stream
            self.streams.append(ICMPStream())

        # Set first time stamp
        self.streams[-1].first_timestamp = first_packet.timestamp
        
        # Unique stream identifier for this session
        self.streams[-1].identifier = identifier

        self.streams[-1].add_packet(first_packet)

        log.debug("[Stream %s]: Created. First Timestamp: %s" % (self.streams[-1].identifier, self.streams[-1].first_timestamp))
        
    def check_stream(self, packet, filter_qname=None):
        log.debug("[Host %s]: Checking stream.", self.host_identifier)
        for stream in self.streams:
            if "tcp" in stream.type and packet.has_layer("tcp"):
                if stream.is_equal(packet["ip"].src_addr,packet["ip"].dest_addr, packet["tcp"].src_port, packet["tcp"].dest_port):
                    log.debug("TCP STREAM FOUND!")
                    return stream

            # DNS identification
            elif "dns" in stream.type and packet.has_layer("dns"):
                if (packet.timestamp - stream.last_timestamp) < DNS_STREAM_TIMEOUT:
                    if stream.contains_qname(packet["dns"].secondlevel_qname):
                        log.debug("[Stream %s]: Contains QNAME!" % stream.identifier)

                        if stream.is_dns_equal(packet["ip"].src_addr,packet["ip"].dest_addr, packet["udp"].src_port, packet["udp"].dest_port):
                            log.debug("[Stream %s]: Found." % stream.identifier)
                            return stream
                        else:
                            log.debug("QNAME FOUND; STREAM NOT FOUND.")
                else:
                    log.debug("[Stream %s]: Too old (disable stream)." % stream.identifier)
                    stream.active = False

            # ICMP identification
            elif "icmp" in stream.type and packet.has_layer("icmp"):
                if (packet.timestamp - stream.last_timestamp) < ICMP_STREAM_TIMEOUT:
                    if stream.is_equal(packet["ip"].src_addr, packet["ip"].dest_addr, packet["icmp"].sess_id):
                        log.debug("[Stream %s]: ICMP STREAM FOUND!" % stream.identifier)
                        return stream
                else:
                    log.debug("[Stream %s]: Too old (disable stream)." % stream.identifier)
                    stream.active = False

        return None