# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging

try:
    from struct import pack, unpack, calcsize
    from binascii import hexlify
    from lib.common.constants import IP_HEADER_PROTOCOLS
    from modules.ippacket import PseudoHeader
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))

log = logging.getLogger(__name__)

# Head (size without optional fields: 20 bytes)
TCP_HEADER_FORMAT = "!HHLLBBHHH"

class TCPPacket():
    """ Handling udp packets. """
    def __init__(self,src_port = None, dest_port = None, seq_num = None, ack_num = None, data_off = None, 
                 flags = None, urg = None, ack = None, psh = None, rst = None, syn = None, fin = None, 
                 window = None, cksum = None, urg_pointer = None, opts = None, data = None):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_off = data_off
        self.flags = flags
        self.flag_urg = urg # urgent flag
        self.flag_ack = ack # acknowledgment flag
        self.flag_psh = psh
        self.flag_rst = rst # reset flag
        self.flag_syn = syn # syn flag
        self.flag_fin = fin # finish flag
        self.window = window # receive window
        self.cksum = cksum # checksum
        self.urg_pointer = urg_pointer # urgent pointer
        self.opts = opts
        self.data = data
    
    def __del__(self):
        pass

    def __repr__(self):
        head = "================ tcp_segment =================\n"
        foot = "==============================================\n"
        body = ("src_port:\t %s\n" \
               +"dest_port:\t %s\n"
               +"seq_num:\t %s\n"
               +"ack_num:\t %s\n"
               +"data_off:\t %s\n"
               +"urg|ack|psh-\nrst|syn|fin:\t %s|%s|%s|%s|%s|%s (0x%.3x)\n"
               +"window:\t\t %s Byte\n"
               +"checksum:\t %s\n"
               +"urg_point:\t %s\n"
               +"options:\t not implemented\n"
               +"data:\t\t %s\n") \
              % (self.src_port, self.dest_port, self.seq_num, self.ack_num, self.data_off, 
                 self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, 
                 self.flag_fin, self.flags, self.window, hex(self.cksum),self.urg_pointer, 
                 repr(self.data))
        return head + body + foot

    def __lt__(self,other):
        ''' 'less than' operator. Used to arrange tcp packets comparing their sequence numbers. '''
        return self.seq_num < other.seq_num

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

        tmp_data  = pack(TCP_HEADER_FORMAT,self.src_port,self.dest_port,self.length,self.cksum)
        tmp_data = tmp_data + self.data

        #log.debug("UDP_PACKED: %s", repr(tmp_data))
        return tmp_data

    def unpack(self, datagram):
        try:
            # Calculate header size
            header_len = calcsize(TCP_HEADER_FORMAT)
            
            # Extract header fields
            tcp_header = datagram[:header_len]
            #log.debug("TCP_HEADER_SIZE: %d", header_len)
            tcp_header = unpack(TCP_HEADER_FORMAT, tcp_header)
            self.src_port = tcp_header[0]
            self.dest_port = tcp_header[1]
            self.seq_num = tcp_header[2]
            self.ack_num = tcp_header[3]
            self.data_off = (tcp_header[4] >> 4) * 32 / 8 # header length
            self.flags = tcp_header[5] 
            self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin = self._resolve_flags(tcp_header[5])
            self.window = tcp_header[6]
            self.cksum = tcp_header[7]
            self.urg_pointer = tcp_header[8]
            
            # options
            # starting after the urgent pointer header field
            # with a length of data_offset * 32 / 8 (Bytes)
            self.opts = datagram[header_len:self.data_off]
            header_len = self.data_off
            #log.debug("TCP_HEADER_SIZE: %d", header_len)
            
            # data 
            self.data = datagram[header_len:]
            #log.debug("UDP_DATA: %s", repr(self.data))
        except Exception as e:
            raise Exception("TCP unpack error: %s" % e)
        
    def _resolve_flags(self, head_data):
        urg = (head_data >> 5) & 0x01
        ack = (head_data >> 4) & 0x01
        psh = (head_data >> 3) & 0x01
        rst = (head_data >> 2) & 0x01
        syn = (head_data >> 1) & 0x01
        fin = head_data & 0x01
        
        return urg, ack, psh, rst, syn, fin

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

    def get_data_size(self,ip_total_len):
        return ip_total_len - 20 - self.data_off

    def is_syn_packet(self):
        ''' Identification of syn packet:
            syn_flag = 1,
            ack_flag = 0
        '''
        if self.flag_syn == 1 and self.flag_ack == 0:
            return True
        return False

    def is_closing_packet(self):
        ''' Identification of first and second tcp stream termination packets:
            fin_flag = 1,
            ack_flag = 1
        '''
        if self.flag_fin == 1 and self.flag_ack == 1:
            return True
        return False

    def is_final_closing_packet(self):
        ''' Identification of final tcp stream termination packet:
            fin_flag = 0,
            ack_flag = 1
        '''
        if self.flag_fin == 0 and self.flag_ack == 1:
            return True
        return False
