# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import logging
from struct import unpack, pack, calcsize
from binascii import hexlify, unhexlify
from lib.common.constants import IP_HEADER_PROTOCOLS

log = logging.getLogger(__name__)

# Head (size without optional fields: 20 bytes)
UDP_HEADER_FORMAT = "!HHHHHH"

class DNSPacket():
    """ Handling udp packets. """
    def __init__(self, id=None, flags=None, qdcount=None, ancount=None, nscount = None, arcount = None, query_data = list(), response_data = list()):
        self.id = id # transaction ID
        self.flags = flags
        self.qdcount = qdcount # number of entries in question section
        self.ancount = ancount # number of rr in answer section
        self.nscount = nscount # number of rr in authority records section
        self.arcount = arcount # number of rr in additional records section
        self.query_data = list()
        self.response_data = list()
        self.secondlevel_qname = None
        self.subdomains = None
    
    def __del__(self):
        pass
    
    def __repr__(self):
        head = "================ dns_data ====================\n"
        foot = "==============================================\n"
        body = (("id:\t\t %s\n" \
               +"flags:\t\t %s (%s)\n"
               +"qd|an|ns|ar #:\t %s|%s|%s|%s\n"
               )
               % (hex(self.id), hex(self.flags), self._get_msg_type(), self.qdcount, self.ancount, self.nscount, self.arcount))
        body = body + self._print_data()
        return head + body + foot
    
    def pack(self, query_data):
        # create dns header
        dns_header = pack(UDP_HEADER_FORMAT, self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount)
        #log.debug("PACKED HEADER: %s", repr(dns_header))

        # create dns data
        dns_data = ""
        for q in query_data: # query
            dns_tmp_data = ""
            qname = q["qname"].split(".")
            #log.debug(qname)
            for val in qname:
                dns_tmp_data = dns_tmp_data + pack('!B%ds' % len(val),len(val),val)
            dns_tmp_data = dns_tmp_data + pack('!BHH',0,1,1) # zero-terminated string, type, class
            #log.debug("TMP_DATA: %s", repr(dns_tmp_data))
            dns_data = dns_data + dns_tmp_data # Append to other queries

        for i in range(0,self.ancount): # answer
            dns_tmp_data = ""
            qname = 0xc00c # pointer to query
            qtype = 1
            qclass = 1
            ttl = 10
            rdlength = 4
            rddata = "192.168.2.111" # "193.99.144.80"
            dns_tmp_data = pack('!HHHIH4B',qname,qtype,qclass,ttl,rdlength,*(int(x) for x in rddata.split('.')))
            #log.debug("joining..")
            dns_data = dns_data + dns_tmp_data
            #log.debug("PACKED DATA:: %s", repr(dns_tmp_data))

        dns_packet = ''.join([dns_header,dns_data]) # header + data
        #log.debug("PACKED_DNS_PACKET: %s", repr(dns_packet))
        return dns_packet
    
    def unpack(self, data):
        try:
            # Calculate header size
            header_len = calcsize(UDP_HEADER_FORMAT)
            # Extract header fields
            udp_header = data[:header_len]
            #log.debug("UDP_HEADER: %s", repr(udp_header))
            udp_header = unpack(UDP_HEADER_FORMAT, udp_header)
            self.id = udp_header[0]
            self.flags = udp_header[1]
            self.qdcount = udp_header[2]
            self.ancount = udp_header[3]
            self.nscount = udp_header[4]
            self.arcount = udp_header[5]

            # Ignore dynamic update requests and responses for now as we dont need it for later analysis (quick and dirty solution)
            # Should be parsed in the future
            if self.flags == 0x2800 or self.flags == 0xa800:
                return
    
            # Extract dns data according to message type
            # http://tools.ietf.org/html/rfc1035
            # http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
            udp_data = data[header_len:] # contains all dns_data (query and response data)
            #log.debug("UDP_DATA: %s", repr(udp_data))
            start = 0 # pointer to current position
            
            for i in range(self.qdcount): # for every query
                query = dict() # one dict for every query
                qname = [] # helper
    
                # extract qname labels
                # according to http://www.freesoft.org/CIE/RFC/1035/40.htm
                while True:
                    # length of the next label
                    qname_length = unpack('!B',udp_data[start:start+1])[0] # I dont know why, but unpack return a tuple here..
    
                    # set current position one forward
                    start = start + 1
                    if qname_length == 0: # we are done when we reach zero (zero-terminated string)
                        break
                    # unpack label using the extracted length
                    qname.append(unpack('{0}s'.format(str(qname_length)), udp_data[start:start+qname_length])[0]) # same here
    
                    start = start + qname_length # update position
    
                # create the full qname string and add it to the dict
                query["qname"] = ".".join(qname)
                # Extract second level domain (only once)
                if i == 0:
                    self.secondlevel_qname = self.get_secondlevel(query["qname"])
                    self.subdomains = self.get_subdomains(query["qname"])

                # now we can extract the rest
                qdata_entries_format = '!HH' # qtype, qclass
                qdata_entries = unpack(qdata_entries_format, udp_data[start:start+calcsize(qdata_entries_format)])
                query["qtype"], query["qclass"] = qdata_entries
                self.query_data.append(query)
                start = start + calcsize(qdata_entries_format) # move forward
    
            for i in range(self.ancount): # number of answers
                response = dict()
                name = unpack('!H', udp_data[start:start+calcsize('!H')])[0]
                if name & 0xc000 == 0xc000: # compression mode, pointer to label in query
                    start = start+calcsize('!H')
                    response["name"] = self.query_data[0]["qname"]
    
                    # now we can extract the rest
                    rdata_entries_format = '!HHIH' # type, class, ttl, rdlength
                    rdata_entries = unpack(rdata_entries_format, udp_data[start:start+calcsize(rdata_entries_format)])
                    response["type"] = rdata_entries[0]
                    response["class"] = rdata_entries[1]
                    response["ttl"] = rdata_entries[2]
                    response["rdlength"] = rdata_entries[3]
                    start = start + calcsize(rdata_entries_format)
    
                    if response["type"] != 1 or response["class"] != 1:
                        # log.warning("I probably will not be able to parse the rdata field (wrong type (%s) or class(%s))." % (response["type"], response["class"]))
                        break
    
                    # extract rdata
                    rdata_data_format = '!{0}s'.format(response["rdlength"])
                    response["rddata"] = unpack(rdata_data_format, udp_data[start:start+calcsize(rdata_data_format)])[0]
                    response["rddata"] = self._get_ipaddr(response["rddata"])
                    self.response_data.append(response)
                    start = start + calcsize(rdata_data_format) # move forward
                else:
                    raise Exception("Cannot parse this label format right now (not implemented yet).")
        except Exception as e:
            raise Exception("DNS unpack error: %s" % e)

    def get_secondlevel(self, qname):
        try:
            return qname.split('.')[-2] + "." + qname.split('.')[-1]
        except IndexError:
            return qname

    def get_subdomains(self, qname):
        try:
            return '.'.join(qname.split('.')[0:-2])
        except IndexError:
            return None

    def _b2h(self, val):
        return int(hexlify(val),16)
    
    def _get_protoname(self, val):
        # All codes can be found here: https://en.wikipedia.org/wiki/EtherType
        if val in IP_HEADER_PROTOCOLS:
            return IP_HEADER_PROTOCOLS[val]
        
    def _get_ipaddr(self, addr):
        return ("%d.%d.%d.%d" % (self._b2h(addr[0]), self._b2h(addr[1]), self._b2h(addr[2]), self._b2h(addr[3])))

    def _get_msg_type(self):
        if self.flags & 0x8000 == 0:
            return "query"
        else:
            return "response"

    def resolve_flag(self, flag=""):
        if flag == "qr": # query or response?
            return (self.flags & 0x8000)
        if flag == "opcode": # Kind of query?
            return (self.flags & 0x7800)
        if flag == "aa": # authoritative answer?
            return (self.flags & 0x0400)
        if flag == "tc": # truncation?
            return (self.flags & 0x0200)
        if flag == "rd": # recursion desired?
            return (self.flags & 0x0100)
        if flag == "ra": # recursion available? (response=
            return (self.flags & 0x0080)
        if flag == "z": # reserved
            return (self.flags & 0x0070)
        if flag == "rcode": # response code
            return (self.flags & 0x000F)

    def _print_data(self):
        val = "----------------------------------------------\n"
        if self.resolve_flag("qr") == 0: # query
            for q in self.query_data:
                val = val + ("> %s: type: 0x%.4x, class: 0x%.4x\n") % (q["qname"], q["qtype"], q["qclass"])
                return val
        elif self.resolve_flag("qr") == 0x8000: # response
            for r in self.response_data:
                val = val + ("< %s: type: 0x%.4x, class: 0x%.4x\n  (ttl: %s, length: %s, addr: %s)\n") \
                % (r["name"], r["type"], r["class"], r["ttl"], r["rdlength"], r["rddata"])
            return val
        else:
            return ""