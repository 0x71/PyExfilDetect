# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import Queue
import csv
import ConfigParser
from threading import Thread, Event, Lock
from datetime import datetime
from time import time
import json
from lib.common.constants import APP_ROOT

try:
    from lib.common.constants import APP_ROOT, VAR_THRESHOLD
    from lib.common.colors import color
    from lib.core.database import Database
    from lib.core.communicator import Communicator
    from modules.host import Host
    from lib.common.math_helper import calc_mean, calc_variance, calc_stdev, calc_stdev_var
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))

log = logging.getLogger(__name__)


class MetaAnalyzer(Thread):
    
    stoprequest = Event() # static variable needed to stop the thread 
    
    def __init__(self, baseline=False, session_id=None, tag=""):
        Thread.__init__(self)
        log.debug("MetaAnalyzer started.")
        self.packet_count = 0
        self.filter_count = 0
        self.byte_count = 0
        self.q = Queue.Queue() # Put packets to be analyzed in a queues
        self.hosts = []
        self.host_identifier = 0
        self.stream_identifier = 0
        self.mutex = Lock()
        self.session_time = time()
        self.session_id = session_id
        self.communicator = Communicator()
        self.filter_qnames = []
        self.baseline = baseline
        self.output_details = "low" # low, high
        self.destip_feature = "no"
        self.active = True
        self.tag = tag
        self.total_stream_summary = {}

        self.parse_config()

        # Check for existing session and baseline
        # If you are the baseline analyzer, create a new session
        if self.baseline == True and self.session_id == None:
            self.session_id = self.communicator.send_session_init(self.session_time, self.tag)
            if self.session_id:
                log.info("Session ID: %s" % self.session_id)

    def __del__(self):
        log.debug("MetaAnalyzer stopped.")
        if self.baseline == True:
            pass
        else:
            self.finish_analysis()

    def parse_config(self):
        cfg = ConfigParser.ConfigParser()

        try:
            cfg.read(os.path.join(APP_ROOT, "conf", "analyzer.conf"))

            details = cfg.get("output","details")
            if details:
                if details in ["low", "high"]:
                    self.output_details = details
                else:
                    log.warning("Wrong detail level specified in conf/analyzer.py. Using default ('low').")

            destip = cfg.get("features","destip")
            if destip:
                if destip in ["no", "yes"]:
                    self.destip_feature = destip
                else:
                    log.warning("Wrong value specified in for 'destip' in conf/analyzer.py. Using default ('no').")

        except:
            sys.exit("ERROR: Reading 'sniffer.conf'")

    def count_streams(self, streams):
        """ Count streams and stream information according to stream types. """
        count_streams = dict()
        for stream in streams:
            try:
                count_streams[stream.type][0] += 1
                count_streams[stream.type][1] += stream.packet_count
                count_streams[stream.type][2] += stream.byte_count
            except KeyError:
                count_streams[stream.type] = [1, stream.packet_count, stream.byte_count] # stream_count, packet_count, byte_count

        return count_streams

    def print_summary(self):
        """ Print a short summary of analyzed hosts and streams. """
        # iterate every host
        print ""
        log.info(color("=== Summary ===",36))
        log.info("Analyzed hosts:   %s" % len(self.hosts))
        log.info("Analyzed packets: %s" % self.packet_count)
        log.info("----------------------------------")
        for host in self.hosts:
            log.info(color(" [*] Host %s (%s):" % (host.host_identifier, host.ip_addr),32))

            for stream_type, stream_summary in self.count_streams(host.streams).iteritems():
                log.info("  => %s: %s streams (%s packets, %s bytes)" % (stream_type, stream_summary[0], stream_summary[1], stream_summary[2]))

    def print_details(self):
        """ Print detailed information about analyzed hosts and streams. """

        for host in self.hosts:
            # Database
            #host_id = self.database.addHost(host.ip_addr, host.host_identifier)

            # File
            log.info(color(" >>> Host[%s] --> %s:" % (host.host_identifier, host.ip_addr),32))
            log.info(color("  [HTTP(S)]",36))
            for stream in host.streams:
                if "tcp" in stream.type:
                    log.info("   < [%s]: Dest: %s:%s, Packets: %s, Bytes: %s [Timestamp: %s, Out: %s [%s bytes], In: %s [%s bytes]] >" % (stream.identifier, stream.dest_addr, stream.dest_port, stream.packet_count, stream.byte_count, stream.first_timestamp, stream.request_count, stream.request_byte_count, stream.response_count, stream.response_byte_count))

            log.info(color("  [DNS]",36))
            for stream in host.streams:
                if "dns" in stream.type:
                    log.info("   < [%s]: Qname: %s, Packets: %s, Bytes: %s, Subdomain: %s [Timestamp: %s, Querys: %s [%s bytes], Responses: %s [%s bytes] >" % (stream.identifier, stream.dns_qname, stream.packet_count, stream.byte_count, len(stream.unique_subdomains), stream.first_timestamp, stream.request_count, stream.request_byte_count, stream.response_count, stream.response_byte_count))

            log.info(color("  [ICMP]",36))
            for stream in host.streams:
                if "icmp" in stream.type:
                    log.info("   < [%s]: ID: %s, Packets: %s, Bytes: %s [Timestamp: %s, Querys: %s [%s bytes], Responses: %s [%s bytes] >" % (stream.identifier, hex(stream.sess_id), stream.packet_count, stream.byte_count, stream.first_timestamp, stream.request_count, stream.request_byte_count, stream.response_count, stream.response_byte_count))

    def write_csv(self, stream_data):
        """ Write stream summary to .csv file in data/ directory. """
        # Create file name using the session time
        dt = datetime.fromtimestamp(self.session_time).strftime('%Y-%m-%d_%H-%M-%S')
        summary_name = "stream_summary-" + dt + ".csv"
        summary_path = os.path.join(APP_ROOT,"data", summary_name)
        log.debug("Writing to %s" % summary_path)

        with open(summary_path, 'ab') as total:
            wr_total = csv.writer(total, quoting=csv.QUOTE_NONE)
            for stream in stream_data:
                wr_total.writerow(stream)

        # Change file owner according to sudo user
        uid = os.environ.get('SUDO_UID')
        gid = os.environ.get('SUDO_GID')
        if uid is not None:
            os.chown(summary_path, int(uid), int(gid))

        # Create simlink to latest sample
        link = os.path.join(APP_ROOT,'data', 'latest')
        try:
            os.remove(link)
        except OSError:
            pass

        os.symlink(summary_path, link)
        os.lchown(link, int(uid), int(gid))

    def write_json(self, stream_data, baseline=False):
        """ Write stream summary to .json file in data/ directory. """
        # Create file name using the session time
        dt = datetime.fromtimestamp(self.session_time).strftime('%Y-%m-%d_%H-%M-%S')
        if baseline == False:
            summary_name = "stream_summary-" + dt + ".json"
            summary_path = os.path.join(APP_ROOT,"data", "streams", summary_name)
        else:
            summary_name = "bl_summary-" + dt + ".json"
            summary_path = os.path.join(APP_ROOT,"data", "baseline", summary_name)
        log.debug("Writing to %s" % summary_path)

        with open(summary_path, 'ab') as total:
            #wr_total = csv.writer(total, quoting=csv.QUOTE_NONE)
            #for stream in stream_data:
                #total.wr
            total.write(json.dumps(stream_data))

        # Change file owner according to sudo user
        uid = os.environ.get('SUDO_UID')
        gid = os.environ.get('SUDO_GID')
        if uid is not None:
            os.chown(summary_path, int(uid), int(gid))

        # Create simlink to latest sample
        if baseline == False:
            link = os.path.join(APP_ROOT,"data", "streams", "latest")
        else:
            link = os.path.join(APP_ROOT,"data", "baseline", "latest")
        try:
            os.remove(link)
        except OSError:
            pass

        os.symlink(summary_path, link)
        os.lchown(link, int(uid), int(gid))

    def read_json(self, baseline=False):
        """ Write stream summary to .json file in data/ directory. """
        # Create file name using the session time
        summary_path = os.path.join(APP_ROOT,"data", "baseline", "latest")
        log.debug("Reading from %s" % summary_path)

        with open(summary_path) as total:
            data = json.load(total)

            return data

    def summarize_streams(self, finish=False):
        """ Summarize streams and return summary. """
        if finish == True:
            log.info("Summarizing streams.")
        # Collect stream data and send it using the communicator

        stream_summary = {}
        # Iterate hosts
        for host in self.hosts:
            if finish == True:
                log.info("Summarizing host %s." % host.ip_addr)

            # Iterate streams
            for stream in host.streams: # use a list copy
                # Send a) disabled streams during the cleanup routine or b) every all streams during finish routine
                if (stream.active == False or finish == True) and len(stream) > 0:
                    stream_meta, stream_data = self.extract_stream_info(stream, stream.type)
                    if stream_meta:
                        stream_meta["h_ip"] = host.ip_addr
                        stream_meta["h_id"] = host.host_identifier
                        stream_meta["dest_ip"] = stream.dest_addr
                        if stream.type == "dns":
                            stream_meta["qname"] = stream.dns_qname
                            stream_data["subs"] = len(stream.unique_subdomains)
                            if self.destip_feature == "yes":
                                stream_data["destip"] = stream.dest_addr
                        if stream.type == "icmp":
                            stream_data.pop("msub_len")
                            stream_data["uniquedata"] = len(stream.unique_datafield)

                    stream_dict = {"meta": stream_meta, "data": stream_data}
                    stream_summary[stream.identifier] = stream_dict

                    # Add stream to master summary
                    # delete stream
                    log.debug("[Stream %s] Summarized. Removing stream packets." % stream.identifier)
                    del stream.packets[:]
                    stream.packets = []
                    del stream.ts_all
                    del stream.ts_out
                    del stream.ts_in

        return stream_summary

    def commit_stream_summaries(self, streams, file=False, network=False, baseline=False):
        """ Write stream summaries to file/database/network. """
        if file:
            # Create data folder       
            folder_path = os.path.join(APP_ROOT,"data", "streams")
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
                
            baseline_path = os.path.join(APP_ROOT, "data", "baseline")
            if not os.path.exists(baseline_path):
                os.makedirs(baseline_path)
            
            if baseline == True:
                self.write_json(streams, baseline=True)
            else:
                self.write_json(streams, baseline=False)
        if network == True:
            if baseline == True:
                self.communicator.send_baseline(json.dumps(streams), self.session_id)
            else:
                self.communicator.send_streams(json.dumps(streams), self.session_id)

    def finish_analysis(self):
        log.info("Total number of analyzed packets: %s (%s bytes)." % (self.packet_count, self.byte_count))
        log.info("Total number of ignored packets: %s." % (self.filter_count))

        if self.output_details == "high":
            self.print_details()
        elif self.output_details == "low":
            self.print_summary()
        stream_summary = self.summarize_streams(finish=True)

        self.commit_stream_summaries(stream_summary, file=True, network=True, baseline=False)

        if self.session_id:
            self.communicator.send_session_end(time(), self.session_id)

    def cleanup_disabled_streams(self):
        # For now, the baseline streams have to be sent all together
        if self.baseline == False:
            #log.info("Cleanup routine")
            stream_summary = self.summarize_streams(finish=False)

            if len(stream_summary) > 0:
                self.commit_stream_summaries(stream_summary, file=True, network=True, baseline=False)

    def add_packet(self, packet):
        try:
            # Filter packets
            if packet.has_layer("dns"):
                if (packet["dns"].secondlevel_qname in self.filter_qnames):
                    #log.debug("PACKET FILTERED FOR %s." % packet["dns"].secondlevel_qname)
                    self.filter_count = self.filter_count + 1
                    return
            # Add packet to queue
            self.q.put(packet)
            #log.debug("Adding packet to queue.")
            self.packet_count = self.packet_count + 1
            self.byte_count = self.byte_count + packet["eth"].size
            # log.debug("Packet added.")
            # log.debug(packet)
        except Exception as e:
            log.error("Analyzer error on packet %s: %s" % (packet.internal_id, e))

    def host_exists(self, ip):
        for host in self.hosts:
            if host.ip_addr == ip:
                return host
        return None

    def run(self):
        log.debug("Waiting for incoming packets..")
        
        # run as long as we do not send an interrupt
        while not MetaAnalyzer.stoprequest.is_set() and self.active == True:
            try:
                # Wait for a new packet
                my_packet = self.q.get(block=True, timeout=0.5)
                # log.debug("== New packet received ==")
                if my_packet:
                    if my_packet.has_layer("tcp"):
                        host = None
                        outgoing = False
                        #log.debug("TCP Packet.")
                        if my_packet["tcp"].dest_port == 80 or my_packet["tcp"].dest_port == 443: # HTTP(S) traffic only
                            log.debug("OUT")
                            outgoing = True
                            host = self.host_exists(my_packet["ip"].src_addr)
                        elif my_packet["tcp"].src_port == 80 or my_packet["tcp"].src_port == 443:
                            log.debug("IN")
                            outgoing = False
                            host = self.host_exists(my_packet["ip"].dest_addr)

                        if host is not None:
                            # Host found
                            log.debug("[Host %s] found (%s)" % (host.host_identifier, host.ip_addr))

                            # Do we have an identical stream?
                            stream = host.check_stream(my_packet)
                            if stream is not None:
                                stream.add_packet(my_packet)
                                log.debug("[Stream %s]: Packet added.\n", stream.identifier)
                            else:
                                if outgoing:
                                    # Add stream
                                    log.debug("Adding new stream.")
                                    self._add_stream_to_host(host.host_identifier, my_packet, "tcp")

                        else:
                            # Create new host
                            #if my_packet["tcp"].is_syn_packet():
                            if outgoing: # if new host and outgoing packet (ignore responses when requests not seen)
                                # Create new host and set src_addr
                                host = self._create_host(my_packet)

                                # Add first stream
                                self._add_stream_to_host(host.host_identifier, my_packet, "tcp")

                    elif my_packet.has_layer("dns"):
                        #log.debug("DNS Packet.")
                        # Unterscheidung zwischen DNS UND ICMP?

                        ## DNS ##
                        # New Query?
                        if my_packet["udp"].dest_port == 53:
                            outgoing = True
                            self.help_dns_debug(my_packet, "query")
                            # Do we know the host already?
                            host = self.host_exists(my_packet["ip"].src_addr)
                        # New Response?
                        elif my_packet["udp"].src_port == 53:
                            outgoing = False
                            self.help_dns_debug(my_packet, "response")
                            # Do we know the host already?
                            host = self.host_exists(my_packet["ip"].dest_addr)

                        if my_packet["udp"].dest_port == 53 or my_packet["udp"].src_port == 53:
                            if host is not None:
                                # Host found
                                log.debug("[Host %s] found (%s)" % (host.host_identifier, host.ip_addr))
                                # Do we have an identical stream?
                                stream = host.check_stream(my_packet)
                                if stream is not None:
                                    # Found identical stream
                                    # log.debug("Stream found.")
                                    # Adding packet
                                    stream.add_packet(my_packet)
                                    log.debug("[Stream %s]: Packet added.\n", stream.identifier)
                                # No stream yet. Let's create one
                                else:
                                    if outgoing: # if new stream and outgoing packet (ignore responses when requests not seen)
                                        # Add stream
                                        log.debug("Stream not found. Creating new stream.")
                                        self._add_stream_to_host(host.host_identifier, my_packet, "dns")
                            else:
                                if outgoing: # if new host and outgoing packet (ignore responses when requests not seen)
                                    # Create new host and set src_addr
                                    host = self._create_host(my_packet)

                                    # Add first stream
                                    self._add_stream_to_host(host.host_identifier, my_packet, "dns")
                        ## /DNS ##

                    ## ICMP ##
                    elif my_packet.has_layer("icmp"):
                        log.debug("ICMP packet. ID: %s" % hex(my_packet["icmp"].sess_id))

                        # Echo Request
                        if my_packet["icmp"].is_echo_request():
                            outgoing = True
                            host = self.host_exists(my_packet["ip"].src_addr)
                        # Echo Response
                        elif my_packet["icmp"].is_echo_reply():
                            outgoing = False
                            host = self.host_exists(my_packet["ip"].dest_addr)

                        if my_packet["icmp"].is_echo_request() or my_packet["icmp"].is_echo_reply():
                            if host is not None:
                                # Host found
                                log.debug("[Host %s] found (%s)" % (host.host_identifier, host.ip_addr))
                                # Do we have an identical stream?
                                stream = host.check_stream(my_packet)
                                if stream is not None:
                                    # Found identical stream
                                    # log.debug("Stream found.")
                                    # Adding packet
                                    stream.add_packet(my_packet)
                                    log.debug("[Stream %s] Packet added.\n", stream.identifier)
                                # No stream yet. Let's create one
                                else:
                                    if outgoing: # if new host and outgoing packet (ignore responses when requests not seen)
                                        # Add stream
                                        log.debug("Stream not found. Creating new stream.")
                                        self._add_stream_to_host(host.host_identifier, my_packet, "icmp")

                            else:
                                if outgoing: # if new host and outgoing packet (ignore responses when requests not seen)
                                    # Create new host and set src_addr
                                    host = self._create_host(my_packet)

                                    # Add first stream
                                    self._add_stream_to_host(host.host_identifier, my_packet, "icmp")

                # Cleanup routine
                # Classify streams that are already closed
                self.cleanup_disabled_streams()

            except Queue.Empty:
                continue

    def get_packet_sizes(self, stream):
        numbers = []
        for packet in stream:
            numbers.append(packet["eth"].size)
        return numbers

    def extract_stream_info(self, stream, type):
        duration = round(stream.last_timestamp - stream.first_timestamp, 4)

        #if duration < 0.25:
        #    log.debug("Skipped stream %s as duration is too small." % stream.identifier)
        #    return None
        mean_size_all = self.help_div(stream.byte_count, stream.packet_count)
        var_size_all = calc_variance(self.get_packet_sizes(stream), VAR_THRESHOLD, mean_size_all)
        stdev_size_all = calc_stdev_var(var_size_all)

        mean_pit_all, var_pit_all, stdev_pit_all = self.calc_pit_statistics(stream.ts_all)
        mean_pit_out, var_pit_out, stdev_pit_out = self.calc_pit_statistics(stream.ts_out)
        mean_pit_in, var_pit_in, stdev_pit_in = self.calc_pit_statistics(stream.ts_in)

        if type == "dns":
            mean_subdomain_len = int(calc_mean(stream.subdomain_length))
        else:
            mean_subdomain_len = 0
        if duration == 0:
            duration = 0.001
        packets_per_second = round(stream.packet_count / float(duration),4)
        #log.debug("DURATION: %s" % duration)
        #log.debug("packets_per_second: %s" % packets_per_second)

        try:
            outgoing_incoming_ratio = round(stream.response_byte_count / float(stream.request_byte_count),4)
        except ZeroDivisionError:
            outgoing_incoming_ratio = 0.01
        #log.debug("outgoing_incoming_ratio: %s" % outgoing_incoming_ratio)

        meta = {"_id": stream.identifier, # Strean Session ID
                "type": type, # Stream type
                "start": stream.first_timestamp, # First timestamp
                "end": stream.last_timestamp
                }

        data = {#"duration": duration, # Stream duration
                #packets_per_second, # packet duration ratio
                "pcount": stream.packet_count, # All packets
                #stream.request_count, # Outgoing packets
                #stream.response_count, # Incoming packets
                "bcount": stream.byte_count, # All bytes
                #stream.request_byte_count, # All outgoing bytes
                #stream.response_byte_count, # All incoming bytes
                #"bratio": outgoing_incoming_ratio,
                #"msize_all": mean_size_all, # Mean: All packet sizes
                "msize_out": self.help_div(stream.request_byte_count, stream.request_count), # Mean: Outgoing packet sizes
                #"msize_in": self.help_div(stream.response_byte_count, stream.response_count), # Mean: Incoming packet sizes
                #var_size_all, # Variance all packets sizes
                #stdev_size_all, # Stdev all packet sizes
                #"mpit_all": mean_pit_all, # Mean: PITS all
                "mpit_out": mean_pit_out, # Mean: PITS out
                #"mpit_in": mean_pit_in, # Mean: PITS in
                #var_ts_all, # Variance all pits
                #var_ts_out, # Variance out pits
                #var_ts_in, # Variance in pits
                #stdev_ts_all, # Stdev all pits
                #stdev_ts_out, # Stdev out pits
                #stdev_ts_in # Stdev in pits
                "msub_len": mean_subdomain_len
                }

        return meta, data

    def _create_host(self, my_packet):
        log.debug("No host found.")
        self.hosts.append(Host())
        self.hosts[-1].set_addr(my_packet["ip"].src_addr)
        self.hosts[-1].host_identifier = self.host_identifier
        self.host_identifier = self.host_identifier + 1
        log.debug("[Host %s] created (%s)." % (self.hosts[-1].host_identifier, self.hosts[-1].ip_addr))
        
        return self.hosts[-1]

        # Database
        #self.database.addHost(my_packet["ip"].src_addr)

    def _add_stream_to_host(self, host_identifier, my_packet, type):
        self.mutex.acquire()
        self.hosts[host_identifier].create_stream(type, my_packet, self.stream_identifier)
        self.mutex.release()
        self.stream_identifier = self.stream_identifier + 1

    """
        Helper functions.
    """

    def help_dns_debug(self, my_packet, type):
        log.debug("== New DNS packet (%s) ==", type)
        log.debug(" > SIZE: %s ", my_packet["eth"].size)
        log.debug(" > TIMESTAMP: %s ", my_packet.timestamp)
        log.debug(" > QNAME: %s", my_packet["dns"].secondlevel_qname)
        log.debug(" > SRC_IP: %s", my_packet["ip"].src_addr)
        log.debug(" > DST_IP: %s", my_packet["ip"].dest_addr)
        log.debug(" > Full Qname: %s", my_packet["dns"].query_data[0]['qname'])

    def help_div(self, x,y):
        ''' Handle division by zero '''
        if x == 0 or y == 0:
            return 0
        else:
            return float(x/y)

    def calc_pits(self, numbers):
        pits = []
        for x in range(1, len(numbers)):
            pits.append(numbers[x]-numbers[x-1])
        return pits

    def calc_pit_statistics(self, timestamps):
        # Sort timestamps
        ts = sorted(timestamps)

        # Calculate pits
        pits = self.calc_pits(ts)

        # Calculate mean, var, stdev
        mean_pits = calc_mean(pits)
        var_pits = calc_variance(pits, VAR_THRESHOLD, mean_pits)
        stdev_pits = calc_stdev_var(var_pits)

        return mean_pits, var_pits, stdev_pits