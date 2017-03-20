# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import argparse
import logging
import signal
from time import time, sleep

try:
    from lib.core.startup import init_logging, interrupt_handler, check_configs
    from lib.common.colors import color
    from lib.core.sniffer import Sniffer, TimerClass
    from lib.core.pcap_parser import PcapParser
    from lib.core.meta_analyzer import MetaAnalyzer
    from modules.rawsocket import RawSocket

except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
signal.signal(signal.SIGINT, interrupt_handler)
log = logging.getLogger()

sniff_interfaces = ["eth0"] # default interface

def extract_packets(file_path):
    """ Extract packets from pcap file using pcap parser. """
    # Init pcap parser
    pcap_parser = PcapParser()
    start = time()
    # Parse file
    packets = pcap_parser.read(file_path)
    end = time()
    log.debug("Time spent reading the pcap file file: %s seconds." % (round(end-start,2)))
    return packets

if __name__ == "__main__":
    
    # To Do: Implement argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-i","--interfaces", help="Filter traffic for a specific interface", type=str, required=False)
    parser.add_argument("-p","--protocols", help="Protocols to be sniffed", type=str, required=False)
    parser.add_argument("-f","--file", help="Read packets from specified pcap file. Interface sniffing will be disabled.", type=str, required=False)
    parser.add_argument("-b","--baseline", help="Read packets from specified pcap baseline file. Interface sniffing will be disabled.", type=str, required=False)
    parser.add_argument("-r","--restore", help="Use latest baseline saved by pyexfildetect.", action="store_true", required=False)
    parser.add_argument("--ignore", help="Ignore Qnames", type=str, required=False)
    parser.add_argument("--ip", help="Filter IPs in sniffer module. Comma separated list.", type=str, required=False)
    parser.add_argument("--tag", help="Add a custom tag to describe the session (for debugging purposes).", type=str, required=False)

    args = parser.parse_args()
    
    # Start console and file logging
    init_logging()

    # Check for existing config files
    check_configs()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.interfaces:
        sniff_interfaces = args.interfaces.split(",")
        log.debug("Interfaces: %s", repr(sniff_interfaces))

    baseline_packets = None
    file_packets = None

    """
        Baselining.
    """

    if args.baseline and args.restore:
        log.warning("Ignoring latest baseline as a new baseline file is specified.")
        args.restore = False

    # Prepare and create the baseline
    analysis_session = None
    if args.baseline:
        log.debug("Parsing baseline file.")
        baseline_packets = extract_packets(args.baseline)

        # Init sniffer
        baseline_sniff = Sniffer(sniff_sock=None, packet_data=baseline_packets, protocols=args.protocols, ip=args.ip)
        baseline_analyze = MetaAnalyzer(baseline=True, session_id=None, tag=args.tag)
        analysis_session = baseline_analyze.session_id
        if args.ignore:
            baseline_analyze.filter_qnames = args.ignore.split(",")
        baseline_analyze.start()
        log.info(color("Sniffing baseline packets.",36))

        # Wait for packets
        while True:
            try:
                # Receive packets according to filter rules
                my_packet = baseline_sniff.sniff()
                if my_packet:
                    # Analyze packets
                    baseline_analyze.add_packet(my_packet)
                    continue
                if len(baseline_sniff.packet_data) == 0:
                        log.info("Finished baseline sniffing.")
                        break

            except Exception as e:
                log.error("Generic error: %s", e)

        log.info("Waiting for baseline analysis.")

        # Block until baseline analysis is done
        while baseline_analyze.q.qsize() != 0:
            sleep(5)
            log.info("Waiting (%s packets left)." % baseline_analyze.q.qsize())
        log.info("Done.")
        baseline_analyze.active = False
        log.info("Analyzer stopped.")
        
        # Create stream summary
        stream_summary = baseline_analyze.summarize_streams()
        
        # Send stream summary as baseline to classification server
        baseline_analyze.commit_stream_summaries(stream_summary, file=True, network=True, baseline=True)

    if args.restore:
        log.debug("Trying to read latest baseline.")
        baseline_analyze = MetaAnalyzer(baseline=True, session_id=None, tag=args.tag)
        analysis_session = baseline_analyze.session_id
        stream_summary = baseline_analyze.read_json(baseline=True)

        # Send stream summary as baseline to classification server
        baseline_analyze.commit_stream_summaries(stream_summary, file=True, network=True, baseline=True)

    """
        Classification.
    """

    # Classification: Parser or sniffer mode?
    if args.file: # Parser mode
        log.debug("Parsing file.")
        file_packets = extract_packets(args.file)

        # Init sniffer
        log.debug("IPs: %s", args.ip)
        sniff = Sniffer(sniff_sock=None, packet_data=file_packets, protocols=args.protocols, ip=args.ip)
        log.debug("Packets parsed: %s." % sniff.data_len)

    else: # Sniffer mode
        # Init raw socket
        my_socket = RawSocket(sniff_interfaces)

        # Init sniffer
        sniff = Sniffer(sniff_sock=my_socket, packet_data=None, protocols=args.protocols, ip=args.ip)

    # Init analyzer
    analyze = MetaAnalyzer(baseline=False, session_id=analysis_session)
    if args.ignore:
        analyze.filter_qnames = args.ignore.split(",")
    analyze.start()

    # Wait for packets
    while True:
        try:
            # Receive packets according to filter rules
            my_packet = sniff.sniff()
            if my_packet:
                # Analyze packets
                analyze.add_packet(my_packet)
                continue
            if args.file:
                # Exit the program properly
                if len(sniff.packet_data) == 0:
                    #log.info("Waiting for analysis.")
                    # Wait for the analyzer to be finished
                    TimerClass.stoprequest.set()
                    while analyze.q.qsize() != 0:
                        sleep(5)
                        log.info("Waiting (%s packets left)." % analyze.q.qsize())

                    MetaAnalyzer.stoprequest.set() # Stop analyzer thread
                    exit(0)

        except Exception as e:
            log.error("Generic error: %s", e)
