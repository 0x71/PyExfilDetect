# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import Queue
from threading import Thread, Event
from datetime import datetime
from time import time
import hashlib
import syslog

try:
    from lib.common.colors import color
    from lib.common.constants import APP_ROOT, STREAM_TIMING_THRESHOLD, STREAM_PACKET_THRESHOLD
    from modules.tcpstream import TCPStream
    from lib.core.hasher import Hasher
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
try:
    import statistics
except ImportError as e:
    sys.exit("ERROR: Missing library 'statistics': {0}".format(e))

log = logging.getLogger()

class Analyzer(Thread):
    
    stoprequest = Event() # static variable needed to stop the thread on ctrl+c
    
    def __init__(self, plot=False, comment=None, extract=False):
        Thread.__init__(self) # init thread class
        log.debug("Analyzer started.")
        self.q = Queue.Queue() # Queue to hold all crude packets
        self.tcp_streams = []
        self.old_fstreams = []
        self.plot = plot
        self.comment = comment
        self.extract = extract
        self.identifier = 0
        self.hasher = Hasher()
        self.hasher.start()
        
    def __del__(self):
        log.debug("Analyzer destroyed.")
        
    def add_packet(self, packet):
        # Add packet to queue
        #log.debug("Adding packet to queue.")
        self.q.put(packet)

    def create_stream(self, my_packet):
        ''' Create and prepare a new stream based on the syn packet data. '''
        # Create a new TCPStream
        self.tcp_streams.append(TCPStream())
        self.tcp_streams[-1].add_packet(my_packet)

        # Save starting time
        self.tcp_streams[-1].first_timestamp = my_packet.timestamp

        # Unique stream identifier for this session
        self.tcp_streams[-1].identifier = self.identifier
        self.identifier = self.identifier + 1

    def append_to_stream(self, my_packet):
        self.old_streams = [] # mark closed streams for deletion
        for stream in self.tcp_streams:
            if stream.is_equal(my_packet["ip"].src_addr, my_packet["ip"].dest_addr,
                               my_packet["tcp"].src_port, my_packet["tcp"].dest_port):
    
                # First, add packet to stream
                stream.add_packet(my_packet)

                # We are just interested in file downloads
                if "GET" in my_packet["tcp"].data[0:4]:
                    # Search for file endings (improvement needed!)
                    if '.exe ' in my_packet["tcp"].data or '.zip ' in my_packet["tcp"].data or '.tar.gz' in my_packet["tcp"].data:
                        # To Do: Identify end of download (http ok 200 packet)
                        log.debug("Found GET and file download.")

                        # Extract domain name
                        domain = '<empty>'
                        request = my_packet["tcp"].data.split('\r\n')
                        for r in request:
                            if 'Host' in r:
                                domain = r.split(' ')[1]
                        if domain == '<empty>':
                            # we were not able to extract the domain name
                            # try to use the host ip instead
                            stream.file_url = "http://" + my_packet["ip"].dest_addr \
                                            + ":" + str(my_packet["tcp"].dest_port) \
                                            + my_packet["tcp"].data.split(' ')[1]
                        else:
                            # we extracted the domain name
                            stream.file_url = "http://" + domain + my_packet["tcp"].data.split(' ')[1]

                        log.debug("URL: %s", stream.file_url)
                        stream.file_name = my_packet["tcp"].data.split(' ')[1].split('/')[-1]
                        log.debug("File: %s", stream.file_name)
                        stream.contains_download = True
                        #print my_packet["tcp"]
                        #print my_packet["tcp"].data

                elif "Content-Length" in my_packet["tcp"].data or "content-length" in my_packet["tcp"].data:
                    if stream.contains_download == True:
                        log.debug("Stream contains download.")
                        http_data = my_packet["tcp"].data.split()
                        if "Content-Length:" in http_data:
                            stream.file_size = http_data[http_data.index("Content-Length:")+1]
                        elif "content-length:" in http_data:
                            stream.file_size = http_data[http_data.index("content-length:")+1]
                        # Calculate file size
                        #stream.file_size = stream.file_size + my_packet["tcp"].get_data_size(my_packet["ip"].total_length)
                        #log.debug("TCP DATA SIZE: %d", stream.file_size)

                # Connection closing
                elif my_packet["tcp"].is_closing_packet():
                    stream.conn_close = stream.conn_close + 1
                    if stream.conn_close == 1:
                        log.debug("TCP stream %d: Closing detected  (first FIN,ACK).", stream.identifier)
                    elif stream.conn_close > 1:
                        log.debug("TCP stream %d: Closing detected  (second FIN,ACK).", stream.identifier)
                    #log.debug("Added packet to TCP stream %d.", stream.identifier)

                # Find final 'ack'
                elif my_packet["tcp"].is_final_closing_packet():
                    if stream.conn_close > 1: # (fin, ack) was seen twice
                        log.debug(color(color("TCP stream %d: Last packet detected (ACK).", 36), 2), stream.identifier)

                        if stream.contains_download == True:

                                # Plot
                                log.info(color("Identified file download in TCP stream %d.", 31), stream.identifier)
                                try:
                                    if self.plot:
                                        self.plot_packets_over_time(stream)
                                        self.plot_packets_over_time_interval(stream,1)

                                    # Remove SYN/ACK/FIN+ACK and unimportant http packets
                                    self.prepare_stream(stream)

                                    # Latest analysis approach
                                    self.statistical_analysis3(stream,0.05,3.5)

                                except IOError:
                                    log.warning("I was not able to create the plot file.")

                                # Calculate hash sum if proxy detected
                                # (-> We can't differ between 'good' or 'bad' proxy servers)
                                if stream.proxy_detected == True:
                                    sha256_hash = self.stream_hash(stream)
                                    log.info("Local hash:")
                                    log.info("  |--- %s", sha256_hash)

                                    if self.hasher.active == True:
                                        self.hasher.add_file_check(stream.file_url, sha256_hash)

                                    if self.extract:
                                        self.extract_files(stream)
				else:
				    log.info("No anomaly detected.")

                        # drop closed stream data to save memory
                        self.old_streams.append(stream)

            # Check whether or not the stream is active
            self.check_stream(stream)

        # Delete all finished streams not containing any download
        self.cleanup_streams()

    def prepare_stream(self,stream):
        ''' Remove unimportant packets; keep data packets. '''
        log.debug("Preparing stream.")
        log.debug("Total packet number: %d", len(stream))

        marked_ack_packets = []
        marked_http_packets = []

        log.debug("Cleanup..")
        for elem in stream:
            if len(elem["tcp"].data) == 0: # SYN/ACK/FIN Packets
                marked_ack_packets.append(elem)
            elif "GET " in elem["tcp"].data[:4] or "302 Found" in elem["tcp"].data[:200]: # HTTP GET/REDIRECT Packets
                marked_http_packets.append(elem)

        for elem in marked_ack_packets:
            stream.remove_packet(elem)

        for elem in marked_http_packets[:len(marked_http_packets)-1]:
            log.debug("Removing.")
            stream.remove_packet(elem)

        # Set stream start to http-get time (get request)
        stream.first_timestamp = stream[0].timestamp

        # Remove get reqeuest (first packet)
        # stream.remove_packet(stream[0])

        log.debug("HTTP Packets: %d", len(marked_http_packets))

        log.debug("Total packet number: %d", len(stream))

    def check_stream(self,stream):
        ''' Check whether or not the stream is still active. '''
        # Garbage collection: Delete half closed streams being still open after some time
        if stream.conn_close > 0:
            current_time = time()
            if current_time - stream[-1].timestamp > 600:
                log.debug("No changes - deleting stream %d.", stream.identifier)
                self.old_streams.append(stream)

    def cleanup_streams(self):
        ''' Delete old non-active streams. '''
        for stream in self.old_streams:

            # Remove temporary files
            # self.cleanup_files(stream)

            # Remove stream
            self.tcp_streams.remove(stream)
            log.debug("Stream %d removed.", stream.identifier)
            log.debug("Number of remaining streams: %d.", len(self.tcp_streams))

    def extract_files(self,stream):
        ''' Extract files, save them temporary to disk, calculate hash sum. '''
        # Order stream according to tcp sequence number
        stream.sort_packets()

        file_name = datetime.fromtimestamp(stream.first_timestamp).strftime('%Y-%m-%d_%H-%M-%S')+'-'+stream.file_name
        # Extract file and write it to disk
        with open(os.path.join(APP_ROOT,"dl",file_name),'wb') as file:
            start = False
            count = 0

            for my_packet in stream:
                if start == True:
                    if len(my_packet["tcp"].data) > 0:
                        if not "\r\n\r\n" in my_packet["tcp"].data:
                            if len(my_packet["tcp"].data) == 120:
                                log.debug("START: %s", str(start))
                                log.debug("120")
                                log.debug(repr(my_packet["tcp"].data))
                            file.write(my_packet["tcp"].data)
                            count = count + 1

                elif "Content-Length" in my_packet["tcp"].data or "content-length" in my_packet["tcp"].data:
                    log.debug("Found content length during extraction.")
                    if "\r\n\r\n" in my_packet["tcp"].data:
                        log.debug("Found header ending.")
                        count = count + 1

                        data_begin = my_packet["tcp"].data.split("\r\n\r\n")[1]
                        file.write(data_begin)
                        start = True

        # Calculate hash
        hash = self.file_hash(os.path.join(APP_ROOT,"dl", file_name), hashlib.sha256(),blocksize=65536)
        log.debug("SHA256 (extracted file): %s", hash)

    def cleanup_files(self, stream):
        ''' Delete temporary files. '''
        if stream.contains_download == True:
            if os.path.isfile(os.path.join(APP_ROOT,"dl",stream.file_name)):
                os.remove(os.path.join(APP_ROOT,"dl",stream.file_name))
                log.debug("File %s removed.", os.path.join(APP_ROOT,"dl",stream.file_name))

    def stream_hash(self, stream):
        ''' Calculate file hash using the packet stream. '''
        # Order stream according to tcp sequence number
        stream.sort_packets()

        hash_handler = hashlib.sha256()

        start = False
        for my_packet in stream:
                if start == True:
                    if len(my_packet["tcp"].data) > 0:
                        if not "\r\n\r\n" in my_packet["tcp"].data:
                            hash_handler.update(my_packet["tcp"].data)

                elif "Content-Length" in my_packet["tcp"].data or "content-length" in my_packet["tcp"].data:
                    if "\r\n\r\n" in my_packet["tcp"].data:

                        data_begin = my_packet["tcp"].data.split("\r\n\r\n")[1]
                        hash_handler.update(data_begin)
                        start = True

        return hash_handler.hexdigest()

    def file_hash(self,afile, hasher, blocksize=65536):
        ''' Calculate hash sum of 'afile' using algorithm 'hasher'. '''
        file_handler = open(afile, 'rb')
        buf = file_handler.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = file_handler.read(blocksize)
        return hasher.hexdigest()


    def run(self):
        # run as long as we did not send an interrupt
        while not Analyzer.stoprequest.is_set():
            try:
                # wait for a new packet
                #log.debug("Waiting for a new packet to analyze.")
                my_packet = self.q.get(block=True, timeout=0.5)
                
                if my_packet:
                    #log.debug("Took new packet from queue.")
                    if my_packet.has_layer("tcp"):
                        # First Packet (SYN)
                        if my_packet["tcp"].is_syn_packet():
                            log.debug(color("New TCP Stream (%d) detected (SYN).",36), self.identifier)

                            # Create and init a new stream
                            self.create_stream(my_packet)

                        else:
                            # Append new packets to existing streams
                            self.append_to_stream(my_packet)

                        # print my_packet
                    
            except Queue.Empty:
                continue

    def plot_packets_over_time(self,stream):
        ''' Plot packet count * time. '''
        t = datetime.fromtimestamp(stream.first_timestamp).strftime('%Y-%m-%d_%H-%M-%S')
        with open(os.path.join(APP_ROOT,"log",'tcpstream-' + str(stream.identifier) + '-' + t + '.dat'), 'w+') as file:
            file.write("# TCP stream data\n")
            file.write("# Time\tSize\tCount\n")

            count = 0 # local packet counter
            for elem in stream:
                count = count + 1
                tcp_data_len = elem["tcp"].get_data_size(elem["ip"].total_length)
                # Ignore ACK packets for now
                if elem["tcp"].flag_ack == 1 and tcp_data_len == 0:
                    continue
                # log.debug("Time: %s, Size: %d", elem.timestamp-stream.first_timestamp, tcp_data_len)
                file.write(str(elem.timestamp-stream.first_timestamp) + "\t"
                           + str(tcp_data_len) + "\t"
                           + str(count) + "\n")

            file.write(str(elem.timestamp-stream.first_timestamp) + "\t"
                           + str(tcp_data_len) + "\t"
                           + str(count) + "\n")

        log.info(color("File 'tcpstream-" + str(stream.identifier) + '-' + t + ".dat' created.", 34))

    def plot_packets_over_time_interval(self, stream, interval):
        ''' Plot packet count * time (in time interval). '''
        t = datetime.fromtimestamp(stream.first_timestamp).strftime('%Y-%m-%d_%H-%M-%S')
        with open(os.path.join(APP_ROOT,"log","tcpstream-" + str(stream.identifier) + "-" + "int" + str(interval) + "-" + t + ".dat"), 'w+') as file:
            file.write("# TCP stream data\n")
            file.write("# Time\tCount\n")

            start_time = stream.first_timestamp
            time_delta = 0
            count = 0

            file.write(str(time_delta) + "\t" + str(count) + "\n")
            for elem in stream:
                if elem.timestamp - (start_time + time_delta) < interval:
                    count = count + 1
                else:
                    time_delta = time_delta + interval
                    file.write(str(time_delta) + "\t" + str(count) + "\n")
                    count = 1

            file.write(str(time_delta + 1) + "\t" + str(count) + "\n")
            file.write("# Total: " + str(len(stream)) + "\n")

        log.info(color("File 'tcpstream-" + str(stream.identifier) + "-"+ "int" + str(interval) + "-" + t + ".dat' created.", 34))

    def statistical_analysis(self, stream, first_span=STREAM_TIMING_THRESHOLD):
        ''' Try to identify transparent proxies using statistical analysis. '''

        start_time = stream.first_timestamp
        end_time = stream[-1].timestamp # take time stamp from the last packet in stream

        log.debug("Alg 1a) =========================")
        log.debug("Threshold: (%s%%/%s%%)", (first_span*100), (100.0-first_span*100))
        log.debug("Start time: %s", str(start_time))
        log.debug("End time: %s", str(end_time))

        # Download time
        download_time = end_time - start_time
        log.debug("Download time: %s.", str(download_time))
        log.debug("File size: %s", str(stream.file_size))

        # 90 percent of download time:
        first_time_span = float(download_time) * first_span
        second_time_span = float(download_time) * (1.0 - STREAM_TIMING_THRESHOLD)
        log.debug("First part: %.2f", first_time_span)
        log.debug("Second part: %.2f", second_time_span)

        packet_number_first = 0
        packet_number_second = 0

        # Count packets according to threshold
        # Skip first packet (get request)
        for elem in stream[1:]:
            packet_time = elem.timestamp - start_time
            if packet_time < first_time_span:
                packet_number_first = packet_number_first + 1
            else:
                packet_number_second = packet_number_second + 1

        log.debug("Total packet count: %d", len(stream))
        percentage_first_part = float(packet_number_first) / float(len(stream)) * 100.0
        percentage_second_part = float(packet_number_second) / float(len(stream)) * 100.0
        log.debug("Packet count - first part: %d (%.2f%%)", packet_number_first, percentage_first_part)
        log.debug("Packet count - second part: %d (%.2f%%)", packet_number_second, percentage_second_part)

        # Filename
        log_file = os.path.join(APP_ROOT,"log","statistical-analysis" + ".dat")
        # Date
        t = datetime.fromtimestamp(stream.first_timestamp).strftime('%Y-%m-%d_%H-%M-%S')
        # Check for an existing file
        if not os.path.isfile(log_file):
            with open(log_file, 'w+') as f:
                tmp = "# Statistical analysis - %s\n" % t
                f.write(tmp)
                #f.write("# Date\tFile\tSize\tDownload time\tT1\tT2\tPackets\t#P/LT1\t#P/RT1\t%P/LT1\t%P/RT1\n")
                f.write('{:20s}\t'.format("# Date")
                      +'{:15s}\t'.format("File")
                      +'{:>10s}\t'.format("Size (MB)")
                      +'{:>6s}\t'.format("DLtime")
                      +'{:>5s}\t'.format("T1")
                      +'{:>5s}\t'.format("T2")
                      +'{:>8s}\t'.format("#Packets")
                      +'{:>8s}\t'.format("#P/LT1")
                      +'{:>8s}\t'.format("#P/RT1")
                      +'{:>6s}\t'.format("%P/LT1")
                      +'{:>6s}\t'.format("%P/RT1")
                      +'{:>3s}\n'.format("Detected")
                      )
        detected = "No"

        #if percentage_first_part < (STREAM_PACKET_THRESHOLD * 100.0):
        if percentage_first_part < percentage_second_part: # First part: 90% of time --> There have to be more packages
            log.critical(color("Network anomaly detected! Download '%s' might be infected.",1), stream.file_name)
            syslog.syslog(syslog.LOG_CRIT, "Network anomaly detected! Download {0} might be infected.".format(stream.file_name))
            stream.proxy_detected = True
            detected = "Yes"

        with open(os.path.join(APP_ROOT,"log","statistical-analysis" + ".dat"), 'a') as file:
            if self.comment:
                file.write("\n### {0} ### \n".format(self.comment))
                self.comment = None
            file.write('{:20s}\t'.format(t)
                      +'{:15s}\t'.format(stream.file_name)
                      +'{:10.3f}\t'.format(int(stream.file_size)/1024.0/1024.0)
                      +'{:6.2f}\t'.format(download_time)
                      +'{:5.2f}\t'.format(STREAM_TIMING_THRESHOLD * 100.0)
                      +'{:5.2f}\t'.format(STREAM_PACKET_THRESHOLD * 100.0)
                      +'{:8d}\t'.format(len(stream))
                      +'{:8d}\t'.format(packet_number_first)
                      +'{:8d}\t'.format(packet_number_second)
                      +'{:6.2f}\t'.format(percentage_first_part)
                      +'{:6.2f}\t'.format(percentage_second_part)
                      +'{:3s}\n'.format(detected)
                      )
        log.debug("============================")

    def statistical_analysis2(self, stream, first_span=STREAM_TIMING_THRESHOLD):
        ''' Try to identify transparent proxies using statistical analysis. '''

        start_time = stream.first_timestamp
        end_time = stream[-1].timestamp # take time stamp from the last packet in stream

        log.debug("2) =========================")
        log.debug("Threshold: (%s%%/%s%%)", (first_span*100), (100.0-first_span*100))
        #log.debug("Start time: %s", str(start_time))
        #log.debug("End time: %s", str(end_time))

        # Download time
        download_time = end_time - start_time
        #log.debug("Download time: %s.", str(download_time))
        #log.debug("File size: %s", str(stream.file_size))

        # 90 percent of download time:
        first_time_span = float(download_time) * first_span
        second_time_span = float(download_time) * (1.0 - first_span)
        log.debug("First part: %.2f", first_time_span)
        log.debug("Second part: %.2f", second_time_span)

        packet_number_first = 0
        packet_number_second = 0

        # Count packets according to threshold
        # Skip first packet (get request)
        for elem in stream[1:]:
            packet_time = elem.timestamp - start_time
            if packet_time < first_time_span:
                packet_number_first = packet_number_first + 1
            else:
                packet_number_second = packet_number_second + 1

        log.debug("Total packet count: %d", len(stream))
        percentage_first_part = float(packet_number_first) / float(len(stream)) * 100.0
        percentage_second_part = float(packet_number_second) / float(len(stream)) * 100.0
        log.debug("Packet count - first part: %d (%.2f%%)", packet_number_first, percentage_first_part)
        log.debug("Packet count - second part: %d (%.2f%%)", packet_number_second, percentage_second_part)

        detected = "No"
        #if percentage_first_part < 2% of all packets:
        if percentage_first_part < 1.00: # First part: 90% of time --> There have to be more packages
            log.critical(color("Network anomaly detected! Download '%s' might be infected.",1), stream.file_name)
            syslog.syslog(syslog.LOG_CRIT, "Network anomaly detected! Download {0} might be infected.".format(stream.file_name))
            stream.proxy_detected = True
            detected = "Yes"
        else:
            log.debug("No proxy detected.")
            stream.proxy_detected = False

        log.debug("============================")
        
    def statistical_analysis3(self, stream, packet_amount=0.01, multiplicator=3.5):
        ''' Try to identify transparent proxies using statistical analysis. '''

        log.debug("Alg 2) =========================")
        log.debug("Total packet count: %d", len(stream))

        # In order to calculate variance and standard deviation we need more than 2 packets (because we take the first one out)
        if len(stream) > 2:
            start_time = stream.first_timestamp
            end_time = stream[-1].timestamp # take time stamp from the last packet in stream
            
            # Download time
            download_time = end_time - start_time        
            
            # Calculate time interval between first and second packet
            delta_one = stream[1].timestamp - stream[0].timestamp
            
            # Calculate every time interval and write it to list (inter packet time)
            log.debug("Calculating inter packet time.")
            deltas = []
            
            # For performance reasons we just focus on the 1000 packets 
            border = -1
            if len(stream) > 1000:
                border = 1000
                log.debug("Too much packets.")

            # Calculate the other time intervals
            for elem in stream[2:border]:
                # find previous packet
                prev = stream[stream.index(elem)-1]
                deltas.append(elem.timestamp - prev.timestamp)
            
            log.debug("Analyzing %d time intervals.", len(deltas)+1) # +1 for delta_one
            
            #log.debug(deltas)
            
            log.debug("Sorting packets.")
            # Sort time values (descending)    
            deltas.sort(reverse=True)
            #log.debug([delta_one] + deltas)
            detected = "No"
            
            log.debug("Packet analysis:")
            
            # Calculate a specified amount of biggest packets
            biggest_packets = int(round(len(deltas) * packet_amount))
            log.debug("First %d%%: %s", (packet_amount*100), biggest_packets)
            
            # Amount is too small
            if biggest_packets < 200:
                # Stream itself is too small
                #log.debug("Packet amount too small.")
                if len(deltas) < 20:
                    # Set amount = stream length
                    biggest_packets = len(deltas)
                    log.debug("Stream too small. Analyzing all packet delays (%d+1).", len(deltas))
                elif len(deltas) < 200:
                    log.debug("Stream too small. Analyzing 20%% of all packet delays (%d+1).", len(deltas)*0.2)
                    biggest_packets = int(round(len(deltas) * 0.2))
                elif len(deltas) < 500:
                    log.debug("Stream too small. Analyzing 10%% of all packet delays (%d+1).", len(deltas)*0.1)
                    biggest_packets = int(round(len(deltas) * 0.1))
            elif len(deltas) < 2000:
                biggest_packets = int(round(len(deltas) * (packet_amount*2)))
                log.debug("Analyzing the first %d packet delays.", biggest_packets)
            else:
                # Set minimium packets to 50
                biggest_packets = 50
                log.debug("Analyzing the first 50 packet delays.")
                
            
            big_packets = deltas[:biggest_packets]
            if biggest_packets >= 2:
                avg_with = statistics.mean([delta_one] + big_packets[:-1])
                avg_without = statistics.mean(big_packets)
                var_with = statistics.variance([delta_one] + big_packets[:-1])
                var_without = statistics.variance(big_packets)
                sdev_with = statistics.pstdev([delta_one] + big_packets[:-1])
                sdev_without = statistics.pstdev(big_packets)
                    
                log.debug("Delta_1: %s", delta_one)
                log.debug("Vals: %d", len(deltas))
                #log.debug(deltas[:biggest_packets])
                #log.debug([delta_one] + deltas[:biggest_packets-1])
                log.debug("AVG: %s", avg_with)
                log.debug("AVG -first: %s", avg_without)
                log.debug("Threshold: %s", avg_without * 2.0)
                log.debug("variance: %s", var_with)
                log.debug("variance -first: %s", var_without)
                log.debug("standard deviation: %s", sdev_with)
                log.debug("standard deviation -first: %s", sdev_without)
                
                # Normalize biggest packets
                log.debug("Normalizing.")
                #log.debug("Overall AVG: %s", statistics.mean(deltas))
                threshold = avg_without + avg_without
                log.debug("Internal threshold: %s", threshold)
                tmp = []
                for val in big_packets:
                    if val > threshold:
                        tmp.append(val)
                for val in tmp:
                    log.debug("Removing %s", val)
                    big_packets.remove(val)
                
                #log.debug(big_packets)
                avg_with = statistics.mean([delta_one] + big_packets[:-1])
                avg_without = statistics.mean(big_packets)
                log.debug("New avg: %s", avg_with)
                log.debug("New avg -first: %s", avg_without)
                log.debug("New Threshold: %s", avg_without * multiplicator)

                if (avg_without * multiplicator) < avg_with:
                    log.critical(color("Network anomaly detected! Download '%s' might be infected.",1), stream.file_name)
                    syslog.syslog(syslog.LOG_CRIT, "Network anomaly! Download {0} might be infected.".format(stream.file_name))
                    detected = "Yes"
                    stream.proxy_detected = True

            else:
                log.error("Dataset to small. Can not calculate variance.")    
            
        else:
            log.debug("Not enough packets. Skipping this test.")
        
        log.debug("============================")
