# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging

from sys import exit
import os
import platform


log = logging.getLogger(__name__)

class RawSocket():
    def __init__(self, interfaces="eth0"):
        
        # init variables
        self.promisc = 0
        self.my_socket = False
        self.interfaces = interfaces
        self.system = platform.system().lower()
        
        log.info("Identified platform %s.", self.system)
        # Trying to start promiscuous mode
        self.__activate_promisc()
        
    def __del__(self):
        # Trying to stop promiscuous mode
        self.__deactivate_promisc()

    def __activate_promisc(self):
        if self.system == "linux":
            # activate promiscuous mode the lazy way
            # non-lazy way: http://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux
            for dev in self.interfaces: # start mode for every specified interface
                log.info("Starting promiscuous mode on %s.", dev)
                self.promisc = os.system("ip link set %s promisc on" % dev)
                if self.promisc != 0:
                    log.warn("I was not able to start promiscuous mode.")
        else:
            log.error("OS not supported yet.")
            exit(0)
            
    def __deactivate_promisc(self):
        if self.system == "linux":
            for dev in self.interfaces:
                if self.promisc == 0:
                    os.system("ip link set %s promisc off" % dev)
                    log.info("Stopping promiscuous mode.")
        else:
            log.error("OS not supported yet.")
            exit(0)
            
    def start(self):
        """ Starts the raw socket. """
        try:
            if self.system == "linux":
                # Create a raw socket
                self.my_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
                # Increase socket buffer size to reduce packet loss
                # Usage of  2**30 is OK as the buffer size is limited by the system anayway (/proc/sys/net/core/rmem_max)
                self.my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

                # Get receive buffer size
                rcvbuf = self.my_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)

                log.info("Raw socket created.")
                log.debug("Raw socket buffer size: %s", rcvbuf)
                '''
                    PF_PACKET:   http://stackoverflow.com/questions/114804/reading-from-a-promiscuous-network-device
                    SOCK_RAW:    Raw socket
                    IPPROTO_IP:  IP Protocol
                '''
            else:
                log.error("OS not supported yet.")
                exit(0)
        except socket.error, msg:
            log.error('Socket cannot be created: ' + str(msg[0]) + ' Message ' + msg[1])
            exit("ERROR: I cannot work without sockets.. Bye.")
            
    def recv(self):
        return self.my_socket.recvfrom(65565)
            