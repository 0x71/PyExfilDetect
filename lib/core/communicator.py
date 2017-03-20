# Copyright (C) 2016-2017  Nils Rogmann.
# This file is part of PyExfilDetect.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import xmlrpclib
import httplib
import socket
import ConfigParser
import ssl
import hashlib
from time import time

try:
    from lib.common.constants import APP_ROOT
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
log = logging.getLogger(__name__)

class CertificatePinningError(Exception):
    pass

class HTTPSConnection(httplib.HTTPConnection):
        """This class allows communication via SSL.
        Custom implementation based on xmlrpclib.
        """

        default_port = httplib.HTTPS_PORT

        def __init__(self, host, port=None, key_file=None, cert_file=None,
                     strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                     source_address=None, context=None,cert_fingerprint=None):
            httplib.HTTPConnection.__init__(self, host, port, strict, timeout,
                                    source_address)
            self.key_file = key_file
            self.cert_file = cert_file
            if context is None:
                context = ssl._create_default_https_context()
            if key_file or cert_file:
                context.load_cert_chain(cert_file, key_file)
            self._context = context

            # Added for certificate pinning
            self.cert_fingerprint = cert_fingerprint
            
        def stream_hash(self,data):
            ''' Calculate file hash using the packet stream. '''
            hash_handler = hashlib.sha256()
        
            hash_handler.update(data)
        
            return hash_handler.hexdigest()

        def connect(self):
            "Connect to a host on a given (SSL) port."
            httplib.HTTPConnection.connect(self)

            if self._tunnel_host:
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host

            self.sock = self._context.wrap_socket(self.sock,
                                                  server_hostname=server_hostname)
            
            if self.cert_fingerprint:
                # Get certificate in binary DER format
                der_cert_bin = self.sock.getpeercert(True)

                # Calculate fingerprint
                calculated_fingerprint = self.stream_hash(der_cert_bin)
                log.debug("Fingerprint in conf/communicator.py: %s" % self.cert_fingerprint)
                log.debug("Calculated fingerprint:              %s" % calculated_fingerprint)
                if calculated_fingerprint == self.cert_fingerprint:
                    pass
                else:
                    raise CertificatePinningError("Possible security breach: Fingerprints do not match.")
                    

class SafeTransport(xmlrpclib.Transport):
    """Handles an HTTPS transaction to an XML-RPC server.
       Custom implementation based on xmlrpclib.
    """

    def __init__(self, use_datetime=0, context=None, cert_fingerprint=None):
        xmlrpclib.Transport.__init__(self, use_datetime=use_datetime)
        self.context = context
        self.cert_fingerprint = cert_fingerprint # certificate pinning

    # FIXME: mostly untested

    def make_connection(self, host):
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        # create a HTTPS connection object from a host descriptor
        # host may be a string, or a (host, x509-dict) tuple
        try:
            HTTPS = HTTPSConnection
        except AttributeError:
            raise NotImplementedError(
                "your version of httplib doesn't support HTTPS"
                )
        else:
            chost, self._extra_headers, x509 = self.get_host_info(host)
            self._connection = host, HTTPS(chost, None, context=self.context, cert_fingerprint=self.cert_fingerprint, **(x509 or {}))
            return self._connection[1]

class Communicator():
    def __init__(self):
        self.classifier_ip = None
        self.classifier_port =  None
        self.configured = False
        self.selfsigned = False
        self.cert_fingerprint = None
        self.enable_https = None
        log.debug("Communicator started.")
        
        self.parse_config()
        
        if self.configured:
            try:
                socket.setdefaulttimeout(30)
                if self.enable_https:
                    if self.selfsigned:
                        # Unverified ssl context
                        self.server = xmlrpclib.ServerProxy("https://%s:%s" % (self.classifier_ip, self.classifier_port),
                                                            transport=SafeTransport(context=ssl._create_unverified_context(),use_datetime=0,cert_fingerprint=self.cert_fingerprint))
                    else:
                        # Verified ssl context
                        self.server = xmlrpclib.ServerProxy("https://%s:%s" % (self.classifier_ip, self.classifier_port),  
                                                            transport=SafeTransport(use_datetime=0,cert_fingerprint=self.cert_fingerprint))
                else:
                    # No SSL support
                    log.warning("SSL disabled. We are not secure.")
                    self.server = xmlrpclib.Server('http://%s:%s' % (self.classifier_ip, self.classifier_port))
            except socket.error as e:
                log.error("Cannot connect to Classifcation Server: %s" % e)
                log.debug("Communicator will be deactivated.")
                self.configured = False
            except CertificatePinningError as e:
                log.error("%s. Communicator will be deactivated." % e)
                self.configured = False

    def __del__(self):
        pass

    def parse_config(self):
        cfg = ConfigParser.ConfigParser()

        try:
            cfg.read(os.path.join(APP_ROOT, "conf", "communicator.conf"))

            host_ip = cfg.get("server","hostip")
            host_port = cfg.get("server","port")
            if host_ip and host_port:
                self.configured = True
                self.classifier_ip = host_ip
                self.classifier_port = host_port
                log.debug("Connecting to %s:%s." % (host_ip, host_port))
            else:
                self.configured = False
                log.warning("Communicator deactivated as no host ip or port set.")

            # Extract fingerprint for certificate pinning
            fingerprint = cfg.get("security", "fingerprint")
            selfsigned = cfg.get("security", "selfsigned")
            enabled = cfg.get("security", "enabled")

            if enabled == "True":
                self.enable_https = True
            else:
                self.enable_https = False

            if fingerprint:
                self.cert_fingerprint = fingerprint

            if selfsigned == "True":
                self.selfsigned = True
            else:
                self.selfsigned = False

        except:
            sys.exit("ERROR: Reading 'communicator.conf'")

    def send_session_init(self, timestamp, tag):
        if self.configured:
            try:
                session_id = self.server.init_session(timestamp, tag)
                return session_id
            except xmlrpclib.Fault as e:
                log.error("Cannot send baseline: %s " % e)
            except socket.error as e:
                log.error("Cannot connect to Classifcation Server: %s" % e)
                log.debug("Communicator will be deactivated.")
                self.configured = False
            except CertificatePinningError as e:
                log.error("%s. Communicator will be deactivated." % e)
                self.configured = False

        return None

    def send_session_end(self, timestamp, session_id):
        if self.configured:
            try:
                session_id = self.server.stop_session(timestamp, session_id)
            except xmlrpclib.Fault as e:
                log.error("Cannot send baseline: %s " % e)
            except socket.error as e:
                log.error("Cannot connect to Classifcation Server: %s" % e)
                log.debug("Communicator will be deactivated.")
                self.configured = False
            except CertificatePinningError as e:
                log.error("%s. Communicator will be deactivated." % e)
                self.configured = False

        return None

    def send_baseline(self, baseline_data, session_id):
        """ Send stream baseline summaries (arrays) to classification server. """
        if self.configured and session_id:
            try:
                first = time()
                log.debug("Trying to send baseline.")
                rows = self.server.set_baseline(baseline_data, session_id)
                second = time()
                log.info("%s rows transmitted in %s seconds." % (rows, round(second-first,2)))

                return rows
            except xmlrpclib.Fault as e:
                log.error("Cannot send baseline: %s " % e)
            except socket.error as e:
                log.error("Cannot connect to Classifcation Server: %s" % e)
                log.debug("Communicator will be deactivated.")
                self.configured = False
            except CertificatePinningError as e:
                log.error("%s. Communicator will be deactivated." % e)
                self.configured = False

    def send_streams(self, stream_data, session_id):
        """ Send stream summaries (arrays) to classification server. """
        if self.configured and session_id:
            try:
                first = time()
                log.debug("Trying to send stream data.")
                rows = self.server.classify_streams(stream_data, session_id)
                second = time()
                log.debug("%s rows transmitted in %s seconds." % (rows, round(second-first,2)))

                return rows
            except xmlrpclib.Fault as e:
                log.error("Cannot send stream data: %s " % e)
            except socket.error as e:
                log.error("Cannot connect to Classifcation Server: %s" % e)
                log.debug("Communicator will be deactivated.")
                self.configured = False
            except CertificatePinningError as e:
                log.error("%s. Communicator will be deactivated." % e)
                self.configured = False
