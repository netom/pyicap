#!/bin/env python
# -*- coding: utf8 -*-

import sys
import random
import threading
import SocketServer

from pyicap import *

cv = threading.Condition()
message = None

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    service = 'PyICAP Server v1.0a'
    max_connections = 100,
    options_ttl = 3600

    def random_istag(self):
        self.send_header('ISTag', ''.join(map(lambda x: random.choice('ABCDIFGHIJabcdefghij1234567890'), xrange(16))))

    def options(self, methodname):
        self.send_response(200)
        self.send_header('Methods', 'RESPMOD')
        self.send_header('Service', 'Vengit ICAP Server 1.0')
        self.send_header('Preview', '0')
        self.send_header('Transfer-Preview', '*')
        self.send_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv,js,css')
        self.send_header('Transfer-Complete', '')
        self.random_istag()
        self.end_headers()

    # Convention: 'icap://<host>/method_name'
    def ssprewriter(self):
        self.random_istag()
        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"
