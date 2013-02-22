#!/bin/env python
# -*- coding: utf8 -*-

import random
import SocketServer

from pyicap import *

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def random_istag(self):
        self.send_header('ISTag', ''.join(map(lambda x: random.choice('ABCDIFGHIJabcdefghij1234567890'), xrange(16))))

    def ssprewriter_options(self):
        self.send_response(200)
        self.send_header('Methods', 'RESPMOD')
        self.send_header('Service', 'Vengit ICAP Server 1.0')
        self.send_header('Preview', '0')
        self.send_header('Transfer-Preview', '*')
        self.send_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv,js,css')
        self.send_header('Transfer-Complete', '')
        self.send_header('Max-Connections', '100')
        self.send_header('Options-TTL', '3600')

        self.random_istag()
        self.end_headers()

    # Convention: 'icap://<host>/service_name'
    def ssprewriter_respmod(self):
        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"
