#!/bin/env python
# -*- coding: utf8 -*-

import random

try:
    import socketserver
except ImportError:
    import SocketServer
    socketserver = SocketServer

from pyicap import *

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'REQMOD')
        self.set_icap_header('Service', 'PyICAP Server 1.0')
        self.send_headers(False)

    def example_REQMOD(self):
        self.set_icap_response(200)

        if ('bbc.com' not in self.enc_req[1] and
            'bbc.co.uk' not in self.enc_req[1] and
            'bbci.co.uk' not in self.enc_req[1] and
            'bbcimg.co.uk' not in self.enc_req[1]
        ):
            self.set_enc_status('HTTP/1.1 307 Temporary Redirect')
            self.set_enc_header('location', 'http://bbc.co.uk/')
            self.send_headers(False)
            return

        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print("Finished")
