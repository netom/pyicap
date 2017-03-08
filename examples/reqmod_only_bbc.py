#!/bin/env python
# -*- coding: utf8 -*-

import random

try:
    import socketserver
except ImportError:
    import SocketServer
    socketserver = SocketServer

import sys
sys.path.append('.')

from pyicap import *

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        self.send_headers(False)

    def example_REQMOD(self):
        self.set_icap_response(200)

        if (b'bbc.com' not in self.enc_req[1] and
            b'bbc.co.uk' not in self.enc_req[1] and
            b'bbci.co.uk' not in self.enc_req[1] and
            b'bbcimg.co.uk' not in self.enc_req[1]
        ):
            self.set_enc_status(b'HTTP/1.1 307 Temporary Redirect')
            self.set_enc_header(b'location', b'http://bbc.co.uk/')
            self.send_headers(False)
            return

        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer((b'', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print("Finished")
