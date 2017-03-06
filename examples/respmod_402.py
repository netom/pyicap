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
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Preview', '0')
        self.send_headers(False)

    def example_RESPMOD(self):
        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print("Finished")
