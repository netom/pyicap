#!/bin/env python
# -*- coding: utf8 -*-

import random
import SocketServer

from pyicap import *

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'REQMOD')
        self.set_icap_header('Service', 'PyICAP Server 1.0')
        self.send_headers(False)

    def example_REQMOD(self):
        self.set_icap_response(200)

        enc_req = self.enc_req[:]
        enc_req[1] = 'http://gravatar.com/avatar/864167d82d60f126e4225e53953461a4'
        self.set_enc_request(' '.join(enc_req))
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)

        # Copy the request body (in case of a POST for example)
        if not self.has_body:
            self.send_headers(False)
            return

        while True:
            chunk = self.read_chunk()
            if chunk == '':
                break

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"
