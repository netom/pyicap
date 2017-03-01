#!/bin/env python
# -*- coding: utf8 -*-

import random
import socketserver
import tempfile

from pyicap import *

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Service', 'PyICAP Server 1.0')
        self.set_icap_header('Preview', '0')
        self.set_icap_header('Transfer-Preview', '*')
        self.set_icap_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header('Transfer-Complete', '')
        self.set_icap_header('Max-Connections', '100')
        self.set_icap_header('Options-TTL', '3600')
        self.send_headers(False)

    def read_into(self, f):
        while True:
            chunk = self.read_chunk()
            if chunk == '':
                return
            f.write(chunk)
        
    def example_RESPMOD(self):
        #while True:
        #    chunk = self.read_chunk()
        #    if chunk == '':
        #        break
        #self.send_enc_error(500, body='<html><head><title>Whoops</title></head><body><h1>500 ICAP meditation</h1></body></html>')
        #return
        self.set_icap_response(200)

        self.set_enc_status(' '.join(self.enc_res_status))
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        if not self.has_body:
            self.send_headers(False)
            return
        
        # Read everything from the response to a temporary file
        # This file can be placed onto a tmpfs filesystem for more performance
        with tempfile.NamedTemporaryFile(prefix='pyicap.', suffix='.tmp') as upstream:
            self.read_into(upstream)
            if self.preview and not self.ieof:
                self.cont()
                self.read_into(upstream)
            upstream.seek(0)
            
            # And write it to downstream
            content = upstream.read()
            self.write_chunk(cont)

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print("Finished")
