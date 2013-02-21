#!/bin/env python
# -*- coding: utf8 -*-

import sys
import threading
import SocketServer
import BaseICAPServer

cv = threading.Condition()
message = None

class ThreadingSimpleServer(SocketServer.ThreadingMixIn, BaseICAPServer.ICAPServer):
    pass

class ICAPHandler(BaseICAPServer.BaseICAPRequestHandler):
    def headers_for(self, msg):
        return (
            "ICAP/1.0 200 OK\nContent-Length: " + str(len(msg)) +
            "\nContent-Type: text/plain; charset=utf8\n\n"
        )

    def do_POST(self):
        pass

    def do_GET(self):
        global message
        if self.path == '/getmsg':
            cv.acquire()
            while message == None:
                print "W: waiting..."
                cv.wait()
                print "W: done wait"
            self.wfile.write(self.headers_for(message) + message)
            message = None
            cv.release()
            return
            
        cv.acquire()
        message = self.path
        print "X: w has been notified."
        cv.notify()
        cv.release()
        msg = "Message sent."
        self.wfile.write(self.headers_for(msg) + msg)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Methods', 'RESPMOD')
        self.send_header('Service', 'Vengit ICAP Server 1.0')
        self.end_headers()

    def do_REQMOD(self):
        self.send_response(204)
        self.end_headers()

    def do_RESPMOD(self):
        self.send_response(204)
        self.end_headers()

        if not self.encapsulated.has_key('null-body'):
            while True:
                chunk = self.read_chunk()
                if chunk == '':
                    break

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"
