pyicap
======

A Python framework for writing ICAP servers

What is ICAP?
-------------

For a dry and precise technical description see RFC 3507.

ICAP is a protocol that is used by HTTP proxies to ask a separate
service (an ICAP server) to do modification on HTTP requests and
responses it proxies. Such proxy is an ICAP client.

ICAP can be used to check permissions, scan viruses, place ads or
otherwise modify the headers, content or request URL or HTTP requests
and/or responses. These can be done without modifying the proxy server's
code.

The popular proxy software Squid 3.x supports the ICAP protocol, and
this framework was tested with Squid3.

Design
------

The ICAP protocol closely resembles HTTP/1.1, so I choosed to modify
Python's stock BaseHTTPServer class for the purpose.

It is important to note that ICAP _IS NOT_ an application of HTTP,
neither a protocoll wrapped into it. If a relationship must be stated,
I's say ICAP is a sibling of HTTP rather it's child.

Because of this relationship a HTTP server or client cannot be trivially
extended (or even monkey-patched) to handle ICAP. This is why I choose
to copy, then completely rewrite the BaseHTTPServer class

How it works?
-------------

You can use a framework by importing stuff from the pyicap package,
extending the protocol handler class and starting the server, passing
your handler to it:

```python
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

    def sampleservice_options(self, methodname):
        self.send_response(200)
        self.send_header('Methods', 'RESPMOD')
        self.send_header('Service', 'Python ICAP Server 1.0')
        self.send_header('Preview', '0')
        self.send_header('Transfer-Preview', '*')
        self.send_header('Transfer-Ignore', 'jpg,jpeg,gif,png,swf,flv,js,css')
        self.send_header('Transfer-Complete', '')
        self.send_header('Max-Connections', '100')
        self.send_header('Options-TTL', '3600')

        self.random_istag()
        self.end_headers()

    # Convention: 'icap://<host>/method_name'
    def sampleservice(self):
        self.no_adaptation_required()

port = 13440

server = ThreadingSimpleServer(('', port), ICAPHandler)
try:
    while 1:
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"

```

The above example is a rewritten SimpleHTTPServer example with
threading. The SocketServer.ThreadingMixin can be used with ICAPServer
just like you would use it with SimpleHTTPServer.

The class ICAPHandler does the real work.

For every service endpoint there is a pair of methods.

ICAP defines three HTTP-like methods: OPTIONS, REQMOD and RESPMOD.

OPTIONS must be handled in every case. An endpoint has to support either
REQMOD or RESPMOD, but not both. However, this is not enforced, and
according to the squid 3 documentation, such overloading will even work
with squid.

REQMOD is called, when a HTTP request must be modified - like checking
access to an URL, stripping or adding query string parameters or POST
data, modifying headers or otherwise mangling the request.

RESPMOD is called when a HTTP response must be modified - such as
checking to-be-downloaded files for viruses, watermarking images or
audio files, placing ad banners, or otherwise modifying the content
and/or the headers of the request.

ICAP works with URLs just like HTTP. Every ICAP service has an URL like:

icap://icap.myorganization.com/place_banners

The PyICAP framework will parse this URL, determines the ICAP method to
call (OPTIONS, REQMOD or RESPMOD), and calls one of the handler methods
that the user (probably) provided. If the ICAP server can't find a
handler method, it returns a 404 error.

In this particular example, the place_banners_*() method is called (*
can be reqmod or respmod).

An OPTIONS request triggers the related _options() method, in this case
the place_banners_options().

Various information can be extracted from the ICAP request by examining
certain fields of the handler object:

* self.enc_req_status: encapsulated request status, list with 3 elements
* self.enc_req_headers: encapsulated request headers, dictionary of lists
* self.enc_res_status: encapsulated response status
* self.enc_res_headers: encapsulated response headers
* self.has_body: True, if the ICAP request has a body
* self.servicename: name of the service endpoint
* self.encapsulated: contains the "Encapsulated:" header's content as a dict

There are several helper methods that can be called while serving a
requets:

* send_response(code[, message])
* send_header()
* send_error(error_code)
* no_adaptation_required()
* continue()

