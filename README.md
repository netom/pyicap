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

    def echo_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD')
        self.set_icap_header('Preview', '0')
        self.send_headers(False)

    def echo_RESPMOD(self):
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

For every service endpoint there is a pair of methods. The current
example simply does nothing by telling the ICAP client that the request
needs no modification.

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

* enc_req: encapsulated request line, list with 3 elements
* enc_req_headers: encapsulated request headers, dictionary of lists
* enc_res_status: encapsulated response status
* enc_res_headers: encapsulated response headers
* has_body: True, if the ICAP request has a body
* servicename: name of the service endpoint
* encapsulated: contains the "Encapsulated:" header's content as a dict
* ieof: True, if read_chunk() encounters an ieof chunk extension
* command: the current ICAP command
* request_uri: contains the full request URI of the ICAP request
* version: the version if the current ICAP request
* preview: None, or an integer that arrived in the Preview header
* allow: Contains a set() of Allow:-ed stuff
* icap_response_code: contains the response code if set_icap_reponse
  was called.

There are several helper methods that can be called while serving a
requets:

* send_error(error_code): Sends and entire ICAP error response
* no_adaptation_required(): Sends a response that means that leaves the
  encapsulated message unaltered. It honors the Allow header, and only
  sends 204 No adaptation required if the client allowed such response.
* cont(): Sends an ICAP 100 Continue response to the client. Can be
  used to request the client to continue sending data after a preview.
* read_chunk(): Reads a chunk from the client. Be aware that this call
  blocks. If there is no available data on the line, and Connection: 
  keep-alive is used, it will cause the server to hang. This method
  should only be called if it's sure there will be data available
  eventually. If it returns an empty string, it means that it's the
  last chunk, and no further read should be executed. It also sets the
  ieof variable to True, if the ieof chunk extension is encountered.
  This extension is sent during a preview if the encapsulated message
  fits in the preview entirelly. If ieof is True continue() must not be
  called.
* set_icap_response(code): sets the ICAP response
* set_enc_status(stats): Sets the encapsulated status line
* set_enc_request(request): Sets the encapsulated request line
* set_enc_header(header, value): Set an encapsulated header. Multiple
  calls will cause the header to be sent more than once. This is useful
  for example for Cookie: headers.
* set_icap_header(header, value): Set an ICAP header. Note that this should
  not be used normally, since all necesary ICAP headers are set
  automatically by the framework (such as ISTag, Encapsulated, Date,
  Server, etc.)
* send_headers(has_body=False): can be used after setting ICAP and
  encapsulated headers. The parameter has_body signals the existance of
  an encapsulated message body.
* send_chunk(data): writes a chunk to the client. An empty chunk must
  be written as the last chunk. Data must be sent after send appropriate
  headers either with send_header() or enc_header()/icap_header() +
  send_headers(). The two header-sending methods must not be mixed.
  If sending data with send_headers, the has_body parameter must be set
  to properly indicate the existance or absence of an encapsulated
  message body.




