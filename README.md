pyicap
======

(This readme is still very incomplete, come back a week or so later)

A Python framework for writing ICAP servers

What is ICAP?
=============

For a dry and precise technical description see RFC 3507.

ICAP is a protocol that is used by HTTP proxies to ask a separate
service to do modification on HTTP requests and responses it proxies.

It can be used to check permissions, scan viruses, place ads or
otherwise modify the headers, content or request URL or HTTP requests
and/or responses.

Design
======

The ICAP protocol closely resembles HTTP/1.1. Because of this I choosed
to (throughly) modify Python's stock BaseHTTPServer class.

It is important to note that ICAP _IS_NOT_ an application of HTTP,
neither a protocoll wrapped into it. If a relationship must be stated,
I's say ICAP is a sibling of HTTP rather it's child.

Because of this relationship a HTTP server or client cannot be trivially
extended (or even monkey-patched) to handle ICAP. This is why I choose
to copy, then completely rewrite the BaseHTTPServer class

How it works?
=============

You can use a framework by importing stuff from the pyicap package,
extending the protocol handler class and starting the server, passing
your handler to it (see example below).

ICAP defines three HTTP-like methods: OPTIONS, REQMOD and RESPMOD.

OPTIONS must be handled in every case.

REQMOD is called, when a HTTP request must be modified - like checking
access to an URL, stripping or adding query string parameters or POST
data, modifying headers or otherwise mangling the request.

RESPMOD is called when a HTTP response must be modified - such as
checking to-be-downloaded files for viruses, watermarking images or
audio files, placing ad banners, or otherwise modifying the content
and/or the headers of the request.

ICAP also works with URLs just like HTTP. Every ICAP service has an URL
like:

icap://icap.myorganization.com/place_banners

The PyICAP framework will parse this URL, determines the ICAP method to
call (OPTIONS, REQMOD or RESPMOD), and calls one of the handler methods
that the user (probably) provided.

In this particular example, the place_banners() method is called.

Various information can be extracted from the ICAP request by examining
certain fields of the handler object.







