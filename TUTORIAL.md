The PyICAP tutorial
===================

This is a short tutorial on how to use PyICAP. A basic knowledge of the
HTTP protocol is required. If you have never used telnet or netcat to
connect to a HTTP server, then most of what's coming will be hard to
understand.

For those who never experimented with HTTP I highly recommend reading
http://www.jmarshall.com/easy/http/.

The Internet Content Adaptation Protocol (ICAP) in a nutshell
-------------------------------------------------------------

### Introduction

Proxy servers are widely used for different purposes: to offer Web-only
internet access, to cache files on web and spare bandwidth, and as
reverse proxies. Proxy server - like squid - has very different and
often quite limited abilities to alter the HTTP documents they pass
along. For example with squid, some basic header adaptations can be
done by configuring ACLs, but if someone wishes to do complicated string
replacement, virus checking or access control, it's most likely that
- without using any sophisticated content adaptation solution like ICAP
- the source code of squid has to be modified to solve the problem.

ICAP come to life to solve a common need: to change content passing
through proxy servers. Therefore ICAP is mostly used between a HTTP
proxy (reverse or otherwise) and an ICAP server. Proxy software
providers are only required to implement ICAP instead of writing their
own content adaptation solutions from scratch.

### Relation to HTTP 1.1

ICAP is a protocol on it's own. It is very similar to HTTP in certain
ways, but it's by no means an application nor an extension of HTTP.
Because of this, an ordinary HTTP server can't handle ICAP requests.
One can't simply just write a PHP or Python-Django application to handle
ICAP requests. If you want to speak ICAP, you need an ICAP
client/server, or you have to write your own.

What is an application of HTTP? For example a RESTful web service is an
application of HTTP because it is relying on HTTP as a transport layer,
and _uses it_ to accomplish something _more specific_ than HTTP itself.
ICAP isn't trying to accomplish something more specific but something
_different_. ICAP has different methods from HTTP, has different
headers, and uses different rules to encode data.

This tutorial explains some of the differences so the reader will be
able to understand the design of the library and use it successfully and
efficiently.

An ICAP server - similar to a HTTP server - listens to on a TCP port
for incoming connections, reads _requests_ and sends back _responses_.
The ICAP request (response) is very similar to a HTTP request
(response). An ICAP request - just like HTTP - has a request line that
contains the _request method_, the URL of the _resource_, and the
protocol version.

A typical HTTP request looks like this:

```
GET http://www.bbc.co.uk/ HTTP/1.1
Host: www.bbc.co.uk
Connection: close

```

Here, GET is the HTTP _method_ or _command_. The string
http://www.bbc.co.uk/ is a resource identifier, HTTP/1.1 is the protocol
version. The two lines after the request line are headers. For their
purpose, see the HTTP 1.1 protocol specification (RFC 2616).

If you connect to www.bbc.co.uk with telnet or netcat, and send the
above message (including the empty line), then you get a HTTP response
back (not the complete response, certain header lines were dropped
because of their length):

```
HTTP/1.1 200 OK
Server: Apache
X-Cache-Action: PASS (non-cacheable)
Vary: X-CDN
Cache-Control: private, max-age=60
X-Cache-Age: 10
Content-Type: text/html
X-TraceId: 18cf197b-0d83cbc8-0bf78e11-traf034
Date: Sun, 10 Mar 2013 10:14:29 GMT
Expires: Sun, 10 Mar 2013 10:15:19 GMT
Connection: close
Content-Length: 113103

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML+RDFa 1.0//EN" ...
```

In this response, we see a _status line_. The first thing on the status
line is the protocol version: HTTP/1.1. What follows is the response
code, in this example the number 200. The third token is a short textual
description of the response code, in this case OK, meaning the request
can be fulfilled, and the requested resource can be returned. We can
observe various headers after the status line. A blank line signals
the end of the header section, and content follows.

HTTP has (for example) POST, GET, OPTIONS, HEAD methods, and extensions
to the protocol add even more. ICAP has only three: REQMOD, RESPMOD and
OPTIONS. (The last one is very similar to the OPTIONS method of HTTP.)
ICAP has special headers not present in the HTTP specs, such as the
ISTag, or the Encapsulated header.

### ICAP headers

ISTag
Encapsulated
Date
Server

### 204 No Content

### Preview

### The OPTIONS method

### The REQMOD method

### The RESPMOD method

Creating the test web page
--------------------------

Configuring Squid for testing PyICAP
------------------------------------
To configure Squid to use your ICAP script make these changes to your 
`sqiud.conf` that possibly will reside in `/etc/squid/` or `/etc/squid3/`.
Further information about the config options may be in the comments in 
the config file.

* First you want to enable ICAP.
```
icap_enable on
```
This directive is pretty self-explanatory.

* Then you want to specify your service.
```
icap_service id vectoring_point uri [option ...]
```
Now we configure the specifics of our service.
First we assign an `id`. This id will be used to direct traffic to this 
specific service.
Next comes the `vectoring_point`. This may be either of 
`{req,resp}mod_{pre,post}cache`. This specifies at with point of transaction
processing this service should be activated. 
Then comes the `URI` which will specify the server, port and service-path. It
looks something like `icap://servername:port/servicepath`.
  
So if we want to implement a simple script that replaces strings in websites
we will use a line like:
```
icap_service my_service respmod_precache icap://localhost:13440/test
```
If one now sends a request via the Squid proxy the `test_RESPMOD(self)` 
method will get invoked.

* Next we have to insert the service
```
adaptation_access service_name allow|deny [!]aclname...
```
This directive specifies when a service will get invoked.
As `service_name` we use the `id` from above.
To selectively use this service apply ACLs to this directive.
If an ACL matches an "allow" rule this service is used to for this
transaction. If a "deny" rule matches, no adaptation service is activated.

To filter all response traffic use:
```
adaptation_access my_service allow all
```


Setting up your browser
-----------------------

Example 0: Using the framework
------------------------------

Example 1: URL rewriting
------------------------

Example 2: Access control
-------------------------

Example 3: Replacing words
--------------------------
