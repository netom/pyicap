"""ICAP server base class.

See RFC 3507
"""

__version__ = "1.0"

__all__ = ['ICAPServer', 'BaseICAPRequestHandler', 'ICAPException']

import sys
import time
import socket
import SocketServer

# Default error message template
DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Error response</title>
</head>
<body>
<h1>Error response</h1>
<p>Error code %(code)d.
<p>Message: %(message)s.
<p>Error code explanation: %(code)s = %(explain)s.
</body>
"""

DEFAULT_ERROR_CONTENT_TYPE = "text/html"

def _quote_html(html):
    return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

class ICAPException(Exception):
    pass

class ICAPServer(SocketServer.TCPServer):

    allow_reuse_address = 1

    def server_bind(self):
        """Override server_bind to store the server name."""
        SocketServer.TCPServer.server_bind(self)
        host, port = self.socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port


class BaseICAPRequestHandler(SocketServer.StreamRequestHandler):

    """ICAP request handler base class.
    """

    # The version of the ICAP protocol we support.
    protocol_version = "ICAP/1.0"

    # Table mapping response codes to messages; entries have the
    # form {code: (shortmessage, longmessage)}.
    # See RFC 2616 and RFC 3507
    responses = {
        100: ('Continue', 'Continue after ICAP Preview'),
        101: ('Switching Protocols',
              'Switching to new protocol; obey Upgrade header'),

        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted',
              'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),

        204: ('No adaptation required', 'There is no need to modify the content'),

        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),

        300: ('Multiple Choices',
              'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified',
              'Document has not changed since given time'),
        305: ('Use Proxy',
              'You must use proxy specified in Location to access this '
              'resource.'),
        307: ('Temporary Redirect',
              'Object moved temporarily -- see URI list'),

        400: ('Bad Request', 'Bad request syntax or unsupported method'),
        401: ('Unauthorized',
              'No permission -- see authorization schemes'),
        402: ('Payment Required',
              'No payment -- see charging schemes'),
        403: ('Forbidden',
              'Request forbidden -- authorization will not help'),
        404: ('ICAP Service not found', 'Nothing matches the given URI'),
        405: ('Method not allowed for service',
              'Specified method is invalid for this resource.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required', 'You must authenticate with '
              'this proxy before proceeding.'),
        408: ('Request Timeout',
              'ICAP server gave up waiting for a request from an ICAP client'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone',
              'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',
              'Cannot satisfy request range.'),
        417: ('Expectation Failed',
              'Expect condition could not be satisfied.'),

        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Method not implemented',
              'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service overloaded',
              'The ICAP server has exceeded a maximum connection '+
              'limit associated with this service'),
        504: ('Gateway Timeout',
              'The gateway server did not receive a timely response'),
        505: ('ICAP Version not supported by server', 'Cannot fulfill request.'),
    }

    # The Python system version, truncated to its first component.
    sys_version = "Python/" + sys.version.split()[0]

    # The server software version.  You may want to override this.
    # The format is multiple whitespace-separated strings,
    # where each string is of the form name[/version].
    server_version = "BaseICAP/" + __version__

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    default_request_version = "ICAP/1.0"

    # Used to signal ieof condition on preview requests
    ieof = False

    def read_status(self):
        """Read a status line from input stream"""
        return self.rfile.readline().strip().split(' ', 2)

    def read_headers(self):
        """Read a sequence of header lines"""
        headers = {}
        while True:
            line = self.rfile.readline().strip()
            if line == '':
                break
            k, v = line.split(':', 1)
            headers[k] = headers.get(k, []) + [v.strip()]
        return headers

    def read_chunk(self):
        """Read a HTTP chunk"""
        while True:
            line = self.rfile.readline().strip()
            if line != '':
                break

        arr = line.split(';', 1)

        chunk_size = 0
        try:
            chunk_size = int(arr[0], 16)
        except ValueError:
            pass
            raise ICAPException(chunk_size)

        # Look for ieof chunk extension
        if len(arr) > 1 and arr[1].strip() == 'ieof':
            self.ieof = True

        if chunk_size == 0:
            return ""

        value = self.rfile.read(chunk_size)

        self.rfile.read(2)

        return value

    def write_chunk(self, data):
        l = hex(len(data))[2:]
        self.wfile.write(l + '\r\n')
        self.wfile.write(data)
        self.wfile.write('\r\n')

    def add_reshdr(self, header, value):
        # TODO
        pass

    def add_reqhdr(self, header, value):
        # TODO
        pass

    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.

        """
        self.command = None
        self.request_version = version = self.default_request_version

        # Default behavior is to leave connection open
        self.close_connection = 0

        requestline = self.raw_requestline.rstrip('\r\n')
        self.requestline = requestline

        words = requestline.split()
        if len(words) != 3:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False

        command, path, version = words

        if version[:5] != 'ICAP/':
            self.send_error(400, "Bad request protocol, only accepting ICAP")
            return False

        if command not in  ['OPTIONS', 'REQMOD', 'RESPMOD']:
            self.send_error(400, "Bad ICAP request type (%r)" % command)
            return False

        try:
            base_version_number = version.split('/', 1)[1]
            version_number = base_version_number.split(".")
            # RFC 2145 section 3.1 says there can be only one "." and
            #   - major and minor numbers MUST be treated as
            #      separate integers;
            #   - ICAP/2.4 is a lower version than ICAP/2.13, which in
            #      turn is lower than ICAP/12.3;
            #   - Leading zeros MUST be ignored by recipients.
            if len(version_number) != 2:
                raise ValueError
            version_number = int(version_number[0]), int(version_number[1])
        except (ValueError, IndexError):
            self.send_error(400, "Bad request version (%r)" % version)
            return False

        if version_number != (1, 0):
            self.send_error(505, "Invalid ICAP Version (%s)" % base_version_number)
            return False

        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive
        self.headers = self.read_headers()

        self.close_connection = 0

        conntype = self.headers.get('Connection', [''])[0]
        if conntype.lower() == 'close':
            self.close_connection = 1

        # Get the encapsulated headers

        self.encapsulated = {}
        if self.command in ['RESPMOD', 'REQMOD']:
            for enc in self.headers.get('Encapsulated', [''])[0].split(','):
                # TODO: raise ICAPError if Encapsulated is malformed or empty
                k,v = enc.strip().split('=')
                self.encapsulated[k] = int(v)

        self.enc_req_status = None
        self.enc_req_headers = {}
        self.enc_res_status = None
        self.enc_res_headers = {}
        self.has_body = False

        if self.command == 'REQMOD':
            if self.encapsulated.has_key('req-hdr'):
                self.enc_req_status = self.read_status()
                self.enc_req_headers = self.read_headers()
            if self.encapsulated.has_key('req-body'):
                self.has_body = True
        elif self.command == 'RESPMOD':
            if self.encapsulated.has_key('req-hdr'):
                self.enc_req_status = self.read_status()
                self.enc_req_headers = self.read_headers()
            if self.encapsulated.has_key('res-hdr'):
                self.enc_res_status = self.read_status()
                self.enc_res_headers = self.read_headers()
            if self.encapsulated.has_key('res-body'):
                self.has_body = True
        # Else: OPTIONS. No encapsulation.

        # Parse service name
        

        return True

    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.

        """
        try:
            self.raw_requestline = self.rfile.readline(65537)
            #if len(self.raw_requestline) > 65536:
            #   self.requestline = ''
            #   self.request_version = ''
            #   self.command = ''
            #   self.send_error(414)
            #   return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.send_error(501, "Unsupported method (%r)" % self.command)
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush() #actually send the response if not already done.
        except socket.timeout, e:
            #a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

    def handle(self):
        """Handle multiple requests if necessary."""
        self.close_connection = 1

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def send_error(self, code, message=None):
        # TODO: maket his ICAP compilant
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching the
        response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        self.log_error("code %d, message %s", code, message)
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': _quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)

    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE

    def send_response(self, code, message=None):
        """Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.
        """
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        self.wfile.write("%s %d %s\r\n" %
                         (self.protocol_version, code, message))
            # print (self.protocol_version, code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def send_header(self, keyword, value):
        """Send a MIME header."""
        self.wfile.write("%s: %s\r\n" % (keyword, value))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = 1
            elif value.lower() == 'keep-alive':
                self.close_connection = 0

    def end_headers(self):
        """Send the blank line ending the MIME headers."""
        self.wfile.write("\r\n")

    def log_request(self, code='-', size='-'):
        """Log an accepted request.

        This is called by send_response().

        """

        self.log_message('"%s" %s %s',
                         self.requestline, str(code), str(size))

    def log_error(self, format, *args):
        """Log an error.

        This is called when a request cannot be fulfilled.  By
        default it passes the message on to log_message().

        Arguments are the same as for log_message().

        XXX This should go to the separate error log.

        """

        self.log_message(format, *args)

    def log_message(self, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.  Override
        it if you have specific logging wishes.

        The first argument, FORMAT, is a format string for the
        message to be logged.  If the format string contains
        any % escapes requiring parameters, they should be
        specified as subsequent arguments (it's just like
        printf!).

        The client ip address and current date/time are prefixed to every
        message.

        """

        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))

    def version_string(self):
        """Return the server software version string."""
        return self.server_version + ' ' + self.sys_version

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
        return s

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def address_string(self):
        """Return the client address formatted for logging.

        This version looks up the full hostname using gethostbyaddr(),
        and tries to find a name that contains at least one dot.

        """

        host, port = self.client_address[:2]
        return socket.getfqdn(host)

    def do_OPTIONS(self):
        self.options('dummy')

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

    def no_adaptation_required(self):
        self.send_response(204)
        self.end_headers()

    def options(self, methodname):
        pass
