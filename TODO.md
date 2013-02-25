TODO
====

Bugs
----

* read_chunk has to look for a non-empty line before it start the real
  work. As far as I understand HTTP and ICAP, this shouldn't be this
  way. It's just a really dirty workaround for a nasty bug. (high
  priority)
* Add support for http entity headers. (high priority)
* squid3: icap_persistent_connections=on does not work (high priority)
* Can't handle Trailer: header (See ICAP errata!) (low priority)
* Can't handle Upgrade: header (low priority)

Improvements
------------

* Generate documentation to pydoc, make available on the web
* Document the use of Date, Server, ISTag headers
* Add a method to send encapsulated HTTP errors
* set_* -> add_* to make handling headers more flexible
* The current read_chunk is too stupid, easy to screw up the protocol,
  needs to be made smarter
* The overall data reading/writing has to be much-much simpler. The user
  has to see input and output streams, not this chunk-based clumsy
  nonsense.
* Provide basic tools to run replace, regexp-replace on data. Such
  things should be done with one-liners (+ a very small boilerplate).
* Provide a and implementation that can call unix commands on messages
  and pass data back to client
