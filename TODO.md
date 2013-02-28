TODO
====

BUGS
----

Not known at the moment. Please let me know if you find one!

Improvements
------------

* Document the use of Date, Server, ISTag headers
* After the above is done, go beta
* Add a method to send encapsulated HTTP errors
* Make header handling smarter
* set_* -> add_* to make handling headers more flexible
* squid3: icap_persistent_connections=on does not work (low priority)
* Can't handle Trailer: header (See ICAP errata!) (low priority)
* Can't handle Upgrade: header (low priority)

High level Featues
------------------

* Provide basic tools to run replace, regexp-replace on data. Such
  things should be done with one-liners (+ a very small boilerplate).
* Provide a and implementation that can call unix commands on messages
  and pass data back to client on stdin/out or named pipe(s)
