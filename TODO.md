TODO
====

BUGS
----

None are known at the moment. Please let me know if you find one!

Improvements
------------

* Document the use of Date, Server, ISTag headers
* Add a tutorial
* Make header handling smarter
* After the above is done, go beta
* Can't handle Trailer: header (See ICAP errata!) (low priority)
* Can't handle Upgrade: header (low priority)

High level Featues
------------------

* Provide basic tools to run replace, regexp-replace on data. Such
  things should be done with one-liners (+ a very small boilerplate).
* Provide a and implementation that can call unix commands on messages
  and pass data back to client on stdin/out or named pipe(s)
