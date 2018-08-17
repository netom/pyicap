FROM ubuntu:18.04

MAINTAINER Fabian Tamas Laszlo <giganetom@gmail.com>

ADD . /pyicap

WORKDIR /pyicap

ENTRYPOINT ./test.sh
