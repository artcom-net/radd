#!/bin/bash

start="docker start radius-server"
run="docker run -d -v $(pwd):/root/radius-server -p 1812:1812/udp -p 1813:1813/udp -p 2201:22 --name radius-server radius-server"
build="docker build --rm -t radius-server ."
$start 2>/dev/null || $run 2>/dev/null || ($build && $run)
