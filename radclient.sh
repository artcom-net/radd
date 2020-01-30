#!/bin/bash

echo "User-Name=vasya,
      User-Password=12345,
      Session-Timeout=3600,
      Framed-IP-Address=10.0.0.1,
      Calling-Station-Id=00:00:00:00:00:01,
      NAS-IP-Address=127.0.0.1,
      Agent-Remote-Id=060504030201,
      Agent-Circuit-Id=1,
      Cisco-AVPair='remote-id=060504030201',
      Cisco-AVPair='circuit-id=00001'" | radclient -x 127.0.0.1 auth secret