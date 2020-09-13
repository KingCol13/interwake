#!/bin/bash
mkdir /usr/local/etc/rpiwol
cp mykey /usr/local/etc/rpiwol/mykey
mkdir /usr/local/lib/systemd
mkdir /usr/local/lib/systemd/system
cp rpiwol.service /usr/local/lib/systemd/system/rpiwol.service
echo "Now move server executable to /usr/local/sbin/rpiwol-daemon."

