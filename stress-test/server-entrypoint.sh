#!/bin/bash

/app/run.sh /wireguard.conf&
JAVA_PID=$!

OLD_GW=$(ip route show | grep default | cut -d' ' -f 3)
ip route delete default
ip route add 0.0.0.0/0 dev tun0
ip route add ${OLD_GW}/32 dev eth0
