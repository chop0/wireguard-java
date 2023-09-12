#!/bin/bash

/app/run.sh /wireguard.conf&
JAVA_PID=$!

# wait for tun0 to be created (check by doing ip addr show dev tun0 and checking the exit code) or for the java process to die
while ! ip addr show dev tun0 > /dev/null 2>&1 && kill -0 $JAVA_PID; do
	sleep 0.1
done

# if the java process died, exit
if ! kill -0 $JAVA_PID; then
	exit 1
fi

OLD_GW=$(ip route show | grep default | cut -d' ' -f 3)
ip link set dev tun0 up
ip route delete default
ip route add 0.0.0.0/0 dev tun0
ip route add ${OLD_GW}/32 dev eth0
echo "Routing all traffic through tun0"

wait $JAVA_PID
