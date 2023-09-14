#!/bin/bash

/app/run.sh "$@"&
JAVA_PID=$!

# wait for tun0 to be created (check by doing ip addr show dev tun0 and checking the exit code) or for the java process to die
while ! ip addr show dev tun0 > /dev/null 2>&1 && kill -0 $JAVA_PID; do
	sleep 0.1
done

handle_signal() {
  local signal=$1
  echo "Received signal: $signal"
  if [ -n "$JAVA_PID" ]; then
    echo "Forwarding signal: $signal to PID: $JAVA_PID"
    kill "-$signal" "$JAVA_PID"
  fi
}

# Specify the signals to trap and the handler function
trap 'handle_signal HUP' HUP
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'handle_signal QUIT' QUIT

# if the java process died, exit
if ! kill -0 $JAVA_PID; then
	exit 1
fi

OLD_GW=$(ip route show | grep default | cut -d' ' -f 3)
ip link set dev tun0 up
ip route delete default
ip route add 0.0.0.0/0 dev tun0
ip route add ${OLD_GW}/32 dev eth0
# route all traffic to iperf3 server through tun0
ip route add $(getent hosts iperf3-server | cut -d' ' -f 1)/32 dev tun0

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo "Routing all traffic through tun0"

wait $JAVA_PID
