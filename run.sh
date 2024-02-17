#!/bin/bash

java \
	-server --enable-preview \
	-p . \
	-XX:CompileThreshold=1500 \
	--add-opens java.base/java.io=ax.xz.raw\
	"$@" \
	-m ax.xz.wireguard.cli/ax.xz.wireguard.cli.WireguardTunnelCLI "/wireguard.conf"&
CHILD=$!

_term() {
  kill -TERM "$child" 2>/dev/null
}

trap _term SIGTERM

mkdir -p /etc/wireguard
inotifywait -e create -r /etc/wireguard

echo "Setting up routing rules"
OLD_GW=$(ip route show | grep default | cut -d' ' -f 3)

ip link set dev tun0 up
ip route delete default
ip route add default dev tun0
ip route add ${OLD_GW}/32 dev eth0
ip route add 162.159.192.1/32 via ${OLD_GW} dev eth0

ip -6 route add default dev tun0

wait "$CHILD"
