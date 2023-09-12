#!/bin/bash
java \
	-server --enable-preview \
	-p . -Djava.library.path=. \
	"$@" \
	-m ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI "/wireguard.conf"
