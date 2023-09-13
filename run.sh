#!/bin/bash
java \
	-server --enable-preview \
	-p . -Djava.library.path=. \
	-XX:CompileThreshold=1500 \
	"$@" \
	-m ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI "/wireguard.conf"
