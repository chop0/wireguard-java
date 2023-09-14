#!/bin/bash
java \
	-server --enable-preview \
	-p . -Djava.library.path=. \
	-XX:CompileThreshold=1500 \
	--add-opens java.base/com.sun.crypto.provider=ax.xz.wireguard.noise \
	"$@" \
	-m ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI "/wireguard.conf"
