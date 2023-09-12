#!/bin/bash
java -server -Djdk.system.logger.level=FINE --enable-preview -p . -Djava.library.path=. -m ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI $*
