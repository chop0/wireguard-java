#!/bin/bash
java \
	-server --enable-preview \
	-p . -Djava.library.path=. \
	-XX:CompileThreshold=1500 \
	--add-opens java.base/com.sun.crypto.provider=ax.xz.wireguard.noise \
	$* \
	-cp /app:/usr/share/java/logback-core-1.4.9.jar:/usr/share/java/logback-classic-1.4.9.jar:/usr/share/java/slf4j-jdk-platform-logging-2.0.9.jar:/usr/share/java/slf4j-api-2.0.9.jar \
	-m ax.xz.wireguard/ax.xz.wireguard.cli.WireguardTunnelCLI "/wireguard.conf"
