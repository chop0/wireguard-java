FROM wireguard-java

COPY ./server.conf /wireguard.conf
COPY ./server-routing-config.sh /server-routing-config.sh

ENTRYPOINT ["/bin/bash", "-c", "/server-routing-config.sh && /app/run.sh /wireguard.conf"]
