FROM wireguard-java

COPY ./server.conf /wireguard.conf
COPY ./server-entrypoint.sh /server-entrypoint.sh

ENTRYPOINT "/server-entrypoint.sh"
