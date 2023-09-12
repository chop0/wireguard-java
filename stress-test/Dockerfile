FROM wireguard-java

RUN apt install -y iptables iperf3

EXPOSE 51820/udp
ENTRYPOINT ["/entrypoint_routing.sh"]
