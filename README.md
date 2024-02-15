# Java implementation of [wireguard](https://www.wireguard.com/)

ip route add 162.159.192.1 via 172.17.0.1 dev eth0 src 172.17.0.2; ip route delete default; ip route add default dev tun0

OLD_GW=$(ip route show | grep default | cut -d' ' -f 3)
ip link set dev tun0 up
ip route delete default
ip route add default dev tun0
ip route add ${OLD_GW}/32 dev eth0
ip route add 162.159.192.1/32 via ${OLD_GW} dev eth0