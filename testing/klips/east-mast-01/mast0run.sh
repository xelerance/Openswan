#tcpdump -i eth1 -n -p &

hping2 -a 192.0.2.254 -c 2 --udp -d 64 -e 'mast0' 192.0.1.254

: ==== end ====
