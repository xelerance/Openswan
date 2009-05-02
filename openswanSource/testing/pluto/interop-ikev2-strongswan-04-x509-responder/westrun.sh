ipsec auto --up  west--east-ikev2
ping -c1 -I 192.0.1.254 192.0.2.254

ipsec look
echo done
