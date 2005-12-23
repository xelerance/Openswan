ipsec auto --replace west--east-psk
ipsec auto --up west--east-psk

ipsec auto --delete west--east-psk

echo done
