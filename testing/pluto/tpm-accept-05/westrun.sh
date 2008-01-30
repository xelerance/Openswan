ipsec auto --replace west--east-psk
ipsec auto --up west--east-psk
: ==== cut ====
ipsec whack --status
sleep 20
sleep 20
ipsec whack --status
sleep 20
sleep 20
ipsec whack --status
sleep 20
sleep 20
ipsec whack --status
: ==== tuc ====

