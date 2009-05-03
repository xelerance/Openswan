ipsec auto --up  westnet-eastnet-xp-emulation
ipsec look
sleep 30
# phase1 should be gone now
ipsec look
ipsec auto --down  westnet-eastnet-xp-emulation
ipsec look
ipsec auto --up  westnet-eastnet-xp-emulation
ipsec look
echo done
