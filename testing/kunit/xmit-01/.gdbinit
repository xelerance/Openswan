define iskbdump
print ixs->skb
print "data"
x/32b ixs->skb->data
print "h.raw"
x/32b ixs->skb->h.raw
print "nh.raw"
x/32b ixs->skb->nh.raw
end

