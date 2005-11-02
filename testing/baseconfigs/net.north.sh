#
# $Id: net.north.sh,v 1.2 2003/11/28 19:32:05 mcr Exp $
#

if [ -n "$UML_private_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:de:cd:49,unix,$UML_private_CTL,$UML_private_DATA";
else
    net_eth0="eth0=mcast,10:00:00:de:cd:49,239.192.0.3,40810";
fi

if [ -n "$UML_northpublic_CTL" ]
then
    net_eth1="eth1=daemon,10:00:00:96:96:49,unix,$UML_northpublic_CTL,$UML_northpublic_DATA";
else
    net_eth1="eth1=mcast,10:00:00:96:96:49,239.192.3.2,31205";
fi

net="$net_eth0 $net_eth1"



