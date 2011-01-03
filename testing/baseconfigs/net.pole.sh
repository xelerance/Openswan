#
# $Id: net.pole.sh,v 1.1 2003/11/27 19:26:25 mcr Exp $
#
if [ -n "$UML_north_CTL" ]
then
    net_eth0="eth0=daemon,12:00:00:de:cd:01,unix,$UML_east_CTL,$UML_east_DATA";
else
    net_eth0="eth0=mcast,12:00:00:de:cd:49,239.192.0.3,40810";
fi

net="$net_eth0"



