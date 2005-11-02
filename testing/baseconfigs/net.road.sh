#
# $Id: net.road.sh,v 1.3 2003/11/28 19:32:05 mcr Exp $
#
if [ -n "$UML_northpublic_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:ab:cd:02,unix,$UML_northpublic_CTL,$UML_northpublic_DATA";
else
    net_eth0="eth0=mcast,10:00:00:96:96:A1,239.192.3.2,31205"
fi

net="$net_eth0"

