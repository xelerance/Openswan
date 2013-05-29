#
# $Id: net.japan.sh,v 1.2 2002/06/18 19:10:31 mcr Exp $
#
if [ -n "$UML_west_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:ab:cd:02,unix,$UML_west_CTL,$UML_west_DATA";
elif [ -n "$UML_private_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:ab:cd:02,unix,$UML_private_CTL,$UML_private_DATA";
else
    net_eth0="eth0=mcast,10:00:00:ab:cd:02,239.192.0.2,40800"
fi

net="$net_eth0"

