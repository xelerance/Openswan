# zero log files
echo >/var/log/auth.log

# start syslogd
syslogd

# start up the system
ipsec setup start


