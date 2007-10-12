#!/usr/bin/perl

while(<>) {
	s/\.isakmp/.500/g;

	next if(/^arp who-has/);
	next if(/^arp reply/);
        next if(/^ARP, Request/);

	if (/\.domain\s/) {
	  next;
	}
	if (/\.53\s/) {
	  next;
	}

	print;
}

