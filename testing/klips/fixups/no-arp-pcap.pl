#!/usr/bin/perl

while(<>) {
	next if(/^arp who-has/);
	next if(/^arp reply/);

	if(/(.* \> .*\.domain:  )(\d*)(\+ .*\? .*)/) {
	  $_=$1."SEQ#".$3;
	} elsif(/(.*\.domain \> .*:  )(\d*)(\* .*)/) {
	  $_=$1."SEQ#".$3;
	}
	print;
}


