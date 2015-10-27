#!/usr/bin/perl

# this script converts a line like:

# Apr 15 13:26:24 parker pluto[4118]: !   87 5a 1b 5e  b4 7f 40 bd  2b 4d 38 79  06 71 25 ca
# into:
# 0x87,

while(<>) {
    # only process lines with ! in them
    next unless /\!/;
    s/^.*\!//;
    @bytes = split;
    print "";
    foreach $byte (@bytes) {
        printf " 0x%s,", $byte;
    }
    print "\n";
}



