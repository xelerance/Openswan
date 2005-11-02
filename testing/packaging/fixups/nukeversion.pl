#!/usr/bin/perl

$FREESWANSRCDIR=$ENV{'FREESWANSRCDIR'};

if ( ! -f "${FREESWANSRCDIR}/Makefile.ver" ) {
  print STDERR "NUKEversion.pl can not determine version number, \n";
  print STDERR "\t${FREESWANSRCDIR}/Makefile.ver can not be found\n";
  print STDERR "Perhaps FREESWANSRCDIR=$FREESWANSRCDIR is wrong?\n";
  exit 1;
}

open(VERSION, "${FREESWANSRCDIR}/Makefile.ver") ||
  die "Can not open ${FREESWANSRCDIR}/Makefile.ver\n";

$version=undef;
while(<VERSION>) {
  next if /^\#/;
  if(/^IPSECVERSION=(.*)/) {
    $version=$1;
    last;
  }
}
close(VERSION);
if(!defined($version)) {
  die "nukeversion.pl: Makefile.ver did not have version string defined!\nPerhaps FREESWANSRCDIR=$FREESWANSRCDIR is wrong?\n";
}

# now process the file looking for the version string.
while(<>) {
  s/$version/VERSION/g;
  print;
}


