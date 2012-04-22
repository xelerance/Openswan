#!/usr/bin/perl

$LIBRESWANSRCDIR=$ENV{'LIBRESWANSRCDIR'};

if ( ! -f "${LIBRESWANSRCDIR}/Makefile.ver" ) {
  print STDERR "NUKEversion.pl can not determine version number, \n";
  print STDERR "\t${LIBRESWANSRCDIR}/Makefile.ver can not be found\n";
  print STDERR "Perhaps LIBRESWANSRCDIR=$LIBRESWANSRCDIR is wrong?\n";
  exit 1;
}

open(VERSION, "${LIBRESWANSRCDIR}/Makefile.ver") ||
  die "Can not open ${LIBRESWANSRCDIR}/Makefile.ver\n";

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
  die "nukeversion.pl: Makefile.ver did not have version string defined!\nPerhaps LIBRESWANSRCDIR=$LIBRESWANSRCDIR is wrong?\n";
}

# now process the file looking for the version string.
while(<>) {
  s/$version/VERSION/g;
  print;
}


