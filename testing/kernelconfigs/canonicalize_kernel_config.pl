#!/usr/bin/perl

# this script goes into $POOLSPACE/{plain,swan}{,26} and looks for the .config
# file that is there. It canonicalizes the file using "sort", and adds any
# missing items to uml{plain,swan}{,26}.config.
#
# Actually, it just cats the new file and the old file, turning all comments
# like '# FOO is not set' into "FOO=n" and uses sort -u on the result.
#

$oldconfig=$ARGV[0];
$newconfig=$ARGV[1];

open(OLD, "$oldconfig") || die "can not open old: $oldconfig: $!\n";

# read in old configuration.
while(<OLD>) {
  chop;
  if(/\# (CONFIG.*) is not set/) {
    $kerneloptions{$1}='n';
    next;
  }
  if(/(CONFIG.*)=([ynm])/) {
    $kerneloptions{$1}=$2;
    next;
  }
  if(/(CONFIG.*)=(.*)/) {
    $kerneloptions{$1}="value";
    $kernelvalue{$1}=$2;
    next;
  }
}
close(OLD);

open(NEW, "$newconfig") || die "can not open new: $newconfig: $!\n";
while(<NEW>) {
  chop;

  #print "processing $_\n";
  if(/\# (CONFIG.*) is not set/ ||
     /(CONFIG.*)=n/) {
    $kerneloptions{$1}='N';
    next;
  }

  #print "2 processing $_\n";
  if(/(CONFIG.*)=y/) {
    $kerneloptions{$1}='Y';
    next;
  }
  #print "3 processing $_\n";
  if(/(CONFIG.*)=m/) {
    $kerneloptions{$1}='M';
    next;
  }
  #print "4 processing $_\n";
}
close(NEW);

foreach $key (sort keys %kerneloptions) {
  if($kerneloptions{$key} eq 'N') {
    print "# $key is not set\n";
  }
  if($kerneloptions{$key} eq 'Y') {
    print "$key=y\n";
  }
  if($kerneloptions{$key} eq 'M') {
    print "$key=m\n";
  }
  if($kerneloptions{$key} eq 'value') {
    print "$key=".$kernelvalue{$key}."\n";
  }
}

print "# what follows are compatibility options with older kernels\n";
foreach $key (sort keys %kerneloptions) {
  if($kerneloptions{$key} eq 'n') {
    print "# $key is not set\n";
  }
  if($kerneloptions{$key} eq 'y') {
    print "$key=y\n";
  }
  if($kerneloptions{$key} eq 'm') {
    print "$key=m\n";
  }
}
