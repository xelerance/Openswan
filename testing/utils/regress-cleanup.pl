#!/usr/bin/perl

# This script is used to clean up the /btmp dir of previous nights runs.
# It expects the following things to be in the environment:
#
#    $BTMP
#    $USER
#    $BRANCH
#    $TODAY

if(!defined($ENV{'BTMP'})   || length($ENV{'BTMP'})==0 ||
   !defined($ENV{'USER'})   || length($ENV{'USER'})==0 ||
   !defined($ENV{'BRANCH'}) || length($ENV{'BRANCH'})==0 ||
   !defined($ENV{'TODAY'})  || length($ENV{'TODAY'})==0 )
  {
    print STDERR "You must define \$BTMP, \$USER, \$BRANCH and \$TODAY for the cleanup to function."; 
    print STDERR "Values are: BTMP=\"".$ENV{'BTMP'}."\"\n";
    print STDERR "\tUSER=\"".$ENV{'USER'}."\"\n";
    print STDERR "\tBRANCH=\"".$ENV{'BRANCH'}."\"\n";
    print STDERR "\tTODAY=\"".$ENV{'TODAY'}."\"\n";
    die "Thank you.";
  }

$BTMP=$ENV{'BTMP'};
$USER=$ENV{'USER'};
$BRANCH=$ENV{'BRANCH'};
$TODAY=$ENV{'TODAY'};

# we need to make all of the directories candidates, otherwise, we get into trouble
# if we are building multiple branches - one may consume all the space, leaving 
# the others screwed.
$cleandir="$BTMP/$USER";

# by default we'd like to have 700Mb to play with. UMLs take lots of space, alas.
$desiredspace=700*1024*1024;

# but, if there is a file in $cleandir called "free", then we take that as
# being the amount to keep free. It would make more sense to put a maximum
# usage instead, but that requires that we walk the file system multiple times.

if(-f "$cleandir/free") {
  $success = open(FREE, "$cleandir/free");
  if($success) {
    chop($desiredspace=<FREE>);
    close(FREE);
  } else {
    warn "Can not open $cleandir/free: $!\n";
  }
}

print "Trying to make sure that at least ".($desiredspace/1024)."KB is free in $cleandir\n";


sub getdiskspace {
# bash-2.05$ df -P /btmp
# Filesystem         1024-blocks      Used Available Capacity Mounted on
# /dev/hda7             33855264   2954140  29181368      10% /abigail
#

  open(DF, "df -P $cleandir |") || die "Can not invoke df: $!\n";
  $header=<DF>;
  $_=<DF>;
  ($filesystem, $blocks, $used, $avail, $percent, $mount)=split;
  return $avail*1024;
}

sub cmpdir {
  # $a and $b contain things to compare.

  local($abase, $bbase);
  ($abase = $a) =~ s,([^/]*/)(.*),\2,;
  ($bbase = $b) =~ s,([^/]*/)(.*),\2,;
  local($ay,$am,$ad) = split(/_/, $abase, 3);
  local($by,$bm,$bd) = split(/_/, $bbase, 3);

  #print STDERR "cmddir A: $a ($ay $am $ad)  B: $b ($by $bm $bd)\n";

  if($ay != $by) {
    return $ay <=> $by;
  } elsif ($am != $bm) {
    return $am <=> $bm;
  } elsif ($ad != $bm) {
    return $ad <=> $bd;
  } else {
    return 0;
  }
}

chdir($cleandir) || die "Can not chdir to $cleandir\n";

opendir(TOPDIR, $cleandir) || die "can not opendir($cleandir): $!\n";
@topdirs=readdir(TOPDIR);
closedir(TOPDIR);

@candiatedirs=();

# recurse on each top level thing that is a directory.
# filter it looking for date format dirs, excepting $TODAY.
foreach $b (@topdirs) {
  if( -d "$cleandir/$b" ) {
    opendir(BRANCHDIR,"$cleandir/$b") || die "can not opendir($cleandir/$b): $!\n";
    @d=readdir(BRANCHDIR);
    close(BRANCHDIR);

    #print "Considering directory: $b/$d vs $TODAY\n";
    for $d (@d) {
      if(($d =~ m,\d\d\d\d\_\d\d\_\d\d,) &&
	 ($d ne $TODAY)) {
	push(@candidatedirs, "$b/$d");
      }
    }
  }
}

# sort them.
@candidatedirs = sort cmpdir @candidatedirs;

print "Candidates: ",join(",", @candidatedirs),"\n";

while($#candidatedirs > 0 &&
      &getdiskspace < $desiredspace) {

  $dir=pop(@candidatedirs);

  print "Removing $cleandir/$dir\n";
  system("rm -rf $cleandir/$dir");
}

if(&getdiskspace < $desiredspace) {
  print STDERR "Failed to free enough disk space\n";
  exit 1;
}

print "Found ".&getdiskspace." free, continuing.\n";

exit 0;  

# $Id: regress-cleanup.pl,v 1.6 2003/01/24 16:18:40 build Exp $
#
# $Log: regress-cleanup.pl,v $
# Revision 1.6  2003/01/24 16:18:40  build
# 	remove directories by explicit path names.
# 	added log of candidate directories
#
# Revision 1.5  2003/01/17 16:54:02  mcr
# 	fixed regress-cleanup.pl so that it attempts to free space
# 	in $BTMP/$USER rather than $BTMP/$USER/$BRANCH.
#
# Revision 1.4  2002/12/06 02:20:04  mcr
# 	once we get enough space, report that fact.
#
# Revision 1.3  2002/04/17 13:18:16  mcr
#   make script live (uncomment rm), add some debugging, fix string comparison and process directories in forward fashion
#
# Revision 1.2  2002/01/11 20:43:02  mcr
# 	perl uses "elsif" - if was missing completely.
#
# Revision 1.1  2002/01/11 04:26:48  mcr
# 	revision 1 of nightly regress scripts.
#
#
