#!/usr/bin/perl

#
# this program processes a bunch of directories routed at
# $REGRESSRESULTS. Each one is examined for a file "status"
# the result is an HTML table with the directory name as
# left columns (it is the implied test name), and the status
# on the right.
#
# if the test status is negative, then the results are a hotlink
# to that directory's output.
#
# The test names are links to the file "description.txt" if it
# exists.
#

require 'ctime.pl';

# colours are RRGGBB
$failedcolour="#990000";  # RED
$succeedcolour="#009900"; # GREEN
$missingcolour="#000099"; # BLUE
$unexpectedcolour="#009999"; # YELLOW
$expectedcolour="#007700"; # dark green
$roguecolour="#999900";    # purple?

$fastrate=20;    # when test are running, how often to refresh
$slowrate=300;   # when tests are not running, how often to refresh.
$maxpieceperpage=20;

$failed=0;
$passed=0;
$missed=0;
$total=0;
$skipped=0;

#$gnatsurl="http://gnats.freeswan.org/bugs/gnatsweb.pl?database=freeswan&amp;cmd=view+audit-trail&amp;pr=";
$gnatsurl=undef;

@faillist=();

sub printit {
  print HTMLFILE @_;
  print HTMLPART @_;
}

sub htmlize_test {
  local($testname)=@_;

  my($expected, $verdict, $packetstat, $consolestat, $file);

  &openpiecefile;

  &printit("<TR><TD>");

  if(-f "$testname/description.txt") {
    &printit("<A HREF=\"$testname/description.txt\">$testname</A>");
  } else {
    &printit("$testname");
  }

  &printit("</TD>");

  if($testname eq $runningtest) {
      $verdict="<BLINK>**RUNNING**</BLINK>";
      &printit("<TD>$verdict</TD></TR>");
      return;
  }

  if(-f "$testname/expected" &&
     open(EXPECTED, "$testname/expected")) {
    chop($expected=<EXPECTED>);
    close(EXPECTED);
  }

  $old ="";
  if(-M "$testname/status" > -M "datestamp") {
      $old = "(old) ";
  }

  if(open(STATUS,"$testname/status")) {
    $total++;
    # First line specifies $result and maybe $story.
    # New form has both, with a colon.
    chomp($result=<STATUS>);
    $story=$result;
    if ($result =~ /([^:]*): (.*)/) {
      $result=$1;
      $story=$2;
    }
    if($result =~ /^(yes|true|1|succeed|passed)$/i) {
      $verdict="$old<FONT COLOR=\"$succeedcolour\">passed</FONT>";
      if(defined($expected) &&
         $expected ne 'good') {
	$verdict .= " <FONT COLOR=\"$unexpectedcolour\">unexpected</FONT>";
      }
      $passed++;

    } elsif($result =~ /^missing$/i) {
      $verdict="$old<FONT COLOR=\"$missingcolour\">missing</FONT>";
      if(defined($expected) &&
         $expected ne 'missing' &&
	 $expected ne 'incomplete') {
	$verdict .= " <FONT COLOR=\"$unexpectedcolour\">AWOL</FONT>";
      }
      $missed++;

    } elsif($result =~ /^skipped$/i) {
      $verdict="$old<FONT COLOR=\"$missingcolour\">skipped</FONT>";
      if(defined($expected) &&
        $expected ne 'missing') {
	$verdict .= " <FONT COLOR=\"$unexpectedcolour\">AWOL</FONT>";
      }
      $skipped++;
    } else {
      $verdict = "${old}FAILED";
      if(!defined($expected) ||
         $expected eq 'good') {
	$verdict=$old."<FONT COLOR=\"$failedcolour\">FAILED {$story}</FONT>";
      }
      if($expected eq 'missing' ||
	$expected eq 'incomplete') {
	$verdict=$old."<FONT COLOR=\"$unexpectedcolour\">FAILED</FONT>";
      }
      if($expected eq 'bad') {
	$verdict=$old."<FONT COLOR=\"$expectedcolour\">FAILED</FONT> (expected)";
      }

      if(-d "$testname/OUTPUT") {
	$output="$testname/OUTPUT";
	$verdict="<A HREF=\"$output\">$verdict</A>";
      }

      my($roguecount);
      $roguecount=0;

      if(open(ROGUE,"$testname/roguelist.txt")) {
	while(<ROGUE>) {
	  $roguecount++;
	}
	close(ROGUE);

	$verdict .=" <FONT COLOR=\"$roguecolour\">ROGUE($roguecount)</A>";
      }

      $packetstat=1;
      $consolestat=1;
      while(<STATUS>) {
	if(/^packet=false/) {
	  $packetstat=0;
	}
	if(/^console=false/) {
	  $consolestat=0;
	}
      }

      if(-d "$testname/OUTPUT") {
	opendir(DIFFS,"$output") || die "diffs opendir $REGRESSRESULTS/$output: $!\n";
	@diffs=readdir(DIFFS);
	closedir(DIFFS);

	foreach $file (@diffs) {
	  print STDERR "checking out $file\n" if $debug;
	  if($file =~ /(.*)console.diff$/) {
	    $type=$1;
	    print STDERR "found the $file\n" if $debug;

	    # see if the file has any content. Skip zero contents
	    if(open(DIFFFILE, "$output/$file")) {
	      $foo=<DIFFFILE>;
	      if(length($foo) > 0) {
		if($type =~ /.*east.*/) {
		  $type=":east";
		} elsif($type =~ /.*west.*/) {
		  $type=":west";
		} else {
		  $type="";
		}
		while (<DIFFFILE>) {
		  if (/^. I.m tracing myself and I can't get out/) {
		    $type .= ":self-tracing";
		    last;
		  }
		}
		$verdict .= " <A HREF=\"$output/$file\">cons${type}</A>";
	      }
	      close(DIFFFILE);
	    }
	  } elsif($file =~ /(.*).diff$/) {
	    $type=$1;
	    print STDERR "found the $file\n" if $debug;

	    # see if the file has any content. Skip zero contents
	    if(open(DIFFFILE, "$output/$file")) {
	      $foo=<DIFFFILE>;
	      if(length($foo) > 0) {
		if($type =~ /.*public.*/) {
		  $type=":pub";
		} elsif($type =~ /.*private.*/) {
		  $type=":priv";
		} elsif($type =~ /.*east.*/) {
		  $type=":east";
		} elsif($type =~ /.*west.*/) {
		  $type=":west";
		} else {
		  $type="";
		}
		$verdict .= " <A HREF=\"$output/$file\">pkt${type}</A>";
		#$verdict .= " <A HREF=\"$output/$file\">packet</A>";
	      }
	    }
	    close(DIFFFILE);
	  }
	}
      }
      push(@faillist, $testname);
      $failed++;
    }
    close(STATUS);
  } else {
    $verdict="<FONT COLOR=\"$missingcolour\">missing</FONT>";
    if(-d "$testname/OUTPUT") {
      $output="$testname/OUTPUT";
      $verdict="<A HREF=\"$output\">$verdict</A>";
    }
    $missed++;
  }

  &printit("<TD>$verdict</TD>");

  if(-f "$testname/regress.txt") {
    open(PROBREPORT, "$testname/regress.txt") || die "$testname/regress.txt: $!\n";
    chop($prnum=<PROBREPORT>);
    close(PROBREPORT);

    if($prnum > 0 && defined($gnatsurl)) {
	    &printit("<TD><A HREF=\"$gnatsurl$prnum\">PR#$prnum</A></TD>");
    }

  } elsif(-f "$testname/goal.txt") {
    open(GOALREQ, "$testname/goal.txt") || die "$testname/regress.txt: $!\n";
    chop($goalnum=<GOALREQ>);
    close(GOALREQ);

    $goalnum=sprintf("%03d", $goalnum);
    #&printit("<TD><A HREF=\"http://www.freeswan.org/freeswan_snaps/CURRENT-SNAP/klips/doc/klipsNGreq/requirements/$goalnum\">Requirement $goalnum</A></TD>";

  } elsif(-f "$testname/exploit.txt") {
    open(EXPLOIT, "$testname/exploit.txt") || die "$testname/exploit.txt: $!\n";
    chop($url=<EXPLOIT>);
    close(EXPLOIT);

  } else {
    # test not categorized, output nothing.
  }

  &printit("</TR>\n");
}

# the test names are sorted.

$REGRESSRESULTS=$ENV{'REGRESSRESULTS'};

if(defined($ARGV[0])) {
  $REGRESSRESULTS=$ARGV[0];
}

if(defined($ARGV[1]) && $ARGV[1] ne "notest") {
  $runningtest=$ARGV[1];
}

if( ! -d $REGRESSRESULTS ) {
  die "No such directory $REGRESSRESULTS.";
}

chdir($REGRESSRESULTS) || die "Can not chdir to $REGRESSRESULTS: $!\n";

opendir(TESTS,".") || die "opendir $REGRESSRESULTS: $!\n";
@tests=readdir(TESTS);
closedir(TESTS);

if(defined($runningtest)) {
	if(!grep /${runningtest}/, @tests) {
		#print "Adding running test: $runningtest\n";
		push(@tests, "${runningtest}");
	}
}

@testnames=sort @tests;

if($wanttestcategories) {
  #
  # make pass through the tests, categorizing them.
  #
  @regresstests=();
  @goaltests=();
  @exploittests=();
  foreach $testname (@testnames) {
    if(-f "$testname/regress.txt") {
      push(@regresstests,$testname);
    } elsif(-f "$testname/goal.txt") {
      push(@goaltests, $testname);
    } elsif(-f "$testname/exploit.txt") {
      push(@exploittests, $testname);
    } else {
      push(@regresstests,$testname);
    }
  }
}


if(open(DATE, "datestamp")) {
  chop($timestamp=<DATE>);
  close(DATE);
  $runtime=&ctime($timestamp);
} else {
  $runtime="an unknown time";
}
$hostname=`uname -n`;

open(HTMLFILE, ">testresults.html") || die "Can not open testresults.html: $!\n";

$piece = 1;
$piececount=0;

sub openpiecefile {
  if($piececount == 0) {
    $file = sprintf("testresult%02d.html", $piece);

    print HTMLPART "</TABLE>  \n";
    print HTMLPART "\n<BR><PRE>TOTAL tests: $total SKIPPED: $skipped   PASSED: $passed   FAILED: $failed   MISSED: $missed SKIPPED: $skipped SUCCESS RATE: $testrate%</PRE><BR>\n";
    print HTMLPART "<A HREF=\"$file\">next page</A><BR>\n";
    print HTMLPART "<A HREF=\"stdout.txt\">stdout</A><BR>\n";
    print HTMLPART "<A HREF=\"stderr.txt\">stderr</A><BR>\n";
    print HTMLPART "</BODY></HTML>\n";
    close(HTMLPART);

    open(HTMLPART, ">$file") || die "Can not open $file: $!\n";

    print HTMLPART "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n";
    print HTMLPART "<HTML>  <HEAD>\n";
    print HTMLPART "<META http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n";

    if(defined($runningtest)) {
      print HTMLPART "<META http-equiv=\"Refresh\" content=\"$fastrate,$file\">\n";
    } else {
      print HTMLPART "<META http-equiv=\"Refresh\" content=\"$slowrate,$file\">\n";
    }

    print HTMLPART "<TITLE>Openswan nightly testing results for $runtime</TITLE>\n";
    print HTMLPART "</HEAD>  <BODY>\n";
    print HTMLPART "<H1>Openswan nightly testing results for $runtime on $hostname</H1>\n";

    if(defined($runningtest)) {
      print HTMLPART "Currently running $runningtest<P>\n";
    }


    print HTMLPART "<TABLE border>\n";
    print HTMLPART "<TD>";

    print HTMLPART "<TR><TH COLSPAN=3>Regression tests</TH></TR>\n";
    print HTMLPART "<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n";
    $piece++;
    $piececount=$maxpieceperpage;
  }
  $piececount--;
}

&printit("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n");
&printit("<HTML>  <HEAD>\n");
&printit("<META http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n");

if(defined($runningtest)) {
  &printit("<META http-equiv=\"Refresh\" content=\"$fastrate,testresults.html\">\n");
} else {
  &printit("<META http-equiv=\"Refresh\" content=\"$slowrate,testresults.html\">\n");
}

&printit("<TITLE>Openswan nightly testing results for $runtime</TITLE>\n");
&printit("</HEAD>  <BODY>\n");
&printit("<H1>Openswan nightly testing results for $runtime on $hostname</H1>\n");

if(defined($runningtest)) {
  &printit("Currently running $runningtest<P>\n");
}


&printit("<TABLE border>\n");
&printit("<TD>");

$testtypename="Regression";
&printit("<TR><TH COLSPAN=3>Regression tests</TH></TR>\n");
&printit("<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n");
$linecount=3;

if($wanttestcategories) {
  foreach $testname (@regresstests) {
    next if($testname =~ /^\./);
    next unless(-d $testname || $testname eq $runningtest);

    &htmlize_test($testname);
  }

  $testtypename="Goal";
  &printit("<TR><TH COLSPAN=3>Goal tests</TH></TR>\n");
  &printit("<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n");
  $linecount+=3;

  foreach $testname (@goaltests) {
    next if($testname =~ /^\./);
    next unless(-d $testname || $testname eq $runningtest);

    &htmlize_test($testname);
  }

  $testtypename="Exploit ";
  &printit("<TR><TH COLSPAN=3>Exploit tests</TH></TR>\n");
  &printit("<TR><TH>Test name</TH><TH>Result</TH><TH>Detail</TH></TR>\n");
  $linecount+=3;

  foreach $testname (@exploittests) {
    next if($testname =~ /^\./);
    next unless(-d $testname || $testname eq $runningtest);

    &htmlize_test($testname);
  }
} else {
  foreach $testname (@testnames) {
    next if($testname =~ /^\./);
    next unless(-d $testname || $testname eq $runningtest);

    &htmlize_test($testname);
  }
}



$subtotal = $passed + $failed;
$skipped = $total - $subtotal;

if($subtotal > 0) {
  $testrate=sprintf("%2.1d",(($passed*100)/$subtotal));
} else {
  $testrate="inf";
}

&printit("</TABLE>  \n");
&printit("\n<BR><PRE>TOTAL tests: $total SKIPPED: $skipped   PASSED: $passed   FAILED: $failed   MISSED: $missed  SUCCESS RATE: $testrate%</PRE><BR>\n");
&printit("<A HREF=\"stdout.txt\">stdout</A><BR>\n");
&printit("<A HREF=\"stderr.txt\">stderr</A><BR>\n");
&printit("</BODY></HTML>\n");
close(HTMLFILE);

if(!defined($runningtest)) {
  open(FAILLIST, ">faillist.txt") || die "failed to write to faillist.txt: $!\n";
  print FAILLIST join('
		      ', @faillist)."\n";
  close(FAILLIST);

  open(STATS, ">stats.txt") || die "failed to write to stats.txt: $!\n";
  print STATS "$timestamp $total $passed $failed $missed $skipped\n";
  close(STATS);
}



