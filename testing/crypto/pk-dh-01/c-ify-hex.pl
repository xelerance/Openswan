#!/usr/bin/perl

$end="";
$output=0;

while(<>) {
  chomp;
  s/^\|//;

  if(/^output:/) {
    $output=1;
    next;
  }
  next unless ($output);

  if(/(s\S*)/) {
    $val=$1;
    s/(s\S*)//;
    print "$end\n";
    print "unsigned char tc2_results_$val\[\]= {\n";
    $end="};\n";
  }

  ($a1,$a2,$a3,$a4,
   $b1,$b2,$b3,$b4,
   $c1,$c2,$c3,$c4,
   $d1,$d2,$d3,$d4) = split;

  printf "	0x%02x, 0x%02x, 0x%02x, 0x%02x,  ",
	 hex($a1), hex($a2), hex($a3), hex($a4);
  printf "0x%02x, 0x%02x, 0x%02x, 0x%02x,  ",
	 hex($b1), hex($b2), hex($b3), hex($b4);
  printf "\n	0x%02x, 0x%02x, 0x%02x, 0x%02x,  ",
	 hex($c1), hex($c2), hex($c3), hex($c4);
  printf "0x%02x, 0x%02x, 0x%02x, 0x%02x,  ",
	 hex($d1), hex($d2), hex($d3), hex($d4);
  printf "\n";
}

print "$end\n";

