#!/usr/bin/perl

$inpacket=0;
$firstpacket=1;

sub extractlastcipherblock {
  my(@bytes_last_two, @bytes_last_three, @bytes, $len, @iv);

#  print "LAST2: $lastPacketLine2";
#  print "LAST3: $lastPacketLine3";
  @bytes_last_two   = split(/\s+/,$lastPacketLine2);
  @bytes_last_three = split(/\s+/,$lastPacketLine3);
  
  # get rid of offset
  shift @bytes_last_two;
  shift @bytes_last_three;

  # get rid of text at right
  pop @bytes_last_two;
  pop @bytes_last_three;

  @bytes = (@bytes_last_three, @bytes_last_two);
  
  # now skip the last 12 bytes as the AUTH MAC.
  # sizes halved because bytes are presented as 16-items
  $len = $#bytes;
#  print "EXTRACT: ".($len-9)."-".($len-6)." of ",join('|',@bytes)."\n";
  @cbcbytes = @bytes[($len-9)..($len-6)];
  
  $cbc = join('',@cbcbytes);
  $myiv= $first4IV.$last4IV;
  
#  print "MyIV: ".$myiv." LastCBC: $cbc\n";

  if($myiv eq $cbc) {
    print $packetHead." IV PREDICTED\n";
  } else {
    print $packetHead." IV PROBABLY RANDOM\n";
  }
}

while(<>) {
  $lastthree = $lasttwo;
  $lasttwo   = $last;
  $last      = $_;

  if(/^\d*\.\d*\.\d*\.\d* \> \d*\.\d*\.\d*\.\d*\: ESP/) {
    $packetnum++;

    # save the lines of the previous packet
    $lastPacketLine2 = $lasttwo;
    $lastPacketLine3 = $lastthree;
    $packetHead = $_;
    chop($packetHead);

#    print "PACKET: $_";

    next;
  }

  if(/^0x0000/) {
    $inpacket=1;
    next;
  }
  
  if(/^0x0010/) {
#    print " FIRST: $_";
    @bytes=split(/\s+/,$_);
    $first4IV = $bytes[7].$bytes[8];
    next;
  }

  if(/^0x0020/) { 
#    print "SECOND: $_";
    @bytes=split(/\s+/,$_);
    $last4IV = $bytes[1].$bytes[2];

    if($packetnum > 1) {
      &extractlastcipherblock;
    }
    next;
  }
}
