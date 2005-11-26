#!/usr/bin/perl

# Takes a file as standard input, and emits a random order 
# for the file. Argument says how many lines to actually emit.

$howmany=shift;
if($howmany < 1) {
  $howmany=1;
}

@lines=();

$count=1;

while(<>) {
  $lines[$count++]=$_;
}

# init random seed.
srand(time|$$);

while($howmany-- > 0) {
  $which=int(rand($count))+1;

  print $lines[$which];
}



