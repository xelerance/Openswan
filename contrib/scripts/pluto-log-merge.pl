#!/usr/bin/perl -w
# vim: set sw=4 et
use strict;
use Term::ReadKey;
use Date::Parse;
use POSIX qw(strftime);
use Data::Dumper;
use Scalar::Util qw(looks_like_number);
use List::Util qw(reduce);
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

my $show_debug=0;
my $show_events=0;
my $output_width=0;
my $sync_sides=0;
my $rdelta=0;

# argument parsing is a bit crude
while (defined $ARGV[0] && $ARGV[0] =~ m/^-[-a-z]/) {
    my $arg = shift @ARGV;

    if ($arg eq "-h" or $arg eq "--help") {
        my $me = $0;
        $me =~ s,.*/,,;
        print
            "$me [ options ] <left-log> <right-log>\n",
            "\n",
            "Options:\n",
            " -h --help             - show this help\n",
            " -D --debug            - show debug of parsed event data\n",
            " -E --events           - show events that don't lead to messages\n",
            " -w --width <char>     - set output width (default terminal width)\n",
            " -s --syncronize       - synchronize clocks by finding first exchange\n",
            "\n",
            "This program reads two log files output by OpenSWAN pluto daemon and converts them\n",
            "into a chronologically ordered packet diagram.\n",
            "\n",
            ;
            exit 0;

    } elsif ($arg eq "-E" or $arg eq "--events") {
        $show_events = 1;

    } elsif ($arg eq "-D" or $arg eq "--debug") {
        $show_debug = 1;

    } elsif ($arg eq "-w" or $arg eq "--width") {
        my $val = shift @ARGV;
        die "$arg needs a value; none given\n" if not defined $val;
        die "$arg needs a number; found '$val'" if not looks_like_number($val);
        die "$arg needs to be greater than 20; found '$val'" if $val < 20;
        $output_width = $val;

    } elsif ($arg eq "-s" or $arg eq "--sync" or $arg eq "--synchronize") {
        $sync_sides = 1;

    } else {
        die "don't know how to handle $arg";
    }
}

# log files to read...
my $left = shift @ARGV;
my $right = shift @ARGV;

die "need some files; see --help\n" if not defined $right;

die "$left: not a file\n" if not -e "$left";
die "$right not a file\n" if not -e "$right";

# figure out how wide to make things
if ($output_width < 20) {
    my ($wchar, $hchar, $wpixels, $hpixels) = GetTerminalSize();
    $output_width = $wchar;
}

# output left/center/right justified, depending on first parameter < = >
sub jprint {
    my ($justify, $txt) = @_;
    if ($justify eq '<') {
        printf("%-${output_width}s\n", $txt);

    } elsif ($justify eq '>') {
        printf("%${output_width}s\n", $txt);

    } elsif ($justify eq '=') {
        printf("%s%s\n",
            ' ' x int(($output_width - length $txt)/2),
            $txt);

    } else {
        printf("%s\n", $txt);
    }
}

# output distributed text accross the ${output_width} characters
sub dprint {
    my (@words) = @_;
    if ($#words < 1) {
        print @words,"\n";
        return;
    }
    my $ttl = reduce { $a + $b } map { length $_ } @words; # sum all words
    my $lft = $output_width - $ttl;     # how much space we will fill
    my $pad = 1.00 * $lft / $#words;    # average spaces between words
    $pad = 1 if $pad < 1;               # at least one space
    my @out;
    my $leftovers = 0;
    foreach my $w (@words) {
        if (not @out) {
            push @out, $w;              # first time just print the word
            next;                       # padding is prepended next time
        }
        my $tpad = $pad + $leftovers;   # how much to pad this word
        my $ipad = int($tpad);          # integer number of spaces
        $leftovers = $tpad - $ipad;     # keep left overs for next time
        push @out, ' ' x $ipad, $w;
    }
    print join('',@out),"\n";
}

sub create_file_reader {
    my ($filename, $tsdelta) = @_;

    die if not defined $filename;
    die if not defined $tsdelta;

    my $self = {
        filename => $filename,
        tsdelta => $tsdelta,
        line => 0,
    };
    

    open($self->{fh},"<",$filename) || die "$filename $!\n";

    $self->{read} = sub {
        my $fh = $self->{fh};

        READ_A_LINE:
        my $line = <$fh>;
        return if not defined $line;

        $self->{line} ++;
        chomp $line;

        # Mar 26 11:17:31 xel-ub-east pluto[9198]: Starting Pluto (Openswan Version 2.6.51dev4-50-g4fda874; Vendor ID OSWI_WX]dFqU) pid:9198
        if ($line =~ m/(^.*) (\d{2}:\d{2}:\d{2}) (\S+) (\S+)\[(\d+)\]: (.*)/) {
            return {
                full => $line,
                line => $self->{line},
                ts => str2time("$1 $2") + $self->{tsdelta},
                date => $1,
                time => $2,
                host => $3,
                proc => $4,
                pid => $5,
                text => $6,
            }
        }
        # 2019-02-06T18:09:00.292254+00:00 alice pluto[1868]: Starting Pluto (Openswan Version 2.6.51.2-65-gb22f20b; Vendor ID OSWgYooxnKAh) pid:1868
        elsif ($line =~ m/^(\d+-\d+-\d+)T(\d+:\d+:[0-9.]+)(Z|\+[0-9:]*) (\S+) (\S+)\[(\d+)\]: (.*)/) {
            return {
                full => $line,
                line => $self->{line},
                ts => str2time("$1 $2") + $self->{tsdelta},
                date => $1,
                time => $2,
                host => $4,
                proc => $5,
                pid => $6,
                text => $7,
            }
        }

        die "skip\n$line\n" if not $line =~ m/Starting Pluto subsystem/;

        goto READ_A_LINE;
    };

    return $self;
}

sub create_simple_event_reader {
    my ($filename) = @_;

    my $self = {};

    $self->{filename} = $filename;
    $self->{reader} = create_file_reader($filename, 0);

    $self->{next} = sub {
        while ( 1 ) {
            my $line = $self->{reader}->{read}();
            return if not defined $line;
            return if not $line;

            # {text} removes the syslog prefix
            my $txt = $line->{text};

            if ($txt =~ m/sending \d+ bytes for \S+ through \S+ to \S+ \(using #\d+\)/) {
                $line->{ev} = 'sending';
                return $line;
            }
            elsif ($txt =~ m/received \d+ bytes from \S+ on \S+ \(port=\d+\) at .*/) {
                $line->{ev} = 'received';
                return $line;
            }
        }
    };

    return $self;
}

sub find_rdelta {
    my ($L, $R) = @_;

    my $l = $L->{next}();
    my $r = $R->{next}();

    #print "L: $l->{ts} $l->{text}\n";
    #print "R: $r->{ts} $r->{text}\n";

    my $fudge = 0.003; # 3 milliseconds
    my $delta = ($l->{ts} - $r->{ts}) + $fudge;

    return $delta
}


my $ev_count = 0;
sub create_event_reader {
    my ($filename, $tsdelta) = @_;

    my $self = {};

    $self->{filename} = $filename;
    $self->{lines} = create_file_reader($filename, $tsdelta);
    $self->{queue} = [];

    sub complete_current_ev {
        my ($self, $line, $why_end) = @_;

        my $ev = $self->{ev};
        $self->{ev} = {};

        $ev->{why_end} = $why_end;
        $ev->{full} = $line->{full};
        $ev->{line} = $line->{line};
        $ev->{text} = $line->{text};
        $ev->{ts_end} = $line->{ts};
        $ev->{raw} = $line;

        $ev->{ts} = $ev->{ts_end};
        $ev->{ts} = ($self->{ev}->{ts_sending}  - 0.000) if defined $self->{ev}->{ts_sending};
        $ev->{ts} = ($self->{ev}->{ts_received} + 0.000) if defined $self->{ev}->{ts_received};

        push @{$self->{queue}}, $ev;
    }

    sub start_new_ev {
        my ($self, $line, $why_start) = @_;

        if ($show_debug) {
            my $ev = $self->{ev};
            my @keys = keys %{$ev};
            if (scalar @keys
                    && defined $self->{ev}->{why_start}
                    && $self->{ev}->{why_start} !~ m/^EVENT_PENDING_DDNS/
                ) {
                print 'LOST: ',Dumper($ev);
            }
        }

        $self->{ev} = { };
        $self->{ev}->{z_index} = $ev_count++;
        if (defined $why_start) {
            $self->{ev}->{why_start} = $why_start;
            $self->{ev}->{ts_start} = $line->{ts};
        }
    }

    sub maybe_update_start {
        my ($self, $line, $why_start) = @_;
        if (not defined $self->{ev}->{why_start}) {
            $self->{ev}->{why_start} = $why_start
        }
        if (not defined $self->{ev}->{ts_start}) {
            $self->{ev}->{ts_start} = $line->{ts}
        }
    }

    sub append_debug_line {
        my ($self, $line) = @_;
        return if not $show_debug;
        return if defined $line->{debugged_already};
        push @{$self->{ev}->{z_debug}}, sprintf(
            "%s %10u %s", $line->{time},$line->{line}, $line->{text});
        $line->{debugged_already} = 1;
    }

    sub short_payload_name {
        my ($txt) = @_;
        if ($txt eq 'ISAKMP Message') {
            return "ISAKMP";
        }
        elsif ($txt eq 'ISAKMP Vendor ID Payload') {
            return "VID";
        }
        elsif ($txt eq 'IKEv2 Identification Payload') {
            return "v2ID";
        }
        elsif ($txt eq 'IKEv2 Authentication Payload') {
            return "v2AUTH";
        }
        elsif ($txt eq 'IKEv2 Encryption Payload') {
            return "v2E";
        }
        elsif ($txt eq 'IKEv2 Key Exchange Payload') {
            return "v2KE";
        }
        elsif ($txt eq 'IKEv2 Delete Payload') {
            return "v2D";
        }
        elsif ($txt eq 'IKEv2 Security Association Payload') {
            return "v2SA";
        }
        elsif ($txt eq 'IKEv2 Nonce Payload') {
            return "v2Ni";
        }
        elsif ($txt eq 'IKEv2 Notify Payload') {
            return "v2N";
        }
        elsif ($txt eq 'IKEv2 Vendor ID Payload') {
            return "v2VID";
        }

        # these cause problems because the parsing and emitting are mixed

        #elsif ($txt eq 'IKEv2 Proposal Substructure Payload') {
        #    return "v2P";
        #}
        #elsif ($txt eq 'IKEv2 Transform Substructure Payload') {
        #    return "v2T";
        #}
        #elsif ($txt eq 'IKEv2 Attribute Substructure Payload') {
        #    return "v2ATTR";
        #}

        warn "UNHANDLED: $txt\n";
        return $txt
    };

    start_new_ev($self);

    $self->{next} = sub {
        while ( 1 ) {
            if (@{$self->{queue}}) {
                my $ev = shift @{$self->{queue}};
                return $ev;
            }

            my $line = $self->{lines}->{read}();
            return if not defined $line;
            return if not $line;

            # {text} removes the syslog prefix
            my $txt = $line->{text};
            chomp $txt;

            # rememember the SA number from the event count down
            if ($txt =~ m/next event (\S+) in \d seconds for #(\d+)/) {
                $self->{next_event_for_sa}->{$1} = $2;
            }

            my $unhandled;
            if ($txt =~ m/handling event (\S+)/) {
                my $name = $1;
                if (defined $self->{ev}->{why_start}) {
                    #append_debug_line($self, $line);
                    complete_current_ev($self, $line, 'interrupt');
                }
                my $sa = $self->{next_event_for_sa}->{$name};
                $name .= " #$sa" if defined $sa;
                start_new_ev($self, $line, $name);
            }
            elsif ($txt =~ m/processing connection (\S+)/) {
                $self->{ev}->{conn} = $1;
            }
            elsif ($txt =~ m/v2 peer, cookies and msgid match on #(\d+)/) {
                $self->{ev}->{sa} = $1;
            }
            elsif ($txt =~ m/now proceed with state specific processing using state #(\d+) (\S+)/) {
                $self->{ev}->{processor}->{name} = "$2";
                $self->{ev}->{processor}->{trans} = "$1";
            }
            elsif ($txt =~ m/processor '(\S+)' returned (\S+)/) {
                my $old = $self->{ev}->{processor}->{name};
                if ( not defined $old ) {
                    $self->{ev}->{processor}->{name} = "$1";
                    warn "processor '$1' completed, but not started\n";
                } elsif ( $old ne "$1" ) {
                    warn "processor was '$old' now '$1'\n";
                }
                $self->{ev}->{processor}->{returned} = "$2";
            }
            elsif ($txt =~ m/creating state object #(\d+)/) {
                $self->{ev}->{SA_new} = $1;
            }
            elsif ($txt =~ m/deleting state #(\d+) \((\S+)\)/) {
                push @{$self->{ev}->{SA_del_state}}, [ $1, $2 ];
            }
            elsif ($txt =~ m/freeing state object #(\d+)/) {
                push @{$self->{ev}->{SA_free}}, $1;
            }
            elsif ($txt =~ m/starting rekey of CHILD SA for state=#(\d+) \(expired\) using PARENT SA #(\d+)/) {
                $self->{ev}->{SA_old} = $1;
                $self->{ev}->{SA_parent} = $2;
            }
            elsif ($txt =~ m/route_and_eroute: instance .*, setting eroute_owner to #(\d+) \(was #(\d+)\) /) {
                $self->{ev}->{SA_routed} = $1;
                $self->{ev}->{SA_unrouted} = $2 if $2;
            }
            elsif ($txt =~ m/emit ISAKMP Message:/) {
                if (defined $self->{ev}->{why_start}
                        && ($self->{ev}->{why_start} eq 'received'
                            || defined $self->{ev}->{parse})) {
                    append_debug_line($self, $line);
                    complete_current_ev($self, $line, 'received');
                    start_new_ev($self, $line, 'responding');
                } else {
                    maybe_update_start($self, $line, 'sending');
                }

                push @{$self->{ev}->{emit}}, "ISAKMP";

            }
            elsif ($txt =~ m/emit ([^:]+):/) {
                my $long = $1;
                if ($long !~ m/Substructure/ && $long !~ m/Selector/) {
                    my $short = short_payload_name($long);
                    push @{$self->{ev}->{emit}}, $short;
                }
            }
            elsif ($txt =~ m/flags: (ISAKMP_FLAG_\S*)/) {
                my $flags = $1;
                $flags =~ s/ISAKMP_FLAG_//g;
                push @{$self->{ev}->{flags}}, $flags;
            }
            elsif ($txt =~ m/exchange type: (\S+)/) {
                $self->{ev}->{exchange} = $1;
            }
            elsif ($txt =~ m/message ID:\s+(\S+)/) {
                my $id = $1;
                $id =~ s/ //g;
                $self->{ev}->{msg_id} = hex($id);
            }
            elsif ($txt =~ m/processing version=(\S+)\s+packet.*msgid:\s+(\S+)/) {
                $self->{ev}->{version} = $1;
                $self->{ev}->{msg_id} = hex($2);
            }
            elsif ($txt =~ m/next-payload: ISAKMP_NEXT_(\S+) /) {
                push @{$self->{ev}->{payloads}}, "$1";
                #push @{$self->{ev}->{payloads_debug}}, "$1".'  @'.$line->{time}.'  '.$line->{line} if $show_debug;
            }
            elsif ($txt =~ m/sending \d+ bytes for \S+ through \S+ to \S+ \(using #\d+\)/) {
                $self->{ev}->{ts_sending} = $line->{ts};
            #   append_debug_line($self, $line);
            #   complete_current_ev($self,$line,'sent',0);
            }
            elsif ($txt =~ m/#(\d+): transition from state (\S+) to state (\S+)/) {
                $self->{ev}->{SA} = $1;
                $self->{ev}->{SA_trans} = [ $2, $3 ];
            }
            elsif ($txt =~ m/received \d+ bytes from \S+ on \S+ \(port=\d+\) at .*/) {
                $self->{ev}->{ts_received} = $line->{ts};
                if (defined $self->{ev}->{why_start}) {
                    complete_current_ev($self, $line, 'incoming');
                }
                start_new_ev($self, $line, 'received');
            }
            elsif ($txt =~ m/parse ([^:]+):/) {
                my $long = $1;
                if ($long !~ m/Substructure/ && $long !~ m/Selector/) {
                    my $short = short_payload_name($long);
                    push @{$self->{ev}->{parse}}, $short;
                }
            }
            elsif ($txt =~ m/processing payload: ISAKMP_NEXT_(\S+) /) {
                push @{$self->{ev}->{payloads}}, "$1";
                #push @{$self->{ev}->{payloads_debug}}, "$1".'  @ '.$line->{time}.'  '.$line->{line} if $show_debug;
            }
            elsif ($txt =~ m/#(\d+): (\S+): CHILD SA established tunnel/) {
            #   append_debug_line($self, $line);
            #   complete_current_ev($self,$line,'established',0);
            }
            elsif ($txt =~ m/processor '(\S+)' returned /) {
            #   append_debug_line($self, $line);
            #   complete_current_ev($self,$line,"$1");
            }
            elsif ($txt =~ m/(did not find valid state; giving up)/) {
                append_debug_line($self, $line);
                $self->{ev}->{error} = $1;
                complete_current_ev($self,$line,'ERROR');
            }
            else {
                $unhandled = 1;
            }

            if (not $unhandled && $show_debug) {
                # this line was handled
                append_debug_line($self, $line);
            }

        }


    };

    return $self;
}


sub create_peer {
    my ($justify, $filename, $tsdelta) = @_;

    my $self = {};

    $self->{filename} = $filename;
    $self->{events} = create_event_reader($filename, $tsdelta);

    #fh => $fh
    #};

    $self->{print} = sub {
        my ($txt) = @_;
        jprint($justify, $txt);
    };
    $self->{printf} = sub {
        $self->{print}( sprintf @_ );
    };
    $self->{printev_start} = sub {
        my ($ev) = @_;
        my @txt;
        push @txt, $ev->{why_start} if defined $ev->{why_start};
        push @txt, "via SA #".$ev->{sa} if defined $ev->{sa};
        $self->{print}( join(' ',@txt) );
    };
    $self->{printev_msg} = sub {
        my ($ev) = @_;
        my @txt;
        push @txt, $ev->{exchange}                         if defined $ev->{exchange};
        push @txt, "msg=".$ev->{msg_id}                    if defined $ev->{msg_id};
        push @txt, "flags{".join(',',@{$ev->{flags}})."}"  if defined $ev->{flags};
        push @txt, join(',',@{$ev->{payloads}})            if defined $ev->{payloads};

        my $arrow = '';
        if ($justify eq '<') {
            $arrow = '<----' if defined $ev->{parse};
            $arrow = '---->' if defined $ev->{emit};

            push @txt, $arrow if $arrow;
        } elsif ($justify eq '>') {
            $arrow = '---->' if defined $ev->{parse};
            $arrow = '<----' if defined $ev->{emit};
            unshift @txt, $arrow if $arrow;
        }
        $self->{print}( join(' ',@txt) );

        my $proc = $ev->{processor};
        if (defined $proc) {
            my $txt = 'running '.$proc->{name};
            $txt .= ' FSM '.$proc->{trans} if defined $proc->{trans} and $proc->{trans};
            $txt .= ' returned '.$proc->{returned} if defined $proc->{returned};
            $self->{print}( $txt );
        }
    };
    $self->{printev_sa} = sub {
        my ($ev) = @_;

        $self->{print}( "replacing #".$ev->{SA_old} )      if defined $ev->{SA_old};
        $self->{print}( "created #".$ev->{SA_new} )        if defined $ev->{SA_new};

        $self->{print}( "unrouted #".$ev->{SA_unrouted} )  if defined $ev->{SA_unrouted};
        $self->{print}( "routed #".$ev->{SA_routed} )      if defined $ev->{SA_routed};

        my @txt;
        push @txt, "#".$ev->{SA}                           if defined $ev->{SA};
        push @txt, join(' -> ',@{$ev->{SA_trans}})         if defined $ev->{SA_trans};
        $self->{print}( join(' ',@txt) )                   if @txt;

        if (defined $ev->{SA_del_state}) {
            foreach my $x (@{$ev->{SA_del_state}}) {
                $self->{print}( sprintf("deleted #%u (%s)", $x->[0], $x->[1]) )
            }
        }
        if (defined $ev->{SA_free}) {
            foreach my $x (@{$ev->{SA_free}}) {
                $self->{print}( "freed #$x" )
            }
        }

        if ($ev->{error}) {
            jprint('=', '*** ERROR ***' );
            $self->{print}( $ev->{error} );
        }
    };
    $self->{printev} = sub {
        my ($ev) = @_;

        if ($show_debug) {
            print map { "$justify $_\n" } split("\n", Dumper($ev));
        }

        $self->{printev_start}($ev);
        $self->{printev_msg}($ev);
        $self->{printev_sa}($ev);
        print "\n";
    };
    $self->{next_validated} = sub {
        my $ev = $self->{events}->{next}();
        return if not defined $ev;
        return if not $ev;

        if (defined $ev->{parse} and defined $ev->{emit}) {
            print Dumper($ev);
            die "ERROR: parse & emit\n";
        }

        if (not defined $ev->{why_start}) {
            print Dumper($ev);
            die "ERROR: no why_start\n";
        }

        if (not defined $ev->{ts}) {
            print Dumper($ev);
            die "ERROR: no ts_start\n";
        }

        if (!looks_like_number($ev->{ts})) {
            print Dumper($ev);
            die "ERROR: ts_start not a number\n";
        }

        return $ev;
    };
    $self->{next_fixedup} = sub {
        my $ev = $self->{next_validated}();
        return if not defined $ev;
        return if not $ev;

        if (!defined $ev->{payloads} && defined $ev->{emit}) {
            # INFORMATION/D messages for some reason don't generate
            # payload log messages that we can parse, so grab the emit
            # messages instead
            $ev->{payloads} = [ grep { !m/ISAKMP/ } @{$ev->{emit}} ];
        }

        return $ev;
    };
    $self->{next} = sub {

        while (1) {
            my $ev = $self->{next_fixedup}();
            return if not defined $ev;

            # if we are showing events, show it
            return $ev if $show_events;

            # if this is not an event, show it
            return $ev if $ev->{why_start} !~ m/^EVENT_/;

            # if it's an error, show it
            return $ev if $ev->{why_end} eq 'ERROR';

            # if it's a message, show it
            return $ev if defined $ev->{msg_id};
            return $ev if defined $ev->{parse};
            return $ev if defined $ev->{emit};

            # if the message contains SA_ info, show it
            my @keys = keys %{$ev};
            return $ev if grep(m/^SA_/,@keys);
        }
    };
    $self->{go} = sub {
        my $last_hms = '';
        while (my $ev = $self->{next}()) {
            my $this_hms = strftime '%T', localtime($ev->{ts});
            if ($last_hms ne $this_hms) {
                jprint('=', "--==[ ".$this_hms." ]==--");
                $last_hms = $this_hms;
            }

            $self->{printev}($ev)
        }
    };

    return $self;
}

# read from two peers, sort events by time stamp, and print chronologically
sub shuffle {
    my ($pr_l, $pr_r) = @_;
    my ($ev_l, $ev_r);
    my $last_hms = '';
    my $header = 0;

    while (1) {

        # make sure we have an event for each side

        $ev_l = $pr_l->{next}() if not defined $ev_l;
        $ev_r = $pr_r->{next}() if not defined $ev_r;

        # if we reached the end, stop

        last if not defined $ev_l and not defined $ev_r;

        # show a header, only once

        if (not $header) {
            dprint( $pr_l->{filename}, $pr_r->{filename} );

            my @show = qw{host proc pid};
            my $head_l = join(' ', map { $ev_l->{raw}->{$_} } @show);
            my $head_r = join(' ', map { $ev_r->{raw}->{$_} } @show);

            dprint( $head_l, $head_r );

            $header = 1;
        }


        # determine which one is first, consume it
        # ties are tricky; break ties using message ID
        # in case of a message ID tie, sender goes befoore receiver

        my $display = sub {
            my ($pr,$ev) = @_;
            # $ev set to either ev_l or ev_r, which ever is first
            # $pr set to either pr_l or pr_r, to match first ev

            # did the timestamp chagne?

            my $this_hms = strftime '%T', localtime($ev->{ts});
            if ($last_hms ne $this_hms) {
                print "\n";
                jprint('=', "--==[ ".$this_hms." ]==--");
                $last_hms = $this_hms;
            }

            # show it

            $pr->{printev}($ev)
        };
        my $consume_left = sub {
            $display->($pr_l, $ev_l);
            undef $ev_l;
        };
        my $consume_right = sub {
            $display->($pr_r, $ev_r);
            undef $ev_r;
        };

        if (not defined $ev_r) {
            # right is done; use left
            $consume_left->();
        }
        elsif (not defined $ev_l) {
            # left is done; use right
            $consume_right->();
        }
        elsif ($ev_l->{ts} < $ev_r->{ts}) {
            # left timestamp is first; consume the left event
            $consume_left->();
        }
        elsif ($ev_r->{ts} < $ev_l->{ts}) {
            # right timestamp is first; consume the right event
            $consume_right->();
        }
        elsif (not defined $ev_l->{msg_id}) {
            # left has no message; let it go first
            $consume_left->();
        }
        elsif (not defined $ev_r->{msg_id}) {
            # right has no message; let it go first
            $consume_right->();
        }
        elsif ($ev_l->{msg_id} < $ev_r->{msg_id}) {
            # left msg_ID is first; consume the left event
            $consume_left->();
        }
        elsif ($ev_r->{msg_id} < $ev_l->{msg_id}) {
            # right msg_ID is first; consume the right event
            $consume_right->();
        }
        elsif (defined $ev_l->{emit}) {
            # left is sending; consume left event
            $consume_left->();
            $consume_right->() if defined $ev_r->{parse};
        }
        elsif (defined $ev_r->{emit}) {
            # right is sending; consume right event
            $consume_right->();
            $consume_left->() if defined $ev_l->{parse};
        }
        else {
            # no other tie breakers; go left
            $consume_left->();
        }


    }


    #$r->{go}();
    #$l->{go}();
}


if ($sync_sides) {
    my $L = create_simple_event_reader($left);
    my $R = create_simple_event_reader($right);
    $rdelta = find_rdelta($L, $R);
    undef $L;
    undef $R;
}

my $l = create_peer('<', $left, 0);
my $r = create_peer('>', $right, $rdelta);

shuffle($l, $r);
