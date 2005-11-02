## tclGetOpts - GetOpts.tcl
## 
## Description
## 	Tcl package: GetOpts v1.1
## 	Procedures: getopt, typedopts
## 	Contact: Ross Mohn, RPMohn@panix.com
## 	Website: http://www.waxandwane.com/toolbox/tclGetOpts/
## 
## 	tclGetOpts contains the Tcl package GetOpts which
## 	includes two procedures for parsing command-line options in a
## 	Tcl script.
## 
## 		* getopt: a close emulation of the C library routine
## 		getopt(3C).
## 
## 		* typedopts: uses long option names and does type checking
## 		on option arguments.
## 
## 
## Directory Listing
## 	GetOpts.tcl, pkgIndex.tcl
## 	index.html / readme.txt
## 	getopt.html / getopt.txt
## 	typedopts.html / typedopts.txt
## 
## 
## Copyright Information
## 	All copyrights of this package are hereby transferred to Ross
## 	Mohn. This package was originally written by Johnson Earls.
## 
## 
## Version History
## 	v1.1
## 		* tclGetOpts1.1.tar.gz
## 		* Created package GetOpts providing both procedures getopt
## 		and typedopts.
## 		* Fixed bug with the -noinit flag that caused the script
## 		to fail.
## 		* Fixed bug with the list-of option type that would only
## 		return the last option instead of the entire list.
## 
## 	v1.0
## 		* tclGetOpts1.0.tar.gz
## 

package provide GetOpts 1.1

set optind 0
set optindc 0

proc getopt { argslist optstring optret argret } {
  global optind optindc
  upvar $optret retvar
  upvar $argret optarg

# default settings for a normal return
  set optarg ""
  set retvar ""
  set retval 0

# check if we're past the end of the args list
  if { $optind < [ llength $argslist ] } then {

# if we got -- or an option that doesn't begin with -, return (skipping
# the --).  otherwise process the option arg.
    switch -glob -- [ set arg [ lindex $argslist $optind ]] {
      "--" {
        incr optind
      }

      "-*" {
        if { $optindc < 1 } then {
          set optindc 1
        }

        set opt [ string index $arg $optindc ]

        if { [ incr optindc ] == [ string length $arg ] } then {
          set arg [ lindex $argslist [ incr optind ]]
          set optindc 0
        }

        if { [ string match "*$opt*" $optstring ] } then {
          set retvar $opt
          set retval 1
          if { [ string match "*$opt:*" $optstring ] } then {
            if { $optind < [ llength $argslist ] } then {
              set optarg [ string range $arg $optindc end ]
              incr optind
              set optindc 0
            } else {
              set optarg "Option requires an argument -- $opt"
              set retvar $optarg
              set retval -1
            }
          }
        } else {
          set optarg "Illegal option -- $opt"
          set retvar $optarg
          set retval -1
        }
      }
    }
  }

  return $retval
}

proc typedopts { args } {

  proc abbr { s1 s2 } {
    if { [ set len [ string length $s1 ]] } then {
      if { ! [ string compare $s1 [ string range $s2 0 [ expr $len - 1 ]]] } then {
        return 1
      }
    }
    return 0
  }

  proc findabbr { list val } {
    set list [ lsort $list ]
    if { [ set pos [ lsearch -exact $list $val ]] > -1 } then {
      return [ lindex $list $pos ]
    }
    if { [ set pos [ lsearch -glob $list "$val*" ]] > -1 } then {
      if { [ abbr $val [ set realval [ lindex $list $pos ]]] } then {
        if { ! [ abbr $val [ lindex $list [ incr pos ]]] } then {
          return $realval
        }
      }
    }
    return ""
  }

  proc shift { listname } {
    upvar $listname list
    set ret [ lindex $list 0 ]
    set list [ lrange $list 1 end ]
    return $ret
  }

  proc extract { list args } {
    foreach arg $args {
      upvar $arg var
      set var [ shift list ]
    }
    return $list
  }

  proc parseFormats { fmts var } {
    foreach fmt $fmts {
      if { [ regexp $fmt $var ] } then {
        return 1
      }
    }
    return 0
  }

  proc parseOptionType { type listname retname } {
    upvar $listname args
    upvar $retname var

    set ifmt {
      "^\[+-\]?0x\[0-9a-fA-F\]+\$"
      "^\[+-\]?0\[0-7\]+\$"
      "^\[+-\]?\[0-9\]+\$"
    }

    set ffmt {
      "^\[+-\]?\.\[0-9\]+(\[Ee\]\[+-\]?\[0-9\]*)?\$"
      "^\[+-\]?\[0-9\]+\.\[0-9\]*(\[Ee\]\[+-\]?\[0-9\]*)?\$"
      "^\[+-\]?\[0-9\]+\[Ee\]\[+-\]?\[0-9\]*\$"
    }

    set nfmt [ concat $ifmt $ffmt ]

    set otype $type
    switch -exact [ shift type ] {
      b {
        set var ""
        return 1
      }
      i {
        if { [ llength $args ] } then {
          set val [ shift args ]
          if { [ parseFormats $ifmt $val ] } then {
            set var $val
            return 1
          }
        }
        set var "requires an integer argument."
        return 0
      }
      f {
        if { [ llength $args ] } then {
          set val [ shift args ]
          if { [ parseFormats $ffmt $val ] } then {
            set var $val
            return 1
          }
        }
        set var "requires a floating-point argument."
        return 0
      }
      n {
        if { [ llength $args ] } then {
          set val [ shift args ]
          if { [ parseFormats $nfmt $val ] } then {
            set var $val
            return 1
          }
        }
        set var "requires a numeric argument."
        return 0
      }
      s {
        if { [ llength $args ] } then {
          set var [ shift args ]
          return 1
        }
        set var "requires a string argument."
        return 0
      }
      o {
        if { [ llength $args ] } then {
          if { [ string length [ set val [ findabbr $type [ shift args ]]]] } then {
            set var $val
            return 1
          }
        }
        set var "requires a string argument."
        return 0
      }
      m {
        return [ parseOptionType $type args var ]
      }
      l {
        set val ""
        while { [ llength $args ] && ! [ string match "-*" $args ] } {
          if { ! [ parseOptionType $type args ret ] } then {
            set var $ret
            return 0
          }
          lappend val $ret
        }
        set var $val
        return 1
      }
      default {
        puts stderr "Eek!  Option type <$otype> not supported yet!"
        set var "isn't a supported type."
        return 0
      }
    }
  }

  proc parseOption { optlist } {
    set type [ shift optlist ]

    switch -exact [ findabbr { "booleans" "integers" "numbers" "floats" "strings" "one-of" "list-of" "multiple" } $type ] {
      "booleans" -
      "integers" -
      "numbers" -
      "floats" -
      "strings" {
        if { [ llength $optlist ] } then {
          puts stderr "typedopts:  Type $type doesn't take arguments"
          return ""
        }
        return [ string index $type 0 ]
      }
      "one-of" {
        if { ! [ llength $optlist ] } then {
          puts stderr "typedopts:  No arguments given to type $type"
          return ""
        }
        return [ concat [ string index $type 0 ] $optlist ]
      }
      "list-of" -
      "multiple" {
        if { ! [ llength $optlist ] } then {
          puts stderr "typedopts:  No arguments given to type $type"
          return ""
        }
        if { ! [ string length [ set subtype [ parseOption $optlist ]]] } then {
          return ""
        }
        return [ concat [ string index $type 0 ] $subtype ]
      }
      default {
        puts stderr "typedopts:  Unknown option type $type"
        return ""
      }
    }
  }

  set doinit 1

  if { [ llength $args ] < 5 } then {
    puts stderr "typedopts: bad number of arguments."
    return -1
  }

  set args [ extract $args arglist optlist optret argret restret ]

  while { [ llength $args ] } {
    set opt [ shift args ]
    switch -exact -- [ findabbr { -noinitialize } $opt ] {
      -noinitialize {
        set doinit 0
      }
      default {
        puts stderr "typedopts: bad option \"$opt\": should be -noinitialize or --"
        return -1
      }
    }
  }

  upvar $optret _opts
  upvar $argret _args
  upvar $restret _rest

  set allopts ""

  set type ""

  foreach word $optlist {
    set word [ string trim $word ]
    if { [ string length $type ] } then {
      foreach arg $word {
        if { [ lsearch -exact $arg $allopts ] > -1 } then {
          puts stderr "typedopts: option -$arg multiply declared."
          return -1
        }
        lappend allopts $arg
        set opttype($arg) $type
      }
      set type ""
    } else {
      if { ! [ string length [ set type [ parseOption $word ]]] } then {
        return -1
      }
    }
  }

  if { $doinit } then {
    foreach opt $allopts {
      set _opts($opt) 0
      set _args($opt) ""
    }
  }

set _args(_ERROR_) ""

  set retval 1

  while { [ llength $arglist ] } {
    switch -glob -- $arglist {
      -- {
        shift arglist
        break
      }
      -* {
      }
      * {
        break
      }
    }
    set opt [ string range [ shift arglist ] 1 end ]
    if { [ string length [ set fnd [ findabbr $allopts $opt ]]] } then {
      set type $opttype($fnd)
      if { [ parseOptionType $opttype($fnd) arglist arg ] } then {
        if { $_opts($fnd) && ! [ string match "m*" $type ] } then {
          set _args(_ERROR_) "Found multiple occurrences of option -$fnd"
          set retval 0
          break
        }
        set _opts($fnd) 1
        lappend _args($fnd) $arg
      } else {
        set _args(_ERROR_) "Option -$fnd $arg"
        set retval 0
        break
      }
    } else {
      set _args(_ERROR_) "Unknown option: -$opt"
      set retval 0
      break
    }
  }

  set _rest $arglist

  return $retval
}
