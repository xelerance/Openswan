#!/bin/sh

available_tests="$(make testlist)"

warn() {
    echo >&2
    echo >&2 "warning: $@"
    echo >&2
}

die() {
    echo >&2
    echo >&2 "error: $@"
    echo >&2
    exit 1
}

do_git_add=true
do_clean=false
do_pcapupdate=false
die_on_failure=false
make_options=

while [ -n "$1" ] ; do
    case "$1" in
        -h|--help)
            cat <<END
$(basename $0) -h | -a
$(basename $0) <test> ...

 -h --help              this help
 -l --list              list available tests
 -p --pcap-update       updte pacap files
 -a --no-git-add-p      skip the git add -p on a per test basis, run all tests
 -v --verbose           make build verbose
 -o --make-options ...  additional options for make
 -e --die-on-failure    stop on non-zero exit from make check
END
            exit 0
            ;;
        -a|--no-git-add-p)
            do_git_add=false
            ;;
        -c|--clean)
            do_clean=true
            ;;
        -e|--die-on-failure)
            die_on_failure=true
            ;;
        -p|--pcapupdate|--pcap-update)
            do_pcapupdate=true
            ;;
        -l|--list)
            echo $available_tests | xargs -n1
            exit 0
            ;;
        -v|--verbose)
            make_options="$make_options V=1"
            ;;
        -o|--make-options)
            shift
            [ -z "$1" ] && die "-o --make-options requires an argument"
            make_options="$make_options $1"
            ;;
        -*)
            die "unknown flag $1"
            ;;
        *)
            name="${1%/}"
            if ! ( echo "$available_tests" | grep -q "\<$name\>" ) ; then
                die "unknown test $1"
            fi
            tests_to_run="$tests_to_run $name"
            ;;
    esac
    shift
done

[ -z "$tests_to_run" ] && tests_to_run="$available_tests"

# set some funky toilet options
toilet_options=
[ -t 0 ] && toilet_options="--metal --width $(tput cols) --font future"

# use toilet if possible
if which toilet ; then
    header() { toilet $toilet_options "$@" ; }
elif which figlet ; then
    header() { figlet -t $@ ; }
else
    header() { echo "###\n### $@\n###" ; }
fi

run() {
    echo >&2 "# $@"
    "$@"
}

run_make_check() {
    run rm -f core
    run make $make_options check
    rc=$?
    if [ $rc -ne 0 ] ; then
        if [ -f core ] ; then
            die "$1: exit with $rc, test crashed creating a core file, halting!"
        fi
        if $die_on_failure; then
            die "$1: exit with $rc"
        else
            warn "$1: exit with $rc"
        fi
    fi
    return $rc
}

for f in $tests_to_run
do
    (
     cd $f
     header $f
     $do_clean && run make $make_options clean
     if $do_pcapupdate
     then
         if ! run make $make_options pcapupdate
         then
             die "$f: make pcapupdate failed"
         fi
     fi
     while ! run run_make_check $f;
     do
         if run make $make_options update
         then
             if $do_git_add
             then
                 run git add -p .
             else
                 warn "$f: ignoring changes as requested"
                 break
             fi
         else
             die "$f: make update failed"
         fi
     done
    )
done

