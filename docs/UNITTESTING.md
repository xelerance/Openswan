Unit Testing
------------

The unit tests are located in tests/unit, in a series of categories according
to which part of the code is exercised, and then in a series of numbered
subdirectories.

The *libpluto* directory started first. It was intended to test just the code
in lib/libpluto, but wound up providing state-transition tests of major
parts of the IKEv1 and IKEv2 processing.  An open project is to split it
up more sanely.

Within the *libpluto* directory the tests are named lpXXX-_something_.
The intention is that each number XXX is unique, but as the numbers increment
and come from different branches, this is not always the case.
The _something_ part is intended to be descriptive.

Within each directory a file _description.txt_ provides additional
understanding of what the test hopes to accomplish.

Each directory compiles a program against libraries and pluto object files,
producing a executable.  It is often the case that a configuration file must
be loaded to make this work, and the program _readwriteconf_ is used in the
mode where it writes the "whack" data to disk for loading my the program.
This simulates the process of running pluto, then running "whack" or
"addconn" to load the configuration.

The data files are endian, processor (32-bit, 64-bit, arm, x86) and even
compiler specific.   While openswan tries to use object directories for all
regular compilation, allowing one to work on multiple architectures in the
same directory at the same time, the unit testing system does not,
regretfully, use object directories (yet?)

In order to make the tests repeatable a number of things need to be made
deterministic.  This unfortunately includes a lot of the crypto!  So a series
of files are provided called "seam_xxx.c" which are #include by the test
driver in order to mock or remote major subsystems.

These are a combination of preprocessor and #include seams.
See: https://www.goodreads.com/book/show/44919.Working_Effectively_with_Legacy_Code

There is a third way to override things. Seams are searched for in
the path, and modules can provide local copies or module-wide copies
outside of the seam template directories.


SEAM #define LIST
-----------------

This section begins the documentation of the various #define which the seam
system uses to enable certain mocks.

NO\_SEAM\_RSASIG - used by seam_rsasig.c to mock: ikev2_calculate_rsa_sha1,
              ikev2_calculate_psk_auth, ikev2_verify_psk_auth,
              ikev2_check_key_seam, and ikev2_verify_rsa_sha1

              This is used by most libpluto test cases to remove processing
              and generation of RSA signatures for IKEv1 and IKEv2.
              The test cases ikev2crypto do not mock these.

NAPT_ENABLED  if set 1, then code to perform IPv4 NAPT transition of incoming
              packets will be done.  This should be enabled on the "public"
              machine to indicate that the initiator is behind a NAT.
              (Not related NO_SEAM_NATT though)

NO\_SEAM\_NATT if set, then do not include seams for nat_traversal.c
