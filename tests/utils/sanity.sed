s/\(state object #. at 0x\)......../\1ABCDABCD/
s/Vendor ID  4f 53 .. ..  .. .. .. ..  .. .. .. ../Vendor ID  4f 53 ab ab  ab ab ab ab  ab ab ab ab/
s/Vendor ID  4f 45 .. ..  .. .. .. ..  .. .. .. ../Vendor ID  4f 45 ab ab  ab ab ab ab  ab ab ab ab/
s/|   4f 45 .. ..  .. .. .. ..  .. .. .. ../|   4f 45 ab ab  ab ab ab ab  ab ab ab ab/
s/ 4f 53 .. ..  .. .. .. ..  .. .. .. ../ 4f 53 ab ab  ab ab ab ab  ab ab ab ab/
s/v2vid: len=12 vid=OE........../v2vid: len=12 vid=OEababababab/
/Vendor.*this version/d
/ignoring unknown Vendor ID payload/d