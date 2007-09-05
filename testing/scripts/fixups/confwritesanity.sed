/^#setting/d
s;\(opening file: \).*\(testing/.*\);\1DIR/\2;
s;\(including file \).*\(testing/.* from line \).*\(testing/.*:.*\);\1DIR/\2DIR/\3;
s;\(end of file \).*\(testing/.*, resuming \).*\(testing/.* line .*\);\1DIR/\2DIR/\3;
s;\(end of file \).*\(, resuming <none> line -1\);\1DIR\2;
