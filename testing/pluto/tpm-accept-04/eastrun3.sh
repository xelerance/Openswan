echo "Stage 04c"

ipsec whack --tpmeval 'set test_stage "t04c"'
ipsec whack --tpmeval 'set stage4c_count 0'
echo "Wait for west to initiate"



