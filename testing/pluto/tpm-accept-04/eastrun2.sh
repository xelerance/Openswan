echo "Stage 04b"

ipsec whack --tpmeval 'set test_stage "t04b"'
ipsec whack --tpmeval 'set stage4b_count 0'
echo "Wait for west to initiate"



