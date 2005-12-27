s/ixt_e=0x......./ixt_e=0xDEADF00D/
s/ips_key_e=0x......../ips_key_e=0xDEADF00D/
s/idat=0x......../idat=0xDEADF00D/
s/iv=0x......../iv=0xDEADF00D/
s/klips_debug:.*@010: .. .. .. .. 12 34 56 78/klips_debug:   @010: IV IV IV IV 12 34 56 78/
s/klips_debug:.*@010: .. .. .. ..$/klips_debug:   @010: IV IV IV IV/
s/SAref\[\(.*\)\]=0x......../SAref\[\1\]=0xABCDABCD/
s/struct=0p0x......../struct=0p0xABCDABCD/
s/ipsec_sa_put: ipsec_sa 0x........ SA/ipsec_sa_put: ipsec_sa 0xBCBCBCBC SA/
s/ipsec_sa_put: freeing 0x......../ipsec_sa_put: freeing 0xBCBCBCBC/
s/(0p0x........), SAref=/(0p0xBCBCBCBC), SAref=/
s/\(table=.*\)(0p0x........)/\1(EFEFEFEF)/
