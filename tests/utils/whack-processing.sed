s/^processing whack msg time: .* size: .*/processing whack msg time: X size: Y/
s/^Pre-amble (offset: .*): #!-pluto-whack-file- recorded on .*/Pre-amble (offset: X): #!-pluto-whack-file- recorded on FOO/
s/creating state object \(.*\) at .*/creating state object \1 at Z/
s/processing whack message of size: .*/processing whack message of size: A/
s/ *$//
/kernel_alg_esp_info/d
s/releasing whack for .* (sock=.*)/releasing whack for #X (sock=Y)/
/newest ISAKMP SA/d
s/(expires .*)/(expires SOMETIME)/
