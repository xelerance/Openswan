s/total size .*/total size X/
s/leak detective found .* leaks/leak detective found Z leaks/
s/new_list nlist, item size: .*/new_list nlist, item size: Y/
s/new_list item, item size: .*/new_list item, item size: Z/
s/leak: \(.*\), item size: .*/leak: \1, item size: X/
/unreference key/d
s/alg_info_delref(.*)/alg_info_delref(ADDRESS)/g
