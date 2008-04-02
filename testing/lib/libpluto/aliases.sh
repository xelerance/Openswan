ee() {
	diff lib-$1/OUTPUT/$1.txt OUTPUT.$1.txt
}
e() {
	diff lib-parent$1/OUTPUT/parent$1.txt OUTPUT.parent$1.txt
}
d() {
	less lib-parent$1/OUTPUT/parent$1.output.diff
}
c() {
	cp lib-parent$1/OUTPUT/parent$1.txt OUTPUT.parent$1.txt
}

