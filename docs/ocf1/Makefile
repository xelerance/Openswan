DRAFT1=ocf-v1
REV=01

drafts: ${DRAFT1}.txt ${DRAFT1}.html 

%.txt: %.xml
	xml2rfc xml2rfc $? $@

%.html: %.xml
	xml2rfc xml2html $? $@



