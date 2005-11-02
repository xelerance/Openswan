.SUFFIXES: .ps .fig .dvi .aux .html .eps .pdf .gif .png

PROJECT=fsumltesting
TOP=top
TEXFILES=top.tex background.tex physical.tex ols2002.bib
TEXFILES+=scaffolding.tex firstattempt.tex secondattempt.tex 
TEXFILES+=conclusions.tex
FIGFILES=testsetup1.fig testsetup2.fig easttest1.fig easttest2.fig 
FIGFILES+=single_netjig.fig klipstest.fig plutotest.fig multi_netjig.fig
PSFILES=${FIGFILES:S/.fig/.eps/}
HTMLDIR=/corp/docs/SSW/freeswan/${PROJECT}
HTMLTOP=${HTMLDIR}/${TOP}.html

all: ${PROJECT}.ps ${HTMLTOP} ${PROJECT}.pdf

${HTMLTOP}: ${TEXFILES} ${PSFILES} 
	-mkdir -p ${HTMLDIR}
	latex2html -info 0 -dir ${HTMLDIR} ${TOP}.tex

${PROJECT}.ps : $(PSFILES) ${TOP}.dvi
	dvips -o ${PROJECT}.ps ${TOP}
	-mkdir -p ${HTMLDIR}
	echo cp ${PROJECT}.ps ${HTMLDIR}

${TOP}.dvi : ${TEXFILES}
	latex ${TOP} || rm ${TOP}.dvi
	touch ${TOP}.aux-old
	if cmp -s ${TOP}.aux ${TOP}.aux-old ;\
        then \
          echo references are correct; \
        else  \
	  bibtex ${TOP} || exit 1;\
          cp ${TOP}.aux ${TOP}.aux-old; \
          latex ${TOP}; \
        fi

${TOP}.bbl : ${TOP}.bib
	latex ${TOP}
	bibtex ${TOP}

clean : 
	-rm -f ${TOP}.aux ${TOP}.bbl ${TOP}.dvi ${TOP}.aux-old ${TOP}.log *.ps 

.fig.eps: 
	fig2dev -L eps $< >$@

.fig.png: 
	fig2dev -L png $< >$@


.ps.pdf:
	ps2pdf $< $@
