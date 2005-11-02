#!/bin/sh 

#MCONSOLE=uml_mconsole
MCONSOLE=/usr/src/freeswan/uml/utils/mconsole/uml_mconsole

for i in /tmp/uml/*
do
	$MCONSOLE $i/mconsole halt
done
