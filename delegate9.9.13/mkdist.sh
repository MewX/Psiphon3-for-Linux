#!/bin/sh

. ./install.sh
cp -p lib/libopt_s.a $INST/dg$DGWER/DGROOT/lib
cp -p lib/libgates.a $INST/dg$DGWER/DGROOT/lib

DGTAR=dg$DGWER.tar

(
cd $INST
dgROOT=dg$DGWER/DGROOT
tar cf $DGTAR \
	dg$DGWER/CONTENTS.txt \
	$dgROOT/bin \
	$dgROOT/doc \
	$dgROOT/etc \
	$dgROOT/lib \
	$dgROOT/subin

gzip -f $DGTAR
tar tfvz $DGTAR.gz
)
