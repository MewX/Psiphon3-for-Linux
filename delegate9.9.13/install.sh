#!/bin/sh

INST=inst
DGVER=`src/dg.exe -Fver -vs`
DGWER=`echo $DGVER|sed 's/\./_/g'`
DGROOT=$INST/dg$DGWER/DGROOT
echo DGROOT=$DGROOT

if [ ! -d $INST ]; then
	mkdir $INST
fi
if [ ! -d $INST/dg$DGWER ]; then
	mkdir $INST/dg$DGWER
fi
if [ ! -d $DGROOT ]; then
	mkdir $DGROOT
	mkdir $DGROOT/bin
	mkdir $DGROOT/doc
	mkdir $DGROOT/etc
	mkdir $DGROOT/lib
	mkdir $DGROOT/subin
fi

cp -p CONTENTS.txt    $INST/dg$DGWER
cp -p COPYRIGHT       $DGROOT/doc/
cp -p LICENSE.txt     $DGROOT/doc/
cp -p LICENSE-ja.txt  $DGROOT/doc/
cp -p src/delegated   $DGROOT/bin/dg$DGWER
cp -p dg9.conf.txt    $DGROOT/bin/dg$DGWER.conf
cp -p setup-subin.sh  $DGROOT/subin/
cp -p subin/dgchroot  $DGROOT/subin/
cp -p subin/dgcpnod   $DGROOT/subin/
cp -p subin/dgbind    $DGROOT/subin/
cp -p subin/dgdate    $DGROOT/subin/
cp -p subin/dgforkpty $DGROOT/subin/
cp -p subin/dgpam     $DGROOT/subin/

(
cd $DGROOT/subin
setup-subin.sh
)
#find $INST -ls
echo "#### INSTALLED ####"
find $INST -type f -printf '%AH:%AM %M %-6u %-6g %p\n'

BINPATH=`pwd`/$DGROOT/bin
echo "#### DO ####"
echo "export PATH=\$PATH:$BINPATH"
echo "setenv PATH \$PATH:$BINPATH"
echo "############"
