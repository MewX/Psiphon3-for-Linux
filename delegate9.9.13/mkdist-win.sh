#!/bin/sh

INST=inst
DGVER=`src/dg.exe -Fver -vs`
DGWER=`echo $DGVER|sed 's/\./_/g'`
DGZIP=win32-dg$DGWER.zip
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
fi

cp -p ./CONTENTS.txt              $INST/dg$DGWER
cp -p ./src/delegated.exe         $DGROOT/bin/con32-dg$DGWER.exe
cp -p ./src/win32-dg.exe          $DGROOT/bin/win32-dg$DGWER.exe
cp -p ./dg9.conf.txt              $DGROOT/bin/con32-dg$DGWER.conf.txt
cp -p ./dg9.conf.txt              $DGROOT/bin/win32-dg$DGWER.conf.txt
cp -p ../cyg/dg$DGVER/subin/dgforkpty.exe $DGROOT/bin/dgforkpty.exe
cp -p ./COPYRIGHT                 $DGROOT/doc/
cp -p ./LICENSE.txt               $DGROOT/doc/
cp -p ./LICENSE-ja.txt            $DGROOT/doc/
cp -p ../dist/doc/OpenSSL-LICENSE $DGROOT/doc/
cp -p ../dist/doc/zlib.h          $DGROOT/doc/
cp -p ../dist/dll/dgzlib1.dll     $DGROOT/bin/
cp -p ../dist/dll/libeay32.dll    $DGROOT/bin/
cp -p ../dist/dll/ssleay32.dll    $DGROOT/bin/
cp -p ./lib/libgates.a            $DGROOT/lib/
cp -p ./lib/libopt_s.a            $DGROOT/lib/
find $INST -ls

(
cd $INST
dgROOT=dg$DGWER/DGROOT
zip -r $DGZIP dg$DGWER/CONTENTS.txt $dgROOT/bin $dgROOT/doc $dgROOT/etc $dgROOT/lib
)
