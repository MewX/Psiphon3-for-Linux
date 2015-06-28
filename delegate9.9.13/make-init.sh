#!/bin/sh

if [ "y" = "x" ]; then
	make clean
	echo "##CLEAN ["`hostname`"][$HTTP_HOST] "`pwd`
	exit 1
fi

#make clean
#rm */Makefile.go

rm -f src/_builtin.c
rm -f src/builtin.o
rm -f src/version.o
rm -f src/conf.o
rm -f gen/bldsign.h

exit 0
rm src/log.o
(cd src; make clean)
touch src/version.c
rm lib/library.a
touch rary/nbio.c
touch src/sox.c
touch src/master.c
rm maker/.cksum.p2lla.c
rm maker/.cksum.p2llb.c
rm src/builtin/icons/ysato/frog9*ico
