#!/bin/sh

MYARC=`uname`" "`hostname`
if [ "$XCCDG" != "" ]; then
	XXCC=":XCC-$XCCDG"
else
	XXCC=":"
fi

if [ "$DGMAKE" = "verbose" ]; then
  echo "#ck_builtin:" \
     `wc src/_builtin.c|awk '{print $1 " " $2 " " $3'}` \
     `cksum src/_builtin.c|awk '{print $1}'` \
     "$XXCC $MYARC"
fi

#src/delegated -Fseltest
#cc -DMAIN -Iinclude maker/_-sgTTy.c -o sgTTy

exit 0
