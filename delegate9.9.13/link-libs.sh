#!/bin/sh

CYGLIB=/cygdrive/d/cygwin/lib/w32api
if [ -d $CYGLIB ]; then
	cd lib
	ln -s $CYGLIB/libadvapi32.a .
	ln -s $CYGLIB/libshell32.a  .
	ln -s $CYGLIB/libuser32.a   .
	ln -s $CYGLIB/libkernel32.a .
fi

exit 0
