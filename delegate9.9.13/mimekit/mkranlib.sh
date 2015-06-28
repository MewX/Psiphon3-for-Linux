#!/bin/sh

RANLIBS="/bin/ranlib /usr/bin/ranlib /usr/ucb/ranlib"
RANLIB="ls"

for RANLIB1 in $RANLIBS
do
#	if [ -x "$RANLIB1" ]; then
	if [ -f "$RANLIB1" ]; then
		RANLIB=$RANLIB1
		break
	fi
done

if [ "$RANLIB" = "" ]; then
	RANLIB=`which ranlib`
	if [ "$RANLIB" = "" -o ! -x "$RANLIB" ]; then
		RANLIB=/bin/echo
	fi
fi

echo $RANLIB
exit 0
