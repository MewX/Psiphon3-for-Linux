#!/bin/sh

if [ "$XCCHOST" = "" ]; then
	if [ -f ../src/delegated.exe ]; then
		XCCHOST=..
	else
		XCCHOST=../dg-host
	fi
fi

#export PATH="$HOME/bin:$PATH"
#if [ ! -f mkmake.exe -o "$1" = "copy" ]; then
#	cp $XCCHOST/mkmake.exe .
#	cp $XCCHOST/mkmkmk.exe .
#	cp $XCCHOST/mkcpp.exe .
#	cp $XCCHOST/mkcpp.exe include
#	cp $XCCHOST/filters/mkstab.exe rary/
#	cp $XCCHOST/filters/mkstab.exe include/
#	cp $XCCHOST/filters/mkstab.exe filters/
#fi

if [ ! -f mkmake.exe -o ! -f DELEGATE_CONF ]; then
	cp -p DELEGATE_CONF.vce DELEGATE_CONF
	#cp -p $XCCHOST/gen/* gen/
	cp $XCCHOST/mkmake.exe .
	cp $XCCHOST/mkmkmk.exe .
	cp -p $XCCHOST/mkcpp.exe .
	cp -p $XCCHOST/filters/mkstab.exe filters/
	cp -p $XCCHOST/src/delegated.exe xdg.exe
	cp -p $XCCHOST/src/embed.exe xembed.exe
	cp -p $XCCHOST/src/embed.exe src/
	cp $XCCHOST/src/.cksum.embed.c src/ #### to be updatable by servce/Win
fi
touch mkmake.exe
touch mkmkmk.exe
touch mkcpp.exe
touch filters/mkstab.exe
touch xdg.exe
touch xembed.exe
touch src/embed.exe
touch src/.cksum.embed.c

export XDG="xdg.exe"
export XEMBED="../xembed.exe"

./make-vs8ce_win8.bat
if [ $? = 0 ];then
	ls -lt lib/lib*.a src/*.exe | head
fi
