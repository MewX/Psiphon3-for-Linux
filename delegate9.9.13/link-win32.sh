#!/bin/sh

#env | grep Program | sort

echo "#### MAKE_WIN32=$MAKE_WIN32"
if [ "$MAKE_WIN32" = "" ]; then
	echo "#### MAKE_WIN32=$MAKE_WIN32 NO"
	exit 0
fi

echo "#### MAKE_WIN32=$MAKE_WIN32 DO"
set -x

#rc /v /r /fo win32-dg.res win32-dg.rc

"C:/Program Files/Microsoft Visual Studio 8/VC/bin/link.exe" \
	/subsystem:windows \
	/out:win32-dg.exe \
	delegated.o builtin.o commands.o croncom.o remote.o \
	../lib/libdelegate.a ../lib/libresolvy.a ../lib/libteleport.a \
	../lib/libmd5.a ../lib/libregex.a ../lib/libcfi.a ../lib/library.a \
	../lib/libmimekit.a ../lib/libfsx.a ../lib/libsubst.a \
	win32-dg.res \
	WS2_32.LIB ADVAPI32.LIB OLE32.LIB SHELL32.LIB UUID.LIB \
	USER32.LIB GDI32.LIB

echo "#### win32-dg.exe ####"
./dg.exe -Fesign -s -w win32-dg.exe
ls -l win32-dg.exe
