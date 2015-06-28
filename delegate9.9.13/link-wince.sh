#!/bin/sh

link -out:$1 \
	 delegated.o builtin.o commands.o croncom.o remote.o \
	win32-dg.res \
	 ../lib/libdelegate.a ../lib/libresolvy.a ../lib/libteleport.a \
	 ../lib/libmd5.a ../lib/libregex.a ../lib/libcfi.a ../lib/library.a \
	 ../lib/libmimekit.a ../lib/libfsx.a ../lib/libsubst.a \
	 ws2.lib uuid.lib ole32.lib secchk.lib toolhelp.lib \
	 /subsystem:windowsce /NODEFAULTLIB:oldnames.lib \
	 /machine:arm \
	 coredll.lib corelibc.lib


link -out:winmo-dg.exe \
	 delegated.o builtin.o commands.o croncom.o remote.o \
	win32-dg.res \
	 ../lib/libdelegate.a ../lib/libresolvy.a ../lib/libteleport.a \
	 ../lib/libmd5.a ../lib/libregex.a ../lib/libcfi.a ../lib/library.a \
	 ../lib/libmimekit.a ../lib/libfsx.a ../lib/libsubst.a \
	 ws2.lib uuid.lib ole32.lib secchk.lib toolhelp.lib \
	 /subsystem:windowsce,5.00 /NODEFAULTLIB:oldnames.lib \
	 /machine:arm \
	 coredll.lib corelibc.lib
