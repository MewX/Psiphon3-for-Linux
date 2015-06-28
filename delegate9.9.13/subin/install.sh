#!/bin/sh

DGROOT=`../src/delegated -Fdump DGROOT`
echo "#####################################################################"
echo "# installing {$*} at DGROOT/subin/" where
echo "#   DGROOT=$DGROOT"
echo "# if above DGROOT is not appropriate, then set it as environment"
echo "# variable before doing 'make install'"
echo "#####################################################################"
set -x

if [ ! -f dgbind ]; then
	make -f Makefile.go
fi
if [ "$*" = "" ]; then
	set $1 "dgpam dgbind dgdate dgchroot dgcpnod" 
fi
echo SUBIN-EXE-="$*"

USRDIR=$DGROOT/usr
USRLIB=$DGROOT/usr/lib

LIBDIR=$DGROOT/lib
ETCDIR=$DGROOT/etc
BINDIR=$DGROOT/bin
SUBINDIR=$DGROOT/subin

UNAME=`uname`

if [ ! -d "$USRDIR" ]; then mkdir "$USRDIR"; fi
if [ ! -d "$USRLIB" ]; then mkdir "$USRLIB"; fi
if [ ! -d "$LIBDIR" ]; then mkdir "$LIBDIR"; fi
if [ ! -d "$ETCDIR" ]; then mkdir "$ETCDIR"; fi
if [ ! -d "$BINDIR" ]; then mkdir "$BINDIR"; fi
if [ ! -d "$SUBINDIR" ]; then mkdir "$SUBINDIR"; fi

if [ -d $LIBDIR ]; then
	cp -p /etc/resolv.conf $ETCDIR
#	cp -p `which /usr/bin/gzip` $BINDIR

	if [ "$UNAME" = "Darwin" ]; then
		if [ ! -d "$USRLIB" ]; then
			echo "#### NO $USRLIB"
		else
			 ( cd /usr/lib;
			   tar cf - dyld libSystem* \
				libmx.A.dylib \
				libutil* libstdc++* libgcc_s* libpam* \
				system/libmath* ) \
			|( cd "$USRLIB"; tar xfv -) 
		fi
		du
		cp -p /etc/nsswitch.conf $ETCDIR
		if [ $? != 0 ]; then touch $ETCDIR/nsswitch.conf; fi
	else
		cp -p /etc/host.conf $ETCDIR
		cp -p /etc/hosts  $ETCDIR
		cp -p /etc/passwd $ETCDIR
		cp -p /etc/ld.so* $ETCDIR
		cp -p /lib/ld*so* $LIBDIR
		cp -p /lib/libc.so* $LIBDIR
		cp -p /lib/libdl.so* $LIBDIR
		cp -p /lib/libnsl.so* $LIBDIR
		cp -p /lib/libutil*.so* $LIBDIR
		cp -p /lib/libpam.so* $LIBDIR
		cp -p /lib/libnss*.so* $LIBDIR
		cp -p /lib/libcript*.so* $LIBDIR
		cp -p /lib/libcrypt*.so* $LIBDIR
		cp -p /lib/libssl.so* $LIBDIR
		cp -p /lib/libz.so* $LIBDIR
		cp -p /usr/lib/libcrypt*.so* $LIBDIR
		cp -p /usr/lib/libssl.so* $LIBDIR
		cp -p /usr/lib/libz.so* $LIBDIR

		cp -p /lib/libresolv*.so.* $LIBDIR
		cp -p /lib/libdl.so.* $LIBDIR
		cp -p /lib/libm.so* $LIBDIR
		cp -p /lib/libgcc_s.so* $LIBDIR
		cp -p /lib/libpthread.so* $LIBDIR
		cp -p /lib/*linux-gcc* $LIBDIR
		cp -p /usr/lib/*linux-gcc* $USRLIB
		cp -p /usr/lib/libstdc++.so* $USRLIB

		if [ -d /lib64 ]; then
			if [ ! -d "$LIBDIR"64 ]; then
				mkdir "$LIBDIR"64
			fi
			cp -p /lib64/ld-linux-x86-64.so.* "$LIBDIR"64
		fi
		if [ -d /usr/lib64 ]; then
			if [ ! -d "$USRLIB"64 ]; then
				mkdir "$USRLIB"64
			fi
			cp -p /lib64/libresolv*.so.* "$LIBDIR"64
		fi
		if [ -d /usr/sfw/lib ]; then
			## Solaris
			mkdir -p "$USRDIR"/sfw/lib/amd64
		fi
		if [ -d /libexec ]; then
			## FreeBSD
			mkdir "$LIBDIR"exec
			cp -p /libexec/ld-elf.so.* "$LIBDIR"exec
		fi
		if [ -d /usr/libexec ]; then
			## FreeBSD4
			mkdir "$USRLIB"exec
			cp -p /usr/libexec/ld-elf.so.* "$USRLIB"exec
		fi

		(
		set - -x
		DGEXE=../src/delegated
		echo "####(referred libraries)########"
		ldd $DGEXE
		if [ -d /lib64 -a ! -d "$LIBDIR"64 ]; then mkdir "$LIBDIR"64;fi
		echo "####(copying libraries)#########"
		ldd $DGEXE | sed -e 's/.* => *//' -e 's/ (.*//' -e '/(.*)/d' |\
		while read FILE
		do
			echo '"'$FILE'"'
			cp -p $FILE $DGROOT/$FILE
		done
		echo "####(copied libraries)##########"
		ls -l $LIBDIR*/* $USRLIB/*
		echo "################################"
		)
	fi
	(cd $SUBINDIR; rm -f $*)
	mv $* $SUBINDIR
	cd $SUBINDIR

	echo "#### setting the owner of $*"

	### sudo for MacOS X
	sudo sh -c "chown root $*; chmod 6550 $*"

	if [ $? != 0 ]; then
		su root -c "chown root $*; chmod 6550 $*"
	fi
	if [ $? != 0 ]; then
		su root -c "chown root $*; chmod 6550 $*"
	fi

	set +x
	if [ $? = 0 ]; then
		echo "################################"
		echo "#  OK, installed successfully  #"
		echo "################################"
		pwd
		ls -l $*
	fi
fi

#
# gdb delegated
# (gdb) break main
# (gdb) run
# (gdb) info sharedlibrary
#
# ldd delegated
# otool -L delegated (MacOSX)
#
# Linux: man ld.so
# LD_BIND_NOW=on
# LD_TRACE_LOADED_OBJECTS=on
#
# MacOS X: man dyld
# DYLD_BIND_AT_LAUNCH=
# DYLD_PRINT_LIBRARIES=
#
# OSF/1: man loader
# _RLD_ARGS=-trace
#
# SunOS5: man ld (/usr/lib/ld.so.1)
# LD_PRELOAD
# LD_DEBUG
