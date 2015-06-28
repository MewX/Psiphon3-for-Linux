#!/bin/sh

CHROOT=/tmp/CHROOT
#DGROOT=$CHROOT/DGROOT
DGROOT=$CHROOT
DGSRCDIR=`pwd`
DGEXE=$DGSRCDIR/src/delegated
#DGROOT=`$DGEXE -Fdump DGROOT`

echo "#####################################################################"
echo "# installing {$*} at DGROOT/subin/" where
echo "#   CHROOT=$CHROOT"
echo "#   DGROOT=$DGROOT"
echo "# if above DGROOT is not appropriate, then set it as environment"
echo "# variable before doing 'make install'"
echo "#####################################################################"
if [ "$DGROOT" = "" ]; then
	echo "#### ERROR: NO DGROOT"
	exit 1
fi

if [ ! -d $CHROOT ]; then
	mkdir $CHROOT
fi
if [ ! -d $DGROOT ]; then
	mkdir $DGROOT
fi

#set -x
cd subin #################################

if [ ! -f dgbind ]; then
	make -f Makefile.go
fi
if [ "$*" = "" ]; then
	set $1 "dgpam dgbind dgdate dgchroot dgcpnod" 
fi
echo SUBIN-EXE-="$*"


#### LOCATION OF SYSTEM LIBRARIES ####
SYSLIB=/lib/x86_64-linux-gnu
if [ ! -d "$SYSLIB" ]; then
	SYSLIB=/lib
fi
USRLIB=/usr/lib/x86_64-linux-gnu
if [ ! -d "$USRLIB" ]; then
	USRLIB=/usr/lib
fi


CHUSRDIR=$CHROOT/usr
CHUSRLIB=$CHROOT/$USRLIB
CHLIBDIR=$CHROOT/$SYSLIB
CHETCDIR=$CHROOT/etc
CHBINDIR=$CHROOT/bin
CHSUBINDIR=$DGROOT/subin

UNAME=`uname`

if [ ! -d "$CHROOT/lib"   ]; then mkdir "$CHROOT/lib"; fi
if [ ! -d "$CHUSRDIR"     ]; then mkdir "$CHUSRDIR"; fi
if [ ! -d "$CHUSRDIR/lib" ]; then mkdir "$CHUSRDIR/lib"; fi
if [ ! -d "$CHUSRLIB"     ]; then mkdir "$CHUSRLIB"; fi
if [ ! -d "$CHLIBDIR"     ]; then mkdir "$CHLIBDIR"; fi
if [ ! -d "$CHETCDIR"     ]; then mkdir "$CHETCDIR"; fi
if [ ! -d "$CHBINDIR"     ]; then mkdir "$CHBINDIR"; fi
if [ ! -d "$CHSUBINDIR"   ]; then mkdir "$CHSUBINDIR"; fi
if [ ! -d "$DGROOT/bin"   ]; then mkdir "$DGROOT/bin"; fi
if [ ! -d "$DGROOT/etc"   ]; then mkdir "$DGROOT/etc"; fi

if [ -d $CHLIBDIR ]; then
	cp -p /etc/resolv.conf $CHETCDIR
	cp -p `which gzip` $CHBINDIR
	cp -p /bin/sh      $CHBINDIR
	cp -p $DGEXE $DGROOT/bin
	cp -p $DGSRCDIR/dg9.conf.txt $DGROOT/etc/delegated.conf.txt

	if [ "$UNAME" = "Darwin" ]; then
		if [ ! -d "$DGUSRLIB" ]; then
			echo "#### NO $DGUSRLIB"
		else
			 ( cd /usr/lib;
			   tar cf - dyld libSystem* \
				libmx.A.dylib \
				libutil* libstdc++* libgcc_s* libpam* \
				system/libmath* ) \
			|( cd "$DGUSRLIB"; tar xfv -) 
		fi
		du
		cp -p /etc/nsswitch.conf      $CHETCDIR
		if [ $? != 0 ]; then touch    $CHETCDIR/nsswitch.conf; fi
	else
		cp -p /etc/host.conf          $CHETCDIR
		cp -p /etc/hosts              $CHETCDIR
		cp -p /etc/passwd             $CHETCDIR
		cp -rp /etc/ld.so*            $CHETCDIR

		cp -p $SYSLIB/ld*so*          $CHLIBDIR
		cp -p $SYSLIB/libc.so*        $CHLIBDIR
		cp -p $SYSLIB/libdl.so*       $CHLIBDIR
		cp -p $SYSLIB/libnsl.so*      $CHLIBDIR
		cp -p $SYSLIB/libutil*.so*    $CHLIBDIR
		cp -p $SYSLIB/libreadline.so* $CHLIBDIR
		cp -p $SYSLIB/libncurses.so.* $CHLIBDIR
		cp -p $SYSLIB/libtinfo.so.*   $CHLIBDIR
		cp -p $SYSLIB/libpam.so*      $CHLIBDIR
		cp -p $SYSLIB/libnss*.so*     $CHLIBDIR
		cp -p $SYSLIB/libcrypt*.so*   $CHLIBDIR
		cp -p $SYSLIB/libcrypt*.so*   $CHLIBDIR
		cp -p $SYSLIB/libssl.so*      $CHLIBDIR
		cp -p $SYSLIB/libz.so*        $CHLIBDIR
		cp -p $SYSLIB/libexpat.so*    $CHLIBDIR
		cp -p $SYSLIB/liblzma.so*     $CHLIBDIR
		cp -p $SYSLIB/libssl.so*      $CHLIBDIR
		cp -p $SYSLIB/libz.so*        $CHLIBDIR
		cp -p $SYSLIB/libresolv*.so.* $CHLIBDIR
		cp -p $SYSLIB/libdl.so.*      $CHLIBDIR
		cp -p $SYSLIB/libm.so*        $CHLIBDIR
		cp -p $SYSLIB/libgcc_s.so*    $CHLIBDIR
		cp -p $SYSLIB/libpthread.so*  $CHLIBDIR
		cp -p $SYSLIB/libselinux.so*  $CHLIBDIR
		cp -p $SYSLIB/libacl.so*      $CHLIBDIR
		cp -p $SYSLIB/libpcre.so*     $CHLIBDIR
		cp -p $SYSLIB/libattr.so*     $CHLIBDIR
		cp -p $SYSLIB/libprocps.so*   $CHLIBDIR

		cp -p $USRLIB/libsigsegv.so*  $CHUSRLIB
		cp -p $USRLIB/libpython*.so*  $CHUSRLIB
		cp -p $USRLIB/libcrypt*.so*   $CHUSRLIB
		cp -p $USRLIB/libstdc++.so*   $CHUSRLIB
		#cp -p $SYSLIB/*linux-gcc*     $CHLIBDIR
		#cp -p $USRLIB/*linux-gcc*     $CHUSRLIB

		if [ -d /lib64 ]; then
			CHLIB64=$CHROOT/lib64
			if [ ! -d $CHLIB64 ]; then
				mkdir $CHLIB64
			fi
			cp -p /lib64/ld-linux-x86-64.so.* $CHLIB64
		fi
		if [ -d /usr/lib64 ]; then
			CHUSERLIB64=$CHROOT/usr/lib64
			if [ ! -d $CHUSERLIB64 ]; then
				mkdir $CHUSERLIB64
			fi
			cp -p /lib64/libresolv*.so.* $CHLIB64
		fi
		if [ -d /usr/sfw/lib ]; then
			## Solaris
			mkdir -p "$CHUSRDIR"/sfw/lib/amd64
		fi
		if [ -d /libexec ]; then
			## FreeBSD
			mkdir "$CHLIBDIR"exec
			cp -p /libexec/ld-elf.so.* "$CHLIBDIR"exec
		fi
		if [ -d /usr/libexec ]; then
			## FreeBSD4
			mkdir "$CHUSRLIB"exec
			cp -p /usr/libexec/ld-elf.so.* "$CHUSRLIB"exec
		fi

		(
		set - -x
		echo "####(referred libraries)########"
		ldd $DGEXE
		if [ -d /lib64 -a ! -d "$CHLIBDIR"64 ]; then mkdir "$CHLIBDIR"64; fi

		echo "####(copying libraries)#########"

		ldd $DGEXE | sed -e 's/.* => *//' -e 's/ (.*//' -e '/(.*)/d' | \
		while read FILE
		do
			echo '"'$FILE'"'
			cp -p $FILE $CHROOT/$FILE
		done

		echo "####(copied libraries)##########"
		ls -l $CHLIBDIR*/* $CHUSRLIB/*
		echo "################################"
		)
	fi
	( cd $CHSUBINDIR; rm -f $* )
	mv $* $CHSUBINDIR
	cd $CHSUBINDIR

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
