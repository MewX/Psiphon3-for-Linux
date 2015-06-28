#/*////////////////////////////////////////////////////////////////////////
#Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI
#
#Permission to use, copy, modify, and distribute this material for any
#purpose and without fee is hereby granted, provided that the above
#copyright notice and this permission notice appear in all copies, and
#that the name of ETL not be used in advertising or publicity pertaining
#to this material without the specific, prior written permission of an
#authorized representative of ETL.
#ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
#MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
#OR IMPLIED WARRANTIES.
#/////////////////////////////////////////////////////////////////////////
#Content-Type:	program/C; charset=US-ASCII
#Program:	Makefile for resolver
#Author:	Yutaka Sato <ysato@etl.go.jp>
#Description:
#History:
#	950820	created
#	970101	ported to Windows
#//////////////////////////////////////////////////////////////////////#*/

MYNAME =	resolvy
VERSION =	1.0
TARFILE =	$(MYNAME)$(VERSION).tar
entry:		all

#
#
#

LIBFILE =	libresolvy.a

CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) XOBJS="" MKMAKE="$(MKMAKE)" SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"
MKMAKE =	exit 1

LIBX = ../lib/library.a ../lib/libmimekit.a ../lib/libcfi.a ../lib/libmd5.a ../lib/libsubst.a

#ifdef MSWIN ######################################################
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
MV =		ren
LS =		dir
TAR =
MKMAKE =	..\src\mkmake.exe
LKFILE =	"$(MKMAKE)" -lkfile
RESOLV =	libresolvy.a
CCINX =		.cpp
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
CCRESCONF =	$(CC) $(CFLAGS) -c $(CCINOUT)
LIBS =		WSOCK32.LIB ADVAPI32.LIB GDI32.LIB
#endif #############
#ifdef OS2EMX #####################################################
LKFILE =	cp
CCRESCONF =	$(CC) -c $(CFLAGS) resconf.c
LIBS =		-lsocket
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINX =		.c
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	$(AR) ts
RANLIB =	ranlib
MV =		mv
LS =		ls -d
TAR =		tar
RESOLV =	libresolvy.a
CCINOUT =	$*.c -o $*.o
#endif #############
#ifdef UNIX #######################################################
LKFILE =	ln -s
CCRESCONF =	-$(SHELL) ./ccres $(CC) -c $(CFLAGS) $(HDRDIR) resconf$(CCINX)
LIBS =		
#LIBS =		-lsocket -lnsl
#endif #############
#IF NONC99 #####################################################
 #MKMKCPP =	../mkcpp
 #CCINOUT =	$*._.c -o $*.o
 #MKCPP =	../mkcpp $*.c $*._.c
 #CCRESCONF =	-$(SHELL) ./ccres $(CC) -c $(CFLAGS) $(HDRDIR) resconf._.c -o resconf.o
#FI ################

CKSUM =		-@"$(MKMAKE)" -cksum
.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) $(HDRDIR) -c $(CCINOUT)
		$(CKSUM) $*.c

LOCALFILES =	Makefile ccres dns.h \
		dnsnode.c resolv.c reshost.c rescache.c hostent.c \
		resconf.c resmain.c ntod.c netdom.sample

XSRC00 =	../include/vsocket.h
XSRC01 =	../include/ysocket.h
XSRC02 =	../include/vsignal.h
XSRC03 =	../include/log.h
XSRC04 =	../include/config.h
XSRC05 =	../include/ystring.h
XSRC06 =	../include/fpoll.h
XSRC07 =	../include/yselect.h
XSRC08 =	../include/ywinsock.h
XSRC09 =	../include/yarg.h
XSRC0A =	../include/file.h
XSRC0B =	../include/typedefs.h
XSRC0C =	../include/vaddr.h
XSRC0D =	../include/proc.h
XSRC0E =	../include/ystrvec.h
XSRC0F =	../include/ysignal.h
XSRC0G =	../include/dgctx.h
XSRC1 =		../rary/String.c
XSRC2 =		../maker/bcopy.c
XSRC3 =		../maker/strcasecmp.c
XSRC4 =		../maker/_-select.c
XSRC5 =		../rary/file.c
XSRC7 =		../rary/syslog.c
XSRC8 =		../rary/windows.c
XSRC9 =		../rary/windows0.c
XSRCA =		../rary/hostaddr.c
XSRCB =		../rary/socks5.c
XSRCC =		../rary/timer.c
XSRCD =		../rary/nbio.c
XSRCF =		../mimekit/gendom.c

XSRCS =		vsocket.h ysocket.h vsignal.h log.h config.h ystring.h fpoll.h \
		yselect.h ywinsock.h yarg.h file.h vaddr.h proc.h \
		ystrvec.h \
		ysignal.h \
		dgctx.h \
		String.c bcopy.c strcasecmp.c \
		_-select.c file.c syslog.c

XOBJS =		String.o bcopy.o strcasecmp.o \
		_-select.o file.o syslog.o windows.o hostaddr.o \
		socks5.o timer.o nbio.o gendom.o

FILES =		$(LOCALFILES) $(XSRCS)

OBJS =		dnsnode.o resolv.o reshost.o rescache.o hostent.o resconf.o

#---BGN---
#---END---

all:		$(XSRCS) $(LIBFILE) resolvy ntod

$(LIBFILE):	Makefile $(XSRCS) $(OBJS) $(XOBJS)
		-$(RM) $@
		$(ARC) $(OBJS) $(XOBJS)
		-$(RANLIB) $@

resolvy:	$(LIBFILE) resmain.o
		$(CC) -o $@ resmain.o $(RESOLV) $(LIBX) $(LIBS) $(NETLIB)

ntod:		$(LIBFILE) ntod.o gendom.o
		$(CC) -o $@ ntod.o gendom.o $(RESOLV) $(LIBX) $(LIBS) $(NETLIB)

dnsnode.o:	dns.h dnsnode.c
resolv.o:	dns.h vsocket.h log.h resolv.c ystring.h
reshost.o:	dns.h vsocket.h reshost.c ystring.h
rescache.o:	dns.h rescache.c
resconf.o:	ccres vsocket.h log.h resconf.c
		$(MKCPP)
		$(CCRESCONF)
		$(CKSUM) resconf.c

log.h:		$(XSRC03)
		-$(LKFILE) $(XSRC03) $@
vsocket.h:;	-$(LKFILE) $(XSRC00) $@
ysocket.h:;	-$(LKFILE) $(XSRC01) $@
vsignal.h:;	-$(LKFILE) $(XSRC02) $@
config.h:;	-$(LKFILE) $(XSRC04) $@
ystring.h:	$(XSRC05)
		-$(RM) $@
		-$(LKFILE) $(XSRC05) $@
fpoll.h:;	-$(LKFILE) $(XSRC06) $@
yselect.h:;	-$(LKFILE) $(XSRC07) $@
ywinsock.h:;	-$(LKFILE) $(XSRC08) $@
yarg.h:;	-$(LKFILE) $(XSRC09) $@
file.h:;	-$(LKFILE) $(XSRC0A) $@
typedefs.h:;	-$(LKFILE) $(XSRC0B) $@
vaddr.h:;	-$(LKFILE) $(XSRC0C) $@
proc.h:;	-$(LKFILE) $(XSRC0D) $@
ystrvec.h:;	-$(LKFILE) $(XSRC0E) $@
ysignal.h:;	-$(LKFILE) $(XSRC0F) $@
dgctx.h:;	-$(LKFILE) $(XSRC0G) $@
String.c:;	-$(LKFILE) $(XSRC1) $@
bcopy.c:;	-$(LKFILE) $(XSRC2) $@
strcasecmp.c:;	-$(LKFILE) $(XSRC3) $@
_-select.c:;	-$(LKFILE) $(XSRC4) $@
syslog.c:;	-$(LKFILE) $(XSRC7) $@

file.c:		$(XSRC5); -$(LKFILE) $(XSRC5) $@
windows.c:	$(XSRC8); -$(LKFILE) $(XSRC8) $@
windows0.c:	$(XSRC9); -$(LKFILE) $(XSRC9) $@
hostaddr.c:	$(XSRCA); -$(LKFILE) $(XSRCA) $@
socks5.c:	$(XSRCB); -$(LKFILE) $(XSRCB) $@
timer.c:	$(XSRCC); -$(LKFILE) $(XSRCC) $@
nbio.c:		$(XSRCD); -$(LKFILE) $(XSRCD) $@
gendom.c:	$(XSRCF); -$(LKFILE) $(XSRCF) $@

windows.o:	windows.c windows0.c

clean:;		-$(RM) *.o $(XSRCS)

files:;		$(LS) $(LOCALFILES)
srcfiles:;	@echo $(LOCALFILES)

tar:		$(TARFILE)
$(TARFILE):	$(FILES)
		$(TAR) cfh $@ $(FILES)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(LOCALFILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB
