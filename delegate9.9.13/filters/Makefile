#
#	Filters for DeleGate
#
#	CFI: Common Filter Interface
#

LIBFILE = libcfi.a

CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"

MKMAKE =	exit 1
CKSUM =		-@"$(MKMAKE)" -cksum

LIBS0 =		../lib/libcfi.a ../lib/library.a ../lib/libmimekit.a \
		../lib/libmd5.a
LIBS =		$(LIBS0) ../lib/libsubst.a ../lib/libsubstx.a ../lib/libcfi.a

SSLEAY=		../../SSL

HDRDIR=		-I../include


#ifdef MSWIN ######################################################
CURDIR =	".\"
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
NETLIB =	WSOCK32.LIB ADVAPI32.LIB GDI32.LIB
EAYLIB =	GDI32.LIB
LIBSSL=		$(SSLEAY)/ssleay32.lib $(SSLEAY)/libeay32.lib
EXE =		.exe
#endif #############
#ifdef UNIX,OS2EMX ################################################
CURDIR =	./
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
#NETLIB =		-lsocket -lnsl -ldl
NETLIB =
EAYLIB =
LIBSSL=		$(SSLEAY)/libssl.a $(SSLEAY)/libcrypto.a \
		-lcrypto -lssl -lcrypt -lkssl
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

FILES =	Makefile bdtee.c bdthru.c fcl.c \
		mkstab.c dl.c gzip.c \
		htview.c cfi.c cfi.conf reclog.c expired.c \
		cafe.c cafemain.c sslway.c \
		regex.c \
		m17nccx.c \
		backup.c \
		swft.c \
		pdft.c \
		dglogs.c \
		dping.c \
		ciicgi.c \
		htwrap.c \
		netzip.c

OBJS =	dl.o cfi.o cafe.o backup.o dping.o swft.o pdft.o sslway_dl.o gzip_dl.o \
	regex_dl.o \
	m17nccx_dl.o

#---BGN---
#---END---

EAYLIBS =	$(NETLIB) $(EAYLIB)

all:	mkstab$(EXE) filters

$(LIBFILE): $(OBJS)
	-$(RM) $@
	$(ARC) $(OBJS)
	-$(RANLIB) $@ 

pdft:	pdft.o
	$(CC) -o $@ pdft.o $(LIBS)

invoke:
	cd ../src; $(MAKE) Makefile.go
	cd ../src; $(MAKE) -f Makefile.go filters

filters: _SSLway bdtee bdthru netzip

reclog:	reclog.o
	$(CC) -o $@ reclog.o

mkstab$(EXE):	mkstab.c Makefile
	$(CC) -o $@ mkstab.c $(LIBDIRS)

expired:	expired.o
		$(CC) -o expired expired.o $(LIBS)

cafe:	Makefile cafe.o cafemain.o
	$(CC) $(LDFLAGS) -o $@ cafe.o cafemain.o $(LIBS) $(NETLIB)

bdtee:	bdtee.o
	$(CC) $(LDFLAGS) -o $@ bdtee.o $(LIBS) $(NETLIB)

dglogs:	dglogs.o
	$(CC) $(LDFLAGS) -o $@ dglogs.o $(LIBS) $(NETLIB)

dping:	dping.o
	$(CC) $(LDFLAGS) -o $@ -DMAIN dping.c $(LIBS) $(NETLIB)

bdthru:	bdthru.o
	$(CC) $(LDFLAGS) -o $@ bdthru.o $(LIBS) $(NETLIB)

pipes:	Makefile pipes.o
	$(CC) $(LDFLAGS) -o $@ pipes.o $(LIBS) $(NETLIB)

netzip:	netzip.o
	$(CC) $(LDFLAGS) -o $@ netzip.o $(LIBS) -lrary -lmd5 -lmimekit -lsubst

cfi.o:	Makefile cfi.c ../include/log.h ../include/dgctx.h
	$(MKCPP)
	$(CC) $(CFLAGS) -I../gen $(HDRDIR) -c $(CCINOUT)
	$(CKSUM) cfi.c

sslway.o:	 sslway.c ../include/randtext.c ../include/log.h

swft.o:	swft.c ../include/dgctx.h
dl.o:	dl.c ../include/log.h
sslway_dl.c:	sslway.c mkstab$(EXE) ../include/dgctx.h ../include/log.h ../include/ysignal.h
	$(CURDIR)mkstab$(EXE) < sslway.c > sslway_dl.c
gzip_dl.c:	gzip.c mkstab$(EXE) ../include/log.h ../include/ysignal.h
	$(CURDIR)mkstab$(EXE) < gzip.c > gzip_dl.c
m17nccx_dl.c:	m17nccx.c mkstab$(EXE) ../include/dgctx.h
	$(CURDIR)mkstab$(EXE) < m17nccx.c > m17nccx_dl.c
regex_dl.c:	regex.c mkstab$(EXE)
	$(CURDIR)mkstab$(EXE) < regex.c > regex_dl.c

sslway:	Makefile.go sslway.o $(LIBS)
	@echo "##--------------------------------------------------------------"
	@echo "##   SSLEAY=$(SSLEAY)   ... the directory of SSLeay"
	@echo "##   LIBSSL=$(LIBSSL)   ... the SSLeay library"
	@echo "##"
	-$(CC) $(LDFLAGS) -o $@ sslway.o -L$(SSLEAY) \
		$(LIBSSL) $(EAYLIBS) $(LIBS) \
		$(LIBSSL) $(EAYLIBS)
	@echo "##--------------------------------------------------------------"
	@echo "## If the above failed, retry like this:"
	@echo "##   make -f Makefile.go LIBSSL=\"-L/usr/local/ssl/lib -lssl -lcrypto\" sslway"
	@echo "##"

htview:	htview.o
	$(CCLD) $@ htview.o $(LIBSC)

files:;		ls -d $(FILES)
srcfiles:;	@echo $(FILES)

_SSLway:	Makefile.go
		$(MAKE) -f Makefile.go sslway SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB "" "$(LIBSSL) $(SSLLIB)" @LIBSSL

.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) -I../gen -I../src $(HDRDIR) -c $(CCINOUT)
		$(CKSUM) $*.c
		-@echo $(FILES) | xargs -n 1 "$(MKMAKE)" -cksum
