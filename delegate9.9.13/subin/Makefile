CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"

commands:	Makefile.go
		$(MAKE) -f Makefile.go all SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"

MKMAKE =	exit 1

LIBS =		../lib/library.a ../lib/libcfi.a ../lib/libmimekit.a ../lib/libmd5.a
LIBSUBST =	-lc ../lib/libsubst.a
SSLEAY=		../../SSL

#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
NETLIB =	WSOCK32.LIB ADVAPI32.LIB GDI32.LIB
EAYLIB =	GDI32.LIB
LIBSSL=		$(SSLEAY)/ssleay32.lib $(SSLEAY)/libeay32.lib
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
#NETLIB =		-lsocket -lnsl -ldl
NETLIB =
EAYLIB =
LIBSSL=		$(SSLEAY)/libssl.a $(SSLEAY)/libcrypto.a
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

CKSUM =		-@"$(MKMAKE)" -cksum
.c.o:;	$(MKCPP)
	$(CC) $(CFLAGS) $(HDRDIR) -c $(CCINOUT)
	$(CKSUM) $*.c

COMMANDS = dgpam dgbind dgdate dgchroot dgcpnod dgforkpty


FILES =	README_SUBIN \
	Makefile \
	dgpam.c \
	dgxauth.c \
	dgbind.c \
	dgdate.c \
	dgchroot.c \
	dgcpnod.c \
	dgforkpty.c \
	dgsetlogin.c \
	install.sh

#---BGN---
#---END---

#### fix-130629a -lutil is necessary on Ubuntu for forkpty
LIBSALL =	$(LIBS) $(NETLIB) $(LIBSUBST) $(NETLIB)

all:	$(COMMANDS)

install:
	$(MAKE) -f Makefile.go all SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"
	./install.sh $(COMMANDS)

dgbind:	dgbind.o
	$(CC) $(LDFLAGS) -o $@ dgbind.o $(LIBSALL)

dgpam:	Makefile dgpam.o ../lib/library.a
	$(CC) $(LDFLAGS) -o $@ dgpam.o $(LIBSALL)

dgdate:	Makefile dgdate.o ../lib/library.a
	$(CC) $(LDFLAGS) -o $@ dgdate.o $(LIBSALL)

dgchroot:	Makefile dgchroot.o ../lib/library.a
	$(CC) $(LDFLAGS) -o $@ dgchroot.o $(LIBSALL)

dgcpnod:	Makefile dgcpnod.o ../lib/library.a
	$(CC) $(LDFLAGS) -o $@ dgcpnod.o $(LIBSALL)

dgforkpty:	Makefile dgforkpty.o ../lib/library.a ../maker/_-sgTTy.c
	$(CC) $(LDFLAGS) -o $@ dgforkpty.o $(LIBSALL)
dgforkpty.o:	dgforkpty.c ../rary/netsh.c

dgsetlogin:	Makefile dgsetlogin.o ../lib/library.a
	$(CC) $(LDFLAGS) -o $@ dgsetlogin.o $(LIBSALL)

files:;		ls -d $(FILES)
srcfiles:;	@echo $(FILES)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

