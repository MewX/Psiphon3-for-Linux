LIBFILE =	libfsx.a
CFLAGS =	-O3
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go CFLAGS="$(CFLAGS)" $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"
MKMAKE =	exit 1

#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

CKSUM =		-@"$(MKMAKE)" -cksum
.c.o:;		$(MKCPP)
	$(CC) $(CFLAGS) -I../gen $(HDRDIR) -I../include -c $(CCINOUT)
		$(CKSUM) $*.c


SRCS = any2fdif.c

all:	$(LIBFILE) any2fdif
lib:	$(LIBFILE)

#---BGN---
#---END---

$(LIBFILE): any2fdif.o
	-$(RM) $@
	$(ARC) any2fdif.o
	-$(RANLIB) $@

any2fdif:	Makefile any2fdif.c ../lib/libmimekit.a ../lib/library.a
	$(CC) $(CFLAGS) -o $@ \
		-DMAIN any2fdif.c \
		$(CFLAGS) -I../include \
		-L../lib -lmimekit -lrary -lmd5 -lsubst $(NETLIB)

any2fdif.o:	any2fdif.c ../include/vaddr.h ../include/log.h ../include/dgctx.h

FILES = Makefile $(SRCS)
files:	$(FILES)
		ls -d $(FILES)
srcfiles:;	@echo $(FILES)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

