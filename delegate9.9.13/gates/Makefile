#
# BUILDING GATES
# Yutaka Sato, Aug. 30, 2014
#

LIBFILE =	libgates.a

CFLAGS =	-O2
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go CFLAGS="$(CFLAGS)" $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"

MKMAKE =	exit 1
CKSUM =		-@"$(MKMAKE)" -cksum
HDRDIR =	-I../include -I../src

B2X = ./b2x.exe
#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
OBJS =		Gates_Win32.o
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
OBJS =		Gates_Win32.o
CCXFLAGS =	-fno-exceptions
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

all:		$(LIBFILE)

CFLAGSPLUS =	-x c++ -DQS

#---BGN---
#---END---

SRCS =		Makefile \
		Gates_Win32.c \
		Gates_Win32.c.des \
		b2x.c \

GATES =		Gates_Win32.o \

XHDRS =		../include/config.h \
		../include/dglib.h \
		../include/delegate.h \

HDRDIR =	-I../gen -I../include -I../src

all:		$(LIBFILE)

.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) $(CCXFLAGS) -I../gen $(HDRDIR) -I../include -I../src -c $(CCINOUT)
		$(CKSUM) $*.c

$(B2X):		b2x.c
		$(CC) -o $(B2X) b2x.c -L../lib

$(LIBFILE):	Makefile $(B2X) $(OBJS)
		$(ARC) $(OBJS)
		-$(RANLIB) $@

Gates_Win32.o:	$(XHDRS) Makefile Gates_Win32.c

files:;		@ls -d $(SRCS)
srcfiles:;	@echo $(SRCS)
clean:;		$(RM) $(LIBFILE) $(OBJS) \
			Makefile.go _.c _.o _.log mkmake.err

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

