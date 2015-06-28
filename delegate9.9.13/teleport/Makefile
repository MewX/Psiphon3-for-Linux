#
#	Teleport-Vehicle/0.0
#			June 1995, <ysato@etl.go.jp>
#

LIBFILE =	libteleport.a

TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"
MKMAKE =	exit 1

CFLAGS =	-O
HDRDIR =	-I../include

#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
ARC =		lib.exe /out:$@
RANLIB =	echo
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
RM =		rm -f
#endif #############
#IF NONC99 #####################################################
 #CCINOUT =	$*._.c -o $*.o
 #MKCPP =	../mkcpp $*.c $*._.c
 #MKMKCPP =	../mkcpp
#FI ################

FILES =		README Makefile teleport.h teleportd.c vehicle.c qzcode.c qz.c

CKSUM =		-@"$(MKMAKE)" -cksum
.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) -I../gen $(HDRDIR) -c $(CCINOUT)
		$(CKSUM) $*.c

LIBOBJS =	teleportd.o vehicle.o qzcode.o
teleportd.o:	teleportd.c ../include/dgctx.h

#---BGN---
#---END---

all:

$(LIBFILE):	Makefile $(LIBOBJS)
		-$(RM) $@
		$(ARC) $(LIBOBJS)
		-$(RANLIB) $@

qz:		qz.o qzcode.o 
		$(CC) -o qz qz.o qzcode.o

files:;         ls -d $(FILES)
srcfiles:;	@echo $(FILES)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

