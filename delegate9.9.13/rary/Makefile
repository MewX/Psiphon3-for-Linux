LIBFILE =	library.a

CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go CFLAGS="$(CFLAGS)" $(LIBFILE) SHELL="$(SHELL)" HDRDIR="$(HDRDIR)"
MKMAKE =	exit 1

CKSUM =		-@"$(MKMAKE)" -cksum

HDRDIR =	-I../include

#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
MKSTAB =	..\filters\mkstab.exe
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
RM =		rm -f
ARC =		$(AR) cr $@
RANLIB =	`../mimekit/mkranlib.sh`
#RANLIB =	$(AR) ts
MKSTAB =	../filters/mkstab
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) $(HDRDIR) -c $(CCINOUT)
		$(CKSUM) $*.c

FILES =		Makefile SLL.c TLEX.c String.c ystring.c modfmt.c JIS.c codeconv.c \
		pilsner.c \
		str_stdio.c \
		ccxmain.c ccx.c html.c urlesc.c \
		Strftime.c Timeofday.c strid.c hash.c bsort.c \
		codec.c uu.c \
		pstitle.c signal.c \
		IsSolaris.c \
		sched.c schedmain.c \
		tar.c sed.c \
		readycc.c fpoll.c fpolls.c frelay.c timer.c \
		nbio.c vsaddr.c pelcgb.c credhy.c cksum.c \
		asock.c lsock.c \
		setutimes.c file.c fstat.c pam.c libpam.c passwd.c syslog.c \
		lock.c \
		dglibs.c \
		forkspawn.c Thread.c randstack.c rawcopy.c \
		hostaddr.c socks5.c \
		cfilib.c \
		netsh.c \
		wince.c \
		winmo.c \
		winsspi.c winnat.c \
		winmisc.c \
		unix.c windows.c windows0.c Finish.c

OBJS =		SLL.o String.o ystring.o modfmt.o TLEX.o JIS.o codeconv.o \
		pilsner.o \
		str_stdio.o \
		ccx.o html.o urlesc.o \
		Strftime.o Timeofday.o strid.o hash.o bsort.o \
		codec.o uu.o \
		pstitle.o signal.o \
		IsSolaris.o \
		sched.o readycc.o fpoll.o fpolls.o frelay.o timer.o \
		tar.o sed.o \
		nbio.o vsaddr.o pelcgb.o credhy.o cksum.o \
		asock.o lsock.o \
		setutimes.o file.o fstat.o pam.o libpam_dl.o passwd.o syslog.o \
		lock.o \
		dglibs.o \
		forkspawn.o Thread.o randstack.o rawcopy.o \
		hostaddr.o socks5.o \
		cfilib.o \
		netsh.o \
		wince.o \
		winmo.o \
		winsspi.o winnat.o \
		winmisc.o \
		unix.o windows.o Finish.o

vsaddr.o:	../include/vsocket.h ../include/log.h vsaddr.c
windows.o:	../include/config.h windows.c windows0.c
unix.o:		../include/config.h ../include/log.h unix.c windows0.c
ystring.o:	../include/ystring.h ../include/log.h ../include/ysignal.h ystring.c
String.o:	../include/ystring.h ../include/log.h String.c
Strftime.o:	../include/ystring.h ../include/log.h ../include/ysignal.h Strftime.c
credhy.o:	../include/credhy.h ../include/log.h credhy.c
passwd.o:	../include/dgctx.h passwd.c pam.c libpam.c
pam.o:		../include/log.h pam.c
socks5.o:	../include/vaddr.h ../include/log.h ../include/dgctx.h socks5.c
dglibs.o:	../include/dgctx.h dglibs.c
pilsner.o:	../include/dgctx.h pilsner.c
file.o:		../include/file.h ../include/log.h file.c
fstat.o:	../include/file.h fstat.c
forkspawn.o:	../include/log.h ../include/ysignal.h forkspawn.c
Thread.o:	../include/log.h ../include/ysignal.h Thread.c
TLEX.o:		../include/log.h TLEX.c
randstack.o:	../include/log.h randstack.c

#---BGN---
#---END---
LIBS =		$(LIBFILE) ../lib/libmimekit.a ../lib/libcfi.a ../lib/libmd5.a ../lib/libsubst.a

all:		$(LIBFILE) ccx sched credhy

syslog.o:	../include/log.h ../include/dgctx.h syslog.c
nbio.o:		../include/log.h nbio.c
wince.o:	../include/log.h wince.c
winmo.o:	../include/log.h winmo.c
winsspi.o:	../include/log.h winsspi.c
winmisc.o:	../include/log.h winmisc.c
ttyio.o:	../include/log.h ttyio.c
winnat.o:	../include/log.h winnat.c
windows.o:	../include/log.h windows.c

ccx:		ccxmain.o $(LIBFILE)
		$(CC) ccxmain.o -o ccx ../lib/libcfi.a $(LIBS)

$(MKSTAB):	../filters/mkstab.c
		$(CC) -o $@ ../filters/mkstab.c $(LIBDIRS)

libpam_dl.c:	libpam.c $(MKSTAB)
		$(MKSTAB) < libpam.c > libpam_dl.c

credhy:		credhy4.o
		$(CC) credhy4.o -o credhy $(LIBS)

credhy4.o:	Makefile credhy.c $(LIBFILE)
		$(CC) $(HDRDIR) $(CFLAGS) -c -DMAIN -O4 credhy.c -o credhy4.o

credhyp:	Makefile credhy.c credhyp.o
		$(CC) credhyp.o -o credhyp $(LIBS) -pg

credhyp.o:	Makefile credhy.c $(LIBFILE)
		$(CC) $(CFLAGS) $(HDRDIR) -c -DMAIN credhy.c -pg -o credhyp.o

sched:		schedmain.o $(LIBFILE)
		$(CC) schedmain.o -o sched $(LIBS)

star:		tar.c $(LIBFILE)
		$(CC) -DMAIN tar.c -o star $(LIBS)

$(LIBFILE):	Makefile $(OBJS)
		-$(RM) $@
		$(ARC) $(OBJS)
		-$(RANLIB) $@

files:;		ls -d $(FILES)
srcfiles:;	@echo $(FILES)

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(FILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB
		"$(MKMAKE)" -randtext randtext.c
