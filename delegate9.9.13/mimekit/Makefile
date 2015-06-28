#
#	MIME Kit 1.9
#
#	99.10.xx  Yutaka Sato <ysato@etl.go.jp>
#

MYNAME =	mimekit
VERSION =	1.9
MYNAMEVER =	$(MYNAME)$(VERSION)
TARFILE =	$(MYNAMEVER).tar

#MIMECONV = "C_DECODE(C_HEAD_CHAR|C_BODY_CHAR)"
MIMECONV =	"C_DECODE(C_HEAD|C_BODY)|C_ENCODE(C_HEAD|C_BODY)"
#MIMECONV =	0

#
#
#

LIBFILE =	libmimekit.a

CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) XOBJS="" MKMAKE="$(MKMAKE)" SHELL="$(SHELL)" HDRDIR="$(HDRDIR)" RANLIB="$(RANLIB)"
MKMAKE =	exit 1

#ifdef MSWIN ######################################################
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
ARC =		lib /out:$@
RANLIB =	dir
DIFF =		dir
CAT =		type
RM =		del
DGDIR =		..\src
#MKMAKE =	$(DGDIR)\mkmake.exe
#LKFILE =	"$(MKMAKE)" -lkfile
LKFILE =	copy
TEST =		enMime<sample|deMime|enMime|deMime
#endif #############
#ifdef OS2EMX #####################################################
LKFILE =	cp
TEST =		enMime<sample|deMime|enMime|deMime
#endif #############
#ifdef UNIX #######################################################
LKFILE =	ln -s
TEST =		./enMime<sample|./deMime|./enMime|./deMime
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
ARC =		$(AR) cr $@
#RANLIB =	$(AR) ts
RANLIB =	`./mkranlib.sh`
DIFF =		diff
CAT =		cat
RM =		rm -f
DGDIR =		../src/
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

INSTDIR =	/usr/local

LOCALFILES =	README \
		README-LIB \
		README-PGP \
		CHANGES \
		ISO2022JP \
		Makefile \
		mkranlib.sh \
		sample \
		mimecodes.c \
		mime.c \
		pgp.c \
		rfc822.c \
		mimehead.c \
		mimeh_ovw.c \
		mimeconv.c \
		mimemain.c \
		noxlib.c \
		gendom.c

SHAREFILES =	str_codes.c

XSRCS =		ystring.h yarg.h file.h log.h \
		String.c ystring.c rawcopy.c TLEX.c \
		str_stdio.h str_stdio.c \
		codeconv.c JIS.c uu.c html.c \
		file.c syslog.c windows0.c \
		strdup.c strstr.c strcasecmp.c strcasestr.c bcopy.c

#PROF =		-p -DSTATIC= -DPROF
#PROF =		-DSTATIC=static

SRCS =		$(LOCALFILES) $(SHAREFILES)
FILES =		$(LOCALFILES) $(SHAREFILES) $(XSRCS)

#STRFUNCS =	strdup.o strstr.o strcasecmp.o strcasestr.o bcopy.o
STRFUNCS =	strcasestr.o

XOBJS =		String.o ystring.o rawcopy.o str_stdio.o \
		TLEX.o codeconv.o JIS.o html.o file.o \
		syslog.o windows0.o \
		$(STRFUNCS)

OBJS =		mimeconv.o mimecodes.o \
		mime.o pgp.o rfc822.o mimehead.o mimeh_ovw.o \
		str_codes.o \
		gendom.o

ALL =		uu.o enMime deMime test.out
TAR =		tar

CCCO =		$(CC) $(PROF) $(CFLAGS) $(HDRDIR) -I. $(CCINOUT) -c -DMIMEKIT

CKSUM =		-@"$(MKMAKE)" -cksum
.c.o:;		$(MKCPP)
		-$(RM) $@
		$(CCCO)
		$(CKSUM) $*.c

NOM17NLIB =	noxlib.a
M17NLIB =	$(NOM17NLIB)

#---BGN---
#---END---

all:
	@echo "#### ---- NOTICE ----"
	@echo "#### You need to do "make mime" at the upper directory"
	@echo "#### (cd ..; make; make mime)"
	@echo "#### ----------------"

all1:		$(SHAREFILES) $(XSRCS) $(LIBFILE) $(NOM17NLIB) $(ALL)

$(LIBFILE):	Makefile $(OBJS)
		-$(RM) $@
		$(ARC) $(OBJS)
		-$(RANLIB) $@

$(NOM17NLIB):	$(XOBJS) noxlib.o
		$(ARC) $(XOBJS) noxlib.o

mime.o:		Makefile ../include/mime.h mime.c
		$(MKCPP)
		$(CCCO) -DMIMECONV=$(MIMECONV)
		$(CKSUM) mime.c

mimehead.o:	Makefile ../include/mime.h mimehead.c

enMime:		mimemain.c $(LIBFILE)
		$(CC) $(CFLAGS) -c -DENMIME  mimemain.c
		$(CC) -o $@ uu.o mimemain.o $(LIBFILE) $(NETLIB) $(M17NLIB)

deMime:		mimemain.c $(LIBFILE)
		$(CC) $(CFLAGS) -c -DDEMIME  mimemain.c
		$(CC) -o $@ uu.o mimemain.o $(LIBFILE) $(NETLIB) $(M17NLIB)


fromMime:	mimemain.c $(LIBFILE)
		$(CC) $(CFLAGS) -c -DMIME2LOCAL mimemain.c
		$(CC) -o fromMime mimemain.o $(LIBFILE)

toMime:		mimemain.c $(LIBFILE)
		$(CC) $(CFLAGS) -c -DLOCAL2MIME mimemain.c
		$(CC) -o toMime   mimemain.o $(LIBFILE)

test.out:	Makefile sample enMime deMime
		$(TEST)>sample.out
		-$(DIFF) sample sample.out > test.out
		-$(CAT) test.out

dist:		dist/$(TARFILE)
dist/$(TARFILE):	$(TARFILE)
		-mkdir dist
		-rm -r $(MYNAMEVER)
		mkdir $(MYNAMEVER)
		cd $(MYNAMEVER); tar xfv ../$(TARFILE)
		tar cfv $@ $(MYNAMEVER)
		gzip $@

tar:		$(TARFILE)
$(TARFILE):	$(FILES)
		$(TAR) cfh $@ $(FILES)
files:;		ls -d $(LOCALFILES) $(SHAREFILES)
srcfiles:;	@echo $(LOCALFILES) $(SHAREFILES)

clean:;		-$(RM) $(OBJS) $(LIBFILE) toMime fromMime \
		enMime deMime test.out sample.out

install:	deMime enMime $(LIBFILE)
		install -o bin -g bin -m 755 deMime $(INSTDIR)/bin
		install -o bin -g bin -m 755 enMime $(INSTDIR)/bin

#		install -o root -g staff -m 644 $(LIBFILE) $(INSTDIR)/lib
#		-$(RANLIB) $(INSTDIR)/lib/$(LIBFILE)

String.o:	ystring.h ystrvec.h String.c

dgctx.h:;	$(LKFILE) ../include/dgctx.h
ystring.h:;	$(LKFILE) ../include/ystring.h
ystrvec.h:;	$(LKFILE) ../include/ystrvec.h .
ysignal.h:;	$(LKFILE) ../include/ysignal.h .
vsignal.h:;	$(LKFILE) ../include/vsignal.h .
yarg.h:;	$(LKFILE) ../include/yarg.h
file.h:;	$(LKFILE) ../include/file.h
log.h:;		$(LKFILE) ../include/log.h
str_stdio.h:;	$(LKFILE) ../include/str_stdio.h .
str_stdio.c:;	$(LKFILE) ../rary/str_stdio.c .
html.c:;	$(LKFILE) ../rary/html.c .
file.c:;	$(LKFILE) ../rary/file.c .
JIS.c:;		$(LKFILE) ../rary/JIS.c .
codeconv.c:;	$(LKFILE) ../rary/codeconv.c .
uu.c:;		$(LKFILE) ../rary/uu.c .
String.c:;	$(LKFILE) ../rary/String.c .
TLEX.c:;	$(LKFILE) ../rary/TLEX.c .
bcopy.c:;	$(LKFILE) ../maker/bcopy.c .
strdup.c:;	$(LKFILE) ../maker/strdup.c .
strstr.c:;	$(LKFILE) ../maker/strstr.c .
strcasecmp.c:;	$(LKFILE) ../maker/strcasecmp.c .
strcasestr.c:;	$(LKFILE) ../maker/strcasestr.c .
syslog.c:;	$(LKFILE) ../rary/syslog.c .
windows0.c:;	$(LKFILE) ../rary/windows0.c .
rawcopy.c:;	$(LKFILE) ../rary/rawcopy.c .
ystring.c:;	$(LKFILE) ../rary/ystring.c .
randstack.c:;	$(LKFILE) ../rary/randstack.c .

syslog.o:	syslog.c dgctx.h
ystring.o:	ystring.h ysignal.h vsignal.h ystring.c
		$(MKCPP)
		-$(RM) $@
		$(CCCO) -DEMU_NO_VSNPRINTF=0

str_codes.o:	str_codes.c mimecodes.c

Makefile.go:	Makefile
		"$(MKMAKE)" -cksum $(SRCS)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB
