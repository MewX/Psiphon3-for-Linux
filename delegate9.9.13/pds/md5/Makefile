LIBFILE =	libmd5.a
CFLAGS =	-O
TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go CFLAGS="$(CFLAGS)" $(LIBFILE) SHELL="$(SHELL)"
MKMAKE =	exit 1
Makefile.go:	Makefile
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

#ifdef MSWIN ######################################################
CCINX =		.c
CCOUT =		-Fo$*.o -TP
RM =		del
ARC =		lib /out:$@
RANLIB =	dir
#endif #############
#ifdef UNIX,OS2EMX ################################################
CCINX =		.c
CCOUT =
RM =		rm -f
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../../mkcpp
#endif #############

.c.o:;		$(MKCPP)
		$(CC) $(CFLAGS) -c $*$(CCINX) $(CCOUT)


RFC = rfc1321.txt
SRCS = global.h md5.h md5c.c md5cb.c mddriver.c

all:	$(LIBFILE)
lib:	$(LIBFILE)

#---BGN---
#---END---

$(LIBFILE): md5c.o md5cb.o md5lib.o md5main.o
	-$(RM) $@
	$(ARC) md5c.o md5cb.o md5lib.o md5main.o
	-$(RANLIB) $@

MD5:	Makefile md5c.o md5cb.o mddriver.o
	$(CC) $(CFLAGS) -o $@ md5c.o md5cb.o mddriver.o

md5c.o:	Makefile md5c.c global.h md5.h
	$(MKCPP)
	$(CC) $(CFLAGS) $(CCOUT) -c md5c$(CCINX)

md5cb.o:	md5cb.c
	$(MKCPP)
	$(CC) $(CFLAGS) $(CCOUT) -c md5cb$(CCINX)
#	$(CC) -c -O $(CCOUT) md5cb$(CCINX)  #### this was for (old?) BC-Gcc

mddriver.o: Makefile mddriver.c global.h md5.h
	$(MKCPP)
	$(CC) $(CFLAGS) $(CCOUT) -c -DMD=5 mddriver$(CCINX)

md5main.o: Makefile mddriver.c global.h md5.h md5main.c
	$(MKCPP)
	$(CC) $(CFLAGS) $(CCOUT) -c -DMD=5 md5main$(CCINX)

global.h:;	sed -n '/^A.1/,/^A.2/p' $(RFC) | ./comskip > $@
md5.h:;		sed -n '/^A.2/,/^A.3/p' $(RFC) | ./comskip > $@
md5c.c:;	sed -n '/^A.3/,/^A.4/p' $(RFC) | ./comskip > $@
md5cb.c:;	sed -n '/^A.3/,/^A.4/p' $(RFC) | ./comskip | sed -n '/^static void MD5_memset.(/,$$p' >$@
mddriver.c:;	sed -n '/^A.4/,/^A.5/p' $(RFC) | ./comskip > $@

clean:;	rm -f mddriver.o $(SRCS)
Clean:; rm -f *.o $(LIBFILE)

FILES = $(RFC) Makefile md5main.c md5lib.c comskip $(SRCS)
files:	$(FILES)
		ls -d $(FILES)
srcfiles:;	@echo $(FILES)
