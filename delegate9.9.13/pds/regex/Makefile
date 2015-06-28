#
# Regex for DeleGate
# 2010-Oct-04 <y.sato@aist.go.jp>
#
libx:		Makefile.go
		$(MAKE) -f Makefile.go CFLAGS="$(CFLAGS)" $(LIBFILE) \
			SHELL="$(SHELL)" all
Makefile.go:	Makefile
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" \
			"" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

#ifdef MSWIN ####
ARC =		lib /out:$@
CCOUT =		-Fo$*.o
#endif
#ifdef UNIX
ARC =		$(AR) cr $@
CCOUT =		-o $*.o
#endif
.c.o:;		$(CC) $(CFLAGS) -c -I. $*.c $(CCOUT)

FILES =		COPYRIGHT INSTALL Makefile README WHATSNEW mkh \
		regex2.h utils.h cclass.h cname.h engine.c \
		regcomp.c regerror.c regexec.c regfree.c \
		regdummy.c
files:;		ls -d $(FILES)
srcfiles:;	@echo $(FILES)

OBJS =		regcomp.o regexec.o regerror.o regfree.o

all:		libregex.a
		@echo "#### DONE ####"
		@ls -l libregex.a
		@echo "#### #### ####"

clean:;		rm *.ih *.o regex.h

regdummy.o:	regdummy.c
		$(CC) $(CFLAGS) -c -I. $*.c $(CCOUT)

dummy.a:	Makefile regdummy.o
		$(ARC) regdummy.o
		cp dummy.a libregex.a

libregex.a:	Makefile regex.h dummy.a $(OBJS)
		-$(ARC) $(OBJS)

.c.ih:;		sh ./mkh -p $< >$@
regcomp.ih:;	sh ./mkh -p regcomp.c > $@
engine.ih:;	sh ./mkh -p engine.c > $@
regerror.ih:;	sh ./mkh -p regerror.c > $@
regcomp.o:	Makefile regcomp.c cclass.h cname.h regcomp.ih
regexec.o:	Makefile regexec.c engine.c engine.ih
regerror.o:	Makefile regerror.c regerror.ih

# stuff to build regex.h
REGSRC=regcomp.c regerror.c regexec.c regfree.c
REGEXHSRC=regex2.h $(REGSRC)
regex.h:	$(REGEXHSRC) mkh
		sh ./mkh $(MKHFLAGS) -i _REGEX_H_ $(REGEXHSRC) >regex.h
