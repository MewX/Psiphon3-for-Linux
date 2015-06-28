# /*////////////////////////////////////////////////////////////////////////
# Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
# Copyright (c) 2001-2004 National Institute of Advanced Industrial Science and Technology (AIST)
#
# Permission to use this material for noncommercial and/or evaluation
# purpose, copy this material for your own use, and distribute the copies
# via publicly accessible on-line media, without fee, is hereby granted
# provided that the above copyright notice and this permission notice
# appear in all copies.
# AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
# MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
# OR IMPLIED WARRANTIES.
# ////////////////////////////////////////////////////////////////////////*/
# Content-Type:	program/C; charset=US-ASCII
# Program:	Makefile for DeleGate
# Author:	Yutaka Sato <ysato@delegate.org>
# Description:
# History:
#	Mar.94	created
#	970105	rewriten to port to Windows
#//////////////////////////////////////////////////////////////////////#*/

#####
##### You MUST define the following ADMIN.  It MUST be the 
##### mail address of yourself or the administrator of your delegated.
#####

ADMIN = undef
ADMINPASS =
IMPSIZE = 10000

#####
##### Don't change the following LICENSEE line if you don't have your
##### commercial license granted by AIST
#####
##### LICENSEE = "anyone for evaluation or non-commercial purpose"
LICENSEE = ""

#
#
#

SRCSIGN =	../srcsign

HLFILES =	Makefile \
		auth.h \
		hostlist.h \
		param.h \
		param.h \
		service.h \
		filter.h

LFILES =	Makefile mkmkmk.c \
		sample.shio \
		version.c \
		editconf.c admin.c notify.c shutter.c abort.c \
		form2conf.c \
		process.c \
		vaddr.c conf.c ddi.c textconv.c \
		auth.h \
		syslog.c log.c svstat.c \
		iotimeout.c \
		misc.c msg.c \
		yshell.c \
		shio.c \
		db.c \
		hostlist.h hostlist.c cond.c \
		script.c param.h param.c env.c \
		delegated.c svport.c remote.c \
		thmain.c \
		commands.c croncom.c \
		qstest.c \
		delegate.c \
		service.h service.c svconf.c \
		filter.h filter.c \
		master.c \
		spinach.c \
		caps.c \
		stls.c \
		tsp.c \
		sudo.c \
		gacl.c access.c ident.c dgauth.c dgsign.c \
		ccache.c cache.c distrib.c \
		bcounter.c \
		ipno.c \
		inets.c uns.c rident.c \
		utmpident.c \
		inetd.c \
		thruwayd.c dget.c urlfind.c \
		mount.c url.c \
		gopher.c \
		icp.c \
		icap.c \
		http.c httpx.c httplog.c httphead.c \
		httpd.c cgi.c ssi.c htaccept.c \
		htccx.c \
		htswitch.c \
		htmlgen.c \
		htfilter.c \
		nntp.c nntplist.c nntpgw.c enews.c \
		pop.c smtp.c telnet.c ftp.c xferlog.c X.c wais.c whois.c \
		xflash.c \
		imap.c \
		ldap.c smtpgate.c alias.c \
		domain.c \
		lpr.c \
		sftp.c \
		socks.c socks4.c sox.c \
		cuseeme.c coupler.c vsap.c tcprelay.c udprelay.c \
		ftpgw.c filetype.c \
		embed.c builtin.c \
		dtot.c \
		smtp_lib.c inets_lib.c

#		WhatIsDeleGate NOTE\
#		delegate_access \

FILES =		$(LFILES) builtin randld

INC_DEPEND_COMMON = \
		../include/config.h \
		../include/log.h \
		../include/vaddr.h \
		../include/vsocket.h \
		../include/ysocket.h

SRCINC_DEPEND =	../include/delegate.h ../include/dgctx.h ../include/vaddr.h ../include/ysocket.h
SRCGEN_DEPEND =	../gen/delegate.h ../gen/vaddr.h
SRC_DEPEND =	$(SRCINC_DEPEND)

GENHDR =	../gen/dglib.h \
		../gen/delegate.h \
		../gen/htswitch.h \
		../gen/ystrvec.h \
		../gen/vaddr.h \
		../gen/http.h \
		../gen/url.h \
		../gen/mime.h \
		../gen/htadmin.h

OPT_S_OBJS =	opt_s_htaccept.o \
		opt_s_sox.o \
		opt_s_stls.o \
		opt_s_vsap.o \
		opt_s_caps.o \

DOBJS =		builtin.o delegated.o commands.o croncom.o remote.o

NETYOBJS =	inets_lib.o \
		smtp_lib.o

LIBOBJS	=	version.o \
		$(SRCSIGN).o \
		editconf.o admin.o notify.o shutter.o abort.o \
		form2conf.o \
		process.o \
		vaddr.o conf.o svport.o ddi.o textconv.o \
		script.o param.o env.o \
		thmain.o \
		syslog.o log.o svstat.o \
		iotimeout.o \
		misc.o msg.o \
		yshell.o \
		shio.o \
		db.o \
		hostlist.o cond.o \
		service.o svconf.o filter.o \
		master.o \
		qstest.o \
		delegate.o \
		caps.o \
		spinach.o \
		stls.o \
		tsp.o \
		sudo.o \
		gacl.o access.o ident.o dgauth.o dgsign.o \
		ccache.o cache.o distrib.o \
		bcounter.o \
		ipno.o \
		inets.o uns.o rident.o \
		inetd.o \
		thruwayd.o dget.o urlfind.o \
		mount.o url.o \
		gopher.o \
		icp.o \
		icap.o \
		http.o httpx.o httplog.o httphead.o \
		httpd.o cgi.o ssi.o htaccept.o \
		htccx.o \
		htswitch.o \
		htmlgen.o \
		htfilter.o \
		nntp.o nntplist.o nntpgw.o enews.o \
		pop.o smtp.o telnet.o ftp.o xferlog.o X.o wais.o whois.o \
		xflash.o \
		imap.o \
		ldap.o smtpgate.o alias.o \
		domain.o \
		lpr.o \
		sftp.o \
		socks.o socks4.o sox.o \
		cuseeme.o coupler.o vsap.o tcprelay.o udprelay.o \
		ftpgw.o filetype.o

LIBSRCS =	TELEPORT=../teleport \
		FSX=../fsx \
		RESOLVY=../resolvy \
		RARY=../rary \
		MIMEKIT=../mimekit \
		CFI=../filters \
		MD5=../pds/md5 \
		REGEX=../pds/regex \
		SUBST=../maker

MYLIBDIR =	../lib

LIBNETYF =	$(MYLIBDIR)/libnety.a
LIBDGF =	$(MYLIBDIR)/libdelegate.a
LIBGATESF =	$(MYLIBDIR)/libgates.a
LIBOPT_SF =	$(MYLIBDIR)/libopt_s.a
RESOLVYF =	$(MYLIBDIR)/libresolvy.a
LIBMKITF =	$(MYLIBDIR)/libmimekit.a
TELEPORTF =	$(MYLIBDIR)/libteleport.a
LIBMD5F =	$(MYLIBDIR)/libmd5.a
LIBREGEXF =	$(MYLIBDIR)/libregex.a
LIBCFIF =	$(MYLIBDIR)/libcfi.a
LIBRARYF =	$(MYLIBDIR)/library.a

LIBSUBSTF =	$(MYLIBDIR)/libsubst.a
LIBSUBSTXF =	$(MYLIBDIR)/libsubstx.a
TYPEDEF =	typedefs
LIBFSX =	$(MYLIBDIR)/libfsx.a

MYLIBS0 =	$(RESOLVYF) \
		$(LIBMKITF) \
		$(LIBMD5F) \
		$(LIBREGEXF) \
		$(LIBRARYF) \
		$(LIBGATESF) \
		$(LIBCFIF) \
		$(LIBFSX)

MYLIBS =	$(TELEPORTF) \
		$(MYLIBS0)

EXE_DEPEND =	Makefile Makefile.go $(MYLIBS) $(LIBSUBST)

######## if you use external libresolv.a
#RESLIB =	-lresolv
######## else
RESLIB =	$(RESOLVYF)
RESLIBF =	$(RESOLVYF)
######## endif

LIBMKIT =	$(LIBMKITF)
LIBSUBST =	$(LIBSUBSTF)

#
# WSOCK32.LIB      ... socket library on Win32
# ADVAPI32.LIB     ... running as a Service on WindowsNT
#
#NETLIB =	-lnsl -lsocket WSOCK32.LIB ADVAPI32.LIB -llwp
#NETLIB =	-lnsl -lsocket WSOCK32.LIB ADVAPI32.LIB -pthread
SOLLIB =	-lnsl -lsocket -ldl -lutil -lpthread -lunalign
#SOLLIB =	-lnsl -lsocket

#ifdef MSWIN ######################################################
WINLIB =	WS2_32.LIB ADVAPI32.LIB OLE32.LIB SHELL32.LIB UUID.LIB \
		USER32.LIB \
		GDI32.LIB \
		-MT
CCLD_WIN32 =	sh ../link-win32_win8.sh
#endif ############################################################

SSLDIR =	../../SSL
SSLLIB =	$(SSLDIR)/libcrypto.a $(SSLDIR)/libssl.a -lcrypto -lssl \
		$(SSLDIR)/LIBEAY32.LIB $(SSLDIR)/SSLEAY32.LIB
NETLIB =	$(SOLLIB) $(WINLIB) -lpam -lstdc++
#NETLIB =	$(SOLLIB) $(WINLIB) -lstdc++

#IF UNIX ##########################################################
 #NETLIB =	$(SOLLIB) -lpam -lstdc++
 #CCLD_WIN32 =	-@echo ""
#FI ###############################################################

HDRDIRS =	-I../gen -I../include
LIBDIRS =	-L$(MYLIBDIR)

#ifdef MSWIN ######################################################
CFLAGSPLUS =	-nologo -DQS
EMBED =		.\embed.exe
DGEXE =		.\dg.exe
COPY =		copy
CFLAGS =	-O2 -MT -D_USE_32BIT_TIME_T
#CFLAGS =	-O2 -MT
#CFLAGS =	-O2
CCINX =		.cpp
CCINOUT =	$*$(CCINX) -Fo$*.o
MKCPPF =	..\mkcpp.exe
MKMKCPP =	$(MKCPPF)
MKCPP =		$(MKCPPF) < $*.c > $*.cpp
GENHDR_DEPEND =	$(MKCPPF) $(GENHDR)
ARC =		lib /out:$@
LDFLAGS =
RANLIB =	dir
TAR =		echo
RM =		del
EXE =		.exe
#endif #############
#ifdef OS2EMX #####################################################
EMBED =		embed.exe
LDOPTS =	-s -Zbin-files -Zbsd-signals
EXE =		.exe
#endif #############
#ifdef UNIX #######################################################
EMBED =		./embed
EXE =
SUBIN = subin
#endif #############
#ifdef UNIX,OS2EMX ################################################
CFLAGSPLUS =	if(WITHCPLUS,UNIX,OS2EMX) -x c++ -DQS
DGEXE =		./dg.exe
COPY =		cp -f -p
CFLAGS =	if(UNIX,OS2EMX) -O2
CCINX =		.c
CCINOUT =	$*$(CCINX)
MKCPP =		-@$(MKMAKE) -noop
MKCPPF =	../mkcpp
LIBC =		-lc
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
LDFLAGS =
TAR =		tar
RM =		rm -f
#endif #############
#IF QSC ####
 #CFLAGSPLUS =
#FI ########
#IF NONC99 ########################################################
 #MKMKCPP =	$(MKCPPF)
 #CCINOUT =	$*._.c -o $*.o
 #MKCPP =	$(MKCPPF) $*.c $*._.c
 #GENHDR_DEPEND = $(MKCPPF) $(GENHDR)
 #SRC_DEPEND =	$(SRCINC_DEPEND) $(SRCGEN_DEPEND)
#FI #################
#IF NONCPLUS ######## .cc will be ignored #########################
 #CFLAGSPLUS =
 #CCINOUT =	$*._.c -o $*.o
 #MKCPP =	$(MKCPPF) $*.c $*._.c
 #MKCPPFF =	$(MKCPPF)
 #SRC_DEPEND =	$(SRCINC_DEPEND) $(SRCGEN_DEPEND)
#FI #################

SRC_LOG_DEPEND = $(SRC_DEPEND) ../include/log.h


XDG = $(DGEXE)
XEMBED = $(EMBED)
TARGET = $(MKCPPFF) delegated$(EXE) $(SUBIN) $(LIBSUBSTXF)
XTARGET = $(TARGET)

MKMAKE =	../mkmake.exe
MKMKMK =	../mkmkmk.exe
LNCONF =	"$(MKMAKE)" +r -lnconf
MAKEIT =	"$(MKMAKE)"    -makeit
MAKEAT =	"$(MKMAKE)"    -makeat
CKCONF =	"$(MKMAKE)" +r -ckconf
CKSUM =		-@"$(MKMAKE)" -cksum

MAKEALL =	$(MAKEIT) "$(MAKE)" -f Makefile.go start2 \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"

#---BGN---
start0:		$(MKMAKE) Makefile.go
		@$(MAKEALL)
#---END---
start1:;	$(MAKEALL)
start2:		$(XTARGET)

LDFLAGS =	$(LDOPTS) $(LIBDIRS)
XCFLAGS =	$(CFLAGS) $(CFLAGSPLUS) $(YCFLAGS)

MAKEENV0 =	MAKE="$(MAKE)" SHELL="$(SHELL)" \
		CC="$(CC)" HDRDIR="$(HDRDIRS)" \
		RANLIB="$(RANLIB)" LDFLAGS="$(LDFLAGS)" LIBDIR="$(LIBDIRS)" \
		NETLIB="$(NETLIB)" \
		AR="$(AR)" TAR="$(TAR)"

MAKEENV =	$(MAKEENV0) CFLAGS="$(XCFLAGS)"

LIBSC0 =	$(RESLIB) $(LIBS) \
		$(TELEPORTF) $(LIBMD5F) $(LIBCFIF) $(LIBRARYF) \
		$(LIBGATESF) $(LIBMKIT) $(LIBFSX) $(NETLIB)

#LIBSC =	$(LIBSC0) $(LIBC) $(LIBREGEXF) $(LIBSUBST)
# fix-130627a added NETLIB after LIBSUBST for forkpty (Ubuntu)
LIBSC =		$(LIBSC0) $(LIBC) $(LIBREGEXF) $(LIBSUBST) $(NETLIB)

CCCO =		$(CC) $(XCFLAGS) $(HDRDIRS) -c $(CCINOUT)
CCLD =		$(CC) $(LDFLAGS) -o $@

.c.o:;		$(MKCPP)
		$(CCCO)
		$(CKSUM) $*.c

MKMAKE_SRC =	Makefile mkmkmk.c ../maker/mkmake.c ../rary/cksum.c

$(MKMAKE):	Makefile $(MKMAKE_SRC)
		-@echo "making $(MKMAKE)"
		-@ls -lt $(MKMAKE) $(MKMAKE_SRC)
		$(CC) -DMKMKMK -DDEFCC=\"$(CC)\" $(HDRDIRS) $(LIBDIRS) mkmkmk.c -o "$(MKMKMK)"
		-"$(MKMKMK)" -mkmkmk "$(CC)" $(HDRDIRS) $(LIBDIRS) ../maker/mkmake.c -o "$(MKMAKE)"
		"$(MKMAKE)" -touch ../maker/mkmake.c

DELEGATE_CONF:
		-@echo "searching $@ ..."
		$(LNCONF) $@

#CONF_IS_GOT:	$(MKMAKE) DELEGATE_CONF
CONF_IS_GOT:	DELEGATE_CONF
		echo "GOT by MKMAKE=$(MKMAKE)" > $@

Makefile.tst:	CONF_IS_GOT Makefile
		@echo "creating $@ ..."
		-@$(RM) $@
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "$(CFLAGSPLUS)" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB "" "$(SSLLIB)" SSLLIB
		"$(MKMAKE)" -touch Makefile

check_conf:
		$(CKCONF) Makefile.chk Makefile.tst DELEGATE_CONF "$(AR)" "$(ADMIN)" "$(ADMINPASS)"

Makefile.chk:	Makefile.tst
		-@$(RM) $@
		"$(MKMAKE)" -makeit "$(MAKE)" -f Makefile.tst check_conf SHELL="$(SHELL)"

dgsign.o:	Makefile.go $(SRC_LOG_DEPEND) dgsign.c
		$(MKCPP)
		$(CCCO) -DADMIN=\"$(ADMIN)\"
		$(CKSUM) dgsign.c

conf.o:		Makefile.go $(SRC_LOG_DEPEND) conf.c
		$(MKCPP)
		$(CCCO) \
			-DADMIN=\"$(ADMIN)\" \
			-DADMINPASS=\"$(ADMINPASS)\"
		$(CKSUM) conf.c

version.o:	Makefile.go $(SRC_LOG_DEPEND) version.c
		$(MKCPP)
		$(CCCO) \
			-DLICENSEE=\"$(LICENSEE)\"
		$(CKSUM) version.c

caps.o:		Makefile.go $(SRC_DEPEND) caps.c ../gen/caps.h ../include/file.h ../include/log.h
		$(MKCPP)
		$(CCCO) \
			-DADMIN=\"$(ADMIN)\" \
			-DLICENSEE=\"$(LICENSEE)\"
		$(CKSUM) caps.c

#### optional insecure ####
opt_s_caps.c:	caps.c
		cp -p caps.c opt_s_caps.c
opt_s_caps.o:	Makefile.go $(SRC_DEPEND) opt_s_caps.c ../gen/caps.h ../include/file.h ../include/log.h
		$(MKCPP)
		$(CCCO) -DOPT_S

opt_s_htaccept.c:	htaccept.c
		cp -p htaccept.c opt_s_htaccept.c
opt_s_htaccept.o:	$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h opt_s_htaccept.c ../gen/htaccept.h
		$(MKCPP)
		$(CCCO) -DOPT_S

opt_s_sox.c:	sox.c
		cp -p sox.c opt_s_sox.c
opt_s_sox.o:	$(SRC_LOG_DEPEND) ../include/credhy.h opt_s_sox.c ../gen/sox.h
		$(MKCPP)
		$(CCCO) -DOPT_S

opt_s_stls.c:	stls.c
		cp -p stls.c opt_s_stls.c
opt_s_stls.o:	$(SRC_LOG_DEPEND) ../include/dglib.h opt_s_stls.c  ../gen/stls.h
		$(MKCPP)
		$(CCCO) -DOPT_S

opt_s_vsap.c:	vsap.c
		cp -p vsap.c opt_s_vsap.c
opt_s_vsap.o:	$(SRC_LOG_DEPEND) opt_s_vsap.c ../gen/vsap.h
		$(MKCPP)
		$(CCCO) -DOPT_S

param.o:	$(SRC_LOG_DEPEND) param.h param.c

MKBUILTIN =	$(XEMBED) -IMPSIZE=$(IMPSIZE) > _builtin.c \
		"../COPYRIGHT" \
		"builtin/**/*.gif" \
		"builtin/**/*.ico" \
		"builtin/**/*.bmp" \
		"builtin/**/*.dll" \
		"builtin/**/*.dhtml" \
		"builtin/**/*.pem" \
		"builtin/**/*.cnf" \
		"builtin/**/*.cnv" \
		"builtin/config/smtpgate/**/conf"

dg.exe:		$(GENHDR_DEPEND) $(EXE_DEPEND) $(LIBDGF) $(DOBJS) $(LIBNETYF)
		"$(MKMAKE)" -randtext ../include/randtext.c
		$(MKBUILTIN)
		$(CCLD) $(DOBJS) $(LIBDGF) $(LIBSC)
		$(CCLD_WIN32)
		@echo "################"
		-$(DGEXE) -Fver
		@echo "################"
		"$(MKMAKE)" -cksum $(HLFILES)
		"$(MKMAKE)" -cksum ../maker/mkmake.c

delegated$(EXE): dg.exe
		$(COPY) dg.exe $@.sign
		-$(XDG) -Fesign -s -w $@.sign
		mv -f $@.sign $@

wince-dg.exe:	$(GENHDR_DEPEND) $(EXE_DEPEND) $(LIBDGF) $(DOBJS) $(LIBNETYF)
		sh ../link-wince.sh $@
		"$(MKMAKE)" -cksum $(HLFILES)
		"$(MKMAKE)" -cksum ../maker/mkmake.c

delegatedp:	delegated
		$(CCLD) -p $(DOBJS) $(LIBDGF) $(LIBSC)

dgp:		delegated
		$(CCLD) -pg $(DOBJS) $(LIBDGF) $(LIBSC)

url.o:		$(SRC_LOG_DEPEND) ../include/url.h url.c
		$(MKCPP)
		$(CCCO)
		$(CKSUM) url.c

qstest.o:	$(SRC_LOG_DEPEND) qstest.c
		$(MKCPP)
		$(CCCO) -DNONE
		-$(CCCO)
		$(CKSUM) qstest.c

$(LIBNETYF):	Makefile $(NETYOBJS)
		-$(RM) $@
		$(ARC) $(NETYOBJS)
		-$(RANLIB) $@

$(LIBDGF):	Makefile $(LIBOBJS)
		-$(RM) $@
		$(ARC) $(LIBOBJS)
		-$(RANLIB) $@
		"$(MKMAKE)" -touch "$@"

$(SRCSIGN).o:	Makefile $(SRCSIGN).c
		$(MKCPP)
		$(CCCO) -o $(SRCSIGN).o
		$(CKSUM) $(SRCSIGN).c

embed.o:	Makefile embed.c
		$(MKCPP)
		$(CCCO) -DADMINPASS=\"$(ADMINPASS)\" -DADMIN=\"$(ADMIN)\" \
			-DIMPSIZE=$(IMPSIZE)
		$(CKSUM) embed.c

$(EMBED):	embed.o version.o $(SRCSIGN).o $(LIBRARYF) $(LIBGATESF)
		$(CCLD) embed.o version.o $(SRCSIGN).o \
			$(LIBRARYF) $(LIBGATESF) $(LIBCFIF) $(LIBMKITF) $(LIBMD5F) \
			$(NETLIB) $(LIBC) $(LIBSUBST) $(NETLIB)

new:;		-@$(RM) _builtin.c

_builtin.c:	$(XEMBED) $(SRCSIGN).c version.c
		$(MKBUILTIN)

builtin.o:	_builtin.c builtin.c

dtot:		dtot.c
		$(MKCPP)
		$(CCLD) dtot.c

lpr:;		lpr $(FILES)

clean:;		$(RM) $(LIBOBJS) _builtin.c builtin.o \
		$(DOBJS) \
		$(LIBSUBSTF)
		$(MAKEAT) "" ../maker "" "$(MAKE)" clean

files:;		ls -d $(FILES)
srcfiles:;	@echo $(FILES)
ver:;		grep '#.*VERSION.*"' version.c|sed -e 's/^[^"]*"//' -e 's/".*//'
dgdate:;	grep '#.*DATE.*"' version.c|sed -e 's/.*	"//' -e 's/"//'


inets.o:	$(SRC_LOG_DEPEND) ../include/vsocket.h inets.c
inets_lib.o:	$(SRC_DEPEND) inets.c inets_lib.c
smtp_lib.o:	$(SRC_DEPEND) smtp.c smtp_lib.c

access.o:	$(SRC_LOG_DEPEND) hostlist.h access.c
hostlist.o:	$(SRC_LOG_DEPEND) hostlist.h hostlist.c
ident.o:	$(SRC_LOG_DEPEND) hostlist.h ident.c
master.o:	$(SRC_LOG_DEPEND) hostlist.h filter.h ../include/url.h master.c
delegated.o:	$(SRC_LOG_DEPEND) ../include/config.h ../include/yselect.h delegated.c ../include/dglib.h
env.o:		$(SRC_LOG_DEPEND) ../include/config.h param.h env.c
httplog.o:	$(SRC_LOG_DEPEND) httplog.c
log.o:		$(SRC_LOG_DEPEND) ../include/ysignal.h log.c
script.o:	$(SRC_LOG_DEPEND) script.c
service.o:	$(SRC_LOG_DEPEND) service.h filter.h service.c
svconf.o:	$(SRC_DEPEND) service.h svconf.c

admin.o:	$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h admin.c
bcounter.o:	$(SRC_LOG_DEPEND) ../include/dglib.h bcounter.c
ccache.o:	$(SRC_LOG_DEPEND) ccache.c
cgi.o:		$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h cgi.c
coupler.o:	$(SRC_DEPEND) coupler.c
croncom.o:	$(SRC_DEPEND) croncom.c
cuseeme.o:	$(SRC_DEPEND) cuseeme.c
ddi.o:		$(SRC_LOG_DEPEND) ddi.c
delegate.o:	$(SRC_DEPEND) delegate.c
dgauth.o:	$(SRC_LOG_DEPEND) ../include/credhy.h dgauth.c
dget.o:		$(SRC_LOG_DEPEND) dget.c
distrib.o:	$(SRC_LOG_DEPEND) distrib.c
domain.o:	$(SRC_LOG_DEPEND) domain.c
editconf.o:	$(SRC_DEPEND) editconf.c
filter.o:	$(SRC_LOG_DEPEND) filter.h filter.c
ftp.o:		$(SRC_LOG_DEPEND) ../include/dglib.h filter.h ftp.c
ftpgw.o:	$(SRC_LOG_DEPEND) ftpgw.c
gacl.o:		$(SRC_DEPEND) gacl.c
gopher.o:	$(SRC_LOG_DEPEND) gopher.c
htmlgen.o:	$(SRC_LOG_DEPEND) ../include/url.h htmlgen.c
htfilter.o:	$(SRC_LOG_DEPEND) htfilter.c
htswitch.o:	$(SRC_DEPEND) ../include/htswitch.h htswitch.c
htccx.o:	$(SRC_LOG_DEPEND) ../include/http.h htccx.c
http.o:		$(SRC_LOG_DEPEND) filter.h ../include/url.h ../include/http.h http.c
httpx.o:	$(SRC_LOG_DEPEND) filter.h ../include/http.h httpx.c
httpd.o:	$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h httpd.c
httphead.o:	$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h httphead.c
htaccept.o:	$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h htaccept.c ../gen/htaccept.h
imap.o:		$(SRC_LOG_DEPEND) filter.h imap.c
ldap.o:		$(SRC_DEPEND) ldap.c
mount.o:	$(SRC_LOG_DEPEND) ../include/url.h mount.c
nntp.o:		$(SRC_LOG_DEPEND) filter.h nntp.c
nntpgw.o:	$(SRC_LOG_DEPEND) ../include/ystring.h ../include/htswitch.h nntpgw.c
notify.o:	$(SRC_DEPEND) notify.c
pop.o:		$(SRC_LOG_DEPEND) filter.h pop.c
process.o:	$(SRC_LOG_DEPEND) process.c
rident.o:	$(SRC_DEPEND) rident.c
shutter.o:	$(SRC_LOG_DEPEND) shutter.c
smtp.o:		$(SRC_LOG_DEPEND) ../include/ystring.h filter.h smtp.c
smtpgate.o:	$(SRC_LOG_DEPEND) smtpgate.c
socks.o:	$(SRC_LOG_DEPEND) socks.c
sox.o:		$(SRC_LOG_DEPEND) ../include/credhy.h sox.c ../gen/sox.h
ssi.o:		$(SRC_LOG_DEPEND) ../include/url.h ../include/http.h ssi.c
stls.o:		$(SRC_LOG_DEPEND) ../include/dglib.h stls.c ../gen/stls.h
svport.o:	$(SRC_LOG_DEPEND) ../include/yselect.h svport.c
tcprelay.o:	$(SRC_LOG_DEPEND) tcprelay.c
telnet.o:	$(SRC_LOG_DEPEND) telnet.c
textconv.o:	$(SRC_LOG_DEPEND) textconv.c
thmain.o:	$(SRC_LOG_DEPEND) thmain.c
thruway.o:	$(SRC_DEPEND) thruway.o
udprelay.o:	$(SRC_LOG_DEPEND) udprelay.c
vaddr.o:	$(SRC_DEPEND) vaddr.c
vsap.o:		$(SRC_LOG_DEPEND) vsap.c ../gen/vsap.h
wais.o:		$(SRC_LOG_DEPEND) wais.c
whois.o:	$(SRC_LOG_DEPEND) whois.c
X.o:		$(SRC_LOG_DEPEND) X.c
yshell.o:	$(SRC_LOG_DEPEND) yshell.c
../include/yselect.h:	../include/ywinsock.h

cache.o:	$(SRC_LOG_DEPEND) cache.c
commands.o:	$(SRC_LOG_DEPEND) commands.c
cond.o:		$(SRC_LOG_DEPEND) cond.c
filetype.o:	$(SRC_LOG_DEPEND) filetype.c
form2conf.o:	$(SRC_LOG_DEPEND) form2conf.c
icap.o:		$(SRC_LOG_DEPEND) icap.c
icp.o:		$(SRC_LOG_DEPEND) icp.c
inetd.o:	$(SRC_LOG_DEPEND) inetd.c
iotimeout.o:	$(SRC_LOG_DEPEND) iotimeout.c
lpr.o:		$(SRC_LOG_DEPEND) lpr.c
misc.o:		../include/log.h misc.c
sftp.o:		$(SRC_LOG_DEPEND) sftp.c
spinach.o:	$(SRC_LOG_DEPEND) spinach.c
shio.o:		$(SRC_LOG_DEPEND) shio.c
socks4.o:	$(SRC_LOG_DEPEND) socks4.c
sudo.o:		$(SRC_LOG_DEPEND) sudo.c
svstat.o:	../include/log.h svstat.c
syslog.o:	$(SRC_LOG_DEPEND) syslog.c
thruwayd.o:	$(SRC_LOG_DEPEND) thruwayd.c
tsp.o:		$(SRC_LOG_DEPEND) tsp.c
uns.o:		../include/log.h uns.c

MKAT =		$(MAKEAT) $@
LMAKE0 =	"$(MAKE)" libx $(MAKEENV0) CFLAGS="$(CFLAGS)"
LMAKE =		"$(MAKE)" libx $(MAKEENV)
LIB_DEPEND0 =	Makefile.go ../include/dgctx.h
LIB_DEPEND =	$(LIB_DEPEND0) $(INC_DEPEND_COMMON)

filters:
		$(MAKEAT) "" ../filters     "" \
			"$(MAKE)" filters $(MAKEENV) \
			CFLAGS="$(XCFLAGS)" LIBSC="$(LIBSC)" LIBDGF=-ldelegate

subin:		../subin/dgpam ../lib/library.a

SUBIN_DEPEND =	../subin/Makefile \
		../subin/dgpam.c \
		../subin/dgforkpty.c ../rary/netsh.c ../maker/_-sgTTy.c \
		../rary/pam.c

../subin/dgpam: $(SUBIN_DEPEND)
		$(MAKEAT) "" ../subin       "" \
			"$(MAKE)" commands $(MAKEENV) \
			CFLAGS="$(XCFLAGS)" LIBSC="$(LIBSC)" LIBDGF=-ldelegate

$(MKCPPF):	../include/mkcpp.c ../putsigned.c
		$(CC) -o $@ ../include/mkcpp.c $(LIBDIRS)

../gen/mime.h:		$(MKCPPF) ../include/mime.h
			$(MKCPPF) ../include/mime.h $@
../gen/dglib.h:		$(MKCPPF) ../include/dglib.h
			$(MKCPPF) ../include/dglib.h $@
../gen/delegate.h:	$(MKCPPF) ../include/delegate.h
			$(MKCPPF) ../include/delegate.h $@
../gen/htswitch.h:	$(MKCPPF) ../include/htswitch.h
			$(MKCPPF) ../include/htswitch.h $@
../gen/ystrvec.h:	$(MKCPPF) ../include/ystrvec.h
			$(MKCPPF) ../include/ystrvec.h $@
../gen/vaddr.h:		$(MKCPPF) ../include/vaddr.h
			$(MKCPPF) ../include/vaddr.h $@
../gen/http.h:		$(MKCPPF) ../include/http.h
			$(MKCPPF) ../include/http.h $@
../gen/url.h:		$(MKCPPF) ../include/url.h
			$(MKCPPF) ../include/url.h $@
../gen/htadmin.h:	$(MKCPPF) ../include/htadmin.h
			$(MKCPPF) ../include/htadmin.h $@

../gen/caps.h:		$(MKCPPF) ../dgcaps.h caps.c
			$(MKCPPF) caps.c $@ -sign
../gen/stls.h:		$(MKCPPF) ../dgcaps.h stls.c
			$(MKCPPF) stls.c $@ -sign
../gen/vsap.h:		$(MKCPPF) ../dgcaps.h vsap.c
			$(MKCPPF) vsap.c $@ -sign
../gen/sox.h:		$(MKCPPF) ../dgcaps.h sox.c
			$(MKCPPF) sox.c $@ -sign
../gen/htaccept.h:	$(MKCPPF) ../dgcaps.h htaccept.c
			$(MKCPPF) htaccept.c $@ -sign

TYPEDEFS_H = ../include/typedefs.h
typedefs:	$(TYPEDEFS_H)
$(TYPEDEFS_H):	Makefile.go ../include/Makefile ../include/mkdef
		$(MAKEAT) "" ../include "" $(LMAKE)

$(TELEPORTF):	$(LIB_DEPEND) $(LIBSRC_TELEPORT)
		$(MKAT) ../teleport libteleport.a $(LMAKE)

$(RESOLVYF):	$(LIB_DEPEND) $(LIBSRC_RESOLVY)
		$(MKAT) ../resolvy  libresolvy.a  $(LMAKE)

$(LIBRARYF):	$(LIB_DEPEND) $(LIBSRC_RARY) ../include/ysignal.h
		$(MKAT) ../rary     library.a     $(LMAKE)

$(LIBMKITF):	$(LIB_DEPEND) $(LIBSRC_MIMEKIT) ../include/mime.h
		$(MKAT) ../mimekit  libmimekit.a  $(LMAKE)

$(LIBCFIF):	$(LIB_DEPEND) $(LIBSRC_CFI) ../include/ysignal.h
		$(MKAT) ../filters  libcfi.a      $(LMAKE) SSLLIB="$(SSLLIB)"

$(LIBMD5F):	$(LIB_DEPEND) $(LIBSRC_MD5)
		$(MKAT) ../pds/md5  libmd5.a      $(LMAKE)

$(LIBREGEXF):	$(LIB_DEPEND) $(LIBSRC_REGEX)
		-$(MKAT) ../pds/regex libregex.a  $(LMAKE0)
		-cp -p ../pds/regex/libregex.a ../lib
		-cp -p ../pds/regex/regex.h ../gen

$(LIBSUBSTF):	$(LIB_DEPEND0) $(LIBSRC_SUBST) $(LIBOPT_SF) ../include/log.h
		$(MKAT) ../maker    libsubst.a    $(LMAKE) \
			LDFLAGS="$(LDFLAGS)" \
			LDLIBS="$(LIBSC0) $(LIBRARYF) $(LIBGATESF) $(LIBC)"

$(LIBSUBSTXF):	$(LIB_DEPEND0) $(LIBSRC_SUBSTX) $(LIBSUBSTF)
		$(MKAT) ../maker    libsubstx.a \
			"$(MAKE)" libxx $(MAKEENV) \
			LDLIBS="$(NETLIB) $(SSLLIB)"

fsx:		delegated$(EXE) $(LIBFSX)
$(LIBFSX):	$(LIB_DEPEND) $(LIBSRC_FSX) ../include/vaddr.h
		$(MKAT) ../fsx  libfsx.a $(LMAKE)

Makefile.go:	Makefile.chk ../maker/Makefile $(MKMAKE)
		"$(MKMAKE)" -cksum $(LFILES)
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "$(CFLAGSPLUS)" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB "$(LIBSRCS)" "$(SSLLIB)" SSLLIB

$(LIBGATESF):	Makefile ../gates/Makefile
		$(MKAT) ../gates libgates.a $(LMAKE)

$(LIBOPT_SF):	Makefile $(OPT_S_OBJS)
		-$(RM) $@
		$(ARC) $(OPT_S_OBJS)
		-$(RANLIB) $@

