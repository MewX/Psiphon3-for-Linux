RANLIB = echo
LIBFILE = libsubst.a
LIBXFILE = libsubstx.a
CFLAGS = -O

MKMAKE =	../mkmake.exe
CKSUM =		-@"$(MKMAKE)" -cksum

TARGET =	all
target:		$(TARGET)
libx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBFILE) MAKEFILE=Makefile.go MKMAKE="$(MKMAKE)" SHELL="$(SHELL)" HDRDIR="$(HDRDIR)" LIBDIR="$(LIBDIR)" LDFLAGS="$(LDFLAGS)"

libxx:		Makefile.go
		$(MAKE) -f Makefile.go $(LIBXFILE) MAKEFILE=Makefile.go MKMAKE="$(MKMAKE)" SHELL="$(SHELL)" HDRDIR="$(HDRDIR)" LIBDIR="$(LIBDIR)"

#ifdef MSWIN ######################################################
HDRDIR =	-I..\include
CCINOUT =	$*.cpp -Fo$*.o
MKMKCPP =       ..\mkcpp.exe
MKCPP =         ..\mkcpp.exe < $*.c > $*.cpp
COPY =		copy
ARC =		lib /out:$@
RANLIB =	dir
RM =		del
#endif #############
#ifdef UNIX,OS2EMX ################################################
HDRDIR =	-I../include
CCINOUT =	$*.c -o $*.o
MKCPP =		-@$(MKMAKE) -noop
#COPY =		cp -p  #### not in CYGWIN32-b18
COPY =		cp
ARC =		$(AR) cr $@
#RANLIB =	ranlib
RANLIB =	$(AR) ts
RM =		rm -f
#endif #############
#ifdef NONC99 #####################################################
CCINX =		.cc
CCINOUT =	$*$(CCINX)
MKCPP =		../mkcpp $*.c $*$(CCINX)
MKMKCPP =	../mkcpp
#endif #############

SUBSTARG = "$(MAKE)" "$(MAKEFILE)" "$(CC)" "$(CFLAGS)" "$(HDRDIR)" \
	   "$(RANLIB)" "$(LIBFILE)" "$(LIBDIR)" "$(LDLIBS)" "$(LDFLAGS)" "$(SUBSTSRCS)"

SUBSTARGX = "$(MAKE)" "$(MAKEFILE)" "$(CC)" "$(CFLAGS)" "$(HDRDIR)" \
	   "$(RANLIB)" "$(LIBXFILE)" "$(LIBDIR)" "$(LDLIBS)" "$(LDFLAGS)" "$(SUBSTSRCSX)"

LIBOBJS = *.o

SUBSTSRCS0 = Makefile mkmake.c avail.c

SUBSTSRCS1 = dummy.c \
	gxx.c \
	p2ll.c p2i.c \
	dlopen.c \
	__uname.c uname.c \
	bcopy.c \
	bzero.c \
	putenv.c \
	unsetenv.c unsetenv_.c \
	__alloca.c old_alloca.c alloca.c \
	__malloc_size.c malloc_size.c \
	killpg.c \
	setsid.c \
	sigmask.c \
	sigsetmask.c \
	setresuid.c \
	seteuid.c \
	setegid.c \
	unaligned.c \
	timegm.c \
	__usleep.c usleep.c \
	__ualarm.c ualarm.c \
	_-poll.c _-select.c _-poll1.c _-poll2.c \
	_-recv.c \
	sendFd1.c sendFd2.c sendFd3.c \
	closesocket.c \
	yp_match.c \
	endhostent.c \
	gethostbyname2.c __gethostbyname2.c \
	socklen_u.c socklen_s.c \
	socketpair.c \
	inet_aton.c \
	_-setferror.c setferror.c \
	strerror.c \
	snprintf.c \
	strcasecmp.c \
	_-strcasestr.c strcasestr.c strrcasestr.c \
	strstr.c \
	strdup.c \
	strncpy.c \
	setbuffer.c \
	setlinebuf.c \
	__syslog.c syslog.c \
	__syscall.c \
	__fork.c fork.c \
	__ptrace.c _-ptrace.c ptrace.c \
	__sigaction.c sigaction.c \
	__futimes.c futimes.c futimes_.c \
	__utimes.c utimes.c

SUBSTSRCS2 = \
	fsync.c \
	__fchmod.c fchmod.c \
	__fchown.c fchown.c \
	chown.c \
	__link.c link.c \
	__symlink.c symlink.c \
	readlink.c \
	__lstat.c lstat.c \
	__statvfs.c _-statvfs.c statvfs.c \
	vfork.c \
	wait3.c \
	waitpid.c \
	getmsg.c \
	chroot.c \
	nice.c \
	__getrlimit.c getrlimit.c \
	_-getrusage.c getrusage.c \
	___spawnvp.c __spawnvp.c _spawnvp.c spawnvp.c spawnvp_.c \
	__system.c _-system.c \
	_-mutex.c mutex.c \
	__pthread_create.c ___lwp_create.c __lwp_create.c \
	_-pthread_create.c \
	__pthread_kill.c pthread_kill.c \
	___beginthread.c nothread.c \
	__flock.c _-fcntl.c \
	flockfile.c \
	FMODE.c \
	getwd.c \
	getcwd.c \
	__opendir.c __scandir.c \
	pam_start.c \
	__forkpty.c _-forkpty.c forkpty1.c forkpty.c \
	__tcsetattr.c Stty.c \
	__getwinsize.c getwinsize.c \
	_-sgTTy.c sgTTy.c \
	setlogin.c \
	_-mkfifo.c mkfifo.c \
	_-fseeko.c fseeko.c \
	_-fgetpos.c fgetpos.c \
	fpurge.c \
	stdio.c \
	pendingcc1.c pendingcc.c \
	_-fcloseFILE.c _-fcloseFILE2.c fcloseFILE.c \
	__setproctitle.c setproctitle.c \
	__sysctl.c sysctl.c __sysinfo.c __sysconf.c sysinfo.c sysctlbyname.c \
	_-sysinfo.c _-sysconf.c _-sysconf2.c \
	netsh_none.c \
	_-regex.c regex.c \
	errno.c

SUBSTSRCS3 = \
	Gates_Win32.c \
	gethostid.c \
	opt_s_vsap.c \
	opt_s_htaccept.c \
	opt_s_sox.c \
	opt_s_stls.c \
	opt_s_caps.c \
	opt_s_pilsner.c \
	opt_s_spinach.c

SUBSTSRCSX = \
	dummy.c \
	SSL_library_init.c \
	ERR_error_string_n.c \
	RSA_generate_key.c \
	SSL_set_SSL_CTX.c \
	SSL_CTX_set_tmp_rsa_callback.c

SUBSTSRCS = $(SUBSTSRCS1) $(SUBSTSRCS2) $(SUBSTSRCS3)

SRCS =	$(SUBSTSRCS0) $(SUBSTSRCS) $(SUBSTSRCSX)

.c.o:;	$(MKCPP)
	-$(CC) $(CFLAGS) -I../gen -I../src $(HDRDIR) -c $(CCINOUT)
	$(CKSUM) $*.c

#---BGN---
#---END---

all:	"$(MKMAKE)" manck $(LIBFILE)

libtemp.a: Makefile
	$(ARC) $(LIBOBJS)
	-$(RANLIB) $@
	$(COPY) $@ $(LIBFILE)
	-$(RANLIB) $(LIBFILE)

#libsubst.a: Makefile $(MKMAKE) $(SUBSTSRCS)
libsubst.a: Makefile $(SUBSTSRCS)
	-$(RM) libtemp.a
	"$(MKMAKE)" -subst libck $(SUBSTARG)
	"$(MKMAKE)" -subst libmk $(SUBSTARG) libtemp.a LIBOBJS
	"$(MKMAKE)" -subst manmk $(SUBSTARG)

#libsubstx.a: Makefile $(MKMAKE) $(SUBSTSRCSX)
libsubstx.a: Makefile $(SUBSTSRCSX)
	-$(RM) libtemp.a
	"$(MKMAKE)" -subst libck $(SUBSTARGX)
	"$(MKMAKE)" -subst libmk $(SUBSTARGX) libtemp.a LIBOBJS

_-pthread_create.o: __pthread_create.c _-pthread_create.c ../include/log.h
__pthread_create.o: __pthread_create.c _-pthread_create.c ../include/log.h
_-select.o:	../include/log.h _-select.c
opt_s_htaccept.o:	opt_s_htaccept.c ../include/dgctx.h
opt_s_pilsner.o:	opt_s_pilsner.c ../include/dgctx.h
opt_s_sox.o:		opt_s_sox.c ../include/dgctx.h
opt_s_spinach.o:	opt_s_spinach.c ../include/dgctx.h
opt_s_stls.o:		opt_s_stls.c ../include/dgctx.h
opt_s_vsap.o:		opt_s_vsap.c ../include/dgctx.h

#manck:; $(MKMAKE) manck $(SUBSTARG)
manck:; manck $(SUBSTARG)

clean:; rm -f *.o errors
files:;		ls -d $(SRCS)
srcfiles:;	@echo " $(SUBSTSRCS0) "
		@echo " $(SUBSTSRCS1) "
		@echo " $(SUBSTSRCS2) "
		@echo " $(SUBSTSRCS3) "
		@echo " $(SUBSTSRCSX) "

Makefile.go:	Makefile mkmake.c
		"$(MKMAKE)" -cksum $(SRCS)
		-"$(MKMAKE)" -unlink $(LIBFILE).list
		-"$(MKMAKE)" -unlink $(LIBXFILE).list
		"$(MKMAKE)" -mkmake "$(MAKE)" $@ "$(CC)" "$(CFLAGS)" "" "$(LDFLAGS)" "$(RANLIB)" "$(NETLIB)" NETLIB

