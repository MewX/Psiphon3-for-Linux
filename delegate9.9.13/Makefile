FILE0 =	COPYRIGHT LICENSE.txt LICENSE-ja.txt \
	CONTENTS.txt \
	Makefile \
	Makefile.QSC \
	make-init.sh \
	make-fin.sh \
	link-win32_win8.sh \
	install.sh dg9.conf.txt install-chroot.sh setup-subin.sh \
	README INSTALL README.5-6 README.7-8 README.MAKE CREDITS INSTALL.txt \
	IPv6NOTE.txt \
	DG9note.html \
	id.shtml \
	gen/README \
	CHANGES lib/README mkmkmk.c

DGDATE =`cd src;       $(MAKE) -s dgdate`
VER =	`cd src;       $(MAKE) -s ver`
DVER =	`cd src;       $(MAKE) -s ver | sed 's/\./_/g'`
SRC =	`cd src;       $(MAKE) -s files | sed "s:^:src/:"`
DOC =	`cd doc;       $(MAKE) -s files | sed "s:^:doc/:"`
ANN =   `cd announce;  ls -d *          | sed "s:^:announce/:"`
MD5 =	`cd pds/md5;   $(MAKE) -s files | sed "s:^:pds/md5/:"`
REGEX =	`cd pds/regex; $(MAKE) -s files | sed "s:^:pds/regex/:"`
RARY =	`cd rary;      $(MAKE) -s files | sed "s:^:rary/:"`
BIN =	`cd bin;       $(MAKE) -s files | sed "s:^:bin/:"`
SUBIN =	`cd subin;     $(MAKE) -s files | sed "s:^:subin/:" `
TLPT =	`cd teleport;  $(MAKE) -s files | sed "s:^:teleport/:"`
FSX =	`cd fsx;       $(MAKE) -s files | sed "s:^:fsx/:"`
FLTR =	`cd filters;   $(MAKE) -s files | sed "s:^:filters/:"`
RSLV =	`cd resolvy;   $(MAKE) -s files | sed "s:^:resolvy/:"`
MIME =	`cd mimekit;   $(MAKE) -s files | sed "s:^:mimekit/:"`
SUBST =	`cd maker;     $(MAKE) -s files | sed "s:^:maker/:"`
GATES = `cd gates;     $(MAKE) -s files | sed "s:^:gates/:"`
HDRS =	`ls -d include/*.h include/Makefile include/mkcpp.c include/mkdef include/typedefs.c`

PDS =	$(MD5) $(REGEX)

FILEA = $(PDS) $(SRC) $(RARY) $(BIN) $(SUBIN) $(DOC) $(TLPT) \
	$(FSX) $(FLTR) $(RSLV) $(SUBST) $(GATES) $(HDRS)

FILEB = $(FILE0) $(PDS) $(SRC) $(RARY) $(BIN) $(SUBIN) $(DOC) $(TLPT) \
	$(FSX) $(FLTR) $(RSLV) $(SUBST) $(GATES) $(HDRS) $(ANN)

FILEC =	rw.c ck.c qastrip.c srcsign.c srcsign srcvrfy newdist cksums \
	putsigned.c \
	dgcaps.h \
	rsasign \
	bench \
	tc \
	mkdist.sh mkdist-win.sh \
	make-xcc make-vc.bat make-vc95.bat make-vc.sh link-wince.sh \
	link-win32.sh \
	link-libs.sh \
	src/win32-dg.rc src/win32-dg.res \
	make-vce.sh make-vs8ce.bat make-vs8ce_win8.bat include-ce DELEGATE_CONF.vce \
	make-vs8.bat make-vs9.bat make-vs8_win8.bat \
	src/delegated.conf \
	src-srcsign.c \
	srcfiles \
	$(FILEB)

FILES = $(FILEC) $(MIME)

MKMKMK = mkmkmk.exe
MKMAKE = mkmake.exe

HDRDIRS = -I../gen -I../include $(CFLAGS)
LIBDIRS = -L../lib
PLIBDIRS = -Llib

XDG =	src/dg.exe
SIGNDG = delegated ### src/delegated is not available in source directory

all:	$(MKMAKE)
	-rm srcsign.o
	sh make-init.sh
	@"./$(MKMAKE)" -makeat "" src dg.exe \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"
	sleep 1
	"$(XDG)" "-Fsrcmd5" -csrc -f srcfiles -type f -o gen/bldsign.h
	rm src/dg.exe
	-rm src/delegated
	rm src/builtin.o
	rm src/_builtin.c
	@"./$(MKMAKE)" -makeat "" src delegated \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"
	@echo "================"
	-"$(XDG)" "-Fsrcmd5" -f srcfiles -type f
	-"$(XDG)" "-Fcksum" -x -c -f srcfiles
	@echo "====FINISHED===="
	-sh make-fin.sh

all1:	$(MKMAKE)
	@"./$(MKMAKE)" -makeat "" src dg.exe \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"

wince-dg.exe:
	sh make-init.sh
	@"./$(MKMAKE)" -makeat "" src $@ \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"
	"$(XDG)" "-Fsrcmd5" -csrc -f srcfiles -type f -o gen/bldsign.h
	rm src/$@
	rm src/builtin.o
	@"./$(MKMAKE)" -makeat "" src $@ \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"
	"$(XDG)" "-Fesign" src\$@
	-sh make-fin.sh

$(MKMAKE): Makefile src/Makefile mkmkmk.c maker/mkmake.c
	-sh link-libs.sh
	$(CC) -DMKMKMK -DDEFCC=\"$(CC)\" $(HDRDIRS) $(PLIBDIRS) mkmkmk.c -o $(MKMKMK)
	-"./$(MKMKMK)" -mkmkmk "$(CC)" $(HDRDIRS) $(PLIBDIRS) maker/mkmake.c -o $@

sslway:	$(MKMAKE)
	@"./$(MKMAKE)" -makeat "" filters filters/sslway \
		"$(MAKE)" _SSLway \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"

mime: $(MKMAKE)
	"./$(MKMAKE)" -makeat "" src dg.exe \
		"$(MAKE)" MKMAKE_SRC="" \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)"
	"./$(MKMAKE)" -makeat "" mimekit mimekit/enMime \
		"$(MAKE)" -f Makefile.go all1 \
		SHELL="$(SHELL)" HDRDIRS="$(HDRDIRS)" LIBDIRS="$(LIBDIRS)" \
		M17NLIB="-L../lib -lcfi -lrary -lmd5 -lsubst"
	ls -l mimekit/*Mime

any2fdif:
	@"./$(MKMAKE)" -makeat "" src fsx $(MAKE) -f Makefile.go fsx
	@"./$(MKMAKE)" -makeat "" fsx any2fdif $(MAKE) -f Makefile.go

## the following target should not be "file:" to avoid loop of "make -s files"
## or "make -s srcmd5s", on error in chdir like SUBST=`cd maker; ...`
Files:;	@echo $(FILES)
filel:;	@ls -d $(FILES) | cat

ver:;	echo $(VER)
dgdate:; echo $(DGDATE)
ctar:;	tar cf core-delegate$(VER).tar $(FILEC)

DATE = `date "+%y%m%d%H"`
dtar:	tar
	mv delegateX$(VER).tar dgX$(DATE).tar
	gzip $$DTARARGS dgX$(DATE).tar
	ls -l dgX$(DATE).tar.gz
tar:
	src/delegated -Fesign -w rary/windows.c
	echo $(FILEB) $(MIME) | tr ' ' '\n' | src/delegated -Fsort > srcfiles
	srcsign
	tar cf delegateX$(VER).tar $(FILES)
	echo $(VER)

rtar:
	tar cf dgX$(DATE)-$(VER).tar $(FILES)
tarcf:
	@tar cf - $(FILES)

sum:
	"$(XDG)" "-Fcksum" -x -c -f srcfiles
sumv:
	"$(XDG)" "-Fcksum" -x -c -v -f srcfiles

srcmd5:
	find $(FILEB) $(MIME) -type f -print|$(SIGNDG) -Fsort|xargs cat|$(SIGNDG) -FMD5

srcmd5f:
	$(SIGNDG) -Ffindu $(FILEB) $(MIME) -type f -print|$(SIGNDG) -Fsort|$(SIGNDG) -FMD5 -c -f -

srcmd5i:
	"$(XDG)" "-Fsrcmd5" -csrc $(FILEB) $(MIME) -type f
srcmd5iv:
	"$(XDG)" "-Fsrcmd5" -v -csrc $(FILEB) $(MIME) -type f

srcmd5s:
	$(SIGNDG) -Fsrcmd5 -s $(FILEB) $(MIME) -type f
srcmd5sv:
	$(SIGNDG) -Fsrcmd5 -s $(FILEB) $(MIME) -type f -v
srcmd5v:
	$(SIGNDG) -Fsrcmd5 -f srcfiles -type f -v

srcmd5ss:
	$(SIGNDG) -Fsrcmd5 -s -f srcfiles -type f

srcfiles: Makefile
	echo $(FILEB) $(MIME) | tr ' ' '\n' | $(SIGNDG) -Fsort > srcfiles

bldsign:
	"$(XDG)" "-Fsrcmd5" -csrc $(FILEB) $(MIME) -type f -o gen/bldsign.h

qastrip:	qastrip.c
	$(CC) -x c++ -DQS -o qastrip -O3 -Iinclude qastrip.c -Llib -lrary -lmimekit -lsubst -lmd5

xtar:	tar
	src/delegated -Fstar f delegate$(VER).tar -e s:^:dg$(DVER)/: > dg$(DVER).tar
	rm delegate$(VER).tar

clean:;	rm -f src/Makefile.chk src/Makefile.tst \
	mkcpp src/embed src/dg.exe srcsign.o \
	mkmake.exe mkmkmk.exe \
	subin/dgbind subin/dgchroot subin/dgcpnod subin/dgpam subin/dgdate \
	*/mkmake.err */*.go */*.cpp */*.o */*.a \
	pds/md5/*.o pds/md5/*.go \
	include/randtext.c rary/randtext.c \
	maker/*.list maker/libsubst.a.mani \
	filters/mkstab filters/gzip_dl.c filters/sslway_dl.c \
	src/CONF_IS_GOT src/_builtin.c src/_.c
	cd mimekit; make clean
	cd resolvy; make clean

zip:
	cp -p src/delegated.exe dg$(DVER).exe
	zip dg$(DVER).zip \
		COPYRIGHT \
		CHANGES \
		README \
		DG9note.html \
		doc/Manual.htm \
		doc/tutor-en.htm \
		doc/tutor-jp.htm \
		dg$(DVER).exe
