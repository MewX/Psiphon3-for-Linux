/*
 * Sgtty.c: extracted from COMSOS (2010/01/17)
 *
 * cosmos/SYS/IOCTL.h
 * cosmos/SYS/ioctl.c
 * cosmos/SYS/WINS.h
 * cosmos/SYS/stty.h
 * cosmos/DLL/0cosmos.c
 * cosmos/SYS/cwin.c
 */
int _PollIn1(int fd,int timeout);

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
#if defined(__cplusplus)
extern "C" {
#endif
*/

static void *STRUCT_ALLOC(size_t siz){ return calloc(1,siz); }

#include "fpoll.h"
#ifdef MAIN
#define _PollIn1(f,t) 1
#endif

static int tcapInit(int f){ return -1; } /* tcap.c */
static int getcapn(const char *cap){ return -1; } /* tcap.c */
static int set_termcapn(const char *cap,int n){ return -1; } /* editcap.c */
static int win_expand(int z){ return -1; } /* xwin.c */

static int IOCTL(int fd, int op, void *arg);
/*--{---------------------------------------------- SYS/IOCTL.h ----*/
/*
 *	IO CONTROL
 */
#ifdef hpux /* { */
#  define notdef
#  include <sgtty.h>
#  include <termio.h>
#  define TIOCSBRK TCSBRK
#  include <bsdtty.h>
#  include <sys/ioctl.h>
#  define IOCTL_FLUSH(fd)	0
#elif defined(__FreeBSD__) && 8 <= __FreeBSD__
#  define COMPAT_43TTY
#  include <sys/ioctl_compat.h>
#  include <sys/filio.h>
#  include <termios.h>
#  define SGTTY_SGTTY
#  define IOCTL_FLUSH(fd)	IOCTL(fd,TIOCFLUSH,0)
#elif defined(sun)
#  define BSD_COMP
#  include <sys/ioctl.h>
#  include <sys/filio.h>
#  include <termios.h>
#  define IOCTL_FLUSH(fd)   0
#  define sigmask(s) 0
#  define sigsetmask(m) 0
#elif defined(__CYGWIN__)
#  include <termios.h>
#  include <sys/ioctl.h>
#  define sigmask(s) 0
#  define sigsetmask(m) 0
#else
#  ifdef __linux__ /* { */
     /* #include <bsd/sgtty.h> */
     /*RH6*/
#    include <termios.h>
#    include <sys/ioctl.h>
#  else
#    include <sgtty.h>
#  endif /* } */
#  ifdef TIOCFLUSH /* { */
#    define IOCTL_FLUSH(fd)	IOCTL(fd,TIOCFLUSH,0)
#  else
#    define IOCTL_FLUSH(fd)	0
#  endif /* } */
#endif /* } */

#ifndef NOFLSH
#define NOFLSH NOFLUSH
#endif

#ifndef TIOCSETP
/*
#include <sys/ttold.h>
*/
#endif
#ifndef TIOCSETN
#ifdef TIOCSETP
#define TIOCSETN TIOCSETP
#endif
#endif

/*
#ifdef __CYGWIN__
#define TIOCSETP	TCSETA
#define TIOCGETP	TCGETA
#endif
*/
/*--}--*/

/*--{---------------------------------------------- ipc/comcom.c ---*/
static int stream_prefetched(FILE *fp){
	int size;

	if( feof(fp) || fileno(fp) < 0 )
		return 0;

	size = READYCC(fp);
	return size;
}
/*--}--*/

/*--{---------------------------------------------- SYS/ioctl.c ----*/
/*
#include "IOCTL.h"
*/
#include <signal.h>

static int NO_TTY;
static int NO_TTYIOCTL;
static int CURTTY_FD;

static void set_notty(void)
{	int ttyfd;

#ifndef __CYGWIN__
	ttyfd = open("/dev/tty",0);
	IOCTL(ttyfd,TIOCNOTTY,0);
	close(ttyfd);
#endif
}

static int TCSETPGRP(int ttyfd, int pgrp) {
	int rcode;
	void (*osig)(int);

#ifndef __CYGWIN__
	osig = signal(SIGTTOU,SIG_IGN);
	rcode = IOCTL(ttyfd,TIOCSPGRP,&pgrp);
	/*flush_output(ttyfd);
	  940216 this is harmful because 
		CosmosJobs destruct output from VIN */
	signal(SIGTTOU,osig);
	return rcode;
#endif
}
static int TCGETPGRP(int ttyfd) {
	int pgrp;

#ifndef __CYGWIN__
	if( IOCTL(ttyfd,TIOCGPGRP,&pgrp) < 0 )
		return -1;
	else	return pgrp;
#endif
}

static void INQ_FLUSH(int fd){
#ifndef __CYGWIN__
	IOCTL_FLUSH(fd);
#endif
}
static int INQ_SIZE(int fd){
	int cc;

	cc = 0;
#ifdef __CYGWIN__
	if( 0 < _PollIn1(fd,1) )
		cc = 1;
#else
	IOCTL(fd,FIONREAD,&cc);
#endif
	return cc;
}

#include <stdio.h>
static int stream_qsize(FILE *fp){
	if( feof(fp) || fileno(fp) < 0 )
		return 0;
	return stream_prefetched(fp) + INQ_SIZE(fileno(fp));
}
static int stdin_qsize(void){
	return stream_qsize(stdin);
}

#ifndef __CYGWIN__
#ifndef __linux__
static int set_interrupt(int tty){
	if( NO_TTY ) return 0;
	IOCTL(tty,TIOCSBRK,0);
	return 1;
}
#endif
#endif

static void dump_ioctls(void) {
#ifndef __CYGWIN__
#ifndef __linux__ /*RH6*/
	printf("TIOCGLTC\t%x\n",	TIOCGLTC);
	printf("TIOCNOTTY\t%x\n",	TIOCNOTTY);
#ifndef __linux__
	printf("TIOCSBRK\t%x\n",	TIOCSBRK);
#endif
	printf("TIOCSETN\t%x\n",	TIOCSETN);
#endif /*RH6*/
#endif
}

static int IOCTL(int fd, int op, void *arg){
	int rcode;

	if( NO_TTY || NO_TTYIOCTL && isatty(fd) )
		return -1;
#ifdef hpux
	set_noflsh(fd,1);
#endif
	rcode = ioctl(fd,op,arg);
	return rcode;
}
/*--}--*/

/*--{---------------------------------------------- SYS/WINS.h -----*/
/*
#include "../SYS/IOCTL.h"
*/

#ifdef TIOCGWINSZ
#	define GETWINCOM	TIOCGWINSZ
#	define SETWINCOM	TIOCSWINSZ
#	define WINSTRUCT	struct winsize
#	define ROWS		ws_row
#	define COLS		ws_col
#else
#	define GETWINCOM	TIOCGSIZE
#	define SETWINCOM	TIOCSSIZE
#	define WINSTRUCT	struct ttysize
#	define ROWS		ts_lines
#	define COLS		ts_cols
#endif
/*--}--*/

/*--{---------------------------------------------- SYS/stty.h -----*/
/*##############################*
 |	Set tty flags		|
 *##############################*/
/*
#include "IOCTL.h"
*/

#define NEGATE		0x80000000
#define X_CBREAK	(ICANON | NEGATE)

static struct { const char *sym; int flag; int local; } sttysyms[] = {
	{"all",		0xFFFF},
	{"echo",	ECHO},		/* echo input			*/
#ifdef ECHOE
	{"echoe",	ECHOE},
#endif
#ifdef ECHOKE
	{"echoke",	ECHOKE},
#endif
#ifdef ECHOCTL
	{"echoctl",	ECHOCTL},
#endif
#ifdef ISIG
	{"isig",	ISIG},
#endif
#ifdef IEXTEN
	{"iexten",	IEXTEN},
#endif
#ifdef CBREAK
	{"cbreak",	CBREAK},	/* half-cooked mode		*/
#endif
#ifdef LCASE
	{"lcase",	LCASE},		/* simulate lower case		*/
#endif
#ifdef CRMOD
	{"crmod",	CRMOD},		/* map \r to \r\n on output	*/
#endif
#ifdef RAW
	{"raw",		RAW},		/* no i/o processing */
#endif

#ifdef ICANON
	{"icanon",	ICANON},
#endif
#ifdef LITOUT
	{"litout",	LITOUT},	/* literal output		*/
#endif
#ifdef MDMBUF
	{"mdmbuf",	MDMBUF},	/* start/stop output */
#endif
#ifndef __CYGWIN__
#ifndef __linux__/*RH6*/
	{"lcase",	LCASE},		/* simulate lower case		*/
	{"crmod",	CRMOD},		/* map \r to \r\n on output	*/
	{"raw",		RAW},		/* no i/o processing		*/
	{"oddp",	ODDP},		/* get/send odd parity		*/
	{"evenp",	EVENP},		/* get/send even parity		*/
	{"anyp",	ANYP},		/* get any parity/send none	*/
#ifndef __linux__
	{"nldelay",	NLDELAY},	/* \n delay			*/
	{"crdelay",	CRDELAY},	/* \r delay			*/
	{"vtdelay",	VTDELAY},	/* vertical tab delay		*/
	{"bsdelay",	BSDELAY},	/* \b delay			*/
#endif
	{"tbdelay",	TBDELAY},	/* horizontal tab delay		*/
#endif
#endif
#if defined(__CYGWIN__ )
	{"nldelay",	NL1},		/* \n delay			*/
	{"crdelay",	CR3},		/* \r delay			*/
	{"vtdelay",	VT1},		/* vertical tab delay		*/
	{"bsdelay",	BS1},		/* \b delay			*/
#endif
	{"xtabs",	XTABS},		/* expand tabs on output	*/
#if defined(hpux)
	{"cbreak",	X_CBREAK,1},	/* cook input */
#endif
#if defined(__CYGWIN__)
	{"cbreak",	X_CBREAK},	/* cook input */
#endif
#if defined(__linux__)/*RH6*/
	{"cbreak",	X_CBREAK},	/* cook input */
#endif
#if !defined(hpux) && !defined(__CYGWIN__)
#if !defined(__linux__)/*RH6*/
	{"cbreak",	CBREAK},	/* half-cooked mode		*/
#endif
#ifndef __linux__
	{"tandem",	TANDEM},	/* send stopc on out q full	*/
	{"crtbs",	CRTBS},		/* do backspacing for crt	*/
	{"prtera",	PRTERA},	/* \ ... / erase		*/
	{"crtera",	CRTERA},	/* " \b " to wipe out char	*/
	{"tilde",	TILDE},		/* hazeltine tilde kludge	*/
#endif
#ifndef sony_news
	{"tostop",	TOSTOP},	/* SIGSTOP on background output	*/
	{"flusho",	FLUSHO},	/* flush output to terminal	*/
#ifndef __CYGWIN__
#ifndef __linux__
	{"nohang",	NOHANG},	/* no SIGHUP on carrier drop	*/
	{"crtkil",	CRTKIL},	/* kill line with " \b "	*/
	{"ctlech",	CTLECH},	/* echo control chars as ^X	*/
	{"decctq",	DECCTQ},	/* only ^Q starts after ^S	*/
#endif
	{"pendin",	PENDIN},	/* tp->t_rawq needs reread	*/
#endif
#ifndef vax
#ifndef mips
	{"noflsh",	NOFLSH},	/* no output flush on signal	*/
#endif
#endif
#endif /* sony_news */
#endif /* hpux */
	0
};

#if defined(__CYGWIN__) \
 || defined(__linux__)/*RH6*/ \
 || defined(__FreeBSD__) && 8 <= __FreeBSD__

#define SGTTY_TYPE "termio"
#define SGTTY_TERMIO
typedef struct {
	struct	termios	SG;
	int		SG_lflag;
	struct winsize	SG_wsz;
} Sgttyb;
#define SG_flags	SG.c_lflag
#define SG_ispeed(tt)	cfgetispeed(&(tt)->SG)
#define SG_ospeed(tt)	cfgetospeed(&(tt)->SG)
#else
#define SGTTY_TYPE "sgtty"
#define SGTTY_SGTTY
typedef struct {
	struct	sgttyb	SG;
	int		SG_lflag;
	struct winsize	SG_wsz;
} Sgttyb;
#define SG_flags	SG.sg_flags
#define SG_ispeed(tt)	(tt)->SG.sg_ispeed
#define SG_ospeed(tt)	(tt)->SG.sg_ospeed
#define SG_erase	SG.sg_erase
#define SG_kill		SG.sg_kill
#endif

#define MAXFD 64
static Sgttyb cur_sgttyb[MAXFD];
static Sgttyb *initial_stty;

static int GETWINSIZE(int fd,struct winsize *win);
static int TC_getattr(int fd,Sgttyb *sgtty){
	GETWINSIZE(fd,&sgtty->SG_wsz);
#if defined(TIOCSETN) && !defined(SGTTY_SGTTY) || !defined(TCSANOW)
	return IOCTL(fd,TIOCGETP,&sgtty->SG);
#else
	return tcgetattr(fd,&sgtty->SG);
#endif
}
static int SETWINSIZE(int fd,struct winsize *win);
static int TC_setattr(int fd,Sgttyb *sgtty){
	/*
	SETWINSIZE(fd,&sgtty->SG_wsz);
	*/
#if defined(__linux__)
	return tcsetattr(fd,TCSANOW,&sgtty->SG);
#elif defined(TIOCSETN) && !defined(SGTTY_SGTTY) || !defined(TCSANOW)
	return IOCTL(fd,TIOCSETN,&sgtty->SG);
#else
	return tcsetattr(fd,TCSANOW,&sgtty->SG);
#endif
}

static int TCgetattr(int fd,Sgttyb *sgtty){
	int xfd = (0 <= fd && fd < MAXFD) ? fd: MAXFD-1;
#if defined(__linux__)
	return tcgetattr(fd,&cur_sgttyb[xfd].SG);
#elif defined(TIOCSETP) && !defined(SGTTY_SGTTY) || !defined(TCSANOW)
	return ioctl(fd, TIOCGETP, &cur_sgttyb[xfd]);
#else
	return tcgetattr(fd,&cur_sgttyb[xfd].SG);
#endif
}
static int TCsetattr(int fd,Sgttyb *sgtty){
#ifdef TIOCSETN
	return ioctl(fd, TIOCSETN, sgtty);
#else
	return tcsetattr(fd,TCSANOW,&sgtty->SG);
#endif
}
static int cached_gtty(int fd,Sgttyb *buf){
	int xfd = (0 <= fd && fd < MAXFD) ? fd: MAXFD-1;
	int rcode;

	if( SG_ispeed(&cur_sgttyb[xfd]) == 0 ){
		rcode = TCgetattr(fd,(Sgttyb*)&cur_sgttyb[xfd].SG);
#ifdef hpux
		cur_sgttyb[xfd].SG_lflag = ICANON;
#endif
	}

	if(initial_stty == 0){
		initial_stty = (Sgttyb *)
			STRUCT_ALLOC( sizeof(*initial_stty) );
		*initial_stty = cur_sgttyb[xfd];
	}
	*buf = cur_sgttyb[xfd];
	return 0;
}
static int cached_stty(int fd,Sgttyb *buf){
	int xfd = (0 <= fd && fd < MAXFD) ? fd: MAXFD-1;
	int rcode;

	if( cur_sgttyb[xfd].SG_flags != buf->SG_flags
	 || cur_sgttyb[xfd].SG_lflag != buf->SG_lflag ){
		cur_sgttyb[xfd] = *buf;
#ifdef hpux
		tcdrain(fd);
		usleep(100*1000);
#endif
		rcode = TCsetattr(fd,buf);
#ifdef hpux
		set_cbreak(fd,!(buf->SG_lflag&ICANON));
#endif
		return rcode;
	}else	return 0;
}

static void dmpttyb(Sgttyb *p){
	printf("input speed: %d\n",SG_ispeed(p));
	printf("output speed: %d\n",SG_ospeed(p));
#ifdef SG_erase
	printf("erase character: %x\n",p->SG_erase);
	printf("kill character: %x\n",p->SG_kill);
#endif
	printf("flags: %2x\n",p->SG_flags);
}
static void cdmpttyb(void){
	Sgttyb s;
	cached_gtty(CURTTY_FD,&s);
	dmpttyb(&s);
}


static void set_curtty_fd(int fd) { CURTTY_FD = fd; }
static void no_tty(void) { NO_TTY = 1; set_notty(); }
static int have_tty(void) { return !NO_TTY; }

static int suppress_ttyioctl(int flag){
	int oflag;

	oflag = NO_TTYIOCTL;
	NO_TTYIOCTL = flag;
	return oflag;
}

#define elnumof(a) (sizeof(a)/sizeof(a[0]))
static int toFlag(const char *mode,int *flags){
	int fi;
	int neg = 0;

	if( *mode == '-' ){
		mode++;
		neg = 1;
	}
	for( fi = 0; fi < elnumof(sttysyms); fi++ ){
		if( sttysyms[fi].sym )
		if( strcmp(mode,sttysyms[fi].sym) == 0 ){
			if( neg )
				*flags &= ~sttysyms[fi].flag;
			else	*flags |=  sttysyms[fi].flag;
		}
	}
	return 0;
}
static int toFlags(int flags,const char *modes){
	int nflags = flags;
	toFlag(modes,&nflags);
	return nflags;
}

static int settty(int fd,const char *modes){
	Sgttyb sgttyb;
	char mv[5][20],*cmode;
	int i,j,argc;
	int flags,lflag;
	int flag1,neg;

	if( NO_TTY ) return 0;

	cached_gtty(fd,&sgttyb);
	flags = sgttyb.SG_flags;
	lflag = sgttyb.SG_lflag;

	argc = sscanf(modes,"%s %s %s %s %s",mv[0],mv[1],mv[2],mv[3],mv[4]);
	for(i = 0; i < argc; i++){
		cmode = mv[i];
		if( neg = (mv[i][0] == '-') )
			cmode++;
		for(j = 0; sttysyms[j].sym; j++)
			if(strcmp(cmode,sttysyms[j].sym)==0){
				neg = mv[i][0] == '-';
				flag1 = sttysyms[j].flag;
				if( flag1 & 0x80000000 ){
					flag1 &= 0x7FFFFFFF;
					neg = !neg;
				}
				if( sttysyms[j].local ){
					if( neg )
						sgttyb.SG_lflag &= ~flag1;
					else	sgttyb.SG_lflag |=  flag1;
				}else{
					if( neg )
						sgttyb.SG_flags &= ~flag1;
					else	sgttyb.SG_flags |=  flag1;
				}
			}
	}

	if( flags != sgttyb.SG_flags || lflag != sgttyb.SG_lflag )
		cached_stty(fd,&sgttyb);
	return 1;
}

static Sgttyb *STTY0(int fd,const char *command){
	Sgttyb *tty;

	if( NO_TTY ) return 0;
	tty = (Sgttyb*)STRUCT_ALLOC( sizeof(*tty) );
	cached_gtty(fd,tty);
	settty(fd,command);
	return tty;
}
static Sgttyb *STTY(const char *command){
	return STTY0(CURTTY_FD,command);
}
static int TTTY(Sgttyb *tty);
static int RTTY(Sgttyb *tty){
	if( NO_TTY ) return 0;
	if( tty == 0 ) return -1;
	TTTY(tty);
	free(tty);
	return 1;
}
static int RTTY0(int fd,Sgttyb *tty){
	if( NO_TTY ) return 0;
	if(tty == 0) return -1;
	cached_stty(fd,tty);
	free(tty);
	return 1;
}
static int TTTY(Sgttyb *tty){
	if( NO_TTY ) return 0;
	if( tty == 0 ) return -1;
	if( SG_ospeed(tty) != SG_ospeed(initial_stty) ){
		fprintf(stderr,"\r[%d] RESET TTY(%d): funny speed %d\n",
			getpid(),CURTTY_FD,SG_ospeed(tty)); 
		sleep(4);
	}else	cached_stty(1,tty);
	return 0;
}
static int copy_stty(int fd0,int fd1){
	Sgttyb sgttyb;

	if( NO_TTY ) return 0;
	cached_gtty(fd0,&sgttyb);
	cached_stty(fd1,&sgttyb);
	return 1;
}
static int set_raw(int fd,int raw){
	Sgttyb sgttyb;

	if( NO_TTY ) return 0;
	cached_gtty(fd,&sgttyb);
#ifdef RAW
	if(raw)
		sgttyb.SG_flags |=  RAW;
	else	sgttyb.SG_flags &= ~RAW;
#endif
	return cached_stty(fd,&sgttyb);
}
/*--}--*/

/*--{---------------------------------------------- DLL/0cosmos.c --*/
static int SETWINSIZE(int fd,struct winsize *win){
	void (*osignal)(int);
	int err;

	osignal = signal(SIGWINCH,SIG_IGN);
	err = IOCTL(fd,SETWINCOM,win);
	signal(SIGWINCH,osignal);
	return err;
}
static int GETWINSIZE(int fd,struct winsize *win){
	int err;
	err = IOCTL(fd,GETWINCOM,win);
	return err;
}
/*--}--*/

/*--{---------------------------------------------- SYS/cwin.c -----*/
/*
#include "WINS.h"
*/
static int WIN_CHANGED;
static WINSTRUCT init_win;

#include <signal.h>
#ifdef SIGWINCH
static void sig_winch(int sig){
	WINSTRUCT win;
	int omask;

	/* 920910 avoid SIGWINCH to be lost?
		signal(SIGWINCH,SIG_IGN);
	*/
	omask = sigsetmask(~(sigmask(SIGINT)|sigmask(SIGQUIT)));
	IOCTL(0,GETWINCOM,&win);
	if( init_win.ROWS != win.ROWS || init_win.COLS != win.COLS ){
		set_termcapn("li",win.ROWS);
		set_termcapn("co",win.COLS);
		tcapInit(1);
		init_win = win;
		win_expand(win.ROWS);
	}
	fprintf(stderr,"WINCH: [%d] WINSIZE->%d\n",getpid(),win.ROWS);
	sigsetmask(omask);
	signal(SIGWINCH,sig_winch);
}
static void set_sigwinch(void){
	signal(SIGWINCH,sig_winch);
}
#else
static void set_sigwinch(){}
#endif


static int WIN_MAXROWS = 128;
static int WIN_MAXCOLS = 512;
static int get_winsize(int fd,int *rowp,int *colp){
	int rcode,li,co;
	WINSTRUCT win;

	rcode = IOCTL(fd,GETWINCOM,&win);
	if( rcode == 0 ){
		*rowp = li = win.ROWS;
		*colp = co = win.COLS;
		if( 0 < li && li < WIN_MAXROWS )
		if( 0 < co && co < WIN_MAXCOLS )
			return 0;
	}
	return -1;
}
static int set_winsize(int fd,int row){
	int col;
	WINSTRUCT winsize;

	if( NO_TTY ) return 0;
	if( WIN_CHANGED == 0 ){
		WIN_CHANGED = 1;
		IOCTL(fd,GETWINCOM,&init_win);
		if( init_win.ROWS == 0 ){
			init_win.ROWS = getcapn("li");
			init_win.COLS = getcapn("co");
		}
	}
	if(row < 0) row = 0;
	col = getcapn("co");
	if(col < 0) col = 0;

	winsize.ROWS = row;
	winsize.COLS = col;
	SETWINSIZE(CURTTY_FD,&winsize);
	return 1;
}
static int clr_winsize(void){
	WINSTRUCT winsize;

	if( NO_TTY ) return 0;
	winsize.ROWS = 0;
	winsize.COLS = 0;
	SETWINSIZE(CURTTY_FD,&winsize);
	return 1;
}

static int SCR_SIZE;
static int set_SCRSIZE(int rows);
static int SCRSIZE(void){
	if( SCR_SIZE == 0 )
		set_SCRSIZE(24);
	return SCR_SIZE;
}
static int set_SCRSIZE(int rows){
	int real_rows,real_cols;

	SCR_SIZE = rows;
	real_rows = rows;
	if( get_winsize(0,&real_rows,&real_cols) == 0 )
		SCR_SIZE = real_rows;
	return SCR_SIZE;
}


#ifdef __FreeBSD__
#define _ANSI_SOURCE
#endif
#include <sys/time.h>
static int cgetc_with_timeout(int sec,int usec){
	Sgttyb *tty;
	int ch;
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = usec;

	tty = STTY("-echo cbreak");
	if( _PollIn1(fileno(stdin),sec*1000+usec/1000) <= 0 ){
		RTTY(tty);
		return -1;
	}
	ch = getc(stdin);
	RTTY(tty);
	return ch;
}

#include <stdio.h>
static int cgetc(void){
	Sgttyb *tty;
	int ch;

#if !defined(__CYGWIN__)
	if( READYCC(stdin) || _PollIn1(fileno(stdin),1) == 0 )
#endif
		tty = STTY("-echo cbreak");

	ch = getc(stdin);
	if( tty )
		RTTY(tty);
	return ch;
}

static int TtyInputReady(int usec){
	Sgttyb *tty = 0;
	int nready;
	int infd = fileno(stdin);

	nready = _PollIn1(infd,1);
	if( nready <= 0 ){
		if( isatty(infd) )
			tty = STTY("-echo cbreak");
		nready = _PollIn1(infd,usec*1000);
	}
	if( tty ){
		if( 0 < nready )
			ungetc(getchar(),stdin);
		RTTY(tty);
	}

	if(nready<0){
		nready = 0;
	}
	return nready;
}

/*--}--*/

const char *sgTTyType(){
	return SGTTY_TYPE;
}
int getTTySize(int fd,int *width,int *height){
	struct winsize wsz;
	int err;
	err = GETWINSIZE(fd,&wsz);
	*width = wsz.COLS;
	*height = wsz.ROWS;
	return err;
}
int setTTySize(int fd,int width,int height){
	struct winsize wsz;
	int err;
	wsz.ROWS = height;
	wsz.COLS = width;
	err = SETWINSIZE(fd,&wsz);
	return err;
}
int setTTyMode(int fd,const char *mode){
	int rcode;
	rcode = settty(fd,mode);
	return rcode;
}

typedef struct {
	int	x_sz;
	Sgttyb	x_sg;
} XSgttyb;
static XSgttyb XSgttyb0;
int getTTyStat(int fd,void *sg,int sz){
	int err;

	*(XSgttyb*)sg = XSgttyb0;
	if( sz < sizeof(XSgttyb) ){
		((XSgttyb*)sg)->x_sz = sizeof(XSgttyb);
		return -99;
	}
	((XSgttyb*)sg)->x_sz = sz;
	err = TC_getattr(fd,&((XSgttyb*)sg)->x_sg);
	return err;
}
int setTTyStat(int fd,void *sg,int sz){
	int err;

	if( sz < sizeof(XSgttyb) ){
		return -99;
	}
	if( ((XSgttyb*)sg)->x_sz != sz ){
		return -98;
	}
	err = TC_setattr(fd,&((XSgttyb*)sg)->x_sg);
	return err;
}
int addTTyMode(void *sg,const char *mode){
	int flags = 0;

	flags = toFlags(flags,mode);
	return ((XSgttyb*)sg)->x_sg.SG_flags |= flags;
}
int clrTTyMode(void *sg,const char *mode){
	int flags = 0;

	flags = toFlags(flags,mode);
	return ((XSgttyb*)sg)->x_sg.SG_flags ^= flags;
}
int issetTTyMode(void *sg,const char *mode){
	int flags = 0;

	flags = toFlags(flags,mode);
	return ((XSgttyb*)sg)->x_sg.SG_flags & flags;
}
int getTTyMode(int fd,const char *mode){
	XSgttyb xsg;
	if( getTTyStat(fd,&xsg,sizeof(xsg)) == 0 ){
		return issetTTyMode(&xsg,mode);
	}
	return 0;
}

void *dumpTTyStat(int fd){
	Sgttyb *sg;
	int err;
	sg = (Sgttyb*)STRUCT_ALLOC(sizeof(Sgttyb));
	err = TC_getattr(fd,sg);
	return sg;
}
int restoreTTyStat(int fd,void *sg){
	int err;
	err = TC_setattr(fd,(Sgttyb*)sg);
	return err;
}
int freeTTyStat(void *sg){
	if( sg ){
		free(sg);
		return 0;
	}else{
		return -1;
	}
}

#ifdef MAIN
#include <errno.h>
int main(int ac,char *av[]){
	int err,col,lin;
	int fd = 0;
	int ssgi[32];
	int sgi[32];

	err = getTTyStat(fd,ssgi,sizeof(ssgi));
	printf("-- getTTyStat()=%d %d/%d\n",err,ssgi[0],(int)sizeof(ssgi));
	bzero(sgi,sizeof(sgi));
	err = getTTyStat(fd,sgi,sizeof(sgi));
	/*
	printf("TERMIO=%s size=%d err=%d\r\n",SGTTY_TYPE,(int)sizeof(Sgttyb),err);
	*/
	printf("[%X %X %X %X %X]\n",sgi[0],sgi[1],sgi[2],sgi[3],sgi[4]);

	err = getTTySize(fd,&col,&lin);
	printf("LINES=%d\r\n",lin);
	printf("COLUMNS=%d\r\n",col);

/*
#if defined(SGTTY_SGTTY)
struct sgttyb *sg = (struct sgttyb*)&sgi[1];
printf("-- ispeed(%d):%X\n",sizeof(sg->sg_ispeed),sg->sg_ispeed);
printf("-- ospeed(%d):%X\n",sizeof(sg->sg_ospeed),sg->sg_ospeed);
printf("-- ERASE(%d): %X\n",sizeof(sg->sg_erase),sg->sg_erase);
printf("-- KILL(%d):  %X\n",sizeof(sg->sg_kill),sg->sg_kill);
printf("-- flags(%d): %X\n",sizeof(sg->sg_flags),sg->sg_flags);
#else
struct termios *tio = (struct termios*)&sgi[1];
printf("-- iflag(%d): %X\n",sizeof(tio->c_iflag),tio->c_iflag);
printf("-- oflag(%d): %X\n",sizeof(tio->c_oflag),tio->c_oflag);
printf("-- cflag(%d): %X\n",sizeof(tio->c_cflag),tio->c_cflag);
printf("-- lflag(%d): %X\n",sizeof(tio->c_lflag),tio->c_lflag);
printf("-- CC(%d):    %X\n",sizeof(tio->c_cc),tio->c_cc[0]);
printf("-- ispeed(%d):%X\n",sizeof(tio->c_ispeed),tio->c_ispeed);
printf("-- ospeed(%d):%X\n",sizeof(tio->c_ispeed),tio->c_ospeed);
#endif
*/

	err = getTTyStat(fd,sgi,sizeof(sgi));
	printf("---- rcode=%d e%d %d/%d\n",err,errno,sgi[0],(int)sizeof(sgi));
	printf("---- %d %X %X %X %X %X %X %X\n",sgi[0],sgi[1],sgi[2],sgi[3],
			sgi[4],sgi[5],sgi[6],sgi[7]);
	printf("---- raw=%X\r\n",getTTyMode(fd,"raw"));

	/*
	lin--;
	setTTySize(fd,col,lin);
	err = getTTySize(fd,&col,&lin);
	printf("LINES=%d\r\n",lin);
	printf("COLUMNS=%d\r\n",col);
	*/

	setTTyMode(fd,"raw");
	err = getTTyStat(0,sgi,sizeof(sgi));
	printf("---- raw=%X\r\n",getTTyMode(fd,"raw"));
	printf("---- %d %X %X %X %X %X %X %X\r\n",sgi[0],sgi[1],sgi[2],sgi[3],
			sgi[4],sgi[5],sgi[6],sgi[7]);

	printf("---- echo=%X\r\n",getTTyMode(fd,"echo"));
	setTTyMode(fd,"-echo");
	printf("---- echo=%X\r\n",getTTyMode(fd,"echo"));
	setTTyMode(fd,"echo");
	printf("---- echo=%X\r\n",getTTyMode(fd,"echo"));

	setTTyMode(fd,"icanon");
	err = getTTyStat(0,sgi,sizeof(sgi));
	printf("---- icanon=%X\r\n",getTTyMode(fd,"icanon"));
	printf("---- %d %X %X %X %X %X %X %X\r\n",sgi[0],sgi[1],sgi[2],sgi[3],
			sgi[4],sgi[5],sgi[6],sgi[7]);

	setTTyStat(fd,ssgi,sizeof(ssgi));
	err = getTTyStat(0,sgi,sizeof(sgi));
	printf("---- %d %X %X %X %X %X %X %X\r\n",sgi[0],sgi[1],sgi[2],sgi[3],
			sgi[4],sgi[5],sgi[6],sgi[7]);

	err = getTTySize(fd,&col,&lin);
	printf("LINES=%d\r\n",lin);
	printf("COLUMNS=%d\r\n",col);
	return 0;
}
#endif

/*
#if defined(__cplusplus)
}
#endif
*/
