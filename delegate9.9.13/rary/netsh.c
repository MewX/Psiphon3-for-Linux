/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2010 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use,
without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	netsh.c
Author:		Yutaka Sato <y.sato@aist.go.jp>
Description:
	master-side == keybord and display emulator
	master-side input as ^C => SIGINT => slave-side process
	shiobar
 	script
	console interaction simulation (input stream with timing)
History:
	100112	created
	100117	added dgforkpty
//////////////////////////////////////////////////////////////////////#*/

#define DGFSZ	64 /* status response from the dgforkpty command */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "mysgTTy.h"
#include "ystring.h"
#include "vsignal.h"
#include "fpoll.h"
#include "proc.h"

int Forkpty(int *pty,char *name);
int _ForkptyX(int *pty,char *name,void *mode,void *size);
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph);
int bgwait(int pid,int ph,double timeout);
int ShutdownSocket(int sock);
int setCloseOnExec(int fd);
int setCloseOnExecSocket(int fd);
int procIsAlive(int pid);
int NoHangWait();
void msleep(int ms);
int Kill(int pid,int sig);
int connectA(PCStr(host),int port,int timeout);
int fileIsdir(PCStr(path));

/* close on exec file-descriptors, filter env. var. to be inherited */
int closeFds(Int64 inheritfds);
extern char **environ;
int filterDGENV(char *ev[],char *nev[],int nec);
int Xexecve(FL_PAR,const char *path,char *av[],char *ev[]);

int _PollIn1(int fd,int timeout);
int _PollIns(int timeout,int nfd,int *fdv,int *rdv);
int fpollins(int fpn,FILE *fpv[],int rdv[]){
	int fi;
	FILE *fp;
	int nready = 0;

	for( fi = 0; fi < fpn; fi++ ){
		fp = fpv[fi];
		if( feof(fp) || 0 < READYCC(fp) ){
			nready++;
			rdv[fi] = 1;
		}else{
			rdv[fi] = 0;
		}
	}
	return nready;
}

#ifndef DGFORKPTY /*{ ---------------*/
#else /*}{*/
#ifndef _MSC_VER

int SocketOf(int fd){
	return fd;
}
#ifdef F_SETFD
int setCloseOnExec(int fd){
	return fcntl(fd,F_SETFD,(void*)1);
}
#else
int setCloseOnExec(int fd){
	return -1;
}
#endif
int connectL(PCStr(host),int port,int timeout);
int connectA(PCStr(host),int port,int timeout){
	return connectL(host,port,timeout);
}
void msleep(int ms){
	usleep(ms*1000);
}
extern int WAIT_WNOHANG;
int NoHangWait(){
	int pid;
	int status[4];
	pid = wait3(status,WAIT_WNOHANG,NULL);
	return pid;
}
int procIsAlive(int pid){
	int rcode;
	errno = 0;
	rcode = kill(pid,0);
	return errno != ESRCH;
}
int Kill(int pid,int sig){
	int rcode;
	if( pid == 0 || pid == 1 || pid == -1 ){
		return -1;
	}
	errno = 0;
	rcode = kill(pid,sig);
	return rcode;
}
int inputReady(int sock,int *rd){
	int ready;
        ready = _PollIn1(sock,1);
        return ready;
}
#undef XsetVStrEnd
int XsetVStrEnd(PVStr(d),int x){
	((char*)d)[x] = 0;
	return x;
}

#undef putenv
#undef fopen
#undef fdopen
#undef fflush
#undef fwrite
#undef fprintf
#undef strcat
#undef sprintf

#define LINESIZE 0x4000
#ifdef daVARGS
#undef VARGS
#define VARGS daVARGS
#endif

int FMT_Xfprintf(FILE *fp,PCStr(fmt),...){
	VARGS(16,fmt);
	return fprintf(fp,fmt,VA16);
}
int FMT_porting_dbg(PCStr(fmt),...){
	VARGS(16,fmt);

	fprintf(stderr,"[%d] ",getpid());
	fprintf(stderr,fmt,VA16);
	fprintf(stderr,"\n");
	return 0;
}
#endif
#endif /*} ---------------*/

/*---- minimum Telent ----*/
#define IAC	255
#define SB	250
#define SE	240
#define O_NAWS	 31

#define TELOK	256
#define TELNG	256+1
#define ISTEL(ch)	(256 <= ch && ch <= 512)

int sendTTySize(FILE *ts,int col,int row){
	IStr(msg,64);
	unsigned char *ub = (unsigned char*)msg;
	int cc = 9;

	ub[0] = IAC;
	ub[1] = SB;
	ub[2] = O_NAWS;
	ub[3] = 0;
	ub[4] = col;
	ub[5] = 0;
	ub[6] = row;
	ub[7] = IAC;
	ub[8] = SE;
	fwrite(msg,1,cc,ts);
	return cc;
}
int recvTTySize(int tty,int pch,FILE *fc,int *col,int *row){
	IStr(msg,64);
	unsigned char *ub = (unsigned char*)msg;
	int icc;
	int ch;
	int tt[32];

	ch = getc(fc);
	if( ch == '~' ){
		int raw = 0;
		if( getTTyStat(tty,tt,sizeof(tt)) == 0 ){
			if( issetTTyMode(tt,"echo") == 0 )
			if( issetTTyMode(tt,"isig") == 0 )
			{
				raw = issetTTyMode(tt,"raw") 
				   || issetTTyMode(tt,"crmod") == 0;
			}
			porting_dbg("--OK ttystat:{%d %X %X %X %X} raw=%d [%X] rw=%X,ec=%X,cb=%X,cr=%X ic=%X is=%X ix=%X",
				tt[0],tt[1],tt[2],tt[3],tt[4],raw,pch,
				issetTTyMode(tt,"raw"),
				issetTTyMode(tt,"echo"),
				issetTTyMode(tt,"cbreak"),
				issetTTyMode(tt,"crmod"),
				issetTTyMode(tt,"icanon"),
				issetTTyMode(tt,"isig"),
				issetTTyMode(tt,"iexten")
			);
		}else{
			porting_dbg("--NG ttystat:%d/%d %X",
				(int)sizeof(tt),tt[0],tt[1]);
		}
		if( raw == 0 )
		if( pch < 0 /* if the cursol is at the top of the input line */
		 || pch == '\r'
		 || pch == '\n'
		 || pch == 'C'-0x40
		 || pch == 'U'-0x40
		){
			int nch;
			nch = getc(fc);
			porting_dbg("--yysh ~ %X (%c)",nch,nch);
			switch( nch ){
				case '.':
					ch = EOF;
						return ch;
				case '~':
					break;
				case 'Z'-0x40:
					break;
				default:
					ungetc(nch,fc);
					break;
			}
		}
	}
	if( ch != IAC ){
		if( ch == EOF ){
			porting_dbg("--yysh Kbd [%02X] eof=%d e%d",ch,
				feof(fc),errno);
		}
		return ch;
	}
	ch = getc(fc);
	if( ch == SB ){
		/* this should be with timeout */
		if( (icc = fread(msg+2,1,7,fc)) == 7 ){
			if( ub[2] == O_NAWS ){
				*col = ub[4];
				*row = ub[6];
				return TELOK;
			}else{
				return TELNG;
			}
		}
		return TELNG;
	}else{
		porting_dbg("--yysh Kbd [%02X %02X] eof=%d e%d",IAC,ch,
			feof(fc),errno);
		ungetc(ch,fc);
		return IAC;
	}
}

int addTTyMode(void *sg,const char *mode);
static void setupTTy(int ptyfd,int silent){
	int ocol,orow,col,row,ncol,nrow;
	int ecol,erow;
	const char *env;
	int gerr1,gerr2,serr;
	int flags;
	int tt[32];
	
	ocol = orow = col = row = ncol = nrow = -1;
	gerr1 = getTTySize(ptyfd,&ocol,&orow); /* might fail (Solaris) */
	col = ocol;
	row = orow;
	if( env = getenv("LINES") ){
		row = atoi(env);
	}
	if( env = getenv("COLUMNS") ){
		col = atoi(env);
	}
	if( 0 < row && 0 < col ){
		serr = setTTySize(ptyfd,col,row);
		gerr2 = getTTySize(ptyfd,&ncol,&nrow);
		if( !silent )
		fprintf(stderr,"[%d] WINSIZE=%dx%d <= %dx%d e{%d %d %d} t%d\n",
			getpid(),ncol,nrow,ocol,orow,gerr1,serr,gerr2,
			isatty(ptyfd));
	}
	/*
	getTTyStat(ptyfd,tt,sizeof(tt));
	addTTyMode(tt,"echo");
	addTTyMode(tt,"echoe");
	addTTyMode(tt,"echoke");
	addTTyMode(tt,"echoctl");
	addTTyMode(tt,"isig");
	setTTyStat(ptyfd,tt,sizeof(tt));
	*/
}

#ifndef DGFORKPTY /*{ ---------------------------------------------------*/

#include "vsocket.h"
#include "dglib.h"
#include "proc.h"
#include "file.h"
#include "log.h"

#define NS_ENDPROC	0x01
#define NS_XPROC	0x02
#define NS_ENDKBD	0x04
#define NS_XKBD		0x08
#define NS_ENDDISP	0x10
#define NS_XDISP	0x20
#define NS_SUTTY	0x40
#define NS_SUACC	0x80
#define NS_SUSELF	0x100

typedef struct _Netsh {
	int	ns_stat;
	int	ns_tty;
	MStr(	ns_name,32);
	int	ns_pid;
	int	ns_ph; /* process handle on Windows */
	int	ns_cpid;
	int	ns_ktid;
	int	ns_dtid;
	int	ns_sync[2];
	int	ns_free;
	const char *ns_shell;
	int	ns_disp_nflush;
	int	ns_disp_total;
	int	ns_disp_nesc;
	int	ns_kbd_total;
	int	ns_kbd_pch;
	int	ns_kbd_numINTR;
	int	ns_shutting;
	Int64	ns_inheritfds;
} Netsh;
#define Disp_nflush Nsh->ns_disp_nflush
#define Disp_total  Nsh->ns_disp_total
#define Disp_nesc   Nsh->ns_disp_nesc
#define Kbd_total   Nsh->ns_kbd_total
#define Kbd_pch     Nsh->ns_kbd_pch
#define Kbd_numINTR Nsh->ns_kbd_numINTR

int bindA(PCStr(host),int *portp,int nlisten);
int acceptA(int asock,int timeout,PVStr(addr));

int fullpathSUCOM(PCStr(path),PCStr(mode),PVStr(xpath));
int spawnv_self1(int aac,const char *aav[]);
/*
 * the external dgforkpty command with set-uid-on-exec is necessary
 * if forkpty() with EACCES needing privilege (KuroBox).
 */
int nonASCIIstr(PCStr(str)){
	const char *sp;
	for( sp = str; *sp; sp++ ){
		if( *sp & 0x80 ){
			return 1;
		}
	}
	return 0;
}
int copyFile(PCStr(src),PCStr(dst)){
	FILE *sfp = 0;
	FILE *dfp = 0;
	IStr(buf,8*1024);
	int rcc;

	sfp = fopen(src,"r");
	dfp = fopen(dst,"w");
	if( sfp != NULL & dfp != NULL ){
		while( 0 < (rcc = fread(buf,1,sizeof(buf),sfp)) ){
			fwrite(buf,1,rcc,dfp);
		}
	}
	if( sfp ) fclose(sfp);
	if( dfp ) fclose(dfp);
	return 0;
}
int copyExec(PCStr(src),PCStr(dst),int force){
	FILE *fp;
	IStr(dstdesc,256);

	if( File_is(dst) && force == 0 ){
		/* if the size is not equal */
		/* if the date of src is not newer than dst */
		return 0;
	}
	copyFile(src,dst);
	/* copy the date and mode */
	chmod(dst,0755);
	if( File_is(dst) ){
		porting_dbg("copied %s <= %s",dst,src);
		sprintf(dstdesc,"%s.desc.txt",dst);
		if( fp = fopen(dstdesc,"a") ){
			fprintf(fp,"[%d] %d copied from %s\n",getpid(),
				itime(0),src);
			fclose(fp);
		}
	}
	return 1;
}
int withDGForkpty(PVStr(path)){
	const char *dgforkpty;
	int isexec;
	IStr(xpath,256);
	IStr(cwd,256);

	if( isWindows() ){
		dgforkpty = "dgforkpty.exe";
	}else{
		dgforkpty = "dgforkpty";
	}
	if( fullpathSUCOM(dgforkpty,"r",AVStr(path)) ){
		// CYGWIN might fail forkpty() with non-ASCII name
		if( isWindows() && nonASCIIstr(path) ){
			sprintf(xpath,"C:/DeleGate/%s",dgforkpty);
			copyExec(path,xpath,0);
			if( File_is(xpath) ){
				strcpy(path,xpath);
				getcwd(cwd,sizeof(cwd));
				if( nonASCIIstr(cwd) ){
					chdir("C:/DeleGate/");
				}
			}
		}
	}else{
		strcpy(path,dgforkpty);
	}
	isexec = File_is(path);
	return isexec;
}

int sudoForkpty(int *rttyfd,int *rttypid,int *rttyph,int flags,PVStr(name),PCStr(shell),char*const sav[],char*const sev[]){
	int ttyph = -1;
	int ttypid = -1;
	int accfd = -1; /* to accept from dgforkpty */
	int ttyfd = -1; /* socket pair end of my side */
	int ptyfd = -1; /* socket pair end of dgforkpty side */
	int pid = -1;
	int xpid;
	IStr(retb,DGFSZ);
	int ret[2];
	int rcc;
	IStr(fdn,32);
	const char *av[16];
	int ac = 0;
	int isexec;
	IStr(dgforkpty,1024);
	Int64 inheritfds = 0;

	isexec = withDGForkpty(AVStr(dgforkpty));
	if( isexec && (flags & NS_SUSELF) ){
		porting_dbg("---ignore {%s}",dgforkpty);
		isexec = 0;
	}

	if( isWindows() || (flags & NS_SUACC) ){
		int port = 0;
		accfd = bindA("127.0.0.1",&port,1);
		sprintf(fdn,"%d/%d/%d",-1,curLogFd(),port);
		ttyfd = -1;
		ptyfd = -1;
	}else{
		Socketpair(ret);
		setCloseOnExecSocket(ret[0]);
		accfd = -1;
		ttyfd = ret[0];
		ptyfd = ret[1];
		sprintf(fdn,"%d/%d",ptyfd,curLogFd());
		inheritfds = 1 << ptyfd;
	}
	if( !isexec ){
		av[ac++] = "-FdgForkpty";
	}else{
		av[ac++] = dgforkpty;
	}
	av[ac++] = fdn;
	av[ac++] = shell; /* path for exec(path,av) */
	if( sav && sav[0] ){
		int ai;
		for( ai = 0; sav[ai]; ai++ )
			av[ac++] = sav[ai];
	}else{
		av[ac++] = shell; /* av[] for exec(path,av) */
	}
	av[ac] = 0;

	if( !isexec ){
		pid = spawnv_self1(ac,av);
	}else
	if( isWindows() ){
		char *nenv[1024];

		/* v9.9.10 fix-140626a a workaround to escape a strange problem
		 * that makes HOME env. be not inherited.
		 * bgexec() -> xspawnvpe() seems dropping it...
		 */ {
			int ei;
			char *e1;
			char *eHOME = 0;

			for( ei = 0; ei < elnumof(nenv)-1 && (e1 = environ[ei]); ei++ ){
				nenv[ei] = e1;
				if( strncmp(e1,"HOME=",5) == 0 )
					eHOME = e1;
			}
			if( eHOME ){
				nenv[ei++] = eHOME;
			}
			nenv[ei] = 0;
		}

		/* "c" for no-console */
		/* "i" for inherit nothing (v9.9.10 mod-140625d) */
		pid = bgexecX("ci",dgforkpty,(char**)av,nenv,&ttyph);
	}else
	if( (pid = fork()) == 0 ){
		if( 0 <= ttyfd ){
			close(ttyfd);
		}
		/* should be execve with LD_LIBRARY_PATH ... */
		closeFds(inheritfds);
		Xexecve(FL_ARG,dgforkpty,(char**)av,environ);
		_exit(-1);
	}
	if( 0 <= ptyfd ){
		close(ptyfd);
	}
	if( 0 <= accfd ){
		ttyfd = acceptA(accfd,10*1000,VStrNULL);
		close(accfd);
	}
	rcc = read(ttyfd,retb,sizeof(retb));
	if( isWindows() ){
		xpid = bgwait(pid,ttyph,0.01);
		if( xpid == pid ){
			ttypid = -1;
			ttyph = -1;
		}
	}else{
		xpid = NoHangWait();
	}
	if( 0 < rcc ){
		setVStrEnd(retb,rcc-1);
		Xsscanf(retb,"%d %s",&ttypid,BVStr(name));
		*rttyph = ttyph;
		*rttypid = ttypid;
		*rttyfd = ttyfd;
		porting_dbg("---- dgforkpty: rcc=%d [%d](%s) [%d %d %d]",
			rcc,ttypid,name,ptyfd,ttyfd,accfd);
		return pid;
	}else{
		porting_dbg("---- dgforkpty: rcc=%d xpid=%d",rcc,xpid);
		close(ttyfd);
		return -1;
	}
}
#if defined(_MSC_VER) /*{*/
static int setHOME(PCStr(home));
static int forksh(Netsh *Nsh,PCStr(shell),char*const sav[],char*const sev[]){
	IStr(name,1024);
	int ph;
	int pid;
	int cpid;

	clearVStr(name);
	Nsh->ns_tty = -1;
	Nsh->ns_cpid = -1;

	if( Nsh->ns_stat & NS_SUTTY ){
		setHOME(getenv("YYHOME"));
		pid = sudoForkpty(&Nsh->ns_tty,&cpid,&ph,Nsh->ns_stat,AVStr(name),shell,sav,sev);
		if( 0 < pid ){
			Nsh->ns_ph = ph;
			Nsh->ns_pid = pid;
			Nsh->ns_cpid = cpid;
			return 0;
		}
	}
	return -1;
}
#else /*}{*/

#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

/* tpid = forkpty(&tty,name,&term,&win); */
int openNull(int rw);
static int forksh(Netsh *Nsh,PCStr(shell),char*const sav[],char*const sev[]){
	struct termios term;
	struct winsize win;
	IStr(name,1024);
	int rcode;
	int oltype;
	int ph;
	int pid;
	int cpid;
	int serrno;

	clearVStr(name);
	Nsh->ns_tty = -1;
	Nsh->ns_cpid = -1;

	if( Nsh->ns_stat & NS_SUTTY ){
		pid = sudoForkpty(&Nsh->ns_tty,&cpid,&ph,Nsh->ns_stat,AVStr(name),shell,sav,sev);
		if( 0 < pid ){
			Nsh->ns_ph = ph;
			Nsh->ns_pid = pid;
			Nsh->ns_cpid = cpid;
			return 0;
		}
	}

	NO_LOGGING = 1;
	errno = 0;
	Nsh->ns_pid = pid = Forkpty(&Nsh->ns_tty,name);
	serrno = errno;

	if( pid < 0 )
	if( errno == EACCES /* KuroBox(HG) */
	 || errno == ENOENT /* lacking dyn. lib. (LD_LIBRARY_PATH) ? */
	){
		Nsh->ns_stat |= NS_SUTTY;
		pid = sudoForkpty(&Nsh->ns_tty,&cpid,&ph,Nsh->ns_stat,AVStr(name),shell,sav,sev);
		NO_LOGGING = 0;
		porting_dbg("--forkpty pid=%d retried on errno=%d",pid,serrno);
		if( 0 < pid ){
			Nsh->ns_ph = ph;
			Nsh->ns_pid = pid;
			Nsh->ns_cpid = cpid;
			return 0;
		}
	}
	if( Nsh->ns_pid == 0 ){
#if defined(__osf__)
		system("stty sane");
#endif
		closeFds(Nsh->ns_inheritfds);
		rcode = Xexecve(FL_ARG,shell,(char**)sav,environ);
		porting_dbg("--Nsh execve()=%d e%d",rcode,errno);
		_exit(0);
		return -1;
	}
	NO_LOGGING = 0;
	if( pid < 0 ){
		porting_dbg("--Nsh tty: [%d] e%d",pid,errno);
		return -1;
	}else{
		setupTTy(Nsh->ns_tty,0);
		strcpy(Nsh->ns_name,name);
		porting_dbg("--Nsh tty: [%d] %s",pid,name);
		return 0;
	}
}
#endif /*}*/

int fpollinsX(int timeout,int fpc,FILE *fpv[],int rdv[]){
	int fi;
	int fdfdv[8],fdrdv[8];
	int nready = 0;
	int dready = 0;
	FILE *fp;

	for( fi = 0; fi < fpc; fi++ ){
		fp = fpv[fi];
		if( feof(fp) || 0 < READYCC(fp) ){
			nready++;
			rdv[fi] = 1;
		}else{
			rdv[fi] = 0;
		}
		fdfdv[fi] = fileno(fpv[fi]);
	}
	if( 0 < nready ){
		timeout = TIMEOUT_IMM;
	}
	dready = PollIns(timeout,fpc,fdfdv,fdrdv);
	for( fi = 0; fi < fpc; fi++ ){
		if( rdv[fi] == 0 && fdrdv[fi] != 0 ){
			rdv[fi] = fdrdv[fi];
			nready++;
		}
	}
	return nready;
}

static int toDisp1(Netsh *Nsh,FILE *fin,FILE *fout){
	int ch = -1;

	ch = getc(fin);
	if( Nsh->ns_shutting ){
		porting_dbg("--toDisp in shutting %X: %X",Nsh->ns_shutting,ch);
	}
	if( ch == EOF ){
		return EOF;
	}
	if( ch == 033 ){
		Disp_nesc++;
	}
	if( putc(ch,fout) == EOF ){
		return EOF;
	}
	Disp_total++;
	return ch;
}
static void toDisp(Netsh *Nsh,int todisp){
	FILE *fin = fdopen(Nsh->ns_tty,"r");
	FILE *fout = fdopen(todisp,"w");
	int fdv[2],rdv[2],rdy;
	int wcc;

	if( fin == 0 || fout == 0 ){
		porting_dbg("----cannot open Disp in=%X out=%X",p2i(fin),p2i(fout));
		wcc = write(Nsh->ns_sync[1],"d",1);
		return;
	}
	fdv[0] = Nsh->ns_tty;
	fdv[1] = Nsh->ns_sync[0];
	for(;;){
		if( ready_cc(fin) <= 0 ){
			if( rdy = PollIns(0,2,fdv,rdv) ){
				if( rdv[1] ){
					break;
				}
			}
		}
		if( toDisp1(Nsh,fin,fout) < 0 ){
			break;
		}
		if( fPollIn(fin,10) == 0 ){
			if( fflush(fout) == EOF ){
				break;
			}
			Disp_nflush++;
		}
	}
	Nsh->ns_stat |= NS_XDISP;
	porting_dbg("--Nsh toDisp:%d flush:%d esc:%d",
		Disp_total,Disp_nflush,Disp_nesc);
	/*
	dupclosed(in);
	*/
	wcc = write(Nsh->ns_sync[1],"D",1);
	msleep(1);
}
static int fromKbd1(Netsh *Nsh,FILE *fin,FILE *fout){
	int ch = -1;
	int serrno;

	errno = 0;
	if( Nsh->ns_cpid < 0 ){ /* without dgforkpty() */
		int col,row;
		ch = recvTTySize(Nsh->ns_tty,Kbd_pch,fin,&col,&row);
		serrno = errno;
		Kbd_pch = ch;
		if( ch == EOF ){
			porting_dbg("--fromKbd EOS recvTTySize e%d",serrno);
		}
		if( ISTEL(ch) ){
			porting_dbg("--WINSIZE %dx%d",col,row);
			setTTySize(Nsh->ns_tty,col,row);
			return ch;
		}
	}else{
		ch = getc(fin);
	}
	serrno = errno;
	if( Nsh->ns_shutting ){
		porting_dbg("--fromKbd in shutting %X: %X",Nsh->ns_shutting,ch);
	}
	if( ch == EOF ){
		porting_dbg("--fromKbd EOS ch=%X e%d",ch,serrno);
		return EOF;
	}
	if( ch == 'Z'-0x40 ){
		porting_dbg("--yy got CTRL-Z");
	}else
	if( ch == 'C'-0x40 ){
		Kbd_numINTR++;
		porting_dbg("--yy got CTRL-C #%d",Kbd_numINTR);
		/*
		Killpg(Nsh->ns_cpid,SIGINT);
		*/
	}
	if( putc(ch,fout) == EOF ){
		porting_dbg("--fromKbd EOS putc e%d",serrno);
		return EOF;
	}
	if( fflush(fout) == EOF ){
		porting_dbg("--fromKbd EOS fflush e%d",serrno);
		return EOF;
	}
	Kbd_total++;
	return ch;
}
static void fromKbd(Netsh *Nsh,int fromkbd){
	FILE *fin = fdopen(fromkbd,"r");
	FILE *fout = fdopen(Nsh->ns_tty,"w");
	int fdv[2],rdv[2],rdy;
	int wcc;

	if( fin == 0 || fout == 0 ){
		porting_dbg("----cannot open Kbd in=%X out=%X",p2i(fin),p2i(fout));
		wcc = write(Nsh->ns_sync[1],"k",1);
		return;
	}
	porting_dbg("--TTy pid[%d] cpid[%d] isatty[%d]%d",
		Nsh->ns_pid,Nsh->ns_cpid,Nsh->ns_tty,isatty(Nsh->ns_tty));

	fdv[0] = fromkbd;
	fdv[1] = Nsh->ns_sync[0];
	for(;;){
		if( ready_cc(fin) <= 0 ){
			if( rdy = PollIns(0,2,fdv,rdv) ){
				if( rdv[1] ){
					break;
				}
			}
		}
		if( fromKbd1(Nsh,fin,fout) == EOF ){
			break;
		}
	}
	Nsh->ns_stat |= NS_XKBD;
	porting_dbg("--Nsh fromKey:%d",Kbd_total);
	/*
	dupclosed(out);
	*/
	wcc = write(Nsh->ns_sync[1],"K",1);
	msleep(1);
}

int shutdownWR(int fd);
static int relayDispKbd(Netsh *Nsh,int todisp,int fromkey){
	FILE *kif,*kof,*dif,*dof,*fiv[2],*fov[2],*fin,*fout;
	int fpc,fpi,fdv[2],rdy,rdv[2];
	int keos = 0;
	int deos = 0;

	kif = fdopen(fromkey,"r");
	kof = fdopen(Nsh->ns_tty,"w");
	dif = fdopen(Nsh->ns_tty,"r");
	dof = fdopen(todisp,"w");

	for(;;){
		fpc = 0;
		if( keos == 0 ){
			fiv[fpc] = kif;
			fov[fpc] = kof;
			fpc++;
		}
		if( deos == 0 ){
			fiv[fpc] = dif;
			fov[fpc] = dof;
			fpc++;
		}
		if( fpc == 0 ){
			syslog_ERROR("--Nsh both closed\n");
			break;
		}
		rdy = fpollinsX(10,fpc,fiv,rdv);
		if( rdy == 0 ){
			fflush(dof);
		}
		if( fpc == 1 ){
			rdy = fpollinsX(300,fpc,fiv,rdv);
			if( rdy == 0 ){
				syslog_ERROR("--Nsh timeout (%d %d)\n",deos,keos);
				break;
			}
		}
		for(;;){
			rdy = fpollinsX(10*1000,fpc,fiv,rdv);
			if( rdy != 0 ){
				break;
			}
		}
		if( rdy < 0 ){
			syslog_ERROR("--Nsh DispKbd poll=%d e%d\n",rdy,errno);
			break;
		}
		for( fpi = 0; fpi < fpc; fpi++ ){
			if( rdv[fpi] == 0 )
				continue;
			fin = fiv[fpi];
			fout = fov[fpi];
			if( fin == kif ){
				if( fromKbd1(Nsh,fin,fout) == EOF ){
					syslog_ERROR("--Nsh Kbd EOS\n");
					keos = 1;
					Nsh->ns_shutting |= 1;
				}
			}else{
				if( toDisp1(Nsh,fiv[fpi],fov[fpi]) == EOF ){
					syslog_ERROR("--Nsh Disp EOS\n");
					deos = 1;
					Nsh->ns_shutting |= 2;
				}
			}
			/*
			if( feof(fin) || ready_cc(fin) == 0 ){
				fflush(fout);
			}
			*/
		}
		if( deos ){
			/* this can caus SIGPIPE
			shutdownWR(todisp);
			*/
		}
		if( 1 ){
			if( keos || deos ){
				break;
			}
		}
	}
EXIT:
	porting_dbg("--Nsh fromKey:%d (c-C:%d), toDisp:%d (flush:%d esc:%d)",
		Kbd_total,Kbd_numINTR,Disp_total,Disp_nflush,Disp_nesc);
	fcloseFILE(kof);
	fcloseFILE(kif);
	fcloseFILE(dif);
	fcloseFILE(dof);
	return 0;
}
Netsh *openNetsh(Netsh *Nsh,PCStr(shell),char*const sav[],char*const sev[],int sync,int fromkey,int todisp,int sutty,int cols,int rows,Int64 inheritfds){
	int terr,xpid;

	if( Nsh == 0 ){
		Nsh = (Netsh*)malloc(sizeof(Netsh));
		bzero(Nsh,sizeof(Netsh));
		Nsh->ns_free = 1;
	}else{
		bzero(Nsh,sizeof(Netsh));
	}
	porting_dbg("---- openNetsh=%X",p2i(Nsh));
	if( sutty ){
		Nsh->ns_stat |= NS_SUTTY;
		if( sutty & 2 ){
			Nsh->ns_stat |= NS_SUACC;
		}
		if( sutty & 4 ){
			Nsh->ns_stat |= NS_SUSELF;
		}
	}
	Nsh->ns_shell = shell;
	Nsh->ns_inheritfds = inheritfds;
	if( forksh(Nsh,shell,sav,sev) < 0 ){
		Nsh->ns_dtid = 0;
		Nsh->ns_ktid = 0;
		Nsh->ns_stat |= NS_ENDPROC;
		return 0;
	}
	Socketpair(Nsh->ns_sync);
	Nsh->ns_kbd_pch = -1;
	if( sync ){
		relayDispKbd(Nsh,todisp,fromkey);
		write(Nsh->ns_sync[1],"S",1);
	}else{
	/* LinuxThread seems duplicate disp. echo with these thread */
	Nsh->ns_dtid = thread_fork(0x40000,0,"Disp",(IFUNCP)toDisp,Nsh,todisp);
	Nsh->ns_ktid = thread_fork(0x40000,0,"Key",(IFUNCP)fromKbd,Nsh,fromkey);
	}
	return Nsh;
}
int waitNetsh(Netsh *Nsh,int timeout){
	int terr;
	int xpid;
	char buf[1];
	int rcc,wcc;

	if( Nsh == 0 ){
		fprintf(stderr,"waitNetsh(NULL)\n");
		return -1;
	}
	if( 0 < PollIn(Nsh->ns_sync[0],timeout) ){
		/*
		rcc = read(Nsh->ns_sync[0],buf,1);
			porting_dbg("-----th-a-END rcc=%d %X",rcc,buf[0]);
		if( 0 < PollIn(Nsh->ns_sync[0],100) ){
			rcc = read(Nsh->ns_sync[0],buf,1);
			porting_dbg("-----th-b-END rcc=%d %X",rcc,buf[0]);
		}
		*/
	}
	if( 0 <= Nsh->ns_sync[1] ){
		wcc = write(Nsh->ns_sync[1],"M",1);
	}
	if( (Nsh->ns_stat & NS_ENDKBD) == 0 && Nsh->ns_ktid ){
		terr = thread_wait(Nsh->ns_ktid,timeout);
		porting_dbg("-----waitNetsh %X %d KEY-DONE %d/%d",
			Nsh->ns_ktid,terr,actthreads(),numthreads());
		if( terr == 0 ){
			Nsh->ns_stat |= NS_ENDKBD;
		}
	}
	if( (Nsh->ns_stat & NS_ENDDISP) == 0 && Nsh->ns_dtid ){
		terr = thread_wait(Nsh->ns_dtid,timeout);
		porting_dbg("-----waitNetsh %X %d DISP-DONE %d/%d",
			Nsh->ns_dtid,terr,actthreads(),numthreads());
		if( terr == 0 ){
			Nsh->ns_stat |= NS_ENDDISP;
		}
	}
	if( 0 <= Nsh->ns_sync[0] ){
		close(Nsh->ns_sync[0]);
		Nsh->ns_sync[0] = -1;
	}
	if( 0 <= Nsh->ns_sync[1] ){
		close(Nsh->ns_sync[1]);
		Nsh->ns_sync[1] = -1;
	}
	if( 0 <= Nsh->ns_tty ){
		ShutdownSocket(Nsh->ns_tty); /* needless with CloseOnExec */
		close(Nsh->ns_tty);
		Nsh->ns_tty = -1;
	}
	if( (Nsh->ns_stat & NS_ENDPROC) == 0 && Nsh->ns_pid ){
		porting_dbg("--Nsh waiting %d ...",Nsh->ns_pid);
		xpid = bgwait(Nsh->ns_pid,Nsh->ns_ph,10);
		porting_dbg("--Nsh WAIT xpid=%d %d/%d",xpid,
			Nsh->ns_pid,Nsh->ns_cpid);
		if( xpid == Nsh->ns_pid || xpid < 0 ){
			Nsh->ns_stat |= NS_ENDPROC;
		}
	}
	if( Nsh->ns_free ){
		porting_dbg("---- free Nsh=%X",p2i(Nsh));
		free(Nsh);
	}
	return 0;
}
int netsh_main(int ac,const char *av[]){
	Netsh *Nsh;
	int sutty = 0;

	Nsh = openNetsh(0,"/bin/sh",(char*const*)av,environ,1,0,1,sutty,0,0,1);
	waitNetsh(Nsh,0);
	return 0;
}

#if defined(_MSC_VER)
typedef void ttyStat;
ttyStat *windumpTTyStat(FILE *infp,PVStr(stat),int ssiz);
int winsetTTyStat(FILE *infp,ttyStat *stat,const char *strstat);
int winrestoreTTyStat(FILE *infp,ttyStat *stat);
#else
#define windumpTTyStat(infp,stat,ssiz) 0
#define winsetTTyStat(inff,stat,strstat) 0
#define winrestoreTTyStat(inff,stat) 0
#endif

int getpass0(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch));
int getpass1(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch)){
	int rcode;
	IStr(ttyb,128);
	/*
	refQStr(pp,pass);
	*/
	void *tty;

	if( isWindows() ){
		tty = windumpTTyStat(in,AVStr(ttyb),sizeof(ttyb));
		winsetTTyStat(in,tty,"raw -echo");
	}else{
	tty = dumpTTyStat(0);
	system("stty raw -echo");
	}

	rcode = getpass0(in,out,BVStr(pass),xpass,echoch);

	if( isWindows() ){
		winrestoreTTyStat(in,tty);
	}else{
		system("stty -raw echo");
		system("stty sane");
		restoreTTyStat(0,tty);
		freeTTyStat(tty);
	}
	return rcode;
}
int getpass0(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch)){
	refQStr(pp,pass);
	int ch;

	if( *pass ){
		for( pp = pass; *pp; pp++ ){
			fputs(echoch,out);
		}
		fflush(out);
	}
	for(;;){
		ch = getc(in);
		if( ch == EOF ){
			break;
		}
		if( ch == '\r' || ch == '\n' ){
			break;
		}
		if( ch == '\b' || ch == '\177' ){
			if( pass < pp ){
				pp--;
				setVStrEnd(pp,0);
				fputs("\b \b",out);
				fflush(out);
			}
			continue;
		}
		if( ch == 'U'-0x40 ){
			while( pass < pp ){
				pp--;
				setVStrEnd(pp,0);
				fputs("\b \b",out);
			}
			fflush(out);
			pp = pass;
			setVStrEnd(pp,0);
			continue;
		}
		setVStrPtrInc(pp,ch);
		setVStrEnd(pp,0);
		if( xpass && xpass[pp-pass-1] != ch ){
			fputs("?",out);
		}else{
			fputs(echoch,out);
		}
		fflush(out);
	}
	return 0;
}
int getpass_main(int ac,const char *av[]){
	IStr(pass1,1024);
	IStr(pass2,1024);

	getpass1(stdin,stderr,AVStr(pass1),0,"*");
	fprintf(stderr,"\r\n");
	getpass1(stdin,stderr,AVStr(pass2),pass1,"*");
	fprintf(stderr,"\r\n");
	fprintf(stdout,"%s\n",pass1);
	if( streq(pass1,pass2) ){
		return 0;
	}else{
		fprintf(stdout,"%s\r\n",pass2);
		return -1;
	}
}
int relay2X(int fromcl,int tocl,int fromsv,int tosv,int ignsig);
int forkpty_main(int ac,const char *av[]){
	IStr(name,256);
	IStr(cwd,256);
	int pid,xpid;
	int tty;
	int withsh = 1;

	getcwd(cwd,sizeof(cwd));
	errno = 0;
	pid = _ForkptyX(&tty,name,0,0);
	if( pid == 0 ){
		if( withsh ){
			fprintf(stderr,"----[%d] /bin/sh ...\n",getpid());
			fflush(stderr);
			execl("/bin/sh","/bin/sh",(void*)0);
		}
		fprintf(stderr,"----[%d] exit ...\n",getpid());
		_exit(0);
	}
	fprintf(stderr,"----[%d] forkpty pid=%d tty=[%d]%s e%d [%s]\n",
		getpid(),pid,tty,name,errno,cwd);
	if( withsh ){
		system("stty raw -echo");
		relay2X(0,1,tty,tty,0);
		system("stty sane");
	}
	fprintf(stderr,"----[%d] wait ...\n",getpid());
	xpid = wait(0);
	fprintf(stderr,"----[%d] wait %d\n",getpid(),xpid);
	return 0;
}

int dgforkpty_main(int ac,char *av[]);
int dgForkpty_main(int ac,const char *av[]){
	int rcode;
	int ai;
	int pid;
	char *nev[1024];

	pid = getpid();
	for( ai = 0; ai < ac; ai++ ){
		fprintf(stderr,"--[%d][%d] %s\n",pid,ai,av[ai]);
	}
	filterDGENV(environ,nev,elnumof(nev));
	environ = nev;
	rcode = dgforkpty_main(ac,(char**)av);
	_exit(rcode);
	return -1;
}
#endif /*} --------------------------------------------------------------*/
//#ifdef DGFORKPTY /*{ ----------------------------------- dgforkpty ----*/

int chrsubst(PVStr(str),int c1,int c2){
	refQStr(sp,str);
	int nx = 0;

	for( sp = str; *sp; sp++ ){
		if( *sp == c1 ){
			*(char*)sp = c2;
			nx++;
		}
	}
	return nx;
}
static int setHOME(PCStr(home)){
	char *ret;
	int rcode;
	IStr(cwd,256);
	IStr(env,256);
	IStr(path,256);

	if( getenv("HOME") != 0 ){
		/* HOME is already set maybe explicitly by YYCONF=HOME: */
	}else
	if( isWindows() && (home==0||*home==0) && getenv("SVPROTO") ){
		/* 9.9.12 new-140824d, running as a service */
		const char *svhome = getenv("SVHOME");
		const char *windrive = getenv("HOMEDRIVE");
		const char *winhome = getenv("HOMEPATH");

		if( svhome && fileIsdir(svhome) ){
			/* maybe from CYGWIN */
			home = svhome;
		}else
		if( windrive && winhome ){
			/* from Windows */
			sprintf(path,"%s%s",windrive,winhome);
			if( fileIsdir(path) ){
				home = path;
			}
		}
	}

	ret = getcwd(cwd,sizeof(cwd));
	if( home && *home ){
		if( chdir(home) == 0 ){
			ret = getcwd(cwd,sizeof(cwd));
		}
	}
	chrsubst(AVStr(cwd),'\\','/');
	if( strcasecmp(cwd+1,":/cygwin") == 0 ){
		strcat(cwd,"/home");
		rcode = chdir(cwd);
	}
	sprintf(env,"HOME=%s",cwd);
	putenv(env);
	porting_dbg("---- HOME=%s [%s]",cwd,home?home:"");
	return 1;
}

static int relayTTy(int ptyfd,int ttyfd,int logfd){
	int fdv[2],rdv[2],ofv[2],rdy,fi,rcc,wcc;
	IStr(buf,1024);
	IStr(end,128);
	FILE *fiv[2],*fov[2];
	int ch;
	int pch = -1;
	int col,row;
	char ibuf[16*1024];
	char obuf[16*1024];

	fdv[0] = ptyfd;
	fiv[0] = fdopen(ptyfd,"r"); fov[1] = fdopen(ptyfd,"a");
	if( fiv[0] == 0 || fov[1] == 0 ){
		fprintf(stderr,"--pty[%d] %X %X\n",ptyfd,p2i(fiv[0]),p2i(fov[1]));
	}
	fdv[1] = ttyfd;
	fiv[1] = fdopen(ttyfd,"r"); fov[0] = fdopen(ttyfd,"a");
	if( fiv[1] == 0 || fov[0] == 0 ){
		fprintf(stderr,"--tty[%d] %X %X\n",ttyfd,p2i(fiv[1]),p2i(fov[0]));
	}

	setvbuf(fiv[0],ibuf,STDIO_IOFBF,sizeof(ibuf));
	setvbuf(fov[1],obuf,STDIO_IOFBF,sizeof(obuf));
	for(;;){
		if( end[0] ){
			break;
		}
		rdy = fpollins(2,fiv,rdv);
		if( rdy == 0 ){
			fflush(fov[0]);
			fflush(fov[1]);
			rdy = _PollIns(0,2,fdv,rdv);
		}
		if( rdy <= 0 ){
			sprintf(end,"---rdy=%d [%d %d] e%d",rdy,
				rdv[0],rdv[1],errno);
			break;
		}
		for( fi = 0; fi < 2; fi++ ){
			if( rdv[fi] == 0 ){
				continue;
			}
			if( fi == 1 ){ /* from remtoe ttyfd */
				ch = recvTTySize(ptyfd,pch,fiv[fi],&col,&row);
				pch = ch;
				if( ISTEL(ch) ){
					porting_dbg("--WINSIZE %dx%d (dg)",
						col,row);
					setTTySize(ptyfd,col,row);
					continue;
				}
			}else{
				ch = getc(fiv[fi]);
			}
			if( ch == EOF ){
				sprintf(end,"--(%d)[%d] in EOS e%d",
					fi,rdv[fi],errno);
				goto EXIT;
			}
			if( putc(ch,fov[fi]) == EOF ){
				sprintf(end,"--(%d)[%d] out EOS e%d",
					fi,rdv[fi],errno);
				goto EXIT;
			}
		}
	}
EXIT:
	fprintf(stderr,"[%d] forkpty exit(%s)\n",getpid(),end);
	return 0;
}

static int KillShell(int pid){
	int xpid;

	xpid = NoHangWait();
	if( xpid < 0 ){
		return 1;
	}
	if( xpid == pid ){
		return 2;
	}
	/*
	if( isCYGWIN() )
	*/
	if( !procIsAlive(pid) ){
		return 3;
	}
	msleep(100);
	if( !procIsAlive(pid) ){
		return 4;
	}
	killpg(pid,SIGINT);
	Kill(pid,SIGINT);
	xpid = NoHangWait();
	if( xpid == pid ){
		return 5;
	}
	msleep(100);
	porting_dbg("--xpid=%d %d/%d",xpid,pid,procIsAlive(pid));
	if( !procIsAlive(pid) ){
		return 6;
	}
	msleep(100);
	xpid = NoHangWait();
	if( xpid == pid ){
		return 6;
	}
	porting_dbg("--xpid=%d %d/%d",xpid,pid,procIsAlive(pid));
	return 0;
}
int dgforkpty_main(int ac,char *av[]){
	int serrno;
	int pid;
	int ttyport = -1;
	IStr(name,128);
	int ptyfd = -1;
	int ttyfd = -1;
	int logfd = -1;
	IStr(rets,DGFSZ);
	int wcc = -1;
	int xend;

#if !defined(UNDER_CE) /*{*/
	if( isCYGWIN() ){
		int ofd = fileno(stderr);
		FILE *fp;
		int err;
		if( fp = fopen("C:/DeleGate/dgpty.log","a") ){
			setbuffer(fp,0,0);
			*stderr = *fp;
			fprintf(stderr,"[%d] %d\n",getpid(),(int)time(0));
		}
	}
#endif /*}*/
	if( ac < 3 ){
		fprintf(stderr,"ERROR: Usage: %s fd# path [arg] ...\n",av[0]);
		fflush(stderr);
		_exit(-1);
		return -1;
	}
	sscanf(av[1],"%d/%d/%d",&ttyfd,&logfd,&ttyport);
	if( isCYGWIN() ){
		setHOME(getenv("YYHOME"));
	}
	if( 0 < logfd ){
		/*
		if( file_is(logfd) <= 0 ){
			if( isWindows() ){
				FILE *logfp;
				logfp = fopen("C:/DeleGate/dgforkpty.log","a");
				logfd = fileno(logfp);
			}
		}
		*/
		if( isCYGWIN() ){
		}else
		dup2(logfd,fileno(stderr));
		/*
		if( 0 <= curLogFd() ){
			dup2(logfd,curLogFd());
		}
		*/
	}
	if( ttyfd < 0 && 0 < ttyport ){
		ttyfd = connectA("127.0.0.1",ttyport,10*1000);
		fprintf(stderr,"[%d] dgforkpty: [%s] %d\n",getpid(),
			av[1],ttyfd);
	}
	if( ttyfd < 0 || 256 <= ttyfd ){
		fprintf(stderr,"ERROR: %s fd#(%s?) path [arg] ...\n",av[0],
			av[1]);
		return -2;
	}

	clearVStr(name);
	errno = 0;
	pid = _ForkptyX(&ptyfd,name,0,0);
	if( pid < 0 ){
		fprintf(stderr,"[%d] ERROR:forkpty: %s pid=%d (%s) e%d\n",
			getpid(),av[0],pid,av[2],errno);
		return -2;
	}else
	if( pid == 0 ){
		if( 0 <= ttyfd ){
			/* v9.9.10 fix-140625d On Windows, since 9.9.7-pre23 (!)
			 * bgexec() use not spawn() but CreateProcess() thus
			 * no "osfhandle" is passed using C_FILE_INFO.
			 * Thus "ttyfd" above is assigned to "1" after the
			 * file for "dgpty.log"is assigned to "0".
			 * Thus close(ttyfd) closes the standard output to
			 * be inherited to the invoked program (ie. shell)
			 */
			if( 2 < ttyfd )
			close(ttyfd);
		}
		setupTTy(0,1);

		/* chroot, setlogin, setuid, setcloseonexec, unsetenv...  */
		/* sync. to the parent process's uid */
		if( !isWindows() ){
			int uid,gid,rcode;
			const char *user;

			uid = getuid();
			gid = getgid();
			/*
			if( user = getenv("LOGNAME") ){
			rcode = SetLogin(user);
	fprintf(stderr,"setlogin(%s)=%d e%d\n",user,rcode,errno);
			}
			*/
			rcode = setegid(gid);
	if( rcode != 0 )
	fprintf(stderr,"setegid(%d)=%d e%d\n",gid,rcode,errno);
			rcode = seteuid(uid);
	if( rcode != 0 )
	fprintf(stderr,"seteuid(%d)=%d e%d\n",uid,rcode,errno);
		}
		execve(av[2],&av[3],environ);
		fprintf(stderr,"[%d] %s ERROR:exec(%s) e%d\n",
			getpid(),av[0],av[2],errno);
		if( isCYGWIN() ){ /* v9.9.12 new-140823h */
			const char *path = "c:/cygwin/bin/sh.exe";
			fprintf(stderr,"-- retrying with SHELL=%s\r\n",path);
			fflush(stderr);
			execve(path,&av[3],environ);
		}
		_exit(-3);
		return -3;
	}else{
		sprintf(rets,"%63s","");
		sprintf(rets,"%d %s\r\n",pid,name);
		wcc = write(ttyfd,rets,DGFSZ);
		fprintf(stderr,"[%d] dgforkpty: [%d][%d] wcc=%d [%d %s]\r\n",
			getpid(),ptyfd,ttyfd,wcc,pid,name);
		relayTTy(ptyfd,ttyfd,logfd);

		setTTyMode(ptyfd,"isig");
		if( 0 < pid ){
			killpg(pid,SIGINT);
		}
		close(ptyfd);
		xend = KillShell(pid);
		return 0;
	}
}
//#endif /*} ------------------------------------------------------------*/
