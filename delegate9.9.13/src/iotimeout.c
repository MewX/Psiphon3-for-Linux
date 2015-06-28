/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	iotimeout.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940802	created

timeout could be the function of I/O buffer size...

//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "vsignal.h"
#include "ysocket.h"
#include "fpoll.h"
#include "dglib.h"
#include "file.h"
#include "log.h"
#include <errno.h>

#undef  sv1log
#define sv1log	syslog_ERROR

#define CHECK_ITVL	(10*1000)

extern int (*CheckClosed)(int);
int checkCloseOnTimeout(int checktime){
	if( CheckClosed )
		return (*CheckClosed)(checktime);
	else	return 0;
}

#define xPollIn(fd,timeout) FL_xPollIn(FL_ARG,fd,timeout)
int FL_xPollIn(FL_PAR,int fd,int timeout)
{	int nready,ntry;
	int remain,timeout1;
	int closed;

	if( readyAlways(fd) )
		return 1;

	timeout = IOTIMEOUT(timeout);

	nready = -1;
	remain = timeout;
	closed = 0;

	for( ntry = 0; timeout == 0 && ntry < 1 || 0 < remain; ntry++ ){
		if( closed = checkCloseOnTimeout(1) )
			timeout1 = remain;
		else
		if( CHECK_ITVL < remain )
			timeout1 = CHECK_ITVL;
		else	timeout1 = remain;
		errno = 0;
		nready = PollIn(fd,timeout1);
		if( 0 < nready )
			break;

/*
this was introduced as a trial to reset possible POLL_PRI status
at DeleGate/5.7.5 (17Nov98), but seemed useless,
and was got rid of at DeleGate/5.9.1 because it is harmful; at least
it cause blocking on slow I/O on Win32.
		if( nready == 0 ){
			CStr(buf,1);
			if( RecvOOB(fd,buf,0) == 0 )
			sv1log("#### POLL_PRI ? PollIn()==0, RecvOOB()==0\n");
		}
*/

		if( nready < 0 ){
			if( errno == EINTR )
				sv1log("#### INTERRUPTED PollIn()=%d <= %s:%d\n",nready,FL_BAR);
			else{
				sv1log("#### xPollIn(%d,%d)=%d errno=%d\n",
					fd,timeout,nready,errno);
				break;
			}
		}else	remain -= timeout1;
	}
	if( closed == 0 )
		checkCloseOnTimeout(1);
	if( 100 < ntry )
		sv1log("#### xPollIn(%d,%d)*%d : %d\n",fd,timeout,ntry,nready);
	return nready;
}

/*
 * the timeout should be shorter when threads or processes are busy.
 */
int IOTIMEOUT_FL(FL_PAR,int msec){
	int to1;
	if( lSINGLEP() ){
		if( lMULTIST() )
			to1 = 60;
		else	to1 = 30;
		if( to1*1000 < msec ){
			Verbose("TIMEOUT shorten (%d <- %d) %s:%d\n",
				to1,msec/1000,FL_BAR);
			msec = to1*1000;
		}
	}
	return msec;
}

int setferror(FL_PAR,FILE *fp);
int Setferror(FL_PAR,FILE *fp,int sig){
	int fd,sfd,nfd;

	if( ferror(fp) )
		return 0;
	if( sig != SIGPIPE ){
		return -1;
	}
	if( isWindowsCE() ){
		return -1;
	}
	fd = fileno(fp);
	if( !file_isSOCKET(fd) && !file_isfifo(fd) ){
		return -1;
	}
	setferror(FL_BAR,fp);
	return 0;
}

/*
 * I/O timeout in seconds
 */
int IO_TIMEOUT = (10*60);

#include "proc.h"
typedef struct {
	int	t_x;
	int	t_pid;
	double	t_Time;
	int	t_id;
	int	t_fd;
	int	t_timer;
	int	t_sig;
 void (*t_pipe)(int sig);
	int	t_sser;
	int	t_cln;
 sigjmp_buf	t_ioenv;
} ThreadIO;
static int sser[MAX_THREADS]; /* setjmp serial */
static int nsig[MAX_THREADS];
static int threadPID[MAX_THREADS];
static ThreadIO *threadIO[MAX_THREADS];

void clearThreadFilter();
void clearThreadEnv(){
	int ti;

	for( ti = 0; ti < MAX_THREADS; ti++ ){
		if( threadIO[ti] ){
			sv1log("-- clearThreadEnv[%d] %X %d %d %d\n",
				ti,p2i(threadIO[ti]),sser[ti],nsig[ti],threadPID[ti]);
		}
		threadIO[ti] = 0;
		sser[ti] = 0;
		nsig[ti] = 0;
		threadPID[ti] = 0;
	}
	clearThreadFilter();
}
void clearThreadSig(){
	int ti;
	for( ti = 0; ti < MAX_THREADS; ti++ ){
		if( nsig[ti] ){
			sv1log("-- clearThreadSig[%d] %d %d\n",ti,
				nsig[ti],sser[ti]);
		}
		nsig[ti] = 0;
	}
}

int getmtpid();
static int okenv(ThreadIO *tio){
	int off = (char*)tio - (char*)&tio;
	if( tio->t_x < 0 || elnumof(threadIO) <= tio->t_x ){
		porting_dbg("--stale ThreadIO %X %X x=%X",p2i(tio),off,tio->t_x);
		return 0;
	}
	if( tio->t_sser != sser[tio->t_x] ){
		porting_dbg("--stale ThreadIO %X %X ser=%X/%X",p2i(tio),off,
			tio->t_sser,sser[tio->t_x]);
		return 0;
	}
	if( tio->t_pid != getmtpid() ){
		porting_dbg("--stale ThreadIO %X %X pid=%d/%d tid=%X",p2i(tio),off,
			tio->t_pid,getmtpid(),tio->t_id
		);
		return 0;
	}
	return 1;
}

int gotSIGPIPE(){
	return nsig[getthreadix()];
}
int iamServer();
int MAX_SIGPIPE = 100; /* max. SIGPIPE caught in an output action */
static void io_timeout(int sig){
	ThreadIO *myenv;
	ThreadIO *ev1;
	int mx,my_tid,tid,tid1;
	int tn,tx,ti;
	int my_pid;

	Vsignal(SIGPIPE,io_timeout); /*should be before thread_kill()*/
	if( sig == SIGPIPE ){
		/* should not do longjump() to set ferror()...
		 * and maybe the longjump() on SIGPIPE is not necessaly.
		 * 9.8.2 set explicitly by Setferror() as an workaround
		 */
		if( lNOSIGPIPE() ){
			return;
		}
	}

	mx = getthreadix();
	my_tid = getthreadid();
	myenv = threadIO[mx];
	sv1log("IO_TIMEOUT[%d] SIGPIPE got by[%X] longjump %X[%X] %d/%d\n",
		mx,my_tid,p2i(myenv),myenv?myenv->t_id:0,
		actthreads(),numthreads());
	if( numthreads() ){
		if( isatty(fileno(stderr)) )
		fprintf(stderr,"-- %X gotSIGPIPE(%d) [%d]%X[%X] %d/%d\n",
			TID,sig,mx,p2i(myenv),myenv?myenv->t_id:0,
			actthreads(),numthreads());
	}

	if( myenv && myenv->t_id == my_tid && okenv(myenv) ){
		nsig[mx] += 1;
		if( myenv->t_sig != 0 ){
			sv1log("IO_TIMEOUT[%d] SIG*%d (%d %d) in longjump\n",
				mx,nsig[mx],myenv->t_sig,sig);
			if( MAX_SIGPIPE < nsig[mx] )
			if( !lSINGLEP() && !iamServer() ){
				sv1log("####Finish: Too Many SIGPIPE: %d\n",
					nsig[mx]);
				Finish(-1);
			}
			return;
		}
		myenv->t_sig = sig;
		siglongjmpX(myenv->t_ioenv,sig);
		return;
	}

	tid = 0;
	my_pid = getmtpid();
	for( tn = 0; tn < elnumof(threadIO); tn++ ){
		tx = (mx + 1 + tn) % elnumof(threadIO);
		if( threadPID[tx] != my_pid ){
			threadIO[tx] = 0;
			continue;
		}
		if( (ev1 = threadIO[tx]) == 0 /*|| !validenv(tx,ev1) */ ){
			continue;
		}
		if( !okenv(ev1) ){
			threadIO[tx] = 0;
			continue;
		}
		if( (tid1 = ev1->t_id) == 0 )
			continue;
		sv1log("IO_TIMEOUT[%d] candidate %X [%d]\n",
			tx,tid1,ev1->t_fd);
		if( tid == 0 ){
			tid = tid1;
		}
		porting_dbg("candidate handler IO_TIMEOUT[%d] %X [%d]",
			tx,tid,ev1->t_fd);
		nsig[tx] += 1;
		break;
	}
	if( tid == my_tid ){
		sv1log("IO_TIMEOUT: dangling? SIG%d -> %X\n",sig,my_tid);
		porting_dbg("IO_TIMEOUT: dangling? SIG%d -> %X ++++",
			sig,my_tid);
	}else
	if( tid ){
		porting_dbg("IO_TIMEOUT: forwarded SIG%d %X -> %X",
			sig,my_tid,tid);
		sv1log("IO_TIMEOUT: forwarded SIG%d %X -> %X\n",
			sig,my_tid,tid);
		thread_kill(tid,sig);
	}else{
		sv1log("IO_TIMEOUT: dangling SIG%d -> %X\n",sig,my_tid);
		porting_dbg("IO_TIMEOUT: dangling SIG%d -> %X ----",
			sig,my_tid);
	}

}
static void gotSIG(PCStr(F),int L,ThreadIO *myenv,int timeout){
	sv1log("IO_TIMOEUT[%d]%X %X longreturn SIG%s timeout=%d [%d] %s:%d/%d\n",
		getthreadix(),getthreadid(),myenv->t_id,
		sigsym(myenv->t_sig),timeout,
		myenv->t_fd,F,L,myenv->t_cln);
}


void putsLogXf(PCStr(wh),int isig);
#define DONE_SUCCESSFULLY() \
	threadIO[mx] = 0; \
	Vsignal(SIGPIPE,myenv.t_pipe); \
	popTimer(myenv.t_timer); \
	checkCloseOnTimeout(1); \
	bzero(&myenv,sizeof(myenv)); \
	putsLogXf("io_timeout",myenv.t_sig); \
	selfLocaltime--; \

#define	fRETURN_ONTIMEOUTX(fp,fd,retv,timeout) \
	ThreadIO myenv; \
	int mx = getthreadix(); \
	selfLocaltime++; \
	if( threadIO[mx] != 0 ) \
		sv1log("IO_TIMEOUT[%d] [%X] overwrites [%X]\n", \
		getthreadix(),getthreadid(),threadIO[mx]->t_id); \
	threadPID[mx] = getmtpid(); \
	nsig[mx] = 0; \
	checkCloseOnTimeout(1); \
	myenv.t_x = mx; \
	myenv.t_sser = (sser[mx] += 1); \
	myenv.t_Time = Time(); \
	myenv.t_pid = getmtpid(); \
	myenv.t_cln = __LINE__; \
	myenv.t_fd = fp ? fileno(fp) : fd; \
	myenv.t_sig = 0; \
	myenv.t_timer = pushTimer("Timered-IO",io_timeout,timeout); \
	myenv.t_id = getthreadid(); \
	if( sigsetjmpX(myenv.t_ioenv,1) != 0 ){ \
		if( fp ) Setferror(FL_ARG,fp,myenv.t_sig); \
		threadIO[mx] = 0; \
		if( !isSolaris() ) if( fp ) funlockfile(fp); \
		gotSIG(__FILE__,__LINE__,&myenv,timeout); \
		DONE_SUCCESSFULLY(); \
		return retv; \
	}else{ \
		myenv.t_pipe = Vsignal(SIGPIPE,io_timeout); \
		threadIO[mx] = &myenv; \
	}

#define	fRETURN_ONTIMEOUT(fp,retv)    fRETURN_ONTIMEOUTX(fp,-1,retv,IO_TIMEOUT)
#define	RETURN_ONTIMEOUTX(fd,retv,to) fRETURN_ONTIMEOUTX((FILE*)0,fd,retv,to)
#define	RETURN_ONTIMEOUT(fd,retv) RETURN_ONTIMEOUTX(fd,retv,IO_TIMEOUT)

extern int CON_TIMEOUT;
int connectV(int s,void *name,int namelen);
int connectTIMEOUT(int fd,void *name,int namelen){
	int rcode;
	int umask,omask;

	if( CON_TIMEOUT == 0 ){
		return connectV(fd,name,namelen);
	}
	CONNERR_TIMEOUT = 1;
	{
	RETURN_ONTIMEOUTX(fd,-1,CON_TIMEOUT);/*longreturn from here on TIMEOUT*/
	rcode = connectV(fd,name,namelen);
	DONE_SUCCESSFULLY();
	}
	CONNERR_TIMEOUT = 0;
	return rcode;
}

/*
int writevTimeout(int fd,char **iov,int nv,int timeout)
{	int wcc;

	RETURN_ONTIMEOUTX(fd,-1,timeout);
	wcc = writev(fd,iov,nv);
	DONE_SUCCESSFULLY();
	return wcc;
}
*/
int sendTimeout(int fd,PCStr(buff),int leng,int flag,int timeout)
{	int wcc;

	RETURN_ONTIMEOUTX(fd,-1,timeout);
	wcc = send(fd,buff,leng,flag);
	DONE_SUCCESSFULLY();
	return wcc;
}

int fwriteTIMEOUT1(PCStr(b),int s,int n,FILE *fp)
{	int rc;

	fRETURN_ONTIMEOUT(fp,0);
	rc = Fwrite(b,s,n,fp);
	DONE_SUCCESSFULLY();
	return rc;
}
int isNULLFP(FILE *fp);
int fwriteTIMEOUT(PCStr(b),int s,int n,FILE *fp){
	int wn;
	wn = fwriteTIMEOUT1(b,s,n,fp);
	if( wn < n || gotSIGPIPE() ){
if( !isNULLFP(fp) )
if( !lMULTIST() )
porting_dbg("+++EPIPE fwriteTIMEOUT() %d/%d SIG*%d",wn,n,gotSIGPIPE());
		if( !isSolaris() ) funlockfile(fp);
	}
	return wn;
}
int fputsTIMEOUT(PCStr(b),FILE *fp)
{	int rcode;

	fRETURN_ONTIMEOUT(fp,0);
	rcode = fputs(b,fp);
	DONE_SUCCESSFULLY();
	return rcode;
}
extern int LIN_TIMEOUT;
int fflushTIMEOUT(FILE *fp)
{
	return fflushTIMEOUT_FL(FL_ARG,fp);
}
int fflushTIMEOUT_FL(FL_PAR,FILE *fp)
{	int rcode;

	if( feof(fp) )
		return EOF;
	if( ferror(fp) ){
		if( !isNULLFP(fp) )
		if( !lMULTIST() )
		porting_dbg("+++EPIPE[%d] fflushTIMEOUT() for EOF",fileno(fp));
		return EOF;
	}

	{
	fRETURN_ONTIMEOUTX(fp,-1,EOF,LIN_TIMEOUT+1);
	/*
	rcode = fflush(fp);
	*/
	rcode = Xfflush(FL_BAR,fp);
	DONE_SUCCESSFULLY();
	return rcode;
	}
}
int fcloseTIMEOUT(FILE *fp)
{
	return fcloseTIMEOUT_FL(__FILE__,__LINE__,fp);
}
int fcloseTIMEOUT_FL(FL_PAR,FILE *fp)
{	int rcode;

	if( fileno(fp) < 0 ){
		porting_dbg("+++EPIPE[%d] fcloseTIMEOUT() for EOF",fileno(fp));
		/*
		return EOF;
		9.8.2 should free the FILE structure.
		*/
		rcode = fcloseFILE(fp);
		return rcode;
	}

	/*
	 * 9.8.2 this code is bad leaving FILE and descriptor unclosed.
	 * added in 2.4.8 maybe (?) intented to close disconnected stream
	 * without causing alarm signal for timeout (and buffer flushing ?).
	if( feof(fp) )
		return EOF;
	 */
	if( feof(fp) /*|| ferror(fp)*/ ){
		if( ferror(fp) || LOG_VERBOSE )
		sv1log("-- fcloseTIMEOUT(%X/%d/S%d) EOF=%d ERR=%d\n",
			p2i(fp),fileno(fp),SocketOf(fileno(fp)),feof(fp),ferror(fp));
		dupclosed_FL(FL_BAR,fileno(fp));
		rcode = Xfclose(FL_BAR,fp);
		return rcode;
	}

	{
	fRETURN_ONTIMEOUTX(fp,-1,EOF,LIN_TIMEOUT+2);
	/*
	rcode = fclose(fp);
	*/
	rcode = Xfclose(FL_BAR,fp);
	DONE_SUCCESSFULLY();
	return rcode;
	}
}
FILE *fopenTO(PCStr(path),PCStr(mode),int timeout){
	FILE *fp;

	RETURN_ONTIMEOUTX(-1,NULL,timeout);
	fp = fopen(path,mode);
	DONE_SUCCESSFULLY();
	return fp;
}

static int readSERNO;
int readTimeoutBlocked(int fd,PVStr(buf),int siz,int timeout)
{	int omask,nmask;
	int rcc;
	int serno;
	int serrno;

	alertVStr(buf,siz);
	rcc = -1;
	omask = sigblock(sigmask(SIGCHLD));
	serno = ++readSERNO;
	if( 0 < PollIn(fd,timeout) ){
		errno = 0;
		rcc = read(fd,(char*)buf,QVSSize(buf,siz));
		serrno = errno;
		if( rcc != siz ){
		sv1log("##ERROR: readTimeoutB insufficient read %d/%d (%d)%X\n",
			rcc,siz,errno,sigblock(0));
		}
		errno = serrno;
	}
	if( serno != readSERNO ){
		sv1log("##ERROR: readTimeoutB broken %d/%d (%d)%X\n",
			serno,readSERNO,errno,sigblock(0));
		sleep(10);
	}
	nmask = sigsetmask(omask);
	return rcc;
}
int readTimeout(int fd,PVStr(b),int z,int tout)
{	int nready,rc;

	alertVStr(b,z);
	if( 0 < (nready = xPollIn(fd,tout*1000)) )
		return read(fd,(char*)b,QVSSize(b,z));
	else{
		sv1log("read(%d) -- ready=%d IO_TIMEOUT(%d)\n",z,nready,tout);
		return 0;
	}
}
int readTIMEOUT(int fd,PVStr(b),int z)
{
	alertVStr(b,z);
	return readTimeout(fd,BVStr(b),z,IO_TIMEOUT);
}
int recvTIMEOUT(int fd,PVStr(b),int z,int f)
{	int rc;

	alertVStr(b,z);
	if( 0 < xPollIn(fd,IO_TIMEOUT*1000) )
		rc = recv(fd,(char*)b,QVSSize(b,z),f);
	else	rc = 0;
	return rc;
}
static int recvPeekTIMEOUT1(int fd,PVStr(b),int z)
{	int rc;

	alertVStr(b,z);
	{
	RETURN_ONTIMEOUTX(fd,-1,10);
	/*
	rc = RecvPeek(fd,(char*)b,z);
	*/
	rc = RecvPeek_FL(fd,(char*)b,z,whStr(b));
	DONE_SUCCESSFULLY();
	}
	return rc;
}
int recvPeekTIMEOUT(int fd,PVStr(b),int z)
{	int rc;

	alertVStr(b,z);
	if( 0 < xPollIn(fd,IO_TIMEOUT*1000) ){
		rc = recvPeekTIMEOUT1(fd,BVStr(b),z);
		if( rc <= 0 )
			sv1log("#### recvPeek: failed: %d\n",rc);
	}else{
		sv1log("recvPeekTIMEOUT: %d\n",IO_TIMEOUT);
		rc = 0;
	}
	return rc;
}
int fgetBuffered(PVStr(b),int n,FILE *fp);
int freadTIMEOUT(PVStr(b),int s,int n,FILE *fp)
{	int rn;

	alertVStr(b,s*n);
	if( feof(fp) ){
		sv1log("-- Tried freadTIMEOUT() for EOF file.\n");
		return 0;
	}
	if( 0 < READYCC(fp) ){
		if( s == 1 ){
			rn = fgetBuffered(BVStr(b),n,fp);
			if( rn == n )
				return rn;
			return rn + freadTIMEOUT(QVStr(b+rn,b),s,n-rn,fp);
		}
	}
	if( 0 < READYCC(fp) || 0 < xPollIn(fileno(fp),IO_TIMEOUT*1000) )
		return fread((char*)b,s,QVSSize(b,n),fp);
	else{
		sv1log("fread(%d*%d) -- IO_TIMEOUT(%d)\n",s,n,IO_TIMEOUT);
		return 0;
	}
}
void discardBuffered(FILE *fp)
{
	while( READYCC(fp) ){
		getc(fp);
	}
}
int fgetsBuffered(PVStr(b),int n,FILE *fp)
{	int mcc,cc,ch;
	int rdy;

	alertVStr(b,n);
	n--;
	rdy = READYCC(fp);
	if( 0 < rdy && isWindowsCE() ){
		sv1log("## fgetsBuffered[%d] %d/%d\n",fileno(fp),n,rdy);
	}
	for( cc = 0; cc < n; cc++ ){
		if( READYCC(fp) <= 0 )
			break;
		ch = getc(fp);
		setVStrElem(b,cc,ch); /**/
		if( ch == 0 )
			break;
		if( ch == EOF )
			break;
		if( ch == '\n' ){
			cc++;
			break;
		}
	}
	setVStrEnd(b,cc); /**/
	return cc;
}
int fgetBuffered(PVStr(b),int n,FILE *fp)
{	int mcc,cc,ch;
	int rdy,rc;

	alertVStr(b,n);
	rdy = READYCC(fp);
	if( 0 < rdy && isWindowsCE() ){
		if( n <= rdy )
			rc = n;
		else	rc = rdy;
		cc = fread((char*)b,1,rc,fp);
		Verbose("## fgetBuffered[%d] %d/%d %d/%d\n",
			fileno(fp),n,rdy,cc,rc);
		return cc;
	}
	for( cc = 0; cc < n; cc++ ){
		if( READYCC(fp) <= 0 )
			break;
		ch = getc(fp);
		setVStrElem(b,cc,ch);
		if( ch == EOF )
			break;
	}
	if( cc < n )
		setVStrEnd(b,cc);
	return cc;
}
int file_copyBuffered(FILE *in,FILE *out)
{	int cc,ch;

	for( cc = 0; 0 < READYCC(in) && (ch = getc(in)) != EOF; cc++ ){
		if( putc(ch,out) == EOF )
			break;
	}
	return cc;
}

char *fgets0(PVStr(b),int n,FILE *fp)
{	int ch,li;

	alertVStr(b,n);
	for( li = 0; li < n - 1; li++ ){
		ch = getc(fp);
		setVStrElem(b,li,ch); /**/
		if( ch == EOF || ch == '\n' )
			break;
		if( ch == 0 ){
			ungetc(ch,fp);
			break;
		}
	}
	setVStrEnd(b,li); /**/
	if( li == 0 )
		return NULL;
	else	return (char*)b;
}

static char *fgetsIfReady(PVStr(b),int s,FILE *fp,int *rc)
{	int bx,ch;

	alertVStr(b,s);
	bx = 0;
	while( bx < s-1 && 0 < READYCC(fp) ){
		ch = getc(fp);
		if( ch == EOF )
			break;
		setVStrElemInc(b,bx,ch); /**/
		if( ch == '\n' )
			break;
	}
	setVStrEnd(b,bx); /**/
	if( rc ) *rc = bx;

	if( bx == 0 && feof(fp) )
		return NULL;
	else	return (char*)b;
}

char *fgetsTIMEOUT(xPVStr(b),int s,FILE *fp)
{	const char *b0;
	const char *rs;
	int rc;

	alertVStr(b,s);
	setVStrEnd(b,0);
	if( feof(fp) ){
		sv1log("-- Tried fgetsTIMEOUT() for EOF file.\n");
		return NULL;
	}

	b0 = b;
	rc = 0;
	if( 0 < READYCC(fp) ){
		rs = fgetsIfReady(BVStr(b),s,fp,&rc);
		if( 0 < rc && b[rc-1] == '\n' || feof(fp) || rc == s-1 )
			return (char*)rs;
		b += rc;
		s -= rc;
	}
	if( 0 < FL_xPollIn(whStr(b),fileno(fp),IO_TIMEOUT*1000) )
		rs = Xfgets(BVStr(b),s,fp);
	else{
		CStr(wh,128);
		VStrId(AVStr(wh),BVStr(b));
		sv1log("fgets(%d) -- IO_TIMEOUT(%d) %s\n",s,IO_TIMEOUT,wh);
		/*
		sv1log("fgets(%d) -- IO_TIMEOUT(%d)\n",s,IO_TIMEOUT);
		*/
		rs = NULL;
	}
	if( rs == NULL && rc == 0 )
		return NULL;
	else	return (char*)b0;
}
char *fgetsTimeout(PVStr(b),int s,FILE *fp,int tout)
{	int stout;
	const char *rs;

	alertVStr(b,s);
	if( tout ){
		stout = IO_TIMEOUT;
		IO_TIMEOUT = tout;
		rs = fgetsTIMEOUT(BVStr(b),s,fp);
		IO_TIMEOUT = stout;
	}else	rs = Xfgets(BVStr(b),s,fp);
	return (char*)rs;
}

int fgetcTIMEOUT(FILE *fp)
{
	if( 0 < fPollIn(fp,IO_TIMEOUT*1000) )
		return getc(fp);
	else	return EOF;
}

char *fgetsTO(PVStr(b),int z,FILE *f,int t1,int t2){
	refQStr(bp,b);
	int ch;

	if( fPollIn(f,t1) <= 0 )
		return NULL;
	for(;;){
		ch = getc(f);
		if( ch == EOF )
			break;
		setVStrPtrInc(bp,ch);
		if( ch == '\n' )
			break;
		if( fPollIn(f,t2) <= 0 )
			break;
	}
	setVStrEnd(bp,0);
	if( b < bp ) 
		return (char*)b;
	else	return NULL;
}

#if defined(UNDER_CE)
char *fgetsByBlock(PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp);
#else
char *fgetsByBlockX(int exsock,PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp);
char *fgetsByBlock(PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp)
{
	return fgetsByBlockX(-1,BVStr(line),size,fs,
		niced,ltimeout,byline,fromcache,remlen,lengp,isbinp);
}
int pollIY(const char *wh,double timeout,int in,int ex,int exin);
int pollIZ(const char *wh,double timeout,int in,int exsock){
	int rem;
	int tom = 1000;
	int to1;
	int rdy1;
	int nrdy = 0;

	Verbose("---- poll(%s) [%d][%d] %.1f ...\n",wh,in,exsock,timeout);
	if( isWindows() && readyAlways(in) ){ /* 9.9.5 for Windows */
		nrdy = 1;
		if( 0 <= exsock && !IsAlive(exsock) ){
			nrdy |= 2;
		}
	}else
	for( rem = (int)(timeout*1000); 0 < rem; rem -= to1 ){
		if( 0 <= exsock && !IsAlive(exsock) ){
			nrdy |= 2;
			break;
		}
		if( tom < rem )
			to1 = tom;
		else	to1 = rem;
		rdy1 = PollIn(in,to1);
		if( rdy1 != 0 ){
			nrdy |= 1;
		}
		Verbose("---- poll(%s) [%d][%d] %.1f %.1f rdy=%X\n",wh,
			in,exsock,timeout,rem/1000.0,nrdy);
		if( nrdy ){
			break;
		}
	}
	if( LOG_VERBOSE || (nrdy == 0) || (nrdy & 2) )
	sv1log("---- poll(%s) [%d][%d] %.1f (%.1f) rdy=%X\n",wh,
		in,exsock,timeout,rem/1000.0,nrdy);
	return nrdy;
}
char *fgetsByBlockX(int exsock,PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp)
{	int cc,ch,bc;
	int timeout;
	int stimeout = 10;
	int mtimeout = 3000; /* timeout for slow input (might be without NL) */
	const char *rcode = line;
	int insize;
	int nread = 0;
	double Start = Time();
	int nnl = 0;
	int nrdy;

	if( ltimeout == 0 ){
		/* 9.9.7 timeout==0 causes timeout unconditionally */
		ltimeout = 60*60*24*1000;
	}

	alertVStr(line,size);
	if( !fromcache ){
		stimeout = 30;
		timeout = ltimeout;
	}
	if( !lFGETSBB_IZ() && 4*1024 <= size ){
		/* 9.9.8 to make faster/lighter relaying text over HTTP (can
		 * be made backward compatible with the "-Bis" option.
		 * This "insize" limitation was here since the origin (5.5.0)
		 * when there was no heavy "chunked encoding with flushing".
		 * It can generate small (1KB) chunks each flushed for send()
		 */
		/*
		insize = (size * 7) / 8;
		 * necessary to leave enough space in the buffer for rewriting
		 * a text data to be expanded with MOUNT, CHARCODE,
		 * Partfilter() or so.  "1/2" seems "enoguth" empirically...
		 */
		insize = size / 2;
	}else
	if( niced )
		insize = size / 2;
	else	insize = 1024;

	size--;
	bc = 0;

	for( cc = 0; cc < size; ){
		if( READYCC(fs) <= 0 ){
			nread++;
		}
		if( READYCC(fs) < 1 ){
		    if( !byline && 0 < cc && mtimeout < timeout ){
			int elp,tout;
			elp = (int)(1000*(Time()-Start));
			tout = mtimeout - elp;
			if( tout < 100 )
				tout = 100;
			/*
			if( fPollIn(fs,tout) == 0 ){
			*/
			nrdy = pollIZ("fgetsBB",tout/1000.0,fileno(fs),exsock);
			if( nrdy == 0 || (nrdy & 2) ){
				syslog_DEBUG("fgetsBB: slow %d/%d %.2f\n",
					cc,nnl,Time()-Start);
				break;
			}
		    }
		}
		if( !fromcache && READYCC(fs)<1 && 0 <= exsock ){
			double Tout = ((double)timeout)/1000;
				/*
			nrdy = pollIY("fgetsBB",Tout,fileno(fs),exsock,1);
				*/
			nrdy = pollIZ("fgetsBB",Tout,fileno(fs),exsock);
			if( nrdy == 0 || (nrdy & 2) ){
				int alive;
				alive = IsAlive(exsock);
				syslog_ERROR("fgetsBB: cc=%d ex[%d]%d %X %d\n",
					cc,exsock,alive,nrdy,timeout);
				if( alive <= 0 ){
					return NULL;
				}
				break;
			}
		}
		if( !fromcache && READYCC(fs)<1 && fPollIn(fs,timeout)<=0 ){
			if( cc == 0 ){
				syslog_ERROR("fgetsBB: TIMEOUT %dms\n",timeout);
				rcode = NULL;
			}
			break;
		}
		if( (ch = getc(fs)) == EOF ){
			if( cc == 0 )
				rcode = NULL;
			break;
		}

		setVStrElemInc(line,cc,ch); /**/
		if( ch == '\n' && (byline || insize < cc) )
			break;
		if( ch == 0 )
			bc++;

		if( !byline ){
			if( ch == '\n' ){
				nnl++;
			}
			if( ch == '\n' || ch == '\r' )
				timeout = stimeout;
			else
			if( remlen <= cc ){
				if( timeout != stimeout )
				syslog_DEBUG("fgetsBB: %d/%d TIMEOUT=%d->%d\n",
					cc,remlen,timeout,stimeout);
				timeout = stimeout;
			}
			else	timeout = ltimeout;
		}
	}

	setVStrEnd(line,cc); /**/
	*lengp = cc;
	*isbinp = bc;
	return (char*)rcode;
}
#endif

char *fgetsByLine(PVStr(line),int lsiz,FILE *in,int timeout,int *rccp,int *isbinp)
{
	alertVStr(line,lsiz);
	/*
	if( fPollIn(in,0) <= 0 )
	*/
	if( fPollIn(in,timeout) <= 0 )
	{
		sv1log("---- fgetsByLine(%d) TIMEOUT %s:%d\n",
			timeout,whStr(line));
		return NULL;
	}
	return fgetsByBlock(BVStr(line),lsiz,in,0,timeout,1,0,lsiz,rccp,isbinp);
}
char *fgetsLinesX(PVStr(line),int lsiz,FILE *in,int timeout,int *rccp,int *binp){
	return fgetsByBlock(BVStr(line),lsiz,in,0,timeout,0,0,lsiz,rccp,binp);
}
char *fgetsLines(PVStr(line),int lsiz,FILE *in,int timeout){
	int rcc;
	int bin;
	return fgetsByBlock(BVStr(line),lsiz,in,0,timeout,0,0,lsiz,&rcc,&bin);
}

int CTX_maxbps(DGC*Conn);
int MAX_NICE_VALUE = 10;
int MAX_NICE_SLEEP = 10;
int MIN_NICE_SLEEP =  1;
int MIN_SOCK_BUFSIZE = 1024;
int MAX_SOCK_BUFSIZE = 1024*64;
/*
 * try to do I/O every MAX_NICE_SLEEP seconds
 * to reduce the cost for process switch
 * without decreasing the speed of relay
 */
int doNice(PCStr(what),DGC*Conn,int ifd,FILE *ifp,int ofd,FILE *ofp,int niced,FileSize bytes,int count,double since)
{	double now,elapsed;
	double sec1,sec;
	int bsize,isize,osize;

	now = Time();
	elapsed = now - since;

	if( 0 < bytes ){
		int maxbps = CTX_maxbps(Conn);
		if( 0 < maxbps ){
			int bps;
			int slp = 0;
			bps = 8*(int)(bytes/elapsed);
			if( maxbps < bps ){
				if( maxbps*3 < bps ) slp = 4000; else
				if( maxbps*2 < bps ) slp = 2000; else
						     slp = 1000;
				msleep(slp);
				sv1log("-- %lld/%d %f %d/%d bps (%d)\n",
					bytes,count,elapsed, bps,maxbps,slp);
			}
		}
	}

	if( 10 <= (now - since) )
	if( niced < MAX_NICE_VALUE && (0x010000 << niced) < bytes ){
		niced += 1;
		IGNRETZ nice(1);

		bsize = ((int)((bytes/elapsed) * MAX_NICE_SLEEP*2)) & ~0x3FF;
		if( bsize == 0 )
			bsize = MIN_SOCK_BUFSIZE;
		if( MAX_SOCK_BUFSIZE < bsize )
			bsize = MAX_SOCK_BUFSIZE;

		if( 0 <= ifd ) expsockbuf(ifd,bsize,0);
		if( 0 <= ofd ) expsockbuf(ofd,0,bsize);

		isize = osize = 0;
		if( 0 <= ifd )
			getsockbuf(ifd,&isize,&osize);
		daemonlog("E","NICE-%d %dK/%d/%4.2fs %d/p %d/s buf=%d(%d)\n",
			niced,(int)(bytes/1024),
			count,elapsed,(int)(bytes/count),
			(int)(bytes/elapsed),isize,bsize);
	}

	if( actthreads() ){
		/* 9.6.1 not to break the scheduling amoung threads ... */
	}else
	if( 0 < niced )
	if( ifp == NULL || READYCC(ifp) <= 0 )
	if( 0 <= ifd && !readyAlways(ifd) && PollIn(ifd,1) == 0 )
	if( getsockbuf(ifd,&isize,&osize) == 0 ){
		sec = sec1 = (isize/4) / (bytes/elapsed);
		if( MIN_NICE_SLEEP < sec1 ){
			if( MAX_NICE_SLEEP < sec ) sec = MAX_NICE_SLEEP;
		daemonlog("E","NICE-%d %dK/%d/%4.2fs %d/p %d/s: %4.2fs/%4.2fs\n",
				niced,(int)(bytes/1024),
				count,elapsed,(int)(bytes/count),
				(int)(bytes/elapsed),sec,sec1);

			if( ofp != NULL )
				fflush(ofp);
			if( isWindowsCE() ){
			}else
			msleep((int)(sec*1000));
		}
	}
	return niced;
}

int connectToX(PCStr(addr),int port,int delayms,int infd)
{	int rcode,sock,nready,fdv[2],qev[2],rev[2];
	double Start1;
	CStr(stat,64);

	Start1 = Time();
	nready = rev[0] = rev[1] = 0;

	sock = Socket1("SMTP-CB", -1,NULL,NULL,NULL, VStrNULL,0, NULL,0, 0,NULL,0);
	if( sock < 0 ){
		rcode = -1;
		goto EXIT;
	}
	if( connectTimeout(sock,addr,port,1) == 0 ){
		rcode = 0;
		goto EXIT;
	}

	Start1 = Time();
	fdv[0] = infd; qev[0] = PS_IN;
	fdv[1] = sock; qev[1] = PS_OUT|PS_PRI;
	nready = PollInsOuts(delayms,2,fdv,qev,rev);

	if( nready <= 0 ){
		rcode = -2;
		goto EXIT;
	}
	if( (rev[1] & PS_OUT) == 0 ){
		rcode = -3;
		goto EXIT;
	}
	if( IsAlive(sock) ){
		rcode = 0;
		goto EXIT;
	}
	rcode = -4;

EXIT:
	if( rcode != 0 ){
		if( 0 <= sock ){
			close(sock);
			sock = -1;
		}
	}

	sprintf(stat,"%d[%d %s %s]",
		sock,
		sock_isconnected(sock),
		IsConnected(sock,NULL)?"Connected":"-",
		IsAlive(sock)?"Alive":"-");

	sv1log("#CToX%d %s %s:%d %d[%o][%o] %s %dms\n",
		rcode,rcode==0?"OK":"ERR", addr,port,
		nready,rev[0],rev[1],
		stat,(int)(1000*(Time()-Start1)));

	return sock;
}

int copyfileTimeout(FILE *in,FILE *out,int mtimeout,int pid){
	int ni;
	int len = 0;
	CStr(buf,8*1024);
	int rcc,wcc;

	for( ni = 0; ; ni++ ){
		if( feof(in) )
			break;
		if( fPollIn(in,1) == 0 ){
			fflush(out);
		}
		if( fPollIn(in,mtimeout) <= 0 ){
			break;
		}
		rcc = fread(buf,1,sizeof(buf),in);
		if( rcc <= 0 ){
			break;
		}
		len += rcc;
		wcc = fwrite(buf,1,rcc,out);
		if( wcc < rcc ){
			break;
		}
	}
	return len;
}
