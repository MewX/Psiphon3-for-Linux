/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Content-Type:   program/C; charset=US-ASCII
Program:        Thread.c
Author:         Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970615 created
	990902 moved from maker/Thread.c
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#define NO_INC_IO
#include "fpoll.h"
#include "ystring.h"
#include "proc.h"
#include "log.h"
#include "ysignal.h"
#include "vsignal.h"
#include "yselect.h" /* FD_SETSIZE */
void putpplog(PCStr(fmt),...);

extern const char *WithThread;
extern int (*ThreadFork)(int size,const char *name,IFUNCP,...);
extern int (*ThreadYield)();
extern int (*ThreadWait)(int tid,int timeout);
extern int (*ThreadKill)(int tid,int sig);
extern int (*ThreadDestroy)(int tid);
extern void (*ThreadExit)(void *code);
extern int (*ThreadId)();
extern int (*ThreadPriority)(int pri);
extern int (*ThreadSigmask)(PCStr(show),SigMaskInt nmask,SigMaskInt *omask);

static CriticalSec ThreadCSC;
int NewThreads;
int cnt_errorCSC;
int cnt_retryCSC;
int cnt_enterCSC;
int cnt_leaveCSC;
int cnt_errCSCpid;
const char *enterCSC_F;
int enterCSC_L;
int enterCSC_tid;

typedef struct {
	int	t_id;
	int	t_tgid;
	int	t_time; /* the time of the last status change */
	short	t_busy;
	short	t_L;
    const char *t_F;
    const char *t_stat;
    const char *t_what;
} Thread;
static Thread threads[MAX_THREADS];
static int Nthreads;
typedef struct {
	int	t_serno;
	int	t_reqno;
} ThreadSerno;
static ThreadSerno threadsSerno[elnumof(threads)];
int numthreads(){
	return Nthreads;
}
static int pNthreads;
int pnumthreads(){
	return pNthreads;
}

typedef struct {
	int	t_dowait;
	int	t_done[2];
	int	t_active;
	int	t_activemax;
	int	t_exited;
	int	t_waiting;
	int	t_spawned;
	int	t_started;
} ThreadEnv;
static ThreadEnv threadEnv = {0,{-1,-1}};
#define ThreadsWaitTO	threadEnv.t_dowait
#define ThreadsDone	threadEnv.t_done
#define ActiveThreads	threadEnv.t_active
#define ActiveThreadsMax	threadEnv.t_activemax
#define ExitedThreads	threadEnv.t_exited
#define WaitingThreads	threadEnv.t_waiting
#define SpawnedThreads	threadEnv.t_spawned
#define StartedThreads	threadEnv.t_started

int main_thread_pid; /* pid differs between threads on LinuxThreads */
int main_thread;
int THREAD_WAIT_TIMEOUT = 0;
void clearThreadEnv();

void on_fork(int pid){
	int ix;
	for( ix = 0; ix < elnumof(threads); ix++ ){
		threads[ix].t_id = 0;
		threads[ix].t_tgid = 0;
	}
	ThreadsWaitTO = 0;
	ThreadsDone[0] = ThreadsDone[1] = -1;
	main_thread_pid = pid;
	main_thread = 0;
	ActiveThreads = 0;
	ActiveThreadsMax = 0;
	ExitedThreads = 0;
	pNthreads = Nthreads;
	Nthreads = 0;
	NewThreads = 0;
	cnt_errorCSC = 0;
	cnt_retryCSC = 0;
	cnt_enterCSC = 0;
	cnt_leaveCSC = 0;
	cnt_errCSCpid = 0;
	enterCSC_F = 0;
	enterCSC_L = 0;
	bzero(ThreadCSC,sizeof(ThreadCSC));
	clearThreadEnv();
}
int actthreads(){
	return ActiveThreads;
}
int actthreadsmax(){
	return ActiveThreadsMax;
}
int endthreads(){
	return ExitedThreads;
}

int statsCSC(void *acs,int *count,int *retry,int *timeout);
int statsThreadCSC(int *count,int *retry,int *timeout){
	statsCSC(ThreadCSC,count,retry,timeout);
	return cnt_errorCSC;
}

static int getthreadixX(int tid);
int getthreadixY(int tid){
	SSigMask sMask;
	int tix;

	if( lMULTIST() == 0 ){
		return getthreadixX(tid);
	}
	if( Nthreads ){
		setSSigMask(sMask);
		setupCSC("getthreadix",ThreadCSC,sizeof(ThreadCSC));
		enterCSCX(ThreadCSC,60*1000);
		/*
		enterCSC(ThreadCSC);
		*/
	}
	tix = getthreadixX(tid);
	if( Nthreads ){
		leaveCSC(ThreadCSC);
		resetSSigMask(sMask);
	}
	return tix;
}
int getthreadix(){
	return getthreadixY(0);
}
static int thtabAdd;
static int thtabClear;
static int getthreadixX(int atid){
	int tid,ix;
	int nix = -1;
	int mytid = getthreadid();

	if( atid )
		tid = atid;
	else	tid = mytid;
	/*
	else
	tid = getthreadid();
	*/
	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( threads[ix].t_id == 0 ){
			if( nix < 0 ){
				nix = ix;
			}
		}
		if( tideq(threads[ix].t_id,tid) ){
			return ix;
		}
	}
	if( tid != mytid ){
		porting_dbg("ERROR: getthreadix(%X) non-existing %X %X",
			atid,tid,mytid);
		/* it might exit already (or not yet active) */
		return 0;
	}
	if( 0 <= nix ){
		ix = nix;
		thtabAdd++;
		threadsSerno[ix].t_serno = thtabAdd;
		threadsSerno[ix].t_reqno = 0;
		threads[ix].t_id = tid;
		threads[ix].t_tgid = 0;
		threads[ix].t_F = "new";
		threads[ix].t_L = 0;
		return ix;
	}
	porting_dbg("ERROR: getthreadix() no more threads (%d)",ix);
	return 0;
}
static int getix(int tid){
	int ix;
	if( tid == 0 ){
		tid = getthreadid();
	}
	for( ix = 0; ix < elnumof(threadsSerno); ix++ ){
		if( threads[ix].t_id == tid ){
			return ix;
		}
	}
	return -1;
}
int getthreadserno(int tid,int *reqno){
	int ix;
	if( 0 <= (ix = getix(tid)) ){
		*reqno = threadsSerno[ix].t_reqno;
		return threadsSerno[ix].t_serno;
	}
	return 0;
}
int incthreadreqno(int tid){
	int ix;
	if( 0 <= (ix = getix(tid)) ){
		return threadsSerno[ix].t_reqno += 1;
	}
	return 0;
}
int clearthreadsixX(int tid);
int clearthreadsix(){
	int tid,ix;
	tid = getthreadid();
	return clearthreadsixX(tid);
}
int clearthreadsixX(int tid){
	int nc = 0;
	int ix;

	if( Nthreads ){
		setupCSC("clearthreadsixX",ThreadCSC,sizeof(ThreadCSC));
		enterCSC(ThreadCSC);
	}
	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( threads[ix].t_id != 0 ){
			if( tideq(threads[ix].t_id,tid) ){
				thtabClear++;
				threads[ix].t_id = 0;
				threads[ix].t_tgid = 0;
				nc++;
			}
		}
	}
	if( Nthreads ){
		leaveCSC(ThreadCSC);
	}
	return nc;
}
int threadIsAlive(int tid){
	int ix;
	int alive = 0;
	if( tid == 0 )
		return 0;

	if( Nthreads ){
		setupCSC("threadIsAlive",ThreadCSC,sizeof(ThreadCSC));
		enterCSC(ThreadCSC);
	}
	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( tideq(threads[ix].t_id,tid) ){
			/*
			return ix+1;
			*/
			alive = 1;
			break;
		}
	}
	if( Nthreads ){
		leaveCSC(ThreadCSC);
	}
	return alive;
	/*
	return 0;
	*/
}
static int Fputlog(FILE *fp,PCStr(fmt),...){
	VARGS(16,fmt);
	if( fp ){
		fprintf(fp,fmt,VA16);
	}else{
		syslog_ERROR(fmt,VA16);
	}
	return 0;
}
int dumpthreads(PCStr(wh),FILE *tc){
	int nt = 0;
	int ix;
	int me;
	int tid;
	Thread *tp;

	me = getthreadid();
	for( ix = 0; ix < elnumof(threads); ix++ ){
		tp = &threads[ix];
		if( tid = tp->t_id ){
			Fputlog(tc,"--TH[%2d] %s %4X %4Xg (%s) %s:%d %s %s\n",
				ix,wh,
				PRTID(tp->t_id),PRTID(tp->t_tgid),
				tp->t_what?tp->t_what:"",
				tp->t_F?tp->t_F:"",tp->t_L,
				tp->t_stat?tp->t_stat:"",
				tid==me?"*":""
			);
			nt++;
		}
	}
	return nt;
}
int dumpThreads(PCStr(wh)){
	int nt = 0;
	int ix;
	int me;
	int tid;
	Thread *tp;

	me = getthreadid();
	for( ix = 0; ix < elnumof(threads); ix++ ){
		tp = &threads[ix];
		if( tid = tp->t_id ){
			putfLog("--TH[%d] %s %04X %04Xg (%s) %s:%d %s %s",
				ix,wh,
				PRTID(tp->t_id),PRTID(tp->t_tgid),
				tp->t_what?tp->t_what:"",
				tp->t_F?tp->t_F:"",tp->t_L,
				tp->t_stat?tp->t_stat:"",
				tid==me?"*":""
			);
			nt++;
		}
	}
	return nt;
}

int setthread_FL(int tid,const char *F,int L,const char *st){
	int ix;
	Thread *tp;
	if( 0 <= (ix = getthreadixY(tid)) ){
		tp = &threads[ix];
		tp->t_F = F;
		tp->t_L = L;
		tp->t_stat = st;
	}
	return 0;
}
void setthread_busy(int tid,int busy){
	int ix;
	Thread *tp;
	if( 0 <= (ix = getthreadixY(tid)) ){
		tp = &threads[ix];
		tp->t_time = time(0);
		tp->t_busy = busy;
	}
}
int busythreads(){
	int ix;
	int nbusy = 0;
	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( threads[ix].t_id ){
			if( threads[ix].t_time != 0 )
			if( threads[ix].t_busy ){
				nbusy++;
			}
		}
	}
	return nbusy;
}
int idlethreads(){
	int ix;
	int nidle = 0;
	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( threads[ix].t_id ){
			if( threads[ix].t_time != 0 )
			if( threads[ix].t_busy == 0 ){
				nidle++;
			}
		}
	}
	return nidle;
}

int getthreadid(){
	if( ThreadId )
		return (*ThreadId)();
	else	return -1;
}
int setthreadgid(int tid,int tgid){
	int ix;
	if( tgid == 0 ){
		return -1;
	}
	ix = getthreadixY(tid);
	if( 0 <= ix ){
		threads[ix].t_tgid = tgid;
	}
	return 0;
}
int getthreadgid(int tid){
	int ix;
	int tgid = -1;
	ix = getthreadixY(tid);
	if( 0 <= ix ){
		tgid = threads[ix].t_tgid;
	}
	return tgid;
}
int getthreadgix(int tid){
	int gid;
	int gix;

	if( Nthreads == 0 ){
		return 0;
	}
	if( gid = getthreadgid(tid) ){
		gix = getthreadixY(gid);
		if( 0 <= gix ){
			return gix;
		}
	}
	return 0;
}
int mainthreadid(){
	return main_thread;
}
int ismainthread(){
	int tid;
	tid = getthreadid();
	if( main_thread == 0 || main_thread == tid ){
		return tid;
	}
	return 0;
}
const char *INHERENT_thread()
{
	if( lNOTHREAD() ){
		return 0;
	}
	return WithThread;
}
int getmtpid(){
	if( main_thread_pid )
		return main_thread_pid;
	else	return getpid();
}
static CriticalSec thforkCSC;
int newthreads(){
	return NewThreads;
}
static int actTid();
int thread_fork(int size,int gtid,PCStr(what),IFUNCP func,...)
{
	int tid;
	int ix;
	int smask,nmask;
	VARGS(8,func);

	if( main_thread == 0 ){
		main_thread = getthreadid();
		main_thread_pid = getpid();
		if( THREAD_WAIT_TIMEOUT ){
			IGNRETZ pipe(ThreadsDone);
			ThreadsWaitTO = 1;
		}
	}
	if( ThreadFork )
	{
		/*
		MyPID = 0;
		*/
		NewThreads++;
		setupCSC("thread_fork",thforkCSC,sizeof(thforkCSC));
		enterCSC(thforkCSC);
		Nthreads++;
		nmask = sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGPIPE);
		smask = sigblock(nmask);
		tid = (*ThreadFork)(size,what,func,VA8);
		if( tid != 0 ){
			ActiveThreads++;
			if( ActiveThreadsMax < ActiveThreads ){
				ActiveThreadsMax = ActiveThreads;
			}
			SpawnedThreads++;
			if( lTHFORKSYNC() ){
				/* should wait the thread to be Started to make
				 * the parallel behavior consistent, but it might
				 * affect signal handling ?
				 */
				void msleep(int ms);
				msleep(0);
			}
			/*
			9.8.5 the thread might exit already, don't add ghost
			if( 0 <= (ix = getthreadixY(tid)) ){
				threads[ix].t_what = what;
			}
			*/
			putpplog("actthreads()++=%d [%X]\n",ActiveThreads,tid);
		}
		sigsetmask(smask);
		leaveCSC(thforkCSC);
		NewThreads--;
		if( lTHREADLOG() ){
			const void *toThd(int tid,int del,int *ser);
			FileSize thd;
			thd = p2llu(toThd(tid,0,0));
			syslog_ERROR("thread_fork(%s %X %X)A%d = %X/%llX\n",
				what,size,gtid,actTid(),tid,thd);
		}
		return tid;
		/*
		return (*ThreadFork)(size,func,VA8);
		*/
	}

	porting_dbg("NO thread_fork() available.");
	exit(-1);
	return -1;
}
unsigned int trand1(unsigned int max);
int allocaCall(PCStr(what),int size,iFUNCP func,...);
typedef void *thchFunc(void *thcharg);
void *thread_child(thchFunc func,void *arg){
	int size;
	size = trand1(256) * 64;
	allocaCall("thread_child",size,(iFUNCP)func,arg);
	/* will not return */
	return 0;
}
int clearthreadsig(int tid,int silent);
int thread_doneX(int tid,void *xcode);
int thread_done(void *xcode){
	int tid;
	tid = getthreadid();
	return thread_doneX(tid,xcode);
}
int thread_doneX(int tid,void *xcode){

	ExitedThreads++;
	if( 0 < ThreadsWaitTO && 0 <= ThreadsDone[1] ){
		IGNRETP write(ThreadsDone[1],&tid,sizeof(tid));
	}
	clearthreadsig(tid,0);
	clearthreadsixX(tid);
	return 0;
}
int thread_sigmask(PCStr(show),SigMaskInt nmask,SigMaskInt *omask){
	if( ThreadSigmask ){
		return (*ThreadSigmask)(show,nmask,omask);
	}
	return -1;
}

#if defined(_MSC_VER) \
 || defined(__APPLE__) \
 || defined(__FreeBSD__)
#define SuppThreadSignal() 1
#else
#define SuppThreadSignal() 0
#endif

int thread_start(const char *name,void *ta){
	int ix;
	SigMaskInt umask,omask,nmask;

	ix = getthreadix();
	StartedThreads++;
	if( 0 <= ix ){
		threads[ix].t_what = name;
	}

	if( !lNOSIGPIPE() )
	if( !SuppThreadSignal() ){
		/*
		umask = sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGPIPE);
		only the main-thread should receive SIGINT/SIGTERM
		*/
		umask = sigmask(SIGPIPE);
		thread_sigmask("UNBLOCK",umask,&omask);
		thread_sigmask("UNBLOCK",0,&nmask);
		syslog_DEBUG("thread_started sigmask=%X <- %X\n",nmask,omask);
	}
	return 0;
}
static int wait_thread(int tid,int timeout){
	double St;
	int xtid,rcc,xi,wcc;
	int xtids[128];
	int xtidn = 0;
	int rcode;

	if( ThreadsWaitTO == 0 || ThreadsDone[0] < 0 ){
		return 0;
	}

	St = Time();
	rcode = -1;
	WaitingThreads++;
	for(;;){
		if( PollIn(ThreadsDone[0],timeout) == 0 ){
			daemonlog("F","thread_wait(%X,%d) timeout\n",
				tid,timeout);
			break;
		}
		xtid = -1;
		rcc = read(ThreadsDone[0],&xtid,sizeof(xtid));
		if( lTHREAD() ){
			syslog_ERROR("thread_wait(%X) = %d %X %d/%d\n",
				tid,rcc,xtid,(int)(1000*(Time()-St)),timeout);
		}
		if( xtid == tid ){
			rcode = 0;
			break;
		}
		xtids[xtidn++] = xtid;
	}
	if( 0 < xtidn ){
		for( xi = 0; xi < xtidn; xi++ ){
			xtid = xtids[xi];
			wcc = write(ThreadsDone[1],&xtid,sizeof(tid));
		}
	}
	WaitingThreads--;
	return rcode;
}
static int thread_wait_timeout(int tid,int timeout){
	double St = Time();
	int slp,rem,to1;

	if( ENBUG_NOTHTMOUT ){
		syslog_ERROR("--- thread_wait(%X,%d) ALIVE=%d\n",
			tid,timeout,threadIsAlive(tid));
		return 0;
	}
	if( !threadIsAlive(tid) ){
		syslog_DEBUG("--- thread_wait(%X,%d) NOT ALIVE\n",
			tid,timeout);
		return 1;
	}
	usleep(1000);
	if( !threadIsAlive(tid) ){
		syslog_DEBUG("--- thread_wait(%X,%d) NOT ALIVE 1.0ms\n",
			tid,timeout);
		return 1;
	}

	slp = 0;
	for( rem = timeout; 0 < rem; rem -= to1 ){
		if( slp < 500 ){
			slp += 10;
		}
		if( rem < slp )
			to1 = rem;
		else	to1 = slp;
		usleep(to1*1000);
		if( !threadIsAlive(tid) ){
			break;
		}
	}
	if( threadIsAlive(tid) ){
		syslog_ERROR("--- thread_wait(%X,%d) TIMEOUT\n",
			tid,timeout);
		return -1;
	}else{
		syslog_ERROR("--- thread_wait(%X,%d) EXIT %.3f\n",
			tid,timeout,Time()-St);
		return 1;
	}
}
static int thwaitTimeout;
static int thwaitWaiterr;
static int thwaitCodeerr;
static int thwait;
int thread_wait_errors(PVStr(st)){
	Xsprintf(AVStr(st),"thread_wait(%d)",thwait);
	Xsprintf(TVStr(st),"start(%d)",StartedThreads);
	Xsprintf(TVStr(st),"add(%d)",thtabAdd);
	Xsprintf(TVStr(st),"clear(%d)",thtabClear);
	Xsprintf(TVStr(st),"tid(%d)",actTid());
	if( thwaitTimeout ) Xsprintf(TVStr(st),"Timeout(%d)",thwaitTimeout);
	if( thwaitWaiterr ) Xsprintf(TVStr(st),"Waiterr(%d)",thwaitWaiterr);
	if( thwaitCodeerr ) Xsprintf(TVStr(st),"Codeerr(%d)",thwaitCodeerr);
	return thwaitTimeout+thwaitWaiterr+thwaitCodeerr;
}
int thread_wait(int tid,int timeout){
	int rcode;
	int nmask,smask;
	if( ThreadWait ){
		thwait++;
		if( lTHREADLOG() ){
			syslog_ERROR("thread_wait(%X %d)\n",tid,timeout);
		}
		if( !isWindows() && 0 < timeout ){
			if( thread_wait_timeout(tid,timeout) < 0 ){
				thwaitTimeout++;
				return -1;
			}
		}
		if( wait_thread(tid,timeout) < 0 )
		{
			thwaitWaiterr++;
			return -1;
		}
		nmask = sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGPIPE);
		nmask |= sigmask(SIGHUP);
		smask = sigblock(nmask);
		rcode = (*ThreadWait)(tid,timeout);
		if( rcode == 0 ){
			ActiveThreads--;
			putpplog("actthreads()--=%d [%X]\n",ActiveThreads,tid);
		}
		else{
			thwaitCodeerr++;
		}
		sigsetmask(smask);
		return rcode;
		/*
		return (*ThreadWait)(tid,timeout);
		*/
	}
	return -1;
}
int DestroyedThreads;
int thread_destroy(int tid){
	if( ThreadDestroy ){
		if( threadIsAlive(tid) ){
			ActiveThreads--;
			DestroyedThreads++;
			thread_doneX(tid,0);
			return (*ThreadDestroy)(tid);
		}
	}
	return -1;
}
int thread_kill(int tid,int sig){
	if( ThreadKill ){
		if( tid == MAINTHREADID ){
			tid = main_thread;
			syslog_ERROR("Killing main-thread %X <- %X\n",
				tid,getthreadid());
		}
		return (*ThreadKill)(tid,sig);
	}
	return -1;
}
void thread_exit(void *code){
	if( ThreadExit ){
		(*ThreadExit)(code);
	}
}
void thread_yield(){
	if( 0 < actthreads() && ThreadYield ){
		(*ThreadYield)();
	}
}
int waitthreads(){
	int ix;
	int tid;
	int fin = 0;
	int mytid = getthreadid();

	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( tid = threads[ix].t_id ){
			if( tid != mytid ){
				if( thread_wait(tid,1) == 0 ){
					fin++;
				}
			}
		}
	}
	return fin;
}
int destroythreads(){
	int ix;
	int tid;
	int fin = 0;
	int mytid = getthreadid();

	for( ix = 0; ix < elnumof(threads); ix++ ){
		if( tid = threads[ix].t_id ){
			if( tid != mytid ){
				if( thread_destroy(tid) == 0 ){
					fin++;
				}
			}
		}
	}
	return fin;
}

/*
int thread_priority(int pri){
	if( ThreadPriority ){
		return (*ThreadPriority)(pri);
	}
	return -1;
}
*/

/*
 * Threads are expected to switch to another when a thread become idle
 * waiting for input.  But threads library on some system don't support
 * it, thus switching must be done explicitly, typically on I/O polling.
 * ThreadYield must be defined in such systems.
 */
static char *fd_polling;
int thread_PollIn(int fd,int timeout)
{	int ti,nth,fdv[8],rfv[8],fdx;
	int timeout1,remain,nready,efd;

	if( fd_polling == 0 )
		fd_polling = (char*)StructAlloc(FD_SETSIZE);

	if( ThreadYield == NULL )
		return PollIn(fd,timeout);

	if( FD_SETSIZE <= fd ){
		porting_dbg("#### THREAD-POLL: too large fd (%d)",fd);
		exit(0);
	}

	if( fd_polling[fd] != 0 ){
	/*porting_dbg("#### THREAD-POLL: another thread waiting on %d",fd);*/
		exit(0);
	}

if( 64 <= fd )
fprintf(stderr,"####[%d] thread_PollIn(%d)\n",getpid(),fd);

	fd_polling[fd] = 1;

START:
	nth = 0;
	fdx = 0;
	for( ti = 0; ti < FD_SETSIZE; ti++ )
	{
		if( 0 < fd_polling[ti] ){
			if( ti == fd )
				fdx = nth;
			fdv[nth++] = ti;
		}
	}
	if( nth == 0 )
		goto EXIT;

	if( nth == 1 )
		timeout1 = 100; /* waiting another thread be started */
	else	timeout1 = 5000; /* and more threads... */

	for( remain = timeout; timeout == 0 || 0 < remain; remain -= timeout1 ){
		nready = PollIns(timeout1,nth,fdv,rfv);
		if( 0 <= (efd = connHUP()) ){
			if( efd == fd ){
				nready = 1;
				goto EXIT;
			}else{
				fd_polling[efd] = 0;
				goto START;
			}
		}
		if( nready < 0 )
			break;
		if( nready == 0 ){
			/*porting_dbg("#### yield 1");*/
			(*ThreadYield)();
			continue;
		}
		if( 0 < rfv[fdx] ){
			nready = 1;
			goto EXIT;
		}
		for( ti = 0; ti < nth; ti++ )
		if( 0 < rfv[ti] ){
			/*porting_dbg("#### yield 2: %d",fdv[ti]);*/
			if( (*ThreadYield)() == 0 )
				break;
		}
	}
EXIT:
	fd_polling[fd] = 0;
	return nready;
}

#undef sigmask
#undef sigsetmask
#undef sigblock
#ifdef _MSC_VER
int sigsetmask(int);
int sigblock(int);
#endif
int sigmask(int sig);
int proc_sigblock(int mask){
	return sigblock(mask);
}
int proc_sigsetmask(int mask){
	return sigsetmask(mask);
}

SigMaskInt SigMask_FL(FL_PAR,SigMaskInt sig){
	return sigmask(sig);
}
SigMaskInt SigSetMask_FL(FL_PAR,SigMaskInt mask){
	SigMaskInt omask,nmask;
	if( Nthreads && !ismainthread() ){
		thread_sigmask("SET",mask,&omask);
		thread_sigmask("GET",0,&nmask);
/*
		if( lTHREADSIG() )
		fprintf(stderr,"-- %X thread_sigsetmask(%X => %X)=%X <= %s:%d\n",
			TID,omask,mask,nmask,FL_BAR);
*/
		return omask;
	}
	nmask = sigsetmask(mask);
	if( lTHREADSIG() )
	fprintf(stderr,"-- %X sigsetmask(%X)=%X <= %s:%d\n",TID,mask,nmask,FL_BAR);
	return nmask;
}
SigMaskInt SigBlock_FL(FL_PAR,SigMaskInt mask){
	SigMaskInt omask,nmask;
	if( Nthreads && !ismainthread() ){
		thread_sigmask("BLOCK",mask,&omask);
		thread_sigmask("GET",0,&nmask);
/*
		if( lTHREADSIG() )
		fprintf(stderr,"-- %X thread_sigblock(%X +> %X)=%X <= %s:%d\n",
			TID,omask,mask,nmask,FL_BAR);
*/
		return omask;
	}
	nmask = sigblock(mask);
	if( lTHREADSIG() )
	fprintf(stderr,"-- %X sigblock(%X)=%X <= %s:%d\n",TID,mask,nmask,FL_BAR);
	return nmask;
}
#undef signal
#undef Vsignal
typedef struct {
	int	ts_tid;
	char	ts_stat;
	vfuncp	ts_func;
    const char *ts_F;
	int	ts_L;
} ThreadSig;
static ThreadSig sigs[1+MAX_THREADS][32];
static CriticalSec sigCSC;
static int nsig;
#define TS_FL ts->ts_F,ts->ts_L

void sigIGNORE(int sig){
}
int clearthreadsig(int tid,int silent){
	ThreadSig *ts;
	int tix = getthreadixY(tid);
	int si;
	int nsig = 0;

	if( isWindowsCE() ){
		return 0;
	}
	if( 0 <= tix && tix < MAX_THREADS ){
		for( si = 0; si < 32; si++ ){
			ts = &sigs[1+tix][si];
			if( ts->ts_stat ){
				/*if( ts->ts_func )*/
				if( !silent )
				porting_dbg("%X [%d][%d] clear signal(%X)",
					tid,tix,si,xp2i(ts->ts_func));
				ts->ts_stat = 0;
				ts->ts_func = 0;
				nsig++;
			}
		}
	}
	return nsig;
}
int VStrSIG();
void sigANY(int sig){
	ThreadSig *ts;
	vfuncp func;
	int tid = TID;
	int tix;
	int ti;

	signal(sig,sigANY); /* for non-BSD */
	tix = 1+getthreadix();
	nsig++;

/*
putfLog("####SIG(%d) tix[%d] *%d",sig,tix,nsig);
VStrSIG();
*/

	if( lTHREADSIG() )
	fprintf(stderr,"-- %X[%d] %d#gotsig %d\n",tid,tix,nsig,sig);

	if( sig < 0 || 32 <= sig ){
		fprintf(stderr,"-- %X[%d] %d#gotsig %d BAD\n",tid,tix,nsig,sig);
		return;
	}
	ts = &sigs[tix][sig];
	if( ts->ts_stat == 0 || ts->ts_func == sigIGNORE ){
		for( ti = 0; ti < MAX_THREADS; ti++ ){
			ts = &sigs[1+ti][sig];
			if( ts->ts_stat && ts->ts_func != sigIGNORE ){
				if( ti != tix ){
			fprintf(stderr,"-- %X[%d] gotsig %d FORW >>> %X[%d] %s:%d\n",
			tid,tix,sig,ts->ts_tid,1+ti,
			ts->ts_F,ts->ts_L);
					if( isWindows() ){
					  /* thread_kill not implemented yet */
					}else{
					thread_kill(ts->ts_tid,sig);
					return;
					}
				}
				break;
			}
			ts = 0;
		}
		if( ts == 0 ){
			ts = &sigs[0][sig];
		}
	}
	if( ts->ts_stat == 0 ){
		fprintf(stderr,"-- %X[%d] %d#gotsig %d UNDEF ????\n",
			tid,tix,nsig,sig);
		return;
	}
	func = ts->ts_func;
	if( func == SIG_DFL ){
		fprintf(stderr,"-- %X[%d] %d#gotsig %d DEFAULT <= %s:%d\n",
			tid,tix,nsig,sig,TS_FL);
	}else
	if( func == SIG_IGN ){
		fprintf(stderr,"-- %X[%d] %d#gotsig %d IGNORED <= %s:%d\n",
			tid,tix,nsig,sig,TS_FL);
	}else{
		if( lTHREADSIG() )
		fprintf(stderr,"-- %X[%d] %d#gotsig %d HANDLED <= %s:%d %X\n",
			tid,tix,nsig,sig,TS_FL,xp2i(func));
		(*func)(sig);
		if( lTHREADSIG() )
		fprintf(stderr,"-- %X[%d] %d#gotsig %d HANDLED <= %s:%d %X\n",
			tid,tix,nsig,sig,TS_FL,xp2i(func));
	}
	if( sig == SIGSEGV ){
		void msleep(int);
		msleep(250);
	}
}
vfuncp Vsignal_FL(FL_PAR,int sig,vfuncp func){
	ThreadSig *ts;
	vfuncp ofunc;
	int tix;

	if( isWindowsCE() ){
		return 0;
	}
	if( sig < 0 || 32 <= sig ){
		return signal(sig,func);
	}
	if( lMULTIST() ){
		tix = 1+getthreadix();
		setupCSC("Vsignal",sigCSC,sizeof(sigCSC));
		enterCSC(sigCSC);
		ts = &sigs[0][sig];
		if( ts->ts_stat == 0 ){
			ts->ts_stat = 1;
			ts->ts_tid = getthreadid();
			ts->ts_func = signal(sig,sigANY);
			ts->ts_F = FL_F;
			ts->ts_L = FL_L;
		}
		ts = &sigs[tix][sig];
		ofunc = ts->ts_func;
		ts->ts_stat = 1;
		ts->ts_tid = getthreadid();
		ts->ts_func = func;
		ts->ts_F = FL_F;
		ts->ts_L = FL_L;
		leaveCSC(sigCSC);
		if( lTHREADSIG() ){
			fprintf(stderr,"-- %X %d/%d Vsignal(%d,%X) <= %s:%d\n",
				TID,actthreads(),numthreads(),
				sig,xp2i(func),FL_BAR);
		}
		return ofunc;
	}
	ofunc = signal(sig,func);
	return ofunc;
}
int SigSetJmp(FL_PAR,sigjmp_buf env,int savemask){
	/*
	fprintf(stderr,"-- %X sigsetjmp(%X,%d) <= %s:%d\n",TID,
		env,savemask,FL_BAR);
	*/
	return 0;
}
int inSignalHandler;
void SigLongJmp(FL_PAR,sigjmp_buf env,int val){
	/*
	fprintf(stderr,"-- %X siglongjmp(%X,%d) <= %s:%d %d/%d\n",TID,
		env,val,FL_BAR,actthreads(),numthreads());
	*/
	if( inSignalHandler ){
		putsLog("##SIGlongjmp in signal handling");
	}
	if( ismainthread() ){
	}else{
		putsLog("##SIGlongjmp in non-main-thread");
		thread_exit(0);
	}
	return;
}
void LongJmp(FL_PAR,jmp_buf env,int val){
	if( inSignalHandler ){
		putsLog("##non-SIG longjmp in signal handling");
	}
	if( ismainthread() ){
	}else{
		putsLog("##non-SIG longjmp in non-main-thread");
		thread_exit(0);
	}
}

int THEXIT;

/*
 * 9.9.3 mapping system's thread-id larger than int to int
 */
typedef struct {
  const void   *t_tidx;
	int	t_Stid;
} TidMap;
static int Stid;
static TidMap tids[MAX_THREADS];
extern int SIZEOF_tid_t;
static CriticalSec TidCSC;

static int ti2tid(int ti);
int dumpTids(){
	int ti;
	TidMap *Tm;
	for( ti = 0; ti < elnumof(tids); ti++ ){
		Tm = &tids[ti];
		if( Tm->t_tidx ){
			porting_dbg("##tid[%2d] %08llX %04X %d",ti,
				p2llu(Tm->t_tidx),PRTID(ti2tid(ti)),
				Tm->t_Stid);
		}
	}
	return 0;
}
static int actTid(){
	int ti;
	TidMap *Tm;
	const void *tidx1;
	int act = 0;

	for( ti = 0; ti < elnumof(tids); ti++ ){
		tidx1 = tids[ti].t_tidx;
		if( tidx1 == 0 || tidx1 == (void*)-1 ){
		}else{
			act++;
		}
	}
	return act;
}
/*
typedef union{
	int	t_idv;
	struct {
	int	t_ix:8,
		t_id:11,
		t_mg:1;
	} t_idx;
} Tid;
*/
static int ti2tid(int ti){
	int tid;
	tid = 0x80000 | (0x7FF00 & (tids[ti].t_Stid<<8)) | ti;
	return tid;
}
static int tid2ti(int tid){
	int ti;
	if( 0x80000 & tid ){
		if( (0xFFF00000 & tid) == 0 ){
			ti = tid & 0xFF;
			return ti;
		} 
	}
	fprintf(stderr,"####tid2ti(%X)=%d####\n",tid,-1);
	return -1;
}
int toTid(const void *tidx,int add){
	int ti;
	int tid;
	const void *tidx1;
	int eti = -1;
	int ntry = 0;

	if( enbugTID64() ){
		return p2llu(tidx);
	}
	if( !lTHREADID() ){
		if( SIZEOF_tid_t <= sizeof(int) ){
			return p2llu(tidx);
		}
		if( p2llu(tidx) & ~0xFFFFFFFF ){
			return p2llu(tidx);
		}
	}

RETRY:
	for( ti = 0; ti < elnumof(tids); ti++ ){
		tidx1 = tids[ti].t_tidx;
		if( tidx1 == tidx ){
			/*
			tid = 0x8000 | (tids[ti].t_Stid<<8) | ti;
			*/
			tid = ti2tid(ti);
			return tid;
		}
		if( add )
		if( eti < 0 )
		if( tidx1 == 0 || tidx1 == (void*)-1 ){
			eti = ti;
		}
	}
	if( add && 0 <= eti ){
		ti = eti;
		tidx1 = tids[ti].t_tidx;
		if( tidx1 == tidx ){
			/* 9.9.4 maybe added by the spawned thread itself */
			/*
			tid = 0x8000 | (tids[ti].t_Stid<<8) | ti;
			*/
			tid = ti2tid(ti);
			return tid;
		}else
		if( tidx1 == 0 || tidx1 == (void*)-1 ){
			tids[ti].t_tidx = tidx;
			tids[ti].t_Stid = ++Stid;
			/*
			tid = 0x8000 | (tids[ti].t_Stid<<8) | ti;
			*/
			tid = ti2tid(ti);
			if( lTHREAD() || lTHREADID() ){
				porting_dbg("##tid add[%d] %d %llX/%X",
					ti,tids[ti].t_Stid,
					p2llu(tidx),tid);
				if( lTHREADID() ){
					dumpTids();
				}
			}
			return tid;
		}
		else{
			if( ++ntry < 10 ){
				eti = -1;
				goto RETRY;
			}
		}
	}
	return p2llu(tidx);
}
const void *toThd(int tid,int del,int *ser){
	const void *tidx;
	int ti;

	if( enbugTID64() ){
		return i2p(tid);
	}
	if( !lTHREADID() ){
		if( SIZEOF_tid_t <= sizeof(int) ){
			return i2p(tid);
		}
	}
	/*
	if( (tid & 0x8000) == 0 ){
		return (void*)tid;
	}
	ti = tid & ~0xFF00;
	*/
	ti = tid2ti(tid);
	if( 0 <= tid && ti < elnumof(tids) ){
		tidx = tids[ti].t_tidx;
		if( del ){
			if( tids[ti].t_Stid == *ser ){
				tids[ti].t_tidx = (void*)-1;
			}else{
				syslog_ERROR("##toThd unmatch ser: %d %d\n",
					*ser,tids[ti].t_Stid);
			}
			if( lTHREAD() || lTHREADID() ){
				porting_dbg("##tid del[%d] %d %llX/%X",
					ti,tids[ti].t_Stid,
					p2llu(tidx),tid);
				if( lTHREADID() ){
					dumpTids();
				}
			}
		}else{
			if( ser ){
				*ser = tids[ti].t_Stid;
			}
		}
		return tidx;
	}
	return i2p(tid);
}
