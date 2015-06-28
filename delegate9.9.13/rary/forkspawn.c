/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	forkspawn.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	990205	extracted from misc.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ystring.h"
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
#include "vsignal.h"
#include "ysignal.h"
#include "proc.h"
#include "log.h"
void on_fork(int pid);
int InFinish;
int DontFork;

#ifdef __osf__
#ifdef __cplusplus
extern "C" {
#endif
extern pid_t wait3(int *status, int options, struct rusage *rusage);
#ifdef __cplusplus
}
#endif
#endif
/*
pid_t wait3(int *status, int options, struct rusage *rusage);
int killpg(pid_t pgrp, int sig);
*/

void BeforeExec();
/*
void endhostent(void);
*/

int doTracePid;
int (*doTraceLog)(const void*,...);
#define TraceLog	doTraceLog==0? 0 : (*doTraceLog)

int MyPID;
int Getpid(){
	if( MyPID == 0 )
		MyPID = getpid();
	return MyPID;
}
int my_pid;
int uGetpid(){
	if( my_pid == 0 ){
		my_pid = getpid();
	}
	return my_pid;
}

static char cof_fds[FD_SETSIZE];
int setCloseOnFork(PCStr(wh),int fd){
	if( LOG_VERBOSE || lTHREAD() )
	syslog_ERROR("{t} setCloseOnFork(%s,%d)\n",wh,fd);
	if( fd < 0 || elnumof(cof_fds) <= fd ){
		return -1;
	}
	cof_fds[fd] = 1;
	setInheritHandle(fd,0);
	return 0;
}
int clearCloseOnFork(PCStr(wh),int fd){
	if( LOG_VERBOSE || lTHREAD() )
	syslog_ERROR("{t} clearCloseOnFork(%s,%d)\n",wh,fd);
	if( fd < 0 || elnumof(cof_fds) <= fd ){
		return -1;
	}
	cof_fds[fd] = 0;
	/* don't set it before it is closed ?
	setInheritHandle(fd,1);
	*/
	return 0;
}
int openNull(int rw);
void execCloseOnFork(PCStr(wh)){
	int fd,rcode;
	int nulfd;

	for( fd = 0; fd < elnumof(cof_fds); fd++ ){
		if( cof_fds[fd] != 0 ){
			if( 0 <= (nulfd = openNull(0)) ){
				rcode = close(fd);
				dup2(nulfd,fd);
				close(nulfd);
			}else
			rcode = close(fd);

	if( LOG_VERBOSE || lTHREAD() )
	fprintf(stderr,"[%d.%X]execCloseOnFork(%s,%d)=%d\n",
		getpid(),getthreadid(),wh,fd,rcode);
	syslog_ERROR("{t} execCloseOnFork(%s,%d)=%d\n",wh,fd,rcode);
			cof_fds[fd] = 0;
		}
	}
}
int Fork(PCStr(what))
{
	return ForkX(what,0);
}

int proc_sigblock(int mask);
int proc_sigsetmask(int mask);
extern int selfLocaltime; /* multi-threads-signal-safe localtime() */

/*
 * 9.9.4 MTSS fork() might call abort() or release signals
 */
static int forker_pid;
const char *suppressAbort;
static void sigTERMx(int sig){
	putsLog("##SIGTERM-C in fork()");
	_exit(0);
}
static void sigPIPEi(int sig){
	if( getpid() == forker_pid ){
		putsLog("##SIGPIPE-P in fork()");
	}else{
		putsLog("##SIGPIPE-C in fork()");
	}
}

/*
static int forkX(){
*/
static int forkX(PCStr(what)){
	int nmask,smask;
	int pmask,tmask;
	int pid;
	vfuncp opsig = 0;
	vfuncp otsig = 0;

	forker_pid = getpid();
	nmask = sigmask(SIGPIPE)|sigmask(SIGTERM)|sigmask(SIGINT);
	nmask |= sigmask(SIGHUP);
	pmask = proc_sigblock(nmask); /* sigblock can be for a thread only */
	tmask = sigblock(nmask);
	/*
	smask = sigblock(nmask);
	*/
	opsig = signal(SIGPIPE,sigPIPEi);
	pid = fork();
	signal(SIGPIPE,opsig);
	/*
	sigsetmask(smask);
	*/

	if( pid ){
		sigsetmask(tmask);
		proc_sigsetmask(pmask);
	}else{
		/*
		 * 9.9.4 MTSS clear inherited env. first not to let signals
		 * be processed under the thread env. of the parent that is
		 * not to be inherited.
		*/
		MyPID = my_pid = getpid();
		on_fork(MyPID);
		execCloseOnFork(what);
		/*
		 * try to capture pending SIGTERM and exit
		 */
		otsig = signal(SIGTERM,sigTERMx);
		sigsetmask(tmask);
		proc_sigsetmask(pmask);
		usleep(1);
		signal(SIGTERM,otsig);
	}
	return pid;
}
/*
#define fork forkX
*/
#define fork() forkX(what)
int ForkY(PCStr(what),int (*xproc)(const char *what,int xpid));
int ForkX(PCStr(what),int (*xproc)(const char *what,int xpid))
{
	int pid;
	int opid;
	int mypid;

	if( !lMTSS_NOSSIG() ){
		suppressAbort = "##SIG Abort in fork()";
		selfLocaltime++;
	}
	opid = my_pid;
	mypid = getpid();
	pid = ForkY(what,xproc);
	if( getpid() == mypid ){
		/* 9.9.4 keep the uGetpid() unique on LinuxThreads */
		my_pid = opid;
	}
	if( !lMTSS_NOSSIG() ){
		selfLocaltime--;
		suppressAbort = 0;
	}
	return pid;
}
/*
#define fork forkX
*/
int ForkY(PCStr(what),int (*xproc)(const char *what,int xpid))
{	register int pid;

	endhostent();
	MyPID = 0;
	pid = fork();

	if( xproc )
	if( pid == -1 && errno == EAGAIN ){
		int fi,xi,xn = 0,xid = 0;
		for( fi = 0; fi < 30 && pid < 0 && errno == EAGAIN; fi++ ){
			usleep((100+fi*10)*1000);
			if( 0 < (xi = NoHangWait()) ){
				xid = xi;
				xn++;
				if( (*xproc)(what,xi) != 0 )
					break;
			}
			pid = fork();
		}
		if( pid != 0 ){
			fprintf(stderr,"----[%d] Fork(%s) AGAIN(%d/%d/%d)=%d\n",
				getpid(),what,fi,xn,xid,pid);
		}
	}
	if( pid == -1 ){
		/*
		syslog_ERROR("-- FAILED fork(%s), errno=%d\n",what,errno);
		*/
		daemonlog("F","-- FAILED fork(%s), errno=%d\n",what,errno);
	}else
	if( pid == 0 ){
		syslog_ERROR("-- Fork(%s): %d -> %d\n",what,getppid(),MyPID);
	}
	else{
		if( lTRVERB() )
		if( doTracePid == getpid() )
			TraceLog("+ Fork(%s) = %d\n",what,pid);
	}
	return pid;
}
int _Forkpty(int *pty,char *name);
int Forkpty(int *pty,char *name){
	int pid;
	const char *what = "Forkpty";

	pid = _Forkpty(pty,name);
	if( pid == 0 ){
		MyPID = getpid();
		syslog_ERROR("-- Forkpty(%s): %d -> %d\n",what,getppid(),MyPID);
		on_fork(MyPID);
		execCloseOnFork(what);
	}
	return pid;
}

extern int SPAWN_P_NOWAIT;
int spawnvp(int pmode,PCStr(path),const char *const argv[]);
static const char *SpawnWhat = "";
#if !defined(_MSC_VER)
int spawnvp(int pmode,PCStr(path),const char *const argv[]){
	int pid;

	pid = Fork(SpawnWhat);
	if( pid != 0 ){
		return pid;
	}
	syslog_ERROR("-- Exec(%s)\n",SpawnWhat);
	execvp(path,(char*const*const)argv);
	exit(-1);
	return -1;
}
#endif

int Spawnvp(PCStr(what),PCStr(path),const char *const av[])
{	int pid;

	if( DontFork ){
		return -1;
	}
	SpawnWhat = what;
	MyPID = 0;
	pid = spawnvp(SPAWN_P_NOWAIT,path,av);
	return pid;
}

void Exit(int code,PCStr(fmt),...)
{	CStr(msg,2048);

	if( code != 0 ){
		VARGS(8,fmt);
		sprintf(msg,"Exit (%d) ",code);
		Xsprintf(TVStr(msg),fmt,VA8);
		syslog_ERROR("%s",msg);
	}
	Finish(code);
}

static int usualsig(int sig)
{
	if( sig == SIGALRM ) return 1;
	if( sig == SIGPIPE ) return 1;
	if( sig == SIGTERM ) return 1;
	return 0;
}
int WaitXX(int mode,int *sigp);
int WaitX(int mode)
{
	return WaitXX(mode,NULL);
}
int WaitXXX(int mode,int *sigp,int *statp);
extern int WAIT_WNOHANG;
int WaitXX(int mode,int *sigp)
{
	return WaitXXX(mode,sigp,NULL);
}
/*
int WaitXX(int mode,int *sigp)
*/
int WaitXXX(int mode,int *sigp,int *statp)
{	int status[4]; /**/
	int pid,xpid,sig,xcode,st;
	int serrno;

	if( sigp )
		*sigp = 0;
	for(;;){
		pid = wait3(status,mode,NULL);
		if( statp ){
			*statp = getWaitExitCode(status);
		}
		if( !lTRACE() )
		if( sigp == NULL )
			break;
		if( pid <= 0 )
			break;
		st = status[0];

		if( 0 <= (xcode = getWaitExitCode(status)) ){
			if( isWindows() ){
				/* introduced in 6.0.4 for PTRACE ?
				 * but seems useless to wait exited process
				 * and anyway unsupported on Windows
				 */
				xpid = -1;
			}else
			xpid = waitpid(pid,status,0);
			if( lTRVERB() )
			TraceLog("- Wait [%04X] pid=%d EXITED(%d) %d\n",
				st,pid,xcode,xpid);
			return pid;
		}
		if( 0 < (sig = getWaitExitSig(status)) ){
			xpid = waitpid(pid,status,0);
			TraceLog("- Wait [%04X] pid=%d SIGNALED(%d=%s)%s %d\n",
				st,pid,sig,sigsym(sig),
				getWaitExitCore(status)?" COREDUMP":"",xpid);
			if( sigp )
				*sigp = sig;
			return pid;
		}
		if( 0 < (sig = getWaitStopSig(status)) ){
			if( lTRVERB() || !usualsig(sig) )
			TraceLog("- Wait [%04X] pid=%d STOPSIG(%d=%s)\n",
				st,pid,sig,sigsym(sig));
			if( sig == SIGTRAP ){
				if( lNOEXEC() )
					ptraceKill(pid);
				else	ptraceContinue(pid,0);
			}else	ptraceContinue(pid,sig);
			continue;
		}
		TraceLog("- Wait [%04X] pid=%d wait unknown\n",st,pid);
		if( mode == WAIT_WNOHANG )
			break;
	}
	/*
	serrno = errno;
	syslog_ERROR("-- Wait()=%d, errno=%d\n",pid,errno);
	errno = serrno;
	*/
	return pid;
}
int NoHangWait()
{
	return WaitX(WAIT_WNOHANG);
}
int NoHangWaitX(int *sigp)
{
	return WaitXX(WAIT_WNOHANG,sigp);
}
int NoHangWaitXX(int *sigp,int *statp)
{
	return WaitXXX(WAIT_WNOHANG,sigp,statp);
}
int procIsAlive(int pid)
{	int rcode;

	errno = 0;
	rcode = kill(pid,0);
	return errno != ESRCH;
}
void msleep(int msec);
int TimeoutWait(double To){
	double Start = Time();
	int xpid = -1;
	int ti,to;

	to = 10;
	for( ti = 0;; ti++ ){
		xpid = NoHangWait();
		if( 0 < xpid )
			break;
		if( xpid <= 0 ){
			if( errno == ECHILD )
				break;
		}
		if( To < Time()-Start )
			break;
		msleep(to);
		if( to < 1000 )
			to += 100;
	}
	return xpid;
}

static int execerror(PCStr(where),PCStr(path),int rcode);
extern char *getusernames(PVStr(names));
int Execvp(PCStr(where),PCStr(path),const char *const av[])
{	int rcode;
	CStr(pwd,1024);
	CStr(names,1024);
	const char *nav[2]; /**/
	const char *env;

	BeforeExec();
	endhostent();
	if( av[0] == NULL ){
		nav[0] = nav[1] = NULL;
		av = nav;
	}
	rcode = execvp(path,(char**)av);
	execerror(where,path,rcode);
	return -1;
}
static int execerror(PCStr(where),PCStr(path),int rcode){
	CStr(pwd,1024);
	CStr(names,1024);
	const char *env;

	fprintf(stderr,"[%d] %s: Could not execute COMMAND: %s\n",getpid(),
		where,path);
	fprintf(stderr," with the OWNER uid/gid: %s\n",getusernames(AVStr(names)));
	fprintf(stderr," at the DIR: %s\n",getcwd(pwd,sizeof(pwd)));
	fprintf(stderr,"You should check that you can execute the COMMAND\n");
	fprintf(stderr," at the DIR with the access right of the OWNER.\n");
	if( env = getenv("PATH") )
		fprintf(stderr,"PATH=%s\n",env);
	else	fprintf(stderr,"PATH undefined.\n");
	perror("Execvp");
	Exit(-1,"%s(%s) failed(%d) errno=%d\n",where,path,rcode,errno);
	return -1;
}

/*
 * env. cause inconsistency after CHROOT or on multi-architectures
 */
int filterDGENV(char *ev[],char *nev[],int nec){
	int ei;
	int en = 0;
	for( ei = 0; ev[ei] && en < nec-1; ei++ ){
		if( strneq(ev[ei],"DYLIB_",5)
		 || strneq(ev[ei],"LIBPATH=",8)
		 || strneq(ev[ei],"_CAPSKEY_=",10)
		){
			continue;
		}
		nev[en++] = ev[ei];
	} 
	nev[en] = 0; 
	return en;
}
int Xexecve(FL_PAR,const char *path,char *av[],char *ev[]){
	int rcode;
	char *nev[1024];

	filterDGENV(ev,nev,elnumof(nev));
	rcode = execve(path,av,nev);
	return rcode;
}
int closeFds(Int64 inheritfds){
	int nc = 0;
	int fd;

	for( fd = 0; fd < 64; fd++ ){
		if( inheritfds & (1 << fd) ){
			continue;
		}
		if( close(fd) == 0 ){
			nc++;
		}
	}
	return nc;
}
extern char **environ;
int ExecveX(PCStr(where),PCStr(path),ConstV av,ConstV ev,int flag){
	const char *nav[2]; /**/
	char *nev[1024];
	char **oev;
	int rcode;

	BeforeExec();
	endhostent();
	if( av[0] == NULL ){
		nav[0] = nav[1] = NULL;
		av = nav;
	}
	oev = (char**)ev;
	if( flag & EXP_NOENV  ){
		filterDGENV(oev,nev,elnumof(nev));
		ev = nev;
	}
	if( flag & EXP_NOFDS ){
		closeFds(0);
	}
	if( flag & EXP_PATH ){
		environ = (char**)ev;
		rcode = execvp(path,(char**)av);
	}else{
		rcode = execve(path,(char**)av,(char**)ev);
	}
	execerror(where,path,rcode);
	return -1;
}

int Kill(int pid,int sig)
{	int rcode;

	syslog_ERROR("Kill(%d,%d)\n",pid,sig);
	if( pid == 0 || pid == 1 || pid == -1 ){
		syslog_ERROR("Error: tried to Kill %d X-<\n",pid);
		return -1;
	}
	errno = 0;
	rcode = kill(pid,sig);
	if( rcode != 0 )
		syslog_ERROR("Kill(%d,%d)=%d, errno=%d\n",pid,sig,rcode,errno);
	return rcode;
}
int KillTERM(int pid)
{
	return Kill(pid,SIGTERM);
}
int Killpg(int pgrp,int sig)
{
	int rcode;
	syslog_ERROR("Killpg(%d,%d)\n",pgrp,sig);
	if( pgrp == 0 || pgrp == 1 ){
		syslog_ERROR("Error: tried to Killpg %d X-<\n",pgrp);
		return -1;
	}
	/*
	return killpg(pgrp,sig);
	*/
	errno = 0;
	rcode = killpg(pgrp,sig);
	if( rcode )
	syslog_ERROR("Killpg(%d,%d)=%d, errno=%d\n",pgrp,sig,rcode,errno);
	return rcode;
}

#ifdef wait
#undef wait
#endif
int Xwait(int *status){
	int pid;
	int serrno;

	pid = wait(status);
	serrno = errno;
	syslog_ERROR("-- Xwait()=%d, errno=%d\n",pid,errno);
	errno = serrno;
	return pid;
}
