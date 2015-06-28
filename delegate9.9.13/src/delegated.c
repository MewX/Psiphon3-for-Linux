/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	delegated (DeleGate Server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940303	created
//////////////////////////////////////////////////////////////////////#*/
#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "hostlist.h"
#include "config.h"
#include "vsignal.h"
#include "yselect.h"
#include "credhy.h"
#include "fpoll.h"
#include "proc.h"
#include "delegate.h"
#include "param.h"
#include "filter.h"
#include "auth.h"
#include <fcntl.h>

extern int AccViaHTMUX; /* accept by normal accept() via SockMux */
#ifdef UNDER_CE
int closeR(FL_PAR,int fd);
static int closeS(FL_PAR,int fd){
	int rcode;
	if( AccViaHTMUX ){
		rcode = closeR(FL_BAR,fd);
	}else{
		rcode = close(fd);
	}
	return rcode;
}
#undef closeEfd
#define closeEfd(efd) \
	(efd==NULL?-1:(efd->_closed?-1:((efd->_closed=1),closeS(FL_ARG,efd->_fd))))
#endif
#if UNDER_CE
int setStdio(FILE *stdio,FILE *fp){
	return -1;
}
#else
int setStdio(FILE *stdio,FILE *fp){
	*stdio = *fp;
	return 0;
}
#endif

static MMap *logMMap;
int setDebugX(Connection *Conn,PCStr(arg),int force);
void setupForSolaris();
void setLogTimeFmt(PCStr(fmt));
void setLogTimeFmtL(int fx);
void appendProcLog(FL_PAR,int pid);
void putWinStatus(PCStr(fmt),...);
int askWinOK(PCStr(fmt),...);

int saveAuthMan();
int restoreAuthMan();

void servlog(PCStr(fmt),...);
int getthreadid();
int create_service(int ac,const char *av[],PCStr(port));
int delete_service(int ac,const char *av[],PCStr(port),PCStr(arg));
int restart_service(PCStr(port),int ac,const char *av[]);
int setDGROOT();
int xrealpath(PCStr(path),PVStr(rpath),int size);
int copyFileAndStat(PCStr(src),PCStr(dst));
void dumpstacksize(PCStr(what),PCStr(fmt),...);
int setNonblockingSocket(int fd,int on);

char *STACK_BASE;
char *STACK_PEAK;
unsigned int STACK_SIZE;

#define SIGHUPTERM	(0 < SIGHUP ? SIGHUP : SIGTERM)
DeleGateEnv *deleGateEnv;

extern char DGAUTHpro[];
extern char DGAUTHdom[];

int NUM_THSV = 0;
int SERNO();
extern int CHILD_SERNO;
extern int CHILD_SERNO_MULTI;
extern int CHILD_SERNO_SINGLE;

extern int SERVER_DEFREEZE;
extern int SERVER_RESTART;
extern int SERVER_TIMEOUT;
extern int VSAP_TIMEOUT;
extern int NUM_CHILDREN;
extern int NUM_PEERS;
extern int START_TIME;
extern int RES_localdns;
extern int RESOLV_UNKNOWN;
extern int SCRIPT_UNKNOWN;
extern int ERROR_RESTART;
extern int NUM_HUPS;
extern int SVSTAT_FD;
extern int config_FD;
extern int SERVER_RESTART_SERNO;

typedef struct {
	int	p_stat:8,
		p_pid:24; /* process id on Unix, process handle on Win32 */
	int	p_xid;	/* zero on Unix, process id on Win32 */
} Proc;

typedef struct {
	int	me_ServerPID;
	int	me_myPrivateMASTER;
	int	me_MASTERisPrivate;
	int	me_IamPrivateMASTER;
	int	me_restartPrivateMASTER;
	int	me_IamCGI;

	int	me_TeleportPID;
	int	me_sudoPID;
	MStr(	me_PrivateMasterOwnerPort,64);
  const	char   *me_workFiles[16]; /**/
	int	me_workFileX;
	jmp_buf me_exec_env;
	int	me_idle_timer;

	int	me_inINITIALIZATION;
	int	me_INTERRUPT_STICKY;
	int	me_StickyMAX_PARA;/* max. parallel Stickies */
	int	me_StickyMAX_LIFE;/* max. services by a Sticky */
	int	me_StickyTIMEOUT; /* standby seconds. (users' click interval) */
	int	me_StickyTIMEOUT1;
	/*
	int    *me_StickyProcs;
	*/
	Proc   *me_StickyProcs;
	int	me_StickyActive;
	int	me_StickyReport[2];
	int	me_StickyLastAccept;
	int	me_StickyNaccepted;
	int	me_StickyNscreened;
	int	me_StickyDone;
	int	me_ACC_BYMAIN_INTERVAL; /* retry after blocked by Stickies */
	int	me_ACC_REJECTED;
  const	char   *me_originWD;

	/*
	int	me_MAX_SERVICE;
	*/
	int	me_gotSIGTERM;
	int	me_doSIGCHLDpid;
	int	me_numSIGCHLD;
	int	me_include_next;
	int	me_dont_check_param;
    Connection *me_mainConn;
	int	me_CLsock;
  const	char   *me_execSPECIAL;
	defQStr(me_Serverurl0);
  const	char   *me_servermount_proto;
	int	me_mount_done;
  const	char  **me_direnv_environ;
	int	me_scannedGlobal;
	int	me_scanDirDefsX;
	defQStr(me_hostid_PATH);
	int	me_IDLE_TIMEOUT;
  const	char   *me_ABMwhere;
	Efd    *me_clientSocks;
	int	me_ACC_NONE_TIMEOUT;
	int	me_lockedoutN;
	int	me_lockedoutT;
	int	me_lastserveN;
	int	me_lastscreenN;
	int	me_lastdoneN;
	int	me_Ntimeout;
  const	char   *me__workdir;
	int	me_init_HOSTS;

  const	char	*me_PrivateMasterOwner;
  const	char	*me_DeleGate1;
  const	char	*me_FuncFunc;
	int	 me_isFuncFunc;
  const	char	*me_FuncSTICKY;
  const	char	*me_FuncFILTER;
	int	 me_Fopt;	/* arg[Fopt] == "-F..." */
	int	 me_isFunc;

	int	 me_restart;
	/*
	int	 me_maxerestart;
	*/
	MStr(	 me_src_socks,128);
	int	 me_ekeyFd;
	int	 me_deleGateId;
	int	 me_privateDGAuth;
	MStr(	 me_curCHROOT,128);
	int	 me_accsimul; /* ACcess Control Simulation */

	int	me_StickyNserved;
	int	me_MainNserved;
	int	me_MainNaccepted;
	int	me_MainLastAccept;
	int	me_terminating;
} MainEnv;

static MainEnv *mainEnv;
#define ME mainEnv[0]
/*
#define MAX_ERESTART	ME.me_maxerestart
*/
#define ServerPID	ME.me_ServerPID
#define myPrivateMASTER	ME.me_myPrivateMASTER
#define MASTERisPrivate	ME.me_MASTERisPrivate
#define IamPrivateMASTER	ME.me_IamPrivateMASTER
#define restartPrivateMASTER	ME.me_restartPrivateMASTER
#define IamCGI		ME.me_IamCGI

#define TeleportPID	ME.me_TeleportPID
#define sudoPID		ME.me_sudoPID
#define PrivateMasterOwnerPort	ME.me_PrivateMasterOwnerPort
/**/
#define workFiles	ME.me_workFiles
#define workFileX	ME.me_workFileX
#define exec_env	ME.me_exec_env
#define idle_timer	ME.me_idle_timer

#define inINITIALIZATION	ME.me_inINITIALIZATION
#define INTERRUPT_STICKY	ME.me_INTERRUPT_STICKY
#define StickyMAX_PARA	ME.me_StickyMAX_PARA
#define StickyMAX_LIFE	ME.me_StickyMAX_LIFE
#define StickyTIMEOUT	ME.me_StickyTIMEOUT
#define StickyTIMEOUT1	ME.me_StickyTIMEOUT1
#define StickyProcs	ME.me_StickyProcs
#define StickyActive	ME.me_StickyActive
#define StickyReport	ME.me_StickyReport
#define StickyLastAccept	ME.me_StickyLastAccept
#define StickyNaccepted	ME.me_StickyNaccepted
#define StickyNscreened	ME.me_StickyNscreened
#define StickyNserved	ME.me_StickyNserved
#define StickyDone	ME.me_StickyDone
#define ACC_BYMAIN_INTERVAL	ME.me_ACC_BYMAIN_INTERVAL
#define ACC_REJECTED	ME.me_ACC_REJECTED
#define MainLastAccept	ME.me_MainLastAccept
#define MainNaccepted	ME.me_MainNaccepted
#define MainNserved	ME.me_MainNserved
#define originWD	ME.me_originWD

/*
#define MAX_SERVICE	ME.me_MAX_SERVICE
*/
#define gotSIGTERM	ME.me_gotSIGTERM
#define terminating	ME.me_terminating
#define doSIGCHLDpid	ME.me_doSIGCHLDpid
#define numSIGCHLD	ME.me_numSIGCHLD
#define include_next	ME.me_include_next
#define dont_check_param	ME.me_dont_check_param
#define mainConn	ME.me_mainConn
#define CLsock		ME.me_CLsock
#define execSPECIAL	ME.me_execSPECIAL
#define Serverurl0	ME.me_Serverurl0
/**/
#define servermount_proto	ME.me_servermount_proto
#define mount_done	ME.me_mount_done
#define direnv_environ	ME.me_direnv_environ
#define scannedGlobal	ME.me_scannedGlobal
#define scanDirDefsX	ME.me_scanDirDefsX
#define hostid_PATH	ME.me_hostid_PATH
/**/
#define IDLE_TIMEOUT	ME.me_IDLE_TIMEOUT
#define ABMwhere	ME.me_ABMwhere
#define clientSocks	ME.me_clientSocks
#define ACC_NONE_TIMEOUT	ME.me_ACC_NONE_TIMEOUT
#define lockedoutN	ME.me_lockedoutN
#define lockedoutT	ME.me_lockedoutT
#define lastserveN	ME.me_lastserveN
#define lastscreenN	ME.me_lastscreenN
#define lastdoneN	ME.me_lastdoneN
#define Ntimeout	ME.me_Ntimeout
#define _workdir	ME.me__workdir
#define init_HOSTS	ME.me_init_HOSTS

#define PrivateMasterOwner	ME.me_PrivateMasterOwner
#define DeleGate1	ME.me_DeleGate1
#define FuncFunc	ME.me_FuncFunc
#define isFuncFunc	ME.me_isFuncFunc
#define FuncSTICKY	ME.me_FuncSTICKY
#define FuncFILTER	ME.me_FuncFILTER
#define Fopt		ME.me_Fopt
#define isFunc		ME.me_isFunc
#define ekeyFd		ME.me_ekeyFd
#define deleGateId	ME.me_deleGateId
#define privateDGAuth	ME.me_privateDGAuth
#define curCHROOT	ME.me_curCHROOT

int MAX_ERESTART = 1;
int MAX_SERVICE;
void minit_main()
{
	if( mainEnv == 0 ){
		mainEnv = NewStruct(MainEnv);

		ACC_BYMAIN_INTERVAL = 200;
		ACC_NONE_TIMEOUT = 60;
		IDLE_TIMEOUT = 10*60;
		StickyTIMEOUT1 = 10;
		/*
		MAX_ERESTART = 1;
		*/

		CLsock = -1;
		StickyReport[0] = StickyReport[1] = -1;

		ABMwhere = "";
		PrivateMasterOwner = "(private-MASTER for ";
		DeleGate1	= "DeleGate";
		FuncFunc	= "(Function)";
		FuncSTICKY	= "(Sticky)";
		FuncFILTER	= "(Filter)";

		deleGateEnv = NewStruct(DeleGateEnv);
		clientSocks = NewStruct(Efd);
		ekeyFd = -1;
	}
}

extern int STANDBY_MAX;
extern int STANDBY_TIMEOUT;
extern int FDSET_MAX;
extern int BREAK_STICKY;

extern int DELEGATE_PAUSE;

extern int   LOG_initFd;
extern int   LOG_init_enable;
extern const char *DELEGATE_LOGCENTER;
extern int   LOG_center;
extern const char *DELEGATE_STDOUTLOG;
extern const char *DELEGATE_ERRORLOG;
extern const char *DELEGATE_TRACELOG;
extern int   DELEGATE_LastModified;
extern int DGEXE_DATE;
extern int DGEXE_SIZE;
extern int DGEXE_MD532;
int MAX_DELEGATEP(int dyn);
#define MAX_DELEGATE MAX_DELEGATEP(1)

extern char **environ;
extern int  main_argc;
extern const char **main_argv;
extern int  param_file;

#define getEnv(name)		DELEGATE_getEnv(name)
#define scanEnv(Conn,name,func)	DELEGATE_scanEnv(Conn,name,func)
#define pushEnv(name,value)	DELEGATE_pushEnv(name,value)

#define cronExit	DELEGATE_cronExit
#define sched_execute	DELEGATE_sched_execute
#define sched_action	DELEGATE_sched_action
int DELEGATE_cronExit(int pid);
void DELEGATE_sched_action(Connection *Conn,PCStr(action));

int set_svstat(int fd);
int set_svname(PCStr(name));
int set_svtrace(int code);
int put_svstat();
int close_svstat();
const char *get_svname();

void compatV5info(PCStr(fmt),...)
{	CStr(msg,1024);
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	Verbose("##DeleGate/6.X: %s will make it compatible with former versions.\n",
		msg);
}

int serverPid(){ return ServerPID ? ServerPID : getpid(); }
int iamServer(){ return getpid() == ServerPID; }

void scan_CRYPT(Connection *Conn,int clnt);
static int doneCRYPT;
int getCKeySec(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int ksiz);
void init_CRYPT(Connection *Conn,int clnt){
	if( 0 <= ekeyFd ){ /* when spawned on Win32 not to ask CRYPT=pass: */
		IStr(ek,64);
		if( getCKeySec(P_CRYPT,"master","",AVStr(ek),sizeof(ek)) ){
			doneCRYPT = 2;
		}
		bzero(ek,sizeof(ek));
	}
	if( doneCRYPT == 0 ){
		if( Conn == NULL )
			Conn = mainConn;
		scan_CRYPT(Conn,1);
		doneCRYPT = 1;
	}
}
Connection *MainConn(){ return mainConn; }

int getCryptKeyX(Connection *Conn,int which,PCStr(param),PCStr(dom),PCStr(user),PVStr(key),int siz);
int getCryptKeyMain(int which,PCStr(param),PCStr(dom),PCStr(user),PVStr(ckey),int ksiz){
	return getCryptKeyX(mainConn,which,param,dom,user,BVStr(ckey),ksiz);
}

extern char DGAUTHadmdom[];
static struct {
	char	*c_salt;
	int	 c_len;
	int	 c_time;
} creySalt;
int findPass(PCStr(proto),PCStr(user),PVStr(pass));
int getCreySalt(PVStr(str)){
	int len;

	if( creySalt.c_salt != NULL ){
		len = creySalt.c_len;
		strcpy(str,creySalt.c_salt);
		return len;
	}

	if( findPass("admin","creysalt",BVStr(str)) ){
		len = strlen(str);
	}else{
		truncVStr(str);
		len = getDigestPass(DGAUTHadmdom,"creysalt",BVStr(str));
		if( len == -AUTH_ENOUSER ){
			sv1log("Will not retry DigestPass: No creysalt\n");
			len = 0;
		}
		if( len == -AUTH_ENOSERV ){
			init_CRYPT(NULL,1);
			len = getDigestPass(DGAUTHadmdom,"creysalt",BVStr(str));
		}
	}
	if( 0 <= len ){
		creySalt.c_len = len;
		creySalt.c_salt = stralloc(str);
		creySalt.c_time = time(0);
	}
	return len;
}
int (*getCreySALT)(PVStr(str)) = getCreySalt;

int CredhyFile(int com,PCStr(p1),PCStr(p2),PCStr(px),FILE *in,FILE *out);
static void setLastModified()
{	FILE *tmp,*fp;
	FILE *tmpx;
	const char *form;
	int modified;
	CStr(xpath,1024);

	tmp = TMPFILE("setLastModified");
	DELEGATE_dumpEnv(tmp,0,IamPrivateMASTER);
	fflush(tmp);
	fseek(tmp,0,0);

	modified = 1;
	form = DELEGATE_PARAMFILE;
	if( doneCRYPT ){
		CStr(ekey,128);
		int klen;
		if( 0 < (klen = getCKey(AVStr(ekey),sizeof(ekey))) ){
			tmpx = TMPFILE("setLastModified-Crypted");
			sprintf(xpath,"%s.cdh",form);
			form = xpath;
			CredhyFile(1,ekey,NULL,NULL,tmp,tmpx);
			bzero(ekey,sizeof(ekey));
			sv0log("Encrypted with the CRYPT MasterKey: %d->%d %s\n",iftell(tmp),iftell(tmpx),form);
			fclose(tmp);
			fflush(tmpx);
			fseek(tmpx,0,0);
			tmp = tmpx;
		}
	}

	if( fp = LOG_openLogFile(form,"r") ){
		if( fcompare(tmp,fp) == 0 ){
			modified = 0;
			DELEGATE_LastModified = file_mtime(fileno(fp));
		}
		fclose(fp);
	}
	if( modified ){
		DELEGATE_LastModified = time(0);
		if( fp = LOG_openLogFile(form,"w") ){
			copy_file(tmp,fp,NULL);
			fclose(fp);
		}
	}
	fclose(tmp);
	/*
	sv0log("DELEGATE_Modified[%d]: %x\n",modified,DELEGATE_LastModified);
	*/
	sv0log("DELEGATE_Modified[%d]: %x %d\n",modified,DELEGATE_LastModified,
		DELEGATE_LastModified);
}

void logTERMINATION(PCStr(what)){
	IStr(uname,128);
	IStr(sdate,128);
	IStr(edate,128);
	int etime;

	Uname(AVStr(uname));
	etime = time(0) - START_TIME;
	sprintf(sdate,"%d+%d:%d:%d",etime/(24*3600),(etime%(24*3600))/3600,
		(etime%3600)/60,etime%60);
	StrftimeLocal(AVStr(edate),sizeof(edate),"%y%m%d%H%z",time(0),0);
	sv0log("--TERMINATION by %s %s (%s) %s on %s\n",
		"SIGTERM",edate,sdate,DELEGATE_ver(),uname);
	sv0log("%s=%s\n",P_EXEC_PATH,EXEC_PATH); /* v9.9.12 140825b */
}

static void sigIGN(int sig){
	/*
	fprintf(stderr,"[%d] SIG-%d ignored in XFinish\n",getpid(),sig);
	*/
	putfLog("SIG%d ignored in XFinish",sig);
}
static int inFinish;
static void XFinish(int sig){
	if( inFinish ){
		/*
		fprintf(stderr,"[%d] XFinish in XFinish\n",getpid());
		*/
		putfLog("XFinish in XFinish (SIG%d)",sig);
	}else{
		inFinish = 1;
		signal(SIGSEGV,SIG_DFL);
		signal(SIGBUS, SIG_DFL);
		signal(SIGILL, SIG_DFL);
		signal(SIGPIPE,sigIGN);
		signal(SIGTERM,sigIGN);
		signal(SIGINT, sigIGN);
		signal(SIGURG, sigIGN);
	}
	Finish(sig);
}
#undef Finish
#define Finish	XFinish

void SetStopService(PCStr(reason));
void childStopService(PCStr(where),int sig,int pid)
{	CStr(reason,256);

	switch( sig ){
		case SIGSEGV:
		case SIGBUS:
		case SIGILL:
			sprintf(reason,"[%s SIG%d in child %d]",where,sig,pid);
			SetStopService(reason);
			break;
	}
}
int checkChildAbort1(PCStr(where))
{	int pid,sig;

	pid = NoHangWaitX(&sig);
	if( pid <= 0 )
		return pid;
	if( sig ){
		sv0log("ChildAbort[%s] PID=%d SIG=%d\n",where,pid,sig);
		childStopService(where,sig,pid);
	}
	return pid;
}
void checkChildAbort(PCStr(where))
{	int pid;

	for(;;){
		if( (pid = checkChildAbort1(where)) <= 0 )
			break;
	}
}
int setgotsigTERM(int sig);
void exitfromXf(PCStr(wh),int isig);
static void exitXf(int sig){
	if( !lMTSS_NOSSIG() ){
		IStr(wh,128);
		if( getpid() == ServerPID )
			strcat(wh,"Parent");
		else	strcat(wh,"Child");
		if( ismainthread() )
			strcat(wh,"Main");
		else	strcat(wh,"Non-main");
		exitfromXf(wh,sig);
	}
}
static void sigPIPE(int sig){
	if( ismainthread() == 0 ){
		/*
		sv1log("ignored: SIGPIPE in non-main thread [%X] %X\n",
		*/
		fprintf(stderr,"[%d.%X]ignored:SIGPIPE in non-main thread %X\n",
			getpid(),
			getthreadid(),mainConn->xf_filters);
		signal(SIGPIPE,sigPIPE);
		/* closing sockets/pipes is fatal */
		return;
	}

	selfLocaltime++; /* 9.9.4 MTSS */
	if( numthreads() ){
		/* 9.9.4 MTSS suppress longjump in termination procedure */
		signal(SIGALRM,sigIGN);
		sv0log("#abort: caught SIGPIPE with threads: %d/%d/%d/%d\n",
			newthreads(),actthreads(),endthreads(),numthreads());
	}else
	sv0log("abort: caught SIGPIPE\n");
	checkChildAbort("sigPIPE");

	if( !lSINGLEP() && iamServer() ){
		/* 9.9.0 might be forwarded from a thread in another process
		 * (RedHat9, NPTL 0.29)
		 */
		sv1log("####[%d.%X]ignored:SIGPIPE in main process %d/%d\n",
			getpid(),getthreadid(),actthreads(),numthreads());
		selfLocaltime--;
		return;
	}

	setgotsigTERM(sig); /* 9.9.4 MTSS suppress further longjmp */
	if( 0 < numthreads() ){
		int fd;
		int nc = 0;
		int ntx;

		/* 9.6.0 closing sockets for safety: this was necessary to
		 * terminate a thread (of SSLway for FTP originally) by letting
		 * it detect the disconnection of its socket then do exit
		 * to be waited and cleaned with thread_wait() without freezing.
		 */
		for( fd = 0; fd < 64; fd++ ){
			if( 0 < file_issock(fd) ){
				if( close(fd) == 0 )
					nc++;
			}
		}
		ntx = waitFilterThread(mainConn,300,XF_ALL);
		if( 0 < actthreads() ){
			/* 9.9.4 */
			sv1log("sigPIPE: sockets*%d threads*%d %d/%d _exit\n",
				nc,ntx,actthreads(),numthreads());
			_exit(-1);
		}
		sv1log("sigPIPE: sockets*%d threads*%d exit\n",nc,ntx);
	}else
	if( mainConn->xf_filters ){
		/* this code is introduced in 9.2.4-pre10 maybe to confirm the
		 * termination of filter processes as SSLway ? But closing all
		 * S_ISFIFO (for thread control?) causes loop in exit() with
		 * a certain implementation of pthread on Linux (LinuxThreads).
		 */
		int fd;
		int nc = 0;
		int ni;
		for( fd = 0; fd < 64; fd++ ){
			if( 0 < file_issock(fd) || file_isfifo(fd) ){
				if( close(fd) == 0 )
					nc++;
			}
		}
		if( 0 < nc ){
			int xpid;
			for( ni = 0; ni < nc; ni++ ){
				xpid = NoHangWait();
				if( xpid <= 0 ){
					break;
				}
				sv1log("sockets*%d exit=%d\n",nc,xpid);
			}
		}
	}
	exitXf(sig);
	Finish(-1);
}
static void sigURG(int sig){
	sv0log("abort: caught SIGURG\n");
	Finish(-1);
}

void deleteWORKDIR();
int ClientCountDown();
int ClientCountUp(PCStr(user),PCStr(host),PCStr(addr),int port);

static const char *NoTmpSpaceLog = "/var/tmp/delegate-error";
int NoTmpSpace(){
	FILE *fp;
	int pid = getpid();
	int now = time(0);

	putsLog("NO DISK SPACE");
	fprintf(stderr,"[%u] %u DeleGate: NO DISK SPACE\n",pid,now);
	if( fp = fopen(NoTmpSpaceLog,"a") ){
		fprintf(fp,"[%u] %u DeleGate: NO DISK SPACE\n",pid,now);
		fclose(fp);
	}
	return 0;
}

static int inMMapWrite;
void exitFATAL(int sig);
void DELEGATE_sigFATAL(int sig){
	CStr(cwd,1024);
	signal(sig,SIG_IGN);
	if( inMMapWrite ){
		putsLog("##SIGFATAL on MMapWrite"); /* file full ? */
		sleep(3);
		_exit(0);
	}
	daemonlog("F","E-A: ABORT: caught SIG%s [%d]\n",sigsym(sig),sig);
	if( EscEnabled() ){
	}else
	ClientCountDown();
/* this AbortLog() will flush the logfile which should be used in abort() */
	AbortLog();
	IGNRETS getcwd(cwd,sizeof(cwd));
	daemonlog("F","E-A: core will be at %s\n",cwd);
	abort();
}
#define sigFATAL DELEGATE_sigFATAL

void sox_finish();
int iamPrivateSox();
int TimeoutWait(double To);
int cleanup_zombis(int log);
double WAITCHILD_TIMEOUT = 3;

extern int inSignalHandler;
extern int logSigblock; /* to force sigblock in logging */
void logCSC(PCStr(wh),int force);
int dumpThreads(PCStr(wh));
void closeReservedPorts();

int FMT_gotsigTERM(PCStr(fmt),...){
	if( fmt && gotSIGTERM ){
		IStr(xfmt,128);
		VARGS(8,fmt);
		strcpy(xfmt,"-- gotSIG%s/%d in ");
		strcat(xfmt,fmt);
		putfLog(xfmt,sigsym(gotSIGTERM),gotSIGTERM,VA8);
	}
	return gotSIGTERM;
}
int setgotsigTERM(int sig){
	if( gotSIGTERM ){
		return gotSIGTERM;
	}
	BREAK_STICKY = 1;
	gotSIGTERM = sig; /* show/detect tht in emergent termination */
	inSignalHandler = sig; /* enable signal logging */
	selfLocaltime = 1; /* avoid mutex in localtime() -Etm */
	return 0;
}

int finishThreadYY(int tgid);
extern int THEXIT;
static void sigTERM(int sig)
{
	CStr(rusg,256);
	int kcode;

	if( lIMMEXIT() ){
		/* 9.9.5-pre3 for X proxy <= 9.8.2-pre47 Killpg(getpgrp()) */
		putsLog("##SIGTERM imm. exit by -Xi");
		putfLog("##SIGTERM imm. exit, pid=%d,pgrp=%d",
			getpid(),getpgrp());
		if( getpgrp() == getpid() ){
			/* 9.9.6 for X/Telnet on Unix */
			Killpg(getpgrp(),SIGTERM);
		}
		_exit(0);
	}

	setgotsigTERM(sig);
	exitXf(sig);

	if( iamPrivateSox() ){
		sv1log("## ignore SIGTERM in PrivateSox\n");
		Finish(0);
	}

	if( lSINGLEP() ){
		/* 9.9.5 for foreground SIGINT on Win32 */
		THEXIT = 1;
		putfLog("##SINGLE SIG%d main=%X",sig,ismainthread());
		finishThreadYY(0);
	}else
	if( !ismainthread() ){
		static int gotsig;
		putsLog("##SIGTERM non-main"); /* may not happen */
		msleep(100); /* try to yield to the main thread ... */
		sv1log("SIGTERM to non-main thread [%X] *%d\n",
			getthreadid(),gotsig);
		if( gotsig++ == 0 ){
			signal(SIGTERM,sigTERM);
			thread_exit(0);
		}
	}

	if( !lMTSS_NOSSIG() ){ /* 9.9.4 MTSS imm. exit on SIGTERM in child */
		if( getpid() != ServerPID ){
			signal(SIGINT, SIG_DFL);
			signal(SIGTERM,SIG_DFL);
			signal(SIGPIPE,SIG_DFL);
			signal(SIGALRM,SIG_DFL);
			closeReservedPorts(); /* 9.9.4 seems necessary */
			if( numthreads() ){
				putsLog("##SIGTERM to child-with-threads");
				if( actthreads() ){
					dumpThreads("SGTERM-to-child");
				}
				_exit(0);
			}else{
				putsLog("SIGTERM to child");
				_Finish(0);
			}
		}
	}
	putfLog("##SIGTERM to parent (%d)",sig);
	/* close(SticyReport[0]); StickyReport[0] = -1; */

	dumpCKey(0);
	gotSIGTERM = sig;
	signal(SIGTERM,SIG_IGN);

	/* set_svtrace(3) to set "Fin" state of this server */
	set_svtrace(3);
	LOG_init_enable = 1;
	lock_exclusiveNB(LOG_initFd);

	sv0log("DeleGate SERVER EXITS: caught SIG%s [%d]\n",sigsym(sig),sig);
	if( getpid() != ServerPID ){
		fprintf(stderr,"\nDeleGate[%d] got SIGTERM(%d) for server=%d\n",
			getpid(),sig,ServerPID);
		Finish(-1);
		_exit(-1);
	}
	logTERMINATION("SIGTERM");
	closeReservedPorts(); /* 9.9.4 should be before LOG_deletePortFile()
			       * for restarting with PORT (for SockMux)
			       */
	if( lSINGLEP() ){
		/* might be blocked or in mutex (?) */
	}else
	closeServPorts();
	sox_finish();
	/*
	Killpg(getpid(),SIGTERM);
	*/
	kcode = Killpg(getpgrp(),SIGTERM);
	signal(SIGTERM,SIG_DFL);

	cleanup_zombis(0);

	if( kcode == 0 && 0 < NUM_CHILDREN && WAITCHILD_TIMEOUT ){
		double Start = Time();
		int ri;
		int xpid;
		IStr(stat,256);

		/* should sweep children before restart by -r and do bind() */
		for( ri = 0; ri < 50 && 0 < NUM_CHILDREN; ri++ ){
			if( WAITCHILD_TIMEOUT < Time()-Start ){
				break;
			}
			sv0log("Left children: %d gr[%d] pp[%d]\n",
				NUM_CHILDREN,getpgrp(),getppid());
			msleep(20+ri*4);
			cleanup_zombis(0);
			if( errno == ECHILD ){
				/* inconsistent NUM_CHILDREN: DNS parallel */
				sv0log("No left children: %d\n",NUM_CHILDREN);
				NUM_CHILDREN = 0;
				break;
			}
		}
		for( ri = 0; ri < 50; ri++ ){
			xpid = NoHangWait();
			sprintf(stat,"Yet Left children: %d (%d %d)\n",
				NUM_CHILDREN,xpid,errno);
			if( WAITCHILD_TIMEOUT < Time()-Start
			 || errno == ECHILD
			){
				break;
			}
			sv0log("%s",stat);
			msleep(20);
		}
		if( NUM_CHILDREN )
			daemonlog("F","%s",stat);
		else	sv0log("%s",stat);
	}
	if( NUM_CHILDREN )
		sv0log("Left children: %d\n",NUM_CHILDREN);

	saveAuthMan();

	notify_ADMIN(NULL,"stop");

	deleteWORKDIR();
	/*
	LOG_deletePortFile();
	*/

	if( EscEnabled() ){
		scounter(-1,0,0,0);
	}
	strfRusage(AVStr(rusg),"%A",3,NULL);
	if( !isWindows() )
	fprintf(stderr,"[%d] RUSAGE: %s\n",getpid(),rusg);
	sv0log("RUSAGE: %s\n",rusg);
	sv0log("FINISH.\n");

	LOG_deletePortFile();  /* 9.9.1 should be after strfRusage() which
				* might be blocked ? by successor
				*/

	if( lSINGLEP() ){
		putfLog("##SINGLE SIG%d _exit(0)",sig);
		_exit(0);
	}
	Finish(0);
	fprintf(stderr,"*** exit() on SIGTERM(%d) failed.1\n",sig);
	_exit(0);
}
static void sigTERM1(int sig)
{
	if( !ismainthread() ){
		static int gotsig;
		msleep(100);
		sv1log("SIGTERM-1 to non-main thread [%X] *%d\n",
			getthreadid(),gotsig);
		if( gotsig++ == 0 ){
			return;
		}
		/* the main-thread can be frozen somewhere...(on Win) */
	}
	Finish(0);
	fprintf(stderr,"[%d]*** exit() on SIGTERM(%d) failed.2\n",getpid(),sig);
	_exit(0);
}


typedef struct {
	short	s_stat;
	short	s_done;
	int	s_pid;
} SReport;
#define SR_STICKY	1
#define SR_ACCEPT	2
#define SR_DETACH	4
#define SR_FINISH	8
#define SR_SCREENED	16

extern int LastCpid;
void putLoadStat(int what,int done);
static void StickyAdd(int pid)
{
	/*
	StickyProcs[StickyActive++] = pid;
	*/
	if( StickyMAX_PARA < StickyActive ){
		porting_dbg("--StickyAdd %d/%d",StickyActive,StickyMAX_PARA);
		return;
	}
	StickyProcs[StickyActive].p_stat = SR_STICKY;
	StickyProcs[StickyActive].p_xid = LastCpid;
	StickyProcs[StickyActive++].p_pid = pid;
}

static void setupStickyReport(int SR[2]){
	CStr(sock,256);
	CStr(peer,256);
	int oiz,ooz,niz,noz;

	if( lSINGLEP() ){
		return;
	}

	SR[0] = SR[1] = -1;
	if( lFXNUMSERV() && isWindows() ){
		return;
	}
	if( Socketpair(SR) != 0 ){
		daemonlog("F","## SERIOUS: Cannot create StickyReport[]\n");
	}else{
		getsockbuf(SR[1],&oiz,&ooz);
		expsockbuf(SR[1],0,0x10000);
		getsockbuf(SR[1],&niz,&noz);
		getpairName(SR[0],AVStr(sock),AVStr(peer));
		sv0log("StickyReport[%d,%d]%s><%s %d/%d %d/%d\n",SR[0],SR[1],
			sock,peer,oiz,ooz,niz,noz);
	}
}
static int nerrSR;
static void repairSR(int SR[2]){
	/*
	if( 5 < nerrSR || !IsConnected(SR[0],NULL) ){
	*/
	if( 5 < nerrSR
	 || !lFXNUMSERV() && !IsConnected(SR[0],NULL)
	){
		daemonlog("F","## SERIOUS: Broken StickyReport[%d,%d]%d\n",
			SR[0],SR[1],IsConnected(SR[0],NULL));
		close(SR[0]); SR[0] = -1;
		close(SR[1]); SR[1] = -1;
		setupStickyReport(SR);
		daemonlog("F","## SERIOUS: Reopened StickyReport[%d,%d]%d\n",
			SR[0],SR[1],IsConnected(SR[0],NULL));
		nerrSR = 0;
	}
}
static void getStickyReports()
{	unsigned char nserv;
	SReport SR;
	int rcc;

	/*
	while( readTimeoutBlocked(StickyReport[0],&nserv,1,1) == 1 ){
	*/
	/*
	if( 0 <= StickyReport[0] && 0 <= StickyReport[1] )
	*/
	if( 0 <= StickyReport[0] )
	if( 0 <= StickyReport[1] || lFXNUMSERV() )
	for(;;){
		rcc = readTimeoutBlocked(StickyReport[0],GVStr(&SR),sizeof(SR),1);
		if( rcc != sizeof(SR) ){
			nerrSR++;
			repairSR(StickyReport);
			break;
		}
		nerrSR = 0;
		nserv = SR.s_done;

		if(  SR.s_stat == SR_SCREENED ){
			StickyNscreened += SR.s_done;
			StickyLastAccept = time(NULL);
		}else
		if( nserv == 0 ){
			StickyNaccepted += 1;
			putLoadStat(ST_ACC,1);
			StickyLastAccept = time(NULL);
			Verbose("## getStickyReport: GOT ACCEPT REPORT #%d (+%d)\n",
				StickyNaccepted,MainNaccepted);
		}else{
			StickyNserved += nserv;
			putLoadStat(ST_DONE,nserv);
		}
		if( SR.s_stat & SR_DETACH ){
			int si;
			for( si = 0; si < StickyActive; si++ ){
				if( StickyProcs[si].p_pid == SR.s_pid
				 || StickyProcs[si].p_xid == SR.s_pid ){
					StickyProcs[si].p_stat = SR_DETACH;
				}
			}
		}
	}
}
static void StickyDel(int pid)
{	int si;

	for( si = 0; si < StickyActive; si++ ){
		/*
		if( StickyProcs[si] == pid ){
		}*/
		if( StickyProcs[si].p_pid == pid ){
			for(; si < StickyActive; si++)
				StickyProcs[si] = StickyProcs[si+1];
			StickyActive--;
			StickyDone++;
			break;
		}
	}

	if( 0 <= StickyReport[0] && inputReady(StickyReport[0],NULL) )
	getStickyReports();
}
static int StickyKill(int sig)
{	int si,pid,rcode;
	int nkill;

	nkill = 0;
	for( si = 0; si < StickyActive; si++ ){
		if( StickyProcs[si].p_stat & SR_DETACH )
			continue; 
		/*
		pid = StickyProcs[si];
		*/
		pid = StickyProcs[si].p_pid;
		rcode = Kill(pid,sig);
		if( rcode == 0 )
			nkill++;
	}
	sv1log("StickyKill(%d): %d/%d killed\n",sig,nkill,StickyActive);
	return nkill;
}
/*
 * Sticky in SR_DETACH status should not be killed nor waited.
 */
static int StickyToWait(){
	int si;
	int nwait = 0;
	for( si = 0; si < StickyActive; si++ ){
		if( StickyProcs[si].p_stat & SR_DETACH ){
		}else{
			nwait++;
		}
	}
	return nwait;
}

int kill_CC();
int num_CC();
void set_CC();
void del_CC(int pid,PCStr(how));
static int mySoxPid;

static void dec_nproc(int pid)
{
	if( pid == mySoxPid ){
		porting_dbg("PrivateSox failure? [%d]",pid);
		Finish(-1);
	}else
	if( pid == myPrivateMASTER ){
		myPrivateMASTER = 0;
		sv1log("#### privateMASTER[%d] dead\n",pid);
		if( getpid() == ServerPID )
			restartPrivateMASTER = 1;
		else	BREAK_STICKY = 1;
	} else
	if( pid == TeleportPID ){
		sv1log("Teleport Closed.\n");
		sigTERM(SIGTERM);
	}else
	if( pid == sudoPID ){
		daemonlog("F","#### SUDO dead [%d]\n",sudoPID);
		sudoPID = 0;
		/* restart it ? */
	}else
	if( cronExit(pid) ){
	}else{
		StickyDel(pid);
		del_CC(pid,"byWait");
		if( 0 < NUM_CHILDREN )
			NUM_CHILDREN--;
		else{
			sv1log("previous server's child ? %d\n",pid);
			TraceLog("grand child ? %d\n",pid);
		}
		Verbose("(%d) process [%d] dead\n",NUM_CHILDREN,pid);
	}
}

extern int doTracePid;
extern iFUNCP doTraceLog;
vfuncp signalRESTART(int sig,vfuncp func);

static void sigCHLD(int sig)
{
	if( getpid() != doSIGCHLDpid ){
		TraceLog("#### received unexpected SIGCHLD (1)\n");
		signal(SIGCHLD,SIG_DFL);
		return;
	}
	if( lSIGCHLD() == 0 ){
		TraceLog("#### received unexpected SIGCHLD (2)\n");
		signal(SIGCHLD,SIG_DFL);
		return;
	}
	++numSIGCHLD;
	if( lTRVERB() )
		TraceLog("SIGCHLD*%d\n",numSIGCHLD);
	cleanup_zombis(0);
	signalRESTART(SIGCHLD,sigCHLD);
}

void setWatchChild()
{	int size;

	if( lTRACE() ){
		doTracePid = getpid();
		doTraceLog = (iFUNCP)A_TraceLog;
		/*
		 * expand fdset for OS like Slaris which read child process's
		 * status via file like "/proc/*"
		 */
		size = expand_fdset(FDSET_MAX+MAX_DELEGATE*3);
		TraceLog("START tracing children, FD_SETSIZE=%d\n",size);
	}
	if( lSIGCHLD() ){
		doSIGCHLDpid = getpid();
		sigblock(sigmask(SIGCHLD));
		signalRESTART(SIGCHLD,sigCHLD);
		TraceLog("START accepting SIGCHLD\n");
	}
}
int ptraceTraceMe();
void setNoExec()
{	int rcode;

	if( lTRACE() == 0 )
		return;
	rcode = ptraceTraceMe();
	if( rcode == 0 )
		signal(SIGTRAP,SIG_IGN);
}
static void logChild(PCStr(what),int inc)
{
	if( lTRACE() == 0 || lTRTERSE() )
		return;
	TraceLog("= %d (%s%d:%s)\n",
		NUM_CHILDREN,0<inc?"+":"",inc,what);
}

int cleanup_zombis(int log)
{	int pid;
	int ndead;

	ndead = 0;
	/*
	while( 0 < (pid = NoHangWait()) ){
	*/
	while( 0 < (pid = checkChildAbort1("zomb")) ){
		ndead++;
		dec_nproc(pid);
	}
	if( MAX_DELEGATE && MAX_DELEGATE + num_CC() <= NUM_CHILDREN ){
		int start = time(0);

		sv1tlog("MAX_DELEGATE: MAXIMA=delegated:%d <= %d - %d\n",
			MAX_DELEGATE,NUM_CHILDREN,num_CC());
		TraceLog("MAX_DELEGATE=%d < children=%d+%d\n",
			MAX_DELEGATE,NUM_CHILDREN,num_CC());

		while( MAX_DELEGATE + num_CC() <= NUM_CHILDREN ){
			if( 0 < (pid = NoHangWait()) ){
				ndead++;
				dec_nproc(pid);
			}else{
				if( gotSIGTERM )
					break;
				if( 0 <= StickyReport[0] ){
	 				if( 0 < PollIn(StickyReport[0],1000) ){
						getStickyReports();
			sv1tlog("MAX_DELEGATE: got StickyReports: %d %d\n",
				StickyNaccepted,StickyNserved);
					}
				}else
				sleep(1);
			}
		}
		sv1tlog("MAX_DELEGATE: %d < %d + %d (%d seconds) finished=%d\n",
			NUM_CHILDREN,MAX_DELEGATE,num_CC(),(int)(time(0)-start), pid);
	}
	if( ndead )
		logChild("cleanup",-ndead);
	return ndead;
}


/*
 *	temporary argument to be removed after got
 */
#define TMP_SYM		"++"
#define TMP_SYM_LEN	(sizeof(TMP_SYM)-1)

static int ccsvPid;
int stopcloseR();
int stopSoxThread();
static int killChildren()
{	int nproc;

	nproc = 0;
	if( 0 < myPrivateMASTER ){
		if( Kill(myPrivateMASTER,SIGTERM) == 0 ){
			svlog("Killed private-MASTER [%d]\n",myPrivateMASTER);
			myPrivateMASTER = 0;
			++nproc;
		}
	}
	if( 0 < mySoxPid ){
		int closeSoxSync();
		int closeSoxLocal();
		int pid;

		closeSoxSync();
		closeSoxLocal();
		Kill(mySoxPid,SIGTERM);
		for(;;){
			pid = TimeoutWait(3.0);
			if( pid <= 0 )
				break;
			if( pid == mySoxPid ){
				mySoxPid = 0;
				break;
			}else	dec_nproc(pid);
		}
	}
	if( 0 < actthreads() ){
		stopcloseR();
		stopSoxThread();
	}
	if( 0 < ccsvPid ){
		int xpid;
		Kill(ccsvPid,SIGTERM);
		xpid = TimeoutWait(3.0);
		svlog("-Ecc Killed CCSV %d %d\n",ccsvPid,xpid);
		if( xpid == ccsvPid ){
			ccsvPid = 0;
		}
	}
	return nproc;
}

int ServSock();
int isServSock(int sock);
static void send_socks(PVStr(socks),int cpid);
void LOG_checkAged(int renew);
int PortLockFd();
int spawnv_self(int aac,const char *aav[]);
int recv_file(int desc);
int numServPorts();
static struct {
	const char *RES_ORDER;
	const char *RESOLV;
} OrigEnv;
extern int CFI_SHARED_FD;
int close_shared();
static void resetEnvFds(){
	int fv[32];
	int fi,fo;
	int vfd = -1;
	int sfd = -1;

	if( RESOLV_UNKNOWN ){
		/* to retry detection of resolvers after restart */
		int ei;
		int eo = 0;
		const char *e1;
		for( ei = 0; e1 = environ[ei]; ei++ ){
			if( !OrigEnv.RES_ORDER && parameq(e1,"RES_ORDER") )
				continue;
			if( !OrigEnv.RESOLV    && parameq(e1,"RESOLV") )
				continue;
			if( strheadstrX(e1,"DYLIB_",0) )
				continue;
			if( strheadstrX(e1,"CFI_SHARED_",0) )
				continue;
			environ[eo++] = (char*)e1;
		}
		environ[eo] = 0;
	}
	if( 0 <= CFI_SHARED_FD ){
		close(CFI_SHARED_FD);
		CFI_SHARED_FD = -1;
	}
	if( lFILEDESC() ){
		dumpFds(stderr);
	}
	vfd = close_svstat();
	sfd = close_shared();

	if( lFILEDESC() ){
		int ei;

		fprintf(stderr,"--{F} RESTART [%d][%d]\n",sfd,vfd);
		dumpFds(stderr);

		fprintf(stderr,"--{F} available file descriptors:\n");
		for( fi = 0; fi < elnumof(fv); fi++ ){
			fv[fi] = dup(0);
			fprintf(stderr,"[%2d]",fv[fi]);
		}
		fprintf(stderr,"\n");
		for( fi = 0; fi < elnumof(fv); fi++ )
			close(fv[fi]);

		if( 2 <= LOGLEVEL )
		for(ei=0;environ[ei];ei++)
			fprintf(stderr,"--{F}[%d]%s\n",ei,environ[ei]);
	}
}

int closeNullFd();
int closePrivatePorts();
int closeLOG_UDPsock();
extern int RunningAsService;
static int isService;
static int ServerPid;
int log_fprintf(FILE *fp,PCStr(fmt),...);

static int inSIGHUP;
static void sigHUPX(int sig,PCStr(execpath),const char *argv[])
{	const char *nargv[MAX_ARGC]; /**/
	const char *arg;
	CStr(path,1024);
	CStr(port,PORTSSIZE);
	/*
	CStr(nchild,32);
	*/
	CStr(nchild,1024);
	CStr(wd,1024);
	int ai,ac,portset;
	int nproc;
	CStr(orig_av0,1024);
	int svclose_restart = 0;

 if( execpath == NULL ){
	strcpy(path,EXEC_PATH);
	wordScan(main_argv[0],orig_av0);/*av[0] may be expanded for ps_title*/
 }

	if( getpid() != ServerPID ){
		fprintf(stderr,"\nDeleGate[%d] got SIGHUP(%d) for server=%d\n",
			getpid(),sig,ServerPID);
		exit(1);
	}
	if( iamPrivateSox() ){
		extern int SoxImmRestart;
		SoxImmRestart = 1;
		sv1log("## ignore SIGHUP in PrivateSox (%d)\n",ServerPID);
		return;
	}

	signal(SIGHUP,SIG_IGN);
	alarm(0);
	sigsetmask(0);
	LOG_init_enable = 1;

	dumpCKey(1);

 {
 CStr(lpath,1024);
 CStr(host,MaxHostNameLen);
 FILE *logfp;
 int port;
 int lsock;

 sprintf(lpath,"/tmp/delegate/restart/%d",getpid());
 if( logfp = fopen(lpath,"r") ){
	CStr(buf,1024);
	if( fgets(buf,sizeof(buf),logfp) != NULL )
	if( Xsscanf(buf,"%[^:]:%d",AVStr(host),&port) == 2 ){
		fclose(logfp);
		lsock = client_open("LOG","http",host,port);
		fprintf(stderr,"#### %s : %d [%d]\n",host,port,lsock);
		IGNRETP write(lsock,"(^_^)\n",6);
		sleep(5);
		close(lsock);
	}
 }
 }

	sv0log("DeleGate SERVER RESTART: %s\n",
		sig==0?"timeout":"caught SIGHUP");

 {
 int fd;
 fd = openNull(0);
 sv0log("NUM_HUPS=%d FD=[%d]\n",NUM_HUPS+1,fd);
 if( 0 < fd )
 close(fd);
 }

	if( logMMap && logMMap->m_fp ){
		/* it should be reopened after exec() */
		setCloseOnExec(fileno(logMMap->m_fp));
	}
	closeLOG_UDPsock();
	closePrivatePorts();
	printServPort(AVStr(port),"-P",1);

	if( sig == -1 ){
		sv0log("REOPEN PORT: %s\n",port);
		printServPort(AVStr(port),"-P",0);
		closeServPorts();
		svclose_restart = 1;
	}
	sv1log("## SIGHUP passing %s\n",port);

	if( !INHERENT_fork() ){ /* try not to kill active Sticky ... */
		sv1log("## StickyActive=%d\n",StickyActive);
		if( 0 < StickyActive ){
			int ti,tx;
			int shlock,rcode,etime;
			int nwait;

			tx = 15;
			shlock = PortLockFd();
			if( 0 <= shlock ){
				/* block new request to be accepted by Sticky */
				rcode = lock_exclusiveTO(shlock,tx*1000,&etime);
				sv1log("## StickyActive lockout=%d (%d)\n",
					rcode,etime);
			}
			for( ti = 0; 0 < StickyActive && ti < tx; ti++ ){
				cleanup_zombis(0);
				nwait = StickyToWait();
				sv1log("## StickyActive=%d %d/%d (%d)\n",
					StickyActive,ti+1,tx,nwait);

				if( nwait == 0 ){
					sv1log("## No Sticky to be waited\n");
					break;
				}
				sleep(1);
			}
		}
		/* ServPorts should be passed (duplicated) to the restarted
		 * DeleGate keeping the backlog...
		 */
		if( !svclose_restart ){
		printServPort(AVStr(port),"-P",-1);
		}
		/*
		closeServPorts();
		*/
	}

	nproc = killChildren();
	StickyKill(SIGHUPTERM);

	LOG_deletePortFile();
	deleteWORKDIR();
	if( originWD ){ IGNRETZ chdir(originWD); }

	LOG_checkAged(1);
	sv0log("DeleGate SERVER RESTART in progress...\n");
	strcpy(wd,"?");
	IGNRETS getcwd(wd,sizeof(wd));
	sv0log("PWD: %s\n",wd);
if( execpath == NULL )
	sv0log("EXEC: %s\n",path);
	LOG_closeall();

	close(StickyReport[0]); StickyReport[0] = -1;
	close(StickyReport[1]); StickyReport[0] = -1;
	/*
	closeNullFd();
	*/

	if( 0 < nproc || NUM_CHILDREN )
		msleep(100);
	cleanup_zombis(0);
	sprintf(nchild,"HUPENV=%d/%d/%d",++NUM_HUPS,NUM_CHILDREN,LOG_initFd);

 if( execpath != NULL ){
	const char *ppid;
	CStr(dgpid,32);
	CStr(dgargs,1024);
	/* maybe restarting DeleGate via shell script or so.  */
	ppid = getenv("DELEGATE_PID");
	sv1log("#### parent DELEGATE_PID=%s\n",ppid?ppid:"NULL");
	if( ppid == NULL || atoi(ppid) != getpid() ){
		/* the shell (parent) process may be waiting exit code
		 * from this process rathar than "exec" this process.
		 */
		if( INHERENT_fork() ){
			if( Fork("execmain") != 0 )
				exit(0);
		}
	}
	sprintf(dgpid,"DELEGATE_PID=%d",getpid());
	putenv(dgpid);
	sprintf(dgargs,"DELEGATE_ARGS=%s %s",port,nchild);
	putenv(dgargs);
	sv1log("#### %s %s\n",dgpid,dgargs);
	resetEnvFds();
	Execvp("execmain",execpath,argv);
	Finish(-1);
 }

	nargv[0] = orig_av0;
	ac = 1;
	portset = 0;

	if( getEnv(P_DGROOT) == 0 ){
		CStr(dgroot,1024);
		sprintf(dgroot,"DGROOT=%s",DELEGATE_DGROOT);
		nargv[ac++] = dgroot;
		sv1log("## set %s\n",dgroot);
	}

	for( ai = 1; ai < main_argc; ai++ ){
		if( elnumof(nargv)-3 <= ac ){
			sv1log("#### ignored too many args [%d -]\n",ac);
			break;
		}
		arg = main_argv[ai];
		if( arg[0]=='-' && arg[1]=='-' )
			continue;
		if( strncmp(arg,TMP_SYM,TMP_SYM_LEN) == 0 )
			continue;
		if( strncmp(arg,"HUPENV=",7) == 0 )
			continue;
		if( arg[0]=='-' && arg[1]=='P' ){
			if( !portset ){
				portset = 1;
				nargv[ac] = port;
			}
		}else	nargv[ac] = (char*)arg;
		ac++;
	}
	if( !portset )
		nargv[ac++] = port;
	nargv[ac++] = nchild;
	nargv[ac] = 0;

	if( !INHERENT_fork() ){
		sprintf(nchild,"HUPENV=%d/%d/%d",NUM_HUPS,NUM_CHILDREN,-1);

		if( isatty(fileno(stdin)) ){
			int fd,logfd,ssfd,rcode;
			int bgpid,pid,si;
			IStr(svpid,128);
			IStr(isserv,32);
			printf("NUM_HUPS=%d FD=[%d]\n",NUM_HUPS+1,
				dup(fileno(stderr)));

			logfd = curLogFd();
			ssfd = SessionFd();
			si = 0;
			for( fd = 0; fd < FD_SETSIZE; fd++ ){
				if( fd == logfd
				 || fd == config_FD
				 || fd == ssfd
				 || fd == fileno(stdin)
				 || fd == fileno(stdout)
				 || fd == fileno(stderr) )
					continue;
				if( isServSock(fd) ){
					setrsvdsock(si++,fd);
					continue;
				}
				/*
				rcode = setCloseOnExec(fd);
				*/
				rcode = close(fd);
			}
			if( logfd != fileno(stdout) )
			if( logfd != fileno(stderr) )
				close(logfd);

			/*
			setserversock(ServSock());
			*/
			if( isWindowsCE() ){
				int doDeleteOnExit();
				doDeleteOnExit();
			}
			log_fprintf(stderr,"----RESTARTING s%X H%d %s [%d]\n",
				isService,NUM_HUPS,DELEGATE_ver(),ServerPid);
			if( isService ){
				sprintf(isserv,"_isService=%d",0x2|isService);
				nargv[ac++] = isserv;
				nargv[ac] = 0;
			}
			if( NUM_HUPS <= 1 ){
				sprintf(svpid,"_ServerPid=%d",getpid());
				nargv[ac++] = svpid;
				nargv[ac] = 0;
			}
			bgpid = Spawnvp("HUP",path,nargv);
			closeServPorts();
			if( NUM_HUPS <= 1 ){
				signal(SIGHUP,(vfuncp)sigHUPX);
				while( pid = wait(0) ){
					if( pid == bgpid ){
						break;
					}
				}
			}else{
				/* wait chld to get environment ? */
				sleep(5);
			}
			/*
			Execvp("HUP",path,nargv);
			*/
		}else{
			int pid;
			extern int LastCpid;
			int wi;

			if( !svclose_restart ){
			ac = 0;
			nargv[ac++] = "-Fsleep"; /* to hold socket */
			nargv[ac++] = "10";
			nargv[ac] = 0;
			pid = spawnv_self(ac,nargv);

			sprintf(nchild,"HUPENV=%d/%d/%d/",
				NUM_HUPS,NUM_CHILDREN,-1);
			send_socks(TVStr(nchild),LastCpid);
			}

			/*
			nargv[0] = "-Fkill-hup";
			nargv[1] = port;
			nargv[2] = 0;
			spawnv_self(2,nargv);
			*/
			inSIGHUP = 1;
			ac = 0;
			nargv[ac++] = "-Fkill-hup";
			nargv[ac++] = port;
			if( !svclose_restart ){
			nargv[ac++] = nchild;
			}
			nargv[ac] = 0;

			sv1log("RESTART %s ...\n",port);
			spawnv_self(ac,nargv);
			sv1log("RESTART WAITING to be STOPPED ...\n");
			/*
			sleep(15);
			*/
			for( wi = 0; wi < 150; wi++ ){
				if( terminating == 999 )
					break;
				sv1log("[%d] WAITING to be STOPPED (%d)%d\n",
					getthreadid(),wi,terminating);
				msleep(100);
			}
			if( terminating == 999 ){
				sv1log("[%d] STOPPED (%d)\n",getthreadid(),wi);
			}else
			sv1log("RESTART ERROR: not have been STOPPED\n");
		}
		Finish(0);
	}

	resetEnvFds();
	Execvp("sigHUP",path,nargv);
}
int recv_sock(int spid,int ssock,int closesrc);
int send_sock(int dpid,int fd,int closesrc);
static void recv_socks(){
	int pid,si,sock,fd;
	const char *dp;
	CStr(num,32);

	if( ME.me_src_socks[0] == 0 )
		return;

	sv1log("#### recv_socks {%s}\n",ME.me_src_socks);
	dp = ME.me_src_socks;
	dp = wordscanY(dp,AVStr(num),sizeof(num),"^,");
	if( *dp == ',' )
		dp++;
	pid = atoi(num);

	for( si = 0; *dp; si++ ){
		dp = wordscanY(dp,AVStr(num),sizeof(num),"^,");
		if( *dp == ',' )
			dp++;
		sock = atoi(num);
		if( sock <= 0 )
			break;
		fd = recv_sock(pid,sock,1);
		sv1log("#### recv_sock(pid=%d,fd=%d) port=%d\n",
			pid,sock,sockPort(fd));
	}
	ME.me_src_socks[0] = 0;
}
static void send_socks(PVStr(socks),int cpid)
{	refQStr(dp,socks); /**/
	int fd,sock;

	sprintf(dp,"%d",cpid);
	dp += strlen(dp);

	for( fd = 0; fd < FD_SETSIZE; fd++ ){
		if( !isServSock(fd) )
			continue;
		sock = send_sock(cpid,fd,1);
		sprintf(dp,",%d",sock);
		dp += strlen(dp);
		sv1log("#### send_sock(pid=%d,fd=%d) port=%d\n",
			cpid,sock,sockPort(fd));
	}
	sv1log("#### send_socks {%s}\n",socks);
}
static void sigHUP(int sig)
{
	sigHUPX(sig,NULL,NULL);
}
void doSIGHUP(){ sigHUP(0); }
void DELEGATE_execmain(PCStr(command))
{	CStr(argb,1024);
	const char *av[128]; /**/
	int ac;

	ac = decomp_args(av,128,command,AVStr(argb));
	sigHUPX(0,av[0],av);
}

extern int  AF_UNIX_DISABLE;
/*
 *	This function should be called after the process's real OWNER
 *	is set so that the directry is writable for the process itself.
 */
int IsSolaris();
static void mkdirForSolaris()
{
	/* this was for Solaris2.4 or older (3.0.35)
	if( IsSolaris() )
		AF_UNIX_DISABLE = 1;
	*/
}

#define LOAD_SYM	"-="
#define LOAD_SYM_LEN	(sizeof(LOAD_SYM)-1)

extern int DEBUG_FILE;

void makeWorkFile(PVStr(path),PCStr(type),PCStr(file));
static int subst_argurl(PCStr(base),PCStr(url),PCStr(arg),PVStr(xarg))
{	CStr(aurl,1024);
	CStr(path,1024);
	CStr(param,1024);
	FILE *sfp,*dfp;
	int size;

	sfp = openPurl(base,url,AVStr(aurl));
	if( sfp == NULL ){
		ERRMSG("Cannot load: %s\n",url);
		return -1;
	}

	param[0] = 0;
	Xsscanf(arg,"%[^=]",AVStr(param));
	makeWorkFile(AVStr(path),"mirror",param);

	dfp = dirfopen(param,AVStr(path),"w");
	if( dfp == NULL ){
		ERRMSG("Cannot create: %s\n",path);
		fclose(sfp);
		return -1;
	}

	copyfile1(sfp,dfp);
	fclose(sfp);
	fflush(dfp);
	size = file_size(fileno(dfp));
	fclose(dfp);

	sprintf(xarg,"%s=%s",param,path);
	/*fprintf(stderr,"Argument substituted [%s] -> [%s](%dbytes)\n",
		arg,xarg,size);*/
	return 0;
}

/* inherited descriptors to be interprete in main()
 * -IxN
 * -Ix-filename
 *
 * -IA ... +=script
 * -IO ... stdout.log (to service process on Win32)
 * -II ... InitLog
 * -IC ... write resutl code when initialization finished (pipe)
 * -IS ... SvStat for load average
 */
static void getInheritedFds(PCStr(arg)){
	int fd;
	int locked;
	const char *dp;
	int xfd;

	fd = atoi(arg+1);
	switch( arg[0] ){
		case 'O': /* stdout.log */
			xfd = fd;
			fd = recv_file(xfd);
			if( 0 <= fd ){
				if( fileno(stdout) < 0 ){
				}else{
					dup2(fd,fileno(stdout));
				}
				if( fileno(stderr) < 0 ){
				}else{
					dup2(fd,fileno(stderr));
				}
			}
			break;
		case 'I':
			if( LOG_initFd != fd ){
				LOG_initFd = fd;
				if( 0 <= LOG_initFd ){
					LOG_init_enable = 1;
					locked = lock_exclusiveNB(LOG_initFd);
				}
			}
			break;

		case 'S':
			set_svstat(fd);
			if( dp = strchr(arg,':') ){
				set_svname(dp+1);
			}
			set_svtrace(1);
			break;
	}
	sv1log("*** inherited -I%s [%d]\n",arg,fd);
}

int scan_yyopts(Connection *Conn,PCStr(arg));
void scanServPortX(PCStr(portspecs),int init);
void scanServPort(PCStr(portspecs));
/*
extern int lock_ext;
const char *scan_arg1(PCStr(ext_base),PCStr(arg))
*/
const char *scan_arg1(Connection *Conn,PCStr(ext_base),PCStr(arg))
{	const char *list;
	const char *val;
	int num;
	const char *as;
	const char *dp;
	CStr(xarg,1024);

	if( ext_base ){
		if( param_lock(PARAM_SCRIPT,arg,&arg) < 0 ){
			return "";
		}
	}

	if( dp = strchr(arg,'=') ){
		dp++;
		if( strncmp(dp,LOAD_SYM,LOAD_SYM_LEN) == 0 ){
			dp += LOAD_SYM_LEN;
			if( subst_argurl(ext_base,dp,arg,AVStr(xarg)) == 0 )
				arg = stralloc(xarg);
		}
	}

	/* inherited on SIGHUP */
	if( strncmp(arg,"HUPENV=",7) == 0 ){
		Xsscanf(arg+7,"%d/%d/%d/%s",&NUM_HUPS,&NUM_CHILDREN,
			&LOG_initFd,AVStr(ME.me_src_socks));
	}else
	if( include_next ){
		include_next = 0;
		load_script(NULL,ext_base,arg);
	}else
	if( strneq(arg,"+=enc:",6) ){
		/* short-cut bypassing tmpfile for URLget(enc:) */
		load_encrypted(NULL,ext_base,arg+6);
	}else
	if( strncmp(arg,INC_SYM,INC_SYM_LEN) == 0 ){
		if( arg[INC_SYM_LEN] == 0 )
			include_next = 1;
		else	load_script(NULL,ext_base,arg+INC_SYM_LEN);
	}else
	if( strncmp(arg,"-e",2) == 0 ){
		putenv(StrAlloc(arg+2));
	}else
	if( list = strchr(arg,'=') ){
		if( !dont_check_param ){
			check_param(arg,1);
		}

		list++;
		if( strncmp(list,INC_SYM,INC_SYM_LEN) != 0 )
		if( dp = strstr(arg,":+=") )
			list = dp+1;
		else
		if( dp = strstr(arg,",+=") )
			list = dp+1;

		if( strncmp(list,INC_SYM,INC_SYM_LEN) == 0 ){
			CStr(name,128);
			extern int SCRIPT_ASIS;
			int asis;

			QStrncpy(name,arg,list-arg+1);
			asis = SCRIPT_ASIS;
			SCRIPT_ASIS = script_asis(name);
			load_script(name,ext_base,list+INC_SYM_LEN);
			SCRIPT_ASIS = asis;
		}else
		if( ext_base != NULL )
			DELEGATE_addEnvExt(arg);
	}else
	if( strncmp(arg,PrivateMasterOwner,strlen(PrivateMasterOwner)) == 0 ){
		PrivateMasterOwnerPort[0] = 0;
		Xsscanf(arg+strlen(PrivateMasterOwner),"%[^)]",AVStr(PrivateMasterOwnerPort));
	}else
	switch( arg[0] ){
	    case '-':
	    val = &arg[2];
	    switch( arg[1] ){
		case 'R':
			if( arg[2] && strchr(arg+2,':') ){
				/* -Rhost:port to accept at remote host:port */
				break;
			}
		case 'B':
		case 'E':
		case 'D':
		case 'L':
		case 'd':
		case 'l':
		case 'n':
		case 'p':
		case 't':
		case 'v':
		case 'w':
		case 'x':
			setDebugX(Conn,arg,0);
			break;
		case 'y':
			scan_yyopts(Conn,arg);
			break;
		case 'i':
			LOG_type |= L_REINIT;
			break;

		case 'F':
			/* function selector */
			break;

		case 'P': /* server port */
			if( *DELEGATE_DGROOT == 0 ){
				/*
			 	 * v9.9.13 fix-141028c, making LOGFILE must
			 	 * be suppressed until ${DGROOT} is set.
				 * This case happens if -P is specified in
				 * the default conf.  It should be cared
				 * more generally in log.c:open_logtmpfile().
			 	 */
			}else
			if( strstr(DELEGATE_DGROOT,"${") != 0 ){
				/* v9.9.13 fix-141031b, not substituted yet,
				 * seems occur when invoked by Windows GUI
				 * under the above condition (141028c).
				 */
			}else
			svlog("PORT> %s\n",arg);

			/* this code seems to be introduced at 4.0.4 maybe for
			 * passing server-socket to Sticky process on Win32,
			 * but seems not to have been used...
			 */{int sock;
			    if( 0 < (sock = getserversock()) ){
				char *ap = (char*)malloc(strlen(arg)+16);
				defQStr(dp); /*alloc*//**/
				arg = (char*)memcpy(ap,arg,strlen(arg)+1);
				setQStr(dp,(char*)arg,strlen(arg)+16);
				val = &arg[2];
				if( (dp = strchr(arg,'/')) == 0 )
					dp = (char*)&arg[strlen(arg)];
				sprintf(dp,"/%d",sock);
			    }
			}
			if( strncmp(arg,"-P0/",4) == 0 )
				IamPrivateMASTER = getppid();
			scanServPort(val);
			break;

		case 'Q':
			scanServPortX(arg+2,0);
			break;

		case 'c':
			switch( arg[2] ){
			    case 'e': pushEnv(P_CHARCODE,"EUC"); break;
			    case 'j': pushEnv(P_CHARCODE,"JIS"); break;
			    case 's': pushEnv(P_CHARCODE,"SJIS"); break;
			}
			break;

		case 'C':
			switch( arg[2] ){
				case '+': LOG_type2 |= L_RCONFIG; break;
				default:
			DELEGATE_CONFIG = stralloc(val);
					break;
			}
			break;

		case 'I':
			getInheritedFds(arg+2);
			break;

		case 'b':
			/* go background immediately */
			break;
		case 'f':
			switch( arg[2] ){
			case 'v': LOG_type |= L_CONSOLE; break;
			}
			LOG_type |= L_FG;
			break;
		case '1':
			LOG_type |= L_SYNC | L_TTY;
			break;
		/*
		case 's':
			LOG_type |= L_FORK;
			break;
		*/

		case 's':
			LOG_type2 |= L_STRICT;
			switch( arg[2] ){
				case 'x': LOG_type2 |= L_SECUREEXT; break;
			}
			break;


		case 'S':
			if( SIGCHLD < 0 ){
				fprintf(stderr,"#### -S NOT SUPPORTED: %s\n",
					"SIGCHLD signal is not available");
				break;
			}
			LOG_type |= L_SIGCHLD;
			break;
		case 'T': /* trace / trap */
			if( !INHERENT_ptrace() ){
				fprintf(stderr,"#### -T NOT SUPPORTED: %s\n",
					"ptrace system call is not available");
				break;
			}
			LOG_type |= L_TRACE | L_SIGCHLD;
			for( as = arg+2; *as; as++ ){
			    switch( *as ){
				case 'x': LOG_type |= L_NOEXEC; break;
				case 's': LOG_type &= ~L_SIGCHLD; break;
				case 't': LOG_type |= L_TRTERSE; break;
				case 'd': LOG_type |= L_TRVERB; break;
			    }
			}
			break;

		case 'u':
			/* force to fork a private SUDO */
			break;

		case 'r':
			ME.me_restart = 1;
			break;
		case 'X':
			switch( arg[2] ){
				case 'i':
				default:
					LOG_bugs |= L_IMMEXIT;
					break;
			}
			break;

		case 'a':
			LOG_type |= L_TTY | L_FG;
			ME.me_accsimul = 1;
			switch( arg[2] ){
				case 'b': LOG_type &= ~(L_TTY|L_FG); break;
			}
			break;
		}
		break;
	}
	LOG_VERBOSE = lVERB() ? 1 : 0;
	return arg;
}

static scanListFunc scanopt1(PCStr(arg),Connection *Conn)
{
	scan_arg1(Conn,NULL,arg);
	return 0;
}
void scan_DGOPTS(Connection *Conn,PCStr(arg))
{
	scan_ListL(arg,';',1,scanListCall scanopt1,Conn);
}
int add_condarg(PCStr(arg));
void encrypt_args();

#define scan_args(ac,av) DELEGATE_scan_argsX(Conn,ac,av)
int DELEGATE_scan_argsX(Connection *Conn,int ac,const char *av[])
{	int ai;
	int dgopt;
	const char *arg;
	int ign = 0;

	if( lVERB() || lARGDUMP() ){
		for( ai = 0; ai < ac; ai++ )
			fprintf(stderr,"[%d] %s\n",ai,av[ai]);
	}

	dgopt = 0;
	for( ai = 0; ai < ac; ai++ )
	{	arg = av[ai];

		if( streq(arg,"END") ){
			break;
		}
		if( streq(arg,"IGN++") ){
			ign++;
		}else
		if( streq(arg,"IGN--") ){
			ign--;
		}
		if( 0 < ign ){
			continue;
		}

		if( add_condarg(arg) )
			continue;

		/* ignoring options for -Ffunction */
		if( Fopt && ai < Fopt ){
			/* delegated -dgopt -dgopt ... -Ffunc -fopt -fopt ... */
		}else
		if( Fopt || isFunc ){
			/* ... -fopt -fopt -- -dgopt -dgopt ... */
			if( strcmp(arg,TMP_SYM) == 0 ){
				dgopt = 1;
				continue;
			}
			if( dgopt == 0 && arg[0] == '-' ){
				if( strchr("P",arg[1]) == 0 )
					continue;
			}else
			if( strchr(arg,'=') == 0 ){
				continue;
			}
		}
		av[ai] = scan_arg1(Conn,NULL,av[ai]);
	}

	if( lVERB() )
		LOG_VERBOSE = 1;

	encrypt_args();
	setupForSolaris();
	return ac;
}

/*
 * redirect output from child process to standard out/err to logfile.
 */
FILE *LOG_open(Logfile *logF);
Logfile *LOG_create(PCStr(proto),PCStr(filters),PCStr(logform),PCStr(pathform),PCStr(mode),int dolock);;

int log_fprintf(FILE *fp,PCStr(fmt),...){
	IStr(date,128);
	VARGS(16,fmt);

	StrftimeLocal(AVStr(date),sizeof(date),"%Y/%m/%d-%H:%M:%S",time(0),0);
	fprintf(fp,"%s [%d] ",date,getpid());
	fprintf(fp,fmt,VA16);
	fflush(fp);
	daemonlog("E",fmt,VA16);
	return 0;
}

int stdfds[3] = {-99,-99,-99};
void setSTDLOG()
{
	int fis[3] = {-9,-9,-9};
	int nfd;
	FILE *nfp;

	if( stdfds[0] < 0 ){
		fis[0] = file_is(0);
		fis[1] = file_is(1);
		fis[2] = file_is(2);
		sv1log("----STDIO fd[%d %d %d] is[%d %d %d]\n",
			stdfds[0],stdfds[1],stdfds[2],fis[0],fis[1],fis[2]);

		if( isWindows() )
		if( nulSTDIN() )
		if( fileno(stdin) == -2 && fis[0] == 0 ){
			/* this causes service restart ... ??? */
			if( 0 < (nfd = open("nul",0)) ){
				dup2(nfd,0);
				close(nfd);
				nfd = 0;
			}
			if( nfd == 0 )
			if( nfp = fdopen(0,"r") ){
				setStdio(stdin,nfp);
				sv1log("----STDIO set stdin[%d]\n",
					fileno(stdin));
			}else{
				sv1log("----STDIO cannot open[0]\n");
				close(nfd);
			}
		}
	}

	LOG_open(LOG_create("stdout",LF_STDOUTLOG,"-",DELEGATE_STDOUTLOG,"a",0));

	if( !enbugNOSTDERR() )
	if( stdfds[1] == -2 && fis[1] == 0 ){
		/* Win32 service */
		if( fileno(stdout) == -2 && file_isreg(1) ){
			if( nfp = fdopen(1,"a") ){
				setStdio(stdout,nfp);
			}
		}
		if( fileno(stderr) == -2 && file_isreg(2) ){
			if( nfp = fdopen(2,"a") ){
				setStdio(stderr,nfp);
				setbuffer(stderr,0,0);
			}
		}
		log_fprintf(stderr,"----STDOUTLOG 1 stderr\n");
		log_fprintf(stdout,"----STDOUTLOG 2 stdout\n");
				/* ^^^ to activate stderr ?? */
		log_fprintf(stderr,"----STDOUTLOG 3 stderr\n");
		log_fprintf(stderr,"----STDOUTLOG=%s %s ----\n",
			DELEGATE_STDOUTLOG,DELEGATE_ver());
		log_fprintf(stderr,"----STDOUTLOG nulSTDIN()=%d\n",nulSTDIN());
	}
	/*
	LOG_open(LOG_create("stdout","STDOUTLOG","-","stdout.log","a",0));
	*/
}
/*
setSTDLOG()
{	FILE *logfp;
	int logfd;

	logfp = LOG_openLogFile("stdout.log","a");
	if( logfp != NULL ){
		sv1log("Redirect {stdout,stderr} to LOGDIR/stdout.log\n");
		logfd = fileno(logfp);
		dup2(logfd,fileno(stderr));
		dup2(logfd,fileno(stdout));
	}
}
*/

void put_identification(FILE *out);
int askADMIN(FILE *out,FILE *in,PVStr(admin),int size);
int checkCACHEDIR(Connection *Conn);
int CTX_evalMountCond(Connection *ctx,PCStr(opts),PCStr(user),PCStr(chost),int cport,PCStr(ihost),int iport);

void putBLDsign(FILE *fp);
void putSSLver(FILE *fp);
void putZLIBver(FILE *fp);
int checkVer();
void openServPorts();
void put_myconf(FILE *out);

/* moved to caps.c */
void setup_exeid(Connection *Conn);
int beDaemon(Connection *Conn,int isService,double waitBG);
void syncDaemon(int dmsync);
static double waitBG = 3;
int WinServ;

int fromSSH();
int fromCGI(){
	if( getenv("REMOTE_ADDR") )
		return 1;
	return 0;
}

int dumpCKeyParams(int mac,const char *av[],PVStr(abuf));
int closeServPortsX(int clear);

static int START_TIMEP; /* start time of this DeleGate (config. time) */
extern int START_TIME1;
extern const char *hostmatch_withauth;

static void scan_serverspec(Connection *Conn,PCStr(serverspec),PVStr(url),PVStr(hostlist))
{	const char *hl;
	CStr(map,256);
	CStr(type,16);
	refQStr(op,url); /**/

	/*
	 * strip "URI[:-:srcList]" postfix first
	 */
	if( hl = strstr(serverspec,":-:") ){
		strcpy(url,serverspec);
		hl = strstr(url,":-:");
		truncVStr(hl);
		strcpy(hostlist,hl+3);
	}else{
		strcpy(url,serverspec);
		strcpy(hostlist,"");
	}
	if( strchr(url,':') == NULL )
	{
		if( op = strstr(url,",-") ){
			/* SERVER=telnet,-in -> SERVER=telnet://-/,-in */
			Strins(AVStr(op),"://-/");
		}else
		strcat(url,"://-/");
	}

	/* ex. SERVER=telnet://host,-in */
	if( op = strstr(url,",-") ){
		wordscanY(op+2,AVStr(type),sizeof(type),"^,(:");
		/*
		Xsprintf(TVStr(hostlist),",%s",hostmatch_withauth);
		*/
		if( hostlist[0] )
			strcat(hostlist,",");
		strcat(hostlist,hostmatch_withauth);
		sprintf(map,"{%s}:vp_%s:*:%s",url,type,hostlist);
		sv1log("XSERVER: %s\n",map);
		scan_CMAP2(Conn,"XSERVER",map);
	}

	/* ex. SERVER=sockmux:commin@/tmp/com1 */
	if( strstr(url,"://") == 0 )
	if( op = strstr(url,":") ){
	const char *dp = wordscanY(op+1,AVStr(type),sizeof(type),"^@:/?");
		if( *dp == '@' )
		if( type[0] ){
			sprintf(map,"{%s}:vp_%s:*:%s",url,type,hostlist);
			sv1log("XSERVER: %s\n",map);
			scan_CMAP2(Conn,"XSERVER",map);
			Strins(QVStr(op+1,url),"//-/");
			/* sockmux://-/commin@/tmp/...  */
		}
	}
}
/*
 *  DEST=host:port:srcList     -> SERVER=tcprelay://host:port,-in
 *  DEST=host:port/udp:srcList -> SERVER=udprelay://host:port,-in
 */
static void scan_DEST(Connection *Conn,PCStr(dest))
{	CStr(destb,MaxHostNameLen);
	const char *proto;
	const char *av[4]; /**/
	const char *dp;
	CStr(map,256);

	lineScan(dest,destb);
	av[2] = "*";
	if( list2vect(destb,':',3,av) < 2 ){
		sv1log("error DEST=%s\n",dest);
		return;
	}
	proto = "tcprelay";
	if( (dp = strchr(av[1],'/')) || (dp = strchr(av[1],'.')) ){
		truncVStr(dp); dp++;
		if( streq(dp,"udp") ) 
			proto = "udprelay";
	}
	sprintf(map,"{%s://%s:%s}:vp_in:*:%s",proto,av[0],av[1],av[2]);
	sv1log("DEST=%s -> XSERVER: %s\n",dest,map);
	scan_CMAP2(Conn,"XSERVER",map);
}

int addServPorts(PCStr(portspec),PCStr(servspec),Connection *Conn);
static int server0(Connection *Conn,PCStr(serverspec)){
	IStr(serverurl,1024);
	IStr(hostlist,1024);
	scan_serverspec(Conn,serverspec,AVStr(serverurl),AVStr(hostlist));
	/*
	must ignore "-in,:-:"
	if( hostlist[0] ){
		addServPorts(hostlist,serverurl,Conn);
	}
	*/
	return 0;
}
static void Scan_SERVER0(Connection *Conn){
	scanEnv(Conn,P_SERVER,(scanPFUNCP)server0);
}
static int server2(Connection *Conn,PCStr(serverspec),PVStr(serverurl))
{	CStr(hostlist,1024);
	CStr(chost,MaxHostNameLen);
	CStr(ihost,MaxHostNameLen);
	int cport,iport;
	int match;
	const char *user;

	/*
	scan_serverspec(serverspec,serverurl,hostlist);
	*/
	scan_serverspec(Conn,serverspec,AVStr(serverurl),AVStr(hostlist));
	if( hostlist[0] == 0 ){
		strcpy(Serverurl0,serverurl);
		return 0;
	}
	if( !Conn->cl.p_connected )
		return 0;

	iport = gethostNAME(ClientSock,AVStr(ihost));
	cport = getClientHostPort(Conn,AVStr(chost));
	user = getClientUser(Conn);
	if( user == NULL )
		user = "-";

	/* to setup for matching SERVER=url:-:-Pxxxx */
	HL_setClientIF(ihost,iport,0);

	match = CTX_evalMountCond(Conn,hostlist,user,chost,cport,ihost,iport);

	if( match ){
		Verbose("OK [%s] [%s][%s]\n",serverurl,chost,hostlist);
		scan_SERVER(Conn,serverurl);
		Conn->cl.p_bound = 1;
		return 1;
	}else{
		Verbose("NO [%s] [%s][%s]\n",serverurl,chost,hostlist);
		return 0;
	}
}

static int server1(Connection *Conn,PCStr(serverspec))
{	CStr(serverurl,1024);

	if( Conn->cl.p_bound )
		return 1;

	if( server2(Conn,serverspec,AVStr(serverurl)) )
		return 1;

	return 0;
}

static int REUSE_ENV();
static const char *Scan_SERVER(Connection *Conn)
{	const char *proto;
	CStr(url,1024);

	setQStr(Serverurl0,url,(UTail(url)-url)+1);
	setVStrEnd(Serverurl0,0);
	scanEnv(Conn,P_SERVER,(scanPFUNCP)server1);

	if( !Conn->cl.p_bound && Serverurl0[0] )
		if( scan_SERVER(Conn,Serverurl0) == 0 )
			Exit(-1,"ERROR: %s=%s\n",P_SERVER,Serverurl0);

	/* V8.0.1 SERVER=http by default and SERVER=delegate to be Generalist */
	/* V8.0.4 SERVER=delegate with REMITTABLE={http*} by default */
	if( strcmp(DFLT_PROTO,"delegate") == 0 ){
		DFLT_PROTO[0] = 0;
		DFLT_HOST[0] = 0;
	}else
	if( getEnv(P_SERVER) == NULL ){
		/*
		scan_SERVER(Conn,"http");
		*/
	}

	if( DFLT_PROTO[0] ){
		BORN_SPECIALIST = 1;
		proto = DFLT_PROTO;
		if( !REUSE_ENV() )
		Verbose("SPECIALIST: %s\n",proto);
	}else{
		Verbose("GENERALIST\n");
		BORN_SPECIALIST = 0;
		proto = "delegate";
	}
	return proto;
}

int isHTTP(PCStr(proto))
{
	if( strcaseeq(proto,"httpft") ) return 1;
	if( strcaseeq(proto,"htaccept") ) return 1;
	if( strcaseeq(proto,"http-proxy") ) return 1;
	return strcaseeq(proto,"http") || strcaseeq(proto,"https");
}
static void servermount1(Connection *Conn,PCStr(serverspec))
{	CStr(serverurl,1024);
	CStr(hostlist,1024);
	CStr(mountopt,1024);
	CStr(mount,1024);
	IStr(svproto,64);
	IStr(svsite,256);
	int isorigdst = 0;

const char *proto;
proto = servermount_proto;

	/*
	scan_serverspec(serverspec,serverurl,hostlist);
	*/
	scan_serverspec(Conn,serverspec,AVStr(serverurl),AVStr(hostlist));
	decomp_absurl(serverurl,AVStr(svproto),AVStr(svsite),VStrNULL,0);
	if( isorigdst = strheadstrX(svsite,ORIGDST_HOST,0) != 0 ){
		sv1log("##NAT SERVER=%s\n",svsite);
		LOG_type4 |= L_ORIGDST;
	}
	if( hostlist[0] )
		if( strchr(hostlist,'=') )
			sprintf(mountopt,"%s",hostlist);
		else	sprintf(mountopt,"via=%s",hostlist);
	else	strcpy(mountopt,"");

	/* V8.0.0 forbid non-RELIABLE hosts to access internal pages */
	set_MOUNT_ifndef(Conn,"/-/builtin/icons/*","=","default");
	set_MOUNT_ifndef(Conn,"/-/*","=","forbidden,from=!.RELIABLE,default");

	if( isHTTP(proto) ){
		/* if SERVER=http://server then this should be "%s/*" */
		const char *up;
		if( (up = strstr(serverurl,"://")) && strchr(up+3,'/') == 0 ){
		sprintf(mount,"%s/*",serverurl);
		}else{
		sprintf(mount,"%s*",serverurl);
		}
		set_MOUNT_ifndef(Conn,"/-*","=",mountopt);
		set_MOUNT_ifndef(Conn,"/=*","=",mountopt);

		if( isorigdst ){
		}else
		if( strstr(serverspec,"://") )
		set_MOUNT_ifndef(Conn,"/*",mount,mountopt);
		else{
			/* MOUNT="/* //-/*" causes virtual hosting,
			 * "//-" in right hand is interpreted so ... */
		}
	}
	if( streq(proto,"nntp") || streq(proto,"news") ){
		sprintf(mount,"%s*",serverurl);
		set_MOUNT_ifndef(Conn,"=",mount,mountopt);
	}
	if( streq(proto,"ftp") ){
		/*
		set_MOUNT_ifndef(Conn,"/*","file:/-stab-/*","default");
		*/
		if( !streq(serverurl,"ftp://-/") ){
			/* SERVER=ftp://host ... implicit MOUNT for the root */
		}else
		set_MOUNT_ifndef(Conn,"/*","file:/-stab-/*","!asproxy,default");
		set_MOUNT_ifndef(Conn,"//*","=",mountopt);
		if( !isMYSELF(DFLT_HOST) )
		if( getEnv(P_MOUNT) != NULL || strchr(serverurl,'@') ){
			sprintf(mount,"%s*",serverurl);
			set_MOUNT_ifndef(Conn,"/*",mount,mountopt);
		}
	}
	if( streq(proto,"pop") || streq(proto,"imap") )
		set_MOUNT_ifndef(Conn,"//*","=",mountopt);
}

const char *DELEGATE_builtout();
const char *getEMCert(PCStr(emcert));
static void mount_all(Connection *Conn,PCStr(proto))
{	const char *env;
	const char *email = "config-data@id.delegate.org";
	CStr(opt,128);

	if( mount_done )
		return;
	mount_done = 1;

	scanEnv(Conn,P_MOUNT,scan_MOUNT);

servermount_proto = proto;
	scanEnv(Conn,P_SERVER,servermount1);

	if( isHTTP(proto) || streq(proto,"delegate") ){
		set_MOUNT_ifndef(Conn,"/favicon.ico","builtin:icons/ysato/default.ico","default,direction=fo,onerror=404,expires=15m");
	}

	if( 0 <= withAdminPort(NULL,NULL) )
	if( Fopt == 0 && isFunc == 0 && Conn->_isFunc == 0 ){
	sprintf(opt,"default,verify=rsa:%s",email);
	if( set_MOUNT_ifndef(Conn,"/-/ext/builtin/*",DELEGATE_builtout(),opt) ){
		if( INHERENT_fork() ){
			CStr(emcert,128);
			sprintf(emcert,"%s.pem",email);
			VerifyRSA(emcert,getEMCert(emcert),NULL,0,NULL,0);
		}
	}
	}

	init_mtab();
}

static const char *defaultPERMIT(Connection *Conn)
{	CStr(remitable,128);

	if( BORN_SPECIALIST ){
		if( streq(DFLT_PROTO,"telnet") )
		if( iSERVER_PORT != 0 ){
			sprintf(remitable,"%s/%d",iSERVER_PROTO,iSERVER_PORT);
			sv1log("REMITTABLE bound by SERVER: %s\n",remitable);
			return stralloc(remitable);
		}
		if( streq(DFLT_PROTO,"tunnel1") )
			return DELEGATE_G_PERMIT;

		if( isHTTP(DFLT_PROTO) || streq(DFLT_PROTO,"icp") )
			return DELEGATE_HTTP_PERMIT;
		else
		/*
		if( streq(DFLT_PROTO,"socks") )
		*/
		if( strneq(DFLT_PROTO,"socks",5) )
			return DELEGATE_SOCKS_PERMIT;
		else
		if( streq(DFLT_PROTO,"telnet") )
			return DELEGATE_TELNET_PERMIT;
		else	return DELEGATE_S_PERMIT;
	}else{
		/* V8.0.4 SERVER=delegate with REMITTABLE={http*} by default */
		if( getEnv(P_SERVER) == 0 )
			return DELEGATE_HTTP_PERMIT;
		else	return DELEGATE_G_PERMIT;
	}
}
static void scan_PERMITdflt(Connection *Conn){
	CStr(extproto,1024);
	if( lHTTPACCEPT() ){
		strcpy(extproto,defaultPERMIT(Conn));
		strcat(extproto,",htaccept,incoming,ssltunnel");
		scan_PERMIT(Conn,extproto);
		if( getEnv(P_REMITTABLE) == NULL && getEnv(P_PERMIT) == NULL ){
			/* allow ACCEPT and transparent CONNECT from local hosts */
			sprintf(extproto,"htaccept,ssltunnel:-P:.RELIABLE");
			scan_PERMIT(Conn,extproto);
			/* allow incoming via SocMux from external hosts */
			sprintf(extproto,"incoming:-P:*");
			scan_PERMIT(Conn,extproto);
			if( !streq(iSERVER_PROTO,"htmux") ){
			/* allow usual protocols over HTTP-proxy for local hosts */
			sprintf(extproto,"%s:-P:.RELIABLE",defaultPERMIT(Conn));
			scan_PERMIT(Conn,extproto);
			}
		}
	}else	scan_PERMIT(Conn,defaultPERMIT(Conn));
}
static void scan_PERMITX(Connection *Conn,PCStr(proto))
{	CStr(extproto,1024);

	if( num_ListElems(proto,':') == 1 ){
		PERMIT_GLOBAL++;
		if( *proto == '+' ){
			sprintf(extproto,"%s%s",defaultPERMIT(Conn),proto+1);
			proto = extproto;
		}
	}else{
		if( PERMIT_GLOBAL == 0 ){
			/*
			scan_PERMIT(Conn,defaultPERMIT(Conn));
			*/
			scan_PERMITdflt(Conn);
			PERMIT_GLOBAL++;
		}
	}
	scan_PERMIT(Conn,proto);
}

void httplog_head(Connection *Conn,int time,FILE *fp)
{	CStr(host,MaxHostNameLen);
	const char *user;
	CStr(date,64);

	strcpy(host,"-");
	getClientHostPort(Conn,AVStr(host));
	if( (user = getClientUserC(Conn)) == NULL )
		user = "-";
	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_HTTPD,time,0);
	fprintf(fp,"%s %s %s [%s] ",host,user,"-",date);
}

Logfile *LOG_which(PCStr(proto),PCStr(filter1),int options);
void LOG_printf(Logfile *logF,PCStr(fmt),...);
int FMT_fputLog(Connection *Conn,PCStr(filter),PCStr(fmt),...)
{	CStr(date,64);
	Logfile *Log;
	VARGS(8,fmt);

	if( Log = LOG_which(DFLT_PROTO,filter,0) ){
		StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_HTTPD,time(0),0);
		LOG_printf(Log,"[%s]{%d+%d} %s: ",
			date,CHILD_SERNO,CHILD_SERNO_MULTI,filter);
		LOG_printf(Log,fmt,VA8);
		return 1;
	}
	return 0;
}

void scan_LOG(Connection *Conn,PCStr(log))
{	CStr(proto,64);
	CStr(filters,256);
	CStr(logform,256);
	CStr(pathform,1024);
	int ni;

	proto[0] = filters[0] = logform[0] = pathform[0] = 0;
	ni = Xsscanf(log,"%[^:]:%[^:]:%[^:]:%s",AVStr(proto),AVStr(filters),AVStr(logform),AVStr(pathform));
	if( ni != 4 ){
		ERRMSG("ERROR LOG=%s\n",log);
		return;
	}
	LOG_create(proto,filters,logform,pathform,"a",0);
}
static const char *logfile()
{	const char *logfile;

	if( (logfile = getEnv(P_LOGFILE)) == 0 )
		logfile = DELEGATE_LOGFILE;
	return logfile;
}

static char *primaryPort(PVStr(port))
{
	if( IamPrivateMASTER )
		sprintf(port,"%s++",PrivateMasterOwnerPort);
	else	printPrimaryPort(BVStr(port));
	return (char*)port;
}
static void strsubstDE(PVStr(spath),PCStr(path),PCStr(root),PCStr(var))
{
	strcpy(spath,path);
	strsubstDirEnv(AVStr(spath),root,var);
}

int substEXECDIR(PCStr(fpath),PVStr(opath),int osize);
int substEXECNAME(PCStr(fpath),PVStr(opath),int osize);

#define substfile DELEGATE_substfile
#define substFile(f) substfile(AVStr(f),"",VStrNULL,VStrNULL,VStrNULL)

typedef struct {
	QPtr        se_ref;
	const char *se_dgroot;
	const char *se_vardir;
	const char *se_logdir;
} substEnv;
static const char *ssLogdir(PVStr(dirbuf),substEnv *se){
	const char *logdir;

	if( (logdir = getEnv(P_LOGDIR)) == 0 )
		logdir = DELEGATE_LOGDIR;

	if( !isBoundpath(logdir) ){
		strcpy(dirbuf,logdir);
		strsubstDirEnv(AVStr(dirbuf),se->se_dgroot,se->se_vardir);
		if( strstr(dirbuf,"${EXECDIR}") ){
			substEXECDIR(dirbuf,AVStr(dirbuf),1024);
		}
		if( !isBoundpath(dirbuf) )
			sprintf(dirbuf,"%s/%s",se->se_vardir,logdir);
		logdir = dirbuf;
	}
	return logdir;
}
static const char *ssPort(PVStr(port),substEnv *se){
	primaryPort(BVStr(port));
	return port;
}
static const char *ssPid(PVStr(pidb),substEnv *se){
	sprintf(pidb,"%d",getpid());
	return pidb;
}
const char *WINSERV_DGROOT();
static char *tmpdgroot(){
	static char *temproot;

	if( isWindows() ) 
	if( main_argc == 1 )
	if( getenv("DGROOT") == 0 )
	if( !file_is(0) && !file_is(1) && !file_is(2) )
	{
		if( temproot == 0 ){
			CStr(path,1024);
			const char *tmp;
			if( (tmp = getenv("TEMP")) == 0 )
			if( (tmp = getenv("TMP")) == 0 )
				tmp = "/windows/temp";
			sprintf(path,"%s/%s",tmp,WINSERV_DGROOT());
			temproot = strdup(path);
		}
		return temproot;
	}
	return 0;
}

int normalizePath(PCStr(ipath),PVStr(npath));
void substfile(PVStr(file),PCStr(proto),PVStr(rvardir),PVStr(rlogdir),PVStr(ractdir))
{	CStr(port,MaxHostNameLen);
	CStr(pid,64);
	CStr(dir,1024);
	substEnv seb,*se = &seb;
	const char *vardir;
	const char *etcdir;
	const char *admdir;
	const char *actdir;
	const char *TMPDIR;
	const char *WORKDIR;
	const char *CACHEDIR;
	const char *dgroot;
	const char *libdir;
	/*
	CStr(alogdir,1024);
	*/

	if( strstr(file,"$") == 0 ){
		if( rvardir == NULL && rlogdir == NULL && ractdir == 0 )
			return;
	}
	if( lPATHFIND() )
	fprintf(stderr,"--- %s:%d %s\n",whStr(file),file);

	if( (dgroot = tmpdgroot()) ){
		/* starting as a service on Win */
	}else
	if( (dgroot = getEnv(P_DGROOT)) == 0 ) dgroot = DELEGATE_DGROOT;
	if( (libdir = getEnv(P_LIBDIR)) == 0 ) libdir = DELEGATE_LIBDIR;
	if( (vardir = getEnv(P_VARDIR)) == 0 ) vardir = DELEGATE_VARDIR;
	if( (etcdir = getEnv(P_ETCDIR)) == 0 ) etcdir = DELEGATE_ETCDIR;
	if( (admdir = getEnv(P_ADMDIR)) == 0 ) admdir = DELEGATE_ADMDIR;
	if( (actdir = getEnv(P_ACTDIR)) == 0 ) actdir = DELEGATE_ACTDIR;
	if( (TMPDIR = getEnv(P_TMPDIR)) == 0 ) TMPDIR = DELEGATE_TMPDIR;
	if( (WORKDIR = getEnv(P_WORKDIR)) == 0 ) WORKDIR = DELEGATE_WORKDIR;
	if( (CACHEDIR = getEnv(P_CACHEDIR)) == 0 ) CACHEDIR = DELEGATE_CACHEDIR;
	if( strstr(file,"${HOME}") ){
		CStr(home,1024);
		getHOME(getuid(),AVStr(home));
		if( streq(home,"/") ){
			/* don't generate "//" prefixed path on Win */
		}else
		strsubst(AVStr(file),"${HOME}",home);
	}

	/*
	if( lARGDUMP() )
	*/
	if( lFILETRACE() )
		fprintf(stderr,"[%d]< %s\n",getpid(),file);

	cpyQPtr(se->se_ref,file);
	se->se_dgroot = dgroot;
	se->se_vardir = vardir;
	se->se_logdir = 0;
	if( strstr(file,"${EXECDIR}") ){
		fprintf(stderr,"-- obsolete ${EXECDIR} by substfile(%s)\n",
			file);
	}

	if( strstr(file,"${STARTDIR}") ){
		const char *startdir;
		if( startdir = getenv("STARTDIR") )
			strsubst(AVStr(file),"${STARTDIR}",startdir);
	}

	/* obsolete */
	if( strstr(file,"${EXECDIR}") ){
		CStr(execdir,1024);
		const char *dp;
/*
		if( 0 < readlink(EXEC_PATH,execdir,sizeof(execdir)) ){
			CStr(cwd,1024);
			if( !isFullpath(execdir) ){
				getcwd(cwd,sizeof(cwd));
				chdir_cwd(cwd,execdir,0);
				strcpy(execdir,cwd);
			}
		}else
*/
		strcpy(execdir,EXEC_PATH);
		if( (dp= strrchr(execdir,'/')) || (dp= strrchr(execdir,'\\')) )
			truncVStr(dp);
		else	strcpy(execdir,".");
		strsubst(AVStr(file),"${EXECDIR}",execdir);
	}

	strsubst(AVStr(file),"${LIBDIR}",libdir);
	strsubst(AVStr(file),"${ETCDIR}",etcdir);
	strsubst(AVStr(file),"${ADMDIR}",admdir);
	/*
	strsubst(AVStr(file),"${LOGDIR}",logdir);
	*/
	if( strstr(file,"${LOGDIR}") )
	strsubst(AVStr(file),"${LOGDIR}",ssLogdir(AVStr(dir),se));
	strsubst(AVStr(file),"${ACTDIR}",actdir);
	strsubst(AVStr(file),"${TMPDIR}",TMPDIR);
	strsubst(AVStr(file),"${WORKDIR}",WORKDIR);
	strsubst(AVStr(file),"${CACHEDIR}",CACHEDIR);

	strsubstDirEnv(AVStr(file),dgroot,vardir);
	strsubst(AVStr(file),"${PROTO}",proto);
	/*
	strsubst(AVStr(file),"${PORT}",port);
	strsubst(AVStr(file),"${PID}",pid);
	*/
	strsubst(AVStr(file),"${PORT}",ssPort(AVStr(port),se));
	strsubst(AVStr(file),"${PID}",ssPid(AVStr(pid),se));

	{
		Connection *Conn = mainConn;
		if( Conn ){
			if( Client_Host[0] )
				strsubst(AVStr(file),"${CLIENTHOST}",Client_Host);
			else	strsubst(AVStr(file),"${CLIENTHOST}","");
		}
	}

	/*
	if( lARGDUMP() )
	*/
	if( lFILETRACE() )
		fprintf(stderr,"[%d]> %s\n",getpid(),file);

	if( rvardir != NULL ) strsubstDE(AVStr(rvardir),vardir,dgroot,vardir);
	/*
	if( rlogdir != NULL ) strsubstDE(AVStr(rlogdir),logdir,dgroot,vardir);
	*/
	if( rlogdir != NULL ) strsubstDE(AVStr(rlogdir),ssLogdir(AVStr(dir),se),dgroot,vardir);
	if( ractdir != NULL ) strsubstDE(AVStr(ractdir),actdir,dgroot,vardir);

	/* might be referred in ${xxxDIR} via ${DGROOT} */
	/* obsolete */
	if( strstr(file,"${EXECDIR}") ){
		substEXECDIR(file,AVStr(file),1024);
	}
	if( strstr(file,"${EXECNAME}") ){
		substEXECNAME(file,AVStr(file),1024);
	}
	if( file[0] == '/' || file[0] == '\\' )
	if( file[1] == '/' || file[1] == '\\' ){
		ovstrcpy((char*)file,file+1);
	}
	normalizePath(file,BVStr(file));
}
int realpathX(PCStr(xpath),PVStr(rpath),int rsize,int lev){
	int ll;
	CStr(rp,1024);

	if( xrealpath(xpath,AVStr(rp),sizeof(rp)) == 0 ){
		if( xpath != rpath )
			strcpy(rpath,xpath);
		return 0;
	}
	linescanX(rp,AVStr(rpath),rsize);
	for( ll = 1; ll < lev && xrealpath(rpath,AVStr(rp),sizeof(rp)); ll++ ){
		linescanX(rp,AVStr(rpath),rsize);
	}
	return ll;
}

int EXT_fullpathCOM(PCStr(path),PCStr(mode),PVStr(apath));
int substEXECDIR(PCStr(fpath),PVStr(opath),int osize)
{	CStr(xpath,4096);
	CStr(xdir,4096);
	const char *dp;
	CStr(ipath,1024);

	if( strstr(fpath,"${EXECDIR}") == 0 )
		return 0;
	strcpy(ipath,fpath);

    if( EXEC_PATH[0] && isFullpath(EXEC_PATH) ){
	strcpy(xpath,EXEC_PATH);
    }else{
	if( main_argv == 0 )
		return 0;

	if( streq(main_argv[0],DeleGate1) ){
		sv1log("---- substEXE NO %s\n",main_argv[0]);
		return 0;
	}
	/*
	toFullpathENV("PATH",main_argv[0],"r",AVStr(xpath),sizeof(xpath));
	*/
	EXT_fullpathCOM(main_argv[0],"r",AVStr(xpath));
    }

	realpathX(xpath,AVStr(xpath),sizeof(xpath),8);

	if( dp = strrpbrk(xpath,"/\\") ){
		truncVStr(dp);
		lineScan(fpath,xdir);
		strsubst(AVStr(xdir),"${EXECDIR}",xpath);
		setVStrEnd(opath,0);
		chdir_cwd(AVStr(opath),xdir,0); /* reduce redundant "." and ".." */
		if( opath[0] == 0 ){
			if( xdir[0] ){
				/* don't reduce "." to "" */
				strcpy(opath,".");
			}
		}
		if( lPATHFIND() ){
			fprintf(stderr,"--- EXECPATH FORM: %s\n",ipath);
			fprintf(stderr,">>> EXECPATH REAL: %s\n",opath);
		}
		return 1;
	}
	return 0;
}
int substEXECNAME(PCStr(fpath),PVStr(opath),int osize)
{	const char *name;
	CStr(nameb,1024);
	refQStr(np,nameb);

	if( main_argv == 0 )
		return 0;

	if( strstr(fpath,"${EXECNAME}") ){
		if( name = strrpbrk(main_argv[0],"/\\") )
			name += 1;
		else	name = main_argv[0];
		strcpy(nameb,name);
		if( np = strrchr(nameb,'.') ){
			truncVStr(np);
			name = nameb;
		}
		linescanX(fpath,AVStr(opath),osize);
		strsubst(AVStr(opath),"${EXECNAME}",name);
		return 1;
	}
	return 0;
}

static int findConf(PVStr(path),PCStr(func)){
	CStr(conf1,1024);
	CStr(confs,1024);
	const char *cf;
	int ci;

	if( func ){
		strcpy(conf1,DELEGATE_CONF);
		strsubst(AVStr(conf1),"${EXECNAME}",func);
	}else{
		substEXECNAME(DELEGATE_CONF,AVStr(conf1),sizeof(conf1));
		if( conf1[0] == 0 ){
			strcpy(conf1,DELEGATE_CONF);
			if( !isFullpath(conf1) ){
				IGNRETS getcwd(conf1,sizeof(conf1));
				Xsprintf(TVStr(conf1),"/%s",DELEGATE_CONF);
			}
		}
	}
	DELEGATE_substPath("CONF",';',conf1,AVStr(confs));
	cf = confs;
	for( ci = 0; *cf; ci++ ){
		cf = scan_ListElem1(cf,';',AVStr(path));
		if( File_is(path) )
			return 1;
		strcat(path,".txt");
		if( File_is(path) )
			return 1;
	}
	return 0;
}

int findConfFile(PCStr(file),PVStr(path)){
	strcpy(path,file);
	substFile(path);
	if( File_is(path) )
		return 1;
	strcat(path,".txt");
	if( File_is(path) ){
		return 1;
	}
	return 0;
}
extern const char *DGCOMMON_CONF;
static int loadQuietly(PCStr(conf)){
	FILE *fp;
	IStr(buf,1024);
	IStr(com,128);
	int otype4,ntype4;

	otype4 = LOG_type4;
	if( fp = fopen(conf,"r") ){
		while( Fgets(AVStr(buf),sizeof(buf),fp) != NULL ){
			wordScan(buf,com);
			if( isinList(com,"-vQ") ){
				LOG_type4 |= L_QUIET;
			}
			if( isinList(com,"-vq") ){
				LOG_type4 |= L_QUIET;
				otype4 |= L_QUIET;
			}
		}
		fclose(fp);
	}
	ntype4 = LOG_type4;
	LOG_type4 = otype4;
	if( ntype4 & L_QUIET )
		return 1;
	return 0;
}
int loadConfFile(Connection *Conn,PCStr(what),PCStr(conf)){
	if( lQUIET() || loadQuietly(conf) ){
	}else{
		fprintf(stderr,"#### loading %s conf: %s\n",what,conf);
	}
	load_script(NULL,NULL,conf);
	return 0;
}
static void loadCommonConf(Connection *Conn){
	IStr(conf,1024);

	if( lISCHILD() ){
		/* don't repeat loading common.conf. */
		return;
	}
	if( findConfFile(DGCOMMON_CONF,AVStr(conf)) ){
		loadConfFile(Conn,"common",conf);
	}
}
/*
 * v9.9.13 new-141023a, DGROOT should be set as fast as possible.
 * Among cofig. files, only the default config. file can set DGROOT
 * because other config. file can be relative to the DGROOT.
 */
static int getDefaultConf(PCStr(conf)){
	FILE *fp;
	IStr(buf,1024);
	IStr(arg,256);
	IStr(val,256);
	const char *vp;
	int gotroot = 0;

	if( fp = fopen(conf,"r") ){
		while( Fgets(AVStr(buf),sizeof(buf),fp) != NULL ){
			wordScan(buf,arg);
			if( arg[0] == '-' ){
			  switch( arg[1] ){
			    case 'f':
			      switch( arg[2] ){
				case 'v': LOG_type |= L_CONSOLE; break;
			      }
			      LOG_type |= L_FG;
			  }
			  continue;
			}
			if( vp = strchr(arg,'=') ){
				valuescanX(vp+1,AVStr(val),sizeof(val));
			}
			if( strneq(arg,"DGROOT=",7) ){
				if( lQUIET() || loadQuietly(conf) ){
				}else
				if( lFG() ){
		fprintf(stderr,"#### in default conf: DGROOT='%s'\n",val);
				}
				DELEGATE_DGROOT = stralloc(val);
				gotroot = 1;
			}
		}
		fclose(fp);
	}
	return gotroot;
}
void scan_DGPATH(PCStr(path));
void setEXEC_PATH();
void loadDefaultConf(Connection *Conn,int ac,const char *av[]){
	/*
	CStr(conf1,1024);
	*/
	CStr(conf,1024);
	int ai;

	const char *dconf;
	if( dconf = getEnv(P_DGCONF) )
		DELEGATE_CONF = stralloc(dconf);

	setEXEC_PATH(); /* needs EXEC_PATH for ${EXECDIR} substitution */
	/*
	substEXECDIR(DELEGATE_CONF,AVStr(conf1),sizeof(conf1));
	substEXECNAME(conf1,AVStr(conf),sizeof(conf));
	if( File_is(conf) ){
	*/
	if( findConf(AVStr(conf),NULL) ){
		/*
		fprintf(stderr,"#### loading default conf: %s\n",conf);
		load_script(NULL,NULL,conf);
		*/
		if( getDefaultConf(conf) ){ /* v9.9.13 mod-141023  */
			/*
			 * v9.9.13 mod-141023a, DGPATH must set before
			 * loadConfFile() is called because it and its
			 * decendant might include config. file by
			 * +=relative.
			 * And it must be after EXECDIR is set because
			 * DGPATH is including ${EXECDIR}.
			 */
			scan_DGPATH(DELEGATE_DGPATH);
		}
		loadConfFile(Conn,"default",conf);
	}

	/* apply xxxx.conf to -Fxxxx too */
	for( ai = 0; ai < ac; ai++ ){
	    if( strneq(av[ai],"-F",2) ){
		const char *func = av[ai] + 2;
		/*
		substEXECDIR(DELEGATE_CONF,AVStr(conf),sizeof(conf));
		strsubst(AVStr(conf),"${EXECNAME}",func);
		if( File_is(conf) ){
		*/
		if( findConf(AVStr(conf),func) ){
			/*
			fprintf(stderr,"#### loading default conf: %s\n",conf);
			load_script(NULL,NULL,conf);
			*/
			loadConfFile(Conn,"default",conf);
		}
	    }
	}
}

static scanListFunc shared1(PCStr(pathpat))
{	CStr(xpathpat1,1024);
	CStr(xpathpat2,1024);

	if( !isBoundpath(pathpat) ){
		strcpy(xpathpat1,pathpat);
		substFile(xpathpat1);
		if( isBoundpath(xpathpat1) )
			pathpat = xpathpat1;
		else{
			sprintf(xpathpat2,"${DGROOT}/%s",pathpat);
			substFile(xpathpat2);
			if( isBoundpath(xpathpat2) )
				pathpat = xpathpat2;
		}
	}
	if( isBoundpath(pathpat) )
		setSHARE(pathpat);
	else	ERRMSG("Not absolute path: SHARE=%s\n",pathpat);
	return 0;
}
void scan_SHARE(Connection*_,PCStr(pathpats))
{
	if( *pathpats == 0 )
		setSHARE("*");
	else	scan_commaList(pathpats,0,scanListCall shared1);
}
static void _setTMPDIR(PCStr(dir))
{	CStr(tmpdir,1024);

	if( dir == NULL )
		dir = DELEGATE_TMPDIR;
	if( dir == NULL || *dir == 0 )
		return;

	strcpy(tmpdir,dir);
	substFile(tmpdir);
	if( !fileIsdir(tmpdir) )
		mkdirRX(tmpdir);
	setTMPDIR(tmpdir);
}

static char *putDirEnv1(PVStr(buf),PCStr(name))
{	CStr(param,32);
	refQStr(ep,buf); /**/

	if( getEnv(name) == NULL )
		return 0;

	sprintf(ep,"%s=",name);
	ep += strlen(ep);
	sprintf(param,"${%s}",name);
	strcpy(ep,param);
	substfile(AVStr(ep),"",VStrNULL,VStrNULL,VStrNULL);
	if( strcmp(param,ep) == 0 )
		return 0;

	return (char*)ep + strlen(ep) + 1;
}
static const char *direnvs[] = {
	P_DGROOT,
	P_ACTDIR,
	P_ADMDIR,
	P_ETCDIR,
	P_TMPDIR,
	P_LOGDIR,
	P_VARDIR,
	P_WORKDIR,
	P_CACHEDIR,
	0
};
static int insenv(int mac,const char **ev,PCStr(estr))
{	int ei,len;
	char ec;
	const char *env1;

	for( len = 0; ec = estr[len]; len++ ){
		if( ec == '=' ){ 
			len++;
			break;
		}
	}
	for( ei = 0; env1 = ev[ei]; ei++ ){
		if( strncmp(env1,estr,len) == 0 )
			break;
	}
	if( mac-1 <= ei ){
		return -1;
	}
	ev[ei] = (char*)estr;
	return ei;
}
const char **addDirEnv(const char *const*oenv)
{	const char *env;
	const char *nenv[256]; /**/
	CStr(nenvb,4096);
	refQStr(ep,nenvb); /**/
	const char *xp;
	const char *name;
	int ei,ej,di;

	ej = 0;
	for( ei = 0; env = oenv[ei]; ei++ ){
		if( elnumof(nenv)-1 <= ej )
			break;
		nenv[ej++] = (char*)env;
	}

	for( di = 0; name = direnvs[di]; di++ ){
		if( elnumof(nenv)-1 <= ej)
			break;
		if( xp = putDirEnv1(AVStr(ep),name) ){
			nenv[ej++] = ep;
			ep = (char*)xp;
		}
	}

	sprintf(ep,"%s=%s",P_LIBPATH,DELEGATE_LIBPATH);
	substfile(AVStr(ep),"",VStrNULL,VStrNULL,VStrNULL);
	nenv[ej] = 0;
	if( insenv(256,nenv,ep) == ej )
		ej++;

	nenv[ej] = 0;
	return dupv(nenv,0);
}
int ExecSpawnvpDirenv(PCStr(what),PCStr(execpath),const char*const*av,int spawn)
{	int pid;
	const char *const*oenv;
	const char *tmpenv[1024]; /**/
	const char *e1;
	int ei,ec;

	if( direnv_environ == 0 ){
		tmpenv[0] = 0;
		direnv_environ = addDirEnv(tmpenv);
	}
	ec = 0;
	for( ei = 0; e1 = environ[ei]; ei++ ){
		if( elnumof(tmpenv)-1 <= ec ){
			break;
		}
		tmpenv[ec++] = (char*)e1;
	}
	for( ei = 0; e1 = direnv_environ[ei]; ei++ ){
		tmpenv[ec] = 0;
		if( insenv(1024,tmpenv,e1) == ec )
			ec++;
	}
	tmpenv[ec] = 0;
	oenv = (char const*const*)environ;
	environ = (char**)tmpenv;

	if( spawn ){
		pid = Spawnvp(what,execpath,av);
		environ = (char**)oenv;
		return pid;
	}else{
		Execvp(what,execpath,av);
		return -1;
	}
}
int ExecvpDirenv(PCStr(what),PCStr(execpath),const char*const*av)
{
	return ExecSpawnvpDirenv(what,execpath,av,0);
}
int SpawnvpDirenv(PCStr(what),PCStr(execpath),const char*const*av)
{	
	return ExecSpawnvpDirenv(what,execpath,av,1);
}

static const char *logfmtpart(PCStr(path))
{	const char *dp;

	if( dp = strrchr(path,':') )
		if( strchr(dp,'%') )
			return dp;
	return NULL;
}

int notREMITTABLE(Connection *Conn,PCStr(proto),int port);
extern int HTTP_ftpXferlog;
static void set_PROTOLOG(Connection *Conn,PCStr(proto))
{	const char *env;
	CStr(logspec,1024);
	const char *path;
	const char *fmt;
	CStr(tmp,1024);
	const char *dp;

	if( lNOPROTOLOG() )
		return;

	if( ( env = getEnv(P_PROTOLOG)) == 0 )
		env = DELEGATE_PROTOLOG;

	/*
	 *   PROTOLOG=[//host:port][/path][:format]
	 */

	strcpy(logspec,env);
	path = logspec;

	if( fmt = (char*)logfmtpart(logspec) ){
		truncVStr(fmt); fmt++;
		if( path[0] == 0 ){
			strcpy(tmp,DELEGATE_PROTOLOG);
			path = tmp;
			if( dp = logfmtpart(path) )
				truncVStr(dp);
		}
	}else	fmt = "";

	if( streq(proto,"sudo") ){
		return;
	}
	if( streq(proto,"nntp") )
		LOG_create("nntp",LF_PROTOLOG,"-",path,"a",1);
	if( streq(proto,"smtp") )
		LOG_create("smtp",LF_PROTOLOG,"-",path,"a",1);
	if( !BORN_SPECIALIST || isHTTP(proto) )
		LOG_create("http",LF_PROTOLOG,fmt,path,"a",1);
	if( isFTPxHTTP(proto) ){
		LOG_create("http",LF_PROTOLOG,fmt,path,"a",1);
	}
	if( !BORN_SPECIALIST || streq(proto,"ftp") || HTTP_ftpXferlog )
		LOG_create("ftp", LF_PROTOLOG,"-",path,"a",1);

	if( streq(proto,"yysh") ){
		IStr(xpath,1024);
		strcpy(xpath,path);
		strsubst(AVStr(xpath),"${PROTO}","http");
		LOG_create("http",LF_PROTOLOG,fmt,xpath,"a",1);
	}
	if( streq(proto,"socks") ){
		if( !notREMITTABLE(Conn,"http",80) )
			LOG_create("http",LF_PROTOLOG,fmt,path,"a",1);
		if( !notREMITTABLE(Conn,"ftp",21) )
			LOG_create("ftp",LF_PROTOLOG,fmt,path,"a",1);
		if( !notREMITTABLE(Conn,"smtp",25) )
			LOG_create("smtp",LF_PROTOLOG,fmt,path,"a",1);
		if( !notREMITTABLE(Conn,"nntp",119) )
			LOG_create("nntp",LF_PROTOLOG,fmt,path,"a",1);
	}
}

void setAbortLog(PCStr(form));

static void ScanLogs(Connection *Conn,PCStr(proto))
{	const char *env;

	_setTMPDIR(getEnv(P_TMPDIR));

	if( ( env = getEnv(P_LOGFILE) ) == 0 )
		env = DELEGATE_LOGFILE;
	LOG_create("delegate",LF_LOGFILE,"-",env,"a",0);

	if( ( env = getEnv(P_ERRORLOG) ) == 0 )
		env = DELEGATE_ERRORLOG;
	LOG_create(LP_NOTTY,LF_ERRORLOG,"-",env,"a",0);

	if( lTRACE() ){
		if( ( env = getEnv(P_TRACELOG) ) == 0 )
			env = DELEGATE_TRACELOG;
		LOG_create(LP_NOTTY,LF_TRACELOG,"-",env,"a",0);
	}

	if( ( env = getEnv(P_ABORTLOG) ) == 0 )
		env = DELEGATE_ABORTLOG;
	setAbortLog(env);

	if( !IamPrivateMASTER && execSPECIAL == 0 ){
		set_PROTOLOG(Conn,proto);
		scanEnv(Conn,P_LOG,scan_LOG);
	}

	scanEnv(Conn,P_SYSLOG,scan_SYSLOG);
	LOG_openall();
}

int MAXCONN_PCH;

void scan_SMTPSERVER(PCStr(smtpserver));
void scan_MIMECONV(PCStr(convspec));
void scan_SSLTUNNEL(PCStr(spec));
void scan_FILTERS(Connection *Conn);
void setupSSLifnotyet(Connection *Conn);
int scan_CGIENV(Connection *Conn,PCStr(envlist));
void scan_OVERRIDE(Connection *Conn,PCStr(ovparam));
void setURICONVdefault(int force);
void downloadCCXTabs(Connection *Conn);
void getGlobalCCX(CCXP ccx,int siz);
int PERMIT_withSrc();

extern const char *DELEGATE_SMTPGATE;
int rescanGlobal;

void scan_MIMECONV_(Connection *Conn,PCStr(spec)){
	scan_MIMECONV(spec);
}

static void scan_HOSTS0(Connection *Conn);
void init_resolv(PCStr(resolv),PCStr(conf),PCStr(ns),PCStr(types),PCStr(verify),PCStr(rr),PCStr(debug),PCStr(log));

/*
 * Global environment for -Ffunc (and to be scanned when given in INETD)
 */
static void scanGGlobals(Connection *Conn,int inmain){
	scanEnv(Conn,P_DGDEF,scan_DGDEF);
	scan_HOSTS0(Conn); /* gethostname() and "localhost" for init_myname() */
	if( inmain ){
		P_LV("-- _main scan_HOSTS0() DONE");
		iLog("--- _main scan_HOSTS0() DONE");
	}
	scanEnv(Conn,P_HOSTLIST,scan_HOSTLIST); /* might be referred in RESOLV*/
	if( inmain ){
		P_LV("-- _main scan_HOSTSLISTS() DONE");
		iLog("--- _main scan_HOSTSLISTS() DONE");
	}
	scanEnv(Conn,P_ARPCONF,scan_ARPCONF);
	putWinStatus("** Resolvers ...");
	if( inmain || getv(main_argv,P_RESOLV) ){
		OrigEnv.RES_ORDER = getenv("RES_ORDER");
		OrigEnv.RESOLV    = getenv("RESOLV");
		init_resolv(getEnv(P_RESOLV),
			getEnv(P_RES_CONF),getEnv(P_RES_NS),
			getEnv(P_RES_AF),getEnv(P_RES_VRFY),
			getEnv(P_RES_RR),getEnv(P_RES_DEBUG),getEnv(P_RES_LOG));
		if( inmain ){
			P_LV("-- _main init_resolv() DONE");
			iLog("--- _main init_resolv() DONE");
		}
	}
	putWinStatus("** Initializing ...");

	scanEnv(Conn,P_ENTR,scan_ENTR);
	scanEnv(Conn,P_SOCKOPT,scan_SOCKOPT);
	scanEnv(Conn,P_IPV6,scan_IPV6);
	scanEnv(Conn,P_SOCKS,scan_SOCKS);
	scanEnv(Conn,P_SRCIF,scan_SRCIF);
	scan_RIDENT(Conn,getEnv(P_RIDENT));
}

#define ScanGlobal(Conn,proto) DELEGATE_ScanGlobal(Conn,proto)
void ScanGlobal(Connection *Conn,PCStr(proto))
{	const char *env;

	if( scannedGlobal && !rescanGlobal )
		return;
	if( rescanGlobal ){
		scanGGlobals(Conn,0);
	}
	rescanGlobal = 0;
	scannedGlobal = 1;

	if( env = getEnv(P_ADMIN ) )
		DELEGATE_ADMIN = env;
	else
	if( env = getEnv(P_MANAGER) ){
		sv1log("##DeleGate/6.X: %s should not be used. Use %s instead.\n",
			P_MANAGER,P_ADMIN);
		DELEGATE_ADMIN = env;
	}

	scanEnv(Conn,P_DYCONF,scan_DYCONF);
	scan_DYCONF(Conn,"(done)");
	scanEnv(Conn,P_HOSTLIST,scan_HOSTLIST);
	scanEnv(Conn,P_CLUSTER,scan_CLUSTER);

	scanEnv(Conn,P_TIMEOUT, scan_TIMEOUT);
	scanEnv(Conn,P_MAXIMA,  scan_MAXIMA);
	scanEnv(Conn,P_M17N,scan_M17N); /* must be before scan_CHARCODE() */
	scanEnv(Conn,P_CHARCODE,scan_CHARCODE);
	scanEnv(Conn,P_CHARMAP, scan_CHARMAP);
	if( getEnv(P_CHARMAP) ){
		if( getEnv(P_CHARCODE) == 0 ){
			scan_CHARCODE(Conn,"asis");
		}
	}
	scanEnv(Conn,P_CHARSET,scan_CHARCODE);
	getGlobalCCX(CCX_TOCL,CCX_SIZE); /* globalCCX to CCX_TOCL */

	if( env = getEnv(P_MIMECONV) ){
		scanEnv(Conn,P_MIMECONV,scan_MIMECONV_);
	}else
	if( getEnv(P_CHARCODE) == 0 ){
		scan_MIMECONV("thru");
		compatV5info("MIMECONV=thru is set by default. MIMECONV=\"\"");
	}

	/* fix-140509d disable PORT for non-daemon, for -Fkill
	scanEnv(Conn,P_PORT,  scan_PORT);
	*/
	scanEnv(Conn,P_VSAP,  scan_VSAP);

	scanEnv(Conn,P_SERVICE, scan_SERVICE);
	scanEnv(Conn,P_CMAP,  scan_CMAP);
	scanEnv(Conn,P_STLS,  scan_STLS);
	scanEnv(Conn,P_TLSCONF,scan_TLSCONF);
	scanEnv(Conn,P_TLS,   scan_STLS);
	ScanLogs(Conn,proto);
	scanEnv(Conn,P_ROUTE, scan_ROUTE);
	scanEnv(Conn,P_FORWARD,scan_FORWARD);
	scanEnv(Conn,P_GATEWAY,scan_GATEWAY);
	scanEnv(Conn,P_MASTER,scan_MASTER);
	scanEnv(Conn,P_PROXY, scan_PROXY);
	scanEnv(Conn,P_HTMUX, scan_HTMUX);
	scanEnv(Conn,P_FTPTUNNEL,(scanPFUNCP)scan_FTPTUNNEL);
	if( env = getEnv(P_SSLTUNNEL) )
		scan_SSLTUNNEL(env);
	scanEnv(Conn,P_ICPCONF,scan_ICPCONF);
	scanEnv(Conn,P_ICP,   scan_ICP);

	if( env = getEnv(P_SMTPSERVER) )
		scan_SMTPSERVER(env);

	/*
	 * SERVER=socks MASTER=... SOCKS=-.- means using MASTER as SOCKS server
	 */
	if( strcaseeq(proto,"socks") ){
		if( getEnv(P_MASTER) ){
			if( getEnv(P_SOCKS) == 0 ){
				scan_SOCKS(Conn,"-.-");
			}
		}
	}
	scanEnv(Conn,P_DEST,  scan_DEST);

	NotifyPltfrmHosts(); /* initialize Notify-Platform table */
	scanEnv(Conn,P_OWNER,(scanPFUNCP)scan_OWNER);
	scanEnv(Conn,P_AUTH,scan_AUTH);
	scanEnv(Conn,P_AUTHORIZER,scan_AUTHORIZER);
	scanEnv(Conn,P_MYAUTH,scan_MYAUTH);
	scanEnv(Conn,P_PGP, (scanPFUNCP)scan_PGP);
	scanEnv(Conn,P_PAMCONF, scan_PAMCONF);

	scanEnv(Conn,P_SOCKSTAP,scan_SOCKSTAP);
	scanEnv(Conn,P_SCREEN,scan_SCREEN);
	if( env = getEnv(P_REMITTABLE) )
		scanEnv(Conn,P_REMITTABLE,scan_PERMITX);
	else{
		if( strcaseeq(proto,"dns") && getEnv(P_PERMIT) ){
			/* 9.9.8 for proxying DNS by UDPrelay with PERMIT */
			scan_PERMITX(Conn,"+,udprelay");
		}
	}
	if( env = getEnv(P_PERMIT) )
		scanEnv(Conn,P_PERMIT,scan_PERMITX);
	if( getEnv(P_REMITTABLE) == NULL && getEnv(P_PERMIT) == NULL )
		scan_PERMITdflt(Conn);
		/*
		scan_PERMIT(Conn,defaultPERMIT(Conn));
		*/
	scanEnv(Conn,P_REJECT,scan_REJECT);

	if( getEnv(P_RELIABLE) )
		scanEnv(Conn,P_RELIABLE,scan_RELIABLE);
	else{
		if( PERMIT_withSrc() == 0 )
			scan_RELIABLE(Conn,DELEGATE_RELIABLE);
		/* Allow expanding permission by PERMIT=proto:dst:extraSrcList
		 * without adding RELIABLE=extraSrcList.
		 * The default DELEGATE_RELIABLE is added to PERMIT without
		 * srcHostList.
		 * Like REMITTABLE is expanded for dstHost of MOUNT, RELIABLE
		 * could be expanded for the any srcHost in PERMIT...
		 */
	}
	scanEnv(Conn,P_REACHABLE,scan_REACHABLE);

	if( env = getEnv(P_RELAY) )
		scanEnv(Conn,P_RELAY,scan_RELAY);
	else	scan_RELAY(Conn,DELEGATE_RELAY);

	scanEnv(Conn,P_FILETYPE,(scanPFUNCP)scan_FILETYPE);
	scanEnv(Conn,P_HTTPCONF,scan_HTTPCONF);
	if( HTTP_ftpXferlog ){
		set_PROTOLOG(Conn,proto);
		LOG_openall();
	}
	scanEnv(Conn,P_NNTPCONF,scan_NNTPCONF);
	scanEnv(Conn,P_POPCONF, scan_POPCONF);
	scanEnv(Conn,P_MHGWCONF,scan_MHGWCONF);
	scanEnv(Conn,P_FTPCONF, scan_FTPCONF);
	scanEnv(Conn,P_DNSCONF, scan_DNSCONF);
	scanEnv(Conn,P_YYCONF,  scan_YYCONF);
	scanEnv(Conn,P_YYMUX,   scan_YYMUX);
	scanEnv(Conn,P_SOXCONF, scan_SOXCONF);
	scanEnv(Conn,P_SOCKMUX, scan_SOCKMUX);
	scanEnv(Conn,P_TELNETCONF, scan_TELNETCONF);

	scanEnv(Conn,P_SMTPCONF,scan_SMTPCONF);
	if( strcaseeq(proto,"smtp") ){
		if( env = getEnv(P_SMTPGATE) )
			scan_SMTPGATE(Conn,env);
		else	scan_SMTPGATE(Conn,DELEGATE_SMTPGATE);
	}

	if( env = getEnv(P_CGIENV) )
		scan_CGIENV(Conn,env);

	if( env = getEnv(P_DELAY) )
		scanEnv(Conn,P_DELAY,scan_DELAY);

	scan_FILTERS(Conn);
	setupSSLifnotyet(Conn);
	scanEnv(Conn,P_HTMLCONV,(scanPFUNCP)scan_HTMLCONV);
	scanEnv(Conn,P_URICONV,(scanPFUNCP)scan_URICONV);
	setURICONVdefault(0); /* initialize URICONV table if not set */

	/*
	if( env = getEnv(P_OVERRIDE) )	scan_OVERRIDE(Conn,env);
	*/
	scanEnv(Conn,P_CRON,scan_CRON);
	scanEnv(Conn,P_CRONS,scan_CRONS);

	if( isHTTP(proto) || strcaseeq(proto,"delegate") )
	{
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:*.update.microsoft.com:*");
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:*.wii.com:*");
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:*.google.com:*");
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:*.google.co.jp:*");
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:*.facebook.com:*");
	}
	/*
	scan_CMAP(Conn,"thru-CONNECT:HTTPCONF:https:update.microsoft.com:*");
	*/

	downloadCCXTabs(Conn);
}

static void scan_HOSTS0(Connection *Conn)
{	CStr(hosts,0x10000);

	if( init_HOSTS == 0 ){
		init_HOSTS = 1;
		scanEnv(Conn,P_HOSTS,scan_HOSTS);
		scan_HOSTS(Conn,"localhost/127.0.0.1");
		scan_HOSTS(Conn,"localhost/__1");
		sprintf(hosts,"%s/%s",VSA_hostlocal(),VSA_hostlocaladdr());
		scan_HOSTS(Conn,hosts);
		dump_HOSTS(AVStr(hosts));
		Verbose("scanned HOSTS=%s\n",hosts);
	}
}

static void ScanEachConn(Connection *Conn)
{	const char *env;

	HAS_MASTER = getEnv(P_PROXY) || getEnv(P_MASTER) || getEnv(P_TUNNEL);

	if( env = getEnv(P_BASEURL) )
		set_BASEURL(Conn,env);

	if( env = getEnv(P_DELEGATE) )
		scan_DELEGATE(Conn,env);

	if( env = getEnv(P_OVERRIDE) )
		scan_OVERRIDE(Conn,env);
}

static int DGROOT_SUBST;
static void ScanDirDefs(Connection *Conn)
{	const char *env;
	int created;
	int scanX = inINITIALIZATION ? scanDirDefsX++ : 0;

	created = setDGROOT();
/*
	if( strstr(DELEGATE_DGROOT,"${EXECDIR}") ){
		CStr(path,1024);
		if( substEXECDIR(DELEGATE_DGROOT,AVStr(path),sizeof(path)) ){
			DELEGATE_DGROOT = stralloc(path);
			DGROOT_SUBST = 1;
		}
	}
*/
	if( getEnv(P_SHARE) )
		scanEnv(Conn,P_SHARE,scan_SHARE);
	else
	if( inINITIALIZATION && scanX == 0 )
		compatV5info("created directory/file will be non-sharable. SHARE=\"\"");

	if( created )
		chmodShared(DELEGATE_DGROOT);
	if( env = getEnv(P_LIBPATH) )
		DELEGATE_LIBPATH = stralloc(env);
	if( env = getEnv(P_DATAPATH) )
		DELEGATE_DATAPATH = stralloc(env);
	if( env = getEnv(P_LDPATH) )
		DELEGATE_LDPATH = stralloc(env);

	if( env = getEnv(P_VARDIR)   )	DELEGATE_VARDIR = stralloc(env);
	if( env = getEnv(P_LOGFILE)  )	DELEGATE_LOGFILE = stralloc(env);
	if( env = getEnv(P_ERRORLOG) )	DELEGATE_ERRORLOG = stralloc(env);
	if( env = getEnv(P_STDOUTLOG))	DELEGATE_STDOUTLOG = stralloc(env);
	if( env = getEnv(P_TRACELOG) )	DELEGATE_TRACELOG = stralloc(env);
	if( env = getEnv(P_PIDFILE)  )  DELEGATE_PIDFILE = stralloc(env);
	if( env = getEnv(P_PROTOLOG) ){
		CStr(logspec,1024);
		const char *fmt;
		if( env[0] == ':' ){
			/* PROTOLOG="[Path]:Form" - Path part is omitted */
			strcpy(logspec,DELEGATE_PROTOLOG);
			if( fmt = logfmtpart(logspec) )
				truncVStr(fmt);
			strcat(logspec,env);
			env = logspec;
		}
		DELEGATE_PROTOLOG = stralloc(env);
	}
	if( env = getEnv(P_CERTDIR) ) scan_CERTDIR(Conn,env);
}

void scan_CACHE(Connection *Conn,PCStr(spec));
void scan_CACHEARC(PCStr(file));
void scan_CACHEDIR(PCStr(dirs));
void scan_CACHEFILE(PCStr(file));

void ScanFileDefs(Connection *Conn)
{	const char *env;

	ScanDirDefs(Conn);
	if( env = getEnv("IMAGEDIR") )	DELEGATE_IMAGEDIR = stralloc(env);

	if( env = getEnv(P_CACHEARC) )	scan_CACHEARC(stralloc(env));
	if( env = getEnv(P_CACHEDIR) )	scan_CACHEDIR(stralloc(env));
	if( env = getEnv(P_CACHEFILE))	scan_CACHEFILE(stralloc(env));
	/*
	if( env = getEnv(P_CACHE)    )	scan_CACHE(Conn,env);
	*/
	scanEnv(Conn,P_CACHE,scan_CACHE);
	if( env = getEnv(P_COUNTER)  )	scan_COUNTER(Conn,env);

	if( scannedGlobal )
	/* Resolvy must be used after it is initialized,
	 * and after socket initialization in DO_INITIALIZE in Win32
	 */
	{
	if( env = getEnv(P_EXPIRE)   )  scanEnv(Conn,P_EXPIRE,scan_EXPIRE);
	}
}

static int REUSE_ENV()
{
	return (1 < CHILD_SERNO_MULTI);
}
#define config(Conn,csock)	DELEGATE_config(Conn,csock)
void DELEGATE_configx(Connection *Conn,int force);
void config(Connection *Conn,int csock)
{
	START_TIMEP = time(0);
	if( REUSE_ENV() || lSYNC() ){
		Scan_SERVER(Conn);
		ScanEachConn(Conn);
		return;
	}
/*
if( env = getEnv(P_EXPIRE) )	scanEnv(Conn,P_EXPIRE,scan_EXPIRE);
- should clear dynamically added CMAP (using peak index of static CMAPs ?)
*/
	DELEGATE_configx(Conn,0);
}
void DELEGATE_configx(Connection *Conn,int force)
{	const char *proto;
	const char *env;

	if( force ){
		mount_done = 0;
	}

	scan_HOSTS0(Conn);
	proto = Scan_SERVER(Conn);

	scanEnv(Conn,P_CONNECT,scan_CONNECT);
	ScanGlobal(Conn,proto);
	ScanEachConn(Conn);
	ScanFileDefs(Conn);
	mount_all(Conn,proto);
}

int LOG_createPortFile(PCStr(file),int stayopen);
static void PutPortFile(int stayopen)
{	const char *file;

	if( (file = getEnv(P_PIDFILE)) == 0 )
		file = DELEGATE_PIDFILE;
	if( LOG_createPortFile(file,stayopen) != 0 ){
		if( lLOCK() ){
			CStr(path,1024);
			strcpy(path,file);
			substFile(path);
			fprintf(stderr,"DeleGate: could not create lock.\n");
 fprintf(stderr,"DeleGate could not start because it failed creating '%s'\n",
path);
			Finish(-1);
		}
	}
}
static void get_pidfile(PVStr(path))
{	const char *file;

	if( (file = getEnv(P_PIDFILE)) == 0 )
		file = DELEGATE_PIDFILE;
	strcpy(path,file);
	substFile(path);
}
static int killServer(PCStr(killspec),int warn)
{	CStr(signame,64);
	CStr(path,1024);
	FILE *fp;
	int sig,pid,rcode;
	int mtime1,mtime2;

	get_pidfile(AVStr(path));
	if( (fp = fopen(path,"r")) == NULL ){
		if( warn )
		fprintf(stderr,"\"%s\": no active server on the port.\n",path);
		return -1;
	}

	signame[0] = 0;
	Xsscanf(killspec,"-%s",AVStr(signame));
	if( strcaseeq(signame,"HUP") ) sig = SIGHUP; else
	if( strcaseeq(signame,"INT") ) sig = SIGINT; else
	sig = SIGTERM;

	pid = 0;
	IGNRETP fscanf(fp,"%d",&pid);
	fclose(fp);
	printf("\"%s\": kill(%d,SIG%s) = ",path,pid,sigsym(sig));
	fflush(stdout);
	mtime1 = File_mtime(path);

	if( 1 < pid ){
		errno = 0;
		if( isWindows() ){
			int killWin(int pid,int sig);
			rcode = killWin(pid,sig);
		}else
		rcode = Kill(pid,sig);
		if( rcode == 0 )
			printf("%d (%d) ** OK **",rcode,errno);
		else	printf("%d (%d) ** ERROR **",rcode,errno);
		fflush(stdout);
	}
	if( 1 < pid ){
		double Start = Time();
		int wi;
		for( wi = 0; wi < 100 && (Time()-Start) < 5.0; wi++ ){
			mtime2 = File_mtime(path);
			if( sig == SIGHUP && mtime1 != mtime2 ){
				/* 9.9.8 the process stay alive in this case */
				break;
			}
			if( !procIsAlive(pid) )
				break;
			printf("*");
			fflush(stdout);
			msleep(50);
		}
		if( 0 < wi )
			printf(" (%.2f/%d)",Time()-Start,wi);
		syslog_ERROR("killServer(%d) alive=%d (%.2f/%d) -P%d\n",
			pid,procIsAlive(pid),Time()-Start,wi,SERVER_PORT());
	}
	printf("\n");
	return rcode;
}

static void kill_predecessor(int ac,const char *av[],PCStr(sigtype),int warn)
{	CStr(port,PORTSSIZE);
	const char *hav[2]; /**/
	CStr(hab,128);
	const char *env;
	int hac;
	int isHUP,killed = 0;

	if( env = getEnv("HUPENV") ){
		hac = 1;
		hav[0] = hab;
		hav[1] = 0;
		sprintf(hab,"HUPENV=%s",env);
	}else{
		hav[0] = 0;
		hac = 0;
	}
	isHUP = streq(sigtype,"-hup");

	if( isWindows() )
	if( strneq(av[0],"-F",2) ){
		/* 9.9.2 for -Fkill delete_service() on Win32 (9.4.0-pre8) */
		av[0] = EXEC_PATH;
	}

	printServPort(AVStr(port),"",1);
	/*
	if( !INHERENT_fork() && strcmp(sigtype,"-hup") == 0
	 && restart_service(port,hac,hav) ){
	*/
	if( !INHERENT_fork() && isHUP && restart_service(port,hac,hav) ){
		printf("restarted service: %s\n",port);
	}else
	if( delete_service(ac,av,port,sigtype) ){
		printf("stopped service: %s\n",port);
		msleep(100);
		killed = 1;
	}else{
		/*
		killServer(sigtype,warn);
		*/
		if( killServer(sigtype,warn) == 0 )
			killed = !isHUP;
	}

	/* make sure the finish of predecessor */
	/*
	if( strcmp(sigtype,"-hup") != 0 ){
	*/

	if( LOG_VERBOSE )
	fprintf(stderr,"** killed = %d\n",killed);
	if( killed ){
		CStr(path,1024);
		int xtry;
		FILE *pfp;
		int pid;

		get_pidfile(AVStr(path));
		for( xtry = 0; xtry < 25; xtry++ ){
			pfp = fopen(path,"r");
			if( pfp == 0 ){
				if( LOG_VERBOSE )
				fprintf(stderr,"** file gone: %s\n",path);
				break;
			}
			if( fscanf(pfp,"%d",&pid) == 1 ){
				if( procIsAlive(pid) <= 0 ){
					if( LOG_VERBOSE )
					fprintf(stderr,"** process gone: %d\n",
						pid);
					break;
				}
			}
			fclose(pfp);
			if( 0 < xtry )
			fprintf(stderr,"Waiting predecessor to exit: %s...\n",
				path);
			msleep(200);
		}
	}
}
int kill_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *sigtype = "";
	const char *dp;

	for( ai = 0; ai < ac; ai++ ){
		if( dp = strheadstrX(av[ai],"-Fkill-",0) ){
			/*
			sigtype = dp;
			*/
			sigtype = dp - 1;
			break;
		}
	}
	scan_args(ac,av);
	if( SERVER_PORT() == 0 ){
		scanEnv(Conn,P_DGOPTS,scan_DGOPTS);
	}
	if( numServPorts() == 0 ){
		scanEnv(Conn,P_INETD,scan_INETD);
	}
	kill_predecessor(ac,av,sigtype,1);
	Finish(0);
	return -1;
}

extern int CACHE_READONLY;

int withORIGINAL_DST();
static void setCLIF(Connection *Conn,int csock){
	/* 9.9.1 ipfw on BSD and MacOSX */
	int asock = Conn->clif._acceptSock;
	CLIF_PORT = gethostAddr(asock,AVStr(CLIF_HOST));
	if( streq(CLIF_HOST,"?") ){
		sv1log("#getsockname(%s:%d)err=%d\n",CLIF_HOST,CLIF_PORT,errno);
		CLIF_PORT = Conn->clif._acceptSock;
		VA_HostPortIFclnt(Conn,csock,AVStr(CLIF_HOST),VStrNULL,NULL);
	}else
	if( streq(CLIF_HOST,"0.0.0.0") ){
		/* can't get real interface for wild-card -Pxxx */
		sv1log("#getsockname(%s:%d)err=%d\n",CLIF_HOST,CLIF_PORT,errno);
		VA_HostPortIFclnt(Conn,csock,AVStr(CLIF_HOST),VStrNULL,NULL);
	}else{
		VA_HostPortIFclnt(Conn,asock,AVStr(CLIF_HOST),VStrNULL,NULL);
	}
}
static void initConn(Connection *Conn,int csock)
{
	int asock = AcceptSock;
	double atime = ACCEPT_TIME;

	ConnInit(Conn);
	STX_tid = getthreadid();
	AcceptSock = asock;
	ACCEPT_TIME = atime;
	Conn->cl.p_connected = 1;
	ClientSock = csock;
	ClientSockX = csock;
	CLsock = csock;
	Conn->ma_private = myPrivateMASTER | MASTERisPrivate;
	clear_DGconn(Conn);

	if( 0 <= csock ){
		if( lORIGDST() && !withORIGINAL_DST() ){
			setCLIF(Conn,csock);
		}else
	CLIF_PORT = VA_HostPortIFclnt(Conn,csock,AVStr(CLIF_HOST),VStrNULL,NULL);
	sprintf(CLIF_HOSTPORT,"%s:%d",CLIF_HOST,CLIF_PORT);
	}else{
		/* maybe just cleaning ... */
	}

	if( CACHE_READONLY )
		DontWriteCache = 1;
}

int ipno(PVStr(path),PCStr(addr));

extern const char *DELEGATE_HOSTID;
int HostId(PCStr(addr))
{	CStr(path,2048);

	if( hostid_PATH == NULL ){
		strcpy(path,DELEGATE_HOSTID);
		substFile(path);
		setQStr(hostid_PATH,stralloc(path),strlen(path)+1);
	}
	return ipno(AVStr(hostid_PATH),addr);
}

void flush_publiclog(PCStr(route));
static void put_publiclog(PCStr(addr))
{	CStr(route,256);

	/*sprintf(route,"%d/%d",HostId(myaddr),HostId(addr));*/
	sprintf(route,"%d",HostId(addr));
	flush_publiclog(route);
}

void HL_setClientInfo(VAddr *peerhost);
void setOriginIdent(Connection *Conn,PCStr(sockname),PCStr(peername));
int set_OWNER(Connection *Conn,PCStr(host),int port,PCStr(user));

int getClientSockPeer(PVStr(sockname),PVStr(peername)){
	if( clientSocks != 0 && clientSocks->_sockname[0] ){
		strcpy(sockname,clientSocks->_sockname);
		strcpy(peername,clientSocks->_peername);
		return 0;
	}
	return -1;
}

void HL_setRidentInfo(VAddr*peer,VAddr*host);
int scan_hostport0(PCStr(hostport),PVStr(host));
void setRidentInfo(Connection *Conn,Efd *clSock){
	VAddr host,peer;
	CStr(phost,MaxHostNameLen);
	CStr(hhost,MaxHostNameLen);
	int hport,pport;

	if( clSock->_remote ){
		hport = scan_hostport0(SocknameOf(clSock),AVStr(hhost));
		pport = scan_hostport0(PeernameOf(clSock),AVStr(phost));
		VA_setVAddr(&peer,phost,pport,1);
		VA_setVAddr(&host,hhost,hport,1);
		HL_setRidentInfo(&peer,&host);
	}else{
		HL_setRidentInfo(NULL,NULL);
	}
}

const char *SCREEN_FILE;
int SCREEN_FILE_ACCEPT;
int addrGroup(PCStr(addrpatp),PCStr(hostname),VAddr *hostaddr);
void scan_condargs(Connection *Conn);
static int setClientInfo(Connection *Conn,Efd *clSock,PVStr(addr),PVStr(clntinfo))
{	int port;
	CStr(host,MaxHostNameLen);
	IStr(odst,MaxHostNameLen);
	const char *user;

	ClntConnTime = ACCEPT_TIME;
	if( VA_getClientAddr(Conn) ){
		if( (user = getClientUserC(Conn)) == NULL )
			user = "-";
		strcpy(host,Client_Host);
		VA_inetNtoah(Client_VAddr,AVStr(addr));
		port = Client_Port;
		if( EscEnabled() ){
			Conn->cl_count = scounter(0,&Client_VAddr->I3,4,1);
		}else
		Conn->cl_count = ClientCountUp(user,host,addr,port);
		HL_setClientInfo(Client_VAddr);
		if( SCREEN_FILE ){
			int match;
			match = addrGroup(SCREEN_FILE,host,Client_VAddr);
			if( match != 0 && SCREEN_FILE_ACCEPT == 0
			 || match == 0 && SCREEN_FILE_ACCEPT != 0
			){
				ConnectFlags |= COF_SCREENED;
			}
		}
	}else{
		user = "-";
		strcpy(host,"-");
		strcpy(addr,"0.0.0.0");
		port = 0;
		Conn->cl_count = 0;
	}
	sprintf(clntinfo,"%s@[%s]%s:%d",user,addr,host,port);

	Conn->clif = clSock->_clif;

	if( clSock->_remote ){
		setOriginIdent(Conn,SocknameOf(clSock),PeernameOf(clSock));
	}
	if( TeleportHost[0] )
		Xsprintf(TVStr(clntinfo),".-.%s:%d",
			TeleportHost,TeleportPort);

	setRidentInfo(Conn,clSock);
	scan_condargs(Conn);

	if( lORIGDST() ){
		int clsock = getEfd(clSock);
		IStr(addr,128);
		if( VA_getodstNAME(clsock,Origdst_VAddr) )
		if( CLIF_PORT != Origdst_Port
		 || !streq(CLIF_HOST,Origdst_Host)
		){
			sv1log("##NAT clif/%s:%d odst/%s:%d clnt/%s:%d\n",
				CLIF_HOST,CLIF_PORT,
				Origdst_Host,Origdst_Port,
				Client_Host,Client_Port
			);
			GatewayFlags |= GW_WITH_ORIGDST;
			Xsprintf(TVStr(clntinfo)," ##NAT%s/%s:%d",
				Origdst_Addr(odst),
				Origdst_Host,Origdst_Port);
		}
	}
	daemonlog("E","(%d) accepted [%d] %s (%5.3fs)(%d)\n",
		NUM_PEERS+NUM_CHILDREN,
		getEfd(clSock),clntinfo, Time()-ACCEPT_TIME,Conn->cl_count);

	if( streq(addr,"0.0.0.0") && port == 0 )
	if( !IsConnected(getEfd(clSock),NULL) ){
		/* may cause freezing on Win */
		return -1;
	}

	if( set_OWNER(Conn,host,port,user) < 0 )
		return -1;

	return 0;
}

/*
 * DGLEV was introduced in 8.2.0 for (condition)parameter.
 * it does not work with multi-sesion-threads mode.
 */
int G_DGLEV = SB_PROC;
int setDGLEV(Connection *Conn,int nlev){
	int olev;
	if( 1 < NUM_THSV ){
		if( Conn == 0 ){
			fprintf(stderr,"-- %X setDGLEV[%d] NULL Conn\n",
				TID,NUM_THSV);
			G_DGLEV = nlev;
		}
		olev = STX_lev;
		STX_lev = nlev;
	}else{
		olev = G_DGLEV;
		G_DGLEV = nlev;
	}
	return 0;
}
int getDGLEV(Connection *Conn,PCStr(what)){
	int olev;
	if( 1 < NUM_THSV ){
		if( Conn == 0 ){
			fprintf(stderr,"-- %X getDGLEV[%d] NULL Conn (%s)\n",
				TID,NUM_THSV,what);
			return G_DGLEV;
		}
		olev = STX_lev;
	}else	olev = G_DGLEV;
	return olev;
}
void xmem_pushX(Connection *Conn,void *addr,int size,PCStr(what),iFUNCP func)
{
	int lev = getDGLEV(Conn,what);
	if( SB_PROC < lev ){
		mem_push(lev,(char*)addr,size,what,func);
	}
}

int IsWindows95();
int have_publiclog();
static int ExecGeneralist(Connection *Conn,int fromC,int toC);
void beginGeneralist(Connection *Conn,int clsock);
/*
int RIDENT_recv(int clsock,PVStr(sockname),PVStr(peername));
*/
int RIDENT_recvX(int clsock,PVStr(sockname),PVStr(peername),int force);
void close_filterctls(Connection *Conn);
int aliveServ(Connection *Conn);
int clearServ(Connection *Conn);
int tobeREJECTED(Connection *Conn);

int SvSock_withRIDENT(int sstype);
int RIDENT_recvY(Connection *Conn,int clsock,PVStr(sockname),PVStr(peername),int force){
	int rcode;
	rcode = RIDENT_recvX(clsock,BVStr(sockname),BVStr(peername),force);
	if( 0 < rcode ){
		if( EscEnabled() ){
			IStr(host,MaxHostNameLen);
			wordScanY(peername,host,"^:");
			VA_gethostint_nbo(host,Rident_VAddr);
			scounter(1,&Rident_VAddr->I3,4,1);
		}
	}
	return rcode;
}
/*
#define RIDENT_recv(c,h,p) RIDENT_recvX(c,h,p,SvSock_withRIDENT(clSock->_clif._portFlags))
*/
#define RIDENT_recv(c,h,p) RIDENT_recvY(Conn,c,h,p,SvSock_withRIDENT(clSock->_clif._portFlags))

/*
static int recv_RIDENT(Connection *Conn,int clsock,PVStr(sock),PVStr(peer)){
	int remote;
	remote = RIDENT_recv(clsock,BVStr(sock),BVStr(peer));
	if( remote ){
		ClientFlags |= PF_RIDENT_RECV;
	}
	return remote;
}
#define RIDENT_recv(clsock,sock,peer) recv_RIDENT(Conn,clsock,sock,peer)
*/

int CTX_countdown(Connection *Conn,PCStr(wh)){
	int count;
	if( EscEnabled() ){
		if( Client_VAddr->I3 ){
			count = scounter(0,&Client_VAddr->I3,4,-1);
			daemonlog("E","Disconnected [%d] %s (%5.3fs)(%d) %s\n",
				ClientSock,"--",Time()-ACCEPT_TIME,count,wh);
			LOG_flushall();
		}
		if( Rident_VAddr->I3 ){
			scounter(1,&Rident_VAddr->I3,4,-1);
			Rident_VAddr->I3 = 0;
		}
	}
	return 0;
}

static void call_client1(Connection *Conn,Efd *clSock)
{	int clsock = getEfd(clSock);
	CStr(addr,512);
	CStr(clntinfo,512);
	int count;

	dumpstacksize("call_client1","");
	if( *PeernameOf(clSock) == 0 ){
		int remote;
		CStr(sockname,512);
		CStr(peername,512);

		remote = RIDENT_recv(clsock,AVStr(sockname),AVStr(peername));
		if( remote < 0 ){
			close(clsock);
			return;
		}
		setEfd(clSock,clsock,sockname,peername,remote);
	}

	if( execSPECIAL )
	sv1log(">>>>>>>> %s\n",execSPECIAL);

	if( isWindows() ){
	/* 9.0.3 On Windows without fork(), unconditional (client
	 * independent) initialization including ScanGlobal() is not
	 * yet finished here.  It is to be done in beginGeneralist().
	 * Thus setting DGLEV to SB_CONN before beginGeneralist() will
	 * push uninitialized status of config., as an unconditional
	 * FTOCL or TIMEOUT parameter for example, which will be popped
	 * in the second and after connections in StickyServer().
	 */
	}else
setDGLEV(Conn,SB_CONN);
	beginGeneralist(Conn,clsock);
setDGLEV(Conn,SB_CONN);
	if( 0 < clSock->_remote ){
		ClientFlags |= PF_RIDENT_RECV;
	}

	ACC_REJECTED = 0;
	if( setClientInfo(Conn,clSock,AVStr(addr),AVStr(clntinfo)) == 0 ){
		addAccHist(Conn,ACC_STARTED);
		if( lIMMREJECT() && (ConnectFlags & COF_SCREENED) ){
			/* new-140509a immediate disconn. by SCREEN with -Eri */
			sv1log("--SCREENed %s:%d\n",Client_Host,Client_Port);
		}else
		if( lIMMREJECT() && tobeREJECTED(Conn) ){
			IStr(accinfo,128);
			sprintf(accinfo,"%d << %s",
				clSock->_clif._acceptPort,Client_Host);
			sv1log("### Rejected %s\n",accinfo);
			putWinStatus("** Rejected %s",accinfo);
			addAccHist(Conn,ACC_FORBIDDEN);
		}else
		if( 0 < MAXCONN_PCH && MAXCONN_PCH < Conn->cl_count ){
			ACC_REJECTED = 1;
			sv1log("Too many connections(%d) %s\n",
				Conn->cl_count,clntinfo);
		}else	ExecGeneralist(Conn,clsock,clsock);
		if( EscEnabled() ){
			count = scounter(0,&Client_VAddr->I3,4,-1);
		}else
		count = ClientCountDown();
	}else	count = -1;
	if( EscEnabled() ){
		if( Rident_VAddr->I3 ){
			scounter(1,&Rident_VAddr->I3,4,-1);
			Rident_VAddr->I3 = 0;
		}
	}
	daemonlog("E","disconnected [%d] %s (%5.3fs)(%d)\n",
		clsock,clntinfo, Time()-ACCEPT_TIME,count);

	/*
	if( lACCLOG() ){
		if( ClientAuth.i_stat ){
			if( ClientAuth.i_error ){
				LOGX_authErr++;
			}else{
				LOGX_authOk++;
			}
		}else{
			LOGX_authNone++;
		}
	}
	*/

mem_pops(SB_CONN);
setDGLEV(Conn,SB_PROC);

	if( aliveServ(Conn) <= 0 )
	if( 0 <= ServerSock && file_isSOCKET(ServerSock) ){
		/* 9.6.3 socket to the server of a dead FSV=sslway thread or
		 * process left unclosed, and must be closed to save the leak
		 * of the file-descriptor
		 */
		int rcode;
		rcode = close(ServerSock);
		if( lMULTIST() ){
			/* should check if it's mine (TID == f_tid) ? */
			porting_dbg("--ServerSock[%d][%d] %d/%X close()=%d",
				ServerSock,SocketOf(ServerSock),
				ServerFilter.f_svsock,ServerFilter.f_tid,
				rcode
			);
		}
		sv1log("--ServerSock[%d] client1 %d/%X close()=%d %s://%s:%d\n",
			ServerSock,
			ServerFilter.f_svsock,ServerFilter.f_tid,rcode,
			DST_PROTO,DST_HOST,DST_PORT);
		ServerSock = -1;
	}
	/*
	 * wait children to die if possible
	 * This seems be necessary to make the TCP connections to client
	 * be normally closed on Windows95/98 ...
	 */
	if( Conn->xf_filters ){
		int pid,wi,done;
		int nch,mask;
		int nalive = 0;

		close_filterctls(Conn);
		waitPreFilter(Conn,300);

		nch = 0;
		for( mask = 0; mask < 32; mask++ )
			if( (1 << mask) & Conn->xf_filters )
				nch++;

		if( 0 < nch && 0 < waitFilterThread(Conn,300,XF_FCL) ){
			nch--;
		}
		if( aliveServ(Conn) ){
			/* don't wait FSV filter of server in keep-alive */
if( ServerFilter.f_tid )
Verbose("-- DONT WAIT FSV filter in keep-alive: %X\n",Conn->xf_filters);
			nch--;
		}else
		if( 0 < nch && 0 < waitFilterThread(Conn,300,XF_FSV) ){
			nch--;
		}
		if( 0 < nch && (Conn->xf_filters & XF_FSV) ){
			int na;
			if( na = aliveServ(Conn) ){
			/* if the server is alive with a filter process */
				if( ServerFlags & (PF_MITM_ON|PF_SSL_ON) ){
sv1log("FSV=sslway in Keep-Alive(*%d) nproc=%d\n",na,nch);
					nalive++;
					nch--;
				}
			}
		}

		done = 0;
		if( IsWindows95() )
		for( wi = 0; done < nch && wi < 5; wi++ ){
			while( 0 < (pid = NoHangWait()) ){
				done++;
				sv1log("CFI process [%d] done (%d/%d BEF-%d)\n",
					pid,done,nch,wi);
			}
			if( done < nch )
				msleep(100);
		}
		closeEfd(clSock);
		if( done < nch )
		for( wi = 0; done < nch && wi < 10; wi++ ){
			while( 0 < (pid = NoHangWait()) ){
				done++;
				sv1log("CFI process [%d] done (%d/%d AFT-%d)\n",
					pid,done,nch,wi);
			}
			if( done < nch )
			if( pid < 0 && errno == ECHILD ){
				sv1log("CFI process none (%d/%d)\n",done,nch);
				done = nch;
				break;
			}else{
				msleep(100);
			}
		}
		if( done < nch )
			sv1log("CFI process remaining (%d/%d)\n",
				nch-done,nch);
		else
		if( nalive ){
			sv1log("CFI process remaining (sv*%d)\n",nalive);
		}
	}

/* when `clsock' is closed in execGeneralist(), LOG_flushall() will reuse
 * the fd slot, then the slot will be closed in main as `clsock'.
 * Therefore call closeEfd() to avoid it... X-<
 */
	closeEfd(clSock);
	LOG_flushall();

	if( 0 <= LOG_center )
	if( have_publiclog() )
		put_publiclog(addr);
}

int func_inetd(void *Conn,int clsock);
void set_USER(Connection *Conn,int clsock);

void clearAdhocSERVER(Connection *Conn){
	Conn->cl.p_bound = 0;
	clearVStr(Serverurl0); /* this not multi-thread safe */
	mount_done = 0;
	rescanGlobal = 1;
}
int load_DYCONF(Connection *Conn,int clsock);

void beginGeneralist(Connection *Conn,int clsock)
{
	START_TIME1 = time(0);
	initConn(Conn,clsock);
	if( lSINGLEP() ){
		/* 9.9.8 for multiplexing connections over a YYMUX */
		GatewayFlags |= GW_IS_YYSHD;
		/* and should set longer YYMUX holding timeout ... */
	}
	if( scannedGlobal == 0 ){ /* without fork() */
		scanEnv(Conn,P_DYCONF,scan_DYCONF);
		scan_DYCONF(Conn,"(done)");
	}
	if( 0 < load_DYCONF(Conn,clsock) ){
		/* 9.9.8 loaded dynamic config. param. before config() */
	}
	if( func_inetd(Conn,clsock) )
		rescanGlobal = 1;
	config(Conn,clsock);
	if( BORN_SPECIALIST )
		set_USER(Conn,clsock);
}
void initDelegate1(Connection *Conn,int fromC,int toC)
{
	START_TIME1 = time(0);
	initConn(Conn,fromC);
	config(Conn,fromC);
}

void callDelegate1(int clsock,PCStr(imsg),PCStr(telehost),int teleport)
{	Connection ConnBuf, *Conn = &ConnBuf;

	initConn(Conn,clsock);
	config(Conn,clsock);
	DFLT_HOST[0] = 0; /* be Generalist ;-) */

	strcpy(TeleportHost,telehost);
	TeleportPort = teleport;

	if( imsg != NULL )
		DDI_pushCbuf(Conn,imsg,strlen(imsg));

	ExecGeneralist(Conn,clsock,clsock);
}

int callSelf(int clsock)
{	Connection ConnBuf, *Conn = &ConnBuf;

	initConn(Conn,clsock);
	config(Conn,clsock);
	Conn->from_myself = 1;
	return execGeneralist(Conn,clsock,clsock,-1);
}

int inShutdown(Connection *Conn,int toC);
int insert_FCLIENTS(Connection *Conn,int *fromCp,int *toCp);

static int ExecGeneralist(Connection *Conn,int fromC,int toC)
{	int fpid;
	int mypid;
	int rcode;

	if( inShutdown(Conn,toC) != 0 )
		return -1;

	mypid = getpid();
	fpid = insert_FCLIENTS(Conn,&fromC,&toC);
	Conn->xf_pidFFROMCL = fpid;
	rcode = execGeneralist(Conn,fromC,toC,-1);
	if( 0 < fpid ){
		if( Conn->xf_pidFFROMCL <= 0 ){
			/* waited in WaitShutdown() */
			fpid = 0;
		}
	}
	if( 0 < fpid ){
		if( mypid == getpid() )
			Kill(fpid,SIGTERM);
		else{
			/* can be a NNTPCC process with FFROMCL ... */
			sv1log("NNTPCC ? PID=(%d -> %d) XF=%x\n",mypid,getpid(),
				Conn->xf_filters);
			Conn->xf_filters = 0;
		}
		NoHangWait();
	}
	return rcode;
}

int gethostnameIFIF(PVStr(host),int size);
static int withSCREEN = 0;
int getNullFd(PCStr(what));
int setNullFd(int fd);
static int SRport;

static void env2str(PVStr(seqno),int size,int svsock,Efd *clSock)
{	int logfd;
	CStr(svhost,MaxHostNameLen);
	int statfd;
	refQStr(sp,seqno);

	gethostnameIFIF(AVStr(svhost),sizeof(svhost));

	logfd = curLogFd();

	/* statdata as a TMPFILE may not inherited to grand child on Win32 */
	if( iamServer() )
		statfd = put_svstat();
	else	statfd = SVSTAT_FD;
	/*
	else	statfd = -1;
	*/

	sprintf(sp,"%d/%d/%d/%d/%d/%d/%d/%d/%d/%f,",
		clSock->_fd,
		clSock->_clif._acceptPort,
		clSock->_clif._portProto,
		clSock->_clif._isAdmin,
		clSock->_clif._withAdmin,
		clSock->_clif._adminPort,
		clSock->_clif._userPort,
		clSock->_clif._yshPort,
		clSock->_clif._portFlags,
		clSock->_clif._ACCEPT_TIME
	);
	sp += strlen(sp);
	sprintf(sp,"%x/%d/%d/%d/%d/%d/%d/%d/%d/%d,",
		deleGateId,
		SERVER_PORT(),
		ServerPID,
		DELEGATE_LastModified,
		IamPrivateMASTER,
		svsock,
		param_file,
		TOTAL_SERVED,
		SERNO(),
		NUM_CHILDREN
	);
	sp += strlen(sp);
	Xsprintf(AVStr(sp),"%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%llX,",
		getNullFd("env2str"),
		LOG_initFd,
		SRport,
		StickyReport[1],
		DELEGATE_LINGER,
		logfd,
		LOG_type,
		LOG_type2,
		statfd,
		ekeyFd,
		withSCREEN,
		myPrivateMASTER,
		AF_UNIX_DISABLE,
		RES_localdns,
		clSock->_remote,
		p2ll(logMMap?getmmap(logMMap):0)
	);
	sp += strlen(sp);
	sprintf(sp,"%s/%s/%s/",
		svhost,
		SocknameOf(clSock),
		PeernameOf(clSock)
	);
}

int ViaVSAPassociator(int sock);
int DELEGATE_copyEnv(int mac,const char *av[],int ac,PCStr(path),PVStr(abuff));
void sendReservedPorts();

static int EXEC_client1(Connection *Conn,PCStr(path),PCStr(func),int svsock,Efd *clSock)
{	int clsock = getEfd(clSock);
	CStr(from,1024);
	CStr(seqno,256);
	CStr(stime,32);
	CStr(alive,32);
	CStr(abuff,MAX_ARGB);
	const char *av[MAX_ARGC]; /**/
	CStr(logtype,32);
	CStr(logtype2,32);
	CStr(dgroot,1024);
	int ac,ai;
	int ao;
	int port;
	int rcode;
	const char *cpath;
	int pid;
	int pass_svsock;
	CStr(ekeyb,32);

	pass_svsock = func != NULL &&
		(  streq(func,FuncSTICKY) && !ViaVSAPassociator(-1)
		|| streq(func,FuncFunc) );

	if( pass_svsock == 0 ){
		extern int SoxOutPort; 
		if( streq(func,FuncSTICKY) )
		if( SoxOutPort ){
			/* the port to which PrivateSox will forward */
			pass_svsock = 1;
		}
	}

	clSock->_clif._ACCEPT_TIME = ACCEPT_TIME;
	env2str(AVStr(seqno),sizeof(seqno),svsock,clSock);
	sendReservedPorts();
	Verbose("SEQNO: %s\n",seqno);

	ac = 0;
	av[ac++] = (char*)DeleGate1;
	av[ac++] = seqno;
	if( func != NULL ){
		av[ac++] = (char*)func;
	}else{
		scan_HOSTS0(Conn);
		strcpy(from,"src=");

/* getpeerName(clsock,from+4,PN_HOSTPORT); */
Conn->cl.p_connected = 1;
ClientSock = clsock;
if( port = getClientHostPort(Conn,QVStr(from+4,from)) )
Xsprintf(TVStr(from),":%d",port);

		Verbose("%s\n",from);
		av[ac++] = from;
	}
	if( 0 <= ekeyFd ){
		sprintf(ekeyb,"_ekeyFd=%d",ekeyFd);
		av[ac++] = ekeyb;
	}

	sprintf(stime,"%s=%d",P_START_TIME,START_TIME);
	av[ac++] = stime;
	sprintf(alive,"%s=%d",P_ALIVE_PEERS,NUM_CHILDREN);
	av[ac++] = alive;
	ac = DELEGATE_copyEnv(MAX_ARGC-1,av,ac,path,AVStr(abuff));
	sprintf(logtype,"-L0x%x/%d",LOG_type,curLogFd());
	av[ac++] = logtype;
	if( LOG_type2 || LOG_bugs ){
		sprintf(logtype2,"-L20x%X/%X",LOG_type2,LOG_bugs);
		av[ac++] = logtype2;
	}
	av[ac] = 0;
	ao = 0;
	for( ai = 0; ai < ac; ai++ ){
		if( strneq(av[ai],"-IO",3) ){
			continue;
		}
		av[ao++] = av[ai];
	}
	ac = ao;

	if( func != NULL && streq(func,FuncFunc) ){
		for( ai = 0; ai < ac; ai++ ){
			if( strncmp(av[ai],"-F",2) == 0 ){
				if( strcaseeq(av[ai]+2,"dget") ){
					/* FSV and STLS are necessary */
					av[ai] = "";
					continue;
				}
				ac = ai;
				av[ac] = 0;
				break;
			}
		}
	}

	/* 9.2.3 pass the determined DGROOT as an absolute path to
	 *  - suppress repetitve search for the determination
	 *  - avoid to be modified by environmental change
	 * it's not set when it's not specified explicitly in arg. or env.
	 */
	if( getv(av,P_DGROOT) == 0 ){
		sprintf(dgroot,"%s=%s",P_DGROOT,DELEGATE_DGROOT);
		av[ac++] = dgroot;
		av[ac] = 0;
	}

	if( !INHERENT_fork() ){
		setclientsock(clsock);
		if( pass_svsock )
			setserversock(svsock);
		return Spawnvp("EXEC_client1",path,av);
	}else{
		if( !pass_svsock )
			closeServPorts();
		Execvp("EXEC_client1",path,av);
		return -1;
	}
}

static void idleTIMEOUT()
{
	longjmp(exec_env,-1);
}
void setTimeout()
{
	setTimer(idle_timer,IDLE_TIMEOUT);
}
static void EXEC_client(Connection *Conn,PCStr(path),PCStr(func),Efd *clSock)
{
	int done = 0;

	idle_timer = pushTimer("EXEC_client",(vfuncp)idleTIMEOUT,0);
	if( setjmp(exec_env) == 0 ){
		if( lSYNC() ){
			call_client1(Conn,clSock);
		}else
		/*
		if( !(lEXEC() || lSEXEC()) && func == NULL ){
		*/
		if( !lEXEC() && func == NULL ){
			call_client1(Conn,clSock);
		}else	EXEC_client1(Conn,path,func,-1,clSock);
		done = 1; /* done without longjmp */
	}
	popTimer(idle_timer);

	if( done ){
		/* 9.6.3 this closedups(0) is added in 4.0.4 to avoid a
		 * problem (disconn. client with CFIscript?) on Windows but
		 * there canbe pending CFI output to be drained via
		 * the thread for FCL=sslway
		 */
		if( (ClientFlags & PF_SSL_ON)
		 || (Conn->xf_filters & XF_FTOCL)
		){
			double St = Time();
			int eth = endthreads();
			int TimeoutWait(double To);
			int xpid,ypid;
			if( actthreads() ){
				waitFilterThread(Conn,30*1000,XF_FCL);
				xpid = TimeoutWait(0.01);
				if( numthreads() <= endthreads() ){
					int thread_wait_errors(PVStr(st));
					IStr(st,128);
					thread_wait_errors(AVStr(st));
					putfLog("thread-zombi: %s",st);
					dumpThreads("thread-zombi");
				}
			}else{
				xpid = TimeoutWait(30);
			}
			ypid = TimeoutWait(1);
			sv1log("CFI-wait %d/%d A%d/%d as=%d xpid=%d,%d %.2f\n",
				endthreads(),eth,actthreads(),numthreads(),
				aliveServ(Conn),xpid,ypid,Time()-St);
		}
		closedups(0);
	}else{
		sv1log("TIMEOUT of idling.\n");
	}
}
void configX(PCStr(what),Connection *Conn,int ac,const char *av[]){
	const char *a1;
	int ai;

	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' )
			scan_arg1(Conn,NULL,a1);
		else	DELEGATE_addEnvExt(a1);
	}
	scannedGlobal = 0;
	DELEGATE_config(Conn,ClientSock);
	BREAK_STICKY = 1;
}

/*
 *	fork private MASTER if MASTER is not specified.
 *	this will be used for caching on {Gopher,FTP}/HTTP,
 *	and Connection Cache.
 */
int DELEGATE_copyEnvPM(int mac,const char *dav[],PCStr(name));
static int fork_MASTER(PVStr(hostport),int frominetd)
{	int svsock;
	int svport;
	CStr(svhost,MaxHostNameLen);
	const char *av[MAX_ARGC]; /**/
	int ai,ac;
	register int pid;
	const char *env;
	CStr(logtype,32);
	CStr(logfile,1024);
	CStr(port,128);
	CStr(oport,PORTSSIZE);
	CStr(what,128);
	CStr(master,1024);
	CStr(permit,128);
	const char *name;
	CStr(epath,1024);
	int closestdIO;

	svhost[0] = 0;
	svport = 0;
	Xsscanf(hostport,"%[^:]:%d",AVStr(svhost),&svport);
	if( svhost[0] == 0 )
		GetHostname(AVStr(svhost),sizeof(svhost));
	svsock = server_open("delegate",AVStr(svhost),svport,1);
	if( svsock < 0 )
		return -1;

	svport = sockPort(svsock);
	sprintf(hostport,"%s:%d",svhost,svport);

	printServPort(AVStr(oport),"",0);

	ac = 0;
	if( name = strrpbrk(EXEC_PATH,"/\\") )
		name = name + 1;
	else	name = EXEC_PATH;
	av[ac++] = name;

	sprintf(what,"%s%s)",PrivateMasterOwner,oport);
	av[ac++] = what;
	sprintf(port,"-P0/%d",svsock);
	av[ac++] = port; 

	sprintf(logtype,"-L0x%x",LOG_type);
	av[ac++] = logtype;
	sprintf(logfile,"%s=%s++",P_LOGFILE,oport);
	av[ac++] = logfile; 

	ac += DELEGATE_copyEnvPM(MAX_ARGC-ac,&av[ac],NULL);

	if( getEnv(P_MASTERP) )
		ac += DELEGATE_copyEnvPM(MAX_ARGC-ac,&av[ac],P_MASTER);

	sprintf(permit,"%s=*:*:{.,localhost}",P_PERMIT);
	av[ac++] = permit;
	sprintf(epath,"%s=%s",P_EXEC_PATH,EXEC_PATH);
	av[ac++] = epath;
	av[ac] = 0;

	if( closestdIO = frominetd || IamCGI ){
		sv1log("## private-MASTER: frominetd=%d IamCGI=%d (%d,%d,%d)\n",
			frominetd,IamCGI,
			fileno(stdin),fileno(stdout),fileno(stderr));
	}

	if( !INHERENT_fork() ){
		if( closestdIO ){
			av[ac++] = "CLOSE-STDIO";
			av[ac] = 0;
		}
		setserversock(svsock);
		pid = Spawnvp("fork_MASTER",EXEC_PATH,av);
	}else{
		pid = Fork("private-MASTER");
		if( pid == 0 ){
			LOG_closeall();
			if( closestdIO ){
				fclose(stdin);
				fclose(stdout);
				fclose(stderr);
			}
			closeServPorts();
			Execvp("fork_MASTER",EXEC_PATH,av);
		}
	}
	close(svsock);
	return pid;
}

static int unsetEnv(int mac,const char *dav[],const char *const sav[],PCStr(what))
{	const char *arg;
	int len,ai,ac;

	len = strlen(what);
	ac = 0;
	for( ai = 0; sav[ai]; ai++ ){
		if( dav != sav )
		if( mac <= ac )
			break;
		arg = sav[ai];
		if( strncmp(arg,what,len) == 0 )
			if( arg[len] == '=' || arg[len] == 0 )
				continue;
		dav[ac++] = (char*)arg;
	}
	dav[ac] = 0;
	return ac;
}

/*
 * Using private-MASTER even when connecting to HTTP might be
 * useful to control connection cache and keep-alive...
 */
static int filterEnv(int mac,const char *dav[],const char *sav[])
{	const char *arg;
	int ai,ac;

	ac = 0;
	for( ai = 0; sav[ai]; ai++ ){
		if( dav != sav )
		if( mac <= ac )
			break;
		arg = sav[ai];
		/* CONNECT and MASTER must be used in the private-MASTER. */
		if( strncmp(arg,"CONNECT=",8) == 0 ) continue;
		if( strncmp(arg,"MASTER=",7) == 0 ) continue;
		/* not to repeat execWithPrivateMASTER() */
		if( strncmp(arg,"MASTERP=",8) == 0 ) continue;
		/* -P with socket fd is set */
		if( strncmp(arg,"-P",2) == 0 ) continue;
		dav[ac++] = sav[ai];
	}
	dav[ac] = 0;
	return ac;
}
static void execWithPrivateMaster(Connection *Conn,PCStr(MasterP),int frominetd)
{	const char *av[MAX_ARGC]; /**/
	CStr(port,PORTSSIZE);
	CStr(master,128);
	CStr(masterp,128);
	CStr(hostport,MaxHostNameLen);
	int ac;

	strcpy(hostport,MasterP);
	myPrivateMASTER = fork_MASTER(AVStr(hostport),frominetd);
	if( myPrivateMASTER == 0 )
		return;

	ac = 0;
	if( 1 <= main_argc )
		av[ac++] = main_argv[0];
	av[ac++] = port; printServPort(AVStr(port),"-P",1);
	av[ac++] = master; sprintf(master,"%s=%s",P_MASTER,hostport);
	av[ac++] = masterp; sprintf(masterp,"_masterp=%d",myPrivateMASTER);

	filterEnv(elnumof(av)-ac,&av[ac],&main_argv[1]);
	filterEnv(0,(const char**)environ,(const char**)environ);

	if( !INHERENT_fork() ){
		setserversock(ServSock());
		Spawnvp("with-private-MASTER",EXEC_PATH,av);
		ServerPID = 0;
		closeServPorts();
		wait(0);
	}else{
		Execvp("with-private-MASTER",EXEC_PATH,av);
	}
	sv1log("private-MASTER forked: %s [%d]\n",hostport,myPrivateMASTER);
}

static void finalize()
{
	killChildren();
	StickyKill(SIGHUPTERM);
	kill_CC();
	deleteWORKDIR();
}

int killchildren();
void closeReservedPorts();
extern int DontFork;
static void _TERMINATE()
{
	terminating = 1;
	DontFork = 1;
	sv1log("TERMINATE...\n");
	dumpCKey(0);
	/*
	doing it here activates PollIn in main thread then termination
	(removing PortFile for -r restart) might not be completed successfully
	closeServPorts();
	*/
	finalize();
	/*
	LOG_deletePortFile();
	*/
	cleanup_zombis(0);
	if( !inSIGHUP ){
	/* can be Killpg(), don't kill processes to inherit sockets on Win32 */
	killchildren();
	}
	closeReservedPorts();
	closeServPorts();
	LOG_deletePortFile();  /* 9.9.1 should be after finished closing
				* server-ports for sync. kill_predecessor()
				*/

	sv1log("TERMINATED.\n");
	set_svtrace(3);
	terminating = 999;
}
void (*DELEGATE_TERMINATE)() = _TERMINATE;

#define ACC_FAILED	-1
#define ACC_TIMEOUTED	-2

static void _main(int ac,const char *av[]);
static int _mainx(int ac,const char *av[]){
	_main(ac,av);
	return 0;
}
static int _start(int ac,const char *av[])
{ 
	int ai,ao;
	const char *arg;

	isService = 1;
	RunningAsService = isService;
	ao = 0;
	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( *arg == '-' && arg[1] == 'I' ){
			getInheritedFds(arg+2);
			continue;
		}
		av[ao++] = arg;
	}
	ac = ao;

	_main(ac,av);
	sv1log("_main() done\n");
	return 0;
}
int (*DELEGATE_START)(int ac,const char *av[]) = _start;
int (*DELEGATE_MAIN)(int ac,const char *av[]) = _mainx;

static void sigALRM(int sig)
{
	sv1log("AcceptByMain: Frozen (%s) ? try restart...\n",ABMwhere);
	sigHUP(0);
	Finish(-1);
}

/* do substitution for ${xxx} like ${VARDIR} ? */
const char *absPathParam(PCStr(param),PCStr(prefix))
{	CStr(name,128);
	const char *vp;
	const char *rpath;
	CStr(apath,2048);
	const char *dp;
	CStr(xparam,2048);
	int nonexist;

	if( (vp = strchr(param,'=')) == 0 )
		return 0;
	Xsscanf(param,"%[^=]",AVStr(name));
	rpath = vp + 1;
	if( *rpath == 0 )
		return 0;

	if( isFullpath(rpath) )
		return 0;

	{	CStr(cwd,1024);
		const char *PATHSEP = "/";
		IGNRETS getcwd(cwd,sizeof(cwd));
		sprintf(apath,"%s%s%s",cwd,PATHSEP,rpath);
	}

	sprintf(xparam,"%s%s=%s",prefix,name,apath);
	if( nonexist = !File_is(apath) ){
		if( dp = strpbrk(apath," \t") ){
			truncVStr(dp);
			nonexist = !File_is(apath);
		}
		if( nonexist )
			fprintf(stderr,"CAUTION: nonexistent \"%s\"\n",xparam);
	}
	return stralloc(xparam);
}
void substArgvAbstpath(int ac,const char *av[])
{	int ai;
	const char *a1;
	const char *xa;

	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( strchr(a1,'=') == 0 )
			continue;
		xa = 0;
		if( strncmp(a1,  "+/",2) == 0 ) xa = absPathParam(a1+2,""); else
		if( strncmp(a1,"-e+/",4) == 0 ) xa = absPathParam(a1+4,"-e");
		if( xa )
			av[ai] = (char*)xa;
	}
}
static void setSTARTDIR()
{	CStr(cwd,1024);

	if( getenv("STARTDIR") )
		return;

	*cwd = 0;
	IGNRETS getcwd(cwd,sizeof(cwd));
	if( *cwd != 0 )
		PutEnv("STARTDIR",cwd);
}

int travlinks(PCStr(path),int ac,char *av[],PVStr(pb)){
	int ai;
	refQStr(pp,pb);
	CStr(rpath,1024);

	for( ai = 0; ai < ac; ai++ ){
		if( xrealpath(path,AVStr(rpath),sizeof(rpath)) == 0
		 || streq(path,rpath)
		){
			break;
		}
		path = pp;
		av[ai] = (char*)pp;
		strcpy(pp,rpath);
		pp += strlen(pp);
		setVStrPtrInc(pp,0);
	}
	return ai;
}
int todirv(int ac,char *av[]){
	int ai;
	const char *dp;

	for( ai = 0; ai < ac; ai++ ){
		if( dp = strrpbrk(av[ai],"/\\") )
			truncVStr(dp);
	}
	return ai;
}
int uniqv(int ac,const char *av[]){
	int ai,ao;
	ao = 0;

	for( ai = 0; ai < ac; ai++ ){
		av[ao] = av[ai];
		if( ai == ac-1 || !streq(av[ai],av[ai+1]) ){
			ao++;
		}
	}
	return ao;
}
int dirv(int pc,char *pv[],xPVStr(pb),PCStr(path)){
	int pn = 0;

	pv[pn++] = (char*)pb;
	strcpy(pb,path);
	pb += strlen(pb);
	setVStrPtrInc(pb,0);

	pn += travlinks(path,pc-1,pv+1,BVStr(pb));
	todirv(pn,pv);
	pn = uniqv(pn,(const char**)pv);
	return pn;
}

int DELEGATE_substPath(PCStr(what),int del,PCStr(path),PVStr(xpath)){
	CStr(spath,4096);
	refQStr(xp,xpath);
	CStr(l1,4096);
	CStr(l2,4096);
	refQStr(lp,l1);
	const char *sp;
	int pn = 0,pi;
	char *pv[4];
	CStr(pb,4096);

	if( lPATHFIND() )
		fprintf(stderr,"--- %s(%c) = %s\n",what,del,path);

	xp = xpath;
	if( xpath == path ){
		strcpy(spath,path);
		sp = spath;
	}else{
		sp = path;
	}
	for(; *sp; ){
		sp = scan_ListElem1(sp,del,AVStr(l1));
		if( *l1 == 0 )
		{
		/* should care a dir. ending with "\" before ";" on Win ... */
			if( *sp != 0 ){ /* 9.9.7 may be an empty member */
				continue;
			}
			break;
		}

		if( strstr(l1,"${EXECDIR}") ){
			if( pn == 0 ){
				pn = dirv(elnumof(pv),pv,AVStr(pb),EXEC_PATH);
			}
			strcpy(l2,l1);
			truncVStr(l1);
			lp = l1;
			for( pi = 0; pi < pn; pi++ ){
				if( l1 < lp ) setVStrPtrInc(lp,del);
				strcpy(lp,l2);
				strsubst(AVStr(lp),"${EXECDIR}",pv[pi]);
				lp += strlen(lp);
			}
		}

		substFile(l1);
		if( xp != xpath )
			setVStrPtrInc(xp,del);
		strcpy(xp,l1);
		xp += strlen(xp);
	}
	if( lPATHFIND() )
		fprintf(stderr,"--- %s(%c) = %s\n",what,del,xpath);
	return 1;
}

static void setLIBPATH()
{	CStr(libpath,1024);

	if( getenv(P_LIBPATH) )
		return;

	setEXEC_PATH();
	lineScan(DELEGATE_LIBPATH,libpath);
	DELEGATE_substPath("LIBPATH",';',libpath,AVStr(libpath));
/*
	substFile(libpath);
*/
	DELEGATE_LIBPATH = stralloc(libpath);
	PutEnv(P_LIBPATH,libpath);
}

extern const char *BINSHELL;
static void setBINSHELL()
{	const char *sh;
	CStr(path,1024);

	sh = getenv("BINSHELL");
	if( sh == NULL ){
		if( curCHROOT[0] == 0 )
			return;
		sh = "sh";
	}

	if( fullpathCOM(sh,"r",AVStr(path)) ){
		if( strcmp(BINSHELL,path) != 0 ){
			BINSHELL = stralloc(path);
			sprintf(path,"BINSHELL=%s",BINSHELL);
			putenv(stralloc(path));
		}
	}
	if( !isFullpath(BINSHELL) ){
		BINSHELL = "/bin/sh";
	}
}

static void putDGROOT(PVStr(dgmsg));
static void noargs()
{	CStr(yn,128);
	CStr(dgmsg,1024);

	put_identification(stderr);
	put_myconf(stderr);

	setDGROOT();
	putDGROOT(AVStr(dgmsg));
	fprintf(stderr,"--\r\n%s",dgmsg);

	fprintf(stderr,"Do configuration ? y / [n] : ");
	fflush(stderr);
	fgets(yn,sizeof(yn),stdin);
	if( yn[0] != 'y' && yn[0] != 'Y' )
		exit(0);

	fprintf(stderr,"-------------------------\n");
	fprintf(stderr,"INTERACTIVE CONFIGURATION\n");
	fprintf(stderr,"-------------------------\n");
	fprintf(stderr,"## see http://www.delegate.org/delegate/tutorial/\n");
}
static void scan_DELEGATE_ARGS(Connection *Conn)
{	const char *dgargs;
	const char *dgav[128]; /**/
	CStr(dgargb,1024);
	int dgac,dgai;

	if( dgargs = getenv("DELEGATE_ARGS") ){
		sv1log("DELEGATE_ARGS=%s\n",dgargs);
		dgac = decomp_args(dgav,128,dgargs,AVStr(dgargb));
		scan_args(dgac,dgav);
	}
}
static void set_eRESTART(int rtime){
	CStr(reason,128);
	refQStr(rp,reason); /**/
	reason[0] = 0;

	if( RESOLV_UNKNOWN ){
		sprintf(rp,"(%d unknown host)",RESOLV_UNKNOWN);
		rp += strlen(rp);
	}
	if( SCRIPT_UNKNOWN ){
		sprintf(rp,"(%d unknown script)",SCRIPT_UNKNOWN);
		rp += strlen(rp);
	}
	sv1log("eRESTART in %d sec %s config err.\n",rtime,reason);
}

static const char *sysfiles[] = {
	"/etc/resolv.conf",
	"/etc/localtime",
	"/etc/nsswitch.conf",
	"/etc/hosts",
	"/etc/passwd",
	"/dev/null",
	"/dev/urandom",
	0
};
static void copy_sysfiles(PCStr(rootpath))
{	const char *file;
	CStr(dgpath,1024);
	int fi;

	for( fi = 0; file = sysfiles[fi]; fi++ ){
		sprintf(dgpath,"%s/%s",rootpath,file);
		if( File_is(dgpath) == 0 )
			copyFileAndStat(file,dgpath);
	}
}

#define OLDCHROOT	"--CHROOT."
int Chroot(PCStr(rootpath),int ac,const char *av[])
{	int rcode,off,ai,nac;
	const char *nav[MAX_ARGC]; /**/
	CStr(xcompath,1024);
	CStr(dgrpath,1024);
	CStr(dgpath,1024);
	CStr(sdgpath,1024);
	CStr(chrootok,1024);
	const char *env;
	int withDGROOT,setDGROOT;
	int ei,ec;
	const char *dgd;
	CStr(me,MaxHostNameLen);
	CStr(hosts,MaxHostNameLen);
	CStr(path,4096);
	CStr(ii,32);

	setDGROOT = 0;
	if( *rootpath == 0 || strcmp(rootpath,"/") == 0 ){
		/* DGROOT=/path + CHROOT=/ -> CHROOT=/path + DGROOT=/ */
		rootpath = DELEGATE_DGROOT;
		setDGROOT = 1;
	}

	for( ai = 0; ai < ac; ai++ ){
		if( strncmp(av[ai],OLDCHROOT,strlen(OLDCHROOT)) == 0 ){
			goto CHROOT_OK;
		}
	}
	rcode = chroot(rootpath);
	if( rcode == 0 )
		goto CHROOT_OK;

	if( fullpathSUCOM("dgchroot","r",AVStr(xcompath)) == 0 ){
		daemonlog("F","---- CHROOT ERROR: cannot read dgchroot [%s]\n",
			xcompath);
		fprintf(stderr,"ERROR: %s not found\n","dgchroot");
		exit(-1);
	}

	if( env = getenv("PATH") ){
		strcpy(path,"PATH=subin:");
		linescanX(env,TVStr(path),sizeof(path)-strlen(path));
		putenv(stralloc(path));
	}

	copy_sysfiles(rootpath);

	if( dgd = strrpbrk(av[0],"/\\") )
		dgd++;
	else	dgd = av[0];
	sprintf(dgrpath,"subin/%s",dgd);
	if( fullpathLIB(av[0],"r",AVStr(sdgpath)) == 0 )
	if( fullpathCOM(av[0],"r",AVStr(sdgpath)) == 0 ){
		daemonlog("F","---- CHROOT ERROR: not found [%s]\n",av[0]);
		fprintf(stderr,"ERROR: %s not found\n",av[0]);
		exit(-1);
	}
	sprintf(dgpath,"%s/%s",rootpath,dgrpath);
	if( File_is(dgpath) == 0 
	 || File_mtime(dgpath) != File_mtime(sdgpath) ){
		copyFileAndStat(sdgpath,dgpath);
	}

	withDGROOT = 0;
	nac = 0;
	nav[nac++] = xcompath;
	nav[nac++] = (char*)rootpath;
	nav[nac++] = dgrpath; /* exec path */
	nav[nac++] = dgrpath; /* av[0] */
	for( ai = 1; ai < ac; ai++ ){
		if( strncmp(av[ai],"CHROOT=",7) == 0 ){
			continue;
		}
		if( strncmp(av[ai],"DGROOT=",7) == 0 ){
			if( setDGROOT ){
 fprintf(stderr,"#### ignore original DGROOT\n");
				continue;
			}
			withDGROOT = 1;
		}
		if( elnumof(nav)-4 <= nac ){
			break;
		}
		nav[nac++] = av[ai];
	}
	if( withDGROOT == 0 ){
		nav[nac++] = "DGROOT=/";
	}
	sprintf(chrootok,"%s%s",OLDCHROOT,rootpath);
	nav[nac++] = chrootok;

	gethostname(me,sizeof(me));
	strcpy(hosts,"HOSTS=");
	make_HOSTS(TVStr(hosts),me,0);
	nav[nac++] = hosts;
	nav[nac] = 0;

	ec = 0;
	for( ei = 0; env = environ[ei]; ei++ ){
		if( strncmp(env,"CHROOT=",7) == 0 ){
			continue;
		}
		if( ei != ec ){
			environ[ec] = environ[ei];
		}
		ec++;
	}
	if( ei != ec )
		environ[ec] = 0;

	if( 0 ){
		for( ai = 0; ai < nac; ai++ )
			daemonlog("F","---- CHROOT [%d] %s\n",ai,nav[ai]);
	}

	execvp(xcompath,(char*const*)nav);
	fprintf(stderr,"ERROR: failed %s for CHROOT=%s, errno=%d\n",
		xcompath,rootpath,errno);
	daemonlog("F","---- CHROOT ERROR: failed, errno=%d\n",errno);
	exit(-1);

CHROOT_OK:
	daemonlog("E","---- CHROOT ... OK\n");
	if( setDGROOT ){
		DELEGATE_DGROOT = "/";
	}
	return 0;
}

const char *DeleGateId(){
	static CStr(id,32);
	CStr(key,128);
	CStr(port,128);
	CStr(uniq,128);

	if( deleGateId == 0 ){
		NonceKey(AVStr(key));
		printPrimaryPort(AVStr(port));
		sprintf(uniq,"%s.%s",key,port);
		deleGateId = strCRC32(uniq,strlen(uniq));
	}
	sprintf(id,"DG%08x",deleGateId);
	return id;
}
/*
 * make the key be shared by the children, in a temporary file
 */
void setCKeyP(PCStr(param),PCStr(dom),PCStr(user),PCStr(ekey),int elen);
void setCKey(PCStr(ekey),int elen)
{
	setCKeyP(P_CRYPT,"master","",ekey,elen);
}

char PW_imp[] = "imp";
char PW_ext[] = "ext";
char PW_sudo[] = "sudo";
char PW_exec[] = "exec";

void setCKeyP(PCStr(param),PCStr(dom),PCStr(user),PCStr(ekey),int elen)
{	CStr(skey,64);
	CStr(epass,128);
	int len,wcc;
	FILE *cfp;
	int off;

	if( 0 <= ekeyFd ){
		cfp = fdopen(ekeyFd,"r+");
		fseek(cfp,0,0);
	}else{
		cfp = TMPFILE("CRYPT");
		ekeyFd = fileno(cfp);
		clearCloseOnExec(ekeyFd);
	}
	/*
	sprintf(skey,"%x.%d.%d",setCKey,serverPid(),file_ino(ekeyFd));
	serverPid() changes before and after beDaemin()
	*/
	sprintf(skey,"%x.%d",xp2i(setCKey),file_ino(ekeyFd));
	aencrypty(skey,strlen(skey),ekey,elen,epass);

	if( streq(param,P_PASSWD) ){
		if( streq(dom,PW_imp)  ) fseek(cfp,1*1024,0); else
		if( streq(dom,PW_ext)  ) fseek(cfp,2*1024,0); else
		if( streq(dom,PW_sudo) ) fseek(cfp,3*1024,0); else
		if( streq(dom,PW_exec) ) fseek(cfp,4*1024,0); else
					 fseek(cfp,5*1024,0);
	}
	off = ftell(cfp);
	wcc = fwrite(epass,1,strlen(epass),cfp);
	if( lCRYPT() ){
		fprintf(stderr,"##[%d] SetCK wr %s=%-4s [%4x-%4x] %d/%d\n",
			getpid(),param,dom,off,iftell(cfp),istrlen(epass),elen);
	}
	fflush(cfp);
	fcloseFILE(cfp);
}
int getCKeySec(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int ksiz);
int getCKey(PVStr(ekey),int ksiz)
{
	return getCKeySec(P_CRYPT,"master","",BVStr(ekey),ksiz);
}

int putImpKey(PCStr(opt),PCStr(ekey));
int getImpKey(PCStr(opt),PVStr(ekey));
int dumpCKeyParams(int mac,const char *av[],PVStr(abuf)){
	int ac = 0;
	refQStr(ap,abuf);
	CStr(ekey,128);

	if( 0 < getCKeySec(P_CRYPT,"master","",AVStr(ekey),sizeof(ekey)) ){
		av[ac++] = ap;
		av[ac] = 0;
		sprintf(ap,"CRYPT=pass:%s",ekey);
		ap += strlen(ap) + 1;
	}
	if( 0 < getCKeySec(P_PASSWD,PW_ext,"",AVStr(ekey),sizeof(ekey)) ){
		av[ac++] = ap;
		av[ac] = 0;
		sprintf(ap,"PASSWD=%s:::%s",PW_ext,ekey);
		ap += strlen(ap) + 1;
	}
	if( 0 < getCKeySec(P_PASSWD,PW_imp,"",AVStr(ekey),sizeof(ekey)) ){
		putImpKey("",ekey);
	}
	return ac;
}
void setTMPDIRX(PCStr(dir),int ovw);
static void setWinTMPDIR(){
	const char *dir = 0;

	if( isWindows() && !isWindowsCE() ){
		if( fileIsdir(dir = "C:/Windows/Temp") ){
			setTMPDIRX(dir,0);
		}else
		if( fileIsdir(dir = "/Windows/Temp") ){
			setTMPDIRX(dir,0);
		}
	}
}
static void getimpkey(){
	IStr(ekey,128);
	if( getImpKey("",AVStr(ekey)) ){
		setCKeyP(P_PASSWD,PW_imp,"",ekey,strlen(ekey));
	}
}

int getCKeySec(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int ksiz)
{	CStr(skey,64);
	CStr(epass,128);
	int klen,len;
	int off = 0;
	int noff = 0;

	if( ekeyFd < 0 ){
		setVStrEnd(ekey,0);
		/*
		daemonlog("F","DGAuth: ERROR getCkey(), ekeyFd=%d\n",ekeyFd);
		*/
		return 0;
	}
	Lseek(ekeyFd,0,0);
	if( streq(param,P_PASSWD) ){
		if( streq(dom,PW_imp)  ) off = lseek(ekeyFd,1*1024,0); else
		if( streq(dom,PW_ext)  ) off = lseek(ekeyFd,2*1024,0); else
		if( streq(dom,PW_sudo) ) off = lseek(ekeyFd,3*1024,0); else
		if( streq(dom,PW_exec) ) off = lseek(ekeyFd,4*1024,0); else
					 off = lseek(ekeyFd,5*1024,0);
	}
	/*
	klen = read(ekeyFd,epass,sizeof(epass));
	*/
	klen = read(ekeyFd,epass,sizeof(epass)-1);
	if( lCRYPT() ){
		noff = lseek(ekeyFd,0,1);
		fprintf(stderr,"##[%d] GetCK rd %s=%-4s [%4x-%4x] %d\n",
			getpid(),param,dom,off,noff,klen);
	}

	if( klen <= 0 )
	{
		if( lCRYPT() || klen < 0 )
		daemonlog("F","DGAuth: ERROR getCkey(%s=%s:%s), klen=%d\n",
			param,dom,user,klen);
		return 0;
	}

	setVStrEnd(epass,klen);
	/*
	sprintf(skey,"%x.%d.%d",setCKey,serverPid(),file_ino(ekeyFd));
	*/
	sprintf(skey,"%x.%d",xp2i(setCKey),file_ino(ekeyFd));

	/*
	len = adecrypty(skey,strlen(skey),epass,klen,(char*)ekey);
	*/
	len = adecrypty(skey,strlen(skey),epass,strlen(epass),(char*)ekey);
	if( lCRYPT() ){
		fprintf(stderr,"##[%d] GetCK rd %s=%-4s len=%d [%s]\n",
			getpid(),param,dom,len,0<=len?ekey:"?");
	}
	if( len <= 0 ){
		if( lCRYPT() || klen < 0 )
		daemonlog("F","DGAuth: ERROR getCkey(%s=%s:%s %s), len=%d\n",
			param,dom,user,skey,len);
	}
	return len;
}
int stripPortAttrs(PCStr(a1),PVStr(ports));
/*
void dumpCKeyPath(PVStr(path))
{
	dumpCKeyPathX("",P_CRYPT,"master","",BVStr(path));
}
*/
char *myName(PVStr(name),int osiz);
void dumpCKeyPathX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),PVStr(path))
{	CStr(ports,PORTSSIZE);
	CStr(md5,64);

	if( WinServ ) {
		/*
		IStr(me,128);
		myName(AVStr(me),sizeof(me));
		*/
		sprintf(ports,"EXECPATH=%s",main_argv[0]);
	}else
	if( privateDGAuth )
		strcpy(ports,"P0");
	/*
	else	printServPort(AVStr(ports),"P",0);
	*/
	else{ /* for getting CKey before -Pports are scanned */
		int ai;
		const char *a1;
		refQStr(pp,ports);
		setVStrEnd(pp,0);
		for( ai = 0; ai < main_argc; ai++ ){
			a1 = main_argv[ai];
			if( strneq(a1,"-P",2) ){
				Xsscanf(a1,"%[^/]",AVStr(pp)); /* for SIGHUP */
				stripPortAttrs(a1,AVStr(pp));
				strcat(pp," ");
			}else
			if( strneq(a1,"+=",2) ){
				sprintf(pp,"%s ",a1);
			}
			pp += strlen(pp);
		}
	}
	toMD5(ports,md5);
	if( !streq(param,P_CRYPT) ){
		CStr(xports,128);
		sprintf(xports,"%s.%s.%s",md5,param,dom);
		if( strchr(opts,'t') ){
			Xsprintf(TVStr(xports),".%d",file_ino(0));
		}
		if( strchr(opts,'u') ){
			Xsprintf(TVStr(xports),".%d",getuid());
		}
		toMD5(xports,md5);
	}
	sprintf(path,"${ADMDIR}/authorizer/%s/save/%s",md5,DGAUTHdom);

	if( streq(param,P_PASSWD) ){
		if( streq(dom,PW_imp)
		 || streq(dom,PW_ext)
		 || streq(dom,PW_sudo)
		 || streq(dom,PW_exec)
		){
			const char *atmp;
			if( isWindows() ){
				/* should be via registry ... */
				if( fileIsdir("C:/Windows/Temp") )
					atmp = "C:/Windows/Temp";
				else
				if( fileIsdir("/Windows/Temp") )
					atmp = "/Windows/Temp";
				else	atmp = "/Temp";
			}else{
				atmp = "/var/tmp";
			}
			strsubst(AVStr(path),"${ADMDIR}",atmp);
			/*
			strsubst(AVStr(path),"${ADMDIR}","/var/tmp");
			*/
		}
	}
	substFile(path);
	path_escchar(AVStr(ports));
	/*
	fprintf(stderr,"##Path(%s) %s %s\n",opts,param,path);
	*/
	/*
	servlog("%d ##Path(%s) %s %s %s\n",time(0),opts,param,dom,path);
	*/
}

int newPath(PVStr(path))
{	int len;

	if( File_is(path) )
		return 0;
	if( curCHROOT[0] == 0 )
		return 0;

	len = strlen(curCHROOT);
	if( strncmp(path,curCHROOT,len) == 0 ){
		if( File_is(path+len) ){
			ovstrcpy((char*)path,path+len);
			return 1;
		}
	}
	return -1;
}

void minits();
void syslog_init();
void setProcTitleHead(PCStr(arg0),int ac,const char *av[]);
void DO_INITIALIZE(int ac,const char *av[]);
void DO_STARTUP(int ac,const char *av[]);
void set_textconvCTX(Connection *Conn);

int asFunc(PCStr(arg1));
int IsFunc(int ac,const char *av[]){
	int ai;

	if( 0 < ac )
	if( asFunc(av[0]) )
		return 1;
	for( ai = 1; ai < ac; ai++ ){
		if( strneq(av[ai],"-F",2) )
			return 1;
	}
	return 0;
}

/*
 * 9.8.0 setting [DY]LD_LIBRARY_PATH env. var. from the "LDPATH" param.
 * the env. var. must be set before the init. of dyld on MacOSX 10.[23].
 * this automatic execution can be suppressed by adding "-.-x" as
 * the last commandline argument.
 */
int dylib_exec(PCStr(path));
static const char *inexec = "-.-x";
static int set_DYLIB(int ac,const char *av[]){
	const char *path;
	IStr(xpath,1024);
	IStr(av1,1024);
	const char **avx;
	int ai;

	if( ac < 1 )
		return ac;
	if( streq(av[ac-1],inexec) ){
		av[ac-1] = 0;
		return ac-1;
	}

	if( (path = getEnv(P_LDPATH)) == 0 ){
		path = DELEGATE_LDPATH;
	}
	if( path[0] ){
		substEXECDIR(path,AVStr(xpath),sizeof(xpath));
		substFile(xpath);
		if( dylib_exec(xpath) ){
			sprintf(av1,"%s%s",inexec,av[1]);
			avx = (const char**)malloc(sizeof(char*)*(ac+2));
			for( ai = 0; ai < ac; ai++ )
				avx[ai] = av[ai];
			avx[ai++] = inexec;
			avx[ai] = 0;
			Execvp("set-DYLIB",av[0],avx);
		}
	}
	return ac;
}

int checkSUDOAUTH(Connection *Conn,int ac,const char *av[]);
int checkEXECAUTH(Connection *Conn,int ac,const char *av[]);
int service_sudo(Connection *Conn,int svsock,int svport);
int controlSUDO[2] = {-1,-1};
SStr(portSUDO,64);
void startSUDO(Connection *Conn,int csock);
int forkSUDO(int ac,const char *av[],Connection *Conn,int csock);
static void setupSUDO(int ac,const char *av[],Connection *Conn){
	int pid;
	const char *a1;
	int ai;
	int sudo = 0;
	CStr(buf,1024);

	if( isWindows() ){
		return;
	}
	if( dosetUidOnExec("fork-SUDO",NULL,NULL,NULL) ){
		sudo = 1;
	}
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( a1[0] == '-' ){
			switch( a1[1] ){
				case 'u':
					sudo |= 2;
					break;
				case 'v':
					switch( a1[2] ){
					    case 0:
						LOG_type |= L_FG|L_TTY;
						break;
					}
					break;
			}
		}
	}
	if( sudo == 0 ){
		return;
	}

	Socketpair(controlSUDO);
	if( pid = Fork("SUDO") ){
		close(controlSUDO[0]);
		return;
	}
	close(controlSUDO[1]);
	dup2(open("/dev/null",0),0);
	dup2(open("/dev/null",1),1);

	/* setProcTitleHead("SUDO",ac,av); */
	if( forkSUDO(ac,av,Conn,controlSUDO[0]) != 0 ){
		_exit(-1);
		return;
	}

	sprintf(buf,"${LOGDIR}/sudo-error.log");
	DELEGATE_ERRORLOG = stralloc(buf);
	if( lTTY() ){
	}else{
		sprintf(buf,"${LOGDIR}/sudo.log");
		DELEGATE_LOGFILE = stralloc(buf);
	}
	ScanLogs(Conn,"sudo");

	if( geteuid() == 0 ){
		CStr(dgroot,1024);
		sprintf(dgroot,"%s/sudo",DELEGATE_DGROOT);
		DELEGATE_DGROOT = stralloc(dgroot);
	}
	sv0log("--SU start at DGROOT=%s\n",DELEGATE_DGROOT);

	service_sudo(Conn,-1,0);
	_exit(0);
}

extern int (*fullpath_cmd)(PCStr(path),PCStr(mode),PVStr(xpath));

void loadViaImp(Connection *Conn);
static void delegate_main(int ac,const char *av[])
{	Connection MainConn;
	int code;
	const char *root;
	int ai;
	int setd = 0;

	minits();
	mainConn = &MainConn; set_textconvCTX(mainConn);
	setthreadgid(0,getthreadid());

	setWinTMPDIR();
	setSTARTDIR();

	main_argc = ac;
	main_argv = dupv(av,0);
	LOG_stdlogfile = logfile;
	LOG_substfile  = substfile;
	fullpath_cmd = fullpathCOM;
	syslog_init();

	for( ai = 0; ai < ac; ai++ ){
		const char *arg;
		arg = av[ai];
		if( strcmp(arg,"-DCS") == 0 ){
			LOG_type4 |= L_UNSIGNEDCRC8;
		}else
		if( strncmp(arg,"-L40x",5) == 0 ){
			int lx = 0;
			sscanf(&arg[5],"%x",&lx);
			LOG_type4 |= L_UNSIGNEDCRC8 & lx;
		}else
		if( *arg == '_' && strneq(arg,"_ekeyFd=",8) ){
			sscanf(arg,"_ekeyFd=%d",&ekeyFd);
		}
		if( strncmp(arg,"-Ed",3) == 0 ){
			setd = 1;
		}
	}
	if( !streq(av[0],DeleGate1) ){
		if( isWindows() ){
			if( main_argc == 1 ){
				if( !file_is(0) ){
					getimpkey();
				}
				if( !file_is(0) && !file_is(1) ){
					WinServ = 2;
				}
			}
		}
		if( checkSUDOAUTH(mainConn,ac,av) != 0 ){
			fprintf(stderr,"DeleGate: checkEXECSUDO() failed.\n");
			exit(-1);
		}
	}
	loadViaImp(mainConn);

	/*
	loadDefaultConf();
	*/
	if( av[0] && DeleGate1 && streq(av[0],DeleGate1) ){
		/* don't apply the default .conf to child-processes (8.9.6) */
	}else
	loadDefaultConf(mainConn,ac,av);

	for( ai = 0; ai < ac; ai++ ){
		if( strncmp(av[ai],OLDCHROOT,strlen(OLDCHROOT)) == 0 ){
			lineScan(av[ai]+9,curCHROOT);
 fprintf(stderr,"#### save CHROOT=%s\n",curCHROOT);
		}
	}

	/*
	if( streq(av[0],DeleGate1) )
	*/
	if( streq(av[0],DeleGate1)
	 || getv(av,P_SOXOUTPORT) /* PrivateSox for HTMUX */
	)
	/* setup the logging environment inherited via spawn() */
	{	int lfd;
		const char *env;
		int ai;
		/*
		if( 1 < ac && strncmp(av[ac-1],"-L0x",4) == 0 ){
			sscanf(&av[ac-1][4],"%x/%d",&LOG_type,&lfd);
		*/
		for( ai = ac-1; 0 < ai; ai-- ){
		    if( strncmp(av[ai],"-L0x",4) == 0 ){
			lfd = -1;
			sscanf(&av[ai][4],"%x/%d",&LOG_type,&lfd);
			if( 0 <= lfd )
			fdopenLogFile(lfd);
			break;
		    }
		    if( strncmp(av[ai],"-L20x",5) == 0 ){
			sscanf(&av[ai][5],"%x/%x",&LOG_type2,&LOG_bugs);
			if( LOG_type2 & L_TIMEFMT ){
				setLogTimeFmtL(LOG_type2&L_TIMEFMT);
			}
		    }
		}
		LOG_type0 |= L_ISCHILD;
		if( env = getEnv(P_RES_DEBUG) )
			RES_debug(env);
		if( LOG_type & L_RAND_TRACE )
			RAND_TRACE = 1;
	}
	else{
		getEnvBin(""); /* init. */
		for( ai = 1; ai < ac; ai++ ){
			if( param_lock(PARAM_MAINARG,av[ai],&av[ai]) < 0 ){
				av[ai] = "";
			}
		}
	}
	iLOGinit();
	iLog("--- DO_STARTUP");
	DO_STARTUP(ac,av); /* setup sessionfd() and WSAstartup() on Win32.
	 * It must be done as immediate as possible after invocation,
	 * not to let wait the parent DeleGate to finish spawn procedure, and
	 * not to use DNS (which may take seconds, use socket)
	 * before it is initizlied...
	 */

	substArgvAbstpath(ac,av);
	ScanFileDefs(mainConn);
	appendProcLog(FL_ARG,getpid());

	if( getEnv(P_DYLIB) ){
		scan_DYLIB(getEnv(P_DYLIB));
		/* and do link before chroot() ? */
	}
	if( !streq(av[0],DeleGate1) ){
		if( setd )
		ac = set_DYLIB(ac,av);
	}

	if( 1 < ac && !streq(av[0],DeleGate1) && !IsFunc(ac,av) ){
		setupSUDO(ac,av,mainConn);
	}

	if( root = getEnv(P_CHROOT) ){
		if( Chroot(root,ac,av) != 0 ){
			fprintf(stderr,"DeleGate: chroot(%s) failed.\n",root);
			exit(-1);
		}
	}

	iLog("--- DO_INITIALIZE");
	DO_INITIALIZE(ac,av);
	if( terminating ){
		/* a service on Win, started and terminated in DO_INITIALIZE */
		Finish(0);
	}
	(*DELEGATE_MAIN)(ac,av);
	Finish(0);
}

void gotoWORKDIR();
void mainProcTitle(Connection *Conn);
void Exec_client(Connection *Conn,int ac,const char *av[]);
void setStickyParams(Connection *Conn,PCStr(proto));
int isNotStickyPort(Connection *Conn,Efd *clSock);
void setTeleportMASTER(Connection *Conn);
int execOnetimeFilter(Connection *Conn,Efd *clSock);
static void putREADY(int isafilter,int istunnel1);
static int AcceptByMain(Connection *Conn,int timeout,int *svsockp,Efd *clSock);
int forkOnetimeServer(Connection *Conn,int svsock,Efd *clSock,int isafilter);
int forkStickyServer(Connection *Conn,int svsock,Efd *clSock);
void setLOGCENTER(PCStr(center));
void setEXEC_PATH();
void putSTART(PCStr(what),int frominetd);
int logTimeout();
void load_params(Connection *Conn);
int pollServPort(int timeout,int *rsockv,int *udpv,int *optv);
int pollServPortX(int timeout,int *rsockv,int *udpv,int *optv,int *typev);
void dumpHTMLCONV();
void RshWatcher(int ninvoke,int port);
void udp_relayX(Connection *Conn,int csc,int csv[]);
int getServPorts(int sc,int sv[]);
int sox_main(int ac,const char *av[],Connection *ctx,int svsock,int svport);
int service_domain(Connection *Conn,int sock,int port);
void dns_init();
int service_ecc(Connection *Conn,int sock,int port);
int service_icp(Connection *Conn,int sock,int port);
int service_syslog(Connection *Conn,int sock,int port);
int service_cuseeme(Connection *Conn,int svsock,int myport);
int service_sudo(Connection *Conn,int svsock,int myport);
int TeleportServer(PCStr(tunnel),PCStr(invites));
int checkDGAuthConfig();
int set_Owner(int real,PCStr(aowner),int file);
void makeEntrance();
void setServUDP();
void setSERVER_PORT(PCStr(host),int port,int sock);
void setSERVER_PORTX(PCStr(host),int port,int sock,int stype);
int activeServPort();
int withDGAuth(Connection *Conn);
void inetdServPort();
int authRsh();
int fromRsh();
int fromInetd();
void new_param_file(PCStr(path));
FILE *new_shared();
void reopenLogFile();
void editconf1(int *acp,const char **avp[],FILE *in,FILE *out);
int DELEGATE_subfunc(Connection*Conn,int ac,const char *av[],PCStr(func),int _Fopt,int type);
int defineAdminSTLS(Connection *Conn);

const char *ACTDIR();
int softbreakFile(PCStr(what),PCStr(serv),PVStr(path)){
	if( serv == 0 || *serv == 0 )
		serv = get_svname();
/*
	sprintf(path,"${ACTDIR}/restart/%s",serv);
	substFile(path);
*/
	sprintf(path,"%s/restart/%s",ACTDIR(),serv);
	return 0;
}
/*
int getSoftBreak(Connection *Conn,PCStr(serv)){
*/
int getSoftBreakX(PCStr(F),int L,Connection *Conn,PCStr(serv)){
	CStr(path,1024);
	FILE *fp;
	int st;

	if( lSINGLEP() ){
		return 0;
	}
	if( softbreakFile("get",serv,AVStr(path)) == 0 ){
		CStr(wh,128);
		sprintf(wh,"SoftBreak-%s:%d",F,L);
		/*
		if( fp = dirfopen("SoftBreak",AVStr(path),"r") ){
		*/
		if( fp = dirfopen(wh,AVStr(path),"r-") ){
			fclose(fp);
		}
		st = File_mtime(path);
		if( START_TIMEP < st ){
			sv0log("---- got.SoftBreak(%s) [%X %X][%s]\n",
				serv,START_TIMEP,File_mtime(path),path);
			StopKeepAlive = 1;
			BREAK_STICKY = 1;
			return 1;
		}else{
			return 0;
		}
	}
	return 0;
}
int setSoftBreak(Connection *Conn,PCStr(serv)){
	CStr(path,1024);
	FILE *fp;

	if( softbreakFile("set",serv,AVStr(path)) == 0 ){
		if( fp = dirfopen("SoftBreak",AVStr(path),"w") ){
			fprintf(fp,"%d\n",getpid());
			fclose(fp);
			sv0log("---- set.SoftBreak(%s) [%X %X][%s]\n",
				serv,START_TIMEP,File_mtime(path),path);
		}
		/* touch it: the clock of the file system might be diff. */
		File_touch(path,time(0));
	}
	StopKeepAlive = 1;
	BREAK_STICKY = 1;
	return 0;
}

int toSafeFileName(PCStr(name),PVStr(xname)){
	refQStr(xp,xname);
	CStr(uname,1024);
	const char *np;
	unsigned char nc;
	int IS_SJIS_STR(unsigned char *str);

	if( strchr(name,'\033') || IS_SJIS_STR((unsigned char*)name) ){
				   /* and not EUC-JP ... */
		TO_euc(name,AVStr(uname),sizeof(uname));
		name = uname;
	}
	for( np = name; nc = (unsigned char)*np; np++ ){
		switch( nc ){
			case '.':
				if( name < np ){
					setVStrPtrInc(xp,nc);
					break;
				}
				xp += sprintf(xp,"%%%02X",nc);
				break;
			case '!': case '"': case '%': case '&': case '\'':
			case '(': case ')': case '*': case '/':
			case ':': case ';': case '<': case '>': case '?':
			case '[': case '\\': case ']': case '^':
			case '`':
			case '{': case '|': case '}':
				xp += sprintf(xp,"%%%02X",nc);
				break;
			default:
				if( nc < 0x20 || 0x7F <= nc ){
					xp += sprintf(xp,"%%%02X",nc);
				}else{
					setVStrPtrInc(xp,nc);
				}
				break;
		}
	}
	setVStrEnd(xp,0);
	return 0;
}
int fromSafeFileName(PCStr(name),PVStr(xname)){
	URL_unescape(name,BVStr(xname),0,0);
	return 0;
}
int dgconfigFile(PCStr(what),PCStr(name),PVStr(path)){
	if( name == NULL ){
		strcpy(path,"${ADMDIR}/config/");
	}else
	if( *name == 0 || streq(name,"default") )
		strcpy(path,"${ADMDIR}/config/${PORT}.cnf");
	else{
		CStr(xname,1024);
		toSafeFileName(name,AVStr(xname));
		sprintf(path,"${ADMDIR}/config/%s.cnf",xname);
	}
	substFile(path);
	return 0;
}
int getConfig(PCStr(name),PVStr(path)){
	FILE *fp;
	dgconfigFile("get",name,BVStr(path));
	if( fp = dirfopen("getConfig",AVStr(path),"r") ){
		fclose(fp);
		return 1;
	}
	return 0;
}
int putConfig(PCStr(name),PCStr(mode),PCStr(conf)){
	CStr(path,1024);
	FILE *fp;
	dgconfigFile("put",name,AVStr(path));
	if( fp = dirfopen("putConfig",AVStr(path),mode) ){
		fputs(conf,fp);
		if( strtailchr(conf) != '\n' )
			fputc('\n',fp);
		fclose(fp);
		return 1;
	}
	return 0;
}

void setSHUTOUT();
const char *ADMDIR();
const char *ACTDIR();

void daemonStarted(int isdaemon){
	if( isdaemon ){
		fflush(stdout);
		fflush(stderr);
		setSTDLOG();
	}
	iLOGstop();
	if( LOG_VERBOSE )
		iLOGdump(0,"---- trace of initialization ----\n");
}
int getServStat(PCStr(proto),int *act);
void makeDeleGateHTM(){
	int port,act;
	FILE *fp;
	IStr(path,1024);

	if( (port = getServStat("/admin",0))
	 || (port = getServStat("http",0))
	 || (port = getServStat("http-proxy",0)) ){
		sprintf(path,"%s/%s",DELEGATE_DGROOT,"DeleGate.htm");
		if( fp = dirfopen("DGHTML",AVStr(path),"w") ){
			IStr(stime,128);
			StrftimeLocal(AVStr(stime),sizeof(stime),
				TIMEFORM_ANSI_C,time(0),0);
			fprintf(fp,"DeleGate/%s started at %s<BR>\r\n",
				DELEGATE_ver(),stime);
			fprintf(fp,
	"DeleGate <A HREF=http://localhost:%d/-/admin/setup>Setup</A>\n",
				port);
			fclose(fp);
			Verbose("DeleGate.HTM: %d %s\n",port,path);
		}
	}
}

int SimulateAC(int ac,const char *av[],Connection *Conn);
int startSockMux();
int service_disabled(PCStr(proto));
void setCredhyCache(PCStr(dir));
void set_MAXIMA(Connection *Conn,int update);
void ThreadServers(Connection *Conn);
void setupUDPlog(DGC*Conn);
static void FixedNumServers(Connection *Conn);
int NOSOCKINH_FD = 0x10000;

int load_CAPSKEY(int init);
void scan_CAPSKEY(Connection *Conn,PCStr(capskey));
void print_caps(FILE *out,int test);
int Gmtoff();

double ServerStarted;
static void _main(int ac,const char *av[])
{	FILE *fp;
	int clsock;
	Efd *clSock = clientSocks;
	register int pid;
	const char *name;
	const char *func;
	const char *ext;
	const char *env;
	const char *proto;
	Connection *Conn = mainConn;
	int xcode;
	int frominetd,isafilter,isteleportd;
	int issockmux;
	int istunnel1;
	int cnt;
	int restart;
	int reinit = 0;
	int IamServer;
	int ai;
	int isDaemon = 0;
	int OPTSscan = 0;
	int withDGA;
	int restarting = 0;
	int dmsync = -1;
	int gobg = 0;
	int svpid = 0;
	const char *stopss = 0; /* stop ans sweep StickyServer on exit */

	Gmtoff(); /* initialize gmt_off */
	if( env = getv(av,"_isService") ){
		isService = atoi(env);
		RunningAsService = isService;
		/* 9.9.7 indicates that it is started as service and restarted
		 * on HUP. This flag suppresses the trial to terminate previous
		 * server (-r) and startng DeleGate as a service (beDaemon())
		 * both are not necessary in this case.
		 */
	}
	if( env = getEnv("_ServerPid") ){
		svpid = atoi(env);
		ServerPid = svpid;
	}

	putWinStatus("** Initializing ...");
	for( ai = 1; ai < ac; ai++ ){
		const char *arg;
		arg = av[ai];
		if( strncmp(arg,"-F",2) == 0 ){
			/* 9.9.1 for -Fany2fdif -b name (9.4.3) */
			break;
		}
		if( *arg == '-' && arg[1] == 'b' ){
			if( arg[2] ){
				waitBG = atoi(&arg[2]);
			}else{
				gobg = 1;
			}
		}
	}
	if( gobg )
	if( isatty(0) || isatty(1) )
	{
		sv1log("goBackground...\n");
		if( !isWindows() ){
			if( Fork("goBackground") != 0 ){
				exit(0);
			}
		}
	}

	P_LV("-- _main START");
	iLog("--- _main START");
	if( main_argc == 1 && 1 < ac ){
		/* started as a service on Windows, main() receives no
		 * arguments, then _main() receives real arguments via
		 * the ServiceStart. Thus DGROOT which was initialized
		 * in delegate_main() must be reinitialized here after. 
		 */
		DELEGATE_DGROOT = "";
		isDaemon = 1;
	}
	main_argc = ac;
	main_argv = dupv(av,0);
	if( isDaemon ){
		setDGROOT();
		/* DGROOT is necessary to fine +=servname */
	}
	loadCommonConf(Conn);


	ACCEPT_TIME = Time();
	clSock->_clif._ACCEPT_TIME = Time();
	signal(SIGHUP,SIG_IGN);

	if( EXEC_PATH[0] && isFullpath(EXEC_PATH) ){
		/* set in loadDefaultConf(ac,av) */
	}else
	if( isFullpath(av[0]) )
		strcpy(EXEC_PATH,av[0]);
	else	wordscanX(av[0],AVStr(EXEC_PATH),1024);

	/* set LIBPATH for library.a (ex. JIS.c)
	 * this must be done after EXEC_PATH is set.
	 */
	setLIBPATH();
	setBINSHELL();
	setSHUTOUT();
	ADMDIR();
	ACTDIR();
	setCredhyCache(ACTDIR());

	if( name = strrpbrk(EXEC_PATH,"/\\") )
		name = name + 1;
	else	name = EXEC_PATH;

	istunnel1 = 0;
	if( func = getEnvBin(P_FUNC) ){
		InvokeStats |= INV_IMPFUNC;
	}else
	if( (func = getEnv(P_FUNC)) == 0 )
		func = name;
	for( ai = 1; ai < ac; ai++ ){
		if( strncmp(av[ai],"-F",2) == 0 ){
			func = &av[ai][2];
			Fopt = ai;
		}else
		if( strncmp(av[ai],"SERVER=tunnel1",14) == 0 ){
			istunnel1 = 1;
		}
	}

	if( (ext = (const char*)strcasestr(func,".exe")) && ext[4] == 0 ){
		func = StrAlloc(func);
		*(char*)strcasestr(func,".exe") = 0;
		/*
		*strcasestr(func,".exe") = 0;
		*/
	}

	if( strstr(func,"cgi") )
		IamCGI = 1;

	START_TIME1 = time(0);

	if( strncmp(func,"kill",4) == 0 ){
		func = "kill";
	}

	ConnInit(Conn); /* set RPORTsock=-1 before -Ffunc */
	for( ai = 1; ai < ac; ai++ ){
		const char *a1;
		a1 = av[ai];
		if( strneq(a1,"-f",2) ){
			LOG_type |= L_FG;
			switch( a1[2] ){
				case 'f': InvokeStats |= INV_ASFILTER; break;
				case 'd': InvokeStats |= INV_ASDAEMON; break;
			}
		}
	}
	P_LV("-- _main ConnInit() DONE");
	iLog("--- _main ConnInit() DONE");
	dont_check_param = 1;

	if( IsFunc(ac,av) ){ /* fix-140509c for +=script -> load_script() */
		if( env = getEnv(P_DGPATH) )
			DELEGATE_DGPATH = env;
		scan_DGPATH(DELEGATE_DGPATH);
	}
	isFunc = DELEGATE_subfunc(Conn,ac,av,func,Fopt,0);
	dont_check_param = 0;
	if( isFunc ){
		GatewayFlags |= GW_COMMAND;
	}

	frominetd = fromInetd();
	P_LV("-- _main fromInetd()=%d",frominetd);
	iLog("--- _main fromInetd()=%d",frominetd);
	isafilter = 0;
	isteleportd = streq(func,"teleportd");
	issockmux = strcaseeq(func,"sockmux");
	IamPrivateMASTER = 0;

	if( SERVER_PORT() == 0 )
	if( !isFunc && !isteleportd )
	if( ac < 2 && !frominetd && !IamCGI ){
		if( getEnvBin(P_SERVER) || getEnvBin(P_FUNC) ){
		}else{
		noargs();
		editconf1(&ac,&av,stdin,stderr);
		}
	}

	if( IamCGI ){
		setEXEC_PATH();
		if( env = getEnv(P_DGPATH) )
			DELEGATE_DGPATH = env;
		scan_DGPATH(DELEGATE_DGPATH);
		ac = scan_args(ac,av);
	}

	for( ai = 0; ai < ac; ai++ ){
		int encrypted_script(PCStr(name));
		if( strstr(av[ai],"+=") ){
			if( encrypted_script(av[ai]) ){
				init_CRYPT(Conn,1);
				break;
			}
		}
	}

	putWinStatus("** Initializing ...");
	/*
	if( !isFunc || isteleportd )
	*/
	if( !isFunc || isteleportd || issockmux )
	if( !IamCGI )
	if( !streq(EXEC_PATH,DeleGate1) ) /* is the parent delegated */
	{
		ERROR_RESTART = 0;

		setEXEC_PATH();
		if( env = getEnv(P_DGPATH) )
			DELEGATE_DGPATH = env;
		scan_DGPATH(DELEGATE_DGPATH);

		ac = scan_args(ac,av);
		scan_DELEGATE_ARGS(Conn);
		if( issockmux ){
			/* 9.9.0 to let the mapping of "127.0.0.1" and "__1"
			 * with "localhost" be consistent with the parent.
			 */
			scan_HOSTS0(Conn);
		}
		Scan_SERVER0(Conn); /* scan "-Pxxx" in SERVER=url:-:-Pxxx */

		if( lRCONFIG() ){
			CStr(conf,1024);
			/* save commandline arguments here ... */
			if( getConfig("default",AVStr(conf)) ){
				sv1log("#### load_script(%s)\n",conf);
				load_script(NULL,NULL,conf);
				/* and scan_args for ext_args */
			}
		}

		scanEnv(Conn,P_DGOPTS,scan_DGOPTS); /* for DGOPTS=-r */
		OPTSscan = 1;

		if( isService ){
			sv1log("## ignored -r in a service\n");
		}else
		if( ME.me_restart ){
			restarting = 1;
			kill_predecessor(ac,av,"",0);
			ME.me_restart = 0;
		}

		reopenLogFile(); /* reopen LOGFILE with a proper PORT number */

		if( !istunnel1 )
		if( frominetd == 0 )
		if( numServPorts() == 0 ) /* no -P option given */
		if( getEnv(P_INETD) == 0 )
		if( (InvokeStats & INV_ASDAEMON) == 0 )
		if( (InvokeStats & INV_ASFILTER) != 0
		 || 0 < file_issock(0) && 0 < file_issock(1) )
		{
			sv1log("## maybe from SSH/RSH as a filter\n");
			frominetd = 1;
		}

		_setTMPDIR(getEnv(P_TMPDIR));
		if( !IamPrivateMASTER ){
			new_shared();
			if( env = getEnv(P_INPARAM) )
				new_param_file(env);

			if( !frominetd ){
				if( fromRsh() ){
					if( authRsh() != 0 )
						Finish(-1);
				}
			}
			if( istunnel1 ){
				setTeleportMASTER(Conn);
			}
			if( frominetd ){
				InvokeStats |= INV_ASFILTER;
				isafilter = 1;
				inetdServPort();
			}
		}
		setup_exeid(Conn);
	}
	if( !ME.me_accsimul )
	if( DELEGATE_getEnvX(P_SAC,PARAM_ALL & ~PARAM_ENV) ){
		fprintf(stderr,"---- Simulating Access Control ---\n");
		LOG_type |= L_TTY | L_FG;
		ME.me_accsimul = 1;
	}

	if( OPTSscan == 0 )
	scanEnv(Conn,P_DGOPTS,scan_DGOPTS);

	if( getEnv(P_INETD) ){
		STANDBY_MAX = 0;
		scanEnv(Conn,P_INETD,scan_INETD);
		if( restarting ){
			/* INETD without -Pxxx */
			kill_predecessor(ac,av,"",0);
		}
		/* "port stream tcp nowait owner SERVER=exec XFIL=... */
		/* "port stream tcp nowait owner SERVER=exec XCOM=... */
		/* "port stream tcp wait owner SERVER=... */
		/* PollIns(ports) */
		/* wait -- don't accept, just exec */
		/* nowait -- accept and exec */
	}
	scanGGlobals(Conn,1);

	isFunc = DELEGATE_subfunc(Conn,ac,av,func,Fopt,1);

	if( checkVer() != 0 ){
		Finish(-1);
		return;
	}

	if( streq(EXEC_PATH,DeleGate1) )
	{
		load_CAPSKEY(0);
		scanEnv(Conn,P_DGSIGN,scan_DGSIGN);
		_setTMPDIR(getEnv(P_TMPDIR));/* for Resolvy cache originally */
		signal(SIGTERM,sigTERM1);
		signal(SIGINT, sigTERM1);
		signal(SIGHUP, sigTERM1);
		/* should set SIGSEGV handler ? */
		Exec_client(Conn,ac,av);
		Finish(0);
		fprintf(stderr,"\n[%d] DeleGate: exit from DeleGate1 failed.\n",
			getpid());
		return;
	}
	/* if( with filter params ) */{
		int getLockFile(PCStr(dir),PCStr(file),PVStr(lkpath));
		CStr(dir,128);
		CStr(name,128);
		CStr(path,1024);
		int fd;
		CStr(fenv,1024);
		CStr(envb,32);
		FILE *fp;

		fp = NULL;
		primaryPort(AVStr(name));
		Strins(AVStr(name),"CFI-SHARED-");
		strcpy(dir,"${TMPDIR}");
		substFile(dir);
		if( 0 <= (fd = getLockFile(dir,name,AVStr(path))) ){
			chmod(path,0600);
			sprintf(fenv,"CFI_SHARED_LOCK=%s",path);
			putenv(stralloc(fenv));
			close(fd);
		}

		fp = TMPFILE("CFI_SHARED");
		CFI_SHARED_FD = fileno(fp);
		if( lFILEDESC() ){
			fprintf(stderr,"--{F} CFI_SHARED_FD=%d %s\n",
				CFI_SHARED_FD,path);
		}
		clearCloseOnExec(fileno(fp));
		sprintf(envb,"CFI_SHARED_FD=%d",fileno(fp));
		putenv(stralloc(envb));
	}

	/*
	if( !IamPrivateMASTER ){
		checkADMIN(Conn,proto);
		validateEmailAddr(getADMIN1(),0);
	}
	*/
	notify_ADMIN(Conn,"start");

	if( LOG_initFd < 0 ){
		FILE *fopenInitLog(PCStr(name),PCStr(mode));
		const char *mode;
		FILE *fp;
		if( isService )
			mode = "a+";
		else	mode = "w+";

		if( fp = fopenInitLog(get_svname(),mode) ){
			LOG_initFd = fileno(fp);
			fseek(fp,0,2);
			fprintf(fp,"-- InitLog for [%s]\n",get_svname());
			fflush(fp);
		}
		if( fp == NULL ){
		LOG_initFd = fileno(TMPFILE("LOG_init"));
		clearCloseOnExec(LOG_initFd);
		}
	}

	if( LOG_init_enable == 0 ){
	LOG_init_enable = 1;
		lock_exclusiveNB(LOG_initFd);
	}
	inINITIALIZATION = 1;
	if( curLogFp() ){
	putSRCsign(curLogFp());
	putBLDsign(curLogFp());
	}
	putWinStatus("** Initializing ...");
	putSTART("START",frominetd);
	sv1log("BINSHELL=%s\n",BINSHELL);

	START_TIME = time(0);

	set_MAXIMA(Conn,0);
	scan_HOSTS0(Conn);
	if( env = getEnv(P_TIMEOUT)) scanEnv(Conn,P_TIMEOUT,scan_TIMEOUT);
	if( env = getEnv(P_MAXIMA))  scanEnv(Conn,P_MAXIMA,scan_MAXIMA);

/* check UDP before mkEntrance */
proto = Scan_SERVER(Conn);
if( streq(proto,"cuseeme") ) DELEGATE_LISTEN = -1;
if( streq(proto,"udprelay") ) DELEGATE_LISTEN = -1;
if( streq(proto,"icp") ) DELEGATE_LISTEN = -1;
if( streq(proto,"dns") ) DELEGATE_LISTEN = -1;
if( streq(proto,"syslog") ) DELEGATE_LISTEN = -1;
if( streq(proto,"teleport") ) isteleportd = 1;

	if( service_disabled(proto) ){
		fprintf(stderr,"Disabled: %s\n",proto);
		sv1log("Disabled: %s\n",proto);
		Finish(-1);
	}

	withDGA = 0;
	ScanDirDefs(Conn); /* ADMDIR is necessary as service on Win32 */
	scanEnv(Conn,P_AUTH,scan_AUTH); /* to find AUTH=admin:-dgauth:... */
	if( streq(proto,DGAUTHpro) ){
		if( SERVER_PORT() == 0 ){
			privateDGAuth = 1;
		}
		init_CRYPT(Conn,0);
		withDGA = 1;
	}else
	if( withDGAuth(Conn) || getEnv(P_CRYPT) ){
		init_CRYPT(Conn,1);
		withDGA = 1;
	}

	defineAdminSTLS(Conn);
	if( streq(iSERVER_PROTO,"ftp") || streq(iSERVER_PROTO,"ftps") ){
		scan_TLSCONF(Conn,"shutdown");
	}
	if( getEnv(P_STLS) )
	if( doneCRYPT == 0 && withDGA == 0 ){
		sv1log("scan STLS and FILTERS before beDaemon()...\n");
		scanEnv(Conn,P_TLSCONF,scan_TLSCONF);
		scanEnv(Conn,P_STLS,  scan_STLS);
		scan_FILTERS(Conn);
	}

	if( !isteleportd )
	if( env = getEnv(P_LOGCENTER) )
		setLOGCENTER(env);

	load_CAPSKEY(1);
	if( getEnv(P_CAPSKEY) ){
		scanEnv(Conn,P_CAPSKEY,scan_CAPSKEY);
		print_caps(stderr,0);
	}

	/* 940930 beDaemon() moved before the TUNNEL_open to let
	 *        PGID of TUNNEL processes to be that of delegated.
	 */
	if( !lFG() && !lSYNC() )
	if( !IamPrivateMASTER )
	if( !istunnel1 )
	if( !issockmux )
	if( !IamCGI )
	if( activeServPort() == 0 )
	{
		if( !streq(proto,"sockmux") )
		if( numServPorts() == 0 ){
			fprintf(stderr,"*** ERROR: NO ACTIVE PORT\r\n");
			Finish(-1);
		}
		dmsync = beDaemon(Conn,isService,waitBG);
		isDaemon = 1;
		Conn->cx_pid = Getpid(); /* to approve the magic in Conn */
	}

	if( SERVER_PORT() == 0 )
	{
		if( isteleportd ){
			/* for compatibility with "teleportd" program */
			setSERVER_PORT("",8000,-1);
		}
	}
	if( streq(proto,DGAUTHpro) ){
		int sock,port;
		CStr(host,MaxHostNameLen);
		sock = DGAuth_port(1,AVStr(host),&port);
		if( 0 <= sock ){
			setSERVER_PORT("localhost",port,sock);
		}
	}

	if( streq(proto,"udprelay1") ){
		extern int IO_TIMEOUT;
		IO_TIMEOUT = 60;
		if( getEnv(P_CONNECT) == NULL )
			scan_CONNECT(Conn,"udp");
		setServUDP();
	}

	if( 0 <= controlSUDO[1] ){
		primaryPort(FVStr(portSUDO));
		startSUDO(Conn,controlSUDO[1]);
	}

	/*
	 * makeEntrance() is here to, may be(-_-;, to avoid giving
	 * SVsock to TUNNEL processes.
	 */
	if( getEnv(P_SOXOUTPORT) == 0 ){
		/* setup VSAP port for HTMUX accept, if not in PrivateSox */
		/* for HTMUX with HTMUX=cl:host:port */
		scanEnv(Conn,P_HTMUX,scan_HTMUX);
		if( AccViaHTMUX ){
			putREADY(isafilter,istunnel1);
		}
	}
	scanEnv(Conn,P_VSAP,scan_VSAP);

	if( !AccViaHTMUX )
	if( !ViaVSAPassociator(-1) ) /* NOT to accept at remote associator */
	if( !IamCGI )
	if( getEnv("_masterp") == 0 )/* NOT in execWithPrivateMASTER() */
	{
		if( isWindows() ){
			/* before doing SUDO for -Pxx */
			AF_UNIX_DISABLE = 1;
		}
	    if( lFXNUMSERV() && isWindows() ){
	    }else{
		recv_socks();
		if( restarting ){
			extern double BINDENTER_TIMEOUT;
			extern double BIND_TIMEOUT1;
			BIND_TIMEOUT1 = BINDENTER_TIMEOUT;
			makeEntrance();
			BIND_TIMEOUT1 = 0;
		}else
		makeEntrance();
		scanEnv(Conn,P_PORT,scan_PORT); /* fix-140509d for non -Fkill */
	    }
		if( getEnv(P_SOXOUTPORT) ){
			/* suppress the banner in private SockMux */
		}else
		putREADY(isafilter,istunnel1);
	}
	RES_isself(ServSock());

	/*
	 * makeEntrance() should be before set_Owner() to use privireged port.
	 */
	if( set_Owner(1,getEnv(P_OWNER),curLogFd()) < 0 )
		Finish(-1);
	if( checkEXECAUTH(Conn,ac,av) < 0 ){
		Finish(-1);
	}

	mkdirForSolaris(); /* should be after set_Owner() */
	proto = Scan_SERVER(Conn);

	/* These should be done after "SERVER" scanned
	 * (to use DFLT_PROTO in defaultPERMIT() ?)
	 */
	ServerPID = getpid(); /* might be referred in init. config. */
	ScanGlobal(Conn,proto);
	if( withDGA ) /* after AUTHORIZER is scanned in ScanGlobal() */ {
		if( checkDGAuthConfig() != 0 ){
			/* Finish(-1); */
		}
	}

	if( !IamPrivateMASTER ){
		checkADMIN(Conn,proto);
		ScanFileDefs(Conn);
		if( checkCACHEDIR(Conn) != 0 )
			Finish(-1);
	}

	if( env = getEnv("LINGER") ) DELEGATE_LINGER = atoi(env);
	ServerPID = getpid();
	DeleGateId();
	gotoWORKDIR();
	mount_all(Conn,proto);


	if( env = getEnv(P_TUNNEL) ){
		sv1log("SET TUNNEL AS MASTER: %s\n",env);
		scan_MASTER(Conn,"tty7:0/teleport");
	}

	if( IamPrivateMASTER ){
		int ai;
		for( ai = 0; ai < ac; ai++ )
			svlog("> arg[%d] %s\n",ai,av[ai]);
		/*
		somthing wrong (accept lock failure?)(at NNTP/HTTP proxy?)
		3.0.59: YES. lLOCK() was turned off in setupForSolaris()
		*/
		setStickyParams(Conn,proto);

	}else{
		if( env = getEnv("_masterp") ){
			myPrivateMASTER = atoi(env);
		}else
		if( env = getEnv(P_MASTERP) ){
			execWithPrivateMaster(Conn,env,frominetd);
		}else
		if( streq(proto,"http") ){
			compatV5info("No default private-MASTER. MASTERP=\"\"");
		}

		if( !lFORK() )
			setStickyParams(Conn,proto);

		ScanFileDefs(Conn);
		ScanEachConn(Conn);
		/*load_resources(Conn);*/
	}

	if( !isteleportd )
	if( IamPrivateMASTER || myPrivateMASTER == 0 )
		TeleportPID = TeleportServer(getEnv(P_TUNNEL),getEnv(P_INVITE));

	mySoxPid = startSockMux();

	if( AccViaHTMUX ){
		/* for accept on non -Pxxx/remote port */
		int openLocalServPorts();
		openLocalServPorts();
	}

	if( istunnel1 ){
		sv1log("TeleportPID = %d\n",TeleportPID);
		while( 0 < (pid = wait(0)) ){
			sv1log("child dead: pid=%d\n",pid);
			if( pid == TeleportPID )
				break;
		}
		goto EXIT;
	}

	if( streq(proto,"http") || BORN_SPECIALIST == 0 ){
		int size;
		size = expand_stack(2*1024*1024);
		STACK_SIZE = size;
		sv1log("#### stack size limit = %X (%d)\n",size,size);
	}

	if( !streq(proto,"http") )
		PEEK_CLIENT_REQUEST = 0;

	if( streq(proto,"dns") && 1 < numServPorts() ){
		PutPortFile(1);
	}else
	if( 0 < StickyMAX_PARA )
		PutPortFile(1);
	else	PutPortFile(0);

	signal(SIGURG, sigURG);
	signal(SIGBUS, sigFATAL);
	signal(SIGSEGV,sigFATAL);
	signal(SIGILL, sigFATAL);
	if( lNOSIGPIPE() ){
		signal(SIGPIPE,SIG_IGN);
	}else
	signal(SIGPIPE,sigPIPE);
	signal(SIGTERM,sigTERM);
	signal(SIGINT, sigTERM);
	if( istunnel1 )
		signal(SIGHUP, sigTERM);
	else	signal(SIGHUP, sigHUP);
	setWatchChild();

	if( StickyReport[0] < 0 || StickyReport[1] < 0 )
		setupStickyReport(StickyReport);
		/*
		Socketpair(StickyReport);
		*/

	pid = 0;
	DELEGATE_dumpEnv(NULL,1,IamPrivateMASTER);
	setLastModified();

	Verbose("Accept-LOCK: %d\n",LOG_type & L_LOCK);
	StickyProcs = (Proc*)StructAlloc((StickyMAX_PARA+1)*sizeof(Proc));

	if( NUM_HUPS ){
		sv1log("NUM_HUPS=%d\n",NUM_HUPS);
	}
	putSTART("DONE",frominetd);
	putWinStatus("** Initialized");
	scanEnv(Conn,P_DGSIGN,scan_DGSIGN);

	syncDaemon(dmsync);
	if( lSTRICT() ){
		if( RESOLV_UNKNOWN || SCRIPT_UNKNOWN ){
			int ai;
			for( ai = 0; ai < ac; ai++ ){
				sv1log("#### arg[%d] %s\n",ai,av[ai]);
			}
			set_svtrace(4);
			daemonlog("F","#### Aborted on Configuration Error.\n");
			Finish(-1);
		}
	}
	LOG_init_enable = 0;
	lock_unlock(LOG_initFd);
	set_svtrace(2);
	inINITIALIZATION = 0;

	if( lFILEDESC() && curLogFp() != 0 ){
		sv1log("----active file descriptors----\n");
		dumpFds(curLogFp());
		fflush(curLogFp());
	}

	if( streq(proto,"sudo") ){
		service_sudo(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( streq(proto,"cuseeme") ){
		service_cuseeme(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( streq(proto,"ecc") || streq(proto,"http-sp") ){
		setDebugX(Conn,"-Ecc",0);
		service_ecc(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( streq(proto,"icp") ){
		service_icp(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( streq(proto,"syslog") ){
		service_syslog(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	if( streq(proto,"dns") ){
		daemonStarted(isDaemon);
		signal(SIGBUS, exitFATAL);
		signal(SIGSEGV,exitFATAL);
		dns_init(/*SERVER_PORT()*/);
		service_domain(Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	/*
	if( streq(proto,"sockmux") ){
	*/
	if( issockmux
	 || streq(proto,"sockmux") &&
	  ( SERVER_PORT() <= 0 /* without -Pxxx */
	  || *iSERVER_HOST && !isMYSELF(iSERVER_HOST) /* SERVER=sockmux://H:P */
	  )
	){
		if( lFG() ){
		}else
		/*
		if( iamPrivateSox() )
		if( getenv("SSH_CONNECTION") )
		*/
		if( isatty(fileno(stdout)) && isatty(fileno(stderr)) ){
			/* to disconnect output tty from remote via SSH */
			fflush(stdout);
			fflush(stderr);
			setSTDLOG();
		}
		daemonStarted(isDaemon);
		scanEnv(Conn,P_CONNECT,scan_CONNECT);
		sox_main(ac,av,Conn,ServSock(),SERVER_PORT());
		Finish(0);
	}
	isFunc = DELEGATE_subfunc(Conn,ac,av,func,Fopt,2);
	if( DELEGATE_LISTEN <= 0 ){
		int fdc,fdv[64];
		fdc = getServPorts(64,fdv);

		if( getEnv(P_CONNECT) )
			scanEnv(Conn,P_CONNECT,scan_CONNECT);
		else	scan_CONNECT(Conn,"None");

		udp_relayX(Conn,fdc,fdv);
		goto EXIT;
	}

	if( isafilter )
	if(!istunnel1 ){
		if( execOnetimeFilter(Conn,clSock) == 0 )
			goto EXIT;
	}

	if( !IamPrivateMASTER && getpid() == ServerPID ){
		if( myPrivateMASTER ){
			/* wait the private-MASTER ready */
		}
		if( fromRsh() && SERVER_PORT() != 0 ){
			RshWatcher(NUM_HUPS,SERVER_PORT());
		}
	}

	MainLastAccept = time(0);

	/*
	if( ERROR_RESTART )
	*/
	if( 0 < MAX_ERESTART )
	if( RESOLV_UNKNOWN || SCRIPT_UNKNOWN ){
		/*
		SERVER_RESTART = (NUM_HUPS+1)*(NUM_HUPS+1)*ERROR_RESTART;
		sv1log("SERVER_RESTART=%d (%d)\n",SERVER_RESTART,NUM_HUPS);
		*/
		if( NUM_HUPS <  MAX_ERESTART && 0 < ERROR_RESTART ){
		SERVER_RESTART = ERROR_RESTART;
		set_eRESTART(ERROR_RESTART);
		}
		if( NUM_HUPS == MAX_ERESTART && 0 < ERROR_RESTART
		 || NUM_HUPS == 0 && ERROR_RESTART == 0
		){
			sv1log("#### restarting is set on config err.\n");
			iLOGdump(0,"---- ERROR in initialization ----\n");
			reinit = 1;
		}
	}
	if( lSINGLEP() && reinit ){
		putWinStatus("** reinit %d %d",RESOLV_UNKNOWN,SCRIPT_UNKNOWN);
		askWinOK("** reinit %d %d",RESOLV_UNKNOWN,SCRIPT_UNKNOWN);
		reinit = 0;
	}
	if( SERVER_RESTART ){
		int now;
		CStr(date,64);

		now = time(0);
		if( 3600*24 <= SERVER_RESTART )
			restart = timeBaseDayLocal(now) + SERVER_RESTART;
		else	restart = ((now/SERVER_RESTART)+1) * SERVER_RESTART;
		StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_HTTPD,restart,0);
		sv1log("RESTART at %s\n",date);
	}

	IamServer = (getpid() == ServerPID);
	if( IamServer ){
		set_CC();
	}

	if( frominetd ){
		/* NDELAY may be left ON by former user of the socket */
		SetNonblockingIO("svsock",ServSock(),0);
		/*
		repetitive listen() is fatail at least in Solaris2.6
		set_listenX(ServSock(),DELEGATE_LISTEN);
		*/
	}

	if( IamServer && LOG_VERBOSE && getEnv(P_URICONV) ) dumpHTMLCONV();

	signal(SIGALRM,sigALRM);

	/*
	if( LOG_type & L_REINIT && NUM_HUPS == 0 ){
	*/
	if( !ME.me_accsimul )
	if( ViaVSAPassociator(-1) == 0 ) /* no local connect with -Pxxx@vsap */
	if( reinit || (LOG_type & L_REINIT) && NUM_HUPS == 0 ){
		int nready,sockv[FD_SETSIZE],udpv[FD_SETSIZE];
		int isset = 0;

		sv1log("#### wait the first contact...\n");
		if( isDaemon ){
		    const char *via;
		    const char *from;

		    if( (from = getenv("REMOTE_ADDR")) || fromSSH() ){
			CStr(local,128);
			CStr(remote,128);
			CStr(fromb,256);
			if( from ){
				via = "CGI/SSI";
			}else{
				via = "SSH";
				getpairName(0,AVStr(local),AVStr(remote));
				sprintf(fromb,"[%s]<-[%s]",local,remote);
				from = fromb;
			}
			daemonlog("F","-- seems via %s %s\n",via,from);
			printf("## seems via %s %s ##\n",via,from);
			fflush(stdout);
			fflush(stderr);
			setSTDLOG(); /* to close the PIPE of the CGI */
			isset = 1;
		    }
		}
		if( !isset )
		if( isDaemon )
		{
			sv1log("#### output reg:%d fifo:%d socket:%d/%d\n",
				file_isreg(fileno(stdout)),
				file_isfifo(fileno(stdout)),
				file_issock(fileno(stdout)),
				file_isSOCKET(fileno(stdout))
			);
			if( !file_isreg(fileno(stdout))
			 || !file_isreg(fileno(stderr))
			){
				/* to suppress SIGPIPE on the stdout/err */
				fflush(stdout);
				fflush(stderr);
				setSTDLOG();
				isset = 1;
			}
		}
		if( !isset )
		if( isDaemon )
		if( isatty(fileno(stdout)) && isatty(fileno(stderr)) )
		{	/* to disconnect output tty from remote via SSH */
			fflush(stdout);
			fflush(stderr);
			setSTDLOG();
		}
		/*
		nready = pollServPort(0,sockv,udpv,NULL);
		*/
		for(;;){
			nready = pollServPort(5*1000,sockv,udpv,NULL);
			if( svpid || nready ){
				sv1log("-- ppid=%d/%d nready=%d\n",
					svpid,procIsAlive(svpid),nready);
			}
			if( svpid && !procIsAlive(svpid) ){
				sv1log("-- ppid=%d/%d nready=%d BROKEN\n",
					svpid,procIsAlive(svpid),nready);
				Finish(0);
			}
			if( nready ){
				break;
			}
		}
		sv1log("#### got the first contact\n");
		sigHUP(0);
	}

	if( isDaemon ){
		fflush(stdout);
		fflush(stderr);
		setSTDLOG();
	}
	if( lNOMMAPLOG() || lSINGLEP() ){
		LOG_owner = LOG_WH_SHARED;
	}else
	if( logMMap = filemmap("","w+",0,sizeof(LogControls)) ){
		errno = 0;
		if( logMMap->m_fp ){
			fwrite(logControl,1,sizeof(MMap),(FILE*)logMMap->m_fp);
			fflush((FILE*)logMMap->m_fp);
		}
		if( errno == ENOSPC ){
			NoTmpSpace();
		}else{
		inMMapWrite = 1;
		*(LogControl*)logMMap->m_addr = *logControl;
		inMMapWrite = 0;
		logControl = (LogControl*)logMMap->m_addr;
		LOG_owner = LOG_WH_SHARED;
		sv0log("logMMap: %X %d\n",p2i(logMMap->m_addr),logMMap->m_size);
		}
	}else{
		sv0log("logMMap: NOT-AVAILABLE\n");
	}
	if( EscEnabled() ){
		scounter(0,0,0,0);
	}
	if( lNOUDPLOG() ){
	}else{
		setupUDPlog(Conn);
	}
	restoreAuthMan();

	iLOGstop();
	if( LOG_VERBOSE )
		iLOGdump(0,"---- Initialization Finised ----\n");
	dumpstacksize("_main loop start","");

	if( ME.me_accsimul ){
		Finish(SimulateAC(ac,av,Conn));
	}
	ServerStarted = Time();

	makeDeleGateHTM();
	LOG_type3 |= L_INITDONE;

	if( SERVER_PORT() != 0 ){
		/* 9.9.3 sweep left sockets (9.6.3-pre6) */
		void sweepSockets(int all);
		sweepSockets(0);
	}

	if( EccEnabled() ){
		int startCCSV(Connection *Conn);
		ccsvPid = startCCSV(Conn);
	}

	logSigblock = 1; /* 9.9.4 MTSS sigblock(SIGTERM) in lputLog() */

	if( lFXNUMSERV() ){
		FixedNumServers(Conn);
	}else
	if( lSINGLEP() ){
		ThreadServers(Conn);
	}else
	for(cnt = 1;;cnt++){
		int idle,timeout,logtimeout,svsock;
		int now,sched_next;
		int ndead;

		if( svpid && !procIsAlive(svpid) ){
			sv1log("-- ppid=%d/%d BROKEN\n",
				svpid,procIsAlive(svpid));
			break;
		}

		ndead =
		cleanup_zombis(0);
		if( IamServer && getSoftBreak(Conn,"") ){
			sv0log("## SoftBreak detected\n");
			if( IamServer ){
				sigHUP(0);
				break;
			}
		}

		if( SERVER_RESTART_SERNO
		 && SERVER_RESTART_SERNO <= MainNaccepted ){
			fprintf(stderr,"---- RESTART %d/%d\n",
				MainNaccepted,SERVER_RESTART_SERNO);
			sigHUP(0);
			break;
		}

		if( restartPrivateMASTER ){
			restartPrivateMASTER = 0;
			if( IamServer ){
				sigHUP(0);
				break;
			}
		}

		load_params(Conn);

		/*
		TOTAL_SERVED = CHILD_SERNO_SINGLE + StickyNserved; 
		*/
		*pTOTAL_SERVED = CHILD_SERNO_SINGLE + StickyNserved; 

		if( IamPrivateMASTER && getppid() != IamPrivateMASTER ){
			sv1log("private-MASTER DONE: OWNER seems dead. %d/%d\n",
				getppid(),IamPrivateMASTER);
			break;
		}

		if( MAX_SERVICE ){
			if( MAX_SERVICE <= TOTAL_SERVED ){
				sv1log("MAX_SERVICE done: %d\n",MAX_SERVICE);
				stopss = "MAX_SERVICE";
				break;
			}
		}

		now = time(0);
		if( SERVER_TIMEOUT ){
			idle = now - MainLastAccept;
			if(  SERVER_TIMEOUT < idle ){
				sv1log("SERVER_TIMEOUT: %d seconds.\n",idle);
				stopss = "SERVER_TIMEOUT";
				break;
			}
		}

		mainProcTitle(Conn);
		logtimeout = logTimeout();
		if( 0 < NUM_CHILDREN || IamPrivateMASTER ){
			timeout = 60;
			if( logtimeout != 0 && logtimeout < timeout )
				timeout = logtimeout;
		}else{
			timeout = logtimeout;
			if( timeout <= 0 )
				timeout = 0;
		}

		if( SERVER_RESTART ){
			int rstimeout;

			rstimeout = restart - now;
			if( timeout == 0 || rstimeout < timeout ){
				timeout = rstimeout;
				if( timeout <= 0 ){
					sigHUP(0);
					break;
				}
			}
		}

		if( SERVER_TIMEOUT )
		if( timeout == 0 || SERVER_TIMEOUT < timeout )
			timeout = SERVER_TIMEOUT;

if( !IamPrivateMASTER && IamServer )
if( timeout <= 0 || 15 < timeout )
timeout = 15;

sched_next = sched_execute(now,(iFUNCP)sched_action,Conn);
if( now < sched_next && sched_next-now < timeout )
	timeout = sched_next-now;

if( RESTART_NOW ){
	RESTART_NOW = 0;
	sigHUP(0);
	break;
}

		/*putStatus("Accept(%d,1,%d): nch=%d\n",ServSock(),timeout,
			NUM_CHILDREN);*/

		if( DELEGATE_PAUSE ){
			sleep(10);
			continue;
		}

		set_MAXIMA(Conn,1);
		if( 0 < SIGALRM ) alarm(300);
		clsock = AcceptByMain(Conn,timeout,&svsock,clSock);
		if( 0 < SIGALRM ) alarm(0);

		if( clsock < 0 ){
			if( terminating ){
				sv1log("main loop break on TERMINATE.\n");
				return;
			}
			/*putStatus("TIMEOUT\n");*/
			LOG_checkAged(0);
			if( clsock != ACC_TIMEOUTED )
				msleep(ACC_BYMAIN_INTERVAL);
			continue;
		}else{
			putLoadStat(ST_ACC,1);
			MainNaccepted++;
			if( lSYNC() ){ 
				CHILD_SERNO_MULTI++;
			}else	CHILD_SERNO++;
		}

		MainLastAccept = time(0);
		/*putStatus("Accepted[%d]\n",CHILD_SERNO);*/

		if( lSYNC() ){
			StickyNserved++;
			EXEC_client(Conn,EXEC_PATH,NULL,clSock);
			initConn(Conn,-1);
		}else
		/*
		if( !lEXEC() && StickyActive < StickyMAX_PARA ){
		*/
		if( !lEXEC() && StickyActive < StickyMAX_PARA
		 && !isNotStickyPort(Conn,clSock)
		){
			pid = forkStickyServer(Conn,svsock,clSock);
/*
if( pid <= 0 ){
	sv1tlog("CANNOT FORK Sequential, (%d children)\n",StickyActive);
	cleanup_zombis(0);
	pid = forkStickyServer(Conn,svsock,clSock);
and set MAXIMA=delegated automatically temporalily ?
}
*/
			if( pid <= 0 ){
				TraceLog("? cannot fork Sticky (%d)\n",errno);
				sv1tlog("CANNOT FORK Sequential (%d)\n",errno);
			}else{
				StickyAdd(pid);
				NUM_CHILDREN++;
				logChild("StickyServer",1);
			}
		}else{
			pid = forkOnetimeServer(Conn,svsock,clSock,isafilter);
			if( pid == -1 ){
				TraceLog("? cannot fork Onetime (%d)\n",errno);
				sv1tlog("CANNOT FORK Onetime (%d)\n",errno);
			}else
			if( pid == -2 ){
				/* screened */
			}else{
				NUM_CHILDREN++;
				logChild("OntimeServer",1);
				CHILD_SERNO_SINGLE++;
				putLoadStat(ST_DONE,1);
				MainNserved++; /* must be done at wait() ... */ 
			}
			if( pid == -1 ){
				sleep(10);
			}
		}
		closeEfd(clSock);
	}

EXIT:
	if( 0 < StickyActive )
	{
		/*
		 * 9.9.4 this wait() has been here since 2.7.3 maybe to wait
		 * and cleanup StickyServers when invoked via inetd.
		 * Similarly MAXIMA=service or TIMEOUT=daemon will cause
		 * active Sticky processes left here.
		 * But it might wait endlessly while StickyServers are blocked
		 * to write the socket for StickyReport (under heavy load).
		 */
		if( 0 <= StickyReport[0] ){
			double St = Time();
			int sa = StickyActive;
			int xpid;
			int wi;

			if( stopss ){
				StickyKill(SIGHUP); /* let them release -Pxxx */
			}
			for( wi = 0; 0 < StickyActive; wi++ ){
				if( 0 < (xpid = NoHangWait()) ){
					dec_nproc(xpid);
				}
				if( PollIn(StickyReport[0],3*1000) <= 0 )
					break;
				getStickyReports();
			}
			close(StickyReport[0]); StickyReport[0] = -1;
			putfLog("Sticky left %d / %d",StickyActive,sa);
		}else
		WaitX(0);
	}

	if( EscEnabled() ){
		scounter(-1,0,0,0);
	}
	saveAuthMan();
	finalize();
	notify_ADMIN(Conn,"stop");
	if( isWindowsCE() ){
		Finish(0);
	}else
	Exit(0,"");
}

void PG_incAccServed(){
	MainNaccepted++;
	CHILD_SERNO_MULTI++;
	MainLastAccept = time(0);
	StickyNserved++;
}
int PG_terminating(){
	return terminating;
}
void PG_sigTERM(int sig){
	sigTERM(sig);
}
int PG_AcceptByMain(Connection *Conn,int timeout,int *svsockp,Efd *clSock){
	return AcceptByMain(Conn,timeout,svsockp,clSock);
}
int PG_MainLastAccept(){
	return MainLastAccept;
}
void PG_EXEC_client(Connection *Conn,PCStr(path),PCStr(func),Efd *clSock){
	EXEC_client(Conn,path,func,clSock);
}
void PG_initConn(Connection *Conn,int csock){
	initConn(Conn,csock);
}

static int timerThread(Connection *Conn){
	int cnt;
	int idle,timeout,logtimeout;
	int now,sched_next;

	for( cnt = 0; ; cnt++ ){
		if( terminating ){
			break;
		}
		if( MAX_SERVICE ){
			if( MAX_SERVICE <= TOTAL_SERVED ){
				sv1log("MAX_SERVICE done: %d\n",MAX_SERVICE);
				break;
			}
		}
		now = time(0);
		logtimeout = logTimeout();
		if( 0 < NUM_CHILDREN ){
			timeout = 60;
			if( logtimeout != 0 && logtimeout < timeout )
				timeout = logtimeout;
		}else{
			timeout = logtimeout;
			if( timeout <= 0 )
				timeout = 0;
		}
		/*
		if( SERVER_RESTART ){
			int rstimeout;
			rstimeout = restart - now;
			if( timeout == 0 || rstimeout < timeout ){
				timeout = rstimeout;
				if( timeout <= 0 ){
					sigHUP(0);
					break;
				}
			}
		}
		*/
		if( SERVER_TIMEOUT )
		if( timeout == 0 || SERVER_TIMEOUT < timeout )
			timeout = SERVER_TIMEOUT;
		if( timeout <= 0 || 60 < timeout )
			timeout = 60;
		sched_next = sched_execute(now,(iFUNCP)sched_action,Conn);
		if( now < sched_next && sched_next-now < timeout )
			timeout = sched_next-now;

		if( RESTART_NOW ){
			RESTART_NOW = 0;
			sigHUP(0);
			break;
		}
		set_MAXIMA(Conn,1);
		sv1log("--- FixedNumServ timerThread sleep=%d\n",timeout);
		sleep(timeout);
	}
	return cnt;
}

int NUM_FNSV = 8;
#define MAX_STICKIES 32
static void FixedNumServers(Connection *Conn){
	Efd *clSock = clientSocks;
	int clsock;
	int pid;
	int si;
	int ndead;
	IStr(shost,128);
	int nready;
	int numsv;
	int port;

	thread_fork(0x40000,0,"timer",(IFUNCP)timerThread,Conn);

	clsock = NOSOCKINH_FD;
	setEfd(clSock,clsock,"","",0);
	ndead = 1;
	strcpy(shost,"127.0.0.1");
	if( isWindows() || lNOSOCKINH() ){
		StickyReport[0] = server_open("StickyReport",AVStr(shost),0,-1);
		SRport = sockPort(StickyReport[0]);
		sv1log("--- FixedNumServ SR[%d]%d\n",StickyReport[0],SRport);
	}
	numsv = NUM_FNSV;
	if( MAX_STICKIES < numsv ){
		numsv = MAX_STICKIES;
	}
	for(;;){
		for( si = StickyActive; si < numsv; si++ ){
			if( terminating ){
				break;
			}
			CHILD_SERNO++;
			pid = forkStickyServer(Conn,-1,clSock);
			sv1log("--- FixedNumServ add [%d]%d\n",si,pid);
			StickyAdd(pid);
			NUM_CHILDREN++;
			logChild("StickyServer",1);
		}
		if( terminating ){
			break;
		}
		if( 0 <= StickyReport[0] ){
			nready = PollIn(StickyReport[0],10*1000);
			if( 0 < nready ){
				sv1log("--- FixedNumServ [%d] rdy=%d\n",
					StickyReport[0],nready);
				getStickyReports();
			}
		}else	sleep(1);
		if( ndead = cleanup_zombis(0) ){
			sv1log("--- FixedNumServ dead=%d (%d)\n",ndead,
				StickyActive);
		}
	}
}

static int xproc(PCStr(what),int pid){
	fprintf(stderr,"----[%d] Fork(%s) detected exit of [%d]\n",
		getpid(),what,pid);
	dec_nproc(pid);
	logChild("xproc",-1);
	return 0;
}

void StickyServer(Connection *Conn,Efd *clSock,int max);
int setupSCREEN(Connection *Conn);
int forkStickyServer(Connection *Conn,int svsock,Efd *clSock)
{	int clsock = getEfd(clSock);
	int pid;

	setupSCREEN(Conn);
	if( !INHERENT_fork() ){
		setcontrolsock(StickyReport[1]);
		pid = EXEC_client1(Conn,EXEC_PATH,FuncSTICKY,svsock,clSock);
		return pid;
	}

	/*
	if( pid = Fork("SequentialServer") )
	*/
	if( pid = ForkX("SequentialServer",xproc) )
		return pid;
	if( lSEXEC() ){
		EXEC_client1(Conn,EXEC_PATH,FuncSTICKY,svsock,clSock);
		Finish(0);
	}
	setNoExec();

	close(StickyReport[0]); StickyReport[0] = -1;
	NUM_PEERS = NUM_CHILDREN;
	appendProcLog(FL_ARG,getpid());
	StickyServer(Conn,clSock,StickyMAX_LIFE);
	Finish(0);
	return -1;
}

int screenIncomming(int clsock,const char *addr);
int hasHostSet(PCStr(hostset));
static int screened = 0;
int setupSCREEN(Connection *Conn){
	int ws;
	int wsv = 1;
	int now = 0;

	ws = withSCREEN;
	if( ws < -1 || 1 < ws ){
		now = time(0) / 60;
		if( ws < -1 && ws != -now ){
			withSCREEN = 0;
			wsv = now;
		}
	}
	if( withSCREEN == 0 ){
		if( getEnv(P_SCREEN) == NULL ){
			if( hasHostSet("screen") ){
				DELEGATE_pushEnv(P_SCREEN,"log:__screen");
				sv1log("default SCREEN=log:__screen\n");
			}
			wsv = time(0) / 60; /* check it periodically */
		}
		if( getEnv(P_SCREEN) == NULL ){
			/*
			withSCREEN = -1;
			*/
			withSCREEN = -wsv;
		}else{
			/*
			withSCREEN = 1;
			*/
			withSCREEN = wsv;
			scanEnv(Conn,P_SCREEN,scan_SCREEN);
		}
	}	
	return withSCREEN;
}
static int toBeScreened(Connection *Conn,int clsock,Efd *clSock){
	if( iamServer() && !lSINGLEP() ){
		/* 9.9.5 don't consume time nor leave status in the main process */
		return 0;
	}
	if( *PeernameOf(clSock) == 0 ){
		int remote;
		CStr(sockname,512);
		CStr(peername,512);
		remote = RIDENT_recv(clsock,AVStr(sockname),AVStr(peername));
		if( remote < 0 ){
		}else{
			setEfd(clSock,clsock,sockname,peername,remote);
		}
	}
	clSock->_screened = screenIncomming(clsock,clSock->_peername);
	if( clSock->_screened ){
		IGNRETP write(clsock,"Screened\r\n",10);
		screened++;
		Verbose("Screened(%d) %s\n",screened,clSock->_peername);
		return -2;
	}
	return 0;
}

static int randFd(PCStr(wh),Efd *clSock,int clsock){
	Verbose("randFd[%d][%d]%sA %d\n",clsock,clSock->_fd,wh,clSock->_randfd);
	if( clSock->_randfd == 0 ){
		clsock = randfd(clsock);
		clSock->_fd = clsock;
		clSock->_randfd = 1;
	Verbose("randFd[%d][%d]%sB %d\n",clsock,clSock->_fd,wh,clSock->_randfd);
	}
	return clsock;
}

int forkOnetimeServer(Connection *Conn,int svsock,Efd *clSock,int isafilter)
{	int clsock = getEfd(clSock);
	int pid;

	setupSCREEN(Conn);
	if( toBeScreened(Conn,clsock,clSock) )
		return -2;

	if( !INHERENT_fork() ){
		pid = EXEC_client1(Conn,EXEC_PATH,NULL,-1,clSock);
		return pid;
	}

	/*
	if( pid = Fork("OnetimeServer") )
	*/
	if( pid = ForkX("OnetimeServer",xproc) )
		return pid;
	if( RIDENT_CLIENT ){ /* re-check with RIDENT */
		if( toBeScreened(Conn,clsock,clSock) )
			return -2;
	}
	setNoExec();

	if( !isafilter )
		closeServPorts();

	close(StickyReport[0]); StickyReport[0] = -1;
	setProcTitleHead(DeleGate1,main_argc,main_argv);
	NUM_PEERS = NUM_CHILDREN;
	appendProcLog(FL_ARG,getpid());
	clsock = randFd("formOnetimeServer",clSock,clsock);
	EXEC_client(Conn,EXEC_PATH,NULL,clSock);
	Finish(0);
	return -1;
}

void putSTART(PCStr(what),int frominetd)
{	CStr(uname,128);
	CStr(sdate,128);
	CStr(inetd,128);
	CStr(rsh,128);

	Uname(AVStr(uname));
	StrftimeLocal(AVStr(sdate),sizeof(sdate),"%y%m%d%H%z",time(0),0);
	if( frominetd )
		sprintf(inetd,"[viaInetd]");
	else	inetd[0] = 0;
	if( fromRsh() )
		sprintf(rsh,"[viaRsh]");
	else	rsh[0] = 0;

	sv0log("--INITIALIZATION %s-%s: %s on %s--%s%s\n",
		what,sdate,DELEGATE_ver(),uname,inetd,rsh);
	sv0log("%s=%s\n",P_EXEC_PATH,EXEC_PATH); /* v9.9.12 140825b */

	if( isFullpath(EXEC_PATH) ){
		CStr(eb,1024);
		refQStr(ep,eb);
		const char *oe;

		strcpy(eb,EXEC_PATH);
		if( ep = strrpbrk(eb,"/\\") ){
			setVStrEnd(ep,0);
		}
		oe = getenv("EXECDIR");
		if( oe == 0 || !streq(oe,eb) ){
			Strins(AVStr(eb),"EXECDIR=");
			sv0log("%s\n",eb);
			putenv(stralloc(eb));
		}
	}
}
static void putDGROOT(PVStr(dgmsg))
{	const char *dgroot;

	setVStrEnd(dgmsg,0);
	dgroot = getEnv(P_DGROOT);
	if( *DELEGATE_DGROOT ){
		if( dgroot == 0 ){
		compatV5info("DGROOT=%s is set automatically. DGROOT=\"\"",
				DELEGATE_DGROOT);
		}
		if( DGROOT_SUBST == 0 )
		if( dgroot && strcmp(dgroot,DELEGATE_DGROOT) != 0 )
			sprintf(dgmsg,"NOT-USED DGROOT=%s\n",dgroot);
		Xsprintf(TVStr(dgmsg),"DGROOT=%s\r\n",DELEGATE_DGROOT);
	}else{
		if( dgroot != 0 )
			sprintf(dgmsg,"FAILED DGROOT=%s\n",dgroot);
		else	sprintf(dgmsg,"FATAL!!!! NO DGROOT !!!!\n");
	}
}
int dump_hostidX(PVStr(hostid),int verb);
static void putREADY(int isafilter,int istunnel1)
{	CStr(msg,1024);
	CStr(port,PORTSSIZE);
	CStr(dgmsg,1024);
	const char *admin;
	IStr(hostid,256);

	putDGROOT(AVStr(dgmsg));
	if( *dgmsg )
		sv1log("%s",dgmsg);
	admin = getADMIN1();
	Xsprintf(TVStr(dgmsg),"ADMIN=%s\r\n",admin?admin:"");

	printServPort(AVStr(port),"-P",0);
	sprintf(msg,"<DeleGate/%s> [%d] %s READY\r\n",DELEGATE_ver(),
		getpid(),port);
	svlog("%s",msg);
	dump_hostidX(AVStr(hostid),0);
	svlog("HostID: %s\n",hostid);
	if( istunnel1 ){
		fputs(msg,stdout);
		fflush(stdout);
	}else
	if( !isafilter )/* suppress the banner if from inetd */
	if( isatty(fileno(stderr)) || fromRsh() || fromSSH() ){
		fputs(msg,stderr);
		if( !lQUIET() ){
		put_myconf(stderr);
		fputs(dgmsg,stderr);
		fprintf(stderr,"%s\r\n",DELEGATE_copyright());
		putBLDsign(stderr);
		fprintf(stderr,"HostID: %s\r\n",hostid);
		putSSLver(stderr);
		putZLIBver(stderr);
		}
	}

	printServPort(AVStr(port),"",1);
	if( istunnel1 )
		sv1log("PORT= 0 TeleportTunnel dummy=%s\n",port);
	else{
		CStr(ftpport,64);
		int porti;
		if( (porti = atoi(port)) == 0 )
			sscanf(port,"%*[^:]:%d",&porti);
		sprintf(ftpport,"%d,%d",porti/256,porti%256);
		sv1log("PORT= %s (%s)\n",port,ftpport);
	}
}
int service_tunnel1(Connection *Conn)
{
	sv1log("#### service_tunnel\n");
	return -1;
}

void setEXEC_PATH()
{	const char *env;

	if( isWindowsCE() ){
		const char *myExePath();
		strcpy(EXEC_PATH,myExePath());
	}else
	if( env = getEnv(P_EXEC_PATH) )
		strcpy(EXEC_PATH,env);
	else
	if( isWindows() ){ /* v9.9.12 fix-140825a, exec path on Win. */
		const char *myExePath();
		strcpy(EXEC_PATH,myExePath());
	}else
	if( EXEC_PATH[0] == 0 && main_argv )
		EXT_fullpathCOM(main_argv[0],"r",AVStr(EXEC_PATH));
	else	EXT_fullpathCOM(EXEC_PATH,"r",AVStr(EXEC_PATH));
	/*
	else	FullpathOfExe(AVStr(EXEC_PATH));
	*/
}
const char *getEXEC_PATH(){
	if( EXEC_PATH[0] == 0 )
		setEXEC_PATH();
	return EXEC_PATH;
}
void setLOGCENTER(PCStr(center))
{	CStr(host,MaxHostNameLen);
	CStr(ifhost,MaxHostNameLen);
	CStr(hostport,MaxHostNameLen);
	int port;

	if( *center == 0 )
		center = DELEGATE_LOGCENTER;
	port = 8000;
	Xsscanf(center,"%[^:]:%d",AVStr(host),&port);
	gethostnameIFIF(AVStr(ifhost),sizeof(ifhost));
	LOG_center = UDP_client_open1("frog","frog",host,port,
			ifhost,SERVER_PORT());
	setCloseOnExec(LOG_center);

	/*
	gethostName(LOG_center,hostport,PN_ADDRPORT);
	put_publiclog("I","DeleGate.Start %s\n",hostport);
	*/
}
int execOnetimeFilter(Connection *Conn,Efd *clSock)
{	CStr(hostn,MaxHostNameLen);
	int port;
	int clsock,fds[3];
	int pid,xpid;

	port = getpeerNAME(0,AVStr(hostn));
	if( port <= 0 )
		return -1;

	/* connected, in nowait mode from inetd */

	if( lTRACE() ){
		if( pid = Fork("FilterTrace") ){
			TraceLog("tracing OnetimeFilter... %d\n",pid);
			xpid = WaitX(0);
			TraceLog("tracing OnetimeFilter DONE: %d\n",xpid);
			return 0;
		}
		setNoExec();
	}

	clsock = randfd(0);
	fds[0] = fds[1] = fds[2] = -1;
	if( 0 < clsock ){ fds[0] = open("/dev/null",0); }
	if( peerPort(1) == port ){ fds[1] = dup2(curLogFd(),1); }
	if( peerPort(2) == port ){ fds[2] = dup2(curLogFd(),2); }
	svlog("ONE-TIME SERVER(in nowait from inetd)[%d]%d,%d,%d\n",
		clsock,fds[0],fds[1],fds[2]);
	setEfd(clSock,clsock,"","",0);
	EXEC_client(Conn,EXEC_PATH,NULL,clSock);
	if( lTRACE() ){
		Finish(0);
		return -1;
	}else	return 0;
}
void setTeleportMASTER(Connection *Conn)
{	CStr(master,256);

	sprintf(master,"tty7:0/teleport:!*");
	scan_MASTER(Conn,master);
	pushEnv(P_INVITE,"*");
}

/*
 * using file-time is not good when the file is not on the local disk
 * on the host...
 */
static int skew_isset;
static int skew;
static int getStickyIdle(PCStr(what),int shlock){
	int mtime;

	mtime = file_mtime(shlock) + skew;
	if( 0 < mtime ){
		return time(0) - mtime;
	}else	return 0;
}
static void setStickyActive(PCStr(what),int shlock){
	if( shlock < 0 )
		return;
	file_touch(shlock);
	if( skew_isset == 0 ){
		skew_isset = 1;
		skew = time(0) - file_mtime(shlock);
	}
}

static void breakStickies(int shlock)
{	int idle;
	int timeout;
	int ndead;

	if( ndead = cleanup_zombis(1) )
	sv1log("AcceptByMain: Sticky*%d/%d cleared before trying ex-lock\n",
		ndead,StickyActive);
	if( (idle = getStickyIdle("bS1",shlock)) < SERVER_DEFREEZE ){
		sv1log("AcceptByMain: Sticky deFrozen-1 (%d)\n",idle);
		return;
	}

	ABMwhere = "breaking";
	timeout = StickyTIMEOUT;
	if( timeout < 10 ) timeout = 10; else
	if( 60 < timeout ) timeout = 60;
/*
 * timeout *= 1000;
 * because timeout in lock_exclusiveTO() is in milli-seconds.
 */

	sv1log("AcceptByMain: Wait Frozen Sticky*%d become active ...\n",
			StickyActive);

	if( lock_exclusiveTO(shlock,timeout,NULL) == 0 ){
		lock_unlock(shlock);
		idle = time(0) - lockedoutT;
		sv1log("AcceptByMain: Frozen Sticky*%d become active (%ds)\n",
			StickyActive,idle);
		return;
	}
	if( (idle = getStickyIdle("bS2",shlock)) < SERVER_DEFREEZE ){
		sv1log("AcceptByMain: Sticky deFrozen-2 (%d)\n",idle);
		return;
	}

	/* Try normal termination first.  Sending SIGHUP is not harmful
	 * for Stickies because they are blocking the signal during
	 * the execution of its service for a client.
	 */
	if( ndead = cleanup_zombis(1) )
	sv1log("AcceptByMain: Sticky*%d/%d cleared before sending SIGHUP\n",
		ndead,StickyActive);

	if( StickyKill(SIGHUP) ){
		sleep(5);
		while( 0 < (ndead = cleanup_zombis(1)) ){
			sv1log("AcceptByMain: Sticky*%d/%d cleaned by SIGHUP\n",
				ndead,StickyActive);
			sleep(1);
		}
	}

	sv1log("AcceptByMain: Wait Frozen Sticky*%d cleaned by SIGHUP ...\n",
		StickyActive);

	if( lock_exclusiveTO(shlock,timeout,NULL) == 0 ){
		lock_unlock(shlock);
		idle = time(0) - lockedoutT;
		sv1log("AcceptByMain: Frozen Sticky*%d were cleaned (%ds)\n",
			StickyActive,idle);
		return;
	}

	idle = time(0) - lockedoutT;
	sv1log("AcceptByMain: KILL Frozen Sticky*%d (%ds) %d/%d\n",
		StickyActive, idle, StickyNserved,StickyDone);

	daemonlog("F","E-F: kill Frozen Sticky*%d (%ds)\n",StickyActive,idle);
	if( StickyKill(SIGKILL) ){
		sleep(5);
		cleanup_zombis(1);
	}

	idle = time(0) - lockedoutT;
	if( lock_exclusiveTO(shlock,timeout,NULL) == 0 ){
		sv1log("AcceptByMain: Frozen Sticky*%d were KILLED (%ds)\n",
			StickyActive,idle);
	}else{
		sv1log("AcceptByMain: couldn't KILL Frozen Sticky*%d (%ds)\n",
			StickyActive,idle);
		sv1log("AcceptByMain: #### restarting may fail... ####\n");
	}

	if( fromInetd() )
		sigTERM(0);
	else	sigHUP(0);
	Finish(-1);
}
static void locked_out(int shlock)
{	int now,idle,nserved,ndone,reset;
	int (*LF)(PCStr(fmt),...);

	now = time(0);
	reset = 0;
	if( ndone = StickyDone - lastdoneN ){
		lastdoneN = StickyDone;
		lockedoutT = now;
		reset = 1;
	}
	if( nserved = StickyNserved - lastserveN ){
		lastserveN = StickyNserved;
		lockedoutT = now;
		reset = 1;
	}
	if( lockedoutN == 0 ){
		lockedoutT = now;
		reset = 1;
	}

	if( lockedoutT < now ){
		if( idle = getStickyIdle("lo1",shlock) )
		if( lockedoutT < now-idle )
		{
			lockedoutT = now-idle;
			if( SERVER_DEFREEZE < idle ){
				reset = 1;
			}
		}
	}

	if( lockedoutT < StickyLastAccept ){
		/* there were activities in Sticky since the last check */
		sv1log("## lockedoutT:%d < StickyLastAccept:%d\n",
			lockedoutT,StickyLastAccept);
		lockedoutT = StickyLastAccept;
	}

	idle = now - lockedoutT;
	if( ++lockedoutN % 10 == 0 || reset )
		LF = A_svlog;
	else	LF = A_svvlog;
	(*LF)("AcceptByMain: locked out*%d/%d by Sticky*%d %d/%d\n",
		lockedoutN,idle,StickyActive,nserved,ndone);

	/*
	 * A Sticky server possibly frozen in accept() ...
	 * Kill them and restart emulating SIGHUP.
	 */

	/*
	if( ACC_NONE_TIMEOUT < idle ){
	*/
	if( SERVER_DEFREEZE < idle ){
		breakStickies(shlock);
		lockedoutT = time(0);
	}
}

int ACCEPT1(int sock,int isServer,int lockfd,int timeout,PVStr(sockname));
int AcceptByMain1(Connection *Conn,int timeout,int exlock,int svsock,PVStr(sockname),Efd *clSock)
{	int clsock;
	int shlock;
	int ocsock,nvfd;
	CStr(vfd,2048);

	shlock = PortLockFd();

	if( 0 < StickyActive && 0 <= shlock ){
		ABMwhere = "locking";
		if( isWindows() && 1 < numServPorts() ){
			/* 9.2.4 don't do mutual-exclusion between the Main
			 * and Sticky childen because only one of ports is
			 * inherited to children, thus mutex will cause block
			 * of other ports not of current Sticky (since 9.0.6)
			 */
		}else
		if( lock_exclusiveNB(shlock) != 0 ){
			locked_out(shlock);
			return ACC_FAILED;
		}
		lockedoutN = 0;

		if( PollIn(svsock,1) <= 0 ){
			sv1log("AcceptByMain: yielded to a Sticky (%d)\n",
				StickyActive);
			lock_unlock(shlock);
			return ACC_FAILED;
		}
	}
	if( THEXIT ){
		return ACC_FAILED;
	}

	ABMwhere = "accepting1";
	if( isWindows() ){
		/* 9.6.3 to avoid frozen in accept() on Windows() */
		setNonblockingSocket(svsock,1);
	}
	clsock = ACCEPT1(svsock,1,exlock,1,AVStr(sockname));
	if( isWindows() && 0 <= clsock ){
		setNonblockingSocket(clsock,0);
	}
	ocsock = clsock;
	/*
	9.9.8 should do minimum in the parent (main) process
	clsock = randfd(clsock);
	*/
	if( lTRVERB() ){
		nvfd = valid_fdl(AVStr(vfd));
		TraceLog("accepted %d -> %d (%d child, %d act-fds)\n",
			ocsock,clsock,NUM_CHILDREN,nvfd);
	}
	ACCEPT_TIME = Time();
	clSock->_clif._ACCEPT_TIME = ACCEPT_TIME;
	if( clsock < 0 )
		sv1log("AcceptByMain[%d]: taken by a Sticky (%d)?\n",svsock,
			StickyActive);

	if( StickyActive && 0 <= shlock )
		lock_unlock(shlock);

	return clsock;
}
/*
static int pollServPortAndSticky(DGC*Conn,int timeout,int *sockv,int *udpv)
*/
static int pollServPortAndStickyX(DGC*Conn,int timeout,int *sockv,int *udpv,int *typev)
{	int rtimeout;
	int optv[2],nready,si,sock1;
	double Start;

	optv[0] = StickyReport[0];
	optv[1] = -1;
	Verbose("AcceptByMain: start polling(%d)[%d]...\n",timeout,optv[0]);

	for( rtimeout = timeout; ; rtimeout -= (int)(1000*(Time()-Start)) ){
		if( rtimeout <= 0 ){
			sv1log("AcceptByMain: polling timeout = %d / %d\n",
				rtimeout,timeout);
			break;
		}
		Start = Time();
		/*
		nready = pollServPort(rtimeout,sockv,udpv,optv);
		*/
		nready = pollServPortX(rtimeout,sockv,udpv,optv,typev);
		if( nready <= 0 )
			break;
		for( si = 0; si < nready; si++ ){
			sock1 = sockv[si];
			if( sock1 == StickyReport[0] ){
				getStickyReports();
Verbose("AcceptByMain: got Sticky REPORT 1/%d (%d)\n",nready,StickyToWait());
				cleanup_zombis(0);
				sockv[si] = -1;
				nready--;
			}
		}
		if( 0 < nready )
			break;
		if( getSoftBreak(Conn,"") ){
			sv1log("AcceptByMain: got SoftBreak\n");
			break;
		}
	}
	return nready;
}

int getConsolePort(const char **host,int *port);
static void initClif(Connection *Conn,ClPort *clif){
	int aport = 0;
	int uport = 0;
	int cport = 0;

	AcceptSock = -1;
	clif->_isAdmin = -1;

	if( 0 < clif->_adminPort && 0 < clif->_userPort ){
		/* in StickyProcess, initialized (inherited) */
	}else{
		clif->_withAdmin = withAdminPort(NULL,&aport);
		clif->_adminPort = aport;
		getUserPort1(NULL,&uport);
		clif->_userPort = uport;
		getConsolePort(NULL,&cport);
		clif->_yshPort = cport;
	}
	clif->_acceptSock = -1;
	clif->_acceptPort = 0;
	clif->_portFlags = 0;
}
int portOfSock(int sock);
int protoOfSock(int sock);
static void setClif(Connection *Conn,ClPort *clif,int clsock){
	AcceptSock = clsock;
	clif->_acceptSock = clsock;
	if( 0 <= clsock ){
		clif->_acceptPort = portOfSock(clsock);
		clif->_portProto = protoOfSock(clsock);
		if( clif->_portProto ){
			Verbose("-- [%d] port=%d proto=%d\n",
				clsock,clif->_acceptPort,clif->_portProto);
		}
	}
	/*
	if( withAdminPort(NULL,NULL) == clsock ){
	*/
	if( clif->_withAdmin == clsock ){
		clif->_isAdmin = clsock;
	}
}

int CTX_VSAPbindaccept(Connection *Conn,int timeout,int priority,PVStr(sockname),PVStr(peername));
static int AcceptByMain(Connection *Conn,int timeout,int *svsockp,Efd *clSock)
{	int clsock;
	int sx,nready,sockv[FD_SETSIZE],udpv[FD_SETSIZE];
	int typev[FD_SETSIZE];
	int exlock,sock1;
	CStr(primport,MaxHostNameLen);
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	int remote;

	initClif(Conn,&clSock->_clif);

	if( AccViaHTMUX ){
	}else
	if( ViaVSAPassociator(-1) ){
		double St = Time();
		if( VSAP_TIMEOUT ) timeout = VSAP_TIMEOUT;
		ABMwhere = "VSAPbind-accept";
		clsock = CTX_VSAPbindaccept(Conn,timeout,1,AVStr(sockname),AVStr(peername));
		if( 0 <= clsock ){
			ACCEPT_TIME = Time();
			clSock->_clif._ACCEPT_TIME = ACCEPT_TIME;
			setEfd(clSock,clsock,sockname,peername,1);
		sv1log("AcceptByMain: VSAP[%s<-%s]\n",sockname,peername);
			return clsock;
		}
		ABMwhere = "VSAPbind-accept-failed";
		if( BreakSticky ){
			/* means VSAP server rejected due to heavy load */
			BreakSticky = 0;
			sleep(1);
			return ACC_FAILED;
		}else
		if( 5 < Time()-St ){
			/* not to retry too fast when the VSAP server is down */
			/* but retry immediately if the reason is timeout */
			return ACC_TIMEOUTED;
		}else
		sleep(5);
		return -1;
	}

	ABMwhere = "polling";
	gotSIGTERM = 0;
	if( lSIGCHLD() ){
		int rtimeout,ntry;
		double Start,Elps;

		Start = Time();
		rtimeout = timeout * 1000;
		sigsetmask(sigblock(0) & ~sigmask(SIGCHLD));
		for( ntry = 0;; ntry++ ){
			errno = 0;
			/*
			nready = pollServPortAndSticky(Conn,rtimeout,sockv,udpv);
			*/
			nready = pollServPortAndStickyX(Conn,rtimeout,sockv,udpv,typev);
			Elps = Time() - Start;
			rtimeout = (int)(timeout*1000 - Elps*1000);
			if( lTRVERB() ){
TraceLog("AcceptByMain: poll*%d nready=%d errno=%d ELP=%d %d/%d\n",
				ntry,nready,errno,
				(int)(Elps*1000),rtimeout,timeout*1000);
			}
			if( 0 < nready || errno != EINTR || rtimeout <= 0 )
				break;
			mainProcTitle(Conn);
			if( lTRVERB() ){
TraceLog("AcceptByMain: retry poll*%d nready=%d timeout=%d/%d\n",
				ntry,nready,rtimeout,timeout);
			}
		}
		sigsetmask(sigblock(0) |  sigmask(SIGCHLD));
		if( lTRVERB() ){
TraceLog("AcceptByMain: poll SIGCHLD END SD=%d,LD=%d,SN=%d,LN=%d,LO=%d\n",
				StickyDone,lastdoneN,
				StickyNserved,lastserveN,lockedoutN);
		}
	}else{
		/*
		nready = pollServPortAndSticky(Conn,100,sockv,udpv);
		*/
		nready = pollServPortAndStickyX(Conn,100,sockv,udpv,typev);
		if( nready == 0 ){
			/* put status utilizing idle time */
			put_svstat();
		/*
		nready = pollServPortAndSticky(Conn,timeout*1000,sockv,udpv);
		*/
		nready = pollServPortAndStickyX(Conn,timeout*1000,sockv,udpv,typev);
		}
	}
	if( THEXIT ){
		return ACC_FAILED;
	}
	if( nready <= 0 ){
		if( terminating ){
			sv1log("AcceptByMain: break on TERMINATE.\n");
			return ACC_FAILED;
		}
		if( getpid() == ServerPID ){
			int port;

			port = sockPort(ServSock());
			if( port <= 1 ){
				if( lSINGLEP() ){
					sv1log("##AccMM %d/%d err=%d\n",
						port,ServSock(),errno);
					if( ServSock() < 0 ){
						return ACC_FAILED;
					}
					msleep(10);
					return ACC_FAILED;
				}
				sv1log("RESTART ON RESUME ? -P%d SIGTERM=%d\n",
					port,gotSIGTERM);
				if( gotSIGTERM )
					return ACC_FAILED;
				sleep(1);
				sigHUP(-1);
			}
		}
		if( Ntimeout == 0 )
		svvlog("AcceptByMain: TIMEOUT(children=%d, timeout=%d)\n",
			NUM_CHILDREN,timeout);
		Ntimeout++;
		return ACC_TIMEOUTED;
	}
	Ntimeout = 0;

	if( 0 < nready && 0 <= StickyReport[0] && 8 < StickyActive ){
	    if( 0 < PollIn(StickyReport[0],10) ){
		int oacc = StickyNaccepted;
		int nacc;
		getStickyReports();
		cleanup_zombis(0);
		nacc = StickyNaccepted;
		if( oacc < nacc ){
			sv1log("AcceptByMain: activity in Stickies %d/%d\n",
				nacc-oacc,StickyActive);
			return ACC_FAILED;
		}
	    }
	}

	ABMwhere = "accepting";
	primaryPort(AVStr(primport));
	for( sx = 0; sx < nready; sx++ ){
/*
if connected, then it is from VSAP server
 */
		sock1 = sockv[sx];
		if( lLOCK() )
			exlock = PortLocks(primport,0,VStrNULL);
		else	exlock = -1;

		if( udpv[sx] ){
			clsock = UDPaccept(sock1,exlock,timeout);
			/* parallel accept of UDP does not work without
			 * SO_REUSEPORT.  So it must not inherited to
			 * StickyProcess...
			 */
			StickyMAX_PARA = 0;
		}else	clsock = AcceptByMain1(Conn,timeout,exlock,sock1,AVStr(sockname),clSock);
		if( 0 <= clsock ){
			clSock->_clif._portFlags = typev[sx];
			setClif(Conn,&clSock->_clif,sockv[sx]);
			setEfd(clSock,clsock,sockname,"",0);
			*svsockp = sockv[sx];
			return clsock;
		}
	}

	return ACC_FAILED;
}

static int ss_yielded;
static int ss_pri;
int getParentSock();

static int AcceptBySticky1(Connection *Conn,int timeout,int shlock,int exlock,Efd *clSock)
{	int clsock = -1;
	int sx,nready,sockv[FD_SETSIZE],udpv[FD_SETSIZE];
	int typev[FD_SETSIZE];
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	int remote;
	int remto;
	int to1;
	int nretry = 0;
	int optv[2];

	initClif(Conn,&clSock->_clif);

	if( AccViaHTMUX ){
	}else
	if( ViaVSAPassociator(-1) ){
		double St = Time();
		if( VSAP_TIMEOUT ) timeout = VSAP_TIMEOUT;
		clsock = CTX_VSAPbindaccept(Conn,timeout,0,AVStr(sockname),AVStr(peername));
		if( 0 <= clsock ){
			ACCEPT_TIME = Time();
			clSock->_clif._ACCEPT_TIME = ACCEPT_TIME;
			setEfd(clSock,clsock,sockname,peername,1);
		sv1log("AcceptBySticky: VSAP[%s<-%s]\n",sockname,peername);
			return clsock;
		}
		if( BreakSticky ){
			return ACC_FAILED;
		}else
		if( 5 < Time()-St ){
			return ACC_TIMEOUTED;
		}else
		sleep(5);
		return -1;
	}

	if( 0 <= shlock )
	if( lock_sharedTO(shlock,timeout*1000,NULL) != 0 ){
		sv1log("AcceptBySticky: lock timeout\n");
		return -1;
	}

	/*
	 * can poll with StickyReport[1] to check if closed on
	 * the death of the parent ...
	 */
	/*
	nready = pollServPort(timeout*1000,sockv,udpv,NULL);
	*/

	optv[0] = getParentSock();
	optv[1] = -1;
	for( remto = timeout * 1000; 0 < remto; remto -= to1 ){ 
	    if( 0 <= optv[0] ){
		if( 5*1000 < remto )
			to1 = 5*1000;
		else	to1 = remto;
		nready = pollServPortX(to1,sockv,udpv,optv,typev);
		for( sx = 0; sx < nready; sx++ ){
			if( sockv[sx] == optv[0] ){
				/* maybe the parent terminated */
				sockv[sx] = -1;
				nready--;
			}
		}
	    }else{
		if( 1000 < remto )
			to1 = 1000;
		else	to1 = remto;
		/*
		nready = pollServPort(to1,sockv,udpv,NULL);
		*/
		nready = pollServPortX(to1,sockv,udpv,NULL,typev);
	    }
		if( !procIsAlive(serverPid()) ){
			clsock = -3;
			goto EXIT;
		}
		if( nready < 0 ){
			if( nready == -2 ){
				/* -2: no ServPort, maybe CloseOnTimeout  */
				clsock = -3;
				goto EXIT;
			}else
			if( !file_ISSOCK(sockv[0]) ){
				sv1log("AcceptBySticky: non-SOCKET[%d] %d\n",
					sockv[0],nready);
				clsock = -3;
				goto EXIT;
			}
		}
		if( nready ){
			break;
		}
	}

	if( nready <= 0 )
		goto EXIT;

RECHECK:
	for( sx = 0; sx < nready; sx++ ){
		if( nretry == 0 )
		if( isWindows() ){
			setNonblockingSocket(sockv[sx],1);
		}
		if( udpv[sx] )
			clsock = UDPaccept(sockv[sx],exlock,timeout);
		else	clsock = ACCEPT(sockv[sx],1,exlock,timeout);
		if( 0 <= clsock )
		{
			if( isWindows() ){
				setNonblockingSocket(clsock,0);
			}
			clSock->_clif._portFlags = typev[sx];
			setClif(Conn,&clSock->_clif,sockv[sx]);
			break;
		}
	}

	/* 9.6.3 prioritized accept
 	 * - to avoid frozen in accept() on Windows()
	 * - to reduce reused processes
 	 */
	if( isWindows() && clsock == -2 && nretry++ < 10 ){
		ss_yielded += 1;
		msleep(ss_pri%10);
		nready = pollServPort(100-(ss_pri%10)*5,sockv,udpv,NULL);
		if( 0 < nready ){
			goto RECHECK;
		}
	}
	if( 0 < nretry ){
		Verbose("AcceptBySticky: yielded %d/%d P%d [%d]\n",
			nretry,ss_yielded,ss_pri,clsock);
	}

	/*
	clsock = randfd(clsock);
	*/
	clsock = randFd("AcceptBySticky",clSock,clsock);
	ACCEPT_TIME = Time();
	clSock->_clif._ACCEPT_TIME = ACCEPT_TIME;
EXIT:
	if( 0 <= shlock )
	{	int rcode;

		errno = 0;
		rcode =
		lock_unlock(shlock);
		if( rcode != 0 || errno != 0 ){
			sv1log("AcceptBySticky: unlock failed: %d %d\n",
				rcode,errno);
			close(shlock);
			BREAK_STICKY = 1;
		}
	}

	if( 0 <= clsock ){
		remote = RIDENT_recv(clsock,AVStr(sockname),AVStr(peername));
		if( remote < 0 ){
			close(clsock);
			clsock = -1;
		}else{
			setEfd(clSock,clsock,sockname,peername,remote);
		}
	}
	return clsock;
}

/* SCREEN */
int ShutdownSocket(int sock);
static int screen_hosts;
static Logfile *scrLog;
FILE *LOG_file(Logfile *logF);
static int scrlogN;
static int screen_peek;
int SCREEN_TIMEOUT = 0;
void scan_SCREEN(Connection *Conn,const char *screen){
	CStr(opts,1024);
	CStr(hosts,1024);
	CStr(path,1024);
	const char *to;

	fieldScan(screen,opts,hosts);
	if( isinListX(opts,"reject","c")
	 || isinListX(opts,"accept","c")
	){
		const char *ltype = "ima";
		if( *hosts == 0 ){
	 		if( isinListX(opts,"accept","c") )
				strcpy(hosts,"accept");
			else	strcpy(hosts,"reject");
		}
		if( strcasestr(hosts,"mac")
		 || isinListX(opts,"mac","c")
		){
			ltype = "mac";
		}
		if( strcasestr(hosts,"ip4")
		 || isinListX(opts,"ip4","c")
		){
			ltype = "ip4";
		}
		sprintf(path,"%s.%s.list.-",hosts,ltype);
		SCREEN_FILE = stralloc(path);
		if( isinListX(opts,"accept","c") ){
			SCREEN_FILE_ACCEPT = 1;
		}
		return;
	}

	if( screen ){
		if( withSCREEN < 1 )
		withSCREEN = 1;
	}else{
		withSCREEN = -1;
		return;
	}

	fieldScan(screen,opts,hosts);
	if( to = strstr(opts,"expire/") ){
		CStr(too,1024);
		SCREEN_TIMEOUT = atoi(to+7);
		sprintf(too,"--expire.%d,",SCREEN_TIMEOUT);
		Strins(AVStr(hosts),too);
	}
	screen_hosts = makePathList("SCREEN",hosts);
	if( isinList(opts,"log") ){
		/*
		scrlogfp = LOG_openLogFile("screen.log","a");
		*/
		scrLog=LOG_create("screen","SCREENLOG","-","screen.log","a",0);
		LOG_open(scrLog);
	}
	if( isinList(opts,"peek") ){
		screen_peek = 1;
	}
}
int screenIncomming(int clsock,const char *addr){
	CStr(host,512);
	int port;

	if( screen_hosts ){
		const char *dp;
		strcpy(host,"-");
		dp = wordscanY(addr,DVStr(host,1),sizeof(host)-1,"^:");
		if( *dp == ':' )
			port = atoi(dp+1);
		else	port = 0;
		if( matchPath1(screen_hosts,"",host,port) ){
			FILE *scrlogfp = LOG_file(scrLog);
			if( scrlogfp ){
			fprintf(scrlogfp,"%d %s:%d\n",itime(NULL),host+1,port);
				fflush(scrlogfp);
				/*
				if( ++scrlogN == 100 ){
					fflush(scrlogfp);
					scrlogN = 0;
				}
				*/
			}
			return 1;
		}
	}
	if( screen_peek ){
		int nready;
		nready = PollIn(clsock,1);
		if( 0 < nready ){
			CStr(buf,128);
			int rcc;
			rcc = recvPeekTIMEOUT(clsock,AVStr(buf),sizeof(buf));
			if( 0 < rcc ){
				/* check the message pattern ... */
			}
			if( rcc < 0 ){
				/* disconnected */
			}
		}
	}
	return 0;
}

static int AcceptBySticky(Connection *Conn,int timeout,int shlock,int exlock,Efd *clSock)
{	int clsock;
	int timeout1,rtimeout;

	Verbose("StickyServer: start accept()\n");
	for( rtimeout = timeout; 0 < rtimeout; rtimeout -= timeout1 ){
		ProcTitle(Conn,"*standby=%ds",rtimeout);
		if( StickyTIMEOUT1 < rtimeout )
			timeout1 = StickyTIMEOUT1;
		else	timeout1 = rtimeout;
		clsock = AcceptBySticky1(Conn,timeout1,shlock,exlock,clSock);
		if( 0 < clsock )
		{
		clSock->_screened = screenIncomming(clsock,clSock->_peername);
			break;
		}
		if( BreakSticky ){
			break;
		}
		if( clsock == -3 ){
			break;
		}
	}
	if( clSock->_screened == 0 )
	if( 0 <= clsock ){
		CStr(accReport,1);
		SReport SR;
		Verbose("## AcceptBySticky: SEND ACCEPT REPORT\n");
		/*
		accReport[0] = 0;
		write(StickyReport[1],accReport,1);
		*/
		SR.s_stat = SR_ACCEPT;
		SR.s_done = 0;
		SR.s_pid = getpid();
		IGNRETP write(StickyReport[1],&SR,sizeof(SR));
	}
	return clsock;
}

static int start0;
static int nreq;
static void reportNserv(PCStr(stat),int start,int nreq)
{	char nconn;
	vfuncp osig;
	SReport SR;

	if( StickyReport[1] < 0 )
		return;

	/* might get SIGALRM in accept(), free accept lock immediately */
	if( PortLockFd() != -1 )
		close(PortLockFd());

	nconn = CHILD_SERNO_MULTI + nreq;

	SR.s_stat = SR_FINISH;
	if( BREAK_STICKY & SR_DETACH )
		SR.s_stat |= SR_DETACH;
	SR.s_done = nconn;
	SR.s_pid = getpid();

	osig =
	signal(SIGPIPE,SIG_IGN);
	/*
	write(StickyReport[1],&nconn,1);
	*/
	IGNRETP write(StickyReport[1],&SR,sizeof(SR));
	close(StickyReport[1]);
	StickyReport[1] = -1;
	signal(SIGPIPE,osig);

	/*
	sv1log("StickyServer done [%s] %d req / %d conn / %d sec\n",
		stat,CHILD_SERNO_MULTI+nreq,CHILD_SERNO_MULTI,time(0)-start);
	*/
	sv1log("StickyServer done [%s] %d req / %d+%d/%d conn / %d sec\n",
		stat,CHILD_SERNO_MULTI+nreq,CHILD_SERNO_MULTI,
		ss_yielded,ss_pri,
		(int)(time(0)-start));
	/*
	Finish(0);
	*/
}
void stopStickyServer(PCStr(why))
{
	if( lSINGLEP() ){
		return;
	}
	BREAK_STICKY = SR_DETACH;
	reportNserv(why,start0,nreq+1);
}
extern int in_exit;
static void sigHUPforAbort(int sig){
	if( numthreads() ){ /* 9.9.4 MTSS SIGHUP with multi-threads */
		Connection *Conn = MainConn();
		setgotsigTERM(sig);
		signal(SIGHUP,SIG_IGN);
		closeServPorts();
		if( !ismainthread() ){
			putsLog("##SIGHUP non-main");
			return;
		}
		putsLog("##SIGHUP Sticky-with-threads");
		sv1log("StickyServer SIGHUPed after %d services. %d/%d\n",
			CHILD_SERNO_MULTI,actthreads(),numthreads());
		if( 0 <= ClientSock ){
			ShutdownSocket(ClientSock);
			ClientSock = -1;
			putsLog("##SIGHUP close ClientSock");
		}
		if( 0 <= ServerSock ){
			ShutdownSocket(ServerSock);
			ServerSock = -1;
			putsLog("##SIGHUP close ServerSock");
		}
		in_exit = time(0);
		_exit(0);
	}
	closeServPorts();
	sv1log("StickyServer SIGHUPed after %d services.\n",CHILD_SERNO_MULTI);
	Finish(0);
}
static int isStickyProto(Connection *Conn)
{	int nntps,otimeout;
	const char *proto;

	if( streq(iSERVER_PROTO,"https") ){
		if( ToMyself )
		if( httpStat == 'I' || httpStat == 'L' ){
			sv1log("Sticky HTTPS/self: M%d I%d (%c) %X %X [%s]\n",
				ToMyself,IsInternal,httpStat,
				ClientFlags,ServerFlags,DST_PROTO);
			return 1;
		}
	}
	if( IsInternal ) return 1;

	proto = DFLT_PROTO;
	if( strcaseeq(iSERVER_PROTO,"socks") )  return 1;
	if( strcaseeq(proto,"tcprelay") )  return 1;
	if( strcaseeq(proto,"vsap") )  return 1;
	if( strcaseeq(proto,"http") )	return 1;
	if( strcaseeq(proto,"httpft") )	return 1;
	/*
	if( strcaseeq(proto,"https") )	return 1;
	*/
	if( strcaseeq(proto,"https") ){
		if( ClientFlags & PF_MITM_ON ){
			return 1;
		}
		/*
		if( ServerFlags & PF_DO_STICKY )
		*/
		if( ClientFlags & PF_DO_STICKY )
		{
			sv1log("Sticky CONNECT %s:%d << %s:%s [%X]\n",
				DST_HOST,DST_PORT,
				CLNT_PROTO,Client_Host,ServerFlags);
			return 1;
		}
		if( (ServerFlags & PF_SSL_ON) && aliveServ(Conn) ){
			sv1log("Sticky HTTPS (%d) %s:%d << %s:%s [%X]\n",
				aliveServ(Conn),DST_HOST,DST_PORT,
				CLNT_PROTO,Client_Host,ServerFlags);
			return 1;
		}
	}
	if( strcaseeq(proto,"gopher") )	return 1;
	if( strcaseeq(proto,"ftp") && IsAnonymous ) return 1;
	if( strcaseeq(proto,DGAUTHpro) ) return 1;

	if( localPathProto(proto) && IsLocal )
	if( streq(iSERVER_PROTO,"http") )
		return 1;

	if( strcaseeq(proto,"nntp") || strcaseeq(proto,"ftp") )
	if( streq(iSERVER_PROTO,"http") && !ACT_GENERALIST )
		 return 1;

	return 0;
}
/* 9.9.7 ex. SERVER=http -P8080 -Q6023/yysh */
const char *servicename(int port,const char **name);
int isNotStickyPort(Connection *Conn,Efd *clSock){
	const char *sname = "";
	int sport;

	if( sport = clSock->_clif._portProto ){
		if( sname = servicename(sport,0) ){
			if( streq(sname,"http")
			 || streq(sname,"https")
			 || streq(sname,"socks")
			 || streq(sname,"delegate")
			){
				return 0;
			}
			return 1;
		}
		return 0;
	}
	return 0;
}
void setStickyParams(Connection *Conn,PCStr(proto))
{
	if( lFXNUMSERV() ){
		StickyMAX_PARA = MAX_STICKIES;
		StickyMAX_LIFE = STANDBY_MAX * 4;
		StickyTIMEOUT  = STANDBY_TIMEOUT;
		return;
	}
	if( 0 < STANDBY_MAX )
	if( streq(proto,"http")
	 || streq(proto,"https") /* 9.6.0 enabled ... */
	 || streq(proto,"icap")
	 || streq(proto,"vsap")
	 || streq(proto,"socks")
	 || streq(proto,"tcprelay")
	 || streq(proto,DGAUTHpro)
	 || BORN_SPECIALIST == 0 ){
		StickyMAX_PARA = MAX_DELEGATE;
		StickyMAX_LIFE = STANDBY_MAX * 4;
		StickyTIMEOUT  = STANDBY_TIMEOUT;
	}
}

extern int lock_ext;
int PortLockReopen();
void setCloseOnTimeout(int timeout);

void reportScreened(int mypid,int nscr,int tscr,int nserv){
	SReport SR;
	SR.s_stat = SR_SCREENED;
	SR.s_done = nscr;
	SR.s_pid = mypid;
	IGNRETP write(StickyReport[1],&SR,sizeof(SR));
	sv1log("Screened: (+%d) %d / %d\n",nscr,nscr+tscr,nserv);
}
static void setupFixedNumServ(Connection *Conn,int ac,const char *av[]){
	int ai;
	const char *arg;

	if( !lFXNUMSERV() ){
		return;
	}
	StickyTIMEOUT = 600;
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( arg[0] == '-' ){
			switch( arg[1] ){
				case 'D':
				case 'E':
					setDebugX(Conn,arg,0);
					break;
				case 'P':
				case 'Q':
					scanServPortX(arg+2,0);
					break;
			}
		}
	}
	openServPorts();
}
static int withBacklog(){
	int sockv[FD_SETSIZE];
	int udpv[FD_SETSIZE];
	int nready;

	nready = pollServPort(1,sockv,udpv,NULL);
	return nready;
}
void StickyServer(Connection *Conn,Efd *clSock,int max)
{	int clsock;
	int omask;
	int timer;
	int mypid,ppid,ouid,ogid;
	const char *stat;
	int shlock,exlock,madelock;
	/*
	int start0,start,now;
	int nreq;
	*/
	int start,now;
	int sx;
	CStr(tmp,512);
	const char *screen_msg;
	int nserv;
	int nscr = 0;
	int tscr = 0;
	double Prev;

	mypid = getpid();
	ppid = getppid();
	ouid = getuid();
	ogid = getgid();
	ss_pri = SERNO() % 10;

	if( streq(iSERVER_PROTO,"http") )
		screen_msg = "HTTP/1.0 403 Screened\r\n\r\n";
	else	screen_msg = "Screened\r\n";

	signal(SIGHUP,sigHUPforAbort);
	NUM_CHILDREN = 0;
	nreq = 0;

	start = start0 = time(0);

	clsock = getEfd(clSock);
    if( clsock == NOSOCKINH_FD ){
	StickyTIMEOUT = 600;
	sv1log("--- FixedNumServ start [%x]\n",clsock);
    }else{
	clsock = randFd("StickyServer1",clSock,clsock);
	setupSCREEN(Conn);
	if( *PeernameOf(clSock) == 0 ){
		int remote;
		CStr(sockname,512);
		CStr(peername,512);
		remote = RIDENT_recv(clsock,AVStr(sockname),AVStr(peername));
		if( remote < 0 ){
		}else{
			setEfd(clSock,clsock,sockname,peername,remote);
		}
	}
	clSock->_screened = screenIncomming(clsock,clSock->_peername);

	if( clSock->_screened ){
		IGNRETP write(clsock,screen_msg,strlen(screen_msg));
		ShutdownSocket(clsock);
		closeEfd(clSock);
		nscr++;
	}else{
	omask = sigblock(sigmask(SIGHUP));
	{
		CHILD_SERNO_MULTI = 1;
		setProcTitleHead(DeleGate1,main_argc,main_argv);
		setCloseOnTimeout(StickyTIMEOUT);
		EXEC_client(Conn,EXEC_PATH,NULL,clSock);
		closeEfd(clSock);
	}
	sigsetmask(omask);
	}
    }

	madelock = 0;
	Prev = Time();
	for( nserv = 1;; nserv++ ){
		if( clSock->_screened ){
/*
			if( nscr % 100 == 0 )
*/
			{
				double Now = Time();
				if( 5 <= Now - Prev ){
					Prev = Now;
					reportScreened(mypid,nscr,tscr,nserv);
					tscr += nscr;
					nscr = 0;
				}
			}
			goto START_ACCEPT;
		}
		set_MAXIMA(Conn,2);
		if( 0 < REQUEST_SERNO ){
			nreq += REQUEST_SERNO - 1;
			REQUEST_SERNO = 0;
		}

		if( getpid() != mypid ){
			/* may be forkd in sendDistribution() */
			if( ServerFlags & PF_IS_DISTRIB ){
			}else
			sv1log("#### not the Sticky server process, EXIT.\n");
			Finish(0);
		}
		if( lFXNUMSERV() ){
			if( nserv == 1 ){
				/* the first request in the FXNUMSERV mode */
				goto START_ACCEPT;
			}
			if( 0 < withBacklog() ){
				/* not to drop the requests in the backlog */
				goto START_ACCEPT;
			}
		}
		if( max <= CHILD_SERNO_MULTI ){
			stat = "natural";
			break;
		}
		if( INTERRUPT_STICKY ){
			stat = "interrupted";
			break;
		}
		if( BreakSticky ){
			stat = "Broken";
			break;
		}
		if( BREAK_STICKY ){
			stat = "broken";
			break;
		}
		if( !ACC_REJECTED && !isStickyProto(Conn) ){ /* generalist */
			stat = "nonStickyProtocol";
			sprintf(tmp,"%s(%s:%s:%s)",stat,
				iSERVER_PROTO,DFLT_PROTO,DST_PROTO);
			stat = tmp;
			break;
		}
		if( getppid() != ppid || getuid() != ouid || getgid() != ogid ){
			stat = "parentChanged";
			break;
		}
		if( AccViaHTMUX ){
		 	/* via VSAP but by direct TCP/HTMUX */
			if( activeServPort() == 0 ){
				/* maybe closed by CloseOnTimeout */
				stat = "serverSocketClosed/HTMUX";
				break;
			}
		}else
		if( !ViaVSAPassociator(-1) )
		if( activeServPort() == 0 ){
			stat = "serverSocketClosed";
			break;
		}
		if( getSoftBreak(Conn,"") ){
			stat = "softBreak";
			break;
		}

	START_ACCEPT:
		now = time(0);
		if( 120 < (now - start) ){
			stat = "lifeSpan1";
			break;
		}
		start = now;

		initConn(Conn,-1);
		if( lFXNUMSERV() && isWindows() ){
			shlock = -1;
			exlock = -1;
		}else
		if( !madelock ){
			madelock = 1;
			shlock = PortLockReopen();
			if( lLOCK() )
				exlock = PortLocks(primaryPort(AVStr(tmp)),0,VStrNULL);
			else	exlock = -1;
		}
		setStickyActive("POLL",shlock);
		clSock->_screened = 0;
		clsock=AcceptBySticky(Conn,StickyTIMEOUT,shlock,exlock,clSock); 
		setStickyActive("ACCEPTED",shlock);
		if( clSock->_screened ){
			IGNRETP write(clsock,screen_msg,strlen(screen_msg));
			ShutdownSocket(clsock);
			close(clsock);
			nscr++;
			continue;
		}

		if( clsock < 0 ){
			if( StickyTIMEOUT <= time(0)-start ){
				stat = "timeout";
			}else
			stat = "acceptFailed";
			break;
		}

		omask = sigblock(sigmask(SIGHUP));
		{
			CHILD_SERNO_MULTI++;
			setCloseOnTimeout(StickyTIMEOUT);
			EXEC_client(Conn,EXEC_PATH,NULL,clSock);
			closeEfd(clSock);
			cleanup_zombis(1);
		}
		sigsetmask(omask);
	}
	if( nscr ){
		reportScreened(mypid,nscr,tscr,nserv);
	}
	reportNserv(stat,start0,nreq);
	clearServ(Conn);
	Finish(0);
}

void get_svstat(int fd);
static int str2env(PCStr(seqno),int *svsockp,Efd *clSock,int *lfdp)
{	int ac,port;
	int isock;
	int clsock;
	CStr(svhost,MaxHostNameLen);
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	CStr(seq0,256);
	CStr(seq1,256);
	CStr(seq2,256);
	CStr(seq3,256);
	IStr(dummy,256);
	int remote;
	int statfd;
	int nullfd;
	void *logmmap; Int64 llx;
	void *logaddr;

	clsock = -1;
	*svsockp = -1;
	statfd = -1;
	nullfd = -1;
	svhost[0] = 0;
	sockname[0] = peername[0] = 0;

	seq0[0] = seq1[0] = seq2[0] = seq3[0] = 0;
	Xsscanf(seqno,"%[^,],%[^,],%[^,],%[^\n]",
		AVStr(seq0),AVStr(seq1),AVStr(seq2),AVStr(seq3));

	ac = 0;
	ac += sscanf(seq0,"%d/%d/%d/%d/%d/%d/%d/%d/%d/%lf",
		&clsock,
		&clSock->_clif._acceptPort,
		&clSock->_clif._portProto,
		&clSock->_clif._isAdmin,
		&clSock->_clif._withAdmin,
		&clSock->_clif._adminPort,
		&clSock->_clif._userPort,
		&clSock->_clif._yshPort,
		&clSock->_clif._portFlags,
		&clSock->_clif._ACCEPT_TIME
	);
	ac += sscanf(seq1,"%x/%d/%d/%d/%d/%d/%d/%d/%d/%d",
		&deleGateId,
		&port,
		&ServerPID,
		&DELEGATE_LastModified,
		&IamPrivateMASTER,
		svsockp,
		&param_file,
		/*
		&TOTAL_SERVED,
		*/
		pTOTAL_SERVED,
		&CHILD_SERNO,
		&NUM_PEERS
	);
	ac += Xsscanf(seq2,"%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%llX",
		&nullfd,
		&LOG_initFd,
		&SRport,
		&StickyReport[1],
		&DELEGATE_LINGER,
		lfdp,
		&LOG_type,
		&LOG_type2,
		&statfd,
		&ekeyFd,
		&withSCREEN,
		&MASTERisPrivate,
		&AF_UNIX_DISABLE,
		&RES_localdns,
		&remote,
		&llx
	);
	logmmap = (void*)ll2p(llx);
	/*
	ac += Xsscanf(seq3,"%[^/]/%[^/]/%[^/]",
		AVStr(svhost),
		AVStr(sockname),
		AVStr(peername)
	);
	*/
	ac += scan_Listlist(seq3,'/',
		AVStr(svhost),
		AVStr(sockname),
		AVStr(peername),
		AVStr(dummy), /* not to get "/" into peername if empty */
		VStrNULL
	);

	if( 0 <= nullfd ){
		setNullFd(nullfd);
	}
	if( logmmap ){
		if( logaddr = setmmap(logmmap,0,sizeof(LogControls)) ){
			logControl = (LogControl*)logaddr;
			inheritLogControl();
		}
	}

	LOG_type0 |= L_ISCHILD;
	if( 0 <= statfd ){
		SVSTAT_FD = statfd;
	}
	get_svstat(statfd);

	if( lVERB() )
		LOG_VERBOSE = 1;

	if( LOG_type2 & L_LOCKSHARED ){
		lock_ext = 0;
	}

  if( clsock == NOSOCKINH_FD ){
	setEfd(clSock,clsock,sockname,peername,remote);
	if( 0 < SRport ){
		StickyReport[1] = UDP_client_open("StickyReport","",
			"127.0.0.1",SRport);
	}
	sv1log("--- FixedNumServ[%d] --- SR[%d]%d\n",clsock,
		StickyReport[1],SRport);
  }else{
	if( 0 < (isock = getclientsock()) )
		clsock = isock;
	if( 0 <= clsock )
	{
	/*
	clsock = randfd(clsock);
	*/
	setEfd(clSock,clsock,sockname,peername,remote);
	clsock = randFd("str2env",clSock,clsock);
	}

	if( 0 < (isock = getserversock()) )
		*svsockp = isock;

	if( 0 < (isock = getcontrolsock()) )
		StickyReport[1] = isock;
  }

	if( isFuncFunc ){
		/* passed svsock is not the socket to accept client
		 * but a socket connected to the server
		 */
		setSERVER_PORT(svhost,port,-1);
	}else
	/*
	 * svhost derived from -Phostname:port is necessary to be set as
	 * the PrimayPort to generate ${PORT}, "Location:", etc.
	 */
	{
		/* inheriting -Pxxx/rident of VSAP for HTMUX */
		setSERVER_PORTX(svhost,port,*svsockp,clSock->_clif._portFlags);
	/*
	setSERVER_PORT(svhost,port,*svsockp);
	*/
	}

	return ac;
}

static int recvEnv(Connection *Conn,int ac,const char *av[],int *svsockp,Efd *clSock)
{	int av1ac;
	int lfd;
	const char *env;

	lfd = -1;
	if( (av1ac = str2env(av[1],svsockp,clSock,&lfd)) < 3 ){
		if( env = getEnv(P_EXEC_ENV) )
			av1ac = str2env(env,svsockp,clSock,&lfd);
		else	av1ac = 0;
	}
	ACCEPT_TIME = clSock->_clif._ACCEPT_TIME;
	if( 0 <= lfd )
	fdopenLogFile(lfd);
	return av1ac;
}

int callFilter(Connection *Conn,int ac,const char *av[]);
static int callFunc(Connection *Conn,int ac,const char *av[],Efd *clSock,int svsock);
void Exec_client(Connection *Conn,int ac,const char *av[])
{	int av1ac;
	int svsock;
	Efd *clSock = clientSocks;
	const char *env;

	if( 2 < ac ){
		if( streq(av[2],FuncFunc) ) isFuncFunc = 1;
	}
	if( 1 < ac && streq(av[1],FuncFILTER) )
		av1ac = 0;
	else
	av1ac = recvEnv(Conn,ac,av,&svsock,clSock);

	if( env = getEnv(P_EXEC_PATH)  ) strcpy(EXEC_PATH,env);
	if( env = getEnv(P_START_TIME) ) START_TIME = atoi(env);
	if( env = getEnv(P_ALIVE_PEERS)) NUM_CHILDREN = atoi(env);

	if( 1 < ac ){
	  if( streq(av[1],FuncFILTER) )    Finish(callFilter(Conn,ac,av));
	  if( streq(av[2],FuncSTICKY) ){
		set_MAXIMA(Conn,0);
		scanEnv(Conn,P_MAXIMA,  scan_MAXIMA);
		scanEnv(Conn,P_TIMEOUT, scan_TIMEOUT);
		setStickyParams(Conn,DFLT_PROTO);
		if( (LOG_type2 & L_LOCKSHARED) == 0 ){
			/* this PutPortFile() was put here at 9.0.6-pre3
			 * to open PIDFILE to be used for shared lock for
			 * mutual exclusion of entrant port to be reopened
			 * in PortLockReopen().
			 */
			PutPortFile(1);
		}
		setupFixedNumServ(Conn,ac,av);
		StickyServer(Conn,clSock,StickyMAX_LIFE);
		closeEfd(clSock);
		Finish(0);
	  }
	  if( streq(av[2],FuncFunc)) Finish(callFunc(Conn,ac,av,clSock,svsock));
	}

	if( av1ac < 3 )
		Exit(-1,"cannot get socket argument.\n");
	else{
		call_client1(Conn,clSock);
		closeEfd(clSock);
	}
}

void gotoWORKDIR()
{	const char *wd;
	const char *pp;
	CStr(wdir,1024);
	CStr(cwd,1024);
	CStr(var,1024);
	CStr(tmp,1024);
	FILE *fp;

	wd = (char*)getEnv(P_WORKDIR);
	if( wd == 0 ){
		if( lFG() || lSYNC() )
			return;
		else	wd = DELEGATE_WORKDIR;
	}
	strcpy(wdir,wd);
	substfile(AVStr(wdir),"PROTOCOL",AVStr(var),VStrNULL,VStrNULL);

	if( !isBoundpath(wdir) ){
		strcpy(tmp,wdir);
		sprintf(wdir,"%s/%s",var,tmp);
		/*
		if( lARGDUMP() )
		*/
		if( lFILETRACE() )
			fprintf(stderr,"WORKDIR=%s\n",wdir);
	}

	path_escchar(AVStr(wdir));
	mkdirRX(wdir);
	IGNRETS getcwd(cwd,sizeof(cwd));
	originWD = StrAlloc(cwd);

	if( chdir(wdir) == 0 ){
		CStr(pid,64);

		sv1log("%s=%s\n",P_WORKDIR,wdir);
		_workdir = stralloc(wdir);
		sprintf(pid,"%d",getpid());
		if( fp = dirfopen("WORKFILE",AVStr(pid),"w") )
			fclose(fp);
	}else{
		sv1log("ERROR can't goto %s=%s\n",P_WORKDIR,wdir);
	}
}
void makeWorkFile(PVStr(path),PCStr(type),PCStr(file))
{
	sprintf(path,"${ACTDIR}/%s/%d.%s",type,getpid(),file);
	substFile(path);
	if( elnumof(workFiles)-1 <= workFileX ){
		syslog_ERROR("ignored too many work-files -- %s\n",path);
		return;
	}
	workFiles[workFileX++] = stralloc(path);
}
void deleteWORKDIR()
{	int pid;
	CStr(pidfile,1024);
	const char *workfile;
	const char *dp;
	int tx;

	pid = getpid();
	if( _workdir ){
		sprintf(pidfile,"%s/%d",_workdir,pid);
		if( unlink(pidfile) == 0 ){
			sv1log("unlinked %s\n",pidfile);
			IGNRETZ chdir("..");
			if( rmdir(_workdir) == 0 )
				sv1log("removed %s/\n",_workdir);
			else	sv1log("remove failed, errno=%d, %s\n",
					errno,_workdir);
		}
		_workdir = NULL;
	}
	for( tx = 0; workfile = workFiles[tx]; tx++ ){
		if( dp = strrpbrk(workfile,"/\\") )
			if( atoi(dp+1) == pid )
				unlink(workfile);
	}
}

FILE *openStatusFile(PCStr(pathform));
void putStatus(PCStr(fmt),...)
{	const char *file;
	FILE *fp;
	VARGS(8,fmt);

	if( file = getEnv("STATFILE") )
	if( fp = openStatusFile(file) ){
		/* fseek(fp,0,0); */
		fprintf(fp,"%d ",itime(0));
		fprintf(fp,fmt,VA8);
		fflush(fp);
		/* Ftruncate(fp,0,1); */
	}
}

static void printXdisplay(PVStr(pxdisplay),PCStr(pxhost),int pxport,int scrnum)
{	const char *pxaddr;

	if( pxaddr = gethostaddr(pxhost) )
		sprintf(pxdisplay,"%s:%d.%d",pxaddr,pxport-6000,scrnum);
	else	sprintf(pxdisplay,"%s:%d.%d",pxhost,pxport-6000,scrnum);
	sv1log("Xproxy -- %s:%d.%d -- %s\n",pxhost,pxport,scrnum,pxdisplay);
}
int makeXproxy(Connection *Conn,PVStr(pxdisplay),PCStr(display),PVStr(pxhost),PCStr(relhost),PCStr(me),int timeo)
{	const char *av[32]; /**/
	CStr(port,MaxHostNameLen);
	IStr(admin,256);
	IStr(logtype,256);
	IStr(logtype2,256);
	CStr(timeout,256);
	CStr(server,MaxHostNameLen);
	CStr(permit,256);
	CStr(desc,256);
	const char *env;
	CStr(conn,256);
	CStr(vardir,1024);
	CStr(logdir,1024);
	CStr(logfile,1024);
	CStr(disphost,128);
	int dispport,dispsock;
	int pxsock,pxport;
	int ac;
	int pid;
	int dispnum,scrnum;
	CStr(cachepath,2048);
	FILE *cachefp;
	CStr(hosts,0x4000);
	CStr(clientid,256);

	dispnum = scrnum = 0;
	Xsscanf(display,"%[^:]:%d.%d",AVStr(disphost),&dispnum,&scrnum);
	dispport = 6000+dispnum;

	sprintf(clientid,"pid-port-%s",relhost);
	if( CTX_cache_path(Conn,"X",disphost,dispnum,clientid,AVStr(cachepath)) ){
		CStr(line,256);

		sv1log("##[%s][%s] %s\n",display,relhost,cachepath);
		if( cachefp = fopen(cachepath,"r+") ){
			fgets(line,sizeof(line),cachefp);
			fclose(cachefp);

			/* cleanup zombis of previous X-proxy to make kill()==0
			 * work to sense the existence of the process */
			while( 0 < NoHangWait() )
				;

			if( sscanf(line,"%d %d",&pid,&pxport) == 2 )
			if( Kill(pid,SIGHUP) == 0 )
			{
				sv1log("REUSE X-PROXY for %s: port=%d pid=%d\n",
					relhost,pxport,pid);
				printXdisplay(AVStr(pxdisplay),pxhost,pxport,scrnum);
				return pid;
			}
			/* should add "xhost" */
		}
	}

	pxsock = -1;
	for( pxport = 6010; pxport < 6100; pxport++ ){
		pxsock = server_open("Xpxdisplay",AVStr(pxhost),pxport,1);
/*
DEBUG: bind with wildcard interface
		pxsock = server_open("Xpxdisplay","",pxport,1);
*/
		if( 0 < pxsock )
			break;
	}
	if( pxsock < 0 )
		return 0;

	pxport = sockPort(pxsock);

	if( (pid = Fork("Xpxdisplay")) != 0 ){
		close(pxsock);
		printXdisplay(AVStr(pxdisplay),pxhost,pxport,scrnum);
		return pid;
	}

	if( cachepath[0] ){
		if( cachefp = dirfopen("X-Proxy",AVStr(cachepath),"w") ){
			fprintf(cachefp,"%d %d\n",getpid(),pxport);
			fclose(cachefp);
		}
		/* should read "xhost" and set it to PERMIT */
	}

	if( fromInetd() ){
		close(0);
		close(1);
	}
	closeServPorts();
	close(ToS);
	close(FromS);
	close(ToC);
	close(FromC);

	ac = 0;
	av[ac++] = EXEC_PATH;

	sprintf(port,"-P%d/%d",pxport,pxsock);
	av[ac++] = port;

	Xsscanf(display,"%[^:]:%d",AVStr(disphost),&dispport);
	sprintf(server,"%s=X://%s:%d/",P_SERVER,disphost,6000+dispport);
	av[ac++] = server;

	if( timeo ){
		sprintf(timeout,"%s=daemon:%ds",P_TIMEOUT,timeo);
		av[ac++] = timeout;
	}

	unsetEnv(0,(const char**)environ,(const char*const*)environ,P_PERMIT);
	unsetEnv(0,(const char**)environ,(const char*const*)environ,P_RELIABLE);
	unsetEnv(0,(const char**)environ,(const char*const*)environ,P_REACHABLE);
	sprintf(permit,"%s=X:%s:%s",P_PERMIT,disphost,relhost);
/*
DEBUG: don't check X-client host
	sprintf(permit,"%s=X:%s:*",P_PERMIT,disphost);
*/
	av[ac++] = permit;

	if( env = getEnv(P_CONNECT) ){
		sprintf(conn,"%s=%s",P_CONNECT,env);
		av[ac++] = conn;
	}

	if( 1 ){ /* 9.9.6 */
		setpgid(0,0); /* 9.9.6 for -Xi X/Telnet */
		if( LOG_type2 || LOG_bugs ){
			sprintf(logtype2,"-L20x%X/%X",LOG_type2,LOG_bugs);
			av[ac++] = logtype2;
		}
	}
	if( 1 ){ /* 9.9.5 */
		av[ac++] = "-Xi"; /* immediate _exit() on SIGTERM */
		sprintf(admin,"ADMIN=%s",DELEGATE_ADMIN);
		av[ac++] = admin;
		sprintf(logtype,"-L0x%x/%d",LOG_type,curLogFd());
		av[ac++] = logtype;
	}

	if( lVERB() )
		av[ac++] = "-vv";
	if( env = getEnv(P_VARDIR) ){
		sprintf(vardir,"%s=%s",P_VARDIR,env);
		av[ac++] = vardir;
	}
	if( env = getEnv(P_LOGDIR) ){
		sprintf(logdir,"%s=%s",P_LOGDIR,env);
		av[ac++] = logdir;
	}
	if( env = getEnv(P_LOGFILE) ){
		sprintf(logfile,"%s=%s",P_LOGFILE,env);
		av[ac++] = logfile;
	}

	sprintf(desc,"(X proxy for %s)",me);
	av[ac++] = desc;

	strcpy(hosts,"HOSTS=");
	dump_HOSTS(TVStr(hosts));
	av[ac++] = hosts;

	av[ac] = 0;
	Execvp("Xproxy",EXEC_PATH,av);
	Finish(0);
	return -1;
}



void fdcheck(PCStr(msg),int waits)
{	CStr(fds,256);
	refQStr(fdp,fds); /**/
	int fd;

	for( fd = 0; fd < 64; fd++ ){
		if( 0 <= file_uid(fd) ){
			sprintf(fdp,"[%2d]",fd);
			fdp += strlen(fdp);
		}
	}
	setVStrEnd(fdp,0);
	fprintf(stderr,"####[%d]%s ACTIVE FD: %s\n",getpid(),msg,fds);

	if( waits ){
		signal(SIGHUP, sigHUP);
		fprintf(stderr,"#### (%s) SLEEPING\n",msg);
		sleep(waits);
	}
}

static int callFunc(Connection *Conn,int ac,const char *av[],Efd *clSock,int svsock)
{	const char *env;
	iFUNCP func; Int64 ifunc;
	const char *funcenv;
	const char *arg;
	int clsock;

	clsock = getEfd(clSock);
	config(Conn,clsock);

	funcenv = getenv("FUNCADDR");
	Xsscanf(funcenv,"%llx",&ifunc); func = (iFUNCP)ll2p(ifunc);
	arg = getenv("FUNCARG");
	Verbose("EXEC START: %d %d func=%x arg[%s]\n",
		clsock,svsock,xp2i(func),arg);
	(*func)(Conn,clsock,svsock,ac,av,arg);
	Finish(0);
	return -1;
}
int execFunc(Connection *Conn,int clsock,int svsock,iFUNCP func,PCStr(arg))
{	Efd clSockb,*clSock = &clSockb;
	CStr(funcenv,32);
	CStr(argenv,4098);
	int pid;

	if( INHERENT_fork() )
		if( pid = fork() )
			return pid;

	if( Conn == NULL )
		Conn = mainConn;

	sprintf(funcenv,"FUNCADDR=%llx",p2ll(func)); putenv(funcenv);
	sprintf(argenv,"FUNCARG=%s",arg); putenv(argenv);

	Verbose("START EXEC: %d %d func=%x arg[%s]\n",
		clsock,svsock,xp2i(func),arg);

	setEfd(clSock,clsock,"","",0);

	if( 0 <= clsock ) setclientsock(clsock);
	if( 0 <= svsock ) setserversock(svsock);
	pid = EXEC_client1(Conn,EXEC_PATH,FuncFunc,svsock,clSock);
	return pid;
}

extern const char *mainProcTitleFmt;
void mainProcTitle(Connection *Conn)
{	CStr(stat,256);

	strfLoadStat(AVStr(stat),sizeof(stat),mainProcTitleFmt,time(NULL));
	ProcTitle(Conn,"%s",stat);
}

#define PSTITLE_END "--"
extern struct _pstitle_area { defQStr(p); } pstitle_area;
extern int   pstitle_size;
extern int   pstitle_lengmax;
extern int   pstitle_leng; /* length of original arguments */
static char *pstitle_head;
static char *pstitle_tail;
static int   pstitle_tailleng;

void setProcTitleHead(PCStr(arg0),int ac,const char *av[])
{	CStr(buff,1024);
	const char *arg;
	int ai,bi,len,dispend;

	/*
	if( lEXEC() || lSEXEC() ){
	*/
	if( lEXEC() ){
		/* don't show internal parameters for internal exec (-x) */
		return;
	}
	wordScan(arg0,buff);
	Strdup(&pstitle_head,buff);

	bi = 0;
	dispend = 0;
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		len = strlen(arg);
		if( strncmp(arg,PSTITLE_END,strlen(PSTITLE_END)) == 0 ){
		  if( !strneq(arg,OLDCHROOT,strlen(OLDCHROOT)) ){
			dispend = ai;
			break;
		  }
		}
		if( sizeof(buff) <= bi + len )
			break;
		setVStrElemInc(buff,bi,' ');
		Xstrcpy(DVStr(buff,bi),arg);
		bi += len;
	}
	if( dispend == 0 )
		bi = 0;
	setVStrEnd(buff,bi);
	pstitle_tailleng = bi;
	Strdup(&pstitle_tail,buff);
}

void FMT_ProcTitle(Connection *Conn,PCStr(fmt),...)
{	CStr(buff,4096);
	refQStr(sp,buff); /**/
	const char *tail;
	int bsize,minleng;
	VARGS(8,fmt);

	if( isWindows() ){
		return;
	}
	if( Conn == NULL )
		return;
	if( pstitle_head == NULL )
		return;
	if( lMULTIST() && 0 <= ClientSock ){
		/* 9.9.8 don't update proc-title for each session */
		return;
	}

	/*
	 * ps-title string set as argv[0] should be long enough
	 * so that possibly cached argv[1-] string is not shown
	 */
	minleng = 80;

	bsize = pstitle_lengmax;
	if( sizeof(buff) < bsize )
		bsize = sizeof(buff);
	if( bsize < minleng )
		minleng = bsize;

	if( lTHREADLOG() ){
		IStr(tm,32);
		StrftimeLocal(AVStr(tm),sizeof(tm),"%H:%M:%S",time(0),0);
		sp = Sprintf(AVStr(sp),"%s %s[%d]-{",pstitle_head,tm,getpid());
	}else
	if( IsMacOSX() )
		sp = Sprintf(AVStr(sp),"%s= -{",pstitle_head);
	else	sp = Sprintf(AVStr(sp),"%s -{",pstitle_head);
	if( Getpid() != ServerPID ){
		sp = Sprintf(AVStr(sp),"%03d+%02d",CHILD_SERNO,CHILD_SERNO_MULTI);
		if( RequestSerno || ServReqSerno )
			sp = Sprintf(AVStr(sp),"/%03d",RequestSerno);
		if( ServReqSerno )
			sp = Sprintf(AVStr(sp),"/%03d",ServReqSerno);
	}else{
		sp = Sprintf(AVStr(sp),"%03d",CHILD_SERNO);
		if( StickyDone || CHILD_SERNO_SINGLE )
			sp = Sprintf(AVStr(sp),":");
		if( 0 < StickyDone )
			sp = Sprintf(AVStr(sp),"%03d/%03d",StickyNserved,StickyDone);
		if( 0 < CHILD_SERNO_SINGLE )
			sp = Sprintf(AVStr(sp),"+%03d",CHILD_SERNO_SINGLE);
	}
	if( 0 < ClientSock ){
		sp = Sprintf(AVStr(sp),":");
		if( getClientHostPort(Conn,AVStr(sp)) )
			sp += strlen(sp);
	}

	sp = Sprintf(AVStr(sp),"}[");
	sp = Sprintf(AVStr(sp),fmt,VA8);
	sp = Sprintf(AVStr(sp),"]-P");
	primaryPort(AVStr(sp));
	sp += strlen(sp);
	/*
	sp = Sprintf(AVStr(sp),pstitle_tail);
	*/
	sp = Sprintf(AVStr(sp),"%s",pstitle_tail);
	sp = Sprintf(AVStr(sp)," -- ");

	if( sp - buff < minleng ){
		tail = buff + minleng -1;
		while( sp < tail )
			setVStrPtrInc(sp,'-');
		setVStrPtrInc(sp,0);
	}

	if( bsize <= sp-buff){
		sv1tlog("ProcTitle overflow: %d\n",ll2i(sp-buff));
		setVStrEnd(buff,bsize-1);
		sv1tlog("ProcTitle overflow: %s\n",buff);
		Finish(-1);
	}
	proc_title("%s",buff);
}

void minit_logs();
void minit_main();
void minit_resconf();
void minit_tmpfile();
void minit_html();
void minit_http();
void minit_timer();
void minit_socks5();
void minit_hostlist();
void minit_ports();
void minit_inets();
void minit_access();
void minit_mount();
void minit_loadstat();
void minit_envs();
void minit_script();
void minit_socks();
void minit_ccache();
void minit_filetype();
void minit_textconv();
void minit_cron();
void minit_ftp();
void minit_smtp();
void minit_vsapcl();
void minit_url();

void minits(){
	minit_logs();
	minit_main();

	minit_resconf();
	minit_tmpfile();
	minit_html();
	minit_http();
	minit_timer();
	minit_socks5();
	minit_hostlist();
	minit_ports();
	minit_inets();
	minit_access();
	minit_mount();
	minit_loadstat();
	minit_envs();
	minit_script();
	minit_socks();
	minit_ccache();
	minit_filetype();
	minit_textconv();
	minit_cron();
	minit_ftp();
	minit_smtp();
	minit_vsapcl();
	minit_url();
}

void dumpstacksize(PCStr(what),PCStr(fmt),...)
{	const char *top;

	/*
	if( (char*)STACK_PEAK < (top = (const char *)&what)){
	*/
	if( (char*)STACK_PEAK > (top = (const char *)&what)){
		STACK_PEAK = (char*)top;
		if( LOG_type & L_RAND_TRACE ){
			CStr(buf,1024);
			VARGS(8,fmt);
			sprintf(buf,fmt,VA8);
			sv1log("{Rstack}%6d %s %s\n",ll2i(STACK_BASE-top),what,buf);
		}
	}
}

extern int RANDSTACK_RANGE;
extern int RANDSTACK_UNIT;

void initABORT(int sig){
	CStr(reason,64);
	iLOGdump(sig,"---- initABORT() GOT SIG%d ----\n",sig);
	sprintf(reason,"sig%d initABORT()",sig);
	notify_ADMIN(mainConn,reason);
	Finish(sig);
}

int environCRC;
void initWinCRT();
void mainX(int ac,const char *av[])
{	int ai;
	const char *arg;
	const char *areap;
	int areal,areas;
	int mask;
	int rcode;
	int crc = 0;
	int ei;
	const char *e1;

	stdfds[0] = (stdin  == 0) ? -9 : fileno(stdin);
	stdfds[1] = (stdout == 0) ? -9 : fileno(stdout);
	stdfds[2] = (stderr == 0) ? -9 : fileno(stderr);

	fullpath_cmd = fullpathCOM; /* 9.9.7 for Y11 */

	/* 9.9.3-pre6 for ERESTART since 9.9.0-pre4 */
	LOG_UDPsockfd[0] = LOG_UDPsockfd[1] = -1;

	initWinCRT();
	putWinStatus("** Started");
	for( ei = 0; e1 = environ[ei]; ei++ ){
		crc = strCRC32add(crc,e1,strlen(e1));
	}
	environCRC = crc;

	signal(SIGILL,initABORT);
	signal(SIGBUS,initABORT);
	signal(SIGSEGV,initABORT);
	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( streq(arg,"-vW") ){
			LOG_type2 |= L_SPAWNLOG;
		}
		else
		if( streq(arg,"-dI") ){
			LOG_type2 |= L_NOINITLOG;
		}
	}

	START_TIMEP = time(0);
	STACK_BASE = (char*)(((long int)&ac) | 0xFFFFF);
	STACK_PEAK = STACK_BASE;

	if( 0 < ac && asFunc(av[0]) ){
		/* 9.9.7 implicit -Ffunc at the beginning */
	}else
	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( *arg == '-' && arg[1] == 'F' )
			break;
		if( *arg == '-' && arg[1] == 'I' ){
			getInheritedFds(arg+2);
		}
		if( *arg == '-' && arg[1] == 'v' && arg[2] == 'T' ){
			setLogTimeFmt(arg+3);
		}

		if( *arg == '-' && arg[1] == 'R' ){
			RAND_TRACE = 1;
			LOG_type1 |= L_RAND_TRACE;
		}
		if( *arg == '-' && arg[1] == 'd' ){
			if( arg[2] == 'P' )
				LOG_type2 |= L_PATHFIND;
			else
			if( arg[2] == 'V' )
				LOG_type2 |= L_NO_VSNPRINTF;
		}
		if( *arg == '-' && arg[1] == 'f' ){
			LOG_type |= L_FG;
			if( arg[2] == 'v' ){
				LOG_type |= L_CONSOLE;
			}
		}
		if( *arg == '-' && arg[1] == 'v' && arg[2] == 'C' ){
			LOG_type2 |= L_CRYPT;
		}
		if( *arg == '-' && arg[1] == 'v' && arg[2] == 'l' ){
			LOG_type2 |= L_DYLIB; break;
		}
		if( *arg == '-' && arg[1] == 'v' && arg[2] == 'q' ){
			LOG_type4 |= L_QUIET;
		}
		if( *arg == '-' && arg[1] == 'd' ){
			setDebugX(NULL,arg,0);
		}
		if( strneq(arg,"-df",3) ){
			/*
				setup_flog(arg+3);
				LOG_type2 |= L_FLOG;
			 */
		}
	}
	if( !isWindows() ){
		if( mask = sigblock(0) ){
			/* a process forked from StickyServer has SIGHUP mask,
			 * which seems to be cleared, and must be cleared
			 * especially when it is a new server process.
			 */
			/* 0x80000000 SIGUNUSED? is set by default on Debian */
			if( mask & 0x7FFFFFFF )
			sv0log("*** inherited sigmask=0x%X\n",mask);
			sigsetmask(mask & ~sigmask(SIGHUP));
		}
	}

	areap = 0;
	av = (const char**)move_envarg(ac,av,&areap,&areal,&areas);
	if( areap ){
		pstitle_leng = areal;
		setQStr(pstitle_area.p,(char*)areap,areas);
		pstitle_size = areas;
	}
	setProcTitleHead(av[0],ac,av);
	if( isWindowsCE() ){
	}else
	if( INHERENT_alloca() ){
		RANDSTACK_RANGE = 1024;
		RANDSTACK_UNIT = 96;
	}
	rcode =
	randstack_call(SB_PROC,(iFUNCP)delegate_main,ac,av);
	/* do not return to possibly mushed stack */
	if( IsFunc(ac,av) ){
		/* 9.9.7 result code from -Ffunc */
		exit(rcode);
	}
	exit(-1);
}
void checkstdlog(PCStr(msg)){
	int fd;
	for( fd = 0; fd < 256; fd++ )
		if( file_cmp(1,fd) == 0 )
			fprintf(stderr,"###[%s] SAME %d\n",msg,fd);
}

