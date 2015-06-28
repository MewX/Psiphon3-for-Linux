/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	thmain.c (main loop of a multi-threads server)
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
History:
	091202	extracted from delegated.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vsignal.h"
#include "yselect.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "delegate.h"

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


extern int NUM_THSV;
extern int SERVER_TIMEOUT;

void putWinStatus(PCStr(fmt),...);
int refreshWinStatus;
int askWinOK(PCStr(fmt),...);
extern int MAX_SERVICE;
int stopcloseR();
int stopSoxThread();

int PG_AcceptByMain(Connection *Conn,int timeout,int *svsockp,Efd *clSock);
int PG_terminating();
int PG_MainLastAccept();
void PG_incAccServed();
void PG_sigTERM(int sig);
void PG_EXEC_client(Connection *Conn,PCStr(path),PCStr(func),Efd *clSock);
void PG_initConn(Connection *Conn,int csock);

int THPAUSE;
int updateActiveLamp(int act);
void setthread_busy(int tid,int budy);

#define NUM_SESTH 16
extern int THEXIT;
static int LastFd;
static int LastHandle;
static int NumAcc;
static CriticalSec acsc;
static CriticalSec tscs;
static Connection *mainConns[NUM_SESTH];

typedef struct {
    Connection *te_Conn;
	int	te_tsti;
	int	te_tid;
	int	te_tgid;
	int	te_cnt;
	int	te_locking;
	int	te_timeout;
	int	te_now;
	int	te_nsv;
	int	te_acc;
	int	te_acci;
	int	te_accn;
	int	te_done;
	int	te_stat;
} ThreadEnv;
#define Te_Conn	Te->te_Conn
#define Te_Tsti	Te->te_tsti
#define Te_Tid	Te->te_tid
#define Te_Tgid	Te->te_tgid
#define Te_Cnt	Te->te_cnt
#define Te_Lock	Te->te_locking
#define Te_Tout	Te->te_timeout
#define Te_Now	Te->te_now
#define Te_Nsv	Te->te_nsv
#define Te_Acc	Te->te_acc
#define Te_Acci	Te->te_acci
#define Te_Accn	Te->te_accn
#define Te_Done	Te->te_done
#define Te_Stat	Te->te_stat

static ThreadEnv *threadEnv;

#define TSINIT	0
#define TSIDLE	1
#define TSACC	2
#define TSBUSY	4
static int numsessions(int stat){
	int ti,nbusy;
	ThreadEnv *Te;

	nbusy = 0;
	if( threadEnv != 0 ){
		for( ti = 0; ti < NUM_SESTH; ti++ ){
			Te = &threadEnv[ti];
			if( Te_Stat & stat ){
				nbusy++;
			}
		}
	}
	return nbusy;
}
int idlesessions(){
	return numsessions(TSIDLE);
}
int busysessions(){
	return numsessions(TSBUSY);
}

int getSTStat(PVStr(stat)){
	refQStr(sp,stat);
	int ti,tn;
	ThreadEnv *Te;

	tn = 0;
	if( threadEnv != 0 ){
		for( ti = 0; ti < NUM_SESTH; ti++ ){
			Te = &threadEnv[ti];
			if( Te_Done ){
				if( stat < sp )
					setVStrPtrInc(sp,' ');
				sprintf(sp,"%d",Te_Done);
				sp += strlen(sp);
			}
		}
	}
	return tn;
}
int getSessionThreadInfo(int agid,int *serno,int *reqno,int *svreu,Connection **sConn){
	int ti;
	int gid;
	ThreadEnv *Te;
	Connection *Conn;

	if( serno ) *serno = 0;
	if( reqno ) *reqno = 0;
	if( svreu ) *svreu = 0;
	if( sConn ) *sConn = 0;
	if( threadEnv == 0 )
		return 0;

	if( agid )
		gid = agid;
	else	gid = getthreadgid(0);
	for( ti = 0; ti < NUM_SESTH; ti++ ){
		Te = &threadEnv[ti];
		if( Te_Tid == 0 )
			break;
		if( Te_Tid == gid ){
			Conn = Te_Conn;
			if( sConn ) *sConn = Conn;
			if( serno ) *serno = Te_Accn;
			if( reqno && Conn ) *reqno = RequestSerno;
			if( svreu && Conn ) *svreu = ServReqSerno;
			return 1+ti;
		}
	}
	return 0;
}
Connection *SessionConn(){
	Connection *Conn = 0;
	getSessionThreadInfo(0,0,0,0,&Conn);
	return Conn;
}

static int AccFdQue[2] = {-1,-1};
int AccThread = 1;
static int clSockQz = 32;
static int clSockQi;
static int clSockQo;
static Efd *clSockQ = 0;
static void enQ(Efd *clSock){
	char xi;
	int wcc;

	while( clSockQz <= clSockQi-clSockQo ){
		sv1log("--(%d)-enQ- waiting %d %d\n",clSockQi-clSockQo,clSockQi,clSockQo);
		msleep(300);
	}
	xi = clSockQi++ % clSockQz;
	clSockQ[xi] = *clSock;
	wcc = write(AccFdQue[1],&xi,sizeof(xi));
	sv1log("--(%d)-enQ-[%2d] %2d(%d %d)\n",clSockQi-clSockQo,getEfd(clSock),xi,clSockQi,clSockQo);
}
static int deQ(Efd *clSock){
	char xi;
	int rcc;

	rcc = read(AccFdQue[0],&xi,sizeof(xi));
	if( rcc < 1 ){
		return -1;
	}
	*clSock = clSockQ[xi];
	clSockQo++;
	sv1log("--(%d)-deQ-[%2d] [%2d]%d %d\n",clSockQi-clSockQo,getEfd(clSock),xi,clSockQi,clSockQo);
	return 0;
}

static void ThreadServer1(int ti,void **tscs,void **acsc,ThreadEnv *Te,Connection *Conn){
	int idle,sched_next;
	int svsock,clsock;
	Efd *clSock = &STX_clSock;

	Te_Conn = Conn;
	Te_Tid = getthreadid();
	bzero(clSock,sizeof(Efd));
	Te_Tout = 15;
	STX_tix = Te_Tsti;
	STX_tid = getthreadid();
	setthreadgid(0,STX_tid);
	setDGLEV(Conn,SB_PROC);

	setthread_FL(Te_Tid,FL_ARG,"waiting");
	for(Te_Cnt = 1;;Te_Cnt++){
		if( THEXIT ){
			break;
		}
		if( PG_terminating() ){
			/* terminating as a service on Win */
			sv1log("#### TERMINATE Service Thread\n");
			break;
		}
		setthread_busy(0,0);
		if( AccThread && 0 <= AccFdQue[0] ){
			if( ti == 0 ){
			}else{
				if( deQ(clSock) == 0 ){
					clsock = getEfd(clSock);
					/* sefosfhande_FL(clsock,gtid) */
					goto ACC1;
				}else{
					sv1log("## ACC read() FATAL %d,%d\n",
						THEXIT,PG_terminating());
					break;
				}
			}
		}
		Te_Stat = TSIDLE;
		while( THPAUSE ){
			if( THEXIT || PG_terminating() ){
				break;
			}
			msleep(300);
		}
		Te_Nsv = TOTAL_SERVED;
		if( Te_Lock ){
			Te_Now = time(0);
			if( 2 < Te_Now - Te_Lock ){
				leaveCSC(tscs);
				Te_Lock = 0;
			}else{
				Te_Lock = Te_Now;
			}
		}
		if( !isWindowsCE() ){
			/* 9.8.2 Te_Lock is to reduce active threads on small
			 * cache on CPU as ARM (WinCE)
			 * 9.8.6 this is bad on usual CPU causing blocking
			 * new request with long-life threads as HTTP-ACCEPT
			 * for VSAP.
			 */
		}else
		if( Te_Lock == 0 ){
			Te_Acc = NumAcc;
			if( enterCSCX(tscs,100+Te_Tsti*100) == 0 ){
				Te_Lock = time(0);
			}else{
				if( Te_Acc < NumAcc ){
					continue;
				}
				if( Te_Nsv < TOTAL_SERVED ){
					continue;
				}
				/* the other threads seems busy */
			}
		}
		if( MAX_SERVICE ){
			if( MAX_SERVICE <= TOTAL_SERVED ){
				sv1log("MAX_SERVICE done: %d\n",MAX_SERVICE);
				break;
			}
		}
		Te_Now = time(0);
		if( SERVER_TIMEOUT ){
			idle = Te_Now - PG_MainLastAccept();
			if(  SERVER_TIMEOUT < idle ){
				sv1log("SERVER_TIMEOUT: %d seconds.\n",idle);
				break;
			}
			if( Te_Tout <= 0 || 15 < Te_Tout )
				Te_Tout = 15;
		}
		/*
		sched_next = sched_execute(Te_Now,(iFUNCP)sched_action,Conn);
		if( Te_Now < sched_next && sched_next-Te_Now < Te_Tout )
			Te_Tout = sched_next-Te_Now;
		*/

		if( THEXIT ){
			break;
		}
		if( enterCSCX(acsc,3*1000+Te_Tsti*100) < 0 ){
			continue;
		}
		if( THEXIT ){
			leaveCSC(acsc);
			break;
		}
		setthread_busy(0,1);
		NumAcc++;
		Te_Acci = NumAcc;
		Te_Accn++;
		setthread_FL(Te_Tid,FL_ARG,"accepting");
		Te_Stat = TSACC;
		bzero(clSock,sizeof(Efd));
		clsock = PG_AcceptByMain(Conn,Te_Tout,&svsock,clSock);
		putLoadStat(ST_ACC,1);
		STX_ser++;
		leaveCSC(acsc);
		if( THEXIT ){
			break;
		}

		if( clsock < 0 ){
			/*
			LOG_checkAged(0);
			*/
			setthread_FL(Te_Tid,FL_ARG,"waiting");
			continue;
		}else{
			PG_incAccServed();
		}
		if( AccThread && 0 <= AccFdQue[1] ){
			if( ti == 0 ){
				enQ(clSock);
				continue;
			}
		}

	ACC1:
		LastFd = clsock;
		LastHandle = SocketOf(clsock);
		setthread_FL(Te_Tid,FL_ARG,"relaying");
		Te_Stat = TSBUSY;
		PG_EXEC_client(Conn,EXEC_PATH,NULL,clSock);
		/*
		TOTAL_SERVED++;
		*/
		*pTOTAL_SERVED += 1;
		PG_initConn(Conn,-1);
		closeEfd(clSock);
		Te_Done++;
		updateActiveLamp(Te_Done);
		setthread_FL(Te_Tid,FL_ARG,"waiting");
	}
	if( Te_Lock ){
		leaveCSC(tscs);
		Te_Lock = 0;
	}
}
void dumpDGFL(void *myConn,FILE *tc){
	Connection *Conn;
	int ci;
	ThreadEnv *Te;

	if( threadEnv == 0 ){
		return;
	}
	for( ci = 0; ci < elnumof(mainConns); ci++ ){
		Conn = mainConns[ci];
		if( Conn == 0 )
			break;
		Te = &threadEnv[ci];
	fprintf(tc,"--ST[%2d] %d %4X %5d %5d %5d %s:%d Q%d S%d %s:%d %s\n",
			ci,
			STX_tix,PRTID(STX_tid),Te_Acc,Te_Acci,STX_ser,
			STX_F?STX_F:"",STX_L,
			RequestSerno,ServReqSerno,DST_HOST,DST_PORT,
			Conn==myConn?"*":""
		);
	}
}
int dumpConnects(FILE *out);
void dumpResStat(FILE *out);
void dumpFILEY(FILE *out);
extern int actFILEY;
extern int numFILEY;
int dumpWhere(FILE *out,int flags){
	dumposf(out,"main",18,0,0);
	if( 64 <= actFILEY )
		dumpFILEY(out);
	dumpthreads("",out);
	dumpDGFL(0,out);

	dumpResStat(out);
	dumpConnects(out);
	return 0;
}
void LOGX_stats2(PVStr(line));
extern int DISABLE_MANAUTH;
int pingServPorts();
static void waitThreads(int tids[],int tn){
	double St = Time();
	int ti,err;
	int tid;
	IStr(buf,1024);
	refQStr(bp,buf);

	DISABLE_MANAUTH = -1;
	pingServPorts(); /* to wakeup threads in select() or accept() */
	if( 1 < actthreads() ){
		stopcloseR();
		if( stopSoxThread() == 0 ){
			msleep(100);
		}
	}
	for( ti = 0; ti < tn; ti++ ){
		if( (tid = tids[ti]) == 0 ){
			continue;
		}
		putWinStatus("** Terminating-A (%d/%d/%d threads) **",ti,tn,
			actthreads());
		if( err = thread_wait(tid,1000) ){
			Rsprintf(bp,"** Terminated-1 [%d/%d](%X) ** err=%d\n",
				ti,tn,tid,err);
		}else{
			tids[ti] = 0;
		}
	}
	for( ti = 0; ti < tn; ti++ ){
		if( (tid = tids[ti]) == 0 ){
			continue;
		}
		thread_kill(tid,9);
		putWinStatus("** Terminating-B (%d/%d/%d threads) **",ti,tn,
			actthreads());
		if( err = thread_wait(tids[ti],30*1000) ){
			Rsprintf(bp,"** Terminated-2 [%d/%d](%X) ** err=%d\n",
				ti,tn,tid,err);
		}
	}
	putWinStatus("** Terminated (%d/%.2f) **",tn,Time()-St);
	if( 1 < actthreads() ){
		Rsprintf(bp,"** Terminated (%d/%.2f) ** (%d/%d)\n",tn,
			Time()-St,actthreads(),numthreads());
		askWinOK("Warning: something left on exit\n%s",buf);
	}
}
int finishThreadYY(int tgid);
int dump_ENTR(PCStr(fmt),PVStr(entrance));
int suppressWinStatus;
double awakeSeconds;
int TH_STSIZE = 0x140000; /* 0x100000 is too small for "<=+= 304" relay */
void ThreadServers(Connection *Conn){
	int ti,tid;
	int tids[NUM_SESTH],tn = 0;
	Connection *Conn1;
	double First;
	double Now;
	IStr(rusg,128);
	int ri;
	int si;
	ThreadEnv Tev[NUM_SESTH];
	double Prev1,Now1,Elps1;

	Vsignal(SIGINT,PG_sigTERM);
	Vsignal(SIGTERM,PG_sigTERM);

	setupCSC("ThreadServers",tscs,sizeof(tscs));
	setupCSC("ThreadServers-Accept",acsc,sizeof(acsc));
	bzero(Tev,sizeof(Tev));
	threadEnv = Tev;

	Socketpair(AccFdQue);
	clSockQ = (Efd*)calloc(clSockQz,sizeof(Efd));
	for( ti = 0; ti < NUM_THSV && ti < elnumof(mainConns); ti++ ){
		if( THEXIT ){
			break;
		}
		Conn1 = (Connection*)malloc(sizeof(Connection));
		*Conn1 = *Conn;
		mainConns[ti] = Conn1;
		Tev[ti].te_tsti = ti;
		tid = thread_fork(TH_STSIZE,STX_tid,"ThreadServer1",
			(IFUNCP)ThreadServer1,ti,&tscs,&acsc,&Tev[ti],Conn1);
		fprintf(stderr,"server[%d][%04X] %X\n",ti,PRTID(tid),tid);
		tids[tn++] = tid;
	}
	/*
	ThreadServer1(tscs,acsc,0,Conn);
	*/
	signal(SIGPIPE,sigIGNORE);
	signal(SIGALRM,sigIGNORE);

	First = Time();
	for( ri = 0;; ri++ ){
		IStr(line,256);
		/*
		strfRusage(AVStr(rusg),"%uu %ss %d/%rK %ff",3,NULL);
		*/
		strfRusage(AVStr(rusg),"%uu %ss %d/%rK",3,NULL);
		Now = Time();
		if( suppressWinStatus ){
		}else
		putWinStatus("** Running **");
		if( ri % 3 == 0 ){
			sprintf(line,
			"## %6.1f %4d REQ#%d/%d TH#%2d/%d/%d %s",
				Now-First,TOTAL_SERVED,
				LOGX_appHit,LOGX_appReq,
				actthreads(),actthreadsmax(),numthreads(),
				rusg);
			fprintf(stderr,"%s\n",line);
			syslog_ERROR("%s\n",line);
		}
		if( ri % 12 == 0 ){
			sprintf(line,"## %6.1f ",Now-First);
			LOGX_stats2(TVStr(line));
			Xsprintf(TVStr(line)," CLS#%d/%d",LastHandle,LastFd);
			fprintf(stderr,"%s\n",line);
			syslog_ERROR("%s\n",line);
			strfRusage(AVStr(rusg),"%A",3,NULL);
			fprintf(stderr,"## %6.1f %s\n",Now-First,rusg);
			dumpResStat(stderr);
		}
		if( ri % 24 == 0 ){
			dumpWhere(stderr,0);
		}

		Prev1 = Time();
		for( si = 0; si < 10; si++ ){
			usleep(1000*1000);
			if( THEXIT ){
				break;
			}
			if( PG_terminating() ){
				/* terminating as a service on Win */
				sv1log("#### TERMINATE Service Loop\n");
				break;
			}
			if( refreshWinStatus ){
				refreshWinStatus = 0;
				break;
			}
		}
		Now1 = Time();
		Elps1 = Now1 - Prev1;
		if( 10 < Elps1 && Elps1 < 20 ){
			awakeSeconds += Elps1;
		}

		if( lTHREADSIG() ){
		}
		if( THEXIT ){
			fprintf(stderr,"-- THEXIT=%d\n",THEXIT);
			fflush(stderr);
			break;
		}
		if( PG_terminating() ){
			break;
		}
	}
	finishThreadYY(0);
	dupclosed(AccFdQue[1]);
	dupclosed(AccFdQue[0]);
	threadEnv = 0;
	waitThreads(tids,tn);
}
