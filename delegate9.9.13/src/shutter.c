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
Program:	shutter.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	991209	extracted from delegated.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vsignal.h"
#include "delegate.h"
#include "file.h"
#include "proc.h"
#include "fpoll.h"
#include <errno.h>
int setgotsigTERM(int sig);

/*
#define SHUTOUT	"${ADMDIR}/shutout"
*/
#define ShutOUT	"${ADMDIR}/shutout"
static char *_shutout_dir;
static const char *shutout_dir(){
	if( _shutout_dir == 0 ){
		CStr(buf,1024);
		strcpy(buf,ShutOUT);
		DELEGATE_substfile(AVStr(buf),"",VStrNULL,VStrNULL,VStrNULL);
		_shutout_dir = stralloc(buf);
	}
	return _shutout_dir;
}
#define SHUTOUT shutout_dir()
void setSHUTOUT(){
	shutout_dir();
}

int SHUTOUT_TIMEOUT = 30*60;

static FILE *stopServ(PCStr(what),PCStr(mode),PCStr(host))
{	CStr(path,1024);
	FILE *fp;

	if( host == 0 )
		return 0;

	sprintf(path,"%s/%s",SHUTOUT,host);
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
	fp = dirfopen(what,AVStr(path),mode);
	if( fp == NULL )
		return 0;
	daemonlog("F","#### %s [%s]\n",what,path);
	return fp;
}

static struct {
	int	cl_sock;
  const	char   *cl_addr;
	int	cl_port;
    Connection *cl_Conn;
} curClient;

int dumpThreads(PCStr(wh));
extern const char *PRTHstage;
static FILE *setStopService(PCStr(addr))
{
	/*
	daemonlog("F","####! EMERGENCY STOP !####\n");
	*/
	if( newthreads() || numthreads() || pnumthreads() ){
		extern const char *SSLstage;
		int getXf_list(PVStr(Xf));
		IStr(Xf,128);

		setgotsigTERM(999);
		getXf_list(AVStr(Xf));
		putfLog("####! thread-EMERGENCY-STOP !#### %X in (%s)(%s)(%s)",
			ismainthread(),Xf,SSLstage?SSLstage:"",PRTHstage);
		dumpThreads("thread-EMERGENCY-STOP");
	}
	daemonlog("F","####! EMERGENCY STOP !#### [%d.%X]%X %d/%d\n",
		getpid(),getthreadid(),ismainthread(),
		actthreads(),numthreads());

	return stopServ("setStopService","a",addr);
}
static int getStopService(Connection *Conn,PCStr(addr))
{	FILE *fp;
	int mtime,now;

	if( lSINGLEP() ){
		return 0;
	}
	fp = stopServ("getStopService","r",addr); 
	if( fp == NULL )
		return 0;
	mtime = file_mtime(fileno(fp));
	fclose(fp);
	if( SHUTOUT_TIMEOUT ){
		now = time(NULL);
		if( SHUTOUT_TIMEOUT < now-mtime ){
			daemonlog("F","#### getStopService: expired = %d > %d\n",
				now-mtime,SHUTOUT_TIMEOUT);
			return 0;
		}
	}
	return 1;
}
/*
 * hold the connection untill closed by the intruder
 * behaving like /bin/sh ...
 */
static void holder(FILE *log)
{	FILE *fc,*tc;
	CStr(line,256);
	CStr(com,256);
	CStr(date,64);

	fc = fdopen(curClient.cl_sock,"r");
	tc = fdopen(curClient.cl_sock,"w");
	while( 0 < fPollIn(fc,0) ){
		if( fgets(line,sizeof(line),fc) == NULL )
			break;
		if( log ){
			StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_mdHMS,time(0),0);
			fprintf(log,"%s: %s",date,line);
			fflush(log);
		}
		wordScan(line,com);
		fprintf(tc,"%s: not found\n",com);
		fflush(tc);
		sleep(1);
	}
}

static const char *introFATAL = "\
To administrator:\n\
  Remove this file to restart the service for \"%s\"\n\
This file was created on a fatal error detected in DeleGate,\n\
which COULD BE the result of an ATTACK from the host.\n\
More likely, it can be a usual bug in DeleGate.\n\
See LOGDIR/abort/%s, and consult with the author if necessary.\n\
(You can specify the varidity of shutout like TIMEOUT=shutout:60s)\n\
--\n";

static void logFATAL(FILE *log,PCStr(reason),PCStr(clnt),PCStr(serv))
{	Connection *Conn = curClient.cl_Conn;
	CStr(date,64);
	CStr(port,256);

	printPrimaryPort(AVStr(port));
	fprintf(log,introFATAL,clnt,port);
	fflush(log);
	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_mdHMS,time(0),0);
	fprintf(log,"%s: [%d] reason=%s src=%s dst=%s\n",date,getpid(),
		reason,clnt,serv);
	fflush(log);
	fprintf(log,"%s: [%d] SERVER=%s\n",date,getpid(),DST_PROTO);
	if( DST_HOST[0] ){
		fprintf(log,"%s: [%d] SERVER=%s://%s:%d\n",date,getpid(),
			DST_PROTO,DST_HOST,DST_PORT);
		fflush(log);
	}
	fflush(log);
}
static int exiting;
void SetStopService(PCStr(reason))
{	const char *clnt;
	FILE *clog;
	Connection *Conn = curClient.cl_Conn;

	clnt = curClient.cl_addr;
	clog = setStopService(clnt);
	if( clog )
		logFATAL(clog,reason,clnt,"*:*");
	notify_ADMIN(Conn,reason);
}
void exitFATAL(int sig)
{	FILE *clog,*slog;
	CStr(reason,32);
	const char *clnt;
	CStr(serv,256);
	const char *dp;
	int servport;
	Connection *Conn = curClient.cl_Conn;
	Connection ConnBuf;

	if( exiting != 0 )
		return;
	exiting = 1;

	signal(sig,SIG_DFL);

	sprintf(reason,"SIG%s",sigsym(sig));
	if( streq(reason+3,"???") ){
		sprintf(reason,"SIG#%d",sig);
	}
	if( Conn == NULL ){
		Conn = &ConnBuf;
		bzero(Conn,sizeof(Conn));
	}

	if( sig == SIGSEGV && errno == ENOMEM ){
		syslog_ERROR("#### EXIT on insufficient memory, exceeded data or stack limitation, or exausted swap space. ####\n");
		Finish(-1);
	}

	serv[0] = 0;
	if( 0 < ToS && IsConnected(ToS,NULL) ){
		if( getpeerName(ToS,AVStr(serv),"%A:%P") ){
			dp = strchr(serv,':');
			truncVStr(dp); dp++;
			servport = atoi(dp);
		}
	}

	clnt = curClient.cl_addr;
	clog = setStopService(clnt);
	if( clog )
		logFATAL(clog,reason,clnt,serv);

	if( serv[0] && (slog = setStopService(serv)) ){
		logFATAL(slog,reason,clnt,serv);
		fclose(slog);
	}
	notify_ADMIN(Conn,reason);

	if( curClient.cl_sock < 0 ){
		DELEGATE_sigFATAL(sig);
		Finish(-1);
	}
	ProcTitle(Conn,"INTRUDER !? %s",reason);
	if( Fork("FATAL") == 0 ){
		DELEGATE_sigFATAL(sig);
		Finish(-1);
	}
	wait(0);
	/* send mail to ADMIN ... */
	holder(clog);
	ProcTitle(Conn,"INTRUDER !? disconnected");
	sleep(60);
	Finish(0);
}

static void putStopInfo(Connection *Conn)
{	CStr(mssg,1024);

	mssg[0] = 0;
	/* set protocol dependent header */
	Xsprintf(TVStr(mssg),
"Services for your host[%s] are suspended now on a suspicion of intruder.\r\n",
		curClient.cl_addr);

	if( source_permitted(Conn) )
	Xsprintf(TVStr(mssg),
"Ask your administrator <%s> to check %s/%s\r\n",
		getADMIN1(),ShutOUT,curClient.cl_addr);

	IGNRETP write(curClient.cl_sock,mssg,strlen(mssg));
}

int inShutdown(Connection *Conn,int toC)
{	CStr(addrport,256);
	const char *dp;

	if( getpeerName(ClientSock,AVStr(addrport),"%A:%P") ){
		dp = strchr(addrport,':');
		truncVStr(dp); dp++;
		curClient.cl_sock = toC;
		Strdup((char**)&curClient.cl_addr,addrport);
		curClient.cl_port = atoi(dp);
		curClient.cl_Conn = Conn;
		if( getStopService(Conn,curClient.cl_addr) ){
			putStopInfo(Conn);
			return -1;
		}
	}else{
	}
	return 0;
}
void execGeneralist1(Connection *Conn,int fromC,int toC,int svsock);
int execGeneralist(Connection *Conn,int fromC,int toC,int svsock)
{	CStr(addrport,256);
	const char *dp;
	int port,rcode;

	randenv();
/*
	if( getpeerName(fromC,addrport,"%A:%P") ){
*/
/*
	if( getpeerName(ClientSock,addrport,"%A:%P") ){
		dp = strchr(addrport,':');
		*dp++ = 0;
		curClient.cl_sock = toC;
		Strdup(&curClient.cl_addr,addrport);
		curClient.cl_port = atoi(dp);
		curClient.cl_Conn = Conn;
		if( getStopService(Conn,curClient.cl_addr) ){
			putStopInfo(Conn);
			return -1;
		}
	}else{
	}
*/
	if( inShutdown(Conn,toC) != 0 )
		return -1;

	signal(SIGILL, exitFATAL);
	signal(SIGTRAP,exitFATAL);
	signal(SIGEMT, exitFATAL);
	signal(SIGFPE, exitFATAL);
	signal(SIGSEGV,exitFATAL);
	signal(SIGBUS, exitFATAL);
	rcode = randstack_call(SB_CONN,(iFUNCP)execGeneralist1,Conn,fromC,toC,svsock);
	curClient.cl_sock = -1;
	return rcode;
}

void Abort(int code,PCStr(fmt),...){
	const char *body = 0;
	VARGS(8,fmt);

	setgotsigTERM(99);
	if( errno == ENOMEM ){
		body = "#### EXIT on insufficient memory, exceeded data or stack limitation, or exausted swap space. ####";
		daemonlog("F","%s\n",body);
	}
	daemonlog("F",fmt,VA8);

	if( code == 0 ){
		Connection *Conn = curClient.cl_Conn;
		Connection ConnBuf;
		CStr(reason,256);
		const char *dp;

		if( Conn == NULL ){
			Conn = &ConnBuf;
			bzero(Conn,sizeof(Conn));
		}
		sprintf(reason,fmt,VA8);
		if( dp = strpbrk(reason,"\r\n") )
			truncVStr(dp);
		notify_ADMINX(Conn,getADMIN1(),reason,body);
		Finish(-1);
	}else{
		abort();
	}
}
