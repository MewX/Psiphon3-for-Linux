/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	ccache.c (Connection Cache)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970125	created
//////////////////////////////////////////////////////////////////////#*/
#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "ystring.h"
#include "vsignal.h"
#include "delegate.h"
#include "fpoll.h"
#include "proc.h"
int MAX_CC = 16;

void clear_DGclnt(Connection *Conn);
FILE *fopenCC(PCStr(server),PCStr(mode),PVStr(path));
FILE *fcloseCC();
void del_CC(int pid,PCStr(how));
void sayStartCC();
void sayFinishCC();

typedef struct {
	MStr(	ce_Mypath,256);
	int	ce_CC_master;
	int	ce_CC_Report[2];
	int	ce_CC_Active;
	int	ce_CC_Procs[256];
} CCacheEnv;
static CCacheEnv *ccacheEnv;
#define Mypath		ccacheEnv[0].ce_Mypath
/**/
#define CC_master	ccacheEnv[0].ce_CC_master
#define CC_Report	ccacheEnv[0].ce_CC_Report
#define CC_Active	ccacheEnv[0].ce_CC_Active
#define CC_Procs	ccacheEnv[0].ce_CC_Procs
void minit_ccache()
{
	if( ccacheEnv == 0 ){
		ccacheEnv = NewStruct(CCacheEnv);
		CC_Report[0] = -1;
		CC_Report[1] = -1;
	}
}


#define LOCALHOST	"127.0.0.1"

extern int CON_RETRY;
static int tryOpen(Connection *Conn,PCStr(user),int xnew,PVStr(path),int *portp)
{	FILE *ccfp;
	CStr(url,1024);
	CStr(server,1024);
	CStr(buff,128);
	int cci,svport,svpid,sock;
	int rcode;
	int conretry;

	/* ServerSiceCC should not connect to another ServerSideCC
	 * of the same protocol with itself...
	 */
	if( !xnew && ImCC /*&& strcmp(DST_PROTO,ImCC_PROTO) == 0*/ ){
		sv1log("serverCC: don't connect svCC from svCC\n");
		return -1;
	}

	sock = -1;
	ccfp = NULL;

	if( user[0] == 0 )
		user = "anonymous";
	sprintf(url,"%s-%s-%s-%d",DST_PROTO,user,DST_HOST,DST_PORT);

	for( cci = 0; cci < MAX_CC; cci++ ){
		sprintf(server,"%s-%d",url,cci);
		if( ccfp = fopenCC(server,"r+",AVStr(path)) ){
			if( xnew ){
				fcloseCC();
				continue;
			}
			if( lock_exclusiveNB(fileno(ccfp)) != 0 ){
				fcloseCC();
				continue;
			}
			svport = -1;
			buff[0] = 0;
			fgets(buff,sizeof(buff),ccfp);
			sscanf(buff,"%d %d",&svport,&svpid);
			if( svpid == getpid() ){
				sv1log("serverCC: don't connect to myself\n");
				fcloseCC();
				continue;
			}

			conretry = CON_RETRY;
			CON_RETRY = 1;
			sock = client_open("serverCC",DST_PROTO,LOCALHOST,svport);
			CON_RETRY = conretry;
			fcloseCC();

			if( 0 <= sock ){
				*portp = svport;
				break;
			}
			sv1log("serverCC: salvaged [%s] %s\n",path,buff);
			unlink(path);

		}else{
			if( !xnew )
				break;

			if( (ccfp = fopenCC(server,"w+",AVStr(path))) == NULL )
				continue;

			if( sock == -1 )
				sock = server_open("serverCC",CVStr(LOCALHOST),0,1);
			svport = sockPort(sock);
			sprintf(buff,"%d %d\n",svport,getpid());
			fputs(buff,ccfp);
			fcloseCC();

			*portp = svport;
			break;
		}
	}
	if( 0 < sock )
		sv1log("serverCC: %s [%s] %s",xnew?"wrote":"read",path,buff);
	else if( xnew )
		sv1log("serverCC: cannot open Connection Cache file\n");
	return sock;
}
int CC_open(PCStr(proto),PCStr(host),int port,PCStr(user),int xnew){
	Connection ConnBuf, *Conn = &ConnBuf;
	CStr(path,1024);
	int sock;
	int xport;

	bzero(Conn,sizeof(Connection));
	strcpy(REAL_PROTO,proto);
	strcpy(REAL_HOST,host);
	REAL_PORT = port;
	sock = tryOpen(Conn,user,xnew,AVStr(path),&xport);
	return sock;
}
int CC_connect(PCStr(proto),PCStr(host),int port,PCStr(user)){
	int svsock;
	svsock = CC_open(proto,host,port,user,0);
	sv1log("---- CC connect got %d\n",svsock);
	return svsock;
}
int serverPid();
static int CCready(int timeout,int svacc,int svcon){
	int fdv[2],rdv[2],nready;
	double Start,Elp;

	fdv[0] = svacc;
	fdv[1] = svcon;
	sv1log("---- CC watching acc[%d]con[%d]pid[%d]\n",
		svacc,svcon,serverPid());

	Start = Time();
	for(;;){
		Elp = Time() - Start;
		Verbose("---- CC watching acc[%d]con[%d]pid[%d]%.1fs\n",
			svacc,svcon,serverPid(),Elp);
		if( timeout < Elp ){
			sv1log("---- CC timeout[%d]\n",svcon);
			break;
		}
		nready = PollIns(5*1000,2,fdv,rdv);
		if( 0 < nready ){
			if( 0 < rdv[1] ){
				sv1log("---- CC eof from the server[%d]\n",
					svcon);
				break;
			}
			if( 0 < rdv[0] ){
				return 1;
			}
		}
		if( !procIsAlive(serverPid()) ){
			sv1log("---- CC service done [%d]\n",serverPid());
			break;
		}
	}
	return -1;
}
int CC_TIMEOUT = 180;
int CC_accept(PCStr(proto),PCStr(host),int port,PCStr(user),int fromS){
	int mysock;
	int clsock;

	mysock = CC_open(proto,host,port,user,1);
	sv1log("---- CC accept got mysock=%d\n",mysock);
	if( 0 <= mysock ){
		Connection ConnBuf, *Conn = &ConnBuf;
		bzero(Conn,sizeof(Connection));
		ProcTitle(Conn,"SFTPCC://%s@%s:%d",user,host,port);

		/*
		if( 0 < PollIn(mysock,0) ){
		*/
		if( 0 < CCready(CC_TIMEOUT,mysock,fromS) ){
			clsock = ACCEPT(mysock,1,-1,10);
		}else	clsock = -1;
		sv1log("---- CC accept got clsock=%d\n",clsock);
		close(mysock);
		return clsock;
	}
	sv1log("---- CC accept can't get mysock\n");
	return -1;
}

static void sigTERM(int sig)
{
	sv1log("SIGTERM for BoundProxy: %s\n",Mypath);
	unlink(Mypath);
	Finish(0);
}

void beBoundProxy(Connection *Conn,PCStr(user),int timeout,iFUNCP func,...)
{	int svsock,svport,clsock,clport;
	CStr(path,1024);
	CStr(stime,128);
	CStr(clhost,MaxHostNameLen);
	int rcode;
	FILE *ccfp;
	int ccc,start,done;
	int startSerno;
	int fdv[3],rfdv[3];
	VARGS(8,func);

	if( ServViaCc )
		return;

	checkCloseOnTimeout(0);
	closedups(0);

	if( Conn->xf_filters ){
		/* no good on Windows */
		sv1log("#### NO CC with CFI filters = 0x%x\n",Conn->xf_filters);
		return;
	}

	svsock = tryOpen(Conn,user,1,AVStr(path),&svport);
	if( svsock < 0 )
		return;

	sayStartCC();

	strcpy(Mypath,path);
	Vsignal(SIGINT,sigTERM);
	Vsignal(SIGTERM,sigTERM);
	close_FSERVER(Conn,0);

	if( ccfp = fopen(path,"a") )
	for( ccc = 1; ; ccc++ ){
		clear_DGclnt(Conn);
		ProcTitle(Conn,"(standby=%s://%s:%d)",DST_PROTO,DST_HOST,DST_PORT);

		fdv[0] = svsock;
		fdv[1] = ToS;
		fdv[2] = FromS;

		if( PollIns(timeout*1000,3,fdv,rfdv) <= 0 ){
			sv1log("serverCC: exit by timeout=%ds\n",timeout);
			break;
		}
		if( !IsConnected(ToS,NULL) || !IsConnected(FromS,NULL) ){
			sv1log("serverCC: exit by stale CC [%d=%d][%d=%d].\n",
				ToS,rfdv[1],FromS,rfdv[2]);
			break;
		}
		if( PollIn(FromS,1) != 0 ){
			CStr(buf,128);
			int cc;
			cc = readTIMEOUT(FromS,AVStr(buf),sizeof(buf)-1);
			if( 0 < cc )
				setVStrEnd(buf,cc);
			else	setVStrEnd(buf,0);
			sv1log("serverCC: exit by something from server: %s\n",
				buf);
			break;
		}
		clsock = ACCEPT(svsock,1,-1,10);
		if( clsock < 0 ){
			sv1log("serverCC: exit by accept() failure\n");
			break;
		}

/*
BIND/CONNECT AT LOCLHOST PORT ONLY
		if( !localsocket(clsock) ){
			clport = getpeerNAME(clsock,clhost);
			sv1log("#### forbidden access from remote host(%s)\n",
				clhost,clport);
			close(clsock);
			continue;
		}
*/

		rcode = lock_exclusiveTO(fileno(ccfp),1000,NULL);
		start = time(0L);
		startSerno = RequestSerno;
		StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_ANSI_C,start,0);
		fprintf(ccfp,"[%s] start\n",stime);
		fflush(ccfp);
		sv1log("%sCC [%d] restart\n",DST_PROTO,ccc);

		ProcTitle(Conn,"(%s://%s:%d)",DST_PROTO,DST_HOST,DST_PORT);
		FromC = ToC = ClientSock = clsock;
		ImCC = 1;

		setsockbuf(clsock,32*1024,32*1024);
		rcode = (*func)(Conn,VA8);
		ImCC = 0;
		close(clsock);

		done = time(0L);
		StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_ANSI_C,done,0);
		fprintf(ccfp,"[%s] done, %d seconds\n",stime,done-start);
		fflush(ccfp);
		lock_unlock(fileno(ccfp));
		sv1log("%sCC [%d] done, %d requests / %d seconds\n",
			DST_PROTO,ccc,RequestSerno-startSerno,done-start);

		if( rcode != 0 ){
			sv1log("serverCC: exit by exit code=%d\n",rcode);
			break;
		}
	}
	close(svsock);
	if( ccfp != NULL )
	fclose(ccfp);
	unlink(path);
	sayFinishCC();
}

int connectToCache(Connection *Conn,PCStr(user),int *svsockp)
{	CStr(path,1024);
	int clsock,svport;

	clsock = tryOpen(Conn,user,0,AVStr(path),&svport);
	if( 0 <= clsock ){
		*svsockp = clsock;
		ServViaCc = 1;
		return 1;
	}else	return 0;
}

void set_CC()
{
	if( CC_Report[0] < 0 ){
		CC_master = getpid();
		Socketpair(CC_Report);
		setNonblockingIO(CC_Report[1],1);
		setCloseOnExec(CC_Report[0]);
		setCloseOnExec(CC_Report[1]);
	}
}
void putCCinfo(int pid)
{	int fd;

	if( (fd = CC_Report[1]) < 0 )
		return;
	IGNRETP write(fd,&pid,sizeof(pid));
}
void sayStartCC(){
	/* When the CC_master is not the parent of this process,
	 * it will not able to count down this CC by wait().
	 * Such CC will be fork()ed as a NNTPCC on timeout...
	 */
	if( getppid() != CC_master )
		return;
	putCCinfo(getpid());
}
void sayFinishCC(){
	if( getppid() != CC_master )
		return;
	putCCinfo(-getpid());
}
int num_CC()
{	int fd,pid;

	if( (fd = CC_Report[0]) < 0 )
		return 0;

	if( getpid() != CC_master )
		return 0;

	while( readTimeoutBlocked(fd,GVStr(&pid),sizeof(pid),1)==sizeof(pid) ){
		sv1log("## got_CCinfo: %d\n",pid);
		if( 0 <= pid ){
			sv1log("## add_CC [%d] %d\n",CC_Active,pid);
			CC_Procs[CC_Active++] = pid;
		}else{
			del_CC(-pid,"byRead");
		}
	}
	return CC_Active;
}
void del_CC(int pid,PCStr(how))
{	int ci;

	for( ci = 0; ci < CC_Active; ci++ ){
		if( CC_Procs[ci] == pid ){
			sv1log("## del_CC [%d/%d] %d %s\n",
				ci,CC_Active,pid,how);
			for(; ci < CC_Active; ci++ )
				CC_Procs[ci] = CC_Procs[ci+1];
			CC_Active--;
			break;
		}
	}
}
int kill_CC()
{	int ci,pid,nkill;

	nkill = 0;
	for( ci = 0; ci < CC_Active; ci++ ){
		if( 0 < (pid = CC_Procs[ci]) ){
			if( Kill(pid,SIGTERM) == 0 ){
				sv1log("Killed CC [pid=%d]\n",pid);
				nkill++;
			}
		}
	}
	return nkill;
}
