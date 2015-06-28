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
Program:	notify.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    category
	emergent
	infomational
	periodical report
	...

History:
	991207	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include "delegate.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"

int putAbortLog(FILE *fp);
extern int START_TIME;
void sendmail1(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log);
void putBackTrace(FILE *out);
FILE *curLogFp();

void notify_ADMIN(Connection *xConn,PCStr(what))
{
	notify_ADMINX(xConn,getADMIN1(),what,"");
}
extern char *STACK_BASE;
extern char *STACK_PEAK;
extern unsigned int STACK_SIZE;
void iLOGdump1(FILE *lfp,int sig);
FileSize file_copyTimeout(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout);
int iamServer();

void notify_ADMINX(Connection *xConn,PCStr(admin),PCStr(what),PCStr(body))
{	FILE *tmp;
	FILE *bt;
	Connection ConnBuff,*Conn = &ConnBuff;
	CStr(head,1024);
	CStr(me,128);
	CStr(date,128);
	CStr(load,128);
	CStr(cwd,1024);
	CStr(uname,128);
	int now;
	const char *bugbox = "bugs@delegate.org";
	CStr(msgid,1024);
	CStr(buf,1024);

	if( strncasecmp(what,"sig",3) != 0 )
	if( strncasecmp(what,"failed",6) != 0 )
	if( strncasecmp(what,"modified",8) != 0 )
	if( strncasecmp(what,"approved",8) != 0 )
	if( strncasecmp(what,"detected",8) != 0 )
	if( strncasecmp(what,"[",1) != 0 ) /* abort in child process */
		return;

	if( admin == NULL || *admin == 0 )
		admin = getADMIN1();

	now = time(NULL);
	if( xConn )
		*Conn = *xConn;
	else	bzero(Conn,sizeof(Connection));
	tmp = TMPFILE("NOTIFY");

	head[0] = 0;
	if( gethostname(me,sizeof(me)) != 0 )
		strcpy(me,"?");
	sprintf(msgid,"%d.%d.%d@%s",getpid(),itime(0),getuid(),me);

	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_RFC822,now,0);
	Xsprintf(TVStr(head),"Subject: DeleGate-Report: %s\r\n",what);
	Xsprintf(TVStr(head),"From: [%d]@%s\r\n",getuid(),me);
	Xsprintf(TVStr(head),"To: %s (DeleGate ADMIN)\r\n",admin);
	Xsprintf(TVStr(head),"Reply-To: %s\r\n",bugbox);
	Xsprintf(TVStr(head),"Date: %s\r\n",date);
	Xsprintf(TVStr(head),"Message-Id: <%s>\r\n",msgid);
	Xsprintf(TVStr(head),"Content-Type: text/plain\r\n");
	fprintf(tmp,"%s\r\n",head);
	fprintf(tmp,"PLEASE FORWARD THIS MESSAGE TO <%s>.\r\n",bugbox);
	fprintf(tmp,"IT WILL BE HELPFUL FOR DEBUGGING.\r\n");
	fprintf(tmp,"\r\n");
	fprintf(tmp,"%s",head);
	fprintf(tmp,"Event: %s\r\n",what);
	Uname(AVStr(uname));
	fprintf(tmp,"Version: %s (%s)\r\n",DELEGATE_verdate(),uname); 
	fprintf(tmp,"Host: %s\r\n",me);
	fprintf(tmp,"Owner: uid=%d/%d, gid=%d/%d\r\n",
		geteuid(),getuid(),getegid(),getgid());
	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_RFC822,START_TIME,0);
	fprintf(tmp,"Started: %s\r\n",date);
	fprintf(tmp,"Pid: %d\r\n",getpid());
	cwd[0] = 0;
	IGNRETS getcwd(cwd,sizeof(cwd));
	fprintf(tmp,"Cwd: %s\r\n",cwd);
	strfLoadStat(AVStr(load),sizeof(load),"%L (%l)",now);
	fprintf(tmp,"Load: %s\r\n",load);
	fprintf(tmp,"Stack: %X %d/%d\r\n",p2i(STACK_PEAK),ll2i(STACK_BASE-STACK_PEAK),
		STACK_SIZE);
	fprintf(tmp,"\r\n");

	if( iamServer() ){
	}else{
	fprintf(tmp,"Client-Proto: %s\r\n",CLNT_PROTO);
	fprintf(tmp,"Client-Host: %s:%d\r\n",Client_Addr(buf),Client_Port);
	if( TeleportHost[0] )
	fprintf(tmp,"Rident-Host: %s:%d..%s:%d\r\n",TelesockHost,TelesockPort,
		TeleportAddr,TeleportPort);
	fprintf(tmp,"\r\n");
	}
	fprintf(tmp,"%s\r\n",body);

/*
	if( strncasecmp(what,"sig",3) == 0 || *what == '[' ){
*/
	if( strncasecmp(what,"sig",3) == 0
	 || strncasecmp(what,"failed",6) == 0
	 || *what == '[' ){
		fprintf(tmp,"--iLog--begin\r\n");
		iLOGdump1(tmp,0);
		fprintf(tmp,"--iLog--end\r\n");

		fprintf(tmp,"\r\n");
		fprintf(tmp,"--AbortLog--begin\r\n");
		putAbortLog(tmp);
		fprintf(tmp,"--AbortLog--end\r\n");
	}

	if( strncasecmp(what,"sig",3) == 0 ){
		int btout[2];
		double Start = Time();
		int rcc;

		fprintf(tmp,"\r\n");
		fprintf(tmp,"--BackTrace--begin\r\n");
		fflush(tmp);

		if( pipe(btout) == 0 ){
			setNonblockingIO(btout[1],1);
			bt = fdopen(btout[1],"w");
			putBackTrace(bt);
			fclose(bt);
			bt = fdopen(btout[0],"r");
			rcc = file_copyTimeout(bt,tmp,NULL,128*1024,NULL,15);
			fclose(bt);
			sv1log("BatckTrace: %dB / %.1fs\n",rcc,Time()-Start);
		}else{
		bt = TMPFILE("BackTrace");
		putBackTrace(bt);
		fseek(bt,0,0);
		copyfile1(bt,tmp);
		fclose(bt);
		}
		fprintf(tmp,"\r\n");
		fprintf(tmp,"--BackTrace--end\r\n");
	}

	fflush(tmp);
	fseek(tmp,0,0);
	if( curLogFp() ){
		CStr(line,1024);
		while( fgets(line,sizeof(line),tmp) != NULL )
			fprintf(curLogFp(),"--ABORT-- %s",line);
		fseek(tmp,0,0);
	}
	Conn->co_mask = (CONN_NOPROXY | CONN_NOMASTER); 
	sendmail1(Conn,admin,admin,tmp,NULL);
	fclose(tmp);
}

static FILE *dout;
static double dStart;
static void __BtLog(const char *fmt,...){
	CStr(msg,64);
	double Lap = Time()-dStart;
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	daemonlog("F","## %.3f %s\n",Lap,msg);
	fprintf(dout,"[%d] ## %.3f %s\n",getpid(),Lap,msg);
	fflush(dout);
	fprintf(stderr,"[%d] ## %.3f %s\n",getpid(),Lap,msg);
}
void putBackTrace(FILE *out)
{	CStr(pid,32);
	int cpid,Cpid,nready,xpid;
	int pipes[2],psync[2];
	CStr(command,128);
	const char *path;
	int mpid = getpid();

	if( INHERENT_fork() == 0 )
		return;

	dout = out;
	dStart = Time();

	IGNRETZ pipe(psync);
	if( (Cpid = fork()) == 0 ){ /* the clone to be traced */
		__BtLog("X target");
		close(psync[1]);
		errno = 0;
		nready =
		PollIn(psync[0],10*1000);
		__BtLog("Y target, nready=%d errno=%d",nready,errno);
		if( nready < 0 && errno == EINTR ){
			/* INTR by ptrace() attach/detach ? */
			errno = 0;
			/* psync[0] become EOF when DBX finised */
			nready = PollIn(psync[0],10*1000);
			__BtLog("Z target, nready=%d errno=%d",nready,errno);
		}
		_exit(0);
	}

	sprintf(pid,"%d",Cpid);
	sprintf(command,"where\ndetach\nquit\n");
	/*
	sprintf(command,"where\nquit\n");
	*/

	IGNRETZ pipe(pipes);
	if( (cpid = fork()) == 0 ){
		close(pipes[1]);
		dup2(pipes[0],0);
		dup2(fileno(out),1);
		dup2(fileno(out),2);
		if( sizeof(void*) == 8 ){ /* DEC ALPHA ? */
			execlp("dbx","dbx",EXEC_PATH,"-pid",pid,(void*)0);
		}
		execlp("dbx","dbx","-q",EXEC_PATH,pid,(void*)0);
		execlp("gdb","gdb","-q",EXEC_PATH,pid,(void*)0);
		path = getenv("PATH");
		fprintf(out,"#### error: no dbx nor gdb in PATH=%s\n",
			path?path:"");
		exit(-1);
	}
	close(pipes[0]);
	IGNRETP write(pipes[1],command,strlen(command));
	close(psync[1]);

	__BtLog("A caller, poll [target=%d DBX=%d]",Cpid,cpid);
	nready = PollIn(psync[0],10*1000);
	__BtLog("B caller, nready=%d errno=%d",nready,errno);
	close(psync[0]);
	close(pipes[1]);
	xpid = NoHangWait();
	if( xpid == 0 ){
		sleep(1);
		xpid = NoHangWait();
	}
	__BtLog("C caller, xpid=%d [%d %d]",xpid,Cpid,cpid);

	if( xpid != Cpid ){
		int Xpid;
	Kill(Cpid,9);
		Xpid = NoHangWait();
		if( Xpid == 0 ){
			sleep(1);
			Xpid = NoHangWait();
		}
		__BtLog("D caller, Xpid=%d [%d %d]",Xpid,Cpid,cpid);
		if( xpid == 0 )
			xpid = Xpid;
	}
	/*
	if( nready == 0 || xpid != cpid ){
	*/
	if( xpid != cpid ){
		int rcode;
		daemonlog("F","\n#### debugger freezed? nready=%d %d/%d/%d\n",
			nready,xpid,cpid,Cpid);
		fprintf(out,"#### error: nready=%d xpid=%d/%d/%d\n",
			nready,xpid,cpid,Cpid);

		rcode = Kill(cpid,9);
		sleep(3);
		xpid = NoHangWait();
		fprintf(out,"#### Terminate Debugger: kill(%d)=%d xpid=%d\n",
			cpid,rcode,xpid);
		__BtLog("#### Terminate Debugger: kill(%d)=%d xpid=%d\n",
			cpid,rcode,xpid);
	}
}

void notify_overflow(PCStr(what),PCStr(buf),int off)
{	CStr(msg,1024);
	refQStr(mp,msg); /**/
	const char *mx;
	int ci,ch;

	mx = msg + (sizeof(msg)-1);
	mp = msg;
	for( ci = 0; ci < off; ci++ ){
		if( mx <= mp )
			break;
		ch = buf[ci] & 0xFF;
		if( 0x40 <= ch && ch < 0x7F || ch == ' ' ){
			setVStrPtrInc(mp,ch);
		}else{
			sprintf(mp,"%%%02X",ch);
			mp += 3;
		}
	}
	setVStrEnd(mp,0);
	daemonlog("F","#### Overflow: %s: %d: %s\n",what,off,msg);
}
