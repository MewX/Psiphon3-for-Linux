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
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	unix.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	061103	extracted from windows.c
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include "ystring.h"
#include "vsignal.h"
#include "proc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

const char *BINSHELL = "/bin/sh";
int errorECONNRESET;
int LastCpid;

void deltmpfiles();
int curLogFd();
typedef struct sockaddr *SAP0;
void socklog(PCStr(where),int fd,const SAP0 addr,int rcode,int csock);
int setCFIshared();
FileSize Lseek(int fd,FileSize off,int wh);

void env2arg(PCStr(prefix));
extern int MAIN_argc;
extern const char **MAIN_argv;
void DO_INITIALIZE(int ac,const char *av[]);
void DO_FINALIZE(int code);
void DO_STARTUP(int ac,const char *av[]);
static int STARTED;

static int tmpLogFd = -1;

#include "config.h"
#include "log.h"
#define LE (LOGLEVEL<0) ? 0:porting_dbg
#define LT (LOGLEVEL<1) ? 0:porting_dbg
#define LV (LOGLEVEL<2) ? 0:porting_dbg
#define LW (LOGLEVEL<4) ? 0:porting_dbg
#define LS (!lSOCKET() && LOGLEVEL<4) ? 0:porting_dbg
#define DBGWRITE	write
#define SYST		"UNIX"

#ifdef __EMX__
#undef SYST
#define SYST		"OS/2"
#include <os2emx.h>
#endif

#ifdef _MSC_VER /*{*/
#include "vsocket.h"
#undef SYST
#define SYST		"WIN"

#else /*}{*/
int DELEGATE_PAUSE;
int SPAWN_TIMEOUT = 10*1000;
int MIN_DGSPAWN_WAIT = 100; /* expecting when a child is a DeleGate */
int setwaitspawn(int ws){ return 0; }
int winCP;

#define _YSOCKET_H   /* don't include ysocket.h in vsocket.h */
#include "vsocket.h" /* definition of VSAddr */
#include "yarg.h"
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
void setBinaryIO();
int setCloseOnExec(int fd);
int setNonblockingIO(int fd,int on);
int *StructAlloc(int size);

int SocketOf(int sock);
int _BIND(int fd,struct sockaddr *addr,int len)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = bind(sock,addr,len);
	socklog("bind",fd,addr,rcode,fd);
	return rcode;
}
int _ACCEPT(int fd,struct sockaddr *addr,int *len)
{	int csock;

	csock = Xaccept(fd,addr,len);
	socklog("accept",fd,addr,csock,fd);
	return csock;
}
int _CONNECT(int fd,struct sockaddr *addr,int len)
{	int rcode;

	rcode = connect(fd,addr,len);
	socklog("connect",fd,addr,rcode,fd);
	return rcode;
}

int init_socketpair(int port){ return -1; }
void setclosesource(int si){ }
void setclientsock(int sock){ }
int getclientsock(){ return -1; }
int setserversock(int sock){ return -1; }
int getserversock(){ return -1; }
int setcontrolsock(int sock){ return -1; }
int getcontrolsock(){ return -1; }
int setrsvdsock(int si,int sock){ return -1; }
int getrsvdsock(int si){ return -1; }
int send_sock(int dpid,int fd,int closesrc){ return -1; }
int recv_sock(int spid,int ssock,int closesrc){ return -1; }

int SocketOf(int sock){ return sock; }
int closedups(int si){ return 0; }
void dontclosedups(int fd){ }
void setNonblockingPipe(int pv[]){ setNonblockingIO(pv[0],1); }
int setNonblockingSocket(int fd,int on){ return setNonblockingIO(fd,on); }
int file_isselectable(int fd){ return 1; }
int pollPipe(int pfd,int msec){ return -1; }
int numsocks(int *nmaxp){
	if( nmaxp) *nmaxp = 0;
	return 0;
}

int create_service(int ac,const char *av[],PCStr(port))
{
	return 0;
}
int delete_service(int ac,const char *av[],PCStr(port),PCStr(arg))
{
	return 0;
}
int killchildren()
{
	return 0;
}
int killWin(int pid,int sig){
	return -1;
}

/*
int system(PCStr(com))
*/
int unix_system(PCStr(com))
{	int pid,xpid;

	if( com == 0 )
		return 1;
	pid = fork();
	if( pid < 0 )
		return -1;
	if( pid == 0 ){
		execlp(BINSHELL,BINSHELL,"-c",com,NULL);
		exit(-1);
	}
	xpid = waitpid(pid,NULL,0);
	return 0; /* should return the status code */
}
void DO_INITIALIZE(int ac,const char *av[]);
int CFI_init(int ac,const char *av[]){
	if( STARTED ){
		setCFIshared();
		return ac;
	}
	DO_INITIALIZE(ac,av);
	env2arg("CFI_");

	setCFIshared();
	return ac;
}
int SessionFd(){ return -1; }
int setCloseOnExecSocket(int fd){ return setCloseOnExec(fd); }
int clearCloseOnExecSocket(int fd){ return -1; }
int setInheritance(int ifd,int inherit){ return -1; }
int setInheritHandle(int fd,int on){ return -1; }
int getParentSock(){ return -1; }

#ifdef __EMX__ /*{*/
int putenv_sockhandle(int fd,PVStr(env))
{	int shandle;

	shandle = _getsockhandle(fd);
	if( shandle != -1 ){
		sprintf(env,"EMX_SOCKHANDLE%d=%d",fd,shandle);
		putenv(env);
	}
	return shandle;
}

int getenv_sockhandle(int fd){
	CStr(name,32);
	const char *env;
	int shandle,fdx;

	sprintf(name,"EMX_SOCKHANDLE%d",fd);
	if( (env = getenv(name)) && *env ){
		shandle = atoi(env);
		if( 0 <= shandle ){
			for( fdx = 0; fdx < 32; fdx++ ){
				if( _getsockhandle(fdx) == shandle ){
					dup2(fdx,fd);
					return fd;
				}
			}
			fdx = _impsockhandle(shandle,0);
			if( fdx != fd ){
				dup2(fdx,fd);
				close(fdx);
			}
			return fd;
		}
	}
	return -1;
}

void DO_FINALIZE(int code){
	fcloseall();
	deltmpfiles();
	_rmtmp();
}

void DO_STARTUP(int ac,const char *av[])
{
	STARTED = 1;
}
void DO_INITIALIZE(int ac,const char *av[])
{	int fd;
	unsigned long rel = 0, cur;
 
	MAIN_argc = ac;
	MAIN_argv = av;
	DosSetRelMaxFH(&rel, &cur);
	if( cur < 48 ){
		LV("increase MaxFH: %d -> %d",cur,48);
		DosSetMaxFH(48);
	}

	for( fd = 0; fd < 32; fd++ )
		getenv_sockhandle(fd);

	setBinaryIO();
}
extern int SPAWN_P_WAIT;
int execvp(PCStr(path),char *const argv[])
{	int stat;
	int fd;
	char envs[32][32]; /**/

	for( fd = 0; fd < 32; fd++ )
		putenv_sockhandle(fd,envs[fd]);

	stat = spawnvp(SPAWN_P_WAIT,path,argv);
	if( stat == -1 )
		return -1;
	else	exit(stat);
}
int WithSocketFile(){ return 0; }
int getsockHandle(int fd){ return _getsockhandle(fd); }

#else /*}{*/

void DO_STARTUP(int ac,const char *av[])
{
	STARTED = 1;
}
void DO_INITIALIZE(int ac,const char *av[])
{
	MAIN_argc = ac;
	MAIN_argv = av;
	setBinaryIO();
}
void DO_FINALIZE(int code){
/*
	deltmpfiles();
*/
}
int WithSocketFile(){ return 1; }
int getsockHandle(int fd){ return -1; }

#endif /*}*/


int Fork(PCStr(what));
extern char **environ;
extern char **environ;
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph);
int bgexec(PCStr(path),char *av[],char *ev[],int *ph){
	int pid;
	pid = bgexecX("",path,av,ev,ph);
	return pid;
}
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph){
	int pid;

	/* closeServerPorts() */
	if( (pid = Fork("bgexec")) == 0 ){
		char *nev[1024];
		if( strchr(mode,'e') ){
			filterDGENV(environ,nev,elnumof(nev));
			environ = nev;
		}
		execvp(path,av);
		porting_dbg("FAILD exec(%s) errno=%d",path,errno);
		exit(-1);
		return -1;
	}
	*ph = 0;
	return pid;
}
int bgwait(int pid,int ph,double timeout){
	return wait(0);
}

int mysystem(PCStr(path),const char *const *av,const char *const ev[]){
	int pid,xpid;
	int xcode;
	errno = 0;
	if( (pid = Fork("mysystem")) == 0 ){
		environ = (char**)ev;
		execvp(path,(char**)av);
		_exit(0);
	}
	if( pid < 0 ){
		return -1;
	}
	for(;;){
		errno = 0;
		xpid = wait(0);
		if( xpid == pid ){
			xcode = 0;
			break;
		}
		if( errno == ECHILD ){
			xcode = -1;
			break;
		}
	}
	return xcode;
}
int Send_file(int dpid,int fd,int closesrc,int inheritable){ return -1; }
int recv_file(int desc){ return -1; }

int start_service(int ac,const char *av[])
{
	return 0;
}
int restart_service(PCStr(port),int ac,const char *av[])
{
	return 0;
}
int regGetResolvConf(PVStr(buf),PVStr(where))
{
	setVStrEnd(buf,0);
	return -1;
}
int fd2handle(int fd){
	return -1;
}
int pipeX(int sv[2],int size){
	return pipe(sv);
}

int File_uid(PCStr(name));
int ttyuid(int fd){
	int uid = -1;
	const char *name;

	if( isatty(fd) ){
		if( name = ttyname(fd) ){
			uid = File_uid(name);
			if( uid != -1 )
				return uid;
		}
	}
	return -1;
}

int ShutdownSocket(int sock){
	return shutdown(sock,2);
}
int waitShutdownSocket(FL_PAR,int fd,int ms){
	int nready = -2;
	double St = Time();
	int PollIn1(int,int);

	shutdown(fd,SHUT_WR);
	nready = PollIn1(fd,ms);
	syslog_DEBUG("--waitShutdownSocket([%d/%d],%d)=%d,err=%d (%.3f) <= %s:%d",
		fd,SocketOf(fd),ms,nready,errno,Time()-St,FL_BAR);
	return nready;
}

#include <sys/mman.h>
FILE *TMPFILE(PCStr(wh));
int file_size(int fd);
MMap *filemmap(PCStr(fname),PCStr(fmode),int off,int len){
	FILE *fp;
	int fd;
	MMap *mm;
	int rw;
	void *addr;

	if( *fname != 0 ){
		fp = fopen(fname,fmode);
	}else{
		/* this is bad on Zaurus... why?
		fp = TMPFILE("filemmap");
		*/
		fp = tmpfile();
	}
	if( fp == 0 ){
		return 0;
	}
	fd = fileno(fp);
	if( *fmode == 'w' || strchr(fmode,'+') )
		rw = PROT_READ|PROT_WRITE;
	else	rw = PROT_READ;

	if( *fname == 0 && (rw & PROT_WRITE) && 0 < len ){
		/* necessary for CYGWIN */
		fseek(fp,len-1,0);
		fwrite("",1,1,fp);
		fflush(fp);
	}
	if( len == 0 ){
		len = file_size(fd);
	}
	addr = mmap(0,len,rw,MAP_SHARED,fd,off);
	if( addr == 0 || addr == (void*)-1 ){
		fprintf(stderr,"-- %X mmap(%s,%s,%X,%d,%d)=%X errno=%d\n",
			TID,fname,fmode,rw,off,len,p2i(addr),errno);
	}
	if( addr == 0 || addr == (void*)-1 ){
		return 0;
	}
	mm = (MMap*)malloc(sizeof(MMap));
	mm->m_addr = addr;
	mm->m_size = len;
	mm->m_fp = fp;
	mm->m_mh = 0;
	mm->m_fh = 0;
	return mm;
}
int freemmap(MMap *mm){
	int rcode;
	if( mm == 0 ){
		return -1;
	}
	rcode = munmap((char*)mm->m_addr,mm->m_size);
	fclose(mm->m_fp);
	free(mm);
	return rcode;
}
void *getmmap(MMap *mmap){
        return 0;
}       
void *setmmap(void *mh,int off,int len){
	return 0;
}

int inheritLogControl(){
	LOG_UDPsock[0] = LOG_UDPsockfd[0];
	LOG_UDPsock[1] = LOG_UDPsockfd[1];
	return 0;
}

int getAnswerYNtty(PCStr(msg),PVStr(ans),int siz);
int getAnswerYN(PCStr(msg),PVStr(ans),int siz){
	return getAnswerYNtty(msg,BVStr(ans),siz);
}
int getAnswerYNWTO(double dto,PCStr(msg),PVStr(ans),int siz){
	int code;
	code = getAnswerYNtty(msg,BVStr(ans),siz);
	return code;
}
int remoteWinSize(int *w,int *h){
	*w = 0;
	*h = 0;
	return -1;
}
int remoteWinCtrl(FILE *tc,PCStr(com),PCStr(arg),int width,int height,PCStr(query),PCStr(form),PVStr(stat)){
	clearVStr(stat);
	return -1;
}

int regdump_main(int ac,const char *av[],FILE *out,FILE *err){
	return -1;
}
int setRegVal(FILE *tc,PCStr(name),PCStr(val)){
	return -1;
}
int setfdowner(int fd,int tid,int tgid){
	return -1;
}
void popupConsole(){
}
void setWinClassTitleStyle(PCStr(wclass),PCStr(wtitle),PCStr(wstyle)){
}
void putWinStatus(PCStr(fmt),...){
}
int askWinOKWTO(double dtx,PCStr(fmt),...){
	return -1;
}
int askWinOK(PCStr(fmt),...){
	return -1;
}
int updateActiveLamp(int act){
	return -1;
}
void initWinCRT(){
}
int disableWinCtrl(FILE *fp){
	return -1;
}
int ps_unix(FILE *out){
	return -1;
}
int putImpKey(PCStr(opt),PCStr(ekey)){
	return -1;
}
int getImpKey(PCStr(opt),PVStr(ekey)){
	clearVStr(ekey);
	return -1;
}
int dialupTOX(PCStr(wh),int asock,void *addr,int leng,int timeout,PVStr(cstat)){
	return -1;
}
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr)){
	clearVStr(macaddr);
	return (char*)macaddr;
}
void dumpsockets(FILE *out,PCStr(wh)){
}
int testLogin(PCStr(user),PCStr(pass)){
	return -1;
}
#ifndef _MSC_VER
const char *myExePath(){
	return "";
}
#endif
int isWindows95(){ return 0; }
#endif /*}*/

int getAnswerYNtty(PCStr(msg),PVStr(ans),int siz){
	fprintf(stderr,"-------- DeleGate --------\n");
	fprintf(stderr,"%s : y / [n] : ",msg);
	fflush(stderr);
	clearVStr(ans);
	if( fgets(ans,siz,stdin) == 0 ){
		return -1;
	}
	fprintf(stderr,"-------- DeleGate --------\n");
	return 0;
}

char *VSA_xtoap(VSAddr *sa,PVStr(buf),int siz);
void socklog(PCStr(where),int fd,const SAP0 addr,int rcode,int csock)
{	CStr(ina,64);
	CStr(arg,64);
	CStr(self,64);
	int len;
	int serrno;

	if( (lSOCKET()) == 0 )
		return;

	serrno = errno;
	VSA_xtoap((VSAddr*)addr,AVStr(arg),sizeof(arg));

	len = sizeof(ina);
	bzero(ina,len);
	getsockname(csock,(SAP)ina,&len);
	VSA_xtoap((VSAddr*)ina,AVStr(self),sizeof(self));

	LE("{s} %7s(%2d,%-18s)=%2d %s",where,fd,arg,rcode,self);
	errno = serrno;
}

#include "yselect.h" /* FD_SETSIZE */
static int fd_stack[FD_SETSIZE][2];
void push_fd(int fd,int fd2,int rw)
{
	if( fd < 0 || FD_SETSIZE <= fd )
		return;

	fd_stack[fd][rw] = fd2 + 1;
}
int top_fd(int fd,int rw)
{
	if( fd < 0 || FD_SETSIZE <= fd )
		return -1;

	return fd_stack[fd][rw] - 1;
}
int pop_fd(int fd,int rw)
{	int nfd,xfd,xrw;

	if( fd < 0 || FD_SETSIZE <= fd )
		return -1;

	nfd = fd_stack[fd][rw] - 1;
	if( 0 <= nfd ){
		fd_stack[fd][rw] = 0;
		dup2(nfd,fd);

		xrw = (rw+1) % 2;
		xfd = fd_stack[fd][xrw] - 1;
		if( 0 <= xfd ){
			fd_stack[fd][xrw] = 0;
		}
	}
	return nfd;
}
int get_writelimit(int fd,int siz){
	return siz;
}

extern char *LOG_timefmt;
int getthreadid();
static int fileno_set;
static int fileno_stderr = -1;

#ifdef daVARGS
#undef VARGS
#define VARGS daVARGS
#define LINESIZE 1024
#endif

FILE *logMonFp();
extern long Gmt_off;
int getmtpid();

CriticalSec portdbgCSC;

int FMT_porting_dbg(PCStr(fmt),...)
{	CStr(buf,4096);
	int logfd;
	struct timeval tv;
	int now;
	int nowu;
	int hour;
	IStr(ptid,64);
	int nmask,smask;
	VARGS(16,fmt);

	if( !isWindows() ){
	nmask = sigmask(SIGPIPE)|sigmask(SIGTERM)|sigmask(SIGINT);
	smask = sigblock(nmask);
	}

	if( fileno_set == 0 ){
		fileno_set = 1;
		fileno_stderr = fileno(stderr);
	}

	gettimeofday(&tv,NULL);
	now = tv.tv_sec;
	nowu = tv.tv_usec;
	hour = ((tv.tv_sec+Gmt_off) / 3600) % 24;
	if( lSINGLEP() )
		sprintf(ptid,"%04X",TID);
	else
	if( lTHREAD() || lTHREADID() )
		sprintf(ptid,"%4d.%X",getmtpid(),getthreadid());
	else	sprintf(ptid,"%4d",getmtpid());
	sprintf(buf,"(%s) %02d:%02d:%02d.%03d [%s] ",
		SYST,hour,(now%3600)/60,now%60,nowu/1000,ptid);
	Xsprintf(TVStr(buf),fmt,VA16);
	strcat(buf,"\n");

	if( logMonFp() ){
		fwrite(buf,1,strlen(buf),logMonFp());
		fflush(logMonFp());
	}
	if( lSINGLEP() && lMULTIST() ){
		putInitlog("%s",buf);
	}

	if( 0 <= tmpLogFd )
		logfd = tmpLogFd;
	else
	if( curLogFd() < 0 )
		logfd = fileno_stderr;
	else	logfd = curLogFd();
	if( 0 <= logfd ){
		Lseek(logfd,0,2);
		IGNRETP DBGWRITE(logfd,buf,strlen(buf));
	}
	if( 0 <= fileno_stderr ){
		if( lFG() && logfd != fileno_stderr ){
			if( isatty(logfd) && isatty(fileno_stderr) ){
			}else{
				logfd = fileno_stderr;
				Lseek(logfd,0,2);
				IGNRETP DBGWRITE(logfd,buf,strlen(buf));
				addCR(0,logfd,buf);
			}
		}
	}

	if( !isWindows() ){
	sigsetmask(smask);
	}

EXIT:
	return 0;
}

/*
 * windows0.c is included for LE/LV/... ?
 */
#include "windows0.c"

int setNonblockingSocket(int fd,int on);
/*////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	fcntl.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961231	extracted from file.c
	990309	merged to windows0.c
//////////////////////////////////////////////////////////////////////#*/

int setNonblockingIO(int fd,int on)
{	int flags;
	int rcode;

	if( F_SETFL == -1 || O_NDELAY == -1 ){
		rcode = setNonblockingSocket(fd,on);
		if( rcode < 0 ){
			/*
			syslog_ERROR("Non-Blocking I/O not supported\n");
			*/
			syslog_ERROR("Non-Blocking I/O not supported[%d]\n",fd);
			return -1;
		}else	return rcode;
	}

	flags = fcntl(fd,F_GETFL,0);
	if( on )
		flags |=  O_NDELAY;
	else	flags &= ~O_NDELAY;
#ifdef _MSC_VER
	return fcntl(fd,F_SETFL,(void*)flags);
#else
	return fcntl(fd,F_SETFL,flags);
#endif
}

#if !defined(_MSC_VER)
int setDeleteOnClose(FILE *fp,int fd,const char *path){
	return -1;
}
int doDeleteOnClose(int fd,int fh){
	return -1;
}
int doDeleteOnExit(){
	return -1;
}
#endif
