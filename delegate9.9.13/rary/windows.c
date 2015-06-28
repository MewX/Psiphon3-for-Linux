const char *SIGN_windows_c="{FILESIGN=windows.c:20141031194211+0900:735eebc51ee5cd0a:Author@DeleGate.ORG:LnJbSRH+NJcIG4Zr/IJHr3hs8AjWPl9B4F0RVDTHZwuwrzESzIKPxvUre0Uz4eBfgzdZ2vnQB1Z9kYnT4WrqdP6A3kkhkFiUxAEisSUeuSAF/iGsxPmsgsvceAYuaD82CgXsz6FceA21hDG7YKhoASU/EC0qbBWICCLOPaI4Po8=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2007-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	windows.c
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
	A collection of functions to make DeleGate work on Windows.
History:
	970202	created
TODO:
	to be LIBDGWIN.DLL
//////////////////////////////////////////////////////////////////////#*/
/* '"DiGEST-OFF"' */

int win_simple_send;
int RunningAsService;

/* FrOM-HERE
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */
//////////////////////////////////////////////////////////////////////////
#ifdef _MSC_VER
//////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include "ystring.h"
#include "fpoll.h"
#undef socket
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#define FL_Par const char *FL_F,int FL_L
#define FL_Bar FL_F,FL_L
#define FL_Arg __FILE__,__LINE__
#define FL_Arg0 "",0

int dup2_FL(FL_Par,int fd1,int fd2);
int dup_FL(FL_Par,int fd);
int close_FL(FL_Par,int fd);

#if defined UNDER_CE
int _dup_FL(FL_Par,int fd);
int _dup2_FL(FL_Par,int sfd,int dfd);
#define _dup(fd) _dup_FL(FL_Arg,fd)
#define _dup2(fd1,fd2) _dup2_FL(FL_Arg,fd1,fd2)
extern int WCE_sDEBUG();
#define WCE_sDBG WCE_sDEBUG()==0?0:fprintf
int setosf_FL(const char *wh,const char *path,int fd,FILE *fp,FL_Par);
#define isWindowsCE() 1
#else
#define _dup_FL(FL_Par,fd) _dup(fd)
#define _dup2_FL(FL_Par,sfd,dfd) _dup2(sfd,dfd)
#define isWindowsCE() 0
#define setosf_FL(wh,path,fd,fp,FL_Par) 0
#define WCE_sDBG 1?0:
#endif

int curLogFd();
typedef struct sockaddr *SAP0;
void socklog(PCStr(where),int fd,const SAP0 addr,int rcode,int csock);
int setCFIshared();
extern int (*fullpath_cmd)(PCStr(path),PCStr(mode),PVStr(xpath));

void env2arg(PCStr(prefix));
extern int MAIN_argc;
extern const char **MAIN_argv;
void DO_INITIALIZE(int ac,const char *av[]);
void DO_FINALIZE(int code);
void DO_STARTUP(int ac,const char *av[]);

#include "config.h"
#include "log.h"
void wlfprintf(PCStr(fmt),...);

#define WLE (LOGLEVEL<0) ? 0:syslog_ERROR
int porting_dbg(PCStr(fmt),...);
#define LE (LOGLEVEL<0) ? 0:porting_dbg
#define LT (LOGLEVEL<1) ? 0:porting_dbg
#define LV (LOGLEVEL<2) ? 0:porting_dbg
#define LW (LOGLEVEL<4) ? 0:porting_dbg
#define LS (!lSOCKET() && LOGLEVEL<4) ? 0:porting_dbg

char *FILEOWNER = "";
char *FILEACL = "SYSTEM";

#ifdef _MSC_VER

extern int errorECONNRESET;
extern int LastCpid;
extern const char *BINSHELL;

void deltmpfiles();
static int STARTED;
static int tmpLogFd = -1;
int winCP; /* xspawn().CreateProcess() instead of spawnvp() */
int SPAWN_TIMEOUT = 10*1000;
int MIN_DGSPAWN_WAIT = 100; /* expecting when a child is a DeleGate */
int _waitspawn = 10*1000;
int setwaitspawn(int ws){
	int ows = _waitspawn;
	_waitspawn = ws;
	return ows;
}

#include "vsignal.h"
#undef DBGWRITE
#define DBGWRITE	__write
#undef SYST
#define SYST		"WIN"

#define WINSOCKVER	"2.2"
const char *WinSockVer = WINSOCKVER;
#include "ywinsock.h"
#include <sys/timeb.h> /* for ftime() */
#include <share.h> /* _SH_DENYNO */

#include <shlobj.h>
#include <stdio.h>
/*
these are included in "ystring.h"
#include <io.h>
#include <process.h>
#include <direct.h>
*/

#include <crtdbg.h>
#if 1400 <= _MSC_VER
void invalid_parameter_handler(const wchar_t* expression, 
const wchar_t*function,const wchar_t*file,unsigned int line,uintptr_t reserved
){
	if( 2 < LOGLEVEL ){
		fprintf(stderr,"--CRT ERROR\n");
		fflush(stderr);
	}
}
#else
#define _set_invalid_parameter_handler(func)
#endif

int getppid();
int pipe(int*);

int getserversock();
int getclientsock();
FileSize Lseek(int fd,FileSize off,int wh);
int wait3(int *statusp,int options,void *rusage);
static int sessionfd();
static int acceptsocket(int asock);
static int bindsocket(int sock,int *portp);
static int connectsocket(int sock,int port);

int Isend(int sock,const void *buf,unsigned int len,int flags){
	return send(sock,(const char*)buf,len,flags);
}
int Irecv(int sock,void *buf,unsigned int len,int flags){
	return recv(sock,(char*)buf,len,flags);
}

static int sends(int fd,PCStr(buf),int len,int flags)
{	int rem,wcc,mtu,wcc1;
	int xerr;

	rem = len;
	wcc = 0;
	while( 0 < rem ){
		mtu = rem;
		if( WIN_MTU && WIN_MTU < mtu )
			mtu = WIN_MTU;

		wcc1 = send(fd,buf+wcc,mtu,flags);
		if( 0 < wcc1 ){
			LOGX_sentBytes += wcc1;
		}
		if( wcc1 <= 0 ){
			xerr = WSAGetLastError();
			if( 1 < LOGLEVEL || xerr != WSAEWOULDBLOCK )
			if( xerr == WSAECONNRESET || xerr == WSAECONNABORTED )
			LV("send(%d) = %d+%d errno=%d",len,wcc1,wcc,xerr);
			else
			LE("send(%d) = %d+%d errno=%d [%d]",len,wcc1,wcc,xerr,fd);
			if( wcc == 0 )
				wcc = -1;
			if( xerr == WSAEWOULDBLOCK ){
				errno = EAGAIN;
			}else{
				LV("Emulating SIGPIPE: send(%d/%d/%d) err=%d",
					wcc1,wcc,len,xerr);
				errno = EPIPE;
				if( lSINGLEP() ){
LE("-- NO Emulating SIGPIPE: send(%d/%d/%d) err=%d",wcc1,wcc,len,xerr);
				}else
				raise(SIGPIPE);
			}
			break;
		}
		wcc += wcc1;
		rem -= wcc1;
	}
	return wcc;
}

typedef union {
 struct sockaddr_in	_sin;
	char		_sab[64]; /**/
} VSAddr;
typedef struct sockaddr *SAP;
/* vsocket.h */
int VSA_atosa(VSAddr *sa,int port,PCStr(addr));
int VSA_port(VSAddr *sap);
const char *VSA_ntoa(VSAddr *sap);
char *VSA_xtoap(VSAddr *sa,PVStr(buf),int siz);
int start_service(int ac,const char *av[]);
void WINthread();
void setBinaryIO();

#define MAXHANDLE	4096
#define MIS		8 /* the max. number of inherited sockets */

int fd2handle(int fd){
	return _get_osfhandle(fd);
}
int handle2fd(int oh){
	return _open_osfhandle(oh,0);
}
/*
int duposf2(int src,int dst){
	HANDLE sh,dh;
	sh = (HANDLE)_get_osfhandle(src);
	dh = (HANDLE)_get_osfhandle(dst);
	nh = (HANDLE)duphandle(0,dh,0,0,1);
	DuplicateHandle(SELF(),sh,SELF(),&dh,0,1,DUPLICATE_SAME_ACCESS);
	retrun (int)nh;
}
*/
/*
FILE *_fdopen(int fd,const char *mode){
	short wmode[32];
	FILE *fp;
	int mi;

	for( mi = 0; mode[mi] && mi < elnumof(wmode)-1; mi++ )
		wmode[mi] = mode[mi];
	wmode[mi] = 0;
	fp = _wfdopen(fd,(const unsigned short*)wmode);
	return fp;
}
*/

static int __write(int fd,PCStr(buf),int size)
{	int oh;
	int ok;
	unsigned long wcc;

	oh = _get_osfhandle(fd);
	ok = WriteFile((HANDLE)oh,buf,size,&wcc,NULL);
	return wcc;
}
static int __read(int fd,char *buf,int size)
{	int oh;
	int ok;
	unsigned long rcc;
	
	oh = _get_osfhandle(fd);
	ok = ReadFile((HANDLE)oh,buf,size,&rcc,NULL);
	return rcc;
}

/*######## CLOCK ########*/
int gettimeofday(struct timeval *tp, struct timezone *tzp)
{	struct timeb timeb;

	ftime(&timeb);
	tp->tv_sec = timeb.time;
	tp->tv_usec = timeb.millitm * 1000;
	LW("gettimeofday(%x,%x) = [%d,%d]",tp,tzp,tp->tv_sec,tp->tv_usec);
	return 0;
}

/*######## SIGNAL ########*/
#undef sigsetmask
int sigsetmask(int mask){
	/*
	LV("sigsetmask() not supported");
	*/
	return -1;
}
#undef sigblock
int sigblock(int mask){
	/*
	LV("sigblock() not supported");
	*/
	return -1;
}
int killWin(int pid,int sig){
	int rcode = -9;
	HANDLE ph;

	ph = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	if( ph != INVALID_HANDLE_VALUE ){
		rcode = kill((int)ph,sig);
		CloseHandle(ph);
	}
	return rcode;
}
int kill(int pid,int sig){
	HANDLE ph;
	unsigned long int xcode;
	int ok;

	if( sig == 0 ){
		errno = 0;
		if( isWindowsCE() ){
			if( pid == getpid() )
				return 0;
fprintf(stderr,"----WinCE kill(%X,%d)\n",pid,sig);fflush(stderr);
			return 0;
		}
		ph = OpenProcess(PROCESS_QUERY_INFORMATION,0,pid);
		if( ph == NULL ){
			errno = ESRCH;
			return -1;
		}
		xcode = -1;
		ok = GetExitCodeProcess(ph,&xcode);
		CloseHandle(ph);
		if( ok && xcode != STILL_ACTIVE ){
			LV("kill(%d)=-1 the process did exit(%d)",pid,xcode);
			errno = ESRCH;
			return -2;
		}
		return 0;
	}

	ph = (HANDLE)pid;
	/* it should be ph = OpenProcess(pid), but because the pid
	 * argument given is a process handle which is got at spawnvp()...
	 */

	if( !GetExitCodeProcess(ph,&xcode) )
	{	LE("kill(%d,%d) = -1, failed GetExitCodeProcess()",pid,sig);
		return -1;
	}
	if( xcode != STILL_ACTIVE )
	{	LE("kill(%d,%d) = -1, not active (xcode=%d)",pid,sig,xcode);
		return -1;
	}
	if( sig == SIGTERM ){
		if( TerminateProcess(ph,0) )
			return 0;
		else{
			LE("kill(%d,%d) = -1, failed TerminateProcess()",pid,sig);
			return -1;
		}
	}
	LE("kill(%d,%d) not supported",pid,sig);
	return -1;
}

unsigned int alarm(unsigned int sec){
	LE("alarm(%d) not supported",sec);
	return 0;
}
void sleep(unsigned int sec){
	LW("sleep(%d)",sec);
	_sleep(sec*1000);
}

/*######## USER and GROUP ########*/
#include "passwd.h"
static struct passwd passwd;
void setpwent(){
	LV("setpwent()");
}
void endpwent(){
	LV("endpwent()");
}
struct passwd *getpwuid(int uid){
	LV("getpwuid(%d)",uid);
	passwd.pw_name = "windows";
	passwd.pw_passwd = "";
	passwd.pw_uid = 0;
	passwd.pw_gid = 0;
	passwd.pw_quota = 0;
	passwd.pw_comment = "";
	passwd.pw_gecos = "Windows";
	passwd.pw_dir = "/users/default";
	passwd.pw_shell = "";
	return &passwd;
}
int getgrnam(PCStr(name))
{
	LV("getgrnam(%s)",name);
	return 0;
}
int getpwnam(PCStr(name))
{
	LV("getpwnam(%s)",name);
	return 0;
}
int getgrgid(int gid){
	LV("getgrgid(%d)",gid);
	return 0;
}
char *getlogin(void){
	return 0;
}
int setlogin(const char *name){
	return -1;
}

/* ######## PROCESS OWNER ######## */
int getegid(){
	LW("getegid() = 0");
	return 0;
}
int geteuid(){
	LW("geteuid() = 0");
	return 0;
}

int getuid(){
	LW("getuid() = 0");
	return 0;
}
int getgid(){
	LW("getgid() = 0");
	return 0;
}
int setuid(int uid){
	int rcode;
	if( uid == 0 )
		rcode = 0;
	else	rcode = -1;
	LW("setuid(%d) = %d",uid,rcode);
	return rcode;
}
int setgid(int gid){
	int rcode;
	if( gid == 0 )
		rcode = 0;
	else	rcode = -1;
	LW("setgid(%d) = %d",gid,rcode);
	return rcode;
}
int initgroups(const char *user,int group){
	LW("initgroups() = -1");
	return -1;
}

/*######## FILE ########*/

#include <WINDOWS.H>
#include <WINBASE.H>
#if isWindowsCE()
#include "wince.h"
#endif

static HANDLE _SELF;
static HANDLE SELF()
{
	if( _SELF == 0 ){
		_SELF = OpenProcess(PROCESS_ALL_ACCESS,0,getpid());
		LV("PID=%d SELF_HANDLE=%d",getpid(),_SELF);
	}
	return _SELF;
}

int duphandle(HANDLE sproc,HANDLE shandle,HANDLE dproc,int closesrc,int noinherit)
{	HANDLE dhandle;
	DWORD access;
	BOOL inherit;
	DWORD options;

	access = 0;
	inherit = !noinherit; /* FALSE may be good for some sockets... */
	options = DUPLICATE_SAME_ACCESS;
	if( closesrc )
		options |= DUPLICATE_CLOSE_SOURCE;

	if( sproc == NULL ) sproc = SELF();
	if( dproc == NULL ) dproc = SELF();

	dhandle = NULL;
	DuplicateHandle(sproc,shandle,dproc,&dhandle,
		access,inherit,options);

	if( dhandle == NULL )
	LT("DUPHANDLE: %d,%d => %d,%d",sproc,shandle,dproc,dhandle);
	return (int)dhandle;
}
int duphandlei(int shandle,int closesrc,int noinherit){
	return duphandle(0,(HANDLE)shandle,0,closesrc,noinherit);
}

int WITH_symlink(){ return 1; }
int symlink(PCStr(dst),PCStr(src))
{	HRESULT Rc;
	WCHAR wsrc[MAX_PATH]; /**/
	IShellLink* Sl;
	IPersistFile* pf;
	int rcode = -1;
	CStr(dstx,MAX_PATH);

	CoInitialize(NULL);
	MultiByteToWideChar(CP_ACP,0,src,-1,wsrc,MAX_PATH);

	Sl = 0;
	Rc = CoCreateInstance(CLSID_ShellLink,NULL,
		CLSCTX_INPROC_SERVER,IID_IShellLink,(LPVOID *)&Sl);
	if( FAILED(Rc) )
		goto EXIT;
	if( Sl == 0 )
		goto EXIT;

	if( strchr(dst,':') == 0 ){
		if( getcwd(dstx,sizeof(dstx)) == dstx )
		if( dstx[0] != 0 && dstx[1] == ':' )
		{
			Xstrcpy(DVStr(dstx,2),dst);
			dst = dstx;
		}
	}

	Rc = Sl->SetPath(dst);

	Sl->SetDescription("");
	Rc = Sl->QueryInterface(IID_IPersistFile,(LPVOID*)&pf);
	if( SUCCEEDED(Rc) ){
		Rc = pf->Save(wsrc,FALSE);
		pf->Release();
		rcode = 0;
	}
	Sl->Release();

EXIT:	CoUninitialize();
	return rcode;
}

int File_is(PCStr(path));
int File_size(PCStr(path));
int File_mtime(PCStr(path));
int readlink(PCStr(src),char dst[],unsigned int siz)
{	HRESULT Rc;
	WCHAR wsrc[MAX_PATH]; /**/
	IShellLink* Sl;
	IPersistFile* Pf;
	WIN32_FIND_DATA Fd;
	int rcode = -1;

	if( File_size(src) <= 0 && File_mtime(src) <= 0 ){
		/* 9.9.1 Load() can freeze on device file like "con" */
		LV("ERROR readlink(%s) is=%d siz=%d mtm=%d",src,
			File_is(src),File_size(src),File_mtime(src));
		return -1;
	}
	CoInitialize(NULL);
	MultiByteToWideChar(CP_ACP,0,src,-1,wsrc,MAX_PATH);
	*dst = 0;
	Sl = 0;
	Rc = CoCreateInstance(CLSID_ShellLink,NULL,
		CLSCTX_INPROC_SERVER,IID_IShellLink,(LPVOID *)&Sl);
	if( FAILED(Rc) )
		goto EXIT;
	if( Sl == 0 )
		goto EXIT;

	Rc = Sl->QueryInterface(IID_IPersistFile,(void**)&Pf);
	if( SUCCEEDED(Rc) ){
		Rc = Pf->Load(wsrc,STGM_READ);
		if( SUCCEEDED(Rc) ){
			Rc = Sl->GetPath(dst,siz,
				(WIN32_FIND_DATA *)&Fd,SLGP_SHORTPATH);
			if( SUCCEEDED(Rc) )
				rcode = 0;
		}
		Pf->Release();
	}
	Sl->Release();

EXIT:	CoUninitialize();
	if( rcode != 0 ){
	}
	return rcode;
}

/*######## SOCKET ########*/
static WORD wVersionRequested;
static WSADATA wsaData;
static struct {
	int	ws_qver;
	int	ws_code;
	int	ws_errno;
} wsaStat;
static int _nullsock = -1;

#undef socket
#undef accept
static int setSockInh(PCStr(wh),int sock){
	int dsock;
	int on;
	int ok1,ok2;
	int flag;

	if( lDOSOCKINH() ) on = 1; else
	if( lNOSOCKINH() ) on = 0; else
	if( lWOSOCKINH() ) on = 0; else{
		SetHandleInformation((HANDLE)sock,HANDLE_FLAG_INHERIT,
			HANDLE_FLAG_INHERIT);
		return sock;
	}

	flag = on ? HANDLE_FLAG_INHERIT : 0;
	/*
	ok1 = SetHandleInformation((HANDLE)dsock,flag,on);
	*/
	ok1 = SetHandleInformation((HANDLE)sock,flag,on);
	if( ok2 = DuplicateHandle(GetCurrentProcess(),(HANDLE)sock,
	    GetCurrentProcess(),(HANDLE*)&dsock,0,on,DUPLICATE_SAME_ACCESS)
	){
		closesocket(sock);
	}else{
		dsock = sock;
	}
	LV("--Eis %s INHERIT[%d]%d = %d %d",wh,sock,on,ok1,ok2);
	return dsock;
}
static int socketX(int dom,int type,int proto){
	int sock;
	sock = socket(dom,type,proto);
	if( 0 <= sock ){
		sock = setSockInh("socket",sock);
	}
	return sock;
}
static int acceptX(int sock,SAP addr,int *len){
	int csock;
	csock = accept(sock,addr,len);
	if( 0 <= csock ){
		csock = setSockInh("accept",csock);
	}
	return csock;
}
#define socket socketX
#define accept acceptX

void socket_init(){
	int err;
	int qvmaj,qvmin;

	if( wsaData.szDescription[0] != 0 )
		return;
	qvmaj = 1;
	qvmin = 0;
	sscanf(WinSockVer,"%d.%d",&qvmaj,&qvmin);
	wVersionRequested = MAKEWORD(qvmaj,qvmin);
	/*
	wVersionRequested = MAKEWORD(1,1);
	*/
	err = WSAStartup(wVersionRequested,&wsaData);
	wsaStat.ws_qver = wVersionRequested;
	wsaStat.ws_code = err;
	wsaStat.ws_errno = WSAGetLastError();

	_nullsock = socket(AF_INET,SOCK_STREAM,0);
}
int nullsock(){
	return _nullsock;
}
#ifndef UNDER_CE
static void dumpWSAstat()
{	int hi,nh,nhi,nsh,nshi,len,type;
	CStr(sockets,MAXHANDLE*8);
	refQStr(sp,sockets); /**/
	unsigned long int flags;

	if( LOGLEVEL < 4 )
		return;

	LV("WinSock option \"-WSAV:%s\" ReqVer:%x Result:%x Errno:%d",
		WinSockVer,wsaStat.ws_qver,wsaStat.ws_code,wsaStat.ws_errno);
	LV("Version:%x HighVersion:%x Description:%s",
		wsaData.wVersion,wsaData.wHighVersion,wsaData.szDescription);
	LV("SystemStatus:%s MaxSockets:%d MaxUdpDg:%d",
		wsaData.szSystemStatus,wsaData.iMaxSockets,wsaData.iMaxUdpDg);
	if( wsaData.lpVendorInfo )
	LV("VenderInfo:%s",wsaData.lpVendorInfo);

	nh = nsh = nhi = nshi = 0;
	for( hi = 0; hi < MAXHANDLE; hi++ ){
		flags = 0;
		if( GetHandleInformation((HANDLE)hi,&flags) == 0 )
			continue; /* not available on Win95 */
		nh++;
		if( flags & HANDLE_FLAG_INHERIT )
			nhi++;
		if( hi < 128 ){
			/* getsockopt() blocks for lower handle ??? */
			continue;
		}

		len = sizeof(type);
		if( getsockopt(hi,SOL_SOCKET,SO_TYPE,(char*)&type,&len) == 0 ){
			nsh++;
			if( flags & HANDLE_FLAG_INHERIT )
				nshi++;
			sprintf(sp," %d",hi);
			sp += strlen(sp);
			if( type != 1 ){
				sprintf(sp,"/%d",type);
				sp += strlen(sp);
			}
			if( (flags & HANDLE_FLAG_INHERIT) == 0 ){
				sprintf(sp,"#");
				sp += strlen(sp);
			}
		}
	}
	setVStrEnd(sp,0);
	if( *sockets )
	LV("Sockets(%d/%d/%d:%d/%d):%s",nshi,nsh,FD_SETSIZE,nhi,nh,sockets);
}
#else
static void dumpWSAstat(){
}
#endif
static void sockInfo()
{
	if( getppid() == 0 ){
		LT("WINSOCK INFO.");
		LT("Desc: %s",wsaData.szDescription);
		LT("Stat: %s",wsaData.szSystemStatus);
		LT("Maxs: %d, Vend: %s",wsaData.iMaxSockets,wsaData.lpVendorInfo);
	}
}
static int ISSOCK(int sock)
{	int len,type;

	len = sizeof(type);
	if( getsockopt(sock,SOL_SOCKET,SO_TYPE,(char*)&type,&len) == 0 )
		return 1 <= type;
	return 0;
}
struct hostent *gethostbyname2(const char *name,int af){
	return 0;
}

static int NO_SOCKOPEN = 1;
/* bad if this value is zero in CHARCODE filter from FTP/HTTP on WindowsNT
 * where the client SOCKET is inherited twice...
 */

int SocketOf_FL(const char *F,int L,int fd);
#define SocketOf(fd) SocketOf_FL(__FILE__,__LINE__,fd)

#define USE_SOSMAP 1
#if isWindowsCE() || USE_SOSMAP /* ---{ */
#define MAXOSF 256
typedef struct {
	char	x_act;
	char	x_typ;
	int	x_idx;
	int	x_val;
} IdxVal;
static struct {
	int cs_init;
	CRITICAL_SECTION cs;
	int lock;
	IdxVal openosfx[MAXOSF];
	int cs_max;
} SockOsf;

#define SOS_GET 0
#define SOS_SET 1
#define SOS_INC 2
#define SOS_DEC 3
#define SOS_DEL 4
static const char *op_syms[] = {"GET", "SET", "INC", "DEC", "DEL"};

#define TY_OSF 1
#define TY_DUP 2
#define TY_CNT 3
static const char *ty_syms[] = { "?","OSF","DUP","CNT" };

#define SOS_GetOsfh(fd)   idxval(TY_OSF,__LINE__,SOS_GET,fd,0)
#define SOS_SetOsfh(fd,f) idxval(TY_OSF,__LINE__,SOS_SET,fd,f)
#define SOS_DelOsfh(fd)   idxval(TY_OSF,__LINE__,SOS_DEL,fd,0)

#define SOS_GetDuph(fd)   idxval(TY_DUP,__LINE__,SOS_GET,fd,0)
#define SOS_SetDuph(fd,f) idxval(TY_DUP,__LINE__,SOS_SET,fd,f)
#define SOS_DelDuph(fd)   idxval(TY_DUP,__LINE__,SOS_DEL,fd,0)

#define SOS_GetRcnt(sock) idxval(TY_CNT,__LINE__,SOS_GET,sock,0)
#define SOS_IncRcnt(sock) idxval(TY_CNT,__LINE__,SOS_INC,sock,1)
#define SOS_DecRcnt(sock) idxval(TY_CNT,__LINE__,SOS_DEC,sock,1)
#define SOS_DelRcnt(sock) idxval(TY_CNT,__LINE__,SOS_DEL,sock,0)

int numsocks(int *nmaxp){
	int fi;
	IdxVal *iv = SockOsf.openosfx;
	IdxVal *iv1;
	int nact = 0;
	for( fi = 0; fi < MAXOSF; fi++ ){
		iv1 = &iv[fi];
		if( iv1->x_act ){
			nact++;
		}
	}
	if( nmaxp ) *nmaxp = SockOsf.cs_max;
	return nact;
}

int getthreadid();
static const IdxVal NullIdxVal;
static int idxval(int typ,int L,int set,int idx,int val){
	int fi;
	IdxVal *iv = SockOsf.openosfx;
	IdxVal *iv1;
	int nact = 0;
	int rval = 0;
	IdxVal *firstfree = 0;

	if( SockOsf.cs_init == 0 ){
		InitializeCriticalSection(&SockOsf.cs);
		SockOsf.cs_init++;
	}
	EnterCriticalSection(&SockOsf.cs);
	if( 1 < SockOsf.lock++ ){
		int li;
		for( li = 0; li < 100; li++ ){
			fprintf(stderr,"--idxval--locked %d\n",SockOsf.lock);
			_sleep(100);
			if( SockOsf.lock == 1 ){
				break;
			}
		}
	}

	for( fi = 0; fi < MAXOSF; fi++ ){
		iv1 = &iv[fi];
		if( iv1->x_act ){
			nact++;
			if( SockOsf.cs_max < fi ){
				SockOsf.cs_max = fi;
			}
			if( iv1->x_typ == typ && iv1->x_idx == idx ){
				switch( set ){
				    case SOS_GET:
				    case SOS_SET:
				    case SOS_INC:
				    case SOS_DEC:
				    case SOS_DEL:
					goto FOUND;
if( set != SOS_GET )
fprintf(stderr,"--HIT %s windows.c:%d (%d/%2d) %s[%d]=%d %d\n",
op_syms[set],L,nact,fi,ty_syms[typ],idx,iv1->x_val,val);
				}
			}
		}else
		if( set == SOS_GET || set == SOS_DEL ){
		}else
		if( set == SOS_SET || set == SOS_INC || set == SOS_DEC ){
			if( firstfree == 0 ){
				firstfree = iv1;
			}
		}
	}
	if( firstfree != 0 ){
		iv1 = firstfree;
		if( set == SOS_SET || set == SOS_INC ){
			iv1->x_act = 99;
			iv1->x_typ = typ;
			iv1->x_idx = idx;
/*
fprintf(stderr,"--NEW %s windows.c:%d (%d/%2d) %s[%d] %d\n",
op_syms[set],L,nact,fi,ty_syms[typ],idx,val);
*/
			goto FOUND;
		}else
		if( set == SOS_DEC ){
			// dangling ?
		}
	}
if( set == SOS_INC ){
fprintf(stderr,"--MIS %s windows.c:%d (%d/%2d) %s[%d] ???\n",
op_syms[set],L,nact,fi,ty_syms[typ],idx);
 {
  int i;
  for( i = 0; i < MAXOSF; i++){
	iv1 = &iv[fi];
	if( iv1->x_act )
	fprintf(stderr,"sosf[%3d] act=%X %s %d %d\n",i,
		iv1->x_act,ty_syms[iv1->x_typ],iv1->x_idx,iv1->x_val);
  }
 }
}

	rval = 0;
	goto EXIT;

FOUND:
	switch( set ){
	    case SOS_GET: break;
	    case SOS_SET: iv1->x_val = val; break;
	    case SOS_INC: iv1->x_val += 1; break;
	    case SOS_DEC: iv1->x_val -= 1;
		if( iv1->x_val == 0 ){
/*
fprintf(stderr,"--del %d windows.c:%d (%d/%2d) %s[%d] %d\n",
set,L,nact,fi,wh,idx,val);
*/
			*iv1 = NullIdxVal;
		}
		break;
	    case SOS_DEL:
/*
fprintf(stderr,"--DEL %d windows.c:%d (%d/%2d) %s[%d] %d\n",
set,L,nact,fi,wh,idx,val);
*/
		*iv1 = NullIdxVal;
		break;
	}
	rval = iv1->x_val;
EXIT:
	SockOsf.lock--;
	LeaveCriticalSection(&SockOsf.cs);

	if(0)
	if( set != SOS_GET )
	for( fi = 0; fi < MAXOSF; fi++ ){
		iv1 = &iv[fi];
		if( iv1->x_act )
fprintf(stderr,"++[%2d/%2d] (%s %s[%d]) act=%2d typ=%s[idx=%2d]=[val=%2d]\n",
			fi,MAXOSF,op_syms[set],ty_syms[typ],idx,
			iv1->x_act,ty_syms[iv1->x_typ],iv1->x_idx,iv1->x_val);
	}
	return rval;
}
static int SOS_Next(int *idx,int *val,int sock,int typ){
	int ix;
	for( ix = *idx + 1; ix < MAXOSF; ix++ ){
		if( SockOsf.openosfx[ix].x_act
		 && SockOsf.openosfx[ix].x_typ == typ
		 && SockOsf.openosfx[ix].x_val == sock ){
			*idx = ix;
			*val = SockOsf.openosfx[ix].x_idx;
			return 1;
		}
	}
	return 0;
}
#define SOS_NextDuph(i,v,s) SOS_Next(i,v,s,TY_DUP)
#define SOS_NextOsfh(i,v,s) SOS_Next(i,v,s,TY_OSF)

#else /* ---}{--- */

static short open_osfhandle[MAXHANDLE]; /* get_osfhandle(fd) emulation */
static short isdup_handles[MAXHANDLE];
static short opened_sockcnt[MAXHANDLE];

#define MAXOSF MAXHANDLE
#define BADRANGE(f) ((f)<0||MAXHANDLE<=(f))?0
#define SOS_GetOsfh(fd)   (BADRANGE(fd):open_osfhandle[fd])
#define SOS_SetOsfh(fd,f) (BADRANGE(fd):open_osfhandle[fd] = f)
#define SOS_DelOsfh(fd)   (BADRANGE(fd):open_osfhandle[fd] = 0)
#define SOS_GetDuph(fd)   (BADRANGE(fd):isdup_handles[fd])
#define SOS_SetDuph(fd,f) (BADRANGE(fd):isdup_handles[fd] = f)
#define SOS_DelDuph(fd)   (BADRANGE(fd):isdup_handles[fd] = 0)
#define SOS_GetRcnt(sock) (BADRANGE(sock):opened_sockcnt[sock])
#define SOS_IncRcnt(sock) (BADRANGE(sock):opened_sockcnt[sock] += 1)
#define SOS_DecRcnt(sock) (BADRANGE(sock):opened_sockcnt[sock] -= 1)
#define SOS_DelRcnt(sock) (BADRANGE(sock):opened_sockcnt[sock] = 0)
static int SOS_Next(int *idx,int *val,int sock,short *iv){
	int ix;
	for( ix = *idx + 1; ix < MAXHANDLE; ix++ ){
		if( iv[ix] == sock ){
			*idx = ix;
			*val = ix;
			return 1;
		}
	}
	return 0;
}
#define SOS_NextDuph(i,v,s) SOS_Next(i,v,s,isdup_handles)
#define SOS_NextOsfh(i,v,s) SOS_Next(i,v,s,open_osfhandle)
#endif /* ---} */

void dumpsockets(FILE *out,PCStr(wh)){
	int hi,hx;
	fprintf(out,"---sockets--- %s\n",wh);
	for( hi = 0; hi < MAXOSF; hi++ ){
	    if( hx = SOS_GetOsfh(hi) ) fprintf(out,"[%2d]%dh ",hi,hx);
	}
	fprintf(out,"\n");
	for( hi = 0; hi < MAXOSF; hi++ ){
	    if( hx = SOS_GetDuph(hi) ) fprintf(out,"[%3d]%du ",hi,hx);
	    if( hx = SOS_GetRcnt(hi) ) fprintf(out,"[%3d]%dn ",hi,hx);
	}
	fprintf(out,"\n");
}

static int coes[64];
static int coen;
static int setCloseOnExecSocketX(int fd,int sock){
	int ci;
	int cj;

	cj = 0;
	for( ci = 0; ci < coen; ci++ ){
		if( ISSOCK(coes[ci]) ){
			coes[cj++] = coes[ci];
		}else{
			LE("--COE salvaged[%d/%d] %d",cj,coen,coes[ci]);
		}
	}
	coen = cj;

	for( ci = 0; ci < coen; ci++ )
		if( coes[ci] == sock )
			return 0;

	LV("set CloseOnExecSocket[%d] = %d/%d",coen,sock,fd);
	if( elnumof(coes) <= coen ){
		LE("ERROR OVERFLOW set CloseOnExecSocket[%d]",coen);
		return -1;
	}
	coes[coen++] = sock;
	return 0;
}
int clearCloseOnExecSocketX(int fd,int sock){
	int ci,cj;

	for( ci = 0; ci < coen; ci++ ){
		if( coes[ci] == sock ){
			/*
			if( ISSOCK(sock) ){
				LE("--COE[%d/%d] dont clear",sock,ci);
				continue;
			}
			*/
			for( cj = ci; cj < coen; cj++ )
				coes[cj] = coes[cj+1];
			LV("clr CloseOnExec[%d] = %d/%d",ci,sock,fd);
			coen--;
			return 0;
		}
	}
	return -1;
}
int setCloseOnExecSocket(int fd)
{	int sock;

	if( 0 <= fd )
	if( sock = SocketOf(fd) ){
		return setCloseOnExecSocketX(fd,sock);
	}
	return -1;
}
int clearCloseOnExecSocket(int fd)
{	int sock;

	if( 0 <= fd )
	if( sock = SocketOf(fd) ){
		return clearCloseOnExecSocketX(fd,sock);
	}
	return -1;
}
int setInheritHandle(int fd,int on){
	HANDLE ih;
	unsigned long int of,nf,flags;
	int ok;

	if( isWindowsCE() ){
		return -1;
	}
	if( fd < 0 || MAXHANDLE <= fd ){
		LE("-- setInheritHandle(%d,%d) BAD fd",fd,on);
		return -1;
	}
	flags = 0;
	if( on & 1 )
		flags |= HANDLE_FLAG_INHERIT;
	if( ih = (HANDLE)SocketOf(fd) ){
		of = nf = 0;
		GetHandleInformation(ih,&of);
		ok = SetHandleInformation(ih,HANDLE_FLAG_INHERIT,flags);
		GetHandleInformation(ih,&nf);
		LV("-- setInheritHandle/S %d/%d %d (%X %X)",ih,fd,ok,of,nf);
	}else
	if( ih = (HANDLE)_get_osfhandle(fd) ){
		of = nf = 0;
		GetHandleInformation(ih,&of);
		ok = SetHandleInformation(ih,HANDLE_FLAG_INHERIT,flags);
		GetHandleInformation(ih,&nf);
		LV("-- setInheritHandle/O %d/%d %d (%X %X)",ih,fd,ok,of,nf);
	}else{
		LE("-- dontInherit(%d/%d) BAD handle",ih,fd);
	}
	return 0;
}
int setInheritance(int ifd,int inherit)
{	HANDLE ih,nh;
	int nfd;

	ih = (HANDLE)_get_osfhandle(ifd);
	nh = (HANDLE)duphandle(0,ih,0,0,!inherit);
	close(ifd);
	nfd = _open_osfhandle((int)nh,0);
	if( nfd != ifd ){
		dup2(nfd,ifd);
		close(nfd);
	}
	LE("setInferitance(%d,%d) %d %d %d",ifd,inherit,ih,nh,nfd);
	return ifd;
}

static int issock(int fd,int sock)
{	struct stat st0,st1;
	int bi,diff;

	if( isWindowsCE() ){
		int ofh,sfh;
		ofh = _get_osfhandle(fd);
		sfh = _get_osfhandle(sessionfd());
		if( ofh == sfh )
			return 1;
		if( ISSOCK(sock) ){
		WCE_sDBG(stderr,"---s issock(%d,%d) OK ofh=%X sfd=%d/%X\n",
		fd,sock, ofh,sessionfd(),sfh);
fprintf(stderr,
"------s issock(%d,%d) OK ofh=%X sfd=%d/%X\n",fd,sock, ofh,sessionfd(),sfh);
dumposf(stderr,"issock",fd,0,0);
dumpsockets(stderr,"issock");
			/*
			return 2;
			*/
		}
		WCE_sDBG(stderr,"---s issock? %d/%X sfd=%d/%X\n",
			ofh==sfh,fd,ofh,sessionfd(),sfh);
		return 0;
	}

	if( fstat(fd,&st1) != 0 ){
		LV("issock(%d) CANT OPEN1",fd);
		return 0;
	}
	if( fstat(sessionfd(),&st0) != 0 ){
		/*
		LE("######## issock(%d) CANT OPEN2",fd);
		*/
		LE("######## issock(%d) CANT OPEN2 sessionfd(%d)",fd,
			sessionfd());
		exit(1);
	}
	if( st0.st_mode != st1.st_mode ){
		LV("DIFF %d:%d %d:%d",fd,st1.st_mode,sessionfd(),st0.st_mode);
		return 0;
	}
	return 1;
}

int strfSocket(PVStr(desc),int size,PCStr(fmt),int sock);
static int closesocketX(FL_Par,int L,int sock){
	int rcode;
	int fx;
	int fi;
	IStr(desc,MaxHostNameLen);
	double St;

	WCE_sDBG(stderr,"---s %s:%d/%d closesocket(%d)----\n",
		__FILE__,__LINE__,L,sock);
	if( sock <= 0 ){
		LE("ERROR closesocketX(%d,%d) = -1",L,sock);
		return -1;
	}
	St = Time();
	if( lWINSOCK() )
		syslog_ERROR("closesocket(%d) :%d <= %s:%d\n",sock,L,FL_Bar);
	rcode = closesocket(sock);
	if( lWINSOCK() )
		syslog_ERROR("closesocket(%d) :%d ... DONE\n",sock,L);
	if( lCONNECT() && 0.9 <= Time()-St ){
		fprintf(stderr,"--{c} closesocketX(%d) took %.3f\n",
			sock,Time()-St);
	}
	for( fi = -1; SOS_NextDuph(&fi,&fx,sock); ){
		strfSocket(AVStr(desc),sizeof(desc),"",fx);
		syslog_ERROR("%d clear-closedups(%d/%d) %s windows.c:%d\n",
			rcode,sock,fx,desc,L);
	}
	return rcode;
}
int Closesocket(int sock){
	return closesocketX(FL_Arg,0,sock);
}
#define closesocket(sock)	closesocketX(FL_Arg,__LINE__,sock)

/*
static int closeSocket(int fd,int sock)
*/
int _close_FL(FL_Par,int fd);
#define closeSocket_FL(FL_Par,fd,sock) closeSocketX_FL(FL_Bar,fd,sock,1)
#define closeSocket(fd,sock)           closeSocketX_FL(FL_Arg,fd,sock,1)
static int closeSocketX_FL(FL_Par,int fd,int sock,int do_close_fd)
{	int rcode1,rcode2,isdup;
	int closedsock = 0;
	int xsock = 0;

	clearCloseOnExecSocket(fd);

	if( fd < 0 ){
		rcode1 = -1;
		isdup = 0;
	}else{
		if( isWindowsCE() ){
			rcode1 = _close_FL(FL_Bar,fd);
		}else
		if( do_close_fd ){
		rcode1 = _close(fd);
		}else{
			rcode1 = 0;
			// it will be closed by _dup2() in openSocket()
		}
		isdup = SOS_GetDuph(fd);
		SOS_DelDuph(fd);
		xsock = SOS_GetOsfh(fd);
		SOS_DelOsfh(fd);
	}

	if( 0 < sock )
	if( 0 < SOS_GetRcnt(sock) )
	{
		SOS_DecRcnt(sock);
		WCE_sDBG(stderr,"---s %s:%d closeSocket(%d/%d)----\n",
			__FILE__,__LINE__,sock,fd);
	}

	if( sock < 0 )
		rcode2 = -1;
	else
	if( 0 < SOS_GetRcnt(sock) )
		rcode2 = 0;
	else{
		rcode2 = closesocketX(FL_Bar,__LINE__,sock);
		WCE_sDBG(stderr,"---s %s:%d closesocket(%d/%d)----\n",
			__FILE__,__LINE__,sock,fd);
		closedsock = 1;
	}

	LS("{s} clr %4d*%d [%2d] %s closed (hooked) %d",
	xsock,SOS_GetRcnt(sock),fd,closedsock?"SOCKET":"handle",xsock);

	LV("-- SOCKET %d*(%3d/%2d) = %d,%d close() dup=%d",
		SOS_GetRcnt(sock),sock,fd,rcode1,rcode2,isdup);

	return rcode1;

}
/*
 * getSocketOf(fd,1) to be called after the fd is closed.
 * - clear "open_osfhandle[fd]" which indicated that the fd is bound to a socket
 * - close the socket handle if there is no remaining fd bound to the socket
 */
static int getSocketOf(int fd,int closed){
	int sock;
	int closedsock = 0;

	if( NO_SOCKOPEN == 0 ){
		return 0;
	}
	if( isWindowsCE() ){
		if( fd == -1 || fd == -2 ){
			return 0;
		}
	}else
	if( fd < 0 || MAXHANDLE <= fd ){
		return 0;
	}
	if( 0 < (sock = SOS_GetOsfh(fd)) ){
		if( closed && clearCloseOnExecSocketX(fd,sock) == 0 ){
			LS("{s} coe %4d*%d clearCloseOnExecSocket\n",
			sock,fd);
		}
#if defined(UNDER_CE) || USE_SOSMAP
		if( lMULTIST() ){
		}else
		if( closed || SOS_GetRcnt(sock) <= 0 || !issock(fd,sock) ){
porting_dbg("## %X DelSOCK[%d/%d] closed=%d cnt=%d nots=%d",
TID,sock,fd,closed,SOS_GetRcnt(sock),!issock(fd,sock));
			SOS_DelOsfh(fd);
			SOS_DelDuph(fd);
			if( 0 < SOS_GetRcnt(sock) ){
				SOS_DecRcnt(sock);
				if( SOS_GetRcnt(sock) <= 0 )
				{
					closesocket(sock);
					closedsock = 1;
				}
			}
			LV("-- SOCKET %d*(%3d/%2d) closed (detected)",
				SOS_GetRcnt(sock),sock,fd);

			LS("{s} CLR %4d*%d [%2d] %s closed (%s)",
				sock,SOS_GetRcnt(sock),fd,
				closedsock?"SOCKET":"handle",
				closed?"noticed":"DETECTED");

			sock = 0;
		}
#else
		if( lMULTIST() ){
		}else
		if( closed || opened_sockcnt[sock] <= 0 || !issock(fd,sock) ){
			open_osfhandle[fd] = 0;
			isdup_handles[fd] = 0;
			if( 0 < opened_sockcnt[sock] ){
				opened_sockcnt[sock] -= 1;
				if( opened_sockcnt[sock] <= 0 )
				{
					closesocket(sock);
					closedsock = 1;
				}
			}
			LV("-- SOCKET %d*(%3d/%2d) closed (detected)",
				opened_sockcnt[sock],sock,fd);

			LS("{s} CLR %4d*%d [%2d] %s closed (%s)",
				sock,opened_sockcnt[sock],fd,
				closedsock?"SOCKET":"handle",
				closed?"noticed":"DETECTED");

			sock = 0;
		}
#endif
	}
	return sock;
}

static int openSocket_FL(FL_Par,int tfd,int sock,int isdup,PCStr(wfmt),...);
static int openSocket(int tfd,int sock,int isdup,PCStr(wfmt),...)
{
	VARGS(2,wfmt);
	return openSocket_FL(wfmt,0,tfd,sock,isdup,wfmt,va[0],va[1]);
}
static int openSocket_FL(FL_Par,int tfd,int sock,int isdup,PCStr(wfmt),...)
{	int fd;
	CStr(msg,256);
	VARGS(2,wfmt);

	sprintf(msg,wfmt,va[0],va[1]);
	if( sock <= 0 ){
		LE("%s -- openSocket(%d) bad SOCKET handle",msg,sock);
		return -1;
	}
	fd = -1;
	if( !NO_SOCKOPEN ){
		/*
		 * how should it be treated when 0 <= tfd ... dup2() case ?
		 */
		fd = _open_osfhandle(sock,0);
		if( fd < 0 ){
			LE("NO OPEN_OSFHANDLE(SOCKET)");
			NO_SOCKOPEN = 1;
		}
	}
	if( NO_SOCKOPEN ){
		if( 0 <= tfd ){
			if( _dup2_FL(FL_Bar,sessionfd(),tfd) == 0 )
				fd = tfd;
			else{
				LE("%s -- failed dup2(x,%d)\n",tfd);
				return -1;
			}
		}else{
			fd = _dup_FL(FL_Bar,sessionfd());
		}
		SOS_SetOsfh(fd,sock);
	}
	if( isdup ){
		SOS_SetDuph(fd,sock);
		SOS_IncRcnt(sock);
	}else{
		SOS_DelDuph(fd);
		SOS_DelRcnt(sock); SOS_IncRcnt(sock);
	}

	LS("{s} set %4d*%d [%2d] %s",sock,
		SOS_GetRcnt(sock),fd,isdup?"duplicated":"CREATED");
	LV("-- SOCKET %d*(%3d/%2d) opened %s",
		SOS_GetRcnt(sock),sock,fd,msg);
	return fd;
}

/*
int SocketOf(int fd)
*/
int SocketOf_FL(const char *F,int L,int fd)
{	int sock;

	if( fd < 0 || MAXHANDLE <= fd ){
		if( isWindowsCE() && (fd == -1 || fd == -2) ){
			fprintf(stderr,"-- %X SocketOf(%d) <= %s:%d\n",TID,
				fd,F,L);
		}
		LW("SocketOf(%d)?",fd);
		return 0;
	}

	if( NO_SOCKOPEN )
		sock = getSocketOf(fd,0);
	else	sock = _get_osfhandle(fd);

	LW("SocketOf(%d/%d) ISSOCK=%d",sock,fd,ISSOCK(sock));

	if( sock && !ISSOCK(sock) )
		sock = 0;

	return sock;
}
int getsockHandle(int fd){ return (0 < SocketOf(fd)) ? SocketOf(fd) : -1; }

int BadSweepDangs;
int BadSweepDups;
static void sweepdanglingsock(PCStr(what),int sock){
	int fd;
	int fi;
	int nc = 0;

	if( sock == INVALID_SOCKET ){
		BadSweepDangs++;
		return;
	}
	for( fi = -1; SOS_NextOsfh(&fi,&fd,sock); ){
		LE("%s:dangling socket descriptor: %d/%d",what,sock,fd);
		SOS_SetOsfh(fd,-1);
	syslog_ERROR("%s:dangling socket descriptor: %d/%d\n",what,sock,fd);
		nc++;
	}
	for( fi = -1; SOS_NextDuph(&fi,&fd,sock); ){
		LE("%s:dangling socket dup_handle: %d/%d",what,sock,fd);
		SOS_DelDuph(fd);
	syslog_ERROR("%s:dangling socket dup_handle: %d/%d\n",what,sock,fd);
		nc++;
	}
}
static void sweepduphandle(PCStr(what),int fd,int sock){
	int fx;
	int fi;

	if( sock == INVALID_SOCKET ){
		BadSweepDups++;
		return;
	}
	for( fi = -1; SOS_NextDuph(&fi,&fx,sock); ){
	    if( fx != fd ){
		LE("%s:dangling socket dup_handle: %d/%d",what,sock,fx);
		SOS_DelDuph(fx);
	syslog_ERROR("%s:dangling socket dup_handle: %d/%d\n",what,sock,fx);
	    }
	}
}
static int _SOCKET(int dom,int type,int proto)
{	int sock,fd;
	int wsaerrno;

	socket_init();
	sock = socket(dom,type,proto);
	if( sock < 0 ){
		if( dom == AF_UNIX )
			LV("socket(AF_UNIX) = -1, NOT SUPPORTED");
		wsaerrno = WSAGetLastError();
		if( wsaerrno == WSAEAFNOSUPPORT && dom == AF_INET6 ){
		LE("#### IPv6 is disabled or unsupported on this host ####");
		}
		return sock;
	}
	sweepdanglingsock("SOCKET",sock);
	fd = openSocket(-1,sock,0,"socket()");
	LV("socket() = %d/%d",sock,fd);
	return fd;
}
int socket_FL(FL_PAR,int dom,int type,int proto){
	int sock;
	if( lWINSOCK() )
		syslog_ERROR("socket(%s:%d)...\n",FL_BAR);
	sock = _SOCKET(dom,type,proto);
	if( lWINSOCK() )
		syslog_ERROR("socket(%s:%d)=H[%d]S[%d]F[%d]\n",FL_BAR,
			_get_osfhandle(sock),SocketOf(sock),sock);
	return sock;
}
int _BIND(int fd,SAP addr,int len)
{	int sock = SocketOf(fd);
	int rcode;
	int wserrno;

	rcode = bind(sock,addr,len);
	wserrno = WSAGetLastError();
	if( wserrno ){
		LV("bind(%d/%d) = %d errno=(%d <- %d)",sock,fd,rcode,
			errno,wserrno);
		errno = wserrno;
	}else
	LV("bind(%d/%d) = %d",sock,fd,rcode);
	socklog("bind",fd,addr,rcode,sock);
	return rcode;
}
int _LISTEN(int fd,int nblog)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = listen(sock,nblog);
	LV("listen(%d/%d) = %d",sock,fd,rcode);
	return rcode;
}
#undef accept
#define accept acceptX
void putWinStatus(PCStr(fmt),...);
int askWinOK(PCStr(fmt),...);
int _ACCEPT(int fd,SAP addr,int *len)
{	int sock = SocketOf(fd);
	int csock,nfd;
	int xerr;
	int olen = *len;
	int eacc = 0;

	WSASetLastError(0);
	csock = accept(sock,addr,len);
	xerr = WSAGetLastError();

	if( csock == INVALID_SOCKET || csock == 0 ){
		syslog_ERROR("## FATAL accept(%d)=%d err=%d,%d len=%d/%d\n",
			sock,csock,errno,xerr,*len,olen);
		eacc = 1;
	}
	if( csock == INVALID_SOCKET ){
	  if( isWindowsCE() ){
		putWinStatus("_ACCEPT(%d/%d)=%d err=%d",fd,sock,csock,xerr);
	  }
	}
	sweepdanglingsock("ACCEPT",csock);
	if( 0 <= csock )
		nfd = openSocket(-1,csock,0,"accept(%d)",fd);
	else	nfd = -1;
	//putWinStatus("accept()=%d/%d err=%d",csock,nfd,xerr);
	if( csock < 0 ){
		errno = WSAGetLastError();
	}

	/*
	if( isWindowsCE() ){
	fprintf(stderr,"----WinCE ACCEPT(%d/%d)=%d/%d(S%d)\n",
		sock,fd,csock,nfd,SocketOf(nfd));
	}
	*/

	LV("accept(%d/%d) = %d/%d",sock,fd,csock,nfd);
	socklog("accept",fd,addr,nfd,sock);
	if( isWindowsCE() ){
		void HookAccept(int fd,int nfd,SAP addr,int *len);
		HookAccept(fd,nfd,addr,len);
	}
	return nfd;
}
int _CONNECT(int fd,const SAP addr,int len)
{	int sock = SocketOf(fd);
	int rcode;
	int wserrno;

	WSASetLastError(0);
	rcode = connect(sock,addr,len);
	wserrno = WSAGetLastError();
	if( wserrno ){
		LV("connect(%d/%d) = %d errno=(%d <- %d)",sock,fd,rcode,
			errno,wserrno);
		errno = wserrno;
	}else	LV("connect(%d/%d) = %d",sock,fd,rcode);
	socklog("connect",fd,addr,rcode,sock);
/*
if( rcode != 0 && errno != 10035 )
fprintf(stderr,"-- %X -x CONNECT[%d/%d]=%d err=%d %d %d\n",TID,sock,fd,rcode,wserrno,errno,WSAECONNREFUSED);
*/
	// errno = wserrno; /* to get errno==0 on success */
	return rcode;
}
int _SHUTDOWN(int fd,int how)
{	int sock = SocketOf(fd);
	int rcode;
	double St = Time();
	double Et;

	rcode = shutdown(sock,how);
	Et = Time() - St;
	if( 0.1 < Et ){
		syslog_ERROR("slow shutdown(%d/%d,%d) = %d (%.2f)\n",
			sock,fd,how,rcode,Et);
	}
	LV("shutdown(%d/%d,%d) = %d",sock,fd,how,rcode);
	return rcode;
}

int SHUT_RD   = SD_RECEIVE;
int SHUT_WR   = SD_SEND;
int SHUT_RDWR = SD_BOTH;
static int pollin(int sock,int msec);
static int pollinX(int wh,int sock,int msec);

int waitShutdownSocket(FL_PAR,int fd,int ms){
	int sock = SocketOf(fd);
	int rcode;
	int nready = -2;
	double St = Time();
	int xerr1,xerr2;

	if( lSINGLEP() ){
		rcode = shutdown(sock,SHUT_WR);
		xerr1 = WSAGetLastError();
		nready = pollinX(5,sock,ms);
		xerr2 = WSAGetLastError();
		/*
		if( 0.1 < Time()-St )
		*/
		{
			syslog_ERROR("-- waitShutdownSocket([%d/%d],%d)=%d,%d,err=%d,%d,%d (%.3f) <= %s:%d\n",
				fd,sock,ms,nready,rcode,xerr1,xerr2,errno,Time()-St,FL_BAR);
		}
	}
	return nready;
}

int ShutdownSocket(int fd){
	int sock = SocketOf(fd);
	int rcode;
	CStr(buf,1024);
	CStr(vbuf,1024);
	refQStr(vp,vbuf);
	int ri,rcc,ch,vch,rj;

	if( sock <= 0 ){
		LE("ShutdownSocket(%d/%d)=-1",sock,fd);
		return -1;
	}
	rcode = shutdown(sock,1);
	if( rcode != 0 )
		LE("ShutdownSocket(%d/%d,1)=%d",sock,fd,rcode);
	if( 0 < pollin(sock,1) ){
	    for( ri = 0; ri < 32; ri++ ){
		if( 0 < pollin(sock,1) ){
			if( (rcc = recv(sock,(char*)&buf[ri],1,0)) <= 0 )
				break;
		}
		if( pollin(sock,1) <= 0 ){
			break;
		}
	    }
	    if( 0 < ri ){
		vp = vbuf;
		for( rj = 0; rj < ri; rj++ ){
			ch = 0xFF & buf[rj];
			if( isprint(ch) )
				sprintf(vp,"%c",ch);
			else	sprintf(vp,"\\x%02X",ch);
			vp += strlen(vp);
		}
		syslog_ERROR("ShutdownSocket(%d) \"%s\"\n",fd,vbuf);
	    }
	}
	rcode = shutdown(sock,2);
	if( rcode != 0 )
		LE("ShutdownSocket(%d/%d,2)=%d",sock,fd,rcode);
	return rcode;
}

int pollPipe(int pfd,int slpmsec);
static void FD_dump(struct fd_set *ss,int sz,PVStr(ssb)){
	int fd;
	refQStr(bp,ssb);

	for( fd = 0; fd < MAXHANDLE; fd++ ){
		if( FD_ISSET(fd,ss) ){
			if( ssb < bp ) setVStrPtrInc(bp,',');
			sprintf(bp,"%d",fd);
			bp += strlen(bp);
		}
	}
}
int _SELECT(int sz,struct fd_set *x,struct fd_set *y,struct fd_set *z,struct timeval *tv)
{	int rcode;
	int wserrno;

	HANDLE ph;
	struct fd_set ss;
	IStr(ssb,128);

	if( x ) ss = *x; else
	if( y ) ss = *y; else
	if( z ) ss = *z; else
		FD_ZERO(&ss);

	if( x != 0 && FD_ISSET(0,x) )
	if( ph = (HANDLE)_get_osfhandle(0) )
	{
		switch( GetFileType(ph) ){
		    case FILE_TYPE_CHAR:
			FD_dump(&ss,sz,AVStr(ssb));
			LE("## WARNING: select(%s) applied to regular-file? (%X,%X,%X)",
				ssb,x,y,z);
			FD_SET(0,x);
			return 1;

		    case FILE_TYPE_PIPE:
		    {
			LE("## WARNING: select() applied to PIPE?");
			/*
			int si,sn;
			int fd;
			fd = -1;
			sn = 0;
			for( si = 1; si < FD_SETSIZE; si++ ){
				if( FD_ISSET(si,x) ){
					sn++;
					break;
				}
			}
			if( sn == 0 ){
				int slpmsec;
				fd = 0;
				if( tv )
					slpmsec = tv->tv_sec*1000+tv->tv_usec/1000;
				else	slpmsec = 0;
				rcode = pollPipe(fd,slpmsec);
				if( 0 < rcode )
					FD_SET(0,x);
				return rcode;
			}
			break;
			*/
		    }
		}
	}

	LV("select(%d,%d) start",sz,tv?tv->tv_sec:0);
	errno = 0;
	WSASetLastError(0);
	rcode = select(sz,x,y,z,tv);
	wserrno = WSAGetLastError();

	if( rcode < 0 ){
		extern const char *FL_F_Poll;
		extern int FL_L_Poll;
		LE("select() = %d [errno=(%d / %d)]",rcode,errno,wserrno);
		if( errno == EBADF || wserrno == WSAENOTSOCK ){
			FD_dump(&ss,sz,AVStr(ssb));
	LE("## ERROR: select(%X,%X,%X/%d,%d+%d,(%s)) applied to non-SOCKET handle <= %s:%d",
	x,y,z,sz,tv?tv->tv_sec:0,tv?tv->tv_usec:0,ssb,
	FL_F_Poll?FL_F_Poll:"",FL_L_Poll);
			//if( lNODELAY_ON_SELECT_ERROR() )
			_sleep(200);
		}
	}
	else
	LV("select() = %d errno=(%d / %d)",rcode,errno,wserrno);
	return rcode;
}
int _SEND(int fd,const void *buf,unsigned int len,int flags)
{	int sock = SocketOf(fd);
	int wcc;

	wcc = sends(sock,(char*)buf,len,flags);
	LW("send(%d/%d) = %d",sock,fd,wcc);
	return wcc;
}
int Xrecv(int fd,int sock,void *buf,unsigned int len,int flags);
int _RECV(int fd,void *buf,unsigned int len,int flags)
{	int sock = SocketOf(fd);
	int rcc;

	setthread_FL(0,__FILE__,__LINE__,"RECV...");
	if( isWindowsCE() ){
		rcc = Xrecv(fd,sock,buf,len,flags);
	}else
	rcc = recv(sock,(char*)buf,len,flags);
	if( 0 < rcc ){
		LOGX_recvBytes += rcc;
	}
	setthread_FL(0,__FILE__,__LINE__,"RECV-DONE");
	LW("recv(%d/%d) = %d",sock,fd,rcc);
	return rcc;
}
int _SENDTO(int fd,const void *buf,unsigned int len,int flags,SAP to,unsigned int tolen)
{	int sock = SocketOf(fd);
	int wcc;

	wcc = sendto(sock,(char*)buf,len,flags,to,tolen);
	LW("sendto(%d/%d) = %d",sock,fd,wcc);
	return wcc;
}
int _RECVFROM(int fd,void *buf,unsigned int len,int flags,SAP from,int *fromlen)
{	int sock = SocketOf(fd);
	int rcc;
	int xerr;

	errorECONNRESET = 0;
	rcc = recvfrom(sock,(char*)buf,len,flags,from,fromlen);
	LW("recvfrom(%d/%d) = %d",sock,fd,rcc);
	if( rcc < 0 ){
		xerr = WSAGetLastError();
		if( xerr == WSAECONNRESET )
			errorECONNRESET = 1;
	}
	return rcc;
}
int _GETSOCKNAME(int fd,SAP addr,int *len)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = getsockname(sock,addr,len);
	LW("getsockname(%d/%d) = %d",sock,fd,rcode);
	return rcode;
}
int _GETPEERNAME(int fd,SAP addr,int *len)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = getpeername(sock,addr,len);
	LW("getpeername(%d/%d) = %d",sock,fd,rcode);
	return rcode;
}
int _SETSOCKOPT(int fd,int lev,int op,const void *val,int len)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = setsockopt(sock,lev,op,(char*)val,len);
	LW("setsockopt(%d/%d) = %d",sock,fd,rcode);
	return rcode;
}
int _GETSOCKOPT(int fd,int lev,int op,void *val,int *len)
{	int sock = SocketOf(fd);
	int rcode;

	rcode = getsockopt(sock,lev,op,(char*)val,len);
	LW("getsockopt(%d/%d) = %d",sock,fd,rcode);
	if( rcode != 0 ){
		errno = WSAGetLastError();
	}
	return rcode;
}
int _GETHOSTNAME(char *name,unsigned int size)
{
	socket_init();
	return gethostname(name,size);
}

/*
int socketpair(int d,int type,int protocol,int fsv[2])
*/
static int pollin(int sock,int msec);
static int ports[2];
static int portx;
extern int BREAK_STICKY;

int SocketpairAccPort; /* to accept socketpair() */
int SocketpairConPort;
int init_socketpair(int port){
	LV("socketpair() set #%d <- %d",port,SocketpairAccPort);
	SocketpairAccPort = port;
	SocketpairConPort = 0;
	return 0;
}
int actthreads();
int numthreads();
int socketpairY(int d,int type,int protocol,int sv[2],int baseoff);
int socketpairX(int d,int type,int protocol,int sv[2])
{	int rcode;
	double Start = Time();
	int retry;
	int xerr;

	rcode = socketpairY(d,type,protocol,sv,0);
	if( rcode == 0 || rcode == -1 ){
		return rcode;
	}
	if( d == AF_UNIX || type == SOCK_DGRAM ){
		return rcode;
	}

	for( retry = 1; retry < 10; retry++ ){
		xerr = WSAGetLastError();
		if( xerr != WSAEADDRINUSE ){
			break;
		}
		LV("--socketpair()=%d FAILED err=%d %.3f/%d (%d %d)",
			rcode,xerr,Time()-Start,retry,
			SocketpairAccPort,SocketpairConPort);

		/* failure will be repeated in this process ... why? */
		BREAK_STICKY = 1;

		_sleep(15);
		rcode = socketpairY(d,type,protocol,sv,retry*2);
		if( rcode == 0 ){
			LE("--socketpair()=%d OK err=%d %.3f/%d (%d %d) %d/%d",
				rcode,xerr,Time()-Start,retry,
				SocketpairAccPort,SocketpairConPort,
				actthreads(),numthreads());
			break;
		}
	}
	if( rcode != 0 ){
		init_socketpair(0);
		rcode = socketpairY(d,type,protocol,sv,0);
	}
	if( rcode != 0 ){
		LE("--socketpair()=%d FAILED err=%d %.3f/%d EXIT",
			rcode,xerr,Time()-Start,retry);
		_exit(rcode);
	}
	return rcode;
}
int SERNO();
static int trybind(int sock,PCStr(host),int port0){
	VSAddr ina;
	int inalen,port;
	int ntry;

	for( ntry = 0; ntry < 30; ntry++ ){
		port = (port0 + ntry*(100+SERNO()%100)) % 0x10000;
		if( port < 1024 ){
			continue;
		}
		inalen = VSA_atosa(&ina,port,host);
		if( bind(sock,(SAP)&ina,inalen) == 0 ){
			return 0;
		}
	}
	LE("socketpair(%d).trybind(%d)*%d FAILED (%d)",sock,port0,ntry,port);
	return -1;
}

/*
#define setHInherit(h) \
	SetHandleInformation((HANDLE)h,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT)
*/
static void setHInheritX(int *h){
	if( lNOSOCKINH() || lDOSOCKINH() ){
		*h = setSockInh("socketpair",*h);
		return;
	}
	if( lWOSOCKINH() ){
		return;
	}
	SetHandleInformation((HANDLE)*h,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT);
}
#define setHInherit(h) setHInheritX(&h)

int socketpairY(int d,int type,int protocol,int sv[2],int baseoff)
{	VSAddr ina;
	int inalen,port;
	int asock,len;
	int rcode = 0;
	int on = 1;

	sv[0] = sv[1] = -1;

	asock = socket(d,type,protocol);
	sweepdanglingsock("socketpair-1",asock);
	if( asock < 0 ){
		return -1;
	}
	on = 0;
	setsockopt(asock,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
	if( 0 < SocketpairAccPort ){
		inalen = VSA_atosa(&ina,SocketpairAccPort,"127.0.0.1");
		if( bind(asock,(SAP)&ina,inalen) == 0 ){
		}else{
			SocketpairAccPort = 0;
		}
	}
	if( SocketpairAccPort == 0 ){
		inalen = VSA_atosa(&ina,SocketpairAccPort,"127.0.0.1");
		if( bind(asock,(SAP)&ina,inalen) != 0 ){
			rcode = -2;
			goto EEXIT;
		}
		len = sizeof(VSAddr);
		getsockname(asock,(SAP)&ina,&len);
		port = VSA_port(&ina);
		SocketpairAccPort = port;
	}
	port = SocketpairAccPort;

	sv[1] = socket(d,type,protocol);
	sweepdanglingsock("socketpair-2",sv[1]);
	if( sv[1] < 0 ){
		rcode = -4;
		goto EEXIT;
	}
	setHInherit(sv[1]);
	setsockopt(sv[1],SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
	if( 0 < SocketpairConPort ){
		trybind(sv[1],"127.0.0.1",SocketpairConPort+baseoff);
	}

	if( type != SOCK_DGRAM )
	if( listen(asock,1) != 0 ){
		rcode = -3;
		goto EEXIT;
	}
	inalen = VSA_atosa(&ina,port,"127.0.0.1");
	rcode |= connect(sv[1],(SAP)&ina,inalen);
	if( rcode != 0 ){
		rcode = -5;
		goto EEXIT;
	}
	if( type == SOCK_DGRAM ){
		sv[0] = asock;
		setHInherit(sv[0]);
		return 0;
	}
	if( SocketpairConPort == 0 ){
		int csock = sv[1];
		len = sizeof(VSAddr);
		getsockname(csock,(SAP)&ina,&len);
		port = VSA_port(&ina);
		SocketpairConPort = port;
	}
	len = sizeof(VSAddr);
	if( pollin(asock,10*1000) == 0 ){
		rcode = -6;
		goto EEXIT;
	}
	sv[0] = accept(asock,(SAP)&ina,&len);
	sweepdanglingsock("socketpair-3",sv[0]);
	if( sv[0] < 0 ){
		rcode = -7;
		goto EEXIT;
	}
	setHInherit(sv[0]);
	closesocket(asock);
	return rcode;

EEXIT:
	closesocket(asock);
	if( 0 <= sv[1] ) closesocket(sv[1]);
	sv[0] = sv[1] = -1;
	return rcode;
}

#undef socketpair
int socketpair(int d,int type,int protocol,int fsv[2]){
	int rcode;
	int sv[2];

	if( (rcode = socketpairX(d,type,protocol,sv)) != 0 ){
		return -1;
	}
	fsv[0] = openSocket(-1,sv[0],0,"socketpair(0)");
	fsv[1] = openSocket(-1,sv[1],0,"socketpair(1)");

	LV("socketpair() = %d [%d/%d,%d/%d]",rcode,sv[0],fsv[0],sv[1],fsv[1]);
	return rcode;
}

int setNonblockingSocket(int fd,int aon)
{	int sock;
	int rcode;
	unsigned long int on = aon;

	if( sock = SocketOf(fd) ){
		rcode = ioctlsocket((SOCKET)sock,FIONBIO,&on);
		LV("setNonblockingSocket(%d,%d)=%d",fd,on,rcode);
		return rcode;
	}
	return -1;
}
void setNonblockingPipe(int pv[])
{	HANDLE phandle;
	unsigned long int mode;
	int ok;

	mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
	phandle = (HANDLE)_get_osfhandle(pv[0]);
	ok = SetNamedPipeHandleState(phandle,&mode,NULL,NULL);
	LE("setNonblockingPipe(%d/%d) ok=%d",phandle,pv[0],ok);
}
static int ISREG(int fd){
	HANDLE handle;
	handle = (HANDLE)_get_osfhandle(fd);
	if( handle == 0 ){
		return 0;
	}
	if( GetFileType(handle) == FILE_TYPE_CHAR )
		return 1;
	return 0;
}
static int ISPIPE(int pfd)
{	int ok;
	unsigned long int ninst;
	HANDLE phandle;

	if( isWindowsCE() ){
		/* no pipe on WinCE */
		return 0;
	}

	phandle = (HANDLE)_get_osfhandle(pfd);
	if( GetFileType(phandle) == FILE_TYPE_PIPE )
		return 1;

	ninst = -1;
	ok = GetNamedPipeHandleState(phandle,NULL,&ninst,NULL,NULL,NULL,0);
	if( ok == TRUE && 0 < ninst )
		return 1;
	else	return 0;
}
int file_ISPIPE(int pfd){
	return ISPIPE(pfd);
}
int pollPipe(int pfd,int slpmsec)
{	HANDLE phandle;
	int rem,slept,sleep1,s1;
	unsigned long int nready;

	if( SocketOf(pfd) )
		return -1;
	if( !ISPIPE(pfd) )
		return -1;

	phandle = (HANDLE)_get_osfhandle(pfd);
	if( isWindows95() ){
		/* PeekNamedPipe of Win95/98 seems never fail on EOF ... */
		if( 15000 < slpmsec ){
			LT("pollPipe(%d,%d->15000) for Win95/98...",slpmsec);
			slpmsec = 15000;
		}
	}
	/*
	for( slept = 0; slpmsec == 0 || slept <= slpmsec; slept += s1 ){
	*/
	for( slept = 0; slpmsec <= 0 || slept <= slpmsec; slept += s1 ){
		nready = -1;
		if( PeekNamedPipe(phandle,NULL,0,NULL,&nready,NULL) == FALSE )
		{	int xerr = GetLastError();
			if( xerr == ERROR_BROKEN_PIPE ){
				LV("pollPipe(%d) error=%d (EPIPE)",pfd,xerr);
				return 1;
			}
			LE("## pollPipe(%d) error=%d",pfd,xerr);
			return -1;
		}

		if( nready != 0 )
			return nready;
		if( TIMEOUT_isIMM(slpmsec) )
			break;
		if( slpmsec != 0 && slpmsec <= slept )
			break;

		rem = slpmsec - slept;
		if( slept <  500 ) sleep1 =   5; else
		if( slept < 5000 ) sleep1 =  50; else
				   sleep1 = 500;

		if( slpmsec == 0 || sleep1 < rem )
			s1 = sleep1;
		else	s1 = rem;
		/*
		usleep(s1*1000);
		*/
		_sleep(s1);
	}
	return 0;
}

/* ######## NIS ######## */
int yp_get_default_domain(char **domp)
{
	LV("yp_get_default_domain() = -1");
	*domp = NULL;
	return -1;
}
int yp_match(PCStr(dom),PCStr(map),PCStr(name),int len,char **vp,int *vlen)
{
	LV("yp_match() = -1");
	return -1;
}

/* ######## STDIO ######## */

int accept_FL(FL_Par,int fd,void *sa,int *len){
	int rcode;
	rcode = _ACCEPT(fd,(SAP)sa,len);
	return rcode;
}
int socketpair_FL(FL_Par,int d,int type,int protocol,int fsv[2]){
	int rcode;
	rcode = socketpair(d,type,protocol,fsv);
	setosf_FL("socketpair","(socket)",fsv[0],0,FL_Bar);
	setosf_FL("socketpair","(socket)",fsv[1],0,FL_Bar);
	return rcode;
}

#ifndef dup2
int dup2_FL(FL_Par,int fd1,int fd2);
int dup2(int fd1,int fd2)
{
	return dup2_FL(FL_Arg0,fd1,fd2);
}
#endif
#undef dup2_FL
int dup2_FL(FL_Par,int fd1,int fd2)
{	int rcode;
	int sock,nsock,nfd;
	int sock2;

	LT("dup2(%d/%d/%d,%d/%d/%d)",
		_get_osfhandle(fd1),SocketOf(fd1),fd1,
		_get_osfhandle(fd2),SocketOf(fd2),fd2);
	if( fd1 == fd2
	 || SocketOf(fd2) && SocketOf(fd1) == SocketOf(fd2)
	){
		return fd2;
	}

	if( isWindowsCE() ){
	if( close_FL(FL_Bar,fd2) == 0 )
		LT("closed(%d) before dup2(%d,%d)",fd2,fd1,fd2);
	}else{
		if( sock2 = SocketOf(fd2) ){
			closeSocketX_FL(FL_Bar,fd2,sock2,0);
		}else{
			// it will be closed by _dup2() in openSocket()
		}
	}

	if( sock = SocketOf(fd1) ){
		if( NO_SOCKOPEN )
			nsock = sock;
		else	nsock = duphandle(0,(HANDLE)sock,0,0,0);
		nfd = openSocket_FL(FL_Bar,fd2,nsock,1,"dup2(%d/%d)",sock,fd2);
	}else{
		if( isWindowsCE() ){
			rcode = _dup2_FL(FL_Bar,fd1,fd2);
		}else
		rcode = _dup2(fd1,fd2);
		if( rcode == 0 )
			nfd = fd2;
		else	nfd = -1;
	}
	return nfd;
}
#ifndef dup
int dup(int fd)
{
	return dup_FL(FL_Arg0,fd);
}
#endif
#undef dup_FL
int dup_FL(FL_Par,int fd)
{	int sock,nsock,nfd;

	if( sock = SocketOf(fd) ){
		if( NO_SOCKOPEN )
			nsock = sock;
		else	nsock = duphandle(0,(HANDLE)sock,0,0,0);
		nfd = openSocket_FL(FL_Bar,-1,nsock,1,"dup(%d/%d)",sock,fd);
	}else
	if( isWindowsCE() ){
		nfd = _dup_FL(FL_Bar,fd);
	}else	nfd = _dup(fd);
	return nfd;
}
#undef close_FL
int close_FL(FL_Par,int fd)
{	int sock,rcode;

	if( fd < 0 ){
		LE("FATAL DBGFD close(%d) <= %s:%d",fd,FL_Bar);
	}else
	if( sock = SocketOf(fd) )
		rcode = closeSocket_FL(FL_Bar,fd,sock);
	else
	if( isWindowsCE() )
		rcode = _close_FL(FL_Bar,fd);
	else	rcode = _close(fd);
	return rcode;
}
#undef close
int close(int fd){
	return close_FL(FL_ARG,fd);
}
#undef open
int open(PCStr(path),int flag,int mode)
{	int fd;

	if( strcmp(path,"/dev/null") == 0 )
		path = "nul";
	else
	if( strcmp(path,"/dev/tty") == 0 )
		path = "con";
	fd = _open(path,flag,mode);
	LT("open(%s,%d) = %d",path,flag,fd);
	return fd;
}

#define F_SETFD 1
int fcntl(int fd,int cmd,void *arg){
	int fh;
	int flag,ok,rcode;
	int sock;

	fh = _get_osfhandle(fd);
	switch( cmd ){
	    case F_SETFD:
		if( sock = SocketOf(fd) ){
			LT("fcntl(fh=%d/fd=%d/sock=%d) -> CloseOnExecSocket()",
				fh,fd,sock);
			if( arg )
				return setCloseOnExecSocket(sock);
			else	return clearCloseOnExecSocket(sock);
		}
		flag = HANDLE_FLAG_INHERIT;
		ok = SetHandleInformation((HANDLE)fh,flag,arg?0:flag);
		rcode = ok ? 0 : -1;
		LV("fcntl(%d,F_SETFD,%d) = %d",fd,arg,rcode);
		return rcode;
	}
	LE("fcntl(%d) NOT SUPPORTED",fd);
	return -1;
}

int _read(int fd,char *buf,unsigned int size)
{	int rcc;
	int sock;
	HANDLE oh;
	int xerr;

	if( sock = SocketOf(fd) ){
		double Start = Time();
		if( isWindowsCE() ){
			rcc = Xrecv(fd,sock,buf,size,0);
		}else
		rcc = recv(sock,buf,size,0);
		if( 0 < rcc ){
			LOGX_recvBytes += rcc;
		}
		if( rcc < 0 )
		LV("-- SOCKET recv(%d/%d,%x,%d,0) = %d",sock,fd,buf,size,rcc);
		if( rcc <= 0 ){
			xerr = WSAGetLastError();
			if( rcc == 0 && xerr == 0 ){
				/* no ready input on non-blocking mode ? */
				LV("-- SOCKET recv(%d)=%d error=%d [%.3f]",
					fd,rcc,xerr,Time()-Start);
				/* gracefully closing ... */
			}else
			LE("-- SOCKET recv(%d)=%d error=%d [%.3f]",fd,rcc,xerr,
				Time()-Start);
			{
			IStr(peer,128);
			strfSocket(AVStr(peer),sizeof(peer),"",fd);
			syslog_ERROR("SOCKET recv(%d)=%d error=%d [%.3f] %s\n",
				fd,rcc,xerr,Time()-Start,peer);
			}
			/*
			LE("-- SOCKET recv(%d)=%d error=%d",fd,rcc,xerr);
			*/
			if( xerr == WSAENETRESET
			 || xerr == WSAECONNRESET || xerr == WSAECONNABORTED ){
				errno = xerr;
			}
		}
	}else{
		rcc = __read(fd,buf,size);
		if( rcc < 0 )
		LW("-- read(%d,%x,%d) = %d",fd,buf,size,rcc);
	}
	return rcc;
}
int _write(int fd,PCStr(buf),unsigned int size)
{	int wcc;
	int sock;
	int xerr;

	if( sock = SocketOf(fd) ){
		wcc = sends(sock,buf,size,0);
		if( xerr = WSAGetLastError() ){
			if( xerr == WSAEWOULDBLOCK ){
				errno = EAGAIN; /* == EWOULDBLOCK */
			}
			if( 1 < LOGLEVEL || xerr != WSAEWOULDBLOCK )
			LE("-- SOCKET send(%d/%d,%x,%d,0) = %d %d",
				sock,fd,buf,size,wcc,xerr);

			if( getenv("SIGPIPE_TERM") )
			if( xerr == WSAENETRESET
			 || xerr == WSAECONNRESET || xerr == WSAECONNABORTED ){
				LE("send() -- cause SIGTERM for SIGPIPE");
				raise(SIGTERM);
			}
			if( actthreads() ){
				_sleep(1);
			}
		}else
		LV("-- SOCKET send(%d/%d,%x,%d,0) = %d",sock,fd,buf,size,wcc);
	}else{
		wcc = __write(fd,buf,size);
		LW("-- write(%d,%x,%d) = %d",fd,buf,size,wcc);
	}
	return wcc;
}
int (*win_read)(int,char*,unsigned int) = _read;
int (*win_write)(int,const char*,unsigned int) = _write;

static int sleepsock = -1;
int usleep(unsigned int timeout)
{ 	struct timeval tvbuf,*tv;
	struct fd_set mask;
	int port;

	if( 1000 % timeout == 0 ){
		Sleep(timeout/1000);
		return 0;
	}
	if( timeout ){
		tv = &tvbuf;
		tv->tv_sec  = timeout / 1000000;
		tv->tv_usec = timeout % 1000000;
	}else	tv = NULL;

	if( sleepsock < 0 ){
		sleepsock = bindsocket(-1,&port);
		if( sleepsock < 0 )
			return -1;
	}
	FD_ZERO(&mask);
	FD_SET(sleepsock,&mask);
	return select(128,&mask,NULL,NULL,tv);
}
void Usleep(int usec){
	int msec;
	msec = (usec + 999) / 1000;
	_sleep(msec);
}

static int pollinX(int wh,int sock,int msec){
	struct timeval tv;
	struct fd_set imask,omask,xmask,*pimask,*pomask,*pxmask;
	int nready;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;
	FD_ZERO(&imask);
	FD_SET(sock,&imask);
	omask = imask;
	xmask = imask;
	pimask = (wh & 1) ? &imask : 0; 
	pomask = (wh & 2) ? &omask : 0; 
	pxmask = (wh & 4) ? &xmask : 0; 
	nready = select(128,pimask,pomask,pxmask,&tv);
	return  (pimask && FD_ISSET(sock,pimask) ? 1 : 0)
	      | (pomask && FD_ISSET(sock,pomask) ? 2 : 0)
	      | (pxmask && FD_ISSET(sock,pxmask) ? 4 : 0);
}
static int pollin(int sock,int msec)
{	struct timeval tv;
	struct fd_set mask;
	struct fd_set xmask;
	int nready;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;
	FD_ZERO(&mask);
	FD_SET(sock,&mask);
	/*
	return select(128,&mask,NULL,NULL,&tv);
	*/
	xmask = mask;
	nready = select(128,&mask,NULL,&xmask,&tv);
	if( FD_ISSET(sock,&xmask) && nready != 2 ){
		porting_dbg("-- %X EXP pollin[%d]%d",TID,sock,nready);
	}
	return nready;
}
int pollIn(int sock,int msec){
	return pollin(sock,msec);
}
static int pollin2(int sock1,int sock2,int msec)
{	struct timeval tv;
	struct fd_set mask;
	int nready;
	int rmask = 0;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;
	FD_ZERO(&mask);
	if( 0 <= sock1 ) FD_SET(sock1,&mask);
	if( 0 <= sock2 ) FD_SET(sock2,&mask);
	nready = select(128,&mask,NULL,NULL,&tv);
	if( FD_ISSET(sock1,&mask) ) rmask |= 1;
	if( FD_ISSET(sock2,&mask) ) rmask |= 2;
	return rmask;
}
int pollsock3(int isock,int osock,int xsock,int msec)
{	struct timeval tv;
	struct fd_set imask;
	struct fd_set omask;
	struct fd_set xmask;
	int nready;
	int rmask = 0;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;
	FD_ZERO(&imask);
	FD_ZERO(&omask);
	FD_ZERO(&xmask);
	if( 0 <= isock ) FD_SET(isock,&imask);
	if( 0 <= osock ) FD_SET(osock,&omask);
	if( 0 <= xsock ) FD_SET(xsock,&xmask);
	nready = select(128,&imask,&omask,&xmask,&tv);
	if( FD_ISSET(isock,&imask) ) rmask |= 1;
	if( FD_ISSET(osock,&omask) ) rmask |= 2;
	if( FD_ISSET(xsock,&xmask) ) rmask |= 4;
	return rmask;
}

int uname(void *name)
{
	return -1;
}
int Uname(PVStr(name))
{
	if( isWindowsCE() )
		strcpy(name,"WindowsCE");
	else
	if( isWindows95() )
		strcpy(name,"Windows95");
	else	strcpy(name,"WindowsNT");
	return 0;
}
int isWindows95(){ return getpid() < 0; }

#include <time.h>

int Timegm(struct tm *tm);
int SystemTimeToTm(SYSTEMTIME *st,struct tm *tm){
	tm->tm_year = st->wYear - 1900;
	tm->tm_mon = st->wMonth - 1;
	tm->tm_mday = st->wDay;
	tm->tm_hour = st->wHour;
	tm->tm_min = st->wMinute;
	tm->tm_sec = st->wSecond;
	tm->tm_wday = st->wDayOfWeek;
	return 0;
}
int FileTimeToUnixTime(FILETIME *ft){
	SYSTEMTIME st;
	struct tm tm;
	int ut;

	bzero(&st,sizeof(st));
	bzero(&tm,sizeof(tm));
	FileTimeToSystemTime(ft,&st);
	SystemTimeToTm(&st,&tm);
	ut = Timegm(&tm);
	return ut;
}
void UnixTimeToFileTime(time_t ut,FILETIME *ft){
	LONGLONG ll;
	ll = Int32x32To64(ut,10000000) + 116444736000000000;
	ft->dwLowDateTime = (DWORD)ll;
	ft->dwHighDateTime = ll >> 32;
}
int INHERENT_utimes(){ return 1; }
int fileIsdir(PCStr(path));
int utimes(PCStr(path),struct timeval *tvp)
{	HANDLE fh;
	FILETIME atime,mtime;
	BOOL ok;
	struct tm *tm;

	if( isWindowsCE() && fileIsdir(path) ){
		return -1;
	}
	fh = CreateFile(path,GENERIC_READ|GENERIC_WRITE,
		0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	/*
	if( fh == NULL )
	*/
	if( fh == NULL || fh == INVALID_HANDLE_VALUE )
		return -1;

	UnixTimeToFileTime(tvp[0].tv_sec,&atime);
	UnixTimeToFileTime(tvp[1].tv_sec,&mtime);

	ok = SetFileTime(fh,NULL,&atime,&mtime);
	CloseHandle(fh);
	if( ok )
		return 0;
	else	return -1;
}
int futimes(int fd,const struct timeval *tvp){
	HANDLE fh;
	FILETIME atime,mtime;
	BOOL ok;

	fh = (HANDLE)_get_osfhandle(fd);
	UnixTimeToFileTime(tvp[0].tv_sec,&atime);
	UnixTimeToFileTime(tvp[1].tv_sec,&mtime);
	ok = SetFileTime(fh,NULL,&atime,&mtime);
	if( ok )
		return 0;
	else	return -1;
}
int INHERENT_futimes(){ return 1; }
int file_mtime(int fd);
int Futimes(int fd,int as,int au,int ms,int mu){
	struct timeval tv[2];
	int rcode;
	tv[0].tv_sec = as;
	tv[0].tv_usec = au;
	tv[1].tv_sec = ms;
	tv[1].tv_usec = mu;
	rcode = futimes(fd,tv);
	return rcode;
}

int SUBST_timegm = 1;
int Timegm(struct tm *tm);
int Timelocal(struct tm *tm);
time_t timegm(struct tm *tm){
	return Timegm(tm);
}
time_t timelocal(struct tm *tm){
	return Timelocal(tm);
}

int newtmp(PCStr(path))
{	HANDLE fh;
	int fd;
	SECURITY_ATTRIBUTES secattr;
	int werr;

	/* setting bInheritHandle seems neccessary on Win9X */
	secattr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secattr.lpSecurityDescriptor = NULL;
	secattr.bInheritHandle = 1;

	fh = CreateFile(path,GENERIC_READ|GENERIC_WRITE,
		0,&secattr,CREATE_NEW,
		FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,
		NULL);

	werr = GetLastError();
	if( fh == NULL || fh == INVALID_HANDLE_VALUE ){
		fprintf(stderr,"#### newtmp(%s)=%X err=%d\n",path,fh,werr);
		return -1;
	}

	fd = _open_osfhandle((int)fh,0);
	if( fd < 0 ){
		LE("#### newtmp(%s) = %d/%d werr=%d,%d err=%d",path,fd,fh,
			werr,GetLastError(),errno);
	}
	LV("#### newtmp(%s) = %d/%d",path,fd,fh);
	return fd;
}
#if !defined(UNDER_CE)
int doDeleteOnClose(int fd,int fh){
	return -1;
}
#endif

/* ################### */
void writev(int fd, struct iovec *iov, int iovcnt)
{
	LE("writev() NOT SUPPORTED");
	exit(1);
}
void sigpause(){
	LE("sigpause() NOT SUPPORTED");
	exit(1);
}

/*
 *	parent-child relationship is not implemented in Windows
 */

/* old struction until DeleGate/7.9.3 */
typedef struct {
	int	p_ppid;		/* parent's process handle */
	int	p_pmode;	/* spawn mode from the parent {P_NOWAIT} */
	int	p_inhfd[4];
	int	p_inhsock[4];	/* socket handle connected to the client */
	int	p_pinhsock[4];	/* parent's clsock inherited if in WindowsNT */
	int	p_toparent;	/* socket for sync and exist status code */
	int	p_nosockopen;
	struct {
	int	p_sessionfd[2];
	} p_common;
	int	p_closeOnExecN;
	int	p_closeOnExec[8];
} OldProcEnv;

/* new structure after DeleGate/7.9.5 */
typedef struct {
	int	p_ppid;		/* parent's process handle */
	int	p_pmode;	/* spawn mode from the parent {P_NOWAIT} */
	int	p_toparent;	/* socket for sync and exist status code */
	int	p_toparentFd;
	int	p_toparentFdSet;
	int	p_nosockopen;
	int	p_inhfd[MIS];
	int	p_inhsock[MIS];	/* socket handle connected to the client */
	int	p_pinhsock[MIS];/* parent's clsock inherited if in WindowsNT */
	struct {
	int	p_sessionfd[2];
	} p_common;
	int	p_closeOnExecN;
	int	p_closeOnExec[MIS];
} ProcEnv;
static void inheritsock(int si,HANDLE cphandle,ProcEnv *cpe);

typedef struct {
	OldProcEnv	p_ope;
	int		p_envlen;
	MStr(		p_envstr,256);
} TransProcEnv;

void setiv(int di[],int ni,int iv);
void copyiv(int di[],int si[],int ni);
char *htoniv(xPVStr(bp),int bsiz,PCStr(what),int ic,int iv[]);
char *ntohiv(PCStr(buf),PCStr(bp),int blen,PCStr(what),int ic,int iv[],int *np);
static ProcEnv MyProcEnv;
static ProcEnv ProcEnv0;

static void ntoo(OldProcEnv *os,ProcEnv *ns)
{
	os->p_ppid = ns->p_ppid;
	os->p_pmode = ns->p_pmode;
	os->p_toparent = ns->p_toparent;
	os->p_nosockopen = ns->p_nosockopen;
	copyiv(os->p_inhfd,ns->p_inhfd,4);
	copyiv(os->p_inhsock,ns->p_inhsock,4);
	copyiv(os->p_pinhsock,ns->p_pinhsock,4);
	copyiv(os->p_common.p_sessionfd,ns->p_common.p_sessionfd,2);
	os->p_closeOnExecN = ns->p_closeOnExecN;
	copyiv(os->p_closeOnExec,ns->p_closeOnExec,8);
}
static void oton(ProcEnv *ns,OldProcEnv *os)
{
	setiv(ns->p_inhsock,MIS,-1);
	setiv(ns->p_pinhsock,MIS,-1);

	ns->p_ppid = os->p_ppid;
	ns->p_pmode = os->p_pmode;
	ns->p_toparent = os->p_toparent;
	ns->p_nosockopen = os->p_nosockopen;
	copyiv(ns->p_inhfd,os->p_inhfd,3);
	copyiv(ns->p_inhsock,os->p_inhsock,3);
	copyiv(ns->p_pinhsock,os->p_pinhsock,3);
	copyiv(ns->p_common.p_sessionfd,os->p_common.p_sessionfd,2);
	ns->p_closeOnExecN = os->p_closeOnExecN;
	copyiv(ns->p_closeOnExec,os->p_closeOnExec,8);
}
static int htonx(ProcEnv *pe,PVStr(buf),int bsiz)
{	refQStr(bp,buf); /**/
	const char *bx;
	int si;

	bx = buf+bsiz;
	sprintf(bp,"(env 4 %d %d %d %d)",
		pe->p_ppid,pe->p_pmode,pe->p_toparent,pe->p_nosockopen);
	bp += strlen(bp);
	bp = htoniv(QVStr(bp,buf),bx-bp,"inf",MIS,pe->p_inhfd);
	bp = htoniv(QVStr(bp,buf),bx-bp,"ins",MIS,pe->p_inhsock);
	bp = htoniv(QVStr(bp,buf),bx-bp,"pin",MIS,pe->p_pinhsock);
	bp = htoniv(QVStr(bp,buf),bx-bp,"ses",2,pe->p_common.p_sessionfd);
	bp = htoniv(QVStr(bp,buf),bx-bp,"cox",pe->p_closeOnExecN,pe->p_closeOnExec);
	return bp - buf;
}
static void ntohx(ProcEnv *pe,PVStr(buf),int blen)
{	char *bp = (char*)buf; /**/
	const char *bx;
	int si,ne;
	int iv[8]; /**/

	setiv(pe->p_inhsock,MIS,-1);
	setiv(pe->p_pinhsock,MIS,-1);

	bx = buf+blen;
	bp = ntohiv(buf,bp,bx-bp,"env",8,iv,&ne);
	pe->p_ppid = iv[0];
	pe->p_pmode = iv[1];
	pe->p_toparent = iv[2];
	pe->p_nosockopen = iv[3];
	bp = ntohiv(buf,bp,bx-bp,"inf",MIS,pe->p_inhfd,&ne);
	bp = ntohiv(buf,bp,bx-bp,"ins",MIS,pe->p_inhsock,&ne);
	bp = ntohiv(buf,bp,bx-bp,"pin",MIS,pe->p_pinhsock,&ne);
	bp = ntohiv(buf,bp,bx-bp,"ses",2,pe->p_common.p_sessionfd,&ne);
	bp = ntohiv(buf,bp,bx-bp,"cox",MIS,pe->p_closeOnExec,&ne);
	pe->p_closeOnExecN = ne;
}

typedef struct {
	int	c_pid;
	int	c_inherr;
} ChildEnv;

static int argc;
static const char **argv;
extern char **environ;
void unsetenv(const char *name){
}

/*
#define SPAWNENV	"SPAWN_ENVIRON"
*/
#define SPAWNENV	"SPAWN_ENVIRON2"

#if 1400 <= _MSC_VER /* VC2005 or laters */
static int _fileinfo;
#else
extern int _fileinfo;
#endif
int SUBST_setbuffer = 1;
extern int STDIO_IOFBF;
void setbuffer(FILE *fp,char *buff,unsigned int size){
	if( buff == NULL ){
		setbuf(fp,NULL);
	}else{
		setvbuf(fp,buff,STDIO_IOFBF,size);
	}
}

static int children[MAXHANDLE];
static int child_pid[MAXHANDLE];
static double child_start[MAXHANDLE];
static int nalive;
static int ntotal;
static char child_flags[MAXHANDLE];
#define CT_NONDELEGATE	0x01 /* by xspawn() */
static int peek1(int sock){
	IStr(buf,1);
	int rcc;

	if( pollin(sock,0) == 0 )
		rcc = 0;
	else	rcc = recv(sock,buf,1,MSG_PEEK);
	return rcc;
}

#undef closesocket
#define closesocket(sock) (sock < 0 ? -1 : closesocketX(FL_Arg,__LINE__,sock))

int File_isreg(PCStr(path));
int xspawnvpe(int pmode,PCStr(path),const char *const av[],const char *const ev[],PROCESS_INFORMATION *pinfo);
static int dupsock(int si,int pid,WSAPROTOCOL_INFO *pip);
int spawnvpe(int pmode,PCStr(path),const char *const *av,const char *const environ[])
{	const char *nenviron[256]; /**/
	CStr(spenv,128);
	int ei;
	int ci,cj,dsock;
	int isock[MIS],si;
	HANDLE cphandle;
	int psp[2];
	int asock,port,csock,wcc,rcc;
	TransProcEnv tpe;
	CStr(ststat,1);
	const char *env;
	int len,nei;
	BOOL ok;
	DWORD xcode1,xcode2;
	int ai,slogtype;
	double Laps[10];
	Laps[0] = Time();
	int waitspawn;
	int nready = 0;
	int spx[2] = {-1,-1};
	PROCESS_INFORMATION pinfo;
	double waitstart = 0.1;

	_fileinfo = -1;

    if( lNOSOCKINH() ){
	asock = bindsocket(-1,&port);
	psp[0] = psp[1] = -1;
	sprintf(spenv,"%s=%d",SPAWNENV,port);
	Laps[1] = Time();
	LV("--Eis asock=[%d]%d",asock,port);
    }else{
	if( lDOSOCKDUP() ){
		asock = bindsocket(-1,&port);
	}else
	if( lNO_WSOCKWA() ){
	asock = bindsocket(-1,&port);
	}else{
		asock = -1;
		port = -1;
	}
	socketpairX(AF_INET,SOCK_STREAM,0,psp);

	Laps[1] = Time();
	if( lNO_WSOCKWA() ){
	sprintf(spenv,"%s=%d",SPAWNENV,port);
	}else{
	sprintf(spenv,"%s=%d/%d/%d/%d",SPAWNENV,port,psp[0],psp[1],getpid());
	}
	if( lDOSOCKDUP() ){
		WSAPROTOCOL_INFO pi;
		int rcode,wcc;

		_pipe(spx,4*1024,O_BINARY);
		rcode = WSADuplicateSocket((SOCKET)psp[1],getpid(),&pi);
		wcc = write(spx[1],&pi,sizeof(pi));
		Xsprintf(TVStr(spenv),"/%d",spx[0]);
		LV("--Eid [%d][%d] >> [%d][%d]",psp[0],psp[1],spx[1],spx[0]);
	}
    }
	len = strlen(SPAWNENV) + 1;

	nei = 0;
	for( ei = 0; env = environ[ei]; ei++ ){
		if( elnumof(nenviron)-2 <= ei )
			break;
		if( strncmp(env,spenv,len) != 0 )
			nenviron[nei++] = env;
	}
	nenviron[nei++] = spenv;
	nenviron[nei] = NULL;
	LastCpid = 0;

	/*
	if( _waitspawn n< MIN_DGSPAWN_WAIT )
	 * spawnning non-DeleGate program
	 */
	if( winCP )
	{
	    if( xspawnvpe(pmode,path,av,nenviron,&pinfo) != -1 ){
		int spid = -1;
		cphandle = pinfo.hProcess;
		LastCpid = pinfo.dwProcessId;
		closesocket(psp[1]);
		csock = psp[0];
		ntotal++;
		nalive++;
		child_flags[csock] = CT_NONDELEGATE;
		child_start[csock] = Time();
		children[csock] = (int)cphandle;
		child_pid[csock] = LastCpid;
		LE("xspawn() = %d [%d], children(alive=%d/%d) %.3fs",
			cphandle,LastCpid,nalive,ntotal,Time()-Laps[0]);
		/*
		return (int)cphandle;
		*/
		goto EXIT;
	    }
	}

	cphandle = (HANDLE)_spawnvpe(pmode,path,av,nenviron);
	closesocket(psp[1]);

	Laps[2] = Time();
	if( (int)cphandle == -1 ){
		CStr(cwd,1024);
		getcwd(cwd,sizeof(cwd));
		LE("failed spawn(%s) at %s",path,cwd);
		fprintf(stderr,"failed spawn(%s) at %s\n",path,cwd);
		closesocket(psp[0]);
		closesocket(asock);
		/*
		return (int)cphandle;
		*/
		goto EXIT;
	}

	xcode1 = -1;
	ok = GetExitCodeProcess(cphandle,&xcode1);
	Laps[3] = Time();
	waitspawn = SPAWN_TIMEOUT * 1000; 
	if( _waitspawn < waitspawn )
		waitspawn = _waitspawn;
	if( lSPAWNLOG() )
		LE("spawn() %d ... stat=%d pollin(%d/%d,%d)",
			cphandle,xcode1,port,asock,waitspawn);

	if( xcode1 == STILL_ACTIVE ){
		if( psp[0] < 0 ){
			nready = pollin(asock,waitspawn);
		}else
		nready = pollin2(asock,psp[0],waitspawn);
		if( nready & 2 ){
			ok = GetExitCodeProcess(cphandle,&xcode1);
		}
	}

	if( xcode1 != STILL_ACTIVE || nready == 0 ){
		/* should do pollin() parallely with GetExtCodeProcess... */
		if( MIN_DGSPAWN_WAIT <= _waitspawn )
		if( xcode1 == STILL_ACTIVE ){
			LE("failed spawn(), terminate frozen child: %d",
				TerminateProcess((HANDLE)cphandle,0));
			_sleep(10);
		}
		xcode2 = -1;
		ok = GetExitCodeProcess((HANDLE)cphandle,&xcode2);
		CloseHandle(cphandle);
		LE("spawn(%s) = %d, no response from child, %d,%d/%d%s",
			path,cphandle,xcode1,
			ok,xcode2,xcode2==STILL_ACTIVE?"(STILL_ACTIVE)":"");
		closesocket(asock);
		closesocket(psp[0]);
		if( _waitspawn < MIN_DGSPAWN_WAIT ){
			LV("@@[%.3f] return HANDLE for pid: %d",
				Time()-Laps[0],(int)cphandle);
			/*
			return 100000 + (int)cphandle;
			*/
			cphandle = (HANDLE)(100000 + (int)cphandle);
			goto EXIT;
			/*
			LE("return HANDLE for pid: %d",cphandle);
			return (int)cphandle;
			*/
		}
		LV("@@[%.3f] return HANDLE for pid: %d",Time()-Laps[0],-1);
		/*
		return -1;
		*/
		cphandle = (HANDLE)-1;
		goto EXIT;
	}
	Laps[4] = Time();
	slogtype = LOG_type;
	for( ai = 0; av[ai]; ai++ ){
		if( streq(av[ai],"(Sticky)") ){
			waitstart = 3.0;
			/* to reduce Sticky processes under heavy load */
		}else
		if( strncmp(av[ai],"-WSAV:",6) == 0 ){
		}else
		if( strncmp(av[ai],"-W",2) == 0 ){
		    if( isalpha(av[ai][2]) ){
		    }else{
			LOG_type = (LOG_type & ~0xF) | atoi(av[ai]+2);
			dumpWSAstat();
			break;
		    }
		}
	}

	/*
	if( nready == 2 ){
	*/
	if( 0 <= psp[0] && nready == 2 ){
		int rcc;
		ChildEnv sce;
		csock = psp[0];
		bzero(&sce,sizeof(sce));
		rcc = recv(csock,(char*)&sce,sizeof(sce),0);
		if( rcc != sizeof(sce) ){
			LE("spawn(%s) rcc=%d cpid=%d",path,rcc,sce.c_pid);
			closesocket(asock);
			closesocket(psp[0]);
			/*
			return -1;
			*/
			cphandle = (HANDLE)-1;
			goto EXIT;
		}
		LV("@@[%.3f] spawn(%s) cpid=%d",Time()-Laps[0],path,sce.c_pid);
	}else
	if( asock < 0 ){
		csock = psp[0];
		LE("spawn(), no conn. with the child [%d][%d]%d",
			asock,csock,cphandle);
		LE("## HINT: socket seems not inherited to a child process");
		LE("## HINT: try the option \"-Eis\" to enfoce inheritance,");
		LE("## HINT:  or the option \"-Eid\" to try duplication,");
		LE("## HINT: or the options \"-Dis\" together with \"-n8\"");
	}else{
	csock = acceptsocket(asock);
		sweepdanglingsock("spawnvpe",csock);
		LV("--Eis csock=[%d] << accept(%d)",csock,asock);
	}
	Laps[5] = Time();
	closesocket(asock);
	SetHandleInformation((HANDLE)csock,HANDLE_FLAG_INHERIT,0);

    {
	ProcEnv cpe;
	cpe = ProcEnv0;
	cpe.p_pmode = pmode;
	cpe.p_ppid = getpid();
	cpe.p_nosockopen = NO_SOCKOPEN;
	cpe.p_common = MyProcEnv.p_common;

	for( si = 0; si < MIS; si++ )
		inheritsock(si,cphandle,&cpe);
	Laps[6] = Time();

	cj = 0;
	for( si = 0; si < MIS; si++ )
		isock[si] = cpe.p_inhsock[si];

	for( ci = 0; ci < coen; ci++ ){
		dsock = coes[ci];
		if( ISSOCK(dsock) ){
			int match = 0;
			for( si = 0; si < MIS; si++ ){
				if( isock[si] == dsock ){
					LE("don't closeOnExec (%d) (inherited)",
						dsock);
					match = 1;
					break;
				}
			}
			if( !match ){
				if( elnumof(cpe.p_closeOnExec) <= cj ){
					LE("IGNORED closeOnExec[%d]",coen);
				}else
				{
					LV("--COE[%d][%d]",cj,dsock);
				cpe.p_closeOnExec[cj++] = dsock;
				}
			}
		}
		else{
			LE("--COE[%d][%d] NOT SOCK",cj,dsock);
		}
	}
	cpe.p_closeOnExecN = cj;

	ntoo(&tpe.p_ope,&cpe);
	tpe.p_envlen = htonx(&cpe,AVStr(tpe.p_envstr),sizeof(tpe.p_envstr));
	wcc = send(csock,(char*)&tpe,sizeof(tpe),0);
	LV("--Eis parent-side [%d] wcc=%d",csock,wcc);
    }
	Laps[7] = Time();

	ntotal++;
	nalive++;
	children[csock] = (int)cphandle;
	child_start[csock] = Laps[7];
	child_flags[csock] = 0;
	LV("--Eis csock[%d]",csock);

	LastCpid = 0;
	/*
	if( 0 < pollin(csock,100) ){
	*/
	if( 0 < pollin(csock,waitstart*1000) ){
		ChildEnv sce;
		int rcc;
		bzero(&sce,sizeof(sce));
		rcc = recv(csock,(char*)&sce,sizeof(sce),0);
		Laps[8] = Time();
		if( sizeof(sce.c_pid) <= rcc ){
			LastCpid = sce.c_pid;
			if( sce.c_inherr ){
			    for( si = 0; si < MIS; si++ ){
				WSAPROTOCOL_INFO pi;
				if( dupsock(si,sce.c_pid,&pi) ){
					send(csock,(char*)&pi,sizeof(pi),0);
					LV(">>>> sent[%d]",si);
				}
			    }
			}
		}
	}
	else{
		Laps[8] = Time();
		/*
		LE("No response from child process");
		*/
		LE("spawn() = %d, No response from child [%.3f] (%d/%d)",
			cphandle,Laps[8]-Laps[0],nalive,ntotal);
	}
	Laps[9] = Time();
	child_pid[csock] = LastCpid;

	LE("spawn() = %d [%d], children(alive=%d/%d) %.3fs",
		cphandle,LastCpid,nalive,ntotal,Laps[9]-Laps[0]);
	syslog_ERROR("spawn() = %d [%d], children(alive=%d/%d) %.3fs\n",
		cphandle,LastCpid,nalive,ntotal,Laps[9]-Laps[0]);

	if( 0.001 <= Laps[9] - Laps[0] ){
		CStr(laps,256);
		refQStr(lp,laps);
		int li;
		for( li = 1; li <= 9; li++ ){
			double lap;
			lap = Laps[li] - Laps[li-1];
			if( 0.001 <= lap ){
				sprintf(lp,"[%d]%.3f",li,lap);
				lp += strlen(lp);
			}
		}
		sprintf(lp," %.3f",Laps[9]-Laps[0]);
		lp += strlen(lp);
		setVStrEnd(lp,0);
		/*
		if( 0.1 <= Laps[9] - Laps[0] )
		*/
		if( waitstart <= Laps[9] - Laps[0] )
			LE("spawn() = %d %s",cphandle,laps);
		else	LV("spawn() = %d %s",cphandle,laps);
	}

	LOG_type = slogtype;

EXIT:
	if( 0 <= spx[0] ) close(spx[0]);
	if( 0 <= spx[1] ) close(spx[1]);
	return (int)cphandle;
}
#ifdef UNDER_CE
int _open_osfhandleX(int fd,int mod,int mfd);
#else
#define _open_osfhandleX(fd,mod,mfd) _open_osfhandle(fd,mod)
#endif
static int set_sessionfd(int sfdv[2]){
	int sv[2];
	socket_init();
	socketpairX(AF_INET,SOCK_STREAM,0,sv);
	sfdv[0] = _open_osfhandleX(sv[0],0,3);
	sfdv[1] = _open_osfhandleX(sv[1],1,3);
	WCE_sDBG(stderr,"---s set[%d/%d][%d/%d] sessionfd()=%d\n",
		sv[0],sv[1],sfdv[0],sfdv[1],sessionfd());
	return 0;
}
static int sessionfd(){
	int fd;

	fd = MyProcEnv.p_common.p_sessionfd[0];
	if( fd == -1 ){
		WCE_sDBG(stderr,"---s sessionfd = %d\n",fd);
		set_sessionfd(MyProcEnv.p_common.p_sessionfd);
		fd = MyProcEnv.p_common.p_sessionfd[0];
		WCE_sDBG(stderr,"---s sessionfd = %d <<<\n",fd);
		sleep(3);
	}
	return fd;
}
int SessionFd(){ return sessionfd(); }

/* Set it on to emulate systems without SOCKET inheritance (Windows95) */
static int forceDUP = 1;

int CFI_init(int ac,const char *av[]){
	int clsock,svsock;
	int sfd,efd,fd;
	int mfd;

	if( STARTED ){
		setCFIshared();
		return ac;
	}

	DO_STARTUP(ac,av);
	DO_INITIALIZE(ac,av);
	env2arg("CFI_");

	clsock = getclientsock();
	svsock = getserversock();

	if( clsock < 0 || svsock < 0 )
		LE("CFI_init: clsock=%d svsock=%d\n",clsock,svsock);

	if( clsock != 0 ) dup2(clsock,0);
	if( svsock != 1 ) dup2(svsock,1);

	sfd = sessionfd();
	efd = fileno(stderr);
	mfd = setCFIshared();
	for( fd = 3; fd < 32; fd++ ){
		if( fd != mfd )
		if( fd != sfd && fd != efd )
			close(fd);
	}

	return ac;
}
static const char *tmplog;
static void set_childlog(int ac,const char *av[])
{	int ai;
	const char *arg;
	int fgexe = 0;
	int loglev = 0;
	const char *logdir = 0;
	CStr(lpath,256);
	int now = time(0L);

	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( streq(arg,"-v") || streq(arg,"-vv") || streq(arg,"-f") )
			fgexe = 1;
		else
		if( strncmp(arg,"-WSAV:",6) == 0 ){
		}else
		if( strncmp(arg,"-W",2) == 0 ){
		    if( isalpha(arg[2]) ){
		    }else{
			loglev = atoi(arg+2);
			if( logdir = strchr(arg,',') )
				logdir++;
		    }
		}
	}
	if( loglev ){
		LOG_type = (LOG_type & ~0xF) | loglev;
		if( !fgexe || logdir ){
			if( logdir == 0 )
				logdir = "/delegate-tmplog";
			sprintf(lpath,"%s/%02d%02d-%04d",logdir,
				(now%3600)/60,now%60,getpid());
			tmpLogFd = creat(lpath,0666);
			if( 0 <= tmpLogFd )
				tmplog = strdup(lpath);
		}
		for( ai = 0; ai < ac; ai++)
			LV("arg[%d] %s",ai,av[ai]);
	}
}
void DO_INITIALIZE(int ac,const char *av[])
{
	MAIN_argc = ac;
	MAIN_argv = av;
	if( MyProcEnv.p_ppid == 0 ){
		if( start_service(ac,av) )
		{
	LE("[%d] svc DO_INITIALIZE -> DO_FINALIZE",GetCurrentThreadId());
			DO_FINALIZE(0);
		}
	}
}
void inheritSOCK(int ppid,HANDLE pphandle,int pport,int si);
static void dumpsockX(PVStr(str),int csock,const char *fmt,...){
	CStr(buf,128);
	int len,type;
	VSAddr sina,pina;
	VARGS(8,fmt);

	len = sizeof(type);
	type = -1;
	getsockopt(csock,SOL_SOCKET,SO_TYPE,(char*)&type,&len);
	len = sizeof(sina);
	bzero(&sina,sizeof(sina));
	getsockname(csock,(SAP)&sina,&len);
	len = sizeof(pina);
	bzero(&pina,sizeof(pina));
	getpeername(csock,(SAP)&pina,&len);

	sprintf(buf,fmt,VA8);
	sprintf(str,"%s%d %d [%s:%d]<-[%s:%d]%d",
		buf,csock,type,
		VSA_ntoa(&sina),VSA_port(&sina),
		VSA_ntoa(&pina),VSA_port(&pina),
		WSAGetLastError());
}
static void dumpsock(int csock,const char *fmt,...){
	CStr(str,1024);
	VARGS(8,fmt);

	dumpsockX(AVStr(str),csock,fmt,VA8);
	LV("%s",str);
}
static int check_sockets(){
	int si,csock,psock;

	for( si = 0; si < MIS; si++ ){
		csock = MyProcEnv.p_inhsock[si];
		psock = MyProcEnv.p_pinhsock[si];
		if( csock <= 0 )
			continue;
		dumpsock(csock,">>>>  inherited[%d] ",si,csock);
		if( 0 < psock )
		dumpsock(psock,">>>> duplicated[%d] ",si,psock);

		if( !ISSOCK(csock) )
		if( ISSOCK(psock) ){
			MyProcEnv.p_inhsock[si] = psock;
LE(">>>> [%d] %d is not socket, substitute inherited (%d)",si,csock,psock);
		}else{
LE(">>>> [%d] %d is not socket, retrying WSADuplicateSocket ...",si,csock);
			return -1;
		}
	}
	return 0;
}

static void dumpsocket3(int sock,int snum){
	int sx;
	int rcode;
	unsigned long int on;

	for( sx = sock; sx < sock+snum; sx++ ){
		rcode = ioctlsocket((SOCKET)sx,FIONBIO,&on);
		if( rcode != 0 )
			continue;
	}
}
static void inspectSockets(){
	int si;
	int pclsock,nclsock;

	if( lNO_WSOCKWA() )
		return;

	for( si = 2; si < 3; si++ ){
		pclsock = MyProcEnv.p_pinhsock[si];
		nclsock = MyProcEnv.p_inhsock[si];
		if( 0 <= nclsock ) dumpsocket3(nclsock,3);
		if( 0 <= pclsock ) dumpsocket3(pclsock,3);
		MyProcEnv.p_pinhsock[si] = -1; /* disable closing pinhsock */
	}
}

int inheritLogControl(){
	if( lNOSOCKINH() ){
		return -1;
	}
	LOG_UDPsock[0] = openSocket(-1,LOG_UDPsockfh[0],1,"UDPlog/spawn");
	LOG_UDPsock[1] = openSocket(-1,LOG_UDPsockfh[1],1,"UDPlog/spawn");
	return 0;
}
static int getdupsock(int spx){
	WSAPROTOCOL_INFO pi;
	int psock;
	int rcc;

	rcc = read(spx,&pi,sizeof(pi));
	if( rcc == sizeof(pi) ){
		psock = WSASocket(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,
			FROM_PROTOCOL_INFO,&pi,0,0);
		LV("--getdupsock[%d]%d sock=%d",spx,rcc,psock);
		return psock;
	}
	return -1;
}

#undef closesocket
#define closesocket(sock)	closesocketX(FL_Arg,__LINE__,sock)
int regdump_main(int ac,const char *av[],FILE *out,FILE *err);
void DO_STARTUP(int ac,const char *av[])
{	int pin;
	int rcc;
	int pport,psock;
	int psp[2];
	int spx;
	int ei,nei;
	int ci;
	const char *env;
	int len;
	int ppid;
	int wcc;
	TransProcEnv tpe;
	int ai;
	ChildEnv sce;
	double Start;
	int Facl = 0;

	_set_invalid_parameter_handler(invalid_parameter_handler);

	if( isWindows95() ){
		/* 9.9.1 necessary to inherit socket to children (9.2.5) */
		LOG_type4 |= L_NOSOCKINH;
		/* 9.9.1 to disable lock_ext for shared lock (9.0.6) */
		LOG_type2 |= L_LOCKSHARED;
	}

	Start = Time();
	if( lSPAWNLOG() ){
		if( env = getenv(SPAWNENV) ){
			LE("spawn() ... DO_STARTUP %s=%s",SPAWNENV,env);
		}
	}

	STARTED = 1;
	setBinaryIO();
	WINthread();

	argc = ac;
	argv = av;
	for( ai = 0; ai < ac; ai++ ){
		const char *arg = av[ai];
		if( strncmp(arg,"-WSAV:",6) == 0 )
			WinSockVer = stralloc(arg+6);
		else
		if( strncmp(arg,"-w",2) == 0 ){
			int lev = atoi(arg+2);
			if( lev == 0 )
				lev = 1;
			LOG_type = (LOG_type & ~0xF) | lev;
		}
		else
		if( strncmp(arg,"FILEOWNER=",10) == 0 ){
			FILEOWNER = stralloc(arg+10); 
			Facl |= 1;
		}
		else
		if( strncmp(arg,"FILEACL=",8) == 0 ){
			FILEACL = stralloc(arg+8); 
			Facl |= 2;
		}
		else
		if( streq(arg,"-Ffacl") ){
			void lsacl(PCStr(path),PCStr(owner),PCStr(acl));
			lsacl(av[ai+1],(Facl&1)?FILEOWNER:"",(Facl&2)?FILEACL:"");
			exit(0);
		}
		if( streq(arg,"-Fregdump") ){
			regdump_main(ac-ai,av+ai,stdout,stderr);
			exit(0);
		}
	}

	socket_init();
	dumpWSAstat();

	psock = -1;
	nei = 0;
	len = strlen(SPAWNENV);

	for( ei = 0; env = environ[ei]; ei++ ){
		if( strncmp(env,SPAWNENV,len) == 0 && env[len] == '=' ){
			unsigned long int on = 1;
			unsigned long int off = 0;

			if( environ[ei+1] != NULL ){
			    /* 9.9.1: this is since 9.2.4 to ignore the
			     * env. not for this process, but there can be
			     * SystemRoot= on Win95 (1400 <= _MSC_VER)
			     * added automaticlly after the SPAWN_ENVIRON.
			     */
			    if( strneq(environ[ei+1],"SystemRoot=",11)
			     && environ[ei+2] == 0 ){
				LV("not ignored %s",env);
				LV("not ignored %s",environ[ei+1]);
			    }else{
				LE("ignored ancestor's %s",env);
				continue;
			    }
			}
			environ[ei] = NULL;

			if( lSPAWNLOG() ) LE("spawn() ... %s",env);
			set_childlog(ac,av);
			dumpWSAstat();
			/*
			pport = atoi(&env[len+1]);
			*/
			pport = -1;
			psp[0] = psp[1] = -1;
			ppid = -1;
			spx = -1;
			/*
			sscanf(&env[len+1],"%d/%d/%d/%d",&pport,&psp[0],&psp[1],&ppid);
			*/
			sscanf(&env[len+1],"%d/%d/%d/%d/%d",
				&pport,&psp[0],&psp[1],&ppid,&spx);
			if( 0 <= psp[0] && ISSOCK(psp[0]) ){
				int rcode;
				int wcc;
				rcode = closesocket(psp[0]);
				psock = psp[1];

				bzero(&sce,sizeof(sce));
				sce.c_pid = getpid();
				wcc = send(psock,(char*)&sce,sizeof(sce),0);
			}else
			if( 0 <= spx && 0 <= (psock = getdupsock(spx)) ){
				LV("--Eid [%d]->[%d]",spx,psock);

				bzero(&sce,sizeof(sce));
				sce.c_pid = getpid();
				wcc = send(psock,(char*)&sce,sizeof(sce),0);
			}else{
			ioctlsocket((SOCKET)psock,FIONBIO,&on);
			psock = connectsocket(-1,pport);
				LV("--Eis child-side connect %d[%d] %s",
					pport,psock,env);
			}

			if( lSPAWNLOG() ){
				LE("spawn() ... connected=%d (%.3f)",
					psock,Time()-Start);
			}
			if( psock < 0 ){
				LE("CANNOT CONNECT TO PARENT");
				exit(-1);
			}
			ioctlsocket((SOCKET)psock,FIONBIO,&off);
			if( pollin(psock,10*1000) <= 0 ){
				LE("NO DATA FROM PARENT");
				exit(-1);
			}
			rcc = recv(psock,(char*)&tpe,sizeof(tpe),0);
			if( rcc <= 0 ){
				LE("@@ NO DATA FROM PARENT: rcc=%d %s",rcc,env);
				close(psock);
				psock = -1;
				continue;
			}
			LV("inheritance recv() = %d",rcc);

			bzero(&sce,sizeof(sce));
			sce.c_pid = getpid();

			if( rcc == sizeof(OldProcEnv) ){
				oton(&MyProcEnv,&tpe.p_ope);
			}else
			if( rcc == sizeof(tpe) ){
				ntohx(&MyProcEnv,AVStr(tpe.p_envstr),tpe.p_envlen);
				sce.c_inherr = check_sockets();
			}else{
				LT("CANNOT READ ARGUMENTS [%d/%d]: %d/%d",
					pport,psock,rcc,sizeof(ProcEnv));
				closesocket(psock);
				exit(-1);
			}
			wcc = send(psock,(char*)&sce,sizeof(ChildEnv),0);
			MyProcEnv.p_toparent = psock;
			LV("STARTUP: %s, got[%d], ppid=%d,pmode=%d",
				env,rcc, MyProcEnv.p_ppid, MyProcEnv.p_pmode);
			iLog("--- STARTUP: %s, got[%d], ppid=%d,pmode=%d",
				env,rcc, MyProcEnv.p_ppid, MyProcEnv.p_pmode);
		}
	}

	ppid = MyProcEnv.p_ppid;

	if( ppid == 0 ){
		if( isWindowsCE() )
			set_sessionfd(MyProcEnv.p_common.p_sessionfd);
		else
		pipe(MyProcEnv.p_common.p_sessionfd);
	}else{
		NO_SOCKOPEN = MyProcEnv.p_nosockopen;
	}

	for( ci = 0; ci < MyProcEnv.p_closeOnExecN; ci++ ){
		int sock,rcode;
		sock = MyProcEnv.p_closeOnExec[ci];
		rcode = closesocket(sock);
		LV("do CloseOnExec[%d]=%d, do close=%d",ci,sock,rcode);
		iLog("--- do CloseOnExec[%d]=%d, do close=%d",ci,sock,rcode);
	}

	/* 9.2.5 a workaround to escape frozen .exe on Cygwin */
	inspectSockets();

	if( 0 <= psock ){
		HANDLE pphandle;
		int si;
		pphandle = OpenProcess(PROCESS_ALL_ACCESS,0,ppid);
		for( si = 0; si < MIS; si++ )
		{	int dclsock;
			WSAPROTOCOL_INFO pi;

			if( sce.c_inherr )
			if( 0 <= MyProcEnv.p_inhsock[si] )
			if( recv(psock,(char*)&pi,sizeof(pi),0) == sizeof(pi) ){
				dclsock = WSASocket(
					FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,
					FROM_PROTOCOL_INFO,&pi,0,0);
				LV(">>>> recv[%d] clsock=%d nc=%d %d %d %d",
					si,MyProcEnv.p_inhsock[si],dclsock,
					pi.iAddressFamily,
					pi.iSocketType,
					pi.iProtocol);
				if( 0 < dclsock ){ 
			dumpsock(dclsock,">>>> Duplicated[%d] ",si,dclsock);
					MyProcEnv.p_inhsock[si] = dclsock;
				}
			}
			inheritSOCK(ppid,pphandle,pport,si);
		}

		if( tmplog ){
			close(tmpLogFd);
			tmpLogFd = -1;
			LOG_type = (LOG_type & ~0xF);
			if( LOGLEVEL < 6 ){
				unlink(tmplog);
				tmplog = 0;
			}
		}
	}else{
	}
}
int getParentSock(){
	if( MyProcEnv.p_toparent <= 0 )
		return -1;
	if( MyProcEnv.p_toparentFdSet == 0 ){
		MyProcEnv.p_toparentFdSet = 1;
		MyProcEnv.p_toparentFd = 
			openSocket(-1,MyProcEnv.p_toparent,0,"PraentSock");
		LT("getParentSock[%d][%d]",
			MyProcEnv.p_toparent,MyProcEnv.p_toparentFd);
	}
	return MyProcEnv.p_toparentFd;
}
void inheritSOCK(int ppid,HANDLE pphandle,int pport,int si){
	int pclsock,nclsock,fd;
	VSAddr ina;
	int len;

	pclsock = MyProcEnv.p_pinhsock[si];
	nclsock = MyProcEnv.p_inhsock[si];

	LV("[%d] PPID=%d/%d CLSOCK=[%d->%d]",si,ppid,pphandle,pclsock,nclsock);

	if( 0 <= pclsock )
	iLog("--- [%d] PPID=%d/%d CLSOCK=[%d->%d]",si,ppid,pphandle,pclsock,nclsock);

	/* CLSOCK possibly inherited (WindowsNT) */
	if( !isWindows95() )
	if( 0 <= pclsock && pclsock != nclsock )
	{
		int sx,inherited;
		inherited = 0;
		for( sx = 0; sx < MIS; sx++ )
			if( MyProcEnv.p_inhsock[sx] == pclsock )
				inherited = 1;
		if( inherited == 0 ){
		LV("inheritSOCK -- closesocket(%d)",pclsock);
		closesocket(pclsock);
		}
	}

	if( 0 <= nclsock ){
		if( !ISSOCK(nclsock) ){
			LE("FATAL: inherited handle[%d] %d is not socket",si,nclsock);
			exit(-1);
		}
		MyProcEnv.p_inhfd[si] = fd = openSocket(-1,nclsock,1,"fork()");
		if( lNOSOCKINH() ){
			if( isWindows95() ){
			}else
			LE("---- can't inherit [%d][%d]",fd,nclsock);
		}
		if( fd < 0 )
			exit(-1);

		len = sizeof(VSAddr);
		bzero(&ina,len);
		getpeername(nclsock,(SAP)&ina,&len);

		LV("PARENT=%d, PORT=%d, CLSOCK[%d]=%d/%d:%d [%s:%d]",
			ppid,pport,si,
			nclsock,fd,ISSOCK(nclsock),
			VSA_ntoa(&ina),VSA_port(&ina));
	}
}

static int bindsocket(int sock,int *portp)
{	int port;
	int rcode;
	VSAddr ina;
	int inalen,len;

	if( sock < 0 )
	{
		socket_init();
		sock = socket(AF_INET,SOCK_STREAM,0);
		sweepdanglingsock("bindsocket",sock);
	}

	inalen = VSA_atosa(&ina,0,"127.0.0.1");
	rcode = bind(sock,(SAP)&ina,inalen);
	rcode = listen(sock,1);

	if( portp ){
		len = sizeof(VSAddr);
		getsockname(sock,(SAP)&ina,&len);
		*portp = VSA_port(&ina);
	}
	return sock;
}
static int connectsocket(int sock,int port)
{	VSAddr ina;
	int inalen,rcode;

	if( port <= 0 ){
		LE("connectsocket(%d) bad port number",port);
		return -1;
	}
	if( sock < 0 )
	{
		sock = socket(AF_INET,SOCK_STREAM,0);
		sweepdanglingsock("connectsocket",sock);
	}
	if( sock < 0 ){
		LE("connectsocket(%d) failed to create socket",port);
		return -1;
	}

	inalen = VSA_atosa(&ina,port,"127.0.0.1");
	rcode = connect(sock,(SAP)&ina,inalen);

	LV("connect(%d,%d) = %d",sock,port,rcode);
	return sock;
}
static int acceptsocket(int asock)
{	int csock;
	VSAddr ina;
	int len;
	int myport;

	len = sizeof(VSAddr);
	getsockname(asock,(SAP)&ina,&len);
	myport = VSA_port(&ina);

	len = sizeof(VSAddr);
	csock = accept(asock,(SAP)&ina,&len);
	sweepdanglingsock("acceptsocket",csock);
	LV("accept(%d,%d) = %d [%s:%d]",asock,myport,csock,
		VSA_ntoa(&ina),VSA_port(&ina));
	return csock;
}

static struct InheritSock {
	int	is_fd;
	int	is_sock;
	int	is_set;
	int	is_close_src;
} INHERIT_SOCK[MIS];
void setclosesource(int si){
	if( isWindows95() )
		INHERIT_SOCK[si].is_close_src = 1;
}

static int dummy_in = -1;
static int dummy_input()
{	int io[2];
	int in2;

	if( dummy_in < 0 ){
		pipe(io);
		dummy_in = io[0];
		if( dummy_in == 0 ){
			in2 = _dup(dummy_in);
			_close(dummy_in);
			dummy_in = in2;
		}
		close(io[1]);
	}
	return dummy_in;
}

static int dupsock(int si,int pid,WSAPROTOCOL_INFO *pip){
	int sock;
	int rcode;

	if( 0 <= (sock = INHERIT_SOCK[si].is_sock) ){
		rcode = WSADuplicateSocket((SOCKET)sock,pid,pip);
		if( rcode != 0 )
			return 0;

		LV(">>>> dupsock(%d,%d)=%d [%d %d %d]",sock,pid,rcode,
			pip->iAddressFamily,pip->iSocketType,pip->iProtocol);
		return 1;
	}else	return 0;
}
static void inheritsock(int si,HANDLE cphandle,ProcEnv *cpe)
{	struct InheritSock *ihs;
	int cs,rcode,dummy;

	ihs = &INHERIT_SOCK[si];
	if( ihs->is_set ){
		unsigned long inh = 0;
		GetHandleInformation((HANDLE)ihs->is_sock,&inh);
		if( (inh & HANDLE_FLAG_INHERIT) == 0 ){
		    if( lDOSOCKDUP() && !lNOSOCKINH() ){
			LV("--Dis DO inheritsock(%d,%d) inh=%d",
				si,ihs->is_sock,inh);
		    }else
		    if( isWindows95() ){
		    }else{
			LE("--NO inheritsock(%d,%d) inh=%d",
				si,ihs->is_sock,inh);
			cpe->p_pinhsock[si] = -1;
			cpe->p_inhsock[si] = -1;
			return;
		    }
		}

		ihs->is_set = 0;
		cs = ihs->is_close_src;
		ihs->is_close_src = 0;
		cpe->p_pinhsock[si] = ihs->is_sock;
		cpe->p_inhsock[si] = duphandle(0,(HANDLE)ihs->is_sock,cphandle,cs,0);
		if( lNOSOCKINH() ){
			cpe->p_pinhsock[si] = -1;
		}
		if( lWOSOCKINH() ){
			int osock;
			/*
			osock = cpe->p_pinhsock[si];
			cpe->p_pinhsock[si] = setSockInh("inheritsock",osock);
			closesocket(osock);
			*/
			osock = cpe->p_inhsock[si];
			cpe->p_inhsock[si] = setSockInh("inheritsock",osock);
			closesocket(osock);
		}
		if( cs ){
			dummy = dummy_input();
			rcode = closeSocket(ihs->is_fd,ihs->is_sock);
			_dup2(dummy,ihs->is_fd);
		}
		LV("INHERIT: %d->%d (close_source=%d,%d/%d)",
		ihs->is_sock,cpe->p_inhsock[si],cs,ihs->is_sock,ihs->is_fd);
	}else{
		cpe->p_pinhsock[si] = -1;
		cpe->p_inhsock[si] = -1;
	}
}
int passsock(int si,int sock)
{
	if( sock < 0 )
		return sock;
	if( SocketOf(sock) == 0 )
		return sock;

	LV("set INHERIT_SOCK=%d/%d",SocketOf(sock),sock);
	INHERIT_SOCK[si].is_fd = sock;
	INHERIT_SOCK[si].is_sock = SocketOf(sock);
	INHERIT_SOCK[si].is_set = 1;
	return sock;
}
int recvsock(int si)
{	int fd;

	fd = MyProcEnv.p_inhfd[si];
	LV("get INHERIT_SOCK=%d/%d",SocketOf(fd),fd);
	return fd;
}
void dontclosedups(int fd){
	int sock,clsock;
	int fx;
	IStr(desc,MaxHostNameLen);
	int fi;

	sock = SocketOf(fd);
	clsock = MyProcEnv.p_inhsock[0];

	if( isWindowsCE() ){
		return;
	}
	for( fi = -1; SOS_NextDuph(&fi,&fx,sock); ){
		{
			SOS_DelDuph(fx);
			/*
			strfSocket(AVStr(desc),sizeof(desc),"",fx);
			syslog_ERROR("[%d]%d dontclosedups(%d/%d) %s\n",
				clsock,clsock==sock,sock,fx,desc);
			*/
		}
	}
}
int closedups(int si){
	int fd,sock;
	int closed;
	IStr(desc,MaxHostNameLen);
	int fi;

	closed = 0;
	sock = MyProcEnv.p_inhsock[si];
	if( sock <= 0 ){
		if( lNOSOCKINH() ){
		}else
		if( sock == 0 && (lSINGLEP() || lSYNC()) ){
		}else
		LE("ERROR closedups(%d/%d)",sock,si);
		return 0;
	}

	for( fi = -1; SOS_NextDuph(&fi,&fd,sock); )
		{
			strfSocket(AVStr(desc),sizeof(desc),"",fd);
			LE("closedups(%d/%d)",sock,fd);
			LE("[%d] closedups(%d/%d) %s",si,sock,fd,desc);
			closeSocket(fd,sock);
			closed++;
			syslog_ERROR("closedups(%d/%d) %s\n",sock,fd,desc);
		}
	return closed;
}
int setclientsock(int sock){ return passsock(0,sock); }
int getclientsock(){ return recvsock(0); }
int setserversock(int sock){ return passsock(1,sock); }
int getserversock(){ return recvsock(1); }
int setcontrolsock(int sock){ return passsock(2,sock); }
int getcontrolsock(){ return recvsock(2); }
int setrsvdsock(int si,int sock){
	if( 3+si < MIS )
		return passsock(3+si,sock);
	else	return -1;
}
int getrsvdsock(int si){
	if( 3+si < MIS )
		return recvsock(3+si);
	else	return -1;
}
int send_sock(int dpid,int fd,int closesrc)
{	HANDLE dph;
	int ssock,sock;

	ssock = SocketOf(fd);
	dph = OpenProcess(PROCESS_ALL_ACCESS,0,dpid);
	sock = duphandle(NULL,(HANDLE)ssock,dph,0,0);
	CloseHandle(dph);
	return sock;
}
int recv_sock(int spid,int ssock,int closesrc)
{	HANDLE sph;
	int sock;
	int options;
	int fd;

	sph = OpenProcess(PROCESS_ALL_ACCESS,0,spid);
	sock = duphandle(sph,(HANDLE)ssock,NULL,0,0);
	CloseHandle(sph);
	if( 0 < sock )
		fd = openSocket(-1,sock,0,"recv_sock()");
	else	fd = -1;
	LT("recv_sock(%d/%d,%d) sock=%d/%d,issock=%d err=%d",
		sph,spid,ssock,fd,sock,ISSOCK(sock),WSAGetLastError());
	return fd;
}

int WithSocketFile(){ return 0; }
int file_isselectable(int fd){
	if( SocketOf(fd) )
		return 1;
	if( ISPIPE(fd) )
		return 1;
	return 0;
}

extern int WAIT_WNOHANG;
int fork(){
	porting_dbg("*** fork() is not available.");
	exit(1);
	return -1;
}

int killchildren()
{	int px,pi,pid,ok,nkill;
	int ph;

	nkill = 0;
	for( px = 0; px <  MAXHANDLE; px++ ){
		ph = children[px];
		if( 0 < ph ){
			pid = child_pid[px];
			ok = TerminateProcess((HANDLE)ph,0);
			nkill++;
			LE("killchildren#%d Terminate %d [%d] = %d",
				nkill,ph,pid,ok);
		}
	}

	if(nkill ){
		_sleep(1);
		for( pi = 0; pi < nkill; pi++ ){
			if( wait3(NULL,WAIT_WNOHANG,NULL) < 0 )
				break;
		}
	}
	return nkill;
}

int waitpid(int pid,int *statusp,int options)
{
	LE("waitpid() = -1 (not supported)");
	return -1;
}
static int recvCpid(int chsock){
	int cpid = 0;
	HANDLE cphandle;
	ChildEnv sce;
	int rcc;
	int cph;
	int ok,tok;
	unsigned long int xcode;

	SetLastError(0);
	bzero(&sce,sizeof(sce));
	rcc = recv(chsock,(char*)&sce,sizeof(sce),0);
	cpid = sce.c_pid;

	cphandle = (HANDLE)children[chsock];
	xcode = 0;
	ok = GetExitCodeProcess(cphandle,&xcode);

	LE("spawn() = %d [%d] --DELAYED--[%.3f] rc=%d/%d st=%d/%d",
		cphandle,cpid,Time()-child_start[chsock],
		rcc,WSAGetLastError(),ok,xcode);
	if( rcc < sizeof(sce.c_pid) )
		return -1;
	if( 0 < cpid )
		return cpid;
	if( ok && xcode == STILL_ACTIVE ){
		tok = TerminateProcess(cphandle,0);
		xcode = 0;
		ok = GetExitCodeProcess(cphandle,&xcode);
		LE("spawn() = %d [%d] --DELAYED-- Terminate()=%d/%d %d/%d",
			cphandle,cpid,tok,GetLastError(),ok,xcode);
	}
	return -1;
}

typedef union {
	FILETIME ft;
	unsigned __int64 li;
} FTint;
static FTint ru_ut;
static FTint ru_st;

int wait3(int *statusp,int options,void *rusage)
{	int chsock,pid;
	int nready;
	int xpid,xstatus;
	int cpid;
	struct fd_set chset;
	struct timeval tvb,*tv = &tvb;
	double Start = Time();
	double Etime;
	int nc;
	struct fd_set ochset;

	cpid = -1;
	xpid = -1;
	xstatus = -1;
	if( statusp ) *statusp = -1;

	FD_ZERO(&chset);
	nc = 0;
	for( chsock = 0; chsock < MAXHANDLE; chsock++ )
		if( children[chsock] )
		{
			nc++;
			FD_SET(chsock,&chset);
		}

	if( nc == 0 ){
		LV("ERROR wait3() no child");
		errno = ECHILD;
		return -1;
	}

	if( options == WAIT_WNOHANG ){
		tv->tv_sec = 0;
		tv->tv_usec = 0;
	}else	tv = NULL;

	ochset = chset;
	nready = select(MAXHANDLE,&chset,NULL,NULL,tv);

	if( nready < 0 ){
		int xerr = WSAGetLastError();
		if( nc != 0 )
		{
		LE("ERROR wait3() select(%d)=%d, errno=%d",nc,nready,xerr);
			/* check which socket cause the error and remove it */
			if( xerr == WSAENOTSOCK ){
				int chs;
				IStr(ssbi,256);
				IStr(ssbo,256);
				for( chs = 0; chs < MAXHANDLE; chs++ ){
					if( children[chs] == 0 ){
						if( child_pid[chs] == 0 ){
							continue;
						}
					}
					LE("--chs[%d] %d %d",chs,children[chs],
						child_pid[chs]);
				}
				FD_dump(&ochset,MAXHANDLE,AVStr(ssbi));
				FD_dump(&chset,MAXHANDLE,AVStr(ssbo));
				LE("--children select(%s) >>",ssbi);
				LE("--children select(%s) <<",ssbo);
			}
		}
	}else
	if( 0 < nready )
	for( chsock = 0; chsock < MAXHANDLE; chsock++ ){
		if( FD_ISSET(chsock,&chset) ){
			if( child_pid[chsock] == 0 ){
				/* delayed response from the spawned child */
				int cpid;
				cpid = recvCpid(chsock);
				if( 0 < cpid ){
					child_pid[chsock] = cpid;
					continue;
				}
				if( cpid == 0 )
					continue;
			}
			cpid = child_pid[chsock];
			pid = children[chsock];
			children[chsock] = 0;
{
	FTint ct,xt,kt,ut;
	if( GetProcessTimes((HANDLE)pid,&ct.ft,&xt.ft,&kt.ft,&ut.ft) ){
		ru_ut.li += ut.li;
		ru_st.li += kt.li;
	}
/* should receive the ru_ut/ru_st of the child via the chsock ... */
}
			closesocket(chsock);
			xpid = _cwait(&xstatus,pid,0);
			nalive--;
			if( 0 < xpid )
				break;
		}
	}

	Etime = Time() - Start;

	if( 0 <= xpid || 1 <= Etime )
	LE("wait3(%s) = %d [%d] %X, children(alive=%d/%d) %.2fs",
		tv?"N":"H",xpid,cpid,xstatus,nalive,ntotal,Etime);

	if( nready != 0 || xpid != -1 || cpid != -1 || xstatus != -1 )
	syslog_ERROR("wait3(%s) = %d [%d] %X, children(alive=%d/%d) %.2fs\n",
		tv?"N":"H",xpid,cpid,xstatus,nalive,ntotal,Etime);

	if( statusp )
		*statusp = xstatus;
	return xpid;
}

static void checkarg(PCStr(path),const char *const av[],int mac,const char *nav[],PVStr(nab))
{	const char *arg;
	refQStr(ap,nab); /**/
	int ai;

	for( ai = 0; arg = av[ai]; ai++ ){
		if( mac-1 <= ai ){
			break;
		}
		if( strpbrk(arg," \t") && *arg != '"' ){
			nav[ai] = ap;
			sprintf(ap,"\"%s\"",arg);
			ap += strlen(ap) + 1;
		}else	nav[ai] = arg;
	}
	nav[ai] = NULL;
}

int isFullpath(PCStr(path));
static int fullpathCOM(PCStr(path),PCStr(mode),PVStr(xpath)){
	CStr(epath,1024);
	int ok;

	if( isFullpath(path) ){
		strcpy(xpath,path);
		return 1;
	}
	if( fullpath_cmd == 0 )
		return 0;
	ok = (*fullpath_cmd)(path,mode,BVStr(xpath));
	if( !ok && strtailstrX(path,".exe",1) == 0 ){
		sprintf(epath,"%s.exe",path);
		ok = (*fullpath_cmd)(epath,mode,BVStr(xpath));
	}
	if( ok ){
		LE("%s -> %s",path,xpath);
	}
	return ok;
}
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph);
int bgexec(PCStr(path),char *av[],char *ev[],int *ph){
	return bgexecX("",path,av,ev,ph);
}
#define XP_NOCONS	0x01000000
#define XP_DETACH	0x02000000
#define XP_NEWPRG	0x04000000
#define XP_NOINHH	0x08000000
int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph){
	PROCESS_INFORMATION pinfo;
	IStr(fpath,1024);
	char *nev[1024];
	int rfp;
	int rcode;
	int pid;
	const char *pe;
#ifdef UNDER_CE
	int pmode = _P_NOWAIT;
#else
	int pmode = _P_NOWAIT | _P_DETACH;
#endif

	if( mode && *mode ){
		pmode = _P_NOWAIT;
		if( strchr(mode,'c') ){
			pmode |= XP_NOCONS;
		}
		if( strchr(mode,'d') ){
			pmode |= XP_DETACH;
		}
		if( strchr(mode,'e') ){
			/*
			filterDGENV(ev,nev,elnumof(nev));
			ev = nev;
			*/
		}
		if( strchr(mode,'g') ){
			pmode |= XP_NEWPRG;
		}
		if( strchr(mode,'i') ){
			pmode |= XP_NOINHH;
		}
	}
	pe = getenv("PATH");
	rfp = fullpathCOM(path,"r",AVStr(fpath));
	LE("bgexe(%s) %d (%s) %X (%s)",path,rfp,fpath,fullpath_cmd,pe?pe:"");
	if( fpath[0] == 0 ){
		strcpy(fpath,path);
	}
	pinfo.dwProcessId = -1;
	rcode = xspawnvpe(pmode,fpath,(const char *const*)av,(const char *const*)ev,&pinfo);
	pid = pinfo.dwProcessId;
	*ph = (int)pinfo.hProcess;
	return pid;
}
int bgwait(int pid,int ph,double timeout){
	HANDLE hp = (HANDLE)ph;
	int wi;
	unsigned long int xcode;
	int to = 10;
	double St = Time();

	for( wi = 0; wi < 100; wi++ ){
		xcode = -1;
		GetExitCodeProcess(hp,&xcode);
		fprintf(stderr,"-- wait[%d] xcode=%d (%.2f/%.2f)\n",pid,xcode,Time()-St,timeout);
		syslog_ERROR("-- wait[%d] xcode=%d (%.2f/%.2f)\n",pid,xcode,Time()-St,timeout);
		if( xcode != STILL_ACTIVE ){
			return pid;
		}
		if( timeout < Time()-St ){
			return -1;
		}
		Sleep(to);
		if( to < 1000 )
			to += 100;
	}
	return -1;
}
int xspawnvpe(int pmode,PCStr(path),const char *const av[],const char *const ev[],PROCESS_INFORMATION *pinfo){
	CStr(ab,MAX_ARGB);
	refQStr(ap,ab);
	const char *a1;
	int ai;
	int cflags = 0;
	int inhh = 1;
	CStr(eb,MAX_ARGB);
	refQStr(ep,eb);
	int ei;
	int ok;
	STARTUPINFO stup;
	HINSTANCE mod;
	int status;
	int pid;
	CStr(magic,1024);
	IStr(spath,1024);
	IStr(xp,1024);
	FILE *efp;

	int xpmode;
	xpmode = pmode;
#if defined(UNDER_CE)
	pmode &= _P_NOWAIT;
#else
	pmode &= (_P_NOWAIT|_P_DETACH);
#endif

	for( ai = 0; a1 = av[ai]; ai++ ){
		if( ab < ap ){
			setVStrPtrInc(ap,' ');
		}
		strcpy(ap,a1);
		if( strpbrk(ap," \t") ){
			strsubst(AVStr(ap),"\"","\\\"");
			Strins(AVStr(ap),"\"");
			strcat(ap,"\"");
		}
		ap += strlen(ap);
	}
	for( ei = 0; ev[ei]; ei++ ){
		const char *xep = ep;
		int esc = 0;
		syslog_DEBUG("---xspawn env[%d]%s\n",ei,ev[ei]);
		const unsigned char *sep;
		int ch;
		for( sep = (const unsigned char*)ev[ei]; ch = *sep; sep++ ){
			if( ch < ' ' || 0x7F <= ch ){
				/* 9.9.7 it might be in Hankaku-Kana of "desktop" */
				/* - if it at the end of value, it might be catenated with the following environ. */
				/* - it should be in Unicode with CREATE_UNICODE_ENVIRONMENT in cflags */
				/* - maybe it must NOT in UTF-8 but UTF-16 WCHAR */
				sprintf(ep,"=%02X",ch);
				ep += strlen(ep);
				esc++;
			}else{
				setVStrPtrInc(ep,ch);
			}
		}
		if( esc ){
			syslog_ERROR("--xspawn env[%d]%s\n",ei,xep);
		}
		/*
		strcpy(ep,ev[ei]);
		ep += strlen(ep);
		*/
		setVStrPtrInc(ep,0);
	}

	setVStrPtrInc(ep,0);
	if( efp = fopen(path,"r") ){
		if( fgets(magic,sizeof(magic),efp) ){
			if( strneq(magic,"#!",2) ){
				lineScan(magic+2,spath);
				if( streq(spath,"/bin/sh")
				 || strtailstrX(path,".sh",1)
				){
					if( fullpathCOM("sh","r",AVStr(xp)) ){
						strcpy(spath,xp);
					}
					Strins(AVStr(ab),"-c ");
				}else
				if( strstr(spath,"/perl")
				 || strtailstrX(path,".pl",1)
				){
					if( fullpathCOM("perl","r",AVStr(xp)) ){
						strcpy(spath,xp);
					}
					Strins(AVStr(ab),"-e ");
				}
			}
		}
		fclose(efp);
	}

	if( 2 <= LOGLEVEL ){
		LV("--- spawn path: %s",path);
		LV("--- spawn args: %s",ab);
	}
	bzero(&stup,sizeof(stup));
	bzero(pinfo,sizeof(PROCESS_INFORMATION));
	ok = 0;

/*
FILE *fp;
int fd1,fd2;
fd2 = dup(2);
fd1 = dup(1);
fp = fopen("c:/tmp/dgsp.out","w+");
syslog_ERROR("----FP=%X (%d %d %d)\n",fp,fileno(stdin),fileno(stdout),fileno(stderr));
if(fp){
dup2(fileno(fp),1);
dup2(fileno(fp),2);
}
*/
	if( xpmode & XP_NOINHH ){
		inhh = 0;                           /* don't inherit handles */
	}
#ifndef UNDER_CE
	if( xpmode & XP_NOCONS ){
		cflags |= CREATE_NO_WINDOW;         /* without console */
	}
	if( xpmode & XP_DETACH ){
		cflags |= DETACHED_PROCESS;         /* without console */
	}
	if( xpmode & XP_NEWPRG ){
		cflags |= CREATE_NEW_PROCESS_GROUP; /* detach Control-C */
	}
	if( pmode & _P_DETACH ){
		cflags |= CREATE_NO_WINDOW;         /* without console */
		cflags |= DETACHED_PROCESS;         /* detach current console */
		cflags |= CREATE_NEW_PROCESS_GROUP; /* detach Control-C */
		inhh = 0;                           /* don't inherit handles */
	}
#endif
	if( spath[0] ){
		ok = CreateProcess(spath,ab,NULL,NULL,inhh,cflags,eb,NULL,&stup,pinfo);
		LE("A CreateProcess(%s)=%d pid=%d %d",spath,ok,pinfo->dwProcessId,GetLastError());
	}
	if( !ok ){
		ok = CreateProcess(path,ab,NULL,NULL,inhh,cflags,eb,NULL,&stup,pinfo);
		LE("B CreateProcess(%s)=%d pid=%d %d",path,ok,pinfo->dwProcessId,GetLastError());
	}
/*
dup2(fd2,2);
dup2(fd1,1);
*/

	if( !ok ){
		return -1;
	}

	pid = pinfo->dwProcessId;
fprintf(stderr,"----WinCE xspawnvpe() %d ok=%X pid=%X/H%X wait=%x/%x\n",
__LINE__,(int)ok,(int)pid,(int)pinfo->hProcess,pmode,_P_NOWAIT);
	if( pmode != _P_NOWAIT ){
		if( isWindowsCE() ){
			int code;
			code = _cwait(&status,(int)pinfo->hProcess,0);
			CloseHandle(pinfo->hProcess);
			CloseHandle(pinfo->hThread);
fprintf(stderr,"----WinCE xspawnvpe() %d ok=%X pid=%X/H%X wait=%x/%x DONE=%d\n",
__LINE__,(int)ok,(int)pid,(int)pinfo->hProcess,pmode,_P_NOWAIT,code);
		}
		/*
		_cwait(&status,(int)pinfo->hProcess,0);
		*/
	}
	return (int)pinfo->hProcess;
}
int spawnvp(int pmode,PCStr(path),const char *const av[])
{	const char *nav[MAX_ARGC]; /**/
	CStr(nab,MAX_ARGB);

	checkarg(path,av,elnumof(nav),nav,AVStr(nab));
	return spawnvpe(pmode,path,nav,environ);
}
int execvp(PCStr(path),const char *const av[])
{	const char *nav[MAX_ARGC]; /**/
	CStr(nab,MAX_ARGB);

	checkarg(path,av,elnumof(nav),nav,AVStr(nab));
	return _execvp(path,nav);
}
int execvx(PCStr(path),const char *const av[]){
	CStr(ab,MAX_ARGB);
	refQStr(ap,ab);
	const char *a1;
	int ai;
	int cflags = 0;
	int ok;
	STARTUPINFO stup;
	PROCESS_INFORMATION pinfo;
	HINSTANCE mod;

	for( ai = 0; a1 = av[ai]; ai++ ){
		if( ab < ap ){
			setVStrPtrInc(ap,' ');
		}
		strcpy(ap,a1);
		if( strpbrk(ap," \t") ){
			strsubst(AVStr(ap),"\"","\\\"");
			Strins(AVStr(ap),"\"");
			strcat(ap,"\"");
		}
		ap += strlen(ap);
	}
	if( 0 ){
		fprintf(stderr,"--- path: %s\n",path);
		fprintf(stderr,"--- args: %s\n",ab);
	}
	bzero(&stup,sizeof(stup));
	bzero(&pinfo,sizeof(pinfo));
	ok = CreateProcess(path,ab,NULL,NULL,1,cflags,NULL,NULL,&stup,&pinfo);
	LE("C CreateProcess(%s)=%d pid=%d %d",path,ok,pinfo.dwProcessId,GetLastError());

	if( ok ){
		int status;
		int pid = pinfo.dwProcessId;

fprintf(stderr,"----[%d] WAITING [%d]\n",getpid(),pid);
		/* wish free the main module and wait the child ... */
		mod = LoadLibrary(path);
		ok = FreeLibrary(mod);
		_cwait(&status,(int)pinfo.hProcess,0);
fprintf(stderr,"----[%d] WAITING [%d] exit(%d)\n",getpid(),pid,status);
		ExitProcess(0);
	}
	return -1;
}

int wait(int *statusp)
{	int pid;

	if( lSINGLEP() ){
		return -1;
	}
	LE("wait(%x) = ...",statusp);
	pid = wait3(NULL,0,NULL);
	LE("wait(%x) = %d",statusp,pid);
	return pid;
}
int getppid(){
	int ppid;
	HANDLE ph;

	ppid = MyProcEnv.p_ppid;
	if( ppid == 0 )
		return ppid;
	ph = OpenProcess(PROCESS_QUERY_INFORMATION,0,ppid);
	if( ph == NULL )
		return 0;
	CloseHandle(ph);
	LV("getppid() = %d",ppid);
	return ppid;
}
int setsid(){
	LT("setsid() = -1 (not supported)");
	return -1;
}

static int FinFin;
static int Finalized;
static int Terminated;
static int ServiceDone;

extern int InFinish;
void closepplog();
void closeNULLFP();

/* this is necessary before doing fcloseall() or deltmpfiles() */
void initWinCRT(){
	_set_invalid_parameter_handler(invalid_parameter_handler);
}

void DO_FINALIZE(int code){
	int fd,sock;

	if( FinFin ){
		return;
	}
	if( lISCHILD() ){
	}else
	LE("[%d] svc DO_FINALIZE %d %d",GetCurrentThreadId(),FinFin,Finalized);
	FinFin++;

	LV("PID=%d exit(%d) ...",getpid(),code);

	closepplog();
	closeNULLFP();
	if( isWindowsCE() ){
		fprintf(stderr,"-- NO fcloseall() %s:%d\n",__FILE__,__LINE__);
	}else
	fcloseall();
	/*
	killchildren();
	can be harmful?
	*/

	if( NO_SOCKOPEN )
	if( isWindowsCE() ){
	}else
	for( fd = 0; fd < MAXHANDLE; fd++ )
		if( sock = SOS_GetOsfh(fd) )
			closeSocket(fd,sock);

	if( isWindowsCE() ){
		fprintf(stderr,"-- NO deltmpfiles() %s:%d\n",__FILE__,__LINE__);
	}else
	deltmpfiles();
	_rmtmp();

	LV("PID=%d exit(%d)",getpid(),code);
	Finalized = 1;
}

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
const char *dlerror(void){
	return NULL;
}
void *dlopen(const char *path,int mode){
	void * dll;
	if( path == NULL ){
		dll = GetModuleHandle(NULL);
	}else
	dll = LoadLibrary(path);
	LV("DLL %X %s",dll,path);
	return dll;
}
void *dlsym(void *handle,const char *symbol){
	void *sym;
	sym = GetProcAddress((HMODULE)handle,symbol);
	return sym;
}
const char *sdlerror(void){
	return "(dl NOT SUPPORTED)";
}
int dlclose(void *handle){
	return FreeLibrary((HMODULE)handle);
}
#ifdef __cplusplus
}
#endif

int file_size(int);
int mysystemX(PCStr(path),const char *const *av,const char *const environ[],int timeout,HANDLE *php){
	HANDLE ph;
	unsigned long int xcode = ~0;
	int xph;
	int syncp[2]; /* a socket to detect the exit of the child */
	int nready;
	double Start,Lap1;
	double LastAct;
	int xerr;
	double elps;
	const char *nav[MAX_ARGC];
	CStr(nab,MAX_ARGB);

	Start = Time();
	socketpair(AF_INET,SOCK_STREAM,0,syncp);
	Lap1 = Time();

	/* should use CreateProcess() ? */
	/* should care "arg with space" ? */
	/*
	PROCESS_INFORMATION pinfo;
	int pid;
	if( xspawnvpe(_P_NOWAIT,path,av,environ,&pinfo) != -1 ){
		ph = pinfo.hProcess;
		pid = pinfo.dwProcessId;
	}
	*/
	checkarg(path,av,elnumof(nav),nav,AVStr(nab));
	av = nav;
	ph = (HANDLE)_spawnvpe(_P_NOWAIT,path,av,environ);

	xerr = GetLastError();
	elps = Time()-Start;
	close(syncp[1]);

	if( (int)ph <= 0 ){
		LE("msystem(%s) FAILED spawn xerr=%d [%.3f]",path,xerr,elps);
	}else
	if( GetExitCodeProcess(ph,&xcode) == 0 ){
		LE("msystem(%s) FAILED wait xerr=%d [%.3f]",path,xerr,elps);
	}else
	if( xcode != STILL_ACTIVE ){
		LE("msystem(%s) EARLY-EXIT xerr=%d [%.3f]",path,xerr,elps);
	}else{
		/* break a frozen child if no I/O is done by it. */
		int osiz,nsiz;
		int ooff,noff;
		int nwait;
		FTint oct,oxt,okt,out,nct,nxt,nkt,nut;

		GetProcessTimes(ph,&oct.ft,&oxt.ft,&okt.ft,&out.ft);
		ooff = lseek(0,0,1);
		osiz = file_size(1);
		LastAct = Time();
		for( nwait = 0; ; nwait++ ){
			nready = PollIn(syncp[0],timeout);
			GetExitCodeProcess(ph,&xcode);
			if( xcode != STILL_ACTIVE ){
				break;
			}
			nsiz = file_size(1);
			GetProcessTimes(ph,&nct.ft,&nxt.ft,&nkt.ft,&nut.ft);
			if( nsiz == osiz ){
				noff = lseek(0,0,1);
				if( noff == ooff ){

			LE("mysystemX(%s) NOIO %.2f %.2f %d/%d %d/%d %d/%d/%d",
			path,Time()-LastAct,Time()-Start,
			(int)okt.li/10000-(int)nkt.li/10000,okt.li!=nkt.li,
			(int)out.li/10000-(int)nut.li/10000,out.li!=nut.li,
			noff,nsiz,nwait
			);

					if( 60 < Time()-LastAct )
					if( okt.li == nkt.li )
					if( out.li == nut.li )
					break;
				}
				ooff = noff;
			}
			if( nsiz!=osiz || okt.li!=nkt.li || out.li!=nut.li ){
				LastAct = Time();
			}
			osiz = nsiz;
			okt = nkt;
			out = nut;
		}
		if( 0 < nwait ){
			GetProcessTimes(ph,&nct.ft,&nxt.ft,&nkt.ft,&nut.ft);
			LE("mysystemX(%s) DONE %.2f (%.2fu %.2fs) %d/%d/%d",
				path,Time()-Start,
				((int)(nut.li/10000))/1000.0,
				((int)(nkt.li/10000))/1000.0,
				lseek(0,0,1),file_size(1),nwait);
		}
	}
	close(syncp[0]);
	*php = ph;
	return xcode;
}
int mysystem(PCStr(path),const char *const *av,const char *const environ[]){
	int retry;
	HANDLE ph;
	int xcode;
	int rcode = -1;
	double Start;

	Start = Time();
	for( retry = 0; retry < 3; retry++ ){
		xcode = mysystemX(path,av,environ,15*1000,&ph);
		if( xcode != STILL_ACTIVE ){
			break;
		}
		TerminateProcess(ph,0);
		if( 0 < lseek(0,0,1) || 0 < lseek(1,0,1) ){
			break;
		}
	}
	if( xcode != STILL_ACTIVE )
		rcode = 0;
	if( retry ){
		LE("mysystem()=%d RETRY*%d in(%d) out(%d) [%.3f] %s",
			rcode,retry,lseek(0,0,1),lseek(1,0,1),
			Time()-Start,path);
	}
	return rcode;
}

int Send_file(int dpid,int fd,int closesrc,int inheritable){
	HANDLE sph,ioh,soh,dph,doh;
	int access = 0;
	int options = DUPLICATE_SAME_ACCESS;
	int ok;
	int desc;

	sph = SELF();
	soh = (HANDLE)_get_osfhandle(fd);

	dph = OpenProcess(PROCESS_ALL_ACCESS,0,dpid);
	if( closesrc )
		options |= DUPLICATE_CLOSE_SOURCE;
	doh = 0;
	ok = DuplicateHandle(sph,soh,dph,&doh,access,inheritable,options);
	LE("#### send_file (%d,%d)[%d,%d] -> %d[%d,%d] (%d,Err=%d)",
		getpid(),fd,sph,soh, dpid,dph,doh, ok,GetLastError());
	CloseHandle(dph);

	desc = (dpid << 16) | (0xFFFF & (int)doh);
	LE("#### file to be sent fd=%d -> %d %X %d",fd,doh,desc,desc);
	return desc;
}
int recv_file(int desc){
	int spid;
	HANDLE sph,soh,dph,doh;
	int access = 0;
	int inheritable = 1;
	int options = DUPLICATE_SAME_ACCESS;
	int ok;
	int fd;

	spid = 0xFFFF & (desc >> 16);
	soh = (HANDLE)(desc & 0xFFFF);
	sph = OpenProcess(PROCESS_ALL_ACCESS,0,spid);
	dph = SELF();
	doh = 0;
	ok = DuplicateHandle(sph,soh,dph,&doh,access,inheritable,options);

	fd = _open_osfhandle((int)doh,0);
	LE("#### recv_file %X pid=%d[%d],%d -> %d,%d (%d) fd=%d err=%d",
		desc,spid,sph,soh, dph,doh,ok, fd,GetLastError());
	return fd;
}

const char *ver_sendFd(){ return "sendFdW"; };
int sendFd(int sockfd,int fd,int pid){
	HANDLE sph,soh,dph,doh;
	int access = 0;
	int inheritable = 1;
	int options = DUPLICATE_SAME_ACCESS;
	int rcode = -1;
	int dpid;
	int rcc;
	int wcc;
	int ok;

	dpid = pid;
	sph = SELF();
	if( 0 <= SocketOf(fd) )
		soh = (HANDLE)SocketOf(fd);
	else	soh = (HANDLE)_get_osfhandle(fd);
	dph = OpenProcess(PROCESS_ALL_ACCESS,0,dpid);
	doh = 0;
	ok = DuplicateHandle(sph,soh,dph,&doh,access,inheritable,options);
	wcc = write(sockfd,&doh,sizeof(doh));
	LE("sendFd() %d:%d -> %d:%d",getpid(),soh,dpid,doh);
	return rcode;
}
int recvFd(int sockfd){
	int spid;
	int fd = -1;
	int rcc;
	int wcc;
	CStr(buf,128);
	HANDLE soh;

	spid = getpid();
	if( 0 < pollin(SocketOf(sockfd),3*1000) ){
		rcc = read(sockfd,&soh,sizeof(soh));
		if( rcc == sizeof(soh) ){
			if( ISSOCK((int)soh) )
				fd = openSocket(-1,(int)soh,0,"recvFd()");
			else	fd = _open_osfhandle((int)soh,0);
			LE("recvFd() %d/%d",soh,fd);
			return fd;
		}
	}
	LE("FAILED recvFd()");
	return fd;
}
#undef SocketOf
int SocketOf(int fd){
	return SocketOf_FL(__FILE__,__LINE__,fd);
}

#if 1400 <= _MSC_VER && !isWindowsCE()
#include <psapi.h>
BOOL DLL_GetProcessMemoryInfo(HANDLE p,PPROCESS_MEMORY_COUNTERS pmc,DWORD sz);
#define GetProcessMemoryInfo DLL_GetProcessMemoryInfo
#endif

int getrusage(int who,struct rusage *rusage){
	HANDLE cph;
	FTint ct,xt,kt,ut;

	bzero(rusage,sizeof(struct rusage));
	if( who == 0 ){
		GetProcessTimes(SELF(),&ct.ft,&xt.ft,&kt.ft,&ut.ft);
		rusage->ru_utime.tv_sec  =  ut.li / 10000000;
		rusage->ru_utime.tv_usec = (ut.li % 10000000) / 10;
		rusage->ru_stime.tv_sec  =  kt.li / 10000000;
		rusage->ru_stime.tv_usec = (kt.li % 10000000) / 10;

#if 1400 <= _MSC_VER && !isWindowsCE()
		PROCESS_MEMORY_COUNTERS pmc;
		GetProcessMemoryInfo(SELF(),&pmc,sizeof(pmc));
		rusage->ru_minflt = pmc.PageFaultCount;
		rusage->ru_majflt = pmc.PageFaultCount;
		rusage->ru_maxrss = pmc.PeakWorkingSetSize / 1024;
		rusage->ru_idrss  = pmc.WorkingSetSize / 1024;
#endif
	}else{
		rusage->ru_utime.tv_sec  =  ru_ut.li / 10000000;
		rusage->ru_utime.tv_usec = (ru_ut.li % 10000000) / 10;
		rusage->ru_stime.tv_sec  =  ru_st.li / 10000000;
		rusage->ru_stime.tv_usec = (ru_st.li % 10000000) / 10;
	}
	return 0;
}
#else
/*
int send_file(int dpid,int fd,int closesrc,int inheritable){ return -1; }
int recv_file(int desc){ return -1; }
*/
#endif

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
Program:	winserv.c (DeleGate Service)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970629	created
	061103	merged into windows.c
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"

int DELEGATE_PAUSE;
#define SVNAME "DeleGate"
extern const char *env_REGSERV;

#include <stdio.h>
#include <windows.h>
#include <winbase.h>
#include <winsvc.h>

#define winlog	syslog_ERROR
int regGetVec(PCStr(what),PCStr(servname),int ac,const char *av[]);
void regPutVec(PCStr(what),PCStr(servname),int ac,const char *av[]);
int regPutService(PCStr(servname),int ac,const char *av[]);

/*
extern int (*DELEGATE_MAIN)(int ac,const char *av[]);
*/
extern int (*DELEGATE_START)(int ac,const char *av[]);
extern void (*DELEGATE_TERMINATE)();

int file_is(int fd);
int FullpathOfExe(PVStr(path));

/* MAX_ARGC */
#include "config.h"

#if !isWindowsCE() /*{*/
static SERVICE_STATUS SvSt;
static SERVICE_STATUS_HANDLE SvStH;

#define SV_CREATE	1
#define SV_DELETE	2
#define SV_RESTART	4
#define SV_NOINTERACT	8

static VOID ServiceCtrlHandler(IN DWORD opcode)
{	DWORD status;
	const char *stat;

	switch( opcode ){
	case SERVICE_CONTROL_PAUSE:
		DELEGATE_PAUSE = 1;
		stat = "PAUSE";
		SvSt.dwCurrentState = SERVICE_PAUSED;
		break;
	case SERVICE_CONTROL_CONTINUE:
		DELEGATE_PAUSE = 0;
		stat = "CONTINUE";
		SvSt.dwCurrentState = SERVICE_RUNNING;
		break;
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		LE("[%d] svc Terminate...",GetCurrentThreadId());
		(*DELEGATE_TERMINATE)();
		if( opcode == SERVICE_CONTROL_SHUTDOWN )
		stat = "SHUTDOWN";
		else
		stat = "STOP";
		SvSt.dwWin32ExitCode = 0;
		SvSt.dwCurrentState = SERVICE_STOPPED;
		SvSt.dwCheckPoint = 0;
		SvSt.dwWaitHint = 0;
		SetServiceStatus(SvStH,&SvSt);
		winlog("SetStatus: %s\n",stat);
		LE("[%d] svc SetStatus: %s",GetCurrentThreadId(),stat);
		Terminated = 1;
		return;
	case SERVICE_CONTROL_INTERROGATE:
		stat = "INTERROGATE";
		break;
	default:
		stat = "UNKNOWN";
		break;
	}
	winlog("SetStatus: %s\n",stat);
	if( SetServiceStatus(SvStH,&SvSt) == 0 ){
		status = GetLastError();
		winlog("SetServiceStatus Error: %d\n",status);
	}
}
static int ServiceInitialization(DWORD argc, LPTSTR *argv, DWORD *specificError)
{
	argv;
	argc;
	specificError;
	return 0;
}

/*
int getServiceArgs(int argc,char *argv[],const char *av[]);
*/
int getServiceArgsX(int argc,char *argv[],const char *av[],int an);
#define getServiceArgs(argc,argv,av) getServiceArgsX(argc,argv,av,elnumof(av))
static DWORD service_argc;
static LPTSTR *service_argv;
void dumpSerivceArgs(){
	int ai;
	syslog_ERROR("svarg[%d]%X\n",service_argc,service_argv);
	for( ai = 0; ai < service_argc; ai++ ){
		syslog_ERROR("svarg[%d] %s\n",ai,service_argv[ai]);
	}
}
static VOID ServiceStart(DWORD argc, LPTSTR *argv)
{	DWORD status;
	DWORD specificError;
	int ac,ai;
	const char *av[MAX_ARGC]; /**/
	int rcode;

	winlog("[%d] svc ServiceStart()",GetCurrentThreadId());
	service_argc = argc;
	service_argv = argv;

	SvSt.dwServiceType = SERVICE_WIN32;
	SvSt.dwCurrentState = SERVICE_START_PENDING;
	SvSt.dwControlsAccepted = SERVICE_ACCEPT_STOP
				| SERVICE_ACCEPT_SHUTDOWN
				| SERVICE_ACCEPT_PAUSE_CONTINUE;
	SvSt.dwWin32ExitCode = 0;
	SvSt.dwServiceSpecificExitCode = 0;
	SvSt.dwCheckPoint = 0;
	SvSt.dwWaitHint = 0;

	winlog("RegisterServiceCtrlHandler\n");
	SvStH = RegisterServiceCtrlHandler(TEXT(SVNAME),(LPHANDLER_FUNCTION)ServiceCtrlHandler);
	if( SvStH == 0 ){
		winlog("RegisterServiceCtrlHandler: failed\n");
		return;
	}

	ac = getServiceArgs(argc,argv,av);
	if( ac <= 1 ){
		return;
	}
	winlog("Service Initialization\n");
	status = ServiceInitialization(argc,argv,&specificError);
	if( status != NO_ERROR ){
	winlog("Service Initialization: ERROR %d\n",status);
		SvSt.dwCurrentState  = SERVICE_STOPPED;
		SvSt.dwCheckPoint    = 0;
		SvSt.dwWaitHint      = 0;
		SvSt.dwWin32ExitCode = status;
		SvSt.dwServiceSpecificExitCode = specificError;
		SetServiceStatus(SvStH,&SvSt);
		exit(0);
	}

	SvSt.dwCurrentState  = SERVICE_RUNNING;
	SvSt.dwCheckPoint    = 0;
	SvSt.dwWaitHint      = 0;
	if( SetServiceStatus(SvStH,&SvSt) == 0 ){
	}

	winlog("Start DeleGate ...\n");
	rcode = (*DELEGATE_START)(ac,av);
	/*
	rcode = (*DELEGATE_MAIN)(ac,av);
	*/

	winlog("SetStatus: %s\n","STOPPED");
	LE("[%d] svc SetStatus: %s",GetCurrentThreadId(),"STOPPED");
	SvSt.dwCurrentState  = SERVICE_STOPPED;
	SetServiceStatus(SvStH,&SvSt);

	LE("[%d] svc ExitThread() from ServiceStart()",GetCurrentThreadId());
	ServiceDone = 1;
	ExitThread(0);
/*
	return rcode;
*/
}
static SERVICE_TABLE_ENTRY DispatchTable[] = {
	{ TEXT(SVNAME), (LPSERVICE_MAIN_FUNCTION)ServiceStart },
	{ NULL, NULL }
};


static void dumpService(LPQUERY_SERVICE_CONFIG conf,PCStr(servname))
{	const char *str;
	DWORD dwv;

	printf("SERVICE %s configuration:\n",servname);
	printf("Type: 0x%x\n",conf->dwServiceType);
	printf("Start Type: 0x%x\n",conf->dwStartType);
	printf("Err Control: 0x%x\n",conf->dwErrorControl);
	printf("Binary Path: %s\n",conf->lpBinaryPathName);
	if( str = conf->lpLoadOrderGroup )
		printf("Load order group: %s\n",str);
	if( dwv = conf->dwTagId )
		printf("Tag ID: %d\n",dwv);
	if( str = conf->lpDependencies )
		printf("Dependencies: %s\n",str);
	if( str = conf->lpServiceStartName )
		printf("Start Name: %s\n",str);
}

int restart_service(PCStr(port),int ac,const char *av[])
{	SC_HANDLE schSCManager;
	CStr(servname,128);
	const char *p;
	SERVICE_STATUS SvSt;
	SC_HANDLE schService;
	int ok;

	sprintf(servname,"%s-P%s",SVNAME,port);
	for( p = servname; *p; p++ )
		if( *p == ':' )
			*(char*)p = '.';

	schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if( schSCManager == NULL )
	winlog("RESTART: SCManager=%X, err=%d\n",schSCManager,GetLastError());

	schService = OpenService(schSCManager,servname,SERVICE_ALL_ACCESS);
	if( schService == NULL )
	winlog("RESTART: Service=%X err=%d\n",schService,GetLastError());

	ok = ControlService(schService,SERVICE_CONTROL_STOP,&SvSt);
	if( ok == 0 )
	winlog("RESTART: STOP=%d, err=%d\n",ok,GetLastError());

	ok = StartService(schService,ac,(LPCSTR*)av);

	if( ok == 0 )
	winlog("RESTART: START=%d, err=%d\n",ok,GetLastError());

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	winlog("RESTART %s: %s\n",ok?"OK":"ERR",servname);
	return ok;
}

int getpass1(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch));
int getcuser(PVStr(name),int size,PVStr(group),int gsiz);
static int getServiceUserPass(int ac,const char *av[],PVStr(us),PVStr(pa)){
	CStr(userb,128);
	CStr(passb,128);
	refQStr(pb,passb);
	IStr(ownerb,128);
	const char *owner;
	const char *un;
	const char *pw;

	owner = getMainArg("*","OWNER");
	if( owner == 0 ){ /* v9.9.10 mod-140626i set default OWNER */
	  const char *proto;
	  proto = getMainArg("*","SERVER");
	  if( proto && strneq(proto,"yysh",4) ){
		IStr(g,128);
		getcuser(AVStr(ownerb),sizeof(ownerb),AVStr(g),sizeof(g));
		if( *ownerb ){
		  owner = ownerb;
		  printf("## OWNER=%s by default for SEVER=yysh\n",owner);
		}
	  }
	}
	if( owner == 0 )
		return 0;

	fieldScan(owner,userb,passb);
	if( userb[0] == 0 ){
		if( un = getMainArg("*","USERNAME") ){
			strcpy(userb,un);
		}else{
			return 0;
		}
	}
	if( strchr(userb,'\\') == 0 ){
		Strins(AVStr(userb),".\\");
	}
	/*
	if( passb[0] == 0 )
	*/
	{
		/* password might be from MYPASS or AUTH or -Fauth ... */
		if( pw = getMainArg("*","PASS") )
			strcpy(passb,pw);
	}
	if( passb[0] == 0 ){
printf("//// NOTE: password can be given by PASS environ. variable.\n");
		printf("User(%s) Password: ",userb);
		fflush(stdout);
		/*
		tty_fgets(passb,sizeof(passb),stdin);
		*/
		getpass1(stdin,stdout,AVStr(passb),0,"*"); /* new-140626g */
		fprintf(stdout,"\r\n");
		fflush(stdout);
		if( pb = strpbrk(passb,"\r\n") )
			truncVStr(pb);
	}
	strcpy(us,userb);
	strcpy(pa,passb);
	printf("OWNER=%s\n",userb);
	return 1;
}

int putServiceArgs(PCStr(execpath),PCStr(servname),int ac,const char *av[]);
static int newServ(SC_HANDLE schSCManager,LPCTSTR servname,LPCTSTR dispname,LPCTSTR execpath,int ac,const char *av[],int ast)
{	SC_HANDLE schService;
	BOOL ok;
	SERVICE_STATUS SvSt;
	DWORD starttype;
	CStr(userb,128);
	CStr(passb,128);
	const char *user = NULL;
	const char *pass = NULL;
	int ntry;

	if( 0 < ast )
		starttype = SERVICE_AUTO_START;
	else	starttype = SERVICE_DEMAND_START;

	if( getServiceUserPass(ac,av,AVStr(userb),AVStr(passb)) ){
		user = userb;
		pass = passb;
	}

    for( ntry = 0; ntry < 10; ntry++ ){
	schService = CreateService(
		schSCManager,
		servname,
		dispname,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		starttype,
		SERVICE_ERROR_NORMAL,
		execpath,
		NULL,
		NULL,
		NULL,
		user,
		pass);

	if( schService != NULL )
		break;
	/* mod-140511a */
	printf("cannot create the service %s, retrying ...\n",servname);
	fflush(stdout);
	sleep(1);
    }

	if( putServiceArgs(execpath,servname,ac,av) < 0 ){
		printf("ERROR. Cannot put args to %s\n",servname);
		return 0;
	}
	if( schService == NULL ){
		printf("######## ");
		printf("ERROR. Cannot CREATE the service %s\n",servname);
		return 0;
	}
	printf("OK. The service is created successfully.\n");

	ok = StartService(schService,0,NULL);
	if( ok )
		printf("OK. The service started successfully.\n");
	else{
		DWORD status;
		IStr(err,128);

		status = GetLastError();
		sprintf(err,"%d",status);
		switch( status ){
			case ERROR_SERVICE_LOGON_FAILED:
				strcpy(err,"SERVICE_LOGIN_FAILED");
				break;
			case ERROR_ACCESS_DENIED:
				strcpy(err,"ACCESS_DENIED");
				break;
		}
		printf("######## ");
		printf("ERROR. The service failed to start (%s).\n",err);
		if( status == ERROR_ACCESS_DENIED ){
			printf("######## File: %s\n",execpath);
			printf("######## Hint: let it be executable by %s or\n",
				"SYSTEM/Administrators");
		}
		if( user == NULL && status == ERROR_ACCESS_DENIED ){
			const char *un;
			if( (un = getenv("USER")) == 0 )
			if( (un = getenv("USERNAME")) == 0 )
				un = "username";
			printf("######## Hint: retry with OWNER=%s\n",un);
		}
	}

	/* should check the status here */

	CloseServiceHandle(schService);
	return 1;
}
static int register_service(int ac,const char *av[],PCStr(servname))
{	CStr(ans,128);

	printf("Cannot open Service Control Manager.\n");
	printf("Select one of:\n");
	printf("  x - exit (do nothing)\n");
	printf("  f - execute in foreground\n");
	printf("  r - register as a service\n");
	printf(">> ");
	fflush(stdout);
	/*
	fgets(ans,sizeof(ans),stdin);
	*/
	tty_fgets(ans,sizeof(ans),stdin);
	if( ans[0] == 'x' )
		return -1;
	if( ans[0] == 'r' ){
		regPutService(servname,ac,av);
		return 1;
	}
	return 0;
}

void setupSTDIO1(){
	int ok;
	FILE *Fi;
	FILE *Fo;
	FILE *Fe;

	if( ok = AllocConsole() ){
	    if( Fi = fopen("CONIN$","r")  ){ close(fileno(stdin)); *stdin = *Fi; }
	    if( Fo = fopen("CONOUT$","w") ){ close(fileno(stdout)); *stdout = *Fo; }
	    if( Fe = fopen("CONOUT$","w") ){ close(fileno(stderr)); *stderr = *Fe; }
	}else{
	}
}
int validateLicense(PCStr(path),PCStr(date));
static int deletecreate_serv(int ac,const char *av[],PCStr(port),int svcop)
{	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	SERVICE_STATUS SvSt;
	CStr(servname,128);
	CStr(dispname,128);
	const char *p;
	CStr(yn,128);
	int running,ok;
	CStr(execpath,1024);
	CStr(param,256);
	int ast,ai;
	const char *env;

if( (svcop & SV_NOINTERACT) == 0 ){
 printf("=============================================================== Hints ====\r\n");
 printf("  You need to be Administrator to start DeleGate as a service.\r\n");
 printf("\r\n");
 printf("  You can modify the name of service by specifying tcp / udp explicitly:\r\n");
 printf("      -P[hostname:]port[.udp|.tcp]\r\n");
 printf("\r\n");
 printf("  You can define the whole name of the service with the following option:\r\n");
 printf("      SERVCONF=\"name:DeleGate Service Name\"\r\n");
 printf("\r\n");
 printf("  You can ommit the interactions with the following option:\r\n");
 printf("      SERVCONF=yesall   ... 'y' for all question by default\r\n");
 printf("      SERVCONF=auto     ... to select automatic service start\r\n");
 printf("      SERVCONF=demand   ... to select on demand service start\r\n");
 printf("\r\n");
 printf("  You can see the parameters of running DeleGate with \"regedit\" tool.\r\n");
 printf("      Be Administrator and see the registory shown bellow.\r\n");
 printf("      If necessary, you can edit the parameters with regedit then\r\n");
 printf("      restart the DeleGate service to use the parameters.\r\n");
 printf("==========================================================================\r\n");
}
fflush(stdout);

	if( env = getenv("SHLVL") ){ /* CYGWIN */
		/* maybe this was a workaround to do interaction at Cygwin console */
		if( isatty(0) ){
			/* v9.9.9 fix-140610h */
		}else
		setupSTDIO1();
	}
	strcpy(execpath,av[0]);
	if( !FullpathOfExe(AVStr(execpath)) ){
		printf("ERROR. Cannot get full-path of \"%s\"\n",av[0]);
		return 0;
	}
	av[0] = execpath;
	sprintf(dispname,"%s Server -P%s",SVNAME,port);
	if( p = strchr(dispname,'/') ) /* strip "/admin" extension */
		truncVStr(p);
	for( p = port; *p; p++ )
		if( *p == ':' )
			*(char*)p = '.';
	sprintf(servname,"%s-P%s",SVNAME,port);
	if( p = strchr(servname,'/') )
		truncVStr(p);

	for( ai = 0; ai < ac; ai++ ){
		if( strncaseeq(av[ai],"SERVCONF=",9) ){ /* v9.9.9 new-140608c */
			const char *conf;
			const char *np;
			IStr(name,256);

			conf = av[ai]+9;
			if( np = strstr(conf,"name:") ){
				Xsscanf(np+5,"%[^,]",AVStr(dispname));
				strcpy(servname,dispname);
				strsubst(AVStr(servname),"/",".");
				strsubst(AVStr(servname),":","..");
			}
			if( isinListX(conf,"yesall","c") ){
				svcop |= SV_NOINTERACT;
			}
		}
	}

	schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if( schSCManager == NULL ){
		switch( GetLastError() ){
		case ERROR_CALL_NOT_IMPLEMENTED:
			if( getenv(env_REGSERV) )
			if( register_service(ac,av,servname) )
				exit(0);
			break;
		case ERROR_DATABASE_DOES_NOT_EXIST:
			printf("SCM - database does not exist.\n");
			break;
		case ERROR_ACCESS_DENIED:
	printf("---- ");
	printf("Tried to start as a service [%s], but failed.\n",dispname);
	/*
	printf("You must login as \"Administrator\"\n");
	new-140511b kindly expalin how to run under Administrator's right
	*/
	printf("---- Now your DeleGate is running as a foreground process.\n");
  printf("#### Hint: You need to invoke DeleGate (to be a service) from\n");
  printf("#### a Command prompt window under Administrator's right.\n");
  printf("#### A way to make such a window is logging in as Administrator.\n");
  printf("#### Another way, if you are a user with Administrator's right,\n");
  printf("#### is doing right-click 'Command prompt' icon and then click\n");
  printf("#### 'Run as administrator'. You can find the icon at\n");
  printf("#### 'C:\\Windows\\system32\\cmd(.exe)' Copying the cmd.exe to the\n");
  printf("#### directory where DeleGate's executable is and then click it\n");
  printf("#### will ease working with the DeleGate in the window.\n");
  printf("#### See: http://technet.microsoft.com/library/cc947813.aspx\n");
  printf("#### If you need Cygwin Terminal, right-click 'Cygwin Terminal'\n");
  printf("#### icon then click 'Run as administrator' in the same way.\n");
  printf("#### Try win32-dg.exe instead of dg.exe if you have a problem\n");
  printf("#### in the console interaction with DeleGate.\n");
			putenv("SVPROTO="); /* for setting HOME in netsh.c */
			break;
		case ERROR_INVALID_PARAMETER:
			printf("INVALID parameter to OpenSCManager()\n");
			break;
		}
		return 0;
	}

	if( svcop & SV_CREATE )
	printf("Trying to start as a service [%s] ...\n",dispname);
	fflush(stdout);

	schService = OpenService(schSCManager,servname,SERVICE_QUERY_CONFIG);
	if( schService == NULL )
	{
		if( (svcop & SV_CREATE) == 0 )
			return 0;
		goto NEW;
	}

/*
	LPQUERY_SERVICE_CONFIG conf;
	DWORD dwBytesNeeded;

	conf = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR,4096);
	if( QueryServiceConfig(schService,conf,4096,&dwBytesNeeded) )
		dumpService(conf,servname);
	else	printf("ERROR. Cannot query config: %s\n",dispname);
	LocalFree(conf);
*/
	CloseServiceHandle(schService);

	schService = OpenService(schSCManager,servname,SERVICE_STOP|DELETE);
	if( schService == NULL ){
		printf("ERROR. Cannot STOP/DELETE the service.\n");
		exit(0);
	}

	if( (svcop & SV_NOINTERACT) == 0 ){
	printf("The service `%s' exists.  Delete it ? [y] / n : ",dispname);
	fflush(stdout);
	/*
	fgets(yn,sizeof(yn),stdin);
	*/
	tty_fgets(yn,sizeof(yn),stdin);
	if( yn[0] == 'n' || yn[0] == 'N' )
		exit(0);
	}

	if( ControlService(schService,SERVICE_CONTROL_STOP,&SvSt) )
		printf("OK. STOPped the previous service.\n");

	ok = DeleteService(schService);
	if( !ok ){
		printf("ERROR: DeleteService() %d\n",GetLastError());
	}
	CloseServiceHandle(schService);
	if( !ok ){
		printf("ERROR. Could not DELETE the service.\n");
		exit(0);
	}
	printf("OK. DELETEd the previous service.\n");
	fflush(stdout);

	if( (svcop & SV_CREATE) == 0 )
		return 1;

	if( (svcop & SV_NOINTERACT) == 0 ){
	printf("Create a new service ? [y] / n : ");
	fflush(stdout);
	/*
	fgets(yn,sizeof(yn),stdin);
	*/
	tty_fgets(yn,sizeof(yn),stdin);
	if( yn[0] == 'n' || yn[0] == 'N' )
		exit(0);
	}

	sleep(1); /* to make sure the deletion from the service DB ... */

NEW:
	if( validateLicense(av[0],__DATE__) != 0 ){
		return 0;
	}
	ast = 0;
	if( env = getMainArg("*","SERVCONF") ){
		if( isinListX(env,"auto","c") )
			ast = 1;
		if( isinListX(env,"demand","c") )
			ast = -1;
	}
	if( env = getenv("SERVCONF") ){
		if( strcasecmp(env,"auto") == 0 )
			ast = 1;
		if( strcasecmp(env,"demand") == 0 )
			ast = -1;
	}
	for( ai = 0; ai < ac; ai++ ){
		if( strcasecmp(av[ai],"SERVCONF=auto") == 0 )
			ast = 1;
		if( strcasecmp(av[ai],"SERVCONF=demand") == 0 )
			ast = -1;
	}
	if( ast == 0 )
	if( (svcop & SV_NOINTERACT) == 0 )
	{
		printf("Set Automatic Start on System Startup ? [y] / n : ");
		fflush(stdout);
		/*
		fgets(yn,sizeof(yn),stdin);
		*/
		tty_fgets(yn,sizeof(yn),stdin);
		if( yn[0] == 'n' || yn[0] == 'N' )
			ast = -1;
		else	ast = 1;
	}
	if( ast == 0 )
		ast = 1;

	ok = newServ(schSCManager,servname,dispname,execpath,ac,av,ast);
	return ok;
}

static int at_command_prompt()
{
	if( RunningAsService ){
		fprintf(stderr,"----[%d] RunningAsService %X [%d %d %d]\n",
			getpid(),file_is(0),file_is(1),file_is(2));
		return 0;
	}
	/* [0] might be directed to the NUL device and
	 * [1][2] might be redirected to STDOUTLOG
	 */
	return file_is(0) && file_is(1) && file_is(2);
}

int start_service(int ac,const char *av[])
{	int ai;

	for( ai = 0; ai < ac; ai++ )
		if( strcmp(av[ai],"-SERVICE") == 0 )
			goto START;

	if( isWindows95() ) /* may be on Win95 */
		return 0;
	if( ac != 1 )
		return 0;
	if( at_command_prompt() )
		return 0;

START:
	LE("[%d] svc start_service()",GetCurrentThreadId());
	winlog("StartServiceCtrlDispatcher\n");
	if( StartServiceCtrlDispatcher(DispatchTable) == 0 ){
		/* SvcDebugOut("[DeleGate] cannot start.\n"); */
		if( at_command_prompt() )
			printf("Cannot start ServiceCtrlDispatcher\n");
	}

	if( ServiceDone == 0 ){
		int fi;
		for( fi = 0; fi < 30 && !ServiceDone; fi++ ){
	LE("[%d] svc start_service() waiting (%d,%d,%d)",GetCurrentThreadId(),
				Terminated,ServiceDone,Finalized);
			usleep(100000);
		}
	}
	LE("[%d] svc start_service() done (%d,%d,%d)",GetCurrentThreadId(),
		Terminated,ServiceDone,Finalized);
	return 1;
}
int delete_service(int ac,const char *av[],PCStr(port),PCStr(arg))
{
	if( strcasecmp(arg,"-hup") == 0 ){
		return restart_service(port,ac,av);
	}else	return deletecreate_serv(ac,av,port,SV_DELETE|SV_NOINTERACT);
}
int create_service(int ac,const char *av[],PCStr(port))
{	int ai;
	const char *env = 0;

	if( ac <= 1 )
		return 0;

	if( env = getenv("REMOTE_ADDR") ){
		syslog_ERROR("---- creating service remotely: %s\n",env?env:"");
	}else
	if( !at_command_prompt() )
		return 0;

	for( ai = 0; ai < ac; ai++ )
		if( strcmp(av[ai],"-SERVICE") == 0 )
			return 0;

	if( deletecreate_serv(ac,av,port,SV_CREATE) )
	{
		return 1;
		exit(0);
	}
	return 0;
}
#endif /*} WindowsCE */
/*
#endif
*/


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
Program:	winreg.c (Windows Registry Access)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	980630	extracted from winserv.c
	061103	merged into windows.c
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"

#ifdef _MSC_VER
#if !isWindowsCE() /*{*/

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winbase.h>

const char *env_REGSERV = "REGSERV";

#define SERVICE_REG  "SYSTEM\\CurrentControlSet\\Services"
#define OSERVICE_REG "Software\\Microsoft\\Windows\\CurrentVersion"

void regPutStr(PCStr(what),PCStr(servname),PCStr(value)){
	IStr(rkey,1024);
	LONG res;
	HKEY hkey = 0;
	DWORD disp = 0;

	sprintf(rkey,"%s\\%s",SERVICE_REG,servname);
	res = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		rkey,
		0,
		"",
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hkey,
		&disp);

	res = RegSetValueEx(
		hkey,
		what,
		0,
		REG_SZ,
		(unsigned const char*)value,
		strlen(value)+1
	);
	RegCloseKey(hkey);

	if( res == 0 ){
		printf("OK. %s is saved in registry:\r\n\"%s\\%s\"\n",
			what,"HKEY_LOCAL_MACHINE",rkey);
	}else{
	}

}
void regPutVec(PCStr(what),PCStr(servname),int ac,const char *av[])
{	HKEY hkey;
	DWORD disp;
	LONG res;
	CStr(rkey,1024);
	CStr(args,0x2000);
	refQStr(ap,args); /**/
	int ai;

	sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,servname,what);
	res = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		rkey,
		0,
		"",
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hkey,
		&disp);

	for(ai = 0; ai < ac; ai++){
		strcpy(ap,av[ai]);
		ap += strlen(ap) + 1;
	}
	setVStrPtrInc(ap,0);

	res = RegSetValueEx(
		hkey,
		"ARGV",
		0,
		REG_MULTI_SZ,
		(unsigned const char*)args, ap-args);

	if( res != 0 ){
		printf("ERROR. Cannot set registry: %s\r\n",av[ai]);
		exit(0);
	}

	printf("OK. %s are saved in registry:\r\n\"%s\\%s\"\n",
		what,"HKEY_LOCAL_MACHINE",rkey);

	RegCloseKey(hkey);
}
int regGetVec(PCStr(what),PCStr(servname),int mac,const char *av[])
{	HKEY hkey;
	CStr(rkey,1024);
	IStr(argb,0x2000);
	defQStr(args); /*alloc*//**/
	const char *ap;
	int bi;
	unsigned int long type,len;
	int res;
	int nac;

	sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,servname,what);
	res = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		rkey,
		0,
		KEY_QUERY_VALUE,
		&hkey);

	if( res != ERROR_SUCCESS ){
		av[0] = 0;
		return 0;
	}
		
	type = REG_MULTI_SZ;
	len = sizeof(argb);
	res = RegQueryValueEx(
		hkey,
		"ARGV",
		NULL,
		&type,
		(unsigned char*)argb,
		&len);

	setQStr(args,(char*)malloc(len),len);
	Bcopy(argb,args,len);

	nac = 0;
	for( ap = args; *ap; ap++ ){
		if( mac-1 <= nac ){
			break;
		}
		av[nac++] = (char*)ap;
		ap += strlen(ap);
/* ap += strlen(ap) + 1 ??? */
	}
	av[nac] = 0;

	RegCloseKey(hkey);
	return nac;
}
int regDelVec(PCStr(what),PCStr(servname)){
	HKEY hkey;
	CStr(rkey,1024);
	int res;

	sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,servname,what);
	/*
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_QUERY_VALUE,&hkey);
	res = RegDeleteValue(hkey,"ARGV");
	RegCloseKey(hkey);
	*/
	res = RegDeleteKey(HKEY_LOCAL_MACHINE,rkey);
	return res;
}
int regPutService(PCStr(servname),int ac,const char *av[])
{	CStr(rkey,1024);
	HKEY hkey;
	LONG res;
	DWORD disp;
	const char *a1;
	CStr(args,2048);
	refQStr(ap,args); /**/
	int ai;
	unsigned long int type,len;
	unsigned char value[2048]; /**/
	CStr(yn,128);
	const char *rstype;

	if( (rstype = getenv(env_REGSERV)) == NULL )
		rstype = "once";
	if( strcaseeq(rstype,"once") )
		sprintf(rkey,"%s\\RunServicesOnce",OSERVICE_REG);
	else	sprintf(rkey,"%s\\RunServices",OSERVICE_REG);
	printf("Registry: HKEY_LOCAL_MACHINE\\%s\r\n",rkey);

	res = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		rkey,
		0,
		"",
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&hkey,
		&disp);

	if( res != ERROR_SUCCESS ){
		printf("ERROR: cannot open the registry\r\n");
		return -1;
	}

	len = sizeof(value);
	res = RegQueryValueEx(hkey,servname,NULL,&type,value,&len);
	if( res == ERROR_SUCCESS ){
		printf("Serivce exists: %s = %s\n",servname,value);
		printf("Remove it ? [y] / n : ");
		fflush(stdout);
		/*
		fgets(yn,sizeof(yn),stdin);
		*/
		tty_fgets(yn,sizeof(yn),stdin);
		if( yn[0] != 'y' && yn[0] != '\r' && yn[0] != '\n' )
			goto EXIT;
		RegDeleteValue(hkey,servname);
		printf("Register new service ? [y] / n : ");
		fflush(stdout);
		/*
		fgets(yn,sizeof(yn),stdin);
		*/
		tty_fgets(yn,sizeof(yn),stdin);
		if( yn[0] != 'y' && yn[0] != '\r' && yn[0] != '\n' )
			goto EXIT;
	}

	ap = args;
	for( ai = 0; ai < ac; ai++ ){
		if( 0 < ai )
			setVStrPtrInc(ap,' ');
		a1 = av[ai];
		if( strpbrk(a1," \t") && strchr(a1,'"') == NULL )
			sprintf(ap,"\"%s\"",a1);
		else	strcpy(ap,a1);
		ap += strlen(ap);
	}
	strcpy(ap," -SERVICE");

	res = RegSetValueEx(
		hkey,
		servname,
		0,
		REG_SZ,
		(unsigned char*)args, strlen(args));
	printf("Registered new serivce: %s = %s\r\n",servname,args);
	printf("Reboot the system to enable this service.\r\n");

EXIT:
	RegCloseKey(hkey);
	return 0;
}

static int scanregdir(PVStr(rkey),PVStr(buf),PVStr(where));
static void getresconfX(HKEY hkey,PCStr(skey),PVStr(where),PVStr(buf));
#define getresconf(hkey,buf)	getresconfX(hkey,rkey,BVStr(where),BVStr(buf))

int regGetResolvConf(PVStr(buf),PVStr(where))
{	HKEY hkey;
	CStr(rkey,1024);
	LONG res;

	setVStrEnd(buf,0);
	setVStrEnd(where,0);
	sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,"Tcpip","Parameters");

	{	refQStr(tp,rkey); /**/
		tp = rkey + strlen(rkey);
		strcpy(tp,"\\Transient"); /* Win2K and later ? */
		res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, rkey, 0,
			KEY_QUERY_VALUE, &hkey);
		if( res == ERROR_SUCCESS ){
			getresconf(hkey,buf);
			RegCloseKey(hkey);
		}
		setVStrEnd(tp,0);
	}

	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, rkey, 0,
		KEY_QUERY_VALUE, &hkey);

	if( res != ERROR_SUCCESS ){
		sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,"VxD","MSTCP");
		res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, rkey, 0,
			KEY_QUERY_VALUE, &hkey);
		if( res != ERROR_SUCCESS )
			return -1;
	}


	getresconf(hkey,buf);
	RegCloseKey(hkey);

	if( buf[0] != 0 )
		return 0;

	sprintf(rkey,"%s\\%s\\%s",SERVICE_REG,"Tcpip","Parameters");
	strcat(rkey,"\\Interfaces");
	scanregdir(AVStr(rkey),AVStr(buf),AVStr(where));
	return 0;
}
static int scanregdir(PVStr(rkey),PVStr(buf),PVStr(where))
{	HKEY hkey,hkey1;
	refQStr(tp,rkey); /**/
	CStr(skey,256);
	DWORD ksize;
	FILETIME mtime;
	DWORD ski;
	LONG res;

	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, rkey, 0,
		KEY_ENUMERATE_SUB_KEYS, &hkey);
	if( res != ERROR_SUCCESS )
		return -1;
	tp = rkey + strlen(rkey);

	for( ski = 0; ski < 20; ski++ ){
		ksize = sizeof(skey);
		skey[0] = 0;
		res = RegEnumKeyEx(hkey,ski,skey,&ksize,NULL,NULL,NULL,&mtime);
		if( res != ERROR_SUCCESS )
			break;
		sprintf(tp,"\\%s",skey);
		res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, rkey, 0,
			KEY_QUERY_VALUE, &hkey1);
		if( res == ERROR_SUCCESS ){
			getresconf(hkey1,buf);
			RegCloseKey(hkey1);
		}
	}
	RegCloseKey(hkey);
	return 0;
}
#endif /*} !WindowsCE */

#if isWindowsCE()
LONG RegOpenKeyExX(HKEY hk,const char *nm,DWORD rs,REGSAM sa,PHKEY pk);
LONG RegEnumKeyExX(HKEY hk,int ix,const char *nm,LPDWORD nz,LPDWORD rs,
        const char *cn,LPDWORD cz,FILETIME *ft);
LONG RegSetValueExX(HKEY hk,const char *vn,DWORD rs,DWORD ty,
	const LPBYTE dt,DWORD dz);
#undef RegOpenKeyEx
#define RegOpenKeyEx RegOpenKeyExX
#undef RegEnumKeyEx
#define RegEnumKeyEx RegEnumKeyExX
#undef RegSetValueEx
#define RegSetValueEx RegSetValueExX
#endif

int regGetStorageCard1(PVStr(cardpath),HKEY hroot,PCStr(key),PCStr(val)){
	int res;
	IStr(rkey,256);
	HKEY hkey;
	unsigned char card[64];
	unsigned long int len,type;

	strcpy(rkey,key);
	res = RegOpenKeyEx(hroot,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(cardpath,"?No Key?%s",rkey);
		return -1;
	}
	len = sizeof(card);
	res = RegQueryValueEx(hkey,val,NULL,&type,card,&len);
	RegCloseKey(hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(cardpath,"?No Card?");
		return -1;
	}
	sprintf(cardpath,"%s",card);
	strsubst(BVStr(cardpath),"\\","/");
	if( streq(cardpath,"/") ){
		sprintf(cardpath,"?Root?");
		return -1;
	}
	if( *cardpath != '/' ){
		Strins(BVStr(cardpath),"/");
	}
	return 0;
}
int regGetStorageCard(PVStr(cardpath)){
	if( regGetStorageCard1(BVStr(cardpath),HKEY_CURRENT_USER,
	"Software\\Microsoft\\File Explorer","StorageCardPath") == 0 )
	{
		refQStr(dp,cardpath);
		if( cardpath[0] )
		if( dp = strchr(cardpath+1,'/') ){
			truncVStr(dp);
		}
		return 0;
	}
	/*
the last directory of the download on WinCE4.2
to be used to make the full-path of ExecFile
	if( regGetStorageCard1(BVStr(cardpath),HKEY_CURRENT_USER,
	"Software\\Microsoft\\Internet Explorer","Download Directory") == 0 )
		return 0;
	*/
	if( regGetStorageCard1(BVStr(cardpath),HKEY_LOCAL_MACHINE,
	"System\\StorageManager\\Profiles\\SDMemory","Folder") == 0 )
		return 0;
	return -1;
}
int regGetActsync(PVStr(hosts)){
	int res;
	IStr(rkey,256);
	HKEY hkey;
	unsigned char addr[64];
	unsigned long int len,type;
	IStr(adpt,128);

	sprintf(rkey,"Comm\\%s","DTPT");
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		return -1;
	}
	len = sizeof(addr);
	res = RegQueryValueEx(hkey,"ADAPTER_NAME",NULL,&type,addr,&len);
	if( res == ERROR_SUCCESS ){
		strcpy(adpt,(char*)addr);
	}
	len = sizeof(addr);
	res = RegQueryValueEx(hkey,"DTPTSRV_ADDR",NULL,&type,addr,&len);
	RegCloseKey(hkey);
	if( res != ERROR_SUCCESS ){
		return -1;
	}
	sprintf(hosts,"%s (%s %s) ",addr,adpt,"ActiveSync");
	return 0;
}
int regGetHostA(PCStr(wh),PCStr(adap),PCStr(typ),PVStr(hosts),int actonly){
	int res;
	IStr(rkey,256);
	HKEY hkey;
	unsigned char addr[64];
	unsigned long int len,type;

	sprintf(rkey,"Comm\\%s\\Parms\\TCPIP",adap);
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(hosts,"No TCPIP Param (%s%s) ",wh,typ);
		return -1;
	}
	len = sizeof(addr);
	res = RegQueryValueEx(hkey,"IpAddress",NULL,&type,addr,&len);
	RegCloseKey(hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(hosts,"No IpAddress (%s%s) ",wh,typ);
		return -1;
	}
	if( actonly && streq((char*)addr,"0.0.0.0") ){
		return -1;
	}
	sprintf(hosts,"%s (%s%s) ",addr,adap,typ);
	return 0;
}
#define CONNSTAT_REG  "System\\State\\Connections"
int regGetConns(PCStr(wh),PVStr(adps)){
	refQStr(hp,adps);
	IStr(rkey,256);
	int res;
	HKEY hkey;
	unsigned char adap[256];
	unsigned long int len,type;

	clearVStr(adps);
	sprintf(rkey,"%s\\%s",CONNSTAT_REG,wh);
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		Rsprintf(hp,"No Adapter State (%s) ",wh);
		return -1;
	}
	len = sizeof(adap);
	res = RegQueryValueEx(hkey,"Adapters",NULL,&type,adap,&len);
	RegCloseKey(hkey);
	if( res != ERROR_SUCCESS ){
		Rsprintf(hp,"No Adapter value (%s) ",wh);
		return -1;
	}
	strcpy(adps,(char*)adap);
	return 0;
}

typedef struct {
	HKEY  ra_hroot;
  const char *ra_sroot;
	FILE *ra_out;
	FILE *ra_err;
  const char *ra_fmt;
} RegArg;
#ifdef UNDER_CE
#undef ferror
#define ferror(fp) XX_ferror(FL_ARG,fp)
#endif
static void dumpmsz(FILE *out,const unsigned char *value,int len){
	const unsigned char *up;
	fprintf(out,"{");
	for( up = value; *up; up++ ){
		if( fprintf(out,"%s'%s'",up==value?"":" ",up) <= 0 ){
			break;
		}
		for(; *up; up++ ){
		}
	}
	fprintf(out,"}");
}
static void dumpbin(FILE *out,const unsigned char *value,int len){
	int bi;
	for( bi = 0; bi < len && bi < 16; bi++ ){
		if( fprintf(out,"%s%02X",0<bi?" ":"",value[bi]) <= 0 )
			break;
	}
	if(bi < len)
		fprintf(out," ...");
	fprintf(out," [%d]",len);
}
static int dumpregval(RegArg *Ra,HKEY hkey,PCStr(rkey)){
	int res;
	unsigned long int type,len;
	unsigned char value[1024];
	unsigned char *iv = value;
	unsigned int ival;
	CStr(sval,1024);
	DWORD svsz;
	int svi;
	FILE *out = Ra->ra_out;
	int rcode = 0;

	for( svi = 0; ; svi++ ){
		if( ferror(out) )
			break;
		sval[0] = 0;
		svsz = sizeof(sval);
		type = REG_SZ;
		len = sizeof(value);
		res = RegEnumValue(hkey,svi,sval,&svsz,0,&type,value,&len);
		if( res != ERROR_SUCCESS ){
			if( res == ERROR_NO_MORE_ITEMS ){
			}else
			if( res == ERROR_ACCESS_DENIED ){
			}else
			if( res == ERROR_MORE_DATA ){
fprintf(out,"--errM=%d [%d] %s\n",res,svi,sval);
			}else{
fprintf(out,"--errV=%d [%d] %s\n",res,svi,sval);
			}
			break;
		}
		fprintf(out," %s = ",sval);
		switch( type ){
			case REG_BINARY:
				dumpbin(out,value,len);
				break;
			case REG_DWORD_LITTLE_ENDIAN:
				ival = (iv[3]<<24)|(iv[2]<<16)|(iv[1]<<8)|iv[0];
				fprintf(out,"0x%X (%d)",ival,ival);
				break;
			case REG_DWORD_BIG_ENDIAN:
				ival = (iv[0]<<24)|(iv[1]<<16)|(iv[2]<<8)|iv[3];
				fprintf(out,"0x%X (%d)",ival,ival);
				break;
			case REG_SZ:
				fprintf(out,"'%s'",value);
				break;
			case REG_MULTI_SZ:
				dumpmsz(out,value,len);
				break;
			default:
				fprintf(out,"<type=%d>",type);
				dumpbin(out,value,len);
				break;
		}
		if( fprintf(out,"\n") <= 0 ){
			rcode = -2;
			break;
		}
	}
	return rcode;
}
static int scanregdirR(RegArg *Ra,PVStr(rkey)){
	HKEY hkey;
	refQStr(tp,rkey);
	CStr(skey,256);
	DWORD sksz;
	FILETIME mtime;
	DWORD ski;
	LONG res;
	int rcode = 0;

	if( ferror(Ra->ra_out) ){
		return -2;
	}
	res = RegOpenKeyEx(Ra->ra_hroot,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		if( res == ERROR_ACCESS_DENIED ){
		}else{
fprintf(Ra->ra_err,"--errK=%d %s\\%s\n",res,Ra->ra_sroot,rkey);
		}
		return -1;
	}
	tp = rkey + strlen(rkey);
	if( fprintf(Ra->ra_out,"%s\\%s\n",Ra->ra_sroot,rkey) <= 0 ){
		rcode = -2;
		goto EXIT;
	}
	dumpregval(Ra,hkey,rkey);

	for( ski = 0; ; ski++ ){
		sksz = sizeof(skey);
		skey[0] = 0;
		res = RegEnumKeyEx(hkey,ski,skey,&sksz,NULL,NULL,NULL,&mtime);
		if( res != ERROR_SUCCESS ){
			if( res == ERROR_NO_MORE_ITEMS ){
			}else
			if( res == ERROR_ACCESS_DENIED ){
			}else{
fprintf(Ra->ra_err,"--errE=%d %s\\%s\n",res,Ra->ra_sroot,rkey);
			}
			break;
		}
		if( tp == rkey )
			sprintf(tp,"%s",skey);
		else	sprintf(tp,"\\%s",skey);
		rcode = scanregdirR(Ra,BVStr(rkey));
		clearVStr(tp);
		if( rcode == -2 ){
			break;
		}
	}
EXIT:
	RegCloseKey(hkey);
	return rcode;
}

int regGetRasBook(PVStr(books)){
	refQStr(bp,books);
	int res;
	HKEY hkey;
	int ski;
	CStr(skey,128);
	DWORD sksz;
	FILETIME mtime;

	res = RegOpenKeyEx(HKEY_CURRENT_USER,"\\Comm\\RasBook",0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS )
		return -1;
	for( ski = 0; ; ski++ ){
		sksz = sizeof(skey);
		clearVStr(skey);
		res = RegEnumKeyEx(hkey,ski,skey,&sksz,NULL,NULL,NULL,&mtime);
		if( res != ERROR_SUCCESS )
			break;
		Rsprintf(bp,skey);
		setVStrPtrInc(bp,0);
	}
	setVStrPtrInc(bp,0);
	RegCloseKey(hkey);
	return ski;
}
int regGetHostY(PVStr(hosts),PCStr(conns),int actonly){
	refQStr(hp,hosts);
	IStr(rkey,512);
	HKEY hkey;
	int res;
	int ski;
	CStr(skey,128);
	DWORD sksz;
	FILETIME mtime;
	const char *typ;

	strcpy(rkey,"Comm");
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS )
		return -1;

	for( ski = 0; ; ski++ ){
		sksz = sizeof(skey);
		clearVStr(skey);
		res = RegEnumKeyEx(hkey,ski,skey,&sksz,NULL,NULL,NULL,&mtime);
		if( res != ERROR_SUCCESS )
			break;
		if( conns && isinList(conns,skey) )
			typ = "*";
		else	typ = "";
		if( regGetHostA(skey,skey,typ,AVStr(hp),1) == 0 ){
			hp += strlen(hp);
		}else{
			clearVStr(hp);
		}
	}
	RegCloseKey(hkey);
	if( hosts < hp ){
		return 0;
	}
	return -1;
}
int regGetHosts(PVStr(hosts)){
	IStr(adps,256);
	refQStr(hp,hosts);
	IStr(host1,128);
	int actonly;

	if( regGetConns("Network",AVStr(adps)) == 0 ){
		actonly = 1;
	}else{
		actonly = 0;
	}
	regGetHostY(AVStr(hp),adps,actonly);
	hp += strlen(hp);
	regGetActsync(AVStr(hp));
	return 0;
}

int regdump_main(int ac,const char *av[],FILE *out,FILE *err){
	IStr(rkey,512);
	const char *fmt;
	RegArg Ra;

	Ra.ra_out = out;
	Ra.ra_err = err;
	Ra.ra_fmt = "";

	if( ferror(out) ) return 0;
	fprintf(out,"%X %s\n",HKEY_LOCAL_MACHINE,"HKEY_LOCAL_MACHINE");
	Ra.ra_hroot = HKEY_LOCAL_MACHINE;
	Ra.ra_sroot = "HKEY_LOCAL_MACHINE";
	clearVStr(rkey); scanregdirR(&Ra,AVStr(rkey));

	if( ferror(out) ) return 0;
	fprintf(out,"%X %s\n",HKEY_CURRENT_USER,"HKEY_CURRENT_USER");
	Ra.ra_hroot = HKEY_CURRENT_USER;
	Ra.ra_sroot = "HKEY_CURRENT_USER";
	clearVStr(rkey); scanregdirR(&Ra,AVStr(rkey));

	if( ferror(out) ) return 0;
	fprintf(out,"%X %s\n",HKEY_USERS,"HKEY_USERS");
	Ra.ra_hroot = HKEY_USERS;
	Ra.ra_sroot = "HKEY_USERS";
	clearVStr(rkey); scanregdirR(&Ra,AVStr(rkey));

	/*
	fprintf(out,"%X %s\n",HKEY_CURRENT_CONFIG,"HKEY_CURRENT_CONFIG");
	Ra.ra_hroot = HKEY_CURRENT_CONFIG;
	Ra.ra_sroot = "HKEY_CURRENT_CONFIG";
	clearVStr(rkey); scanregdirR(&Ra,AVStr(rkey));
	*/

	if( ferror(out) ) return 0;
	fprintf(out,"%X %s\n",HKEY_CLASSES_ROOT,"HKEY_CLASSES_ROOT");
	Ra.ra_hroot = HKEY_CLASSES_ROOT;
	Ra.ra_sroot = "HKEY_CLASSES_ROOT";
	clearVStr(rkey); scanregdirR(&Ra,AVStr(rkey));

	fflush(out);
	fflush(err);
	return 0;
}
int setRegValue(PVStr(stat),PCStr(root),PCStr(key),PCStr(name),PCStr(val)){
	int res;
	char i32[4];
	int iv;
	int werr;
	int code = 0;
	HKEY hkey;
	HKEY rootkey;

	if( val ){
		iv = atoi(val);
	}
	rootkey = HKEY_LOCAL_MACHINE;
	if( root ){
		if( streq(root,"HKEY_LOCAL_MACHINE") ) rootkey = HKEY_LOCAL_MACHINE;
		if( streq(root,"HKEY_CURRENT_USER" ) ) rootkey = HKEY_CURRENT_USER;
	}
	
	res = RegOpenKeyEx(rootkey,key,0,KEY_ALL_ACCESS,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(stat,"NG Can't open the registry, r=%d e=%d\n",
			res,GetLastError());
		return -4;
	}
	if( val == 0 ){
		res = RegDeleteValue(hkey,name);
		RegCloseKey(hkey);
		if( res == ERROR_SUCCESS ){
			sprintf(stat,"OK removed the value, r=%d e=%d\n",
				res,GetLastError());
			return 0;
		}else{
			sprintf(stat,"NG can't remove it, r=%d e=%d\n",
				res,GetLastError());
			return -3;
		}
	}

	i32[0] = iv >> 24;
	i32[1] = iv >> 16;
	i32[2] = iv >> 8;
	i32[3] = iv;

	res = RegSetValueEx(hkey,name,0,REG_DWORD_BIG_ENDIAN,
		(const LPBYTE)i32,4);
	if( res != ERROR_SUCCESS ){
		sprintf(stat,"NG Can't set the registry value, r=%d e=%d\n",
			res,GetLastError());
		code = -2;
	}else{
		sprintf(stat,"OK Set the registry value, r=%d e=%d v=%d\n",
			res,GetLastError(),iv);
	}
	RegCloseKey(hkey);
	return code;
}
int setRegVal(FILE *tc,PCStr(name),PCStr(val)){
	IStr(rkey,256);
	int res;
	char i32[4];
	int iv;
	int werr;
	int code = 0;
	HKEY hkey;

	if( val ){
		iv = atoi(val);
	}
/*
	sprintf(rkey,"Comm\\Tcpip\\Parms");
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_ALL_ACCESS,&hkey);
*/
sprintf(rkey,"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
res = RegOpenKeyEx(HKEY_CURRENT_USER,rkey,0,KEY_ALL_ACCESS,&hkey);
	if( res != ERROR_SUCCESS ){
/*
		fprintf(tc,"NG Can't open the registry, res=%d, err=%d\n",
			res,GetLastError());
*/
		return -4;
	}
	if( val == 0 ){
		res = RegDeleteValue(hkey,name);
		RegCloseKey(hkey);
		if( res == ERROR_SUCCESS )
			return 0;
		else	return -3;
	}

	i32[0] = iv >> 24;
	i32[1] = iv >> 16;
	i32[2] = iv >> 8;
	i32[3] = iv;
/*
	sprintf(rkey,"TimerWheelSize");
*/
strcpy(rkey,name);
	res = RegSetValueEx(hkey,rkey,0,REG_DWORD_BIG_ENDIAN,
		(const LPBYTE)i32,4);
	if( res != ERROR_SUCCESS ){
		fprintf(tc,"NG Can't set the registry value, res=%d, err=%d\n",
			res,GetLastError());
/*
		code = -1;
*/
		code = -2;
	}else{
		fprintf(tc,"OK Set the registry value, res=%d, err=%d, v=%d\n",
			res,GetLastError(),iv);
	}
	RegCloseKey(hkey);
	return code;
}
int setTcpRegVal(PVStr(stat),int adp,PCStr(name),PCStr(val)){
	IStr(rkey,256);
	int res;
	char i32[4];
	int iv;
	int werr;
	int code = 0;
	HKEY hkey;

	if( adp )
		sprintf(rkey,"Comm\\GSPI86861\\Parms\\TcpIp");
	else	sprintf(rkey,"Comm\\TcpIp\\Parms");
	res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,rkey,0,KEY_ALL_ACCESS,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(stat,"%s: No %s\n",name,rkey);
		return -1;
	}

	sprintf(rkey,name);
	if( val == 0 ){
		res = RegDeleteValue(hkey,rkey);
		if( res != ERROR_SUCCESS ){
			sprintf(stat,"%s: Cannot remove\n",rkey);
		}else{
			sprintf(stat,"%s: Removed\n",rkey);
		}
	}else{
		iv = 0;
		if( strncmp(val,"0x",2) == 0 )
			sscanf(val,"0x%x",&iv);
		else	iv = atoi(val);
		i32[0] = iv >> 24;
		i32[1] = iv >> 16;
		i32[2] = iv >> 8;
		i32[3] = iv;

		res = RegSetValueEx(hkey,rkey,0,REG_DWORD_BIG_ENDIAN,
			(const LPBYTE)i32,4);
		if( res != ERROR_SUCCESS ){
			sprintf(stat,"%s: Cannot set\n",rkey);
			code = -1;
		}else{
			sprintf(stat,"%s: Set 0x%X (%d)\n",rkey,iv,iv);
		}
	}
	RegCloseKey(hkey);
	return code;
}
int regGetValue(PCStr(which),PCStr(key),PCStr(val),PVStr(rvalue)){
	int res;
	HKEY hroot;
	HKEY hkey;
	unsigned long int type,len;
	unsigned char value[1024];
	int rcode = 0;

	hroot = HKEY_LOCAL_MACHINE;
	res = RegOpenKeyEx(hroot,key,0,KEY_READ,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(rvalue,"NoSuchKey:%s",key);
		return -1;
	}
	len = sizeof(value);
	res = RegQueryValueEx(hkey,val,NULL,&type,value,&len);
	type = REG_SZ;
	if( res != ERROR_SUCCESS ){
		sprintf(rvalue,"NoSuchValue:%s(%d,%d)",val,res,GetLastError());
		rcode = -1;
	}else{
		/* based on the type */
		strcpy(rvalue,(char*)value);
	}
	RegCloseKey(hkey);
	return rcode;
}
int getRegValue(PVStr(stat),PVStr(val),PCStr(root),PCStr(key),PCStr(name)){
	int res;
	int werr;
	int code = 0;
	HKEY hkey;
	HKEY rootkey;
	unsigned long int type,len;
	unsigned char value[1024];

	clearVStr(stat);
	clearVStr(val);
	rootkey = HKEY_LOCAL_MACHINE;
	if( root ){
		if( streq(root,"HKEY_LOCAL_MACHINE") ) rootkey = HKEY_LOCAL_MACHINE;
		if( streq(root,"HKEY_CURRENT_USER" ) ) rootkey = HKEY_CURRENT_USER;
	}
	
	res = RegOpenKeyEx(rootkey,key,0,KEY_ALL_ACCESS,&hkey);
	if( res != ERROR_SUCCESS ){
		sprintf(stat,"NG Can't open the registry, r=%d e=%d",
			res,GetLastError());
		return -4;
	}
	len = sizeof(value);
	res = RegQueryValueEx(hkey,name,NULL,&type,value,&len);
	RegCloseKey(hkey);

	if( res == ERROR_SUCCESS ){
		unsigned char *iv = value;
		int ival;

		clearVStr(stat);
		clearVStr(val);
		switch( type ){
			case REG_BINARY:
				break;
			case REG_DWORD_LITTLE_ENDIAN:
				ival = (iv[3]<<24)|(iv[2]<<16)|(iv[1]<<8)|iv[0];
				sprintf(val,"%d",ival);
				break;
			case REG_DWORD_BIG_ENDIAN:
				ival = (iv[0]<<24)|(iv[1]<<16)|(iv[2]<<8)|iv[3];
				sprintf(val,"%d",ival);
				break;
			case REG_SZ:
				sprintf(val,"%s",value);
				break;
			case REG_MULTI_SZ:
				break;
			default:
				break;
		}
		return 0;
	}else{
		sprintf(stat,"NG can't get the value, r=%d e=%d [%s]",
			res,GetLastError(),name);
		return -3;
	}
	return code;
}

static void getresconfX(HKEY hkey,PCStr(skey),PVStr(where),PVStr(buf))
{	refQStr(bp,buf); /**/
	unsigned long int type,len;
	int nv,vi;
	LONG res;
	unsigned char value[1024]; /**/
	ACStr(vv,4,256);
	const char *bp0;

	type = REG_MULTI_SZ;
	len = sizeof(value);
	res = RegQueryValueEx(hkey,"NTEContextList",NULL,&type,value,&len);
	if( res == ERROR_SUCCESS ){
		if( value[0] == 0 ){
			/* this interface seems inactive */
			return;
		}
	}

	bp += strlen(buf);
	bp0 = bp;

	type = REG_SZ;
	len = sizeof(value);
	if( isWindowsCE() ){
		res = RegQueryValueEx(hkey,"DNSDomain",NULL,&type,value,&len);
	}else
	res = RegQueryValueEx(hkey,"Domain",NULL,&type,value,&len);
	if( res != ERROR_SUCCESS || value[0] == 0 ){
		type = REG_SZ;
		len = sizeof(value);
	res = RegQueryValueEx(hkey,"DhcpDomain",NULL,&type,value,&len);
	}
	if( res == ERROR_SUCCESS && value[0] ){
		sprintf(bp,"domain %s\r\n",value);
		bp += strlen(bp);
	}

	type = REG_SZ;
	len = sizeof(value);
	res = RegQueryValueEx(hkey,"SearchList",NULL,&type,value,&len);
	if( res == ERROR_SUCCESS && value[0] ){
		sprintf(bp,"search %s\r\n",value);
		bp += strlen(bp);
	}

	type = REG_SZ;
	len = sizeof(value);
	if( isWindowsCE() ){
		res = RegQueryValueEx(hkey,"DNS",NULL,&type,value,&len);
	}else
	res = RegQueryValueEx(hkey,"NameServer",NULL,&type,value,&len);
	if( res != ERROR_SUCCESS || value[0] == 0 ){
		type = REG_SZ;
		len = sizeof(value);
	res = RegQueryValueEx(hkey,"DhcpNameServer",NULL,&type,value,&len);
	}
	if( res == ERROR_SUCCESS && value[0] ){
		const unsigned char *dp;
		if( type == REG_MULTI_SZ ){
			for( dp = value; dp[0] || dp[1]; dp++ ){
				if( *dp == 0 ){
					*(char*)dp = ' ';
				}
			}
		}else{
		for( dp = value; *dp; dp++ )
			if( *dp == ',' )
				*(char*)dp = ' ';
		}
		nv = Xsscanf((char*)value,"%s %s %s %s",EVStr(vv[0]),EVStr(vv[1]),EVStr(vv[2]),EVStr(vv[3]));
		for( vi = 0; vi < nv; vi++ )
		{
			sprintf(bp,"nameserver %s\r\n",vv[vi]);
		bp += strlen(bp);
		}
	}

	if( bp != bp0 ){
		strcpy(where,skey);
	}
}
void getResconfX(HKEY hkey,PCStr(skey),PVStr(where),PVStr(buf)){
	getresconfX(hkey,skey,BVStr(where),BVStr(buf));
}

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
Program:	__locking.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	061104	merged into windows.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "log.h"
#include <process.h>
#include <io.h>
#include <sys/locking.h>
FileSize Ltell(int fd);

int file_isregular(int fd);
static int LockingX(int fd,int type,int bytes);
int lock_dbg = 0;
int lock_ext = 1;

static int Locking(int fd,int type,int bytes)
/*
{ 	int off,rcode;
*/
{	FileSize off;
	int rcode;

	if( lock_ext ){
		return LockingX(fd,type,bytes);
	}

	rcode = -1;
	/*
	if( 0 <= (off = tell(fd)) )
	*/
	if( 0 <= (off = Ltell(fd)) )
	if( 0 <= lseek(fd,0,0) ){
		rcode = locking(fd,type,bytes);
		lseek(fd,off,0);
	}
	if( rcode == -1 && !file_isregular(fd) ){
		/* treat as success, 
		 * mainly for lock_TIMEOUT not to wait non-lockable file ... ?
		 */
		rcode = 0;
	}
	return rcode;
}

int SHlockB(int fd){	return	Locking(fd,_LK_RLCK,1); }
int SHlockNB(int fd){	return	Locking(fd,_LK_NBRLCK,1); }
int EXlockB(int fd){	return	Locking(fd,_LK_LOCK,1); }
int EXlockNB(int fd){	return	Locking(fd,_LK_NBLCK,1); }
int UNlock(int fd){	return	Locking(fd,_LK_UNLCK,1); }


int porting_dbg(const char *fmt,...);
static const char *lksym(int type){
	switch(type){
		case _LK_RLCK:  return "RLCK";   break;
		case _LK_NBRLCK:return "NBRLCK"; break;
		case _LK_LOCK:  return "LOCK";   break;
		case _LK_NBLCK: return "NBLCK";  break;
		case _LK_UNLCK: return "UNLCK";  break;
	}
	return "?";
}
static void lklog(int fd,int type,int bytes,const char *fmt,...){
	VARGS(16,fmt);
	CStr(msg,1024);
	const char *st;
	int xerr;

	if( !file_isregular(fd) ) /* not the tty for LOGFILE */
		return;

	xerr = GetLastError();
	sprintf(msg,"Locking(%d,%-6s,%d)[xerr=%d err=%d] ",fd,lksym(type),bytes,
		GetLastError(),errno);
	Xsprintf(TVStr(msg),fmt,VA8);
	porting_dbg("%s",msg);
}

static int dolock1(int fd,int type,FileSize lkoff,FileSize bytes){
	HANDLE oh;
	int offh,offl,lenh,lenl;
	int rcode;
	int xerr;

	if( isWindowsCE() ){
		return 0;
	}

	oh = (HANDLE)_get_osfhandle(fd);
	offh = lkoff >> 32;
	offl = lkoff & 0xFFFFFFFF;
	lenh = bytes >> 32;
	lenl = bytes & 0xFFFFFFFF;
	SetLastError(0);

	if( type == _LK_UNLCK ){
		if( UnlockFile(oh,offl,offh,lenl,lenh) )
			rcode = 0;
		else	rcode = -1;
	}else{
		if( LockFile(oh,offl,offh,lenl,lenh) )
			rcode = 0;
		else	rcode = -1;
	}

	if( lock_dbg || lDEBUGLOCK() ){
		xerr = GetLastError();
		porting_dbg("-- LK [%d/%d] %-6s %llX %llX = %d xerr=%d",
			fd,oh,lksym(type),lkoff,bytes,rcode,xerr);
	}
	return rcode;
}
static int dolock(int fd,int type,FileSize lkoff,FileSize bytes){
	int ti;
	int rcode;

	for( ti = 0; ti < 10; ti++ ){
		rcode = dolock1(fd,type,lkoff,bytes);
		if( rcode == 0 )
			break;
		if( type == _LK_NBLCK || type == _LK_NBRLCK )
			break;
		if( type == _LK_UNLCK )
			break;
		if( lock_dbg || lDEBUGLOCK() ){
			porting_dbg("-- lock retry [%d] %d\n",ti,type);
		}
		sleep(1);
	}
	return rcode;
}
static int LockingX(int fd,int type,int xbytes){
	int shared;
 	int rcode;
	int pid;
	int bytes = 0;
	FileSize poff;
	FileSize loff;

	shared = (type == _LK_RLCK || type == _LK_NBRLCK);
	rcode = -1;
	SetLastError(0);
	/*
	if( 0 <= tell(fd) ){
	*/
	if( 0 <= Ltell(fd) ){
		pid = _getpid() & 0xFFFF;
		if( shared ){
			poff = pid;
			bytes = 1;
		}else{
			poff = 0;
			bytes = 0x10000;
		}

		loff = 0x10 * 0x100000000;
		poff += loff;

		rcode = dolock(fd,type,poff,bytes);
		if( rcode != 0 && type == _LK_UNLCK ){
			if( shared ){
				poff = 0;
				bytes = 0x10000;
			}else{
				poff = pid;
				bytes = 1;
			}
			poff += loff;
			rcode = dolock(fd,type,poff,bytes);
		}
		if( type != _LK_UNLCK )
		if( type != _LK_NBRLCK && type != _LK_NBLCK ){
			if( rcode != 0 || lock_dbg || lDEBUGLOCK() ){
				lklog(fd,type,bytes,"=%d",rcode);
			}
		}
		errno = 0;
	}else{
		lklog(fd,type,bytes,"tell error");
		errno = 0;
		rcode = 0; // 9.8.2 not to be retried...
	}
	if( rcode == -1 && !file_isregular(fd) ){
		/* treat as success, 
		 * mainly for lock_TIMEOUT not to wait non-lockable file ... ?
		 */
		rcode = 0;
	}
	return rcode;
}

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
Program:	_-CreateThred.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	061104	merged into windows.c
//////////////////////////////////////////////////////////////////////#*/
#include <windows.h>
#include <stdio.h>
#include "ystring.h"

static struct {
	HANDLE t_handle;
} threads[64];
static CRITICAL_SECTION threadCSC;
static int Nthreads;
static int Athreads;
static int settx(int tid,HANDLE th){
	int tx;
	int tidh = 0;

	if( Nthreads++ == 0 ){
		InitializeCriticalSection(&threadCSC);
	}
	EnterCriticalSection(&threadCSC);
	Athreads++;
	for( tx = 1; tx < elnumof(threads); tx++ ){
		if( threads[tx].t_handle == 0 ){
			threads[tx].t_handle = th;
			if( isWindows95() ){ // 9.9.5
				tidh = (tx << 24) | (0x00FFFFFF & tid);
			}else
			tidh = (tx << 24) | tid;
			syslog_DEBUG("-- %d/%d settx[%X] %X = %X H/%X\n",
				Athreads,Nthreads,tx,tidh,tid,th);
			break;
		}
	}
	LeaveCriticalSection(&threadCSC);
	if( tidh == 0 ){
		LE("---- settx: no more thread(%d) %X %X",tx,tid,th);
	}
	return tidh;
}
static int gettx(int tidh,HANDLE *thp,int clear){
	int tx;
	int tid;
	HANDLE th;

	EnterCriticalSection(&threadCSC);
	Athreads--;
	tx = (tidh >> 24) & 0xFF;
	if( elnumof(threads) <= tx ){
		*thp = (HANDLE)-1;
		tid = -1;
		LE("---- gettx: [%d] bad handle %X",tx,tidh);
	}else{
		*thp = threads[tx].t_handle;
		if( clear )
		threads[tx].t_handle = 0;
		if( isWindows95() ){ // 9.9.5
			tid = 0xFF000000 | (0xFFFFFF & tidh);
		}else
		tid = 0xFFFFFF & tidh;
		syslog_DEBUG("---- %d/%d gettx[%d] %X = %X H/%X\n",
			Athreads,Nthreads,tx,tidh,tid,*thp);
	}
	LeaveCriticalSection(&threadCSC);
	return tid;
}
#if isWindowsCE()
#define _beginthreadex(a,b,c,d,e,f) 0
#define _endthreadex(a) 0
#endif

typedef struct {
	IFUNCP	 th_func;
  const char	*th_name;
	char	*th_av[8]; /**/
	int	 th_started;
} threadEntry;

int thread_start(const char *name,void *ta);
int thread_done(void *xcode);
int thread_doneX(int tid,void *xcode);
static void thread2(threadEntry *ath)
{	int rcode;
	char **av;
	threadEntry the,*cth = &the;

	*cth = *ath;
	ath->th_started = 1;
	thread_start(ath->th_name,cth);
	av = cth->th_av;
	rcode = (*(cth->th_func))(av[0],av[1],av[2],av[3],av[4],av[5],av[6]);
	if( lTHREAD() )
	porting_dbg("thread exit(%d)",rcode);
	thread_done(0);
	if( isWindowsCE() ){
		ExitThread(rcode);
	}else{
		_endthreadex(rcode);
	}
}
static void thread_exit(void *code){
	thread_done(0);
	if( isWindowsCE() ){
		ExitThread(0);
	}else{
		_endthreadex(0);
	}
}
typedef void *(*thchFuncp)(void *thcharg);
void *thread_child(thchFuncp func,void *arg);
static void thread1(threadEntry *ta){
        thread_child((thchFuncp)thread2,ta);
}
static unsigned __stdcall thread0(void *ta){
        thread_child((thchFuncp)thread2,ta);
	return 0;
}

static int thread_fork(int ssize,const char *name,IFUNCP func,...)
{	DWORD tid;
	unsigned int utid;
	HANDLE thandle;
	threadEntry thb;
	threadEntry *th;
	int ai;
	VARGS(7,func);
	int ri;
	int tidh;
	int siz;

	if( lTHREAD() )
	porting_dbg("thread fork(%d,%s,%x) --> CreateThread()",ssize,name,func);

	Sleep(0);
	th = &thb;
	th->th_started = 0;
	markStackBase(th);
	th->th_name = name;
	th->th_func = func;
	for( ai = 0; ai < 7; ai++ )
		th->th_av[ai] = va[ai];

	tid = 0;
	for( ri = 0; ri < 10; ri++ ){
		if( isWindowsCE() ){
	thandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)thread1,th,0,&tid);
		}else{
	thandle = (HANDLE)_beginthreadex(NULL,0,thread0,th,0,&utid);
			tid = utid;
		}
		if( thandle != 0 )
			break;
		WLE("(%d) thread_fork() Err=%d %X\n",ri,GetLastError(),th);
		Sleep(100);
	}
	for( ri = 0; ri < 100 && th->th_started == 0; ri++ ){
		if( 10 < ri ){
			LE("-- waiting thread(%X) start... (%d)",tid,ri);
		}
		Sleep(ri);
	}

	/*
	porting_dbg("thread fork(%x / %d)",th->th_func,tid);
	return tid;
	*/
	if( lTHREAD() )
	porting_dbg("thread fork(%x / %X %X)",th->th_func,tid,thandle);

	if( isWindowsCE() ){
		/* tid == thandle on WinCE */
		return (int)thandle;
	}
	tidh = settx(tid,thandle);
	return tidh;
}

int SIZEOF_tid_t = sizeof(HANDLE);
static unsigned __stdcall threadx(void *ta){
	return 0;
}
int getThreadIds(FileSize *mtid,FileSize *ctid){
	HANDLE th;
	unsigned int utid;
	DWORD tid;

	*mtid = (FileSize)GetCurrentThreadId();
	if( isWindowsCE() ){
		th = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)threadx,0,0,&tid);
	}else{
		th = (HANDLE)_beginthreadex(NULL,0,threadx,0,0,&utid);
		tid = utid;
	}
	*ctid = (FileSize)tid;
	return sizeof(HANDLE);
}

const char *WithThread = "Winthread";
int (*ThreadFork)(int,const char *name,IFUNCP,...) = thread_fork;
static int thread_yield(){
	Sleep(0);
	return 0;
}
int (*ThreadYield)() = thread_yield;
void WINthread(){}

extern int THEXIT;
int THWAIT_noBug = 0;
static int thread_wait(int tidh,int timeout){
	DWORD ex;
	int ok;
	int tid;
	HANDLE th;
	int wi;
	double Start = Time();
	int elp = 0;
	int slp;
	int cok;
	int noBug = 0;

	if( isWindowsCE() ){
		th = (HANDLE)tidh;
		tid = tidh;
	}else{
		if( lSINGLEP() || lNOTHWAITBUG() || THWAIT_noBug ){
			tid = gettx(tidh,&th,0); /* 9.9.7 */
			noBug = 1;
		}else
		tid = gettx(tidh,&th,1);
/* this means that when wait timeouted the thread will not be waited again ? */
	}

	Sleep(0);
	ok = 0;
	ex = 0;
	slp = 0;
	errno = 0;
	setthread_FL(0,__FILE__,__LINE__,"thread_wait...");
	for( wi = 0; ; wi++ ){
		ok = GetExitCodeThread(th,&ex);
		if( ex != STILL_ACTIVE )
			break;
		elp += slp;
		if( timeout ){
			if( timeout < elp ){
				break;
			}
		}
		slp += 10;
		if( 300 < slp ){
			slp = 300;
		}
		Sleep(slp);
	}
	setthread_FL(0,__FILE__,__LINE__,"thread_wait");
	if( ok == 0 ){
		/* kill the thread */
	}
	if( lTHREAD() )
	LE("[%.3f](%d) thread_wait(%X %X) -> %d %X%s",Time()-Start,wi,
		tid,th,ok,ex,ex==STILL_ACTIVE?"(ALIVE)":"");

	if( noBug ){
		if( ok && ex != STILL_ACTIVE ){
			tid = gettx(tidh,&th,1); /* 9.9.7 */
			cok = CloseHandle(th);
			return 0;
		}else{
			return -3;
		}
	}
	if( lSINGLEP() ){
		/* 9.8.2 should be like this always
		 * (don't close handle prematurly)
		 */
		if( ok ){
			if( ex != STILL_ACTIVE ){
				cok = CloseHandle(th);
				return 0;
			}else{
				return -2;
			}
		}else{
			return -1;
		}
	}

	if( ok ){
		cok = CloseHandle(th);
		if( cok == 0 ){
			LE("---- failed CloseHandle(th=%X,tid=%X)",th,tid);
		}
	}
	if( ok && ex == STILL_ACTIVE ){
		errno = EAGAIN;
		return -2;
	}else
	if( ok )
		return 0;
	else	return -1;
}
int (*ThreadWait)(int tid,int timeout) = thread_wait;
static int getthreadid(){
	 return (int)GetCurrentThreadId();
}
int (*ThreadId)() = getthreadid;
int threadIsAlive(int tid);
static int thread_kill(int tidh,int sig){
	HANDLE th;
	int tid;
	if( isWindowsCE() ){
		th = (HANDLE)tidh;
		tid = tidh;
	}else{
		tid = gettx(tidh,&th,0);
	}
	if( sig == 9 ){
		syslog_ERROR("thread kill (%X/%X/%X)%d act=%d\n",
			tid,th,tidh,threadIsAlive(tid),actthreads());
		if( threadIsAlive(tid) ){
			thread_doneX(tid,0);
		}
		if( TerminateThread(th,0) ){
			/*
			the ID might be reused by another thread already
			thread_doneX(tid,0);
			*/
			syslog_ERROR("thread killed (%X/%X/%X) act=%d\n",
				tid,th,tidh,actthreads());
			porting_dbg("[%X] thread killed (%X/%X/%X)",
				getthreadid(),tid,th,tidh);
			return 0;
		}
		else{
			syslog_ERROR("thread kill (%X) FAILED err=%d\n",
				tid,GetLastError());
		}
	}
	return -1;
}
static int thread_destroy(int tidh){
	return thread_kill(tidh,9);
}
int (*ThreadDestroy)(int tid) = thread_destroy;
int (*ThreadKill)(int tid,int sig) = thread_kill;
void (*ThreadExit)(void *code) = thread_exit;
/*
int (*ThreadKill)(int tid,int sig) = 0;
void (*ThreadExit)(void *code) = 0;
*/
static int thread_sigmask(const char *show,SigMaskInt nmaski,SigMaskInt *omaski){
	int rcode = -1;
	int how;

	/*
	switch( *show ){
		case 'g': case 'G': how = SIG_UNBLOCK; break;
		case 'b': case 'B': how = SIG_BLOCK;   break;
		case 'u': case 'U': how = SIG_UNBLOCK; break;
		case 's': case 'S': how = SIG_SETMASK; break;
	}
	*/
	return rcode;
}
int (*ThreadSigmask)(const char *show,SigMaskInt nmaski,SigMaskInt *omaski) = thread_sigmask;

/*///////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	windows0.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	061104	merged into windows.c
//////////////////////////////////////////////////////////////////////#*/
/* ######## PIPE ######## */
int _pipeX(int sv[2],int size,int mode){
	int rcode;
	int ri;
	_heapLock lock;

	sv[0] = sv[1] = -1;
	for( ri = 0; ri < 10; ri++ ){
		errno = 0;
		Sleep(0);
		heapLock(FL_ARG,lock);
		rcode = _pipe(sv,size,mode);
		heapUnLock(FL_ARG,lock);
		if( rcode == 0 ){
			if( isWindowsCE() ){
				break;
			}else
			if( !ISPIPE(sv[0]) || !ISPIPE(sv[1]) ){
				LE("-- _pipeX(%d)=%d,errno=%d [%d,%d]%d %d",
					size,rcode,errno, sv[0],sv[1],
					ISPIPE(sv[0]),ISPIPE(sv[1]));
			}
			else
			break;
		}
		WLE("(%d) _pipeX(%d)=%d,errno=%d\n",ri,size,rcode,errno);
		_sleep(100);
	}
	return rcode;
}
int pipe(int sv[2])
{	int rcode;

	/*
	rcode = _pipe(sv,4096,O_BINARY);
	*/
	rcode = _pipeX(sv,4096,O_BINARY);
	LS("pipe() = %d [%d,%d]",rcode,sv[0],sv[1]);
	return rcode;
}
int pipeX(int sv[2],int size){
	int rcode;
	/*
	rcode = _pipe(sv,size,O_BINARY);
	*/
	/*
	if( isWindows95() ){ // 9.9.5
		if( socketpair(AF_INET,SOCK_STREAM,0,sv) == 0 ){
			return 0;
		}
	}
	*/
	rcode = _pipeX(sv,size,O_BINARY);
	LS("pipeX(%d) = %d [%d,%d]",size,rcode,sv[0],sv[1]);
	return rcode;
}
FILE *popen(PCStr(command),PCStr(mode))
{
	LV("popen(%s,%s)",command,mode);
	return _popen(command,mode);
}
int pclose(FILE *fp)
{
	LV("pclose(%x)",fp);
	return _pclose(fp);
}
int ftruncate(int fd,unsigned int size)
{	int rcode;

	rcode = chsize(fd,size);
	LV("ftruncate(%d,%d) = %d",fd,size,rcode);
	return rcode;
}

/* 9.9.2 NTFS-BUG? http://support.microsoft.com/kb/190315
 * or simply TZ problem?
 */
#ifdef UNDER_CE
#define adj_stattime 1?0:
#else
static int adj_stattime(const char *what,const char *path,BY_HANDLE_FILE_INFORMATION *fa,time_t *otc,time_t *otm,time_t *ota){
	int ftc,ftm,fta;

	if( 1 ){
		/* this might be enabled in future */
		return 0;
	}

	ftc = FileTimeToUnixTime(&fa->ftCreationTime);
	ftm = FileTimeToUnixTime(&fa->ftLastWriteTime);
	fta = FileTimeToUnixTime(&fa->ftLastAccessTime);

	if( ftc == *otc || ftm == *otm )
		/* st_atime seems diff. with AccessTime */
		return 0;

	if( enbugWIN_NTFS_TIME() ){
		LE("## NTFS DLT time fix %X %X (%d) %X %X (%d) %X %X (%d) %s(%s)",
			*otc,ftc,*otc-ftc,*otm,ftm,*otm-ftm,
			*ota,fta,*ota-fta,what,path);
		fprintf(stderr,"## NTFS DLT time %X %X (%d) %s(%s)\n",
			*otc,ftc,*otc-ftc,what,path);
		return 0;
	}
	LV("## NTFS DLT time fix %X %X (%d) %s(%s)",
		*otc,ftc,*otc-ftc,what,path);
	*otc = ftc;
	*otm = ftm;
	*ota = fta;
	return 1;
}
#endif

/*
int add_stat(struct stat *stp,int fh){
*/
int add_stat(struct stat *stp,int fh,const char *path){
	int ok;
	BY_HANDLE_FILE_INFORMATION fa;

	ok = GetFileInformationByHandle((HANDLE)fh,&fa);
	if( !ok ){
		return -1;
	}
	/* st_ino on Windows is just a short int ... */
	stp->st_ino = (((Foff_t)fa.nFileIndexHigh) << 32) | fa.nFileIndexLow;
	adj_stattime("stat",path,&fa,
		&stp->st_ctime,&stp->st_mtime,&stp->st_atime);
	return 0;
}
/*
int add_stat64(struct _stati64 *stp,int fh){
*/
int add_stat64(struct _stati64 *stp,int fh,const char *path){
	int ok;
	BY_HANDLE_FILE_INFORMATION fa;

	ok = GetFileInformationByHandle((HANDLE)fh,&fa);
	if( !ok ){
		return -1;
	}

	/* st_ino on Windows is just a short int ... */
	stp->st_ino = (((Foff_t)fa.nFileIndexHigh) << 32) | fa.nFileIndexLow;
	adj_stattime("stat64",path,&fa,
		&stp->st_ctime,&stp->st_mtime,&stp->st_atime);
	return 0;
}
__int64 fstati64(int handle,struct _stati64 *st){
	int rcode;
	rcode = _fstati64(handle,st);
	return rcode;
}
#if !isWindowsCE() /*{*/
int withwchar(const char *path,WCHAR *wpath,int wsize);
__int64 stati64(const char *path,struct _stati64 *st){
	int rcode;

	rcode = _stati64(path,st);
	if( rcode != 0 ){
		WCHAR wpath[1024];
		if( withwchar(path,wpath,elnumof(wpath)) ){
			rcode = _wstati64(wpath,st);
			if( rcode == 0 ){
				fprintf(stderr,"---- ---- wstati64(%s)=%d\n",path,rcode);
			}
		}
	}
	if( rcode == 0 ){
		HANDLE fh;
		fh = CreateFile(path,GENERIC_READ,FILE_SHARE_READ,
			NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

		if( fh == INVALID_HANDLE_VALUE
		 && GetLastError() == ERROR_ACCESS_DENIED ){
			/* 9.9.2 to get directory attributes */
			int attr;
			attr = GetFileAttributes(path);
			if( attr & FILE_ATTRIBUTE_DIRECTORY ){
				fh = CreateFile(path,0,FILE_SHARE_READ,
					NULL,OPEN_EXISTING,
					FILE_FLAG_BACKUP_SEMANTICS,NULL);
			}
		}
		if( fh && fh != INVALID_HANDLE_VALUE ){
			add_stat64(st,(int)fh,path);
			CloseHandle(fh);
		}
	}
	/*
	if( rcode == 0 ){
		HFILE fh;
		OFSTRUCT fs;
		if( fh = OpenFile(path,&fs,OF_READ) ){
			add_stat64(st,fh,path);
			_lclose(fh);
		}
	}
	*/
	return rcode;
}

int getcuser(PVStr(name),int size,PVStr(group),int gsiz){
	DWORD len = size;
	int sid[16];
	DWORD cbSid = sizeof(sid);
	IStr(rdom,128);
	DWORD cbdom = sizeof(rdom);
	SID_NAME_USE use;

	if( GetUserName((char*)name,&len) == 0 ){
		return -1;
	}
	if( LookupAccountName(NULL,name,sid,&cbSid,(char*)rdom,&cbdom,&use) ){
		if( group && 0 < cbdom )
			strcpy(group,rdom);
		return 0;
	}else{
		return -1;
	}
}

#include "accctrl.h"
#include "aclapi.h"
int getowner(PCStr(path),PVStr(fowner),int size,PVStr(group),int gsiz){
	HANDLE fh;
	int si;
	PSID owner;
	PSECURITY_DESCRIPTOR sd;
	SID_NAME_USE eu;
	IStr(user,128);
	DWORD usiz = sizeof(user);
	IStr(dom,128);
	DWORD dsiz = sizeof(dom);
	int ok;
	int rcode = -1;

	setVStrEnd(fowner,0);
	fh = CreateFile(path,GENERIC_READ,FILE_SHARE_READ,
		NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if( fh == NULL ){
		return -1;
	}
	si = OWNER_SECURITY_INFORMATION;
	owner = (SID*)GlobalAlloc(GMEM_FIXED,sizeof(PSID));
	sd = (SECURITY_DESCRIPTOR*)GlobalAlloc(GMEM_FIXED,sizeof(SECURITY_DESCRIPTOR));
	ok = GetSecurityInfo(fh,SE_FILE_OBJECT,si,&owner,NULL,NULL,NULL,&sd);
	if( ok != ERROR_SUCCESS ){
		LE("## FAILED getowner(%s).SecInfo err=%d",path,GetLastError());
		rcode = -2;
		goto EXIT;
	}
	if( LookupAccountSid(NULL,owner,user,&usiz,dom,&dsiz,&eu) == 0 ){
		LE("## FAILED getowner(%s).Lookup err=%d",path,GetLastError());
		rcode = -3;
		goto EXIT;
	}
	strcpy(fowner,user);
	if( group ){
		strcpy(group,dom);
	}
	rcode = 0;
EXIT:
	CloseHandle(fh);
	return rcode;
}

#if 1400 <= _MSC_VER /* VC2005 or laters */
#define stat(p,s) winStat(p,s)
#endif
/* stat() of Windows95 does not recognize "/dir/" as "/dir" */
int stat(PCStr(path),struct stat *stp)
{	int rcode;
	CStr(pathb,1024);

	if( rcode = _stat(path,(struct _stat *)stp) )
	if( path[0] && path[1] && strtailchr(path) == '/' ){
		QStrncpy(pathb,(char*)path,strlen(path));
		rcode = _stat(pathb,(struct _stat*)stp);
	}
	/*
	if( rcode == 0 ){
		HFILE fh;
		OFSTRUCT fs;
		if( fh = OpenFile(path,&fs,OF_READ) ){
			add_stat(stp,fh,path);
			_lclose(fh);
		}
	}
	*/
	return rcode;
}
#endif /*} !WindowsCE */
/*
 * 9.8.1 from ___findfirst.c
 */
int scan_ino;
int pathnorm(PCStr(what),PCStr(path),PVStr(xpath));
#ifdef UNDER_CE
struct _finddata_t {
	const char *name;
};
int _findfirst(const char *filepat,struct _finddata_t *filedata);
int _findnext(int File,struct _finddata_t *filedata);
int _findclose(int File);
#endif
int Scandir(const char *dirpath,int(*func)(const char*,...),...){
	struct _finddata_t filedata;
	long File;
	int rcode = -1;
	CStr(xdir,1024);
	CStr(cwd,1024);
	VARGS(8,func);

	if( pathnorm("Scandir",dirpath,AVStr(xdir)) ){
		dirpath = xdir;
	}

	if( getcwd(cwd,sizeof(cwd)) == 0L )
		return -1;

	if( chdir(dirpath) != 0 )
		return -1;

	File = _findfirst("*.*",&filedata);
	chdir(cwd);

	if( File == -1L )
		return -1;

	do {
		if( rcode = (*func)(filedata.name,VA8) )
			break;

	} while ( _findnext(File,&filedata) == 0 );
	_findclose(File);
	return rcode;
}

int ttyuid(int fd){
        return -1;
}

int INHERENT_ptrace(){ return 0; }
int ptraceTraceMe(){ return -1; }
int ptraceContinue(int a,int b){ return -1; }
int ptraceKill(int a){ return -1; }
int getWaitStopSig(int*a){ return -1; }
int getWaitExitSig(int*a){ return -1; }
int getWaitExitCode(int*a){ return a[0] & 0xFF; }
int getWaitExitCore(int*a){ return -1; }

#if !isWindowsCE() /*{*/
int isatty(int fd){
	HANDLE ph;
	char *env = getenv("SESSIONNAME");
	ph = (HANDLE)_get_osfhandle(fd);

	/*
	if( getenv("SSH_CONNECTION") )
	*/
	if( env != NULL && streq(env,"Console") /* fix-140502h */
	 || getenv("LANG") /* mod-140511c seems not set under a service */
	 || getenv("SSH_CONNECTION")
	 || getenv("CYGWIN")
	 || getenv("YYSH")
	 || getenv("YYEXEC")
	)
	if( GetFileType(ph) == FILE_TYPE_PIPE )
	{
		if( fd == fileno(stdin)
		 || fd == fileno(stdout)
		 || fd == fileno(stderr)
		){
			if( LOG_type & L_CONSOLE ){ /* for -fv option */
				setvbuf(stderr,NULL,_IONBF,0);
				setvbuf(stdout,NULL,_IONBF,0);
			}
			return 1;
		}
	}
	return _isatty(fd);
}
#endif /*}*/

typedef struct {
	int xcs_ok;
	int xcs_tid;
	int xcs_count;
	int xcs_retry;
	int xcs_timeout;
	CRITICAL_SECTION xcs_cs;
} XCS;
extern int cnt_enterCSC;
extern int cnt_leaveCSC;

int sizeofCSC(){
	return sizeof(XCS);
}
int statsCSC(void *acs,int *count,int *retry,int *timeout){
	XCS *xcs = (XCS*)acs;
	*count = xcs->xcs_count;
	*retry = xcs->xcs_retry;
	*timeout = xcs->xcs_timeout;
	return 0;
}
int debugCSC(void *acs,int on){
	return 0;
}

const char *WithMutex = "win";
int setupCSC(const char *wh,void *acs,int asz){
	XCS *xcs = (XCS*)acs;
	if( asz < sizeof(XCS) ){
		return -1;
	}
	if( xcs->xcs_ok )
		return 0;
	xcs->xcs_ok = 1;
	InitializeCriticalSection(&xcs->xcs_cs);
	xcs->xcs_tid = 0;
	xcs->xcs_count = 0;
	xcs->xcs_retry = 0;
	xcs->xcs_timeout = 0;
	return 0;
}
#if !defined(UNDER_CE)
extern "C" {
  BOOL WINAPI TryEnterCriticalSection(
    LPCRITICAL_SECTION lpCriticalSection
  );
}
#endif

/*
int win_noCSC = isWindows95() ? 1 : 0; // 9.9.5
*/
int win_noCSC = 0;

/*
int enterCSCX(void **xcs,int timeout){
*/
int enterCSCX_FL(FL_PAR,void *xcs,int timeout){
	((XCS*)xcs)->xcs_count++;
	if( win_noCSC ){
		return 0;
	}
	if( isWindows95() ){ // 9.9.5
		if( timeout ){
			if( lTHREAD() )
			putfLog("--enterCSCX NOT-SUPPORTED timeout=%d %s:%d",timeout,FL_BAR);
		}
	}else
	if( timeout ){
		int rem,to1,Err;
		to1 = timeout / 10;
		if( to1 <= 0 )
			to1 = 10;
		for( rem = timeout; 0 < rem; rem -= to1 ){
			if( THEXIT ){
				break;
			}
			/*
			9.9.5 this can affect caller's behavior
			SetLastError(0);
			*/
			if( TryEnterCriticalSection(&((XCS*)xcs)->xcs_cs) ){
				((XCS*)xcs)->xcs_tid = getthreadid();
				cnt_enterCSC++;
				return 0;
			}
			((XCS*)xcs)->xcs_retry++;
			/*
			Err = GetLastError();
			usleep(to1 * 1000);
			*/
			Sleep(to1);
		}
		/*
		fprintf(stderr,"--%X enterCSCX FAILED Err=%d tid=%X\n",
			getthreadid(),Err,((XCS*)xcs)->xcs_tid);
		*/
		((XCS*)xcs)->xcs_timeout++;
		return -1;
	}
	if( THEXIT ){
		/* 9.9.7 freeze on Win32 in call from Thread.c */
		return -1;
	}
	EnterCriticalSection(&((XCS*)xcs)->xcs_cs);
	((XCS*)xcs)->xcs_tid = getthreadid();
	cnt_enterCSC++;
	return 0;
}
/*
int enterCSC(void **xcs){
*/
int enterCSC_FL(FL_PAR,void *xcs){
	int ok;
	if( win_noCSC ){
		return 0;
	}
	ok = enterCSCX_FL(FL_BAR,xcs,0);
	((XCS*)xcs)->xcs_tid = getthreadid();
	cnt_enterCSC++;
	return ok;
}
int leaveCSC_FL(FL_PAR,void *xcs){
	if( win_noCSC ){
		return 0;
	}
	LeaveCriticalSection(&((XCS*)xcs)->xcs_cs);
	((XCS*)xcs)->xcs_tid = 0;
	cnt_leaveCSC++;
	return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
static int cs0ok;
static CRITICAL_SECTION cs0;
static CRITICAL_SECTION csv[8];
static int csfdv[8];
static CRITICAL_SECTION *getFILEcs(int fd){
	int fi;
	for( fi = 0; fi < elnumof(csfdv); fi++ ){
		if( csfdv[fi] == fd ){
			return &csv[fi];
		}
		if( csfdv[fi] == 0 ){
			return 0;
		}
	}
	return 0;
}
static CRITICAL_SECTION *setFILEcs(int fd){
	int fi;
	CRITICAL_SECTION *csp;

	if( csp = getFILEcs(fd) ){
		return csp;
	}
	if( cs0ok == 0 ){
		InitializeCriticalSection(&cs0);
		cs0ok = 1;
	}
	EnterCriticalSection(&cs0);
	if( csp = getFILEcs(fd) ){
		return csp;
	}
	csp = &csv[0];
	for( fi = 0; fi < elnumof(csfdv); fi++ ){
		if( csfdv[fi] == 0 ){
			csp = &csv[fi];
			csfdv[fi] = fd;
			InitializeCriticalSection(&csv[fi]);
			if( lTHREAD() )
				fprintf(stderr,"[%d] newcs=%d [%d]\n",
					getpid(),fi,fd);
			goto EXIT;
		}
	}
	fprintf(stderr,"[%d] CANNOT newcs=%d [%d]\n",
		getpid(),fi,fd);
EXIT:
	LeaveCriticalSection(&cs0);
	return csp;
}
void flockfile(FILE *fp){
	CRITICAL_SECTION *csp;
	if( InFinish )
		return;
	csp = setFILEcs(fileno(fp));
	/*
	if( TryEnterCriticalSection(csp) ){
		return;
	}
	*/
	EnterCriticalSection(csp);
}
void funlockfile(FILE *fp){
	CRITICAL_SECTION *csp;
	if( InFinish )
		return;
	if( csp = getFILEcs(fileno(fp)) ){
		LeaveCriticalSection(csp);
	}
}
#ifdef __cplusplus
}
#endif

FileSize getSysinfo(const char *name){
	/*
	SYSTEM_INFO sysinfo info;
	GetSystemInfo(&info);
	*/
	MEMORYSTATUS meminfo;
	GlobalMemoryStatus(&meminfo);

	if( strcmp(name,"freemem") == 0 ){
		return meminfo.dwAvailPhys;
	}
	if( strcmp(name,"totalmem") == 0 ){
		return meminfo.dwTotalPhys;
	}
	return -1;
}

#define A_OWN	1
#define A_GRP	2

typedef struct {
	char *sc_domain;
	char *sc_name;
	int   sc_nsz;
	char *sc_sid;
	int   sc_isz;
	char *sc_dom;
	int   sc_dsz;
	SID_NAME_USE sc_use;
} SidCache;
static SidCache sidCache[8];
static CriticalSec sidCSC;

#if !isWindowsCE() /*{*/
const char *sidtype(SID_NAME_USE use){
	switch( use ){
		case SidTypeUser: return "user";
		case SidTypeGroup: return "group";
		case SidTypeDomain: return "domain";
		case SidTypeAlias: return "alias";
		case SidTypeWellKnownGroup: return "wkgroup";
		case SidTypeDeletedAccount: return "dacount";
		case SidTypeInvalid: return "invalid";
		case SidTypeUnknown: return "unknown";
		//case SidTypeComputer: return "computer";
		//case SidTypeLabel: return "label";
	}
	return "?";
}
static int lookupAccountName(PCStr(domain),PCStr(iname),void *id,DWORD *isz,PVStr(dom),DWORD *dsz,SID_NAME_USE *use){
	int ok;
	int ii;
	SidCache *sc;

	setupCSC("sidCacheLookupName",sidCSC,sizeof(sidCSC));
	enterCSC(sidCSC);
	for( ii = 0; ii < elnumof(sidCache); ii++ ){
		sc = &sidCache[ii];
		if( sc->sc_name == 0 )
			break;
		if( domain == 0 && sc->sc_domain == 0 )
		if( streq(sc->sc_name,iname) ){
			if( sc->sc_isz <= *isz && sc->sc_dsz <= *dsz ){
				bcopy(sc->sc_sid,id,sc->sc_isz);
				*isz = sc->sc_isz;
				strcpy(dom,sc->sc_dom);
				*dsz = sc->sc_dsz;
				*use = sc->sc_use;
				leaveCSC(sidCSC);
				return 1;
			}
		}
	}
	if( ok = LookupAccountName(domain,iname,id,isz,(char*)dom,dsz,use) ){
		if( ii < elnumof(sidCache) ){
			sc = &sidCache[ii];
			sc->sc_domain = domain?stralloc(domain):NULL;
			sc->sc_name = stralloc(iname);
			sc->sc_nsz = strlen(iname)+1;
			sc->sc_isz = GetLengthSid(id);
			sc->sc_sid = (char*)malloc(sc->sc_isz);
			bcopy(id,sc->sc_sid,sc->sc_isz);
			sc->sc_dom = stralloc(dom);
			sc->sc_dsz = *dsz;
			sc->sc_use = *use;
		}else{
			LV("--[%d] %s CANT PUTn",ii,iname);
		}
	}
	leaveCSC(sidCSC);
	return ok;
}
static int lookupAccountSid(PCStr(domain),void *id,PVStr(oname),DWORD *nsz,PVStr(dom),DWORD *dsz,SID_NAME_USE *use){
	int ok;
	int ii;
	SidCache *sc;

	setupCSC("sidCacheLookupSid",sidCSC,sizeof(sidCSC));
	enterCSC(sidCSC);
	for( ii = 0; ii < elnumof(sidCache); ii++ ){
		sc = &sidCache[ii];
		if( sc->sc_name == 0 )
			break;
		if( domain == 0 && sc->sc_domain == 0 )
		if( bcmp(id,sc->sc_sid,sc->sc_isz) == 0 ){
			if( sc->sc_nsz <= *nsz && sc->sc_dsz <= *dsz ){
				strcpy(oname,sc->sc_name);
				*nsz = sc->sc_nsz;
				strcpy(dom,sc->sc_dom);
				*dsz = sc->sc_dsz;
				*use = sc->sc_use;
				leaveCSC(sidCSC);
				return 1;
			}
		}
	}
	if( ok = LookupAccountSid(domain,id,(char*)oname,nsz,(char*)dom,dsz,use) ){
		if( ii < elnumof(sidCache) ){
			sc = &sidCache[ii];
			sc->sc_domain = domain?stralloc(domain):NULL;
			sc->sc_name = stralloc(oname);
			sc->sc_nsz = strlen(oname)+1;
			sc->sc_isz = GetLengthSid(id);
			sc->sc_sid = (char*)malloc(sc->sc_isz);
			bcopy(id,sc->sc_sid,sc->sc_isz);
			sc->sc_dom = stralloc(dom);
			sc->sc_dsz = *dsz;
			sc->sc_use = *use;
		}else{
			LV("--[%d] CANT PUTi %s",ii,oname);
		}
	}
	leaveCSC(sidCSC);
	return ok;
}
static int siduserdom(PSID sid,PVStr(name),PVStr(rdom),PVStr(stype)){
	IStr(user,128);
	DWORD usiz = sizeof(user);
	IStr(dom,128);
	DWORD dsiz = sizeof(dom);
	SID_NAME_USE use;

	if( lookupAccountSid(NULL,sid,AVStr(user),&usiz,AVStr(dom),&dsiz,&use) ){
		strcpy(name,user);
		strcpy(rdom,dom);
		strcpy(stype,sidtype(use));
		return 0;
	}else{
		strcpy(name,"");
		strcpy(dom,"");
		strcpy(stype,"");
		return -1;
	}
}
static void dumpACL(PCStr(wh),PACL acl){
	int ai;
	void *ace;
	ACE_HEADER *ah;
	PSID sid;
	ACCESS_ALLOWED_ACE *aa;
	IStr(usr,128);
	IStr(dom,128);
	IStr(stype,128);
	IStr(udom,128);
	void *id1;

	for( ai = 0; GetAce(acl,ai,&ace); ai++ ){
		ah = (ACE_HEADER*)ace;
		if( ah->AceType != ACCESS_ALLOWED_ACE_TYPE ){
			continue;
		}
		aa = (ACCESS_ALLOWED_ACE*)ah;
		id1 = &aa->SidStart;
		if( IsValidSid(id1) ){
			siduserdom(id1,AVStr(usr),AVStr(dom),AVStr(stype));
			sprintf(udom,"%s@%s(%s)",usr,dom,stype);
		}else{
			strcpy(udom,"");
		}
		LE("dumpACL %s %X[%2d] %X [%X %X z%d %X][%s]",wh,acl,ai,ace,
			ah->AceType,ah->AceFlags,ah->AceSize,
			aa->Mask,udom);
	}
}
static int addACL(void *asd,PACL dacl,PCStr(path),int aty,void *mid,int midz,PCStr(user),int mask){
	IStr(userb,256);
	refQStr(udom,userb);
	DWORD cbmid = midz;
	IStr(rdom,128);
	DWORD cbdom = sizeof(rdom);
	SID_NAME_USE use;
	int ok1,ok2,err;
	int ai;
	void *ace;
	IStr(xacc,128);
	IStr(xdom,128);
	DWORD xasz = sizeof(xacc);
	DWORD xdsz = sizeof(xdom);
	int added = 0;
	int idsiz;
	IStr(stype,128);

	udom = 0;
	if( strchr(user,'@') ){
		strcpy(userb,user);
		if( udom = strchr(userb,'@') ){
			setVStrPtrInc(udom,0);
			if( *udom != 0 ){
				user = userb;
			}else{
				udom = 0;
			}
		}
	}
	if( !lookupAccountName(udom,user,mid,&cbmid,AVStr(rdom),&cbdom,&use) ){
		LE("--addACL can't lookup user[%s]",user);
		return -1;
	}
	idsiz = GetLengthSid(mid);
	if( !lookupAccountSid(udom,mid,AVStr(xacc),&xasz,AVStr(xdom),&xdsz,&use) ){
		LE("--addACL can't reverse lookup user[%s]",user);
	}else{
		LV("--addACL reverse lookup user[%s] -> %s",user,xacc,xdom);
	}

	for( ai = 0; GetAce(dacl,ai,&ace); ai++ ){
		ACE_HEADER *ah;
		ACCESS_ALLOWED_ACE *aa;
		PSID sid;
		IStr(usr1,128);
		IStr(dom1,128);

		ah = (ACE_HEADER*)ace;
		if( ah->AceType != ACCESS_ALLOWED_ACE_TYPE ){
			continue;
		}
		aa = (ACCESS_ALLOWED_ACE*)ace;
		if( !IsValidSid(&aa->SidStart) ){
			continue;
		}

		if( 1 <= LOGLEVEL ){
			siduserdom(&aa->SidStart,AVStr(usr1),AVStr(dom1),AVStr(stype));
			LV("--[%d] (%d %2d %X) %8X %s@%s(%s)",
				ai,ah->AceType,ah->AceFlags,ah->AceSize,
				aa->Mask,usr1,dom1,stype);
		}
		if( ai == 0 ){
			/* can be pseudo SYSTEM ACE ?? */
			continue;
		}
		if( bcmp(mid,&aa->SidStart,idsiz) == 0 ){
			siduserdom(&aa->SidStart,AVStr(usr1),AVStr(dom1),AVStr(stype));
			if( 1 <= LOGLEVEL )
			LE("--with %s@%s(%s) permission already %s",
				usr1,dom1,stype,path);
			goto SETOWN;
		}

		/*
		if( streq(usr1,user) && streq(dom1,rdom) ){
			LV("--with %s@%s permission already-1 %s",
				usr1,dom1,path);
			goto SETOWN;
		}
		if( streq(usr1,xacc) && streq(dom1,xdom) ){
			LV("--with %s@%s permission already-2 %s",
				usr1,dom1,path);
			goto SETOWN;
		}
		*/
	}
	ok2 = AddAccessAllowedAce(dacl,ACL_REVISION2,mask,mid);
	added++;
	if( !ok2 ){
		LE("--addACL failed err=%d %s",GetLastError(),path);
	}

SETOWN:
	if( aty & A_OWN ){
		ok1 = SetSecurityDescriptorOwner(asd,mid,1);
		added++;
	}
	if( aty & A_GRP ){
		ok1 = SetSecurityDescriptorGroup(asd,mid,1);
		added++;
	}
	return added;
}
static void dumpSD(void *ssd,int lsacl){
	PSID usid,gsid;
	IStr(uname,128);
	IStr(udom,128);
	IStr(gname,128);
	IStr(gdom,128);
	PACL odacl;
	int odaclis;
	int ok1,ok2,ok3;
	int rf1,rf2,rf3;
	IStr(stype,128);

	ok1 = GetSecurityDescriptorOwner(ssd,&usid,&rf1);
	siduserdom(usid,AVStr(uname),AVStr(udom),AVStr(stype));
	ok2 = GetSecurityDescriptorGroup(ssd,&gsid,&rf2);
	siduserdom(gsid,AVStr(gname),AVStr(gdom),AVStr(stype));
	ok3 = GetSecurityDescriptorDacl(ssd,&odaclis,&odacl,&rf3);
	if( 1 <= LOGLEVEL || !ok1 || !ok2 || !ok3 || lsacl )
	LE("--addACL OWN%d%d[%s@%s] GRP%d%d[%s@%s] AD%d%d[%d/%X]",
		ok1,rf1,uname,udom,
		ok2,rf2,gname,gdom,
		ok3,rf3,odaclis,odacl);
	dumpACL("GSD",odacl);
}
int addFileACL(const char *path,PCStr(owner),PCStr(acl),int lsacl){
	IStr(pown,128);
	IStr(pgrp,128);
	long ssd[512];
	unsigned long qsiz;
	int qt;
	int ok1,ok2,ok3;
	int added;
	int rcode = -1;

	if( lsacl ){
		IStr(fow,128);
		IStr(fgr,128);
		getcuser(AVStr(pown),sizeof(pown),AVStr(pgrp),sizeof(pgrp));
		getowner(path,AVStr(fow),sizeof(fow),AVStr(fgr),sizeof(fgr));
		LE("--addACL PROC[%s@%s] FILE[%s@%s] %s ...",
			pown,pgrp,fow,fgr,path);
	}

	qt = OWNER_SECURITY_INFORMATION
	   | GROUP_SECURITY_INFORMATION
	   | DACL_SECURITY_INFORMATION;

	if( GetFileSecurity(path,qt,ssd,sizeof(ssd),&qsiz) == 0 ){
		if( 1 <= LOGLEVEL || ServerMain && SERNO()==0 || lsacl )
		LE("--addACL can't GetFileSecirity(%s): %d err=%d",
			path,qsiz,GetLastError());
		return -1;
	}

	if( lsacl ){
		dumpSD(ssd,lsacl);
		if( owner == 0 || *owner == 0 )
		if( acl == 0 || *acl == 0 ){
			return 0;
		}
	}

	/* SYSTEM (service) should have full-access to it  */
	/*
	if( !streq(pown,"SYSTEM") && !streq(pgrp,"SYSTEM") ){
		LE("--chwon ok [%s@%s] %s",uname,gname,path);
	}else
	*/
	{
		long asd[128];
		ACL dacl[128];
		ACL sacl;
		long own[128];
		long grp[128];
		unsigned long daclz,saclz,ownz,grpz;
		IStr(account1,128);
		const char *ap;
		long amid[8][128];
		int midx = 0;

		qsiz = sizeof(asd);
		daclz = sizeof(dacl);
		saclz = sizeof(sacl);
		ownz = sizeof(own);
		grpz = sizeof(grp);

		dacl[0].AclSize = 0;
		dacl[0].AceCount = 0;
		ok1 = MakeAbsoluteSD(ssd,asd,&qsiz,dacl,&daclz,
			&sacl,&saclz,own,&ownz,grp,&grpz);
		//dumpACL("MkA",dacl);

		if( 1 <= LOGLEVEL || !ok1 )
		LE("--addACL ok=%d DACL valid=%d z=%d %d,%d / %d err=%d %s",
			ok1,IsValidAcl(dacl),sizeof(ACL),daclz,dacl[0].AclSize,
			dacl[0].AceCount,GetLastError(),path);
			dacl[0].AclSize = sizeof(dacl);

		added = 0;
		if( owner && *owner ){
			IStr(aown,128);
			IStr(agrp,128);
			sscanf(owner,"%[^/]/%s",aown,agrp);
			if( aown[0] )
			if( 0 < addACL(asd,dacl,path,A_OWN,amid[midx++],sizeof(amid[0]),aown,GENERIC_ALL) ){
				added++;
			}
			if( agrp[0] )
			if( 0 < addACL(asd,dacl,path,A_GRP,amid[midx++],sizeof(amid[0]),agrp,GENERIC_ALL) ){
				added++;
			}
			if( 0 < added ){
				if( ServerMain )
				LE("--set FILEOWNER=%s %s",owner,path);
			}
		}
		if( acl && *acl ){
		    for( ap = acl; *ap; ){
			ap = scan_ListElem1(ap,',',AVStr(account1));
			if( *account1 == 0 )
				break;
			if( 0 < addACL(asd,dacl,path,0,amid[midx++],sizeof(amid[0]),account1,GENERIC_ALL) ){
				if( ServerMain )
				if( !lSINGLEP() || !lINITDONE() )
				LE("--set FILEACL=%s %s",acl,path);
				added++;
			}
			if( elnumof(amid) <= midx ){
				break;
			}
		    }
		}
		if( 0 < added ){
			if( SetFileSecurity(path,qt,asd) ){
				rcode = 0;
			}else
			if( GetLastError() == ERROR_NO_SYSTEM_RESOURCES ){
			    syslog_ERROR("--addACL err=%d SetFileSecurity(%s)\n",
					GetLastError(),path);
			}else{
				LE("--addACL failed FILEOWNER=%s FILEACL=%s err=%d SetFileSecurity(%s)",
					FILEOWNER,FILEACL,GetLastError(),path);
			}
		}
	}
	return rcode;
}
void lsacl(PCStr(path),PCStr(owner),PCStr(acl)){
	LOG_type |= 0xF & (LOG_type+1);
	addFileACL(path,owner,acl,1);
}

int File_is(PCStr(path));
int INHERENT_chown(){ return 0; }
int SUBST_chown = 1;
int chown(const char *path,int uid,int gid){
	int rcode = -1;
	if( File_is(path) == 0 ){
		LV("No such file: chown(%s)",path);
		return rcode;
	}
	if( FILEOWNER && *FILEOWNER || FILEACL && *FILEACL ){
		addFileACL(path,FILEOWNER,FILEACL,0);
	}
	return rcode;
}
#endif /*} !WindowsCE */

#undef signal
typedef void (*sigFunc)(int);
sigFunc winSignal(int sig,sigFunc func){
	if( sig <= 0 ){
		return 0;
	}
	return signal(sig,func);
}

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 0
static HANDLE last_fmh[2];
void *mmap(void *adr,size_t len,int pro,int flg,int fd,off_t off){
	void *addr;
	HANDLE fh,fmh;
	int protect;
	int acc;
	int rw;
	int Err;

	fh = (HANDLE)_get_osfhandle(fd);
	if( pro == PROT_READ ){
		protect = PAGE_READONLY;
		acc = FILE_MAP_READ;
	}else{
		protect = PAGE_READWRITE;
		acc = FILE_MAP_WRITE;
	}

	fmh = CreateFileMapping(fh,NULL,protect,0,len,NULL);
	Err = GetLastError();
	if( last_fmh[0] == 0 )
		last_fmh[0] = fmh;
	else	last_fmh[1] = fmh;
	addr = MapViewOfFile(fmh,acc,0,off,len);
	Err = GetLastError();
	return addr;
}
int munmap(void *adr,size_t le){
	int ok = UnmapViewOfFile(adr);
	if( last_fmh[0] ){
		CloseHandle(last_fmh[0]);
		last_fmh[0] = 0;
	}
	if( last_fmh[1] ){
		CloseHandle(last_fmh[1]);
		last_fmh[0] = 0;
	}
	return ok ? 0 : -1;
}
#if !defined(UNDER_CE)	
#define CreateFileForMapping CreateFile
#endif

#undef filemmap
#undef freemmap
MMap *filemmap(PCStr(fname),PCStr(fmode),int off,int len){
	HANDLE fh,mh;
	void *addr;
	const unsigned char *bp;
	MMap *mmap;
	int rdonly;
	int fshare;
	int frw;
	int fmk;
	SECURITY_ATTRIBUTES sa;
	int fd;
	int prot;
	int mapprot;
	FILE *fp;
	IStr(path,1024);

	if( lNOMMAP() ){
		return 0;
	}

	rdonly = (fmode[0] == 'r') && (fmode[1] != '+');
	if( rdonly ){
		fshare = FILE_SHARE_READ;
		frw = GENERIC_READ;
		fmk = OPEN_EXISTING;
		prot = PAGE_READONLY;
		mapprot = FILE_MAP_READ;
	}else{
		fshare = FILE_SHARE_READ|FILE_SHARE_WRITE;
		frw = GENERIC_READ|GENERIC_WRITE;
		if( fmode[0] == 'r' )
			fmk = OPEN_EXISTING;
		else	fmk = CREATE_NEW;
		prot = PAGE_READWRITE;
		mapprot = FILE_MAP_READ|FILE_MAP_WRITE;
	}
	if( *fname == 0 ){
		fh = INVALID_HANDLE_VALUE;
		fd = -1;
		fp = 0;
	}else{
		strcpy(path,fname);
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = 1;

		fh = CreateFileForMapping(path,frw,fshare,&sa,
			fmk,FILE_ATTRIBUTE_NORMAL,NULL);

		if( fh == 0 || fh == INVALID_HANDLE_VALUE )
		if( !rdonly ){
		fh = CreateFileForMapping(path,frw,fshare,NULL,
			OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		}
		if( fh == 0 || fh == INVALID_HANDLE_VALUE ){
			return 0;
		}
		fd = _open_osfhandle((int)fh,0);
		fp = fdopen(fd,fmode);
	}

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = 1;
	mh = CreateFileMapping(fh,&sa,prot,0,len,NULL);
	if( mh == 0 || mh == INVALID_HANDLE_VALUE ){
		return 0;
	}

	SetLastError(0);
	addr = MapViewOfFile(mh,mapprot,0,off,len);
	bp = (const unsigned char*)addr;
	/*
	fprintf(stderr,"--3 fmmap[%X]%X %X[%X][%X] Err=%d [%d,%d]\n",fh,mh,addr,
		bp?bp[0]:-1,bp?bp[1]:-2,GetLastError(),off,len);
	*/
	if( len == 0 ){
		len = GetFileSize(fh,0);
	}
	mmap = (MMap*)malloc(sizeof(MMap));
	mmap->m_addr = addr;
	mmap->m_size = len;
	mmap->m_fp = fp;
	mmap->m_mh = mh;
	mmap->m_fh = fh;
	LV("--filemmap(%X,%X,%X,%X)\n",mmap,mmap->m_addr,mmap->m_mh,mmap->m_fh);
/*
fprintf(stderr,"--filemmap(%s,%s)%X,%X,%X,%X\n",
fname,fmode,mmap,mmap->m_addr,mmap->m_mh,mmap->m_fh);
*/
	return mmap;
}
int freemmap(MMap *mmap){
	int res;

	if( mmap == 0 ){
		return -1;
	}
	LV("--freemmap(%X,%X,%X,%X)\n",mmap,mmap->m_addr,mmap->m_mh,mmap->m_fh);
	res = UnmapViewOfFile(mmap->m_addr);
	res = CloseHandle(mmap->m_mh);
	if( mmap->m_fp ){
		fclose(mmap->m_fp); /* includes CloseHandle(mmap->m_fh) */
	}else{
		res = CloseHandle(mmap->m_fh);
	}
	free(mmap);
	return 0;
}
void *getmmap(MMap *mmap){
	return mmap->m_mh;
}
void *setmmap(void *mh,int off,int len){
	void *addr;
	int mapprot;
	mapprot = FILE_MAP_READ|FILE_MAP_WRITE;
	addr = MapViewOfFile((HANDLE)mh,mapprot,0,off,len);
	return addr;
}


#if !isWindowsCE() /*{*/ /*-- Win32 --*/
#undef open
int open_FL(FL_Par,const char *path,int flag){
	int fd;
	fd = open(path,flag);
	/* open() seems WCHAR capable ? */
	return fd;
	/*
	return open(path,flag);
	*/
}

#undef fclose /* fclose() */
int XX_fclose_FL(FL_PAR,FILE *fp){
	int fd;
	int sock;
	int rcode;

	fd = fileno(fp);
	sock = SocketOf(fd);
	if( sock ){
		fflush(fp);
		rcode = closeSocket_FL(FL_BAR,fd,sock);
		rcode = fclose(fp);
	}else{
		rcode = fclose(fp);
	}
	return rcode;
}


int Fseeko(FILE *fp,FileSize off,int whence){
#if 1400 <= _MSC_VER
	return _fseeki64(fp,off,whence);
#else
	return fseek(fp,off,whence);
#endif
}
FileSize Ftello(FILE *fp){
#if 1400 <= _MSC_VER
	return _ftelli64(fp);
#else
	return ftell(fp);
#endif
}

#undef abort
void abortX(FL_PAR){
	fprintf(stderr,"abortX() <= %s:%d\n",FL_BAR);
	fflush(stderr);
	LE("abortX() <= %s:%d",FL_BAR);
	abort();
}
#undef exit /* exit() */
void exitX(int code,FL_PAR){
	if( lSINGLEP() ){
		fprintf(stderr,"exitX(%d) <= %s:%d\n",code,FL_BAR);
		fflush(stderr);
		LE("exitX(%d) <= %s:%d",code,FL_BAR);
	}
	exit(code);
}

#undef _exit /* _exit() */
void _exitX(int code,FL_PAR){
	if( lSINGLEP() ){
		fprintf(stderr,"_exitX(%d) <= %s:%d\n",code,FL_BAR);
		fflush(stderr);
		LE("_exitX(%d) <= %s:%d",code,FL_BAR);
	}
	_exit(code);
}

/*
int getAnswerYN(PCStr(msg),PVStr(ans),int siz){
	int buttons;
	int code;

	buttons = MB_YESNO|MB_ICONQUESTION|MB_SETFOREGROUND;
	code = MessageBox(NULL,msg,"DeleGate/YesNo",buttons);
	switch( code ){
		case IDYES: sprintf(ans,"y"); break;
		default: sprintf(ans,"n"); break;
	}
	return 0;
}
int getAnswerYNWTO(double dtx,PCStr(msg),PVStr(ans),int siz){
	int code;
	code = getAnswerYN(msg,BVStr(ans),siz);
	return code;
}
int askWinOK(PCStr(fmt),...){
	int buttons;
	IStr(msg,1024);
	int code;
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	buttons = MB_OK|MB_ICONQUESTION|MB_SETFOREGROUND|MB_TOPMOST;
	code = MessageBox(NULL,msg,"DeleGate/Ok",buttons);
	return code;
}
int askWinOKWTO(double dtx,PCStr(fmt),...){
	int code;
	VARGS(16,fmt);

	code = askWinOK(fmt,VA16);
	return code;
}

int updateActiveLamp(int act){
	return -1;
}
void popupConsole(){
}
*/
int setfdowner(int fd,int tid,int tgid){
	return -1;
}
/*
void setWinClassTitleStyle(PCStr(wclass),PCStr(wtitle),PCStr(wstyle)){
}
void putWinStatus(PCStr(fmt),...){
}
*/
int disableWinCtrl(FILE *fp){
	return -1;
}
/*
int ps_unix(FILE *out){
	return -1;
}
*/
int setferror(FL_PAR,FILE *fp){
	fp->_flag |= _IOERR;
	return 0;
}
int dialupTOX(PCStr(wh),int asock,void *addr,int leng,int timeout,PVStr(cstat)){
	return -1;
}

int WinMainArgv(const char *av[],int mac,PVStr(cls),PVStr(clb)){
	const char *cll;
	int ac;

	cll = GetCommandLine();
	strcpy(cls,cll);
	ac = decomp_args(av,mac,cll,AVStr(clb));
	return ac;
}
#endif /*} !WindowsCE */

int toUTF8(unsigned int uc,unsigned char *us);
int wstrtostrX(int sz,char *dst,WCHAR *src,int esc){
	const WCHAR *sp;
	char *dp = dst;
	char *dpx = &dst[sz-1];

	if( dst == 0 )
		return 0;
	for( sp = src; *sp; sp++ ){
		if( dpx <= dp ){
			break;
		}
		if( (*sp & 0xFF80) == 0 )
			*dp++ = *sp;
		else{
			dp += toUTF8((unsigned int)*sp,(unsigned char*)dp);
		}
	}
	*dp = 0;
	if( dp+1 < dpx ){ dp[1] = 0; } /* for list of str */
	return 0;
}
unsigned int FromUTF8(unsigned char *us,int *lengp);
int fromSafeFileName(PCStr(name),PVStr(xname));
int strtowstrX(int sz,WCHAR *dst,PCStr(src),int esc){
	const char *sp;
	WCHAR *dp = dst;
	WCHAR *dpx = &dst[sz-1];
	unsigned int uc;
	int len;
	IStr(xsrc,1024);

	/*
	if( esc == ESC_URL ){
		fromSafeFileName(src,AVStr(xsrc));
		if( strcmp(src,xsrc) != 0 ){
//_Fprintf(stderr,"----unescaped %d -> %d [%s]\n",strlen(src),strlen(xsrc),src);
			src = xsrc;
		}
	}
	*/
	if( dst == 0 )
		return 0;
	for( sp = src; *sp; sp ){
		if( dpx <= dp ){
			break;
		}
		if( *sp & 0x80 ){
			uc = FromUTF8((unsigned char*)sp,&len);
			if( len <= 0 || 5 < len || (uc & 0xFFFF0000) ){
				break;
			}
			*dp++ = uc;
			sp += len;
		}else
		{
			*dp++ = *sp;
			sp += 1;
		}
	}
	*dp = 0;
	if( dp+1 < dpx ){ dp[1] = 0; } /* for list of str */
	return dp - dst;
}
int withwchar(const char *path,WCHAR *wpath,int wsize){
	const char *sp;
	for( sp = path; *sp; sp++ ){
		if( *sp & 0x80 ){
			strtowstrX(wsize,wpath,path,0);
			return 1;
		}
	}
	return 0;
}
FILE *wfopenX(const char *path,const char *mode){
	WCHAR wpath[1024];
	WCHAR wmode[32];
	FILE *fp;

	if( withwchar(path,wpath,elnumof(wpath)) ){
		strtowstrX(elnumof(wmode),wmode,mode,0);
		fp = _wfopen(wpath,wmode);
		if( fp != 0 ){
			fprintf(stderr,"---- ---- wfopen(%s)=%X\n",path,fp);
			return fp;
		}
	}
	return 0;
}

#endif
//////////////////////////////////////////////////////////////////////////
#endif
//////////////////////////////////////////////////////////////////////////
