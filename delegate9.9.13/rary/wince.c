const char *SIGN_wince_c="{FILESIGN=wince.c:20141031194212+0900:100ad7b9b54458f1:Author@DeleGate.ORG:py3Yrkek2I4P0yPb+61l5lGU8X535cmvSJwNHrDThRu3FzsR+uScvJ2WZKro/vHX+plxhqWUoTpQEum1DUQqmt2cbhPN/9mMQWIFbfULv9bA0as7Xj6QmWLpaQroxESzRNyG2ci6Dd4a9S9A+xMQ/Oabq25XX43ZsL5amoUD9bc=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2007-2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

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
Program:	wince.c (for Windows CE)
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
History:
	071117	created
//////////////////////////////////////////////////////////////////////#*/
/* '"DiGEST-OFF"' */

#if defined(_MSC_VER) && !defined(UNDER_CE) /*#################*/
#define _WINSOCKAPI_ /* Prevent inclusion of winsock.h in windows.h */
#define UNICODE
#include <WINDOWS.H>
#include <WINBASE.H>
#include "vsocket.h"
#include "config.h"
#include "ystring.h"
#include "file.h"
#include "log.h"
#endif

#ifndef UNDER_CE /*{*/
#include "ystring.h"

#ifndef _MSC_VER /*{*/
int FMT_putInitlog(const char *fmt,...){
	return -1;
}
int dumpScreen(FILE *fp){
	fprintf(fp,"Screen dump not supported\n");
	return -1;
}
const char *ControlPanelText(){
	return "";
}
#endif /*}*/

int unamef(PVStr(uname),PCStr(fmt)){
	return -1;
}
int setNonblockingFpTimeout(FILE *fp,int toms){
	return -1;
}
char *printnetif(PVStr(netif)){
	strcpy(netif,"127.0.0.1 192.168.1.2 192.168.0.2");
	return (char*)netif;
}
int setosf_FL(const char *wh,const char *path,int fd,FILE *fp,const char *F,int L){
	return -1;
}
#endif /*}*/

/* FrOM-HERE
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */

#if defined(_MSC_VER) && !defined(UNDER_CE) /*#################*/
const char *DELEGATE_verdate();
int setNonblockingIO(int fd,int on);
int clearAuthMan();

#define ESC_NONE 0
#define ESC_URL  1
int wstrtostrX(int sz,char *dst,WCHAR *src,int esc);
int strtowstrX(int sz,WCHAR *dst,PCStr(src),int esc);
#define wstrtostr(dst,src,e) wstrtostrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
#define strtowstr(dst,src,e) strtowstrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
static const WCHAR *_T(const char *s){
	static WCHAR buf[2][64];
	static int ci;
	WCHAR *bp;
	bp = buf[ci++ % 2];
	strtowstrX(64,bp,s,0);
	return bp;
}

static struct {
	MStr(i_msg,256);
} IMsg;
static struct {
	double	poT;
	double	poTMax;
	int	poN;
	int	poZ;
	int	poX;
} POut;
static struct {
	int	r_notify;
	int	r_nwritten;
	int	r_checked;
	int	r_tested;
	int	r_reset;
	int	r_noreset;
	int	r_resetting;
	int	r_diffsec;
	int	r_difftck;
	int	r_notifytck;
	int	r_lasttck;
     SYSTEMTIME r_lastst;
} resettick;

static int Terminating; // Terminated manually
static int Finishing;

static int _main_thread;
extern int refreshWinStatus;
extern int THEXIT;
#define THEX_DO    1
#define THEX_DOING 2
#define THEX_DONE  3

static int TotalOpen;
static int TotalRead;
static int TotalWrote;
static int TotalClose;
static double TotalOpenTime;
static double TotalReadTime;
static double TotalWriteTime;
static double TotalCloseTime;
static int SleptMsec;
static int LOGX_GetFa;
static double LOGX_GetFaElp;
static char *do_pause;
static char *StorageCard;
static int CF_NUM;
static int CF_OK;
static int CF_RET;
static int CF_ERR;
static int CF_DEV;
static int CF_NOTMP;

static void settick0(){
}
void resetIdleTimer();
int GetIdleTime(){
	return 0;
}
int SystemIdleTimerReset(){
	return 0;
}

int getNullFd(const char *wh);
static int terminatemainthread(const char *F2,int L2,const char *fmt,...){
	THEXIT = THEX_DO;
	return 0;
}
static void filecloser(){
}
static void setdbg(const char *flags){
}
static int Igetc(FILE *fp){
	return getc(fp);
}
static int getStartMenu(PVStr(rpath),PVStr(xpath)){
	return 0;
}
static int addStartMenu(PVStr(rpath)){
	return -1;
}
static int getStartUp(PVStr(stup),PVStr(xpath)){
	return 0;
}
static int delStartMenu(PVStr(rpath)){
	return -1;
}
static int addStartUp(PCStr(path),PVStr(sstat)){
	return -1;
}

int ps_unix(FILE *out);
void popupConsole();
int updateActiveLamp(int act);
int askWinOK(PCStr(fmt),...);
int askWinOKWTO(double dtx,PCStr(fmt),...);
int getAnswerYN(PCStr(msg),PVStr(ans),int siz);
void putWinStatus(PCStr(fmt),...);
int dialupTOX(PCStr(wh),int asock,void *addr,int leng,int timeout,PVStr(cstat));

int tryConnection(PCStr(dsturl),PVStr(cstat)){
	return -1;
}
int withActiveConnections(int op){
	return 1;
}
int releaseConnections(PVStr(msg)){
	return -1;
}
char *doPing(PCStr(addr),int timeout,int count,PVStr(stat)){
	return "";
}
char *printConnMgr(PVStr(cstat),int showall,int simple,int doconn){
	return "";
}
char *findConnMgr(PVStr(cstat),PCStr(fmt),PCStr(type),PCStr(subtype)){
	return "";
}
char *devpwstat(PVStr(stat),PCStr(dev),int force){
	return "";
}
int setsyspower(const char *name,int flag,int *pflag){
	return 0;
}
HBITMAP SHLoadDIBitmap(WCHAR*wpath){
	HBITMAP bm;
	bm = (HBITMAP)LoadImage(0,wpath,IMAGE_BITMAP,0,0,LR_LOADFROMFILE);
	return bm;
}

#undef fopen
static FILE *XX_fopen_FL(FL_PAR,PCStr(path),PCStr(mode)){
	return fopen(path,mode);
}
#undef fclose
static int XX_fclose_FL(FL_PAR,FILE *fp){
	return fclose(fp);
}
#undef fflush
static int XX_fflush_FL(FL_PAR,FILE *fp){
	return fflush(fp);
}
#undef XX_fwrite
#undef fwrite
static int XX_fwrite(FL_PAR,const void *buf,int siz,int nel,FILE *fp){
	return fwrite(buf,siz,nel,fp);
}
#undef XX_feof
#undef feof
static int XX_feof(FILE *fp){
	return feof(fp);
}
#undef fseek
static int XX_fseek(FILE *fp,int off,int wh){
	return fseek(fp,off,wh);
}
#undef fgets
static char *XX_fgets(PVStr(buf),int siz,FILE *fp){
	return fgets((char*)buf,siz,fp);
}
#endif /*######################################################*/

extern int DGZ_DEBUG;
#define DBG_ERR  'E'
#define DBG_WARN 'W'
#define DBG_DESC 'D'
#define DBG_FILE 'F'
#define DBG_BUFF 'B'
#define DBG_LINK 'L'
#define DBG_PORT 'P'
#define DBG_SOCK 'S'
#define DBG_STAT 'T'
#define DBG_MEMF 'M'
#define DBG_MEMFx 'N'

#define flDBG(f) (1 << (f)-'A')
#define inDBG(f) (WCE_DEBUGS & flDBG(f))
#define doDBG(f) (WCE_DEBUGS |= flDBG(f))

static int notty;
static int _Fprintf(void *fp,const char *fmt,...);
#define WCE_ERR  inDBG(DBG_ERR )==0?0:_Fprintf
#define WCE_WARN inDBG(DBG_WARN)==0?0:_Fprintf
#define WCE_DESC inDBG(DBG_DESC)==0?0:_Fprintf
#define WCE_FILE inDBG(DBG_FILE)==0?0:_Fprintf
#define WCE_BUFF inDBG(DBG_BUFF)==0?0:_Fprintf
#define WCE_LINK inDBG(DBG_LINK)==0?0:_Fprintf
#define WCE_PORT inDBG(DBG_PORT)==0?0:_Fprintf
#define WCE_SOCK inDBG(DBG_SOCK)==0?0:_Fprintf
#define WCE_STAT inDBG(DBG_STAT)==0?0:_Fprintf
#define WCE_MEMF inDBG(DBG_MEMF)==0?0:_Fprintf
#define WCE_MEMFx inDBG(DBG_MEMF)==0&&inDBG(DBG_MEMFx)==0?0:_Fprintf

int WCE_DEBUGS = flDBG(DBG_ERR);
int WCE_sDEBUG(){ return inDBG(DBG_SOCK); }

int getthreadid();
#ifndef PRTID
#define PRTID(tid) (0xFFFF & tid)
#endif
#define TID PRTID(getthreadid())
#define XTID TID,CHILD_SERNO_MULTI
extern int CHILD_SERNO_MULTI;

static void thexitX(const char *F,int L,const char *F2,int L2,int code);
#define thexit(F,L,code) thexitX(__FUNCTION__,__LINE__,F,L,code)

int SocketOf_FL(const char *F,int L,int fd);
#define SocketOf(fd) SocketOf_FL(__FILE__,__LINE__,fd)

#ifdef UNDER_CE /*{*/
#define UNICODE
#include <WINDOWS.H>
#include <WINBASE.H>

static int _main_thread;
extern int refreshWinStatus;
extern int THEXIT;
#define THEX_DO    1
#define THEX_DOING 2
#define THEX_DONE  3

static double fxcs[16];
int setupCSC(const char *wh,void *acs,int asz);
int enterCSC_FL(const char *F,int L,void *cs);
#define enterCSC(cs) enterCSC_FL(__FILE__,__LINE__,cs)
int leaveCSC_FL(const char *F,int L,void *cs);
#define leaveCSC(cs) leaveCSC_FL(__FILE__,__LINE__,cs)

#define CLOSED_HANDLE_VALUE -2

static void setdbg(const char *flags){
	const char *fp;
	int f;
	for( fp = flags; f = *fp; fp++ ){
		if( 'A' <= f && f <= 'Z' )
			doDBG(f);
		else
		if( f == 'a' )
			WCE_DEBUGS = 0xFFFFFFFF;
	}
}

static char *do_pause;
static char *adminpass = "";
static int pausemainX(const char *wh);
#define pausemain(wh) do_pause?pausemainX(wh):0

int _getpid();
long int _time32(long int *t);
int _sleep(int);
extern "C" {
	int getpid(){
		//_Fprintf(stderr,"----WinCE getpid()\n");
		return _getpid();
	}
	time_t time(time_t *clock){
		int ut;
		ut = _time32((long int*)clock);
		//_Fprintf(stderr,"----WinCE time()\n");
		return ut;
	}
	int sleep(int sec){
		_Fprintf(stderr,"----WinCE sleep(%d)\n",sec);
		return _sleep(sec);
	}
}
#endif /*}*/
static int Iftell(FILE *fp){
	return ftell(fp);
}
static int Ifflush(FILE *fp){
	return fflush(fp);
}
static int Ifclose(FILE *fp){
	return fclose(fp);
}


#if defined(UNDER_CE) /*{*/
//---- no environ on WinCE
static char *env0[32] = {
	"USER=WinCE",
	"HOME=/",
	0
};
char **environ = env0;
const char *strheadstrX(const char *s,const char *t,int igncase);
char *getenv(const char *name){
	int ei;
	const char *e1;
	const char *b1;
	if( environ == 0 )
		return 0;
	for( ei = 0; e1 = environ[ei]; ei++ ){
		if( b1 = strheadstrX(e1,name,0) ){
			if( *b1 == '=' ){
	//_Fprintf(stderr,"---- getenv(%s=%s)\n",name,b1+1);
				return (char*)b1+1;
			}
		}
	}
	return 0;
}
static int myputenv(const char *env);
int putenv(const char *env){
	return myputenv(env);
}
//------- handling open file
long lseek(int fd,long off,int wh){
	_Fprintf(stderr,"----WinCE lseek %d\n",fd);
	return -1;
}

int _get_osfhandle_FL(const char *F,int L,int fd);
static int isMemDevHandle(int fh);

int _read(int fd,char *buf,unsigned int size);
static int MemRead(int fd,void *buf,int siz);
int read(int fd,void *buf,int size){
	int rcc;
	int fh;

	fh = _get_osfhandle_FL(__FUNCTION__,__LINE__,fd);
	if( isMemDevHandle(fh) ){
		rcc = MemRead(fd,buf,size);
		WCE_MEMF(stderr,"MEM_read  [%d] %d/%d\n",fd,rcc,size);
		return rcc;
	}
	/* should do setfh() */
	rcc = _read(fd,(char*)buf,size);
	/* _read() returns strange value for invalid fd */
	if( size < rcc ){
		_Fprintf(stderr,"----!!!! read(%d,%d)=%d\n",fd,size,rcc);
		getc(stdin);
		size = rcc;
	}
	if( rcc <= 0 ){
		WCE_SOCK(stderr,"----WinCE read %d %d\n",fd,rcc);
	}
	return rcc;
}
int syslog_ERROR(const char *fmt,...);
int syslog_DEBUG(const char *fmt,...);
int _write(int fd,const char *,unsigned int size);
int write(int fd,const void *buf,int len){
	int wcc;
	int fh;

	fh = _get_osfhandle_FL(__FUNCTION__,__LINE__,fd);
	if( isMemDevHandle(fh) ){
		wcc = -1;
 _Fprintf(stderr,"!!!!!############## MEM_write [%d] %d/%d\n",fd,wcc,len);
 syslog_ERROR("!!!!!#### NOT-SUPPORTED write() to MemDev [%d] %d/%d\n",fd,wcc,len);
		return wcc;
	}

	if( fd == (int)fileno(stderr) || fd == (int)fileno(stdout) ){
	}
	wcc = _write(fd,(const char*)buf,len);
	if( wcc <= 0 ){
		WCE_SOCK(stderr,"----WinCE write %d/%X = %d/%d %X/%X\n",
			fd,fd,wcc,len,fileno(stderr),fileno(stdout));
	}
	return wcc;
}
int isatty(int fd){
	//_Fprintf(stderr,"----WinCE isatty(%d/%X) [%X %X %X]\n",
	//fd,fd,fileno(stdin),fileno(stdout),fileno(stderr));
	if( fd == 0 || fd == 1 || fd == 2 )
		return 1;
	if( fd == (int)fileno(stdin)
	 || fd == (int)fileno(stdout)
	 || fd == (int)fileno(stderr) )
		return 2;
	return 0;
}
int locking(int fd,int,int){
	_Fprintf(stderr,"----WinCE locking(%X)\n",fd);
	return 0;
}

int doCloseHandle(int oh){
	CloseHandle((HANDLE)oh);
	return 0;
}

//-- process
int _getpid(){
	int pid;
	pausemain("_getpid");
	pid = GetCurrentProcessId();
	return pid;
}

int errno;
int *_errno(){ return &errno; };
int perror(const char *msg){
	_Fprintf(stderr,"%s: errno=%d\n",msg);
	return 0;
}

typedef void (*sigFunc)(int);
sigFunc signal(int sig,sigFunc func){
	pausemain("signal");
	//_Fprintf(stderr,"----WinCE signal(%d,%X)\n",sig,func);
	return 0;
}
int raise(int sig){
	pausemain("raise");
	_Fprintf(stderr,"----WinCE raise(%d)\n",sig);
	return -1;
}

//----------------------------------
int usleep(unsigned int timeout);
int _sleep(int msec){
	if( msec == 0 )
		return 0;
	usleep(msec*1000);
	return 0;
}

//------------------------ STDIO
void setlinebuf(FILE *fp){
}
long lseek(int fd,long off,int wh);
int rewind(FILE *fp){
	int off;
	off = lseek((int)fileno(fp),0,0);
	return off;
}
void _rmtmp(){
}

int getthreadgid(int tid);

int daemonlog(const char *sel,const char *fmt,...);

//---- service
int start_service(int,char const * * const){
	return 0;
}
int delete_service(int,char const * * const,char const *,char const *){
	return 0;
}
int restart_service(char const *,int,char const * * const){
	return 0;
}
int create_service(int,char const * * const,char const *){
	return 0;
}
void regPutVec(char const *,char const *,int,char const * * const){
}
int regGetVec(char const *,char const *,int,char const * * const){
	return -1;
}
void lsacl(char const *,char const *,char const *){
}
int getcuser(char const *,int,char const *,int,char const * const,int,char const *,int,char const *,int,char const * const,int){
	return -1;
}
int getowner(char const *,char const *,int,char const *,int,char const * const,int,char const *,int,char const *,int,char const * const,int){
	return -1;
}
int fromclockLocal(long,int *,int *,int *,int *,int *,int *,int *){
	return -1;
}

//--------------------------------------------------------------------{
int INHERENT_spawn(){
	return 1;
}
int SPAWN_P_NOWAIT = 0;
int execlp(const char *path,...){
	_Fprintf(stderr,"----WinCE execlp()\n");
	return -1;
}
int execl(const char *path,...){
	_Fprintf(stderr,"----WinCE execvl(%s)\n",path);
	return -1;
}
int execvp(const char*path,char *const*arg){
	_Fprintf(stderr,"----WinCE execvp(%s)\n",path);
	return -1;
}
int _execvp(char const *path,char const**const av){
	_Fprintf(stderr,"----WinCE _execvp(%s)\n",path);
	return -1;
}

FILE *_popen(const char *com,const char *mdoe){
	_Fprintf(stderr,"----WinCE _popen(%s)\n",com);
	return 0;
}
int system(const char *com){
	_Fprintf(stderr,"----WinCE system(%s)\n",com);
	return -1;
}

int umask(int mask){
	_Fprintf(stderr,"----WinCE umask(%x)\n",mask);
	return -1;
}
int creat(const char *path,int mode){
	return -1;
}
int stat(const char *path,struct stat *st);
__int64 lstati64(char const *path,struct stat *st){
	WCE_FILE(stderr,"----WinCE lstati64(%s)\n",path);
	return stat(path,st);
}
__int64 stati64(char const *path,struct stat *st){
	int rcode;
	WCE_FILE(stderr,"----WinCE stati64(%s)\n",path);
	rcode = stat(path,st);
	return rcode;
}
int _stati64(char const *path,struct _stati64 *st){
	WCE_FILE(stderr,"----WinCE _stati64(%s)\n",path);
	return -1;
}
int chmod(const char *path,int mode){
	WCE_FILE(stderr,"----WinCE _stati64(%s,%o)\n",path,mode);
	return -1;
}
//--------------------------------------------------------------------}
int sleep(int);
int unlink(const char *path);

#define MINOSF 0
#define MAXOSF 1024
static void *_nuldevhandle = (void*)0x7FFF;
static int _nuldevfd = -1;

int Xfileno(FILE *fp){
	/*
	void *fd;
	fd = fileno(fp);
	if( SocketOf(
	*/
	return (int)fileno(fp);
}

#define MAXDUP	128
static struct {
	int d_fh;
	int d_cnt;
	int d_tid;
} _duph[MAXDUP];

static int _duphn;
typedef struct {
	int o_fh;
	int o_time;
	char o_act;
	char o_free; /* not owned by any thread */
	const char *o_F;
	int o_L;
	int o_ser;
	int o_tid;
	int o_tgid;
} OSF;
static void *_osf_Lock[16];
static char o_path[32][256];
static OSF _osfhandles[MAXOSF];
static int _osfn;
static int _osdn;
#define F_ACT 1
#define F_DUP 2

#define lock_osf() 0
#define unlock_osf() 0

static void LockOSF(){
	setupCSC("lock_osf",_osf_Lock,sizeof(_osf_Lock));
	enterCSC(_osf_Lock);
}
static void UnLockOSF(){
	leaveCSC(_osf_Lock);
}

void dumposf(FILE *tc,const char *wh,int min,int max,int dup){
	int fi;
	int act;
	int fh;
	OSF *osf;

	_Fprintf(tc,"-- %X OSF %d/%d (%s)\n",TID,_osfn,_osdn,wh);
	for( fi = min; fi < MAXOSF; fi++ ){
		/*
		if( 0 < max && max < fi ){
			break;
		}
		*/
		osf = &_osfhandles[fi];
		if( act = osf->o_act ){
			fh = osf->o_fh;
			_Fprintf(tc,"--FD[%2d] %X %4X %d %X/%u #%d %X",
				fi,osf->o_time,PRTID(osf->o_tid),act,fh,fh,osf->o_ser);
			if( osf->o_F ){
				_Fprintf(tc," %s:%d",osf->o_F,osf->o_L);
			}
			if( fi < 32 )
				_Fprintf(tc," %s",o_path[fi]);
			_Fprintf(tc,"\n");
		}
	}
	if( dup == 0 ){
		return;
	}
	int cnt;
	_Fprintf(tc,"---- DUP\n");
	for( fi = 0; fi < MAXDUP; fi++ ){
		if( cnt = _duph[fi].d_cnt ){
			fh = _duph[fi].d_fh;
			_Fprintf(tc,"[%2d] %X %d %X/%u\n",
				fi,_duph[fi].d_tid,cnt,fh,fh);
		}
	}

}
static int mdx;
static int isFreeMemDevHandle(int fh);
#define MINMEMF 0x4000
#define NUMMEMF 0x20
static int newMemDevHandle(){
	int fh;
	int fi;
	for( fi = 0; fi < 0x1000; fi++ ){
		fh = MINMEMF + (mdx++ % NUMMEMF);
		if( isFreeMemDevHandle(fh) ){
			break;
		}
	}
	WCE_MEMF(stderr,"MEM newMemDev %X\n",fh);
	return fh;
}
static int isMemDevHandle(int fh){
	return (MINMEMF <= fh && fh < MINMEMF+NUMMEMF);
}
static int NulDevHandle(){
	FILE *fp;
	if( _nuldevhandle == 0 ){
		if( fp = _wfopen(L"/nul",L"r") ){
			_nuldevhandle = fileno(fp);
		}else{
			_nuldevhandle = (void*)0x7FFF;
		}
	}
	return (int)_nuldevhandle;
}
int _open_osfhandleX_FL(const char *F,int L,int fh,int mode,int mfd);
static int NulDevFd(){
	if( _nuldevfd < 0 ){
		_nuldevfd = _open_osfhandleX_FL(__FUNCTION__,__LINE__,
			NulDevHandle(),2,3);
		_Fprintf(stderr,"--WinCE new NulDev FD %X/%d\n",
			NulDevHandle(),_nuldevfd);
	}
	return _nuldevfd;
}

static int _get_duph(int fh);
int isHandle(int oh){
	WORD hinfo;
	HANDLE nh;

	if( oh == NulDevHandle() ){
		return 1;
	}
	if( GetFileSize((HANDLE)oh,0) != -1 ){
		return 1;
	}
	/*
	// no GetHandleInformation on WinCE
	if( DuplicateHandle(0,oh,0,&nh,) ){
		CloseHandle();
		_Fprintf(stderr,"----WinCE isHandle(H%X) HANDLE %X\n",fd,hinfo);
		return 1;
	}
	*/
	return 0;
}
int _get_osfhandle_FL(const char *F,int L,int fd){
	int fi;
	int fh = 0;

	LockOSF();
	if( 0 <= fd && fd < MAXOSF ){
		if( _osfhandles[fd].o_act ){
			fh = _osfhandles[fd].o_fh;
			goto EXIT;
		}
	}else{
		for( fi = 0; fi < MAXOSF; fi++ ){
			if( _osfhandles[fi].o_act )
			if( _osfhandles[fi].o_fh == fd ){
if( _get_duph(fd) == 0 )
_Fprintf(stderr,"----WinCE %04X _get_osfhandle(H%X) %s:%d\n",TID,fd,F,L);
				fh = fd;
				goto EXIT;
			}
		}
	}
	if( isHandle(fd) ){
_Fprintf(stderr,"----WinCE ---- _get_osfhandle(H%X) HANDLE %s:%d\n",fd,F,L);
		fh = fd;
		goto EXIT;
	}

EXIT:
	UnLockOSF();
	return fh;
}

int SessionFd();
int setfdowner(int fd,int tid,int tgid){
	if( fd < 0 || MAXOSF <= fd ){
		return -1;
	}

if(0)
_Fprintf(stderr,"-- %4X freefd[%d] [%X/%X] << [%X/%X]%d\n",
TID,fd,tid,tgid,
_osfhandles[fd].o_tid,_osfhandles[fd].o_tgid,_osfhandles[fd].o_free);

	if( tid ){
		_osfhandles[fd].o_tid = tid;
		_osfhandles[fd].o_tgid = tgid;
		_osfhandles[fd].o_free = 0;
	}else{
		_osfhandles[fd].o_free = 1;
	}
	return 0;
}
int _open_osfhandleX_FL(const char *F,int L,int fh,int mode,int mfd){
	int fi;
	OSF oosf;
/*
	if( fh == NulDevHandle() ){
_Fprintf(stderr,"----NUL---- _open_osfhandle(%d/%X)...\n",fh,fh);
		return fh;
	}
*/
	LockOSF();
	fi = mfd;
	if( mfd < MINOSF )
		fi = MINOSF;
	for( ; fi < MAXOSF; fi++ ){
		if( _osfhandles[fi].o_act == 0 ){
			_osfhandles[fi].o_act = F_ACT;
			_osfhandles[fi].o_fh = fh;
			_osfhandles[fi].o_F = F;
			_osfhandles[fi].o_L = L;
			_osfhandles[fi].o_ser = CHILD_SERNO_MULTI;
			_osfhandles[fi].o_time = time(0);
			_osfhandles[fi].o_tid = getthreadid();
			_osfhandles[fi].o_tgid = getthreadgid(0);
			_osfhandles[fi].o_free = 0;
if( getthreadgid(0) == 0 )
_Fprintf(stderr,"-- %03X gid=0 <= _open(%X/%d) %s:%d\n",
PRTID(_osfhandles[fi].o_tid),fh,fi,F?F:"",L);
			_osfn++;
			if( fi < 5 ){
		WCE_DESC(stderr,"---- _open_osfhandle(%X)=[%d]\n",fh,fi);
			}
			goto EXIT;
		}
	}
	fi = -1;

EXIT:
	UnLockOSF();
	return fi;
}
int _open_osfhandleX(int fh,int mode,int mfd){
	return _open_osfhandleX_FL(__FUNCTION__,__LINE__,fh,mode,mfd);
}
int _open_osfhandle(int fh,int mode){
	return _open_osfhandleX(fh,mode,0);
}
int _get_osfcount(int fh){
	int fi;
	int cnt = 0;

	LockOSF();
	for( fi = 0; fi < MAXOSF; fi++ ){
		if( _osfhandles[fi].o_act )
		if( _osfhandles[fi].o_fh == fh )
			cnt++;
	}
	UnLockOSF();
	return cnt;
}
static void redirect_osf(int fd,int fh,int nfh){
	int fi;

	LockOSF();
	_osfhandles[fd].o_fh = nfh;
	_osfhandles[fd].o_tid = getthreadid();
	for( fi = 0; fi < MAXOSF; fi++ ){
		if( _osfhandles[fi].o_fh == fh ){
			_Fprintf(stderr,"MEM_FFLUSH[%d] %X <- %X\n",
				fi,nfh,fh);
			_osfhandles[fi].o_fh = nfh;
			//_osfhandles[fi].o_act = F_DUP;
		}
	}
	UnLockOSF();
}

static int _get_duph(int fh){
	int hi;
	for( hi = 0; hi < MAXDUP; hi++ ){
		if( _duph[hi].d_fh == fh ){
			return _duph[hi].d_cnt;
		}
	}
	return 0;
}
static int _inc_duph(int fh,const char *path){
	int hi;
	for( hi = 0; hi < MAXDUP; hi++ ){
		if( _duph[hi].d_cnt == 0
		 || _duph[hi].d_fh == fh ){
			if( _duph[hi].d_cnt++ == 0 ){
				_duph[hi].d_fh = fh;
				_duph[hi].d_tid = getthreadid();
			}
WCE_FILE(stderr,"---- inc_duph[%d] %X*%d %s\n",hi,fh,_duph[hi].d_cnt,path);
			return _duph[hi].d_cnt;
		}
	}
	return 0;
}
static int _dec_duph(int fh,const char *wh){
	int hi;
	for( hi = 0; hi < MAXDUP; hi++ ){
		if( _duph[hi].d_fh == fh ){
			if( _duph[hi].d_cnt == 0 ){
		WCE_WARN(stderr,"---- dec_duph[%d] %X*%d (%s) ??\n",
		hi,fh,_duph[hi].d_cnt,wh);
			}else
			if( --_duph[hi].d_cnt == 0 ){
				_duph[hi].d_fh = 0;
			}
WCE_FILE(stderr,"---- dec_duph[%d] %X*%d (%s)\n",hi,fh,_duph[hi].d_cnt,wh);
			return _duph[hi].d_cnt;
		}
	}
	return 0;
}

#define _get_osfhandle(fd) _get_osfhandle_FL(__FUNCTION__,__LINE__,fd)
int _dupX_FL(const char *F,int L,int fd){
	int fh;
	int nfd;

	if( fd == -1 ){
		_Fprintf(stderr,"--WinCE ---------------- _dup(%d)=-1\n",
			fd);
		return -1;
	}
	fh = _get_osfhandle(fd);

	if( fh == 0 && 0 < fd && fd < 256 ){
 _Fprintf(stderr,"---[%X#%d] _dup(%d) USE IT AS HANDLE? <= %s:%d",XTID,fd,F,L);
getc(stdin);
	}
	nfd = _open_osfhandleX_FL(F,L,fh,0,0);
	if( fd < 0 || MAXOSF <= fd ){
		_inc_duph(fd,"_dup");
	}
	if( isMemDevHandle(fh) ){
		WCE_MEMFx(stderr,"#MEM_dup(%d)=%d /%X <= %s:%d\n",
			fd,nfd,fh,F,L);
	}

 //_Fprintf(stderr,"---- WinCE _dup(%d/%X/%X)=%d/%X/%X osf(%d/%d)\n",
 //fd,fh,SocketOf(fd),nfd,_get_osfhandle(nfd),SocketOf(nfd),_osfn,_osdn);
	return nfd;
}
int _dup(int fd){
	int nfd;

	lock_osf();
	nfd = _dupX_FL(__FUNCTION__,__LINE__,fd);
	unlock_osf();
	return nfd;
}

int _dup_FL(const char *F,int L,int fd){
	int nfd;

	lock_osf();
	nfd = _dupX_FL(F,L,fd);
	unlock_osf();

	if( fd == 0 || nfd == 0 ){
		_Fprintf(stderr,"-- %X _dup(%s:%d,%d/%X)=%d/%X THX=%d\n",
			TID,F,L,fd,_get_osfhandle(fd),nfd,_get_osfhandle(nfd),
			THEXIT
		);
	}
	return nfd;
}
int usedFDX(const char *F,int L,int usedfd){
	return 0;
}
int nextFDX(const char *F,int L){
	return 0;
}
int Closesocket(int sock);
static int invalidFd(int fd){
	int act;
	if( fd < 0 ){
		return 9991;
	}
	if( MAXOSF <= fd ){
		return 9992;
	}
	LockOSF();
	act = _osfhandles[fd].o_act;
	UnLockOSF();
	if( act == 0 ){
		return 9993;
	}
	return 0;
}
int _dup2X_FL(const char *F,int L,int sfd,int dfd){
	int sh;
	int dh;
	OSF *osf;
	int dsock;
	OSF dosf;
	int duph;

	sh = _get_osfhandle(sfd);
	dh = _get_osfhandle(dfd);

	WCE_FILE(stderr,"----WinCE _dup2(%d/%X,%d/%X) osf(%d/%d) %s:%d\n",
		sfd,sh,dfd,dh,_osfn,_osdn,F,L);
	if( invalidFd(sfd) ){
		_Fprintf(stderr,"---[%X#%d] INVALID dup2(%d,%d)\n",XTID,sfd,dfd);
		return -1;
	}
	/*
	_osfhandles[dfd].o_fh = _osfhandles[sfd].o_fh;
	return 0;
	*/

	if( sfd == dfd ){
		return 0;
	}
	if( dfd < 0 || MAXOSF <= dfd ){
WCE_FILE(stderr,"----WinCE _dup2 dfd out-of-range:%X (%d) <<< %X\n",dfd,
_get_osfcount(dfd),sfd);
		// sfd can be NulDev
		return -1;
	}
	duph = _dec_duph(dh,"_dup2");
	dsock = SocketOf(dfd);
	if( dsock ){
		_Fprintf(stderr,"#### closesocket(%d/%d) by dup=%d %s:%d\n",
			dsock,dfd,sfd,F,L);
	}

	LockOSF();
	dosf = _osfhandles[dfd];
	_osfhandles[dfd].o_fh = _osfhandles[sfd].o_fh;
	_osfhandles[dfd].o_act = F_DUP;
	_osfhandles[dfd].o_F = F;
	_osfhandles[dfd].o_L = L;
	_osfhandles[dfd].o_ser = CHILD_SERNO_MULTI;
	_osfhandles[dfd].o_time = time(0);
	_osfhandles[dfd].o_tid = getthreadid();
	_osfhandles[dfd].o_tgid = getthreadgid(0);
	_osfhandles[dfd].o_free = 0;
if( getthreadgid(0) == 0 )
_Fprintf(stderr,"-- %X gid=0 <= _dup2(%d,%d) %s:%d\n",
PRTID(_osfhandles[dfd].o_tid),sfd,dfd,F?F:"",L);
	if( dosf.o_act ){
		if( duph <= 0 )
		if( _get_osfcount(dosf.o_fh) == 0 ){
			if( dsock ){
_Fprintf(stderr,"############# closesocket(%d/%X) dup=%d\n",dfd,dsock,duph);
				Closesocket(dsock);
			}else{
_Fprintf(stderr,"############# Closehandle(%d/%X) dup=%d\n",dfd,dosf.o_fh,duph);
				CloseHandle((HANDLE)dosf.o_fh);
			}
		}
	}else{
		_osfn++;
		_osdn++;
	}
	UnLockOSF();
	/* if Socket then it must be feat to openSocket() */
	return 0;
}
int _dup2_FL(const char *F,int L,int sfd,int dfd){
	int rcode;
	lock_osf();
	rcode = _dup2X_FL(F,L,sfd,dfd);
	unlock_osf();
	return rcode;
}
#undef dup2
int _dup2(int sfd,int dfd){
	return _dup2_FL("",0,sfd,dfd);
}

//---- pipe
int SocketPipe(int hv[2],int size);
int _open_osfhandle(int,int);
int _pipe(int *const pv,int siz,int mod){

	pv[0] = pv[1] = -1;
	if( SocketPipe(pv,siz) == 0 ){
		return 0;
	}else{
		_Fprintf(stderr,"----WinCE pipe(%d,%X)=-1 ERROR\n",siz,mod);
		return -1;
	}
}
int _pclose(FILE *fp){
	_Fprintf(stderr,"--WinCE _pclose(%X)\n",fp);
	return -1;
}

#define NUMDoC	256
static struct {
	FILE *doc_fp;
	int   doc_fd;
	int   doc_fh;
	char *doc_path;
	int   doc_dead;
} _doc[NUMDoC];
static int isActiveTmp(int fh){
	int fi;
	for( fi = 0; fi < NUMDoC; fi++ ){
		if( fh == _doc[fi].doc_fh ){
			return 1;
		}
	}
	return 0;
}
char *StrAlloc_FL(const char *F,int L,const char *str);
int setDeleteOnClose(FILE *fp,int fd,const char *path){
	int fi;
	int fh;
	for( fi = 0; fi < NUMDoC; fi++ ){
		if( _doc[fi].doc_fh == 0 ){
			_doc[fi].doc_fp = fp;
			_doc[fi].doc_fd = fd;
			_doc[fi].doc_fh = fh = _get_osfhandle(fd);
			_doc[fi].doc_path = StrAlloc_FL(__FILE__,__LINE__,path);
			_doc[fi].doc_dead = 0;
	WCE_LINK(stderr,"-- setDOC[%d] %X [%d] %X %s\n",fi,fp,fd,fh,path);
			return 0;
		}
	}
	return -1;
}
int File_is(const char *path);
static int delete1(const char *wh,int fi,int force){
	char *path = _doc[fi].doc_path;
	FILE *fp = _doc[fi].doc_fp;
	int fd = _doc[fi].doc_fd;
	int fh = _doc[fi].doc_fh;
	int ok,rcode;

	rcode = unlink(path);
//_Fprintf(stderr,"-- exeDOC[%d] %X [%d] %X %s\n",fi,fp,fd,fh,path);
	if( rcode != 0 && force && fh != 0 ){
		ok = CloseHandle((HANDLE)fh);
		rcode = unlink(path);
_Fprintf(stderr,"-- exeDOC[%d] %X [%d] %X CloseHandle()=%d unlink()=%d\n",
fi,fp,fd,fh,ok,rcode);
		if( ok ){
			_doc[fi].doc_fh = 0;
		}
	}
	if( rcode != 0 && File_is(path) == 0 ){
		_Fprintf(stderr,"--#%d DelOn%s %d[%d](%X) %d %s (NONE)\n",
			CHILD_SERNO_MULTI,wh,force,fi,fh,rcode,path);
		rcode = 0;
	}
	if( rcode != 0 ){
		_Fprintf(stderr,"--#%d DelOn%s %d[%d](%X) %d %s\n",
			CHILD_SERNO_MULTI,wh,force,fi,fh,rcode,path);
	}else{
		free(path);
		_doc[fi].doc_path = 0;
		_doc[fi].doc_fh = 0;
		_doc[fi].doc_dead = 0;
	}
	_doc[fi].doc_dead = 1;
	return rcode;
}
int doDeleteOnClose(int fd,int fh){
	int fi;
	int fhh = _get_osfhandle(fd);

	WCE_LINK(stderr,"---- DelOnClose [%d](%X:%X)\n",fd,fh,fhh);
	if( fh == 0 && fhh != 0 ){
		fh = fh;
	}
	for( fi = 0; fi < NUMDoC; fi++ ){
		if( _doc[fi].doc_dead && _doc[fi].doc_path != 0 ){
			delete1("Sweep",fi,0);
		}
		if( fh != 0 && _doc[fi].doc_fh == fh ){
			// if there is no _osfhandles[*]==fh
			delete1("Close",fi,0);
			return 1;
		}
	}
	return 0;
}
int doDeleteOnExit(){
	int fi;
	int fh;
	int ndel = 0;
	int ok;

	for( fi = 0; fi < NUMDoC; fi++ ){
		if( fh = _doc[fi].doc_fh ){
			delete1("Exit",fi,1);
			ndel++;
		}
	}
	return ndel;
}

static void closeFILEXofFd(const char *F,int L,int fd);
int _close_osfhandle_FL(const char *F,int L,int fd){
	int oh;
	int fi;
	int cnt;
	int act;
	int sock;
	int rcode;
	OSF *osf;
	int tid;
	int gtid;

/*
	if( fd == NulDevFd() ){
_Fprintf(stderr,"----NUL---- _close_osfhandle(%d/%X)...\n",fd,fd);
		return 0;
	}
*/
	if( fd < 0 || MAXOSF <= fd ){
		// could be close(fileno(fp))
		// doDeleteOnClose(fd,0);
		return -1;
	}

	LockOSF();
	if( act = _osfhandles[fd].o_act ){
		closeFILEXofFd(F,L,fd);
		oh = _osfhandles[fd].o_fh;
if( oh == 0 ){
_Fprintf(stderr,"---[%X#%d] _close_osfhandle(%d/%X) OH=0 stdin=%X: OK?",
XTID,fd,fd,fileno(stdin));getc(stdin);
}
		sock = SocketOf(fd);
		if( act & F_DUP ){
			_osdn--;
		}
		_osfn--;
		_osfhandles[fd].o_act = 0;
		_osfhandles[fd].o_fh = 0;
		osf = &_osfhandles[fd];
		tid = getthreadid();
		gtid = getthreadgid(0);
		if( osf->o_free == 0 )
		if( osf->o_tgid != gtid )
		if( osf->o_tid != tid ){
	_Fprintf(stderr,"## %X close[%d]%X [%X/%X]%s:%d => [%X/%X]%s:%d %s\n",
	PRTID(tid),fd,oh,
	PRTID(osf->o_tgid), PRTID(osf->o_tid), osf->o_F?osf->o_F:"",osf->o_L,
	PRTID(gtid),        PRTID(tid),F?F:"",L,
	osf->o_tgid!=gtid?"--ERROR--":""
	);
		}
		if( F != 0 && L != 0 ){
			_osfhandles[fd].o_F = F;
			_osfhandles[fd].o_L = L;
			_osfhandles[fd].o_tid = getthreadid();
			_osfhandles[fd].o_tgid = getthreadgid(0);
if( getthreadgid(0) == 0 )
_Fprintf(stderr,"-- %X gid=0 <= _close(%X/%d) %s:%d\n",
PRTID(_osfhandles[fd].o_tid),oh,fd,F?F:"",L);
		}
		cnt = 0;
		for( fi = 0; fi < MAXOSF; fi++ ){
			if( _osfhandles[fi].o_act )
			if( _osfhandles[fi].o_fh == oh ){
				cnt++;
			}
		}
		if( cnt == 0 ){
			doDeleteOnClose(fd,oh);
// maybe copied with DuplicateSocket ?
//_Fprintf(stderr,"----WinCE ---- _close(%2d/%d,%X) DID CloseHandle\n",
//fd,oh,oh);
			//doCloseHandle(oh);
		}
		rcode = 0;
	}else{
		int cnt = 0;
		if( oh = _get_osfhandle(fd) ){
			cnt = _get_osfcount(oh);
		}
		doDeleteOnClose(fd,oh);
//_Fprintf(stderr,"----WinCE ---- _close(%X/%X*%d) NONE ---- (%d)\n",
//fd,oh,cnt,_osfn);
		rcode = -1;
	}
EXIT:
	UnLockOSF();
	return rcode;
}
int _close_osfhandle(int fd){
	return _close_osfhandle_FL("",0,fd);
}

//-------- current directory
static char *_getcwd();
char *getcwd(char *cwd,int z){
	strcpy(cwd,_getcwd());
	//_Fprintf(stderr,"----WinCE getcwd()=%s\n",cwd);
	return cwd;
}

FILE *XX_fdopen_FL(const char *F,int L,int fd,char const *mode);
FILE *fdopen(int fd,char const *mode){
	return XX_fdopen_FL("",0,fd,mode);
}
FILE *_fdopen(int fd,char const *mode){
	return XX_fdopen_FL("",0,fd,mode);
}

static int Igetc(FILE *fp){
	return getc(fp);
}

#undef TID
#undef PRTID
#undef _get_osfhandle
#undef enterCSC
#undef leaveCSC
#include "ystring.h"
#include "file.h"
#include "log.h"

static struct {
	MStr(i_msg,256);
} IMsg;

#undef strdup
char *strdup(const char *src){
	char *sp;
	int siz;
	siz = strlen(src)+1;
	sp = (char*)malloc(siz);
	Xstrcpy(ZVStr(sp,siz),src);
	//_Fprintf(stderr,"----DeleGate/WinCE strdup(%X)\n",sp);
	return sp;
}

#include <time.h>

static int noms;
static int tck0;
static SYSTEMTIME gst0,lst0;
static int gsu0,lsu0;
static int gettime(struct tm *tm,int loc);
int SystemTimeToTm(SYSTEMTIME *st,struct tm *tm);
void UnixTimeToSystemTime(time_t ut,SYSTEMTIME *st);
int Timegm(struct tm *tm);
int Timelocal(struct tm *tm);
time_t SystemTimeToUnixTime(SYSTEMTIME *st){
	struct tm tm;
	time_t ut = 0;
	SystemTimeToTm(st,&tm);
	ut = Timegm(&tm);
	return ut;
}
time_t LocalTimeToUnixTime(SYSTEMTIME *st){
	struct tm tm;
	time_t ut = 0;
	SystemTimeToTm(st,&tm);
	ut = Timelocal(&tm);
	return ut;
}
static void testtick(){
	SYSTEMTIME st;
	struct tm tm;
	int i;
	int psec,usec;
	IStr(buf,4*1024);
	refQStr(bp,buf);

	psec = 0;
	for( i = 0; i < 50; i++ ){
		GetLocalTime(&st);
		usec = gettime(&tm,1);
		if( tm.tm_sec != psec ){
			sprintf(bp,"\n---- %02d:%02d:%02d ",
				tm.tm_hour,tm.tm_min,tm.tm_sec);
			bp += strlen(bp);
			psec = tm.tm_sec;
		}
		sprintf(bp,"%02d.%03d ",st.wSecond,usec);
		bp += strlen(bp);
		usleep(100*1000);
	}
	_Fprintf(stderr,"%s\n",buf);
}
static void settick0(){
	tck0 = GetTickCount();
	GetSystemTime(&gst0);
	GetLocalTime(&lst0);
	gsu0 = SystemTimeToUnixTime(&gst0);
	lsu0 = LocalTimeToUnixTime(&lst0);
	if( gst0.wMilliseconds == 0 && lst0.wMilliseconds == 0 ){
		noms = 1;
	}
}
static struct {
	int	r_notify;
	int	r_nwritten;
	int	r_checked;
	int	r_tested;
	int	r_reset;
	int	r_noreset;
	int	r_resetting;
	int	r_diffsec;
	int	r_difftck;
	int	r_notifytck;
	int	r_lasttck;
     SYSTEMTIME r_lastst;
} resettick;
static int SleptMsec;
static int resettick0(int tck){
	SYSTEMTIME stn;
	struct tm tmn;
	struct tm tmc;
	int off;
	int ds = 0;

	if( tck0 == 0 ){
		return 0;
	}
	resettick.r_checked++;
	if( tck < resettick.r_lasttck+1000*3 ){
		return 0;
	}
	if( resettick.r_resetting )
		return 0;
	resettick.r_resetting++;
	resettick.r_tested++;

	resettick.r_lasttck = tck;
	GetLocalTime(&stn);
	off = stn.wSecond - resettick.r_lastst.wSecond;
	bzero(&tmn,sizeof(tmn));
	SystemTimeToTm(&stn,&tmn);
	gettime(&tmc,1);
	if( tmn.tm_sec != tmc.tm_sec ){
		ds = Timegm(&tmn) - Timegm(&tmc);
		if( -1 <= ds && ds <= 1 ){
			resettick.r_noreset++;
		}else{
			settick0();
			resettick.r_reset++;
			resettick.r_notify++;
			resettick.r_diffsec += ds;
			resettick.r_notifytck = tck;
			refreshWinStatus = 1;
			if( 0 < ds ){
				SleptMsec += ds*1000;
			}
		}
	}
	resettick.r_lastst = stn;
	resettick.r_difftck = tck - resettick.r_lasttck;
	resettick.r_lasttck = tck;

	resettick.r_resetting--;
	return ds;
}
static int gettime(struct tm *tm,int loc){
	SYSTEMTIME st;

	if( noms ){
		int tck = GetTickCount();
		int etck,msec,esec;
		time_t ut;

		resettick0(tck);
		etck = tck - tck0;
		msec = etck % 1000;
		esec = etck / 1000;
		if( loc ){
			ut = lsu0 + esec;
			*tm = *localtime(&ut);
		}else{
			ut = gsu0 + esec;
			*tm = *gmtime(&ut);
		}
		return msec;
	}else{
		if( loc )
			GetLocalTime(&st);
		else	GetSystemTime(&st);
		bzero(tm,sizeof(struct tm));
		SystemTimeToTm(&st,tm);
		return st.wMilliseconds;
	}
}
int ftime(struct timeb *tb){
	struct tm tm;
	tb->millitm = gettime(&tm,0);
	tb->time = Timegm(&tm);
	return 0;
}
long int _time32(long int *t){
	struct timeb tb;
	ftime(&tb);
	return tb.time;
}

int timeToTm(time_t t,struct tm *tm,int loc);
#define NTBUF 8
static struct tm _lot[NTBUF];
static int _lotx;
struct tm *localtime(const time_t *clock){
	int lx = ++_lotx%8;

	timeToTm(*clock,&_lot[lx],1);
	return &_lot[lx];
}
static struct tm _gmt[NTBUF];
static int _gmtx;
struct tm *gmtime(const time_t *clock){
	int lx = ++_gmtx%8;

	timeToTm(*clock,&_gmt[lx],0);
	return &_gmt[lx];
}

int _get_osfcount(int oh);
int FileTimeToUnixTime(FILETIME *ft);
static int FileInfoToSt(BY_HANDLE_FILE_INFORMATION *finfo,struct stat *st){
	int attr = finfo->dwFileAttributes;

	st->st_size = finfo->nFileSizeLow;
	if( attr & FILE_ATTRIBUTE_DIRECTORY ){
		st->st_mode |= S_IFDIR;
	}else{
		st->st_mode |= S_IFREG;
	}
	st->st_ctime = FileTimeToUnixTime(&finfo->ftCreationTime);
	st->st_atime = FileTimeToUnixTime(&finfo->ftLastAccessTime);
	st->st_mtime = FileTimeToUnixTime(&finfo->ftLastWriteTime);
	return 0;
}
static int fstatHandle(HANDLE fh,struct stat *st){
	BY_HANDLE_FILE_INFORMATION finfo;

	bzero(st,sizeof(struct stat));
	if( GetFileInformationByHandle(fh,&finfo) ){
		FileInfoToSt(&finfo,st);
		return 0;
	}else{
		_Fprintf(stderr,"----fstatH %X ERROR\n",fh);
		return -1;
	}
}
static int MemStat(int fd,struct stat *st);
void dumpDGFL(void *me,FILE *tc);
int fstat(int fd,struct stat *st){
	int oh;
	DWORD lenl,lenh;
	int type;
	int stok;
	BY_HANDLE_FILE_INFORMATION finfo;
	OSF *osf;

	bzero(st,sizeof(struct stat));
	if( fd == fileno(stderr) ){
		// should set the attributes of the "CON"
		/*
		WCE_FILE(stderr,"--[%X#%d]--WinCE fstat(%X/%u) stderr\n",
			XTID,_get_osfhandle(fd),fd);
		*/
		return -1;
	}
	if( 1024 <= fd && _get_osfcount(fd) ){
		// might be a handle from fileno(fopen())
		//return 0;
		oh = fd;
		WCE_FILE(stderr,"--?-WinCE fstat(%X/%u/%X) cnt=%d\n",
			_get_osfhandle(fd),fd,fd,_get_osfcount(fd));
	}else
	if( oh = _get_osfhandle(fd) ){
		//WCE_FILE(stderr,"----WinCE fstat(%d)=%X is FD\n",fd,oh);
		//return 0;
		if( isMemDevHandle(oh) ){
			MemStat(fd,st);
			return 0;
		}
	}else{
		_Fprintf(stderr,"--[%X#%d] fstat(%d) oh=%X is UNKNOWN\n",
			XTID,fd,oh);
		if( 0 <= fd && fd < MAXOSF ){
			osf = &_osfhandles[fd];
		_Fprintf(stderr,"--[%X#%d] fstat(%d) oh=%X <= [%X#%d]%s:%d\n",
			XTID,fd,oh,
			PRTID(osf->o_tid),osf->o_ser,
			osf->o_F?osf->o_F:"",osf->o_L);
		}
		if( fd != CLOSED_HANDLE_VALUE ){
			dumposf(stderr,"fstat-error",fd,0,0);
			dumpDGFL(0,stderr);
		}
		oh = fd;
	}
	lenh = 0;
	lenl = GetFileSize((HANDLE)oh,&lenh);
	type = GetFileType((HANDLE)oh);
	bzero(&finfo,sizeof(finfo));
	stok = GetFileInformationByHandle((HANDLE)oh,&finfo);
/*
_Fprintf(stderr,"----WinCE fstat(%X)=%X len=%d typ=%d stk=%d -------\n",
fd,oh,lenl,type,stok);
*/
//_Fprintf(stderr,"----WinCE fstat(H%X/%d) len=%x,%x typ=%d ok=%d attr=%X\n",
//oh,fd,lenl,lenh,type,stok,finfo.dwFileAttributes);

	if( stok ){
		FileInfoToSt(&finfo,st);
		return 0;
	}
	return -1;
}

int fromSafeFileName(PCStr(name),PVStr(xname));

#define ESC_NONE 0
#define ESC_URL  1
int wstrtostrX(int sz,char *dst,WCHAR *src,int esc);
int strtowstrX(int sz,WCHAR *dst,PCStr(src),int esc);

static void dumpwstr(PCStr(what),WCHAR *ws){
	int i;
	_Fprintf(stderr,"%s",what);
	for( i = 0; i < 64 && ws[i]; i++ ){
		_Fprintf(stderr,"%X ",0xFFFF & ws[i]);
	}
	_Fprintf(stderr,"\n");
}
#define wstrtostr(dst,src,e) wstrtostrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
#define strtowstr(dst,src,e) strtowstrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)

extern const char *FinishFile;
extern int FinishLine;
int getthreadix();

HANDLE CreateFileForMappingA(const char *fn,DWORD da,DWORD sm, PSECURITY_ATTRIBUTES sa,DWORD cd,DWORD fa,HANDLE tf){
	WCHAR wfn[1024];
	strtowstr(wfn,fn,ESC_NONE);
	return CreateFileForMappingW(wfn,da,sm,sa,cd,fa,tf);
}
HANDLE CreateFileMappingA(HANDLE fh,LPSECURITY_ATTRIBUTES sa,DWORD pr,DWORD hi,DWORD lo,const char *nm){
	WCHAR wnm[1024];
	HANDLE mh;
	if( nm ){
		strtowstr(wnm,nm,ESC_NONE);
	}
	//_Fprintf(stderr,"---CFM %X ...\n",fh);
	if( mh = CreateFileMappingW(fh,sa,pr,hi,lo,nm?wnm:0) ){
	//_Fprintf(stderr,"---CFM %X ... OK %X\n",fh,mh);
		return mh;
	}
	//_Fprintf(stderr,"---CFM %X ... NG %X ERR=%d\n",fh,mh,GetLastError());
	return INVALID_HANDLE_VALUE;
}
static int setfd_FL(const char *F,int L,FILE *fp,int fd);
static int CF_NUM;
static int CF_OK;
static int CF_RET;
static int CF_ERR;
static int CF_DEV;
static int CF_NOTMP;
HANDLE CreateFileX(const char *fn,int da,int sm,LPSECURITY_ATTRIBUTES sa,int cd,int fa,HANDLE tf){
	HANDLE oh;
	WCHAR wfn[1024];

	/*
	if( cd & CREATE_NEW ){ cd |= OPEN_ALWAYS; }
	if( fa & FILE_ATTRIBUTE_TEMPORARY ){ fa &= ~FILE_ATTRIBUTE_TEMPORARY; }
	if( fa & FILE_FLAG_DELETE_ON_CLOSE){ fa &= ~FILE_FLAG_DELETE_ON_CLOSE;}
	*/
	if( CF_NOTMP ){
		// this is necessary at least on non-SD-memory of WinCE4.2
	if( fa & FILE_ATTRIBUTE_TEMPORARY ){ fa &= ~FILE_ATTRIBUTE_TEMPORARY; }
	if( fa & FILE_FLAG_DELETE_ON_CLOSE){ fa &= ~FILE_FLAG_DELETE_ON_CLOSE;}
	}

	CF_NUM++;
	SetLastError(0);
	strtowstr(wfn,fn,ESC_URL);
	oh = CreateFileW(wfn,da,sm,sa,cd,fa,tf);

	if( oh == 0 || oh == INVALID_HANDLE_VALUE )
	if( fa & (FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE) ){
		fa &= ~(FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE);
		oh = CreateFileW(wfn,da,sm,sa,cd,fa,tf);
		if( 0 < oh ){
		_Fprintf(stderr,"---[%X#%d] create oh=%X %s err=%d [NOTMP]\n",
			XTID,oh,fn,GetLastError(),oh);
			CF_NOTMP++;
		}
	}
	if( oh == 0 || oh == INVALID_HANDLE_VALUE ){
		FILE *fp;
		int fd;
		const WCHAR *mode;

		_Fprintf(stderr,"---[%X#%d] create oh=%X %s err=%d\n",
			XTID,oh,fn,GetLastError());
		SetLastError(0);

		if( da & GENERIC_WRITE )
		  if( da & GENERIC_READ )
			mode = L"w+";
		  else	mode = L"w";
		else	mode = L"r";
		fp = _wfopen(wfn,mode);
		if( fp != NULL ){
			oh = (HANDLE)fileno(fp);
			fd = _open_osfhandle((int)oh,0);
			setfd_FL(__FILE__,__LINE__,fp,fd);
			XX_fcloseFILE_FL(__FILE__,__LINE__,fp);
		_Fprintf(stderr,"---[%X#%d] create oh=%X %s err=%d [wfdopen]\n",
			XTID,oh,fn,GetLastError());
		}
		if( oh == INVALID_HANDLE_VALUE )
			CF_ERR++;
		else	CF_RET++;
	}
	else{
		CF_OK++;
		if( strchr(fn,':') )
			CF_DEV++;
		if(0)
		_Fprintf(stderr,"---[%X#%d] create oh=%X %s err=%d OK\n",
			XTID,oh,fn,GetLastError());
	}
	return oh;
}

HRESULT CoInitialize(LPVOID rs){
	return S_FALSE;
}
int CreateProcessX(const char *an,char *cl,struct _SECURITY_ATTRIBUTES *pa,struct _SECURITY_ATTRIBUTES *ta,int ih,int cf,void *ev,void *cd,struct _STARTUPINFOA  *si,struct _PROCESS_INFORMATION *pi){
	WCHAR wan[1024];
	WCHAR wcl[1024];
	int ok;

	strtowstr(wan,an,ESC_URL);
	strtowstr(wcl,cl,ESC_URL);
	ok = CreateProcessW(wan,wcl,NULL,NULL,FALSE,cf,NULL,NULL,NULL,pi);
	_Fprintf(stderr,"----WinCE create %X [%s][%s]\n",ok,an,cl?cl:"");
	return ok;
}
HMODULE LoadLibraryX(const char *mn){
	WCHAR wmn[1024];
	HMODULE oh;
	strtowstr(wmn,mn,ESC_URL);
	oh = LoadLibraryW(wmn);
	return oh;
}
HMODULE GetModuleHandleX(char *mn){
	WCHAR wmn[1024];
	HMODULE oh;
	if( mn == NULL ){
		oh = GetModuleHandleW(NULL);
	}else{
		oh = GetModuleHandleW(wmn);
		wstrtostr(mn,wmn,ESC_NONE);
	}
	return oh;
}
int WSADuplicateSocketW(SOCKET s,int pid,LPWSAPROTOCOL_INFOW pi){
	int ok;

	// no dupsock on WinCE
	ok = 0;
	return ok;
}
static FILETIME ft0;
BOOL WINAPI GetProcessTimes(HANDLE hProcess,FILETIME *ct,FILETIME *et,FILETIME *kt,FILETIME *ut){
	if( ct ) *ct = ft0;
	if( et ) *et = ft0;
	if( kt ) *kt = ft0;
	if( ut ) *ut = ft0;
	return 0;
}
//int CoCreateInstance(REFCLSID rs,LPUNKNOWN uo,DWORD cx,REFIID ri,LPVOID *ppv){
//	return 0;
//}

static int LOGX_GetFa;
static double LOGX_GetFaElp;

#undef stat
int heapLock(FL_PAR,void *locked);
int heapUnLock(FL_PAR,void *locked);
static char *fsAt;
static struct {
	MStr(gfa_path,256);
} GFA;
static int LK_GetFileAttributes(FL_PAR,WCHAR *wpath){
	void *Lock[16];
	const char *at = 0;
	double St;
	int locked;
	int attr;

	double Start = Time();
	LOGX_GetFa++;

	if( locked = numthreads() ){
		if( at = fsAt ){
			St = Time();
			setthread_FL(0,FL_BAR,"GetFileAttributes-A");
		}
		heapLock("GetFileAttributes",__LINE__,Lock);
		fsAt = "GetFileAttributes";
		if( at ){
			if( 0.2 < Time()-St )
			_Fprintf(stderr,"-- %X MUTEX %s >>> %s %.3f << %s:%d\n",
				TID,at,fsAt,Time()-St,FL_BAR);
		}
	}
	wstrtostr(GFA.gfa_path,wpath,0);
	attr = GetFileAttributes(wpath);
	if( locked ){
		fsAt = 0;
		heapUnLock("GetFileAttributes",__LINE__,Lock);
		if( at ){
			setthread_FL(0,FL_BAR,"GetFileAttributes-A");
		}
	}
	LOGX_GetFaElp += Time()-Start;
	return attr;
}
static int LK_CreateDirectory(FL_PAR,WCHAR *wpath,LPSECURITY_ATTRIBUTES arg){
	void *Lock[16];
	const char *at = 0;
	double St;
	int locked;
	int rcode;

	if( locked = numthreads() ){
		if( at = fsAt ){
			St = Time();
			setthread_FL(0,FL_BAR,"GetFileAttributes-A");
		}
		heapLock("CreateDirectory",__LINE__,Lock);
		fsAt = "CreateDirectory";
		if( at ){
			if( 0.2 < Time()-St )
			_Fprintf(stderr,"-- %X MUTEX %s >>> %s %.3f << %s:%d\n",
				TID,at,fsAt,Time()-St,FL_BAR);
		}
	}
	rcode = CreateDirectory(wpath,arg);
	if( locked ){
		fsAt = 0;
		heapUnLock("CreateDirectory",__LINE__,Lock);
		if( at ){
			setthread_FL(0,FL_BAR,"GetFileAttributes-A");
		}
	}
	return rcode;
}

int stat(char const *path,struct stat *st){
	HANDLE fh;
	int err;
	int attrs;
	WCHAR wpath[1024];
	WCHAR cwd[1024];
	int stok;
	int attr;

	//int clen;
	//clen = GetCurrentDirectoryW(elnumof(cwd),cwd);

	strtowstr(wpath,path,ESC_URL);
	attr = LK_GetFileAttributes("stat",__LINE__,wpath);

	bzero(st,sizeof(struct stat));
	if( attr == -1 ){
		WCE_FILE(stderr,"----WinCE stat(%s) attr=%X\n",path,attr);
		return -1;
	}else{
		if( attr & FILE_ATTRIBUTE_DIRECTORY ){
			/*
			fh = CreateFile(wpath,0,FILE_SHARE_READ,
				NULL,OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS,NULL);
			if( fh != INVALID_HANDLE_VALUE ){
				goto GOTDIR;
			}
			*/
			WCE_FILE(stderr,"----WinCE stat(%s)%X DIR\n",path,attr);
			st->st_mode |= S_IFDIR;
			return 0;
		}else{
			WCE_FILE(stderr,"----WinCE stat(%s)%X REG\n",path,attr);
			st->st_mode |= S_IFREG;
		}
	}

	SetLastError(0);
	fh = CreateFile(wpath,0,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	err = GetLastError();
GOTDIR:
	attrs = LK_GetFileAttributes("stat",__LINE__,wpath);

	if( fh == INVALID_HANDLE_VALUE ){
/*
 HANDLE mfh = 0;
 mfh = CreateFileForMapping(wpath,0,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
 if( mfh != INVALID_HANDLE_VALUE ){
   CloseHandle(mfh);
   WCE_STAT(stderr,"---- -- WinCE stat(%s) fh=%d err=%d %X\n",path,fh,err,mfh);
 }
*/

		switch( err ){
			case ERROR_FILE_EXISTS:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (dir)\n",path,fh,err);
				st->st_mode |= S_IFDIR;
				return 0;
			case ERROR_INVALID_PARAMETER:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (Invalid)\n",path,fh,err);
				return 0;
			case ERROR_INVALID_NAME:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (BadName)\n",path,fh,err);
				return 0;
			case ERROR_FILE_NOT_FOUND:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (fNOTfound)\n",path,fh,err);
				return 0;
			case ERROR_PATH_NOT_FOUND:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (pNOTfound)\n",path,fh,err);
				return 0;
			case ERROR_SHARING_VIOLATION:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (CantShare) %X\n",
path,fh,err,attrs);
				return 0;
			case ERROR_ACCESS_DENIED:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (Denied)\n",path,fh,err);
				return 0;
			default:
WCE_STAT(stderr,"----WinCE stat(%s) fh=%d err=%d (Unknown)\n",path,fh,err);
				return 0;
		}
	}
	if( fh == 0 ){
_Fprintf(stderr,"----WinCE stat(%s) fh=%d err=%d\n",path,fh,err);
		return 0;
	}
	if( fh == INVALID_HANDLE_VALUE ){
	fh = CreateFileW(wpath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,NULL);
_Fprintf(stderr,"----WinCE Wstat(%s) fh=%d err=%d\n",path,fh,err);
	}
	if( fstatHandle(fh,st) == 0 ){
//_Fprintf(stderr,"----WinCE stat(%s):fstat(fh) OK\n",path,fh);
		CloseHandle(fh);
		return 0;
	}
	CloseHandle(fh);
	strtowstr(wpath,path,ESC_URL);
	attrs = LK_GetFileAttributes("stat",__LINE__,wpath);
_Fprintf(stderr,"----WinCE stat(%s) OK %x Attr[%X]\n",path,fh,attrs);

	st->st_mode |= S_IFREG;
	return 0;
}
static char *StorageCard;
static int direq(PCStr(dir1),PCStr(dir2)){
	while( *dir1 == '/' || *dir1 == '\\' )
		dir1++;
	while( *dir2 == '/' || *dir2 == '\\' )
		dir2++;
	return strcaseeq(dir1,dir2);
}
void putWinStatus(PCStr(fmt),...);
int _mkdir(const char *dir){
	WCHAR wdir[1024];
	int ok;
	int err;

	if( StorageCard && strcaseeq(dir,StorageCard) ){
		putWinStatus("Don't create %s",dir);
		return -1;
	}
	strtowstr(wdir,dir,ESC_URL);
	ok = LK_CreateDirectory("_mkdir",__LINE__,wdir,NULL);
	err = GetLastError();
	if( ok ){
		return 0;
	}else{
if( err != ERROR_ALREADY_EXISTS )
_Fprintf(stderr,"----WinCE _mkdir(%s)=%d err=%d\n",dir,ok,err);
		return -1;
	}
}

#include "ystring.h"
const char *DELEGATE_verdate();
const char *DELEGATE_ver();
const char *Starts[] = {
	"/Windows/%e3%82%b9%e3%82%bf%e3%83%bc%e3%83%88%20%e3%83%a1%e3%83%8b%e3%83%a5%e3%83%bc",
	"/Windows/%e3%82%b9%e3%82%bf%e3%83%bc%e3%83%88%20%e3%83%a1%e3%83%8b%e3%83%a5%e3%83%bc/%e3%83%97%e3%83%ad%e3%82%b0%e3%83%a9%e3%83%a0",
	"/Windows/%e3%83%97%e3%83%ad%e3%82%b0%e3%83%a9%e3%83%a0",
	"/Windows/Start Menu",
	"/Windows/Start Menu/Program",
	"/Windows/Program",
	0
};
const char *MenuFile = "DeleGate.lnk";

int regGetValue(PCStr(which),PCStr(key),PCStr(val),PVStr(rvalue));
const char *myExePath();

static int readLinkPath(PCStr(path),PVStr(xpath)){
	FILE *fp;
	IStr(line,512);
	const char *lp;

	clearVStr(xpath);
	if( fp = fopen(path,"r") ){
		fread(line,1,sizeof(line),fp);
		fclose(fp);
		for( lp = line; isdigit(*lp); lp++ )
			;
		if( *lp == '#' ){
			lp++;
			if( *lp == '"' ){
				lp++;
				wordscanY(lp,BVStr(xpath),256,"^\"");
			}
		}
	}
	return 0;
}
static int getStartMenu(PVStr(rpath),PVStr(xpath)){
	int pi;
	IStr(path,1024);

	for( pi = 0; Starts[pi]; pi++ ){
		fromSafeFileName(Starts[pi],AVStr(path));
		if( fileIsdir(path) ){
			strcat(path,"/");
			strcat(path,MenuFile);
			if( File_is(path) ){
				if( rpath ) strcpy(rpath,path);
				if( xpath ) readLinkPath(path,BVStr(xpath));
				return 1;
			}
		}
	}
	return 0;
}
static int delStartMenu(PVStr(rpath)){
	int pi;
	IStr(path,1024);
	FILE *fp;

	for( pi = 0; Starts[pi]; pi++ ){
		fromSafeFileName(Starts[pi],AVStr(path));
		if( fileIsdir(path) ){
			strcat(path,"/");
			strcat(path,MenuFile);
			if( File_is(path) ){
				return unlink(path);
			}
		}
	}
	return -1;
}
static int addStartMenu(PVStr(rpath)){
	int pi;
	IStr(path,1024);
	const char *xpath;
	FILE *fp;

	xpath = myExePath();
	for( pi = 0; Starts[pi]; pi++ ){
		fromSafeFileName(Starts[pi],AVStr(path));
		if( fileIsdir(path) ){
			strcat(path,"/");
			strcat(path,MenuFile);
			if( (fp = fopen(path,"r+"))||(fp = fopen(path,"w")) ){
				fprintf(fp,"%d#\"%s\"",strlen(xpath),xpath);
				fclose(fp);
				Sleep(300);
				if( File_is(path) ){
					if( rpath ){
						strcpy(rpath,path);
					}
					return 0;
				}
				/* might be moved from StartMenu to Program */
			}
		}
	}
	return -1;
}
static int addStartUp(PCStr(path),PVStr(sstat)){
	FILE *fp;
	const char *xpath;

	if( (fp = fopen(path,"r+"))||(fp = fopen(path,"w")) ){
		xpath = myExePath();
		fprintf(fp,"%d#\"%s\"",strlen(xpath),xpath);
		fclose(fp);
		return 0;
	}else{
		sprintf(sstat,"can't open(%d)'%s'",
			GetLastError(),path);
		return -1;
	}
}
static int getStartUp(PVStr(stup),PVStr(xpath)){
	regGetValue("HKEY_LOCAL_MACHINE","System\\Explorer\\Shell Folders",
		"StartUp",AVStr(stup));
	strsubst(AVStr(stup),"\\","/");
	strcat(stup,"/");
	strcat(stup,MenuFile);
	if( File_is(stup) ){
		if( xpath ) readLinkPath(stup,BVStr(xpath));
		return 1;
	}else{
		return 0;
	}
}

int getNullFd(const char *wh);

#define _IOFBF 0x0000
static int setfx(FILE *fp,const char *F,int L);
static int setfd_FL(const char *F,int L,FILE *fp,int fd){
	int *ip;
	ip = (int*)fp;

//_Fprintf(stderr,"----%X setfd(%X,%X<-%X) %s:%d\n",&F,fp,fd,ip[11],F,L);
	ip[11] = fd;
	return 0;
}
static int setfh_FL(const char *F,int L,FILE *fp){
	int *ip;
	int fd;
	int fh;

	ip = (int*)fp;
	fd = fileno(fp);
	if( 0 <= fd && fd <= MAXOSF ){
		if( fh = _get_osfhandle(fd) ){
			ip[11] = _get_osfhandle(fd);
//_Fprintf(stderr,"--->%X setfh(%X),%X->%X %s:%d\n",&F,fp,fd,ip[11],F,L);
		}else{
		}
	}
	return fd;
}
#define setfd(fp,fd) setfd_FL(__FUNCTION__,__LINE__,fp,fd)
#define setfh(fp)    setfh_FL(__FUNCTION__,__LINE__,fp)

int setosf_FL(const char *wh,const char *path,int fd,FILE *fp,const char *F,int L){
	OSF *osf;
	int sock;
	if( inDBG(DBG_DESC) ){
		sock = SocketOf(fd);
	}else	sock = -1;

	LockOSF();
	if( 0 <= fd && fd < MAXOSF ){
		osf = &_osfhandles[fd];
		WCE_DESC(stderr,"---s %s (%s:%d)<-(%s:%d) %X/%d sock=%d\n",
			wh,F,L,osf->o_F?osf->o_F:"",osf->o_L,fp,fd,sock);
		if( fd < elnumof(o_path) )
		{
			if( sizeof(o_path[fd])-1 <= strlen(path) ){
				/*
				_Fprintf(stderr,"overflow << %s:%d (%d) %s\n",
					F,L,strlen(path),path);
				*/
			Xstrncpy(FVStr(o_path[fd]),path,sizeof(o_path[fd]));
			}else
			Xstrcpy(FVStr(o_path[fd]),path);
		}
		osf->o_F = F;
		osf->o_L = L;
	}
	UnLockOSF();
	return fd;
}
int set_fh(FILE *fp){
	int fd = fileno(fp);
	if( SocketOf(fd) == 0 )
	if( !isMemDevHandle(_get_osfhandle(fd)) ){
		setfh(fp);
		return fd;
	}
	return -1;
}
int set_fd(FILE *fp,int fd){
	return setfd(fp,fd);
}

#undef fflush
static FILE *fdopenMemTmpfile(FL_PAR,int fd,const char *mode);
FILE *XX_fdopen_FL(FL_PAR,int fd,char const *mode){
	int ofh;
	int fh;
	int sock;
	int *ip;
	FILE *fp;
	WCHAR wmode[128];
	int nfd;

	if( fd < 0 || MAXOSF <= fd ){
		return 0;
	}
	strtowstr(wmode,mode,ESC_URL);
	fh = _get_osfhandle(fd);

	if( fd == CLOSED_HANDLE_VALUE ){
		fp = _wfdopen((void*)CLOSED_HANDLE_VALUE,wmode);
		_Fprintf(stderr,"## %X fdopen(%d) <= %s:%d ################\n",
			TID,FL_BAR);
		return fp;
	}
	if( fd == NulDevFd() || fh == NulDevHandle() ){
		/*
		fp = _wfdopen((void*)NulDevHandle(),wmode);
		nfd = _open_osfhandleX_FL(FL_BAR,NullDevHandle(),2,0);
		setfd(fp,nfd);
		*/
		fp = _wfdopen((void*)fd,wmode);
_Fprintf(stderr,"-- %X --NUL-- _fdopen(%d/%X)... ([%X]%s:%d) <= %s:%d OK????\n",
			TID,fd,fh,
			PRTID(_osfhandles[fd].o_tid),
			_osfhandles[fd].o_F,_osfhandles[fd].o_L,
			FL_BAR);
		// this can occer dupclosed(fileno(fp)) + fclose(fp)
		/*
		getc(stdin);
		*/
		return fp;
	}
	if( isMemDevHandle(fh) ){
		fp = fdopenMemTmpfile(FL_BAR,fd,mode);
WCE_DESC(stderr,"-- %X -- ++ --fdopen %X/%d <= %s:%d\n",TID,fp,fd,FL_BAR);
		return fp;
	}

/* use the socket handle
	if( fh = SocketOf(fd) ){
	}else
		fh = _get_osfhandle(fd);
	fp = _wfdopen((void*)fh,wmode);
*/
	if( fh < 0 || MAXOSF <= fh )
		sock = 0;
	else	sock = SocketOf(fd);
	if( sock ){
		fp = _wfdopen((void*)fd,wmode);
		WCE_SOCK(stderr,"---s[%X] fdopenFL (%s:%d) %X/%d sock=%d\n",
			getthreadid(),FL_BAR,fp,fd,sock);
		setosf_FL("fdopen","(fd)",fd,fp,FL_BAR);
		/*
		if( fp ){
			char *bp;
			int size = 1024;
			bp = (char*)malloc(size);
			setvbuf(fp,bp,_IOFBF,size);
		}
		*/
		setfx(fp,FL_BAR);
	}else{
		fh = _get_osfhandle(fd);
		fp = _wfdopen((void*)fh,wmode);
WCE_FILE(stderr,"---- FILE _fdopen(%X/%X)... %X\n",fh,fd,fp);
		/*
		if( fp ){
			int *ifp = (int*)fp;
WCE_FILE(stderr,"---- FILE _fdopen(%X/%X)... %X [11]%X\n",fh,fd,fp,ifp[11]);
getc(stdin);
			if( ifp[11] == fh ){
				ifp[11] = fd;
			}
			// and then overwrite fileno on any fwrite/fread/...
		}
		*/
	}
	if( fp ){
		_setmode(fp,_O_BINARY);
//_Fprintf(stderr,"---- _fdopen(%d) %X/%X\n",fd,fp,fileno(fp));
	}
/*
_Fprintf(stderr,"----WinCE fdopen(S%d/H%d/%d,%s) fp=%X\n",
SocketOf(fd),fh,fd,mode,fp);
*/
	if( fd < 0 || MAXOSF < fd ){
		int ofd = fd;
		fd = _open_osfhandleX_FL(FL_BAR,fileno(fp),2,0);
_Fprintf(stderr,"-- %X %X HANDLE-A? _fdopen(%s) fn=%X/%d <= %s:%d\n",TID,
fp,mode,fileno(fp),ofd,FL_BAR);
		setfd(fp,fd);
_Fprintf(stderr,"-- %X %X HANDLE-B? _fdopen(%s) fd=%X/%d\n",TID,
fp,mode,fileno(fp),fd);
	}else
	if( sock ){
		WCE_DESC(stderr,"---s %X SOCKET _fdopen(%d/%d,%s)\n",
			fp,sock,fileno(fp),mode);
	}else
	if( fp && 0 <= fd && fd < MAXOSF ){
		int fn = fileno(fp);
		setfd(fp,fd);
		WCE_DESC(stderr,"----%X FILE _fdopen(%X/%d,%s) %d\n",
			fp,fh,fd,mode,fileno(fp));
	}else
	if( fp && fh ){
		fd = _open_osfhandleX_FL(FL_BAR,fh,2,0);
_Fprintf(stderr,"----%X C _fdopen(%s) fd=%d fn=%X\n",fileno(fp),mode,fd,fh);
		setfd(fp,fd);
_Fprintf(stderr,"----%X D _fdopen(%s) fd=%d fn=%X\n",fileno(fp),mode,fd,fh);
	}else{
		fd = _open_osfhandleX_FL(FL_BAR,fh,2,0);
_Fprintf(stderr,"----%X X _fdopen(%s) fd=%d fn=%X\n",fp,mode,fd,fh);
		setfd(fp,fd);
_Fprintf(stderr,"----%X Y _fdopen(%s) fd=%d fn=%X\n",fp,mode,fd,fh);
	}
/*
_Fprintf(stderr,"-- %X -- ++ --fdopen %X/%d <= %s:%d\n",TID,fp,fd,FL_BAR);
*/
	return fp;
}
FILE *freopen(char const *,char const *,void *){
	return 0;
}
void setBinaryIO(){
	//_setmode(x,_O_BINARY);
}
static int MemFseek(FILE *fp,int fd,int off,int wh);
int _lseeki64(int fd,int off,int wh){
	HANDLE fh;
	DWORD noff = -1;
	LONG hi = 0;
	int Err;

	if( fd == fileno(stdout) || fd == fileno(stderr) ){
		return -1;
	}
	if( fh = (HANDLE)SocketOf(fd) ){
//_Fprintf(stderr,"----WinCE _lseeki64(%X/%X,%d,%d) SOCKET\n",fd,fh,off,wh);
		return -1;
	}
	fh = (HANDLE)_get_osfhandle(fd);
	if( (int)fh == NulDevHandle() ){
		return -1;
	}
	if( isMemDevHandle((int)fh) ){
		return MemFseek(NULL,fd,off,wh);
	}
	if( fh == 0 )
		fh = (HANDLE)fd;
	SetLastError(0);
/*
siz = GetFileSize(fh,&sizh);
*/
	noff = SetFilePointer((HANDLE)fh,off,&hi,wh);
	Err = GetLastError();
	if( noff == -1 ){
		if( Err != 0 )
_Fprintf(stderr,"-- %X _lseeki64([%d]%X,%d,%d) %d Err=%d \n",
TID,fd,fh,off,wh,noff,Err);
	}else{
//_Fprintf(stderr,"----WinCE _lseeki64(%X/%X,%d,%d) OK %d\n",fd,fh,off,wh,noff);
	}
	SetLastError(Err);
	return noff;
}
int tell(int fd){
	int off;
	int Err;

	if( fd == fileno(stderr) ){
//_Fprintf(stderr,"----WinCE tell(stderr=%X) Err=%d\n",fd,GetLastError());
		return -1;
	}
	off = _lseeki64(fd,0,1);
	if( off != -1 ){
//_Fprintf(stderr,"----WinCE tell(%X) OK %d\n",fd,off);
		return off;
	}else{
		if( Err = GetLastError() )
_Fprintf(stderr,"----WinCE tell(%X) Err=%d\n",fd,Err);
		return -1;
	}
}

static int MemChsize(int fd,int size);
int file_size(int fd);
int chsize(int fd,int size){
	HANDLE fh;
	int osiz,nsiz,rs,re,Err;

	osiz = file_size(fd);
	fh = (HANDLE)_get_osfhandle(fd);
	if( fh == 0 )
		fh = (HANDLE)fd;
	if( isMemDevHandle((int)fh) ){
		return MemChsize(fd,size);
	}

	/*
	rs = lseek(fd,size,0);
	*/
	rs = SetFilePointer(fh,size,0,0);
	SetLastError(0);
	re = SetEndOfFile(fh);
	Err = GetLastError();
	nsiz = file_size(fd);
	if( nsiz != size ){
	_Fprintf(stderr,"----WinCE chsize(%d/%X,siz=%d) %d >>> %d (%d %d) %d\n",
		fd,fh,size,osiz,nsiz,rs,re,Err);
		return -1;
	}else{
		return 0;
	}
}

HANDLE CreateFileX(const char *fn,int da,int sm,LPSECURITY_ATTRIBUTES sa,int cd,int fa,HANDLE tf);
int _openX(const char *path,int mode,int flags){
	int oh;
	int fd;
	int da = 0;
	int sm = 0;
	int cd = 0;
	int fa = FILE_ATTRIBUTE_NORMAL;
	const char *mod = "r";
	int duph;

	if( strcaseeq(path,"nul") || strcaseeq(path,"nul:") ){
		fd = NulDevFd();
		fd = _open_osfhandleX_FL(__FUNCTION__,__LINE__,NulDevHandle(),2,3);
_Fprintf(stderr,"--WinCE --NUL-- _open(%s,%d) = NulDevFd() = %X/%d --\n",
path,flags,fd,fd);
		return fd;
	}

	_Fprintf(stderr,"---[%X#%d] _open %s,%d\n",XTID,path,mode);
	switch( mode ){
		case 0: da = GENERIC_READ;
			sm = FILE_SHARE_READ;
			cd = OPEN_EXISTING;
			mod = "r";
			break;
		case 1: da = GENERIC_WRITE;
			sm = FILE_SHARE_WRITE;
			cd = OPEN_EXISTING | CREATE_NEW;
			mod = "w";
			break;
		case 2: da = GENERIC_READ | GENERIC_WRITE;
			sm = FILE_SHARE_READ | FILE_SHARE_WRITE;
			cd = OPEN_EXISTING | CREATE_NEW;
			mod = "w+";
			break;
	}

	oh = (int)CreateFileX(path,da,sm,0,cd,fa,0);
_Fprintf(stderr,"---[%X#%d] _open '%s'%d oh=%X err=%d\n",XTID,path,mode,oh,
GetLastError());
	if( 0 < oh ){
		fd = _open_osfhandleX_FL(__FUNCTION__,__LINE__,oh,mode,0);
		duph = _inc_duph(oh,"_open");
_Fprintf(stderr,"---- _open %s %X/%d ---- duph=%d\n",path,oh,fd,duph);
		return fd;
	}else{
		return -1;
	}
}
int _open(const char *path,int mode,int flags){
	int fd;
	lock_osf();
	fd = _openX(path,mode,flags);
	unlock_osf();
	return fd;
}
int open_FL(const char *F,int L,const char *path,int mode){
	int fd;
	fd = _open(path,mode,0);
	if( fd < 0 ){
		_Fprintf(stderr,"---[%X#%d] open %s %X <= %s:%d\n",XTID,
			path,fd,F,L);
	}
	return fd;
}

//#define TCP_MSS 1024
//#define TCP_MSS 1408
#define TCP_MSS 1448
//#define TCP_MSS 1460 EM-ONE

#undef getc
#undef fgetc
typedef struct _FILEX {
	int fx_fi;
	const char *fx_F;
	int fx_L;
	int fx_tid;
	FILE *fx_fp;
	int fx_fd;
	int fx_fxi;
	int fx_fil;
	int fx_pos;
	int fx_wcc; // really written bytes
	int fx_rcc;
	int fx_scc;
	int fx_mode;
	int fx_eof;
	int fx_error;
	int fx_rcvbuf;
	int fx_sndbuf;
	int fx_winctl;
	int fx_closing;
	int fx_closed;
	int fx_debug;
	int fx_nw;
	int fx_nonblock;
	MStr(fx_path,256);
	int fx_fh;
 struct _FILEX *fx_mem;
/*
	char fx_buf[8*1024];
*/
	char fx_buf[4*TCP_MSS];
} FILEX;
static FILEX *fxs[64];
static FILEX *fxm[64];
static int isFreeMemDevHandle(int fh){
	int fi;
	for( fi = 0; fi < elnumof(fxs); fi++ ){
		if( fxs[fi] == 0 )
			break;
		if( fxs[fi]->fx_fh == fh )
			return 0;
	}
	return 1;
}
void dumpFILEX(FILE *tc,int inact){
	int fi;
	FILEX *fxp;

	_Fprintf(tc,"-- %X FILEX\n",TID);
	for( fi = 0; fxp = fxs[fi]; fi++ ){
		if( fxp->fx_F ){
			if( inact || fxp->fx_fp )
			_Fprintf(tc,"--FX[%2d] %4X %d/%d/%X fp=%X %s:%d\n",
				fi,PRTID(fxp->fx_tid),
				SocketOf(fxp->fx_fd),fxp->fx_fd,
				fxp->fx_fh,fxp->fx_fp,
				fxp->fx_F,fxp->fx_L
			);
		}
	}
}
static void closeFILEXofFd(const char *F,int L,int fd){
	int fi;
	FILEX *fxp;
	FILE *fp;
	int cnt = 0;

	for( fi = 0; fxp = fxs[fi]; fi++ ){
		if( fp = fxp->fx_fp ){
			if( fileno(fp) == fd ){
				cnt++;
			}
		}
	}
if(0)
	if( 1 < cnt ){
_Fprintf(stderr,"-- %X -- -- (%d)closeFILEXofFd[%d] <= %s:%d\n",
TID,cnt,fd,F,L);
	    for( fi = 0; fxp = fxs[fi]; fi++ ){
		if( fp = fxp->fx_fp ){
			if( fileno(fp) == fd ){
_Fprintf(stderr,"-- %X -- -- (%d)closeFILEXofFd[%d]%X [%d] <= [%X]%s:%d\n",
TID,cnt,fd,_get_osfhandle(fd),fi,
PRTID(fxp->fx_tid),fxp->fx_F,fxp->fx_L);
			}
		}
	    }
	}
}
static int prev_fi;
static FILE *prev_fp;
static FILEX *prev_fxp;

static FILEX *getfxfh(int fh){
	int fi;
	FILEX *fxp = 0;

	enterCSC(fxcs);
	for( fi = 0; fi < elnumof(fxs); fi++ ){
		fxp = fxs[fi];
		if( fxp == 0 )
			break;
		if( fxp->fx_fh == fh ){
			break;
		}
	}
	leaveCSC(fxcs);
	return fxp;
}
static FILEX *getfxfd(int fd){
	int fi;
	FILEX *fxp = 0;
	int fh,fd1,fh1;

	enterCSC(fxcs);
	fh = _get_osfhandle(fd);
	for( fi = 0; fi < elnumof(fxs); fi++ ){
		fxp = fxs[fi];
		if( fxp == 0 )
			break;
		if( fxp->fx_path[0] == 0 )
			continue;
		fd1 = fileno(fxp->fx_fp);
		fh1 = _get_osfhandle(fd1);
//_Fprintf(stderr,"## getfxfd(%d/%X)[%d]%d %X\n",fd,fh,fi,fd1,fh1);
		if( fh1 == fh ){
			if( fxp->fx_mem ){
				fxp = fxp->fx_mem;
			}else{
_Fprintf(stderr,"-----------------???? no fx_mem? %X\n",fxp);
			}
			break;
		}
	}
	leaveCSC(fxcs);
	return fxp;
}
static FILEX *getfxx(const char *F,int L,FILE *fp,int create){
	int fi;
	FILEX *fxp = 0;

	setupCSC("getfxx",fxcs,sizeof(fxcs));
	enterCSC(fxcs);

	if( create == 0 ){
		if( fp == prev_fp ){
			fxp = prev_fxp;
			goto EXIT;
		}
	}

	for( fi = 0; fi < elnumof(fxs); fi++ ){
		fxp = fxs[fi];
		if( fxp == 0 )
			break;
		if( fxp->fx_fp == fp ){
			if( create ){
_Fprintf(stderr,"-- %X --reuFILEX [%d] fp=%X ---- LEFT DIRTY [%X]%s:%d\n",
TID,fi,fp,PRTID(fxp->fx_tid),fxp->fx_F?fxp->fx_F:"",fxp->fx_L);
			}else{
				goto EXIT;
			}
		}
		if( create && fxp->fx_fp == 0 ){
//_Fprintf(stderr,"-----------reuFILEX [%d] %X\n",fi,fp);
			break;
		}
	}
	if( create ){
/*
_Fprintf(stderr,"---- newFILEX %s:%d [%d] %X/%d [%X %d %X/%d] ####\n",F,L,
fi,fp,fileno(fp),fxp,fxp?fxp->fx_fxi:0,fxp?fxp->fx_fp:0,fxp?fxp->fx_fd:0);
*/
		if( fxp == 0 )
		{
			fxp = (FILEX*)malloc(sizeof(FILEX));
		}
		bzero(fxp,sizeof(FILEX));
		fxp->fx_fi = fi;
		fxp->fx_fp = fp;
		fxp->fx_fd = fileno(fp);
		fxp->fx_fxi = fi;
		fxp->fx_fil = 0;
		fxp->fx_pos = 0;
		fxp->fx_winctl = 0;
		fxp->fx_sndbuf = 0;
		fxp->fx_rcvbuf = 0;
		fxp->fx_closing = 0;
		fxp->fx_F = F;
		fxp->fx_L = L;
		fxp->fx_tid = getthreadid();
		fxs[fi] = fxp;
	}else{
	}
EXIT:
	prev_fp = fp;
	prev_fxp = fxp;
	leaveCSC(fxcs);
	return fxp;
}
static FILEX *getfxa(const char *F,int L,FILE *fp){
	FILEX *fxp;
	FILEX *mfxp;
	int fd;
	int fh;

	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	if( fh == 0 ){
		/*
		it could be, if it is closed already
		return NULL;
		*/
	}
	fxp = getfxx("",0,fp,0);
	if( fxp == 0 ){
		if( isMemDevHandle(fh) )
		_Fprintf(stderr,"MEM_getfxa[%d] %X/%X NONE <= %s:%d\n",
			fd,fh,fxp,F,L);
		return NULL;
	}
	if( isMemDevHandle(fh) ){
		if( fxp->fx_mem == 0 ){
			/*
			_Fprintf(stderr,"MEM_getfxa ... NONE!!!! [%d]%X %X\n",
				fd,fh,fxp);
			*/
		}
		fxp = fxp->fx_mem;
	}else{
		if( fxp && fxp->fx_path[0] ){
/*
MemFile with external storage
			mfxp = getfxfd(fd);
			if( mfxp != fxp ){
				_Fprintf(stderr,"MEM_getfxa[%d] %X/%X %X\n",
					fd,fh,mfxp,fxp);
				fxp = mfxp;
			}
*/
		}
	}
	return fxp;
}
#define getfx(fp) getfxa(__FUNCTION__,__LINE__,fp)

int setsocksndbuf(int sock,int osz);
int disableWinCtrl(FILE *fp){
	FILEX *fxp;
	if( fxp = getfxx("",0,fp,0) ){
		fxp->fx_winctl = 1;
		//setsocksndbuf(fileno(fp),32*TCP_MSS);
		return 0;
	}
	return -1;
}

static int setfx(FILE *fp,const char *F,int L){
	FILEX *fxp;
	fxp = getfxx(F,L,fp,1);
	return 0;
}

static void MemFree(FILEX *fxp){
	FILEX *mfxp;
	FILEX *fxp1;
	int fi;
	int cnt = 0;

	if( fxp == 0 )
		return;

	enterCSC(fxcs);
	if( mfxp = fxp->fx_mem ){
		fxp->fx_mem = 0;
		for( fi = 0; fi < elnumof(fxs); fi++ ){
			fxp1 = fxs[fi];
			if( fxp1 == 0 )
				break;
			if( fxp1->fx_mem == mfxp ){
				cnt++;
			}
		}
		if( cnt == 0 ){
			free(mfxp);
		}
		if( cnt == 0 ){
			WCE_MEMFx(stderr,"#MEM_free %X\n",mfxp);
		}else{
			WCE_MEMFx(stderr,"#MEM_free %X LEFT REF#%d\n",
				mfxp,cnt);
		}
	}
	leaveCSC(fxcs);
}
static void clearFILEX(FILEX *fxp){
	const char *F;
	int L;

	enterCSC(fxcs);
	F = fxp->fx_F;
	L = fxp->fx_L;
	if( fxp->fx_fp ){
		bzero(fxp,sizeof(FILEX));
		fxp->fx_F = F;
		fxp->fx_L = L;
	}
	prev_fp = 0;
	prev_fxp = 0;
	leaveCSC(fxcs);
}
static void freeFILEX(const char *F,int L,FILEX *fxp,FILE *fp,int fd,int fh){
	FILEX *myfxp;
	//free(fxp->fx_buf);

	if( fxp->fx_path[0] )
	if( myfxp = getfxx("",0,fp,0) ){
		WCE_MEMFx(stderr,"#MEM_fcloseFILE[%d] %X/%X/%X %s\n",
			fd,fh,fxp,myfxp,fxp->fx_path);
		MemFree(myfxp?myfxp:fxp);
		if( myfxp != fxp ){
			clearFILEX(myfxp);
		}
	}
	clearFILEX(fxp);
}

int fdebug(FILE *fp,const char *mode){
	FILEX *fxp;
	if( (fxp = getfx(fp)) == 0 ){
		return -1;
	}
	fxp->fx_debug = 1;
	return 0;
}

#undef ferror
#undef feof
#undef clearerr
int XY_feof(FILE *fp);
int XY_ferror(FILE *fp);
void XY_clearerr(FILE *fp);

#undef setbuf
void XY_setbuf(FILE *fp,char *buf){
	if( buf ){
		setvbuf(fp,buf,1,512);
	}else{
		setvbuf(fp,buf,0,0);
	}
}
void XX_setbuf(FILE *fp,char *buf){
	int fd = fileno(fp);
	FILE *fxp;
	if( fxp = getfx(fp) ){
//_Fprintf(stderr,"---- SOCK setbuf[%d/%d]\n",SocketOf(fd),fd);
	}else{
		XY_setbuf(fp,buf);
	}
}

#undef setvbuf
int XX_setvbuf(FILE *fp,char *buf,int mode,size_t size){
	int fd = fileno(fp);
	FILEX *fxp;
	if( fxp = getfx(fp) ){
//_Fprintf(stderr,"---- SOCK setvbuf[%d/%d] mode=%X\n",SocketOf(fd),fd,mode);
		fxp->fx_mode = mode;
		return 0;
	}else{
		return setvbuf(fp,buf,mode,size);
	}
}

int XX_feof(FILE *fp){
	FILEX *fxp;
	int fd;
	int fh;
	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	fxp = getfx(fp);
	if( fxp ){
		if( fxp->fx_eof ){
//_Fprintf(stderr,"----feof(%X/%d)=EOF\n",fp,fileno(fp));
			return EOF;
		}
		if( isMemDevHandle(fh) ){
			return 0;
		}
	}
//_Fprintf(stderr,"----feof(%X/%d/%d)=%d\n",fp,fd,SocketOf(fd),feof(fp));
	return XY_feof(fp);
}
int XX_ferror(FL_PAR,FILE *fp){
	FILEX *fxp;
	if( fxp = getfx(fp) ){
		if( fxp->fx_error || fxp->fx_eof ){
/*
 if( strstr(FL_F,"iotimeout.c") == 0 )
 _Fprintf(stderr,"-- %s:%d ferror(%X/%d)=ERROR %d %d\n",FL_BAR,fp,fileno(fp),
 fxp->fx_error,fxp->fx_eof);
*/
			return 1;
		}
	}
	return XY_ferror(fp);
}
int XX_clearerr(FILE *fp){
	int fd = fileno(fp);
	int fh;
	FILEX *fxp;

	fxp = getfx(fp);
	fh = _get_osfhandle(fd);
	if( isMemDevHandle(fh) ){
_Fprintf(stderr,"MEM_clearerr(%X/%d) fxp=%X\n",
fp,fileno(fp),fxp);
	}
	if( fxp ){
_Fprintf(stderr,"----clearerr(%X/%d) eof=%d err=%d\n",
	fp,fileno(fp),fxp->fx_eof,fxp->fx_error);
		fxp->fx_eof = 0;
		fxp->fx_error = 0;
		return 0;
	}
	XY_clearerr(fp);
	return 0;
}

int ShutdownSocket(int fd);
int doDeleteOnClose(int fd,int fh);
static
int _closeX_FL(const char *F,int L,int fd){
	int fh;
	int sock;
	int rcode;
	int ok;
	int osfn;
	int refcnt;
	int duph;
 
	osfn = _osfn;
	fh = _get_osfhandle(fd);
	refcnt = _get_osfcount(fh);

	sock = SocketOf(fd);
	if( sock ){
WCE_SOCK(stderr,"---s[%X] close S%d/%d %d cnt=%d\n",getthreadid(),
sock,fd,fh,refcnt);
/*
		ShutdownSocket(fd);
_Fprintf(stderr,"-----------------s[%X] close S%d/%d %d cnt=%d\n",getthreadid(),
sock,fd,fh,refcnt);
*/
	}

	if( ok = invalidFd(fd) ){
WCE_FILE(stderr,"----close(%d) #### INVALID close(%d) ####\n",fd,ok);
		if( 0 <= fd && fd < MAXOSF ){
			return -1;
		}
		// could be a TMPFILE handle
		rcode = 0;
	}else{
		rcode = _close_osfhandle_FL(F,L,fd);
	}
	WCE_FILE(stderr,"----close(%d/%X) %d/%d cnt(%d >>> %d)\n",
		fd,osfn,_osfn,osfn,refcnt,_get_osfcount(fh));
	duph = _dec_duph(fh,"_close");

	if( fd == NulDevHandle() || fh == NulDevHandle() ){
WCE_FILE(stderr,"----NUL---- DONT CloseHandle _close(%d/%X) nul:%d/%X\n",
		fd,fh,NulDevHandle(),NulDevHandle());
	}else
	if( rcode == 0 || fh != 0 ){
WCE_FILE(stderr,"----WinCE _close(H%X/F%X)=%d\n",fh,fd,rcode);
		if( _get_osfcount(fh) == 0
		 && 0 <= GetFileSize((HANDLE)fh,0) ){
			int cok;
			cok = CloseHandle((HANDLE)fh);
WCE_LINK(stderr,"-- _closeX(%X/%d)*%d type=%d size=%d closeH=%d\n",
fh,fd,refcnt,GetFileType((HANDLE)fh),GetFileSize((HANDLE)fh,0),cok);
			doDeleteOnClose(fd,fh);
		}
	}else
	if( 0 < _get_osfcount(fh) ){
WCE_FILE(stderr,"----WinCE _close(H%X/F%X)=%d DONT YET\n",fh,fd,rcode);
	}else
	if( 0 < duph ){
WCE_FILE(stderr,"----WinCE _close(H%X/F%X) YET DUP %d\n",fh,fd,duph);
	}else{
		ok = CloseHandle((HANDLE)fd);
		doDeleteOnClose(fd,fh);
_Fprintf(stderr,"----WinCE _close(H%X/F%X)=%d del=%d (%d/%d)\n",
fh,fd,rcode,ok,_osfn,_osdn);
	}
	return rcode;
}
int _close_FL(const char *F,int L,int fd){
	int rcode;
	double St0 = Time();
	lock_osf();
	rcode = _closeX_FL(F,L,fd);
	unlock_osf();
	if( 0.1 < Time()-St0 ){
		_Fprintf(stderr,"-- %X %.3f close(%d)\n",TID,Time()-St0,fd);
	}
	return rcode;
}
int _close(int fd){
	return _close_FL(__FUNCTION__,__LINE__,fd);
}

#define FILEif1(name,ecode) \
int XY_##name(FILE *fp){ \
	int fd; \
	int fh; \
	int rcode; \
	fh = (int)fileno(fp); \
	if( fh == CLOSED_HANDLE_VALUE ){ /* closed by fcloseFILE */ \
		rcode = name(fp); \
		WCE_DESC(stderr,"--a-- (fp=%X / %d)=%d %s:%d\n", \
			fp,fh,rcode,__FUNCTION__,__LINE__);\
	}else \
	if( fh == (int)INVALID_HANDLE_VALUE ){ /* closed by setfd() ? */ \
		rcode = name(fp); \
		WCE_DESC(stderr,"--a-- (fp=%X / %d)=%d %s:%d\n", \
			fp,fh,rcode,__FUNCTION__,__LINE__);\
	}else \
	if( 0 <= (fd = setfh(fp)) ){ \
		rcode = name(fp); \
		setfd(fp,fd); \
	}else{ \
		rcode = ecode; \
		_Fprintf(stderr,"--z--%X (%X/%d)=%d %s:%d\n",\
			fp,fh,fd,rcode,__FUNCTION__,__LINE__);\
	} \
	return rcode; \
}
#define FILEvf1(name) \
static void XY_##name(FILE *fp){ \
	int fd; \
	int fh; \
	fh = (int)fileno(fp); \
	if( 0 <= (fd = setfh(fp)) ){ \
		name(fp); \
		setfd(fp,fd); \
	}else{ \
_Fprintf(stderr,"--y--%X (%X/%d) %s:%d\n",\
	fp,fh,fd,__FUNCTION__,__LINE__);\
	} \
}

#define FCQSIZE 128
static FILE *DelayedCloseB[FCQSIZE];
static int DelayedCloseN;
static int DelayedCloseX;
static int maxFCQ;
static int numFCQ;

static int enqclosed(const char *F,int L,FILE *fp,int fd,int fh){
	int nq;
	fflush(fp);
	DelayedCloseB[DelayedCloseN%FCQSIZE] = fp;
	DelayedCloseN++;
	numFCQ++;
	nq = DelayedCloseN - DelayedCloseX;
	if( maxFCQ < nq || DelayedCloseN%1000==0 ){
		if( maxFCQ < nq ){
			maxFCQ = nq;
		}
		_Fprintf(stderr,"-- %X (%d) %d enQ fclose(%X/%X/%d) <= %s:%d\n",
			TID,nq,DelayedCloseN,fp,fh,fd,F,L);
	}
	return 0;
}
static FILE *deqclosed(){
	FILE *fp = 0;
	int si;
	for( si = 0;; si++ ){
		if( THEXIT ){
			break;
		}
		if( DelayedCloseX < DelayedCloseN ){
			fp = DelayedCloseB[DelayedCloseX%FCQSIZE];
			DelayedCloseX++;
			/*
			_Fprintf(stderr,"-- %X (%d) %d deQ fclose(%X)\n",
				TID,DelayedCloseN-DelayedCloseX,
				DelayedCloseX,fp);
			*/
			break;
		}
		usleep(300000);
	}
	return fp;
}
#undef fclose
static void filecloser(){
	int fi;
	int fh;
	int rcode;
	FILE *fp;
	double St0,St1,St2,St3;
	_heapLock lock;

	//usleep(10*1000000);
	_Fprintf(stderr,"-- %X started filecloser()\n",TID);
	for(;;){
		if( THEXIT ){
			break;
		}
		fp = deqclosed();
		if( fp == 0 ){
			continue;
		}
		fh = fileno(fp);
		St0 = Time();
		fflush(fp);
		St1 = Time();
		setfd(fp,(int)INVALID_HANDLE_VALUE);
		heapLock("FileCloser",__LINE__,lock);
		St2 = Time();
		rcode = fclose(fp);
		heapUnLock("FileCloser",__LINE__,lock);
		St3 = Time();

 if( 0.5 < St3-St0 )
 _Fprintf(stderr,"-- %X %d/%d delayed fclose(%X/%X)=%d (%.3f %.3f %.3f)\n",
 TID,DelayedCloseX,DelayedCloseN,fp,fh,rcode,St1-St0,St2-St1,St3-St2);
	}
}

#undef feof
FILEif1(feof,-1)
#undef ferror
FILEif1(ferror,-1)
#undef clearerr
FILEvf1(clearerr)
#undef fgetc
FILEif1(fgetc,EOF)

static int TotalOpen;
static int TotalClose;
static int TotalRead;
static int TotalWrote;
static double TotalOpenTime;
static double TotalCloseTime;
static double TotalWriteTime;
static double TotalReadTime;
extern double TotalSendTime;
extern double LOGX_recvTime;
extern int LOGX_sentCount;
extern int LOGX_recvCount;

#undef fflush
typedef int (*FILEfunc)(FILE *fp);
int XY_fflush(FILE *fp){
	int fd;
	int fh;
	int rcode;

FILEfunc func = fflush;
double *Total = &TotalWriteTime;
int ecode = EOF;

	double St0 = Time();

	fh = (int)fileno(fp);
	if( fh == CLOSED_HANDLE_VALUE ){ /* closed by fcloseFILE */
		rcode = (*func)(fp);
	}else
	if( fh == (int)INVALID_HANDLE_VALUE ){ /* closed by setfd() ? */
		rcode = (*func)(fp);
	}else
	if( 0 <= (fd = setfh(fp)) ){
		rcode = (*func)(fp);
		setfd(fp,fd);
	}else{
		rcode = ecode;
		_Fprintf(stderr,"--z--%X (%X/%d)=%d %s:%d\n",
			fp,fh,fd,rcode,__FUNCTION__,__LINE__);
	}
	*Total += Time()-St0;
	return rcode;
}

#undef fclose
static int XY_fclose_FL(const char *F,int L,FILE *fp){
	int fd;
	int rcode = EOF;
	int fh;

	fh = (int)fileno(fp);
	if( fh == CLOSED_HANDLE_VALUE ){ /* closed by fcloseFILE */
		rcode = fclose(fp);
		WCE_DESC(stderr,"--a-- (fp=%X / %d)=%d %s:%d\n",
			fp,fh,rcode,__FUNCTION__,__LINE__);
		rcode = 0;
	}else
	if( 0 <= (fd = setfh(fp)) ){
		double St0 = Time();
		if( lFCLOSEQ() ){
			rcode = enqclosed(F,L,fp,fd,fileno(fp));
		}else{
		rcode = fclose(fp);
			TotalClose++;
			TotalCloseTime += Time()-St0;
		}
		if( 0.1 < Time()-St0 ){
			_Fprintf(stderr,"-- %X %.3f fclose(%X/%d) << %s:%d\n",
				TID,Time()-St0,fh,fd,F,L);
		}
	}else{
		rcode = fclose(fp);
		WCE_DESC(stderr,"--x-- (fp=%X / %d)=%d %s:%d <- %s:%d\n",
			fp,fh,rcode,__FUNCTION__,__LINE__,F,L);
		rcode = EOF;
	}
	return rcode;
}
#undef ftell
long XY_ftell(FILE *fp){
	int fd;
	long rcode;
	if( 0 <= (fd = setfh(fp)) ){
		rcode = ftell(fp);
		setfd(fp,fd);
	}else{
		rcode = -1;
	}
	return rcode;
}
#undef fseek
int XY_fseek(FILE *fp,int off,int wh){
	int fd;
	int rcode;
	if( 0 <= (fd = setfh(fp)) ){
		rcode = fseek(fp,(off_t)off,wh);
		setfd(fp,fd);
	}else{
		rcode = -1;
	}
	return rcode;
}
#undef ungetc
static int XY_ungetc(int ch,FILE *fp){
	int fd;
	int rcode;
	if( 0 <= (fd = setfh(fp)) ){
		rcode = ungetc(ch,fp);
		setfd(fp,fd);
	}else{
		rcode = EOF;
	}
	return rcode;
}
#undef fread
int XY_fread(void *buf,int siz,int nel,FILE *fp){
	int fh = 0;
	int fd;
	int rcode;
	if( 0 <= (fd = setfh(fp)) ){
		double St0 = Time();
		fh = fileno(fp);
		rcode = fread(buf,siz,nel,fp);
//SetFilePointer((HANDLE)fh,ftell(fp),0,0);
		setfd(fp,fd);
//_Fprintf(stderr,"--[%d %X/%X] XY_fread  %d,%d = %d\n",fd,fp,fh,siz,nel,rcode);
		if( 0 < rcode ){
			TotalRead += siz*nel;
			TotalReadTime += Time()-St0;
		}
	}else{
		rcode = -1;
	}
//_Fprintf(stderr,"---XY_fread(%X/%d,%d,%d)=%d\n",fh,fd,siz,nel,rcode);
	return rcode;
}
#undef fwrite
int XY_fwrite(const void *buf,int siz,int nel,FILE *fp){
	int fh = 0;
	int fd;
	int rcode;
	if( 0 <= (fd = setfh(fp)) ){
		double St0 = Time();
		fh = fileno(fp);
		rcode = fwrite(buf,siz,nel,fp);
//_Fprintf(stderr,"--[%d %X/%X] XY_fwrite %d,%d = %d\n",fd,fp,fh,siz,nel,rcode);
//SetFilePointer((HANDLE)fh,ftell(fp),0,0);
		setfd(fp,fd);
		if( 0 < rcode ){
			TotalWrote += siz*nel;
			TotalWriteTime += Time()-St0;
		}
	}else{
		rcode = -1;
	}
//_Fprintf(stderr,"---XY_fwrite(%X/%d,%d,%d)=%d\n",fh,fd,siz,nel,rcode);
	return rcode;
}
#undef fputc
static int XY_fputc(int ch,FILE *fp){
	int fh = 0;
	int fd;
	int rcode;
	if( 0 <= (fd = setfh(fp)) ){
		fh = fileno(fp);
		rcode = fputc(ch,fp);
		setfd(fp,fd);
		TotalWrote += 1;
	}else{
		rcode = -1;
	}
	return rcode;
}
#undef fputs
int XY_fputs(const char *s,FILE *fp){
	int fh = 0;
	int fd = fileno(fp);
	int rcode;

	if( fd == fileno(stdout)
	 || fd == fileno(stderr)
	 || fp == stdout
	 || fp == stderr
	){
		return fputs(s,fp);
	}
	if( 0 <= (fd = setfh(fp)) ){
		fh = fileno(fp);
		rcode = fputs(s,fp);
//SetFilePointer((HANDLE)fh,ftell(fp),0,0);
		setfd(fp,fd);
		TotalWrote += strlen(s);
	}else{
		rcode = EOF;
	}
	_Fprintf(stderr,"---fputs(%X/%d,%d)=%d\n",fh,fd,strlen(s),rcode);
	return rcode;
}

#undef fopen
FILE *XX_fopen_FL(const char *F,int L,const char *path,const char *mode){
	FILE *fp;
	FILEX *fxp;
	double St0 = Time();

	if( strcaseeq(path,"nul") || strcaseeq(path,"nul:") ){
		/*
		fp = fdopen(NulDevHandle(),mode);
		*/
		fp = fdopen(NulDevFd(),mode);
_Fprintf(stderr,"----NUL---- XX_fopen(%s): %X: OK?",mode,fp);
fflush(stderr);fgetc(stdin);
		return fp;
	}
	fp = fopen(path,mode);
	if( fp == NULL ){
		WCHAR wpath[1024];
		WCHAR wmode[32];
		strtowstr(wpath,path,ESC_URL); /* UTF-8 to Unicode */
		strtowstr(wmode,mode,ESC_NONE);
		fp = _wfopen(wpath,wmode);
	}

	if( fp ){
		TotalOpenTime += Time()-St0;
		TotalOpen++;
		int fd;
		HANDLE fh;
		fh = (HANDLE)fileno(fp);
		_inc_duph(fileno(fp),path);
		_setmode(fp,_O_BINARY);

		fd = _open_osfhandleX_FL(F,L,fileno(fp),2,0);
		WCE_DESC(stderr,"----A fopen(%X) fn=%X/%d %s %s\n",
			fp,fileno(fp),fd,path,mode);
		setfd(fp,fd);
		setosf_FL("fopen",path,fd,fp,F,L);
		if( SocketOf(fd) ){
			_Fprintf(stderr,"----C socket????%d/%d\n",
				SocketOf(fd),fd);
			sleep(10);
		}
	}else{
		int Err;
		Err = GetLastError();
		WCE_FILE(stderr,"---F XX_fopen(%s,%s)=NULL err=%d/%d\n",
			path,mode,Err,ERROR_SHARING_VIOLATION);
	}
	return fp;
}

#undef fclose
const char *type_fcloseFILE = "W";
int XX_fcloseFILE_FL(FL_PAR,FILE *fp);
int XX_fclose_FL1(FL_PAR,FILE *fp){
	FILEX *fxp;
	int fd;
	int ccode;
	int rcode = EOF;
	int del;
	int fh;
	int refcnt;
	int duph = 0;
	int sock;
	const char *fx_F = "";
	int fx_L = 0;

	fd = fileno(fp);
	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_fclose(): %X\n",fp);
		return 0;
	}

	fxp = getfx(fp);
	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	sock = SocketOf(fd);
	refcnt = _get_osfcount(fh);
	if( fxp ){
		fx_F = fxp->fx_F;
		fx_L = fxp->fx_L;
	}
/*
_Fprintf(stderr,"-- %X %X IHfclose-A [%d]%X/%d (%s:%d) <= %s:%d\n",
TID,fp,fd,fh,sock,fx_F,fx_L,FL_BAR);
*/
	if( isMemDevHandle(fh) ){
		/* fxp points to the FILEX of the target MemDev */
		rcode = XY_fclose_FL(FL_BAR,fp);
		if( fxp ){
			freeFILEX(FL_BAR,fxp,fp,fd,fh);
		}
ccode = _close_osfhandle_FL(FL_BAR,fd);
/*
_Fprintf(stderr,"-- %X %X IHfclose-B [%d]%X/%d (%s:%d) <= %s:%d, r=%d,c=%d\n",
TID,fp,fd,fh,sock,fx_F,fx_L,FL_BAR,rcode,ccode);
*/
		return rcode;
	}
	if( fd ==  CLOSED_HANDLE_VALUE ){
		rcode = XY_fclose_FL(FL_BAR,fp);
_Fprintf(stderr,
"-- %X fclose fxp=%X fp=%X fh=%X fd=%d sock=%d ref=%d rcode=%d <= %s:%d\n",
TID,fxp,fp,fh,fd,sock,refcnt,rcode,FL_BAR);
		return rcode;
	}

	if( sock ){
		WCE_SOCK(stderr,"---s[%X] fcloseFL (%s:%d) fp=%X sock=%d/%d\n",
			getthreadid(),FL_BAR,fp,sock,fd);
		duph = 0;
	}else
	if( fh == 0 ){
//// ------------------ should be specially marked on the first fclose()
//// and rewrite fileno(fp) of other copies with CLOSED_HANDLE_VALUE
		// this can happen duplicated (f)closes for a single fd as
		//  ts = fdopen(ToS,"w"); fs = fdopen(FromS,"r");
		//  fclose(ts); fclose(fs);
		if( fxp == 0 ){
			WCE_ERR(stderr,
			"--#%d fclose(%X H%X/F%d/S%d) %X <- %s:%d ????\n",
			CHILD_SERNO_MULTI,fp,fh,fd,sock,fxp,FL_BAR);
		}else
		if( fxp->fx_error ){
		}else
WCE_ERR(stderr,
"--#%d fclose(%X H%X/F%d/S%d) %X/%s:%d e%d%d r=%d %s a%d d=%d <- %s:%d\n",
 CHILD_SERNO_MULTI,
 fp, fh,fd,sock,fxp,fxp?fxp->fx_F:"",fxp?fxp->fx_L:0,
 fxp?fxp->fx_error:-1,fxp?fxp->fx_eof:-1,
 refcnt,invalidFd(fd)?"i":"0",isActiveTmp(fh),_get_duph(fh),FL_BAR);
		duph = 0;
	}else{
		duph = _dec_duph(fh,"_fclose");
	}
	if( fxp ){
		fxp->fx_closing = 1;
		freeFILEX(FL_BAR,fxp,fp,fd,fh);
	}

	XY_fflush(fp);
	if( sock ){
		WCE_FILE(stderr,"---- XX_fclose(%X %X/%X) ref=%d SHUTDOWN ##\n",
			fp,fh,fd,refcnt);
		/*
		this is bad for Keep-Alive
		ShutdownSocket(fd);
		*/
		Xclose_FL(FL_BAR,fd);
		{
		int *fpp;
		fpp = (int*)fp;
		fpp[11] = CLOSED_HANDLE_VALUE; // INVALID_HANDLE_VALUE
		rcode = XY_fclose_FL(FL_BAR,fp);
		if( rcode != 0 )
		_Fprintf(stderr,"---fclose SOCKET %X rcode=%d\n",fd,rcode);
		}

		rcode = 0;
		return rcode;
	}

 WCE_FILE(stderr,"---- XX_fclose(%X %X/%X/%d) ref=%d inv=%d act=%d dup=%d\n",
 fp,fh,fd,sock,refcnt,invalidFd(fd),isActiveTmp(fh),duph);

	if( fh != 0 && fh != -1 )
	if( 2 <= (refcnt = _get_osfcount(fh)) ){
WCE_FILE(stderr,"---- XX_fclose(%X %X/%X) ref=%d >>> %d\n",fp,fh,fd,
refcnt,_get_osfcount(fh));
		XX_fcloseFILE_FL(FL_BAR,fp);
		_close_osfhandle_FL(FL_BAR,fd);
		return 0;
	}
	if( sock != SocketOf(fd) ){
	_Fprintf(stderr,"-- %X ----fclose F%d/H%X/S%d -> H%X/S%d <= %s:%d\n",
		TID,fd,fh,sock, _get_osfhandle(fd),SocketOf(fd),FL_BAR);
	}
	if( fh == 0 ){
	_Fprintf(stderr,"-- %X ----fclose F%d/H%X/S%d -> H%X/S%d <= %s:%d\n",
		TID,fd,fh,sock, _get_osfhandle(fd),SocketOf(fd),FL_BAR);

		rcode = XY_fclose_FL(FL_BAR,fp);
	}else
	if( sock ){
		_Fprintf(stderr,"---fclose SOCKET F%d/S%d <= %s:%d\n",
			fd,sock,FL_BAR);
		close(fd);
		/*
		rcode = fclose(fp);
		*/
		rcode = XY_fclose_FL(FL_BAR,fp);
	}else
	if( 0 < duph ){
		WCE_FILE(stderr,"---- XX_fclose(%X/%X)*%d/%d DONT YET DUPH\n",
			fh,fd,_get_osfcount(fd),duph);
	}else{
		rcode = XY_fclose_FL(FL_BAR,fp);
		ccode = _close_osfhandle_FL(FL_BAR,fd);
		del = doDeleteOnClose(fd,fh);
	}
	return rcode;
}
int XX_fclose_FL(FL_PAR,FILE *fp){
	int rcode;
	if( 0 ){
		FILEX *fxp;
		int fd = fileno(fp);
		int fh;
		int sock;
		double St = Time();

		sock = SocketOf(fd);
		fh = _get_osfhandle(fd);
		fxp = getfx(fp);
		rcode = XX_fclose_FL1(FL_BAR,fp);
		if( 0.1 < Time()-St )
		_Fprintf(stderr,"-- %X %.3f fclose(F%d/S%d/H%u)%X << %s:%d\n",
			TID,Time()-St,fd,sock,fh,fxp,FL_BAR);
		return rcode;
	}else{
		rcode = XX_fclose_FL1(FL_BAR,fp);
		return rcode;
	}
}

/* just free the FILE without closing */
#undef fcloseFILE
int XX_fcloseFILE_FL(FL_PAR,FILE *fp){
	int fd;
	int fh;
	FILEX *fxp;
	const char *fx_F = "";
	int fx_L = 0;
	int *fpp;
	int fpi;
	int sock;
	int rcode;
	int ccode;

	if( fileno(fp) == CLOSED_HANDLE_VALUE ){
		/* ??? must free the FILE */
		rcode = XY_fclose_FL(FL_BAR,fp);
		_Fprintf(stderr,"-- %X a-- fcloseFILE B:fp=%X / %d, r=%d\n",
			TID,fp,fileno(fp),rcode);
		return -1;
	}
	XY_fflush(fp);
	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	WCE_DESC(stderr,"--a-- fcloseFILE B:fp=%X / %d\n",fp,fd);

	sock = SocketOf(fd);
	fxp = getfx(fp);
	if( fxp ){
		fx_F = fxp->fx_F;
		fx_L = fxp->fx_L;
	}
/*
_Fprintf(stderr,"-- %X %X IHfcloseFILE [%d]%X/%d (%s:%d) <= %s:%d\n",
TID,fp,fd,fh,sock,fx_F,fx_L,FL_BAR);
*/
//_Fprintf(stderr,"---XX_fcloseFILE[%d] fh=%X fp=%X fxp=%X[%d]\n",fd,fh,fp,fxp,fxp?fxp->fx_fi:-1);
	if( isMemDevHandle(fh) ){
		rcode = XY_fclose_FL(FL_BAR,fp);
		if( fxp ){
			freeFILEX(FL_BAR,fxp,fp,fd,fh);
		}
/*
_Fprintf(stderr,"-- %X %X IHfcloseFILE [%d]%X/%d (%s:%d) <= %s:%d r=%d\n",
TID,fp,fd,fh,sock,fx_F,fx_L,FL_BAR,rcode);
*/
		return 0;
	}

	if( fxp ){
		if( fx_F == 0 ){
FILEX *nfxp;
nfxp = getfx(fp);
_Fprintf(stderr,"-- %X fcloseFILE [%d][%d] %X %X <= %s:%d\n",TID,fd,fileno(fp),
fxp,nfxp,FL_BAR);
		}
		freeFILEX("fcloseFILE",__LINE__,fxp,fp,fd,fh);
	}

	fpp = (int*)fp;
	if( fpp[11] == fd ){
		if( sock )
		WCE_SOCK(stderr,"---s fcloseFILE(%X/%X/%X)[11]%X S%d\n",
			fp,fd,fxp,fpp[11],sock);
		fpp[11] = CLOSED_HANDLE_VALUE; // INVALID_HANDLE_VALUE
		/*
		fclose(fp);
		*/
		rcode = XY_fclose_FL(__FUNCTION__,__LINE__,fp);
	}else{
	_Fprintf(stderr,"---- fcloseFILE(%X/%X/%X)[11] IS NOT %X <= %s:%d\n",
			fp,fd,fxp,fpp[11],FL_BAR);
	}
	/*
	for( fpi = 0; fpi < 16; fpi++ ){
		_Fprintf(stderr,"----fcloseFILE(%X/%X)[%d]%8X\n",
			fp,fd,fpi,fpp[fpi]);
		if( fpp[fpi] == fd ){
			fpp[fpi] = -1; // INVALID_HANDLE_VALUE
			fclose(fp);
			break;
		}
	}
	*/
	return fd;
}
void closeFDs(FILE *ifp,FILE *ofp){
	int ifd = -1,ofd = -1;
	int ifh = 0,ofh = 0;
	FILEX *ifxp = 0,*ofxp = 0;

	if( ifp ){
		ifd = fileno(ifp);
		ifh = _get_osfhandle(ifd);
		ifxp = getfx(ifp);
	}
	if( ofp ){
		ofd = fileno(ofp);
		ofh = _get_osfhandle(ofd);
		ofxp = getfx(ofp);
	}
_Fprintf(stderr,"----closeFDs(%X/%X/%X, %X/%X/%X) OK?",
ifp,ifd,ifxp,ofp,ofd,ofxp);
fflush(stderr);fgetc(stdin);

	_dec_duph(ifh,"closeFD-i");
	_close_osfhandle_FL(__FUNCTION__,__LINE__,ifd);
	if( ofd != ofd ){
		_dec_duph(ofh,"closeFD-o");
		_close_osfhandle_FL(__FUNCTION__,__LINE__,ofd);
	}
}

#define READYCC(fxp) (fxp->fx_fil - fxp->fx_pos)
int Xready_cc(void *fp){
	FILEX *fxp;

	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- Xready_cc(): %X\n",fp);
		return 1;
	}
	pausemain("Xready_cc");
	if( fxp = getfx(fp) ){
		if( fxp->fx_pos < fxp->fx_fil )
			return fxp->fx_fil - fxp->fx_pos;
	}
	return 0;
}

int expsockbuf(int fd,int iz,int oz);
static void expsockrcvbuf(FILEX *fxp,int fd,int siz){
	if( fxp->fx_rcvbuf != siz ){
		expsockbuf(fd,siz,0);
		fxp->fx_rcvbuf = siz;
	}
}
static void expandsockrcvbuf(FILEX *fxp,int fd){
	int rcc = fxp->fx_rcc;

	if( 16*TCP_MSS <= rcc ) expsockrcvbuf(fxp,fd,32*TCP_MSS); else
	if(  8*TCP_MSS <= rcc ) expsockrcvbuf(fxp,fd,16*TCP_MSS); else
				expsockrcvbuf(fxp,fd, 8*TCP_MSS);
}
int pollIn(int sock,int msec);
void resetIdleTimer();
int Xrecv(int fd,int sock,void *abuf,unsigned int len,int flags);
static int fillrbuf(FILEX *fxp,int fd,int sock,int ilen,FL_PAR){
	int rcc = 0;
	char *buff = fxp->fx_buf;
	int bsiz = sizeof(fxp->fx_buf);
	int rcc1;
	double St = Time();

	resetIdleTimer();
	expandsockrcvbuf(fxp,fd);
	/*
	rcc1 = recv(sock,buff,bsiz,0);
	*/
	rcc1 = Xrecv(fd,sock,buff,bsiz,0); // to care MSG_PEEK
	if( rcc1 <= 0 )
		return rcc1;
	rcc += rcc1;
	LOGX_recvCount++;
	LOGX_recvBytes += rcc;
	LOGX_recvTime += Time()-St;
	return rcc;

	while( rcc < bsiz && 0 < pollIn(sock,1) ){
_Fprintf(stderr,"--B-- %X (%5d / %5d/ %d) %s:%d\n",TID,rcc1,rcc,ilen,FL_BAR);
		rcc1 = recv(sock,buff+rcc,bsiz-rcc,0);
		if( rcc1 <= 0 )
			break;
_Fprintf(stderr,"--C-- %X (%5d / %5d/ %d) %s:%d\n",TID,rcc1,rcc,ilen,FL_BAR);
		if( 0 < rcc1 ){
			rcc += rcc1;
		}
	}
	return rcc;
}
int XX_fgetc(FILE *fp){
	int fd;
	int rcc;
	int ch;
	int bi;
	int rcode;
	FILEX *fxp;
	int fh;
	int sock;

	if( fp == stdin || fileno(fp) == fileno(stdin) ){
		return fgetc(fp);
	}
	if( fileno(fp) == NulDevHandle() ){
		//_Fprintf(stderr,"----NUL---- XX_fgetc(%X)\n",fp);
		return EOF;
	}
	pausemain("XX_fgetc");
	if( fp == NULL )
		return EOF;
	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	sock = SocketOf(fd);
	if( sock == 0 && !isMemDevHandle(fh) ){
		ch = XY_fgetc(fp);
		return ch;
	}

	/*
	if( isMemDevHandle(fh) )
		fxp = getfxfd(fd);
	else	fxp = getfx(fp);
	*/
	fxp = getfx(fp);

	if( fxp == 0 ){
		WCE_ERR(stderr,
		"--#%d fgetc(%X F%d) %X ????\n",CHILD_SERNO_MULTI,fp,fd,fxp);
		return EOF;
	}

	if( fxp->fx_eof ){
		//_Fprintf(stderr,"---- XX_fgetc[%d] got EOF\n",fileno(fp));
		return EOF;
	}

	if( fxp->fx_pos < fxp->fx_fil ){
		ch = 0xFF & fxp->fx_buf[fxp->fx_pos++];
		return ch;
	}
	if( isMemDevHandle(fh) ){
		WCE_MEMF(stderr,"MEM_fgetc[%d] %X/%X %d/%d EOF (%d)\n",
			fd,fh,fxp,fxp->fx_pos,fxp->fx_fil,fxp->fx_rcc);
		fxp->fx_eof = __LINE__;
		return EOF;
	}
	if( 0 < sock )
		rcc = fillrbuf(fxp,fd,sock,1,FL_ARG);
	else
	rcc = read(fd,fxp->fx_buf,sizeof(fxp->fx_buf));
		//_Fprintf(stderr,"---------getc buffer read=%d\n",rcc);
	if( rcc <= 0 ){
		WCE_SOCK(stderr,"---- XX_fgetc[%d] set EOF <= %s:%d\n",
			fileno(fp),fxp->fx_F,fxp->fx_L);
		fxp->fx_eof = __LINE__;
		ch = EOF;
	}else{
		fxp->fx_rcc += rcc;
		fxp->fx_fil = rcc;
		fxp->fx_pos = 1;
		ch = 0xFF & fxp->fx_buf[0];
		XY_clearerr(fp);
	}
	return ch;
}
char *XX_fgets(PVStr(buf),int siz,FILE *fp){
	FILEX *fxp;
	int fd = fileno(fp);
	int ifd = -1;
	int fh;
	int ismem;
	int sock;
	int i;
	int ch;
	refQStr(dp,buf);

	fh = _get_osfhandle(fd);
	if( fxp = getfx(fp) ){
	}else{
		ifd = setfh(fp);
	}
	for( i = 0; i < siz; i++ ){
		if( fxp ){
			if( fxp->fx_pos < fxp->fx_fil ){
				ch = 0xFF & fxp->fx_buf[fxp->fx_pos++];
			}else	ch = XX_fgetc(fp);
		}else{
			ch = Igetc(fp);
		}
		/*
		if( ch == EOF ){
			if( fpop_fd(fp) ){
				ch = getc(fp);
			}
		}
		*/
		if( ch == EOF ){
			break;
		}
		setVStrPtrInc(dp,ch);
		if( ch == '\n' ){
			break;
		}
	}
	//fprintf(stderr,"---XX_fgets[%d]%X=%d\n",fd,fh,i);
	if( 0 <= ifd ){
		setfd(fp,ifd);
	}
	return (char*)dp;
}

/* should do detection of exeptionReady(fileno(fc)) */
int receiverReset(const char *wh,double timeout,int in,int out);
int pollsock3(int isock,int osock,int xsock,int msec);
static int pollInX(PCStr(wh),int timeout,int sock,int exfd,int cc){
	int tout;
	int ready;
	int xsock;
	double St = Time();
	if( 0 <= exfd ){
		xsock = SocketOf(exfd);
		ready = pollsock3(sock,-1,xsock,timeout);
		tout = ready & 4;
		if( tout )
		syslog_ERROR("[%s]reset pollInX(%d,[%d,%d/%d])=%d %.2f\n",
			wh,timeout,sock,xsock,exfd,tout,Time()-St);
	}else{
		tout = pollIn(sock,timeout) <= 0;
		if( tout )
		syslog_ERROR("[%s] pollInX(%d,[%d])=%d %.2f\n",
			wh,timeout,sock,tout,Time()-St);
	}
	return tout;
}

char *fgetsByBlockX(int exsock,PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp);
char *fgetsByBlock(PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp)
{
	return fgetsByBlockX(-1,BVStr(line),size,fs,
		niced,ltimeout,byline,fromcache,remlen,lengp,isbinp);
}
char *fgetsByBlockX(int exsock,PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp)
{	int cc,ch,bc;
	int timeout;
	int stimeout = 10;
	const char *rcode = line;
	int insize;
	int nread = 0;
	double Start = Time();
	int nnl = 0;
	FILEX *fxp;
	int sock;
	int ready;
	int Fs[32];
	int fd = -1;
	int ofd = fileno(fs);
	int fh;
	int ismem;

	fh = _get_osfhandle(ofd);
	ismem = isMemDevHandle(fh);
	if( ismem ){
		syslog_DEBUG("##fgetsByBlock-MemDev %X/%d fromcache=%d\n",
			fh,ofd,fromcache);
		fromcache = 1;
	}

	alertVStr(line,size);
	if( !fromcache ){
		stimeout = 30;
		timeout = ltimeout;
	}
	if( niced )
		insize = size / 2;
	else	insize = 1024;

	size--;
	bc = 0;

	if( fxp = getfx(fs) ){
		sock = SocketOf(fileno(fs));
	}else{
		sock = -1;
		fd = setfh(fs);
	}

	for( cc = 0; cc < size; ){
		if( ismem ){
			ch = XX_fgetc(fs);
		}else
		if( fxp && 0 < sock ){
		    if( fxp->fx_pos < fxp->fx_fil ){
			ch = 0xFF & fxp->fx_buf[fxp->fx_pos++];
		    }else{
			nread++;
			/* fromcache means from a cache-file or a pipe from
			 * the gzunip filter, so the timeout is not necessary
			 * or the timeout will be done in gunzip filter.
			 * thus "!fromcache" means to do timeout by itself.
			 */
			if( !fromcache ){
			  if( pollIn(sock,10) <= 0 ){
if( fxp->fx_scc == 0 && cc == 0 )
_Fprintf(stderr,"-- %X fgetsBB poll[%d]%d %dms r/z=%d/%d cc=%d/%d <= %s:%d\n",
TID,ofd,sock,timeout,remlen,size,cc,fxp->fx_scc,whStr(line));
			    if( pollInX("fgetsBB",timeout,sock,exsock,cc) ){
				if( cc == 0 ){
_Fprintf(stderr,"-- %X fgetsBB poll[%d]%d %dms r/z=%d/%d cc=%d/%d\n",
TID,ofd,sock,timeout,remlen,size,cc,fxp->fx_scc);
				syslog_ERROR("fgetsBB: TIMEOUT %dms\n",timeout);
				rcode = NULL;
				}
				break;
			    }
			  }
			}
			ch = XX_fgetc(fs);
		    }
		}else{
			ch = Igetc(fs);
		}
		if( ch == EOF ){
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
	if( sock == -1 && 0 <= fd ){
		setfd(fs,fd);
	}
	if( fxp ){
		fxp->fx_scc += cc;
	}

	setVStrEnd(line,cc); /**/
	*lengp = cc;
	*isbinp = bc;
	return (char*)rcode;
}
#undef ungetc
int XX_ungetc(FL_PAR,int ch,FILE *fp){
	int fd = fileno(fp);
	int fh;
	FILEX *fxp;
	int ismem;

	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_ungetc(%X)\n",fp);
		return 0;
	}
	fh = _get_osfhandle(fd);
	ismem = isMemDevHandle(fh);
	if( SocketOf(fd) == 0 && !ismem ){
		/*
		return ungetc(ch,fp);
		*/
		return XY_ungetc(ch,fp);
	}else{
		fxp = getfx(fp);
		if( fxp->fx_fil == 0 || fxp->fx_pos == 0 ){
			fxp->fx_buf[0] = ch;
			fxp->fx_pos = 0;
			fxp->fx_fil = 1;
			/*
			fxp->fx_fil = 0;
			*/
		}else{
			fxp->fx_buf[--fxp->fx_pos] = ch;
		}
		/*
		clearerr(fp);
		*/
		XY_clearerr(fp);
if( strstr(FL_F,"rfc822") == 0 )
_Fprintf(stderr,"---- %s:%d ungetc %d/%d\n",FL_BAR,fxp->fx_pos,fxp->fx_fil);
		return 0;
	}
}
static int readMemFile(FL_PAR,FILEX *fxp,void *buf,int len){
	int rem;
	int icc;

	rem = fxp->fx_fil - fxp->fx_pos;
	if( rem < len )
		icc = rem;
	else	icc = len;
	bcopy(fxp->fx_buf+fxp->fx_pos,(char*)buf,icc);
	fxp->fx_pos += icc;
	return icc;
}

#undef fread
static int fri;
int XX_fread(FL_PAR,void *buf,int siz,int nel,FILE *fp){
	int fd = fileno(fp);
	int fh;
	int sock;
	int len,icc,ri,retry;
	int rcc;
	double St = Time();
	FILEX * fxp;

	fri++;
	thexit(FL_F,FL_L,0);
	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_fread(%X)\n",fp);
		return 0;
	}
	fh = _get_osfhandle(fd);
	fxp = getfxfd(fd);
	if( fxp /*&& fxp->fx_path[0]*/ )
	{
		WCE_MEMF(stderr,"MEM_fread [%d] %X/%X %d/%d\n",
			fd,fh,fxp,fxp->fx_pos,fxp->fx_fil);
	}
	if( isMemDevHandle(fh) && fxp ){
		len = siz*nel;
		if( fxp->fx_eof || fxp->fx_fil == 0 ){
			return 0;
		}
		if( fxp->fx_pos < fxp->fx_fil ){
			icc = readMemFile(FL_BAR,fxp,buf,len);
			/*
			int rem;
			rem = fxp->fx_fil - fxp->fx_pos;
			if( rem < len )
				icc = rem;
			else	icc = len;
			bcopy(fxp->fx_buf+fxp->fx_pos,(char*)buf,icc);
			fxp->fx_pos += icc;
			*/
			if( fxp->fx_pos == fxp->fx_fil ){
	WCE_MEMF(stderr,"MEM_fread set feof fxp=%X %X/%d pos=%d/%d <= %s:%d\n",
	fxp,fh,fd,fxp->fx_pos,fxp->fx_fil,FL_BAR);
				//fxp->fx_fil = 0;
				fxp->fx_pos = 0;
				fxp->fx_eof = __LINE__;
			}
			return icc;
		}
		return 0;
	}else
	if( (sock = SocketOf(fd)) ){
		int opos = 0;
		FILEX * fxp;
		fxp = getfx(fp);
		len = siz*nel;
		icc = 0;
		if( fxp->fx_eof ){
//_Fprintf(stderr,"---- XX_fread[%d] got EOF\n",fileno(fp));
			return 0;
		}

		if( fxp->fx_fil == fxp->fx_pos ){
			opos = fxp->fx_pos;
			syslog_DEBUG("##clear-buff(fil=pos=%d)",opos);
			fxp->fx_fil = 0;
			fxp->fx_pos = 0; /* 9.9.5 this can occur maybe after
			 * fgetBuffered().  Without this clear, filled data
			 * by the next fillrbuf() will be lost.
			 */
		}
		if( fxp->fx_fil == 0 && len < sizeof(fxp->fx_buf) ){
			rcc = fillrbuf(fxp,fd,sock,len,FL_BAR);
			if( rcc <= 0 ){
				fxp->fx_eof = __LINE__;
				return 0;
			}
			fxp->fx_rcc += rcc;
			fxp->fx_fil = rcc;
			WCE_BUFF(stderr,"---- XX_fread[%d]fill %d/%d len=%d\n",
				fileno(fp),fxp->fx_pos,fxp->fx_fil,len);
			if( 0 < opos ){
			syslog_ERROR("##fread(%d) fil=%d pos=%d <= %s:%d\n",
				len,rcc,opos,FL_BAR);
			}
		}
		if( fxp->fx_pos < fxp->fx_fil ){
			int rem;
			rem = fxp->fx_fil - fxp->fx_pos;
			if( rem < len )
				icc = rem;
			else	icc = len;
			bcopy(fxp->fx_buf+fxp->fx_pos,(char*)buf,icc);
			fxp->fx_pos += icc;
			WCE_BUFF(stderr,"---- XX_fread[%d/%d]read %d/%d %d\n",
				sock,fd,fxp->fx_pos,fxp->fx_fil,icc);
			if( fxp->fx_pos == fxp->fx_fil ){
				fxp->fx_fil = 0;
				fxp->fx_pos = 0;
			}
		}
		retry = 0;
		for( ri = 0; icc < len; ri++ ){
/*
			if( 0 < icc && siz == 1 ){
				if( pollIn(sock,2*1000) == 0 ){
_Fprintf(stderr,"----(%d.%d) fread([%d/%d],%d,%d) partial %d/%d (%.3f)\n",
fri,ri,sock,fd,siz,nel,icc,len,Time()-St);
syslog_ERROR("(%d.%d) fread([%d/%d],%d,%d) partial %d/%d (%.3f)\n",
fri,ri,sock,fd,siz,nel,icc,len,Time()-St);
					if( 128 <= icc || 5 <= retry ){
						break;
					}else{
						retry++;
						continue;
					}
				}
			}
*/
			retry = 0;
			setthread_FL(0,FL_ARG,"XX_fread");
			rcc = read(fd,(char*)buf+icc,len-icc);
			setthread_FL(0,FL_ARG,"XX_fread");
			if( rcc <= 0 ){
			WCE_SOCK(stderr,"-- XX_fread[%d/%d] set EOF <= %s:%d\n",
			sock,fd,fxp->fx_F,fxp->fx_L);
				fxp->fx_eof = __LINE__;
				break;
			}
			icc += rcc;
//if(0)
			if( icc < len ){
				if( siz == 1 /* and non-blocking */ ){
					break;
				}
			}
		}
		return icc / siz;
	}else{
		rcc = XY_fread(buf,siz,nel,fp);
		return rcc;
	}
}

int getsockbuf(int fd,int *iz,int *oz);
int setsockbuf(int fd,int iz,int oz);
void set_nodelay(int sock,int onoff);
static CriticalSec sendCSC;

static struct {
	double	poT;
	double	poTMax;
	int	poN;
	int	poZ;
	int	poX;
} POut;
int PollOut(int fd,int timeout);

static double getosv();
int setNonblockingIO(int fd,int on);
int setNonblockingFpTimeout(FILE *fp,int toms){
	FILEX *fxp;
	int fd = fileno(fp);
	/* Non-blocking-I/O seems desired (not to cause blocking) but
	 * chaning SO_SNDBUF during relay or relaying larger data than
	 * SO_SNDBUF seems to make blocking on CE4.1.
	 * It is cared in writes() not to do so.
	if( getosv() < 5 ){
		return -1;
	}
	*/
	if( fxp = getfx(fp) ){
		syslog_ERROR("setNonblockingFpTo(%X/%d,%d)\n",fp,fd,toms);
		setNonblockingIO(fd,toms?1:0);
		fxp->fx_nonblock = toms;
		return 0;
	}
	return -1;
}
static int writes(FL_PAR,FILEX *fxp,int fd,const void *buf,int len){
	int sock;
	int occ,wcc;
	int mutex;
	int nodelay;
	int enfragment;
	int first = fxp?(fxp->fx_wcc==0):0;
	double St,Elp;

	if( fxp->fx_error ){
		_Fprintf(stderr,"-- %X writes[%d] %X -- got ERROR\n",TID,fd,fxp);
		return -1;
	}
	sock = SocketOf(fd);
	mutex = SOCK_SNDMUTEX;
	nodelay = SOCK_SNDNODELAY;
	if( 0 < sock ){
		if( mutex ){
			setupCSC("writes",sendCSC,sizeof(sendCSC));
		}
		if( nodelay ){
			set_nodelay(fd,1);
		}
		POut.poX++;
		POut.poZ += len;
	}
	enfragment = 0;
	St = Time();
	for( occ = 0; occ < len; ){
		if( 0 < sock ){
			int tuc;
			tuc = len-occ;
			if( 0 ){ /* for performance test */
				POut.poN++;
				if( PollOut(fd,30*1000) <= 0 ){
				}
				Elp = Time() - St;
				POut.poT += Elp;
				if( POut.poTMax < Elp ){
					POut.poTMax = Elp;
				}
			}
			if( 0 < SOCK_SNDBUF_MAX && SOCK_SNDBUF_MAX < tuc )
				tuc = SOCK_SNDBUF_MAX;

			if( 0 < fxp->fx_nonblock /* && getosv() < 5 */ ){
				/* in non-blocking output mode, chaning
				 * SO_SNDBUF during relay or sending larger
				 * than SO_SNDBUF seems to block on CE4.1
				 */
				int oosz = -1;
				if( fxp->fx_sndbuf == 0 ){
					int oisz;
					getsockbuf(fd,&oisz,&oosz);
					if( 0 < oosz ){
						fxp->fx_sndbuf = oosz;
					}
				}
				if( 0 < fxp->fx_sndbuf && fxp->fx_sndbuf < tuc){
					syslog_DEBUG("-- SNDBUF %d < %d\n",
						fxp->fx_sndbuf,tuc);
					enfragment = 2;
					tuc = fxp->fx_sndbuf;
				}
			}else
			if( fxp->fx_winctl ){
				int oosz = -1;
				int sbsz = 0;
				if( 32*TCP_MSS <= fxp->fx_wcc ){
					sbsz = TCP_MSS*32;
				}else
				if( 16*TCP_MSS <= fxp->fx_wcc ){
					sbsz = TCP_MSS*8;
				}else{
					sbsz = TCP_MSS*4;
				}
				oosz = setsocksndbuf(fd,sbsz);
				fxp->fx_sndbuf = sbsz;
			}else{
				int oisz = -1;
				int oosz = -1;
				int sbsz = 0;

				oisz = oosz = 0;
				if( fxp->fx_sndbuf ){
					oosz = fxp->fx_sndbuf;
				}else{
					getsockbuf(fd,&oisz,&oosz);
				}
				if( 32*TCP_MSS <= fxp->fx_wcc ){
					sbsz = TCP_MSS*32;
				}else
				if( 16*TCP_MSS <= fxp->fx_wcc ){
					if( TCP_MSS*2 < tuc ){
						enfragment = 1;
						tuc = TCP_MSS*2;
					}
					sbsz = TCP_MSS*8;
				}else
				if( TCP_MSS < tuc ){
					tuc = TCP_MSS;
					enfragment = 1;
					sbsz = TCP_MSS*2;
				}else
				if( fxp->fx_closing ){
					if( fxp->fx_wcc+len < TCP_MSS ){
						/* this seems significant */
						sbsz = TCP_MSS;
					}else	sbsz = oosz + TCP_MSS;
				}else{
					sbsz = oosz;
				}
				if( sbsz != oosz ){
					oosz = setsocksndbuf(fd,sbsz);
					fxp->fx_sndbuf = sbsz;
				}
			}
			if( mutex ){ 
				enterCSC(sendCSC);
			}
			IStr(wh,128);
			sprintf(wh,"writes_%s_%d",FL_BAR);
			setthread_FL(0,FL_BAR,wh);
			wcc = send(sock,(const char*)buf+occ,tuc,0);
			setthread_FL(0,FL_BAR,"writes");
			if( fxp->fx_winctl == 0 ){
				/* keep silent trying not to lose Ack ? */
				if( first && occ == 0 && 1024 <= tuc ){
					Sleep(100);
				}
			}
			if( /*1024 <= tuc &&*/ SOCK_SNDWAIT ){
				Sleep(SOCK_SNDWAIT);
			}
			if( mutex ){ 
				leaveCSC(sendCSC);
			}
			if( 0 < wcc ){
				LOGX_sentBytes += wcc;
				LOGX_sentCount++;
			}
			if( fxp->fx_debug )
				_Fprintf(stderr,"-- send(%d/%d,%d)=%d\n",
					sock,fd,len,wcc);

			if( 0 < fxp->fx_nonblock )
			if( wcc == -1 && GetLastError() == WSAEWOULDBLOCK ){
				double St = Time();
				int err = GetLastError();
				int ready;

				ready = PollOut(fd,fxp->fx_nonblock);
				syslog_ERROR("NBsend(%d) %d/%d E%d R%d %.3f\n",
					fd,wcc,tuc,err,ready,Time()-St);
				if( 0 < ready ){
					continue;
				}
			}
		}else{
			wcc = _write(fd,(const char*)buf+occ,len-occ);
			WCE_MEMFx(stderr,"#### write[%d] %X/%X %d = %d\n",
				fd,_get_osfhandle(fd),fxp,len-occ,wcc);
		}
		if( wcc <= 0 ){
			_Fprintf(stderr,"-- %X writes[%d/%d] %X set ERROR\n",
				TID,sock,fd,fxp);
			fxp->fx_error = 1;
			break;
		}
		occ += wcc;
		fxp->fx_wcc += wcc;

		if( !enfragment )
		if( occ < len ){
			_Fprintf(stderr,"---- fwrite partial %d/%d\n",occ,len);
		}
		TotalSendTime += Time()-St;
	}
	if( 0 < sock ){
		if( nodelay ){
			set_nodelay(fd,0);
		}
	}
	setthread_FL(0,FL_BAR,"writes");
	return occ;
}
int exceptionReady(int fd);
int newtmp(const char *path);
static FILE *setrealtmp(FILEX *fxp,FILE *fp,int fd,int fh){
	int nfd;
	int nfh;
	FILE *ofp = fxp->fx_fp;
	FILE *nfp;
	WCHAR wpath[1024];

	WCE_MEMF(stderr,"MEM_FFLUSH[%d] %X/%X/%X %d %s\n",
		fd,fh,fp,fxp,isMemDevHandle(fh),fxp->fx_path);

	strtowstr(wpath,fxp->fx_path,ESC_NONE);
	nfd = newtmp(fxp->fx_path);
	if( 0 <= nfd ){
		nfp = ofp;
		nfh = _get_osfhandle(nfd);
		WCE_MEMF(stderr,"MEM_inst created real tmp %d/%X %s\n",
			nfd,nfh,fxp->fx_path);
	}else{
		nfp = _wfopen(wpath,L"w+");
		//dumpwstr("--setrealtmp--",wpath);
		nfh = fileno(nfp);
		setfd(nfp,fd);
		fxp->fx_fp = nfp;
	}
	redirect_osf(fd,fh,nfh);
	if( 0 <= nfd ){
		WCE_MEMF(stderr,"MEM_inst close pseudo %d/%X %s\n",
			nfd,nfh,fxp->fx_path);
		close(nfd);
	}
	setDeleteOnClose(nfp,fd,fxp->fx_path);

_Fprintf(stderr,"MEM_FFLUSH[%d] %X/%X/%X %d %s\n",
		fd,nfh,nfp,fxp,isMemDevHandle(nfh),fxp->fx_path);

	return nfp;
}
static int sfwrite(FL_PAR,FILEX *fxp,FILE *fp,const void *buf,int len){
	int fd;
	int fh;
	int pos,occ,wcc;
	int rem = 0;
	int obsize;

	fd = fileno(fp);
	if( fd == CLOSED_HANDLE_VALUE ){
		_Fprintf(stderr,"-- %X sfwrite(%d) fxp=%X <= %s:%d\n",
			TID,fd,fxp,FL_BAR);
		return -1;
	}
	fh = _get_osfhandle(fd);
	if( fxp ){
		obsize = sizeof(fxp->fx_buf);
		/*
		if( fxp->fx_wcc < 8*TCP_MSS ){
			obsize = obsize / 2;
		}
		*/

		if( fxp->fx_error ){
			return -1;
		}
		fxp->fx_nw++;
		if( fxp->fx_debug )
			_Fprintf(stderr,"--(%d) %s(%d/%d,%d) %d %s:%d\n",
				fxp->fx_nw,len==0?"sfflush":"sfwrite",
				SocketOf(fd),fd,len,fxp->fx_pos,FL_BAR);
		if( len == 0 && isMemDevHandle(fh) ){
 WCE_MEMF(stderr,"MEM_fflush[%d] %X/%X/%X dummy %d/%d\n",
 fd,fh,fxp,getfxfd(fd),fxp->fx_pos,fxp->fx_fil);
			return 0;
		}
		if( len == 0 ){ // flush
 if( fxp->fx_path[0] )
 WCE_MEMF(stderr,"MEM_fflush[%d] %X/%X/%X real %d/%d\n",
 fd,fh,fxp,getfxfd(fd),fxp->fx_pos,fxp->fx_fil);
/*
			if( isMemDevHandle(fh) ){
				fp = setrealtmp(fxp,fp,fd,fh);
			}
*/
			if( pos = fxp->fx_pos ){
				wcc = writes(FL_BAR,fxp,fd,fxp->fx_buf,pos);
				fxp->fx_pos = 0;
				fxp->fx_fil = 0;
				if( wcc < pos ){
					fxp->fx_error = 1;
 _Fprintf(stderr,"-- %X ERR sfwrite[%d] %d/%d fflush <= %s:%d\n",
TID,fd,wcc,pos,FL_BAR);
					return -1;
				}
			}
			return 0;
		}
		if( fxp->fx_pos+len < obsize ){
			bcopy(buf,fxp->fx_buf+fxp->fx_pos,len);
			pos = fxp->fx_pos;
			fxp->fx_pos += len;
			fxp->fx_fil = fxp->fx_pos;
			return len;
		}
		if( (pos = fxp->fx_pos) && isMemDevHandle(fh) ){
 WCE_MEMFx(stderr,"----A open Tmpfile and flush %d+%d\n",pos,len);
			setrealtmp(fxp,fp,fd,fh);
			wcc = writes(FL_BAR,fxp,fd,fxp->fx_buf,pos);
			fxp->fx_pos = 0;
			fxp->fx_fil = 0;
			wcc = writes(FL_BAR,fxp,fd,buf,len);
			return wcc;
		}
		if( pos = fxp->fx_pos ){
			if( isMemDevHandle(fh) ){
 WCE_MEMFx(stderr,"----B open Tmpfile %s\n",fxp->fx_path);
				fp = setrealtmp(fxp,fp,fd,fh);
			}
			if( 0 < (rem = obsize - pos) ){
 if(0)
 _Fprintf(stderr,"-- %X SHIFT WRITE %4d+%4d=%4d + %4d (%4d)\n",
 TID,pos,rem,pos+rem,len,len-rem);
				bcopy(buf,fxp->fx_buf+pos,rem);
				pos += rem;
				len -= rem;
				buf = ((char*)buf) + rem;
			}
			wcc = writes(FL_BAR,fxp,fd,fxp->fx_buf,pos);
			fxp->fx_pos = 0;
			fxp->fx_fil = 0;
			if( wcc < pos ){
 _Fprintf(stderr,"-- %X ERR sfwrite[%d] %d/%d pre-flush <= %s:%d\n",
TID,fd,wcc,pos,FL_BAR);
				fxp->fx_error = 1;
				return -1;
			}
			if( len <= 0 ){
_Fprintf(stderr,"-- %X SHIFT WRITE %4d+%4d=%4d + %4d JUST\n",
TID,pos,rem,pos+rem,len);
				return rem;
			}
		}
		if( len <= obsize ){
			bcopy(buf,fxp->fx_buf,len);
			fxp->fx_pos = len;
			fxp->fx_fil = len;
			/*
			return len;
			*/
			return rem+len;
		}else{
			if( isMemDevHandle(fh) ){
 _Fprintf(stderr,"---------B open Tmpfile %s\n",fxp->fx_path);
				fp = setrealtmp(fxp,fp,fd,fh);
			}
			wcc = writes(FL_BAR,fxp,fd,buf,len);
			if( wcc < len ){
 _Fprintf(stderr,"--ERR sfwrite[%d] %d/%d put-direct\n",fd,wcc,len);
				fxp->fx_error = 1;
				return -1;
			}
			/*
			return wcc;
			*/
			return rem+wcc;
		}
	}
	for( occ = 0; occ < len; ){
		wcc = write(fd,(const char*)buf+occ,len-occ);
		if( wcc <= 0 ){
			break;
		}
		occ += wcc;
		if( occ < len ){
			_Fprintf(stderr,"---- fwrite partial %d/%d\n",occ,len);
		}
	}
	_Fprintf(stderr,"-- %X sfwrite[%d]%X(%d/%d) %X\n",TID,fd,fxp,wcc,len);
	return occ;
}

#undef fwrite
int XX_fwrite(FL_PAR,const void *buf,int siz,int nel,FILE *fp){
	int fd = fileno(fp);
	int fh;
	int len,occ;
	int wcc;
	FILEX *fxp;

	if( fp == stdout || fp == stderr ){
		return fwrite(buf,siz,nel,fp);
	}
	thexit(FL_F,FL_L,0);
	//thexit(FL_BAR,0);
	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_fwrite(%X)\n",fp);
		return nel;
	}
	fh = _get_osfhandle_FL(FL_BAR,fd);
	if( isMemDevHandle(fh) ){
		if( fxp = getfxfd(fd) ){
			len = siz * nel;
			occ = sfwrite(FL_BAR,fxp,fp,buf,len);
 WCE_MEMF(stderr,"MEM_fwrite[%d] %X,%X/%X/%X %d %d/%d\n",
 fd,fh,_get_osfhandle(fd),fxp,getfxfd(fd),nel,fxp->fx_pos,fxp->fx_fil);
			return occ / siz;
		}else{
 _Fprintf(stderr,"MEM_fwrite ???\n");
			return -1;
		}
	}else
	if( SocketOf(fd) ){
		fxp = getfx(fp);
		if( fxp ){
			if( fxp->fx_error ){
//_Fprintf(stderr,"---- XX_fxwrite[%d] fx_error DONT WRITE\n",fd);
				return 0;
			}
		}
		len = siz * nel;
		fxp = getfx(fp);
		occ = sfwrite(FL_BAR,fxp,fp,buf,len);
		if( occ != len ){
			_Fprintf(stderr,"-- %X XX_fwrite sfwrite(%d)=%d<=%s:%d\n",
				TID,len,occ,FL_BAR);
		}
		return occ / siz;
	}else{
		wcc = XY_fwrite(buf,siz,nel,fp);
		return wcc;
	}
}

#undef fputc
int XX_fputc(int ch,FILE *fp){
	int fd = fileno(fp);
	int fh;
	char buf[1];
	int wcc;
	int sock;
	FILEX *fxp;

	fh = _get_osfhandle(fd);
	if( isMemDevHandle(fh) ){
		buf[0] = ch;
		fxp = getfx(fp);
		/*
		fxp = getfxfd(fd);
		if( getfx(fp) != getfxfd(fd) )
		fprintf(stderr,"---- XX_fputc[%d] %X %X\n",fd,fxp,getfxfd(fd));
		*/
		wcc = sfwrite(__FILE__,__LINE__,fxp,fp,buf,1);
	}else
	if( sock = SocketOf(fd) ){
		buf[0] = ch;
		fxp = getfx(fp);
		wcc = sfwrite(__FILE__,__LINE__,fxp,fp,buf,1);
		WCE_FILE(stderr,"----SOCK putc(%X/%d/%d %X)=%d %c\n",
			fp,fd,ch,wcc,isprint(ch)?ch:' ');
	}else{
		wcc = XY_fputc(ch,fp);
		/*
		WCE_FILE(stderr,"----FILE putc(%X/%d %X)=%d %c\n",
			fp,fd,ch,wcc,isprint(ch)?ch:' ');
		*/
	}
	return wcc;
}
static int putcX(FILEX *fxp,FILE *fp,int ch){
	char buf[1];
	buf[0] = ch;
	if( fxp ){
		if( sfwrite("Xfputs",__LINE__,fxp,fp,buf,1) <= 0 )
			return EOF;
	}else{
		if( XY_fputc(ch,fp) == EOF )
			return EOF;
	}
	return 0;
}
int XfputsCRLF(PVStr(str),FILE *fp){
	int err = 0;
	int ch;
	int lastch = 0;
	const char *sp;
	int fd = fileno(fp);
	int fh;
	FILEX *fxp;

	fh = _get_osfhandle(fd);
	fxp = getfx(fp);

	for( sp = str; ch = *sp; sp++ ){
		assertVStr(str,sp);
		if( putcX(fxp,fp,ch) == EOF ){
			return 1;
		}
		lastch = ch;
		if( sp[1] == '\n' ){
			if( ch != '\r' ){
				if( putcX(fxp,fp,'\r') == EOF ){
					return 2;
				}
			}
		}
	}
	if( lastch != '\n' ){
		if( lastch != '\r' ){
			if( putcX(fxp,fp,'\r') == EOF ){
				return 3;
			}
		}
		if( putcX(fxp,fp,'\n') == EOF ){
			return 4;
		}
	}
	return 0;
}

#undef fputs
#undef Xfputs
int XX_fputs(FL_PAR,const char *s,FILE *fp){
	int fd = fileno(fp);
	int fh;
	int len;
	int wcc;

	thexit("",0,0);
	if( fd == fileno(stdout)
	 || fd == fileno(stderr)
	 || fp == stdout
	 || fp == stderr
	){
		return _Fprintf(fp,"%s",s);
	}
	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"-- %X --NUL-- XX_fputs(%X/%d,%d)\n",
			TID,fp,fd,strlen(s));
		return 1;
	}
	fd = fileno(fp);
	fh = _get_osfhandle(fd);
	len = strlen(s);
	if( isMemDevHandle(fh) ){
		wcc = XX_fwrite("MEM_fputs",__LINE__,s,1,len,fp);
		if( wcc <= 0 )
			return EOF;
		else	return 0;
	}else
	if( SocketOf(fd) ){
		wcc = XX_fwrite(__FUNCTION__,__LINE__,s,1,len,fp);
		if( wcc != len ){
		_Fprintf(stderr,"-- %X %s:%d fputs - fwrite error: %d/%d\n",
				TID,FL_BAR,wcc,len);
		}
		if( wcc <= 0 ){
			return EOF;
		}else{
			return 0;
		}
	}else{
		return XY_fwrite(s,1,strlen(s),fp);
	}
}
#endif /*} WinCE */

#if defined(_MSC_VER) /*{*/
FILE *initLogfp;
static int initLogStart;
static int initLogSize = 128*1024;
static int initLogDuration = 600;
static CriticalSec ilogCSC;
static void openInitLog(){
	initLogfp = _wfopen(L"/DeleGate/initial-log.txt",L"w");
	if( initLogfp ){
		IStr(cwd,512);
		initLogStart = time(0);
		getcwd(cwd,sizeof(cwd));
		putInitlog("----BEGIN initial-log.txt [%d] %X %s\n",
			getpid(),initLogStart,cwd);
	}
}
static int closeInitLog(){
	if( initLogfp == 0 )
		return 0;

	if( initLogSize < Iftell(initLogfp) ){
		fwprintf(initLogfp,L"\n--initial-log END by size (%d)\n",
			initLogSize);
	}else 
	if( initLogDuration < time(0)-initLogStart ){
		fwprintf(initLogfp,L"\n--initial-log END by time (%d)\n",
			initLogDuration);
	}else{
		return 0;
	}
	Ifclose(initLogfp);
	initLogfp = 0;
	return 1;
}
int FMT_putInitlog(const char *fmt,...){
	IStr(buf,8*1024);
	VARGS(16,fmt);

	if( initLogfp == 0 )
		return 0;
	
	setupCSC("Initlog",ilogCSC,sizeof(ilogCSC));
	enterCSC(ilogCSC);
	sprintf(buf,fmt,VA16);
	fwrite(buf,1,strlen(buf),initLogfp);
	Ifflush(initLogfp);
	closeInitLog();
	leaveCSC(ilogCSC);
	return 1;
}

int XX_fflush_FL(FL_PAR,FILE *fp);
static int _Fprintf(FILE *fp,const char *fmt,...){
	IStr(buf,8*1024);
	WCHAR wbuf[8*1024];
	int wcc;
	VARGS(16,fmt);

	if( fp == stderr || fp == stdout ){ /* isatty(fileno(fp)) */
		if( notty ){
			wcc = 0;
		}else{
			sprintf(buf,fmt,VA16);
			strtowstr(wbuf,buf,strlen(buf));
			wcc = fwprintf(fp,L"%s",wbuf);
			if( wcc <= 0 ){
				notty = 1;
			}
		}
	}else{
		wcc = fprintf(fp,fmt,VA16);
	}
	if( initLogfp ){
		putInitlog(fmt,VA16);
	}
	return wcc;
}
#endif /*} Win */

#ifdef UNDER_CE /*{*/
#undef fprintf
#undef Xfprintf
int XX_vfprintf(FILE *fp,const char *fmt,va_list ap){
	int wcc,occ;
	IStr(buf,8*1024);

	if( fp == stderr || fileno(fp) == fileno(stderr)
	 || fp == stdout || fileno(fp) == fileno(stdout)
	){
		vsnprintf((char*)buf,sizeof(buf),fmt,ap);
		wcc = _Fprintf(fp,"%s",buf);
		return wcc;
	}

	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_vfprintf(%X)\n",fp);
		return 1;
	}
	occ = vsnprintf((char*)buf,sizeof(buf),fmt,ap);
	wcc = XX_fwrite(__FUNCTION__,__LINE__,buf,1,occ,fp);
	if( wcc != occ ){
		FILEX *fxp;
		if( fxp = getfx(fp) ){
	_Fprintf(stderr,"-- vfprintf/fwrite error: %X %d/%d %d/%d %s:%d\n",
			fxp,wcc,occ,
			fxp->fx_error,fxp->fx_eof,
			fxp?fxp->fx_F:"",fxp?fxp->fx_L:0);
		}
	}
	return wcc;
}

#undef ftell
long XX_ftell(FILE *fp){
	long off;
	int fd = fileno(fp);
	int fh;
	FILEX *fxp;

	if( fileno(fp) == fileno(stdout) || fileno(fp) == fileno(stderr) ){
		WCE_FILE(stderr,"----ftell(%X/%X) stdio\n",fp,fileno(fp));
		return -1;
	}
	fh = _get_osfhandle(fd);
	fxp = getfx(fp);

	if( isMemDevHandle(fh) ){
		if( fxp )
			off = fxp->fx_pos;
		else	off = -1;
		WCE_MEMF(stderr,"MEM_ftell [%d] %X %X %X off=%d [%s]\n",
			fd,fh,fp,fxp,off,fxp?fxp->fx_path:"");
		return off;
	}else
	if( SocketOf(fd) ){
		WCE_FILE(stderr,"----ftell(%X/%X) socket\n",fp,fileno(fp));
		return -1;
	}else{
		off = XY_ftell(fp);
		return off;
	}
}

static int MemChsize(int fd,int size){
	FILEX *fxp;
	int fh;
	if( fxp = getfxfd(fd) ){
		fh = _get_osfhandle(fd);
		WCE_MEMFx(stderr,"#MEM_chsize[%d] %X/%X (%d) %d/%d\n",
			fd,fh,fxp,size,fxp->fx_pos,fxp->fx_fil);
		fxp->fx_fil = size;
		return 0;
	}
	return -1;
}
static int MemStat(int fd,struct stat *st){
	FILEX *fxp;
	int fh;

	fxp = getfxfd(fd);
	if( fxp == 0 ){
		return -1;
	}
	fh = _get_osfhandle(fd);
	st->st_size = fxp->fx_fil;
	st->st_mode |= S_IFREG;
	st->st_ctime = time(0);
	st->st_atime = time(0);
	st->st_mtime = time(0);
	WCE_MEMF(stderr,"MemStat  [%d] %X/%X SIZE=%d\n",
		fd,fh,fxp,fxp->fx_fil);
	return 0;
}
static int MemFseek(FILE *fp,int fd,int off,int wh){
	FILEX *fxp;

	/*
	if( fp )
		fxp = getfx(fp);
	else	fxp = getfxfd(fd);
	*/
	fxp = getfxfd(fd);
	if( fxp ){
		WCE_MEMF(stderr,"MEM_fseek [%d] %X/%X/%X %d,%d %d/%d\n",
			fd,_get_osfhandle(fd),fxp,getfxfd(fd),
			off,wh,fxp->fx_pos,fxp->fx_fil);
		switch( wh ){
			case 0: fxp->fx_pos = off; break;
			case 1: fxp->fx_pos += off; break;
			case 2: fxp->fx_fil += off; break;
		}
		if( fxp->fx_pos < 0 ){
			fxp->fx_pos = 0;
		}else
		if( fxp->fx_fil < fxp->fx_pos ){
			fxp->fx_pos = fxp->fx_fil;
		}
 WCE_MEMF(stderr,"MEM_fseek(%d,%d) >>> %d/%d\n",off,wh,fxp->fx_pos,fxp->fx_fil);
		if( fxp->fx_eof ){
 WCE_MEMF(stderr,"MEM_fseek cleared EOF=%d\n",fxp->fx_eof);
			fxp->fx_eof = 0;
		}
		return fxp->fx_pos;
	}
	return -1;
}
static int MemRead(int fd,void *buf,int siz){
	FILEX *fxp;
	int rcc;
	fxp = getfxfd(fd);
	if( fxp == 0 ){
		return -1;
	}

	rcc = -1;
	if( fxp->fx_pos < fxp->fx_fil ){
		rcc = readMemFile(FL_ARG,fxp,buf,siz);
		WCE_MEMF(stderr,"MEM_read [%d] %d/%d %d/%d ####\n",
			fd,rcc,siz, fxp->fx_pos,fxp->fx_fil);
	}
	return rcc;
}

#undef fseek
int XX_fseek(FILE *fp,int off,int wh){
	FILEX *fxp;
	int fh;

	int fd = fileno(fp);
	if( fp == stdout
	 || fp == stderr
	 || fd == fileno(stdout)
	 || fd == fileno(stderr)
	){
		return -1;
	}
	fh = _get_osfhandle(fd);
	if( isMemDevHandle(fh) ){
		return MemFseek(fp,fd,off,wh);
	}else
	if( SocketOf(fd) ){
		return -1;
	}else{
		int noff;
		noff = XY_fseek(fp,off,wh);
		return off;
	}
}
#undef fflush
int IsConnected(int sock,const char **reason);
int XX_fflush_FL(FL_PAR,FILE *fp){
	int fd = fileno(fp);
	int fh;
	FILEX *fxp;
	int sock;
	int wascon;

	if( fileno(fp) == fileno(stdout) || fileno(fp) == fileno(stderr) ){
		return fflush(fp);
	}
	if( fileno(fp) == NulDevHandle() ){
		_Fprintf(stderr,"----NUL---- XX_fflush(%X)\n",fp);
		return 0;
	}
	fh = _get_osfhandle(fd);
	if( isMemDevHandle(fh) ){
		if( fxp = getfxfd(fd) ){
			sfwrite(FL_BAR,fxp,fp,"",0);
			return 0;
		}else{
			_Fprintf(stderr,"MEM_fflush fxp none\n");
			return EOF;
		}
	}else
	if( (fxp = getfx(fp)) && (sock = SocketOf(fd)) ){
		/*
		if( fxp = getfx(fp) ){
			if( fxp->fx_error ){
//_Fprintf(stderr,"---- FFLUSH[%d] fxp:%X error=%d\n",fd,fxp,fxp->fx_error);
				return EOF;
			}
		}else{
			_Fprintf(stderr,"---FFLUSH[%d] fxp:0\n",fd);
		}
		*/
		wascon = IsConnected(fd,NULL);
		if( sfwrite(FL_BAR,fxp,fp,"",0) < 0 ){
 syslog_ERROR("---- SOCKET fflush(%d/%d/%X/%X) EOF %d %d %s:%d\n",
sock,fd,fp,fxp,wascon,fxp->fx_error,FL_BAR);
 _Fprintf(stderr,"-- %X SOCKET fflush(%d/%d) EOF %d %s:%d\n",
TID,sock,fd,wascon,FL_BAR);
			return EOF;
		}
		return 0;
	}else{
		return XY_fflush(fp);
	}
}

static FILE *memTmpfile(FL_PAR,int fd,const char *path,const char *mode){
	FILE *fp;
	FILEX *fxp;
	int fh;

	fp = _wfdopen((void*)fd,L"w+b");
	fh = _get_osfhandle(fd);
	syslog_DEBUG("##memTmpFile(%s)=%d/%X/%X <= %s:%d\n",path,fd,fp,fh,FL_BAR);

	if( fp ){
		_setmode(fp,_O_BINARY);
		/*
		setDeleteOnClose(fp,fileno(fp),path);
		it need to be set when the file is really created
		*/
		fxp = getfxx(FL_BAR,fp,1);
fxp->fx_fh = fh;
fxp->fx_mem = (FILEX*)malloc(sizeof(FILEX));
bzero(fxp->fx_mem,sizeof(FILEX));
strcpy(fxp->fx_mem->fx_path,path);
strcpy(fxp->fx_path,path);
WCE_MEMF(stderr,"#### #### MEM_tmpfile[%d/%d %X %X %X]%s\n",
	fd,fileno(fp),fh,fp,fxp,path);
		return fp;
	}
	return 0;
}
FILE *fdopenMemTmpfile(FL_PAR,int fd,const char *mode){
	FILEX *fxp;
	FILEX *nfxp;
	FILE *nfp = 0;
	int ofd;
	int fh;

	fh = _get_osfhandle(fd);
	if( fxp = getfxfh(fh) ){
		ofd = fileno(fxp->fx_fp);
		nfp = _wfdopen((void*)fd,L"w+b");
		_setmode(nfp,_O_BINARY);
		nfxp = getfxx(FL_BAR,nfp,1);
		fxp->fx_fh = fh;
		if( fxp->fx_mem ){
			fxp->fx_mem->fx_eof = 0;
			fxp->fx_mem->fx_error = 0;
	/* fx_eof and fx_error of nfxp ("myfxp") must be used */
	/* fx_pos too. */
	/* but fx_fil must be of the real-body of the MemFile */
		}
		nfxp->fx_mem = fxp->fx_mem;
		/*
		nfp = memTmpfile(FL_BAR,fd,fxp->fx_path,mode);
		*/
		WCE_MEMFx(stderr,"#MEM_fdopen(%d/%d)=%X %X/%X/%X (found)\n",
			fd,ofd,nfp, fxp,_get_osfhandle(fd),_get_osfhandle(ofd));
		return nfp;
	}
	_Fprintf(stderr,"???? MEM_fdopen(%d/%X)=%X (not-found)\n",fd,fh,nfp);
	return 0;
}
FILE *fopen_tmpfile(const char *path){
	int fd;
	FILE *fp;
	FILEX *fxp;

	fd = _open_osfhandle(newMemDevHandle(),2);
	if( fp = memTmpfile(__FUNCTION__,__LINE__,fd,path,"w+b") ){
		return fp;
	}

	fd = newtmp(path);
	if( fd < 0 ){
		_Fprintf(stderr,"---- WinCE cannot create tmp: %s\n",path);
		return 0;
	}
	fp = fdopen(fd,"w+b");
	setDeleteOnClose(fp,fd,path);
	return fp;
}
FILE *TMPFILEXX(const char*,const char*,int,const char*,int,const char*);
FILE *XX_TMPFILEXX(PCStr(what),xPVStr(path)){
	FILE *fp;
	IStr(pathb,1024);
	if( path == 0 ){
		path = pathb;
		pathBASE = pathb;
		pathSIZE = sizeof(pathb);
	}
	fp = TMPFILEXX(what,BVStr(path));
	WCE_FILE(stderr,"TMPFILE(%s) %s:%d (%s) fp=%X/%d\n",what,
		pathFILE,pathLINE,path,fp,fp?fileno(fp):-1);
/*
_Fprintf(stderr,"-- %X TMPFILE [%X/%d](%s) %s:%d (%s)\n",TID,
fp,fp?fileno(fp):-1,what,pathFILE,pathLINE,path);
*/
	if( fp ){
		setosf_FL(what,path,fileno(fp),fp,what,0);
	}
	return fp;
}
FILE *MEMFILE(PCStr(what)){
	return TMPFILE(what);
	/*
	FILE *fp;
	fp = _wfdopen((void*)NulDevHandle(),L"w+");
	_Fprintf(stderr,"---------------------MEMFILE(%s)=%X\n",what,fp);
	return fp;
	*/
}

int unlink(const char *path){
	int rcode;
	int exist;
	WCHAR wpath[1024];
	struct stat st;

	exist = stat(path,&st) == 0;
	strtowstr(wpath,path,ESC_NONE);
	SetLastError(0);
	if( DeleteFile(wpath) )
		rcode = 0;
	else	rcode = -1;
	WCE_LINK(stderr,"-- unlink(%s)=%d err=%d exist=%d\n",path,rcode,
		GetLastError(),exist);
	return rcode;
}
int rename(const char *opath,const char *npath){
	int rcode;
	WCHAR wopath[1024];
	WCHAR wnpath[1024];
	strtowstr(wopath,opath,ESC_URL);
	strtowstr(wnpath,npath,ESC_URL);
	if( MoveFile(wopath,wnpath) )
		rcode = 0;
	else	rcode = -1;
	//_Fprintf(stderr,"----WinCE rename(%s,%s)\n",npath,opath,rcode);
	return rcode;
}
int rmdir(const char *path){
	int rcode;
	WCHAR wpath[1024];
	int xerr;

	strtowstr(wpath,path,ESC_NONE);
	if( RemoveDirectory(wpath) )
		rcode = 0;
	else	rcode = -1;

	xerr = GetLastError();
	_Fprintf(stderr,"----WinCE rmdir(%s)=%d err=%d\n",path,rcode,xerr);
	return rcode;
}

void *GetProcAddressW(struct HINSTANCE__ *mh,char const *sym){
	WCHAR wsym[1024];
	void *sa;
	strtowstr(wsym,sym,ESC_NONE);
	sa = GetProcAddressW(mh,wsym);
	//_Fprintf(stderr,"----WinCE GetProcAddressW(%s)=%X\n",sym,sa);
	return sa;
}
int xspawnvpe(int pmode,PCStr(path),const char*const av[],const char*const ev[],PROCESS_INFORMATION *pinfo);
int _spawnvpe(int pmode,PCStr(path),const char*const av[],const char*const ev[]){
	int pid;
	PROCESS_INFORMATION pinfo;
	_Fprintf(stderr,"----WinCE spawnvep(%d,%s)\n",pmode,path);
	bzero(&pinfo,sizeof(pinfo));
	pid = xspawnvpe(pmode,path,av,ev,&pinfo);
	_Fprintf(stderr,"----WinCE spawnvep(%s)=%X\n",path,pid);
	return pid;
}
int _cwait(int *stat,int pid,int){
	int ok;
	_Fprintf(stderr,"----WinCE _cwait(%X)...\n",pid);
	ok = WaitForSingleObject((HANDLE)pid,15*1000);
	_Fprintf(stderr,"----WinCE _cwait(%X)=%d\n",pid,ok);
	if( ok != WAIT_TIMEOUT ){
		return 0;
	}else{
		return -1;
	}
}

int Timelocal(struct tm *tm);
extern "C" {
static char *_ctime;
char *ctime(const time_t *clock){
	IStr(st,128);
	int ut;
	ut = *clock;
	StrftimeLocal(AVStr(st),sizeof(st),"%a %b %d %H:%M:%S %Y",ut,0);
	if( _ctime == 0 )
		_ctime = (char*)malloc(sizeof(st));
	Xstrcpy(ZVStr(_ctime,sizeof(st)),st);
	//_Fprintf(stderr,"----WinCE   ctime(%8X) %s (%X)\n",ut,st,clock);
	return _ctime;
}
static char *_atime;
char *asctime(const struct tm *tm){
	IStr(st,128);
	int ut;
	struct tm tmb;

	tmb = *tm;
	ut = Timegm(&tmb);
	StrftimeGMT(AVStr(st),sizeof(st),"%a %b %d %H:%M:%S %Y",ut,0);
	if( _atime == 0 )
		_atime = (char*)malloc(sizeof(st));
	Xstrcpy(ZVStr(_atime,sizeof(st)),st);
	//_Fprintf(stderr,"----WinCE asctime(%8X) %s\n",ut,st);
	return _atime;
}
}
char *rsctime(long,char const *,int,char const *,int,char const * const){
	_Fprintf(stderr,"----WinCE rsctime()\n");
        return "";
}

void UnixTimeToFileTime(time_t ut,FILETIME *ft);
void UnixTimeToSystemTime(time_t ut,SYSTEMTIME *st){
	FILETIME ft;
	UnixTimeToFileTime(ut,&ft);
	FileTimeToSystemTime(&ft,st);
}
/*
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
*/

static TIME_ZONE_INFORMATION tz;
static int rt = -1;
static int gmtoff;
int timeToTm(time_t ut,struct tm *tm,int loc){
	SYSTEMTIME st;

	bzero(&tz,sizeof(tz));
	if( rt == -1 ){
		rt = GetTimeZoneInformation(&tz);
		gmtoff = -tz.Bias/60;
		_Fprintf(stderr,"--WinCE GMTOFF = %d\n",gmtoff);
	}
	if( loc ) ut += gmtoff*60*60;
	UnixTimeToSystemTime(ut,&st);
	SystemTimeToTm(&st,tm);
	return 0;
}

#include <winioctl.h>
#include <ntddndis.h>
int wstrlen(WCHAR *ws){
	int wi;
	for( wi = 0; ws[wi]; wi++ ){
	}
	return wi;
}
static int wmsztoszX(int osz,int isz,void *val,WCHAR *wval,int typ,int esc){
	int usz = isz;

	//_Fprintf(stderr,"--Reg typ=%d/%d %d/%d\n",typ,REG_SZ,isz,osz);
	switch( typ ){
		case REG_SZ:
			wstrtostrX(osz,(char*)val,wval,esc);
			usz = strlen((char*)val) + 1;
			break;
		case REG_MULTI_SZ:
		 {
			int rem = osz;
			char *vp = (char*)val;
			WCHAR *wvp = wval;
			int len;
			int wlen1;
			for(; 0 < rem; ){
				wlen1 = wstrlen(wvp);
				wstrtostrX(rem,vp,wvp,esc);
				len = strlen(vp);
				vp += len + 1;
				/*
				wvp += len + 1;
				*/
				rem -= len + 1;
				wvp += wlen1 + 1;
				if( *wvp == 0 ){
					*vp++ = 0;
					break;
				}
			}
			usz = vp - val;
		 }
		 break;
	}
	return usz;
}
int askWinOK(PCStr(fmt),...);
extern "C" {
	long RegQueryValueExA(HKEY hKey,const char *vn,LPDWORD lpReserved,
		LPDWORD typ,LPBYTE val,LPDWORD len)
	{	int ok;
		WCHAR wvn[1024];
		unsigned char *vp = (unsigned char *)val;
		int olen = *len;
		int usz;

		strtowstr(wvn,vn,ESC_NONE);
		ok = RegQueryValueExW(hKey,wvn,lpReserved,typ,val,len);
		if( ok == ERROR_SUCCESS ){
			if( *typ == REG_MULTI_SZ ){
				WCHAR *wval = (WCHAR*)val;
				int nlen = *len;
				int wlen = *len/2;
				if( nlen < olen )
				if( wval[wlen-2] != 0 || wval[wlen-1] != 0 ){

				// MULTI_SZ not terminated with 0 0 (DNS) ??
				IStr(buf,1024);
				refQStr(bp,buf);
				int wi;
				for(wi=0;wi<wlen+2;wi++){
					Rsprintf(bp,"(%d)%X ",wi,wval[wi]);
				}
if(0)askWinOK("Non-00-Terminated MSZ (%s)(%d/%d) %s",vn,nlen,olen,buf);

					wval[wlen] = 0;
				}
			}
			if( *typ == REG_SZ || *typ == REG_MULTI_SZ ){
				IStr(uv,1024);
	usz = wmsztoszX(sizeof(uv),olen,(char*)uv,(WCHAR*)val,*typ,ESC_NONE);
				bcopy(uv,val,usz);
			}
		}
		return ok;
	}
	LONG RegEnumValueA(HKEY hk,DWORD ix,char *vn,LPDWORD nz,LPDWORD rs,
		LPDWORD ty,LPBYTE dt,LPDWORD dz){
		WCHAR wvn[1024];
		int ok;
		int onz = nz?*nz:0;
		int odz = dz?*dz:0;
		int usz;

		ok = RegEnumValueW(hk,ix,wvn,nz,0,ty,dt,dz);
		if( ok == ERROR_SUCCESS ){
			if( vn ) wstrtostrX(onz,(char*)vn,wvn,ESC_NONE);
			if( (*ty == REG_SZ||*ty == REG_MULTI_SZ) && dt != 0 ){
				char uv[1024];
	usz = wmsztoszX(sizeof(uv),odz,(char*)uv,(WCHAR*)dt,*ty,ESC_NONE);
				bcopy(uv,dt,usz);
			}
		}
		return ok;
	}
	LONG RegDeleteValueA(HKEY hk,const char *vn){
		WCHAR wvn[1024];
		int ok;
		strtowstr(wvn,vn,ESC_NONE);
		ok = RegDeleteValueW(hk,wvn);
		return ok;
	}
}
LONG RegSetValueExX(HKEY hk,const char *vn,DWORD rs,DWORD ty,const LPBYTE dt,DWORD dz){
	WCHAR wvn[1024];
	int ok;
	strtowstr(wvn,vn,ESC_NONE);
	ok = RegSetValueEx(hk,wvn,rs,ty,dt,dz);
	return ok;
}
LONG RegOpenKeyExX(HKEY hk,const char *nm,DWORD rs,REGSAM sa,PHKEY pk){
	WCHAR wnm[1024];
	int ok;
	strtowstr(wnm,nm,ESC_NONE);
	ok = RegOpenKeyExW(hk,wnm,rs,sa,pk);
	return ok;
}
LONG RegEnumKeyExX(HKEY hk,int ix,const char *nm,LPDWORD nz,LPDWORD rs,
	const char *cn,LPDWORD cz,FILETIME *ft){
	WCHAR wnm[1024];
	WCHAR wcn[1024];
	int ok;
	int onz = nz?*nz:0;
	int ocz = cz?*cz:0;

	ok = RegEnumKeyExW(hk,ix,wnm,nz,0,cn?wcn:0,cz,ft);
	if( ok == ERROR_SUCCESS ){
		if( nm ) wstrtostrX(onz,(char*)nm,wnm,ESC_NONE);
		if( cn ) wstrtostrX(ocz,(char*)cn,wcn,ESC_NONE);
	}
	return ok;
}

void getResconfX(HKEY hkey,PCStr(skey),PVStr(where),PVStr(buf));
static struct {
	MStr(cm_list,256);
} CommList;
static int getres1(PCStr(inf),PVStr(buf),PVStr(where)){
	CStr(rkey,1024);
	WCHAR wrkey[1024];
	int res;
	HKEY hkey;

	sprintf(rkey,"Comm\\%s\\Parms\\Tcpip",inf);
	strtowstr(wrkey,rkey,ESC_NONE);
	res = RegOpenKeyExW(HKEY_LOCAL_MACHINE,wrkey,0,
		KEY_QUERY_VALUE,&hkey);
	if( res == ERROR_SUCCESS ){
		getResconfX(hkey,inf,BVStr(where),BVStr(buf));
		RegCloseKey(hkey);
		return 0;
	}else{
		return -1;
	}
}
int regGetResolvConf(PVStr(buf),PVStr(where))
{	HKEY hkey;
	CStr(rkey,1024);
	WCHAR wrkey[1024];
	LONG res;
	char *Adapter_Name = "";
	int ok;

{
int ki;
res = RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"Comm",0,KEY_QUERY_VALUE,&hkey);
refQStr(lp,CommList.cm_list);
 if( res == ERROR_SUCCESS ){
  for( ki = 0; ki < 16; ki++ ){
	IStr(nm,128);
	DWORD nz = sizeof(nm);
	IStr(cn,128);
	DWORD cz = sizeof(cn);
	res = RegEnumKeyExX(hkey,ki,nm,&nz,0,cn,&cz,0);
	if( res == ERROR_SUCCESS ){
		if( CommList.cm_list < lp ) setVStrPtrInc(lp,',');
		Rsprintf(lp,nm);
	}else{
		break;
	}
  }
  RegCloseKey(hkey);
  if( CommList.cm_list < lp ){
	IStr(inf,128);
	const char *dp;
	refQStr(bp,buf);
	refQStr(wp,where);
	clearVStr(buf);
	clearVStr(where);

	dp = CommList.cm_list;
	for( ki = 0; *dp && ki < 16; ki++ ){
		dp = wordScanY(dp,inf,"^,");
		if( *dp == ',' ) dp++;
		if( getres1(inf,AVStr(bp),AVStr(wp)) == 0 ){
			if( *bp ){
				bp += strlen(bp);
				if( where < wp ) setVStrPtrInc(wp,',');
				Rsprintf(wp,"%s",inf);
			}
		}
	}
	if( buf < bp ){
		return 0;
	}
  }
 }
}
	WCHAR wdl[1024];
	IStr(dl,1024);
	DWORD dr;
	HANDLE ndis;
	ndis = CreateFileX("NDS0:",GENERIC_READ,FILE_SHARE_READ,
		0,OPEN_ALWAYS,0,0);
	ok = DeviceIoControl(ndis,IOCTL_NDIS_GET_ADAPTER_NAMES,
		0,0,wdl,elnumof(wdl),&dr,0);
	CloseHandle(ndis);
	if( ok ){
		wstrtostr(dl,wdl,ESC_NONE);
		_Fprintf(stderr,"--WinCE NDIS=%X OK [%d] %s\n",ndis,dr,dl);
	}else{
		_Fprintf(stderr,"----WinCE NDIS=%X NG no Adapter Names\n",ndis);
		return -1;
	}
	setVStrEnd(buf,0);

	return getres1(dl,AVStr(buf),AVStr(where));
/*
	Adapter_Name = dl;
	sprintf(rkey,"Comm\\%s\\Parms\\Tcpip",Adapter_Name);
	strtowstr(wrkey,rkey,ESC_NONE);
	res = RegOpenKeyExW(HKEY_LOCAL_MACHINE,wrkey,0,
		KEY_QUERY_VALUE,&hkey);

	if( res == ERROR_SUCCESS ){
		getResconfX(hkey,rkey,BVStr(where),BVStr(buf));
		_Fprintf(stderr,"--WinCE %s resconf: %s\n",rkey,buf);
		RegCloseKey(hkey);
		return 0;
	}else{
		_Fprintf(stderr,"----WinCE NG %s %d Err=%d\n",rkey,res,
			GetLastError());
	}
	return -1;
*/
}

//-------- current directory
static struct {
	MStr(c_path,1024);
} _cwd;
static char *_getcwd(){
	if( _cwd.c_path[0] == 0 )
		return "/";
	else	return _cwd.c_path;
}
void chdir_cwd(PVStr(cwd),PCStr(go),int userdir);
int chdir(const char *dir){
	IStr(nwd,1024);
	strcpy(nwd,_cwd.c_path);
	chdir_cwd(AVStr(nwd),dir,0);
	WCE_PORT(stderr,"----WinCE chdir([%s][%s][%s])\n",
		_cwd.c_path,dir,nwd);
	strcpy(_cwd.c_path,nwd);
	return 0;
}

struct _finddata_t {
	const char *name;
};
static struct {
	MStr(dirbuf,1024);
} dirBuf;
int _findfirst(const char *filepat,struct _finddata_t *fd){
	WIN32_FIND_DATAW wfd;
	WCHAR wfp[1024];
	HANDLE File;
	IStr(fn,1024);

	if( strtailchr(_getcwd()) != '/' )
		sprintf(fn,"%s/%s",_getcwd(),filepat);
	else	sprintf(fn,"%s%s",_getcwd(),filepat);
	strtowstr(wfp,fn,ESC_URL);
	File = FindFirstFileW(wfp,&wfd);
	WCE_PORT(stderr,"----WinCE FindFirstFile(%s %s)=%X\n",
		fn,filepat,File);
	if( File ){
		wstrtostr(fn,wfd.cFileName,ESC_URL);
		fd->name = strcpy(dirBuf.dirbuf,fn);
 //_Fprintf(stderr,"----WinCE FindFirstFile() %X %s\n",fd->name,fd->name);
		return (int)File;
	}
	return -1;
}
int _findnext(int File,struct _finddata_t *fd){
	WIN32_FIND_DATAW wfd;
	IStr(fn,1024);

	if( FindNextFileW((HANDLE)File,&wfd) ){
		wstrtostr(fn,wfd.cFileName,ESC_URL);
		fd->name = strcpy(dirBuf.dirbuf,fn);
 //_Fprintf(stderr,"----WinCE FindNextFile() %X %s\n",fd->name,fd->name);
		return 0;
	}
	return -1;
}
int _findclose(int File){
	CloseHandle((HANDLE)File);
	return 0;
}

void socket_init();
int SocketPipe(int hv[2],int size){
	socket_init();
	if( Xsocketpair_FL(FL_ARG,AF_INET,SOCK_STREAM,0,hv) == 0 ){
		if( 1024 < size ){
			int iz = -1,oz = -1;
			/*
			setsockbuf(hv[1],0,size);
			*/
			setsocksndbuf(hv[1],size);
			getsockbuf(hv[1],&iz,&oz);
//_Fprintf(stderr,"----PIPE setsockbuf[%d]%X (%X,%X)\n",hv[1],size,iz,oz);
		}
		return 0;
	}else{
		return -1;
	}
}

static struct {
	char *e_vec[256];
	MStr(e_buf,4*1024);
} myenv;
static int myputenv(const char *env){
	int oi,ni,ei;
	const char *oe;
	const char *ob;
	const char *ne;
	refQStr(bp,myenv.e_buf);
	IStr(name,256);

	if( strheadstrX(env,"RANDENV=",0) ){
		return 0;
	}
	ob = wordScanY(env,name,"^=");
	WCE_PORT(stderr,"#### putenv(%s%s)\n",name,ob);

//for(ei=0;environ[ei];ei++) _Fprintf(stderr,"OE[%d] %s\n",ei,environ[ei]);

	bp = myenv.e_buf;
	ni = 0;
	for( oi = 0; oe = environ[oi]; oi++ ){
		if( elnumof(myenv.e_vec) <= ni+1 ){
			break;
		}
		if( ob = strheadstrX(oe,name,0) ){
		}else{
			myenv.e_vec[ni++] = (char*)bp;
			strcpy(bp,oe);
			bp += strlen(bp) + 1;
		}
	}
	myenv.e_vec[ni++] = strcpy(bp,env);
	myenv.e_vec[ni] = 0;
	environ = myenv.e_vec;

//for(ei=0;environ[ei];ei++) _Fprintf(stderr,"NE[%d] %s\n",ei,environ[ei]);
	return 0;
}
int LockFile(void *hf,int ol,int oh,int bl,int bh){
	return 0;
}
int UnlockFile(void *hf,int ol,int oh,int bl,int bh){
	return 0;
}

FILE *tmpfile(){
	FILE *fp;
	_Fprintf(stderr,"----WinCE tmpfile()\n");
	fp = TMPFILEXX("tmpfile()",__FILE__,__LINE__,0,0,0);
	return fp;
}

int saveAuthMan();
int clearAuthMan();
int close_shared();
int close_svstat();
void closeNULLFP();
void closepplog();
int stopcloseR();
int stopSoxThread();
int getNullFd(const char *wh);
extern int CFI_SHARED_FD;
void exitmessageX(const char *F,int L,const char *fmt,...);
static void destroyMainWin(int code,const char *fmt,...);
void putWinStatus(PCStr(fmt),...);
int askWinOK(PCStr(fmt),...);
int getAnswerYN(PCStr(msg),PVStr(ans),int siz);

static void dgcloseall(){
	_Fprintf(stderr,"#### dgcloseall()\n");
	saveAuthMan();
	stopSoxThread();
	stopcloseR();
	close_shared();
	close_svstat();
	closeNULLFP();
	closepplog();
	if( CFI_SHARED_FD != -1 ){
		_Fprintf(stderr,"#### [%d]CFI_SHARED_FD %X\n",
			CFI_SHARED_FD,_get_osfhandle(CFI_SHARED_FD));
		close(CFI_SHARED_FD);
		CFI_SHARED_FD = -1;
	}
	doDeleteOnExit();
	/* should do things equiv. to DO_FINALIZE() */
}
static void thexitX(const char *F,int L,const char *F2,int L2,int code){
	if( getthreadid() == _main_thread ){
		if( THEXIT == THEX_DO ){
			THEXIT = THEX_DOING;
			_Fprintf(stderr,"#### thexit(%s:%d,%d)\n",F,L,code);
			dgcloseall();
			exitmessageX(F,L,"exit(0) th-A (%s:%d)",F2,L2);
			Finish(0);
			_exit(0);
			ExitThread(0);
		}
		if( THEXIT == THEX_DONE ){
			usleep(3*1000000);
			exitmessageX(F,L,"exit(0) th-B %s:%d",F2,L2);
			_exit(0);
		}
	}
}
static int terminatemainthread(const char *F2,int L2,const char *fmt,...){
	VARGS(8,fmt);
	THEXIT = THEX_DO;
	usleep(1*1000000); // might be waiting in select()
	if( THEXIT == THEX_DO ){
		THEXIT = THEX_DONE;
		_Fprintf(stderr,"#### exit by subthread...\n");
		dgcloseall();
		exitmessageX(__FUNCTION__,__LINE__,fmt,VA8);
		Finish(0);
		_exit(0);
	}
	return 0;
}
static int Terminating; // Terminated manually
static int Finishing;
void exitmessageX(const char *F,int L,const char *fmt,...){
	IStr(msg,1024);
	WCHAR wmsg[1024];
	VARGS(16,fmt);

	sprintf(msg,"[%d][%X] ",getthreadix(),TID);
	Xsprintf(TVStr(msg),fmt,VA16);
	if( FinishFile ){
		Xsprintf(TVStr(msg),"\n<<< %s:%d",FinishFile,FinishLine);
	}
	Xsprintf(TVStr(msg),"\n>>> %s:%d",F,L);
	strtowstr(wmsg,msg,ESC_NONE);

	if( !Finishing )
	if( !Terminating )
	MessageBox(NULL,wmsg,L"DeleGate/WinCE",MB_OK|MB_SETFOREGROUND);
}
#undef _exit
static int _inexit;
void exitX(int code,const char *fmt,...){
	VARGS(16,fmt);
	IStr(msg,256);

	destroyMainWin(code,fmt,VA16);

	_Fprintf(stderr,"#### exit(%d) %d ",code,_inexit);
	_Fprintf(stderr,fmt,VA16);
	_Fprintf(stderr,"\n");

	sprintf(msg,"#### exit(%d) %d ",code,_inexit);
	Xsprintf(TVStr(msg),fmt,VA16);
	syslog_ERROR("%s\n",msg);

	if( _inexit ){
		exitmessageX(__FUNCTION__,__LINE__,"exitX(%d) dup",code);
		_exit(code);
	}
	_inexit++;
	_Fprintf(stderr,"#### exit(%d)\n",code);
	dgcloseall();
	if( fmt ){
		exitmessageX(__FUNCTION__,__LINE__,fmt,VA16);
	}else{
		exitmessageX(__FUNCTION__,__LINE__,"exitX(%d) no-fmt",code);
	}
	_exit(code);
}

#endif /*} UNDER_CE */

#ifdef _MSC_VER /*{*/
int thread_fork(int size,int gtid,const char *what,IFUNCP func,...);
const char *DELEGATE_version();
const char *ZlibVersion();
const char *SSLVersion();
int setDebug(const char *arg);
int setDebugForce(const char *arg);
extern int RES_HC_EXPIRE;
int LOGX_stats(PVStr(msg),int shortfmt);
extern const char *DELEGATE_DGROOT;
extern const char *DELEGATE_VARDIR;
extern double ServerStarted;
extern int START_TIME;
extern double awakeSeconds;
double LastIdleReset;
static MEMORYSTATUS mst0,mst1,mstm;

static void globalMemoryStatus(MEMORYSTATUS *mst){
	mst->dwLength = sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(mst);
}
#define GlobalMemoryStatus globalMemoryStatus
static int memused(){
	MEMORYSTATUS mst;
	GlobalMemoryStatus(&mst);
	return (int)(mst.dwTotalPhys - mst.dwAvailPhys);
}

static void makeMssg(PVStr(msg),int stats){
	refQStr(mp,msg);
	IStr(stime,128);

	MEMORYSTATUS mst;
	mst.dwLength = sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(&mst);
	Rsprintf(mp,"Memory: %d%% %d/%dKB\n",mst.dwMemoryLoad,
		mst.dwTotalPhys-mst.dwAvailPhys,mst.dwTotalPhys/1024);
	Rsprintf(mp,"Memory-Delta: %d + %d / %d\n",
		(mst.dwTotalPhys-mst0.dwAvailPhys)/1024,
		(mst0.dwAvailPhys-mst.dwAvailPhys)/1024,
		(mst0.dwAvailPhys-mstm.dwAvailPhys)/1024,
		0
	);

	/*
	Rsprintf(mp,"DeleGate/%s %s\n",DELEGATE_ver(),notty?"NoCon":"");
	*/
	if( START_TIME ){
	StrftimeLocal(AVStr(stime),sizeof(stime),"%H:%M:%S %m/%d",START_TIME,0);
	Rsprintf(mp,"Started: %s (%d/%d/%d)\n",stime,
		(int)awakeSeconds,SleptMsec/1000,time(0)-START_TIME);
	//StrftimeLocal(AVStr(stime),sizeof(stime),"%H:%M:%S %m/%d",time(0),0);
	//Rsprintf(mp,"Current: %s\n",stime);
	}
	Rsprintf(mp,"Proxy-Idle: %.1fs\n",Time()-LastIdleReset);

	/*
	StrftimeLocal(AVStr(stime),sizeof(stime),"%H:%M:%S %m/%d",time(0),0);
	Rsprintf(mp,"Current: %s\n",stime);
	*/
	if( stats ){
	//Rsprintf(mp,"\n");
	LOGX_stats(AVStr(mp),0); mp += strlen(mp);
	Rsprintf(mp,"Write:%8u %6.2f\n",TotalWrote,TotalWriteTime);
	Rsprintf(mp,"Read: %8u %6.2f\n",TotalRead,TotalReadTime);
	Rsprintf(mp,"Open: %8u %6.2f (%.3f)\n",TotalOpen,TotalOpenTime,
		TotalOpen?TotalOpenTime/TotalOpen:0);
	Rsprintf(mp,"Close:%8u %6.2f (%.3f)\n",TotalClose,TotalCloseTime,
		TotalClose?TotalCloseTime/TotalClose:0);
	Rsprintf(mp,"GetFA:%8u %6.2f (%.3f)\n",LOGX_GetFa,LOGX_GetFaElp,
		LOGX_GetFaElp/LOGX_GetFa);
	//Rsprintf(mp,"(%s)\n",GFA.gfa_path);
	}
}
#if defined(UNDER_CE)
static int pausemainX(const char *wh){
	int wcc;
	int ch;

	if( do_pause == 0 )
		return 0;
	wcc = _Fprintf(stderr,">>>> PAUSE %X %s: Hit any key to start >>>>\n",
		getthreadid(),wh);
	if( wcc <= 0 ){
		exitX(0,0);
	}
	ch = Igetc(stdin);

	switch( ch ){
		case 'x':
		case 'q':
		case EOF:
			exitX(0,0);
	}
	_Fprintf(stderr,">>>> RESTARTED >>>>\n");
	do_pause = 0;
	return 1;
}
#endif
extern int THWAIT_noBug;
int thread_wait(int tid,int timeout);
int thread_destroy(int tid);
int setsyspower(const char *name,int flag,int *pflag);
static void updateMainWindow();
int askWinOKWTO(double dtx,PCStr(fmt),...);
int getAnswerYNWTO(double dtx,PCStr(msg),PVStr(ans),int siz);
static int mbox(HWND wnd,const WCHAR *txt,const WCHAR *cap,UINT typ,int *codep){
	int code;
	code = MessageBox(wnd,txt,cap,typ);
	*codep = code;
	return 0;
}
int MessageBoxWTO(double dtx,HWND wnd,const WCHAR *txt,const WCHAR *cap,UINT typ){
	int tid;
	int err;
	int pstat;
	static int code;
	int rem,tx1;
	int noBug;

	if( dtx <= 0 ){
		code = MessageBox(wnd,txt,cap,typ);
		return code;
	}
	code = -1;
	setsyspower("ACTIVE",-1,&pstat);
	tid = thread_fork(0,0,"MessageBox",(IFUNCP)mbox,wnd,txt,cap,typ,&code);
	for( rem = dtx*1000; 0 < rem; rem -= tx1 ){
		if( 2000 < rem )
			tx1 = 2000;
		else	tx1 = rem;
		noBug = THWAIT_noBug;
		THWAIT_noBug = 1;
		err = thread_wait(tid,tx1);
		THWAIT_noBug = noBug;
		if( err == 0 ){
			break;
		}
		putWinStatus("MsgBox Timeout %d/%.1f",rem/1000,dtx);
	}
	if( err == 0 ){
	}else{
		/* should send message to the window and wait */
		thread_destroy(tid);
		updateMainWindow();
		putWinStatus("MsgeBox Timeout(%.1f) %d",dtx,code);
	}
	setsyspower(0,pstat,0);
	return code;
}
int askWinOK(PCStr(fmt),...){
	int code;
	VARGS(16,fmt);

	code = askWinOKWTO(0,fmt,VA16);
	return code;
}
int askWinOKWTO(double dtx,PCStr(fmt),...){
	int buttons;
	IStr(msg,1024);
	WCHAR wmsg[1024];
	int code;
	VARGS(16,fmt);

	sprintf(msg,fmt,VA16);
	strtowstr(wmsg,msg,ESC_URL);
	buttons = MB_OK|MB_ICONQUESTION|MB_SETFOREGROUND|MB_TOPMOST;
	if( 0 < dtx )
		code = MessageBoxWTO(dtx,NULL,wmsg,L"DeleGate/Ok",buttons);
	else
	code = MessageBox(NULL,wmsg,L"DeleGate/Ok",buttons);
	return code;
}
int getAnswerYN(PCStr(msg),PVStr(ans),int siz){
	return getAnswerYNWTO(0,msg,BVStr(ans),siz);
}
int getAnswerYNWTO(double dtx,PCStr(msg),PVStr(ans),int siz){
	int buttons;
	WCHAR wmsg[1024];
	int code;

	strtowstr(wmsg,msg,ESC_URL);
	buttons = MB_YESNO|MB_ICONQUESTION|MB_SETFOREGROUND|MB_TOPMOST;
	if( 0 < dtx )
		code = MessageBoxWTO(dtx,NULL,wmsg,L"DeleGate/YesNo",buttons);
	else
	code = MessageBox(NULL,wmsg,L"DeleGate/YesNo",buttons);
	if( ans == 0 ){
		return code;
	}
	switch( code ){
		case IDYES: sprintf(ans,"y"); break;
		default: sprintf(ans,"n"); break;
	}
	updateMainWindow();
	if( code < 0 )
		return code;
	return 0;
}
static int Nconsole;
static int detect_end(){
	int code;
	IStr(msg,1024);
	WCHAR wmsg[1024];
	int buttons = 0;
	int i;
	int btn;
	int doexit = 0;

	Nconsole++;
	setthreadgid(0,_main_thread);
	for( i = 0; i < 15; i++ ){
		if( ServerStarted )
			break;
		usleep(1000000);
	}
	_Fprintf(stderr,"----DetectEnd START\n");
	buttons = MB_ABORTRETRYIGNORE|MB_DEFBUTTON3|MB_SETFOREGROUND;
	for( i = 0; ; i++ ){
		if( i == 0 ){
		 sprintf(msg,"%s\nZlib: %s\nDGROOT=%s",
			DELEGATE_verdate(),
			ZlibVersion(),
			DELEGATE_DGROOT
		 );
			btn = buttons|MB_ICONINFORMATION;
		}else{
			makeMssg(AVStr(msg),1);
			btn = buttons;
		}

		strtowstr(wmsg,msg,ESC_URL);
		code = MessageBox(NULL,wmsg,L"DeleGate/WindowsCE",btn);

		switch( code ){
			default:
				_Fprintf(stderr,"----Detected %d\n",code);
			case IDABORT:
				doexit = 1;
				goto EXIT;
			case IDRETRY:
				continue;
			case IDIGNORE:
				continue;
		}
	} EXIT:;
	_Fprintf(stderr,"----DetectEnd END\n");
	Nconsole--;
	if( doexit ){
		terminatemainthread(FL_ARG,"Terminated By MessageBox");
	}
	return 0;
}

static int consoleTid;
void closeConsole(){
	int tid;
	if( tid = consoleTid ){
		consoleTid = 0;
		//thread_kill(tid,SIGTERM);
	}
}
static int showMessageBox;
void popupConsole(){
	if( showMessageBox == 0 || 0 < Nconsole ){
		return;
	}
	_Fprintf(stderr,"----DetectEnd start...\n");
	consoleTid = thread_fork(0,0,"dialogue",(IFUNCP)detect_end);
	_Fprintf(stderr,"----DetectEnd started tid=%X\n",consoleTid);
}

#include <TLHELP32.H>
#define TH32CS_SNAPNOHEAPS 0x40000000
static struct {
	double ConnDelay;
	MStr(lc_stat,512);
	MStr(HostName,256);
	/*
	MStr(ExeFile,256);
	*/
	MStr(ExeFilePath,256);
	MStr(RASconns,256);
	MStr(ConnMgr,256);
} lastConn;
const char *myExePath(){
	WCHAR wmyname[256];
	if( lastConn.ExeFilePath[0] == 0 ){
		if( GetModuleFileName(NULL,wmyname,sizeof(wmyname)) ){
			wstrtostr(lastConn.ExeFilePath,wmyname,0);
		}else{
			sprintf(lastConn.ExeFilePath,"%s%s",
				"\\My Documents\\","wince-dg.exe");
		}
	}
	return lastConn.ExeFilePath;
}
#if 0
static const char *myExeFile(PVStr(path)){
	const char *file;
	file = lastConn.ExeFile[0] ? lastConn.ExeFile : "wince-dg.exe";
	sprintf(path,"\\My Documents\\%s",file);
	return path;
}
void getExecPath(){
	HANDLE me;
	MODULEENTRY32 mo;
	PROCESSENTRY32 po;
	IStr(name,1024);
	IStr(path,1024);
	IStr(full,1024);
	int np = 0;
	int mask;

	/*
	QueryFullProcessImageNameW(0,0,full,sizeof(full));
	*/
	mask = TH32CS_SNAPPROCESS|TH32CS_SNAPNOHEAPS;
	//me = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
	me = CreateToolhelp32Snapshot(mask,0);
	_Fprintf(stderr,"--Snapshot=%X\n",me);
	if( me == 0 ){
		sprintf(lastConn.ExeFile,"(Snap-1 Err=%d)",GetLastError());
		return;
	}

	bzero(&po,sizeof(po));
	po.dwSize = sizeof(po);
	if( Process32First(me,&po) == 0 ){
		//sprintf(lastConn.ExeFile,"(Snap-2 Err=%d)",GetLastError());
		sprintf(lastConn.ExeFile,"wince-dg.exe");
		_Fprintf(stderr,"--Process ERROR %d\n",GetLastError());
	}else{
		for(;;){
			np++;
			wstrtostr(path,po.szExeFile,0);
			_Fprintf(stderr,"--Process %8X[%s]\n",
				po.th32ProcessID,path);
			if( po.th32ProcessID == getpid() ){
				strcpy(lastConn.ExeFile,path);
			}
			po.dwSize = sizeof(po);
			if( Process32Next(me,&po) == 0 ){
				break;
			}
		}
	}
	if( lastConn.ExeFile[0] == 0 ){
		sprintf(lastConn.ExeFile,"(Snap-3 No-match/%d)",np);
	}

	bzero(&mo,sizeof(mo));
	mo.dwSize = sizeof(mo);
	if( Module32First(me,&mo) == 0 ){
		_Fprintf(stderr,"--Module ERROR %d\n",GetLastError());
		return;
	}
	for(;;){
		wstrtostr(name,mo.szModule,0);
		wstrtostr(path,mo.szExePath,0);
		_Fprintf(stderr,"--Module %8X[%s][%s]\n",
			mo.th32ProcessID,name,path);

		mo.dwSize = sizeof(mo);
		if( Module32Next(me,&mo) == 0 ){
			break;
		}
	}

	CloseToolhelp32Snapshot(me);
}
#endif
#if defined(UNDER_CE) || (1400 <= _MSC_VER) /*{*/
int ps_unix(FILE *out){
	HANDLE me;
	PROCESSENTRY32 po;
	IStr(path,256);
	int mask;

	SetLastError(0);
	mask = TH32CS_SNAPPROCESS|TH32CS_SNAPNOHEAPS;
	me = CreateToolhelp32Snapshot(mask,0);
	if( me == 0 || me == INVALID_HANDLE_VALUE ){
		Xfprintf(out,"ps: ERROR can't get process snapshot (%d)\n",
			GetLastError());
		Sleep(100);
		me = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		if( me == 0 || me == INVALID_HANDLE_VALUE ){
			return -1;
		}
	}

	bzero(&po,sizeof(PROCESSENTRY32));
	po.dwSize = sizeof(PROCESSENTRY32);
	SetLastError(0);
	if( Process32First(me,&po) == 0 ){
		Xfprintf(out,"ps: ERROR can't get the first process (%d)\n",
			GetLastError());
		return -1;
	}
#ifdef UNDER_CE
	Xfprintf(out,"%8s %2s %3s %s\n",
		"pid","mb","thr","command");
#else
	Xfprintf(out,"%5s %5s %3s %s\n",
		"pid","ppid","thr","command");
#endif
	for(;;){
		wstrtostr(path,po.szExeFile,0);
#ifdef UNDER_CE
		Xfprintf(out,"%8X %02X %3d %s\n",
			po.th32ProcessID,
			po.th32MemoryBase>>24,
			po.cntThreads,
			path);
#else
		Xfprintf(out,"%5u %5u %3d %s\n",
			po.th32ProcessID,
			po.th32ParentProcessID,
			po.cntThreads,
			path);
#endif
		po.dwSize = sizeof(PROCESSENTRY32);
		if( Process32Next(me,&po) == 0 ){
			break;
		}
	}
#ifdef UNDER_CE
	CloseToolhelp32Snapshot(me);
#else
	CloseHandle(me);
#endif
	return 0;
}
#else /*}{*/
int ps_unix(FILE *out){
	return -1;
}
#endif /*}*/
static const char *getvh1(int ac,const char **v,const char *s){
	const char *v1;
	int i;
	for( i = 0; i < ac && (v1 = v[i]); i++ ){
		if( strheadstrX(v1,s,1) ){
			return v1;
		}
	}
	return 0;
}
static const char *getvhs(int ac,const char **v,int cc,const char **cv,const char *s,int body){
	const char *v1,*b1;
	if( (v1 = getvh1(ac,v,s)) || (v1 = getvh1(cc,cv,s)) ){
		if( body ){
			if( b1 = strchr(v1,'=') ){
				v1 = b1+1;
			}
		}
		return v1;
	}
	return 0;
}
#define getvh(ac,av,s) getvhs(ac,av,Cc,Cv,s,0)
#define getvb(ac,av,s) getvhs(ac,av,Cc,Cv,s,1)

static int replacev(int ac,const char **v,const char *h,const char *s){
	int i;
	int len = strlen(h);
	int nr = 0;
	for( i = 0; i < ac; i++ ){
		if( strncmp(v[i],h,len) == 0 ){
			nr++;
			v[i] = s;
		}
	}
	return nr;
}

#define MSGSIZE (4*1024)
static struct {
	MStr(VARDIR,256);
	MStr(ce_prevmsg,MSGSIZE);
} WinCEE;
#define prevmsg WinCEE.ce_prevmsg
const char *ControlPanelText(){
	return prevmsg;
}
static void loadFlags();
int regGetStorageCard(PVStr(cardpath));
void mainX(int ac,const char *av[]);
static int winrestart(HINSTANCE ci,HINSTANCE pi,int ics);
static double MainStart;
extern int RES_TRACE;
extern int SUPPRESS_SYSLOG;
static int issetfv(int *ia);

static char *conffile = "/DeleGate/common.conf.txt";
static int getCv(const char *cv[],int maxcc){
	int cc;
	FILE *fp;
	IStr(line,1024);
	refQStr(lp,line);

	fp = XX_fopen_FL(FL_ARG,conffile,"r");
	if( fp == 0 ){
		fp = XX_fopen_FL(FL_ARG,"/DeleGate/common.conf","r");
		if( fp == 0 ){
			if( fp = XX_fopen_FL(FL_ARG,conffile,"w") ){
				fprintf(fp,"# DeleGate config. file\r\n");
				XX_fclose_FL(FL_ARG,fp);
			}
			return 0;
		}
	}
	cc = 0;
	for(;;){
		if( fgets(line,sizeof(line),fp) == 0 )
			break;
		if( lp = strpbrk(line,"#\r\n") )
			truncVStr(lp);
		for( lp = line; *lp && isspace(*lp); lp++ );
		if( line < lp ){
			ovstrcpy(line,lp);
		}
		if( *line ){
			cv[cc++] = stralloc(line);
			cv[cc] = 0;
			_Fprintf(stderr,"common.conf[%d] %s\n",cc,line);
		}
		if( maxcc <= cc ){
			break;
		}
	}
	XX_fclose_FL(FL_ARG,fp);
	return cc;
}

#define WCON_USE 1
#define WCON_NEW 2

#ifdef UNDER_CE /*{*/
void setupSTDIO(FILE *lfp,int withcon){
}
#else /*}{*/
#include <fcntl.h>
#include <io.h>
/* http://www.halcyon.com/~ast/dload/guicon.htm */
static const WORD MAX_CONSOLE_LINES = 1024;
/* StdHanle = {stdin=3, stdout=7, stderr=11} can be broken on CYGWIN */
static int assignStdio(FILE *lfp,int hm,const char *mode,FILE *stdfp){
	long sh;
	int ok;
	unsigned long flags;
	int fd;
	FILE *fp;

	sh = (long)GetStdHandle(hm);
	if( sh < 0 ){
		return -1;
	}
	flags = 0;
	ok = GetHandleInformation((HANDLE)sh,&flags);
	if( lfp ){
		fprintf(lfp,"[%d] stdio %d sh=%d ok=%d fl=%X\n",getpid(),
			hm,sh,ok,flags);
	}
	fd = _open_osfhandle(sh,_O_TEXT);
	if( fd < 0 ){
		return -2;
	}
	fp = _fdopen(fd,mode);
	if( fp == 0 ){
		return -3;
	}
	*stdfp = *fp;
	if( fd == 2 ){
		setvbuf(fp,NULL,_IONBF,0);
	}
	return 0;
}
void setupSTDIO(FILE *lfp,int withcon){
	int ok;
	FILE *Fi;
	FILE *Fo;
	FILE *Fe;

	if( 0 <= fileno(stdin) && (withcon & WCON_NEW) == 0 ){
		return;
	}
	ok = AllocConsole();
	if( lfp ){
		fprintf(lfp,"[%d] LOG(%d) STD(%d %d %d)(%d %d %d) EOF(%d %d %d)\n",
			getpid(),fileno(lfp),
			STD_INPUT_HANDLE,STD_OUTPUT_HANDLE,STD_ERROR_HANDLE,
			GetStdHandle(STD_INPUT_HANDLE),
			GetStdHandle(STD_OUTPUT_HANDLE),
			GetStdHandle(STD_ERROR_HANDLE),
			feof(stdin),ferror(stdout),ferror(stderr)
		);
	}
	if( 0 ){ /* enlarge the console buffer */
		CONSOLE_SCREEN_BUFFER_INFO coninfo;
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&coninfo);
		coninfo.dwSize.Y = MAX_CONSOLE_LINES;
		SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),coninfo.dwSize);
	}
	close(0);
	close(1);
	close(2);
	if( 0 ){
		assignStdio(lfp,STD_INPUT_HANDLE, "r",stdin);
		assignStdio(lfp,STD_OUTPUT_HANDLE,"w",stdout);
		assignStdio(lfp,STD_ERROR_HANDLE, "w",stderr);
	}else{
		if( Fi = fopen("CONIN$","r")  ) *stdin = *Fi;
		if( Fo = fopen("CONOUT$","w") ) *stdout = *Fo;
		if( Fe = fopen("CONOUT$","w") ) *stderr = *Fe;
	}
	if( lfp ){
		fprintf(lfp,"[%d] stdin(%d) stdout(%d) stderr(%d)\r\n",
			getpid(),fileno(stdin),fileno(stdout),fileno(stderr));
	}
	fprintf(stdout,"[%d] stdout: stdin(%d) stdout(%d) stderr(%d)\r\n",
		getpid(),fileno(stdin),fileno(stdout),fileno(stderr));
	fflush(stdout);
	fprintf(stderr,"[%d] stderr: stdin(%d) stdout(%d) stderr(%d)\r\n",
		getpid(),fileno(stdin),fileno(stdout),fileno(stderr));
	fflush(stderr);
}
#endif /*}*/

int IsFunc(int ac,const char *av[]);
static int asDaemon(FILE *lfp,int ac,const char *av[]){
	const char *pt,*cn,*sn;

	pt = getenv("PROMPT");
	cn = getenv("CLIENTNAME");
	sn = getenv("SESSIONNAME");
	if( lfp ){
		fprintf(lfp,"--asDaemon? std[%d %d %d] env[%s][%s][%s]\n",
			fileno(stdin),fileno(stdout),fileno(stderr),
			pt?pt:"",cn?cn:"",sn?sn:""
		);
	}
	if( fileno(stdin) < 0 && pt == 0 && cn == 0 && sn == 0 ){
		return 1;
	}
	return 0;
}
static int xmain(HINSTANCE ci,HINSTANCE pi,WCHAR *cl,int cs){
	int rcode;
	WCHAR *cll;
	char cls[8*1024];
	IStr(clb,8*1024);
	const char *sdm = 0;
	IStr(sdmb,1024);
	IStr(dgroot,256);
	IStr(dgrootv,256);
	IStr(tmpdir,256);
	IStr(vardir,256);
	IStr(syslog,64);
	const char *av[1024];
	int ac,oc,ai;
	int fctid;
	int mac = elnumof(av);
	const char *dbg;
	int fd0;
	const char *Cv[1024];
	int Cc;
	const char *v1;

#ifndef UNDER_CE /*{*/
	if( !isWindowsCE() ){
		int WinMainArgv(const char *av[],int mac,PVStr(cls),PVStr(clb));
		FILE *lfp;
		int pid;
		const char *a1;
		const char *conApp = 0;
		int isFunc = 0;
		int isDaemon = 0;
		int withWin = 0;
		int withCon = 0;
		int nac = 0;

		ac = WinMainArgv(av,elnumof(av),FVStr(cls),AVStr(clb));

		if( File_is("/DeleGate/dg.log") )
		if( lfp = fopen("/DeleGate/dg.log","a") ){
			pid = getpid();
			fprintf(lfp,"[%d] stdio(%d %d %d) isatty(%d %d %d) ----\n",pid,
				fileno(stdin),fileno(stdout),fileno(stderr),
				_isatty(fileno(stdin)),_isatty(fileno(stdout)),_isatty(fileno(stderr))
			);
			fprintf(lfp,"[%d] isatty(%d %d %d) ----\n",pid,
				_isatty(0),_isatty(1),_isatty(2));
			for( ai = 0; ai < ac; ai++)
				fprintf(lfp,"[%d] arg[%d]%s\n",pid,ai,av[ai]);
			for( ai = 0; environ[ai]; ai++)
				fprintf(lfp,"[%d] env[%d]%s\n",pid,ai,environ[ai]);
			fflush(lfp);
		}
		if( asDaemon(lfp,ac,av) ){
			conApp = "IsDaemon"; /* invoked as a service */
			isDaemon = 1;
		}else
		if( isFunc = IsFunc(ac,av) ){
			conApp = "IsFunc";
		}
		for( ai = 0; ai < ac; ai++ ){
			a1 = av[ai];
			if( strneq(a1,"-WCAP",4) ){ /* -WCA */
				conApp = "WCA";
				withCon |= WCON_USE;
				continue;
			}
			if( strneq(a1,"-WCON",3) ){ /* -WC */
				withCon |= WCON_NEW;
				continue;
			}
			if( strneq(a1,"-WWAP",4) ){ /* -WWA */
				conApp = 0;
				withWin = 1;
				continue;
			}
			if( strneq(a1,"-WWCE",3) || strneq(a1,"-WW32",3) ){ /* -WW */
				conApp = 0;
				withWin = 1;
				continue;
			}
			av[nac++] = a1;
			if( strneq(a1,"SERVER=",7) ){
				conApp = "BackgroundService";
			}
			if( strneq(a1,"SERVCONF=",9) ){
				conApp = "BackgroundService";
			}
			if( isFunc ){
				continue;
			}
			if( strneq(a1,"-F",2) ){
				isFunc = 9;
			}
			if( strneq(a1,"-f",2) || streq(a1,"-v") || streq(a1,"-vv") ){
				conApp = "ForeGround";
			}
		}
		av[nac] = 0;
		ac = nac;

		if( conApp && !isDaemon || withCon ){
			setupSTDIO(lfp,withCon);
		}
		if( lfp ){
			fprintf(lfp,"[%d] stdio(%d %d %d) isatty(%d %d %d) ++++\n",pid,
				fileno(stdin),fileno(stdout),fileno(stderr),
				_isatty(fileno(stdin)),_isatty(fileno(stdout)),_isatty(fileno(stderr))
			);
			fprintf(lfp,"[%d] stdin=%d withWin=%d withCon=%d conApp=%s\n",
				pid,fileno(stdin),withWin,withCon,conApp?conApp:"");
			fflush(lfp);
			fclose(lfp);
		}
		if( conApp && !(withWin && withCon) ){
			if( !isDaemon )
			fprintf(stderr,"## running as a Console Application. conApp=%s withWin=%X withCon=%X\n",
				conApp?conApp:"",withWin,withCon);

			mainX(ac,av);
			return 0;
		}
		else{
			fprintf(stderr,"## running as a Windows Application. conApp=%s withWin=%X withCon=%X\n",
				conApp?conApp:"",withWin,withCon);
		}
		if( withWin && !withCon ){
			int ok;
			dupclosed(fileno(stdin));
			dupclosed(fileno(stdout));
			dupclosed(fileno(stderr));
			ok = FreeConsole();
		}
	}
#endif /*}*/
	RES_TRACE = 1;
	settick0();
	MainStart = Time();
	//testtick(); testtick();

	openInitLog();

	//fd0 = _open_osfhandle(NulDevHandle(),2);
	_Fprintf(stderr,"--WinCE %s\n",DELEGATE_version());
	//_Fprintf(stderr,"----fd0 = %d\n",fd0);

	_main_thread = getthreadid();
	setthreadgid(0,_main_thread);

	if( isWindowsCE() ){
	cll = GetCommandLine();
	wstrtostr(cls,cll,ESC_NONE);
	ac = decomp_args(av,elnumof(av),(const char*)cls,AVStr(clb));
	}
	_Fprintf(stderr,"--WinCE ac=%d: %s\n",ac,cls);
	Cc = getCv(Cv,elnumof(Cv));

	/*
	getExecPath();
	*/
	myExePath();

	for( ai = 0; ai < ac; ai++ ){
		if( av[ai][0] == '-' ){
			setDebug(av[ai]);
		}
	}
	if( winrestart(ci,pi,cs) ){
		return 0;
	}

	if( ac == 0 ){
		av[0] = "wince-dg.exe";
		av[1] = 0;
		ac = 1;
	}
	if( dbg = getvh(ac,av,"WCE=") ){
		setdbg(dbg+4);
		*(char*)dbg = 0;
	}
	if( lFCLOSEQ() ){
		fctid = thread_fork(0,0,"filecloser",(IFUNCP)filecloser);
	}
	loadFlags();

	oc = ac;
	sprintf(dgrootv,"/DeleGate");
	if( v1 = getvb(ac,av,"DGROOT=") ){
		sprintf(dgrootv,v1);
		if( !getvh1(ac,av,"DGROOT=") ){
			/* DGROOT= in common.conf */
			sprintf(dgroot,"DGROOT=%s",v1);
			av[ac++]=dgroot;
		}
	}
	if(ac<mac&&!getvh(oc,av,"DGROOT")){
		if( 0 && regGetStorageCard(AVStr(sdmb)) == 0 ){
			sprintf(dgrootv,"%s/DeleGate",sdmb);
			sprintf(dgroot,"DGROOT=%s/DeleGate",sdmb);
			av[ac++]=dgroot;
		}else
		av[ac++]="DGROOT=/DeleGate";
	}
	if( regGetStorageCard(AVStr(sdmb)) == 0 ){
	    StorageCard = stralloc(sdmb);
	    if( fileIsdir(sdmb) ){
		sdm = sdmb;
		if(ac<mac&&!getvh(oc,av,"VARDIR")){
			sprintf(WinCEE.VARDIR,"%s/DeleGate",sdm);
			sprintf(vardir,"VARDIR=%s",WinCEE.VARDIR);
			av[ac++]=vardir;
		}
		if( 0 )
		if(ac<mac&&!getvh(oc,av,"TMPDIR")){
			sprintf(tmpdir,"TMPDIR=%s/DeleGate/tmp",sdm);
			av[ac++]=tmpdir;
		}
		/*
		sprintf(sdmount,"MOUNT=\"/SD/* %s/*\"",sdm);
		av[ac++]=sdmount;
		*/
		if(ac<mac&&!getvh(oc,av,"HTTPCONF=cache:"))
			av[ac++]="HTTPCONF=cache:any";
	    }
	}
	if(ac<mac && (v1=getvb(ac,av,"VARDIR=")) ){
		if( *v1 != '/' && *v1 != '\\' ){
			/* relative-path to full-path */
			sprintf(WinCEE.VARDIR,"%s/%s",dgrootv,v1);
			sprintf(vardir,"VARDIR=%s",WinCEE.VARDIR);
			if( replacev(ac,av,"VARDIR=",vardir) == 0 ){
				/* VARDIR= in common.conf */
				av[ac++]=vardir;
			}
		}else
		if( !getvh1(ac,av,"VARDIR=") ){
			/* VARDIR= in common.conf */
			sprintf(WinCEE.VARDIR,"%s",v1);
			sprintf(vardir,"VARDIR=%s",v1);
			av[ac++]=vardir;
		}
	}
	if(ac<mac)av[ac++]="CACHEFILE=$[server:%P/=%-1mu/%-2mu/%mu]";
	if(ac<mac&&!getvh(oc,av,"CACHE=")){
		if( sdm && strstr(sdm,"micro")==0 && strstr(sdm,"mini")==0 )
			av[ac++]="CACHE=do";
		else	av[ac++]="CACHE=no";
	}

	if(ac<mac&&!getvh(oc,av,"EXPIRE"))av[ac++]="EXPIRE=1d";
	if(ac<mac&&!getvh(oc,av,"HTTPCO"))av[ac++]="HTTPCONF=cache:less-reload";

	RES_HC_EXPIRE = 60*60*8;
	if( 0 ){
		av[ac++]="-d1+3";
		av[ac++]="-vs";
		//av[ac++]="PROXY=192.168.1.10:8080";
		//av[ac++]="SYSLOG=-vH,syslog://192.168.1.255:8514";
		//av[ac++]="LOGFILE=";
		//av[ac++]="RESOLV=sys";
		//av[ac++]="RESOLV=cache,dns,sys";
		//av[ac++]="RES_NS=192.168.1.1";
	}else{
//av[ac++]="PROXY=192.168.1.109:9821";
#if defined(UNDER_CE)
	if(ac<mac&&!getvh(oc,av,"-d1")   )av[ac++]="-d1+4";
#else
	if(ac<mac&&!getvh(oc,av,"-d1")   )av[ac++]="-d1+7";
#endif
	/*
	if(ac<mac&&!getvh(oc,av,"-v")    )av[ac++]="-vs";
	*/
	av[ac++]="TIMEOUT=con:30";
	//av[ac++]="MAXIMA=contry:3";

	if( getvh(oc,av,"-v") ){
	}
	if( issetfv(&SUPPRESS_SYSLOG) ){
	}else{
	SUPPRESS_SYSLOG = 1;
	}
	if( SUPPRESS_SYSLOG ){
		if(ac<mac&&!getvh(oc,av,"-v")    )av[ac++]="-vs";
	}
	if(!getvh(oc,av,"SYSLOG"))
	//if(ac<mac)av[ac++]="SYSLOG=-vH,syslog://192.168.1.255:8514";
	if( ac < mac && !getvh(oc,av,"SYSLOG") ){
		int isinListX(PCStr(list),PCStr(word),PCStr(sopts));
		char *printnetif(PVStr(netif));
		IStr(netif,128);
		int off;
		const char *dp;
		IStr(privnet,32);
		IStr(if1,128);

		printnetif(AVStr(netif));
		strcpy(privnet,"192.168.");
		dp = 0;
		if( 0 < (off = isinListX(netif,privnet,"oH ")) ){
			dp = netif+off;
		}else
		if( strheadstrX(netif,privnet,0) ){
			dp = netif;
		}
		if( dp ){
			wordScan(dp,if1);
			if( dp = strrchr(if1,'.') )
				*(char*)dp = 0;
			sprintf(syslog,"SYSLOG=-vH,syslog://%s.255:8514",if1);
			av[ac++] = syslog;
		}
	}
	//if(ac<mac&&!getvh(oc,av,"-v")    )av[ac++]="-va";

	//if(ac<mac&&!getvh(oc,av,"-v")    )av[ac++]="-v";
	if(ac<mac&&!getvh(oc,av,"LOGFILE"))av[ac++]="LOGFILE=9821.txt";
	}
	if(ac<mac&&!getvh(oc,av,"-Dz")   )av[ac++]="-Dz";
	//if(ac<mac)av[ac++]="TIMEOUT=con:30";
	if(ac<mac)av[ac++]="TIMEOUT=takeover:1";
	//if(ac<mac&&!getvh(oc,av,"-dc0")  )av[ac++]="-dc"; //debugging CONNECT
	if(ac<mac&&!getvh(oc,av,"-f")    )av[ac++]="-1";

	if(ac<mac&&!getvh(oc,av,"ERRORLOG"))av[ac++]="ERRORLOG=errors.txt";
	if(ac<mac&&!getvh(oc,av,"STDOUTLOG"))av[ac++]="STDOUTLOG=stdout.txt";
	if(ac<mac&&!getvh(oc,av,"-dm")    )av[ac++]="-dm";
	//if(ac<mac&&!getvh(oc,av,"-dt")   )av[ac++]="-dt";
	//if(ac<mac&&!getvh(oc,av,"-dx")   )av[ac++]="-dx";
	//if(ac<mac&&!getvh(oc,av,"-P")    )av[ac++]="-P9821/admin";
	//if(ac<mac&&!getvh(oc,av,"DYLIB") )av[ac++]="DYLIB=";

if( 0 ){
	if(ac<mac) av[ac++]="SERVER=ftp:-:-P21";
	if(ac<mac) av[ac++]="SERVER=http:-:-P80";
	if(ac<mac) av[ac++]="SERVER=http-proxy:-:-P8080";
	if(ac<mac) av[ac++]="SERVER=https:-:-P443";
	if(ac<mac) av[ac++]="SERVER=socks:-:-P1080";
	if(ac<mac) av[ac++]="SERVER=http:-:-P9821";
	if(ac<mac) av[ac++]="SERVER=console:-:-P9823";
}else{
	/*
	if(ac<mac&&!getvh(oc,av,"-Q")){
	this should be getvh("-P") but there is a "Lanchar" that
	uses "-P" to wrap DeleGate, so default ports should not
	be overriden by "-P" :-P
	*/
	if(ac<mac&&!getvh1(oc,av,"-Q")){
if(0){
		// this should be added via the control menu
		if(ac<mac) av[ac++]="-Q192.168.1.39:8080/http";
		if(ac<mac) av[ac++]="-Q192.168.1.39:1080/socks";
}else{
		/*
		if(ac<mac) av[ac++]="-Q8080/http";
		if(ac<mac) av[ac++]="-Q8888/ecc";
		*/
		if(ac<mac) av[ac++]="-Q8080/http-sp";
		if(ac<mac) av[ac++]="-Q1080/socks";
}
		if(ac<mac) av[ac++]="-Q2080/http"; /* mod-140502e */
		if(ac<mac) av[ac++]="-Q6060/yymux";
		if( !isWindowsCE() ){
			if(ac<mac) av[ac++]="-Q6023/yysh";
			if(ac<mac) av[ac++]="-Q6010/yy11";
			if(ac<mac) av[ac++]="-Q443/https";
			if(ac<mac) av[ac++]="STLS=fcl:::-P443";
		}
		if(ac<mac) av[ac++]="-Q21/ftp";
		if(ac<mac) av[ac++]="-Q25/smtp";
		if(ac<mac) av[ac++]="-Q110/pop";
		if(ac<mac) av[ac++]="-Q143/imap";
		//if(ac<mac) av[ac++]="-Q2180/ftpxhttp";
		if(ac<mac) av[ac++]="-Q9821/http";
		if(ac<mac) av[ac++]="-Q9823/ysh";

		if(!getvh(oc,av,"REMITTABLE"))
		if(ac<mac) av[ac++]="REMITTABLE=+,smtp,pop,imap";
	}
}

	if(ac<mac&&!getvh(oc,av,"SERVER"))av[ac++]="SERVER=http";

	if(ac<mac&&!getvh(oc,av,"HTTPCO"))av[ac++]="HTTPCONF=tout-cka:3";
	if(ac<mac&&!getvh(oc,av,"MAXIMA"))av[ac++]="MAXIMA=delegated:4";

	/*if( is-local )*/
	if(ac<mac)av[ac++]="-Dkc"; /* disable keep-alive with the client */
//	if(ac<mac&&!getvh(oc,av,"HTTPCO"))av[ac++]="HTTPCONF=bugs:no-keepalive";
	if(ac<mac&&!getvh(oc,av,"HTTPCO"))av[ac++]="HTTPCONF=bugs:no-flush-chunk";

	//if(ac<mac&&!getvh(oc,av,"TIMEOU"))av[ac++]="TIMEOUT=daemon:600";
	//if(ac<mac&&!getvh(oc,av,"MAXIMA"))av[ac++]="MAXIMA=service:10000";
	//if(ac<mac&&!getvh(oc,av,"SYSLOG"))av[ac++]="SYSLOG=syslog://192.168.1.255:8514";
	//if(ac<mac&&!getvh(oc,av,"SYSLOG"))av[ac++]="SYSLOG=-vH,-vM,syslog://192.168.1.255:8514";
	if(ac<mac&&!getvh(oc,av,"MOUNT=")){
		av[ac++]="MOUNT=/* /* AUTHORIZER=-man/1h,rw";
	}
	if(ac<mac&&!getvh(oc,av,"MOUNT=/-/")){
		av[ac++]="MOUNT=/-/screen/* gendata:/-/ysh/screen/* AUTHORIZER=-man/10m";
	}
	if(ac<mac) av[ac++]="MOUNT=/moved /moved/ moved";
	if(ac<mac&&!getvh(oc,av,"HTTPCO"))av[ac++]="HTTPCONF=proxycontrol:??";
	if(ac<mac&&!getvh(oc,av,"ADMIN="))av[ac++]="ADMIN=adm@WinCE.delegate.org";

//if(ac<mac&&!getvh(oc,av,"AUTH=admin"))av[ac++]="AUTH=admin::adm:wce";
	if(ac<mac&&!getvh(oc,av,"AUTH=admin")){
		/*
		unsigned int trand1(unsigned int max);
		IStr(pass,32);
		IStr(arg,32);
		sprintf(pass,"%d",trand1(100000));
		adminpass = strdup(pass);
		sprintf(arg,"AUTH=admin::admin:%s",pass);
		av[ac++] = strdup(arg);
		*/
		av[ac++] = "AUTH=admin:-man/1h";
	}

	if(ac<mac&&!getvh(oc,av,"AUTHORIZER=")){
		av[ac++] = "AUTHORIZER=-man";
		LOG_type4 |= L_NOAUTHPROXY;
	}
	LOG_type4 |= L_ACCLOG;
	if( !getvh(oc,av,"-Dri") ){
		LOG_type4 |= L_IMMREJECT;
	}

if(0)
	if(ac<mac
	&&!getvh(oc,av,"AUTHORIZER=")
	&&!getvh(oc,av,"RELIABLE=")
	&&!getvh(oc,av,"PERMIT=")
	&&!getvh(oc,av,"REJECT=")
	){
		av[ac++] = "AUTHORIZER=-man/1h";
	}
	if(0){
		if(ac<mac) av[ac++] = "SOCKMUX=192.168.1.10:8707:con";
		if(ac<mac) av[ac++] = "PROXY=-:-";
	}
	if(0){
		extern int SLOW_CONN;
		SLOW_CONN = 200;
		if(ac<mac) av[ac++] = "-Ecq";
		//if(ac<mac) av[ac++] = "PROXY=192.168.1.10:2080";
	}

	if(ac<mac&&!getvh(oc,av,"-Dty"))av[ac++]="-Ety"; /* THFORKSYNC */
	if(ac<mac&&!getvh(oc,av,"-Dcp"))av[ac++]="-Ecp";
	if(ac<mac&&!getvh(oc,av,"-Est"))av[ac++]="-Dst";
	//if(ac<mac&&!getvh(oc,av,"-Dcs"))av[ac++]="-Ecs";
	//if(ac<mac&&!getvh(oc,av,"RES_AF"))av[ac++]="RES_AF=4";
	//if(ac<mac&&!getvh(oc,av,"RESOLV"))av[ac++]="RESOLV=dns";
if(ac<mac&&!getvh(oc,av,"RESOLV"))av[ac++]="RESOLV=cache,file,nis,dns,sys";
	if(ac<mac&&!getvh(oc,av,"-Dns"))av[ac++]="-Ens";
	if(ac<mac&&!getvh(oc,av,"-Ddr"))av[ac++]="-Edr";
if(ac<mac&&!getvh(oc,av,"RES_WAIT"))av[ac++]="RES_WAIT=0";
	//if(ac<mac&&!getvh(oc,av,"RES_DE"))av[ac++]="RES_DEBUG=-1";

	loadFlags();

	if( ac < mac ) av[ac] = 0;
	for( ai = 0; ai < ac; ai++ ){
		_Fprintf(stderr,"--WinCE argv[%d] %s\n",ai,av[ai]);
	}

	_Fprintf(stderr,"--WinCE set NullFd=%d\n",getNullFd("xmain"));
	//_Fprintf(stderr,"----sessionfd=%d\n",SessionFd());
	popupConsole();

	//doDBG(DBG_MEMFx);
	putWinStatus("** started");
	GlobalMemoryStatus(&mst1);
	mainX(ac,av);
	return 0;
}

#if defined(UNDER_CE)
int WINAPI WinMain(HINSTANCE ci,HINSTANCE pi,LPWSTR cl,int cs){
	GlobalMemoryStatus(&mst0);
	xmain(ci,pi,cl,cs);
	return 0;
}
#else
int WINAPI WinMain(HINSTANCE ci,HINSTANCE pi,LPSTR cl,int cs){
	GlobalMemoryStatus(&mst0);
	xmain(ci,pi,(WCHAR*)cl,cs);
	return 0;
}
#endif

typedef struct {
	int sb_fh;
	int sb_fd;
	int sb_sock;
	int sb_bufn;
 unsigned char sb_buf[1];
} SockBuf;
static SockBuf sockBuf[32];
static CriticalSec sockBufCSC;
static SockBuf *getSockBuf(int fd,int sock,int fh,int create){
	int si,si0 = 0;
	SockBuf *sb,*sb0 = 0;

	setupCSC("getSockBuf",sockBufCSC,sizeof(sockBufCSC));
	enterCSC(sockBufCSC);
	for( si = 0; si < elnumof(sockBuf); si++ ){
		sb = &sockBuf[si];
		if( sb->sb_sock == sock ){
if( 0 < si )
_Fprintf(stderr,"-- %4X found SB[%d] %d %X %d (%d %X %d)\n",
TID, si,  fd,fh,sock, sb->sb_fd,sb->sb_fh,sb->sb_sock);
			leaveCSC(sockBufCSC);
			return sb;
		}
		if( sb0 == 0 && sb->sb_sock == 0 ){
			si0 = si;
			sb0 = sb;
		}
	}
	leaveCSC(sockBufCSC);
	if( create ){
if( 0 < si0 )
_Fprintf(stderr,"-- %4X creat SB[%d] %d %X %d (%d %X %d)\n",
TID, si0, fd,fh,sock, sb->sb_fd,sb->sb_fh,sb->sb_sock);
		sb0->sb_fh = fh;
		sb0->sb_fd = fd;
		sb0->sb_sock = sock;
		return sb0;
	}
	return 0;
}

#if defined(UNDER_CE)
int Xrecv(int fd,int sock,void *abuf,unsigned int len,int flags){
	int rcc,rcc1;
	int xerr;
	OSF *osf;
	unsigned char *buf = (unsigned char*)abuf;
	int fh;
	SockBuf *sb;

	if( fd < 0 || elnumof(_osfhandles) <= fd ){
_Fprintf(stderr,"-- %X recv bad fd[%d]\n",TID,fd);
		return -1;
	}
	osf = &_osfhandles[fd];
	fh = osf->o_fh;

	if( 0 < sock && (flags & MSG_PEEK) && len <= 1 ){
	}else
	if( 0 < sock && (flags & (MSG_PEEK|MSG_OOB)) ){
		_Fprintf(stderr,"-- %X RECV(%d,len=%d fl=%X/O%X/P%X)----\n",
			TID,sock,len,flags,MSG_OOB,MSG_PEEK);
		//errno = WSAECONNRESET;
		return 0;
	}

	rcc = 0;
	if( sb = getSockBuf(fd,sock,fh,0) ){
		if( 0 < sb->sb_bufn ){
			buf[0] = sb->sb_buf[0];
			if( (flags & MSG_PEEK) == 0 ){
				rcc = sb->sb_bufn;
				sb->sb_bufn = 0;
				sb->sb_sock = 0;
if(0)
_Fprintf(stderr,"-- %4X recv got MSG_PEEK[%d] rcc=%d\n",TID,fd,rcc);
			}
		}
	}
	if( 0 < len-rcc ){
		rcc1 = recv(sock,((char*)buf)+rcc,len-rcc,0);
		if( rcc == 0 ){
			rcc = rcc1;
		}else{
			if( 0 < rcc1 ){
				rcc += rcc1;
			}
		}
	}
	if( 0 < rcc ){
		if( (flags & MSG_PEEK) != 0 ){
			if( sb = getSockBuf(fd,sock,fh,1) ){
				sb->sb_buf[0] = buf[0];
				sb->sb_bufn = 1;
if(0)
_Fprintf(stderr,"-- %4X recv sav MSG_PEEK[%d] rcc=%d [%X]\n",
TID,fd,sb->sb_bufn,sb->sb_buf[0]);
			}
		}
	}

	xerr = WSAGetLastError();
	if( 0 < sock && rcc <= 0 && flags & (MSG_PEEK|MSG_OOB) ){
	    switch( xerr ){
		/*
		case WSAEAGAIN:
			break;
		*/
		case WSAENOTSOCK: errno = WSAECONNRESET;
		_Fprintf(stderr,"-1--WinCE RECV(%d,len=%d fl=%X/O%X/P%X)=%d Err=%d\n",
			sock,len,flags,MSG_OOB,MSG_PEEK,rcc,xerr);
			break;
		case WSAEOPNOTSUPP:
			break;
		default:
		_Fprintf(stderr,"-2--WinCE RECV(%d,len=%d fl=%X/O%X/P%X)=%d Err=%d\n",
			sock,len,flags,MSG_OOB,MSG_PEEK,rcc,xerr);
	    }
	}
	return rcc;
}
#endif

static int dbgWin = 0;
#define DGWIN 1
#if defined(DGWIN) /*{*/
#include <Winuser.h>
#include <Wingdi.h>
HINSTANCE g_hInst = NULL; // Handle to the application instance
HWND winMain = NULL;
#if defined(UNDER_CE)
#define MYNAME "DeleGate/WindowsCE"
#else
#define MYNAME "DeleGate/Win32"
#endif
static TCHAR *winTitle = TEXT(MYNAME);
static TCHAR *winClassName = TEXT(MYNAME);  
static char *uwinClassName = MYNAME;
static struct {
	int	wi_none:1,
		wi_iconic:1,
		wi_hide:1,
		wi_changed:1,
		wi_disabled:1;
} win_init;
static int Mini1;
static int winReady;
static HWND scrWin;
static HWND winHome;
static HWND winMini;
static HWND winNext;
static HWND winAlts;
static HWND winPrev;
static HWND winTerm;
static HWND winMenu;

static HWND winActv;

static COLORREF WBGC = RGB(0xFF,0xFF,0xFF);
static COLORREF YBGC = RGB(0xFF,0xFF,0x80);
static COLORREF XBGC = RGB(0xD0,0xD0,0xD0);
static COLORREF ZBGC = RGB(0x00,0x00,0x00);
static COLORREF RBGC = RGB(0xFF,0x00,0x00);
static COLORREF GBGC = RGB(0x00,0xFF,0x00);
static COLORREF BBGC = RGB(0x00,0x00,0xFF);
static HBRUSH wbbg;
static HBRUSH xbbg;
static HBRUSH ybbg;
static HBRUSH zbbg;
static HBRUSH rbbg;
static HBRUSH gbbg;
static HBRUSH bbbg;
static HDC dcMain;
static int Stats;
static int Clear;

static int PrevNRefresh;
static int NRefresh;
static int DoRefresh;
static int NRefreshX;
static int buttonSets;
static int NDISP = 7;

#define DISP_HOME	0
#define DISP_NETS	1
#define DISP_POWER	2
#define DISP_PROXY	3
#define DISP_AUTH	4
#define DISP_PROCESS	5
#define DISP_INSTALL	6

static int g_HIDPI_LogPixelsX;
static int g_HIDPI_LogPixelsY;
static void HIDPI_InitScaling(){
	HDC screen;
	if( g_HIDPI_LogPixelsX )
		return;
	screen = GetDC(NULL);
	g_HIDPI_LogPixelsX = GetDeviceCaps(screen, LOGPIXELSX);
	g_HIDPI_LogPixelsY = GetDeviceCaps(screen, LOGPIXELSY);
	ReleaseDC(NULL, screen);
}
#define HIDPISIGN(x) (((x)<0)?-1:1)
#define HIDPIABS(x) (((x)<0)?-(x):x)
#define HIDPIMulDiv(x,y,z) ((((HIDPIABS(x)*(y))+((z)>>1))/(z))*HIDPISIGN(x))
#define SCALEX(argX) (HIDPIMulDiv(argX,g_HIDPI_LogPixelsX,96))
#define SCALEY(argY) (HIDPIMulDiv(argY,g_HIDPI_LogPixelsY,96))

static int HalfWin = 0;
#define ScaleX(x) (SCALEX(x)/(HalfWin?2:1))
#define ScaleY(y) (SCALEY(y)/(HalfWin?2:1))

WCHAR *wstralloc(WCHAR *wstr){
	int wlen,wi;
	WCHAR *ws;

	for( wlen = 0; wstr[wlen]; wlen++ );
	ws = (WCHAR*)malloc(sizeof(WCHAR)*(wlen+1));	
	for( wi = 0; wi < wlen+1; wi++ )
		ws[wi] = wstr[wi];
	return ws;
}
static int updateWinTytle(HWND hwnd){
	if( win_init.wi_changed ){
		SetWindowText(hwnd,winTitle);
		win_init.wi_changed = 0;
		return 1;
	}
	return 0;
}
void setWinClassTitleStyle(PCStr(wclass),PCStr(wtitle),PCStr(wstyle)){
	WCHAR wbuf[1024];
	if( wclass ){
		strtowstr(wbuf,wclass,0);
		winClassName = wstralloc(wbuf);
		uwinClassName = stralloc(wclass);
	}
	if( wtitle ){
		strtowstr(wbuf,wtitle,0);
		winTitle = wstralloc(wbuf);
		win_init.wi_changed = 1;
	}
	if( wstyle ){
		switch( wstyle[0] ){
			case 'i':
				switch( wstyle[1] ){
					case 'h':
						win_init.wi_hide = 1;
						break;
					case 'i':
						win_init.wi_iconic = 1;
						break;
					case 'd':
						//win_init.wi_disabled = 1;
						break;
				}
				break;
			case 'n':
				win_init.wi_none = 1;
				break;
			case 'm':
				showMessageBox = 1;
				break;
		}
	}
}
static int winHeight;
static int winWidth;
/*
static COLORREF BLAMPS[] = {
	RGB(0x20,0xFF,0x20),
	RGB(0x80,0x80,0x80)
};
static RECT brc;
static HBRUSH blamps[elnumof(BLAMPS)];
static HDC dcActv;
*/

static void redrawButtons(){
	if( winHome && !isWindowsCE() ){
		InvalidateRect(winAlts,NULL,0);
		InvalidateRect(winMenu,NULL,0);
		InvalidateRect(winTerm,NULL,0);
		InvalidateRect(winMini,NULL,0);
		InvalidateRect(winHome,NULL,0);
		InvalidateRect(winPrev,NULL,0);
		InvalidateRect(winNext,NULL,0);
	}
}
static void switchButtons(){
	//ShowWindow(winAlts,SW_SHOWNORMAL);

	switch( buttonSets % 3 ){
		case 0:
			if( (NRefresh % NDISP) == DISP_HOME ){
				ShowWindow(winHome,SW_HIDE);
			}else{
				ShowWindow(winHome,SW_SHOWNORMAL);
			}
			ShowWindow(winAlts,SW_HIDE);
			ShowWindow(winMenu,SW_HIDE);
			ShowWindow(winTerm,SW_HIDE);
			ShowWindow(winMini,SW_HIDE);

			ShowWindow(winPrev,SW_SHOWNORMAL);
			ShowWindow(winNext,SW_SHOWNORMAL);
			break;
		case 1:
			//ShowWindow(winHome,SW_HIDE);
			//ShowWindow(winPrev,SW_HIDE);
			//ShowWindow(winNext,SW_HIDE);
			ShowWindow(winAlts,SW_SHOWNORMAL);
			ShowWindow(winMenu,SW_SHOWNORMAL);
			ShowWindow(winHome,SW_SHOWNORMAL);
			ShowWindow(winMini,SW_SHOWNORMAL);
			ShowWindow(winTerm,SW_SHOWNORMAL);
			break;
		case 2:
			ShowWindow(winAlts,SW_HIDE);
			ShowWindow(winMenu,SW_HIDE);
			ShowWindow(winTerm,SW_HIDE);
			ShowWindow(winMini,SW_HIDE);
			ShowWindow(winHome,SW_HIDE);
			ShowWindow(winPrev,SW_HIDE);
			ShowWindow(winNext,SW_HIDE);
			break;
	}
}
static int prevHeight;
static int prevWidth;
static RECT altsRect;
static RECT menuRect;
static RECT homeRect;
static RECT prevRect;
static RECT nextRect;
static RECT miniRect;
static RECT termRect;

#define PWW	ScaleX(230) /* 230 / 240 */
#define PWH	ScaleY(265) /* 265 / 300 */
#define PWSP	6	    /* window border internal padding */
#define PMLH	ScaleY(46)
#define PBTH	ScaleY(36)
#define PBTHS	ScaleY(40)
#define PBTW	ScaleX(70)
#define PBTWS	ScaleX(76)

static void moveWindow(HWND hwnd,RECT *R){
	MoveWindow(hwnd,
		R->left,
		R->top,
		R->right-R->left,
		R->bottom-R->top,
		0);
}

static void placeButtons(HWND hwnd){
	if( winHeight == 0 )
		return;

	if( winHeight == prevHeight )
	if( winWidth  == prevWidth )
		return;

	altsRect.left   = winWidth  -PBTWS;
	altsRect.top    = PWSP;
	altsRect.right  = altsRect.left +PBTW;
	altsRect.bottom = altsRect.top  +PBTH;
	moveWindow(winAlts,&altsRect);

	menuRect.left   = winWidth  -PBTWS;
	menuRect.top    = PWSP+PBTHS;
	menuRect.right  = menuRect.left +PBTW;
	menuRect.bottom = menuRect.top  +PBTH;
	moveWindow(winMenu,&menuRect);

	miniRect.left   = winWidth  -PBTWS;
	miniRect.top    = winHeight -PMLH -PBTHS -PBTH;
	miniRect.right  = miniRect.left +PBTW;
	miniRect.bottom = miniRect.top  +PBTH;
	moveWindow(winMini,&miniRect);

	termRect.left   = winWidth  -PBTWS -PBTWS;
	termRect.top    = winHeight -PMLH -PBTHS -PBTH;
	termRect.right  = termRect.left +PBTW;
	termRect.bottom = termRect.top  +PBTH;
	moveWindow(winTerm,&termRect);

	nextRect.left   = winWidth  -PBTWS;
	nextRect.top    = winHeight -PMLH -PBTH;
	nextRect.right  = nextRect.left +PBTW;
	nextRect.bottom = nextRect.top  +PBTH;
	moveWindow(winNext,&nextRect);

	prevRect.left   = winWidth  -PBTWS -PBTWS;
	prevRect.top    = winHeight -PMLH -PBTH;
	prevRect.right  = prevRect.left +PBTW;
	prevRect.bottom = prevRect.top  +PBTH;
	moveWindow(winPrev,&prevRect);

	homeRect.left   = winWidth  -PBTWS -PBTWS -PBTWS;
	homeRect.top    = winHeight -PMLH -PBTH;
	homeRect.right  = homeRect.left +PBTW;
	homeRect.bottom = homeRect.top  +PBTH;
	moveWindow(winHome,&homeRect);

	prevHeight = winHeight;
	prevWidth  = winWidth;
	UpdateWindow(hwnd);
	//MoveWindow(winActv,  0,winHeight-25,300,3,0);
}
#define iBUTTON_ALTS	1
#define iBUTTON_NEXT	2
#define iBUTTON_PREV	3
#define iBUTTON_HOME	4
#define iBUTTON_TERMIN	5
#define iBUTTON_MINIMZ	6
#define iBUTTON_MENU	7

#define BUTTON_ALTS	(HMENU)iBUTTON_ALTS
#define BUTTON_NEXT	(HMENU)iBUTTON_NEXT
#define BUTTON_PREV	(HMENU)iBUTTON_PREV
#define BUTTON_HOME	(HMENU)iBUTTON_HOME
#define BUTTON_TERMIN	(HMENU)iBUTTON_TERMIN
#define BUTTON_MINIMZ	(HMENU)iBUTTON_MINIMZ
#define BUTTON_MENU	(HMENU)iBUTTON_MENU

static void setupMainWin(HWND hwnd,WPARAM wParam,LPARAM lParam){
	if( winReady )
		return;

	winHome = CreateWindow(_T("BUTTON"),_T("Home"),
		WS_CHILD|BS_PUSHBUTTON,
		  5,200,70,35,hwnd,BUTTON_HOME,g_hInst,NULL);
	winPrev = CreateWindow(_T("BUTTON"),_T("Prev"),
		WS_CHILD|BS_PUSHBUTTON,
		 80,200,70,35,hwnd,BUTTON_PREV,g_hInst,NULL);
	winNext = CreateWindow(_T("BUTTON"),_T("Next"),
		WS_CHILD|BS_PUSHBUTTON,
		154,200,70,35,hwnd,BUTTON_NEXT,g_hInst,NULL);

	winAlts = CreateWindow(_T("BUTTON"),_T("Alt"),
		WS_CHILD|BS_PUSHBUTTON,
		154,200, 5,35,hwnd,BUTTON_ALTS,g_hInst,NULL);
	winMenu = CreateWindow(_T("BUTTON"),_T("Menu"),
		WS_CHILD|BS_PUSHBUTTON,
		154,200-45,70,35,hwnd,BUTTON_MENU,g_hInst,NULL);
	winMini = CreateWindow(_T("BUTTON"),_T("Minimize"),
		WS_CHILD|BS_PUSHBUTTON,
		154,200-85,70,35,hwnd,BUTTON_MINIMZ,g_hInst,NULL);
	winTerm = CreateWindow(_T("BUTTON"),_T("Fin"),
		WS_CHILD|BS_PUSHBUTTON,
		154,200-85,70,35,hwnd,BUTTON_TERMIN,g_hInst,NULL);

	/*
	winActv = CreateWindow(_T("BUTTON"),_T(""),
		WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
		  0,240,300,3,hwnd,(HMENU)4,g_hInst,NULL);
	{	int bi;
		dcActv = GetDC(winActv);
		for( bi = 0; bi < elnumof(BLAMPS); bi++ )
			blamps[bi] = CreateSolidBrush(BLAMPS[bi]);
		SetRect(&brc,0,0,300,3);
	}
	*/
	winReady = 1;
}
static int prevl = -1;
extern int eccTOTAL_SERVED;
int updateActiveLamp(int act){
	int bi;
	int llev;
	RECT rc;
	int mx,rx,gx,bx;
	int tsv;

	if( winMain == 0 || dcMain == 0 )
		return 0;
	/*
	llev = TOTAL_SERVED/5;
	if( llev == prevl )
		return 0;
	prevl = llev;
	if( winMain == 0 || winActv == 0 || dcActv == 0 )
		return 0;
	FillRect(dcActv,&brc,blamps[llev%elnumof(blamps)]);
	UpdateWindow(winActv);
	*/

	if( wbbg ){
		tsv = TOTAL_SERVED + eccTOTAL_SERVED;
		mx = tsv / 1000;
		rx = mx + (tsv%1000)/100;
		gx = rx + (tsv%100)/2;
		bx = gx + (tsv%10)*10;
		SetRect(&rc, 0,1,mx,4); FillRect(dcMain,&rc,zbbg);
		SetRect(&rc,mx,1,rx,4); FillRect(dcMain,&rc,rbbg);
		SetRect(&rc,rx,1,gx,4); FillRect(dcMain,&rc,gbbg);
		SetRect(&rc,gx,1,bx,4); FillRect(dcMain,&rc,bbbg);
		SetRect(&rc,bx,1,300,4); FillRect(dcMain,&rc,wbbg);
		if( act ){
			UpdateWindow(winMain);
		}
	}
	return 1;
}

static HBITMAP myMark;
static HBITMAP myMarkX;
int dump_ENTR(PCStr(fmt),PVStr(entrance));
int regGetHosts(PVStr(hosts));
int setTcpRegVal(PVStr(stat),int adp,PCStr(name),PCStr(val));
static HDC cdcMain;
static int TerminatingX;
static int Nfrogs;

int connectServer(PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int UDP_client_open(PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int SendTo(int sock,PCStr(buf),int len,PCStr(host),int port);
static int NoNet;
static int reconnecting = -1;
static void reconnect(){
	IStr(yn,32);

	if( 0 <= reconnecting ){
		send(reconnecting,"",1,0);
		return;
	}
	if( NoNet ){
		getAnswerYN("Try IP enale?",AVStr(yn),sizeof(yn));
		if( yn[0] == 'y' ){
			reconnecting = socket(AF_INET,SOCK_DGRAM,0);
			if( 0 < reconnecting ){
				send(reconnecting,"",1,0);
			}
/*
	sock = connectServer("ping","http","wince.delegate.org",9820);
			if( 0 < sock ){
				NoNet = 0;
				askWinOK("OK");
				close(sock);
			}else{
				askWinOK("NG");
			}
*/
		}
	}
}

int regGetRasBook(PVStr(books));

#define MENU_CANCELL		1000
#define MENU_ADD_STARTMENU	1001
#define MENU_ADD_STARTUP	1002
#define MENU_AWAKE_FORPROXY	1003
#define MENU_TRACE_RESOLVER	1004
#define MENU_TRACE_CONNMGR	1005
#define MENU_AUTODIAL_TCP	1006
#define MENU_AUTODIAL_UDP	1007
#define MENU_AUTODIAL_DNS	1008
#define MENU_AUTOHANGUP		1009
#define MENU_HANGUP		1010
#define MENU_DIALUP		1011
#define MENU_SMALLFONT		1012
#define MENU_BUTTONSETS		1013
#define MENU_SHOW_ARPTAB	1014
#define MENU_CACHE		1015
#define MENU_AUTH_PROXY		1016
#define MENU_AUTH_CLEAR_MEMORY	1017
#define MENU_AUTH_CLEAR_FILE	1018
#define MENU_SYSLOG		1019
#define MENU_IMMREJECT		1020
#define MENU_ACCEPT_WIFIONLY	1021
#define MENU_ACCEPT_PCONLY	1022
#define MENU_SHOW_ALLCONN	1023
#define MENU_TEXT_NOWRAP	1024
#define MENU_SHOW_ALLROUTE	1025
#define MENU_PING_ROUTERS	1026
#define MENU_SET_TO_DEFAULT	1027
#define MENU_SHOW_TCPTAB	1028
#define MENU_PAUSE		1029
#define MENU_DUMP_SCREEN	1030
#define MENU_WIN_HALF		1031
#define MENU_TERMINATE		1032
#define MENU_AUTH_PST		1033
#define MENU_POWER_OFF		1034
#define MENU_POWER_REBOOT	1035
#define MENU_POWER_RESET	1036
#define MENU_POWER_SUSPEND	1037
#define MENU_POWER_IDLE		1038

static HMENU menuMain;
static HMENU menuNets;
static HMENU menuNetsDial;
static HMENU menuNetsShow;
static HMENU menuInst;
static HMENU menuPower;
static HMENU menuProxy;
static HMENU menuAuth;
static HMENU menuProcs;

extern int THPAUSE;
static int smallFont;
static int fontChanged;
static int textNoWrap;
static int AUTODIAL_TCP = 1;
static int AUTODIAL_UDP = 1;
static int AUTODIAL_DNS = 1;
static int AUTOHANGUP = 0;
static int CMG_TRACE;
int withActiveConnections(int op);
static int getStartUp(PVStr(stup),PVStr(xpath));
static int awakeIfProxyActive = 1;
static int showArp;
static int showTcptab;
static int showallRoute;
static int showallConn;
static int ppingRouters;
static int accWiFiOnly;
static int accPcOnly;
static int updateSyslog(int *ia);
static int updateHalfWin(int *ia);
extern int suppressManAuthExpire;

static int *_LOG_type4(int *addr){ return &LOG_type4; }
static struct winFlag {
	char	*p_name;
	char	*p_fmt;
	int	 p_dflt;
	int	*p_addr;
	int   *(*p_addrf)(int *addr);
	int	 p_mask;
	int    (*p_update)(int *addr);
	int	 p_isset;
} winflags[] = {
	{"AUTODIAL-ON-TCP",	"%d", 1, &AUTODIAL_TCP},
	{"AUTODIAL-ON-UDP",	"%d", 1, &AUTODIAL_UDP},
	{"AUTODIAL-ON-DNS",	"%d", 1, &AUTODIAL_DNS},
	{"SMALL-FONT",		"%d", 0, &smallFont},
	{"AWAKE-FOR-PROXY",	"%d", 1, &awakeIfProxyActive},
	{"PING-ROUTERS",	"%d", 0, &ppingRouters},
	{"IMMEDIATE-REJECT",	"%d", 1, 0,_LOG_type4,L_IMMREJECT},
	{"NO-PROXY-AUTH",	"%d", 1, 0,_LOG_type4,L_NOAUTHPROXY},
	{"SYSLOG-SUPPRESS",	"%d", 1, &SUPPRESS_SYSLOG,0,0,updateSyslog},
	{"DONT-WRAP-TEXT",	"%d", 0, &textNoWrap},
	{"SMALL-WINDOW",	  "", 0, &HalfWin,0,0,updateHalfWin},
	{"MANAUTH-PERSISTENT",	"%d", 0, &suppressManAuthExpire},
	{"SHOW-TCPTAB",		"%d", 0, &showTcptab},
	{"SHOW-ALLROUTES",	"%d", 0, &showallRoute},
};
static FILE *fopenFlags(PCStr(mode)){
	FILE *fp;
	fp = XX_fopen_FL(FL_ARG,"/DeleGate/wince-conf.txt",mode);
	return fp;
}
static void setfv(struct winFlag *wf,int iv){
	int *iaddr;
	if( wf->p_addrf )
		iaddr = (*wf->p_addrf)(wf->p_addr);
	else	iaddr = wf->p_addr;
	if( wf->p_mask ){
		if( iv )
			*iaddr |=  wf->p_mask;
		else	*iaddr &= ~wf->p_mask;
	}else{
		*iaddr = iv;
	}
	wf->p_isset++;
	if( wf->p_update ){
		(*wf->p_update)(wf->p_addr);
	}
}
static int getfv(struct winFlag *wf){
	int iv;
	if( wf->p_addrf )
		iv = *(*wf->p_addrf)(wf->p_addr);
	else	iv = *wf->p_addr;
	if( wf->p_mask ){
		if( iv & wf->p_mask )
			iv = 1;
		else	iv = 0;
	}
	return iv;
}
static int issetfv(int *ia){
	int fi;
	struct winFlag *wf;
	for( fi = 0; fi < elnumof(winflags); fi++ ){
		wf = &winflags[fi];
		if( wf->p_addr == ia ){
			return wf->p_isset;
		}
	}
	return 0;
}
static void saveFlags(){
	int fi;
	struct winFlag *wf;
	FILE *fp;
	int iv;

	if( (fp = fopenFlags("w")) == 0 ){
		return;
	}
	for( fi = 0; fi < elnumof(winflags); fi++ ){
		wf = &winflags[fi];
		if( wf->p_fmt == 0 || wf->p_fmt == "" ){
			continue;
		}
		Xfprintf(fp,"%s: ",wf->p_name);
		iv = getfv(wf);
		Xfprintf(fp,wf->p_fmt,iv);
		Xfprintf(fp,"\n");
	}
	XX_fclose_FL(FL_ARG,fp);
}
static void loadFlags(){
	int fi;
	struct winFlag *wf;
	IStr(line,256);
	IStr(name,256);
	IStr(value,256);
	FILE *fp;
	int iv;

	if( (fp = fopenFlags("r")) == 0 ){
		return;
	}
	for(;;){
		if( XX_feof(fp) )
			break;
		if( XX_fgets(AVStr(line),sizeof(line),fp) == 0 )
			break;
		Xsscanf(line,"%[^:]: %[^\r\n]",AVStr(name),AVStr(value));
		for( fi = 0; fi < elnumof(winflags); fi++ ){
			wf = &winflags[fi];
			if( streq(wf->p_name,name) ){
				sscanf(value,wf->p_fmt,&iv);
				setfv(wf,iv);
			}
		}
	}
	XX_fclose_FL(FL_ARG,fp);
	fontChanged++;
}
static void setDefaultFlags(HWND hwnd){
	int fi;
	struct winFlag *wf;
	int iv;

	for( fi = 0; fi < elnumof(winflags); fi++ ){
		wf = &winflags[fi];
		iv = wf->p_dflt;
		setfv(wf,iv);
	}
	fontChanged++;
	buttonSets = 0;
	switchButtons();
}

static void home_disp(HWND hwnd,LPARAM lParam);
static void next_disp(HWND hwnd,LPARAM lParam);
static void prev_disp(HWND hwnd,LPARAM lParam);
static void popupMenu(HWND hwnd,LPARAM lParam,int umsg){
	int flags;

	if( 1 ){
		int xpos,ypos;
		xpos = LOWORD(lParam);
		ypos = HIWORD(lParam);
		if( altsRect.top < ypos && ypos < altsRect.bottom )
		if( altsRect.left < xpos && xpos < altsRect.right )
		{
			++buttonSets;
			switchButtons();
			return;
		}
		if( homeRect.top < ypos && ypos < homeRect.bottom )
		if( homeRect.left < xpos && xpos < homeRect.right )
		{
			home_disp(hwnd,lParam);
			return;
		}
		if( nextRect.top < ypos && ypos < nextRect.bottom )
		if( nextRect.left < xpos && xpos < nextRect.right )
		{
			next_disp(hwnd,lParam);
			return;
		}
		if( prevRect.top < ypos && ypos < prevRect.bottom )
		if( prevRect.left < xpos && xpos < prevRect.right )
		{
			prev_disp(hwnd,lParam);
			return;
		}
	}

	switch( NRefresh % NDISP ){
	    case DISP_HOME:
		if( menuMain ) DestroyMenu(menuMain);
		menuMain = CreatePopupMenu();
		AppendMenu(menuMain,MF_STRING,MENU_CANCELL,
			TEXT("xxx HOME xxx"));

		flags = MF_STRING;
		AppendMenu(menuMain,flags,MENU_POWER_IDLE,
			TEXT("I) Idle (Power Save Mode)"));
		/*
		flags = MF_STRING;
		AppendMenu(menuMain,flags,MENU_DUMP_SCREEN,TEXT("D) Dump screen"));
		*/
		flags = MF_STRING;
		if( HalfWin ) flags |= MF_CHECKED;
		AppendMenu(menuMain,flags,MENU_WIN_HALF,TEXT("W) small Window"));

		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuMain,flags,MENU_SMALLFONT,TEXT("S) Small Font"));

		flags = MF_STRING;
		if( textNoWrap ) flags |= MF_CHECKED;
		AppendMenu(menuMain,flags,MENU_TEXT_NOWRAP,TEXT("T) don't wrap text"));

		flags = MF_STRING;
		AppendMenu(menuMain,flags,MENU_SET_TO_DEFAULT,TEXT("R) Revert to default"));

		flags = MF_STRING;
		AppendMenu(menuMain,flags,MENU_BUTTONSETS,
			TEXT("B) switch Button set"));

		flags = MF_STRING;
		AppendMenu(menuMain,flags,MENU_TERMINATE,
			TEXT("T) Terminate"));

		TrackPopupMenuEx(menuMain,0,0,0,winMain,0);
		break;

	    case DISP_NETS:
		if( menuNets ) DestroyMenu(menuNets);
		menuNets = CreatePopupMenu();
		AppendMenu(menuNets,MF_STRING,
			MENU_CANCELL,TEXT("xxx NETWORK xxx"));

		//if( menuNetsDial ) DestroyMenu(menuNetsDial);
		//destroyed automatically recursively from destroy(menuNets)?
		menuNetsDial = CreatePopupMenu();
		flags = MF_STRING|MF_POPUP;
		if( AUTODIAL_TCP|AUTODIAL_UDP|AUTODIAL_DNS )flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,(UINT)menuNetsDial,
			TEXT("A) AutoDial"));
		AppendMenu(menuNetsDial,MF_STRING,MENU_CANCELL,
			TEXT("xxx AUTO-DIAL xxx"));
		flags = MF_STRING;
		if( AUTODIAL_TCP ) flags |= MF_CHECKED;
		AppendMenu(menuNetsDial,flags,MENU_AUTODIAL_TCP,
			TEXT("T) AutoDial for TCP connection"));
		flags = MF_STRING;
		if( AUTODIAL_UDP ) flags |= MF_CHECKED;
		AppendMenu(menuNetsDial,flags,MENU_AUTODIAL_UDP,
			TEXT("U) AutoDial for UDP outgoing"));
		flags = MF_STRING;
		if( AUTODIAL_DNS ) flags |= MF_CHECKED;
		AppendMenu(menuNetsDial,flags,MENU_AUTODIAL_DNS,
			TEXT("D) AutoDial for DNS retrieval"));

		/*
		flags = MF_STRING;
		if( AUTODIAL_TCP ) flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,MENU_AUTODIAL_TCP,
			TEXT("T) AutoDial for TCP"));
		flags = MF_STRING;
		if( AUTODIAL_UDP ) flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,MENU_AUTODIAL_UDP,
			TEXT("U) AutoDial for UDP"));
		flags = MF_STRING;
		if( AUTODIAL_DNS ) flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,MENU_AUTODIAL_DNS,
			TEXT("D) AutoDial for DNS"));
		*/
		flags = MF_STRING;
		if( AUTOHANGUP ) flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,MENU_AUTOHANGUP,
			TEXT("H) AutoHangup"));

		flags = MF_STRING;
		if( ppingRouters ) flags |= MF_CHECKED;
		AppendMenu(menuNets,flags,MENU_PING_ROUTERS,
			TEXT("K) Keep Routes alive"));

		menuNetsShow = CreatePopupMenu();
		AppendMenu(menuNets,MF_POPUP,(UINT)menuNetsShow,
			TEXT("S) Show tables"));

		AppendMenu(menuNetsShow,MF_STRING,MENU_CANCELL,
			TEXT("xxx NETWORK-TABLES xxx"));
		flags = MF_STRING;
		if( showTcptab ) flags |= MF_CHECKED;
		AppendMenu(menuNetsShow,flags,MENU_SHOW_TCPTAB,
			TEXT("T) show TCP table"));

		flags = MF_STRING;
		if( showallRoute ) flags |= MF_CHECKED;
		AppendMenu(menuNetsShow,flags,MENU_SHOW_ALLROUTE,
			TEXT("R) show all Routes"));

		flags = MF_STRING;
		if( showallConn ) flags |= MF_CHECKED;
		AppendMenu(menuNetsShow,flags,MENU_SHOW_ALLCONN,
			TEXT("C) show all Connections"));

		flags = MF_STRING;
		if( showArp ) flags |= MF_CHECKED;
		AppendMenu(menuNetsShow,flags,MENU_SHOW_ARPTAB,
			TEXT("A) show ARP table"));

		if( showTcptab ){ /* vertical view */
			flags = MF_STRING;
			if( RES_TRACE ) flags |= MF_CHECKED;
			AppendMenu(menuNets,flags,MENU_TRACE_RESOLVER,
				TEXT("R) trace Resolver actions"));

			flags = MF_STRING;
			if( CMG_TRACE ) flags |= MF_CHECKED;
			AppendMenu(menuNets,flags,MENU_TRACE_CONNMGR,
				TEXT("M) trace Connection Manager"));
		}
		{
			int nact;
			IStr(menu,128);
			WCHAR wmenu[128];
			int menux;

			flags = MF_STRING;
			nact = withActiveConnections(0);
			if( nact < 0 ){
				sprintf(menu,"O) Hang-Up (no-dialup)");
				flags |= MF_GRAYED;
				menux = MENU_HANGUP;
			}else
			if( 0 < nact ){
				sprintf(menu,"O) Hang-Up (%d)",nact);
				menux = MENU_HANGUP;
			}else{
				sprintf(menu,"N) Dial-Up Now");
				menux = MENU_DIALUP;
			}
			strtowstr(wmenu,menu,0);
			AppendMenu(menuNets,flags,menux,wmenu);
		}
		TrackPopupMenuEx(menuNets,0,0,0,winMain,0);
		break;

	    case DISP_POWER:
		if( menuPower ) DestroyMenu(menuPower);
		menuPower = CreatePopupMenu();
		AppendMenu(menuPower,MF_STRING,MENU_CANCELL,
			TEXT("xxx POWER xxx"));
		flags = MF_STRING;
		if( awakeIfProxyActive ) flags |= MF_CHECKED;
		AppendMenu(menuPower,flags,MENU_AWAKE_FORPROXY,
			TEXT("U) keep system awake while proxying"));

		flags = MF_STRING;
		if( ppingRouters ) flags |= MF_CHECKED;
		AppendMenu(menuPower,flags,MENU_PING_ROUTERS,
			TEXT("R) keep Routes alive"));

		flags = MF_STRING;
		if( AUTOHANGUP ) flags |= MF_CHECKED;
		AppendMenu(menuPower,flags,MENU_AUTOHANGUP,
			TEXT("H) AutoHangup (180s)"));
		/*
		flags = MF_STRING;
		AppendMenu(menuPower,flags,MENU_POWER_OFF,
			TEXT("O) power Off"));
			// makes Power Manager Stall?
		flags = MF_STRING;
		AppendMenu(menuPower,flags,MENU_POWER_REBOOT,
			TEXT("B) Reboot"));
			// not supported?
		*/
		flags = MF_STRING;
		AppendMenu(menuPower,flags,MENU_POWER_IDLE,
			TEXT("I) Idle (Power Save Mode)"));
		/*
		flags = MF_STRING;
		AppendMenu(menuPower,flags,MENU_POWER_SUSPEND,
			TEXT("S) Suspend"));
		*/
		flags = MF_STRING;
		AppendMenu(menuPower,flags,MENU_POWER_RESET,
			TEXT("S) Reset Device"));

		flags = MF_STRING;
		if( THPAUSE ) flags |= MF_CHECKED;
		AppendMenu(menuPower,flags,MENU_PAUSE,
			TEXT("P) Pause proxy"));

		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuPower,flags,MENU_SMALLFONT,TEXT("S) Small Font"));

		TrackPopupMenuEx(menuPower,0,0,0,winMain,0);
		break;

	    case DISP_PROXY:
		if( menuProxy ) DestroyMenu(menuProxy);
		menuProxy = CreatePopupMenu();
		AppendMenu(menuProxy,MF_STRING,MENU_CANCELL,
			TEXT("xxx PROXY xxx"));

		const char *cachedir();
		flags = MF_STRING;
		if( cachedir() == 0 ){
			flags |= MF_GRAYED;
		}else{
			if( lNOCACHE() ) flags |= MF_CHECKED;
		}
		AppendMenu(menuProxy,flags,MENU_CACHE,
			TEXT("R) disable Response Cache"));

		flags = MF_STRING;
		if( !SUPPRESS_SYSLOG ) flags |= MF_CHECKED;
		AppendMenu(menuProxy,flags,MENU_SYSLOG,TEXT("L) Syslog broadcast to 8514/udp"));

		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuProxy,flags,MENU_SMALLFONT,TEXT("S) Small Font"));

		TrackPopupMenuEx(menuProxy,0,0,0,winMain,0);
		break;

	    case DISP_AUTH:
		if( menuAuth ) DestroyMenu(menuAuth);
		menuAuth = CreatePopupMenu();
		AppendMenu(menuAuth,MF_STRING,MENU_CANCELL,
			TEXT("xxx AUTHENTICATION xxx"));

		flags = MF_STRING;
		if( lNOAUTHPROXY() ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_AUTH_PROXY,
			TEXT("A) disable proxy authentication"));

		flags = MF_STRING;
		if( lIMMREJECT() ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_IMMREJECT,
			TEXT("I) enable immediate rejection"));

		flags = MF_STRING;
		if( suppressManAuthExpire ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_AUTH_PST,
			TEXT("E) don't Expire authentication"));

		flags = MF_STRING;
		if( accWiFiOnly ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_ACCEPT_WIFIONLY,
			TEXT("W) accept only from WiFi"));

		flags = MF_STRING;
		if( accPcOnly ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_ACCEPT_PCONLY,
			TEXT("P) accept only from Pc"));

		flags = MF_STRING;
		AppendMenu(menuAuth,flags,MENU_AUTH_CLEAR_MEMORY,
			TEXT("M) clear authentication on memory"));

		/*
		flags = MF_STRING;
		AppendMenu(menuAuth,flags,MENU_AUTH_CLEAR_FILE,
			TEXT("F) clear authentication on file"));
		*/

		flags = MF_STRING;
		if( ppingRouters ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_PING_ROUTERS,
			TEXT("P) keep Routes alive"));

		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuAuth,flags,MENU_SMALLFONT,TEXT("F) Small Font"));

		TrackPopupMenuEx(menuAuth,0,0,0,winMain,0);
		break;

	    case DISP_PROCESS:
		if( menuProcs ) DestroyMenu(menuProcs);
		menuProcs = CreatePopupMenu();
		AppendMenu(menuProcs,MF_STRING,MENU_CANCELL,
			TEXT("xxx PROCESS xxx"));
		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuProcs,flags,MENU_SMALLFONT,TEXT("S) Small Font"));
		TrackPopupMenuEx(menuProcs,0,0,0,winMain,0);
		break;

	    case DISP_INSTALL:
		IStr(dir,512);
		IStr(xpath,512);
		IStr(ypath,512);
		int smis = getStartMenu(AVStr(dir),AVStr(xpath));
		int suis = getStartUp(AVStr(dir),AVStr(ypath));

		if( menuInst ) DestroyMenu(menuInst);
		menuInst = CreatePopupMenu();
		AppendMenu(menuInst,MF_STRING,MENU_CANCELL,
			TEXT("xxx INSTALLATION xxx"));
		flags = MF_STRING;
		if( smis ) flags |= MF_CHECKED;
		AppendMenu(menuInst,flags,MENU_ADD_STARTMENU,
			TEXT("M) add to StartMenu"));
		flags = MF_STRING;
		if( suis ) flags |= MF_CHECKED;
		AppendMenu(menuInst,flags,MENU_ADD_STARTUP,
			TEXT("U) add to StartUp"));

		flags = MF_STRING;
		if( smallFont ) flags |= MF_CHECKED;
		AppendMenu(menuInst,flags,MENU_SMALLFONT,TEXT("S) Small Font"));

		flags = MF_STRING;
		if( textNoWrap ) flags |= MF_CHECKED;
		AppendMenu(menuInst,flags,MENU_TEXT_NOWRAP,TEXT("W) don't wrap text"));

		TrackPopupMenuEx(menuInst,0,0,0,winMain,0);
		break;
	}
}

static void toggleStartMenu(HWND hwnd,UINT umsg,WPARAM wParam,LPARAM lParam){
	IStr(dir,1024);
	IStr(xpath,1024);
	int smis;
	smis = getStartMenu(AVStr(dir),AVStr(xpath));
	if( smis )
		delStartMenu(AVStr(dir));
	else	addStartMenu(AVStr(dir));
}
static void toggleStartUp(HWND hwnd,UINT umsg,WPARAM wParam,LPARAM lParam){
	IStr(stup,256);
	int suis;
	int rcode;
	IStr(sstat,256);
	IStr(xpath,256);

	suis = getStartUp(AVStr(stup),AVStr(xpath));
	if( suis ){
		rcode = unlink(stup);
		/*
		if( rcode != 0 )
		sprintf(sstat,"can't remove(%d)",rcode);
		*/
	}else{
		addStartUp(stup,AVStr(sstat));
	}
}
static int updateSyslog(int *ia){
	if( SUPPRESS_SYSLOG ){
		setDebugForce("-vs");
	}else{
		setDebugForce("-vu");
	}
	return 0;
}
static void toggleSyslog(HWND hwnd,UINT umsg,WPARAM wParam,LPARAM lParam){
	SUPPRESS_SYSLOG = !SUPPRESS_SYSLOG;
	updateSyslog(&SUPPRESS_SYSLOG);
}
char *findConnMgr(PVStr(cstat),PCStr(fmt),PCStr(type),PCStr(subtype));
int assignServAddr(PCStr(host));
static int naWiFi;
static int naPc;
static void toggleWiFiOnly(){
	IStr(wifi,128);

	accWiFiOnly = !accWiFiOnly;
	if( accWiFiOnly ){
		accPcOnly = 0;
	}
	findConnMgr(AVStr(wifi),"%A","Nic","WiFi");
	if( *wifi ){
		if( accWiFiOnly ){
			naWiFi = assignServAddr(wifi);
		}else{
			naWiFi = assignServAddr("");
		}
	}
}
static void togglePcOnly(){
	IStr(aspc,128);

	accPcOnly = !accPcOnly;
	if( accPcOnly ){
		accWiFiOnly = 0;
	}
	findConnMgr(AVStr(aspc),"%A","Pc","");
	if( *aspc ){
		if( accPcOnly ){
			naPc = assignServAddr(aspc);
		}else{
			naPc = assignServAddr("");
		}
	}
}
static void toggleHalfWin(HWND hwnd,int toggle);
static void schedHangup();
static void schedDialup();
int dumpScreen(FILE *fp);
static int inIdle = 0;
static void setSyspower(const char *name){
	IStr(msg,128);
	IStr(yn,32);
	int err;
	int pstat;
	int ok;

	sprintf(msg,"POWER %s ?",name);
	ok = getAnswerYNWTO(8,msg,AVStr(yn),sizeof(yn));
	if( yn[0] == 'y' || *name == 'I' && ok == -1/*TIMEOUT*/ ){
		err = setsyspower(name,0,&pstat);
		if( err == ERROR_SUCCESS ){
			if( *name == 'I' )
				inIdle = 1;
			else	inIdle = 0;
		}else{
			askWinOK("%s err=%d %d",msg,err,GetLastError());
		}
	}
}
static void actNetMenu(HWND hwnd,UINT umsg,WPARAM wParam,LPARAM lParam){
	switch( (int)wParam ){
		case MENU_SET_TO_DEFAULT:
			setDefaultFlags(hwnd);
			break;
		case MENU_DUMP_SCREEN:
			dumpScreen(0);
			break;
		case MENU_WIN_HALF:
			toggleHalfWin(hwnd,1);
			break;
		case MENU_TERMINATE:
			Finishing = 1; /* to suppress MessageBox */
			THEXIT = 1;
			break;
		case MENU_ADD_STARTMENU:
			toggleStartMenu(hwnd,umsg,wParam,lParam);
			refreshWinStatus = 1;
			break;
		case MENU_ADD_STARTUP:
			toggleStartUp(hwnd,umsg,wParam,lParam);
			refreshWinStatus = 1;
			break;
		case MENU_AWAKE_FORPROXY:
			awakeIfProxyActive = !awakeIfProxyActive;
			refreshWinStatus = 1;
			break;
		case MENU_POWER_OFF:
			setSyspower("OFF");
			break;
		case MENU_POWER_REBOOT:
			setSyspower("BOOT");
			break;
		case MENU_POWER_RESET:
			setSyspower("RESET");
			break;
		case MENU_POWER_IDLE:
			setSyspower("IDLE");
			break;
		case MENU_POWER_SUSPEND:
			setSyspower("SUSPEND");
			break;
		case MENU_PAUSE:
			THPAUSE = !THPAUSE;
			break;
		case MENU_SHOW_TCPTAB:
			showTcptab = !showTcptab;
			break;
		case MENU_SHOW_ARPTAB:
			showArp = !showArp;
			break;
		case MENU_PING_ROUTERS:
			ppingRouters = !ppingRouters;
			break;
		case MENU_SHOW_ALLROUTE:
			showallRoute = !showallRoute;
			break;
		case MENU_SHOW_ALLCONN:
			showallConn = !showallConn;
			break;
		case MENU_TRACE_RESOLVER:
			RES_TRACE = !RES_TRACE;
			break;
		case MENU_TRACE_CONNMGR:
			CMG_TRACE = !CMG_TRACE;
			break;
		case MENU_AUTODIAL_TCP:
			AUTODIAL_TCP = !AUTODIAL_TCP;
			break;
		case MENU_AUTODIAL_DNS:
			AUTODIAL_DNS = !AUTODIAL_DNS;
			break;
		case MENU_AUTODIAL_UDP:
			AUTODIAL_UDP = !AUTODIAL_UDP;
			break;
		case MENU_AUTOHANGUP:
			AUTOHANGUP = !AUTOHANGUP;
			break;
		case MENU_HANGUP:
			schedHangup();
			break;
		case MENU_DIALUP:
			schedDialup();
			break;
		case MENU_SMALLFONT:
			smallFont = !smallFont;
			fontChanged++;
			break;
		case MENU_TEXT_NOWRAP:
			textNoWrap = !textNoWrap;
			break;
		case MENU_BUTTONSETS:
			++buttonSets;
			switchButtons();
			break;
		case MENU_CACHE:
			if( lNOCACHE() ){
				LOG_type3 &= ~L_NOCACHE;
			}else{
				LOG_type3 |= L_NOCACHE;
			}
			break;
		case MENU_ACCEPT_WIFIONLY:
			toggleWiFiOnly();
			break;
		case MENU_ACCEPT_PCONLY:
			togglePcOnly();
			break;
		case MENU_IMMREJECT:
			if( lIMMREJECT() )
				LOG_type4 &= ~L_IMMREJECT;
			else	LOG_type4 |= L_IMMREJECT;
			break;
		case MENU_AUTH_PROXY:
			if( lNOAUTHPROXY() )
				LOG_type4 &= ~L_NOAUTHPROXY;
			else	LOG_type4 |= L_NOAUTHPROXY;
			break;
		case MENU_AUTH_PST:
			suppressManAuthExpire = !suppressManAuthExpire;
			break;
		case MENU_AUTH_CLEAR_MEMORY:
			clearAuthMan();
			break;
		case MENU_SYSLOG:
			toggleSyslog(hwnd,umsg,wParam,lParam);
			break;
	}
	saveFlags();
}

int regGetResolvConf(PVStr(buf),PVStr(where));
static char *disp_main(HWND hwnd,PVStr(mbuf)){
	CStr(temp,256);
	IStr(hosts,1024); IStr(ports,1024);
	IStr(stime,1024);
	refQStr(mp,mbuf);

	if( IMsg.i_msg[0] ){
		Rsprintf(mp,"%s",IMsg.i_msg);
	}
	Rsprintf(mp,"%s\n",DELEGATE_verdate());
	if( isWindowsCE() )
		Rsprintf(mp,"Home: http://wince.delegate.org\n");
	else	Rsprintf(mp,"Home: http://mswin.delegate.org\n");
	Rsprintf(mp,"Class: %s\n",uwinClassName);
	Rsprintf(mp,"DGROOT=%s\n",DELEGATE_DGROOT);
#if defined(UNDER_CE)
	regGetStorageCard(AVStr(temp));
	Rsprintf(mp,"StorageCard: %s %s\n",temp,
		fileIsdir(temp)?"(on)":"(empty)");
#endif
	if( streq(DELEGATE_VARDIR,WinCEE.VARDIR) ){
		Rsprintf(mp,"VARDIR=%s\n",DELEGATE_VARDIR);
	}
	/*
	if( START_TIME ){
		StrftimeLocal(AVStr(stime),sizeof(stime),
			"%H:%M:%S %m/%d",START_TIME,0);
		Rsprintf(mp,"Started: %s\n",stime);
	}
	*/
	if( 2 <= Terminating ){
		return (char*)mp;
	}

	/*
	if( regGetHosts(AVStr(hosts)) == 0 ){
		NoNet = 0;
		if( 0 <= reconnecting ){
			closesocket(reconnecting);
			reconnecting = -1;
		}
	}else{
		if( NoNet == 0 ){
			NoNet = time(0);
		}
		Rsprintf(mp,"... connecting[%d](%d) ...\n",
			reconnecting,time(0)-NoNet);
	}
	*/
#if defined(UNDER_CE)
	char *printConnMgr(PVStr(cstat),int showall,int simple,int doconn);
	Rsprintf(mp,"Networks:\n");
	printConnMgr(AVStr(mp),0,1,0); mp += strlen(mp);
#endif

	/*
	just for ActiveSync? but don't show stale info.
	regGetHosts(AVStr(hosts));
	if( hosts[0] ){
		Rsprintf(mp,"Hosts: %s\n",hosts);
	}
	*/

/*
setTcpRegVal(AVStr(mp),1,"TcpInitialRTT",        0); mp += strlen(mp);
setTcpRegVal(AVStr(mp),0,"TCP1323Opts",          0); mp += strlen(mp);
setTcpRegVal(AVStr(mp),1,"TcpDelAckTicks",       0); mp += strlen(mp);
setTcpRegVal(AVStr(mp),1,"TcpWindowSize",        0); mp += strlen(mp);
*/
//setTcpRegVal(AVStr(mp),1,"TcpInitialRTT",      "1"); mp += strlen(mp);
//setTcpRegVal(AVStr(mp),0,"TCP1323Opts",        "1"); mp += strlen(mp);
//setTcpRegVal(AVStr(mp),1,"TcpDelAckTicks",     "2"); mp += strlen(mp);
//setTcpRegVal(AVStr(mp),1,"TcpWindowSize","0x10000"); mp += strlen(mp);

	dump_ENTR("",AVStr(ports));
	if( ports[0] ){
		Rsprintf(mp,"Ports:\n%s\n",ports);
	}
	return (char*)mp;
}
static char *disp_proxy(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);

	mp += strlen(mp);
	if( LOGX_app_respIncomplete ){
		Rsprintf(mp,"Truncated:%4d\n",LOGX_app_respIncomplete);
	}
	if( 0 < POut.poT ){
		Rsprintf(mp,"\nPollOut:%.3f/%d/%d/%.1f/%d\n",
			POut.poT/POut.poN,POut.poN,
			POut.poX,POut.poTMax,POut.poZ);
	}
	if( CF_NUM ){
		Rsprintf(mp,"\nCreateFile:%3d OK=%d D%d T%d R%d E%d",
			CF_NUM,CF_OK,CF_DEV,CF_NOTMP,CF_RET,CF_ERR);
	}
	return (char*)mp;
}
int authOnMemory(int *acc,int *rej);
char *listAccHist(PVStr(list),int am);
extern int BadSweepDangs;
extern int BadSweepDups;

int VSA_strisaddr(PCStr(addr));
char *printRoutes(PVStr(buf),PCStr(ifp),PCStr(ipp),int all,int closeEther);
char *doPing(PCStr(addr),int timeout,int count,PVStr(stat));
static int Started;
static IStr(lastClient,32);
static char *pingRouters(PVStr(msg)){
	static IStr(pingRes,256);
	static int lastPing;
	refQStr(mp,msg);
	IStr(addr,1024);
	int nping = 0;
	int now = time(0);

	if( now-lastPing < 10 ){
		Rsprintf(mp,"%s",pingRes);
		return (char*)mp;
	}
	if( Started )
	if( ppingRouters || now-Started<60 ){
		lastPing = now;
		printRoutes(AVStr(addr),"eth","*.*.*.*",0,0);
		if( addr[0] && VSA_strisaddr(addr) ){
			mp = doPing(addr,500,1,AVStr(mp));
			nping++;
		}
		printRoutes(AVStr(addr),"ppp","*.*.*.*",0,0);
		if( addr[0] && VSA_strisaddr(addr) ){
			mp = doPing(addr,500,1,AVStr(mp));
			nping++;
		}
		if( lastClient[0] && VSA_strisaddr(lastClient) ){
			mp = doPing(lastClient,500,1,AVStr(mp));
			nping++;
		}
		if( nping == 0 ){
			sprintf(mp,"Ping: no default routes\n");
		}else
		if( *msg == 0 ){
			sprintf(mp,"Ping: no responses (%d)\n",nping);
		}else{
			strcpy(pingRes,msg);
		}
	}
	return (char*)mp;
}

static char *cpuUsage(PVStr(buf)){
	refQStr(mp,buf);
	static DWORD its[8],ets[8],tx;
	DWORD it,et;

	it = GetIdleTime();
	et = GetTickCount();
	Rsprintf(mp,"CPU:");
	if( its[0] ){
		int id,ed;
		id = it - its[0];
		ed = et - ets[0];
		Rsprintf(mp," %d%% / %.1fs",
			((ed-id)*100)/ed,((double)ed)/1000);
	}
	Rsprintf(mp," (%d%% / %ds)",
			((et-it)*100)/et,et/1000);
	Rsprintf(mp,"\n");
	its[0] = it;
	ets[0] = et;
	return (char*)mp;
}
static char *disp_auth(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);
	IStr(wifi,256);
	IStr(uspc,256);
	IStr(grps,256);
	IStr(unim,256);
	int acmem;
	int nacc,nrej;

	Rsprintf(mp,"ACCESS CONTROL\n");
	Rsprintf(mp,"\n");

	mp = cpuUsage(AVStr(mp));
	mp = pingRouters(AVStr(mp));
	findConnMgr(AVStr(uspc),"%A","Pc","");
	findConnMgr(AVStr(wifi),"%A","Nic","WiFi");
	findConnMgr(AVStr(grps),"%A","Cellular","");
	findConnMgr(AVStr(unim),"%A","Unimodem","");
	if( *wifi ){
		Rsprintf(mp,"WiFi%s: %s",accWiFiOnly?"-Only":"", wifi);
		if( accWiFiOnly ) Rsprintf(mp," (%d ports)",naWiFi);
		Rsprintf(mp,"\n");
	}
	if( *uspc ){
		Rsprintf(mp,"Pc%s: %s",accPcOnly?"-Only":"", uspc);
		if( accPcOnly ) Rsprintf(mp," (%d ports)",naPc);
		Rsprintf(mp,"\n");
	}
	if( *grps ){
		Rsprintf(mp,"Dialup: %s\n",grps);
	}
	if( *unim ){
		Rsprintf(mp,"Dialup: %s\n",unim);
	}

	Rsprintf(mp,"Accepted:  %5d\n",LOGX_accPassed);
	Rsprintf(mp,"Rejected:  %5d\n",LOGX_accDenied);
	if( LOGX_authNone )
	Rsprintf(mp,"Auth-None: %5d\n",LOGX_authNone);
	if( LOGX_authErr )
	Rsprintf(mp,"Auth-Err:  %5d\n",LOGX_authErr);
	if( LOGX_authOk )
	Rsprintf(mp,"Auth-OK:   %5d\n",LOGX_authOk);
	if( acmem = authOnMemory(&nacc,&nrej) )
	Rsprintf(mp,"Auth-Cache: On-Mem(%d Acc=%d,Rej=%d)\n",acmem,nacc,nrej);

	if( 1 < BadSweepDangs )
	Rsprintf(mp,"BadSweep: Dang=%d Dup=%d\n",BadSweepDangs,BadSweepDups);
	Rsprintf(mp,"\n");
	mp = listAccHist(AVStr(mp),32);
	return (char*)mp;
}

static int ItemX;
static WPARAM lastwParam;
static LPARAM lastlParam;
static char *disp_procs(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);

	MEMORYSTATUS mst;
	mst.dwLength = sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(&mst);

	Rsprintf(mp,"PROCESS STATUS\n");
	Rsprintf(mp,"\n");
	mp = cpuUsage(AVStr(mp));
	Rsprintf(mp,"MemoryUsage:");
	Rsprintf(mp," %d%%",mst.dwMemoryLoad);
	Rsprintf(mp," P:%d/%d",mst.dwAvailPhys/1024/1024,
			mst.dwTotalPhys/1024/1024);
	Rsprintf(mp," V:%d/%d",mst.dwAvailVirtual/1024/1024,
			mst.dwTotalVirtual/1024/1024);
	/*
	Rsprintf(mp," %d",mst.dwTotalPageFile);
	*/
	Rsprintf(mp," %llu",(FileSize)mst.dwTotalPageFile);
	Rsprintf(mp,"\n");

	FILE *tmp = TMPFILE("ps");
	int rcc;
	int siz;
	ps_unix(tmp);
	fflush(tmp);
	siz = file_size(fileno(tmp));
	XX_fseek(tmp,0,0);
	if( !isWindowsCE() ){
		/* XX_fread() is not defined for Win32 */
		unsigned int Xfread(FL_PAR,PVStr(d),int ez,int en,FILE *fp);
		rcc = Xfread(FL_ARG,AVStr(mp),1,3*1024,tmp);
	}else
	rcc = XX_fread(FL_ARG,(char*)mp,1,1024,tmp);
	XX_fclose_FL(FL_ARG,tmp);
	if( 0 < rcc ){
		mp += rcc;
		setVStrEnd(mp,0);
	}
	return (char*)mp;
}
#include <Ras.h>
#include <RasError.h>
int regGetRasBook(PVStr(books));
void testconn(PCStr(host),PVStr(mp));

#if 0
/*
should be implemented by INetwork, INetworkListManager ?
http://msdn.microsoft.com/en-us/library/aa965303(VS.85).aspx
 */
DWORD DLL_RasEnumConnections(LPRASCONN rc,LPDWORD cb,LPDWORD cC);
DWORD DLL_RasGetConnectStatus(HRASCONN rc,LPRASCONNSTATUS rcs);
int rasstat(PVStr(stat)){
	refQStr(sp,stat);
	int code;
	IStr(ename,128);
	RASCONN rasconns[128];
	DWORD cb;
	DWORD nc;
	DWORD rc;
	int ri;
	RASCONNSTATUS cstat;
	IStr(dtype,128);
	IStr(dname,128);
	RASCONN *rp;

	clearVStr(stat);
	bzero(rasconns,sizeof(rasconns));
	rasconns[0].dwSize = sizeof(RASCONN);
	cb = sizeof(rasconns);
	nc = 0;
	rc = DLL_RasEnumConnections(rasconns,&cb,&nc);
	if( nc < 0 ){
		return 0;
	}
	Rsprintf(sp,"Act[%d]",nc);
	if( rc != 0 ){
		Rsprintf(sp,"(rc=%d)",rc);
	}
	for( ri = 0; ri < nc; ri++ ){
		rp = &rasconns[ri];
		wstrtostr(ename,rp->szEntryName,0);
		Rsprintf(sp," %s",ename);
		if( rp->hrasconn ){
			cstat.dwSize = sizeof(cstat);
			code = DLL_RasGetConnectStatus(rp->hrasconn,&cstat);
			wstrtostr(dtype,cstat.szDeviceType,0);
			wstrtostr(dname,cstat.szDeviceName,0);
		}
	}
	return 0;
}
#endif

static int rasDial(PCStr(books),PVStr(stat),int dialup){
	refQStr(sp,stat);
	RASDIALPARAMS rdp;
	BOOL passwd;
	int code;
	WCHAR pn[128];
	IStr(ename,128);
	IStr(user,128);
	IStr(pass,128);
	HRASCONN nrconn = 0;
	RASENTRY ras1;


	/*
	bzero(&ras1,sizeof(ras1));
	ras1.dwSize = sizeof(RASENTRY);
	RasGetEntryProperties();
	*/

	passwd = -123;
	bzero(&rdp,sizeof(rdp));
	rdp.dwSize = sizeof(rdp);
	SetLastError(0);

	RASCONN rasconns[16];
	DWORD cb;
	DWORD nc;
	DWORD rc;
	int ri;
	bzero(rasconns,sizeof(rasconns));
	rasconns[0].dwSize = sizeof(RASCONN);
	cb = sizeof(rasconns);
	nc = 0;
	rc = RasEnumConnections(rasconns,&cb,&nc);

	if( 0 < nc ){
		int isconn = 0;
		Rsprintf(sp,"Act[%d]",nc);
		if( rc != 0 ){
			Rsprintf(sp,"(rc=%d)",rc);
		}
		for( ri = 0; ri < nc; ri++ ){
			RASCONN *rp;
			rp = &rasconns[ri];
			wstrtostr(ename,rp->szEntryName,0);
			Rsprintf(sp,"%s",ename);
			if( rp->hrasconn ){
RASCONNSTATUS cstat;
cstat.dwSize = sizeof(cstat);
code = RasGetConnectStatus(rp->hrasconn,&cstat);

IStr(dtype,128);
IStr(dname,128);
wstrtostr(dtype,cstat.szDeviceType,0);
wstrtostr(dname,cstat.szDeviceName,0);

/*
askWinOK("RASdial: %d/%d [%s] %d(%s)(%s)(%d)(%X)",
ri,nc,ename,code,dtype,dname,cstat.dwError,cstat.rasconnstate);
*/
				if( code != 0 ){
					Rsprintf(sp,"(code=%d)",code);
				}else{
				if( cstat.dwError )
				Rsprintf(sp,"(Err=%d)",cstat.dwError);

	Rsprintf(sp,"/%s%s/%s",
	(cstat.rasconnstate & RASCS_Connected ? "C":""),
	(cstat.rasconnstate & RASCS_Disconnected ? "D":""),
	dtype);
					//Rsprintf(sp,"(%s)",dname);
if( cstat.dwError == ERROR_PORT_DISCONNECTED
 || cstat.dwError == ERROR_PORT_NOT_AVAILABLE
){
	code = RasHangUp(rp->hrasconn);
	Rsprintf(sp,"(cleared=%d)",code);
}
				}
				continue;

if( cstat.dwError == ERROR_PORT_DISCONNECTED
 || cstat.dwError == 633
){
	code = RasHangUp(rp->hrasconn);
	Rsprintf(sp,"(cleared=%d)",code);
	continue;
}
if( cstat.rasconnstate & RASCS_Connected){
	return 0;
}
				isconn++;
				code = RasHangUp(rp->hrasconn);
				//CloseHandle(rp->hrasconn);
				Rsprintf(sp,"(hang=%d)",code);
			}
		}
		if( isconn ){
			//return 0;
		}
	}
	if( ename[0] == 0 ){
		strcpy(ename,books);
	}

	if( dialup == 0 ){
		return -1;
	}
return -1;
	/* the following shoud be in background */

/*
	IStr(yn,8);
	getAnswerYN("Dialup?",AVStr(yn),sizeof(yn));
	UpdateWindow(winMain);
	if( yn[0] != 'y' ){
		return -1;
	}
*/

	strtowstr(rdp.szEntryName,ename,0);
	code = RasGetEntryDialParams(NULL,&rdp,&passwd);
	if( code != 0 ){
		Rsprintf(sp,"RAS(%d)%d Err=%d",
			passwd,code,GetLastError());
		return -1;
	}else{
		wstrtostr(user,rdp.szUserName,0);
		wstrtostr(pass,rdp.szPassword,0);
		Rsprintf(sp,"(%s%s)",user,passwd?":pass":"");

		code = RasDial(NULL,NULL,&rdp,0,0,&nrconn);
		switch( code ){
			case ERROR_NOT_ENOUGH_MEMORY:
				Rsprintf(sp,"dial(NOT_ENOUGH_MEMORY,%X)",
					nrconn);
				break;
			case ERROR_PORT_NOT_AVAILABLE:
				Rsprintf(sp,"dial(PORT_NOT_AVAILABLE,%X)",
					nrconn);
				break;
			case ERROR_PORT_NOT_OPEN:
				Rsprintf(sp,"dial(PORT_NOT_OPEN)");
				break;
			case ERROR_DEVICE_DOES_NOT_EXIST:
				Rsprintf(sp,"dial(DEVICE_NONEXISTENT)");
				break;
			default:
				int codeh;
IStr(connst,128);
/*AAAA
testconn(AVStr(connst));
*/
				codeh = RasHangUp(nrconn);
				Rsprintf(sp,"dial(%d,%X,%d)%s",
					code,nrconn,codeh,connst);
				break;
		}
		return 0;
	}
}

static int noDfltRoute;
static void tryRASconn(int dodial){
	IStr(books,256);
	RASENTRYNAME ren[8];
	DWORD cb,ne;
	IStr(stat,256);

	ren[0].dwSize = sizeof(ren[0]);
	if( RasEnumEntries(NULL,NULL,ren,&cb,&ne) == 0 ){
		wstrtostr(books,ren[0].szEntryName,0);
	}else{
		regGetRasBook(AVStr(books));
	}
	dodial |= lastConn.ConnDelay < 0 && noDfltRoute;
	rasDial(books,AVStr(stat),dodial);
	sprintf(lastConn.RASconns,"%s",stat);
}
void winmo_dllstat(PVStr(stat),int all);
//#include <Shlobj.h>

static OSVERSIONINFO osv;
static double getosv(){
	if( osv.dwOSVersionInfoSize == 0 ){
		osv.dwOSVersionInfoSize = sizeof(osv);
		GetVersionEx(&osv);
	}
	return osv.dwMajorVersion; // + ov.dwMinorVersion/100.0;
}
static char *disp_install(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);
	refQStr(op,mbuf);
	IStr(dir,1024);
	IStr(stup,256);
	IStr(sstat,256);
	int rcode;
	int smis;
	int suis;
	int ypos;
	int flags;
	IStr(mypath,512);
	IStr(xpath,512);
	IStr(ypath,512);

	ypos = HIWORD(lastlParam);
	smis = getStartMenu(AVStr(dir),AVStr(xpath));
	suis = getStartUp(AVStr(stup),AVStr(ypath));

	Rsprintf(mp,"INSTALLATION\n");
	Rsprintf(mp,"\n");

	op = mp;
	strcpy(mypath,myExePath());
	strsubst(AVStr(mypath),"\\","/");
	Rsprintf(mp,"Executable:\n %s\n",mypath);

/*
	smis = getStartMenu(AVStr(dir),AVStr(xpath));
	if( DoRefresh && 50 < ypos && ypos < 100 ){
		if( smis )
			delStartMenu(AVStr(dir));
		else	addStartMenu(AVStr(dir));
	}
*/
	Rsprintf(mp,"\n");
	Rsprintf(mp,"StartMenu: ");
	if( getStartMenu(AVStr(dir),AVStr(xpath)) )
	{
		strsubst(AVStr(xpath),"\\","/");
		if( strcaseeq(mypath,xpath) )
		Rsprintf(mp,"tap here to Remove\n %s\n",dir);
		else
		Rsprintf(mp,"tap here to Remove (%s)\n %s\n",xpath,dir);
	}
	else	Rsprintf(mp,"tap here to Add\n (%s)\n","Not in the Start Menu");


	Rsprintf(mp,"\n");
/*
	if( DoRefresh && 120 < ypos && ypos < 140 ){
		int rcode;
		if( suis ){
			rcode = unlink(stup);
			if( rcode != 0 )
			sprintf(sstat,"can't remove(%d)",rcode);
		}else{
			addStartUp(stup,AVStr(sstat));
		}
	}
*/
	suis = File_is(stup);
	Rsprintf(mp,"StartUp: ");
	if( suis )
	{
		strsubst(AVStr(ypath),"\\","/");
		if( strcaseeq(mypath,ypath) )
		Rsprintf(mp,"tap here to Remove\n %s\n",stup);
		else
		Rsprintf(mp,"tap here to Remove (%s)\n %s\n",ypath,stup);
	}
	else	Rsprintf(mp,"tap here to Add\n (%s)\n","Not in the StartUp");

	/*
	ITEMIDLIST *idls = 0;
	if( SHGetSpecialFolderLocation(hwnd,CSIDL_STARTMENU,&idl) == NOERROR ){
	}
	*/
	Rsprintf(mp,"\n");
	OSVERSIONINFO ov;
	ov.dwOSVersionInfoSize = sizeof(ov);
	if( GetVersionEx(&ov) ){
		IStr(ver,128);
		wstrtostr(ver,ov.szCSDVersion,0);
		Rsprintf(mp,"OS: ver=%d.%d build=%d %s\n",
			ov.dwMajorVersion,ov.dwMinorVersion,ov.dwBuildNumber,
			ver
		);
	}

	Rsprintf(mp,"Zlib: %s\n",ZlibVersion());
	Rsprintf(mp,"\n");
	winmo_dllstat(AVStr(mp),1);
	mp += strlen(mp);

	return (char*)mp;
}
#if defined(UNDER_CE)
int unamef(PVStr(uname),PCStr(fmt)){
	OSVERSIONINFO ov;
	const char *fp = fmt;
	refQStr(up,uname);
	IStr(ver,128);

	if( GetVersionEx(&ov) == 0 ){
		setVStrEnd(up,0);
		return -1;
	}
	wstrtostr(ver,ov.szCSDVersion,0);
	Rsprintf(up,"ver=%d.%d build=%d %s\n",
		ov.dwMajorVersion,ov.dwMinorVersion,ov.dwBuildNumber,
		ver
	);
	return 0;
}
#endif

int setRegValue(PVStr(stat),PCStr(root),PCStr(rkey),PCStr(name),PCStr(val));

static int inDialup;
int withWaitingConnections();
int tryConnection(PCStr(dsturl),PVStr(cstat));
int newSocket(PCStr(what),PCStr(opts));
int isUDPsock(int sock);

#undef SocketOf
#include "vsocket.h" // contains the definition of SocketOf()
int VSA_satoap(VSAddr *sa,PVStr(addrport));

int getpeerName(int sock,PVStr(sockname),PCStr(form));
int gethostName(int sock,PVStr(sockname),PCStr(form));
int VSA_satoap(VSAddr *sa,PVStr(addrport));
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr));
void HookAccept(int fd,int nfd,_SAP aaddr,int *len){
	IStr(addr,64);
	refQStr(pp,addr);
	IStr(maca,64);

	if( nfd < 0 )
		return;
	if( *len <= 0 )
		return;
	if( VSA_satoap((VSAddr*)aaddr,AVStr(addr)) == 0 ){
		if( pp = strrchr(addr,':') ){
			clearVStr(pp);
			if( getMacAddr(addr,AVStr(maca)) == maca ){
				/* it is not on the local segment */
				return;
			}
			strcpy(lastClient,addr);
		}
	}
	/*
	if( getpeerName(nfd,AVStr(addr),"%A") ){
		strcpy(lastClient,addr);
	}
	*/
}
static int suppressWinStatus;
#if defined(UNDER_CE)
int dialupTOX(PCStr(wh),int asock,void *addr,int leng,int timeout,PVStr(cstat)){
	IStr(msg,MSGSIZE);
	int rcode = -1;
	int ccode;
	int ti;
	IStr(dsthost,256);
	IStr(dsturl,256);
	int sock;
	int isudp;
	int serrno = errno;
	int nact;

	if( Terminating || THEXIT ){
		return -9;
	}
	if( inDialup ){
		return -2;
	}
	isudp = isUDPsock(asock);
	VSA_satoap((VSAddr*)addr,AVStr(dsthost));
	for( ti = 0; ti < 20; ti++ ){
		if( Terminating || THEXIT ){
			rcode = -9;
			break;
		}
		if( withWaitingConnections() == 0 )
			break;
		sprintf(lastConn.lc_stat,"DialUp/%s(%d) Waiting... > %s %s",
			wh,ti,dsthost,isudp?"U":"T");
		putWinStatus("DialUp/%s(%d) Waiting...",wh,ti);
		Sleep(1000);
	}
	if( nact = withActiveConnections(0) ){
		// should check active connections to the "addr"
		if( 0 < ti ){ // did wait
			sprintf(lastConn.lc_stat,"DialUp/%s(%d)>%s",
				wh,ti,dsthost);
		}
		return -3;
	}
	if( isudp ){
		if( AUTODIAL_DNS == 0 || AUTODIAL_UDP == 0 )
			return -4;
	}else{
		if( AUTODIAL_TCP == 0 )
			return -5;
	}
	inDialup++;
	syslog_ERROR("Dialup to %s%s ti=%d act=%d err=%d <= %s:%d\n",
		dsthost,isudp?"/udp":"",ti,nact,serrno,cstatFILE,cstatLINE);
	sprintf(dsturl,"http://%s",dsthost);
	sock = newSocket("dialup","");
	setNonblockingIO(sock,1);
	tryConnection(dsturl,AVStr(msg));
	syslog_ERROR("Dialup to %s tried: %s",dsthost,msg);

	if( serrno == WSAETIMEDOUT || serrno == 0 ){
	}else{
	NRefresh = DISP_NETS;
	suppressWinStatus = 1;
	}
	for( ti = 0; ti < 20; ti++ ){
		if( Terminating || THEXIT ){
			rcode = -9;
			break;
		}
		errno = 0;
	/*
		if( isudp ){
			if( 0 < withActiveConnections(0) ){
				ccode = 0;
				rcode = 0;
			}else{
				ccode = -2;
				errno = WSAEHOSTUNREACH;
			}
		}else
	*/
		ccode = _CONNECT(sock,(_SAP)addr,leng);
		sprintf(lastConn.lc_stat,"DialUp/%s(%d)*%d %d %d %d > %s %s",
			wh,serrno,ti,errno,ccode,rcode,dsthost,(isudp?"U":"T"));
		putWinStatus("DialUp/%s(%d) %d %d",wh,ti,ccode,errno);
		syslog_ERROR("DialUp/%s(%d) %d %d\n",wh,ti,ccode,errno);

		if( ccode == 0 || errno == WSAEISCONN ){
			rcode = 0;
			break;
		}
		if( errno == WSAEINVAL ){
			/* might be because it is connected */
			/* should wait "Connected" status of the connection */
			IStr(stime,32);
			StrftimeLocal(AVStr(stime),sizeof(stime),"%H:%M",-1,-1);
			sprintf(lastConn.lc_stat,"%s DialUp/%s(%d)>%s",
				stime,wh,ti,dsthost);
			rcode = 0;
			break;
		}
	/*
		if( errno != WSAEFAULT )
	*/
		if( errno != WSAEHOSTUNREACH && errno != WSAENETUNREACH ){
			break;
		}
		Sleep(1000);
	}
	if( serrno == WSAETIMEDOUT ){
	}else{
	suppressWinStatus = 0;
	}
	inDialup--;
	close(sock);
	return rcode;
}
#endif
int setPowerBG(int bg);
static char *batteryStat(int flags,PVStr(msg)){
	refQStr(mp,msg);
	const char *st;
	int flag1,fi;

	if( (flags & BATTERY_FLAG_HIGH) && (flags & BATTERY_FLAG_LOW) ){
		Rsprintf(mp,"Unknown");
		return (char*)mp;
	}
	for( fi = 0; fi < 8; fi++ ){
	    if( flag1 = flags & (1 << fi) ){
		switch( flag1 ){
		  case BATTERY_FLAG_HIGH:       st="High"; break;
		  case BATTERY_FLAG_LOW:        st="Low"; break;
		  case BATTERY_FLAG_CRITICAL:   st="Critical"; break;
		  case BATTERY_FLAG_CHARGING:   st="Charging"; break;
		  case BATTERY_FLAG_NO_BATTERY: st="None"; break;
		  case BATTERY_FLAG_UNKNOWN:    st="Unknown"; break;
		  default: st="?";
		}
		Rsprintf(mp,"%s%s",msg<mp?",":"",st);
	    }
	}
	return (char*)mp;
}
char *syspwstat(PVStr(stat));
char *devpwstat(PVStr(stat),PCStr(dev),int force);
int getRegValue(PVStr(stat),PVStr(val),PCStr(root),PCStr(key),PCStr(name));
static const char *devlist;
static int devlist_date;
int getdevlist(PVStr(devs),int pow){
	refQStr(dp,devs);
	IStr(stat,128);
	IStr(key,128);
	IStr(val,128);
	int dn = 0;
	int di;
	static int nstat;

	if( devlist == 0 || 60 < time(0)-devlist_date ){
		for( di = 0; di < 100; di++ ){
			sprintf(key,"Drivers\\Active\\%02d",di);
			clearVStr(val);
			getRegValue(AVStr(stat),AVStr(val),
				"HKEY_LOCAL_MACHINE",key,"Name");
			if( *val ){
				Rsprintf(dp,"%s%s",devs<dp?",":"",val);
				dn++;
			}
		}
		devlist_date = time(0);
		if( devlist )
			free((char*)devlist);
		devlist = stralloc(devs);
	}
	if( pow ){
		IStr(dev,128);
		const char *sp;

		dn = 0;
		dp = devs;
		for( sp = devlist; *sp; ){
			sp = wordScanY(sp,dev,"^,");
			if( *sp == ',' )
				sp++;
			devpwstat(AVStr(stat),dev,nstat==0);
			if( *stat == '?' )
				continue;
			Rsprintf(dp,"%s %s\n",dev,stat);
			dn++;
		}
	}
	nstat++;
	return dn;
}
static char *disp_power(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);
	IStr(stat,64);
	IStr(val,128);
	const char *st;

	Rsprintf(mp,"POWER STATUS\n\n");

	mp = pingRouters(AVStr(mp));
	Rsprintf(mp,"AwakeForProxy: %s (tap here to change)\n",
		awakeIfProxyActive?"On":"Off");
	if( LastIdleReset == 0 )
		LastIdleReset = Time();

	mp = cpuUsage(AVStr(mp));

	Rsprintf(mp,"Proxy-Idle: %.1fs\n",Time()-LastIdleReset);

#if defined(UNDER_CE)
	SYSTEM_POWER_STATUS_EX2 pws2;
	syspwstat(AVStr(stat));
	Rsprintf(mp,"Status: %s\n",stat);

	GetSystemPowerStatusEx2(&pws2,sizeof(pws2),0);
	switch( pws2.ACLineStatus ){
		case AC_LINE_OFFLINE: st="Off"; break;
		case AC_LINE_ONLINE:  st="On"; break;
		case AC_LINE_BACKUP_POWER:  st="Backup"; break;
		case AC_LINE_UNKNOWN: st="Unknown"; break;
		default: st="?";
	}
	Rsprintf(mp,"ACin: %s\n",st);
	batteryStat(pws2.BatteryFlag,AVStr(stat));
	Rsprintf(mp,"Main: %d%% %s",pws2.BatteryLifePercent,stat);
	batteryStat(pws2.BackupBatteryFlag,AVStr(stat));
	if( pws2.BatteryVoltage ){
		Rsprintf(mp," %dmV",pws2.BatteryVoltage);
		if( pws2.BatteryCurrent )
		Rsprintf(mp," %dmA",pws2.BatteryCurrent);
	}
 if( 0 ){
	Rsprintf(mp,"\n");
	if( pws2.BackupBatteryLifePercent == BATTERY_PERCENTAGE_UNKNOWN )
	Rsprintf(mp,"Backup: Unknown %s\n",stat);
	else
	Rsprintf(mp,"Backup: %d%% %s\n",pws2.BackupBatteryLifePercent,stat);

	if( pws2.BatteryTemperature )
		Rsprintf(mp,"Temperature: %d\n",pws2.BatteryTemperature);
	switch( pws2.BatteryChemistry ){
		case BATTERY_CHEMISTRY_ALKALINE: st = "ALKALINE"; break;
		case BATTERY_CHEMISTRY_NICD: st = "NICD"; break;
		case BATTERY_CHEMISTRY_NIMH: st = "NIMH"; break;
		case BATTERY_CHEMISTRY_LION: st = "LION"; break;
		case BATTERY_CHEMISTRY_LIPOLY: st = "LIPOLY"; break;
		case BATTERY_CHEMISTRY_UNKNOWN: st = "UNKNOWN"; break;
	}
	Rsprintf(mp,"Type: %s\n",st);
 }
#endif

	Rsprintf(mp,"\n");

	/*
	DWORD tsec = -1;
	SystemParametersInfo(SPI_GETBATTERYIDLETIMEOUT,0,&tsec,0);
	Rsprintf(mp,"IdleToSuspend: %d\n",tsec);

	if(getRegValue(AVStr(stat),AVStr(val),"HKEY_LOCAL_MACHINE",
	 "SYSTEM\\CurrentControlSet\\Control\\Power","BattPowerOff")==0)
		Rsprintf(mp,"IdleSuspend: %s %s\n",val,stat);

	if(getRegValue(AVStr(stat),AVStr(val),"HKEY_LOCAL_MACHINE",
	 "SYSTEM\\CurrentControlSet\\Control\\Power","ScreenPowerOff")==0)
		Rsprintf(mp,"ScreenPowerOff: %s %s\n",val,stat);

	if(getRegValue(AVStr(stat),AVStr(val),"HKEY_LOCAL_MACHINE",
	 "SYSTEM\\CurrentControlSet\\Control\\Power","DisableGwesPowerOff")==0)
	  if( atoi(val) != 1 )
		Rsprintf(mp,"DisableGwesPowerOff: %s %s\n",val,stat);

	if(getRegValue(AVStr(stat),AVStr(val),"HKEY_LOCAL_MACHINE",
	 "SYSTEM\\CurrentControlSet\\Control\\Power","SystemPriority256")==0)
	  if( atoi(val) != 248 )
		Rsprintf(mp,"SystemPriority256: %s %s\n",val,stat);
	*/

	Rsprintf(mp,"\n");
	IStr(devs,2048);
	getdevlist(AVStr(devs),1);
	Rsprintf(mp,"%s\n",devs);

	// setPowerBG(1);
	// Attend / Unattend (standy mode)
	/* suspend timeout */
	/* time till suspend */
	// Wifi-power
	/* default status: sleep or suspend */

	return (char*)mp;
}

int releaseConnections(PVStr(msg));
static int _doHangup;
static int doHangup(PVStr(rstat)){
	int nrc;

	if( _doHangup == 0 )
		return 0;
	nrc = releaseConnections(BVStr(rstat));
	_doHangup = 0;
	sprintf(rstat,"(Hangup-Manually(%d))",nrc);
	return 1;
}
static void schedHangup(){
	int nact;
	nact = withActiveConnections(0);
	if( nact ){
		_doHangup = time(0);
	}
}
static int _doDialup;
static int doDialup(PVStr(rstat)){
	int nrc;

	if( _doDialup == 0 )
		return 0;
	_doDialup = 0;
	tryConnection("http://wince.delegate.org:80",BVStr(rstat));
	sprintf(rstat,"(Dialup-Manually)");
	return 1;
}
static void schedDialup(){
	int nact;
	nact = withActiveConnections(0);
	if( nact == 0 ){
		_doDialup = time(0);
	}
}

/*
setRegValue(AVStr(mp),
"HKEY_LOCAL_MACHINE","Comm\\Tcpip\\Parms","EnableDeadGwDetect","0");
setRegVal(stderr,"EnableAutodial",0);
setRegVal(stderr,"NoNetAutodial", 0);
setRegValue(AVStr(mp),"HKEY_CURRENT_USER","ControlPanel\\Wireless","WLAN","0");
*/
int RES_getnslist(PVStr(list));
int getResTrace(PVStr(trace));
char *printTcpTable(PVStr(buf));
static char *disp_nets(HWND hwnd,PVStr(mbuf)){
	refQStr(mp,mbuf);
	IStr(stat,MSGSIZE);

	Rsprintf(mp,"NETWORK STATUS\n");
	Rsprintf(mp,"\n");

	if( showTcptab ){
		mp = printTcpTable(AVStr(mp));
	}
	if( showArp ){
		char *listIpNetTab(PVStr(list),PCStr(fmt),PCStr(ipaddr));
		mp = listIpNetTab(AVStr(mp),"","");
	}
	if( RES_TRACE ){
		IStr(trace,1024);
		getResTrace(AVStr(trace));
		if( trace[0] ){
			Rsprintf(mp,"ResTrace: %s\n",trace);
		}
		IStr(dnslist,1024);
		RES_getnslist(AVStr(dnslist));
		Rsprintf(mp,"DNS: %s\n",dnslist);
	}
	if( 1 ){
		/*
		IStr(resconf,1024);
		IStr(reswh,256);
		int resrcode;
		resrcode = regGetResolvConf(AVStr(resconf),AVStr(reswh));
		Rsprintf(mp,"DNS: %s (%s) %d",resconf,reswh,resrcode);
		*/
	}
	mp = pingRouters(AVStr(mp));
	printRoutes(AVStr(mp),0,0,showallRoute,0); mp += strlen(mp);
	if( lastConn.RASconns[0] == 0 ){
		//tryRASconn(0);
	}
	if( lastConn.lc_stat[0] )
		Rsprintf(mp,"%s\n",lastConn.lc_stat);

	char *printConnMgr(PVStr(cstat),int showall,int simple,int doconn);
	printConnMgr(AVStr(mp),showallConn,0,0); mp += strlen(mp);

	if( lastConn.RASconns[0] ){
		Rsprintf(mp," RASconn: %s\n",lastConn.RASconns);
	}
	char *printNetstat(PVStr(buf));
	printNetstat(AVStr(mp)); mp += strlen(mp);

	NRefreshX = NRefresh;
	DoRefresh = 0;
	bzero(&lastlParam,sizeof(lastlParam));

	return (char*)mp;
}

static int DoRefreshMain;
static CriticalSec showstatCSC;
static int Showing;
static RECT pswrc;
static void adjMainWin(RECT swrc,HFONT normFont,HFONT miniFont){
	int shi;
	RECT mwrc;
	int wx,wy,ww,wh;

	if( fontChanged ){
		fontChanged = 0;
		if( smallFont ){
			SelectObject(dcMain,miniFont);
		}else{
			SelectObject(dcMain,normFont);
		}
		return;
	}
	if( HalfWin ){
		return;
	}
	/*
	static int prevButtonSets;
	if( buttonsSets != prevButtonSets ){
		prevButtonSets = buttonSets;
		return;
	}
	*/

	if( bcmp(&pswrc,&swrc,sizeof(RECT)) == 0 ){
		return;
	}
	shi = swrc.bottom - swrc.top;
	GetWindowRect(winMain,&mwrc);

	if( shi < ScaleY(250) || smallFont ){
		SelectObject(dcMain,miniFont);
		if( ScaleY(250) <= shi && Started == 0 ){
			wh = ScaleY(265);
		}else
		wh = swrc.bottom - swrc.top;
	}else{
		SelectObject(dcMain,normFont);
		wh = ScaleY(265);
	}
	ww = ScaleX(230);
	wx = mwrc.left;
	wy = mwrc.top;
	MoveWindow(winMain,wx,wy,ww,wh,0);
	pswrc = swrc;
}
static int AUTOHANGSEC = 180;

int dumpScreen(FILE *fp){
	int height,width;
	HDC dc;
	HDC cdc;
	FILE *lfp = 0;

	if( fp == NULL ){
		lfp = XX_fopen_FL(FL_ARG,"/DeleGate/screendump.bmp","w");
		fp = lfp;
	}

	/*
	if( scrWin == 0 ){
		scrWin = GetDesktopWindow();
	}
	RECT swrc;
	GetWindowRect(scrWin,&swrc);
	height = swrc.bottom - swrc.top;
	width = swrc.right - swrc.left;
	*/

	dc = GetDC(0);
	cdc = CreateCompatibleDC(dc);
	height = GetSystemMetrics(SM_CYSCREEN);
	//height = GetDeviceCaps(dc,VERTRES);
	width  = GetSystemMetrics(SM_CXSCREEN);
	//width = GetDeviceCaps(dc,HORZRES);

	int bsiz;
	void *data = 0;
	BITMAPINFO bi;
	BITMAPINFOHEADER *bih = &bi.bmiHeader;
	HBITMAP bm;
	HBITMAP obm = 0;

syslog_ERROR("-- dv=%d tn=%d hz=%d,%d vz=%d,%d\n",
GetDeviceCaps(dc,DRIVERVERSION),
GetDeviceCaps(dc,TECHNOLOGY),
GetDeviceCaps(dc,HORZSIZE),
GetDeviceCaps(dc,HORZRES),
GetDeviceCaps(dc,VERTSIZE),
GetDeviceCaps(dc,VERTRES)
);
int xdpi,ydpi,nbpx,ncpl;
xdpi = GetDeviceCaps(dc,LOGPIXELSX);
ydpi = GetDeviceCaps(dc,LOGPIXELSY);
nbpx = GetDeviceCaps(dc,BITSPIXEL);
ncpl = GetDeviceCaps(dc,PLANES);
syslog_ERROR("-- xp=%d yp=%d px=%d cb=%d\n",
xdpi,ydpi,nbpx,ncpl);

syslog_ERROR("-- nb=%d np=%d nf=%d nc=%d\n",
GetDeviceCaps(dc,NUMBRUSHES),
GetDeviceCaps(dc,NUMPENS),
GetDeviceCaps(dc,NUMFONTS),
GetDeviceCaps(dc,NUMCOLORS)
);

	bsiz = height * ((3*width + 3)/4)*4;
	/* getImage(dc,cdc,width,height,&bi,&data) */{
		bzero(&bi,sizeof(bi));
		bih->biSize = sizeof(BITMAPINFO);
		bih->biWidth = width;
		bih->biHeight = -height;
		bih->biPlanes = 1;
		bih->biBitCount = 24;
		bih->biCompression = BI_RGB;
		bih->biSizeImage = bsiz;

		//_Fprintf(stderr,"--dumpScreen A %d\n",memused());
		bm = CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&data,NULL,0);
		syslog_ERROR("--dumpScr bm=%X data=%X siz=%d\n",bm,data,bsiz);
		if( data == 0 ){
		}else{
		//_Fprintf(stderr,"--dumpScreen B %d data=%X\n",memused(),data);
		obm = (HBITMAP)SelectObject(cdc,bm);
		BitBlt(cdc,0,0,width,height,dc,0,0,SRCCOPY);
		}
	}
	/* dumpImage(fp,bih,data) */
	if( data ){
		BITMAPFILEHEADER bfh;
		bzero(&bfh,sizeof(bfh));
		bfh.bfType = *(WORD*)"BM";
		bfh.bfSize = sizeof(bfh) + sizeof(*bih) + bsiz;
		bfh.bfOffBits = sizeof(bfh) + sizeof(*bih);
		XX_fwrite(FL_ARG,&bfh,sizeof(bfh),1,fp);
		XX_fwrite(FL_ARG,bih,sizeof(*bih),1,fp);
		XX_fwrite(FL_ARG,data,1,bsiz,fp);
		XX_fflush_FL(FL_ARG,fp);
	}
	if( bm ){
		_Fprintf(stderr,"--dumpScreen C %d\n",memused());
		SelectObject(cdc,obm);
		DeleteDC(cdc);
		_Fprintf(stderr,"--dumpScreen D %d\n",memused());
		DeleteObject(bm);
		_Fprintf(stderr,"--dumpScreen E %d\n",memused());
		ReleaseDC(NULL,dc);
		_Fprintf(stderr,"--dumpScreen F %d\n",memused());
	}
	if( fp == lfp ){
		fflush(fp);
		fclose(fp);
	}
	return 0;
}

static HFONT miniFont;
static HFONT normFont;
static int origHeight;
static int origWidth;
static int halfWinHeight;
static void setHalfWin(HWND hwnd){
	RECT rc;
	GetWindowRect(hwnd,&rc);
	if( rc.bottom - rc.top <= halfWinHeight+1 ){
		HalfWin = 1;
	}else{
		//HalfWin = 0;
	}
}
static void toggleHalfWin(HWND hwnd,int toggle){
	static int change;
	RECT rc;
	int nw,nh;
	if( change++ == 0 ){
		if( toggle ){
			HalfWin = !HalfWin;
		}
		GetWindowRect(hwnd,&rc);
		nh = rc.bottom - rc.top;
		nw = rc.right  - rc.left;
		if( HalfWin ){
			origHeight = rc.bottom - rc.top;
			origWidth = rc.right  - rc.left;
			nh = origHeight / 2;
			nw = origWidth  / 2;
			halfWinHeight = nh;
		}else{
			if( origHeight != 0 ){
				nh = origHeight;
				nw = origWidth;
			}
		}
		MoveWindow(hwnd,rc.left,rc.top,nw,nh,0);
	}
	change--;
}
static int updateHalfWin(int *hw){
	if( winMain ){
		toggleHalfWin(winMain,0);
	}
	return 0;
}
static void activateWin(HWND hwnd){
	SetForegroundWindow(hwnd);
	BringWindowToTop(hwnd);
	ShowWindow(hwnd,SW_SHOWNA);
#if !defined(UNDER_CE)
	//SwitchToThisWindow(hwnd,0);
#endif
}
static void minimize(HWND hwnd,LPARAM lParam);
static int showstat(HWND hwnd,LPARAM lParam,int stat,PCStr(fmt),...);
int connectTimeout(int sock,PCStr(host),int port,int timeout);
int remoteWinSize(int *w,int *h){
	RECT siz;
	if( scrWin == 0 ){
		scrWin = GetDesktopWindow();
	}
	if( GetWindowRect(scrWin,&siz) ){
		*w = siz.right;
		*h = siz.bottom;
		return 0;
	}else{
		*w = 320;
		*h = 240;
		return -1;
	}
}
int remoteWinCtrl(FILE *tc,PCStr(com),PCStr(arg),int width,int height,PCStr(query),PCStr(form),PVStr(stat)){
	refQStr(sp,stat);
	int ok;
	RECT scrSiz;
	const char *pp;

	clearVStr(stat);
	if( scrWin ){
		GetWindowRect(scrWin,&scrSiz);
		sprintf(sp,"SCRSIZE=%dx%d+%d+%d; ",scrSiz.right,scrSiz.bottom,scrSiz.left,scrSiz.top);
		sp += strlen(sp);
	}
	if( winMain == 0 ){
		sprintf(sp,"%s","winMain==0");
		return -1;
	}
	if( pp = strstr(form,"win_com=") ){
		IStr(wcom,128);
		Xsscanf(pp,"win_com=%[^&]",AVStr(wcom));
		if( wcom[0] ){
IStr(rwcom,128);
URL_unescape(wcom,AVStr(rwcom),1,0);
			sprintf(sp,"win_com=%s; ",rwcom);
			sp += strlen(sp);
			if( pp = strstr(form,"win_wid=") ){
				HWND hw = 0;
				Xsscanf(pp,"win_wid=%X",&hw);
				if( hw ){
					WCHAR wclass[128];
					LRESULT ok;
					int ci,ch,vch;
					if( GetClassName(hw,wclass,elnumof(wclass)) ){
						IStr(aclass,128);
						wstrtostr(aclass,wclass,0);
						sprintf(sp,"CLASS=%s; ",aclass);
						sp += strlen(sp);
					}else{
						sprintf(sp,"CLASS=unknown; ");
					}
					for( ci = 0; ch = rwcom[ci]; ci++ ){
						ok = PostMessage(hw,WM_CHAR,ch,0);
					}
					ok = PostMessage(hw,WM_KEYDOWN,VK_RETURN,0);
					ok = PostMessage(hw,WM_KEYUP,VK_RETURN,0);
					sprintf(sp,"SentKey=%X/%d/E%d; ",hw,ok,GetLastError());
				}
			}
		}
	}
	if( strstr(form,"cmd=Reset") ){
	}else
	if( streq(com,"screen/click")
	 || strcasestr(form,"&x=") && strcasestr(form,"&y=")
	){
		HWND ccwh;
		HWND cwh;
		HWND pwh;
		POINT pt;
		WCHAR wtxt[128];
		IStr(txt,128);
		WCHAR wclass[128];
		IStr(aclass,128);
		DWORD tid;
		DWORD pid;
		LPARAM lpa;
		RECT rc;
		IStr(queryb,128);

		if( query == 0 && strcasestr(form,"&x=") ){
			const char *dp;
			int x = 0,y = 0;
			if( dp = strcasestr(form,"&x=") ) x = atoi(dp+3);
			if( dp = strcasestr(form,"&y=") ) y = atoi(dp+3);
			sprintf(queryb,"%d,%d",x,y);
			query = queryb;
		}
		if( scrWin && query){
			sscanf(query,"%d,%d",&pt.x,&pt.y);
sprintf(sp,"SIZE=%dx%d/%dx%d; ",scrSiz.right,scrSiz.bottom,width,height);
sp += strlen(sp);
			pt.x = (pt.x * scrSiz.right  ) / width; 
			pt.y = (pt.y * scrSiz.bottom ) / height; 
			sprintf(sp,"POINT=%d,%d; ",pt.x,pt.y);
			sp += strlen(sp);
			cwh = WindowFromPoint(pt);
			if( ccwh = ChildWindowFromPoint(cwh,pt) )
			if( ccwh != cwh ){
				if( GetClassName(cwh,wclass,elnumof(wclass)) ){
					wstrtostr(aclass,wclass,0);
				}
				GetWindowRect(cwh,&rc);
				sprintf(sp,"CWID=%X/%d,%d{%s}; ",ccwh,rc.left,rc.top,aclass);
				sp += strlen(sp);
			}
			if( GetClassName(cwh,wclass,elnumof(wclass)) ){
				wstrtostr(aclass,wclass,0);
				sprintf(sp,"CLASS=%s; ",aclass);
				sp += strlen(sp);
			}
if( tid = GetWindowThreadProcessId(cwh,&pid) ){
	sprintf(sp,"WINPID=%d/%d; ",pid,tid);
	sp += strlen(sp);
}
			GetWindowText(cwh,wtxt,elnumof(wtxt));
			wstrtostr(txt,wtxt,0);
			activateWin(cwh);

	GetWindowRect(cwh,&rc);
	sprintf(sp,"chld(%d,%d) ",rc.left,rc.top);
	sp += strlen(sp);

if( 0 ){
	lpa = MAKELPARAM(pt.x,pt.y);
	ok = PostMessage(scrWin,WM_LBUTTONDOWN,MK_LBUTTON,lpa);
	ok = PostMessage(scrWin,WM_LBUTTONUP,MK_LBUTTON,lpa);
}
	if( pwh = GetParent(cwh) ){
		HWND wh;
		RECT prc;
		for( wh = cwh; pwh = GetParent(wh); wh = pwh ){
			GetWindowRect(pwh,&prc);
			sprintf(sp,"prnt=%X(%d,%d); ",pwh,prc.left,prc.top);
			sp += strlen(sp);
		}
	}else{
		if( streq(aclass,"HHTaskBar")
		 || streq(aclass,"MNU")
		){
		}else{
			pt.y -= scrSiz.top; /* is not zero on WinCE */
		}
	}
	rc.left = pt.x - rc.left;
	rc.top = pt.y - rc.top;
	if( rc.top < 0 ){
		/* maybe to the title bar of WinCE */
	}else{
		lpa = MAKELPARAM(rc.left,rc.top);
		if( strstr(form,"btn_mode=down") ){
			ok = PostMessage(cwh,WM_LBUTTONDOWN,MK_LBUTTON,lpa);
			sprintf(sp,"BTN=down; "); sp += strlen(sp);
		}else
		if( strstr(form,"btn_mode=up") ){
			ok = PostMessage(cwh,WM_LBUTTONUP,MK_LBUTTON,lpa);
			sprintf(sp,"BTN=up; "); sp += strlen(sp);
		}else{
			ok = PostMessage(cwh,WM_LBUTTONDOWN,MK_LBUTTON,lpa);
			ok = PostMessage(cwh,WM_LBUTTONUP,MK_LBUTTON,lpa);
			if( strstr(form,"btn_mode=double") ){
				ok = PostMessage(cwh,WM_LBUTTONDOWN,MK_LBUTTON,lpa);
				ok = PostMessage(cwh,WM_LBUTTONUP,MK_LBUTTON,lpa);
				sprintf(sp,"BTN=double; "); sp += strlen(sp);
			}
		}
	}

			sprintf(sp,"COORD=%s; XY=%d,%d; WINDOWID=%X; TITLE=%s",
				query?query:"",rc.left,rc.top,cwh,txt);
		}
	}else
	if( strtailstr(com,"/alt.html")  || strstr(form,"cmd=Alt") ){
		++buttonSets;
		switchButtons();
	}else
	if( strtailstr(com,"/home.html") || strstr(form,"cmd=Home") ){
		home_disp(winMain,0);
	}else
	if( strtailstr(com,"/next.html") || strstr(form,"cmd=Next") ){
		next_disp(winMain,0);
	}else
	if( strtailstr(com,"/prev.html") || strstr(form,"cmd=Prev") ){
		prev_disp(winMain,0);
	}else
	if( strtailstr(com,"/small.html") || strstr(form,"cmd=Small") ){
		toggleHalfWin(winMain,1);
	}else
	if( strtailstr(com,"/mini.html") || strstr(form,"cmd=Minimize") ){
		ShowWindow(winMain,SW_MINIMIZE);
	}else
	if( strstr(form,"cmd=Normal") ){
		activateWin(winMain);
		sprintf(sp,"cmd=Normal; WINDOWID=%X",winMain);
	}else
	if( strtailstr(com,"/hide.html") || strstr(form,"cmd=Hide") ){
		ShowWindow(winMain,SW_HIDE);
	}else
	if( strtailstr(com,"/show.html") || strstr(form,"cmd=Show") ){
		activateWin(winMain);
	}else
	if( strstr(form,"cmd=Network") ){
		NRefresh = DISP_NETS;
	}else
	if( strstr(form,"cmd=Power") ){
		NRefresh = DISP_POWER;
	}else
	if( strstr(form,"cmd=Proxy") ){
		NRefresh = DISP_PROXY;
	}else
	if( strstr(form,"cmd=Access") ){
		NRefresh = DISP_AUTH;
	}else
	if( strstr(form,"cmd=Process") ){
		NRefresh = DISP_PROCESS;
	}else
	if( strstr(form,"cmd=Install") ){
		NRefresh = DISP_INSTALL;
	}else
	if( strstr(form,"cmd=Idle") || strstr(form,"cmd=PowerSave") ){
		inIdle = 1;
		setsyspower("IDLE",0,0);
	}else
	if( strstr(form,"cmd=Active") ){
		inIdle = 0;
		setsyspower("ACTIVE",0,0);
	}else
	if( strstr(form,"cmd=ConnTest") ){
		NRefresh = DISP_NETS;
	}else
	if( strstr(form,"cmd=DnsTest") ){
		NRefresh = DISP_NETS;
	}else
	if( strstr(form,"cmd=DialUp") ){
		schedDialup();
		doDialup(AVStr(sp));
		NRefresh = DISP_NETS;
	}else
	if( strstr(form,"cmd=HangUp") ){
		schedHangup();
		doHangup(AVStr(sp));
		NRefresh = DISP_NETS;
	}else
	if( strstr(form,"cmd=FontSize") ){
		smallFont = !smallFont;
		fontChanged++;
		sprintf(sp,"smallFont=%d",smallFont);
	}else
	if( strstr(form,"cmd=Refresh") ){
	}else
	{
		sprintf(sp,"Unknown Command\n");
	}
	ok = UpdateWindow(winMain);
	showstat(winMain,0,1,"");
/*
sp += strlen(sp);
sprintf(sp,"\n{com=%s; form=%s}",com,form);
*/
	return 0;
}
static int showstat(HWND hwnd,LPARAM lParam,int stat,PCStr(fmt),...){
	RECT rc;
	static int pw,ph;
	IStr(msg,MSGSIZE);
	refQStr(mp,msg);
	WCHAR wmsg[1024];
	VARGS(8,fmt);
	IStr(arg,256);
	RECT swrc;
	RECT wrc;
	int zx = 240-5;
	HBRUSH bbg;
	COLORREF BGC;
	int showing;
	int dorefresh = 0;
	LPARAM lparam = lastlParam;

	if( winReady == 0 ){
		return -1;
	}
	updateWinTytle(hwnd);
	/*
	if( 2 <= Terminating ){
		return -1;
	}
	*/
	if( LastIdleReset == 0 ){
		LastIdleReset = Time();
	}
	int actconn;
	if( AUTOHANGUP )
	if( AUTOHANGSEC < Time()-LastIdleReset )
	if( actconn = withActiveConnections(0) )
	{
		releaseConnections(AVStr(mp));
		sprintf(mp,"HangUp/Auto(%ds)",AUTOHANGSEC);
		strcpy(lastConn.lc_stat,mp);

		/*
		fmt = "%s";
		sprintf(arg,"ProxyIdle=%.1f ActiveConn=%d",
			Time()-LastIdleReset,actconn);
		va[0] = arg;
		NRefresh = 1;
		withActiveConnections(1);
		*/
	}

	setupCSC("showstat",showstatCSC,sizeof(showstatCSC));
	enterCSC(showstatCSC);
	if( (showing = Showing) == 0 )
		Showing++;
	leaveCSC(showstatCSC);
	if( showing ){
		return -1;
	}

	if( dcMain == 0 ){
		dcMain = GetDC(hwnd);
		SetBkColor(dcMain,WBGC);
	}
	if( wbbg == 0 ){
		wbbg = CreateSolidBrush(WBGC);
		ybbg = CreateSolidBrush(YBGC);
		xbbg = CreateSolidBrush(XBGC);
		zbbg = CreateSolidBrush(ZBGC);
		rbbg = CreateSolidBrush(RBGC);
		gbbg = CreateSolidBrush(GBGC);
		bbbg = CreateSolidBrush(BBGC);
	}
	SetBkColor(dcMain,WBGC);
	if( 1 < Terminating ){
		bbg = xbbg;
		BGC = XBGC;
	}else{
		bbg = ybbg;
		BGC = YBGC;
	}

	if( scrWin == 0 ){
		scrWin = GetDesktopWindow();
	}
	if( GetWindowRect(hwnd,&wrc) != ERROR ){
		static RECT pwrc;
		winHeight = wrc.bottom - wrc.top;
		winWidth = wrc.right - wrc.left;
		if( bcmp(&pwrc,&wrc,sizeof(RECT)) != 0 ){
			syslog_ERROR("--WinSize %d x %d [%d,%d][%d,%d]\n",
				winWidth,winHeight,
				wrc.left,wrc.top,wrc.right,wrc.bottom
			);
		}
		pwrc = wrc;
		zx = wrc.right - 5;
		if( HalfWin ){ /* ???? space for control bar ? */
			//winHeight -= PMLH;
			winHeight -= ScaleY(30);
		}
	}
	if( cdcMain == 0 && myMark != 0 ){
		HGDIOBJ gdio;
		cdcMain = CreateCompatibleDC(NULL);
		gdio = SelectObject(cdcMain,myMark);
		_Fprintf(stderr,"-- select %X %X %d %d\n",cdcMain,myMark,
			gdio,GetLastError());
	}

static LOGFONTW normFontb;
static int fErr1 = 0;
static int fErr2 = 0;

	if( dcMain && miniFont == 0 ){
		HGDIOBJ gdio;
		LOGFONTW logf;

	normFont = (HFONT)GetCurrentObject(dcMain,OBJ_FONT);
	if( GetObject(normFont,sizeof(logf),&logf) ){
		DeleteObject(normFont);
		//logf.lfWeight = FW_MEDIUM;
		logf.lfWeight = FW_THIN;
		//logf.lfPitchAndFamily = FF_SCRIPT|FIXED_PITCH;
/*
		logf.lfPitchAndFamily =
(logf.lfPitchAndFamily&0xF0) | FIXED_PITCH;
*/
		normFont = CreateFontIndirect(&logf);
	}

		bzero(&logf,sizeof(logf));
		logf.lfWeight = FW_MEDIUM;
		logf.lfPitchAndFamily = FIXED_PITCH;
		logf.lfHeight = -HIDPIMulDiv(6,g_HIDPI_LogPixelsY,72);

		SetLastError(0);
		miniFont = CreateFontIndirect(&logf);
		fErr1 = GetLastError();
		if( fErr1 ){
			logf.lfHeight = 0;
			SetLastError(0);
			miniFont = CreateFontIndirect(&logf);
			fErr1 = GetLastError();
		}

		if( miniFont == INVALID_HANDLE_VALUE ){
		}else{
			SetLastError(0);
			fErr2 = GetLastError();
		}
	}
	if( scrWin && miniFont && normFont ){
		if( GetWindowRect(scrWin,&swrc) != ERROR ){
			adjMainWin(swrc,normFont,miniFont);
		}
	}
	if( 1 < Terminating ){
		SelectObject(cdcMain,myMarkX);
	}
	placeButtons(hwnd);
	switchButtons();
	if( DoRefreshMain ){
		stat = 1; /* force refresh of the displayed text */
		clearVStr(prevmsg);
		DoRefreshMain = 0;
	}

	if( stat ){
	    if( Terminating < 2 ){
		if( fErr1 ){
			Rsprintf(mp,"FONT: %X Err=(%d %d)\n",
				miniFont,fErr1,fErr2);
		}
		if( NRefresh % NDISP != 0 ){
			Rsprintf(mp,"%d) ",NRefresh % NDISP);
		}
pingRouters(AVStr(mp));
		switch( NRefresh % NDISP ){
			case DISP_HOME:
				//setPowerBG(0);
				mp = disp_main(hwnd,AVStr(mp));
				break;
			case DISP_NETS:
				//setPowerBG(1);
				mp = disp_nets(hwnd,AVStr(mp));
				break;
			case DISP_POWER:
				//setPowerBG(1);
				mp = disp_power(hwnd,AVStr(mp));
				break;
			case DISP_PROXY:
				//setPowerBG(0);
				Rsprintf(mp,"PROXY STATISTICS\n\n");
				mp = cpuUsage(AVStr(mp));
				makeMssg(TVStr(msg),1);
				mp = disp_proxy(hwnd,AVStr(mp));
				break;
			case DISP_AUTH:
				mp = disp_auth(hwnd,AVStr(mp));
				break;
			case DISP_PROCESS:
				//setPowerBG(0);
				mp = disp_procs(hwnd,AVStr(mp));
				break;
			case DISP_INSTALL:
				//setPowerBG(0);
				dorefresh = DoRefresh;
				mp = disp_install(hwnd,AVStr(mp));
				break;
		}
		if( doHangup(AVStr(mp)) ){
			strcpy(lastConn.lc_stat,mp);
		}
		if( doDialup(AVStr(mp)) ){
			strcpy(lastConn.lc_stat,mp);
		}
		if( Terminating ){
			Rsprintf(mp,"\n\n");
			if( fmt ){
				Rsprintf(mp,fmt,VA8);
			}
		}
		if( scrWin ){
			if( GetWindowRect(scrWin,&swrc) != ERROR ){
				/*
				Rsprintf(mp,"SCR(%d %d %d %d)",
				swrc.left,swrc.top,swrc.right,swrc.bottom);
				*/
			}
			/*
			Rsprintf(mp,"WIN(%d %d %d %d)",
				wrc.left,wrc.top,wrc.right,wrc.bottom);
			*/
		}
		if( 1 < stat
		 || !streq(msg,prevmsg) || pw != winWidth || ph != winHeight ){
			strtowstr(wmsg,msg,0);
			SetRect(&rc,0,0,winWidth,winHeight-PMLH);
			FillRect(dcMain,&rc,wbbg);
			SetRect(&rc,PWSP,PWSP,zx,winHeight-PMLH);
			if( textNoWrap )
				DrawText(dcMain,wmsg,-1,&rc,0);
			else	DrawText(dcMain,wmsg,-1,&rc,DT_WORDBREAK);
/*
			if( NRefresh % NDISP == DISP_INSTALL )
				DrawText(dcMain,wmsg,-1,&rc,0);
			else	DrawText(dcMain,wmsg,-1,&rc,DT_WORDBREAK);
*/
			strcpy(prevmsg,msg);
			pw = winWidth;
			ph = winHeight;

			DrawFocusRect(dcMain,&altsRect);
			if( 1 ){
				DrawFocusRect(dcMain,&menuRect);
				DrawFocusRect(dcMain,&homeRect);
				DrawFocusRect(dcMain,&nextRect);
				DrawFocusRect(dcMain,&prevRect);
			}
		}
	    }
	    if( NRefresh % NDISP == 0 ){
		if( cdcMain ){
			if( 1 < Terminating ){
				TerminatingX++;
			}else
			if( Nfrogs < 4 ){
				if( Nfrogs % 2 == 0 )
					SelectObject(cdcMain,myMarkX);
				else	SelectObject(cdcMain,myMark);
			}
			StretchBlt(dcMain,
				winWidth - ScaleX(80 - 5*TerminatingX),
				winHeight - PMLH - PBTH - ScaleY(64),
				ScaleX(96),ScaleY(96),
				cdcMain,0,0,64,64,SRCCOPY);
			Nfrogs++;
		}
	    }
	}

	//if( !Terminating )
	{
		SetRect(&rc,0,winHeight-PMLH,winWidth,winHeight);
		FillRect(dcMain,&rc,bbg);
		if( fmt ){
			mp = msg;
			if( Terminating == 0 ){
				Rsprintf(mp,"(%.2f)",Time()-MainStart);
			}
			if( dorefresh ){
				int xpos,ypos;
				xpos = LOWORD(lparam);
				ypos = HIWORD(lparam);
				Rsprintf(mp,"[%d,%d]",xpos,ypos);
			}
			Rsprintf(mp," ");
			Rsprintf(mp,fmt,VA8);
			strtowstr(wmsg,msg,0);
			SetBkColor(dcMain,BGC);
			DrawText(dcMain,wmsg,-1,&rc,DT_WORDBREAK);
		}
	}
	Mini1 = 0;
	if( !Terminating ){
		updateActiveLamp(0);
	}
	redrawButtons();
	UpdateWindow(hwnd);
	if( fmt != NULL && *fmt == '?' ){
		IStr(msg,1024);
		sprintf(msg,fmt,VA8);
		askWinOK("%s",msg);
	}
	reconnect();

	Showing = 0;
	return 0;
}
static int NputWS;
static void setupDGMark();
void send_syslogX(PCStr(lclass),PCStr(log));
extern int eccActivity;

void putWinStatus(PCStr(fmt),...){
	MEMORYSTATUS mstt;
	GlobalMemoryStatus(&mstt);
	if( mstm.dwAvailPhys == 0 || mstt.dwAvailPhys < mstm.dwAvailPhys ){
		mstm = mstt;
	}

	if( resettick.r_nwritten < resettick.r_notify*3 )
	if( resettick.r_notifytck+1000 < GetTickCount() )
	{
		syslog_ERROR("## Time Reset %d/%d %d/%d (%d+%d/%d/%d)\n",
			resettick.r_nwritten,
			resettick.r_notify*3,
			resettick.r_diffsec,
			resettick.r_difftck,
			resettick.r_reset,
			resettick.r_noreset,
			resettick.r_tested,
			resettick.r_checked
		);
		resettick.r_nwritten++;
		/* maybe resumed, should check devices and sockets */
	}

	/*
	if( Terminating ){
		return;
	}
	*/
	if( inIdle ){
		resetIdleTimer();
	}
	else
	if( eccActivity ){
		eccActivity = 0;
		resetIdleTimer();
	}
	if( Started == 0 && strstr(fmt,"Running") ){
		Started = time(0);
		RES_TRACE = 0;
	}
	if( !Terminating ){
		if( Mini1 ){
			Mini1 = 0;
			return;
		}
	}
	if( winMain ){
		VARGS(8,fmt);
		if( 1 < NputWS++ ){
			setupDGMark();
		}
		if( strstr(fmt,"Rejected") ){
			NRefresh = DISP_AUTH;
		}
		showstat(winMain,0,1,fmt,VA8);

if(0)//this is very slow
		if( File_is("/DeleGate/restart") ){
			FILE *fp;
			unlink("/DeleGate/restart");
			rmdir("/DeleGate/restart");
			if( fp = fopen("/DeleGate/restarted.txt","w") ){
				fprintf(fp,"%f",Time());
				fclose(fp);
			}
		}
	}
/*AAAA
	if( PowerOff ){
		refreshWinStatus = 1;
		if( PowerOff <= Time() ){
			PowerOff = 0;
			SetSystemPowerState(0,POWER_STATE_SUSPEND,0);
		}
	}
*/
}
                
const char *dump_builtin_data(PCStr(name),PVStr(path));
char *WinDGMark ="builtin/icons/ysato/frog9RT.bmp";
char *WinDGMarkX ="builtin/icons/ysato/frog9L.bmp";
static void setupDGMark(){
	IStr(path,1024);
	WCHAR wpath[1024];

	if( myMark != 0 )
		return;
	strcpy(path,"");
	if( dump_builtin_data(WinDGMark,AVStr(path)) ){
		strtowstr(wpath,path,0);
		myMark = SHLoadDIBitmap(wpath);
		_Fprintf(stderr,"MyMark: %X %s\n",myMark,path);
		strcpy(path,"");
		if( dump_builtin_data(WinDGMarkX,AVStr(path)) ){
			strtowstr(wpath,path,0);
			myMarkX = SHLoadDIBitmap(wpath);
		}
	}else{
		_Fprintf(stderr,"Cant-Get MyMark: %s\n",path);
	}
}

static int terminate(HWND hwnd,LPARAM lParam){
	IStr(ans,128);
	if( Terminating ){
		return 0;
	}
	Terminating = 1;
	UpdateWindow(hwnd);
	showstat(hwnd,lParam,0,"** Terminate ?");
	getAnswerYN("Terminate?",AVStr(ans),sizeof(ans));
	if( ans[0] != 'y' ){
		Terminating = 0;
		UpdateWindow(hwnd);
		showstat(hwnd,lParam,0,"");
		return 0;
	}

	UpdateWindow(hwnd); // to repair the area overwritten by MessageBox()
	showstat(hwnd,lParam,1,"** Terminating (%d)...",actthreads());
	THEXIT = THEX_DO;
	Terminating = 2;
	return 0;
}
static void home_disp(HWND hwnd,LPARAM lParam){
	if( NRefresh == DISP_HOME ){
		NRefresh = PrevNRefresh;
	}else{
		PrevNRefresh = NRefresh;
	NRefresh = DISP_HOME;
	}
	UpdateWindow(hwnd);
	showstat(hwnd,lParam,1,"NRefresh=%d",NRefresh);
}
static void minimize(HWND hwnd,LPARAM lParam){
	if( Mini1 ){
		showstat(hwnd,lParam,0,"** Minimizing ...");
			ShowWindow(hwnd,SW_MINIMIZE);
	}else{
		showstat(hwnd,lParam,0,"Push once more to Minimize");
		Mini1++;
	}
}
static void next_disp(HWND hwnd,LPARAM lParam){
	if( NRefresh == 0 ){
		setupDGMark();
	}
	NRefresh++;
	Stats++;
	if( winPrev ){
		showstat(hwnd,lParam,1,"");
	}
}
static void prev_disp(HWND hwnd,LPARAM lParam){
	NRefresh += (NDISP - 1);
	UpdateWindow(hwnd);
	showstat(hwnd,lParam,1,"");
}
static int wcb;
LRESULT CALLBACK WndProc(HWND hwnd,UINT umsg,WPARAM wParam,LPARAM lParam){
	int rcode;

	wcb++;
	switch( umsg ){
	  case WM_DESTROY:
		if( dbgWin ) askWinOK("??? %X WndProc DESTROY",TID);
		PostQuitMessage(0); /* break the loop of GetMessage() */
		return 0;
	}
	if( Terminating ){
		rcode = DefWindowProc(hwnd,umsg,wParam,lParam);
		return rcode;
	}
	if( umsg == WM_LBUTTONDOWN ){
		syslog_ERROR("--LBUTTONDOWN wid=%X (%d,%d)\n",
			hwnd,lParam&0xFFFF,(lParam>>16)&0xFFFF);
	}
	switch( umsg ){
	  case WM_CTLCOLORBTN:
		break;
	  case WM_CREATE:
		setupMainWin(hwnd,wParam,lParam);
		return 0;

	  case WM_PAINT:
		break;

	  case WM_CLOSE:
		/*
		if( hwnd == winMain ){
			//winMain = 0;
			DestroyWindow(winMain);
		}
		*/
		terminate(hwnd,lParam);
		return 0;

	  case WM_DESTROY:
		//winMain = 0;
		return 0;
	/*
	  case WM_ENABLE:
	  case WM_MOVING:
	  case WM_MOVE:
	*/
	  case WM_SIZE:
		setHalfWin(hwnd);
		switch( (int)wParam ){
			case SIZE_MAXIMIZED: HalfWin = 0; break;
			case SIZE_MINIMIZED:
			case SIZE_RESTORED:
			case SIZE_MAXSHOW:
			case SIZE_MAXHIDE: break;
		}
	  case 0x006:
	  case 0x007:
	  case 0x008:
	  case 0x014:
	  case 0x086:
	  case 0x281:
	  case 0x282:
	  case 0x30F:
	  case WM_WINDOWPOSCHANGED:
setHalfWin(hwnd);
		DoRefreshMain++;
		refreshWinStatus = 1;
		break;
	  case WM_KEYDOWN:
		return 0;
	  case WM_KEYUP:
		showstat(hwnd,lParam,2,0);
		return 0;
	  case WM_COMMAND:
		switch( (int)wParam ){
		  case MENU_SET_TO_DEFAULT:
		  case MENU_DUMP_SCREEN:
		  case MENU_WIN_HALF:
		  case MENU_TERMINATE:
		  case MENU_ADD_STARTMENU:
		  case MENU_ADD_STARTUP:
		  case MENU_AWAKE_FORPROXY:
		  case MENU_POWER_OFF:
		  case MENU_POWER_REBOOT:
		  case MENU_POWER_RESET:
		  case MENU_POWER_IDLE:
		  case MENU_POWER_SUSPEND:
		  case MENU_PAUSE:
		  case MENU_SHOW_TCPTAB:
		  case MENU_SHOW_ARPTAB:
		  case MENU_SHOW_ALLROUTE:
		  case MENU_SHOW_ALLCONN:
		  case MENU_PING_ROUTERS:
		  case MENU_TRACE_RESOLVER:
		  case MENU_TRACE_CONNMGR:
		  case MENU_AUTODIAL_TCP:
		  case MENU_AUTODIAL_UDP:
		  case MENU_AUTODIAL_DNS:
		  case MENU_AUTOHANGUP:
		  case MENU_HANGUP:
		  case MENU_DIALUP:
		  case MENU_SMALLFONT:
		  case MENU_TEXT_NOWRAP:
		  case MENU_BUTTONSETS:
		  case MENU_CACHE:
		  case MENU_SYSLOG:
		  case MENU_IMMREJECT:
		  case MENU_ACCEPT_WIFIONLY:
		  case MENU_ACCEPT_PCONLY:
		  case MENU_AUTH_PROXY:
		  case MENU_AUTH_PST:
		  case MENU_AUTH_CLEAR_MEMORY:
		  case MENU_AUTH_CLEAR_FILE:
			actNetMenu(hwnd,umsg,wParam,lParam);
			refreshWinStatus = 1;
			return 0;
		  case iBUTTON_MENU:
			popupMenu(hwnd,lParam,umsg);
			return 0;
		  case iBUTTON_TERMIN:
			terminate(hwnd,lParam);
			return 0;
		  case iBUTTON_ALTS:
			++buttonSets;
			switchButtons();
			return 0;
		  case iBUTTON_HOME:
			home_disp(hwnd,lParam);
			return 0;
		}
		break;

	case WM_LBUTTONDOWN:
	//case WM_0x282:
		if( winPrev ){
			popupMenu(hwnd,lParam,umsg);
			DoRefresh = NRefresh;
			refreshWinStatus = 1;
			ItemX++;
			lastwParam = wParam;
			lastlParam = lParam;
		}
		break;

	  default:
/*
if( START_TIME )
_Fprintf(stderr,"-- %X #%d R%d %3d um=%-8X %-8d\n",
	TID,wcb,DoRefreshMain,Stats,umsg,umsg);
*/
/*
 if( Stats )
 _Fprintf(stderr,"-- %X %3d um=%-8X %-8d\n",TID,Stats,umsg,umsg);
*/
		break;
	}
	rcode = DefWindowProc(hwnd,umsg,wParam,lParam);

	switch( umsg ){
	  case WM_ERASEBKGND:
		Clear++;
		if( winPrev ){
			showstat(hwnd,lParam,2,0);
		}
		break;
	  case WM_COMMAND:
		switch( (int)wParam ){
		  case iBUTTON_NEXT:
			next_disp(hwnd,lParam);
			return 0;
		  case iBUTTON_PREV:
			prev_disp(hwnd,lParam);
			return 0;
		  case iBUTTON_MINIMZ:
			minimize(hwnd,lParam);
			return 0;
		}
		break;
	}
	return rcode;
}
BOOL InitInstance(HINSTANCE hInstance,int iCmdShow){
	int ws;

	g_hInst = hInstance;

	if( 0 ){
		ws = WS_SIZEBOX;
		ws |= WS_SYSMENU;
		ws |= WS_MINIMIZEBOX;
		ws |= WS_MAXIMIZEBOX;
	}else{
		//ws = WS_OVERLAPPEDWINDOW;
		ws = WS_OVERLAPPED;
		//ws |= WS_THICKFRAME;
		ws |= WS_SYSMENU;
		ws |= WS_MINIMIZEBOX;
		ws |= WS_MAXIMIZEBOX;
	}

	/*
	if( win_init.wi_iconic ){
		ws |= WS_ICONIC;
	}
	*/
	if( win_init.wi_disabled ){
		ws |= WS_DISABLED;
	}
	if( win_init.wi_hide ){
		iCmdShow = SW_MINIMIZE;
	}

RECT swrc;
scrWin = GetDesktopWindow();
GetWindowRect(scrWin,&swrc);

int width = PWW;
int height = PWH;

int shi = swrc.bottom - swrc.top;
if( shi < height ) height = shi;

//ws |= WS_VSCROLL;

	winMain = CreateWindow(
		winClassName,   // Registered class name         
		winTitle,       // Application window name
		ws,             // Window style
		CW_USEDEFAULT,  // Horizontal position of the window
		CW_USEDEFAULT,  // Vertical position of the window
		width,          // Window width
		height,         // Window height
		NULL,           // Handle to the parent window
		NULL,           // Handle to the menu identifier
		hInstance,      // Handle to the application instance
		NULL);          // Pointer to the window-creation data

	// If it failed to create the window, return FALSE.
	if (!winMain)
		return FALSE;

	ShowWindow(winMain,iCmdShow);
	/*
	UpdateWindow(winMain);
	*/
	return TRUE;
}
BOOL InitApplication(HINSTANCE hInstance){
	WNDCLASS wndclass;
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = (WNDPROC)WndProc;
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hIcon = NULL;
	wndclass.hInstance = hInstance;
	wndclass.hCursor = NULL;
	if( isWindowsCE() ){
		wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	}else{
		wndclass.hbrBackground = NULL;
	}
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = winClassName;
	return RegisterClass (&wndclass);
}
void WinMainLoop(HINSTANCE ci,HINSTANCE pi,int ics){
	MSG msg; // Message structure
	HACCEL hAccel = 0;
	int ok;
	HWND wnd;

	setthreadgid(0,getthreadid());

	//if( pi == 0 )
	{
		ok = InitApplication(ci);
	}
	ok = InitInstance(ci,ics);
	while( GetMessage(&msg,NULL,0,0) ){
		/*
		if( !TranslateAccelerator(winMain,hAccel,&msg) ){
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		*/
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	if( dbgWin ) askWinOK("??? %X MainLoop Exit: %X",TID,winMain);
	if( wnd = winMain ){
		winMain = 0;
		DestroyWindow(wnd);
	}
}
static void updateMainWindow(){
	DoRefreshMain++;
	refreshWinStatus = 1;
	if( winMain ){
		UpdateWindow(winMain);
	}
}
static int winThread;
static void destroyMainWin(int code,const char *fmt,...){
	if( winMain ){
		double St = Time();
		int oact = actthreads();
		int nact;
		VARGS(16,fmt);
		/*
		if( winHome ) DestroyWindow(winHome);
		if( winPrev ) DestroyWindow(winPrev);
		if( winNext ) DestroyWindow(winNext);
		*/
		if( dbgWin ) askWinOK("??? %X destroyMainWin-1",TID);
		if( winMain ){
			showstat(winMain,0,1,fmt,VA16);
			DestroyWindow(winMain);
			winMain = 0;
		}
		if( dbgWin ) askWinOK("??? %X destroyMainWin-2",TID);
		//PostQuitMessage(0); /* break the loop of GetMessage() */
		if( winThread ){
			int err;
	if( dbgWin ) askWinOK("??? %X waiting destroyed %.2f",TID,Time()-St);
			err = thread_wait(winThread,30*1000);
			_Fprintf(stderr,"terminated winThread: %d %X\n",
				err,winThread);
			nact = actthreads();
	if( dbgWin ) askWinOK("%X waiting %X = %d %.2f (%d >>> %d)",TID,
				winThread,err,Time()-St,oact,nact);
		}
		if( dbgWin ) askWinOK("??? %X destroyed %.2f",TID,Time()-St);
	}else{
		if( dbgWin ) askWinOK("??? %X NO destroyMainWin-0",TID);
	}
}
static void winmainloop(HINSTANCE ci,HINSTANCE pi,int ics){
	if( win_init.wi_none ){
		return;
	}
	HIDPI_InitScaling();
	winThread =
	thread_fork(0x40000,0,"MainWin",(IFUNCP)WinMainLoop,ci,pi,ics);
}
static int winrestart(HINSTANCE ci,HINSTANCE pi,int ics){
	int ri;
	HWND win;

	if( win = FindWindow(winClassName,winTitle) ){
		//SetForegroundWindow(FindWindow(winClassName,winTitle));
		activateWin(win);
		return 1;
	}else{
		winmainloop(ci,pi,ics);
		for( ri = 0; ri < 20; ri++ ){
			if( winHome ){
				break;
			}
			Sleep(200);
		}
		return 0;
	}
}
#else
static void winmainloop(HINSTANCE ci,HINSTANCE pi,int ics){
}
static int winrestart(HINSTANCE ci,HINSTANCE pi,int ics){
	return 0;
}
void putWinStatus(PCStr(fmt),...){
}
void setWinClassTitleStyle(PCStr(wclass),PCStr(wtitle),PCStr(wstyle)){
}
#endif /*}DGWIN*/

#include <Winuser.h>
extern double LastIdleReset;
void resetIdleTimer(){
	LastIdleReset = Time();
	if( awakeIfProxyActive ){
		SystemIdleTimerReset();
	}
}

#endif /*}*/
