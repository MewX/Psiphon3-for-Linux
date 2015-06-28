/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2004-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	ystring.c (boundary checkiing string manipulation)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	041107	created

TODO:
	strlen() should not be used to avoid read-overrun
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#if defined(_MSC_VER) && defined(UNDER_CE)
static int Igetc(FILE *fp){ return getc(fp); }
char *strdup(const char*);
FILE *fdopen(int,const char*);
#endif

const char *MyVer = "";

#if defined(FMT_CHECK) /*{*/
#define daemonlog(wh,fmt,...)  fprintf(stderr,fmt,##__VA_ARGS__)
#define porting_dbg(fmt,...)   fprintf(stderr,fmt,##__VA_ARGS__)
#else
int daemonlog(const char *what,const char *fmt,...);
int porting_dbg(const char *fmt,...);
#endif

void Abort(int code,const char *fmt,...);
int numthreads();
int actthreads();

char *Xstrdup(const char *F,int L,int pstm,const char *s){
	char *mp;
	mp = strdup(s);
	if( mp == NULL ){
		Abort(0,"FAILED strdup(%X) %s:%d\n",s,F,L);
	}
	else{
	}
	return mp;
}

/*
 * mutex and memory leak detection for heap area
 */
typedef struct {
    const char *a_F; /* source-file of the allocator */
	short	a_L;	/* source-line of the allocator */
	char	a_free;	/* flags */
	char	a_base;	/* is stack-base */
	int	a_z;	/* size of the area */
	void   *a_p;	/* the address of the allocated memory */
} Alloc;

static Alloc persistents[1024];
static Alloc allocs[1024];
static int allocsp;
static int lastpopend;

typedef struct {
	int  l_lid;
	int  l_tid;
	int  l_dbg;
	char l_lev;
 const char *l_wh;
 const char *l_F;
	int  l_L;
      double l_Time;
} Lock;
static Lock curLock;
static Lock noLock;
static Lock doLock_FL(const char *F,int L,const char *wh,int log);
static void unLock_FL(const char *F,int L,const char *wh,int log,Lock locked);

#ifdef __FUNCTION__
#define _WHERE_ __FUNCTION__
#else
#define _WHERE_ __FILE__
#endif
#define doLock(wh,log) locked = doLock_FL(_WHERE_,__LINE__,wh,log)
#define unLock(wh,log) unLock_FL(_WHERE_,__LINE__,wh,log,locked)
#define doLockB(wh,log) locked = doLock_FL(FL_Bar,wh,log)
#define unLockB(wh,log) unLock_FL(FL_Bar,wh,log,locked)

/*
#include <signal.h>
*/
#include "vsignal.h"
#include "ysignal.h"
static struct {
	const char *h_W;
	const char *h_F;
	int h_L;
	int h_Z;
} heapst = {"",""};
void putfLog(const char *fmt,...);
void msleep(int ms);
static void sigSEGV(int sig){
	errno = ENOMEM;
	putfLog("####got sigSEGV");
	msleep(200);
	if( 0 <= heapst.h_Z )
		Abort(0,"FATAL %s(%d) %s:%d\n",
			heapst.h_W,heapst.h_Z,heapst.h_F,heapst.h_L);
	else	Abort(0,"FATAL %s() %s:%d\n",heapst.h_W,heapst.h_F,heapst.h_L);
}
typedef void (*sigfunc)(int);
static sigfunc setsig(const char *W,const char *F,int L,int z){
	heapst.h_W = W;
	heapst.h_F = F;
	heapst.h_L = L;
	heapst.h_Z = z;
	return signal(SIGSEGV,sigSEGV);
}
int VStrSIG(){
	if( heapst.h_W && heapst.h_F ){
		putfLog("####lastSIG: %s[%d] <= %s:%d",
			heapst.h_W,heapst.h_Z,heapst.h_F,heapst.h_L);
		return 1;
	}
	return 0;
}

#define FL_Par const char *FL_F,int FL_L
#define FL_Bar FL_F,FL_L
void add_FILEY(FL_Par,const char *wh,FILE *fp);
void del_FILEY(FL_Par,const char *wh,FILE *fp);

/*
#undef tmpfile
FILE *Xtmpfile(FL_Par){
	FILE *fp;
	fp = tmpfile();
	if( fp ){
		add_FILEY(FL_Bar,"tmpfile",fp);
	}
	return fp;
}
*/

int p2iX(FL_PAR,const void *p);
#define p2i(p) p2iX(FL_ARG,p)

#if defined(_MSC_VER) && UNDER_CE
#define isWindowsCE() 1
#define isWindows() 1
int XX_fflush_FL(const char *F,int L,FILE *fp);
int XX_fclose_FL(const char *F,int L,FILE *fp);
int XX_fcloseFILE_FL(const char *F,int L,FILE *fp);
FILE *XX_fdopen_FL(const char *F,int L,int fd,const char *mode);
FILE *XX_fopen_FL(const char *F,int L,const char *path,const char *mode);
#define FL_fcloseFILE(F,L,fp) 0
#else
int FL_fcloseFILE(const char *F,int L,FILE *fp);
#define isWindowsCE() 0
#define XX_fgets(buf,siz,fp) 0
#define XX_fflush_FL(FL_P,fp) 0
#if defined(_MSC_VER)
#define isWindows() 1
int XX_fclose_FL(const char *F,int L,FILE *fp);
#else
#define isWindows() 0
#define XX_fclose_FL(FL_P,fp) 0
#endif
#define XX_fcloseFILE_FL(FL_P,fp) 0
#define XX_fdopen_FL(FL_P,fd,mode) 0
#define XX_fopen_FL(FL_P,p,m) 0
#endif

/* may block seconds for linger. */
/* fcloseFILE() under mutex + close() could be enough. */
#undef fclose
int XXfclose(FL_Par,FILE *fp){
	int rcode;
	sigfunc sig = setsig("Xfclose",FL_Bar,-1);
	Lock locked;
	SSigMask sMask; setSSigMask(sMask);
	doLockB("fclose",2);
	if( isWindows() ){
		rcode = XX_fclose_FL(FL_Bar,fp);
	}else
	rcode = fclose(fp);
	del_FILEY(FL_Bar,"fclose",fp);
	unLockB("fclose-done",2);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	return rcode;
}
#undef fcloseFILE
int XXfcloseFILE(FL_Par,FILE *fp){
	int rcode;
	sigfunc sig = setsig("XfcloseFILE",FL_Bar,-1);
	Lock locked;
	SSigMask sMask; setSSigMask(sMask);
	doLockB("fcloseFILE",2);
    if( isWindowsCE() ){
	rcode = XX_fcloseFILE_FL(FL_Bar,fp);
    }else{
	rcode = FL_fcloseFILE(FL_Bar,fp);
    }
	del_FILEY(FL_Bar,"fcloseFILE",fp);
	unLockB("fcloseFILE-done",2);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	return rcode;
}
#undef fdopen
int getthreadid();
FILE *XXfdopen(FL_Par,int fd,const char *mode){
	FILE *fp;
	sigfunc sig = setsig("Xdopen",FL_Bar,-1);
	Lock locked;
	SSigMask sMask; setSSigMask(sMask);
	doLockB("fdopen",2);
	if( isWindowsCE() ){
		fp = XX_fdopen_FL(FL_Bar,fd,mode);
		if( fp ){
int nfd;
nfd = (int)fileno(fp);
if( fd != nfd ){
fprintf(stderr,"-- %X fdopen %d -> %d/%d/%X <= %s:%d --------------------\n",
0xFFF&getthreadid(),fd,nfd,fileno(fp),p2i(fp),FL_Bar);
}
		}
	}else
	{
	fp = fdopen(fd,mode);
	}
	/*
	if( fp && numthreads() ){
		setvbuf(fp,0,_IOFBF,1024);
	}
	*/
	add_FILEY(FL_Bar,"fdopen",fp);
	unLockB("fdopen-done",2);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	return fp;
}
#undef fopen
#if isWindows()
FILE *wfopenX(const char *path,const char *mode);
#else
#define wfopenX(path,mode) 0
#endif
FILE *XXfopen(FL_Par,const char *path,const char *mode){
	FILE *fp;
	Lock locked;
	SSigMask sMask; setSSigMask(sMask);
	doLockB("fopen",2);
	if( isWindowsCE() ){
		fp = XX_fopen_FL(FL_Bar,path,mode);
	}else{
		fp = fopen(path,mode);
		if( fp == NULL && isWindows() ){
			fp = wfopenX(path,mode);
		}
	}
	/*
	if( fp && numthreads() ){
		setvbuf(fp,0,_IOFBF,1024);
	}
	*/
	add_FILEY(FL_Bar,"fopen",fp);
	unLockB("fopen-done",2);
	resetSSigMask(sMask);
	return fp;
}

#if defined(_MSC_VER) && defined(UNDER_CE)
int Xfileno(FILE *fp);
#undef fileno
#define fileno(f) Xfileno(f)
#endif
int pop_fd(int fd,int rw);
int fpop_fd(FILE *fp){
	if( feof(fp) ){
		if( 0 <= pop_fd(fileno(fp),0) ){
			daemonlog("E","fpop_fd(%d)\n",fileno(fp));
			clearerr(fp);
			return 1;
		}
	}
	return 0;
}

#undef p2i
#undef daemonlog

#include "ystring.h"
#include "log.h"
#ifndef EMU_NO_VSNPRINTF
#define EMU_NO_VSNPRINTF lNO_VSNPRINTF()
#endif

#define HeapDebug lMALLOC()
#define HEAPCHK (1<HeapDebug)
#define HEAPDBG HeapDebug<4?0:fprintf
#define HEAPVRB HeapDebug!=3?0:fprintf
#define HEAPTRC HeapDebug<2?0:fprintf
#define HEAPERR HeapDebug<1?0:fprintf


#if defined(QSC)
#define dSIZE VStrSIZE(d)
#define dTAIL &dBASE[VStrSIZE(d)-1]
#define AdTAIL dBASE,VStrSIZQ(d)
#else
#if !defined(QSS)
#define dTAIL &dBASE[dSIZE-1]
#define AdTAIL dBASE,dSIZE
#else
#define dBASE d
#endif
#endif

#undef memmove
#undef strncpy
#undef sprintf
#undef scanf

SStr(VStrUNKNOWN,1);

int FMT_XRsprintf(PRVStr(d),PCStr(f),...){
	int n;
	VARGS(16,f);

	n = Xsprintf(UVStr(d)*d,f,VA16);
	if( 0 < n ){
		*d += strlen(*d);
	}
	return n;
}
int strRL(const char **d){
	int len = strlen(*d);
	*d += len;
	return len;
}

/* 9.9.4 MTSS setSSigMask/resetSSigMask -Ets (-Dts)
 * suppressing signals that may cause freezing or "spin_lock" in mutex
 * (for flockfile, malloc, etc. and CSC) which are activated after a
 * thread is created.
 */
int cnt_SSigMask;
int pnumthreads();
int set_SSigMask(SSigMask *sMask,int force){
	int nmask;

	sMask->s_set = 0;
	if( lMTSS_NOSSIG() ){ /* MTSS disabled safe-signal "-Dts" */
		return -1;
	}
	if( force
	 || pnumthreads()
	 || !isWindowsCE() && numthreads()
	){
		cnt_SSigMask++;
		nmask = sigmask(SIGTERM)|sigmask(SIGINT)|sigmask(SIGPIPE);
		nmask |= sigmask(SIGHUP); /* for SIGHUP to Sticky */
		sMask->s_mask = sigblock(nmask);
		sMask->s_set = 1;
		return 0;
	}
	return -1;
}
int reset_SSigMask(SSigMask *sMask){
	if( sMask->s_set ){
		sMask->s_set = 0;
		sigsetmask(sMask->s_mask);
		return 0;
	}
	return -1;
}
static const char *litoa(int base,PVStr(buf),FileSize ival,int bytes,int wd){
	refQStr(bp,buf);
	char iv[32];
	int len;
	int v1;
	int cha;
	int neg = 0;
	int bits,obits;

	if( ival < 0 ){
		if( base == 10 ){
			setVStrPtrInc(bp,'-');
			neg = 1;
			ival = -ival;
		}
	}
	bits = bytes * 8;
	obits = 0;
	for( len = 0; len < elnumof(iv); ){
		if( base == 8 ){
			iv[len++] = ival & 0x7;
			if( (ival = ival >> 3) == 0 )
				break;
			if( bits <= (obits += 3) )
				break;
		}else
		if( base == 16 ){
			iv[len++] = ival & 0xF;
			if( (ival = ival >> 4) == 0 )
				break;
			if( bits <= (obits += 4) )
				break;
		}else{
			iv[len++] = ival % base;
			if( (ival = ival / base) == 0 )
				break;
		}
	}
	if( len < wd ){
		int wi;
		if( neg ) wd--;
		for( wi = 0; wi < (wd-len); wi++ ){
			setVStrPtrInc(bp,'0');
		}
	}
	for( len--; 0 <= len; len-- ){
		v1 = 0xF & iv[len];
		if( v1 < 10 )
			cha = '0' + v1;
		else	cha = 'A' + v1-10;
		setVStrPtrInc(bp,cha);
	}
	setVStrEnd(bp,0);
	return bp;
}
int sputf(PVStr(msg),PCStr(fmt),...){
	refQStr(mp,msg);
	const char *fp;
	int fc;
	int ai = 0;
	int ib;
	int zp;
	int wd;
	FileSize iv;
	int with_ll = 0;
	VARGS(16,fmt);

	for( fp = fmt; fc = *fp; fp++ ){
		if( fc != '%' ){
			setVStrPtrInc(mp,fc);
			continue;
		}
		zp = 0;
		if( fp[1] == '0' ){
			zp = 1;
			fp++;
		}
		wd = 0;
		while( '0' <= fp[1] && fp[1] <= '9' ){
			wd = wd * 10 + (fp[1] - '0');
			fp++;
		}
		iv = p2ll(va[ai]);
		ib = sizeof(int);
		if( with_ll == 0 ){
			iv &= 0xFFFFFFFF;
			if( fp[1] == 'd' ){
				iv = (FileSize)(int)iv;
			}
		}
		switch( fp[1] ){
			case '%':
				setVStrPtrInc(mp,fc);
				fp++;
				break;
			case 'x':
			case 'X':
				mp = (char*)litoa(16,AVStr(mp),iv,ib,wd);
				ai++;
				fp++;
				break;
			case 'u':
			case 'd':
				mp = (char*)litoa(10,AVStr(mp),iv,ib,wd);
				ai++;
				fp++;
				break;
			case 's':
				strcpy(mp,va[ai]);
				mp += strlen(mp);
				ai++;
				fp++;
				break;
		}
	}
	setVStrEnd(mp,0);
	return mp - msg;
}
int curLogFd();
int uGetpid();
int GmtOff();
int endthreads();

int addCR(FILE *fp,int fd,PCStr(str)){
	if( lCONSOLE() ){
		if( strchr(str,'\r') == 0 )
		if( isatty(fd) ){
			/* if( isnotcooked(fd) ) */
			if( fp ){
				fputc('\r',fp);
			}else{
				write(fd,"\r",1);
			}
		}
	}
	return 0;
}
void FMT_putfLog(PCStr(fmt),...){
	IStr(msg,256);
	refQStr(mp,msg);
	int now;
	int pid;
	int upid;
	int efd;
	VARGS(16,fmt);

	if( curLogFd() < 0 ){
		return;
	}
	now = time(0) + GmtOff();
	mp += sputf(AVStr(mp),"%02d:%02d:%02d",(now/3600)%24,(now/60)%60,now%60);
	pid = getpid();
	upid = uGetpid();
	if( pid != upid )
		mp += sputf(AVStr(mp),"[%d][%d][%d]%X ",pid,upid,getppid(),TID);
	else	mp += sputf(AVStr(mp),"[%d][%d]%X ",upid,pid,TID);
	mp += sputf(AVStr(mp),"%d/%d/%d/%d ",newthreads(),actthreads(),
		endthreads(),numthreads());
	sputf(AVStr(mp),fmt,VA16);
	strcat(mp,"\n");

	IGNRETP write(curLogFd(),msg,strlen(msg));
	if( lCONSOLE() && curLogFd() != (efd = fileno(stderr)) ){
		IGNRETP write(efd,msg,strlen(msg));
		addCR(0,efd,msg);
	}
}

extern const char *FL_F_Xfputs;  extern int FL_L_Xfputs, inXfputs;
extern const char *FL_F_Xfwrite; extern int FL_L_Xfwrite,inXfwrite;
extern const char *FL_F_Xfflush; extern int FL_L_Xfflush,inXfflush;
extern const char *FL_F_Xfclose; extern int FL_L_Xfclose,inXfclose;
extern const char *FL_F_Malloc;  extern int FL_L_Malloc,inMalloc;
extern const char *FL_F_Localtm; extern int FL_L_Localtm,inLocaltm;
const char *FL_F_Gzip; int FL_L_Gzip,inGzip;

int getXf_list(PVStr(Xf)){
	if( inXfputs || inXfwrite || inXfflush || inXfclose || inGzip ){
		if( inXfputs ){
			strcat(Xf,"Xfputs");
			if( FL_F_Xfputs )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Xfputs,FL_L_Xfputs);
		}
		if( inXfwrite ){
			strcat(Xf,"Xfwrite");
			if( FL_F_Xfwrite )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Xfwrite,FL_L_Xfwrite);
		}
		if( inXfflush ){
			strcat(Xf,"Xfflush");
			if( FL_F_Xfflush )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Xfflush,FL_L_Xfflush);
		}
		if( inXfclose ){
			strcat(Xf,"Xfclose");
			if( FL_F_Xfclose )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Xfclose,FL_L_Xfclose);
		}
		if( inLocaltm ){
			strcat(Xf,"Localtm");
			if( FL_F_Localtm )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Localtm,FL_L_Localtm);
		}
		if( inMalloc ){
			strcat(Xf,"Malloc");
			if( FL_F_Malloc )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Malloc,FL_L_Malloc);
		}
		if( inGzip ){
			strcat(Xf,"Gzip");
			if( FL_F_Gzip )
			sputf(TVStr(Xf),"(%s:%d)",FL_F_Gzip,FL_L_Gzip);
		}
		return 1;
	}else{
		return 0;
	}
}
void putsLogXf(PCStr(wh),int isig){
	const char *ssig = "";
	IStr(Xf,64);

	if( isig )
	if( getXf_list(AVStr(Xf)) ){
		switch( isig ){
			case SIGTERM: ssig = "TERM"; break;
			case SIGPIPE: ssig = "PIPE"; break;
			case SIGALRM: ssig = "ALRM"; break;
			case SIGINT:  ssig = "INT";  break;
			case SIGHUP:  ssig = "HUP";  break;
		}
		putfLog("%s got SIG%s/%d in %s",wh,ssig,isig,Xf);
	}
}


#if defined(WITH_QVSTR)

#define DBG_INIT	1
#define DBG_ABORT	2
#define DBG_VERBOSE	4
#define DBG_NOTIFY	8

static int debug_flags;
static int nov;
static void setup_debug(){
	const char *env;
	if( (debug_flags & DBG_INIT) != 0 ){
		return;
	}
	debug_flags |= DBG_INIT;
	if( env = getenv("DEBUG_VSTR") ){
		if( strstr(env,"abort") )
			debug_flags |= DBG_ABORT;
		if( strstr(env,"notify") )
			debug_flags |= DBG_NOTIFY;
		if( strstr(env,"verb") )
			debug_flags |= DBG_VERBOSE;
	}
/*
	if( debug_flags & DBG_VERBOSE )
		fprintf(stderr,"DEBUG_VSTR %X\n",debug_flags);
*/
}
void Xwhatis(PVStr(d)){
	const char *F = dFILE;
	int L = dLINE;
	const char *T = dTAIL;
	int z;
	if( T == 0 )
		z = 0;
	else	z = (char*)T - d + 1;
	fprintf(stderr,"#### %s:%d %X - %X - %X (%d/%d)\n",F,L,p2i(dBASE),p2i(d),p2i(T),z,ll2i(T-dBASE+1));
}
char *VStrId(PVStr(wh),PVStr(vs)){
#if defined(QSC)
	snprintf((char*)wh,VStrSIZE(wh),"%s:%d",vsFILE,vsLINE);
#else
	snprintf((char*)wh,whSIZE,"%s:%d",vsFILE,vsLINE);
#endif
	return (char*)wh;
}

static void putvstr(char *dst,int siz,PVStr(d)){
	int di,ch;
	const char *dp;
	const char *vx;
	char *vp;
	vp = dst;

	*vp++ = '"';
	vx = &d[siz-1];
	/*
	if( dp == NULL ){
	bug from 9.0.6
	*/
	if( d == NULL ){
		goto END;
	}

	for( di = 0; di < dSIZE && di < 32; di++ ){
		dp = &dBASE[di];
		ch = 0xFF & *dp;
		if( ch == 0 )
			goto END;
		if( 0x20 <= ch && ch < 0x7F && ch != '\\' )
			*vp++ = ch;
		else{
			snprintf(vp,vx-vp,"\\%02X",ch);
			vp += strlen(vp);
		}
	}
	dp = &d[di];
	if( dp < dTAIL-32 ){
		*vp++ = '"';
		snprintf(vp,vx-vp,"[%X]",p2i(dTAIL-32));
		vp += strlen(vp);
		*vp++ = '"';
	}
	for( dp = dTAIL-32; dp < dTAIL+16; dp++ ){
		ch = 0xFF & *dp;
		if( ch == 0 && d <= dp )
			break;
		if( 0x20 <= ch && ch < 0x7F && ch != '\\' )
			*vp++ = ch;
		else{
			snprintf(vp,vx-vp,"\\%02X",ch);
			vp += strlen(vp);
		}
		if( dp == dTAIL ){
			*vp++ = '"';
			*vp++ = '|';
			*vp++ = '"';
		}
	}
END:
	*vp++ = '"';
	snprintf(vp,vx-vp,"[%X]",p2i(dp));
	vp += strlen(vp);
	*vp = 0;
}
void VStr_overflow(PCStr(where),PVStr(d),int len,int siz,PCStr(fmt),...){
	char msg[1024]; /**/
	char vstr[512];
	VARGS(16,fmt);

	snprintf(msg,sizeof(msg),
		"VStr overflow in %s (%s:%s:%d) %d/%d/%d %X-%X-%X ",
		where,MyVer,dFILE,dLINE,len,siz,dSIZE,p2i(dBASE),p2i(d),p2i(dTAIL));
	snprintf(msg+strlen(msg),sizeof(msg)-strlen(msg),fmt,VA16);
	putvstr(vstr,sizeof(vstr),BVStr(d));
	snprintf(msg+strlen(msg),sizeof(msg)-strlen(msg)," %s",vstr);
	if( lMULTIST() ){
		fprintf(stderr,"## [%X] %s\n",TID,msg);
	}else
	fprintf(stderr,"## [%d] %s\n",getpid(),msg);
	daemonlog("F","%s\n",msg);

	if( debug_flags & DBG_ABORT ){
daemonlog("E","#### abort after 10 seconds...\n");
sleep(10);
		abort();
	}
	nov++;
	if( 10 < nov )
		usleep(100);
}
#define Notify(v)	((debug_flags&DBG_ABORT)?(abort(),v):v)

const char *XcheckPtr(PVStr(d),const char *p){
	if( p < dBASE ){
		fprintf(stderr,"## POINTER UNDERFLOW %s:%d\n",dFILE,dLINE);
		VStr_overflow("XcheckPtr",BVStr(d),p-dBASE,dSIZE,"UNDERFLOW");
		abort();
	}
	if( dTAIL < p ){
		fprintf(stderr,"## POINTER OVERFLOW %s:%d\n",dFILE,dLINE);
		VStr_overflow("XcheckPtr",BVStr(d),p-dBASE,dSIZE,"OVERFLOW");
		abort();
	}
	return p;
}

int Xassert(PVStr(d),PCStr(p)){
	if( p < dBASE ){
		VStr_overflow("Xassert",dFILE,dLINE,AdTAIL,d,p-d,dTAIL-d,"");
		sleep(1);
		return -1;
	}
	if( dTAIL <= p ){
		VStr_overflow("Xassert",dFILE,dLINE,AdTAIL,d,p-d,dTAIL-d,"");
		sleep(1);
		return -1;
	}
	return 0;
}
static int outofrange(PCStr(wh),PVStr(d),int z){
	setup_debug();
	if( d < dBASE || dTAIL < d ){
		VStr_overflow(wh,dFILE,dLINE,AdTAIL,d,UTail(d)-d+1,0,
			"pointer out of range");
		return 1;
	}
	if( z )
	if( d+z < dBASE || dTAIL+1 < d+z ){
		VStr_overflow(wh,dFILE,dLINE,AdTAIL,d,UTail(d)-d+1,z,
			"index out of range");
		return 1;
	}
	return 0;
}

int XQVSSize(PVStr(d),int z){
	int rem;
	if( outofrange("XQVSSize",BVStr(d),z) ){
		return Notify(0);
	}
	rem = (dBASE+dSIZE) - d;
	if( rem < z ){
		VStr_overflow("XQVSSize",dFILE,dLINE,AdTAIL,d,z,rem,"");
		if( rem < 0 )
			z = 0;
		else	z = rem;
	}
	return z;
}

void *Xmemmove(PVStr(d),PCStr(s),int size){
	int z;
	if( outofrange("Xmemmove",BVStr(d),size) ){
		return Notify((char*)d);
	}
	if( dTAIL == 0 )
		z = 0;
	else	z = (char*)dTAIL - d + 1;
	if(dTAIL+1 < d+size){
		VStr_overflow("Xmemmove",dFILE,dLINE,AdTAIL,d,size,z,"");
		/*
		size = dTAIL+1-d;
		*/
		size = dTAIL - d;
		if( size < 0 ){
			return (char*)d;
		}
	}
	return memmove((char*)d,s,size);
}
void Xbcopy(const void *s,PVStr(d),int z){
	if( outofrange("Xbcopy",BVStr(d),z) ){
		return;
	}
	if( dTAIL+1 < d+z ){
	VStr_overflow("Xbcopy",dFILE,dLINE,AdTAIL,d,UTail(d)-d+1,z,"");
		/*
		z = dTAIL - d + 1;
		*/
		z = dTAIL - d;
	}
	/*
	source pointer "s" should be checked too, not to cause overrun.
	 */
	bcopy(s,(char*)d,z);
}
char *XStrncpy(PVStr(d),PCStr(s),int z){
	char *dp = (char*)d;
	int n = z;

	if( outofrange("XStrncpy",BVStr(d),0) ){
		return Notify((char*)d);
	}
	if( dTAIL+1 < d+z ){
	VStr_overflow("XStrncpy",dFILE,dLINE,AdTAIL,d,UTail(d)-d+1,z,"");
		n = dTAIL - d + 1;
	}
	while( 1 < n-- ){
		if( (*dp++ = *s++) == 0 )
			break;
	}
	*dp = 0;
	return (char*)d;
}
char *Xstrncpy(PVStr(d),PCStr(s),int size){
	const char *F = dFILE;
	int L = dLINE;
	const char *T = dTAIL;
	int z;

	setup_debug();
	if( outofrange("Xstrncpy",BVStr(d),size) ){
		return Notify((char*)d);
	}
	if( T == 0 )
		z = 0;
	else	z = (char*)T - d + 1;
	if(z < size ){
		VStr_overflow("Xstrncpy",F,L,AdTAIL,d,size,z,"");
		size = z;
	}
	strncpy((char*)d,s,size);
	return (char*)d;
}
int XsetVStrEnd(PVStr(d),int x){
/*
fprintf(stderr,"######## TAIL dTAIL=%X UTAIL=%X toP=%X size=%X CUR %X\n",dTAIL,UTail(d),d,dSIZE,&d[x]);
*/
	if( dBASE == 0 && dSIZE == 0 ){
		VStr_overflow("XsetVStrEnd",dFILE,dLINE,AdTAIL,d,x,0,"");
		return Notify(0);
	}
	if( outofrange("XsetVStrEnd",BVStr(d),0) ){
		*(char*)dTAIL = 0;
		return Notify(0);
	}
	if( dTAIL < &d[x] ){
		VStr_overflow("XsetVStrEnd",dFILE,dLINE,AdTAIL,d,x,UTail(d)-d+1,"");
		*(char*)UTail(d) = 0;
		return UTail(d)-d;
	}else{
		((char*)d)[x] = 0;
		return x;
	}
}

char *Xstrcpy(PVStr(d),PCStr(s)){
	const char *F = dFILE;
	int L = dLINE;
	const char *T = dTAIL;
	char *e; /**/
	int z;
	int l; /* source string length */
	int i;

	setup_debug();
	if( outofrange("Xstrcpy",BVStr(d),0) ){
		return Notify((char*)d);
	}
	if( T == 0 )
		z = 0;
	else	z = (char*)T - d + 1;
	l = strlen(s);

/*
fprintf(stderr,"##### U=%X T=%X d=%X B=%X Z=%X T=%X %X\n",
VStrUNKNOWN,T,d,dBASE,dSIZE,dTAIL,T);
*/
	if(T != VStrUNKNOWN)
	if(T == 0 || z < l ){
		VStr_overflow("Xstrcpy",F,L,AdTAIL,d,l,z,"");
	}

 if( debug_flags & DBG_VERBOSE )
 fprintf(stderr,"## [%d] Xstrcpy (%s:%d) %3X/%5X %08X - %08X\n",
	getpid(),F,L, istrlen(s),z,p2i(d),p2i(s));

	e = (char*)d;
	for( i = 1; i < z; i++ ){
		if( (*e++ = *s++) == 0 ){
			break;
		}
	}
	if( i == z )
	*e = 0;
	return (char*)d;
}
char *Xstrcat(PVStr(d),PCStr(s)){
	const char *F = dFILE;
	int L = dLINE;
	const char *T = dTAIL;
	char *t; /**/
	int z;

	setup_debug();
	if( outofrange("Xstrcat",BVStr(d),0) ){
		return Notify((char*)d);
	}
	if( T == 0 )
		z = 0;
	else	z = (char*)T - d + 1;

 if( debug_flags & DBG_VERBOSE )
 fprintf(stderr,"## [%d] Xstcrat (%s:%d) %3X/%5X %08X - %08X)\n",
	getpid(),F,L, istrlen(s),z,p2i(d),p2i(s));

	for(t = (char*)d; *t; t++);
	Xstrcpy(F,L,AdTAIL,t,s);
	return (char*)d;
}
static void vfputs(PCStr(s),FILE *f){
	const char *p;
	int ch;
	for(p = s; ch = *p; p++){
		if( 0x20 <= ch && ch < 0x7F ){
			putc(ch,f);
		}else{
			putc('.',f);
		}
	}
}

static int floatFmt(PCStr(fmt));
int FMT_Xsprintf(PVStr(d),PCStr(f),...){
	const char *F = dFILE;
	int L = dLINE;
	const char *T = dTAIL;
	int z,n;
	CStr(llfmt,1024);

/*
	static int N;
	fprintf(stderr,"---- %4d %s:%d %s\n",++N,dFILE,dLINE,f);
*/
	setup_debug();
	if( outofrange("Xsprintf",BVStr(d),0) ){
		return Notify(0);
	}
	if( dTAIL == 0 )
		z = 0;
	else	z = (char*)T - d + 1;

#ifndef NOVSNPRINTF
 if( !EMU_NO_VSNPRINTF )
 {
	va_list nap;
	va_start(nap,f);

	if( modifyFmt(f,AVStr(llfmt),sizeof(llfmt)) )
		f = llfmt;

	if( numthreads() && floatFmt(f) ){
		/* 9.9.4 MTSS to guard dtoa() for "%f" */
		SSigMask sMask;
		setSSigMask(sMask);
		if( 0 < z )
			n = vsnprintf((char*)d,z,f,nap);
		else	n = vsnprintf((char*)d,0,f,nap);
		resetSSigMask(sMask);
	}else
	if( 0 < z )
		n = vsnprintf((char*)d,z,f,nap);
	else	n = vsnprintf((char*)d,0,f,nap);
	va_end(nap);
 }
 else
#endif
 {
	VARGS(16,f);

	if( modifyFmt(f,AVStr(llfmt),sizeof(llfmt)) )
		f = llfmt;
	if( 0 < z )
		n = snprintf((char*)d,z,f,VA16);
	else	n = snprintf((char*)d,0,f,VA16);
 }

 if( debug_flags & DBG_VERBOSE ){
 fprintf(stderr,"## [%d] Xsprintf (%s:%d) %3X/%5X",
	getpid(),F,L, n,z);
 vfputs(f,stderr);
 fprintf(stderr,"\n");
 }

	if( z == 0 || z <= n || n == -1 ){
		VStr_overflow("Xsprintf",F,L,AdTAIL,d,n,z,"(%d) %s",strlen(d),f);
	}

	return n;
}

static int strlongereq(PCStr(str),int len){
	int li;
	const char *sp = str;
	for( li = 0; li < len; li++ ){
		if( *sp == 0 )
			return 0;
		sp++;
	}
	return 1;
}
int NO_ll_Fmt();
int Xsscanf(PCStr(str),PCStr(fmt),...){
	const char *f;
	int fc;
	char xfmt[1024]; /**/
	char *yfmt = xfmt;
	char *x; /**/
	const char *xp;
	int ni = 0;
	const char *F;
	int L;
	const char *T;
#if defined(QSC)
	char *N; /**/
#endif
	char *d; /**/
	char *b; /**/
	int z;
	int xn;
	int xi;
	va_list ap;
	char *va[16]; /**/
	int len[16]; /**/
	char *sa[16]; /* for safety in the case where length information */
	char sc[16];  /* is longer than the real length */
	int noverflow;
	CStr(llfmt,1024);

	IStr(afmt,256);
	if( NO_ll_Fmt() ){
		if( modifyFmt(fmt,AVStr(afmt),sizeof(afmt)) ){
			fmt = afmt;
		}
	}

	va_start(ap,fmt);
	setup_debug();

	x = xfmt;
	xp = &xfmt[sizeof(xfmt)-1];
	for(f = fmt; fc = *f; f++){
		if( xp <= x ){
			break;
		}
		*x++ = fc;
		if( fc != '%' )
			continue;
		if( elnumof(va) <= ni ){
			fprintf(stderr,"## too many format specs: %s\n",fmt);
			break;
		}
		fc = *++f;
		*x++ = fc;
		switch(fc){
			case '%': continue;
			case '*': continue;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
			case 'h': case 'l': case 'L': case 'j': case 't':
			case 'z': case 'q':

			case 'd': case 'i': case 'o': case 'u':
			case 'x': case 'X': case 'a': case 'A':
			case 'e': case 'E': case 'f': case 'F':
			case 'g': case 'G':
			case 'c': case 'C':
				len[ni] = 0;
				va[ni++] = va_arg(ap,char*);
				break;
			default:
			fprintf(stderr,"## unknown format [%c]%s\n",fc,fmt);
				break;
			case 's':
			case '[':
				F = va_arg(ap,char*);
				L = va_arg(ap,int);
#if defined(QSC)
				b = va_arg(ap,char*);
				N = va_arg(ap,char*);
				z = N - b;
				T = &b[z-1];
				d = va_arg(ap,char*);
				z = T - d + 1;
				if( outofrange("Xsscanf",F,L,b,N,d,0) ){
					return Notify(0);
				}
#else
#if !defined(QSS)
				b = va_arg(ap,char*);
				z = va_arg(ap,int);
				T = &b[z-1];
				d = va_arg(ap,char*);
				z = T - d + 1;
				if( outofrange("Xsscanf",F,L,b,z,d,0) ){
					return Notify(0);
				}
#else
				T = va_arg(ap,char*);
				d = va_arg(ap,char*);
				z = T - d + 1;
#endif
#endif

 if(ni==0)
 if( debug_flags & DBG_VERBOSE ){
 fprintf(stderr,"## [%d] Xsscanf (%s:%d) ",getpid(),F,L);
 vfputs(fmt,stderr);
 fprintf(stderr,"\n");
 }
				if( z <= 0 || 0x10000 < z ){
					z = 0;
fprintf(stderr,"## Xsscanf ## %d:%s size unknown [%c]%s[%d]\n",L,F,fc,fmt,ni);
sleep(2);
				}else{
					len[ni] = z;
					snprintf(x-1,8,"%d",z-1);
/* sscanf() on RedHat7.1 writes length=z+1(for  NUL) at overflow */
sa[ni] = &d[z-1];
sc[ni] = d[z-1];
d[z-1] = 0;
					x += strlen(x);
					*x++ = fc;
				}
				len[ni] = z;
				va[ni++] = d;
				break;
		}
	}
	*x = 0;

	yfmt = xfmt;
	if( modifyFmt(xfmt,AVStr(llfmt),sizeof(llfmt)) )
	{
		yfmt = llfmt;
	}

	xn = sscanf(str,yfmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6],va[7],va[8],va[9],va[10],va[11],va[12],va[13],va[14],va[15]);

	noverflow = 0;
	for(xi = 0; xi < xn; xi++){
		if(len[xi] && len[xi]-1 <= strlen(va[xi])){
			const char *dBASE = va[xi];
#if defined(QSC)
			const char *dNEXT = va[xi] + len[xi];
#else
			int dSIZE = len[xi];
#endif
		VStr_overflow("Xsscanf",F,L,AdTAIL,va[xi],strlen(va[xi]),len[xi],"\"%s\" -> \"%s\" $%d",fmt,yfmt,xi);
			noverflow++;

			/* 9.2.5 sa[] and sc[] is introduced in 8.11.0-pre2 to
			 * try fix mad str[N] = '\0'; for "%Ns" format spec.
			 * [DeleGate:12693]
			 * Now it is not necessary and halmful.
			 * sc[] which is likely non '\0' should not be
			 * restored at least in this case, since it is halmful
			 * making unterminated string.
			 */
			continue;
		}
		if( 0 < len[xi] ){
			*sa[xi] = sc[xi];
		}
	}
	if( noverflow )
		if( debug_flags & DBG_ABORT ) abort();
	return xn;
}

#if defined(UNDER_CE)
char *XX_fgets(PVStr(buf),int siz,FILE *fp);
#else
#define XX_fgets(buf,siz,fp) 0
#endif

char *Xfgets(PVStr(d),int siz,FILE *fp){
	char *dp; /**/
	int ch;
	int i;
	const char *dtail = dTAIL;

	if( outofrange("Xfgets",BVStr(d),0) ){
		return Notify((char*)NULL);
	}
	if( siz <= 1 ){
		VStr_overflow("Xfgets",dFILE,dLINE,AdTAIL,d,0,siz,"(size<=1)");
		return NULL;
	}

	dp = (char*)d;
	if( isWindowsCE() ){
		dp = XX_fgets(BVStr(d),siz,fp);
		i = dp - d;
	}else
	for( i = 0; i < siz; i++ ){
		/*
		if( dTAIL <= dp ){
		*/
		if( dtail <= dp ){
			break;
		}
		ch = getc(fp);
		if( ch == EOF ){
			if( fpop_fd(fp) ){
				ch = getc(fp);
			}
		}
		if( ch == EOF ){
			break;
		}
		*dp++ = ch;
		if( ch == '\n' ){
			break;
		}
	}
	*dp = 0;
	if( dTAIL <= dp && dTAIL+1 < d+siz ){
		VStr_overflow("Xfgets",dFILE,dLINE,AdTAIL,d,i,siz,"");
	}
	if( dp == d ){
		return NULL;
	}
	return (char*)d;
}

int ready_cc(FILE *fp);
unsigned int Xfread(FL_PAR,PVStr(d),int ez,int en,FILE *fp){
	int z;
	int rcc;

	setup_debug();
	if( outofrange("Xfread",BVStr(d),0) ){
		return Notify(0);
	}
	if( dTAIL == 0 )
		z = 0;
	else	z = (char*)dTAIL - d + 1;

/*
 if( debug_flags & DBG_VERBOSE )
 fprintf(stderr,"## [%d] Xfread (%s:%d) %d/%d\n",
	getpid(),dFILE,dLINE, ez*en,z);
*/

	if( z < ez*en ){
		VStr_overflow("Xfread",dFILE,dLINE,AdTAIL,d,ez*en,z,"");
		return 0;
	}
	if( isWindowsCE() ){
		rcc = XX_fread(FL_BAR,(char*)d,ez,en,fp);
	}else
	if( ready_cc(fp) == 0 ){
		/* 9.9.4 MTSS to guard malloc() on the first fread */
		/* but fread from a stream should be interruptable ... */
		SSigMask sMask;
		setSSigMask(sMask);
		rcc = fread((char*)d,ez,en,fp);
		resetSSigMask(sMask);
	}else
	rcc = fread((char*)d,ez,en,fp);
	return rcc;
}

#endif

#if !defined(WITH_QVSTR)
int Ysprintf(PVStr(dst),PCStr(fmt),...){
	IStr(afmt,256);
	int n;
	VARGS(16,fmt);

	if( modifyFmt(fmt,AVStr(afmt),sizeof(afmt)) ){
		fmt = afmt;
	}
	n = sprintf((char*)dst,fmt,VA16);
	return n;
}
#endif
int Ysscanf(PCStr(str),PCStr(fmt),...){
	int ne;
	IStr(afmt,256);
	VARGS(16,fmt);

	if( NO_ll_Fmt() ){
		if( modifyFmt(fmt,AVStr(afmt),sizeof(afmt)) ){
			fmt = afmt;
		}
	}
	ne = sscanf(str,fmt,VA16);
	return ne;
}
static int floatFmt(PCStr(fmt)){
	char fc;
	const char *fp;

	for( fp = fmt; fc = *fp; fp++ ){
		if( fc == '%' ){
			if( fp[1] == '-' )
				fp++;
			while( fc = *++fp ){
				if( fc != '*' && fc != '.' )
				if( fc < '0' || '9' < fc )
					break;
			}
			if( fc == 'f' )
				return 1;
			if( fc == 0 )
				break;
		}
	}
	return 0;
}

#if !defined(WITH_QVSTR)
/*
 * Xsscanf() / Xsprintf() should be redefined to be with modifyFmt()
 * to care "%lld" on Windows
 */
#endif

#ifdef NOVSNPRINTF
int NoVFPRINTF = 1;
#else
int NoVFPRINTF = 0;
#endif

#undef fprintf
int curLogFd();
FILE *curLogFp();
FILE *logMonFp();
FILE *logTeeFp;

int FMT_Xfprintf(FILE *fp,const char *fmt,...){
	int rcode;
	CStr(llfmt,1024);

	if( modifyFmt(fmt,AVStr(llfmt),sizeof(llfmt)) ){
		fmt = llfmt;
	}
	/*
	rcode = fprintf(fp,fmt,VA16);
	*/
	if( !NoVFPRINTF ){
		va_list nap;
		va_start(nap,fmt);
		if( isWindowsCE() ){
			rcode = XX_vfprintf(fp,fmt,nap);
		}else
		rcode = vfprintf(fp,fmt,nap);
		va_end(nap);
		/*
		if( fp == curLogFp() ){
		*/
		if( fp == curLogFp() || fileno(fp) == curLogFd() ){
			if( lCONSOLE() && logTeeFp ){
				va_start(nap,fmt);
				vfprintf(logTeeFp,fmt,nap);
				va_end(nap);
				fflush(logTeeFp);
			}else
			if( lCONSOLE() && fp != stderr ){
				va_start(nap,fmt);
				vfprintf(stderr,fmt,nap);
				va_end(nap);
				fflush(stderr);
			}
			if( logMonFp() ){
				va_start(nap,fmt);
				vfprintf(logMonFp(),fmt,nap);
				va_end(nap);
				fflush(logMonFp());
			}
		}
		if( fp == stdout || fp == stderr ){
			if( logMonFp() && logMonFp() != fp ){
				va_start(nap,fmt);
				vfprintf(logMonFp(),fmt,nap);
				va_end(nap);
				fflush(logMonFp());
			}
		}
	}else{
		VARGS(16,fmt);
		rcode = fprintf(fp,fmt,VA16);
	}
	if( isWindows() ){
		if( fp == stderr ){
			fflush(stderr);
		}
	}
	return rcode;
}

#undef fflush

#define TR_FFLUSH 0
static fd_set *trace_files[8];
int traceFiles(int what,FILE *fp,int set){
	int oval;
	int fd;

	if( fp == NULL )
		return -1;

	if( trace_files[what] == 0 ){
		if( set < 0 ) return 0;
		trace_files[what] = (fd_set*)malloc(sizeof(fd_set));
		FD_ZERO(trace_files[what]);
	}
	fd = fileno(fp);
	oval = FD_ISSET(fd,trace_files[what]);
	switch( set ){
		case 0: FD_CLR(fd,trace_files[what]); break;
		case 1: FD_SET(fd,trace_files[what]); break;
	}
	return oval;
}
int fflushTrace(FILE *fp,int set){ return traceFiles(TR_FFLUSH,fp,set); }

int inXfflush;
const char *FL_F_Xfflush;
int FL_L_Xfflush;
int Xfflush(FL_PAR, FILE *fp){
	int rcode;

	if( fp == 0 ){
		return -1;
	}
	if( !isWindowsCE() )
	if( fileno(fp) < 0 ){
		putfLog("##Xfflush(%d) suppressed <= %s:%d",fileno(fp),FL_BAR);
		fpurge(fp);
		return -1;
	}
	inXfflush = 1;
	FL_F_Xfflush = FL_F;
	FL_L_Xfflush = FL_L;
	if( trace_files[TR_FFLUSH] && FD_ISSET(fileno(fp),trace_files[TR_FFLUSH]) ){
		daemonlog("E","-- Xflush(%d/%X) %d\n",fileno(fp),p2i(fp),pendingcc(fp));
	}
	if( isWindowsCE() ){
		rcode = XX_fflush_FL(FL_BAR,fp);
	}else
	rcode = fflush(fp);
	inXfflush = 0;
	return rcode;
}

static int poppersist(const void *mp,FL_PAR,int ssi){
	Alloc *ap;
	int si;

	for( si = 1; si < elnumof(persistents); si++ ){
		ap = &persistents[si];
		if( ap->a_p == mp ){
HEAPVRB(stderr,"-dm clr persistent[%3d] S[%3d] %s:%d << [%d] %X %s:%d\n",
si,allocsp, ap->a_F,ap->a_L,ssi,p2i(ap->a_p), FL_BAR);
			ap->a_p = 0;
			return 1;
		}
	}
	return 0;
}
static int pushpersist(Alloc *aap){
	Alloc *ap;
	int si;

	for( si = 1; si < elnumof(persistents); si++ ){
		ap = &persistents[si];
		if( ap->a_p == 0 ){
			if( aap->a_F == ap->a_F && aap->a_L == ap->a_L ){
			}else{
			}
HEAPVRB(stderr,"-dm add persistent[%3d][%d] %s:%d (%d)\n",
allocsp,si,aap->a_F,aap->a_L,aap->a_z);
			persistents[si] = *aap;
			return si;
		}
	}
	return 0;
}
/*
void *markPersistentMem(const void *mp){
	Alloc *ap = 0;
	int si;
	int pi = 0;
	Lock locked;

	if( !HEAPCHK ){
		return (void*)mp;
	}
	doLock("",0);
	for( si = allocsp-1; 0 <= si; si-- ){
		ap = &allocs[si];
		if( ap->a_p == mp ){
			pi = pushpersist(ap);
			ap->a_free = 2;
			break;
		}
	}
	unLock("",0);
	return (void*)mp;
}
*/
void markStackBase(void *mp){
	Alloc *ap;
	int si;
	Lock locked;

	if( !HEAPCHK ){
		return;
	}
	doLock("markStB",0);
	for( si = allocsp-1; 0 <= si; si-- ){
		ap = &allocs[si];
		if( ap->a_p == mp ){
			ap->a_base = 1;
			break;
		}
	}
	unLock("markStB-done",0);
}
void pushalloc(const char *wh,FL_PAR_P,unsigned int sz,void *mp){
	Alloc *ap;
	Lock locked;

	if( !HEAPCHK ){
		return;
	}
	doLockB("pushalloc",0);
	if( allocsp < elnumof(allocs) ){
		if( 0 < lastpopend )
		if( allocsp == lastpopend+1 ){
			ap = &allocs[lastpopend];
			if( ap->a_free == 0 )
			if( ap->a_base == 0 )
			{
HEAPERR(stderr,"-dm new persistent[%3d] %s:%d (%d) %s:%d\n",
allocsp,ap->a_F,ap->a_L,ap->a_z,FL_BAR);
fflush(stderr);
			}
		}
		ap = &allocs[allocsp];
		ap->a_F = FL_F;
		ap->a_L = FL_L;
		ap->a_p = mp;
		ap->a_z = sz;
		ap->a_free = 0;
		ap->a_base = 0;
		if( pstm ){
			int pi;
			pi = pushpersist(ap);
		HEAPDBG(stderr,"-dm [%3d]%d %5X %8X %s:%d put [%d] by %s\n",
			allocsp,pstm,sz,p2i(mp),FL_BAR,pi,wh);
		}else{
		HEAPDBG(stderr,"-dm [%3d]%d %5X %8X %s:%d pushed by %s\n",
			allocsp,pstm,sz,p2i(mp),FL_BAR,wh);
			allocsp++;
		}
	}
EXIT:
	unLockB("pushalloc-done",0);
}
static void pops(const char *wh,FL_PAR){
	Alloc *ap;
	int si;

	lastpopend = 0;
	for( si = allocsp-1; 0 <= si; si-- ){
		ap = &allocs[si];
		if( !ap->a_free ){
			lastpopend = si;
			break;
		}
		allocsp--;
		HEAPDBG(stderr,"-dm [%3d]%d %5X %8X %s:%d %s %s:%d (POP)\n",
			allocsp,ap->a_free,ap->a_z,p2i(ap->a_p),ap->a_F,ap->a_L,
			wh,FL_BAR);
	}
}
void popfree(const char *wh,FL_PAR,void *mp){
	Alloc *ap;
	int si;
	Lock locked;
	const void *op;
	int poped = 0;

	if( !HEAPCHK ){
		return;
	}
	doLockB("popfree",0);
	for( si = allocsp-1; 0 <= si; si-- ){
		ap = &allocs[si];
		op = ap->a_p; /* might be cleared in poppersist() */
		if( ap->a_free == 2 ){
			if( poppersist(mp,FL_BAR,si) ){
				poped++;
			}
		}
		if( op == mp ){
			ap->a_free = 1;
			HEAPDBG(stderr,"-dm [%3d]%d %5X %8X %s:%d %s %s:%d\n",
				si,ap->a_free,ap->a_z,p2i(mp),ap->a_F,ap->a_L,
				wh,FL_BAR);
			pops(wh,FL_BAR);
			goto EXIT;
		}
	}
	if( poped || poppersist(mp,FL_BAR,si) ){
		goto EXIT;
	}
	HEAPERR(stderr,"-dm [???](%d) %X %s %s:%d\n",allocsp,p2i(mp),wh,FL_BAR);
EXIT:
	unLockB("popfree-done",0);
}

int getthreadid();
static CriticalSec LockCSC;
#define EnterCSC(wh) \
	if( numthreads() ){ \
		setthread_FL(0,FL_BAR,wh); \
		enterCSCX_FL(FL_ARG,LockCSC,300*1000); \
		/* \
		enterCSC(LockCSC); \
		*/ \
	}
#define LeaveCSC(wh) \
	if( numthreads() ){ \
		setthread_FL(0,FL_BAR,wh); \
		leaveCSC(LockCSC); \
	}

static void printLockStat(FL_PAR,PCStr(wh),int tid,int ntry,PCStr(act)){
 IStr(msg,256);
 Xsprintf(AVStr(msg),"-- %04X %.1f[%5d %d %X %s/%s:%d]%d*%s %s/%s:%d",
		PRTID(tid),Time()-curLock.l_Time,
		curLock.l_lid,curLock.l_lev,PRTID(curLock.l_tid),
		curLock.l_wh,curLock.l_F,curLock.l_L,ntry,
		act,wh,FL_BAR
	);
	strsubst(AVStr(msg),".cpp:",":");
	fprintf(stderr,"%s\n",msg);
	fflush(stderr);
}
static void printUnLockStat(FL_PAR,PCStr(wh),int tid,Lock locked,PCStr(act)){
 IStr(msg,256);
 Xsprintf(AVStr(msg),"-- %04X [%5d %d %X %s:%d] [%5d %d %X] %s %s %s:%d",
		PRTID(tid),
		curLock.l_lid,curLock.l_lev,PRTID(curLock.l_tid),
		curLock.l_F,curLock.l_L,
		locked.l_lid,locked.l_lev,PRTID(locked.l_tid),
		act,wh,FL_BAR);
	strsubst(AVStr(msg),".cpp:",":");
	fprintf(stderr,"%s\n",msg);
	fflush(stderr);
}
void msleep(int ms);
int waitLock(){
	int wi;

	msleep(1);
	for( wi = 0; wi < 10; wi++ ){
		if( curLock.l_lev <= 0 ){
			break;
		}
		syslog_ERROR("-- waitLock %2d) %d %X <= %s:%d\n",
			wi,curLock.l_lev,PRTID(curLock.l_tid),
			curLock.l_F?curLock.l_F:"",curLock.l_L
		);
		msleep(100);
	}
	return wi;
}
static Lock doLock_FL(FL_PAR,PCStr(wh),int log){
	int tid = getthreadid();
	Lock preLock;
	int li;
	int ri;
	int dbg = 0;
	int clev;
	int ctid;
	int failed = 0;

	setupCSC("doLock",LockCSC,sizeof(LockCSC));
	for( ri = 0; ri < 10; ri++ ) RETRY:{
		EnterCSC(wh);
		clev = curLock.l_lev;
		if( curLock.l_lev == 0 || curLock.l_tid == tid ){
			curLock.l_lev++;
			curLock.l_lid++;
			curLock.l_tid = tid;
			curLock.l_wh = wh;
			curLock.l_F = FL_F;
			curLock.l_L = FL_L;
			if( clev == 0 ){
				curLock.l_Time = Time();
			}
			preLock = curLock;
			preLock.l_lev--;
			LeaveCSC(wh);

			if( 2 < log && 1 < curLock.l_lev ){
				/* curLock.l_dbg = tid; */
 printLockStat(FL_BAR,wh,tid,failed,"LOCKED+");
			}else
			if( 2 < log || 50 < failed ){
 printLockStat(FL_BAR,wh,tid,failed,"LOCKED-");
			}
			return preLock;
		}
		LeaveCSC(wh);
		for( li = 0; li < 100; li++ ){
			EnterCSC(wh);
			clev = curLock.l_lev;
			LeaveCSC(wh);
			if( clev == 0 ){
				if( 80 < li ){
 printLockStat(FL_BAR,wh,tid,failed,"RETRY-a");
					/* curLock.l_dbg = tid; */
				}
				goto RETRY;
			}
			usleep(10*1000);
			failed++;
		}
 printLockStat(FL_BAR,wh,tid,failed,"RETRY-b");
	}
 printLockStat(FL_BAR,wh,tid,failed,"RESET ---- !!!!");

	if( numthreads() ){
		/* should do destroy the CriticalSec here ... */
		/*
		this causes SEGV
		bzero(LockCSC,sizeof(LockCSC));
		*/
		/*
		curLock = noLock;
		*/
		curLock.l_lev = 0;
	}
	return noLock;
}
static void unLock_FL(FL_PAR,PCStr(wh), int log,Lock locked){
	int tid = getthreadid();

	EnterCSC(wh);
	if( curLock.l_tid == tid ){
		if( 3 < log || curLock.l_dbg )
 printUnLockStat(FL_BAR,wh,TID,locked,"unLocked");

		curLock.l_lev = locked.l_lev;
		curLock.l_tid = locked.l_tid;
		if( curLock.l_dbg == tid && curLock.l_lev == 0 ){
			curLock.l_dbg = 0;
		}
	}else{
 printUnLockStat(FL_BAR,wh,TID,locked,"unLock ABNORMAL");
	}
	LeaveCSC(wh);
}
int heapLock(FL_PAR,void *locked){
	*(Lock*)locked = doLock_FL(FL_BAR,"heapLock",0);
	return 0;
}
int heapUnLock(FL_PAR,void *locked){
	unLock_FL(FL_BAR,"heapUnLock",2,*(Lock*)locked);
	return 0;
}

typedef struct {
	const char *fx_wh;
	const char *fx_F;
	int    fx_L;
	FILE * fx_fp;
	int    fx_fd;
} FILEY;
#define NUM_FILEY 256
static FILEY filexs[NUM_FILEY];
int actFILEY;
int numFILEY;
void dumpFILEY(FILE *out){
	int fn = 0;
	int fi;
	FILEY *fxp;
	for( fi = 0; fi < NUM_FILEY; fi++ ){
		fxp = &filexs[fi];
		if( fxp->fx_wh )
		if( fxp->fx_fp )
		{
			porting_dbg("--FY(%2d)(%2d)[%2d]%X %6s << %s:%d",
				fn++,fi,fxp->fx_fd,p2i(fxp->fx_fp),
				fxp->fx_wh,fxp->fx_F,fxp->fx_L);
		}
	}
	porting_dbg("--FY act=%d / total=%d",actFILEY,numFILEY);
}
static void add_FILEY1(FL_Par,const char *wh,FILE *fp){
	int fi;
	FILEY *fxp;
	int added = 0;

	for( fi = 0; fi < NUM_FILEY; fi++ ){
		fxp = &filexs[fi];
		if( fxp->fx_fp == fp ){
porting_dbg("--FY[%d]%X adding dup (%s)%s:%d[%d] >>> (%s)%s:%d[%d]",
fi,p2i(fp),fxp->fx_wh,fxp->fx_F,fxp->fx_L,fxp->fx_fd,
wh,FL_F,FL_L,fileno(fp));
			fxp->fx_fp = 0;
			actFILEY--;
		}
		if( fxp->fx_fp == 0 ){
			fxp->fx_wh = wh;
			fxp->fx_F = FL_F;
			fxp->fx_L = FL_L;
			fxp->fx_fp = fp;
			fxp->fx_fd = fileno(fp);
			added = 1;
			actFILEY++;
			if( numFILEY < actFILEY )
				numFILEY = actFILEY;
			break;
		}
	}
	if( added == 0 ){
		porting_dbg("--FY[%d] cannot add %X %s << %s:%d",fi,p2i(fp),
			wh,FL_F,FL_L);
	}
}
void del_FILEY1(FL_Par,const char *wh,FILE *fp){
	int fi;
	FILEY *fxp;
	int deled = 0;

	for( fi = 0; fi < NUM_FILEY; fi++ ){
		fxp = &filexs[fi];
		if( fxp->fx_fp == fp ){
			fxp->fx_wh = wh;
			fxp->fx_F = FL_F;
			fxp->fx_L = FL_L;
			fxp->fx_fp = 0;
			deled = 1;
			actFILEY--;
			break;
		}
	}
	if( deled == 0 ){
		porting_dbg("--FY[%d] not found %X %s << %s:%d",fi,p2i(fp),
			wh,FL_F,FL_L);
	}
}
void add_FILEY(FL_Par,const char *wh,FILE *fp){
	Lock locked;

	if( !lMEMUSAGE() ){ return; }
	if( fp == 0 )
		return;
	if( !lSINGLEP() )
		return;
	doLockB(wh,2);
	add_FILEY1(FL_Bar,wh,fp);
	unLockB(wh,2);
}
void del_FILEY(FL_Par,const char *wh,FILE *fp){
	Lock locked;

	if( !lMEMUSAGE() ){ return; }
	if( fp == 0 )
		return;
	if( !lSINGLEP() )
		return;
	doLockB(wh,2);
	del_FILEY1(FL_Bar,wh,fp);
	unLockB(wh,2);
}


#undef malloc
const char *FL_F_Malloc;
int FL_L_Malloc;
int inMalloc;
void *Xmalloc(FL_PAR,int pstm,unsigned int z){
	Lock locked;
	void *mp;
	sigfunc sig = setsig("Xmalloc",FL_BAR,z);
	SSigMask sMask; setSSigMask(sMask);
	doLockB("malloc",0);
	inMalloc++; FL_F_Malloc = "Xmalloc"; FL_L_Malloc = __LINE__;
	mp = malloc(z);
	inMalloc--;
	unLockB("malloc-done",0);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	if( mp == NULL ){
		errno = ENOMEM;
		Abort(0,"FAILED Xmalloc(%d) %s:%d\n",z,FL_BAR);
	}
	pushalloc("malloc",FL_BAR,pstm,z,mp);
	return mp;
}
#undef calloc
void *Xcalloc(FL_PAR,int pstm,unsigned int n,unsigned int z){
	Lock locked;
	void *mp;
	sigfunc sig = setsig("Xcalloc",FL_BAR,z);
	SSigMask sMask; setSSigMask(sMask);
	doLockB("calloc",0);
	inMalloc++; FL_F_Malloc = "Xcalloc"; FL_L_Malloc = __LINE__;
	mp = calloc(n,z);
	inMalloc--;
	unLockB("calloc-done",0);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	if( mp == NULL ){
		Abort(0,"FAILED Xcalloc(%d,%d) %s:%d\n",n,z,FL_BAR);
	}
	pushalloc("calloc",FL_BAR,pstm,n*z,mp);
	return mp;
}

#undef free
int numthreads();
int mallocSize(void *p);
void Xfree(FL_PAR,void *p){
	Lock locked;
	sigfunc sig = setsig("Xfree",FL_BAR,-1);
	SSigMask sMask; setSSigMask(sMask);
	doLockB("free",1);
	inMalloc++; FL_F_Malloc = "Xfree"; FL_L_Malloc = __LINE__;
	free(p);
	inMalloc--;
	unLockB("free-done",1);
	resetSSigMask(sMask);
	signal(SIGSEGV,sig);
	popfree("free",FL_BAR,p);
}
#undef realloc
void *Xrealloc(FL_PAR,int pstm,void *p,unsigned int z){
	Lock locked;
	void *mp;
	int oz;
	sigfunc sig = setsig("Xrealloc",FL_BAR,z);
	SSigMask sMask; setSSigMask(sMask);
	oz = p ? mallocSize(p) : 0;
	doLockB("realloc",1);
	inMalloc++; FL_F_Malloc = "Xrealloc"; FL_L_Malloc = __LINE__;
	mp = realloc(p,z);
	inMalloc--;
	unLockB("realloc-done",1);
	resetSSigMask(sMask);

if( HEAPCHK )
if( p != 0 && mp != p )
porting_dbg("realloc(%X/%d,%d)=%X %s:%d",
p2i(p),oz,z,p2i(mp),FL_BAR);

	if( mp == NULL ){
		int serrno = errno;
		int nerrno;

		//msleep(10);
		errno = 0;
		setSSigMask(sMask);
		doLockB("realloc-2",1);
		mp = realloc(p,z);
		unLockB("realloc-2-done",1);
		resetSSigMask(sMask);
		nerrno = errno;

porting_dbg("Xrealloc(%X/%d,%d)=%X %s:%d errno=%d,%d th=%d/%d",
p2i(p),oz,z,p2i(mp),FL_BAR,serrno,nerrno,actthreads(),numthreads());

	}

	if( mp != NULL ){
		if( mp != p ){
			popfree("realloc",FL_BAR,p);
			pushalloc("realloc",FL_BAR,pstm,z,mp);
		}
	}

	signal(SIGSEGV,sig);
	if( mp == NULL ){
		Abort(0,"FAILED Xrealloc(%X,%d) %s:%d\n",p,z,FL_BAR);
	}
	return mp;
}

#undef putenv
#if isWindowsCE()
int putenv(const char*env);
#endif
int Xputenv_FL(FL_PAR,const char *env){
	Lock locked;
	int rcode;
	if( lMULTIST() ){
		doLockB("putenv",1);
		rcode = putenv((char*)env);
		if( LOG_VERBOSE )
		porting_dbg("putenv(%s)",env);
		unLockB("putenv-done",1);
	}else{
		SSigMask sMask;
		setSSigMask(sMask);
		rcode = putenv((char*)env);
		resetSSigMask(sMask);
	}
	return rcode;
}

#ifdef _MSC_VER
int open_FL(FL_PAR, const char *path,int flag);
int close_FL(FL_PAR, int fd);
int dup_FL(FL_PAR, int fd);
int dup2_FL(FL_PAR, int sfd,int dfd);
int socketpair_FL(FL_PAR, int d,int t,int p,int v[]);
int accept_FL(FL_PAR, int fdd,void *sa,int *len);
int socket_FL(FL_PAR,int d,int t,int p);

int Xopen_FL(FL_PAR, const char *path,int flag){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("open",2);
		rcode = open_FL(FL_BAR,path,flag);
		unLockB("open-done",2);
	}else{
		rcode = open(path,flag);
	}
	return rcode;
}
/* may block seconds for linger. */
int Xclose_FL(FL_PAR, int fd){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("close",2);
		rcode = close_FL(FL_BAR,fd);
		unLockB("close-done",2);
	}else{
		rcode = close(fd);
	}
	return rcode;
}
int Xdup_FL(FL_PAR, int fd){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("dup",2);
		rcode = dup_FL(FL_BAR,fd);
		unLockB("dup-done",2);
	}else{
		rcode = dup(fd);
	}
	return rcode;
}
int Xdup2_FL(FL_PAR, int sfd,int dfd){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("dup2",2);
		rcode = dup2_FL(FL_BAR,sfd,dfd);
		unLockB("dup2-done",2);
	}else{
		rcode = dup2(sfd,dfd);
	}
	return rcode;
}
int Xsocketpair_FL(FL_PAR,int d,int t,int p,int v[]){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("socketpair",2);
		rcode = socketpair_FL(FL_BAR,d,t,p,v);
		unLockB("socketpair-done",2);
	}else{
		rcode = socketpair(d,t,p,v);
	}
	return rcode;
}
int Xaccept_FL(FL_PAR,int fd,void *sa,int *len){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("accept",2);
		rcode = accept_FL(FL_BAR,fd,sa,len);
		unLockB("accept-done",2);
	}else{
		rcode = accept(fd,sa,len);
	}
	return rcode;
}
int Xsocket_FL(FL_PAR,int d,int t,int p){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("socket",2);
		rcode = socket_FL(FL_BAR,d,t,p);
		unLockB("socket-done",2);
	}else{
		rcode = socket(d,t,p);
	}
	return rcode;
}

#undef filemmap
#undef freemmap
MMap *Xfilemmap_FL(FL_PAR,PCStr(fname),PCStr(fmode),int off,int len){
	MMap *mm;
	if( isWindows() ){
		Lock locked;
		doLockB("filemmap",2);
		mm = filemmap(fname,fmode,off,len);
		unLockB("filemmap-done",2);
	}else{
		mm = filemmap(fname,fmode,off,len);
	}
	return mm;
}
int Xfreemmap_FL(FL_PAR,MMap *mm){
	int rcode;
	if( isWindows() ){
		Lock locked;
		doLockB("freemmap",2);
		rcode = freemmap(mm);
		unLockB("freemmap-done",2);
	}else{
		rcode = freemmap(mm);
	}
	return rcode;
}

#else
#endif

static int ignRet;
int *IgnRet(FL_PAR){
	if( lRETERR() ){
		fprintf(stderr,"--{%d} %s:%d\n",ignRet,FL_BAR);
	}
	return &ignRet;
}
