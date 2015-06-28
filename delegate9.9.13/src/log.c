/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	delegated (DeleGate Server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950525	extracted from delegated.c
	950525	reformed to be independent of DeleGate
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"

#ifdef daVARGS
#undef VARGS
#define VARGS daVARGS
#endif

#include "vsocket.h" /* VSAddr for HostSet */
#include "vsignal.h" /* for sigblock() */
#include "ysignal.h"
#include "dglib.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "log.h"
LogControlSet(2);

int INHERENT_link();
int WITH_symlink();
void DO_FINALIZE(int code);
int procIsAlive(int pid);
void send_syslogX(PCStr(lclass),PCStr(log));
/*
void LOG_makeTime(MemFile *MemF,int now,int usec);
*/
void LOG_makeTime(PVStr(buf),int now,int usec);
int getLockFile(PCStr(dir),PCStr(file),PVStr(lkpath));
/*
void xferlog(PVStr(log),int start,PCStr(chost),int size,PCStr(path),int bin,int in, int anon,PCStr(user),PCStr(auser));
*/
void xferlog(PVStr(log),int start,PCStr(chost),FileSize rsize,FileSize size,PCStr(md5),PCStr(path),int bin,int in, int anon,PCStr(user),PCStr(auser));
void loglog(PCStr(fmt),...);

Logfile *LOG_create(PCStr(proto),PCStr(filters),PCStr(logform),PCStr(pathform),PCStr(mode),int dolock);

void BeforeExit();
void LOG_write(Logfile *LogF,PCStr(str),int leng);
static void LOG_flush(Logfile *logF,int now);
static int fputlog(int flags,PCStr(str),FILE *fp);
static void FatalTraceLog(PCStr(which),PCStr(fmt),...);
void lputLog(PCStr(sel),Logfile *logF,PCStr(fmt),...);

#define NOLOG	((FILE*)-1)
#define RIGHTNOW	-1

#define LINESIZE	0x4000
#define PATHLENG	1024

const char *(*LOG_stdlogfile)();
substFile *LOG_substfile;

int LOG_initFd = -1;
int LOG_init_enable;
int LOG_public;
int LOG_center = -1;

#define NUMLOCKS 32
typedef struct {
	int	l_pid; /* the owner of this lock file */
	int	l_fd;
	int	l_group;
  const	char   *l_port;
	defQStr(l_path);
} Lock;
typedef void (*vcFUNCP)(const char*,const void*);
typedef struct {
  const	char	*x_what;
	vcFUNCP	 x_func;
  const void	*x_arg;
	int	 x_pid;
	int	 x_done;
} XFunc;

typedef struct {
	Logfile	le_LogFiles[32]; /**/
	int	le_numLogFiles;
	Logfile le_tmpF;
	Logfile le_PortF;
	Logfile le_CCF;
	Lock	le_Locks[NUMLOCKS]; /**/
	int	le_ClientCountFilePID;
	MStr(	le_ClientCountFile,256);
	MStr(	le_Myport,64);
  const	char   *le_unlinkv[256]; /**/
	int	le_unlinks;
	XFunc	le_before_exits[16]; /**/
	int	le_before_exitX;

	Logfile *le_LogAbort;
	char    *le_publog;
	Logfile *le_errorTraceLog[2]; /**/
	FILE   *le_StatFp;
  const	char   *le_actdir;
  const	char   *le_admdir;
} LogEnv;
static LogEnv *logEnv;
#define LE	logEnv[0]
#define LogFiles	LE.le_LogFiles
#define numLogFiles	LE.le_numLogFiles
#define tmpF		LE.le_tmpF
#define PortF		LE.le_PortF
#define CCF		LE.le_CCF
#define Locks		LE.le_Locks
#define ClientCountFilePID LE.le_ClientCountFilePID
#define ClientCountFile	LE.le_ClientCountFile
/**/
#define Myport		LE.le_Myport
/**/
#define unlinkv		LE.le_unlinkv
#define unlinks		LE.le_unlinks
#define before_exits	LE.le_before_exits
#define before_exitX	LE.le_before_exitX

#define LogAbort	LE.le_LogAbort
#define publog		LE.le_publog
#define errorTraceLog	LE.le_errorTraceLog
#define StatFp		LE.le_StatFp
#define actdir		LE.le_actdir
#define admdir		LE.le_admdir

#define LogF0		LogFiles[0]
#define MAXLENG		0x10000

void minit_logs(){
	if( logEnv == 0 ){
		logEnv = NewStruct(LogEnv);
		numLogFiles = 1;
	}
}

char LP_NOTTY[] = "NoTTY";
char LF_LOGFILE[]  = "LOGFILE";
char LF_ERRORLOG[] = "ERRORLOG";
char LF_TRACELOG[] = "TRACELOG";
char LF_PROTOLOG[] = "PROTOLOG";
char LF_ABORTLOG[] = "ABORTLOG";
char LF_STDOUTLOG[]= "STDOUTLOG";

const char LS_VERBOSE[] = "V";
const char LS_DEBUG[] = "D";
const char LS_USUAL[] = "U";
const char LS_TERSE[] = "T";
const char LS_ERROR[] = "E";
const char LS_FATAL[] = "F";
const char LS_ACCESS[] = "A";

#define LOG_buffered(logF)	(logF->l_buff && logF->l_buff[0])
#define isPROTOLOG(lF)		(lF->l_filters && streq(lF->l_filters,LF_PROTOLOG))

int static log_flush(Logfile *logF,FILE *fp)
{	int rcode;

	if( logF == NULL )
		return 0;

	if( logF->l_abandon || fp == NULL )
		rcode = 0;
	else{
		int flags;
		flags = (logF == LogAbort) ? 0x02 : 0;
		rcode = fputlog(flags,logF->l_buff,fp);
	}

	logF->l_leng = 0;
	if( logF->l_buff )
	setVStrEnd(logF->l_buff,0);
	return rcode;
}

void setAbortLog(PCStr(form))
{	const char *buff;

	if( form ){
		LogAbort = LOG_create("abortlog",LF_ABORTLOG,"-",form,"a",0);
		LogAbort->l_abandon = 1;
		if( buff = getStrBuffer(SB_PROC,MAXLENG,1) ){
			LogAbort->l_dontfree = 1;
			LogAbort->l_size = MAXLENG;
			setQStr(LogAbort->l_buff,(char*)buff,MAXLENG);
		}
	}
}
int putAbortLog(FILE *fp)
{
	if( LogAbort && LogAbort->l_buff )
		return fwrite(LogAbort->l_buff,1,LogAbort->l_leng,fp);
	else	return -1;
}
void AbortLog(){
	int abandon;

	if( LogAbort ){
		LOG_write(LogAbort,"\n",1);
		abandon = LogAbort->l_abandon;
		LogAbort->l_abandon = 0;
		LOG_flush(LogAbort,time(0));
		LogAbort->l_abandon = abandon;
	}
}
void clrAbortLog(){
	log_flush(LogAbort,NULL);
}

/*
static int *stack0,*stackm;
checkStackSize(arg)
{

	if( stack0 == NULL || (unsigned int)stack0 < ((unsigned int)&arg) ){
		stack0 = &arg;
		if( stackm == NULL )
			stackm = stack0;
	}
	if( ((unsigned int)&arg) < ((unsigned int)stackm) ){
		stackm = &arg;
		fprintf(stderr,"#### STACK SIZE #### %8d\n%s\n",
			(unsigned int)stack0-(unsigned int)stackm,arg);
		sleep(3);
	}
}
*/

static FILE *pplog;
void putpplog(PCStr(fmt),...){
	VARGS(8,fmt);

return;
	if( pplog == NOLOG ){
		return;
	}
	if( pplog == 0 ){
		CStr(path,128);
		sprintf(path,"c:/tmp/plog/%d",getpid());
		pplog = fopen(path,"w");
		if( pplog == 0 ){
			pplog = NOLOG;
			return;
		}
	}
	if( pplog ){
		fprintf(pplog,"[%X] ",getthreadid());
		fprintf(pplog,fmt,VA8);
		fflush(pplog);
	}
}
void closepplog(){
	FILE *plog;
	if( plog = pplog ){
		pplog = 0;
		fclose(plog);
	}
}

FILE *logMonFp();
extern FILE *logTeeFp;
static int fputlog(int flags,PCStr(str),FILE *fp)
{	int rcode;
	int len;
	int wcc;
	int xpublic = flags & 0x01;
	int noapab = flags & 0x02; /* don't append to LogAbort */

	if( lCONSOLE() ){
		if( logTeeFp ){
			fputs(str,logTeeFp);
		}else{
			fputs(str,stderr);
			addCR(stderr,fileno(stderr),str);
		}
	}
	if( logMonFp() ){
		fputs(str,logMonFp());
		fflush(logMonFp());
	}
	putpplog("%s",str);
/*
	checkStackSize(str);
*/
	len = strlen(str);

	if( 0 < len && fp != NULL && fp != NOLOG ){
		fseek(fp,0,2);
		fputs(str,fp);
		rcode = fflush(fp);
	}else	rcode = 0;

	if( 0 < len ){
		if( (xpublic || LOG_public) && 0 <= LOG_center ){
			wcc = write(LOG_center,str,len);
			Verbose("sendlog[%d] %s",wcc,str);
		}

		if( LogAbort )
		if( noapab == 0 )
			LOG_write(LogAbort,str,len);
	}
	return rcode;
}

int logVERBOSE(){ return LOG_VERBOSE; }
extern int START_TIME;

static FILE *_UDPsockfp;
FILE *logUDPsockfp(){
	return _UDPsockfp;
}
void setupUDPlog(DGC*Conn){
	int sv[2];
	IStr(host,128);
	int port;
	int as;

	sv[0] = sv[1] = -1;
	if( 0 ){
		strcpy(host,"127.255.255.255");
		sv[0] = server_open("UDPlog",AVStr(host),0,-1);
		if( 0 <= sv[0] ){
			setsockREUSE(sv[0],1);
			port = sockPort(sv[0]);
			sv[1] = UDP_client_open("UDPlog","UDPlog",host,port);
			sv1log("UDPlog port=%d[%s][%d,%d]\n",port,host,
				sv[0],sv[1]);
			if( sv[1] < 0 ){
				sv[0] = -1;
			}else{
			}
		}else{
			sv[1] = -1;
		}
	}
	if( sv[0] < 0 ){
		UDP_Socketpair(sv);
		sv1log("LOG-Socketpair[%d,%d]\n",sv[0],sv[1]);
	}
	LOG_UDPsockfd[0] =
	LOG_UDPsock[0] = sv[0];
	LOG_UDPsockfd[1] =
	LOG_UDPsock[1] = sv[1];
	if( !lSINGLEP() && isWindows() ){
		LOG_UDPsockfh[0] = SocketOf(LOG_UDPsock[0]);
		LOG_UDPsockfh[1] = SocketOf(LOG_UDPsock[1]);
	}
	if( !lSINGLEP() ){
		_UDPsockfp = fdopen(LOG_UDPsockfd[1],"w");
	}
}
int closeLOG_UDPsock(){
	int fd0,fd1;
	if( 0 <= LOG_UDPsockfd[0] && 0 <= LOG_UDPsockfd[0] ){
		fd0 = LOG_UDPsockfd[0];
		fd1 = LOG_UDPsockfd[1];
		LOG_UDPsockfd[0] = -1;
		LOG_UDPsockfd[1] = -1;
		close(fd0);
		close(fd1);
		sv1log("## closed LOG-Socketpair[%d][%d]\n",fd0,fd1);
	}
	return 0;
}
static int doUDPlog(PCStr(wh),PCStr(sel)){
	int sc = sel ? *sel : 0;

	if( lLOGCTRL() ){
		fprintf(stderr,"--%c%c%c (%c) %s \n",
			lSILENT_T()?'s':'-',lTERSE_T()?'t':'-',
			lVERB_T()?'d':'-',sc?sc:'-',wh
		);
	}
	if( lSILENT_T() && sc != 'P' ){
		return 0;
	}
	if( !lVERB_T() && sc && sc == 'D' ){
		return 0;
	}
	if( lTERSE_T() && sc )
	if( sc != 'E' && sc != 'F' && sc != 'T' && sc != 'P' ){
		return 0;
	}
	return 1;
}
int sendLog(int sock,PCStr(str),int len);
static void putUDPlog(PCStr(wh),PCStr(sel),PCStr(str),int len){
	int now;

	if( lNOUDPLOG() ){
		return;
	}
	if( !lPUTUDPLOG() || LOG_UDPsock[1] < 0 ){
		return;
	}
	now = time(0);
	if( lPUTUDPLOG() < now ){
		if( lLOGCTRL() ){
			fprintf(stderr,"[%u] disabled UDPLOG: %d<%d\n",
				getpid(),lPUTUDPLOG(),now);
		}
		lPUTUDPLOG() = 0;
		return;
	}
	if( !doUDPlog(wh,sel) ){
		return;
	}
	sendLog(LOG_UDPsock[1],str,len);
}

int CHILD_SERNO;
int CHILD_SERNO_MULTI;
int CHILD_SERNO_SINGLE;
int SERNO(){ return CHILD_SERNO; }
int SERNO_MINOR(){ return CHILD_SERNO_MULTI; }
int MySeqNum(){ return (CHILD_SERNO<<16) + (CHILD_SERNO_MULTI+CHILD_SERNO_SINGLE); }

#define LOGFILE_ACTIVE(fp) (fp!=NULL && fp!=NOLOG && fp!=stderr)
#define LOGFILE_OPENED(fp) (fp!=NULL && fp!=NOLOG)
#define Lfileno(fp) (LOGFILE_OPENED(fp) ? fileno(fp) : -1)

static int locked_fclose(Logfile *logF)
{	FILE *fp;
	FILE *fp1;
	int rcode,lkfd,lkrcode,elapsed;
	int logfd;
	Logfile *logf;
	int li;

	fp = logF->l_fp;
	rcode = 0;

	if( !LOGFILE_ACTIVE(fp) )
		goto EXIT;

	for( li = 0; li < numLogFiles; li++ ){
		logf = &LogFiles[li];
		fp1 = logf->l_fp;
		if( fp1 == fp && logF != logf )
			goto EXIT;
	}

	logfd = fileno(fp);
	lkfd = -1;
	if( logF->l_dolock ){
		if( (lkfd = logF->l_lockfd) < 0 )
			lkfd = logfd;
		if( 0 <= lkfd )
			lkrcode = lock_exclusiveTO(lkfd,5*1000,&elapsed);
	}

	/* explicit unlock seems necessary
	 * when another process is openning the file ... */
	if( lkfd == logfd && lkrcode == 0 )
		lock_unlock(lkfd);

	rcode = fclose(fp);

	if( logF->l_dolock ){
		if( 0 <= logF->l_lockfd ){
			close(logF->l_lockfd);
			logF->l_lockfd = -1;
		}
	}

EXIT:
	logF->l_fp = NULL;
	return rcode;
}
static int locked_fflush(Logfile *logF)
{	FILE *fp;
	int rcode,lkfd,lkrcode,elapsed;

	fp = logF->l_fp;
	lkfd = -1;
	if( logF->l_dolock && LOG_buffered(logF) ){
		if( (lkfd = logF->l_lockfd) < 0 )
			lkfd = fileno(fp);
		if( 0 <= lkfd )
			lkrcode = lock_exclusiveTO(lkfd,5*1000,&elapsed);
	}

	if( logF->l_buff )
		rcode = log_flush(logF,fp);
	else	rcode = fflush(fp);

	if( 0 <= lkfd )
		lock_unlock(lkfd);

	return rcode;
}

static void setLogf(Logfile *logF,FILE *fp)
{	FILE *Fp;

	if( logF == NULL )
		return;
	if( logF->l_fp == fp )
		return;

	Fp = logF->l_fp;
	if( LOGFILE_OPENED(Fp) ){
		fprintf(stderr,
		"DeleGate[%d] overwrite log entry! %x[%d]->%x[%d] %s\n",
			getpid(),p2i(Fp),Lfileno(Fp),p2i(fp),Lfileno(fp),
			logF->l_pform?logF->l_pform:"(NoFileName)");
		locked_fclose(logF);
	}
	logF->l_fp = fp;
}
static void Lclose(Logfile *logF)
{
	if( LOGFILE_ACTIVE(logF->l_fp) )
		locked_fclose(logF);
	logF->l_fp = NULL;
}
static int closeAgedLog1(Logfile *Logf,int now)
{
	if( Logf != NULL )
	if( LOGFILE_ACTIVE(Logf->l_fp) )
	if( now == RIGHTNOW || Logf->l_until != 0 && Logf->l_until <= now )
	{
/*
should not write such a debug info into the logfile like http.log ...
if( SERNO_MINOR() == 0 ){
fseek(Logf->l_fp,0,2);
LOG_putTime(Logf->l_fp);
 fprintf(Logf->l_fp,"Check logfile age: %s\n",Logf->l_path);
}
*/
		Lclose(Logf);
		return 1;
	}
	return 0;
}

static void substDate1(PVStr(file),PVStr(link),PCStr(tag),int date)
{
	refQStr(fdp,file); /**/
	refQStr(ldp,link);
	const char *np;
	const char *tp;
	CStr(format,256);

	while( ldp = strstr(link,tag) ){
		if( tp = strchr(link,']') ){
			strcpy(ldp,tp+1);
		}else{
			fprintf(stderr,"missing ']' for %s...\n",tag);
			break;
		}
	}

	while( fdp = strstr(file,tag) ){
		np = fdp + strlen(tag);
		strcpy(format,np);
		if( tp = strchr(format,']') ){
			truncVStr(tp); tp++;
			StrftimeLocal(AVStr(fdp),32,format,date,0);
			strcat(fdp,tp);
		}else{
			fprintf(stderr,"missing ']' for %s...\n",tag);
			break;
		}
	}
}
static int substDate(PVStr(file),PVStr(link),int now,int start)
{
	strcpy(link,file);
	substDate1(AVStr(file),AVStr(link),"[date+",now);
	substDate1(AVStr(file),AVStr(link),"[start+",start);
	if( strcmp(file,link) != 0 )
		return 1;
	else	return 0;
}
int StrSubstDate(PVStr(str))
{	CStr(tmp,1024);

	return substDate(AVStr(str),AVStr(tmp),time(0),START_TIME);
}
int StrSubstDateX(PVStr(str),PVStr(cur))
{
	return substDate(AVStr(str),AVStr(cur),time(0),START_TIME);
}

/*
 * assuming that log file name is valid at least in the same minute.
 */
#define AGEBYINC 0
static int xdate[] = { 60, 60, 24, 7, 0 };
static int valid_until(PCStr(filefmt),int now)
{	int until,step,stepi;
	CStr(file1,PATHLENG);
	CStr(file2,PATHLENG);
	CStr(current,PATHLENG);

	strcpy(file1,filefmt); substDate(AVStr(file1),AVStr(current),now,START_TIME);
	step = 24 * 3600 * 7;
	until = now;

    if( AGEBYINC ){
	step = 1;
	until = now;
	for( stepi = 0; xdate[stepi]; stepi++ ){
		step *= xdate[stepi];
		until += step;
		strcpy(file2,filefmt);
		substDate(AVStr(file2),AVStr(current),until,START_TIME);
		if( strcmp(file1,file2) != 0 )
			break;
	}
    }else{
	step /= 2;
	until += step;
	for( stepi = 0; 0 < step; stepi++ ){
		strcpy(file2,filefmt);
		substDate(AVStr(file2),AVStr(current),until,START_TIME);
		step /= 2;
		if( strcmp(file1,file2) == 0 )
			until += step;
		else	until -= step;
	}
	if( strcmp(file1,file2) == 0 )
		until += 60;
     }
	if( until < now + 60 )
		until = now + 60;
	until = (until / 60) * 60;
	return until;
}

static void makeAbspath(PVStr(file),PCStr(base))
{	CStr(tmp,PATHLENG);

	if( !isBoundpath(file) ){
		strcpy(tmp,file);
		setVStrEnd(file,0);
		strcats3(AVStr(file),base,"/",tmp);
	}
}

/*
 * Unlinking an opened NFS file (inode) will produce a .nfsXXXX file.
 * This will happen when one of possible multiple hard links of the file
 * is opened.  Moreover on Solaris2.5, repetitive link & unlink will
 * produce multiple .nfsXXXX files...
 * - the link to the current file should be symbolic link on Unix ?
 * - previous one can be moved to LOGDIR/prev/LOGFILE if it is a symlink.
 * - unlinking could be done by rename() safely ?
 * - should wait until all referers of the file will close it ?
 * - old "current" link with only one link count must be backed up.
 */
static FILE *agefile(FILE *ofp,PCStr(file),PCStr(current),PCStr(mode),PCStr(tmpdir))
{	CStr(agelock,PATHLENG);
	CStr(lkpath,PATHLENG);
	int was_active;
	int lockfd = -1;
	FILE *nfp;

	was_active = LOGFILE_ACTIVE(ofp);

	if( WITH_symlink() && !INHERENT_link() ){
		CStr(lcurrent,PATHLENG);
		CStr(rcurrent,PATHLENG);
		if( strtailstr(current,".lnk") == 0 ){
			sprintf(lcurrent,"%s.lnk",current);
			path_escchar(AVStr(lcurrent));
			current = lcurrent;
		}
		if( readlink(current,rcurrent,sizeof(rcurrent)) == 0 ){
			if( File_cmp(file,rcurrent) == 0 )
				return ofp;
			unlink(current);
		}
		IGNRETZ symlink(file,current);
		if( was_active )
			fclose(ofp);
		nfp = fopen(file,mode);
		return nfp;
	}

loglog("agefile(%x,%s,%s,%s,%s) %d\n",ofp,file,current,mode,tmpdir,was_active);

	if( File_cmp(file,current) == 0 ){
		if( was_active ){
			/* if the active file is obsoleted, reopen it... */
			if( file_ino(fileno(ofp)) != File_ino(current) )
				goto REOPEN;
		}
		return ofp;
	}

	sprintf(agelock,"%s.aging",current);
	lockfd = getLockFile(tmpdir,agelock,AVStr(lkpath));
loglog("#### agelock=%s %s [%d]\n",agelock,lkpath,lockfd);
	if( 0 <= lockfd && lock_exclusiveTO(lockfd,20*1000,NULL) != 0 )
		goto REOPEN;

	/* another process may aged the file during waiting for lock */
	if( File_cmp(file,current) == 0 )
		goto REOPEN;

loglog("AGEFILE(%x,%s,%s,%s,%s) %d\n",ofp,file,current,mode,tmpdir,was_active);

	if( File_is(current) && 0 < File_size(file) ){
		CStr(aged,PATHLENG);
		const char *aged_ext;
		CStr(ext,256);
		int rcode;
		aged_ext = getenv("AGEDFILEEXT");
		if( aged_ext == 0 || *aged_ext == 0 )
			aged_ext = "-%Y%m%d%H%M%S.old";
		StrftimeLocal(AVStr(ext),sizeof(ext),aged_ext,File_mtime(file),0);
		sprintf(aged,"%s%s",file,ext);
		rcode = rename(file,aged);
		File_touch(file,time(0));
loglog("AGEFILE rename(%s,%s)=%d\n",file,aged,rcode);
	}

	unlink(current);
	linkRX(file,current); /* should use symbolic link ? */

REOPEN:
	nfp = fopen(file,mode);
	if( nfp == NULL ){
		CStr(names,1024);
		CStr(msg,1024);
		FILE *tfp;

		sprintf(msg,"Can't fopen(\"%s\",\"%s\") by %s",file,mode,
			getusernames(AVStr(names)));

		if( was_active )
			fprintf(ofp,"#### %s\n",msg);
		else
		if( tfp = fopen(current,"a") ){
			fprintf(tfp,"#### %s\n",msg);
			fclose(tfp);
		}else{
			fprintf(stderr,"DeleGate: %s\n",msg);
		}
	}
	if( was_active )
		fclose(ofp);

	if( 0 <= lockfd )
		close(lockfd);

	return nfp;
}

static FILE *open_logtmpfile(Logfile *Logf,int istmp,PCStr(form),PCStr(mode),PCStr(proto))
{
	CStr(file,PATHLENG);
	CStr(current,PATHLENG);
	CStr(filefmt,PATHLENG);
	CStr(vardir,PATHLENG);
	CStr(logdir,PATHLENG);
	CStr(tmpdir,PATHLENG);
	int now;
	int linked;
	FILE *fp;
	CStr(lkpath,PATHLENG);

	if( form == NULL || *form == 0 )
		return NOLOG;
	if( strcmp(form,"-stderr") == 0 )
		return stderr;

	strcpy(file,form);
	if( LOG_substfile != NULL )
		(*LOG_substfile)(AVStr(file),proto,AVStr(vardir),AVStr(logdir),AVStr(tmpdir));
	if( istmp )
		makeAbspath(AVStr(file),tmpdir);
	else	makeAbspath(AVStr(file),logdir);
	now = time(0);
	strcpy(filefmt,file);
	linked = substDate(AVStr(file),AVStr(current),now,START_TIME);

	if( Logf->l_fp == NULL )
		setLogf(Logf,NOLOG);

	fp = dirfopen("LOG-ACT",AVStr(file),mode);
	/*
	if( lARGDUMP() ){
	*/
	if( lFILETRACE() ){
		fprintf(stderr,"open:   %x %s (%s,%s)=%x\n",
			p2i(Logf),form,file,mode,fp==NULL?-1:fileno(fp));
		sleep(1);
	}
	if( fp == NULL ){
		/*ERRMSG("Warning: cannot open logfile %s\n",file);*/
		fp = NOLOG;
	}

	if( fp != NOLOG )
	if( Logf->l_filters && streq(Logf->l_filters,"STDOUTLOG") ){
		dup2(fileno(fp),1);
		dup2(fileno(fp),2);
	}
	if( fp == NOLOG )
	if( Logf->l_filters && streq(Logf->l_filters,"STDOUTLOG") ){
		if( isatty(fileno(stderr)) )
		fprintf(stderr,"\r\n#### [%d] cannot open STDOUTLOG: %s\r\n",
			getpid(),file);
	}

	if( linked ){
		makeAbspath(AVStr(current),logdir);
		fp = agefile(fp,file,current,mode,tmpdir);
		if( fp == NULL )
			fp = NOLOG;
		Logf->l_until = valid_until(filefmt,now);

 {
 CStr(next,64);
 StrftimeLocal(AVStr(next),sizeof(next),TIMEFORM_HTTPD,Logf->l_until,0);
 loglog("valid_until: next=[%s] cur=[%s] fp=%x\n",next,file,fp);
 }
	}

	if( fp != NOLOG && Logf != NULL ){
		Strdup((char**)&Logf->l_pform,form);
		Strdup((char**)&Logf->l_path,file);
		Strdup((char**)&Logf->l_mode,mode);
		setLogf(Logf,fp);
		if( Logf->l_dolock && Logf->l_lockfd < 0 ){
			Logf->l_lockfd = getLocalLock(fp,tmpdir,current,AVStr(lkpath));
			if( 0 <= Logf->l_lockfd ){
				/*
				if( lARGDUMP() )
				*/
				if( lFILETRACE() )
					fprintf(stderr,"##REMOTE:%s\n",current);
				Strdup((char**)&Logf->l_lkpath,lkpath);
			}
		}
	}
	return fp;
}

static FILE *open_tmpfile(Logfile *Logf,PCStr(form),PCStr(mode),PCStr(proto))
{	FILE *fp;

	fp = open_logtmpfile(Logf,1,form,mode,proto);
	if( fp == NOLOG )
		return NULL;
	else	return fp;
}

#if defined(__APPLE__)
/* to escape leak? (by unknown reason) of file-descriptor on SIGHUP */
int DUP_TTYLOGFD = 1;
#else
int DUP_TTYLOGFD = 0;
#endif

FILE *open_logfile(Logfile *Logf,PCStr(form),PCStr(mode),PCStr(proto))
{	FILE *fp;

	if( lTTY() && !Logf->l_notty )
	{
		if( DUP_TTYLOGFD ){
			fp = fdopen(dup(fileno(stderr)),"a");
		}else
		fp = stderr;
	}
	else	fp = open_logtmpfile(Logf,0,form,mode,proto);
	setLogf(Logf,fp);
	return fp;
}

static Logfile *findlog(PCStr(proto),PCStr(filter1),int options,int wildon)
{	int li;
	Logfile *logF;
	const char *proto1;
	const char *filters;

	if( streq(filter1,LF_LOGFILE) ){
		/* 9.2.3 LogF0 == LogFiles[0] is reserved for "LOGFILE"
		 * its attribute including l_proto and l_filters
		 * might not be initialized when it is retrieved.
		 * (as in the case it is set by fdopenLogFile() invoked
		 * with -x option on Unix)
		 */
		logF = &LogF0;
		/*
		fprintf(stderr,"---- findlog LOGFILE=%X [%s][%s]\n",logF,
			logF->l_proto?logF->l_proto:"UNDEF",
			logF->l_filters?logF->l_filters:"UNDEF");
		*/
		return logF;
	}
	logF = NULL;
	for( li = 0; li < numLogFiles; li++ ){
		logF = &LogFiles[li];
		proto1 = logF->l_proto;

		if( proto1 != 0 )
		if( wildon && streq(proto1,"*") || strcaseeq(proto1,proto) )
		if( filters = logF->l_filters ){
			if( strcmp(filter1,filters) == 0 )
				goto EXIT;
			if( (options & LW_EXMATCH) == 0 ){
				if( wildon && streq(filters,"*") )
					goto EXIT;
				if( strstr(filters,filter1) )
					goto EXIT;
			}
		}
	}
	logF = NULL;
EXIT:
	return logF;
}
Logfile *LOG_which(PCStr(proto),PCStr(filter1),int options)
{	Logfile *logF;

	logF = findlog(proto,filter1,options,0);
	if( logF == NULL )
		logF = findlog(proto,filter1,options,1);
	if( logF == NULL && (options & LW_CREATE) ){
		if( elnumof(LogFiles) <= numLogFiles ){
			return &LogFiles[0];
		}
		logF = &LogFiles[numLogFiles++];
	}

	if( lFILETRACE() )
	    fprintf(stderr,"[%d] >> LOG_which(%s,%s) = %s\n",
		getpid(),proto,filter1,
		(logF&&logF->l_path)?logF->l_path:"<not-enabled>");
	return logF;
}
static Logfile *HTTPlog;
Logfile *HTTP_PROTOLOG(){
	if( HTTPlog == 0 ){
		HTTPlog = LOG_which("http",LF_PROTOLOG,0);
	}
	return HTTPlog;
}

const char *LOG_format(Logfile *logF)
{
	return logF->l_lform;
}
const char *LOG_buffer(Logfile *logF)
{
	return logF->l_buff;
}

static void setLogParams(Logfile *logF,PCStr(proto),PCStr(filters),PCStr(logform),PCStr(mode),PCStr(pathform),int dolock)
{

	/*
	if( lARGDUMP() )
	*/
	if( lFILETRACE() )
	    fprintf(stderr,"[%d] LOG(%-8s, %-8s, %1s, %1s, %-26s) %x %x\n",
		getpid(),proto,filters,logform,mode,pathform,p2i(logF),p2i(logF->l_fp));

	Strdup((char**)&logF->l_proto,  proto);
	Strdup((char**)&logF->l_pform,  pathform);
	Strdup((char**)&logF->l_filters,filters);
	Strdup((char**)&logF->l_lform,  logform);
	Strdup((char**)&logF->l_mode,   mode);
	logF->l_dolock = dolock;
	logF->l_notty = strcmp(proto,LP_NOTTY) == 0;
	logF->l_lockfd = -1;
}
Logfile *LOG_create(PCStr(proto),PCStr(filters),PCStr(logform),PCStr(pathform),PCStr(mode),int dolock)
{	Logfile *logF;

	logF = LOG_which(proto,filters,LW_EXMATCH|LW_CREATE);
	if( LOGFILE_ACTIVE(logF->l_fp) )
		Lclose(logF);
	setLogParams(logF,proto,filters,logform,mode,pathform,dolock);
	LOG_GENERIC = 1;
	return logF;
}

static void LOG_pop(Logfile *savF,Logfile *logF,int siz,PCStr(what))
{ 
	LOG_flush(logF,time(0));
	*logF = *savF;
}
void LOG_push(DGC*Conn,PCStr(proto),PCStr(filters),PCStr(logform),PCStr(pathform),PCStr(mode),int dolock)
{	Logfile *logF,*xnew;
	CStr(path,1024);
	CStr(buff,1024);
	CStr(xproto,64);

	logF = LOG_which(proto,filters,LW_EXMATCH);
	if( logF == 0 )
		return;

	LOG_flush(logF,time(0));
	xmem_push(logF,sizeof(Logfile),"LOG_push",(iFUNCP)LOG_pop);

	/* to reuse the same logfile which is identified by
	 * the combination of {proto,filters,logform,pathform}
	 */
	lineScan(pathform,path);
	Substfile(path);
	sprintf(buff,"%s %s %s %s",proto,filters,logform,path);
	toMD5(buff,xproto);
	xnew = LOG_which(xproto,filters,LW_EXMATCH);
	if( xnew == NULL )
		xnew = LOG_create(xproto,filters,logform,pathform,mode,dolock);
	*logF = *xnew;
}
void scan_LOGFILE(DGC*Conn,PCStr(pathform))
{
	LOG_push(Conn,"delegate",LF_LOGFILE,"-",pathform,"a",0);
}

FILE *LOG_open(Logfile *logF)
{
	if( logF->l_pform == NULL ){
		return NULL;
	}
	return open_logfile(logF,logF->l_pform,logF->l_mode,logF->l_proto);
}
FILE *LOG_file(Logfile *logF){
	if( logF == NULL )
		return NULL;
	closeAgedLog1(logF,time(NULL));
	if( logF->l_fp == NULL ){
		open_logfile(logF,logF->l_pform,logF->l_mode,logF->l_proto);
	}
	if( LOGFILE_ACTIVE(logF->l_fp) )
		return logF->l_fp;
	else	return NULL;
}

#define LOGCHUNK	(MAXLENG/8)

void LOG_write0(Logfile *LogF,PCStr(str),int leng);
void LOG_write1(Logfile *LogF,PCStr(str),int leng);
static CriticalSec logbufCSC;
void LOG_write(Logfile *LogF,PCStr(str),int leng)
{
	SSigMask sMask;
	setSSigMaskX(sMask,1);
	if( numthreads() ){
		setupCSC("LOG_write",logbufCSC,sizeof(logbufCSC));
		enterCSC(logbufCSC);
	}
	LOG_write1(LogF,str,leng);
	if( numthreads() ){
		leaveCSC(logbufCSC);
	}
	resetSSigMask(sMask);
}
void LOG_write1(Logfile *LogF,PCStr(str),int leng)
{
	int ex;
	if( ex = LogF->l_ex ){
		double St = Time();
		int leng = LogF->l_leng;
		int ri;
		for( ri = 0; ri < 10; ri++ ){
			usleep(100);
			if( LogF->l_ex == 0 )
				break;
		}
		if( lTHREAD() )
	fprintf(stderr,"[%d.%X] LOG_write ex %.4f/%d (%d %d -> %d %d)\n",
			getpid(),getthreadid(),Time()-St,ri,
			ex,leng,LogF->l_ex,LogF->l_leng
		);
		if( LogF->l_ex != 0 ){
			return;
		}
	}
	if( 1 < ++LogF->l_ex ){
	fprintf(stderr,"[%d.%X] LOG_write ex batting: %d\n",
			getpid(),getthreadid(),LogF->l_ex);
		--LogF->l_ex;
		return;
	}
	LOG_write0(LogF,str,leng);
	--LogF->l_ex;
}
void LOG_write0(Logfile *LogF,PCStr(str),int leng)
{	const char *buff;
	int inc;

	if( isPROTOLOG(LogF) ){
		send_syslogX(LS_ACCESS,str);
		putUDPlog("PROTOLOG","P",str,leng);
		if( lSILENT() && lSYNC() && lTTY() ){
			return;
		}
	}

	buff = LogF->l_buff;
	if( LogF->l_size < LogF->l_leng + leng + 1 ){
		inc = MAXLENG; /* 9.7.0 to reduce realloc() */
		/*
		inc = (((leng+1)/LOGCHUNK) + 1) * LOGCHUNK;
		*/
		if( MAXLENG < LogF->l_size + inc )
			LogF->l_leng = 0;
		else{
			LogF->l_size += inc;
			setQStr(LogF->l_buff,Malloc((char*)LogF->l_buff,LogF->l_size),LogF->l_size);
		}
	}
	if( LogF->l_buff == NULL ){
		if( LOGFILE_OPENED(LogF->l_fp) ){
			fprintf(LogF->l_fp,"#### FATAL: Malloc(%x,%d) failed.\n",
				p2i(buff),LogF->l_size);
			fflush(LogF->l_fp);
		}
		LogF->l_size = 0;
		return;
	}
	XStrncpy(DVStr(LogF->l_buff,LogF->l_leng),str,leng+1); /**/
	LogF->l_leng += leng;
}

void LOG_printf(Logfile *logF,PCStr(fmt),...)
{	MemFile MemF;
	CStr(msg,LINESIZE);
	VARGS(14,fmt);

	str_sopen(&MemF,"LOG_printf",msg,sizeof(msg),0,"w");
	str_sprintf(&MemF,fmt,VA14);
	LOG_write(logF,msg,strlen(msg));
}

static void LOG_flush(Logfile *logF,int now)
{	FILE *fp;
	int rcode;

	if( !LOG_buffered(logF) )
		return;

	closeAgedLog1(logF,now);
	if( logF->l_fp == NULL )
		LOG_open(logF);
	fp = logF->l_fp;

	if( fp == NULL || fp == NOLOG )
		return;

	rcode = locked_fflush(logF);

	if( rcode == EOF ){
		fprintf(stderr,"DeleGate-LOG_flush: EOF[%d]\n",fileno(fp));
		perror("DeleGate-LOG_flush");
	}
}
void LOG_flushall()
{	int li;
	Logfile *logF;
	int now;

	now = time(0);
	for( li = 0; li < numLogFiles; li++ ){
		logF = &LogFiles[li];
		LOG_flush(logF,now);
	}
}
void LOG_closeall()
{	int li;
	Logfile *logF;
	int now;

	now = time(0);
	for( li = 0; li < numLogFiles; li++ ){
		logF = &LogFiles[li];
		LOG_flush(logF,now);
		Lclose(logF);
	}
}
void LOG_openall()
{	int li;
	Logfile *logF;

	for( li = 0; li < numLogFiles; li++ ){
		logF = &LogFiles[li];
		if( LOGFILE_OPENED(logF->l_fp) ){
			LOG_flush(logF,time(0));
			Lclose(logF);
		}
		LOG_open(logF);
	}
}

void reopenLogFile()
{	CStr(path,PATHLENG);
	CStr(vardir,PATHLENG);
	CStr(logdir,PATHLENG);
	CStr(tmpdir,PATHLENG);

	if( LOG_stdlogfile != NULL )
	if( LogF0.l_path != NULL )
	{
		strcpy(path,(*LOG_stdlogfile)());
		(*LOG_substfile)(AVStr(path),LogF0.l_proto,AVStr(vardir),AVStr(logdir),AVStr(tmpdir));
		if( strcmp(path,LogF0.l_path) != 0 ){
			/*
			if( lARGDUMP() )
			*/
			if( lFILETRACE() )
			    fprintf(stderr,"LOG file switched: %s -> %s\n",
				LogF0.l_path,path);
			Strdup((char**)&LogF0.l_path,path);
			Lclose(&LogF0);
		}
	}
}
FILE *openLogFile(int now)
{
	if( LogF0.l_filters == NULL ){
		/* temporary registration to be found in LOG_which... */
		setLogParams(&LogF0,"delegate",LF_LOGFILE,"","","",0);
	}

	closeAgedLog1(&LogF0,now);

	/* lTTY() might be turn on after NOLOG was set */
	if( LogF0.l_fp == NOLOG && lTTY() )
		LogF0.l_fp = NULL;

	if( LogF0.l_fp == NULL ){
		setLogf(&LogF0,NOLOG); /* suppress log during opening */
		if( LOG_stdlogfile != NULL )
			open_logfile(&LogF0,(*LOG_stdlogfile)(),"a","delegate");
	}
	if( LogF0.l_fp == NOLOG )
		return NULL;

	if( LogF0.l_fp != stderr ) /* if not a tty exactly X-< */
		fseek(LogF0.l_fp,0,2);

	return LogF0.l_fp;
}
void fdopenLogFile(int fd)
{	FILE *fp;

	if( logEnv == NULL ){
		return;
	}
	if( fd < 0 ){
	}else
	if( LogF0.l_fp == NULL || LogF0.l_fp == NOLOG ){
		if( fd == fileno(stderr) )
			fd = dup(fd);
		if( fp = fdopen(fd,"a") )
		{
			setLogf(&LogF0,fp);
			/*
			LogF0.l_proto = strdup("delegate");
			LogF0.l_filters = strdup(LF_LOGFILE);
			*/
		}
	}
}
int dupLogFd()
{	int logfd,nlogfd;

	if( logEnv == NULL )
		return -1;
	if( LogF0.l_fp == NULL || LogF0.l_fp == NOLOG )
		return -1;

	fflush(LogF0.l_fp);
	logfd = fileno(LogF0.l_fp);
	nlogfd = dup(logfd);
	fclose(LogF0.l_fp);
	LogF0.l_fp = fdopen(nlogfd,LogF0.l_mode);
	Verbose("moved fileno(LOGFILE) %d -> %d\n",logfd,nlogfd);
	return nlogfd;
}
int curLogFd()
{	int logfd;

	if( logEnv == NULL )
		return -1;
	else
	if( LogF0.l_fp == NULL || LogF0.l_fp == NOLOG )
		logfd = -1;
	else	logfd = fileno(LogF0.l_fp);
	return logfd;
}
FILE *curLogFp()
{
	if( logEnv == NULL )
		return NULL;
	if( LogF0.l_fp == NULL || LogF0.l_fp == NOLOG )
		return NULL;
	else	return LogF0.l_fp;
}

int logTimeout()
{	int timeout = 0;
	int now = time(0);
	int to;
	int li;
	Logfile *Logf;

	for( li = 0; li < numLogFiles; li++ ){
		Logf = &LogFiles[li];
		if( 0 < Logf->l_until && LOGFILE_ACTIVE(Logf->l_fp) ){
			to = Logf->l_until - now;
			if( 0<to && (timeout==0 || (0<timeout && to<timeout))  )
				timeout = to;
		}
	}
	return timeout;
}
void LOG_checkAged(int renew)
{	int now;
	int checknow;
	int li;
	Logfile *logF;

	if( renew )
		now = RIGHTNOW;
	else{
		now = time(0);
		checknow = 0;
		for( li = 0; li < numLogFiles; li++ ){
			logF = &LogFiles[li];
			if( 0 < logF->l_until && logF->l_until <= now ){
				checknow = 1;
				break;
			}
		}
		if( !checknow )
			return;
	}

	for( li = 0; li < numLogFiles; li++ ){
	    logF = &LogFiles[li];
	    if( logF->l_pform && (logF->l_fp!=NOLOG && logF->l_fp!=stderr) ){
		if( logF->l_fp != NULL ){
			if( closeAgedLog1(logF,now) )
				LOG_open(logF); /* to unlink aged log ... */
		}else{
		    open_logfile(logF,logF->l_pform,"r",logF->l_proto);
		    if( LOGFILE_ACTIVE(LogF0.l_fp) ){
			if( closeAgedLog1(logF,now) )
				LOG_open(logF);
		    }
		    Lclose(logF);
		}
	    }
	}
	/*
	fprintf(stderr,"#### checkAGED done\n");
	checkstdlog("AGED");
	*/
}

void publiclog(PCStr(sel),PCStr(fmt),...)
{	CStr(vmsg,LINESIZE);
	int leng;
	VARGS(14,fmt);

	vmsg[0] = 0;
	sprintf(vmsg,fmt,VA14);
	if( publog == NULL )
		publog = stralloc(vmsg);
	else{
		defQStr(pp);
		leng = strlen(publog);
		publog = Malloc(publog,leng+strlen(vmsg)+1);
		setQStr(pp,publog,leng+strlen(vmsg)+1);
		Xstrcpy(DVStr(pp,leng),vmsg);
	}
}
void clear_publiclog()
{
	if( publog ){
		free(publog);
		publog = NULL;
	}
}
int have_publiclog()
{
	return publog != NULL;
}
void flush_publiclog(PCStr(route))
{	CStr(vmsg,LINESIZE);

	if( publog ){
		if( route ){
			sprintf(vmsg,"=<!%s ",route);
			strcat(vmsg,publog);
			fputlog(0x01,vmsg,NULL);
		}else	fputlog(0x01,publog,NULL);
		free(publog);
		publog = NULL;
	}
}
void put_publiclog(PCStr(sel),PCStr(fmt),...)
{	CStr(vmsg,LINESIZE);
	VARGS(14,fmt);

	sprintf(vmsg,fmt,VA14);
	fputlog(0x01,vmsg,NULL);
}
typedef struct {
	defQStr(L_buff);
	int	 size;
	int	 sec;
	int	 usec;
} Larg;
/*
void static makelog1(Larg *larg,PCStr(fmt),...)
{	MemFile MemF;
	CStr(msg,LINESIZE);
	VARGS(14,fmt);

	str_sopen(&MemF,"lputLog",msg,sizeof(msg),0,"w");
	if( lPOLL() ){
		str_sprintf(&MemF,"(%5X)",sigblock(0));
	}
	LOG_makeTime(&MemF,larg->sec,larg->usec);
	str_sprintf(&MemF,fmt,VA14);
	Str2vstr(msg,str_stell(&MemF),AVStr(larg->L_buff),larg->size);
}
*/
int logSigblock;
void static makelog1(Larg *larg,PCStr(fmt),...){
	IStr(msg,LINESIZE);
	/*
	int nmask,smask,actth=0;
	*/
	SSigMask sMask;
	VARGS(14,fmt);

	/*
	if( actth = actthreads() ){
		nmask = sigmask(SIGPIPE)|sigmask(SIGTERM)|sigmask(SIGINT);
		smask = sigblock(nmask);
	}
	*/

	setSSigMaskX(sMask,logSigblock);
	if( lPOLL() ){
		sprintf(msg,"(%5X)",sigblock(0));
	}
	LOG_makeTime(TVStr(msg),larg->sec,larg->usec);
	Xsprintf(TVStr(msg),fmt,VA14);
	Str2vstr(msg,strlen(msg),AVStr(larg->L_buff),larg->size);
	resetSSigMask(sMask);

	/*
	if( actth ){
		sigsetmask(smask);
	}
	*/
}
int FMT_putLog0(PCStr(fmt),...)
{
	VARGS(14,fmt);

	lputLog("T",&LogF0,fmt,VA14);
	return 0;
}
static void makelog(PVStr(vmsg),int siz,PCStr(fmt),...){
	Larg larg;
	VARGS(14,fmt);

	setQStr(larg.L_buff,vmsg,siz);
	larg.size = siz;
	larg.sec = Gettimeofday(&larg.usec);
	makelog1(&larg,fmt,VA14);
}
static int initlog(PCStr(fmt),...){
	if( LOG_init_enable ){
		CStr(vmsg,LINESIZE);
		VARGS(14,fmt);

		makelog(AVStr(vmsg),sizeof(vmsg),fmt,VA14);
		IGNRETP write(LOG_initFd,vmsg,strlen(vmsg));
		if( 0x20000 < Lseek(LOG_initFd,0,1) ){
			sprintf(vmsg,"[%d] --initlog TOO LARGE--\n",getpid());
			IGNRETP write(LOG_initFd,vmsg,strlen(vmsg));
			LOG_init_enable = 0;
		}
		return 1;
	}
	return 0;
}
#define initLog	(LOG_init_enable==0)?0:initlog

static void valog(PCStr(fmt),...)
{
	VARGS(14,fmt);

	if( LogAbort && lVERBABORT() ){
		CStr(vmsg,LINESIZE);
		Larg larg;
		setQStr(larg.L_buff,vmsg,sizeof(vmsg));
		larg.size = sizeof(vmsg);
		larg.sec = Gettimeofday(&larg.usec);
		makelog1(&larg,fmt,VA14);
		LOG_write(LogAbort,vmsg,strlen(vmsg));
	}
}
static void bclog(PCStr(wh),PCStr(sel),PCStr(fmt),...){
	int sc = sel ? *sel : 0;
	CStr(vmsg,LINESIZE);
	Larg larg;
	VARGS(14,fmt);

	if( !doUDPlog(wh,sel) ){
		return;
	}
	setQStr(larg.L_buff,vmsg,sizeof(vmsg));
	larg.size = sizeof(vmsg);
	larg.sec = Gettimeofday(&larg.usec);
	makelog1(&larg,fmt,VA14);
	putUDPlog(wh,sel,vmsg,strlen(vmsg));
}
static const char *lclass;
int NO_LOGGING;
int FMT_daemonlog(PCStr(sel),PCStr(fmt),...)
{
	int serrno = errno;
	VARGS(14,fmt);

	if( NO_LOGGING ){
		return 0;
	}
	if( STOP_LOGGING ){
		return 0;
	}

	/*
	if( lSILENT() )
	*/
	if( lSILENT()                     /* -vs */
	 || logEnv && LogF0.l_fp == NOLOG /* LOGFILE="" (initialized) */
	)
	{
		static int nlog;
		if( isWindows() && nlog++ == 0 ){
			/* to initialize something for Win32 */
		}else
		goto VERBABORT;
	}

	if( sel != NULL ){
		if( *sel == 'D' && !lVERB() && !lSYNC() )
			goto VERBABORT;
		if( *sel != 'E' && *sel != 'F' && *sel != 'T' && lTERSE() )
			goto VERBABORT;
	}
	if( sel != NULL )
		FatalTraceLog(sel,fmt,VA14);
	lclass = sel;
	lputLog(sel,&LogF0,fmt,VA14);
	lclass = 0;
	initLog(fmt,VA14);

	errno = serrno;
	return 0;

VERBABORT:
	if( lBCASTLOG() )
		bclog("daemonlog",sel,fmt,VA14);

	if( LogAbort && lVERBABORT() )
	valog(fmt,VA14);
	initLog(fmt,VA14);

	errno = serrno;
	return 0;
}
void lputLogX(PCStr(sel),Logfile *logF,PCStr(fmt),...);
void lputLog(PCStr(sel),Logfile *logF,PCStr(fmt),...)
{
	/*
	int smask,nmask;
	*/
	SSigMask sMask;
	VARGS(14,fmt);

	setSSigMaskX(sMask,logSigblock);
	lputLogX(sel,logF,fmt,VA14);
	resetSSigMask(sMask);

	/*
	 * 9.9.4 MTSS mutex for FILEs seem activated persistently
	 * after a thread creation and inherited to child process.
	if( actthreads() == 0 ){
		lputLogX(sel,logF,fmt,VA14);
		return;
	}

	nmask = sigmask(SIGPIPE)|sigmask(SIGTERM)|sigmask(SIGINT);
	smask = sigblock(nmask);
	lputLogX(sel,logF,fmt,VA14);
	sigsetmask(smask);
	*/
}
void lputLogX(PCStr(sel),Logfile *logF,PCStr(fmt),...)
{	CStr(vmsg,LINESIZE);
	Larg larg;
	int now;
	FILE *locked = 0;
	VARGS(14,fmt);

	if( logEnv == 0 ){
		if( !LOG_init_enable ){
		fprintf(stderr,"[%d] **LOG-NOT-INITIALIZED-YET**",getpid());
		fprintf(stderr,fmt,VA14);
		}
		return;
	}

	now = larg.sec = Gettimeofday(&larg.usec);
	setQStr(larg.L_buff,vmsg,sizeof(vmsg));
	larg.size = sizeof(vmsg);

	if( actthreads() )
	if( LOGFILE_OPENED(logF->l_fp) ){
		double St,Et;
		St = Time();
		flockfile(logF->l_fp);
		locked = logF->l_fp;
		Et = Time() - St;
		if( 1.0 < Et )
		fprintf(stderr,"[%d.%X] LOG locked: %f\n",
			getpid(),getthreadid(),Et);
	}
	if( logF == &LogF0 )
	if( openLogFile(now) == NULL )
	if( LOG_init_enable == 0 )
		goto EXIT;
		/*
		return;
		*/

	makelog1(&larg,fmt,VA14);

	if( lSINGLEP() && lMULTIST() && !isWindowsCE() ){
		putInitlog("%s",vmsg);
	}
	fputlog(0,vmsg,logF->l_fp);
	send_syslogX(lclass,vmsg);
	if( lPUTUDPLOG() ){
		putUDPlog("lputLog",sel,vmsg,strlen(vmsg));
	}
EXIT:
	if( locked ){
		if( actthreads() == 0 || !LOGFILE_OPENED(logF->l_fp) ){
			putpplog("--FATAL: flockfile %X -> %X, actth=%d\n",
				locked,logF->l_fp,actthreads());
		}
		if( locked == logF->l_fp )
			funlockfile(locked);
	}
	/*
	if( actthreads() )
	if( LOGFILE_OPENED(logF->l_fp) ){
		funlockfile(logF->l_fp);
	}
	*/
}

#define LF_FATAL	0
#define LF_TRACE	1
#define ETLogfile	errorTraceLog[LF_which]
#define ETLogid		(LF_which == LF_FATAL ? LF_ERRORLOG : LF_TRACELOG)

static void FatalTraceLog(PCStr(which),PCStr(fmt),...)
{	int LF_which;
	int now,usec;
	MemFile MemF;
	CStr(msg,LINESIZE);
	VARGS(14,fmt);

	if( logEnv == 0 )
		return;

	switch( *which ){
		case 'F': LF_which = LF_FATAL; break;
		case 'T': LF_which = LF_TRACE; break;
		default:  return;
	}
	if( ETLogfile == NULL )
		ETLogfile = LOG_which(LP_NOTTY,ETLogid,0);

	if( ETLogfile == NULL )
		return;

	if( Myport[0] == 0 )
		printPrimaryPort(AVStr(Myport));

	if( LOGFILE_OPENED(ETLogfile->l_fp) == 0 )
		LOG_open(ETLogfile);

	if( LOGFILE_OPENED(ETLogfile->l_fp) == 0 )
		return;

	now = Gettimeofday(&usec);
	StrftimeLocal(AVStr(msg),sizeof(msg),TIMEFORM_mdHMS,now,usec);
	str_sopen(&MemF,"FatalTraceLog",msg,sizeof(msg),strlen(msg),"w");
	if( lMULTIST() )
		str_sprintf(&MemF," [%X]-P%s ",TID,Myport);
	else
	str_sprintf(&MemF," [%d]-P%s ",Getpid(),Myport);
	str_sprintf(&MemF,fmt,VA14);
	fputlog(0,msg,ETLogfile->l_fp);
}
void FMT_TraceLog(PCStr(fmt),...)
{	CStr(xfmt,1024);
	VARGS(14,fmt);

	sprintf(xfmt,"#{TR}# %s",fmt);
	daemonlog("T",xfmt,VA14);
}

int FMT_svlog(PCStr(fmt),...)
{
	VARGS(14,fmt);
	return daemonlog(LS_TERSE,fmt,VA14);
	/*
	return daemonlog(NULL,fmt,VA14);
	*/
}
int FMT_sv0log(PCStr(fmt),...)
{
	VARGS(14,fmt);
	closeAgedLog1(&LogF0,time(0));
	return daemonlog(LS_TERSE,fmt,VA14);
	/*
	return svlog(fmt,VA14);
	*/
}
int FMT_svvlog(PCStr(fmt),...)
{
	VARGS(14,fmt);
	return sv1vlog(fmt,VA14);
}
int FMT_sv1log(PCStr(fmt),...)
{
	VARGS(14,fmt);
	if( !lTERSE() )
	{
		/*
		svlog(fmt,VA14);
		*/
		daemonlog(LS_USUAL,fmt,VA14);
		return 0;
	}
	if( lBCASTLOG() ){
		bclog("sv1log",LS_USUAL,fmt,VA14);
	}
	if( LogAbort && lVERBABORT() )
		valog(fmt,VA14);
	initLog(fmt,VA14);
	return 0;
}
int FMT_sv1vlog(PCStr(fmt),...)
{
	VARGS(14,fmt);
	if( logEnv == 0 )
		return 0;

	if( !lTERSE() )
	/*
	if( lSYNC() || lVERB() )
	*/
	if( lVERB() )
	{
		/*
		svlog(fmt,VA14);
		*/
		daemonlog(LS_VERBOSE,fmt,VA14);
		return 0;
	}
	if( lBCASTLOG() ){
		bclog("sv1vlog",LS_VERBOSE,fmt,VA14);
	}
	if( LogAbort && lVERBABORT() )
		valog(fmt,VA14);
	initLog(fmt,VA14);
	return 0;
}
int FMT_sv1tlog(PCStr(fmt),...)
{
	VARGS(14,fmt);
	return daemonlog(LS_TERSE,fmt,VA14);
	/*
	return svlog(fmt,VA14);
	*/
}
void dbg(PCStr(fmt),...)
{
	VARGS(14,fmt);
	daemonlog(LS_DEBUG,fmt,VA14);
	/*
	svlog(fmt,VA14);
	*/
}

int FMT_ERRMSG(PCStr(fmt),...)
{	MemFile MemF;
	CStr(msg,LINESIZE);

	VARGS(14,fmt);
	str_sopen(&MemF,"ERRMSG",msg,sizeof(msg),0,"w");
	str_sprintf(&MemF,"-delegated[%d]- ",getpid());
	str_sprintf(&MemF,fmt,VA14);
	fputlog(0,msg,stderr);
	return 0;
}
void FMT_DBGMSG(PCStr(fmt),...)
{
	if( lSYNC() || lVERB() ){
		VARGS(14,fmt);
		ERRMSG(fmt,VA14);
	}
}

FILE *openStatusFile(PCStr(pathform))
{	FILE *fp;

	if( StatFp == NULL ){
		if( pathform == NULL )
			StatFp = NOLOG;
		else	StatFp = open_tmpfile(NULL,pathform,"w","");
	}
	if( StatFp != NOLOG && StatFp != NULL )
		return StatFp;
	else	return NULL;
}

FILE *fopenCC(PCStr(server),PCStr(mode),PVStr(path))
{	CStr(form,1024);
	FILE *fp;

	sprintf(form,"servers/cc/%s",server);
	fp = open_tmpfile(&CCF,form,mode,"servers");
	if( fp != NULL && CCF.l_path != NULL )
		strcpy(path,CCF.l_path);
	else	setVStrEnd(path,0);
	return fp;
}
FILE *fcloseCC()
{
	Lclose(&CCF);
	return NULL;
}



/*
static const char *ACTDIR(){
*/
const char *ACTDIR(){
	CStr(path,1024);
	if( actdir == 0 ){
		strcpy(path,"${ACTDIR}");
		Substfile(path);
		actdir = stralloc(path);
	}
	return actdir;
}
const char *ADMDIR(){
	CStr(path,1024);
	if( admdir == 0 ){
		strcpy(path,"${ADMDIR}");
		Substfile(path);
		admdir = stralloc(path);
	}
	return admdir;
}
FILE *fopen_authlog(PCStr(proto),PCStr(clhost),PCStr(mode)){
	CStr(path,1024);
	FILE *fp;

	sprintf(path,"${ADMDIR}/authlog/%s/%02d/%s",proto,
		FQDN_hash(clhost)%32,clhost);
	Substfile(path);
	fp = dirfopen("LoginLog",AVStr(path),mode);
	return fp;
}

FILE *LOG_openLogFile(PCStr(form),PCStr(mode))
{	FILE *fp;

	bzero(&tmpF,sizeof(Logfile));
	fp = open_logtmpfile(&tmpF,0,form,mode,"*");
	if( fp == NOLOG )
		return NULL;
	else	return fp;
}

void rmPortLocks()
{	int lid,pid;
	const char *path;

	pid = getpid();
	for( lid = 0; lid < NUMLOCKS; lid++ )
	if( pid == Locks[lid].l_pid && 0 <= Locks[lid].l_fd ){
		path = Locks[lid].l_path;
		Verbose("LOCK: unlink %s\n",path);
		unlink(path);
		free((char*)path);
		Locks[lid].l_pid = 0;
	}
}
int PortLocks(PCStr(port),int group,xPVStr(path))
{	CStr(pathbuf,1024);
	CStr(ports,PORTSSIZE);
	int lid,pid,fd;
	FILE *fp;

	pid = getpid();
	for( lid = 0; lid < NUMLOCKS; lid++ ){
		if( Locks[lid].l_port == NULL )
			break;
		if( Locks[lid].l_group == group )
		if( strcmp(Locks[lid].l_port,port) == 0 ){
			if( Locks[lid].l_pid == pid && 0 <= Locks[lid].l_fd ){
				if( path )
					strcpy(path,Locks[lid].l_path);
				return Locks[lid].l_fd;
			}
			free((char*)Locks[lid].l_port);
			free((char*)Locks[lid].l_path);
			close(Locks[lid].l_fd);
			Locks[lid].l_pid = 0;
			Locks[lid].l_group = 0;
			break;
		}
	}

	if( path == NULL )
		setPStr(path,pathbuf,sizeof(pathbuf));
	sprintf(path,"%s/locks/PORT/%s.%d",ACTDIR(),port,group);

	fp = dirfopen("PortLock",ZVStr(path,sizeof(pathbuf)),"w+");
	if( fp != NULL ){
		if( elnumof(Locks) <= lid ){
			return -1;
		}
		printServPort(AVStr(ports),"",1);
		fprintf(fp,"%s %d\n",ports,pid);
		fd = dup(fileno(fp));
		fclose(fp);
		setCloseOnExec(fd);
		Locks[lid].l_pid = pid;
		Locks[lid].l_fd = fd;
		Locks[lid].l_group = group;
		Locks[lid].l_port = stralloc(port);
/**/
		setQStr(Locks[lid].l_path,stralloc(path),strlen(path)+1);
		return fd;
	}
	return -1;
}

void get_LOCKFILE(PVStr(path))
{
	sprintf(path,"%s/locks/LOCKFILE",ACTDIR());
}

void get_delaysock(PCStr(file),PVStr(path))
{
	sprintf(path,"%s/delay/%s",ACTDIR(),file);
	path_escchar(AVStr(path));
}

int iamServer();
int LOG_createPortFile(PCStr(file),int stayopen)
{	FILE *fp;
	int ai;

	if( stayopen && !iamServer() ){
		/* 9.9.8 don't overwrite PIDFILE by each child (9.0.6-pre3)
		 * called from EXEC_cleint() via PutPortFile()
		 */
		fp = open_tmpfile(&PortF,file,"r+","");
		if( fp != NULL ){
			IStr(pid,128);
			fgets(pid,sizeof(pid),fp);
			if( atoi(pid) == getppid() ){
				return 0;
			}
			fclose(fp);
		}
	}
	fp = open_tmpfile(&PortF,file,"w+","");
	if( fp != NOLOG && fp != NULL ){
		fprintf(fp,"%d\n",getpid());
		fflush(fp);
		setCloseOnExec(fileno(fp)); /* 9.9.8 to be reopened for lock */

		if( stayopen ){
		sv1log("Stay open PIDFILE for accept() lock[fd=%d]\n",
			fileno(fp));
		}else
		if( fp != stderr ){
			Lclose(&PortF);
		}
	}
	if( fp == NULL ){
		fprintf(stderr,"[%d] DeleGate: cannot create %s\n",
			getpid(),file);
		return -1;
	}
	return 0;
}
void LOG_deletePortFile()
{	FILE *fp;
	CStr(pid,256);

	if( PortF.l_path ){
		if( fp = dirfopen("PortFile",AVStr(PortF.l_path),"r") ){
			fgets(pid,sizeof(pid),fp);
			fclose(fp);
			Lclose(&PortF);
			if( atoi(pid) == getpid() )
				unlink(PortF.l_path);
		}
	}
}
int PortLockReopen()
{
	if( PortF.l_fp != NULL && PortF.l_fp != NOLOG ){
		fclose(PortF.l_fp);
		PortF.l_fp = NULL;
		setLogf(&PortF,dirfopen("PortFile",AVStr(PortF.l_path),"r+"));
		if( PortF.l_fp != NULL )
			return fileno(PortF.l_fp);
	}
	return -1;
}
int PortLockFd()
{	FILE *fp;

	fp = PortF.l_fp;
	if( fp != NULL && fp != NOLOG )
		return fileno(PortF.l_fp);
	else	return -1;
}

int get_init_time(){
	return file_mtime(LOG_initFd);
}
int get_init_size(){
	return file_size(LOG_initFd);
}
int static get_serverlog(FILE *dst,PCStr(end),int timeout)
{	FILE *log;
	CStr(buff,0x20000);
	const char *ep;
	const char *bgn;
	int rcc;
	CStr(line,LINESIZE);
	int leng = 0;

	Lseek(LOG_initFd,0,0);
	rcc = read(LOG_initFd,buff,sizeof(buff)-1);
	/* recv(MSG_PEEK) returns only the first line on Linux ...
	rcc = RecvPeek(LOG_sockio[0],buff,sizeof(buff)-1);
	 */
	setVStrEnd(buff,rcc);
	bgn = buff;
	if( end ){
		while( ep = strstr(bgn,end) ){
			ep += strlen(end);
			if( strstr(ep,end) )
				bgn = ep;
			else	break;
		}
	}
	log = TMPFILE("ServerLog");
	fputs(bgn,log);
	fflush(log);
	fseek(log,0,0);
	while( fgetsTimeout(AVStr(line),sizeof(line),log,timeout) != NULL ){ 
		leng += strlen(line);
		fputs(line,dst);
		if( end != NULL && strstr(line,end) != NULL )
			break;
	}
	fflush(dst);
	fclose(log);
	return leng;
}
int get_serverinitlog(FILE *dst)
{	int leng;

	fprintf(dst,"--BEGIN--\r\n");
	leng = get_serverlog(dst,"--INITIALIZATION DONE--",4);
	fprintf(dst,"--END--\r\n");
	return leng;
}
int restart_server(FILE *dst)
{	int leng;

	leng = get_serverlog(dst,NULL,1);
	if( 0 < leng )
		fputs("--\n",dst);
	Kill(getppid(),1);
	sleep(2); /* wait until restart done ... */
	return ftell(dst) + get_serverinitlog(dst);
}


/*
void ftp_xferlog(int start,PCStr(chost),int size,PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser),PCStr(cstat))
*/
void ftp_xferlog(int start,PCStr(chost),FileSize rest,FileSize size,PCStr(md5),PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser),PCStr(cstat))
{	Logfile *LogF;
	CStr(log,LINESIZE);

	/*
	xferlog(AVStr(log),start,chost,size,path,bin,in,anon,user,auser);
	*/
	xferlog(AVStr(log),start,chost,rest,size,md5,path,bin,in,anon,user,auser);
	sv1log("XFERLOG: %s %s\n",log,cstat);
	if( LogF = LOG_which("ftp",LF_PROTOLOG,0) ){
		LOG_printf(LogF,"%s %s\n",log,cstat);
		LOG_flush(LogF,time(0));
	}
}

extern const char *DELEGATE_MTAB;
void MtabFileName(PCStr(user),PVStr(path))
{
	sprintf(path,"%s/%s",DELEGATE_MTAB,user);
	if( LOG_substfile )
		Substfile(path);
}

extern const char *DELEGATE_NEWSLIB;
void NewsLibdir(PVStr(path),PCStr(spec))
{
	if( spec[0] == '/' )
		strcpy(path,spec);
	else	sprintf(path,"%s/%s",DELEGATE_NEWSLIB,spec);
	Substfile(path);
}

extern const char *DELEGATE_SOCKETS;
void UnixSocketDir(PVStr(path))
{	CStr(dir,PATHLENG);

	strcpy(dir,DELEGATE_SOCKETS);
	Substfile(dir);

	if( File_mtime(dir) < 0 )
	if( mkdirRX(dir) != 0 ){
		sprintf(dir,"/tmp/delegate.sockets.%d",geteuid());
		if( mkdirRX(dir) != 0 )
			strcpy(dir,"/tmp");
	}
	strcpy(path,dir);
	strcat(path,"/");
}

int TIMEOUT_SWEEP_SOCKETS = 3;
typedef struct {
	int	sw_now;
	int	sw_cnt;
	int	sw_del;
	int	sw_err;
	int	sw_timeout;
} Swept;
static scanDirFunc rmsocket(PCStr(file),PCStr(dir),Swept *sw){
	IStr(path,PATHLENG);
	IStr(stime,128);
	int mtime,ctime,cpid,cser,rcode;

	if( 0 < sw->sw_timeout ){
		if( sw->sw_timeout < time(0)-sw->sw_now ){
			porting_dbg("##swept too many sockets: timeout(%d)",
				sw->sw_timeout);
			porting_dbg("##Do -Fsweepf manually to sweep all");
			return -1;
		}
	}
	sprintf(path,"%s/%s",dir,file);
	if( file[0] == '.' ){
	}else
	if( fileIsdir(path) ){
		if( Scandir(path,scanDirCall rmsocket,path,sw) != 0 ){
			return -1;
		}
	}else
	if( sscanf(file,"%d.%d.%d",&ctime,&cpid,&cser) == 3 ){
		sw->sw_cnt++;
		mtime = File_mtime(path);
		if( 24*3600 < sw->sw_now - mtime ){
			rcode = unlink(path);
			sw->sw_del++;
			StrftimeLocal(AVStr(stime),sizeof(stime),
				"%Y-%m-%d",mtime,0);
			porting_dbg("##swept %d/%d %s %s",
				sw->sw_del,sw->sw_cnt,stime,path);
			if( rcode != 0 ){
				sw->sw_err++;
				porting_dbg("##not swept: errno=%d",errno);
				msleep(100);
			}
		}
	}
	return 0;
}
void sweepSockets(int all){
	IStr(dir,PATHLENG);
	Swept sw;

	strcpy(dir,DELEGATE_SOCKETS);
	Substfile(dir);
	if( !fileIsdir(dir) ){
		return;
	}
	bzero(&sw,sizeof(sw));
	sw.sw_now = time(0);
	if( all ){
	}else{
		sw.sw_timeout = TIMEOUT_SWEEP_SOCKETS;
	}
	Scandir(dir,scanDirCall rmsocket,dir,&sw);
}
int sweepfiles_main(int ac,const char *av[]){
	sweepSockets(1);
	return 0;
}

#define CLRCNT	0
#define INCCNT	1
#define ADDPID	2
#define DELPID	3
#define DECCNT	4
#define GETCNT	5

static int getclpids(FILE *fp,int pids[],int npids,int pid,PCStr(path))
{	int count,rcc,xpid;
	CStr(procs,0x10000);
	const char *lp;
	const char *np;
	int mtime;
	int ncheck;

	mtime = file_mtime(fileno(fp));
	if( mtime < START_TIME ){
		ncheck = 8;
		/* 9.2.1 try cleaning up children processes in old invocations.
		 * Leaving zombi processes in this list of alive processes
		 * from the client host will reduce maximum effective
		 * Keep-Alive or connections to decrease the performance.
		 * On Windows, the process-ID is in so narrow range and
		 * reused in so short time.  Thus an alive process in this
		 * list might be non-DeleGate process in high probability.
		 * Since this list is shared among multiple DeleGate servers,
		 * it cannot be expired on the invocation.  It might be
		 * able to be removed if it is older than the last system
		 * shutdown time when all processes are terminated.
		 */
	}else{
		ncheck = 1;
		/* light alive check only for the oldest process */
	}

	count = 0;
	rcc = fread(procs,1,sizeof(procs)-1,fp);
	setVStrEnd(procs,rcc);

	for( lp = procs; lp && *lp; lp = np ){
		if( *lp == '#' )
			break;
		if( np = strchr(lp,'\n') ){
			truncVStr(np); np++;
		}
		xpid = atoi(lp);

		if( xpid == 0 )
			sv1log("#### countUp: found PID==0\n");
/*
		else
		if( !aliveProc(xpid) )
			sv1log("#### countUp: dead %d\n",xpid);
*/
		else
/*
		if( xpid != pid && count == 0 && !procIsAlive(xpid) ){
*/
		if( xpid != pid && count < ncheck && !procIsAlive(xpid) ){
			/* count == 0 ... check from the oldest process
			 * untill alive one is found
			 */
			daemonlog("F","#### countUp: nonexistent %d, %s\n",
				xpid,path);
		}else
		if( xpid != pid ){
			pids[count++] = xpid;
			if( npids <= count-1 )
				break;
		}
	}
	return count;
}

static void addUnlinks(PCStr(path))
{	int ui;

	for( ui = 0; ui < unlinks; ui++ )
		if( strcmp(path,unlinkv[ui]) == 0 )
			return;
	if( elnumof(unlinkv) <= unlinks ){
		return;
	}
	unlinkv[unlinks++] = stralloc(path);
}
void unlinkOnExit(PCStr(path)){
	addUnlinks(path);
}
static void canUnlinks(PCStr(path))
{	int ui,uj;

	/* should do mutex for unlinkv[] */
	for( ui = 0; ui < unlinks; ui++ ){
		if( strcmp(path,unlinkv[ui]) == 0 ){
			free((char*)unlinkv[ui]);
			for( uj = ui; uj < unlinks; uj++ )
				unlinkv[uj] = unlinkv[uj+1];
			unlinks--;
			break;
		}
	}
}
static void exeUnlinks()
{	int ui;
	CStr(line,32);
	FILE *fp;
	int pid;
	int Unlinks;

	Unlinks = unlinks;
	unlinks = 0; /* to be safe for duplication in multi-threads */
	/*
	for( ui = 0; ui < unlinks; ui++ ){
	*/
	for( ui = 0; ui < Unlinks; ui++ ){
		if( fp = fopen(unlinkv[ui],"r") ){
			fgets(line,sizeof(line),fp);
			fclose(fp);
			if( sscanf(line,"#%d",&pid) ){
				if( pid == getpid() )
					unlink(unlinkv[ui]);
			}
		}
		free((char*)unlinkv[ui]);
	}
}

#define MAX_CLPROCS 1024
int countUp(PCStr(file),int istmp,int op,int pid,long *lmtime,xPVStr(path))
{	CStr(pathb,PATHLENG);
	CStr(line,128);
	FILE *fp;
	int xpid,pids[MAX_CLPROCS],count,px;
	int now;
	IStr(buf,4*1024);

	if( path == NULL ){
		setPStr(path,pathb,sizeof(pathb));
	}

	setVStrEnd(path,0);
	if( istmp )
		strcats3(AVStr(path),ACTDIR(),"/",file);
	else	strcats3(AVStr(path),ADMDIR(),"/",file);
	if( op == GETCNT ){
		fp = dirfopen("ClientCounter",AVStr(path),"r");
		if( fp == NULL ){
			return -1;
		}
		count = getclpids(fp,pids,MAX_CLPROCS,pid,path);
		fclose(fp);
		return count;
	}

	fp = dirfopen("ClientCounter",AVStr(path),"r+");
	if( lmtime != NULL ){
		if( fp == NULL )
			*lmtime = 0;
		else	*lmtime = file_mtime(fileno(fp));
	}
	if( fp == NULL ){
		if( op == DELPID ){
			sv1log("#### countUp can't open r+ [%s]\n",path);
			return -1;
		}
		fp = dirfopen("ClientCounter",AVStr(path),"w+");
		if( fp == NULL ){
			sv1log("#### countUp can't open w+ [%s]\n",path);
			return -1;
		}
	}
/*
 * unlink too old counter file on count-up ...
 */
	setbuffer(fp,buf,sizeof(buf)); /* 9.9.4 MTSS for malloc() */

	if( lock_exclusiveTO(fileno(fp),10*1000,NULL) != 0 ){
		sv1log("#### countUp can't lock [%s]\n",path);
		count = -1;
	}else{
		if( op == INCCNT || op == DECCNT || op == CLRCNT ){
			now = time(0);
			count = 0;
			if( fgets(line,sizeof(line),fp) != NULL )
				count = atoi(line);
			if( op == INCCNT ) count++; else
			if( op == DECCNT ) count--; else
			if( op == CLRCNT ) count=0;
			fseek(fp,0,0);
			fprintf(fp,"%d %d\n",count,now);
			fflush(fp);
			Ftruncate(fp,0,1);
		}else{
			/*
			count = getclpids(fp,pids,MAX_CLPROCS,pid);
			*/
			count = getclpids(fp,pids,MAX_CLPROCS,pid,path);
			if( op == ADDPID ){
				canUnlinks(path);
				pids[count++] = pid;
			}

			clearerr(fp);
			fseek(fp,0,0);
			if( 0 < count ){
				for( px = 0; px < count; px++ )
					fprintf(fp,"%8d\r\n",pids[px]);
				fputs("########\r\n",fp);
			}else{
				fprintf(fp,"#%7d\r\n",pid);
			}
			fflush(fp);
		}
		lock_unlock(fileno(fp));
	}
	fclose(fp);

	/* unlink after close for Windows */
	if( count == 0 )
		addUnlinks(path);

	return count;
}

int getmtpid(); /* getpid() and Getpid() can be changed after thread_fork() */
int addtoHostSet(PCStr(hostset),PCStr(host),PCStr(addr));
int ClientCount(PCStr(host),PCStr(addr)){
	IStr(file,128);
	int ccount;

	sprintf(file,"clients/%02d/%s:%s",FQDN_hash(host)%32,addr,host);
	ccount = countUp(file,1,GETCNT,0,NULL,VStrNULL);
	return ccount;
}
int ClientCountUp(PCStr(user),PCStr(host),PCStr(addr),int port)
{	CStr(file,128);
	int ccount;
	int pid;

	if( lSINGLEP() ){
		return 1;
	}
	if( EscEnabled() ){
		return 1;
	}
	addtoHostSet("client",host,addr);
	/*
	pid = Getpid();
	*/
	pid = getmtpid();
	sprintf(file,"clients/%02d/%s:%s",FQDN_hash(host)%32,addr,host);
	ccount = countUp(file,1,ADDPID,pid,NULL,VStrNULL);
	if( 0 < ccount ){
		strcpy(ClientCountFile,file);
		ClientCountFilePID = pid;
	}
	return ccount;
}
int ClientCountDown()
{	const char *file;
	const char *dp;
	int count;
	int pid;

	if( lSINGLEP() ){
		return 1;
	}
	if( EscEnabled() ){
		return 1;
	}
	if( actthreads() && gotsigTERM(0) ){
		/* 9.9.4 MTSS might have locked mutex */
		/* and should not cause a rush of CountDown on SIGTERM */
		putsLog("SIGTERM suppressed ClientCountDown");
		return 1;
	}
	/*
	pid = Getpid();
	*/
	pid = getmtpid();
	if( pid != ClientCountFilePID )
	{
		if( ClientCountFilePID ){
			if( lTHREAD() )
			daemonlog("F","ClientCountDown pid=%d/%d [%d][%d]\n",
				pid,ClientCountFilePID,getpid(),Getpid());
		}
		return -1;
	}
	ClientCountFilePID = 0;

	file = ClientCountFile;
	if( file[0] == 0 )
		return -1;

	count = countUp(file,1,DELPID,pid,NULL,VStrNULL);
/*
	{
		for( dp = file; *dp; dp++ )
			if( *dp == '.' )
				*(char*)dp = '/';
		countUp(file,0,INCCNT,pid,NULL,VStrNULL);
	}
*/
	truncVStr(file);
	return count;
}

void BeforeExec(){
	ClientCountDown();
}

extern int cnt_errorCSC;
extern int cnt_retryCSC;
extern int cnt_enterCSC;
extern int cnt_leaveCSC;
extern int cnt_errCSCpid;
int statsThreadCSC(int *count,int *retry,int *timeout);
void logCSC(PCStr(wh),int force){
	int tcount,tretry,ttimeout;
	const char *lf;

	statsThreadCSC(&tcount,&tretry,&ttimeout);
	if( force || cnt_errorCSC || cnt_errCSCpid || ttimeout || tretry ){
		IStr(whe,128);

		if( cnt_errorCSC || ttimeout )
			lf = "F";
		else	lf = "E";
		daemonlog(lf,"#Sig/CSC %s %d %d P%X R%d E%X {%d r%d t%d} %d/%d/%d\n",
			wh,cnt_SSigMask,cnt_enterCSC,cnt_errCSCpid,
			cnt_retryCSC,cnt_errorCSC,
			tcount,tretry,ttimeout,
			actthreads(),numthreads()-endthreads(),numthreads());
	}
}

static int infinish;
void removeProcLog(FL_PAR);
static int in_finish;
static int sig_in_finish;
void fin_sigANY(int sig){
	/* 9.9.4 MTSS to ignore signals under finish() */
	/*
	putfLog("SIGNAL (%d) ignored in finish()",sig);
	*/
	int now = time(0);
	putfLog("SIGNAL#%d %d/%d ignored in finish()",sig,
		sig_in_finish,now-in_finish);
	if( sig == SIGTERM || sig_in_finish || newthreads() || actthreads() ){
		putfLog("thread-sig#%d %d/%d _exit in finish()",sig,
			sig_in_finish,now-in_finish);
		_exit(-1);
	}
	sig_in_finish = sig;
	if( in_finish ){
		if( 3 < time(0)-in_finish ){
			_exit(0);
		}
	}
	return;
}
static void finish(int code)
{
	if( !lMTSS_NOSSIG() ){
		if( in_finish == 0 ){
			in_finish = time(0);
			/* should be sigaction() */
			signal(SIGALRM,fin_sigANY);
			signal(SIGPIPE,fin_sigANY);
			signal(SIGTERM,fin_sigANY);
			signal(SIGINT, fin_sigANY);
			signal(SIGHUP, fin_sigANY);
		}
	}
	if( infinish ){
		fprintf(stderr,"[%d] ignored finish in finish[%d]\n",
			getpid(),infinish);
		daemonlog("F","ignored finish in finish[%d]\n",infinish);
		_exit(code);
		return;
	}
	logCSC("finish",0);

	infinish = getpid();
	removeProcLog(FL_ARG);

	BeforeExit();
	ClientCountDown();
	exeUnlinks();
	DO_FINALIZE(code);
}

#undef Finish
void Finish(int code)
{
	FinishX("",0,code);
}
const char *FinishFile = "";
int FinishLine = 0;
int in_exit;
void FinishX(PCStr(F),int L,int code)
{
	FinishFile = F;
	FinishLine = L;

	if( in_exit ){
		putsLog("SIG ignored in FinishX under exit()");
		return;
	}
	InFinish = 1;
	if( lMULTIST() ){
		extern int THEXIT;
		void dumpDGFL(void *me,FILE *tc);
		fprintf(stderr,"-- %X Finish-Threads: %d %d/%d <= %s:%d\n",
			TID,THEXIT,actthreads(),numthreads(),F,L);
		setthread_FL(0,FL_ARG,"finishing");
		dumpthreads("Finish",stderr);
		dumpDGFL(0,stderr);
	}
	if( ismainthread() == 0 ){
		syslog_ERROR("DONT Finish(%s:%d %d) in child-thread: %X\n",
			F,L,code,getthreadid());
		thread_exit(0);
		return;
	}
	finish(code);
	exit(code);
	fprintf(stderr,"\n[%d] exit(%d) INTERRUPTED\n",getpid(),code);
	_exit(code);
}
void _Finish(int code)
{
	finish(code);
	_exit(code);
}

void addBeforeExit(PCStr(what),vFUNCP func,void *arg)
{	int fi;
	XFunc *xp;

	if( elnumof(before_exits) <= before_exitX ){
		return;
	}
	sv1log("[%d] ADD BeforeExit[%d] %s\n",getpid(),before_exitX,what);
	xp = &before_exits[before_exitX++];
	xp->x_what = what;
	xp->x_func = (vcFUNCP)func;
	xp->x_arg = arg;
	xp->x_pid = getpid();
}
void BeforeExit(){
	int fi;
	XFunc *xp;
	int pid;

	pid = getpid();
	for( fi = 0; fi < before_exitX; fi++ ){
		xp = &before_exits[fi];
		if( xp->x_pid == pid && xp->x_done == 0 ){
			sv1log("[%d] DO BeforeExit[%d] %s\n",pid,fi,xp->x_what);
			xp->x_done = 1;
			(*xp->x_func)(xp->x_what,xp->x_arg);
		}
	}
}


void putRejectList(PCStr(what),PCStr(dproto),PCStr(dhost),int dport,PCStr(dpath),PCStr(referer),PCStr(sproto),PCStr(shost),int sport,PCStr(suser),PCStr(auser),PCStr(apass),PCStr(reason))
{	FILE *fp;
	CStr(path,2048);
	const char *rp;
	char rc;
	CStr(hostport,MaxHostNameLen);
	CStr(stime,256);

	HostPort(AVStr(hostport),dproto,dhost,dport);
	sprintf(path,"%s/rejects/%s/%s",ADMDIR(),dproto,hostport);

	fp = dirfopen("RejectList",AVStr(path),"r+");
	if( fp == NULL )
		fp = dirfopen("RejectList",AVStr(path),"w+");
	if( fp == NULL ){
		/*fp = stderr;*/
		/* no reject list is available */
		return;
	}

	StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,time(NULL),0);

	lock_exclusiveTO(fileno(fp),10*1000,NULL);
	fseek(fp,0,2);
	fprintf(fp,"[%s] %s %s://%s:%s@%s:%d/%s %s %s://%s:%s@%s:%d/%s ",
		stime,what,
		dproto,auser,apass,dhost,dport,dpath, referer,
		sproto,suser,"",   shost,sport,""
	);
	putc('"',fp);
	for( rp = reason; rc = *rp; rp++ ){
		if( ' ' <= rc && rc < 0x7F && rc != '"' && rc != '%' )
			putc(rc,fp);
		else if( rc == '\n' ) fputs("\\n",fp);
		else if( rc == '\r' ) fputs("\\r",fp);
		else if( rc == '\t' ) fputs("\\t",fp);
		else if( rc == '\f' ) fputs("\\f",fp);
		else if( rc == '\\' ) fputs("\\\\",fp);
		else	fprintf(fp,"%%%02x",rc);
	}
	putc('"',fp);
	fputs("\r\n",fp);
	lock_unlock(fileno(fp));
	fclose(fp);
}

extern const char *MAILGATE;

FILE *openMbox(int create,PVStr(mbox),PCStr(muid));
FILE *openMuid(int create,PCStr(muid),PVStr(mbox))
{	CStr(path,1024);
	FILE *fp;

	sprintf(path,"%s/%s/muid/%s",ADMDIR(),MAILGATE,muid);
	if( create ){
		if( fp = dirfopen("MBOXMUID",AVStr(path),"w+") )
			fputs(mbox,fp);
		return fp;
	}else{
		if( fp = dirfopen("MBOXMUID",AVStr(path),"r+") ){
			fgets(mbox,256,fp);
			fclose(fp);
			return openMbox(0,AVStr(mbox),muid);
		}
		return NULL;
	}
}
FILE *openMbox(int create,PVStr(mbox),PCStr(muid))
{	CStr(path,1024);
	FILE *fp,*ufp;

	sprintf(path,"%s/%s/mbox/%s",ADMDIR(),MAILGATE,mbox);
	fp = dirfopen("MBOXMBOX",AVStr(path),"r+");
	if( fp == NULL && create ){
		fp = dirfopen("MBOXUSER",AVStr(path),"w+");
		if( fp != NULL )
			if( ufp = openMuid(1,muid,AVStr(mbox)) )
				fclose(ufp);
	}
	return fp;
}
FILE *openGACL(int create,PCStr(muid))
{	CStr(path,1024);
	FILE *fp;

	sprintf(path,"%s/admin/%s",ADMDIR(),muid);
	fp = dirfopen("MUIDGACL",AVStr(path),"r+");
	if( fp == NULL && create )
		fp = dirfopen("MUIDGACL",AVStr(path),"w+");
	return fp;
}

FILE *openAclRecord(int create,PCStr(url),PVStr(path))
{	CStr(proto,128);
	CStr(login,128);
	CStr(upath,1024);
	FILE *fp;

	decomp_absurl(url,AVStr(proto),AVStr(login),AVStr(upath),sizeof(upath));
	sprintf(path,"%s/record/%s/%s/%s",ADMDIR(),proto,login,upath);

	fp = dirfopen("ACL",AVStr(path),"r+");
	if( fp == NULL && create )
		fp = dirfopen("ACL",AVStr(path),"w+");
	return fp;
}
FILE *openAclFile(int create,PCStr(proto),PCStr(host),int port,PCStr(upath))
{	CStr(hostport,1024);
	CStr(aclpath,2048);
	FILE *fp;

	HostPort(AVStr(hostport),proto,host,port);
	sprintf(aclpath,"%s/acl/%s/%s/%s",ADMDIR(),proto,hostport,upath);

	fp = dirfopen("ACL",AVStr(aclpath),"r+");
	if( fp == NULL && create )
		fp = dirfopen("ACL",AVStr(aclpath),"w+");
	return fp;
}

int local_lockTO(int ex,PCStr(path),FILE *fp,int timeout,int *elapsedp,int *lkfdp)
{	CStr(dir,1024);
	CStr(lkpath,1024);
	int lkfd,lkrcode;

	if( path[0] ){
		strcpy(dir,ACTDIR());
		lkfd = getLocalLock(fp,dir,path,AVStr(lkpath));
		if( lkfd < 0 ){
			lkfd = fileno(fp);
			strcpy(lkpath,path);
		}
	}else{
		lkfd = fileno(fp);
		strcpy(lkpath,"[tmpfile]");
	}

	if( ex )
		lkrcode = lock_exclusiveTO(lkfd,timeout,elapsedp);
	else	lkrcode = lock_sharedTO(lkfd,timeout,elapsedp);

	if( lkrcode != 0 && lkfd != fileno(fp) ){
		close(lkfd);
		lkfd = -1;
	}

	*lkfdp = lkfd;
	return lkrcode;
}

static FILE *_flog;
void flog(PCStr(fmt),...){
	int now,usec;
	CStr(ts,32);
	VARGS(8,fmt);

	if( _flog == 0 ){
		_flog = fopen("/tmp/flog","a");
	}
	if( _flog != 0 ){
		now = Gettimeofday(&usec);
		StrftimeLocal(AVStr(ts),sizeof(ts),"%H:%M:%S%.2s",now,usec);
		fseek(_flog,0,2);
		fprintf(_flog,"%s [%4d] ",ts,getpid());
		fprintf(_flog,fmt,VA8);
		fflush(_flog);
	}
}


#define HS_DIVN	64
#define HS_DIV	'+'
#define HS_SET	'+'

/* if with mask, then it might be matched with xx.xx.xx.255 */
static int hostSetPath(PVStr(path),PCStr(hostset),PCStr(addr)){
	/*
	sprintf(path,"${ADMDIR}/hosts/byaddr");
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
	*/
	sprintf(path,"%s/hosts/byaddr",ADMDIR());
	if( addr ){
		int strCRC8(int,PCStr(str),int);
		int hash;
		hash = strCRC8(0,addr,strlen(addr)) % HS_DIVN;
		Xsprintf(TVStr(path),"/%c%02d/%s",HS_DIV,hash,addr);
		if( hostset && *hostset ){
			Xsprintf(TVStr(path),"%c%s",HS_SET,hostset);
		}
	}
	return 0;
}
int matchHostSetX(const char *hostset,VAddr *ahost,VAddr *hosti,VAddr *mask,int expire){
	CStr(path,1024);
	const char *addr = VA_inAddr(ahost);
	hostSetPath(AVStr(path),hostset,addr);
	if( File_is(path) ){
		if( expire != 0 ){
			int mtime;
			mtime = File_mtime(path);
			if( mtime+expire < time(NULL) ){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}
int matchHostSet(const char *hostset,VAddr *ahost,VAddr *hosti,VAddr *mask){
	return matchHostSetX(hostset,ahost,hosti,mask,0);
}
int hasHostSet(PCStr(hostset)){
	CStr(path,1024);
	/*
	sprintf(path,"${ADMDIR}/hosts/sets/%s",hostset);
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
	*/
	sprintf(path,"%s/hosts/sets/%s",ADMDIR(),hostset);
	return File_is(path);
}
int addHostSet(PCStr(hostset),PCStr(host),PCStr(addr),int del,PVStr(msg)){
	CStr(path,1024);
	FILE *fp;
	int rcode = -1;

	hostSetPath(AVStr(path),hostset,addr);
	if( msg ){
		Xsprintf(BVStr(msg),"*** HostSet %s %s %s %s\n",
			del?"DEL":"ADD",hostset,host,addr);
		Xsprintf(TVStr(msg),"*** HostSet %s\n",path);
	}
	if( del ){
		rcode = unlink(path);
	}else{
		if( File_is(path) ){
			File_touch(path,time(0));
			rcode = 0;
		}else
		if( (fp = dirfopen("addHostSet",AVStr(path),"a+")) ){
			fclose(fp);
			rcode = 0;
		}else{
		}
	}
	return rcode;
}
int addtoHostSet(PCStr(hostset),PCStr(host),PCStr(addr)){
	CStr(path,1024);
	if( lSINGLEP() ){
		return -1;
	}
	hostSetPath(AVStr(path),NULL,NULL);
	if( File_is(path) )
		return addHostSet(hostset,host,addr,0,VStrNULL);
	else	return -1;
}

#define IsDigit(ch)	('0'<=ch && ch<='9')

static scanDirFunc puthost2(PCStr(file),PCStr(dir),PCStr(set),FILE *fp,int expire,int *nh){
	CStr(path,1024);
	const char *dp;

	if( file[0] == HS_DIV || IsDigit(file[0]) ){
		if( (dp = strchr(file,HS_SET)) && streq(dp+1,set) ){
			sprintf(path,"%s/%s",dir,file);
			if( expire ){
				int mtime;
				mtime = File_mtime(path);
				if( mtime+expire < time(0) )
					return 0;
			}
			if( fp ){
				strcpy(path,file);
				if( dp = strchr(path,HS_SET) )
					truncVStr(dp);
				fprintf(fp,"%s\n",path);
			}
			if( nh ){
				*nh += 1;
			}
		}
	}
	return 0;
}
static scanDirFunc puthost1(PCStr(file),PCStr(set),PCStr(dir),FILE *fp,int expire,int *nh){
	if( file[0] == HS_DIV )
	if( IsDigit(file[1]) && IsDigit(file[2]) && file[3] == 0 ){
		CStr(path,1024);
		sprintf(path,"%s/%s",dir,file);
		Scandir(path,scanDirCall puthost2,path,set,fp,expire,nh);
	}
	return 0;
}
int sorta(VSAddr **a,VSAddr **b){
	const unsigned char *ap;
	const unsigned char *bp;
	int la;
	int lb;
	int i;
	la = VSA_decomp(*a,(const char**)&ap,NULL,NULL);
	lb = VSA_decomp(*b,(const char**)&bp,NULL,NULL);
	if( la != lb ){
		return la - lb;
	}
	for( i = 0; i < la; i++ ){
		if( ap[i] < bp[i] ) return -1;
		if( bp[i] < ap[i] ) return 1;
	}
	return 1;
}
int sortAddrFile(FILE *fp){
	int size = file_size(fileno(fp));
	int nele;
	int ei;
	int en;
	int ej;
	CStr(line,128);
	CStr(addr,128);
	const char *dp;
	VSAddr *addrs;
	VSAddr **addrp;

	nele = 128 + size / 4; 
	addrs = (VSAddr*)malloc(nele*sizeof(VSAddr));
	addrp = (VSAddr**)malloc(nele*sizeof(VSAddr*));
	en = 0;
	for( ei = 0; ei < nele; ei++ ){
		if( fgets(line,sizeof(line),fp) == NULL )
			break;
		wordScan(line,addr);
		if( dp = strchr(addr,HS_SET) )
			truncVStr(dp);
		if( VSA_strisaddr(addr) ){
			VSA_atosa(&addrs[en],0,addr);
			addrp[en] = &addrs[en];
			en++;
		}else{
		}
	}
	qsort(addrp,en,sizeof(VSAddr*),(sortFunc)sorta);
	fseek(fp,0,0);
	for( ej = 0; ej < en; ej++ ){
		fprintf(fp,"%s\n",VSA_ntoa(addrp[ej]));
	}
	free(addrs);
	free(addrp);
	return 0;
}
int updateHostSet(PCStr(set),int *nh){
	CStr(spath,1024);
	CStr(path,1024);
	FILE *fp;
	int nhosts = 0;

	sprintf(path,"${ADMDIR}/hosts/sets/%s",set);
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
	fp = dirfopen("HostSet",AVStr(path),"w+");
	if( fp == NULL ){
		fprintf(stderr,"Cannot create %s\n",path);
		return -1;
	}
	sprintf(spath,"${ADMDIR}/hosts/byaddr");
	DELEGATE_substfile(AVStr(spath),"",VStrNULL,VStrNULL,VStrNULL);
	Scandir(spath,scanDirCall puthost1,set,spath,fp,0,&nhosts);
	fflush(fp);
	Ftruncate(fp,0,1);

	fseek(fp,0,0);
	sortAddrFile(fp);
	fclose(fp);
	printf("*** Updated %s (%d hosts)\n",path,nhosts);
	if( nh ) *nh = nhosts;
	return 0;
}
int extractHostSet(PCStr(set),FILE *fp,int del){
	CStr(line,1024);
	CStr(addr,128);
	CStr(msg,128);
	while( fgets(line,sizeof(line),fp) != NULL ){
		wordScan(line,addr);
		if( VSA_strisaddr(addr) ){
			addHostSet(set,addr,addr,del,VStrNULL);
		}else{
			fprintf(stderr,"*** ERR bad addr [%s]\n",addr);
		}
	}
	return 0;
}
int putHostSet(FILE *fp,PCStr(set),int expire){
	CStr(path,1024);
	FILE *tmp = TMPFILE("HostSet");

	hostSetPath(AVStr(path),NULL,NULL);
	Scandir(path,scanDirCall puthost1,set,path,tmp,expire,NULL);
	fflush(tmp);
	fseek(tmp,0,0);
	sortAddrFile(tmp);
	fseek(tmp,0,0);
	copyfile1(tmp,fp);
	fclose(tmp);
	return 0;
}
int hosts_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	const char *com = NULL;
	const char *set = NULL;
	const char *host = NULL;
	const char *addr;
	int rcode = -1;

	if( ac <= 2 ){
		fprintf(stderr,
		"Usage: %s [-adv] hostSetName [host | +=[file]]\n",av[0]);
		fprintf(stderr,"       %s -o ... dump to stdout\n",av[0]);
		return 0;
	}
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
			com = a1+1;
		}else{
			if( set == NULL )
				set = a1;
			else{
				host = a1;
			}
		}
	}
	if( set ){
		if( strpbrk(set,"/\\") ){
			fprintf(stderr,"Bad hostset name: %s\n",set);
			return -1;
		}
	}
	if( strpbrk(com,"ad") )
	if( set != NULL ){
	    int del = strchr(com,'d') != NULL;
	    if( host == NULL || strncmp(host,"+=",2) == 0 ){
		FILE *fp;
		if( host == NULL || host[2] == 0 )
			fp = stdin;
		else{
			fp = fopen(host+2,"r");
		}
		if( fp != NULL ){
			extractHostSet(set,fp,del);
			if( fp != stdin )
				fclose(fp);
		}
		rcode = 0;
	    }else
	    if( addr = gethostaddr(host) ){
		CStr(msg,1024);
		rcode = addHostSet(set,host,addr,del,AVStr(msg));
		printf("--> %s -%s hostset=%s host=%s addr=%s\n%s",
			rcode==0?"OK":"ERR",com,set,host,addr,msg);
		if( *com == 'v' ){
			VAddr va;
			VA_strtoVAddr(addr,&va);
			if( matchHostSet(set,&va,NULL,NULL) ){
				printf("--> '%s/%s' is in the set '%s'\n",
					host,addr,set);
			}else{
				printf("--> '%s/%s' is NOT in the set '%s'\n",
					host,addr,set);
			}
			return 0;
		}
	    }
	    if( rcode == 0 ){
		updateHostSet(set,NULL);
	    }
	}
	if( strchr(com,'o') ){
		putHostSet(stdout,set,0);
		rcode = 0;
	}
	if( rcode != 0 ){
		printf("--> ERR bad arguments\n");
	}
	return 0;
}

static const char *init_logFILE;
static int init_logLINE;
static defQStr(init_logbuf);
static PCStr(init_logtop);
void iLOGinit(){
	if( init_logbuf == 0 ){
		setQStr(init_logbuf,(char*)malloc(0x4000),0x4000);
	}
	init_logtop = init_logbuf;
	truncVStr(init_logtop);

	sprintf(init_logbuf,"ppid=%d\n",getppid());
	init_logbuf += strlen(init_logbuf);

	LOG_type2 &= ~L_NOINITLOG;
}
int iLOGpos(PCStr(F),int L){
	init_logFILE = F;
	init_logLINE = L;
	return 0;
}
void iLOGdump1(FILE *lfp,int sig){
	if( init_logtop ){
		fputs(init_logtop,lfp);
		fflush(lfp);
	}
}
void FMT_iLOGdump(int sig,PCStr(fmt),...){
	FILE *lfp;
	VARGS(8,fmt);
	if( init_logtop ){
		lfp = curLogFp();
		if( sig || lfp == NULL ){
			fprintf(stderr,"-- {{ "); fprintf(stderr,fmt,VA8);
			iLOGdump1(stderr,sig);
			fprintf(stderr,"-- }} "); fprintf(stderr,fmt,VA8);
		}
		if( lfp ){
			fprintf(lfp,"-- {{ "); fprintf(lfp,fmt,VA8);
			iLOGdump1(lfp,sig);
			fprintf(lfp,"-- }} "); fprintf(lfp,fmt,VA8);
		}
	}
}
int FMT_iLOGput(PCStr(fmt),...){
	double Now = Time();
	const char *top;
	CStr(ts,256);
	VARGS(16,fmt);

	if( init_logbuf == 0 ){
		iLOGinit();
	}

	sprintf(ts,"%02d:%02d.%03d [%d] %s:%d ",
		(((int)Now)%3600)/60,((int)Now)%60,
		((int)((Now-(int)Now)*1000))%1000,
		getpid(),init_logFILE?init_logFILE:"",init_logLINE);
	top = init_logbuf;
	sprintf(init_logbuf,"%s",ts);
	init_logbuf+= strlen(init_logbuf);
	sprintf(init_logbuf,fmt,VA16);
	init_logbuf += strlen(init_logbuf);
	sprintf(init_logbuf,"\n");
	init_logbuf += strlen(init_logbuf);

	/*
	if( 1 ){
		fprintf(stderr,"%s ",ts);
		fprintf(stderr,fmt,VA16);
		fprintf(stderr,"\n");
	}
	*/
	return 0;
}

int fileIsremote(PCStr(path),int fd);
int getLockFile(PCStr(dir),PCStr(file),PVStr(lkpath))
{	FILE *lkfp;
	int lkfd;

	sprintf(lkpath,"%s/locks/FILE/%s",dir,file);
	if( lkfp = dirfopen("LOCALLOCK",AVStr(lkpath),"w+") ){
		lkfd = dup(fileno(lkfp));
		fclose(lkfp);
		setCloseOnExec(lkfd);
		return lkfd;
	}
	return -1;
}
int getLocalLock(FILE *fp,PCStr(dir),PCStr(file),PVStr(lkpath))
{
	if( !fileIsremote(file,fileno(fp)) )
		return -1;
	return getLockFile(dir,file,AVStr(lkpath));
}
void loglog(PCStr(fmt),...)
{	FILE *logfp;
	const char *file;
	CStr(stime,256);
	VARGS(14,fmt);

	if( file = getenv("DELEGATE_LOGLOG") )
	if( logfp = fopen(file,"a") ){
		getTimestamp(AVStr(stime));
		fprintf(logfp,"%s [%5d][%5d][%5d] ",
			stime,SERVER_PORT(),getpid(),getppid());
		fprintf(logfp,fmt,VA14);
		fclose(logfp);
	}
}

int getSTStat(PVStr(stat));
double TotalSendTime;
double LOGX_recvTime;
int idlesessions();
int busysessions();
int LOGX_sentCount;
int LOGX_recvCount;
extern int eccLOGX_appReq;
extern int eccLOGX_tcpAcc;
extern int eccLOGX_tcpCon;
extern int DestroyedThreads;
int LOGX_stats(PVStr(msg),int shortfmt){
	refQStr(mp,msg);
	IStr(svstat,128);
	double meandelay;

	if( LOGX_tcpConSuccess )
		meandelay = (LOGX_tcpConDelays/1000.0)/LOGX_tcpConSuccess;
	else	meandelay = 0;

	Rsprintf(mp,"Accept:%7d",LOGX_tcpAcc+eccLOGX_tcpAcc);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');
	Rsprintf(mp,"Request:%6d",LOGX_appReq+eccLOGX_appReq);
	if( LOGX_appHit ) Rsprintf(mp," [%dhit]",LOGX_appHit);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');

	Rsprintf(mp,"Connect:%6d (%.3f %.1f)[-%d-%d]",
		LOGX_tcpCon+eccLOGX_tcpCon,
		meandelay,LOGX_tcpConDelayMax/1000.0,
		LOGX_tcpConRefused,LOGX_tcpConTimeout
	);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');
	if( LOGX_app_keepAliveSV || LOGX_app_keepAliveCL ){
	Rsprintf(mp,"Reuse:%8d+%d/%dsv %d/%dcl ",
			LOGX_tcpConRecycleOk,
			LOGX_app_keepAliveSVreu,LOGX_app_keepAliveSV,
			LOGX_app_keepAliveCLreu,LOGX_app_keepAliveCL,
			0
		);
		if( !shortfmt ) setVStrPtrInc(mp,'\n');
	}
	if( lCONNQUE()
	 || LOGX_tcpConParaTried || LOGX_tcpConRecycled ){ /* TURBO */
	Rsprintf(mp,"Turbo:%8d+%d/%d+%d -%d-%d-%d-%d %dS ",
		 LOGX_tcpConPrefOk,LOGX_tcpConParaOk,
		 LOGX_tcpConParaTried,LOGX_tcpConRecycled,
		 LOGX_tcpConAbandon1,LOGX_tcpConAbandon2,
		 LOGX_tcpConAbandon3,LOGX_tcpConAbandon4,
		 LOGX_tcpConSorted
		);
		if( !shortfmt ) setVStrPtrInc(mp,'\n');
	}
	Rsprintf(mp,"Resolv:%7d (%.3f)[%de %du %dR %dU] ",
		LOGX_resReq,
		LOGX_resReq?(((double)LOGX_resTime)/LOGX_resReq)/1000:0,
		LOGX_resEnt,
		LOGX_resUpd,LOGX_resRet,LOGX_resUnk
	);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');
	getSTStat(AVStr(svstat));
	if( svstat[0] ){
	Rsprintf(mp,"Thread:%d/%d/%d/%d [%s] ",
			busysessions(),idlesessions(),
			actthreads(),numthreads(),svstat);
		if( DestroyedThreads )
			Rsprintf(mp,"D%d",DestroyedThreads);
		if( !shortfmt ) setVStrPtrInc(mp,'\n');
	}
	if( LOGX_gzip || LOGX_gunzip ){
	Rsprintf(mp,"Gunzip: %d Gzip:%d ",LOGX_gunzip,LOGX_gzip);
		if( !shortfmt ) setVStrPtrInc(mp,'\n');
	}

	Rsprintf(mp,"Send:%9u %6.2f /%d",LOGX_sentBytes,TotalSendTime,
		LOGX_sentCount);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');
	Rsprintf(mp,"Recv:%9u %6.2f /%d",LOGX_recvBytes,LOGX_recvTime,
		LOGX_recvCount);
	if( !shortfmt ) setVStrPtrInc(mp,'\n');

	truncVStr(mp);
	return 0;
}

int numsocks(int *nmaxp);
extern int actFILEY;
extern int numFILEY;
void LOGX_stats2(PVStr(line)){
	refQStr(lp,line);
	int actsock,maxsock;

	Rsprintf(lp,"ACC#%d CON#%d %d+%d/%d+%d -%d-%d-%d-%d -%dR-%dT RES#%d/%d",
		LOGX_tcpAcc+eccLOGX_tcpAcc,LOGX_tcpCon+eccLOGX_tcpCon,
		LOGX_tcpConPrefOk,LOGX_tcpConParaOk,
		LOGX_tcpConParaTried,LOGX_tcpConRecycled,
		LOGX_tcpConAbandon1,LOGX_tcpConAbandon2,
		LOGX_tcpConAbandon3,LOGX_tcpConAbandon4,
		LOGX_tcpConRefused,LOGX_tcpConTimeout,
		(LOGX_resReq-LOGX_resHit),LOGX_resReq
	);

	actsock = numsocks(&maxsock);
	Rsprintf(lp," SOCK#%d/%d FILE#%d/%d",
		actsock,maxsock,
		actFILEY,numFILEY
	);
}

int fileIsdir(PCStr(path));
int mkdirShared(PCStr(path),int mode);
static FILE *proc_fp;
static char *proc_file;
static int proc_pid;
FILE *procLog(){
	return proc_fp;
}
void appendProcLog(FL_PAR,int pid){
	IStr(tmst,256);
	IStr(path,256);
	FILE *pfp = 0;

	if( !lPROCLOG() ){
		return;
	}
	StrftimeLocal(AVStr(tmst),sizeof(tmst),"%d%H%M",time(0),0);
	sprintf(path,"%s/delegate-procs/%s",ACTDIR(),tmst);
	if( !fileIsdir(path) ){
		mkdirShared(path,0770);
	}
	Xsprintf(TVStr(path),"/%d",pid);
	if( proc_file && streq(path,proc_file)
	 && proc_fp
	 && proc_pid == pid
	){
		pfp = proc_fp;
	}else
	if( pfp = fopen(path,"a") ){
		if( proc_pid != pid ){
			proc_file = stralloc(path);
			proc_pid = pid;
			proc_fp = pfp;
		}else{
		}
	}else{
	}
	if( pfp ){
		fprintf(pfp,"%s %s:%d\n",tmst,FL_BAR);
		fflush(pfp);
	}
}
void removeProcLog(FL_PAR){
	IStr(path,256);
	refQStr(pp,path);
	FILE *pfp;
	const char *pathf;

	if( proc_pid == getpid() )
	if( pfp = proc_fp ){
		proc_fp = 0;
		proc_pid = 0;
		strcpy(path,proc_file);
		pathf = proc_file;
		proc_file = 0;
		free((char*)pathf);
		fclose(pfp);
		unlink(path);
		/*
		9.9.5 <- 9.8.2-pre19 "-dp" + ACTDIR/delegate-procs
		free(path);
		*/
		if( pp = strrchr(path,'/') ){
			clearVStr(pp);
			rmdir(path);
		}
	}
}

const char *PRTHstage = "";
