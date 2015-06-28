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
Program:	file.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951029	extracted from DelaGate
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
/*
#include <sys/stat.h>
*/
#include <fcntl.h>
#include "ystring.h"
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include "file.h"
/*
#ifdef MIMEKIT
#define lPATHFIND() 0
#define lFILEOPEN() 0
#define lDEBUGMSG() 0
#else
*/
#include "log.h"
/*
#endif
*/

int getNonblockingIO(int fd);
int setCloseOnExec(int fd);
int clearCloseOnExec(int fd);
extern int FS_dosPath;


#ifdef S_ISUID /* set UID on execution */
#define IS_UNIX_FS
int FS_maybeUnix(){ return 1; }
int FS_withSetuid(){ return 1; }
#else
int FS_maybeUnix(){ return 0; }
int FS_withSetuid(){ return 0; }
#endif

#ifdef S_IFLNK
int FS_withSymlink(){ return 1; }
#else
int FS_withSymlink(){ return 0; }
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#endif

#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#endif

int File_stats(PCStr(path),int link,int *mode,int *uid,int *gid,int *size,int *mtime)
{	FileStat st;
	int code;

	if( link )
		code = lstat(path,&st);
	else	code = stat(path,&st);
	if( code == 0 ){
		*mode = st.st_mode;
		*uid = st.st_uid;
		*gid = st.st_gid;
		*size = st.st_size;
		*mtime = st.st_mtime;
	}
	return code;
}
int File_ident(PCStr(path),PVStr(ident))
{	FileStat st;

	if( stat(path,&st) == 0 ){
		sprintf(ident,"%x:%x:%x",ll2i(st.st_dev),ll2i(st.st_ino),ll2i(st.st_ctime));
		return 0;
	}
	setVStrEnd(ident,0);
	return -1;
}
int File_is(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return 1;
	else	return 0;
}
int File_isreg(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return S_ISREG(st.st_mode);
	else	return 0;
}
int File_ctime(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_ctime;
	else	return -1;
}
int File_mtime(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_mtime;
	else	return -1;
}
FileSize File_sizeX(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_size;
	else	return -1;
}
int File_size(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_size;
	else	return -1;
}
int File_uid(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_uid;
	else	return 0;
}
int File_gid(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_gid;
	else	return 0;
}
int File_ino(PCStr(path))
{	FileStat st;

	if( stat(path,&st) == 0 )
		return st.st_ino;
	else	return 0;
}
int file_cmp(int fd1,int fd2)
{	FileStat st1,st2;

	bzero(&st1,sizeof(st1));
	bzero(&st2,sizeof(st2));
	if( fstat(fd1,&st1) != 0 ) return -1;
	if( fstat(fd2,&st2) != 0 ) return -1;
	if( bcmp(&st1,&st2,sizeof(st1)) == 0 )
		return 0;
	else	return 1;
}
int File_cmp(PCStr(path1),PCStr(path2))
{	FileStat st1,st2;

	bzero(&st1,sizeof(st1));
	bzero(&st2,sizeof(st2));
	if( stat(path1,&st1) != 0 ) return -1;
	if( stat(path2,&st2) != 0 ) return -1;

/* st_dev will differ from each other for NFS files mounted by
 * different host name (even when they are same in IP address)
 * (/net/host/path != /net/alias/path)
 */
	if( st1.st_dev == st2.st_dev &&
	    st1.st_mtime == st2.st_mtime &&
	    st1.st_size == st2.st_size &&
	    st1.st_ino == st2.st_ino )
		return 0;
	else	return 1;
/*
return bcmp(&st1,&st2,sizeof(FileStat));
*/
}

int fcompare(FILE *fp1,FILE *fp2)
{	CStr(buf1,1024);
	CStr(buf2,1024);
	int off1,off2;
	int rc1,rc2,ri;
	int diff;

	off1 = ftell(fp1);
	off2 = ftell(fp2);
	diff = 0;
	for(;;){
		rc1 = fread(buf1,1,sizeof(buf1),fp1);
		rc2 = fread(buf2,1,sizeof(buf2),fp2);
		if( rc1 != rc2 ){
			diff = 1;
			break;
		}
		if( rc1 == 0 )
			break;
		for( ri = 0; ri < rc1; ri++ )
			if( buf1[ri] != buf2[ri] ){
				diff = 1;
				break;
			}
	}
	fseek(fp1,off1,0);
	fseek(fp2,off2,0);
	return diff;
}

static const char *_pathsep;
static const char *_PATHSEP(){
	CStr(cwd,1024);
	if( _pathsep == NULL ){
		IGNRETS getcwd(cwd,sizeof(cwd));
		if( strchr(cwd,'\\') )
			_pathsep = "\\";
		else	_pathsep = "/";
	}
	return _pathsep;
}

int FullpathOfExe(PVStr(path))
{	CStr(xpath,1024);

	if( isFullpath(path) )
		return 1;

	if( getcwd(xpath,sizeof(xpath)) == NULL )
		return 0;

	strcat(xpath,_PATHSEP());
	strcat(xpath,path);

	if( File_mtime(xpath) != -1 ){
		strcpy(path,xpath);
		return 1;
	}

	/* should scan getenv("PATHEXT") ... */
	strcat(xpath,".exe");
	if( File_mtime(xpath) != -1 ){
		strcpy(path,xpath);
		return 1;
	}
	return 0;
}

static int colonForDrive;
int ColonForDrive()
{	FILE *fp;
	CStr(path,1024);

	if( colonForDrive == 0 ){
		/* cannot use ':' in a file name if on Windows */

		IGNRETS getcwd(path,sizeof(path));
		if( isalpha(path[0]) && path[1] == ':' )
			colonForDrive =  1;
		else{
			/*
			const char *dir = "/share/dgroot/tmp";
			sprintf(path,"%s/%d:%d",dir,time(NULL),getpid());
			*/
			sprintf(path,"/tmp/%d:%d",itime(NULL),getpid());
			if( fp = fopen(path,"w") ){
				fclose(fp);
				unlink(path);
				/*
				if( file_matches(dir,":") == 0 )
					colonForDrive = 1;
				else
				*/
				colonForDrive = -1;
			}else	colonForDrive =  1;
		}
	}
	return 0 < colonForDrive;
}

char *fullPath(PCStr(path),PVStr(buff))
{
#ifndef IS_UNIX_FS
	/*
	 * //X/path -- OpenNT -- X:/path
	 */ 
	if( path[0] == '/' && path[1] == '/'
	 && 'A' <= path[2] && path[2] <= 'Z'
	 && path[3] == '/' )
	{
		setVStrElem(buff,0,path[2]);
		setVStrElem(buff,1,':');
		Xstrcpy(DVStr(buff,2),&path[3]);
		path = buff;
	}
#endif
	return (char*)path;
}
int isFullpath(PCStr(path))
{
	if( FS_dosPath || *_PATHSEP() == '\\' ){
		if( isalpha(path[0]) && path[1] == ':' ){
			if( path[2] == '\\' || path[2] == '/' )
				return 3;
			else	return 2;
		}
		if( path[0] == '\\' )
			return 1;
	}
	if( path[0] == '/' )
		return 1;
	return 0;
}
int isBoundpath(PCStr(path))
{
	if( isFullpath(path) )
		return 1;
	if( path[0] == '.' ){
		if( path[1] == 0 )
			return 1;
		if( path[1] == *_PATHSEP() )
			return 1;
		if( path[1] == '/' )
			return 1;
	}
	return 0;
}

static int _TMPSEQ;
static int _TMPDIR_set;
#ifdef IS_UNIX_FS
static const char *_TMPDIR;
#else
static const char *_TMPDIR = "\\tmp";
#endif

const char *getTMPDIR(){ return _TMPDIR; }

static void *shared_frex;

static void normpath(PCStr(src),PVStr(dst))
{	refQStr(dp,dst); /**/
	const char *sp;
	int ch;

	for( sp = src; ; sp++ ){
		ch = *sp;
		setVStrPtrInc(dp,ch);
		if( ch == 0 )
			break;
		assertVStr(dst,dp+1);
		if( *sp == '/' && sp[1] == '/' )
			sp++;
	}
	setVStrPtrInc(dp,0);
}

int setSHARE(PCStr(pathpat))
{	CStr(xpathpat,1024);

	normpath(pathpat,AVStr(xpathpat));
	shared_frex = frex_append((struct fa_stat*)shared_frex,xpathpat);
	return 0;
}
static int beshared(PCStr(path),int isdir)
{	int match;
	CStr(xpath,1024);

	if( shared_frex == 0 )
		return 0;

	normpath(path,AVStr(xpath));
	if( isdir && strtailchr(xpath) != '/' )
		strcat(xpath,"/");

	match = frex_match((struct fa_stat*)shared_frex,xpath) != 0;
	return match;
}

static const char *OWNER_DIR;
static int OWNER_UID = -1;
static int OWNER_GID = -1;

void setOWNER(PCStr(dir),int uid,int gid)
{
	OWNER_DIR = stralloc(dir); 
	OWNER_UID = uid;
	OWNER_GID = gid;
}
static int bemine(PCStr(path),int *uidp,int *gidp)
{
/*
	if( OWNER_DIR == 0 || OWNER_UID < 0 )
*/
	if( OWNER_DIR == 0 || OWNER_UID == -1 )
		return 0;
	/*if( strstr(path,OWNER_DIR) )*/
	{
		*uidp = OWNER_UID;
		*gidp = OWNER_GID;
		return 1;
	}
	return 0;
}
void chmodShared(PCStr(path))
{	int uid,gid,isdir;

	if( bemine(path,&uid,&gid) )
		IGNRETZ chown(path,uid,gid);
	isdir = fileIsdir(path);
	if( beshared(path,isdir) ){
		if( isdir )
			chmod(path,0777);
		else	chmod(path,0666);
	}
}
FILE *fopenShared(PCStr(path),PCStr(mode))
{	FILE *fp;
	int uid,gid;
	int mine;

	fp = fopen(path,mode);
	mine = bemine(path,&uid,&gid);
	if( fp == NULL &&  mine ){
		if( getuid() == 0 && uid != 0 ){
			seteuid(uid);
			fp = fopen(path,mode);
			seteuid(0);
		}
	}
	if( fp != NULL )
		chmodShared(path);
	return fp;
}
extern FILE *fopentmpfile(const char*,int);
FILE *fopentmpfileShared(PCStr(path),int remove)
{	FILE *fp;
	int mine,uid,gid;

	mine = bemine(path,&uid,&gid);
	fp = fopentmpfile(path,remove);
	if( fp == NULL && mine ){
		if( getuid() == 0 && uid != 0 ){
			seteuid(uid);
			fp = fopentmpfile(path,remove);
			seteuid(0);
		}
	}
	return fp;
}
int mkdirShared(PCStr(dir),int mode)
{	int uid,gid,rcode;
	int share,mine;
	int err;

	if( mode == 0 )
		mode = 0755;
	share = beshared(dir,1);
	mine = bemine(dir,&uid,&gid);
	rcode = mkdir(dir,mode);
	err = errno;
	if( rcode != 0 && mine ){
		if( getuid() == 0 && uid != 0 ){
			seteuid(uid);
			rcode = mkdir(dir,mode);
			err = errno;
			seteuid(0);
		}
	}
	if( rcode != 0 ){
		syslog_ERROR("mkdirShared FALED errno=%d: %s\n",err,dir);
		return rcode;
	}
	if( mine )
		IGNRETZ chown(dir,uid,gid);
	if( share )
		chmod(dir,0777);
	return rcode;
}
int chmodIfShared(PCStr(file),int mode)
{	int uid,gid;

	if( bemine(file,&uid,&gid) )
		IGNRETZ chown(file,uid,gid);
	if( !beshared(file,0) )
		return -1;
	return chmod(file,mode);
}

void setTMPDIRX(PCStr(dir),int ovw);
void setTMPDIR(PCStr(dir))
{
	setTMPDIRX(dir,1);
}
void setTMPDIRX(PCStr(dir),int ovw)
{	CStr(buff,1024);

	if( _TMPDIR_set && ovw == 0 )
		return;
	if( dir ){
		if( _TMPDIR && _TMPDIR_set )
			free((char*)_TMPDIR);
		_TMPDIR = stralloc(fullPath(dir,AVStr(buff)));
		_TMPDIR_set = 1;
	}
}

FILE *TMPFILEXX(PCStr(what),xPVStr(path))
{	const char *tmpdir;
	CStr(pathb,1024);
	CStr(buff,1024);
	FILE *fp;
	int seq;
	int now;
	int pid;
	_heapLock lock;

	tmpdir = _TMPDIR;
	if( tmpdir == NULL ){
		if( path == NULL )
			return NULL;
		if( (tmpdir = getenv("TMPDIR")) == NULL )
			tmpdir = "/tmp";
	}
	if( !fileIsdir(tmpdir) )
		mkdirShared(tmpdir,0);

	if( path == NULL )
		setPStr(path,pathb,sizeof(pathb));

	pid = getpid();
	now = time(NULL);
	heapLock(FL_ARG,lock);
	seq = ++_TMPSEQ;
	if( isWindowsCE() )
		sprintf(path,"%s/dg%X.%04X.%X",tmpdir,now,seq,pid);
	else	sprintf(path,"%s/dg%d.%06d.%d",tmpdir,pid,seq,now);
	errno = 0;
	fp = fopentmpfileShared(fullPath(path,AVStr(buff)),path==pathb);
	heapUnLock(FL_ARG,lock);

	if( fp != NULL )
		syslog_DEBUG("TMPFILE(%s) = (%d) %s\n",what,fileno(fp),path);
	else	syslog_ERROR("TMPFILE(%s): cannot create (%d) = %s\n",what,errno,path);
	return fp;
}

#if isWindowsCE()
FILE *XX_TMPFILEXX(PCStr(what),xPVStr(path));
static FILE *TMPFILEXXX(PCStr(what),PVStr(path)){
	return XX_TMPFILEXX(what,BVStr(path));
}
#define TMPFILEXX(what,path) TMPFILEXXX(what,path)
#endif

FILE *TMPFILEX(PVStr(path))
{
	return TMPFILEXX("*",AVStr(path));
}

#ifndef EMFILE
#define EMFILE -1
#endif

FILE *TMPFILE(PCStr(what))
{	FILE *fp;
	int besilent;
	const char *tmpdir;
	int serrno;

	fp = TMPFILEXX(what,VStrNULL);
	if( fp == NULL )
		fp = tmpfile();
	serrno = errno;

	besilent = what[0] == '-';

	if( fp != NULL ){
		setCloseOnExec(fileno(fp));
		if( !besilent )
		syslog_DEBUG(">>>TMPFILE(%s)>>>%x[%d]\n",what,p2i(fp),fileno(fp));
	}else{
		tmpdir = _TMPDIR;
		if( tmpdir == NULL )
			tmpdir = "(system default, may be /tmp or /usr/tmp)";
		syslog_ERROR(">>>TMPFILE(%s)>>> cannot create.\n",what);
		if( errno == EMFILE ){
			syslog_ERROR(">>> Too many open files.\n");
		}else{
			syslog_ERROR(">>> You MUST have the WRITE permission\n");
			syslog_ERROR(">>> to the TMPDIR=%s\n",tmpdir);
		}
		if( lMULTIST() ){
			fp = fdopen(openNull(0),"r");
			syslog_ERROR("### FATAL, try to continue, e%d %X\n",serrno,p2i(fp));
			return fp;
		}
		exit(0);
	}
	return fp;
}

static int tmpfiles[1] = {-1};
static int tmpfilepids[1];
FILE *reusableTMPFILE(PCStr(what),iFUNCP where)
{	FILE *tmp;
	int tx,fd,pid;

	if( isWindowsCE() ){ /* 9.9.5 with light-weight on-memory tmpfile */
		tmp = TMPFILE(what);
		syslog_DEBUG("##reuseTMPFILE(%s) %X/%d\n",what,p2i(tmp),fileno(tmp));
		return tmp;
	}

	tx = 0;
	fd = tmpfiles[tx];
	pid = getpid();

	if( 0 <= fd && tmpfilepids[0] == pid ){
		tmp = fdopen(dup(fd),"w+");
		fseek(tmp,0,0);
		Ftruncate(tmp,0,0);
		syslog_DEBUG(">>>TMPFILE(%s) reused [%d]->[%d]\n",what,
			fd,fileno(tmp));
	}else{
		tmp = TMPFILE(what);
		tmpfiles[tx] = dup(fileno(tmp));
		tmpfilepids[tx] = pid;
	}
	return tmp;
}


FILE *Tmpfile()
{
	return TMPFILE("Tmpfile");
}

#ifdef NULLFP
#undef NULLFP /* defined in <sys/file.h> of Solaris */
#endif

int Ofclose(FILE *fp);
static FILE *NullFP;
int isNULLFP(FILE *fp){
	return fp == NullFP;
}
void closeNULLFP(){
	if( NullFP ){
		/*
		Ofclose(NullFP);
		*/
		FILE *nullfp = NullFP;
		NullFP = 0;
		Ofclose(nullfp);
	}
}
FILE *NULLFP(){
	FILE *tmp;

	if( NullFP == NULL ){
		tmp = TMPFILE("NULLFP");
		if( tmp == NULL || fileno(tmp) < 0 ){
			daemonlog("F","--FATAL: NULLFP ERROR A\n");
			_exit(-1);
		}
		/*close(fileno(NULLFP)); should hold to avoid reuse */
		NullFP = fdopen(fileno(tmp),"r");
		if( NullFP == NULL ){
			daemonlog("F","--FATAL: NULLFP ERROR B\n");
			_exit(-1);
		}
	}
	return NullFP;
}
static FILE *WrNullFP;
FILE *WRNULLFP(){
	if( WrNullFP == 0 ){
		if( isWindows() )
			WrNullFP = fopen("nul:","w");
		else	WrNullFP = fopen("/dev/null","w");
	}
	return WrNullFP;
}

int nullFd = -1;
int setNullFd(int fd){
	int ofd = nullFd;
	nullFd = fd;
	return ofd;
}
/* "nullFd" needs to be inheritable via env2str/str2env (on Win32) */
int closeNullFd(){
	int fd = nullFd;
	if( 0 <= fd ){
		nullFd = -1;
		close(fd);
		return fd;
	}else{  
		return 0;
	}       
}     
int getNullFd(PCStr(what)){
	int nfd;

	if( 0 <= nullFd ){
		nfd = nullFd;
	}else{
		if( isWindows() )
			nfd = open("nul",0);
		else	nfd = open("/dev/null",0);
		if( 0 <= nfd )
			nullFd = nfd;
	}
	return nfd;
}
int openNull(int rw){
	int xfd;
	FILE *xfp;

	xfd = open("/dev/null",rw);
	if( 0 <= xfd )
		return xfd;

	xfp = TMPFILE("openNull");
	if( xfp != NULL ){
		xfd = dup(fileno(xfp));
		fclose(xfp);
		clearCloseOnExec(xfd);
		return xfd;
	}
	return -1;
}

int dupclosed_FL(FL_PAR,int fd){
	int nfd;

	if( NullFP && fileno(NullFP) == fd ){
		/* 9.9.2 to keep isreg(NULLFP()) true */
		porting_dbg("##dupclosed(%d) NULLFP:%X <= %s:%d",
			fd,p2i(NullFP),FL_BAR);
		if( enbugNULLFP_DUPCLOSED() ){
		}else{
			return -1;
		}
	}
	/*
	if( isWindows() )
		nfd = open("nul",0);
	else	nfd = open("/dev/null",0);
	*/
	nfd = getNullFd("dupclosed");
	if( nfd < 0 ){
		porting_dbg("--dupclosed() no NULL device");
		Xclose_FL(FL_BAR,fd);
		return -1;
	}
	if( Xdup2_FL(FL_BAR,nfd,fd) < 0 ){
		porting_dbg("--dupclosed() cannot dup2(%d,%d) errno=%d <= %s:%d",
			nfd,fd,errno,FL_BAR);
		return -1;
	}
	return 0;
}

FileSize copyfile2(FILE *sfp,FILE *dfp,int doflush)
{	CStr(buff,8*1024);
	FileSize totalc;
	int rcc;
	int wcc;

	totalc = 0;
	for(;;){
		rcc = fread(buff,1,sizeof(buff),sfp);
		if( rcc == 0 )
			break;
		totalc += rcc;
		/*
		if( fwrite(buff,1,rcc,dfp) == 0 )
		*/
		wcc = fwrite(buff,1,rcc,dfp);
		if( wcc <= 0 )
			break;
		if( ferror(dfp) ){
			syslog_ERROR("copyfile() detected ferror()\n");
			break;
		}
	}
	if( doflush )
		fflush(dfp);
	return totalc;
}

FileSize copyfile1(FILE *sfp,FILE *dfp)
{
	return copyfile2(sfp,dfp,1);
}


void path_escchar(xPVStr(path))
{	char sc;
	const char *sp;
	refQStr(dp,path); /**/
	const char *buff;

	if( !ColonForDrive() )
		return;

	if( isalpha(path[0]) && path[1] == ':' )
		path += 2;

	/*
	 * escape "//", "\\", and one of ':*?"<>|' on Windows
	 */
	if( strpbrk(path,":") == NULL && strstr(path+2,"./") == NULL )
	if( strstr(path,"//") == 0 )
	if( strstr(path,"\\\\") == 0 )
	if( strpbrk(path,":*?\"<>|") == 0 )
		return;

	buff = stralloc(path);
	dp = path;
	for( sp = buff; sc = *sp; sp++ ){
		assertVStr(path,dp+3);
		if( sc == '.' && sp[1] == '/' ){
			setVStrPtrInc(dp,'%');
			setVStrPtrInc(dp,'2');
			setVStrPtrInc(dp,'E');
		}else
		if( sc == ':' ){
			if( sp[1] == '/' ){
				setVStrPtrInc(dp,'%');
				setVStrPtrInc(dp,'3');
				setVStrPtrInc(dp,'A');
			}else{
				setVStrPtrInc(dp,'.');
				setVStrPtrInc(dp,'.');
			}
		}else
		if( isWindows() && sc == '/' && sp[1] == '/' ){
			setVStrPtrInc(dp,'%');
			setVStrPtrInc(dp,'2');
			setVStrPtrInc(dp,'F');
		}else
		if( isWindows() && sc == '?' ){
			setVStrPtrInc(dp,'%');
			setVStrPtrInc(dp,'3');
			setVStrPtrInc(dp,'F');
		}else
		if( isWindows() && sc == '|' ){
			setVStrPtrInc(dp,'%');
			setVStrPtrInc(dp,'7');
			setVStrPtrInc(dp,'C');
		}else	setVStrPtrInc(dp,sc);
	}
	setVStrEnd(dp,0);
	free((char*)buff);
}

int file_is(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return 1;
	else	return 0;
}
int file_isreg(int fd)
{	FileStat status;

	if( fstat(fd,&status) == 0 )
		return S_ISREG(status.st_mode);
	return 0;
}
int file_isregular(int fd)
{	FileStat st;

	if( fstat(fd,&st) == 0 )
		return S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
	else	return 0;
}
int file_isdir(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return S_ISDIR(stat.st_mode);
	return 0;
}
int fileIsdir(PCStr(path))
{	FileStat status;

	if( stat(path,&status) == 0 )
		return S_ISDIR(status.st_mode);
	return 0;
}
int fileIsflat(PCStr(path))
{	FileStat status;

	if( stat(path,&status) == 0 )
		return S_ISDIR(status.st_mode) == 0;
	return 0;
}
int file_ino(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_ino;
	else	return 0;
}
int file_size(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_size;
	else	return -1;
}
int file_mtime(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_mtime;
	else	return -1;
}

char *freadfile(FILE *fp,int *sizep)
{	FILE *tmp;
	const char *data;
	int size,rcc;

	if( size = *sizep ){
		data = (char*)malloc(size+1);
		rcc = fread((char*)data,1,size,fp); /**/
	}else{
		tmp = TMPFILE("freadfile");
		size = copyfile1(fp,tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		data = (char*)malloc(size+1);
		rcc = fread((char*)data,1,size,tmp); /**/
		fclose(tmp);
	}
	((char*)data)[rcc] = 0; /**/
	*sizep = rcc;
	return (char*)data;
}

char *Fgets(PVStr(str),int size,FILE *fp)
{	const char *rstr;
	const char *dp;

	rstr = fgets(str,size,fp);
	if( rstr != NULL )
		if( dp = strpbrk(str,"\r\n") )
			truncVStr(dp);
	return (char*)rstr;
}
int Fputs(PCStr(str),FILE *fp)
{	const char *dp;
	int rcode;
	int len,rcc;

	/* signal(SIGPIPE,... */

	if( (dp = strtailstr(str,"\r\n")) || (dp = strtailstr(str,"\n")) )
		len = dp - str;
	else	len = strlen(str);

	rcc = fwrite(str,1,len,fp);
	rcode = fputs("\r\n",fp);
	fflush(fp);
	return rcode;
}
int Write(int fd,PCStr(buf),int len)
{	int nw,wcc,wc1;

	nw = 0;
	for(wcc = 0; wcc < len; wcc += wc1 ){
		nw++;
		wc1 = write(fd,buf+wcc,len-wcc);
		if( wc1 <= 0 )
			break;
	}
	return wcc;
}
int Fwrite(PCStr(buf),int esize,int ecount,FILE *fp)
{	int re,we;
	int fd;

	re = ecount;
	fd = fileno(fp);
	do {
		we = fwrite(buf,esize,re,fp);
		if( we != re )
		syslog_ERROR("Fwrite(%d): partial (%d/%d/%d) NBIO=%d errno=%d\n",
			fd,we,re,ecount,getNonblockingIO(fd),errno);

		if( we <= 0 )
			break;
		else	re -= we;
	} while( 0 < re );
	return ecount - re;
}


static int tmpFileFd = -1;
static int tmpFilePid = -1;
static int tmpFileIno = -1;
static const char *tmpFileWhat = "";

void freeTmpFile(PCStr(what))
{
	if( lMULTIST() ){
		int SocketOf(int);
		porting_dbg("-- NO freeTmpFile(%s)[%d] S[%d] H[%d]",what,
			tmpFileFd,SocketOf(tmpFileFd),
			fd2handle(tmpFileFd));
		tmpFileFd = -1;
		return;
	}
	if( 0 <= tmpFileFd ){
		close(tmpFileFd);
		tmpFileFd = -1;
		tmpFilePid = -1;
		tmpFileIno = -1;
		tmpFileWhat = "";
	}
}
FILE *getTmpFile(PCStr(what))
{	FILE *fp;
	int pid;
	CStr(msg,1024);

	if( lMULTIST() ){
		if( tmpFileFd && tmpFileFd != -1 ){
			int doDeleteOnClose(int fd,int fh);
			doDeleteOnClose(tmpFileFd,0);
		}
		fp = TMPFILE("getTmpFile");
		tmpFileFd = fileno(fp);
		return fp;
	}

	pid = getpid();
	sprintf(msg,"getTmpFile: fd=%d [%d]%s->[%d]%s",
		tmpFileFd,tmpFilePid,tmpFileWhat,pid,what);

	if( 0 < tmpFileFd ){
		int ino;
		ino = file_ino(tmpFileFd);
		/*
		if( tmpFilePid != pid || tmpFileWhat != what ){
		*/
		if( tmpFilePid != pid || tmpFileWhat != what
		 || tmpFileIno != ino
		){
			/*
			syslog_ERROR("#### %s\n",msg);
			*/
			syslog_ERROR("#### %s ino=%d->%d\n",msg,tmpFileIno,ino);
			tmpFileFd = -1;
			freeTmpFile(what);
		}
	}
	syslog_DEBUG("%s\n",msg);
	if( tmpFileFd < 0 ){
		fp = TMPFILE(what);
		tmpFileFd = dup(fileno(fp));
		tmpFilePid = pid;
		tmpFileIno = file_ino(tmpFileFd);
		tmpFileWhat = what;
	}else{
		fp = fdopen(dup(tmpFileFd),"r+");
		if( fp == NULL ){
			syslog_ERROR("-- getTmpFile: fd=%d ino=%d errno=%d\n",
				tmpFileFd,file_ino(tmpFileFd),errno);
			syslog_ERROR("-- CANNOT OPEN: %s\n",msg);
			abort();
		}
		fseek(fp,0,0);
	}
	return fp;
}

const char **vect_PATH(PCStr(path))
{	CStr(pathb,2048);
	char del;
	const char *pathv[16]; /**/
	const char **ppv;
	int lc;

	strcpy(pathb,path);
	if( strchr(pathb,';') ) /* Windows */
		del = ';';
	else	del = ':';
	lc = list2vect(pathb,del,elnumof(pathv)-1,pathv);
	pathv[lc] = 0;
	ppv = dupv(pathv,0);
	return ppv;
}
/*
 * "/" in PATH like "/Program Files/DeleGate/lib/"
 * should be replaced with "\" (_PATHSEP())
 */
FILE *fopen_PATHX(const char *pathv[],PCStr(file),PCStr(mode),int ftype,PVStr(xpath));
FILE *fopen_PATH(const char *pathv[],PCStr(file),PCStr(mode),PVStr(xpath))
{
	return fopen_PATHX(pathv,file,mode,FTY_ANY,BVStr(xpath));
}
FILE *fopen_PATHX(const char *pathv[],PCStr(file),PCStr(mode),int ftype,PVStr(xpath))
{	int li;
	const char *dir1;
	CStr(path1,1024);
	FILE *fp;

	for( li = 0; dir1 = pathv[li]; li++ ){
		if( isWindows() && (streq(dir1,"/") || streq(dir1,"\\")) ){
			/* 9.9.1 retrieving //path might cause delay */
			if( LOG_VERBOSE )
			fprintf(stderr,"##ABS fopen_PATH(%s)\n",file);
			if( *file == '/' || *file == '\\' )
				strcpy(path1,file);
			else	sprintf(path1,"/%s",file);
		}else
		if( *dir1 == 0 || strcmp(dir1,".") == 0 )
			strcpy(path1,file);
		else
		/* should be like this in 9.2.4 ...
		 * >>> 9.8.1 done by deltrailslash() in Xfopen()
		if( *file == 0 ){
			sprintf(path1,"%s",dir1);
		}else
		*/
		if( strtailstr(dir1,_PATHSEP()) )
			sprintf(path1,"%s%s",dir1,file);
		else	sprintf(path1,"%s%s%s",dir1,_PATHSEP(),file);
		if( ftype && (ftype & FTY_DIR) == 0 && fileIsdir(path1) ){
			porting_dbg("##fopen_PATHX(%s) ign.dir.{%s}%s <= %s:%d",
				mode,dir1,path1,whStr(xpath));
			continue;
		}
		if( *mode == 'x' )
			fp = fopen(path1,"r");
		else	fp = fopen(path1,mode);

		if( errno == EACCES && fileIsdir(path1) ){
			syslog_ERROR("WARNING: fopen_PATH(%s):isdir %s\n",
				mode,path1);
			fp = TMPFILE("fopen_PATH-DIR");/* dummy for Win32 */
		}

		if( lPATHFIND() ){
			fprintf(stderr,"### [%d] %X \"%s\"\n",li,p2i(fp),path1);
		}
		syslog_DEBUG("### [%d] %s %x\n",li,path1,p2i(fp));
		if( fp != NULL ){
			if( xpath ){
				if( *dir1 == 0 || strcmp(dir1,".") == 0 ){
					IGNRETS getcwd((char*)xpath,256);
					if( strtailchr(xpath) == '/'
					 || strtailchr(xpath) == '\\'
					){
					 /* 9.8.1 don't make duplicate "//" */
					}else
					strcat(xpath,_PATHSEP());
					strcat(xpath,path1);
				}
				else
				strcpy(xpath,path1);
			}
			return fp;
		}
	}
	return NULL;
}
FILE *fopen_PATHLIST(PCStr(pathlist),PCStr(file),PCStr(mode),PVStr(xpath))
{	const char **lpathv;
	FILE *fp;

	lpathv = vect_PATH(pathlist);
	fp = fopen_PATH(lpathv,file,mode,AVStr(xpath));
	freev((char**)lpathv);
	/*
	free(lpathv);
	*/
	return fp;
}
FILE *fopen_LIBPATH(PCStr(file),PCStr(mode),PVStr(xpath))
{	FILE *fp;
	const char *libpath;

	if( isFullpath(file) ){
		if( fp = fopen(file,mode) )
			strcpy(xpath,file);
		else	setVStrEnd(xpath,0);
	}else
	if( libpath = getenv("LIBPATH") )
	{
		if( lPATHFIND() ){
			fprintf(stderr,"### find '%s' in LIBPATH='%s'\n",
				file,libpath);
		}
		fp = fopen_PATHLIST(libpath,file,mode,AVStr(xpath));
	}
	else	fp = 0;
	return fp;
}
int LIBFILE_IS(PCStr(file),PVStr(rxfile))
{	FILE *fp;
	CStr(afile,1024);
	CStr(xfileb,1024);
	defQStr(xfile); /*alt*/

	if( rxfile )
		setVStrEnd(rxfile,0);
	if( file == NULL )
		return 0;

	if( rxfile )
		setQStr(xfile,rxfile,(UTail(rxfile)-rxfile)+1);
	else	setQStr(xfile,xfileb,sizeof(xfileb));

	if( fp = fopen_LIBPATH(file,"r",AVStr(xfile)) ){
		fclose(fp);
		if( rxfile && rxfile[0] == 0 )
			strcpy(rxfile,file);
		return 1;
	}
	return 0;
}

/*
 * Normalize a path name to be compatible between Unix and Windows:
 *
 *   ""      -> "."    (?)
 *   "X:"    -> "X:/"
 *   "path/" -> "path" stati64()/Win rejects this even for a directory
 *                     stat()/Win and Solaris allows this even for a flat file
 */
int deltrailslash(PCStr(ipath),PVStr(pb)){
	int del = 0;
	int len;

	if( strtailchr(ipath) != '/' && strtailchr(ipath) != '\\' )
		return 0;

	strcpy(pb,ipath);
	while( strtailchr(pb) == '/' || strtailchr(pb) == '\\' ){
		len = strlen(pb);
		if( isalpha(pb[0]) && pb[1] == ':' ){ /* full path */
			if( len <= 3 ){
				break;
			}
		}else
		if( pb[0] == '/' || pb[0] == '\\' ){  /* absolute path */
			if( len <= 1 ){
				break;
			}
		}else{                                /* relative path */
			if( len <= 1 ){
				/* never happen */
				break;
			}
		}
		del++;
		setVStrEnd(pb,len-1);
	}
	if( del ){
		if( fileIsdir(pb) ){
			syslog_ERROR("--deltrailslash(%s) %d\n",pb,del);
			return del;
		}
	}
	return 0;
}
int pathnorm(PCStr(what),PCStr(path),PVStr(xpath)){
	const char *npath = 0;
	if( isWindows() ){
		if( path[0] == 0 ){
			/*
			strcpy(xpath,".");
			npath = xpath;
			*/
		}else
		if( isalpha(path[0]) && path[1] == ':' && path[2] == 0 ){
			sprintf(xpath,"%s/",path);
			npath = xpath;
		}else
		if( deltrailslash(path,AVStr(xpath)) ){
			npath = xpath;
		}else
		if( strtailchr(path) == '/' ){
		/* should be like this in 9.2.4 ...
		 * >>> 9.8.1 done by deltrailslash()
		if( strtailchr(path) == '/' || strtailchr(path) == '\\' ){
		*/
			if( isalpha(path[0]) && path[1]==':' && 3 < strlen(path)
			 || (path[0]=='/' || path[0]=='\\') && 2 < strlen(path)
			){ 
				strcpy(xpath,path);
				setVStrEnd(xpath,strlen(xpath)-1);
				npath = xpath;
			}
		}
	}
	if( npath != 0 ){
		if( lDEBUGMSG() )
		porting_dbg("pathnorm(%s)[%s]->[%s]",what,path,xpath);
		return 1;
	}else	return 0;
}

#ifdef statX
int Xstat(PCStr(path),FileStat *st){
	int rcode;
	CStr(xpath,1024);

	if( pathnorm("Xstat",path,AVStr(xpath)) )
		path = xpath;
	rcode = statX(path,st);
	return rcode;
}
#endif

/*
 * opening large-file
 * checking off-limit access
 * "/dev/null" / "nul" selection
 * freopen() should also be redirected
 * ":" to ".." conversion on DOS file system
 * bare open() should not used
 */
FILE *XXfopen(const char *F,int L,const char *path,const char *mode);
#ifdef fopen
#undef fopen
#endif
int fopen_debug = 0;
#ifdef O_LARGEFILE
FILE *large_fopen(PCStr(path),PCStr(mode)){
	int fd;
	int flag;
	FILE *fp;

	if( strchr(mode,'a') ){
		if( strchr(mode,'+') )
			flag = O_CREAT|O_APPEND|O_RDWR;
		else	flag = O_CREAT|O_APPEND|O_WRONLY;
	}else
	if( strchr(mode,'w') ){
		if( strchr(mode,'+') )
			flag = O_CREAT|O_RDWR;
		else	flag = O_CREAT|O_WRONLY|O_TRUNC;
	}else{
		if( strchr(mode,'+') )
			flag = O_RDWR;
		else	flag = O_RDONLY;
	}
	fd = open(path,O_LARGEFILE|flag,0666);
	if( 0 <= fd ){
		fp = fdopen(fd,mode);
	}else{
		fp = NULL;
	}
	return fp;
}
#else
FILE *large_fopen(PCStr(path),PCStr(mode)){
	return NULL;
}
#endif
FILE *Xfopen(const char *F,int L,PCStr(path),PCStr(mode)){
	FILE *fp;
	CStr(xpath,1024);

	/*
	 * 9.8.1 enabled. this pathnorm() is added but disabled (why?)
	 * in 9.2.2-pre3 (060526)
	 */
	if( pathnorm("Xfopen",path,AVStr(xpath)) ){
		syslog_ERROR("Xfopen(%s)->(%s)\n",path,xpath);
		path = xpath;
	}

#if defined(O_LARGEFILE) && defined(STAT64)
	if( fp = large_fopen(path,mode) ){
		return fp;
	}
#endif
	/*
	if( isWindowsCE() ){
		fp = XX_fopen(path,mode);
	}else
	fp = fopen(path,mode);
	*/
	fp = XXfopen(F,L,path,mode);
#if defined(O_LARGEFILE) && defined(EFBIG)
	if( fopen_debug ){
		fprintf(stderr,"---- %X (%s) %s\n",p2i(fp),mode,path);
	}
	if( fp == NULL ){
		if( errno == EFBIG || errno == EOVERFLOW ){
			fp = large_fopen(path,mode);
		}
	}
#endif
	/* should be like this in 9.2.4 ...
	if( fp == NULL && isWindows() && strchr(mode,'r') ){
		if( strtailstr(path) == '/' || strtailstr(path) == '\\' ){
			if( fileIsdir(path) ){
				errno = EACCES;
			}
		}
	}
	*/
	if( lFILEOPEN() ){
		fprintf(stderr,"-- -dO %8X fopen(%s,%s)\n",p2i(fp),path,mode);
	}
	return fp;
}

#ifdef fdopen
#undef fdopen
#endif
FILE *XXfdopen(const char *F,int L,int fd,const char *mode);
FILE *Xfdopen(PCStr(F),int L,int fd,PCStr(mode)){
	FILE *fp;
	fp = XXfdopen(F,L,fd,mode);
	if( fp == NULL ){
		daemonlog("F","--FATAL(%s:%d) Xfdopen(%d,%s)=0, e%d\n",F,L,
			fd,mode,errno);
	}
	return fp;
}

#ifdef fwrite
#undef fwrite
#endif
int inXfwrite;
const char *FL_F_Xfwrite;
int FL_L_Xfwrite;
int Xfwrite(const char *F,int L,const void *b,int z,int n,FILE *f){
	int ne;
	int pfe = ferror(f);

	if( fileno(f) < 0 ){
		/* 9.9.4 */
		putfLog("-- Xfwrite(%d,%d,%X/%X) %s:%d",z,n,p2i(f),fileno(f),F,L);
		return -1;
	}

	if( isWindowsCE() ){
		ne = XX_fwrite(F,L,b,z,n,f);
	}else
	{
		inXfwrite++;
		FL_F_Xfwrite = F;
		FL_L_Xfwrite = L;
	ne = fwrite(b,z,n,f);
		inXfwrite--;
	}

	if( lDEBUGMSG() )
	if( (0 != n && ne <= 0) || ferror(f) )
	if( f == NullFP ){
	}else
	{
		fprintf(stderr,
		"-dD[%d] Xfwrite(%d,%d,%d)=%d, ferror()=%d (%d), errno=%d\n",
			getpid(),z,n,fileno(f),ne,ferror(f),pfe,errno);
	}

	if( 0 < ne ){
		if( ferror(f) ){
			if( lDEBUGMSG() )
			fprintf(stderr,"(Win) fwrite()=%d -> %d, errno=%d\n",
				ne,0,errno);
			ne = 0;
		}
	}
	return ne;
}

#ifdef fputs
#undef fputs
#endif
int inXfputs;
const char *FL_F_Xfputs;
int FL_L_Xfputs;
int Xfputs_FL(FL_PAR,const char *s,FILE *f){
	int rcode;
	inXfputs++;
	FL_F_Xfputs = FL_F;
	FL_L_Xfputs = FL_L;
	rcode = fputs(s,f);
	inXfputs--;
	return rcode;
}
int Xfputs(const char *s,FILE *f){
	int rcode;
	rcode = fputs(s,f);

	if( rcode != EOF ){
		if( ferror(f) ){
			if( lDEBUGMSG() )
			fprintf(stderr,"(Win) fputs()=%d -> %d\n",rcode,EOF);
			rcode = EOF;
		}
	}
	return rcode;
}

#ifdef fclose
#undef fclose
#endif
int Ofclose(FILE *fp){
	return fclose(fp);
}
void del_FILEY(FL_PAR,const char *wh,FILE *fp);
int XXfclose(const char *F,int L,FILE *fp);

/* 9.9.4 MTSS fclose() must be multi-thread-signal-safe by XXfclose()
 * not to let the mutex in fclose() be left locked by longjump() from
 * a signal-handler (as io_timeout)
 */
int inXfclose;
const char *FL_F_Xfclose;
int FL_L_Xfclose;
int Xfclose(const char *F,int L,FILE *fp){
	if( NullFP ){
		if( lDEBUGMSG() )
		if( fp == NullFP ){
			fprintf(stderr,"[%d] %X %s:%d -- Xfclose(%X)\n",
				getpid(),p2i(NullFP),F,L,p2i(fp));
		}
		/* should suppress fclose(NULLFP()) ... */
	}
	if( NullFP || WrNullFP )
	if( fp == NullFP || fp == WrNullFP ){
		/* 9.9.2 to avoid fclose(NULLFP()) */
		porting_dbg("##Xfclose(%X/%d/%d) NULLFP:%X/%X <= %s:%d",
			p2i(fp),fileno(fp),file_isreg(fileno(fp)),
			p2i(NullFP),p2i(WrNullFP),F,L);
		if( enbugNULLFP_FCLOSE() ){
		}else{
			return -1;
		}
	}

	/*
	if( fileno(fp) < 0 )
	if( numthreads() || pnumthreads() ){
		putfLog("##Xfclose(%d) suppressed <= %s:%d",fileno(fp),F,L);
		return -1;
	}
	*/
	if( isWindows()  /* any file must be closed by XX_fclose() */
	 || numthreads() /* must be done under mutex */
	 || pnumthreads() /* 9.9.4 MTSS for the ResponseFilter process */
	){
		int rcode;
		inXfclose++;
		FL_F_Xfclose = F;
		FL_L_Xfclose = L;
		if( !isWindowsCE() ){
			/* 9.9.4 MTSS to reduce the time spent in mutex for
			 * fclose() with free() to be protected from signals.
			 * fflush() might with flockfile() to be protected and
			 * takes long time, but it is interruptable currently...
			 */
			if( fileno(fp) < 0 && strstr(F,"fcloseFILE") ){
				/* 9.9.8 fileno()=-1 set by fcloseFILE() */
			}else
			Xfflush(F,L,fp);
		}
		rcode = XXfclose(F,L,fp);
		inXfclose--;
		return rcode;
	}
	del_FILEY(F,L,"Xfclose",fp);
	return fclose(fp);
}


#if defined(_MSC_VER) || defined(__CYGWIN__) || defined(__EMX__)
int FS_dosPath = 1;
#define IsSep(ch)		(ch == '/' || ch == '\\')
#define FindDirSep(path)	strpbrk(path,"/\\")
#define FindRDirSep(path)	strrpbrk(path,"/\\")
#else
int FS_dosPath = 0;
#define IsSep(ch)		(ch == '/')
#define FindDirSep(path)	strchr(path,'/')
#define FindRDirSep(path)	strrchr(path,'/')
#endif

int isFullpath(PCStr(path));
void chdir_cwd(PVStr(cwd),PCStr(go),int userdir)
{	refQStr(tp,cwd); /**/
	const char *cp;
	int uplen,len;

	for( cpyQStr(tp,cwd); *tp; tp++ ){}
	if( len = isFullpath(go) ){
		tp = (char*)cwd;
		while( 0 < len-- ){
			assertVStr(cwd,tp+1);
			setVStrPtrInc(tp,*go++);
		}
	}else
	if( userdir && go[0] == '~' ){
		if( go[1] == 0   ){ tp = (char*)cwd; go += 1; }else
		if( IsSep(go[1]) ){ tp = (char*)cwd; go += 2; }
	}

	while( *go ){
		uplen = 0;
		if( go[0] == '.' ){
			if( go[1] == 0   ){ go += 1; break; }
			if( IsSep(go[1]) ){ go += 2; continue; }
			if( go[1] == '.' ){
				if( go[2] == 0   ){ uplen = 2; } else
				if( IsSep(go[2]) ){ uplen = 3; }
			}
		}
		if( uplen ){
			if( cwd < tp ){
				while( cwd+1 < tp ){
					if( IsSep(tp[-1]) )
						tp--;
					else	break;
				}
				setVStrEnd(tp,0);
				if( cp = FindRDirSep(cwd) ){
					if( cp == cwd  )
						tp = (char*)cp + 1;
					else	tp = (char*)cp;
				}else	tp = (char*)cwd;
			}
			go += uplen;
		}else{
			if( cp = FindDirSep(go) )
				len = (cp - go) + 1;
			else	len = strlen(go);

			if( cwd < tp && !IsSep(tp[-1]) ){
				setVStrPtrInc(tp,'/');
			}
			strncpy(tp,go,len);
			tp += len;
			go += len;
		}
	}
	while( cwd+1 < tp ){
		if( IsSep(tp[-1]) )
			tp--;
		else	break;
	}
	setVStrEnd(tp,0);
}

#if !isWindowsCE()
int usedFDX(PCStr(F),int L,int usedfd){
	int fd;

	fd = dup(0);
	close(fd);
	if( fd != usedfd ){
		/*fprintf(stderr,"SETFD[%d]\n",usedfd);*/
		syslog_DEBUG("usedFD():setCloseOnExec(%d)\n",fd);

		/*
		fprintf(stderr,"----[%d] %s:%d usedFD():setCloseOnExec(%d)\n",
			getpid(),F,L,fd);
		dumpFds(stderr);
		*/
		setCloseOnExec(usedfd);
		return 1;
	}
	return 0;
}
int nextFDX(PCStr(F),int L){
	int fd;

	fd = dup(0);
	close(fd);
	return fd;
}
#endif
