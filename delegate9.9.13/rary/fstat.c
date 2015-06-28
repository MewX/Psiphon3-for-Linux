/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	fstat.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961010	extracted from misc.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "file.h"
#include <stdlib.h>
#include <time.h>
int INHERENT_lstat();

#include <sys/types.h>
#include <sys/stat.h>
#ifdef S_ISUID /* set UID on execution */
#include <pwd.h>
#endif


#if defined(__CYGWIN__)
#include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifndef S_ISLNK
#ifndef S_IFLNK
#define S_ISLNK(m)	0
#else
#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#endif
#endif

#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#endif
#ifndef S_ISFIFO
#ifdef S_IFIFO
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#else
#define S_ISFIFO(m) 0
#endif
#endif

#if defined(S_ISUID) && defined(S_IRWXU)
#define GETEUID()	geteuid()
#define GETEGID()	getegid()
#define STUID(st)	st.st_uid
#define STGID(st)	st.st_gid
#else
#define GETEUID()	0
#define GETEGID()	0
#define STUID(st)	0
#define STGID(st)	0
#define S_IRWXU		(S_IREAD | S_IWRITE | S_IEXEC)
#define S_IRWXG		(S_IREAD | S_IWRITE | S_IEXEC)
#define S_IRWXO		(S_IREAD | S_IWRITE | S_IEXEC)
#endif

/*
 * This check should be done by access() function, but the function
 * can be platform dependent ??
 */
int access_RWX(PCStr(path))
{	FileStat st;
	int mode,uid,gid;

	if( isWindowsCE() ){
		return 0;
	}
#if defined(__CYGWIN__)
	if( access(path,R_OK|W_OK|X_OK) == 0 )
		return 0;
#endif

	if( stat(path,&st) == 0 ){
		mode = st.st_mode;
		if( STUID(st) == GETEUID() && (mode & S_IRWXU) == S_IRWXU )
			return 0;
		if( STGID(st) == GETEGID() && (mode & S_IRWXG) == S_IRWXG )
			return 0;
		if( (mode & S_IRWXO) == S_IRWXO )
			return 0;
	}
	return -1;
}

int valid_fdl(PVStr(vfd))
{	int fd,nvfd,lastv;
	refQStr(vp,vfd); /**/

	nvfd = 0;
	lastv = 0;
	for( fd = 0; fd < 256; fd++ ){
		if( lastv+8 < fd )
			break;
		if( file_is(fd) ){
			sprintf(vp,"[%2d]",fd);
			vp += strlen(vp);
			nvfd++;
			lastv = fd;
		}
	}
	return nvfd;
}
void valid_fds(PCStr(where))
{	CStr(vfd,256);

	fprintf(stderr,"##[%d][%s]##",getpid(),where);
	valid_fdl(AVStr(vfd));
	fprintf(stderr,"%s\n",vfd);
}

static int touch_ctime(int fd){
	FileStat st0;
	int omode,xmode;

	if( fstat(fd,&st0) != 0 )
		return -1;

	omode = st0.st_mode;
	xmode = (omode & ~S_IEXEC) | (~(omode & S_IEXEC) & S_IEXEC);
	if( fchmod(fd,xmode) != 0 )
		return -1;
	return fchmod(fd,omode);
}

int fileIsremote1(int fd)
{	FileStat st1;
	int time0,time1;

	if( isatty(fd) )
		return 0;

	time0 = time(0);
	if( touch_ctime(fd) < 0 )
		return -1;
	time1 = time(0);
	if( fstat(fd,&st1) != 0 )
		return -1;

	if( st1.st_ctime < time0 || time1 < st1.st_ctime )
		return 1;
	else	return 0;
}

/* 
 * ctime is not updated for TMPFS files on SunOS
 * atime is not updated for NFS files
 */
int file_timeoff(int fd,int created_now)
{	FileStat st0,st1;
	int now;

	if( !file_isreg(fd) )
		return 0;

	if( fstat(fd,&st0) != 0 )
		return 0;

	if( touch_ctime(fd) != 0 )
		return 0;
	now = time(0);

	if( fstat(fd,&st1) != 0 )
		return 0;

	if( !created_now )
	if( st1.st_ctime == st0.st_ctime ){
		/* this will not work right after REAL CHANGE */
		return 0;
	}

	return now - st1.st_ctime;
}

int file_ctime(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_ctime;
	else	return -1;
}
int file_atime(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_atime;
	else	return -1;
}
int file_times(int fd,int *ctime,int *mtime,int *atime)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 ){
		*ctime = stat.st_ctime;
		*mtime = stat.st_mtime;
		*atime = stat.st_atime;
		return 0;
	}else	return -1;
}
int File_islink(PCStr(path)){
	FileStat st;
	if( lstat(path,&st) == 0 ){
		if( S_ISLNK(st.st_mode) ){
			return 1;
		}
	}
	return 0;
}
int File_sizetime(PCStr(path),int *fsize,int *ctime,int *mtime,int *atime)
{	FileStat st;

	if( stat(path,&st) == 0 ){
		if( fsize ) *fsize = st.st_size;
		if( ctime ) *ctime = st.st_ctime;
		if( mtime ) *mtime = st.st_mtime;
		if( atime ) *atime = st.st_atime;
		return 0;
	}else	return -1;
}
int file_sizetime(int fd,int *fsize,int *ctime,int *mtime,int *atime)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 ){
		if( fsize ) *fsize = stat.st_size;
		if( ctime ) *ctime = stat.st_ctime;
		if( mtime ) *mtime = stat.st_mtime;
		if( atime ) *atime = stat.st_atime;
		return 0;
	}else	return -1;
}
FileSize file_sizeX(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_size;
	else	return -1;
}
int file_nlink(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_nlink;
	else	return -1;
}
int file_uid(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_uid;
	else	return -1;
}
int file_gid(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 )
		return stat.st_uid;
	else	return -1;
}
int file_isfifo(int fd)
{	FileStat status;

	if( fstat(fd,&status) == 0 )
		return S_ISFIFO(status.st_mode);
	return 0;
}
#ifndef S_ISSOCK
#define S_ISSOCK(m) 0
#endif
int SocketOf(int fd);
int file_isSOCKET(int fd){
	FileStat stat;
	if( isWindows() ){
		return 0 < SocketOf(fd);
	}else
	if( fstat(fd,&stat) == 0 ){
		if( S_ISSOCK(stat.st_mode) )
			return 1;
	}
	return 0;
}
int file_statX(int fd,int *sizp,int *mtmp,int *atmp,int *uidp,int *ftype)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 ){
		if( sizp ) *sizp = stat.st_size;
		if( mtmp ) *mtmp = stat.st_mtime;
		if( atmp ) *atmp = stat.st_atime;
		if( uidp ) *uidp = stat.st_uid;
		if( ftype ){
			*ftype = '?';
			if( S_ISREG(stat.st_mode) ) *ftype = '-'; else
			if( S_ISDIR(stat.st_mode) ) *ftype = 'd'; else
			if( S_ISLNK(stat.st_mode) ) *ftype = 'l'; else
			if( S_ISFIFO(stat.st_mode) ) *ftype = 'p';
		}
		return 0;
	}else	return -1;
}
int file_stat(int fd,int *sizep,int *mtimep,int *atimep)
{	FileStat stat;

	if( fstat(fd,&stat) == 0 ){
		*sizep = stat.st_size;
		*mtimep = stat.st_mtime;
		*atimep = stat.st_atime;
		return 0;
	}else	return -1;
}
int file_copymod(int src,int dst)
{	FileStat stat;

	if( fstat(src,&stat) == 0 ){
		return fchmod(dst,stat.st_mode);
	}
	return -1;
}
int File_copymod(PCStr(src),PCStr(dst))
{	FileStat st;

	if( stat(src,&st) == 0 ){
		if( chmod(dst,st.st_mode) != 0 )
			return -1;
		if( set_utimes(dst,st.st_atime,st.st_mtime) != 0 )
			return -1;
		return 0;
	}
	return -1;
}
int File_mod(PCStr(path)){
	FileStat st;
	if( stat(path,&st) == 0 ){
		return 07777 & st.st_mode;
	}
	return -1;
}
int file_mod(int fd){
	FileStat st;
	if( fstat(fd,&st) == 0 ){
		return 07777 & st.st_mode;
	}
	return -1;
}

int file_device(int fd)
{	FileStat status;

	if( fstat(fd,&status) == 0 )
		return ((status.st_dev) >> 8) & 0xFF;
	return -1;
}
int File_device(PCStr(path))
{	FileStat status;

	if( stat(path,&status) == 0 )
		return ((status.st_dev) >> 8) & 0xFF;
	return -1;
}
/*
int file_rdev(int fd)
{	FileStat status;

	if( fstat(fd,&status) == 0 )
		return ((status.st_rdev) >> 8) & 0xFF;
	return -1;
}
*/

int File_stat(PCStr(path),FileSize *size,int *time,int *isdir)
{	FileStat status;

	if( stat(path,&status) == 0 ){
		*size = status.st_size;
		*time = status.st_mtime;
		if( S_ISDIR(status.st_mode) )
			*isdir = 1;
		else	*isdir = 0;
		return 0;
	}
	*size = -1;
	*time = -1;
	*isdir = 0;
	return -1;
}

void dump_file_stat(int fd)
{	FileStat stat;

	if( fstat(fd,&stat) != 0 )
		return;
	fprintf(stderr,"size: %d\n",(int)stat.st_size);
	fprintf(stderr,"mode: 0%o\n",stat.st_mode);
	fprintf(stderr,"uid: %d\n",stat.st_uid);
	fprintf(stderr,"gid: %d\n",stat.st_gid);
	fprintf(stderr,"atime: %d\n",ll2i(stat.st_atime));
	fprintf(stderr,"mtime: %d\n",ll2i(stat.st_mtime));
	fprintf(stderr,"ctime: %d\n",ll2i(stat.st_ctime));
}

/*
 *	UNIX LS COMMAND
 */
char *FileModes(int mode){
	static char *smode; /**/
	int maski;

	if( smode == NULL )
		smode = (char*)StructAlloc(10);

	for( maski = 0; maski < 9; maski++ ){
		if( (1 << maski) & mode )
			smode[8-maski] = "xwrxwrxwr"[maski];
		else	smode[8-maski] = '-';
	}
	if( (mode & 04100) == 04100 ) smode[8-6] = 's';
	if( (mode & 02010) == 02010 ) smode[8-3] = 's';
	return smode;
}

#ifdef S_IFBLK
/*
#define Fkbytes(st)	(st.st_blocks/2)
*/
#define Fkbytes(st)	((int)((1<st.st_blocks)?(st.st_blocks/2):(st.st_size/1024)))
int stat_blocks(FileStat *stp){
	return stp->st_blocks;
}
#else
#define Fkbytes(st)	((st.st_size+1023)/1024)
int stat_blocks(FileStat *stp){
	return (stp->st_size / 0x8000 + 1) * 64;
}
#endif

#define Ftypec(st)	(S_ISDIR(st.st_mode)?'d':(S_ISLNK(st.st_mode)?'l':'-'))
#define Fmodes(st)	FileModes(st.st_mode)
#define Fnlink(st)	st.st_nlink
#define Fowner(st,b)	getUsernameCached(st.st_uid,b)
char *getGroupname(int gid,PVStr(name));
#define Fgroup(st,b)	getGroupname(st.st_gid,b)
/*
#define Fbytes(st)	st.st_size
*/
/*
#define Fbytes(st)	((int)st.st_size)
*/
#define Fbytes(st)	((FileSize)st.st_size)
/*
#define Ftime(t,b)	rsctime(t,b)
#define Fmtime(st,b)	Ftime(st.st_mtime,b)
#define Fatime(st,b)	Ftime(st.st_atime,b)
*/

typedef struct {
/*
	int	 s_ikey;
*/
	FileSize s_ikey;
  const	char	*s_skey;
  const	char	*s_line;
} Elem;

typedef struct {
	FILE	*l_out;
  const char	*l_dir;
  const	char	*l_vbase;	/* put with specified virtual base directory */
 struct fa_stat	*l_maskrexp;
    FileStat	*l_stp;
  const	char	*l_fmt;
  const char	*l_tfmt;
	int	 l_all;
	int	 l_reflink;
	int	 l_virtual; /* enable UNO */

/*
	int	 l_ikey;
*/
	FileSize l_ikey;
	defQStr(l_buf); /* to be used by AVStr */

	int	 l_nsize;
	int	 l_nfill;
	Elem	*l_lines;
} LsArg;

static int PrintTime(PVStr(op),int width,PCStr(tfmt),int times){
	CStr(buf,128);
	int len;

	if( tfmt )
		StrftimeGMT(AVStr(buf),sizeof(buf),tfmt,times,0);
	else	rsctime(times,AVStr(buf));
	len = sprintf(op,"%*s",width,buf);
	return len;
}
#define printTime(o,w,f,t)	PrintTime(AVStr(o),w,f,t)
static void mlstPerm(PVStr(out),FileStat *st){
	refQStr(op,out);
	if( S_ISREG(st->st_mode) ){
		if( st->st_mode & 0x2) setVStrPtrInc(op,'a');
		if( st->st_mode & 0x4) setVStrPtrInc(op,'r');
		if( st->st_mode & 0x2) setVStrPtrInc(op,'w');
	}else
	if( S_ISDIR(st->st_mode) ){
		if( st->st_mode & 0x2) setVStrPtrInc(op,'c');
		if( st->st_mode & 0x1) setVStrPtrInc(op,'e');
		if( st->st_mode & 0x4) setVStrPtrInc(op,'l');
	}
	setVStrEnd(op,0);
}
static int permMode(PCStr(perm)){
	const char *pp;
	int mode = 0;
	for( pp = perm; *pp; pp++ ){
		switch( *pp ){
			case 'a': mode |= 0x2; break;
			case 'r': mode |= 0x4; break;
			case 'w': mode |= 0x2; break;
			case 'c': mode |= 0x2; break;
			case 'e': mode |= 0x1; break;
			case 'l': mode |= 0x4; break;
		}
	}
	return mode;
}
int MLSTtoFacts(PCStr(statresp),PVStr(facts),int fsize){
	const char *rp;
	CStr(line,1024);

	setVStrEnd(facts,0);
	for( rp = statresp; *rp; ){
		rp = sgetsX(rp,AVStr(line),0,0);
		if( *line == ' ' ){
			strcpy(facts,line+1);
			return 1;
		}
	}
	return 0;
}

#define VNODE_EXT	".vno"
int vnodeSetMLSTfacts(PCStr(file),PCStr(facts)){
	CStr(vdir,1024);
	refQStr(vp,vdir);
	CStr(vnode,1024);
	CStr(line,1024);
	CStr(ofacts,1024);
	CStr(fval,1024);
	FILE *pfp;
	FILE *nfp;

	strcpy(vdir,file);
	if( vp = strrpbrk(vdir,"/\\") ){
		truncVStr(vp);
		if( !File_is(vdir) ){
			if( mkdir(vdir,0750) != 0 ){
				return 0;
			}
fprintf(stderr,"--- created %s\n",vdir);
		}
	}
	sprintf(vnode,"%s%s",file,VNODE_EXT);

	if( (pfp = fopen(vnode,"r")) && (nfp = fopen(vnode,"r+")) ){
		while( fgets(line,sizeof(line),pfp) ){
			if( strncaseeq(line,"VNO-Version:",12) ){
			}else
			if( strncaseeq(line,"VNO-Permit:",11) ){
				lineScan(line+11,fval);
				if( streq(fval,"read-only") ){
					fclose(pfp);
					fclose(nfp);
					return -1;
				}
			}else
			if( strncaseeq(line,"MLST-Facts:",11) ){
				lineScan(line+11,ofacts);
				if( streq(ofacts,facts) ){
					fclose(pfp);
					fclose(nfp);
					return 0;
				}
			}else{
				fputs(line,nfp);
			}
		}
		fclose(pfp);
fprintf(stderr,"--- CHANGED %s %s\n",vnode,facts);
	}else{
		nfp = fopen(vnode,"w+");
		if( nfp == NULL )
			return -1;
fprintf(stderr,"--- CREATED %s %s\n",vnode,facts);
	}
	fprintf(nfp,"MLST-Facts: %s\r\n",facts);
	Ftruncate(nfp,0,1);
	fclose(nfp);
	return 1;
}

/*
 * name can be defined
 */
int Vstat(PCStr(file),PVStr(path),PVStr(name),int isDGV,int lev,FileStat *st){
	refQStr(dp,path);
	refQStr(ep,name);
	FILE *fp;
	CStr(line,4096);
	CStr(facts,4096);
	CStr(fact1,128);
	const char *fcp;
	int rcc;
	int isdgv;

	if( 8 < lev ){
		return -1;
	}
	if( isDGV ){
		dp = 0;
	}else{
		dp = strrchr(path,'.');
		if( dp == 0 || !strcaseeq(dp,VNODE_EXT) )
			return -2;
	}
	if( (fp = fopen(path,"r+")) == 0 ){
		return -3;
	}
	truncVStr(facts);
	while( fgets(line,sizeof(line),fp) != NULL ){
		if( strncaseeq(line,"MLST-Facts:",11) ){
			lineScan(line+11,facts);
			break;
		}
		if( *line == ' ' && strcasestr(line,"Type=") ){
			lineScan(line+1,facts);
			break;
		}
	}

	if( lev == 0 ){
		FileStat vst;

		if( dp ){
			setVStrEnd(dp,0);
		}
		strcpy(name,file);
		if( ep = strrchr(name,'.') )
			setVStrEnd(ep,0);
		bzero(st,sizeof(FileStat));
		st->st_mode |= S_IFDIR;
		st->st_nlink = 1;
		if( stat(path,&vst) == 0 ){
			st->st_dev = vst.st_dev;
			st->st_ino = vst.st_ino;
		}
	}

	isdgv = 0;
	for( fcp = facts; *fcp; ){
		refQStr(f1,fact1);
		fcp = scan_ListElem1(fcp,';',AVStr(fact1));
		if( f1 = strpbrk(fact1,"\r\n") )
			setVStrEnd(f1,0);
		if( *fact1 == ' ' ){
			break;
		}else
		if( strncaseeq(fact1,"x-ref=",6) ){
			CStr(xpath,1024);
			refQStr(xp,xpath);
			strcpy(xpath,path);
			if( xp = strrpbrk(xpath,"/\\") ){
				truncVStr(xp);
			}
			chdir_cwd(AVStr(xpath),fact1+6,0);
			if( File_is(xpath) ){
				if( isdgv ){
fprintf(stderr,"--->>>> dgv ... %s\n",xpath);
				Vstat(file,AVStr(xpath),BVStr(name),1,lev+1,st);
				}else
				stat(xpath,st);
			}else{
				strcat(xpath,VNODE_EXT);
				Vstat(file,AVStr(xpath),BVStr(name),1,lev+1,st);
			}
		}else
		if( strncaseeq(fact1,"type=",5) ){
			if( strcaseeq(fact1+5,"file") )
				st->st_mode |= S_IFREG;
			else
			if( strcaseeq(fact1+5,"dir") )
				st->st_mode |= S_IFDIR;
			else
			if( strcaseeq(fact1+5,"vno") )
				isdgv = 1;
			else
			if( strcaseeq(fact1+5,"MLST") )
				isdgv = 2;
		}else
		if( strncaseeq(fact1,"perm=",5) ){
			st->st_mode |= permMode(fact1+5);
		}else
		if( strncaseeq(fact1,"size=",5) ){
			st->st_size = atoi(fact1+5);
		}else
		if( strncaseeq(fact1,"modify=",7) ){
			st->st_mtime = scanYmdHMS_GMT(fact1+7);
		}
	}
	fclose(fp);
	return 0;
}

static int ls1(PCStr(file),LsArg *lsa)
{	const char *dir = lsa->l_dir;
	const char *fmt = lsa->l_fmt;
	const char *oline = lsa->l_buf;
	const char *sp;
	char sc;
	FileStat st;
	int rcode;
	int st_ok;
	int width;
	CStr(path,1024);
	CStr(name,1024);
	CStr(buf,1024);
	refQStr(op,lsa->l_buf); /**/
	const char *tail;
	/*
	char *tfmt = 0;
	*/
	const char *tfmt = lsa->l_tfmt;

	((char*)oline)[0] = 0;
	lsa->l_ikey = 0;
	if( file[0] == '.' && !lsa->l_all )
		return 0;

	if( lsa->l_maskrexp ){
		tail = frex_match(lsa->l_maskrexp,file);
		if( tail == NULL || *tail != 0 )
			return 0;
	}

	st_ok = 0;
	path[0] = 0;
	if( dir && dir[0] )
		strcpy(path,dir);
	if( *path )
	if( strtailchr(path) != '/' )
	if( *file != '/' )
		strcat(path,"/");
	strcat(path,file);

	if( lsa->l_stp ){
		st = *lsa->l_stp;
		st_ok = 1;
	}

	op = (char*)oline;
	for( sp = fmt; sc = *sp; sp++ ){
		assertVStr(lsa->l_buf,op+1);
		if( op[0] != 0 )
			op += strlen(op);

		if( sc != '%' || sp[1] == 0 ){
			setVStrPtrInc(op,sc); setVStrEnd(op,0);
			continue;
		}
		sp++;
		width = numscan(&sp);
		sc = *sp;

		if( sc == 'V' ){
			const char *rp;
			if( dir == 0 || dir[0] == 0 ){
				strcpy(op,lsa->l_vbase);
				continue;
			}
			strcpy(op,lsa->l_vbase);
			rp = strrpbrk(file,"/\\");
			if( rp && rp != file && rp[1] )
				rp += 1;
			else	rp = file;
			if( *op && strtailchr(op) != '/' && *rp != '/' )
				strcat(op,"/");
			strcat(op,rp);
			continue;
		}
		if( st_ok == 0 && lsa->l_virtual ){
			if( Vstat(file,AVStr(path),AVStr(name),0,0,&st)==0 ){
				file = name;
				st_ok = 1;
			}else{
				CStr(xpath,1024);
				sprintf(xpath,"%s%s",path,VNODE_EXT);
				if( File_is(xpath) ){
					truncVStr(oline);
					break;
				}
			}
		}
		if( sc == 'N' ){
			strcpy(op,file);
			continue;
		}
		if( sc == 'A' ){
			strcpy(op,path);
			continue;
		}
		if( st_ok == 0 ){
			errno = 0;
			if( lsa->l_reflink || !INHERENT_lstat() )
				rcode = stat(path,&st);
			else	rcode = lstat(path,&st);
			if( rcode != 0 ){
				/* maybe errno=EOVERFLOW */
				fprintf(stderr,"FAILED stat(%s), errno=%d\n",
					path,errno);
				((char*)oline)[0] = 0;
				break;
			}
			st_ok = 1;
		}
		if( sc == 'x' ){
			sc = *++sp;
			switch( sc ){
			    case 0: return 0;
			    case 'P':
				mlstPerm(AVStr(op),&st);
				continue;
			    case 'Y':
				if( S_ISDIR(st.st_mode) ){
					if( streq(file,".") )
						sprintf(op,"cdir");
					else
					if( streq(file,"..") )
						sprintf(op,"pdir");
					else	sprintf(op,"dir");
				}else
				if( S_ISREG(st.st_mode) )
					sprintf(op,"file");
				else	sprintf(op,"unknown");
				continue;
				break;
			    default:
				continue;
			    case 'T':
				tfmt = "%Y%m%d%H%M%S";
				sc = *++sp;
				break;
			    case 'U':
			    {
				struct {
					int u_dev;
					int u_ino;
				} u;
				u.u_dev = st.st_dev;
				u.u_ino = st.st_ino;
				str_to64((char*)&u,sizeof(u),AVStr(buf),sizeof(buf),1);
				Xsscanf(buf,"%[a-zA-Z0-9/+]",AVStr(op));
				continue;
			    }
			    break;
			}
		}

		switch( sc ){
			case 'd': {
				void ftoMD5(FILE *fp,char md5[]);
				FILE *fp;
				CStr(digest,64);
				if( fp = fopen(path,"r") ){
					ftoMD5(fp,(char*)digest);
					fclose(fp);
				}else	strcpy(digest,"-");
				sprintf(op,"%*s",width,digest);
				break;
			}
			case 'm': lsa->l_ikey = st.st_mtime; break;
			case 'a': lsa->l_ikey = st.st_atime; break;
			case 'z': lsa->l_ikey = st.st_size; break;
			case 'I': sprintf(op,"%*d",width,ll2i(st.st_ino)); break;
			case 'T': setVStrPtrInc(op,Ftypec(st)); setVStrEnd(op,0); break;
			case 'M': strcpy(op,Fmodes(st)); break;
			case 'L': sprintf(op,"%*d",width,ll2i(Fnlink(st))); break;
			case 'O': sprintf(op,"%*s",width,Fowner(st,AVStr(buf))); break;
			case 'G': sprintf(op,"%*s",width,Fgroup(st,AVStr(buf))); break;
			/*
			case 'S': sprintf(op,"%*d",width,Fbytes(st)); break;
			*/
			/*
			case 'S': sprintf(op,"%*u",width,Fbytes(st)); break;
			*/
			case 'S': sprintf(op,"%*lld",width,Fbytes(st)); break;
			case 'K': sprintf(op,"%*d",width,Fkbytes(st)); break;
			/*
			case 'D': sprintf(op,"%*s",width,rsctime(st.st_mtime,AVStr(buf))); break;
			case 'U': sprintf(op,"%*s",width,rsctime(st.st_atime,AVStr(buf))); break;
			*/
			case 'C': printTime(op,width,tfmt,st.st_ctime); break;
			case 'D': printTime(op,width,tfmt,st.st_mtime); break;
			case 'U': printTime(op,width,tfmt,st.st_atime); break;
		}
	}
	return 0;
}

static scanDirFunc ls2(PCStr(file),LsArg *lsa)
{	int li,osize,nsize;

	ls1(file,lsa);
	if( lsa->l_buf[0] ){
		if( lsa->l_nfill == lsa->l_nsize ){
			osize = lsa->l_nsize;
			nsize = (lsa->l_nsize += 2048) * sizeof(Elem);
			if( osize == 0 )
				lsa->l_lines=(Elem*)malloc(nsize);
			else	lsa->l_lines=(Elem*)realloc(lsa->l_lines,nsize);
		}
		li = lsa->l_nfill++;
		lsa->l_lines[li].s_ikey = lsa->l_ikey;
		lsa->l_lines[li].s_skey = stralloc(file);
		lsa->l_lines[li].s_line = stralloc(lsa->l_buf);
	}
	return 0;
}
static int cmpline(Elem *e1,Elem *e2)
{	int diff;

	if( e1->s_ikey < e2->s_ikey )
		return 1;
	if( e2->s_ikey < e1->s_ikey )
		return -1;

	if( diff = e2->s_ikey - e1->s_ikey )
		return diff;
	else	return strcmp(e1->s_skey,e2->s_skey);
}
static void sort_ls(PCStr(dirpath),LsArg *lsa)
{	int li;
	const char *line;

	lsa->l_nfill = 0;
	lsa->l_nsize = 0;
	lsa->l_lines = NULL;

	Scandir(dirpath,scanDirCall ls2,lsa);
	qsort(lsa->l_lines,lsa->l_nfill,sizeof(Elem),(sortFunc)cmpline);

	for( li = 0; li < lsa->l_nfill; li++ ){
		line = lsa->l_lines[li].s_line;
		fprintf(lsa->l_out,"%s\r\n",line);
		free((char*)line);
		free((char*)lsa->l_lines[li].s_skey);
	}
	free(lsa->l_lines);
}

#define O_PUTSELF	1
#define O_TIMESORT	2
#define O_BYATIME	4
#define O_SIZESORT	8
#define O_FORM_L	0x10
#define O_FORM_S	0x20
#define O_REXP		0x40
#define O_VBASE		0x80

extern int TIME_NOW;
static int DoFileRexp;
int pathnorm(PCStr(what),PCStr(path),PVStr(xpath));

void dir2ls(PCStr(dirpath),FileStat *stp,PCStr(opt),xPVStr(fmt),FILE *fp)
{	const char *op;
	const char *dp;
	int onow;
	int flags;
	char sortspec;
	LsArg lsa;
	CStr(fmt_s,256);
	CStr(fmt_a,256);
	CStr(line,2048);
	int f_l,f_s;
	CStr(fmt_b,256);
	CStr(spath,1024);
	const char *vbase = 0;
	CStr(vbaseb,1024);

	CStr(xpath,1024);
	if( pathnorm("sort_ls",dirpath,AVStr(xpath)) ){
		dirpath = xpath;
	}

	if( opt == NULL )
		opt = "";

	bzero(&lsa,sizeof(lsa));
	lsa.l_tfmt = getenv("LSTFMT");
	flags = 0;

	for( op = opt; *op; op++ ){
		switch( *op ){
			case 'a':
				lsa.l_all = 1;
				break;
			case 'l':
				flags |= O_FORM_L;
				break;
			case 's':
				flags |= O_FORM_S;
				break;
			case 'L':
				lsa.l_reflink = 1;
				break;
			case 'V':
				lsa.l_virtual = 1;
				break;
			case 'd':
				flags |= O_PUTSELF;
				break;
			case 't':
				flags |= O_TIMESORT;
				break;
			case 'z':
				flags |= O_SIZESORT;
				break;
			case 'u':
				flags |= O_BYATIME;
				break;
			case '*':
				flags |= O_REXP;
				break;
			case '/':
				flags |= O_VBASE;
				vbase = op + 1;
				while( op[1] ) *op++; /* skip remaining */
				if( strpbrk(vbase,"*?[") ){
/* vbase is "const" */
					strcpy(vbaseb,vbase);
					vbase = vbaseb;
					if( dp = strrchr(vbase,'/') )
						((char*)dp)[1] = 0;
					else	Xstrcpy(QVStr((char*)vbase,vbaseb),"");
				}
				break;
		}
	}
	if( (DoFileRexp || (flags & O_REXP)) && strpbrk(dirpath,"*?[") ){
		strcpy(spath,dirpath);
		dirpath = spath;
		if( dp = strrchr(dirpath,'/') ){
			lsa.l_maskrexp = frex_create(dp + 1);
			truncVStr(dp);
		}else{
			lsa.l_maskrexp = frex_create(dirpath);
			dirpath = ".";
		}
	}

	if( fmt == NULL ){
		cpyQStr(fmt,fmt_b);
		setVStrEnd(fmt,0);

		if( flags & O_FORM_S )
			strcat(fmt,"%4K ");
		if( flags & O_FORM_L )
			strcat(fmt,"%T%M %2L %-8O %8S %D ");
			/*
			strcat(fmt,"%T%M%3L %-8O %8S %D ");
			*/

		if( flags & O_VBASE )
			strcat(fmt,"%V");
		else	strcat(fmt,"%N");
	}

	if( flags & O_TIMESORT ){
		if( flags & O_BYATIME )
			sortspec = 'a';
		else	sortspec = 'm';
		sprintf(fmt_s,"%%%c%s",sortspec,fmt);
		fmt = fmt_s;
	}
	if( flags & O_SIZESORT ){
		sprintf(fmt_s,"%%%c%s",'z',fmt);
		fmt = fmt_s;
	}
	if( flags & O_BYATIME ){
		strcpy(fmt_a,fmt);
		fmt = fmt_a;
		if( dp = strstr(fmt,"%D") )
			((char*)dp)[1] = 'U';
	}

	lsa.l_dir = dirpath;
	lsa.l_vbase = (char*)vbase;
	lsa.l_stp = stp;
	lsa.l_fmt = (char*)fmt;
	lsa.l_out = fp;
	setQStr(lsa.l_buf,line,sizeof(line));
	line[0] = 0;

	onow = TIME_NOW;
	TIME_NOW = time(0);
	setpwent();

	if( !(flags & O_PUTSELF) && fileIsdir(dirpath) )
		sort_ls(dirpath,&lsa);
	else{
		lsa.l_dir = "";
		lsa.l_all = 1;
		ls1(dirpath,&lsa);
		fprintf(fp,"%s\r\n",lsa.l_buf);
	}

	endpwent();
	TIME_NOW = onow;

	if( lsa.l_maskrexp )
		frex_free(lsa.l_maskrexp);
	return;
}

FILE *ls_unix(FILE *fp,PCStr(opt),PVStr(fmt),PCStr(dir),FileStat *stp)
{	int io[2];

	if( dir == NULL )
		dir = ".";

	if( fp != NULL ){
		dir2ls(dir,stp,opt,BVStr(fmt),fp);
		return fp;
	}else{
		IGNRETZ pipe(io);
		if( fork() == 0 ){
			close(io[0]);
			fp = fdopen(io[1],"w");
			dir2ls(dir,stp,opt,BVStr(fmt),fp);
			exit(0);
			return NULL;
		}else{
			close(io[1]);
			fp = fdopen(io[0],"r");
			return fp;
		}
	}
}
int strls_unix(PCStr(path),PVStr(ls),int size){
	FILE *tmp = TMPFILE("CRYPT-ls");
	const char *tail;

	ls_unix(tmp,"-l",VStrNULL,path,NULL);
	fflush(tmp);
	fseek(tmp,0,0);
	fgets(ls,size,tmp);
	fclose(tmp);
	if( tail = strpbrk(ls,"\r\n") ){
		*(char*)tail = 0;
	}
	return 0;
}

int ls_main(int ac,const char *av[])
{	const char *fmt;

	fmt = getenv("LSFMT");
	if( 4 <= ac || 1 < ac && streq(av[1],"-ll") ){
		int ai;
		const char *a1;
		const char *opt = 0;
		int nput = 0;
		for( ai = 1; ai < ac; ai++ ){
			a1 = av[ai];
			if( streq(a1,"-ll") ){
				putenv("LSTFMT=%Y/%m/%d-%H:%M:%S");
				opt = "-l";
			}else
			if( strneq(a1,"-l",2) ){
				opt = a1;
			}else{
				ls_unix(stdout,opt,CVStr(fmt),a1,NULL);
				nput++;
			}
		}
		if( nput == 0 ){
			ls_unix(stdout,opt,CVStr(fmt),".",NULL);
		}
		return 0;
	}
	if( ac <= 1 )
		ls_unix(stdout,NULL,CVStr(fmt),".",NULL);
	else
	if( av[1][0] == '-' )
		ls_unix(stdout,av[1],CVStr(fmt),av[2],NULL);
	else	ls_unix(stdout,NULL,CVStr(fmt),av[1],NULL);
	return 0;
}
#ifdef LSMAIN
main(ac,av) char *av[]; { DoFileRexp = 1; ls_main(ac,av); }
#endif

static scanDirFunc fmatch(PCStr(file),PCStr(pat),int *nump)
{
	if( strstr(file,pat) != 0 ){
		*nump += 1;
	}
	return 0;
}
int file_matches(PCStr(dir),PCStr(pat))
{	int num;

	num = 0;
	Scandir(dir,scanDirCall fmatch,pat,&num);
	return num;
}

int file_isdir(int fd);
int strfSocket(PVStr(desc),int size,PCStr(fmt),int sock);
void dumpFdsX(PCStr(what),FILE *outf,PCStr(types));
void dumpFds(FILE *outf){
	/*
	dumpFdsX("",outf,"");
	*/
	dumpFdsX("",outf,NULL);
}
void dumpFdsY(PCStr(what),FILE *outf,PCStr(types),int ffrom,int fto);
void dumpFdsX(PCStr(what),FILE *outf,PCStr(types)){
	dumpFdsY(what,outf,types,0,127);
}
void dumpFdsY(PCStr(what),FILE *outf,PCStr(types),int ffrom,int fto){
	int fd;
	int nf = 0;
	int flag = -1;
	CStr(fst,256);
	CStr(pfx,128);

	if( *what )
		sprintf(pfx,"%s: ",what);
	else	sprintf(pfx,"");

	for( fd = ffrom; fd <= fto; fd++ ){
		errno = 0;
		/*
		flag = fcntl(fd,F_GETFL,0);
		if( flag == -1 ){
			if( errno != EBADF ){
				fprintf(stderr,"[%d] errno=%d\n",fd,errno);
			}
			continue;
		}
		*/
		if( isatty(fd) ){
			if( types && !isinListX(types,"tty","h") )
				continue;
			sprintf(fst,"tty    ");
		}else
		if( 0 < file_issock(fd) ){
			CStr(desc,MaxHostNameLen);
			if( types && !isinListX(types,"socket","h") )
				continue;
			/*
			CStr(host,MaxHostNameLen);
			CStr(peer,MaxHostNameLen);
			getpairName(fd,AVStr(host),AVStr(peer));
			sprintf(fst,"socket [%s][%s]",host,peer);
			*/
			strfSocket(AVStr(desc),sizeof(desc),"",fd);
			sprintf(fst,"socket %s",desc);
		}else
		if( 0 < file_isfifo(fd) ){
			if( types && !isinListX(types,"fifo","h") )
				continue;
			sprintf(fst,"fifo   ");
		}else
		if( 0 < file_isdir(fd) ){
			if( types && !isinListX(types,"dir","h") )
				continue;
			sprintf(fst,"dir    ");
		}else
		if( file_isreg(fd) ){
			if( types && !isinListX(types,"reg","h") )
				continue;
			sprintf(fst,"reg    time=%d size=%d ino=%d",
				file_mtime(fd),file_size(fd),
				file_ino(fd));
		}else
		if( file_is(fd) ){
			if( types && !isinListX(types,"any","h") )
				continue;
			sprintf(fst,"is     size=%d",file_size(fd));
		}else
		if( 0 <= flag ){
			if( types && !isinListX(types,"any","h") )
				continue;
			sprintf(fst,"?      size=%d",file_size(fd));
		}else{
			continue;
		}
		if( outf )
		fprintf(outf,"[%d] %s%2d %2X FD[%2d] %s\r\n",
			getpid(),pfx,++nf,0xFF&flag,fd,fst);
		else
		syslog_ERROR("[%d] %s%2d %2X FD[%2d] %s\n",
			getpid(),pfx,++nf,0xFF&flag,fd,fst);
	}
}
