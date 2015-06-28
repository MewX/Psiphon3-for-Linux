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
Program:	cache.c (cache create, open and lock)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	Cache file in a directory hierarchy.
	On creation of a cache file, if the name is already used by a
	directory, the cache file name is extended with "/=". 
	On creation of a directory, if the name is already used by a
	cache file, the cache file name is extended with "/=".
History:
	Mar1994	created
//////////////////////////////////////////////////////////////////////#*/
#define MKDIR_MODE	0755
#define FORCE_MODE	0

#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "ystring.h"
#include "dglib.h"
#include "log.h"

int file_isdir(int fd);

int CACHE_READONLY;
int MaxSymLink = 8;
static int NumSymLink;

static int mkdirR(PCStr(dir),int mode);
static int linkR(PCStr(to),PCStr(from),int mode);
static int renameR(PCStr(old),PCStr(xnew),int mode);

int mkdirRX(PCStr(dir))
{
	NumSymLink = 0;

	if( isWindows() && strpbrk(dir,"?*<>|") ){
		/* this will not occur, rewritten by others already */
		IStr(dirx,4*1024);
		int rcode;
		strcpy(dirx,dir);
		path_escchar(AVStr(dirx));
		rcode = mkdirR(dirx,MKDIR_MODE);
		return rcode;
	}
	return mkdirR(dir,MKDIR_MODE);
}
int linkRX(PCStr(to),PCStr(from))
{
	NumSymLink = 0;
	return linkR(to,from,MKDIR_MODE);
}
int renameRX(PCStr(old),PCStr(xnew))
{
	NumSymLink = 0;
	return renameR(old,xnew,MKDIR_MODE);
}
int Readlink(PCStr(dir),PVStr(xdir),int xsiz)
{	const char *dp;
	CStr(xtmp,1024);
	int scc;

	setVStrEnd(xdir,0);
	scc = readlink(dir,(char*)xdir,xsiz);
	if( scc < 0 )
		return scc;
	if( xsiz <= scc )
		return -1;
	if( xdir[0] == 0 )
		return -1;
	if( 8 < ++NumSymLink ){
		fprintf(stderr,"DeleGate: too many symbolic links: %s\n",dir);
		return -1;
	}
	setVStrEnd(xdir,scc);
	if( isFullpath(xdir) ){
		if( strcmp(dir,xdir) == 0 )
			return -1; /* symbolic link to self */
		else	return scc;
	}

	strcpy(xtmp,xdir);
	strcpy(xdir,dir);
	if( dp = strrpbrk(xdir,"/\\") )
		((char*)dp)[1] = 0;
	chdir_cwd(AVStr(xdir),xtmp,1);

	if( strcmp(dir,xdir) == 0 ){
		/* symbolic link to self */
		return -1;
	}
	return scc;
}

#define DIR_ESCAPE	"@"
#define DIR_DESCRIBER	"="

int mkdir1(PCStr(dir),int mode)
{	CStr(xpath,1024);
	CStr(ypath,1024);
	int rcode;
	CStr(xdir,1024);
	int scc;

	if( 0 < (scc = Readlink(dir,AVStr(xdir),sizeof(xdir))) ){
		dir = xdir;
	}
	if( mkdirShared(dir,mode) == 0 ){
		if( FORCE_MODE ){ if( mode != -1 ) chmod(dir,mode); }
		return 0;
	}
	if( fileIsflat(dir) ){
		sprintf(xpath,"%s.%s",dir,DIR_ESCAPE);
		sprintf(ypath,"%s/%s",dir,DIR_ESCAPE);
		rename(dir,xpath);
		mkdirShared(dir,mode);
		if( FORCE_MODE ){ if( mode != -1 ) chmod(dir,mode); }
		if( rename(xpath,ypath) == 0 ){
			sv1log("mkdir1: ESCAPED `%s' to `%s'\n",dir,ypath);
			return 0;
		}
	}
	if( 0 < scc )
		return mkdirR(dir,mode);

	return -1;
}
static int mkdirR(PCStr(dir),int mode)
{	const char *dp;
	const char *tp;
	int isdir;

	if( fileIsdir(dir) )
		return 0;

	dp = (char*)dir; /* not "const" but restored */
	tp = (char*)&dir[strlen(dir)-1]; /* not "const" but restored */
	for( ; dir < tp; tp-- ){
		if( *tp != '/' )
			continue;
		*(char*)tp = 0;
		isdir = fileIsdir(dir);
		*(char*)tp = '/';
		if( isdir ){
			dp = tp + 1;
			break;
		}
	}

	if( dp == dir && *dp == '/' ){
		dp++;
		/* don't try mkdir1("",mode) */
	}
	while( dp = strchr(dp,'/') ){
		int rcode;
		*(char*)dp = 0;
		rcode =
		mkdir1(dir,mode);
		if( rcode != 0 && !fileIsdir(dir) ){
			*(char*)dp = '/';
			return -1;
		}
		*(char*)dp++ = '/';
	}
	return mkdir1(dir,mode);
}
static int linkR(PCStr(to),PCStr(from),int mode)
{	CStr(dir,1024);
	const char *dp;

	/*
	 * should do path_escchar() ...
	 */
	if( link(to,from) == 0 )
		return 0;

	strcpy(dir,from);
	if( dp = strrchr(dir,'/') ){
		truncVStr(dp);
		mkdirR(dir,mode);
		return link(to,from);
	}
	return -1;
}
static int renameR(PCStr(old),PCStr(xnew),int mode)
{	CStr(dir,1024);
	const char *dp;
	CStr(path,1024);

	strcpy(path,xnew);
	path_escchar(AVStr(path));
	xnew = path;

	/*
	if( File_size(old) < 0 )
	*/
	if( !File_is(old) )
		return -1;

	if( rename(old,xnew) == 0 )
		return 0;

	if( unlink(xnew) == 0 )
		if( rename(old,xnew) == 0 )
			return 0;

	strcpy(dir,xnew);
	if( dp = strrchr(dir,'/') ){
		truncVStr(dp);
		mkdirR(dir,mode);
		if( rename(old,xnew) == 0 )
			return 0;
	}
	return -1;
}

static void cachelog(FILE *fp,PCStr(path),PCStr(mode))
{	CStr(dir,2048);
	const char *dp;
	int pino,ino;
	int now,ctime,mtime,atime;

/*
	strcpy(dir,path);
	if( dp = strrchr(dir,'/') ){
		truncVStr(dp);
		pino = File_ino(dir);
	}else	pino = 0;
	ino = file_ino(fileno(fp));
	file_times(fileno(fp),&ctime,&mtime,&atime);
	now = time(0);

 fprintf(stderr,"#### %6d %6d [%8d %8d %8d] [%-2s] %s\n",
pino,ino,
now-ctime,now-mtime,now-atime,
mode,path);
*/
}

FILE *dirfopen(PCStr(what),PVStr(file),PCStr(mode))
{	const char *dp;
	CStr(xpath,2048);
	FILE *fp;

	if( file[0] == 0 )
		return NULL;

	path_escchar(BVStr(file));

	if( file[strlen(file)-1] == '/' )
		strcat(file,DIR_DESCRIBER);

	if( streq(mode,"r-") ){
		/* don't create the upper directories in read mode */
		mode = "r";
	}else
	if( dp = strrchr(file,'/') ){
		*(char*)dp = 0;
		mkdirRX(file);
		*(char*)dp = '/';
	}

	if( fileIsdir(file) ){
/*
BUG?941027
sprintf(xpath,"%s/%s",file,DIR_DESCRIBER);
*/
sprintf(xpath,"%s/%s",file,DIR_ESCAPE);
		sv1log("dirfopen: ESCAPED `%s' to `%s'\n",file,xpath);
		strcpy(file,xpath);
	}
	fp = fopenShared(file,mode);
	Verbose("dirfopen(%s,%s): %x [%d]\n",file,mode,p2i(fp),fp?fileno(fp):-1);

	if( fp != NULL )
		cachelog(fp,file,mode);
	return fp;
}

/*
 * check the date and expire
 */
static void expfopen_log(PCStr(what),double Start,PCStr(file),int atime,PCStr(fmt),int a,int b)
{	double Now,Lap;
	int iatime; /* seconds since the last access */
	CStr(log,2048);

	Now = Time();
	Lap = Now - Start;
	if( atime == 0 )
		iatime = -1;
	else	iatime = (int)(Now - atime);
	sprintf(log,fmt,a,b);
	daemonlog("E","[%3.2f,%d][%s %s] %s\n",Lap,iatime,what,log,file);
}
FILE *expfopen(PCStr(what),int expire,PVStr(file),PCStr(mode),int *datep)
{	FILE *fp;
	int stat,size,mtime,atime,etime;
	CStr(xpath,2048);
	double Start;

	Start = Time();
	if( file[0] == 0 )
		return NULL;

	path_escchar(BVStr(file));

	if( file[strlen(file)-1] == '/' )
		strcat(file,DIR_DESCRIBER);
	else
	if( fileIsdir(file) ){
		sprintf(xpath,"%s/%s",file,DIR_ESCAPE);
		strcpy(file,xpath);
	}
	Verbose("expfopen: %s\n",file);

	if( (fp = fopen(file,mode)) == NULL ){
		expfopen_log(what,Start,file,0,"cache-NONE",0,0);
		return NULL;
	}

	stat = file_stat(fileno(fp),&size,&mtime,&atime);
	/*
	if( stat != 0 || size <= 0 ){
	*/
	if( stat != 0
	 || size == 0 /* 9.2.2 can be < 0 (can be zero for FTP-cache ...) */
	){
		expfopen_log(what,Start,file,atime,"cache-EMPTY: %d",size,0);
		fclose(fp);
		fp = NULL;
	}else
	if( expire == CACHE_DONTEXP ){
		return fp;
	}else{
		if( datep )
			*datep = mtime;
		etime = time(0) - mtime;
		if( expire < etime ){
			expfopen_log(what,Start,file,atime,
				"cache-EXPIRED: %d > %d",etime,expire);
			fclose(fp);
			fp = NULL;
		}else{
			expfopen_log(what,Start,file,atime,
				"cache-VALID: %d < %d",etime,expire);
		}
	}
	if( fp != NULL )
		cachelog(fp,file,mode);
	return fp;
}

/*
const char *cachefmt();
*/
const char *cachefmt(PCStr(base));
void evalPATHexp(PVStr(xpath),PCStr(pathfmt),PCStr(proto),PCStr(server),int port,PCStr(path));

int CTX_cache_pathX(DGC*ctx,PCStr(base),PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath));
int CTX_cache_path(DGC*ctx,PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath))
{
	setVStrEnd(cachepath,0);
	if( cachedir() == 0 )
		return 0;
	return CTX_cache_pathX(ctx,cachedir(),proto,server,iport,path1,BVStr(cachepath));
}

/*
 * Unify Escaped URLs into an Upper Case Format
 */
#define UUNIF_UCASE	1
int CACHE_URLUNIFY = UUNIF_UCASE;

#define isDec(ch)	('0'<=ch && ch<='9')
#define isLHex(ch)	('a'<=ch && ch<='f')
#define isUHex(ch)	('A'<=ch && ch<='F')
#define isHex(ch)	(isLHex(ch) || isUHex(ch))
#define isDecHex(ch)	(isDec(ch) || isHex(ch))
#define toBin(c)	(isDec(c) ? (c-'0') : \
			(isLHex(c)? (c-'a'+10) : (isUHex(c) ? c-'A'+10 : 0)))

int url_escunify(PVStr(eurl),PCStr(surl)){
	refQStr(ep,eurl);
	const char *sp;
	int sc,nsc1,nsc2;
	int ne = 0;

	for( sp = surl; sc = *sp; sp++ ){
		if( sc == '%' )
		if( (nsc1 = sp[1]) && isDecHex(nsc1) )
		if( (nsc2 = sp[2]) && isDecHex(nsc2) ){
			sprintf(ep,"%%%c%c",toupper(nsc1),toupper(nsc2));
			ep += 3;
			sp += 2;
			ne++;
			continue;
		}

		if( isalnum(sc) ){
			setVStrPtrInc(ep,sc);
		}else
		switch( sc ){
			case '!': case '#': case '$': case '&':
			case '(': case ')': case '*':
			case '+': case ',': case '-':
			case '.': case '/':
			case ':': case ';': case '=': case '?':
			case '@':
			case '[': case ']': case '^': case '_':
			case '`':
			case '{': case '|': case '}': case '~':
				setVStrPtrInc(ep,sc);
				break;
			default:
				/*
				sprintf(ep,"%%%02X",sc);
				*/
				sprintf(ep,"%%%02X",0xFF&sc);
				ep += strlen(ep);
				ne++;
				break;
		}
	}
	setVStrPtrInc(ep,0);
	if( ne && strcmp(surl,eurl) != 0 ){
		syslog_ERROR("url_escunify: %s -> %s\n",surl,eurl);
	}
	return ne;
}

int getNvserv(DGC*Conn,PVStr(nvserv));
int CTX_cache_pathX(DGC*ctx,PCStr(base),PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath))
{	const char *rp;
	CStr(pathb,4096);
	CStr(pathe,4096);
	CStr(xpath,4096);
	int plen;
	char sc;
	CStr(lproto,256);
	CStr(aserver,MaxHostNameLen);
	CStr(lserver,MaxHostNameLen);
	int si;
	IStr(nvserv,MaxHostNameLen);
	refQStr(nvport,nvserv);

	setVStrEnd(cachepath,0);

	strtolower(proto,lproto);

	if( getNvserv(ctx,AVStr(nvserv)) ){
		int port = 0;
		if( nvport = strchr(nvserv,':') ){
			setVStrPtrInc(nvport,0);
			port = atoi(nvport);
		}
		if( port == 0 )
			port = serviceport(proto);
		if( !strcaseeq(server,nvserv) || iport != port ){
			sv1log("CACHE name based vhost: %s:%d [%s:%d]\n",
				nvserv,port,server,iport);
			server = nvserv;
			iport = port;
		}
	}
	if( VSA_strisaddr(server) ){
		gethostbyAddr(server,AVStr(aserver));
		if( !streq(server,aserver) ){
		sv1log("CACHE hostname: %s -> %s\n",server,aserver);
		server = aserver;
		}
	}

	strtolower(server,lserver);

	if( strcmp(proto,lproto) != 0 || strcmp(server,lserver) != 0 )
		sv1log("CACHE: case changed %s://%s -> %s://%s\n",
			proto,server,lproto,lserver);

	if( rp = strpbrk(path1,"\r\n\t ") ){
		plen = rp - path1;
		strncpy(pathb,path1,plen); setVStrEnd(pathb,plen);
		path1 = pathb;
	}
	if( CACHE_URLUNIFY ){
		url_escunify(AVStr(pathe),path1);
		path1 = pathe;
	}

	xpath[0] = 0;
	chdir_cwd(AVStr(xpath), path1, 0);
	if( strtailchr(path1) == '/' && strtailchr(xpath) != '/' ) 
		strcat(xpath,"/");
	/*
	evalPATHexp(AVStr(cachepath),cachefmt(),lproto,lserver,iport,xpath);
	*/
	evalPATHexp(AVStr(cachepath),cachefmt(base),lproto,lserver,iport,xpath);
	return 1;
}
int cache_path(PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath))
{
	return CTX_cache_path(NULL,proto,server,iport,path1,AVStr(cachepath));
}

FILE *cache_fopen_rd(PCStr(what),PVStr(cpath),int expire,int *datep)
{	FILE *cfp;

	if( cachedir() == 0 )
		return NULL;

	cfp = expfopen(what,expire,BVStr(cpath),"r",datep);
	if( cfp != NULL ){
		if( file_isdir(fileno(cfp)) ){
			fclose(cfp);
			cfp = NULL;
		}
	}
	return cfp;
}
FILE *cache_fopen_wr(PCStr(what),PVStr(cpath))
{	FILE *fp;

	if( CACHE_READONLY )
		return NULL;

	if( cachedir() == 0 )
		return NULL;

	fp = dirfopen(what,AVStr(cpath),"w");
	return fp;
}
FILE *cache_fopen_rw(PCStr(what),PVStr(cpath))
{	FILE *fp;

	if( cachedir() == 0 )
		return NULL;

	if( (fp = dirfopen(what,AVStr(cpath),"r+")) == NULL )
		fp = dirfopen(what,AVStr(cpath),"w+");

	return fp;
}

int cache_expire(PCStr(sexp),int dflt)
{	int clock;

	clock = scan_period(sexp,'d',dflt);
	Verbose("EXPIRE %s = %d\n",sexp,clock);
	return clock;
}

void cache_delete(PCStr(cpath))
{
	unlink(cpath);
}

/*
int CTX_cache_remove(DGC*ctx,PCStr(proto),PCStr(host),int port,PCStr(path))
*/
int CTX_cache_remove(DGC*ctx,PCStr(proto),PCStr(host),int port,PCStr(path),int dir)
{	CStr(base,1024);
	CStr(cpath,1024);
	const char *dp;
	int len;

	if( cachedir() == 0 )
		return -1;

	CTX_cache_path(ctx,proto,host,port,"",AVStr(base));
	len = strlen(base);
	if( base[len-1] == '/' )
		setVStrEnd(base,len-1);

	if( strstr(path,base) == NULL )
	{
		path_escchar(AVStr(base));
		if( strstr(path,base) == NULL )
		return -1;
	}

	if( unlink(path) != 0 )
	{
		sv1log("## cache_remove ERROR: failed unlink(%s)\n",path);
		return -1;
	}
	Verbose("## cache_remove DONE: unlink(%s)\n",path);

	if( dir == 0 )
		return 0;

	strcpy(cpath,path);
	while( dp = strrchr(cpath,'/') ){
		truncVStr(dp);
		if( strstr(cpath,base) == NULL )
			break;

		if( rmdir(cpath) != 0 )
			break;
	}
	return 0;
}


void stripPATHexp(PCStr(path),PVStr(spath))
{	const char *sp;
	refQStr(dp,spath); /**/
	char ch;
	int in;

	cpyQStr(dp,spath);
	in = 1;
	for( sp = path; ch = *sp; sp++ ){
		if( ch == '$' && sp[1] == '[' ){
			sp++;
			in = 0;
		}else
		if( ch == ']' && in == 0 )
			in = 1;
		else
		if( in )
			setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
}


/*
 *	$[client:...]
 *		%A    user-agent
 */
static int evalClient(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(host),int port,PCStr(path))
{
	return 0;
}
static int evalQuery(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(host),int port,PCStr(path))
{
	return 0;
}

static const char *getdomN(PCStr(name),int lev)
{	const char *dp;
	int lv;

	if( name[0] == 0 || name[1] == 0 )
		return name;

	dp = &name[strlen(name)-1];
	lv = 0;
	for(; name < dp; dp-- ){
		if( *dp == '.' )
			if( ++lv == lev )
				return &dp[1];
	}
	return name;
}
static void getdomN1(PVStr(dst),PCStr(src),int lev)
{	const char *sp;
	refQStr(dp,dst); /**/
	int lx;

	if( VSA_strisaddr(src) ){
		for( lx = 1, sp = src; lx < lev && *sp; sp++ )
			if( *sp == '.' )
			if( ++lx == lev )
				break;
	}else{
		for( lx = 0, sp = &src[strlen(src)-1]; lx < lev && src < sp; sp-- )
			if( *sp == '.' )
			if( ++lx == lev )
				break;
	}
	if( *sp == '.' )
		sp++;

	cpyQStr(dp,dst);
	while( *sp && *sp != '.' ){
		assertVStr(dst,dp+1);
		setVStrPtrInc(dp,*sp++);
	}
	setVStrEnd(dp,0);
}

static void layered_name(PVStr(dst),PCStr(src),int addhost)
{	refQStr(dp,dst); /**/
	const char *sp;
	CStr(buf,512);

	if( VSA_strisaddr(src) ){
		strcpy(dst,src);
	}else{
		strcpy(buf,src);
		sp = &buf[strlen(src)-1];
		cpyQStr(dp,dst);
		for(; buf <= sp; sp-- ){
			if( *sp == '.' ){
				truncVStr(sp);
				strcpy(dp,sp+1);
				dp += strlen(dp);
				setVStrPtrInc(dp,'.');
				setVStrEnd(dp,0);
			}
			if( sp == buf && addhost )
				strcpy(dp,sp);
		}
	}
	for( cpyQStr(dp,dst); *dp; dp++ )
		if( *dp == '.' )
			setVStrElem(dp,0,'/');
}

int FQDN_HSIZE = 32;
static int evalServer(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(server),int port,PCStr(path));
static int evalHash(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(server),int port,PCStr(path))
{	CStr(pathbuf,256);

	evalServer(AVStr(pathbuf),fmt,proto,server,port,path);
	sprintf(xpath,"%02x",((unsigned int )FQDN_hash(pathbuf)) % FQDN_HSIZE);
	return 1;
}

static int evalServer(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(server),int port,PCStr(path))
{	const char *fp;
	const char *p1;
	CStr(tmp,256);
	CStr(fqdn,MaxHostNameLen);
	int neval = 0;
	int tomd5;
	refQStr(xp,xpath); /**/

	setVStrEnd(xpath,0);
	for( fp = fmt; *fp; fp++ )
	if( *fp == '%' && fp[1] ){
		int width;
		fp++;
		width = 0;
		if( *fp == '-' ){
			fp++;
			while( isdigit(*fp) ){
				width = width*10 + *fp-'0';
				fp++;
			}
		}
		if( tomd5 = (fp[0] == 'm') && (fp[1] != 0) )
			fp++;
		if( *fp == '(' && (p1 = strchr(fp+1,')')) ){
			IStr(a1,256); IStr(v1,256); IStr(op,256);
			IStr(a2,256); IStr(v2,256); IStr(f1,256); IStr(f2,256);
			const char *fo;
			Xsscanf(fp+1,"%[^!=<>]%[!=<>]%[^?]?%[^:)]:%[^)]",
			    AVStr(a1),AVStr(op),AVStr(a2),AVStr(f1),AVStr(f2));
			Verbose("--{%s %s %s? %s : %s}\n",a1,op,a2,f1,f2);
			evalServer(AVStr(v1),a1,proto,server,port,path);
			evalServer(AVStr(v2),a2,proto,server,port,path);
			if( streq(op,"==") &&  streq(v1,v2)
			 || streq(op,"!=") && !streq(v1,v2)
			 || streq(op,">=") && strstr(v1,v2)
			 || streq(op,"<=") && strstr(v2,v1)
			){
				fo = f1;
			}else	fo = f2;
			evalServer(AVStr(xp),fo,proto,server,port,path);
			Verbose("--{%s %s %s? => %s => %s}\n",v1,op,v2,fo,xp);
			fp = p1;
		}else
		switch( *fp ){
		    default:  return -1;
		    case '%': strcpy(xp,"%"); break;
		    case 'Q': getFQDN(server,AVStr(fqdn)); server = fqdn; break;
		    case 'P': strcpy(xp,proto); break;
		    case 'H': strcpy(xp,server); break;
		    case 'd': layered_name(AVStr(xp),server,0); break;
		    case 'h': layered_name(AVStr(xp),server,1); break;
		    case 'T': sprintf(xp,"%d",port); break;
		    case 'L':
			if( port != serviceport(proto) )
				sprintf(xp,"%s:%d",server,port);
			else	strcpy(xp,server);
			break;
		    case '1':
		    case '2':
		    case '3':
		    case '4':
		    case '5':
/*
			if( p1 = strrchr(server,'.') ){
				if( isdigits(p1+1) ) 
					strcpy(xp,"no-name");
				else	strcpy(xp,getdomN(server,atoi(fp)));
			}else	strcpy(xp,"no-domain");
*/
			getdomN1(AVStr(xp),server,atoi(fp));
			break;
		    case 'p':
			strcpy(xp,path);
			break;
		    case 'u':
			sprintf(xp,"%s://%s:%d/%s",proto,server,port,path);
			break;
		}
		neval++;
		if( tomd5 ){
			toMD5(xp,tmp);
			strcpy(xp,tmp);
		}
		if( 0 < width && width < strlen(xp) ){
			setVStrEnd(xp,width);
		}
		xp += strlen(xp);
	}else{
		assertVStr(xpath,xp);
		setVStrPtrInc(xp,*fp);
		setVStrEnd(xp,0);
	}
	return neval;
}
typedef int evalFunc(PVStr(xpath),PCStr(fmt),PCStr(proto),PCStr(server),int port,PCStr(path));
static struct {
  const	char	*f_begin;
  const	char	*f_end;
    evalFunc	*f_func;
} tab_formats[] = {
	{"$[server:",	"]",	evalServer},
	{"$[hash:",     "]",    evalHash},
	{"$[query:",	"]",	evalQuery},
	{"$[cleint:",	"]",	evalClient},
	0
};
#define formats	tab_formats

#define _PATH_MAX 512

void evalPATHexp(PVStr(xpath),PCStr(pathfmt),PCStr(proto),PCStr(server),int port,PCStr(path))
{	const char *dp;
	const char *fp;
	const char *tp;
	int fi;
	ACStr(fmtv,2,1024);
	const char *fmts;
	defQStr(fmtd); /*alt*/
	const char *fmtt;
	CStr(fmtb,1024);
	int cfmt,nfmt,dlen,flen;
	const char *bsym;
	const char *esym;
	evalFunc *ffunc;

	IStr(pathb,_PATH_MAX);
	if( _PATH_MAX <= strlen(path) ){ /* v9.9.11 fix-140807b */
		daemonlog("F","CACHE: truncated too long URL (%d) %s\n",
			strlen(path),path);
		FStrncpy(pathb,path);
		path = pathb;
	}

	Xstrcpy(EVStr(fmtv[0]),pathfmt);
	fmts = fmtv[0];
	setQStr(fmtd,fmtv[1],sizeof(fmtv[1]));

	Verbose("CACHE: `%s'\n",fmts);
	for(;;){
		ffunc = NULL;
		for( fi = 0; bsym = formats[fi].f_begin; fi++ ){
			esym = formats[fi].f_end;
			ffunc = formats[fi].f_func;
			if( (dp = strstr(fmts,bsym)) && (tp = strstr(dp,esym)) )
				break;
		}
		if( bsym == 0 )
			break;

		dlen = dp - fmts;
		strncpy(fmtd,fmts,dlen);
		fp = dp +strlen(bsym);
		flen = tp - fp;
		strncpy(fmtb,fp,flen); setVStrEnd(fmtb,flen);
		if( (*ffunc)(QVStr(&fmtd[dlen],fmtd),fmtb,proto,server,port,path) <= 0 )
			break;
		strcat(fmtd,tp+1);
		fmtt = fmts;
		fmts = fmtd;
		setQStr(fmtd,(char*)fmtt,sizeof(fmtv[0]));
		Verbose("CACHE: `%s'\n",fmts);
	}
	strcpy(xpath,fmts);
}

static FILE *sharedfp;
FILE *new_shared()
{
	return sharedfp = TMPFILE("new_shared");
}
int close_shared(){
	int fd;
	if( sharedfp ){
		fd = fileno(sharedfp);
		fclose(sharedfp);
		sharedfp = 0;
		return fd;
	}
	return -1;
}
int get_shared(PVStr(buf),int size,FILE *fp)
{	int rc;

	if( fp == NULL )
		fp = sharedfp;
	if( fp == NULL ){
		sv1log("get_shared: not opened.\n");
		return -1;
	}

	fseek(fp,0,0);
	lock_shared(fileno(fp));
	alertVStr(buf,size);
	rc = fread((char*)buf,1,size-1,fp);
	lock_unlock(fileno(fp));
	setVStrEnd(buf,rc); /**/
	return rc;
}
int put_shared(PCStr(buf),int size,FILE *fp)
{	int wc;

	if( fp == NULL )
		fp = sharedfp;
	if( fp == NULL ){
		sv1log("put_shared: not opened.\n");
		return -1;
	}
	lock_exclusive(fileno(fp));
	wc = fwrite(buf,1,size,fp);
	fflush(fp);
	lock_unlock(fileno(fp));
	return wc;
}
int get_equiv_user(PCStr(clhost),int clport,PVStr(eqhost),PVStr(equser))
{	CStr(buff,2048);
	const char *bp;
	const char *np;
	CStr(equserhost,1024);
	CStr(chost1,MaxHostNameLen);

	if( get_shared(AVStr(buff),sizeof(buff),NULL) <= 0 )
		return 0;

	for( bp = buff; *bp; ){
		if( np = strstr(bp,"\r\n") )
			truncVStr(np);

		Xsscanf(bp,"%s %s\n",AVStr(equserhost),AVStr(chost1));
		if( strcasecmp(chost1,clhost) == 0 ){
			if( Xsscanf(equserhost,"%[^@]@%s",AVStr(equser),AVStr(eqhost)) == 2 ){
				fprintf(stderr,"EQUIVE %s -> %s@%s\n",clhost,
					equser,eqhost);
				return 1;
			}
		}
		if( np == NULL )
			break;
		bp = np + 2;
	}
	return 0;
}


#define CREATING	"#CREATING"
FILE *cache_make(PCStr(what),PCStr(cpath),PVStr(xcpath))
{	FILE *cachefp;

/*
to invalidate cache ???
it is halmful for whom is reading it now, and for
whom has different EXPIRE period.

	cachefp = cache_fopen_wr(what,cpath);
	if( cachefp == NULL ){
		sv1log("CACHE: can't create (%d) = %s\n",errno,cpath);
		return NULL;
	}
	if( rename(cpath,xcpath) == 0 ){
		sv1log("CACHE: created = %s\n",xcpath);
	}else{
		sv1log("CACHE: can't rename (%d) = %s\n",errno,xcpath);
		fclose(cachefp);
		cachefp = NULL;
	}
*/

	/*
	9.9.4
	sprintf(xcpath,"%s%s",cpath,CREATING);
	*/
	sprintf(xcpath,"%s%s#%d",cpath,CREATING,getpid());
	cachefp = cache_fopen_wr(what,AVStr(xcpath));
	if( cachefp != NULL )
		sv1log("CACHE: created %s\n",xcpath);
	else	sv1log("CACHE: can't create (%d) = %s\n",errno,xcpath);
	return cachefp;
}

void cache_done(int gotok,FILE *cachefp,PCStr(cpath),PCStr(xcpath))
{	FileSize size;

	if( cachefp == NULL ){
		sv1log("CACHE: no cache opened.\n");
		return;
	}
	/*
	size = ftell(cachefp);
	*/
	size = Lseek(fileno(cachefp),0,2);
	fclose(cachefp);

	if( gotok ){
		if( renameRX(xcpath,cpath) == 0 )
			sv1log("CACHE: got = [%lld] %s\n",size,cpath);
		else	sv1log("CACHE: can't link %s => %s\n",cpath,xcpath);
	}else{
		sv1log("CACHE: err = [%lld] %s\n",size,xcpath);
		unlink(xcpath);
	}
}

const char *DELEGATE_ACLFILE = "$[server:%P/%L/%p]";
FILE *ACL_fopen(PCStr(proto),PCStr(host),int port,PCStr(upath),int wr,PVStr(cpath)){
	CStr(fmt,1024);
	CStr(lproto,32);
	CStr(lhost,128);
	CStr(aclpath,1024);
	FILE *fp;

	strcpy(fmt,"${ADMDIR}");
	Substfile(fmt);
	Xsprintf(TVStr(fmt),"/attrs/%s",DELEGATE_ACLFILE);
	strtolower(proto,lproto);
	strtolower(host,lhost);
	evalPATHexp(AVStr(aclpath),fmt,lproto,lhost,port,upath);
	strcat(aclpath,"#attr");

	if( wr ){
		fp = dirfopen("ACL",AVStr(aclpath),"r+");
		if( fp == NULL )
			fp = dirfopen("ACL",AVStr(aclpath),"w+");
	}else{
		fp = dirfopen("ACL",AVStr(aclpath),"r-");
	}

	if( lGATEWAY() )
	fprintf(stderr,"ACL_fopen(wr=%d) = %X [%s]\n",wr,p2i(fp),aclpath);

	if( cpath ) strcpy(cpath,aclpath);
	return fp;
}

#define A_GET	0
#define A_ADD	1
#define A_DEL	2
#define A_RPL	3
#define A_SET	3

int ACL_edit(FILE *fp,int op,PCStr(name),PVStr(value)){
	CStr(nam,1024);
	CStr(val,1024);
	int ndel = 0;
	CStr(data,64*1024);
	refQStr(dp,data);

	if( fp == NULL )
		return -1;

	for(;;){
		if( fgets(dp,sizeof(data)-(dp-data),fp) == NULL )
			break;
		truncVStr(nam);
		truncVStr(val);
		Xsscanf(dp," %[^:] : %[^\r\n]",AVStr(nam),AVStr(val));
		switch( op ){
		case A_GET:
			if( strcaseeq(name,nam) ){
				strcpy(value,val);
				return 1;
			}
			break;
		case A_ADD:
			if( strcaseeq(name,nam) ){
				if( strcaseeq(value,val) ){
					return 0;
				}
			}
			break;
		case A_DEL:
			if( strcaseeq(name,nam) ){
				if( *value == 0 || streq(value,val) ){
					ndel++;
					continue;
				}
			}
			dp += strlen(dp);
			break;
		case A_RPL:
			if( strcaseeq(name,nam) ){
				ndel++;
				continue;
			}
			dp += strlen(dp);
			break;
		}
	}
	switch( op ){
	case A_GET:
		truncVStr(value);
		return 0;
	case A_ADD:
		fprintf(fp,"%s:%s\n",name,value);
		fflush(fp);
		return 1;
	case A_DEL:
		if( ndel ){
			fseek(fp,0,0);
			fputs(data,fp);
			Ftruncate(fp,0,1);
		}
		return ndel;
	case A_RPL:
		if( ndel ){
			fseek(fp,0,0);
			fputs(data,fp);
			Ftruncate(fp,0,1);
		}
		fprintf(fp,"%s:%s\n",name,value);
		fflush(fp);
		return ndel;
	}
	return -1;
}

int ACL_get(PCStr(proto),PCStr(host),int port,PCStr(upath),PCStr(nam),PVStr(val)){
	FILE *afp;
	int code;

	truncVStr(val);
	afp = ACL_fopen(proto,host,port,upath,0,VStrNULL);
	if( afp == NULL )
		return 0;
	code = ACL_edit(afp,A_GET,nam,BVStr(val));
	fclose(afp);
	if( code ){
		return code;
	}else{
		return 0;
	}
}

int acledit_main(int ac,const char *av[]){
	int ai;
	CStr(line,1024);
	CStr(com,128);
	CStr(arg1,1024);
	CStr(arg2,128);
	CStr(proto,128);
	CStr(host,128);
	CStr(path,128);
	CStr(xpath,128);
	int port = 0;
	const char *ap;
	FILE *fp = NULL;
	int op;
	int code;

	truncVStr(proto);
	truncVStr(host);
	truncVStr(path);
	strcpy(proto,"nntp");
	strcpy(host,"localhost");
	strcpy(path,"mail-lists.delegate/1");

	for(;;){
		fprintf(stderr,"[%s://%s:%d/%s] ",proto,host,port,path);
		fflush(stderr);
		if( fgets(line,sizeof(line),stdin) == NULL )
			break;
		ap = wordScan(line,com);
		if( streq(com,"quit") ){ break; }
		ap = wordScan(ap,arg1);
		lineScan(ap,arg2);

		if( streq(com,"proto") ){ strcpy(proto,arg1); }else
		if( streq(com,"host") ){  strcpy(host,arg1); }else
		if( streq(com,"port") ){  port = atoi(arg1); }else
		if( streq(com,"path") ){  strcpy(path,arg1); }else
		if( streq(com,"get")
		 || streq(com,"add")
		 || streq(com,"del")
		 || streq(com,"rpl")
		){
			if( streq(com,"get") ) op = A_GET; else
			if( streq(com,"add") ) op = A_ADD; else
			if( streq(com,"del") ) op = A_DEL; else
			if( streq(com,"set") ) op = A_RPL; else
			if( streq(com,"rpl") ) op = A_RPL; else op = A_GET;

			if( port == 0 ){
				port = serviceport(proto);
			}
			strcpy(xpath,path);
			if( streq(proto,"nntp") ){
				strsubst(AVStr(xpath),".","/");
			}
			fp = ACL_fopen(proto,host,port,xpath,1,VStrNULL);
			if( fp == NULL ){
				fprintf(stderr,"cannot open ACL\n");
				continue;
			}
			code = ACL_edit(fp,op,arg1,AVStr(arg2));
			fclose(fp);
			fprintf(stderr,"=%d",code);
			if( op == A_GET ){
				fprintf(stderr,": %s",arg2);
			}
			fprintf(stderr,"\n");
		}else{
			fprintf(stderr,"Unkown: %s",line);
		}
	}
	return 0;
}
