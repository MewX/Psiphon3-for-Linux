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
Program:	filter.c (external/internal filter for each connection)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    remote filter ...

        FFROMCL=cfi://host:port
	Filter: cfi://host:port
	CGI:    cgi://host:port

History:
	970814	extracted from service.c and delegated.c
//////////////////////////////////////////////////////////////////////#*/

//#define ENBUG_HEAVYLOAD /* emulate heavy load or slow thread creation */
//#define ENBUG_DANGLINGFD /* emulate a bug in versions older than 9.9.8 */
int clearSSLready(int fd);

#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include "delegate.h"
#include "fpoll.h"
#include "filter.h"
#include "vsignal.h"
#include "ystring.h"
#include "param.h"
#include "proc.h"
#include "errno.h"
#include <ctype.h> /* isdigit(), isspace() */
int ShutdownSocket(int sock);

#define FTOCL_FIELD     "X-Request"
#define CFI_TYPE	"CFI_TYPE"

static int CFI_STAT = -1;
static int CFI_STATFD = -1;
int DFLT_CFI_STATFD = 3;
int CFI_DISABLE;

extern char **environ;

int inherent_fork(PCStr(F),int L){
	if( _INHERENT_fork() == 0 )
		return 0;
	if( lEMU_NOFORK() ){
		sv1log("\"%s:%d\" emulating no INHERENT_fork() by -dF\n",F,L);
		return 0;
	}
	return 1;
}
#define INHERENT_fork() inherent_fork(__FILE__,__LINE__)

/* filter flags */
#define F_HEADONLY	0x01 /* header only */
#define F_BODYONLY	0x02 /* body only, without keep-alive ? */
#define F_BUFFERED	0x04 /* get the client/server side by DeleGate */

typedef struct {
  const	char	*f_name;
  const char	*f_filter;

	int	 f_push; /* the filter will be detached after EOF */
	int	 f_wait; /* start I/O after the death of the filter */
	int	 f_stat; /* start I/O after the "status code" is got */
	int	 f_opt;  /* the filter is optional, continue even if failed */
	int	 f_flags;
} Filter;
typedef struct {
	Filter	f_filters[16]; /**/
} Filters;
/*
static Filter tab_filters[16] = {
*/
static Filters tab_Filters = {{
	{ ""		},
	{ P_FCL		},
	{ P_FTOCL	},
	{ P_FFROMCL	},
	{ P_FSV		},
	{ P_FTOSV	},
	{ P_FFROMSV	},
	{ P_FMD		},
	{ P_FTOMD	},
	{ P_FFROMMD	},
	{ P_RPORT	},
	{ ""		},
}};
/*
};
*/
#define tab_filters	tab_Filters.f_filters
static Filters sav_Filters;
void save_filters(){
	sav_Filters = tab_Filters;
}
void reset_filters(){
	if( sav_Filters.f_filters[0].f_name )
	tab_Filters = sav_Filters;
}

static int fntoi(PCStr(fname))
{	int i;
	const char *fname1;

	for( i = 1; fname1 = tab_filters[i].f_name; i++ ){
		if( streq(fname,fname1) )
			return i;
	}
	return 0;
}

#define filters		tab_filters
#define FS_RPORT	filters[F_RPORT].f_filter
#define FS_FTOCL	filters[F_TOCL].f_filter
#define FS_FTOSV	filters[F_TOSV].f_filter
#define FS_FTOMD	filters[F_TOMD].f_filter
#define FS_FSV		filters[F_SV].f_filter

#define CFIMAGIC	"#!cfi"
#define isCFI(filter)	(strncmp(filter,CFIMAGIC,strlen(CFIMAGIC)) == 0)

int IsCFI(PCStr(filter)){ return filter?isCFI(filter):0; }

int filter_isCFI(int which)
{	const char *filter;

	if( which == XF_FTOCL )
		return FS_FTOCL != NULL && isCFI(FS_FTOCL);
	if( which == XF_FTOSV )
		return FS_FTOSV != NULL && isCFI(FS_FTOSV);
	if( which == XF_FTOMD )
		return FS_FTOMD != NULL && isCFI(FS_FTOMD);
	return 0;
}

static void sigTERM(int sig)
{
	exit(0);
}
/*
static void close_all(int ifd,int ofd,int lfd)
*/
static void close_allX(Connection *Conn,int ifd,int ofd,int lfd)
{	int fdx,efd;
	int rcode;
	const char *env;
	int mfd = -9;

	efd = fileno(stderr);
	if( (env = getenv("CFI_SHARED_FD")) ){
		mfd = atoi(env);
	}
	for( fdx = 0; fdx < 32; fdx++ ){
		if( fdx == SessionFd() )
			continue;
		if( fdx != mfd )
		if( fdx != ifd && fdx != ofd && fdx != lfd && fdx != efd ){
			rcode = close(fdx);
		}
	}
}
#define close_all(ifd,ofd,lfd) close_allX(Conn,ifd,ofd,lfd)

static int scanComArg(PCStr(command),PVStr(execpath),const char *av[],int mac,PVStr(argb))
{	int ac;
	const char *dp;

	if( command[0] != '[' )
		return -1;

	if( dp = strchr(command,']') ){
		setVStrEnd(execpath,0);
		Xsscanf(command+1,"%[^]]",AVStr(execpath));
		command = dp + 1;
	}else{
		strcpy(execpath,command+1);
		command = "";
	}
	if( *command == ' ' )
		command++;

	ac = decomp_args(av,mac,command,AVStr(argb));
	Verbose("#### [%s](%d) %s\n",execpath,ac,command);
	return ac;
}
static const char *open_cfi(PCStr(file))
{	FILE *fp;
	CStr(convspec,0x10000);
	CStr(execpath,1024);
	const char *av[8]; /**/
	CStr(argb,1024);
	const char *sp;
	int size;
	int off;

	if( 0 <= scanComArg(file,AVStr(execpath),av,elnumof(av),AVStr(argb)) ){
		Verbose("CFI: %s -> %s\n",file,execpath);
		file = execpath;
	}

	fp = fopen(file,"r");
	if( fp == NULL )
		if( isLoadableURL(file) )
			fp = URLget(file,1,NULL);

	sp = NULL;
	if( fp != NULL ){
		CStr(desc,32);
		bzero(desc,sizeof(desc));
		off = ftell(fp);
		IGNRETP fread(desc,1,sizeof(desc),fp);
		fseek(fp,off,0);

		if( strncmp(desc,CFIMAGIC,strlen(CFIMAGIC)) == 0 ){
			size = file_size(fileno(fp));
			sp = (char*)malloc(size+1);
			IGNRETP fread((char*)sp,1,size,fp); /**/
			((char*)sp)[size] = 0;
			if( strncasecmp(file,"data:",5) == 0 )
				sv1log("#### cfi data: scheme ####\n%s\n",sp);
		}
		fclose(fp);
	}
	return sp;
}

void set_CERTDIR(PCStr(dir),int exp);
static int certdir_set;
void scan_CERTDIR(Connection *Conn,PCStr(dir)){
	IStr(xdir,1024);
	if( !isFullpath(dir) && !strneq(dir,"./",2) ){
		sprintf(xdir,"${DGROOT}/%s",dir);
		dir = xdir;
	} 
	DELEGATE_CERTDIR = stralloc(dir);
	certdir_set = 1;
}
void scan_TLSCONFs(Connection *Conn,PCStr(confs));
void scan_TLSCONF(Connection *Conn,PCStr(confs)){
	CStr(sel,256);
	const char *dp;
	int direct = 0;

	dp = wordScanY(confs,sel,"^:");
	if( *dp == ':' ){
		if( streq(sel,"") ) direct = 3;
		if( isinListX(sel,"mitm","c") ) direct = 3;
		if( isinListX(sel,"fsv","c") ) direct |= 1;
		if( isinListX(sel,"fcl","c") ) direct |= 2;
		if( direct ){
			fprintf(stderr,"---- [%x] %s\n",direct,dp+1);
			return;
		}
	}
	scan_TLSCONFs(Conn,confs);
}
void sslway_dflt_certkey(PCStr(cert),PCStr(pkey));
int sslway_dl();
int sslwayFilter(SSLwayCTX *Swc,int ac,char *av[],FILE *cl,FILE *sv,int internal);
int sslwayFilterX(SSLwayCTX *Swc,int ac,char *av[],int clnt,int serv,int internal);

#include "auth.h"
extern int (*SSL_getpassCB)(PCStr(file),PVStr(pass),int size);
extern char DGAUTHadmdom[];
extern char DGAUTHdom[];
void init_CRYPT(Connection *Conn,int clnt);
static int ssl_error;
static int ssl_getpass(PCStr(file),PVStr(pass),int size){
	init_CRYPT(NULL,1);
	if( 0 < getDigestPass(DGAUTHadmdom,"sslway",AVStr(pass))
	 || 0 < getDigestPass(DGAUTHdom,"sslway",AVStr(pass)) ){
		sv1log("%s: passphrase got from DGAuth.\n",file);
		return 0;
	}else{
		ssl_error |= 1;
		return -1;
	}
	/*
	}else	return -1;
	*/
}
extern int (*SSL_fatalCB)(PCStr(mssg),...);
static int ssl_fatal(PCStr(mssg),...){
	CStr(msgb,1024);
	VARGS(8,mssg);

	sprintf(msgb,mssg,VA8);
	daemonlog("F","builtin-SSLway: %s",msgb);
	ssl_error |= 2;
	return 0;
}

void initSSLwayCTX(SSLwayCTX *Swc);
static SSLwayCTX SWCb[8];
static int SWCx;
static SSLwayCTX *newSWC(void *ctx,PFilter *Pf,PCStr(filter)){
	SSLwayCTX *Swc;
	int si;

	for( si = 0; si < elnumof(SWCb); si++ ){
		SWCx++;
		Swc = &SWCb[SWCx % elnumof(SWCb)];
		if( Swc->ss_fid == 0 || Swc->ss_ready < 0 ){
			break;
		}
		syslog_ERROR("#### newSWC[%d] zombi fid=%d rdy=%d [%X][%X]\n",
			SWCx,Swc->ss_fid,Swc->ss_ready,
			PRTID(Swc->ss_owner),PRTID(Swc->ss_tid));
	}
	initSSLwayCTX(Swc);
	Swc->ss_Start = Time();
	Swc->ss_owner = getthreadid();
	return Swc;
}

char **DupvCached(const char *const av[]);
static int XsslwayFilterX(SSLwayCTX *Swc,Connection *Conn,int clnt,int serv,PCStr(filter));

static int XsslwayFilter(Connection *Conn,FILE *in,FILE *out,PCStr(filter)){
	SSLwayCTX *Swc = newSWC(Conn,0,filter);
	return XsslwayFilterX(Swc,Conn,in?fileno(in):-1,out?fileno(out):-1,filter);
}
static int XsslwayFilterX(SSLwayCTX *Swc,Connection *XConn,int clnt,int serv,PCStr(filter)){
	const char *args;
	CStr(argb,1024);
	const char *av[32];
	int ac;
	const char *cert;
	const char *key;
	int size,date;
	int rcode;
	const char **nav;

	strcpy(argb,DELEGATE_CERTDIR);
	DELEGATE_substfile(AVStr(argb),"",VStrNULL,VStrNULL,VStrNULL);
	set_CERTDIR(argb,certdir_set);

	SSL_getpassCB = ssl_getpass;
	SSL_fatalCB = ssl_fatal;

	ac = decomp_args(av,32,filter,AVStr(argb));
	if( XConn ){
		int getOpt1Vserv(Connection *Conn,PCStr(opts),PVStr(vserv));
		IStr(snihost,MaxHostNameLen);
		Connection *Conn = XConn;
		const char *sn;
		const char *sh;

		if( IsMounted && MountOptions
		 && getOpt1Vserv(Conn,MountOptions,AVStr(snihost)) ){
		}else
		if( REAL_HOST[0] ){
			strcpy(snihost,REAL_HOST);
		}
		sn = getenv("SERVER_NAME");
		sh = getenv("SERVER_HOST");
		Verbose("--MOUNT=%d[%s] [%s][%s][%s] => [%s]\n",IsMounted,
			MountOptions?MountOptions:"",
			sn?sn:"",sh?sh:"",REAL_HOST,snihost);
		if( snihost[0] && ac < elnumof(av)-1 ){
			refQStr(ap,argb);
			if( 0 < ac ){
				/* 9.9.8 not to overwrite av[] (9.9.7-pre1) */
				ap = av[ac-1] + strlen(av[ac-1]) + 1;
			}
			av[ac++] = ap;
			av[ac] = 0;
			sprintf(ap,"SNIHOST=%s",snihost);
		}
	}

	cert= get_builtin_data("builtin/config/anonymous-cert.pem",&size,&date);
	key = get_builtin_data("builtin/config/anonymous-key.pem",&size,&date);
	sslway_dflt_certkey(cert,key);

	/*
	nav = (const char**)Dupv(av);
		the value need to be persistent because the pointers to av[] as
		config. param. might be copied to poinsters in the static area
		in SSLway.
	*/
	nav = (const char**)DupvCached(av);
	rcode = sslwayFilterX(Swc,ac,(char**)nav,clnt,serv,filter[0]=='-');
	return rcode;
}
void setupSSLifnotyet(Connection *Conn){
	if( SSL_getpassCB != 0 )
		return;
	if( isinList("https,smtps,imaps,pop3s",DFLT_PROTO) ){
		XsslwayFilter(Conn,NULL,NULL,"sslway");
	}
}
void CFI_closeLock();
int strCRC32(PCStr(str),int len);
static void sslwaySetup(Connection *Conn,PCStr(map),PCStr(filter)){
	static CStr(id,32);
	static CStr(type,32);

	if( !streq(map,"FCL") ){
		/* only FCL is ready for SSL context/session cache */
		return;
	}
	if( SSL_getpassCB != 0 )
	if( ssl_error == 0 )
	{
		return;
	}
	ssl_error = 0;

	/*
	sprintf(id,"CFI_FILTER_ID=%d",filter);
	*/
	sprintf(id,"CFI_FILTER_ID=%d",strCRC32(filter,strlen(filter)));
	putenv(id);
	sprintf(type,"CFI_TYPE=%s",map);
	putenv(type);
	XsslwayFilter(Conn,NULL,NULL,filter);
	/* not in Win32 ?
	unsetenv("CFI_FILTER_ID");
	unsetenv("CFI_TYPE");
	*/
	CFI_closeLock();
}

static int searchLIB = 1;
static int searchPATH;
static int toFullpath(PCStr(command),PVStr(xcommand),PCStr(ext0),PCStr(ext1),PCStr(ext2),PCStr(ext3))
{	CStr(file,1024);
	CStr(xfile,1024);
	CStr(path,1024);
	const char *extv[4]; /**/
	int xi;
	int lib,com;

	if( command[0] == '[' ){
		strcpy(xcommand,command);
		return 1;
	}
	if( isFullpath(command) || isFullURL(command) )
		return 0;

	wordScan(command,file);

	if( streq(file,"sslway") ){
		if( sslway_dl() )
			return 0;
	}

	extv[0] = ext0;
	extv[1] = ext1;
	extv[2] = ext2;
	extv[3] = ext3;
	for( xi = 0; xi < 4; xi++ ){
		if( extv[xi] == NULL )
			break;
		sprintf(xfile,"%s%s",file,extv[xi]);
		/*
	 	if( fullpathLIB(xfile,"r",path) ){
		*/
		/*
	 	if( (lib = fullpathLIB(xfile,"r",AVStr(path)))
		*/
		lib = com = 0;
	 	if( searchLIB  && (lib = fullpathLIB(xfile,"r",AVStr(path)))
		 || searchPATH && (com = fullpathCOM(xfile,"r",AVStr(path)))
		){
			sprintf(xcommand,"[%s]%s",path,command);
			if( lib )
				InitLog("LIBPATH: %s -> %s\n",file,path);
			else	InitLog("PATH: %s -> %s\n",file,path);
			return 1;
		}
		/*
		fprintf(stderr,"Not found: %s\n",xfile);
		*/
	}
	return 0;
}
static int EXT_File_is(PCStr(path),PVStr(xpath)){
	strcpy(xpath,path);
	if( File_is(xpath) == 0 ){
		sprintf(xpath,"%s.exe",path);
		if( File_is(xpath) == 0){
			sprintf(xpath,"%s.bat",path);
			if( File_is(xpath) == 0){
				return 0;
			}
		}
	}
	return 1;
}
int EXT_fullpathCOM(PCStr(path),PCStr(mode),PVStr(apath)){
	CStr(opath,1024);
	CStr(xpath,1024);

	strcpy(opath,path);
	if( strpbrk(path,"/\\") && EXT_File_is(path,BVStr(apath)) ){
		if( !isFullpath(apath) ){
			CStr(cwd,1024);
			IGNRETS getcwd(cwd,sizeof(cwd));
			strcat(cwd,"/");
			Strins(BVStr(apath),cwd);
		}
		if( 0 <= curLogFd() )
		InitLog("command PATH: %s -> %s\n",opath,apath);
		iLog("--- [%d] command PATH: %s -> %s",curLogFd(),opath,apath);
		return 1;
	}

	strcpy(xpath,path);
	if( fullpathCOM(xpath,mode,BVStr(apath)) == 0 ){
		sprintf(xpath,"%s.exe",path);
		if( fullpathCOM(xpath,mode,BVStr(apath)) == 0 ){
			sprintf(xpath,"%s.bat",path);
			if( fullpathCOM(xpath,mode,BVStr(apath)) == 0 ){
				iLog("--E command PATH: %s -> ?",opath);
				sv1log("command PATH: %s -> ?\n",opath);
				return 0;
			}
		}
	}
	if( 0 <= curLogFd() )
	InitLog("command PATH: %s -> %s\n",opath,apath);
	iLog("--- [%d] command PATH: %s -> %s",curLogFd(),opath,apath);
	return 1;
}

int withGzip;
static const char *gzip;
static const char *gunzip;

int gzipInit();
int gzipFilter(FILE *in,FILE *out);
int gunzipFilter(FILE *in,FILE *out);

int checkGzip(Connection *Conn){
	CStr(path,1024);
	int rcode;
	const char *env;
	CStr(envb,1024);

	if( withGzip )
		return withGzip;

	if( env = getenv("GZIP_PATH") ){
		withGzip = 1;
		gzip = stralloc(env);
		Verbose("#### got GZIP_PATH: gzip = %s\n",gzip);
		sprintf(envb,"%s -d",env);
		gunzip = stralloc(envb);
		Verbose("#### got GZIP_PATH: gunzip = %s\n",gunzip);
		return withGzip;
	}
	if( env = getenv("GUNZIP_PATH") ){
		withGzip = 1;
		gunzip = stralloc(env);
		Verbose("#### got GUNZIP_PATH: gunzip = %s\n",gunzip);
		return withGzip;
	}

	rcode = gzipInit();
	if( rcode == 0 ){
		InitLog("#### gzip/gunzip = dynamically linked\n");
		withGzip = 2;
		gzip = "-";
		gunzip = "-";
		return withGzip;
	}

	searchPATH = 1;
	if( toFullpath("gzip",AVStr(path),"",".exe",NULL,NULL) ){
		sprintf(envb,"GZIP_PATH=%s",path);
		putenv(stralloc(envb));

		gzip = stralloc(path);
		InitLog("#### gzip = %s\n",gzip);
		strcat(path," -d");
		gunzip = stralloc(path);
		withGzip = 1;
		InitLog("#### gunzip = %s\n",path);
	}else
	if( toFullpath("gunzip",AVStr(path),"",".exe",NULL,NULL) ){
		sprintf(envb,"GUNZIP_PATH=%s",path);
		putenv(stralloc(envb));

		gunzip = stralloc(path);
		withGzip = 1;
		InitLog("#### gunzip = %s\n",path);
	}else
	{
		InitLog("#### gzip nor gunzip not found in LIBPATH\n");
	}
	searchPATH = 0;
	return withGzip;
}

int systemFilter(PCStr(command),FILE *in,FILE *out);
/*
FILE *Gzip(PCStr(enc),FILE *src)
*/
FILE *Gzip(PVStr(enc),FILE *src)
{	FILE *out;
	int isize;
	double Start;
	const char *en;

	if( !withGzip || gzip == 0 )
		return 0;

	/*
	if( strcaseeq(enc,"gzip") || strcaseeq(enc,"x-gzip") ){
	*/
	if( isinListX(enc,en="gzip","c") || isinListX(enc,en="x-gzip","c") ){
		strcpy(enc,en);
		Start = Time();
		out = TMPFILE("gzip");
		if( streq(gzip,"-") ){
			isize = gzipFilter(src,out);
		}else{
		clearCloseOnExec(fileno(src));
		clearCloseOnExec(fileno(out));
		isize = file_size(fileno(src)) - ftell(src);
		systemFilter(gzip,src,out);
		}
		sv1log("####Gzip [%f] %s %d => %d [%d=>%d]\n",Time()-Start,gzip,
			isize,file_size(fileno(out)),
			fileno(src),fileno(out));
		return out;
	}

	return 0;
}
FILE *Gunzip(PCStr(enc),FILE *fs)
{	FILE *itmp,*otmp;
	double Start;

	if( !withGzip )
		return fs;

	if( strcaseeq(enc,"gzip") || strcaseeq(enc,"x-gzip") ){
		itmp = 0;
		Start = Time();
		if( streq(gzip,"-") ){
			otmp = TMPFILE("gunzip");
			gunzipFilter(fs,otmp);
		}else{
		/* Socket cannot be passed as stdin on Windows */
		if( !INHERENT_fork() && file_ISSOCK(fileno(fs)) ){
			itmp = TMPFILE("gunzip-in");
			copyfile1(fs,itmp);
			fseek(itmp,0,0);
			fs = itmp;
		}
		otmp = TMPFILE("gunzip");
		clearCloseOnExec(fileno(otmp));
		systemFilter(gunzip,fs,otmp);
		fseek(otmp,0,0);
		}
		/*
		sv1log("#### [%f] %s => %d\n",Time()-Start,gunzip,
		*/
		sv1log("####Gunzip [%f] %s => %d\n",Time()-Start,gunzip,
			file_size(fileno(otmp)));
		fs = otmp;
		if( itmp ){
			fclose(itmp);
		}
	}
	return fs;
}

static const char *getFilterCFI(PCStr(path),PVStr(apath),const char **cfip)
{	const char *cfi;

	if( toFullpath(path,AVStr(apath),"",".exe",".cfi",NULL) )
		path = apath;
	*cfip = open_cfi(path);
	return path;
}

static int _withCFI;
int withCFI(int fiset){
	return fiset & _withCFI;
}
/*
static void setF1(int fi,PCStr(filter))
*/
#define setF1(fi,filter)	setF1X(Conn,fi,filter)
static void setF1X(Connection *Conn,int fi,PCStr(filter))
{	const char *fname;
	const char *cfi;
	CStr(file,1024);
	CStr(cfile,1024);
	CStr(xfile,1024);
	CStr(path,1024);
	CStr(xfilter,1024);

	xmem_push(&tab_filters[fi],sizeof(Filter),filters[fi].f_name,NULL);
	fname = filters[fi].f_name;
	if( filter == NULL ){
		filter = DELEGATE_getEnv(fname);
	}

	if( filter && strneq(filter,"-cc-",4) ){
		switch( fi ){
			case F_TOSV:
				CCXcreate("*",filter+4,CCX_TOSV);
				CCXtosv(CCX_TOSV,1);
 fprintf(stderr,"----FTOSV-- setF1X %d [%s] act=%d %X\n",fi,filter?filter:"",
 CCXactive(CCX_TOSV),p2i(CCX_TOSV));
				break;
			case F_TOCL:
 fprintf(stderr,"----FTOCL-- setF1X %d [%s]\n",fi,filter?filter:"");
				CCXcreate("*",filter+4,CCX_TOCL);
				break;
			default: break;
		}
	}else
	if( filter && filters[fi].f_filter == NULL ){
		const char *dp;
		CStr(arg,32);
		int ival;
		for(;;){
			if( strncmp(filter,"-o,",3) == 0 ){
				filter += 3;
				filters[fi].f_opt = 1;
			}else
			if( strncmp(filter,"-p,",3) == 0 ){
				filter += 3;
				filters[fi].f_push = 1;
			}else
			/*
			if( strncmp(filter,"-s",2) == 0 ){
			*/
			if( strncmp(filter,"-s",2) == 0
			 && strchr("0123456789,",filter[2]) ){
				dp = wordscanY(filter+2,AVStr(arg),sizeof(arg),"^,");
				if( *dp == ',' )
					dp++;
				filter = dp;
				ival = atoi(arg);
				if( ival == 0 )
					/*
					ival = 2;
					*/
					ival = DFLT_CFI_STATFD;
				filters[fi].f_stat = ival;
			}else
			if( strncmp(filter,"-h,",3) == 0 ){
				filters[fi].f_push = 1;
				filters[fi].f_flags |= F_HEADONLY;
				filter += 3;
			}else
			if( strncmp(filter,"-b,",3) == 0 ){
				filters[fi].f_flags |= F_BODYONLY;
				filter += 3;
			}else
			if( strncmp(filter,"-w,",3) == 0 ){
				filter += 3;
				filters[fi].f_wait = 1;
			}else{
				break;
			}
		}
		filter = getFilterCFI(filter,AVStr(xfilter),&cfi);
		if( cfi )
			filters[fi].f_filter = cfi;
		else	filters[fi].f_filter = stralloc(filter);
		_withCFI |= cfi ? (1<<fi) : 0;

		/* if sslway is found as an external command, it is
		 * translated into "[path]com arg" format
		 */
		if( strncmp(filter,"sslway",6) == 0
		 || strncmp(filter,"-sslway",7) == 0 ){
			sslwaySetup(Conn,fname,filter);
		}
	}
}
/*
static void setF0(int fi)
*/
#define setF0(fi)	setF0X(Conn,fi)
static void setF0X(Connection *Conn,int fi)
{
	setF1(fi,NULL);
}

const char *getCMAPiMap(int mi);
const char *getCMAPi(int mi);
#define FBSIZE 2048

static void stripFopts(PVStr(filterb)){
	const char *dp;
	for(;;){
		if( strncmp(filterb,"-o,",3) == 0 ){
			ovstrcpy((char*)filterb,filterb+3);
		}else
		if( strncmp(filterb,"-ss,",4) == 0 ){
			ovstrcpy((char*)filterb,filterb+4);
		}else
		if( strncmp(filterb,"--",2) == 0 ){
			if( dp = strchr(filterb,',') ){
				ovstrcpy((char*)filterb,dp+1);
			}
		}else{
			break;
		}
	}
}

typedef struct {
  const char *f_map;
  const	char *f_filter;
  const	char *f_filterx;
} MapFilter;
static MapFilter mapFilters[32];
static void initMapFilters(Connection *Conn){
	int mx;
	const char *map;
	MapFilter *mf;
	const char *cfi;
	const char *apath;
	CStr(filterb,FBSIZE);
	CStr(xfilter,FBSIZE);
	MapFilter *sslf = 0;

	for( mx = 0; map = getCMAPiMap(mx); mx++ ){
		if( elnumof(mapFilters) <= mx ){
			break;
		}
		if( streq(map,"FCL")
		 || streq(map,"FSV")
		 || streq(map,"FTOCL")
		 || streq(map,"FFROMCL")
		 || streq(map,"FTOSV")
		 || streq(map,"FFROMSV")
		){
			mf = &mapFilters[mx];
			mf->f_map = map;
			mf->f_filter = getCMAPi(mx);
			strcpy(filterb,mf->f_filter);

			Verbose("## initMapFilter[%s][%s]\n",map,filterb);
			stripFopts(AVStr(filterb));
			apath = getFilterCFI(filterb,AVStr(xfilter),&cfi);
			if( cfi ){
				strncpy(filterb,cfi,FBSIZE);
				free((char*)cfi);
			}else
			if( apath != filterb ){
				strncpy(filterb,apath,FBSIZE);
			}
			mf->f_filterx = strdup(filterb);
			if( strncmp(filterb,"sslway",6) == 0
			 || strncmp(filterb,"-sslway",7) == 0 ){
				sslf = mf;
			}
		}
	}
	if( sslf ){
		/*
		if( isWindowsCE() && sslway_dl() <= 0 ){
			int sslway_dl_reset();
			sslway_dl_reset();
			sslway_dl();
		}
		*/
		sslwaySetup(Conn,sslf->f_map,sslf->f_filter);
	}
}

int controlFilters(Connection *Conn,int disable){
	int ofilters = Conn->xf_filters;
	if( disable )
		Conn->xf_filters |= XF_DISABLE;
	else	Conn->xf_filters &= ~XF_DISABLE;
	return ofilters;
}
int withPortFilter(Connection *Conn,PCStr(what),PCStr(proto),PCStr(method),PVStr(filter));
static const char *getFilter(Connection *Conn,int fi)
{	const char *fname;
	const char *filter;
	const char *fid;
	int mfx;
	CStr(xfilter,FBSIZE);
	const char *cfi;
	const char *apath;
	static struct { defQStr(filterb); } filterb;
#define filterb filterb.filterb
	if( filterb==NULL ) setQStr(filterb,(char*)StructAlloc(FBSIZE),FBSIZE);

	filter = NULL;
	if( Conn->xf_filters & XF_DISABLE ){
		return 0;
	}

	fid = 0;
	fname = filters[fi].f_name;
	setVStrEnd(filterb,0);
	/*
	if( 0 <= find_CMAP(Conn,fname,ZVStr(filterb,FBSIZE)) ){
	*/
	mfx = find_CMAP(Conn,fname,ZVStr(filterb,FBSIZE));
	if( 0 <= mfx ){
		if( mfx < elnumof(mapFilters) && mapFilters[mfx].f_filter ){
			filter = mapFilters[mfx].f_filterx;
			fid = getCMAPi(mfx);
		}else
		if( filterb[0] ){
			Verbose("## gotFilter[%s][%s]\n",fname,filterb);
			stripFopts(AVStr(filterb));
			apath = getFilterCFI(filterb,AVStr(xfilter),&cfi);
			if( cfi ){
				QStrncpy(filterb,cfi,FBSIZE);
				free((char*)cfi);
			}else
			if( apath != filterb ){
				QStrncpy(filterb,apath,FBSIZE);
			}
			filter = filterb;
			fid = getCMAPi(mfx);
		}
	}
	if( filter == NULL )
	{
		filter = filters[fi].f_filter;
		fid = filter;
	}
	if( filter == NULL ){
		int wf = 0;
		wf = withPortFilter(Conn,fname,REAL_PROTO,ClientAuth.i_meth,
			AVStr(filterb));
		if( wf )
		sv1log("----getFilter[%s] [%s][%s] -P%d/%X = %s\n",
			fname,REAL_PROTO,ClientAuth.i_meth,
			AccPort_Port,AccPort_Flags,filterb);
		if( wf ){
			filter = filterb;
			fid = filter;
		}
	}

	if( filter ){
		static CStr(env,32);
		/*
		sprintf(env,"CFI_FILTER_ID=%d",fid);
		*/
		sprintf(env,"CFI_FILTER_ID=%d",strCRC32(filter,strlen(filter)));
		putenv(env);
	}

	return filter;
}

const char *getFSV(Connection *Conn){ return getFilter(Conn,F_SV); }
const char *setFSV(PCStr(fsv)){
	const char *ofsv = FS_FSV;
	FS_FSV = fsv;
	return ofsv;
}

const char *getFTOCL(Connection *Conn){ return getFilter(Conn,F_TOCL); }
void setFTOCL(PCStr(ftocl)){ FS_FTOCL = ftocl; }

const char *getFTOSV(Connection *Conn){ return getFilter(Conn,F_TOSV); }
void setFTOSV(PCStr(ftosv)){ FS_FTOSV = ftosv; }

void scan_FILTERS(Connection *Conn)
{
	setF0(F_CL    );
	setF0(F_FROMCL);
	setF0(F_TOCL  );

	setF0(F_SV    );
	setF0(F_FROMSV);
	setF0(F_TOSV  );

	setF0(F_MD    );
	setF0(F_TOMD  );
	setF0(F_FROMMD);

	FS_RPORT    = DELEGATE_getEnv(P_RPORT);
      /*scan_RPORT(Conn,DELEGATE_getEnv(P_RPORT));*/

	save_filters();
	checkGzip(Conn);

	initMapFilters(Conn);
}

void scan_FCL(Connection *Conn,PCStr(f)){ setF1(F_CL,f); }
void scan_FFROMCL(Connection *Conn,PCStr(f)){ setF1(F_FROMCL,f); }
void scan_FTOCL(Connection *Conn,PCStr(f)){ setF1(F_TOCL,f); }
void scan_FSV(Connection *Conn,PCStr(f)){ setF1(F_SV,f); }
void scan_FFROMSV(Connection *Conn,PCStr(f)){ setF1(F_FROMSV,f); }
void scan_FTOSV(Connection *Conn,PCStr(f)){ setF1(F_TOSV,f); }

/*
int relay_tee(PCStr(arg),int src,int dst1,int dst2,int *rccp,int *wccp1,int *wccp2);
void teeThru(FILE *in,FILE *outfp,FILE *teefp)
{	int ch;

	while( 0 < ready_cc(in) ){
		ch = getc(in);
		if( ch == EOF )
			return;
		if( outfp ) putc(ch,outfp);
		if( teefp ) putc(ch,teefp);
	}
	if( outfp ) fflush(outfp);
	if( teefp ) fflush(teefp);

	if( outfp == 0 ) simple_relay(fileno(in),fileno(teefp)); else
	if( teefp == 0 ) simple_relay(fileno(in),fileno(outfp)); else
			 relay_tee(fileno(in),fileno(outfp),fileno(teefp));
}
*/

#define STAT	1
#define HEAD	2
#define	EOH	3
#define BODY	4
#define	EOR	5
#define BINARY	6

/* use fprintf() for -fv option to put both to LOGFILE and console */
static void fprintln(FILE *teefp,PCStr(line),int len){
	int bi;
	const char *bp = line;
	for( bi = 0; bi < len; bi++ ){
		if( line[bi] == 0 ){
			fprintf(teefp,"%s\\0",bp);
			bp = line+bi+1;
		}
	}
	fprintf(teefp,"%s",bp);
}
/*   TEEFILTER
 *	Output to "outfp" is through always to a client/servers
 *	Output to "teefp" may be prefixed with something by "-t -p -n"
 *	When in "tee" mode with "-h -b", only specified part of input will
 *	be relayed to "teefp"
 *	When in non-"tee" mode (maybe in "cat" mode), "teefp" is directed
 *	to original "outfp".  All of output is relayed to "teefp" in this
 *	case and "-h -b" controls to which parts "-t -p -n" is applied
 *	selectively.
 */
FILE *curLogFp();
int dupLogFd();
static
void teeFilter(FILE *infp0,FILE *outfp0,FILE *infp1,FILE *outfp1,PCStr(filter),PCStr(opts),int tee)
{	FILE *teefp;
	CStr(line,1024*2);
	CStr(vline,1024*8);
	CStr(fb,1024);
	int headonly = 0;
	int bodyonly = 0;
	int append = 0;
	int withlnum = 0;
	int processid = 0;
	int timestamp = 0;
	int bevisible = 0;
	int delcr = 0;
	int toLOGFILE = 1;
	int ix,mls[2],mbs[2],NLs[2],ready[2],where[2],thrubody[2],isbin[2];
	FILE *ifps[2],*ofps[2];
	int pid = 0;
	CStr(stime,32);
	int rcc;
	int timeout;
	const char *dp = (char*)opts; /* opts must be "const" */

	for( ix = 0; ix < 2; ix++ ){
		where[ix] = STAT;
		mls[ix] = 0;
		mbs[ix] = 0;
		NLs[ix] = 0;
		thrubody[ix] = 0;
		isbin[ix] = 0;
		ready[ix] = 0;
	}
	ifps[0] = infp0; ofps[0] = outfp0;
	ifps[1] = infp1; ofps[1] = outfp1;

	timeout = 300; /* milli seconds for waiting the end of line (LF) */

	for(;;){
		if( strncmp(dp,"-s",2)==0 ){ where[0] = HEAD;  dp += 2; }else
		if( strncmp(dp,"-h",2)==0 ){ headonly = 1;  dp += 2; }else
		if( strncmp(dp,"-b",2)==0 ){ bodyonly = 1;  dp += 2; }else
		if( strncmp(dp,"-t",2)==0 ){ timestamp = 1; dp += 2; }else
		if( strncmp(dp,"-y",2)==0 ){ timestamp = 2; dp += 2; }else
		if( strncmp(dp,"-p",2)==0 ){ processid = 1; dp += 2; pid = getpid(); }else
		if( strncmp(dp,"-n",2)==0 ){ withlnum = 1;  dp += 2; }else
		if( strncmp(dp,"-a",2)==0 ){ append = 1;    dp += 2; }else
		if( strncmp(dp,"-L",2)==0 ){ toLOGFILE = 1; dp += 2; }else
		if( strncmp(dp,"-l",2)==0 ){ toLOGFILE = 1; dp += 2; }else
		if( strncmp(dp,"-e",2)==0 ){ toLOGFILE = 0; dp += 2; }else
		if( strncmp(dp,"-v",2)==0 ){ bevisible = 1; dp += 2; }else
		if( strncmp(dp,"-cr",3)==0 ){ delcr = 1;    dp += 3; }else
		if( strncmp(dp,"-T",2)==0 ){
			dp = numscanX(dp+2,AVStr(line),sizeof(line));
			timeout = atoi(line);
		}else
			break;
	}

	/* 9.9.8 wait the first response */
	if( fPollIn(ifps[0],1) == 0 ){
		int timeout0 = 8*1000;
		int rdy,nf,rv[2];
		double St = Time();

		if( ifps[1] == 0 )
			nf = 1;
		else	nf = 2;
		rdy = fPollIns(timeout0,nf,ifps,rv);
		Verbose("teeFilter rdy=%d (%d %d) %.3f\n",
			rdy,rv[0],rv[1],Time()-St);
	}

	if( *dp == ' ' )
		dp++;
	
	if( dp[0] == 0 && toLOGFILE ){
		teefp = curLogFp();
	}else
	if( dp[0] == 0 )
		teefp = stderr;
	else{
		if( !File_is(dp) ){
			dp = strcpy(fb,dp);
			newPath(AVStr(fb));
		}
		if( append )
			teefp = fopen(dp,"a");
		else	teefp = fopen(dp,"w");
	}
	if( teefp == NULL ){
		sv1log("#### -tee: cannot open %s\n",dp);
		return;
	}
	if( !tee ){
		teefp = ofps[0];
		ofps[0] = NULL;
	}

	for(;;){
		if( ifps[1] != NULL ){
		    if( ready[0] ) ix = 0; else
		    if( ready[1] ) ix = 1; else
		    {
			if( fPollIns(100,2,ifps,ready) == 0 ){
				if( ofps[0] ) if( fflush(ofps[0]) == EOF ) break;
				if( ofps[1] ) if( fflush(ofps[1]) == EOF ) break;
				if( teefp ) if( fflush(teefp) == EOF ) break;
				fPollIns(0,2,ifps,ready);
			}
			if( ready[1] ) ix = 1; else ix = 0;
			ready[ix] = 0;
		    }
		}else{
			ix = 0;
			if( fPollIn(ifps[0],100) == 0 ){
				if( ofps[0] ) if( fflush(ofps[0]) == EOF ) break;
				if( teefp ) if( fflush(teefp) == EOF ) break;
			}
		}

		if( thrubody[ix] ){
			FILE *ifp = ifps[ix];
			FILE *ofp;
			int rcc,brcc,ch;

			if( isbin[ix] ){
				line[0] = ch = fgetc(ifp);
				if( ch == EOF )
					break;
				rcc = 1;
				brcc = fgetBuffered(QVStr(&line[1],line),sizeof(line)-1,ifp);
				if( 0 < brcc )
					rcc += brcc;
			}else{
				if( fgetsByLine(AVStr(line),sizeof(line),ifps[ix],
					timeout, &rcc,&isbin[ix]) == NULL )
					break;
			}
			/*
			if( tee )
				fwrite(line,1,rcc,ofps[ix]);
			else	fwrite(line,1,rcc,teefp);
			*/
			if( tee )
				ofp = ofps[ix];
			else	ofp = teefp;
			fwrite(line,1,rcc,ofp);
			if( isbin[ix] ){
				fflush(ofp);
			}
			continue;
		}

		if( fgetsByLine(AVStr(line),sizeof(line),ifps[ix],
			timeout, &rcc,&isbin[ix]) == NULL )
			break;

		if( headonly || bodyonly )
		if( where[ix] == HEAD && NLs[ix] == 1 )
		if( line[3]==' '
		 && isdigit(line[0])
		 && isdigit(line[1])
		 && isdigit(line[2])
/* maybe it's a response status line (previous message was status line only) */
		 || line[0]=='+' || line[0]=='-'
/* maybe it's a response status line of POP */
		){
			where[ix] = STAT;
			NLs[ix] = 0;
		}

		mbs[ix] += strlen(line);
		mls[ix] += 1;

		if( where[ix] <= HEAD && !bevisible ){
			if( strncmp(line,FTOCL_FIELD,strlen(FTOCL_FIELD))==0 )
				continue;
			if( strncmp(line,"X-Status",8) == 0 )
				continue;
		}

		if( line[0] == '.' && (line[1] == '\n' || line[1] == '\r') )
			where[ix] = BINARY;

		if( delcr ){
			if( dp = strchr(line,'\r') )
				ovstrcpy((char*)dp,dp+1);
		}

		if( ofps[ix] )
			fwrite(line,1,rcc,ofps[ix]);

		if( where[ix] == HEAD && strchr(line,':') == NULL )
		if( line[0] != '\r' && line[0] != '\n' )
			where[ix] = BODY;

		if( teefp ){
			if( !tee && where[ix] == STAT )
				fwrite(line,1,rcc,teefp);
			else
			if( headonly && HEAD < where[ix]
			 || bodyonly && where[ix] != BODY ){
				if( !tee )
				fwrite(line,1,rcc,teefp);
			}else{
				NLs[ix] += 1;
				if( timestamp ){
					if( timestamp == 2 ){ /* v9.9.12 new-140817i */
						void getTimestampY(PVStr(stime));
						getTimestampY(AVStr(stime));
					}else
					getTimestamp(AVStr(stime));
					fprintf(teefp,"%s ",stime);
				}
				if( processid )
					fprintf(teefp,"[%d] ",pid);
				if( withlnum )
					fprintf(teefp,"%6d\t",NLs[ix]);
				if( bevisible ){
					Str2vstr(line,rcc,AVStr(vline),sizeof(vline));
					/*
					fputs(vline,teefp);
					*/
					fprintf(teefp,"%s",vline);
				}else
				{
					fprintln(teefp,line,rcc);
				/*
				fwrite(line,1,rcc,teefp);
				*/
				}

				if( strchr(line,'\n') == 0 )
				if( ready_cc(ifps[ix]) <= 0 )
				{
					/*
					fputs("<<TIMEOUT>>\n",teefp);
					*/
					fprintf(teefp,"<<TIMEOUT>>\n");
				}
			}
		}

		if( where[ix] == STAT )
			where[ix] = HEAD;

		if( where[ix] <= HEAD  && (line[0] == '\n' || line[0] == '\r') )
			where[ix] = EOH;

		if( where[ix] == EOH ){
			where[ix] = BODY;
			if( headonly ){
				thrubody[ix] = 1;
				/*
				 * this may change the timing of the observed
				 * original sequence of data packets
				 *
				fflush(ofps[ix]);
				 */
			}
		}

		if( headonly || bodyonly )
		if( line[0] == '.' && (line[1] == '\n' || line[1] == '\r') ){
			where[ix] = STAT;
			NLs[ix] = 0;
		}
	}
	if( toLOGFILE )
		fflush(teefp);
	else
	if( tee && teefp != stderr )
		fclose(teefp);

	Verbose("#### %s [%d] bytes / [%d] lines\n",filter,mbs[0],mls[0]);
	if( ifps[1] != NULL )
	Verbose("#### %s [%d] bytes / [%d] lines\n",filter,mbs[1],mls[1]);
}

void relaysx(int timeout,int sdc,int sdv[][2],int sdx[],int rccs[],IFUNCP funcv[],void *argv[]);
static void relay2f(FILE *in,FILE *out,FILE *ts,int sock)
{	int sv[2][2],rv[2],xv[2];
	int ch;

	while( 0 < ready_cc(in) ){
		ch = getc(in);
		putc(ch,ts);
	}
	fflush(ts);

	sv[0][0] = fileno(in); sv[0][1] = sock;        xv[0] = 1;
	sv[1][0] = sock;       sv[1][1] = fileno(out); xv[1] = 0;
	relaysx(0,2,sv,xv,rv,NULL,NULL);
}

int remote_cfi(PCStr(filter),FILE *in,FILE *out)
{	CStr(host,1024);
	CStr(options,1024);
	int port,sock;
	FILE *ts,*fs;

	host[0] = 0;
	port = 0;
	options[0] = 0;
	if( Xsscanf(filter,"cfi://%[^:]:%d/%s",AVStr(host),&port,AVStr(options)) ){
		sock = client_open("cfi","data",host,port);
		if( sock < 0 )
			return -1;
	}else	return -1;

	ts = fdopen(sock,"w");
	if( options[0] ){
		fprintf(ts,"POST /%s HTTP/1.0\r\n",options);
		fprintf(ts,"\r\n");
		fflush(ts);
	}

	relay2f(in,out,ts,sock);
	fclose(ts);
	return 0;
}

void sedFilter(FILE *in,FILE *out,PCStr(comline),PCStr(args));
void credhyFilter(PCStr(ftype),FILE *in0,FILE *out0,FILE *in1,FILE *out1,PCStr(com),PCStr(args));
FileSize CCV_relay_textX(PCStr(ccspec),FILE *in,FILE *out);

int builtin_filter(Connection *Conn,PCStr(what),PCStr(filter),FILE *in,FILE *out,FILE *in1,FILE *out1)
{	int rcc;

	if( what == 0 ){
		what = getenv(CFI_TYPE);
		if( what == NULL )
			what = "";
	}
	if( strncasecmp(filter,"tcprelay://",11) == 0 ){
		CStr(host,MaxHostNameLen);
		int port,sock;

		if( Xsscanf(filter+11,"%[^:]:%d",AVStr(host),&port) == 2 ){
			sock = client_open("cfi","data",host,port);
			if( 0 <= sock ){
				FILE *ts;
				ts = fdopen(sock,"w");
				relay2f(in,out,ts,sock);
				fclose(ts);
			}else{
			}
		}else{
		}
		return 0;
	}

	if( strncmp(filter,"cfi:",4) == 0 ){
		remote_cfi(filter,in,out);
		return 1;
	}
	if( strtailstr(what,"-P-CFI-MIME") ){
		IStr(line,1024);
		IStr(com,1024);
		for(;;){
			if( fgets(line,sizeof(line),in) == NULL )
				break;
			fputs(line,out);
			wordScan(line,com);
			if( strcaseeq(com,"DATA") || strcaseeq(com,"POST") )
				putMESSAGEline(out,"mime",com);
			fflush(out);
		}
		return 1;
	}
	if( strcmp(filter,"-thru") == 0 ){
		rcc = simple_relayf(in,out);
		Verbose("#### %s [%d] bytes\n",filter,rcc);
		return 1;
	}
	if( strncmp(filter,"-cat",4) == 0 ){
		teeFilter(in,out,in1,out1,filter,filter+4,0);
		return 1;
	}else
	if( strncmp(filter,"-gzip",5) == 0 ){
		gzipFilter(in,out);
		return 1;
	}else
	if( strncmp(filter,"-gunzip",7) == 0 ){
		gunzipFilter(in,out);
		return 1;
	}else
	if( strncmp(filter,"sslway",6) == 0
	 || strncmp(filter,"-sslway",7) == 0
	){
		return XsslwayFilter(Conn,in,out,filter);
	}else
	if( strncmp(filter,"-tee",4) == 0 ){
		teeFilter(in,out,in1,out1,filter,filter+4,1);
		return 1;
	}else
	if( strncmp(filter,"-credhy",7) == 0 ){
		credhyFilter(what,in,out,in1,out1,filter,filter+7);
		return 1;
	}else
	if( strncmp(filter,"-swft",5) == 0 ){
		swfFilter(NULL,in,out,filter+5);
		return 1;
	}else
	if( strncmp(filter,"-ssed",5) == 0 ){
		sedFilter(in,out,filter,filter+5);
		return 1;
	}else
	if( strncmp(filter,"-sed",4) == 0 ){
		sedFilter(in,out,filter,filter+4);
		return 1;
	}
	if( strcmp(filter,"-utf8") == 0 ){
		rcc = CCV_relay_textX("UTF8.JP",in,out);
		Verbose("#### %s [%d]\n",filter,rcc);
		return 1;
	}
	if( strcmp(filter,"-jis") == 0 ){
		rcc = CCV_relay_textX("JIS.JP",in,out);
		Verbose("#### %s [%d]\n",filter,rcc);
		return 1;
	}
	if( strcmp(filter,"-euc") == 0 ){
		rcc = CCV_relay_textX("EUC.JP",in,out);
		Verbose("#### %s [%d]\n",filter,rcc);
		return 1;
	}
	if( strcmp(filter,"-sjis") == 0 ){
		rcc = CCV_relay_textX("SJIS.JP",in,out);
		Verbose("#### %s [%d]\n",filter,rcc);
		return 1;
	}
	if( strneq(filter,"-m17n",5) ){
		int m17n_ccx_Filter(PCStr(filter),FILE *in,FILE *out);
		rcc = m17n_ccx_Filter(filter,in,out);
		return 1;
	}
	return -1;
}

static void addConnEnviron(Connection *Conn)
{	CStr(env,1024);
	const char *serv;
	const char *addr;
	int port;
	CStr(host,MaxHostNameLen);
	const char *val;
	CStr(tmp,64);

	strfConnX(Conn,"REMOTE_IDENT=%u",AVStr(env),sizeof(env));putenv(stralloc(env));
	strfConnX(Conn,"REMOTE_HOST=%h", AVStr(env),sizeof(env));putenv(stralloc(env));
	strfConnX(Conn,"REMOTE_ADDR=%a", AVStr(env),sizeof(env));putenv(stralloc(env));

	if( port = HTTP_ClientIF_H(Conn,AVStr(host)) ){
	sprintf(env,"SERVER_NAME=%s",host); putenv(stralloc(env));
	sprintf(env,"SERVER_PORT=%d",port); putenv(stralloc(env));
	}

	if( lORIGDST() ){
	sprintf(env,"ORIGINAL_SERVER_NAME=%s",Origdst_Host); putenv(stralloc(env));
	sprintf(env,"ORIGINAL_SERVER_PORT=%d",Origdst_Port); putenv(stralloc(env));
	}

	serv = DST_HOST;
	sprintf(env,"SERVER_HOST=%s",serv); putenv(stralloc(env));
	if( addr = gethostaddr(serv) )
	{
	sprintf(env,"SERVER_ADDR=%s",addr); putenv(stralloc(env));
	}

	if( MountOptions ){
		sprintf(env,"SCRIPT_NAME_BASE=%s",MountVbase(MountOptions));
		putenv(stralloc(env));
	}
	if( getenv("PATH_INFO") == 0 ){
		sprintf(env,"PATH_INFO=%s",D_SELECTOR);
		putenv(stralloc(env));
	}

	if( ClientSession[0] && decrypt_opaque(ClientSession,AVStr(tmp)) ){
		sprintf(env,"X_COOKIE_SESSION=%s",tmp);
		putenv(stralloc(env));
	}
	if( (val = HTTP_DigestOpaque(Conn)) && decrypt_opaque(val,AVStr(tmp)) ){
		sprintf(env,"X_DIGEST_SESSION=%s",tmp);
		putenv(stralloc(env));
	}
}
int getsockHandle(int fd);
static void addSockEnviron(Connection *Conn,PCStr(what),int sock)
{	int sockhandle;
	CStr(env,128);

	if( (sockhandle = getsockHandle(sock) ) != -1 ){
		sprintf(env,"SOCKHANDLE_%s=%d",what,sockhandle);
		putenv(stralloc(env));
	}
}

extern int IO_TIMEOUT;
static int recvPeek1(int ifd,char buff[],int size)
{	int rcc;

	if( 0 < PollIn(ifd,IO_TIMEOUT*1000) ){
		setNonblockingIO(ifd,1);
		rcc = RecvPeek(ifd,buff,size);
		setNonblockingIO(ifd,0);
		if( 0 < rcc ) buff[rcc] = 0;
		return rcc;
	}
	return -1;
}
void packComArg(PVStr(command),PCStr(execpath),PCStr(args))
{
	sprintf(command,"[%s]%s",execpath,args);
}

int dping_main(int ac,const char *av[]);
void execsystem(PCStr(what),PCStr(pathcom))
{	CStr(execpath,1024);
	const char *av[128]; /**/
	CStr(argb,1024);
	const char *command;
	int ac;

	/*
	 * if in "[execpath]command" but with some shell syntax in command,
	 * call shell process ignoring "[execpath]" ...
	 */
	command = 0;
	if( *pathcom == '[' ){
		if( command = strchr(pathcom,']') )
			command++;
	}
	if( command == 0 )
		command = pathcom;

	ac = decomp_args(av,elnumof(av),command,AVStr(argb));
	if( streq(what,"XCOM") ){
		if( av[0] )
		if( strcaseeq(av[0],"-dping") ){
			dping_main(ac,av);
			Finish(0);
		}
		if( !INHERENT_fork() ){
			if( *pathcom == '[' )
				scanComArg(pathcom,AVStr(execpath),av,elnumof(av),AVStr(argb));
			else	strcpy(execpath,av[0]);

			/* use spawn to inherit socket descriptors ... */
			setclientsock(1);
			SpawnvpDirenv(what,execpath,av);
			wait(0);
			Finish(0);
		}
	}

	if( strpbrk(command,"\r\n|()[]<>{}:;") )
		Finish(system(command));
	else
	if( 0 <= scanComArg(pathcom,AVStr(execpath),av,elnumof(av),AVStr(argb)) )
		Execvp(what,execpath,av);
	else	Finish(system(command));
}

void closeOnExecServPorts(int set);
int popenx(PCStr(command),PCStr(mode),FILE *io[2]){
	int fromf[2];
	int tof[2];
	int ac;
	const char *av[32];
	CStr(execpath,1024);
	CStr(ab,1024);
	int pid;

	/*
	if( strchr(mode,'r') )
	*/
	if( strchr(mode,'r') || strchr(mode,'+') )
		IGNRETZ pipe(fromf);
	else	fromf[0] = fromf[1] = -1;
	/*
	if( strchr(mode,'w') )
	*/
	if( strchr(mode,'w') || strchr(mode,'+') )
		IGNRETZ pipe(tof);
	else	tof[0] = tof[1] = -1;
	ac = scanComArg(command,AVStr(execpath),av,elnumof(av),AVStr(ab));
	if( ac < 0 ){
		ac = decomp_args(av,elnumof(av),command,AVStr(ab));
		if( 0 < ac )
			strcpy(execpath,av[0]);
		else	strcpy(execpath,"");
	}

	if( INHERENT_fork() ){
		pid = Fork("popenx");
		if( pid == 0 ){
			if( 0 <= fromf[0] ) close(fromf[0]);
			if( 0 <= tof[1] ) close(tof[1]);
			dup2(tof[0],0);
			dup2(fromf[1],1);
			if( strchr(mode,'R') ){
				dup2(1,2);
			}
			closeOnExecServPorts(1);
			/*
			Execvp("popenx",execpath,av);
			*/
			ExecveX("popenx",execpath,(ConstV)av,(ConstV)environ,EXP_PATH|EXP_NOENV);
			_exit(-1);
		}
	}else{
		int setwaitspawn(int ws);
		extern int MIN_DGSPAWN_WAIT;
		int s0,s1,ws;
		s0 = dup(0);
		s1 = -1;
		if( 0 <= tof[0] ){
			dup2(tof[0],0);
			setCloseOnExec(tof[1]);
		}else{
			/*
			if( strchr(mode,'&' ){
				close(0);
			}
			*/
		}
		if( 0 <= fromf[1] ){
			s1 = dup(1);
			dup2(fromf[1],1);
			if( strchr(mode,'R') ){
				dup2(1,2);
			}
			if( 1 ){
				/* this is necessary at least for .bat */
				setCloseOnExec(0);
			}
			setCloseOnExec(fromf[0]);
		}
		ws = setwaitspawn(MIN_DGSPAWN_WAIT-1);
		/* not supposing the child is DeleGate */
		closeOnExecServPorts(1);
		pid = SpawnvpDirenv("popenx",execpath,av);
		closeOnExecServPorts(0);
		setwaitspawn(ws);
		dup2(s0,0);
		close(s0);
		if( 0 <= tof[0] ){
			clearCloseOnExec(tof[1]);
		}
		if( 0 <= fromf[1] ){
			clearCloseOnExec(fromf[0]);
			dup2(s1,1);
			if( strchr(mode,'R') ){
				dup2(1,2);
			}
			close(s1);
		}
	}
	if( 0 <= fromf[1] ) close(fromf[1]);
	if( 0 <= tof[0] ) close(tof[0]);
	io[0] = io[1] = 0;
	if( 0 <= fromf[0] ) io[0] = fdopen(fromf[0],"r");
	if( 0 <= tof[1] ) io[1] = fdopen(tof[1],"w");
	/*
	if( 0 <= tof[1] ) io[1] = fdopen(tof[0],"w");
	*/
	return pid;
}

extern FILE *logTeeFp;
extern const char *BINSHELL;
int cfi(DGC *ctx,int isresp,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec));
void arg2env(PCStr(prefix),int logfd);

static void execFilter(Connection *Conn,FILE *in,FILE *out,int ifd,int ofd,PCStr(what),int isresp,PCStr(filter))
{	const char *av[128]; /**/
	int ac,ai;
	CStr(execpath,1024);
	CStr(abuff,0x2000);
	CStr(argb,0x2000);
	int tofil[2];
	int bi;
	FILE *in1,*out1;
	CStr(type,32);
	const char *env;

	sprintf(type,"%s=%s",CFI_TYPE,what);
	putenv(stralloc(type));

	if( in  == NULL ) in = fdopen(ifd,"r");
	if( in  == NULL ){
		sv1log("-- %s can't fdopen(%d,r) errno=%d\n",what,ifd,errno);
		Finish(-1);
	}
	if( out == NULL ) out = fdopen(ofd,"w");

	in1 = out1 = NULL;
	bi = streq(what,"FCL")||streq(what,"FSV")||streq(what,"FMD");
	if( bi && *filter == '-' ){
		in1 = fdopen(ofd,"r");
		out1 = fdopen(ifd,"w");
	}
	if( env = getenv("CFI_SYNC") ){
		sscanf(env,"%d/%d",&CFI_SYNC[1],&CFI_SYNC[0]);
	}
	if( 0 < CFI_SYNC[0] || 0 < CFI_SYNC[1] ){
		close(CFI_SYNC[0]);
		IGNRETP write(CFI_SYNC[1],"S",1);
	}
/*
	if( 0 <= builtin_filter(what,filter,in,out,in1,out1) ){
		fflush(out);
		if( out1 ) fflush(out1);
		Finish(0);
	}
*/

	/* DeleGate's "MASTER" protocol header must not be passed to the
	 * FCL or FFROMCL filter of this delegated if the client delegated have
	 * FTOMD or FMD filter which is not passed such header also.
	 * That is, a pair of FCL/FFROMCL and FMD/FTOMD must communicate
	 * transparently.
	 */
	if( (ClientFlags & PF_SSL_ON) && streq(iSERVER_PROTO,"delegate") ){
		sv1log("[%s] don't allow raw head with SSL: %X %s\n",
			iSERVER_PROTO,ClientFlags,filter);
	}else
	if( DFLT_PROTO[0] == 0 && ready_cc(in) <= 0 )
	if( streq(what,"FCL") || streq(what,"FFROMCL") ){
		int li,rcc;
		CStr(line,1024);

		rcc = recvPeek1(ifd,line,32);
		if( isHelloRequest(line) ){
			sv1log("#%s: don't pass DeleGate-HELLO to the filter\n",
				what);
			for( li = 0; ; li++ ){
				rcc = RecvLine(ifd,line,sizeof(line));
				if( rcc <= 0 )
					break;
				Verbose("#%s: %s",what,line);
				IGNRETP write(ofd,line,rcc);
				if( line[0] == '\r' || line[0] == '\n' )
					break;
			}
		}
	}
	if( 0 <= builtin_filter(Conn,what,filter,in,out,in1,out1) ){
		fflush(out);
		if( out1 ) fflush(out1);

		if( isWindows() ){ /* 9.6.3 for Windows */
			if( bi || streq(what,"FTOCL") ){
				fflush(out);
				ShutdownSocket(fileno(out));
			}
		}
		Finish(0);
	}

	if( isCFI(filter) ){
		int logteeFd = -1;
		CStr(conninfo,2048);

		sv1log("#### execFilter[%s] CFI\n",what);
		make_conninfo(Conn,AVStr(conninfo));

		addConnEnviron(Conn);
		if( lCONSOLE() ){
			/* 9.9.4 must escape file-desc.{0,1,2} for xsystem() */
			logteeFd = dup(2);
		}
		close_all(ifd,ofd,curLogFd());
		if( lCONSOLE() ){
			/* with -fv, output to curLog will be duplicated to
			 * stderr in log.c:fputlog() and ystring.c:Xprintf().
			 * but curLog == stderr in a filter program by dup2(2)
			 * as follows (to do redirect output to stderr from
			 * a extern filter program to curLog) thus the curLog
			 * shoud be redirected to the origina stderr directed
			 * to the console.
			 */
			/*
			logTeeFp = fdopen(dup(2),"a");
			*/
			dup2(2,logteeFd);
			logTeeFp = fdopen(logteeFd,"a");
		}
		dup2(curLogFd(),2);
		cfi(Conn,isresp,in,out,conninfo,filter);

		if( isWindows() ){ /* 9.6.3 for Windows */
			/* don't shutdown with FTOSV before resp. is got */
			if( bi || streq(what,"FTOCL") ){
				fflush(out);
				ShutdownSocket(fileno(out));
			}
		}
		Finish(0);
	}else{
		sv1log("#### execFilter[%s] %s\n",what,filter);
		ac = scanComArg(filter,AVStr(execpath),av,elnumof(av),AVStr(argb));

		if( ac < 0 && INHERENT_fork() /* NOT Windows :-) */ ){
			ac = 0;
			av[ac++] = (char*)BINSHELL;
			strcpy(execpath,av[0]);
			av[ac++] = "-c";
			av[ac++] = (char*)filter;
			av[ac] = 0;
		}
		if( ac < 0 ){
			ac = decomp_args(av,elnumof(av),filter,AVStr(argb));
			strcpy(execpath,av[0]);
			sv1log("#### [%s](%d) %s\n",execpath,ac,filter);
		}
		addConnEnviron(Conn);

		for( ai = 0; ai < ac; ai++ )
			Verbose("%s arg[%d] %s\n",what,ai,av[ai]);

		if( 0 < ready_cc(in) ){
			sv1log("#### relay buffered input\n");
			IGNRETZ pipe(tofil);
			if( Fork("FILTER-INBUFF") == 0 ){
				FILE *tout;
				close(tofil[0]);
				tout = fdopen(tofil[1],"w");
				simple_relayf(in,tout);
				Finish(0);
			}else{
				close(tofil[1]);
				ifd = tofil[0];
			}
		}

		bi = streq(what,"FCL")||streq(what,"FSV")||streq(what,"FMD");

		if( 0 <= CFI_STAT ){
			CStr(env,32);
			if( 0 <= CFI_STATFD ){
				/* escape fd of LOGFILE on CFI_STATFD */
				if( CFI_STATFD == curLogFd() ){
					dupLogFd();
				}
				dup2(CFI_STAT,CFI_STATFD);
				close(CFI_STAT);
				CFI_STAT = CFI_STATFD;
			}
			sprintf(env,"CFI_STAT=%d",CFI_STAT);
			putenv(env);
		}

		/* don't pass "CFI_LOGFD=2" environment to filter program
		 * when CFI_STATFD == 2 to prevent it from being overwritten
		 * in the begining in CFI_init()->env2arg() which duplicates
		 * CFI_LOGFD -> stderr(==2)
		 */
		if( 0 <= CFI_STAT && CFI_STATFD == 2 ){
		}else{
			arg2env("CFI_",curLogFd());
		}

		if( !bi || INHERENT_fork() /* NOT Windows :-) */ ){
			dup2(ifd,0);
			dup2(ofd,1);
			if( 0 <= CFI_STAT && CFI_STATFD == 2 ){
			}else{
			if( Conn->xf_stderr2out ){
				sv1log("%s: direct stderr to stdout\n",what);
				dup2(ofd,2);
			}
			else{
				if( lCONSOLE() ){
				logTeeFp = fdopen(dup(fileno(stderr)),"a");
				}
				dup2(curLogFd(),2);
			}
			}
			ExecvpDirenv(what,execpath,av);
			Finish(-1);
		}else{
			close_all(ifd,ofd,curLogFd());
			setclientsock(ifd);
			setserversock(ofd);
			if( 0 <= CFI_STAT && CFI_STATFD == 2 ){
			}else{
			dup2(curLogFd(),2);
			}
			/* use spawn to inherit socket descriptors ... */
			SpawnvpDirenv(what,execpath,av);

			/* if( Windows95() )
			 * to make inherited sockets be disconnected ? */
				wait(0);

			Finish(0);
		}
	}
}

static int callF2(Connection *Conn,int clsock,int svsock,int ac,const char *av[],PCStr(arg))
{	CStr(what,32);
	const char *filter;
	CStr(fds,32);
	int rstat,fctl[2];

	/*
	filter = wordScan(arg,what);
	*/
	arg = wordScan(arg,what);
	filter = wordScan(arg,fds);
	if( sscanf(fds,"%d/%d/%d",&rstat,&fctl[0],&fctl[1]) == 3 ){
		if( rstat ){
			close(fctl[0]);
			CFI_STAT = fctl[1];
			CFI_STATFD = rstat;
		}
	}

	ClientSock = clsock;
	addConnEnviron(Conn);

	while( *filter == ' ' ) filter++;
	sv1log("[%s] callFilter2: %d=%d %d=%d %s\n",what,
		clsock,file_ISSOCK(clsock), svsock,file_ISSOCK(svsock), filter);
	execFilter(Conn,NULL,NULL,clsock,svsock,what,2,filter);
	close(clsock);
	close(svsock);
	return 0;
}

void poll_filterctl1(Connection *Conn,int fid,int timeout);
void poll_filterctls(Connection *Conn,int timeout)
{	int fid,tout;
	FILE *fp;

	for( fid = 1; filters[fid].f_name; fid++ ){
		if( fp = Conn->xf_fp[fid] ){
			if( Conn->xf_codes[fid] == 200 )
				tout = 1;
			else	tout = timeout;
			if( 0 < fPollIn(fp,tout) )
			{
				poll_filterctl1(Conn,fid,timeout);
			}
		}
	}
}
static int scan_fstat(Connection *Conn,int fid,PCStr(stat))
{	int scode;
	CStr(ver,8);
	CStr(scodes,8);
	CStr(field,1024);

	scode = 0;
	field[0] = 0;
	Xsscanf(stat,"CFI/%s %s %[^\r\n]",AVStr(ver),AVStr(scodes),AVStr(field));
	scode = atoi(scodes);
	Conn->xf_codes[fid] = scode;

	if( scode == 200 ){
		if( strncasecmp(field,"Ident:",6) == 0 ){
			switch( fid ){
			case F_SV: case F_TOSV: case F_FROMSV:
				Verbose("## server ident: %s\n",field+6);
				setServerCert(Conn,filters[fid].f_name,field+6);
				break;
			case F_CL: case F_TOCL: case F_FROMCL:
				Verbose("## client ident: %s\n",field+6);
				setClientCert(Conn,filters[fid].f_name,field+6);
				break;
			}
		}else
		if( strncasecmp(field,"Certificate:",12) == 0 ){
			switch( fid ){
			case F_SV: case F_TOSV: case F_FROMSV:
				linescanX(field+12,AVStr(Conn->sv_cert),sizeof(Conn->sv_cert));
				break;
			case F_CL: case F_TOCL: case F_FROMCL:
				linescanX(field+12,AVStr(Conn->cl_cert),sizeof(Conn->sv_cert));
				break;
			}
		}else
		if( strncasecmp(field,"Filter:",7) == 0 ){
			/* next filter */
		}
	}
	return scode;
}
void poll_filterctl1(Connection *Conn,int fid,int timeout)
{	CStr(buf,1024);
	refQStr(bp,buf); /**/
	const char *bx;
	FILE *fp;
	int got = 0;

	fp = Conn->xf_fp[fid];
	if( fp == NULL )
		return;

	bx = buf + sizeof(buf) - 1;
	strcpy(buf,"\n");
sv1log("##A## %d %d\n",filters[fid].f_stat,timeout);
timeout = 5*1000;
	for(;;){
		if( fPollIn(fp,timeout) <= 0 )
			break;
		if( fgets(bp,bx-bp,fp) == NULL )
			break;
		Verbose(">> %s",bp);
		if( scan_fstat(Conn,fid,bp) == 200 ){
			timeout = 1;
			bp += strlen(bp);
		}
	}
}
double CFISTAT_TIMEOUT = 1;
static void get_fstat(Connection *Conn,int fid,int fctl[2])
{	FILE *fp;

	close(fctl[1]);
	fp = Conn->xf_fp[fid] = fdopen(fctl[0],"r");
	sv1log("%s CFI_STAT fopen(%d/%X)\n",filters[fid].f_name,fileno(fp),p2i(fp));
	poll_filterctl1(Conn,fid,(int)CFISTAT_TIMEOUT*1000);

	if( filters[fid].f_wait )
		wait(0);
}
void close_filterctls(Connection *Conn)
{	int fid,fd,rcode;
	const char *name;
	FILE *fp;

	for( fid = 1; name = filters[fid].f_name; fid++ ){
		fp = Conn->xf_fp[fid];
		if( fp == NULL )
			continue;
		fd = fileno(fp);
		rcode = fclose(fp);
		sv1log("%s CFI_STAT fclose(%d/%X)=%d\n",name,fd,p2i(fp),rcode);
		Conn->xf_fp[fid] = 0;
	}
}

/*
static putProtoEnv(Conn)
	Connection *Conn;
{
	putCGIENV(Conn);
}
*/
void pushCGIENV(Connection *Conn,void *sevp);
void popCGIENV(Connection *Conn,void *sevp);
static void pushProtoEnv(Connection *Conn,void *evp)
{
	GatewayFlags |= GW_IS_CFI;
	pushCGIENV(Conn,evp);
	GatewayFlags &= ~GW_IS_CFI;
}
static void popProtoEnv(Connection *Conn,void *evp)
{
	popCGIENV(Conn,evp);
}

/*
static PFilter PFB[16];
#define PFv PFB
*/
#define PFv Conn->dg_sthread.st_PFpushed

PFilter *lastPFilter(Connection *Conn,int owner,int which){
	int pi;
	PFilter *Pf;
	PFilter *Pf1 = 0;

	for( pi = 0; pi < elnumof(PFv); pi++ ){
		Pf = &PFv[pi];
		if( which & Pf->f_ftype )
		if( Pf->f_tid ){
			if( Pf->f_owner == owner || owner == 0 ){
				if( Pf1 == 0 || Pf1->f_fid < Pf->f_fid ){
					Pf1 = Pf;
				}
			}
		}
	}
	return Pf1;
}
int pushPFilter(Connection *Conn,PCStr(proto),PFilter *aPf){
	int pi;
	PFilter *Pf;

	for( pi = 0; pi < elnumof(PFv); pi++ ){
		Pf = &PFv[pi];
		if( Pf->f_tid == aPf->f_tid ){
			if( Pf->f_fid == aPf->f_fid ){
				/* duplicated push (SSLway) */
				return 0;
			}
		}
	}
	for( pi = 0; pi < elnumof(PFv); pi++ ){
		Pf = &PFv[pi];
		if( Pf->f_tid == 0){
			*Pf = *aPf;
			sv1log("--pushPFilter (%s/%s) tid=%X [%d][%d] %X %X\n",
				REAL_PROTO,proto,PRTID(Pf->f_tid),
				Pf->f_svsock,Pf->f_clsock,
				ServerFlags,p2i(&ServerFlags));
			break;
		}
	}
	return 0;
}
static int donePFilter(Connection *Conn,int tid){
	int nex = 0;
	PFilter *Pf;
	int pi;

	if( tid == 0 ){
	}else
	for( pi = 0; pi < elnumof(PFv); pi++ ){
		Pf = &PFv[pi];
		if( Pf->f_tid == tid ){
			Pf->f_tid = 0;
			nex++;
		}
	}
	if( ClientFilter.f_tid == tid ){
		ClientFilter.f_tid = 0;
		nex++;
	}
	if( ServerFilter.f_tid == tid ){
		ServerFilter.f_tid = 0;
		nex++;
	}
	return nex;
}
int dumpThreads(PCStr(wh));
static CriticalSec PFilterCSC;
int popPFilter(Connection *Conn,int timeout,int which){
	int pi;
	PFilter *Pf;
	int tid;
	int alv;
	int err;

	/* must be in CSC */
	for( pi = 0; pi < elnumof(PFv); pi++ ){
		Pf = &PFv[pi];
		if( Pf->f_ftype & which )
		if( Pf->f_tid ){
			tid = Pf->f_tid;
			alv = threadIsAlive(tid);
			err = thread_wait(tid,timeout);
			sv1log("--popPFilter(%X) ty=%d tid=%X [%d][%d] %d/%d err=%d\n",
				0xFFFF&which,Pf->f_ftype,PRTID(tid),
				Pf->f_svsock,Pf->f_clsock,
				actthreads(),numthreads(),err);
			if( err == 0 ){
				donePFilter(Conn,tid);
				Pf->f_tid = 0;
			}
		}
	}
	return 0;
}
void clearThreadFilter(){
	Connection *Conn = MainConn();
	if( ClientFilter.f_tid || ServerFilter.f_tid ){
		sv1log("-- clearThreadFilter %X %X\n",
			ClientFilter.f_tid,ServerFilter.f_tid);
	}
	ClientFilter.f_tid = 0;
	ServerFilter.f_tid = 0;
}
int waitFilterThread(Connection *Conn,int timeout,int which){
	int tid;
	int err;
	int done = 0;

	if( (which & XF_FCL) && (tid = ClientFilter.f_tid) ){
		errno = 0;
		if( (err = thread_wait(tid,timeout)) == 0 )
			done++;
		if( err == 0 || errno != EAGAIN )
			ClientFilter.f_tid = 0;
		if( err == 0 ){
			donePFilter(Conn,tid);
		}
		/*
		if( lTHREAD() ){
		*/
		if( lTHREAD() || err != 0 ){
			sv1log("-- wait threadFilter[FCL][%X] %d/%d err=%d\n",
				tid,actthreads(),numthreads(),err);
		}
	}
	if( (which & XF_FSV) && (tid = ServerFilter.f_tid) ){
		errno = 0;
		if( (err = thread_wait(tid,timeout)) == 0 )
			done++;
		if( err == 0 || errno != EAGAIN )
			ServerFilter.f_tid = 0;
		if( err == 0 ){
			donePFilter(Conn,tid);
		}
		if( lTHREAD() ){
			sv1log("-- wait threadFilter[FSV][%X] %d/%d err=%d\n",
				tid,actthreads(),numthreads(),err);
		}
	}
	popPFilter(Conn,timeout,which);
	return done;
}

/*
static int threadSSLway(PCStr(what),int clsock,int svsock,PCStr(filter)){
*/
static int nSSLway[2];
static int threadSSLwayX(SSLwayCTX *Swc,PCStr(what),int clsock,int svsock,PCStr(filter),Connection *Conn){
	int rc;

#if defined(ENBUG_HEAVYLOAD)
	msleep(300);
#endif
	Verbose("---tSSLway %8X%s base=%X %d/%d\n",getthreadid(),
		ismainthread()?"":"S",p2i(&what),actthreads(),numthreads());
	if( lTHREADLOG() ){
		int si = streq(what,"FSV") ? 1 : 0;
		int ns;
		nSSLway[si] += 1;
		ns = nSSLway[0] + nSSLway[1];
		putfLog("thread-SSLway start [%s]%d/%d",what,nSSLway[si],ns);
		rc = XsslwayFilterX(Swc,Conn,clsock,svsock,filter);
		nSSLway[si] -= 1;
		ns = nSSLway[0] + nSSLway[1];
		putfLog("thread-SSLway done [%s]%d/%d",what,nSSLway[si],ns);
	}else{
		rc = XsslwayFilterX(Swc,Conn,clsock,svsock,filter);
	}
	if( lTHREAD() ){
		syslog_ERROR("-- [%s] SSLwayF DONT close[%d,%d] FINth=%d/%d\n",
			what,clsock,svsock,actthreads(),numthreads());
	}
	return rc;
}

extern int SSLready;
extern int SSLstart;
double TIMEOUT_SSLNEGO1 = 8.0;
double TIMEOUT_SSLNEGO = 16.0;

/* 9.9.4 MTSS this can happen only if a non-main thread received signal */
int SSL_PollIn(PCStr(wh),int fd,int msec){
	int rem,to1;
	int nready;
	if( msec <= 0 || !ismainthread() ){
		return PollIn(fd,msec);
	}
	nready = -1;
	to1 = 0;
	for( rem = msec; 0 < rem; rem -= to1 ){
		if( gotsigTERM("%s",wh) ){
			extern int BREAK_STICKY;
			Verbose("#SIGTERM-SSLready %d/%d BS=%d\n",
				msec-rem,msec,BREAK_STICKY);
			BREAK_STICKY = 1;
			return -1;
		}
		to1 += 50;
		if( rem  < to1 ) to1 = rem; else
		if( 1000 < to1 ) to1 = 1000;
		if( nready = PollIn(fd,to1) ){
			break;
		}
	}
	return nready;
}

static void waitSSLready(PCStr(what),int sv[2]){
	double St;
	double To;
	int nready;

	St = Time();
	/*
	nready = PollIn(sv[0],(int)(TIMEOUT_SSLNEGO1*1000));
	*/
	nready = SSL_PollIn("SSLreadyA",sv[0],(int)(TIMEOUT_SSLNEGO1*1000));
	if( lTHREAD() || nready == 0 ){
		syslog_ERROR("-- SSLready[%s] << [%d][%d/%d] %d %.3f\n",
			what?what:"",sv[0],sv[1],SSLready,nready,Time()-St);
		To = TIMEOUT_SSLNEGO - TIMEOUT_SSLNEGO1;
		if( nready == 0 && 0 < To ){
			/*
			nready = PollIn(sv[0],(int)(To*1000));
			*/
			nready = SSL_PollIn("SSLreadyB",sv[0],(int)(To*1000));
			syslog_ERROR("-- SSLready[%s] << [%d] %d %.3f\n",
				what?what:"",sv[0],nready,Time()-St);
			fprintf(stderr,"[%d] SSLready[%s] = %d %.3f\r\n",
				getpid(),what?what:"",nready,Time()-St);
		}
	}
}

int FilterID;
static CriticalSec trfCSC;

static int threadFilter1(Connection *Conn,int clsock,int svsock,PCStr(what),PCStr(filter)){
	int tid;
	int sv[2];
	IStr(env,128);
	PFilter Pfb;
	PFilter *Pf;
	const char *e1;
	int envput = 0;
	int CSCerr = 0;
	SSLwayCTX *Swc;

	Verbose("---tFiltr1 %8X%s base=%X %d/%d\n",getthreadid(),
		ismainthread()?"":"S",p2i(&Conn),actthreads(),numthreads());

	if( strneq(filter,"sslway",6) )
	if( streq(what,"FCL") || streq(what,"FSV") )
	{

		setupCSC("threadFilter",trfCSC,sizeof(trfCSC));
		if( enterCSCX(trfCSC,1) != 0 ){
			double St = Time();
			if( enterCSCX(trfCSC,3*100) != 0 ){
				CSCerr = 1;
			}else{
			}
			sv1log("##CSC %s %.3f threadFilter [%s] %s\n",
				CSCerr?"ERR":"OK",Time()-St,what,filter);
		}
			if( GatewayFlags & GW_SYN_SSLSTART ){
				if( lTHREAD() )
				sv1log("## [%s][%s] SSLstart 1 <- %d [%d][%d]\n",
					what,DST_PROTO,SSLstart,clsock,svsock);
				SSLstart = 1;
			}
			e1 = getenv(CFI_TYPE);
			if( e1 == 0 || !streq(e1,what) ){
				envput = 1;
				sprintf(env,"CFI_TYPE=%s",what);
				putenv(stralloc(env));
			}
			IGNRETZ pipe(sv);
			SSLready = sv[1];

			if( streq(what,"FCL") )
				Pf = &ClientFilter;
			else	Pf = &ServerFilter;
			Pfb = *Pf;
			if( streq(what,"FCL") )
				Pfb.f_ftype = XF_FCL;
			else	Pfb.f_ftype = XF_FSV;
			Pfb.f_fid = ++FilterID;
			Pfb.f_owner = getthreadid();
			Pfb.f_svsock = svsock;
			Pfb.f_clsock = clsock;

			Swc = newSWC(Conn,&Pfb,filter);
			Swc->ss_fid = Pfb.f_fid;
			Swc->ss_ftype = Pfb.f_ftype;
			Swc->ss_ready = SSLready;

		tid = thread_fork(0x80000,STX_tid,"threadSSLway",
		(IFUNCP)threadSSLwayX,Swc,what,clsock,svsock,filter,Conn);

			Swc->ss_tid = tid;
			Pfb.f_tid = tid;
			waitSSLready(what,sv);
			Pfb.f_error = Swc->ss_error;
			*Pf = Pfb;

		pushPFilter(Conn,DST_PROTO,&Pfb);

			SSLready = -1;
			Swc->ss_ready = -2;
#if !defined(ENBUG_DANGLINGFD)
			clearSSLready(sv[1]); /* 9.9.8 dangling cl/sv_Ready */
#endif
			close(sv[0]);
			close(sv[1]);
			if( envput ){
				putenv(stralloc("CFI_TYPE="));
			}
		if( CSCerr == 0 ){
			leaveCSC(trfCSC);
		}
		return 1;
	}
	return 0;
}

static int threadFilter(Connection *Conn,int clsock,int svsock,PCStr(what),PCStr(filter)){
	if( !INHERENT_thread() ) return 0;
	if( lNOTHREAD() ) return 0;

	return threadFilter1(Conn,clsock,svsock,what,filter);
}


void push_fd(int fd,int fd2,int rw);
int spawnFilter(Connection *Conn,int iomode,int tofil[],int sock,iFUNCP func,PCStr(args));
/*
 * bi-directional filters: FCL,FSV,FMD
 */
static int isSSLway(PCStr(filter));
static void forkspawnFilter(Connection *Conn,PCStr(what),int clsock,int svsock,int oclsock,int osvsock,PCStr(filter))
{
	int fid = fntoi(what);
	int rstat,fctl[2];
	int clclose = -1;
	void *evp;
	int syncenv = 0;
	IStr(type,32);

	int flag_sav = 0;
	if( isSSLway(filter) ){ /* 9.9.4 for safe SSLway CGI environ. */
		flag_sav = 1;
		ThreadFlags |= TH_MTSS_PUTENV;
	}

	if( streq(what,"FSV") || streq(what,"FMD") ){
		if( oclsock != ClientSock )
			clclose = ClientSock;
	}
	if( 0 < CFI_SYNC[0] || 0 < CFI_SYNC[1] ){
		CStr(env,32);
		sprintf(env,"CFI_SYNC=%d/%d",CFI_SYNC[1],CFI_SYNC[0]);
		putenv(stralloc(env));
		syncenv = 1;
	}

	if( rstat = filters[fid].f_stat )
		IGNRETZ pipe(fctl);

	CFI_STAT = -1;
	/*
	putProtoEnv(Conn);
	*/

	sprintf(type,"%s=%s",CFI_TYPE,what);
	putenv(stralloc(type)); /* 9.6.0 should be set before pushCGIENV() */
	pushProtoEnv(Conn,&evp);
	if( threadFilter(Conn,clsock,svsock,what,filter) ){
	}else
	if( INHERENT_fork() ){
	    if( Fork(what) == 0 ){
		ProcTitle(Conn,"(filter:%s)",what);
		if( rstat ){
			close(fctl[0]);
			CFI_STAT = fctl[1];
			CFI_STATFD = rstat;
		}
		if( 0 <= clclose ) close(clclose);
		if( 0 <= oclsock ) close(oclsock);
		if( 0 <= osvsock ) close(osvsock);
		execFilter(Conn,NULL,NULL,clsock,svsock,what,2,filter);
	    }
	}else{
		CStr(arg,1024);
		/*
		sprintf(arg,"%s %s",what,filter);
		*/
		sprintf(arg,"%s %d/%d/%d %s",what,rstat,fctl[0],fctl[1],filter);
		if( 0 <= clclose) setCloseOnExecSocket(clclose);
		if( 0 <= oclsock) setCloseOnExecSocket(oclsock);
		if( 0 <= osvsock) setCloseOnExecSocket(osvsock);
		execFunc(Conn,clsock,svsock,(iFUNCP)callF2,arg);
		if( 0 <= clclose) clearCloseOnExecSocket(clclose);
		if( 0 <= oclsock) clearCloseOnExecSocket(oclsock);
		if( 0 <= osvsock) clearCloseOnExecSocket(osvsock);
	}
	popProtoEnv(Conn,&evp);
	putenv(stralloc("CFI_TYPE="));

	if( rstat ){
		get_fstat(Conn,fid,fctl);
	}
	if( filters[fid].f_wait || filters[fid].f_push ){
		switch( fid ){
		case F_CL:
			Verbose("## %s %d -> %d\n",what,oclsock,clsock);
			push_fd(oclsock,clsock,0);
			push_fd(oclsock,clsock,1);
			break;
		}
	}
	if( syncenv ){
		putenv("CFI_SYNC=-1/-1");
	}
	if( flag_sav ){
		ThreadFlags &= ~TH_MTSS_PUTENV;
	}
}

static void callF1(Connection *Conn,FILE *in,FILE *out,PCStr(filter))
{
	execFilter(Conn,in,out,fileno(in),fileno(out),
		Conn->fi_what,Conn->fi_isresp,filter);
}

#define	F_IN	     0 /* input from filter, thus close dst side socket */ 
#define F_OUT	     1 /* output to filter, thus close src side socket */
#define F_CLOSE_CLNT 4 /* don't inherit client's side pipe/socket (may be
 a pipe to FTOCL) in server side filter (FTOSV,FTOMD) */

#define Close(fd)	( 0 <= fd && fd != src && fd != dst )

/*
 * uni-directional filters: FTOCL,FFROMCL,FTOSV,FFROMSV,FTOMD,FFROMMD
 */
static int forkexecFilter1X(Connection *Conn,int src,int dst,PCStr(what),int iomode,int isresp,PCStr(filter),int *pidp)
{	int tofil[2],fd;
	int pid;
	int clclnt;
	int fid = fntoi(what);
	int rstat,fctl[2];
	void *evp;

	IGNRETZ pipe(tofil);
	if( tofil[0] == src || tofil[1] == src ){
		src = -1; /* dangling descriptor */
		sv1log("-- forkexecF1X pipe=[%d][%d] src[%d]dst[%d]\n",
			tofil[0],tofil[1],src,dst);
	}
	if( tofil[0] == dst || tofil[1] == dst ){
		dst = -1; /* dangling descriptor */
		sv1log("-- forkexecF1X pipe=[%d][%d] src[%d]dst[%d]\n",
			tofil[0],tofil[1],src,dst);
	}
	if( rstat = filters[fid].f_stat )
		IGNRETZ pipe(fctl);

	CFI_STAT = -1;
	/*
	putProtoEnv(Conn);
	*/
	pushProtoEnv(Conn,&evp);
	if( INHERENT_fork() ){
		if( (pid = Fork(what)) == 0 ){
			if( rstat ){
				close(fctl[0]);
				CFI_STAT = fctl[1];
				CFI_STATFD = rstat;
			}
			ProcTitle(Conn,"(filter:%s)",what);
			Vsignal(SIGTERM,sigTERM);
			Vsignal(SIGINT, sigTERM);
			if( iomode & F_CLOSE_CLNT ){
				if( Close(ToC) ) close(ToC);
				if( Close(FromC) ) close(FromC);
				if( Close(ClientSock) ) close(ClientSock);
			}
			if( iomode & F_OUT ){
				if( 0 <= src && src != dst ) close(src);
				close(tofil[1]);
				execFilter(Conn,NULL,NULL,tofil[0],dst,
					what,isresp,filter);
			}else{
				if( 0 <= dst && dst != src ) close(dst);
				close(tofil[0]);
				execFilter(Conn,NULL,NULL,src,tofil[1],
					what,isresp,filter);
			}
		}

		if( iomode & F_OUT ){
			close(tofil[0]);
			if( pidp ) *pidp = pid;
			/*
			return tofil[1];
			*/
			fd = tofil[1];
		}else{
			close(tofil[1]);
			if( pidp ) *pidp = pid;
			/*
			return tofil[0];
			*/
			fd = tofil[0];
		}
	}else{
		strcpy(Conn->fi_what,what);
		Conn->fi_isresp = isresp;

		clclnt = 0;
		if( iomode & F_CLOSE_CLNT ){
			if( 0 <= ToC && ToC != src && ToC != dst ){
				setCloseOnExecSocket(ToC);
				clclnt = 1;
			}
		}
		if( iomode & F_OUT ){
			if( src != dst ) setCloseOnExecSocket(src);
			pid = spawnFilter(Conn,iomode,tofil,dst,(iFUNCP)callF1,filter);
			if( src != dst ) clearCloseOnExecSocket(src);
			close(tofil[0]);
			if( pidp ) *pidp = pid;
			fd = tofil[1];
		}else{
			if( dst != src ) setCloseOnExecSocket(dst);
			pid = spawnFilter(Conn,iomode,tofil,src,(iFUNCP)callF1,filter);
			if( dst != src ) clearCloseOnExecSocket(dst);
			close(tofil[1]);
			if( pidp ) *pidp = pid;
			fd = tofil[0];
		}
		if( clclnt ){
			clearCloseOnExecSocket(ToC);
		}
		/*
		return fd;
		*/
	}
	popProtoEnv(Conn,&evp);

	if( rstat ){
		get_fstat(Conn,fid,fctl);
	}

	if( filters[fid].f_wait || filters[fid].f_push ){
		if( iomode & F_OUT ){
			Verbose("## %s %d -> %d\n",what,fd,dst);
			push_fd(fd,dst,1);
		}else{
			Verbose("## %s %d -> %d\n",what,fd,src);
			push_fd(fd,src,0);
		}
	}
	return fd;
}

#define IS_BUILTIN(filter)	(filter[0] == '-')
int WithSocketFile();

static int thruFilter1(int iomode,int src,int dst){
	IStr(buf,4*1024);
	int rcc,wcc;
	int rtotal = 0,wtotal = 0;

	while( 1 ){
		rcc = read(src,buf,sizeof(buf));
		if( rcc <= 0 ){
			break;
		}
		rtotal += rcc;
		wcc = write(dst,buf,rcc);
		if( wcc <= 0 ){
			break;
		}
		wtotal += wcc;
	}
	if( iomode & F_OUT ){
		close(dst);
	}else{
		close(src);
	}
	sv1log("--thruFilter[%X] [%d][%d] %d/%d\n",TID,src,dst,wtotal,rtotal);
	return 0;
}
static int thruFilter(Connection *Conn,int fi,int iomode,int src,int dst){
	int pf[2];
	int in,out,rfd;
	int tid;

	IGNRETZ pipe(pf);
	if( iomode & F_OUT ){
		in = pf[0];
		out = dst;
		rfd = pf[1];
	}else{
		in = src;
		out = pf[1];
		rfd = pf[0];
	}
	tid = thread_fork(0,0,"pre-filter",(IFUNCP)thruFilter1,iomode,in,out);

	sv1log("--thruFilter(%d)[%X] [%d][%d][%d]\n",fi,PRTID(tid),
		pf[0],pf[1],rfd);
	STX_fth[fi] = tid;
	return rfd;
}
/* wait pre-filter thread to drain before shutdown the socket with the peer */
int waitPreFilter(Connection *Conn,int msec){
	int err;
	int fi;
	int fix;

	fi = F_PRE_TOCL;
	fix = XF_mask(fi);
	if( Conn->xf_filters & fix ){
        	if( STX_fth[fi] ){
			err = thread_wait(STX_fth[fi],msec);
			sv1log("--wait pre-filter(%d)[%X] err=%d\n",
				fi,PRTID(STX_fth[fi]),err);
			if( err == 0 ){
				STX_fth[fi] = 0;
				Conn->xf_filters &= ~fix;
				return 1;
			}else{
				return -1;
			}
		}
	}
	return 0;
}

static int forkexecFilter1(Connection *Conn,int src,int dst,PCStr(what),int iomode,int isresp,PCStr(filter),int *pidp)
{	CStr(xwhat,64);
	int sock,psock,fsock,pid;
	int pfi;

	if( pidp != NULL )
		*pidp = 0;

	if( iomode & F_OUT )
		sock = dst;
	else	sock = src;

	if( pidp == NULL )
	if( IS_BUILTIN(filter)
	 || WithSocketFile() || !file_ISSOCK(sock)
	)
	if( ClientFlags & PF_DO_PREFILTER ){
		sv1log("---- forcing pre-filter A\n");
	}else
	if( lNOSOCKINH() || lDOSOCKDUP() ){
		sv1log("---- NOSOCKINH pre-filter A\n");
	}else
	return forkexecFilter1X(Conn,src,dst,what,iomode,isresp,filter,NULL);

	if( !isresp && DFLT_PROTO[0] == 0 && isCFI(filter) ){
		CStr(buff,32);

		if( 0 < recvPeek1(src,buff,16) ){
			if( HTTP_isMethod(buff) )
				strcpy(DFLT_PROTO,"http");
		}
	}

	/* 9.2.3 pre-filter / post-filter to relay between the pipe
	 * (as the standard I/O of a filter program) with the client's/server's
	 * socket is not necessary with CFI (to be regarded as IS_BUILTIN())
	 */
	if( isCFI(filter) )
	if( fntoi(what) == F_TOCL )
	if( ClientFlags & PF_DO_PREFILTER ){
		sv1log("---- forcing pre-filter B\n");
	}else
	if( lNOSOCKINH() || lDOSOCKDUP() ){
		sv1log("---- NOSOCKINH pre-filter B\n");
	}else
	{
		Verbose("## %s don't insert pre-filter for CFI\n",what);
	return forkexecFilter1X(Conn,src,dst,what,iomode,isresp,filter,NULL);
	}

	if( filters[fntoi(what)].f_push ){
		Verbose("## %s don't insert pre-filter\n",what);
		psock = -1;
	return forkexecFilter1X(Conn,src,dst,what,iomode,isresp,filter,NULL);
	}else{
	    switch( fntoi(what) ){
		case F_TOCL:   pfi = F_PRE_TOCL; break;
		case F_FROMCL: pfi = F_PRE_FROMCL; break;
		case F_TOSV:   pfi = F_PRE_TOSV; break;
		case F_FROMSV: pfi = F_PRE_FROMSV; break;
		case F_TOMD:   pfi = F_PRE_TOMD; break;
		case F_FROMMD: pfi = F_PRE_FROMMD; break;
		default:
			sv1log("FATAL: pre-filter for [%s]\n",what);
			pfi = F_DISABLE;
			break;
	    }
	    if( lNOSOCKINH() || lDOSOCKDUP() ){
		psock = thruFilter(Conn,pfi,iomode,src,dst);
		sv1log("---- NOSOCKINH pre-filter thread inserted [%d]\n",
			psock);
	    }else{
	sprintf(xwhat,"%s-P",what);
		if( pfi == F_PRE_FROMCL )
		if( isCFI(filter) )
		if( streq(iSERVER_PROTO,"smtp")||streq(iSERVER_PROTO,"nntp") ){
			sprintf(xwhat,"%s-P-CFI-MIME",what);
		}
	psock = forkexecFilter1X(Conn,src,dst,xwhat,iomode,isresp,"-thru",&pid);
	if( pidp != NULL )
		*pidp = pid;
	sv1log("#### pre-filter inserted: %d\n",pid);
	    }
	switch( fntoi(what) ){
		case F_TOCL:   Conn->xf_filters |= XF_PRE_TOCL; break;
		case F_FROMCL: Conn->xf_filters |= XF_PRE_FROMCL; break;
		case F_TOSV:   Conn->xf_filters |= XF_PRE_TOSV; break;
		case F_FROMSV: Conn->xf_filters |= XF_PRE_FROMSV; break;
		case F_TOMD:   Conn->xf_filters |= XF_PRE_TOMD; break;
		case F_FROMMD: Conn->xf_filters |= XF_PRE_FROMMD; break;
		default:
			break;
	}

	if( iomode & F_OUT )
		dst = psock;
	else	src = psock;
	}

	fsock = forkexecFilter1X(Conn,src,dst,what, iomode,isresp,filter, NULL);
	close(psock);
	return fsock;
}

/*
 * RPORT : redirection port for response from the MASTER
 */
void scan_RPORT(Connection *Conn,PCStr(portin))
{	CStr(host,MaxHostNameLen);
	CStr(tcp_udp,128);
	int sock,port,listen = 0;

	RPORTsock = -1;
	if( portin == NULL )
		return;

	tcp_udp[0] = host[0] = 0;
	port = 0;
	Xsscanf(portin,"%[^:]:%[^:]:%d",AVStr(tcp_udp),AVStr(host),&port);
	if( strcasecmp(tcp_udp,"tcp") == 0 ) listen =  1; else
	if( strcasecmp(tcp_udp,"udp") == 0 ) listen = -1; else{
		/*
		sv1tlog("%s ? %s\n",tcp_udp,portin);
		*/
		sv1tlog("scan_RPORT: %s ? %s\n",tcp_udp,portin);
		Finish(-1);
	}
	RPORTudp = (listen < 0);
	sock = server_open("RPORT",AVStr(host),port,listen);
	port = sockPort(sock);
	if( host[0] == 0 )
		gethostname(host,sizeof(host));

	sprintf(D_RPORT,"%s:%s:%d",tcp_udp,host,port);
	RPORTsock = sock;
}
int static accept_RPORT(Connection *Conn)
{	int sock;

	if( RPORTsock < 0 )
		return -1;

	sv1log("ACCEPT RPORT[%d]...\n",RPORTsock);
	if( RPORTudp ){
		sock = RPORTsock;
		sv1log("ACCEPT RPORT[%d][%d] UDP\n",RPORTsock,sock);
	}else{
		sock = ACCEPT(RPORTsock,0,-1,0);
		sv1log("ACCEPT RPORT[%d][%d]\n",RPORTsock,sock);
		close(RPORTsock);
	}
	RPORTsock = -1;
	return sock;
}
static int connect_RPORTX(Connection *Conn,PCStr(portin))
{	CStr(host,MaxHostNameLen);
	CStr(tcp_udp,128);
	int sock,port,listen;

	if( D_RPORTX[0] == 0 )
		return -1;

	sv1log("CONNECT RPORTX[%s]\n",portin);
	if( Xsscanf(portin,"%[^:]:%[^:]:%d",AVStr(tcp_udp),AVStr(host),&port) != 3 )
		return -1;

	if( strcasecmp(tcp_udp,"udp") == 0 )
		sock = UDP_client_open("RPORTX","raw",host,port);
	else	sock = client_open("RPORTX","raw",host,port);
	Conn->xf_filters |= XF_RPORT;
	return sock;
}
int insertFTOCL(Connection *Conn,int client,int server)
{	const char *filter;
	int fsock;

	filter = getFilter(Conn,F_TOCL);
	if( filter == NULL )
		return client;

	fsock = forkexecFilter1(Conn,server,client,"FTOCL",  1,1,filter,NULL);

	EchoRequest = 1;
	Conn->xf_filters |= XF_FTOCL;
	if( isCFI(filter) )
		Conn->xf_filtersCFI |= XF_FTOCL;
	return fsock;
}
static int insertFFROMCL(Connection *Conn,int client,int *fpidp)
{	const char *filter;
	int fromclp[2];
	int fsock;

	filter = getFilter(Conn,F_FROMCL);
	if( filter == NULL )
		return -1;

	/* V.3.0.12 insert a simple relay process
	 * to cause normal EOF at the input of FFROMCL filter ?
	 */
	fsock = forkexecFilter1(Conn,client,-1,    "FFROMCL",0,0,filter,fpidp);
	Conn->xf_filters |= XF_FFROMCL;
	if( isCFI(filter) )
		Conn->xf_filtersCFI |= XF_FFROMCL;
	return fsock;
}

static int isSSLway(PCStr(filter)){
	if( filter[0] == '[' && strstr(filter,"/sslway") != 0
	 || strncmp(filter,"-sslway",7) == 0
	 || strncmp(filter,"sslway",6) == 0
	){
		return 1;
	}
	return 0;
}
int insertFCLF(Connection *Conn,int fromC,PCStr(filter));
int insertFCL(Connection *Conn,int fromC)
{	const char *filter;

	if( Conn->xf_filters & XF_FCL ){
		sv1log("insertFCL: duplicate\n");
		return -1;
	}
	filter = getFilter(Conn,F_CL);
	if( filter == NULL )
		return -1;

	return insertFCLF(Conn,fromC,filter);
}
int insertFCLF(Connection *Conn,int fromC,PCStr(filter)){
	int fromcl[2];

	if( isSSLway(filter) ){
		ClientFlags |= PF_SSL_ON;
	}
	/*
	Socketpair(fromcl);
	*/
	if( Socketpair(fromcl) != 0 ){
		daemonlog("F","FATAL: FCL failed to get socketpair()\n");
		return -1;
	}
	expsockbuf(fromcl[1],0x4000,0x8000);
	expsockbuf(fromcl[0],0x8000,0x4000);
	forkspawnFilter(Conn,"FCL",fromC,fromcl[1],fromcl[0],-1,filter);
	close(fromcl[1]);

	Conn->xf_filters |= XF_FCL;
	return fromcl[0];
}

int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock);
static int HTTPtunnel(Connection *Conn,PCStr(what),int serv)
{	CStr(connectmsg,1024);
	CStr(resp,1024);
	int rcc;

	if( !streq(CLNT_PROTO,"http") || !streq(DST_PROTO,"https") )
		return 0;

	/* from_client is on only if CONNECT method is used ... */
	if( Conn->from_myself && Conn->from_client )
		return 0;

	/* CONNECTed via SSLTUNNEL */
	if( ConnType == 'h' /* C_SSLTUNNEL */ ){
		return 0;
	}

	/*
	sprintf(connectmsg,"CONNECT %s:%d HTTP/1.0\r\n\r\n",DST_HOST,DST_PORT);
	write(serv,connectmsg,strlen(connectmsg));

	for(;;){
		rcc = RecvLine(serv,resp,sizeof(resp));
		if( rcc <= 0 )
			break;
		sv1log("[%s] %s",what,resp);
		if( *resp == '\r' || *resp == '\n' )
			break;
	}
	*/
	if( SSLtunnelNego(Conn,DST_HOST,DST_PORT,serv) < 0 ){
	}
	return 1;
}

int insertFMDX(Connection *Conn,int client,int msock,int ifSSL);
static int insertFMD(Connection *Conn,int client,int msock)
{
	return insertFMDX(Conn,client,msock,0);
}
int insertFMDX(Connection *Conn,int client,int msock,int SSLonly)
{	const char *filter;
	int tosv[2];

	if( Conn->xf_filters & XF_FMD ){
		if( ServerFlags & PF_SSL_ON ){
			return -1;
		}
	}
	if( msock < 0 )
		return -1;

	filter = getFilter(Conn,F_MD);
	if( filter == NULL )
		return -1;

	if( isSSLway(filter) ){
		ServerFlags |= PF_SSL_ON;
	}else
	if( SSLonly ){
		return 0;
	}

	HTTPtunnel(Conn,"FMD",msock);

	Socketpair(tosv);
	expsockbuf(tosv[0],0x4000,0x8000);
	expsockbuf(tosv[1],0x8000,0x4000);
	forkspawnFilter(Conn,"FMD",tosv[0],msock,client,tosv[1],filter);
	close(tosv[0]);

	Conn->xf_filters |= XF_FMD;
	return tosv[1];
}
int insertFSV(Connection *Conn,int client,int toS)
{
	return insertFSVF(Conn,client,toS,NULL);
}
int insertFSVF(Connection *Conn,int client,int toS,PCStr(filterx))
{	const char *filter;
	int tosv[2];

	if( toS < 0 )
		return -1;

	if( filterx )
		filter = filterx;
	else
	filter = getFilter(Conn,F_SV);
	if( filter == NULL )
		return -1;

	if( Conn->xf_filters & XF_FSV ){
		if( ServerFlags & PF_CREDHY_ON )
		if( streq(filter,"-credhy") )
		{
			Verbose("Duplicate FSV=-credhy\n");
			return -1;
		}
		sv1log("Duplicate %X FSV=%s\n",Conn->xf_filters,filter);
	}

	if( toProxy )
	HTTPtunnel(Conn,"FSV",toS);

	Socketpair(tosv);
	expsockbuf(tosv[0],0x4000,0x8000);
	expsockbuf(tosv[1],0x8000,0x4000);
	forkspawnFilter(Conn,"FSV",tosv[0],toS,client,tosv[1],filter);
	close(tosv[0]);

	if( filter[0] == '[' && strstr(filter,"/sslway") != 0
	 || strncmp(filter,"-sslway",7) == 0
	 || strncmp(filter,"sslway",6) == 0
	){
		ServerFlags |= PF_SSL_ON;
	}

	Conn->xf_filters |= XF_FSV;
	return tosv[1];
}
int insertFTOSV(Connection *Conn,int client,int server,int *pidp)
{	const char *filter;
	int fsock;

	filter = getFilter(Conn,F_TOSV);
	if( filter == NULL )
		return server;

	fsock = forkexecFilter1(Conn,client,server,"FTOSV",  5,0,filter,pidp);
	Conn->xf_filters |= XF_FTOSV;
	if( isCFI(filter) )
		Conn->xf_filtersCFI |= XF_FTOSV;
	return fsock;
}
/*
static int insertFFROMSV(Connection *Conn,int client,int server)
*/
int insertFFROMSV(Connection *Conn,int client,int server)
{	const char *filter;
	int fsock;

	filter = getFilter(Conn,F_FROMSV);
	if( filter == NULL )
		return server;

	fsock = forkexecFilter1(Conn,server,client,"FFROMSV",4,1,filter,NULL);
	Conn->xf_filters |= XF_FFROMSV;
	if( isCFI(filter) )
		Conn->xf_filtersCFI |= XF_FFROMSV;
	return fsock;
}

static int insertFTOMD(Connection *Conn,int client,int master)
{	int pipe[2];
	const char *filter;
	int fsock;

	filter = getFilter(Conn,F_TOMD);
	if( filter == NULL )
		return -1;

	fsock = forkexecFilter1(Conn,client,master,"FTOMD",  5,0,filter,NULL);
	Conn->xf_filters |= XF_FTOMD;
	return fsock;
}
static int insertFFROMMD(Connection *Conn,int client,int master)
{	const char *filter;
	int fsock;

	filter = getFilter(Conn,F_FROMMD);
	if( filter == NULL )
		return -1;

	fsock = forkexecFilter1(Conn,master,client,"FFROMMD",4,1,filter,NULL);
	Conn->xf_filters |= XF_FFROMMD;
	return fsock;
}


/*
 * Insert filters before the invocation of protocol interpreters
 * Filters which proces all of data from client (FCL and FFROMCL)
 * must be invoked at the start of interpretation.
 */
int insert_FCLIENTS(Connection *Conn,int *fromCp,int *toCp)
{	const char *filter;
	int fpid;
	int fromC,toC,toF;

	scan_CCXTOCL(Conn);

	fromC = *fromCp;
	toC = *toCp;
	fpid = 0;

	if( 0 <= (toF = insertFCL(Conn,fromC)) )
		fromC = toC = toF;
	else
	if( 0 <= (toF = insertFFROMCL(Conn,fromC,&fpid)) )
		fromC = toF;

	scan_RPORT(Conn,(char*)FS_RPORT);

	*fromCp = fromC;
	*toCp = toC;
	return fpid;
}

/*
 * ToServ is a FILE directed to a MASTER-DeleGate, which is used by
 * HTTP-DeleGate to suppress flushing a request message to MASTER-DeleGate,
 * buffered in the FILE buffer, before sending succeeding request data
 * for target-server, in NOACK or NOSYNC mode.
 * ToServ can be discarded (maybe) without side effects after flushed, and
 * should be because it is useless.
 */
void resetToServ(Connection *Conn,int nfd,PCStr(where))
{
	if( ToServ && fileno(ToServ) != nfd ){
		sv1log("####[%s] ToServ discarded (%d -> %d)\n",where,
			fileno(ToServ),nfd);
		fflush(ToServ);
		fcloseFILE(ToServ);
		ToServ = 0;
	}
}

/*
 * Insert filters right after the connection establishment to the server
 */
void insert_FSERVER(Connection *Conn,int fromC)
{	int toS;
	int toF;

	scan_CCXTOSV(Conn);

	if( CFI_DISABLE ){
		return;
	}

	if( ImCC ) return;

	if( 0 <= (toF = insertFSV(Conn,fromC,ToS)) ){
		resetToServ(Conn,toF,"FSV");
		ToSX = dup(ToS);
		dup2(toF,ToS);

		if( filters[F_SV].f_wait || filters[F_SV].f_push ){
			Verbose("## %s %d -> %d\n","FSV",ToS,ToSX);
			push_fd(ToS,ToSX,0);
			push_fd(ToS,ToSX,1);
		}

		/* close(toF); bad for Windows */
		ToSF = toF;
		Verbose("-- duplicated ToSX=%d, ToSF=%d\n",ToSX,ToSF);
	}else
/*
to enable the comination of FTOSV and FSV
	}
*/
	if( 0 <= ToS ){
		toS = ToS;
		ToS = insertFTOSV(Conn,fromC,ToS,NULL);
		resetToServ(Conn,ToS,"FTOSV");

		if( ToS != toS )
			ToSX = toS;
		else	ToSX = -1;
	}

	if( 0 <= FromS )
		FromS = insertFFROMSV(Conn,fromC,FromS);
}
void close_FSERVER(Connection *Conn,int realclose)
{
	if( 0 <= ToSX ){
		close(ToS);
		if( realclose ){
			close(ToSX);
			ToS = -1;
		}else{
			ToS = ToSX;
			/* maybe ImCC */
		}
		ToSX = -1;

		if( Conn->xf_filters & XF_FTOSV ){
			Conn->xf_filters &= ~XF_FTOSV;
			if( (Conn->xf_isremote & XF_FTOSV) == 0 )
				wait(0);
			Conn->xf_isremote &= ~XF_FTOSV;
		}
	}
}
void wait_FSERVER(Connection *Conn)
{
	if( Conn->xf_filters & XF_SERVER ){
		int pid;
		if( (Conn->xf_filters & XF_FTOSV) && 0 < ToSX ){
			Conn->xf_filters &= ~XF_FTOSV;
			close(ToS);
			ToS = -1;
		}
		pid = NoHangWait();
		if( pid == 0 ){
			msleep(1);
			pid = NoHangWait();
		}
		sv1log("wait_FSERVER() pid=%d\n",pid);
	}
}

/*
 * Insert filters right after the connection establishment to the MASTER
 */
void insert_FMASTER(Connection *Conn,int msock)
{	int fromS,toS;
	int toF;

	if( 0 <= (toF = insertFMD(Conn,ClientSock,msock)) ){
		resetToServ(Conn,toF,"FMD");
		dup2(toF,msock);
		close(toF);
		return;
	}

	if( (fromS = accept_RPORT(Conn)) < 0 )
		fromS = msock;

	if( (FromS = insertFFROMMD(Conn,ClientSock,fromS)) < 0 )
		FromS = fromS;
	else	FromSX = FromS; /* FFROMMD is inserted */

	if( 0 <= (toS = insertFTOMD(Conn,ClientSock,msock)) ){
		resetToServ(Conn,toS,"FTOMD");
		ToSX = msock;
		ToS = toS;
	}
}
int getservsideNAME(Connection *Conn,PVStr(me))
{
	if( Conn->xf_filters & (XF_FTOSV|XF_FTOMD) )
		return gethostNAME(ToSX,AVStr(me));
	else	return gethostNAME(ToS,AVStr(me));
}

/*
 * Postpone inserting FTOCL until request header is got.
 */
static int postponeFTOCL(Connection *Conn)
{
	if( strcaseeq(CLNT_PROTO,"http") ||  strcaseeq(CLNT_PROTO,"https") )
	{
		if( Conn->xf_reqrecv == 0 )
			return 1;
	}
	return 0;
}
/*
 *  Insert filters after some protocol (HTTP) header interpretation
 */
void insert_FPROTO(Connection *Conn,int fromC,int *toCp,int toS,int *fromSp)
{	int xtoC,fromS,toC;

	fromS = *fromSp;
	toC = *toCp;

	if( fromS < 0 )
		fromS = toS;

	if( (Conn->xf_filters & XF_RPORT) == 0 )
	if( 0 <= (xtoC = connect_RPORTX(Conn,D_RPORTX)) ){
		if( toC != ClientSock )
			close(toC);
		toC = xtoC;
	}

	if( !postponeFTOCL(Conn) )
	if( (Conn->xf_filters & XF_FTOCL) == 0 ) /* to avoid
		duplicate insertion in FTP-proxy ... */
	if( 0 <= (xtoC = insertFTOCL(Conn,toC,toS)) && xtoC != toC ){
		if( toC != ClientSock )
		if( toC == FromC || toC == fromC ){
			/* 9.8.6 don't disable FromC after FTOCL insertion */
			Verbose("don't close[%d] [%d][%d]\n",toC,FromC,ToC);
		}else{
			/* this close() is here from the origin (3.0.49)
			 * it should be saved as ToCX or so and closed later.
			 */
			closed("FTOCL",toC,-1);
			close(toC);
		}
		toC = xtoC;
	}

	*fromSp = fromS;
	*toCp = toC;
}


int filter_withCFI(Connection *Conn,int which)
{
	if( ImCC == 0 )
	if( Conn->xf_filters & which )
	if( filter_isCFI(which) )
		return 1;
	else
	if( Conn->xf_filtersCFI & which ){
		return 2;
	}
	return 0;
}

int mysystem(PCStr(path),const char *const *av,const char *const environ[]);
int isystem(PCStr(command)){
	int ch,qch;
	const char *a1;
	CStr(execpath,1024);
	const char *av[64];
	CStr(ab,2048);
	int ac,ai;
	int code;
	double Start;

	/* might be set if it's a TMPFILE() */
	clearCloseOnExec(0);
	clearCloseOnExec(1);

	qch = 0;
	for( a1 = command; ch = *a1; a1++ ){
		if( qch ){
			if( ch == qch )
				qch = 0;
		}else{
			if( ch == '"' || ch == '\'' ){
				qch = ch;
				continue;
			}
			switch( ch ){
				case ';': case '\r': case '\n':
				case '(': case ')': case '<': case '>':
				case '|':
				Verbose("calling system(%s)\n",execpath);
				code = system(command);
				return code;
			}
		}
	}

	ac = scanComArg(command,AVStr(execpath),av,elnumof(av),AVStr(ab));
	if( ac < 0 ){
		ac = decomp_args(av,elnumof(av),command,AVStr(ab));
		if( 0 < ac )
			strcpy(execpath,av[0]);
		else	strcpy(execpath,"");
	}
	Verbose("calling mysystem(%s)\n",execpath);
	Start = Time();
	closeOnExecServPorts(1); /* this does not work on Win */
	code = mysystem(execpath,av,(const char**)environ);
	closeOnExecServPorts(0);
	/*
	sv1log("%.3fs mysystem(%s)\n",Time()-Start,execpath);
	*/
	sv1log("%.3fs mysystem(%s) %d/%d\n",
		Time()-Start,execpath,(int)lseek(1,0,1),(int)lseek(0,0,1));
	return code;
}
#define system(com) isystem(com)

static void callFsystem(Connection *Conn,FILE *in,FILE *out,PCStr(command))
{	int fd;
	int savout;
	int lfd;
	int ufdbase;

	/* direct redirection will overwrite another if fileno(out)==0 */
	if( isWindows() ){
		ufdbase = 4; /* 9.9.7 [3] is sessionfd() on Win32 */
		if( fileno(in) != ufdbase )
			savout = ufdbase;
		else	savout = ufdbase+1;
    	}else{
		ufdbase = 3;
	if( fileno(in) == 3 )
		savout = 4;
	else	savout = 3;
    	}
	dup2(fileno(out),savout);
	dup2(fileno(in),0);
	dup2(savout,1);
	dup2(savout,2);
	/*
	  this is bad because it overwrites fileno(in) if fileno(in)==3
	dup2(fileno(out),3);
	dup2(fileno(in),0);
	dup2(3,1);
	dup2(3,2);
	*/
	lfd = curLogFd();
	/*
	for( fd = 3; fd < 32; fd++ )
	*/
	for( fd = ufdbase; fd < 32; fd++ )
	{
		if( fd != lfd )
		close(fd);
	}
	system(command);
}

int systemFilterNowait(PCStr(command),FILE *in,FILE *out,int tofd[])
{	int pid;
	Connection ConnBuf, *Conn = &ConnBuf;
	int fdi,fdo;

	sv1log("systemFilter[with buffered input = %d]: %s\n",
		ready_cc(in),command);

	IGNRETZ pipe(tofd);
/* use socketpair on Win32 ? */
	if( INHERENT_fork() ){
		if( (pid = fork()) == 0 ){
			fdi = dup(tofd[0]);
			fdo = dup(fileno(out));
			close(tofd[1]);
			close(fileno(in));
			dup2(fdi,0); close(fdi);
			dup2(fdo,1); close(fdo);
			execsystem("systemFilterNowait",command);
			Finish(-1);
		}
	}else{
		bzero(Conn,sizeof(Connection));
		pid = spawnFilter(Conn,1,tofd,fileno(out),(iFUNCP)callFsystem,command);
	}

	return pid;
}
static char *stripExecpath(PCStr(xcommand),PVStr(ycommand),int ysize)
{	const char *dp;

	if( xcommand[0] != '[' )
		return (char*)xcommand;

	/*
	dp = wordscanY(xcommand+1,AVStr(ycommand),ysize,"^]");
	 *
	 * wrap the command with '"' to cope with
	 * the command path includes spaces or
	 * the command path includes '/' (mixed with '\') on Win32
	 */
	strcpy(ycommand,"\"");
	dp = wordscanY(xcommand+1,QVStr(ycommand+1,ycommand),ysize,"^]");
	strcat(ycommand,"\"");

	if( *dp == ']' ){
		for( dp++; *dp && !isspace(*dp); dp++ ){
		}
		if( *dp == ' ' )
			strcat(ycommand,dp);
	}
	return (char*)ycommand;
}

/*
 * if fileno(in) or fileno(out) == 0 or 1,
 * especially when fileno(in)==1 and fileno(out)==0,
 * (this is the case when the system is called as CFI Header-Filter)
 * it must be carefully handled not to be closed and restored
 * after system() call...
 */
static int xsystem(FILE *in,FILE *out,PCStr(command))
{	int code;
	int fi,fo,fdi,fdo;
	int fix,fox;
	int fd0,fd1;
	CStr(ycommand,1024);

	fi = fdi = fileno(in);
	fo = fdo = fileno(out);

	sv1log("systemFilter[%d,%d]: %s\n",fi,fo,command);
	command = stripExecpath(command,AVStr(ycommand),sizeof(ycommand));

	/*
	 * move FD[0,1] if it belong to FILE *in,*out
	 * (move fi/fo to fdi/fdo out of FD[0,1])
	 */
	if( fi < 2 ) fdi = dup(fi);
	if( fdi< 2 ){ fix = fdi; fdi = dup(fix); close(fix); }
	if( fo < 2 ) fdo = dup(fo);
	if( fdo< 2 ){ fox = fdo; fdo = dup(fox); close(fox); }
/*
	if( fdi != fi ) close(fi);
	if( fdo != fo ) close(fo);
this is not necessary as it is closed automatically by dup2(fdi/fdo,0/1)
and is harmful making saved fd0/fd1 be lower than 2 which will cause
wrong restore.
*/

	/*
	 * save FD[0,1] if it does not belong to FILE *in,*out
	 */
	if( fi != 0 && fo != 0 ) fd0 = dup(0); else fd0 = -1;
	if( fi != 1 && fo != 1 ) fd1 = dup(1); else fd1 = -1;

	/*
	 * move FD[in,out] to FD[0,1] and call system()
	 */
	dup2(fdi,0); if( fdi != fi ) close(fdi);
	dup2(fdo,1); if( fdo != fo ) close(fdo);
	code = system(command);

	/*
	 * restore FD[0,1] which belonged to FILE *in,*out
	 */
	if( fdi != fi || fdo != fo ){
		Verbose("## xsystem() restore fdi=%d fdo=%d\n",fi,fo);
		fix = dup(0);
		fox = dup(1);
		if( fi < 2 ) dup2(fix,fi);
		if( fo < 2 ) dup2(fox,fo);
		close(fix);
		close(fox);
	}
	/*
	 * restore FD[0,1] which did not belong to FILE *in,*out
	 */
	if( fd0 != -1 || fd1 != -1 ){
		Verbose("## xsystem() restore fd0=%d, fd1=%d\n",fd0,fd1);
		if( fd0 != -1 ){ dup2(fd0,0); close(fd0); }
		if( fd1 != -1 ){ dup2(fd1,1); close(fd1); }
	}
	return 0;
}

int systemFilter(PCStr(command),FILE *in,FILE *out)
{	int pid;
	int tofd[2];
	FILE *tofp;
	vfuncp sig;
	CStr(xcommand,1024);
	int xpid;

	if( toFullpath(command,AVStr(xcommand),"",".exe",".cgi",NULL) )
		command = xcommand;

	fflush(out);

	if( ready_cc(in) <= 0 )
	if( xsystem(in,out,command) == 0 )
		return 0;

	pid = systemFilterNowait(command,in,out,tofd);
	close(tofd[0]);

	tofp = fdopen(tofd[1],"w");
	sig = Vsignal(SIGPIPE,SIG_IGN);
	simple_relayf(in,tofp);
	Vsignal(SIGPIPE,sig);

	fclose(tofp);

	for(;;){
		xpid = wait(0);
		Verbose("wait systemFilter: %d ... %d\n",pid,xpid);
		if( xpid <= 0 || xpid == pid ){
			break;
		}
	}
	return pid;
}

int relay_tofilter(int pid,int fromC,int toF,int fromF,int toC)
{	int nready,rcc,nrelayed;
	CStr(buf,4096);
	int wpid,xpid;

	wpid = pid;
	for(;;){
		nrelayed = 0;
		if( 0 <= fromC ){
			nready = PollIn(fromC,10);
			if( nready < 0 )
				goto EXIT;
			if( 0 < nready ){
				rcc = read(fromC,buf,sizeof(buf));
				if( rcc <= 0 )
					goto EXIT;
				nrelayed++;
				IGNRETP write(toF,buf,rcc);
			}
		}
		for(;;){
			nready = PollIn(fromF,100);
			if( nready < 0 )
				goto EXIT;
			if( 0 < nready ){
				rcc = read(fromF,buf,sizeof(buf));
				if( rcc <= 0 )
					goto EXIT;
				nrelayed++;
				IGNRETP write(toC,buf,rcc);
			}
			if( nready == 0 )
				break;
		}
		if( nrelayed == 0 ){ /* Win95 cant sense EOF of PIPE on Poll */
			xpid = NoHangWait();
			if( xpid == pid ){
				wpid = 0;
				goto EXIT;
			}
		}
	}
EXIT:
	return wpid;
}

int doXCOM(Connection *Conn,int in,int out,int err)
{	const char *command;

	command = DELEGATE_getEnv(P_XCOM);
	if( command == NULL )
		return 0;

	sv1log("exec-COMMAND: [%d,%d,%d] %s\n",in,out,err,command);
	if( Conn ){
		addConnEnviron(Conn);
		addSockEnviron(Conn,"CLIENT",ClientSock);
	}
	dup2(in,0);
	dup2(out,1);
	if( curLogFd() == 2 ){
		CStr(logfile,32);
		/* maybe running with -v or -vv option */
		int newlogfd;
		newlogfd = dup(2);
		LOG_closeall();
		fdopenLogFile(newlogfd);
		sv1log("#### fd[2] >> LOGFILE, redirect to fd[%d]\n",newlogfd);
		sprintf(logfile,"CFI_LOGFD=%d",newlogfd);
		putenv(stralloc(logfile));
	}
	dup2(err,2);
	if( 2 < in  ) close(in);
	if( 2 < out ) close(out);
	if( 2 < err ) close(err);

	execsystem("XCOM",command);
	Finish(-1);
	return -1;
}
int doXFIL(Connection *Conn,int in,int out,int err)
{	const char *filter;
	int toF,fromF,pidF,wpid;
	int tosv[2];

	filter = DELEGATE_getEnv(P_XFIL);
	sv1log("exec-FILTER: %s\n",filter?filter:"NONE (echo)");
	if( filter == NULL )
		return 0;

	Conn->xf_stderr2out = 1;
	fromF = forkexecFilter1(Conn,in,-1,"XFIL", 0,0,filter,&pidF);

/*
wpid = pidF; simple_relay(fromF,out);
*/
wpid = relay_tofilter(pidF,-1,-1,fromF,out);

	if( 0 < wpid ){
		close(fromF);
		close(ClientSock);
		Kill(wpid,SIGTERM);
		wait(0);
	}
	return 1;
}

int service_exec(Connection *Conn)
{
	if( service_permitted(Conn,"exec") == 0 )
		return -1;

	if( doXCOM(Conn,FromC,ToC,ToC) == 0 )
	if( doXFIL(Conn,FromC,ToC,ToC) == 0 )
		simple_relay(FromC,ToC);
	return 0;
}

extern int RELAYS_IGNEOF;
int relay_svclX(Connection *Conn,int fromC,int toC,int fromS,int toS,int ins);
int connect_main(int ac,const char *av[],Connection *Conn)
{	int ai;
	const char *arg;
	CStr(host,128);
	CStr(type,128);
	int port;
	int porth,portl;
	int sock;
	int qh = 0; /* send input as HTTP request(s) */

	host[0] = 0;
	port = 0;
	type[0] = 0;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strncmp(arg,"-F",2) == 0 )
			continue;
		if( strncmp(arg,"-qh",3) == 0 ){
			qh = atoi(arg+3) + 1;
		}else
		if( host[0] == 0 )
			strcpy(host,arg);
		else
		if( 2 <= Xsscanf(arg,"%d,%d/%s",&porth,&portl,AVStr(type)) )
			port = porth*256 + portl;
		else	Xsscanf(arg,"%d/%s",&port,AVStr(type));
	}
	if( host[0] == 0 || strstr(host,".af-local") == 0 && port <= 0 ){
		fprintf(stderr,
			"Usage: %s host port[/udp] [XCOM=command]\n",
			1<ac&&strncmp(av[1],"-F",2)==0?av[1]:"connect");
		exit(-1);
	}
	if( 1 ){ /* TLSxSNI */
		IStr(env,MaxHostNameLen);
		sprintf(env,"SERVER_NAME=%s",host);
		putenv(env);
	}

	if( strcasecmp(type,"udp") == 0 )
		scan_CONNECT(Conn,"udp");

	set_realserver(Conn,"tcprelay",host,port);
	Conn->from_myself = 1;
	if( streq(type,"udp") ){
		sock = UDP_client_open("connect","udprelay",host,port);
	}else
	sock = connect_to_serv(Conn,0,1,0);
	if( sock < 0 ){
		fprintf(stderr,"Cannot connect to %s:%d\n",host,port);
		exit(-1);
	}

	if( 0 ){
		if( 0 < PollIn(sock,300) ){
			CStr(buf,32);
			int rcc;
			rcc = RecvPeek(sock,buf,sizeof(buf));
			fprintf(stderr,"--- From Server ... %d\n",rcc);
		}
	}
	if( qh ){
		FILE *fc,*ts;
		IStr(line,256);
		int method = 0;
		fc = fdopen(0,"r");
		ts = fdopen(sock,"w");
		for(;;){
			if( fgets(line,sizeof(line),fc) == 0 )
				break;
			if( method == 0 ){
				method = line[0];
			}
			if( fputs(line,ts) == EOF )
				break;
			if( *line == '\r' || *line == '\n' ){
				if( method == 'G' ){
					fflush(ts);
					msleep(qh);
					method = 0;
				}
			}
		}
		fflush(ts);
		fcloseFILE(fc);
		fcloseFILE(ts);
	}

/*
	if( sock == 4 || sock == 5 || sock == 6 ){
		int sock2;
		sock2 = dup2(sock,16);
		close(sock);
		sock = sock2;
	}

The following may overwrite file descriptors of socket or log file
(at least on FreeBSD) but has no functio, maybe it's a kind of test...

	dup2(0,4);
	dup2(1,5);
	dup2(2,6);
*/
	if( doXCOM(NULL,sock,sock,fileno(stderr)) == 0 )
	if( doXFIL(Conn,sock,sock,fileno(stderr)) == 0 )
	{
		RELAYS_IGNEOF = 1;
		relay_svclX(Conn,0,1,sock,sock,1);
		RELAYS_IGNEOF = 0;
	}
	finishServYY(FL_ARG,Conn);
	exit(0);
	return 0;
}

int procSocket(Connection *Conn,PCStr(command),int sio[])
{	CStr(xcommand,1024);
	CStr(ycommand,1024);
	CStr(arg,1024);

	if( toFullpath(command,AVStr(xcommand),"",".exe",".cgi",NULL) )
		command = xcommand;
	command = stripExecpath(command,AVStr(ycommand),sizeof(ycommand));

	if( INHERENT_fork() ){
		INET_Socketpair(sio);
		if( Fork("procSocket") == 0 ){
			close(sio[1]);
			dup2(sio[0],0);
			dup2(sio[0],1);
			system(command);
			Finish(0);
		}
		close(sio[0]);
		sio[0] = sio[1];
		return 0;
	}else{
		sv1log("#### procSocket() not supported on Win32 yet.\n");
		return -1;
	}
}

void close_FSV(Connection *Conn)
{
	if( Conn->xf_filters & XF_FSV ){
		Conn->xf_filters &= ~XF_FSV;
		close(ToSX); ToSX = -1;
		close(ToSF); ToSF = -1;
	}
}

int find_CMAPXX(Connection *Conn,PCStr(map),PVStr(str),PCStr(proto),PCStr(method),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser));

int withFilter(Connection *Conn,PCStr(what),PCStr(proto),PCStr(method),PCStr(user),PVStr(str)){
	int mi;
	mi = find_CMAPXX(Conn,what,BVStr(str),proto,method,DST_HOST,DST_PORT,Client_Host,Client_Port,user);
	if( 0 <= mi ){
		return 1;
	}
	if( withPortFilter(Conn,what,proto,method,BVStr(str)) ){
		return 2;
	}
	return 0;
}
int insertFCLX(Connection *Conn,PCStr(proto),PCStr(method),int clnt,int serv)
{	int fcl;
	Port sv;

	sv = Conn->sv;
	strcpy(Conn->sv.p_proto,proto);
	fcl = insertFCL(Conn,clnt);
	Conn->sv = sv;
	return fcl;
}
/*
extern char CMAPmethod[32];
*/
int insertFSVX(Connection *Conn,PCStr(proto),PCStr(method),int clnt,int serv)
{	int tosv;
	Port sv;

	sv = Conn->sv;

    if( !enbugSTLS_BY_PROTO() && streq(proto,"starttls") ){
		IStr(dst_proto,64);
		IStr(dst_host,MaxHostNameLen);
		int dst_port;
		IStr(ometh,64);
		IStr(imeth,64);

		sv1log("--FSVX R[%s:%s] D[%s:%s] <= [%s/%s]\n",
			REAL_PROTO,REAL_HOST,DFLT_PROTO,DFLT_HOST,proto,method);
		strcpy(dst_proto,DST_PROTO);
		strcpy(dst_host,DST_HOST);
		dst_port = DST_PORT;
		if( *method == 0 ){
			method = dst_proto;
			sv1log("--WARN empty method => [%s/%s]\n",proto,method);
		}
		strcpy(imeth,method);

		strcpy(Conn->sv.p_proto,proto);
		strcpy(Conn->sv.p_host,dst_host);
		Conn->sv.p_port = dst_port;
			/* Conn->sv will be restored at exit */
		strcpy(ometh,ClientAuth.i_meth);
		strcpy(ClientAuth.i_meth,imeth);
		tosv = insertFSV(Conn,clnt,serv);
		strcpy(ClientAuth.i_meth,ometh);
    }else{
	Xstrcpy(FVStr(CMAPmethod),method); /* method might be sv.p_proto */
	if( proto[0] != 0 && Conn->sv.p_host[0] == 0 ){
		/* REAL_HOST need to be set for matching of CMAP because
		 * REAL_PROTO is used as DST_PROTO in the matching of CMAP
		 * only when REAL_HOST[0] != 0. 
		 * It can be unset yet even with SERVER=proto://host is
		 * specified in Telnet and Tcprelay.
		 */
		sv1log("[%s:%s][%s:%s]<-[%s/%s]\n",REAL_PROTO,REAL_HOST,
			DFLT_PROTO,DFLT_HOST,proto,method);
		strcpy(Conn->sv.p_host,DFLT_HOST);
	}
	strcpy(Conn->sv.p_proto,proto);
	tosv = insertFSV(Conn,clnt,serv);
	Xstrcpy(FVStr(CMAPmethod),"");
    }

	if( ServerFlags & PF_SSL_ON ){
		sv.p_flags |= PF_SSL_ON;
	}

	/* return attributes of ServerFilter */
	sv.p_filter[0] = Conn->sv.p_filter[0];

	Conn->sv = sv;
	return tosv;
}

int closeFilters(Connection *Conn,PCStr(what)){
	int nc = 0;
	if( 0 <= ToC && ToC != ClientSock ){
		int toC = ToC;
		closedX(what,toC,-1,1);
		close(toC);
		nc++;
	}
	if( 0 <= FromC && FromC != ClientSock ){
		int fromC = FromC;
		closedX(what,fromC,-1,1);
		close(fromC);
		nc++;
	}
	return nc;
}
