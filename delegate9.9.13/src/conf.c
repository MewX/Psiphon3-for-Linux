/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	conf.c (configuration variables)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	March94	created
//////////////////////////////////////////////////////////////////////#*/

#include "delegate.h"
#include "http.h" /* HTTP_cacheopt, CACHE_WITHAUTH */
#include "param.h"
#include "file.h"
#include "ccenv.h"

const char *MYSELF                 = "-.-";
const char *CLIENT_HOST            = "clnt.-";
const char *CLIENTIF_HOST          = "clif.-";
const char *ORIGDST_HOST           = "odst.-";
const char *DELEGATE_CONFIG        = "delegated.cf:/usr/etc/delegated.cf";
const char *DELEGATE_ADMIN_DFLT    = ADMIN;
const char *DELEGATE_ADMIN         = "";
const char *DELEGATE_ADMINPASS     = ADMINPASS;
const char *DELEGATE_OWNER         = "nobody";
const char *DELEGATE_G_PERMIT      = "*";
const char *DELEGATE_S_PERMIT      = "!*,.";
const char *DELEGATE_TELNET_PERMIT = "!*,telnet/{23,992,22}";
const char *DELEGATE_SOCKS_PERMIT  = "!*,socks,tcprelay";
const char *DELEGATE_HTTP_PERMIT   = "!*,http,https/{80,443},gopher,ftp,wais";
/* V8.0.0 limited default RELIABLE(.localnet) */
const char *DELEGATE_LOCALNET      = "localhost,./.,-/.,.o/."; /* .localnet */
const char *DELEGATE_RELAY         = "delegate,nojava:*:*:.localnet;vhost,nojava:http:{*:80}:.localnet;proxy";
const char *DELEGATE_RELIABLE      = ".localnet";

char	 SERV_HTTP[]         = "-.-";

const char *NOTIFY_PLATFORM        = "*.delegate.org";
const char *DELEGATE_LOGCENTER     = "www.delegate.org:8000";
const char *DELEGATE_DGPATH        = "+:.:${HOME}/delegate:${EXECDIR}:${ETCDIR}";

const char *DELEGATE_DGROOT        = "";
/*
const char *DELEGATE_CONF          = "${EXECDIR}/${EXECNAME}.conf";
v9.9.13 new-141023a
*/
const char *DELEGATE_CONF          = "${EXECDIR}/${EXECNAME}.conf;${EXECDIR}/../etc/${EXECNAME}.conf";
const char *DGCOMMON_CONF          = "${DGROOT}/common.conf";
const char *DELEGATE_VARDIR        = "${DGROOT?&:/var/spool/delegate}";
#if _MSC_VER
const char *DELEGATE_LDPATH        = "${ETCDIR};${LIBDIR};${EXECDIR};${STARTDIR};${HOME}/lib;/Windows;/";
#else
const char *DELEGATE_LDPATH        = "${ETCDIR};${LIBDIR};${EXECDIR};${STARTDIR};${HOME}/lib;/usr/local/lib;/usr/lib;/lib";
#endif
const char *DELEGATE_LIBDIR        = "${VARDIR}/lib";
const char *DELEGATE_LIBPATH       = ".;${STARTDIR};${LIBDIR};${EXECDIR};${ETCDIR}";
const char *DELEGATE_DATAPATH      = ".;${DGROOT};${STARTDIR};${EXECDIR}";
const char *DELEGATE_SUBINPATH     = ".;${DGROOT}/subin;${STARTDIR};${EXECDIR}";
const char *DELEGATE_WORKDIR       = "${VARDIR}/work/${PORT}";
const char *DELEGATE_LOGDIR        = "${VARDIR}/log";
const char *DELEGATE_ETCDIR        = "${VARDIR}/etc";
const char *DELEGATE_ADMDIR        = "${VARDIR}/adm";
const char *DELEGATE_HOSTID        = "${ETCDIR}/hosts/serno";
const char *DELEGATE_SMTPGATE      = "${ETCDIR}/smtpgate";
const char *DELEGATE_MTAB          = "${ETCDIR}/conf/${PORT}/mtab";
const char *DELEGATE_NEWSLIB       = "${ETCDIR}/news";
const char *DELEGATE_CERTDIR       = "${ETCDIR}/certs";
const char *DELEGATE_DBFILE        = "";
const char *DELEGATE_UASFILE       = "${LOGDIR}/uas/${UA}";
const char *DELEGATE_LOGFILE       = "${LOGDIR}/${PORT}";
const char *DELEGATE_STDOUTLOG     = "${LOGDIR}/stdout.log";
const char *DELEGATE_ERRORLOG      = "${LOGDIR}/errors.log";
const char *DELEGATE_TRACELOG      = "${LOGDIR}/ptrace.log";
const char *DELEGATE_EXPIRELOG     = "${LOGDIR}/expire.log";
const char *DELEGATE_ABORTLOG      = "${LOGDIR}/abort/${PORT}";
const char *DELEGATE_ACTDIR        = "${DGROOT?&/act:/tmp/delegate}";
const char *DELEGATE_TMPDIR        = "${DGROOT?&/tmp:/tmp/delegate}";
const char *DELEGATE_PIDFILE       = "${ACTDIR}/pid/${PORT}";
const char *DELEGATE_SOCKETS       = "${ACTDIR}/sockets";
const char *DELEGATE_STATFILE      = "";
const char *DELEGATE_PARAMFILE     = "${ETCDIR}/params/${PORT}";
const char *DELEGATE_PROTOLOG      = "${LOGDIR}/${PORT}.${PROTO}";
const char *DELEGATE_CACHEDIR      = "${VARDIR}/cache";
const char *DELEGATE_CACHEFILE     = "$[server:%P/%L/%p]";
const char *DELEGATE_CACHEPATH     = "";
int   DELEGATE_CACHE_CONTROL = 0;
const char *GOPHER_CACHE_ITEM      = "04569gI";
int   GOPHER_EXPIRE          = 60*60;	/* 1 hour */
int   HTTP_EXPIRE            = 60*60;	/* 1 hour */
int   FTP_EXPIRE             = 1*24*60*60;	/* 1 day */
int   FTP_ACCEPT_TIMEOUT     = 30; /* data connection timeout: 1 minute */
int   DELEGATE_syncro        = 0; /* syncronous mode (only one client
                                          at a time, for debug) */
const char *DELEGATE_IMAGEDIR      = 0;

int   DELEGATE_LISTEN        = 20;
/*
int   MAX_DELEGATE           = 64;
*/
int   MAX_DELEGATEdef        = 64; /* the default value */
int   MAX_DELEGATEdyn        = -1; /* calculated dynamically */
int   MAX_DELEGATEsta        = -1; /* explicitly specified */
int   BREAK_STICKY           = 0;

int   STANDBY_MAX            = 32;
int   STANDBY_TIMEOUT        = 30;
int   FDSET_MAX              = 64;

int   HELLO_TIMEOUT          = 30; /* HELLO negotiation with the MASTER */
int   LOGIN_TIMEOUT          = 60; /* Proxy telnet/ftp */
int   SERVER_TIMEOUT         = 0;
int   SERVER_RESTART         = 0;
int   SERVER_DEFREEZE        = 60;
int   VSAP_TIMEOUT           = 0;

int   BORN_SPECIALIST;

int   MASTER_ROUND_ROBIN     = 0;
double IDENT_TIMEOUT         = 1;
const char *HTTP_AUTHBASE          = "/delegate-auth";

/*
 *	CACHE FILE CONTROLE
 */
int CACHE_RDRETRY_INTERVAL =  3; /* in seconds */
int CACHE_WRRETRY_INTERVAL = 10; /* in seconds */

void disable_cache()
{
	DELEGATE_CACHE_CONTROL = -1;
}
void enable_cache()
{
	DELEGATE_CACHE_CONTROL = 0;
}
void set_CACHE(Connection *Conn){
	IStr(cache,128);
	if( 0 <= find_CMAP(Conn,"CACHE",AVStr(cache)) ){
		if( isinListX(cache,"no","c") ) disable_cache();
		if( isinListX(cache,"do","c") ) enable_cache();
		if( isinListX(cache,"auth","c") ) CacheFlags |= CACHE_WITHAUTH;
	}
}
/*
int without_cache(){
*/
int without_cacheX(Connection *Conn){
	if( lNOCACHE() ){
		return 1;
	}
	set_CACHE(Conn);
	return DELEGATE_CACHE_CONTROL < 0;
}

extern int CACHE_READONLY;
extern int CACHE_URLUNIFY;
void scan_CACHE1(Connection *Conn,PCStr(specs))
{
	CStr(spec,128);
	const char *sp;

	for( sp = specs; *sp; ){
		sp = scan_ListElem1(sp,',',AVStr(spec));
		if( *spec == 0 )
			break;
		if( streq(spec,"nounify") ){
			CACHE_URLUNIFY = 0;
			continue;
		}

	if( streq(spec,"auth") ){
		HTTP_cacheopt |= CACHE_WITHAUTH;
	}else
	if( streq(spec,"do") )
		enable_cache();
	else
	if( streq(spec,"no") )
		disable_cache();
	else
	if( streq(spec,"ro") )
		CACHE_READONLY = 1;
	}
}
/*
 * CACHE=do:http:*.sv.domain:*.cl.domain
 */
void scan_CACHE(Connection *Conn,PCStr(specs)){
	if( strchr(specs,':') ){
		IStr(spec1,128);
		IStr(proto,1024);
		IStr(dst,1024);
		IStr(src,1024);
		IStr(xmap,1024);
		scan_Lists4(specs,':',spec1,proto,dst,src);
		if( *proto || *dst || *src ){
			if( *proto == 0 ) strcpy(proto,"*");
			if( *dst   == 0 ) strcpy(dst,"*");
			if( *src   == 0 ) strcpy(src,"*");
			sprintf(xmap,"%s:%s:%s:%s:%s",spec1,"CACHE",proto,dst,src);
			scan_CMAP(Conn,xmap);
			return;
		}
	}
	scan_CACHE1(Conn,specs);
}

void scan_CACHEARC(PCStr(path)){
	DELEGATE_CACHEPATH = stralloc(path);
}
void scan_CACHEDIR(PCStr(dirs))
{
	if( dirs )
		DELEGATE_CACHEDIR = (char*)dirs;
}
void scan_CACHEFILE(PCStr(file))
{
	DELEGATE_CACHEFILE = (char*)file;
}

void strsubstDirEnv(PVStr(dir),PCStr(dgroot),PCStr(vardir))
{	const char *pp;
	const char *dp;
	const char *subst;
	const char *var;
	CStr(pat,1024);
	CStr(word1,1024);
	CStr(word2,1024);

	strsubst(AVStr(dir),"${VARDIR}",vardir);
	strsubst(AVStr(dir),"${DGROOT}",dgroot);

	subst = "${DGROOT?";
	if( pp = strstr(dir,subst) ){
		var = dgroot;
		word1[0] = word2[0] = 0;
		Xsscanf(pp+strlen(subst),"%[^:]:%[^}]",AVStr(word1),AVStr(word2));
		strcpy(pat,pp);
		if( dp = strchr(pat,'}') )
			((char*)dp)[1] = 0;
		if( var && *var )
			strsubst(AVStr(dir),pat,word1);
		else	strsubst(AVStr(dir),pat,word2);
		strsubst(AVStr(dir),"&",var);
	}
}

/*
const char *cachefmt()
*/
const char *cachefmt(PCStr(base))
{
	static struct { defQStr(fmt); } fmt;
	if( fmt.fmt==NULL ) setQStr(fmt.fmt,(char*)StructAlloc(1024),1024);
	/*
	sprintf(fmt.fmt,"%s/%s",cachedir(),DELEGATE_CACHEFILE);
	*/
	sprintf(fmt.fmt,"%s/%s",base,DELEGATE_CACHEFILE);
	return fmt.fmt;
}
void set_DG_EXPIRE(Connection *Conn,int expi)
{
	add_DGheader(Conn,D_EXPIRE,"%ds",expi);
}
void scan_EXPIRE(Connection *Conn,PCStr(expire))
{	CStr(period,256);
	CStr(triple,1024);
	CStr(cmap,1024);

	if( strchr(expire,':') ){
		period[0] = triple[0] = 0 ;
		Xsscanf(expire,"%[^:]:%s",AVStr(period),AVStr(triple));
		sprintf(cmap,"%s:expire:%s",period,triple);
	}else	sprintf(cmap,"%s:expire:*:*:*",expire);
	scan_CMAP(Conn,cmap);
}
int find_EXPIRE(Connection *Conn,int dflt_ev)
{	CStr(expire,256);
	int ev;

	if( D_EXPIRE[0] )
		ev = cache_expire(D_EXPIRE,dflt_ev);
	else
	if( 0 <= find_CMAP(Conn,"expire",AVStr(expire)) )
		ev = cache_expire(expire,dflt_ev);
	else	ev = dflt_ev;
	return ev;
}
int http_EXPIRE(Connection *Conn,PCStr(url))
{
	return find_EXPIRE(Conn,HTTP_EXPIRE);
}
int gopher_EXPIRE(Connection *Conn,PCStr(url))
{ 
	return find_EXPIRE(Conn,GOPHER_EXPIRE);
}
int ftp_EXPIRE(Connection *Conn)
{
	return find_EXPIRE(Conn,FTP_EXPIRE);
}

const char *isSetProxyOfClient(Connection *Conn,PVStr(cl_proto));
const char *baseURL(Connection *Conn)
{	const char *cl_proxy;
	CStr(mhp,MaxHostNameLen);
	CStr(cl_proto,64);
	MrefQStr(self,Conn->dg_iconbase); /**/

	if( Conn->cl_baseurl[0] )
		return Conn->cl_baseurl;

	if( self[0] == 0 ){
		if( cl_proxy = isSetProxyOfClient(Conn,AVStr(cl_proto)) ){
			if( cl_proto[0] == 0 )
				strcpy(cl_proto,CLNT_PROTO);
			if( cl_proto[0] )
				sprintf(self,"%s://%s",cl_proto,cl_proxy);
			else	sprintf(self,"//%s",cl_proxy);
		}else{
			HTTP_ClientIF_HP(Conn,AVStr(mhp));
			sprintf(self,"%s://%s",CLNT_PROTO,mhp);
		}
	}
	return self;
}

const char *MY_HOSTPORT()
{
	return MYSELF;
}
int isMYSELF(PCStr(host))
{
	if( streq(host,MYSELF) )
		return 1;
	if( streq(host,"-") )
		return 1;
	return 0;
}

int never_cache(Connection *Conn)
{
	return strchr(DELEGATE_FLAGS,'C') != 0;
}
int remote_access(Connection *Conn)
{
	return strchr(DELEGATE_FLAGS,'R') != 0;
}
int use_numaddress(Connection *Conn)
{
	return strchr(DELEGATE_FLAGS,'N') != 0;
}
int reserve_url(Connection *Conn)
{
	if( strchr(DELEGATE_FLAGS,'=') || strchr(DELEGATE_FLAGS,'T') )
		return 1;
	else	return 0;
}

/*
 *	BUILT-IN FILES
 */
const char *getIcon(PCStr(name),int *size)
{	int date;

	return get_builtin_data(name,size,&date);
}

const char *getMssg(PCStr(name),int *size)
{
	return getIcon(name,size);
}

const char *getIconX(PCStr(name),int *size,int *date){
	return get_builtin_data(name,size,date);
}
const char *getMssgX(PCStr(name),int *size,int *date){
	return getIconX(name,size,date);
}

void scan_builtin_data(PCStr(name),int (*func)(const void*,...),PCStr(arg1),PCStr(arg2));
void scanIcons(PCStr(name),int (*func)(const void*,...),PCStr(arg1),PCStr(arg2))
{
	scan_builtin_data(name,func,arg1,arg2);
}

void fcloseLinger(FILE *fp)
{
	fflush(fp);
	set_linger(fileno(fp),DELEGATE_LINGER);
	fcloseTIMEOUT(fp);
	set_linger(fileno(fp),0);
}

int	 IamPrivateMASTER       = 0;
int	 MASTERisPrivate        = 0 ;
int	 myPrivateMASTER        = 0 ;


#define WIN_PGROOT	"/Program Files"
#define WIN_DGROOT	"/Program Files/DeleGate"

#define DFLT_OWNER	"nobody"
#define DGROOT_GLOB	"/var/spool"
#define DGROOT_DFLT	"/tmp"
#define DGROOT_NAME	"delegate"

/* Normalize duplicated "//" to "/" or "\\" to "/" at the end of path
 * to avoid errors on Windows.
 * this normalization should be applied to any path-name by default
 * but it might be unsafe for path-name origined by remote-users
 * especially for ones derived from a URL-path.
 */
int normalizePath(PCStr(ipath),PVStr(npath)){
	refQStr(pp,npath);
	const char *sp;
	char sc;
	int norm = 0;
	int tail = 0;

	for( sp = ipath; sc = *sp; sp++ ){
	    /*
	    if( sc == '\\' ){
		sc = '/';
		if( norm++ == 0 ){
			porting_dbg("Path-Normalized<<< %s",ipath);
		}
	    }
	    */
	    if( sc == '/' || sc == '\\' ){
		while( sp[1]=='/' || sp[1]=='\\' || ipath<sp && sp[1]==0 ){
		    if( norm++ == 0 ){
/*
fprintf(stderr,"Path-Normalized<<< %s\n",ipath);
*/
		    }
		    if( sp[1] == 0 ){
			porting_dbg("Path-Normalized<<< %s",ipath);
			tail++;
			goto STREND;
		    }
		    sp++;
		}
	    }
	    setVStrPtrInc(pp,sc);
	} STREND:
	setVStrEnd(pp,0);
	if( norm ){
/*
fprintf(stderr,"Path-Normalized>>> %s\n",npath);
*/
		if( tail ){
			porting_dbg("Path-Normalized>>> %s",npath);
		}else{
		}
	}
	return norm;
}
int askNewrdir(PCStr(newdir),PCStr(cwd),PCStr(dir)){
	void YesOrNo(FILE *out,FILE *in,PCStr(msg),PVStr(yn));
	CStr(msg,1024);
	CStr(yn,128);

	sprintf(msg,"Create '%s/%s' for DGROOT='%s'",cwd,dir,newdir);
	YesOrNo(stderr,stdin,msg,AVStr(yn));
	if( yn[0] != 'y' )
		return -1;
	if( mkdirRX(dir) != 0 )
		return -1;
	return 1;
}
int tryDGROOT(int *created,int uid,int gid,PCStr(updir),PCStr(fmt),PCStr(a),PCStr(b))
{	CStr(dir,1024);
	const char *env;
	int isdir,rwx;

	*created = 0;
	strcpy(dir,updir);
	if( *dir != 0 && strtailchr(dir) != '/' )
		strcat(dir,"/");
	Xsprintf(TVStr(dir),fmt,a,b);
	normalizePath(dir,AVStr(dir));
	setOWNER(dir,uid,gid); /* this must be done beofre mkdirRX() */

      if( isFullpath(dir) && fileIsdir(dir) ){
	/* DGROOT=fullPathExistingDir ... use it as is */
      }else{
	substEXECDIR(dir,AVStr(dir),sizeof(dir));
	if( !isFullpath(dir) ){
		CStr(cwd,1024);
		CStr(xdir,1024);
		if( getcwd(cwd,sizeof(cwd)) != NULL ){
			int fis = File_is(dir);
			if( fis && !fileIsdir(dir) ){
fprintf(stderr,"DGROOT '%s' at '%s' is not directory.\n",dir,cwd);
				exit(0);
				return 0;
			}else
			if( !fis && askNewrdir(updir,cwd,dir) < 0 ){
fprintf(stderr,"DGROOT '%s' at '%s' not created.\n",dir,cwd);
				exit(0);
				return 0;
			}
			if( chdir(dir) == 0 ){
				if( getcwd(xdir,sizeof(xdir)) != NULL ){
fprintf(stderr,"DGROOT '%s' => '%s'\n",dir,xdir);
					strcpy(dir,xdir);
				}
				IGNRETZ chdir(cwd);
			}
		}
	}
      }

	if( isdir = fileIsdir(dir) ){
		rwx = access_RWX(dir);
		if( rwx != 0 && getuid() == 0 && uid != 0 ){
			seteuid(uid);
			rwx = access_RWX(dir);
			seteuid(0);
		}
		else
		if( geteuid() == 0 ){
			int fuid;
			fuid = File_uid(dir);
			if( fuid == uid ){
				/* will do setuid(uid) after, so the dir will
				 * become able to acess_RWX(dir) for the user
				 */
				rwx = 0;
			}
		}
		if( rwx != 0 ){
fprintf(stderr,"-delegate[%d]- insufficient access right: DGROOT=%s\n",
getpid(),dir);
			isdir = 0;
		}
	}else
	if( File_is(dir) ){
		isdir = 0;
	}else
	if( isdir = (mkdirRX(dir) == 0) ){
		*created = 1;
	}
	if( isdir ){
		CStr(cwd,1024);

		if( DELEGATE_DGROOT == 0 || strcmp(DELEGATE_DGROOT,dir) != 0 )
			DELEGATE_DGROOT = StrAlloc(dir);

		if( DELEGATE_DGROOT[0] == '/'
		 && getcwd(cwd,sizeof(cwd)) != NULL
		 && cwd[1] == ':' && cwd[2] == '\\' ){
			Xstrcpy(DVStr(cwd,2),DELEGATE_DGROOT);
			DELEGATE_DGROOT = StrAlloc(cwd);
		}

		if( env = DELEGATE_getEnv(P_DGROOT) )
		if( strcmp(env,dir) != 0 )
		{
			DELEGATE_pushEnv(P_DGROOT,dir);
		}
		if( File_uid(dir) != uid )
			setOWNER("",-1,-1);
		return 1;
	}
	return 0;
}

#include <sys/types.h>
#include <sys/stat.h>
static int DGROOT_done;
int setDGROOT(){
	const char *umasks;
	const char *dgroot;
	const char *owner;
	const char *env;
	int umaski;
	CStr(user,256);
	CStr(home,1024);
	CStr(shell,1024);
	int issu,withshell,uid,gid;
	int pid;
	int created = 0;
	IStr(dgrootb,1024);

	pid = getpid();
	if( DGROOT_done == pid )
	if( *DELEGATE_DGROOT != 0 )
		return 0;
	DGROOT_done = pid;

	if( umasks = DELEGATE_getEnv(P_UMASK) ){
		umaski = -1;
		sscanf(umasks,"%o",&umaski);
		if( umaski != -1 ){
			umask(umaski);
		}
		/* can be umasks for directory, file, ... respectively */
	}

	if( dgroot = DELEGATE_getEnv(P_DGROOT)  ){
		if( normalizePath(dgroot,AVStr(dgrootb)) ){
			dgroot = dgrootb;
		}
		DELEGATE_DGROOT = StrAlloc(dgroot);
		if( *DELEGATE_DGROOT == 0 ){
			/* compatible with DeleGate/5.X and former */
			return 0;
		}
	}

	/*
	if( getuid() == 0 ){
	*/
	if( dosetUidOnExec("set_DGROOT",DELEGATE_getEnv(P_OWNER),&uid,&gid) ){
		getUsername(uid,AVStr(user));
	}else
	if( getuid() == 0 || geteuid() == 0 ){
		if( (owner = DELEGATE_getEnv(P_OWNER)) == 0 )
			owner = DFLT_OWNER;
		if( scan_guid(owner,&uid,&gid) == 0 ){
			getUsername(uid,AVStr(user));
		}else{
			strcpy(user,DFLT_OWNER);
			uid = -1;
			gid = -1;
		}
	}else{
		uid = getuid();
		gid = getgid();
		getUsername(uid,AVStr(user));
	}

	/*
	 * if DGROOT is defined explicitly, use it.
	 */
	dgroot = DELEGATE_DGROOT;
	if( dgroot != NULL && *dgroot != 0 ){
		if( tryDGROOT(&created,uid,gid,"","%s",dgroot,NULL) )
			return created;
fprintf(stderr,"-delegate[%d]- bad DGROOT=%s\n",getpid(),dgroot);
	}

	/*
	 * if ${STARTDIR}/DGROOT exists, use it. new-140509b
	 */
	if( fileIsdir("DGROOT") ){
		IStr(cwd,256);
		if( getcwd(cwd,sizeof(cwd)) != NULL ){
			sprintf(dgrootb,"%s/DGROOT",cwd);
			DELEGATE_DGROOT = stralloc(dgrootb);
fprintf(stderr,"DGROOT=\"%s\"\n",dgrootb);
			return 0;
		}
	}

	/*
	 * on Windows: X:\Program Files\DeleGate
	 */
	if( fileIsdir(WIN_PGROOT) ){
		CStr(cwd,1024);

		if( WIN_DGROOT[0] == '/'
		&& getcwd(cwd,sizeof(cwd)) != NULL
		&& cwd[1] == ':' && cwd[2] == '\\' ){
			Xstrcpy(DVStr(cwd,2),WIN_DGROOT);
			DELEGATE_DGROOT = StrAlloc(cwd);
		}else
		DELEGATE_DGROOT = StrAlloc(WIN_DGROOT);
		return created;
	}

	/*
	 * on Unix: $HOME/delegate
	 *          /var/spool/delegate/$OWNER
	 *          /tmp/delegate/$OWNER
	 */
	issu = (uid == 0 || gid == 0);
	withshell = getSHELL(uid,AVStr(shell)) && *shell != 0 && fileIsflat(shell);
	if( !issu && withshell ){
		if( uid == getuid() && (env = DELEGATE_getEnv("HOME")) )
			strcpy(home,env);
		else	getHOME(uid,AVStr(home));
		if( strcmp(home,"/") != 0 && fileIsdir(home) )
		if( tryDGROOT(&created,uid,gid,home,"%s",DGROOT_NAME,NULL) )
			return created;
	}

	if( isWindows() ){
		/* not to create /tmp and /var/spool on Windows */
		const char *pdgroot;
		pdgroot = DELEGATE_getEnv(P_DGROOT);
		fprintf(stderr,"---- DONT TRY DGROOT for [%s] DGROOT=%s\n",
			user,pdgroot?pdgroot:"");
		return 0;
	}

	if( tryDGROOT(&created,uid,gid,DGROOT_GLOB,"%s-%s",DGROOT_NAME,user) )
		return created;

	if( tryDGROOT(&created,uid,gid,DGROOT_DFLT,"%s-%s",DGROOT_NAME,user) )
		return created;

	return 0;
}


static const char **PATHv[6]; /**/
#define X_LIB	0
#define X_DATA	1
#define X_COM	2
#define X_SUCOM	3
#define X_CACHE	4
#define X_DYLIB	5

static const char *pathn[6] = {
	"LIBPATH",
	"DATAPATH",
	"PATH",
	"SUBINPATH",
	"CACHEPATH",
	"LDPATH",
};

static char *getenvPATH(PVStr(path),int psiz)
{	const char *env;

	setVStrEnd(path,0);
	if( env = getenv("PATH") ){
		linescanX(env,AVStr(path),psiz);
	}
	return (char*)path;
}

int resetPATH(unsigned int li){
	if( elnumof(PATHv) <= li ){
		return -1;
	}else{
		if( PATHv[li] == 0 )
			return 0;
		PATHv[li] = 0;
		return 1;
	}
}
int resetPATHs(){
	int rn = 0;
	int li;
	for( li = 0; li < elnumof(PATHv); li++ ){
		if(  0 < resetPATH(li) ){
			rn++;
		}
	}
	return rn;
}
static void initPATH(int li){
	const char *paths;
	CStr(path,2048);
	int del;

	if( elnumof(PATHv) <= li ){
		daemonlog("F","## initPATH[%d/%d] overrun\n",li,elnumof(PATHv));
		return;
	}
	if( PATHv[li] == 0 ){
		switch( li ){
		case X_LIB:  paths = DELEGATE_LIBPATH; break;
		case X_DATA: paths = DELEGATE_DATAPATH; break;
		case X_COM:  paths = getenvPATH(AVStr(path),sizeof(path)); break;
		case X_SUCOM: paths = DELEGATE_SUBINPATH; break;
		case X_CACHE: paths = DELEGATE_CACHEPATH; break;
		case X_DYLIB: paths = DELEGATE_LDPATH; break;
		default:
			daemonlog("F","## initPATH[%d/%d]\n",li,elnumof(PATHv));
			return;
		}
		if( paths != path )
			strcpy(path,paths);
		/*
		DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
		*/
		if( strchr(path,';') )
			del = ';';
		else	del = ':';
		DELEGATE_substPath(pathn[li],del,path,AVStr(path));
		PATHv[li] = vect_PATH(path);
	}
}

static FILE* fopenLIBDATA(int li,PCStr(file),PCStr(mode),PVStr(xpath))
{
	initPATH(li);
	return fopen_PATH(PATHv[li],file,mode,AVStr(xpath));
}
FILE* fopenLIB(PCStr(file),PCStr(mode),PVStr(xpath))
{
	return fopenLIBDATA(X_LIB,file,mode,AVStr(xpath));
}
FILE* fopenDATA(PCStr(file),PCStr(mode),PVStr(xpath))
{
	return fopenLIBDATA(X_DATA,file,mode,AVStr(xpath));
}


int CTX_cache_pathX(Connection *Conn,PCStr(base),PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath));
FILE* fopenCACHEARC(Connection *Conn,PCStr(proto),PCStr(host),int port,PCStr(upath),PVStr(cpath)){
	int ok;
	FILE *fp;
	const char *dir;
	CStr(rpath,1024);

	if( DELEGATE_CACHEPATH[0] == 0 ){
		return NULL;
	}
	dir = cachedir();
	if( CTX_cache_pathX(Conn,dir,proto,host,port,upath,BVStr(cpath)) ){
		if( fp = fopen(cpath,"r") ){
			fclose(fp);
			return NULL;
		}
	}
	CTX_cache_pathX(Conn,".",proto,host,port,upath,AVStr(rpath));
	fp = fopenLIBDATA(X_CACHE,rpath,"r",BVStr(cpath));
	return fp;
}

static int fullpathLIBDATA(int li,PCStr(path),PCStr(mode),int ftype,PVStr(xpath))
{	FILE *fp;

	initPATH(li);
	if( lPATHFIND() ){
		fprintf(stderr,"### find '%s' in %s='",path,pathn[li]);
		if( PATHv[li] ){
			int i;
			for( i = 0; PATHv[li][i]; i++ ){
				if( 0 < i ) fprintf(stderr,";");
				fprintf(stderr,"%s",PATHv[li][i]);
			}
		}
		fprintf(stderr,"'\n");
	}
	if( fp = fopen_PATHX(PATHv[li],path,mode,ftype,BVStr(xpath)) ){
		fclose(fp);
		return 1;
	}
	return 0;
}
int fullpathDYLIB(PCStr(path),PCStr(mode),PVStr(xpath))
{
	return fullpathLIBDATA(X_DYLIB,path,mode,FTY_REG,BVStr(xpath));
}
int fullpathLIB(PCStr(path),PCStr(mode),PVStr(xpath))
{
	return fullpathLIBDATA(X_LIB,path,mode,FTY_REG,BVStr(xpath));
}
int fullpathDATA(PCStr(path),PCStr(mode),PVStr(xpath))
{
	/* MOUNT need to search both regular file and directory */
	return fullpathLIBDATA(X_DATA,path,mode,FTY_ANY,BVStr(xpath));
}
int fullpathCOM(PCStr(path),PCStr(mode),PVStr(xpath))
{
	return fullpathLIBDATA(X_COM,path,mode,FTY_REG,BVStr(xpath));
}
int fullpathSUCOM(PCStr(path),PCStr(mode),PVStr(xpath))
{
	return fullpathLIBDATA(X_SUCOM,path,mode,FTY_REG,BVStr(xpath));
}

int CACHE_TAKEOVER = 5;
int ERROR_RESTART;


const char *DELEGATE_exesign();
const char *DELEGATE_srcsign();
const char *DELEGATE_bldsign();
int sslway_dl();
void putSSLver(FILE *fp);
void putZLIBver(FILE *fp);
int Zsize(int *asize);
void put_identification(FILE *out);
int withPAM();
extern const char *type_fcloseFILE;
extern const char *WithThread;
extern const char *WithMutex;
int sizeofCSC();
int newSocket(PCStr(what),PCStr(opts));
int sock_peerfamlen(int sock);
int withORIGINAL_DST();
const char *SttyType();
const char *sgTTyType();
FileSize getSysctl(PCStr(name));
FileSize getSysinfo(PCStr(name));
extern int MAG_EXPSOCKBUF;
const char *RegexVer();

int prevMEM;

FileSize getMeminfo(PCStr(name)){
	FILE *fp;
	IStr(info,8*1024);
	const char *val;
	int memtotal;
	int memfree;
	int inactive;
	int active;
	int ina;

	fp = fopen("/proc/meminfo","r");
	if( fp == 0 )
		return -1;
	IGNRETP fread(info,1,sizeof(info),fp);
	fclose(fp);
	if( streq(name,"inactive") ){
		memtotal = -1;
		memfree = -1;
		inactive = -1;
		active = -1;
		if( val = findFieldValue(info,"MemTotal") )
			memtotal = atoi(val);
		if( val = findFieldValue(info,"MemFree") )
			memfree = atoi(val);
		if( val = findFieldValue(info,"Active") )
			active = atoi(val);
		if( val = findFieldValue(info,"Inactive") )
			inactive = atoi(val);
		if( inactive < 0 ){
			if( 0 < active )
				inactive = memtotal - active;
			else	inactive = memtotal / 8;
		}
		if( inactive < memfree )
			ina = memfree;
		else	ina = inactive;
		return ina * 1024;
	}
	return -1;
}
int MAX_DELEGATEP(int dyn){
	int max;
	static int prevmax;

	if( 0 < MAX_DELEGATEsta ) max = MAX_DELEGATEsta; else
	if( dyn && 0 < MAX_DELEGATEdyn ) max = MAX_DELEGATEdyn; else
		max = MAX_DELEGATEdef;
	if( max != prevmax )
	Verbose("MAX_DELEGATEP %d (%d)%d %d >>> %d\n",
		MAX_DELEGATEsta,dyn,MAX_DELEGATEdyn,MAX_DELEGATEdef,max);
	prevmax = max;
	return max;
}
void set_MAXIMA(Connection *Conn,int update){
	FileSize mem;
	FileSize imem;
	int max;
	int omax;
	int oexp;
	int mag;

	if( lNOAUTOMAXIMA() ){
		return;
	}
	if( 0 < (mem = getSysctl("hw.usermem"))
	 || 0 < (mem = getSysctl("hw.physmem"))
	 || 0 < (mem = getSysctl("hw.memsize"))
	 || 0 < (mem = getSysinfo("freemem"))
	 || 0 < (mem = getSysinfo("totalmem"))
	){
		imem = getMeminfo("inactive");
		if( mem < imem ){
			mem = imem;
		}
		mem /= 1024*1024;
		max = 0;
		/*
		omax = MAX_DELEGATE;
		*/
		omax = MAX_DELEGATEdyn;
		oexp = MAG_EXPSOCKBUF;

		/*
		if( 0 < origMAX_DELEGATE ){
			max = origMAX_DELEGATE;
		}else
		*/
		if( mem <  16 ) max =  8; else
		if( mem <  32 ) max = 10; else
		if( mem <  64 ) max = 12; else
		if( mem <  96 ) max = 14; else
		if( mem < 128 ) max = 16; else
		if( mem < 172 ) max = 20; else
		if( mem < 256 ) max = 24; else
		if( mem < 512 ) max = 32;
			   else max = MAX_DELEGATEP(0);

		if( 0 < max && max != omax ){
			if( MAX_DELEGATEsta < 0 )
			sv1log("MAXIMA=delegated:%d for small mem=%dM\n",
				max,(int)mem);
/*
porting_dbg("MAXIMA=delegated:%d for small mem=%dM <- %d (%d)",
max,(int)mem,prevMEM,origMAX_DELEGATE);
*/
			/*
			MAX_DELEGATE = max;
			*/
			MAX_DELEGATEdyn = max;
		}
		if( mem <  16 ){ mag = 16; }else
		if( mem <  32 ){ mag = 32; }else
		if( mem <  64 ){ mag = 48; }else
		if( mem <  96 ){ mag = 64; }else
		if( mem < 128 ){ mag = 80; }else
		if( mem < 172 ){ mag = 96; }else
			mag = -1;
		MAG_EXPSOCKBUF = mag;

		if( prevMEM )
		if( omax != max || oexp != mag ){
			sv1log("MAXIMA=delegated:%d <-%d, %d <-%d (%d <-%d)\n",
				max,omax,mag,oexp,(int)mem,prevMEM);
		}
		prevMEM = mem;
	}
}

#define memMB(z) (int)(z/(1024*1024))

int signedChar();

extern int SIZEOF_tid_t;
#if defined(m64)
#define optM64 "(-m64)"
#else
#define optM64 0
#endif

const char *myconf(PVStr(conf)){
	CStr(uname,256);
	FileStat *St;
	struct stat *st;
	int sock,iz,oz;
	int piz,poz;
	int sv[2];
	FileSize mem;
	int ssize,asize;

	Uname(AVStr(uname));
	sprintf(conf,"Config: %s",uname);
	if( optM64 ){
		Xsprintf(TVStr(conf),"%s",optM64?optM64:"");
	}
	Xsprintf(TVStr(conf),"; FileSize-Bits=%d/%d,%d/%d,%d,%d",
		isizeof(St->st_size)*8,isizeof(FileSize)*8,
		isizeof(st->st_size)*8,isizeof(int)*8,isizeof(int*)*8,
		SIZEOF_tid_t*8
	);

	sock = newSocket("conf","");
	getsockbuf(sock,&iz,&oz);
	close(sock);
	Xsprintf(TVStr(conf),"; socket=%d/%d",iz,oz);
	if( withORIGINAL_DST() ){
		Xsprintf(TVStr(conf),",++NAT");
	}
	if( Socketpair(sv) == 0 ){
		int svx = dup(sv[0]);
		int usp,usv[2],usc;

		getsockbuf(sock,&piz,&poz);
		Xsprintf(TVStr(conf),"; sockpair=%d/%d,%d%c%c",
			piz,poz,
			sock_peerfamlen(sv[0]),
			isAlive(sv[0])?'+':'-',
			isAlive(svx)?'+':'-'
		);
		close(svx);
		close(sv[0]);
		close(sv[1]);

		if( usp = UDP_Socketpair(usv) == 0 ){
			if( sock_isAFUNIX(usv[0]) )
				usc = 'U';
			else	usc = 'u';
		}else	usc = '-';
		Xsprintf(TVStr(conf),"%c",usc);
		if( usp ){
			close(usv[0]);
			close(usv[1]);
		}
	}
	Xsprintf(TVStr(conf),"; char=%s",signedChar()?"signed":"unsigned");
	Xsprintf(TVStr(conf),"; fcF=%s",type_fcloseFILE);
	Xsprintf(TVStr(conf),"; thread=%s",WithThread?WithThread:"none");
	Xsprintf(TVStr(conf),"/%s",WithMutex?WithMutex:"none");
	Xsprintf(TVStr(conf),",%s%d/%d",
		sizeof(CriticalSec)<sizeofCSC()?"#ERR#":"",
		sizeofCSC(),isizeof(CriticalSec));
	ssize = Zsize(&asize);
	Xsprintf(TVStr(conf),"; zlib=%d,%d",ssize,asize);
	Xsprintf(TVStr(conf),"; pam=%X",withPAM());
	Xsprintf(TVStr(conf),"; stty=%s/%s",SttyType(),sgTTyType());
	Xsprintf(TVStr(conf),"; regex=%s",RegexVer());
	if( LOG_VERBOSE ){
		Xsprintf(TVStr(conf),"; FDs=%d",FD_SETSIZE);
	}
	if( 1 ){
		extern const char *p2llx;
		Xsprintf(TVStr(conf),"; addr=%s/%llX/%llX",p2llx,p2llu(myconf),p2llu(&conf));
	}
	if( 0 < (mem = getSysctl("hw.usermem")) ){
		FileSize zmem,pmem;
		pmem = getSysctl("hw.physmem");
		zmem = getSysctl("hw.memsize");
		Xsprintf(TVStr(conf),"; umem=%d/%d/%dM",
			memMB(mem),memMB(pmem),memMB(zmem));
	}
	if( 0 < (mem = getSysinfo("totalmem")) ){
		FileSize fmem;
		FileSize imem;
		fmem = getSysinfo("freemem");
		imem = getMeminfo("inactive");
		/*
		Xsprintf(TVStr(conf),"; fmem=%d/%dM",
			memMB(fmem),memMB(mem));
		*/
		Xsprintf(TVStr(conf),"; fmem=%d/%d/%dM",
			memMB(fmem),memMB(imem),memMB(mem));
	}
	if( isWindows() ){
		Xsprintf(TVStr(conf),"; MSC=%d",MSCver());
	}
	return conf;
}
void put_myconf(FILE *out){
	CStr(conf,512);
	fprintf(out,"%s=%s\r\n",P_EXEC_PATH,EXEC_PATH);
	myconf(AVStr(conf));
	fprintf(out,"%s\r\n",conf);
}
static void puts1(PCStr(str),FILE *fp){
	const char *sp;
	char ch;
	for( sp = str; ch = *sp; sp++ ){
		if( strchr("'}\r\n",ch) )
			continue;
		putc(ch,fp);
	}
}
const char *getEXEsignMD5(PVStr(md5)){
	setVStrEnd(md5,0);
	Xsscanf(DELEGATE_exesign(),"%*[^:]:%*[^:]:%[^:]",BVStr(md5));
	return md5;
}
const char *getSRCsignDATE(PVStr(date)){
	setVStrEnd(date,0);
	Xsscanf(DELEGATE_srcsign(),"%*[^:]:%[^:]",BVStr(date));
	return date;
}
void putSRCsign(FILE *out){
	if( isWindowsCE() ){
		if( out == stdout || out == stderr )
			return;
	}
	fprintf(out,"%s=","SRCSIGN");
	puts1(DELEGATE_srcsign(),out);
	fprintf(out,"\r\n");
}
void putBLDsign(FILE *out){
	if( isWindowsCE() ){
		if( out == stdout || out == stderr )
			return;
	}
	fprintf(out,"%s=","BLDSIGN");
	puts1(DELEGATE_bldsign(),out);
	fprintf(out,"\r\n");
}
void setup_hostid(FILE *out,int verb);
extern const char *SIGN_windows_c;
int myid_mainX(int ac,const char *av[],FILE *idout){
	const char *admin;
	int ai;
	int v = 0;
	int vs = 0;

	for( ai = 1; ai < ac; ai++ ){
		if( strneq(av[ai],"-v",2) ){
			switch( av[ai][2] ){
				case 'v': v = 1; break;
				case 's': vs = 1; break;
			}
		}
	}
	if( vs ){
		fprintf(idout,"%s\n",DELEGATE_ver());
		return 0;
	}

	fprintf(idout,"--\r\n");
	put_identification(idout);
	put_myconf(idout);
	if( v || getenv("REMOTE_ADDR") ){
		IStr(uname,128);
		int tsiz;
		FileSize mtid = 0,ctid = 0;
		int getThreadIds(FileSize *mtid,FileSize *ctid);
		tsiz = getThreadIds(&mtid,&ctid);
		Uname(AVStr(uname));
		if( (mtid | 0xFFFFFFFF) == -1 ) mtid &= 0xFFFFFFFF;
		if( (ctid | 0xFFFFFFFF) == -1 ) ctid &= 0xFFFFFFFF;
		fprintf(idout,
			"Thread-IDs: size=%d/%d/%d main=%llX child=%llX (%s)\n",
			8*tsiz,8*isizeof(int*),8*isizeof(int),mtid,ctid,uname);
	}
	admin = getADMIN1();
	fprintf(idout,"ADMIN=%s\r\n",admin?admin:"");
	fprintf(stderr,"DGROOT=%s\r\n",DELEGATE_DGROOT);
	fflush(idout);
	fflush(stderr);
	if( v )
	LOG_type2 |= L_DYLIB;
	sslway_dl();
	putSSLver(idout);
	putZLIBver(idout);

	setup_hostid(idout,v);
	if( v == 0 ){
		fprintf(stderr,"Usage: add -vv option to trace the library search\n");
	}else{
		int with_gethostbyname2();
		fprintf(idout,"gethostbyname2: %s\r\n",
			with_gethostbyname2()?"yes":"no");

		fprintf(idout,"%s=","SRCSIGN");
		puts1(DELEGATE_srcsign(),idout);
		fprintf(idout,"\r\n");
		fprintf(idout,"%s=","BLDSIGN");
		puts1(DELEGATE_bldsign(),idout);
		fprintf(idout,"\r\n");
		fprintf(idout,"%s=","EXESIGN");
		puts1(DELEGATE_exesign(),idout);
		fprintf(idout,"\r\n");
	}
	if( v ){
		fprintf(idout,"%s\n",SIGN_windows_c);
	}
	if( LOG_VERBOSE ){
		iLOGdump(0,"---- initialization ----\n");
	}
	fprintf(idout,"--\r\n");
	return 0;
}

int myid_main(int ac,const char *av[]){
	return myid_mainX(ac,av,stdout);
}
