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
Program:	ftpgw.c (FTP on HTTP)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940321	creatged
//////////////////////////////////////////////////////////////////////#*/
/*
HTTP/FTP<- Accept: xxx
	<- Accept: ...
	...

	=> USER username
	=> PASS password
	=> TYPE I
	=> PORT h,h,h,h,p,p
	=> RETR filename

	-> HTTP/1.0 200 OK
	-> MIME-Version: 1.0
	-> Content-Type: application/octet-stream
	-> Content-Transfer-Encoding: 8bit
	-> Content-Lenght: 4096
	->
	<= data
	-> data
	...

	=> QUIT
*/

#include <errno.h>
#include <stdio.h>
#include "delegate.h"
#include "ystring.h"
#include "filter.h"
#include "fpoll.h"
#include "file.h"
#include "http.h"
#include "auth.h"
#include "proc.h"

int connectToSftpX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC);
void ftpc_dirext(PVStr(path));
FileSize FTP_datasize(PCStr(stat));
int unescape_path(PCStr(path),PVStr(xpath));
void gwputXferlog(Connection *Conn,PCStr(user),PCStr(pass),PCStr(path),FileSize start,int chit,FileSize xc);
int CTX_checkAnonftpAuth(Connection *Conn,PVStr(user),PCStr(pass));
FILE *ftp_fopen(Connection *Conn,int put,int server,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp,FILE *fsc);


extern int HTTP_ftpXferlog;

#define FORM_GOPHER	1
#define FORM_HTML	2
#define CHECK_LENG	2048

static const char *dgserv;
static const char *DGserv()
{	CStr(buff,128);

	if( dgserv == 0 ){
		sprintf(buff,"ETL-DeleGate/%s (as a FTP/HTTP gateway)",
			DELEGATE_ver());
		dgserv = StrAlloc(buff);
	}
	return dgserv;
}
void putAncestorAnchor(Connection *Conn,FILE *dst,PCStr(proto),PCStr(host),int port,PCStr(path),int hidepass)
{	CStr(url,256);
	CStr(durl,2048);
	CStr(pathbuf,2048);
	const char *pb;
	const char *dp;
	char dc;
	CStr(hostport,512);
	CStr(purl,512);
	CStr(psite,512);

	if( strcaseeq(REAL_PROTO,"sftp") )
		proto = "sftp";
	HostPort(AVStr(hostport),proto,host,port);
	if( DONT_REWRITE ){
		strcpy(url,"/");
		strcpy(durl,"/");
	}else{
	sprintf(url,"%s://%s/",proto,hostport);
	redirect_url(Conn,url,AVStr(durl));
	if( hidepass ) url_strippass(AVStr(durl));
	}

	strcpy(psite,hostport);
	if( hidepass )
		site_strippass(AVStr(psite));
	sprintf(purl,"%s://%s/",proto,psite);
	fprintf(dst,"<A HREF=\"%s\">%s</A>",durl,purl);

	strcpy(pathbuf,path);
	for( pb = pathbuf; dp = strchr(pb,'/'); pb = dp +1 ){
		dc = dp[1];
		((char*)dp)[1] = 0; /**/
		strcat(url,pb);
		redirect_url(Conn,url,AVStr(durl));
		if( hidepass ) url_strippass(AVStr(durl));
		fprintf(dst,"<A HREF=\"%s\">%s</A>",durl,pb);
		((char*)dp)[1] = dc; /**/
	}
	if( *pb ){
		strcat(url,pb);
		redirect_url(Conn,url,AVStr(durl));
		if( hidepass ) url_strippass(AVStr(durl));
		fprintf(dst,"<A HREF=\"%s\">%s</A>",durl,pb);
	}
}
static const char *get_ctype(PCStr(path),int binary,const char **encodingp)
{	const char *ctype;

	if( encodingp ) *encodingp = 0;
	if( (ctype = filename2ctype(path)) == 0 ){
		if( binary ){
			ctype = "application/octet-stream";
			if( encodingp ) *encodingp = "binary";
		}else	ctype = "text/plain";
	}
	return ctype;
}


#define VNO 100		/* X-) */

typedef struct {
  const char	*user;
  const char	*host;
	int	 port;
  const	char	*path;
	int	 isdir;
	double	 proc_secs;
	int	 dir_lines;
	int	 cache_date;
} FtpEnv;
static int printItem(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),FtpEnv *env)
{	CStr(buff,1024);

	if( streq(name,"ADMIN") || streq(name,"MANAGER") ){
		fprintf(fp,fmt,DELEGATE_ADMIN);
	}else
	if( streq(name,"anonftpAuth") ){
		if( streq(arg,"nopass") )
			return CTX_auth_anonftp(Conn,"PASSWD","UUUU@DDDD","*");
	}else
	if( streq(name,"resptime") ){
		fprintf(fp,"%3.1f",env->proc_secs);
	}else
	if( streq(name,"isdir") ){
		return env->isdir;
	}else
	if( streq(name,"site") ){
		HostPort(AVStr(buff),"ftp",env->host,env->port);
		if( streq(arg,"hidepass") )
			site_strippass(AVStr(buff));
		fprintf(fp,"%s",buff);
	}else
	if( streq(name,"host") ){
		fprintf(fp,"%s",env->host);
	}else
	if( streq(name,"port") ){
		fprintf(fp,"%d",env->port);
	}else
	if( streq(name,"path") ){
		fprintf(fp,"%s",env->path);
	}else
	if( streq(name,"anonymous") ){
		return is_anonymous(env->user);
	}else
	if( streq(name,"ancestor") ){
		putAncestorAnchor(Conn,fp,"ftp",env->host,env->port,env->path,
			streq(arg,"hidepass"));
	}else
	if( streq(name,"lines") ){
		fprintf(fp,"%d",env->dir_lines);
	}else
	if( streq(name,"cache") ){
		if( streq(arg,"hit") ){
			if( 0 < env->cache_date )
				return 1;
			else	return 0;
		}else
		if( streq(arg,"date") ){
			StrftimeLocal(AVStr(buff),sizeof(buff),TIMEFORM_mdHMS,
				env->cache_date,0);
			fprintf(fp,"%s",buff);
		}
	}
	return 0;
}

#ifndef MAIN

static int needAuth(PCStr(quser),PCStr(resp))
{	const char *dp;
	const char *busy = "530-COMMAND: USER ";
	CStr(user,256);
	CStr(unknown,256);

	if( atoi(resp) == 530 ){
		if( is_anonymous(quser) ){
			if( strcasestr(resp,"too many") )
				return 0;
			if( strcasestr(resp,"at a time") )
				return 0;
		}
		if( dp = strstr(resp,busy) ){
			wordScan(dp+strlen(busy),user);
			if( is_anonymous(user) ){
				if( strstr(dp,"Guest login not permitted") )
					return 1;
				sprintf(unknown,"User %s unknown",user);
				if( strstr(dp,unknown) )
					return 1;

				/* maybe too many anonymous login, or
				 * no anonymous support.
				 */
				sv1log("NO (more) anonyomous ?\n");
				return 0;
			}
		}
		return 1;
	}
	return 0;
}
static void putErrorHead(Connection *Conn,FILE *out,int vno,PCStr(req),PCStr(host),PCStr(user),PCStr(resp),int *stcodep)
{
	if( atoi(resp) == 530 ){
		if( Conn->reject_reason[0] == 0 ){
			IStr(reason,sizeof(Conn->reject_reason));
			lineScan(resp,reason);
			sprintf(Conn->reject_reason,"%s:%s",user,reason);
		}
		if( isinFTPxHTTP(Conn) ){
			/* 9.9.8 maybe anonymous or without PASS */
		}else
		HTTP_delayReject(Conn,req,resp,1);
		if( needAuth(user,resp) ){
			putNotAuthorized(Conn,out,req,ProxyAuth,NULL,"");
			*stcodep = 401;
		}else{
			putHttpNotAvailable(Conn,out,resp);
			*stcodep = 503;
		}
	}else{
		delayUnknown(Conn,1,req);
		putHttpNotFound(Conn,out,resp);
		*stcodep = 404;
	}
}

FileSize CCV_relay_texts(Connection *Conn,FILE *ins[],FILE *out,FILE *dup);
FileSize file_copy(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary);
FileSize CTX_file_copy(Connection *Conn,FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary);

int relay_bytes(Connection *Conn,FILE *in,FILE *out,PCStr(range)){
	FileSize from,len,rcc,wcc;
	int ch;

	from = len = 0;
	Xsscanf(range,"%lld %lld",&len,&from);

	wcc = 0;
	for( rcc = 0; wcc < len; rcc++ ){
		ch = getc(in);
		if( ch == EOF )
			break;
		if( rcc < from )
			continue;

		if( putc(ch,out) == EOF )
			break;
		wcc++;
	}
	fflush(out);
	sv1log("relay_bytes[%s] %lld/%lld\n",range,wcc,len);
	return rcc;
}

static FileSize ident_copy(Connection *Conn,FILE *fsd,FILE *tc,FILE *cachefp,PCStr(server),PCStr(path),FileSize size,int expire)
{	int binary;
	const char *encoding;
	FILE *tmp;
	FileSize totalc;
	const char *ctype;
	int ci;
	const char *base;
	FILE *ins[3]; /**/
	FILE *tcx = 0;

	EmiSetupMD5(Conn,"ident_copy");

	tmp = reusableTMPFILE("ident_copy",(iFUNCP)ident_copy);
	file_copy(fsd,tmp,NULL,CHECK_LENG,&binary);
	fflush(tmp);

	ctype = get_ctype(path,binary,&encoding);

	if( (base = strrchr(path,'/')) == 0 )
		base = path;

	if( !Conn->body_only && 0<Conn->cl.p_range[0] || 0<Conn->cl.p_range[1] ){
		FileSize len;
		CStr(range,32);
		/*
		*stcodep = 206;
		*/
		Conn->sv.p_range[0] = Conn->cl.p_range[0];
		if( Conn->cl.p_range[1] <= 0 || size <= Conn->cl.p_range[1] )
			Conn->sv.p_range[1] = size-1;
		else	Conn->sv.p_range[1] = Conn->cl.p_range[1];
		Conn->sv.p_range[2] = size;
		len = Conn->sv.p_range[1] - Conn->sv.p_range[0] + 1;
		putHEAD(Conn,tc,206,"Partial",server,ctype,encoding,len,-1,expire);
		fputs("\r\n",tc);
		fflush(tc);

		sprintf(range,"%lld",len);
		tcx = openFilter(Conn,"RANGE",(iFUNCP)relay_bytes,tc,range);
		if( tcx != NULL ){
			tc = tcx;
		}
	}else
if( !Conn->body_only )
	{
	putHttpHeader1(Conn,tc,server,ctype,encoding,size,expire);
	/* fprintf(tc,"X-Local-Filename: %s\r\n",base); */
	}

	fseek(tmp,0,0);

/*
4.3.0: code conversion should be done at HttpResponseFilter
but CHARCODE env is not passed to the filter in Windows version...
*/
	if( strncmp(ctype,"text/",5) == 0 ){
		ins[0] = tmp;
		ins[1] = fsd;
		ins[2] = 0;
		totalc = CCV_relay_texts(Conn,ins,tc,cachefp);
	}else{
		totalc = CTX_file_copy(Conn,tmp,tc,cachefp,0,NULL);
		totalc += CTX_file_copy(Conn,fsd,tc,cachefp,0,NULL);
		/*
		totalc = file_copy(tmp,tc,cachefp,0,NULL);
		totalc += file_copy(fsd,tc,cachefp,0,NULL);
		*/
	}
	if( EmiActive(Conn) ){
		IStr(md5a,64);
		EmiFinishMD5(Conn,"ident_copy",totalc);
		EmiPrintMD5(Conn,AVStr(md5a));
		sv1log("## MD5=%s %s leng=%lld %s\n",md5a,ctype,totalc,
			file_isreg(fileno(fsd))?"Cache":"");
	}

	fclose(tmp);
	if( tcx != NULL ){
		int wi;
		fclose(tcx);

		/* wait child (or suppress shutdown the socket ...) */
		for( wi = 0; wi < 30; wi++ ){
			int pid;
			errno = 0;
			pid =
		NoHangWait();
			Verbose("Waiting pid=%d errno=%d\n",pid,errno);
			if( 0 < pid )
				break;
			if( errno == ECHILD )
				break;
			msleep(100);
		}
	}
	return totalc;
}

static int ftp_cachepath(Connection *Conn,PCStr(host),int port,PCStr(path),PVStr(cachepath))
{
	CStr(xpath,1024);

	setVStrEnd(cachepath,0);
	if( without_cache() )
		return 0;

	nonxalpha_escapeX(path,AVStr(xpath),sizeof(xpath));
	path = xpath;
	CTX_cache_path(Conn,"ftp",host,port,path,AVStr(cachepath));
	return cachepath[0] != 0;
}

int FTP_CACHE_ANYUSER;
static int get_ftpcache(Connection *Conn,PCStr(user),PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cachepath))
{	int rcode;

	setVStrEnd(cachepath,0);

	if( FTP_CACHE_ANYUSER || is_anonymous(user) )
	if( rcode = ftp_cachepath(Conn,host,port,path,AVStr(cachepath)) ){
		if( ext != NULL && ext[0] ){
			if( strtailchr(cachepath) == '/' && ext[0] == '/' )
				ext++;
			strcat(cachepath,ext);
		}
		return rcode;
	}
	return 0;
}

FILE *CTX_creat_ftpcache(Connection *Conn,PCStr(user),PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cpath),PVStr(xcpath))
{
	if( xcpath )
		setVStrEnd(xcpath,0);
	if( get_ftpcache(Conn,user,host,port,path,ext,AVStr(cpath)) )
		return cache_make("FTP-CACHE",cpath,AVStr(xcpath));
	else	return NULL;
}

#define TOLERANCE	(5*60)

static FILE *openLIST(PCStr(ocpath),int *Tdp)
{	FILE *pfp;
	const char *dp;
	CStr(ppath,1024);
	CStr(cwd,256);

	strcpy(ppath,ocpath);
	if( dp = strrchr(ppath,'/') )
		if( dp[1] == 0 )
			truncVStr(dp);
	strcpy(cwd,"../");
	ftpc_dirext(AVStr(cwd));
	chdir_cwd(AVStr(ppath),cwd,0);
	if( pfp = fopen(ppath,"r") )
		*Tdp = file_mtime(fileno(pfp));
	else	*Tdp = -1;
	return pfp;
}

char *scan_ls_l(PCStr(lsl),PVStr(mode),int *linkp,PVStr(owner),PVStr(group),FileSize *sizep,PVStr(date),PVStr(name),PVStr(sname));

static int getstatFromLIST(FILE *pfp,PCStr(ocpath),int Tn,int *TFp,FileSize *SFp)
{	int TF;
	FileSize SF;
	const char *dp;
	const char *file;
	CStr(line,1024);
	CStr(date,1024);
	CStr(name,1024);
	CStr(sname,1024);

	if( dp = strrchr(ocpath,'/') )
		if( dp[1] == 0 )
			truncVStr(dp);
	if( file = strrchr(ocpath,'/') )
		file += 1;
	else	file = ocpath;

	TF = SF = -1;
	while( fgets(line,sizeof(line),pfp) != NULL ){
		if( strstr(line,file) == NULL )
			continue;
		if( scan_ls_l(line,VStrNULL,NULL,VStrNULL,VStrNULL,&SF,AVStr(date),AVStr(name),AVStr(sname))
			== NULL )
			continue;
		if( strcmp(name,file) != 0 )
			continue;
		TF = LsDateClock(date,Tn);
		break;
	}

	*TFp = TF;
	*SFp = SF;
	if( TF == -1 && SF == -1 )
		return 0;
	else	return 1;
}
static int cache_reload(Connection *Conn,PCStr(ocpath),FILE *cachefp,int isdir,FileSize fsize,int mtime,int expire)
{	FILE *pfp;
	int reload,obsolete;
	int Tn;	/* current time */
	int Te; /* EXPIRE in seconds */
	int Td; /* modified time of DIR cache (.ls-l.) */
	int Tf; /* modified time of FILE cache (file or subdirectory) */
	FileSize Sf; /* size of FILE cache */
	int TF; /* modified time of original FILE shown in DIR */
	FileSize SF; /* size of original FILE shown in DIR */
	int TT; /* tolerance */
	const char *status;
	const char *reason;

	Tn = time(0);
	Te = expire;
	Tf = mtime;
	Sf = fsize;
	TT = TOLERANCE;
	obsolete = Tf + Te < Tn;

	if( (pfp = openLIST(ocpath,&Td)) == NULL ){
		reload = obsolete;
		status = "A";
		reason = "can't find LIST cache";
	}else
	if( getstatFromLIST(pfp,ocpath,Tn,&TF,&SF) == 0 )
	{
		reload = obsolete;
		status = "B"; reason = "LIST cache does not contain the file";
	}else
	if( Td + Te < Tn )
	{
		reload = obsolete;
		status = "C"; reason = "LIST cache is out of date";
	}else
	if( Td < Tf )
	{
		reload = obsolete;
		status = "D"; reason = "can't rely on LIST cache";
	}else
	if( !isdir && Sf != SF )
	{
		reload = 1;
		status = "E"; reason = "size changed";
	}else
	if( TF+TT < Tf )
	{
		reload = 0;
		status = "F"; reason = "cache seems new enough";
	}else
	if( TT < TF - Tf )
	{
		reload = 1;
		status = "G"; reason = "cache seems old enough";
	}else
	if( TT > Tn - Tf )
	{
		reload = 0;
		status = "H"; reason = "may be obsolete but in tolerance";
	}else
	{
		reload = 1;
		status = "I"; reason = "may be obsolete and out of tolerance";
	}

	if( pfp != NULL )
		fclose(pfp);

	if( DontReadCache ){
		reload = 1;
		status = "R"; reason = "forced reload by HTTP/no-cache";
	}

	sv1log("FTP-CACHE-%s %s: (%s)\n",
		status,reload?"RELOAD":"REUSE",reason);
	if( obsolete && !reload || !obsolete && reload )
		sv1log("## ignore EXPIRE[%d] %d < %d\n",obsolete,Te,Tn-Tf);
	if( pfp != NULL ){
		Verbose("## LIST= %d {%d/%lld} FILE= {%d/%lld}\n",Td,TF,SF,Tf,Sf);
		Verbose("## tolerance=%d : newer=%d, age=%d : expire=%d\n",
			TT,Tf-TF,Tn-Tf,Te);
	}
	return reload;
}

#define STRIPPATH(path)	(path = (path[0] == '/') ? path + 1 : path)

FILE *fopen_ftpcache0(Connection *Conn,int expire,PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cpath),int *isdirp,FileSize *sizep,int *mtimep)
{	CStr(ocpath,1024);
	CStr(xcpath,1024);
	FILE *cachefp;
	FileSize fsize;
	int expire0,mtime;
	int isdir;

	if( sizep ) *sizep  = -1;

	if( ftp_cachepath(Conn,host,port,path,BVStr(cpath)) == 0 )
		return NULL;

	strcpy(ocpath,cpath);
	if( ext && ext[0] )
		strcat(cpath,ext);

	isdir = *isdirp;
	strcpy(xcpath,cpath);
	if( isdir == 0 )
		ftpc_dirext(AVStr(xcpath));

	Verbose("(don't determin expire here)\n");
	expire0 = 0x7FFFFFFF; /* don't determine expire here */

	if( isdir <= 0 && (cachefp = cache_fopen_rd("FTP/HTTP",BVStr(cpath),expire0,&mtime)) ){
		if( isdir == 0 ) *isdirp = -1;
	}else
	if( 0 <= isdir && (cachefp = cache_fopen_rd("FTP/HTTP",AVStr(xcpath),expire,&mtime)) ){
		strcpy(cpath,xcpath);
		if( isdir == 0 ) *isdirp = 1;
	}else{
		return NULL;
	}

	fsize = file_sizeX(fileno(cachefp));
	if( sizep ) *sizep = fsize;
	if( mtimep ) *mtimep = mtime;

	/*
	if( cache_reload(ocpath,cachefp,*isdirp,fsize,mtime,expire) ){
	*/
	if( cache_reload(Conn,ocpath,cachefp,*isdirp,fsize,mtime,expire) ){
		fclose(cachefp);
		return NULL;
	}
	return cachefp;
}
FILE *fopen_ftpcache(Connection *Conn,int expire,PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cpath),int *isdirp)
{	FileSize size;
	int mtime;
	FILE *cfp;

	*isdirp = 0;
	cfp = fopen_ftpcache0(Conn,expire,host,port,path,ext,BVStr(cpath),isdirp,
		&size,&mtime);
	if( *isdirp < 0 )
		*isdirp = 0;
	return cfp;
}

int putMovedToDir(Connection *Conn,FILE *tc)
{	int totalc;
	CStr(url,1024);
	refQStr(qp,url);

	HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
	if( qp = strchr(url,'?') ){
		if( qp[-1] != '/' ){
			/* dir?qery -> dir/?query */
			Strins(AVStr(qp),"/");
			totalc = putMovedTo(Conn,tc,url);
			return totalc;
		}
		return 0;
	}
	if( strtailchr(url) != '/' ){
		strcat(url,"/");
		totalc = putMovedTo(Conn,tc,url);
		return totalc;
	}
	return 0;
}

void waitFT_FLX(Connection *Conn,FILE *tcx,FILE *tc,int leng,FL_PAR);
int dir_copy(Connection *Conn,FILE *src,FILE *dst,FILE *cachefp,PCStr(user),PCStr(host),int port,PCStr(path),int form,int ctime);

FileSize httpftp_cached(Connection *Conn,FILE *tc,PCStr(user),PCStr(pass),PCStr(host),int port,PCStr(path),int *stcodep)
{	CStr(cpath,1024);
	FILE *cachefp;
	FILE *tc0;
	int expire,isdir,mtime;
	FileSize fsize;
	FileSize totalc;

	STRIPPATH(path);

	SetStartTime();

	if( !is_anonymous(user) )
		return 0;
	IsAnonymous = 1;

	expire = http_EXPIRE(Conn,host);
	cachefp = fopen_ftpcache(Conn,expire,host,port,path,"",AVStr(cpath),&isdir);
	if( cachefp == NULL )
		return 0;

	if( reqPARTIAL ){
		/* should use ident_copy() */
	}

	tc0 = tc;
	if( !HTTP_relayThru(Conn) && fileMaybeText(path) )
		tc = openHttpResponseFilter(Conn,tc0);

	if( isdir ){
		if( totalc = putMovedToDir(Conn,tc) ){
			*stcodep = 302;
		}else{
		putHttpHeader1(Conn,tc,DGserv(),"text/html",NULL,0,0);
		mtime = file_mtime(fileno(cachefp));
		totalc = dir_copy(Conn,cachefp,tc,NULL,user,host,port,path,FORM_HTML,mtime);
		}
	}else{
		fsize = file_sizeX(fileno(cachefp));
		totalc = ident_copy(Conn,cachefp,tc,NULL,DGserv(),path,fsize,0);

if( HTTP_ftpXferlog )
gwputXferlog(Conn,user,pass,path,(int)GetStartTime(),1,totalc);
	}
	fclose(cachefp);

	if( tc != tc0 ){
		waitFT_FLX(Conn,tc,tc0,1,FL_ARG);
		fclose(tc);
		wait(0);
	}
	sv1log("FTP/HTTP from cache [%lld bytes] %s\n",totalc,cpath);
	return totalc;
}

static void dumpfiles(){
	int fd;
	fprintf(stderr,"#### FILES #### ");
	for( fd = 0; fd < 128; fd++ ){
		if( 0 < file_ISSOCK(fd) )
			fprintf(stderr,"S:%d,",fd);
		else
		if( file_isreg(fd) )
			fprintf(stderr,"R:%d,",fd);
		else
		if( file_is(fd) )
			fprintf(stderr,"?:%d,",fd);
	}
	fprintf(stderr,"\n");
}

static int authDBG = 0;
#define AUTHDBG	authDBG==0?0:fprintf

FileSize file_copyTimeout(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout);
int waitFilterThread(Connection *Conn,int timeout,int which);

static int isStatOnly(Connection *Conn,PCStr(path),PCStr(resp)){
	sv1log("FtpStat %d {%s}\n",atoi(resp),path);
	switch( atoi(resp) ){
		case 150:
			return 0;
			break;

		/* maybe should return true for all of non-150 resp.
		 * at least isinFTPxHTTP()
		 */
		case 501: /* bad arg. */
		case 550:
		case 503:
		case 350:
		case 257:
		case 250:
		case 213:
			return 1;
			break;
	}
	return 0;
}
static void putStatResp(FILE *tc,PCStr(xcmd),PCStr(resp)){
	FileSize ival = -9;
	IStr(sval,128);
	IStr(buff,128);
	IStr(stat,128);
	IStr(head,128);

	if( strcaseeq(xcmd,"SIZE") ){
		Xsscanf(resp,"%*d %lld",&ival);
		if( ival < 0 ){
		}else
		fprintf(tc,"Content-Length: %lld\r\n",ival);
	}else 
	if( strcaseeq(xcmd,"MDTM") ){
		Xsscanf(resp,"%*d %s",AVStr(buff));
		ival = scanYmdHMS_GMT(buff);
		if( ival == 0 || ival == -1 ){
		}else{
		StrftimeGMT(AVStr(sval),sizeof(sval),TIMEFORM_RFC822,ival,0);
		fprintf(tc,"Last-Modified: %s\r\n",sval);
		}
	}
	Xsscanf(resp,"%*d%*c%[^\r\n]",AVStr(stat));
	sprintf(head,"X-FTPxHTTP-Status: %d %s",atoi(resp),stat);
	sv1log("%s\n",head);
	fprintf(tc,"%s\r\n",head);
}

int scanFTPxHTTP(Connection *Conn,PCStr(cmdopt),PVStr(xcmd),PVStr(xopt),PVStr(xctype));
static FileSize relayFTPxHTTP(Connection *Conn,FILE *tc,PCStr(path),int isdir,FILE *svdata,PCStr(resp),int *stcodep){
	FileSize totalc = -1;
	IStr(xcmd,128);
	IStr(xopt,128);
	IStr(xctype,128);
	const char *qp;
	const char *hver = "1.0";
	IStr(KA,128);

	if( (RequestFlags & QF_FTPXHTTP) == 0 ){
		return totalc;
	}

	if( isStatOnly(Conn,path,resp) ){
		/* file status only, without data */
		goto RELAY_RESP;
	}else
	if( (RequestFlags & QF_FTP_COMRETR)
	 && (RequestFlags & QF_FTP_COMLIST)
	){
		goto RELAY_RESP;
	}else
	if( isdir && (totalc = putMovedToDir(Conn,tc)) ){
		*stcodep = 302;
	}else
	if( isdir != 0 && (RequestFlags & QF_FTP_COMRETR)
	 || isdir == 0 && (RequestFlags & QF_FTP_COMLIST)
	){
		fprintf(tc,"HTTP/1.0 404\r\n");
		fprintf(tc,"Content-Length: 0\r\n");
		fprintf(tc,"\r\n");
		totalc = 0;
	}else
	if( isdir ){
		goto RELAY_RESP;
	}
	return totalc;

RELAY_RESP:
	strcpy(xctype,"text/x-ftpx");
	if( qp = strchr(path,'?') ){
		scanFTPxHTTP(Conn,qp+1,AVStr(xcmd),AVStr(xopt),AVStr(xctype));
	}
	if( *resp == '1' || *resp == '2' ){
		fprintf(tc,"HTTP/%s 200\r\n",hver);
		/* should have Last-Modified to be cached */
	}else{
		fprintf(tc,"HTTP/%s 404\r\n",hver);
	}
	if( !RespWithBody ){
		if( getKeepAlive(Conn,AVStr(KA)) ){
			fprintf(tc,"%s",KA);
		}
	}
	fprintf(tc,"Content-Type: %s\r\n",xctype);
	if( isStatOnly(Conn,path,resp) ){
		putStatResp(tc,xcmd,resp);
	}
	fprintf(tc,"\r\n");
	if( RespWithBody ){
		totalc = copyfile1(svdata,tc);
	}else{
		totalc = 0;
	}
	return totalc;
}

FileSize httpftp(Connection *Conn,FILE *fc,FILE *tc,PCStr(ver),PCStr(method),int svsock,PCStr(auth),PCStr(uuser),PCStr(upass),PCStr(host),int port,int gtype,PCStr(path),int *stcodep)
{	FILE *tc0,*fsc,*svdata;
	int server = -1;
	CStr(req,1024);
	CStr(authinfo,1024);
	CStr(auser,256);
	CStr(apass,256);
	CStr(dpass,256);
	int uuser_anon,auser_anon;
	defQStr(cuser); /*alt*/
	const char *ruser;
	const char *rpass;
	CStr(xpath,1024);
	CStr(resp,4096);
	CStr(buff,1024);
	FileSize totalc = 0;
	int isdir;
	int put;
	int docache;
	CStr(cachepath,1024);
	CStr(xcachepath,1024);
	FILE *cachefp;
	int gotok;
	int gotOrigData = 0;

	STRIPPATH(path);

	sprintf(req,"%s ftp://%s:%d/%s HTTP/%s",method,host,port,path,ver);
	sv1log("FTP/HTTP: %s\n",req);
	put = strcaseeq(method,"PUT");

	tc0 = tc;
	if( isinFTPxHTTP(Conn) && !RespWithBody ){
		/* 9.9.8 suppress needless filter for HEAD.
		 * (the Location: header might need rewritten by the filter...)
		 */
	}else
	if( !HTTP_relayThru(Conn) && fileMaybeText(path) )
	{
		if( lSINGLEP() ){ /* 9.9.5 if NBIO */
			/* HTTP (HttpResponseFilter) cannot be with NBIO */
			setNonblockingIO(fileno(tc0),0);
		}
		tc = openHttpResponseFilter(Conn,tc0);
	}

	docache = get_ftpcache(Conn,uuser,host,port,path,"",AVStr(cachepath));
	cachefp = NULL;
	gotok = 0;

	auser[0] = apass[0] = 0;
	Xsscanf(auth,"%[^:]:%[^\r\n]",AVStr(auser),AVStr(apass));
	uuser_anon = is_anonymous(uuser);
	auser_anon = is_anonymous(auser);
	FTPHTTP_genPass(AVStr(dpass));

	/*
	 * uuser : upass  -- user & pass in request URL (or in SERVER parameter)
	 * auser : apass  -- user & pass in request HTTP Authorization header
	 *         dpass  -- ADMIN's e-mail address
	 *
	 * With AUTH=anonftp, user's e-mail address is sent as USER name (auser)
	 * if AUTH=anonftp, auser is checked to be a valid e-mail address, and
	 *  (1)	anonymous  + upass  -- use password in URL if exists (*A)
	 *  (2) anonymous  + apass  -- only if auser==anonymous
	 *  (3)	anonymous  + auser  -- use password in Authorization
	 *  (4)	anonymous  + dpass  -- use ADMIN if no password is given
	 * else
	 * if uuser is anonymous
	 *  (1)	anonuymous + upass  -- (*A)
	 *  (2)	anonuymous + apass  -- only if auser==anonymous (*B)
	 *  (3)	anonuymous + dpass
	 * else
	 *  (1)	auser      + apass  -- auser can be anonymous or anything
	 *  (2)	uuser      + upass
	 *
	 * (*A) uuser:upass in URL is given top priority because it can be
	 *      explisitly controled by user than auser:apass in Authorization
	 * (*B) to avoid leak of password for non-anonymous user which may
	 *      be sent from client when switched from non-anonymous account
	 *
	 */

	AUTHDBG(stderr,"## AUTH [%s]:[%s] URL[%s]:[%s] WAA=%d\n",
	auser,apass,uuser,upass,CTX_with_auth_anonftp(Conn));

	if( uuser_anon &&  CTX_with_auth_anonftp(Conn) /* AUTH=anonftp */ ){
		if( !auser_anon )
			setQStr(cuser,auser,sizeof(auser));
		else	setQStr(cuser,apass,sizeof(apass)); /* if no passwd check in AUTH=anonftp */

		if( !NoAuth )
		if( CTX_checkAnonftpAuth(Conn,AVStr(cuser),apass) != 0 ){
FILE*tmp;
const char *mssg;
int size;
tmp = TMPFILE("FTP/anonftpAuth");
putBuiltinHTML(Conn,tmp,"FTP/anonftpAuth","file/ftpgw-anonauth.dhtml",
NULL,(iFUNCP)printItem,NULL);
fflush(tmp); size = ftell(tmp); fseek(tmp,0,0);
mssg = (char*)malloc(size+1);
IGNRETP fread((char*)mssg,1,size,tmp); /**/
((char*)mssg)[size] = 0;
fclose(tmp);
/*
totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,mssg);
*/
totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,"anonftp",mssg);
*stcodep = 401;
free((char*)mssg);
			AUTHDBG(stderr,"## AUTH [%s]:[%s] ERROR\n",cuser,apass);
			goto EXIT;
		}
		AUTHDBG(stderr,"## AUTH [%s]:[%s] OK\n",cuser,apass);

		ruser = uuser;
		if( *upass )
			rpass = upass;
		else
		if( *auser && !auser_anon )
			rpass = auser;
		else
		if( *apass && auser_anon )
			rpass = apass;
		else	rpass = dpass;
	}else{
		if( uuser_anon ){
			ruser = uuser;
			if( *upass )
				rpass = upass;
			else
			if( auser_anon && apass[0] )
				rpass = apass;
			else	rpass = dpass;
		}else{
			if( *auser && !streq(auser,uuser) )
				ruser = auser;
			else	ruser = uuser;
			if( *apass )
				rpass = apass;
			else	rpass = upass;
		}
	}
	AUTHDBG(stderr,"## LOGIN[%s]:[%s]\n",ruser,rpass);

	sv1log("authorization user[%s] pass[%s]\n",
		ruser,is_anonymous(ruser)?rpass:"********");

	if( unescape_path(path,AVStr(xpath)) )
		path = xpath;

	if( svsock != -1 )
		server = dup(svsock);
	else
	if( strcaseeq(REAL_PROTO,"sftp") ){
		server = connectToSftpX(Conn,DST_HOST,DST_PORT,ruser,fileno(tc));
	}else
	if( (server = connect_to_serv(Conn, FromC,ToC,0)) < 0 ){
		sv1log("FTP/HTTP: cannot connect to the server\n");
		totalc = putHttpCantConnmsg(Conn,tc,DST_PROTO,DST_HOST,DST_PORT,
			req);
		*stcodep = 502;
		goto EXIT;
	}
	sv1log("FTP/HTTP: server opened [%d]\n",server);

	if( Conn->xf_filters & XF_FFROMSV ){
		fsc = fdopen(FromS,"r");
	}else
	fsc = fdopen(server,"r");

	if( reqPARTIAL ){
		docache  = 0;
		gotPART_FROM = -1;
	}
	if( isinFTPxHTTP(Conn) ){
		if( strcaseeq(method,"POST") ){
			put = 2;
		}
	}
	svdata = ftp_fopen(Conn,put,server,host,ruser,rpass,path,AVStr(resp),sizeof(resp),&isdir,fsc);

	/*
	if( svdata != NULL && file_isreg(fileno(svdata)) ){
	*/
	if( svdata != NULL ){
	    if( file_isreg(fileno(svdata)) ){
		/* verified cache file is returned */
		docache = 0;
	    }else{
		gotOrigData = 1;
	    }
	}

	if( svdata == NULL ){
		sv1log("FTP/HTTP: negotiation with the server failed\r\n");
		if( resp[0] == 0 || atoi(resp) == 421 ){
			/* 9.9.7 too many connections or so */
			putHttpNotAvailable(Conn,tc,resp);
			*stcodep = 503;
		}else
		if( atoi(resp) == 530 ){
			putErrorHead(Conn,tc,VNO,req,host,ruser,resp,stcodep);
		}else
		if( put ){
			CStr(req,1024);
			sprintf(req,"PUT ftp://%s:%d/%s\r\n",host,port,path);
			putHttpRejectmsg(Conn,tc,"ftp",host,port,AVStr(req));
			*stcodep = 401;
		}else{
			if( HTTP_setRetry(Conn,req,404) ){
				sv1log("setRetry: %s\n",req);
				*stcodep = 404;
				goto EXIT_0;
			}
			if( isinFTPxHTTP(Conn) ){
				/* 550 maybe RETR for dir. or CWD for file */
			}else
			delayUnknown(Conn,1,req);
			putHttpNotFound(Conn,tc,resp);
			*stcodep = 404;
		}
		if( !RespWithBody ){
		}else{
			/* 9.9.8 this extra message breaks keep-alive
			 * maybe originally this was just for 530 error header.
			 */
			HTTP_clntClose(Conn,"FTP/HTTP-extra-error-mssg");
		fprintf(tc,"<TITLE> FTP/HTTP error </TITLE>\n");
		fprintf(tc,"<P>\n");
		fprintf(tc,"<B>FTP/HTTP error</B>:<BR>\n");
		fprintf(tc,"USER:[%s]<BR>\n",ruser);
		fprintf(tc,"PASS:[%s]<BR>\n",is_anonymous(ruser)?rpass:"******");
		fprintf(tc,"Message from %s follows:<BR>\n",host);
		fprintf(tc,"<MENU><PRE>%s</PRE></MENU>\n",resp);
		putFrogVer(Conn,tc);
		}
	}else{
	    if( put ){
		CStr(cLeng,1024);
		const char *buff;
		FileSize Length;
		int rcc;

		HTTP_getRequestField(Conn,"Content-Length",AVStr(cLeng),sizeof(cLeng));
		Xsscanf(cLeng,"%lld",&Length);
		totalc = file_copyTimeout(fc,svdata,NULL,Length,NULL,10);
		putHttpHeader1(Conn,tc,DGserv(),"text/html",NULL,0,0);
		sv1log("FTP/HTTP DONE: PUT %lld / %lld bytes\n",totalc,Length);
	    }else{
		FileSize size = 0;

		if( docache )
			cachefp = cache_make("FTP/HTTP",cachepath,AVStr(xcachepath));

		totalc = relayFTPxHTTP(Conn,tc,path,isdir,svdata,resp,stcodep);
		if( 0 <= totalc ){
		}else
		if( isdir ){
			if( totalc = putMovedToDir(Conn,tc) ){
				*stcodep = 302;

				/* 9.9.7 to get the list into the cache */
				totalc = dir_copy(Conn,svdata,WRNULLFP(),cachefp,
					ruser,host,port,path,FORM_HTML,0);
			}else{
			putHttpHeader1(Conn,tc,DGserv(),"text/html",NULL,0,0);
			totalc = dir_copy(Conn,svdata,tc,cachefp,ruser,host,port,path,FORM_HTML,0);
			}
		}else{
			if( 0 < Conn->sv.p_range[2] ){
				size = Conn->sv.p_range[2];
			}else
			size = FTP_datasize(resp);
			totalc = ident_copy(Conn,svdata,tc,cachefp,DGserv(),path,size,0);

if( HTTP_ftpXferlog )
gwputXferlog(Conn,ruser,rpass,path,(int)GetStartTime(),0,totalc);
		}
		gotok = isdir || !isdir && (size == totalc);
		sv1log("FTP/HTTP DONE: GOT %lld / %lld bytes\n",totalc,size);
	    }

	   /* fclose() on Win32 does not disconnect with WU-ftpd-2.6.1...
	    * so try disconnect it by direct close() 
	    */
	    {	int svdatafd,rcode;
		svdatafd = fileno(svdata);

	    fclose(svdata);

#ifndef WIN32_FCLOSE_TEST
		/* Close(fileno(fp)) even after fclose(fp) is effective for
		 * disconnection, although it returns -1 with errno=EBADF.
		 * It seems to implies fclose(fp) does incomplete closing...
		 */
		rcode = close(svdatafd);
		Verbose("## confirm data-conn close(%d)=%d\n",svdatafd,rcode);
#else
		if( IsConnected(svdatafd,NULL) ){
		/* this part seems not to be executed maybe because
		 * getpeername() in IsConnected() make the connection close.
		 */
			rcode = close(svdatafd);
			sv1log("## retry data-conn close(%d)=%d\n",svdatafd,rcode);
		}
#endif
	    }
	}
EXIT_0:

/* wait 226 (Transfer Complete) before sending QUIT */
	if( isStatOnly(Conn,path,resp) ){
		sv1log("FTPGW without data: %d\n",atoi(resp));
	}else
	/* the following should be applied only with status code 150 */
if( !feof(fsc) ){
  double St = Time();
 if( gotOrigData ){
  int rdy;
  rdy = fPollIn(fsc,300);
  strcpy(buff,"\n");
  fgetsTIMEOUT(AVStr(buff),sizeof(buff),fsc);
  sv1log("FTPGW %.2f%s(%d) %s",Time()-St,feof(fsc)?"EOF":"",rdy,buff);
 }else{
	/* No 226 response will be: hit the cache, or got an error */
 }
  if( !feof(fsc) && atoi(buff) != 221 ){
	IGNRETP write(server,"QUIT\r\n",6);
	while( fgetsTIMEOUT(AVStr(buff),sizeof(buff),fsc) != NULL)
	  sv1log("FTPGW %.2f%s %s",Time()-St,feof(fsc)?"EOF":"",buff);
/*
		if( strncmp(buff,"221",3) == 0 )
			break;
*/
;
  }
}
	fclose(fsc);
	wait_FSERVER(Conn);

EXIT:
	if( tc != tc0 ){
		waitFT_FLX(Conn,tc,tc0,1,FL_ARG);
		fclose(tc);
		wait(0);
	}
	if( docache && cachefp != NULL ){
		if( isdir )
			ftpc_dirext(AVStr(cachepath));
		fflush(cachefp);
		cache_done(gotok,cachefp,cachepath,xcachepath);
	}
	if( Conn->xf_filters & XF_SERVER ){
		Verbose("--ftpgw ToSX[%d] SF=%X FF=%X\n",
			ToSX,ServerFlags,Conn->xf_filters);
		if( 0 <= ToSX ){
			/* saved for ServSock() */
			close(ToSX);
			ToSX = -1;
		}
		waitFilterThread(Conn,100,XF_FSV);
	}
	return totalc;
}

extern int SFTP_WITH_SEEK;
int connectToSftp(PCStr(host),int port,PCStr(user),int fdc,int fdv[]);
int connectToSftpXX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC,int fromC);
int connectToSftpX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC){
	return connectToSftpXX(Conn,host,port,user,toC,-1);
}
int connectToSftpXX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC,int fromC){
	int sock;
	int fdc;
	int fdv[2];

	if( MountOptions ){
		if( isinList(MountOptions,"noseek") )
			SFTP_WITH_SEEK = 0;
	}

	fdc = 0;
	fdv[fdc++] = ClientSock;
	if( ToC != ClientSock )
		fdv[fdc++] = ToC;
	if( FromC != ClientSock && FromC != ToC )
		fdv[fdc++] = FromC;
	if( toC != ClientSock && toC != ToC && toC != FromC )
		fdv[fdc++] = toC;
	if( 0 <= fromC )
	if( fromC!=ClientSock && fromC!=ToC && fromC!=FromC && fromC!=toC )
		fdv[fdc++] = fromC;

	sock = connectToSftp(host,port,user,fdc,fdv);
	ToS = FromS = sock;
	return sock;
}

#endif /* !MAIN */


extern int CACHE_TAKEOVER;
FileSize CTX_file_copyTimeout(Connection *XConn,FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout);
FileSize file_copyTimeout(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout)
{
	return CTX_file_copyTimeout(0,src,dst,cache,bytes,binary,timeout);
}
static int writes(int dst,PCStr(buff),int occ,FileSize off){
	int wcc = 0;
	int o1,w1;
	int retrying = 0;
	int serrno;
	int oready;
	double St;

	for( wcc = 0; wcc < occ; wcc += w1 ){
		o1 = occ - wcc;
		w1 = write(dst,buff+wcc,o1);
		serrno = errno;
		if( w1 <= 0 || retrying ){
			sv1log("##writes[%d] %d/%d/%d errno=%d *%d %lld\n",
				dst,w1,o1,occ,serrno,retrying,off);
		}
		if( w1 <= 0 ){
			if( serrno == EAGAIN ){
				if( 10 < ++retrying ){
					break;
				}
				St = Time();
				oready = PollOut(dst,1000);
				sv1log("##writes[%d] pollout=%d (%.2f)\n",
					dst,oready,Time()-St);
				w1 = 0;
				continue;
			}
			break;
		}
	}
	return wcc;
}
FileSize CTX_file_copyTimeout(Connection *XConn,FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout)
{	FileSize rbytes;
	FileSize totalc;
	int rcc;
	int ci,bin;
	CStr(buff,1024*8);
	int bsize;
	int start = time(0);

	if( file_isreg(fileno(src)) )
		bsize = sizeof(buff);
	else	bsize = 2048;

	if( bytes == 0 )
	{
		/*
		rbytes = 0x7FFFFFFF;
		*/
		rbytes = 1;
		rbytes = -1 ^ (rbytes << (sizeof(rbytes)*8-1));
	}
	else	rbytes = bytes;
	totalc = 0;
	bin = 0;

	if( lSINGLEP() && !isWindowsCE() ){ /* if NBIO */
		fflush(dst); /* 9.9.5 */
	}
	while( 0 < rbytes ){
		if( feof(src) )
			break;
		if( fPollIn(src,timeout*1000) <= 0 ){
			sv1log("file_copy: timeout %d seconds\n",timeout);
			break;
		}

		if( bsize < rbytes )
			rcc = bsize;
		else	rcc = rbytes;

/*
		if( 0 < ready_cc(src) ){
			rcc = fgetBuffered(AVStr(buff),rcc,src);
			if( rcc <= 0 ){
				break;
			}
		}else
*/
		if( 0 < timeout && 0 < READYCC(src) ){
			/* not to block in freadTIMEOUT() with IO_TIMEOUT */
			rcc = fgetBuffered(AVStr(buff),rcc,src);
		}else
		if( (rcc = freadTIMEOUT(AVStr(buff),1,rcc,src)) == 0 )
			break;
		if( rcc < 0 ){
			sv1log("file_copy: read=%d errno=%d\n",rcc,errno);
			break;
		}
		if( XConn ){
			EmiUpdateMD5(XConn,buff,rcc);
		}
		if( lSINGLEP() && !isWindowsCE() ){ /* 9.9.5 if NBIO */
			if( writes(fileno(dst),buff,rcc,ftell(src)) < rcc ){
				break;
			}
		}else
		if( fwrite(buff,1,rcc,dst) == 0 )
			break;
		/* should wait CACHE_TAKEOVER ... */

		if( ferror(dst) && cache == NULL ){
			sv1log("file_copy: client disconnected & no-cache\n");
			break;
		}
		if( ferror(dst) && cache != NULL )
		if( CACHE_TAKEOVER < time(0)-start ){
			sv1log("file_copy: client disconnected\n");
			break;
		}

		if( cache != NULL )
			fwrite(buff,1,rcc,cache);

		if( bin == 0 )
		for( ci = 0; ci < rcc; ci++ )
			if( buff[ci] & 0x80 ){
				bin = 1;
				break;
			}
			else
			if( buff[ci] == 0 ){
				bin = 1;
				break;
			}

		totalc += rcc;
		rbytes -= rcc;
	}
	if( binary )
		*binary = bin;
	return totalc;
}
FileSize CTX_file_copy(Connection *Conn,FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary)
{
	return CTX_file_copyTimeout(Conn,src,dst,cache,bytes,binary,0);
}
FileSize file_copy(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary)
{
	return file_copyTimeout(src,dst,cache,bytes,binary,0);
}

void ls_form(Connection *Conn,PCStr(line),PVStr(dirent),PCStr(host),int port,PCStr(dir),int form);
int dir_copy(Connection *Conn,FILE *src,FILE *dst,FILE *cachefp,PCStr(user),PCStr(host),int port,PCStr(path),int form,int ctime)
{	int lines,totalc;
	CStr(line,1024);
	CStr(dirent,1024);
	FtpEnv env;
	int start = time(0);

	totalc = 0;

	if( form == FORM_GOPHER ){
		fprintf(dst," Content of FTP Directory: HOST[%s] DIR[%s]\n\n",
			host,path);
	}
	if( form == FORM_HTML ){
		env.isdir = 1;
		env.user = user;
		env.host = host;
		env.port = port;
		env.path = path;
putBuiltinHTML(Conn,dst,"FTP/header","file/ftpgw-header.dhtml",NULL,
(iFUNCP)printItem,&env);
	}

/* skip "total" line
fgetsTIMEOUT(line,sizeof(line),src);
*/
	for( lines = 0; fgetsTIMEOUT(AVStr(line),sizeof(line),src) != NULL; )
	{
		if( cachefp != NULL )
			fputs(line,cachefp);

		if( lines == 0 && strncasecmp(line,"total",5) == 0 )
			continue;

		ls_form(Conn,line,AVStr(dirent),host,port,path,form);
		fputs(dirent,dst);
		fflush(dst);

		if( ferror(dst) && cachefp == NULL ){
			sv1log("dir_copy: client disconnected & no-cache\n");
			break;
		}
		if( ferror(dst) && cachefp != NULL )
		if( CACHE_TAKEOVER < time(0)-start ){
			sv1log("dir_copy: client disconnected\n");
			break;
		}

		totalc += strlen(dirent);
		lines++;
	}

	env.dir_lines = lines;
	env.proc_secs = Time() - GetStartTime();
	env.cache_date = ctime;
	if( form == FORM_HTML ){
putBuiltinHTML(Conn,dst,"FTP/tailer","file/ftpgw-tailer.dhtml",NULL,
(iFUNCP)printItem,&env);
putFrogForDeleGate(Conn,dst,"");
	}

	return totalc;
}


/*
 *	support only UNIX type "ls -lL" output
 */
static int isMSDOSDIR(PCStr(line),int *isdir)
{
	if( isdigit2(&line[0]) && line[2] == '-' )
	if( isdigit2(&line[3]) && line[5] == '-' ){
		if( isdir ) *isdir = (strstr(line,"<DIR>") != NULL);
		return 1;
	}
	return 0;
}
char *scan_ls_l(PCStr(lsl),xPVStr(mode),int *linkp,PVStr(owner),PVStr(group),FileSize *sizep,PVStr(date),PVStr(name),PVStr(sname))
{	const char *slp;
	const char *dp;
	const char *np;
	const char *nnp;
	CStr(modeb,128);
	CStr(tmp,256);
	CStr(links,256);
	CStr(field4,128);
	int len,nlink;

	setVStrEnd(date,0);
	if( sname )
		setVStrEnd(sname,0);
	if( mode == NULL )
		setPStr(mode,modeb,sizeof(modeb));

	if( dp = strpbrk(lsl,"\r\n") )
		truncVStr(dp);

	if( isMSDOSDIR(lsl,NULL) ){
		CStr(time,32);
		CStr(typesize,32);

		if( linkp ) *linkp = 0;
		if( owner ) setVStrEnd(owner,0);
		if( group ) setVStrEnd(group,0);
		setVStrEnd(name,0);
		setVStrEnd(sname,0);

		Xsscanf(lsl,"%s %s %s %s",AVStr(date),AVStr(time),AVStr(typesize),AVStr(name));
		strcat(date," ");
		strcat(date,time);

		if( strcasecmp(typesize,"<DIR>") == 0 ){
			strcpy(mode,"d");
			if( sizep ) *sizep = 0;
		}else{
			strcpy(mode,"-");
			if( sizep ) Xsscanf(typesize,"%lld",sizep);
		}
		return (char*)name;
	}

	/* np = wordscanX(np,mode,128); */
	np = lsl;
	Xsscanf(np,"%[^ \t\r\n0-9]",AVStr(mode));
	np += strlen(mode);
	np = wordScan(np,tmp);

	strcpy(links,tmp);
	if( len = strlen(links) ){
		if( links[len-1] == 'L' )
			setVStrEnd(links,len-1);
	}

	if( !isdigits(links) )
	{
		if( linkp ) *linkp = 0;
		if( owner ) strcpy(owner,tmp);
		np = wordScan(np,tmp);
		if( sizep ) Xsscanf(tmp,"%lld",sizep);
		nnp = scanLsDate(np,AVStr(date));
		if( nnp == NULL ){
			strcpy(name,"?");
			return NULL;
		}
		np = nnp;
	}else{
		if( linkp ) *linkp = atoi(links);
		if( owner )
			np = wordscanX(np,AVStr(owner),128);
		else	np = wordScan(np,tmp);
		np = wordScan(np,field4);

		if( isdigits(field4) && (nnp = scanLsDate(np,AVStr(date))) != NULL ){
			np = nnp;
			if( group ) setVStrEnd(group,0);
			if( sizep ) Xsscanf(field4,"%lld",sizep);
		}else{
			if( group ) strcpy(group,field4);
			np = wordScan(np,tmp);
			if( sizep ) Xsscanf(tmp,"%lld",sizep);
			np = scanLsDate(np,AVStr(date));

			if( !isdigits(tmp) || np == NULL ){
				strcpy(name,"?");
				return NULL;
			}
		}
	}
	while( *np == ' ' )
		np++;
	strcpy(name,np);

	if( *mode == 'l' ){
		setVStrElem(mode,0,'-');
		if( slp = strstr(name," -> ") ){
			truncVStr(slp);
			slp += 4;
			if( sname )
				strcpy(sname,slp);
			if( (dp = strrchr(slp,'/')) && dp[1]==0 )
				setVStrElem(mode,0,'d');
		}
	}
	return (char*)name;
}

void ls_form(Connection *Conn,PCStr(line),PVStr(dirent),PCStr(host),int port,PCStr(dir),int form)
{	int gtype,isdir;
	const char *dp;
	CStr(name,1024);
	const char *dispname;
	CStr(dnameb,1024);
	FileSize size;
	CStr(path,1024);
	CStr(xselector,1024);
	CStr(url,1024);
	CStr(durl,1024);
	const char *proto;
	CStr(hostport,128);
	CStr(image,1024);
	const char *icon;
	const char *ialt;
	CStr(iconbase,256);

	if( *line == '-' ){
		gtype = 0;
		strcpy(name,line);
		if( dp = strpbrk(name,"\r\n") )
			truncVStr(dp);
		if((dp = strrchr(name,'~')) && dp[1] == 0 )
			truncVStr(dp);
		if( dp = strrchr(name,' ') )
			gtype = filename2gtype(dp+1);
		else	gtype = filename2gtype(name);
	}else
	switch( *line ){
		case 'l': gtype = '1'; break; /* X-< */
		case 'd': gtype = '1'; break;
		case 's': gtype = '-'; break;
		default:
			if( !isMSDOSDIR(line,&isdir) ){
				strcpy(dirent,line);
				return;
			}
			if( isdir )
				gtype = '1';
			else	gtype = '-';
	}

	if( dp = strrchr(line,' ') ){
		CStr(mode,128);
		CStr(date,128);
		CStr(sname,1024);
		scan_ls_l(line,AVStr(mode),NULL,VStrNULL,VStrNULL,&size,AVStr(date),AVStr(name),AVStr(sname));
		if( *sname ){
			if( *mode == 'd' )
				gtype = '1';
			else	gtype = '-';
		}
		if( gtype == '1' )
			strcat(name,"/");
		sprintf(dnameb,"%10lld %s",size,date);
		dispname = dnameb;
	}else{
		dispname = "?";
		strcpy(name,"?");
	}

	if( DONT_REWRITE ){
		const char *lastdir;
		/*
		if( strtailchr(dir) != '/' ){
		*/
		if( dir[0] != 0 && strtailchr(dir) != '/' ){
			if( lastdir = strrchr(dir,'/') )
				lastdir++;
			else	lastdir = dir;
			sprintf(path,"%s/%s",lastdir,name);
		}else	strcpy(path,name);
	}else{
		if( dir[0] == 0 || name[0] == '/' )
			strcpy(path,name);
		else
		if( strtailchr(dir) != '/' )
			sprintf(path,"%s/%s",dir,name);
		else	sprintf(path,"%s%s",dir,name);
	}

	/* reduce ./ and ../ */{
		const char *cdir; /* not "const" but fixed */
		const char *pdir;
		const char *ppdir;

		while( cdir = strstr(path,"/./") )
			ovstrcpy((char*)cdir,cdir+2);

		while( pdir = strstr(path,"/../") ){
			if( pdir == path )
				ppdir = path;
			else
			for( ppdir = pdir-1; path < ppdir; ppdir-- )
				if( *ppdir == '/' )
					break;
			ovstrcpy((char*)ppdir,pdir+3);
		}
	}

	if( strcaseeq(REAL_PROTO,"sftp") ){
		proto = "sftp";
	}else
	proto = "ftp";
	HostPort(AVStr(hostport),proto,host,port);

	if( form == FORM_GOPHER ){
		CStr(myhost,128);
		int myport;

		myport = ClientIF_H(Conn,AVStr(myhost));
		sprintf(xselector,"%s=@=ftp:%s=%c",path,hostport,gtype);
		sprintf(dirent,"%c%s\t%s\t%s\t%d\n",
			gtype,dispname,xselector,myhost,myport);
	}else
	if( form == FORM_HTML ){
		nonxalpha_escapeX(path,AVStr(path),sizeof(path));

		if( DONT_REWRITE )
			strcpy(durl,path);
		else{
			if( path[0] == '/' && path[1] == '/' ) 
				sprintf(url,"%s://%s%s",proto,hostport,path);
			else	sprintf(url,"%s://%s/%s",proto,hostport,path);
			redirect_url(Conn,url,AVStr(durl));
		}

		getCERNiconBase(Conn,AVStr(iconbase));
		if( gtype == '1' )
			icon = filename2icon("/", &ialt);
		else	icon = filename2icon(path,&ialt);

		sprintf(image,"ALT=\"[%s]\" ALIGN=TOP SRC=\"%s%s\"",
			ialt,iconbase,icon);

		sprintf(dirent,"%s <IMG %s> <A HREF=\"%s\"><B>%s</B></A>\n",
			dispname,image,durl,name);
	}
}
/*
maybe, HREF=file is enough except in case when the directory is refered
without trailing '/'.   such access should be redirected by `302 Moved'...
 */
