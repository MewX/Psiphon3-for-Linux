/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003-2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        dgauth.c
Author:         Yutaka Sato <ysato@delegate.org>
Description:
History:
        031115	extracted from delegated.c, access.c, ...
//////////////////////////////////////////////////////////////////////#*/
#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <sys/types.h>
#include <sys/stat.h>
#include "delegate.h"
#include "param.h"
#include "credhy.h"
#include "auth.h"
int serverPid();

extern const char *MAP_AUTHSERV;
char DGAUTHpro[] = "dgauth";
char DGAUTHdom[] = "-dgauth";
char DGAUTHadmdom[] = "-dgauth@admin";
const char *DGAuthDFLT_realm = "-";
int NONCE_TIMEOUT = 60;

static const char *DGAuthHost;
static int DGAuthPort;
static struct { MStr(e_nonceKey,64); } nonceKey;
#define nonceKey nonceKey.e_nonceKey
static int xgetpass(PCStr(passspec),PVStr(pass))
{	CStr(what,32);
	CStr(data,64);
	FILE *kfp;

	scan_field1(passspec,AVStr(what),sizeof(what),AVStr(data),sizeof(data));
	if( streq(what,"pass") ){
		strcpy(pass,data);
	}else
	if( streq(what,"file") ){
		if( kfp = fopen(data,"r") ){
			fgets(data,sizeof(data),kfp);
			fclose(kfp);
			linescanX(data,AVStr(pass),64);
		}else{
		}
	}else
	if( streq(what,"serv") ){
		DGAuthHost = "127.0.0.1";
		DGAuthPort = atoi(data);
	}else{
		return -1;
	}
	return 0;
}

/*
 * make the key reloadable on restart (by reboot, in an hour)
 * ignore it if something modified (DeleGate binary, the file, or the directory)
 */
/*
static void dumpCKeyKey(PCStr(path),PVStr(skey),int prev)
*/
static void dumpCKeyKeyX(PCStr(opts),PCStr(param),PCStr(path),PVStr(skey),int prev)
{	CStr(dir,1024);
	const char *dp;
	CStr(date,64);
	int now;
	CStr(cwd,1024);

	lineScan(path,dir);
	if( (dp = strrchr(dir,'/')) && dp != dir )
		truncVStr(dp);
	if( strchr(opts,'M') ){
		now = time(0) - prev*60;
		StrftimeLocal(AVStr(date),sizeof(date),"%y%m%d%H%M",now,0);
	}else{
	now = time(0) - prev*60*60;
	StrftimeLocal(AVStr(date),sizeof(date),"%y%m%d%H",now,0);
	}
	/*
	sprintf(skey,"%s.%x.%x",date,File_ctime(dir),(int)dumpCKeyKey);
	*/
	/*
	sprintf(skey,"%s.%x.%lx",date,0,dumpCKeyKey);
	*/
	if( streq(param,P_CRYPT) ){
	sprintf(skey,"%s.%x.%llx",date,0,p2llu(dumpCKeyKeyX));
	}else{
		IStr(xkey,1024);
		IStr(md5,64);
		sprintf(skey,"%s.%llx",date,p2llu(dumpCKeyKeyX));
		if( strchr(opts,'e') ){
			extern int environCRC;
			Xsprintf(TVStr(xkey),".%X",environCRC);
		}
		if( strchr(opts,'p') ){
			Xsprintf(TVStr(xkey),".%d",getppid());
		}
		if( strchr(opts,'t') ){
			Xsprintf(TVStr(xkey),".%d",file_ino(0));
		}
		if( strchr(opts,'w') ){
			CStr(cwd,1024);
			IGNRETS getcwd(cwd,sizeof(cwd));
			Xsprintf(TVStr(xkey),".%s",cwd);
		}
		if( xkey[0] ){
			toMD5(xkey,(char*)md5);
			Xsprintf(TVStr(skey),".%s",md5);
		}
	}
}
int getCKeySec(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int ksiz);
/*
void dumpCKeyPath(PVStr(path));
*/
void dumpCKeyX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),int force);
void dumpCKey(int force)
{
	dumpCKeyX("",P_CRYPT,"master","",force);
	dumpCKeyX("",P_PASSWD,"imp","",force);
	dumpCKeyX("",P_PASSWD,"ext","",force);
	dumpCKeyX("",P_PASSWD,"sudo","",force);
	dumpCKeyX("",P_PASSWD,"exec","",force);
}
void dumpCKeyPathX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),PVStr(path));
void dumpCKeyX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),int force)
{	CStr(path,256);
	CStr(ekey,256);
	CStr(cc,64);
	CStr(md5,64);
	CStr(skey,64);
	CStr(xpass,256);
	int elen,xlen;
	FILE *fp;

	if( force || getpid() == serverPid() )
	/*
	if( 0 < (elen = getCKey(AVStr(ekey),sizeof(ekey))) )
	*/
	if( 0 < (elen = getCKeySec(param,dom,user,AVStr(ekey),sizeof(ekey))) )
	{
		/*
		dumpCKeyPath(AVStr(path));
		*/
		dumpCKeyPathX(opts,param,dom,user,AVStr(path));
		if( !force /* not create_service() nor SIGHUP */
		 && File_is(path)
		 && File_mtime(path) == 1 /* set by set_utimes() bellow */
		){
			/* don't overwrite new data by old one on TERMINATE */
			daemonlog("E","#### KEY DONT OVERWRITE %s\n",path);
		}else
		if( fp = dirfopen("CKey",AVStr(path),"w") ){
			chmod(path,0600);
			/*
			dumpCKeyKey(path,AVStr(skey),0);
			*/
			dumpCKeyKeyX(opts,param,path,AVStr(skey),0);
			sprintf(cc,"%s.%s",skey,ekey);
			toMD5(cc,md5);
			xlen = aencrypty(skey,strlen(skey),ekey,elen,xpass);
			fprintf(fp,"%s %s\n",md5,xpass);
/*
fprintf(stderr,"#### DUMPED %s %d[%s %s] to %s\n",skey,elen,md5,xpass,path);
*/
			daemonlog("E","#### KEY %s=%s DUMPED %X TO %s\n",
				param,dom,strCRC32(skey,strlen(skey)),path);
			fclose(fp);
			set_utimes(path,-1,1);
		}
		else{ /* new-140514a */
			int strls_unix(PCStr(path),PVStr(ls),int size);
			IStr(ls,1024);

			strls_unix(path,AVStr(ls),sizeof(ls));
			daemonlog("F","#### FATAL: cannot save CRYPT: %s\n",path);
			sv1log("#### CRYPT file: %s\n",ls);
		}
		bzero(ekey,sizeof(ekey));
	}
}
/*
static int restoreCKey(PVStr(ekey),int esiz)
*/
int restoreCKeyX(PCStr(opts),PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int esiz)
{	CStr(path,256);
	CStr(key,256);
	CStr(cc,64);
	CStr(md5,64);
	CStr(epass,256);
	CStr(xmd5,64);
	ACStr(skeys,2,64);
	int si,elen;
	FILE *fp;

	/*
	dumpCKeyPath(AVStr(path));
	*/
	dumpCKeyPathX(opts,param,dom,user,AVStr(path));
	if( fp = fopen(path,"r") ){
		for( si = 0; si < 2; si++ )
			dumpCKeyKeyX(opts,param,path,EVStr(skeys[si]),si);
			/*
			dumpCKeyKey(path,EVStr(skeys[si]),si);
			*/
		key[0] = 0;
		fgets(key,sizeof(key),fp);
		fclose(fp);
		if( strchr(opts,'L') == 0 )
		unlink(path);

		md5[0] = epass[0] = 0;
		Xsscanf(key,"%s %s",AVStr(md5),AVStr(epass));

		for( si = 0; si < 2; si++ ){
			const char *skey; /**/
			skey = skeys[si];
			elen = adecrypty(skey,strlen(skey),epass,strlen(epass),
				(char*)ekey);
			sprintf(cc,"%s.%s",skey,ekey);
			toMD5(cc,xmd5);

/*
if( elen <= 0 )
fprintf(stderr,"#### RESTORED %s %d[%s %s]\n",skey,elen,md5,epass);
*/

			/*
			sv1log("#### KEY RESTORED FROM %s\n",path);
			*/
			daemonlog("E","#### KEY RESTORED %X FROM %s\n",
				strCRC32(skey,strlen(skey)),path);
			if( streq(md5,xmd5) ){
				return elen;
			}
		}
	}
	return 0;
}

/*
 * should be CRYPT=pass:word[:realm] ...
 */
void setCKey(PCStr(ekey),int elen);
void setCKeyP(PCStr(param),PCStr(dom),PCStr(user),PCStr(ekey),int elen);

void scan_CRYPTX(Connection *Conn,int clnt,PCStr(opts),PCStr(param),PCStr(dom),PCStr(user));
void scan_CRYPT(Connection *Conn,int clnt)
{
	scan_CRYPTX(Conn,clnt,"",P_CRYPT,"master","");
}

typedef struct {
	const char *fcp_param;
	const char *fcp_dom;
	const char *fcp_user;
	const char *fcp_spec;
} FcpArg;
static FcpArg fcp1;
static void fcp(Connection *Conn,PCStr(spec)){
	const char *sp;

	if( streq(fcp1.fcp_param,P_CRYPT) ){
		fcp1.fcp_spec = spec;
	}
	if( fcp1.fcp_dom && (sp = strheadstrX(spec,fcp1.fcp_dom,0)) ){
		if( strneq(sp,"::pass:",7) ){
			fcp1.fcp_spec = sp+2;
		}
		if( strneq(sp,":::",3) ){
			fcp1.fcp_spec = sp+2;
		}
	}
}
const char *getCKeyMainArg(Connection *Conn,PCStr(param),PCStr(dom),PCStr(user)){
	int ai;
	const char *dp;

	fcp1.fcp_param = param;
	fcp1.fcp_dom   = dom;
	fcp1.fcp_user  = user;
	fcp1.fcp_spec  = 0;
	for( ai = 1; ai < main_argc; ai++ ){
		if( dp = strheadstrX(main_argv[ai],param,0) )
		if( *dp == '=' ){
			fcp(Conn,dp+1);
			if( fcp1.fcp_spec != 0 )
				return fcp1.fcp_spec;
		}
	}
	return 0;
}
int getCryptKeyMainArg(PCStr(param),PCStr(dom),PCStr(user),PVStr(ckey),int csiz){
	const char *ck;
	if( ck = getCKeyMainArg(MainConn(),param,dom,user) ){
		if( strneq(ck,":",1) ){
			strcpy(ckey,ck+1);
			return strlen(ckey);
		}
		if( strneq(ck,"pass:",5) ){
			strcpy(ckey,ck+5);
			return strlen(ckey);
		}
	}
	return -1;
}

const char *getCKeyArg(Connection *Conn,PCStr(param),PCStr(dom),PCStr(user)){
	fcp1.fcp_param = param;
	fcp1.fcp_dom   = dom;
	fcp1.fcp_user  = user;
	fcp1.fcp_spec  = 0;
	DELEGATE_scanEnv(Conn,param,fcp);
	if( fcp1.fcp_spec != 0 ){
		return fcp1.fcp_spec;
	}
	return 0;
}
int getCryptKeyTty(PCStr(param),PCStr(dom),PCStr(user),PVStr(ekey),int esiz){
	FILE *keyin = 0;
	const char *dp;

	if( !isatty(fileno(stdin)) ){
		if( isWindows() )
			/* should popup window ? */
			keyin = fopen("con","r");
		else	keyin = fopen("/dev/tty","r");
	}
	if( keyin == NULL ){
		if( !isatty(fileno(stdin)) && !isatty(fileno(stderr)) ){
			sv1log("ERROR: cannot get CRYPT value\n");
			return -1;
		}
		keyin = fdopen(fileno(stdin),"r");
	}
	setbuf(keyin,NULL);

	if( streq(param,P_CRYPT) ){
		fprintf(stderr,
		"**** Specify the key of encryption for '%s'\r\n",DGAUTHpro);
		fprintf(stderr,"**** CRYPT=pass:");
	}else{
		/*
		fprintf(stderr,"**** %s=%s:%s:pass:",param,dom,user);
		*/
		fprintf(stderr,"**** %s=%s:%s::",param,dom,user);
	}
	fflush(stderr);

	strcpy(ekey,"");
	fgetsTimeout(BVStr(ekey),esiz,keyin,60);

	if( dp = strpbrk(ekey,"\r\n") )
		truncVStr(dp);
	/*
	fprintf(stderr,"\r\n");
	*/
	return strlen(ekey);
}

void scan_CRYPTX(Connection *Conn,int clnt,PCStr(opts),PCStr(param),PCStr(dom),PCStr(user))
{	const char *cryptspec;
	CStr(ekey,32);
	const char *dp;
	int elen,reset;

	reset = 0;
	/*
	if( cryptspec = DELEGATE_getEnv(P_CRYPT) ){
	*/
	if( cryptspec = getCKeyArg(Conn,param,dom,user) ){
		if( cryptspec[0] == 0 ){
			/* maybe after "erestart" */
		}else
		if( strcmp(cryptspec,"pass:") == 0 ){
			reset = 1;
		}else{
			if( xgetpass(cryptspec,AVStr(ekey)) != 0 )
				return;
			if( *ekey == 0 )
				return;
			for( dp = cryptspec; *dp; dp++ )
			{
				truncVStr(dp); /* hide commandline arg. */
			}
			goto GOT;
		}
	}

	/*
	elen = restoreCKey(AVStr(ekey),sizeof(ekey));
	*/
	elen = restoreCKeyX(opts,param,dom,user,AVStr(ekey),sizeof(ekey));
	if( 0 < elen && !reset )
		goto GOT;

	if( clnt ){
		int sock,port;
		CStr(host,MaxHostNameLen);
		sock = DGAuth_port(0,AVStr(host),&port);
		if( 0 <= sock ){
			close(sock);
			return;
		}
	}
	if( getCryptKeyTty(param,dom,user,AVStr(ekey),sizeof(ekey)) < 0 )
		return;
GOT:
	/*
	setCKey(ekey,strlen(ekey));
	*/
	setCKeyP(param,dom,user,ekey,strlen(ekey));
	for( dp = ekey; *dp; dp++ )
		truncVStr(dp);
}
int getCryptKeyX(Connection *Conn,int which,PCStr(param),PCStr(dom),PCStr(user),PVStr(key),int siz){
	int len = -1;

	if( which & (1|4) ){
		const char *spec;
		if( spec = getCKeyMainArg(Conn,param,dom,user) ){
			if( strneq(spec,"pass:",5) && spec[5] != 0 ){
				strcpy(key,spec+5);
				len = strlen(key);
				setCKeyP(param,dom,user,key,strlen(key));
		sv1log("{K}#a getCryptKeyX(%s=%s:%s)=%d\n",param,dom,user,len);
				return len;
			}
		}
		len = getCryptKeyMainArg(param,dom,user,AVStr(key),siz);
		if( 0 <= len ){
		sv1log("{K}#a2 getCryptKeyX(%s=%s:%s)=%d\n",param,dom,user,len);
			setCKeyP(param,dom,user,key,strlen(key));
			return len;
		}
	}
	if( len <= 0 )
	if( which & 1 ){
		len = getCKeySec(param,dom,user,BVStr(key),siz);
		sv1log("{K}#A getCryptKeyX(%s=%s:%s)=%d\n",param,dom,user,len);
	}
	if( len <= 0 )
	if( which & 2 ){
		scan_CRYPTX(Conn,1,"",param,dom,user);
		len = getCKeySec(param,dom,user,BVStr(key),siz);
		sv1log("{K}#B getCryptKeyX(%s=%s:%s)=%d\n",param,dom,user,len);
	}
	if( len <= 0 )
	if( which & 4 ){
		len = getCryptKeyTty(param,dom,user,BVStr(key),siz);
		if( 0 < len ){
			setCKeyP(param,dom,user,key,strlen(key));
		}
	}
	return len;
}

#define EMSG(msg) { \
	daemonlog("F","!!!! FATAL: %s\n",msg); \
	fprintf(stderr,"!!!! FATAL: %s\n",msg); \
}

int scanAuthServPort(PCStr(domain),PVStr(serv));
int checkEkey(Connection *Conn,int store,PCStr(proto),PCStr(host),int port,PCStr(ekey));

int checkDGAuthConfig()
{	int mx;
	const char *authservp;
	CStr(domain,MaxHostNameLen);
	CStr(msg,512);
	const char *dp;
	CStr(serv,64);
	CStr(ekey,64);
	int port,elen,rcode,ecode;

	rcode = 0;
	for( mx = 0; ; mx++ ){
		mx = scan_CMAPi(MAP_AUTHSERV,mx,&authservp);
		if( mx < 0 )
			break;
		if( strstr(authservp,DGAUTHdom) != authservp )
			continue;
		lineScan(authservp,domain);
		if( dp = strchr(domain,',') )
			truncVStr(dp);
		if( dp = strchr(domain,'@') )
			truncVStr(dp);
		if( dp = strchr(domain,'(') ){
			/* 9.8.2 -dgauth(userOrOptions) */
			truncVStr(dp);
		}

		port = scanAuthServPort(domain,AVStr(serv));
		if( serv[0] ){
			/* check connectivity */
			continue;
		}
		if( (dp = strchr(domain,'{')) && strtailchr(dp) == '}' ){
			/* v9.9.9 fix-140615e literal list -dgauth{user:pass} */
			/* is not in file. don't put error, don't erase CKey */
			continue;
		}
		elen = getCKey(AVStr(ekey),sizeof(ekey));
		if( elen <= 0 ){
			sprintf(msg,"CRYPT=pass:... is not specified.");
			EMSG(msg);
			rcode = -1;
			continue;
		}
		ecode = checkEkey(MainConn(),0,DGAUTHpro,domain,0,ekey);
		bzero(ekey,sizeof(ekey));
		if( ecode != 0 ){
			if( ecode == -AUTH_EBADDOMAIN )
				sprintf(msg,"bad domain AUTHORIZER=%s",domain);
			else	sprintf(msg,"CRYPT=pass:... is wrong.");
			setCKey("",0);
			EMSG(msg);
			rcode = -1;
		}
	}
	return rcode;
}
int withAuthDigest(Connection *Conn,PVStr(authserv))
{
	if( 0 <= find_CMAP(Conn,MAP_AUTHSERV,AVStr(authserv)) ){
		if( strncmp(authserv,DGAUTHdom,7) == 0 )
			return 1;
	}
	return 0;
}

static int found;
int static isDGAdom(Connection *Conn,PCStr(dom))
{
	if( strstr(dom,DGAUTHdom) == dom )
	if( dom[strlen(DGAUTHdom)] != '{' )
		/* with DGAuth which requires CRYPT passphrase */
		found = 1;
	return 0;
}
int withDGAuth(Connection *Conn)
{
	found = 0;
	DELEGATE_scanEnv(Conn,P_AUTHORIZER,(scanPFUNCP)isDGAdom);
	if( found == 0 ){
		CStr(asv,256);
		if( getAdminAuthorizer(Conn,AVStr(asv),sizeof(asv),0) ){
			if( isinList(asv,DGAUTHdom) ){
				found = 1;
			}
			/* asv might be like -dgauth.realm ... */
		}
	}
	if( found == 0 ){
		/* should check AUTHORIZER in MOUNTs ... */
	}
	return found;
}

FILE *fopen_DGAuth()
{	int sock;

	if( DGAuthPort == 0 )
		return NULL;
	sock = client_open(DGAUTHpro,DGAUTHpro,DGAuthHost,DGAuthPort);
	if( 0 <= sock )
		return fdopen(sock,"r+");
	else	return NULL;
}
int DGAuth_port(int create,PVStr(host),int *portp)
{	CStr(path,1024);
	CStr(lpath,1024);
	const char *dp;
	FILE *fp,*lfp;
	int sock,port;

	sprintf(path,"${ADMDIR}/authorizer/%s/port",DGAUTHdom);
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
	sprintf(lpath,"%s.lock",path);

	if( create ){
		lfp = fopen(lpath,"w+");
		if( lfp == NULL || lock_exclusiveTO(fileno(lfp),1,NULL) != 0 ){
			if( lfp ) fclose(lfp);
			return -1;
		}
		fp = fopen(path,"w+");
		if( fp == NULL ){
			fp = dirfopen("DGAuth_port",AVStr(path),"w");
			if( fp == NULL ){
				fclose(lfp);
				return -1;
			}
		}
		sock = server_open(DGAUTHpro,CVStr("127.0.0.1"),0,10);
		if( sock < 0 ){
			fclose(lfp);
			fclose(fp);
			return -1;
		}
		strcpy(host,"127.0.0.1");
		*portp = port = sockPort(sock);
		fseek(fp,0,0);
		fprintf(fp,"%s:%d\n","127.0.0.1",port);
		fclose(fp);
		chmod(path,0600);
		fcloseFILE(lfp);
	}else{
		if( !File_is(lpath) ){
			/* no server */
			return -1;
		}
		lfp = fopen(lpath,"r");
		if( lfp == NULL || lock_sharedTO(fileno(lfp),1,NULL)==0 ){
			/* no active server locking it. */
			if( lfp ) fclose(lfp);
			return -1;
		}
		fclose(lfp);

		fp = fopen(path,"r");
		if( fp == NULL )
			return -1;

		setVStrEnd(host,0);
		fgets(host,256,fp);
		port = 0;
		if( dp = strchr(host,':') ){
			truncVStr(dp); dp++;
			port = atoi(dp);
		}
		sock = client_open(DGAUTHpro,DGAUTHpro,host,port);
		*portp = port;
		DGAuthHost = stralloc(host);
		DGAuthPort = port;
		fclose(fp);
	}
	return sock;
}
int connectDGAuth(PCStr(domain),FILE *sv[2])
{	int sock,port;
	CStr(dom,MaxHostNameLen);
	CStr(host,MaxHostNameLen);

	lineScan(domain,dom);
	if( port = scanAuthServPort(dom,AVStr(host)) )
		sock = client_open(DGAUTHpro,DGAUTHpro,host,port);
	else	sock = DGAuth_port(0,AVStr(host),&port);

	if( 0 <= sock ){
		sv[0] = fdopen(sock,"r");
		sv[1] = fdopen(sock,"w");
		return 0;
	}
	return -1;
}
int remoteEditDGAuthUser(int com,PCStr(domain),PCStr(user),PCStr(pass))
{	int sock;
	CStr(epass,64);
	CStr(resp,256);
	CStr(req,256);
	CStr(ereq,256);
	FILE *sv[2],*tc,*fc;
	Credhy K[1]; /**/
	int qlen;

	if( connectDGAuth(domain,sv) == 0 ){
		if( CredhyClientStart("CREDHY",K,sv[1],sv[0],200) < 0 ){
			fclose(sv[1]);
			fclose(sv[0]);
			return -AUTH_ENOSERV;
		}
		tc = sv[1];
		fc = sv[0];
		if( com == 'a' )
			sprintf(req,"ADD %s %s",user,pass);
		else	sprintf(req,"DEL %s %s",user,pass);

		CredhyAencrypt(K,req,AVStr(ereq),sizeof(ereq));
		fprintf(tc,"%s\r\n",ereq);
		fflush(tc);
		*resp = 0;
		fgets(resp,sizeof(resp),fc);
		fclose(fc);
		fclose(tc);

		fprintf(stderr,"%s\n",resp);
		if( strncmp(resp,"+OK ",4) == 0 )
			return 0;
		if( atoi(resp) == 200 )
			return 0;
		else	return -AUTH_ENOUSER;
	}
	return -AUTH_ENOSERV;
}
int remoteGetDigestPass(PCStr(host),PCStr(user),PVStr(spass))
{	FILE *sv[2],*ts,*fs;
	CStr(req,256);
	CStr(ereq,256);
	CStr(resp,512);
	CStr(code,32);
	CStr(epass,512);
	int qlen,plen,len;
	Credhy K[1]; /**/

	plen = -1;
	if( connectDGAuth(host,sv) == 0 ){
		fs = sv[0];
		ts = sv[1];
		CredhyClientStart("CREDHY",K,sv[1],sv[0],200);
		sprintf(req,"GETPASS %s",user);
		CredhyAencrypt(K,req,AVStr(ereq),sizeof(ereq));

		fprintf(ts,"%s\r\n",ereq);
		fflush(ts);
		if( fgets(resp,sizeof(resp),fs) != NULL ){
			lineScan(wordScan(resp,code),epass);
			if( atoi(code) == 200 ){
			plen = CredhyAdecrypt(K,epass,AVStr(spass),sizeof(epass));
			}
		}
		fclose(ts);
		fclose(fs);
	}
	return plen;
}

/*
 * for -Fauth ... -dgauth
 */
int getCRYPTkey(Connection *Conn,int clnt,PVStr(ckey),int ksiz)
{ 
	scan_CRYPT(Conn,clnt);
	return getCKey(AVStr(ckey),ksiz);
}
int getEKey(Connection *ctx,FILE *tc,int com,PCStr(proto),PCStr(host),PCStr(port),PCStr(user),PCStr(pass),PVStr(ekey))
{	int elen;

	if( remoteEditDGAuthUser(com,host,user,pass) != -AUTH_ENOSERV )
		return 0;
	elen = getCRYPTkey(ctx,1,AVStr(ekey),128); /*ERR_sizeof(ekey));*/
	if( elen == 0 ){
		fprintf(tc,"-ERROR No Encryption Key\n");
		return 0;
	}
	if( checkEkey(ctx,1,proto,host,atoi(port),ekey) != 0 ){
		fprintf(tc,"-ERROR Bad Encryption Key\n");
		return 0;
	}
	return elen;
}
void showPass(Connection *Conn,FILE *out,PCStr(tmp),int com,PCStr(host),PCStr(user),PCStr(pass)){
	IStr(md5,128);
	IStr(epass,128);
	IStr(spass,128);
	int plen;
	int elen;
	IStr(ekey,128);

	Xsscanf(tmp,"%s %s",AVStr(md5),AVStr(epass));
	elen = getCRYPTkey(Conn,1,AVStr(ekey),sizeof(ekey));
	plen = adecrypty(ekey,elen,epass,strlen(epass),(char*)spass);
	fprintf(out,"Password: %s [%s]\n",epass,spass);
}

static int clockencdec(int enc,int clock)
{	int crc,xclock;

	return clock;
/*
	crc = NonceKeyCRC32();
	if( enc )
		xclock = (clock + crc) ^ crc;
	else	xclock = (clock ^ crc) - crc;
	if( crc & 1 )
		xclock = ~xclock;
	return xclock;
*/
}

void NonceKey(PVStr(key));
void genNonce(Connection *Conn,PCStr(uri),PVStr(nonce),int clock)
{	CStr(key,64);
	CStr(eclocks,64);
	CStr(nonce1,64);
	CStr(nonce2,64);
	CStr(nonce3,64);
	const char *dp;
	int eclock,crc;

	NonceKey(AVStr(key));
	sprintf(nonce1,"%x:%s",clock,key);
	toMD5(nonce1,nonce2);
	eclock = clockencdec(1,clock);
	sprintf(eclocks,"%x",eclock);
	crc = strCRC8(0,eclocks,strlen(eclocks));
	strreverse(eclocks);
	sprintf(nonce3,"%x.%s.%s",crc,eclocks,nonce2);
	str_to64(nonce3,strlen(nonce3),AVStr(nonce),64,1);
	if( dp = strpbrk(nonce,"\r\n") )
		truncVStr(dp);
}
static int scanNonceDate(PCStr(qnonce))
{	int nlen,xcrc,crc,xclock;
	CStr(dqnonce,64);
	CStr(eclocks,64);

	nlen = str_from64(qnonce,strlen(qnonce),AVStr(dqnonce),sizeof(dqnonce));
	if( nlen < 32 ){
		sv1log("## DGAuth: Invalid Nonce Format: %s [%s]\n",
			qnonce,dqnonce);
		return -1;
	}
	xcrc = -1;
	eclocks[0] = 0;
	Xsscanf(dqnonce,"%x.%[^.]",&xcrc,AVStr(eclocks));
	strreverse(eclocks);
	crc = strCRC8(0,eclocks,strlen(eclocks));
	if( xcrc != crc ){
		sv1log("## DGAuth: Invalid Nonce Clock: %X %X %s %s\n",
			crc,xcrc,eclocks,qnonce);
		return -1;
	}
	xclock = 0;
	sscanf(eclocks,"%x",&xclock);
	return xclock;
}

int genDigestNonce(Connection *Conn,AuthInfo *ident,PCStr(uri),PVStr(nonce))
{
	genNonce(Conn,uri,AVStr(nonce),time(0));
	return 1;
}
int genDigestResp(Connection *Conn,AuthInfo *ident,PVStr(xrealm),PCStr(uri),PVStr(nonce))
{
	CStr(authserv,MaxAuthServLen);
/*
{	CStr(authserv,128);
*/
	const char *dp;

	/*
	if( getAdminAuthorizer(Conn,AVStr(authserv),sizeof(authserv),0) ){
	*/
	if( (ClientFlags & PF_ADMIN_ON)
	 && getAdminAuthorizer(Conn,AVStr(authserv),sizeof(authserv),0) ){
	}else
	if( getMountAuthorizer(Conn,AVStr(authserv),sizeof(authserv)) ){
	}else
	if( find_CMAP(Conn,MAP_AUTHSERV,AVStr(authserv)) < 0 )
		return 0;
	if( !strneq(authserv,DGAUTHdom,7) )
		return 0;

	setVStrEnd(xrealm,0);
	if( dp = strchr(authserv,'@') ){
		linescanX(dp+1,AVStr(ident->i_realm),sizeof(ident->i_realm));
		strcpy(xrealm,ident->i_realm);
	}

	if( dp = strchr(authserv,',') )
		truncVStr(dp);

	if( dp = strstr(authserv,"//") )
		truncVStr(dp);

	if( xrealm[0] == 0 )
	if( authserv[7] == '.' )
		strcpy(xrealm,authserv+8);
	else
	if( ClientFlags & PF_MITM_DO ){
		strcpy(xrealm,"MITM-proxy");
	}
	else	strcpy(xrealm,DGAuthDFLT_realm);

	genDigestNonce(Conn,ident,uri,AVStr(nonce));
	return 1;
}

void genDigestReq(AuthInfo *ident,PCStr(Method),PCStr(uri),PCStr(user),PCStr(pass),PCStr(realm),PCStr(nonce),PVStr(digest))
{	CStr(HA1,64);
	CStr(HA2,64);
	CStr(digestr,64);
	MD5 *md5;

	md5 = newMD5();
	addMD5(md5,user,strlen(user));
	addMD5(md5,":",1);
	addMD5(md5,realm,strlen(realm));
	addMD5(md5,":",1);
	addMD5(md5,pass,strlen(pass));
	endMD5(md5,digestr);
	MD5toa(digestr,HA1);

	md5 = newMD5();
	addMD5(md5,Method,strlen(Method));
	addMD5(md5,":",1);
	addMD5(md5,uri,strlen(uri));
	endMD5(md5,digestr);
	MD5toa(digestr,HA2);

	md5 = newMD5();
	addMD5(md5,HA1,strlen(HA1));
	addMD5(md5,":",1);

	addMD5(md5,nonce,strlen(nonce));
	if( ident && streq(ident->i_qop,"auth") ){
	addMD5(md5,":",1);
	addMD5(md5,ident->i_nc,strlen(ident->i_nc));
	addMD5(md5,":",1);
	addMD5(md5,ident->i_cnonce,strlen(ident->i_cnonce));
	addMD5(md5,":",1);
	addMD5(md5,ident->i_qop,strlen(ident->i_qop));
	}
	addMD5(md5,":",1);
	addMD5(md5,HA2,strlen(HA2));
	endMD5(md5,digestr);
	MD5toa(digestr,(char*)digest);
}

int localGetDigestPass(Connection *Conn,PCStr(host),PCStr(user),PVStr(spass));
int remoteHTTPreqDigest(FILE *afp,PCStr(user),PCStr(method),PCStr(uri),PCStr(realm),PCStr(nonce),PVStr(digest),AuthInfo *au);

int getPassFromList(Connection *Conn,PCStr(list),PCStr(user),PVStr(pass)){
	char *uplist;
	const char *up;
	const char *pp;
	int igncase = 0;

	if( (uplist = strchr((char*)list,'{')) == 0 )
		return -1;
	if( strchr(uplist+1,'}') == 0 )
		return -1;
	for( up = uplist+1; *up; up++ ){
		if( pp = strheadstrX(user,up,igncase) ){
			if( *pp == ':' ){
				wordscanY(pp+1,BVStr(pass),128,"^,}");
				return strlen(pass);
			}
		}
		up = strpbrk(up,",}");
		if( *up != ',' )
			break;
	}
	return -1;
}
static scanListFunc fup(PCStr(userpass),PCStr(user),int ulen,PVStr(pass)){
	if( strncmp(userpass,user,ulen) == 0 ){
		if( userpass[ulen] == ':' ){
			strcpy(pass,userpass+ulen+1);
			return 1;
		}
	}
	return 0;
}
int getListPass(PCStr(dom),PCStr(user),PVStr(spass)){
	const char *dp;
	CStr(list,1024);
	int ulen;

	if( (dp = strchr(dom,'{')) == 0 )
		return 0;
	strcpy(list,dp+1);
	if( dp = strchr(list,'}') )
		truncVStr(dp);
	ulen = strlen(user);
	if( scan_commaListL(list,0,scanListCall fup,user,ulen,AVStr(spass)) ){
		return 1;
	}
	return 0;
}

/*
int UpdateSession(AuthInfo *ident,int expire);
*/
int UpdateSession(Connection *Conn,AuthInfo *ident,int expire);
int HTTP_authorize_Digest(Connection *Conn,AuthInfo *ident,PCStr(dom),PCStr(user),PCStr(dpass),PVStr(serv),int port)
{	int sock,xclock,clock,now,age,plen,rcode;
	FILE *tsfs;
	CStr(spass,128);
	CStr(nonce,64);
	CStr(digest,64);
	const char *uri = ident->i_path;
	const char *realm = ident->i_realm;
	const char *Method = ident->i_meth;
	const char *qnonce = ident->i_nonce;
	const char *xrealm;
	const char *vrealm;

	if( uri == 0 ){
		uri = "";
		porting_dbg("## DGAuth: authrize_Digest: no URI set");
		/* it might be Proxy-Authorization for CONNECT */
	}

	if( vrealm = strchr(dom,'@') ){ /* -dgauth[.realm]@vrealm */
		truncVStr(vrealm);
		vrealm++;
		xrealm = vrealm;
	}else
	if( xrealm = strchr(dom,'.') )
		xrealm++;
	else	xrealm = DGAuthDFLT_realm;
	if( ident->i_xrealm ){
		xrealm = ident->i_xrealm;
	}
	if( strcmp(xrealm,realm) != 0 ){
		sv1log("## DGAuth: Invalid Realm: %s / %s\n",realm,xrealm);
		if( ClientFlags & PF_MITM_DO ){
			/* mixed HTTP proxy / HTTPS mitm proxy */
		}else
		return -1;
	}

	xclock = scanNonceDate(qnonce);
	if( xclock == -1 )
		return -1;

	clock = clockencdec(0,xclock);
	now = time(0);
	age = now - clock;

	genNonce(Conn,uri,AVStr(nonce),clock);
	if( strcmp(qnonce,nonce) != 0 ){
		sv1log("## DGAuth: Invalid Nonce: Q=%s G=%s\n",qnonce,nonce);
		return -1;
	}

	if( strchr(dom,'{') && strchr(dom,'}') )
	if( getListPass(dom,user,AVStr(spass)) ){
		plen = strlen(spass);
		genDigestReq(ident,Method,uri,user,spass,realm,nonce,AVStr(digest));
		goto VALIDATE;
	}

	if( serv[0] != 0 && port != 0 )
	/* explicit remote server */
	{
		sock = client_open(DGAUTHpro,DGAUTHpro,serv,port);
		if( sock < 0 ){
			sv1log("## DGAuth: Cannot Connext %s server [%s:%d]\n",
				DGAUTHpro,serv,port);
			ident->i_error |= AUTH_ENOSERV;
			return -1;
		}
		tsfs = fdopen(sock,"r+");
		goto REMOTE;
	}

	plen = localGetDigestPass(Conn,dom,user,AVStr(spass));
	if( 0 < plen )
	/* self */
	{
		genDigestReq(ident,Method,uri,user,spass,realm,nonce,AVStr(digest));
		bzero(spass,sizeof(spass));
		goto VALIDATE;
	}

	/* find implicit local sever */
	if( plen <= 0 )
	{
		tsfs = fopen_DGAuth();
		if( tsfs == NULL ){
			sock = DGAuth_port(0,AVStr(serv),&port);
			if( 0 <= sock ){
				tsfs = fdopen(sock,"r+");
			}
		}
		if( tsfs != NULL )
			goto REMOTE;

		if( plen == -AUTH_ENOUSER )
			ident->i_error |= AUTH_ENOUSER;
		else{
			ident->i_error |= AUTH_ENOSERV;
			sv1log("## DGAuth: No server\n");
		}
		return -1;
	}

REMOTE:
	rcode = remoteHTTPreqDigest(tsfs,user,Method,uri,realm,nonce,AVStr(digest),ident);
	fclose(tsfs);
	if( rcode != 0 ){
		sv1log("## DGAuth: Error from Server\n");
		return -1;
	}

VALIDATE:
/*
 fprintf(stderr,"#Q nonce=%s age=%d realm=[%s][%s]\n",nonce,age,realm,xrealm);
*/
	if( strcmp(digest,dpass) != 0 ){
		sv1log("## DGAuth: Invalid Nonce (%s)\n",dom);
		if( strcmp(dom,"-dgauth.-crypt") == 0 ){
			ident->i_stat |= AUTH_GEN;
		}
		return -1;
	}
	if( age < 0 ){
		sv1log("## DGAuth: Valid bad Future Nonce: age=%d %s\n",
			age,nonce);
		return -1;
	}
	if( NONCE_TIMEOUT < age ){
		sv1log("## DGAuth: Valid bad Stale Nonce: age=%d %s\n",
			age,nonce);
		ident->i_error |= AUTH_ESTALE;
		return -1;
	}

	/*
	if( UpdateSession(ident,AuthTimeout(Conn)) < 0 ){
	*/
	if( UpdateSession(Conn,ident,AuthTimeout(Conn)) < 0 ){
		return -1;
	}

	sv1log("## DGAuth: Valid Digest, age=%d %s\n",age,nonce);
	return 0;
}
int authAPOP(Connection *Conn,PCStr(domain),PCStr(user),PCStr(seed),PVStr(mpass))
{	CStr(digest,64);
	CStr(pass,256);
	const char *pp;
	int plen;
	MD5 *md5;

	plen = getDigestPass(domain,user,AVStr(pass));
	sv1log("authAPOP(%s,%s) len=%d\n",user,seed,plen);
	if( plen < 0 ){
		sv1log("cannot get password for %s\n",user);
		return -1;
	}

	md5 = newMD5();
	addMD5(md5,seed,strlen(seed));
	addMD5(md5,pass,strlen(pass));
	endMD5(md5,digest);
	MD5toa(digest,(char*)mpass);

	for( pp = pass; *pp; pp++ )
		*(char*)pp = 0;
	return 0;
}

/*
 * check the correctness of encryption key
 * store the encryption key at the first store
 */
int authEdit(Connection *Conn,int detail,FILE *tc,int com,PCStr(proto),PCStr(host),int port,PCStr(user),PCStr(pass),PCStr(ekey),int expire);
void DGAuth_file(PVStr(path),PVStr(uh),PCStr(proto),PCStr(user),PCStr(host),int port);

int checkEkey(Connection *Conn,int store,PCStr(proto),PCStr(host),int port,PCStr(ekey))
{	CStr(path,1024);
	CStr(uh,1024);
	CStr(pw_md5,256);
	CStr(md5,64);
	CStr(amd5,64);
	FILE *fp;

	DGAuth_file(AVStr(path),AVStr(uh),proto,"-ADMIN-",host,port);
	if( fp = fopen(path,"r") ){
		*pw_md5 = 0;
		fgets(pw_md5,sizeof(pw_md5),fp);
		fclose(fp);
		wordScan(pw_md5,md5);
		toMD5(ekey,amd5);
		if( streq(md5,amd5) )
			return 0;
		else	return -AUTH_EBADCRYPT;
	}
	if( !store ){
		return -AUTH_EBADDOMAIN;
	}
	authEdit(Conn,1,stderr,'a',proto,host,port,"-ADMIN-",ekey,"",0);
	return 0;
}
int putDigestPass(FILE *fp,PCStr(fmt),PCStr(host),PCStr(user))
{	CStr(pass,64);

	if( getDigestPass(host,user,AVStr(pass)) < 0 )
		return -1;
	fprintf(fp,fmt,pass);
	bzero(pass,sizeof(pass));
	return 0;
}
int getDigestPassX(Connection *Conn,PCStr(host),PCStr(user),PVStr(spass))
{	int plen;

	/*
	if( plen = remoteGetDigestPass(host,user,AVStr(spass)) )
	*/
	if( 0 < (plen = remoteGetDigestPass(host,user,AVStr(spass))) )
		return plen;
	else	return localGetDigestPass(Conn,host,user,AVStr(spass));
}
static int getCKeyX(Connection *Conn,PCStr(host),PVStr(ekey),int size)
{	int elen;

	elen = getCKey(AVStr(ekey),size);
	if( elen <= 0 ){
		sv1log("## DGAuth: Decryption key is not available.\n");
		return -AUTH_ENOSERV;
	}
	if( checkEkey(Conn,0,DGAUTHpro,host,0,ekey) != 0 ){
		sv1log("## DGAuth: Decryption key is not correct.\n");
		sv1log("## DGAuth: disable the Decryption key.\n");
		setCKey("",0);
		return -AUTH_ENOSERV;
	}
	return elen;
}

/* the pass is encrypted string of user */
int genPass(Connection *Conn,PCStr(host),PCStr(user),PVStr(pass))
{	int elen,plen;
	CStr(ekey,64);

	elen = getCKeyX(Conn,host,AVStr(ekey),sizeof(ekey));
	if( elen < 0 ){
		sv1log("### genPass: CANT GET CKey\n");
		setVStrEnd(pass,0);
		return elen;
	}
	plen = aencrypty(ekey,elen,user,strlen(user),pass);
	setVStrEnd(pass,4);
	bzero(ekey,sizeof(ekey));
	return plen;
}

int localGetDigestPass(Connection *Conn,PCStr(host),PCStr(user),PVStr(spass))
{	CStr(uh,256);
	CStr(epath,1024);
	const char *dp;
	CStr(dpass,64);
	CStr(epass,128);
	CStr(xpass,256);
	CStr(pass_md5,64);
	CStr(ekey,128);
	FILE *afp;
	int elen,plen,ki;
	IStr(xhost,1024);

	if( 0 <= (plen = getPassFromList(Conn,host,user,BVStr(spass))) ){
		return plen;
	}

	setVStrEnd(spass,0);
	if( host == 0 || *host == 0 )
		host = DGAUTHdom;

	if( strncmp(host,"-dgauth.-crypt",14) == 0 ){
		plen = genPass(Conn,host,user,AVStr(spass));
		sv1log("#### -dgauth.-crypt: user=%s pass=%s\n",user,spass);
		return plen;
	}

	DGAuth_file(AVStr(epath),AVStr(uh),DGAUTHpro,user,host,0);

	afp = fopen(epath,"r");
	if( afp == NULL ){
		sv1log("## DGAuth: No such user [%s] in %s auth.\n",user,host);
		return -AUTH_ENOUSER;
	}
	fgets(xpass,sizeof(xpass),afp);
	fclose(afp);
	dp = wordScan(xpass,dpass);
	dp = wordScan(dp,epass);

	/*
	elen = getCKey(AVStr(ekey),sizeof(ekey));
	if( elen <= 0 ){
		sv1log("## DGAuth: Decryption key is not available.\n");
		return -AUTH_ENOSERV;
	}
	if( checkEkey(Conn,0,DGAUTHpro,host,0,ekey) != 0 ){
		sv1log("## DGAuth: Decryption key is not correct.\n");
		sv1log("## DGAuth: disable the Decryption key.\n");
		setCKey("",0);
		return -AUTH_ENOSERV;
	}
	*/
	elen = getCKeyX(Conn,host,AVStr(ekey),sizeof(ekey));
	if( elen < 0 )
		return elen;

	plen = adecrypty(ekey,elen,epass,strlen(epass),(char*)spass);
	for( ki = 0; ki < elen; ki++ )
		setVStrEnd(ekey,ki);
	toMD5(spass,pass_md5);
	if( strcmp(dpass,pass_md5) != 0 ){
		sv1log("## DGAuth: Decryption key is wrong.\n");
		return -AUTH_ENOSERV;
	}
	return plen;
}

/*
 * HTTP user method uri realm nonce
 */
int remoteHTTPreqDigest(FILE *afp,PCStr(user),PCStr(method),PCStr(uri),PCStr(realm),PCStr(nonce),PVStr(digest),AuthInfo *au)
{	CStr(resp,256);
	CStr(code,32);
	const char *dp;
	const char *proto;
	CStr(erealm,256);

	if( streq(au->i_qop,"auth") )
		proto = "HTTPX";
	else	proto = "HTTP";

	url_escapeX(realm,AVStr(erealm),sizeof(erealm)," \t\r\n","");
	sv1log("DGAuth-CL: %s %s %s %s %s [%s %s %s] %s\r\n",
		proto,user,nonce,erealm,method,
		au->i_qop,au->i_cnonce,au->i_nc,uri);
	fprintf(afp,"%s %s %s %s %s ",proto,user,nonce,erealm,method);
	if( streq(au->i_qop,"auth") ){
		fprintf(afp,"%s %s %s ",au->i_qop,au->i_cnonce,au->i_nc);
	}
	fprintf(afp,"%s\r\n",uri);
	fflush(afp);
	if( fgets(resp,sizeof(resp),afp) != NULL ){
		dp = wordScan(resp,code);
		if( atoi(code) == 200 ){
			wordscanX(dp,AVStr(digest),64);
			return 0;
		}
	}
	return -1;
}
static int servHTTPreqDigest(Connection *Conn,FILE *tc,PCStr(com),PCStr(arg),PVStr(digest))
{	const char *av[16]; /**/
	const char *user;
	const char *method;
	const char *uri;
	const char *realm;
	const char *nonce;
	CStr(spass,128);
	int nac,ac,ai,plen;
	AuthInfo au;

	sv1log("DGAuth-SV: HTTP %s\r\n",arg);
	if( streq(com,"HTTPX") )
		nac = 8;
	else	nac = 5;
	ac = list2vect(arg,' ',nac,av);

	if( ac != nac ){
		fprintf(tc,"501 BAD arg. count(%d/%d)\r\n",ac,nac);
		return -1;
	}
	ai = 0;
	user = av[ai++];
	nonce = av[ai++];
	realm = av[ai++];
	method = av[ai++];

	bzero(&au,sizeof(AuthInfo));
	if( 5 < ac ){
		wordScan(av[ai++],au.i_qop);
		wordScan(av[ai++],au.i_cnonce);
		wordScan(av[ai++],au.i_nc);
	}

	uri = av[ai++];

	plen = localGetDigestPass(Conn,"",user,AVStr(spass));
	if( plen <= 0 ){
		fprintf(tc,"502 BAD user\r\n");
		return -1;
	}
	genDigestReq(&au,method,uri,user,spass,realm,nonce,AVStr(digest));
	bzero(spass,sizeof(spass));
	return 0;
}

int service_DGAuth(Connection *Conn)
{	int elen,olen;
	CStr(req,1024);
	CStr(com,64);
	CStr(arg,1024);
	CStr(ekey,64);
	CStr(md5,64);
	const char *dp;
	CStr(out,256);
	FILE *fc,*tc;
	const char *av[8]; /**/
	int ac;
	CStr(digest,128);
	int rcode;
	Credhy K[1]; /**/
	int xskey;

	if( !source_permitted(Conn) ){
		CStr(shost,MaxHostNameLen);
		getClientHostPort(Conn,AVStr(shost));
		daemonlog("F","E-P: No permission: \"%s\" is not allowed (%s)\n",
			shost,Conn->reject_reason);
		return -1;
	}

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");
	elen = getCKey(AVStr(ekey),sizeof(ekey));
	if( elen == 1 && *ekey == '\n' ){
		*ekey = 0;
		elen = 0;
	}

	xskey = 0;
	for(;;){
		fflush(tc);
		if( fgets(req,sizeof(req),fc) == NULL ){
			break;
		}
		if( dp = strpbrk(req,"\r\n") )
			truncVStr(dp);
		if( xskey ){
			olen = CredhyAdecrypt(K,req,AVStr(req),sizeof(req));
			if( olen < 0 ){
				continue;
			}
		}
		dp = wordScan(req,com);
		dp = lineScan(dp,arg);
		sv1log("[%s] elen=%d\n",com,elen);

		if( strcaseeq(com,"CREDHY") ){
			CredhyServerStart(com,K,tc,fc,arg,200,500);
			xskey = 1;
			continue;
		}
		if( strcaseeq(com,"END") ){
			fprintf(tc,"200 bye.\r\n");
			break;
		}

		if( elen == 0 ){
			fprintf(tc,"500 encryption key is not set\n");
			continue;
		}
		if( strcaseeq(com,"HTTP") || strcaseeq(com,"HTTPX") ){
			rcode = servHTTPreqDigest(Conn,tc,com,arg,AVStr(digest));
			if( rcode == 0 )
				fprintf(tc,"200 %s\r\n",digest);
			continue;
		}
		if( strcaseeq(com,"APOP") ){
			/* APOP user seed */
			const char *user;
			const char *seed;
			ac = list2vect(arg,' ',2,av);
			if( ac != 2 ){
				fprintf(tc,"501 BAD arg. count(%d)\r\n",ac);
				continue;
			}
			user = av[0];
			seed = av[1];
			rcode = authAPOP(NULL,"",user,seed,AVStr(digest));
			if( rcode == 0 )
				fprintf(tc,"200 %s\r\n",digest);
			else	fprintf(tc,"500 internal error.\r\n");
			continue;
		}


		if( xskey == 0 ){
			fprintf(tc,"500 communication is not encrypted.\r\n");
			continue;
		}
		if( strcaseeq(com,"CLR") ){
			if( streq(arg,ekey) ){
				*ekey = 0;
				elen = 0;
				fprintf(tc,"200 OK, reset.\r\n");
			}else{
				fprintf(tc,"500 BAD, unmatch.\r\n");
			}
		}
		else
		if( strcaseeq(com,"KEY") ){
			if( elen != 0 ){
				fprintf(tc,"400 set already.\r\n");
				continue;
			}
			toMD5(arg,md5);
			/*
			if( !streq(md5,) ){
				fprintf(tc,"400\r\n");
				continue;
			}
			*/
			setCKey(arg,strlen(arg));
			elen = getCKey(AVStr(ekey),sizeof(ekey));
			fprintf(tc,"200 OK, set(%d).\r\n",elen);
		}
		else
		if( strcaseeq(com,"DEL") ){
			const char *user;
			const char *pass;
			ac = list2vect(arg,' ',2,av);
			if( ac != 2 ){
				fprintf(tc,"501 BAD arg. count(%d)\r\n",ac);
				continue;
			}
			user = av[0];
			pass = av[1];
			authEdit(Conn,0,tc,'d',DGAUTHpro,DGAUTHdom,0,user,pass,ekey,0);
			fprintf(tc,"200 removed\r\n");
		}
		else
		if( strcaseeq(com,"ADD") ){
			/* ADD user pass [dom] */
			const char *user;
			const char *pass;
			const char *realm;
			ac = list2vect(arg,' ',3,av);
			if( ac < 2 ){
				fprintf(tc,"501 BAD arg. count(%d)\r\n",ac);
				continue;
			}
			user = av[0];
			pass = av[1];
			if( 2 < ac )
				realm = av[2];
			else	realm = DGAUTHdom;
			sv1log("## DGAuth: %s %s *** %s\n",com,user,realm);

			rcode =
			authEdit(Conn,0,tc,'a',DGAUTHpro,realm,0,user,pass,ekey,0);
			if( rcode == 0 )
				fprintf(tc,"200 added\r\n");
			else	fprintf(tc,"500 error\r\n");
		}
		else
		if( strcaseeq(com,"AUTH") ){
			/* AUTH dom user pass */
		}
		else
		if( strcaseeq(com,"GETPASS") ){
			/* GETPASS user [dom] */
			const char *user;
			const char *dom;
			CStr(spass,256);

			ac = list2vect(arg,' ',2,av);
			if( ac == 0 ){
				fprintf(tc,"500 GETPASS user [domain]\r\n");
				continue;
			}
			user = av[0];
			if( 1 < ac )
				dom = av[1];
			else	dom = "";
			olen = localGetDigestPass(Conn,dom,arg,AVStr(spass));
			CredhyAencrypt(K,spass,AVStr(arg),sizeof(arg));
			bzero(spass,sizeof(spass));
			fprintf(tc,"200 %s\r\n",arg);
			sv1log("## 200 %s\n",arg);
		}
		else
		if( strcaseeq(com,"ENC") ){
			olen = aencrypty(ekey,elen,arg,strlen(arg),out);
			fprintf(tc,"200 %d %s\r\n",olen,out);
		}
		else
		if( strcaseeq(com,"DEC") ){
			if( 0 ){
				olen = adecrypty(ekey,elen,arg,strlen(arg),out);
				fprintf(tc,"200 %d %s\r\n",olen,out);
			}else{
				fprintf(tc,"403 Forbidden\r\n");
			}
		}
		else
		{
			break;
		}
	}
	fclose(tc);
	fclose(fc);
	return 0;
}

/*
 *
 */
typedef struct {
 unsigned int	o_start;
 unsigned short	o_count;
 unsigned short	o_realmCRC; /* CRC32&0xFFFF of the realm */
 unsigned short	o_pid;
 unsigned short	o_serno;
} Opaque;
#define OPQSIZE	(sizeof(Opaque)+2)
#define o_serno_multi(Op)	((char*)(&Op[1]))[0]
#define o_reqserno(Op)		((char*)(&Op[1]))[1]

void printOpaque(PVStr(opqs),Opaque *Op)
{	CStr(st,64);
	CStr(ser,32);

	StrftimeLocal(AVStr(st),sizeof(st),"%y%m%d-%H%M%S",Op->o_start,0);
	sprintf(ser,"%d+%d",Op->o_serno,o_serno_multi(Op));
	if( o_reqserno(Op) )
		Xsprintf(TVStr(ser),"+%d",o_reqserno(Op));
	sprintf(opqs,"%s.%d.%s.%d",st,Op->o_pid,ser,Op->o_count);
}
extern int CHILD_SERNO;
extern int CHILD_SERNO_MULTI;
void genSessionID(Connection *Conn,PVStr(opaque),int inc)
{	CStr(opq,128);
	CStr(opqs,128);
	CStr(key,64);
	const char *op;
	int olen,startu;
	Opaque Ops[2],*Op = &Ops[0];
	const char *realm = ClientAuth.i_realm;
	int realmcrc;

	NonceKey(AVStr(key));
	bzero(Op,OPQSIZE);
	if( opaque[0] ){
		olen = adecrypty(key,strlen(key),opaque,strlen(opaque),opq);
		if( olen == OPQSIZE ){
			bcopy(opq,Op,OPQSIZE);
		}
		if( Op->o_pid != 0 && Op->o_start != 0 ){
/*
			printOpaque(AVStr(opqs),Op);
fprintf(stderr,"#### GET OPAQ %s %s\n",opqs,opaque);
*/
		}
	}
	realmcrc = 0xFFFF & strCRC32(realm,strlen(realm));
	Op->o_realmCRC = realmcrc;
	if( Op->o_pid == 0 || Op->o_start == 0 ){
		Op->o_pid = serverPid();
		Op->o_start = time(0);
		Op->o_serno = CHILD_SERNO;
		o_serno_multi(Op) = CHILD_SERNO_MULTI;
		o_reqserno(Op) = RequestSerno;
	}
	Op->o_count += inc;

	olen = aencrypty(key,strlen(key),(char*)Op,OPQSIZE,opaque);
	printOpaque(AVStr(opqs),Op);
	if( Op->o_count == 0 ){
		daemonlog("F","NewSession %s\n",opqs);
	}
/*
fprintf(stderr,"#### NEW OPAQ %s %s\n",opqs,opaque);
*/
}
int UpdateSession(Connection *Conn,AuthInfo *ident,int expire){
/*
int UpdateSession(AuthInfo *ident,int expire){
	Opaque Op;
	*/
	Opaque Ops[2],*Op = &Ops[0]; /* v9.9.9 fix-140613b */
	CStr(opq,128);
	refQStr(iopq,ident->i_opaque);
	const char *realm = ident->i_realm;
	int olen;
	CStr(key,64);
	int now;
	int age;
	int realmCRC;

	NonceKey(AVStr(key));
	olen = adecrypty(key,strlen(key),iopq,strlen(iopq),opq);
	if( olen == OPQSIZE ){
		bcopy(opq,Op,OPQSIZE);
		now = time(0);
		realmCRC = 0xFFFF&strCRC32(realm,strlen(realm));
		sv1log("Session: age=%d/%d cnt=%d pid=%d.%d %X/%X\n",
			now-Op->o_start,expire,Op->o_count,Op->o_pid,Op->o_serno,
			Op->o_realmCRC,realmCRC);
		if( expire <= 0 ){
			return 0;
		}
		age = now - Op->o_start;
		if( realmCRC == Op->o_realmCRC ){
			if( age <= expire ){
				return 0;
			}
		}
		Op->o_start = now;
		Op->o_pid = serverPid();
		Op->o_serno = CHILD_SERNO;
		Op->o_count += 1;
		Op->o_realmCRC = realmCRC;
		o_serno_multi(Op) = CHILD_SERNO_MULTI;
		o_reqserno(Op) = RequestSerno;
		aencrypty(key,strlen(key),(char*)Op,OPQSIZE,iopq);

		/*
		bcopy(opq,&Op,OPQSIZE);
		now = time(0);
		realmCRC = 0xFFFF&strCRC32(realm,strlen(realm));
		sv1log("Session: age=%d/%d cnt=%d pid=%d.%d %X/%X\n",
			now-Op.o_start,expire,Op.o_count,Op.o_pid,Op.o_serno,
			Op.o_realmCRC,realmCRC);
		if( expire <= 0 ){
			return 0;
		}
		age = now - Op.o_start;
		if( realmCRC == Op.o_realmCRC ){
			if( age <= expire ){
				return 0;
			}
		}
		Op.o_start = now;
		Op.o_pid = serverPid();
		Op.o_serno = CHILD_SERNO;
		Op.o_count += 1;
		Op.o_realmCRC = realmCRC;
		aencrypty(key,strlen(key),(char*)&Op,OPQSIZE,iopq);
		*/
		return -1;
	}
	clearVStr(ident->i_opaque);
	return -1;
}
int decrypt_opaque(PCStr(opaque),PVStr(opqs))
{	CStr(opq,128);
	CStr(key,64);
	int olen;
	Opaque Ops[2],*Op = &Ops[0];

	NonceKey(AVStr(key));
	olen = adecrypty(key,strlen(key),opaque,strlen(opaque),opq);
	if( olen == OPQSIZE ){
		bcopy(opq,Op,OPQSIZE);
		printOpaque(AVStr(opqs),Op);
		return olen;
	}else{
		setVStrEnd(opqs,0);
		return 0;
	}
}


/*
 * a key to encrypt opaque or session-Id
 */
void NonceKey(PVStr(key))
{	CStr(dir,1024);
	CStr(path,1024);
	CStr(skey,256);
	FILE *fp;

	if( nonceKey[0] ){
		strcpy(key,nonceKey);
		return;
	}

	strcpy(dir,"${ADMDIR}/secret");
	DELEGATE_substfile(AVStr(dir),"",VStrNULL,VStrNULL,VStrNULL);
	sprintf(path,"%s/%s",dir,"noncekey");

	if( !File_is(path) ){
		if( fp = dirfopen("NonceKey",AVStr(path),"w") ){
			sv1log("#### NonceKey created: %s\n",path);
			fprintf(fp,"%d%d",getpid(),itime(0));
			fclose(fp);	
			chmod(dir,0700);
			chmod(path,0400);
		}
	}
	skey[0] = 0;
	if( fp = fopen(path,"r") ){
		sprintf(skey,"%d.%d.",File_ctime(dir),File_mtime(path));
		Xfgets(TVStr(skey),sizeof(skey)-strlen(skey),fp);
		fclose(fp);
	}
	toMD5(skey,(char*)key);
	strcpy(nonceKey,key);
}
int NonceKeyCRC32()
{	CStr(key,64);
	int crc;

	NonceKey(AVStr(key));
	crc = strCRC32(key,strlen(key));
	return crc;
}
int NonceKeyCRC8()
{	CStr(key,64);
	int crc;

	NonceKey(AVStr(key));
	crc = strCRC8(0,key,strlen(key));
	return crc;
}

int getCreySalt(PVStr(str));
int creyInt32(int val,int dec){
	CStr(b,8);
	const unsigned char *u = (const unsigned char*)b;
	int xval;
	CStr(saltstr,128);

	getCreySalt(AVStr(saltstr));
	setVStrElem(b,0,val>>24);
	setVStrElem(b,1,val>>16);
	setVStrElem(b,2,val>>8);
	setVStrElem(b,3,val);
	if( dec )
		CreyDecrypts(saltstr,strlen(saltstr),AVStr(b),4);
	else	CreyEncrypts(saltstr,strlen(saltstr),AVStr(b),4);
	xval = (u[0]<<24) | (u[1]<<16) | (u[2]<<8) | u[3];
	return xval;
}

int enBase32(PCStr(src),int sbits,PVStr(dst),int dsiz);
int deBase32(PCStr(src),int slen,PVStr(dst),int dsiz);

int makeAdminKey(PCStr(from),PVStr(key),int siz){
	CStr(addr,1024);
	MD5 *md5;
	CStr(md5b,32);

	CStr(saltstr,128);
	getCreySalt(AVStr(saltstr));

	RFC822_addresspartX(from,AVStr(addr),sizeof(addr));
	strtolower(addr,addr);
	md5 = newMD5();
	addMD5(md5,saltstr,strlen(saltstr));
	addMD5(md5,"",1);
	addMD5(md5,addr,strlen(addr));
	endMD5(md5,md5b);
	enBase32(md5b,8*16,AVStr(key),siz);
	return 0;
}
int (*MIME_makeAdminKey)(PCStr(from),PVStr(key),int siz) = makeAdminKey;

/* Finger print of an Email address */
int makeEmailFP(PVStr(ocrc),PCStr(addr)){
	int crc;
	CStr(bi,8);
	CStr(ba,16);
	int icrc;

	crc = creyInt32(strCRC32(addr,strlen(addr)),0);
	setVStrElem(bi,0,crc>>24);
	setVStrElem(bi,1,crc>>16);
	setVStrElem(bi,2,crc>>8);
	setVStrElem(bi,3,crc);
	icrc = creyInt32(strCRC32(bi,4),0);
	setVStrElem(bi,4,(0x7 & icrc) << 5);
	enBase32(bi,35,AVStr(ba),sizeof(ba));
	strcpy(ocrc,ba);
	return 0;
}
int (*MIME_makeEmailFP)(PVStr(ocrc),PCStr(addr)) = makeEmailFP;

int makeEmailCX(PVStr(ocrc),PCStr(wf),PCStr(addr)){
	CStr(fmt,128);
	int crc;
	int len;

	sprintf(fmt,"%%%sX",wf);
	crc = creyInt32(strCRC32(addr,strlen(addr)),0);
	sprintf(ocrc,fmt,crc);
	if( len = atoi(wf) ){
		if( len < strlen(ocrc) ) 
			setVStrEnd(ocrc,len);
	}
	return 0;
}
int (*MIME_makeEmailCX)(PVStr(ocrc),PCStr(wf),PCStr(addr)) = makeEmailCX;

/*########################################################################
 *
 * HTTPCONF=cryptCookie[:listOfDomAttrs[/cryptOptions][:cryptKey[:CMAP]]]
 * cryptKey %P -- the password for AUTHORIZER
 * cryptOptions: prefix, expire, host-match, port-match,
 *               proxy-match, client-host-match, ...
 *
 * listOfDomAttrs = key1@dom1,{key21,key22}@{dom21,dom22}
 * host-match={exact|domain|any}
 */
int getParamX(PVStr(params),PCStr(name),PVStr(val),int siz,int del,int cookie);
/*
static const char *rewcPfx = "DG_";
*/
static const char *rewcPfx = "";
static const char *rewcAttrs;
static const char *rewcEKey;
static int rewcHosts;
static const char *delcAttrs;

void setupDeleteCookie(PCStr(value)){
	delcAttrs = stralloc(value);
}
void setupCryptCookie(PCStr(value)){
	CStr(attrs,1024);
	CStr(ckey,1024);
	CStr(cmap,1024);

	truncVStr(attrs);
	truncVStr(cmap);
	truncVStr(ckey);

	Xsscanf(value,"%[^:]:%[^:]:%s",AVStr(attrs),AVStr(ckey),AVStr(cmap));
	rewcAttrs = stralloc(attrs);
	rewcEKey = stralloc(ckey);
}

static scanListFunc dommatch1(PCStr(dom1),PCStr(host),int port){
	const char *dp;
	if( dom1[0] == '.' ){
		if( strcaseeq(host,dom1+1) ){
			return 2;
		}
		if( dp = strcasestr(host,dom1) ){
			if( dp[strlen(dom1)] == 0 ){
				return 3;
			}
		}
	}else{
		if( strcaseeq(dom1,host) ){
			return 4;
		}
	}
	return 0;
}
static int dommatch(Connection *Conn,PCStr(rdom),PCStr(attrn)){
	int isin;
	if( rdom[0] == 0 ){
		return 1;
	}
	isin=scan_commaListL(rdom,0,scanListCall dommatch1,DST_HOST,DST_PORT);

if( lSECRET() )
fprintf(stderr,"--[%s:%d] [%s]@[%s] ISIN=%d\n",
DST_HOST,DST_PORT,attrn,rdom,isin);

	return isin;
}

int getrewCookie(Connection *Conn,PCStr(rewcAttrs),PCStr(pfx),PVStr(cookie),PVStr(attrv),int size,PVStr(attrn),PVStr(rdom),PVStr(ekey),int esiz){
	const char *alist;
	refQStr(dp,attrn);
	int off;
	const char *a1;
	CStr(an,128);

	if( rewcAttrs == 0 )
		return 0;

	alist = rewcAttrs;
	if( pfx && *pfx ){
		strcpy(attrn,pfx);
		off = strlen(pfx);
	}else	off = 0;

	while( alist && *alist ){
		alist = scan_ListElem1(alist,',',DVStr(attrn,off));
		if( attrn[0] == 0 )
			break;
		if( dp = strchr(attrn,'@') ){
			setVStrEnd(dp,0);
			strcpy(rdom,dp+1);
			if( lSECRET() ){
 fprintf(stderr,"--[%s:%d] [%s]@[%s]\n",DST_HOST,DST_PORT,attrn,rdom);
			}
			if( !dommatch(Conn,rdom,attrn) ){
				continue;
			}
		}else{
			setVStrEnd(rdom,0);
		}

		/* should be replaced with scan_ListElem1L() ... */
		if( attrn[0] == '{' && strtailchr(attrn) == '}' ){
			ovstrcpy((char*)attrn,attrn+1);
			setVStrEnd(attrn,strlen(attrn)-1);
		}
		a1 = attrn;
		strcpy(an,attrn);
		while( *a1 ){
			a1 = scan_ListElem1(a1,',',DVStr(an,off));
			if( an[0] == 0 )
				break;
			if(getParamX(BVStr(cookie),an,BVStr(attrv),size,1,1)){
				strcpy(attrn,an);
				strfConnX(Conn,rewcEKey,AVStr(ekey),esiz);
				return 1;
			}
		}
	}
	return 0;
}

void encryptCookie1(Connection *Conn,PVStr(cookie),PCStr(oattr),PCStr(attrn),PCStr(ekey)){
	CStr(nattr,4096);
	CStr(oa,4096);
	CStr(xa,4096);
	int oalen;
	int crc;
	CStr(dom,MaxHostNameLen);
	CStr(path,1024);

	getParamX(BVStr(cookie),"domain",AVStr(dom),sizeof(dom),0,1);
	if( dom[0] == 0 )
		strcpy(dom,"=");
	strcpy(path,"/");
	sprintf(oa,"%s:%s:%s:%d:%s",dom,path,DST_HOST,DST_PORT,oattr);
	oalen = strlen(oa);

	crc = CreyEncrypts(ekey,strlen(ekey),AVStr(oa),strlen(oa));
	strtoHex(oa,oalen,AVStr(xa),sizeof(xa));
	sprintf(nattr,"%s%s=%X.%s;",rewcPfx,attrn,crc,xa);
	Strins(AVStr(cookie),nattr);
	sv1log("#### Encrypt-Cookie: %s\n",attrn);
}
void encryptCookie(Connection *Conn,PVStr(cookie)){
	CStr(oa,4096);
	CStr(an,128);
	CStr(dom,256);
	CStr(ek,128);
	int na;

	if( lSECRET() )
	fprintf(stderr,"<<<<<<<<< %s\nSet-Cookie: %s\n",DST_HOST,cookie);

	for( na = 0; na < 10; na++ ){
		if( getrewCookie(Conn,rewcAttrs,"",BVStr(cookie),AVStr(oa),sizeof(oa),AVStr(an),AVStr(dom),AVStr(ek),sizeof(ek)) == 0 )
			break;
		encryptCookie1(Conn,BVStr(cookie),oa,an,ek);
		if( strlen(rewcPfx) == 0 ){
			break;
		}
	}

	if( lSECRET() )
	fprintf(stderr,">>>>>>>>> %s\nSet-Cookie: %s\n",DST_HOST,cookie);
}

int hextoStr(PCStr(hex),PVStr(bin),int siz);
void decryptCookie1(Connection *Conn,PVStr(cookie),PCStr(oattr),PCStr(attrn),PCStr(rdom),PCStr(ekey)){
	CStr(chost,MaxHostNameLen);
	int cport;
	CStr(oa,4096);
	CStr(nattr,4096);
	CStr(xa,4096);
	int xalen;
	int ocrc;
	int crc;
	const char *dattrn = attrn+strlen(rewcPfx);
	CStr(dom,MaxHostNameLen);
	CStr(path,256);

	ocrc = -1;
	truncVStr(oa);
	Xsscanf(oattr,"%X.%s",&ocrc,AVStr(oa));

	xalen = hextoStr(oa,AVStr(xa),sizeof(xa));
	setVStrEnd(xa,xalen);
	crc = CreyDecrypts(ekey,strlen(ekey),AVStr(xa),xalen);

	if( crc != ocrc ){
		daemonlog("F","## Decrypt-Cookie: CRC error: %X %X [%s]\n",
			ocrc,crc,attrn);
		return;
	}
	if( Xsscanf(xa,"%[^:]:%[^:]:%[^:]:%d:%[^\n]",AVStr(dom),AVStr(path),AVStr(chost),&cport,AVStr(oa)) == 5 ){
		if( dom[0] ){
			if( streq(dom,"=") ){
				strcpy(dom,chost);
			}
			if( !dommatch(Conn,dom,attrn) ){
				LSEC("## Decrypt-Cookie: domain[%s] != %s:%d\n",
					dom,DST_HOST,DST_PORT);
 fprintf(stderr,"## Decrypt-Cookie: ERROR %s:%d != %s@%s:%d(%s)\n",
	DST_HOST,DST_PORT,attrn,chost,cport,dom);
				return;
			}
		}
		if( !strcaseeq(DST_HOST,chost) ){
			if( dommatch(Conn,rdom,attrn) ){
				LSEC("## Decrypt-Cookie: %s <= %s ALLOW\n",
					chost,dom);
			}else{
 fprintf(stderr,"## Decrypt-Cookie: ERROR %s:%d != %s@%s:%d(%s)[%s]\n",
	DST_HOST,DST_PORT,attrn,chost,cport,dom,rdom);
				LSEC("## Decrypt-Cookie: [%s][%s] != %s:%d\n",
					chost,rdom,DST_HOST,DST_PORT);
				return;
			}
		}
		LSEC("## Decrypt-Cookie: %s[%s] %s\n",chost,DST_HOST,attrn);
		if( lSECRET() ){
 fprintf(stderr,"## Decrypt-Cookie: OK %s:%d == %s@%s:%d(%s)[%s]\n",
			DST_HOST,DST_PORT,attrn,chost,cport,dom,rdom);
		}
		sprintf(nattr,"%s=%s;",dattrn,oa);
		Strins(AVStr(cookie),nattr);
	}
	else{
		daemonlog("F","## Decrypt-Cookie: BAD FORM[%s]=%s\n",attrn,xa);
	}
}
void decryptCookie(Connection *Conn,PVStr(cookie)){
	CStr(oa,4096);
	CStr(an,128);
	CStr(dom,256);
	CStr(ek,128);
	int na;

	if( lSECRET() )
	fprintf(stderr,"<<<<<<<<< %s\nCookie: %s\n",DST_HOST,cookie);

	if( strlen(rewcPfx) )
	for( na = 0; na < 10; na++ ){
		const char *dattrn;
		CStr(da,4096);
		dattrn = an + strlen(rewcPfx);
		if( getParamX(BVStr(cookie),dattrn,AVStr(da),sizeof(da),1,1) ){
		}
	}
	for( na = 0; na < 10; na++ ){
		if( getrewCookie(Conn,rewcAttrs,rewcPfx,AVStr(cookie),AVStr(oa),sizeof(oa),AVStr(an),AVStr(dom),AVStr(ek),sizeof(ek)) == 0 ){
			break;
		}
		decryptCookie1(Conn,BVStr(cookie),oa,an,dom,ek);
		if( strlen(rewcPfx) == 0 ){
			break;
		}
	}
	for( na = 0; na < 10; na++ ){
		if( getrewCookie(Conn,delcAttrs,"",AVStr(cookie),AVStr(oa),sizeof(oa),AVStr(an),AVStr(dom),AVStr(ek),sizeof(ek)) == 0 ){
			break;
		}
	}
	if( lSECRET() )
	fprintf(stderr,">>>>>>>>> %s\nCookie: %s\n",DST_HOST,cookie);
}
