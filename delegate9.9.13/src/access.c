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
Program:	access.c (Access Control)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

  AUTH = what : authProto : valid-user@host-list

    AUTH=manager:*:user@host
    AUTH=anonftp:*:user@host
    AUTH=anonftp:smtp-vrfy:user@host
    AUTH=proxy:{auth,pauth}  ... authorization is done by RELIABLE/PREMIT

    AUTH=authgen:basic:authString
    AUTH=fromgen:fromString
    AUTH=forward:paramList
    AUTH=log:remoteHost:Ident:authUser

History:
	940303	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "ystring.h"
#include "hostlist.h"
#include "vaddr.h"
#include "delegate.h"
#include "file.h"
#include "credhy.h"
#include "auth.h"
#include "param.h"

HostList *ReliableHosts();
HostList *ReachableHosts();
int notREMITTABLE(Connection *Conn,PCStr(proto),int port);
HostList *NotifyPltfrmHosts();

double AUTHORIZER_TIMEOUT;
int AuthTimeout(Connection *Conn){
	if( ClientAuth.i_expire )
		return ClientAuth.i_expire;
	if( AUTHORIZER_TIMEOUT )
		return (int)AUTHORIZER_TIMEOUT;
	return 0;
}

int ftp_auth(FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(user),PCStr(pass));
int connect_to_servX(Connection *Conn, int fromC,int toC, int relay_input, int do_filter);
void VA_HL_pushClientInfo(double Now,VAddr *peerhost,VAddr *sockhost,int _self);
int HTTP_authorize_Digest(Connection *Conn,AuthInfo *ident,PCStr(dom),PCStr(user),PCStr(dpass),PVStr(serv),int port);
int pam_service(Connection *ctx,int forbidden,PVStr(req),PVStr(user),int *stcodep);
int pam_checkPasswd(Connection *ctx,PCStr(host),int port,PCStr(service),PCStr(user),PCStr(pass));
int get_MYAUTH(Connection *Conn,PVStr(myauth),PCStr(proto),PCStr(dhost),int dport);
int DELEGATE_permitM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);
int DELEGATE_rejectM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);
void putRejectList(PCStr(what),PCStr(dproto),PCStr(dhost),int dport,PCStr(dpath),PCStr(referer),PCStr(sproto),PCStr(shost),int sport,PCStr(suser),PCStr(auser),PCStr(apass),PCStr(reason));

int getEKey(Connection *ctx,FILE *tc,int com,PCStr(proto),PCStr(host),PCStr(port),PCStr(user),PCStr(pass),PVStr(ekey));

#define Ident()	getClientUserC(Conn)

#define A_MANAGER	"manager"
#define A_ADMIN		"admin"
#define A_ANONFTP	"anonftp"
#define A_ORIGIN	"origin"
#define A_PROXY		"proxy"
#define A_LOG		"log"
#define A_FORWARD	"forward"
#define A_VIAGEN	"viagen"
#define A_FROMGEN	"fromgen"
#define A_AUTHGEN	"authgen"
#define A_PAUTHGEN	"pauthgen"
#define A_PASS		"pass"

#define AP_SMTP_VERIFY	"smtp-vrfy"
#define AP_REQ_AUTH	"auth"	/* use auth. info. in request message */
#define AP_REQ_PAUTH	"pauth"	/* use proxy auth. info. in req. message */

typedef struct {
	MStr(	a_authority,1024);
	defQStr(a_authp); /**/
  const	char   *a_authv[32]; /**/
	int	a_authx;
} AuthEnv;
static AuthEnv *authEnv;
#define Auth	authEnv[0]
void minit_access()
{
	if( authEnv == 0 )
		authEnv = NewStruct(AuthEnv);
}
#define Authority	Auth.a_authority
/**/
#define Authp		Auth.a_authp
#define Authv		Auth.a_authv
#define Authx		Auth.a_authx

void scan_AUTH(Connection *Conn,PCStr(auth))
{
	int ai;
	CStr(autha,256);
	CStr(authb,256);

	if( streq(auth,A_ADMIN) ){
		/* AUTH=admin -> AUTH=admin:-pam:${OWNER} */
		sprintf(autha,"%s:-pam:%%O",A_ADMIN);
		auth = autha;
	}
	strfConnX(Conn,auth,AVStr(authb),sizeof(authb));
	if( strcmp(auth,authb) != 0 ){
		sv1log("AUTH=\"%s\" -> AUTH=\"%s\"\n",auth,authb);
		auth = authb;
	}

	for( ai = 0; ai < Authx; ai++ ){
		if( streq(Authv[ai],auth) ){
			/* maybe by duplicated initialization */
			return;
		}
	}
	if( elnumof(Authv) <= Authx ){
		daemonlog("F","ERROR: ignored too many AUTH -- %s\n",auth);
		return;
	}
	if( Authp == 0 )
		McpyQStr(Authp,Authority);
	Authv[Authx++] = Authp;
	strcpy(Authp,auth);
	Authp += strlen(Authp) + 1;
}
char *encryptMountPass(PCStr(a1));
static const char *encryptAuthAdmin(PCStr(a1)){
	CStr(user,64);
	CStr(pass,64);
	CStr(ab,256);
	CStr(argb,256);
	CStr(md5,64);

	truncVStr(user);
	truncVStr(pass);

	/* AUTH=admin:: */
	Xsscanf(a1+12,"%[^:]:%s",AVStr(user),AVStr(pass));
	if( strneq(pass,"MD5:",4) ){
		sprintf(ab,"%s:%s",user,pass);
	}else
	if( *pass ){
		toMD5(pass,md5);
		sprintf(ab,"%s:MD5:%s",user,md5);
		fprintf(stderr,"**** Encrypt it as AUTH=\"admin::%s\"\n",ab);
	}else{
		sprintf(ab,"%s",user);
	}
	sprintf(argb,"AUTH=admin:-list{%s}",ab);
	return stralloc(argb);
}
const char *encryptAuthorizer(PCStr(pname),PCStr(pval));
int encrypt_argv(int ac,char *av[]){
	int ai;
	const char *a1;
	const char *na1;

	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		na1 = 0;
		if( strneq(a1,"AUTHORIZER=-userpass/",21) ){
			IStr(buf,256);
			refQStr(bp,buf);
			sprintf(buf,"AUTHORIZER=-list{%s}",a1+21);
			if( bp = strchr(buf,'/') ){
				setVStrElem(bp,0,':');
			}
			sv1log("CONV %s => %s\n",a1,buf);
			bzero((char*)a1,strlen(a1));
			na1 = a1 = stralloc(buf);
			av[ai] = (char*)a1;
		}
		if( strneq(a1,"AUTH=admin::",12) ){
			na1 = encryptAuthAdmin(a1);
		}
		else
		if( strneq(a1,"AUTHORIZER=",11) ){
			na1 = encryptAuthorizer("AUTHORIZER",a1+11);
			if( na1 )
				fprintf(stderr,"**** Encrypt it as %s\n",na1);
		}else
		if( strneq(a1,"MOUNT=",6) ){
			na1 = encryptMountPass(a1);
			if( na1 )
				fprintf(stderr,"**** Encrypt it as %s\n",na1);
		}
		if( na1 ){
			bzero((char*)a1,strlen(a1)); /*clear pass. on the mem*/
			av[ai] = (char*)na1;
			sv1log("encrypted -> %s\n",na1);
		}
	}
	/*
	for( ai = 0; ai < ac; ai++ ){
		fprintf(stderr,"[%d] %s\n",ai,av[ai]);
	}
	*/
	return ac;
}

static const char *find_auth(PCStr(what),PCStr(val))
{	int ai;
	int len,vlen;
	const char *auth1;
	const char *val1;

	len = strlen(what);
	if( val )
		vlen = strlen(val);
	else	vlen = 0;
	for( ai = 0; ai < Authx; ai++ ){
		auth1 = Authv[ai];
		if( strncmp(auth1,what,len) != 0 )
			continue;
		if( auth1[len] == 0 )
			val1 = &auth1[len];
		else
		if( auth1[len] == ':' )
			val1 = &auth1[len+1];
		else	continue;

		if( val == NULL )
			return val1;
		if( strncmp(val1,val,vlen) == 0 ){
			if( val1[vlen] == 0 )
				return &val1[vlen];
			if( val1[vlen] == ':' )
				return &val1[vlen+1];
		}
	}
	return 0;
}
int findPass(PCStr(proto),PCStr(user),PVStr(pass)){
	CStr(xauth,128);
	const char *pa;

	sprintf(xauth,"%s:%s",proto,user);
	if( pa = find_auth("pass",xauth) ){
		strcpy(pass,pa);
		return 1;
	}else{
		truncVStr(pass);
		return 0;
	}
}
static int findAuth(Connection *Conn,PCStr(what),PCStr(proto),PCStr(auth))
{	CStr(xauth,1024);

	if( strcasecmp(proto,AP_SMTP_VERIFY) != 0 )
		proto = "*";

	sprintf(xauth,"%s:%s",proto,auth);
	if( find_auth(what,xauth) )
		return 1;

	sprintf(xauth,"%s:*",proto);
	if( find_auth(what,xauth) )
		return 1;

	return 0;
}
/* AUTH=admin:authServ[:userList[:srcHostList]] */
const char *getAdminAuthorizer(Connection *Conn,PVStr(authsv),int asiz,int any){
	const char *fmt;
	const char *users;

	if( fmt = find_auth(A_ADMIN,NULL) ){
		const char *av[2];
		int ac;
		ac = list2vectX(fmt,':',STR_OVWR|STR_RO,2,av);
		if( ac == 2 )
			users = av[1];
		else	users = fmt + strlen(fmt) + 1;
		if( any || strncmp(fmt,"*:",2) != 0 ){
			if( authsv ){
				QStrncpy(authsv,fmt,users-fmt);
			}
			return users;
		}
	}
	return 0;
}
int CTX_with_auth_admin(Connection *Conn)
{
	if( find_auth(A_ADMIN,NULL) )
		return 1;
	else	return 0;
}
int CTX_auth_admin(Connection *Conn,PCStr(what),PCStr(proto),PCStr(userhost))
{
	if( findAuth(Conn,A_ADMIN,proto,userhost) )
		return 1;
	return findAuth(Conn,A_MANAGER,proto,userhost);
}
int CTX_with_auth_anonftp(Connection *Conn)
{
	if( find_auth(A_ANONFTP,NULL) )
		return 1;
	else	return 0;
}
int CTX_auth_anonftp(Connection *Conn,PCStr(proto),PCStr(user),PCStr(pass))
{
	if( find_auth(A_ANONFTP,NULL) == 0 )
		return 1;

	if( is_anonymous(user) || user[0] == 0 )
		return 0;
	if( strchr(user,'@') == 0 )
		return 0;
	return findAuth(Conn,A_ANONFTP,proto,pass);
}
int auth_origin_auth()
{
	if( find_auth(A_ORIGIN,AP_REQ_AUTH) )
		return 1;
	else	return 0;
}
int auth_proxy_auth()
{
	if( find_auth(A_PROXY,AP_REQ_AUTH) )
		return 1;
	else	return 0;
}
int auth_proxy_pauth()
{
	if( find_auth(A_PROXY,AP_REQ_PAUTH) )
		return 1;
	else	return 0;
}

int NotifyPlatform(Connection *Conn,int isreq)
{	const char *host;
	CStr(hostb,MaxHostNameLen);
	const char *user;
	int port,match;
	HostList *notplat;

	notplat = NotifyPltfrmHosts();
	if( isreq ){
		host = DST_HOST;
		port = DST_PORT;
		user = "-";
	}else{
		host = hostb;
		port = getClientHostPort(Conn,AVStr(hostb));
		user = "-";
	}
	match = hostIsinList(notplat,DST_PROTO,host,port,user);
	return match;
}
void makeVia(Connection *Conn,PVStr(via))
{	const char *fmt;

	if( fmt = find_auth(A_VIAGEN,NULL) ){
		if( strcmp(fmt,"-") == 0 ){
			setVStrEnd(via,0);
		}else
		if( *fmt == 0 )
			ClientIF_HP(Conn,AVStr(via));
		else	strfConnX(Conn,fmt,AVStr(via),256);
	}else{
		strcpy(via,"-");
	}
}
int makeForwarded(Connection *Conn,PVStr(forwarded))
{	CStr(myuri,256);
	CStr(client,MaxHostNameLen);
	CStr(myhp,MaxHostNameLen);

	if( find_auth(A_FORWARD,NULL) ){
		ClientIF_HP(Conn,AVStr(myhp));
		sprintf(myuri,"http://%s/",myhp);
		getClientHostPort(Conn,AVStr(client));
	}else{
		return 0;
		/*
		strcpy(myuri,"-");
		strcpy(client,"-");
		*/
	}
	sprintf(forwarded,"by %s (DeleGate/%s) for %s",
		myuri,(char*)DELEGATE_ver(),client);

	return 1;
}

int makeAuthorization(Connection *Conn,PVStr(genauth),int proxy)
{	const char *fmt;
	CStr(atype,128);
	const char *afmt;
	CStr(gauth,256);
	CStr(eauth,256);
	CStr(host,128);
	int port;
	const char *dp;
	CStr(authb,256);
	CStr(fmtb,256);

	authb[0] = 0;
	if( !proxy && ClientAuth.i_stat == AUTH_FORW ){
		sprintf(authb,"%s:%s",ClientAuth.i_user,ClientAuth.i_pass);
	}else
	/*
	if( streq(GatewayProto,"ssltunnel") ){
	*/
	if( proxy && streq(GatewayProto,"ssltunnel") ){
		get_MYAUTH(Conn,AVStr(authb),"ssltunnel",GatewayHost,GatewayPort);
		if( authb[0] == 0 )
		get_MYAUTH(Conn,AVStr(authb),"http-proxy",GatewayHost,GatewayPort);
	}else
	if( proxy ){
		if( toProxy && streq(GatewayProto,"http") )
		get_MYAUTH(Conn,AVStr(authb),"http-proxy",GatewayHost,GatewayPort);
	}else{
		get_MYAUTH(Conn,AVStr(authb),"http",DST_HOST,DST_PORT);
	}
	if( authb[0] ){
		sprintf(fmtb,"basic:%s",authb);
		fmt = fmtb;
	}else{
	if( proxy ){
	if( (fmt = find_auth(A_PAUTHGEN,NULL)) == NULL )
		return 0;
	}else
	if( (fmt = find_auth(A_AUTHGEN,NULL)) == NULL )
		return 0;
	}
	strcpy(atype,fmt);
	if( afmt = strchr(atype,':') ){
		truncVStr(afmt); afmt++;
	}else	afmt = "";
	atype[0] = toupper(atype[0]);

	strfConnX(Conn,afmt,AVStr(gauth),sizeof(gauth));
	if( gauth[0] == 0 )
		return 0;

	if( authb[0] == 0 )
	if( !proxy ){
		gethostname(host,sizeof(host));
		strcat(gauth,"/");
		strcat(gauth,host);
	}

	str_to64(gauth,strlen(gauth),AVStr(eauth),512,1);
	if( dp = strpbrk(eauth,"\r\n") )
		truncVStr(dp);

	sprintf(genauth,"%s %s",atype,eauth);
	return 1;
}
int getMyauthB64(Connection *Conn,PCStr(proto),PVStr(auth),int asiz){
	IStr(eauth,128);
	if( get_MYAUTH(Conn,AVStr(eauth),proto,DST_HOST,DST_PORT) ){
		str_to64(eauth,strlen(eauth),BVStr(auth),asiz,1);
		strsubst(BVStr(auth),"\r","");
		strsubst(BVStr(auth),"\n","");
		return 1;
	}else{
		clearVStr(auth);
		return 0;
	}
}

int makeFrom(Connection *Conn,PVStr(genfrom))
{	const char *fmt;

	setVStrEnd(genfrom,0);
	if( (fmt = find_auth(A_FROMGEN,NULL)) == NULL )
		return 0;

	if( *fmt == 0 )
		fmt = "%u@%h";
	strfConnX(Conn,fmt,AVStr(genfrom),256);
	return 1;
}

void makeClientLog(Connection *Conn,PVStr(clientlog))
{	CStr(host,MaxHostNameLen);
	CStr(iuser,256);
	CStr(auser,256);
	const char *hfmt;
	const char *ifmt;
	const char *afmt;
	CStr(xhfmt,128);
	CStr(xifmt,128);
	CStr(xafmt,128);
	const char *fmt;

	hfmt = "%h";
	ifmt = "%u";
	afmt = "%U";
	if( fmt = find_auth(A_LOG,NULL) ){
		xhfmt[0] = xifmt[0] = xafmt[0] = 0;
		scan_Listlist(fmt,':',AVStr(xhfmt),AVStr(xifmt),AVStr(xafmt),VStrNULL,VStrNULL);
		if( xhfmt[0] ) hfmt = xhfmt;
		if( xifmt[0] ) ifmt = xifmt;
		if( xafmt[0] ) afmt = xafmt;
	}

	strfConnX(Conn,hfmt,AVStr(host),sizeof(host));  if(host[0] ==0) strcpy(host,"-");
	strfConnX(Conn,ifmt,AVStr(iuser),sizeof(iuser)); if(iuser[0]==0) strcpy(iuser,"-");
	strfConnX(Conn,afmt,AVStr(auser),sizeof(auser)); if(auser[0]==0) strcpy(auser,"-");

	sprintf(clientlog,"%s %s %s",host,iuser,auser);
}

/*
 *	If no RELIABLE host is specified explicitly, then suppose that any
 *	hosts is relaible.  Typical case is that the DeleGate is running
 *	on the host which belongs to a secure network within a firewall.
 */
extern const char *hostmatch_ignauth;
int tobeREJECTED(Connection *Conn){
	HostList *hostlist;
	IStr(shost,MaxHostNameLen);
	int sport;
	const char *suser;
	int ac = 0;
	AuthInfo *av[1];
	int isrel;

	hostlist = ReliableHosts();
	if( hostlist->hl_cnt == 0 )
		return 0;
	sport = getClientHostPort(Conn,AVStr(shost));
	if( sport <= 0 )
		return 0;
	suser = hostmatch_ignauth;
	isrel = hostIsinListX(hostlist,DFLT_PROTO,shost,sport,suser,ac,av);
	return isrel == 0;
}
static int RELIABLE_HOST(Connection *Conn,HostList *hostlist,PCStr(srchost),int srcport)
{	const char *suser;
	int ac;
	AuthInfo *av[4]; /**/

	if( hostlist->hl_cnt == 0 )
		return 1;

	suser = Ident();
	if( suser == 0 && Conn->no_authcheck )
		suser = hostmatch_ignauth;
	ac = getClientAuthList(Conn,4,av);
	HLdebug("{HL} RELIABLE\n");
	return hostIsinListX(hostlist,DFLT_PROTO,srchost,srcport,suser,ac,av);
/*
{
CStr(ohost,128);
getOriginator(ohost);
printf("ROUTE: %s [%s]\n",CTX_get_PATH(Conn),ohost);
}
*/
/*
		if( suser == NULL ){
			CStr(qhost,128);
			CStr(quser,128);
			if( get_equiv_user(srchost,srcport,qhost,quser) ){
				suser = quser;
				srchost = qhost;
				srcport = 0;
			}
		}
*/
}
static int REACHABLE_HOST(Connection *Conn,HostList *hostlist,PCStr(proto),PCStr(hostname),int dstport)
{	const char *duser = Conn ? DST_USER : NULL;

	if( hostlist->hl_cnt == 0 )
		return 1;
	if( Conn != NULL && Conn->no_dstcheck )
		return 1;

	return hostIsinList(hostlist,proto,hostname,dstport,duser);
}
int source_permitted(Connection *Conn)
{	int ok;
	int dstcheck;

	dstcheck = Conn->no_dstcheck;
	Conn->no_dstcheck = 1;
	ok = service_permitted2(Conn,DST_PROTO,1);
	Conn->no_dstcheck = dstcheck;
	/*
	Conn->no_dstcheck = 0;
	*/
	return ok;
}
int source_permittedX(Connection *Conn)
{	int ok;

	Conn->no_authcheck = 1;
	ok = source_permitted(Conn);
	Conn->no_authcheck = 0;
	return ok;
}
int service_permitted0X(PCStr(clhost),int clport,PCStr(svproto),PCStr(svhost),int svport,int silent);
int service_permitted0(PCStr(clhost),int clport,PCStr(svproto),PCStr(svhost),int svport)
{
	return service_permitted0X(clhost,clport,svproto,svhost,svport,0);
}
int service_permitted0X(PCStr(clhost),int clport,PCStr(svproto),PCStr(svhost),int svport,int silent)
{	Connection ConnBuf, *Conn = &ConnBuf;
	int ok;

	ConnInitNew(Conn); /* v9.9.12 fix-140912a */
	if( clhost ){
		strcpy(Client_Host,clhost);
	}else{
		Client_Host[0] = 0;
	}
	Client_Port = clport;
	set_realsite(Conn,svproto,svhost,svport);
	ok = service_permitted2(Conn,svproto,1);

	if( !silent )
	if( !ok ){
		daemonlog("E","No permission: %s:%d > %s://%s:%d\n",
			clhost,clport,svproto,svhost,svport);
	}
	return ok;
}
int method_permitted0()
{
	return 1;
}

/*
 *	Not implemented yet
 *	(This is done in RELIABLE_HOST() ?)
 */
static int PERMITTED_USER(Connection *Conn,HostList *hostlist,PCStr(hostname),int lport,int stdport)
{
	if( hostlist->hl_cnt == 0 )
		return 1;
	return 1;
}

static int PERMITTED_PORT(Connection *Conn,PCStr(proto),PCStr(host),int port)
{	int stdport;

	if( streq(proto,"telnet") ){
	    stdport = serviceport("telnet");

if( getenv("ANYPORT") == 0 )
	    if( port != 0 && port != stdport ){
		if( ImProxy )
			sv1log("Proxy telnet follows PERMIT parameter\n");
		else
		if( streq(iSERVER_PROTO,"telnet") && port==iSERVER_PORT )
			sv1log("TELNET to non-standard port: %d %d/%d\n",
				port,DFLT_PORT,iSERVER_PORT);
		else{
			Verbose("cannot TELNET to non-standard port %d\n",
				DFLT_PORT);
			return 0;
		}
	    }
	}
	if( port == 19 ){
		if( streq(proto,"http") || streq(proto,"gopher") ){
			sv1log("HTTP,Gopher to 19(chargen) is inhibited.\n");
			return 0;
		}
	}
	return 1;
}
static int PERMITTED_PAIR(Connection *Conn,PCStr(proto),PCStr(dhost),int dport,PCStr(shost),int sport)
{
	return DELEGATE_permitM(Conn,proto,NULL,dhost,dport,shost,sport);
}

int PERMITTED_ACCESS(Connection *Conn,PCStr(shost),int sport,int stdport)
{	int permitted = 0;

	Conn->reject_reason[0] = 0;
	if( ConnectFlags & COF_SCREENED ){
		sprintf(Conn->reject_reason,"'%s' by SCREEN",shost);
		Verbose("rejected by SCREEN\n");
	}else
	if(!RELIABLE_HOST(Conn,ReliableHosts(),shost,sport))
	{
		sprintf(Conn->reject_reason,"'%s' not RELIABLE",shost);
		Verbose("not RELIABLE\n");
	}
	else
	if(!PERMITTED_USER(Conn,ReliableHosts(),shost,sport,stdport))
	{
		sprintf(Conn->reject_reason,"not PERMITTED_USER");
		Verbose("not PERMITTED_USER\n");
	}
	else
	if(!REACHABLE_HOST(Conn,ReachableHosts(),DST_PROTO,DST_HOST,DST_PORT))
	{
		sprintf(Conn->reject_reason,"'%s' not REACHABLE",DST_HOST);
		Verbose("not REACHABLE\n");
	}
	else
	if(!PERMITTED_PORT(Conn,DST_PROTO,DST_HOST,DST_PORT))
	{
		sprintf(Conn->reject_reason,"not PERMITTED_PORT");
		Verbose("not PERMITTED_PORT\n");
	}
	else
	if( DELEGATE_rejectM(Conn,DST_PROTO,NULL,DST_HOST,DST_PORT,shost,sport) ){
		Verbose("REJECTED_PAIR\n");
		sprintf(Conn->reject_reason,"matched REJECT");
	}else
	if(!PERMITTED_PAIR(Conn,DST_PROTO,DST_HOST,DST_PORT,shost,sport))
	{
		Verbose("not PERMITTED_PAIR {%s}\n",Conn->reject_reason);
		if( Conn->reject_reason[0] == 0 )
		sprintf(Conn->reject_reason,"unmatch PERMIT");
	}
	else
	{
		permitted = 1;
	}

if(!permitted)
if(LOG_GENERIC){
const char *user;
if( (user = getClientUserC(Conn)) == NULL )
	user = "-";
fputLog(Conn,"Reject","%s@%s:%d; to=%s://%s:%d\n",
user,shost,sport,
DST_PROTO,DST_HOST,DST_PORT);
}

	return permitted;
}

int VA_strtoVAddr(PCStr(saddr),VAddr *Vaddr);
int VA_atoVAddr(PCStr(aaddr),VAddr *Vaddr);
int getClientAddr(Connection *Conn,PVStr(iaddr),int isize){
	if( TeleportHost[0] ){
		VAddr va;
		VA_strtoVAddr(TeleportAddr,&va);
		Verbose("getClientAddr Teleport[%s][%s]%X : %X\n",
			TeleportHost,TeleportAddr,va.I3,Client_VAddr->I3);
		Bcopy(&va.a_ints,iaddr,isize);
	}else
	Bcopy(&Client_VAddr->a_ints,iaddr,isize);
	return 1;
}
void VA_setClientAddr(Connection *Conn,PCStr(addr),int port,int remote)
{
	VA_setVAddr(Client_VAddr,addr,port,remote);
}
int VA_getClientAddr(Connection *Conn)
{
	if( Client_Port == 0 && (Client_VAddr->a_flags & VA_SOCKPAIR) ){
		/* don't repeat getpeername() successfull but port==0 */
	}else
	if( 0 <= ClientSock )
	if( Client_Port == 0 ){
		VA_getpeerNAME(ClientSock,Client_VAddr);
	}
	if( Client_Port == 0 && (Client_VAddr->a_flags & VA_SOCKPAIR) ){
		if( lSOCKPAIRNM() ){ /* to distinguisch socketpair */
			Client_VAddr->I3 = 0xFFFFFFFF;
			Client_Port = 0xFFFF;
			strcpy(Client_Host,"--Socket-Pair.-");
		}
	}
	return 0 < Client_Port;
}
int getClientHostPortAddr(Connection *Conn,PVStr(rhost),PVStr(raddr))
{
	VA_getClientAddr(Conn);

	if( Client_Port <= 0 ){
		if( rhost != NULL ) strcpy(rhost,"--Cant-GetPeerName");
		if( raddr != NULL ) strcpy(raddr,"255.255.255.255");
		return 0;
	}

	if( rhost != NULL ) strcpy(rhost,Client_Host);
	if( raddr != NULL ) VA_inetNtoah(Client_VAddr,AVStr(raddr));
	return Client_Port;
}
int getClientHostPort(Connection *Conn,PVStr(rhost))
{
	return getClientHostPortAddr(Conn,BVStr(rhost),VStrNULL);
}


/*
 *	PERMIT about RELAY function
 *	control accessibility of relay function
 */
static scanListFunc scan_relay1(PCStr(r1),int *maskp)
{
	if( streq(r1,"novhost")  ) *maskp &= ~RELAY_VHOST;
	if( streq(r1,"vhost")    ) *maskp |= RELAY_VHOST;
	if( streq(r1,"origdst")  ) *maskp |= RELAY_ORIGDST;
	if( streq(r1,"y11")      ) *maskp |= RELAY_Y11;
	if( streq(r1,"yy")       ) *maskp |= RELAY_YYMUX;
	if( streq(r1,"tproxy")   ) *maskp |= RELAY_VHOST;
	if( streq(r1,"proxy")    ) *maskp |= RELAY_PROXY;
	if( streq(r1,"delegate") ) *maskp |= RELAY_DELEGATE;
	if( streq(r1,"noapplet") ) *maskp &= ~RELAY_APPLET;
	if( streq(r1,"nojava")   ) *maskp &= ~RELAY_JAVA;
	return 0;
}
static int scan_relay(PCStr(realm))
{	int mask;

/*
	mask = RELAY_VHOST | RELAY_JAVA | RELAY_APPLET;
*/
	mask = RELAY_JAVA | RELAY_APPLET;
	scan_List(realm,',',0,scanListCall scan_relay1,&mask);
	if( mask & RELAY_ORIGDST ){
		LOG_type4 |= L_ORIGDST;
	}
	return mask;
}
scanListFunc scan_RELAY1(PCStr(relay1),Connection *Conn)
{
	scan_CMAP2(Conn,"relay",relay1);
	return 0;
}
void scan_RELAY(Connection *Conn,PCStr(relay))
{
	scan_List(relay,';',0,scanListCall scan_RELAY1,Conn);
}
int do_RELAY(Connection *Conn,int what)
{	CStr(realm,128);
	int found;
	int caps,relay;

	/* this function should be unified with service_permitted() ... */
	if( Conn->from_myself )
		return 1;

	CTX_pushClientInfo(Conn);
	relay = 0;
	for( found = 0;; found++){
		found = find_CMAPi(Conn,"relay",found,AVStr(realm));
		if( found < 0 )
			break;
		caps = scan_relay(realm);
		if( (caps & what) == what ){
			relay = caps;
			break;
		}
	}
	HL_popClientInfo();
	return relay;
}

Connection *FORCE_REWRITE = (Connection*)-1;
/*
it's too heavy to be checked for each embedded URL in HTML...

int isRELAYABLE(Connection *Conn,PCStr(proto),PCStr(hostport))
{
	if( Conn == FORCE_REWRITE )
		return 1;
	return do_RELAY(Conn,RELAY_DELEGATE);
}
*/

int isREACHABLE(PCStr(proto),PCStr(hostport))
{	CStr(host,512);
	int port;
	int svf,yes;

	port = scan_hostport(proto,hostport,AVStr(host));
	svf = RES_CACHEONLY(1);
	yes = REACHABLE_HOST(NULL,ReachableHosts(),ANYP,host,port);
	RES_CACHEONLY(svf);
	return yes;
}

int NotREACHABLE(Connection *Conn,PCStr(proto),PCStr(host),int port)
{	int reach;

	if( Conn != NULL && Conn->no_dstcheck ){
		return 0;
	}

	if( Conn != NULL
	 && Conn->no_dstcheck_proto
	 && Conn->no_dstcheck_proto == serviceport(proto) )
		return 0;

	if( notREMITTABLE(Conn,proto,port) )
	{
		if( Conn != NULL )
		sprintf(Conn->reject_reason,"%s/%d not REMITTABLE",proto,port);
		return 1;
	}

	CTX_pushClientInfo(Conn);
	reach = REACHABLE_HOST(NULL,ReachableHosts(),proto,host,port);
	HL_popClientInfo();
	if( !reach )
	{
		return 1;
	}

	return 0;
}

void addRejectList(Connection *Conn,PCStr(what),PCStr(dpath),PCStr(referer),PCStr(auser),PCStr(apass),PCStr(reason))
{	CStr(src_host,MaxHostNameLen);
	const char *src_user;
	int src_port;

	if( lSINGLEP() ){
		int getthreadid();
		fprintf(stderr,"-- [%d]%X no addRejectList: %s://%s:%d (%s)\n",
			SVX,TID,DST_PROTO,DST_HOST,DST_PORT,reason);
		return;
	}
	src_user = getClientHostPortUser(Conn,AVStr(src_host),&src_port);
	if( src_user == NULL )
		src_user = "-";

	if( *apass != 0 )
	if( !strcaseeq(auser,"anonymous") )
	if( !strcaseeq(auser,"ftp") || !strcaseeq(DST_PROTO,"ftp") )
		apass = "*";

	if( *referer == 0 )
		referer = "-";

	putRejectList(what,
		DST_PROTO, DST_HOST,DST_PORT, dpath, referer,
		DFLT_PROTO,src_host,src_port, src_user,
		auser,apass,reason);
}
static void local_auth(PVStr(path),PVStr(uh),PCStr(proto),PCStr(user),PCStr(host),int port)
{	CStr(uh_md5,64);

	if( host[0] == 0 ) Xstrcpy(ZVStr((char*)host,16),"localhost"); /* not "const" but fixed */
	if( port == 0 ) port = serviceport(proto);

	sprintf(uh,"%s://%s@%s:%d",proto,user,host,port);
	toMD5(uh,uh_md5);
	sprintf(path,"${ADMDIR}/authorizer/%s/%s",host,uh_md5);
	DELEGATE_substfile(AVStr(path),"",VStrNULL,VStrNULL,VStrNULL);
}
void DGAuth_file(PVStr(path),PVStr(uh),PCStr(proto),PCStr(user),PCStr(host),int port)
{
	local_auth(AVStr(path),AVStr(uh),proto,user,host,port);
}

/*
 * AUTHORIZER=-dgauth[.realm][//server..port]
 */
int scanAuthServPort(PCStr(domain),PVStr(serv))
{	int port;
	const char *dp;

	setVStrEnd(serv,0);
	port = 0;
	if( dp = strstr(domain,"//") ){
		truncVStr(dp);
		wordscanX(dp+2,AVStr(serv),64);
		if( dp = strstr(serv,"..") ){
			truncVStr(dp);
			port = atoi(dp+2);
		}
	}
	return port;
}

extern char DGAUTHpro[];
extern char DGAUTHdom[];

int authEdit(Connection *ctx,int detail,FILE *tc,int com,PCStr(proto),PCStr(host),int port,PCStr(user),PCStr(pass),PCStr(ekey),int expire);
int authedit_main(int ac,const char *av[],Connection *ctx)
{	const char *userpass;
	CStr(user,64);
	CStr(pass,64);
	const char *hostport;
	CStr(host,64);
	CStr(port,64);
	const char *dp;
	int expire;
	FILE *afp,*tc;
	int com;
	CStr(ekey,64);
	int elen;
	int remote;
	const char *proto;

	tc = stdout;
	if( ac < 4 || av[1][0] != '-' ){
		fprintf(tc,
		"-USAGE: %s -{a|d|v|V} user[:pass] host[:port] [expire]\r\n",
			av[0]);
		return -1;
	}
	userpass = av[2];
	hostport = av[3];
	scan_namebody(userpass,AVStr(user),sizeof(user),":",AVStr(pass),sizeof(pass),NULL);
	scan_namebody(hostport,AVStr(host),sizeof(host),":",AVStr(port),sizeof(port),NULL);
	expire = 0;

	com = av[1][1];
	ekey[0] = 0;
	if( com == 'a' ){
		const char *dp;
		if( pass[0] == 0 ){
			fprintf(tc,"Password (not hidden): ");
			fflush(tc);
			fgets(pass,sizeof(pass),stdin);
			if( dp = strpbrk(pass,"\r\n") )
				truncVStr(dp);
		}
	}

	if( strneq(host,DGAUTHdom,7) )
		proto = DGAUTHpro;
	else	proto = "ftp";
	remote = strstr(host,"//") != 0;
	if( com == 'a' || remote ){
		if( remote || ekey[0] == 0 && streq(proto,DGAUTHpro) ){
			elen = getEKey(ctx,tc,com,proto,host,port,user,pass,AVStr(ekey));
			if( elen <= 0 )
				return 0;
		}
	}

	authEdit(ctx,1,tc,com,proto,host,atoi(port),user,pass,ekey,expire);
	return 0;
}
void showPass(Connection *ctx,FILE *out,PCStr(tmp),int com,PCStr(host),PCStr(user),PCStr(pass));
int authEdit0(Connection *ctx,int detail,FILE *tc,int com,PCStr(host),PCStr(user),PCStr(pass))
{	const char *proto;
	CStr(ekey,256);
	int elen,rcode;

	if( strneq(host,DGAUTHdom,7) ){
		proto = DGAUTHpro;
		elen = getCKey(AVStr(ekey),sizeof(ekey));
		/*
		elen = getEKey(ctx,tc,com,proto,host,"",user,pass,ekey);
		*/
	}else	proto = "ftp";
	rcode = authEdit(ctx,detail,tc,com,proto,host,0,user,pass,ekey,0);
	bzero(ekey,sizeof(ekey));
	return rcode;
}
int authEdit(Connection *ctx,int detail,FILE *tc,int com,PCStr(proto),PCStr(host),int port,PCStr(user),PCStr(pass),PCStr(ekey),int expire)
{	CStr(uh,MaxHostNameLen);
	CStr(epass,128);
	CStr(pw_md5,64);
	CStr(path,1024);
	FILE *afp;
	int rcode;

	local_auth(AVStr(path),AVStr(uh),proto,user,host,port);
	rcode = 0;

	switch( com ){
	  case 'v':
	  case 'V':
	  default:
		if( File_is(path) ){
			fprintf(tc,"+OK current auth. for %s follows:\r\n",uh);
		}else{
			fprintf(tc,"-ERROR no auth. for %s\r\n",uh);
			rcode = -1;
		}
		break;
	  case 'd':
		rcode = unlink(path);
		if( rcode == 0 )
			fprintf(tc,"+OK removed the auth.\r\n");
		else	fprintf(tc,"-ERROR could not remove the auth. (errno=%d)\r\n",errno);
		break;

	  case 'a':
		if( File_is(path) ){
			fprintf(tc,"-ERROR the auth. exists already, remove it first by `-d' option\r\n");
			rcode = -1;
			break;
		}
		if( afp = dirfopen("AUTH",AVStr(path),"w") ){
			toMD5(pass,pw_md5);
			if( *ekey ){
			aencrypty(ekey,strlen(ekey),pass,strlen(pass),epass);
			fprintf(afp,"%s %s\r\n%d\r\n",pw_md5,epass,expire);
			}else{
			fprintf(afp,"%s\r\n%d\r\n",pw_md5,expire);
			}
			fprintf(tc,"+OK added the auth.\r\n");
			fclose(afp);
		}else{
			fprintf(tc,"-ERROR could not add the auth. (errno=%d)\r\n",errno);
			rcode = -1;
		}
		break;
	}
	if( detail ){
		fprintf(tc,"PATH: %s\r\n",path);
		fprintf(tc,"AUTH: %s\r\n",uh);
		if( afp = dirfopen("AUTH",AVStr(path),"r") ){
			CStr(tmp,128);
			strcpy(tmp,"\n");
			fgets(tmp,sizeof(tmp),afp);
			fprintf(tc,"PASS: %s",tmp);
			if( com == 'V' ){
				showPass(ctx,stderr,tmp,com,host,user,pass);
			}
			tmp[0] = 0;
			fgets(tmp,sizeof(tmp),afp);
			fprintf(tc,"EXPIRE: %s",atoi(tmp)==0?"never\r\n":tmp);
			fclose(afp);
		}
		fprintf(tc,"\r\n");
	}
	return rcode;
}
int CTX_auth_cache(Connection *ctx,int store,int expire,PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port)
{	CStr(uh,512);
	CStr(uh_md5,128);
	CStr(pw_md5,128);
	CStr(apath,1024);
	CStr(cpass,128);
	FILE *afp;
	CStr(hostb,128);
	const char *dp;
	CStr(lapath,1024);
	int authtime;
	Connection *Conn = ctx;

	if( strchr(host,'/') ){
		/* set by AUTHORIZER=host/port */
		dp = wordscanY(host,AVStr(hostb),sizeof(hostb),"^/");
		host = hostb;
		port = atoi(dp+1);
	}

	sprintf(uh,"%s://%s@%s:%d",proto,user,host,port);
	Verbose("AUTH_CACHE %d %s\n",store,uh);

	toMD5(uh,uh_md5);
	toMD5(pass,pw_md5);

	/*
	SPRINTF(rpath,"%d/%s",SERVER_PORT(),uh_md5);
	CTX_cache_path(ctx,"delegate","auth",9999,rpath,apath);
	*/
	local_auth(AVStr(lapath),AVStr(uh),proto,user,host,port);
	sprintf(apath,"%s-cache",lapath);

	authtime = time(0);
	if( store == 0 )
	if( AuthTimeout(Conn) ) /* need to check timeout */
	if( ClientSession[0] == 0 ) /* not checked with SessionCookie */
	{
		if( afp = dirfopen("AUTH",AVStr(apath),"r+") ){
			int mtime;
			IStr(authed,128);
			int age;
			int off;

			mtime = file_mtime(fileno(afp));
			Fgets(AVStr(authed),sizeof(authed),afp);
			off = ftell(afp);
			Fgets(AVStr(authed),sizeof(authed),afp);
			sscanf(authed,"Auth-Time: %d",&authtime);
			age = time(0) - authtime;

			sv1log("---- Auth-Age:%d/%d cacheAge=%d [%s]\n",
				age,AuthTimeout(Conn),ll2i(time(0)-mtime),user);
			if( AuthTimeout(Conn) < age ){
				fseek(afp,off,0);
				fprintf(afp,"Auth-Time: %d %d\n",itime(0),
					authtime);
				fclose(afp);
				set_utimes(apath,-1,mtime); /* restore mtime */
				ClientAuth.i_error |= AUTH_ESTALE;
				return -1;
			}
			fclose(afp);
		}
	}
	if( store ){
		if( afp = dirfopen("AUTH",AVStr(apath),"w") ){
			fprintf(afp,"%s\n",pw_md5);
			fprintf(afp,"Auth-Time: %d\n",authtime);
			fclose(afp);
			return 0;
		}else	return -1;
	}else{
		if( afp = fopen(lapath,"r") )
			sv1log("persistent auth: %s %s\n",uh,lapath);
		else	afp = expfopen("AUTH",expire,AVStr(apath),"r",NULL);
		if( afp ){
			cpass[0] = 0;
			Fgets(AVStr(cpass),sizeof(cpass),afp);
			fclose(afp);
			if( strcmp(pw_md5,cpass) == 0 ){
				Verbose("cached auth OK: %s@%s\n",user,host);
				return 1;
			}
		}
		return 0;
	}
}

#define IDENTIFY_MAP	"Identifier"
#define AUTHORIZE_MAP	"Authorizer"
#define AUTHSERV_MAP	"AuthServer"
const char *MAP_AUTHSERV = AUTHSERV_MAP;

#define I_IDENT		"?"
#define I_FTP		"&"
#define I_ANY		"*"
#define AUTH_VDOM	"-AUTH"

void scan_AUTHORIZER(Connection *Conn,PCStr(authserv))
{	CStr(vauthserv,MaxHostNameLen);
	CStr(aserv,MaxHostNameLen);
	CStr(proto,256);
	CStr(dhost,MaxHostNameLen);

/*
	if( !streq(authserv,I_IDENT) && !streq(authserv,I_FTP) ){
		if( num_ListElems(authserv,':') == 1 ){
			sprintf(vauthserv,"%s.%s",authserv,AUTH_VDOM);
			scan_RELIABLE(Conn,vauthserv);
		}else{
			scan_Listlist(authserv,':',aserv,proto,dhost,0);
			if( aserv[0] == 0 ) strcpy(aserv,"*");
			if( proto[0] == 0 ) strcpy(proto,"*");
			if( dhost[0] == 0 ) strcpy(dhost,"*");
			sprintf(vauthserv,"%s:%s:%s.%s",
				proto,dhost,aserv,AUTH_VDOM);
			scan_PERMIT(Conn,vauthserv);
		}
	}
*/
	CStr(asv,1024);
	CStr(xasv,1024);
	const char *cond;
	cond = scan_ListElem1(authserv,':',AVStr(asv));
	if( !lDONTHT() ){
		if( strneq(asv,"-ntht",5) ){
			LOG_type4 |= L_DONTHT;
		}
	}
	if( *cond == 0 && strcaseeq(iSERVER_PROTO,"delegate") ){
		sprintf(xasv,"%s:%s",authserv,"delegate,socks,http-proxy");
		authserv = xasv;
		InitLog(">>> AUTHORIZER=%s\n",authserv);
	}
	scan_CMAP2(Conn,AUTHSERV_MAP,authserv);
}

int AuthenticateY(Connection *Conn,PVStr(host),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident);

static int Identify(Connection *Conn,int identonly,FILE *fc,FILE *tc,PCStr(authserv),xPVStr(user),PVStr(host),PVStr(phost),iFUNCP func,AuthInfo *arg)
{	int ci;
	CStr(userhost,1024);
	CStr(pass,256);
	CStr(aproto,64);
	CStr(ahost,MaxHostNameLen);
	CStr(asvhost,MaxAuthServLen);
	int aport;
	CStr(clhost,MaxHostNameLen);
	const char *iuser;
	CStr(userb,256);
	UTag Tuserhost,Tpass;
	AuthInfo xarg;

	truncVStr(asvhost);

	setQStr(Tuserhost.ut_addr,userhost,sizeof(userhost));
	Tuserhost.ut_size = sizeof(userhost);
	setQStr(Tpass.ut_addr,pass,sizeof(pass));
	Tpass.ut_size = sizeof(pass);

	if( strchr(user,':') ){
		scan_namebody(user,AVStr(userb),128,":",AVStr(pass),128,"\r\n");
		setPStr(user,userb,sizeof(userb));
	}else	pass[0] = 0;

	getpeerNAME(FromC,AVStr(clhost));

	if( wordIsinList(authserv,I_IDENT) )
	if( iuser = getClientHostPortUser(Conn,AVStr(clhost),NULL) ){
		strcpy(user,iuser);
		strcpy(host,clhost);
		strcpy(phost,host);
		goto EXIT;
	}
 if( fc != NULL ){
	if( strcmp(authserv,"&") == 0 )
	fprintf(tc,">>>>>>>> login with your account at <%s>\r\n",clhost);

	fprintf(tc,">>>>>>>> Username: ");
	fflush(tc);
	setVStrEnd(host,0);
	setVStrEnd(user,0);
	setVStrEnd(userhost,0);

	ci = (*func)((void*)1,fc,tc,&Tuserhost,arg);
	if( userhost[0]  == 0 )
		return 0;
	if( ci == EOF )
		return 0;

	scan_namebody(userhost,AVStr(user),128,"@",AVStr(host),128," \t\r\n");
 }
	strcpy(phost,"******");

	if( host[0] ){
		if( wordIsinList(authserv,host) ){ 
			/* authorized */
		}else
		if( wordIsinList(authserv,I_FTP) && hostcmp(host,clhost) == 0 ){
			/* not authorized */
		}else
		if( wordIsinList(authserv,I_ANY) ){
			/* not authorized */
		}else{
			fprintf(tc,"!!!!!!!! %s: not authentiation server\r\n",
				host);
			fflush(tc);
			return 0;
		}
		strcpy(phost,host);
	}else
	if( 1 ){
		int ac,ai;
		CStr(udhost,64);
		/*
		CStr(ab,256);
		*/
		CStr(ab,MaxAuthServLen);
		refQStr(vp,asvhost);
		const char *av[8]; /**/
		const char *a1;
		const char *ao;

		wordScan(host,udhost);
/* udhost always empty... */
		lineScan(authserv,ab);
		ac = list2vect(ab,',',8,av);
		setVStrEnd(host,0);
		for( ai = 0; ai < ac; ai++ ){
			a1 = ao = av[ai];
			if( streq(a1,I_FTP)   ) ao = clhost; else
			if( streq(a1,I_IDENT) ) ao = clhost; else
			if( streq(a1,I_ANY)   ) ao = udhost;
			if( ao != a1 )
				strcpy(phost,ao);
			vp = Sprintf(AVStr(vp),"%s%s",asvhost[0]?",":"",ao);

		}
	}else{
		if( wordIsinList(authserv,I_FTP) ){
			/* authorized */
			strcpy(host,clhost);
			strcpy(phost,host);
		}else{
			/* authorized */
			Xsscanf(authserv,"%[^,]",AVStr(host));
		}
	}
	if( streq(host,I_ANY) ){
		fprintf(tc,"!!!!!!!! enter user@yourAuthHost\r\n");
		fflush(tc);
		return 0;
	}
/*
	if( !identonly && !service_authorized(Conn,user,host) ){
		fprintf(tc,"<<<<<<<< No, <%s@%s> is not an authorized user\r\n",
			user,phost);
		fflush(tc);
		return 0;
	}
*/

if( fc != NULL ){
	fprintf(tc,">>>>>>>> Password: ");
/*
	ci = (*func)(0,fc,tc,pass,arg);
*/
	ci = (*func)((void*)0,fc,tc,&Tpass,arg);
	if( ci == EOF )
		return 0;
	fflush(tc);
 }

	/*
	if( Authenticate(Conn,host,user,pass,"/") < 0 ){
	*/
	/*
	if( AuthenticateX(Conn,host,user,pass,"/",arg) < 0 ){
	*/
	if( arg == 0 ){
		/* to get host[] info into arg->i_Host[] */
		bzero(&xarg,sizeof(xarg));
		arg = &xarg;
	}
	if( asvhost[0] )
	if( 0 <= AuthenticateX(Conn,asvhost,user,pass,"/",arg) ){
		/* this function is desined to return the auth-host to host */
		if( arg  && host != arg->i_Host && arg->i_Host[0] ){
			strcpy(host,arg->i_Host);
			sv1log("-- matched '%s' in {%s}\n",host,asvhost);
		}
		return 1;
	}
	else{
		if( AuthTimeout(Conn) )
		if( ClientAuth.i_error & AUTH_ESTALE ){
			sv1log("---- Identity STALE %X\n",ClientAuth.i_error);
			return 0;
		}
	}
	if( host[0] == 0 || AuthenticateX(Conn,host,user,pass,"/",arg) < 0 ){
		if( user[0] || pass[0] )
		fprintf(tc,
		"!!!!!!!! USER <%s@%s> authentication failed\r\n",user,phost);
		fflush(tc);
		return 0;
	}

EXIT:
	return 1;
}

void setServerCert(Connection *Conn,PCStr(what),PCStr(mbox))
{	AuthInfo ident;
	const char *dp;

	bzero(&ident,sizeof(AuthInfo));
	dp = wordscanY(mbox,AVStr(ident.i_user),sizeof(ident.i_user),"^@");
	if( *dp == '@' )
		wordscanX(dp+1,AVStr(ident.i_Host),sizeof(ident.i_Host));
	sv1log("##[%s] set ServerAuth [%s@%s]\n",what,ident.i_user,ident.i_Host);
	Conn->sv_certauth = ident;
}
void setClientCert(Connection *Conn,PCStr(what),PCStr(mbox))
{	AuthInfo ident;
	const char *dp;

	bzero(&ident,sizeof(AuthInfo));
	dp = wordscanY(mbox,AVStr(ident.i_user),sizeof(ident.i_user),"^@");
	if( *dp == '@' )
		wordscanX(dp+1,AVStr(ident.i_Host),sizeof(ident.i_Host));
	else	ident.i_Host[0] = 0;

	if( dp = strchr(ident.i_Host,':') ){
		truncVStr(dp); dp++;
		ident.i_Port = atoi(dp);
	}else	ident.i_Port = 0;

	/*
	sv1log("##[%s] set ClientAuth [%s@%s]\n",what,ident.i_user,ident.i_Host);
	*/
	sv1log("##[%s] set ClientAuth [%s@%s]:%d\n",what,ident.i_user,
		ident.i_Host,ident.i_Port);
	/*
	Conn->cl_certauth = ident;
	*/
	ClientCert = ident;
}

static
void setClientAuth(Connection *Conn,PCStr(what),PCStr(auser),PCStr(ahost))
{	const char *user;
	CStr(userb,64);
	const char *dp;

	if( strchr(auser,':') ){
		wordscanY(auser,AVStr(userb),sizeof(userb),"^:");
		user = userb;
	}else	user = auser;
	sv1log("##[%s] set ClientAuth [%s@%s]\n",what,user,ahost);

	ClientAuth.i_stat = AUTH_SET;
	/*
	wordScan(auser,ClientAuthUser);
	wordScan(ahost,ClientAuthHost);
	*/
	dp = wordscanY(auser,AVStr(ClientAuthUser),sizeof(ClientAuthUser),"^:");
	if( *dp == ':' )
		wordscanY(dp+1,AVStr(ClientAuthPass),sizeof(ClientAuthPass),"^\r\n");
	else	ClientAuthPass[0] = 0;
	dp = wordscanY(ahost,AVStr(ClientAuthHost),sizeof(ClientAuthHost),"^/");
	if( *dp == '/' )
		ClientAuthPort = atoi(dp+1);
	else
	ClientAuthPort = 0;

	reset_MOUNTconds(); /* reset cond. by FROM */
}
int getClientAuthList(Connection *Conn,int ax,AuthInfo *av[])
{	int ac;

	ac = 0;
	if( ClientAuthUser[0] ){
		av[ac++] = &ClientAuth;
	}
	/*
	if( Conn->cl_certauth.i_user[0] ){
		av[ac++] = &Conn->cl_certauth;
	}
	*/
	if( ClientCert.i_user[0] ){
		av[ac++] = &ClientCert;
	}
	return ac;
}

int service_authorized(Connection *Conn,PCStr(user),PCStr(host))
{	int ok;
	AuthInfo sauth;
	CStr(ahost,MaxHostNameLen);

	sauth = ClientAuth;
	sprintf(ahost,"%s.%s",host,AUTH_VDOM);
	wordscanX(ahost,AVStr(ClientAuthHost),sizeof(ClientAuthHost));
	wordscanX(user, AVStr(ClientAuthUser),sizeof(ClientAuthUser));

	Conn->auth_check = 1;
	ok = service_permitted2(Conn,DST_PROTO,1);
	Conn->auth_check = 0;

	ClientAuth = sauth;
	return ok;
}

int CTX_auth(Connection *Conn,PCStr(user),PCStr(pass))
{	AuthInfo ident;

	bzero(&ident,sizeof(ident));
	if( user == 0 && pass == 0 ){
		ident.i_stat = AUTH_TESTONLY;
	}
	if( user ) wordscanX(user,AVStr(ident.i_user),sizeof(ident.i_user));
	if( pass ) wordscanX(pass,AVStr(ident.i_pass),sizeof(ident.i_pass));
	return doAuth(Conn,&ident);
}
int matchCMAP(Connection *Conn,PCStr(cmap),PCStr(iproto),PCStr(imethod)){
	const char *dst;
	CStr(proto,256);
	refQStr(dp,proto);
	CStr(port,256);
	const char *methods;

	dst = scan_ListElem1(cmap,':',AVStr(proto));
	truncVStr(port);
	methods = "";
	if( dp = strchr(proto,'/') ){
		truncVStr(dp);
		methods = scan_ListElem1(dp+1,'/',AVStr(port));
	}
	if( *proto ){
		if( !isinList(proto,iproto) ){
			return 0;
		}
	}
	if( *methods && imethod[0] ){
		if( !isinListX(methods,imethod,"c") ){
			return 0;
		}
	}
	return 1;
}
const char *getMountAuthorizer(Connection *Conn,PVStr(authserv),int size)
{
	if( !IsMounted || MountOptions == 0 )
		return 0;

	if( *MO_Authorizer != 0 )
		goto EXIT;

	getOpt1(MountOptions,"AUTHORIZER",AVStr(MO_Authorizer));
	/*
	if( authopt = strcasestr(MountOptions,"AUTHORIZER=") )
		wordscanY(authopt+11,AVStr(MO_Authorizer),sizeof(MO_Authorizer),"^,");
	}
	*/
	if( *MO_Authorizer == 0 )
		strcpy(MO_Authorizer,"-");

EXIT:
	if( strcmp(MO_Authorizer,"-") == 0 )
		return 0;

	{
		const char *cmap;
		cmap = scan_ListElem1(MO_Authorizer,':',VStrNULL);
		if( *cmap ){
			/*
			CStr(proto,256);
			scan_ListElem1(cmap,':',AVStr(proto));
			if( !isinList(proto,DST_PROTO) ){
			*/
			if( !matchCMAP(Conn,cmap,DST_PROTO,RequestMethod) ){
				return 0;
			}
		}
	}
	if( authserv )
		scan_ListElem1(MO_Authorizer,':',BVStr(authserv));
		/*
		wordscanX(MO_Authorizer,AVStr(authserv),size);
		*/

	return MO_Authorizer;
}
int withMountAUTHORIZER(Connection *Conn)
{ 
	if( MO_Authorizer[0] && strcmp(MO_Authorizer,"-") != 0 )
		return 1;
	if( getMountAuthorizer(Conn,VStrNULL,0) )
		return 1;
	return 0;
}

int CTX_protoAuthorizer(Connection *Conn,PCStr(proto),PVStr(asv),int asiz){
	int wa;
	Port sv;
	sv = Conn->sv;
	strcpy(REAL_PROTO,proto);
	strcpy(REAL_HOST,"-");
	if( wa = getMountAuthorizer(Conn,AVStr(asv),asiz) != NULL ){
	}else
	{
		/* this matching must be sucess only when the protocol
		 * (maybe "admin") is explicitly sepcified in CMAP...
		 */
	wa = 0 <= find_CMAP(Conn,AUTHSERV_MAP,AVStr(asv));
	}
	Conn->sv = sv;
	return wa;
}
int CTX_withAuth(Connection *Conn){
	/*
	CStr(authserv,MaxHostNameLen);
	*/
	CStr(authserv,MaxAuthServLen);
	if( getMountAuthorizer(Conn,AVStr(authserv),sizeof(authserv)) ){
		return 1;
	}else
	if( 0 <= find_CMAP(Conn,AUTHSERV_MAP,AVStr(authserv)) )
		return 2;
	return 0;
}

void scan_condargs(Connection *Conn);
int doAuthX(Connection *Conn,AuthInfo *ident);
extern int MAXCONN_PCH;
int doAuth(Connection *Conn,AuthInfo *ident)
{	int stat;

	stat = doAuthX(Conn,ident);
	if( 0 <= stat ){
		scan_condargs(Conn);
		if( 0 < MAXCONN_PCH && MAXCONN_PCH < Conn->cl_count ){
			sv1log("Too many connections(%d < %d)[%s][%s]\n",
				MAXCONN_PCH,Conn->cl_count,ident->i_user,
				Client_Host);
			return -2;
		}
	}
	return stat;
}
int doAuthX(Connection *Conn,AuthInfo *ident)
{	int rcode;
	/*
	CStr(authserv,MaxHostNameLen);
	*/
	CStr(authserv,MaxAuthServLen);
	CStr(userpass,256);
	const char *dp;

	if( ident->i_stat & AUTH_MAPPED ){
		syslog_ERROR("??? AUTHORIZED ALREADY %X [%s][%s]\n",
			ident->i_stat,ident->i_user,ident->i_Host);
		/* return 1; */
	}

	if( getMountAuthorizer(Conn,AVStr(authserv),sizeof(authserv)) ){
	}else
	if( find_CMAP(Conn,AUTHSERV_MAP,AVStr(authserv)) < 0 )
		return 0;
	sprintf(userpass,"%s:%s",ident->i_user,ident->i_pass);
	/*
	rcode = doAUTH(Conn,NULL,NULLFP(),DST_PROTO,DST_HOST,0,
			AVStr(userpass),ident->i_Host,NULL,NULL);
	*/
	rcode = doAUTH(Conn,NULL,NULLFP(),DST_PROTO,DST_HOST,0,
			AVStr(userpass),AVStr(ident->i_Host),NULL,ident);


	if( dp = strstr(ident->i_Host,"..") ){
		truncVStr(dp);
		ident->i_Port = atoi(dp+2);
	}
	if( dp = strchr(ident->i_Host,'/') ){
		/* set by AUTHORIZER=host/port */
		truncVStr(dp);
		ident->i_Port = atoi(dp+1);
	}

	if( ident->i_stat & AUTH_MAPPED ){
		CStr(up,256);
		CStr(user,128);
		CStr(pass,128);
		CStr(hp,256);
		CStr(host,128);
		CStr(port,128);
		CStr(muserb,1024);
		const char *muser = ident->i_user;

		strcpy(host,ident->i_Host);
		/*
		Xsscanf(ident->i_user,"%[^@]@%s",AVStr(user),AVStr(host));
		*/
		if( *muser == '{' && strtailchr(muser) == '}' ){
			QStrncpy(muserb,muser+1,strlen(muser)-1);
			muser = muserb;
		}
		if( strchr(muser,'@') == 0 ){
			strcpy(up,muser);
			fieldScan(muser,user,pass);
			strcpy(hp,"");
			strcpy(host,"");
			strcpy(port,"");
		}else
		decomp_URL_siteX(muser,AVStr(up),AVStr(user),AVStr(pass),
			AVStr(hp),AVStr(host),AVStr(port));
		setClientAuth(Conn,"doAuth-MAPPED",up,host);
		/*
		setClientAuth(Conn,"doAuth-MAPPED",user,host);
		*/
		/*
		setClientAuth(Conn,"doAuth-MAPPED",ident->i_user,"");
		*/
		if( ClientAuthPass[0] == 0 ){
			strcpy(ClientAuthPass,ident->i_pass);
		}
		ClientAuth.i_stat |= AUTH_MAPPED;
	}

	if( rcode == 0 && streq(ident->i_Host,"-none") ){
		sv1log("## -none : emulate no AUTHORIZER\n");
		return 0;
	}
	if( rcode != 0 ){
		if( ident->i_error == 0 )
			ident->i_error = AUTH_EBADPASS;
	}
	if( rcode == -1 && streq(ident->i_Host,"-never") ){
		sv1log("## -never: reject regardless of AUTHORIZER\n");
		return -1;
	}

	if( strcmp(userpass,":") != 0 )
	sv1log("AUTHORIZER=%s host=[%s] user=[%s] -> %s\n",
		authserv,ident->i_Host,ident->i_user,rcode==0?"OK":"NO");
	if( rcode == 0 )
		return 1;
	else	return -1;
}
int doAUTH(Connection *Conn,FILE *fc,FILE *tc,PCStr(dstproto),PCStr(dsthost),int dstport,PVStr(auser),PVStr(ahost),iFUNCP func,AuthInfo *arg)
{	int da;
	Port dflt;

	dflt = Conn->sv_dflt;
	da = doAUTH0(Conn,fc,tc,dstproto,dsthost,dstport,AVStr(auser),AVStr(ahost),func,arg);
	Conn->sv_dflt = dflt;
	return da;
}
int doAUTH0(Connection *Conn,FILE *fc,FILE *tc,PCStr(dstproto),PCStr(dsthost),int dstport,PVStr(auser),PVStr(ahost),iFUNCP func,AuthInfo *arg)
{	CStr(authserv,1024);
	CStr(phost,MaxHostNameLen);
	int identonly;
	int authorized;

/*
	if( ClientAuthUser[0] != 0 )
	if( source_permitted(Conn) )
*/
	if( streq(DST_PROTO,dstproto) )
	if( streq(DST_HOST,dsthost) )
	if( DST_PORT == dstport )
	{
		sv1log("#### already authorized\n");
		return 0;
	}
	set_SERVER(Conn,dstproto,dsthost,dstport);

	if( getMountAuthorizer(Conn,AVStr(authserv),sizeof(authserv)) ){
		identonly = 0;
	}else
	if( 0 <= find_CMAP(Conn,IDENTIFY_MAP,AVStr(authserv)) ){
		identonly = 1;
	}else
	if( 0 <= find_CMAP(Conn,AUTHSERV_MAP,AVStr(authserv)) ){
		identonly = 0;
	}else{
		sv1log("#### no authorization required\n");
		return 0;
	}

	fprintf(tc,
		"<<<<<<<< Authorization for this proxy required.\r\n");

	for(;;){
		if( Identify(Conn,identonly,fc,tc,authserv,AVStr(auser),AVStr(ahost),AVStr(phost),func,arg) )
			break;
		if( auser[0] == 0 )
			return EOF;
		if( fc == NULL )
			return EOF;
	}

	if( identonly ){
		fprintf(tc,
		"<<<<<<<< Ok, You are identified as <%s@%s>\r\n",auser,phost);
		authorized = service_authorized(Conn,auser,ahost);
	}else	authorized = 1;

	if( authorized ){
		fprintf(tc,
		"<<<<<<<< Ok, you <%s@%s> are an authorized user :-)\r\n",
			auser,phost);

		setClientAuth(Conn,"doAUTH",auser,ahost);
		return 0;
	}else{
		fprintf(tc,
		"!!!!!!!! USER <%s@%s> not permitted by DeleGate.\r\n",
			auser,phost);
		fflush(tc);
		return EOF;
	}
}

static int connect_auth(Connection *OrigConn,PCStr(proto),PCStr(host),int port,PCStr(user),PCStr(pass),PCStr(path),FILE *svfp[])
{	int svsock,io[2];
	Connection ConnBuf,*Conn = &ConnBuf;
	const char *dp;
	CStr(hostb,MaxHostNameLen);
	int xport;

	/*
	if( strchr(host,'/') ){
	*/
	if( strchr(host,'/') || strstr(host,"..") ){
		wordScan(host,hostb);
		dp = strchr(hostb,'/');
		if( dp ){
		truncVStr(dp); dp++;
		}else{
			dp = strstr(hostb,"..");
			truncVStr(dp);
			dp += 2;
		}
		if( 0 < (xport = atoi(dp)) ){
			sv1log("Authorizer: ftp://%s:%d -> xxx://%s:%d\n",
				host,port,hostb,xport);
			host = hostb;
			port = xport;
		}
	}

	if( CTX_auth_cache(OrigConn,0,180,proto,user,pass,host,port) )
		return 1;

	if( host[0] == '-' ){
		/* virtual auth host */
		return -1;
	}

	ConnInit(Conn);
	Conn->from_myself = 1;
	Conn->co_mask |= CONN_NOPROXY;

	set_realserver(Conn,proto,host,port);
	Socketpair(io);

	svsock = connect_to_servX(Conn,io[0],io[1],0,0);
	close(io[0]);
	close(io[1]);
	if( svsock < 0 ){
		sv1tlog("cannot connect: %s://%s@%s/\n",proto,user,host);
		return -1;
	}

	svfp[0] = fdopen(svsock,"r");
	svfp[1] = fdopen(svsock,"w");
	return 0;
}

int authenticate_by_FTP(Connection *Conn,PVStr(host),PCStr(user),PCStr(pass),PCStr(path))
{	FILE *svfp[2];
	CStr(resp,1024);
	int rcode;

	if( rcode = connect_auth(Conn,"ftp", host,21,user,pass,path,svfp) )
		return rcode;

	rcode = ftp_auth(svfp[1],svfp[0],AVStr(resp),sizeof(resp),user,pass);
	fclose(svfp[0]);
	fclose(svfp[1]);

	if( rcode == EOF )
		return -1;
	else{
		CTX_auth_cache(Conn,1,180,"ftp",user,pass,host,21);
		return 0;
	}
}

/*
 * -auth.passwd.host.pam/port
 * -auth.passwd.pam = auth.passwd.-.pam/0
 * -passwd.pam
 * -.pam
 *
 * -pam//host..port/passwd.auth
 * -pam//host/passwd.auth
 * -pam/passwd.auth = -pam///passwd.auth = -pam//-..0/passwd.auth
 * -pam/passwd
 * -pam
*
 * => auth.passwd.host.pam:port
 *
 * -pam.host/port.passwd.auth
 * -pam.passwd
 */

extern int START_TIME;
extern const char *PAMbaseurl;
extern const char *PAMurl;
int PAMport;
void scan_PAMCONF(Connection *Conn,PCStr(conf))
{	CStr(name,64);
	CStr(value,64);

	scan_field1(conf,AVStr(name),sizeof(name),AVStr(value),sizeof(value));
	if( streq(name,"baseurl") )
		PAMbaseurl = stralloc(value);
	else
	if( streq(name,"url") )
		PAMurl = stralloc(value);
	else
	if( streq(name,"port") )
		PAMport = atoi(value);
}

int authenticate_by_PAM(Connection *Conn,xPVStr(host),PCStr(user),PCStr(pass),PCStr(path))
{	int rcode;
	CStr(servb,128);
	CStr(svhost,128);
	CStr(svdom,128);
	const char *dp;
	int svport;
	int expire;
	Connection *appConn = Conn;

	if( *host == '-' )
		host++;

	svhost[0] = 0;
	svport = 0;
	servb[0] = 0;

	if( strncmp(host,"pam/",4) == 0 ){
		if( host[4]=='/' ){
			dp = wordscanY(host+5,AVStr(svhost),sizeof(svhost),"^/");
			if( *dp == '/' ){
				wordScan(dp+1,servb);
			}
			if( dp = strstr(svhost,"..") ){
				truncVStr(dp);
				svport = atoi(dp+2);
			}else	svport = serviceport("pam");
		}else{
			wordScan(host+4,servb);
		}
	}else
	if( strtailstr(host,".pam") ){
		wordScan(host,servb);
		*strtailstr(servb,".pam") = 0;
	}
	if( servb[0] == 0 )
		strcpy(servb,"passwd");
	if( svhost[0] == 0 )
		strcpy(svhost,"-");

	sprintf(svdom,"%s.%s.pam",servb,svhost);
	/* rewrite "host" as "what.service.host.pam" */
	if( svport )
		sprintf(host,"%s/%d",svdom,svport);
	else	strcpy(host,svdom);

/* don't use cache for PAM */
/* if(0) */
{
	expire = time(0) - START_TIME;
	if( 180 < expire )
		expire = 180;

	if( CTX_auth_cache(Conn,0,expire,"pam",user,pass,svdom,svport) )
		return 1;
}

	/* Conn might be rewritten if remote PAM-server is used */
	{
		Connection ConnBuf, *Conn = &ConnBuf;
		*Conn = *appConn;
		Conn->no_dstcheck = 1;
		ToS = ToSX = FromS = FromSX = -1;

		rcode = pam_checkPasswd(Conn,svhost,svport,servb,user,pass);

		if( 0 <= ToS ){
			Verbose("## ToS=%d ToSX=%d\n",ToS,ToSX);
			close(ToS);
			if( 0 <= ToSX ) close(ToSX);
		}
		if( 0 <= FromS ){
			Verbose("## FromS=%d FromSX=%d\n",FromS,FromSX);
			if( FromS != ToS ) close(FromS);
			if( 0 <= FromSX ) close(FromSX);
		}
	}

	if( 0 < rcode ){
		CTX_auth_cache(Conn,1,180,"pam",user,pass,svdom,svport);
		return 0;
	}
	return -1;
}
int service_pam(Connection *Conn)
{	int forbidden,stcode;
	CStr(request,128);
	CStr(user,128);
	CStr(clhost,128);

	dup2(FromC,0);
	dup2(ToC,1);
	forbidden = !source_permitted(Conn);
	pam_service(Conn,forbidden,AVStr(request),AVStr(user),&stcode);

	getClientHostPort(Conn,AVStr(clhost));
	if( user[0] == 0 )
		strcpy(user,"-");
	sv1log("## PAM/HTTP: %s - %s \"%s\" %d\n",clhost,user,request,stcode);
	/* should output HTTP compatible log */
	return 0;
}

static int authenticate_by_Digest(Connection *Conn,PVStr(domain),PCStr(user),PCStr(dpass),PCStr(path),AuthInfo *ident)
{	CStr(dom,128);
	CStr(serv,128);
	int port;

	if( ident == 0 || *ident->i_atyp == 0 )
		return -1;
	if( strcasecmp(ident->i_atyp,"Digest") != 0 ){
		sv1log("Unexpected Auth.type[%s] for Digest\n",ident->i_atyp);
		return -1;
	}

	wordScan(domain,dom);
	if( port = scanAuthServPort(dom,AVStr(serv)) ){
		/* return "-dgauth[.realm]" stripped "//host..port" off */
		strcpy(domain,dom);
	}

	return HTTP_authorize_Digest(Conn,ident,dom,user,dpass,AVStr(serv),port);
}

extern const char *HTTP_AUTHBASE;

int authenticate_by_HTTP(Connection *Conn,PVStr(host),PCStr(user),PCStr(pass),PCStr(path))
{	FILE *svfp[2];
	int rcode;
	CStr(buff,1024);
	CStr(authBASIC,1024);
	CStr(authMD5,1024);
	CStr(resp,1024);
	const char *dp;
	CStr(me,MaxHostNameLen);
	int scode;
	CStr(authpath,1024);

	sprintf(buff,"%s:%s",user,pass);
	toMD5(buff,authMD5);
	str_to64(buff,strlen(buff),AVStr(authBASIC),sizeof(authBASIC),1);
	if( dp = strpbrk(authBASIC,"\r\n") )
		truncVStr(dp);
	ClientIF_name(Conn,ClientSock,AVStr(me));

	if( rcode = connect_auth(Conn,"http",host,80,user,pass,path,svfp) )
		return rcode;
sprintf(authpath,"%s/%s/%s",HTTP_AUTHBASE,me,authMD5);
	fprintf(svfp[1],"HEAD %s HTTP/1.0\r\n",authpath);
	fprintf(svfp[1],"\r\n");
	fflush(svfp[1]);
	sv1log("HTTP-AUTH << path=%s user=%s\n",authpath,user);
	rcode = -1;
	if( fgets(resp,sizeof(resp),svfp[0]) != NULL ){
		sv1log("HTTP-AUTH >> %s",resp);
		if( sscanf(resp,"HTTP/%*s %d",&scode) )
			if( scode == 200 ){
				rcode = 0;
				goto EXIT;
			}
	}

	fclose(svfp[0]);
	fclose(svfp[1]);
	if( rcode = connect_auth(Conn,"http",host,80,user,pass,path,svfp) )
		return rcode;

sprintf(authpath,"%s/%s/%s",HTTP_AUTHBASE,me,user);
	fprintf(svfp[1],"HEAD %s HTTP/1.0\r\n",authpath);
	fprintf(svfp[1],"Authorization: Basic %s\r\n",authBASIC);
	fprintf(svfp[1],"\r\n");
	fflush(svfp[1]);
	sv1log("HTTP-AUTH << path=%s user=%s\n",authpath,user);
	rcode = -1;
	if( fgets(resp,sizeof(resp),svfp[0]) != NULL ){
		sv1log("HTTP-AUTH >> %s",resp);
		if( sscanf(resp,"HTTP/%*s %d",&scode) )
			if( scode == 200 ){
				rcode = 0;
				goto EXIT;
			}
	}

EXIT:
	fclose(svfp[0]);
	fclose(svfp[1]);
	return rcode;
}

static int authenticate_by_list(Connection *Conn,PCStr(list),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident)
{	CStr(up,256);
	CStr(xlist,1024);
	CStr(md5,256);

	if( isinList(list,user) )
		return 1;

	sprintf(up,"%s:%s",user,pass);
	strfConnX(Conn,list,AVStr(xlist),sizeof(xlist));
	list = xlist;
	if( isinList(list,up) )
	{
		if( strneq(pass,"MD5:",4) ){
			sv1log("## password as MD5 as is ?? [%s]\n",pass);
		}else
		return 1;
	}

	toMD5(pass,md5);
	sprintf(up,"%s:MD5:%s",user,md5);
	if( isinList(list,up) )
		return 1;

	sprintf(up,"%s:",user);
	if( ident && isinListX(list,up,"H") ){
		ident->i_error |= AUTH_EBADPASS; /* checked by -fail.badpass */
		return -1;
	}
	else	return -1;
}

/*
 * AUTHORIZER="-list{u1:p1,u2,u3:p3}" => "-list{u1:MD5:xxxx,u2,u3:MD5:yyyy}"
 */
static int encryptList(PCStr(list),PVStr(xlist),int xsize){
	int nenc = 0;
	refQStr(xp,xlist);
	const char *np;
	const char *pp;
	const char *remp;
	CStr(up,256);
	CStr(pass,256);
	CStr(md5,256);
	int li;

	/* copy "-list{" part */
	np = wordscanY(list,AVStr(xlist),xsize,"^{");
	if( *np++ != '{' )
		return 0;
	xp = xlist + strlen(xlist);
	setVStrPtrInc(xp,'{');
	setVStrEnd(xp,0);

	for( li = 0; np && *np; li++ ){
		xp += strlen(xp);
		if( 0 < li ) setVStrPtrInc(xp,',');
		np = scan_ListElem1(np,',',AVStr(up));
		/*
		if( pp = strchr(up,':') ){
		*/
		if( pp = strchrX(up,':',"{(",")}") ){
			pp++;
			if( !strneq(pp,"MD5:",4) ){
				remp = wordScanY(pp,pass,"^}");
				toMD5(pass,md5);
				Xsscanf(up,"%[^:]",AVStr(xp));
				xp += strlen(xp);
				sprintf(xp,":MD5:%s%s",md5,remp);
				nenc++;
				continue;
			}
		}
		strcpy(xp,up);
	}
	return nenc;
}
const char *encryptAuthorizer(PCStr(pname),PCStr(pval)){
	CStr(auth,MaxAuthServLen);
	const char *dp;
	CStr(servs,MaxAuthServLen);
	CStr(xlist,MaxAuthServLen);
	CStr(xservs,MaxAuthServLen);
	refQStr(xp,xservs);
	const char *sv[8]; /**/
	int sc,si;
	int nenc = 0;

	strcpy(auth,pval);
	if( dp = strheadstrX(auth,"-cmd{",0) ){
		CStr(cmd,1024);
		CStr(xcmd,1024);
		dp = wordScanY(dp,cmd,"^ \t}");
		if( !isFullpath(cmd) ){
			if( fullpathLIB(cmd,"r",AVStr(xcmd))
			 || fullpathCOM(cmd,"r",AVStr(xcmd))
			){
				sv1log("%s -> %s\n",cmd,xcmd);
				sprintf(xservs,"%s=-cmd{%s%s",pname,xcmd,dp);
				return stralloc(xservs);
			}
		}
		return 0;
	}

	dp = scan_ListElem1(auth,':',AVStr(servs));
	sc = list2vect(servs,',',8,(const char**)sv);
	for( si = 0; si < sc; si++ ){
		if( strneq(sv[si],"-list{",6) ){
			if( encryptList(sv[si],AVStr(xlist),sizeof(xlist)) ){
				sv[si] = stralloc(xlist);
				nenc++;
			}
		}
	}
	if( nenc ){
		xp = xservs;
		sprintf(xp,"%s=",pname);
		xp += strlen(xp);
		for( si = 0; si < sc; si++ ){
			if( 0 < si ){
				setVStrPtrInc(xp,',');
			}
			strcpy(xp,sv[si]);
			xp += strlen(xp);
		}
		if( *dp )
			sprintf(xp,":%s",dp);
		return stralloc(xservs);
	}
	return 0;
}

/*
 * -crc32/8x{key:user1,user2,...}
 */
static int authenticate_by_CRC32(Connection *Conn,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident){
	const char *kp;
	IStr(buf,128);
	IStr(key,128);
	IStr(fmt,8);
	refQStr(fp,fmt);
	int prec = 0;
	int crci;
	IStr(crcs,128);

	kp = host;
	if( *host == '/' ){
		kp = host + 1;
		setVStrPtrInc(fp,'%');
		prec = atoi(kp);
		if( isdigit(*kp) ) setVStrPtrInc(fp,*kp++);
		if( isdigit(*kp) ) setVStrPtrInc(fp,*kp++);
		switch( *kp ){
			default:
				setVStrPtrInc(fp,'u');
				break;
			case 'u':
			case 'd':
				setVStrPtrInc(fp,'u');
				kp++;
				break;
			case 'x':
			case 'X':
				setVStrPtrInc(fp,*kp++);
				break;
		}
		setVStrPtrInc(fp,0);
	}else{
		strcpy(fmt,"%x");
	}
	if( *kp == '{' ){
		wordScanY(kp+1,key,"^:}");
	}
	if( key[0] == 0 ){
		NonceKey(AVStr(key));
	}
	sprintf(buf,"%s:%s",key,user);
	crci = strCRC32(buf,strlen(buf));
	sprintf(crcs,fmt,crci);

	sv1log("## Auth/crc32/%d = [%s:%s] %s\n",prec,user,pass,crcs);
	if( prec == 0 && strcaseeq(crcs,pass)
	 || prec != 0 && strncaseeq(crcs,pass,prec)
	){
		return 1;
	}
	return -1;
}

/*
 * AUTHORIZER="-cmd{command arg1 arg2}{ENV1=val1 ENV2=val2}{input}"
 * AUTHORIZER="-cmd{dgauth %U}{DG_USER=%P DG_PASS=%P}{%U\n%P\n}"
 *
 * should be controllable: to be cached or not
 */
int strtoB64(PCStr(str),int slen,PVStr(b64),int bsiz,int withnl);
int NoHangWaitXX(int *sigp,int *statp);
extern char **environ;
extern int winCP;

int scanBList(PCStr(list),PVStr(cmd),PVStr(env),PVStr(sin),PVStr(sout)){
	int got = 0;
	CStr(buf,1024);
	const char *lp = list;
	int ei;

	for( ei = 0; ei < 4; ei++ ){
		if( (lp = strchr(lp,'{')) == 0 )
			goto EXIT;
		if( lp[1] == '}' ){
			strcpy(buf,"");
			lp++;
		}else{
			lp = wordScanY(lp+1,buf,"^}");
		}
		got |= (1 << ei);
		switch( ei ){
			case 0: if(cmd)  strcpy(cmd,buf); break;
			case 1: if(env)  strcpy(env,buf); break;
			case 2: if(sin)  strcpy(sin,buf); break;
			case 3: if(sout) strcpy(sout,buf); break;
		}
	}
EXIT:
	return got;
}

int authenticate_by_cmd(Connection *Conn,PCStr(dom),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident){
	IStr(cmd,1024);
	IStr(xcmd,1024);
	IStr(env,512);
	IStr(xenv,512);
	IStr(sin,512);
	IStr(xsin,512);
	IStr(sout,512);
	const char *ev[256];
	const char *e1;
	int en = 0;
	int ei,ej;
	AuthInfo si;
	int code;
	int ok = -1;
	FILE *fpv[2];
	IStr(resp,8*1024);
	const char *rp;
	IStr(resp1,1024);
	CStr(tmp,1024);
	int rcc;
	char **senviron;
	int wi;
	int pid,xpid;
	int xsig = 0;
	int xcode = -1;
	int expire;
	CStr(cmdid,128);
	int got;

	/* ignore the cache older than the invocation of this DeleGate */
	expire = time(0) - START_TIME;
	if( 180 < expire )
		expire = 180;
	strtoB64(dom,strlen(dom),AVStr(cmdid),sizeof(cmdid),0);
	if( CTX_auth_cache(Conn,0,expire,"-cmd",user,pass,cmdid,0) )
		return 1;

	/*
	Xsscanf(dom,"{%[^}]}{%[^}]}{%[^}]}",AVStr(cmd),AVStr(env),AVStr(sin));
	*/
	got = scanBList(dom,AVStr(cmd),AVStr(env),AVStr(sin),AVStr(sout));

	si = ClientAuth;
	bzero(&ClientAuth,sizeof(AuthInfo));
	strcpy(ClientAuth.i_user,user);
	strcpy(ClientAuth.i_pass,pass);
	ClientAuth.i_stat = AUTH_GOT;
	strfConnX(Conn,cmd,AVStr(xcmd),sizeof(xcmd));

	ev[0] = 0;
	if( (got & 2) == 0 || streq(env,"+") ){
		strcpy(env,"DG_USER=%U DG_PASS=%P");
	}
	en = stoV(env,elnumof(ev),ev,' ');
	for( ei = 0; ei < en; ei++ ){
		strfConnX(Conn,ev[ei],AVStr(xenv),sizeof(xenv));
		if( xenv[0] ){
			ev[ei] = stralloc(xenv);
			putenv((char*)ev[ei]);
		}
	}
	for( ej = 0; e1 = environ[ej]; ej++ ){
		ev[ei++] = e1;
	}
	ev[ei] = 0;

	if( (got & 4) == 0 || streq(sin,"+") ){
		strcpy(sin,"USER %U\\nPASS %P\\n");
	}
	strfConnX(Conn,sin,AVStr(xsin),sizeof(xsin));
	ClientAuth = si;

	senviron = environ;
	environ = (char**)ev;

	winCP = 1;
	pid = popenx(xcmd,"w+",fpv);
	winCP = 0;
	if( 0 < pid && fpv[1] ){
		fputs(xsin,fpv[1]);
		fclose(fpv[1]);
		fpv[1] = 0;
	}

	environ = senviron;
	for( ei = 0; ei < en; ei++ ){
		free((char*)ev[ei]);
	}

	if( 0 < pid && fpv[0] ){
		if( fpv[1] && fpv[1] != fpv[0] ) fclose(fpv[1]);
		rcc = fread((char*)resp,1,sizeof(resp),fpv[0]);
		if( 0 < rcc ){
			setVStrEnd(resp,rcc);
		}
		while( fgetsTimeout(AVStr(tmp),sizeof(tmp),fpv[0],1) ){
			/* wait the exit of the auth. process */
		}
		fclose(fpv[0]);
	}
	for( wi = 0; wi < 10; wi++ ){
		xpid = NoHangWaitXX(&xsig,&xcode);
		if( xpid < 0 && errno == ECHILD || xpid == pid ){
			break;
		}
		msleep(100);
	}
	if( strtailchr(resp) != '\n' )
		strcat(resp,"\n");
	sv1log("AUTH> code=%d sig=%d pid=%d(%d) %s",xcode,xsig,xpid,pid,resp);

	ok = 0;
	if( resp[0] ){
		/* reason message should be passed to the client ... */
		if( strncmp(resp,"HTTP/1.",7) == 0 ){
			switch( atoi(resp+8) ){
				case 401: ok = -1; break;
				case 403: ok = -2; break;
				case 407: ok = -1; break;
			}
		}else{
		   for( rp = resp; *rp; rp++ ){
			rp = lineScan(rp,resp1); 
			switch( atoi(resp1) ){
				case 230: ok =  1; break;
				case 331: ok = -1; break;
				case 530: ok = -2; break;
			}
			if( 0 < ok )
				break;
			if( *rp == '\r' )
				rp++;
			if( *rp != '\n' )
				break;
		   }
		}
	}
	if( ok == 0 ){
		if( xcode == 0 ){
			ok = 1;
		}else{
			ok = -1;
		}
	}
	if( 0 < ok ){
		CTX_auth_cache(Conn,1,expire,"-cmd",user,pass,cmdid,0);
	}else{
		/* should be failure cache ? */
	}
	return ok;
}

typedef struct {
  const	char	*a_name;
	iFUNCP	a_func;
} AuthServ;
static AuthServ authenticators[] = {
	{"PAM", (iFUNCP)authenticate_by_PAM	},
	{"FTP",  (iFUNCP)authenticate_by_FTP	},
	/*{"HTTP", (iFUNCP)authenticate_by_HTTP	},*/
	/*{"RADIUS", (iFUNCP)authenticate_by_RADIUS },*/
	0
};
int authenticate_by_man(Connection *Conn,PVStr(comment),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident);

int Authenticate(Connection *Conn,PCStr(host),PCStr(user),PCStr(pass),PCStr(path))
{
	return AuthenticateX(Conn,host,user,pass,path,NULL);
}
const char *scanAuthOptions(Connection *Conn,PCStr(serv),PCStr(muser)){
	IStr(opts,1024);
	IStr(opt1,256);
	const char *op;
	const char *vp;
	const char *nmuser = 0;

	if( strchr(muser,'=') == 0 )
	if( strchr(muser,',') == 0 )
		return muser;
	wordScanY(muser,opts,"^)");
	for( op = opts; *op; op++ ){
		op = wordScanY(op,opt1,"^,");
		if( vp = strheadstrX(opt1,"expire=",1) ){
			ClientAuth.i_expire = scan_period(vp,1,0);
		}else
		if( vp = strheadstrX(opt1,"user=",1) ){
			nmuser = vp;
		}else
		if( vp = strheadstrX(opt1,"userpfx=",1) ){
			/* the format of a prefix with %X spec. */
			strcpy(ClientAuth.i_upfx,vp);
		}else{
		}
		if( *op != ',' )
			break;
	}
	return nmuser;
}
static int auth_decompose(PCStr(asv),AuthInfo *ident,PCStr(user),PCStr(pass),PVStr(suserb),PVStr(spassb)){
	const char *up,*pp,*dp;
	IStr(delim,32);
	IStr(userb,128);
	IStr(passb,128);

	if( strneq(asv,"-fwd",4) ){
		if( ident ){
			ident->i_stat = AUTH_FORW;
			ident->i_stype = AUTH_APROXY | AUTH_AORIGIN;
			strcpy(suserb,user);
			strcpy(spassb,pass);
			strcpy(ident->i_user,user);
			strcpy(ident->i_pass,pass);
		}
		return 1;
	}
	if( strneq(asv,"-map",4) ){
		const char *asva;
		int do_svgetsv = 1;
		int do_svstrip = 1;
		IStr(ifmt,128);
		IStr(lmap,128);
		IStr(vmap,128);
		IStr(upi,256);
		IStr(upl,256);
		IStr(upr,256);
		UTag *uv[33],ub[32];
		int uc;
		const char *rsp;
		const char *rfp;
		int ni;

		uvinit(uv,ub,32);
		if( ident == 0 ){
			return 1;
		}
		asva = asv + 4;
		while( isalpha(*asva) || *asva == '_' || *asva == '-' ){
			if( strncmp(asva,"-sv",3) ){
				do_svgetsv = 0;
				asva += 3;
			}else
			if( strncmp(asva,"-st",3) ){
				do_svstrip = 0;
				asva += 3;
			}else{
				asva++;
			}
		}
		ni = Xsscanf(asva,"{%[^}]}{%[^}]}{%[^}]}",
			AVStr(ifmt),AVStr(lmap),AVStr(vmap));
		sprintf(upi,"%s:%s",user,pass);
		uc = uvfromsfX(upi,0,ifmt,uv,&rsp,&rfp);
		uvtosf(AVStr(upl),sizeof(upl),lmap,uv);
		uvtosf(AVStr(upr),sizeof(upr),vmap,uv);
		Xsscanf(upl,"%[^:]:%s",AVStr(suserb),AVStr(spassb));
		if( ident ){
			ident->i_stat = AUTH_FORW;
			ident->i_stype = AUTH_APROXY | AUTH_AORIGIN;
			Xsscanf(upr,"%[^:]:%s",AVStr(ident->i_user),
				AVStr(ident->i_pass));
			if( dp = strrchr(ident->i_user,'@') ){
				if( do_svgetsv ){
					strcpy(ident->i_Host,dp+1);
				}
				if( do_svstrip ){
					truncVStr(dp);
				}
			}
		}
		return 1;
	}
	if( !strneq(asv,"-strip",6) ){
		return 0;
	}
	strcpy(delim,"^@");
	if( strneq(asv,"-strip{",7) ){
		strcpy(delim,"^");
		Xsscanf(asv+7,"%[^}]",DVStr(delim,1));
	}
	up = wordScanY(user,userb,delim); if( *up ) up++;
	pp = wordScanY(pass,passb,delim); if( *pp ) pp++;
	strcpy(suserb,userb);
	strcpy(spassb,passb);
	if( ident && *user && *pass ){
		ident->i_stat = AUTH_FORW;
		ident->i_stype = AUTH_APROXY | AUTH_AORIGIN;
		strcpy(ident->i_user,up);
		if( dp = strrchr(ident->i_user,'@') ){
			truncVStr(dp);
			strcpy(ident->i_Host,dp+1);
		}
		strcpy(ident->i_pass,pp);
	}
	return 1;
}
int AuthenticateX(Connection *Conn,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident)
{	CStr(servs,1024);
	const char *sv[8]; /**/
	int sc,si,rcode;
	const char *realm;
	CStr(dom,128);
	const char *dp;
	CStr(serv,512);
	CStr(sv1,1024);
	const char *muser;
	IStr(suserb,128);
	IStr(spassb,128);

	lineScan(host,servs);
	if( realm = strchrX(servs,'@',"{(",")}") ){
		truncVStr(realm);
		realm++;
	}

	if( ident && realm ){
		refQStr(rp,ident->i_realm);
		/* this should be here to return the realm even on success */
		linescanX(realm,AVStr(ident->i_realm),sizeof(ident->i_realm));
		if( rp[0] == '{' && strtailchr(rp) == '}' ){
			QStrncpy(rp,rp+1,strlen(rp)-1);
		}
	}

	sc = list2vect(servs,',',8,(const char**)sv);
	muser = 0;
	for( si = 0; si < sc; si++ ){
		if( auth_decompose(sv[si],ident,user,pass,AVStr(suserb),AVStr(spassb)) ){
			user = suserb;
			pass = spassb;
			continue;
		}
		muser = 0;
		if( strtailchr(sv[si]) == ')' ){
			if( dp = strrchr(sv[si],'(') ){
				strcpy(serv,sv[si]);
				muser = strrchr(serv,'(');
				truncVStr(muser);
				muser++;
				sv[si] = serv;
				muser = scanAuthOptions(Conn,sv[si],muser);
			}
		}
		if( realm && strneq(sv[si],DGAUTHdom,7) ){
			sprintf(dom,"%s@%s",sv[si],realm);
			rcode = AuthenticateY(Conn,AVStr(dom),user,pass,path,ident);
		}else
		{
			/*
		rcode = AuthenticateY(Conn,QVStr((char*)sv[si],servs),user,pass,path,ident);
			-pam "authenticate_by_PAM()" will rewrite sv[si]
			to overwrite the content of sv[si+1] in servs
			*/
			strcpy(sv1,sv[si]);
			rcode = AuthenticateY(Conn,AVStr(sv1),user,pass,path,ident);
			sv[si] = sv1;
		}
		if( 0 <= rcode )
		{
			if( ident )
			if( ident->i_stat == 0 )
			  /* this condition might be necessary for compat. ?
			   * or it might be set in Digest ?
			   */
			{
				/*
				wordScanY(sv[si],ident->i_Host,"^{/");
				don't ignore port by "host/port"
				*/
				wordScanY(sv[si],ident->i_Host,"^{");
			}
			if( ident && muser ){
				if( strneq(muser,"-reject.",8) ){
					sv1log(">>>> [%s] rejected\n",user);
					muser += 8;
					rcode = -1;
				}
				QStrncpy(ident->i_user,muser,strlen(muser));
				ident->i_stat |=  AUTH_MAPPED;
			}
			return rcode;
		}
		if( ident->i_stat & AUTH_BREAK ){
			break;
		}
	}
	return -1;
}
int testLogin(PCStr(user),PCStr(pass));
int isinHOSTLIST(PCStr(lname),PCStr(proto),PCStr(host),int port,PCStr(user));
int AuthenticateY(Connection *Conn,PVStr(host),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident)
{	int rcode;
	int ai;
	iFUNCP afunc;
	iFUNCP xfunc;

	rcode = -1;
	if( streq(host,"-none") ){
		sv1log("## Auth/none = 0 <%s:%s>\n",user,*pass?"****":"");
		return 0;
	}
	if( streq(host,"-never") ){
		sv1log("## Auth/never = -1 <%s:%s>\n",user,*pass?"****":"");
		return -1;
	}
	if( streq(host,"-any") ){
		sv1log("## Auth/any = 0 <%s:%s>\n",user,*pass?"****":"");
		if( *user == 0 && *pass == 0 ){
			if( ident->i_error & AUTH_ENOAUTH ){
				return -1;
			}
		}
		return 0;
	}
	if( strneq(host,"-fail",5) ){
		if( streq(host+5,".nopass") ){
			if( *pass == 0 ){
				sv1log("## Auth/-fail.nopass\n");
				ident->i_stat |= AUTH_BREAK;
			}
		}else
		if( streq(host+5,".badpass") ){
		 	if( ident->i_error & AUTH_EBADPASS ){
				sv1log("## Auth/-fail.badpass\n");
				ident->i_stat |= AUTH_BREAK;
			}
		}else{
			ident->i_stat |= AUTH_BREAK;
		}
		return -1;
	}
	if( streq(host,"-login") ){
		if( testLogin(user,pass) == 0 ){
			return 1;
		}
		return -1;
	}
	if( streq(host,"-ntht") ){
		ident->i_error |= AUTH_EDONTHT;
		return -1;
	}
	if( streq(host,"-anonftp") ){
		if( is_anonymous(user) ){
			if( strchr(pass,'@') )
				rcode = 0;
		}
		sv1log("## Auth/anonftp = %d <%s:%s>\n",rcode,user,pass);
		return rcode;
	}
	if( streq(host,"-smtp-vrfy") ){
		if( validateEmailAddr(pass,0) == 0 ){
			return 1;
		}
		return -1;
	}
	if( streq(host,"-ident") ){
	}
	if( strneq(host,DGAUTHdom,7) ){
		rcode = authenticate_by_Digest(Conn,AVStr(host),user,pass,path,ident);
		return rcode;
	}
	if( strneq(host,"-crc32",6) && strchr("/{",host[6]) ){
		rcode = authenticate_by_CRC32(Conn,host+6,user,pass,path,ident);
		return rcode;
	}
	if( strneq(host,"-passwd/",8) ){
		/* /etc/passwd format */
	}
	if( strneq(host,"-list{",6) ){
		/* followed by a list of {user:pass} */
		rcode = authenticate_by_list(Conn,host+5,user,pass,path,ident);
		return rcode;
	}
	if( strneq(host,"-hostlist/",10) ){
		/* 9.9.3 AUHOTIZER=-hostlist/Name with
		 * HOSTLIST=Name:host1,host2,*.domain1,...
		 */
		int match;
		match = isinHOSTLIST(host+10,"",Client_Host,Client_Port,user);
		if( match < 0 ){
			sv1log("## -hostlist unknown HOSTLIST=%s\n",host+10);
		}
		if( 0 < match )
			rcode = 1;
		else	rcode = -1;
		sv1log("## -hostlist/%s %s => %d\n",host+10,Client_Host,rcode);
		return rcode;
	}
	if( strneq(host,"-exec/",6) ){
		/* execute specified program which get environment var.
		 * USER and PASS then outputs "0" or "1"
		 */
	}
	if( strneq(host,"-hash/",6) ){
		/*
		 * pass == MD5(key:user)
		 */
	}
	if( strneq(host,"-cmd{",4) ){
		rcode = authenticate_by_cmd(Conn,host+4,user,pass,path,ident);
		return rcode;
	}
	if( strneq(host,"-man",4) ){
		rcode = authenticate_by_man(Conn,DVStr(host,4),user,pass,path,ident);
		return rcode;
	}

	xfunc = 0;
	if( *host == '-' )
	if( streq(host,"-pam")||strneq(host,"-pam/",4)||strtailstr(host,".pam"))
		xfunc = (iFUNCP)authenticate_by_PAM;

	rcode = -1;
	for( ai = 0; afunc = authenticators[ai].a_func; ai++ ){
		if( xfunc != 0 && xfunc != afunc )
			continue;
		if( afunc == (iFUNCP)authenticate_by_PAM ){
			if( xfunc != (iFUNCP)authenticate_by_PAM )
				continue;
		}
		if( *user == 0 && *pass == 0 )
			continue;
		rcode = (*afunc)(Conn,BVStr(host),user,pass,path);
		/*
		sv1log("## Auth/%s = %d\n",authenticators[ai].a_name,rcode);
		*/
		sv1log("## Auth/%s = %d <%s:%s@%s>\n",
			authenticators[ai].a_name,
			/*
			rcode,user,*pass?"****":"",host);
			*/
			rcode,user,streq(user,"guest")?pass:(*pass?"****":""),host);
		if( AuthTimeout(Conn) )
		if( 0 < rcode )
		if( ClientAuth.i_error & AUTH_ESTALE ){
			sv1log("---- STALE Auth/%s %s@%s\n",
				authenticators[ai].a_name,user,host);
			return -1;
		}
		if( 0 <= rcode )
			return rcode;
	}
	return rcode;
}

int CTX_preset_loginX(Connection *Conn,PCStr(method),PVStr(vurl),AuthInfo *ident,PVStr(path))
{	CStr(proto,128);
	CStr(site,1024);
	CStr(pb,1024);

	if( CTX_mount_url_to(Conn,NULL,method,AVStr(vurl)) ){
		decomp_absurl(vurl,AVStr(proto),AVStr(site),AVStr(pb),sizeof(pb));
		if( strchr(site,'@') ){
			/* with USER:PASS@SERVER */
			if( ident ) decomp_siteX("ftp",site,ident);
			if( path ) strcpy(path,pb);
			return 1;
		}
	}
	return 0;
}

int unescape_user_at_host(PVStr(email))
{	const char *dp;

	if( strchr(email,'@') == 0 )
	if( dp = strrpbrk(email,"%") ){
		*(char*)dp = '@';
		return 1;
	}
	return 0;
}

Connection *SessionConn();
int CTX_getClientInfo(Connection *Conn,ClientInfo *local,ClientInfo *rident){
	bzero(local,sizeof(ClientInfo));
	if( Conn == 0 ){
		Conn = SessionConn();
	}
	if( Conn == 0 ){
		return -1;
	}
	local->currentTime = Time();
	if( Client_VAddr ){
		local->clientsideHost = *Client_VAddr;
	}
	if( 0 <= ClientSock ){
		VA_HostPortIFclnt(Conn,ClientSock,VStrNULL,VStrNULL,
			&local->clientSockHost);
	}
	local->_fromself = Conn->from_myself;
	return 0;
}
void CTX_pushClientInfo(Connection *Conn)
{	VAddr sockhost;

	if( ClientSock < 0 ){
		bzero(&sockhost,sizeof(sockhost));
		/* maybe in UDP, thus it should be given in another way...
		 * as ClientIF_VAddr for example similarly to Client_VAddr.
		 */
	}else
	VA_HostPortIFclnt(Conn,ClientSock,VStrNULL,VStrNULL,&sockhost);
	/*
	VA_HL_pushClientInfo(Time(),Client_VAddr,&sockhost);
	*/
	VA_HL_pushClientInfo(Time(),Client_VAddr,&sockhost,Conn->from_myself);
}

/*
 * MYAUTH=username:password[:proto[:dst[:src]]]
 * generating my (DeleGate's) authorization as a client of server/proxy
 */
int isHTTP(PCStr(proto));
void scan_MYAUTH(Connection *Conn,PCStr(myauth))
{	CStr(myauthx,256);
	CStr(user,256);
	CStr(pass,256);
	CStr(proto,256);
	CStr(dst,MaxHostNameLen);
	CStr(src,MaxHostNameLen);

	user[0] = pass[0] = 0;
	/*
	strcpy(proto,"*");
	*/
	strcpy(proto,"");
	strcpy(dst,"*");
	strcpy(src,"*");
	scan_Listlist(myauth,':',AVStr(user),AVStr(pass),AVStr(proto),AVStr(dst),AVStr(src));

	if( proto[0] == 0 )
	if( iSERVER_HOST[0]==0 || isMYSELF(iSERVER_HOST) )
	/* acting as a proxy with an upstream proxy asking authentication.
	 * don't send the auth. info. to target servers
	 * if( no MOUNT exists ) ... exclude the case of reverse proxy
	 */
	{
		if( DELEGATE_getEnv(P_SOCKS) ){
			strcpy(proto,"socks");
		}
		if( DELEGATE_getEnv(P_SSLTUNNEL) ){
			if( proto[0] ) strcat(proto,",");
			strcpy(proto,"ssltunnel");
		}
		if( DELEGATE_getEnv(P_MASTER) ){
			if( proto[0] ) strcat(proto,",");
			strcat(proto,"delegate");
		}
		if( DELEGATE_getEnv(P_PROXY) && isHTTP(iSERVER_PROTO) ){
			if( proto[0] ) strcat(proto,",");
			strcat(proto,"http-proxy");
		}
		if( proto[0] != 0 ){
			InitLog(">>> dstProto=%s for SOCKS/MASTER/PROXY\n",
				proto);
		}else{
			strcpy(proto,"*");
		}
	}

	InitLog("MYAUTH=%s:****:%s:%s:%s\n",user,proto,dst,src);
	sprintf(myauthx,"{%s:%s}:%s:%s:%s",user,pass,proto,dst,src);
	scan_CMAP2(Conn,"MyAuth",myauthx);
}
void getREALPort(Connection *Conn,Port *dst);
void setREALPort(Connection *Conn,Port *src);
void setREALPortl(Connection *Conn,PCStr(proto),PCStr(host),int port);
int get_MYAUTH(Connection *Conn,PVStr(myauth),PCStr(proto),PCStr(dhost),int dport)
{	CStr(xproto,256);
	CStr(xhost,MaxHostNameLen);
	CStr(user,256);
	Port sv;
	int xport;
	int mx;

	/*
	if( streq(proto,GatewayProto) )
	if( GatewayUser[0] ){
	*/
	if( GatewayAuth && GatewayProto[0] && GatewayUser[0] )
	if( streq(proto,"http-proxy") && streq(GatewayProto,"http")
	 || streq(proto,"http-proxy") && streq(GatewayProto,"http-proxy")
	 || streq(proto,"ssltunnel")  && streq(GatewayProto,"ssltunnel")
	 || streq(proto,"socks")      && streq(GatewayProto,"socks")
	 || streq(proto,"delegate")   && streq(GatewayProto,"delegate")
	 || streq(proto,"ftp")        && streq(GatewayProto,"ftp")
	 || streq(proto,"telnet")     && streq(GatewayProto,"telnet")
	){
		sprintf(myauth,"%s:%s",GatewayUser,GatewayPass);
		nonxalpha_unescape(myauth,AVStr(myauth),1);
		sv1log("ROUTE/MYAUTH=%s:**** for %s:%s:%d\n",GatewayUser,
			REAL_PROTO,REAL_HOST,REAL_PORT);
		return 1;
	}

	if( proto ){
		getREALPort(Conn,&sv);
		setREALPortl(Conn,proto,dhost,dport);
	}

	if( 0 <= (mx = find_CMAP(Conn,"MyAuth",AVStr(myauth))) ){
		nonxalpha_unescape(myauth,AVStr(myauth),1);
		wordscanY(myauth,AVStr(user),sizeof(user),"^:");
		sv1log("MYAUTH=%s:**** for %s:%s:%d\n",user,
			REAL_PROTO,REAL_HOST,REAL_PORT);
	}

	if( proto )
		setREALPort(Conn,&sv);
	return 0 <= mx;
}

void cpyPort(Port *dst,Port *src)
{
	strcpy(dst->p_proto,src->p_proto);
	strcpy(dst->p_host, src->p_host);
	dst->p_port = src->p_port;
}
void getREALPort(Connection *Conn,Port *dst)
{
	cpyPort(dst,&Conn->sv);
}
void setREALPort(Connection *Conn,Port *src)
{
	cpyPort(&Conn->sv,src);
}
void setPort(Port *dst,PCStr(proto),PCStr(host),int port)
{
	wordscanX(proto,AVStr(dst->p_proto),sizeof(dst->p_proto));
	wordscanX(host, AVStr(dst->p_host), sizeof(dst->p_host));
	dst->p_port = port;
}
void setREALPortl(Connection *Conn,PCStr(proto),PCStr(host),int port)
{
	setPort(&Conn->sv,proto,host,port);
}


static struct {
	int ac_ok;
	int ac_err;
} SAC;
static void scan_SAC(Connection *Conn,PCStr(acscl)){
	CStr(clhost,MaxHostNameLen);
	refQStr(cp,clhost);
	int clport = 0;
	CStr(auth,256);
	refQStr(ap,auth);
	int ok;
	const char *addr;
	CStr(ab,128);

	strcpy(clhost,"255.255.255.255");
	strcpy(auth,"");
	clport = 1;
	Xsscanf(acscl,"%[^:]:%s",AVStr(clhost),AVStr(auth));
	if( cp = strchr(clhost,'/') ){
		truncVStr(cp);
		clport = atoi(cp+1);
	}

	bzero(Client_VAddr,sizeof(VAddr));
	strcpy(Client_Host,clhost);
	Client_Port = clport;
	if( VSA_strisaddr(clhost) ){
		VA_setClientAddr(Conn,clhost,clport,0);
	}else
	if( addr = gethostaddr(clhost) ){
		VA_setClientAddr(Conn,addr,clport,0);
	}
	bzero(&ClientAuth,sizeof(ClientAuth));
	if( auth[0] ){
		CStr(userpass,256);
		CStr(ahost,256);
		truncVStr(userpass);
		truncVStr(ahost);
		Xsscanf(auth,"%[^@]@%s",AVStr(userpass),AVStr(ahost));
		Xsscanf(userpass,"%[^:]:%[^\n]",
			AVStr(ClientAuth.i_user),
			AVStr(ClientAuth.i_pass));
	}

	daemonlog("F","-- SAC=%s\n",acscl);
	if( doAuth(Conn,&ClientAuth) < 0 ){
		daemonlog("F","Auth error\n");
		SAC.ac_err++;
	}
	if( ok = service_permitted2(Conn,DST_PROTO,2) )
		SAC.ac_ok++;
	else	SAC.ac_err++;
	daemonlog("F","%s %s:%d => %s://%s:%d\n",
		ok?"OK":"ERROR",
		clhost,clport,
		DST_PROTO,DST_HOST,DST_PORT
	);
}
int SimulateAC(int ac,const char *av[],Connection *Conn){
	CStr(svproto,64);
	CStr(svhost,MaxHostNameLen);
	int svport = 0;

	daemonlog("F","---- Simulated Access Control ------\n");
	strcpy(svproto,iSERVER_PROTO);
	strcpy(svhost,iSERVER_HOST);
	set_realserver(Conn,svproto,svhost,svport);

	DELEGATE_scanEnv(Conn,P_SAC,scan_SAC);
	daemonlog("F","---- Simulated Access Control => OK:%d ERR:%d\n",
		SAC.ac_ok,SAC.ac_err);
	if( SAC.ac_err )
		return -1;
	else	return 0;
}


#define WORDSIZE 64
#define LINESIZE 512

int getAnswerYNWTO(double dtx,PCStr(msg),PVStr(ans),int siz);
int getAnswerYNtty(PCStr(msg),PVStr(ans),int siz);
int dumpAuthMan(FILE *out){
	int ai;
	TmpAcl *Ta;
	for( ai = 0; ai < elnumof(TmpACL); ai++ ){
		Ta = &TmpACL[ai];
		if( Ta->ac_acrc ){
			fprintf(out,"Auth-Man: %X %X %X %X\r\n",
				Ta->ac_acrc,Ta->ac_time,
				Ta->ac_code,Ta->ac_count
			);
		}
	}
	return 0;
}
int loadAuthMan(FILE *in){
	int ao;
	TmpAcl *Ta;
	TmpAcl ta;
	IStr(line,256);
	int sn;

	ao = 0;
	for(;;){
		if( fgets(line,sizeof(line),in) == NULL ){
			break;
		}
		sn = sscanf(line,"Auth-Man: %X %X %X %X\r\n",
			&ta.ac_acrc,&ta.ac_time,
			&ta.ac_code,&ta.ac_count
		);
		if( sn != 4 ){
			continue;
		}
		if( elnumof(TmpACL) <= ao ){
			break;
		}
		Ta = &TmpACL[ao++];
		*Ta = ta;
	}
	return 0;
}
static FILE *fopenAuthMan(PCStr(mode)){
	IStr(path,1024);
	FILE *fp;
	sprintf(path,"%s/authman.txt",ADMDIR());
	fp = fopen(path,mode);
	return fp;
}
int clearAuthMan(){
	if( TmpACL[0].ac_acrc ){
		bzero(TmpACL,sizeof(TmpACL));
	}
	return 0;
}
int saveAuthMan(){
	FILE *fp;

	if( TmpACL[0].ac_acrc == 0 ){
		return 0;
	}
	if( fp = fopenAuthMan("w") ){
		dumpAuthMan(fp);
		fclose(fp);
		return 1;
	}
	return -1;
}
int restoreAuthMan(){
	FILE *fp;
	if( fp = fopenAuthMan("r") ){
		loadAuthMan(fp);
		fclose(fp);
		return 0;
	}
	return -1;
}

/*
 * AUTHORIZER=-man/3600
 */
int DISABLE_MANAUTH;
int suppressManAuthExpire;
static int MAX_PARA_MANAUTH = 1;
static int inManAuth;
char *getMacAddr(PCStr(host),PVStr(macaddr));
int authOnMemory(int *acc,int *rej){
	int ai;
	TmpAcl *Ta;
	int na = 0;

	if( acc ) *acc = 0;
	if( rej ) *rej = 0;
	for( ai = 0; ai < elnumof(TmpACL); ai++ ){
		Ta = &TmpACL[ai];
		if( Ta->ac_acrc ){
			na++;
			if( acc && Ta->ac_code ==  1 ) *acc += 1;
			if( rej && Ta->ac_code == -1 ) *rej += 1;
		}
	}
	return na;
}
int authenticate_by_man(Connection *Conn,PVStr(comment),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident){
	IStr(acdc,LINESIZE);
	int crc;
	int now;
	int ai;
	TmpAcl OTa;
	TmpAcl *Ta;
	TmpAcl *TaN = 0;
	TmpAcl *TaO = 0; /* oldest entry */
	int oldest = 0x7FFFFFFF;
	IStr(date,WORDSIZE);
	IStr(mssg,LINESIZE);
	IStr(line,WORDSIZE);
	IStr(com,WORDSIZE);
	IStr(cmn,WORDSIZE);
	const char *dp;
	int expire = 600;
	int code;
	IStr(maca,64);
	int gotyn;

	if( DISABLE_MANAUTH ){
		return DISABLE_MANAUTH;
	}

	if( *comment == '/' ){
		expire = (int)Scan_period(comment+1,'s',(double)600);
		if( expire == 0 ){
			expire = 600;
		}
	}
	clearVStr(comment);

	clearVStr(acdc);
	if( maca < getMacAddr(Client_Host,AVStr(maca)) )
	Xsprintf(TVStr(acdc),"-- MacA: %s\r\n",maca);
	Xsprintf(TVStr(acdc),"-- Client: %s\r\n",Client_Host);
	Xsprintf(TVStr(acdc),"-- User: %s\r\n",user);
	Xsprintf(TVStr(acdc),"-- Pass: %s\r\n",pass);

	crc = strCRC32(acdc,strlen(acdc));
	now = time(0);
	for( ai = 0; ai < elnumof(TmpACL); ai++ ){
		Ta = &TmpACL[ai];
		if( Ta->ac_acrc == crc ){
			Ta->ac_count++;
			if( 0 < Ta->ac_code ){
				/*
				if( now <= Ta->ac_time+expire ){
				*/
				if( (suppressManAuthExpire & 1)
				 || now <= Ta->ac_time+expire ){
		sprintf(comment,"%d seconds remains",Ta->ac_time+expire-now);
					sv1log("-- auth_by_man OK cached\n");
					Ta->ac_time = now;
					return Ta->ac_code;
				}
			}else{
				if( now <= Ta->ac_time+10
				 || (suppressManAuthExpire & 2)
				 || 2 < Ta->ac_count && now <= Ta->ac_time+30
				){
		sv1log("-- auth_by_man NG cached (%ds #%d) code=%d\n",
		now-Ta->ac_time,Ta->ac_count,Ta->ac_code);
					if( Ta->ac_code == -99 ){
						/* incomplete */
						break;
					}
					return Ta->ac_code;
				}
			}
			TaN = Ta;
			break;
		}
		if( Ta->ac_acrc == 0 || Ta->ac_time+expire < now ){
			if( TaN == 0 ){
				TaN = Ta;
			}
		}
		if( Ta->ac_time < oldest ){
			oldest = Ta->ac_time;
			TaO = Ta;
		}
	}
	if( ident->i_stat == AUTH_TESTONLY ){
		return -1;
	}
	if( lNOAUTHPROXY() ){
		if( ClientFlags & PF_AS_PROXY ){
			/* suppress the interaction for -man */
			return 0;
		}
	}
	if( TaN == 0 && TaO != 0 ){
		sv1log("-- auth_by_man pushed out %d %d %d\n",
			now-TaO->ac_time,TaO->ac_code,TaO->ac_count);
		TaN = TaO;
	}
	if( TaN ){
		OTa = *TaN;
		TaN->ac_code = -99; /* under auth. confirmation */
		TaN->ac_acrc = crc;
		TaN->ac_time = time(0);
		TaN->ac_count = 1;
	}

	if( 1 ){
		int dstok,srcok;
		dstok = isREACHABLE(DST_PROTO,DST_HOST);
		if( lIMMREJECT() ){
			/* must have checked already with tobeREJECTED() */
	 		srcok = 2;
		}else
	 	srcok = source_permitted(Conn);
		sv1log("--man-- dst=%d <%s://%s> src=%d\n",dstok,DST_PROTO,DST_HOST,
			srcok);
		if( !dstok || !srcok ){
			return -1;
		}
	}

	StrftimeLocal(AVStr(date),sizeof(date),"%H:%M:%S",time(0),0);
	clearVStr(mssg);
	if( TaN ){
		if( OTa.ac_acrc == crc )
			Xsprintf(TVStr(mssg),"Re-Auth. Request\r\n");
		else	Xsprintf(TVStr(mssg),"New-Auth. Request\r\n");
	}else
	Xsprintf(TVStr(mssg),"Auth. Request\r\n",path);
	Xsprintf(TVStr(mssg),"-- Service: %s\r\n",DST_PROTO);
	Xsprintf(TVStr(mssg),"-- Port: %d\r\n",Conn->clif._acceptPort,
		Conn->clif._portProto);
	Xsprintf(TVStr(mssg),"-- Time: %s\r\n",date);
	Xsprintf(TVStr(mssg),"%s",acdc);
	Xsprintf(TVStr(mssg),"Permit ? ");
	if( MAX_PARA_MANAUTH < ++inManAuth ){
		sv1log("-- auth_by_man NG max-para %d > %d\n",inManAuth,
			MAX_PARA_MANAUTH);
		inManAuth--;
		return -1;
	}
	if( lNOWIN() )
		gotyn = getAnswerYNtty(mssg,AVStr(line),sizeof(line));
	else	gotyn = getAnswerYNWTO(60,mssg,AVStr(line),sizeof(line));
	inManAuth--;
	if( gotyn != 0 ){
		sv1log("-- auth_by_man NG cant-get\n");
		return -1;
	}
	dp = wordScan(line,com);
	lineScan(dp,cmn);
	strcpy(comment,cmn);
	if( com[0] != 'y' ){
		sv1log("-- auth_by_man NG [%s][%s]\n",com,cmn);
		code = -1;
	}else{
		sv1log("-- auth_by_man OK [%s][%s]\n",com,cmn);
		code = 1;
	}
	if( TaN ){
		TaN->ac_code = code;
	}
	return code;
}

int AuthThru(Connection *Conn,PCStr(user)){
	if( Conn && MountOptions ){
		if( isinList(MountOptions,"authru") ){
			return 1;
		}
	}
	return 0;
}
