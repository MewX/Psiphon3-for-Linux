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
Program:	service.c (DeleGatable services)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940303	created
	940623	made per port restriction configurable
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "delegate.h"
#include "url.h"
#include "param.h" /* P_RES_VRFY */
#include "ystring.h"
#include "filter.h"
#include "fpoll.h"
#include "file.h"
#include "proc.h"
#include "auth.h"
#include "service.h"
extern Service services[];

int never_cache(Connection *Conn);
int setupConnect(Connection *Conn);
void set_SRCIF(Connection *Conn,PCStr(proto),PCStr(host),int port);

int tryCONNECT(Connection *Conn,void *cty,int relay_input,int *svsockp);
int ConnectViaICP(Connection *Conn,PCStr(dsturl));
int connectToUpper(Connection *Conn,PCStr(where),PCStr(proto),PCStr(host),int port);
int ConnectViaSSLtunnel(Connection *Conn,PCStr(host),int port);

char D_SERVICE_BYPORT[] = "-";

extern int IamPrivateMASTER;
extern int myPrivateMASTER;
extern int BREAK_STICKY;
static void sv1mlog(PCStr(fmt),...)
{
	VARGS(7,fmt);

	if( IamPrivateMASTER || myPrivateMASTER )
		return;

	sv1log(fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
}

void prservices(FILE *fp)
{	int si;
	Service *sp;

	for( si = 1; services[si].s_name; si++ ){
		sp = &services[si];
		if( 0 < sp->s_iport && sp->s_iport < 8000 )
		fprintf(fp,"%-15s %d\r\n",sp->s_name,sp->s_iport);
	}
}

const char *servicename(int port,const char **name){
	int si;
	Service *sp;
	const char *nm;

	for( si = 1; nm = services[si].s_name; si++ ){
		sp = &services[si];
		if( sp->s_iport == port ){
			if( name ) *name = nm;
			return nm;
		}
	}
	if( name ) *name = "";
	return 0;
}
static int servicex(PCStr(service))
{	int si;
	Service *sp;

	for( si = 1; services[si].s_name; si++ ){
		sp = &services[si];
		if( strcaseeq(sp->s_name,service) )
			return si;
	}
	return 0;
}
int serviceid(PCStr(service)){
	return servicex(service);
}

void enableServs(PCStr(proto),int enable){
	int si;
	if( streq(proto,"*") ){
		for( si = 1; services[si].s_name; si++ ){
			if( 0 < enable )
				services[si].s_stats &= ~SV_DISABLE;
			else	services[si].s_stats |=  SV_DISABLE;
		}
	}else{
		if( si = servicex(proto) ){
			if( 0 < enable )
				services[si].s_stats &= ~SV_DISABLE;
			else	services[si].s_stats |=  SV_DISABLE;
		}
	}
}
int service_disabled(PCStr(proto)){
	int si;
	if( si = servicex(proto) ){
		if( services[si].s_stats & SV_DISABLE )
			return 1;
		else	return 0;
	}
	return -1;
}
void lsProtos(FILE *out){
	int fi;
	const char *name;
	for( fi = 1; name = services[fi].s_name; fi++ )
		fprintf(out,"%-15s ",name);
}

/*
 * SERVICE=name:[port[/udp]][:service]
 */
void scan_SERVICE(Connection *Conn,PCStr(desc))
{	int ic,ii,port,si,sn;
	CStr(ib,64);
	const char *iv[4]; /**/
	const char *equiv;
	const char *name;

	lineScan(desc,ib);
	ic = stoV(ib,3,iv,':');
	for( ii = ic; ii < 3; ii++ )
		iv[ii] = "";
	name = iv[0];
	port = atoi(iv[1]);
	equiv = iv[2];

	sn = servicex(name);
	if( sn == 0 ){
		for( sn = 1; sn < NSERVICES-1; sn++ )
			if( services[sn].s_name == 0 )
				break;
	}
	si = 0;
	if( equiv[0] ){
		si = servicex(equiv);
		if( si == 0 ){
			sv1log("ERROR: unknown service '%s'\n",equiv);
			return;
		}
	}
	if( sn != si && si != 0 ){
		services[sn] = services[si];
		services[sn].s_name = stralloc(name);
	}
	if( port ){
		services[sn].s_iport = port;
	}
	sv1log("[%d][%d] SERVICE=%s:%d:%s\n",sn,si,
		services[sn].s_name,services[sn].s_iport,equiv);
}
int protoeq(PCStr(proto1),PCStr(proto2))
{	int s1,s2;

	if( strcaseeq(proto1,proto2) == 0 )
		return 1;
	s1 = servicex(proto1);
	s2 = servicex(proto2);
	return services[s1].s_client == services[s2].s_client;
}
int foreach_eqproto(PCStr(proto),int (*func)(const void*,...),...)
{	int sn,sx,si;
	servFuncP svfunc;
	const char *name;

	sn = 0;
	if( sx = servicex(proto) )
	if( svfunc = services[sx].s_client ){
		VARGS(16,func);
		for( si = 1; name = services[si].s_name; si++ ){
			if( services[si].s_client == svfunc ){
				(*func)(name,VA16);
				sn++;
			}
		}
	}
	return sn;
}
int serviceport(PCStr(service))
{	int si;

	if( si = servicex(service) )
		return services[si].s_iport;
	else	return 0;
}
static int withcache(PCStr(proto))
{	int si;

	if( si = servicex(proto) )
		return services[si].s_withcache;
	else	return 0;
}
int serviceWithSTLS(PCStr(service)){
	int si;

	if( si = servicex(service) )
		return services[si].s_stls;
	else	return 0;
}
static int get_initfrom(Connection *Conn){
	int si;
	if( si = servicex(DST_PROTO) )
		return services[si].s_initfrom;
	else	return 0;
}

servFunc service_console;
servFunc service_delegate;
static servFuncP get_servfunc(Connection *Conn,int clsock,int *withcachep,int *selfackp,int *initfrom)
{	int si;
	Service *sp;
	const char *service;
	int iport;
	int byport;

	*withcachep = 0;
	*selfackp = 0;
	*initfrom = 0;

	if( CLIF_PORT != 0 )
	if( CLIF_PORT == Console_Port ){
		return service_console;
	}

	service = DFLT_PROTO;

	iport = DFLT_PORT;
	byport = streq(service,D_SERVICE_BYPORT);
	if( byport == 0 ){
		if( Port_Proto ){
			byport = 1;
			iport = Port_Proto;
		}
	}

	for( si = 1; services[si].s_name; si++ ){
	    sp = &services[si];
	    if( !byport && strcaseeq(sp->s_name,service)
	     ||  byport && iport && sp->s_iport == iport
	    ){
		if( byport )
			strcpy(DFLT_PROTO,sp->s_name);

		if( DFLT_PORT == 0 )
			DFLT_PORT = sp->s_iport;
		*withcachep = sp->s_withcache;
		*selfackp = sp->s_selfack;
		*initfrom = sp->s_initfrom;

		if( DFLT_HOST[0] == 0 )
			if( sp->s_Host )
				strcpy(DFLT_HOST,sp->s_Host);

		return sp->s_client;
	    }
	}
	*initfrom = PI_CLNT;
	return &service_delegate;
}

void scan_REJECT(Connection *Conn,PCStr(protolist))
{
	Conn->forreject = 1;
	scan_PERMIT(Conn,protolist);
	Conn->forreject = 0;
}
void scan_PERMITV(Connection *Conn,PCStr(list),const char *protov[]);
void scan_PERMIT(Connection *Conn,PCStr(protolist))
{	const char *pn;
	const char *pv[NSERVICES]; /**/
	int si,pi;

	pi = 0;
	for( si = 1; pn = services[si].s_name; si++ ){
		if( elnumof(pv)-1 <= pi )
			break;
		pv[pi++] = (char*)pn;
	}
	pv[pi] = 0;
	scan_PERMITV(Conn,protolist,pv);
}

int permitted_readonly(Connection *Conn,PCStr(proto))
{
	int ro = 0;
	int ndck;
	ndck = Conn->no_dstcheck;
	Conn->no_dstcheck = 0; /* protList must be checked */

	if( method_permittedX(Conn,"readonly",NULL,0)
	 || method_permittedX(Conn,proto,".REJECT",0) == 0 /* explicitly defined */
	 && method_permittedX(Conn,proto,"readonly",0) != 0 ){
		sv1log("#### %s: READ-ONLY\n",proto);
		ro = 1;
		/*
		return 1;
		*/
	}
	Conn->no_dstcheck = ndck;
	return ro;
	/*
	return 0;
	*/
}

int DO_METHOD_FILTER;
int method_permitted(Connection *Conn,PCStr(proto),PCStr(method),int igncase)
{	int ok;

	if( DO_METHOD_FILTER == 0 )
		return 1;

	/* method filtering with password authentication for HTTP does
	 * not work in the current implementation... when the method is
	 * checked, HTTP authentication information is not set in
	 * Conn. structure... method checking should be done in
	 * service_permitted() in future implementation.
	 */
	ok = method_permittedX(Conn,proto,method,igncase);
	return ok;
}
int DELEGATE_permitM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);
int DELEGATE_rejectM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);

int method_permittedX(Connection *Conn,PCStr(proto),PCStr(method),int igncase)
{	CStr(shost,512);
	CStr(umethod,64);
	int sport;
	int acceptable;

	if( method != NULL && igncase ){
		strtoupper(method,umethod);
		method = umethod;
	}

	sport = getClientHostPort(Conn,AVStr(shost));
	CTX_pushClientInfo(Conn);
	acceptable = DELEGATE_permitM(Conn,proto,method,DST_HOST,DST_PORT,
			shost,sport /*,serviceport(proto)*/);
	if( acceptable ){
		if( DELEGATE_rejectM(Conn,proto,method,DST_HOST,DST_PORT,
			shost,sport /*,serviceport(proto)*/) )
				acceptable = 0;
	}
	HL_popClientInfo();
	return acceptable;
}

int addtoHostSet(PCStr(hostset),PCStr(host),PCStr(addr));
void logReject(Connection *Conn,int self,PCStr(shost),int sport);
void delayReject(Connection *Conn,int self,PCStr(method),PCStr(sproto),PCStr(shost),int sport,PCStr(dpath),PCStr(referer),PCStr(reason));
int PERMITTED_ACCESS(Connection *Conn,PCStr(shost),int sport,int stdport);

int VA_url_permitted(VAddr *vaddr,AuthInfo *auth,PCStr(url)){
	Connection ConnBuf,*Conn = &ConnBuf;
	CStr(proto,64);
	CStr(site,MaxHostNameLen);
	CStr(path,1024);
	CStr(host,MaxHostNameLen);
	int port;
	int ok;

	/* fix-140524c
	bzero(Conn,sizeof(Conn));
	 */
	bzero(Conn,sizeof(Connection));
	*Client_VAddr = *vaddr;
	Conn->cl_sockHOST = *vaddr;
	if( auth ){
	}
	decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(path),sizeof(path));
	port = scan_hostportX(proto,site,AVStr(host),sizeof(host));
	set_realsite(Conn,proto,host,port);
	ok = service_permitted2(Conn,proto,1);
	return ok;
}
int url_permitted(PCStr(url)){
	VAddr vaddr;
	int ok;

	bzero(&vaddr,sizeof(VAddr));
	VA_setVAddr(&vaddr,"127.0.0.1",1,0);
	strcpy(vaddr.a_name,"localhost");
	ok = VA_url_permitted(&vaddr,NULL,url);
	return ok;
}

typedef struct {
	int	ac_time;
	int	ac_stat;
	int	ac_addr;
	short	ac_port;
	short	ac_cnt;
} AccHist;
static AccHist *accHist;
static int accx;
static int accn;
void addAccHist(Connection *Conn,int stat){
	int acci;
	AccHist *ap = 0;
	int now;

	if( !lACCLOG() )
		return;

	now = time(0);
	if( accn == 0 ){
		accn = 32;
		accHist = (AccHist*)malloc(sizeof(AccHist)*accn);
		bzero(accHist,sizeof(AccHist)*accn);
	}
	if( 0 < accx ){
		acci = (accx-1) % accn;
		ap = &accHist[acci];
		if( ap->ac_addr != Client_VAddr->I3
		 || ap->ac_stat && stat && ap->ac_stat != stat
		 || 30 < now - ap->ac_time
		){
			ap = 0;
		}
	}
	if( ap == 0 ){
		acci = accx++ % accn;
		ap = &accHist[acci];
		bzero(ap,sizeof(AccHist));
	}
	ap->ac_time = now;
	ap->ac_addr = Client_VAddr->I3;
	ap->ac_port = Conn->clif._acceptPort;
	if( stat != ACC_STARTED )
	ap->ac_stat = stat;
	if( stat ){
		ap->ac_cnt++;
	}
	if( stat & ACC_OK ){
		LOGX_accPassed++;
	}
	if( stat & ACC_FORBIDDEN ){
		LOGX_accDenied++;
	}
	if( stat & ACC_AUTH_DENIED ){
		LOGX_accDenied++;
	}
}
char *listAccHist(PVStr(list),int am){
	refQStr(lp,list);
	int ai0,ax0,ai,ax,an;
	AccHist *ap;
	IStr(stm,32);

	if( accHist == 0 ){
		return (char*)list;
	}
	ai0 = accx;
	ax0 = ai0 % accn;
	an = 0;
	for( ai = accx - 1; 0 <= ai; ai-- ){
		ax = ai % accn;
		ap = &accHist[ax];
		StrftimeLocal(AVStr(stm),sizeof(stm),"%H:%M:%S",ap->ac_time,0),
		Rsprintf(lp,"%s %s %3d %4d %s\n",stm,
			ap->ac_stat == ACC_OK?"+":"-",
			ap->ac_cnt,ap->ac_port,
			_inet_ntoaV4I(htonl(ap->ac_addr)));
		if( ax == ax0 )
			break;
		if( am <= ++an ){
			break;
		}
	}
	return (char*)lp;
}

int service_permitted2(Connection *Conn,PCStr(service),int silent)
{	int clsock;
	int acceptable;
	CStr(shost,512);
	int sport;

	if( Conn->from_myself )
		return 1;

	clsock = ClientSock;
	sport = getClientHostPort(Conn,AVStr(shost));

	if( !IsInetaddr(shost) ) /* i.e. it's a reverse-resolved name */
	if( !hostIsResolvable(shost) ) /* but it cannot be resolved */
	{	CStr(addr,64);

		VA_inetNtoah(Client_VAddr,AVStr(addr));
		sv1log("### INCONSISTENT client host name: %s -> %s -> ?\n",
			addr,shost);
		if( DELEGATE_getEnv(P_RES_VRFY) )
			return 0;
		if( !IsInetaddr(addr) )
			return 0;
		strcpy(Client_Host,addr);
		strcpy(shost,addr);
	}
	if( sport == 0 ){
		sv1log("Cannot get peer name: fd=[%d]\n",clsock);
		return 0;
	}
	CTX_pushClientInfo(Conn);
	acceptable = PERMITTED_ACCESS(Conn,shost,sport,serviceport(service));
	HL_popClientInfo();

	if( acceptable && TeleportHost[0] ){
		strcpy(shost,TeleportHost);
		sport = TeleportPort;
		acceptable = PERMITTED_ACCESS(Conn,shost,sport,serviceport(service));
	}

	if( !silent ){
		addAccHist(Conn,acceptable?ACC_OK:ACC_FORBIDDEN);
	}

	if( acceptable ){
		Verbose("PERMITTED: %s://%s\n",DST_PROTO,DST_HOST);
	}else{
		if( streq(DST_PROTO,"ssltunnel") ){
			/* it is normal in usual config. */
		}else{
		CStr(addr,64);
		addtoHostSet("rejected",shost,Client_Addr(addr));
		}
		if( silent & 0x02 ){
			logReject(Conn,1,shost,sport);
		}else
		if( !silent ){
			logReject(Conn,1,shost,sport);
			delayReject(Conn,1,"DELEGATE",service,shost,sport,"","",
			"Forbidden by DeleGate");
		}
		ConnError = CO_REJECTED;
	}
	return acceptable;
}
void setOriginIdent(Connection *Conn,PCStr(sockname),PCStr(peername))
{
	if( peername && *peername ){
	Xsscanf(peername,"%[^:]:%d",AVStr(TeleportHost),&TeleportPort);
	strcpy(TeleportAddr,TeleportHost);
	gethostbyAddr(TeleportHost,AVStr(TeleportHost));
	}
	if( sockname && *sockname ){
	Xsscanf(sockname,"%[^:]:%d",AVStr(TelesockHost),&TelesockPort);
	}
}
int gettelesockname(Connection *Conn,PVStr(sockname)){
	if( TelesockHost[0] ){
		sprintf(sockname,"%s:%d",TelesockHost,TelesockPort);
		return 0;
	}
	return -1;
}
int getteleportname(Connection *Conn,PVStr(peername)){
	if( TeleportHost[0] ){
		sprintf(peername,"%s:%d",TeleportHost,TeleportPort);
		return 0;
	}
	return -1;
}

int DELAY_REJECT_S = 60;
int DELAY_UNKNOWN_S = 60;
int DELAY_REJECT_P = 0;
int DELAY_UNKNOWN_P = 0;
int DELAY_ERROR = 30;
int DELAY_OVERLOOK = 5;

int server_open_localhost(PCStr(what),PVStr(path),int nlisten);
static void delayClose(PVStr(path),int clsock,int delay)
{	CStr(buf,1024);
	int start;
	int wsock;
	int fc,fv[2],rfv[2],nready;
	int ssec;

	fc = 0;
	fv[fc++] = clsock;

	wsock = server_open_localhost("doDelay",AVStr(path),1);
	if( 0 <= wsock )
		fv[fc++] = wsock;
	else	sv1log("#### doDelay: bind failed.\n");

	while( 0 < delay ){
		start = time(0L);
		if( 0 < (nready = PollIns(delay*1000,fc,fv,rfv)) )
		if( 1 < fc && 0 < rfv[1] ){
			sv1log("doDelay: pushed out.\n");
			break;
		}
		/*
		 * Maybe this is intended to detect disconnection of this
		 * client's connection (clsock) and stop delaying as soon
		 * as possible after the disconnection.
		 *
		 * Real reading of client data is harmful for delaying for
		 * connection oriented protocol like FTP, or keep-alived HTTP.
		 * But the disconnection may not be detected without draining
		 * queued input data if exist. (although it may be rare case,
		 * at least "QUIT command" may be waiting in the queue)
		 * Checking output ability (by PollOut()) for disconnection
		 * detection can be useful... but it might not be
		 * a bi-directional socket (although it's rare case)
		 *
		if( readTimeout(clsock,buf,sizeof(buf),1) <= 0 )
			break;
		*/
		if( !IsAlive(clsock) ){
			sv1log("#### doDelay: client seems disconnected.\n");
			break;
		}
		delay -= (time(0L) - start);
		if( delay <= 0 )
			break;

		/*
		 * interval to check the death of this client or arrival of
		 * another connection from the client which will be detected
		 * with "wsock".
		 */
		ssec = 2;
		if( delay < ssec )
			ssec = delay;
		if( 0 < ssec )
			sleep(ssec);
		delay -= ssec;
	}
	close(wsock);
	unlink(path);
}

void get_delaysock(PCStr(file),PVStr(path));
static void delaysockpath(Connection *Conn,PVStr(file),PVStr(path))
{	CStr(host,MaxHostNameLen);
	CStr(addr,256);

	getClientHostPortAddr(Conn,AVStr(host),AVStr(addr));
	sprintf(file,"%02d/%s:%s",FQDN_hash(host)%32,addr,host);
	get_delaysock(file,AVStr(path));
}

/*
 * wait by MD5 of given key ... MD5("name:value")
 * client:host
 * content-md5:md5
 */
void waitClientDelay(Connection *Conn,int ifd,int delay)
{	CStr(spath,1024);
	CStr(cpath,1024);
	CStr(file,256);
	int wsock,nfd,fdv[2],rdv[2],nready;

	if( lSINGLEP() ){
		fprintf(stderr,"-- %X no waitClientDelay: %s://%s:%d\n",
			TID,DST_PROTO,DST_HOST,DST_PORT);
		return;
	}
	delaysockpath(Conn,AVStr(file),AVStr(spath));
sv1log("##CALLBACK# SET DELAY[%s]\n",spath);
	wsock = client_open_localhost("doDelay",spath,1);
	if( 0 <= wsock ){
		sv1log("##[%s] push out previous delay (%ds)\n",
			file,(int)(time(0L)-File_mtime(spath)));
		close(wsock);
	}
	wsock = server_open_localhost("doDelay",AVStr(spath),1);
	nfd = 0;
	if( 0 <= wsock )
		fdv[nfd++] = wsock;
	if( 0 <= ifd )
		fdv[nfd++] = ifd;
	nready = PollIns(delay,nfd,fdv,rdv);
}
int findClientDelay(Connection *Conn)
{	CStr(spath,1024);
	CStr(file,256);

	if( lSINGLEP() ){
		fprintf(stderr,"-- %X no findClientDelay: %s://%s:%d\n",
			TID,DST_PROTO,DST_HOST,DST_PORT);
		return 0;
	}
	delaysockpath(Conn,AVStr(file),AVStr(spath));
	if( File_is(spath) ){
sv1log("##CALLBACK# GET DELAY[%s] = age:%d\n",spath,
(int)(time(0L)-File_mtime(spath)));
		return time(0L)-File_mtime(spath);
	}
	return 0;
}

static int doDelay(Connection *Conn,PCStr(method),int maxdelay,PVStr(cpath),PVStr(spath),int *countp)
{	CStr(path,1024);
	CStr(file,256);
	long count,mtime,age,dodelay;
	int delays;
	int wsock;

	if( RequestFlags & QF_NO_DELAY ){
		return 0;
	}
	if( lSINGLEP() ){
		if( !lSILENT() )
		if( lTRANSMIT() )
		fprintf(stderr,"-- %4X no delay: %s://%s:%d (%s)\n",
			TID,DST_PROTO,DST_HOST,DST_PORT,method);
		return 0;
	}
	if( maxdelay <= 0 )
		return 0;

	/* The client host may make next connection without waiting the
	 * closing of the current connection.  In such case, delaying all
	 * connection to close will make a pile of waiting process for the
	 * client.  Thus push out previous process if exists.
	 */
	delaysockpath(Conn,AVStr(file),AVStr(spath));
	wsock = client_open_localhost("doDelay",spath,1);
	if( 0 <= wsock ){
		sv1log("doDelay: push out previous delay.\n");
		close(wsock);
	}

	/* peer count is not available ? */
	if( Conn->cl_count <= 0 )
		return 0;

	sprintf(path,"%s/%s",method,file);
	count = countUp(path,1,1,getpid(),&mtime,AVStr(cpath));

	/* error counter is not available ? */
	if( count <= 0 || mtime == 0 )
		return 0;

	/* overlook the first error */
/*
	if( count <= 1 )
*/
	if( count <= DELAY_OVERLOOK  )
		return 0;

	/* clear errors of long ago. */
	age = time(0L) - mtime;
	if( maxdelay < age ){
		sv1log("doDelay: clear old errors: count=%d,age=%d,delay=%d\n",
			ll2i(count),ll2i(age),maxdelay);
		count = countUp(path,1,0,getpid(),&mtime,AVStr(cpath));
		return 0;
	}

	/* Do delay when errors occured in rapid succession.
	 * The age of the error coutner shows the interval of errors.
	 * The minimum interval should be long if the desirable delay is
	 * long, the situation where error is serious.
	 */
	dodelay = age <= maxdelay / 4 + 1;
	Verbose("doDelay: %d count=%d, age=%d, delay=%d\n",
		ll2i(dodelay),ll2i(count),ll2i(age),maxdelay);
	if( !dodelay )
		return 0;

	/* reach the maximum delay in 20 errors. */
	*countp = count;
/*
	delays = count * (maxdelay / 20 + 1);
*/
	delays = (count - DELAY_OVERLOOK) * (maxdelay / 20 + 1);
	if( maxdelay < delays )
		delays = maxdelay;
	return delays;
}
void logReject(Connection *Conn,int self,PCStr(shost),int sport)
{	const char *what;
	const char *direct;
	CStr(server,MaxHostNameLen);

	HostPort(AVStr(server),DST_PROTO,DST_HOST,DST_PORT);
	if( self ){
		what = "E-P: No permission";
		direct = "=>";
	}else{
		what = "E-R: Rejected";
		direct = "<=";
	}
/*
	daemonlog("F","%s: %s:%d %s %s://%s\n",
		what, shost,sport, direct, DST_PROTO,server);
*/
	daemonlog("F","%s: %s:%d %s %s://%s (%s)\n",
		what, shost,sport, direct, DST_PROTO,server,Conn->reject_reason);
}

void addRejectList(Connection *Conn,PCStr(what),PCStr(dpath),PCStr(referer),PCStr(auser),PCStr(apass),PCStr(reason));
void delayRejectX(Connection *Conn,int self,PCStr(sproto),PCStr(shost),int sport,int clsock);
void delayReject(Connection *Conn,int self,PCStr(method),PCStr(sproto),PCStr(shost),int sport,PCStr(dpath),PCStr(referer),PCStr(reason))
{
	if( lSINGLEP() ){
		fprintf(stderr,"-- [%X]%X no delayReject: %s://%s:%d <= \n",
			SVX,TID,DST_PROTO,DST_HOST,DST_PORT);
		return;
	}
	addRejectList(Conn,method,dpath,referer,"","",reason);
	delayRejectX(Conn,self,sproto,shost,sport,FromC);
}
void delayRejectX(Connection *Conn,int self,PCStr(sproto),PCStr(shost),int sport,int clsock)
{	CStr(cpath,1024);
	CStr(spath,1024);
	int delays,count;
	int delay;

	if( self )
		delay = DELAY_REJECT_S;
	else	delay = DELAY_REJECT_P;
	delays = doDelay(Conn,"errors/reject",delay,AVStr(cpath),AVStr(spath),&count);
	if( delays == 0 )
		return;

	checkCloseOnTimeout(0);
	sv1log("doDelay: delaying reject*%d (%d/%dsecond) %s:%d[%d]\n",
		count, delays,delay, shost,sport,Conn->cl_count);
	ProcTitle(Conn,"(reject:%d)%s://%s/",delays,DST_PROTO,DST_HOST);
	delayClose(AVStr(spath),clsock,delays);
	File_touch(cpath,time(0));
}
void delayConnError(Connection *Conn,PCStr(req))
{	int delay;
	CStr(path,1024);
	CStr(msg,0x4000);

/*
The delay should be done just after accept() ...

	delay = DELAY_ERROR;
	if( !doDelay(Conn,"error/comm",delay,path) )
		return;

	checkCloseOnTimeout(0);
	sv1log("delaying on communication error (%d)\n",delay);
	ProcTitle(Conn,"(error:%d)%s://%s/",delay,DST_PROTO,DST_HOST);
	delayClose(FromC,delay);
	File_touch(path,time(0));
*/
}
void delayUnknown(Connection *Conn,int self,PCStr(req))
{	int delay;
	int delays,count;
	CStr(cpath,1024);
	CStr(spath,1024);
	CStr(shost,MaxHostNameLen);
	int sport;
	const char *eol;
	CStr(reqn,URLSZ);

	eol = strtailchr(req) == '\n' ? "" : "\n";
	sport = getClientHostPort(Conn,AVStr(shost));
/*
	daemonlog("F","%s: %s:%d %s %s%s",
		"E-U: Unknown",shost,sport,"=>",req,eol);
*/
	lineScan(req,reqn);
	daemonlog("F","%s: %s:%d %s %s [%s://%s:%d]\n","E-U: Unknown",
		shost,sport,"=>",reqn,DST_PROTO,DST_HOST,DST_PORT);

	if( self )
		delay = DELAY_UNKNOWN_S;
	else	delay = DELAY_UNKNOWN_P;
	delays = doDelay(Conn,"errors/unknown",delay,AVStr(cpath),AVStr(spath),&count);
	if( delays == 0 )
		return;

	checkCloseOnTimeout(0);

	sv1log("doDelay: delaying unknown*%d (%d/%dseconds) %s%s",
		count, delays,delay, req,eol);

	ProcTitle(Conn,"(unknown:%d)%s://%s/",delays,DST_PROTO,DST_HOST);
	delayClose(AVStr(spath),FromC,delays);
	File_touch(cpath,time(0));
}

int service_permitted(Connection *Conn,PCStr(service)/*,int silent*/)
{
	return service_permitted2(Conn,service,0);
}

const char *HelloWord(){ return "DeleGate-HELLO"; }
int isHelloRequest(PCStr(req))
{
	return strncmp(req,"DeleGate-HELLO",14) == 0;
}
static
int scanHelloVer(PCStr(resp),PVStr(ver))
{
	setVStrEnd(ver,0);
	return Xsscanf(resp,"DeleGate-HELLO %[^ \t\r\n]",AVStr(ver));
}

int vercmp(PCStr(ver1),PCStr(ver2))
{	int v1[3],v2[3],vi,diff;

	for( vi = 0; vi < 3; vi++ )
		v1[vi] = v2[vi] = 0;

	sscanf(ver1,"%d.%d.%d",&v1[0],&v1[1],&v1[2]);
	sscanf(ver2,"%d.%d.%d",&v2[0],&v2[1],&v2[2]);

	diff = 0;
	for( vi = 0; vi < 3; vi++ )
		if( diff = v1[vi] - v2[vi] )
			break;

	return diff;
}

extern int HELLO_TIMEOUT;
/*
 * -- HELLO_TIMEOUT COULD BE LONG ENOUGH IF NOT ALWAYS CHECKED
 * -- If already elapsed more than HELLO_TIMEOUT seconds since connection open
 * (= about since forked), then the client is no more waiting for HELLO reply,
 * and sending it is halmful for the client.
 */

#include "credhy.h"
int hextoStr(PCStr(hex),PVStr(bin),int siz);
static Credhy cKey;
static int DHKEYwithCL;
static void sendDHkey(FILE *tc){
	int klen;
	CStr(key,1024);
	CStr(xkey,1024);

	CredhyInit(&cKey,0);
	cKey.k_flags |= CR_AKFIRST | CR_CRC32;
	klen = CredhyGenerateKey(&cKey,AVStr(key),sizeof(key));
	strtoHex(key,klen,AVStr(xkey),sizeof(xkey));
	fprintf(tc,"DHKEY %s\r\n",xkey);
	fflush(tc);
}
static void recvDHkey(PCStr(pkey)){
	CStr(xkey,512);
	CStr(key,512);

	truncVStr(xkey);
	Xsscanf(pkey,"%s",AVStr(xkey));
	hextoStr(xkey,AVStr(key),sizeof(key));
	if( CredhyAgreedKey(&cKey,key) != 0 ){
		sv1log(">>>> DHKEY -- CANT GET AGREED KEY\n");
	}
}
static void sendAUTH(Connection *Conn,FILE *ts,PCStr(auth)){
	CStr(xauth,256);
	if( cKey.k_leng == 0 ){
		return;
	}
	CredhyAencrypt(&cKey,auth,AVStr(xauth),sizeof(xauth));
	fprintf(ts,"AUTH CREDHY %s\r\n",xauth);
	fflush(ts);
}
static int recvAUTH(Connection *Conn,PCStr(name),PCStr(value),AuthInfo *ident){
	CStr(atype,128);
	CStr(xauth,256);
	CStr(auth,256);

	if( !strcaseeq(name,"AUTH") )
		return 0;

	truncVStr(xauth);
	Xsscanf(value,"%s %s",AVStr(atype),AVStr(xauth));
	truncVStr(auth);
	CredhyAdecrypt(&cKey,xauth,AVStr(auth),sizeof(auth));
	Xsscanf(auth,"%[^:]:%[^\n]",AVStr(ident->i_user),AVStr(ident->i_pass));
	return 1;
}
static void getAuthXM(Connection *Conn,PVStr(myauth),int mx,int msock){
	Port sv = Conn->sv;
	VAddr master;

	strcpy(REAL_PROTO,"delegate");
	if( VA_getpeerNAME(msock,&master) ){
		strcpy(REAL_HOST,master.a_name);
		REAL_PORT = master.a_port;
	}
	get_MYAUTH(Conn,AVStr(myauth),"delegate",DST_HOST,DST_PORT);
	Conn->sv = sv;
}
int doAuthX(Connection *Conn,AuthInfo *ident);
static int doAuthXM(Connection *Conn,int clsock,AuthInfo *ident){
	Port sv = Conn->sv;
	int sfc = FromC;
	int wa;

	strcpy(REAL_PROTO,"delegate");
	strcpy(REAL_HOST,"-"); /* MASTER DeleGate itself */
	REAL_PORT = -1; /* to avoid "already authrorized" in doAUTH0() */
	FromC = clsock; /* referred in Identify() */
	if( wa = CTX_withAuth(Conn) ){
		if( ident != NULL ){
			if( doAuthX(Conn,ident) < 0 ){
				wa = -1;
			}
		}
	}
	FromC = sfc;
	Conn->sv = sv;
	return wa;
}

static void returnHELO(Connection *Conn,FILE *tc);
static void gotHELLO(Connection *Conn,FILE *tc,PCStr(fieldname),PCStr(value))
{	CStr(version,64);
	CStr(control,64);
	const char *cp;

	cp = wordScan(value,version); lineScan(cp,control);
	sv1mlog("CLIENT says: %s %s [%s]\n",fieldname,version,control);

	DHKEYwithCL = 0;
	if( streq(control,"DHKEY") ){
		if( doAuthXM(Conn,fileno(tc),NULL) ){
			DHKEYwithCL = 1;
		}
	}

	strcpy(ClientVER,version);
	if( streq(control,"NOACK") )   NoACK = 1; else
	if( streq(control,"NOSYNC") )  RespNOSYNC = 1;

	returnHELO(Conn,tc);
	if( DHKEYwithCL ){
		sendDHkey(tc);
		DHKEYwithCL = 0;
	}
}
static void toclnt(Connection *Conn,FILE *tc,PCStr(fmt),...)
{	CStr(msg,1024);
	VARGS(7,fmt);

	/*
	if( fileno(tc) == ClientSock ){
	*/
	if( fileno(tc) == ClientSock
	 || (Conn->xf_filters & XF_FCL) /* for FCL=-credhy */
	){
		fprintf(tc,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
		fflush(tc);
	}else{
		sprintf(msg,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
		IGNRETP write(ClientSock,msg,strlen(msg));
	}
}
static void respHELO(Connection *Conn,FILE *tc)
{
	toclnt(Conn,tc,"HELO DeleGate/%s\r\n",DELEGATE_ver());
}
static void returnHELO(Connection *Conn,FILE *tc)
{	CStr(host,128);
	CStr(seed,128);

	if( NoACK )
		return;

	if( SaidHello )
		sv1log("#### ignore duplicate HELLO response.\n");

	if( !SaidHello ){
		if( RespNOSYNC ){
			/* Say HELLO later */
			SayHello = 1;
		}else{
			GetHostname(AVStr(host),sizeof(host));
			sprintf(seed,"<%d.%d@%s>",getpid(),itime(0),host);
			if( DHKEYwithCL ){
				strcat(seed,"[DHKEY]");
			}
			toclnt(Conn,tc,"%s %s %s\r\n",
				HelloWord(),DELEGATE_ver(),seed);
			SayHello = 0;
		}
		SaidHello = 1;
	}
	ReturnACK = 1;
}
static void returnAck(Connection *Conn,FILE *tc,PCStr(fmt),...)
{	CStr(msg,1024);
	VARGS(7,fmt);

	if( NoACK )
		return;

	sprintf(msg,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
	if( ReturnACK ){
		if( SayHello ){
			toclnt(Conn,tc,"%s %s\r\n",HelloWord(),DELEGATE_ver());
			SayHello = 0;
		}
		toclnt(Conn,tc,"%s",msg);
		ReturnACK = 0;
		sv1log("RETURNED ACK = %s",msg);
	}
}

int waitSTLS_CL(Connection *Conn,int timeout);
void returnAckOK(Connection *Conn,FILE *tc,PCStr(reason))
{
	returnAck(Conn,tc,"200 OK: %s\r\n",reason);

	if( ImMaster )
	if( (ClientFlags & PF_STLS_ON) == 0 )
	if( (ClientFlags & PF_STLS_DO) != 0 )
	{
/*
 fprintf(stderr,"---- CHECK STLS after ACK OK: %X\n",ClientFlags);
 fprintf(stderr,"---A %d, retry STLS iPROTO[%s] CLNT_PROTO[%s] Flags=%X\n",
	ImMaster,iSERVER_PROTO,CLNT_PROTO,ClientFlags);
*/
/*
		waitSTLS_CL(Conn,1000);
*/
	}
}
void returnAckCONTINUE(Connection *Conn,FILE *tc,PCStr(reason))
{
	if( ReturnACK ){
		returnAck(Conn,tc,"201 CONTINUE: %s\r\n",reason);
		ReturnACK = 1;
	}
}
void returnAckLOOP(Connection *Conn,FILE *tc,PCStr(where))
{
	returnAck(Conn,tc,"601 LOOP: %s\r\n",where);
}
void returnAckDENIED(Connection *Conn,FILE *tc,PCStr(reason))
{
	returnAck(Conn,tc,"602 DENIED: %s\r\n",reason);
}
void returnAckUNKNOWN(Connection *Conn,FILE *tc,PCStr(host))
{
	returnAck(Conn,tc,"603 UNKNOWN_HOST: %s\r\n",host);
}
void returnAckCANTCON(Connection *Conn,FILE *tc,PCStr(host))
{
	returnAck(Conn,tc,"604 CANT_CONNECT: %s\r\n",host);
}
void returnAckBADREQ(Connection *Conn,FILE *tc,PCStr(reason))
{
	returnAck(Conn,tc,"605 BAD_REQUEST: %s\r\n",reason);
}

int portMap(Connection *Conn,PCStr(proto),PCStr(host),PCStr(portspec))
{	int port,ifport;

	if( strtailstr(portspec,".udp") ){
		Conn->sv_dflt.p_flags |= PF_UDP;
		Conn->sv.p_flags |= PF_UDP;
	}

	if( *portspec == 'N' ){
		SvPortMapType = SVPM_ORIGDST;
		portspec++;
	}
	if( *portspec == 'C' ){
		SvPortMapType = SVPM_CLIENT;
		portspec++;
	}
	if( *portspec == 'I' ){
		SvPortMapType = SVPM_CLIF;
		portspec++;
	}
	if( SvPortMapType == 0 ){
		if( lORIGDST() ){
			SvPortMapType = SVPM_ORIGDST;
		}else{
			SvPortMapType = SVPM_CLIF;
		}
	}
	switch( portspec[0] ){
		case '+':
			Conn->sv_portmap = atoi(portspec+1);
			break;
		case '-':
			Conn->sv_portmap = atoi(portspec);
			break;
	}
	if( Conn->sv_portmap == 0 )
	if( portspec[0] == '-' || portspec[0] == '+' )
		Conn->sv_portmap |= 0x40000000; /* add IS_PORTMAP */

	if( portspec[0] == '+' )
		port = atoi(portspec+1);
	else	port = atoi(portspec);

	if( !streq(proto,"file") ) /* and not other virtual protocols ... */
	if( 0 <= ClientSock )
	if( SvPortMapType != SVPM_ORIGDST )
	if( portspec[0] == '+' || portspec[0] == '-' ){
		if( SvPortMapType == SVPM_CLIENT ){
			VA_getClientAddr(Conn);
			ifport = Client_Port;
		}else
		ifport = VA_HostPortIFclnt(Conn,ClientSock,VStrNULL,VStrNULL,NULL);
		sv1log("### map accept port#%d to server#%d\n",
			ifport,ifport+port);
		port += ifport;
	}
	return port;
}
int mapPort1(PCStr(portspec),int port){
	int mport;
	if( *portspec == '+' )
		mport = port + atoi(portspec+1);
	else
	if( *portspec == '-' )
		mport = port - atoi(portspec+1);
	else	mport = atoi(portspec);
	return mport;
}
int mapPort(Connection *Conn,int port,PVStr(mhost)){
	int mport = port;
	int map;
	int oport;
	int origdst;

	if( map = Conn->sv_portmap ){
		origdst = 0;
		if( SvPortMapType == SVPM_CLIENT ){
		}else
		if( SvPortMapType == SVPM_CLIF ){
		}else{
			if( lORIGDST() && Origdst_Port )
			if( GatewayFlags & GW_WITH_ORIGDST ){
				origdst = 1;
			}
		}
		if( origdst ){
			mport = Origdst_Port;
		}else
		if( SvPortMapType == SVPM_CLIENT ){
			mport = Client_Port;
		}else{
			mport = CLIF_PORT;
		}
		oport = mport;
		if( map == 0x40000000 ){
		}else{
			mport += map;
		}
		sv1log("##NAT mapped port %d <- %d %d [%d](%d)\n",mport,port,
			oport,map==0x40000000?0:map,SvPortMapType
		);
	}else	mport = port;
	return mport;
}

int unesc_siteX(AuthInfo *auth){
	nonxalpha_unescape(auth->i_user,AVStr(auth->i_user),1);
	nonxalpha_unescape(auth->i_pass,AVStr(auth->i_pass),1);
	return 0;
}
static int scan_server(Connection *Conn,PCStr(url),PVStr(proto),PVStr(host),int *portp,PVStr(upath))
{	CStr(xproto,1024);
	CStr(site,1024);
	CStr(userpasshost,1024);
	CStr(portspec,1024);
	int xport;

	xproto[0] = 0;
	xport = 0;
	setVStrEnd(upath,0);

	if( Xsscanf(url,"%s %s %d",AVStr(site),AVStr(xproto),&xport) < 2 ) /* DeleGate/1.X */
	if( decomp_absurl(url,AVStr(xproto),AVStr(site),AVStr(upath),1024) < 2 ){
		wordScan(url,xproto);
		if( 0 < serviceport(xproto) )
			strcpy(site,"-");
		else{
			sv1log("ERROR: cannot scan SERVER=%s\n",url);
			return 0;
		}
	}

	if( xproto[0] == 0 || site[0] == 0 ){
		sv1log("ERROR: cannot scan SERVER: %s\n",url);
		return 0;
	}
	strcpy(proto,xproto);
	decomp_URL_site(site,AVStr(userpasshost),AVStr(portspec));
	scan_hostport1X(userpasshost,AVStr(host),256);
	if( strchr(userpasshost,'@') ){
		DFLT_AUTH = (AuthInfo*)malloc(sizeof(AuthInfo));
		bzero(DFLT_AUTH,sizeof(AuthInfo));
		decomp_siteX(proto,site,DFLT_AUTH);
		unesc_siteX(DFLT_AUTH);
		/* copy to MYAUTH ? or see DFLT_AUTH in MYAUTH ? */
	}
	xport = portMap(Conn,proto,host,portspec);
	if( xport == 0 )
		xport = serviceport(proto);
	*portp = xport;
	return 1;
}
static void set_iserver(Connection *Conn,PCStr(upath))
{
	if( iSERVER_HOST[0] == 0 ){
		strcpy(iSERVER_PROTO,DFLT_PROTO);
		strcpy(iSERVER_HOST,DFLT_HOST);
		iSERVER_PORT = DFLT_PORT;
	}
	wordscanX(upath,AVStr(D_SELECTOR),sizeof(D_SELECTOR));
	ProcTitle(Conn,"%s://%s/",DFLT_PROTO,DFLT_HOST);
}
int scan_SERVER(Connection *Conn,PCStr(server))
{	CStr(sbuff,4096);
	refQStr(proto,sbuff); /**/
	refQStr(login,sbuff); /**/
	refQStr(upath,sbuff); /**/

	proto = sbuff;
	login = proto + 64;
	upath = login + 256;
	if( scan_server(Conn,server,AVStr(proto),AVStr(login),&DFLT_PORT,AVStr(upath)) ){
		wordscanX(login,AVStr(DFLT_SITE),sizeof(DFLT_SITE));
		wordscanX(proto,AVStr(DFLT_PROTO),sizeof(DFLT_PROTO));
		wordscanX(login,AVStr(DFLT_HOST),sizeof(DFLT_HOST));
		if( server != D_SERVER )
			add_DGheader(Conn,D_SERVER,"%s",server);
		set_iserver(Conn,upath);
		return 1;
	}
	return 0;
}
void set_SERVER(Connection *Conn,PCStr(proto),PCStr(host),int port)
{	const char *serv;

	/*
	if( port )
	*/
	if( 0 < port ) /* port number can be netative for pseudo protocols */
		serv = add_DGheader(Conn,D_SERVER,"%s://%s:%d",proto,host,port);
	else	serv = add_DGheader(Conn,D_SERVER,"%s://%s",proto,host);
	scan_SERVER(Conn,serv);
}
void set_realproto(Connection *Conn,PCStr(rproto))
{
	wordscanX(rproto,AVStr(REAL_PROTO),sizeof(REAL_PROTO));
}
void set_ClientSock(Connection *Conn,int sock,PCStr(remote),PCStr(local))
{
	Conn->from_myself = 0;
	ClientSock = sock;
	Client_Port = 0;
	VA_getClientAddr(Conn);
}
void set_USER(Connection *Conn,int clsock);
void set_realsite(Connection *Conn,PCStr(rproto),PCStr(rserver),int riport);
void set_realserver(Connection *Conn,PCStr(rproto),PCStr(rserver),int riport)
{
	set_realsite(Conn,rproto,rserver,riport);
	set_SERVER(Conn,REAL_PROTO,REAL_SITE,REAL_PORT);
	set_USER(Conn,FromC); /* maybe unnecessary */
}
void set_realsite(Connection *Conn,PCStr(rproto),PCStr(rserver),int riport)
{	int port;
	CStr(host,MaxHostNameLen);

	wordscanX(rproto,AVStr(REAL_PROTO),sizeof(REAL_PROTO));
	wordscanX(rserver,AVStr(REAL_SITE),sizeof(REAL_SITE));
	VSA_cto_(REAL_SITE);
	port = scan_Hostport1p(REAL_PROTO,REAL_SITE,host);
	wordscanX(host,AVStr(REAL_HOST),sizeof(REAL_HOST));
	REAL_PORT = riport ? riport : port;
}
void scan_realserver(Connection *Conn,PCStr(url),PVStr(upath))
{	CStr(sbuff,4096);
	refQStr(proto,sbuff); /**/
	refQStr(login,sbuff); /**/
	const char *dp;
	int riport;

	proto = sbuff;
	login = proto + 64;
	decomp_absurl(url,AVStr(proto),AVStr(login),AVStr(upath),1024);
	if( dp = strrchr(login,':') ){
		truncVStr(dp); dp++;
		riport = atoi(dp);
	}else	riport = 0;
	set_realsite(Conn,proto,login,riport);
	set_SERVER(Conn,REAL_PROTO,REAL_SITE,REAL_PORT);
}
void set_USER(Connection *Conn,int clsock)
{	CStr(clnthost,MaxHostNameLen);

	if( D_USER[0] == 0 ){
		if( getClientHostPort(Conn,AVStr(clnthost)) )
			add_DGheader(Conn,D_USER,"anonymous@%s",clnthost);
		else	add_DGheader(Conn,D_USER,"anonymous");
	}
}

static void Metamorphose(Connection *Conn,PCStr(proto),PCStr(host),PVStr(req),PCStr(crlf))
{
	Verbose("=======> Metamorphose: [%s]->[%s]://%s/\n",DFLT_PROTO,
		proto,host);

	ACT_SPECIALIST = 1;
	META_SPECIALIST = 1;
	set_SERVER(Conn,proto,host,0);
	if( crlf )
		strcat(req,crlf);
	DDI_pushCbuf(Conn,req,strlen(req));
}

static int isGopherRequest(Connection *Conn,PCStr(line))
{	CStr(req,128);
	CStr(flags,128);
	CStr(proto,128);
	CStr(host,128);
	CStr(path,128);
	int port;
	int gtype;

	wordScan(line,req);
	if( CTX_url_derefer(Conn,"?",AVStr(req),VStrNULL,AVStr(flags),AVStr(proto),AVStr(host),&port) )
		if( strcasecmp(proto,"gopher") == 0 )
			return 1;
	return 0;
}

int bindTeleportVehicle(int tx,int clsocks[],PCStr(host),int port,PCStr(tunnel),PCStr(invites));
static void beTeleportd(Connection *Conn,int fromC,int toC)
{	int iov[2];

	iov[0] = fromC;
	iov[1] = toC;
	ProcTitle(Conn,"teleportd");

	checkCloseOnTimeout(0);
	bindTeleportVehicle(0,iov,"private.vehicle",0,NULL,NULL);
}

int execGeneralist(Connection *Conn,int fromC,int toC,int svsock);
int execSpecialist(Connection *Conn,int fromC,FILE *tc,int toS);
void beGeneralist(Connection *Conn,FILE *fc,FILE *tc,PCStr(hello))
{	int fromC,toC;
	CStr(buf,0x4000);
	int len;

	BORN_SPECIALIST = 0;
	ACT_GENERALIST = 1;
	sv1log("BE GENERALIST[%s]: %s",DFLT_PROTO,hello);
	strcpy(buf,hello);
	len = strlen(buf);
	fgetBuffered(QVStr(buf+len,buf),sizeof(buf)-len,fc);
	DDI_pushCbuf(Conn,buf,strlen(buf));

	toC = fcloseFILE(tc);
	fromC = fcloseFILE(fc);

	DFLT_HOST[0] = 0;
	execGeneralist(Conn,fromC,toC,-1);
}

int get_shared(PVStr(buf),int size,FILE *fp);
int put_shared(PCStr(buf),int size,FILE *fp);
int add_params(Connection *Conn,FILE *tc,PCStr(command));
void setREQUEST(Connection *Conn,PCStr(req));
void scan_OVERRIDE(Connection *Conn,PCStr(ovparam));
static int obsoletecoms(Connection *Conn,FILE **tcp,int fromC,int toC,PCStr(fieldname),PCStr(value),int *do_exitp)
{	FILE *tc = *tcp;

	if( streq(fieldname,"RPORT") ){
		linescanX(value,AVStr(D_RPORTX),sizeof(D_RPORTX));
	}else
	if( streq(fieldname,"MASTER") ){
		scan_MASTER(Conn,value);
		add_DGheader(Conn,fieldname,"%s",value);
	}else
	if( streq(fieldname,"REQUEST") ){
		setREQUEST(Conn,value);
	}else
	if( streq(fieldname,"CLIENTS-PROXY") ){
		linescanX(value,AVStr(CLIENTS_PROXY),sizeof(CLIENTS_PROXY));
		Verbose("CLIENTS-PROXY: %d\n",1);
	}else
	if( streq(fieldname,"LOCAL-PROXY") ){
		ACT_TRANSLATOR = 1;
		/* no =@=, but only translator ... ?;-< */
	}else
	if( streq(fieldname,"LOCAL-DELEGATE") ){
		Verbose("LOCAL-DELEGATE: %s\n",value);
		DELEGATE_LPORT =
		scan_hostport1X(value,AVStr(DELEGATE_LHOST),sizeof(DELEGATE_LHOST));
		ACT_SPECIALIST = 1;
	}else
	if( streq(fieldname,"LOCAL-FLAGS") ){
		Verbose("LOCAL-FLAGS: %s\n",value);
		linescanX(value,AVStr(DELEGATE_FLAGS),sizeof(DELEGATE_FLAGS));
	}else
	if( streq(fieldname,"LOCAL-CHARCODE") ){
		Verbose("LOCAL-CHARCODE: %s\n",value);
		scan_CHARCODE(Conn,value);
	}else
	if( streq(fieldname,"CACHE") ){
		if( streq(value,"DONT_READ") ){
			Verbose("DontReadCache\n");
			DontReadCache = 1;
		}else
		if( streq(value,"DONT_WAIT") ){
			Verbose("DontWaitCache\n");
			DontWaitCache = 1;
		}else
		if( strncmp(value,"ONLY",4) == 0 ){
			CacheOnly = 1;
			CacheLastMod = atoi(value+5);
			Verbose("CacheOnly IfLastMod>%d\n",CacheLastMod);
		}else{
			/* DISABLE */

			DontUseCache = 1;
			DontWaitCache = 1;
			DontReadCache = 1;
			DontWriteCache = 1;
		}
		/* add_DGheader(Conn,fieldname,"%s",value); */
	}else
	if( streq(fieldname,"OVERRIDE") ){
		int ok;
		CStr(proto,64);
		strcpy(proto,DST_PROTO);
		Xstrcpy(EVStr((const char*)DST_PROTO),"override");
		ok = service_permitted(Conn,"override");
		Xstrcpy(EVStr((const char*)DST_PROTO),proto);

		if( ok ){
		CStr(nam,256);
		CStr(val,256);
		CStr(ov,1024);
		scan_namebody(value,AVStr(nam),sizeof(nam),"=",AVStr(val),sizeof(val),"\r\n");
			if( nam[0] ){
				sv1mlog("OVERRIDE %s %s\n",nam,val);
				sprintf(ov,"*:*:%s",value);
				scan_OVERRIDE(Conn,ov);

				if( streq(nam,"TIMEOUT") )
					scan_TIMEOUT(Conn,val);
				else
				if( streq(nam,"CONNECT") ){
					if( streq(val,"cache") ){
						scan_CONNECT(Conn,val);
						CacheOnly = 1;
					}
				}
			}
		}
	}else
	if( streq(fieldname,"TELEPORT") ){
		fflush(tc);
		beTeleportd(Conn,fromC,toC /*,value*/);
		Finish(0);
	}else
	if( streq(fieldname,"CPORT") ){
		CStr(hp,MaxHostNameLen);
		CStr(clhost,MaxHostNameLen);
		CStr(xclhost,MaxHostNameLen);
		const char *dp;
		int clport,xclport,csock;

		dp = wordScan(value,hp);
		clport = scan_hostport1X(hp,AVStr(clhost),sizeof(clhost));
		dp = wordScan(dp,hp);
		xclport = scan_hostport1X(hp,AVStr(xclhost),sizeof(xclhost));

		if( clhost[0] && sockFromMyself(fromC) ){
			sv1log("CPORT: %s:%d\n",clhost,clport);
			strcpy(TeleportHost,clhost);
			TeleportPort = clport;
			fprintf(tc,"200 Ok [%s:%d]\r\n",clhost,clport);
			fflush(tc);
		}
		if( xclhost[0] != 0 ){
			csock = client_open("CPORT","delegate",xclhost,xclport);
			if( 0 <= csock ){
				dup2(csock,toC);
				close(csock);
			}
		}
	}else
	if( strcaseeq(fieldname,"!SET") ){
		FILE *tc;
		tc = fdopen(toC,"w");
		*do_exitp = 1;
	}else
	if( streq(fieldname,"OUT") ){
		CStr(buff,2048);
		CStr(UserHost,MaxHostNameLen);
		if( getClientUserMbox(Conn,AVStr(UserHost)) ){
			sprintf(buff,"%s %s\r\n",UserHost,value);
			put_shared(buff,strlen(buff),NULL);
			fflush(tc);
			IGNRETP write(toC,buff,strlen(buff));
		}
	}else
	if( streq(fieldname,"IN") ){
		CStr(buff,2048);
		int rc;
		rc = get_shared(AVStr(buff),sizeof(buff),NULL);
		fflush(tc);
		IGNRETP write(toC,buff,rc);
	}else
	if( strcaseeq(fieldname,"PARAM") ){
		fflush(tc);
		add_params(Conn,tc,value);
		fflush(tc);
	}else{
		return 0;
	}
	*tcp = tc;
	return 1;
}

extern int IO_TIMEOUT;

void scan_header(Connection *Conn,int fromC,PCStr(name),PCStr(value));

static int execGeneralist0(Connection *Conn,FILE *tc,int fromC,int toC)
{	CStr(line,1024); /* the smaller the safer, but can be
			  * insufficient for HOSTS transfer ?
			  */
	const char *crlfp;
	CStr(crlf,4);
	const char *fieldname;
	const char *value;
	int lines;
	int do_exit = 0;

	lines = 0;
	for(;;){
		line[0] = 0;
		if( DDI_fgetsFromCbuf(Conn,AVStr(line),sizeof(line),NULL) == 0 )
		{
			if( PollIn(fromC,IO_TIMEOUT*1000) <= 0 ){
				sv1log("execGeneralist(): TIMEOUT\n");
				do_exit = 1;
				break;
			}
			if( RecvLine(fromC,line,sizeof(line)) < 0 )
				break;
		}
		crlf[0] = 0;
		if( crlfp = strpbrk(line,"\r\n") ){
			QStrncpy(crlf,crlfp,3);
			truncVStr(crlfp);
		}

		Verbose("DGHeader: %s\n",line);
		if( *line == 0 )
			break;

		if( lines == 0 ){
			if( HTTP_isMethod(line) ){
				Metamorphose(Conn,"http",SERV_HTTP,AVStr(line),crlf);
				set_USER(Conn,fromC);
				break;
			}

			if( !source_permitted(Conn) ){
				CStr(host,MaxHostNameLen);
				int port;
				port = getClientHostPort(Conn,AVStr(host));
				sv1log("E-P: Rejected MASTER usage < %s:%d\n",
					host,port);
				do_exit = 1;
				break;
			}
			if( VSAP_isMethod(line) ){
				Metamorphose(Conn,"vsap",MY_HOSTPORT(),AVStr(line),crlf);
				break;
			}
			if( strncmp(line,"whois://",8) == 0 ){
				Metamorphose(Conn,"whois",MY_HOSTPORT(),AVStr(line),crlf);
				set_USER(Conn,fromC);
				break;
			}
			if( isGopherRequest(Conn,line) ){
				Metamorphose(Conn,"gopher",MY_HOSTPORT(),AVStr(line),crlf);
				set_USER(Conn,fromC);
				break;
			}
			Verbose("ImMaster: act as a MASTER\n");
			ImMaster = 1;
		}

		lines++;
		if( value = strpbrk(line,"\r\n\t ") ){
			truncVStr(value); value++;
		}else	value = "";
		fieldname = line;


		if( streq(fieldname,"HELO") ){
			respHELO(Conn,tc);
		}else
		if( streq(fieldname,HelloWord()) ){
			gotHELLO(Conn,tc,fieldname,value);
		}else
		if( streq(fieldname,"SERVER") ){
			scan_SERVER(Conn,value);
			set_USER(Conn,fromC);
		}else
		if( strcaseeq(fieldname,"QUIT") ){
			do_exit = 1;
			break;
		}else
		if( strcaseeq(fieldname,"DHKEY") ){
			recvDHkey(value);
		}else
		if( recvAUTH(Conn,fieldname,value,&ClientAuth) ){
		}else
		if( obsoletecoms(Conn,&tc,fromC,toC,fieldname,value,&do_exit) ){
			if( do_exit )
				break;
		}else	scan_header(Conn,fromC,fieldname,value);
	}

	if( doAuthXM(Conn,fileno(tc),&ClientAuth) < 0 ){
		returnAckDENIED(Conn,tc,"Auth. error");
		do_exit = 1;
	}
	bzero(&ClientAuth,sizeof(ClientAuth));

	return do_exit;
}

int STLS_error(Connection *Conn,int fromC);
void execGeneralist1A(Connection *Conn,int fromC,int toC,int svsock);
void execGeneralist1(Connection *Conn,int fromC,int toC,int svsock)
{
	Port dflt = Conn->sv_dflt;
	PortMap pm = Conn->sv_pm;
	IStr(addr,128);
	int dopm = 0;
	int port = 0;

	if( GatewayFlags & GW_WITH_ORIGDST ){
		Origdst_Addr(addr);
		port = Origdst_Port;
		dopm = SVPM_ORIGDST;
	}else
	if( streq(DFLT_HOST,CLIENT_HOST) ){
		Client_Addr(addr);
		port = Client_Port;
		dopm = SVPM_CLIENT;
	}
	if( dopm ){
		sv1log("##NAT (%d) redirect: %s:%d (%s:%d)\n",
			dopm,addr,port,DFLT_HOST,DFLT_PORT);
		if( SvPortMapType == 0 )
			SvPortMapType = dopm;
		strcpy(DFLT_HOST,addr);
		DFLT_PORT = mapPort(Conn,DFLT_PORT,VStrNULL);
	}
	execGeneralist1A(Conn,fromC,toC,svsock);
	if( dopm ){
		Conn->sv_dflt = dflt;
		Conn->sv_pm = pm;
	}
	finishServYY(FL_ARG,Conn);
}
int CTX_setSockOpts(FL_PAR,Connection *Conn,int sock,int clnt);
void execGeneralist1A(Connection *Conn,int fromC,int toC,int svsock)
{	FILE *tc;
	int gssl = 0;

	CTX_setSockOpts(FL_ARG,Conn,ClientSock,1);
	set_keepalive(fromC,1);
	tc = fdopen(toC,"w");
	if( tc == NULL ){
		sv1log("----Generalist FATAL fopen(toC=%d) e%d\n",
			toC,errno);
		return;
	}

	if( Port_Proto == serviceport("delegate") ){
		sv1log("----Generalist by -P%d.%X [%s://%s:%d]\n",
			AccPort_Port,AccPort_Flags,
			DFLT_PROTO,DFLT_HOST,DFLT_PORT);
		BORN_SPECIALIST = 0;
		ACT_GENERALIST = 1;
		strcpy(DFLT_PROTO,"delegate");
		strcpy(DFLT_HOST,"-");
		DFLT_PORT = 0;
		Port_Proto = 0;
	}
	if( Port_Proto ){
		if( DFLT_HOST[0] == 0 ){
			strcpy(DFLT_HOST,"-.-");
		}
		if( Port_Proto == 1080 ){
			Conn->no_dstcheck_proto = serviceport("tcprelay");
		}
		if( Port_Proto == 21 ){
			Conn->no_dstcheck_proto = 21;
		}
		switch( Port_Proto ){
			case 25:
			case 110:
			case 119:
			case 143:
				Conn->no_dstcheck_proto = Port_Proto;
				break;
		}
		execSpecialist(Conn,fromC,tc,svsock);
		goto EXIT;
	}

	if( !strcaseeq(DFLT_PROTO,"delegate") )
	if( DFLT_HOST[0] ){
		/* then it is Specialized already */
		Verbose("execGeneralist->execSpecialist\n");
		execSpecialist(Conn,fromC,tc,svsock);
		goto EXIT;
	}

ProcTitle(Conn,"(delegate)");

	if( STLS_error(Conn,fromC) ){
		goto EXIT;
	}
	willSTLS_CL(Conn);
	if( ClientFlags & (PF_SSL_ON|PF_STLS_ON) ){
		/* with SSLway as MASTER DeleGate */
		gssl = 1;
	}
	if( execGeneralist0(Conn,tc,fromC,toC) != 0 )
		goto EXIT;

	fflush(tc);
	execSpecialist(Conn,fromC,tc,svsock);

EXIT:
	if( 0 <= FromS && ToS != FromS ){ /* FFROMMD filter inserted ... */
		close(FromS);
		Verbose("close FromS:%d (ToS=%d)\n",FromS,ToS);
	}
	if( lSINGLEP() ){
		fcloseFILE(tc);
	}else
	fclose(tc);
	if( gssl && lSINGLEP() ){
		sv1log("----Generalist/SSL [%d][%d][%d] %d/%d\n",
			ClientSock,FromC,ToC,actthreads(),numthreads());
		/* should clean SSLway thread and descriptors */
	}
}

void DELEGATE_setenv(FILE *fc,FILE *tc,PCStr(line))
{
	fprintf(tc,"SET\r\n");
}

static int setServ(Connection *Conn,int svsock)
{
	/*Verbose("####setServ: %d %d\n",FromS,svsock);*/
	if( (Conn->xf_filters & XF_FTOMD) == 0 || (ToSX < 0 && ToS < 0) )
	ToS   = svsock;

	if( FromSX < 0 && FromS < 0 )
		FromS = svsock;
	return svsock;
}
static void setConn(Connection *Conn,int fromC,int toC,int fromS,int toS)
{
	/*Verbose("#### setConn: FromS:%d fromS:%d,toS:%d\n",FromS,fromS,toS);*/
	FromC = fromC;
	ToC   = toC;
	if( FromSX < 0 )
		FromS = fromS;
	ToS   = toS;
}

const char *CTX_get_PATH(Connection *Conn);
const char *CTX_add_PATH(Connection *Conn,PCStr(me),PCStr(hostport),PCStr(teleport));

int log_PATH(Connection *Conn,PCStr(where))
{	const char *path;
	CStr(teleport,512);
	CStr(dest,MaxHostNameLen*2);
	int loop;

	loop = 0;
	if( Conn->path_added == 0 ){
		CStr(me,MaxHostNameLen);
		CStr(hostport,MaxHostNameLen);
		int port;
		const char *dp;
		int len;

		if( TeleportHost[0] && TeleportPort ){
			sprintf(teleport,"%s:%d.-.%s:%d",TelesockHost,TelesockPort,
				TeleportHost,TeleportPort);
		}else	teleport[0] = 0;

		Conn->path_added = 1;
		gethostName(ClientSock,AVStr(me),PN_HOSTPORT);
		FStrncpy(Conn->cl_myhp,me);

		len = strlen(me);
		if( 0 < (port = getClientHostPort(Conn,AVStr(hostport))) )
			Xsprintf(TVStr(hostport),":%d",port);
		else	strcpy(hostport,"?:0");

		path = CTX_add_PATH(Conn,me,hostport,teleport);

if( !Conn->from_myself )
if( SERVER_PORT() != 0 ) /* FTP/TUNNEL mistaken as loop by "0.0.0.0:0" */
		if( !isMYSELF(DST_HOST) )
		if( dp = strstr(path+len,me) ){
		    if( dp[-1] == '!' && dp[len] == '!' ){
			loop = 1;
			sv1log("ERROR: loop found in PATH: %s!%s\n",me,path);
		    }
		}
	}else	path = CTX_get_PATH(Conn);

	if( DST_HOST[0] )
		sprintf(dest,"%s://%s:%d",DST_PROTO,DST_HOST,DST_PORT);
	else	sprintf(dest,"%s",DST_PROTO);

	if( where[0] == ':' && streq(DFLT_PROTO,"http") )
		Verbose("PATH%s %s!%s\n",where,dest,path);
	else	sv1tlog("PATH%s %s!%s\n",where,dest,path);
	return loop;
}

void setFROM(Connection *Conn,PCStr(username),PCStr(hostaddr),int port);
static void setClientInfo(Connection *Conn)
{	CStr(username,64);
	CStr(hostname,MaxHostNameLen);
	CStr(hostaddr,256);
	int cport;

	if( (cport = getClientHostPortAddr(Conn,AVStr(hostname),AVStr(hostaddr))) == 0 ){
		strcpy(hostname,"-");
		strcpy(hostaddr,"0.0.0.0");
	}

	strcpy(CLNT_PROTO,DFLT_PROTO);
	if( strcmp(CLNT_PROTO,iSERVER_PROTO) != 0 ){
		Verbose("CLNT_PROTO[%s] <- iSERVER_PROTO[%s]\n",
			CLNT_PROTO,iSERVER_PROTO);
		/* can be defferent on HTTP->Generalist metamo... */
	}

	if( D_FROM[0] == 0 ){
		getUsernameCached(getuid(),AVStr(username));
		setFROM(Conn,username,hostaddr,cport);
	}
}

int withCFI(int fiset);
void setConnX(Connection *Conn,int fromC,int toC,int fromS,int toS);
int connect_to_serv(Connection *Conn, int fromC,int toC, int relay_input);
int daemonControl(Connection *Conn,int fromC,FILE *tc,int timeout);
void mount_nodefaults(PCStr(iproto),int on);

void dynamic_config(Connection *Conn);
int ShutdownSocket(int sock);
/* Stale Session Watcher */
static void TSwatcher(Connection *Conn,int syin){
	for(;;){
		if( PollIn(syin,15*1000) )
			break;
		if( !service_permitted2(Conn,DFLT_PROTO,1) ){
			sv1log("--TSwatcher permission turned-off\n");
			msleep(10);
			ShutdownSocket(ClientSock);
			msleep(10);
		}
	}
}
int execServiceTSwatcher(Connection *Conn,iFUNCP svfunc){
	int sy[2],tid,rcode;

	Socketpair(sy);
	/*
	tid = thread_fork(0,STX_tid,"TSwatcher",(IFUNCP)TSwatcher,Conn,sy[0]);
	*/
	tid = thread_fork(0x40000,STX_tid,"TSwatcher",(IFUNCP)TSwatcher,Conn,sy[0]);
	rcode = (*svfunc)(Conn,0,0,FromC,ToC,DST_PROTO,DST_HOST,DST_PORT,"");
	close(sy[1]);
	thread_wait(tid,15*1000);
	close(sy[0]);
	return rcode;
}
int execSpecialist(Connection *Conn,int fromC,FILE *tc,int toS)
{	iFUNCP client;
	int clsock;
	int withcache,selfack;
	int fromS;
	int rcode;
	int initfrom;

	/*
	sv1log("---- testing SIGSEGV ----\n");
	(*(iFUNCP)-1)(0);
	*/

	if( iSERVER_PROTO[0] && strcmp(iSERVER_PROTO,DFLT_PROTO) != 0 )
		mount_nodefaults(iSERVER_PROTO,1);

	fromS = -1;
	clsock = ClientSock;
	setClientInfo(Conn);

	if( log_PATH(Conn,":") != 0 ){
		returnAckLOOP(Conn,tc,"path loop found");
		return -1;
	}

	if( IsAdmin ){
	/* from -Pxxx/admin, postpone the detection after SSL is inserted */
	}else
	if( daemonControl(Conn,fromC,tc,10) ){
		fflush(tc);
		return -1;
	}

	client = (iFUNCP)get_servfunc(Conn,clsock,&withcache,&selfack,&initfrom);
	if( client == 0 ){
		sv1log("-- NO protocol interpreter [%s]\n",iSERVER_PROTO);
		return -1;
	}
	if( YY_accept(Conn,tc,initfrom) < 0 ){
		return -1;
	}

	if( withcache == 0 && isMYSELF(DFLT_HOST) ){
		sv1log("Free proxy -- %s://%s/\n",DFLT_PROTO,DFLT_HOST);
		withcache = 1;
	}

	if( serviceWithSTLS(DST_PROTO) == 0 ){
		if( STLS_error(Conn,fromC) ){
			return -1;
		}
	}

	if( toS == -1 ){
	    if( isMYSELF(DFLT_HOST) && streq(DFLT_PROTO,"telnet") ){
	    }else
	    if( isMYSELF(DFLT_HOST) && (streq(DFLT_PROTO,"nntp") || streq(DFLT_PROTO,"news")) ){
	    }else
	    if( withcache ){
		/*
		should search caches here...
		 */
		if( ReturnACK ){
			if( !service_permitted(Conn,DFLT_PROTO) )
			{
				returnAckDENIED(Conn,tc,"access denied");
				return -1;
			}
			if( !HAS_MASTER )
			if( !IsResolvable(DFLT_HOST) )
			if( !isMYSELF(DFLT_HOST) && !streq(".",DFLT_HOST) )
			{
				sv1log("unknown host: %s [%d]\n",DFLT_HOST,HAS_MASTER);
				returnAckUNKNOWN(Conn,tc,DFLT_HOST);
				return -1;
			}
			/*
			if( connectOnlyCache )
			if( no-cache-available  )
				returnAckNOCACHE(Conn,tc,"cache unavailable\n");
			*/
		}
	    }else{
		toS = connect_to_serv(Conn,fromC,fileno(tc), 0);
		/*
		 * ToS and FromS may be set already differently by FTOSV
		 */
		if( 0 <= ToS && toS == ToSX && 0 <= FromS ){
			toS = ToS;
			fromS = FromS;
		}
		/* FromS may be set already */
		if( Conn->xf_filters & XF_FFROMSV ){
			fromS = FromS;
		}

		if( toMaster ){
Verbose("====> RETURN Ack <200 Ok.> from Mediator.\n");
			returnAckOK(Conn,tc,"connected to the master");

			/* ProcTitle(Conn,"(relay)"); */
			fflush(tc);
			if( withCFI(XF_SERVER|XF_MASTER|XF_CLIENT) ){
				if( Conn->xf_filters & XF_FTOMD )
				if( 0 <= ToS && 0 <= FromS )
				{
					toS = ToS;
					fromS = FromS;
				}
			}else{
			setConnX(Conn,fromC,fileno(tc),fromS,toS);
			ProcTitle(Conn,"%s://%s/(relay)",DST_PROTO,DST_HOST);
			relay_svcl(Conn,FromC,ToC,FromS,ToS /*,1,512*/);
			return -1;
			}
		}
	    }
	}

	if( !selfack || D_RPORTX[0] )
		returnAckOK(Conn,tc,"good");

	setConnX(Conn,fromC,fileno(tc),fromS,toS);
	ProcTitle(Conn,"%s://%s/",DST_PROTO,DST_HOST);

	fflush(tc);

if( ImMaster && (ClientFlags & PF_STLS_ON) ){
	/* TLS is ON to wrap the inter-DeleGate (MASTER) protocol */
}else{
	willSTLS_CL(Conn);
	if( (ClientFlags & PF_STLS_ON) ){
		if( strcasecmp(CLNT_PROTO,"http") == 0 ){
			/* set CLNT_PROTO for MOUNT */
			strcpy(CLNT_PROTO,"https");
			sv1log("## STLS=fcl SERVER=http -> SERVER=https\n");
		}
	}
	if( streq(CLNT_PROTO,"http") || streq(CLNT_PROTO,"https") ){
		dynamic_config(Conn);
	}
	if( (ClientFlags & PF_STLS_ON) )
	if( (ClientFlags & PF_ADMIN_SW) == 0 ){
		if( daemonControl(Conn,fromC,tc,10) ){
			fflush(tc);
			return -1;
		}
	}
	if( (ClientFlags & PF_STLS_ON) )
	if( (ClientFlags & PF_ADMIN_SW) != 0 ){
		client = (iFUNCP)get_servfunc(Conn,clsock,&withcache,&selfack,&initfrom);
		/* client = service_http; */
	}
}

	if( ImMaster )
	if( !selfack || D_RPORTX[0] )
	if( (ClientFlags & PF_STLS_ON) == 0 )
	if( (ClientFlags & PF_STLS_DO) != 0 )
	{
		/* this should be in returnAckOK()
		 * but waitSTLS_CL() must be after setConnX()
		 */
/*
 fprintf(stderr,"---B %d, retry STLS iPROTO[%s] Flags=%X\n",
	ImMaster,iSERVER_PROTO,ClientFlags);
*/
		waitSTLS_CL(Conn,500);
	}

	if( lTSWATCHER() ){ /* to be enabled with -Etw option */
		rcode = execServiceTSwatcher(Conn,client);
	}else
	rcode = (*client)(Conn,0,0,FromC,ToC,DST_PROTO,DST_HOST,DST_PORT,D_SELECTOR);

	/* close FFROMMD filter if exists */
	/* ... and if I'm not StickyServer ?? ... */
	if( 0 <= FromSX ){
		close(FromSX);
		FromSX = -1;
	}

	return rcode;
}
void closeServer(Connection *Conn,FILE *ts){
}

void insert_FPROTO(Connection *Conn,int fromC,int *toCp,int toS,int *fromSp);
void setConnX(Connection *Conn,int fromC,int toC,int fromS,int toS)
{
	insert_FPROTO(Conn,fromC,&toC,toS,&fromS);
	setConn(Conn,fromC,toC,fromS,toS);
}

int RecvLineTIMEOUT(int sock,char buff[],int size,int timeout)
{
	if( 0 < PollIn(sock,timeout) )
 		return RecvLine(sock,buff,size);
	return -1;
}

/*
 *	get_masterserv() could use a persistent data file shared among
 *	delegateds of the same access right.
 */
int get_masterenv(int mx,const char **version,const char **server);
static int reuseMASTER(Connection *Conn,int mx,int msock,const char **version,const char **server)
{
	if( 0 <= RPORTsock )
		return 0;

	if( mx <= 0 )
		return 0;

	if( get_masterenv(mx,version,server) == 0 )
		return 0;

	if( ClientFlags & PF_MITM_ON ){
		/* to get MASTER ACK not postponed till HTTP (HTTPS in SSL) */
		sv1log("---- don't reuse MASTER in MITM [%X %X]\n",
			ClientFlags,ServerFlags);
		return 0;
	}

	if( vercmp(*version,"3.0.38") < 0 )
		return 0;

	return 1;
}

extern int CON_TIMEOUT;
void set_masterenv(int mx,PCStr(version),PCStr(server));
void insert_FMASTER(Connection *Conn,int msock);
void forward_RIDENT(Connection *Conn,int where,int svsock,PCStr(ident));
static void relayInput(Connection *Conn,FILE *mfp,int msock,int cache_only,int relay_input,int doflush);
int insertTLS_SV(Connection *Conn,int client,int server);
int insertTLS_SVi(Connection *Conn,int client,int server,PCStr(proto));
int pushSTLS_FSV(Connection *Conn,PCStr(proto));
int checkPortSTLS(Connection *Conn,PCStr(what),PCStr(proto),PCStr(method));
int ConnectViaSSLtunnelX(Connection *Conn,PCStr(host),int port,int svsock);
int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock);
const char *getFSV(Connection *Conn);

int insertCredhy(Connection *Conn,int clsock,int svsock){
	const char *filter;
	int fsv;

	if( ServerFlags & PF_CREDHY_ON ){
		return -1;
	}
	if( filter = getFSV(Conn) ){
		if( streq(filter,"-credhy") ){
			fsv = insertFSVF(Conn,clsock,svsock,filter);
			ServerFlags |= PF_CREDHY_ON;
			return fsv;
		}
	}
	return -1;
}

int pushFtpServSock(PCStr(wh),Connection *Conn,int svsock);
int insertFMDX(Connection *Conn,int client,int msock,int ifSSL);
int DELEGATE_STARTTLS_withSV(Connection *Conn,int msock){
	int fsv;
	if( 0 < (fsv = insertTLS_SVi(Conn,ClientSock,msock,"delegate")) ){
		pushFtpServSock("DELEGATE",Conn,msock);
		dup2(fsv,msock);
		close(fsv);
		pushSTLS_FSV(Conn,"delegate");
	}else{
		uncheckSTLS_SV(Conn);
	}
	return fsv;
}
static int connect_master(Connection *Conn,int mx,int msock,int cache_only,int relay_input)
{	FILE *mfpo;
	CStr(resp,128);
	int newver;
	int rcode = 0;
	int fromS;
	CStr(Hello,128);
	int nHello;
	int reuse;
	const char *version;
	const char *server;
	int fsv;

	CStr(myauth,256);
	getAuthXM(Conn,AVStr(myauth),mx,msock);

	set_keepalive(msock,1);

	ServerFlags |= PF_IS_MASTER;
	if( 0 <= (fsv = insertFMDX(Conn,ClientSock,msock,1)) ){
		dup2(fsv,msock);
		close(fsv);
	}else
	if( 0 <= (fsv = insertCredhy(Conn,ClientSock,msock)) ){
		dup2(fsv,msock);
		close(fsv);
	}else
	/*
	if( 0 < (fsv = insertTLS_SV(Conn,ClientSock,msock)) ){
		dup2(fsv,msock);
		close(fsv);
	}
	*/
	{
		DELEGATE_STARTTLS_withSV(Conn,msock);
	}

	forward_RIDENT(Conn,'m',msock,NULL);

	/*
	set_keepalive(msock,1);
	*/
	if( myauth[0] ){
		/* should be reused with a session-ID */
		reuse = 0;
	}else
	reuse = reuseMASTER(Conn,mx,msock,&version,&server);

	if( reuse && strcmp(server,D_SERVER) == 0 ){
		sv1mlog("#### reuse MASTER[%d] Ver=%s SERVER=%s [NOACK]\n",
			mx,version,server);
		strcpy(MediatorVer,version);
		ToServ = fdopen(msock,"w");
		fprintf(ToServ,"%s %s NOACK\r\n",HelloWord(),DELEGATE_ver());
		relayInput(Conn,ToServ,msock,cache_only,relay_input,0);
		goto EXIT;
	}

	nHello = 0;
	Hello[0] = 0;
	mfpo = fdopen(dup(msock),"w");
	if( mfpo == NULL )
	{
		ServerFlags &= ~PF_IS_MASTER;
		return -1;
	}

	if( reuse ){
		sv1log("#### reuse MASTER[%d] Ver=%s [NOSYNC]\n",mx,version);
		fprintf(mfpo,"%s %s NOSYNC\r\n",HelloWord(),DELEGATE_ver());
		strcpy(MediatorVer,version);
		newver = 1;
	}else{
		if( myauth[0] ){
			fprintf(mfpo,"%s %s DHKEY\r\n",HelloWord(),
				DELEGATE_ver());
		}else
		fprintf(mfpo,"%s %s\r\n",HelloWord(),DELEGATE_ver());
		fflush(mfpo);
		if( 0 < RecvLineTIMEOUT(msock,resp,sizeof(resp),HELLO_TIMEOUT*1000) ){
			sv1log("MASTER[%d] says(1): %s",mx,resp);
			strcpy(Hello,resp);
			scanHelloVer(Hello,AVStr(MediatorVer));
			nHello++;
			newver = 1;

			if( strstr(resp,"[DHKEY]") )
			if( recvPeekTIMEOUT(msock,AVStr(resp),5) == 5 )
			if( strneq(resp,"DHKEY",5) ){
				CStr(dhk,512);
				RecvLineTIMEOUT(msock,dhk,sizeof(dhk),3*1000);
				sendDHkey(mfpo);
				recvDHkey(dhk+5);
			}
		}else{
	sv1log("HELLO negotiation TIMEOUT: OLD version MASTER before 2.0 ?\n");
			strcpy(MediatorVer,"1");
			newver = 0;
		}
	}
	if( myauth[0] )
		sendAUTH(Conn,mfpo,myauth);

	if( strncmp(D_SERVER,"https:",6) == 0 )
	if( vercmp(MediatorVer,"3.0.4") < 0 ){
		CStr(buff,1024);
		strcpy(buff,D_SERVER+6);
		sprintf(D_SERVER,"tcprelay:%s",buff);
		sv1log("#### https -> %s\n",D_SERVER);
	}
	else
	if( vercmp(MediatorVer,"5.3.5") < 0 ){
		CStr(buff,1024);
		strcpy(buff,D_SERVER+6);
		sprintf(D_SERVER,"http:%s",buff);
		sv1log("#### https -> %s\n",D_SERVER);
	}

	relayInput(Conn,mfpo,msock,cache_only,relay_input,1);

	if( newver ){
	getresp:
		if( RecvLineTIMEOUT(msock,resp,sizeof(resp),CON_TIMEOUT*1000) <= 0 ){
			sv1log("MASTER closed\n");
			rcode = -1;
		}else{
			sv1log("MASTER[%d] says(2): %s",mx,resp);
			rcode = atoi(resp);
			if( *resp == '6' )
				rcode = -rcode;

			if( isHelloRequest(resp) ){
				if( 1 < ++nHello )
				sv1log("#### got duplicate HELLO response.\n");
				strcpy(Hello,resp);
				goto getresp;
			}
		}
	}
	fclose(mfpo);

	if( reuse ){
		if( Hello[0] )
			scanHelloVer(Hello,AVStr(MediatorVer));

		if( strcmp(version,MediatorVer) != 0 ){
			sv1log("#### MASTER version [%s]->[%s]\n",
				version,MediatorVer);
			set_masterenv(mx,MediatorVer,"");
		}
	}

	if( rcode < 0 )
	{
		ServerFlags &= ~PF_IS_MASTER;
		return rcode;
	}

	if( 0 <= mx && rcode == 200 )
		set_masterenv(mx,MediatorVer,D_SERVER);

	/* DeleGate < 9.2.6-pre6 doesn't support bare HTTPS/SSL relay, so
	 * relay it by repeating CONNECT.
	 * If the MASTER is not MITM, the following is OK:
	 *	Strrplc(AVStr(D_SERVER),5,"tcprelay");
	 */
	if( vercmp(MediatorVer,"9.2.4-pre6") < 0 )
	if( ClientFlags & PF_MITM_ON ){
		if( ConnectViaSSLtunnelX(Conn,DFLT_HOST,DFLT_PORT,msock) < 0 ){
			ServerFlags &= ~PF_IS_MASTER;
			close(msock);
			return -1;
		}
	}
EXIT:
	insert_FMASTER(Conn,msock);
	return 0;
}

void setToProxy(Connection *Conn,PCStr(proto),PCStr(host),int port)
{
	toProxy = 1;
	strcpy(GatewayProto,proto);
	strcpy(GatewayHost,host);
	GatewayPort = port;
}

int DELEGATE_forward(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,const char **rhost,int *rport,const char **rpath);
int DELEGATE_forwardX(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,AuthInfo **rauth,const char **rhost,int *rport,const char **rpath);

int forwardtoSocks(Connection *Conn,VSAddr *sv){
	const char *proto,*host,*path;
	CStr(clnt,128);
	int port;
	AuthInfo *auth = 0;
	const char *addr;

	if( DELEGATE_forwardX(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,
		clnt,&proto,&auth,&host,&port,&path)
	){
		if( streq(proto,"socks") ){
			if( sv ){
				if( addr = gethostaddr(host) ){
					VSA_atosa(sv,port,addr);
					strcpy(GatewayProto,proto);
					GatewayAuth = auth;
				}
			}
			return 1;
		}
	}
	if( sv ) bzero(sv,sizeof(VSAddr));
	return 0;
}
int ConnectViaYYMUXX(Connection *Conn,void *cty,int relay_input,PCStr(yyhost),int yyport);
int forwardit(Connection *Conn,int fromC,int relay_input)
{	CStr(clnt,128);
	int svaddr,claddr;
	int forw;
	const char *proto;
	const char *host;
	const char *path;
	int port;
	int msock;
	AuthInfo *auth = 0;

	if( Conn->co_mask & CONN_NOPROXY )
		return 0;

	if( MO_ProxyHost[0] != 0 && MO_ProxyPort != 0 ){
		SetStartTime();
		msock = connectToUpper(Conn,"PROXYmo",
			iSERVER_PROTO,MO_ProxyHost,MO_ProxyPort);
		if( 0 < msock ){
			sv1log("PROXY=\"%s:%d\" by MountOption\n",
				MO_ProxyHost,MO_ProxyPort);
			FromS = ToS = msock;
host = MO_ProxyHost;
port = MO_ProxyPort;
			setToProxy(Conn,iSERVER_PROTO,host,port);
			return 1;
		}
	}

/* getpeerName(fromC,clnt,PN_HOST); */
if( getClientHostPort(Conn,AVStr(clnt)) == 0 )
	strcpy(clnt,"?");

	/*
	forw = DELEGATE_forward(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,clnt,&proto,&host,&port,&path);
	*/
	forw = DELEGATE_forwardX(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,clnt,&proto,&auth,&host,&port,&path);
	if( forw == 0 )
		return 0;

	if( CTX_findInPath(Conn,host,port) ){
		sv1log("don't make PROXY loop for %s:%d\n",host,port);
		return 0;
	}

	if( auth && auth->i_user[0] ){
		sv1log("ROUTE: %s://%s:%s@%s:%d/%s\n",proto,
			auth->i_user,auth->i_pass,host,port,path);
	}else
	if( (streq(proto,"direct")||streq(proto,"noroute")) && host[0] == 0 ){
		sv1log("ROUTE: %s\n",proto);
	}else
	sv1log("ROUTE: %s://%s:%d/%s\n",proto,host,port,path);
	SetStartTime();
	if( streq(proto,"noroute") ){
		FromS = ToS = -1;
		return forw;
	}
	if( streq(proto,"direct") ){
		msock = ConnectToServer(Conn,relay_input);
		if( 0 <= msock ){
			ConnType = 'd';
			FromS = ToS = msock;
			return forw;
		}
		return 0;
	}
	if( streq(proto,"socks") ){
		strcpy(GatewayProto,proto);
		GatewayAuth = auth;
		msock = connectViaSocksX(Conn,host,port,path,DST_HOST,DST_PORT);
		if( 0 <= msock ){
			ConnType = 's';
			FromS = ToS = msock;
			return forw;
		}
		return 0;
	}
	if( streq(proto,"yymux") || streq(proto,"yy") ){
		strcpy(GatewayProto,proto);
		GatewayAuth = auth;
		msock = ConnectViaYYMUXX(Conn,NULL,relay_input,host,port);
		if( 0 <= msock ){
			ConnType = 'y';
			FromS = ToS = msock;
			return forw;
		}
		return 0;
	}
	msock = connectToUpper(Conn,"Forward",proto,host,port);
	if( 0 <= msock ){
		strcpy(GatewayProto,proto);
		GatewayPath = stralloc(path);
		GatewayAuth = auth;
		FromS = ToS = msock;

		if( streq(proto,"ssltunnel") ){
			if( SSLtunnelNego(Conn,DST_HOST,DST_PORT,msock) < 0 ){
				close(msock);
				FromS = ToS = msock = -1;
			}else{
				setToProxy(Conn,proto,host,port);
				ConnType = 'h';
			}
		}else
/* fix-120131a these protocols (non-circuit level proxy) can be forwarded by the proxy with the same protocol of the target server ... it cannot relay socks for example */
		if( streq(proto,"http")
/* v9.9.10 fix-140715b this strange code disables non-HTTP proxying
 * (as HTTPS/SSL via CONNECT) via an upstream HTTP proxy
&& strcaseeq(proto,DST_PROTO)
*/
		 || streq(proto,"http-proxy")
		 || streq(proto,"ftp")
		 || streq(proto,"telnet")
		){
			setToProxy(Conn,proto,host,port);
		}
		else /* if( streq(proto,"delegate")) */
		{
			if( connect_master(Conn,-1,msock,0,relay_input) == 0 )
				toMaster = 1;
			else{
				close(msock);
				FromS = ToS = msock = -1;
			}
		}
	}
	return forw;
}

extern double CFISTAT_TIMEOUT;
int ConnectViaVSAP(Connection *Conn,int relay_input);
int open_master(Connection *Conn,int try_direct,PCStr(server),int svport,int sendhead,int relay_input);
void poll_filterctls(Connection *Conn,int timeout);

extern int CON_RETRY;
int insert_CLUSTER(Connection *Conn,int sock);
static void init_CLUSTER(Connection *Conn);
int serverWithEquiv(PCStr(host1),int port1,PCStr(host2),int port2,int *rand);
int connect_to_aliases(Connection *Conn,int fromC,int toC,int relay_input);
#define CLDBG	lTHREAD()==0?0:sv1log

int getConnectFlags(PCStr(wh)){
	int flags = 0;
	if( *wh == '-' ){
		flags |= COF_TERSE;
		flags |= COF_DONTRETRY;
	}
	return flags;
}
static int _OpenServer;
int OpenServerX(Connection *Conn,PCStr(what),PCStr(proto),PCStr(host),int port){
	const char *server;
	int sock;
	Port sv;
	int con_retry = CON_RETRY;
	int rand = 0;
	const char *wh = "ConnectToServer";

	if( lMULTIST() ){
		/* 9.8.2 CLUSTER should be disabled with multi-server-threads
		if( _OpenServer )
		fprintf(stderr,"-- %3X (%d) OpenServer\n",TID,_OpenServer);
		*/
	}else
	if( _OpenServer ){
		return -1;
	}
	_OpenServer++;

	if( server = strchr(host,'@') )
		server = server + 1;
	else	server = host;

	init_CLUSTER(Conn);
	if( serverWithEquiv(server,port,0,0,&rand) ){
		CON_RETRY = 1;
	}
	if( rand ){
		sock = -1;
	}else
	{
		if( ConnectFlags & COF_TERSE ){
			wh = "-ConnectToServer";
		}
		sock = client_open(wh,proto,server,port);
	/*
	sock = client_open("ConnectToServer",proto,server,port);
	*/
	}

	sv = Conn->sv;
	ToS = sock;
	strcpy(REAL_PROTO,proto);
	strcpy(REAL_HOST,server);
	REAL_PORT = port;
	CLDBG("---OpenServer [%s://%s:%d]\n",REAL_PROTO,REAL_HOST,REAL_PORT);

	if( sock < 0 ){
		sock = connect_to_aliases(Conn,-1,-1,-1);
		CLDBG("---OpenServer(%s %s://%s:%d) failed >>> %d\n",
			DST_PROTO,proto,host,port,sock);
	}
	if( 0 <= sock ){
		sock = insert_CLUSTER(Conn,sock);
		CLDBG("---OpenServer(%s %s://%s:%d) INSC >>> %d\n",
			DST_PROTO,proto,host,port,sock);
	}
	Conn->sv = sv;
	_OpenServer--;

	CLDBG("---OpenServer returns %d\n",sock);
	CON_RETRY = con_retry;
	return sock;
}

static int connect_to_serverX(Connection *Conn,PCStr(proto),PCStr(host),int port, int fromC,int toC, int relay_input);
static int connect_to_server(Connection *Conn,PCStr(proto),PCStr(host),int port, int fromC,int toC, int relay_input)
{	int sock;
	int con_retry = CON_RETRY;
	int rand = 0;

	init_CLUSTER(Conn);
	if( serverWithEquiv(host,port,0,0,&rand) ){
		CON_RETRY = 1;
	}
	if( rand ){
		sock = -1;
	}else
	sock = connect_to_serverX(Conn,proto,host,port,fromC,toC,relay_input);
	if( sock < 0 ){
		sock = connect_to_aliases(Conn,fromC,toC,relay_input);
	}
	if( 0 <= sock ){
		CTX_setSockOpts(FL_ARG,Conn,sock,0);
		sock = insert_CLUSTER(Conn,sock);
	}
	CON_RETRY = con_retry;
	return sock;
}
int connect_to_serverY(Connection *Conn,void *cty,PCStr(proto),PCStr(host),int port, int fromC,int toC, int relay_input);
static int connect_to_serverX(Connection *Conn,PCStr(proto),PCStr(host),int port, int fromC,int toC, int relay_input)
{
	int rcode;
	rcode = connect_to_serverY(Conn,NULL,proto,host,port,fromC,toC,relay_input);
	return rcode;
}
int connect_to_serverY(Connection *Conn,void *cty,PCStr(proto),PCStr(host),int port, int fromC,int toC, int relay_input)
{	int svsock;
	double Start;

	poll_filterctls(Conn,(int)CFISTAT_TIMEOUT*1000);

	FromS = ToS = svsock = -1;
	FromSX = -1;
	Conn->sv.p_SOCKSCTL = -1;
	toMaster = 0;
	Start = Time();

	/* internal protocol */
	if( port == 0 )
		return -1;

	if( isMYSELF(host) && strcaseeq(proto,"smtp") )
		return -1;

	if( strcaseeq(proto,"dump") || strcaseeq(proto,"pgps") )
		return -1;

	if( !service_permitted(Conn,proto) )
		return -1;

	if( Conn->co_mask & CONN_DIRECTONLY ){
		svsock = client_open(DFLT_PROTO,DST_PROTO,DST_HOST,DST_PORT);
		return svsock;
	}

	setupConnect(Conn); /* setup the order of connection types */
	ProcTitle(Conn,"%s://%s/",DST_PROTO,DST_HOST);
	/* 9.9.6 this should be applied to the DST_PROTO://DST_HOST always */
	set_SRCIF(Conn,proto,host,port);

	SetStartTime();

	if( !streq(proto,"http")
	 && !streq(proto,"https")
	 && !tryProxyOnly
	 && connectToCache(Conn,"",&svsock) ){
		svsock = setServ(Conn,svsock);
		ConnType = 'R';
		goto CONNECTED;
	}else
	if( tryCONNECT(Conn,cty,relay_input,&svsock) ){
		svsock = setServ(Conn,svsock);
		/* ConnType has been set in tryCONNECT() */
		goto CONNECTED;
	}else{
		if( 0 <= (svsock = ConnectViaICP(Conn,NULL)) ){
			if( toMaster
			 && connect_master(Conn,-1,svsock,0,relay_input) != 0 ){
				close(svsock);
			}else{
				svsock = setServ(Conn,svsock);
				ConnType = 'i';
				goto CONNECTED;
			}
		}

		if( forwardit(Conn,fromC,relay_input) ){
			svsock = ToS;
			if( ConnType=='d' || ConnType=='s' || ConnType=='h' ){
			}else
			if( toProxy )
				ConnType = 'p';
			else	ConnType = 'm';
			goto CONNECTED;
		}
		if( tryProxyOnly ){
			Verbose("tryProxyOnly:NO PROXY/MASTER\n");
			return -1;
		}

		if( 0 <= (svsock=open_master(Conn,1,host,port,1,relay_input))){
			svsock = setServ(Conn,svsock);
			ConnType = 'm';
			goto CONNECTED;
		}

		if( 0 <= (svsock = ConnectViaSSLtunnel(Conn,host,port)) ){
			svsock = setServ(Conn,svsock);
			ConnType = 'h';
			goto CONNECTED;
		}

		if( 0 <= (svsock = ConnectViaYYMUX(Conn,cty,relay_input)) ){
			ConnType = 'y';
			goto CONNECTED;
		}
		if( 0 <= (svsock = ConnectViaVSAP(Conn,relay_input)) ){
			ConnType = 'v';
			goto CONNECTED;
		}

		if( 0 <= (svsock = ConnectViaSocks(Conn,relay_input)) ){
			ConnType = 's';
			goto CONNECTED;
		}

		if( (ConnectFlags & COF_NONDIRECT) == 0 )
		if( 0 <= (svsock=ConnectToServer(Conn,relay_input)) ){
			ConnType = 'd';
			goto CONNECTED;
		}

		/* V8.0.0 CONNECT=...,s,d by default
		if( 0 <= (svsock = ConnectViaSocks(Conn,relay_input)) ){
			ConnType = 's';
			goto CONNECTED;
		}
		*/
	}
	if( ConnectFlags & COF_TERSE ){
		sv1log("Cannot connect to %s://%s:%d (%.2f) e%d\n",
			proto,host,port,Time()-Start,errno);
	}else
	sv1log("ERROR: cannot connect to %s://%s:%d - %d\n",
		proto,host,port,svsock);
FAILED:
	return svsock;

CONNECTED:
	switch( ConnType ){
		case 'd':
		case 's':
	/* forwarding RIDENT must be done as fast as possible after the
	 * connection establishment */
			forward_RIDENT(Conn,ConnType,svsock,NULL);
			break;
	}

	if( 0 <= svsock )
	if( 1 ){
		CStr(addr,128);
		getpeerName(svsock,AVStr(addr),"%A");
		addtoHostSet("server",host,addr);
	}
	ServConnTime = Time();

	/* Currently, ToServ is supported only in HTTP */
	if( ToServ && !streq(proto,"http") )
		fflush(ToServ);
	ConnDelay = ServConnTime - Start;

	return svsock;
}

void insert_FSERVER(Connection *Conn,int fromC);
int connect2server(Connection *Conn,PCStr(proto),PCStr(host),int port)
{	int sock;

	ToSF = -1;
	ServerFlags = 0;
	Conn->from_myself = 1;
	set_realserver(Conn,proto,host,port);
	sv1log("#### %s://%s:%d ...\n",proto,host,port);
	sock = connect_to_server(Conn,proto,host,port,-1,-1,0);
	sv1log("#### %s://%s:%d = %d\n",proto,host,port,sock);
	if( sock < 0 ){
		return -1;
	}
	insert_FSERVER(Conn,-1);
	return sock;
}

/*
 *	DFLT_... should be replaced by DST_...
 */
int connect_to_servX0(Connection *Conn, int fromC,int toC, int relay_input, int do_filter);
int connect_to_servX(Connection *Conn, int fromC,int toC, int relay_input, int do_filter)
{	int sock;

	/* 9.8.2 the error status and message in parallel-connects
	 * will be jammed if they occur ...
	if( numthreads() ){
		static CriticalSec connCSC;
		static int pconn;
		pconn++;
		setupCSC("connect_to_servX",connCSC,sizeof(connCSC));
		enterCSC(connCSC);
		sock = connect_to_servX0(Conn,fromC,toC,relay_input,do_filter);
		leaveCSC(connCSC);
		pconn--;
		return sock;
	}
	 */
	sock = connect_to_servX0(Conn,fromC,toC,relay_input,do_filter);
	if( YY_connect(Conn,sock,get_initfrom(Conn)) < 0 ){
		close(sock);
		CTX_closedX(FL_ARG,"YY_connect",Conn,sock,-1,1);
		return -1;
	}
	return sock;
}
int connect_to_servX0(Connection *Conn, int fromC,int toC, int relay_input, int do_filter)
{	int sock;
	int toSX = -1;

	CONNERR_CANTRESOLV = 0;
	sock = connect_to_server(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,
		fromC,toC,relay_input);

	if( sock < 0 && tryProxyOnly /* && no-other-alternative-left */ )
		return sock;

	if( ConnType != 'N' )
	if( sock < 0 ){
		const char *reason;
		CStr(server,1024);
		CStr(shost,MaxHostNameLen);
		int sport;

		if( ConnError == 0 ){
			if( CONNERR_CANTRESOLV ){
				ConnError |= CO_CANTRESOLV;
			}
			ConnError |= CO_NOROUTE;
		}
		reason = "?";
		if( ConnError & CO_CANTRESOLV ) reason = "unknown";
		if( ConnError & CO_TIMEOUT    ) reason = "timeout";
		if( ConnError & CO_REFUSED    ) reason = "refused";
		if( ConnError & CO_UNREACH    ) reason = "unreach";
		if( ConnError & CO_NOROUTE    ) reason = "noRoute";

		sport = getClientHostPort(Conn,AVStr(shost));
		HostPort(AVStr(server),DST_PROTO,DST_HOST,DST_PORT);
		if( ConnectFlags & COF_TERSE ){
		}else
		daemonlog("F","%s: %s:%d %s %s://%s (%s)\n",
		"E-C: Can't connect",shost,sport,"=>",DST_PROTO,server,reason);
	}

	willSTLS_SV(Conn);
	/*
	if( needSTLS_SV(Conn) && serviceWithSTLS(DST_PROTO) == 0 ){
		daemonlog("E","ERROR: SSL/sv is not detected\n");
	}
	*/

	if( do_filter )
	insert_FSERVER(Conn,fromC);
	return sock;
}
int connect_to_serv(Connection *Conn, int fromC,int toC, int relay_input)
{
	return connect_to_servX(Conn, fromC,toC, relay_input, 1);
}
int connect_to_sv(Connection *Conn,PCStr(proto),PCStr(host),int port){
	int sock;

	set_realsite(Conn,proto,host,port);
	if( !streq(DFLT_PROTO,REAL_PROTO) && strcaseeq(proto,REAL_PROTO) ){
		Conn->no_dstcheck_proto = serviceport(proto);
	}
	sock = connect_to_server(Conn,DST_PROTO,DST_HOST,DST_PORT,-1,-1,0);
	return sock;
}

/*
int connect_to(PCStr(proto),PCStr(host),int port)
{	Connection ConnBuff,*Conn = &ConnBuff;
	int sv;

	Conn->from_myself = 1;
	sv = connect_to_server(Conn,proto,host,port, -1,-1,0);
	return sv;
}
*/

void DG_relayInput(Connection *Conn,int fd);
int openMaster(Connection *Conn,int svsock,PCStr(server),int relay_input)
{	int msock,sv[2];
	FILE *mfp;

	if( svsock == -1 )
	if( 0 <= (msock = open_master(Conn,0,server,0,1,relay_input) ) )
		return msock;

	if( svsock != -1 && toMaster ){
		if( relay_input )
			DG_relayInput(Conn,svsock);
		return  svsock;
	}

	Socketpair(sv);
	if( Fork("openMaster") == 0 ){
		close(sv[1]);
		sv1log("PRIVATE MASTER[%d/%d] svsock=%d\n",sv[0],sv[1],svsock);
		DFLT_HOST[0] = 0;
		clear_DGconn(Conn);
		execGeneralist(Conn,sv[0],sv[0],svsock);
		Finish(0);
	}
	close(sv[0]);
	mfp = fdopen(dup(sv[1]),"w");
	relayInput(Conn,mfp,sv[1],0,relay_input,1);
	fclose(mfp);
	return sv[1];
}

extern int FromTeleport;
int fromTunnel(Connection *Conn,int sock)
{
	/*
	sv1log("#### fromTunnel(%d) ? proto=%s FromTeleport=%d\n",sock,
		iSERVER_PROTO,FromTeleport);
	*/
	if( streq(iSERVER_PROTO,"tunnel1") )
		return 1;
	return 0;
}
int toTunnel(Connection *Conn)
{
	return toMaster == 2;
}
int connectViaTunnel(Connection *xConn,PCStr(proto),PCStr(host),int port)
{	Connection ConnBuf, *Conn = &ConnBuf;
	int msock;
	CStr(req,1024);

	*Conn = *xConn;
	sprintf(D_SERVER,"%s://%s:%d",proto,host,port);
	msock = open_master(Conn,0,host,port,1,0);
	if( 0 <= msock && toMaster != 2 ){
		sv1log("[%d] not viaTunnel\n",msock);
		close(msock);
		msock = -1;
	}
	return msock;
}

int teleportOpen(int mx,PCStr(master),int mport,PCStr(target_server),int closefd);
int DELEGATE_Filter(int mi,PCStr(dstproto),PCStr(dsthost),int dstport);
int DELEGATE_master(Connection *Conn,int ms,const char **master,int *mport,int *teleport,int *cacheonly);

int MasterXi;
int MasterXo;
int nMASTERS();

int open_master(Connection *Conn,int try_direct,PCStr(server),int svport,int sendhead,int relay_input)
{	int msock;
	int mi,mx;
	int mn,mi0;
	const char *master;
	int no_socks;
	int mport;
	int tport;
	int cache_only;
	const char *hp;

	if( Conn->co_mask & CONN_NOMASTER )
		return -1;

	if( MasterIsPrivate && ACT_GENERALIST )
		return -1;

	SetStartTime();

	if( hp = strchr(server,'@') )
		server = hp + 1;

	no_socks = MasterIsPrivate;

	msock = -1;

	/*
	for(mi = 0; ;mi++){
	*/
	if( 1 < MasterXi ){
		mi0 = MasterXi-1;
	}else	mi0 = 0;
	for( mn = 0; mn < nMASTERS(); mn++ ){
		mi = (mi0 + mn) % nMASTERS(); 
		if( (mx = DELEGATE_master(Conn,mi,&master,&mport,&tport,&cache_only)) == 0 ){
			msock = -1;
			goto EXIT;
		}

		if( master == NULL )
			continue;/* Teleport */

		if( cache_only ){
			if( DontReadCache )
				continue;
			if( !withcache(DST_PROTO) )
				continue;
		}

		if( DELEGATE_Filter(mx,DST_PROTO,server,svport) != 0 )
			continue;

		if( CTX_findInPath(Conn,master,mport) ){
			sv1log("don't make MASTER loop for %s:%d\n",
				master,mport);
			continue;
		}

		if( streq(master,"*") ){
			if( !try_direct )
				continue;

			msock = ConnectToServer(Conn,relay_input);
			if( 0 <= msock )
				goto EXIT;
		}

		if( tport )
			msock = teleportOpen(mx,master,mport,
				server,ClientSock);
		else
		if( !no_socks )
			msock = connectToUpper(Conn,"MasterOpen","delegate",
				master,mport);
		else	msock = connectServer("MasterOpen","delegate",
				master,mport/*,no_socks*/);

		if( 0 <= msock ){
			if( CCSV_reusing(Conn,"MASTER",msock) ){
				toMaster = 1;
				strcpy(MediatorVer,"9.9.3");
				/*
				- toMaster to let X-Cache-ID be sent
				- MediatorVer no to let HTTP FORCE HTTP/1.0
				  for MASTER-DeleGate/5.x.x
				these should be set in CCSV_reusing()
				*/
				break;
			}
			if( !sendhead ){
				if( tport ) toMaster = 2; else
				toMaster = 1;
				break;
			}

			if( connect_master(Conn,mx,msock,cache_only,relay_input) == 0 ){
				if( tport ) toMaster = 2; else
				toMaster = 1;
				MasterXo = mi+1;
				break;
			}
			close(msock);
			msock = -1;
		}
	}
EXIT:
	if( msock < 0 && withTmpMaster() ){
		msock = connectServer("MO-MasterOpen","delegate",
			MO_MasterHost,MO_MasterPort/*,no_socks*/);
		if( 0 <= msock ){
			if( connect_master(Conn,-1,msock,0,relay_input) == 0 )
				toMaster = 1;
		}
	}

	if( 0 <= msock )
		set_keepalive(msock,1);
	else{
		/* something wrong in private master...  (may be replaced)
		 */
		if( myPrivateMASTER != 0 )
			BREAK_STICKY = 1;
	}
	return msock;
}

void initConnected(Connection *Conn,int svsock,int relay_input);
int ConnectViaVSAP(Connection *Conn,int relay_input)
{	int sock;
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen+16);

	sockname[0] = 0;
	sprintf(peername,"%s:%d",DST_HOST,DST_PORT);
	if( 0 <= (sock = CTX_VSAPconnect(Conn,AVStr(sockname),AVStr(peername))) )
		initConnected(Conn,sock,relay_input);

	return sock;
}

void scan_OVERRIDE(Connection *Conn,PCStr(ovparam))
{	CStr(master,MaxHostNameLen);
	CStr(port,256);

	Xsscanf(ovparam,"%[^:]:%[^:]:%s",AVStr(master),AVStr(port),AVStr(D_OVERRIDE));
}

static void lfprintf(FILE *fp,PCStr(fmt),...)
{	CStr(line,4096);
	int wc = -1;
	VARGS(7,fmt);

	if( fp != NULL )
		wc = fprintf(fp,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);

	strcpy(line,"<= ");
	Xsprintf(TVStr(line),fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
	Verbose("%s",line);
}

static void relayInput(Connection *Conn,FILE *mfp,int msock,int cache_only,int relay_input,int doflush)
{	CStr(mhostport,MaxHostNameLen);
	CStr(me,MaxHostNameLen);
	CStr(dstaddr,512);
	int hi;

	getpeerName(msock,AVStr(mhostport),PN_HOSTPORT);
	sv1log("forwarding to [%d] %s://%s\n",msock,"delegate",mhostport);
	gethostnameIF(AVStr(me),sizeof(me));

	/* this should done before any name resolution occures */
	if( make_HOSTS(AVStr(dstaddr),DST_HOST,1) )
		lfprintf(mfp,"HOSTS %s\n",dstaddr);

			     lfprintf(mfp,"MEDIATOR %s\r\n",me);
	if(D_RPORT[0])       lfprintf(mfp,"RPORT %s\r\n",  D_RPORT);
	if(D_FTPHOPS )	     lfprintf(mfp,"FTPHOPS %d\r\n",D_FTPHOPS);
	if(D_SERVER[0])      lfprintf(mfp,"SERVER %s\r\n", D_SERVER);
	if(D_REQUESTtag.ut_addr)
			     lfprintf(mfp,"REQUEST %s\r\n",D_REQUESTtag.ut_addr);
	if(D_FROM[0]  )      lfprintf(mfp,"FROM %s\r\n",   D_FROM);
	if(D_USER[0]  )      lfprintf(mfp,"USER %s\r\n",   D_USER);
	if(D_PATH[0]  )      lfprintf(mfp,"PATH %s\r\n",   D_PATH);
	if(D_EXPIRE[0])      lfprintf(mfp,"EXPIRE %s\r\n", D_EXPIRE);
	if(D_GTYPE[0] )      lfprintf(mfp,"LOCAL-GTYPE %c\r\n",D_GTYPE[0]);
	if(never_cache(Conn))lfprintf(mfp,"CACHE DISABLE\r\n");
	if(DontReadCache)    lfprintf(mfp,"CACHE DONT_READ\r\n");
	if(DontWaitCache)    lfprintf(mfp,"CACHE DONT_WAIT\r\n");
	if(cache_only)       lfprintf(mfp,"CACHE ONLY %d\r\n",CacheLastMod);
	if(CLIENTS_PROXY[0]) lfprintf(mfp,"CLIENTS-PROXY %s\r\n",CLIENTS_PROXY);
	if(D_OVERRIDE[0])    lfprintf(mfp,"OVERRIDE %s\r\n",D_OVERRIDE);

	if( headerX ){
		for( hi = 0; hi < headerX; hi++ )
	        	lfprintf(mfp,"%s",headerB[hi]);
	}
	lfprintf(mfp,"\r\n");

	if(relay_input && inputsX ){
		for( hi = 0; hi < inputsX; hi++ )
			lfprintf(mfp,"%s",inputsB[hi]);
/*
Verbose("RelayInput: <= %d bytes\n%s\n",strlen(D_inputs),D_inputs);
*/
	}
	if( mfp != NULL && doflush )
		fflush(mfp);
}

void setConnStart(Connection *Conn){ CONN_START= Time(); }
void setConnDone(Connection *Conn){ CONN_DONE = Time(); }


/*
 * DELEGATE=host:port:"callback-protoList"
 * it resticts protocols to be redirected with "/-_-" notation.
 * it should be obsoleted by MOUNT="/-_-* * proto="!{callback-protoList}"
 */
static scanListFunc callback1(PCStr(proto))
{	int callback;
	int si;

	callback = 1;
	if( *proto == '-' ){
		callback = 0;
		proto++;
	}
	if( strcaseeq(proto,"all") ){
		for( si = 1; services[si].s_name; si++ )
			services[si].s_nocallback = !callback;
	}else
	if( si = servicex(proto) )
		services[si].s_nocallback = !callback;
	else	sv1log("CALLBACK: %s ?\n",proto);
	return 0;
}
void scan_CALLBACK(PCStr(protolist))
{	int si;

	for( si = 1; services[si].s_name; si++ )
		services[si].s_nocallback = 1;
	scan_commaList(protolist,0,scanListCall callback1);
}
int callback_it(PCStr(proto))
{	int si;

	if( si = servicex(proto) )
		return !services[si].s_nocallback;
	return 0;
}


int service_permitted0X(PCStr(clhost),int clport,PCStr(svproto),PCStr(svhost),int svport,int silent);
void tcp_relay2(int timeout,int s1,int d1,int s2,int d2);
int HTTP_isMethod(PCStr(method));
int service_http(Connection *Conn);
int service_imap(Connection *Conn);
int service_smtp(Connection *Conn);
int service_nntp(Connection *Conn);
int service_ftp(Connection *Conn);
int service_pop(Connection *Conn);
int service_telnet(Connection *Conn);
static int withSOCKSTAP;

/*
 * Circuit level to Application level Gateway
 *
 * postpone the connection to the destination server not to establishh
 * a connection in vain when there is a valid cache of the protocol (HTTP).
 *
 * SOCKSTAP=do:protoList:dstHost:srcHost:{listOfParameters}"
 */
const char _SOCKSTAP[] = "_SOCKSTAP";
#define dotap(pr,hn,pn,a) \
  (0 <= find_CMAPX(Conn,_SOCKSTAP,AVStr(a),pr,hn,pn,Client_Host,Client_Port,""))

int CLALGconn(Connection *Conn,PCStr(com),int sock,PCStr(remote),PCStr(opts)){
	IStr(host,MaxHostNameLen);
	int port = 0;
	int ok = 0;
	int osock;
	const char *proto = 0;
	IStr(lhost,MaxHostNameLen);
	int lport = 0;
	CStr(args,128);

	if( withSOCKSTAP == 0 ){
		return -1;
	}
	Xsscanf(remote,"%[^:]:%d",AVStr(host),&port);
	ok = dotap("http",host,port,args)
	  || dotap("imap",host,port,args)
	  || dotap("nntp",host,port,args)
	  || dotap("smtp",host,port,args)
	  || dotap("ftp", host,port,args)
	  || dotap("pop", host,port,args)
	  || dotap("telnet",host,port,args)
	;
	if( !ok ){
		return -1;
	}
	GatewayFlags |= GW_IN_CLALG;
	osock = sock;
	if( sock < 0 ){
		switch( port ){
			case  21: proto = "ftp"; break;
			case  23: proto = "telnet"; break;
			case  25: proto = "smtp"; break;
			case 110: proto = "pop"; break;
			case 119: proto = "nntp"; break;
			case 143: proto = "imap"; break;
			default:  proto = "http"; break;
		}
		if( proto && streq(proto,"http") ){
			SRCIFfor(Conn,proto,host,port,AVStr(lhost),&lport);
			if( *lhost == '*' )
				truncVStr(lhost);
			sock = server_open("VSocket",AVStr(lhost),lport,0);
		}
	}
	sv1log("-- CLALG mode [%d %d] %s <- %s:%d\n",sock,osock,remote,
		Client_Host,Client_Port);
	if( 0 <= sock ){
		ToS = FromS = sock;
	}
	return sock;
}

double TIMEOUT_CLAL = 5;
int insert_FCLIENTS(Connection *Conn,int *fromCp,int *toCp);
void configX(PCStr(what),Connection *Conn,int ac,const char *av[]);
static int metamo(Connection *Conn,int s1,int d1,int s2,int d2,PCStr(proto),servFunc *func){
	int ok;
	IStr(args,1024);

	ok = dotap(proto,REAL_HOST,REAL_PORT,args);
	sv1log("-- CLALG Metamo from '%s/%s' to '%s'://%s:%d ... do=%d\n",
		DFLT_PROTO,iSERVER_PROTO,proto,REAL_HOST,REAL_PORT,ok);
	if( !ok ){
		return 0;
	}
	FromC = s1; ToS = d1;
	FromS = s2; ToC = d2;
	strcpy(CLNT_PROTO,proto);
	strcpy(REAL_PROTO,proto);
	
	/*
	Conn->no_dstcheck_proto == serviceport(proto);
	*/
	Conn->no_dstcheck = 1;
	if( args[0] ){
		CStr(ab,1024);
		const char *av[256];
		int ac;
		ac = decomp_args(av,elnumof(av),args,AVStr(ab));
		configX("SOCKSTAP",Conn,ac,av);
	}

	insert_FCLIENTS(Conn,&FromC,&ToC);
	insert_FSERVER(Conn,FromC);
	(*func)(Conn);
	/* for pop with FCL */ {
		if( 0 <= ToC ) close(ToC);
		if( 0 <= FromC && FromC != ToC ) close(FromC);
	}
	sv1log("-- CLALG Metamo done [%d %d %d]\n",ClientSock,FromC,ToC);
	return 1;
}

/*
 * detecting the protocol by listening data from a client or a server
 * on a established connection between a client and a server,
 * then metamorphose to the application-level proxy of the protocol.
 */
int CLALGrelay(Connection *Conn,int timeout,int s1,int d1,int s2,int d2){
	int fdv[2];
	int rdv[2];
	CStr(re,128);
	const unsigned char *ure = (unsigned char*)re;
	int siz;
	int rcc;
	const char *proto = 0;
	servFunc *sfp;
	int nready;
	

	if( (GatewayFlags & GW_IN_CLALG) == 0 )
		return 0;

	fdv[0] = s1;
	fdv[1] = s2;
	nready = PollIns((int)(TIMEOUT_CLAL*1000),2,fdv,rdv);
	if( nready <= 0 )
		return 0;

	siz = sizeof(re)-1;
	if( 0 < rdv[0] ){
		rcc = recvPeekTIMEOUT(fdv[0],AVStr(re),siz);
		sv1log("-- CLALG got from client rcc=%d\n",rcc);
		if( 0 < rcc )
			setVStrEnd(re,rcc);
		else	setVStrEnd(re,0);

		if( HTTP_isMethod(re) ){
			if( metamo(Conn,s1,d1,s2,d2,"http",service_http) )
				return 1;
		}
	}

	if( 0 < rdv[1] || 0 < PollIn(fdv[1],(int)(TIMEOUT_CLAL*1000)) ){
		rcc = recvPeekTIMEOUT(fdv[1],AVStr(re),siz);
		sv1log("-- CLALG got from server rcc=%d\n",rcc);
		if( 0 < rcc )
			setVStrEnd(re,rcc);
		else	setVStrEnd(re,0);

		if( strneq(re,"200",3) ){
			if( metamo(Conn,s1,d1,s2,d2,"nntp",service_nntp) )
				return 1;
		}else
		if( strneq(re,"* OK ",5) ){
			if( metamo(Conn,s1,d1,s2,d2,"imap",service_imap) )
				return 1;
		}else
		if( strneq(re,"220",3) ){
		  int ok;
		  if( DST_PORT == 25 )
			ok = metamo(Conn,s1,d1,s2,d2,"smtp",service_smtp);
		  else	ok = metamo(Conn,s1,d1,s2,d2,"ftp",service_ftp);
		  if( ok )
			return 1;
		}else
		if( strneq(re,"+OK",3) ){
			if( metamo(Conn,s1,d1,s2,d2,"pop",service_pop) )
				return 1;
		}
		else
		if( DST_PORT == 23 && ure[0] == 255/*IAC*/ ){
			if( metamo(Conn,s1,d1,s2,d2,"telnet",service_telnet) )
				return 1;
		}
	}
	return 0;
}
void tcp_relay2X(Connection *Conn,int timeout,int s1,int d1,int s2,int d2){
	if( CLALGrelay(Conn,timeout,s1,d1,s2,d2) )
		return;
	tcp_relay2(timeout,s1,d1,s2,d2);
}

void scan_SOCKSTAP(Connection *Conn,PCStr(tapspec)){
	IStr(proto,1024);
	IStr(dst,1024);
	IStr(src,1024);
	IStr(args,1024);
	CStr(xspec,2048);

	withSOCKSTAP = 1;
	scan_Lists4(tapspec,':',proto,dst,src,args);
	if( streq(proto,"") || streq(proto,"all") ) strcpy(proto,"*");
	if( streq(dst,"") ) strcpy(dst,"*");
	if( streq(src,"") ) strcpy(src,"*");
	sprintf(xspec,"{%s}:%s:{%s}:{%s}:{%s}",args,_SOCKSTAP,proto,dst,src);
	scan_CMAP(Conn,xspec);
}

/*
 * CLUSTER=proto1,proto2:__RR,host1..port1,host2..port2,...
 */
int getHostInList(int hlid,int hi,const char **host,PVStr(addr),int *port);
int getHostListSize(int hlid,int *rand);
static int withepsv = 0;
static int eqSVtid;
static int eqSVn = 0;
static int eqSVx = 0;
static int eqSVL;
static int eqSVs[32];
static int eqSVN;
static int eqSVinRetry;

static scanListFunc normlist(PCStr(hp),Connection *Conn,PVStr(list)){
	refQStr(lp,list);
	IStr(host,MaxHostNameLen);
	refQStr(pp,host);
	int port = 0;

	if( *hp == '/' ){
		lp = list + strlen(list);
		if( list < lp )
			setVStrPtrInc(lp,',');
		sprintf(lp,"%s",hp);
		return 0;
	}
	strcpy(host,hp);
	if( pp = strstr(host,"..") ){
		port = atoi(pp+2);
		setVStrEnd(pp,0);
	}
	if( port == 0 )
		port = serviceport(DST_PROTO);
	lp = list + strlen(list);
	if( list < lp )
		setVStrPtrInc(lp,',');
	sprintf(lp,"%s..%d",host,port);
	InitLog("EQSV/%s %s >>> %s\n",DST_PROTO,hp,lp);
	return 0;
}
void scan_CLUSTER(Connection *Conn,PCStr(servs)){
	const char *pp;
	IStr(tag,1024);
	IStr(list,1024);

	pp = wordScanY(servs,tag,"^:");
	if( *pp == ':' ){
		scan_commaList(pp+1,1,scanListCall normlist,Conn,AVStr(list));
		InitLog("EQSV/%s [%d] >>> %s\n",DST_PROTO,eqSVN,list);
		if( eqSVN < elnumof(eqSVs) ){
			eqSVs[eqSVN++] = makePathList(tag,list);
		}
	}
}
int serverWithEquiv(PCStr(host1),int port1,PCStr(host2),int port2,int *rand){
	int li,lid;

	for( li = 0; li < eqSVN && li < elnumof(eqSVs); li++ ){
		lid = eqSVs[li];
		if( matchPath1(lid,"",host1,port1)
		 || matchPath1(lid,"",host1,0)  ){
			if( host2 == NULL
			 || matchPath1(lid,"",host2,port2)
			 || matchPath1(lid,"",host2,0) ){
				if( rand ) getHostListSize(lid,rand);
				return lid;
			}
		}
	}
	return 0;
}
static void init_CLUSTER(Connection *Conn){
	int err;

	if( eqSVinRetry ){
		err = 0;
		Verbose("EQSV/%s cleanup previous[%d] tid=%X err=%d RETRYING\n",
			DST_PROTO,eqSVx,eqSVtid,err);
		return;
	}
	if( eqSVtid ){
		err = thread_wait(eqSVtid,100);
		sv1log("EQSV/%s cleanup previous[%d] tid=%X err=%d\n",
			DST_PROTO,eqSVx,eqSVtid,err);
		eqSVtid = 0;
	}
	eqSVx = 0;
	eqSVL = 0;
}
static int set_EQSV(Connection *Conn){
	if( eqSVL == 0 ){
		if( eqSVL == 0 ) eqSVL = serverWithEquiv(REAL_HOST,REAL_PORT,0,0,0);
		if( eqSVL == 0 ) eqSVL = serverWithEquiv(DFLT_HOST,DFLT_PORT,0,0,0);
		if( eqSVL != 0 ){
			eqSVn = getHostListSize(eqSVL,0);
			CLDBG("EQSV/%s L=%d N=%d\n",DST_PROTO,eqSVL,eqSVn);
		}else	eqSVn = 0;
		eqSVx = 0;
	}
	return eqSVL;
}
int connect_to_aliases(Connection *Conn,int fromC,int toC,int relay_input){
	int sock;
	Port sv;
	Port sv_dflt;
	const char *host;
	int port;
	IStr(addr,256);

	if( eqSVL == 0 ){
		set_EQSV(Conn);
		if( eqSVL == 0 ){
			return -1;
		}
	}
	if( eqSVn <= eqSVx )
		return -1;
	sv = Conn->sv;
	sv_dflt = Conn->sv_dflt;
	eqSVinRetry++;
	for(; eqSVx < eqSVn; eqSVx++ ){
		if( getHostInList(eqSVL,eqSVx,&host,AVStr(addr),&port) != 0 ){
			continue;
		}
		CLDBG("EQSV/%s con[%d] %s:%d\n",DST_PROTO,eqSVx,host,port);
		if( port == 0 ) port = DFLT_PORT;
		if( hostcmp(host,DFLT_HOST)==0 && port == DFLT_PORT
		 || hostcmp(host,REAL_HOST)==0 && port == REAL_PORT ){
			continue;
		}
		if( relay_input < 0 ){
			sock = client_open("EQSV",DST_PROTO,host,port);
		}else{
		set_realserver(Conn,DST_PROTO,host,port);
		sock = connect_to_serverX(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,
			fromC,toC,relay_input);
		}
		if( 0 <= sock ){
			eqSVx++;
			break;
		}
	}
	eqSVinRetry--;
	if( sock < 0 ){
		Conn->sv = sv;
	}
	Conn->sv_dflt = sv_dflt;
	return sock;
}
typedef struct {
	int	 c_csn;
	int	 c_csvlen[8];
     const char	*c_csv[8];
	MStr(	 c_stoc,1024);
} ClientReq;
static int retryConn(Connection *Conn,int toS,ClientReq *cq,int *rccp){
	int csi;
	int fsv;
	int rcc,wcc;
	IStr(buf,1024);
	refQStr(stoc,cq->c_stoc);
	refQStr(rp,cq->c_stoc);
	const char *proto = DST_PROTO;
	const char *host;
	IStr(addr,256);
	int port;

	if( eqSVL == 0 ){
		set_EQSV(Conn);
		if( eqSVL == 0 )
			return -1;
	}
RETRY:
	if( strcaseeq(proto,"http") ){
		int code = 0;
		sscanf(stoc,"HTTP/%*s %d",&code);
		if( code != 404 && code != 503 ){
			return 0;
		}
	}else
	if( strcaseeq(proto,"socks") ){
		if( stoc[0] == 5 )
			return 0;
		if( *rccp == 2 && stoc[0] == 1 && stoc[1] == 0 )
			return 0;
	}else
	if( strcaseeq(proto,"pop") ){
		if( stoc[0] == '+' )
			return 0;
	}else
	if( strcaseeq(proto,"ftp") ){
		if( stoc[0] == '2' )
			return 0;
	}else
	if( strcaseeq(proto,"nntp") ){
		if( stoc[0] == '2' )
			return 0;
	}else{
		return 0;
	}
	if( eqSVn <= eqSVx ){
		return -1;
	}
	host = 0;
	port = 0;
	clearVStr(addr);
	for(; eqSVx < eqSVn; eqSVx++ ){
		if( getHostInList(eqSVL,eqSVx,&host,AVStr(addr),&port) != 0 ){
			continue;
		}
		if( port == 0 )
			port = DFLT_PORT;
		if( hostcmp(host,DFLT_HOST)==0 && port == DFLT_PORT
		 || hostcmp(addr,DFLT_HOST)==0 && port == DFLT_PORT
		 || hostcmp(host,REAL_HOST)==0 && port == REAL_PORT
		 || hostcmp(addr,REAL_HOST)==0 && port == REAL_PORT
		){
			continue;
		}
		break;
	}
	if( eqSVn <= eqSVx ){
		return -1;
	}
	CLDBG("EQSV/%s app[%d] %s[%s]:%d\n",proto,eqSVx,host?host:"",addr,port);
	eqSVx++;

	eqSVinRetry++;
	set_realserver(Conn,proto,addr,port);
	if( strcaseeq(proto,"socks") ){
		fsv = client_open("EQSV",DST_PROTO,addr,port);
	}else{
		fsv = connect_to_serverX(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT,
			FromC,ToC,0);
	}
	eqSVinRetry--;
	if( fsv < 0 ){
		goto RETRY;
	}
	dup2(fsv,toS);
	close(fsv);

	if( strcaseeq(proto,"socks") ){
		for( csi = 0; csi < cq->c_csn; csi++ ){
			wcc = write(toS,cq->c_csv[csi],cq->c_csvlen[csi]);
			CLDBG("EQSV D-S: %d\n",cq->c_csvlen[csi]);
			rcc = read(toS,buf,sizeof(buf));
			CLDBG("EQSV S-D: %d [%X %X]\n",rcc,buf[0],buf[1]);
			if( 0 < rcc ){
				Bcopy(buf,stoc,rcc);
			}
		}
		*rccp = rcc;
		goto RETRY;
	}
	if( strcaseeq(proto,"http") ){
		wcc = write(toS,cq->c_csv[0],strlen(cq->c_csv[0]));
		PollIn(toS,10*1000);
		rcc = RecvLine(toS,buf,sizeof(buf)-1);
		strcpy(stoc,buf);
		CLDBG("EQSV/%s S-C: %s",proto,stoc);
		*rccp = rcc;
		goto RETRY;
	}

	rcc = RecvLine(toS,buf,sizeof(buf)-1);
	CLDBG("EQSV/%s S-C: %s",proto,buf);
	for( csi = 0; csi < cq->c_csn; csi++ ){
		wcc = write(toS,cq->c_csv[csi],strlen(cq->c_csv[csi]));
		CLDBG("EQSV D-S: %s",cq->c_csv[csi]);
		rp = stoc;
		rcc = RecvLine(toS,buf,sizeof(buf)-1);
		strcpy(rp,buf);
		rp += strlen(rp);
		while( 0 < PollIn(toS,1) ){
			rcc = RecvLine(toS,buf,sizeof(buf)-1);
			strcpy(rp,buf);
			rp += strlen(rp);
		}
		CLDBG("EQSV S-D: %s",stoc);
	}
	*rccp = strlen(stoc);
	goto RETRY;
}
typedef struct {
	int	ts_stat;
} ThStat;
static int eqsvThread(Connection *XConn,int sio0,int sio1,int toS){
	Connection ConnBuf,*Conn = &ConnBuf;
	int fdv[2],rdv[2],nready;
	int rcc,wcc;
	int sentauth = 0;
	IStr(ctosb,16*1024);
	refQStr(cbp,ctosb);
	refQStr(cbq,ctosb);
	int cbl = 0;
	ClientReq clntreq;
	refQStr(stoc,clntreq.c_stoc);
	int toSS;
	int brk = 0;
	const char *proto;
	ThStat thstat;

	*Conn = *XConn;
	wcc = write(sio0,&thstat,sizeof(thstat));
	proto = DST_PROTO;
	CLDBG("--eqsvThread[%s][%d %d %d] ToS=%d\n",proto,sio0,sio1,toS,ToS);
	toSS = ToS;
	fdv[0] = toS;
	fdv[1] = sio0;

	clntreq.c_csv[0] = cbp;
	clntreq.c_csv[1] = 0;
	clntreq.c_csn = 0;

	for(;;){
		nready = PollIns(0,2,fdv,rdv);
		if( nready <= 0 ){
			break;
		}
		if( 0 < rdv[0] ){
			if( strcaseeq(proto,"socks") ){
				rcc = read(fdv[0],clntreq.c_stoc,sizeof(clntreq.c_stoc));
				CLDBG("EQSV/%s S-C: %d [%d %d]\n",proto,
					rcc,stoc[0],stoc[1]);
				if( rcc <= 0 ){
					break;
				}
				brk = retryConn(Conn,toS,&clntreq,&rcc);

				wcc = write(fdv[1],stoc,rcc);
				if( brk ){
					break;
				}
				if( rcc == 2 && stoc[0] == 1 ){
					break;
				}
				continue;
			}
			rcc = RecvLine(fdv[0],(char*)clntreq.c_stoc,sizeof(clntreq.c_stoc)-1);
			if( rcc <= 0 ){
				break;
			}
			setVStrEnd(stoc,rcc);
			CLDBG("EQSV/%s S-D: %s",proto,stoc);
			brk = retryConn(Conn,toS,&clntreq,&rcc);
			rcc = strlen(stoc);
			wcc = write(fdv[1],stoc,rcc);
			CLDBG("EQSV/%s D-C: %s",proto,stoc);
			if( brk ){
				break;
			}
			if( wcc < rcc ){
				break;
			}
			if( strcaseeq(proto,"http")
			 || strcaseeq(proto,"nntp")
			){
				break;
			}
			if( sentauth ){
				CLDBG("EPSV/%s S-C: done/sentauth\n",proto);
				break;
			}
			if( cbp[0] ){
				cbp += strlen(cbp) + 1;
				clearVStr(cbp);
				clntreq.c_csn++;
				clntreq.c_csv[clntreq.c_csn] = cbp;
				clntreq.c_csv[clntreq.c_csn+1] = 0;
				clntreq.c_csvlen[clntreq.c_csn] = strlen(cbp);
				//csv[csn+1] = 0;
			}
		}
		if( 0 < rdv[1] ){
			if( strcaseeq(proto,"socks") ){
				cbq = cbp + cbl;
				rcc = read(fdv[1],(char*)cbq,sizeof(ctosb)-(cbq-ctosb));
				CLDBG("EQSV/%s C-S: %d [%d %d]\n",proto,
					rcc,cbq[0],cbq[1]);
				if( rcc <= 0 ){
					break;
				}
				clntreq.c_csv[clntreq.c_csn] = cbq;
				clntreq.c_csv[clntreq.c_csn+1] = 0;
				clntreq.c_csvlen[clntreq.c_csn] = rcc;

				clntreq.c_csn++;
				cbl += rcc;
				wcc = write(fdv[0],cbq,rcc);
				if( wcc < rcc ){
					break;
				}
				continue;
			}
			cbq = cbp + strlen(cbp);
			rcc = RecvLine(fdv[1],(char*)cbq,sizeof(ctosb)-(cbq-ctosb));
			if( rcc <= 0 ){
				break;
			}
			CLDBG("EQSV/%s C-S: %s",proto,cbq);
			if( strncaseeq(cbp,"PASS",4) ){
				if( strcaseeq(proto,"pop")
				 || strcaseeq(proto,"ftp")
				){
					sentauth = 1;
				}
			}
			wcc = write(fdv[0],cbq,rcc);
			if( wcc < rcc ){
				break;
			}
		}
	}
	CLDBG("EQSV/%s DONE [%d,%d,%d][%d,%d]\n",proto,toS,ToS,toSS,sio0,sio1);

	/* drain the data in the C-S / S-C socket buffers */
	{
		int eof = 0;
		CStr(buf,1024);
		int ri;
		for(; !eof;){
			nready = PollIns(100,2,fdv,rdv);
			if( nready <= 0 ){
				break;
			}
			for( ri = 0; ri < 2; ri++ ){
				if( rdv[ri] ){
					rcc = read(fdv[ri],buf,sizeof(buf));
					if( rcc <= 0 ){
						eof = 1;
						break;
					}
					wcc = write(fdv[(ri+1)%2],buf,rcc);
					CLDBG("EQSV/%s relayed[%d] %d/%d\n",
						proto,ri,wcc,rcc);
					if( wcc < rcc ){
						eof = 1;
						break;
					}
				}
			}
		}
	}
	if( inputReady(toSS,NULL) ){
		/* wait the data in the S-C socket buffer to be drained */
		int ri;
		for( ri = 0; ri < 10; ri ++ ){
			msleep(1+ri);
			if( inputReady(toSS,NULL) == 0 )
				break;
		}
	}

	dup2(toS,toSS);
	close(toS);
	close(sio0);
	close(sio1);
	withepsv = 0;
	eqSVL = 0;
	eqSVn = 0;
	eqSVx = 0;
	return 0;
}
static int _ClusterTid;
int WaitCluster(Connection *Conn){
	int terr;
	if( _ClusterTid ){
		terr = thread_wait(_ClusterTid,10*1000);
		CLDBG("--- WaitCluster tid=%X, err=%d\n",_ClusterTid,terr);
		if( terr == 0 ){
			_ClusterTid = 0;
		}
	}
	return 0;
}
int insert_CLUSTER(Connection *Conn,int sock){
	int sio[2];
	int toS;
	int tid;
	ThStat thstat;
	int rcc;

	if( withepsv ) return sock;
	if( lNOTHREAD() ) return sock;
	if( !INHERENT_thread() ) return sock;

	if( eqSVL == 0 ){
		set_EQSV(Conn);
		if( eqSVL == 0 )
			return sock;
	}
	if( eqSVn <= eqSVx ) return sock;

	if( !strcaseeq(DST_PROTO,"pop")
	 && !strcaseeq(DST_PROTO,"ftp")
	 && !strcaseeq(DST_PROTO,"http")
	 && !strcaseeq(DST_PROTO,"http-proxy")
	 && !strcaseeq(DST_PROTO,"nntp")
	 && !strcaseeq(DST_PROTO,"delegate")
	 && !strcaseeq(DST_PROTO,"socks")
	 && !strcaseeq(DST_PROTO,"ssltunnel")
	 && !strcaseeq(DST_PROTO,"tcprelay")
	){
		return sock;
	}

	Socketpair(sio);
	toS = dup(ToS);
	dup2(sio[1],ToS);

	tid = thread_fork(0x40000,STX_tid,"eqsvThread",(IFUNCP)eqsvThread,Conn,sio[0],sio[1],toS);
	_ClusterTid = tid;
	CLDBG("--EQSV/%s start [%d] %d %d %d %d (tid=%X)\n",
		DST_PROTO,sock,ToS,toS,sio[0],sio[1],tid);
	rcc = read(ToS,&thstat,sizeof(thstat));
	if( tid ){
		eqSVtid = tid;
		withepsv = 1;
		return sock;
	}
	close(sio[0]);
	close(sio[1]);
	dup2(toS,ToS);
	close(toS);
	return sock;
}


/*
 * SOCKOPT=buffsize:1024o+2048i:proto:dst:src
 */
static int nsb;
static scanListFunc setsb(PCStr(conf1),Connection *Conn,int sock,int clnt,int *cisz,int *cosz){
	const char *op;
	IStr(conf1b,128);
	int ib = 0, ob = 0, cl = 0, sv = 0, vz = 0;
	int isz = 0, osz = 0;
	int size = 0;

	size = atoi(conf1);
	for( op = conf1; *op; op++ ){
		switch( *op ){
			case 'k': size *= 1024; break;
			case 'i': ib = 1; break;
			case 'o': ob = 1; break;
			case 's': sv = 1; break;
			case 'c': cl = 1; break;
			case 'v': vz = 1; break; /* left variable size */
		}
	}
	if( clnt ){
		if( cl || cl == 0 && sv == 0 ){
			if( ib ) isz = size;
			if( ob ) osz = size;
			if( ib == 0 && ob == 0 ) isz = osz = size;
		}
	}else{
		if( sv || cl == 0 && sv == 0 ){
			if( ib ) isz = size;
			if( ob ) osz = size;
			if( ib == 0 && ob == 0 ) isz = osz = size;
		}
	}
	if( 0 < isz ){
		*cisz = isz;
		/* ClientFlags |= DontChangeBufSize; */
		/* ServerFlags |= DontChangeBufSize; */
	}
	if( 0 < osz ){
		*cosz = osz;
	}
	return 0;
}
int CTX_setSockBuf(FL_PAR,Connection *Conn,int sock,int clnt){
	int mi,mj;
	IStr(conf,128);
	int cisz = 0, cosz = 0;
	int oisz,oosz,nisz,nosz;

	if( nsb == 0 ){
		return 0;
	}
	for( mi = 0; ; mi++ ){
		mj = find_CMAPi(Conn,"SOCKBUFFSIZE",mi,AVStr(conf));
		if( mj < 0 ){
			break;
		}
		scan_List(conf,'+',0,scanListCall setsb,Conn,sock,clnt,
			&cisz,&cosz);
	}
	if( 0 < cisz || 0 < cosz ){
		getsockbuf(sock,&oisz,&oosz);
		setsockbuf(sock,cisz,cosz);
		getsockbuf(sock,&nisz,&nosz);
		sv1log("BUFFSIZE-%s[%d] %d/%d -> %d/%d (%d/%d) <= %s:%d\n",
			clnt?"CL":"SV",sock,oisz,oosz,nisz,nosz,cisz,cosz,
			FL_BAR);
		return 1;
	}
	return 0;
}

#if _MSC_VER
extern int SHUT_RD;
extern int SHUT_WR;
extern int SHUT_RDWR;
#endif
static int nss;
static scanListFunc shutfp(PCStr(conf1),Connection *Conn,FILE *fp,int clnt){
	int how = 0;
	const char *op;
	int sock;
	int rcode;
	double St = Time();

	if( fp == 0 ){
		return -1;
	}
	sock = fileno(fp);
	if( sock < 0 ){
		return -2;
	}
	for( op = conf1; *op; op++ ){
		switch( *op ){
			case 'i': how |= 1; break;
			case 'o': how |= 2; break;
			case 'g': how |= 4; break;
			case 'f': how |= 8; break;
			case 'n': how |= 0x10; break;
		}
	}
	if( how ){
		if( how == 0x10 ){
		}else{
			fflush(fp);
			if( how & 4 ){
				if( isWindows() )
					rcode = ShutdownSocket(sock);
				else	rcode = shutdown(sock,SHUT_WR);
			}else
			if( (how & 3) == 3 ){
				rcode = shutdown(sock,SHUT_RDWR);
			}else
			if( how & 1 ){
				rcode = shutdown(sock,SHUT_RD);
			}else
			if( how & 2 ){
				rcode = shutdown(sock,SHUT_WR);
			}
			sv1log("SHUTDOWN-%s[%d] %s %X = %d (%.3f)\n",
				clnt?"CL":"SV",sock,conf1,how,rcode,
				Time()-St);
			return how;
		}
	}
	return 0;
}
int CTX_doSockShutdown(FL_PAR,Connection *Conn,FILE *fp,int clnt){
	int mi,mj;
	IStr(conf,128);

	if( nss == 0 ){
		return 0;
	}
	for( mi = 0; ; mi++ ){
		mj = find_CMAPi(Conn,"SOCKSHUTDOWN",mi,AVStr(conf));
		if( mj < 0 ){
			break;
		}
		scan_List(conf,'+',0,scanListCall shutfp,Conn,fp,clnt);
	}
	return 0;
}

int CTX_setSockOpts(FL_PAR,Connection *Conn,int sock,int clnt){
	CTX_setSockBuf(FL_BAR,Conn,sock,clnt);
	return 0;
}
int CTX_defSockOpts(Connection *Conn,PCStr(name),PCStr(spec),int neg){
	IStr(map,1024);

	sprintf(map,"%s",spec);
	if( streq(name,"buffsize") ){
		nsb++;
		scan_CMAP2(Conn,"SOCKBUFFSIZE",map);
	}else
	if( streq(name,"shutdown") ){
		nss++;
		scan_CMAP2(Conn,"SOCKSHUTDOWN",map);
	}else
	if( streq(name,"linger") ){
		scan_CMAP2(Conn,"SOCKLINGER",map);
	}else
	if( streq(name,"keepalive") ){
		scan_CMAP2(Conn,"SOCKKEEPALIVE",map);
	}else{
		return -1;
	}
	return 0;
}
