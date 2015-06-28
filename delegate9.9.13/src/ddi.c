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
Program:	ddi.c (DeleGate to DeleGate interface)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950218	extracted from conf.c and service.c
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "ystring.h"
#include "fpoll.h"
#include "file.h"
#include "proc.h"
#include "auth.h"
#include "url.h"
#include "param.h"
#define PEEKSIZE 0x2000

int DDI_readyCbuf(Connection *Conn);

int fPollInSX(FILE *fp,int timeout){
	int rem,to1,nready;

	if( timeout <= 0 )
		return fPollIn(fp,timeout);
	nready = 0;
	for( rem = timeout; 0 < rem; rem -= to1 ){
		if( !procIsAlive(serverPid()) ){
			porting_dbg("fPollInSX() server [%d] dead",serverPid());
			if( lMULTIST() ){
				sv1log("##IGN server death th=%d/%d\n",
					actthreads(),numthreads());
			}else
			break;
		}
		if( rem <= 1000 )
			to1 = rem;
		else	to1 = 1000;
		if( nready = fPollIn(fp,to1) ){
			break;	
		}
	}
	return nready;
}

int DDI_PollIn(Connection *Conn,FILE *fc,int timeout)
{	int nready;

	if( DDI_readyCbuf(Conn) )
		nready = 1;
	else	nready = fPollInSX(fc,timeout);
	/*
	else	nready = fPollIn(fc,timeout);
	*/
	return nready;
}

void DDI_clearCbuf(Connection *Conn)
{
if( FromCpeak != FromCfill )
sv1log("#### CLEAR CBUF: %d %d\n",FromCpeak,FromCfill);

	/* to be reused, restored by ConnInit()
	if( FromCbuff != NULL ){
		free(FromCbuff);
		FromCbuff = NULL;
	}
	*/
	FromCpeak = 0;
	FromCfill = 0;
	FromCread = 0;
}

void DDI_pushCbuf(Connection *Conn,PCStr(req),int len)
{
	if( FromCbuff != NULL && len+1 < FromCsize ){
	}else{
		int size;
		if( FromCbuff ){
			free(FromCbuff);
		}
		size = ((len+1024)/1024)*1024;
		FromCbuff = (char*)malloc(size);
		FromCsize = size;
	}
	FromCfill = len;
	/*
	if( FromCbuff != NULL ){
		FromCbuff = (char*)realloc(FromCbuff,len+1);
	}else	FromCbuff = (char*)malloc(len+1);
	*/
	bcopy(req,FromCbuff,len); FromCbuff[len] = 0; /**/
	FromCpeak = 0;
}
int DDI_peekCbuf(Connection *Conn,PVStr(buf),int siz){
	if( FromCbuff != NULL && FromCpeak < FromCfill ){
		int rcc;
		rcc = FromCfill - FromCpeak;
		if( siz < rcc )
			rcc = siz;
		strncpy(buf,&FromCbuff[FromCpeak],rcc);
		return rcc;
	}
	return 0;
}
char *DDI_fgetsFromCbuf(Connection *Conn,PVStr(str),int size,FILE *fp)
{	char ch;
	int dx;

	if( size == 0 )
		return NULL;
	if( size == 1 ){
		setVStrEnd(str,0);
		return (char*)str;
	}

	dx = 0;
	if( FromCbuff && FromCpeak < FromCfill ){
		while( FromCpeak < FromCfill ){
			if( size-1 <= dx ){
sv1log("#### DDI_fgetsFromCbuf: over flow! %d / %d\n",dx,size);
				AbortLog();
				break;
			}
			ch = FromCbuff[FromCpeak++];
			setVStrElemInc(str,dx,ch); /**/
			if( ch == '\n' )
				break;
		}
		setVStrEnd(str,dx); /**/
		if( FromCpeak == FromCfill ){
			/* don't DDI_proceedFromC(Conn) for Solaris... */
		}
		return (char*)str;
	}
	return NULL;
}
int DDI_readyCbuf(Connection *Conn)
{
	return FromCbuff && FromCpeak < FromCfill;
}

int DDI_flushCbuf(Connection *Conn,PVStr(bbuff),int bsize,FILE *fc)
{	int bn;

	bn = 0;
	while( 0 < DDI_readyCbuf(Conn) ){
		if( DDI_fgetsFromCbuf(Conn,QVStr(bbuff+bn,bbuff),bsize-bn,fc) == NULL )
			break;
		bn += strlen(bbuff+bn);
	}
	return bn;
}

int DDI_proceedFromC(Connection *Conn,FILE *fp)
{	CStr(buff,PEEKSIZE);
	int len,rrc,rcc;
	int rcode = 0;

	if( 0 < FromCread ){
		len = FromCpeak;
		rrc = 0;
		while( 0 < len && 0 < ready_cc(fp) ){
			if( getc(fp) == EOF )
				break;
			len--;
			rrc++;
		}
		rcc = reads(fileno(fp),AVStr(buff),len);

		sv1log("-- discard %d+%d = %d /%d/%d Bytes of peeked request\n",
			rrc,rcc,FromCpeak,FromCfill,FromCread);

		if( rrc+rcc != FromCpeak ){
			sv1log("#### discard failed: %d + %d / %d\n",
				rrc,rcc,FromCpeak);
			rcode = -1;
		}
		DDI_clearCbuf(Conn);
	}
	return rcode;
}

int DDI_peekcFromC(Connection *Conn,FILE *fp)
{	int ch;

	if( FromCbuff && FromCpeak < FromCfill )
		return  FromCbuff[FromCpeak];

	if( PEEK_CLIENT_REQUEST )
		DDI_proceedFromC(Conn,fp);

	ch = getc(fp);
	if( ch != EOF ){
		CStr(buff,1);
		buff[0] = ch;
		DDI_pushCbuf(Conn,buff,1);
	}
	return ch;
}
char *DDI_fgetsFromC(Connection *Conn,PVStr(req),int size,FILE *fp)
{	const char *rcode;
	int len;
	CStr(buff,PEEKSIZE+1);
	int cc;

	if( size <= 0 ){
		sv1log("#### Negative size for DDI_fgetsFromC(%x,%d)\n",
			p2i(req),size);
		AbortLog();
		abort();
	}

	rcode = DDI_fgetsFromCbuf(Conn,AVStr(req),size,fp);
	if( rcode != NULL ){
		if( strchr(req,'\n') != NULL )
			return (char*)rcode;
		else{
			len = strlen(req);
			return DDI_fgetsFromC(Conn,QVStr(req+len,req),size-len,fp);
		}
	}

	cc = 0;
	if( ready_cc(fp) <= 0 )
	if( PEEK_CLIENT_REQUEST ){
		DDI_proceedFromC(Conn,fp);
		buff[0] = 0; /* a charm against Solaris2.X CC -O bug? */
		cc = recvPeekTIMEOUT(fileno(fp),AVStr(buff),sizeof(buff)-1);

		if( 0 < cc ){
			FromCread = cc;
			Verbose("++ peek %d Bytes of request.\n",cc);
		}
	}
/*
else
 if( 0 < PollIn(fileno(fp),2000) ){
	setNonblockingIO(fileno(fp),1);
	cc = readTIMEOUT(fileno(fp),buff,sizeof(buff)-1);
	setNonblockingIO(fileno(fp),0);
 }
*/
/* switching NonBlocking seems halmful... e.g. http://www.opentext.com */

	if( 0 < cc ){
		setVStrEnd(buff,cc);
		DDI_pushCbuf(Conn,buff,cc);
		return DDI_fgetsFromC(Conn,AVStr(req),size,fp);
	}

	rcode = fgetsTIMEOUT(AVStr(req),size,fp);
	if( rcode == NULL )
		return NULL;
	else	return (char*)rcode;
}

const char *CCV_TOCL = "tocl";
const char *CCV_TOSV = "tosv";
extern int CodeConv_x;
void CCV_clear(){ CodeConv_x = 0; }

void getGlobalCCX(CCXP ccx,int siz);
void reset_filters();
int MarkNewConn(FL_PAR,Connection *Conn){
	Conn->cx_magic = 0;
	return 0;
}
void ConnInit(Connection *Conn)
{
	SessionThread st = Conn->dg_sthread;
	VAddr rident;
	int restore = 0;
	int cff = 0;
	int magic;
	/*
	magic = ((int)&Conn) ^ ((int)&ConnInit);
	*/
	magic = 0x12345678 ^ sizeof(Connection);
	if( Conn->cx_magic == magic ){
		if( Conn->cx_pid != serverPid() && Conn->cx_pid != Getpid() ){
			/* 9.9.5 could be debris in a memory of another process ? */
			daemonlog("E","ConnInit non-unique magic %d %d %d\n",
				Getpid(),Conn->cx_pid,serverPid());
		}
		restore = 1;
		cff = ConfigFlags;
		rident = *Rident_VAddr;
	if( Conn->xf_mounted )
		reset_filters();
	}
	bzero((char*)Conn,sizeof(Connection));
	Conn->cx_magic = magic;
	Conn->cx_pid = Getpid();
	if( restore ){
		Conn->dg_sthread = st;
		*Rident_VAddr = rident;
	}
	ConfigFlags = cff;
	ClientSock = -1;
	ClientSockX = -1;
	ServerSock = -1;
	ServerSockX = -1;
	ToSF = -1;
	ToS = ToSX = FromS = FromSX = -1;
	Conn->sv.p_SOCKSCTL = -1;
	ToC = -1;
	ToCX = FromCX = -1;
	RPORTsock = -1;
	getGlobalCCX(CCX_TOCL,CCX_SIZE);

	if( strcmp(iSERVER_PROTO,"tunnel1") == 0 )
		Conn->from_myself = 1;

/*
fprintf(stderr,"---- [%d] saved my_Rusage-Q\n",getpid());
	strfRusage(AVStr(Conn->my_Rusage),"%B",3,NULL);
*/
}
static int clearRequestFlags(Connection *Conn,FL_PAR){
	RequestFlags = 0;
	return 0;
}


void clear_DGreq(Connection *Conn);
void clear_DGheader(Connection *Conn);
void clear_DGinputs(Connection *Conn);

void ConnCopy(Connection *Conn,Connection *OrigConn)
{
	*Conn = *OrigConn;
	FromCbuff = NULL;
	headerX = 0;
	inputsX = 0;
	/*
	UTfree(&D_REQUESTtag);
	*/
if( D_REQUESTtag.ut_addr )
sv1log("#### ConnCopy: clearing D_REQUEST<%d> %d %X\n",
D_REQUESTtag.ut_strg,D_REQUESTtag.ut_size,p2i(D_REQUESTtag.ut_addr));
	UTclear(&D_REQUESTtag);
	LockedByClient = 0;
	clear_DGreq(Conn);
}

void strClear(PVStr(buf),int size){
	int bi;
	for( bi = 0; bi < size; bi++ ){
		if( buf[bi] == 0 )
			break;
		setVStrEnd(buf,bi);
	}
}
void clearAuthInfo(AuthInfo *auth){
	strClear(AVStr(auth->i_user),sizeof(auth->i_user));
	strClear(AVStr(auth->i_pass),sizeof(auth->i_pass));
	auth->i_stat = 0;
	auth->i_user[0] = 0;
	auth->i_pass[0] = 0;
}

/*
 *	environment per client's connection
 */
void clear_DGconn(Connection *Conn)
{
	CLIF_HOSTPORT[0] = 0;
	CLIF_HOST[0]   = 0;
	CLIF_PORT      = 0;

	D_SERVER[0]    = 0;
	D_SELECTOR[0]  = 0;
	D_USER[0]      = 0;
	D_FROM[0]      = 0;
	D_PATH[0]      = 0;

	clear_DGreq(Conn);
	if( lSINGLEP() ){
		/* DON'T CLEAR THREADS OF OTHER PARALLEL SESSIONS !! */
	}else
	clearthreadsix();
}
/*
 *	environment per request
 */
void clearThreadSig();
void clear_DGreq(Connection *Conn)
{
	extern int MasterXi;
	extern int MasterXo;
	MasterXi = 0;
	MasterXo = 0;

	clearThreadSig();
	DDI_clearCbuf(Conn);
	if( headerX ) clear_DGheader(Conn);
	if( inputsX ) clear_DGinputs(Conn);
	InCharset[0] = 0;
	InLang[0] = 0;
	CCV_clear();
	reset_MOUNTconds();
	if( Conn->xf_mounted ){
		Conn->xf_mounted = 0;
		reset_filters();
	}
	clearAuthInfo(&Conn->sv_certauth);
	/*
	Conn->sv_certauth.i_user[0] = 0;
	*/
	MO_Authorizer[0] = 0;
	mo_COUNTER = 0;
	GEN_VHOST[0]   = 0;
	addRespHeaders[0] = 0;

	MODIFIERS[0]   = 0;
	D_GTYPE[0]     = 0;
	D_HOPS         = 0;
	IAM_GATEWAY    = 0;

	DO_DELEGATE    = 0;
	IsMounted      = 0;
	IsVhost        = 0;

	CacheFlags     = 0;
	ServerFlags    = 0;
	clearRequestFlags(Conn,FL_ARG);
	Conn->statcode = 0;
	ProxyControls[0] = 0;
	Conn->dg_putpart[0] = 0;
	ClientSession[0] = 0;
	Conn->xf_reqrecv = 0;

	Conn->cl.p_range[0] = 0;
	Conn->cl.p_range[1] = 0;
	Conn->sv.p_range[0] = 0;
	Conn->sv.p_range[1] = 0;
	Conn->sv.p_range[2] = 0;
	Conn->sv.p_range[3] = 0;
	Conn->sv_retry = 0;
}
void clear_DGserv(Connection *Conn){
	ServerSock = -1;
	ServerSockX = -1;
	ToS = ToSX = ToSF = FromS = -1;
	ServerFlags = 0;
	clearRequestFlags(Conn,FL_ARG);
}
void clear_DGclnt(Connection *Conn)
{
	ClientSock = -1;
	ClientSockX = -1;
	clear_DGreq(Conn);
}
/*
 *	constant through keep-alive
 */
void restoreConn(Connection *dst,Connection *src)
{
	Connection *Conn = dst;

	dst->sv_dflt        = src->sv_dflt;
	dst->sv             = src->sv;

	dst->cl.p_connFname[0] = 0;
	dst->cl.p_wantKeepAlive = src->cl.p_wantKeepAlive;
	dst->cl.p_willKeepAlive = src->cl.p_willKeepAlive;
	dst->cl.p_whyclosed[0] = '-';
	dst->cl_nocache     = src->cl_nocache;
	dst->cl_reqbuf      = NULL;
	dst->cl_setccx      = 0;

	dst->ca_dontread    = src->ca_dontread;
	dst->ca_dontwrite   = src->ca_dontwrite;
	dst->ca_curoff      = 0;
	dst->ca_mtime       = 0;

	dst->co_setup       = 0;
	dst->co_nonet       = src->co_nonet;
	dst->co_nointernal  = src->co_nointernal;
	dst->fi_builtin     = 0;

	if( dst->xf_filters ){
		int pid;
		while( 0 < (pid = NoHangWait()) ){
			sv1log("CFI process [%d] done\n",pid);
		}
	}
	dst->xf_filters     = src->xf_filters;
	dst->xf_filtersCFI  = 0;
	dst->xf_clprocs     = 0;

	/* these lines could be unnecessary since sv.* would be reset as a whole ... */
	dst->sv.p_viaCc     = 0;
	dst->sv.p_viaSocks  = 0;
	dst->sv.p_viaVSAP   = 0;
	dst->sv.p_connType  = 0;

	dst->oc_proxy[0]    = 0;
	dst->oc_norewrite   = src->oc_norewrite; /* DONT_REWRITE */
	dst->co_internal    = 0;
	dst->mo_options     = 0;
	dst->mo_optionsX    = 0;
	dst->mo_flags       = 0;
	clearRequestFlags(dst,FL_ARG);

	dst->cl_noauth      = 0;

	if( (ClientFlags & PF_MITM_ON)
	 && (ClientAuth.i_stat == AUTH_SET)
	 && (ClientAuth.i_stype == AUTH_APROXY) ){
		/* reuse ClientAuth in Keep-Alive in MITM */
	}else{
	clearAuthInfo(&dst->cl_auth);
	}
	/*
	dst->cl_auth.i_user[0] = 0;
	*/
	dst->no_dstcheck_proto = 0;
	dst->from_myself    = 0;
	dst->from_client    = 0;
	if( src->gw_flags & GW_FROM_MYSELF ){
		dst->from_myself = src->from_myself;
	}

	if( strcmp(iSERVER_PROTO,"tunnel1") == 0 )
		dst->from_myself = 1;

	/*
	CCXclear(dst->cl.p_ccxbuf);
	*/
	bcopy(src->cl.p_ccxbuf,dst->cl.p_ccxbuf,sizeof(dst->cl.p_ccxbuf));
	CCXclear((CCXP)dst->sv.p_ccxbuf);

	if( dst->my_vbase.u_proto != src->my_vbase.u_proto ){
		dst->my_vbase = src->my_vbase;
	}
	strcpy(dst->cl_baseurl,src->cl_baseurl);
	strcpy(dst->ma_SERVER,src->ma_SERVER); /* D_SERVER */

	truncVStr(dst->cl_reqmethod);
	dst->cl_reqlength = 0;

/*
fprintf(stderr,"---- [%d] saved my_Rusage-R\n",getpid());
	strfRusage(AVStr(dst->my_Rusage),"%B",3,NULL);
*/
}

const char *add_DGheader(Connection *Conn,PCStr(head),PCStr(fmt),...)
{
	const char *cbuf;
	CStr(line,0x4000);
	MemFile MemF;
	VARGS(8,fmt);

#define PrintBuf(buf) { \
	sprintf(line,fmt,VA8); \
	FStrncpy(buf,line); \
	cbuf = buf; \
 }
	if( head == D_SERVER ){ PrintBuf(D_SERVER); }else
	if( head == D_FROM   ){ PrintBuf(D_FROM  ); }else
	if( head == D_USER   ){ PrintBuf(D_USER  ); }else
	if( head == D_PATH   ){ PrintBuf(D_PATH  ); }else
	if( head == D_EXPIRE ){ PrintBuf(D_EXPIRE); }else
	{
		str_sopen(&MemF,"add_DGheader",line,sizeof(line),0,"w");
		str_sprintf(&MemF,"%s ",head);
		str_sprintf(&MemF,fmt,VA8);
		str_sprintf(&MemF,"\r\n");
		cbuf = stralloc(line);

		if( headerX == DG_MAXHEAD-1 ){
			int i;
			for( i = 0; i < headerX; i++ )
			sv1log("#### generalist header overflow? %s",headerB[i]);
			sv1log("#### generalist header overflow? %s",cbuf);
		}
		if( headerX < DG_MAXHEAD )
			headerB[headerX++] = (char*)cbuf;
		else	sv1log("#### generalist header overflow: %s",cbuf);
	}
	return cbuf;
}
void clear_DGheader(Connection *Conn)
{	int hi;

	if( headerX ){
		for( hi = 0; hi < headerX; hi++ ){
			free((char*)headerB[hi]);
			headerB[hi] = 0;
		}
		headerX = 0;
	}
}
void clear_DGinputs(Connection *Conn)
{	int hi;

	if( inputsX ){
		for( hi = 0; hi < inputsX; hi++ )
		{
			free((char*)inputsB[hi]);
			inputsB[hi] = 0;
		}
		inputsX = 0;
	}
}

char *fgets_DGclient(Connection *Conn,PVStr(str),int size,FILE *fp)
{	const char *rcode;

	if( rcode = fgets(str,size,fp) )
		inputsB[inputsX++] = stralloc(str);
	return (char*)rcode;
}
void add_DGinputs(Connection *Conn,PCStr(fmt),...)
{	CStr(line,4096);
	MemFile MemF;
	VARGS(7,fmt);

	str_sopen(&MemF,"add_DGinputs",line,sizeof(line),0,"w");
	str_sprintf(&MemF,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6]);
	Verbose("**** add_input: %s",line);
	inputsB[inputsX++] = stralloc(line);
}


/*
 *	Transfer the local SPECIALIST's environment to the remote GENERALIST
 *	to act as a SPECIALIST for the local one.
 */
void add_localheader(Connection *Conn,int proxy)
{	CStr(codeconv,128);

	if( proxy )
		add_DGheader(Conn,"LOCAL-PROXY","%d",1);

	if( !proxy ){
		CStr(myhp,1024);

		ClientIF_HP(Conn,AVStr(myhp));
		add_DGheader(Conn,"LOCAL-DELEGATE","%s",myhp);
	}
	if( DELEGATE_FLAGS[0] )
		add_DGheader(Conn,"LOCAL-FLAGS",   "%s",DELEGATE_FLAGS);

	/* why is this necessary? Gopher-Specialist DeleGate? */
	if( CTX_cur_codeconvCL(Conn,AVStr(codeconv)) )
		add_DGheader(Conn,"LOCAL-CHARCODE", "%s",codeconv);
}
void del_DGlocalheader(Connection *Conn)
{
	clear_DGheader(Conn);
}
void CTX_set_clientgtype(Connection *Conn,int gtype)
{
	D_GTYPE[0] = gtype;
}
int CTX_get_clientgtype(Connection *Conn)
{
	return D_GTYPE[0];
}

void setProtoOfClient(Connection *Conn,PCStr(proto))
{
	strcpy(CLIENTS_PROTO,proto);
}
void setProxyOfClient(Connection *Conn,int proxy_client,PCStr(url))
{
	if( proxy_client ){
		scan_URI_scheme(url,AVStr(CLIENTS_PROTO),sizeof(CLIENTS_PROTO));
		strcpy(CLIENTS_PROXY,MY_HOSTPORT());
	}else{
		ClientIF_HP(Conn,AVStr(CLIENTS_PROXY));
	}
}
const char *isSetProxyOfClient(Connection *Conn,PVStr(cl_proto))
{
	if( CLIENTS_PROXY[0] ){
		strcpy(cl_proto,CLIENTS_PROTO);
		return CLIENTS_PROXY;
	}else	return 0;
}
double CTX_setIoTimeout(Connection *Conn,double tosec){
	double ot;
	ot = Conn->io_timeout;
	Conn->io_timeout = tosec;
	return ot;
}
int CTX_getGatewayFlags(Connection *Conn){
	return GatewayFlags;
}
int CTX_setGatewayFlags(Connection *Conn,int flags){
	return GatewayFlags = flags;
}
int CTX_addGatewayFlags(Connection *Conn,int flags){
	return GatewayFlags |= flags;
}
int CTX_getConnType(Connection *Conn){
	return ConnType;
}

void DG_relayInput(Connection *Conn,int fd);
void initConnected(Connection *Conn,int svsock,int relay_input)
{
	if( relay_input ){
		DG_relayInput(Conn,svsock);
	}
	set_keepalive(svsock,1);
	FromS = ToS = svsock;
	ServerSock = svsock;
	ServerSockX = svsock;
}

int ConnectToServer(Connection *Conn,int relay_input)
{	int svsock;

	CONNERR_CANTRESOLV = 0;
	CONNERR_TIMEOUT = 0;
	CONNERR_REFUSED = 0;
	CONNERR_UNREACH = 0;

	/* log for debug when REAL differs from DFLT ... */
	if( strcmp(DFLT_PROTO,REAL_PROTO)
	 || DFLT_PORT != REAL_PORT
	 || hostcmp(DFLT_HOST,REAL_HOST) != 0 )
	sv1log("ConnectToServer: DFLT=%s://%s:%d REAL=%s://%s:%d\n",
		DFLT_PROTO,DFLT_HOST,DFLT_PORT, REAL_PROTO,REAL_HOST,REAL_PORT);

	if( ServerFlags & PF_UDP ){
		svsock = UDP_client_open("ConnectToServer",DST_PROTO,DST_HOST,DST_PORT);
	}else
	svsock = OpenServer("ConnectToServer",DST_PROTO,DST_HOST,DST_PORT);

	if( 0 <= svsock ){
		initConnected(Conn,svsock,relay_input);
		return svsock;
	}

	if( CONNERR_CANTRESOLV ) ConnError |= CO_CANTRESOLV;
	if( CONNERR_TIMEOUT    ) ConnError |= CO_TIMEOUT;
	if( CONNERR_REFUSED    ) ConnError |= CO_REFUSED;
	if( CONNERR_UNREACH    ) ConnError |= CO_UNREACH;
	return -1;
}
int CTX_CantResolv(Connection *Conn){
	return ConnError & CO_CANTRESOLV;
}
void DG_relayInput(Connection *Conn,int fd)
{	int hi;

	if( inputsX ){
		for( hi = 0; hi < inputsX; hi++ )
			IGNRETP write(fd,inputsB[hi],strlen(inputsB[hi]));
	}
}

const char *CTX_add_PATH(Connection *Conn,PCStr(me),PCStr(hostport),PCStr(teleport))
{	CStr(path,4096);
	refQStr(pp,path); /**/

	strcpy(path,me);
	pp = path+strlen(path);

	if( D_PATH[0] == 0 ){
		setVStrPtrInc(pp,'!');
		strcpy(pp,hostport);
		pp += strlen(pp);
	}

	if( teleport[0] ){
		setVStrPtrInc(pp,'[');
		strcpy(pp,teleport);
		pp += strlen(pp);
		setVStrPtrInc(pp,']');
	}

	setVStrPtrInc(pp,'!');
	if( D_PATH[0] ) /* D_PATH given from client DeleGate */
		strcpy(pp,D_PATH);
	else	sprintf(pp,"%s;%d",D_USER,itime(0));

	strcpy(D_PATH,path);
	return D_PATH;
}
const char *CTX_get_PATH(Connection *Conn)
{
	return D_PATH;
}

static scanListFunc findPath1(PCStr(path1),PCStr(hostport))
{
	if( strcmp(path1,hostport) == 0 )
		return 1;
	return 0;
}
int CTX_findInPath(Connection *Conn,PCStr(host),int port)
{	const char *path;
	CStr(hostport,MaxHostNameLen);

	path = CTX_get_PATH(Conn);
	sprintf(hostport,"%s:%d",host,port);
	return scan_List(path,'!',0,scanListCall findPath1,hostport);
}

static scanListFunc match1(PCStr(path1),PCStr(user),int hlid)
{	CStr(host,1024);
	int port;

	if( Xsscanf(path1,"%[^:]:%d",AVStr(host),&port) == 2 )
	if( matchPath1(hlid,user,host,port) )
		return 1;
	return 0;
}
int CTX_matchPATH1(Connection *Conn,int hlid,PCStr(path),PCStr(user))
{
	if( path == NULL )
		path = D_PATH;
	return scan_List(path,'!',0,scanListCall match1,user,hlid);
}
static scanListFunc matchs(PCStr(path1),int hlid)
{	CStr(host,1024);
	int port;

	if( Xsscanf(path1,"%[^:]:%d",AVStr(host),&port) == 2 )
	if( matchPath1(hlid,"-",host,port) == 0 )
		return 1;
	return 0;
}
int CTX_matchPATHs(Connection *Conn,int hlid,PCStr(path))
{
	if( path == NULL )
		path = D_PATH;
	return scan_List(path,'!',0,scanListCall matchs,hlid) == 0;
}

void setFROM(Connection *Conn,PCStr(username),PCStr(hostaddr),int port)
{
	sprintf(D_FROM,"%s@[%s] (port=%d; DeleGate%s)",
		username,hostaddr,port,DELEGATE_ver());
}
int getFROM(Connection *Conn,PVStr(username),PVStr(hostaddr),PVStr(ver))
{	int port;

	setVStrEnd(hostaddr,0);
	setVStrEnd(username,0);
	Xsscanf(D_FROM,"%[^@]@[%[^]]] (port=%d; DeleGate%s)",AVStr(username),AVStr(hostaddr),&port,AVStr(ver));
	return port;
}

int matchAUTH(Connection *Conn,int hlid)
{
	if( ClientAuthUser[0] )
	if( matchPath1(hlid,ClientAuthUser,ClientAuthHost,ClientAuthPort) ){
		return 1;
	}
	return 0;
}
int matchFROM(Connection *Conn,int hlid)
{	CStr(user,256);
	CStr(host,MaxHostNameLen);
	CStr(ver,256);
	int port;

	if( port = getFROM(Conn,AVStr(user),AVStr(host),AVStr(ver)) )
		return matchPath1(hlid,user,host,port);
	return 0;
}

int CTX_VA_getOriginatorAddr(Connection *Conn,VAddr *Vaddr)
{	CStr(tmp,1024);
	CStr(ohost,MaxHostNameLen);
	const char *dp;
	int oport;

	strcpy(tmp,D_PATH);

	bzero(Vaddr,sizeof(VAddr));
	if( dp = strrchr(tmp,'!') ){
		truncVStr(dp);
		if( dp = strrchr(tmp,'!') ){
			if( Xsscanf(dp+1,"%[^:]:%d",AVStr(ohost),&oport) == 2 ){
				wordscanX(ohost,AVStr(Vaddr->a_name),sizeof(Vaddr->a_name));
				Vaddr->a_port = oport;
				return oport;
			}
		}
	}
	return 0;
}

void scan_header(Connection *Conn,int fromC,PCStr(name),PCStr(value))
{
	if( streq(name,"MEDIATOR") ){
		D_HOPS++;
		add_DGheader(Conn,name,"%s",value);
	}else
	if( streq(name,"FTPHOPS")){D_FTPHOPS = atoi(value); }else
	if( streq(name,"FROM")   ){add_DGheader(Conn,D_FROM,"%s",value); }else
	if( streq(name,"PATH")   ){add_DGheader(Conn,D_PATH,"%s",value); }else
	if( streq(name,"EXPIRE") ){add_DGheader(Conn,D_EXPIRE,"%s",value); }else
	if( streq(name,"LOCAL-GTYPE") ){
		sv1log("LOCAL-GTYPE: %s\n",value);
		CTX_set_clientgtype(Conn,*value);
	}else
	if( streq(name,"USER") ){
		CStr(user,256);
		wordScan(value,user);
		CLNT_USER = stralloc(user);
		add_DGheader(Conn,D_USER,"%s",user);
	}else
	if( streq(name,"CALLER") ){
		CStr(user,256);
		Xsscanf(value,"CALLER %s %s %d",AVStr(user),AVStr(CLNT_HOST),&CLNT_PORT);
		CLNT_USER = stralloc(user);
		add_DGheader(Conn,name,"%s",value);
	}else
	if( streq(name,"HOSTS") ){
		scan_HOSTS(Conn,value);
	}else
	{
		add_DGheader(Conn,name,"%s",value);
	}
}

/**/
void setREQUEST(Connection *Conn,PCStr(req))
{
	int len,size;
	len = strlen(req);
	size = ((len+1024)/1024)*1024; /* to be reusable, non fragmented */
	if( D_REQUESTtag.ut_addr && len+1 <= D_REQUESTtag.ut_size ){
	}else{
	UTfree(&D_REQUESTtag);
		if( lSINGLEP() ){
			/* it must be persistent to be pointed from
			 * the D_REQUESTtag as persistent STX_QUt
			 */
			D_REQUESTtag = UTalloc(SB_PROC,size,1);
		}else{
	D_REQUESTtag = UTalloc(SB_CONN,size,1);
		}
	/*
	D_REQUESTtag = UTalloc(SB_CONN,strlen(req)+1,1);
	*/
	}
	linescanX(req,AVStr(D_REQUESTtag.ut_addr),D_REQUESTtag.ut_size);
}

int CTX_rootdir(Connection *Conn,PVStr(rootdir)){
	strcpy(rootdir,DELEGATE_DGROOT);
	return 0;
}
int CTX_getodstAddrName(Connection *Conn,PVStr(odaddr),PVStr(odname)){
	int port;
	int init = 0;

	if( 0 ){
		strcpy(odaddr,"1.2.3.4");
		return 1234;
	}

	if( AddrEQ((*Origdst_VAddr),AddrZero) ){
		VA_getodstNAME(ClientSock,Origdst_VAddr);
		if( Origdst_VAddr->a_port == 0 ){
			sv1log("[%d] odst=? Cannot Get SO_ORIGINAL_DST\n",
				ClientSock);
		}
		init = 1;
	}
	if( !AddrInvalid(*Origdst_VAddr) ){
		VA_inetNtoah(Origdst_VAddr,BVStr(odaddr));
		port = Origdst_VAddr->a_port;
		strcpy(odname,Origdst_VAddr->a_name);
		if( init ){
			sv1log("[%d] odst=%s:%d\n",ClientSock,odaddr,port);
		}
		return port;
	}
	return 0;
}
int CTX_getodstAddr(Connection *Conn,PVStr(odaddr)){
	IStr(odname,MaxHostNameLen);
	return CTX_getodstAddrName(Conn,BVStr(odaddr),AVStr(odname));
}

extern int CHILD_SERNO_MULTI;
int CTX_RequestSerno(Connection *Conn){
	return (CHILD_SERNO_MULTI << 16) | RequestSerno;
}
int CTX_withSSL(Connection *Conn){
	return ClientFlags & PF_SSL_ON;
}
int CTX_asproxy(Connection *Conn){
	return ClientFlags & PF_AS_PROXY;
}
const char *CTX_dst_proto(Connection *Conn)
{
	return DST_PROTO;
}
const char *CTX_clif_proto(Connection *Conn)
{
	return DFLT_PROTO[0] ? DFLT_PROTO : iSERVER_PROTO;
}
const char *CTX_CLNT_PROTO(Connection *Conn)
{
	return CLNT_PROTO;
}
const char *CTX_clif_host(Connection *Conn)
{
	return CLIF_HOST;
}
int CTX_clif_port(Connection *Conn)
{
	return CLIF_PORT;
}
const char *CTX_clif_hostport(Connection *Conn)
{
	return CLIF_HOSTPORT;
}
const char *CTX_get_modifires(Connection *Conn)
{
	return MODIFIERS;
}
void CTX_set_modifires(Connection *Conn,PCStr(modifires))
{
	strcpy(MODIFIERS,modifires);
}
const char *CTX_get_baseurl(Connection *Conn)
{
	if( Conn->cl_baseurl[0] )
		return Conn->cl_baseurl;
	else	return 0;
}
int CTX_get_iserver(Connection *Conn,const char **proto,const char **host)
{
	*proto = iSERVER_PROTO;
	*host = iSERVER_HOST;
	return iSERVER_PORT;
}
void set_BASEURL(Connection *Conn,PCStr(url))
{	CStr(proto,128);
	CStr(site,128);
	CStr(path,1024);
	CStr(host,128);
	CStr(sport,128);
	CStr(hp,128);
	int port;

	strcpy(Conn->cl_baseurl,url);
	Verbose("BASEURL=%s\n",url);
	if( isFullURL(url) ){
		decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(path),sizeof(path));
		if( *site == '-' ){
			ovstrcpy(site,site+1);
			Conn->my_vbase.u_pri = 1;
		}
		decomp_URL_site(site,AVStr(host),AVStr(sport));
		if( *sport )
			port = atoi(sport);
		else	port = serviceport(proto);

		/* should use StrAlloc() for repetition without free() */
		Conn->my_vbase.u_proto = stralloc(proto);
		Conn->my_vbase.u_host = stralloc(host);
		Conn->my_vbase.u_port = port;
		Conn->my_vbase.u_path = stralloc(path);
		HostPort(AVStr(hp),proto,host,port);
		Conn->my_vbase.u_hostport = stralloc(hp);

		sv1log("BASEURL= %s :// %s : %d %s\n",
			Conn->my_vbase.u_proto,Conn->my_vbase.u_host,
			Conn->my_vbase.u_port,Conn->my_vbase.u_path);
	}
}
void scan_BASEURL(Connection *Conn,PCStr(url))
{
	xmem_push(Conn->cl_baseurl,strlen(Conn->cl_baseurl)+1,"BASEURLs",NULL);
	if( isFullURL(url) )
	xmem_push(&Conn->my_vbase,sizeof(Conn->my_vbase),"BASEURLx",NULL);
	set_BASEURL(Conn,url);
}

int HTTP_originalURLPath(Connection *Conn,PVStr(path));
const char *get_UrlX(Connection *Conn,UrlX *up,PCStr(url),PVStr(strbuff)){
	IStr(urlb,URLSZ);
	IStr(proto,128);
	IStr(site,256);
	IStr(path,URLSZ);
	refQStr(pp,path);
	IStr(host,MaxHostNameLen);
	int port;
	refQStr(bp,strbuff);
	int isdir = 0;

	if( !isFullURL(url) ){
		strcpy(proto,CLNT_PROTO);
		HTTP_ClientIF_HP(Conn,AVStr(site));
		HTTP_originalURLPath(Conn,AVStr(path));
		if( isFullpath(url) ){
			strcpy(path,url);
		}else{
			if( pp = strrchr(path,'/') ){
				Xstrcpy(DVStr(pp,1),url);
			}else{
				strcpy(path,url);
			}
		}
		if( *path == '/' ){
			ovstrcpy((char*)path,path+1);
		}
		sprintf(urlb,"%s://%s/%s",proto,site,path);
		url = urlb;
	}
	decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(path),sizeof(path));
	up->u_proto    = bp; strcpy(bp,proto); bp += strlen(bp) + 1;
	up->u_hostport = bp; strcpy(bp,site); bp += strlen(bp) + 1;
	up->u_port = scan_hostportX(proto,site,AVStr(host),sizeof(host));
	up->u_host     = bp; strcpy(bp,host); bp += strlen(bp) + 1;
	up->u_path     = bp; strcpy(bp,path);  bp += strlen(bp) + 1;
	return bp;
}
void set_VBASE(Connection *Conn,PCStr(url),PVStr(strbuff)){
	get_UrlX(Conn,&Conn->rq_vbase,url,BVStr(strbuff));
}
void push_VBASE(Connection *Conn,void *sav,int siz){
	if( siz < sizeof(UrlX) ){
		daemonlog("F","-- push_VBASE too small %d/%d\n",
			siz,sizeof(UrlX));
		return;
	}
	bcopy(&Conn->rq_vbase,sav,sizeof(UrlX));
	bzero(&Conn->rq_vbase,sizeof(UrlX));
}
void pop_VBASE(Connection *Conn,void *sav){
	bcopy(sav,&Conn->rq_vbase,sizeof(UrlX));
}

int strNetaddr(PCStr(host),PVStr(net));
int substCGIENV(Connection *Conn,PCStr(name),PVStr(out),int size);

char *strfConnX(Connection *Conn,PCStr(fmt),PVStr(str),int size)
{	const char *fp;
	CStr(tmp,1024);
	CStr(outb,1024);
	const char *outp;
	const char *dp;
	CStr(xfmt,1024);
	int rem,len;
	refQStr(sp,str); /**/
	int in2B = 0;

	setVStrEnd(str,0);
	rem = size - 1;

	if( strchr(fmt,'[') ){
		lineScan(fmt,xfmt);
		StrSubstDate(AVStr(xfmt));
		if( strcmp(fmt,xfmt) != 0 ){
			fmt = xfmt;
		}
	}
	for( fp = fmt; *fp; fp++ ){
		if( *fp == 033 ){
			if( fp[1] == '$' ){
				in2B = 1;
			}else
			if( fp[1] == '(' ){
				in2B = 0;
			}
		}
		if( in2B ){
			setVStrPtrInc(sp,*fp);
			setVStrEnd(sp,0);
			continue;
		}

		outp = 0;
		outb[0] = 0;
		outb[1] = 0;
		if( *fp == '\\' ){
			int ch = -1;
			switch( fp[1] ){
				case '\\': ch = '\\'; break;
				case 'r': ch = '\r'; break;
				case 'n': ch = '\n'; break;
				case 't': ch = '\t'; break;
				case 's': ch = ' '; break;
				case '0': ch = 0; break;
				case '$': ch = '$'; break;
				case '%': ch = '%'; break;
			}
			if( ch != -1 ){
				outb[0] = ch;
				fp++;
				goto xOUT;
			}
		}
		if( *fp != '%' ){
			outb[0] = *fp;
			goto xOUT;
		}
		if( fp[1] == '{' ){
			CStr(name,32);
			dp = wordscanY(fp+2,AVStr(name),sizeof(name),"^}");
			if( *dp == '}' ){
				fp = dp;
				if( !substCGIENV(Conn,name,AVStr(outb),sizeof(outb)) )
					syslog_ERROR("Undef %%{%s}\n",name);
				goto xOUT;
			}
		}
		if( *++fp == 0 )
			break;

		switch( *fp ){
		case '%':
			outb[0] = '%';
			break;

		case 'c':
			if( Conn->cl_cert[0] )
				outp = Conn->cl_cert;
			break;

		case 'C':
			if( Conn->sv_cert[0] )
				outp = Conn->sv_cert;
			break;

		case 'u':
			if( (outp = getClientUserC(Conn)) == 0 )
				outp = "-";
			break;

		case 'h':
			if( CLNT_HOST[0] )
				strcpy(outb,CLNT_HOST);
			else{
				getClientHostPort(Conn,AVStr(outb));
				if( *outb == 0 )
					outb[0] = '-';
			}
			if( TeleportHost[0] ){
				if( isinetAddr(TeleportHost) )
					addr2dom(TeleportHost,AVStr(tmp),sizeof(tmp));
				else	lineScan(TeleportHost,tmp);
				Xsprintf(TVStr(outb),".-.%s",tmp);
			}
			break;

		case 'p':
			sprintf(outb,"%d",getClientHostPort(Conn,AVStr(tmp)));
			break;

		case 'i':
			gethostNAME(ClientSock,AVStr(outb));
			break;

		case 'I':
			HTTP_ClientIF_HP(Conn,AVStr(outb));
			break;

		case 'd':
			getClientHostPort(Conn,AVStr(tmp));
			if( dp = strrchr(tmp,'.') )
				outp = dp+1;
			else	outp = tmp;
			break;

		case 'a':
			if( TeleportAddr[0] )
				sprintf(outb,"%s.-.",TeleportAddr);
			getClientHostPortAddr(Conn,VStrNULL,TVStr(outb));
			break;

		case 'n':
			getClientHostPortAddr(Conn,VStrNULL,AVStr(tmp));
			strNetaddr(tmp,AVStr(outb));
			break;

		case 'A':
			if( 0 <= find_CMAP(Conn,"authgen",AVStr(tmp)) ){
				strfConnX(Conn,tmp,AVStr(outb),sizeof(outb));
				if( strchr(tmp,':') == 0 )
					strcat(tmp,":");
			}
			break;

		case 'H':
			gethostname(outb,sizeof(outb));
			break;

		case 'M':
			outp = DELEGATE_ADMIN;
			break;

		case 'O':
			getUsername(getuid(),AVStr(outb));
			break;

		case 'F':
		case 'L':
		case 'D':
			if( HTTP_getRequestField(Conn,"From",AVStr(tmp),sizeof(tmp)) ){
				switch( *fp ){
				case 'F': Xsscanf(tmp,"%s",AVStr(outb)); break;
				case 'L': Xsscanf(tmp,"%[^@]",AVStr(outb)); break;
				case 'D': Xsscanf(tmp,"%*[^@]@%s",AVStr(outb)); break;
				}
			}
			if( outb[0] == 0 )
				outp = "-";
			break;

		case 'U':
		case 'P':
			{
			  AuthInfo ident;
			  if( HTTP_getAuthorization(Conn,1,&ident,2)
			   || HTTP_getAuthorization(Conn,0,&ident,2)
			   || HTTP_getAuthorization(Conn,0,&ident,0)
			  ){
			    switch( *fp ){
			      case 'U': outp = ident.i_user; break;
			      case 'P':
				if( strcaseeq(ident.i_atyp,"Digest") ){
					const char *host;
					if( ClientAuth.i_stat == AUTH_SET )
						host = ClientAuth.i_Host;
					else	host = "";
					getDigestPassX(Conn,host,ident.i_user,AVStr(outb));
				}else	outp = ident.i_pass;
				break;
			    }
			  }
			}
			if( outb[0] == 0 && outp == 0 ){
				/*
				if( ClientAuth.i_stat == AUTH_GOT ){
				*/
				if( ClientAuth.i_stat == AUTH_GOT
				 || (ClientFlags & PF_MITM_ON)
				 && (ClientAuth.i_stat == AUTH_SET)
				 && (ClientAuth.i_stype == AUTH_APROXY)
				){
				  switch( *fp ){
				    case 'U': outp = ClientAuth.i_user; break;
				    case 'P': outp = ClientAuth.i_pass; break;
				  }
				}
			}
			if( outb[0] == 0 && outp == 0 )
				outp = "-";
			break;

		case 'Q':
		if( HTTP_getRequestField(Conn,"Forwarded",AVStr(tmp),sizeof(tmp)) )
			if( dp = strstr(tmp," for ") )
				Xsscanf(dp+5,"%s",AVStr(outb));
			if( outb[0] == 0 )
				outp = "-";
			break;
		}
xOUT:
		if( outb[0] )
			outp = outb;
		if( outp ){
			len = strlen(outp);
			if( rem < len )
				len = rem;
			if( 0 < len ){
				QStrncpy(sp,outp,len+1);
				rem -= len;
				sp += strlen(sp);
			}
		}
	}
	return (char*)str+strlen(str);
}
void genheadf(PCStr(fmt),PVStr(out),int siz)
{	Connection ConnBuf,*Conn = &ConnBuf;

	bzero(Conn,sizeof(Connection));
	strfConnX(Conn,fmt,AVStr(out),siz);
}

void make_conninfo(Connection *Conn,PVStr(conninfo))
{	CStr(buff,1024);
	const char *proto;
	refQStr(sp,conninfo); /**/

	if( CLNT_PROTO[0] )
		proto = CLNT_PROTO;
	else	proto = DFLT_PROTO;
	sp = Sprintf(AVStr(sp),"Client-Protocol: %s\n",proto);
	sp = Sprintf(AVStr(sp),"Server-Protocol: %s\n",REAL_PROTO);

	sp = strfConnX(Conn,"Client-User-Ident: %u\n",AVStr(sp),64);
	sp = strfConnX(Conn,"Client-Host: %h\n",AVStr(sp),13+70+1);
	sp = strfConnX(Conn,"Client-Addr: %a\n",AVStr(sp),64);
	sp = strfConnX(Conn,"Client-User-Auth: %U\n",AVStr(sp),64);

	sp = Sprintf(AVStr(sp),"Server-Host: %s\n",DST_HOST);

	ClientIF_HP(Conn,AVStr(buff));
	sprintf(sp,"Client-IF-Host: %s\n",buff);
	sp += strlen(sp);

	if( MountOptions ){
	sp = Sprintf(AVStr(sp),"Client-URL-Base: %s\n",MountVbase(MountOptions));
	sp = Sprintf(AVStr(sp),"Server-URL-Base: %s\n",MountRpath(MountOptions));
	}
}

int reverseMOUNT(Connection *Conn,PVStr(url),int siz)
{	const char *opts;
	const char *proto;
	CStr(hp,MaxHostNameLen);
	const char *path;
	const char *search;
	const char *dgproto;
	CStr(dghp,MaxHostNameLen);
	CStr(xurl,1024);
	CStr(protob,64);
	CStr(pathb,256);
	CStr(uhead,256);

	if( Conn == NULL )
		return 0;

	if( isFullURL(url) ){
		decomp_absurl(url,AVStr(protob),AVStr(hp),AVStr(pathb),sizeof(pathb));
		proto = protob;
		path = pathb;
		search = NULL;
	}else
	if( url[0] == '/' ){
		proto = DST_PROTO;
		sprintf(hp,"%s:%d",DST_HOST,DST_PORT);
		path = url + 1;
		search = NULL;
	}else{
		return 0;
	}

	dgproto = CLNT_PROTO;
	HTTP_ClientIF_HP(Conn,AVStr(dghp));
	opts = CTX_mount_url_fromL(Conn,AVStr(xurl),proto,hp,path,search,dgproto,dghp);

	if( opts ){
		sprintf(uhead,"%s://%s/",dgproto,dghp);
		if( strneq(xurl,uhead,strlen(uhead)) ) /* if partialize enabled */
			linescanX(xurl+strlen(uhead)-1,AVStr(url),siz);
		else	linescanX(xurl,AVStr(url),siz);
		Verbose("reverseMOUNT %s://%s/%s -> %s\n",proto,hp,path,url);
	}
	return opts != NULL;
}

/*
 * in current implementation, only FTOCL is supported to be
 * "mount-point-local" or "request-local" filter
 */
void scan_FFROMSV(Connection *Conn,PCStr(f));
static int mount_filters(Connection *Conn,PCStr(opt))
{
	if( strncasecmp(opt,"FTOCL=",6) == 0 )
			/*
			scan_FTOCL(opt+6);
			*/
			scan_FTOCL(Conn,opt+6);
	else
	if( strncasecmp(opt,"FTOSV=",6) == 0 )
			/*
			scan_FTOSV(opt+6);
			*/
			scan_FTOSV(Conn,opt+6);
	else
	if( strncasecmp(opt,"FFROMSV=",8) == 0 ){
			scan_FFROMSV(Conn,opt+8);
	}else
	if( strncasecmp(opt,"FSV=",4) == 0 )
			/*
			scan_FSV(opt+4);
			*/
			scan_FSV(Conn,opt+4);
	else
	if( strncaseeq(opt,"STLS=",5) ){
		extern int BREAK_STICKY;
		void scan_STLS(Connection *Conn,PCStr(stls));
		scan_STLS(Conn,opt+5);
		/* the MOUNT local CMAP for STLS must not be reused */
		CKA_RemAlive = 0;
		BREAK_STICKY = 1;
	}else
	return 0;

	Conn->xf_mounted++;
	sv1log("#### MountOption %s\n",opt);
	return 1;
}

int MAX_BPS = 0;
int CTX_maxbps(Connection *Conn){
	if( 0 < Conn->gw_maxbps )
		return Conn->gw_maxbps;
	if( 0 < MAX_BPS )
		return MAX_BPS;
	return 0;
}
void scan_FTPCONFm(Connection *Conn,PCStr(conf));
void setCCX0(PCStr(what),PCStr(chset),CCXP ccx);
void setpathExt(Connection *Conn,PCStr(ext));
extern const char *OPT_NVSERV;
extern const char *OPT_AVSERV;
/*
static scanListFunc opt1(PCStr(opt),Connection *Conn)
*/
static scanListFunc opt1(PCStr(opt),Connection *Conn,PCStr(opts))
{	int leng;
	const char *val;

	if( (val = parameq(opt,P_CHARCODE)) || (val = parameq(opt,P_CHARSET)) ){
		if( strstr(val,":tosv") ){
			IStr(chset,128);
			wordScanY(val,chset,"^:");
			setCCX0("CCXTOSV/MOUNT",chset,CCX_TOSV);
			CCXtosv(CCX_TOSV,1);
		}else
		if( Conn->cl_setccx && CCXactive(CCX_TOCL) ){
			/* CCX is set by client */
		}else{
			leng = CCXcreate("*",val,CCX_TOCL);
			sv1log("#### MountOption CHARCODE=%s [%d]\n",val,leng);
		}
	}else
	if( strncasecmp(opt,"FTOSV=-cc-",10) == 0 ){
		if( CCXactive(CCX_TOSV) == 0 ){
			leng = CCXcreate("*",opt+10,CCX_TOSV);
			CCXtosv(CCX_TOSV,1);
			sv1log("#### MountOption FTOSV=%s [%d]\n",opt+10,leng);
		}
	}else
	if( mount_filters(Conn,opt) ){
	}else
	if( strcasecmp(opt,"AUTH=none") == 0 ){
		NoAuth = 1;
		sv1log("#### NoAuth\n");
	}else
	if( strcasecmp(opt,"public") == 0 ){
		Conn->from_myself = 1;
	}else
/*
	if( strcasecmp(opt,"rident") == 0 ){
*/
	if( strcasecmp(opt,"rident") == 0
	 || strcasecmp(opt,"rident=server") == 0 ){
		ServerFlags |= PF_RIDENT;
	}else
	if( strcasecmp(opt,"rident:no") == 0 ){
		ServerFlags |= PF_RIDENT_OFF;
	}else
	if( strncasecmp(opt,"MASTER=",7) == 0 ){
		MO_MasterPort = scan_hostport("http",opt+7,AVStr(MO_MasterHost));
	} else
	if( strncasecmp(opt,"PROXY=",6) == 0 ){
		MO_ProxyPort = scan_hostport("http",opt+6,AVStr(MO_ProxyHost));
	}
	else
	if( strncasecmp(opt,"GENVHOST=",9) == 0 )
		strcpy(GEN_VHOST,opt+9);
	else
	if( val = parameq(opt,OPT_AVSERV) )
		strcpy(GEN_VHOST,val);
	else
	if( val = parameq(opt,OPT_NVSERV) ){
		strcpy(GEN_VHOST,val);
	}else
	if( strncasecmp(opt,"CACHE=NO",8) == 0 )
		DontUseCache = DontReadCache = DontWriteCache = 1;
	else
	if( strncasecmp(opt,"COUNTER=",8) == 0 ){
		int scan_COUNTER1(DGC*ctx,int COUNTER,PCStr(spec));
		CStr(opt1,1024);
		getOpt1(opts,"COUNTER",AVStr(opt1));
		mo_COUNTER = CNT_MOUNTOPT|scan_COUNTER1(Conn,gl_COUNTER,opt1);
	}else
	if( strncasecmp(opt,"EXPIRE=",7) == 0 ){
		strcpy(D_EXPIRE,opt+7);
	}
	else
	if( strncasecmp(opt,"BASEURL=",8) == 0 ){
		/*
		strcpy(Conn->cl_baseurl,opt+8);
		it must override BASEURL paraemeter, which is interpreted and
		setup with set_BASEURL()
		*/
		set_BASEURL(Conn,opt+8);
	}
	else
	if( strncasecmp(opt,"HTTPCONF=",9) == 0 ){
		extern int BREAK_STICKY;
		BREAK_STICKY = 1;
		scan_HTTPCONF(Conn,opt+9);
	}
	else
	if( strncasecmp(opt,"FTPCONF=",8) == 0 ){
		scan_FTPCONFm(Conn,opt+8);
	}else
	if( strncasecmp(opt,"MAXIMA=bps:",11) == 0 ){
		Conn->gw_maxbps = kmxatoi(opt+11);
	}else
	if( strncasecmp(opt,"pathext=",8) == 0 ){
		setpathExt(Conn,opt+8);
	}
	else
	if( strcasecmp(opt,"thru") == 0 ){
		RelayTHRU = 1;
	}
	else
	if( strcasecmp(opt,"asis") == 0 ){
		DONT_REWRITE = 1;
	}
	else
	if( strncasecmp(opt,"sign",4) == 0 && (opt[4]==0||opt[4]=='=') ){
		Conn->mo_flags |= (MO_MD5_ADD|MO_MD5_SIGN);
	}
	else
	if( strncasecmp(opt,"verify",6) == 0 && (opt[6]==0||opt[6]=='=') ){
		Conn->mo_flags |= MO_MD5_VERIFY;
	}
	return 0;
}
void eval_mountOptions(Connection *Conn,PCStr(opts))
{
/*
	scan_commaList(opts,0,scanListCall opt1,Conn);
*/
	scan_commaList(opts,0,scanListCall opt1,Conn,opts);
}
/* TODO...
 * evaluated mountOptions must be reset on the change of MOUNT point... 
 */

#define PRDBG() //fprintf(stderr,"-- %03X [%d] %s\n",TID,SVX,__FUNCTION__);

int recycleConnSocket(int sock,PCStr(what),int age);

int NumServCache = 16;
typedef struct {
	Port	sv_Serv;
	Port	sv_Gway;
	int	sv_tid;
	int	sv_cid; /* servCacheId */
} ServCache;
static ServCache *servPorts;
static int servCacheId;
void minit_curServ(){
	if( servPorts == 0 ){
		servPorts = (ServCache*)calloc(NumServCache,sizeof(ServCache));
		bzero(servPorts,NumServCache*sizeof(ServCache));
	}
}

static int SERV_gix(FL_PAR,Connection *Conn){
	static int ngix;
	int gix;

	gix = SVX;
	ngix++;
	//fprintf(stderr,"-- %X %d SERV[%d] <= %s:%d\n",TID,ngix,gix,FL_BAR);
	return gix;
}
#define GIX()	SERV_gix(FL_ARG,Conn)
#define curServ servPorts[GIX()].sv_Serv
#define curGw   servPorts[GIX()].sv_Gway
#define curSCid	servPorts[GIX()].sv_cid

#undef NOcurServ
#define NOcurServ() 0

/*
static Port *servPorts;
static Port *gwPorts;
#define curServ	servPorts[0]
#define curGw gwPorts[0]
void minit_curServ()
{
	if( servPorts == 0 )
	{
		servPorts = NewStruct(Port);
		gwPorts = NewStruct(Port);
	}
}
*/

int DontKeepAliveServ(Connection *Conn,PCStr(what))
{
	if( RIDENT_SENT ){
		if( lSINGLEP() )
		if( (ServerFlags & PF_RIDENT_SENT) == 0 ){
			/* 9.9.0 sent not to this server, in another thread */
			return 0;
		}
		/* since 8.4.0 */
		sv1log("#### RIDENT was sent, disable %s\n",what);
		return 1;
	}
	return 0;
}
int SRCIFHPfor(Connection *Conn,PCStr(proto),PCStr(rhost),int rport,PVStr(lhp));
static int matchSRCIF(Connection *Conn){
	CStr(lhp,MaxHostNameLen);
	int bound;

	bound = SRCIFHPfor(Conn,DST_PROTO,DST_HOST,DST_PORT,AVStr(lhp));
	if( bound ){
		if( strcaseeq(lhp,curServ.p_SRCIF) ){
			strcpy(Conn->sv.p_SRCIF,curServ.p_SRCIF);
			return 1;
		}else{
			return 0;
		}
	}else{
		if( curServ.p_SRCIF[0] ){
			return 0;
		}else{
			return 1;
		}
	}
}

void closingServ(Connection *Conn,int fsd,int tsd){
	PRDBG(); if( NOcurServ() ){ return; }
	if( fsd == curServ.p_sock || tsd == curServ.p_sock ){
		Verbose("--closingServ(%d/%d / %d/%d) %X\n",
			fsd,tsd,curServ.p_sock,ServerSock,ServerFlags);
		if( ServerSock == curServ.p_sock )
			ServerSock = -1;
		curServ.p_sock = -1;
	}
	if( fsd == ServerSock || tsd == ServerSock ){
		Verbose("--closingServ(%d/%d / %d)\n",fsd,tsd,ServerSock);
		ServerSock = -1;
	}
	if( fsd == ServerSockX || tsd == ServerSockX ){
		Verbose("--closingServX(%d/%d / %d)\n",fsd,tsd,ServerSockX);
		ServerSockX = -1;
	}
	if( Conn->sv_retry == SV_RETRY_DO ){ /* to be generic */
	    if( ToS == fsd || ToS == tsd ){
		Verbose("--closingServ ToS=%d (%d %d)\n",ToS,fsd,tsd);
		ToS = -1;
	    }
	    if( FromS == fsd || FromS == tsd ){
		Verbose("--closingServ FromS=%d (%d %d)\n",FromS,fsd,tsd);
		FromS = -1;
	    }
	}
}
void dontclosedups(int fd);
int putServ(Connection *Conn,int tsfd,int fsfd)
{
	PRDBG(); if( NOcurServ() ){ return 0; }
	if( lNOSERVKA() ){ return 0; }
	if( EccEnabled() ){
		if( ClientFlags & PF_MITM_ON ){
			/* should reuse conn. in MITM */
		}else{
			/* 9.9.3 conn. to serv. is kept and managed in CCSV */
			dupclosed_FL(FL_ARG,tsfd);
			if( fsfd != tsfd )
				dupclosed_FL(FL_ARG,fsfd);
			return 0;
		}
	}
	minit_curServ();

	if( DontKeepAliveServ(Conn,"HTTP putServ()") )
		return 0;

	if( ServKeepAlive )
	if( IsConnected(fsfd,NULL) )
	if( IsConnected(tsfd,NULL) )
	/*
	if( 0 < PollIn(fsfd,1) ){
	reduce delay by polling when doing Keep-Alive with the client
	*/
	if( !WillKeepAlive && 0 < PollIn(fsfd,1) ){
		sv1log("#HT11 putServ EOF or pending data from the server\n");
	}else
	{
		LOGX_app_keepAliveSV++;
		curServ = Conn->sv;
		curSCid = ++servCacheId;
		curGw = Conn->gw;
		strcpy(curServ.p_host,DST_HOST);
		curServ.p_port = DST_PORT;
		curServ.p_wfd = tsfd;
		curServ.p_rfd = fsfd;
		curServ.p_viaProxy = toProxy;
		curServ.p_viaMaster = toMaster;
		strcpy(curServ.p_viaMasterVer,MediatorVer);
		/*
		curServ.p_connTime = Time();
		*/
		if( curServ.p_connTime == 0 )
			curServ.p_connTime = CONN_DONE;
		curServ.p_saveTime = Time();
		curServ.p_connType = ConnType;
		/* save ServerFlags and xf_filter&XF_SERVER too ? */
sv1log("#HT11 %d putServ(%d/%d/%d) %s:%d\n",curSCid,
curServ.p_wfd,curServ.p_rfd,ServerSock, curServ.p_host,curServ.p_port);

{
/*
 int strfSocket(PVStr(desc),int size,PCStr(fmt),int fd);
 IStr(desc,MaxHostNameLen);
 strfSocket(AVStr(desc),sizeof(desc),"",ServerSock);
 sv1log("---FD putServ(%d/%d %d/%d %d/%d) %s:%d (%s)\n",
  SocketOf(ServerSock),ServerSock,SocketOf(tsfd),tsfd, SocketOf(fsfd),fsfd,
  curServ.p_host,curServ.p_port, desc
 );
*/

 if( 0 <= ServerSock )
 dontclosedups(ServerSock);
 dontclosedups(tsfd);
 dontclosedups(fsfd);
}
		return 1;
	}
	return 0;
}
void delServ(Connection *Conn,int tsfd,int fsfd)
{
	PRDBG(); if( NOcurServ() ){ return; }
	minit_curServ();

sv1log("##HT11 delServ(%d/%d): %s:%d (%d/%d)\n",
		tsfd,fsfd,
		curServ.p_host,curServ.p_port,curServ.p_wfd,curServ.p_rfd);

/*
sv1log("##HT11 delServ(%d:%d, %d:%d) %d %d A\n",
curServ.p_wfd,IsConnected(curServ.p_wfd,NULL),
curServ.p_rfd,IsConnected(curServ.p_rfd,NULL),
tsfd,fsfd);
close(curServ.p_rfd);
close(curServ.p_wfd);
sv1log("##HT11 delServ(%d:%d, %d:%d) %d %d B\n",
curServ.p_wfd,IsConnected(curServ.p_wfd,NULL),
curServ.p_rfd,IsConnected(curServ.p_rfd,NULL),
tsfd,fsfd);
*/

	curServ.p_host[0] = 0;
	if( tsfd == curServ.p_wfd )
		curServ.p_wfd = -1;
	if( fsfd == curServ.p_rfd )
		curServ.p_rfd = -1;

	if( ServerFlags ){
		sv1log("delServ: clear ServerFlags=%X\n",ServerFlags);
		ServerFlags = 0;
	}
	if( 0 <= ServerSock ){
		int rcode;
		rcode = close(ServerSock);
sv1log("--ServerSock[%d] delServ():close()=%d\n",ServerSock,rcode);
		ServerSock = -1;
	}
	if( 0 <= ServerSock ){
		ServerSockX = -1;
	}
}
int aliveServ(Connection *Conn){
	PRDBG(); if( NOcurServ() ){ return 0; }
	if( servPorts == 0 )
		return 0;
	if( curServ.p_host[0] ){
		return curServ.p_reqserno + 1;
	}
	return 0;
}

#include <errno.h>
#include "filter.h"
int ShutdownSocket(int sock);
/* 9.7.1 shutdown the connection to the server, which is in keep-alive by the
 * server, to finish the server and filter process(es) on the connesion.
 */
int shutdownServConn(Connection *Conn){
	int xpid = 0;

	PRDBG(); if( NOcurServ() ){ return 0; }
	/*
	if( Conn->xf_filters & XF_SERVER )
		it is not saved in putServ()
	*/
	xpid = NoHangWait();
	if( errno == ECHILD )
		return -1;

	/* there is child process(es), maybe as external filter(s) */
	ShutdownSocket(FromS);
	if( ToS != FromS )
		ShutdownSocket(ToS);

	sv1log("#clearServ xpid=%d errno=%d [%d %d %d %d %d %d]\n",
		xpid,errno,
		FromS,ToS,ToSX,ToSF,ServerSock,curServ.p_sock);
	return xpid;
}

int clearServ(Connection *Conn){
	int tid = 0;
	int terr = 0;
	int pid = 0;
	int xpid = 0;

	PRDBG(); if( NOcurServ() ){ return 0; }
	if( servPorts == 0 )
		return 0;
	if( curServ.p_host[0] == 0 )
		return 0;

	FromS = curServ.p_rfd;
	ToS = curServ.p_wfd;
	ToSX = curServ.p_wfdx;
	ToSF = curServ.p_wfdf;
	ServerFilter = curServ.p_filter[0];
	xpid = shutdownServConn(Conn);
	/* should restore ServerSock here ? */
	if( 0 <= ServerSock ){
sv1log("--ServerSock[%d] clearServ(%d,%d)\n",ServerSock,ToS,FromS);
		close(ServerSock);
		ServerSock = -1;
	}
	if( 0 <= ServerSockX ){
		ServerSockX = -1;
	}
	close(FromS);
	close(ToS);
	if( 0 <= ToSX )
	close(ToSX);
	if( 0 <= ToSF )
	close(ToSF);
	if( tid = ServerFilter.f_tid ){
		if( (terr = thread_wait(ServerFilter.f_tid,1000)) == 0 ){
			ServerFilter.f_tid = 0;
		}
	}else{
		msleep(10);
		pid = NoHangWait();
		if( pid <= 0 && 0 < xpid )
			pid = xpid;
	}
	FromS = -1;
	ToS = -1;
	ToSX = -1;
	ToSF = -1;

	sv1log("clearServ: %s:%d [%d][%X/%d]\n",
		curServ.p_host,curServ.p_port,pid,tid,terr);
	if( terr == 0 ){
		curServ.p_host[0] = 0;
	}
	return 1;
}

static void SVKA_close(Connection *Conn,Port *SvKa,int fd){
	/*
	fprintf(stderr,"----recycle[%s][%d][%d][%d] [%d][%d] [%d][%d]\n",
		SvKa->p_host,ToS,FromS,ServerSock,
		SvKa->p_wfd,SvKa->p_rfd,SvKa->p_wfdx,SvKa->p_wfdf);
	*/
	if( 0 <= fd ) close(fd);
	if( fd == SvKa->p_wfd  ) SvKa->p_wfd  = -1;
	if( fd == SvKa->p_rfd  ) SvKa->p_rfd  = -1;
	if( fd == SvKa->p_wfdx ) SvKa->p_wfdx = -1;
	if( fd == SvKa->p_wfdf ) SvKa->p_wfdf = -1;
}
int isSockOfServ(Connection *Conn,int fd){
	minit_curServ();
	if( fd == curServ.p_rfd  ){ return 1; }
	if( fd == curServ.p_wfd  ){ return 2; }
	if( fd == curServ.p_wfdx ){ return 3; }
	if( fd == curServ.p_wfdf ){ return 4; }
	if( fd == curServ.p_sock ){ return 5; }
	return 0;
}
int getServ(Connection *Conn)
{	double age;
	double Now,idle;
	IStr(sage,128);
	int oSvF = ServerFlags;

	PRDBG(); if( NOcurServ() ){ return 0; }
	minit_curServ();

	if( curServ.p_host[0] == 0 )
		return 0;

	/*
	age = Time() - curServ.p_connTime;
	*/
	Now = Time();
	age = Now - curServ.p_connTime;
	idle = Now - curServ.p_saveTime;
	sprintf(sage,"%.1fs(%.1fs)",age,idle);

	if( matchSRCIF(Conn) == 0 ){
		sv1log("#HT11 getServ diff. SRCIF [%s]\n",curServ.p_SRCIF);
	}else
	/*
	if( IsAlive(curServ.p_rfd)
	*/
	if( idle <= 3 || IsAlive(curServ.p_rfd)
	/* and service_permitted() */
	/* and (client dependent) filter is the common one ... */
	){
/*
		if( hostcmp(curServ.p_host,DST_HOST) == 0
7.4.1 can be bad when ther server is IIS with virtual-hosting
*/
		int hostmatch;
		hostmatch = 0;
		if( strcaseeq(curServ.p_host,DST_HOST)
		){
			hostmatch = 1;
		}else
		if( (curServ.p_flags & PF_MITM_ON)
		 && hostcmp(curServ.p_host,DST_HOST) == 0 ){
			/* 9.9.4 put by Host:name but get by CONNECT-addr */
			/* if SNI/TLX show by client matches the name */
			/* if in Keep-Alive with the client */
			/* if address of the client is the same (weak) */
			/* it must be matched with the Host later */
			/*
			hostmatch = 2;
			*/
		}

		if( hostmatch
		 && curServ.p_port == DST_PORT ){
			/*
			if( 0 < PollIn(curServ.p_rfd,1) ){
			*/
			if( 3 < idle && 0 < PollIn(curServ.p_rfd,1) ){
daemonlog("E","#HT11 %d getServ EOF or pending data from the server\n",curSCid);
			}else{
			LOGX_app_keepAliveSVreu++;
			ServReqSerno = curServ.p_reqserno;
			incServReqSerno(Conn);

			toProxy = curServ.p_viaProxy;
			toMaster = curServ.p_viaMaster;
			strcpy(MediatorVer,curServ.p_viaMasterVer);
			FromS = curServ.p_rfd;
			ToS = curServ.p_wfd;
			ToSX = curServ.p_wfdx;
			ToSF = curServ.p_wfdf;
			ServerFilter = curServ.p_filter[0];
			ServerSock = curServ.p_sock;
			ServerSockX = curServ.p_SockX;
/* ServerSock can be closed/overwritten? ... */
			if( 0 <= ServerSock && !IsConnected(ServerSock,NULL) ){
				/* failure should be return but leaving it alive
				 * might be useful to to cope with a server
				 * (with disconnected SSL filter via MITM)
				 * while doing cached responses...
				 */
sv1log("--ServerSock[%d] getServ():disconn. [%d,%d]\n",ServerSock,ToS,FromS);
				ServerSock = -1;
			}
			ServConnTime = curServ.p_connTime; /* 9.6.0 to get
				the age since the connection to the server */
			/*
			ServConnTime = Time();
			*/
			ConnDelay = 0;
			ConnType = curServ.p_connType;
			/* should restore ServerFlags ? */
			ServerFlags |= curServ.p_flags & (PF_SSL_ON|PF_STLS_ON);
			ServerFlags |= curServ.p_flags & PF_VIA_CONNECT;
			strcpy(GatewayProto,curGw.p_proto);
			GatewayAuth = curGw.p_auth;

daemonlog("E","#HT11 %d getServ %s*%d SERVER REUSE (%d/%d/%d) [%s:%d] %s [%X %X %X]\n",
	curSCid,
	sage,curServ.p_reqserno+1,ToS,FromS,ServerSock,
	curServ.p_host,curServ.p_port,DST_HOST,
	curServ.p_flags,oSvF,ServerFlags
);

			}

		}else{
			ServerFlags |= curServ.p_flags & (PF_SSL_ON|PF_STLS_ON);
			ServerFlags |= curServ.p_flags & PF_VIA_CONNECT;
/*
daemonlog("E","#HT11 getServ %4.1fs*%d SERVER SWITCH[%s:%d]->[%s:%d]\n",
age,ServReqSerno,
*/
daemonlog("E","#HT11 %d getServ %s*%d SERVER SWITCH[%s:%d]->[%s:%d]\n",curSCid,
sage,curServ.p_reqserno,
curServ.p_host,curServ.p_port,DST_HOST,DST_PORT);
		}
	}else{
/*
daemonlog("E","#HT11 getServ %4.1fs*%d SERVER TIMEOUT[%s:%d] %s:%d\n",
age,ServReqSerno,
*/
daemonlog("E","#HT11 %d getServ %s*%d SERVER TIMEOUT[%s:%d] %s:%d\n",curSCid,
sage,curServ.p_reqserno,
curServ.p_host,curServ.p_port,DST_HOST,DST_PORT);
	}

	if( 0 <= FromS ){
		if( ClientFlags & PF_MITM_ON )
		if( streq(DFLT_HOST,"-") )
		{
			/* 9.5.7 to cope with retrying CONNECT for this server
			 * when disconnected, and with PROXY=ph:pp:dstHostList
			 * where dstHostList is matched with DFLT_HOST:DFLT_PORT
			 */
			strcpy(DFLT_HOST,REAL_HOST);
			DFLT_PORT = REAL_PORT;
		}
		return ++curServ.p_reqserno;
	}else{
		if( lMULTIST() ){
			if( ServerFlags & (PF_SSL_ON|PF_STLS_ON) ){
			}else
			if( ServerFlags & PF_VIA_CONNECT ){
				/* 9.9.0 it must not be recycled as a fresh
				 * connection to the SSL-TUNNEL proxy, but it
				 * must be reused as the connection to the
				 * real target server.  It hould be reused by
				 * shifting to an empty cache slot.
				 */
				/* also connections via PROXY,MASTER,SOCKS,...
				 * must not be recycled
				 */
				sv1log("getServ DONT recycle[%d] AH=%d SF=%X\n",
					curServ.p_wfd,AccViaHTMUX,ServerFlags);
			}else{
				recycleConnSocket(curServ.p_wfd,"getServ",0);
			}
		}
		curServ.p_host[0] = 0;
		SVKA_close(Conn,&curServ,curServ.p_wfd);
		SVKA_close(Conn,&curServ,curServ.p_rfd);

		if( 0 <= curServ.p_wfdx ){ /* ToSX */
			SVKA_close(Conn,&curServ,curServ.p_wfdx);
			if( 0 <= curServ.p_wfdf ) /* ToSF */
				SVKA_close(Conn,&curServ,curServ.p_wfdf);
			NoHangWait();
		}

		curServ.p_rfd = -1;
		curServ.p_wfd = -1;
		curServ.p_reqserno = 0;
		SERVREQ_SERNO = 0;

		if( ServerFlags ){
		/* must be reset in connect_to_server() ? */
		sv1log("getServ: clear ServerFlags=%X\n",ServerFlags);
		ServerFlags = 0;
		}
		if( actthreads() ){
			/* 9.9.4 */
			int tid;
			if( tid = curServ.p_filter[0].f_tid ){
				if( thread_wait(tid,300) == 0 ){
					curServ.p_filter[0].f_tid = 0;
					putfLog("FSV thread-SSLway cleared-C %X",tid);
				}else{
				}
			}
		}
		return 0;
	}
}
void setIsFunc(Connection *Conn,int fc)
{
	Conn->_isFunc = fc;
}

void CTX_dumpGatewayAuth(Connection *Conn,PCStr(F),int L){
	sv1log("--%s:%d %X [%s][%s]\n",F,L,p2i(Conn),GatewayUser,GatewayPass);
}

#undef ConnCSC
static CriticalSec ConnCSC; /* should be in the Connection structure */

void fclosesX(Connection *Conn){
	int ei;
	FILE *fp;

	/*
	if( numthreads() ){
		setupCSC("fcloses",ConnCSC,sizeof(ConnCSC));
		enterCSC(ConnCSC);
	}
	*/
	for( ei = 0; ei < elnumof(Efiles); ei++ ){
		if( fp = Efiles[ei].e_fp ){
			Efiles[ei].e_fp = 0;
			Verbose("---EPIPE fcloses [%d] %X/%d http.c:%d\n",
				ei,p2i(fp),fileno(fp),Efiles[ei].e_ln);
			/*
			sv1log("---FD fcloses [%d] %X/%d/%d http.c:%d\n",
			ei,fp,SocketOf(fileno(fp)),fileno(fp),Efiles[ei].e_ln);
			*/
			fclose(fp);
		}
	}
	Efilex = 0;
	/*
	if( numthreads() ){
		leaveCSC(ConnCSC);
	}
	*/
}
void addfcloseX(Connection *Conn,FILE *fp,FL_PAR){
	int ei,ex;

	if( numthreads() ){
		setupCSC("addfclose",ConnCSC,sizeof(ConnCSC));
		enterCSC(ConnCSC);
	}
	for( ei = 0; ei < elnumof(Efiles); ei++ ){
		if( Efiles[ei].e_fp == fp )
			goto EXIT;
	}
	if( elnumof(Efiles) <= Efilex ){
		sv1log("---EPIPE fcloses [%d] overflow %X\n",Efilex,p2i(fp));
		fclose(fp);
	}else{
		fflush(fp);
		ex = Efilex++;
		Efiles[ex].e_fp = fp;
		Efiles[ex].e_ln = FL_L;
		dupclosed_FL(FL_BAR,fileno(fp));
	}
	/*
	sv1log("---FD addfclose [%d] %X/%d/%d http.c:%d\n",
		ex,fp,SocketOf(fileno(fp)),fileno(fp),L);
	*/
EXIT:;
	if( numthreads() ){
		leaveCSC(ConnCSC);
	}
}

int CTX_closedX(FL_PAR,PCStr(wh),Connection *Conn,int fd1,int fd2,int force);
int CTX_closed(FL_PAR,PCStr(wh),Connection *Conn,int fd1,int fd2){
	return CTX_closedX(FL_BAR,wh,Conn,fd1,fd2,0);
}
int CTX_closedX(FL_PAR,PCStr(wh),Connection *Conn,int fd1,int fd2,int force){
	int toS;
	int fromS;
	int serverSock;
	int toSX;
	int toSF;
	int toC;
	int fromC;
	int clientSock;
	int fi;
	int nc[2];
	int fdv[2];
	int fd;

	if( Conn->sv_retry == SV_RETRY_DO && (0 <= ToS || 0 <= FromS) ){
		sv1log("Retrying [%d][%d] [%d][%d][%d]\n",
			fd1,fd2,ToS,FromS,ServerSock);
	}else
	if( force ){
	}else
	if( numthreads() == 0 ){
		return 0;
	}

	toS = ToS;
	fromS = FromS;
	serverSock = ServerSock;
	toSX = ToSX;
	toSF = ToSF;
	toC = ToC;
	fromC = FromC;
	clientSock = ClientSock;

	nc[0] = nc[1] = 0;
	fdv[0] = fd1;
	fdv[1] = fd2;
	for( fi = 0; fi < 2; fi++ ){
		fd = fdv[fi];
		if( fd < 0 ){
			continue;
		}
		if( fd == ToS ){
			ToS = -1;
			nc[fi] += 1;
		}
		if( fd == FromS ){
			FromS = -1;
			nc[fi] += 1;
		}
		if( fd == ServerSock ){
			ServerSock = -1;
			nc[fi] += 1;
		}
		if( fd == ServerSockX ){
			ServerSockX = -1;
			nc[fi] += 1;
		}
		if( fd == ToSX ){
			ToSX = -1;
			nc[fi] += 1;
		}
		if( fd == ToSF ){
			ToSF = -1;
			nc[fi] += 1;
		}
		if( fd == ToC ){
			ToC = -1;
			nc[fi] += 1;
		}
		if( fd == FromC ){
			FromC = -1;
			nc[fi] += 1;
		}
		if( fd == ClientSock ){
			ClientSock = -1;
			nc[fi] += 1;
		}
		if( fd == ClientSockX ){
			ClientSockX = -1;
			nc[fi] += 1;
		}
		if( fd == STX_clSock._fd ){
			STX_clSock._fd = -1;
			nc[fi] += 1;
		}
	}
	if( nc[0] + nc[1] ){
		IStr(buf,256);
		sprintf(buf,
			"closed-%d[%d %d][%d %d %d %d %d/%d %d %d]%s %s:%d",
			nc[0]+nc[1],fd1,fd2,
			toS,fromS,serverSock,toSX,toSF,
			toC,fromC,clientSock,
			wh,FL_BAR
		);
		strsubst(AVStr(buf),".cpp:",":");
		if( strheadstrX(wh,"fclosesTIMEOUT",0) == 0
		 && strheadstrX(wh,"closeCONNECT",0) == 0
		 && strheadstrX(wh,"HTTPexit",0) == 0
		){
			porting_dbg("%s",buf);
		}
	}
	return nc[0]+nc[1];
}
int CTX_fcloses(FL_PAR,PCStr(wh),Connection *Conn,FILE *fp1,FILE *fp2){
	int rcode = EOF;
	int fd1,fd2;

	if( fp1 == 0 )
		return EOF;
	if( !lMULTIST() || Conn == 0 ){
		if( fp1 ) rcode = Xfclose(FL_BAR,fp1);
		if( fp2 ) rcode = Xfclose(FL_BAR,fp2);
		return rcode;
	}
	if( fp1 ) fd1 = fileno(fp1); else fd1 = -1;
	if( fp2 ) fd2 = fileno(fp2); else fd2 = -1;

	if( fp1 )
		rcode = Xfclose(FL_BAR,fp1);
	if( fp2 )
	if( fd1 != fd2 )
		rcode = Xfclose(FL_BAR,fp2);
	else	rcode = XXfcloseFILE(FL_BAR,fp2);
	CTX_closed(FL_BAR,wh,Conn,fd1,fd2);
	return rcode;
}

const char *getMountOptions(FL_PAR,Connection *Conn){
	/*
	syslog_ERROR("##getMOpts %X <= %s:%d\n",Conn->mo_options,FL_BAR);
	*/
	return Conn->mo_options;
}
const char *setMountOptions(FL_PAR,Connection *Conn,PCStr(opts)){
	/*
	syslog_ERROR("##setMOpts %X %X <= %s:%d\n",
		Conn->mo_options,opts,FL_BAR);
	*/
	Conn->mo_options = opts;
	return Conn->mo_options;
}

int CCSV_reusing(Connection *Conn,PCStr(what),int sock){
	if( EccEnabled() ){
		if( Conn->ccsv.ci_id ){
			porting_dbg("-Ecc(%2d){%d}*%d => Reu[%s] %s:%d",
				Conn->ccsv.ci_ix,Conn->ccsv.ci_id,
				Conn->ccsv.ci_reused,
				what,DST_HOST,DST_PORT
			);
			return Conn->ccsv.ci_reused;
		}
	}
	return 0;
}

int Em_active(int out,Connection *Conn,FL_PAR){
	if( LOGMD5_IN <= 0 )
		return 0;
	if( 0 < Conn->md_in.md_md5 ){
		return 1;
	}
	return 0;
}
int Em_setupMD5(int out,Connection *Conn,PCStr(wh)){
	int ecode;

	if( LOGMD5_IN <= 0 )
		return 0;

	Conn->md_in.md_leng = 0;
	ecode = startMD5(Conn->md_in.md_md5ctx,sizeof(Conn->md_in.md_md5ctx));
	if( ecode == 0 ){
		Conn->md_in.md_md5 = 1;
		return 1;
	}else{
		porting_dbg("FTP-MD5 init. error (%d)",ecode);
		Conn->md_in.md_md5 = -1;
		return -1;
	}
}
int Em_updateMD5(int out,Connection *Conn,const void *buff,int leng){
	if( LOGMD5_IN <= 0 )
		return 0;
	if( 0 < Conn->md_in.md_md5 ){
		updateMD5(Conn->md_in.md_md5ctx,(char*)buff,leng);
		Conn->md_in.md_leng += leng;
		return 1;
	}else{
		return -1;
	}
}
int Em_finishMD5(int out,Connection *Conn,PCStr(wh),FileSize leng){
	if( LOGMD5_IN <= 0 )
		return 0;
	if( 0 < Conn->md_in.md_md5 ){
		IStr(md5a,64);
		finishMD5(Conn->md_in.md_md5ctx,Conn->md_in.md_md5b,md5a);
		sv1log("md5=%s %s leng=%lld %lld\n",md5a,wh,leng,
			Conn->md_in.md_leng);
		return 1;
	}else{
		return -1;
	}
}
int Em_printMD5(int out,Connection *Conn,PVStr(md5a)){
	IStr(md5ab,64);
	clearVStr(md5a);
	if( LOGMD5_IN <= 0 )
		return 0;
	if( 0 < Conn->md_in.md_md5 ){
		MD5toa(Conn->md_in.md_md5b,md5ab);
		setVStrEnd(md5ab,LOGMD5_IN-1);
		strcpy(md5a,md5ab);
		return 1;
	}else{
		return -1;
	}
}
