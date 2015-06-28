/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2007 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	socks5.c (RFC1928 SocksV5 server and client)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	Authentication is not supported yet.
History:
	980211	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "vsocket.h"
#include "vaddr.h"
#include "fpoll.h"
#include "log.h"

void finishClntYY(FL_PAR,DGC*ctx);
void finishServYY(FL_PAR,DGC*ctx);
int CTX_closed(FL_PAR,PCStr(wh),DGC*ctx,int fd1,int fd2);
int CTX_close(FL_PAR,DGC*ctx,int fd){
	int rcode;
	rcode = close(fd);
	if( ctx == 0 ){
	}else
	CTX_closed(FL_BAR,__FILE__,ctx,fd,-1);
	return rcode;
}
#undef close
#define close(fd) CTX_close(FL_ARG,ctx,fd) 

void tcp_relay2X(DGC*ctx,int timeout,int s1,int d1,int s2,int d2);
#define tcp_relay2(timeout,s1,d1,s2,d2) tcp_relay2X(ctx,timeout,s1,d1,s2,d2)

#if !defined(FMT_CHECK)
#define syslog_DEBUG  LOG_VERBOSE==0 ? 0 : syslog_ERROR
#endif

#define Send(s,b,l,f)	send(s,(char*)b,l,f)
#define Recv(s,b,l,f)	recv(s,(char*)b,l,f)
#define Sendto(s,b,l,f,a,n)	sendto(s,(char*)b,l,f,a,n)
#define Recvfrom(s,b,l,f,a,n)	recvfrom(s,(char*)b,l,f,a,n)

int VSA_comp(VSAddr*,VSAddr*);
int setCloseOnExec(int);
int CTX_auth(DGC*ctx,PCStr(user),PCStr(pass));
int CTX_ToS(DGC*ctx);
int CTX_FromS(DGC*ctx);

const char *gethostaddrX(PCStr(host));
int SRCIFfor(DGC*Conn,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport);
int CTX_VSA_SRCIFfor(DGC*ctx,PCStr(wh),VSAddr *me);

static int recv_mssg(int sock,PVStr(sbuf),int siz)
{	UrefQStr(buf,sbuf);
	int rcc,rcc1,alen;

	rcc = Recv(sock,buf,10,0);
	if( rcc < 10 ) return rcc;
	if( buf[0] != 5 ) return rcc; /* VER */
	alen = 0;
	switch( buf[3] ){ /* ATYP, common(4)+addr(4)+port(2) has got */
		case 3: alen = 1+buf[4] - 4; break;
		case 4: alen = 16 - 4; break;
	}
	if( siz < rcc+alen ){
		syslog_ERROR("recv_mssg: too long addr (%d %d/%d)\n",
			buf[4],rcc+alen,siz);
		return rcc;
	}
	if( alen )
		rcc1 = Recv(sock,&buf[rcc],alen,0);
	else	rcc1 = 0;
	return rcc + rcc1;
}
typedef unsigned char USChar;
typedef struct {
	USChar	p_ver;
	USChar	p_cmd;
	USChar	p_rsv;
	USChar	p_typ;
	MStr(	p_host,512);
	int	p_port;
} PackHead;
#define GETPC()	((rcc <= pi)?-1:pack[pi++])
static int scanPack(PackHead *PK,unsigned PCStr(pack),int rcc){
	int pi = 0;
	int aleng;
	int ai;
	JStr(hostbuf,512);
	unsigned char *qh;
	IStr(host,512);

	PK->p_ver = GETPC();
	PK->p_cmd = GETPC();
	PK->p_rsv = GETPC();
	PK->p_typ = GETPC();
	aleng = 0;
	switch( PK->p_typ ){
		case 1: aleng = 4; break; /* IPv4 */
		case 3: aleng = GETPC(); break; /* DOMAIN NAME */
		case 4: aleng = 16; break; /* IPv6 */ break;
	}
	if( 0 < aleng ){
		for( ai = 0; ai < aleng; ai++ )
			setVStrElem(hostbuf,ai,GETPC());
	}
	qh = (unsigned char*)hostbuf;
	switch( PK->p_typ ){
		case 1: sprintf(host,"%d.%d.%d.%d",qh[0],qh[1],qh[2],qh[3]);
			break;
		case 3: QStrncpy(host,(char*)qh,aleng+1); break;
		case 4: strcpy(host,VSA_ltoa(qh,16,AF_INET6)); break;
	}
	strcpy(PK->p_host,host);
	if( rcc < pi+2 ){
		PK->p_port = -1;
		return -1;
	}
	PK->p_port = (GETPC() << 8) | GETPC();
	return 0;
}


static const char *socks_host = NULL;
static int   socks_port = 1080;
static int   socks_sock = -1;
int VSA_getViaSocksX(DGC*Conn,PCStr(host),int port,VSAddr *sv,AuthInfo *au,VSAddr *vlocal);

typedef struct {
	int	s_ssock;	/* socket connected by TCP to sockd */
	VSAddr	s_rme;		/* remote UDP port on the sockd */
	int	s_msock;	/* local UDP socket for reception */
	VSAddr	s_me;		/* local UDP port */
} SocksServ;
typedef struct {
	SocksServ se_socksServ[32]; /**/
	int	se_socksServN;
	VSAddr	se_to_socksV[8]; /**/
	int	se_to_socksN;
} Socks5Env;
static Socks5Env *socks5Env;
#define socksServ	socks5Env[0].se_socksServ
#define socksServN	socks5Env[0].se_socksServN
#define to_socksV	socks5Env[0].se_to_socksV
#define to_socksN	socks5Env[0].se_to_socksN
void minit_socks5()
{
	if( socks5Env == 0 ){
		socks5Env = NewStruct(Socks5Env);
	}
}

static int fixed_udp_address = 0;

static int VSA_stosaX(VSAddr *sap,unsigned PCStr(resp)){
	int af;
	int leng;

	if( resp[3] == 4 )
		af = AF_INET6;
	else	af = AF_INET;
	leng = VSA_stosa(sap,af,(char*)&resp[4]);
	return leng;
}

#define ltob(l,b) {(b)[0]=l>>24;(b)[1]=l>>16;(b)[2]=l>>8;(b)[3]=l;}
#define stob(s,b) {(b)[0]=s>>8; (b)[1]=s;}

#define btol(b)   (((b)[0]<<24)|((b)[1]<<16)|((b)[2]<<8)|(b)[3])
#define btos(b)   (((b)[0]<<8) | (b)[1])

void SOCKS_udpclose(int msock)
{	int si,sj;

	for( si = 0; si < socksServN; si++ )
	if( socksServ[si].s_msock == msock ){
		for( sj = si; sj < socksServN; sj++ )
			socksServ[sj] = socksServ[sj+1];
		socksServN--;
		break;
	}
}

#define AUTH_M_NONE	0 /* NO AUTHENTICATION REQUIRED */
#define AUTH_M_USERPASS	2 /* USERNAME/PASSWORD */
#define AUTH_M_ERROR	0xFF /* NO ACCEPTABLE METHODS */

#define AUTH_R_OK	0
#define AUTH_R_ERR	1

/*
 * declare the socket is a local UDP socket to be used for
 * UDP communication throught the socks server
 */
int SOCKS_udpassocX(DGC*ctx,int msock,VSAddr *me,VSAddr *rme);
int SOCKS_udpassoc(int msock,VSAddr *me,VSAddr *rme)
{
	return SOCKS_udpassocX(NULL,msock,me,rme);
}
int SOCKS_udpassoc0(DGC*ctx,int ssock,VSAddr *me,VSAddr *rme);
int SOCKS_udpassocX(DGC*ctx,int msock,VSAddr *me,VSAddr *rme)
{	int sock;
	int rcode;
	VSAddr sab;
	int salen;
	int si;
	SocksServ *ssp;

	if( socks_host == NULL ){
		/*
		syslog_ERROR("SocksV5_udpassoc: NO socks.\n");
		*/
		syslog_DEBUG("SocksV5_udpassoc: NO static SOCKS.\n");
		return -1;
	}
	for( si = 0; si < socksServN; si++ ){
		if( VSA_comp(&socksServ[si].s_me,me) == 0 ){
			syslog_DEBUG("SocksV5_udpassoc[%d]: already done\n",si);
			ssp = &socksServ[si];
			sock = socksServ[si].s_ssock;
			goto EXIT;
		}
	}

	if( elnumof(socksServ) <= socksServN ){
		return -1;
	}

	ssp = &socksServ[socksServN];
	ssp->s_msock = msock;
	ssp->s_me = *me;

	/*
	sock = socket(AF_INET,SOCK_STREAM,0);
	*/
	salen = VSA_atosa(&sab,socks_port,socks_host);
	sock = socket(VSA_af(&sab),SOCK_STREAM,0);
	setCloseOnExec(sock);

	ssp->s_ssock = sock;
	syslog_DEBUG("SocksV5_connect [%x]%s:%d ...\n",
		VSA_addr(&sab),socks_host,socks_port);

	if( ctx ){
		JStr(remote,256);
		JStr(local,256);
		int osock;
		strcpy(local,"*:*");
		sprintf(remote,"%s:%d",socks_host,socks_port);
		osock = sock;
		sock = VSocket(ctx,"CNCT/SocksV5",sock,AVStr(local),AVStr(remote),"proto=socks");
		if( sock != osock ){
			/* may be replaced with the socket to MASTER */
			close(osock);
		}
		rcode = 0;
	}else
	rcode = connect(sock,(SAP)&sab,salen);

	if( rcode < 0 ){
		syslog_ERROR("SocksV5_udpassoc: connect error\n");
		close(sock);
		return -1;
	}

	if( SOCKS_udpassoc0(ctx,sock,me,&ssp->s_rme) < 0 ){
		return -1;
	}

	syslog_ERROR("SocksV5_udpassoc[%d]: OK (%s:%d/%s:%d)\n",
		socksServN,
		VSA_ntoa(&ssp->s_rme),VSA_port(&ssp->s_rme),
		VSA_ntoa(me),VSA_port(me));

	socksServN++;

EXIT:
	if( rme ){
		*rme = ssp->s_rme;
	}
	socks_sock = sock;
	return 0;
}

#if 0
static int issocks = -1;
static int isSocks(int sock){
	if( issocks == sock ){
		/* check if the CRC32(host:port) is in list */
		return 1;
	}
	return 0;
}	
void setUDPviaSocks(int sock){
	issocks = sock;
	/* and add the CRC32(host:port) into the list */
}
#endif

#define addQbuf(qcc,v) setVStrElemInc(qbuf,qcc,v)
#define addRbuf(rcc,v) setVStrElemInc(rbuf,rcc,v)
#define setQbuf(qix,v) setVStrElem(qbuf,qix,v)
#define setRbuf(qix,v) setVStrElem(rbuf,qix,v)

static int doAuth(int sock,unsigned PCStr(aub),int acc,AuthInfo *auth){
	int ulen,plen,qcc,wcc,rcc;
	JStr(qbuf,512);
	JStr(rbuf,512);
	const char *user;
	const char *pass;

	if( acc < 2 )
		return -1;
	if( aub[1] == AUTH_M_NONE )
		return 0;
	if( aub[1] != AUTH_M_USERPASS )
		return -2;
	if( auth == NULL )
		return -3;

	user = auth->i_user;
	pass = auth->i_pass;
	ulen = strlen(user);
	plen = strlen(pass);
	qcc = 0;
	addQbuf(qcc,1);
	addQbuf(qcc,ulen); Xstrcpy(DVStr(qbuf,qcc),user); qcc += ulen;
	addQbuf(qcc,plen); Xstrcpy(DVStr(qbuf,qcc),pass); qcc += plen;
	wcc = Send(sock,qbuf,qcc,0);
	rcc = Recv(sock,rbuf,2,0);
	syslog_ERROR("SocksV5_start: %d VER[%d] AUTH-STATUS[%d]\n",
		rcc,rbuf[0],rbuf[1]);
	if( rbuf[1] != 0 ){
		return -4;
	}
	return 0;
}
int SOCKS_udpassoc0X(DGC*ctx,int sock,VSAddr *me,VSAddr *rme,AuthInfo *auth);
int SOCKS_udpassoc0(DGC*ctx,int sock,VSAddr *me,VSAddr *rme){
	return SOCKS_udpassoc0X(ctx,sock,me,rme,NULL);
}
int SOCKS_udpassoc0X(DGC*ctx,int sock,VSAddr *me,VSAddr *rme,AuthInfo *auth){
	UJStr(resp,512);
	JStr(qbuf,512);
	int rcc,ri;
	const char *baddr;
	const char *bport;
	int bleng,btype;
	int qcc;
	int wcc;

	setQbuf(0,5); /* VERSION */
	setQbuf(1,1); /* leng */
	if( auth && auth->i_user[0] ){
		setQbuf(2,AUTH_M_USERPASS);
	}else	setQbuf(2,0); /* NO AUTH */
	Send(sock,qbuf,3,0);
	rcc = Recv(sock,resp,2,0);
	if( 0 <= doAuth(sock,resp,rcc,auth) ){
	}else
	if( rcc < 2 || resp[1] != 0 ){
		syslog_ERROR("SocksV5_udpassoc: AUTH error (V%d %d) rcc=%d\n",
			resp[0],resp[1],rcc);
		close(sock);
		return -1;
	}

	if( fixed_udp_address && VSA_addr(me) == 0 ){
		VSAddr xme;
		int port;
		int addrlen = sizeof(VSAddr);
		getsockname(sock,(SAP)&xme,&addrlen);
		port = VSA_port(me);
		*me = xme;
		VSA_setport(me,port);
	}
/*
	if( VSA_addrisANY(me) ){
		VSAddr xme,xsv;
		int len;
		len = sizeof(VSAddr); getsockname(sock,(SAP)&xme,&len);
		len = sizeof(VSAddr); getpeername(sock,(SAP)&xsv,&len);
		if( VSA_addrcomp(&xme,&xsv) == 0 ){
			VSA_addrcopy(me,&xme);
		}
	}
*/
	/* 9.9.5 set DST.ADDR/PORT, ex. SRCIF=0.0.0.0:0:socks-udp-tosv */
	CTX_VSA_SRCIFfor(ctx,"socks-udp-tosv",me);

	bleng = VSA_decomp(me,&baddr,&btype,&bport);
	qcc = 0;
	addQbuf(qcc,5); /* VERSION */
	addQbuf(qcc,3); /* CMD = UDP ASSOCIATE */
	addQbuf(qcc,0); /* reserved */
	if( btype == AF_INET6 ){
		addQbuf(qcc,4); /* ATYP = IPv6 address type */
	}else	addQbuf(qcc,1); /* ATYP = IP V4 address type */
	Xbcopy(baddr,DVStr(qbuf,qcc),bleng); /* DST.ADDR */
	qcc += bleng;
	Xbcopy(bport,DVStr(qbuf,qcc),2); /* DST.PORT */
	qcc += 2;
	wcc = Send(sock,qbuf,qcc,0);
	syslog_DEBUG("[SocksV5-clnt] UDPASSOC [%d]%s:%d sent(%d/%d)\n",
		qbuf[3],VSA_ltoa((unsigned char*)&qbuf[4],bleng,btype),
		VSA_port(me),wcc,qcc);

	((char*)resp)[0] = ((char*)resp)[1] = 0;
	rcc = recv_mssg(sock,AVStr(resp),sizeof(resp));
	if( rcc < 10 || resp[1] != 0 ){
		PackHead PK;
		IStr(dump,1024);
		strtoHexX((char*)resp,rcc,AVStr(dump),sizeof(dump),"s");
		syslog_ERROR("SocksV5_udpassoc: UDP ASSOC error(V%d %d)%d/%s\n",
			resp[0],resp[1],rcc,dump);

		if( scanPack(&PK,resp,rcc) == 0 ){
			/* empty domain name ?? */
		}else{
			close(sock);
			return -1;
		}
	}
	if( rme ){
		/*
		*rme = ssp->s_rme;
		 */
		VSA_stosaX(rme,resp);
	}
	return 0;
}

int SOCKS_sendto0(int sock,PCStr(msg),int len,int flags,VSAddr *to,VSAddr *rme,int isconn,int si);
int SOCKS_Sendto(int sock,PCStr(msg),int len,int flags,VSAddr *to,int tolen)
{	JStr(buf,8*1024);
	int wcc;
	VSAddr me,rme;
	int si;

	bzero(&rme,sizeof(rme));
	for( si = 0; si < socksServN; si++ )
		if( socksServ[si].s_msock == sock ){
			rme = socksServ[si].s_rme;
			break;
		}
	if( socksServN <= si ){
		int len = sizeof(me);
		getsockname(sock,(SAP)&me,&len);
		if( SOCKS_udpassoc(sock,&me,&rme) < 0 )
			return -1;
	}

	wcc = SOCKS_sendto0(sock,msg,len,flags,to,&rme,0,si);
	return wcc;
}
int SOCKS_sendto0(int sock,PCStr(msg),int len,int flags,VSAddr *to,VSAddr *via,int isconn,int si){
	VSAddr rme;
	const char *baddr;
	const char *bport;
	int bleng,btype;
	JStr(qbuf,10+32*1024);
	int salen;
	int qcc;
	int wcc;

	rme = *via;
	bleng = VSA_decomp(to,&baddr,&btype,&bport);

	qcc = 0;
	addQbuf(qcc,0); /* reserved */
	addQbuf(qcc,0); /* reserved */
	addQbuf(qcc,0); /* FRAGment number */
	if( btype == AF_INET6 ){
		addQbuf(qcc,4); /* ATYP = IPV6 address type */
	}else	addQbuf(qcc,1); /* ATYP = IP V4 address type */
	Xbcopy(baddr,DVStr(qbuf,qcc),bleng); /* DST.ADDR */
	qcc += bleng;
	Xbcopy(bport,DVStr(qbuf,qcc),2); /* DST.PORT */
	qcc += 2;
	Xbcopy(msg,DVStr(qbuf,qcc),len);

	salen = VSA_size(&rme);
	wcc = -1;
	if( isconn ){
		wcc = send(sock,qbuf,qcc+len,flags);
	}
	if( wcc < 0 )
	wcc = Sendto(sock,qbuf,qcc+len,flags,(SAP)&rme,salen);

	syslog_DEBUG("SocksV5_sendto[%d](%s:%d/%s:%d)=%d,errno=%d\n",si,
		VSA_ntoa(to),VSA_port(to), VSA_ntoa(&rme),VSA_port(&rme),
		wcc,errno);

	return wcc - qcc;
}
int SOCKS_gotudp(PVStr(msg),int rcc,VSAddr *via,VSAddr *from,int *fromlen);
int SOCKS_Recvfrom(int sock,PVStr(msg),int len,int flags,VSAddr *from,int *fromlen)
{	int rcc;
	VSAddr sab;
	int addrlen;

	addrlen = sizeof(VSAddr);
	rcc = Recvfrom(sock,msg,len,flags,(SAP)&sab,&addrlen);
	if( rcc <= 0 )
		return rcc;

	if( msg[0] != 0 || msg[1] != 0 )
	{
		*from = sab;
		*fromlen = addrlen;
		return rcc;
	}
	return SOCKS_gotudp(BVStr(msg),rcc,&sab,from,fromlen);
}
int SOCKS_gotudp(PVStr(msg),int rcc,VSAddr *via,VSAddr *from,int *fromlen){
	VSAddr sab;

	sab = *via;
	*fromlen = VSA_stosaX(from,(const unsigned char*)msg);
	syslog_DEBUG("SocksV5_recvfrom(%x:%d/%x:%d) = %d\n",
		VSA_addr(from),VSA_port(from),
		VSA_addr(&sab),VSA_port(&sab),rcc);

	bcopy(10+msg,(char*)msg,rcc-10);
	return rcc - 10;
}


void SOCKS_addserv(PCStr(dhost),int dport,PCStr(shost),int sport)
{	VSAddr *to;
	int si;

	socks_host = stralloc(shost);
	socks_port = sport;
	if( strcmp(dhost,"*") == 0 )
		dhost = "255.255.255.255"; /* use it for wild card */
	else{
		if( !VSA_strisaddr(dhost) ){
			syslog_ERROR("SocksV5_addrserv(%s) host ERROR\n",dhost);
			return; 
		}
	}
	if( elnumof(to_socksV) <= to_socksN ){
		return;
	}
	to = &to_socksV[to_socksN];
	VSA_atosa(to,dport,dhost);
	for( si = 0; si < to_socksN; si++ ){
		if( VSA_comp(to,&to_socksV[si]) == 0 ){
			return;
		}
	}
	syslog_DEBUG("SocksV5_addrserv[%d](%x/%s:%d,%s:%d)\n",
		to_socksN,VSA_addr(to),dhost,dport,shost,sport);
	to_socksN++;
}
int SOCKS_via_socks(VSAddr *dist)
{	int ni;
	VSAddr *can1;

	for( ni = 0; ni < to_socksN; ni++ ){
		can1 = &to_socksV[ni];
		if( VSA_addr(can1) == -1 )
			return 1; /* "host=*" (255.255.255.255) */
		if( VSA_comp(can1,dist) == 0 )
			return 1;
	}
	return 0;
}
static int UDPviaSocks(PCStr(host))
{
	if( host == 0 )
		return 0;
	if( !VSA_strisaddr(host) ) /* can be -.- */
		return 0;
	return 1;
}
int dialupTOX(PCStr(wh),int sock,void *addr,int leng,int timeout,PVStr(cstat));
int SOCKS_sendtoX(int sock,PCStr(buf),int len,int flags,SAP to,int tolen);
int SOCKS_sendto(int sock,PCStr(buf),int len,int flags,SAP to,int tolen)
{
	int rcode;
	rcode = SOCKS_sendtoX(sock,buf,len,flags,to,tolen);
	if( isWindows() )
	if( rcode < 0 && (errno == EHOSTUNREACH || errno == ENETUNREACH) ){
		IStr(cstat,256);
		dialupTOX("SENDTO",sock,to,tolen,0,AVStr(cstat));
		rcode = SOCKS_sendtoX(sock,buf,len,flags,to,tolen);
	}
	return rcode;
}
int SOCKS_sendtoX(int sock,PCStr(buf),int len,int flags,SAP to,int tolen)
{
	/*
	if( isSocks(sock) )
		return SOCKS_Sendto(sock,buf,len,flags,(VSAddr*)to,tolen);
	*/
	if( UDPviaSocks(socks_host) && SOCKS_via_socks((VSAddr*)to) )
		return SOCKS_Sendto(sock,buf,len,flags,(VSAddr*)to,tolen);
	else	return       Sendto(sock,buf,len,flags,to,tolen);
}
int SOCKS_recvfrom(int sock,PVStr(buf),int len,int flags,SAP from,int *fromlen)
{
	/*
	if( isSocks(sock) )
	return SOCKS_Recvfrom(sock,BVStr(buf),len,flags,(VSAddr*)from,fromlen);
	*/
	if( UDPviaSocks(socks_host) )
		return SOCKS_Recvfrom(sock,BVStr(buf),len,flags,(VSAddr*)from,fromlen);
	else	return       Recvfrom(sock,buf,len,flags,from,fromlen);
}

int SOCKS_LOGIN_TIMEOUT;
int SOCKS_recvResponseV5(int sock,int command,PVStr(rhost),int *rport);
int SOCKS_startV5(int sock,int command,PCStr(host),int port,PCStr(user),PCStr(pass),PVStr(rhost),int *rport)
{	JStr(qbuf,512);
	UJStr(rbuf,512);
	int qcc,rcc,wcc;
	int ulen,plen;
	int nlen;
	const char *hp;
	VSAddr sab;
	const char *baddr;
	int bleng,btype;
	int qauth,rauth;

errno = 0;

	if( pass != NULL )
		qauth = AUTH_M_USERPASS;
	else	qauth = AUTH_M_NONE;

	setQbuf(0,5);
	setQbuf(1,1);
	setQbuf(2,qauth);
	((char*)rbuf)[0] = ((char*)rbuf)[1] = 0;

	wcc = Send(sock,qbuf,3,0);
	if( 0 < SOCKS_LOGIN_TIMEOUT ){
		if( PollIn(sock,SOCKS_LOGIN_TIMEOUT*1000) == 0 ){
			syslog_ERROR("SocksV5_start: AUTH timeout (%ds)\n",
				SOCKS_LOGIN_TIMEOUT);
			return -1;
		}
	}
	rcc = Recv(sock,rbuf,2,0);
	rauth = rbuf[1];

	if( 1 < rcc && rauth == 4 )
		return 4;

	if( rcc < 2 || rauth != qauth && rauth != AUTH_M_NONE ){
		syslog_ERROR("SocksV5_start: AUTH error (V%d %d) %d,errno=%d\n",
			rbuf[0],rbuf[1],rcc,errno);
		return -1;
	}

	if( rauth == AUTH_M_USERPASS ){
		ulen = strlen(user);
		plen = strlen(pass);
		qcc = 0;
		addQbuf(qcc,1);
		addQbuf(qcc,ulen); Xstrcpy(DVStr(qbuf,qcc),user); qcc += ulen;
		addQbuf(qcc,plen); Xstrcpy(DVStr(qbuf,qcc),pass); qcc += plen;
		wcc = Send(sock,qbuf,qcc,0);
		rcc = Recv(sock,rbuf,2,0);
		syslog_ERROR("SocksV5_start: %d VER[%d] AUTH-STATUS[%d]\n",
			rcc,rbuf[0],rbuf[1]);
		if( rbuf[1] != 0 ){
			return -1;
		}
	}

	qcc = 0;
	addQbuf(qcc,5); /* VERSION */
	addQbuf(qcc,command); /**//* CMD = CONNECT:1,BIND:2 */
	addQbuf(qcc,0); /* reserved */
	if( VSA_strisaddr(host) ){
		VSA_atosa(&sab,0,host);
		bleng = VSA_decomp(&sab,&baddr,&btype,NULL);
		if( btype == AF_INET6 )
			addQbuf(qcc,4); /* ATYP = IPv6 address type */
		else	addQbuf(qcc,1); /* ATYP = IP V4 address type */
		Xbcopy(baddr,DVStr(qbuf,qcc),bleng); /* DST.ADDR */
		qcc += bleng;
	}else{
		addQbuf(qcc,3); /* ATYP = host name */
		nlen = strlen(host);
		addQbuf(qcc,nlen);
		Xstrcpy(DVStr(qbuf,qcc),host);
		qcc += nlen;
	}
	stob(port,(char*)&qbuf[qcc]); qcc += 2; /* DST.PORT */
	wcc = Send(sock,qbuf,qcc,0);
	return SOCKS_recvResponseV5(sock,command,AVStr(rhost),rport);
}

int SOCKS_recvResponseV5(int sock,int command,PVStr(rhost),int *rport)
{	int rcc;
	int addr,port;
	UJStr(rbuf,512);
	int ratyp;

	((char*)rbuf)[0] = ((char*)rbuf)[1] = 0;
	rcc = recv_mssg(sock,AVStr(rbuf),sizeof(rbuf));
	if( rcc < 10 || rbuf[1] != 0 ){
		syslog_ERROR("SocksV5_resp: cmd=%d error=%x rcc=%d\n",
			command,rbuf[1],rcc);
		return -1;
	}

	ratyp = rbuf[3];
	if( ratyp == 1 ){
		addr = btol(&rbuf[4]);
		port = btos(&rbuf[8]);
		if( rhost ) sprintf(rhost,"%d.%d.%d.%d",
				rbuf[4],rbuf[5],rbuf[6],rbuf[7]);
		if( rport ) *rport = port;
	}else
	if( ratyp == 4 ){ /* IPv6 */
		addr = 0;
		port = btos(&rbuf[20]);
		if( rhost ) strcpy(rhost,VSA_ltoa(&rbuf[4],16,AF_INET6));
	}else{
		addr = -1;
		port = 0;
		if( rhost ) sprintf(rhost,"255.255.255.255");
		if( rport ) *rport = port;
	}

	syslog_ERROR("[SocksV5-clnt] start: OK CMD=%d ATYP=%d %x:%d\n",
		command,ratyp,addr,port);
	return 0;
}

#define F_USECLIENTSPORT 0x4 /* share a UDP port between client and server */
int SOCKS_QFLAGS = F_USECLIENTSPORT;

#define Q_VER		((unsigned char*)qbuf)[0]
#define Q_NMETHODS	((unsigned char*)qbuf)[1]
#define Q_METHODS	&qbuf[2]
#define Q_CMD		((unsigned char*)qbuf)[1]
#define Q_RSV		((unsigned char*)qbuf)[2]
#define Q_ATYP		((unsigned char*)qbuf)[3]
#define Q_HOST		&qbuf[4]

#define S_CNTL	0
#define S_CLNT	1
#define S_SERV	2

static VSAddr *selectSockServ(DGC*ctx,PackHead *PK,VSAddr *viaSocks){
	VSAddr sv;
	VSAddr me;

	if( !VSA_getViaSocksX(ctx,PK->p_host,PK->p_port,&sv,NULL,&me) )
		return 0;

	VSA_atosa(viaSocks,PK->p_port,PK->p_host);
	syslog_ERROR("##%x new UDP ASSOC via SOCKS=%s:%d << %s:%d\n",
		ctx!=0,VSA_ntoa(&sv),VSA_port(&sv),PK->p_host,PK->p_port);
	return viaSocks;
}
static void setupSockPort(DGC*ctx,VSAddr *viaSocks,int svsock){
	VSAddr vme;
	int mlen;

	mlen = sizeof(vme);
	getsockname(svsock,(struct sockaddr*)&vme,&mlen);
	syslog_ERROR("##%x UDP/SocksV5 UDP ASSOC forw port=%d -> %d\n",
		ctx!=0,VSA_port(viaSocks),VSA_port(&vme));
	VSA_setport(viaSocks,VSA_port(&vme));
}
static int setupSockServ(DGC*ctx,PackHead *PK,VSAddr *viaSocks,VSAddr *serv){
	int svctrl;
	VSAddr sv;
	VSAddr me;
	JStr(local,256);
	JStr(remote,256);
	AuthInfo auth;

	if( !VSA_getViaSocksX(ctx,PK->p_host,PK->p_port,&sv,&auth,&me) )
		return -1;

	strcpy(local,"*:*");
	if( streq(VSA_ntoa(&sv),"0.0.0.0") ){
		sprintf(remote,"-.-:%d",VSA_port(&sv));
	}else
	sprintf(remote,"%s:%d",VSA_ntoa(&sv),VSA_port(&sv));
	/*
	svctrl = VSocket(ctx,"CNCT/SocksV5",-1,AVStr(local),AVStr(remote),"");
	*/
	svctrl = VSocket(ctx,"CNCT/SocksV5",-1,AVStr(local),AVStr(remote),"proto=socks");
	if( SOCKS_udpassoc0X(ctx,svctrl,viaSocks,serv,&auth) != 0 ){
		return -2;
	}
	syslog_ERROR("##%x set UDP ASSOC via %s:%d [%d] << %s:%d\n",
		ctx!=0,VSA_ntoa(serv),VSA_port(serv),svctrl,
		PK->p_host,PK->p_port);
	return svctrl;
}
int CTX_VSA_SRCIFfor(DGC*ctx,PCStr(wh),VSAddr *me){
	IStr(ohost,64);
	int oport;
	IStr(lhost,MaxHostNameLen);
	int lport;
	IStr(laddr,64);

	if( ctx == 0 ){
		return 0;
	}
	strcpy(ohost,VSA_ntoa(me));
	oport = VSA_port(me);
	strcpy(lhost,ohost);
	lport = oport;
	if( SRCIFfor(ctx,wh,ohost,oport,AVStr(lhost),&lport) ){
		if( lport == 0xFFFF0000 ){
			lport = 0;
		}
		strcpy(laddr,gethostaddrX(lhost));
		syslog_ERROR("## SRCIF %s:%d <= %s:%d\n",laddr,lport,
			ohost,oport);
		VSA_atosa(me,lport,laddr);
		return 1;
	}
	return 0;
}

int serverPid();
int procIsAlive(int pid);
int UDPSOCKS_TIMEOUT = 0;
static int pollUDP(int ns,int sockV[],int sockR[]){
	int nready = 0;
	double St = Time();
	for(;;){
	    	nready = PollIns(5*1000,ns,sockV,sockR);
		if( nready ){
			break;
		}
		if( !procIsAlive(serverPid()) ){
			syslog_ERROR("UDP/SocksV5 server dead\n");
			errno = 0;
			break;
		}
		if( 0 < UDPSOCKS_TIMEOUT && UDPSOCKS_TIMEOUT < Time()-St ){
			syslog_ERROR("UDP/SocksV5 timeout %.1f/%d\n",
				Time()-St,UDPSOCKS_TIMEOUT);
			errno = 0;
			break;
		}
	}
	return nready;
}
static int udp_relay_socks(DGC*ctx,int cntlsock,int clsock,PCStr(clname),int flags,VSAddr *viaSocks)
{	JStr(clhost,256);
	int clport;
	UJStr(rbuf,8*1024);
	unsigned char *data; /**/
	int svsock;
	int rcc,wcc;
	int sockV[3],sockR[3],sentN[3],xi;
	int ns;
	VSAddr clnt,from,to;
	VSAddr serv;
	const char *baddr;
	const char *bport;
	int btype,bleng,clntleng;
	int len,fromlen,tolen;
	int nready;
	JStr(froms,256);
	int qc;
	int pi;
	VSAddr clme;
	int hlen;
	int svctrl = -1; /* upstream on-demand SOCKS server */
	VSAddr viaSocksb;

	clearVStr(clhost);
	clport = 0;
	Xsscanf(clname,"%[^:]:%d",AVStr(clhost),&clport);
	if( clport != 0 && strcmp(clhost,"0.0.0.0") == 0 ){
		JStr(local,256);
		JStr(remote,256);
		JStr(options,256);
		*(char*)local = *(char*)remote = 0;
		VSocket(ctx,"Q/SocksV5",cntlsock,AVStr(local),AVStr(remote),options);
		wordscanY(remote,AVStr(clhost),sizeof(clhost),"^:");
	}
	if( clhost[0] == 0 )
		strcpy(clhost,"0.0.0.0");
	VSA_atosa(&clnt,clport,clhost);

	sockV[S_CNTL] = cntlsock;
	sockV[S_CLNT] = clsock;

/*
	if( (flags | SOCKS_QFLAGS) & F_USECLIENTSPORT ){
*/
	len = sizeof(clme);
	getsockname(clsock,(struct sockaddr*)&clme,&len);
	if( CTX_VSA_SRCIFfor(ctx,"socks-udp-tosv",&clme) ){
		/* 9.9.5 server-side port, ex. SRCIF=0.0.0.0:0:socks-udp-tosv */
		JStr(local,256);
		sprintf(local,"%s:%d",VSA_ntoa(&clme),VSA_port(&clme));
		svsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),CVStr("*:*"),"protocol=udp");
		ns = 3;
	}else
	if( !VSA_islocal(&clme) && ((flags | SOCKS_QFLAGS) & F_USECLIENTSPORT) ){
		/*
		 * this is bad when the socket for the client is bound to
		 * an interface which is not reachable to the server...
		 */
		svsock = clsock;
		ns = 2;
	}else{
		JStr(local,256);
		strcpy(local,"*:*");
		svsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),CVStr("*:*"),"protocol=udp");
		ns = 3;
	}
	sockV[S_SERV] = svsock;

	bzero(&serv,sizeof(VSAddr));
	if( viaSocks ){
		int xcode;

		setupSockPort(ctx,viaSocks,svsock);
		if( SOCKS_udpassocX(ctx,svsock,viaSocks,&serv) < 0 )
		{
			/*
			9.4.3 it is usual because socks_host is NULL for
			SOCKS server to make udpassocX() fail
			return -1;
			*/
		}
		/*
		xcode = connect(svsock,(SAP)&serv,VSA_size(&serv));
		*/
	}

	if( flags != 0 )
		syslog_ERROR("UDP/SocksV5 flags=%X\n",flags);

	for( xi = 0; xi < 3; xi++ )
		sentN[xi] = 0;

	/* when the destination address in packet is IPv6
	hlen = 22;
	*/
	hlen = 10;
	data = (unsigned char*)&rbuf[hlen];
	len = sizeof(rbuf) - hlen;

	for( pi = 0; ; pi++ ){
		/*
	    nready = PollIns(0,ns,sockV,sockR);
		*/
	    nready = pollUDP(ns,sockV,sockR);
	    if( nready <= 0 ){
		syslog_ERROR("UDP/SocksV5 POLL ERROR (%d)\n",errno);
		break;
	    }
	    if( 0 < sockR[S_CNTL] ){
		syslog_ERROR("UDP/SocksV5 GOT CONTROL\n");
		break;
	    }
	    if( 0 < sockR[S_CLNT] ){
		fromlen = sizeof(VSAddr);
		rcc = Recvfrom(clsock,rbuf,sizeof(rbuf),0,(SAP)&from,&fromlen);
		if( rcc <= 0 ){
			syslog_ERROR("UDP/SocksV5 ERROR recv(CL)=%d errno=%d\n",
				rcc,errno);
			break;
		}

		sprintf(froms,"%s:%d",VSA_ntoa(&from),VSA_port(&from));

		if( VSA_addr(&clnt) == 0
		 || pi == 0 && rbuf[0] == 0 && rbuf[1] == 0
		){
			if( clport = VSA_port(&clnt) )
			if( VSA_port(&from) != clport )
			    syslog_ERROR("## BAD PORT ? %d != %d (%d %d %d)\n",
				VSA_port(&from),clport,rcc,errno,fromlen);
			clnt = from;
			syslog_ERROR("UDP/SocksV5 C-S client set < %s\n",froms);
		}else
		if( VSA_comp(&clnt,&from) != 0 ){
			if( ns == 2 /* USECLIENTPORT */
			 || rbuf[0] != 0 || rbuf[1] != 0 /* nonSOCKSUDP pack */
			){
				bcopy(rbuf,data,rcc);
				goto SV2CL;
			}
			syslog_ERROR("## BAD CLIENT: %s %s\n",froms,clname);
			continue;
		}
		if( viaSocks == 0 && pi == 0 ){ /* the first packet */
			PackHead PK;
			scanPack(&PK,rbuf,rcc);
			/* select the upstream SOCKS server for the DST.ADDR
			 * in the packet
			 */
			if( viaSocks = selectSockServ(ctx,&PK,&viaSocksb) ){
				setupSockPort(ctx,viaSocks,svsock);
			}
		}
		if( viaSocks ){ /* relay SOCKS packet as is */
			if( VSA_port(&serv) == 0 ){
				PackHead PK;
				scanPack(&PK,rbuf,rcc);
				/* initiate the control connection with the
				 * SOCKS server
				 */
				svctrl = setupSockServ(ctx,&PK,viaSocks,&serv);
				if( svctrl < 0 ){
					goto DIRECT;
				}
			}
			tolen = VSA_size(&serv);
			wcc = Sendto(svsock,rbuf,rcc,0,(SAP)&serv,tolen);
			if( sentN[S_CLNT] == 0 ){
				PackHead PK;
				scanPack(&PK,rbuf,rcc);
				syslog_ERROR("C-S forw %d/%d > %s:%d >>%s:%d\n",
				wcc,rcc,VSA_ntoa(&serv),VSA_port(&serv),
					PK.p_host,PK.p_port);
			}
			sentN[S_CLNT] += wcc;
			continue;
		}
	DIRECT: /* direct UDP to the destination */
		tolen = VSA_stosaX(&to,rbuf);
		syslog_ERROR("UDP/SocksV5 C-S %d ATYP[%d] > %s:%d\n",
			rcc,rbuf[3],VSA_ntoa(&to),VSA_port(&to));
		wcc = Sendto(svsock,data,rcc-hlen,0,(SAP)&to,tolen);
		if( wcc <= 0 ){
			VSAddr me;
			int mlen = sizeof(me);
			getsockname(svsock,(struct sockaddr*)&me,&mlen);
			syslog_ERROR("[%s] Sendto(%s:%d,%d) = %d, errno=%d\n",
				VSA_ntoa(&me),VSA_ntoa(&to),VSA_port(&to),
				rcc-hlen,wcc,errno);
		}
		sentN[S_CLNT] += wcc;
	    }

	if( 2 < ns )
	    if( 0 < sockR[S_SERV] ){
		fromlen = sizeof(VSAddr);
		rcc = Recvfrom(svsock,data,len,0,(SAP)&from,&fromlen);
		if( rcc <= 0 ){
			syslog_ERROR("UDP/SocksV5 ERROR recv(SV)=%d errno=%d\n",
				rcc,errno);
			break;
		}
	SV2CL:
		if( viaSocks ){ /* relay SOCKS packet as is */
			clntleng = VSA_size(&clnt);
			wcc = Sendto(clsock,data,rcc,0,(SAP)&clnt,clntleng);
			if( sentN[S_SERV] == 0 ){
				PackHead PK;
				scanPack(&PK,data,rcc);
				syslog_ERROR("S-C forw %d/%d > %s:%d <<%s:%d\n",
				wcc,rcc,VSA_ntoa(&clnt),VSA_port(&clnt),
					PK.p_host,PK.p_port);
			}
			sentN[S_SERV] += rcc;
			continue;
		}
		bleng = VSA_decomp(&from,&baddr,&btype,&bport);
		syslog_DEBUG("UDP/SocksV5 S-C %d < %s:%d\n",rcc,
			VSA_ntoa(&from),VSA_port(&from));
		qc = 0;
		addRbuf(qc,0);
		addRbuf(qc,0);
		addRbuf(qc,0); /* FRAGment not suppported */
		addRbuf(qc,1); /* IPv4 */
		Xbcopy(baddr,DVStr(rbuf,qc),bleng);
		qc += bleng;
		Xbcopy(bport,DVStr(rbuf,qc),2);
		qc += 2;
		clntleng = VSA_size(&clnt);
		wcc = Sendto(clsock,rbuf,qc+rcc,0,(SAP)&clnt,clntleng);
		sentN[S_SERV] += rcc;
	    }
	}
	syslog_ERROR("UDP/SocksV5 C-S:%d S-C:%d\n",
		sentN[S_CLNT],sentN[S_SERV]);
	if( viaSocks ){
		SOCKS_udpclose(svsock);
		if( 0 <= svctrl ) close(svctrl);
	}
	return 0;
}

static void send_resp(FILE *tc,int rep,PCStr(bound))
{	JStr(rbuf,512);
	JStr(bhost,256);
	const char *bp;
	const char *baddr;
	int btype,bleng;
	int port;
	int rcc,hlen;
	VSAddr sab;

	setRbuf(0,5);
	setRbuf(1,rep);
	setRbuf(2,0); /* RSV */
	rcc = 3;

	strcpy(bhost,bound);
	if( bp = strrchr(bhost,':') ){
		truncVStr(bp); bp++;
		port = atoi(bp);
	}else	port = -1;
	if( VSA_strisaddr(bhost) ){
		if( strncasecmp(bhost,"__FFFF_",7) == 0 )
		if( VSA_strisaddr(bhost+7) == 1 )
		{
			/* Don't export IPv4 mapped IPv6 address */
			ovstrcpy((char*)bhost,bhost+7);
		}
		VSA_atosa(&sab,port,bhost);
		bleng = VSA_decomp(&sab,&baddr,&btype,NULL);
		if( btype == AF_INET6 ){
			addRbuf(rcc,4); /* IPv6 */
		}else	addRbuf(rcc,1); /* IPv4 */
		Xbcopy(baddr,DVStr(rbuf,rcc),bleng);
		rcc += bleng;
	}else{
		addRbuf(rcc,3); /* DOMAINNAME */
		/*
		addRbuf(rcc,hlen = strlen(bhost));
		*/
		hlen = strlen(bhost);
		addRbuf(rcc,hlen);
		Xbcopy(bhost,DVStr(rbuf,rcc),hlen);
		rcc += hlen;
	}
	stob(port,(char*)&rbuf[rcc]);
	rcc += 2;
	fwrite(rbuf,1,rcc,tc);
	fflush(tc);

	syslog_ERROR("[SocksV5-serv] resp %d [%s]\n",rep,bound);
}
int SOCKS_serverV5A(DGC*ctx,int fromcl,int tocl,int tms,FILE *fc,FILE *tc);
int SOCKS_serverV5(DGC*ctx,int fromcl,int tocl,int timeout_ms)
{	FILE *fc,*tc;
	int rcode;
	int idlethreads();
	double St = Time();

	fc = fdopen(fromcl,"r");
	tc = fdopen(tocl,"w");
	rcode = SOCKS_serverV5A(ctx,fromcl,tocl,timeout_ms,fc,tc);
	fcloseFILE(tc);
	fcloseFILE(fc);
	if( lSINGLEP() && lMULTIST() ){
		syslog_ERROR("SocksV5 %.3f %d/%d\n",Time()-St,
			idlethreads(),numthreads());
	}
	return rcode;
}

int findopen_port(PCStr(wh),PVStr(host),int port,int nlisten);
static const char *ACCONN = ".accept.-";
static int AccByConn(DGC*ctx,FILE *tcfp,int rep,int fc,int tc,int toms,PCStr(host),int port){
	IStr(remote,MaxHostNameLen);
	IStr(local,MaxHostNameLen);
	refQStr(lp,local);
	int asock,csock;
	int sv[2],rv[2];

	strcpy(local,host);
	if( lp = strtailstr(local,ACCONN) ){
		clearVStr(lp);
	}else	return -1;

	asock = findopen_port("XSOCKS",AVStr(local),port,20);
	sv[0] = fc;
	sv[1] = asock;
	if( PollIns(toms,2,sv,rv) == 0 || rv[0] ){
		/* close(asock); to be shared and reused */
		return -1;
	}
	csock = VSocket(ctx,"ACPT/SocksV5",asock,AVStr(local),AVStr(remote),"");
	/* close(asock); to be shared and reused */
	send_resp(tcfp,rep,remote);
	tcp_relay2(toms,fc,csock,csock,tc);
	close(csock);
	return 1;
}

int SOCKS_serverV5A(DGC*ctx,int fromcl,int tocl,int timeout_ms,FILE *fc,FILE *tc){
	UJStr(qbuf,512);
	UJStr(rbuf,512);
	const unsigned char *qh;
	JStr(host,256);
	int aleng,port,rep;
	int svsock,bsock;
	JStr(remote,256);
	JStr(local,256);
	const char *bound;
	int qauth,rauth;
	int ai;
	JStr(rhost,256);
	int rport,viasocks;
	VSAddr qp;
	VSAddr sif;
	int sifset = 0; /* SRCIF=host:port:socks-udp-tocl is set */
	const char *opt;

	rep = 0;
	bound = "";
	Q_VER = getc(fc);
	Q_NMETHODS = getc(fc);
	((char*)qbuf)[2] = ((char*)qbuf)[3] = 0;
	IGNRETP fread((char*)Q_METHODS,1,Q_NMETHODS,fc);
	qauth = qbuf[2];
	syslog_ERROR("[SocksV5-serv] VER[%x] NMETHODS[%d] [%x][%x]\n",
		Q_VER,Q_NMETHODS,qbuf[2],qbuf[3]);

	rauth = AUTH_M_NONE;
	if( lNOAUTHPROXY() ){
		LOGX_authNone++;
	}else
	if( CTX_auth(ctx,NULL,NULL) ){
		rauth = AUTH_M_ERROR;
		for( ai = 0; ai < Q_NMETHODS; ai++ ){
			if( (Q_METHODS)[ai] == AUTH_M_USERPASS ){
				rauth = AUTH_M_USERPASS;
				break;
			}
		}
	}
	if( rauth == AUTH_M_ERROR ){
		if( 0 <= CTX_auth(ctx,"","") ){
			syslog_ERROR("[SocksV5-serv] empty Auth. accepted\n");
			rauth = AUTH_M_NONE;
			LOGX_authOk++;
		}
	}
	setRbuf(0,5);
	setRbuf(1,rauth);
	fwrite(rbuf,1,2,tc);
	fflush(tc);

	if( rauth == AUTH_M_ERROR ){
		syslog_ERROR("[SocksV5-serv] WITH AUTHORIZER, NO METHOD\n");
		LOGX_authErr++;
		return -1;
	}

	if( rauth == AUTH_M_USERPASS ){
		unsigned int ver,ulen,plen;
		JStr(user,256);
		JStr(pass,256);
		int rcode;
		int rcc;

		ver = getc(fc);
		ulen = getc(fc);
		if( ulen < 0 || sizeof(user) <= ulen ) rcc = -1; else
		if( ulen == 0 ) rcc = 0; else
		rcc = fread((char*)user,1,QVSSize(user,ulen),fc);
		/*
		if( ver == EOF || ulen == EOF || rcc <= 0 ){
		*/
		if( ver == EOF || ulen == EOF || rcc < ulen ){
			syslog_ERROR("EOF in user [%d %d %d]\n",ver,ulen,rcc);
			goto ERREXIT;
		}
		setVStrEnd(user,ulen);
		plen = getc(fc);
		if( plen < 0 || sizeof(pass) <= plen ) rcc = -1; else
		if( plen == 0 ) rcc = 0; else
		rcc = fread((char*)pass,1,QVSSize(pass,plen),fc);
		/*
		if( plen == EOF || rcc <= 0 ){
		*/
		if( plen == EOF || rcc < plen ){
			syslog_ERROR("EOF in pass [%d %d]\n",plen,rcc);
			goto ERREXIT;
		}
		setVStrEnd(pass,plen);
		if( feof(fc) ){
			syslog_ERROR("EOF in auth [%d %d]\n",plen,rcc);
			goto ERREXIT;
		}

		rcode = CTX_auth(ctx,user,pass);
		syslog_ERROR("[SocksV5-serv] auth USER:[%s] PASS:*%d => %d\n",
			user,plen,rcode);

		setRbuf(0,1);
		if( rcode < 0 )
			setRbuf(1,AUTH_R_ERR);
		else	setRbuf(1,AUTH_R_OK);
		fwrite(rbuf,1,2,tc);
		fflush(tc);

		if( rcode < 0 )
		{
			LOGX_authErr++;
			return -1;
		}else{
			LOGX_authOk++;
		}
	}

	rep = 0;
	svsock = -1;
	bound = "";
	Q_VER = getc(fc);
	Q_CMD = getc(fc);
	Q_RSV = getc(fc);
	Q_ATYP = getc(fc);
	*((char*)Q_HOST) = 0;
	aleng = 0;
	switch( Q_ATYP ){
		case 1: aleng = 4; break; /* IPv4 */
		case 3: aleng = getc(fc); break; /* DOMAIN NAME */
		case 4: aleng = 16; break; /* IPv6 */ break;
	}
	if( 0 < aleng )
		IGNRETP fread((char*)Q_HOST,1,aleng,fc);
	qh = Q_HOST;
	switch( Q_ATYP ){
		case 1: sprintf(host,"%d.%d.%d.%d",qh[0],qh[1],qh[2],qh[3]);
			break;
		case 3: QStrncpy(host,(char*)qh,aleng+1); break;
/*
		case 4: host[0] = 0; rep = 0x08; break;
*/
		case 4: strcpy(host,VSA_ltoa(qh,16,AF_INET6)); break;
		default: clearVStr(host); break;
	}

	/*
	port = (getc(fc) << 8) | getc(fc);
	*/
	{
		int hi,lo;
		hi = getc(fc);
		lo = getc(fc);
		port = (hi << 8) | lo;
	}

	syslog_ERROR("[SocksV5-serv] VER[%x] CMD[%x] ATYP[%x] %s:%d\n",
		Q_VER,Q_CMD,Q_ATYP,host,port);

	if( Q_CMD == 1 && lSINGLEP() && strtailstr(host,ACCONN) ){
		AccByConn(ctx,tc,rep,fromcl,tocl,timeout_ms,host,port);
		return 0;
	}

	strcpy(local,"*:*");
	sprintf(remote,"%s:%d",host,port);

	switch( Q_CMD ){
	    case 1: /* CONNECT */

/* MUST CHECK access right to remote */

		svsock = VSocket(ctx,"CNCT/SocksV5",-1,AVStr(local),AVStr(remote),"");
		if( svsock < 0 ){ rep = 0x01; goto ERREXIT; }
		send_resp(tc,rep,bound=local);
/*
		tcp_relay2(timeout_ms,fromcl,svsock,svsock,tocl);
*/
		tcp_relay2(timeout_ms,fromcl,CTX_ToS(ctx),CTX_FromS(ctx),tocl);
		finishClntYY(FL_ARG,ctx);
		finishServYY(FL_ARG,ctx);
		if( CTX_ToS(ctx) != svsock ) close(CTX_ToS(ctx));
		if( CTX_FromS(ctx) != svsock ) close(CTX_FromS(ctx));
		close(svsock);
		if( tocl != fromcl ){ /* close pipe for FTOCL/FFROMCL */
			close(tocl);
			close(fromcl);
		}
		break;

	    case 2: /* BIND */
		viasocks = 0;
		if( GetViaSocks(ctx,host,port) ){
			/*
			syslog_ERROR("#### MUST DO bindViaSocks... %s:%d\n",
				host,port);
			*/
			bsock = bindViaSocks(ctx,host,port,AVStr(rhost),&rport);
			if( bsock < 0 ){
				syslog_ERROR("##bindViaSocks(%s) ERROR\n",
					remote);
			}else{
				viasocks = 1;
				sprintf(local,"%s:%d",rhost,rport);
				syslog_ERROR("##bindViaSocks(%s)=%d [%s]\n",
					remote,bsock,local);
			}
		}
		else
		{
		/*
		 * local port must be derived from DST.PORT, in new protocol ?
		 */
		bsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),AVStr(remote),"listen=1");
		}
		if( bsock < 0 ){ rep = 0x01; goto ERREXIT; }
		send_resp(tc,rep,bound=local);

/* MUST POLL {fromcl,bsock} */

		if( viasocks ){
			if( acceptViaSocks(bsock,AVStr(rhost),&rport) < 0 ){
				svsock = -1;
				syslog_ERROR("##acceptViaSocks() ERROR\n");
			}else{
				svsock = bsock;
				sprintf(remote,"%s:%d",rhost,rport);
				syslog_ERROR("##acceptViaSocks() = [%s]\n",
					remote);
			}
		}else{
		svsock = VSocket(ctx,"ACPT/SocksV5",bsock,AVStr(local),AVStr(remote),"");
		close(bsock);
		}
		if( svsock < 0 ){ rep = 0x01; goto ERREXIT; }

		send_resp(tc,rep,bound=remote);
		/* FTOSV/FFROMSV should be inserted */
		tcp_relay2(timeout_ms,fromcl,svsock,svsock,tocl);
		/* should close FTOSV/FFROMSV pipe here */
		close(svsock);
		break;

	    case 3: /* UDP ASSOCIATE */
		bsock = -1;
		opt = "protocol=udp,noreuseaddr";
		if( viasocks = GetViaSocks(ctx,host,port) ){
			syslog_ERROR("UDP ASSOC via upstream Socks: %s:%d\n",
				host,port);
			VSA_atosa(&qp,port,host);
		}

		/* 9.9.5 set BND.ADDR/PORT, ex. SRCIF=clif.-:0:socks-udp-tocl */
		VSA_atosa(&sif,port,host);
		if( sifset = CTX_VSA_SRCIFfor(ctx,"socks-udp-tocl",&sif) ){
			sprintf(local,"%s:%d",VSA_ntoa(&sif),VSA_port(&sif));
			bsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),CVStr("*:*"),opt);
		}
		if( bsock < 0 && port != 0 ){
			sprintf(local,"%s:%d",host,port);
			bsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),CVStr("*:*"),opt);
		}
		if( bsock < 0 && port != 0 ){
			sprintf(local,"%s:*",host);
			bsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),CVStr("*:*"),opt);
		}
		if( bsock < 0 ){
			sprintf(local,"*:*");
			if( sifset == 0 && strheadstrX(remote,"0.0.0.0:",0) ){
				/* 9.9.5 eq. SRCIF=0.0.0.0:0:socks-udp-tocl */
				strcpy(local,"0.0.0.0"); /* or "__" for IPv6 */
			}
			bsock = VSocket(ctx,"BIND/SocksV5",-1,AVStr(local),AVStr(remote),opt);
			/* BUG: binding local=127.0.0.1:N for
			 * remote=0.0.0.0:0 by hostIFfor() is bad
			 */
		}
		if( bsock < 0 ){ rep = 0x01; goto ERREXIT; }
/*
		if( strncmp(local,"0.0.0.0:",8) == 0 ){
*/
		if( strncmp(local,"0.0.0.0:",8) == 0 || strneq(local,"__:",3) ){
			JStr(clifhp,256);
			JStr(dummy,256);
			JStr(options,256);
			int port;
			if( strneq(local,"__:",3) )
				port = atoi(local+3);
			else
			port = atoi(local+8);
			*(char*)clifhp = *(char*)dummy = 0;
			VSocket(ctx,"Q/SocksV5",fromcl,AVStr(clifhp),AVStr(dummy),options);
			wordscanY(clifhp,AVStr(host),sizeof(host),"^:");
			sprintf(local,"%s:%d",host,port);
		}
		send_resp(tc,rep,bound=local);
		udp_relay_socks(ctx,fromcl,bsock,remote,Q_RSV,viasocks?&qp:0);
		close(bsock);
		if( 0 <= socks_sock ){
			close(socks_sock);
			socks_sock = -1;
		}
		break;

	    default:
		syslog_ERROR("## Command not supported: %x\n",Q_CMD);
		rep = 0x07;
		goto ERREXIT;
	}
	return 0;

ERREXIT:
	send_resp(tc,rep,bound);
	return -1;
}


int RecvFrom(int sock,char buf[],int len,PVStr(froma),int *fromp)
{	VSAddr from;
	int rcc,fromlen;

	fromlen = sizeof(from);
	rcc = SOCKS_recvfrom(sock,ZVStr(buf,len),len,0,(SAP)&from,&fromlen);
	strcpy(froma,VSA_ntoa(&from));
	*fromp = VSA_port(&from);
	return rcc;
}
int SendTo(int sock,PCStr(buf),int len,PCStr(host),int port)
{	VSAddr to;
	int tolen;

	tolen = VSA_atosa(&to,port,host);
	return SOCKS_sendto(sock,buf,len,0,(SAP)&to,tolen);
}

int recvFromA(int sock,PVStr(buf),int len,int flags,PVStr(froma),int *fromp)
{	VSAddr from;
	int rcc,fromlen;

	fromlen = sizeof(from);
	rcc = recvfrom(sock,(char*)buf,QVSSize(buf,len),flags,(SAP)&from,&fromlen);
	strcpy(froma,VSA_ntoa(&from));
	*fromp = VSA_port(&from);
	return rcc;
}
int sendToA(int sock,PCStr(buf),int len,int flags,PCStr(host),int port){
	VSAddr to;
	int tolen;

	tolen = VSA_atosa(&to,port,host);
	return Sendto(sock,buf,len,flags,(SAP)&to,tolen);
}
