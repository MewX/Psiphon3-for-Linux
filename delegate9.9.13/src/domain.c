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
Program:	domain.c (DNS server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960528	created
	9806 origin DNS server and gateway to NIS
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
#include "delegate.h"
#include "fpoll.h"
#include "proc.h"
#include <errno.h>

extern int CHILD_SERNO_MULTI;
extern int CHILD_SERNO;
extern int NUM_CHILDREN;
static int PARASERV = 2;
int iamServer();

#define MAXQSIZ	2048
extern int (*RES_DNSSERVER)(int,int);
extern int (*RES_DNSSEARCH)(PVStr(r),const char*,int,const char*,int);
extern int DNS_dbgvul;
extern int DNS_svtcp;
extern int DNS_cltcp;
static int DNS_acctcp;
static int DNS_tcpsock = -1;
int ACCEPT1(int sock,int isServer,int lockfd,int timeout,PVStr(sockname));

extern int DELEGATE_LastModified;
extern int errorECONNRESET;
#ifndef ECONNRESET
#define ECONNRESET -1
#endif

void udp_relay(Connection *Conn,int clsock);
void RES_nsloopcheck(int mysock);
int service_domain1(Connection *Conn,int sock);
void dns_init();

static void dom1(Connection *Conn,int clsock,int svsock,int ac,char *av[],PCStr(arg))
{
	DELEGATE_LastModified = atoi(arg);
	RES_nsloopcheck(svsock);
	dns_init();
	service_domain1(Conn,svsock);
}
int service_domain(Connection *Conn,int sock,int port)
{
	if( isMYSELF(DST_HOST) && RES_DNSSEARCH ){
		int si;

		RES_nsloopcheck(sock);
		dns_init();

		if( DNS_acctcp ){
			CStr(host,128);
			truncVStr(host);
			DNS_tcpsock = server_open("DNS-SV",AVStr(host),port,1);
		}

		NUM_CHILDREN = PARASERV;
		CHILD_SERNO = 1;
		if( INHERENT_fork() ){
			for( si = 1; si < PARASERV; si++ ){
				if( Fork("DNS") == 0 )
				{
					if( !iamServer() ){
						/* just for LoadStat ... */
						IGNRETZ nice(1);
					}
					break;
				}
				CHILD_SERNO++;
			}
		}else{
			CStr(arg,32);
			sprintf(arg,"%d",DELEGATE_LastModified);
			for( si = 1; si < PARASERV; si++ ){
				execFunc(Conn,-1,sock,(iFUNCP)dom1,arg);
			}
		}
		service_domain1(Conn,sock);
	}else{
		if( !isUDPsock(sock) ){
			int clsock;
			CStr(froma,128);
			CStr(ib,MAXQSIZ);
			CStr(ob,MAXQSIZ);
			int icc,occ;
			int wcc,rcc;
			int svsock;
			const unsigned char *up = (const unsigned char*)ib;

			sv1log("--DNSrelay ACCEPTing from TCP[%d]\n",sock);
			for(;;){
				clsock = ACCEPT1(sock,1,-1,0,AVStr(froma));
				if( clsock < 0 ){
					continue;
				}
				icc = read(clsock,ib,sizeof(ib));
				sv1log("--rc=%d [%x][%x] len=%d\n",
					icc,up[0],up[1],(up[0]<<8)|up[1]);

				svsock = UDP_client_open("DNS","dns",
					DST_HOST,DST_PORT);
				expsockbuf(svsock,0,sizeof(ib));
				wcc = write(svsock,ib+2,icc-2);
				rcc = -1;
				if( wcc < 0 ){
					sv1log("--cannot write to SV\n");
				}else
				if( PollIn(svsock,3*1000) <= 0 ){
					sv1log("--SV timeout\n");
				}else{
					rcc = read(svsock,ob+2,sizeof(ob)-2);
					if( rcc <= 0 ){
						sv1log("--SV rcc=%d\n",rcc);
						goto END1;
					}
					setVStrElem(ob,0,rcc >> 8);
					setVStrElem(ob,1,rcc);
					occ = write(clsock,ob,rcc+2);
				}
				sv1log("--DNSrelay [%d]%s(%d)->[%d](%d)->%d\n",
					clsock,froma,icc,
					svsock,wcc,rcc);
			END1:
				close(svsock);
				close(clsock);
			}
			return 0;
		}
		scan_PERMIT(Conn,"udprelay");
		udp_relay(Conn,sock);
	}
	return 0;
}
extern const char *RES_client;
extern int RES_client_dependent;

int PortLockFd();
int numServPorts();
int pollServPort(int timeout,int *rsockv,int *udpv,int *optv);
int lock_exclusive(int fd);
int lock_unlock(int fd);
int PortLockReopen();

int RecvFromPorts(int *sock,char ib[],int ibsize,PVStr(froma),int *lfromp){
	int sockv[FD_SETSIZE];
	int rdv[FD_SETSIZE];
	int udpv[FD_SETSIZE];
	int ntry,lockfd,lockok,etime,nready,si,sock1,rcc;

	if( numServPorts() <= 1 ){
		rcc = RecvFrom(*sock,ib,ibsize,BVStr(froma),lfromp);
		return rcc;
	}

	lockfd = PortLockFd();
	lockok = 0;
	rcc = -1;
	for( ntry = 0; rcc <= 0 && ntry < 10; ntry++ ){
		if( lockok == 0 ){
			lockok = lock_exclusive(lockfd) == 0;
		}
		nready = pollServPort(0,sockv,udpv,NULL);
		if( nready <= 0 ){
			syslog_ERROR("-- poll failed, errno=%d\n",errno);
			break;
		}
		for( si = 0; si < nready; si++ ){
			sock1 = sockv[si];
			rcc = RecvFrom(sock1,ib,ibsize,BVStr(froma),lfromp);
			if( 0 < rcc ){
				*sock = sock1;
				break;
			}
			syslog_ERROR("-- failed to recv(%d) errno=%d\n",
				sock1,errno);
		}
	}
	if( lockok ){
		lock_unlock(lockfd);
	}
	return rcc;
}

int service_domain1(Connection *Conn,int sock)
/*
{	CStr(ib,2048);
	CStr(ob,2048);
*/
{
	CStr(ib,MAXQSIZ);
	CStr(ob,MAXQSIZ);
	CStr(prevq,MAXQSIZ);

	int icc,occ;
	CStr(froma,128);
	int fromp;
	double Start,Time();
	CStr(msg,128);
/*
	CStr(prevq,2048);
*/
	int prevqlen;
	int prevrlen;
	int repeated;
	double prevTime;
	int done = 0;
	int clsock = -1;
	int rsock = sock;

	if( 1 < numServPorts() ){
		PortLockReopen();
	}
	prevqlen = 0;
	for(;;){
		CHILD_SERNO_MULTI++;
		errno = 0;
		errorECONNRESET = 0;

		if( DNS_acctcp == 0 )
		if( 10 < done && iamServer() ){
			if( PollIn(sock,5*1000) == 0 ){
				putLoadStat(ST_ACC,done);
				putLoadStat(ST_DONE,done);
				put_svstat();
				done = 0;
			}
		}

		if( DNS_acctcp ){
			refQStr(dp,froma);
			clsock = ACCEPT1(DNS_tcpsock,1,-1,0,AVStr(froma));
			if( clsock < 0 ){
				break;
			}
			fromp = 0;
			if( dp = strchr(froma,':') ){
				setVStrEnd(dp,0);
				fromp = atoi(dp+1);
			}
			icc = read(clsock,(char*)ib,sizeof(ib));
		}else{
		/*
		icc = RecvFrom(sock,ib,sizeof(ib),AVStr(froma),&fromp);
		*/
			/*
			icc = RecvFrom(sock,(char*)ib,sizeof(ib),
				AVStr(froma),&fromp);
			*/
			rsock = sock;
			icc = RecvFromPorts(&rsock,(char*)ib,sizeof(ib),
				AVStr(froma),&fromp);
		}

		if( icc <= 0 || strcmp(froma,"0.0.0.0") == 0 ){
			if( errorECONNRESET || errno == ECONNRESET ){
			sv1log("## RecvFrom(%d) = %d, ECONNRESET\n",
				sock,icc);
				/* previous resp. is discarded(Win32) */
				continue;
			}
			sv1log("FATAL RecvFrom(%d) = %d, errno=%d\n",
				sock,icc,errno);
			sleep(10);
			continue;
		}

		VA_setClientAddr(Conn,froma,fromp,1);
		PageCountUpURL(Conn,CNT_TOTALINC,"#total",NULL);

		if( !service_permitted0(froma,fromp,"dns","-",0) )
			continue;

		Start = Time();
		if( icc == prevqlen
		 && bcmp(prevq,ib,icc) == 0
		 && Start-prevTime < 10.0 /* cache expiration time */
		){
			occ = prevrlen;
			sv1log("## QUERY repeated * %d: return cached (%d)\n",
				++repeated,occ);
			/*
			sv1log("## QUERY repeated * %d\n",++repeated);
			*/
		}else{
			RES_client_dependent = 0;
			RES_client = froma;
		occ = (*RES_DNSSEARCH)(AVStr(ob),ib,icc,froma,fromp);
			RES_client = 0;
			if( RES_client_dependent ){
				/* don't cache client dependent result */
			}else
			if( 0 < occ ){
				prevTime = Time();
				Bcopy(ib,prevq,icc);
				prevqlen = icc;
				prevrlen = occ;
				repeated = 0;
			}
		}
		if( 0 < occ )
		{
			int wcc;
			errno = 0;
			if( DNS_acctcp ){
				wcc = write(clsock,ob,occ);
				close(clsock);
			}else{
				/*
				wcc = SendTo(sock,ob,occ,froma,fromp);
				*/
				wcc = SendTo(rsock,ob,occ,froma,fromp);
			/*
			SendTo(sock,ob,occ,froma,fromp);
			*/
			}
			if( wcc != occ ){
				sv1log("## failed resp %d/%d err=%d [%s:%d]\n",
					wcc,occ,errno,froma,fromp);
				prevqlen = 0;
			}
		}
		sprintf(msg,"[%5.3fs] %s:%d ID=%d",Time()-Start,
			froma,fromp,(0xFF&ib[0])<<8|(0xFF&ib[1]));
		sv1log("%s\n",msg);

		/*
		TOTAL_SERVED++;
		*/
		*pTOTAL_SERVED += 1;
		done++;
		if( 10 < done && iamServer() ){
			if( done % 100 == 0 ){
				putLoadStat(ST_ACC,done);
				putLoadStat(ST_DONE,done);
				put_svstat();
				done = 0;
			}
		}
	}
	return 0;
}

extern const char *DNS_DOMAIN;
extern const char *DNS_ORIGIN;
extern const char *DNS_ADMIN;
extern const char *DNS_MX;
extern int   DNS_SERIAL;
extern int   DNS_REFRESH;
extern int   DNS_RETRY;
extern int   DNS_EXPIRE;
extern int   DNS_MINTTL;

void dns_initX();
void dns_init(){
	if( !streq(iSERVER_PROTO,"dns") )
		return;
	dns_initX();
}
void dns_initX(){
	CStr(buf,128);
	const char *dp;
	int init;

	init = 0;
	if( DNS_ORIGIN == NULL ){
		init++;
		GetHostname(AVStr(buf),sizeof(buf));
		sv1log("getFQDN(%s) for DNSCONF=origin: ...\n",buf);
		getFQDN(buf,AVStr(buf));
		sv1log("getFQDN(%s).\n",buf);
		DNS_ORIGIN = StrAlloc(buf);
	}
	if( DNS_DOMAIN == NULL ){
		init++;
		if( dp = strchr(DNS_ORIGIN,'.') )
			DNS_DOMAIN = StrAlloc(dp+1);
		else	DNS_DOMAIN = StrAlloc("");
/*
		else	DNS_DOMAIN = StrAlloc(DNS_ORIGIN);
*/
	}
	if( DNS_ADMIN == NULL ){
		init++;
		DNS_ADMIN = getADMIN1();
	}
	if( DNS_ADMIN && strchr(DNS_ADMIN,'@') ){
		init++;
		strcpy(buf,DNS_ADMIN);
		for( dp = buf; *dp; dp++ )
			if( *dp == '@' )
				*(char*)dp = '.';
		DNS_ADMIN = StrAlloc(buf);
	}

	if( DNS_SERIAL == 0 ){
		init++;
		StrftimeGMT(AVStr(buf),sizeof(buf),"%Y%m%d%H",DELEGATE_LastModified,0);
		DNS_SERIAL = atoi(buf);
	}
	if( DNS_REFRESH == 0 ){ init++; DNS_REFRESH = 3600 * 6; }
	if( DNS_RETRY   == 0 ){ init++; DNS_RETRY   =  600; }
	if( DNS_EXPIRE  == 0 ){ init++; DNS_EXPIRE  = 3600 * 24 * 14; }
	if( DNS_MINTTL  == 0 ){ init++; DNS_MINTTL  = 3600 * 6; }

	if( init ){
		sv1log("DNS_DOMAIN=%s\n", DNS_DOMAIN);
		sv1log("DNS_ORIGIN=%s\n", DNS_ORIGIN);
		sv1log("DNS_ADMIN=%s\n",  DNS_ADMIN);
		sv1log("DNS_SERIAL=%d\n", DNS_SERIAL);
		sv1log("DNS_REFRESH=%d\n",DNS_REFRESH);
		sv1log("DNS_RETRY=%d\n",  DNS_RETRY);
		sv1log("DNS_EXPIRE=%d\n", DNS_EXPIRE);
		sv1log("DNS_MINTTL=%d\n", DNS_MINTTL);
	}
}

static scanListFunc scanconf1(PCStr(conf))
{	CStr(name,128);
	CStr(value,128);
	int ival;

	name[0] = value[0] = 0;
	Xsscanf(conf,"%[^:]:%s",AVStr(name),AVStr(value));
	sv1log("DNSCONF = %s : %s\n",name,value);
	ival = atoi(value);
	ival = (int)Scan_period(value,'s',(double)atoi(value));

	if( strcaseeq(name,"para") ){
		PARASERV = ival;
	}else
	if( strcaseeq(name,"domain") ){
		DNS_DOMAIN = StrAlloc(value);
	}else
	if( strcaseeq(name,"origin") ){
		DNS_ORIGIN = StrAlloc(value);
	}else
	if( strcaseeq(name,"admin") ){
		DNS_ADMIN = StrAlloc(value);
	}else
	if( strcaseeq(name,"serial") ){
		DNS_SERIAL = ival;
	}else
	if( strcaseeq(name,"refresh") ){
		DNS_REFRESH = ival;
	}else
	if( strcaseeq(name,"retry") ){
		DNS_RETRY = ival;
	}else
	if( strcaseeq(name,"expire") ){
		DNS_EXPIRE = ival;
	}else
	if( strcaseeq(name,"minttl") ){
		DNS_MINTTL = ival;
	}else
	if( strcaseeq(name,"mx") ){
		DNS_MX = StrAlloc(value);
	}else
	if( strcaseeq(name,"acctcp") ){
		DNS_acctcp = 1;
	}else
	if( strcaseeq(name,"cltcp") ){
		DNS_cltcp = 1;
	}else
	if( strcaseeq(name,"svtcp") ){
		DNS_svtcp = 1;
	}else
	if( strcaseeq(name,"dbgvul") ){
		DNS_dbgvul = 1;
	}else{
		sv1log("#### unknown [%s]\n",name);
	}
	return 0;
}

void scan_DNSCONF(Connection *Conn,PCStr(conf))
{
	scan_commaList(conf,0,scanListCall scanconf1);
}
