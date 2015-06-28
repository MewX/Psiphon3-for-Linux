/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	nbio.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	980804	extracted from inets.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "log.h"
#include "ysignal.h"

void msleep(int msec);
void Usleep(int);
int getNonblockingIO(int fd);
int setNonblockingIO(int fd,int on);

int file_issock(int fd);
int file_ISSOCK(int fd);
int sock_isconnected(int sock);
int sock_isconnectedX(int sock,int sinonly);
#define sock_isconnected(s)	sock_isconnectedX(s,0)

int IsSolaris();
int IsWindows95();
int IsBOW1_5();

int SLOW_CONN = 4000;
int PCON_TIMEOUT = 30;
int PCON_PERSERV = 2;
int PollOuts(int timeout,int fc,int fv[],int rv[]);
int inoutReady(int sock,int inout);
int dupSocket(int sock);
int setfdowner(int fd,int tid,int tgid);
#define RCODE_RECYC	1

typedef struct {
    const char *sp_what;
	double	sp_Time;
	int	sp_sock;
	int	sp_rcode;
	int	sp_leng;
	VSAddr	sp_addr;
} SockPool;
static SockPool sockPool[16];
static int sockPoolN;
static CriticalSec sockCSC;
int VSA_satoap(VSAddr *sa,PVStr(addrport));

int dumpConnects(FILE *out){
	double Now = Time();
	IStr(saddr,128);
	SockPool *sp;
	int sn = 0;
	int si;

	for( si = 0; si < elnumof(sockPool); si++ ){
		sp = &sockPool[si];
		if( sp->sp_Time == 0 ){
			continue;
		}
		VSA_satoap(&sp->sp_addr,AVStr(saddr));
		fprintf(out,"--CO[%2d][%2d] %5.2f %2d %s %s\n",si,
			sp->sp_sock,Now-sp->sp_Time,
			sp->sp_rcode,sp->sp_what,
			saddr
		);
	}
	return sn;
}
static void abandon(SockPool *sp,int wh){
	close(sp->sp_sock);
	sp->sp_Time = 0;
	sockPoolN--;
}
static int putConnSocket(int orig_sock,int sock,SAP addr,int leng,PCStr(what),int rcode){
	int si;
	int csi = -1;
	SockPool *sp;
	SockPool *osp = 0;
	double Now = Time();
	double oTime;
	int csock = -1;

	oTime = Now;
	setupCSC("putConnSocket",sockCSC,sizeof(sockCSC));
	enterCSC(sockCSC);
	for( si = 0; si < elnumof(sockPool); si++ ){
		sp = &sockPool[si];
		if( sp->sp_Time != 0 ){
			if( sp->sp_Time < oTime )
				osp = sp;
			continue;
		}
		osp = sp;
		csi = si;
		break;
	}
	if( osp ){
		if( osp->sp_Time ){
			LOGX_tcpConAbandon1++;
			abandon(osp,0);
		}
		sockPoolN++;
		setfdowner(sock,0,0);
		osp->sp_what = what;
		osp->sp_Time = Time();
		osp->sp_sock = sock;
		osp->sp_rcode = rcode;
		osp->sp_leng = leng;
		bcopy(addr,&osp->sp_addr,leng);
		if( rcode != RCODE_RECYC ){
			porting_dbg("--putConnSocket(%d) %d[%d]",
				sockPoolN,sock,csi,csock);
			porting_dbg("++putConnSock(%s)[%d] (%d)%d[%d]",
			what,sock,csi,osp->sp_leng,osp->sp_sock);
		}
		syslog_ERROR("--putConnSocket([%d]%d)<-[%d]%d %s %d\n",
			sock,SocketOf(sock),orig_sock,SocketOf(orig_sock),
			what,rcode);
	}
	leaveCSC(sockCSC);
	return 0;
}
int recycleConnSocket(int sock,PCStr(what),int age){
	VSAddr sab;
	int len;

	if( lNOCONNRECYC() ){
		return -1;
	}
	len = sizeof(VSAddr);
	if( getpeername(sock,(SAP)&sab,&len) != 0 ){
		return -1;
	}else{
		LOGX_tcpConRecycled++;
		putConnSocket(sock,dup(sock),(SAP)&sab,len,what,RCODE_RECYC);
		return 0;
	}
}
static int getConnSocket(int sock,SAP addr,int leng,int *rcsock,int *pending){
	int si;
	int csi = -1;
	SockPool *sp;
	int got_csock = -1;
	double Now = Time();
	double Age = 0;
	static int getOk;
	static int getNg;
	int rcode = -1;

	setupCSC("getConnSocket",sockCSC,sizeof(sockCSC));
	enterCSC(sockCSC);
	*pending = 0;
	for( si = 0; si < elnumof(sockPool); si++ ){
		sp = &sockPool[si];
		if( sp->sp_Time == 0 )
			continue;
		if( PCON_TIMEOUT < Now - sp->sp_Time ){
			LOGX_tcpConAbandon2++;
			abandon(sp,1);
			continue;
		}
		if( sp->sp_leng != leng ){
			continue;
		}
		if( bcmp(addr,&sp->sp_addr,leng) != 0
		 && VSA_addrcomp((VSAddr*)addr,&sp->sp_addr) != 0
		){
			continue;
		}
		rcode = sp->sp_rcode;
		if( rcode == RCODE_RECYC ){
			if( /* HTTP && */ inoutReady(sp->sp_sock,1)
			 || !sock_isconnected(sp->sp_sock)
			){
				getNg++;
	/*
	porting_dbg("--getConnSock(%d/%d) age=%.2f [%d] NO-R %d:%d",
	si,sockPoolN,Now-sp->sp_Time,sp->sp_sock,getNg,getOk);
	*/
				LOGX_tcpConAbandon3++;
				abandon(sp,2);
				continue;
			}
			LOGX_tcpConRecycleOk++;
		}else{
			if( inoutReady(sp->sp_sock,2) == 0 ){
				if( PCON_TIMEOUT < Now - sp->sp_Time ){
	porting_dbg("--getConnSock(%d/%d)%s age=%.2f [%d] NO-A",
	si,sockPoolN,sp->sp_what,Now-sp->sp_Time,sp->sp_sock);
					LOGX_tcpConAbandon4++;
					abandon(sp,3);
				}else{
					*pending += 1;
				}
				continue;
			}
			if( !sock_isconnected(sp->sp_sock) ){
	porting_dbg("--getConnSock(%d/%d)%s age=%.2f [%d] NO-B",
	si,sockPoolN,sp->sp_what,Now-sp->sp_Time,sp->sp_sock);
				LOGX_tcpConAbandon4++;
				abandon(sp,3);
				continue;
			}
		}
		getOk++;
	if( rcode != RCODE_RECYC )
	porting_dbg("--getConnSock(%d/%d)%s age=%.2f [%d] OK (%d)",
	si,sockPoolN,sp->sp_what,Now-sp->sp_Time,sp->sp_sock,getOk);
	syslog_ERROR("--getConnSock(%d/%d)%s age=%.2f [%d] OK (%d)\n",
	si,sockPoolN,sp->sp_what,Now-sp->sp_Time,sp->sp_sock,getOk);

		Age = Now - sp->sp_Time;
		sp->sp_Time = 0;
		sockPoolN--;
		csi = si;
		got_csock = sp->sp_sock;
		break;
	}
	leaveCSC(sockCSC);

	if( got_csock < 0 ){
		return -1;
	}

if( rcode != RCODE_RECYC )
porting_dbg("--getConnSocket(%d)[%d]>>>%d[%d]",
sockPoolN,sock,csi,got_csock);

	setfdowner(got_csock,getthreadid(),getthreadgid(0));
	*rcsock = got_csock;
	syslog_ERROR("--getConnSocket([%d]%d)<-[%d]%d %.2f (%d)\n",
		sock,SocketOf(sock),got_csock,SocketOf(got_csock),
		Age,*pending);
	return 0;
}

int connectTO1(int sock,SAP addr,int leng,int timeout,PVStr(cstat))
{	int NB;
	int rcode;
	int nready;
	int serrno;
	double Start = Time();
	int csock;
	int pending = 0;

	if( 0 <= getConnSocket(sock,addr,leng,&csock,&pending) ){
		dup2(csock,sock);
		close(csock);
		LOGX_tcpConPrefOk++;
		sprintf(cstat,"Prf");
		return 0;
	}

	if( timeout == 0 )
	{
		rcode = connect(sock,addr,leng);
		if( rcode != 0 ){
			switch( errno ){
			  case ECONNREFUSED:
			  case ENETUNREACH:
			  case EHOSTUNREACH:
				LOGX_tcpConRefused++;
				break;
			  default:
				LOGX_tcpConTimeout++;
				break;
			}
		}
		return rcode;
	}

	NB = getNonblockingIO(sock);
	if( NB < 0 ){
		syslog_ERROR("connectTO: assume in non-blocking mode\n");
		NB = 0;
	}
	if( !NB ) rcode = setNonblockingIO(sock,1);

	errno = 0;
	rcode = connect(sock,addr,leng);
	serrno = errno;

	if( rcode == 0 ){
		if( !NB ) setNonblockingIO(sock,0);
		return 0;
	}
	if( errno == EISCONN ){
		if( !NB ) setNonblockingIO(sock,0);
		return 0;
	}
	switch( errno ){
	  case ECONNREFUSED:
	  case ENETUNREACH:
	  case EHOSTUNREACH:
		syslog_ERROR("## connect[%d] refused (%d)\n",sock,errno);
		LOGX_tcpConRefused++;
		return -1;
	}

	nready = 0;
	if( lCONNPARA() && 0 < SLOW_CONN && SLOW_CONN < timeout ){
	  /* should poll pending connect() too ... */
	  if( pending ){
	  }
	  nready = PollOut(sock,SLOW_CONN);
	  if( nready == 0 ){
	    if( pending && 0 <= getConnSocket(sock,addr,leng,&csock,&pending) ){
		putConnSocket(sock,dup(sock),addr,leng,"pending",rcode);
		dup2(csock,sock);
		close(csock);
		LOGX_tcpConParaOk++;
		sprintf(cstat,"Pnd");
	    }else
	    if( PCON_PERSERV < pending ){
		/* don't make too many pending connect() to a server */
	    }else{
	      int nsock;
	      nsock = dupSocket(sock);
	      if( 0 <= nsock ){
	        int rdv[2];
		if( !NB ) setNonblockingIO(nsock,1);
		errno = 0;
		rcode = connect(nsock,addr,leng);
		LOGX_tcpConParaTried++;
		if( rcode == 0 ){
			nready = 9;
		}else{
	    		int skv[2];
			skv[0] = sock;
			skv[1] = nsock;
			nready = PollOuts(timeout-SLOW_CONN,2,skv,rdv);
			timeout = 1;
		}
		if( nready == 9 || 0 < nready && rdv[0] == 0 && 0 < rdv[1] ){
			putConnSocket(sock,dup(sock),addr,leng,"overtook",rcode);
			dup2(nsock,sock);
			close(nsock);
			LOGX_tcpConParaOk++;
			sprintf(cstat,"Ovr");
			porting_dbg("## para.conn.%d %d/%d+%d %.2f %d",
				nready,
				LOGX_tcpConParaOk,LOGX_tcpConParaTried,
				LOGX_tcpConSuccess,Time()-Start,errno);
		}else{
			putConnSocket(nsock,nsock,addr,leng,"unused",rcode);
		}
	      }
	    }
	  }
	}

	if( !NB ) setNonblockingIO(sock,0);
	if( nready == 0 ){
		nready = PollOut(sock,timeout);
	}

	/* 9.8.0 get appropriate errno by SO_ERROR in non-blocking connect */
	/*
	if( serrno == EINPROGRESS ){
	*/
	if( serrno == EINPROGRESS
	 || serrno == EWOULDBLOCK /* 9.8.2 Windows returns this */
	){
		int err = 0;
		int len = sizeof(err);

		if( getsockopt(sock,SOL_SOCKET,SO_ERROR,&err,&len) == 0 ){
			syslog_DEBUG("connect[%d] ready=%d, err=%d\n",
				sock,nready,err);
if( err != 0 )
if( err != ECONNREFUSED )
porting_dbg("[%X][%u] connectTO rdy=%d err=%d/%d/%d GOT %d/%d %s %.2f/%d",
TID,getppid(),nready,serrno,EWOULDBLOCK,EINPROGRESS,err,len,
VSA_ntoa((VSAddr*)addr),Time()-Start,timeout);
			switch( err ){
			  case ECONNREFUSED:
			  case ENETUNREACH:
			  case EHOSTUNREACH:
				errno = err;
				LOGX_tcpConRefused++;
				return -1;
			}
		}
		else{
/*
fprintf(stderr,"-- %X connectTO rdy=%d err=%d/%d/%d NG errno=%d\n",
TID,nready,serrno,EWOULDBLOCK,EINPROGRESS,errno);
*/
		}
	}
	if( nready <= 0 ){
		if( *cstat == '-' ){
			/* ( ConnectFlags & COF_TERSE ) */
		}else
		syslog_ERROR("## connect[%d] TIMEOUT(%d) e%d\n",sock,timeout,serrno);
		errno = ETIMEDOUT;
		LOGX_tcpConTimeout++;
		return -1;
	}

if( !sock_isconnected(sock) ){
	msleep(10);
	if( !sock_isconnected(sock) ){
		syslog_ERROR("## connect[%d] failure (%d)\n",sock,errno);
		errno = ETIMEDOUT;
		LOGX_tcpConTimeout++;
		return -1;
	}
	else{
		syslog_ERROR("## connect[%d] delayed success\n",sock);
	}
}

	return 0;
}

int dialupTOX(PCStr(wh),int sock,void *addr,int leng,int timeout,PVStr(cstat));
void putWinStatus(PCStr(fmt),...);
static int dialup(int sock,SAP addr,int leng,int timeout,PVStr(cstat),int rcode){
	int serrno = errno;
	int ccode;
	int nrcode;
	int nerrno;
	int nsock;
	int ri;

	if( !isWindowsCE() ){
		return -1;
	}

	nsock = dupSocket(sock);
	ccode = dialupTOX("CONNECT",sock,addr,leng,timeout,BVStr(cstat));
	if( 0 ){ // no dialup
		goto EXIT;
	}
	setNonblockingIO(nsock,1);
	for( ri = 0; ri < 10; ri++ ){
		nrcode = connect(nsock,addr,leng);
		if( errno == EISCONN ){
			nrcode = 0;
			serrno = 0;
			rcode = 0;
			break;
		}
		if( nrcode == 0 )
			break;
		nerrno = errno;
		msleep(500);
	}
	setNonblockingIO(nsock,0);
	if( nrcode == 0 ){
		dup2(nsock,sock);
		serrno = nerrno;
		rcode = 0;
	}
EXIT:
	close(nsock);
	errno = serrno;
	return rcode;
}
int connectTOX(int sock,SAP addr,int leng,int timeout,PVStr(cstat))
{	int rcode;
	int ri;
	double Start = Time();
	int delay;
	int poolN;

	/* 9.8.2 trial to avoid too slow connect() ... */
	/*
	int expsockbuf(int sock,int in,int out);
	int set_keepalive(int sock,int on);
	void setsockREUSE(int sock,int onoff);
	int setsockSHARE(int sock,int onoff);
	if( isWindowsCE() ){
		set_keepalive(sock,1);
		//expsockbuf(sock,8*1024,8*1024);
		setsockREUSE(sock,1);
		setsockSHARE(sock,1);
	}
	*/

	poolN = sockPoolN;
	LOGX_tcpCon++;
	rcode = connectTO1(sock,addr,leng,timeout,BVStr(cstat));
	if( rcode == 0 ){
		LOGX_tcpConSuccess++;
		delay = (int)((Time()-Start)*1000);
		LOGX_tcpConDelays += delay;
		if( LOGX_tcpConDelayMax < delay )
			LOGX_tcpConDelayMax = delay;

		if( lCONNQUE() )
		if( sockPoolN <= poolN )
		{
			int nsock,nrcode;
			nsock = dupSocket(sock);
			setNonblockingIO(nsock,1);
			nrcode = connect(nsock,addr,leng);
			setNonblockingIO(nsock,0);
			putConnSocket(sock,nsock,addr,leng,"queued",nrcode);
		}
	}
	if( rcode != 0 ){
		switch( errno ){
		  case ECONNREFUSED:
		  case EFAULT:
			/* should be the default */
			break;
		  case EHOSTUNREACH:
		  case ENETUNREACH:
		  default:
			rcode = dialup(sock,addr,leng,timeout,BVStr(cstat),rcode);
			break;
		}
	}
	return rcode;
}
int dialupOnConnect(int sock,SAP addr,int leng,int timeout,PVStr(cstat),int rcode){
	return dialup(sock,addr,leng,timeout,BVStr(cstat),rcode);
}
int connectTO(int sock,SAP addr,int leng,int timeout){
	IStr(cstat,256);
	return connectTOX(sock,addr,leng,timeout,AVStr(cstat));
}

void SetNonblockingIO(PCStr(what),int sock,int on)
{	int onbio,nnbio;

	if( sock < 0 )
		return;

	onbio = getNonblockingIO(sock);
	setNonblockingIO(sock,on);
	nnbio = getNonblockingIO(sock);
	if( onbio != nnbio )
		syslog_DEBUG("NBIO[%s][%d] %d -> %d\n",what,sock,onbio,nnbio);
}

/*
int recvX(int sock,PVStr(buff),int size,int flags){
	struct msghdr mh;
	struct iovec iov[1];
	int rcc;

	bzero(&mh,sizeof(mh));
	mh.msg_iov = iov;
	mh.msg_iov[0].iov_base = (char*)buff;
	mh.msg_iov[0].iov_len = QVSSize(buff,size);
	mh.msg_iovlen = 1;
	rcc = recvmsg(sock,&mh,flags);
	return rcc;
}
*/

int sendOOB(int sock,PCStr(buff),int size)
{
	return send(sock,buff,size,MSG_OOB);
}
int readyOOB(int sock){
	CStr(buff,1);
	return 0 < recv(sock,buff,1,MSG_OOB|MSG_PEEK);
}
int recvOOB(int sock,PVStr(buff),int size)
{
	alertVStr(buff,size);
	if( 0 < recv(sock,(char*)buff,size,MSG_OOB|MSG_PEEK) )
		return recv(sock,(char*)buff,size,MSG_OOB);
	else	return -1;
}
int recvOOBx(int sock,PVStr(buff),int size)
{	int rcode;

	alertVStr(buff,size);
	SetNonblockingIO("relayOOB",sock,1);
	rcode = recv(sock,(char*)buff,size,MSG_OOB);
	SetNonblockingIO("relayOOB",sock,0);
	return rcode;
}
/* relay OOB (maybe SYNCH signal of Telnet) */
int relayOOB(int in,int out)
{	CStr(buff,128);
	int rcc;
	int pi,nready;
	CStr(oobb,128);
	int oobx = 0;
	int noob = 0;

/*
	msleep(1);
	SetNonblockingIO("relayOOB",in,1);
	rcc = recvOOB(in,AVStr(buff),sizeof(buff));
	SetNonblockingIO("relayOOB",in,0);
	if( rcc != 1 )
		return 0;
*/
	SetNonblockingIO("relayOOB",in,1);
	oobx = 0;
	rcc = recv(in,buff,sizeof(buff),MSG_PEEK|MSG_OOB);
	if( 0 < rcc ){
		rcc = recv(in,oobb+oobx,sizeof(oobb)-oobx,MSG_OOB);
		oobx += rcc;
		while( 0 < withOOB(in) ){
			errno = 0;
			rcc = recv(in,buff,sizeof(buff),MSG_PEEK);
			/* recv() even with MSG_PEEK seems to clear
			 * "exceptfds" in select()
			 */
			if( rcc < 0 && errno == EAGAIN ){
				syslog_ERROR("relay OOB: EAGAIN\n");
				msleep(1);
			}else
			if( 0 < rcc && 0 < withOOB(in) ){
				/* maybe skipping non-OOB before OOB ... */
				CStr(vb,32);
				refQStr(vp,vb);
				int i;
				for( i = 0; i < rcc; i++ ){
					if( sizeof(vb) <= (vp-vb)+3 ){
						break;
					}
					if( 0 < i ) setVStrPtrInc(vp,' ');
					sprintf(vp,"%02X",0xFF&buff[i]);
					vp += strlen(vp);
				}
				syslog_DEBUG("relay pre-OOB: %d [%s]\n",rcc,vb);
				rcc = recv(in,buff,sizeof(buff),0);
				noob += rcc;
				send(out,buff,rcc,0);
			}else{
				break;
			}
		}
	}
	if( 0 <= oobx ){
		send(out,oobb,oobx,MSG_OOB);
		syslog_DEBUG("relay OOB: [%d]->[%d] %dbytes (%02X)\n",
			in,out,oobx,oobb[0]&0xFF);
	}
	SetNonblockingIO("relayOOB",in,0);
	return oobx;


	syslog_DEBUG("relay OOB: [%d]->[%d] %dbytes (%x)\n",
		in,out,rcc,buff[0]&0xFF);
	sendOOB(out,buff,rcc);

	/* if the protocol is Telnet,
	 *  in-band data should be ignored until the MARK(242) ... */
	for( pi = 0; pi < 50; pi++ ){
		if( nready = PollIn(in,1) )
			break;
		msleep(10);
	}
	syslog_DEBUG("relay OOB: nready=%d after %dms\n",nready,pi*10);

	return 1;
}
int IsConnected(int sock,const char **reason);
int Peek1(int sock){
	CStr(buf,1);

	if( isWindowsCE() ){
		if( IsConnected(sock,NULL) ){
			return 1; /* no MSG_PEEK on WinCE */
		}
	}
#ifdef __APPLE__
	/*
	 * MacOSX (Darwin7) do recv(PIPE) without failure
	 * MacOSX (Darwin8) do recv(PIPE,MSG_PEEK) ignoring MSG_PEEK
	 */
	if( file_issock(sock) < 0 ){
		fprintf(stderr,"[%d]## Peek1(%d) NOT SOCKET\n",getpid(),sock);
		syslog_ERROR("## Peek1(%d) NOT SOCKET\n",sock);
		return -1;
	}
#endif

	return recv(sock,buf,1,MSG_PEEK);
}
int recvPEEK(int sock,PVStr(buf),int size){
	return recv(sock,(char*)buf,QVSSize(buf,size),MSG_PEEK);
}

int Send(int s,PCStr(buf),int len)
{	int wcc;

	wcc = send(s,buf,len,0);
	return wcc;
}

/*
 * 991112 extracted from tcprelay.c
 */
int dump_tcprelay = 0;
static void bdump(int src,int dst,PCStr(buf),int rcc)
{	int rc,ch;

	printf("[%2d->%2d](%d) ",src,dst,rcc);
	for( rc = 0; rc < rcc; rc++ ){
		ch = buf[rc] & 0xFF;
		if( 0x21 <= ch && ch <= 0x7E )
			printf("%c",ch);
		else	printf(".");
	}
	printf(" ");
	for( rc = 0; rc < rcc; rc++ ){
		if( rc != 0 ) printf(" ");
		ch = buf[rc] & 0xFF;
		printf("%02x",ch);
	}
	printf("\n");
}

static int relay1(PCStr(arg),int src,int dst,int *rccp,int *wccp);
int simple_relayTimeout(int src,int dst,int timeout)
{	int rcc,wcc,rcc1,wcc1,nio;

	rcc = wcc = 0;
	for( nio = 0;; nio++ ){
		if( !IsWindows95() || file_ISSOCK(src) )
		if( timeout != 0 )
		if( PollIn(src,timeout) <= 0 )
			break;
		if( relay1(NULL,src,dst,&rcc1,&wcc1) <= 0 )
			break; 
		rcc += rcc1;
		wcc += wcc1;
	}
	syslog_ERROR("simple_relay [%d -> %d] = (%d -> %d) / %d\n",
		src,dst,rcc,wcc,nio);
	return rcc;
}

int simple_relayfTimeout(FILE *src,FILE *dst,int timeout)
{	int rcc,wcc,ch;

	for( rcc = 0; READYCC(src); rcc++ ){
		ch = getc(src);
		if( ch == EOF )
			return rcc;
		putc(ch,dst);
	}
	fflush(dst);
	syslog_ERROR("simple_relayf [%d -> %d] = %d\n",
		fileno(src),fileno(dst),rcc);
	return rcc + simple_relayTimeout(fileno(src),fileno(dst),timeout);
}

int getsockbuf(int sock,int *in,int *out);
int expsockbuf(int sock,int in,int out);
static int enwrite(int isize,int src,int dst1,PCStr(buf),int rcc){
	int wc1;
	int ois,oos,nis,nos;

	wc1 = write(dst1,buf,rcc);
	if( 0 <= wc1 )
		return wc1;
	if( errno != EMSGSIZE )
		return wc1;

	/* too large UDP ? */
	getsockbuf(dst1,&ois,&oos);
	expsockbuf(dst1,0,isize);
	getsockbuf(dst1,&nis,&nos);
	syslog_ERROR("## relay1 write failed: %d/%d errno=%d\n",wc1,rcc,errno);
	syslog_ERROR("## relay1 sockbuf[%d] %d -> %d\n",dst1,oos,nos);
	errno = 0;
	wc1 = write(dst1,buf,rcc);
	syslog_ERROR("## relay1 write retry: %d/%d errno=%d\n",wc1,rcc,errno);
	return wc1;
}
static int writes(int isize,int src,int dst1,PCStr(buf),int rcc,int *wc1p){
	int wcc;
	int wc1;

	wcc = 0;
	while( wcc < rcc ){
		wc1 = enwrite(isize,src,dst1,buf+wcc,rcc-wcc);
		if( 3 <= LOGLEVEL || wc1 != rcc ){
			syslog_ERROR("relay1[%d<-%d] %d/%d\n",dst1,src,wc1,rcc);
		}
		if( wc1 <= 0 )
			break;
		/* might be in non-blocking */
		wcc += wc1;
	}
	*wc1p = wc1;
	return wcc;
}
static int lastpackLeng;
static char lastpack[8];
int relay_tee(PCStr(arg),int src,int dst1,int dst2,int *rccp,int *wccp1,int *wccp2)
{	int rcc,wcc,wc1;
/*
	CStr(buf,0x4000);
*/
	CStr(buf,0x10000);
	int isize = 0x4000;

	*wccp1 = 0;
	if( wccp2 ) *wccp2 = 0;

	/*
	rcc = read(src,buf,sizeof(buf));
	*/
	rcc = read(src,buf,QVSSize(buf,isize));
	if( rcc <= 0 && 0 <= top_fd(src,0) ){
		int pop_fd(int fd,int rw);
		if( pop_fd(src,0) ){
			syslog_ERROR("relay_tee(%d) -> pop_fd()\n",src);
			errno = EAGAIN;
			*rccp = 0;
			return -1;
		}
	}
	*rccp = rcc;
	if( rcc <= 0 )
	{
		lastpackLeng = rcc;
		bzero(lastpack,sizeof(lastpack));
		return rcc;
	}

	lastpackLeng = rcc;
	bcopy(buf,lastpack,8<rcc?8:rcc);

	if( dump_tcprelay )
		bdump(src,dst1,buf,rcc);

	/*
	wcc = 0;
	while( wcc < rcc ){
		wc1 = write(dst1,buf,rcc);
		if( wc1 <= 0 )
			break;
		wcc += wc1;
	}
	*/
	wcc = writes(isize,src,dst1,buf,rcc,&wc1);
	*wccp1 = wcc;
	if( dst2 < 0 || wc1 <= 0 )
		return wc1;

	/*
	wcc = 0;
	while( wcc < rcc ){
		wc1 = write(dst2,buf,rcc);
		if( wc1 <= 0 )
			break;
		wcc += wc1;
	}
	*/
	wcc = writes(isize,src,dst2,buf,rcc,&wc1);
	*wccp2 = wcc;
	return wc1;
}
static int relay1(PCStr(arg),int src,int dst,int *rccp,int *wccp)
{
	return relay_tee(arg,src,dst,-1,rccp,wccp,NULL);
}

#define IGN_EOF	1
int RELAYS_IGNEOF;

int SILENCE_TIMEOUT;

RelayCtrl relayCtrlBuf;
RelayCtrl *relayCtrlG = &relayCtrlBuf;

void sigURG(int sig){
	fprintf(stderr,"------- got SIGURG\n");
}

static int isSSLrecord(unsigned PCStr(up),PCStr(spack),int rcc,int fd){
	int sslv = 0;
	int len;
	int nready = 0;

	if( 0x14 <= up[0] && up[0] <= 0x17 && up[1] == 3 ){
		len = 5 + ((up[3] <<8 ) | up[4]);
		sslv = 3;
	}else{
		if( up[0] & 0x80 ){
			len = 2 + (((up[0] & 0x7F) << 8) | up[1]);
		}else{
			len = 3 + (((up[0] & 0x3F) << 8) | up[1]);
		}
		sslv = 2;
	}

	if( len <= rcc ){
		syslog_DEBUG("# SSL record head[%s] SSL%d %d/%d\n",
			spack,sslv,rcc,len);
	}else{
		if( PollIn(fd,1000) <= 0 ){
			sslv = -sslv;
		}
		if( isupper(up[0]) && isupper(up[1]) && isupper(up[2]) ){
			/* maybe bair HTTP, should be sslv == 0 ? */
			syslog_DEBUG("# non-SSL record [%s] SSL%d %d%c/%d\n",
				spack,sslv,rcc,0<nready?'+':'?',len);
		}else
		syslog_ERROR("# SSL record head[%s] SSL%d %d%c/%d\n",
			spack,sslv,rcc,0<nready?'+':'?',len);
	}
	return sslv;
}
int SSL_isrecord(int fd,int timeout){
	CStr(buf,8);
	unsigned char *up = (unsigned char *)buf;
	CStr(spack,64);
	int rcc;
	int sslv;

	if( PollIn(fd,timeout) <= 0 ){
		return 0;
	}
	bzero(buf,sizeof(buf));
	rcc = recvPEEK(fd,AVStr(buf),sizeof(buf));
	if( rcc <= 0 ){
		return 0;
	}
	sprintf(spack,"%2X %2X %2X %2X %2X",up[0],up[1],up[2],up[3],up[4]);
	syslog_DEBUG("SSL_isrecord? %d [%s]\n",rcc,spack);
	sslv = isSSLrecord((const unsigned char*)buf,spack,rcc,fd);
	if( sslv == 3 ){
		return 1;
	}
	return 0;
}

static int toBeBroken(RelayCtrl *relayCtrl,int fdc,int fdv[]){
	/*
	unsigned char b[4];
	*/
	unsigned char b[5];
	int rcc;
	int fi;
	int fd;

	if( !IsAlive(fdv[0]) )
	{
		return 0;
	}
	if( !IsAlive(fdv[1]) )
	{
		return 0;
	}
	for( fi = 0; fi < 2; fi++ ){
		fd = fdv[fi];
		/*
		rcc = recv(fd,(char*)b,1,MSG_PEEK);
		syslog_ERROR(
		"## EXIT relaysx: not half_duplex ? [%d] %d[%X]\n",fd,rcc,b[0]);
		*/
		rcc = recv(fd,(char*)b,sizeof(b),MSG_PEEK);
		syslog_ERROR(
		"## EXIT relaysx: not half_duplex ? [%d] %d[%X][%X][%X][%X][%X]%d\n",
			fd,rcc,b[0],b[1],b[2],b[3],b[4],(b[3]<<8)|b[4]);

		if( b[1] == 3 )
		if( b[0] == 0x15 ){ /* SSL_RT_ALERT */
			syslog_ERROR(
			"## relaysx: thru SSL ALERT [%d] %d[%X]\n",fd,rcc,b[0]);
			return 0;
		}
	}

	/* testing server-side packet */
	if( b[0] == 0x17 ) /* SSL DATA */
	if( b[1] == 3 ){
		RELAY_num_paras++;
		syslog_ERROR(
		/*
		"## relaysx: not half-dup, pipeline? #%d (%d/%d)\n",
		*/
		"## don't EXIT relaysx: not half-dup, pipeline? #%d (%d/%d)\n",
			RELAY_num_turns,RELAY_num_paras,RELAY_max_paras);
		if( RELAY_num_paras <= RELAY_max_paras ){
			return 0;
		}
	}
	RELAY_stat = RELAY_NOTHALFDUP;
	if( lCONNECT() )
	fprintf(stderr,
	"--{c} EXIT relaysx: not half_duplex ? [%d] %d[%X][%X][%X][%X][%X]%d\n",
			fd,rcc,b[0],b[1],b[2],b[3],b[4],(b[3]<<8)|b[4]);
	return 1;
}
static int concat(RelayCtrl *relayCtrl,int s1,int nx,int tl,int rcode,int nready){
	int oready = 0;
	int timeout;
	double St;

	St = Time();
	if( 0 < rcode )
		oready = inputReady(s1,NULL);
	else	oready = 0;
	if( 0 < rcode ){
		if( oready ){
			syslog_DEBUG("## relaysx[%d]: concat+%d 0.000 %d /%d\n",
				s1,nx+1,tl,nready);
			return 1;
		}

		timeout = RELAY_concat;
		if( 0 < timeout && 0 < PollIn(s1,timeout) ){
			syslog_DEBUG("## relaysx[%d]: concat+%d %.3f %d /%d\n",
				s1,nx+1,Time()-St,tl,nready);
			return 2;
		}
	}
	if( 0 < nx ){
		syslog_DEBUG("## relaysx[%d]: concat*%d %.3f %d /%d %d\n",
			s1,nx,Time()-St,tl,nready,rcode);
	}
	return 0;
}

int RELAY_threads_timeout = 0;
int idlethreads();
int relaysxX(RelayCtrl *relayCtrl,int timeout,int sdc,int sdv[][2],int sdx[],int rccs[],IFUNCP funcv[],void *argv[]);
void relaysx(int timeout,int sdc,int sdv[][2],int sdx[],int rccs[],IFUNCP funcv[],void *argv[])
{
	relaysxX(relayCtrlG,timeout,sdc,sdv,sdx,rccs,funcv,argv);
}
int relaysxX(RelayCtrl *relayCtrl,int timeout,int sdc,int sdv[][2],int sdx[],int rccs[],IFUNCP funcv[],void *argv[])
{	int fi;
	int pc,pi,pfv[32],pxv[32];
	int fds[32],errv[32],rfds[32];
	int isreg[32];
	int wccs[32];
	int sdxb[32];
	int cntv[32];
	int rcode,rcc,wcc;
	IFUNCP funcvb[32];
	void *argvb[32];
	int nready;
	double Lastin[32],Now,Timeout,Idlest,Time();
	double Start;
	int timeouti;
	int prepi;
	int fj;
	int dobreak;
	int packs;
	relayCB cb;
	int otimeout = timeout;

	RELAY_stat = 0;
	if( SILENCE_TIMEOUT )
	syslog_ERROR("relays(%d) start: TIMEOUT=io:%ds,silence:%ds\n",
		sdc,timeout/1000,SILENCE_TIMEOUT);
	else
	syslog_ERROR("relays(%d) start: timeout=%dmsec\n",sdc,timeout);
	if( lMULTIST()){
		if( RELAY_threads_timeout ){
			syslog_ERROR("relays thread (%d/%d) timeout=%d <= %d\n",
				actthreads(),numthreads(),
				RELAY_threads_timeout,timeout/1000);
			timeout = RELAY_threads_timeout * 1000;
		}
	}

	if( funcv == NULL ){
		funcv = funcvb;
		for( fi = 0; fi < sdc; fi++ )
			funcv[fi] = NULL;
	}
	if( argv == NULL ){
		argv = argvb;
		for( fi = 0; fi < sdc; fi++ )
			argv[fi] = NULL;
	}

	Now = Time();
	Start = Now;
	for( fi = 0; fi < sdc; fi++ ){
/*
syslog_ERROR("#### NODELAY\n");
set_nodelay(sdv[fi][1],1);
*/
		fds[fi] = sdv[fi][0];
		isreg[fi] = file_isreg(fds[fi]);
		errv[fi] = 0;
		rccs[fi] = 0;
		cntv[fi] = 0;
		wccs[fi] = 0;
		Lastin[fi] = Now;
		if( funcv[fi] == NULL )
			funcv[fi] = (IFUNCP)relay1;

/*
fcntl(fds[fi],F_SETOWN,getpid());
signal(SIGURG,sigURG);
*/

		if( sdx == NULL ){
			sdxb[fi] = 0;
			if( RELAYS_IGNEOF ){
				if( file_issock(sdv[fi][0]) < 0 )
					sdxb[fi] |= IGN_EOF;
			}
		}
	}
	if( sdx == NULL )
		sdx = sdxb;

	RELAY_num_turns = 0;
	dobreak = 0;
	prepi = -1;
	packs = 0;
	for(;;){
	    pc = 0;
	    Idlest = Now = Time();
	    for( fi = 0; fi < sdc; fi++ ){
		if( errv[fi] == 0 ){
			pfv[pc] = fds[fi];
			pxv[pc] = fi;
			pc++;
		}
		if( Lastin[fi] < Idlest ){
			Idlest = Lastin[fi];
		}
	    }
	    if( pc == 0 )
		break;

	    if( lSINGLEP() ){
		int nith;
		/* with no idle threads ... and ready to accept()? */
		/* 9.9.7 this restriction became less necessary with http-sp */
		if( lMULTIST() && RELAY_threads_timeout ){
			/* 9.9.8 for CONNECT/yyshd */
		}else
		if( (nith = idlethreads()) < 3 ){
			int ntimeout = (10+nith*2)*1000;
			nready = PollIns(1,pc,pfv,rfds);
			if( nready == 0 )
			if( ntimeout < timeout ){
				syslog_ERROR("shorten timeout %.2f <= %.2f (%d/%d)\n",
					ntimeout/1000.0,timeout/1000.0,
					nith,actthreads());
				timeout = ntimeout;
			}
		}
	    }

	    errno = 0;

	    if( RELAY_idle_cb ){
		int cbtime;

		nready = PollIns(1,pc,pfv,rfds);
		if( nready )
			goto POLLED;

		if( cb = RELAY_idle_cb ){
			cbtime = (*cb)(relayCtrl,Now-Start,RELAY_num_turns);
		    if( cbtime <= 0 ){
			nready = 0;
			syslog_ERROR("## relaysx: idle_cb timeout %d/%.2f %X\n",
				cbtime,Now-Start,xp2i(RELAY_idle_cb));
		    }else{
			if( timeout < cbtime )
				cbtime = timeout;
			nready = PollIns(cbtime,pc,pfv,rfds);
			if( nready ){
				goto POLLED;
			}
		    }
			if( cb = RELAY_idle_cb ){
				Now = Time();
				(*cb)(relayCtrl,Now-Start,RELAY_num_turns);
			}
		}
	    	errno = 0;
	    }
	    if( SILENCE_TIMEOUT ){
		timeouti = (int)(1000*(SILENCE_TIMEOUT - (Now-Idlest)));
		if( timeouti <= 0 )
			break;
		if( timeouti <= timeout ){
			nready = PollIns(timeouti,pc,pfv,rfds);
			goto POLLED;
		}
	    }
if(0)
	    if( dobreak ){
		/* shorten the timeout of the connection to be broken */
		timeouti = 1000*2;
		if( timeouti <= timeout ){
			syslog_ERROR("## EXIT relaysx: shorten timeout %d\n",
				timeouti);
			nready = PollIns(timeouti,pc,pfv,rfds);
			goto POLLED;
		}
	    }

	    if( 0 <= RELAY_getxfd() ){
		int elp,rem,to1;
		elp = 0;
		rem = timeout;
		for( rem = timeout; 0 < rem; rem -= to1 ){
			if( 200 < rem )
				to1 = 200;
			else	to1 = rem;
	    		nready = PollIns(to1,pc,pfv,rfds);
			if( nready ){
				break;
			}
			if( inputReady(RELAY_getxfd(),0) ){
				if( lCONNECT() )
		fprintf(stderr,"--{c} relaysx: xfd ready: %d/%d/%d/%d\n",
					to1,rem,elp,timeout);
				if( 400 < rem ){
					rem = 400;
				}
			}
			elp += to1;
	    	}
	    }else
	    nready = PollIns(timeout,pc,pfv,rfds);
	/*
should ignore EINTR, by SIGSTOP/SIGCONT
	    if( nready < 0 && errno == EINTR ){
		continue;
	    }
	*/
POLLED:
/*
	    if( nready == 0 && errno == 0 ){
*/
	    if( nready == 0 && errno == 0 || gotOOB(-1) ){
		int fi,sync;
		int oob = 0;

if(nready==0)
syslog_ERROR("-- relaysx: pc=%d nready==0 errno==%d OOB=%d (%.2f)\n",pc,errno,
	gotOOB(-1),Time()-Idlest);

		if( nready == 0 && errno == 0 ){
			syslog_ERROR("relaysx: TIMEOUT=io:%.2f (%.2f)\n",
				timeout/1000.0,Time()-Start);
		}

		sync = 0;
		for( fi = 0; fi < sdc; fi++ )
		{
			if( !isreg[fi] )
			if( withOOB(sdv[fi][0]) )
			{
			oob++;
			sync += relayOOB(sdv[fi][0],sdv[fi][1]);
				if( sync == 0 && isWindowsCE() ){
					/* 9.9.7 no-OOB on WinCE */
					int ifd,alv;
					ifd = sdv[fi][0];
					alv = IsAlive(ifd);
 syslog_ERROR("non-OOB [%d] alive=%d, rdy=%d,err=%d\n",ifd,alv,nready,errno);
					goto RELAYS; /* to detect EOF */
				}
			}
		}
		if( oob ){
		if( sync )
			continue;

		Usleep(1);
		nready = PollIns(1,pc,pfv,rfds);
		if( 0 < nready ){
			syslog_ERROR("## tcprelay: ignore OOB? rdy=%d/%d,oob=%d\n",nready,pc,oob);
			if( 1 ){
			    /* 9.9.7 break loop on shutdown socket (FreeBSD8) */
			    for( fi = 0; fi < sdc; fi++ ){
				int ifd = sdv[fi][0];
				if( !isreg[fi] && !IsAlive(ifd) ){
 syslog_ERROR("non-OOB [%d] Not-alive, rdy=%d,err=%d\n",ifd,nready,errno);
					goto RELAYS;
				}
			    }
			}
			continue;
		}
		}
	    }
	RELAYS:
	    if( nready <= 0 )
		break;

	    if( RELAY_half_dup ){
		if( 0 < RELAY_max_paras || 1 < RELAY_concat ){
			/* be tolerant about non-half-dup */
		}else
		/* to more strictly checking non-half_dup */
		if( nready < pc ){
			Usleep(1000);
			nready = PollIns(1,pc,pfv,rfds);
		}
		if( nready == pc ){
			if( 2 <= pc && toBeBroken(relayCtrl,pc,pfv) ){
				/*
			syslog_ERROR("## EXIT relaysx: not half_duplex\n");
			RELAY_stat = RELAY_NOTHALFDUP;
			goto EXIT;
				*/

		fj = pxv[0<prepi?prepi:0];
		syslog_ERROR("## EXIT relaysx: not half_duplex %d[%d] %d/%d\n",
			RELAY_num_turns,fj,rccs[fj],cntv[fj]);

				dobreak = 3;
			}
		}
	    }
	    for( pi = 0; pi < pc; pi++ ){
		if( 0 < rfds[pi] ){
			int pushed;
			int nx = 0;
			int tl = 0;
		RELAY1:
			if( RELAY_half_dup && nready == pc ){
				if( pi != prepi ){
					/* postpone for serialize,
					 * relay as half-dup as possible
					 */
					continue;
				}
			}
			fi = pxv[pi];
			if( pi != prepi ){
				if( dobreak ){
				/*
				syslog_ERROR("## EXIT relaysx: %d\n",dobreak);
				*/
		fj = pxv[0<prepi?prepi:0];
		syslog_ERROR("## EXIT relaysx: break=%d %d [%d] %d/%d\n",
			dobreak,RELAY_num_turns,fj,rccs[fj],cntv[fj]);
					goto EXIT;
				}
				RELAY_num_turns++;
				packs = 0;
			}
			if( RELAY_max_packintvl ){
				if( pi == prepi ){
					double intvl;
					intvl = Time() - Lastin[fi];
					if( RELAY_max_packintvl < intvl ){
						if( RELAY_num_turns <= 5 ){
syslog_ERROR("## %d[%d] max-intvl(%d)<%d\n",
	RELAY_num_turns,pi,(int)(1000*RELAY_max_packintvl),(int)(1000*intvl));
				syslog_ERROR("## %d[%d] tout-pack-intvl<%d\n",
					RELAY_num_turns,pi,(int)(1000*intvl));
						}else
						{
						RELAY_packintvl = intvl;
						dobreak = 1;
						/*
				syslog_ERROR("## EXIT relaysx: max-intvl<%d\n",
					(int)(1000*intvl));
						*/
		fj = pxv[0<prepi?prepi:0];
		syslog_ERROR("## EXIT relaysx: tout-pack-intvl<%d %d [%d] %d/%d\n",
			(int)(1000*intvl),RELAY_num_turns,fj,rccs[fj],cntv[fj]);
						}
					}
				}else{
					if( dobreak )
						goto EXIT;
				}
			}
			if( RELAY_max_turns && pi != prepi ){
				if( Now-Start < RELAY_thru_time ){
				}else
				if( RELAY_max_turns < RELAY_num_turns ){
				syslog_ERROR("## EXIT relaysx: max_turns=%d\n",
					RELAY_num_turns);
					goto EXIT;
				}
			}
			prepi = pi;

			pushed = 0 <= top_fd(sdv[fi][0],0);
			rcode = (*funcv[fi])(argv[fi],sdv[fi][0],sdv[fi][1],&rcc,&wcc);
			Lastin[fi] = Time();
			/*
			rccs[fi] += wcc;
			*/
			rccs[fi] += rcc;
			wccs[fi] += wcc;
			cntv[fi] += 1;

			packs += 1;
			if( RELAY_half_dup /* && RELAY_ssl_only */ ){
				CStr(spack,32);
				unsigned char *up = (unsigned char*)lastpack;
				sprintf(spack,"%2X %2X %2X %2X %2X",
					up[0],up[1],up[2],up[3],up[4]);
				syslog_DEBUG("%2d.%d %2d->%2d %4d [%s]\n",
					RELAY_num_turns,packs,
					sdv[fi][0],sdv[fi][1],rcc,
					spack);

				/* the first packet in the turn of the side
				 * must begin with a heaer of a SSL frame.
				 * (CONNECT for STARTTLS on HTTP might be
				 * allowed...)
				 */
			   if( RELAY_ssl_peek || RELAY_ssl_only ){
				if( RELAY_ssl_peek ){ /* new-140518b */
				    syslog_ERROR("SSL %2d.%d [%d]->[%d] %4d [%s]\n",
					RELAY_num_turns,packs,
					sdv[fi][0],sdv[fi][1],rcc,
					spack);
				}
				if( packs == 1 && 5 <= lastpackLeng ){
					/*
					if( 0x20 < up[0] && up[0] != 0x80 ){
					*/
					if( isSSLrecord(up,spack,lastpackLeng,pfv[fi]) < 0 ){
					    if( RELAY_ssl_only ){ /* mod-140518a */
				syslog_ERROR("## EXIT relaysx: non-SSL [%s]\n",
					spack);
						dobreak = 2;
					    }
					}
				}
				lastpackLeng = 0;

				if( RELAY_half_dup ){
					int s1 = sdv[fi][0];
					if( concat(relayCtrl,s1,nx,tl,rcode,nready) ){
						nx++;
						tl += rcode;
						goto RELAY1;
					}
				}
			    }
			}

			if( pushed && rcode == -1 && errno == EAGAIN ){
				syslog_ERROR("## relaysx() pop_fd:%d\n",
					sdv[fi][0]);
			}else
			if( rcode <= 0 ){
				syslog_ERROR(
					"relays[%d]: [%d->EOF] %d(%di+%do)\n",
					fi,fds[fi],rcode,rcc,wcc);
				if( sdx == NULL || (sdx[fi] & IGN_EOF) == 0 )
					goto EXIT;
				else	errv[fi] = 1;
			}
		}
	    }
	}
EXIT:
	for( fi = 0; fi < sdc; fi++ )
		syslog_ERROR("relays[%d]: [%d->%d] %d bytes / %d -> %d\n",fi,
			sdv[fi][0],sdv[fi][1],rccs[fi],cntv[fi],wccs[fi]);
	/*
		syslog_ERROR("relays[%d]: [%d->%d] %d bytes / %d\n",fi,
			sdv[fi][0],sdv[fi][1],rccs[fi],cntv[fi]);
	*/
	return 0;
}
void relays(int timeout,int sdc,int sdv[][2],int rccs[])
{
	relaysx(timeout,sdc,sdv,NULL,rccs,NULL,NULL);
}
void tcp_relay2(int timeout,int s1,int d1,int s2,int d2)
{	int sdv[2][2];
	int rccs[2];

	sdv[0][0] = s1;
	sdv[0][1] = d1;
	sdv[1][0] = s2;
	sdv[1][1] = d2;
	relays(timeout,2,sdv,rccs);
}
void relay2_cntl(int timeout,int s1,int d1,int s2,int d2,int s3,int d3,IFUNCP cntlfunc,void *arg)
{	int sdv[3][2];
	int rccs[3];
	IFUNCP fnv[3]; /**/
	void *agv[3]; /**/

	sdv[0][0] = s1;
	sdv[0][1] = d1;
	fnv[0] = 0;
	agv[0] = 0;

	sdv[1][0] = s2;
	sdv[1][1] = d2;
	fnv[1] = 0;
	agv[1] = 0;

	sdv[2][0] = s3;
	sdv[2][1] = d3;
	fnv[2] = cntlfunc;
	agv[2] = arg;

	relaysx(timeout,3,sdv,NULL,rccs,fnv,agv);
}



#if defined(sun) && !defined(NC_TPI_CLTS)
#define SunOS4bin 1 /* this binary is compiled on SunOS4.X */
#else
#define SunOS4bin 0
#endif
int Getsockopt(int s,int level,int optname,char optval[],int *optlen)
{
	int rcode;

	if( IsBOW1_5() ){
		syslog_DEBUG("BOW1.5: ignore getsockopt(%d,%x)...\n",s,optname);
		return -1; /* avoid a bug of BOW1.5 ... */
	}
	rcode = getsockopt(s,level,optname,optval,optlen);
	if( rcode == 0 && optname == SO_TYPE && SunOS4bin && IsSolaris() ){
		switch( *(int*)optval ){
			case SOCK_DGRAM:  *(int*)optval = SOCK_STREAM; break;
			case SOCK_STREAM: *(int*)optval = SOCK_DGRAM;  break;
		}
	}
	return rcode;
}
int Setsockopt(int s,int level,int optname,PCStr(optval),int optlen)
{
	if( level == SOL_SOCKET ){
		switch( optname ){
			case SO_REUSEADDR:
				break;
			case SO_RCVBUF:
			case SO_SNDBUF:
				break;
		}
	}
	return setsockopt(s,level,optname,optval,optlen);
}
#define GETsockopt(s,l,o,v,n)	Getsockopt(s,l,o,(char*)v,n)
#define SETsockopt(s,l,o,v,n)	Setsockopt(s,l,o,(char*)v,n)

int getsocktype(int sock)
{	int type,len;

	len = sizeof(type);
	if( GETsockopt(sock,SOL_SOCKET,SO_TYPE,&type,&len) == 0 )
		return type;
	return -1;
}
int isUDPsock(int sock)
{	int type;

	type = getsocktype(sock);
	return type == SOCK_DGRAM;
}
int file_ISSOCK(int fd)
{
	return 0 <= getsocktype(fd);
}
int file_issock(int fd)
{	int ISSOCK;

	if( isatty(fd) || file_isreg(fd) )
		return -1;

	ISSOCK = file_ISSOCK(fd);
	if( 0 < ISSOCK )
		return ISSOCK;
	if( 0 < getsocktype(fd) )
		return 1;
	return -1;
}

#if defined(SOL_IP) && defined(EOPNOTSUPP)
#define SO_ORIGINAL_DST 80 /* <linux/netfilter_ipv4.h> */
#define SO_ORIGINAL_SRC 81 /* <linux/netfilter_ipv4.h> */
static int withOD;
int withORIGINAL_DST(){
	return 1;
}
int getorigaddr(int sock,VSAddr *Addr){
	int rcode;
	int len;

	bzero(Addr,sizeof(VSAddr));
	if( withOD < 0 ){
		return -1;
	}
	len = sizeof(struct sockaddr_in);
	rcode = getsockopt(sock,SOL_IP,SO_ORIGINAL_DST,Addr,&len);
	return rcode;
}
int getorigdst(int sock,struct sockaddr *dst,int *dstlen){
	int rcode;
	rcode = getsockopt(sock,SOL_IP,SO_ORIGINAL_DST,dst,dstlen);
	return rcode;
}
int getorigsrc(int sock,struct sockaddr *src,int *srclen){
	int rcode;
	rcode = getsockopt(sock,SOL_IP,SO_ORIGINAL_SRC,src,srclen);
	return rcode;
}
#else
int withORIGINAL_DST(){ return 0; }
int getorigaddr(int sock,VSAddr *Addr){
	bzero(Addr,sizeof(VSAddr));
	return -1;
}
int getorigdst(int sock,struct sockaddr *dst,int *dstlen){
	if( lORIGDST() ){
		/* 9.9.1 ipfw on BSD and MacOSX */
		return getsockname(sock,dst,dstlen);
	}
	return -1;
}
int getorigsrc(int sock,struct sockaddr *src,int *srclen){
	return -1;
}
#endif

void set_nodelay(int sock,int onoff)
{	int ooo,oon,len;

	len = sizeof(ooo);
	GETsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&ooo,&len);
	SETsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&onoff,sizeof(onoff));
	len = sizeof(oon);
	GETsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&oon,&len);
	syslog_DEBUG("TCP_NODELAY[%d] %d -> %d\n",sock,ooo,oon);
}
void set_cork(int sock,int onoff){
	int ooo,oon,len;

#ifdef TCP_CORK
	len = sizeof(ooo);
	GETsockopt(sock,IPPROTO_TCP,TCP_CORK,&ooo,&len);
	SETsockopt(sock,IPPROTO_TCP,TCP_CORK,&onoff,sizeof(onoff));
	len = sizeof(oon);
	GETsockopt(sock,IPPROTO_TCP,TCP_CORK,&oon,&len);
	syslog_DEBUG("TCP_CORK[%d] %d -> %d\n",sock,ooo,oon);
#endif
}
void set_nopush(int sock,int onoff){
	int ooo,oon,len;

#ifdef TCP_NOPUSH
	len = sizeof(ooo);
	GETsockopt(sock,IPPROTO_TCP,TCP_NOPUSH,&ooo,&len);
	SETsockopt(sock,IPPROTO_TCP,TCP_NOPUSH,&onoff,sizeof(onoff));
	len = sizeof(oon);
	GETsockopt(sock,IPPROTO_TCP,TCP_NOPUSH,&oon,&len);
	syslog_DEBUG("TCP_NOPUSH[%d] %d -> %d\n",sock,ooo,oon);
#endif
}
int setsockSHARE(int sock,int onoff)
{
#ifdef SO_REUSEPORT
	return SETsockopt(sock,SOL_SOCKET,SO_REUSEPORT,&onoff,sizeof(onoff));
#else
	return -1;
#endif
}
void setsockREUSE(int sock,int onoff)
{
	SETsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&onoff,sizeof(onoff));
}
int set_keepalive(int sock,int on)
{	int On = 1, No = 0;	
	int Ov = -1, len = sizeof(Ov);

	if( on)
		SETsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &On, sizeof(On));
	else	SETsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &No, sizeof(No));
	GETsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &Ov, &len);
	syslog_DEBUG("KeepAlive[%d] = %d\n",sock,Ov);
	return Ov;
}
int getsockbuf(int sock,int *in,int *out)
{	int len;
	int rcode;

	*in = 0;
	*out = 0;

	len = sizeof(int);
	rcode = GETsockopt(sock, SOL_SOCKET, SO_RCVBUF, in,&len);
	len = sizeof(int);
	rcode = GETsockopt(sock, SOL_SOCKET, SO_SNDBUF, out,&len);
	return rcode;
}
int setsocksndbuf(int sock,int osz){
	int oos;
	int os = osz;
	int len;

	len = sizeof(oos);
	GETsockopt(sock, SOL_SOCKET, SO_SNDBUF, &oos,&len);
	SETsockopt(sock, SOL_SOCKET, SO_SNDBUF, &os,sizeof(os));
	return oos;
}
int setsockbuf(int sock,int in,int out)
{	int ois,is,oos,os;
	int len;

	if( 0 < in ){
		len = sizeof(ois);
		GETsockopt(sock, SOL_SOCKET, SO_RCVBUF, &ois,&len);
		is = in;
		SETsockopt(sock, SOL_SOCKET, SO_RCVBUF, &is,sizeof(is));
	}else	ois = is = 0;

	if( isWindowsCE() ){
		oos = os = 0;
	}else
	if( 0 < out ){
		len = sizeof(oos);
		GETsockopt(sock, SOL_SOCKET, SO_SNDBUF, &oos,&len);
		os = out;
		if( 0 < SOCK_SNDBUF_MAX && SOCK_SNDBUF_MAX < os ){
			os = SOCK_SNDBUF_MAX;
		}
		SETsockopt(sock, SOL_SOCKET, SO_SNDBUF, &os,sizeof(os));
	}else	oos = os = 0;
	syslog_DEBUG("setsockbuf[%d] in:%d->%d out:%d->%d\n",sock,ois,is,oos,os);
	return 0;
}
int MAG_EXPSOCKBUF = -1;
int expsockbuf(int sock,int in,int out)
{	int isize,osize;

	if( getsockbuf(sock,&isize,&osize) == 0 ){
		if( 0 <= MAG_EXPSOCKBUF ){
			int oin = in,oout = out;
			if( 0 < in && 16*1024 < in ){
				in = (in * MAG_EXPSOCKBUF) / 128;
				if( in < 16*1024 ) in = 16*1024;
			}
			if( 0 < out && 16*1024 < out ){
				out = (out *MAG_EXPSOCKBUF) / 128;
				if( out < 16*1024 ) out = 16*1024;
			}
			syslog_DEBUG("%d/128 expsockbuf(%d,%d<<%d,%d<<%d)\n",
				MAG_EXPSOCKBUF,
				sock,in,isize,out,osize);
/*
porting_dbg("%d/128 expsockbuf(%d,%d<<%d<<%d,%d<<%d<<%d)",
MAG_EXPSOCKBUF,sock, in,oin,isize, out,oout,osize);
*/
		}
		if( in  <= isize ) in = 0;
		if( out <= osize ) out = 0;
		if( in || out )
			return setsockbuf(sock,in,out);
		else	return 0;
	}
	return -1;
}
void set_linger(int sock,int secs)
{	struct linger sl,gl;
	int len,rcode;

	if( secs < 0 ){
		sl.l_onoff = 0;	
		sl.l_linger = 0;
	}else
	if( isWindowsCE() ){
		sl.l_onoff = 1;	
		sl.l_linger = secs;
	}else
	if( secs ){
		sl.l_onoff = 1;	/* on */
		sl.l_linger = secs;	/* seconds */
	}else{
#if defined(hpux) || defined(__hpux__)
		sl.l_onoff = 1;
		sl.l_linger = 0;
#else
		sl.l_onoff = 0;
		sl.l_linger = 0;
#endif
	}
	rcode = SETsockopt(sock, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
	if( rcode != 0 ){
		syslog_DEBUG("setsockopt(%d,LINGER) faield, errno=%d\n",sock,errno);
		return;
	}

	len = sizeof(gl);
	rcode = GETsockopt(sock, SOL_SOCKET, SO_LINGER, &gl, &len);
	if( rcode != 0 )
		syslog_DEBUG("getsockopt(%d,LINGER) failed, errno=%d\n",sock,errno);
	else	syslog_DEBUG("LINGER: [%d] %d %d{%d,%d}\n",sock,secs,
			len,gl.l_onoff,gl.l_linger);
}

/*
 * 9.9.7 not to regard reset by select(exception) or poll(PRIl) as OOB.
 */
int enbugSelect;
int BrokenSocket(FL_PAR,int fd){
	IStr(uname,128);
	IStr(msg,256);
	if( file_ISSOCK(fd) ){
		if( !IsConnected(fd,0) ){
			Uname(AVStr(uname));
			sprintf(msg,"[%s] not OOB: BrokenSocket[%d] <= %s:%d",
				uname,fd,FL_BAR);
			syslog_ERROR("%s ####\n",msg);
			if( enbugSelect ){
				fprintf(stdout,"%s ####\n",msg);
				return 0;
			}
			return 1;
		}
	}
	return 0;
}

#ifdef sun
#define SUNBUG ENAMETOOLONG
#else
#define SUNBUG -1
#endif

int IsConnected(int sock,const char **reason)
{	int nready,rcc;
	CStr(buf,1);
	int len;
	VSAddr sab;

	len = sizeof(VSAddr);
	if( getpeername(sock,(SAP)&sab,&len) != 0 ){
		int isconn = 0;
		if( errno == SUNBUG )
		if( PollIn(sock,1) == 0 || 0 < Peek1(sock) ){ 
			/* AF_UNIX/socketpair copied by dup2() on Solaris2.5
			 * results in ENAMETOOLONG if connected or not
			 */
			isconn = 1;
		}
		if( !isconn ){
		if(reason) *reason = "cant_getpeername";
		return 0;
		}
	}

if(reason) *reason = "connected";
return 1;

/*
	nready = rPollIn(sock,1);
	if( nready < 0 ){
		if(reason) *reason = "peer_reset";
		return 0;
	}

	if( nready == 0 ){
		if(reason) *reason = "poll_none_ready";
		return 1;
	}

	rcc = recv(sock,buf,1,MSG_PEEK);
	if( rcc == 1 ){
		if(reason) *reason = "recv_ok";
		return 1;
	}

	if(reason) *reason = "cant_recv";
	return 0;
*/
}
/*
int IsAlive(int sock){
*/
int IsAlive_FL(FL_PAR,int sock){
	int serrno,rdy1,rdy2;
	int r1,d1,r2,d2;

	if( IsConnected(sock,NULL) ){
		if( isWindowsCE() ){
			int exceptionReady(int sock);
			int rdy1,rdy2,rev2;
			if( rdy1 = exceptionReady(sock) ){
				rdy2 = inputReady(sock,&rev2);
				/*
				syslog_DEBUG("## IsNotAlive[%d] %d,%d/%d <= %s:%d\n",
					sock,rdy1,rdy2,rev2,FL_BAR);
				*/
				return 0;
			}
			return 1; /* no MSG_PEEK on WinCE */
		}
	    if( !lSISALIVE() ){
		SSigMask sMask;
		setSSigMask(sMask);
		/*
		rdy1 = PollIn(sock,1);
		9.9.8 for faster IsAlive()
		*/
		rdy1 = PollIn(sock,TIMEOUT_IMM);
		serrno = errno;
		resetSSigMask(sMask);

		if( rdy1 < 0 ){ /* 9.9.4 MTSS interrupted by a signal ? */
			putsLog("IsAlive PollIn failed");
			rdy2 = PollIn(sock,1);
			syslog_ERROR("IsAlive[%d] rdy=%d,%d err=%d <= %s:%d\n",
				sock,rdy1,rdy2,serrno,FL_BAR);
			rdy1 = rdy2;
		}
		/*
		if( PollIn(sock,1) == 0 || 0 < Peek1(sock) ) 
		*/
		if( rdy1 == 0 || 0 < rdy1 && Peek1(sock) )
			return 1;
		else	syslog_ERROR("## left connected but dead [%d] <= %s:%d\n",
				sock,FL_BAR);
		/*
		else	syslog_ERROR("## left connected but dead [%d]\n",sock);
		*/
	    }else{
		errno = 0;
		rdy1 = PollIn(sock,1);
		serrno = errno;
		if( rdy1 == 0 ){
			return 2;
		}
		msleep(1);
		r1 = inputReady(sock,&d1);
		rdy2 = PollIn(sock,1);
		r2 = inputReady(sock,&d2);
		if( rdy2 == 0 ){
		    porting_dbg("## IsAlive(%d) %d => %d (%d/%d %d/%d) e%d a%d <= %s:%d",
				sock,rdy1,rdy2,r1,d1,r2,d2,serrno,
				actthreads(),FL_BAR);
			return 3;
		}
		if( 0 < Peek1(sock) ){
			return 4;
		} 
		syslog_ERROR("## left connected but dead [%d]\n",sock);
	    }
	}
	return 0;
}
/*
int isAlive(int sock){
*/
int isAlive_FL(FL_PAR,int sock){
	int rd;
	if( sock_isconnectedX(sock,0) ){
		if( isWindowsCE() ){
			return 1; /* no MSG_PEEK on WinCE */
		}
		if( inputReady(sock,&rd) == 0 || 0 < Peek1(sock) ) 
			return 1;
		else	syslog_ERROR("## Left connected but dead [%d] <= %s:%d\n",
				sock,FL_BAR);
	}
	return 0;
}

int PollOuts(int timeout,int fc,int fv[],int rv[]){
	int fi;
	int qv[256];
	int nready;

	for( fi = 0; fi < fc; fi++ ){
		rv[fi] = 0;
		qv[fi] = PS_OUT;
	}
	nready = PollInsOuts(timeout,fc,fv,qv,rv);
	return nready;
}

int inoutReady(int sock,int inout){
	int fv[1];
	int qv[1];
	int rv[1];
	int ready;

	fv[0] = sock;
	qv[0] = PS_PRI;
	if( inout & 1 ) qv[0] |= PS_IN;
	if( inout & 2 ) qv[0] |= PS_OUT;
	ready = PollInsOuts(0,1,fv,qv,rv);
	return ready;
}
int file_isSOCKET(int fd);
#undef inputReady
int inputReady(int sock,int *rd){
	int fv[1];
	int qv[1];
	int rv[1];
	int ready;

	if( isWindows() && !file_isSOCKET(sock) ){
		ready = pollPipe(sock,TIMEOUT_IMM);
		return ready;
	}
	fv[0] = sock;
	qv[0] = PS_IN|PS_PRI;
	ready = PollInsOuts(0,1,fv,qv,rv);
	if( rd ) *rd = rv[0];
	return ready;
}
int finputReady(FILE *fs,FILE *ts){
	if( ts && ferror(ts) ) return 1;
	if( feof(fs) ) return 2;
	if( 0 < ready_cc(fs) ) return 3;
	if( IsConnected(fileno(fs),NULL) <= 0 ) return 4;
	if( 0 < inputReady(fileno(fs),NULL) ) return 5;
	return 0;
}

int watchBothside(int in,int out){
	if( in < 0 ) return -1;
	if( out < 0 ) return -1;
	if( file_isSOCKET(in) && file_isSOCKET(out) ){
		return 1;
	}
	return 0;
}
int exceptionReady(int sock){
	int fv[1];
	int qv[1];
	int rv[1];
	int ready;

	fv[0] = sock;
	qv[0] = PS_PRI;
	ready = PollInsOuts(0,1,fv,qv,rv);
	return ready;
}
#if defined(__APPLE__) || defined(_MSC_VER) || defined(__Free_BSD__)
/* this should be tested detecting RESET on a socketpair with PS_PRI */
#define withoutPoll() 1
#else
#define withoutPoll() 0
#endif
int pollIY(const char *wh,double timeout,int in,int ex,int exin);
int pollIX(const char *wh,double timeout,int in,int ex){
	int nrdy;
	nrdy = pollIY(wh,timeout,in,ex,0);
	return nrdy;
}
int pollIY(const char *wh,double timeout,int in,int ex,int exin){
	int fv[2],qv[2],rv[2],ready;
	int rcode = 0;
	double St;

	fv[0] = in; qv[0] = PS_PRI|PS_IN; rv[0] = 0;
	fv[1] = ex; qv[1] = PS_PRI;       rv[1] = 0;
	if( exin && withoutPoll() ){
		/* 9.9.1 select() does not detect RESET as exception */
		/* but detected PS_IN might be next request pipelined */
		qv[1] = PS_PRI|PS_IN;
	}
	St = Time();
	ready = PollInsOuts((int)(timeout*1000),2,fv,qv,rv);
	if( rv[0] ) rcode |= 1;
	if( rv[1] ) rcode |= 2;
	if( ready == 1 && rv[0] == 0 && rv[1] == 0 ) rcode |= 2;

	if( rcode & 2 )
	syslog_ERROR("--%d pollIX(%s,%d,%d/%d,%d/%d)%d{%d %d}(%.3f/%.3f)\n",
		rcode,wh,(int)(timeout*1000),
		SocketOf(in),in,SocketOf(ex),ex,ready,rv[0],rv[1],
		Time()-St,timeout);
	return rcode;
}
int receiverReset(const char *wh,double timeout,int in,int out){
	int rdy;
	if( (rdy = pollIX(wh,timeout,in,out)) == 0 )
		return 0;
	if( (rdy & 2) == 0 )
		return 0;
	syslog_ERROR("--- %s detected reset %X [%d/%d]%d%d [%d/%d]%d%d\n",
		wh,rdy,SocketOf(in),in,IsConnected(in,0),IsAlive(in),
		SocketOf(out),out,IsConnected(out,0),IsAlive(out));
	return 1;
}

#undef recv
#ifdef __APPLE__
/*
 * recv(PEEK) for pipe on Darwin returns success just doing recv() without PEEK
 */
int recvDarwin(int sock,void *buf,int len,int flags,FL_PAR){
	int rcc;

	if( flags & MSG_PEEK )
	if( file_issock(sock) < 0 ){
		porting_dbg("## Non-Socket recv(%d,%d,PEEK) <= %s:%d",
			sock,len,FL_BAR);
		return -1;
	}
	rcc = recv(sock,buf,len,flags);
	return rcc;
}
#endif
