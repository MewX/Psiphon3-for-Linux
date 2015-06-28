const char *SIGN_sox_c="{FILESIGN=sox.c:20141031194212+0900:8f57bd71083c3ec7:Author@DeleGate.ORG:1YiHM0MKjYpoV/3cpoPrBeujKgQRmVt0fDoJ+hnMbdTFHKwu0+s5NSZwgJLyVXkiv5nEImt+9BpX6w+zi19u7R3qQISzmrISJTeaGLd7CPrR0hWVdvTjWCOx6ogWyp4bz5uBlEpT4vT+FKYaWj41a/R1fTOuQg5O/KV4g2vWO/o=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2002-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	SockMux (socket multiplexer)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	Multiplex local sockets and tunnel to remote via a single
	bidrectional communication channel.

    Server binding:
	SERVER=proto[://server],-in  server for connection incoming from remote

TODO:
 - SERVER="sockmux:shio:script.shio"
 - SERVER=proto[://server],-out server for outogoing
 - SERVER="proto[://server]-out(optionList):-:-Pxxxx"
 - substitute "CRON=..." parameter ?

 - resumable commin/commout for movile usage
 - multiple commin/commout with encryption or not
 - 7bit mode comm relayable over telnet
 - SockMux as hidden background exchange like Telnet commands
 - SockMux for FTP data-connections like MODE XDC
 - symbolic message version of SockMux
 - remote administration commands like SNMP

 - multiple queue with priority
 - give the highest priority to Telnet, the lowest one to FTP, etc.
 - QoS control

 - forwarding originator's (and forwarder's) identity in chained SockMux
 - forwarding originator's certificate (singed and verified, or encrypted)
 - C1 -> S <- C2 ... and C1 <-> C2, relay as a reflector
 - SENDME/IHAVE or CONNECT2vaddr + ACCEPTvaddr or SEND2vaddr+RECVvaddr
 - HELLO assoc-name
 - multicasting on SockMux, like ViaBus

 - UTF-8 encoding including header ?

History:
	021215	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include "vsocket.h"
#include "vsignal.h"
#include "ystring.h"
#include "dglib.h"
#include "credhy.h"
#include "fpoll.h"
#include "proc.h"
#include "log.h"
#include "file.h" /* dupclosed() */

int isPrivateSox(DGC*ctx);
int CTX_withAuth(DGC*ctx);
int CTX_withYY(DGC*ctx);
int CTX_withYY_SV(DGC*ctx);
int CTX_withYY_CL(DGC*ctx);
int CTX_withYY_BROKEN(DGC*ctx);
int doAuth(DGC*ctx,AuthInfo *auth);
int get_MYAUTH(DGC*ctx,PVStr(myauth),PCStr(proto),PCStr(dhost),int dport);

extern int CHILD_SERNO;
extern int NUM_CHILDREN;

extern int ACC_TIMEOUT;
extern int CFI_DISABLE;

/*
 *	SIMPLE SOCKET TUNNELING MULTIPLEXER PROTOCOL
 *	Version: 0.3
 */
#define MAJVER	0
#define MINVER	3
#define MYVER	((MAJVER<<4) | MINVER)
#define VERENC	0x80

/*
 *	PROTOCOL SPECIFICATION
 */
typedef unsigned char octet1;
typedef struct {
	octet1	ph_ver;	/* protocol version */
	octet1	ph_type; /* packet type */
	octet1	ph_Said[2]; /**//* sender's id */
	octet1	ph_Raid[2]; /**//* receiver's id */
	octet1	ph_leng[2]; /**//* payload length */
} PackV03;
#define PHSIZE	sizeof(PackV03)
/*
#define PWSIZE	512
*/
#if isWindowsCE()
#define PWSIZE	1024
#else
#define PWSIZE	16*1024
#endif
#define PBSIZE	(PWSIZE-PHSIZE)

typedef struct SoxPacket {
	PackV03	p_head;
	MStr(	p_data,PWSIZE-PHSIZE);
} Packet;

/*
 *	PACKET TYPES
 */
#define SOX_ACK		0x40
#define SOX_NOOP	0x00 /* NO operation (for keep-alive) */
#define SOX_HELLO	0x01 /* HELLO hostname */
#define SOX_CONNECT	0x02 /* CONNECT bufsize client clif [bindif?] */
#define SOX_CONNECT2	0x03 /* CONNECT TO ... specifying destination port */
#define SOX_BIND	0x04
#define SOX_ACCEPT	0x05
#define SOX_SEND	0x06 /* SEND    L# R# data */
#define SOX_SENDOOB	0x07 /* SENDOOB L# R# data */
#define SOX_CLOSE	0x08 /* CLOSE   L# R# reason */
#define SOX_ECHO	0x09
#define SOX_SETOPT	0x0A
#define SOX_GETOPT	0x0B
#define SOX_CRYPTON	0x0C /* packets will be encrypted after this packet */
#define SOX_OOBPUSH	0x0D
#define SOX_UNBIND	0x0E

#define SOX_HELLOOK	(SOX_ACK|SOX_HELLO)   /* HELLOOK hostname */
#define SOX_CONNECTED	(SOX_ACK|SOX_CONNECT) /* CONNECTED bufsize server svif */
#define SOX_ECHOOK	(SOX_ACK|SOX_ECHO)
#define SOX_SENT	(SOX_ACK|SOX_SEND)    /* SENT length */
#define SOX_SENTOOB	(SOX_ACK|SOX_SENDOOB) /* SENTOOB length */
#define SOX_CLOSED	(SOX_ACK|SOX_CLOSE)   /* CLOSED reason */
#define SOX_BINDOK	(SOX_ACK|SOX_BIND)

/*
 * OPTIONS
 */
#define SOX_O_CRYPT	0x01
#define SOX_O_CONNDATA	0x02
#define CRYPT_CREDHY	0x01
#define CRYPT_DHKEY	0x01
#define CRYPT_DHKEYX	0x00

#define SOX_O_PACKSIZE	0x03
#define SOX_O_AUTH	0x04
#define AUTH_PASS	0x01

/* internal status */
#define SOX_COMMOUT	0x0100
#define SOX_COMMIN	0x0200
#define SOX_LISTEN	0x0300
#define SOX_WAITING	0x1000 /* waiting remote, stop local input */
#define SOX_SENDING	(SOX_WAITING|SOX_SEND)
#define SOX_SENDINGOOB	(SOX_WAITING|SOX_SENDOOB)
#define SOX_PARENT	0x8000

#define p_Ver	p_head.ph_ver
#define p_Type	p_head.ph_type
#define GET_INT16(a)	((a[0]<<8)|a[1])
/*
#define SET_INT16(a,v)	{a[0] = v>>8; a[1] = v;}
just to suppress the warning for setting Aid with only 8bits of "unsigned char"
*/
#define SET_INT16(a,v)	{a[0] = ((int)(v))>>8; a[1] = v;}
#define PK_Leng(p)	GET_INT16((p)->p_head.ph_leng)
#define PK_setLeng(p,l)	SET_INT16((p)->p_head.ph_leng,l)
#define PK_Said(p)	GET_INT16((p)->p_head.ph_Said)
#define PK_setSaid(p,l)	SET_INT16((p)->p_head.ph_Said,l)
#define PK_Raid(p)	GET_INT16((p)->p_head.ph_Raid)
#define PK_setRaid(p,l)	SET_INT16((p)->p_head.ph_Raid,l)

/*
 *	PROTOCOL INTERPRETER
 */
/*
#define NSOCK	256
*/
#define NSOCK	64
#define MAXPENDING	4
#define MAXBUFSIZE	((MAXPENDING+2)*PWSIZE)
typedef struct {
	int	b_fd;	/* socket file descriptor */
	int	b_rem;	/* remaining in buffer */
	MStr(	b_buf,MAXBUFSIZE);
} Buffer;

typedef struct {
  unsigned int	s_gotHELLO;
  unsigned int  s_rrecvN; /* received from remote agent */
  unsigned int  s_rrecv;  /* bytes received */
  unsigned int  s_rsentN; /* sent to remote agent */
  unsigned int  s_rsent;  /* bytes sent */
  unsigned int	s_rpendN; /* pending status caused */
  unsigned int	s_time; /* the clock of the last activity */
  unsigned int	s_wtime; /* the clock of the last write */
  unsigned int	s_rtime; /* the clock of the last read */
  unsigned int	s_ltCLOSED; /* the clock of closed from local agent */
  unsigned int	s_rtCLOSED; /* the clock of closed from remote agent */
} Stats;

#define AUTH_REQ	1
#define AUTH_OK		2
#define AUTH_ERR	4

typedef unsigned char Aid;
typedef struct SoxAgent {
	int	a_abid;	/* agent buffer id */
	Aid	a_Laid;	/* local agent id */
	Aid	a_Xaid;	/* remote agent id */
  unsigned int	a_rpend; /* bytes pending in remote */
  unsigned int	a_stat;	/* local agent status */
	char	a_remote; /* initiated by remote */
	Buffer	a_lbuf; /* buffer for output to local socket */
	int	a_pid;	/* process id */
	Stats	a_stats;
	short	a_commin; /* Laid of commin */
	short	a_commout; /* Laid of commout */
	short	a_Ludp; /* local port is UDP */
	short	a_errs; /* error counter */
	double	a_start;
	int	a_authstat;
    const char *a_serverurl; /* the local server for this Agent */
} Agent;

#define a_gotH	a_stats.s_gotHELLO
#define a_recv	a_stats.s_rrecv
#define a_recvN	a_stats.s_rrecvN
#define a_sent	a_stats.s_rsent
#define a_sentN	a_stats.s_rsentN
#define a_pendN	a_stats.s_rpendN
#define a_sock	a_lbuf.b_fd
#define a_lpend	a_lbuf.b_rem
#define a_ltCLOSED a_stats.s_ltCLOSED
#define a_rtCLOSED a_stats.s_rtCLOSED

typedef struct DGSox {
	int	s_time;
	int	s_clock;
	int	s_nlaid;
	Credhy	s_credhy[2]; /**/
	int	s_Rpstats[256];	/* per received packet type */

	MStr(	s_serverurl,256);
	MStr(	s_myname,256);
	MStr(	s_lhello,64);
	MStr(	s_xhello,64);
	MStr(	s_Infifo,256);
	MStr(	s_Outfifo,256);
	MStr(	s_proc,256);
	FILE   *s_comminfp;
	int	s_ocommin;

	int	s_agentserno;
	int	s_agents;
	Agent	s_agentbv[NSOCK]; /**/
	Agent  *s_agentpv[NSOCK]; /**/
	MStr(	s_aidactive,NSOCK);

	int	s_qfdset;
	int	s_qtimeout;
	int	s_qfdc;
	int	s_qfdv[NSOCK];
	int	s_qcxv[NSOCK];
	int	s_qqev[NSOCK];
	int	s_commout;
	int	s_relayOOB;
	int	s_oneTime;
	int	s_conndata;
	DGC	*s_ctx;
	MStr(	s_stime,128);

    const char *s_soxinports;
} Sox;
static const char *s_rsap;
static int s_rsap_allow = 0;

#define ToKey	(&sox->s_credhy[1])
#define TiKey	(&sox->s_credhy[0])
#define Tocrypt	ToKey->k_active
#define Ticrypt	TiKey->k_active
#define ToCRC8	ToKey->k_crc8
#define TiCRC8	TiKey->k_crc8

#define Serverurl	sox->s_serverurl
/**/
#define Myname	sox->s_myname
#define LHello	sox->s_lhello
/**/
#define XHello	sox->s_xhello
#define Infifo	sox->s_Infifo
/**/
#define Outfifo	sox->s_Outfifo
/**/
#define Comminfp	sox->s_comminfp
#define Ocommin	sox->s_ocommin

#define AgentSerno	sox->s_agentserno
#define Agents	sox->s_agents
#define Agentbv	sox->s_agentbv
#define Agentpv	sox->s_agentpv

#define Qfdset	sox->s_qfdset
#define Qtimeout	sox->s_qtimeout
#define Qfdc	sox->s_qfdc
#define Qfdv	sox->s_qfdv
#define Qcxv	sox->s_qcxv
#define Qqev	sox->s_qqev

#define CommoutFd	sox->s_commout
#define CommOutAp	Agentpv[0]
#define CommInAp	Agentpv[1]
#define RelayOOB	sox->s_relayOOB
#define oneTime		sox->s_oneTime
#define DO_CONNDATA	sox->s_conndata

#define Trecv	CommInAp->a_recv
#define TrecvN	CommInAp->a_recvN
#define Tsent	CommOutAp->a_sent
#define TsentN	CommOutAp->a_sentN
#define TpendN	CommOutAp->a_pendN

void send_BIND(Sox *sox,Agent *Apc,Packet *pack,PCStr(ports),Agent *Ap1);
void recv_BOUND(Sox *sox,Packet *pack);
void recv_BIND(Sox *sox,Agent *Apc,Packet *pack);

static int Llinger = 3; /* wait closing local socket with remaining output */
static int DHKgrp = 2;
static int Nodelay = 0;
static int Nopush = 0;
static int Cork = 0;
void set_nopush(int sock,int onoff);
void set_cork(int sock,int onoff);
static int PackSize = 512; /* the small PWSIZE of original version */
static int PackSizeExp = 0;
static int PqueSize = MAXPENDING;
static int sox_private; /* private SockMux of the parent DeleGate */
int iamPrivateSox(){
	return sox_private;
}

/* OPT_S */
#define newAgent		SOX_newAgent
Agent *newAgent(Sox *sox,int raid,int sock,int stat);
#define get_CONNECT		SOX_get_CONNECT
void get_CONNECT(Packet *pack,PVStr(remote),PVStr(local));
#define checkServerFinish	SOX_checkServerFinish
void checkServerFinish(const char *fmt,...);
#define writecomm		SOX_writecomm
int writecomm(Sox *sox,Agent *Apc,Packet *pack);
#define send_ACK		SOX_send_ACK
void send_ACK(Sox *sox,Agent *Apc,Packet *pack);
#define dbgprintf		PK_dbgprintf
int dbgprintf(PCStr(fmt),...);
static int (*dbglog)(PCStr(fmt),...) = dbgprintf;
#define Trace	(*dbglog)
#define Debug	(dbglev==0)?0:(*dbglog)

#define PK_clrRaid(pack)	PK_setRaid(pack,(Aid)-1)
#define PK_clrSaid(pack)	PK_setSaid(pack,(Aid)-1)

#ifndef OPT_S /*{*/

int SOXMUX_UDP_TIMEOUT = 180;
int SOXMUX_UDP_MAX = 64;
int SOX_NOENCRYPT = 0;
int SOX_NOCONNDATA = 0;

void scan_SOXCONF(DGC*ctx,PCStr(conf))
{	CStr(what,32);
	CStr(value,64);

	fieldScan(conf,what,value);
	if( streq(what,"dhkey") ){
		if( '0' <= *value && *value <= '9' )
			DHKgrp = atoi(value);
		else	DHKgrp = -1;
	}
	else
	if( streq(what,"noconndata") ){
		SOX_NOCONNDATA = 1;
	}
	else
	if( streq(what,"nodelay") ){
		if( streq(value,"on") )
			Nodelay = 1;
	}
	else
	if( streq(what,"nopush") ){
		if( streq(value,"on") )
			Nopush = 1;
	}
	else
	if( streq(what,"cork") ){
		if( streq(value,"on") )
			Cork = 1;
	}
	else
	if( streq(what,"crypt") ){
		if( streq(value,"no") || streq(value,"off") )
			SOX_NOENCRYPT = 1;
	}
	else
	if( streq(what,"packsize") ){
		int size = kmxatoi(value);
		if( PWSIZE < size ){
			PackSizeExp = PWSIZE;
		}else
		if( size < 128 ){
			PackSizeExp = 128;
		}else{
			PackSizeExp = size;
		}
		sv1log("---- PackSizeExp = %d\n",PackSizeExp);
	}
	else
	if( streq(what,"allow") ){
		if( isinList(value,"acc") )
			s_rsap_allow = 1;
	}
	else
	if( streq(what,"acc") ){
		/* SOXCONF="acc:tcp:rhost:rport:lhost:lport" for
		 *   PORT="rhost:rport" at remote and
		 *   SERVER="tcprelay://lhost:lport,-in:-:-P{rhost:rport}"
		 */
		sv1log("#### SOXCONF=%s:%s\n",what,value);
		s_rsap = stralloc(value);
	}
	else
	if( streq(what,"private") ){
		sox_private = 1;
	}
}

static const char *tstmp(Sox *sox){
	StrftimeLocal(AVStr(sox->s_stime),sizeof(sox->s_stime),
		"%y%m%d-%H%M%S",time(0),0);
	return sox->s_stime;
}

static int sox_init_done = 0;
static int dbglev = 0;
static FILE *logfp;
int dbgprintf(PCStr(fmt),...)
{	CStr(xfmt,256);
	int sec,usec;
	IStr(msg,2*1024);
	VARGS(16,fmt);

	if( lSILENT() && sox_init_done ){
		return 0;
	}
	if( logfp == NULL ){
		if( 0 < curLogFd() )
			logfp = fdopen(curLogFd(),"a");
		else	logfp = stderr;
	}
	sec = Gettimeofday(&usec);
	/*
	sprintf(xfmt,"{S}%02d.%03d ",sec%60,usec/1000);
	*/
	sprintf(xfmt,"{S}%02d:%02d.%03d ",(sec%3600)/60,sec%60,usec/1000);
	strcat(xfmt,fmt);
	strcat(xfmt,"\n");
	/*
	fprintf(logfp,xfmt,VA16);
	*/
	sprintf(msg,xfmt,VA16);
	fprintf(logfp,"%s",msg);
	fflush(logfp);

	if( logfp == stderr ){
		void send_syslogY(PCStr(lclass),PCStr(log));
		if( isWindowsCE() ){
			sprintf(msg,xfmt,VA16);
			send_syslogY("E",msg);
		}
	}
	return 0;
}

static int nsigPIPE;
static void sigPIPE(int sig)
{
	nsigPIPE++;
	signal(SIGPIPE,sigPIPE);
}
static void sigCONT(int sig)
{
	signal(SIGCONT,sigCONT);
}

static int writeb(Sox *sox,Agent *Ap1,char buf[],int len)
{	int wcc,rem;
	int wccs;
	Buffer *Buf = &Ap1->a_lbuf;

	wcc = 0;
	if( Buf->b_rem ){
		wcc = write(Buf->b_fd,Buf->b_buf,Buf->b_rem);
		Debug("## FLUSHED %d/%d (+%d)",wcc,Buf->b_rem,len);
		if( wcc < Buf->b_rem ){
			if( wcc < 0 )
				wcc = 0;
			rem = Buf->b_rem;
			if( 0 < wcc ){
				rem = rem - wcc;
				bcopy(Buf->b_buf+wcc,Buf->b_buf,rem);
			}
			bcopy(buf,Buf->b_buf+rem,len);
			Buf->b_rem = rem + len;
			return wcc;
		}
		Qfdset = 0;
		Buf->b_rem = 0;
	}
	wccs = wcc;

	if( buf != 0 && len ){
		wcc = write(Buf->b_fd,buf,len);
		if( wcc < len ){
			Debug("## SENDING %d/%d",wcc,len);
			Qfdset = 0;
			if( wcc < 0 )
				wcc = 0;
			rem = len - wcc;
			bcopy(buf+wcc,Buf->b_buf,rem);
			Buf->b_rem = rem;
		}
		wccs += wcc;
	}
	return wccs;
}

static void dumpPack(PCStr(pack),PCStr(epack),int len)
{	int bi;
	const char *bp;

	/*
	fprintf(stderr,"ORIG ");
	bp = pack;
	for( bi = 0; bi < len; bi++ )
		fprintf(stderr,"%02X",0xFF&*bp++);
	fprintf(stderr,"\n");
	*/
	if( epack ){
		fprintf(stderr,"ENCD ");
		bp = epack;
		for( bi = 0; bi < len; bi++ )
			fprintf(stderr,"%02X",0xFF&*bp++);
		fprintf(stderr,"\n");
	}
}
static void getCryptPreamble(Sox *sox,Agent *Api,Packet *pack)
{	CStr(rand,8);
	CStr(buf,8);
	CStr(tmp,32);
	int plen;
	int rcc;

	if( 2 <= PK_Leng(pack) )
		plen = pack->p_data[PK_Leng(pack)-1];
	else	plen = 0;
	Trace("#### Encryption start for incoming comm. [%d](%d)/%d",
		TiKey->k_group,plen,PK_Leng(pack));
	Ticrypt = CRYPT_CREDHY;
	if( 0 < plen && plen <= sizeof(buf) ){
		rcc = fread(buf,1,QVSSize(buf,plen),Comminfp);
		CredhyDecrypt(TiKey,plen,buf,rand);
		strtoHex(rand,plen,AVStr(tmp),sizeof(tmp));
		if( 2 < dbglev )
			Trace("#### GOT PREAMBLE %s",tmp);
	}
}
static void putCryptPreamble(Sox *sox,Agent *Api,Packet *pack,int plen)
{	CStr(rand,8);
	CStr(buf,8);
	CStr(tmp,32);
	int rand32,wcc;

	Trace("#### Encryption start for outgoing comm. [%d](%d)",
		ToKey->k_group,plen);
	Tocrypt = CRYPT_CREDHY;
	if( plen ){
		rand32 = DH_rand32() ^ getpid();
		rand[0] = rand32 >> 24;
		rand[1] = rand32 >> 16;
		rand[2] = rand32 >> 8;
		rand[3] = rand32 >> 0;
		CredhyEncrypt(ToKey,plen,rand,buf);
		wcc = writeb(sox,Api,buf,plen);
		strtoHex(rand,plen,AVStr(tmp),sizeof(tmp));
		if( 2 < dbglev )
			Trace("#### PUT PREAMBLE %s",tmp);
	}
}
static int sendpackX(Sox *sox,Agent *Api,Agent *Apc,Packet *pack,int len,int OOB)
{	int wcc;
	Packet *opack;
	Packet epack;

	opack = pack;
	if( Tocrypt == CRYPT_CREDHY ){
		pack->p_Ver = VERENC|MYVER;
		CredhyEncrypt(ToKey,len,(char*)pack,(char*)&epack);
		if( 2 < dbglev )
			dumpPack((char*)pack,(char*)&epack,len);
		pack = &epack;
	}

	if( OOB && RelayOOB ){
		wcc = sendOOB(Apc->a_sock,(char*)pack,len);
	}else	wcc = writeb(sox,Apc,(char*)pack,len);

	Apc->a_stats.s_time = sox->s_time;
	Apc->a_stats.s_wtime = sox->s_time;
	Tsent += wcc;
	TsentN++;
/*
Trace("#### SENT %d/%d %d CRC=%X",Tsent,TsentN,len,ToCRC8);
*/
	if( 0 < wcc && (opack->p_Type & SOX_ACK) == 0 ){
		if( Api ){
			Api->a_sent += PK_Leng(opack);
			Api->a_sentN++;
		}
	}
	if( 1 < dbglev ){
		Agent *ApS = 0;
		int ci,laid,raid;
		for( ci = 0; ci < Agents; ci++ ){
			if( Agentpv[ci]->a_Laid == PK_Said(opack) ){
				ApS = Agentpv[ci];
				break;
			}
		}
		laid = PK_Said(opack)!=0xFFFF?PK_Said(opack):-1;
		raid = PK_Raid(opack)!=0xFFFF?PK_Raid(opack):-1;
		Trace("sendpack L#%d[%02X] -> R#%d[%02X] %d/%d/%d",
			laid,ApS?ApS->a_stat:0,
			raid,opack->p_Type,
			PK_Leng(opack),ApS?ApS->a_sent:0,ApS?ApS->a_sentN:0
		);
	}
	return wcc;
}
static int writecommX(Sox *sox,Agent *ApL,Agent *Apc,Packet *pack)
{	int wcc;

	pack->p_Ver = MYVER;
	wcc = sendpackX(sox,ApL,Apc,pack,PHSIZE+PK_Leng(pack),0);
	return wcc;
}
int writecomm(Sox *sox,Agent *Apc,Packet *pack)
{
	return writecommX(sox,NULL,Apc,pack);
}
static int writesock(Sox *sox,Agent *ApR,Packet *pack)
{ 	int wcc;

	if( pack == NULL ) /* just to flush pending */
		wcc = writeb(sox,ApR,NULL,0);
	else	wcc = writeb(sox,ApR,pack->p_data,PK_Leng(pack));
	return wcc;
}
static int recvpack(Sox *sox,Agent *Apc,FILE *infp,Packet *pack,int OOB)
{	int rcc,wcc,leng;

	if( OOB && RelayOOB ){
		rcc = recvOOB(fileno(infp),GVStr(pack),PHSIZE);
	}else	rcc = fread(pack,1,PHSIZE,infp);
	if( rcc <= 0 ){
		return -1;
	}
	if( Ticrypt == CRYPT_CREDHY ){
		CredhyDecrypt(TiKey,rcc,(char*)pack,(char*)pack);
		if( pack->p_Ver != (VERENC|MYVER) ){
			Trace("BAD VERSION! %02X %02X|%02X",pack->p_Ver,
				VERENC,MYVER);
			return -1;
		}
	}

	if( 0 < (leng = PK_Leng(pack)) )
	{
		if( PWSIZE < leng ){
			Trace("Too large packet: %d",leng);
			return -1;
		}
		if( OOB && RelayOOB )
			rcc += recvOOB(fileno(infp),AVStr(pack->p_data),leng);
		else	rcc += fread(pack->p_data,1,QVSSize(pack->p_data,leng),infp);
		if( Ticrypt == CRYPT_CREDHY ){
			CredhyDecrypt(TiKey,leng,pack->p_data,pack->p_data);
		}
	}
	Apc->a_stats.s_time = sox->s_time;
	Apc->a_stats.s_rtime = sox->s_time;
	Trecv += rcc;
	TrecvN++;

/*
Trace("#### RECV %d/%d %d CRC=%X",Trecv,TrecvN,rcc,TiCRC8);
*/
	/*
	Debug(" comm input...pack(#%d %02X %d) %d",
		PK_Raid(pack),pack->p_Type,PK_Leng(pack),rcc);
	*/
	return rcc;
}
static int sock2comm(Sox *sox,Agent *Api,int sock,Agent *Apc,Packet *pack,int OOB)
{	int laid = Api->a_Laid;
	int raid = Api->a_Xaid;
	int rcc,wcc,type;
	int nrcc;
	char buf[8];

	errno = 0;
	if( OOB == 2 ){
		rcc = PK_Leng(pack);
		type = SOX_SENDOOB;

		/* MSG_PEEK clears "exceptfds" in select() */
		Trace("----flush OOB %d, withOOB=%d",rcc,withOOB(sock));
		nrcc = recv(sock,buf,sizeof(buf),MSG_PEEK);
		Trace("----flush OOB %d, withOOB=%d, next non-OOB=%d",
			rcc,withOOB(sock),nrcc);
	}else
	if( OOB ){
		rcc = recvOOB(sock,AVStr(pack->p_data),sizeof(pack->p_data));
		if( 0 < withOOB(sock) ){
			nrcc = recv(sock,buf,sizeof(buf),MSG_PEEK);
			Debug("----got OOB %d, withOOB=%d, next non-OOB=%d",
				rcc,withOOB(sock),nrcc);
			if( 0 < nrcc && withOOB(sock) ){
				Trace("----pushed OOB %d, non-OOB %d",
					rcc,nrcc);
				PK_setLeng(pack,rcc);
				pack->p_Type = SOX_OOBPUSH;
				return 0;
			}
		}
		else
		if( rcc < 0 ){
			/* 9.9.0 this might be a local connection and detected
			 * shutdown() by the peer, to stop farther incoming
			 * data, as OOB/PRI? (Only with poll(),Ubuntu,SUSE,...)
			 */
			Trace("----sensed OOB but no-OOB and rcc=%d",rcc);
			errno = EAGAIN;
			return 0;
		}
		type = SOX_SENDOOB;
	}else{
		rcc = read(sock,pack->p_data,QVSSize(pack->p_data,PackSize-PHSIZE));
		type = SOX_SEND;
	}
	if( rcc <= 0 ){
		Debug("## sock2comm() EOF rcc=%d from client L#%d[%d]",
			rcc,laid,sock);
		pack->p_Type = SOX_CLOSE;
		Api->a_ltCLOSED = sox->s_time;
		return rcc;
	}
	pack->p_Type = type;
	PK_setLeng(pack,rcc);
	PK_setSaid(pack,laid);
	PK_setRaid(pack,raid);

	wcc = sendpackX(sox,Api,Apc,pack,PHSIZE+rcc,OOB);
	if( wcc <= 0 ){
		Trace("## sock2comm() write %d/%d",wcc,PHSIZE+rcc);
	}
	/*
	Debug(" sock input...pack(#%d %02X %d) %d",
		PK_Raid(pack),pack->p_Type,PK_Leng(pack),wcc);
	*/
	return wcc;
}

static void set_STR(Packet *pack,PCStr(str))
{
	FStrncpy(pack->p_data,str);
	PK_setLeng(pack,strlen(pack->p_data)+1);
}
static void set_INT(Packet *pack,int ival)
{
	sprintf(pack->p_data,"%d",ival);
	PK_setLeng(pack,strlen(pack->p_data)+1);
}
static int get_INT(Packet *pack)
{	int ival;

	sscanf(pack->p_data,"%d",&ival);
	return ival;
}

static int SOX_WAITINIT = 1; /* wait the initial data ready (in milli-sec.) */
/*
 * initial data which is ready at the begining of a connection is sent
 * with a CONNECT request or a CONNECTED response packet
 */
static void get_conndata(Sox *sox,Agent *Apn,Packet *pack){
	int len;
	int pcc;

	if( SOX_NOCONNDATA ) /* it is disabled locally */
		return;
	if( !DO_CONNDATA ) /* the peer does not ask it */
		return;

	if( 0 < PollIn(Apn->a_sock,SOX_WAITINIT) ){
		len = strlen(pack->p_data);
		/*
		pcc = recv(Apn->a_sock,pack->p_data+len+1,PWSIZE-len-1,0);
		*/
		pcc = recv(Apn->a_sock,pack->p_data+len+1,sizeof(pack->p_data)-len-1,0);
		if( 0 < pcc ){
			PK_setLeng(pack,len+1+pcc);
			Trace("CONNECT+DATA send %d (%d)",pcc,PK_Leng(pack));
		}
	}
}
static void put_conndata(Packet *pack,int clsock)
{	int wcc;
	int pcc = 0;
	int len;
	const char *peek;

	len = strlen(pack->p_data);
	if( len+1 < PK_Leng(pack) ){
		pcc = PK_Leng(pack) - len - 1;
		peek = pack->p_data+len+1;
	}
	if( pcc <= 0 )
		return;

	wcc = send(clsock,peek,pcc,0);
	Trace("CONNECT+DATA recv %d / %d (%d)",pcc,wcc,PK_Leng(pack));
	if( wcc != pcc ){
		/* this is assumed to succeed immediately */
		daemonlog("F","SOX CONNECT+DATA failed %d/%d\n",pcc,wcc);
	}
}
/*
 * CONNECT N.bufsize A.client A.clientif
 */
static void set_CONNECT(Agent *Apn,Packet *pack,PCStr(remote),PCStr(local))
{	CStr(pair,512);

	sprintf(pair,"%d %s %s",MAXBUFSIZE,remote,local);
	linescanX(pair,AVStr(pack->p_data),sizeof(pack->p_data));
	PK_setLeng(pack,strlen(pack->p_data)+1);
}
void get_CONNECT(Packet *pack,PVStr(remote),PVStr(local))
{	int bsiz;

	bsiz = 0;
	setVStrEnd(local,0);
	setVStrEnd(remote,0);
	Xsscanf(pack->p_data,"%d %s %s",&bsiz,AVStr(remote),AVStr(local));
}

static int send_HELLO(Sox *sox,Agent *Apc,int ack,Packet *pack)
{	int wcc;

	pack->p_Ver = MYVER;
	pack->p_Type = ack?SOX_HELLOOK:SOX_HELLO;

	set_STR(pack,LHello);
	wcc = sendpackX(sox,NULL,Apc,pack,PHSIZE+PK_Leng(pack),0);
	return wcc;
}
static void got_HELLO(Sox *sox,Agent *Api,Packet *pack)
{	const char *data = pack->p_data;
	int leng = PK_Leng(pack);

	if( Api->a_gotH != 0 ){
		Trace("Got HELLO OK (dup)");
		return;
	}
	if( sizeof(XHello) <= leng )
		leng = sizeof(XHello)-1;
	XStrncpy(AVStr(XHello),data,leng+1);
	Trace("Got HELLO OK[%s]",XHello);
	Api->a_gotH = 1;
}

static void send_doCONNDATA(Sox *sox,Agent *Apc,Packet *pack){
	pack->p_Ver = MYVER;
	pack->p_Type = SOX_SETOPT;
	PK_clrRaid(pack);
	PK_clrSaid(pack);
	pack->p_data[0] = SOX_O_CONNDATA;
	pack->p_data[1] = 1;
	pack->p_data[2] = 0;
	PK_setLeng(pack,3);
	writecomm(sox,Apc,pack);
}
static void send_PACKSIZE(Sox *sox,Agent *Apc,Packet *pack){
	int pwsize;

	if( PackSizeExp )
		pwsize = PackSizeExp;
	else	pwsize = PWSIZE;
	pack->p_Ver = MYVER;
	pack->p_Type = SOX_SETOPT;
	PK_clrRaid(pack);
	PK_clrSaid(pack);
	pack->p_data[0] = SOX_O_PACKSIZE;
	pack->p_data[1] = pwsize >> 8;
	pack->p_data[2] = pwsize;
	PK_setLeng(pack,3);
	writecomm(sox,Apc,pack);
	Trace("---- sent my PackSize = %d (max. %d)",pwsize,PWSIZE);
}
static void set_PACKSIZE(Sox *sox,Agent *Api,Packet *pack){
	int pwsize;

	pwsize = ((0xFF&pack->p_data[1])<<8) | (0xFF & pack->p_data[2]);
	Trace("---- got remote PackSize = %d",pwsize);
	if( PackSizeExp ){
		if( PackSizeExp < pwsize ){
			pwsize = PackSizeExp;
		}
	}
	if( pwsize < PackSize ){
		if( 128 < pwsize )
			PackSize = pwsize;
	}else
	if( PackSize < pwsize ){
		if( PWSIZE < pwsize )
			PackSize = PWSIZE;
		else	PackSize = pwsize;
	}
	Trace("---- set PackSize = %d",PackSize);
}

static void send_PASS(Sox *sox,Agent *Api,Packet *pack){
	DGC*ctx = sox->s_ctx;
	CStr(local,128);
	CStr(remote,128);
	CStr(authb,256);
	CStr(host,128);
	int port;

	getpairName(Api->a_sock,AVStr(local),AVStr(remote));
	Xsscanf(remote,"%[^:]:%d",AVStr(host),&port);
	if( get_MYAUTH(ctx,AVStr(authb),"socmux",host,port) ){
		pack->p_Type = SOX_SETOPT;
		PK_clrRaid(pack);
		PK_clrSaid(pack);
		pack->p_data[0] = SOX_O_AUTH;
		pack->p_data[1] = AUTH_PASS;
		Xstrcpy(DVStr(pack->p_data,2),authb);
		PK_setLeng(pack,2+strlen(pack->p_data+2)+1);
		Trace("---- sent PASSWORD from MYAUTH [%s]",authb);
		writecomm(sox,CommOutAp,pack);
	}
}
static void recv_AUTH(Sox *sox,Agent *Api,Packet *pack){
	int len;
	DGC*ctx = sox->s_ctx;
	const char *authb = &pack->p_data[2];
	AuthInfo auth;
	CStr(user,128);
	CStr(pass,128);

	if( pack->p_data[1] == AUTH_PASS ){
		Trace("---- got PASS[%s] %X",authb,CommInAp->a_authstat);
		if( CommInAp->a_authstat & AUTH_REQ ){
			bzero(&auth,sizeof(auth));
			Xsscanf(authb,"%[^:]:%s",AVStr(user),AVStr(pass));
			strcpy(auth.i_user,user);
			strcpy(auth.i_pass,pass);
			if( 0 <= doAuth(ctx,&auth) ){
				CommInAp->a_authstat |= AUTH_OK;
			}else{
				CommInAp->a_authstat |= AUTH_ERR;
			}
		}
	}
}

static void send_willCRYPT(Sox *sox,Agent *Apc,Packet *pack,int grp)
{	int len,poff,wcc;

	poff = 0;
	pack->p_Ver = MYVER;
	pack->p_Type = SOX_SETOPT;
	PK_clrRaid(pack);
	PK_clrSaid(pack);
	pack->p_data[poff++] = SOX_O_CRYPT;
	pack->p_data[poff++] = CRYPT_CREDHY; /* crypting by XOR CRC8 */
	if( grp == 0 ){
	pack->p_data[poff++] = CRYPT_DHKEY; /* DH key follows */
	}else{
	pack->p_data[poff++] = CRYPT_DHKEYX; /* DH key follows */
	pack->p_data[poff++] = grp; /* DH group */
	}

	len = CredhyGenerateKey(ToKey,QVStr(&pack->p_data[poff],pack->p_data),PBSIZE-poff);
	pack->p_data[poff+len+1] = 4; /* desired length of preamble */
	PK_setLeng(pack,poff+len+2);
	wcc = writecomm(sox,Apc,pack);
}
static void set_CRYPT(Sox *sox,Agent *Apc,Packet *pack)
{	int wcc;
	CStr(tmp,512);
	int poff,grp;
	int cv0,plen;
	int elen;
	CStr(ekey,64);
	Packet ipack;

	if( TiKey->k_group < 0 ){
		Trace("#Ignore cryption request");
		return;
	}
	poff = 0;
	if( pack->p_data[++poff] != CRYPT_CREDHY ){
		Trace("#Unknown cryption type <%x>",pack->p_data[poff]);
		return;
	}
	cv0 = 0;
	if( pack->p_data[++poff] != CRYPT_DHKEYX ){
		if( pack->p_data[poff] == CRYPT_DHKEY ){
			grp = 0;
			cv0 = 1;
			goto DOWNGRADE;
		}else{
		Trace("#No cryption key given <%x>",pack->p_data[poff]);
		return;
		}
	}
	grp = pack->p_data[++poff];
	if( grp != ToKey->k_group ){
DOWNGRADE:
		if( ToKey->k_group < grp ){
		Trace("##Unmatch group R=%d L=%d",grp,ToKey->k_group);
		return;
		}
		if( grp < ToKey->k_group ){
		Packet rpack;
		Trace("##Downgrade key from #%d to #%d",ToKey->k_group,grp);
		CredhyInit(ToKey,grp);
		CredhyInit(TiKey,grp);
		rpack = *pack;
		send_willCRYPT(sox,Apc,&rpack,grp);
		}
	}

	++poff;
	strtoHex(&pack->p_data[poff],PK_Leng(pack)-poff,AVStr(tmp),sizeof(tmp));
	Debug("got CRYPT[%s]",tmp);
	if( CredhyAgreedKey(ToKey,&pack->p_data[poff]) != 0 ){
		Trace("#Bad cryption key given");
		sleep(10);
		return;
	}
	ipack = *pack;
	if( 0 < (elen = getCKey(AVStr(ekey),sizeof(ekey))) ){
		CredhyEncrypt(ToKey,elen,ekey,ekey);
		bzero(ekey,elen);
	}
	*TiKey = *ToKey;
	/* generate up/down asymmetry */
	TiCRC8 = strCRC8(TiCRC8,TiKey->k_rcrc8,1);
	ToCRC8 = strCRC8(ToCRC8,ToKey->k_lcrc8,1);

	pack->p_Type = SOX_CRYPTON;
	pack->p_data[0] = CRYPT_CREDHY;

	if( fileno(Comminfp) != CommoutFd ){
		Trace("Don't put preamble on separate comm[%d %d]",
			fileno(Comminfp),CommoutFd);
		plen = 0;
		PK_setLeng(pack,1);
	}else
	if( !cv0 && (plen = pack->p_data[PK_Leng(pack)-1]) ){
		pack->p_data[1] = plen; /* preamble length to be sent */
		PK_setLeng(pack,2);
	}else{
		plen = 0;
		PK_setLeng(pack,1);
	}
	wcc = writecomm(sox,Apc,pack);
	putCryptPreamble(sox,Apc,&ipack,plen);

	if( file_issock(sox->s_commout) < 0 ){
		sv1log("#### NotSocket[%d] WAIT for what?\n",sox->s_commout);
		/* bug: decryption may fail at the receiver end ... */
		msleep(100);
	}
}

static int send_PING(Sox *sox,Agent *Apc,Packet *pack)
{	int wcc;
	CStr(stime,64);
	int sec,usec,msec;

	pack->p_Type = SOX_ECHO;
	PK_clrRaid(pack);
	PK_clrSaid(pack);
	sec = Gettimeofday(&usec);
	msec = sec*1000 + usec/1000;
	set_INT(pack,msec);
	wcc = writecomm(sox,Apc,pack);

	getTimestamp(AVStr(stime));
	Debug("Put ECHO [%u] %s #%d (%d)",msec,stime,TsentN,wcc);
	return wcc;
}
static int commInactive(Sox *sox)
{	int ci;
	Agent *Ap1;
	int rtime,wtime,noresp;

	rtime = wtime = 0;
	for( ci = 0; ci < Agents; ci++ ){
		Ap1 = Agentpv[ci];
		if( Ap1->a_stat == SOX_COMMOUT ){
			wtime = Ap1->a_stats.s_wtime;
		}else
		if( Ap1->a_stat == SOX_COMMIN ){
			rtime = Ap1->a_stats.s_rtime;
		}
	}
	if( rtime == 0 || wtime == 0 )
		return 0;

	noresp = wtime - rtime;
	return noresp;
}
void send_ACK(Sox *sox,Agent *Apc,Packet *pack)
{	int tid;

	pack->p_Type |= SOX_ACK;
	tid  = PK_Said(pack);
	PK_setSaid(pack,PK_Raid(pack));
	PK_setRaid(pack,tid);
	writecomm(sox,Apc,pack);
}

static int newlaid(Sox *sox)
{	int ci;

	for( ci = sox->s_nlaid; ci < NSOCK-1; ci++ )
		if( sox->s_aidactive[ci] == 0 )
			goto EXIT;

	for( ci = 0; ci < sox->s_nlaid; ci++ )
		if( sox->s_aidactive[ci] == 0 )
			goto EXIT;

	return -1;
EXIT:
	sox->s_aidactive[ci] = 1;
	sox->s_nlaid = ci + 1;
	return ci;
}

static void sweepAgents(Sox *sox)
{	int ai,idle,nudp,maxi,maxit;
	Agent *Ap,*Api;

	nudp = 0;
	Api = 0;
	maxit = -1;
	for( ai = 0; ai < Agents; ai++ ){
		Ap = Agentpv[ai];
		if( !Ap->a_Ludp )
			continue;

		nudp++;
		idle = sox->s_time - Ap->a_stats.s_time;
		if( maxit < idle ){
			Api = Ap;
			maxit = idle;
		}
		if( idle < SOXMUX_UDP_TIMEOUT )
			continue;

		Ap->a_stat = SOX_CLOSED;
		Trace("Timeout L#%d[%d]%d idle=%ds",
			Ap->a_Laid,Ap->a_abid,Ap->a_sock,
			idle);
	}
	if( SOXMUX_UDP_MAX < nudp ){
		if( Api->a_stat != SOX_CLOSED ){
			Trace("Pushout L#%d[%d]%d idle=%ds",
				Api->a_Laid,Api->a_abid,Api->a_sock,
				sox->s_time - Api->a_stats.s_time);
			Api->a_stat = SOX_CLOSED;
		}
	}
}
Agent *newAgent(Sox *sox,int raid,int sock,int stat)
{	Agent *Apn;
	int bid;

	sweepAgents(sox);

	if( elnumof(Agentpv) <= Agents ){
		static Agent dummy;
		syslog_ERROR("#### FATAL: Too many agents ####\n");
		return &dummy;
	}

	AgentSerno++;
	Apn = Agentpv[Agents++];
	bid = Apn->a_abid;
	bzero(Apn,sizeof(Agent));
	Apn->a_abid = bid;

	Apn->a_Laid = newlaid(sox);
	Apn->a_Xaid = raid;
	Apn->a_sock = sock;
	Apn->a_stat = stat;
	Apn->a_start = Time();
	return Apn;
}
static void delAgent(Sox *sox,int ci)
{	int cj;
	Agent *Ap1;

	if( ci != Agents-1 ){
		Ap1 = Agentpv[ci];
		for( cj = ci; cj < Agents-1; cj++ ){
			Agentpv[cj] = Agentpv[cj+1];
		}
		Agentpv[Agents-1] = Ap1;
	}
	Agents--;
}
static void dumpAgent(PCStr(what),Agent *Ap1)
{	CStr(local,256);
	CStr(remote,256);

	getpairName(Ap1->a_sock,AVStr(local),AVStr(remote));
	if( strncmp(local,"0.0.0.0:",8) == 0 )
		Strrplc(AVStr(local),7,"*");
	Trace("%s[%2d] L#%d[%02X] R#%d P=%d,%d S=%d/%d R=%d/%d [%s %s]",
		what,
		Ap1->a_sock,Ap1->a_Laid,Ap1->a_stat,Ap1->a_Xaid,
		Ap1->a_pendN,Ap1->a_lbuf.b_rem,
		Ap1->a_sent,Ap1->a_sentN,
		Ap1->a_recv,Ap1->a_recvN,
		local,remote);
}
static int Nshut;
void sox_dumpFds(Sox *sox,PVStr(fds),int siz);
static void shutdownAgents(Sox *sox)
{	int ci;
	Agent *Ap1;
	CStr(fds,256);

	sox_dumpFds(sox,AVStr(fds),sizeof(fds));
	Trace("SHUTDOWN#%d (%d){%s}",++Nshut,Qfdc,fds);
	for( ci = 0; ci < Agents; ci++ ){
		Ap1 = Agentpv[ci];
		dumpAgent("shut",Ap1);
	}
	for( ci = 0; ci < Agents; ci++ ){
		Ap1 = Agentpv[ci];
		if( Ap1->a_stat != SOX_LISTEN )
		{
			if( Ap1->a_stat == SOX_PARENT ){
				Trace("## DONT close parent[%d]",Ap1->a_sock);
			}else
			close(Ap1->a_sock);
			Ap1->a_sock = -1;
			Ap1->a_stat = SOX_CLOSED;
		}
	}
	if( CTX_withYY(sox->s_ctx) ){
		finishServYY(FL_ARG,sox->s_ctx);
		finishClntYY(FL_ARG,sox->s_ctx);
		sv1log("--yySox shutdown\n");
	}
}

int sox_connects(void *sc,Sox *sox,DGC*ctx,PVStr(local),PVStr(remote),int itvl);
#define connects(ctx,lo,re,iv) sox_connects(optctx(ctx),sox,ctx,lo,re,iv)

int CTX_CantResolv(DGC*ctx);
void clear_DGserv(DGC*ctx);

#include "param.h"
int SoxOutPort = -1; /* from PrivateSox to the owner DeleGate */
int SyncHTMUX = -1;

static void sox_init(Sox *sox,DGC*ctx,int ac,const char *av[],int *comminp,int *commoutp,PVStr(server),int ssiz)
{	int commin,commout;
	int ai;
	int stat;
	CStr(local,256);
	CStr(remote,256);
	CStr(tmp,256);
	int sock;

	dbglev = LOGLEVEL;
	commin = *comminp;
	commout = *commoutp;
	for( ai = 0; ai < ac; ai++ ){
	    const char *arg; /**/
	    const char *pp;
	    arg = av[ai];
		if( isPrivateSox(ctx) ){
			sv1log("--Sox[%d] %s\n",ai,arg);
		}
		if( pp = parameq(arg,P_SOXOUTPORT) ){
			SoxOutPort = atoi(pp);
		}else
	    if( strncasecmp(arg,"-A",2) == 0 ){
		/* accept commin/commout */
		remote[0] = 0;
		sock = VSocket(ctx,"BIND/SOX*",-1,CVStr(arg+2),AVStr(remote),"listen=1");
		Trace("BIND %d",sock);

		ACC_TIMEOUT = 0;
		local[0] = remote[0] = 0;
		commin = commout =
			VSocket(ctx,"ACPT/SOX*",sock,AVStr(local),AVStr(remote),"");
		Trace("ACPT %d",commin);

		close(sock);
	    }else
	    if( strncasecmp(arg,"-C",2) == 0 ){ /* connect commin/commout */
		int citvl = 5;
		const char *hp; /**/

		hp = arg+2;
		if( *hp == '-' ){
			hp = numscanX(hp+1,AVStr(tmp),sizeof(tmp));
			citvl = atoi(tmp);
			if( citvl <= 0 )
				citvl = 1;
			if( *hp == '-' )
				hp++;
		}
		strcpy(local,"*:*");
		commin = commout = connects(ctx,AVStr(local),CVStr(hp),citvl);
	    }else
	    if( strncasecmp(arg,"-B",2) == 0 ){
		/* accept() to be issued by remote agent */
		sock = VSocket(ctx,"BIND/SOX*",-1,CVStr(arg+2),AVStr(remote),"listen=8");
		Trace("## BIND for rmote: %d",sock);
	    }else
	    if( strncasecmp(arg,"-X",2) == 0 ){
		commin = commout = open(arg+2,2);
		Trace("COMM IN/OUT=%d %s",commin,arg+2);
	    }else
	    if( strncasecmp(arg,"-I",2) == 0 ){
		commin = open(arg+2,2);
		Trace("COMM IN=%d %s",commin,arg+2);
	    }else
	    if( strncasecmp(arg,"-O",2) == 0 ){
		commout = open(arg+2,2);
		Trace("COMM OUT=%d %s",commout,arg+2);
	    }else
	    if( strncasecmp(arg,"-Q",2) == 0 ){
		setVStrEnd(server,0);
		if( strstr(arg,"://") == 0 )
			wordscanX("tcprelay://",AVStr(server),ssiz);
		wordscanX(arg+2,TVStr(server),ssiz-strlen(server));
	    }else
	    if( strncasecmp(arg,"-v",2) == 0 ){
		switch(arg[2]){
			case 'v':
			case 'd':
				dbglev = 1;
				break;
		}
	    }
	}
	*comminp = commin;
	*commoutp = commout;
}
static int getserver(DGC*ctx,PCStr(proto),PVStr(serverurl),PCStr(from),PCStr(rclif),xPVStr(mbox),int msiz)
{	CStr(mboxb,256);
	const char *dp;
	CStr(addr,256);
	int port;

	addr[0] = 0;
	port = 0;
	if( from != NULL ){
		if( dp = wordScanY(from,addr,"^:") )
		if( *dp == ':' )
			port = atoi(dp+1);
	}
	VA_setClientAddr(ctx,addr,port,1);

	HL_setClientIF(NULL,0,1);
	if( rclif != NULL ){
		wordscanX(rclif,AVStr(addr),sizeof(addr));
		if( dp = strchr(addr,':') ){
			port = atoi(dp+1);
			truncVStr(dp);
		}else	port = 0;
		HL_setClientIF(addr,port,1);
	}

	if( mbox == 0 ){
		setPStr(mbox,mboxb,sizeof(mboxb));
		msiz = sizeof(mboxb);
	}
	setVStrEnd(mbox,0);
	if( from == 0 ){
		wordscanX("-@-",AVStr(mbox),msiz);
	}else{
		if( strchr(from,'@') ){
			wordscanX(from,TVStr(mbox),msiz-strlen(mbox));
		}else{
			wordscanX("-@",TVStr(mbox),msiz-strlen(mbox));
			wordscanX(from,TVStr(mbox),msiz-strlen(mbox));
		}
	}

	setClientCert(ctx,"SOX",mbox);
	set_realproto(ctx,proto);
	if( find_CMAP(ctx,"XSERVER",AVStr(serverurl)) < 0 )
	{
		return 0;
	}
	return 1;
}

/*
 * accept from local socket, then connect at remote host
 */
static void sox_accept1(Sox *sox,DGC*ctx,Agent *Api,Packet *pack)
{	CStr(local,256);
	CStr(remote,256);
	Agent *Apn;
	int clsock;
	int aid;
	int wcc;

	strcpy(local,"*:*");
	strcpy(remote,"*:*");
	errno = 0;
	clsock = VSocket(ctx,"ACPT/SOX",Api->a_sock,AVStr(local),AVStr(remote),"");
	Trace("L#%d accept(%d)=%d [%s]<-[%s] errno=%d",
		Api->a_Laid,Api->a_sock,clsock,remote,local,errno);
	if( clsock < 0 )
		return;

	set_ClientSock(ctx,clsock,remote,local);
	if( isPrivateSox(ctx) ){
	}else
	if( !source_permitted(ctx) ){
		Trace("Forbidden %s",remote);
		close(clsock);
		return;
	}
	if( 0 <= clsock ){
		CTX_setSockBuf(FL_ARG,ctx,clsock,1);
	}

	setNonblockingIO(clsock,1);
	set_nodelay(clsock,1);

	Apn = newAgent(sox,-1,clsock,SOX_CONNECT);
	Apn->a_Ludp = isUDPsock(clsock);
	aid = Apn->a_Laid;
	Apn->a_remote = 0;
	Qfdset = 0;

	pack->p_Type = SOX_CONNECT;
	PK_setSaid(pack,aid);
	PK_clrRaid(pack);
	set_CONNECT(Apn,pack,remote,local);
	get_conndata(sox,Apn,pack);
	Trace("CONN> L#%d[%s]",aid,pack->p_data);
	wcc = writecomm(sox,CommOutAp,pack);
}
/*
 * SERVER=proto://host:port or SERVER=proto
 */
int sox_connect1(void *sc,DGC*ctx,Packet *pack,PCStr(serverURL),PVStr(remote),PVStr(local),int *pidp);
int sox_connect0(void *sc,DGC*ctx,Packet *pack,PCStr(serverURL),PVStr(remote),PVStr(local),int *pidp)
{	int clsock,logfd;
	CStr(servU,256);
	CStr(proto,64);
	CStr(serv,256);
	CStr(opt,256);
	CStr(param,256);
	CStr(mbox,256);
	CStr(client,256);
	CStr(clif,256);
	int sockv[2];
	const char *dp;
	const char *ep;
	int pid;
	int ai;

	linescanX(serverURL,AVStr(servU),sizeof(servU));
	get_CONNECT(pack,AVStr(client),AVStr(clif));

	if( servU[0] && strstr(servU,",-fixin") ){
		sv1log("#### connect[%s][%s] R#%d L#%d\n",
			remote,servU,PK_Said(pack),PK_Raid(pack));
	}else
	getserver(ctx,"vp_in",AVStr(servU),client,clif,AVStr(mbox),sizeof(mbox));

	if( servU[0] == 0 ){
		Trace("No server L#%d R#%d %s <- %s",
			PK_Raid(pack),PK_Said(pack),clif,client);
		return -1;
	}

	Trace("SERVER=%s",servU);
	param[0] = 0;
	if( dp = strchr(servU,'(') ){
		wordScanY(dp+1,param,"^)");
		if( ep = strchr(servU,')')  )
			ovstrcpy((char*)dp,ep+1);
	}
	opt[0] = 0;
	if( dp = strchr(servU,',') ){
		wordscanX(dp,AVStr(opt),sizeof(opt));
		truncVStr(dp);
	}
	proto[0] = serv[0] = 0;
	Xsscanf(servU,"%[^:]://%[^/?]",AVStr(proto),AVStr(serv));
	if( serv[0] && strchr(serv,':') == 0 )
	if( !streq(serv,"-") && !streq(serv,"-.-") )
	{
		Xsprintf(TVStr(serv),":%d",serviceport(proto));
	}
	if( streq(proto,"udprelay") )
		strcat(serv,".udp");
	Trace("SERVER=%s://%s/%s(%s):-:%s",proto,serv,opt,param,mbox);

	if( streq(serv,"-") || streq(serv,"-.-") || param[0] ){
		const char *av[32]; /**/
		CStr(ab,1024);
		refQStr(ap,ab); /**/
		int ac,fd,fd0,fd1,fd2;

		/*
		INET_Socketpair(sockv);
		*/
		if( INET_Socketpair(sockv) < 0 ){
			Trace("Could not get Socketpair()");
			return -1;
		}
		clsock = sockv[0];
		setserversock(sockv[1]);
		logfd = curLogFd();
		for( fd = 0; fd < NSOCK; fd++ ){
			if( fd != sockv[1] )
			if( fd != logfd )
			if( fd != fileno(stderr) )
				setCloseOnExec(fd);
		}
		ac = 0;
		ap = ab;
		sprintf(ap,"SERVER=%s://%s",proto,serv);
		av[ac++] = ap; ap += strlen(ap) + 1;
		sprintf(ap,"-P-%s",clif);
		av[ac++] = ap; ap += strlen(ap) + 1;
		sprintf(ap,"-L0x%x/%d",LOG_type,logfd);
		av[ac++] = ap; ap += strlen(ap) + 1;
		sprintf(ap,"ADMIN=%s",getADMIN());
		av[ac++] = ap; ap += strlen(ap) + 1;
{
FILE *fopenSvstats(PCStr(serv),PCStr(mode));
FILE *fopenInitLog(PCStr(name),PCStr(mode));
	static FILE *sfp; 
	static FILE *ifp; 
	CStr(serv,128);

	if( sfp == NULL ){
		sprintf(serv,"_sockmux_");
		sfp = fopenSvstats(serv,"w+");
		ifp = fopenInitLog(serv,"a+");
	}
	if( sfp ){
		sprintf(ap,"-IS%d",fileno(sfp));
		av[ac++] = ap; ap += strlen(ap) + 1;
	}
	if( ifp ){
		sprintf(ap,"-II%d",fileno(ifp));
		av[ac++] = ap; ap += strlen(ap) + 1;
	}
 }

		/*
		sscanf (pack->p_data,"%s %s",rclient,rhost);
		sprintf(ap,"_remoteport=%s",rsvd);
		av[ac++] = ap; ap += strlen(ap) + 1;
		*/

		if( param[0] ){
			ac += decomp_args(&av[ac],32-ac,param,AVStr(ap));
		}
		av[ac] = 0;
		for( ai = 0; ai < ac; ai++ ){
			Debug("[%d] %s",ai,av[ai]);
		}
		fd0 = dup(0); fd1 = dup(1); fd2 = dup(2);
		dup2(sockv[1],0);
		dup2(sockv[1],1);
		dup2(fileno(stderr),2);
		pid = spawnv_self1(ac,av);
		close(sockv[1]);
		dup2(fd0,0); dup2(fd1,1); dup2(fd2,2);
		close(fd0); close(fd1); close(fd2);
		Trace("Fork pid=%d",pid);
		NUM_CHILDREN++;
		CHILD_SERNO++;
		putLoadStat(ST_ACC,1);
		put_svstat();
		*pidp = pid;
	}else{
		void initConnect(DGC*ctx);
		initConnect(ctx);

		/* this connect should be in non-blocking */
		setVStrEnd(local,0);
		clsock = VSocket(ctx,"CNCT/SOX",-1,AVStr(local),AVStr(serv),"self");
		*pidp = 0;
	}
	if( 0 <= clsock ){
		gethostName(clsock,AVStr(local),"%A:%P");
		getpeerName(clsock,AVStr(remote),"%A:%P");
	}
	return clsock;
}
static void getcommpath(PCStr(fifo),PVStr(path))
{	const char *dp;

	setVStrEnd(path,0);
	if( dp = strstr(fifo,"@") )
	{
		strcpy(path,dp+1);
	}
}
Sox *sox_setup1(DGC*ctx)
{	CStr(fifo,256);
	Sox *sox;
	int sec,usec,len;

	sox = (Sox*)calloc(1,sizeof(Sox));

	if( lVERB() )
	if( dbglev == 0 )
		dbglev = 1;

	bzero(sox,sizeof(Sox));
	sox->s_ctx = ctx;

	sec = Gettimeofday(&usec);
	StrftimeGMT(AVStr(LHello),sizeof(LHello),"%Y%m%d-%H%M%S%.6s ",sec,usec);
	gethostname(Myname,sizeof(Myname));
	len = strlen(LHello);
	XStrncpy(NVStr(LHello) LHello+len,Myname,sizeof(LHello)-len);

	Ocommin = -1;
	Qtimeout = -1; /* infinite wait for PollInsOuts() */

	if( getserver(ctx,"vp_comm",AVStr(fifo),NULL,NULL,VStrNULL,0) ){
		getcommpath(fifo,AVStr(Infifo));
		strcpy(Outfifo,Infifo);
		Trace("comm=%s [%s]",Infifo,fifo);
	}
	if( getserver(ctx,"vp_commin",AVStr(fifo),NULL,NULL,VStrNULL,0) ){
		getcommpath(fifo,AVStr(Infifo));
		Trace("commin=%s [%s]",Infifo,fifo);
	}
	if( getserver(ctx,"vp_commout",AVStr(fifo),NULL,NULL,VStrNULL,0) ){
		getcommpath(fifo,AVStr(Outfifo));
		Trace("commout=%s [%s]",Outfifo,fifo);
	}
	if( getserver(ctx,"vp_proc",AVStr(fifo),NULL,NULL,VStrNULL,0) ){
		getcommpath(fifo,AVStr(sox->s_proc));
		Trace("proc=%s",sox->s_proc);
	}
	return sox;
}

int SoxImmRestart;
/*
int sox_setup(int ac,const char *av[],DGC*ctx,int svsock,int svport,Sox *sox)
*/
int sox_setupX(int ac,const char *av[],DGC*ctx,int svsock,int svport,Sox *sox,int insock,int inport)
{	const char *isvproto;
	const char *isvhost = 0;
	int isvport = 0;
	int stat;
	int commin;
	int ci;
	int rcode;
	Packet packb,*pack = &packb;
	CStr(local,256);
	CStr(remote,256);
	Agent *Ap1,*Apn,*Apb;
	int wcc,rcc,pid;
	int sockc,portv[NSOCK],sockv[NSOCK];
	int ntry = 0;

	if( 1 ){
		int ai;
		const char *a1;
		const char *pp;
		for( ai = 0; ai < ac; ai++ ){
			a1 = av[ai];
			if( pp = parameq(a1,P_SYNCHTMUX) ){
				SyncHTMUX = atoi(pp);
			}else
			if( pp = parameq(a1,P_SOXINPORTS) ){
				sox->s_soxinports = pp;
			}
		}
	}
	if( lSINGLEP() && isPrivateSox(ctx) ){
		int ai;
		const char *a1;
		IStr(host,256);
		int port = 8707;

		for( ai = 0; ai < ac; ai++ ){
			a1 = av[ai];
			if( strneq(a1,"SERVER=sockmux://",17) ){
				Xsscanf(a1+17,"%[^:]:%d",AVStr(host),&port);
				isvproto = "sockmux";
				isvhost = stralloc(host);
				isvport = port;
			}else
			if( strneq(a1,"SOXCONF=",8) ){
				scan_SOXCONF(ctx,a1+8);
			}
		}
		sockv[0] = svsock;
		sockc = 1;
		if( 1 ){
			/* should be by SOXCONF=dhkey:none if necessary */
		}else
		DHKgrp = -1; /* WinCE on ARM ? */
	}else{
	isvport = CTX_get_iserver(ctx,&isvproto,&isvhost);
	sockc = getReservedPorts(portv,sockv);
	}
	if( 0 <= insock ){
		portv[sockc] = inport;
		sockv[sockc] = insock;
		sockc++;
		for( ci = 0; ci < sockc; ci++ ){
			porting_dbg("###SoxIn(%d) PORT[%d/%d]",
				ci,portv[ci],sockv[ci]);
		}
	}

	if( 0 <= DHKgrp ){
		CredhyInit(ToKey,DHKgrp);
		CredhyInit(TiKey,DHKgrp);
	}else{
		ToKey->k_group = -1;
		TiKey->k_group = -1;
	}

	if( 0 < svport && IsConnected(svsock,NULL) ){
		commin = CommoutFd = svsock;
		Trace("Given Connected Socket [%d]",svsock);
		oneTime = 1;
		goto CONNDONE;
	}

RETRY:
	if( oneTime )
		return -1;

	if( 3 < ntry++ ){
		sleep(3);
	}

	CFI_DISABLE = 0;
	close_FSV(ctx);
	if( 0 <= Ocommin ){
		Trace("## Close old commin hidden by FCL: %d",Ocommin);
		close(Ocommin);
		Ocommin = -1;
	}
	if( Comminfp != NULL ){
		Trace("## Close Comminfp %d/%X",fileno(Comminfp),Comminfp);
		fshutdown(Comminfp,1);
		fclose(Comminfp);
		Comminfp = NULL;

		Trace("## [%d.%X] %d) %d %d",getpid(),PRTID(getthreadid()),
			ntry,isPrivateSox(ctx),AccViaHTMUX);
		if( lSINGLEP() && isPrivateSox(ctx) ){
			/* maybe this delay is for non-socket/IP Commin */
		}else
		if( SoxImmRestart ){
			SoxImmRestart = 0;
			Trace("## Set Restart Immediately");
		}else
		if( ntry < 3 ){
		}else
		sleep(5);
	}
	/*
	while( 0 < (pid = NoHangWait()) ){
	*/
	while( 0 < (pid = timeoutWait(100)) ){
		Trace("Exit pid=%d",pid);
	}
	set_ClientSock(ctx,-1,"","");

	commin = CommoutFd = -1;
	if( commin < 0 && sox->s_proc[0] ){
		int sio[2];
		if( procSocket(ctx,sox->s_proc,sio) == 0 ){
			commin = sio[0];
			CommoutFd = sio[1];
		}
		Trace("PROC [%d,%d] %s",commin,CommoutFd,sox->s_proc);
	}
	if( commin < 0 && Infifo[0] ){
		commin = open(Infifo,2);
		Trace("COMMIN %d %s",commin,Infifo);
	}
	if( CommoutFd < 0 && Outfifo[0] ){
		if( strcmp(Infifo,Outfifo) == 0 )
			CommoutFd = commin;
		else{
			CommoutFd = open(Outfifo,2);
			Trace("COMMOUT %d %s",CommoutFd,Outfifo);
		}
	}
	if( commin < 0 )
	if( 0 < isvport && !streq(isvhost,"-") && !streq(isvhost,"-.-") )
	/* SERVER=sockmux://host:port given */
	{
		local[0] = 0;
		sprintf(remote,"%s:%d",isvhost,isvport);
		commin = CommoutFd = connects(ctx,AVStr(local),AVStr(remote),3);
	}
	if( commin < 0 && 0 < svport )
	/* -Pport given */
	{
		int acto = ACC_TIMEOUT;
		ACC_TIMEOUT = 0;
		local[0] = remote[0] = 0;
		commin = CommoutFd =
			VSocket(ctx,"ACPT/SOX*",svsock,AVStr(local),AVStr(remote),"");
		ACC_TIMEOUT = acto;
		if( commin < 0 ){
			Trace("ACPT %d = %d ERROR",svsock,commin);
			/*
			sleep(3);
			*/
			if( CTX_withYY_CL(ctx) ){
				sv1log("----yySox-CL broken e%d\n",errno);
				_exit(0);
			}
			goto RETRY;
		}
		Trace("ACPT %d %s <- %s",commin,local,remote);
		set_ClientSock(ctx,commin,remote,local);
		set_keepalive(commin,1);
		if( isPrivateSox(ctx) ){
		}else
		if( !source_permitted(ctx) ){
			Trace("Forbidden %s",remote);
			close(commin);
			commin = -1;
			goto RETRY;
		}
	}

CONNDONE:
	sox_init(sox,ctx,ac,av,&commin,&CommoutFd,AVStr(Serverurl),sizeof(Serverurl));
	Trace("SOX reception[%d/%d] reserved(%d) channel[%d,%d]",
		svport,svsock,sockc,commin,CommoutFd);

	if( commin < 0 ){
		return -1;
	}

	if( Nodelay )
	set_nodelay(CommoutFd,1);

	if( 0 < file_issock(commin) ){
		int fcl;
		fcl = insertFCL(ctx,commin);
		if( 0 <= fcl ){
			Trace("Filter inserted: %d -> %d",fcl,commin);
			Ocommin = commin;
			commin = CommoutFd = fcl;
		}
	}
	Comminfp = fdopen(commin,"r");
	if( Comminfp == NULL ){
		Trace("## cannot open %d\n",commin);
		return -1;
	}

	CFI_DISABLE = 1;
	RES_CACHEONLY(1);

	for( ci = 0; ci < NSOCK; ci++ ){
		Ap1 = &Agentbv[ci];
		bzero(Ap1,sizeof(Agent));
		Agentpv[ci] = Ap1;
		Ap1->a_abid = ci;
		Ap1->a_sock = -1;
		Ap1->a_Laid = (Aid)-1;
		Ap1->a_Xaid = (Aid)-1;
		sox->s_aidactive[ci] = 0;
	}
	Agents = 0;

	Apn = newAgent(sox,-1,CommoutFd,SOX_COMMOUT);
	Trace("L#%d %d COMMOUT",Apn->a_Laid,Apn->a_sock);

	Apn = newAgent(sox,-1,commin,SOX_COMMIN);
	Trace("L#%d %d COMMIN(-P%d)",Apn->a_Laid,Apn->a_sock,
		sockPort(0<=Ocommin?Ocommin:commin));

	if( lSINGLEP() ){
	}else
	if( sox_private ){
		int getParentSock();
		int fd;
		if( 0 <= (fd = getParentSock()) ){
			Apn = newAgent(sox,-1,fd,SOX_PARENT);
		}
	}

	/* must do exclusive lock here ... */
	/*
	wcc = send_HELLO(sox,&out,0,pack);
	*/
	wcc = send_HELLO(sox,CommOutAp,0,pack);
	if( CTX_withAuth(ctx) ){
		extern int AccViaHTMUX;
		if( AccViaHTMUX || sox->s_soxinports ){
			Trace("#### Auth. for non-SockMux? %d %X",
				AccViaHTMUX,sox->s_soxinports);
		}else
		CommInAp->a_authstat = AUTH_REQ;
	}

	stat = 0;
	for( ci = 0; ci < 100; ci++ ){
		double St;
		/*
		rcc = recvpack(sox,Comminfp,pack,0);
		*/
		St = Time();
		if( fPollIn(Comminfp,15*1000) == 0 ){
			Trace("COMMIN error read() timeout");
			close(CommoutFd);
			/*
			sleep(3);
			*/
			goto RETRY;
		}
		Trace("--Sox setup %.2f",Time()-St);
		rcc = recvpack(sox,CommInAp,Comminfp,pack,0);
		if( rcc < (int)PHSIZE ){
			Trace("COMMIN error read()=%d < %d",rcc,PHSIZE);
			close(CommoutFd);
			/*
			sleep(3);
			*/
			goto RETRY;
		}
		stat = pack->p_Type;
		Trace("waiting HELLO V%02X > %02X",pack->p_Ver,stat);

		if( pack->p_Ver != MYVER ){
			Trace("SockMux protocol version mismatch: %X / %X",
				pack->p_Ver,MYVER);
			close(CommoutFd);
			/*
			sleep(3);
			*/
			goto RETRY;
		}

		if( stat == SOX_HELLO
		 || stat == SOX_HELLOOK
		){
			if( stat == SOX_HELLOOK )
				got_HELLO(sox,CommInAp,pack);
			else	Trace("Got HELLO");
			/*
			send_HELLO(sox,&out,1,pack);
			*/
			send_HELLO(sox,CommOutAp,1,pack);

			if( stat == SOX_HELLOOK )
				break;
		}
	}
	if( stat != SOX_HELLOOK ){
		Trace("no HELLOOK");
		return -1;
	}

	send_PACKSIZE(sox,CommOutAp,pack);
	if( !SOX_NOENCRYPT ){
		if( 0 <= ToKey->k_group )
			send_willCRYPT(sox,CommOutAp,pack,ToKey->k_group);
		send_PING(sox,CommOutAp,pack); /* for test */
	}
	if( !SOX_NOCONNDATA )
		send_doCONNDATA(sox,CommOutAp,pack);
	if( s_rsap ){
		send_BIND(sox,CommOutAp,pack,s_rsap,0);
	}

	/*
	 * set Nonblocking after HELLO done, or do HELLO after PollIn()
	 */
	/*
	setNonblockingIO(CommoutFd,1);
	*/

	for( ci = 0; ci < sockc; ci++ ){
		Apn = newAgent(sox,-1,sockv[ci],SOX_LISTEN);
		Trace("L#%d %d PORT=%d",Apn->a_Laid,Apn->a_sock,portv[ci]);
	}
	return 0;
}

static Sox *sox0;
static void (*savsigTERM)(int);
void sox_finish(){
	if( sox0 ){
		shutdownAgents(sox0);
	}
}
static void sigTERM(int sig)
{
	Trace("---- SIGTERM %d ----",sig);
	if( sox0 )
		shutdownAgents(sox0);
	if( savsigTERM )
		(*savsigTERM)(sig);
	Finish(0);
}
void checkServerFinish(const char *fmt,...){
	IStr(msg,128);
	int ppid;
	VARGS(8,fmt);

	if( lSINGLEP() ){
		return;
	}
	if( !sox_private )
		return;
		
	ppid = getppid();
	if( procIsAlive(ppid) == 0 ){
		sprintf(msg,fmt,VA8);
		porting_dbg("## No parentServ[%d] %s",ppid,msg);
		Finish(-1);
	}
}
static int sox_clock1(Sox *sox,DGC*ctx);
int sox_mainX(int ac,const char *av[],DGC*ctx,int svsock,int svport,int insock,int inport);
int sox_main(int ac,const char *av[],DGC*ctx,int svsock,int svport)
{
	return sox_mainX(ac,av,ctx,svsock,svport,-1,0);
}
int sox_mainX(int ac,const char *av[],DGC*ctx,int svsock,int svport,int insock,int inport)
{	Sox *sox;
/*
{	Sox soxb,*sox = &soxb;
*/

	sv1log("START\n");
	savsigTERM = Vsignal(SIGTERM,sigTERM);
	savsigTERM = Vsignal(SIGINT, sigTERM);
	Vsignal(SIGPIPE,sigPIPE);
	Vsignal(SIGCONT,sigCONT);
	sox = sox_setup1(ctx);
	sox0 = sox;
START:
	/*
	if( sox_setup(ac,av,ctx,svsock,svport,sox) < 0 )
	*/
	if( sox_setupX(ac,av,ctx,svsock,svport,sox,insock,inport) < 0 )
		goto EXIT;

	Debug("---- START ----");
	sox_init_done = 1;
	Qfdset = 0;
	for(;;){
		if( sox_clock1(sox,ctx) < 0 )
		if( oneTime )
			goto EXIT;
		else
			goto START;
	}
EXIT:
	sv1log("DONE\n");
	if( lSINGLEP() && Comminfp != NULL ){
		sv1log("## Comminfp=%X/%d\n",p2i(Comminfp),fileno(Comminfp));
		fcloseFILE(Comminfp);
		Comminfp = 0;
	}else
	Finish(0);
	return 0;
}
int service_sockmux(DGC*ctx,int _1,int _2,int fromC,int toC,PCStr(svproto),PCStr(svhost),int svport,PCStr(svpath))
{ 
	if( isPrivateSox(ctx) ){
	}else
	if( !source_permitted(ctx) ){
		CStr(shost,128);
		int sport;
		sport = getClientHostPort(ctx,AVStr(shost));
		sv1log("Forbidden %s:%d\n",shost,sport);
		return -1;
	}
	sox_main(0,NULL,ctx,fromC,svport);
	return 0;
}

static void sox_fdset(Sox *sox);
static void sox_relay1(Sox *sox,Agent *Api,int sin,Packet *pack,int OOB);
static int sox_COMMIN(Sox *sox,Agent *Api,DGC*ctx,Packet *pack,int OOB);

static int sox_clock1(Sox *sox,DGC*ctx)
{	int nready;
	int rev[NSOCK];
	int ri,rx;
	Agent *Api;
	Packet packb,*pack = &packb;
	Packet oobpack;
	int oobpushed = 0;
	int Na1,Qfdc1=0,Qfdc2=0,Qfdc3=0; /* just for debugging */

	sox->s_clock++;
	sox->s_time = time(0);

	if( Qfdset == 0 )
		sox_fdset(sox);

	Debug("%d poll(%d/%d) S=%u/%u R=%u/%u",sox->s_clock,Qfdc,Agents,
		Tsent,TsentN,Trecv,TrecvN);

	Na1 = Agents;
	Qfdc1 = Qfdc;
	if( 0 < ready_cc(Comminfp) ){
		rx = -1;
		for( ri = 0; ri < Qfdc; ri++ ){
			rev[ri] = 0;
			if( Qfdv[ri] == fileno(Comminfp) ){
				rx = ri;
			}
		}
		if( 0 <= rx ){
			ri = rx;
			Api = Agentpv[Qcxv[ri]];
			rev[ri] = PS_IN; 
			goto COMMIN;
		}
	}

	if( Nopush ){
		set_nopush(CommoutFd,0);
		send(CommoutFd,"",0,0);
	}
	if( Cork ){
		set_cork(CommoutFd,0);
	}
	Qfdc2 = Qfdc;
	nready = PollInsOuts(10*1000,Qfdc,Qfdv,Qqev,rev);
	if( nready < 0 ){
		if( lSINGLEP() ){
			for( ri = 0; ri < Qfdc; ri++ ){
				sv1log("## clock1 %d) [%d]%d\n",
					ri,Qfdv[ri],SocketOf(Qfdv[ri]));
			}
		}
	}
	if( Cork ){
		set_cork(CommoutFd,1);
	}
	if( Nopush ){
		set_nopush(CommoutFd,1);
	}

	if( nready == 0 ){
		checkServerFinish("clock1-A");
		/*
		Trace("poll(%d) = %d",Qfdc,0);
		for( ri = 0; ri < Agents; ri++ ){
			Api = Agentpv[ri];
			Trace("L#%d R#%d stat=%X pending-R=%d,L=%d",
				Api->a_Laid,Api->a_Xaid,
				Api->a_stat,
				Api->a_pend,
				Api->a_lbuf.b_rem);
		}
		for( ri = 0; ri < 256; ri++ ){
			if( sox->s_Rpstats[ri] ){
				Trace("%02X %d",ri,sox->s_Rpstats[ri]);
			}
		}
		*/
		/*
		nready = PollInsOuts(Qtimeout*1000,Qfdc,Qfdv,Qqev,rev);
		*/
		if( Nopush ){
			set_nopush(CommoutFd,0);
			send(CommoutFd,"",0,0);
		}
		if( Cork ){
			set_cork(CommoutFd,0);
		}
		Qfdc3 = Qfdc;
		nready = PollInsOuts(20*1000,Qfdc,Qfdv,Qqev,rev);
		if( Cork ){
			set_cork(CommoutFd,1);
		}
		if( Nopush ){
			set_nopush(CommoutFd,1);
		}
		if( nready == 0 ){
			checkServerFinish("clock1-B");
			if( 60 <= commInactive(sox) ){
				Trace("Comm seems inactive (%d)",Qfdc);
				Trace("Comm seems inactive (%d) %s",
					Qfdc,tstmp(sox));
				shutdownAgents(sox);
				return -1;
			}
			nsigPIPE = 0;
			sox->s_time = time(0);
			send_PING(sox,CommOutAp,pack);
			if( 0 < nsigPIPE ){
				Trace("SIGPIPE when sending to CommOut");
				return -1;
			}else	return 0;
		}
	}
	if( nready <= 0 ){
		Trace("TIMEOUT fdc=%d nready=%d %ds",
			Qfdc,nready,time(0)-sox->s_time);
		if( CTX_withYY_BROKEN(ctx) ){
			sv1log("----yySox poll broken e%d\n",errno);
			_exit(0);
		}
		for( ri = 0; ri < Qfdc; ri++ ){
			sv1log("## clock1 %d) [%d]%d\n",
				ri,Qfdv[ri],SocketOf(Qfdv[ri]));
		}
		checkServerFinish("TIMEOUT");
		return -1;
	}

	for( ri = 0; ri < Qfdc; ri++ ){
		Api = Agentpv[Qcxv[ri]];
		if( rev[ri] == 0 )
			continue;

		if( rev[ri] & (PS_HUP | PS_ERR) ){
			Trace("## POLL_ERROR %x L#%d",rev[ri],Api->a_Laid);
			Trace("## POLL_ERROR %X L#%d/%d/%d %d/%d (%d %d %d) %s",
				rev[ri],Api->a_Laid,Agents,Na1,
				ri,Qfdc,Qfdc1,Qfdc2,Qfdc3,tstmp(sox));
			if( Api->a_stat == SOX_COMMIN ){
				shutdownAgents(sox);
				return -1;
			}else{
				Trace("## CLOSE TOO MUCH POLL_ERROR*%d %x L#%d",
					Api->a_errs,rev[ri],Api->a_Laid);
				if( 100 < Api->a_errs++ ){
					dupclosed(Qfdv[ri]);
				}
			}
		}
		if( rev[ri] & PS_OUT ){
			int rem,sent;
			rem = Api->a_lbuf.b_rem;
			writesock(sox,Api,NULL);
			if( sent = rem - Api->a_lbuf.b_rem ){
				pack->p_Type = SOX_SENT;
				PK_setRaid(pack,Api->a_Xaid);
				PK_setSaid(pack,Api->a_Laid);
				set_INT(pack,sent);
				writecomm(sox,CommOutAp,pack);
				Trace("## FLUSHED=%d L#%d stat=%X",
					sent,Api->a_Laid,Api->a_stat);
				if( Api->a_stat == SOX_CLOSED ){
					Trace("-- FLUSHED L#%d rem(%d/%d)",
						Api->a_Laid,sent,rem);
				}else
				Api->a_stat = SOX_SENT;
				Qfdset = 0;
			}
		}
		if( (rev[ri] & (PS_IN|PS_PRI)) == 0 )
			continue;

		if( Api->a_stat == SOX_PARENT ){
			porting_dbg("## Owner Process Dead [%d] [%d]=%X",
				getppid(),Qfdv[ri],rev[ri]);
			checkServerFinish("poll[%d]=%X",Qfdv[ri],rev[ri]);
			Finish(0);
		}

		if( Api->a_stat == SOX_COMMIN )
		COMMIN:{
		/* relay from remote to local */
			if( rev[ri] & PS_PRI ){
				if( sox_COMMIN(sox,Api,ctx,pack,1) < 0 ){
					return -1;
				}
			}
			if( rev[ri] & PS_IN )
				if( sox_COMMIN(sox,Api,ctx,pack,0) < 0 )
					return -1;
			continue;
		}
		if( Api->a_stat == SOX_LISTEN ){
		/* accept at reception socket(s) */
			sox_accept1(sox,ctx,Api,pack);
			continue;
		}
		/* relay local sockets to remote */
		if( rev[ri] & PS_PRI )
		{
			sox_relay1(sox,Api,Qfdv[ri],pack,1);
			if( pack->p_Type == SOX_OOBPUSH ){
				oobpushed = 1;
				oobpack = *pack;
			}
		}
		if( rev[ri] & PS_IN )
		{
			sox_relay1(sox,Api,Qfdv[ri],pack,0);
		}
		if( oobpushed )
		{
			sox_relay1(sox,Api,Qfdv[ri],&oobpack,2);
		}
	}
	return 0;
}

typedef struct {
	int	c_fd;
	int	c_tid;
    const char *c_F;
	int	c_L;
} Close1;
static int closes[2] = {-1,-1};
int closetid;
int closei;
int closeo;
extern int THEXIT;
int stopcloseR(){
	Close1 c1;
	if( closetid && 0 <= closes[1] ){
		c1.c_fd = -1;
		c1.c_tid = 0;
		IGNRETP write(closes[1],&c1,sizeof(c1));
		return 1;
	}
	return 0;
}
int waitLock();
static int closeQ(){
	int rdy;
	int ci;
	Close1 c1;
	int rcc;
	int wi;
	int rcode;
	double St,Now;

	for( ci = 0; ; ci++ ){
		rdy = PollIn(closes[0],60*1000);
		if( THEXIT ){
			sv1log("-- closeR(%d) %d/%d rdy=%d TX=%d\n",
				ci,closeo,closei,rdy,THEXIT);
			break;
		}
		if( rdy < 0 ){
			sv1log("## closeR(%d) %d/%d rdy=%d\n",
				ci,closeo,closei,rdy);
			break;
		}
		if( rdy == 0 ){
			Verbose("-- closeR(%d) %d/%d rdy=%d\n",
				ci,closeo,closei,rdy);
			continue;
		}
		rcc = read(closes[0],&c1,sizeof(c1));
		if( rcc != sizeof(c1) ){
			sv1log("## closeR(%d) %d/%d rdy=%d rcc=%d\n",
				ci,closeo,closei,rdy,rcc);
			break;
		}
		closeo++;
		wi = waitLock();
		St = Time();
		/* set the owner thread of the fd */
		/*
		waitShutdownSocket(c1.c_F,c1.c_L,c1.c_fd,3*1000);
		*/
		rcode = close(c1.c_fd);
		Now = Time();
		sv1log("-- closeR(%d) %d/%d rco=%d [%d]%04X %d %.3f <= %s:%d\n",
			ci,closeo,closei,rcode,c1.c_fd,PRTID(c1.c_tid),
			wi,Now-St,c1.c_F,c1.c_L);
	}
	return ci;
}
static int byme(){
	int ri;
	if( closetid == 0 ){
		closetid = -1;
		return 1;
	}
	for( ri = 0; ri < 10; ri++ ){
		if( closetid != -1 ){
			break;
		}
		msleep(300);
	}
	sv1log("-- got closeQ %X (%d)\n",closetid,ri);
	return 0;
}
int closeR(FL_PAR,int fd){
	int rcode;
	double St,Now;

	/*
	if( lSINGLEP() )
	*/
	if( INHERENT_thread() )
	{
		Close1 c1;
		if( closetid == 0 ){
		    if( byme() ){
			Socketpair(closes);
			closetid = thread_fork(0x40000,0,"closeR",(IFUNCP)closeQ);
			sv1log("-- created closeQ %X\n",PRTID(closetid));
		    }
		}
		c1.c_fd = fd;
		c1.c_tid = getthreadid();
		c1.c_F = FL_F;
		c1.c_L = FL_L;
		IGNRETP write(closes[1],&c1,sizeof(c1));
		closei++;
		return 0;
	}
	St = Time();
	rcode = close(fd);
	Now = Time();
	if( 1 < Now-St ){
		Trace("#### SLOW CLOSE [%d] %.3f",fd,Now-St);
	}
	return rcode;
}

void sox_dumpFds(Sox *sox,PVStr(fds),int siz)
{	int i;
	refQStr(sp,fds); /**/
	Agent *Ap1;

	setVStrEnd(fds,0);
	cpyQStr(sp,fds);
	for( i = 0; i < Qfdc && i < 16; i++ ){
		Ap1 = Agentpv[Qcxv[i]];
		sprintf(sp,"%s#%d/%d/%d",i?",":"",Ap1->a_Laid,Qfdv[i],Qqev[i]);
		sp += strlen(sp);
	}
}
static void sox_fdset(Sox *sox)
{	int ci,cj;
	Agent *Ap1;
	int rcode;
	int qev;

	for( ci = 0; ci < Agents; ci++ ){
		Ap1 = Agentpv[ci];
		if( Ap1->a_stat == SOX_CLOSED ){
			if( 0 < Ap1->a_lbuf.b_rem ){
				if( Ap1->a_ltCLOSED == 0 )
				if( Llinger < sox->s_time - Ap1->a_rtCLOSED ){
					Trace("-- Timeout close L#%d rem(%d)",
						Ap1->a_Laid,Ap1->a_lbuf.b_rem);
				}else{
					Trace("-- Delay close L#%d rem(%d)",
						Ap1->a_Laid,Ap1->a_lbuf.b_rem);
					continue;
				}
			}
			/*
			rcode = close(Ap1->a_sock);
			*/
			rcode = closeR(FL_ARG,Ap1->a_sock);
/*
	Trace("Fin L#%d[%d]%d S=%d/%d P=%d/%d R=%d/%d S,R=%d/%d,%d/%d",
*/
	Trace("Fin L#%d[%d]%d S=%d/%d P=%d/%d R=%d/%d S,R=%d/%d,%d/%d (%.3f)",
				Ap1->a_Laid,Ap1->a_abid,Ap1->a_sock,
				Ap1->a_sent,Ap1->a_sentN,
				Ap1->a_pendN,TpendN,
				Ap1->a_recv,Ap1->a_recvN,
/*
				Tsent,TsentN,Trecv,TrecvN
*/
				Tsent,TsentN,Trecv,TrecvN,
				Time() - Ap1->a_start
			);
			Ap1->a_sock = -1;

			if( Ap1->a_pid ){
				int pid;
				while( 0 < (pid = NoHangWait()) ){
					Trace("Exit pid=%d",pid);
					/*
					TOTAL_SERVED++;
					*/
					*pTOTAL_SERVED += 1;
					NUM_CHILDREN--;
					putLoadStat(ST_DONE,1);
					put_svstat();
				}
			}
			sox->s_aidactive[Ap1->a_Laid] = 0;
			delAgent(sox,ci);
		}
	}
	Qfdc = 0;
	for( ci = 0; ci < Agents; ci++ ){
		Ap1 = Agentpv[ci];
		qev = 0;

		if( Ap1->a_stat != SOX_COMMOUT )
		if( Ap1->a_stat != SOX_CONNECT )
		if( Ap1->a_stat != SOX_CLOSE )
		if( Ap1->a_stat != SOX_SENDING )
		if( Ap1->a_stat != SOX_SENDINGOOB )
		{
			qev |= (PS_IN | PS_PRI);
		}
		if( Ap1->a_lbuf.b_rem ){
			qev |= PS_OUT;
		}
		if( qev ){
			Qcxv[Qfdc] = ci;
			Qfdv[Qfdc] = Agentpv[ci]->a_sock;
			Qqev[Qfdc] = qev;
			Qfdc++;
		}
	}
	Qfdset = 1;
}
static void sox_relay1(Sox *sox,Agent *Api,int sin,Packet *pack,int OOB)
{	int wcc;

	if( Api->a_stat == SOX_CLOSE || Api->a_stat == SOX_CLOSED ){
		Trace("Closing> L#%d[%X] -> R#%d[SEND] ignored",
			Api->a_Laid,Api->a_stat,Api->a_Xaid);
		Qfdset = 0;
		return;
	}

	wcc = sock2comm(sox,Api,sin,CommOutAp,pack,OOB);
	if( wcc == 0 && pack->p_Type == SOX_OOBPUSH ){
		return;
	}else
	if( 0 < wcc ){
		/*
		Api->a_sent += PK_Leng(pack);
		Api->a_sentN++;
		*/
		Api->a_rpend += PK_Leng(pack);
		if( OOB ){
			TpendN++;
			Api->a_pendN++;
			Api->a_stat = SOX_SENDINGOOB;
		}else{
			/*
			if( PWSIZE*MAXPENDING < Api->a_rpend ){
			*/
			if( PackSize*PqueSize < Api->a_rpend ){
				TpendN++;
				Api->a_pendN++;
				Api->a_stat = SOX_SENDING;
			}else	Api->a_stat = SOX_SEND;
		}
		Qfdset = 0;
		Debug("SEND> L#%d -> R#%d (%d) pending=%d",
			Api->a_Laid,Api->a_Xaid,PK_Leng(pack),Api->a_rpend);
	}else
	if( errno == EAGAIN ){
		Trace("EAGAIN for read()");
	}else{
		Api->a_stat = SOX_CLOSE;
		if( 0 < Api->a_lbuf.b_rem ){
			Trace("##CLOSE>## L#%d discard pending output(%d)",
				Api->a_Laid,Api->a_lbuf.b_rem);
			Api->a_lbuf.b_rem = 0;
		}
		Qfdset = 0;

		pack->p_Type = SOX_CLOSE;
		PK_setSaid(pack,Api->a_Laid);
		PK_setRaid(pack,Api->a_Xaid);
		set_STR(pack,"DO close");
		writecommX(sox,Api,CommOutAp,pack);
		Trace("CLOSE> L#%d -> R#%d (rcc=%d errno=%d)",
			Api->a_Laid,Api->a_Xaid, wcc,errno);
	}
}
static int sox_COMMIN(Sox *sox,Agent *Api,DGC*ctx,Packet *pack,int OOB)
{	int rcc;
	int stat;
	Agent *ApR,*Apn;
	int pid;
	int ci;
	int clsock;
	int aid;
	CStr(local,256);
	CStr(remote,256);
	CStr(pair,512);
	int wcc;
	int ostat;

	/*
	rcc = recvpack(sox,Comminfp,pack,OOB);
	*/
	rcc = recvpack(sox,Api,Comminfp,pack,OOB);
	if( rcc < 0 ){
		shutdownAgents(sox);
		return -1;
	}
	stat = pack->p_Type;
	sox->s_Rpstats[stat] += 1;

	ApR = 0;
	for( ci = 0; ci < Agents; ci++ ){
		if( Agentpv[ci]->a_Laid == PK_Raid(pack) ){
			ApR = Agentpv[ci];
			if( (stat & SOX_ACK) == 0 ){
				ApR->a_recv += PK_Leng(pack);
				ApR->a_recvN++;
			}
			ApR->a_stats.s_time = sox->s_time;
			break;
		}
	}
	if( 1 < dbglev ){
		Trace("recvpack L#%d[%02X] <- R#%d[%02X] %d/%d/%d",
			ApR?ApR->a_Laid:-1,ApR?ApR->a_stat:0,
			PK_Said(pack)!=0xFFFF?PK_Said(pack):-1,stat,
			PK_Leng(pack),ApR?ApR->a_recv:0,ApR?ApR->a_recvN:0);
	}

	if( ApR )
	if( ApR->a_stat == SOX_CLOSE || ApR->a_stat == SOX_CLOSED )
	/* ignore packets arrived during closing */
	{
		if( stat != SOX_CLOSED && stat != SOX_CLOSE ){
			Trace("Closing< L#%d[%X] <- R#%d[%X] ignored",
				PK_Raid(pack),ApR->a_stat,PK_Said(pack),stat);
			return 0;
		}
	}

	if( CommInAp->a_authstat & AUTH_REQ )
	if( (CommInAp->a_authstat & AUTH_OK) == 0 ){
		switch( stat ){
			case SOX_CONNECT:
			case SOX_BIND:
				Trace("NOT AUTHENTICATED");
				pack->p_Type = SOX_CLOSE;
				PK_setRaid(pack,PK_Said(pack));
				PK_clrSaid(pack);
				set_STR(pack,"### Not Authenticated ###");
				wcc = writecomm(sox,CommOutAp,pack);
				return -1;
		}
	}

	switch( stat ){
	case -1:
		Trace("BROKEN CONNECTION");
		/* broken connection */
		return -1;

	case SOX_NOOP:
		{
		CStr(stime,64);
		getTimestamp(AVStr(stime));
		Trace("Got NOOP %s #%d",stime,TrecvN);
		break;
		}
	case SOX_ECHO:
		Debug("Got ECHO [%u]",get_INT(pack));
		send_ACK(sox,CommOutAp,pack);
		break;
	case SOX_ECHOOK:
		Debug("Got ECHO [%u] OK",get_INT(pack));
		break;

	case SOX_HELLO:
		Trace("HELLO");
		shutdownAgents(sox);
		return -1;

	case SOX_HELLOOK:
		got_HELLO(sox,Api,pack);
		break;

	case SOX_SETOPT:
		Trace("Got SETOPT [%X][%X]+%d",
			pack->p_data[0],0xFF&pack->p_data[1],PK_Leng(pack));
		if( pack->p_data[0] == SOX_O_PACKSIZE ){
			set_PACKSIZE(sox,Api,pack);
		}else
		if( pack->p_data[0] == SOX_O_CRYPT )
		{
			set_CRYPT(sox,Api,pack);
			send_PASS(sox,Api,pack);
		}
		else
		if( pack->p_data[0] == SOX_O_CONNDATA ){
			if( !SOX_NOCONNDATA ){
				Trace("CONNECT+DATA enabled");
				DO_CONNDATA = 1;
			}
		}
		else
		if( pack->p_data[0] == SOX_O_AUTH ){
			recv_AUTH(sox,Api,pack);
		}
		break;
	case SOX_CRYPTON:
		Trace("Got CRYPTON: %d",pack->p_data[0]);
		getCryptPreamble(sox,Api,pack);
		break;

	case SOX_CONNECT:
		Debug("Connect< R#%d[%s]",PK_Said(pack),pack->p_data);
		clsock = sox_connect1(optctx(ctx),ctx,pack,Serverurl,AVStr(remote),AVStr(local),&pid);
		if( clsock < 0 )
			goto SOXCLOSE;

		if( 0 <= clsock ){
			put_conndata(pack,clsock);
			setNonblockingIO(clsock,1);
			set_nodelay(clsock,1);
			Apn = newAgent(sox,PK_Said(pack),clsock,SOX_CONNECTED);
			aid = Apn->a_Laid;
			Apn->a_remote = 1;
			Apn->a_pid = pid;
			Qfdset = 0;
			Trace("Connected %d L#%d[%s] <- R#%d[%s]",
				clsock,aid,local,PK_Said(pack),pack->p_data);
			PK_setRaid(pack,Apn->a_Laid);
			set_CONNECT(Apn,pack,remote,local);
			get_conndata(sox,Apn,pack);
			send_ACK(sox,CommOutAp,pack);
		}else SOXCLOSE:{
			pack->p_Type = SOX_CLOSE;
			PK_setRaid(pack,PK_Said(pack));
			PK_clrSaid(pack);
			set_STR(pack,"No server");
			wcc = writecomm(sox,CommOutAp,pack);
		}
		break;

	case SOX_CONNECTED:
		Trace("CONNed< L#%d <- R#%d[%s]",
			PK_Raid(pack),PK_Said(pack),pack->p_data);
		if( ApR ){
			put_conndata(pack,ApR->a_sock);
			ApR->a_Xaid = PK_Said(pack);
			ApR->a_stat = SOX_CONNECTED;
			Qfdset = 0;

/*
reserve port for BIND (data connection) for each CONNECT
L#NL BIND PL
R#NR BIND PR
FTP resp. PORT PL
accept at PL by L#NL
forward to R#NR
R#NR connect to PR
ready L#NL and R#NR

STRCPY(rsvdport,"*:*");
sock = VSocket(ctx,"BIND/SOX",-1,AVSTR(rsvdport),AVSTR(remote),"listen=1");
Apb = newAgent(sox,-1,sock,SOX_LISTEN);
Apn->a_remote = 0;
Qfdset = 0;

or run SERVER=ftp at the entrance ?
*/
		}
		break;

	case SOX_SENDOOB:
		if( ApR ){
			wcc = sendOOB(ApR->a_sock,pack->p_data,PK_Leng(pack));
			Trace("SendOOB< L#%d <- R#%d (%d/%d)",
				PK_Raid(pack),PK_Said(pack),wcc,PK_Leng(pack));
			set_INT(pack,wcc);
			send_ACK(sox,CommOutAp,pack);
		}else{
			/* remove the obsolete remote agent by SOX_CLOSED */
		}
		break;

	case SOX_SENTOOB:
		if( ApR ){
			int sent = get_INT(pack);
			Trace("SENTOOB< L#%d/%X <- R#%d (%d) pending-R=%d,L=%d",
				PK_Raid(pack),ApR->a_stat,PK_Said(pack),sent,
				ApR->a_rpend,ApR->a_lpend);
			ApR->a_stat = SOX_SENTOOB;
			ApR->a_rpend -= sent;
			Qfdset = 0;
		}
		break;

	case SOX_SEND:
		Debug("Send< L#%d <- R#%d",PK_Raid(pack),PK_Said(pack));
		if( ApR ){
			if( ApR->a_stat == SOX_CLOSE ){
				Trace("##Send<## L#%d(CLOSED) R%d discard(%d)",
				PK_Raid(pack),PK_Said(pack),PK_Leng(pack));
				break;
			}
			wcc = writesock(sox,ApR,pack);
			if( wcc <= 0 ){
				break;
			}
			set_INT(pack,wcc);
			if( !OOB )
			send_ACK(sox,CommOutAp,pack);
		}else{
			/* return SOX_CLOSED */
		}
		break;

	case SOX_SENT:
		if( ApR ){
			int sent = get_INT(pack);
			ApR->a_rpend -= sent;
			/*
			if( ApR->a_rpend < PWSIZE*MAXPENDING ){
			*/
			if( ApR->a_rpend < PackSize*PqueSize ){
				if( ApR->a_stat == SOX_SENDING ){
					Debug("## RESUMED> L#%d",ApR->a_Laid);
				}
				ApR->a_stat = SOX_SENT;
				Qfdset = 0;
			}
			Debug("SENT< L#%d <- R#%d (%d) pending=%d",
			PK_Raid(pack),PK_Said(pack),sent,ApR->a_rpend);
		}else{
			/* return SOX_CLOSED */
		}
		break;

	case SOX_CLOSE:
		if( pack->p_data[0] == '#' ){
		Trace("Close< L#%d <- R#%d [%s]",PK_Raid(pack),PK_Said(pack),
			pack->p_data);
		}else
		Trace("Close< L#%d <- R#%d",PK_Raid(pack),PK_Said(pack));
		ostat = 0;
		if( ApR ){
			ostat = ApR->a_stat;
			ApR->a_stat = SOX_CLOSED;
			ApR->a_rtCLOSED = sox->s_time;
			Qfdset = 0;
		}
		if( ostat == SOX_CLOSE ){
			Trace("Close: simultaneous close from both side");
		}else{
		set_STR(pack,"OK closed");
		send_ACK(sox,CommOutAp,pack);
		}
		break;

	case SOX_CLOSED:
		Trace("CLOSED< L#%d <- R#%d",PK_Raid(pack),PK_Said(pack));
		if( ApR ){
			ApR->a_stat = SOX_CLOSED;
			Qfdset = 0;
		}
		break;

	case SOX_BIND:
		Trace("BIND< L#%d <- R#%d %s",PK_Raid(pack),PK_Said(pack),
			pack->p_data);
		recv_BIND(sox,CommOutAp,pack);
		break;
	case SOX_BINDOK:
		Trace("BIND> L#%d <- R#%d %s",PK_Raid(pack),PK_Said(pack),
			pack->p_data);
		recv_BOUND(sox,pack);
		break;

	default:
		Trace("unknown %d",stat);
		break;
	}
	return 0;
}

#endif /*} OPT_S */

/* '"DIGEST-OFF"' */
        
