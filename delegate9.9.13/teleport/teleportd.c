/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	teleportd.c (Teleport Server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950621	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "dglib.h"

int HostId(PCStr(addr));
int ACCEPT(int sock,int isServer,int lockfd,int timeout);
int getpeersNAME(int sock,PVStr(name),PVStr(saddr),int *portp);
int sockHostport(int sock,int *portp);
int set_keepalive(int sock,int on);
int readfrom(int sock,void *buff,int size,PVStr(sfrom));
int sendTimeout(int fd,PCStr(buff),int leng,int flag,int timeout);
int sendTo(int sock,PCStr(sto),PCStr(msg),int len);

#define TELEPORT_VER "0.2"

#define MAX_SOCKETS	128
#define MAX_AGENTS	512
#define MAX_SELECTORS	256

#define MSGSIZE		0x2000
#define HEADSIZE	16

#define CHECK_INTERVAL	10
#define UDP_TIMEOUT	180	/* in seconds */

typedef struct agent {
	int	a_id;
	int	a_isudpmain;
	int	a_isudpchan;
	int	a_discarded;
  const	char   *a_srcport;
	int	a_ipno;
	int	a_puase;
	int	a_nselector;

	int	a_itime;
	char   *a_ibuff;
	int	a_isize;
  const	char   *a_itop;
	int	a_irem;
	int	a_nonl;
	int	a_rfd;
	int	a_rcc;
	int	a_nr;

	int	a_osize;
  const	char   *a_obuff;
	int	a_wfd;
	int	a_wcc;
	int	a_nw;

	int	a_wseq;
  const	char   *a_chan;
  const	char   *a_zomb;
} Agent;

typedef struct receiver {
	Agent  *r_ap;
	int	r_cnt;
	int	r_rcc;
} Receiver;

typedef struct selector {
  const	char   *s_name;
	int	s_leng;
	int	s_nreceivers;
       Receiver s_receiver[MAX_SOCKETS];
} Selector;

typedef struct {
	time_t	te_starttime;
	Agent  *te_Agents[MAX_AGENTS];
	int	te_NAgents;	/* the number of active agents */
	int	te_agentID;
	Selector *te_selectors[MAX_SELECTORS];
	int	te_nselector;
	int	te_inputsN;
	Agent  *te_i_agentv[MAX_SOCKETS];
	int	te_i_sockv[MAX_SOCKETS];
	int	te_i_readyv[MAX_SOCKETS];
} TeleportEnv;
static TeleportEnv *teleportEnv;
#define starttime	teleportEnv->te_starttime
#define Agents		teleportEnv->te_Agents
#define NAgents		teleportEnv->te_NAgents
#define agentID		teleportEnv->te_agentID
#define selectors	teleportEnv->te_selectors
#define nselector	teleportEnv->te_nselector
#define inputsN		teleportEnv->te_inputsN
#define i_agentv	teleportEnv->te_i_agentv
#define i_sockv		teleportEnv->te_i_sockv
#define i_readyv	teleportEnv->te_i_readyv
static void minit_teleport()
{
	if( teleportEnv == 0 )
		teleportEnv = NewStruct(TeleportEnv);
}

static int getAx(int aid)
{	int ax;

	for( ax = 0; ax < NAgents; ax++ )
		if( Agents[ax]->a_id == aid )
			return ax;
	return -1;
}
static Agent *getAp(int aid)
{	int ax;

	if( 0 <= (ax = getAx(aid)) )
		return Agents[ax];
	else	return NULL;
}
static int getagenthost(int aid,PVStr(name),PVStr(addr),int *port)
{	int ax;

	if( (ax = getAx(aid)) < 0 )
		return 0;
	return getpeersNAME(Agents[ax]->a_wfd,AVStr(name),AVStr(addr),port);
}

static int getselx(int alloc,PCStr(selector))
{	int si;
	Selector *sp;

	for( si = 0; si < nselector; si++ ){
		sp = selectors[si];
		if( strcmp(sp->s_name,selector) == 0 )
			return si;
	}
	if( alloc == 0 )
		return -1;
	sp = (Selector*)calloc(sizeof(Selector),1);
	selectors[nselector++] = sp;
	sp->s_name = stralloc(selector);
	sp->s_leng = strlen(selector);
	return si;
}
static void addReceiverAgent(PCStr(selector),Agent *ap)
{	int selx;
	Selector *sp;
	Receiver *rp;
	int ri,rx;

	selx = getselx(1,selector);
	sp = selectors[selx];
	for( ri = 0; ri < sp->s_nreceivers; ri++ ){
		rp = &sp->s_receiver[ri];
		if( rp->r_ap == ap )
			return;
	}

	rx = sp->s_nreceivers++;
	rp = &sp->s_receiver[rx];
	rp->r_ap = ap;
	rp->r_rcc = 0;
	rp->r_cnt = 0;
}

#ifdef _MSC_VER
struct iovec {
  const	char *iov_base;
	int   iov_len;
};
#endif

#define AGENT_DEATH_TIMEOUT	5 /* seconds */

static int Writev(int fd,struct iovec iov[],int nv)
{	int wcc1,wcc,vi;

	wcc = 0;
	for( vi = 0; vi < nv; vi++ ){
		wcc1 = sendTimeout(fd,(char*)iov[vi].iov_base,iov[vi].iov_len,0,
			AGENT_DEATH_TIMEOUT);
		if( wcc1 < iov[vi].iov_len )
			return -1;
		wcc += wcc1;
	}
	return wcc;
}

static void setZOMB(Agent *ap,PCStr(reason))
{
	if( ap->a_isudpmain )
		sv1log("ZOMB: error, don't let the UDP agent be zomby\n");
	else{
		sv1log("ZONB: #%d %s\n",ap->a_id,reason);
		ap->a_zomb = reason;
	}
}

static int writeAgent(Agent *dap,PCStr(msg),int len)
{	int wcc;
	struct iovec sv[1];

	dap->a_nw += 1;
	if( dap->a_isudpchan ){
		wcc = sendTo(dap->a_wfd,dap->a_srcport,msg,len);
		if( wcc <= 0 )
			;
		else	dap->a_wcc += wcc;
	}else{
		sv[0].iov_base = (char*)msg; sv[0].iov_len = len;
		wcc = Writev(dap->a_wfd,sv,1);
		if( wcc <= 0 )
			setZOMB(dap,"CantWrite");
		else	dap->a_wcc += wcc;
	}
	return wcc;
}

static int writesAgent(Agent *dap,PCStr(s0),PCStr(s1))
{	CStr(msg,MSGSIZE*2);

	strcpy(msg,s0);
	strcat(msg,s1);
	return writeAgent(dap,msg,strlen(msg));
}

static void putStat(Agent *ap)
{	CStr(msg,MSGSIZE);
	CStr(hostport,256);
	int ax,sx,rx,aid;
	Agent *ap1;
	Selector *sp;
	Receiver *rp;
	int now;
	CStr(idle,32);

	sprintf(msg,"Teleport/%s Server by <ysato@etl.go.jp>\r\n",TELEPORT_VER);
	writesAgent(ap,msg,"");
	sprintf(msg,"STARTED: (local time) %s\r\n",ctime(&starttime));
	writesAgent(ap,msg,"");

	sprintf(msg,
	"AGENTS:\r\n  %-36s RECEIVED(B/P)   SENT(B/P)         IDLE\r\n",
		"sl#id type Host#IPaddress:port");
	writesAgent(ap,msg,"");

	now = time(0);
	for( ax = 0; ax < NAgents; ax++ ){
		ap1 = Agents[ax];
		sprintf(hostport,"%4s %4d %s",
			(ap1->a_isudpmain||ap1->a_isudpchan)?"UDP":"TCP",
			ap1->a_ipno, ap1->a_srcport);

		if( ap1->a_itime )
			sprintf(idle,"%d",now - ap1->a_itime);
		else	sprintf(idle,"-");

		sprintf(msg,"  %02d#%02d %-30s %8d %6d %8d %6d %6s\r\n",
			ax,ap1->a_id,hostport,
			ap1->a_rcc,ap1->a_nr,ap1->a_wcc,ap1->a_nw,idle);
		writesAgent(ap,msg,"");
	}
	writesAgent(ap,"\r\n","");

	sprintf(msg,
	"MESSAGES:\r\n  %-36s SENT(B/P)\r\n",
		"sl#id type Host#IPaddress:port",nselector);
	writesAgent(ap,msg,"");
	for( sx = 0; sx < nselector; sx++ ){
		sp = selectors[sx];
		sprintf(msg,"  %s\r\n",
			sp->s_name,sp->s_nreceivers);
		writesAgent(ap,msg,"");

		for( rx = 0; rx < sp->s_nreceivers; rx++ ){
			rp = &sp->s_receiver[rx];
			ap1 = rp->r_ap;
			sprintf(hostport,"%4s %4d %s",
			(ap1->a_isudpmain||ap1->a_isudpchan)?"UDP":"TCP",
			ap1->a_ipno, ap1->a_srcport);

			aid = rp->r_ap->a_id;
			sprintf(msg,"  %02d#%02d %-30s %8d %6d\r\n",
				getAx(aid),aid,hostport,
				rp->r_rcc,rp->r_cnt);
			writesAgent(ap,msg,"");
		}
	}
}

static void delReceiverAgent(int selx,Agent *ap,int deadagent)
{	Selector *sp;
	int nrec,ri,rj,closed;
	Receiver rb;

	sp = selectors[selx];
	if( 0 < sp->s_nreceivers ){
		rj = 0;
		closed = 0;
		for( ri = 0; ri < sp->s_nreceivers; ri++ ){
			rb = sp->s_receiver[ri];
			if( rb.r_ap == ap )
				closed++;
			else	sp->s_receiver[rj++] = rb;
		}
		sp->s_nreceivers -= closed;
	}
}
static void delReceiver(PCStr(selector),Agent *ap)
{	int selx;

	selx = getselx(0,selector);
	if( 0 <= selx )
		delReceiverAgent(selx,ap,0);
}
static void clearReceiver(Agent *ap)
{	int selx;

	for( selx = 0; selx < nselector; selx++ )
		delReceiverAgent(selx,ap,1);
}

static int sendFreeMessage(Agent *sap,PCStr(selector),PCStr(msg),int len)
{	Selector *sp;
	Agent *dap;
	Receiver *rp;
	int si,ri;
	CStr(path,1024);
	int nsent;

	nsent = 0;
	for( si = 0; si < nselector; si++ ){
		sp = selectors[si];
		if( strcmp(sp->s_name,"*") == 0 )
			goto MATCH;
		else
		if( strcmp(sp->s_name,selector) == 0 )
			goto MATCH;
		else
		/* substring (generic domain) match */
		if( strncmp(sp->s_name,selector,sp->s_leng) == 0 )
		if( selector[sp->s_leng] == '.' )
			goto MATCH;
		continue;

	MATCH:
	    for( ri = 0; ri < sp->s_nreceivers; ri++ ){
		rp = &sp->s_receiver[ri];
		rp->r_cnt++;
		rp->r_rcc += len;
		dap = rp->r_ap;

		if( dap->a_chan ){
			const char *body;
			if( msg[0] == '='
			&& (msg[1] == '!' || msg[1] == '>' || msg[1] == '<') )
				body = strchr(msg,' ') + 1;
			else	body = (char*)msg;
			writeAgent(dap,body,strlen(body));
		}else{
			sprintf(path,"=<!%d/%d",dap->a_id,sap->a_id);
			if( sap->a_ipno )
				Xsprintf(TVStr(path),"#%d",sap->a_ipno);

			if( msg[0] == '=' && msg[1] == '<' && msg[2] == '!' ){
				/* add path */
				writesAgent(dap,path,msg+2);
			}else{
				/* create path */
				strcat(path," ");
				writesAgent(dap,path,msg);
			}
		}
		dap->a_wseq++;
		nsent++;
	    }
	}
	return nsent;
}

/*
 *	MESSAGE ::= [PATH " "] COMMAND " " ARGUMENT
 */
static int sendMessage(Agent *sap,PCStr(msg),int len)
{	Selector *sp;
	Agent *dap;
	CStr(path,1024);
	const char *bp;
	const char *pp;
	char ch;
	const char *dp;
	CStr(com,MSGSIZE);
	const char *selector;
	int daid,di,bound;
	int nsent;

	/*
	 *	BOUND MESSAGE ::=
	 *		"=<" qpath " " body	... right to left (request)
	 *	    |	"=>" rpath " " body	... left to right (response)
	 *
	 *	qpath ::= path1 1*{ qpassed | actpath }
	 *	rpath ::= [ path1 ] 1*{ rpassed | actpath }
	 *	actpath ::= "!" path1
	 *	qpassed ::= "<" path1
	 *	rpassed ::= ">" path1
	 *
	 */
	bound = 0;
	if( msg[0] == '=' )
	if( msg[1] == '>' || msg[1] == '<' && msg[2] != '!')
		bound = msg[1];

	if( bound ){
		/*
		 *	Find next node next to "!" sign which means
		 *	"this point is not passed yet".
		 */
		if( bound == '>' )
			dp = strchr(msg,'!');
		else{
			dp = NULL;
			for( pp = msg; ch = *pp; pp++ ){
				if( ch == '!' )
					dp = (char*)pp;
				if( ch==' '||ch=='\t'||ch=='\r'||ch=='\n' )
					break;
			}
		}
		if( dp != NULL ){
			/*
			 *	replace "!" by a mark "passed" mark
			 *	from left (">") or from right ("<").
			 */
			*(char*)dp = bound;

			if( bound == '<' )
				sscanf(dp+1,"%d",&daid);
			else	sscanf(dp+1,"%*[^/]/%d",&daid);

			if( 0 <= (di = getAx(daid)) ){
				dap = Agents[di];
				if( dap->a_chan ){
					const char *body;
					body = strchr(msg,' ') + 1;
					writeAgent(dap,body,strlen(body));
				}else	writeAgent(dap,msg,strlen(msg));
				nsent = 1;
				goto exit;
			}
		}
		nsent = 0;
		goto exit;
	}

	if( sap->a_chan ){
		bound = sap->a_chan[0];
		if( bound == '<' || bound == '>' ){
			CStr(xmsg,MSGSIZE);
			sprintf(xmsg,"=%s %s",sap->a_chan,msg);
			return sendMessage(sap,xmsg,strlen(xmsg));
		}
	}

	/*
	 *	FREE MESSAGE ::=
	 *		"=<!" path " " body
	 *	    |	body
	 */
	if( sap->a_chan ){
		selector = sap->a_chan;
	}else
	if( msg[0] == '=' && msg[1] == '<' && msg[2] == '!' ){
		const char *dp;
		dp = wordScan(msg,path);
		dp = wordScan(dp,com);
		selector = com;
	}else{
		wordScan(msg,com);
		selector = com;
	}
	nsent = sendFreeMessage(sap,selector,msg,len);

exit:

	sv1vlog("sentMessage[%d]:%s",nsent,msg);
	return nsent;
}
static void flushMessages()
{	int ax;
	Agent *ap;
	int nsent;

	for( ax = 1; ax < NAgents; ax++ ){
		ap = Agents[ax];
		if( ap->a_osize ){
			nsent = sendMessage(ap,ap->a_obuff,ap->a_osize);
			if( 0 < nsent ){
				free((char*)ap->a_obuff);
				ap->a_obuff = 0;
				ap->a_osize = 0;
			}
		}
	}
}

static int aPollIns(int interval,int fdfull)
{	int ax;
	int nready;

	nready = 0;
	for( ax = 0; ax < inputsN; ax++ ){
		if( i_agentv[ax]->a_irem && !i_agentv[ax]->a_nonl ){
			i_readyv[ax] = 1;
			nready ++;
		}else	i_readyv[ax] = 0;
	}
	if( nready )
		return nready;

	if( fdfull ){
		i_readyv[0] = 0;
		return PollIns(interval, inputsN-1, i_sockv+1, i_readyv+1);
	}else	return PollIns(interval, inputsN,   i_sockv,   i_readyv);
}

static int xreadline(PVStr(buf),int size,Agent *ap,int sx)
{	const char *tp;
	refQStr(bp,buf);
	const char *ip;
	int rfd,rem,rcc;
	int done;

	sv1vlog("xreadline([%d]#%d %d)\n",sx,ap->a_id,size);

	bp = buf;
	rcc = 0;
	done = 0;
	ap->a_nonl = 0;

	if( 0 < ap->a_irem ){
		ip = ap->a_itop;
		tp = &ip[ap->a_irem];
		while( ip < tp ){
			int ch;
			ch = *ip++;
			setVStrPtrInc(bp,ch);
			if( ch == '\n' ){
				done = 1;
				break;
			}
		}

		if( done ){
			rcc = ip - ap->a_itop;
			ap->a_irem -= rcc;
			ap->a_itop = (char*)ip;
			setVStrEnd(bp,0);
			sv1vlog("GOT %d.\n",rcc);
			return rcc;
		}
		if( size <= ap->a_irem ){
			sv1log("Message too large: %d.\n",size);
			return -1;
		}

		{
		char *jp;
		jp = ap->a_ibuff;
		ip = ap->a_itop;
		while( jp < tp )
			*jp++ = *ip++;
		}
	}

	rfd = ap->a_rfd;
	if( PollIn(rfd,AGENT_DEATH_TIMEOUT*1000) <= 0 ){
		sv1vlog("Nothing ready.\n");
		return -1;
	}

	rem = ap->a_irem;
	rcc = recv(rfd,&ap->a_ibuff[rem],ap->a_isize-rem,0);
	if( rcc <= 0 ){
		sv1vlog("EOF got.\n");
		return -1;
	}
	sv1vlog("RECV %d.\n",rcc);

	ap->a_itime = time(0);
	ap->a_itop = ap->a_ibuff;
	ap->a_irem += rcc;
	ip = &ap->a_ibuff[rem];
	tp = &ip[rcc];
	while( ip < tp )
		if( *ip++ == '\n' )
			return xreadline(BVStr(buf),size,ap,sx);

	sv1log("Message half got: [%d]#%d %d/%d.\n",sx,ap->a_id,rcc,ap->a_irem);
	ap->a_nonl = 1;
	return 0;
}

static Agent *udpAgent(int csock,PVStr(port));
static int recvMessage(Agent *ap,int infd,int sx)
{	CStr(msg,MSGSIZE);
	refQStr(hp,msg); /**/
	const char *dp;
	CStr(com,MSGSIZE);
	CStr(arg,MSGSIZE);
	const char *arg1p;
	const char *arg2p;
	CStr(resp,MSGSIZE);
	int len,len1;
	int seli,nsent;

	len = 0;
	if( ap->a_isudpmain ){
		CStr(from,256);

		len = readfrom(infd,(char*)msg,sizeof(msg),AVStr(from));
		ap = udpAgent(infd,AVStr(from));
		ap->a_itime = time(0);
	}else{
		len = xreadline(AVStr(msg),sizeof(msg),ap,sx);
	}

	if( len <= 0 )
		return len;

	setVStrEnd(msg,len);
	ap->a_rcc += len;
	ap->a_nr += 1;
	arg1p = dp = wordScan(msg,com);

	sv1vlog("from#%d %d\n",ap->a_id,len);

	if( strcasecmp(com,"BLOCK") == 0 ){
		hp = msg + strlen(msg);
		len = 0;
		for(;;){
			len1 = xreadline(AVStr(hp),sizeof(msg)-len,ap,sx);
			if( len1 <= 0 )
				break;
			if( *hp == '\r' || *hp == '\n' )
				break;
			len += len1;
			hp = msg+len;
		}
		if( len <= 0 )
			return len;
		arg1p = dp = wordScan(msg,com);
	}

	setVStrEnd(arg,0);
	arg2p = wordScan(arg1p,arg);

	if( strcasecmp(com,"HELO") == 0 ){
		sprintf(resp,"HELO Teleport/%s\r\n",TELEPORT_VER);
		writeAgent(ap,resp,strlen(resp));
	}else
	if( strcasecmp(com,"STAT") == 0 ){
		putStat(ap);
	}else
	if( strcasecmp(com,"INVITE") == 0
	 || strcasecmp(com,"LISTEN") == 0
	 || strcasecmp(com,"SUBSCRIBE") == 0 ){
		CStr(sn,128);
		CStr(selector,MSGSIZE);
		int nlisten;

		if(strcasecmp(com,"INVITE")==0||strcasecmp(com,"SUBSCRIBE")==0)
		{
			strcpy(selector,arg);
		}else
		{
			nlisten = atoi(arg);
			wordScan(arg2p,selector);
		}

		if( selector[0] )
			addReceiverAgent(selector,ap);

		flushMessages();
		sv1log("%s",msg);
	}else
	if( strcasecmp(com,"OFF") == 0 || strcasecmp(com,"UNSUBSCRIBE") == 0 ){
		delReceiver(arg,ap);
	}else
	if( strcasecmp(com,"ROUTE") == 0 ){
		sv1log("%s",msg);
		ap->a_chan = stralloc(arg);
		writeAgent(ap,"OK.\r\n",5);
		/*addReceiverAgent(arg,ap);*/
	}else
	if( strcasecmp(com,"WHOIS") == 0 ){
		const char *path;
		const char *dp;
		CStr(name,256);
		CStr(addr,256);
		int aid,port;

		if( dp = strrchr(arg,'/') )
			aid = atoi(dp+1);
		else	aid = atoi(arg);
		if( getagenthost(aid,AVStr(name),AVStr(addr),&port) )
			sprintf(resp,"%d %s %s %d\r\n",aid,name,addr,port);
		else	sprintf(resp,"%d ? ? 0\r\n",aid);
		writeAgent(ap,resp,strlen(resp));
	}else
	{
		nsent = sendMessage(ap,msg,len);
		if( nsent == 0 ){
			if( ap->a_obuff != 0 ){
				if( ap->a_isudpchan ){
					ap->a_discarded++;
				}else{
					sv1log(">>>>> NoReceiver #%d\n",ap->a_id);
					setZOMB(ap,"NoReceiver");
				}
			}else{
				ap->a_obuff = stralloc(msg);
				ap->a_osize = len;
			}
		}
	}
	return len;
}
static void genMessage(int aid,PCStr(what))
{	Agent *ap;
	CStr(msg,MSGSIZE);
	int nrecv;

	ap = getAp(aid);
	sprintf(msg,"%s %s\r\n",what,ap->a_srcport);
	nrecv = sendMessage(ap,msg,strlen(msg));
}

static int newAgent(int csock)
{	Agent *ap;
	int ax;

	ax = NAgents++;

	ap = (Agent*)calloc(sizeof(Agent),1);
	Agents[ax] = ap;
	ap->a_wfd = csock;
	ap->a_id = ++agentID;
	ap->a_isize = MSGSIZE;
	ap->a_ibuff = (char*)malloc(ap->a_isize);

	sv1log("[%d] new-agent fd=%d id=#%d\n",ax,csock,agentID);
	return ax;
}
static int addAgent(int csock,int udpmain)
{	Agent *ap;
	int ax,ix;
	CStr(hostport,256);

	ax = newAgent(csock);
	ap = Agents[ax];
	ap->a_isudpmain = udpmain;
	if( udpmain ){
		ap->a_srcport = "?";
	}else{
		getpeerName(csock,AVStr(hostport),"%A:%P");
		ap->a_srcport = stralloc(hostport);
		if( hostport[0] != '?' )
			ap->a_ipno = HostId(hostport);
		sv1log("ACCEPT[%d](%d) %s/TCP\n",csock,ap->a_ipno,hostport);
	}

	ix = inputsN++;
	i_agentv[ix] = ap;
	i_sockv[ix] = ap->a_rfd = csock;
	i_readyv[ix] = 0;
	return ap->a_id;
}
static void delIfsock(int aid)
{	int ix,iy;
	int closed = 0;

	iy = 0;
	for( ix = 0; ix < inputsN; ix++ ){
		if( i_agentv[ix]->a_id == aid )
			closed++;
		else{
			i_agentv[iy] = i_agentv[ix];
			i_sockv[iy] = i_sockv[ix];
			i_readyv[iy] = i_readyv[ix];
			iy++;
		}
	}
	inputsN -= closed;
}
static Agent *udpAgent(int csock,PVStr(port))
{	int ax;
	Agent *ap;

	for( ax = 0; ax < NAgents; ax++ ){
		ap = Agents[ax];
		if( ap->a_isudpchan && strcmp(port,ap->a_srcport) == 0 )
			return ap;
	}

	ax = newAgent(csock);
	ap = Agents[ax];
	ap->a_isudpchan = 1;
	ap->a_srcport = stralloc(port);
	ap->a_ipno = HostId(port);
	sv1log("ACCEPT [%d](%d) %s/UDP\n",csock,ap->a_ipno,port);
	return ap;
}
static void clearZomb()
{	int ax,ay;
	Agent *ap;
	int closed = 0;

	for( ax = NAgents-1; 1 <= ax; ax-- ){
		ap = Agents[ax];
		if( ap->a_zomb != NULL )
			clearReceiver(ap);
	}

	ay = 1;
	for( ax = 1; ax < NAgents; ax++ ){
		if( Agents[ax]->a_zomb != NULL ){
			ap = Agents[ax];
			genMessage(ap->a_id,"LOCAL.AGENT.BYE");
			delIfsock(ap->a_id);
			close(ap->a_rfd);
			if( ap->a_wfd != ap->a_rfd )
				close(ap->a_wfd);
			free(ap->a_ibuff);
			sv1log("[%d] dead-agent #%d %di+%do (%s)\n",
				ax,ap->a_id,ap->a_rcc,ap->a_wcc,ap->a_zomb);
			free(ap);
			closed++;
		}else{
			Agents[ay++] = Agents[ax];
		}
	}
	NAgents -= closed;
}

static int addUDPentrance(int tcpsock)
{	int port;

	if( sockHostport(tcpsock,&port) != -1 )
		return server_open("Teleport/UDP",VStrNULL,port,-1);
	else	return -1;
}

int service_teleport(DGC*Conn,int SVsock,int SVport)
{	int si,sj;
	int interval;
	int tcprec,fdfull;
	int udprec;
	int newaid;
	int csock;
	int closed;
	int rcc;
	int nready;

	minit_teleport();

	if( SVsock < 0 ){
		fprintf(stderr,"teleport_server: no server socket(%d)\n",
			SVsock);
		return -1;
	}

	starttime = time(0);

	for( si = 0; si < MAX_SOCKETS; si++ )
		i_sockv[si] = 0;

	tcprec = addAgent(SVsock,0);
	csock = addUDPentrance(SVsock);
	if( csock < 0 )
		sv1log("cannot open socket for UDP reception.\n");
	else{
		udprec = addAgent(csock,1);
		sv1log("[%d] UDP reception #%d.\n",csock,udprec);
	}

	fdfull = 0;
	interval = CHECK_INTERVAL * 1000; /* mili seconds */

	for(;;){
		nready = aPollIns(interval,fdfull);

		if( nready < 0 ){
			sv1log("PollIns error.\n");
			break;
		}
		if( nready == 0 ){
			/*ExpireUdpReceivers();*/
			continue;
		}

		if( !fdfull && 0 < i_readyv[0] ){
			csock = ACCEPT(i_sockv[0],1,-1,0);
			if( csock < 0 ){
				int testfd;
				testfd = dup(SVsock);
				if( testfd < 0 ){
					fdfull = 1;
					sv1log("accept failed (no more fd).\n");
				}else{
					sv1log("accept failed (why?)\n");
					close(testfd);
				}
			}else{
				set_keepalive(csock,1);
				newaid = addAgent(csock,0);
				genMessage(newaid,"LOCAL.AGENT.HELLO");
			}
		}

		for( si = 1; si < inputsN; si++ ){
			if( 0 < i_readyv[si] ){
				rcc = recvMessage(i_agentv[si],i_sockv[si],si);
				if( rcc < 0 ){
sv1log("## READ ERROR: %d/%d nready=%d\n",si,inputsN,nready);
					i_readyv[si] = -1;
				}
			}
		}

		closed = 0;
		for( si = 1; si < inputsN; si++ ){
			if( i_agentv[si]->a_zomb )
				closed++;
			else
			if( i_readyv[si] < 0 ){
				closed++;
sv1log("## POLL ERROR: %d/%d nready=%d\n",si,inputsN,nready);
				setZOMB(i_agentv[si],"CantRead");
			}
		}
		if( 0 < closed ){
			clearZomb();
			fdfull = 0;
		}
	}
	return 0;
}
