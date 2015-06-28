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
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	icp.c (Internet Cache Protocol, RFC2186)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

   ICP server and client with "ICP proxy" private extension.

   private extension:
   ICP_FLAG_X_NAVI (0x08000000) option flag -- server navigation

     If the flag is set in QUERY, it shows that the client is asking
     recommended (HTTP proxy) content server or other ICP servers.
     This can be used ICP redirection(1) or ICP proxying(2).

     (1) icp-client ----> icp-server
                    <---  recommended icp-server:port

     (2) icp-client ----> icp-proxy-server -----> icp-servers
                    <---  recommended http-proxy-server:port

     In responses, show there is a recommended proxy server shown in:
       the address is set in SENDER field
       the port number is set in higher 16bits of OPTDATA field

     Further extension??
       // the protocol of the recommended server is set in OPTIONS & 0x07000000
       //  0 HTTP proxy server
       //  1 DeleGate server
       //  2 proxy of the origin protocol
       //  3 origin server
       //  4 ICP server
       //  5-7 reserved

History:
	980609	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "proc.h"
#include "file.h"
#include "fpoll.h"
#include "dglib.h"
#include <ctype.h>

extern int CHILD_SERNO;
extern int CHILD_SERNO_MULTI;

#define MY_ICP_VER	2
#define MAX_PACKSIZE	(16*1024)

static int PARASERV = 2;
static int ICP_HIT_AGE = 24 * 60*60;
static int HIT_OBJ_SIZE_MAX = 1024;
static int HIT_OBJ_AGE = 1 * 60*60;
static int ICP_NOFETCH_AGE = 24 * 60*60;
static double DFLT_TIMEOUT = 2.0;

static int ICP_NUMSERV = 0;
int ICP_DEBUGLOG = 0;
#define Lprintf	(log==NULL||ICP_DEBUGLOG==0)?0:fprintf

#define ICP_OP_INVALID		0
#define ICP_OP_QUERY		1
#define ICP_OP_HIT		2
#define ICP_OP_MISS		3
#define ICP_OP_ERR		4
#define ICP_OP_SECHO		10
#define ICP_OP_DECHO		11
#define ICP_OP_MISS_NOFETCH	21
#define ICP_OP_DENIED		22
#define ICP_OP_HIT_OBJ		23

#define ICP_FLAG_X_NAVI		0x08000000
#define ICP_FLAG_SRC_RTT	0x40000000
#define ICP_FLAG_HIT_OBJ	0x80000000
#define ICP_FLAG_VALIDS	\
	(ICP_FLAG_HIT_OBJ|ICP_FLAG_SRC_RTT|ICP_FLAG_X_NAVI)

static const char *opsym(int op){
	switch( op ){
		case ICP_OP_INVALID:	return "INVALID";
		case ICP_OP_QUERY:	return "QUERY";
		case ICP_OP_HIT: 	return "HIT";
		case ICP_OP_MISS: 	return "MISS";
		case ICP_OP_ERR: 	return "ERR";
		case ICP_OP_SECHO: 	return "SECHO";
		case ICP_OP_DECHO: 	return "DECHO";
		case ICP_OP_MISS_NOFETCH: 	return "NOFETCH";
		case ICP_OP_DENIED: 	return "DENIED";
		case ICP_OP_HIT_OBJ: 	return "HIT_OBJ";
	}
	return NULL;
}

typedef unsigned char octet;
typedef unsigned int ipv4a;

typedef struct {
	octet	ih_opcode;
	octet	ih_version;
	short	ih_msglen;
	int	ih_reqnum;
	int	ih_options;
	int	ih_optdata;
	ipv4a	ih_sender;
} ICPhead;

#define IPV4SIZE	sizeof(ipv4a)
#define HEADSIZE	sizeof(ICPhead)

typedef struct {
	ipv4a	iq_requester;
	MStr(	iq_url,MAX_PACKSIZE-HEADSIZE-IPV4SIZE);
} ICPbody_QUERY;

typedef union {
	ICPbody_QUERY	ib_query;
	MStr(	ib_url,MAX_PACKSIZE-HEADSIZE);
} ICPbody;

typedef struct {
	ICPhead	i_head;
	ICPbody	i_body;
} ICPpack;

#define IH_OPCODE	i_head.ih_opcode
#define IH_VERSION	i_head.ih_version
#define IH_MSGLEN	i_head.ih_msglen
#define IH_OPTIONS	i_head.ih_options
#define IH_OPTDATA	i_head.ih_optdata
#define IH_REQNUM	i_head.ih_reqnum
#define IH_SENDER	i_head.ih_sender

#define IB_URL		i_body.ib_url
/**/
#define IQ_REQUESTER	i_body.ib_query.iq_requester
#define IQ_URL		i_body.ib_query.iq_url
/**/

#define ICP_ITYPE_SIBLING	0x1000
#define ICP_ITYPE_PARENT	0x0001
#define ICP_ITYPE_LISTENER	0x0002
#define ICP_ITYPES	       (0x000F|ICP_ITYPE_SIBLING)

#define ICP_PTYPE_HTTP		0x2000
#define ICP_PTYPE_DELEGATE	0x0010
#define ICP_PTYPE_ORIG_PROXY	0x0020
#define ICP_PTYPE_ORIG_SERVER	0x0040
#define ICP_PTYPES	       (0x00F0|ICP_PTYPE_HTTP)
#define ICP_TEMP_FLAGS		0xF000

static void bdump(xPVStr(msg),PCStr(pack),int leng)
{	const unsigned char *pp;
	int px;

	pp = (unsigned char*)pack;
	for( px = 0; px < leng; px++ ){
		if( px % 4 == 0 ){
			if( px % 20 == 0 )
				sprintf(msg,"\n");
			else	sprintf(msg," ");
			msg += strlen(msg);
		}
		sprintf(msg,"%02x ",pp[px]);
		msg += strlen(msg);
	}
}
static void dumppack(xPVStr(msg),int leng,ICPpack *pack)
{	int op;
	const char *sym;
	const char *psym;
	const char *url;
	int opt,optdata;
	CStr(opts,32);

	op = pack->IH_OPCODE;
	psym = sym = opsym(op);
	if( psym == NULL )
		psym = "UNKNOWN";
	sprintf(msg,"%s [",psym);
	msg += strlen(msg);

	if( sym != NULL ){
		if( pack->IH_VERSION != 2 ){
			sprintf(msg,"V%d ",pack->IH_VERSION);
			msg += strlen(msg);
		}
		sprintf(msg,"#%x %d/%d",
			ntohL(pack->IH_REQNUM),
			ntohS(pack->IH_MSGLEN),leng
		);
		msg += strlen(msg);

		if( pack->IH_OPTIONS || pack->IH_OPTDATA ){
			opt = ntohL(pack->IH_OPTIONS);
			opts[0] = 0;
			if( opt & ICP_FLAG_HIT_OBJ ) strcat(opts,"O");
			if( opt & ICP_FLAG_SRC_RTT ) strcat(opts,"R");
			if( opt & ICP_FLAG_X_NAVI  ) strcat(opts,"N"); 
			if( opt & ~ICP_FLAG_VALIDS ) sprintf(opts,"0x%x",opt);
			optdata = ntohL(pack->IH_OPTDATA);
			sprintf(msg," O=%s/%d,%d",opts,
				0xFFFF&(optdata>>16),0xFFFF&optdata);
			msg += strlen(msg);
		}
		if( pack->IH_SENDER ){
			sprintf(msg," S=%s",_inet_ntoaV4I(pack->IH_SENDER));
			msg += strlen(msg);
		}
	}
	if( op == ICP_OP_QUERY ){
		if( pack->IQ_REQUESTER ){
			sprintf(msg," R=%s",_inet_ntoaV4I(pack->IQ_REQUESTER));
			msg += strlen(msg);
		}
		url = pack->IQ_URL;
	}else
	if( 0 < op && op < 30 )
		url = pack->IB_URL;
	else	url = "";

	strcpy(msg,"]");
	msg += strlen(msg);

	if( *url ){
		sprintf(msg," U=%s",url);
		msg += strlen(msg);
	}
	/*bdump(msg,pack,leng);*/
}

/* if the RTT to the destination server is long ? */
static void *noicp_domain;
static int MISScode(ICPpack *qpack,PCStr(host),int port,PCStr(froma),int fromp)
{	const char *tail;

	if( noicp_domain )
	if( tail = frex_match((struct fa_stat*)noicp_domain,host) )
	if( *tail == 0 )
		return ICP_OP_MISS_NOFETCH;

	if( !IsResolvable(host) )
		return ICP_OP_MISS_NOFETCH;

	return ICP_OP_MISS;
}

static int valid_object(PCStr(url),PCStr(obj),int size)
{
	if( strncmp(obj,"HTTP/",5) == 0 )
		return 1;
	return 0;
}

static int lRecv;
static int nRecv;
static int nHit;
static int nMiss;
static int nErr;
static int nDenied;
static int nUnknown;
extern int errorECONNRESET;
#ifndef ECONNRESET
#define ECONNRESET -1
#endif

static void icp_reply(int sock,ICPpack *qpack,ICPpack *rpack,PCStr(froma),int fromp,double start,PCStr(url));
int icp_select(PCStr(url),int icpopts[],const char *svaddrs[],int svports[],double timeout,FILE *log,PVStr(sxaddr),int *sxport,int first,int *hitobj,PVStr(objbuf));
int icp_selectconf(PVStr(conf),PCStr(dproto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser));
int icp_getconf(PCStr(conf),int icptypes[],const char *icpaddrs[],int icpports[],const char *pxaddrs[],int pxports[],double *timeout,PVStr(buff));
void scan_ICPCONF(DGC*Conn,PCStr(conf));
void scan_ICP(DGC*Conn,PCStr(conf));

void icp_server(int sock)
{	ICPpack qpack,rpack;
	CStr(froma,64);
	int fromp;
	int rcc;
	const char *url;
	CStr(msg,128+MAX_PACKSIZE);
	double start,done;
	int parent,mypid;
	const char *env;
	int npara,ni;

	setsockbuf(sock,64*1024,0);
	/*set_nodelay(sock,1);*/

	parent = getpid();
	if( INHERENT_fork() ){
		if( env = getenv("PARASERV") )
			npara = atoi(env);
		else	npara = PARASERV;

		for( ni = 1; ni < npara; ni++ ){
			if( Fork("IPC") == 0 )
				break;
			CHILD_SERNO++;
		}
	}
	if( env = getenv("NOICP_DOMAIN") )
		noicp_domain = frex_create(env);

	mypid = getpid();
	daemonlog("E","START\n");
	lRecv = 0;
	nHit = 0;
	nMiss = 0;
	nUnknown = 0;
	nDenied = 0;
	nErr = 0;
	done = Time();

	for( nRecv = 1;; nRecv++ ){
		errno = 0;
		errorECONNRESET = 0;
		rcc = RecvFrom(sock,(char*)&qpack,sizeof(qpack),AVStr(froma),&fromp);
		if( rcc <= 0 || strcmp(froma,"0.0.0.0") == 0 ){
			if( errorECONNRESET || errno == ECONNRESET ){
			daemonlog("F","## RecvFrom(%d) = %d ECONNRESET\n",
				sock,rcc,errno);
				continue;
			}
			daemonlog("F","FATAL RecvFrom(%d) = %d errno=%d\n",
				sock,rcc,errno);
			sleep(10);
			continue;
		}
		start = Time();
		sprintf(msg,"%-5.2f %s ",start-done,froma);
		lRecv += rcc;
		CHILD_SERNO_MULTI++;

		if( qpack.IH_OPCODE == ICP_OP_QUERY )
			dumppack(TVStr(msg),rcc,&qpack);
		daemonlog("E","%s\n",msg);

		url = NULL;
		if( qpack.IH_OPCODE == ICP_OP_QUERY )
			url = qpack.IQ_URL;
		else	nUnknown++;
/*
		if( isalpha(qpack.IH_OPCODE )
			url = ((char*)&qpack);
*/
		icp_reply(sock,&qpack,&rpack,froma,fromp,start,url);
		done = Time();
	}
}
static void icp_reply(int sock,ICPpack *qpack,ICPpack *rpack,PCStr(froma),int fromp,double start,PCStr(url))
{	CStr(proto,256);
	CStr(hostport,1024);
	CStr(host,1024);
	CStr(upath,MAX_PACKSIZE);
	int port;
	CStr(cachepath,MAX_PACKSIZE);
	int ftime,fsize,rsize,psize,fage;
	int msglen;
	CStr(fbuff,MAX_PACKSIZE);
	CStr(msg,256);
	FILE *fp;
	int qopts;
	int opcode,options,optdata,sender;
	FILE *log = stderr;

	if( url == NULL )
		return;

	decomp_absurl(url,AVStr(proto),AVStr(hostport),AVStr(upath),sizeof(upath));
	port = scan_hostport(proto,hostport,AVStr(host));

	qopts = ntohL(qpack->IH_OPTIONS);

	opcode = -1;
	options = 0;
	optdata = 0;
	sender = 0;

	if( host[0] == 0 || port <= 0 ){
		fsize = rsize = -1;
		opcode = ICP_OP_ERR;
		goto REPLY;
	}
	if( !service_permitted0(froma,fromp,proto,host,port) ){
		Lprintf(log,"(ICP)No permission: %s:%d => %s://%s:%d\n",
			froma,fromp,proto,host,port);
		fsize = rsize = -1;
		opcode = ICP_OP_DENIED;
		goto REPLY;
	}

	if( qopts & ICP_FLAG_HIT_OBJ )
	if( !method_permitted0(/*froma,fromp,"icp","hitobj",host,port*/) ){
		qopts &= ~ICP_FLAG_HIT_OBJ;
	}

	ftime = -1;
	fsize = -1;
	fage = -1;
	rsize = -1;

	if( cachedir() != NULL ){
		opcode = MISScode(qpack,host,port,froma,fromp);
		cache_path(proto,host,port,upath,AVStr(cachepath));
		if( fp = dirfopen("ICP",AVStr(cachepath),"r") ){
			ftime = file_mtime(fileno(fp));
			fsize = file_size(fileno(fp));
			fage = time(0) - ftime;

			if( fage < ICP_HIT_AGE ){
				opcode = ICP_OP_HIT;
				psize = HEADSIZE+strlen(url)+1+4+fsize;

				if( qopts & ICP_FLAG_HIT_OBJ )
				if( fage < HIT_OBJ_AGE )
				if( fsize < HIT_OBJ_SIZE_MAX )
				if( psize < MAX_PACKSIZE )
				if( lock_sharedNB(fileno(fp)) == 0 ){
					rsize = fread(fbuff,1,fsize,fp);
					lock_unlock(fileno(fp));
					if( rsize == fsize )
					if( valid_object(url,fbuff,rsize) )
						opcode = ICP_OP_HIT_OBJ;
				}
			}
			fclose(fp);
		}
	}
	if( opcode == ICP_OP_HIT || opcode == ICP_OP_HIT_OBJ )
		goto REPLY;

	if( qopts & ICP_FLAG_X_NAVI || ICP_NUMSERV ){
		CStr(conf,1024);
		CStr(buff,1024);
		int nserv;
		int icptypes[32];
		const char *icpaddrs[32]; /**/
		const char *pxaddrs[32]; /**/
		int icpports[32];
		int pxports[32];
		int pxtypes[32];
		double timeout;
		int sx;
		CStr(sxaddr,64);
		int sxport;
		int *hitobjp;

		if( opcode < 0 ) /* no local cache */
			opcode = ICP_OP_DENIED;

		/* MOUNT URL here ? */

		if( icp_selectconf(AVStr(conf),proto,host,port,froma,fromp,"") < 0 )
			goto REPLY;
		nserv = icp_getconf(conf,icptypes,icpaddrs,icpports,
				pxaddrs,pxports,&timeout,AVStr(buff));
		if( nserv < 0 )
			goto REPLY;

		if( qopts & ICP_FLAG_HIT_OBJ )
			hitobjp = &rsize;
		else	hitobjp = NULL;
		sx = icp_select(url,icptypes,icpaddrs,icpports,timeout,
			stderr, AVStr(sxaddr),&sxport,1,hitobjp,AVStr(fbuff));
		/* multiple responses should be relayed ?? */

		if( 0 <= sx ){
			opcode = ICP_OP_HIT;
			/* possibly MISS if it's "parent" type ... */

			if( qopts & ICP_FLAG_X_NAVI ){
				sender = _inet_addrV4(sxaddr);
				optdata = pxports[sx] << 16;
				options = ICP_FLAG_X_NAVI;
			}

			if( qopts & ICP_FLAG_HIT_OBJ )
			if( 0 <= rsize )
				opcode = ICP_OP_HIT_OBJ;
		}
	}

	daemonlog("D","%5.3f %db/%ds %s\n",
		Time()-start,fsize,fage,cachepath);

REPLY:
	msglen = HEADSIZE + strlen(url) + 1;
	if( 0 < opcode ){
		rpack->IH_OPCODE = opcode;
		switch( opcode ){
			case ICP_OP_ERR:    nErr++; break;
			case ICP_OP_DENIED: nDenied++; break;
			case ICP_OP_HIT:    nHit++; break;
			default:	    nMiss++; break;
		}
	}else
	if( 0 <= fsize ){
		rpack->IH_OPCODE = ICP_OP_HIT;
		nHit++;
	}else{
		rpack->IH_OPCODE = MISScode(qpack,host,port,NULL,0);
		nMiss++;
	}

	rpack->IH_VERSION = MY_ICP_VER;
	rpack->IH_MSGLEN = htonS(msglen);
	rpack->IH_REQNUM = qpack->IH_REQNUM;
	rpack->IH_OPTIONS = htonL(options);
	rpack->IH_OPTDATA = htonL(optdata);
	rpack->IH_SENDER = sender;

	if( qopts & ICP_FLAG_SRC_RTT ){
		/*
		options |= ICP_FLAG_SRC_RTT;
		optdata |= 0xFFFF & getRTT(proto,host,port);
		 */
	}

	strcpy(rpack->IB_URL,url);
	if( opcode == ICP_OP_HIT_OBJ ){
		MrefQStr(op,rpack->IB_URL); /**/
		op = rpack->IB_URL+strlen(url)+1;
		setVStrPtrInc(op,rsize >> 24);
		setVStrPtrInc(op,rsize >> 16);
		setVStrPtrInc(op,rsize >> 8);
		setVStrPtrInc(op,rsize);
		Bcopy(fbuff,op,rsize);

		msglen += 4 + rsize;
		rpack->IH_MSGLEN = htonS(msglen);
		rpack->IH_OPCODE = ICP_OP_HIT_OBJ;
		rpack->IH_OPTIONS = htonL(options|ICP_FLAG_HIT_OBJ);
		/* >> HTTP PROTOLOG */
	}

	SendTo(sock,(char*)rpack,msglen,froma,fromp);
	sprintf(msg,"%5.3f %s %s %d %db/%3.1fh (%dH+%dM+%dE+%dD+%dU/%d) %d",
		Time()-start,
		froma,
		opsym(rpack->IH_OPCODE),
		msglen,
		fsize,fage/3600.0,
		nHit,nMiss,nErr,nDenied,nUnknown,nRecv,lRecv,
		0);
	daemonlog("E","%s\n",msg);
}

static int ReqId = 100;
int icp_client(int ac,const char *av[])
{	int ai;
	const char *arg;
	const char *server;
	const char *url;
	int serverx;
	CStr(svhost,128);
	const char *svaddr;
	int svport;
	ACStr(svaddrb,32,128);
	const char *svaddrs[32]; /**/
	int svports[32];
	float fv;
	FILE *log;
	int sx;
	CStr(sxhost,64);
	int sxport;
	int hitobj;
	CStr(objbuf,MAX_PACKSIZE);
	int icpflag,icpopts[32];
	int first;
	CStr(proto,128);
	CStr(hostport,128);
	CStr(host,128);
	CStr(upath,1024);
	CStr(conf,256);
	const char *pxaddrs[32]; /**/
	CStr(buff,256);
	int port,nserv,pxports[32];

	log = stderr;
	url = NULL;
	serverx = 0;
	icpflag = 0;
	first = 0;
	ICP_DEBUGLOG = 1;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];

		if( *arg == '-' ){
			switch( arg[1] ){
			case 'h':
				if( elnumof(svaddrs) <= serverx ){
					break;
				}
				server = av[++ai];
				svport = 3130;
				Xsscanf(server,"%[^:]:%d",AVStr(svhost),&svport);
				svaddr = gethostaddr(svhost);
				if( svaddr == NULL ){
					fprintf(stderr,"%s ?\n",svhost);
					return -1;
				}
				Xstrcpy(EVStr(svaddrb[serverx]),svaddr);
				svaddrs[serverx] = svaddrb[serverx];
				svports[serverx] = svport;
				icpopts[serverx] = icpflag;
				serverx++;
				break;
			case 'n':
				icpflag |= ICP_FLAG_X_NAVI;
				break;
			case 'o':
				icpflag |= ICP_FLAG_HIT_OBJ;
				break;
			case 't':
				if( arg = av[++ai] ){
					if( sscanf(arg,"%f",&fv) )
						DFLT_TIMEOUT = fv;
				}
				break;
			case '1':
				first = 1;
				break;
			}
		}else
		if( strncmp(arg,"ICP=",4) == 0 )
			scan_ICP(NULL,arg+4);
		else
		if( strncmp(arg,"ICPCONF=",8) == 0 )
			scan_ICPCONF(NULL,arg+8);
		else{
			url = arg;
		}
	}

	if( url == NULL ){
		fprintf(stderr,
		"Usage: icp [-n] [-o] [-h server] [-t timeout] [ICP=...] URL\n");
		return -1;
	}

	decomp_absurl(url,AVStr(proto),AVStr(hostport),AVStr(upath),sizeof(upath));
	port = scan_hostport(proto,hostport,AVStr(host));
	if( icp_selectconf(AVStr(conf),proto,host,port,"",0,"") == 0 ){
		nserv = icp_getconf(conf,
			&icpopts[serverx],&svaddrs[serverx],&svports[serverx],
			pxaddrs,pxports,&DFLT_TIMEOUT,AVStr(buff));
		if( 0 < nserv )
			serverx += nserv;
	}

	if( serverx == 0 ){
		Xstrcpy(EVStr(svaddrb[0]),"127.0.0.1");
		svaddrs[0] = svaddrb[0];
		svports[0] = 3130;
		icpopts[0] = icpflag;
		serverx++;
	}
	svaddrs[serverx] = NULL;

	fprintf(log,"icp -h %s:%d -t %4.2f %s\n",
		svaddrs[0],svports[0],DFLT_TIMEOUT,url);

	sxport = 0;
	sx = icp_select(url,icpopts,svaddrs,svports,DFLT_TIMEOUT,log,
		AVStr(sxhost),&sxport,first,&hitobj,AVStr(objbuf));
	if( 0 <= sx )
		fprintf(log,"%s:%d\n",sxhost,sxport);
	return 0;
}

static int mysock;
static int mysockPID;
static int myICPsock()
{	int pid = getpid();
	if( mysockPID == pid )
		return mysock;
	mysockPID = pid;
	mysock = Socket1("ICP",-1,"inet","dgram","udp", VStrNULL,0,NULL,0,0,NULL,0);
	return mysock;
}
int icp_select(PCStr(url),int icpopts[],const char *svaddrs[],int svports[],double timeout,FILE *log,PVStr(sxaddr),int *sxport,int first,int *hitobj,PVStr(objbuf))
{	ICPpack qpack,rpack;
	int nserv,nwatcher;
	int sock;
	int msglen;
	int sx,nresp;
	int wcc,rcc;
	double start,sent,done;
	CStr(msg,128+MAX_PACKSIZE);
	int qoptions;
	int opcode,options,optdata,sender,hsize,rsize;
	CStr(froma,64);
	int fromp;
	int hit = -1;
	int miss = -1;
	int rreqnum,rreqid,rreqsx;
	int timeout1;
	int mcast = 0;

	if( hitobj != NULL )
		*hitobj = -1;

	nserv = 0;
	for( sx = 0; svaddrs[sx]; sx++ )
		nserv++;

	start = Time();
	msglen = HEADSIZE+IPV4SIZE+strlen(url)+1;
	ReqId++;
	qpack.IH_OPCODE = ICP_OP_QUERY;
	qpack.IH_VERSION = MY_ICP_VER;
	qpack.IH_MSGLEN = htonS(msglen);
	qpack.IH_REQNUM = htonL(ReqId<<8);
	qpack.IH_OPTDATA = 0;
	qpack.IH_OPTIONS = 0;
	qpack.IH_SENDER = 0;
	qpack.IQ_REQUESTER = 0;
	strcpy(qpack.IQ_URL,url);

	sock = myICPsock();
	setsockbuf(sock,32*1024,0);
	/*set_nodelay(sock,1);*/

	nwatcher = 0;
	for( sx = 0; sx < nserv; sx++ ){
		qoptions = icpopts[sx] & ICP_FLAG_VALIDS;
		if( hitobj == NULL )
			qoptions &= ~ICP_FLAG_HIT_OBJ;

		if( icpopts[sx] & ICP_ITYPE_LISTENER ){
			qoptions = 0;
			/* set ICP_FLAG_X_DONTRESP ... */;
			nwatcher++;
		}
		qpack.IH_OPTIONS = htonL(qoptions);
		qpack.IH_REQNUM = htonL((ReqId<<8) | sx);
		wcc = SendTo(sock,(char*)&qpack,msglen,svaddrs[sx],svports[sx]);
		sent = Time();
		dumppack(AVStr(msg),msglen,&qpack);
		Lprintf(log,"(ICP)[%d][%d] %5.3f [%s:%d]%s<< %s\n",
			sx+1,sx,sent-start,svaddrs[sx],svports[sx],
			(icpopts[sx] & ICP_ITYPE_PARENT)?"p":"s", msg);
		if( (_inet_addrV4(svaddrs[sx]) & 0xFF) == 0xFF )
			mcast++;
	}

	/* PARENT is preferable than SIBLING ?? */

	nresp = 0;
	for(;;){
		if( nresp < nserv-nwatcher )
			timeout1 = (int)(1000 * timeout);
		else
		if( mcast )
			timeout1 = (int)(1000 * 0.1);
		else	break;

		if( PollIn(sock,timeout1) <= 0 ){
			Lprintf(log,"(ICP)Timeout %dms\n",timeout1);
			break;
		}
		rcc = RecvFrom(sock,(char*)&rpack,sizeof(rpack),AVStr(froma),&fromp);
		rreqnum = ntohL(rpack.IH_REQNUM);
		rreqid = 0xFFFFFF & (rreqnum >> 8);
		rreqsx = 0xFF & rreqnum;

		if( rreqid != ReqId || nserv <= rreqsx ){
			Lprintf(log,"(ICP)%d/%d previous query ? %x:%d/%d\n",
				ReqId,nserv,rreqnum,rreqid,rreqsx);
			continue;
		}
		if( icpopts[rreqsx] & ICP_ITYPE_LISTENER ){
			Lprintf(log,"(ICP)[%d][%d] LISTENER's response %s:%d\n",
				nresp,rreqsx,froma,fromp);
			continue;
		}
		nresp++;

		opcode = rpack.IH_OPCODE;
		sender = rpack.IH_SENDER;
		options = ntohL(rpack.IH_OPTIONS);
		optdata = ntohL(rpack.IH_OPTDATA);

		if( opcode == ICP_OP_HIT || opcode == ICP_OP_HIT_OBJ )
		if( hit < 0 ){
			if( sxaddr ){
				if( options & ICP_FLAG_X_NAVI ){
					strcpy(sxaddr,_inet_ntoaV4I(sender));
					*sxport = 0xFFFF & (optdata >> 16);
				}else{
					strcpy(sxaddr,froma);
					*sxport = fromp;
				}
			}
			hit = rreqsx;
		}

		if( hit < 0 )
		if( opcode == ICP_OP_MISS )
		if( icpopts[rreqsx] & ICP_ITYPE_PARENT )
		if( miss < 0 ){
			if( sxaddr ){
				if( options & ICP_FLAG_X_NAVI ){
					strcpy(sxaddr,_inet_ntoaV4I(sender));
					*sxport = 0xFFFF & (optdata >> 16);
				}else{
					strcpy(sxaddr,froma);
					*sxport = fromp;
				}
			}
			miss = rreqsx;
		}

		done = Time();
		dumppack(AVStr(msg),rcc,&rpack);
		Lprintf(log,"(ICP)[%d][%d] %5.3f [%s:%d]%s>> %s\n",
			nresp,rreqsx,done-start,froma,fromp,
			(icpopts[rreqsx] & ICP_ITYPE_PARENT)?"p":"s", msg);

		if( opcode == ICP_OP_HIT_OBJ && (options & ICP_FLAG_HIT_OBJ) ){
			const unsigned char *hop;

			url = rpack.IB_URL;
			hop = (unsigned char *)(url + strlen(url) + 1);
			rsize = (hop[0]<<24)|(hop[1]<<16)|(hop[2]<<8)|(hop[3]);
			hop += 4;
			hsize = (char*)hop - (char*)&rpack;

			Lprintf(log,"(ICP)HIT_OBJ %d + %d = %d / %d\n",
				hsize,rsize,hsize+rsize,rcc);

			if( valid_object(url,(char*)hop,rsize) )
			if( hsize + rsize == rcc ){
				if( hitobj != NULL )
					*hitobj = rsize;
				if( objbuf != NULL ){
					Bcopy(hop,objbuf,rsize);
					setVStrEnd(objbuf,rsize);
					break;
				}
			}
		}

		if( 0 <= hit && first )
			break;
	}

	if( 0 <= hit )
		return hit;
	return miss;
}

#define ICPMAP	"ICPmap"
void scan_ICPCONF(DGC*Conn,PCStr(conf))
{	int cc,ci;
	CStr(confb,1024);
	const char *confv[32]; /**/
	const char *conf1;
	CStr(name,128);
	CStr(val,128);

	strcpy(confb,conf);
	cc = list2vect(confb,',',32,confv);
	for( ci = 0; ci < cc; ci++ ){
		conf1 = confv[ci];
		name[0] = val[0] = 0;
		Xsscanf(conf1,"%[^:]:%s",AVStr(name),AVStr(val));

		if( streq(name,"para") )
			PARASERV = atoi(val);
		else
		if( streq(name,"nofetch") )
			ICP_NOFETCH_AGE = cache_expire(val,ICP_NOFETCH_AGE);
		else
		if( streq(name,"hitage") )
			ICP_HIT_AGE = cache_expire(val,ICP_HIT_AGE);
		else
		if( streq(name,"hitobjage") )
			HIT_OBJ_AGE = cache_expire(val,HIT_OBJ_AGE);
		else
		if( streq(name,"hitobjsize") )
			HIT_OBJ_SIZE_MAX = atoi(val);
		else
		if( streq(name,"timeout") )
			sscanf(val,"%lf",&DFLT_TIMEOUT);
		else
		if( streq(name,"debug") )
			ICP_DEBUGLOG = atoi(val);
		else{
			fprintf(stderr,"Unknown ICPCONF=%s\n",conf1);
			Finish(-1);
		}
	}
}
/*
 *  ICP={icpServer}*:icpOptions:proxyPort:icpPort:dstProtos:dstHosts:srcHosts
 *    icpServer=icpHost/icpType/proxyPort/icpPort
 *    icpType={s|p|o|n|H|D|P|O}*
 */
void scan_ICP(DGC*Conn,PCStr(conf))
{	CStr(confb,2048);
	const char *confv[8]; /**/
	int cc;
	const char *icphost;
	const char *icport;
	const char *pxport;
	const char *icpopt;
	const char *icpxmap;
	CStr(map,2048);

	ICP_NUMSERV++;
	strcpy(confb,conf);
	cc = list2vect(confb,':',5,confv);
	icphost = confv[0];
	if( 1<cc && *confv[1] ) icpopt  = confv[1]; else icpopt = "";
	if( 2<cc && *confv[2] ) pxport  = confv[2]; else pxport = "8080";
	if( 3<cc && *confv[3] ) icport  = confv[3]; else icport = "3130";
	if( 4<cc && *confv[4] ) icpxmap = confv[4]; else icpxmap = "*:*:*";

	sprintf(map,"{%s:%s:%s:%s}:%s",icphost,icpopt,pxport,icport,icpxmap);
	scan_CMAP2(Conn,ICPMAP,map);
}

static int scanoptsG(PCStr(optlist),double *timeout)
{	int gf;
	CStr(optbuf,1024);
	const char *optv[32]; /**/
	const char *opt1;
	const char *op;
	int cc,ci;

	gf = 0;
	*timeout = DFLT_TIMEOUT;

	strcpy(optbuf,optlist);
	cc = list2vect(optbuf,',',32,optv);

	for( ci = 0; ci < cc; ci++ ){
		opt1 = optv[ci];
		if( strncmp(opt1,"timeout/",8) == 0 )
			sscanf(opt1+8,"%lf",timeout);
		else
		if( streq(opt1,"navi"    ) ) gf |= ICP_FLAG_X_NAVI;  else
		if( streq(opt1,"hitobj"  ) ) gf |= ICP_FLAG_HIT_OBJ; else
		if( streq(opt1,"parent"  ) ) gf |= ICP_ITYPE_PARENT; else
		if( streq(opt1,"listener") ) gf |= ICP_ITYPE_LISTENER; else
		if( streq(opt1,"DeleGate") ) gf |= ICP_PTYPE_DELEGATE; else
		if( streq(opt1,"Proxy"   ) ) gf |= ICP_PTYPE_ORIG_PROXY; else
		if( streq(opt1,"Origin"  ) ) gf |= ICP_PTYPE_ORIG_SERVER;
	}
	return gf;
}
static int scanoptsP(PCStr(optlist),int gf)
{	int pf;
	const char *op;

	pf = 0;
	for( op = optlist; *op; op++ ){
	    switch( *op ){
		case 's': pf |= ICP_ITYPE_SIBLING;	break;
		case 'p': pf |= ICP_ITYPE_PARENT;	break;
		case 'l': pf |= ICP_ITYPE_LISTENER;	break;

		case 'o': pf |= ICP_FLAG_HIT_OBJ;	break;
		case 'n': pf |= ICP_FLAG_X_NAVI;	break;

		case 'H': pf |= ICP_PTYPE_HTTP;		break;
		case 'D': pf |= ICP_PTYPE_DELEGATE;	break;
		case 'P': pf |= ICP_PTYPE_ORIG_PROXY;	break;
		case 'O': pf |= ICP_PTYPE_ORIG_SERVER;	break;
	    }
	}
	if( (pf & ICP_FLAG_HIT_OBJ) == 0 ) pf |= gf & ICP_FLAG_HIT_OBJ;
	if( (pf & ICP_FLAG_X_NAVI ) == 0 ) pf |= gf & ICP_FLAG_X_NAVI;
	if( (pf & ICP_PTYPES ) == 0 ) pf |= gf & ICP_PTYPES;
	if( (pf & ICP_ITYPES ) == 0 ) pf |= gf & ICP_ITYPES;

	pf &= ~ICP_TEMP_FLAGS;
	return pf;
}
static void optsym(int flag,PVStr(opts))
{	refQStr(op,opts); /**/

	op = (char*)opts;
	if( flag & ICP_FLAG_HIT_OBJ	) setVStrPtrInc(op,'o');
	if( flag & ICP_FLAG_X_NAVI	) setVStrPtrInc(op,'n');
	if( flag & ICP_ITYPE_PARENT	) setVStrPtrInc(op,'p');
	if( flag & ICP_ITYPE_LISTENER	) setVStrPtrInc(op,'l'); else
					  setVStrPtrInc(op,'s');

	if( flag & ICP_PTYPE_DELEGATE	) setVStrPtrInc(op,'D'); else
	if( flag & ICP_PTYPE_ORIG_PROXY	) setVStrPtrInc(op,'P'); else
	if( flag & ICP_PTYPE_ORIG_SERVER) setVStrPtrInc(op,'O'); else
					  setVStrPtrInc(op,'H');
	setVStrEnd(op,0);
}

int icp_selectconf(PVStr(conf),PCStr(dproto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser))
{
	if( ICP_NUMSERV == 0 )
		return -1;
	if( find_CMAPX(MainConn(),ICPMAP,AVStr(conf),dproto,dhost,dport,shost,sport,suser) < 0 )
		return -1;
	return 0;
}
/*
 * Conf is {icpHost/icpType/proxyPort/icpPort}*:icpOption:proxyPort:icpPort
 */
int icp_getconf(PCStr(conf),int icptypes[],const char *icpaddrs[],int icpports[],const char *pxaddrs[],int pxports[],double *timeout,PVStr(buff))
{	const char *addr;
	CStr(dcnfb,1024);
	const char *dcnfv[8];  /**/ /* default hosts:opts:pport:iport */
	CStr(servb,1024);
	const char *servv[32]; /**/ /* each server */
	CStr(srv1b,1024);
	const char *confv[8];  /**/ /* host/type/pport/iport */
	int dcc,scc,cc;
	const char *dicport;
	const char *dpxport;
	const char *dpxopts;
	const char *icphosts;
	const char *icport;
	const char *pxport;
	CStr(pxtype,32);
	int icptype,icptype1;
	const char *icpaddr;
	const char *pxaddr;
	CStr(pxhost,128);
	int pxportn;
	const char *icphost1;
	int ii;
	refQStr(bp,buff); /**/
	const char *tp;
	FILE *log = stderr;

	strcpy(dcnfb,conf);
	dcc = list2vect(dcnfb,':',4,dcnfv);
	strcpy(servb,dcnfv[0]);
	if( 1<dcc && *dcnfv[1] ) dpxopts = dcnfv[1]; else dpxopts = "";
	if( 2<dcc && *dcnfv[2] ) dpxport = dcnfv[2]; else dpxport = "8080";
	if( 3<dcc && *dcnfv[3] ) dicport = dcnfv[3]; else dicport = "3130";

	icptype = scanoptsG(dpxopts,timeout);

	scc = list2vect(servb,',',4,servv);

	for( ii = 0; ii < scc; ii++ ){
		strcpy(srv1b,servv[ii]);
		cc = list2vect(srv1b,'/',4,confv);
		if( 0<cc && *confv[0] )
			icphost1 = confv[0]; else icphost1 = "localhost";
		if( 1<cc && *confv[1] )
			icptype1 = scanoptsP(confv[1],icptype);
		else	icptype1 = icptype;
		if( 2<cc && *confv[2] ) pxport= confv[2]; else pxport= dpxport;
		if( 3<cc && *confv[3] ) icport= confv[3]; else icport= dicport;

		if( addr = gethostaddr(icphost1) )
			icpaddr = addr;
		else	icpaddr = "0.0.0.0";

		if( strchr(pxport,':') ){
			pxportn = 8080;
			Xsscanf(pxport,"%[^:]:%d",AVStr(pxhost),&pxportn);
		}else{
			pxportn = atoi(pxport);
			strcpy(pxhost,icphost1);
		}
		if( addr = gethostaddr(pxhost) )
			pxaddr = addr;
		else	pxaddr = "0.0.0.0";

		icpaddrs[ii] = bp;
		strcpy(bp,icpaddr); bp += strlen(bp) + 1;
		icpports[ii] = atoi(icport);

		pxaddrs[ii] = bp;
		strcpy(bp,pxaddr); bp += strlen(bp) + 1;
		pxports[ii] = pxportn;

		icptypes[ii] = icptype1;
		optsym(icptype1,AVStr(pxtype));

		Lprintf(log,"(ICP)%s/%s/%s:%d/%s\n",
			icpaddr,pxtype,pxaddr,pxportn,icport);
	}
	icpaddrs[scc] = NULL;
	return scc;
}
