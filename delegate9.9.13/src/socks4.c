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
Program:	socks4.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960219	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "file.h"
#include "dglib.h"
void tcp_relay2X(DGC*ctx,int timeout,int s1,int d1,int s2,int d2);
#define tcp_relay2(timeout,s1,d1,s2,d2) tcp_relay2X(ctx,timeout,s1,d1,s2,d2)

extern int IO_TIMEOUT;
extern int CON_TIMEOUT;
extern int ACC_TIMEOUT;

#define SOCKS_VERSION	4
#define SOCKS_FORWRSLV	0x80
#define SOCKS_CONNECT	1
#define SOCKS_BIND	2
#define SOCKS_ACCEPT	8	/* pseudo command */
#define SOCKS_RESULT	90
#define SOCKS_FAIL	91
#define SOCKS_NO_IDENTD	92
#define SOCKS_BAD_ID	93

static const char *scommand(int command)
{
	switch(command){
		case SOCKS_CONNECT:	return "CONNECT";
		case SOCKS_BIND:	return "BIND";
		case SOCKS_ACCEPT:	return "ACCEPT";
		default:		return "BAD-COM";
	}
}

int SocksV4_isConnectReuqest(PCStr(spack),int leng,int *ver,PVStr(addr),int *port,const char **user)
{	const unsigned char *pack = (unsigned char *)spack;

	if( pack[0] == 4 )
	if( pack[1] == SOCKS_CONNECT ){
		*ver = 4;
		*port = pack[2] << 8 | pack[3];
		sprintf(addr,"%d.%d.%d.%d",pack[4],pack[5],pack[6],pack[7]);
		*user = &spack[8];
		return 8 + strlen(*user) + 1;
	}
	return 0;
}

static int makePacket(PVStr(obuf),int version,int command,PCStr(addr),int port,PCStr(user))
{	int av[4][1];
	int pc;
	int forwrslv;
	
	if( forwrslv = !isinetAddr(addr) ){
sv1log("[Socks4A-clnt] forwarding '%s'\n",addr);
	}else{
	if( command == SOCKS_CONNECT && strcmp(addr,"0.0.0.0") == 0 )
		return -1;
	if( sscanf(addr,"%d.%d.%d.%d",av[0],av[1],av[2],av[3]) != 4 )
		return -1;
	}

	switch( command ){
		case SOCKS_RESULT:
		case SOCKS_FAIL:
		case SOCKS_NO_IDENTD:
		case SOCKS_BAD_ID:
			((char*)obuf)[0] = 0; /* the version of the set of reply codes */
			break;
	default:
		((char*)obuf)[0] = version;
	}

	((char*)obuf)[1] = command;
	((char*)obuf)[2] = port >> 8;
	((char*)obuf)[3] = port;

	if( forwrslv ){
		((char*)obuf)[4] = 0;
		((char*)obuf)[5] = 0;
		((char*)obuf)[6] = 0;
		((char*)obuf)[7] = 1;
	}else{
		((char*)obuf)[4] = av[0][0];
		((char*)obuf)[5] = av[1][0];
		((char*)obuf)[6] = av[2][0];
		((char*)obuf)[7] = av[3][0];
	}

	Xstrcpy(DVStr(obuf,8),user);
	pc = 8 + strlen(user) + 1;

	if( forwrslv ){
		Xstrcpy(DVStr(obuf,pc),addr);
		pc += strlen(addr) + 1;
	}

	return pc;
}
static char *getAddrPart(PCStr(pack),PVStr(addr))
{	const unsigned char *up = (unsigned char*)pack;
	sprintf(addr,"%d.%d.%d.%d",up[4],up[5],up[6],up[7]);
	return (char*)addr;
}

int fgetstr(PVStr(user),int size,FILE *fc)
{	int ux,ch;

	ux = 0;
	for( ux = 0; ; ux++ ){
		if( size-1 <= ux )
			return -1;
		ch = fgetc(fc);
		if( ch == EOF )
			return -1;
		if( ch == 0 )
			break;
		setVStrElem(user,ux,ch); /**/
	}
	setVStrEnd(user,ux); /**/
	return ux;
}

/*
 *	SOCKS SERVER
 */
void SocksV4_serverA(DGC*ctx,int _1,int _2,int fromC,int toC,FILE *fc);
void SocksV4_server(DGC*ctx,int _1,int _2,int fromC,int toC)
{	FILE *fc;

	fc = fdopen(fromC,"r");
	SocksV4_serverA(ctx,_1,_2,fromC,toC,fc);
	fcloseFILE(fc);
}
void SocksV4_serverA(DGC*ctx,int _1,int _2,int fromC,int toC,FILE *fc){
	unsigned char ibuf[16]; /**/
	CStr(obuf,16);
	int pc,ver,com,ch;
	int ux,dstport;
	CStr(dstaddr,64);
	CStr(host,512);
	CStr(user,512);
	const char *addr;
	CStr(local,512);
	CStr(remote,512);
	CStr(ahost,64);
	CStr(bhost,64);
	int aport,bport,asock,bsock,csock,nready,socks[2],readyv[2];

	setbuf(fc,NULL);
	pc = fread(ibuf,8,1,fc);
	if( pc <= 0 )
	{
		syslog_ERROR("#### ERROR: can't read packet %d %d\n",pc,errno);
		return;
	}
	ver = ibuf[0];
	com = ibuf[1];
	dstport = (ibuf[2] << 8) | ibuf[3];
	sprintf(dstaddr,"%d.%d.%d.%d",ibuf[4],ibuf[5],ibuf[6],ibuf[7]);

	if( com != SOCKS_CONNECT && com != SOCKS_BIND ){
		syslog_ERROR("#### ERROR: NON SOCKS CLIENT ?[%d]\n",com);
		return;
	}

	if( fgetstr(AVStr(user),sizeof(user),fc) < 0 )
	{
sv1log("[SocksV4-serv] empty user part err=%d\n",errno);
		return;
	}

	if( ibuf[4] == 0 && ibuf[5] == 0 && ibuf[6] == 0 && ibuf[7] != 0 ){
		if( fgetstr(AVStr(host),sizeof(host),fc) < 0 || host[0] == 0 ){
sv1log("[Socks4A-serv] domain name not sent\n",host);
			goto failed;
		}
		if( addr = gethostaddr(host) ){
			strcpy(dstaddr,addr);
sv1log("[Socks4A-serv] received '%s'[%s]\n",host,addr);
		}else{
sv1log("[Socks4A-serv] received '%s'(unknown)\n",host);
			if( GetViaSocks(ctx,host,dstport) )
				strcpy(dstaddr,"0.0.0.1");
			else	goto failed;
		}
	}else
	gethostbyAddr(dstaddr,AVStr(host));

sv1log("[SocksV4-serv] %d ver[%d] com[%d/%s] port[%d] host[%s][%s] user[%s]\n",
		pc,ver,com,scommand(com),dstport,dstaddr,host,user);

	set_realserver(ctx,"tcprelay",dstaddr,dstport);
	if( !service_permitted(ctx,"tcprelay") )
		goto failed;

	strcpy(local,"*:*");
	if( strcmp(dstaddr,"0.0.0.1") == 0 )
		sprintf(remote,"%s:%d",host,dstport);
	else
	sprintf(remote,"%s:%d",dstaddr,dstport);
	if( com == SOCKS_BIND ){
		if( GetViaSocks(ctx,dstaddr,dstport) ){
			sv1log("#### MUST DO bindViaSocks... %s:%d\n",
				dstaddr,dstport);
		}
		bsock = VSocket(ctx,"BIND/SocksV4",-1,AVStr(local),AVStr(remote),"listen=1");
		if( bsock < 0 )
			goto failed;
		bport = scan_hostport1X(local,AVStr(bhost),sizeof(bhost));
		makePacket(AVStr(obuf),SOCKS_VERSION,SOCKS_RESULT,bhost,bport,"");
		IGNRETP write(toC,obuf,8);

		socks[0] = fromC;
		socks[1] = bsock;
		nready = PollIns(ACC_TIMEOUT*1000,2,socks,readyv);
		if( nready <= 0 || readyv[1] <= 0 ){
			close(bsock);
			goto failed;
		}

		asock = VSocket(ctx,"ACPT/SocksV4",bsock,AVStr(local),AVStr(remote),"");
		close(bsock);
		aport = scan_hostport1X(local,AVStr(ahost),sizeof(ahost));
		makePacket(AVStr(obuf),SOCKS_VERSION,SOCKS_RESULT,ahost,aport,"");
		IGNRETP write(toC,obuf,8);
		tcp_relay2(IO_TIMEOUT*1000,fromC,asock,asock,toC);
		close(asock);
	}else{
		csock = VSocket(ctx,"CNCT/SocksV4",-1,AVStr(local),AVStr(remote),"");
		if( csock < 0 )
			goto failed;
		bport = scan_hostport1X(local,AVStr(bhost),sizeof(bhost));
		makePacket(AVStr(obuf),SOCKS_VERSION,SOCKS_RESULT,bhost,bport,"");
		IGNRETP write(toC,obuf,8);
		tcp_relay2(IO_TIMEOUT*1000,fromC,csock,csock,toC);
		close(csock);
	}
	return;

failed:
	makePacket(AVStr(obuf),SOCKS_VERSION,SOCKS_FAIL,dstaddr,dstport,"");
	IGNRETP write(toC,obuf,8);
}

/*
 *	SOCKS CLIENT
 */
static int getResponse(int sock,int command,PVStr(rhost),int *rport)
{	FILE *fs;
	unsigned CStr(ibuf,128);
	int pc;

	if( PollIn(sock,CON_TIMEOUT*1000) <= 0 ){
		sv1log("SOCKS response TIMEOUT (%d)\n",CON_TIMEOUT);
		return SOCKS_FAIL;
	}
	pc = readsTO(sock,QVStr((char*)ibuf,ibuf),8,CON_TIMEOUT*1000);

	sv1log("[SocksV4-clnt] %s %d ver[%d] stat[%d] host[%d.%d.%d.%d]:%d\n",
		scommand(command),
		pc,
		ibuf[0],ibuf[1],
		ibuf[4],ibuf[5],ibuf[6],ibuf[7],
		ibuf[2]<<8|ibuf[3]);

	if( rhost != NULL )
		sprintf(rhost,"%d.%d.%d.%d",ibuf[4],ibuf[5],ibuf[6],ibuf[7]);
		/* it can be "0.0.0.0" for BIND when the Socks server did
		 * bind() with wild-card address.  If it is necessary
		 * (ex. for PORT/FTP) it must be got from the response for
		 * CONNECT command (for control connection).
		 */


	if( rport != NULL )
		*rport = (ibuf[2] << 8) | ibuf[3];

	return ibuf[1];
}
int SocksV4_clientStart(int sock,int command,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport,PVStr(xaddr))
{	CStr(obuf,128);
	char i;
	int pc,wcc,rep;

	pc = makePacket(AVStr(obuf),SOCKS_VERSION,command,host,port,user);
	if( pc < 0 )
		return -1;

	wcc = write(sock,obuf,pc);
	rep = getResponse(sock,command,AVStr(rhost),rport);

	if( rep == SOCKS_RESULT ){
		if( command == SOCKS_CONNECT && xaddr != NULL )
		{
			getAddrPart(obuf,AVStr(xaddr));
		}
		return 0;
	}else	return -1;
}
int SocksV4_acceptViaSocks(int sock,PVStr(rhost),int *rport)
{	int rep;

	rep = getResponse(sock,SOCKS_ACCEPT,AVStr(rhost),rport);
	if( rep == SOCKS_RESULT )
		return 0;
	else	return -1;
}
