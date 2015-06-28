/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato
Copyright (c) 1994-2000 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	ident.c (Identification Protocol - RFC1413)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	000301	extracted from access.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "hostlist.h"
#include "delegate.h"
#include "fpoll.h"
#include <ctype.h>
#include <errno.h>

extern double IDENT_TIMEOUT;

#define IDENT_NOTYET	 0
#define IDENT_GOT	 1
#define IDENT_DONTTRY	-1
#define IDENT_CANTCONN	-2
#define IDENT_TIMEDOUT	-3
#define IDENT_EOF	-4
#define IDENT_BAD	-5

static int getIdent(int timeout,int idsv,int lport,int rport,AuthInfo *ident)
{	FILE *ti,*fi;
	CStr(resp,512);
	CStr(iresp,512);
	CStr(syst,512);
	CStr(user,512);
	int rcode = -1;

	ident->i_user[0] = 0;
	ident->i_stat = IDENT_NOTYET;

	ti = fdopen(idsv,"w");
	fi = fdopen(idsv,"r");

	fprintf(ti,"%d, %d\r\n",rport,lport);
	Verbose("-- ident: %d, %d\n",rport,lport);
	fflush(ti);
	if( fPollIn(fi,timeout) == 0 ){
		ident->i_stat = IDENT_TIMEDOUT;
		Verbose("-- ident: server response TIMEOUT (%ds).\n",	
			timeout);
	}else
	if( fgetsTimeout(AVStr(resp),sizeof(resp),fi,timeout) == NULL ){
		ident->i_stat = IDENT_EOF;
		Verbose("-- ident: EOF from the server.\n");
	}else{
		lineScan(resp,iresp);
		user[0] = 0;
		Xsscanf(iresp,"%*d%*[ ,]%*d%*[ :]USERID%*[ :]%[^ :]%*[ :]%s\n",AVStr(syst),AVStr(user));
		if( user[0] ){
			Verbose("-- ident: %s : %s\n",syst,user);
			ident->i_stat = IDENT_GOT;
			linescanX(syst,AVStr(ident->i_syst),sizeof(ident->i_syst));
			linescanX(user,AVStr(ident->i_user),sizeof(ident->i_user));
			rcode = 0;
		}else{
			ident->i_stat = IDENT_BAD;
			Verbose("-- ident: %s",resp);
		}
	}
	fclose(ti);
	fclose(fi);
	return rcode;
}
static const char *getClientIdent0(Connection *Conn,PCStr(host),int port,AuthInfo *ident)
{	int idsv;
	int timeout;
	int myport;
	CStr(myaddr,64);

	if( lNOIDENT() ){
		ident->i_stat = IDENT_DONTTRY;
		clearVStr(ident->i_syst);
		clearVStr(ident->i_user);
		return NULL;
	}

	VA_inetNtoah(&Conn->cl_sockHOST,AVStr(myaddr));
	myport = Conn->cl_sockHOST.a_port;
	Verbose("-- ident: %s [%s:%d]\n",host,myaddr,myport);
	idsv = Socket1("IDENT",-1,NULL,NULL,NULL, AVStr(myaddr),0,NULL,0, 0,NULL,0);

	Verbose("-- ident: %d\n",idsv);
	if( idsv < 0 ){
		ident->i_stat = IDENT_CANTCONN;
		return NULL;
	}

	timeout = (int)(IDENT_TIMEOUT * 1000);
	if( IDENT_TIMEOUT != 0 && timeout == 0 )
		timeout = 1;

	if( connectTimeout(idsv,host,113,timeout) != 0 ){
		sv1log("### IDENT CONNECT(%s:113) TIMEOUT(%dms) (%d)\n",
			host,timeout,errno);
		close(idsv);
		ident->i_stat = IDENT_CANTCONN;
	}else{
		if( getIdent(timeout,idsv,myport,port,ident) == 0 )
			return ident->i_user;
	}
	return NULL;
}

HostList *IdentHosts();
static const char *getClientIdentH0(Connection *Conn,PCStr(host),int port,int force,AuthInfo *ident)
{	int isin;

	if( ident == NULL )
		ident = &Client_Ident;

	if( ident->i_stat != IDENT_NOTYET )
	if( !(force && ident->i_stat == IDENT_DONTTRY) )
		goto EXIT;

	if( force )
		isin = 1;
	else	isin = hostIsinList(IdentHosts(),ANYP,host,port,NULL);

	if( !isin )
		ident->i_stat = IDENT_DONTTRY;
	else	getClientIdent0(Conn,host,port,ident);

EXIT:
	if( ident->i_stat == IDENT_GOT )
		return ident->i_user;
	else	return NULL;
}
const char *getClientUser(Connection *Conn)
{
	if( VA_getClientAddr(Conn) )
		return getClientIdentH0(Conn,Client_Host,Client_Port,1,NULL);
	return NULL;
}
const char *getClientUserC(Connection *Conn)
{
	if( VA_getClientAddr(Conn) )
		return getClientIdentH0(Conn,Client_Host,Client_Port,0,NULL);
	return NULL;
}
const AuthInfo *getClientIdentX(Connection *Conn)
{
	if( getClientUserC(Conn) )
		return &Client_Ident;
	return NULL;
}
char *getClientUserMbox(Connection *Conn,PVStr(mbox))
{	AuthInfo ident;
	CStr(host,MaxHostNameLen);

	strcpy(mbox,"?");
	if( VA_getClientAddr(Conn) ){
		if( getClientIdent0(Conn,Client_Host,Client_Port,&ident) ){
			getFQDN(Client_Host,AVStr(host));
			sprintf(mbox,"%s@%s",ident.i_user,host);
			return (char*)mbox;
		}
	}
	return NULL;
}
const char *getClientHostPortUser(Connection *Conn,PVStr(host),int *portp)
{
	VA_getClientAddr(Conn);
	if( host ) strcpy(host,Client_Host);
	if( portp ) *portp = Client_Port;
	if( 0 < Client_Port )
		return getClientIdentH0(Conn,Client_Host,Client_Port,1,NULL);
	else	return NULL;
}

int CTX_VA_getOriginatorAddr(Connection *Conn,VAddr *Vaddr);
const char *VA_getOriginatorIdent(Connection *Conn,AuthInfo *ident)
{	VAddr *vaddr;

	vaddr = &ident->i_addr;
	if( CTX_VA_getOriginatorAddr(Conn,vaddr) <= 0 )
		return NULL;

	ident->i_stat = 0;
	return getClientIdentH0(Conn,vaddr->a_name,vaddr->a_port,1,ident);
}
