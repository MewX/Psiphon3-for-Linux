/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Yutaka Sato
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose and
without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	rident.c (remote ident)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	971217	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "dglib.h"

#define RIDENT_SIZE	64
#define RIDENT_MAGIC		"RIDENT/"
#define RIDENT_MAGIC_LEN	(sizeof(RIDENT_MAGIC)-1)
#define RIDENT_VER		"0.9"

#include "vaddr.h"
RidentEnv ridentEnv = {1.0,0,0};

static scanListFunc rident1(PCStr(spec))
{
	if( *spec == 'c' ) RIDENT_CLIENT = 1;
	else
	if( *spec == 's' ) RIDENT_SERVER = 1;
	else
	{
		sv1tlog("ERROR: unknown RIDENT=%s\n",spec);
	}
	return 0;
}
void scan_RIDENT(DGC*Conn,PCStr(specs))
{
	if( specs != NULL )
	{
		xmem_push(&ridentEnv,sizeof(RidentEnv),"RIDENT",NULL);
		scan_commaListL(specs,0,scanListCall rident1);
	}
}

static struct { defQStr(username); } username;
#define username username.username

int RIDENT_sendX(int sock,PCStr(sockname),PCStr(peername),PCStr(ident))
{	CStr(rident,128);
	int wcc;

	if( ident == NULL ){
		if( username == 0 )
			setQStr(username,(char*)StructAlloc(128),128);
		if( username[0] == 0 )
			getUsername(getuid(),AVStr(username));
		ident = username;
	}
	sprintf(rident,"%s%s %s %s %s %64s",RIDENT_MAGIC,RIDENT_VER,
		sockname,peername,ident," ");
	Xstrcpy(DVStr(rident,62),"\r\n");
	wcc = write(sock,rident,RIDENT_SIZE);
	RIDENT_SENT = wcc;
	return wcc;
}
int RIDENT_send(int sock,PCStr(sockname),PCStr(peername),PCStr(ident))
{
	if( RIDENT_SERVER == 0 )
		return 0;
	return RIDENT_sendX(sock,sockname,peername,ident);
}
/*
int RIDENT_recv(int clsock,PVStr(sockname),PVStr(peername))
*/
int RIDENT_recvX(int clsock,PVStr(sockname),PVStr(peername),int force)
{	CStr(rident,128);
	CStr(ver,128);
	CStr(user,128);
	int rcc;
	int ready;
	int timeout;

	/*
	if( RIDENT_CLIENT == 0 ){
	*/
	if( RIDENT_CLIENT == 0 && force == 0 ){
		getpairName(clsock,AVStr(sockname),AVStr(peername));
		return 0;
	}

	rident[0] = 0;
	timeout = (int)(RIDENT_TIMEOUT*1000);
	if( timeout <= 0 )
		timeout = 1;
	ready = PollIn(clsock,timeout);
	if( ready <= 0 ){
		sv1log("####[%d] getRIDENT TIMEOUT(%dms)\n",clsock,timeout);
/*
		close(clsock);
		return -1;
*/
		goto EXIT;
	}
	if( isWindowsCE() ){
		/* recv(MSG_PEEK) for only single byte is implemented */
		rcc = recv(clsock,rident,1,MSG_PEEK);
		if( rcc == 1 && rident[0] == RIDENT_MAGIC[0] ){
			rcc = recv(clsock,rident,RIDENT_SIZE,0);
			if( rcc != RIDENT_SIZE
			 || strncmp(rident,RIDENT_MAGIC,RIDENT_MAGIC_LEN) != 0 ){
				porting_dbg("## RIDENT_recv() failed %d/%d",rcc,RIDENT_SIZE);
			}
		}
	}else
	rcc = recv(clsock,rident,RIDENT_SIZE,MSG_PEEK);
	RIDENT_RCVD = rcc;

	if( RIDENT_MAGIC_LEN <= rcc )
	if( strncmp(rident,RIDENT_MAGIC,RIDENT_MAGIC_LEN) == 0 ){
		if( isWindowsCE() ){
			/* recv() done already */
		}else
		rcc = read(clsock,rident,RIDENT_SIZE);
		setVStrEnd(user,0);
		setVStrEnd(peername,0);
		setVStrEnd(sockname,0);
		if( rcc == RIDENT_SIZE )
		if( 3 <= Xsscanf(rident+RIDENT_MAGIC_LEN,"%s %s %s %s",AVStr(ver),AVStr(sockname),AVStr(peername),AVStr(user)) )
		if( strcmp(ver,RIDENT_VER) == 0 ){
			sv1log("#### getRIDENT %d[%s][%s][%s]\n",
				rcc,sockname,peername,user);
			return 1;
		}
		sv1log("#### getRIDENT Version/Syntax Error\n");
		return -1;
	}
EXIT:
	getpairName(clsock,AVStr(sockname),AVStr(peername));
	return 0;
}
