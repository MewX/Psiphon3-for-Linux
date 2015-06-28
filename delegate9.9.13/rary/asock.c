/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2010 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	asock.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	100118	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"

/*
#if defined(_MSC_VER)
#else
#undef bind
#undef accept Xaccept
#undef connect
#endif
*/

int connectA(PCStr(host),int port,int timeout){
	VSAddr sa;
	int sock;

	sock = socket(AF_INET,SOCK_STREAM,0);
	VSA_atosa(&sa,port,host);

	if( connect(sock,(SAP)&sa,VSA_size(&sa)) == 0 ){
		return sock;
	}else{
		close(sock);
		return -1;
	}
}
int acceptA(int asock,int timeout,PVStr(addr)){
	int rdy;
	int sock;
	VSAddr sa;
	int sl;

	if( (rdy = PollIn1(asock,timeout)) <= 0 ){
		return -1;
	}
	sl = sizeof(sa);
	sock = accept(asock,(SAP)&sa,&sl);
	if( 0 <= sock && addr != 0 ){
		/*
		VSA_ntoa();
		*/
	}
	return sock;
}
int bindA(PCStr(host),int *portp,int nlisten){
	int sock;
	VSAddr sa;
	int port = *portp;
	int sl;

	sock = socket(AF_INET,SOCK_STREAM,0);
	VSA_atosa(&sa,port,host);
	if( bind(sock,(SAP)&sa,VSA_size(&sa)) != 0 ){
		close(sock);
		return -1;
	}
	listen(sock,nlisten);
	sl = sizeof(sa);

	getsockname(sock,(SAP)&sa,&sl);
	*portp = VSA_port(&sa);
	return sock;
}
