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
Program:	lsock.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	100129	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
int _PollIn1(int fd,int timeout);

#if defined(_MSC_VER)
#else
#undef bind
#undef connect
#undef accept
#undef Xaccept
#define accept Xaccept
#endif

int connectL(PCStr(host),int port,int timeout){
	struct sockaddr_in sin;
	int siz = sizeof(sin);
	int sock;

	sock = socket(AF_INET,SOCK_STREAM,0);
sin.sin_family = AF_INET;
sin.sin_port = htons(port);
sin.sin_addr.s_addr = inet_addr(host);

	if( connect(sock,(SAP)&sin,siz) == 0 ){
		return sock;
	}else{
		close(sock);
		return -1;
	}
}
int bindL(PCStr(host),int *portp,int nlisten){
	int sock;
	struct sockaddr_in sin;
	int siz = sizeof(sin);
	int port = *portp;

	sock = socket(AF_INET,SOCK_STREAM,0);
sin.sin_family = AF_INET;
sin.sin_port = htons(port);
sin.sin_addr.s_addr = inet_addr(host);

	siz = sizeof(sin);
	if( bind(sock,(SAP)&sin,siz) != 0 ){
		close(sock);
		return -1;
	}
	listen(sock,nlisten);

	getsockname(sock,(SAP)&sin,&siz);
*portp = sin.sin_port;
	return sock;
}
int acceptL(int asock,int timeout,PVStr(addr)){
	int rdy;
	int sock;
	struct sockaddr_in sin;
	int siz = sizeof(sin);

	if( (rdy = _PollIn1(asock,timeout)) <= 0 ){
		return -1;
	}
	siz = sizeof(sin);
	sock = accept(asock,(SAP)&sin,&siz);
	if( 0 <= sock && addr != 0 ){
	}
	return sock;
}
