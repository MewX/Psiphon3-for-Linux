/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        hostaddr.c
Author:         Yutaka Sato <ysato@etl.go.jp>
Description:
History:
        970728	extracted from inets.c and windows.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "vsocket.h"
#include "vsignal.h"

unsigned short ntohS(int si){	return ntohs((unsigned short)si); }
unsigned short htonS(int si){	return htons((unsigned short)si); }
INETADDRV4 ntohL(INETADDRV4 li){	return ntohl(li); }
INETADDRV4 htonL(INETADDRV4 li){	return htonl(li); }

/*########################################
 *	INHERENT RESOLVER UTILIZATION
 */

#ifdef gethostbyname
#undef gethostbyname
#endif
struct hostent *RES_gethostbyname(const char*);
struct hostent *
EX_GETHOSTBYNAME(PCStr(name))
{	struct hostent *ht;
	int mask;

	/*porting_dbg("gethostbyname(%s) ...",name);*/
	mask = sigblock(sigmask(SIGALRM));
	ht = gethostbyname(name);
	sigsetmask(mask);
	/*porting_dbg("gethostbyname(%s) = %x",name,ht);*/
	return ht;
}
struct hostent *
_GETHOSTBYNAME(PCStr(name))
{	struct hostent *ht;

	return RES_gethostbyname(name);
}

#ifdef gethostbyaddr
#undef gethostbyaddr
#endif
struct hostent *RES_gethostbyaddr(const char*,int,int);
struct hostent *
EX_GETHOSTBYADDR(PCStr(addr),int len,int type)
{	struct hostent *ht;
	const char *aaddr;
	int mask;

	aaddr = inet_ntoa(*(struct in_addr*)addr);
	/*porting_dbg("gethostbyaddr(%s) ...",aaddr);*/
	mask = sigblock(sigmask(SIGALRM));
	ht = gethostbyaddr(addr,len,type);
	sigsetmask(mask);
	/*porting_dbg("gethostbyaddr(%s) = %x",aaddr,ht);*/
	return ht;
}
struct hostent *
_GETHOSTBYADDR(PCStr(addr),int len,int type)
{
	return RES_gethostbyaddr(addr,len,type);
}
