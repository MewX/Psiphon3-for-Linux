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
Program:	hostent.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950822	created
//////////////////////////////////////////////////////////////////////#*/

#include "vsocket.h"
static int dummy; /* to avoid empty symbol table */

#ifndef STD_HOSTENT
int h_errno;

sethostent(stayopen)
{
	return RES_sethostent(stayopen);
}
endhostent()
{
	return RES_endhostent();
}
extern void *RES_gethostent();
void *gethostent()
{
	return RES_gethostent();
}
#endif

#ifndef gethostbyname
extern void *RES_gethostbyname();
void *gethostbyname(char *name)
{
	return RES_gethostbyname(name);
}
#endif

#ifndef gethostbyaddr
extern void *RES_gethostbyaddr();
void *gethostbyaddr(char *addr,int len,int type)
{
	return RES_gethostbyaddr(addr,len,type);
}
#endif
