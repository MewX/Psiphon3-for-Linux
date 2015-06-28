/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	icap.c (Internet Content Adaptation Protocol, RFC3507)
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	050524	created
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"

int service_icap(Connection *Conn)
{	FILE *fc,*tc;
	const char *dp;
	CStr(req,1024);
	CStr(method,16);
	CStr(uri,1024);
	CStr(ver,16);

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");

	if( fgetsTIMEOUT(AVStr(req),sizeof(req),fc) != NULL ){
		dp = wordScan(req,method);
		dp = wordScan(dp,uri);
		wordScan(dp,ver);
		sv1log("ICAP REQUEST [%s][%s][%s]\n",method,uri,ver);
		if( streq(method,"REQMOD") ){
		}else
		if( streq(method,"RESPMOD") ){
		}else
		if( streq(method,"OPTIONS") ){
		}else{
		}
	}

	fcloseFILE(tc);
	fcloseFILE(fc);
	return 0;
}
