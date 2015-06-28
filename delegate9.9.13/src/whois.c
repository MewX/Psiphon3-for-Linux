/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

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
Content-Type:	program/C; charset=US-ASCII
Program:	telnet.c (telnet proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950424	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"
void scan_realserver(Connection *Conn,PCStr(url),PVStr(upath));

static void relay_response(Connection *Conn)
{	FILE *fs,*tc;
	CStr(resp,1024);
	CStr(xresp,1024);
	int doconv;

	fs = fdopen(FromS,"r");
	tc = fdopen(ToC,"w");
	doconv = CTX_check_codeconv(Conn,1);

	for(;;){
		if( fgetsTIMEOUT(AVStr(resp),sizeof(resp),fs) == NULL )
			break;

		if( doconv ){
			CTX_line_codeconv(Conn,resp,AVStr(xresp),"text/plain");
			strcpy(resp,xresp);
		}

		fputs(resp,tc);
		fflush(tc);
	}
	fclose(fs);
	fclose(tc);
}

int service_whois(Connection *Conn)
{	FILE *fc,*ts,*tc;
	CStr(req,1024);
	CStr(ereq,1024);
	CStr(key,1024);

	fc = fdopen(FromC,"r");
	if( DDI_fgetsFromC(Conn,AVStr(req),sizeof(req),fc) == NULL )
		goto EXIT;
	sv1log("WHOIS keyword: %s",req);

	if( strncasecmp(req,"whois://",8) == 0 ){
		scan_realserver(Conn,req,AVStr(key));
		if( *key == 0 ) strcpy(key,"help");
		if( *key == '?' ) ovstrcpy(key,key+1);
		Verbose("WHOIS -> whois://%s:%d/%s\n",DST_HOST,DST_PORT,key);
		sprintf(req,"%s\r\n",key);
	}
	if( isMYSELF(DST_HOST) ){
		tc = fdopen(ToC,"w");
		fprintf(tc,"\r\n");
		fprintf(tc,"  @ @   Proxy-Whois on %s\r\n",DELEGATE_version());
		fprintf(tc," ( - )  Enter whois://SERVER?identifier\r\n");
		fprintf(tc,"\r\n");
		fcloseTIMEOUT(tc);
		goto EXIT;
	}

	if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
		Verbose("Could not connect to: %s\n",DST_HOST);
		goto EXIT;
	}

	ts = fdopen(ToS,"w");
	TO_EUC(req,AVStr(ereq),"text/plain");
	fputsTIMEOUT(ereq,ts);
	fflush(ts);

	relay_response(Conn);
	fclose(ts);
EXIT:
	fcloseTIMEOUT(fc);
	return 0;
}
