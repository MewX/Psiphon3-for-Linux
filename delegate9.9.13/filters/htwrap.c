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
Content-Type:	program/C; charset=US-ASCII
Program:	htwrap.c (HTTP response wrapper)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    USAGE
	FTOCL=htwrap.cfi

	#!cfi
	Content-Type: text/html
	CGI: htwrap

    DESCRIPTION
	- redirect:  no   /-_- in Referer and   no /-_- in Request
	- wrapper:   no   /-_- in Referer and with /-_- in Request
	- through:   with /-_- in Referer and with /-_- in Request
	             without      Referer and   no /-_- in Request

History:
	970910	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
extern char *referer;

main(ac,av)
	char *av[];
{
	htwrap(stdin,stdout);
}

htwrap(in,out)
	FILE *in,*out;
{	char *request;
	CStr(qurl,1024);
	char *referer;
	char *server;
	char *port;
	char *rurl;
	char *lastmod;
	CStr(myname,512);
	CStr(line,1024);
	int rcc;

	request = getenv("HTTP_X_REQUEST_ORIGINAL");
	Xsscanf(request,"%*s %s",AVStr(qurl));
	if( rurl = strstr(qurl,"/-_-") )
		rurl += 4;
	else	rurl = qurl;

	server  = getenv("SERVER_NAME");
	port    = getenv("SERVER_PORT");
	if( strcmp(port,"80") == 0 )
		sprintf(myname,"http://%s",server);
	else	sprintf(myname,"http://%s:%s",server,port);

	referer = getenv("HTTP_X_REQUEST_REFERER");
/*
	if( referer != NULL && strncmp(referer,myname,strlen(myname)) != 0 ){
*/
	if( referer && strstr(referer,"/-_-") == NULL ){
		fprintf(out,"Status: 302 Moved\r\n");
		fprintf(out,"Location: %s/-_-%s\r\n",myname,rurl);
		fprintf(out,"\r\n");
		fprintf(out,"Retry the access via the wrapper.\r\n");
		while( 0 < (rcc = fread(line,1,sizeof(line),in)) )
			;
		return;
	}

	fprintf(out,"\r\n");

	if( strstr(qurl,"/-_-") ){
		fprintf(out,"<B>[HTWRAP/CFI/DeleGate]</B><BR>\r\n");
		fprintf(out,"Original-URL: <A HREF=\"%s\">%s</A><BR>\r\n",
			rurl,rurl);
		if( lastmod = getenv("HTTP_LAST_MODIFIED") )
			fprintf(out,"Last-Modified: %s<BR>\r\n",lastmod);
		fprintf(out,"<HR>\r\n");
	}

	while( 0 < (rcc = fread(line,1,sizeof(line),in)) )
		fwrite(line,1,rcc,out);

}
