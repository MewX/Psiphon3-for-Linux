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
Program:	coupler (TCP coupler)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	TCP/IP reflector
History:
	950619	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"

int service_coupler(Connection *Conn)
{	FILE *fc,*tc;
	FILE *sfp;
	CStr(request,1024);
	CStr(shost,MaxHostNameLen);
	CStr(dst,256);
	CStr(spath,1024);
	int ssock,sport;
	int csock;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,  "w");

	fgets(request,sizeof(request),fc);
	Xsscanf(request,"%s",AVStr(shost));
	sprintf(spath,"/tmp/delegate/coupler/%s",shost);

	if( sfp = fopen(spath,"r") ){
		IGNRETP fscanf(sfp,"%d",&sport);
		fprintf(tc,"connecting...\r\n");
		fflush(tc);
		csock = client_open("coupler","coupler","localhost",sport);
		fprintf(tc,"coupled.\r\n");
		fprintf(tc,"\r\n");
		fflush(tc);
		relay_svcl(Conn,FromC,ToC,csock,csock);
	}else{
		sfp = dirfopen("coupler",AVStr(spath),"w");
		ssock = server_open("coupler",VStrNULL,0,1);
		sport = sockPort(ssock);
		fprintf(sfp,"%d\r\n",sport);
		fflush(sfp);
		fprintf(tc,"waiting...\r\n");
		fflush(tc);
		csock = ACCEPT(ssock,1,-1,30);
		fprintf(tc,"coupled.\r\n",csock);
		fprintf(tc,"\r\n");
		fflush(tc);
		unlink(spath);
		relay_svcl(Conn,FromC,ToC,csock,csock);
	}
	return 0;
}
