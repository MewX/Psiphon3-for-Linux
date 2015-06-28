/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	delegate (verbose delegate protocol)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "ystring.h"
#include "file.h"

int service_delegate(Connection *Conn)
{	CStr(line,256);
	CStr(com,256);
	CStr(arg,256);
	FILE *fc,*tc;
	CStr(host,MaxHostNameLen);
	CStr(xhost,64);
	const char *pp;
	int xport;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,  "w");
	if( fc == NULL || tc == NULL )
		return 0;

	ClientIF_name(Conn,FromC,AVStr(host));
	/*gethostname(host,sizeof(host));*/
	sprintf(line,"%s %s\r\n",host,DELEGATE_Version());
	Fputs(line,tc);

/*
	Fputs("COMMANDS: \r\n",tc);
	Fputs("      telnet host [port]\r\n",tc);
	Fputs("      gopher [host port]\r\n",tc);
	Fputs("\r\n",tc);
*/

	while( fgetsTIMEOUT(AVStr(line),sizeof(line),fc) != NULL ){
		DFLT_HOST[0] = 0;
		DFLT_PORT = 0;
		com[0] = 0;
		arg[0] = 0;
		Xsscanf(line,"%[^\r\n\t ]%*[\r\n\t ]%[^\r\n]",AVStr(com),AVStr(arg));

		if( strcasecmp(com,"QUIT") == 0 )
			break;
		if( strcasecmp(com,"TELNET") == 0 ){
			xport = 0;
			pp = wordScan(arg,xhost);
			sscanf(pp,"%d",&xport);
			set_SERVER(Conn,"telnet",xhost,xport);
			execSpecialist(Conn,FromC,tc,-1);
			break;
		}else
		if( Fputs(line,tc) == EOF )
			break;
	}
	return 0;
}
