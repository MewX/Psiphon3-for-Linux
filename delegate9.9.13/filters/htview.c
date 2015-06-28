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
Program:	htview.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951104	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"

htview(in,out)
	FILE *in,*out;
{	CStr(line,1024);
	CStr(fname,1024);
	CStr(fvalue,1024);
	CStr(ctype,1024);
	FILE *tmp;

	if( fgets(line,sizeof(line),in) == NULL )
		return 0;

	if( strncmp(line,"HTTP/",5) != 0 ){
		fputs(line,out);
		copyfile1(in,out);
		return 0;
	}

	strcpy(ctype,"text/plain");
	while( fgets(line,sizeof(line),in) ){
		fputs(line,out);
		if( line[0] == '\r' || line[0] == '\n' )
			break;
		Xsscanf(line,"%[^: ]%*[: ]%[^\r\n]",AVStr(fname),AVStr(fvalue));
		if( strcasecmp(fname,"Content-Type") == 0 )
			strcpy(ctype,fvalue);
	}
	if( strcasecmp(ctype,"image/gif") == 0
	 || strcasecmp(ctype,"image/jpeg") == 0
	 || strcasecmp(ctype,"image/x-xbm") == 0 
	 || strcasecmp(ctype,"application/postscript") == 0 ){
		int sfd;

		fprintf(out,"[content is displayed on the screen]\r\n");
		fflush(out);

		tmp = tmpfile();
		copyfile1(in,tmp);
		fflush(tmp);
		fseek(tmp,0,0);

		sfd = dup(0);
		dup2(fileno(tmp),0);

		system("xv -");

		close(0);
		dup2(sfd,0);
		fclose(tmp);
	}else{
		copyfile1(in,out);
	}
	return 1;
}

main(ac,av)
	char *av[];
{
	htview(stdin,stdout);
}
