/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1998 Yutaka Sato

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	ciicgi.c (CII as CGI program for CFI)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

USAGE
-----
delegated -P8080 FTOCL=cii.cfi

where the content of cii.cfi file is as follows:

#!cfi
Content-Type: text
CGI: ciicgi
##################

HOW TO MAKE
-----------
LIBRARY = library.a
LIBMIME = libmimekit.a
LIBSUBS = libsubst.a
LIBCII = libcii.a
ciicgi: ciicgi.c $(LIBCII)
	$(CC) -O -o $@ ciicgi.c $(LIBCII) $(LIBMIME) $(LIBRARY) $(LIBSUBS)

History:
	980724	created
/////////////////////////////////////////////////////////////////////// */
#include <stdio.h>
#include <string.h>
extern char *getenv();

/*
 * Only rare clients (e.x Mozilla4.X) supports "data:xxx" URL scheme.
 * So the "data" scheme should be redirected to and interpreted in
 * DeleGate. 
 */
char *data_proxy = "//-/-/";

/*
 * Some clients (e.x. Mosaic) does not recognize folded URL
 */
int url_oneline = 1;

#include "ystring.h"

main(ac,av)
	char *av[];
{	CStr(any_text,0x1000);
	CStr(cii_text,0x20000);
	char *ctype;
	char *charsets[2];
	char *urlbase;
	char *srcurl;
	FILE *in,*out;
	char *env;

	in = stdin;
	out = stdout;

	if( env = getenv("HTTP_CONTENT_TYPE") )
		ctype = env;
	else	ctype = "text/html";

	charsets[0] = "cc=jp&cp=n";
	charsets[1] = NULL;

	urlbase = "";
	srcurl = "";

	if( getenv("HTTP_USER_AGENT") == NULL )
		putenv("HTTP_USER_AGENT=");

	while( fgets(any_text,sizeof(any_text),in) != NULL ){
		CII_toCII(any_text,cii_text,ctype,charsets,urlbase,srcurl);
		CII_toData(cii_text);
		fputs(cii_text,out);
	}
}

CII_toData(PVStr(cii_text))
{	refQStr(url,cii_text);
	CStr(urlb,0x1000);
	CStr(gifb,0x1000);
	char *sp;
	char *dp;
	CStr(b64,0x1000);
	CStr(buf,0x1000);
	int len;

	url = cii_text;
	while( url = strstr(url,"SRC=") ){
		url += 4;
		if( *url == '"' )
			url++;
		dp = urlb;
		for( sp = url; *sp; sp++ ){
			if( *sp == '"' )
				break;
			*dp++ = *sp;
		}
		*dp = 0;

		len = CII_getGIF(urlb,gifb);
		if( 0 < len ){
			strcpy(buf,sp);

			str_to64(gifb,len,b64,sizeof(b64),1);
			if( url_oneline ){
				dp = b64;
				for( sp = b64; *sp; sp++ )
					if( *sp != '\n' && *sp != '\r' )
						*dp++ = *sp;
				*dp = 0;
			}
			sprintf(url,"%sdata:image/gif;base64,%s%s",
				data_proxy,b64,buf);
		}
	}
}
