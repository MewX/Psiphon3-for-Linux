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
Program:	urlfind.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940824	created
TODO:
	must be merged into dget.c
	must check recursion using MD5
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"

static const char *usage = "\
Usage: urlfind URL\n\
    -- Find recursively in URL space.\n\
";
static const char *arg1spec = "\
Argument specification error:\n\
   The first argument should be URL as follows:\n\
      protocol://host\n\
      protocol://host:port\n\
      protocol://host/path\n\
      protocol://host:port/path\n\
";

static void pull_url1(PCStr(url));
int urlfind_main(int ac,const char *av[])
{
	if( ac < 2 ){
		fprintf(stderr,"%s",usage);
		exit(1);
	}
	pull_url1(av[1]);
	return 0;
}

static struct { defQStr(lastURL); } lastURL;
static void http1(int svsock,PCStr(proto),PCStr(host),int port,PCStr(path));

static void pull_url1(PCStr(url))
{	CStr(proto,1024);
	CStr(hostport,1024);
	CStr(host,1024);
	CStr(path,1024);
	int port;
	int svsock;
	CStr(url1,1024);

	path[0] = 0;
	if( Xsscanf(url,"%[^:]://%[^/]%s",AVStr(proto),AVStr(hostport),AVStr(path)) < 2 ){
		fprintf(stderr,"%s",arg1spec);
		exit(1);
	}
	if( strchr(path,'#') )
		return;

	if( strcmp(proto,"http") != 0 ){
		fprintf(stderr,"Only protocol `http' is supported, sorry.\n");
		exit(1);
	}
	if( Xsscanf(hostport,"%[^:]:%d",AVStr(host),&port) != 2 )
		port = serviceport(proto);

	sprintf(url1,"%s://%s/%s",proto,hostport,path[0]=='/'?path+1:path);
	if( lastURL.lastURL == 0 )
		setQStr(lastURL.lastURL,(char*)StructAlloc(1024),1024);

	if( strcmp(url1,lastURL.lastURL) == 0 )
		return;
	strcpy(lastURL.lastURL,url1);

	fprintf(stderr,"%s ",url1);
	fflush(stderr);

	svsock = client_open("URLFIND",proto,host,port);
	if( svsock <= 0 ){
		fprintf(stderr,"Error: cannot connect to the server.\n");
		exit(1);
	}
	http1(svsock,proto,host,port,path);
}

static void url1(PCStr(url),PCStr(base),FILE *urlfp)
{	CStr(xurl,4096);
	const char *bp;
	const char *dp;

	if( strncmp(url,"http:",5) == 0 )
	if( url[5] != '/' )
		url += 5;
	if( strncmp(url,"./",2) == 0 )
		url += 2;

	if( dp = strstr(url,"..") )
	if( dp[2] == 0 || dp[2] == '/' )
	if( dp == url || dp[-1] == '/' )
		return;

	xurl[0] = 0;
	if( strchr(url,':') == 0 ){
		strcpy(xurl,base);
		if( bp = strrchr(xurl,'/') )
			((char*)bp)[1] = 0;
	}
	strcat(xurl,url);

	if( strncmp(xurl,base,strlen(base)) == 0 )
		fprintf(urlfp,"%s\n",xurl);
}
static void http1(int svsock,PCStr(proto),PCStr(host),int port,PCStr(path))
{	FILE *fs,*ts;
	FILE *urlfp;
	CStr(request,1024);
	CStr(resp,1024);
	CStr(xline,4096);
	const char *url;
	CStr(type,256);
	int leng;
	CStr(hostport,MaxHostNameLen);
	CStr(base,1024);

	HostPort(AVStr(hostport),proto,host,port);
	sprintf(base,"%s://%s/%s",proto,hostport,path[0]=='/'?path+1:path);

	ts = fdopen(svsock,"w");
	fs = fdopen(svsock,"r");

	sprintf(request,"GET %s HTTP/1.0\r\n\r\n",path[0]?path:"/");
	fputs(request,ts);
	fflush(ts);

	if( fgets(resp,sizeof(resp),fs) == NULL ){
		fprintf(stderr,"[NULL]\n");
		goto xERR;
	}

	if( strncmp(resp,"HTTP/1.",7) != 0 ){
		fprintf(stderr,"[NON-HTTP/1.X]\n");
		goto xERR;
	}

	type[0] = 0;
	leng = 0;
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		const char *dp;

		if( dp = strpbrk(resp,"\r\n") )
			truncVStr(dp);
		if( dp == resp )
			break;

		if( strncasecmp("Content-Type:",resp,12) == 0 )
			Xsscanf(resp,"%*s %[^;\r\n]",AVStr(type));
		else
		if( strncasecmp("Content-Length:",resp,13) == 0 )
			sscanf(resp,"%*s %d",&leng);
	}
	fprintf(stderr,"[%s][%d]\n",type,leng);
	fflush(stderr);
	if( strcmp(type,"text/html") != 0 )
		goto xERR;

	urlfp = (FILE*)tmpfile();
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		url_absolute("-.-",proto,host,port,"",resp,AVStr(xline),VStrNULL);
		scan_url(xline,(iFUNCP)url1,base,urlfp);
	}
	fclose(ts);
	fclose(fs);
	fflush(urlfp);
	fseek(urlfp,0,0);
	{	CStr(url,1024);
		const char *np;

		while( fgets(url,sizeof(url),urlfp) != NULL ){
			if( np = strpbrk(url,"\r\n") )
				truncVStr(np);
			pull_url1(url);
		}
	}
	fclose(urlfp);
	return;
xERR:
	fclose(ts);
	fclose(fs);
}
