/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	remote.c (delegated invocation from remote hosts)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960606	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#define RHOSTS	".rhosts.delegate"

static int _fromRsh;

#define IS_SSH -2
int fromRsh();
int fromSSH(){
	if( fromRsh() )
		return 0;
	return _fromRsh == IS_SSH;
}

int fromRsh()
{	int hosti,porti,hosto,porto;

	if( 0 < _fromRsh ) return 1;
	if( 0 > _fromRsh ) return 0;

	_fromRsh = -1;

	if( getenv("HOME") == NULL ) return 0;
	if( getenv("SHELL") == NULL ) return 0;

	if( file_issock(0) < 0 ) return 0;
	if( file_issock(1) < 0 ) return 0;

	if( getenv("SSH_CONNECTION") != 0 ){
		if( sock_isAFUNIX(0)
		 || sockFromMyself(0)
		 || sock_isconnectedX(0,0)
		){
			_fromRsh = IS_SSH;
			return 0;
		}
	}

/*
	if( file_issock(2) < 0 ) return 0;
*/
{
	int hostl,portl;
	hostl = sockHostport(0,&portl);
	/*
	 * If this DeleGate is invoked from rshd, the port number must be
	 *   shell(cmd) == 514/tcp
	 */
	if( portl != 514 ){
		return 0;
	}
	/*
	 * Now this DeleGate might be working as a proxy rsh daemon.
	 * It can be detected by peeking the first packet in rsh
	 * protocol which will  be a port number string in ASCII
	 * terminated with '\0'.
	 */
	if( 0 < PollIn(0,100) ){
		int rcc,ci;
		CStr(buf,8);
		rcc = recvPeekTIMEOUT(0,AVStr(buf),7);
		if( 0 < rcc )
		if( buf[rcc-1] == '\0' )
		if( isdigits(buf) ){
			return 0;
		}
	}
}

	hosti = peerHostport(0,&porti);
	if( hosti == -1 || porti<0 || porti<512 || 1023<porti )
		return 0;
	hosto = peerHostport(1,&porto);
	if( hosto == -1 || porto<0 || porto<512 || 1023<porto )
		return 0;
	if( hosti != hosto )
		return 0;

	_fromRsh = 1;
	return 1;
}

int authRsh(/*int *bg*/)
{	const char *home;
	CStr(path,1024);
	FILE *fp;
	CStr(paddr,1024);
	CStr(saddr,1024);
	CStr(line,1024);
	CStr(hosts,1024);
	CStr(phost1,1024); /* client's host */
	const char *paddr1;
	CStr(shost1,1024); /* server's host (optional) */
	const char *saddr1;
	int ok;

	if( (home = getenv("HOME")) == NULL ){
		fprintf(stderr,"Permission denied: no $HOME set\n");
		return -1;
	}

	sprintf(path,"%s/%s",home,RHOSTS);
	fp = fopen(path,"r");
	if( fp == NULL ){
		fprintf(stderr,"Permission denied: no %s\n",RHOSTS);
		return 1;
	}

	getpeerAddr(0,AVStr(paddr));
	gethostAddr(0,AVStr(saddr));

	ok = 0;
	while( fgets(line,sizeof(line),fp) ){
		wordScan(line,hosts);
		if( hosts[0] == 0 )
			continue;
		phost1[0] = shost1[0] = 0;
		if( Xsscanf(hosts,"%[^:]:%s",AVStr(phost1),AVStr(shost1)) < 1 )
			continue;

		if( phost1[0] && strcmp(phost1,"*") != 0 ){
			if( (paddr1 = gethostaddr(phost1)) == NULL )
				continue;
			if( strcmp(paddr,paddr1) != 0 )
				continue;
		}
		if( shost1[0] && strcmp(shost1,"*") != 0 ){
			if( (saddr1 = gethostaddr(shost1)) == NULL )
				continue;
			if( strcmp(saddr,saddr1) != 0 )
				continue;
		}
		ok = 1;
		break;
	}
	fclose(fp);
	if( ok ){
		return 0;
	}else{
		fprintf(stderr,"Permission denied: not in %s\n",RHOSTS);
		return -1;
	}
}

void serverControl(FILE *in,FILE *out);
void RshWatcher(int ninvoke,int port){
	/* echo dynamically allocated PORT number */
	/* fprintf(stdout,"%d\n",port); */

	/* if( foreground ) */
	if( ninvoke == 0 ){
		CStr(host,MaxHostNameLen);
		getpeerNAME(0,AVStr(host));
		proc_title("delegated/rsh/%s",host);

		if( Fork("RshWatcher") == 0 ){
			serverControl(stdin,stdout);
			_Finish(0);
		}
	}else{
		fprintf(stderr,"\r\nRESTARTED\r\n> ");
		fflush(stderr);
	}

	/*
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	*/
}

void serverControl(FILE *in,FILE *out)
{	CStr(line,1024);

	fprintf(out,"[enter q to kill the daemon]\r\n");
	for(;;){
		fprintf(out,"> ");
		fflush(out);
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		fputs(line,out);
		if( line[0] == 'q' )
			break;
		if( line[0] == 'h' || line[0] == '?' )
			fprintf(out,"[enter q to kill the daemon]\r\n");
	}
	Kill(getppid(),SIGTERM);
}
int stop_server(FILE *dst)
{	int rcode;
	CStr(msg,1024);

	rcode = Kill(getppid(),SIGTERM);
	sprintf(msg,"kill() = %d\r\n",rcode);
	fputs(msg,dst);
	return strlen(msg);
}

int fromInetd()
{	int iss0,iss1;

	if( isatty(0) || isatty(1) || file_isreg(0) || file_isreg(1) )
		return 0;

	if( fromRsh() )
		return 0;
	if( _fromRsh == IS_SSH ){
		return 0;
	}

	iss0 = file_issock(0);
	iss1 = file_issock(1);
	if( 0 < iss0 && 0 < iss1 ){
		if( sockPort(1) <= 1 )
			return 0;
		return 1;
	}
	return 0;
}
