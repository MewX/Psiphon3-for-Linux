/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	shio.o (sh I/O)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	Usage:	shio scriptfile
		shio scriptfile:label

MASTER=${MASTER}
TUNNEL=type:script
TUNNEL=tty7:/usr/local/etc/delegate.login

History:
	940730	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"

int shio_debug = 0;

static void Dprintf(PCStr(fmt),...)
{
	if( shio_debug ){
		VARGS(8,fmt);
		fprintf(stderr,fmt,VA8);
	}
}
/*
static void Fprintf(FILE *fp,PCStr(fmt),...)
{
	VARGS(3,fmt);
	fprintf(fp,fmt,va[0],va[1],va[2]);
	fflush(fp);
	Dprintf("<= ");
	Dprintf(fmt,va[0],va[1],va[2]);
}
*/

/*
if( env = getenv("MASTER") )
SPRINTF(args+strlen(args)," MASTER=%s",env);
*/

static const char **script_buf;

void shiobar1(const char *script[]);
void shiobar(PCStr(script)/*,char *id*/)
{	FILE *Script;
	int si;
	CStr(line,1024);
	CStr(dline,1024);
	const char *sp;
	refQStr(dp,dline); /**/
	CStr(xscript,1024);

	if( fullpathLIB(script,"r",AVStr(xscript)) )
		script = xscript;
	Script = fopen(script,"r");
	if( Script == NULL ){
		fprintf(stderr,"cannot open:%s\n",script);
		exit(-1);
	}

	if( script_buf == NULL )
		script_buf = (const char**)calloc(512,sizeof(char*));

	si = 0;
	while( fgets(line,sizeof(line),Script) != NULL ){
		if( *line == '#' || *line == '\n' )
			continue;
		if( *line == ':' )
			continue;

		dp = dline;
		for( sp = line; *sp; sp++ ){
			if( *sp == '\n' && sp[1] == 0 )
				break;
			if( *sp == '\\' ){
				switch( sp[1] ){
				    case 'n': setVStrPtrInc(dp,'\n'); break;
				    case 'r': setVStrPtrInc(dp,'\r'); break;
				    default:  setVStrPtrInc(dp,sp[1]); break;
				}
				sp += 1;
			}else	setVStrPtrInc(dp,*sp);
		}
		setVStrEnd(dp,0);
		script_buf[si++] = stralloc(dline);
	}
	shiobar1(script_buf);
}

void loginproc(const char *script[],int in,int out);
void shiobar1(const char *script[])
{	int tocu[2],fromcu[2];

	if( script[0][0] == 'c' ){
		DGCTX Conn = MainConn();
		CStr(host,MaxHostNameLen);
		int port,sock;
		port = scan_hostport1X(script[0]+2,AVStr(host),sizeof(host));
		sock = OpenServer("SHIO","tcprelay",host,port);
		loginproc(&script[1],sock,sock);
		return;
	}

	IGNRETZ pipe(tocu);
	IGNRETZ pipe(fromcu);
	if( vfork() == 0 ){
		close(fromcu[0]);
		close(tocu[1]);

		dup2(fromcu[1],2);
		dup2(fromcu[1],1);
		dup2(tocu[0],0);

		execl("/bin/sh","sh",(void*)0);
		exit(-1);
	}

	close(fromcu[1]);
	close(tocu[0]);
	loginproc(script,fromcu[0],tocu[1]);
}

static void put_file(FILE *out,PCStr(file))
{	FILE *fp;
	CStr(buff,1024);
	int rc;

	if( fp = fopen(file,"r") ){
		while( rc = fread(buff,1,sizeof(buff),fp) )
			fwrite(buff,1,rc,out);
	}
}
static void relay_blocks(int in,int out,int size)
{	CStr(buff,1024);
	int rc;

	if( fork() == 0 ){
		while( rc = read(in,buff,sizeof(buff)) ){
			fwrite(buff,1,rc,stdout);
			fflush(stdout);
		}
	}else{
		FILE *Out;
		Out = fdopen(out,"w");
		while( 0 < (rc = read(fileno(stdin),buff,sizeof(buff))) ){
			fwrite(buff,1,rc,Out);
			fflush(Out);
		}
	}
}
void xputs(PCStr(s));
void loginproc(const char *script[],int in,int out)
{	int si;
	const char *sl;
	const char *cp;
	int ch;
	int len;
	int ilen;
	CStr(inbuf,256);
	FILE *In,*Out;

	In = fdopen(dup(in),"r");
	setbuf(In,NULL);
	Out = fdopen(dup(out),"w");
	setbuf(Out,NULL);

	Dprintf(">> ");
	for(si = 0; sl = script[si]; si++){
		switch( sl[0] ){
			case 'b':
				relay_blocks(dup(in),dup(out),atoi(&sl[2]));
				break;

			case '=':
fclose(In);
fclose(Out);
				frelay(0,in,fileno(stdout),fileno(stdin),out,NULL);
exit(0);
				break;

			case 'o':
				if( si == 0 )
					Dprintf("%s",sl+2);
				fputs(sl+2,Out);
				break;
			case 'p':
				put_file(Out,sl+2);
				break;

			case 'm':
				msleep(atoi(sl+2));
				break;
			case 's':
				sleep(atoi(sl+2));
				break;

			case 'i':
			len = strlen(sl+2);
			ilen = 0;
			for(;;){
				ch = fgetc(In);
				if( ch == '\r' )
					Dprintf("^M");
				else	Dprintf("%c",ch);

				if( ch == '\n' )
					Dprintf(">> ");
				if( ch == EOF )
					break;

				if( len <= ilen ){
					ovstrcpy(inbuf,inbuf+1);
					setVStrElem(inbuf,ilen-1,ch); /**/
				}else	setVStrElemInc(inbuf,ilen,ch);/**/
				setVStrEnd(inbuf,ilen);

if( 2 <= shio_debug ){
Dprintf("[");
xputs(sl+1);
Dprintf("][");
xputs(inbuf);
Dprintf("]\n");
}
				if( len == ilen )
				if( strcmp(inbuf,sl+2) == 0 )
					break;
			}
			break;

			case '$':
				/* skip untill EOL */
				break;
		}
	}
}


void xputs(PCStr(s))
{
	while(*s){
		if(*s < 0x20)
			Dprintf("^%c",*s+0x40);
		else	Dprintf("%c",*s);
		s++;
	}
}

void gotsig(int sig)
{
	fprintf(stderr,"(%d done)\n",getpid());
/*
	Killpg(getpid(),SIGTERM);
*/
	killpg(getpid(),SIGTERM);
	exit(0);
}
int shio_main(int ac,const char *av[])
{	int ai;
	const char *arg;
	const char *script = 0;

	signal(SIGINT,gotsig);
	signal(SIGTERM,gotsig);

	if( isatty(0) )
		shio_debug = 1;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strncmp(arg,"-d",2) == 0 ){
			if( (shio_debug = atoi(arg+2)) == 0 )
				shio_debug = 1;
		}else	script = arg;
	}
	if( script == 0 ){
		fprintf(stderr,"Usage: %s script-file\n",av[0]);
		exit(-1);
	}
	shiobar(script);
	return 0;
}
