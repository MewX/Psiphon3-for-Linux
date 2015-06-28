/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	inetd.c (inetd like server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
    inetd.conf:
	service-name	"-" or <119> or <host:119>
	socket-type	"-" or "stream" or "dgram"
	protocol	"-" or "tcp" or "udp"
	wait-status	"-" or "wait" or "nowait" (wait is not supported yet)
	uid		"-" or <username> or <8715>
	server-program	"-" or </path/of/the/program>
	server-arguments

EXTENSION:
	service-name	proto://host:port ????
	uid		user/group
	server-program	quotation by <"> like "/Program Files/xxx/yyy.exe"

History:
	980525	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdlib.h>
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"
void packComArg(PVStr(command),PCStr(execpath),PCStr(args));
int scanServPort1(PCStr(portspec));

static const char *usage[] = {
"Usage: INETD=\"port stream tcp nowait user path args\"   -- external command",
"       INETD=\"port - - - - - parameters\"  -- exec DeleGate with parameters",
"       INETD=+=/path/of/inetd.conf             -- read config. from a file",
0};

typedef struct {
  const	char	*i_conf;
  const	char	*i_host;
	int	 i_port;
	int	 i_udp;
  const	char	*i_User;
  const	char	*i_Path;
  const	char	*i_args;
  const	char   **i_argv;
} InetdConf;

typedef struct {
	InetdConf *ie_inetdtab[32]; /**/
	int	ie_inetdN;
} InetdEnv;
static InetdEnv *inetdEnv;
#define inetdtab	inetdEnv->ie_inetdtab
#define inetdN		inetdEnv->ie_inetdN
void minit_inetd()
{
	if( inetdEnv == 0 )
		inetdEnv = NewStruct(InetdEnv);
}

int func_inetd(void *Conn,int clsock)
{	int ix;
	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	int port;
	CStr(clhost,MaxHostNameLen);
	int clport;
	int ai,found;
	InetdConf *ic;
	const char *arg;
	CStr(command,1024);
	CStr(argbuf,1024);
	int params;
	int isudp;

	minit_inetd();

	if( inetdN == 0 )
		return 0;

	gethostName(clsock,AVStr(hostport),"%A:%P");
	isudp = isUDPsock(clsock);
	Xsscanf(hostport,"%[^:]:%d",AVStr(host),&port);

	found = 0;
	for( ix = 0; ix < inetdN; ix++ ){
		ic = inetdtab[ix];
		if( ic->i_host[0] == 0 || hostcmp(ic->i_host,host) == 0 )
		if( ic->i_port == port )
		if( ic->i_udp == isudp ){
			found = 1;
			break;
		}
	}

	if( !found ){
		sv1log("### ACCEPT PORT=%s:%d ? NO INETD CONF\n",host,port);
		return 0;
	}

	params = 0;
	for( ai = 0; arg = ic->i_argv[ai]; ai++ ){
		sv1log("INETD PARAM[%d] %s\n",ai,arg);
		DELEGATE_addEnvExt(arg);
		params++;
	}

	if( !streq(ic->i_User,"-") ){
		sprintf(argbuf,"OWNER=%s",ic->i_User);
		DELEGATE_addEnvExt(argbuf);
		params++;
	}

	if( ic->i_Path[0] != '-' ){
		DELEGATE_addEnvExt("SERVER=exec");
		packComArg(AVStr(command),ic->i_Path,ic->i_args);
		sprintf(argbuf,"XCOM=%s",command);
		DELEGATE_addEnvExt(argbuf);
		sv1log("SERVER=exec \"%s\"\n",argbuf);
		params++;
	}

	return params;
}

void scan_INETD(DGC*Conn,PCStr(confarg))
{	CStr(servname,128);
	CStr(socktype,128);
	CStr(protocol,128);
	CStr(waitstat,128);
	CStr(uid,128);
	CStr(program,1024);
	CStr(path,1024);
	CStr(args,1024);
	CStr(argb,1024);
	const char *av[128]; /**/
	CStr(host,MaxHostNameLen);
	int port;
	CStr(conf,1024);
	const char *dp;
	InetdConf *ic;
	int ac,ai;
	int ci;

	minit_inetd();

	if( strncmp(confarg,"+=",2) == 0 )
		return;

	strcpy(conf,confarg);
	if( dp = strchr(conf,'#') )
		truncVStr(dp);
	for( dp = conf; *dp; dp++ )
		if( *dp != ' ' && *dp != '\t' )
			break;
	if( dp != conf )
		strcpy(conf,dp);
	if( *conf == 0 )
		return;

	/* fprintf(stderr,"INETD=\"%s\"\n",confarg); */

	for( ci = 0; ci < inetdN; ci++ )
		if( streq(inetdtab[ci]->i_conf,conf) )
			return;

	if( elnumof(inetdtab) <= inetdN ){
		return;
	}

	if( Xsscanf(conf,"%s %s %s %s %s %[^\r\n]",AVStr(servname),AVStr(socktype),AVStr(protocol),AVStr(waitstat),AVStr(uid),AVStr(program)) < 6 ){
		fprintf(stderr,"WRONG inetd.conf format: INETD=%s\r\n",conf);
		fprintf(stderr,"%s\r\n",usage[0]);
		fprintf(stderr,"%s\r\n",usage[1]);
		fprintf(stderr,"%s\r\n",usage[2]);
		exit(-1);
	}
	if( streq(servname,"-") ) printPrimaryPort(AVStr(servname));
	if( streq(socktype,"-") ) strcpy(socktype,"stream");
	if( streq(protocol,"-") ) strcpy(protocol,"tcp");
	if( streq(waitstat,"-") ) strcpy(waitstat,"nowait");

	if( streq(protocol,"udp") )
		strcat(servname,"/udp");
	scanServPort1(servname);

	ic = (InetdConf*)calloc(1,sizeof(InetdConf));
	inetdtab[inetdN++] = ic;

	ic->i_conf = stralloc(conf);

	if( strchr(servname,':') ){
		port = 0;
		Xsscanf(servname,"%[^:]:%d",AVStr(host),&port);
		ic->i_host = stralloc(host);
		ic->i_port = port;
	}else{
		ic->i_host = stralloc("");
		ic->i_port = atoi(servname);
	}
	ic->i_udp = streq(protocol,"udp");
	ic->i_User = stralloc(uid);

	av[0] = av[1] = "";
/*
	decomp_args(av,2,program,AVStr(argb));
*/
	decomp_args(av,3,program,AVStr(argb));
	ic->i_Path = stralloc(av[0]);
if( av[1] == 0 ) av[1] = "";
	ic->i_args = stralloc(av[1]);
	ac = decomp_args(av,128,ic->i_args,AVStr(argb));
	ic->i_argv = dupv(av,0);
}

