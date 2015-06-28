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
Program:	pop.c (POP proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941008	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "yarg.h"
#include "ystring.h"
#include "fpoll.h"
#include "delegate.h"
#include "param.h"
#include "filter.h"
#include "file.h"
#include "auth.h"
#include "proc.h"

#define LNSIZE 1024

int POPlistmax = 30;
static scanListFunc scan1(PCStr(conf),Connection *Conn){
	CStr(nam,128);
	CStr(val,2048);

	fieldScan(conf,nam,val);
	if( streq(nam,"listmax") ){
		POPlistmax = atoi(val);
	}
	return 0;
}
void scan_POPCONF(Connection *Conn,PCStr(conf)){
	scan_commaListL(conf,0,scanListCall scan1,Conn);
}

static int putget(int xcode,FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(fmt),...)
{	CStr(req,LNSIZE);
	VARGS(4,fmt);

	if( fmt != NULL ){
		sprintf(req,fmt,VA4);
		strcat(req,"\r\n");
		if( strncasecmp(req,"PASS",4) == 0 )
			syslog_ERROR(">> PASS ****\n");
		else	syslog_ERROR(">> %s",req);
		fputs(req,ts);
		fflush(ts);
	}
	if( fgets(resp,rsize,fs) == NULL ){
		if( xcode < 0 )
			Finish(xcode);
		else	return xcode;
	}
	syslog_ERROR("<< %s",resp);
	if( resp[0] != '+' ){
		if( xcode < 0 )
			Finish(xcode);
		else	return xcode;
	}
	return 0;
}

typedef struct {
  const	char	*name;
	int	 resp;
} CommandSpec;

#define NULL_BODY	0
#define WITH_BODY	1
#define IN_RFC822	2
#define RESPFLAGS	(WITH_BODY|IN_RFC822)
#define NULL_BODY_IFARG	4

static CommandSpec pop_command[] = {
	/* MINIMAL POP3 COMMANDS */
	{ "USER"},
	{ "PASS"},
	{ "QUIT"},
	{ "STAT"},
	{ "LIST", WITH_BODY|NULL_BODY_IFARG },
	{ "RETR", WITH_BODY|IN_RFC822 },
	{ "DELE"},
	{ "NOOP"},
	{ "RSET"},

	/* OPTIONAL POP3 COMMANDS */
	{ "APOP"},
	{ "UIDL", WITH_BODY|NULL_BODY_IFARG },
	{ "TOP",  WITH_BODY|IN_RFC822 },
	{ "AUTH", WITH_BODY|NULL_BODY_IFARG },
	{ "CAPA", WITH_BODY },

	/* private extension ? */
	{ "LAST"},
	{ "RPOP"},
	0
};

static int openARTICLE(FILE *ts,FILE *fs,int anum,PVStr(resp))
{
	fprintf(ts,"ARTICLE %d\r\n",anum);
	fflush(ts);
	fgets(resp,LNSIZE,fs);
	if( atoi(resp) != 220 )
		return -1;
	else	return 0;
}
static int skipmsg(FILE *fs)
{	CStr(line,LNSIZE);
	int size;

	size = 0;
	while( fgets(line,sizeof(line),fs) != NULL ){
		if( line[0] == '.' && line[1] == '\r' )
			break;
		size += strlen(line);
	}
	return size;
}
static void msguid(FILE *fs,PVStr(uid))
{
	msgMD5(fs,NULL,(char*)uid);
}
static void top(FILE *fs,FILE *tc,int lines)
{	CStr(line,LNSIZE);
	int size;
	int li;

	size = 0;
	for(;;){
		if( fgets(line,sizeof(line),fs) == NULL )
			return;
		if( line[0] == '.' && line[1] == '\r' )
			return;
		fputs(line,tc);
		size += strlen(line);
		if( line[0] == '\r' || line[0] == '\n' )
			break;
	}
	for( li = 0; li < lines; li++ ){
		if( fgets(line,sizeof(line),fs) == NULL )
			break;
		if( line[0] == '.' && line[1] == '\r' )
			return;
		fputs(line,tc);
		size += strlen(line);
	}
	skipmsg(fs);
}
static void putclient(FILE *tc,PCStr(fmt),...)
{	CStr(xfmt,LNSIZE);
	VARGS(8,fmt);

	fprintf(tc,fmt,VA8);
	strcpy(xfmt,"D-C ");
	strcat(xfmt,fmt);
	Verbose(xfmt,VA8);
}
void nntp_via_pop(Connection *Conn,PCStr(url),FILE *fc,FILE *tc)
{	CStr(proto,LNSIZE);
	CStr(host,LNSIZE);
	CStr(port,LNSIZE);
	CStr(group,LNSIZE);
	int ni,porti;
	FILE *ts,*fs,*tmp;
	CStr(line,LNSIZE);
	CStr(com,LNSIZE);
	const char *ap;
	CStr(arg,LNSIZE);
	CStr(resp,LNSIZE);
	refQStr(rp,resp); /**/
	int arts,min,max;
	int anum;
	int size,lines;
	CStr(uid,LNSIZE);

	ni = scan_protositeport(url,AVStr(proto),AVStr(host),AVStr(port));
	if( ni < 2 ){
		fprintf(tc,"-ERR\r\n");
		return;
	}
	porti = 119;
	if( ni == 3 ){
		porti = atoi(port);
		if( porti == 0 )
			porti = 119;
	}
	if( Xsscanf(url,"nntp://%*[^/]/%s",AVStr(group)) <= 0 ){
		fprintf(tc,"-ERR\r\n");
		return;
	}

	set_realserver(Conn,"nntp",host,porti);
	Conn->no_dstcheck_proto = serviceport("nntp");
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
		fprintf(tc,"-ERR\r\n");
		return;
	}
	fs = fdopen(FromS,"r");
	ts = fdopen(ToS,"w");

	rp = resp;
	if( fgets(rp,sizeof(resp),fs) == NULL ){
		fprintf(tc,"-ERR gatewaying to NNTP server: closed\r\n");
		return;
	}

	rp = strchr(rp,'\r');
	strcpy(rp," // ");
	rp += strlen(rp);

	fprintf(ts,"MODE READER\r\n");
	fflush(ts);
	fgets(rp,sizeof(resp),fs);

	fprintf(ts,"GROUP %s\r\n",group);
	fflush(ts);
	fgets(rp,sizeof(resp),fs);

	if( atoi(rp) != 211 ){
		putclient(tc,"-ERR gatewaying to NNTP serveri // %s",resp);
		return;
	}
	putclient(tc,"+OK gatewaying to NNTP server // %s",resp);
	sscanf(rp,"211 %d %d %d",&arts,&min,&max);
	sv1log("GROUP %d %d %d %s\n",arts,min,max,group);
	if( POPlistmax ){
		if( POPlistmax < max - min ){
			min = max - POPlistmax;
			sv1log("POPlistmax=%d %d-%d\n",POPlistmax,min,max);
		}
	}

	tmp = TMPFILE("NNTP/POP");

	for(;;){
		fflush(tc);
		if( fgets(line,sizeof(line),fc) == NULL ){
			Verbose("C-S EOF\n");
			break;
		}
		if( strncasecmp(line,"PASS ",5) == 0 )
			Verbose("C-S PASS ****\n");
		else	Verbose("C-S %s",line);

		ap = wordScan(line,com);
		lineScan(ap,arg);
		if( strcaseeq(com,"PASS") ){
			putclient(tc,"+OK %s has %d message(s)\r\n",group,arts);
		}else
		if( strcaseeq(com,"QUIT") ){
			putclient(tc,"+OK NNTP/POP gateway signing off.\r\n");
			break;
		}else
		if( strcaseeq(com,"STAT") ){
			putclient(tc,"+OK %d %d\r\n",arts,arts*10000);
		}else
		if( strcaseeq(com,"LIST") ){
			if( arg[0] ){
				anum = atoi(arg);
				if( openARTICLE(ts,fs,anum,AVStr(resp)) == 0 ){
					size = skipmsg(fs);
					putclient(tc,"+OK %d %d\r\n",anum,size);
				}else	putclient(tc,"+ERR %s",resp);
			}else{
				putclient(tc,"+OK %d messages (%d octet)\r\n",
					arts,arts*10000);

				for( anum = min; anum <= max; anum++ )
				if( openARTICLE(ts,fs,anum,AVStr(resp)) == 0 ){
					size = skipmsg(fs);
					putclient(tc,"%d %d\r\n",anum,size);
					if( anum % 10 == 0 )
						fflush(tc);
				}
				putclient(tc,".\r\n");
			}
		}else
		if( strcaseeq(com,"UIDL") ){
			if( arg[0] ){
				anum = atoi(arg);
				if( openARTICLE(ts,fs,anum,AVStr(resp)) == 0 ){
					msguid(fs,AVStr(uid));
					putclient(tc,"+OK %d %s\r\n",anum,uid);
				}else	putclient(tc,"+ERR %s",resp);
			}else{
				putclient(tc,"+OK %d messages (%d octet)\r\n",
					arts,arts*10000);

				for( anum = min; anum <= max; anum++ )
				if( openARTICLE(ts,fs,anum,AVStr(resp)) == 0 ){
					msguid(fs,AVStr(uid));
					putclient(tc,"%d %s\r\n",anum,uid);
					if( anum % 10 == 0 )
						fflush(tc);
				}
				putclient(tc,".\r\n");
			}
		}else
		if( strcaseeq(com,"RETR") ){
			anum = atoi(arg);
			if( openARTICLE(ts,fs,anum,AVStr(resp)) != 0 )
				putclient(tc,"-ERR %s",resp);
			else{
				fseek(tmp,0,0);
				PGPdecodeMIME(fs,tmp,NULL,0x7,1,0);
				fflush(tmp); Ftruncate(tmp,0,1);
				fseek(tmp,0,0);
				size = file_size(fileno(tmp));
				putclient(tc,"+OK %d octets\r\n",size);
				copyfile1(tmp,tc);
				putclient(tc,".\r\n");
			}
		}else
		if( strcaseeq(com,"DELE") ){
			putclient(tc,"-ERR forbidden\r\n");
		}else
		if( strcaseeq(com,"NOOP") ){
			putclient(tc,"+OK\r\n");
		}else
		if( strcaseeq(com,"RSET") ){
			putclient(tc,"+OK no effect\r\n");
		}else
		if( strcaseeq(com,"TOP") ){
			lines = 0;
			if( sscanf(arg,"%d %d",&anum,&lines) < 1 ){
				putclient(tc,"-ERR arg count.\r\n");
			}else
			if( openARTICLE(ts,fs,anum,AVStr(resp)) != 0 )
				putclient(tc,"-ERR %s",resp);
			else{
				fseek(tmp,0,0);
				top(fs,tmp,lines);
				fflush(tmp); Ftruncate(tmp,0,1);
				fseek(tmp,0,0);
				size = file_size(fileno(tmp));
				putclient(tc,"+OK %d octets\r\n",size);
				copyfile1(tmp,tc);
				putclient(tc,".\r\n");
			}
		}else{
			putclient(tc,"-ERR unknown command [%s]\r\n",com);
		}
	}
}

static int checkPASS(Connection *Conn,PCStr(opts),PCStr(epass),PCStr(seed),FILE *fc,FILE *tc,PVStr(resp))
{	const char *pp;
	CStr(pass,LNSIZE);
	CStr(upass,LNSIZE);
	CStr(xpass,LNSIZE);
	CStr(mpass,LNSIZE);
	CStr(line,LNSIZE);
	CStr(com,LNSIZE);
	const char *vp;

	if( pp = strstr(opts,"apop=") ){
		if( *epass == 0 ){
			if( strstr(opts,"pass=") == NULL ){
				sprintf(resp,"-ERR APOP only\r\n");
				return -1;
			}
		}else{
			Xsscanf(pp+5,"%[^ \t\r\n,]",AVStr(pass));
			sprintf(xpass,"%s%s",seed,pass);
			toMD5(xpass,mpass);
			if( strcmp(mpass,epass) != 0 ){
				sprintf(resp,"-ERR wrong password\r\n");
				return -2;
			}
			return 0;
		}
	}
	if( pp = strstr(opts,"pass=") ){
		Xsscanf(pp+5,"%[^ \t\r\n,]",AVStr(pass));
		fprintf(tc,"+OK password required\r\n");
		fflush(tc);
		if( fgets(line,sizeof(line),fc) == NULL )
			return -1;
		vp = wordScan(line,com);
		lineScan(vp,upass);
		if( strcmp(pass,upass) != 0 ){
			sprintf(resp,"-ERR wrong password\r\n");
			return -3;
		}
	}
	return 0;
}
static int mount1(int *with,PCStr(src),PCStr(proto),PCStr(user),PCStr(pass),PCStr(hostn),PCStr(iport),PCStr(path),PCStr(opts))
{
	if( strstr(opts,"apop=") ){
		*with = 1;
		return 1;
	}
	return 0;
}

void service_pop1(Connection *Conn,PCStr(user),PVStr(nextUSER));

static int withAPOP(Connection *Conn)
{	int with;
	CStr(dom,128);
	with = 0;

	if( withAuthDigest(Conn,AVStr(dom)) )
		return 1;
	CTX_scan_mtab(Conn,(iFUNCP)mount1,&with);
	return with;
}

const char *POP_USERHOST_DELIMITER = "*%#";
const char *POP_USERHOST_ESCDELIM = "*%"; /* escaped "@" for chained proxies */
static int change_server(Connection *Conn,FILE *fc,FILE *tc,PCStr(auser),PCStr(epass),PCStr(seed),PVStr(nextUSER),PVStr(resp))
{	const char *dp;
	CStr(user,LNSIZE);
	CStr(hostport,LNSIZE);
	CStr(userhost,LNSIZE);
	CStr(host,LNSIZE);
	CStr(tmp,LNSIZE);
	const char *opts;
	int port;
	CStr(dom,128);
	CStr(proto,32);

	strcpy(proto,"pop");
	strcpy(userhost,auser);

	if( strchr(userhost,'@') == NULL )
	if( dp = strrpbrk(userhost,POP_USERHOST_DELIMITER) )
		*(char*)dp = '@';  /**//* from user%host1%host2 to user%host1@host2 */

	if( dp = strrchr(userhost,'@') ){
		QStrncpy(user,userhost,dp-userhost+1);
		wordScan(dp+1,hostport);
		if( (dp = strstr(hostport,"..")) && isdigits(dp+2) ){
			strsubst(QVStr(dp,hostport),"..",":");
		}
		if( streq(CLNT_PROTO,"pop3s") && (ClientFlags & PF_MITM_DO) ){
			strcpy(proto,"pop3s");
			ServerFlags |= (PF_SSL_IMPLICIT | PF_STLS_DO);
		}
		if( dp = strrpbrk(user,POP_USERHOST_ESCDELIM) )
			*(char*)dp = '@'; /**/
		sprintf(userhost,"//%s/%s",hostport,user);
	}
	if( withAuthDigest(Conn,AVStr(dom)) ){
		CStr(mpass,64);
		if( authAPOP(Conn,dom,auser,seed,AVStr(mpass)) != 0 ){
			sprintf(resp,"-ERR wrong username\r\n");
			return 0;
		}
		sv1log("APOP Digest pass = %s : %s\n",epass,mpass);
		if( !streq(mpass,epass) ){
			sprintf(resp,"-ERR wrong APOP password\r\n");
			return 0;
		}
	}
	opts = CTX_mount_url_to(Conn,NULL,"GET",AVStr(userhost));
	setMountOptions(FL_ARG,Conn,opts);
	/*
	MountOptions = opts;
	*/
	if( opts ){
		if( checkPASS(Conn,opts,epass,seed,fc,tc,AVStr(resp)) != 0 )
			return 0;
	}

	if( strncasecmp(userhost,"nntp:",5) == 0 ){
		Conn->no_dstcheck_proto = serviceport("nntp");
		nntp_via_pop(Conn,userhost,fc,tc);
		return 1;
	}
	if( strncasecmp(userhost,"pop:",4) == 0 ){
		strcpy(tmp,userhost+4);
		strcpy(userhost,tmp);
	}
	if( strncasecmp(userhost,"pop3s:",6) == 0 ){
		strcpy(tmp,userhost+6);
		strcpy(userhost,tmp);
		strcpy(proto,"pop3s");
		ServerFlags |= (PF_SSL_IMPLICIT | PF_STLS_DO);
	}
	if( Xsscanf(userhost,"//%[^/]/%s",AVStr(hostport),AVStr(user)) == 2 ){
		/*
		port = scan_hostportX("pop",hostport,AVStr(host),sizeof(host));
		set_realserver(Conn,"pop",host,port);
		*/
		port = scan_hostportX(proto,hostport,AVStr(host),sizeof(host));
		set_realserver(Conn,proto,host,port);
		service_pop1(Conn,user,AVStr(nextUSER));
		return 1;
	} 
	return 0;
}

static int authAndConnect(Connection *Conn,FILE *fc,FILE *tc,PCStr(user),PCStr(pass),PVStr(req)){
	IStr(up,256);
	IStr(us,256);
	IStr(resp,256);
	IStr(serv,256);
	AuthInfo ident;
	FILE *xtc;
	int astat;

	bzero(&ident,sizeof(ident));
	sprintf(up,"%s:%s",user,pass);
	xtc = TMPFILE("POPauth");
	astat = doAUTH(Conn,0,xtc,"pop","-",0,AVStr(up),AVStr(serv),0,&ident);
	fclose(xtc);
	sv1log("--POP auth %s st=%X ty=%X {%s:%s}@{%s} ==> {%s:%s}@{%s} serv{%s}\n",
		astat==0?"OK":"NG",ident.i_stat,ident.i_stype,
		user,pass?"*":"",serv,ident.i_user,*ident.i_pass?"*":"",
		ident.i_Host,serv);
	if( astat != 0 ){
		fprintf(tc,"-ERR bad auth.\r\n");
		return -1;
	}

	if( (ident.i_stat & AUTH_FORW) == 0 )
	if( strneq(serv,"-man",4) ){
		IStr(userb,256);
		refQStr(sp,userb);
		clearVStr(serv);
		strcpy(userb,user);
		if( sp = strrchr(userb,'@') ){
			setVStrPtrInc(sp,0);
			strcpy(serv,sp);
			ident.i_stat |= AUTH_FORW;
			ident.i_stype = (AUTH_AORIGIN|AUTH_APROXY);
			strcpy(ident.i_user,userb);
			strcpy(ident.i_pass,pass);
			sv1log("--man/POP %s:%s@%s\n",user,pass[0]?"*":"",serv);

		}
	}
	if( ident.i_stat & AUTH_FORW )
	if( ident.i_stype == (AUTH_AORIGIN|AUTH_APROXY) ){
		sv1log("--POP auth FW\n");
		ClientAuth.i_stat = ident.i_stat;
		ClientAuth.i_stype = ident.i_stype;
		user = ident.i_user;
		pass = ident.i_pass;
		strcpy(ClientAuthUser,user);
		strcpy(ClientAuthPass,pass);
	}
	sv1log("--POP auth SV {%s:%s}@{%s}\n",user,*pass?"*":"",serv);
	sprintf(us,"%s@%s",user,serv);
	change_server(Conn,fc,tc,us,pass,serv,BVStr(req),AVStr(resp));
	return 0;
}

#define acceptSTLS(Conn) \
	((ClientFlags&PF_STLS_DO) && (ClientFlags&(PF_STLS_ON|PF_SSL_ON))==0)

int POP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc,PCStr(com),PCStr(arg));
static void ProxyPOP(Connection *Conn)
{	CStr(myhost,LNSIZE);
	CStr(banner,LNSIZE);
	FILE *tc,*fc;
	CStr(req,LNSIZE);
	CStr(com,LNSIZE);
	const char *vp;
	CStr(seed,LNSIZE);
	CStr(user,LNSIZE);
	CStr(pass,LNSIZE);
	CStr(resp,LNSIZE);
	int proxyLoggedin = 1;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");

	ClientIF_name(Conn,FromC,AVStr(myhost));
	sprintf(banner,"+OK Proxy-POP server (%s) at %s starting.",
		DELEGATE_version(),myhost);
	if( withAPOP(Conn) ){
		sprintf(seed,"<%d.%d@%s>",itime(0),getpid(),myhost);
		Xsprintf(TVStr(banner)," %s",seed);
	}
	strcat(banner,"\r\n");
	fputs(banner,tc);
	fflush(tc);

	if( CTX_withAuth(Conn) ){
		/* with AUTHORIZER, auth. before connect needed */
		proxyLoggedin = 0;
	}

	while( fgetsTIMEOUT(AVStr(req),sizeof(req),fc) != NULL ) GOT: {
		vp = wordScan(req,com);
		if( strcasecmp(com,"XECHO") == 0 ){
			lineScan(vp,resp);
			fprintf(tc,"%s\r\n",resp);
		}else
		if( strcaseeq(com,"CAPA") ){
			fputs("+OK Capability list follows\r\n",tc);
			if( !needSTLS(Conn) ){
				fputs("USER\r\n",tc);
				if( withAPOP(Conn) )
					fputs("APOP\r\n",tc);
			}
			if( acceptSTLS(Conn) ){
				fputs("STLS\r\n",tc);
			}
			fputs(".\r\n",tc);
		}else
		if( strcaseeq(com,"USER") || strcaseeq(com,"APOP") ){
			sv1log("POP C-S: %s",req);
			req[0] = 0;
			if( strcaseeq(com,"USER") ){
				wordScan(vp,user);
				pass[0] = 0;
				if( proxyLoggedin == 0 ){
					fprintf(tc,"+OK password please.\r\n");
					fflush(tc);
					continue;
				}
			}else{
				vp = wordScan(vp,user);
				wordScan(vp,pass);
			}
			resp[0] = 0;
			if( change_server(Conn,fc,tc,user,pass,seed,AVStr(req),AVStr(resp)) ){
				if( req[0] )
					goto GOT;
				else	break;
			}
			if( resp[0] )
				fputs(resp,tc);
			else
			fprintf(tc,"-ERR %s username@hostname is expected.\r\n",
				com);
		}else
		if( strcaseeq(com,"PASS") ){
			if( *vp == ' ' ) vp++;
			Xsscanf(vp,"%[^\r\n]",AVStr(pass));
			authAndConnect(Conn,fc,tc,user,pass,AVStr(req));
			break;
		}else
		if( strcaseeq(com,"QUIT") ){
			fprintf(tc,"+OK bye.\r\n");
			fflush(tc);
			break;
		}else
		if( POP_STARTTLS_withCL(Conn,fc,tc,com,vp) ){
			/* 9.9.8 cope with SERVER=pop (not SERVER=pop://sv) */
		}else{
			fprintf(tc,"-ERR Unknown command: \"%s\"\r\n",com);
		}
		fflush(tc);
	}
	/*
	fclose(tc);
	fclose(fc);
	*/
	CTX_fcloses(FL_ARG,"POPclnt",Conn,tc,fc);
}
int closeFilters(Connection *Conn,PCStr(what));
int service_pop(Connection *Conn)
{
	if( !source_permittedX(Conn) ){
		CStr(msg,128);
		sprintf(msg,"-ERR Forbidden\r\n");
		IGNRETP write(ToC,msg,strlen(msg));
		return -1;
	}
	if( isMYSELF(DST_HOST) )
		ProxyPOP(Conn);
	else	service_pop1(Conn,NULL,VStrNULL);

	closeFilters(Conn,"POP");
	return 0;
}
/*
static void closePOPserver(FILE *ts,FILE *fs)
*/
#define closePOPserver(ts,fs) closePOPserverX(FL_ARG,Conn,ts,fs)
static void closePOPserverX(FL_PAR,Connection *Conn,FILE *ts,FILE *fs)
{	CStr(resp,LNSIZE);

	fputs("QUIT\r\n",ts);
	fflush(ts);
	if( fgets(resp,sizeof(resp),fs) != NULL )
		sv1log("%s",resp);
	else	sv1log("POP S-C EOF on closePOPserver\n");
	/*
	fclose(ts);
	fclose(fs);
	*/
	CTX_fcloses(FL_BAR,"POPserv",Conn,ts,fs);
}
void getPOPcharange(PCStr(banner),PVStr(timestamp))
{	const char *sp;
	refQStr(dp,timestamp); /**/
	char ch;

	cpyQStr(dp,timestamp);
	if( sp = strchr(banner,'<') )
	for(; ch = *sp; sp++ ){
		setVStrPtrInc(dp,ch);
		if( ch == '>' )
			break;
	}
	setVStrEnd(dp,0);
	if( strchr(timestamp,'@') != NULL && strtailchr(timestamp) == '>' )
		sv1log("#### BANNER TIMESTAMP for APOP: %s\n",timestamp);
	else	setVStrEnd(timestamp,0);
}
void makeAPOPrequest(PVStr(req),PCStr(timestamp),PCStr(user),PCStr(pass),char xpass[])
{	CStr(argb,LNSIZE);
	CStr(xpassb,LNSIZE);

	if( xpass == NULL )
		xpass = xpassb;

	sprintf(argb,"%s%s",timestamp,pass);
	toMD5(argb,xpass);
	sprintf(req,"APOP %s %s\r\n",user,xpass);
	sv1log("#### %s",req);
}
int doPopAUTH(Connection *Conn,FILE **tsp,FILE **fsp,PCStr(timestamp),PCStr(user),PCStr(pass),PVStr(resp),int size)
{	FILE *ts,*fs;
	CStr(req,LNSIZE);
	const char *dp;

	sv1log("AUTH start.\n");
	ts = *tsp;
	fs = *fsp;

	if( timestamp[0] ){
		makeAPOPrequest(AVStr(req),timestamp,user,pass,NULL);
		if( dp = strpbrk(req,"\r\n") )
			truncVStr(dp);
		if( putget(1,ts,fs,AVStr(resp),size,"%s",req) == 0 ){
			sv1log("APOP OK.\n");
			return 0;
		}
		sv1log("retry with USER+PASS\n");
		ToS = FromS = -1;
		if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
			return -1;
		/*
		fclose(ts);
		fclose(fs);
		*/
		CTX_fcloses(FL_ARG,"POPserv",Conn,ts,fs);
		*tsp = ts = fdopen(ToS,"w");
		*fsp = fs = fdopen(FromS,"r");
		if( putget(2,ts,fs,AVStr(resp),size,NULL) != 0 )
			return -2;
	}

	if( putget(3,ts,fs,AVStr(resp),size,"USER %s",user) != 0 )
		return -3;

	if( pass != NULL )
	if( putget(4,ts,fs,AVStr(resp),size,"PASS %s",pass) != 0 )
		return -4;

	sv1log("AUTH done.\n");
	return 0;
}
int retryPOPopen(Connection *Conn,FILE **tsp,FILE **fsp,PCStr(user),PCStr(pass),PVStr(resp),int size)
{
	sv1log("POP-AUTH: APOP for USER+PASS failed: %s",resp);
	sv1log("POP-AUTH: retrying with USER+PASS.\n");
	closePOPserver(*tsp,*fsp); *tsp = *fsp = NULL;

	if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
		return -1;

	*tsp = fdopen(ToS,"w");
	*fsp = fdopen(FromS,"r");
	if( fgets(resp,size,*fsp) == NULL )
		return -1;

	fprintf(*tsp,"USER %s\r\n",user);
	fflush(*tsp);
	if( fgets(resp,size,*fsp) == NULL )
		return -1;
	fprintf(*tsp,"PASS %s\r\n",pass);
	fflush(*tsp);
	if( fgets(resp,size,*fsp) == NULL )
		return -1;

	if( *resp != '+' ){
		sv1log("POP-AUTH: USER+PASS failed: %s",resp);
		return -1;
	}
	return 0;
}

static void filterCAPA(Connection *Conn,PCStr(resp),FILE *fs,FILE *tc){
	CStr(line,LNSIZE);
	CStr(cap1,LNSIZE);
	while( 1 ){
		if( fgets(line,sizeof(line),fs) == 0 )
			break;
		Verbose("S-C: CAPA %s",line);
		wordScan(line,cap1);
		if( strcaseeq(cap1,"STLS") ){
			sv1log("S-D: CAPA STLS --- removed\n");
			continue;
		}
		if( line[0] == '.' && (line[1] == '\r' || line[1] == '\n') ){
			if( acceptSTLS(Conn) ){
				sv1log("D-C: CAPA STLS --- appended\n");
				fputs("STLS\r\n",tc);
			}
			fputs(line,tc);
			break;
		}
		fputs(line,tc);
	}
}
int POP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc,PCStr(com),PCStr(arg));
int POP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs,PCStr(user));

void service_pop1(Connection *Conn,PCStr(user),PVStr(nextUSER))
{	FILE *fc,*tc,*ts,*fs;
	CStr(req,LNSIZE);
	CStr(com,LNSIZE);
	CStr(arg,LNSIZE);
	const char *acom;
	CStr(banner,LNSIZE);
	CStr(resp,LNSIZE);
	int ri,body;
	CStr(timestamp,LNSIZE);
	char ch;
	const char *sp;
	refQStr(dp,req); /**/
	CStr(userbuf,LNSIZE);
	CStr(pass,LNSIZE);
	int APOPforUSERPASS;
	CStr(dom,128);

	if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
	{
		sprintf(banner,"-ERR cannot connect to the server (%s)\r\n",
			"see LOGFILE to investigate the reason");
		IGNRETP write(ToC,banner,strlen(banner));
		set_linger(ToC,DELEGATE_LINGER);
		return;
	}

	if( ServerFlags & PF_SSL_IMPLICIT )
	if( (ServerFlags & PF_SSL_ON) == 0 )
	if( (ServerFlags & PF_STLS_OPT) != 0 ){
		sv1log("#### required implicit SSL: %X\n",ServerFlags);
		sprintf(banner,"-ERR cannot setup SSL with the server\r\n");
		IGNRETP write(ToC,banner,strlen(banner));
		set_linger(ToC,DELEGATE_LINGER);
		return;
	}

	fc = fdopen(dup(FromC),"r");
	tc = fdopen(dup(ToC),"w");
	ts = fdopen(ToS,"w");
	fs = fdopen(FromS,"r");

	if( fgets(resp,sizeof(resp),fs) == NULL )
		goto EXIT;
	sv1log("POP S-D: %s",resp);
	POP_STARTTLS_withSV(Conn,ts,fs,user);
	if( needSTLS_SV(Conn) ){
		sv1log("#### required negotiated STLS: %X\n",ServerFlags);
		fprintf(tc,"-ERR cannot negotiate TLS with the server\r\n");
		goto EXIT;
	}

	if( *resp != '+' ){
		fputs(resp,tc);
		fflush(tc);
		goto EXIT;
	}

	/*
	POP_STARTTLS_withSV(Conn,ts,fs,user);
	*/

	strcpy(banner,resp);
	getPOPcharange(banner,AVStr(timestamp));
	if( timestamp[0] && MountOptions && isinList(MountOptions,"noapop") ){
		sv1log("POP ignore APOP timestamp from the server\n");
		timestamp[0] = 0;
	}

	if( user != NULL && timestamp[0] ){
		sprintf(resp,"+OK enter password for APOP/DeleGate: %s",
			banner);
	}else{
		if( *resp == '+' && user != NULL ){
			sprintf(req,"USER %s\r\n",user);
			sv1log("POP D-S: %s",req);
			if( fputs(req,ts) == EOF )
				goto EXIT;
			fflush(ts);
			if( fgets(resp,sizeof(resp),fs) == NULL )
				goto EXIT;
			sv1log("POP S-D: %s",resp);

			if( *resp == '+' )
			if( withAuthDigest(Conn,AVStr(dom)) ){
				sprintf(req,"POP D-S: PASS ****\r\n");
				if( putDigestPass(ts,"PASS %s\r\n",com,user) != 0 ){
					sprintf(req,"POP D-S: PASS Unknown\n");
					goto EXIT;
				}
				fflush(ts);
				if( fgets(resp,sizeof(resp),fs) == NULL )
					goto EXIT;
				sv1log("POP S-D: %s",resp);
			}
			else
			if( (ClientAuth.i_stat & AUTH_FORW)
			 && ClientAuth.i_stype == (AUTH_AORIGIN|AUTH_APROXY)
			 && ClientAuthUser[0] && ClientAuthPass[0]
			){
				sprintf(req,"POP D-S: PASS ****\r\n");
				fprintf(ts,"PASS %s\r\n",ClientAuthPass);
				fflush(ts);
				if( fgets(resp,sizeof(resp),fs) == NULL )
					goto EXIT;
				sv1log("POP S-D: %s",resp);
			}
		}
	}
	if( fputs(resp,tc) == EOF )
		goto EXIT;
	fflush(tc);
	if( *resp != '+' )
		goto EXIT;

	for(;;){
		/* relay unexpected signing off message
		 * and other ? notification messages ?
		 */
		/* should be implemented as PollIns([fs,ts]) ... */
		while( 0 < fPollIn(fs,1) ){
			int fcode;
			if( fgets(resp,sizeof(resp),fs) == NULL ){
				sv1log("POP S-C EOF before client request\n");
				goto EXIT;
			}
			fcode =
			fputs(resp,tc);
			if( fcode == EOF ){
				syslog_ERROR("--POP EOF on fputs >>> client\n");
				goto EXIT;
			}
		}
		if( fflush(tc) == EOF )
			goto EXIT;

		if( pollYY(Conn,"POP-REQ",fc/*,fs*/) != 0 ){
			goto EXIT;
		}
		if( fgets(req,sizeof(req),fc) == NULL )
			goto EXIT;

		if( *req == '\r' || *req == '\n' )
			continue;

		dp = strpbrk(req,"\r\n");
		if( dp == NULL ){
			syslog_ERROR("POP request without CRLF: %s\n",req);
			goto EXIT;
		}
		if( strcmp(dp,"\n") == 0 ){
			syslog_ERROR("WARNING: inserted CR before LF\n");
			strcpy(dp,"\r\n");
		}

		sp = wordScan(req,com);
		if( *sp != 0 ){
			refQStr(ap,arg); /**/
			for( sp++; ch = *sp; sp++ ){
				if( ch == '\r' || ch == '\n' )
					break;
				setVStrPtrInc(ap,ch);
			}
			setVStrEnd(ap,0);
		}else	arg[0] = 0;

		if( POP_STARTTLS_withCL(Conn,fc,tc,com,arg) ){
			continue;
		}
		if( strcasecmp(com,"USER") == 0 )
			sv1log("POP C-S: %s",req);
		else
		if( strcasecmp(com,"PASS") == 0 )
			Verbose("POP C-S: PASS ******\r\n");
		else
		if( isWindowsCE() ){
			sv1log("POP C-S %s",req);
		}
		else	Verbose("POP C-S: %s",req);

		if( method_permitted(Conn,"pop",com,1) == 0 ){
			fprintf(tc,"-ERR (forbidden) %s\r\n",com);
			continue;
		}

		if( strcasecmp(com,"XECHO") == 0 ){
			fprintf(tc,"%s\r\n",arg);
			continue;
		}
		if( needSTLS(Conn) ){
			if( strcaseeq(com,"CAPA") ){
				fputs("+OK Capability list follows\r\n",tc);
				fputs("STLS\r\n",tc);
				fputs(".\r\n",tc);
				continue;
			}
			if( strcasecmp(com,"STLS") != 0 )
			if( strcasecmp(com,"QUIT") != 0 )
			{
				fprintf(tc,"-ERR Say STLS first\r\n");
				continue;
			}
		}

		if( strcasecmp(com,"USER") == 0 ){
			if( nextUSER != NULL ){
				closePOPserver(ts,fs); ts = fs = NULL;
				strcpy(nextUSER,req);
				goto EXIT;
			}
			if( user != NULL && timestamp[0] ){
				closePOPserver(ts,fs); ts = fs = NULL;
				goto EXIT;
			}
			strcpy(userbuf,arg);
			user = userbuf;
			if( timestamp[0] ){
				fprintf(tc,"+OK enter password for APOP/DeleGate.\r\n");
				fflush(tc);
				continue;
			}
		}

		APOPforUSERPASS = 0;
		if( strcasecmp(com,"PASS") == 0 )
		if( user != NULL && timestamp[0] ){
			strcpy(com,"APOP");
			strcpy(pass,arg);
			makeAPOPrequest(AVStr(req),timestamp,user,pass,arg);
			APOPforUSERPASS = 1;
		}

		for( ri = 0; acom = pop_command[ri].name; ri++ ){
			if( strcaseeq(com,acom) )
				break;
		}
		fputs(req,ts);
		fflush(ts);

		if( fgets(resp,sizeof(resp),fs) == NULL )
		{
			syslog_ERROR("POP S-C EOF without response.\n");
			goto EXIT;
		}

		if( *resp == '-' && APOPforUSERPASS )
		if( retryPOPopen(Conn,&ts,&fs,user,pass,AVStr(resp),sizeof(resp)) < 0 )
		{
			fprintf(tc,"-ERR bad login.\r\n");
			goto EXIT;
		}

		body = pop_command[ri].resp;
		if( body && arg[0] ){
			if( body & NULL_BODY_IFARG )
				body = NULL_BODY;
		}

		if( body && *resp == '+' )
		if( (body & RESPFLAGS) == (WITH_BODY|IN_RFC822) ) 
		if( filter_withCFI(Conn,XF_FTOCL) )
			putMESSAGEline(tc,"mime",com);

		if( fputs(resp,tc) == EOF )
			goto EXIT;

		if( strcasecmp(com,"PASS") == 0 )
			Verbose("POP S-C[%d:%d]: PASS ******\r\n",ri,body);
		else	Verbose("POP S-C[%d:%d]: %s",ri,body,resp);

		if( body && *resp == '+' ){
			if( strcaseeq(com,"CAPA") ){
				filterCAPA(Conn,resp,fs,tc);
			}else
			switch( body & RESPFLAGS ){
				case WITH_BODY | IN_RFC822:
					PGPdecodeMIME(fs,tc,NULL,0xFF,1,0);
					break;
				case WITH_BODY:
					thruRESP(fs,tc);
					break;
			}
		}
		fflush(tc);
		if( strcaseeq(com,"QUIT") )
			goto EXIT;

		if( user != NULL )
		if( strcaseeq(com,"PASS") || strcaseeq(com,"APOP") ){
			CStr(clnt,LNSIZE);
			CStr(serv,LNSIZE);
			const char *cluser;
			CStr(clhost,LNSIZE);
			int clport;

			clport = getClientHostPort(Conn,AVStr(clhost));
			if( (cluser = getClientUserC(Conn)) == NULL )
				cluser = "-";
			sprintf(clnt,"%s@%s:%d",cluser,clhost,clport);

			sprintf(serv,"%s@%s",user,DST_HOST);
			sv1log("%cPOP-LOGIN FROM %s TO %s\n",
				resp[0],clnt,serv);
			fputLog(Conn,"Login","%cPOP-LOGIN; from=%s; to=%s\n",
				resp[0],clnt,serv);
			LOG_flushall();
		}
	}

EXIT:
	/*
	if( ts != NULL ) fclose(ts);
	if( fs != NULL ) fclose(fs);
	if( tc != NULL ) fclose(tc);
	if( fc != NULL ) fclose(fc);
	*/
	finishServYY(FL_ARG,Conn);
	CTX_fcloses(FL_ARG,"POPserv",Conn,ts,fs);
	CTX_fcloses(FL_ARG,"POPclnt",Conn,tc,fc);
	return;
}

int getlineBlind(FILE *out,FILE *in,PCStr(prompt),PVStr(line),int size)
{	const char *dp;
	const char *av[3]; /**/
	int pid;

	fprintf(out,"%s",prompt);
	fflush(out);

	setVStrEnd(line,0);
	av[0] = "stty";
	av[1] = "-echo";
	av[2] = 0;
	if( (pid = Spawnvp("getline","stty",av)) < 0 ){
		fprintf(stderr,"Cannot disable ECHO on your terminal\r\n");
		return -1;
	}
	wait(0);

	fgets(line,size,in);
	av[1] = "echo";
	Spawnvp("getline","stty",av);
	wait(0);

	if( dp = strpbrk(line,"\r\n") )
		truncVStr(dp);
	fprintf(out,"\r\n");
	return 0;
}
void getPassword(PCStr(proto),PCStr(site),PCStr(path),PVStr(pass),int size)
{	CStr(prompt,LNSIZE);

	setVStrEnd(pass,0);

	/* pop up window for password if any Window is available ...*/

	if( isatty(fileno(stdin)) ){
	sprintf(prompt,"Enter password for \"%s://%s/%s\": ",proto,site,path);
	getlineBlind(stderr,stdin,prompt,AVStr(pass),size);
	}
}

int POP_open(Connection *Conn,int fromC,int toC,FILE **tsp,FILE **fsp,PCStr(user),PCStr(pass),PVStr(resp),int rsize)
{	int sock;
	CStr(seed,LNSIZE);
	int rcode;

	sock = connect_to_serv(Conn,fromC,toC,0);
	if( sock < 0 ){
		sprintf(resp,"-ERR Could not connect to pop://%s:%d\r\n",
			DST_HOST,DST_PORT);
		return -1;
	}
	*fsp = fdopen(sock,"r");
	*tsp = fdopen(sock,"w");
	if( putget(1,*tsp,*fsp,AVStr(resp),rsize,NULL) != 0 ){
		/*
		fclose(*fsp);
		fclose(*tsp);
		*/
		CTX_fcloses(FL_ARG,"POPserv",Conn,*fsp,*tsp);
		return -1;
	}
	POP_STARTTLS_withSV(Conn,*tsp,*fsp,"");

	getPOPcharange(resp,AVStr(seed));
	setVStrEnd(resp,0);
	rcode = doPopAUTH(Conn,tsp,fsp,seed,user,pass,AVStr(resp),rsize);
	return rcode;
}

int sendmailSMTP(Connection *Conn,PCStr(smtphost),int smtpport,PCStr(mailto),PCStr(mailfrom),FILE *afp);

int poprelay_main(int ac,const char *av[],Connection *xConn)
{	Connection popConnBuf, *popConn = &popConnBuf;
	FILE *tsp,*fsp,*tss,*fss,*afp;
	const char *spool;
	CStr(dest,LNSIZE);
	CStr(req,LNSIZE);
	CStr(resp,LNSIZE);
	int ai,mi;
	const char *arg;
	int msize,wcc;
	const char *error;
	int xdelete;
	CStr(owner,LNSIZE);
	CStr(myhost,LNSIZE);
	CStr(proto,LNSIZE);
	CStr(site,LNSIZE);
	CStr(upath,LNSIZE);
	CStr(pophost,LNSIZE);
	CStr(user,LNSIZE);
	CStr(pass,LNSIZE);
	int maxmsg;
	CStr(mailto,LNSIZE);
	AuthInfo ident;

	ConnInit(popConn);
	popConn->from_myself = 1;
	spool = DELEGATE_getEnv(P_MAILSPOOL);
	if( spool == NULL ){
		fprintf(stderr,"Specify MAILSPOOL=pop://user@host\n");
		Finish(-1);
	}
	decomp_absurl(spool,AVStr(proto),AVStr(site),AVStr(upath),sizeof(upath));
	if( strcmp(proto,"pop") != 0 ){
		fprintf(stderr,"Specify MAILSPOOL=pop://user@host\n");
		Finish(-2);
	}
	if( site[0] == 0 )
		strcpy(site,"localhost");
	decomp_siteX(proto,site,&ident);
	wordScan(ident.i_user,user);
	textScan(ident.i_pass,pass);
	wordScan(ident.i_Host,pophost);

	getUsername(getuid(),AVStr(owner));
	GetHostname(AVStr(myhost),sizeof(myhost));

	if( user[0] == 0 )
		strcpy(user,owner);
	if( pass[0] == 0 )
		getPassword(proto,site,upath,AVStr(pass),sizeof(pass));

	scan_SERVER(popConn,spool);

	dest[0] = 0;
	xdelete = 0;
	maxmsg = 10;
	strcpy(mailto,"");

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( streq(arg,"-DELE") )
			xdelete = 1;
		else
		if( strncasecmp(arg,"-To:",4) == 0 )
			strcpy(mailto,arg+4);
	}

	if( POP_open(popConn,-1,-1,&tsp,&fsp,user,pass,AVStr(resp),sizeof(resp)) ){
		fprintf(stderr,"%s",resp);
		Finish(-3);
	}

/* connect to the SERVER if specified ... (smtp,ftp,nntp,...) */
/* else if XCMD is specified ... */

	afp = TMPFILE("POP2SMTP");
	for( mi = 1; mi <= maxmsg; mi++ ){
		if( putget(7,tsp,fsp,AVStr(resp),sizeof(resp),"RETR %d",mi) != 0 )
			break;
		fseek(afp,0,0);
		relayRESPBODY(fsp,afp,AVStr(resp),sizeof(resp));
		fflush(afp);
		Ftruncate(afp,0,1);
		fseek(afp,0,0);
		/* do filtering here ? */
		msize = file_size(fileno(afp));
		error = 0;
		if( mailto[0] ){
			if( sendmailSMTP(xConn,NULL,0,mailto,NULL,afp) != 0 )
				break;
		}else
		if( dest[0] == 0 ){
			wcc = copyfile1(afp,stderr);
			syslog_ERROR("wrote %d / %d\n",wcc,msize);
			error = "not forwarded (no destination)";
		}else{
			error = "not forwarded (bad destination)";
		}
		if( error ){
			syslog_ERROR("DON'T DELETE: %s\n",error);
			continue;
		}
		if( xdelete )
		if( putget(8,tsp,fsp,AVStr(resp),sizeof(resp),"DELE %d",mi) != 0 )
			break;
	}
	fclose(afp);

	putget(-9,tsp,fsp,AVStr(resp),sizeof(resp),"QUIT");
	Finish(0);
	return 0;
}
int sendmailSMTP(Connection *Conn,PCStr(smtphost),int smtpport,PCStr(mailto),PCStr(mailfrom),FILE *afp)
{	FILE *fpv[2]; /**/
	CStr(admin,LNSIZE);
	CStr(resp,LNSIZE);

	Conn->from_myself = 1;
	if( mailfrom == NULL ){
		sprintf(admin,"%s (POP-GW-DeleGate/%s)",getADMIN(),
			DELEGATE_ver());
		mailfrom = admin;
	}
	if( smtphost == NULL )
		smtphost = "localhost";
	if( smtpport == 0 )
		smtpport = 25;

	if( SMTP_open(Conn,fpv,smtphost,smtpport,mailto,mailfrom,1,stderr)<0 )
		return -1;

	fprintf(fpv[1],"X-Forwarded: by %s (POP-GW-DeleGate/%s)\r\n",
		mailfrom,DELEGATE_ver());
	copyfile1(afp,fpv[1]);
	fputs(".\r\n",fpv[1]);

	putget(0,fpv[1],fpv[0],AVStr(resp),sizeof(resp),"QUIT");
	/*
	fclose(fpv[0]);
	fclose(fpv[1]);
	*/
	CTX_fcloses(FL_ARG,"POPSMTP",Conn,fpv[0],fpv[1]);
	return 0;
}

/*
 * new-110319a popdown
 *   download to popdown.mbox by default, ignoring duplicated articles
 *   relays to SMTP with SMTPSERVER ?
 *   filtering by sender/receiver or From/To
 *   forwarding via SMTP/TLS
 *   periodical report of popdown activity
 */
typedef struct _PopDown {
	int	pd_progress;
	int	pd_numDown;
	int	pd_mboxanum;
	int	pd_mboxsize;
	FILE   *pd_smtpfpv[2];
	FileSize pd_sizDown;
} PopDown;
static int isLoop(FILE *afp,int aoff){
	int off;
	int found = 0;
	IStr(line,1024);

	off = ftell(afp);
	fseek(afp,aoff,0);
	for(;;){
		if( fgets(line,sizeof(line),afp) == NULL ){ /* RFC822_... */
			break;
		}
		if( strstr(line,"popdown/") ){
			fprintf(stderr,"----found %s",line);
			found = 1;
			break;
		}
		if( line[0] == '\r' || line[0] == '\n' ){
			break;
		}
	}
	fseek(afp,off,0);
	return found;
}
void ftoMD5(FILE *fp,char md5[]);
static int isRelayed(FILE *afp,PVStr(md5),int anum){
	int found = 0;
	int off;
	FILE *mfp;
	FILE *nfp;
	int now = time(0);
	IStr(line,256);

	off = ftell(afp);
	ftoMD5(afp,(char*)md5);
	fseek(afp,off,0);

	mfp = fopen("popdown.md5","r");
	nfp = fopen("popdown.md5.new","w");
	if( mfp != NULL ){
		for(;;){
			if( fgets(line,sizeof(line),mfp) == NULL ){
				break;
			}
			if( strstr(line,md5) ){
				fprintf(stderr,"---- found %s : %s",md5,line);
				found = 1;
				break;
			}
			if( nfp ){
				fputs(line,nfp);
			}
		}
		fclose(mfp);
	}
	if( nfp != NULL ){
		if( !found ){
			IStr(buf,1024);
			sprintf(buf,"%d %d %s\r\n",anum,now,md5);
			fprintf(nfp,"%s",buf);
		}
		fclose(nfp);
		if( !found ){
			rename("popdown.md5.new","popdown.md5");
		}else{
			unlink("popdown.md5.new");
		}
	}
	return found;
}
int closeSMTP1(FILE *fpv[2]){
	IStr(resp,LNSIZE);
	putget(9,fpv[1],fpv[0],AVStr(resp),sizeof(resp),"QUIT");
	fclose(fpv[0]);
	fclose(fpv[1]);
	fpv[0] = fpv[1] = NULL;
	return 0;
}
int SMTPgateway(Connection *Conn,FILE *tc,FILE *mfp,PCStr(md5),PCStr(hello),PCStr(sender),PCStr(recipient),FILE *log);
int sendmailSMTP1(Connection *Conn,FILE *fpv[2],PCStr(mailto),PCStr(mailfrom),FILE *afp){
	IStr(resp,LNSIZE);
	IStr(admin,LNSIZE);
	int off;

	Conn->from_myself = 1;
	off = ftell(afp);
	if( mailfrom == NULL ){
		sprintf(admin,"%s (POP-GW-DeleGate/%s)",getADMIN(),
			DELEGATE_ver());
		mailfrom = admin;
	}
FILE *tc = TMPFILE("POPSMTP");
SMTPgateway(Conn,tc,afp,"md5","helo",mailfrom,mailto,stderr);
fclose(tc);
return 0;

	putget(1,fpv[1],fpv[0],AVStr(resp),sizeof(resp),"RCPT TO:%s",mailto);
	putget(2,fpv[1],fpv[0],AVStr(resp),sizeof(resp),"MAIL FROM:%s",mailfrom);
	putget(3,fpv[1],fpv[0],AVStr(resp),sizeof(resp),"DATA");

	fprintf(fpv[1],"X-Forwarded: by %s (POP-GW-DeleGate/%s)\r\n",
		mailfrom,DELEGATE_ver());
	copyfile1(afp,fpv[1]);
	fseek(afp,off,0);
	putget(3,fpv[1],fpv[0],AVStr(resp),sizeof(resp),".");
sv1log("------------FORWARDED\n");
	return 0;
}
static int popdown1(int ac,const char *av[],Connection *xConn,PopDown *Pd){
	Connection pop3ConnBuf, *pop3Conn = &pop3ConnBuf;
	Connection smtpConnBuf, *smtpConn = &smtpConnBuf;
	FILE *tsp,*fsp,*tss,*fss,*afp;
	const char *spool;
	IStr(dest,LNSIZE);
	IStr(req,LNSIZE);
	IStr(resp,LNSIZE);
	int ai,mi;
	const char *arg;
	int msize,wcc;
	const char *error;
	int xdelete;
	IStr(owner,LNSIZE);
	IStr(myhost,LNSIZE);
	IStr(proto,LNSIZE);
	IStr(site,LNSIZE);
	IStr(upath,LNSIZE);
	IStr(pophost,LNSIZE);
	IStr(user,LNSIZE);
	IStr(pass,LNSIZE);
	int maxmsg;
	IStr(mailto,LNSIZE);
	IStr(mxhost,LNSIZE);
	AuthInfo ident;
	const char *popdown_spool;
	FILE *popdown_out;
	int afrom = 1;
	int anum;
	IStr(md5,128);

	ConnInit(pop3Conn);
	pop3Conn->from_myself = 1;
	ConnInit(smtpConn);
	smtpConn->from_myself = 1;

	spool = DELEGATE_getEnv(P_MAILSPOOL);
	if( spool == NULL ){
		fprintf(stderr,"Specify MAILSPOOL=pop://user@host\n");
		Finish(-1);
	}
	decomp_absurl(spool,AVStr(proto),AVStr(site),AVStr(upath),sizeof(upath));
	if( strcmp(proto,"pop") != 0 ){
		fprintf(stderr,"Specify MAILSPOOL=pop://user@host\n");
		Finish(-2);
	}
	if( site[0] == 0 )
		strcpy(site,"localhost");
	decomp_siteX(proto,site,&ident);
	wordScan(ident.i_user,user);
	textScan(ident.i_pass,pass);
	wordScan(ident.i_Host,pophost);

	getUsername(getuid(),AVStr(owner));
	GetHostname(AVStr(myhost),sizeof(myhost));

	if( user[0] == 0 )
		strcpy(user,owner);
	if( pass[0] == 0 )
		getPassword(proto,site,upath,AVStr(pass),sizeof(pass));

	scan_SERVER(pop3Conn,spool);

	dest[0] = 0;
	xdelete = 0;
maxmsg = 3;
	strcpy(mailto,"");
	popdown_spool = "popdown.mbox";
	popdown_out = fopen(popdown_spool,"w");
	if( popdown_out == NULL ){
		popdown_out = stdout;
	}

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( streq(arg,"-DELE") ){
			xdelete = 1;
		}else
		if( strncasecmp(arg,"-To:",4) == 0 ){
			strcpy(mailto,arg+4);
		}
		else
		if( strncasecmp(arg,"-Mx:",4) == 0 ){
			strcpy(mxhost,arg+4);
		}
	}

	if( POP_open(pop3Conn,-1,-1,&tsp,&fsp,user,pass,AVStr(resp),sizeof(resp)) ){
		fprintf(stderr,"%s",resp);
		Finish(-3);
	}
	if( putget(7,tsp,fsp,AVStr(resp),sizeof(resp),"STAT") == 0 ){
		sscanf(resp,"+%*s %d %d",&Pd->pd_mboxanum,&Pd->pd_mboxsize);
		fprintf(stderr,"---- num=%d size=%d\r\n",
			Pd->pd_mboxanum,Pd->pd_mboxsize);
		if( maxmsg < Pd->pd_mboxanum ){
			afrom = Pd->pd_mboxanum - (maxmsg - 1); 
		}
	}else{
	}

/* connect to the SERVER if specified ... (smtp,ftp,nntp,...) */
/* else if XCMD is specified ... */

	afp = TMPFILE("POP2SMTP");
	for( mi = 0; mi < maxmsg; mi++ ){
		IStr(rcvd,256);
		IStr(From,256);
		IStr(sndr,256);
		int aoff;

		anum = afrom + mi;
		if( putget(7,tsp,fsp,AVStr(resp),sizeof(resp),"RETR %d",anum)!=0 ){
			break;
		}
		fseek(afp,0,0);
		if( 1 ){
			fprintf(afp,"Received: by popdown/DeleGate\r\n");
		}
		aoff = ftell(afp);
		relayRESPBODY(fsp,afp,AVStr(resp),sizeof(resp));
		fflush(afp);
		Ftruncate(afp,0,1);
		fseek(afp,0,0);

		/* do filtering here ? */
		msize = file_size(fileno(afp));

		if( isLoop(afp,aoff) ){
			fprintf(stderr,"---- duplicated\r\n");
			continue;
		}
		if( isRelayed(afp,AVStr(md5),anum) ){
			fprintf(stderr,"---- relayed already: %s\r\n",md5);
			continue;
		}

		fgetsHeaderField(afp,"Return-Path",AVStr(From),sizeof(From));
		if( From[0] == 0 ){
			fgetsHeaderField(afp,"From",AVStr(From),sizeof(From));
		}
strcpy(sndr,"");
RFC822_addresspartX(From,AVStr(sndr),sizeof(sndr));
if( sndr[0] == 0 ){
	strcpy(sndr,"-");
}

		error = 0;
		if( mailto[0] ){
			if( Pd->pd_smtpfpv[0] == NULL )
			if( SMTP_open(smtpConn,Pd->pd_smtpfpv,mxhost,25,"",NULL,0,stderr) < 0 ){
				break;
			}
			if( Pd->pd_smtpfpv[0] == NULL ){
				break;
			}
			if( sendmailSMTP1(smtpConn,Pd->pd_smtpfpv,mailto,NULL,afp) != 0 ){
				break;
			}
			closeSMTP1(Pd->pd_smtpfpv);
			/* should user SMTPGATE for forwarding */
		}
		if( dest[0] == 0 ){
IStr(Date,256);
StrftimeLocal(AVStr(Date),sizeof(Date),TIMEFORM_ANSI_C,time(0),0);
			fprintf(popdown_out,"From %s  %s\r\n",sndr,Date);
			wcc = copyfile1(afp,popdown_out);
			syslog_ERROR("wrote %d / %d\n",wcc,msize);
			fprintf(popdown_out,"\r\n\r\n");
			//error = "not forwarded (no destination)";
		}else{
			error = "not forwarded (bad destination)";
		}
		Pd->pd_numDown++;
		Pd->pd_sizDown += msize;
		if( Pd->pd_progress ){
			setVStrEnd(md5,8);
fprintf(stderr,"---- %3d / %3d %6d / %6lld %s %-20s\r\n",
				Pd->pd_numDown,mi,msize,Pd->pd_sizDown,md5,sndr);
			fflush(stderr);
		}
		if( error ){
			syslog_ERROR("DON'T DELETE: %s\n",error);
			continue;
		}
		if( xdelete ){
			if( putget(8,tsp,fsp,AVStr(resp),sizeof(resp),"DELE %d",mi) != 0 )
				break;
		}
	}
	fclose(afp);

	putget(-9,tsp,fsp,AVStr(resp),sizeof(resp),"QUIT");
	return 0;
}
int popdown_main(int ac,const char *av[],Connection *xConn){
	int interval = -1;
	int repeat = 1;
	int ri;
	int rcode;
	double Start = Time();
	PopDown PdBuff,*Pd = &PdBuff;

	fprintf(stderr,"----popdown START\r\n");
	bzero(Pd,sizeof(PopDown));
	if( isatty(fileno(stderr)) ){
		Pd->pd_progress = 1;
	}
	for( ri = 0; ri < repeat; ri++ ){
		if( 0 < ri ){
			sleep(10);
		}
		rcode = popdown1(ac,av,xConn,Pd);
	}
	if( Pd->pd_progress ){
		fprintf(stderr,"\n");
	}
	fprintf(stderr,"----popdown DOWNLOADED %lluB / %d / %.3f\r\n",
		Pd->pd_sizDown,Pd->pd_numDown,Time()-Start);
	return 0;
}
