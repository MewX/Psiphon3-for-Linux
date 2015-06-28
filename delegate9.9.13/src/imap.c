/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	imap.c (IMAP4 RFC2060)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	000616	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "fpoll.h"
#include "delegate.h"
#include "param.h"
#include "auth.h"
#include "filter.h"
#define LNSIZE 1024

static void imap_change_server(Connection *Conn,PVStr(login))
{	const char *dp;
	IStr(proto,64);
	CStr(host,LNSIZE);
	const char *opts;
	CStr(user,LNSIZE);
	CStr(tmp,LNSIZE);
	int port;

	if( *login == '"' )
		wordScanY(login+1,user,"^\"");
	else	wordScan(login,user);
	if( dp = strrpbrk(user,"@%") ){
		truncVStr(dp);
		strcpy(tmp,user);
		wordScan(dp+1,host);
		sprintf(user,"//%s/%s",host,tmp);
	}
	opts = CTX_mount_url_to(Conn,NULL,"GET",AVStr(user));
	strcpy(proto,"imap");
	if( strncasecmp(user,"imap://",7) == 0 )
	{
		ovstrcpy(user,user+5);
	}
	if( strncasecmp(user,"imaps://",8) == 0 )
	{
		strcpy(proto,"imaps");
		ovstrcpy(user,user+6);
	}

	if( Xsscanf(user,"//%[^/]/%s",AVStr(tmp),AVStr(user)) == 2 ){
		/*
		port = scan_hostportX("imap",tmp,AVStr(host),sizeof(host));
		*/
		port = scan_hostportX(proto,tmp,AVStr(host),sizeof(host));
		sprintf(login,"\"%s\"",user);
		goto SWSERV;
	}

	dp = strrpbrk(login,"@%");
	if( dp == 0 )
		return;

	/*
	port = scan_hostportX("imap",dp+1,AVStr(host),sizeof(host));
	*/
	port = scan_hostportX(proto,dp+1,AVStr(host),sizeof(host));
	if( strtailchr(login) == '"' )
		*(char*)dp++ = '"'; /**/
	truncVStr(dp);

SWSERV:
	sv1log("IMAP LOGIN  %s @ %s:%d\n",login,host,port);
	/*
	set_realserver(Conn,"imap",host,port);
	*/
	set_realserver(Conn,proto,host,port);
	if( streq(CLNT_PROTO,"imaps") && (ClientFlags & PF_MITM_DO) ){
		ServerFlags |= (PF_SSL_IMPLICIT | PF_STLS_DO);
	}
	connect_to_serv(Conn,FromC,ToC,0);
}

static void imaplog(Connection *Conn,PCStr(qcmd),PCStr(qarg))
{	CStr(clnt,LNSIZE);
	CStr(user,LNSIZE);
	CStr(serv,LNSIZE);

	strfConnX(Conn,"%u@%h:%p",AVStr(clnt),sizeof(clnt));
	if( *qarg == '"' )
		wordScanY(qarg+1,user,"^\"");
	else	wordScan(qarg,user);
	sprintf(serv,"%s@%s",user,DST_HOST);
	sv1log("%s IMAP-LOGIN FROM %s TO %s\n",
		0<=ToS?"OK":"NO",clnt,serv);
	fputLog(Conn,"Login","%s IMAP-LOGIN; from=%s; to=%s\n",
		0<=ToS?"OK":"NO",clnt,serv);
	LOG_flushall();
}

int IMAP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc,PCStr(tag),PCStr(com),PCStr(arg));
int IMAP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs,PCStr(user));

static void capSTLS(Connection *Conn,PVStr(caps)){
	refQStr(sp,caps);
	const char *np;

	if( willSTLS_CL(Conn) ){
		/* should add STARTTLS if not included */
		return;
	}

	if( sp = strstr(caps,"STARTTLS") ){
		np = sp + 8;
		if( *np == ' ' )
			np++;
		ovstrcpy((char*)sp,np);
	}
}
static int redirect(FILE *fs,PCStr(qcmd),PCStr(resp),PVStr(serv),PVStr(req)){
	const char *dp;
	const char *pfx = "mail server, use ";
	CStr(rtag,LNSIZE);
	CStr(rstat,LNSIZE);

	dp = wordScan(resp,rtag);
	dp = wordScan(dp,rstat);
	if( strcaseeq(qcmd,"LOGIN") && strcaseeq(rstat,"NO") ){
		if( dp = strstr(resp,"[ALERT]") )
		if( dp = strstr(dp,pfx) )
		if( Xsscanf(dp+strlen(pfx),"%[-.0-9a-zA-Z]",AVStr(serv)) ){
			return 1;
		}
	}
	return 0;
}
static int redirectSV(Connection *Conn,PCStr(serv),PCStr(req),PVStr(resp),FILE **fsp,FILE **tsp){
	FILE *fs = 0;
	FILE *ts = 0;
	CStr(rtag,LNSIZE);
	refQStr(rp,resp);
	const char *r1;

	/* should skip input in *fsp here ? */

	fs = fdopen(FromS,"r");
	ts = fdopen(ToS,"w");

	clearVStr(resp);
	r1 = fgetsTIMEOUT(BVStr(resp),LNSIZE,fs);
	sv1log("----OPENING %s",resp);
	if( r1 == NULL || strstr(resp," OK") == NULL ){
		fcloseFILE(fs);
		fclose(ts);
		return -1;
	}
	fputs(req,ts);
	fflush(ts);

	for( rp = resp;;){
		r1 = fgetsTIMEOUT(AVStr(rp),LNSIZE-(rp-resp),fs);
		if( r1 != NULL ){
			sv1log("----LOGIN %s",rp);
		}
		if( r1 != NULL && *r1 == '*' ){
			rp += strlen(rp);
			continue;
		}
		if( r1 == NULL || strcasestr(r1," OK ") == NULL ){
			fcloseFILE(fs);
			fclose(ts);
			return -2;
		}
		break;
	}

	fcloseFILE(*fsp);
	fclose(*tsp);
	*fsp = fs;
	*tsp = ts;
	return 1;
}
int service_imap(Connection *Conn)
{	FILE *fc,*tc,*ts,*fs;
	FILE *fpv[2]; /**/
	int rds[2],idle;
	const char *dp;
	const char *ap;
	CStr(req,LNSIZE);
	CStr(qtag,LNSIZE);
	CStr(qcmd,LNSIZE);
	CStr(qarg,LNSIZE);
	CStr(qrem,LNSIZE);
	CStr(resp,LNSIZE);
	CStr(rtag,LNSIZE);
	CStr(rstat,LNSIZE);
	CStr(myhost,LNSIZE);
	IStr(serv,MaxHostNameLen);
	int newconn;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");

	if( 0 <= ToS ){
		ts = fdopen(ToS,"w");
		fs = fdopen(FromS,"r");
		if( fgetsTIMEOUT(AVStr(resp),sizeof(resp),fs) == NULL )
			return -1;
		sv1log("S: %s",resp);
		IMAP_STARTTLS_withSV(Conn,ts,fs,"");
	}else{
		ts = NULL;
		fs = NULL;
		ClientIF_name(Conn,FromC,AVStr(myhost));
		sprintf(resp,"* OK %s Proxy IMAP4 server DeleGate/%s\r\n",
			myhost,DELEGATE_ver());
		sv1log("D: %s",resp);
	}
	capSTLS(Conn,AVStr(resp));
	fputs(resp,tc);

	for(;;){
		fflush(tc);
		if( pollYY(Conn,"IMAP-REQ",fc) != 0 ){
			break;
		}
		if( fgetsTIMEOUT(AVStr(req),sizeof(req),fc) == NULL ){
			sv1log("C: EOF\n");
			break;
		}
		dp = wordScan(req,qtag);
		ap = wordScan(dp,qcmd);
		dp = wordScan(ap,qarg);
		lineScan(dp,qrem);
		if( strcaseeq(qcmd,"LOGIN") ){
			sv1log("C: %s %s %s ****\n",qtag,qcmd,qarg);
		}else	sv1log("C: %s",req);

		if( method_permitted(Conn,"imap",qcmd,1) == 0 ){
			fprintf(tc,"%s NO (forbidden) %s\r\n",qtag,qcmd);
			fflush(tc);
			continue;
		}
		if( IMAP_STARTTLS_withCL(Conn,fc,tc,qtag,qcmd,qarg) ){
			continue;
		}
		if( needSTLS(Conn) ){
			if( !strcaseeq(qcmd,"XECHO") )
			if( !strcaseeq(qcmd,"LOGOUT") )
			if( !strcaseeq(qcmd,"CAPABILITY") ){
				fprintf(tc,"%s BAD Say STARTTLS first.\r\n",qtag);
				continue;
			}
		}

		if( ts == NULL ){
			if( strcaseeq(qcmd,"XECHO") ){
				while( *ap == ' ' || *ap == '\t' )
					ap++;
				fputs(ap,tc);
				continue;
			}
			if( strcaseeq(qcmd,"LOGOUT") ){
				sv1log("D: %s OK %s\r\n",qtag,qcmd);
				fprintf(tc,"%s OK %s\r\n",qtag,qcmd);
				fflush(tc);
				break;
			}
			if( strcaseeq(qcmd,"CAPABILITY") ){
				sv1log("D: %s OK %s\r\n",qtag,qcmd);
/*
				fprintf(tc,"* CAPABILITY IMAP4 AUTH-LOGIN\r\n");
*/
/*
				fprintf(tc,"* CAPABILITY IMAP4 AUTH-LOGIN");
*/
				fprintf(tc,"* CAPABILITY IMAP4");
				fprintf(tc," IMAP4rev1");
				fprintf(tc," AUTH-LOGIN");
				if( willSTLS_CL(Conn) ){
					fprintf(tc," STARTTLS");
				}
				fprintf(tc,"\r\n");
				fprintf(tc,"%s OK %s\r\n",qtag,qcmd);
				continue;
			}
			if( strcaseeq(qcmd,"LOGIN") )
				imap_change_server(Conn,AVStr(qarg));

			if( ToS < 0 ){
				fprintf(tc,"%s BAD LOGIN user@host first.\r\n",
					qtag);
				sv1log("D: %s BAD LOGIN user@host first.\r\n",
					qtag);
				imaplog(Conn,qcmd,qarg);
				continue;
			}
			ts = fdopen(ToS,"w");
			fs = fdopen(FromS,"r");
			if( fgetsTIMEOUT(AVStr(resp),sizeof(resp),fs) == NULL )
				return -1;
			sv1log(">>>> %s",resp);
			sprintf(req,"%s %s %s %s\r\n",qtag,qcmd,qarg,qrem);
			sv1log(">>>> %s %s %s ****\n",qtag,qcmd,qarg);
			IMAP_STARTTLS_withSV(Conn,ts,fs,"");
			newconn = 1;
		}
		else	newconn = 0;

		if( strcaseeq(qcmd,"AUTHENTICATE") ){
			if( CTX_withAuth(Conn) ){
				sv1log("#### NO AUTHENTICATE [%s]\n",qarg);
				fprintf(tc,"%s NO do LOGIN instead\r\n",qtag);
				fflush(tc);
				continue;
			}
		}
		if( strcaseeq(qcmd,"LOGIN") ){
			CStr(user,64);
			CStr(pass,64);
			if( *qarg == '"' )
				wordScanY(qarg+1,user,"^\"");
			else	wordScan(qarg,user);
			if( *qrem == '"' )
				wordScanY(qrem+1,pass,"^\"");
			else	wordScan(qrem,pass);
			/*
			if( CTX_auth(Conn,user,qrem) < 0 ){
			*/
			if( CTX_auth(Conn,user,pass) < 0 ){
				sv1log("#### [%s] LOGIN forbidden\n",user);
				fprintf(tc,"%s NO LOGIN forbidden\r\n",qtag);
				fflush(tc);
				continue;
			}
		}
		fputs(req,ts);
		fflush(ts);

		rstat[0] = 0;
/*
		if( strcaseeq(qcmd,"IDLE") || strcaseeq(qcmd,"APPEND") ){
*/
		if( strcaseeq(qcmd,"IDLE")
		 || strcaseeq(qcmd,"APPEND")
		 || strcaseeq(qcmd,"AUTHENTICATE")
		){
			fpv[0] = fc;
			fpv[1] = fs;
			idle = 1;
		}else	idle = 0;
		for(;;){
			if( idle ){
				fflush(tc);
				if( fPollIns(0,2,fpv,rds) < 0 )
					break;
				if( 0 < rds[0] ){
					if( fgets(req,sizeof(req),fc) == NULL ){
						sv1log("C> EOF in IDLE\n");
						goto EXIT;
					}
					Verbose("C> %s",req);
					fputs(req,ts);
					fflush(ts);
				}
				if( rds[1] <= 0 )
					continue;
			}
			if( fgetsTIMEOUT(AVStr(resp),sizeof(resp),fs) == NULL ){
				sv1log("S: EOF\n");
				break;
			}
			dp = wordScan(resp,rtag);
			dp = wordScan(dp,rstat);

			if( streq(rtag,"*") && strcaseeq(qcmd,"CAPABILITY") ){
				capSTLS(Conn,QVStr((char*)dp,resp));
			}
			if( redirect(fs,qcmd,resp,AVStr(serv),AVStr(req)) ){
				sv1log("IMAP redirect=>%s %s\n",serv,req);
				set_realserver(Conn,"imap",serv,143);
				connect_to_serv(Conn,FromC,ToC,0);
				if( 0 <= ToS ){
					redirectSV(Conn,serv,req,AVStr(resp),
						&fs,&ts);
				}
			}
			fputs(resp,tc);
			if( qtag[0] == 0 || strcmp(qtag,rtag) == 0 )
				break;
			Verbose("S> %s",resp);
		}
		sv1log("S: %s",resp);
		fflush(tc);
		if( strcaseeq(qcmd,"LOGOUT") && strcaseeq(rstat,"OK")
		 || feof(fs) )
			break;

		if( strcaseeq(qcmd,"LOGIN") )
		if( newconn )
		if( !strcaseeq(rstat,"OK") ){
			fprintf(ts,"X LOGOUT\r\n");
			/*
			fclose(ts);
			fclose(fs);
			*/
			finishServYY(FL_ARG,Conn);
			CTX_fcloses(FL_ARG,"IMAPserv",Conn,ts,fs);
			ts = fs = NULL;
			ToS = FromS = -1;
			sv1log(">>>> IMAP connection to the server closed.\n");
			/* must clear FSV,FTOSV,FFROMSV if exists */
		}
		if( strcaseeq(qcmd,"LOGIN") )
			imaplog(Conn,qcmd,qarg);
	}
EXIT:
	finishServYY(FL_ARG,Conn);
	CTX_fcloses(FL_ARG,"IMAPserv",Conn,ts,fs);
	CTX_fcloses(FL_ARG,"IMAPclnt",Conn,tc,fc);
	return 0;
}
