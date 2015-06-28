const char *SIGN_stls_c="{FILESIGN=stls.c:20141031194212+0900:c6729bac30a08bc2:Author@DeleGate.ORG:zL8qY/LkxK3wGcJJOjTO2HcpBuoSuBnBA1eN7LgRteSr3CaMBNOfKXl8tmDiFSknRiASDAqkiNtcr2UEI6opZLxNQ02vYzA4wJKsY5vxKxH2c+YZ+6opoGvvKMISzxdy8AoEFgCkBGzGy0XUtLT6Zhc8vN4wuXwUn5Z97jhm+TU=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2004-2008 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	stls.c (STARTTLS)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	STARTTLS

	RFC2487 SMTP
	RFC2595 IMAP and POP3
	RFC2449 POP3 (CAPA STLS)
	RFC2228,RFC4217 FTP
	(RFC2817 HTTP)

History:
	041223	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include "delegate.h"
#include "http.h" /* OREQ_MSG */
#include "filter.h" /* XF_FSV */
#include "fpoll.h"
int isinSSL(int fd);
static int withSTLS_FCL = 0;
static int withSTLS_FSV = 0;

static int STLS_opt = 0;
static double STLS_implicit_wait = 0.25;
static int STLS_wait_set = 0;
static double STLS_implicit_waitSV = 1.0;
static int STLS_wait_setSV = 0;

extern int SSLready;
extern int SSLstart;

void setCFI_IDENT(Connection *Conn,int cid[2],int sv);
void getCFI_IDENT(Connection *Conn,int cid[2],int sv);
int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock);
int beManInTheMiddle(Connection *Conn,FILE *tcp,FILE *fcp);
int insertTLS_CL(Connection *Conn,int client,int server);
#define moved	STLS_moved
int moved(Connection *Conn,FILE *tc,int fd,PCStr(host),int port);
extern int TIMEOUT_STLS;

#ifndef OPT_S /*{*/

int TIMEOUT_STLS = 10*1000;

double STLS_fsvim_wait(double ws){
	if( STLS_wait_setSV ){
		return STLS_implicit_waitSV;
	}
	return ws;
}

void scan_STLS(Connection *Conn,PCStr(stls)){
	CStr(filt,1024);
	CStr(proto,1024);
	CStr(cmapb,1024);
	CStr(map,1024);
	CStr(opt1,1024);
	const char *cmap;
	const char *fp;
	refQStr(np,filt);
	refQStr(op,opt1);
	int fcl = 0;
	int fsv = 0;
	int opt = 0;
	const char *com = "sslway";
	CStr(comb,1024);

	/*
	cmap = wordscanY(stls,AVStr(filt),sizeof(filt),"^:");
	if( *cmap == ':' )
		cmap++;
	cmap = wordscanY(cmap,AVStr(proto),sizeof(proto),"^:");
	if( proto[0] )
		sprintf(cmapb,"starttls/{%s}%s",proto,cmap);
	else	sprintf(cmapb,"starttls%s",cmap);
	*/
	strcpy(filt,"");
	strcpy(proto,"");
	strcpy(map,"");
	scan_Listlist(stls,':',AVStr(filt),AVStr(proto),AVStr(map),VStrNULL,VStrNULL);
	if( proto[0] )
		/*
		sprintf(cmapb,"starttls/{%s}%s%s",proto,*map?":":"",map);
		*/
		sprintf(cmapb,"starttls//{%s}%s%s",proto,*map?":":"",map);
	else	sprintf(cmapb,"starttls%s%s",*map?":":"",map);

	for( fp = filt; *fp;){
		int optL;
		np = wordscanY(fp,AVStr(opt1),sizeof(opt1),"^,");
		optL = 0;

		if( strncaseeq(opt1,"-im",3) ){
			STLS_implicit_wait = -1;
			STLS_wait_set = 1;
			if( (fsv & PF_STLS_DO) && (fcl & PF_STLS_DO)==0 ){
				STLS_implicit_waitSV = -1;
				STLS_wait_setSV = 1;
			}
			goto NEXT;
		}
		if( strncaseeq(opt1,"im",2) ){
			STLS_implicit_wait = Scan_period(opt1+2,'s',0);
			STLS_wait_set = 1;
			if( (fsv & PF_STLS_DO) && (fcl & PF_STLS_DO)==0 ){
				STLS_implicit_waitSV = STLS_implicit_wait;
				STLS_wait_setSV = 1;
			}
			if( STLS_implicit_wait && STLS_implicit_wait < 0.001 )
				STLS_implicit_wait = 0.001;
			goto NEXT;
		}
		if( *opt1 == '-' ){
			ovstrcpy(opt1,opt1+1);
			optL |= PF_STLS_OPT;
		}
		if( op = strchr(opt1,'/') ){
			setVStrPtrInc(op,0);
			if( strncaseeq(op,"ssl",3) ){
				optL |= PF_STLS_SSL;
			}
		}
		if( strcaseeq(opt1,"opt") ){
			opt = PF_STLS_OPT;
		}else
		if( strcaseeq(opt1,"ssl") ){
			opt = PF_STLS_SSL;
		}else
		if( strcaseeq(opt1,"mim") || strcaseeq(opt1,"mitm") ){
			fsv = PF_STLS_DO | opt | optL | PF_MITM_DO;
			fcl = PF_STLS_DO | opt | optL | PF_MITM_DO;
		}else
		if( strcaseeq(opt1,"FSV") || strcaseeq(opt1,"SV") ){
			fsv = PF_STLS_DO | opt | optL;
			if( strneq(op,"im",2) ) fsv |= PF_SSL_IMPLICIT;
		}else
		if( strcaseeq(opt1,"FCL") || strcaseeq(opt1,"CL") ){
			fcl = PF_STLS_DO | opt | optL;
			if( strneq(op,"im",2) ) fcl |= PF_SSL_IMPLICIT;
		}else{
			syslog_ERROR("FILTER[%s]: %s\n",com,fp);
			com = fp;
			if( 1 < num_ListElems(com,':') ){
				sprintf(comb,"{%s}",com);
				com = comb;
			}
			break;
		}
	NEXT:
		fp = np;
		if( *fp == ',' )
			fp++;
	}
	if( fsv & PF_STLS_DO ){
		withSTLS_FSV++;
		sprintf(map,"%s:FSV:%s",com,cmapb);
		if( fsv & PF_MITM_DO  ) Strins(AVStr(map),"--mitm,");
		if( fsv & PF_STLS_SSL ) Strins(AVStr(map),"-ss,");
		if( fsv & PF_SSL_IMPLICIT ) Strins(AVStr(map),"--im,");
		if( fsv & PF_STLS_OPT ) Strins(AVStr(map),"-o,");
		scan_CMAP(Conn,map);
		sv1log("STLS -> CMAP=\"%s\"\n",map);
	}
	if( fcl & PF_STLS_DO ){
		withSTLS_FCL++;
		sprintf(map,"%s:FCL:%s",com,cmapb);
		if( fcl & PF_MITM_DO  ) Strins(AVStr(map),"--mitm,");
		if( fcl & PF_STLS_SSL ) Strins(AVStr(map),"-ss,");
		if( fcl & PF_SSL_IMPLICIT ) Strins(AVStr(map),"--im,");
		if( fcl & PF_STLS_OPT ) Strins(AVStr(map),"-o,");
		scan_CMAP(Conn,map);
		sv1log("STLS -> CMAP=\"%s\"\n",map);
	}
}

#define PF_STLS_ALL (PF_STLS_ON|PF_SSL_ON|PF_STLS_OPT|PF_STLS_DO|PF_STLS_CHECKED)
int clearSTLSX(Connection *Conn,int fmask){
	if( fmask & XF_FCL ){
		Conn->xf_filters &= ~XF_FCL;
		ClientFlags &= ~PF_STLS_ALL;
	}
	if( fmask & XF_FSV ){
		Conn->xf_filters &= ~XF_FSV;
		ServerFlags &= ~PF_STLS_ALL;
	}
	return 0;
}
int clearSTLS(Connection *Conn){
	Conn->xf_filters &= ~(XF_FCL|XF_FSV);
	ClientFlags &= ~PF_STLS_ALL;
	ServerFlags &= ~PF_STLS_ALL;
	return 0;
}
int saveSTLS(PCStr(wh),Connection *Conn,int SF[4]){
	SF[0] = 1;
	SF[1] = Conn->xf_filters;
	SF[2] = ClientFlags; 
	SF[3] = ServerFlags;
	return 0;
}
int restoreSTLS(PCStr(wh),Connection *Conn,int SF[4]){
	if( SF[0] == 1 ){
		Conn->xf_filters = SF[1];
		ClientFlags = SF[2]; 
		ServerFlags = SF[3];
		return 1;
	}else{
		return 0;
	}
}
int uncheckSTLS_SV(Connection *Conn){
	if( (ServerFlags & PF_STLS_ALL) == PF_STLS_CHECKED ){
		ServerFlags &= ~PF_STLS_CHECKED;
		return 1;
	}
	return 0;
}
/*
 * introduced to cope with SERVER=yymux STLS=fcl <= STLS=fsv:yymux ftp://serv.
 * but maybe became unnecessary with fix of protocol matching for STLS=fsv:yymux
 */
int dontDupSTLS(Connection *Conn,PCStr(what)){
	IStr(filter,1024);
	char ctype;
	int with;
	int ndck = Conn->no_dstcheck;
	int ndckpr = Conn->no_dstcheck_proto;
	int ndckpo = Conn->no_dstcheck_port;

	if( (ServerFlags & PF_STLS_ALL) == 0 ){
		return 0;
	}
	if( uncheckSTLS_SV(Conn) ){
		/* might be checked for other (proxy) protocol */
		sv1log("##uncheckSTLS D[%s] R[%s]\n",DFLT_PROTO,REAL_PROTO);
		return 0;
	}
	if( (ctype = ConnType) == 0 ){
		ctype = '-';
	}
	if( ndck || ndckpr || ndckpo ){
		sv1log("##NO-DSTCK={%d %d %d}\n",ndck,ndckpr,ndckpo);
	}
	/* maybe unnecessary, to escape flags set for testing PERMIT */
	Conn->no_dstcheck = 0;
	Conn->no_dstcheck_proto = 0;
	Conn->no_dstcheck_port = 0;
	with = withFilter(Conn,what,"starttls",DST_PROTO,"",AVStr(filter)) ;
	Conn->no_dstcheck = ndck;
	Conn->no_dstcheck_proto = ndckpr;
	Conn->no_dstcheck_port = ndckpo;

	if( with ){
		sv1log("##STARTTLS_with %s DUP: %X [%c][%s] %s\n",what,
			ServerFlags,ctype,DST_PROTO,filter);
		return 0;
	}else{
		sv1log("##STARTTLS_with %s NON: %X [%c][%s] %s\n",what,
			ServerFlags,ctype,DST_PROTO,filter);
		return 1;
	}
}

/* memory a socket to server as a direction connection to the server
 * to be used as ServSock() for deta-connection
 */
int pushFtpServSock(PCStr(wh),Connection *Conn,int svsock){
	if( streq(DST_PROTO,"ftp") )
	if( ToSX < 0 && 0 <= svsock ){
		ToSX = dup(svsock); /* for ServSock() */
	sv1log("----[%s] ftp conn. ServSock() [%d][%d] [%d][%d] (%s)\n",
			wh,ToSX,svsock, ToS,ServerSock,DST_PROTO);
		return 1;
	}
	return 0;
}

int scanConnectFlags(PCStr(wh),PCStr(flags),int flagi){
	int oflagi = flagi;
	if( isinListX(flags,"ssl","/")
	 || isinListX(flags,"ssl",".")
	){
		flagi |= COF_SSL_SV;
	}
	if( oflagi || flagi )
	Verbose("----[%s] scanCF{%s} %X <= %X\n",wh,flags,flagi,oflagi);
	return flagi;
}
int setConnectFlags(PCStr(wh),Connection *Conn,int flagi){
	int oflagi = ConnectFlags;
	ConnectFlags |= flagi;
	if( oflagi || flagi )
	Verbose("----[%s] setCF %X <= %X\n",wh,flagi,oflagi);
	return oflagi;
}
int withPortFilter(Connection *Conn,PCStr(what),PCStr(proto),PCStr(method),PVStr(filter)){
	if( streq(proto,"starttls") )
	if( streq(what,"FCL") && (AccPort_Flags&(SVP_SSL|SVP_STLS)) ){
		Verbose("----PortFilter[%s] [%s][%s] -P%d/%X\n",
			what,proto,method,
			AccPort_Port,AccPort_Flags);
		strcpy(filter,"sslway");
		return 1;
	}
	if( streq(proto,"starttls") )
	if( streq(what,"FSV") && (ConnectFlags&(COF_SSL_SV)) ){
		/* MASTER=host:port/ssl */
		if( ServerFlags & (PF_SSL_ON) ){
			return 0;
		}else{
			Verbose("----PortFilter[%s] [%s][%s]\n",
				what,proto,method,ConnectFlags);
			strcpy(filter,"sslway");
			return 1;
		}
	}
	return 0;
}
int checkWithSTLS(Connection *Conn,PCStr(what),PCStr(proto),PCStr(user)){
	CStr(filter,1024);
	int flags;

	if( streq(what,"FSV") && withSTLS_FSV == 0 ){
		if( ConnectFlags & (COF_SSL_SV) ){
			Verbose("----checkWithSTLS[%s][%s] CF=%X\n",
				what,proto,ConnectFlags);
		}else
		return 0;
	}
	if( streq(what,"FCL") && withSTLS_FCL == 0 ){
		if( AccPort_Flags & (SVP_SSL|SVP_STLS) ){
			Verbose("----checkWithSTLS[%s][%s] -P%d/%X\n",
				what,proto,AccPort_Port,AccPort_Flags);
		}else
		return 0;
	}
	if( withFilter(Conn,what,"starttls",proto,user,AVStr(filter)) ){
		if( streq(what,"FSV") ) /* 0 <= ToS */
		if( (ServerFlags & PF_STLS_CHECKED) == 0 ){
			VA_gethostNAME(ToS,&Conn->sv_sockHOST);
		}
		flags = PF_STLS_CHECKED
		      | PF_STLS_DO
		      | (isinList(filter,"--mitm") ? PF_MITM_DO : 0)
		      | (strneq(filter,"--im",4) ? PF_SSL_IMPLICIT : 0)
		      | ((strncmp(filter,"-o,",3) == 0) ? PF_STLS_OPT : 0)
		      | ((strncmp(filter,"-ss,",4) == 0) ? PF_STLS_SSL : 0);

		if( streq(what,"FSV") ){
			/* disable SSL with SV if CL is not with SSL */
			if( flags & PF_MITM_DO )
			if( ServerFlags & PF_IS_MASTER ){
				sv1log("MITM: suppressed STLS=fsv for MASTER\n");
				flags &= ~PF_STLS_DO;
			}else
			if( (ClientFlags & (PF_SSL_ON/*|PF_MITM_ON*/)) == 0 ){
				flags &= ~PF_STLS_DO;
	if( lTLS() )
	Verbose("MITM: suppressed STLS=fsv for non https client %X[%s]\n",
	ClientFlags,CLNT_PROTO);
			} 
		}
		if( streq(what,"FCL") )
			ClientFlags = (ClientFlags & ~PF_STLS_ON) | flags;
		else	ServerFlags = (ServerFlags & ~PF_STLS_ON) | flags;
		return 1;
	}else{
		flags = PF_STLS_DO|PF_STLS_OPT|PF_STLS_ON;
		if( streq(what,"FCL") )
			ClientFlags = PF_STLS_CHECKED | ClientFlags & ~flags;
		else	ServerFlags = PF_STLS_CHECKED | ServerFlags & ~flags;
		/*
		else	ServerFlags = PF_STLS_CHECKED | ClientFlags & ~flags;
		*/
		return 0;
	}
}
int testWithSTLS(Connection *Conn,PCStr(what),PCStr(proto),PCStr(user)){
	Connection XConn;
	int with;

	XConn = *Conn;
	with = checkWithSTLS(&XConn,what,proto,user);
	Verbose("--test with STLS: %d [%s][%s]\n",with,what,proto);
	return with;
}
int pushPFilter(Connection *Conn,PCStr(proto),PFilter *Pf);;
int pushSTLS_FSV(Connection *Conn,PCStr(proto)){
	/* if app. protocol over it needs SSL too. */
	if( testWithSTLS(Conn,"FSV",REAL_PROTO,"") ){
		/* SSL env. (FDs and tid) must be pushed ... */
		clearSTLS(Conn);
		pushPFilter(Conn,proto,&ServerFilter);
		return 1;
	}
	return 0;
}
int withSTLS_SV(Connection *Conn){
	return ServerFlags & PF_STLS_ON;
}

static int nonSSL_SV(Connection *Conn){
	double Start;
	if( FromS <= 0 ){
		return 1;
	}
	Start = Time();
	if( 0 < PollIn(FromS,(int)(1000*STLS_implicit_waitSV)) ){
		IStr(buf,8);
		int rcc;

		if( !IsAlive(FromS) ){
			sv1log("-- nonSSL_SV ? [%d][%s] Disconnected (%.2f)\n",
				FromS,DST_PROTO,Time()-Start);
		}
		rcc = recvPeekTIMEOUT(FromS,AVStr(buf),sizeof(buf));
		if( 0 < rcc ){
			/* could be '2' in POP, '*' in IMAP, ... */
			sv1log("%d [%X %X %X]\n",rcc,buf[0],buf[1],buf[2]);
			return 1;
		}
	}
	return 0;
}
int willSTLS_SV(Connection *Conn){
	int oflags = ServerFlags;

	if( (ServerFlags & PF_STLS_CHECKED) == 0 ){
		checkWithSTLS(Conn,"FSV",REAL_PROTO,"");

		if( (ClientFlags & PF_MITM_ON)
		 && (ServerFlags & PF_STLS_OPT)
		){
			/* 9.8.0-pre1 STLS=mitm,-fsv
			 * expecting STLS=fsv in the upstream proxy
			 * as PROXY, MASTER, or SOCKS
			 */
			sv1log("-- STLS=mitm,-fsv %X %d,%d,%d\n",ServerFlags,
				toMaster,toProxy,ServViaSocks);
			ServerFlags |= PF_SSL_ON;
			return 0;
		}
		if( ServerFlags & (PF_SSL_ON|PF_STLS_ON) ){
		}else
		if( ServerFlags & PF_STLS_DO )
		if( strcaseeq(DST_PROTO,"http")
		 || strcaseeq(DST_PROTO,"https")
		 || strcaseeq(DST_PROTO,"sockmux")
		 || strcaseeq(DST_PROTO,"tcprelay")
		 || strcaseeq(DST_PROTO,"telnet")
		 || strcaseeq(DST_PROTO,"telnets")
		 || (ServerFlags & PF_SSL_IMPLICIT)
		 || strcaseeq(DST_PROTO,"imaps") && !nonSSL_SV(Conn)
		 || strcaseeq(DST_PROTO,"pop3s") && !nonSSL_SV(Conn)
		){	int fsv;

			if( toProxy
			 && streq(GatewayProto,"http")
			 && streq(DST_PROTO,"https")
			){
				/* SERVER=http + STLS=fsv + PROXY */
				SSLtunnelNego(Conn,DST_HOST,DST_PORT,ToS);
				sv1log("-- PROXY=%s:%d [%s] as SSLTUNNEL\n",
					GatewayHost,GatewayPort,GatewayProto);
			}

			fsv = insertFSVX(Conn,"starttls",DST_PROTO,FromC,ToS);
			if( fsv < 0
			 && (ServerFlags & PF_SSL_IMPLICIT)
			 && streq(DST_PROTO,"ftp")
			){
			   /* 9.9.8 STLS=fsv:ftps for STLS=fsv:ftp */
			   fsv = insertFSVX(Conn,"starttls","ftps",FromC,ToS);
			}
			if( 0 <= fsv ){
				if( strncaseeq(CLNT_PROTO,"ftp",3) ){
					if( ToSX == -1 ){
					ToSX = dup(ToS); /* for ServSock() */
					}
				}
				dup2(fsv,ToS);
				close(fsv);
				ServerFlags |= PF_STLS_ON;
			}
		}
	}
	if( ConnectFlags & COF_TERSE ){
		Verbose("willSTLS_SV[%s]: ServerFlags=%X %X\n",DST_PROTO,
			ServerFlags,p2i(&ServerFlags));
	}else{
		sv1log("willSTLS_SV[%s]: ServerFlags=%X %X\n",DST_PROTO,
			ServerFlags,p2i(&ServerFlags));
	}
	if((ServerFlags & PF_STLS_CAP) == 0 )
	if( ServerFlags & PF_STLS_DONTTRY )
	if( ServerFlags & PF_STLS_OPT ){
		sv1log("WILL NOT TRY STLS -- NOT SUPPORTED and OPTIONAL\n");
		return 0;
	}

	/* this should be applied to any protocols */
	if( streq(DST_PROTO,"smtps")
	 || streq(DST_PROTO,"imaps")
	)
	if( ServerFlags & PF_SSL_ON ){
		if( oflags & PF_SSL_ON ){
			sv1log("-- with SSL already -- %s://%s:%d\n",
				DST_PROTO,DST_HOST,DST_PORT);
		}
		return 0;
	}

	return ServerFlags & PF_STLS_DO;
}

int waitSTLS_CL(Connection *Conn,int timeout){
	if( (ClientFlags & PF_STLS_ON) == 0 )
	{
	double St,Sr,Ss,Sn;
	St = Time();
	if( 0 < PollIn(ClientSock,timeout) ){
		Sr = Time();
		if( isinSSL(ClientSock) ){
			CStr(sts,128);
			int fcl;
			Ss = Time();
			fcl = insertFCLX(Conn,"starttls",CLNT_PROTO,FromC,ToS);
			Sn = Time();
			syslog_ERROR("## STLS ## IMPLICIT SSL ON %d,%d,%d,%d\n",
				ClientSock,FromC,ToC,fcl);
			sprintf(sts,"%.2f %.2f/%.2f %.2f %.2f = %.2f",
				St-ClntConnTime,Sr-St,timeout/1000.0,
				Ss-Sr,Sn-Ss,
				Sn-ClntConnTime);
			sv1log("OK: SSL/cl %s\n",sts);
			if( 0 <= fcl ){
				if( strncaseeq(CLNT_PROTO,"ftp",3) ){
					if( FromC == ClientSock ){ 
						ClientSock = dup(ClientSock);
					}
				}
				if( streq(iSERVER_PROTO,"delegate")
				 || ACT_GENERALIST ){
					/* 9.9.7 for FTP-data via MASTER/ssl */
					ClientSock = dup(ClientSock);
					sv1log("----ClientSock=[%d] <= [%d]\n",
						ClientSock,FromC);
				}
				dup2(fcl,FromC);
				close(fcl);
				ClientFlags |= PF_STLS_ON;
				return 1;
			}
		}
	}
	}
	return 0;
}
int willSTLS_CL(Connection *Conn){
	if( Conn->from_myself ){
		Verbose("## STLS ## no client %X [%d/%d/%d] %X %s:%d\n",
			Conn->from_myself,ClientSock,FromC,ToC,
			ClientFlags,Client_Host,Client_Port);
		return 0;
	}
	if( (ClientFlags & PF_STLS_CHECKED) == 0 ){
		CTX_pushClientInfo(Conn);
		checkWithSTLS(Conn,"FCL",CLNT_PROTO,"");

		if( (ClientFlags & PF_STLS_OPT) == 0 )
		if( ClientFlags & PF_STLS_DO )
		if( 0 < STLS_implicit_wait )
		if( STLS_wait_set == 0 )
		if( STLS_implicit_wait < 10 )
		if( strcaseeq(CLNT_PROTO,"tcprelay")
		 || strcaseeq(CLNT_PROTO,"https")
		){
			waitSTLS_CL(Conn,(int)((8-STLS_implicit_wait)*1000));
		}

		if( ClientFlags & PF_STLS_DO )
		if( 0 < STLS_implicit_wait )
			waitSTLS_CL(Conn,(int)(STLS_implicit_wait*1000));
		/*
		if( 0 < PollIn(ClientSock,(int)(STLS_implicit_wait*1000)) )
		if( isinSSL(ClientSock) ){
			int fcl;
			fcl = insertFCLX(Conn,"starttls",CLNT_PROTO,FromC,ToS);
			syslog_ERROR("## STLS ## IMPLICIT SSL ON %d,%d,%d,%d\n",
				ClientSock,FromC,ToC,fcl);
			if( 0 <= fcl ){
				dup2(fcl,FromC);
				close(fcl);
				ClientFlags |= PF_STLS_ON;
			}
		}
		*/
                HL_popClientInfo(); 
	}
	if( ClientFlags & PF_STLS_ON )
		return 0;
	return ClientFlags & PF_STLS_DO;
}
/*
 * needSTLS() -- TLS must be started before going ahead
 */
int needSTLS(Connection *Conn){
        if( willSTLS_CL(Conn) )
        if( (ClientFlags & PF_STLS_ON) == 0 )
	if( (ClientFlags & PF_STLS_OPT) == 0 )
	if( (ClientFlags & PF_MITM_DO) == 0 )
		return 1;
	return 0;
}
int needSTLS_SV(Connection *Conn){
        if( willSTLS_SV(Conn) )
        if( (ServerFlags & PF_STLS_ON) == 0 )
	if( (ServerFlags & PF_STLS_OPT) == 0 )
		return 1;
	return 0;
}
/* needSTLS_SV() may insert a SSL filter using ToS */
int needSTLS_SVi(Connection *Conn,int server,PCStr(proto)){
	int doSSL;
	int toS;
	IStr(oproto,64);

	toS = ToS;
	ToS = server;
	strcpy(oproto,REAL_PROTO);
	strcpy(REAL_PROTO,proto);
	doSSL = needSTLS_SV(Conn);
	strcpy(REAL_PROTO,oproto);
	ToS = toS;
	return doSSL;
}
int insertTLS_CL(Connection *Conn,int client,int server){
	int fcl = -1;
	if( willSTLS_CL(Conn) ){
		fcl = insertFCLX(Conn,"starttls",CLNT_PROTO,client,server);
		if( 0 <= fcl ){
			ClientFlags |= PF_STLS_ON;
		}
	}
	return fcl;
}
/*
 * insertTLS_SVi() for proxy protocols (SOCKS,MASTER,YYMUX)
 */
int insertTLS_SVi(Connection *Conn,int client,int server,PCStr(proto)){
	int fsv = -1;
	int need;

	if( (ServerFlags & PF_STLS_CHECKED) == 0 ){
		need = needSTLS_SVi(Conn,server,proto);
		sv1log("--insertTLS_SVi %d %X P[%s] R[%s] M<%s>\n",
			need,ServerFlags,proto,REAL_PROTO,ClientAuth.i_meth);
	}
	if( willSTLS_SV(Conn) ){
		fsv = insertFSVX(Conn,"starttls",proto,client,server);
		if( 0 <= fsv ){
			ServerFlags |= PF_STLS_ON;
		}
	}
	return fsv;
}
int insertTLS_SV(Connection *Conn,int client,int server){
	int fsv = -1;
	if( willSTLS_SV(Conn) ){
		if( REAL_PROTO[0] == 0 ){
			sv1log("-WARN ERR insertTLS_SV() no REAL_PROTO (%s)\n",
				DFLT_PROTO);
		}
		fsv = insertFSVX(Conn,"starttls",REAL_PROTO,client,server);
		if( 0 <= fsv ){
			ServerFlags |= PF_STLS_ON;
		}
	}
	return fsv;
}

#include "filter.h"
int HTTP_auth2ident(Connection *Conn,PCStr(auth),AuthInfo *ident,int decomp);
int getServ(Connection *Conn);

void setCFI_IDENT(Connection *Conn,int cid[2],int sv){
	CStr(env,1024);

	IGNRETZ pipe(cid);
	sprintf(env,"CFI_IDENT=%d",cid[1]);
	putenv(stralloc(env));
}
void getCFI_IDENT(Connection *Conn,int cid[2],int sv){
	double St = Time();
	IStr(ids,1024);
	IStr(ident,128);
	int rcc;
	int nready;

	putenv("CFI_IDENT=-1");
	/*
	if( PollIn(cid[0],1000) ){
	}
	9.9.4
	*/
	errno = 0;
	nready = PollIn(cid[0],1000);
	if( nready <= 0 || errno != 0 ){
		putfLog("getCFI_IDENT() nready=%d errno=%d",nready,errno);
	}
	if( 0 < nready ){
		rcc = read(cid[0],ids,sizeof(ids)-1);
		if( 0 < rcc ){
			setVStrEnd(ids,rcc);
			getFieldValue2(ids,"Ident",AVStr(ident),sizeof(ident));
			sv1log("%s-Ident: %.3f %.3f %d <%s>\n",sv?"SV":"CL",
				Time()-ServConnTime,Time()-St,rcc,ident);
		}
	}
	close(cid[0]);
	close(cid[1]);
}

int CTX_moved_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url));
int moved(Connection *Conn,FILE *tc,int fd,PCStr(host),int port){
	CStr(hp,1024);
	CStr(url,1024);
	sprintf(hp,"%s:%d",host,port);
	sprintf(url,"https://%s",hp);
	if( CTX_moved_url_to(Conn,hp,"CONNECT",AVStr(url)) ){
		return 1;
	}
	return 0;
}

int HTTP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc){
/*
	double sws = 0;
	if( strcaseeq(CLNT_PROTO,"https") ){
		if( STLS_implicit_wait < 0.5 ){
			sws = STLS_implicit_wait;
			STLS_implicit_wait = 0.5;
		}
	}
*/
	if( Conn->from_myself ){
		return 0;
	}
	if( willSTLS_CL(Conn) ){
		if( 0 < READYCC(fc) ){
			/* pipelined request */
		}else
		if( 0 < fPollIn(fc,10*1000) ){
			if( ClientFlags & PF_MITM_DO ){
				beManInTheMiddle(Conn,tc,fc);
				if( ClientFlags & PF_SSL_ON ){
					return 1;
				}
			}
			if( isinSSL(fileno(fc)) ){
				int fcl;
				fcl = insertTLS_CL(Conn,FromC,ToS);
				if( fcl < 0 ){
					sv1log("### SSL/cl failure %X %X\n",
						ClientFlags,ServerFlags);
				}else{
				dup2(fcl,ClientSock);
				close(fcl);
				}
				return 1;
			}
		}
	}
	return 0;
}


#define lfprintf SMTP_lfprintf
void SMTP_lfprintf(FILE *log,FILE *tosc,PCStr(fmt),...);
void SMTP_putserv(FILE *log,FILE *fs,FILE *ts,PVStr(resp),PCStr(fmt),...);

int SMTP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc){
	CStr(stat,1024);
	int fcl;

	if( willSTLS_CL(Conn) ){
		SSLstart = 1;
		fcl = insertTLS_CL(Conn,FromC,ToS);
		SSLstart = 0;
		if( 0 <= fcl ){
			lfprintf(NULL,tc,"220 Ready to start TLS\r\n");
			fflush(tc);
			fflush(fc);

			/* wait the completion of SSL negotiation and
			 * initialization in SSLway thread for safety ...
			 */
			PollIn(fcl,TIMEOUT_STLS);

			dup2(fcl,fileno(tc));
			dup2(fcl,fileno(fc));
			close(fcl);
			return 1;
		}
	}
	lfprintf(NULL,tc,"454 A Don't start TLS\r\n");
	fflush(tc);
	return 0;
}
int SMTP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs){
	CStr(stat,1024);
	int fsv;

	if( willSTLS_SV(Conn) ){
		SMTP_putserv(NULL,fs,ts,AVStr(stat),"STARTTLS\r\n");
		if( stat[0] != '2' ){
			goto NOTLS;
		}
		fsv = insertTLS_SV(Conn,FromC,ToS);
		if( fsv < 0 ){
			goto NOTLS;
		}
		dup2(fsv,fileno(ts));
		dup2(fsv,fileno(fs));
		close(fsv);
	}
	return 0;
NOTLS:
	ServerFlags &= ~PF_STLS_ON;
	if( (ServerFlags & PF_STLS_OPT) == 0 )
		return -1;
	else	return 0;
}

int POP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc,PCStr(com),PCStr(arg)){
/*
	if( strcaseeq(com,"CAPA") ){
		if( needSTLS(Conn) ){
			fputs("+OK Capability list follows\r\n",tc);
			fputs("STLS\r\n",tc);
			fputs(".\r\n",tc);
			return 1;
		}
	}
*/
	if( strcaseeq(com,"STLS") ){
		if( willSTLS_CL(Conn) ){
			int fcl;
			SSLstart = 1;
			fcl = insertTLS_CL(Conn,ToC,ToS);
			SSLstart = 0;
			if( 0 <= fcl ){
				fputs("+OK\r\n",tc);
				fflush(tc);

				PollIn(fcl,TIMEOUT_STLS);

				dup2(fcl,fileno(tc));
				dup2(fcl,fileno(fc));
				close(fcl);
			}else{
				fputs("-ERR\r\n",tc);
			}
			return 1;
		}
	}
	return 0;
}
int POP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs,PCStr(user)){
	CStr(resp,1024);

	if( ServerFlags & (PF_SSL_ON|PF_STLS_ON) ){
		return 1;
	}
	if( willSTLS_SV(Conn) ){
		if( strcaseeq(DST_PROTO,"pop3s") ){
			return -3;
		}
		sv1log("POP D-S: STLS to server\n");
		fputs("STLS\r\n",ts);
		fflush(ts);
		if( fgets(resp,sizeof(resp),fs) == NULL )
			return -1;
		sv1log("POP S-D: %s",resp);
		if( *resp == '+' ){
			int fsv;
			fsv = insertTLS_SV(Conn,ToC,ToS);
			if( 0 <= fsv ){
				dup2(fsv,fileno(ts));
				dup2(fsv,fileno(fs));
				close(fsv);
				return 0;
			}
		}else{
			return -2;
		}
	}
	return 0;
}

int IMAP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc,PCStr(tag),PCStr(com),PCStr(arg)){
	if( willSTLS_CL(Conn) == 0 )
		return 0;

	if( strcaseeq(com,"STARTTLS") ){
		int fcl;
		SSLstart = 1;
		fcl = insertTLS_CL(Conn,ToC,ToS);
		SSLstart = 0;
		if( 0 <= fcl ){
			fprintf(tc,"%s OK Begin TLS negotiation\r\n",tag);
			fflush(tc);

			PollIn(fcl,TIMEOUT_STLS);

			dup2(fcl,fileno(tc));
			dup2(fcl,fileno(fc));
			close(fcl);
		}else{
			fprintf(tc,"%s BAD\r\n",tag);
		}
		return 1;
	}
	return 0;
}
int IMAP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs,PCStr(user)){
	CStr(resp,1024);
	CStr(code,1024);

	if( willSTLS_SV(Conn) ){
		fputs("stls0 STARTTLS\r\n",ts);
		fflush(ts);
		if( fgets(resp,sizeof(resp),fs) == NULL )
			return -1;
		*code = 0;
		Xsscanf(resp,"%*s %s",AVStr(code));

		if( strcaseeq(code,"OK") ){
			int fsv;
			fsv = insertTLS_SV(Conn,ToC,ToS);
			if( 0 <= fsv ){
				dup2(fsv,fileno(ts));
				dup2(fsv,fileno(fs));
				close(fsv);
				return 0;
			}
		}else{
			return -2;
		}
	}
	return 0;
}

int FTP_putSTLS_FEAT(Connection *Conn,FILE *tc,int wrap){
	if( (ClientFlags & PF_STLS_DO) )
	if( (ClientFlags & (PF_STLS_ON|PF_SSL_ON)) == 0 )
	{
		if( wrap ) fprintf(tc,"211-Extensions supported\r\n");
		fprintf(tc," AUTH TLS\r\n");
		fprintf(tc," PBSZ\r\n");
		fprintf(tc," PROT\r\n");
		if( wrap ) fprintf(tc,"211 END\r\n");
		return 1;
	}
	return 0;
}

#define comeq(com1,com2) (strcasecmp(com1,com2) == 0)
int FTP_STARTTLS_withCL(Connection *Conn,FILE *tc,FILE *fc,PCStr(com),PCStr(arg)){
	if( comeq(com,"AUTH") ){
		sv1log("#### %s %s\n",com,arg);
		if( comeq(arg,"TLS") || comeq(arg,"SSL") ){
			int fcl;
			if( willSTLS_CL(Conn) )
			{
				SSLstart = 1;
				fcl = insertTLS_CL(Conn,ToC,ToS);
				SSLstart = 0;
			}
			else	fcl = -1;
			if( 0 <= fcl ){
				ClientSock = dup(ClientSock);
				fprintf(tc,"234 OK\r\n");
				fflush(tc);
				fflush(fc);

				PollIn(fcl,TIMEOUT_STLS);

				dup2(fcl,fileno(tc));
				dup2(fcl,fileno(fc));
				close(fcl); /* 9.5.7 bug */
				/* this bug disables disconnection from
				 * the server-side to terminate session
				 */
				return 1;
			}else{
				fprintf(tc,"500 not supported\r\n");
				return 1;
			}
		}
	}else
	if( comeq(com,"PBSZ") ){
		sv1log("#### %s %s\n",com,arg);
		fprintf(tc,"200 OK\r\n");
		if( FtpTLSX_VALID ){
			FtpTLSX->ftp_flags |= FtpTLSX_PBSZ;
			FtpTLSX->ftp_PBSZ = atoi(arg);
		}
		return 1;
	}else
	if( comeq(com,"PROT") ){
		sv1log("#### %s %s\n",com,arg);
		if( arg[0] == 'C' && needSTLS(Conn) ){
			fprintf(tc,"534 forbidden\r\n");
			return 1;
		}
		fprintf(tc,"200 OK\r\n");
		if( FtpTLSX_VALID ){
			FtpTLSX->ftp_flags |= FtpTLSX_PROT;
			FtpTLSX->ftp_PROT = arg[0];
		}
		return 1;
	}
	else
	if( comeq(com,"FEAT") ){
		if( (ClientFlags & PF_STLS_DO) )
		if( (ClientFlags & PF_STLS_OPT) == 0 )
		if( FTP_putSTLS_FEAT(Conn,tc,1) )
			return 1;
	}else
	if( comeq(com,"QUIT")
	){
		return 0;
	}else
	if( needSTLS(Conn) ){
		sv1log("#### needAUTH, rejected %s %s\n",com,arg);
		fprintf(tc,"534 do AUTH first.\r\n");
		fflush(tc);
		return 1;
	}
	return 0;
}
int checkFTP_STLS(Connection *Conn){
	int ctrlSSL;
	int dataSSL;

	ctrlSSL = testWithSTLS(Conn,"FSV","ftp","");
	dataSSL = testWithSTLS(Conn,"FSV","ftp-data","");
	sv1log("--FTP-SSL ctrl:%d data:%d\n",ctrlSSL,dataSSL);
	if( ctrlSSL == 0 ){
		ConnectFlags |= COF_NOCTRLSSL;
	}
	if( dataSSL == 0 ){
		ConnectFlags |= COF_NODATASSL;
	}
	return 0;
}
static int willFTPS_dataSSL_CL(Connection *Conn){
	int dataSSL;
	dataSSL = testWithSTLS(Conn,"FCL","ftp-data","");
	if( dataSSL == 0 ){
		Verbose("--don't SSL for data with client\n");
		return 0;
	}
	return 1;
}
int FTP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs){
	if( REAL_PROTO[0] == 0 ){
		sv1log("--WARN FTP_STARTTLS_withSV no REAL_PROTO (%s)\n",
			DFLT_PROTO);
	}
	if( dontDupSTLS(Conn,"FSV") ){
		return 0;
	}
	if( 0 <= ToS )
	if( willSTLS_SV(Conn) ){
		CStr(resp,128);

		if( ServerFlags & PF_SSL_IMPLICIT ){ /* ftps://serv */
			if( ServerFlags & PF_STLS_ON ){
				return 1;
			}
			strcpy(resp,"200\r\n");
		}else{
		if( ServerFlags & PF_STLS_SSL )
			fprintf(ts,"AUTH SSL\r\n");
		else	fprintf(ts,"AUTH TLS\r\n");
		fflush(ts);
		fgets(resp,sizeof(resp),fs);
			sv1log("--AUTH resp: %s",resp);
			/* 9.9.7 might be a resp. in multi-lines */
		}
		
		if( *resp == '2' ){
			int fsv;
			checkFTP_STLS(Conn);
			fsv = insertTLS_SV(Conn,ToC,ToS);
			if( 0 <= fsv ){
				ToSX = dup(ToS); /* for ServSock() */
				    /* to be closed on closing the server */
				dup2(fsv,fileno(ts));
				dup2(fsv,fileno(fs));
				close(fsv);

				if( (ServerFlags & PF_STLS_SSL) == 0 ){
					/* AUTH TLS */
					if( *resp == '2' ){
						fprintf(ts,"PBSZ 0\r\n");
						fflush(ts);
						fgets(resp,sizeof(resp),fs);
					}
					if( *resp == '2' ){
						if( ConnectFlags&COF_NODATASSL )
						fprintf(ts,"PROT C\r\n");
						else
						fprintf(ts,"PROT P\r\n");
						fflush(ts);
						fgets(resp,sizeof(resp),fs);
					}
				}
				return 1;
			}
		}
		if( (ServerFlags & PF_STLS_OPT) == 0 ){
			return -1;
		}
	}
	return 0;
}
static double STLS_implicit_ftpdata = 0.1;
/* 9.9.2 timeout of FTPS data-SSL in non/half negotiatiated */
static int FTPS_detect_dataSSL(Connection *Conn,int cldata){
	double Timeout;
	double Start,Elp;
	int timeout;
	int nready;
	int pbsz = 0;
	int prot = 0;

	if( !streq(iSERVER_PROTO,"ftps") ){
		return 0;
	}
	if( FtpTLSX_VALID ){
		pbsz = FtpTLSX->ftp_PBSZ;
		if( FtpTLSX->ftp_flags & FtpTLSX_PBSZ )
			pbsz += 1;
		prot = FtpTLSX->ftp_PROT;
	}
	if( FtpTLSX->ftp_flags & FtpTLSX_PBSZ ){ /* got PBSZ (without PROT) */
		if( ClientFlags & PF_STLS_OPT ){ /* STLS=-fcl */
			Timeout = STLS_implicit_ftpdata / 10;
		}else{
			Timeout = STLS_implicit_ftpdata;
		}
		if( STLS_implicit_wait < Timeout ){ /* ex. STLS=fcl,im.001 */
			Timeout = STLS_implicit_wait;
		}
	}else{
		if( STLS_wait_set ){
			Timeout = STLS_implicit_wait;
		}else{
			Timeout = 10.0;
		}
	}
	timeout = (int)(Timeout*1000);
	if( timeout <= 0 )
		timeout = 1;
	Start = Time();
	nready = PollIn(cldata,timeout);
	Elp = Time() - Start;

	if( nready <= 0 ){
		sv1log("## FTP-data: NO SSL detected (%.3f/%.3f) %d %X\n",
			Elp,Timeout,pbsz,prot);
		return -1;
	}
	if( isinSSL(cldata) ){
		sv1log("## FTP-data: SSL detected (%.3f/%.3f) %d %X\n",
			Elp,Timeout,pbsz,prot);
		return 1;
	}else{ /* maybe uploading */
		sv1log("## FTP-data: detected NON SSL (%.3f/%.3f) %d %X\n",
			Elp,Timeout,pbsz,prot);
		return -2;
	}
}
int FTP_dataSTLS_FCL(Connection *Conn,Connection *dataConn,int cldata)
{	int fcldata;

	if( (ClientFlags & PF_STLS_ON) == 0 ){
		return -1;
	}
	if( strcaseeq(iSERVER_PROTO,"ftps")  ){ /* accepted as SERVER=ftps */
		/* 9.9.8 suppress SSL for data-conn. with STLS=fcl:ftps */
		if( willFTPS_dataSSL_CL(Conn) == 0 ){
			return -4;
		}
	}
	if( FtpTLSX_VALID ){
		if( FtpTLSX->ftp_PROT == 'C' ){
			return -2;
		}
		if( FtpTLSX->ftp_PROT == 0 ){
			if( FTPS_detect_dataSSL(Conn,cldata) <= 0 ){
				return -3;
			}
		}
	}
	dataConn->cl.p_flags = ClientFlags & ~PF_STLS_ON;
	fcldata = insertTLS_CL(dataConn,cldata,-1);
	return fcldata;
}
int FTP_dataSTLS_FSV(Connection *Conn,Connection *dataConn,int svdata)
{	int fsvdata;

	if( ServerFlags & PF_SSL_IMPLICIT ){ /* connecting with a ftps serv. */
		/* 9.9.8 suppress SSL for data-conn. with STLS=fsv:ftps */
		/* should be checked for each ftp-data ? */
		if( IsMounted && (ConnectFlags & COF_NODATASSL) == 0 ){
			/* might not be checked yet for MOUNT ftps://server */
			checkFTP_STLS(Conn);
		}
	}
	if( ConnectFlags & COF_NODATASSL ){
		Verbose("--don't SSL for data\n");
		return -1;
	}
	if( (ServerFlags & PF_STLS_ON) == 0 ){
		return -1;
	}
	dataConn->sv.p_flags = ServerFlags & ~PF_STLS_ON;
	SSLstart = 1;
	fsvdata = insertTLS_SV(dataConn,-1,svdata);
	SSLstart = 0;
	if( 0 <= fsvdata ){
		/* should wait command/stat on the control connection ? */
		/* PollIn(FromS,TIMEOUT_STLS); */

		dup2(fsvdata,svdata);
		close(fsvdata);
		/* 9.5.7 bug: this disalbes sending ABOR over SSL
		ToS = svdata;
		*/
		dataConn->sv.p_wfd = svdata;
		return 1;
	}
	return -1;
}

#include <ctype.h>
int STLS_error(Connection *Conn,int fromC){
	int fail = 0;
	int nready;
	char statb[2];
	/*
	char stat;
	*/
	int stat;
	FILE *fst;
	double Start;
	int ni;

	if( ClientFlags & PF_STLS_ON ){
		/* SSLway is active already */
		return 0;
	}

	Start = Time();
	IGNRETZ pipe(CFI_SYNC);
	FromC = fromC;

	if( STLS_wait_set == 0 ){
		if( streq("https",CLNT_PROTO) ){
			STLS_implicit_wait = 2;
		}else
		if( isinList("tcprelay",CLNT_PROTO) ){
			STLS_implicit_wait = 1;
		}else
		if( isinList("ftps,telnets,pop3s,imaps,nntps,ldaps",
			CLNT_PROTO) ){
			STLS_implicit_wait = 2;
		}else
		if( isinList("socks",CLNT_PROTO) ){
			STLS_implicit_wait = 1;
		}
		else
		if( isinList("yysh",CLNT_PROTO) ){
			STLS_implicit_wait = 8;
		}else
		if( isinList("yymux",CLNT_PROTO) ){
			STLS_implicit_wait = 15;
		}else
		if( AccPort_Flags & SVP_SSL ){
			STLS_implicit_wait = 2;
			sv1log("----Port/SSL -P%d.%X\n",
				AccPort_Port,AccPort_Flags);
		}
	}
	if( needSTLS(Conn) ){
		/*
		daemonlog("E","ERROR: SSL/cl is not detected\n");
		*/
daemonlog("E","ERROR: SSL/cl is not detected (%.2f %.2f){%.2f %s %X}\n",
			Start-ClntConnTime,Time()-ClntConnTime,
			STLS_implicit_wait,CLNT_PROTO,AccPort_Flags);
		fail = -1;
		goto EEXIT;
	}
	if( (ClientFlags & PF_STLS_ON) == 0 ){
		/* no sslway is invoked */
		goto EEXIT;
	}

	close(CFI_SYNC[1]); CFI_SYNC[1] = 0;
	fst = fdopen(CFI_SYNC[0],"r");
	statb[0] = statb[1] = stat = 0;
	for(;;){
		nready = fPollIn(fst,1000);
		if( nready == 0 )
		if( stat == 0 || stat == 'W' ){
			sv1log("waiting CFI_SYNC from sslway (%d)...\n",300);
			nready = fPollIn(fst,300*1000);
		}
		if( 0 < nready )
			stat = getc(fst);
		else	stat = -2;
		statb[0] = stat;
		if( isalnum(stat) ){
			sv1log("%.3f CFI_SYNC ready=%d [%X/%s]\n",
				Time()-Start,nready,stat,statb);
		}else{
			sv1log("%.3f CFI_SYNC ready=%d [%X]\n",
				Time()-Start,nready,stat);
		}
		if( nready <= 0 || stat < 0 || stat == EOF )
			break;
		if( stat == '\n' )
			break;
	}
	if( nready <= 0 || stat < 0 || stat == EOF || !IsAlive(fromC) ){
		/*
		daemonlog("E","ERROR: SSL/cl disconnected\n");
		*/
		daemonlog("E","ERROR: SSL/cl disconnected: %d %X %d[%d]\n",
			nready,stat,IsAlive(fromC),fromC);
		fail = -2;
	}
	goto EXIT;
EEXIT:
	close(CFI_SYNC[1]); CFI_SYNC[1] = 0;
EXIT:
	close(CFI_SYNC[0]); CFI_SYNC[0] = 0;
	FromC = -1;
	return fail;
}

/* 050427 extracted from sslway.c */
int SSL_isrecord(int fd,int timeout);
int isinSSL(int fd)
{	unsigned CStr(buf,6); /**/
	int rcc,leng,type,vmaj,vmin;
	int isready,rd;

	isready = inputReady(fd,&rd);
	if( isready <= 0 ){
		return 0;
	}

	if( SSL_isrecord(fd,1) ){
		/* more strict checking of SSL/TLS */
		return 1;
	}else{
		/*
		return 0;
		*/
	}

	buf[0] = 0x7F;
	rcc =
	recvPeekTIMEOUT(fd,AVStr(buf),1);
	if( (buf[0] & 0x80) || buf[0] < 0x20 ){
		syslog_ERROR("isinSSL ? [%X] from client\n",0xFF&buf[0]);
		if( buf[0] == 0x80 ){
			rcc = recvPeekTIMEOUT(fd,AVStr(buf),5);
			syslog_ERROR("SSL Hello?%d [%X %d %d %d %d]\n",rcc,
				buf[0],buf[1],buf[2],buf[3],buf[4]);
			leng = (0x7F&buf[0]) << 8 | buf[1];
			type = buf[2];
			if( type == 1 ){ /* SSLv3 ClientHello */
				vmaj = buf[3];
				vmin = buf[4];
				return 1;
			}
		}
		else
		if( buf[0] == 22 ){ /* ConentType:handshake */
			rcc = recvPeekTIMEOUT(fd,AVStr(buf),sizeof(buf));
			syslog_ERROR("SSL Hello?%d [%X %d %d %d %d]\n",rcc,
				buf[0],buf[1],buf[2],buf[3]<<8|buf[4],buf[5]);
			if( buf[5] == 1 ){
				return 1;
			}
		}
	}
	return 0;
}

int getServPorts(int sc,int sv[]);
int optionalAdminPortSSL(int port);
int defineAdminSTLS(Connection *Conn){
	int admsock;
	int admport = 0;
	const char *host;
	CStr(stls,128);
	refQStr(sp,stls);
	int sv[8],nports;

	nports = getServPorts(8,sv);
	admsock = withAdminPort(&host,&admport);
	if( admport ){
		if( nports == 1 ){
			setVStrPtrInc(sp,'-');
		}
		else
		if( optionalAdminPortSSL(admport) ){
			setVStrPtrInc(sp,'-');
		}
		sprintf(sp,"fcl:*:*:");
		sp += strlen(sp);
		if( *host )
			sprintf(sp,"-P{%s:%d}",host,admport);
		else	sprintf(sp,"-P%d",admport);
		sp += strlen(sp);
		sv1log("Generated default STLS=%s\n",stls);
		DELEGATE_pushEnv("STLS",stls);
		/* this should be regarded simply as -Pxxx/admin/ssl */
	}
	return 0;
}

#endif /*} OPT_S */

/* '"DIGEST-OFF"' */
        
