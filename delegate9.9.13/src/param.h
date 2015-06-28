#ifndef _PARAM_H
#define _PARAM_H
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
Program:	param.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950205	created
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"
const char *DELEGATE_getEnv(PCStr(env));
const char *DELEGATE_getEnvX(PCStr(name),int where);
int param_lock(int where,PCStr(param),const char **pp);
int param_locked(PCStr(param));
const char *parameq(PCStr(param),PCStr(name));

#define PARAM_GENENV	0x01
#define PARAM_EXTOVW	0x02
#define PARAM_MAINARG	0x04
#define PARAM_EXTARG	0x08
#define PARAM_DGENV	0x10
#define PARAM_ENV	0x20
#define PARAM_SCRIPT	0x40
#define PARAM_IMPLANT	0x80
#define	PARAM_ALL	0xFF

extern char P_ABORTLOG[];
extern char P_ACTDIR[];
extern char P_ADMDIR[];
extern char P_ADMIN[];
extern char P_ADMINPASS[];
extern char P_ARPCONF[];
extern char P_AUTH[];
extern char P_AUTHORIZER[];
extern char P_BASEURL[];
extern char P_CACHE[];
extern char P_CACHEARC[];
extern char P_CACHEDIR[];
extern char P_CACHEFILE[];
extern char P_CAPSKEY[];
extern char P_CERTDIR[];
extern char P_CFI[];
extern char P_CGIENV[];
extern char P_CHARCODE[];
extern char P_CHARMAP[];
extern char P_CHARSET[];
extern char P_CHROOT[];
extern char P_CMAP[];
extern char P_CONFOPT[];
extern char P_CONNECT[];
extern char P_COUNTER[];
extern char P_CRON[];
extern char P_CRONS[];
extern char P_CRYPT[];
extern char P_DATAPATH[];
extern char P_DBFILE[];
extern char P_DGOPTS[];
extern char P_DGPATH[];
extern char P_DGROOT[];
extern char P_DGSIGN[];
extern char P_DEBUG_VSTR[];
extern char P_DELAY[];
extern char P_DGDEF[];
extern char P_DELEGATE[];
extern char P_DEST[];
extern char P_DGCONF[];
extern char P_DNSCONF[];
extern char P_DYLIB[];
extern char P_DYCONF[];
extern char P_EDITOR[];
extern char P_ENTR[];
extern char P_CLUSTER[];
extern char P_ERRORLOG[];
extern char P_ETCDIR[];
extern char P_EXECAUTH[];
extern char P_EXPIRE[];
extern char P_EXPIRELOG[];
extern char P_FCL[];
extern char P_FMD[];
extern char P_FSV[];
extern char P_FFROMCL[];
extern char P_FFROMMD[];
extern char P_FFROMSV[];
extern char P_FILEACL[];
extern char P_FILEOWNER[];
extern char P_FILETYPE[];
extern char P_FORWARD[];
extern char P_FTOCL[];
extern char P_FTOMD[];
extern char P_FTOSV[];
extern char P_FTPCONF[];
extern char P_FTPTUNNEL[];
extern char P_FUNC[];
extern char P_GATEWAY[];
extern char P_HOSTS[];
extern char P_HOSTLIST[];
extern char P_HTMLCONV[];
extern char P_HTMUX[];
extern char P_HTTPCONF[];
extern char P_ICP[];
extern char P_ICPCONF[];
extern char P_INETD[];
extern char P_IPV6[];
extern char P_INPARAM[];
extern char P_LDPATH[];
extern char P_LIBDIR[];
extern char P_LIBPATH[];
extern char P_LOG[];
extern char P_LOGDIR[];
extern char P_LOGFILE[];
extern char P_LOGCENTER[];
extern char P_M17N[];
extern char P_MAILSPOOL[];
extern char P_MANAGER[];
extern char P_MASTER[];
extern char P_MASTERP[];
extern char P_MAXIMA[];
extern char P_MHGWCONF[];
extern char P_MIMECONV[];
extern char P_MOUNT[];
extern char P_MYAUTH[];
extern char P_NNTPCONF[];
extern char P_OWNER[];
extern char P_OVERRIDE[];
extern char P_PERMIT[];
extern char P_PAMCONF[];
extern char P_PASSWD[];
extern char P_PGP[];
extern char P_PIDFILE[];
extern char P_POPCONF[];
extern char P_PORT[];
extern char P_PROTOLOG[];
extern char P_PROXY[];
extern char P_QPORT[];
extern char P_RIDENT[];
extern char P_RPORT[];
extern char P_REACHABLE[];
extern char P_REJECT[];
extern char P_RES_AF[];
extern char P_RES_CONF[];
extern char P_RES_DEBUG[];
extern char P_RES_EXPIRE[];
extern char P_RES_LOG[];
extern char P_RES_NS[];
extern char P_RES_RR[];
extern char P_RES_VRFY[];
extern char P_RESOLV[];
extern char P_RELIABLE[];
extern char P_REMITTABLE[];
extern char P_RELAY[];
extern char P_ROUTE[];
extern char P_SAC[];
extern char P_SCREEN[];
extern char P_SERVCONF[];
extern char P_SERVER[];
extern char P_SERVICE[];
extern char P_SHARE[];
extern char P_SMTPCONF[];
extern char P_SMTPGATE[];
extern char P_SMTPSERVER[];
extern char P_SOCKMUX[];
extern char P_SOCKOPT[];
extern char P_SOCKS[];
extern char P_SOCKSCONF[];
extern char P_SOCKSTAP[];
extern char P_SOXCONF[];
extern char P_SRCIF[];
extern char P_SSLTUNNEL[];
extern char P_STDOUTLOG[];
extern char P_STLS[];
extern char P_SUDOAUTH[];
extern char P_SYSLOG[];
extern char P_TLSCONF[];
extern char P_INVITE[];
extern char P_TELNETCONF[];
extern char P_THRUWAY_ENTR[];
extern char P_THRUWAY_EXIT[];
extern char P_TMPDIR[];
extern char P_TUNNEL[];
extern char P_TIMEOUT[];
extern char P_TLS[];
extern char P_TRACELOG[];
extern char P_UMASK[];
extern char P_URICONV[];
extern char P_VARDIR[];
extern char P_VHOSTDIR[];
extern char P_VSAP[];
extern char P_WORKDIR[];
extern char P_XCOM[];
extern char P_XFIL[];
extern char P_YYCONF[];
extern char P_YYMUX[];

extern char P_EXEC_PATH[];
extern char P_EXEC_ENV[];
extern char P_START_TIME[];
extern char P_ALIVE_PEERS[];
extern char P_MASTERPMARK[];
extern char P_INPUT[];
extern char P_SOXINPORTS[];
extern char P_SOXOUTPORT[];
extern char P_SYNCHTMUX[];

typedef struct DGCtx *DGCp;
typedef void scanPFunc(DGCp Conn,PCStr(param));
typedef void scanVFunc(void *Conn,PCStr(param));
typedef int iscanPFunc(DGCp Conn,PCStr(param));
typedef void (*scanPFUNCP)(DGCp Conn,PCStr(param));
int DELEGATE_scanEnv(DGCp Conn,PCStr(name),scanPFUNCP func,...);

int scan_HTMLCONV(void*,PCStr(conv));
int scan_URICONV(void*,PCStr(conv));
void scan_PGP(void*,PCStr(conf));

scanPFunc scan_ARPCONF;
scanPFunc scan_CMAP;
scanPFunc scan_HOSTS;
scanPFunc scan_MASTER;
scanPFunc scan_PROXY;
scanPFunc scan_MOUNT;
scanPFunc scan_PERMIT;
scanPFunc scan_REMITTABLE;
scanPFunc scan_RELIABLE;
scanPFunc scan_REACHABLE;
scanPFunc scan_REJECT;
scanPFunc scan_ROUTE;
scanPFunc scan_CONNECT;
scanPFunc scan_LOG;
scanPFunc scan_AUTH;
scanPFunc scan_AUTHORIZER;
scanPFunc scan_INVITE;
iscanPFunc scan_FILETYPE;
iscanPFunc scan_OWNER;
scanPFunc scan_CHARCODE;
scanPFunc scan_CHARMAP;
scanPFunc scan_CHARSET;
scanPFunc scan_HTTPCONF;
scanPFunc scan_MHGWCONF;
scanPFunc scan_NNTPCONF;
scanPFunc scan_POPCONF;
scanPFunc scan_EXPIRE;
scanPFunc scan_RELAY;
scanPFunc scan_TIMEOUT;
scanPFunc scan_DELAY;
scanPFunc scan_PAMCONF;
scanPFunc scan_MAXIMA;
scanPFunc scan_PORT;
scanPFunc scan_VSAP;
scanPFunc scan_CRON;
scanPFunc scan_CRONS;
scanPFunc scan_SMTPCONF;
iscanPFunc scan_SMTPGATE;
scanPFunc scan_INETD;
scanPFunc scan_IPV6;
scanPFunc scan_ICP;
scanPFunc scan_ICPCONF;
scanPFunc scan_DNSCONF;
scanPFunc scan_SHARE;
scanPFunc scan_SOCKMUX;
scanPFunc scan_SOCKOPT;
scanPFunc scan_SOCKS;
scanPFunc scan_SOCKSCONF;
scanPFunc scan_SOCKSTAP;
scanPFunc scan_SOXCONF;
scanPFunc scan_TELNETCONF;
scanPFunc scan_FTPCONF;
scanPFunc scan_SRCIF;
scanPFunc scan_MYAUTH;
scanPFunc scan_FORWARD;
scanPFunc scan_GATEWAY;
scanPFunc scan_HOSTLIST;
iscanPFunc scan_FTPTUNNEL;
scanPFunc scan_SERVICE;
scanPFunc scan_RIDENT;
scanPFunc scan_LOGFILE;
scanPFunc scan_FCL;
scanPFunc scan_FTOCL;
scanPFunc scan_FFROMCL;
scanPFunc scan_FSV;
scanPFunc scan_FTOSV;
scanPFunc scan_FFROMSV;
scanPFunc scan_BASEURL;
scanPFunc scan_DELEGATE;
scanPFunc scan_STLS;
scanPFunc scan_TLSCONF;
scanPFunc scan_DGSIGN;
scanPFunc scan_SCREEN;
scanPFunc scan_COUNTER;
scanPFunc scan_SYSLOG;
scanPFunc scan_CLUSTER;
scanPFunc scan_DYCONF;
scanPFunc scan_CERTDIR;
void scan_DYLIB(PCStr(conf));
scanPFunc scan_DGDEF;
scanPFunc scan_ENTR;
scanPFunc scan_HTMUX;
scanPFunc scan_M17N;
scanPFunc scan_YYCONF;
scanPFunc scan_YYMUX;

#define INC_SYM		"+="
#define INC_SYM_LEN	(sizeof(INC_SYM)-1)

#define ALIST_IN	"LIST"
#define ALIST_OUT	"TSIL"
#define ACAT_IN		"CAT"
#define ACAT_OUT	"TAC"
#define AC_INC	1
#define AC_CAT	2
#define AC_LIST	4

char *catargs(const char *av[],int a0,int ac);
typedef struct _ArgComp {
	int	ac_mode;
	char	ac_delim;
	char  **ac_av;
	int	ac_an;
	int	ac_ac;
  const	char   *ac_arg; /* catenetated argument */
  const char   *ac_rem;
} ArgComp;

int _initArgComp(ArgComp*);
int _freeArgComp(ArgComp*);
int _isinArgComp(ArgComp*,PCStr(arg));
int _inArgComp(ArgComp*,PCStr(arg));
int _outArgComp(ArgComp*,PCStr(arg));
char *_catArgComp(ArgComp*);
int _scanArgComp(ArgComp*,PVStr(com),PCStr(line));
int _flushArgComp(ArgComp*);

#define ArgCompAn		Acmp->ac_an
#define ArgCompAc		Acmp->ac_ac
#define ArgCompAv		Acmp->ac_av
#define ArgCompArg		Acmp->ac_arg
#define ArgCompMode		Acmp->ac_mode
#define ArgCompRem		Acmp->ac_rem

#define defineArgComp		ArgComp Acm,*Acmp = &Acm
#define initArgComp()		_initArgComp(Acmp)
#define freeArgComp()		_freeArgComp(Acmp)
#define isinArgComp(arg)	_isinArgComp(Acmp,arg)
#define inArgComp(arg)		_inArgComp(Acmp,arg)
#define outArgComp(arg)		_outArgComp(Acmp,arg)
#define catArgComp()		_catArgComp(Acmp)
#define scanArgComp(com,line)	_scanArgComp(Acmp,com,line)
#define flushArgComp()		_flushArgComp(Acmp)

#endif
