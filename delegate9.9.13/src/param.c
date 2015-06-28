/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	param.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950205	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include <stdio.h>
#include "delegate.h"
#include "param.h"

char P_ABORTLOG[] = "ABORTLOG";
char P_ACTDIR[]   = "ACTDIR";
char P_ADMDIR[]   = "ADMDIR";
char P_ADMIN[]    = "ADMIN";
char P_ADMINPASS[] = "ADMINPASS";
char P_ARPCONF[]  = "ARPCONF";
char P_AUTH[]     = "AUTH";
char P_AUTHORIZER[] = "AUTHORIZER";
char P_BASEURL[]  = "BASEURL";
char P_CACHE[]    = "CACHE";
char P_CACHEARC[] = "CACHEARC";
char P_CACHEDIR[] = "CACHEDIR";
char P_CACHEFILE[]= "CACHEFILE";
char P_CAPSKEY[]  = "CAPSKEY";
char P_CERTDIR[]  = "CERTDIR";
char P_CFI[]      = "CFI";
char P_CGIENV[]   = "CGIENV";
char P_CHARCODE[] = "CHARCODE";
char P_CHARMAP[]  = "CHARMAP";
char P_CHARSET[]  = "CHARSET";
char P_CHROOT[]   = "CHROOT";
char P_CLUSTER[]  = "CLUSTER";
char P_CMAP[]     = "CMAP";
char P_CRON[]     = "CRON";
char P_CRONS[]    = "CRONS";
char P_CRYPT[]    = "CRYPT";
char P_CONFOPT[]  = "CONFOPT";
char P_CONNECT[]  = "CONNECT";
char P_COUNTER[]  = "COUNTER";
char P_DATAPATH[] = "DATAPATH";
char P_DBFILE[]   = "DBFILE";
char P_DGDEF[]    = "DGDEF";
char P_DGOPTS[]   = "DGOPTS";
char P_DGPATH[]   = "DGPATH";
char P_DGROOT[]   = "DGROOT";
char P_DGSIGN[]   = "DGSIGN";
char P_DEBUG_VSTR[] = "DEBUG_VSTR";
char P_DELAY[]    = "DELAY";
char P_DELEGATE[] = "DELEGATE";
char P_DEST[]     = "DEST";
char P_DGCONF[]   = "DGCONF";
char P_DNSCONF[]  = "DNSCONF";
char P_DYCONF[]   = "DYCONF";
char P_DYLIB[]    = "DYLIB";
char P_EDITOR[]   = "EDITOR";
char P_ENTR[]     = "ENTR";
char P_ERRORLOG[] = "ERRORLOG";
char P_ETCDIR[]   = "ETCDIR";
char P_EXECAUTH[] = "EXECAUTH";
char P_EXPIRE[]   = "EXPIRE";
char P_EXPIRELOG[]= "EXPIRELOG";
char P_FCL[]      = "FCL";
char P_FMD[]      = "FMD";
char P_FSV[]      = "FSV";
char P_FFROMCL[]  = "FFROMCL";
char P_FFROMSV[]  = "FFROMSV";
char P_FFROMMD[]  = "FFROMMD";
char P_FILEACL[]  = "FILEACL";
char P_FILEOWNER[]= "FILEOWNER";
char P_FILETYPE[] = "FILETYPE";
char P_FORWARD[]  = "FORWARD";
char P_FTOCL[]    = "FTOCL";
char P_FTOMD[]    = "FTOMD";
char P_FTOSV[]    = "FTOSV";
char P_FTPCONF[]  = "FTPCONF";
char P_FTPTUNNEL[] = "FTPTUNNEL";
char P_FUNC[]     = "FUNC";
char P_GATEWAY[]  = "GATEWAY";
char P_HOSTS[]    = "HOSTS";
char P_HOSTLIST[] = "HOSTLIST";
char P_HTMLCONV[] = "HTMLCONV";
char P_HTMUX[]    = "HTMUX";
char P_HTTPCONF[] = "HTTPCONF";
char P_ICP[]      = "ICP";
char P_ICPCONF[]  = "ICPCONF";
char P_INETD[]    = "INETD";
char P_IPV6[]     = "IPV6";
char P_INPARAM[]  = "INPARAM";
char P_LDPATH[]   = "LDPATH";
char P_LIBDIR[]   = "LIBDIR";
char P_LIBPATH[]  = "LIBPATH";
char P_LOG[]      = "LOG";
char P_LOGDIR[]   = "LOGDIR";
char P_LOGFILE[]  = "LOGFILE";
char P_LOGCENTER[]= "LOGCENTER";
char P_M17N[]     = "M17N";
char P_MAILSPOOL[]= "MAILSPOOL";
char P_MANAGER[]  = "MANAGER";
char P_MASTER[]   = "MASTER";
char P_MASTERP[]  = "MASTERP";
char P_MAXIMA[]   = "MAXIMA";
char P_MHGWCONF[] = "MHGWCONF";
char P_MIMECONV[] = "MIMECONV";
char P_MOUNT[]    = "MOUNT";
char P_MYAUTH[]   = "MYAUTH";
char P_NNTPCONF[] = "NNTPCONF";
char P_OWNER[]    = "OWNER";
char P_OVERRIDE[] = "OVERRIDE";
char P_PERMIT[]   = "PERMIT";
char P_REMITTABLE[] = "REMITTABLE";
char P_PAMCONF[]  = "PAMCONF";
char P_PASSWD[]   = "PASSWD";
char P_PGP[]      = "PGP";
char P_PIDFILE[]  = "PIDFILE";
char P_POPCONF[]  = "POPCONF";
char P_PORT[]     = "PORT";
char P_PROTOLOG[] = "PROTOLOG";
char P_PROXY[]    = "PROXY";
char P_QPORT[]    = "QPORT";
char P_RIDENT[]   = "RIDENT";
char P_RPORT[]    = "RPORT";
char P_REACHABLE[]= "REACHABLE";
char P_REJECT[]   = "REJECT";
char P_RELIABLE[] = "RELIABLE";
char P_RES_AF[]   = "RES_AF";
char P_RES_CONF[] = "RES_CONF";
char P_RES_DEBUG[]= "RES_DEBUG";
char P_RES_EXPIRE[] = "RES_EXPIRE";
char P_RES_LOG[]  = "RES_LOG";
char P_RES_NS[]   = "RES_NS";
char P_RES_RR[]   = "RES_RR";
char P_RES_VRFY[] = "RES_VRFY";
char P_RES_WAIT[] = "RES_WAIT";
char P_RESOLV[]   = "RESOLV";
char P_RELAY[]    = "RELAY";
char P_ROUTE[]    = "ROUTE";
char P_SAC[]      = "SAC";
char P_SCREEN[]   = "SCREEN";
char P_SERVCONF[] = "SERVCONF";
char P_SERVER[]   = "SERVER";
char P_SERVICE[]  = "SERVICE";
char P_SHARE[]    = "SHARE";
char P_SMTPCONF[] = "SMTPCONF";
char P_SMTPGATE[] = "SMTPGATE";
char P_SMTPSERVER[] = "SMTPSERVER";
char P_SOCKMUX[]  = "SOCKMUX";
char P_SOCKOPT[]  = "SOCKOPT";
char P_SOCKS[]    = "SOCKS";
char P_SOCKSCONF[]= "SOCKSCONF";
char P_SOCKSTAP[] = "SOCKSTAP";
char P_SOXCONF[]  = "SOXCONF";
char P_SRCIF[]    = "SRCIF";
char P_SSLTUNNEL[] = "SSLTUNNEL";
char P_STDOUTLOG[] = "STDOUTLOG";
char P_STLS[]     = "STLS";
char P_SUDOAUTH[] = "SUDOAUTH";
char P_SYSLOG[]   = "SYSLOG";
char P_TLSCONF[]  = "TLSCONF";
char P_INVITE[]   = "INVITE";
char P_TELNETCONF[] = "TELNETCONF";
char P_THRUWAY_ENTR[] = "THRUWAY_ENTR";
char P_THRUWAY_EXIT[] = "THRUWAY_EXIT";
char P_TMPDIR[]   = "TMPDIR";
char P_TUNNEL[]   = "TUNNEL";
char P_TIMEOUT[]  = "TIMEOUT";
char P_TLS[]      = "TLS";
char P_TRACELOG[] = "TRACELOG";
char P_UMASK[]    = "UMASK";
char P_URICONV[]  = "URICONV";
char P_VARDIR[]   = "VARDIR";
char P_VHOSTDIR[] = "VHOSTDIR";
char P_VSAP[]     = "VSAP";
char P_WORKDIR[]  = "WORKDIR";
char P_XCOM[]     = "XCOM";
char P_XFIL[]     = "XFIL";
char P_YYCONF[]   = "YYCONF";
char P_YYMUX[]    = "YYMUX";

char P_EXEC_PATH[]   = "_execPath";
char P_EXEC_ENV[]    = "_execEnv";
char P_START_TIME[]  = "_startTime";
char P_ALIVE_PEERS[] = "_alivePeers";
char P_MASTERPMARK[] = "_masterp";
char P_INPUT[]       = "_input";
char P_SOXINPORTS[]  = "_soxInPorts";
char P_SOXOUTPORT[]  = "_soxOutPort";
char P_SYNCHTMUX[]   = "_syncHTMUX";
char P_ISSERVICE[]   = "_isService";
char P_SERVERPID[]   = "_ServerPid";


#define NOT	0	/* not yet supported */
#define EXP	1	/* experimental */
#define STD	2	/* current standard */
#define DIS	3	/* discurraged */
#define OBS	4	/* obsolete */
#define INT	5	/* internal use */

typedef struct {
  const	char	*p_name;
	int	 p_stat;
  const	char	*p_mssg;
  const char	*p_type;
	char	 p_mpass;	/* pass to private-MASTER */
	char	 p_fpass;	/* pass to external filter program */
	char	 p_spass;	/* pass to spawned self */
     scanPFUNCP	 p_scanner;
	int	 p_breaksticky;
	short	 p_status;
	char	 p_locked;
	char	 p_defined;
} ParamSpec;

/* p_status */
#define PS_DEFINED	0x0001
#define PS_LOCKED	0x0002

#define M0	NULL
static char M1[] = "use PERMIT for it.";
static char M2[] = "use CHARCODE for it.";

static const char T1s[] = "11"; /* single */
static const char T1e[] = "1e"; /* e-mail address */
static const char T1d[] = "1d"; /* directory */
static const char T1h[] = "1h"; /* host */
static const char T1u[] = "1u"; /* url */
static const char T1f[] = "1f"; /* file */
static const char T1p[] = "*d"; /* list of ordered directories */
static const char Tnc[] = "*c"; /* with CMAP */
static const char Tno[] = "*o"; /* -X option */
static const char Tns[] = "*s"; /* specific */
static const char Tnu[] = "*u"; /* list of URLs */

static ParamSpec params[] = {
{ "" },
{ P_ABORTLOG,	STD,M0,T1f,1,1},
{ P_ACTDIR,	STD,M0,T1d,1,1},
{ P_ADMDIR,	STD,M0,T1d,1,1},
{ P_ADMIN,	STD,M0,T1e,1,1},
{ P_ADMINPASS,	STD,M0,T1s,1,1},
{ P_ARPCONF,	EXP,M0,T1s,1,1},
{ P_AUTH,	STD,M0,Tns,1,1},
{ P_AUTHORIZER,	STD,M0,Tnc,0,1},
{ P_BASEURL,	STD,M0,T1u,0,1, 0,scan_BASEURL},
{ P_CACHE,	EXP,M0,Tns,1,1},
{ P_CACHEARC,	EXP,M0,T1s,1,1},
{ P_CACHEDIR,	STD,M0,T1d,1,1},
{ P_CACHEFILE,	STD,M0,T1f,1,1},
{ P_CAPSKEY,	EXP,M0,Tns,1,1},
{ P_CERTDIR,	STD,M0,T1d,1,1},
{ P_CFI,	STD,M0,T1s,1,1},
{ P_CGIENV,	STD,M0,T1s,1,1},
{ P_CHARCODE,	STD,M0,Tns,0,1},
{ P_CHARMAP,	EXP,M0,Tns,0,1},
{ P_CHARSET,	STD,M0,Tns,0,1},
{ P_CHROOT,	STD,M0,T1d,1,1},
{ P_CLUSTER,	EXP,M0,T1f,1,1},
{ P_CMAP,	STD,M0,Tnc,0,0},
{ P_CONFOPT,	EXP,M0,T1s,0,0},
{ P_CONNECT,	EXP,M0,Tnc,1,1},
{ P_COUNTER,	EXP,M0,T1s,1,1},
{ P_CRON,	EXP,M0,Tns,0,0},
{ P_CRONS,	EXP,M0,Tns,0,0},
{ P_CRYPT,	EXP,M0,T1s,1,1},
{ P_DATAPATH,	EXP,M0,T1p,1,1},
{ P_DBFILE,	EXP,M0,T1s,1,1},
{ P_DGDEF,	STD,M0,T1s,1,1},
{ P_DGOPTS,	STD,M0,Tno,1,1},
{ P_DGPATH,	STD,M0,T1p,1,1},
{ P_DGROOT,	STD,M0,T1d,1,1},
{ P_DGSIGN,	STD,M0,Tns,1,1},
{ P_DEBUG_VSTR,	STD,M0,T1s,1,1},
{ P_DELAY,	STD,M0,Tns,0,1, 0,scan_DELAY},
{ P_DELEGATE,	STD,M0,T1s,0,1, 0,scan_DELEGATE},
{ P_DEST,	EXP,M0,Tns,1,1},
{ P_DGCONF,	EXP,M0,T1s,1,1},
{ P_DNSCONF,	EXP,M0,Tns,1,1},
{ P_DYCONF,	EXP,M0,T1u,1,1},
{ P_DYLIB,	EXP,M0,T1p,1,1},
{ P_EDITOR,	STD,M0,T1f,1,1},
{ P_ENTR,	STD,M0,T1u,1,1},
{ P_ERRORLOG,	STD,M0,T1f,1,1},
{ P_ETCDIR,	STD,M0,T1d,1,1},
{ P_EXECAUTH,	EXP,M0,T1s,1,1},
{ P_EXPIRE,	STD,M0,Tns,1,1},
{ P_EXPIRELOG,	STD,M0,T1f,1,1},
{ P_FCL,	EXP,M0,T1s,0,0, 0,scan_FCL},
{ P_FMD,	EXP,M0,T1s,0,0},
{ P_FSV,	EXP,M0,T1s,0,0, 0,scan_FSV},
{ P_FFROMCL,	EXP,M0,T1s,0,0, 0,scan_FFROMCL},
{ P_FFROMMD,	EXP,M0,T1s,0,0},
{ P_FFROMSV,	EXP,M0,T1s,0,0, 0,scan_FFROMSV},
{ P_FILEACL,	EXP,M0,Tns,0,0},
{ P_FILEOWNER,	EXP,M0,Tns,0,0},
{ P_FILETYPE,	EXP,M0,Tns,0,0},
{ P_FORWARD,	EXP,M0,Tnc,0,0},
{ P_FTOCL,	EXP,M0,T1s,0,0, 0,scan_FTOCL},
{ P_FTOMD,	EXP,M0,T1s,0,0},
{ P_FTOSV,	EXP,M0,T1s,0,0, 0,scan_FTOSV},
{ P_FTPCONF,	EXP,M0,Tns,1,1},
{ P_FTPTUNNEL,	EXP,M0,Tns,1,1},
{ P_FUNC,	EXP,M0,T1s,0,0},
{ P_GATEWAY,	EXP,M0,Tnc,0,0},
{ P_HOSTS,	STD,M0,Tns,1,1},
{ P_HOSTLIST,	STD,M0,Tns,1,1},
{ P_HTMLCONV,	STD,M0,Tns,0,1},
{ P_HTMUX,	EXP,M0,T1h,0,1},
{ P_HTTPCONF,	STD,M0,Tns,0,1},
{ P_ICP,	STD,M0,Tns,0,0},
{ P_ICPCONF,	STD,M0,Tns,0,0},
{ P_INETD,	EXP,M0,Tns,0,0},
{ P_IPV6,	EXP,M0,Tns,0,0},
{ P_INPARAM,	EXP,M0,T1s,0,0},
{ P_LDPATH,	EXP,M0,T1p,1,1},
{ P_LIBDIR,	EXP,M0,T1d,1,1},
{ P_LIBPATH,	EXP,M0,T1p,1,1},
{ P_LOG,	EXP,M0,Tns,1,1},
{ P_LOGDIR,	STD,M0,T1d,1,1},
{ P_LOGFILE,	STD,M0,T1f,1,1, 0,scan_LOGFILE},
{ P_LOGCENTER,	STD,M0,T1u,1,1},
{ P_M17N,	EXP,M0,Tns,1,1},
{ P_MAILSPOOL,	STD,M0,T1d,1,1},
{ P_MANAGER,	OBS,M0,T1e,1,1},
{ P_MASTER,	STD,M0,Tnc,0,0},
{ P_MASTERP,	STD,M0,T1s,0,0},
{ P_MAXIMA,	EXP,M0,Tns,1,1, 0,scan_MAXIMA},
{ P_MHGWCONF,	EXP,M0,T1s,1,1},
{ P_MIMECONV,	STD,M0,Tns,0,1},
{ P_MOUNT,	STD,M0,Tns,0,0},
{ P_MYAUTH,	STD,M0,Tnc,0,0},
{ P_NNTPCONF,	EXP,M0,Tns,1,1},
{ P_OWNER,	STD,M0,T1s,1,1},
{ P_OVERRIDE,	EXP,M0,T1s,0,0},
{ P_PERMIT,	STD,M0,Tnc,0,0},
{ P_PAMCONF,	STD,M0,Tns,0,0},
{ P_PASSWD,	EXP,M0,T1s,1,1},
{ P_PGP,	STD,M0,Tns,0,0},
{ P_PIDFILE,	STD,M0,T1f,1,1},
{ P_POPCONF,	EXP,M0,Tns,0,0},
{ P_PORT,	EXP,M0,Tns,0,0},
{ P_PROTOLOG,	STD,M0,T1f,1,1},
{ P_PROXY,	STD,M0,Tnc,0,0},
{ P_QPORT,	EXP,M0,T1s,1,1},
{ P_RIDENT,	EXP,M0,T1s,1,1, 0,scan_RIDENT},
{ P_RPORT,	EXP,M0,T1s,1,1},
{ P_REACHABLE,	DIS,M1,Tns,0,0},
{ P_REJECT,	DIS,M1,Tnc,0,0},
{ P_RELIABLE,	DIS,M1,Tns,0,0},
{ P_REMITTABLE,	STD,M0,Tns,0,0},
{ P_RES_AF,	STD,M0,T1s,1,1},
{ P_RES_CONF,	STD,M0,T1s,1,1},
{ P_RES_DEBUG,	STD,M0,T1s,1,1},
{ P_RES_EXPIRE,	EXP,M0,T1s,1,1},
{ P_RES_LOG,	STD,M0,T1s,1,1},
{ P_RES_NS,	STD,M0,T1s,1,1},
{ P_RES_RR,	STD,M0,T1s,1,1},
{ P_RES_VRFY,	STD,M0,T1s,1,1},
{ P_RES_WAIT,	STD,M0,T1s,1,1},
{ P_RESOLV,	STD,M0,T1s,1,1},
{ P_RELAY,	DIS,M1,Tnc,0,0},
{ P_ROUTE,	STD,M0,Tnc,1,1},
{ P_SAC,	EXP,M0,Tns,1,1},
{ P_SCREEN,	STD,M0,Tns,0,0},
{ P_SERVCONF,	STD,M0,Tns,0,0},
{ P_SERVER,	STD,M0,T1u,0,0},
{ P_SERVICE,	EXP,M0,Tns,0,0},
{ P_SHARE,	EXP,M0,T1s,1,1},
{ P_SMTPCONF,	STD,M0,Tns,1,1},
{ P_SMTPGATE,	STD,M0,T1d,1,1},
{ P_SMTPSERVER,	STD,M0,T1h,0,0},
{ P_SOCKMUX,	EXP,M0,Tnu,1,1},
{ P_SOCKOPT,	STD,M0,Tns,1,1},
{ P_SOCKS,	STD,M0,Tnc,1,1},
{ P_SOCKSCONF,	EXP,M0,Tns,1,1},
{ P_SOCKSTAP,	EXP,M0,Tns,1,1},
{ P_SOXCONF,	STD,M0,Tns,1,1},
{ P_SRCIF,	STD,M0,Tnc,1,1},
{ P_SSLTUNNEL,	EXP,M0,T1h,1,1},
{ P_STDOUTLOG,	EXP,M0,T1f,1,1},
{ P_STLS,	EXP,M0,Tnc,1,1},
{ P_SUDOAUTH,	EXP,M0,T1s,1,1},
{ P_SYSLOG,	EXP,M0,Tnu,1,1},
{ P_INVITE,	EXP,M0,T1s,1,1},
{ P_TELNETCONF,	EXP,M0,Tns,0,0},
{ P_THRUWAY_ENTR,EXP,M0,T1s,0,0},
{ P_THRUWAY_EXIT,EXP,M0,T1s,0,0},
{ P_TMPDIR,	STD,M0,T1d,1,1},
{ P_TUNNEL,	STD,M0,T1s,1,1},
{ P_TIMEOUT,	STD,M0,Tns,1,1, 0,scan_TIMEOUT},
{ P_TLS,	EXP,M0,Tns,1,1},
{ P_TLSCONF,	EXP,M0,Tns,1,1},
{ P_TRACELOG,	EXP,M0,T1f,1,1},
{ P_UMASK,	STD,M0,T1s,1,1},
{ P_URICONV,	STD,M0,Tns,0,1},
{ P_VARDIR,	STD,M0,T1d,1,1},
{ P_VHOSTDIR,	STD,M0,T1d,1,1},
{ P_VSAP,	EXP,M0,Tns,0,0},
{ P_WORKDIR,	STD,M0,T1d,1,1},
{ P_XCOM,	EXP,M0,T1s,0,0},
{ P_XFIL,	EXP,M0,T1s,0,0},
{ P_YYCONF,	EXP,M0,T1s,0,0},
{ P_YYMUX,	EXP,M0,Tnc,0,0},

{ P_EXEC_PATH,  INT,M0,T1s,0,0},
{ P_EXEC_ENV,	INT,M0,T1s,0,0},
{ P_START_TIME, INT,M0,T1s,0,0},
{ P_ALIVE_PEERS,INT,M0,T1s,0,0},
{ P_MASTERPMARK,INT,M0,T1s,0,0},
{ P_INPUT,	INT,M0,T1s,0,0},
{ P_SOXINPORTS, INT,M0,T1s,0,0},
{ P_SOXOUTPORT, INT,M0,T1s,0,0},
{ P_SYNCHTMUX,  INT,M0,T1s,0,0},
{ P_ISSERVICE,  INT,M0,T1s,0,0},
{ P_SERVERPID,  INT,M0,T1s,0,0},
{ 0 }
};

void lsParams(FILE *out){
	int fi;
	const char *name;
	for( fi = 1; name = params[fi].p_name; fi++ )
		if( *name != '_' )
		if( params[fi].p_stat != OBS )
		fprintf(out,"%-15s ",name);
}

#define PFX_LOCK	".lock."
static int lockpfx(PCStr(param),const char **pparam){
	const char *pp;
	if( pp = strheadstrX(param,PFX_LOCK,0) ){
		if( pparam ) *pparam = pp;
		return 1;
	}
	return 0;
}
const char *paramName(int pi){
	if( 1 <= pi && pi < elnumof(params) )
		return params[pi].p_name;
	return 0;
}
int paramX(PCStr(param),int nameonly){
	int pi;
	const char *name1;
	const char *dp;

	for( pi = 1; pi < elnumof(params); pi++ ){
		name1 = params[pi].p_name;
		if( name1 == 0 )
			break;
		if( dp = strheadstrX(param,name1,0) ){
			if( *dp == '=' || *dp == 0 && nameonly ){
				return pi;
			}
		}
	}
	return 0;
}
static ParamSpec *paramp(PCStr(param),int nameonly){
	int pi;
	if( pi = paramX(param,nameonly) ){
		return &params[pi];
	}
	return 0;
}
void enableParams(PCStr(param),int enable){
	int pi;
	ParamSpec *p1;
	if( streq(param,"ALL") ){
		for( pi = 0; pi < elnumof(params); pi++ ){
			p1 = &params[pi];
			if( 0 < enable )
				p1->p_status &= ~PS_LOCKED;
			else	p1->p_status |=  PS_LOCKED;
		}
	}else{
		if( p1 = paramp(param,1) ){
			if( 0 < enable )
				p1->p_status &= ~PS_LOCKED;
			else	p1->p_status |=  PS_LOCKED;
		}
	}
}
int paramMulti(PCStr(param)){
	ParamSpec *p1;
	if( p1 = paramp(param,1) ){
		if( p1->p_type[0] == '*' )
			return 1;
	}
	return 0;
}
int param_lock(int where,PCStr(param),const char **pparam){
	ParamSpec *pp;
	int dolock = 0;

	if( lockpfx(param,&param) ){
		dolock = 1;
		if( streq(param,"all") ){
			int pi;
			for( pi = 0; pi < elnumof(params); pi++ ){
				pp = &params[pi];
				if( pp->p_status & PS_DEFINED ){
					pp->p_status |= PS_LOCKED;
					pp->p_locked |= pp->p_defined;
				}
			}
			if( pparam ) *pparam = "";
			return -1;
		}
	}
	else
	if( param[0] != '-' && strchr(param,'=') == 0 ){
		return 0;
	}

	if( pp = paramp(param,dolock) ){
		int isdef = pp->p_status & PS_DEFINED;

		pp->p_status |= PS_DEFINED;
		pp->p_defined |= where;

		if( pp->p_status & PS_LOCKED ){
			fprintf(stderr,"?? Can't %sdefine locked param: %s\n",
				isdef?"RE":"",param);
			return -1;
		}else{
			if( dolock ){
				pp->p_status |= PS_LOCKED;
				pp->p_locked |= where;
				if( pparam ) *pparam = param;
			}
			return 0;
		}
	}else{
		if( dolock )
		fprintf(stderr,"?? Can't lock unknown param: %s\n",param);
		return 0;
	}
}
int param_locked(PCStr(param)){
	ParamSpec *pp;
	int dolock = 0;
	if( lockpfx(param,&param) ){
		dolock = 1;
	}
	if( pp = paramp(param,dolock) ){
		return pp->p_status & PS_LOCKED;
	}
	return 0;
}

int script_asis(PCStr(param))
{
	if( streq(param,P_CRON)  ) return 1;
	if( streq(param,P_INETD) ) return 1;
	return 0;
}

scanPFUNCP param_scanner(PCStr(param)/*,int breaksticky*/)
{	int pi,nlen;
	const char *name;

	for( pi = 0; name = params[pi].p_name; pi++ ){
		nlen = strlen(name);
		if( strncmp(param,name,nlen) == 0 )
		if( param[nlen] == '=' ){
			return params[pi].p_scanner;
		}
	}
	return 0;
}

int check_paramX(PCStr(param),int warn,PVStr(diag));
int check_param(PCStr(param),int warn)
{
	return check_paramX(param,warn,VStrNULL);
}
int check_paramX(PCStr(param),int warn,PVStr(diag))
{	const char *pn;
	const char *pm;
	const char *dp;
	int pi;
	const char *name;
	CStr(nameb,128);

	if( diag ) setVStrEnd(diag,0);
	if( lockpfx(param,&param) ){
	}

	if( dp = strchr(param,'=') ){
		strncpy(nameb,param,dp-param); setVStrEnd(nameb,dp-param);
		name = nameb;
	}else	name = param;

	for( pi = 0; pn = params[pi].p_name; pi++ ){
	    if( strcmp(pn,name) == 0  ){
		if( warn && params[pi].p_stat == OBS ){
			sv1log("Warning: Obsoleteparameter: %s\n",name);
			if( pm = params[pi].p_mssg )
				sv1log("Warning: %s\n",pm);
		}
		return pi;
	    }
	}
	if( warn )
		fprintf(stderr,"Warning: unknown parameter: %s\n",name);
	if( diag )
		sprintf(diag,"unknown parameter: %s",param);
	return -1;
}

const char *skip_argcond(PCStr(name));
int isFullpath(PCStr(path));
const char *absPARAMS[4];
#define PX_DGROOT	0

const char *paramAbsPath(PCStr(param)){
	int plen;
	int pi;
	CStr(px,1024);
	const char **apath;

	if( strncmp(param,"DGROOT=",plen=7) == 0 ){
		pi = PX_DGROOT;
		apath = &DELEGATE_DGROOT;
	}else{
		return 0;
	}
	if( isFullpath(param+plen) ){
		return 0;
	}
	if( absPARAMS[pi] ){
		return absPARAMS[pi];
	}
	if( !isFullpath(*apath) ){
		return 0;
	}
	strcpy(px,param);
	Xstrcpy(DVStr(px,plen),*apath);
	absPARAMS[pi] = stralloc(px);
	return absPARAMS[pi];
}

int copy_param(PCStr(param),int mac,const char **dav,const char*const*sav)
{	int dai,sai,pi;
	int valid_all;
	int option_also;
	int script_also;
	int for_filters;
	int len;
	const char *name;

	valid_all = 0;
	option_also = 0;
	script_also = 0;
	for_filters = 0;
	if( param ){
		for(; *param; param++ ){
			if( param[0] == '*' ) valid_all = 1; else
			if( param[0] == '-' ) option_also = 1; else
			if( param[0] == '+' ) script_also = 1; else
			if( param[0] == 'f' ) for_filters = 1; else
				break;
		}
		if( *param == 0 )
			param = NULL;
	}
	dai = 0;

	if( param != NULL ){
	    len = strlen(param);
	    for( sai = 0; name = sav[sai]; sai++ ){
		name = skip_argcond(name);
		if( name == NULL )
			continue;
		if( name[len] == '=' )
		if( strncmp(name,param,len) == 0 )
		    dav[dai++] = sav[sai];
	    }
	}else{
	    for( sai = 0; name = sav[sai]; sai++ ){
		if( mac-1 <= dai ){
			break;
		}
		name = skip_argcond(name);
		if( name == NULL )
			continue;
		if( !option_also && strncmp(name,"DGOPTS=",7) == 0 )
			continue;
		if( option_also && name[0] == '-' )
			dav[dai++] = sav[sai];
		else
		if( script_also && name[0] == '+' )
			dav[dai++] = sav[sai];
		else
		if( strchr(name,'=') )
		if( 0 <= (pi = check_param(name,0)) ){
		    if( valid_all
		    || !for_filters && params[pi].p_mpass
		    ||  for_filters && params[pi].p_fpass ){
			if( dav[dai] = paramAbsPath(sav[sai]) ){
				dai++;
			}else
			dav[dai++] = sav[sai];
		    }
		}
	    }
	}
	return dai;
}

const char *parameq(PCStr(param),PCStr(name)){
	int len;
	len = strlen(name);
	if( strneq(param,name,len) ){
		if( param[len] == '=' )
			return param+len+1;
	}
	return 0;
}

