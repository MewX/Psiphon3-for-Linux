/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2007 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	ftp.c (ftp/DeleGate)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940305	created
	940321	added data client protocol
	950107	let service_ftp be half-duplex (single process)
	950107	introduced MODE XDC (Data transfer on Control connection)
	950504	Exit if server dead when waiting client's request
ToDo:
	How about "PORT 0,0,0,0,N,M" instead of "MODE XDC" ?
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "ystring.h"
#include "vsignal.h"
#include "vsocket.h"
#include "delegate.h"
#include "filter.h"
#include "fpoll.h"
#include "file.h"
#include "auth.h"
#include "proc.h"

int ShutdownSocket(int sock);
int connectToSftpX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC);
int connectToSftpXX(Connection *Conn,PCStr(host),int port,PCStr(user),int toC,int fromC);
int connect_ftp_data(Connection*Conn,PCStr(port),int cntrlsock,PCStr(lhost),int lport);
void putFileInHTTP(FILE *tc,PCStr(path),PCStr(file));
FILE *dirtar_fopen(PCStr(path));
int bind_ftp_data(Connection*Conn,PVStr(mport),PCStr(server),int iport,int cntrlsock,int PASV,PCStr(lhost),int lport);

char *scan_ls_l(PCStr(lsl),PVStr(mode),int *linkp,PVStr(owner),PVStr(group),FileSize *sizep,PVStr(date),PVStr(name),PVStr(sname));
FILE *CTX_creat_ftpcache(Connection *Conn,PCStr(user),PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cpath),PVStr(xcpath));
int ftp_EXPIRE(Connection *Conn);
FILE *fopen_ftpcache0(Connection *Conn,int expire,PCStr(host),int port,PCStr(path),PCStr(ext),PVStr(cpath),int *isdirp,FileSize *sizep,int *mtimep);
/*
void ftp_xferlog(int start,PCStr(chost),int size,PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser),PCStr(cstat));
*/
void ftp_xferlog(int start,PCStr(chost),FileSize rest,FileSize size,PCStr(md5),PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser),PCStr(cstat));
FILE *fopen_ICP(Connection *Conn,PCStr(url),FileSize *sizep,int *datep);
int stat_lpr(PCStr(lphost),int lpport,PCStr(queue),PCStr(opt),PCStr(fname),PVStr(stat));
int rmjob_lpr(Connection*Conn,PCStr(lphost),int lpport,PCStr(queue),PCStr(user),PCStr(jobname),PVStr(stat));
int send_lpr(Connection*Conn,PCStr(lphost),int lpport,PCStr(queue),FILE *dfp,int dlen,PCStr(user),PCStr(fname),PVStr(stat));

extern int FTP_ACCEPT_TIMEOUT;
extern int CON_TIMEOUT;
extern int IO_TIMEOUT;

enum _FtpBounce {
	FB_TH = 0x01, /* don't care (backward compatible) */
	FB_NO = 0x02, /* reject unconditionally (default) */
	FB_DO = 0x04, /* allow unconditionally */
	FB_CB = 0x08, /* callback to the client addr. */
	FB_RL = 0x10, /* reject conditionally by REJECT list */
} FtpBounce;

typedef struct {
	int	fc_init;
  const	char   *fc_proxy;	/* {user,open,site,path} */
  const	char   *fc_usdelim;	/* delimiter instead of '@' in user@site */
	int	fc_nullPWD;	/* allow 257 "" response for the PWD command */
	int	fc_swMaster;	/* do server switch by user@site in MASTER */
	int	fc_nodata;	/* don't do anything for data connection */
	int	fc_chokedata;
	int	fc_noxdcSV;	/* don't use XDC with server */
	int	fc_noxdcCL;
	int	fc_doeprtSV;	/* do EPRT with server */
	int	fc_doepsvCL;
	int	fc_doepsvSV;	/* do EPSV with server */
	int	fc_noepsvCL;
	int	fc_nopasvSV;	/* don't use PASV with server */
	int	fc_nopasvCL;
	int	fc_noportSV;
	int	fc_noportCL;
	int	fc_bounce;	/* allow PORT directed not for the client */
	int	fc_immportCL;	/* don't postpone PORT with the client */
	int	fc_rawxdcSV;
	int	fc_rawxdcCL;
	int	fc_nostatSV;
	int	fc_statinfo;	/* insert DeleGate status into reply text */
	int	fc_forcexdcSV;
	int	fc_noMLSxCL;	/* don't support MLSx */
	int	fc_lpr_nowait;
	int	fc_ftp_on_http;
	int	fc_nounesc;	/* dont unescape %XX to be forwarded to server */
	int	fc_thruesc;
  const	char   *fc_dfltuser;
	int	fc_hideserv;
	int	fc_maxreload;	/* max. cachefile size reloaded without verify */
	int	fc_pasvdebug;
	int	fc_debug;
  const char   *fc_uno;		/* maintain UNO */
	int	fc_ccx;
	int	fc_authproxy;
	int	fc_waitSSL;	/* wait SSL before returning 150 reponse */
} FtpConf;

#define CCX_ANYTYPE	0x01	/* CCX even for TYPE IMAGE */
#define CCX_AUTOSVCC	0x02	/* CHARCODE=svcc:tosv automatically */
#define CCX_COMMAND	0x04	/* CCX for command */
#define CCX_RESPONSE	0x08	/* CCX for response */
#define CCX_ANY	0xFF

#define PXA_USERHOSTMAP	0x01	/* auth. USER u@s by AUTHORIZER=user{u}:*:s */
#define PXA_HOSTMAP	0x02	/* auth. USER u@s by AUTHORIZER=user{u@s}:*:s */
#define PXA_USERGEN	0x04	/* forward USER v by AUTHORIZER=user{u}(v) */
#define PXA_AUTHGEN	0x08	/* apply MYAUTH */
#define PXA_MAPANDGEN	(PXA_USERHOSTMAP|PXA_USERGEN|PXA_AUTHGEN)

#define NUE_USER	0x0001
#define NUE_PASS	0x0002
#define NUE_PATH	0x0004
#define NUE_ANY		0xFFFF

#define fddup(x)	dup(x)

#define comeq(com1,com2)	(strcasecmp(com1,com2) == 0)
#define comUPLOAD(com) \
		(  comeq(com,"STOR") || comeq(com,"STOU") || comeq(com,"APPE") )
#define comCHANGE(com) \
		(  comeq(com,"STOR") || comeq(com,"STOU") || comeq(com,"APPE") \
		|| comeq(com,"RNFR") || comeq(com,"RNTO") || comeq(com,"DELE") \
		|| comeq(com,"MKD")  || comeq(com,"RMD") )
#define remote_path(path)	(strncmp(path,"//",2) == 0)

#define DIRCOMS(com) \
		(  comeq(com,"CWD")  || comeq(com,"CDUP") \
		|| comeq(com,"MLSD") \
		|| comeq(com,"STAT") || comeq(com,"LIST") || comeq(com,"NLST") )

#define RETRCOMS(com)	 ( comeq(com,"NLST") || comeq(com,"LIST") \
			|| comeq(com,"MLSD") \
			|| comeq(com,"RETR") || comUPLOAD(com) )

#define PATHCOMS(com)	 ( RETRCOMS(com) \
			|| comCHANGE(com) \
			|| comeq(com,"STAT") \
			|| comeq(com,"MLST") \
			|| comeq(com,"MLSD") \
			|| comeq(com,"SIZE") || comeq(com,"MDTM") )

/* commands either with/without an argument */
#define ARG0COMS(com)	 ( comeq(com,"STAT") \
			|| comeq(com,"NLST") || comeq(com,"LIST") \
			|| comeq(com,"MLSD") || comeq(com,"MLST") \
			 )

/* PATHCOMS with status response only */
#define STATCOMS(com)	 ( comeq(com,"STAT") \
			|| comeq(com,"CWD") \
			|| comeq(com,"MKD") \
			|| comeq(com,"RMD") \
			|| comeq(com,"DELE") \
			|| comeq(com,"RNFR") \
			|| comeq(com,"RNTO") \
			|| comeq(com,"MDTM") \
			|| comeq(com,"SIZE") )

#define fgetsFromST(b,s,f)	fgetsTimeout(b,s,f,FTP_FROMSERV_TIMEOUT)
#define fgetsFromCT(b,s,f)	fgetsTimeout(b,s,f,FTP_FROMCLNT_TIMEOUT)

#define XDC_OPENING	"220-extended FTP [MODE XDC]"
#define XDC_OPENING_B64	"220-extended FTP [MODE XDC][XDC/BASE64]"
#define XDC_OPENING_NONE	"220-extended FTP "
#define XDC_STAT	"999"
#define XDC_PORT_TEMP	"999 PORT %s"
#define XDC_PASV_PORT	"0,0,0,0,0,0"
static const char *DFLT_MLS_FMT = \
 "Type=%xY;Size=%S;Modify=%xTD;Perm=%xP;Unique=%xU; %N";
static const char *FEAT_MLS= \
 "Type*;Size*;Modify*;Perm*;Unique*;";

typedef struct {
	int	xdc_ON;		/* use MODE XDC */
  const	char   *xdc_encode;	/* use MODE XDC/BASE64 */
} XDCmode;

typedef struct {
	int	fs_IAMCC; /* with a cached connection for the host:port */
    Connection *fs_Conn;
    Connection	fs_dataConn;

  const	char   *fs_opening;
	MStr(	fs_proto,64);
	MStr(	fs_host,128);
	int	fs_port;
	MStr(	fs_logindir,1024);
	int	fs_logindir_isset;
	int	fs_nocache;
	double	fs_timeout;

  const char   *fs_changesv;
	int	fs_onLoginDir; /* start at the LoginDir(not the virtual root) */
	int	fs_login1st;
	MStr(	fs_loginroot,256);

	MStr(	fs_myhost,128);
	MStr(	fs_myaddr,64);
	int	fs_myport;
	int	fs_imProxy;
	int	fs_anonymous;
	int	fs_anonymousOK;
	int	fs_serverWithPASV;
	int	fs_serverWithXDC;

	int	fs_relaying_data;
	int	fs_dsvsock;
	int	fs_psvsock;
	int	fs_dclsock;
	int	fs_pclsock;
	MStr(	fs_dataError,32);

	XDCmode	fs_XDC_SV;
	XDCmode	fs_XDC_CL;

	int	fs_PASVforPORT;
	int	fs_PORTforPASV;

  const	char   *fs_cstat;
	MStr(	fs_dport,128);
	MStr(	fs_mport,128);
	MStr(	fs_CWD,1024);
	int	fs_islocal; /* CWD is on the local "file://localhost/" */
	MStr(	fs_prevVWD,1024); /* previous directory as a virtual URL */
	int	fs_auth;
	MStr(	fs_auser,128);
	AuthInfo fs_proxyauth;
	AuthInfo fs_aub;
	MStr(	fs_acct,128);

	MStr(	fs_curcom,32);
	MStr(	fs_curarg,1024); /* the original argument not rewritten */
	MStr(	fs_opts,32);
       FileSize	fs_REST;
       FileSize	fs_RESTed;
	MStr(	fs_RNFR,1024);
	/*
	MStr(	fs_USER,128);
	*/
	MStr(	fs_OUSER,128);	/* original USER argument */
  const	char   *fs_rcUSER;
	MStr(	fs_PASS,128);
  const	char   *fs_rcPASS;
	MStr(	fs_TYPE,128);
  const	char   *fs_rcSYST;	/* SYST response line cache */
	MStr(	fs_qcTYPE,32);	/* TYPE request argument cache */
  const	char   *fs_rcTYPE;	/* TYPE response line cache */

	AuthInfo fs_Ident; /* replaces fs_USER, fs_host and fs_port */
	int	fs_authERR;

	FILE   *fs_ts;
	FILE   *fs_fs;

       FileSize	fs_dsize; /* local file size or size in 150 ... (%u bytes) */
	int	fs_dsrc;
	int	fs_ddst;
	int	fs_ABOR;
	int	fs_peekError;
	int	fs_dstwcc;
	MStr(	fs_ccxtosvb,64); /* CCX for path arg. over control conn. */
	MStr(	fs_ccxtomeb,64); /* CCX for path arg. over control conn. */
} FtpStat;
#define FSCCX_TOSV	(CCXP)FS->fs_ccxtosvb
#define FSCCX_TOME	(CCXP)FS->fs_ccxtomeb

#define IS_LOCAL	1
#define IS_STAB		2
#define IS_PXLOCAL	4

#define fs_USER	fs_Ident.i_user
#define fs_host	fs_Ident.i_Host
#define fs_port	fs_Ident.i_Port

#define FS_NOAUTH	2 /* password authentication unnecessary */

#define fs_XDCforSV	fs_XDC_SV.xdc_ON
#define fs_XDCencSV	fs_XDC_SV.xdc_encode
#define fs_XDCforCL	fs_XDC_CL.xdc_ON
#define fs_XDCencCL	fs_XDC_CL.xdc_encode

typedef struct {
	MStr(	fc_swcom,32);
	MStr(	fc_swopt,32);
	MStr(	fc_swarg,128);
	MStr(	fc_user,128);
	MStr(	fc_pass,128);
	MStr(	fc_acct,128);
	MStr(	fc_Path,128);
	MStr(	fc_type,64);
	MStr(	fc_opts,32);
	int	fc_SUCcode;
	int	fc_ERRcode;
	FILE   *fc_fc;
	FILE   *fc_tc;
	FtpStat	*fc_callersFS;
} FtpConn;

int CC_TIMEOUT_FTP = 120;

typedef struct {
	int	 fe_FTP_FROMSERV_TIMEOUT;
	int	 fe_FTP_FROMCLNT_TIMEOUT;
	int	 fe_FTP_DELAY_REJECT_P;
	int	 fe_CON_TIMEOUT_DATA;
	int	 fe_MAX_FTPDATA_RETRY;
  const	char	*fe_FTP_LIST_COM;
  const	char	*fe_FTP_LIST_OPT;
  const	char	*fe_FTP_LIST_OPT_ORIGIN;
	FtpConf	 fe_FCF;
	FtpConn	*fe_PFC;
	FtpStat	*fe_PFS;
  const	char	*fe_ftp_env_name;
	jmp_buf	 fe_ftp_env;
	int	 fe_relayingDATA;
} FtpEnv;
static FtpEnv *ftpEnv;
#define FTP_FROMSERV_TIMEOUT	ftpEnv->fe_FTP_FROMSERV_TIMEOUT
#define FTP_FROMCLNT_TIMEOUT	ftpEnv->fe_FTP_FROMCLNT_TIMEOUT
#define FTP_DELAY_REJECT_P	ftpEnv->fe_FTP_DELAY_REJECT_P
#define CON_TIMEOUT_DATA	ftpEnv->fe_CON_TIMEOUT_DATA
#define MAX_FTPDATA_RETRY	ftpEnv->fe_MAX_FTPDATA_RETRY
#define FTP_LIST_COM		ftpEnv->fe_FTP_LIST_COM
#define FTP_LIST_OPT		ftpEnv->fe_FTP_LIST_OPT
#define FTP_LIST_OPT_ORIGIN	ftpEnv->fe_FTP_LIST_OPT_ORIGIN
#define FCF		ftpEnv->fe_FCF
#define PFC		ftpEnv->fe_PFC
#define PFS		ftpEnv->fe_PFS
#define ftp_env_name	ftpEnv->fe_ftp_env_name
#define ftp_env		ftpEnv->fe_ftp_env
#define relayingDATA	ftpEnv->fe_relayingDATA
#define ftpDEBUG(f)	(FCF.fc_debug & f)

int scanFTPxHTTP(Connection *Conn,PCStr(cmdopt),PVStr(xcmd),PVStr(xopt),PVStr(xctype));
static int ftpxhttpSIZE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg));
static int ftpxhttpSTAT(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg));
static int ftpxhttpCHANGE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg));
int ftpxhttpSTOR(FtpStat *FS,FILE *tc,FILE *fc,PCStr(com),PCStr(arg),PVStr(path));
int ftpxhttpLIST(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path),PVStr(head));
int ftpxhttpRETR(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path));
static int ftpxhttpAUTH(FtpStat *FS,PCStr(com),PCStr(arg));


static int lookaside_cache(Connection *Conn,FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),int remote);
static int put_get(FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(fmt),...);
void minit_ftp()
{
	if( ftpEnv == 0 ){
		ftpEnv = NewStruct(FtpEnv);
		FTP_FROMSERV_TIMEOUT = 300;
		FTP_FROMCLNT_TIMEOUT = 900;
		FTP_DELAY_REJECT_P = 30;
		MAX_FTPDATA_RETRY = 1;
		FTP_LIST_COM = "LIST";
		FTP_LIST_OPT = "-lL";
		FTP_LIST_OPT_ORIGIN = "-lL";
		ftp_env_name = "FTP";
		FCF.fc_maxreload = 8*1024;
		FCF.fc_usdelim = "*%#";
	}
}

#define TYPE_IMAGE(FS) (toupper(FS->fs_qcTYPE[0])=='I')
#define TYPE_ASCII(FS) (FS->fs_qcTYPE[0]==0 || toupper(FS->fs_qcTYPE[0])=='A')
#define MODE(FS)	((FS)->fs_anonymous ? PS_ANON : 0)

static scanListFunc conf1(PCStr(conf))
{	CStr(what,32);
	CStr(val,256);

	fieldScan(conf,what,val);
	if( strcaseeq(what,"DEFAULT") ){
		bzero(&FCF,sizeof(FCF));
		FCF.fc_maxreload = 8*1024;
		FCF.fc_usdelim = "*%#";
	}else
	if( strcaseeq(what,"PROXY") ){
		FCF.fc_proxy = stralloc(val);
	}else
	if( strcaseeq(what,"PROXYAUTH") ){
		if( *val == 0 )
			FCF.fc_authproxy |= PXA_MAPANDGEN;
		if( isinList(val,"userhostmap") )
			FCF.fc_authproxy |= PXA_USERHOSTMAP;
		if( isinList(val,"hostmap") )
			FCF.fc_authproxy |= PXA_HOSTMAP;
		if( isinList(val,"usergen") )
			FCF.fc_authproxy |= PXA_USERGEN;
		if( isinList(val,"authgen") )
			FCF.fc_authproxy |= PXA_AUTHGEN;
	}else
	if( strcaseeq(what,"USDELIM") ){
		FCF.fc_usdelim = stralloc(val);
	}else
	if( strcaseeq(what,"NULLPWD") ){
		FCF.fc_nullPWD = 1;
	}else
	if( strcaseeq(what,"SWMASTER") ){
		FCF.fc_swMaster = 1;
	}else
	if( strcaseeq(what,"NODATA") ){
		FCF.fc_nodata = 1;
	}else
	if( strcaseeq(what,"CHOKEDATA") ){
		FCF.fc_chokedata = atoi(val);
	}else
	if( strcaseeq(what,"DOEPRT") ){
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_doeprtSV = 1;
	}else
	if( strcaseeq(what,"DOEPSV") ){
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_doepsvCL = 1;
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_doepsvSV = 1;
	}else
	if( strcaseeq(what,"NOEPSV") ){
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_noepsvCL = 1;
	}else
	if( strcaseeq(what,"NOPASV") ){
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_nopasvSV = 1;
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_nopasvCL = 1;
	}else
	if( strcaseeq(what,"NOPORT") ){
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_noportSV = 1;
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_noportCL = 1;
	}else
	if( strcaseeq(what,"BOUNCE") ){
		if( strcaseeq(val,"no") ) FCF.fc_bounce = FB_NO;
		if( strcaseeq(val,"do") ) FCF.fc_bounce = FB_DO;
		if( strcaseeq(val,"th") ) FCF.fc_bounce = FB_TH;
		if( strcaseeq(val,"cb") ) FCF.fc_bounce = FB_CB;
		if( strcaseeq(val,"rl") ) FCF.fc_bounce = FB_RL;
	}else
	if( strcaseeq(what,"IMMPORT") ){
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_immportCL = 1;
	}else
	if( strcaseeq(what,"WAITSSL") ){
		FCF.fc_waitSSL = 1;
	}else
	if( strcaseeq(what,"FORCEXDC") ){
		FCF.fc_forcexdcSV = 1;
	}else
	if( strcaseeq(what,"NOXDC") ){
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_noxdcSV = 1;
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_noxdcCL = 1;
	}else
	if( strcaseeq(what,"RAWXDC") ){
		if( *val == 0 || strcaseeq(val,"sv") ) FCF.fc_rawxdcSV = 1;
		if( *val == 0 || strcaseeq(val,"cl") ) FCF.fc_rawxdcCL = 1;
	}else
	if( strcaseeq(what,"TIMEOUT") ){
		FTP_FROMSERV_TIMEOUT = atoi(val);
		FTP_FROMCLNT_TIMEOUT = atoi(val);
	}else
	if( strcaseeq(what,"NOSTAT") ){
		FCF.fc_nostatSV = 1;
	}else
	if( strcaseeq(what,"NOMLSX") ){
		FCF.fc_noMLSxCL = 1;
	}else
	if( strcaseeq(what,"LPR_NOWAIT") ){
		FCF.fc_lpr_nowait = 1;
	}else
	if( strcaseeq(what,"FTP_ON_HTTP") ){
		FCF.fc_ftp_on_http = 1;
	}else
	if( strcaseeq(what,"UNO") ){
		FCF.fc_uno = stralloc(val);
	}else
	if( strcaseeq(what,"DFLTUSER") ){
		FCF.fc_dfltuser = stralloc(val);
	}else
	if( strcaseeq(what,"THRUESC") ){
		if( *val == 0 ){
			FCF.fc_nounesc = 1;
			FCF.fc_thruesc |= NUE_ANY;
		}
		if( isinListX(val,"user","c") )
			FCF.fc_thruesc |= NUE_USER;
		if( isinListX(val,"pass","c") )
			FCF.fc_thruesc |= NUE_PASS;
		if( isinListX(val,"path","c") ){
			FCF.fc_nounesc = 1;
			FCF.fc_thruesc |= NUE_PATH;
		}
		if( FCF.fc_thruesc & (NUE_USER|NUE_PASS) ){
			if( strchr(FCF.fc_usdelim,'%') ){
				strcpy(val,FCF.fc_usdelim);
				strsubst(AVStr(val),"%","");
				FCF.fc_usdelim = stralloc(val);
			}
		}
	}else
	if( strcaseeq(what,"NOUNESC") ){
		FCF.fc_nounesc = 1;
	}else
	if( strcaseeq(what,"CCX") ){
		if( isinListX(val,"any",     "c") ) FCF.fc_ccx |= CCX_ANY;
		if( isinListX(val,"anytype", "c") ) FCF.fc_ccx |= CCX_ANYTYPE;
		if( isinListX(val,"autosvcc","c") ) FCF.fc_ccx |= CCX_AUTOSVCC;
		if( isinListX(val,"command", "c") ) FCF.fc_ccx |= CCX_COMMAND;
		if( isinListX(val,"response","c") ) FCF.fc_ccx |= CCX_RESPONSE;
	}else
	if( strcaseeq(what,"HIDESERV") ){
		FCF.fc_hideserv = 1;
	}else
	if( strcaseeq(what,"PASVDEBUG") ){
		FCF.fc_pasvdebug = 1;
	}else
	if( strcaseeq(what,"DEBUG") ){
		if( strneq(val,"0x",2) )
			sscanf(val+2,"%x",&FCF.fc_debug);
		else	FCF.fc_debug = atoi(val);
	}else
	if( strcaseeq(what,"MAXRELOAD") ){
		FCF.fc_maxreload = atoi(val);
	}else{
		sv1log("ERROR: unknown FTPCONF=%s\n",conf);
	}
	return 0;
}
static void init_conf()
{	
	if( FCF.fc_init )
		return;
	FCF.fc_init = 1;
	if( getenv("NOPASV")    ) conf1("NOPASV");
	if( getenv("FORCEXDC")  ) conf1("FORCEXDC");
	if( getenv("NOXDC")     ) conf1("NOXDC");
	if( getenv("NOSTAT")    ) conf1("NOSTAT");
	if( getenv("LPR_NOWAIT")) conf1("LPR_NOWAIT");
	if( getenv("FTP_ON_HTTP") ) conf1("FTP_ON_HTTP");
}
void scan_FTPCONF(Connection *Conn,PCStr(conf))
{
	init_conf();
	scan_commaListL(conf,0,scanListCall conf1);
}

static int rewrite_CWD(FtpStat *FS,PVStr(req),PVStr(arg),FILE *tc);
static int changesv(Connection *Conn,FtpStat *FS,PCStr(wh),PVStr(cserv)){
	IStr(url,256);

	if( FS->fs_changesv && streq(FS->fs_changesv,wh) ){
		strcpy(url,"/");
		rewrite_CWD(FS,VStrNULL,AVStr(url),NULL);
		if( !FS->fs_islocal && strneq(url,"//",2) ){
			strcpy(cserv,url+2);
			return 1;
		}
	}
	return 0;
}
static int FTP_getMountOpts(PCStr(wh),Connection *Conn,FtpStat *FS,PCStr(opts)){
	IStr(opt1,128);

	if( opts == 0 ){
		return 0;
	}
	if( getOpt1(opts,"servon",AVStr(opt1)) ){
		FS->fs_changesv = stralloc(opt1);
	}
	if( getOpt1(opts,"timeout",AVStr(opt1)) ){
		FS->fs_timeout = Scan_period(opt1,'s',(double)0);
	}
	return 1;
}

#include "param.h"
void scan_FTPCONFm(Connection *Conn,PCStr(conf)){
	init_conf();
	Verbose("%s=%s (MOUNT)\n",P_FTPCONF,conf);
	scan_commaListL(conf,0,scanListCall conf1);
}
static void setupFCF(Connection *Conn){
	IStr(conf,1024);
	int ci;

	for( ci=0; 0 <= (ci=find_CMAPi(Conn,P_FTPCONF,ci,AVStr(conf))); ci++ ){
		Verbose("%s=%s (CMAP)\n",P_FTPCONF,conf);
		scan_FTPCONF(Conn,conf);
	}
	if( MountOptions ){
		const char *mo,*confv;
		for( mo = MountOptions; *mo; ){
			mo = scan_ListElem1(mo,',',AVStr(conf));
			if( confv = parameq(conf,P_FTPCONF) ){
				Verbose("%s=%s (MOUNT)\n",P_FTPCONF,confv);
				scan_FTPCONF(Conn,confv);
			}
		}
	}
}

static void CCXreq(Connection *Conn,FtpStat *FS,PCStr(in),PVStr(qb),int qz){
	CCXP ccx;

	if( FCF.fc_ccx & CCX_COMMAND ){
		if( CCXactive(FSCCX_TOSV) || CCXactive(CCX_TOSV) ){
			if( CCXactive(CCX_TOSV) )
				ccx = CCX_TOSV;
			else	ccx = FSCCX_TOSV;
			CCXexec(ccx,in,strlen(in),AVStr(qb),qz);
		}
		if( isWindowsCE() )
		if( CCXactive(FSCCX_TOME) ){
			CCXexec(FSCCX_TOME,in,strlen(in),AVStr(qb),qz);
		}
	}
}
static void CCXresp(Connection *Conn,FtpStat *FS,PCStr(in),PVStr(rb),int rz){
	CCXP ccx;
	if( FCF.fc_ccx & CCX_RESPONSE ){
		if( CCXactive(CCX_TOCL) ){
			ccx = CCX_TOCL;
			CCXexec(ccx,in,strlen(in),AVStr(rb),rz);
		}
	}
}

static void sigPIPE(int sig){
	if( relayingDATA ){
		svlog("FTP got SIG%s: data relay aborted\n",sigsym(sig));
		signal(SIGPIPE,sigPIPE);
		relayingDATA |= 2;
		return;
	}
	svlog("FTP got SIG%s: longjump to %s\n",sigsym(sig),ftp_env_name);
	signal(SIGPIPE,SIG_IGN);
	longjmp(ftp_env,sig);
}
static int _sigXFSZ;
static void sigXFSZ(int sig){
	_sigXFSZ++;
	daemonlog("E","caught SIGZFSZ\n");
}

static void command_log(PCStr(fmt),...)
{
	VARGS(8,fmt);
	Verbose(fmt,VA8);
}

static void init_FS(FtpStat *FS,Connection *Conn)
{
	bzero(FS,sizeof(FtpStat));
	FS->fs_dsvsock = -1;
	FS->fs_psvsock = -1;
	FS->fs_dclsock = -1;
	FS->fs_pclsock = -1;
	FS->fs_XDCencCL = "";
	FS->fs_XDCencSV = "";

	if( FCF.fc_nopasvSV )
		FS->fs_serverWithPASV = -1;

	FS->fs_Conn = Conn;
	FS->fs_dataConn = *Conn;
	FS->fs_dataConn.xf_filters = 0;
	strcpy(FS->fs_dataConn.sv.p_proto,"ftp-data"); /* REAL_PROTO */

	if( CCXactive(CCX_TOCL) || CCXactive(CCX_TOSV) ){
		FCF.fc_noxdcSV = 1;
		FCF.fc_noxdcCL = 1;
	}
}
static void save_FS(FtpStat *FS)
{
	if( PFS ){
		PFS->fs_XDCforCL = FS->fs_XDCforCL;
		PFS->fs_XDCencCL = FS->fs_XDCencCL;
		PFS->fs_dclsock = FS->fs_dclsock;
		PFS->fs_pclsock = FS->fs_pclsock;
		PFS->fs_dsvsock = FS->fs_dsvsock;
		PFS->fs_psvsock = FS->fs_psvsock;
		strcpy(PFS->fs_dport,FS->fs_dport);
		strcpy(PFS->fs_mport,FS->fs_mport);
		PFS->fs_REST = FS->fs_REST;
	}
}
static void set_client_mode(FtpStat *FS,PCStr(mode))
{
	if( strncasecmp(mode,"XDC",3) == 0 ){
		if( strncasecmp(mode+3,"/BASE64",7) == 0 )
			FS->fs_XDCencCL = "/BASE64";
		else	FS->fs_XDCencCL = "";
		FS->fs_XDCforCL = 1;
	}else{
		FS->fs_XDCforCL = 0;
		FS->fs_XDCencCL = "";
	}
}

static int ServSock(Connection *Conn,FILE *ts,PCStr(where))
{	int toS;

	if( ConnType == 'y' && 0 <= ServerSockX ){
		toS = ServerSockX;
	}else
	if( (Conn->xf_filters & XF_SERVER) && 0 <= ToSX ){
		sv1log("## viaCFI [%s]: fileno(ts)=%d ToSX=%d\n",
			where,fileno(ts),ToSX);
		toS = ToSX;
	}else	toS = fileno(ts);
	return toS;
}

int is_anonymous(PCStr(user))
{
	if( strcaseeq(user,"ftp") || strcaseeq(user,"anonymous") )
		return 1;
	if( strncmp(user,"ftp@",4)==0 || strncmp(user,"anonymous@",9)==0 )
		return 1;
	return 0;
}

static int com_scode(PCStr(swcom),PCStr(passw),int *scodep,int *ecodep)
{	int scode,ecode;

	scode = 220;
	ecode = 500;
	if( strcaseeq(swcom,"PASS") ){ scode = 230; ecode = 530; }else
	if( strcaseeq(swcom,"OPEN") ){ scode = 220; ecode = 421; }else
	if( strcaseeq(swcom,"USER") ){
		if( passw[0] )       { scode = 230; ecode = 530; }
		else		     { scode = 331; ecode = 530; }
	}else
	if( strcaseeq(swcom,"CWD")  ){ scode = 250; ecode = 550; }
	else
	if( strcaseeq(swcom,"LIST") ){ scode = 150; ecode = 550; }else
	if( strcaseeq(swcom,"NLST") ){ scode = 150; ecode = 550; }else
	if( strcaseeq(swcom,"RETR") ){ scode = 150; ecode = 550; }else
	if( comUPLOAD(swcom)	    ){ scode = 150; ecode = 550; }else
	if( comCHANGE(swcom)	    ){ scode = 250; ecode = 550; }else
	if( strcaseeq(swcom,"STAT") ){ scode = 211; ecode = 550; }else
	if( strcaseeq(swcom,"SIZE") ){ scode = 213; ecode = 550; }else
	if( strcaseeq(swcom,"MDTM") ){ scode = 213; ecode = 550; }

	*scodep = scode;
	*ecodep = ecode;
	return 0;
}

static void putXcomplete(Connection *Conn,FtpStat *FS,FILE *tc,FileSize wcc){
	if( FS->fs_ABOR )
		fprintf(tc,"226 Abort successful\r\n");
	else	fprintf(tc,"226 Transfer complete (%lld bytes)\r\n",wcc);
}

static int check_server(PCStr(server),PCStr(swcom),FILE *tc)
{
	return 0;
}
static int user_permitted(Connection *Conn,FtpStat *FS,FILE *tc,PCStr(serv),int port,PCStr(user))
{	CStr(clnt,128);

	if( strcaseeq(FS->fs_proto,"sftp") ){
		/* permission should be checked with "sftp" */
	}
	set_SERVER(Conn,"ftp",serv,port);
	wordScan(user,REAL_USER);
	getClientHostPort(Conn,AVStr(clnt));
	if( FS->fs_proxyauth.i_user[0] ){
		AuthInfo sident;
		sident = ClientAuth;
		ClientAuth = FS->fs_proxyauth;
		if( service_permitted2(Conn,DST_PROTO,1) ){
			Xsprintf(TVStr(clnt),"<%s@%s>",ClientAuthUser,ClientAuthHost);
		}else{
			ClientAuth = sident;
		}
	}

	if( service_permitted(Conn,DST_PROTO) ){
		sv1log("FTP LOGIN FROM %s TO %s@%s\n",clnt,user,serv);
		fputLog(Conn,"Login","FTP; from=%s; to=%s@%s\n",clnt,user,serv);
		return 1;
	}else{
		sv1log("--U 553 Permission denied by DeleGate.\r\n");
		fprintf(tc,"553 Permission denied by DeleGate.\r\n");
		fflush(tc);
		sv1log("FTP LOGIN FROM %s TO %s@%s REJECTED\n",clnt,user,serv);
		return 0;
	}
}

static void replace_atmark(PCStr(com),char arg[])
{	const char *xp;

	if( strchr(arg,'@') )
		return;

	if( *FCF.fc_usdelim )
	if( xp = strrpbrk(arg,FCF.fc_usdelim) ){
		sv1log("%s [replace %c with @] %s\n",com,*xp,arg);
		*(char*)xp = '@';
	}
}

/*
 * 9.2.2 after an explicit switching to a server is done as
 * "CWD //server" or "USER user@server", and if there is no explicit
 * MOUNT to the server, there is an implicit MOUNT introduced as
 *   MOUNT="/* ftp://server/*"
 * which overrides the default -stab- MOUNT on the virtual root.
 */
static void clearAsProxy(Connection *Conn,PCStr(where)){
	if( ClientFlags & PF_AS_PROXY ){
		Verbose("clearAsProxy [%s]\n",where);
		ClientFlags &= ~PF_AS_PROXY;
	}
}
/*
static void setAsProxy(Connection *Conn,PCStr(com),PCStr(arg)){
*/
static void setAsProxy(Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg)){
	if( IsMounted ){
		if( ClientFlags & PF_AS_PROXY ){
			clearAsProxy(Conn,"change_server");
		}
		return;
	}
	if( comeq(com,"CWD") ){
		if( remote_path(arg) ){
			ClientFlags |= PF_AS_PROXY;
		}
	}else
	if( comeq(com,"USER") ){
		if( strchr(arg,'@') ){
			ClientFlags |= PF_AS_PROXY;
		}
	}else
	if( comeq(com,"PASS") ){
		if( strchr(FS->fs_OUSER,'@')
		 || *FCF.fc_usdelim && strpbrk(FS->fs_OUSER,FCF.fc_usdelim)
		){
			ClientFlags |= PF_AS_PROXY;
		}
	}else
	if( comeq(com,"SITE") || comeq(com,"OPEN") ){
		ClientFlags |= PF_AS_PROXY;
	}
	/*
	 * switching without MOUNTed, then it should be AS_PROXY, without
	 * any other conditions checked like above... but maybe
	 * IsMounted is not allways set and cleared (maybe) ...
	 */
	/* should use isMounted() function ? */
}

static int stripArgOpts(PVStr(arg),PVStr(opt));
static char *getVUpathX(FtpStat *FS,PCStr(cpath),PVStr(vpath),int remote);
static int change_server(Connection *Conn,FtpStat *FS,FILE *fc,FILE *tc,PCStr(swcom),PCStr(server),char cuser[],PCStr(cpass),PCStr(ctype))
{	CStr(serv,128);
	const char *dp;
	const char *xp;
	CStr(dpass,256);
	const char *ppass;
	CStr(duser,256);
	AuthInfo ident;
	int port;
	int shops;
	int svsock;
	int rcode = 0;
	FtpConn *PFCsav;

	SERVREQ_SERNO = 0;

	PFCsav = PFC;
	if( PFC == NULL )
		PFC = (FtpConn*)calloc(sizeof(FtpConn),1);
	/*
	setAsProxy(Conn,FS->fs_curcom,FS->fs_curarg);
	*/
	setAsProxy(Conn,FS,FS->fs_curcom,FS->fs_curarg);
	PFC->fc_callersFS = FS;
	PFC->fc_fc = fc;
	PFC->fc_tc = tc;

	if( PATHCOMS(swcom) ){
		getVUpathX(FS,FS->fs_CWD,AVStr(FS->fs_prevVWD),0);
	}

	if( !IsMounted )
	if( !PATHCOMS(swcom) && !do_RELAY(Conn,RELAY_PROXY)
	 ||  PATHCOMS(swcom) && !do_RELAY(Conn,RELAY_DELEGATE)
	){
		int ok,no;
		com_scode(swcom,cpass,&ok,&no);
		fprintf(tc,"%d Forbidden by DeleGate.\r\n",no);
		return -1;
	}
	IsMounted = 0;


	svsock = -1;
	if( strrchr(server,'@') ){
		xp = scan_userpassX(server,&ident);
		if( *xp == '@' ){
			if( *ident.i_user ) cuser = ident.i_user;
			if( *ident.i_pass ) cpass = ident.i_pass;
		    if( (FCF.fc_thruesc & NUE_PASS) == 0 ){
			nonxalpha_unescape(cpass,AVStr(dpass),1);
			if( strcmp(cpass,dpass) != 0 ){
				sv1log("unescaped password for %s\n",cuser);
				cpass = dpass;
			}
		    }
			server = xp+1;
		}
	}
	if( (FCF.fc_thruesc & NUE_USER) == 0 )
	if( nonxalpha_unescape(cuser,AVStr(duser),1) )
		cuser = duser;
	replace_atmark(swcom,cuser);

	strcpy(PFC->fc_swcom,swcom);
	strcpy(PFC->fc_swarg,FS->fs_curarg);
	stripArgOpts(AVStr(PFC->fc_swarg),AVStr(PFC->fc_swopt));
	com_scode(swcom,cpass,&PFC->fc_SUCcode,&PFC->fc_ERRcode);
	strcpy(PFC->fc_user,cuser);
	strcpy(PFC->fc_pass,cpass);
	strcpy(PFC->fc_type,ctype);
	wordScan(FS->fs_opts,PFC->fc_opts);
	wordScan(FS->fs_acct,PFC->fc_acct);

	wordScan(server,serv);
	if( dp = strchr(serv,'/') )
		truncVStr(dp);
	if( dp = strchr(server,'/') ){
		if( strncmp(dp,"//",2) != 0 )
			dp++;
		wordScan(dp,PFC->fc_Path);
/*
		if( !FCF.fc_nounesc )
			nonxalpha_unescape(PFC->fc_Path,PFC->fc_Path,1);
*/
	}else	PFC->fc_Path[0] = 0;

	if( xp = strrchr(serv,':') ){
		truncVStr(xp);
		xp++;
		port = atoi(xp);
	}else
	if( strcaseeq(FS->fs_proto,"sftp") ){
		port = 22;
	}else
	if( ServerFlags & PF_SSL_IMPLICIT ){ /* set by ftps://serv/ */
		port = 990;
	}else	port = serviceport("ftp");/*DFLT_PORT;*/

	if( 0 <= svsock ){
		Verbose("USER %s\n",cuser);
		port = getpeerNAME(svsock,AVStr(serv));
	}else{
		if( is_anonymous(cuser) )
			ppass = cpass;
		else	ppass = "****";
		Verbose("CWD //[%s:%s]@%s:%d\n",cuser,ppass,serv,port);
	}
	if( serv[0] == 0 )
		strcpy(serv,"localhost");

	if( user_permitted(Conn,FS,tc,serv,port,cuser) ){
		shops = D_FTPHOPS;
		if( strcaseeq(FS->fs_proto,"sftp") ){
			sv1log("-SFTPGW:change_server REAL_PROTO=sftp <-FS\n");
			strcpy(REAL_PROTO,FS->fs_proto);
		}
		Conn->co_setup = 0; /* reset CONNECT env. in repetition */
		execSpecialist(Conn,FromC,tc,svsock);
		D_FTPHOPS = shops;
		rcode = 0;
	}else{
		rcode = -1;
	}

	if( PFCsav == NULL )
		free(PFC);
	PFC = PFCsav;
	return rcode;
}

int saveSTLS(PCStr(wh),Connection *Conn,int SF[4]);
int restoreSTLS(PCStr(wh),Connection *Conn,int SF[4]);
static int makeDataConn(Connection *Conn,PCStr(dport),int cntrlsock,int pasv)
{	int dsock;
	CStr(host,64);
	CStr(hostport,64);
	int port,a0,a1,a2,a3,p0,p1;
	int xtry;
	CStr(xproto,64);
	CStr(myhost,MaxHostNameLen);
	CStr(dshost,MaxHostNameLen);
	int myport,dsport;
	const char *proto;
	IStr(xhost,MaxHostNameLen);
	int xport;
	int SF[4] = {0};

	if( ServerFlags & (PF_SSL_ON|PF_STLS_ON) ){
		/* 9.9.7 CONNECT ftp-data via SOCKS/ssl */
		/* this should be done with dataConn with clear ServerFlags */
		saveSTLS("makeDataConn",Conn,SF);
		clearSTLS(Conn);
	}
/*
	if( !isREACHABLE("ftp",hostport) ){
		Verbose("DataConn to unreachable host [%s]\n",hostport);
		return -1;
	}
*/

	xtry = 0;
	xport = REAL_PORT;
	strcpy(xhost,REAL_HOST);
	strcpy(xproto,REAL_PROTO);
	strcpy(REAL_PROTO,"ftp-data"); /* getViaSocks() requires it */

	dsport = getpeerAddr(cntrlsock,AVStr(dshost));
	if( dsport <= 0 )
		strcpy(dshost,"0.0.0.0");
	myhost[0] = 0;
	myport = 0;
	proto = pasv?"ftp-data-pasv-src":"ftp-data-port-src";
	if( !SRCIFfor(Conn,proto,dshost,dsport,AVStr(myhost),&myport) )
	if( !SRCIFfor(Conn,"ftp-data-src",dshost,dsport,AVStr(myhost),&myport) )
	SRCIFfor(Conn,"ftp-data",dshost,dsport,AVStr(myhost),&myport);

	for(;;){
	dsock = connect_ftp_data(Conn,dport,cntrlsock,myhost,myport);
		if( 0 <= dsock )
			break;
		if( MAX_FTPDATA_RETRY <= ++xtry )
			break;
		sv1log("FTP data connection failed (%d), retrying...\n",xtry);
		msleep(200);
	}
	REAL_PORT = xport;
	strcpy(REAL_HOST,xhost);
	strcpy(REAL_PROTO,xproto);
	/* It should be connect_to_server() to tcprelay://a.b.c.d:ef/
	 * so that it can be controlled and relayed with DeleGate's routing.
	 */

	set_keepalive(dsock,1);
	restoreSTLS("makeDataConn",Conn,SF);
	return dsock;
}

static void insert_scode(PCStr(str),FILE *dst,int scode)
{	const char *sp;
	const char *np;
	char ch;
	char pch = 0;

	for( sp = str; sp && *sp; sp = np ){
		fprintf(dst,"%d- ",scode);
		for( np = sp; ch = *np; np++ ){
			if( ch == '\n' && pch != '\r' ){
				putc('\r',dst);
			}
			putc(ch,dst);
			pch = ch;
			if( ch == '\n' ){
				np++;
				break;
			}
		}
	}
}
/*
static void escape_scode(PVStr(str),FILE *dst)
*/
#define escape_scode(s,d)	escape_scodeX(scode,s,d)
static void escape_scodeX(int iscode,PVStr(str),FILE *dst)
{	refQStr(sp,str); /**/
	const char *np;
	char ch;
	int len;

	for( cpyQStr(sp,str); sp && *sp; sp = (char*)np ){
		if( !ftpDEBUG(0x800) && isdigit(sp[0]) && atoi(sp) != iscode ){
			Strins(AVStr(sp)," ");
		}else
		if( isdigit(sp[0]) && isdigit(sp[1]) && isdigit(sp[2]) ){
			sp += 3;
			ch = *sp;
			if( ch==' ' || ch=='\t' || ch=='\r' || ch=='\n' ){
				assertVStr(str,sp+strlen(sp)+1);
				for( len = strlen(sp); 0 <= len; len-- )
					setVStrElem(sp,len+1,sp[len]);
				setVStrElem(sp,0,'-');
			}
		}
		if( np = strchr(sp,'\n') )
			np++;
	}
	if( dst != NULL )
		fputs(str,dst);
}

/*
 *	get virtual URL path of given MOUNTed URL
 */
static char *getVUpath(FtpStat *FS,PCStr(cpath),PVStr(vpath))
{
	return getVUpathX(FS,cpath,BVStr(vpath),0);
}
static char *getVUpathX(FtpStat *FS,PCStr(cpath),PVStr(vpath),int remote)
{	const char *proto;
	CStr(hostport,MaxHostNameLen);
	const char *path;
	CStr(vurl,1024);
	CStr(xpath,1024);
	const char *np;

	/*
	 * should return NULL if cpath is not mounted URL...
	 * in case such as MOUNT="/xxx/* /*" with CWD="/"
	 * 9.2.2 return a stab virtual URL for non-MOUNTed path.
	 */
	if( FS->fs_islocal == IS_STAB ){
		if( strneq(cpath,"/-stab-",7) ){
			strcpy(vpath,cpath+7);
			return (char*)vpath;
		}
	}

	/* 9.2.3 "fs_islocal" can be set by restoreCWD() meaning that
	 * the current working directroy (prevVWD) is left on the local
	 * even after it connected to a remote server "fs_host" when the
	 * server switch is invoked by a non CWD command.
	 * But the path to be virtualized here can be a remote one of the
	 * remote server like the one in the MLST reponse.
	if( FS->fs_islocal || FS->fs_host[0] == 0 ){
	*/
	if( !remote && FS->fs_islocal || FS->fs_host[0] == 0 ){
		proto = "file";
		sprintf(hostport,"%s:%d","localhost",0);
	}else{
		proto = "ftp";
		sprintf(hostport,"%s:%d",FS->fs_host,FS->fs_port);
	}
	if( cpath[0] == '/' )
		path = cpath + 1;
	else	path = cpath;

domatch:
	if( CTX_mount_url_fromL(FS->fs_Conn,AVStr(vurl),proto,hostport,path,NULL,"ftp","-.-") ){
		setVStrElem(vpath,0,'/');
		decomp_absurl(vurl,VStrNULL,VStrNULL,QVStr(vpath+1,vpath),1024-1);
		return (char*)vpath;
	}else{
		if( *path && strtailchr(path) != '/' ){
			sprintf(xpath,"%s/",path);
			path = xpath;
			goto domatch;
		}
		strcpy(vpath,path);
		return NULL;
	}
}
static int get_VPWD(FtpStat *FS,PVStr(cwd),PVStr(npath))
{	const char *tp;

/*
	if( FS->fs_CWD[0] )
		strcpy(cwd,FS->fs_CWD);
	else	strcpy(cwd,FS->fs_logindir);
*/
	strcpy(cwd,FS->fs_CWD);

	if( getVUpath(FS,cwd,AVStr(npath)) == NULL )
		return -1;

	if( tp = strrchr(npath,'/') )
	if( tp != npath && tp[1] == 0 )
		truncVStr(tp);
	return 1;
}
static const char *isLocal(FtpStat *FS,PCStr(method),PCStr(rpath),int isdir,PVStr(mpath))
{	const char *proto;
	CStr(hostport,MaxHostNameLen);	
	refQStr(cpath,mpath); /**/
	CStr(vurl,1024);
	CStr(vup,1024);
	const char *opts;
	CStr(delegate,MaxHostNameLen);

	/* relative path from non-local directory is non-local too ... */
	if( rpath[0] != '/' )
	if( !FS->fs_islocal )
		return 0;

	if( ftpDEBUG(0x100) == 0 )
	if( rpath[0] != '/' && FS->fs_islocal ){
		CStr(xrpath,1024);
		getVUpath(FS,FS->fs_CWD,AVStr(xrpath));
		if( xrpath[0] != '/' )
			Strins(AVStr(xrpath),"/");
		chdir_cwd(AVStr(xrpath),rpath,1);
		sv1log("isLocal? [%s][%s] => %s\n",FS->fs_CWD,rpath,xrpath);
		rpath = xrpath;
	}

	if( rpath[0] == '/' ){
		strcpy(vurl,rpath);
		if( opts = CTX_mount_url_to(FS->fs_Conn,NULL,method,AVStr(vurl)) ){
			if( strncaseeq(vurl,"ftp://",6) ){
				/* 9.9.1 maybe "fs_islocal" is set by
				 * restoreCWD(1) to indicate staying yet on
				 * the virtual root without doing CWD
				 */
				sv1log("#NOT islocal(%s)%d(%s)\n",
					rpath,FS->fs_islocal,vurl);
				return 0;
			}
			setVStrElem(mpath,0,'/');
			decomp_absurl(vurl,VStrNULL,VStrNULL,QVStr(mpath+1,mpath),1024-1);
			if( isWindows() ){
				if( mpath[0] == '/' && isFullpath(mpath+1) ){
					ovstrcpy((char*)mpath,mpath+1);
				}
			}
			PageCountUpURL(FS->fs_Conn,CNT_ACCESS|CNT_INCREMENT,rpath,NULL);
			return opts;
		}
	}

	strcpy(mpath,FS->fs_CWD);
	chdir_cwd(AVStr(mpath),rpath,1);
	if( !isdir )
		isdir |= fileIsdir(mpath);
	if( mpath[0] == '/' )
		cpath = (char*)mpath + 1;
	else	cpath = (char*)mpath;

	/*
	 *	cover MOUNT="/X*  /dir*"   also
	 *	by    MOUNT="/X/* /dir/*"
	 */
	if( isdir && strtailchr(cpath) != '/' )
		strcat(cpath,"/");

	proto = "file";
	sprintf(hostport,"%s:%d","localhost",0);
	ClientIF_HP(FS->fs_Conn,AVStr(delegate));

	opts = CTX_mount_url_fromL(FS->fs_Conn,AVStr(vurl),proto,hostport,cpath,
		NULL,"ftp",delegate);
	if( opts ){
		eval_mountOptions(FS->fs_Conn,opts);
		sv1log("MOUNTED LOCAL [%s] = [%s] opt=%s\n",vurl,mpath,opts);

		decomp_absurl(vurl,VStrNULL,VStrNULL,AVStr(vup),sizeof(vup));
		PageCountUpURL(FS->fs_Conn,CNT_ACCESS|CNT_INCREMENT,vup,NULL);
		return opts;
	}else{
		return 0;
	}
}

static const char *mount_ftparg(FtpStat *FS,PCStr(com),PCStr(arg),PVStr(vurl))
{	const char *opts;
	int remtail;

	if( arg[0] == '/' )
		strcpy(vurl,arg);
	else{
		getVUpath(FS,FS->fs_CWD,AVStr(vurl));
		if( vurl[0] == 0 )
			strcpy(vurl,"/");
		chdir_cwd(AVStr(vurl),arg,1);
	}

	/* when two MOUNTs like follows specified:
	 *   MOUNT="/d1/* ..."     (1)
	 *   MOUNT="/d1/d2/* ..."  (2)
	 * select (2) for "CWD /d1/d2" though it lacks trailing "/"
	 */
	remtail = 0;
	if( DIRCOMS(com) && strtailchr(vurl) != '/' ){
		strcat(vurl,"/");
		remtail = 1;
	}
	if( opts = CTX_mount_url_to(FS->fs_Conn,NULL,"GET",AVStr(vurl)) ){
		if( remtail )
		if( strtailchr(vurl) == '/' )
			setVStrEnd(vurl,strlen(vurl)-1);
		Verbose("mount_ftparg(%s)#A# [%s]->[%s]\n",com,arg,vurl);
		return opts;
	}

	if( remtail == 0 )
		return NULL;
	setVStrEnd(vurl,strlen(vurl)-1);
	if( opts = CTX_mount_url_to(FS->fs_Conn,NULL,"GET",AVStr(vurl)) ){
		Verbose("mount_ftparg(%s)#B# [%s]->[%s]\n",com,arg,vurl);
		return opts;
	}
	return NULL;
}

/*
 * relative path which will be passed as an argument to the target FTP server
 * (maybe it can unconditionally be absolute path as "LoginDir/UrlPath"...)
 */
static void relative_path(FtpStat *FS,PCStr(upath),PVStr(rpath))
{	const char *cwd;
	const char *cp;
	const char *up;
	int nmatch;

	cwd = FS->fs_CWD;
	cp = cwd;
	up = upath;
	while( *cp == '/' ) cp++;
	while( *up == '/' ) up++;
	while( *cp != 0 && *cp == *up ){
		cp++;
		up++;
	}
	while( *cp == '/' ) cp++;

    if( *cwd == 0 && *upath != '/' || *cp == 0 && *up == '/' ){
	/* v9.9.9 fix-140603a -- only if relative from cur. dir. (v6.0.0) */
	sv1log("--- relative [%s][%s] -> [%s][%s]\n",cwd,upath,cp,up);

	while( *up == '/' ) up++;

	/*
	if( *cp == 0 )
	*/
		strcpy(rpath,up);
    }
	else{
		/* absolute path in the target server: LoginDir/UrlPath */
		strcpy(rpath,FS->fs_logindir);
		if( strtailchr(rpath) != '/' )
			strcat(rpath,"/");
		strcat(rpath,upath);
	}
}
static int sameident(FtpStat *FS,AuthInfo *ident)
{ 
	if( FS->fs_host[0] && hostcmp(FS->fs_host,ident->i_Host) == 0 )
	if( FS->fs_port == ident->i_Port )
	if( strcmp(FS->fs_USER,ident->i_user) == 0
	 || is_anonymous(FS->fs_USER) && is_anonymous(ident->i_user)
	){
		return 1;
	}
	return 0;
}
static void get_dfltuser(PVStr(user),int size)
{
	if( FCF.fc_dfltuser )
		wordscanX(FCF.fc_dfltuser,AVStr(user),size);
	else	strcpy(user,"anonymous");
}
static int decomp_ftpsite(FtpStat *FS,PVStr(site),AuthInfo *ident)
{	int port = 0;

	if( streq(FS->fs_proto,"sftp") ){
		decomp_siteX("sftp",site,ident);
	}else
	decomp_siteX("ftp",site,ident);
	if( ident->i_user[0] == 0 )
	{
		if( FS
		 && hostcmp(FS->fs_host,ident->i_Host) == 0
		 && FS->fs_port == ident->i_Port
		 && FS->fs_USER[0] != 0
		){
			wordScan(FS->fs_USER,ident->i_user);
		}else
		if( FCF.fc_dfltuser ){
			wordScan(FCF.fc_dfltuser,ident->i_user);
		}else
		if( FS
		 && FS->fs_host[0] == 0
		 && FS->fs_USER[0] != 0
		){
			/* not so confident ... but it shold be used if a
			 * user name is given from the client and if it
			 * has not been used for any login to server
			 */
			wordScan(FS->fs_USER,ident->i_user);
		}else{
			get_dfltuser(AVStr(ident->i_user),sizeof(ident->i_user));
		}
	}
	return port;
}

static int authOK(Connection *Conn,FtpStat *FS,PCStr(mopt),PCStr(user),PCStr(pass)){
	CStr(asv,256);
	const char *mp;
	const char *us;
/*
sv1vlog("#### authOK ? opt[%s][%s] up[%s][%s]\n",
mopt?mopt:"",MountOptions?MountOptions:"",user,pass);
*/
	if( mopt == NULL || *mopt == 0 )
		mopt = MountOptions;
	if( mopt == NULL || *mopt == 0 )
		return 0;
	if( getOpt1(mopt,"AUTHORIZER",AVStr(asv)) == 0 )
		return 0;

	us = is_anonymous(user)?pass:user;
	if( (mp = MountVbase(mopt)) == 0 )
		mp = "";
	/*
	if( 0 <= AuthenticateX(Conn,asv,FS->fs_USER,FS->fs_PASS,"",NULL)
	 || 0 <= AuthenticateX(Conn,asv,user,pass,"",NULL) ){
	*/
	if( 0 <= AuthenticateX(Conn,asv,FS->fs_USER,FS->fs_PASS,"",&FS->fs_aub)
	 || 0 <= AuthenticateX(Conn,asv,user,pass,"",&FS->fs_aub) ){
		sv1log("#### %s MOUNT AUTHORIZER[%s][%s][%s][%s]%s\n","OK",
			asv,us,Client_Host,mp,FS->fs_CWD);
		return 1;
	}else{
		sv1log("#### %s MOUNT AUTHORIZER[%s][%s][%s][%s]%s\n","ERR",
			asv,us,Client_Host,mp,FS->fs_CWD);
		return -1;
	}
}

static int swRemote(FtpStat *FS,PCStr(com),xPVStr(arg),PVStr(xserv),int *remp)
{	CStr(proto,256);
	CStr(vurl,1024);
	CStr(site,MaxHostNameLen);
	CStr(path,1024);
	const char *opts;
	const char *iarg;
	AuthInfo ident;
	Connection *Conn = FS->fs_Conn;

	if( remp )
		*remp = 0;

	iarg = arg;
	if( arg[0] == '-' ){
		for( arg++; *arg; arg++ ){
			if( *arg == ' ' || *arg == '\t' ){
				arg++;
				break;
			}
		}
	}

	/* even empty argument might points to a directory on remote site
	 * at least when (proxy) FTP-DeleGate is running without bound
	 * to any FTP-server...
	if( *arg == 0 )
		return 0;
	 */

	IsMounted = 0;
	if( remote_path(arg) ){
		sprintf(vurl,"ftp:%s",arg);
		sv1log("direct access to remote: %s\n",vurl);
		opts = 0;
	}else{
		opts = mount_ftparg(FS,com,arg,AVStr(vurl));
		if( opts == 0 )
			return 0;
		IsMounted = 1;
	}
	FS->fs_authERR = 0;
	if( authOK(Conn,FS,opts,FS->fs_USER,FS->fs_PASS) < 0 ){
		FS->fs_authERR = 1;
		return 0;
	}

	decomp_absurl(vurl,AVStr(proto),AVStr(site),AVStr(path),sizeof(path));
	decomp_ftpsite(FS,AVStr(site),&ident);

	if( isFTPxHTTP(proto) ){
		return 0;
	}
	if( strcaseeq(proto,"file") || strcaseeq(proto,"lpr") )
		return 0;
	if( strcaseeq(proto,"https") )
		return 0;
	if( ident.i_Port <= 0 )
		return 0;

	if( FS->fs_Conn && 0 <= FS->fs_Conn->sv.p_wfd ) /* connected */
	if( sameident(FS,&ident) ){
		CStr(oarg,1024);
		CStr(narg,1024);
		strcpy(oarg,iarg);
		relative_path(FS,path,AVStr(narg));
		if( arg != iarg && *arg == 0 && *narg != 0 ){
			/* with -Opts without Path like "NLST -l" */
			setVStrPtrInc(arg,' ');
		}
		strcpy(arg,narg);
		sv1log("MOUNTED REMOTE [%s] -> [%s][%s]\n",oarg,vurl,iarg);
		if( remp )
			*remp = 1;
		clearAsProxy(Conn,"swRemote-2");
		return 0;
	}

	if( *path == 0 )
		strcpy(path,".");
	if( opts ){
		eval_mountOptions(FS->fs_Conn,opts);
		FTP_getMountOpts("swRemote",Conn,FS,opts);
	}
	sprintf(xserv,"%s/%s",site,path);
	sv1log("MOUNTED REMOTE [%s@%s:%d] %s %s\n",
		ident.i_user,ident.i_Host,ident.i_Port,com,path);
	clearAsProxy(Conn,"swRemote-1");

	FS->fs_Ident = ident;
	return 1;
}

static const char *isGateway(FtpStat *FS,int isdir,PCStr(rpath),PVStr(path),PVStr(scheme),PVStr(lphost),int *lpportp,PVStr(lpq),PVStr(fname))
{	CStr(vpath,1024);
	CStr(lprserv,64);
	CStr(upath,1024);
	const char *opt;
	int tail_added;

	/*
	if( lpr: is not in MOUNTs )
		return 0;
	*/

/*
	strcpy(vpath,FS->fs_CWD);
vpath must be in virtual path
*/
	getVUpath(FS,FS->fs_CWD,AVStr(vpath));
/*
	if( vpath[0] == 0 )
		strcpy(vpath,"/");
*/
	if( vpath[0] != '/' )
		Strins(AVStr(vpath),"/");
	chdir_cwd(AVStr(vpath),rpath,1);
	if( isdir && strtailchr(vpath) != '/' )
		strcat(vpath,"/");
	strcpy(path,vpath);
/*
 * vpath must be virtual path (by getVUpath()?)
 */

	if( opt = CTX_mount_url_to(FS->fs_Conn,NULL,"PUT",AVStr(path)) ){
		decomp_absurl(path,AVStr(scheme),AVStr(lprserv),AVStr(upath),sizeof(upath));
		if( strcasecmp(scheme,"lpr") == 0 ){
			setVStrEnd(lphost,0);
			*lpportp = 0;
			Xsscanf(lprserv,"%[^:]:%d",AVStr(lphost),lpportp);
			setVStrEnd(lpq,0);
			strcpy(fname,"LPR/FTP-GateWay");
			Xsscanf(upath,"%[^/]/%s",AVStr(lpq),AVStr(fname));
			sv1log("LPR: //%s /%s\n",lprserv,lpq);
			return opt;
		}
		if( strcasecmp(scheme,"https") == 0 ){
			sv1log("HTTPS/FTP-GateWay\n");
			return opt;
		}
	}
	return 0;
}

static int stripArgOpts(PVStr(arg),PVStr(opt)){
	const char *ap;
	IStr(optb,128);

	if( *arg == '-' ){
		ap = wordScan(arg,optb);
		strcpy(opt,optb);
		if( isspace(*ap) )
			ap++;
		ovstrcpy((char*)arg,ap);
		sv1log("#stripArgOpts[%s][%s]\n",opt,arg);
		return 1;
	}else{
		clearVStr(opt);
		return 0;
	}
}
static char *scanLISTarg(PCStr(com),PCStr(arg),PVStr(fopt))
{	const char *file;

	if( *arg == '-' )
		file = wordscanX(arg,AVStr(fopt),128);
	else{
		if( strcaseeq(com,"LIST") || strcaseeq(com,"STAT") )
			strcpy(fopt,FTP_LIST_OPT_ORIGIN);
		else	setVStrEnd(fopt,0);
		file = arg;
	}
	/*
	while( *file == ' ' || *file == '\t' )
	*/
	if( arg < file )
	if( *file == ' ' || *file == '\t' )
		file++;
	return (char*)file;
}
static void putlist(FtpStat *FS,FILE *fp,PCStr(com),PCStr(fopt),PCStr(path),PCStr(file))
{	const char *rexp;
	CStr(xfopt,1024);
	refQStr(vbase,xfopt); /**/
	const char *vopt;
	int len;

	rexp = 0;
	if( strneq(path,"/-stab-",7) ){
		/* should return the list of intermediate path in vURL of
		 * MOUNT which has "/path" as the substring of the vURL.
		 */
		fprintf(fp,"dummy\r\n");
	}else
	if( File_is(path) || (rexp = strpbrk(path,"*?[")) ){
		strcpy(xfopt,fopt);
		fopt = xfopt;
		if( vopt = strchr(xfopt,'v') ){ /* -v for test */
			if( strcmp(xfopt,"-v") == 0 )
				*xfopt = 0;
			else	ovstrcpy((char*)vopt,vopt+1);
		}
		if( rexp )
			strcat(xfopt,"*");
		strcat(xfopt,"V"); /* must be before "/" for NLST */

		/*
		 * reverse MOUNT for wild card output should be supported...
		 */
		if( vopt || strcaseeq(com,"NLST") ){
			strcat(xfopt,"/");
			vbase = xfopt + strlen(xfopt);
			if( getVUpath(FS,path,AVStr(vbase)) != NULL ){
				CStr(pcwd,1024);
				CStr(vcwd,1024);
				get_VPWD(FS,AVStr(pcwd),AVStr(vcwd));
				len = strlen(vcwd);
				if( strncmp(vbase,vcwd,len) == 0 ){
					if( vbase[len] == '/' )
						len++;
					ovstrcpy((char*)vbase,vbase+len);
				}
			}
		}
		if( comeq(com,"MLST") || comeq(com,"MLSD") ){
			CStr(fmt,1024);
			sprintf(fmt,"%s%s",comeq(com,"MLST")?" ":"",
				DFLT_MLS_FMT);
			strcat(xfopt,"L");
			if( comeq(com,"MLST") ){
				strcat(xfopt,"d");
			}
			ls_unix(fp,xfopt,AVStr(fmt),path,NULL);
		}else
		ls_unix(fp,xfopt,CVStr(NULL),path,NULL);
		sv1log("FTP LOCAL %s [%s][%s]\n",com,xfopt,file);
	}else{
		fprintf(fp,"unknown: %s\r\n",path);
	}
}
void fputs_CRLF(PCStr(str),FILE *fp)
{	const char *sp;
	char sc;
	for( sp = str; sc = *sp; sp++ ){
		if( sc == '\n' )
		if( sp == str || sp[-1] != '\r' )
			putc('\r',fp);
		putc(sc,fp);
	}
}
static FILE *localLIST(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path))
{	FILE *fp;
	const char *file;
	CStr(fopt,1024);
	CStr(scheme,64);
	CStr(lphost,64);
	CStr(lpq,64);
	CStr(fname,1024);
	CStr(stat,4096);
	int lpport;

	file = scanLISTarg(com,arg,AVStr(fopt));

	scheme[0] = 0;
	if( isGateway(FS,1,file,AVStr(path),AVStr(scheme),AVStr(lphost),&lpport,AVStr(lpq),AVStr(fname)) )
	if( strcaseeq(scheme,"lpr") ){
		stat_lpr(lphost,lpport,lpq,fopt,fname,AVStr(stat));
		fp = TMPFILE("FTP-LPRstat");
		if( TYPE_ASCII(FS) ){
			fputs_CRLF(stat,fp);
		}else{
			fputs(stat,fp);
		}
		fflush(fp);
		fseek(fp,0,0);
		return fp;
	}

	if( isLocal(FS,"GET",file,1,AVStr(path)) ){
		if( path[0] == '/' ) /* not DOS drive: */
		if( 2 <= strlen(path) && strtailchr(path) == '/' )
			setVStrEnd(path,strlen(path)-1);

		fp = TMPFILE("FTP-localLIST");

/* for clients which seems to expect -l by default ... */
if( strchr(fopt,'L') && strchr(fopt,'l') == 0 ){
	sv1log("#### ADDED -l to [%s]\n",fopt);
	strcat(fopt,"l");
}
		putlist(FS,fp,com,fopt,path,file);
		fflush(fp);
		fseek(fp,0,0);
		return fp;
	}
	return NULL;
}
static FILE *localRETR(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path))
{	FILE *fp;
	Connection *Conn = FS->fs_Conn;
	CStr(proto,64);

	if( FCF.fc_ftp_on_http )
	if( strcaseeq(com,"RETR") ){
		CStr(url,2048);
		strcpy(path,FS->fs_CWD);
		if( path[0] == '/' )
			ovstrcpy((char*)path,path+1);
		if( arg[0] ){
			if( path[0] ) strcat(path,"/");
			strcat(path,arg);
		}
		sprintf(url,"ftp://%s:%d/%s",FS->fs_host,FS->fs_port,path);
		if( fp = URLget(url,0,NULL) )
		if( 0 < file_size(fileno(fp)) ){
 sv1log("#### %x [%s] %d/%d [%s]\n\n",
 p2i(fp),url,iftell(fp),file_size(fileno(fp)),path);
			fseek(fp,0,1);
			return fp;
		}
		fclose(fp);
	}

	if( isLocal(FS,"GET",arg,0,AVStr(path)) ){
		if( fileIsdir(path) )
			return NULL;
		fp = fopen(path,"r");
		if( fp == NULL ){
			strcpy(proto,DFLT_PROTO);
			strcpy(DFLT_PROTO,"tar");
			if( service_permitted2(Conn,"tar",1) )
				fp = dirtar_fopen(path);
			strcpy(DFLT_PROTO,proto);
		}
		if( fp != NULL )
		if( FS->fs_REST ){
			FileSize off;
			fseek(fp,FS->fs_REST,0);
			/*
			Lseek(fileno(fp),FS->fs_REST,0);
			*/
			off = Lseek(fileno(fp),FS->fs_REST,0);
			if( off != FS->fs_REST ){
				sv1log("REST ERROR (lseek %lld -> %lld)\n",
					FS->fs_REST,off);
			}
			FS->fs_RESTed = FS->fs_REST;
			FS->fs_REST = 0;
		}
		return fp;
	}
	return NULL;
}

static int localCHANGE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(vpath)){
	IStr(path,1024);
	const char *opts;
	int code;

	opts = isLocal(FS,"PUT",vpath,0,AVStr(path));
	if( opts == 0 )
		return 0;
	if( strstr(opts,"rw") == NULL ){
		fprintf(tc,"553 Forbidden.\r\n");
		return 1;
	}
	sv1log("## %s %s\n",com,path);
	if( strcaseeq(com,"RNFR") ){
		if( File_is(path) ){
			code = 350;
			strcpy(FS->fs_RNFR,path);
			fprintf(tc,"%d OK\r\n",code);
		}else{
			code = 550;
			fprintf(tc,"%d no such file\r\n",code);
		}
		return 1;
	}
	if( strcaseeq(com,"RNTO") ){
		if( rename(FS->fs_RNFR,path) == 0 ){
			code = 250;
			fprintf(tc,"%d renamed\r\n",code);
		}else{
			code = 550;
			fprintf(tc,"%d cannot rename\r\n",code);
		}
		return 1;
	}
	if( strcaseeq(com,"DELE") ){
		if( unlink(path) == 0 ){
			code = 250;
			fprintf(tc,"%d removed\r\n",code);
		}else{
			code = 550;
			fprintf(tc,"%d cannot remove\r\n",code);
		}
		return 1;
	}
	if( strcaseeq(com,"MKD") ){
		if( mkdir(path,0770) == 0 ){
			code = 250;
			fprintf(tc,"%d created\r\n",code);
		}else{
			code = 550;
			fprintf(tc,"%d cannot create\r\n",code);
		}
		return 1;
	}
	if( strcaseeq(com,"RMD") ){
		if( rmdir(path) == 0 ){
			code = 250;
			fprintf(tc,"%d removed\r\n",code);
		}else{
			code = 550;
			fprintf(tc,"%d cannot remove\r\n",code);
		}
		return 1;
	}
	return 0;
}
static int localDELE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(vpath),PVStr(path),Connection *Conn,PCStr(user))
{	const char *opt;
	CStr(scheme,64);
	CStr(lphost,64);
	CStr(lpq,64);
	CStr(fname,1024);
	CStr(stat,4096);
	int lpport;
	int code;

	scheme[0] = 0;
	if( opt = isGateway(FS,0,vpath,AVStr(path),AVStr(scheme),AVStr(lphost),&lpport,AVStr(lpq),AVStr(fname)) )
	if( strcaseeq(scheme,"lpr") ){
		if( rmjob_lpr(Conn,lphost,lpport,lpq,user,vpath,AVStr(stat)) == 0 ){
			code = 250;
			fprintf(tc,"%d- removed [%s]\r\n",code,vpath);
		}else{
			code = 250;
			fprintf(tc,"%d- no such job [%s]\r\n",code,vpath);
		}
		fputs(stat,tc);
		fprintf(tc,"%d \r\n",code);
		return 1;
	}
	if( localCHANGE(FS,tc,com,vpath) ){
		return 1;
	}
	return 0;
}
static int connect_data(PCStr(where),FtpStat *FS,PVStr(port),int cntrlsock);
static FileSize XDCrelayServ(FtpStat *FS,int STOR,FILE *ts,FILE *fs,FILE *tc,FILE *fc,int dsock,PCStr(port), FILE *cachefp,PVStr(resp),int rsize);
int ftp_https_server(Connection *Conn,FtpStat *FS,FILE *ctc,FILE *cfc,int clsock,PCStr(com),PCStr(path));

int FTP_dataSTLS_FCL(Connection *Conn,Connection *dataConn,int cldata);
static int XinsertFCL(FtpStat *FS,int cdsock){
	Connection *ctrlConn = FS->fs_Conn;
	Connection *Conn = &FS->fs_dataConn;
	int gwf;
	int xsrc;
	int ncdsock = cdsock;

	gwf = GatewayFlags;
	GatewayFlags |= GW_SYN_SSLSTART;
	if( 0 <= (xsrc = insertFCL(Conn,ncdsock)) ){
		ncdsock = xsrc;
	}
	if( 0 <= (xsrc = FTP_dataSTLS_FCL(ctrlConn,Conn,ncdsock)) ){
		ncdsock = xsrc;
	}
	GatewayFlags = gwf;
	return ncdsock;
}

void putXferlog(Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg),FileSize start,FileSize xc,PCStr(cstat));
static int localSTOR(FtpStat *FS,FILE *tc,FILE *fc,PCStr(com),PCStr(vpath),PVStr(path),Connection *Conn,PCStr(user))
{	FILE *fp;
	const char *opts;
	int cdsock;
	/* v9.9.11 fix-140722c
	int wcc = -9;
	*/
	FileSize wcc = -9;
	int start = time(0);
	int xcdsock = -1;
	Connection *dataConn = &FS->fs_dataConn;
	CStr(port,256);
	FILE *ifp;
	CStr(scheme,64);
	CStr(lphost,64);
	CStr(lpq,64);
	CStr(fname,1024);
	CStr(stat,4096);
	int lpport;

	fp = NULL;
	scheme[0] = 0;
	if( opts = isGateway(FS,0,vpath,AVStr(path),AVStr(scheme),AVStr(lphost),&lpport,AVStr(lpq),AVStr(fname)) )
		goto STOR;

	opts = isLocal(FS,"PUT",vpath,0,AVStr(path));
	if( opts == NULL )
		return 0;

	if( strstr(opts,"rw") == NULL && strstr(opts,"writeonly") == NULL ){
		fprintf(tc,"553 Writing disabled.\r\n");
		return 1;
	}
	if( comeq(com,"APPE") )
	fp = fopen(path,"a");
	else
	fp = fopen(path,"w");
	if( fp == NULL ){
		fprintf(tc,"553 %s: Write permission denied.\r\n",vpath);
		return 1;
	}
STOR:
	if( FS->fs_XDCforCL ){
		cdsock = 0;
		strcpy(port,FS->fs_dport);
	}else
	cdsock = connect_data("FTP-LOCAL",FS,AVStr(port),ClientSock);
	xcdsock = cdsock;
	if( FCF.fc_waitSSL ){
		cdsock = XinsertFCL(FS,cdsock);
	}
	if( cdsock < 0 )
		fprintf(tc,"550 cannot connect with you.\r\n");
	else
	if( strcaseeq(scheme,"https") ){
		fprintf(tc,"150 Data connection for %s (%s)\r\n",vpath,port);
		fflush(tc);
		if( !FCF.fc_waitSSL ){
			cdsock = XinsertFCL(FS,cdsock);
		}
		wcc = ftp_https_server(FS->fs_Conn,FS,tc,fc,cdsock,com,path);
		fprintf(tc,"226 Transfer complete (%lld bytes)\r\n",wcc);
	}
	else{
		fprintf(tc,"150 Data connection for %s (%s)\r\n",vpath,port);
		fflush(tc);
		if( !FCF.fc_waitSSL ){
			cdsock = XinsertFCL(FS,cdsock);
		}

		ifp = NULL;
		if( strcaseeq(scheme,"lpr") ){
			if( FS->fs_XDCforCL ){
				FILE *tmp;
				tmp = TMPFILE("XDC-localSTOR");
				cdsock = fddup(fileno(tmp));
				fclose(tmp);
				wcc = XDCrelayServ(FS,1,NULL,NULL,tc,fc,
					fddup(cdsock),port,NULL,VStrNULL,0);
				Lseek(cdsock,0,0);
			}
			ifp = fdopen(cdsock,"r");

			if( INHERENT_fork() && FCF.fc_lpr_nowait ){
				FILE *tmp;
				int isize;
				tmp = TMPFILE("LPR/FTP");
				isize = copyfile1(ifp,tmp);
				fflush(tmp);
				fseek(tmp,0,0);
				if( Fork("LPR/FTP") == 0 ){
				wcc = send_lpr(Conn,lphost,lpport,lpq,tmp,isize,
					user,fname,AVStr(stat));
					Exit(0,"");
				}
				fclose(tmp);
				strcpy(stat,"sending to LPR ...\r\n");
			}else
			wcc = send_lpr(Conn,lphost,lpport,lpq,ifp,0,
				user,fname,AVStr(stat));
			fprintf(tc,"226- LPR response:\r\n");
			fputs(stat,tc);
			fprintf(tc,"226 \r\n");
		}else{
			if( FS->fs_XDCforCL ){
				wcc = XDCrelayServ(FS,1,NULL,NULL,tc,fc,
					fileno(fp),port,NULL,VStrNULL,0);
			}else{
				ifp = fdopen(cdsock,"r");
			wcc = copyfile1(ifp,fp);
			}
			fprintf(tc,"226 Transfer complete (%lld bytes)\r\n",wcc);
			sv1log("ftp-data [%s] uploaded %lld\n",com,wcc);
		}
		if( ifp )
		fclose(ifp);
	}
	if( fp )
		fclose(fp);

	if( 0 <= xcdsock && xcdsock != cdsock ){
		Connection *Conn = dataConn;
		sv1log("localSTOR (%lld) CF=%X %X\n",wcc,ClientFlags,ServerFlags);
		waitFilterThread(dataConn,300,XF_ALL);
		clearSTLS(dataConn);
	}

	FS->fs_cstat = "L";
	putXferlog(Conn,FS,com,vpath,start,wcc,""); /* v9.9.11 fix-140722b */
	return 1;
}

int mkdatafile(PCStr(data),int leng)
{	int fd;
	FILE *tmp;

	tmp = TMPFILE("mkdatafile");
	fwrite(data,1,leng,tmp);
	fflush(tmp);
	fseek(tmp,0,0);
	fd = fddup(fileno(tmp));
	fclose(tmp);
	return fd;
}
/*
 * DeleGate <- XDC <- DeleGate <- PASV <- client
 *  Even XDC-client DeleGate passes through PASV command from
 *  it's client since client-side-PASV to server-side-XDC conversion
 *  is not supported (in setupPASV()).
 * DeleGate <- XDC <- DeleGate <- PORT <- client
 *  But a PORT command from XDC-client is dummy PORT containing
 *  client's PORT (forwarded in setupPORT())
 *  and must not be used as PORT of the client-DeleGate
 *
if( FS->fs_dport[0] != 0 || 0 < FS->fs_pclsock )
 */
static int usemodeXDCtoCL(FtpStat *FS)
{
	if( 0 < FS->fs_pclsock )
		return 0;
	else	return FS->fs_XDCforCL;
}

void xdatamsg(FtpStat *FS,PVStr(msg),int datafd,PCStr(com),PCStr(path),FileSize dsize);
FileSize FTP_data_relay(Connection *Conn,FtpStat *FS,int src,int dst,FILE *cachefp,int tosv);

static FileSize putToClient(Connection *Conn,FtpStat *FS,FILE *tc,PCStr(com),PCStr(stat),int datafd,PCStr(data),int leng,PCStr(path))
{	FileSize wcc;
	CStr(msg,256);
	int cdsock;
	CStr(port,256);
	int modeXDC;

	modeXDC = usemodeXDCtoCL(FS);

	if( datafd < 0 && data == NULL ){
		fprintf(tc,"550 No such file\r\n");
		return -1;
	}

	if( FCF.fc_immportCL && 0 <= FS->fs_dclsock ){
		cdsock = FS->fs_dclsock;
		FS->fs_dclsock = -1;
		sv1log("#### DBG use IMMPORT %d\n",cdsock);
	}else
	if( modeXDC ){
		cdsock = 0;
		strcpy(port,FS->fs_dport);
	}else
	cdsock = connect_data("FTP-LOCAL",FS,AVStr(port),ClientSock);
	if( cdsock < 0 ){
		fprintf(tc,"550 cannot connect with you.\r\n");
		return -1;
	}

	if( stat ){
		fprintf(tc,"150- Ok\r\n");
		fprintf(tc,"%s",stat);
	}
	xdatamsg(FS,AVStr(msg),datafd,com,path,-1);
	fprintf(tc,"150 %s\r\n",msg);
	fflush(tc);

	if( modeXDC ){
		CStr(resp,256);
		if( datafd < 0 )
			datafd = mkdatafile(data,leng);
		else	datafd = fddup(datafd);
		wcc = XDCrelayServ(FS,0,NULL,NULL,tc,NULL,datafd,port,
			NULL,AVStr(resp),sizeof(resp));
	}else{
	if( 0 <= datafd )
		wcc = FTP_data_relay(Conn,FS,datafd,cdsock,NULL,0);
	else	wcc = write(cdsock,data,leng);
	close(cdsock);
	}

	putXcomplete(Conn,FS,tc,wcc);

	return wcc;
}
static void get_help(PVStr(data))
{	refQStr(dp,data); /**/

	dp = Sprintf(QVStr(dp,data),"150-  @ @  \r\n");
	dp = Sprintf(QVStr(dp,data),"150- ( - ) { %s }\r\n",DELEGATE_version());
	dp = Sprintf(QVStr(dp,data),"150- Enter cd //server/path\r\n");
	dp = Sprintf(QVStr(dp,data),"150-          to go `path' on FTP `server'\r\n");
	dp = Sprintf(QVStr(dp,data),"150- This (proxy) service is maintained by '%s'\r\n",
		DELEGATE_ADMIN);
}
static void putSTAT(Connection *Conn,FILE *tc)
{	CStr(myhost,MaxHostNameLen);

	ClientIF_name(Conn,FromC,AVStr(myhost));
	fprintf(tc,"211-%s FTP server status:\r\n",myhost);
	fprintf(tc,"    Version: FTP/%s\r\n",DELEGATE_version());
	fprintf(tc,"211 end of status\r\n");
}

/*
 * from "SP listOfFacts; /realpath"
 *   to "SP listOfFacts; /vpath"
 */
static void putMLST1(FtpStat *FS,int remote,PCStr(resp),FILE *tc){
	CStr(line,1024);
	refQStr(lp,line);
	CStr(fname,1024);
	CStr(vpath,1024);

	if( *resp != ' ' ){
		fputs(resp,tc);
		return;
	}
	strcpy(line,resp);
	if( lp = strrchr(line,';') )
		lp++;
	else	lp = line;
	if( *lp == ' ')
		lp++;
	lineScan(lp,fname);
	truncVStr(lp);

	getVUpathX(FS,fname,AVStr(vpath),remote);
	fprintf(tc,"%s%s\r\n",line,vpath);
}
static void relayMLST(FtpStat *FS,PCStr(resp),FILE *tc){
	CStr(line,1024);
	const char *rp;

	for( rp = resp; rp && *rp; ){
		if( rp = wordscanY(rp,AVStr(line),sizeof(line),"^\n") ){
			if( *rp == '\n' ){ strcat(line,"\n"); rp++; }
		}
		putMLST1(FS,1,line,tc);
	}
}
static void fputsMLST(FtpStat *FS,int remote,FILE *tmp,FILE *fp,PVStr(stat)){
	CStr(line,1024);
	refQStr(rp,stat);

	while( fgets(line,sizeof(line),tmp) != NULL ){
		putMLST1(FS,remote,line,fp);
		if( stat != NULL ){
			strcpy(rp,line);
			rp += strlen(rp);
		}
	}
}
static void putlistV(FtpStat *FS,FILE *fp,PCStr(com),PCStr(fopt),PCStr(path),PCStr(file)){
	FILE *tmp;

	tmp = TMPFILE("putlistV");
	putlist(FS,tmp,com,fopt,path,file);
	fflush(tmp);
	fseek(tmp,0,0);
	fputsMLST(FS,0,tmp,fp,VStrNULL);
	fclose(tmp);
}

static int localSTAT(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),int islocal)
{	const char *file;
	CStr(fopt,128);
	CStr(path,1024);
	int body;

	if( islocal && comeq(com,"MLST") && arg[0] == 0 ){
		arg = ".";
	}
	if( islocal && arg[0] == 0 ){
		putSTAT(FS->fs_Conn,tc);
		return 1;
	}

	file = scanLISTarg(com,arg,AVStr(fopt));
	if( strncasecmp(fopt,"-HTTP",5) == 0 ){
		*fopt = 0;
		body = 1;
	}else	body = 0;

	if( isLocal(FS,"GET",file,0,AVStr(path)) ){
	/*
	    if( arg[0] == 0 ){
	*/
	    if( !comeq(com,"MLST") && arg[0] == 0 ){
		putSTAT(FS->fs_Conn,tc);
	    }else{
		fprintf(tc,"211-status of %s [%s][%s]:\r\n",arg,fopt,file);
		if( path[0] == '/' && isFullpath(path+1) ){ /* DOS drive: */
			ovstrcpy(path,path+1);
		}
		if( body ){
			putFileInHTTP(tc,path,file);
			fputs("\r\n--\r\n",tc);
		}else
		if( comeq(com,"MLST") ){
			putlistV(FS,tc,com,fopt,path,file);
		}else	putlist(FS,tc,com,fopt,path,file);
		fprintf(tc,"211 end of status\r\n");
	    }
	    return 1;
	}else{
	    if( islocal ){
		fprintf(tc,"211-status of %s [%s][%s]:\r\n",arg,fopt,file);
		fprintf(tc,"%s not found\r\n",file);
		fprintf(tc,"211 end of status\r\n");
	    }
	    return 0;
	}
}

static int setupPORT(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,FILE *tc,PCStr(arg));
static int setupPASV(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,FILE *tc,PCStr(arg));

static int AsServer0(Connection *Conn,FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PCStr(user))
{	int done = 1;

	if( strcasecmp(com,"XECHO") == 0 ){
		fprintf(tc,"%s\r\n",arg);
	}else
	if( strcasecmp(com,"NOOP") == 0 ){
		fprintf(tc,"200 NOOP command successful.\r\n");
	}else
	if( strcasecmp(com,"SYST") == 0 ){
		/*
		fprintf(tc,"500 SYST command is not supported.\r\n");
		*/
		fprintf(tc,"215 UNIX Type: L8\r\n");
	}else
	if( strcasecmp(com,"MODE") == 0 ){
		set_client_mode(FS,arg);
		fprintf(tc,"200 MODE %s Ok.\r\n",arg);
	}else
	if( strcasecmp(com,"PORT") == 0 ){
		setupPORT(Conn,FS,NULL,NULL,tc,arg);
	}else
	if( strcasecmp(com,"EPRT") == 0 ){
		setupPORT(Conn,FS,NULL,NULL,tc,arg);
	}else
	if( strcasecmp(com,"PASV") == 0 ){
		setupPASV(Conn,FS,NULL,NULL,tc,arg);
	}else
	if( strcasecmp(com,"EPSV") == 0 ){
		setupPASV(Conn,FS,NULL,NULL,tc,arg);
	}else
	if( strcasecmp(com,"TYPE") == 0 ){
		wordScan(arg,FS->fs_TYPE);
		fprintf(tc,"200 Type set to %s\r\n",FS->fs_TYPE);
	}else
	if( strcasecmp(com,"REST") == 0 ){
		Xsscanf(arg,"%lld",&FS->fs_REST);
		if( 0 < FS->fs_REST )
			fprintf(tc,"350 Restarting at %lld.\r\n",FS->fs_REST);
		else{
			fprintf(tc,"500 bad offset %lld.\r\n",FS->fs_REST);
			FS->fs_REST = 0;
		}
	}else{
		done = 0;
	}
	return done;
}

/*
 * it can be always TRUE after LIST / MLSD conversion is implemented.
 */
static int withMLSD(Connection *Conn,FtpStat *FS){
	if( FS->fs_islocal == IS_LOCAL ){
		return 1;
	}
	return 0;
}

int FTP_putSTLS_FEAT(Connection *Conn,FILE *tc,int wrap);
static void putFEAT(Connection *Conn,FtpStat *FS,FILE *tc,int ckssl){
	fprintf(tc,"211-Extensions supported\r\n");
	fprintf(tc," MDTM\r\n");
	if( !FCF.fc_noMLSxCL )
	if( withMLSD(Conn,FS)
	 || isinFTPxHTTP(Conn)
	 || isFTPxHTTP(FS->fs_proto) /* not assured to be set ? */
	){
		fprintf(tc," MLSD %s\r\n",FEAT_MLS);
		fprintf(tc," MLST %s\r\n",FEAT_MLS);
	}
	fprintf(tc," SIZE\r\n");
	if( !FCF.fc_nopasvCL || FCF.fc_doepsvCL )
	if( !FCF.fc_noepsvCL )
		fprintf(tc," EPSV\r\n");
	if( !FCF.fc_noportCL )
		fprintf(tc," EPRT\r\n");

	if( ckssl ){
		FTP_putSTLS_FEAT(Conn,tc,0);
	}
	fprintf(tc,"211 END\r\n");
}

static int AsServer(Connection *Conn,FtpStat *FS,FILE *tc,FILE *fc,PCStr(com),PCStr(arg),PCStr(user))
{	CStr(data,4096);
	CStr(path,1024);
	FILE *fp;
	int done = 1;
	int authok = 0;

	if( FS->fs_anonymousOK == 0
	 && FS->fs_authERR == 0
	 && FS->fs_aub.i_Host[0] != 0 /* implies MOUNT AUTHORIZER */
	){
		authok = 1;
	}
	if( isFTPxHTTP(FS->fs_proto) ){
		if( authok == 0 ){
			authok = 2;
		}
	}

	if( AsServer0(Conn,FS,tc,com,arg,user) ){
	}else
	if( !FS->fs_anonymousOK && (FS->fs_islocal&FS_NOAUTH)==0 && !authok ){
		/*
		 * only anonymous login is allowed in the current implementation.
		 * opts = isLocal()
		 * check "user=..." in opts
		 */
		done = 0;
	}else
	if( strcasecmp(com,"FEAT") == 0 ){
		putFEAT(Conn,FS,tc,1);
	}else
	if( strcasecmp(com,"MDTM") == 0 || strcasecmp(com,"SIZE") == 0 ){
		CStr(paht,1024);
		CStr(stime,128);
		if( ftpxhttpSIZE(FS,tc,com,arg) ){
		}else
		if( isLocal(FS,"GET",arg,0,AVStr(path)) && File_is(path) ){
			if( fileIsdir(path)){
				fprintf(tc,"550 %s: Not a plain file\r\n",arg);
			}else
			if( strcaseeq(com,"MDTM") ){
				StrftimeGMT(AVStr(stime),sizeof(stime),"%Y%m%d%H%M%S",File_mtime(path),0);
				fprintf(tc,"213 %s\r\n",stime);
			}else
			if( strcaseeq(com,"SIZE") ){
				fprintf(tc,"213 %lld\r\n",File_sizeX(path));
			}
		}else	fprintf(tc,"550 %s: No such file\r\n",arg);
	}else
	/*
	if( strcasecmp(com,"STAT") == 0 ){
	*/
	if( comeq(com,"STAT") || !FCF.fc_noMLSxCL && comeq(com,"MLST") ){
		if( ftpxhttpSTAT(FS,tc,com,arg) ){
		}else
	    localSTAT(FS,tc,com,arg,1);
	}else
	if( comUPLOAD(com) ){
		if( ftpxhttpSTOR(FS,tc,fc,com,arg,AVStr(path)) ){
			return 2;
		}else
		if( localSTOR(FS,tc,fc,com,arg,AVStr(path),Conn,user) )
			return 1;
		return 0;
	}else
	if( strcasecmp(com,"DELE")==0 ){
		if( ftpxhttpCHANGE(FS,tc,com,arg) ){
			return 2;
		}else
		if( localDELE(FS,tc,com,arg,AVStr(path),Conn,user) )
			return 1;
		else	return 0;
	}else
	if( comCHANGE(com) ){
		if( ftpxhttpCHANGE(FS,tc,com,arg) ){
			return 2;
		}else
		if( localCHANGE(FS,tc,com,arg) )
			return 1;
		else	return 0;
	}else
	/*
	if( strcasecmp(com,"LIST")==0 || strcasecmp(com,"NLST")==0 ){
	*/
	if( comeq(com,"LIST") || comeq(com,"NLST")
	 || !FCF.fc_noMLSxCL && comeq(com,"MLSD")
	){
		if( ftpxhttpLIST(FS,tc,com,arg,AVStr(path),VStrNULL) ){
		}else
		if( fp = localLIST(FS,tc,com,arg,AVStr(path)) ){
			putToClient(Conn,FS,tc,com,NULL,fileno(fp),NULL,0,path);
			fclose(fp);
		}else{
			get_help(AVStr(data));
			putToClient(Conn,FS,tc,com,data,-1,"",0,"(init)");
		}
	}else
	if( strcasecmp(com,"RETR") == 0 ){
		int start;
		int leng;
		FileSize xc;

		start = time(0);
		if( ftpxhttpRETR(FS,tc,com,arg,AVStr(path)) ){
		}else
		if( fp = localRETR(FS,tc,com,arg,AVStr(path)) ){
			xc = putToClient(Conn,FS,tc,com,NULL,fileno(fp),NULL,0,path);
			fclose(fp);
			FS->fs_cstat = "L";
			putXferlog(Conn,FS,com,arg,start,xc,"");
		}else	putToClient(Conn,FS,tc,com,NULL,-1,NULL,0,"(error)");
	}else{
		/*fprintf(tc,"500 Unknown command\r\n");*/
		done = 0;
	}

	if( !strcaseeq(com,"RETR") && !comUPLOAD(com) )
	if( !strcaseeq(com,"REST") && 0 < FS->fs_REST ){
		sv1log("## %s: cleared REST %lld\n",com,FS->fs_REST);
		FS->fs_REST = 0;
	}
	return done;
}

static int rewrite_CWD(FtpStat *FS,PVStr(req),PVStr(arg),FILE *tc)
{	CStr(mdir,1024);
	CStr(vdir,1024);
	CStr(npath,1024);
	const char *ncwd;
	/*
	CStr(rmsg,1024);
	 */
	IStr(rmsg,1024); /* fix-140506a */
	const char *opts;
	Connection *Conn = FS->fs_Conn;
	CStr(uproto,32);
	CStr(usite,64);
	CStr(upath,256);
	CStr(uhost,64);
	int uport;
	int sv_IsMounted;
	int sv_fs_islocal;
	CStr(sv_fs_CWD,1024);
	CStr(sv_fs_prevVWD,1024);

	/* if( with MOUNT with AUTHORIZER MountOption ) */
	if( 1 ){ /* 9.2.2 save the context to restore on authERR */
		sv_IsMounted = IsMounted;
		sv_fs_islocal = FS->fs_islocal;
		strcpy(sv_fs_CWD,FS->fs_CWD);
		strcpy(sv_fs_prevVWD,FS->fs_prevVWD);
	}

	getVUpath(FS,FS->fs_CWD,AVStr(mdir));
	if( mdir[0] == 0 )
		strcpy(mdir,"/");

	if( isFTPxHTTP(FS->fs_proto) ){
		if( mdir[0] != '/' ){
			/* should be relative to LoginDir ? */
			Strins(AVStr(mdir),"/");
		}
	}
	strcpy(FS->fs_prevVWD,mdir);

	chdir_cwd(AVStr(mdir),arg,1);
	strcpy(vdir,mdir);

	if( strncmp(FS->fs_CWD,"//",2) == 0 && strncmp(mdir,"//",2) != 0 ){
		refQStr(dp,mdir); /**/
		strcpy(mdir,FS->fs_CWD);
		if( dp = strchr(mdir+2,'/') )
			chdir_cwd(AVStr(dp),arg,1);
	}

	IsMounted = 0;
	FS->fs_islocal = 0;

	if( strtailchr(mdir) != '/' )
		strcat(mdir,"/");

	opts = CTX_mount_url_to(FS->fs_Conn,NULL,"GET",AVStr(mdir));
	if( opts == 0 ){
		strcpy(vdir,FS->fs_CWD);
		if( mdir[0] == 0 )
			strcpy(vdir,"/");
		else
		if( strtailchr(vdir) != '/' )
			strcat(vdir,"/");
		strcpy(mdir,vdir);
		if( CTX_mount_url_to(FS->fs_Conn,NULL,"GET",AVStr(mdir)) )
		if( strncmp(mdir,"lpr:",4) == 0 ){
			strcpy(mdir,vdir);
			chdir_cwd(AVStr(mdir),arg,1);
			strcpy(FS->fs_CWD,mdir);
			sv1log("LEAVE-MOUNTED-LPR: %s => %s\n",vdir,mdir);
			sprintf(rmsg,"250 CWD command successful.\r\n");
			goto EXIT;
		}
		return 0;
	}

	if( opts ){
		eval_mountOptions(FS->fs_Conn,opts);
	}
	if( authOK(Conn,FS,opts,FS->fs_USER,FS->fs_PASS) < 0 ){
		IsMounted = sv_IsMounted;
		FS->fs_islocal = sv_fs_islocal;
		strcpy(FS->fs_CWD,sv_fs_CWD);
		strcpy(FS->fs_prevVWD,sv_fs_prevVWD);

		if( FS->fs_aub.i_realm[0] ){
			sprintf(rmsg,"530 %s\r\n",FS->fs_aub.i_realm);
		}else
		sprintf(rmsg,"530 not Authorized\r\n");
		goto EXIT;
	}

	if( strncmp(mdir,"lpr://",6) == 0 ){
		sv1log("MOUNTED-TO-LPR: %s => %s\n",vdir,mdir);
		strcpy(FS->fs_CWD,vdir);
		sprintf(rmsg,"250 CWD command successful.\r\n");
		goto EXIT;
	}

	decomp_absurl(mdir,AVStr(uproto),AVStr(usite),AVStr(upath),sizeof(upath));
	if( streq(uproto,"http")
	 || streq(uproto,"pop")
	 || streq(uproto,"nntp")
	 || streq(uproto,"news")
	){
		strcpy(FS->fs_proto,uproto);
		FS->fs_port = scan_hostport(uproto,usite,AVStr(FS->fs_host));
		strcpy(FS->fs_loginroot,upath);
		FS->fs_login1st = 1;
		sv1log("MOUNTED-TO-%s: %s => %s\n",uproto,vdir,mdir);
		strcpy(FS->fs_CWD,vdir);
		sprintf(rmsg,"250 CWD command successful.\r\n");
		goto EXIT;
	}
	if( isFTPxHTTP(uproto) ){
		IStr(ocwd,1024);
		IStr(dstproto,64);
		int hcode;

		IsMounted = 1;
		strcpy(FS->fs_proto,uproto);
		FS->fs_port = scan_hostport(uproto,usite,AVStr(FS->fs_host));
		strcpy(FS->fs_loginroot,upath);
		sv1log("MOUNTED-TO-%s: %s => %s\n",uproto,vdir,mdir);
		strcpy(ocwd,FS->fs_CWD);
		strcpy(FS->fs_CWD,vdir);
		if( ftpxhttpCHANGE(FS,tc,"CWD",vdir) < 0 ){
			strcpy(FS->fs_CWD,ocwd);
		}
		/* response message(rmsg) is sent already in ftpxhttpCHANGE() */
		goto EXIT;
		/* the followings are in ftpxhttpCHANGE() */
		if( streq(vdir,"/") ){
			hcode = 300;
		}else{
			hcode = ftpxhttpSIZE(FS,0,"CWD",vdir);
		}
		/* testing "vdir" by HEAD to resp. 301 (MovedTo "vdir/") */
		if( 300 <= hcode && hcode <= 303 ){
			sprintf(rmsg,"250 CWD command successful\r\n");
		}else{
			sprintf(rmsg,"550 no such directory\r\n");
			strcpy(FS->fs_CWD,ocwd);
		}
		goto EXIT;
	}

	if( strncaseeq(mdir,"ftps://",7) ){
		/* default port shuold be 990 ... */
		Strrplc(AVStr(mdir),4,"ftp");
		ServerFlags |=  PF_SSL_IMPLICIT;
	}else{
		ServerFlags &= ~PF_SSL_IMPLICIT;
	}

	/*
	if( strncmp(mdir,"ftp://",6) == 0 ){
	*/
	/*
	if( strncasecmp(mdir,"ftp://",6) == 0 ){
	*/
	if( strncaseeq(mdir,"ftp://",6) || strncaseeq(mdir,"sftp://",7) ){
		/*
		strcpy(arg,mdir+4);
		*/
		strcpy(arg,strstr(mdir,"//"));
		if( req != NULL )
			sprintf(req,"CWD %s\r\n",arg);
		sv1log("MOUNTED-TO: %s\n",arg);
		if( streq(uproto,"sftp") ){
			strcpy(FS->fs_proto,"sftp");
			FS->fs_port = scan_hostport(uproto,usite,AVStr(FS->fs_host));
			strcpy(FS->fs_loginroot,upath);
			sv1log("-SFTPGW:CWD set FS->fs_proto=sftp\n");
		}else{
			/* fs_proto might have to be cleared */
		}
		IsMounted = 1;
		if( streq(CLNT_PROTO,"ftps") && !streq(DST_PROTO,"ftp") ){
			/* 9.9.2 to permit MOUNTed ftp/ftps gw. by default */
			Conn->no_dstcheck_proto = serviceport("ftp");
		}
		setMountOptions(FL_ARG,Conn,opts);
		FTP_getMountOpts("rewrite_CWD",Conn,FS,opts);
		/*
		MountOptions = opts;
		*/
		clearAsProxy(Conn,"rewrite_CWD");
		return 0;
	}

	if( strncmp(mdir,"file://localhost/",17) != 0 )
		return 0;

	FS->fs_islocal = 1;
	if( NoAuth ) FS->fs_islocal |= FS_NOAUTH;
	ncwd = mdir + 16;
	if( ncwd[1] != '/' && isFullpath(ncwd+1) ) /* DOS drive: */
		ncwd++;

	if( strncmp(ncwd,"/-stab-",7) == 0 ){
		/* if it's the substring of MOUNTs left hands vURLs ... */
		sv1log("MOUNTED-TO-STAB: %s\n",mdir);
		strcpy(FS->fs_CWD,ncwd);
		sprintf(rmsg,"250 CWD command successful.\r\n");
		FS->fs_islocal = IS_STAB;
	}else
	if( fileIsdir(ncwd) ){
		sv1log("MOUNTED-TO-LOCAL: %s\n",mdir);
		strcpy(FS->fs_CWD,ncwd);
		sprintf(rmsg,"250 CWD command successful.\r\n");
	}else{
		sv1log("MOUNTED-TO-LOCAL#UNKNOWN: %s\n",mdir);
		sprintf(rmsg,"550 %s: No such directory.\r\n",vdir);
	}
EXIT:
	if( tc != NULL ){
		fputs(rmsg,tc);
		fflush(tc);
	}
	return 1;
}
static int scanPWD(PCStr(resp),PVStr(path),xPVStr(rem))
{	CStr(rembuf,1024);

	if( rem == NULL )
		setPStr(rem,rembuf,sizeof(rembuf));
	setVStrEnd(rem,0);
	setVStrEnd(path,0);
	return Xsscanf(resp,"257 \"%[^\"]\"%[^\r\n]",AVStr(path),AVStr(rem));
}
static int rewrite_PWD(FtpStat *FS,PCStr(req),PCStr(arg),FILE *tc)
{	CStr(cwd,1024);
	CStr(npath,1024);
	CStr(resp,1024);

	if( get_VPWD(FS,AVStr(cwd),AVStr(npath)) < 0 )
		return 0;

	sv1log("local echo for PWD: ftp://%s:%d/%s\n",
		FS->fs_host,FS->fs_port,cwd);

	if( streq(npath,FS->fs_logindir) )
	{
		if( !FCF.fc_nounesc
		 && strncaseeq(cwd,"%2F",3) ){
			/* 9.9.1 with MOUNT="/* ftp://server/%2F* */
			/* logindir is not the root directory */
		}else
		strcpy(npath,"");
	}
	if( npath[0] == 0 ){
		/* 9.2.5 returning "" breaks MOUNT of client-side DeleGate */
		if( FCF.fc_nullPWD ){
		}else{
			strcpy(npath,"/");
		}
	}

	sprintf(resp,"257 \"%s\" is current directory.\r\n",npath);
	sv1log("I-SAY: %s",resp);
	CCXresp(FS->fs_Conn,FS,resp,AVStr(resp),sizeof(resp));
	fputs(resp,tc);
	fflush(tc);
	return 1;
}
static int getFTPWD(PCStr(wh),FtpStat *FS,PVStr(resp));
static void getPWD(FtpStat *FS,PVStr(pwd),int siz)
{	CStr(resp,1024);

	if( getFTPWD("getPWD",FS,AVStr(resp)) ){
		/* new-110521d to suppress PWD to save dir. before tmp. CWD */
		scanPWD(resp,BVStr(pwd),VStrNULL);
		chdir_cwd(BVStr(pwd),FS->fs_CWD,0);
		sv1log("##FTPWD/getPWD[%s][%s][%s]\n",resp,FS->fs_CWD,pwd);
		return;
	}
	setVStrEnd(pwd,0);
	if( put_get(FS->fs_ts,FS->fs_fs,AVStr(resp),sizeof(resp),"PWD\r\n") != EOF )
		scanPWD(resp,AVStr(pwd),VStrNULL);
}
static void setLoginPWD0(FtpStat *FS,PCStr(resp))
{	CStr(path,1024);

	scanPWD(resp,AVStr(path),VStrNULL);
	if( path[0] == 0 ){
		/* 9.2.5 setting LoginPWD "" breaks MOUNT of this DeleGate */
		if( FCF.fc_nullPWD ){
		}else{
			strcpy(path,"/");
		}
	}
	strcpy(FS->fs_logindir,path);
	sv1log("LoginPWD: \"%s\"\n",path);
}
static int get_resp(FILE *fs,FILE *tc,PVStr(resps),int rsize);
static int setLoginPWD(FtpStat *FS,FILE *ts,FILE *fs)
{	CStr(resp,1024);

	if( getFTPWD("setLoginPWD",FS,AVStr(resp)) ){
		/* new-110521d to suppress PWD to see the login dir. */
		setLoginPWD0(FS,resp);
		return 0;
	}
	fputs("PWD\r\n",ts);
	fflush(ts);
	if( get_resp(fs,NULL,AVStr(resp),sizeof(resp)) == EOF )
		return -1;

	setLoginPWD0(FS,resp);
	return 0;
}
/* new-110521d to suppress generating PWD to a FTP server */
/* Usage Example: CMAP="/:FTPWD:ftp:*:*" */
static int getFTPWD(PCStr(wh),FtpStat *FS,PVStr(resp)){
	IStr(ftpwd,128);

	if( 0 <= find_CMAP(FS->fs_Conn,"FTPWD",TVStr(ftpwd)) ){
		sprintf(resp,"257 \"%s\"",ftpwd);
		return 1;
	}
	return 0;
}
int CTX_checkAnonftpAuth(Connection *Conn,PVStr(user),PCStr(pass)) 
{	refQStr(host,user); /**/
	int smtp_vrfy,checkuser;

	if( CTX_auth_anonftp(Conn,"*",user,pass) )
		return 0;

	if( CTX_auth_anonftp(Conn,"smtp-vrfy",user,pass) ){ 
		smtp_vrfy = 1;
		checkuser = 1;
	}else
	if( CTX_auth_anonftp(Conn,"smtp-vrfy",user,"-@*") ){
		smtp_vrfy = 1;
		checkuser = 0;
	}else{
		smtp_vrfy = 0;
		checkuser = 1;
	}

	if( smtp_vrfy ) 
	if( validateEmailAddr(user,checkuser) == 0 ){
		if( host = strchr(user,'@') ){
			host++;
			if( strchr(host,'.') == 0 && !isinetAddr(host) ){
				getFQDN(host,AVStr(host));
				sv1log("anonftp PASS rewritten with FQDN: %s\n",
					user);
			}
		}
		return 0;
	}

	return -1;
}
static int anonPASS(Connection *Conn,FILE *tc,PCStr(user),PVStr(pass))
{	CStr(pass1,256);
	CStr(pass2,256);

	RFC822_addresspartX(pass,AVStr(pass1),sizeof(pass1));
	strcpy(pass2,pass1);

	if( CTX_checkAnonftpAuth(Conn,AVStr(pass2),pass2) == 0 ){
		if( strcmp(pass1,pass2) != 0 )
			strcpy(pass,pass2);/* host part rewriten by smtp-vrfy */
		return 0;
	}

	if( tc != NULL ){
		CStr(clnt,MaxHostNameLen);
		getClientHostPort(Conn,AVStr(clnt));
		sv1log("Bad anonymous login:[%s][%s]<-(%s)\n",user,pass,clnt);
		fprintf(tc,"530 Invalid/Forbidden Email address '%s'.",pass);
		if( streq(pass,"mozilla@") ){
			CStr(me,MaxHostNameLen);
			const char *dp;
			ClientIF_HPname(Conn,AVStr(me));
			if( dp = strtailstr(me,":21") )
				truncVStr(dp);
			fprintf(tc," Try URL ftp://ftp@%s/ to indicate your Email address as a password.",me);
		}
		if( streq(pass,"IEUser@")
		 || streq(pass,"IE30User@")
		 || streq(pass,"IE40User@")
		){
			fprintf(tc," Find %s in your registory and repair it...",pass);
		}
		fprintf(tc,"\r\n");
		fflush(tc);
	}
	return -1;
}

static void ftp_banner(Connection *Conn,FILE *tc)
{	const char *aurl;
	CStr(rurl,256);
	CStr(msg,2048);
	CStr(buf,0x4000);
	FILE *tmp;
	int rcc;

	aurl = "/-/builtin/mssgs/file/ftp-banner.dhtml";
	getBuiltinData(Conn,"FTP-banner",aurl,AVStr(msg),sizeof(msg),AVStr(rurl));

	tmp = TMPFILE("FTPbanner");
	put_eval_dhtml(Conn,rurl,tmp,msg);
	fflush(tmp);
	fseek(tmp,0,0);
	if( 0 <= (rcc = fread(buf,1,sizeof(buf)-1,tmp)) )
		setVStrEnd(buf,rcc);
	else	setVStrEnd(buf,0);
	insert_scode(buf,tc,220);

	if( !FCF.fc_noxdcCL )
		fprintf(tc,"%s\r\n",XDC_OPENING_B64);

	fprintf(tc,"220  \r\n");
	fclose(tmp);
}

double STLS_fsvim_wait(double ws);
int FTP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs);
int FTP_STARTTLS_withCL(Connection *Conn,FILE *tc,FILE *fc,PCStr(com),PCStr(arg));
int FTP_dataSTLS_FSV(Connection *Conn,Connection *dataConn,int svdata);
int FTP_dataSTLS_FCL(Connection *Conn,Connection *dataConn,int cldata);

static void url_login(Connection *oConn,FtpStat *FS,FILE *fc,FILE *tc,PCStr(user),PCStr(pass))
{	CStr(url,1024);
	FILE *hfp;
	Connection ConnBuf, *Conn = &ConnBuf;
	const char *msg;

	ConnInit(Conn);
	ToS = ToSX = -1;
	Conn->from_myself = 1;
	wordScan(user,ClientAuth.i_user);
	lineScan(pass,ClientAuth.i_pass);
	/*
	Conn->cl_auth.i_stat = AUTH_SET;
	*/
	Conn->cl_auth.i_stat = AUTH_FORW;

	sprintf(url,"%s://%s:%d/%s",FS->fs_proto,FS->fs_host,FS->fs_port,
		FS->fs_loginroot);
	Conn->no_dstcheck_proto = serviceport(FS->fs_proto);
	hfp = CTX_URLget(Conn,1,url,1,NULL);
	if( hfp && !feof(hfp) )
		msg = "230 logged in";
	else	msg = "530 cannot login";
	sv1log("## %s -> %s\n",url,msg);
	fprintf(tc,"%s\r\n",msg);
	if( hfp )
		fclose(hfp);
}
static int controlCWD(FtpStat *FS,FILE *tc,PCStr(dir));

static int px_doAUTH(FtpStat *FS,Connection *Conn,FILE *tc,PVStr(auser),PVStr(apass),PVStr(ahost),PVStr(cuser),PVStr(cpass),PVStr(cserv)){
	int ok;
	const char *proto = "ftp";
	const char *host = "-";
	int port = 0;
	IStr(up,256);
	refQStr(hostp,up);
	refQStr(passp,up);
	IStr(hostb,MaxHostNameLen);
	IStr(svup,256);
	IStr(userb,128);
	AuthInfo ident;
	IStr(iuser,128); /* u of USER u@h */
	IStr(ihost,128); /* h of USER u@h */

	sprintf(up,"%s:%s",auser,apass);

	if( FCF.fc_authproxy ){
		if( strrchr(auser,'@') ){
			Xsscanf(auser,"%[^@]@%s",AVStr(iuser),AVStr(ihost));
		}
	}
	if( FCF.fc_authproxy & (PXA_HOSTMAP|PXA_USERHOSTMAP) ){
		/* user@host to be matched with user at host */
		if( ihost[0] ){
			port = scan_hostport(proto,ihost,AVStr(hostb));
			host = hostb;
			if( FCF.fc_authproxy & PXA_USERHOSTMAP ){
				sprintf(up,"%s:%s",iuser,apass);
			}
		}
	}

	bzero(&ident,sizeof(ident));
	ok = doAUTH(Conn,0,tc,proto,host,port,AVStr(up),BVStr(ahost),0,&ident);

	if( ident.i_stat & AUTH_FORW )
	if( ident.i_stype == (AUTH_AORIGIN | AUTH_APROXY) ){
		if( FCF.fc_proxy == NULL || isinList(FCF.fc_proxy,"user") ){
			strcpy(cuser,ident.i_user);
			strcpy(cpass,ident.i_pass);
			strcpy(cserv,ident.i_Host);
		}
	}
	if( FCF.fc_authproxy & PXA_USERGEN ){
		/* if with maped-username with AUTHORIZER=asv(mapped-user) */
		if( ident.i_stat & AUTH_MAPPED ){
			Xsscanf(auser,"%[^:]",AVStr(userb));
			sv1log("USER %s <- %s\n",ident.i_user,userb);
			strsubst(AVStr(auser),userb,ident.i_user);
			FS->fs_proxyauth.i_stat |= AUTH_SET;
		}
	}
	if( FCF.fc_authproxy & (PXA_AUTHGEN|PXA_USERHOSTMAP) ){
		/* MYAUTH=u:p:ftp:host */
		if( get_MYAUTH(Conn,AVStr(svup),proto,host,port) ){
			strsubst(AVStr(svup),"%h",ihost);
			strsubst(AVStr(svup),"%U",auser);
			strsubst(AVStr(svup),"%P",apass);
			Xsscanf(svup,"%[^:]:%s",AVStr(cuser),AVStr(cpass));
		}
	}
	return ok;
}

static void proxyFTP(Connection *Conn)
{	FILE *tc,*fc;
	CStr(req,1024);
	const char *dp;
	CStr(com,128);
	CStr(arg,1024);
	const char *chost;
	CStr(cuser,256);
	CStr(cpass,256);
	CStr(cserv,1024);
	CStr(usermbox,MaxHostNameLen);
	int anonymous = 0;
	int islocal;
	int csock;
	FtpStat FSbuf, *FS = &FSbuf;
	int timeout;
	int proxyLoggedin;
	FILE *xtc;
	CStr(pxuser,128);
	CStr(pxpass,128);
	CStr(pxuserpass,256);
	CStr(pxacct,128);
	CStr(pxhost,128);
	CStr(xhost,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	const char *xp;
	int port;
	AuthInfo ident;
	int cerror,error,nerror;
	int noanon = 0;

	fc = tc = xtc = 0;
	if( FCF.fc_ccx & CCX_COMMAND ){
		if( !CCXactive(CCX_TOSV) ){
			scan_CCXTOSV(Conn);
		}
	}
	PFS = FS;
	init_FS(FS,Conn);

	if( isWindowsCE() )
	if( CCXactive(CCX_TOCL) ){
		CCXcreate("*","utf-8",FSCCX_TOME);
		FCF.fc_ccx |= CCX_COMMAND;
	}
	tc = fdopen(fddup(ToC),"w");

	if( CTX_auth(Conn,NULL,NULL) == 0 ) /* no AUTHORIZER, host based auth. only  */
	if( !source_permitted(Conn) ){
		getClientUserMbox(Conn,AVStr(usermbox));
		sv1log("FTP LOGIN FROM %s REJECTED\n",usermbox);
		service_permitted(Conn,"ftp"); /* delay */
		fprintf(tc,"421 forbidden\r\n");
		fflush(tc);
		return;
	}
	strcpy(arg,"/");
	rewrite_CWD(FS,VStrNULL,AVStr(arg),NULL);
	if( MountOptions && isinList(MountOptions,"noanon") ){
		noanon = 1;
	}
	if( changesv(Conn,FS,"init",AVStr(cserv)) ){
		fc = fdopen(fddup(FromC),"r");
		cuser[0] = 0;
		change_server(Conn,FS,fc,tc,"","",cuser,"","");
		fclose(tc);
		fclose(fc);
		return;
	}
/*
this is introduced at 3.0.42.
- should be repealed for server switching by non-CWD command (one-time switch)
- should be repealed, it might do login in vain to server MOUNTed on root ("/")
- might be necessary to avoid repetitive one-time switchs for command on "/"
- might be necessary to avoid useless invalid USER+PASS in vain
	if( strncmp(arg,"//",2) == 0 ){
		change_server(Conn,FS,fc,tc,"OPEN",arg+2,"","","");
		return;
	}
- automatic login to the server MOUNTed at / may not be good if there
  are multiple MOUNT points for multiple destination servers
*/
	strcpy(FS->fs_logindir,FS->fs_CWD);
	fc = fdopen(fddup(FromC),"r");
	ftp_banner(Conn,tc);
	fflush(tc);

	usermbox[0] = 0;
	getClientUserMbox(Conn,AVStr(usermbox));

	cuser[0] = cpass[0] = 0;
	cserv[0] = 0;
	FS->fs_TYPE[0] = 0;
	FS->fs_serverWithPASV = 1;
	islocal = FS->fs_islocal;

	FS->fs_myport = ClientIF_name(Conn,FromC,AVStr(FS->fs_myhost));
	ClientIF_addr(Conn,FromC,AVStr(FS->fs_myaddr));

	xtc = TMPFILE("proxy-auth");
	if( doAUTH(Conn,NULL,xtc,"ftp","-",0,CVStr("user-xxxx:pass-xxxx"),CVStr("host-xxxx"),NULL,NULL) == EOF ){
		pxuser[0] = pxpass[0] = pxacct[0] = pxhost[0] = 0;
		chost = 0;
		proxyLoggedin = 0;
	}else	proxyLoggedin = -1;

	nerror = cerror = error = 0;
	for(;;){
		FS->fs_islocal = islocal;

		if( ConnError & CO_TIMEOUT )
			break;
		if( ConnError & CO_CLOSED )
			break;

		fflush(tc);
		if( FS->fs_timeout ){
			timeout = (int)(FS->fs_timeout * 1000);
		}else
		if( FS->fs_CWD[0] == 0 )
			timeout = LOGIN_TIMEOUT * 1000;
		else	timeout = FTP_FROMCLNT_TIMEOUT * 1000;
		if( fPollIn(fc,timeout) <= 0 ){
			if( feof(fc) || ferror(tc) ){
				sv1log("disconnected from the client: %d %d\n",
					feof(fc),ferror(tc));
				break;
			}
			fprintf(tc,"421 ---- PROXY-FTP login: TIMEOUT(%d)\r\n",
				LOGIN_TIMEOUT);
			fflush(tc);
			break;
		}
		if( fgetsFromCT(AVStr(req),sizeof(req),fc) == NULL ){
			sv1log("proxyFTP got EOF from the client.\n");
			break;
			/* Exit(0); Login LOG should be flushed.  QUIT command
			   from the user should be remembered as a normal EOF
			 */
		}
		incRequestSerno(Conn);
		CCXreq(Conn,FS,req,AVStr(req),sizeof(req));

		if( strncasecmp(req,"PASS",4) == 0 && anonymous == 0 )
			command_log("CLIENT-SAYS: PASS ********\n");
		else    command_log("CLIENT-SAYS: %s",req);

		dp = wordScan(req,com);
		if( *dp == ' ' ){
			textScan(dp+1,arg);
		}else
		lineScan(dp,arg);
		strcpy(FS->fs_curcom,com);
		strcpy(FS->fs_curarg,arg);
		if( streq(com,"USER") )
			strcpy(FS->fs_OUSER,arg);

		Conn->no_dstcheck = 1; /* DST_HOST is not set yet */
		if( !method_permitted(Conn,"ftp",com,1) ){
			fprintf(tc,"500 forbidden command: %s\r\n",com);
			fflush(tc);
			continue;
		}
		Conn->no_dstcheck = 0;

		if( proxyLoggedin == 0 )
		if( strcaseeq(com,"USER") || strcaseeq(com,"PASS") ){
			if( strcaseeq(com,"USER") ){
				lineScan(arg,pxuser);
				if( dp = strstr(pxuser,"//") ){
					truncVStr(dp);
					strcpy(FS->fs_USER,dp+2);
					if( dp = strchr(FS->fs_USER,'@') ){
						truncVStr(dp);
						wordScan(dp+1,xhost);
					}else{
						wordScan(FS->fs_USER,xhost);
						strcpy(FS->fs_USER,"ftp");
					}
					chost = xhost;
					wordScan(FS->fs_USER,cuser);
				}
			}else
			if( strcaseeq(com,"PASS") )
				lineScan(arg,pxpass);
			else	lineScan(arg,pxacct);

			sprintf(pxuserpass,"%s:%s",pxuser,pxpass);
			if( px_doAUTH(FS,Conn,xtc,AVStr(pxuser),AVStr(pxpass),
			   AVStr(pxhost),AVStr(cuser),AVStr(cpass),AVStr(cserv)) == EOF ){
				if( strcaseeq(com,"USER") ){
 fprintf(tc,"331 [Proxy] Password required for %s.\r\n",pxuser);
				}else{
					sv1log("login ERROR (%s)\n",pxuser);
 fprintf(tc,"530 [Proxy] Login failed.\r\n");
				}
			}else{
			if( cuser[0] && cserv[0] ){
				change_server(Conn,FS,fc,tc,com,cserv,
					cuser,cpass,FS->fs_TYPE);
				clearVStr(cuser);
				clearVStr(cpass);
				clearVStr(cserv);
				continue;
			}else
FS->fs_anonymousOK = 1; /* temporary */

				/* tentative ... this should be treated more
				 * generally (based on server, generating
				 * arbitrary user:pass, etc.)
				 */
				if( get_MYAUTH(Conn,AVStr(pxuserpass),"ftp","-",0) ){
					if( streq(pxuserpass,"%U:%P") ){
						lineScan(pxuser,cuser);
						lineScan(pxpass,cpass);
					}
				}

				lineScan(pxuser,FS->fs_proxyauth.i_user);
				lineScan(pxhost,FS->fs_proxyauth.i_Host);
				proxyLoggedin = 1;
				sv1log("proxy-login OK (%s)\n",pxuser);
				if( chost ){
 fprintf(tc,"332 Password requird for target %s@%s.\r\n",cuser,chost);
				}else{
 fprintf(tc,"230-[Proxy] User %s logged in.\r\n",pxuser);
 fprintf(tc,"230 Now you can login a target FTP server with USER user@host\r\n");
/* should do chdir(HOMEofUSER) */
				}
			}
			continue;
		}
		else
		if( comeq(com,"QUIT")
		 || comeq(com,"AUTH")
		 || comeq(com,"HELP")
		){
		}else{
			fprintf(tc,"530 [Proxy] Login required.\r\n");
			continue;
		}
		if( comeq(com,"AUTH") ){
			if( streq(arg,"GSSAPI")
			 || streq(arg,"KERBEROS_V4")
			){
				sv1log("### not supported (%s %s)\n",com,arg);
				fprintf(tc,"500 not supported (yet)\r\n");
				continue;
			}
		}

		if( 0 < proxyLoggedin && chost && strcaseeq(com,"ACCT") ){
			strcpy(cpass,arg);
			change_server(Conn,FS,fc,tc,com,chost,cuser,cpass,
				FS->fs_TYPE);
			continue;
		}

		if( strcaseeq(com,"USER") ){
			int nondefaultMounted();
			replace_atmark("USER",arg);
			if( !nondefaultMounted() ) /* working as a pure proxy */
			if( strchr(arg,'@')==0 )/* USER without @host extension */
			if( FCF.fc_proxy != NULL ){
				if( isinList(FCF.fc_proxy,"user") )
				if( !isinList(FCF.fc_proxy,"path") )
				{
					fprintf(tc,"530 login user@host\r\n");
					continue;
				}
			}

			if( unescape_user_at_host(AVStr(arg)) )
				sprintf(req,"%s %s\r\n",com,arg);
			if( streq(arg,"(none)") || arg[0] == 0 ){
				fprintf(tc,"530 bad user: %s\r\n",arg);
				continue;
			}
		}
		if( isFTPxHTTP(FS->fs_proto) ){
		    if( strcaseeq(com,"USER") || strcaseeq(com,"PASS") ){
			int hcode;
			hcode = ftpxhttpAUTH(FS,com,arg);
			if( hcode == 401 ){
				if( strcaseeq(com,"USER") )
					fprintf(tc,"331 password required\r\n");
				else	fprintf(tc,"530 bad auth.\r\n");
				continue;
			}
		    }
		}

		if( PATHCOMS(com) ){
			int hit;
			AuthInfo sident;
			sident = FS->fs_Ident;
			if( swRemote(FS,com,AVStr(arg),AVStr(cserv),NULL) ){
				/* options like "-l" for LIST must be forwarded too... */
				if( *arg == '-' ){
					wordScan(arg,FS->fs_opts);
				}

				hit = RETRCOMS(com)
				 && lookaside_cache(Conn,FS,tc,com,arg,1);
				FS->fs_Ident = sident;
				if( hit ){
					continue;
				}

				change_server(Conn,FS,fc,tc,com,cserv,
					cuser,cpass,FS->fs_TYPE);
				cserv[0] = 0;
				continue;
			}
			if( FS->fs_authERR ){
				fprintf(tc,"530 not authorized\r\n");
				FS->fs_authERR = 0;
				continue;
			}
		}

		if( FTP_STARTTLS_withCL(Conn,tc,fc,com,arg) ){
			continue;
		}else
		if( AsServer(Conn,FS,tc,fc,com,arg,cuser) ){
			continue;
		}else
		if( Mounted() )
		/* if mounted */{
			if( strcasecmp(com,"USER") == 0 && strchr(arg,'@') ){
			  /* escape "/" in user-name to "%2F" while leaving
			   * original "%2F" and other "%XX" as is.
			   */
			  url_escapeX(arg,AVStr(arg),sizeof(arg),"%%/?",":@");

			    port = decomp_ftpsite(FS,AVStr(arg),&ident);
			    wordScan(ident.i_user,cuser);
			    textScan(ident.i_pass,cpass);
			    wordScan(ident.i_Host,host);
			    if( *host && *cuser ){
				if( !user_permitted(Conn,FS,tc,host,port,cuser) )
					continue;
				anonymous = is_anonymous(cuser);
				strcpy(com,"CWD");
				Strins(AVStr(arg),"//");
				sprintf(req,"%s %s\r\n",com,arg);
				sv1log("rewritten to: %s",req);
			    }
			}
			if( strcaseeq(com,"CDUP") ){
				strcpy(com,"CWD");
				strcpy(arg,"..");
				sprintf(req,"%s %s\r\n",com,arg);
			}
			if( strcasecmp(com,"CWD") == 0 )
				if( rewrite_CWD(FS,AVStr(req),AVStr(arg),tc) ){
					islocal = FS->fs_islocal;
					continue;
				}
				islocal = FS->fs_islocal;
				/* is this really here ? or for "CWD" only? */
		}
		if( strcasecmp(com,"USER") == 0 ){
			url_escapeX(arg,AVStr(arg),sizeof(arg),"/?",":@");
			xp = scan_userpassX(arg,&ident);
			wordScan(ident.i_user,cuser);
			textScan(ident.i_pass,cpass);
			nonxalpha_unescape(cuser,AVStr(cuser),1);
			if( changesv(Conn,FS,"user",AVStr(cserv)) ){
				change_server(Conn,FS,fc,tc,com,cserv,cuser,cpass,FS->fs_TYPE);
				continue;
			}
			if( *xp == '@' ){
				xp++;
				change_server(Conn,FS,fc,tc,com,xp,cuser,cpass,FS->fs_TYPE);
				continue;
			}
			strcpy(FS->fs_USER,cuser);
			anonymous = is_anonymous(cuser);
			if( anonymous && noanon ){
 fprintf(tc,"530 No anonymous\r\n");
			}else
			if( anonymous ){
			    if( usermbox[0] ){
 fprintf(tc,"331- Guest login ok, enter your E-mail address as password.\r\n");
 fprintf(tc,"331  Default value is: %s\r\n",usermbox);
			    }else{
 fprintf(tc,"331 Guest login ok, enter your E-mail address as password.\r\n");
			    }
			}else{
 fprintf(tc,"331 Password required for %s.\r\n",cuser);
			}
		}else
		if( strcasecmp(com,"PASS") == 0 ){
			textScan(arg,cpass);
			/*
			lineScan(arg,cpass);
			*/
			if( anonymous ){
				replace_atmark("ANON-PASS",cpass);
				FS->fs_anonymous = 1;
				FS->fs_anonymousOK = 0;
				if( *cpass == 0 && usermbox[0] != 0 )
					strcpy(cpass,usermbox);
				if( anonPASS(Conn,tc,cuser,AVStr(cpass)) != 0 ){
					cpass[0] = 0;
					continue;
				}
				FS->fs_anonymousOK = 1;
				strcpy(FS->fs_PASS,cpass);
			}else{
				FS->fs_anonymous = 0;
				FS->fs_anonymousOK = 0;
				if( 1 ){
				/* with AUTHORIZER in MOUNT or with ConnMap */
					strcpy(FS->fs_PASS,cpass);
				}
			}
			if( FS->fs_login1st ){
				url_login(Conn,FS,fc,tc,cuser,cpass);
				continue;
			}

			if( changesv(Conn,FS,"pass",AVStr(cserv)) ){
				/* cserv is set */
			}
			/*
			if( cserv[0] ){
			*/
			if( cserv[0] || strcaseeq(FS->fs_proto,"sftp") ){
				if( cserv[0] == 0 ){
					sprintf(cserv,"%s:%d",FS->fs_host,FS->fs_port);
					if( FS->fs_loginroot[0] ){
						Xsprintf(TVStr(cserv),"/%s",
							FS->fs_loginroot);
					}
					sv1log("SFTPGW: SW sftp://%s\n",cserv);
				}
				change_server(Conn,FS,fc,tc,com,cserv,cuser,cpass,FS->fs_TYPE);
				if( strcaseeq(FS->fs_proto,"sftp") )
				/* 9.6.2 to disconnect the STLS=fcl thread */ {
					sv1log("#### %s://%s PASS RETURN\n",
						FS->fs_proto,cserv);
					fclose(fc);
					fclose(tc);
				}
				cserv[0] = 0;
				return;
			}else{
 if( anonymous )
 fprintf(tc,"230- Guest login ok, your E-mail address is <%s>\r\n",cpass);
 else
 fprintf(tc,"230- User %s logged in.\r\n",cuser);
 fprintf(tc,"230  Now you can select a FTP SERVER by cd //SERVER\r\n");
			}
		}else
		if( strcaseeq(com,"CWD") && strncmp(arg,"//",2) == 0 ){
			if( proxyLoggedin == 0 ){
 fprintf(tc,"530 [Proxy] Login required.\r\n");
				continue;
			}

			xp = scan_userpassX(arg+2,&ident);
			if( *xp == '@' ){
				if( streq(ident.i_user,cuser)
				 && ident.i_pass[0] == 0 ){
					/* reuse the previous password, used for onetime
					 * LIST or so, for CWD for the same user
					 */
				}else{
				wordScan(ident.i_user,cuser);
				textScan(ident.i_pass,cpass);
				}
			}
			if( cpass[0] == 0 ){
				strcpy(cserv,arg+2);
 fprintf(tc,"331 Password required for %s.\r\n",cuser);
				continue;
			}
			change_server(Conn,FS,fc,tc,com,req+6,cuser,cpass,FS->fs_TYPE);
		}else
		if( strcaseeq(com,"CWD") && controlCWD(FS,tc,arg) ){
			continue;
		}else
		if( strcasecmp(com,"SITE")==0 || strcasecmp(com,"OPEN")==0 ){
			if( FCF.fc_proxy == 0
			 || !isinListX(FCF.fc_proxy,com,"c")
			){
 fprintf(tc,"500 '%s': command not understood.\r\n",com);
				continue;
			}
			change_server(Conn,FS,fc,tc,com,req+5,cuser,cpass,FS->fs_TYPE);
		}else
		if( strcasecmp(com,"MACB") == 0 ){
 fprintf(tc,"500 MACB? nani sore ?_?\r\n");
		}else
		if( strcasecmp(com,"QUIT") == 0 ){
 fprintf(tc,"221 Goodbye.\r\n");
			break;
		}else
		if( strcasecmp(com,"CDUP")==0 ){
 fprintf(tc,"250 CWD command successful.\r\n");
		}else
		if( strcasecmp(com,"CWD")==0 ){
			if( rewrite_CWD(FS,AVStr(req),AVStr(arg),tc) ){
			}else
			{
/* 9.2.2 the specified directory is not MOUNTed, so 550 shuold be
 returned.  Old versions returned 250 (success) to cope with CWD
 to non-MOUNTed intermediate path of a MOUNTed path, for example
 CWD "/x" + CWD "y" for MOUNT="/x/y/* ftp://server/*"
 From now on, such intermediate path is MOUNTed as "/-stab-/x".
 fprintf(tc,"250 CWD command successful.\r\n");
 */
 fprintf(tc,"550 No such directory.\r\n");
			}
			islocal = FS->fs_islocal;
		}else
		if( strcasecmp(com,"PWD") == 0 ){
			if( !rewrite_PWD(FS,req,arg,tc) ){
				const char *cwd;
				if( FS->fs_CWD[0] )
					cwd = FS->fs_CWD;
				else	cwd = "/";
 fprintf(tc,"257 \"%s\" is current directory.\r\n",cwd);
			}
		}else
		if( strcasecmp(com,"HELP") == 0 ){
 fprintf(tc,"214-\r\n"); /* WS_FTP(6.7) freezes if HELP returns error */
 fprintf(tc,"214 \r\n");
		}else
		if( comeq(com,"FEAT") && (ClientFlags & PF_STLS_DO) ){
			/*
			FTP_putSTLS_FEAT(Conn,tc,1);
			*/
			if( FTP_putSTLS_FEAT(Conn,tc,1) == 0 ){
				/* 9.6.2 can be in SSL already */
				putFEAT(Conn,FS,tc,0);
			}
			/* should be announce another features ? */
		}else{
 fprintf(tc,"500-%s",req);
 fprintf(tc,"500 only USER,PASS,TYPE,QUIT and CWD are available.\r\n");
			sv1log("Unknown request: %s",req);
			error = 1;
		}

		if( error ){
			nerror++;
			cerror++;
		}else{
			cerror = 0;
		}
		error = 0;
		if( 1 < cerror ){
			int delay;
			if( cerror < 10 )
				delay = cerror;
			else	delay = 10;
			sv1log("## delaying %ds on continuous error * %d/%d\n",
				delay,cerror,nerror);
			sleep(delay);
		}

	}
	fflush(tc);
	if( xtc ){
		fclose(xtc);
	}
	if( GatewayFlags & GW_SERV_THREAD ){ /* FTP server as a thread */
		fclose(tc);
		fclose(fc);
	}else
	if( lSINGLEP() ){
		fclose(tc);
		fclose(fc);
	}else
	if( (ClientFlags & PF_SSL_ON) ){
		/* 9.7.0 should close these to shutdown SSL normally from this
		 * side (server side), and should close even without SSL but
		 * it was like this from the origin ... (DeleGate/2.0.6)
		 */
		fclose(tc);
		fclose(fc);
	}
}

static int get_resp(FILE *fs,FILE *tc,PVStr(resps),int rsize)
{	refQStr(rp,resps); /**/
	CStr(resp,1024);
	CStr(rcode,4);
	int lines;
	int remlen;
	int leng;
	int tleng = 0;
	refQStr(tp,resps);

	if( fs == NULL )
		return 0;

	if( resps ){
		remlen = rsize - 1;
		cpyQStr(rp,resps);
		cpyQStr(tp,resps);
		setVStrEnd(resps,0);
	}

	rcode[0] = 0;
	for(lines = 0;;lines++){
		if( fgetsFromST(AVStr(resp),sizeof(resp),fs) == 0 ){
		/*
		sv1log("FTP: connection timedout or closed by the server\n");
		*/
			sprintf(resp,"421 %s\r\n",
			     feof(fs) ? "connection closed by server":
					"server response timedout"
			);
			sv1log("FTP-SERVER: %s",resp);
			if( tc != NULL ){
				fputs(resp,tc);
				fflush(tc);
			}
			return EOF;
		}
		if( tc != NULL ){
			fputs(resp,tc);
			fflush(tc);
		}

		if( lines == 0 )
			command_log("FTP-SERVER-SAYS: %s",resp);

		leng = strlen(resp);
		tleng += leng;
		if( resps && leng < remlen ){
			tp = rp;
			/*
			Xstrcpy(HVStr(rsize,resps) rp,resp);
			*/
			strcpy(rp,resp);
			rp += leng;
			remlen -= leng;
		}

		if( resp[3] == '-' ){
			if( rcode[0] == 0 )
				strncpy(rcode,resp,3);
		}else{
			if( rcode[0] == 0 || strncmp(resp,rcode,3) == 0 )
				break;
		}
	}

	if( !isdigit(resp[0]) )
		return EOF;
	if( resp[0] == '4' )
		return EOF;
	if( resp[0] == '5' )
		return EOF;

	if( isdigit(tp[0])&&isdigit(tp[1])&&isdigit(tp[2]) && tp[3] == '-' ){
		sv1log("## trunc resp. %d/%d/%d\n",istrlen(resps),rsize,tleng);
		setVStrElem(tp,3,' ');
	}
	return 0;
}

#define PS_ANON	1
#define PS_BUFF	2

static int put_serv(int mode,FILE *ts,PCStr(fmt),...)
{	CStr(req,1024);
	int rcode;
	VARGS(8,fmt);

	rcode = fprintf(ts,fmt,VA8);
	if( rcode == EOF )
		return EOF;

	if( (mode & PS_BUFF) == 0 )
		if( fflush(ts) == EOF ){
			sv1log("put_serv: EOF\n");
			return EOF;
		}

	sprintf(req,fmt,VA8);
	if( strncasecmp(req,"PASS",4) == 0 && (mode & PS_ANON) == 0 )
		command_log("I-SAY: PASS ********\n");
	else	command_log("I-SAY: %s",req);
	return rcode;
}
static int _put_get(int mode,FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(fmt),...)
{
	if( fmt ){
		VARGS(8,fmt);
		if( put_serv(mode,ts,fmt,VA8) == EOF )
			return EOF;
	}

	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF )
		return EOF;

	return 0;
}
static int put_get(FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(fmt),...)
{
	VARGS(8,fmt);
	return _put_get(0,ts,fs,AVStr(resp),rsize,fmt,VA8);
}
static int PutGet(FILE *ts,FILE *fs,FILE *stfp,PCStr(req),PVStr(resp),int rsize){
	int rcode = EOF;
	if( put_serv(0,ts,"%s\r\n",req) == EOF ){
		return EOF;
	}
	if( get_resp(fs,stfp,AVStr(resp),rsize) == EOF ){
		return EOF;
	}
	fflush(stfp);
	fseek(stfp,0,0);
	rcode = atoi(resp);
	return rcode;
}

const char *searchPortSpec(PCStr(resp))
{	const char *rp;
	int p;

	if( strncmp(resp,"229",3) == 0 ){
		if( (rp = strstr(resp,"(|")) != 0 )
			return rp+1;
	}
	for( rp = resp; *rp; rp++ ){
		if( isdigit(*rp) )
			if( sscanf(rp,"%*d,%*d,%*d,%*d,%*d,%d",&p) == 1 )
				return rp;
	}
	return NULL;
}

static int insdataFSV(Connection *ctrlConn,PCStr(where),FtpStat *FS,int svdata,int cldata)
{	int fsvdata;
	Connection *Conn = &FS->fs_dataConn;

	if( Conn->xf_filters & XF_FSV )
		return 0;

	if( 0 <= FTP_dataSTLS_FSV(ctrlConn,Conn,svdata) )
		return 1;

	if( REAL_HOST[0] == 0 )
		strcpy(Conn->sv.p_host,"-"); /* for DST_PROTO */
/*
	else	strcpy(Conn->sv.p_host,REAL_HOST);
copying to itself
*/

	/*
	 * the thread for FSV=sslway will not become ready at this point
	 * (where==PASV) until the peer SSLway (SSL at the server-side)
	 * will be started later by RETR or LIST command
	 */
	if( streq(where,"PASV") ){
		int gwf = GatewayFlags;
		GatewayFlags |= GW_SYN_SSLSTART;
		fsvdata = insertFSV(Conn,-1,svdata);
		GatewayFlags = gwf;
	}else
	fsvdata = insertFSV(Conn,-1,svdata);
	if( 0 <= fsvdata ){
		sv1log("inserted FSV[%s] %d -> %d\n",where,svdata,fsvdata);
		dup2(fsvdata,svdata);
		close(fsvdata);
		return 1;
	}
	return 0;
}
static int connectPASV(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,PVStr(resp),int rsize)
{	const char *rp;
	int psock;
	int timeout,stimeout;

	if( FCF.fc_doepsvSV ){
		/* 9.9.8 force EPSV to server */
		put_serv(0,ts,"EPSV\r\n");
	}else
	if( sock_isv6(ServSock(Conn,ts,"mkPASV")) ){
		put_serv(0,ts,"EPSV\r\n");
	}else
	put_serv(0,ts,"PASV\r\n");
	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF || resp[0] != '2' ){
		sv1log("PASV ... %s",resp);
		return -1;
	}

	rp = searchPortSpec(resp);
	if( rp ){
		stimeout = CON_TIMEOUT;
		timeout = CON_TIMEOUT_DATA;
		psock = makeDataConn(Conn,rp,ServSock(Conn,ts,"mkPASV"),1);
		if( 0 <= psock && FS != NULL )
			insdataFSV(Conn,"PASV",FS,psock,-1);
		CON_TIMEOUT = stimeout;
	}else{
		sv1log("UNKNOWN PASV RESPONSE: %s",resp);
		AbortLog();
		psock = -1;
	}
	return psock;
}
static int make_ftp_data(Connection *Conn,PVStr(mport),PCStr(shost),int sport,int csock,int direct,int pasv)
{	CStr(lhost,256);
	int dsock,lport;
	const char *proto;
	int SF[4] = {0};

	if( ServerFlags & (PF_SSL_ON|PF_STLS_ON) ){
		/* 9.9.7 BIND+ACCEPT ftp-data via SOCKS/ssl */
		/* this should be done with dataConn with clear ServerFlags */
		saveSTLS("make-ftp-data",Conn,SF);
		clearSTLS(Conn);
	}
	lhost[0] = 0;
	lport = 0;
	proto = pasv?"ftp-data-pasv":"ftp-data-port";
	if( SRCIFfor(Conn,proto,shost,sport,AVStr(lhost),&lport) ){
	}else
	SRCIFfor(Conn,"ftp-data",shost,sport,AVStr(lhost),&lport);
	dsock = bind_ftp_data(Conn,AVStr(mport),shost,sport,csock,pasv,lhost,lport);
	restoreSTLS("make-ftp-data",Conn,SF);
	return dsock;
}

static int mkdsockPORT(Connection *Conn,PCStr(host),FILE *ts,FILE *fs)
{	int dsock;
	CStr(mport,256);
	CStr(resp,1024);

	if( FCF.fc_noportSV ){
		sv1log("#{ver9.9.4} PORT to server disabled (%s)\n",host);
		return -1;
	}

	dsock = make_ftp_data(Conn,AVStr(mport),host,serviceport("ftp"),ServSock(Conn,ts,"mkPORT"),0,0);
	if( dsock < 0 )
		return dsock;

	if( FCF.fc_doeprtSV && mport[0] != '|' ){
		/* 9.9.8 force EPRT to server */
		VSAddr addr;
		VSA_ftptosa(&addr,mport);
		sprintf(mport,"|||%d|",VSA_port(&addr));
		sv1log("EPRT %s\n",mport);
	}
	if( mport[0] == '|' ){
		put_serv(0,ts,"EPRT %s\r\n",mport);
	}else
	put_serv(0,ts,"PORT %s\r\n",mport);
	if( fs != NULL )
	{
		get_resp(fs,NULL,AVStr(resp),sizeof(resp));
		if( 400 <= atoi(resp) ){
			/* error to be cared ... */
			sv1log("##ERROR mkdsockPORT[%s]: %s",host,resp);
		}
	}
	return dsock;
}
FileSize Xatoi(PCStr(snum)){
	FileSize num = 0;
	const char *sp;
	char sc;
	int neg = 0;

	for( sp = snum; sc = *sp; sp++ ){
		if( sc != ' ' ){
			break;
		}
	}
	if( *sp == '-' ){
		neg = 1;
		sp++;
	}
	for( ; sc = *sp; sp++ ){
		if( isdigit(sc) ){
			num = num*10 + (sc-'0');
		}else
		if( sc == ',' ){
		}else{
			break;
		}
	}
	if( neg ){
		if( 0 < num && num <= 0x7FFFFFFF ){
			/* might be broken expression for 2GB <= num < 4GB */
			num = (unsigned int)-num;
		}else{
			num = -num;
		}
	}
	return num;
}
typedef struct {
	Connection *fg_Conn;
	FILE   *fg_statfp; /* to receive a list in response status */
	MStr(	fg_cmd,128);
	MStr(	fg_opt,128);
} FtpGw;
static int listretr(FtpGw *Fg,FILE *ts,FILE *fs,PCStr(path),int *isdirp,PVStr(resp),int rsize)
{	const char *dp;
	CStr(xpath,1024);
	CStr(apath,1024);
	CStr(comm,1024);
	int isdir;
	int didcwd = 0;
	Connection *Conn = Fg->fg_Conn;

	isdir = 0;
	if( *path == 0 )
		isdir = 1;
	else
	if( (dp = strrchr(path,'/')) && dp != path && dp[1] == 0 ){
		path = strcpy(xpath,path);
		*(char*)strrchr(path,'/') = 0;
		isdir = 1;
	}
	if( isinFTPxHTTP(Conn) ){
		if( RequestFlags & QF_FTP_COMLIST ){
			isdir = 1;
		}
		if( RequestFlags & QF_FTP_COMRETR ){
			/* should not try CWD */
			isdir = 0;
		}
	}

	if( !isdir && put_get(ts,fs,AVStr(resp),rsize,"CWD %s\r\n",path) == EOF ){
		strcpy(xpath,path);
		if( dp = strrchr(xpath,'/') ){
			truncVStr(dp);
			if( put_get(ts,fs,AVStr(resp),rsize,"CWD %s\r\n",xpath) != EOF )
				path = dp + 1;
		}
		if( atoi(resp) == 550 && strstr(resp,"No such file or dir") ){
			return -1;
		}
		sprintf(comm,"RETR %s",path);
		isdir = 0;
	}else{
		if( isdir && path[0] )
		if( put_get(ts,fs,AVStr(resp),rsize,"CWD %s\r\n",path) == EOF )
			return -1;

		sprintf(comm,"%s %s",FTP_LIST_COM,FTP_LIST_OPT);
		isdir = 1;
		didcwd = 1;
	}
	if( Fg->fg_cmd[0] ){
		sprintf(comm,"%s",Fg->fg_cmd);
		if( Fg->fg_opt[0] ){
			Xsprintf(TVStr(comm)," %s",Fg->fg_opt);
		}
		if( didcwd ){ /* already succeeded "CWD path" */
			if( ARG0COMS(Fg->fg_cmd) ){
			}else{
				sprintf(resp,"550 not a plain file\r\n");
				return -1;
			}
		}else{
			if( *path ){
				Xsprintf(TVStr(comm)," %s",path);
			}
		}
	}

	if( !isdir ){
		CStr(size,1024);
		sprintf(size,"SIZE %s",path);
		if( put_get(ts,fs,AVStr(resp),rsize,"%s\r\n",size) != EOF ){
			/*
			Xsscanf(resp,"213 %lld",&Conn->sv.p_range[2]);
			*/
			if( strneq(resp,"213 ",4) ){
				Conn->sv.p_range[2] = Xatoi(resp+4);
				if( isinFTPxHTTP(Conn) ){
				/*
				 * SIZE -> Content-Length
				 * MDTM -> Last-Modified
				 */
				}
			}
		}
	}
	if( 0 < reqPART_FROM ){
		CStr(rest,128);
		sprintf(rest,"REST %lld",reqPART_FROM);
		if( put_get(ts,fs,AVStr(resp),rsize,"%s\r\n",rest) != EOF ){
			gotPART_FROM = reqPART_FROM;
		}else{
			gotPART_FROM = -1;
		}
	}

	if( Fg->fg_statfp ){
		int rcode;
		rcode = PutGet(ts,fs,Fg->fg_statfp,comm,AVStr(resp),rsize);
		if( rcode == EOF ){
			return -1;
		}
	}else
	if( put_get(ts,fs,AVStr(resp),rsize,"%s\r\n",comm) == EOF )
		return -1;

	if( isdirp )
		*isdirp = isdir;
	return 0;
}
static int stor(FtpGw *Fg,FILE *ts,FILE *fs,PCStr(path),PVStr(resp),int rsize)
{	const char *dp;
	CStr(dir,102);

	if( strrchr(path,'/') ){
		strcpy(dir,path);
		path = strrchr(dir,'/');
		*(char*)path++ = 0; /* not "const" but fixed */
		if( put_get(ts,fs,AVStr(resp),rsize,"CWD %s\r\n",dir) == EOF )
			return -1;
	}
	if( Fg->fg_cmd[0] ){
		if( put_get(ts,fs,AVStr(resp),rsize,"%s %s\r\n",Fg->fg_cmd,path) == EOF ){
			return -1;
		}
		return 0;
	}
	if( put_get(ts,fs,AVStr(resp),rsize,"STOR %s\r\n",path) == EOF )
		return -1;
	return 0;
}

int ACCEPTdc(int dsvsock,int asServer)
{	CStr(host,128);
	int port,dsock;

	if( 1 < peerPort(dsvsock) ){
		if( ViaVSAPassociator(dsvsock) ){
			CStr(sockname,256);
			CStr(peername,256);
			dsock = VSAPaccept(MainConn(),FTP_ACCEPT_TIMEOUT,dsvsock,0,AVStr(sockname),AVStr(peername));
			if( 0 <= dsock )
				dsock = fddup(dsvsock);
		}else
		if( acceptViaSocks(dsvsock,AVStr(host),&port) == 0 )
			dsock = fddup(dsvsock);
		else	dsock = -1;
	}else{
		dsock = ACCEPT(dsvsock,asServer,-1,FTP_ACCEPT_TIMEOUT);
		if( dsock < 0 )
			sv1log("FTP ACCEPT_TIMEOUT %d\n",FTP_ACCEPT_TIMEOUT);
	}
	return dsock;
}
static int ACCEPT_SVPORT(int dsvsock,int asServer)
{	int dsock;
	CStr(shost,128);
	int sport;

	Verbose("Start accept on port for PORT from server[%d]\n",dsvsock);
	dsock = ACCEPTdc(dsvsock,asServer);
	if( 0 < dsock ){
		sport = getpeerNAME(dsock,AVStr(shost));
		Verbose("Accepted the data port: %s:%d\n",shost,sport);
	}
	return dsock;
}

typedef struct {
	Connection *a_Conn;
	FtpStat    *a_FS;
	FILE       *a_dfs;  /* data file source */
	FILE	   *a_fc;   /* from client */
	FILE	   *a_fs;   /* from server */
	FILE	   *a_tc;   /* to client */
} RelayArg;
static const char *relay1(int ser,PCStr(buff),int leng,FILE *tcfp,PCStr(a));
static int data_open(FtpGw *Fg,int put,int PASV,int dsock,PCStr(host),FILE *ts,FILE *fs,PCStr(path),int *isdirp,PVStr(resp),int rsize)
{	int psock = -1;
	CStr(xpath,1024);
	RelayArg Ra;
	Connection *Conn = Fg->fg_Conn;

	/* data-connection should be suppressed for STAT and MLST ... */
	if( Fg->fg_cmd[0] != 0 )
	if( Fg->fg_statfp != NULL )
	if( STATCOMS(Fg->fg_cmd) ){
		FILE *statfp = Fg->fg_statfp;
		if( strncaseeq(Fg->fg_opt,"RNFR/",5) ){
			put_serv(0,ts,"RNFR %s\r\n",Fg->fg_opt+5);
			if( get_resp(fs,statfp,AVStr(resp),rsize) != EOF ){
			}
		}
		if( path[0] == 0 && strcaseeq(Fg->fg_cmd,"CWD") ){
			/* maybe "CWD /" at the FTPxHTTP client */
			strcpy(resp,"250 empty CWD.\r\n");
			fprintf(statfp,"%s",resp);
		}else
		if( path[0] == 0 && !strcaseeq(Fg->fg_cmd,"STAT") ){
			fprintf(statfp,"501 empty arg.\r\n");
			strcpy(resp,"501 empty arg.\r\n");
		}else{
			put_serv(0,ts,"%s %s\r\n",Fg->fg_cmd,path); /* with opt ? */
			if( get_resp(fs,statfp,AVStr(resp),rsize) != EOF ){
			}
		}
		fflush(statfp);
		fseek(statfp,0,0);
		return -1;
	}

	if( PASV )
		psock = connectPASV(Conn,NULL,ts,fs,AVStr(resp),rsize);

	if( psock < 0 && toTunnel(Conn) ){
		int mode,fd;
		FILE *tc;
		put_serv(0,ts,"PORT 0,0,0,0,0,0\r\n");
		if( get_resp(fs,NULL,AVStr(resp),rsize) != EOF )
		if( listretr(Fg,ts,fs,path,isdirp,AVStr(resp),rsize) == 0 )
		if( get_resp(fs,NULL,AVStr(resp),rsize) != EOF ){
			tc = TMPFILE("XDC");
			/*
			getMessageFX(fs,NULL,FTP_FROMSERV_TIMEOUT,relay1,tc,"","");
			*/
			Ra.a_Conn = Conn;
			Ra.a_FS = 0;
			Ra.a_dfs = fs;
			Ra.a_fc = 0;
			Ra.a_fs = fs;
			Ra.a_tc = 0;
			getMessageFX(fs,NULL,FTP_FROMSERV_TIMEOUT,relay1,tc,(char*)&Ra,"");
			get_resp(fs,NULL,AVStr(resp),rsize);
			fd = fddup(fileno(tc));
			fclose(tc);
			Lseek(fd,0,0);
			return fd;
		}
	}

	if( psock < 0 && dsock < 0 )
		dsock = mkdsockPORT(Conn,host,ts,fs);

	if( path != 0 ){
	    if( put ){
		if( stor(Fg,ts,fs,path,AVStr(resp),rsize) < 0 ){
			if( 0 <= psock ){
				close(psock);
				psock = -1;
			}
			goto EXIT;
		}
	    }else{
		if( listretr(Fg,ts,fs,path,isdirp,AVStr(resp),rsize) < 0 ){
			if( 0 <= psock ){
				close(psock);
				psock = -1;
			}
			goto EXIT;
		}
	    }
	}

	if( psock < 0 ){
		psock = ACCEPTdc(dsock,0);
		if( psock < 0 ){
			CStr(myhost,MaxHostNameLen);
			gethostname(myhost,sizeof(myhost));
			sprintf(resp,
				"500 Data connection accept timedout (%s).\r\n",
				myhost);
		}
	}
EXIT:
	if( 0 <= dsock ){
		close(dsock);
		dsock = -1;
		/*sv1log("FTP DATA-PORT: %s = sock[%d]\n",mport,psock);*/
	}
	return psock;
}

int ShutdownSocket(int sock);
static int relayABORT(Connection *Conn,FtpStat *FS,int ab);

static const char *relay1(int ser,PCStr(buff),int leng,FILE *tcfp,PCStr(a))
{	int wcc;
	RelayArg *Ra = (RelayArg*)a;
	Connection *Conn;
	int ifd;

/*
 * transmitter: should check ABOR command from client and abort...
 * receiver: should forward ABOR command from client to sever...
 */
	Conn = Ra->a_Conn;
	ifd = Ra->a_dfs ? fileno(Ra->a_dfs) : -1;
	if( ifd == ClientSock || ifd == FromC ){
		/* XDC + STOR ... no ABOR */
	}else
	if( Ra->a_fc == Ra->a_dfs ){
		/* XDC + STOR ... no ABOR */
	}else
	if( inputReady(ClientSock,NULL) ){
		if( Ra->a_FS != NULL ){
			int ra;
			ra = relayABORT(Conn,Ra->a_FS,0);
			if( 0 < ra ){
				fflush(Ra->a_fs);
				sv1log("## ABORT XDC\n");
				return "ABORT";
			}
		}
	}

	Verbose("@%d - %d relay1.\n",ser,leng);
	if( 0 < ser )
	{
		EmiUpdateMD5(Conn,buff,leng);
		wcc = fwriteTIMEOUT(buff,1,leng,tcfp);
	}
	return "";
}

static int gotABOR(void *vRa,PVStr(buff),int leng){
	RelayArg *Ra = (RelayArg*)vRa;
	Connection *Conn;
	int ab;

	Conn = Ra->a_Conn;
	if( inputReady(ClientSock,NULL) ){
		ab = relayABORT(Conn,Ra->a_FS,0);
		sv1log("## XDC gotABOR\n");
		return -1;
	}
	return leng;
}

/* PORT to/from XDC relay */
static FileSize XDCrelayServ(FtpStat *FS,int STOR,FILE *ts,FILE *fs,FILE *tc,FILE *fc,int dsock,PCStr(port), FILE *cachefp,PVStr(resp),int rsize)
{	FILE *dfp;
	FileSize xc;
	const char *encode;
	const char *what;
	int timeout;
	RelayArg Ra;

	if( STOR ){
		what = "STOR";
		encode = FS->fs_XDCencSV;
	}else{
		what = "RECV";
		encode = FS->fs_XDCencCL;
	}
	sv1log("--- XDC%s data_relay SERVER (%s).\n",encode,what);

	if( dsock < 0 ){
		sv1log("FATAL: bad data socket(%d)\n",dsock);
		fprintf(tc,"426 bad data socket\r\n");
		fflush(tc);
		return -1;
	}

	fprintf(tc,XDC_PORT_TEMP,port);
	fprintf(tc,"\r\n");
	fflush(tc);

	Ra.a_Conn = FS->fs_Conn;
	Ra.a_FS = FS;
	Ra.a_fs = fs;

	if( STOR ){
		dfp = fdopen(dsock,"w");
		timeout = FTP_FROMSERV_TIMEOUT;
		/*
		xc = getMessageFX(fc,cachefp,timeout,relay1,dfp,"",encode);
		*/
		Ra.a_dfs = fc;
		Ra.a_fc = fc;
		Ra.a_tc = tc;
		xc = getMessageFX(fc,cachefp,timeout,relay1,dfp,(char*)&Ra,encode);
		fclose(dfp);
		if( fs != NULL ) /* not to local file */
		get_resp(fs,NULL,AVStr(resp),rsize);
	}else{
		dfp = fdopen(dsock,"r");
		/*
		xc = putMessageFX(dfp,tc,cachefp,encode);
		*/
		xc = putMessageFX_CB(dfp,tc,cachefp,encode,gotABOR,&Ra);
		fclose(dfp);
		if( fs == NULL ) /* from local file or cache */
		sprintf(resp,"226 Transfer complete (%lld bytes).\r\n",xc);
		else
		get_resp(fs,NULL,AVStr(resp),rsize);
		putPostStatus(tc,resp);
	}
	if( fs != NULL ){
	fputs(resp,tc);
	fflush(tc);
	}
	return xc;
}
static FileSize XDCrelayClnt(Connection *Conn,FtpStat *FS,int STOR,FILE *ts,FILE *fs,FILE *tc,FILE *fc, FILE *cachefp,PVStr(resp),int rsize)
{	CStr(port,128);
	int dsock;
	FILE *dfp;
	FileSize xc;
	const char *encode;
	const char *what;
	int timeout;
	RelayArg Ra;

	if( STOR ){
		what = "STOR";
		encode = FS->fs_XDCencSV;
	}else{
		what = "RECV";
		encode = FS->fs_XDCencCL;
	}
	sv1log("---- XDC%s data_relay CLIENT (%s).\n",encode,what);
	get_resp(fs,NULL,AVStr(resp),rsize);

	if( sscanf(resp,XDC_PORT_TEMP,port) <= 0 ){
		fputs(resp,tc);
		fflush(tc);
		return 0;
	}

	Verbose("XDC %s",resp);
	if( strcmp(port,XDC_PASV_PORT) == 0 ){
		if( 0 < FS->fs_pclsock )
			dsock = ACCEPTdc(FS->fs_pclsock,1);
		else{
			dsock = -1;
		}
	}else
	dsock = makeDataConn(Conn,port,ClientSock,0);

/*
 * should peek fc to sense ABOR command from the client...
 */
/*
	if( 0 < PollIn(fc,1) ){
		CStr(req,128);
		fgetsTimeout(req,sizeof(req),fc);
		if( strncasecmp(req,"ABOR",4) == 0 ){
			fprintf(tc,"225 ABOR command successful.\r\n");
			return 0;
		}
	}
*/

	if( dsock < 0 ){
		sv1log("cannot (data) connect to client\n");
		fprintf(tc,"426 cannot connect with you: %s",resp);
		fflush(tc);
		return 0;
	}

	if( STOR ){
		dfp = fdopen(dsock,"r");
		xc = putMessageFX(dfp,ts,cachefp,encode);
		fclose(dfp);
		putPostStatus(ts,"done\r\n");
		fflush(ts);
	}else{
		dfp = fdopen(dsock,"w");
		timeout = FTP_FROMSERV_TIMEOUT;
		/*
		xc = getMessageFX(fs,cachefp,timeout,relay1,dfp,"",encode);
		*/
		Ra.a_Conn = Conn;
		Ra.a_FS = FS;
		Ra.a_dfs = fs;
		Ra.a_fc = fc;
		Ra.a_fs = fs;
		Ra.a_tc = tc;
		xc = getMessageFX(fs,cachefp,timeout,relay1,dfp,(char*)&Ra,encode);
		fflush(dfp);
		close(fileno(dfp));
		fclose(dfp);
	}
	get_resp(fs,NULL,AVStr(resp),rsize);
	fputs(resp,tc);
	fflush(tc);
	return xc;
}
static void set_modeXDCtoSV(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs)
{	CStr(resp,256);
	const char *encode;
	const char *opening = FS->fs_opening;

	if( FCF.fc_nodata )
		return;

	FS->fs_serverWithXDC = strstr(opening,XDC_OPENING) != 0;
	if( !FS->fs_serverWithXDC )
		return;

	if( strstr(opening,"XDC/BASE64") )
	if( !FCF.fc_rawxdcSV )
		FS->fs_XDCencSV = "/BASE64";

	if( FCF.fc_noxdcSV )
		return;

	if( D_FTPHOPS != 1 ){
		if( FCF.fc_forcexdcSV )
			sv1log("# force XDC even FTPHOPS=%d\n",D_FTPHOPS);
		else	return;
	}

	if( toTunnel(Conn) ){
		/* via Teleport / TUNNEL ... */
		if( !FCF.fc_nopasvSV ){
			/* and if PASV on TUNNEL is available ... */
			sv1log("--- use PASV / TUNNEL\n");
			return;
		}
	}else{
		if( FS->fs_IAMCC )
			return;
		if( localsocket(ServSock(Conn,ts,"INIT")) )
		{
			if( FS->fs_XDCforCL )
				sv1log("# client's XDC to XDC local host\n");
			else
			if( FCF.fc_forcexdcSV )
				sv1log("# force XDC even to local host\n");
			else	return;
		}
	}

	encode = FS->fs_XDCencSV;
	if( encode == NULL ) encode = "";
	put_serv(MODE(FS),ts,"MODE XDC%s\r\n",encode);
	if( get_resp(fs,NULL,AVStr(resp),sizeof(resp)) != EOF ){
		FS->fs_XDCforSV = 1;
		sv1log("--- use MODE XDC%s with the server.\n",encode);

		/* the following statement will be unnecessary since
		 * XDC-server check became to be done before PASV/PORT
		 * in server_ftp1()
		 */
		if( 0 <= FS->fs_dsvsock){
			sv1log("## clear non-XDC PORT socket to server[%d]\n",
				FS->fs_dsvsock,FS->fs_dport);
			if( FS->fs_dport[0] ){
				sv1log("## XDC server - PORT client[%s]\n",
					FS->fs_dport);
				close(FS->fs_dsvsock);
				FS->fs_dsvsock = -1;
				setupPORT(Conn,FS,ts,fs,NULL,FS->fs_dport);
			}else
			if( 0 <= FS->fs_pclsock ){
				sv1log("## XDC server - PASV client[%d]\n",
					FS->fs_pclsock);
				put_get(ts,fs,AVStr(resp),sizeof(resp),
					"PORT %s\r\n",XDC_PASV_PORT);
				close(FS->fs_dsvsock);
				FS->fs_dsvsock = -1;
			}else{
				sv1log("## XDC server - ??? client ERROR\n");
			}
		}
	}
}
int abortYY(PCStr(wh),Connection *Conn,int src,int dst);
static void sendABOR(Connection *Conn,FtpStat *FS,PVStr(resp),int rsiz)
{	CStr(qb,32);

	FS->fs_ABOR = 1;
	if( ToS < 0 ){
		/* maybe I'm an origin server */
		return;
	}
	if( file_isreg(FS->fs_dsrc) ){
		/* don't forward ABOR when downloading from local/cache */
		return;
	}

 sv1log("-------- sendABOR[%d %d] data[%d %d]\n",
 ToS,FromS,FS->fs_dsrc,FS->fs_ddst);

	if( ConnType == 'y' ){
		abortYY("FTP-sendABOR",Conn,FS->fs_dsrc,FS->fs_ddst);
	}

	qb[0] = 255; qb[1] = 244; /* IAC+IP */
	send(ToS,qb,2,0);
	/*
	msleep(1);
	*/
	/* this seems not sent out on Win ? */
	if( ServerFlags & (PF_STLS_ON) ){
		Verbose("No OOB will be sent over SSL [%d]\n",ToS);
	}
	qb[0] = 255;
	sendOOB(ToS,qb,1);
	/*
	msleep(1);
	*/
	qb[0] = 242; /* SYNC */
	Xstrcpy(DVStr(qb,1),"ABOR\r\n");
	send(ToS,qb,7,0);

	if( FS->fs_XDCforSV ){
		setVStrEnd(resp,0);
		return;
	}

	/*
	 * disconnect after sending ABORT notification...
	 * the receiver (server) will detect the disconnection, and
	 * will see the reason is ABORT.
	 */
	if( !file_isreg(FS->fs_ddst) ) ShutdownSocket(FS->fs_ddst);
	if( !file_isreg(FS->fs_dsrc) ) ShutdownSocket(FS->fs_dsrc);

	setVStrEnd(resp,0);

/*
wait the server blocking in send() to the data-connection
if( 0 < PollIn(FromS,120*1000) ){
*/
	if( 0 < PollIn(FromS,3*1000) ){
		int pcc;
		pcc = recvPeekTIMEOUT(FromS,BVStr(resp),rsiz-1);
		if( 3 <= pcc ){
			if( strneq(resp,"421",3) ){
				setVStrEnd(resp,pcc);
				sv1log("## ABOR back-E %s",resp);
				return;
			}
		}
		if( 0 < RecvLine(FromS,(char*)resp,rsiz) ){
			sv1log("## ABOR back %s",resp);
		}
	}
}
static int relayABORT(Connection *Conn,FtpStat *FS,int ab)
{	unsigned CStr(qb,32);
	int pcc,rcc,wcc;
	const char *msg = "426 aborted by DeleGate\r\n";
	CStr(resp,256);
	refQStr(rp,resp);
	double Start,Now;

	if( PollIn(FromC,1) <= 0 ){
		if( ab ){
			sendABOR(Conn,FS,AVStr(resp),sizeof(resp));
			sv1log("## ABOR\n");
		}
		return 0;
	}

	Start = Time();
	pcc = recvPeekTIMEOUT(FromC,QVStr((char*)qb,qb),sizeof(qb)-1);
	if( 4 <= pcc && strncasecmp((char*)qb,"ABOR",4) == 0
	 || 2 <= pcc && qb[0] == 255 && qb[1] == 244 /* Telnet IAC+IP */
	){
 sv1log("-------- pcc=%d %X %X\n",pcc,qb[0],qb[1]);
		if( ClientFlags & (PF_STLS_ON) ){
			Verbose("No OOB will be recv. over SSL [%d]\n",FromC);
		}
		if( qb[0] == 255 && qb[1] == 244 ){
			qb[0] = 0;
			rcc = recvOOBx(FromC,QVStr((char*)qb,qb),sizeof(qb));
			sv1log("## ABOR recv %d [%X] OOB\n",rcc,qb[0]);
		}
		rcc = RecvLine(FromC,(char*)qb,sizeof(qb));
		sv1log("## ABOR recv %d [%X %X %X %X %X %X %X %X %X]\n",
		  rcc,qb[0],qb[1],qb[2],qb[3],qb[4],qb[5],qb[6],qb[7],qb[8]);
		wcc = write(ToC,msg,strlen(msg));

		sendABOR(Conn,FS,AVStr(resp),sizeof(resp));
		return 1;
	}

	rp = resp;
	truncVStr(resp);
	for( rcc = 0; rcc < pcc; rcc++ ){
		sprintf(rp,"%s%X",0<rcc?" ":"",0xFF&qb[rcc]);
		rp += strlen(rp);
	}

	Now = Time();
	FS->fs_peekError++;
	sv1log("relayABORT[%d %d %d]: recvPeek: %.3f pcc=%d [%s]\n",
		FS->fs_peekError,FS->fs_dstwcc,IsConnected(FromC,NULL),
		Now-Start,pcc,resp);
	if( 10 < FS->fs_peekError ){
		if( IsConnected(FromC,NULL) == 0 ){
			sv1log("relayABORT: control connection reset\n");
			return 1;
		}
		if( 100 < FS->fs_peekError ){
			return 1;
		}
		sleep(1); /* to avoid logging a recvPeek flood */
	}
	return -1;
}

/*
 * shudown() is not enough to terminate SSLway thread when it is blocking
 * in write() which can be resumed with close().
 */
static void CloseSock(int sock){
	int sv[2];
	Socketpair(sv);
	close(sv[1]);
	dup2(sv[0],sock);
	close(sv[0]);
}
/*
 * the thread for SSL on control-connection with the server may be active
 * when SIGPIPE is caused to be handled in sigPIPE(), then waiting the thread
 * will occur to freeze itself.
 */
static void resetServer(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs){
	sv1log("resetServ %d %d %X [%X %X %X] %X[%d %d %d %d %d]%d [%d %d]%d\n",
		FS->fs_relaying_data,FS->fs_ABOR,p2i(PFC),
		ismainthread(),ServerFilter.f_tid,ClientFilter.f_tid,
		Conn->xf_filters,
		ServerSock,ToS,ToSX,ToSF,FromS,IsConnected(ServerSock,NULL),
		ClientSock,FromC,IsConnected(ClientSock,NULL));

	if( numthreads() <= 0 )
		return;

	if( ServerFilter.f_tid )
	if( 0 <= ToS && 0 <= ToSX && ToS != ToSX ){
		sv1log("## resetServ [%d %d %d %d %d] disconn.\n",
			ServerSock,ToS,ToSX,ToSF,FromS);
		CloseSock(ToS);
	}
}
/* 
 * when broken by ABOR, data-connection is still alive thus the SSL thread
 * for the connection is alive too.  So the data-connection is necessary to
 * be closed before waiting the termination of the threads.
 */
static void waitThreads(int fromC,Connection *dataConn,FtpStat *FS,int src,int dst,int upload){
	Connection *Conn = dataConn;
	int isconn;

	if( file_isreg(src) ){
		Verbose("## Don't wait, resp. from local cache [%d]\n",src);
		return;
	}

	if( INHERENT_thread() == 0 )
		return;

	if( numthreads() <= 0 )
		return;
	if( ServerFilter.f_tid == 0 )
	if( ClientFilter.f_tid == 0 )
		return;

	isconn = IsConnected(fromC,NULL);
	if( FS->fs_ABOR || !isconn ){
		sv1log("## ABOR(%d,%d/%d)[%d][%d]%d [%X %X]%d\n",
			FS->fs_ABOR,!isconn,fromC,
			src,dst,upload,
			ServerFilter.f_tid,ClientFilter.f_tid,numthreads());
		/* this delay may let SSLway blocked in write() which is
		 * necessay to be resumed with close()
		sv1log("---- wait SSLway to be blocked in write()...\n");
		sleep(1);
		 */
		CloseSock(src); /* necessary */
		CloseSock(dst); /* maybe ShutdownSocket() is enough */
	}else{
		if( lTHREAD() )
		sv1log("## Shutting down %s %d/%d\n",upload?"UP":"DOWN",
			src,IsConnected(src,NULL));
		ShutdownSocket(src);

		if( upload ){
			if( ServerFilter.f_tid && (Conn->xf_filters & XF_FSV) ){
				if( lTHREAD() )
				sv1log("## Shutting down FSV/UP %d/%d\n",
					dst,IsConnected(dst,NULL));
				ShutdownSocket(dst);
			}
		}else{
			if( ClientFilter.f_tid && (Conn->xf_filters & XF_FCL) ){
				if( lTHREAD() )
				sv1log("## Shutting down FCL/DOWN %d/%d\n",
					dst,IsConnected(dst,NULL));
				ShutdownSocket(dst);
			}
		}
	}

	if( 0 < waitFilterThread(Conn,300,XF_ALL) ){
		if( lTHREAD() ){
			IStr(rusg,128);
			strfRusage(AVStr(rusg),"%A",1,NULL);
			sv1log("Rusage: %s\n",rusg);
		}
	}
}

int YYgetpairName(Connection *Conn,int fd,PVStr(host),PVStr(peer));
FileSize FTP_data_relay(Connection *Conn,FtpStat *FS,int src,int dst,FILE *cachefp,int tosv)
{	CStr(buff,0x8000);
	FileSize xc;
	int rc,wc1,wc,size;
	int sr,ss,dr,ds;
	int dstEOF;
	int niced,rcode,ngets;
	double Start;
	int odst;
	int osrc,pid;
	const char *reason;
	int fromcache;
	int xsrc,xdst;
	Connection *dataConn = &FS->fs_dataConn;
	int rabort;
	CStr(srcp,256);
	CStr(srch,256);
	CStr(dsth,256);
	CStr(dstp,256);
	void (*sigxfsz)(int) = 0;
	void (*sigpipe)(int) = 0;
	void (*sigurg)(int) = 0;
	int timeout;
	int nrd,ifdv[2],iqev[2],ofdv[2],oqev[2],rev[2];
	int ready_src = 0;
	int cksum = 0;
	int ri;
	int nretry = 0;
	int serrno;

	CStr(xbuff,sizeof(buff));
	int oc;
	CCXP ccx = 0;
	IStr(ccxbuf,128);
	int CCXsize();
	FileSize xrc = 0;

	FS->fs_peekError = 0;
	FS->fs_dstwcc = 0;

	EmiSetupMD5(Conn,"FTP_data_relay");

	size = sizeof(buff);

	if( fromcache = file_isreg(src) ){
		sr = ss = 0;
	}else{
		/*
		setsockbuf(src,size,0);
		*/
		expsockbuf(src,size,0);
		getsockbuf(src,&sr,&ss);
	}
	/*
	setsockbuf(dst,0,size);
	*/
	expsockbuf(dst,0,size);
	getsockbuf(dst,&dr,&ds);

	xc = 0;
	Verbose("FTP data-relay(%d,%d): bufsize=%d\n",src,dst,size);
	YYgetpairName(Conn,dst,AVStr(dsth),AVStr(dstp));
	if( fromcache )
		sv1log("DATA cache .. %s -> %s\n",dsth,dstp);
	else{
		YYgetpairName(Conn,src,AVStr(srch),AVStr(srcp));
		sv1log("DATA %s -> %s .. %s -> %s\n",srcp,srch,dsth,dstp);
	}

	strcpy(dataConn->cl_auth.i_meth,ClientAuth.i_meth);
	strcpy(dataConn->dd_selector,D_SELECTOR);
	if( FS->fs_host[0] )
		wordScan(FS->fs_host,dataConn->sv.p_host); /* set REAL_HOST */
	else
	if( REAL_HOST[0] == 0 )
		strcpy(dataConn->sv.p_host,"-"); /* for DST_PROTO */
	else	strcpy(dataConn->sv.p_host,REAL_HOST);

	odst = dst;
	osrc = src;
	if( tosv != 0 && filter_withCFI(dataConn,XF_FTOSV) )
		dst = insertFTOSV(dataConn,dst,src,NULL);
	else
	if( tosv == 0 && filter_withCFI(dataConn,XF_FTOCL) )
		dst = insertFTOCL(dataConn,dst,src /*,NULL*/);
	else
	if( tosv ){
		/* uploading -- src:client dst:server */
		if( 0 <= (xsrc = insertFCL(dataConn,src)) )
			src = xsrc;
		if( 0 <= (xsrc = FTP_dataSTLS_FCL(Conn,dataConn,src)) )
			src = xsrc;

		insdataFSV(Conn,"upload",FS,dst,src);
		dst = insertFTOSV(dataConn,src,dst,NULL);
	}else{
		/* downloading -- src:server dst:client */
		if( 0 <= (xdst = insertFCL(dataConn,dst)) )
			dst = xdst;

		if( 0 <= (xdst = FTP_dataSTLS_FCL(Conn,dataConn,dst)) )
			dst = xdst;
		if( fromcache ){
			/* can't apply a bidirectional filter for cache */
		}else
		insdataFSV(Conn,"download",FS,src,dst);
		dst = insertFTOCL(dataConn,dst,src /*,NULL*/);
	}

	if( (FCF.fc_ccx & CCX_ANYTYPE) || TYPE_ASCII(FS) ){
		if( tosv && CCXactive(CCX_TOSV) ){
			ccx = CCX_TOSV;
		}else
		if( !tosv && CCXactive(CCX_TOCL) ){
			ccx = CCX_TOCL;
		}
		if( ccx ){
			Bcopy(ccx,ccxbuf,CCXsize());
			ccx = (CCXP)ccxbuf;
			size = size / 4;
		}
	}

	Start = Time();
	niced = 0;
	dstEOF = 0;
	reason = "?";
	rabort = 0;

	FS->fs_ABOR = 0;
	FS->fs_dsrc = src;
	FS->fs_ddst = dst;
	_sigXFSZ = 0;
	sigxfsz = Vsignal(SIGXFSZ,sigXFSZ);
	sigpipe = Vsignal(SIGPIPE,SIG_IGN);

	ready_src = readyAlways(src);
	if( !file_isreg(src) )
	SetNonblockingIO("FTP-DATA",src,1);
	SetNonblockingIO("FTP-DATA",dst,1);
/*
 * this Nonblocking(dst) is necessary to detect ABOR as fast as possible.
 * why? ABOR command can be detected as the EAGAIN on write, so set
 * Non-blocking to cause EAGAIN.  But EAGAIN will not occur if the receiver
 * is so fastly skipping data waiting the response to ABOR.
 * Thus ABOR should also be detected before sending data, while waiting data
 * from remote to be relayed (this is disabled for relaying from local file
 * or cache)
 */
	ifdv[0] = src;   iqev[0] = PS_IN|PS_PRI;
	ifdv[1] = FromC; iqev[1] = PS_IN|PS_PRI;
	ofdv[0] = dst;   oqev[0] = PS_OUT;
	ofdv[1] = FromC; oqev[1] = PS_IN|PS_PRI;
	timeout = IO_TIMEOUT * 1000;
	if( timeout == 0 ){
		timeout = -1;
		/* the value for infinite timeout in PollInsOuts() */
	}

	for( ngets = 0; ; ngets++  ){
		if( FCF.fc_chokedata ){
			size = FCF.fc_chokedata;
			if( sizeof(buff) < size )
				size = sizeof(buff);
			sleep(1);
		}
		if( fromcache )
		{
			rc = read(src,buff,QVSSize(buff,size));
			if( inputReady(FromC,NULL) ){
				rabort = relayABORT(Conn,FS,0);
				if( 0 < rabort ){
 sv1log("-------- RA-i %d\n",rabort);
					reason = "ABORT";
					dstEOF = 1;
					break;
				}
			}
		}
		else{
			/*
			if( !readyAlways(src) )
			if( PollIn(src,IO_TIMEOUT*1000) <= 0 ){
				reason = "poll-TIMEOUT";
				break;
			}
			*/
			if( !ready_src ){
				nrd = PollInsOuts(timeout,2,ifdv,iqev,rev);
				if( nrd <= 0 ){
					reason = "poll-TIMEOUT";
					break;
				}
				if( 0 < nrd && rev[1] ){
					rabort = relayABORT(Conn,FS,0);
					if( 0 < rabort ){
 sv1log("-------- RA-I %d\n",rabort);
						reason = "ABORT";
						dstEOF = 1;
						break;
					}
				}
			}

			/*
			rc = readsTO(src,AVStr(buff),size,100);
			*/
			rc = read(src,(char*)buff,QVSSize(buff,size));
		}
		if( rc <= 0 ){
			reason = "read-EOF";
			break;
		}

		EmiUpdateMD5(Conn,buff,rc);
		if( cachefp )
		{	int wc1 =
			fwrite(buff,1,rc,cachefp);
			if( wc1 <= 0 || ferror(cachefp) || _sigXFSZ ){
		sv1log("CACHE fwrite()=%d %X errno=%d ferror=%d SIGXFSZ=%d\n",
			wc1,iftell(cachefp),errno,ferror(cachefp),_sigXFSZ);
				cachefp = NULL;
			}
		}
		xc += rc;
		for( ri = 0; ri < rc; ri++ ){
			cksum ^= buff[ri];
		}

		if( ccx ){
			oc = CCXexec(ccx,buff,rc,AVStr(xbuff),sizeof(xbuff));
			rc = oc;
			Bcopy(xbuff,buff,oc);
			xrc += oc;
		}

		/*
		for( wc = 0; wc < rc; wc += wc1 ){
		*/
		for( wc = 0; wc < rc; ){
			relayingDATA = 1;
			errno = 0;
			wc1 = write(dst,buff+wc,rc-wc);
			serrno = errno;
			if( 0 < wc1 ){
				wc += wc1;
				FS->fs_dstwcc += wc1;
				if( wc == rc ){
					break;
				}
			}
			rabort |= (relayingDATA & 2);
			relayingDATA = 0;
			if( rabort ){
				relayABORT(Conn,FS,1);
			}
			if( serrno == EAGAIN ){
				nretry++;
				nrd = PollInsOuts(3*1000,2,ofdv,oqev,rev);
				if( nrd <= 0 ){
 fprintf(stderr,"--FTP[%d]Poll(%d %d %5d/%5d)..",getpid(),timeout,wc1,wc,rc);
 fflush(stderr);
					wc1 = write(dst,buff+wc,rc-wc);
 fprintf(stderr," write(%5d)=%d",rc-wc,wc1);
 if( wc1 < 0 )
 fprintf(stderr,"(errno=%d xcc=%llX)",errno,xc);
					if( 0 < wc1 ){
 fprintf(stderr,"\n");
						wc += wc1;
						continue;
					}
 fprintf(stderr,".. %d[%d %d]",nrd,rev[0],rev[1]);
 fflush(stderr);
					nrd = PollInsOuts(timeout,2,ofdv,oqev,rev);
 fprintf(stderr,".. %d[%d %d]\n",nrd,rev[0],rev[1]);
				}
				if( 0 < nrd && rev[1] ){
					rabort = relayABORT(Conn,FS,0);
					if( 0 < rabort ){
 sv1log("-------- RA-O %d\n",rabort);
						reason = "ABORT";
						dstEOF = 1;
						goto EXIT;
					}
				}
				continue;
			}

			if( wc1 <= 0 ){
 sv1log("-------- RA-X wc1=%d/%d(%d-%d) errno=%d/%d (%lld)\n",
	wc1,rc-wc,rc,wc,serrno,errno,xc);
				reason = "write-EOF";
				dstEOF = 1;
				goto EXIT;
			}
		}
		if( !ImCC && ngets )
			niced = doNice("FTPdata",Conn,src,NULL,dst,NULL,niced,xc,ngets,Start);
	}

	if( ccx ){
		const char *ics = 0;
		const char *ocs = 0;
		if( !dstEOF ){
			oc = CCXexec(ccx,"",0,AVStr(buff),sizeof(buff));
			if( 0 < oc ){
				wc1 = write(dst,buff,oc);
			}
		}
		ics = CCXident(ccx);
		CCXoutcharset(ccx,&ocs);
		sv1log("FTP-CCX [%s]->[%s] %lld -> %lld\n",
			ics?ics:"",ocs?ocs:"",xc,xrc);

		if( !tosv && !CCXactive(CCX_TOSV) )
		if( ics && *ics && !streq(ics,"US-ASCII") )
		if( DIRCOMS(FS->fs_curcom) )
		if( FCF.fc_ccx & CCX_AUTOSVCC )
		{
			/* remember the charcode from the server to be used in
			 * the conversion of commands (and data) to the server
			 */
			sv1log("SET CHARCODE=%s/%s:tosv:ftp\n",ocs?ocs:"",ics);
			CCXcreate("*",ics,FSCCX_TOSV);
			if( ocs && *ocs ){
				CCX_setindflt(FSCCX_TOSV,ocs);
			}
		}
	}

	EmiFinishMD5(Conn,"FTP_data_relay",xc);

	daemonlog("E",
	"FTP data-relay([%d]%xb -> [%d]%xb) %lldb / %d/ (%X) %4.2fs (%s)\n",
		src,sr,dst,ds,xc,ngets,0xFF&cksum,Time()-Start, reason);
	if( nretry || lDEBUGMSG() ){
		sv1log("-dD FTP data NBIO retry:%d/%d (%lld)\n",
			nretry,ngets,xc);
	}

	if( !dstEOF )
		set_linger(dst,DELEGATE_LINGER);
EXIT:
	if( ConnType == 'y' && rabort ){
		abortYY("FTP-ABORTED",Conn,src,dst);
	}
	waitThreads(FromC,dataConn,FS,src,dst,tosv);

	if( dst != odst ){
		close(dst);
		if( strcaseeq(FS->fs_proto,"sftp")
		 && (ClientFilter.f_tid || ServerFilter.f_tid)
		){
			/* with SFTP/FTP gw. process and SSL thread */
			NoHangWait();
		}else
		wait(0);
	}
	if( src != osrc ){
		close(src); /* close the socket/pipe to the filter */
	}
	if( dst != odst || src != osrc || dataConn->xf_filters ){
		/* wait the filter programs to exit */
		while( 0 < (pid = NoHangWait()) )
			sv1log("## finished filter [%d]\n",pid);
	}
	dataConn->xf_filters = 0;
	if( sigxfsz ) Vsignal(SIGXFSZ,sigxfsz);
	if( sigpipe ) Vsignal(SIGPIPE,sigpipe);

	/*
	 * socket on Windows seems not be shutdown in non-blocking mode.
	 * so do it or shutdown() before close()
	 */
	if( !file_isreg(src) )
	SetNonblockingIO("FTP-DATA",src,0);
	SetNonblockingIO("FTP-DATA",dst,0);
	/*
	if( !file_isreg(src) )
	ShutdownSocket(src);
	ShutdownSocket(dst);
	*/

	if( dstEOF )
		return -xc;
	return xc;
}

static FileSize PORTrelay(Connection *Conn,FtpStat *FS,int STOR,int dsock,FILE *ts,FILE *fs,FILE *tc,FILE *fc,PCStr(port),int modeXDC,FILE *cachefp,PVStr(resp),int rsize)
{	int csock;
	FileSize xc;

	if( modeXDC ){
		xc = XDCrelayServ(FS,STOR,ts,fs,tc,fc,dsock,port,
			cachefp,AVStr(resp),rsize);
		close(dsock);
	}else{
		csock = makeDataConn(Conn,port,ClientSock,0);
		if( STOR )
			xc = FTP_data_relay(Conn,FS,csock,dsock,cachefp,STOR);
		else	xc = FTP_data_relay(Conn,FS,dsock,csock,cachefp,STOR);
		close(csock);
		close(dsock);
		Verbose("Transfer complete (%lld).\n",xc);
		get_resp(fs,tc,AVStr(resp),rsize);
	}
	return xc;
}
static FileSize PASVrelay(Connection *Conn,FtpStat *FS,int STOR,int svd,int cld,FILE *cachefp,FILE *fs,FILE *tc,PVStr(resp),int rsize)
{	FileSize xc;

	if( STOR )
		xc = FTP_data_relay(Conn,FS,cld,svd,cachefp,STOR);
	else	xc = FTP_data_relay(Conn,FS,svd,cld,cachefp,STOR);
	close(cld);
	close(svd);
	Verbose("PASVrelay(%d,%d): %lld\n",svd,cld,xc);
	get_resp(fs,tc,AVStr(resp),rsize);
	fflush(tc);
	return xc;
}

#define SSEEK(str)	{str += strlen(str);}

/*
static int pollSC(PCStr(what),int timeout,FILE *fs,FILE *fc)
*/
static int pollSC(FtpStat *FS,PCStr(what),FILE *fs,FILE *fc)
{	FILE *fpv[2];
	int rds[2];
	int nready;
	int serrno;
	Connection *Conn = FS->fs_Conn;

	int timeout;
	if( FS->fs_timeout )
		timeout = (int)FS->fs_timeout;
	else	timeout = FTP_FROMCLNT_TIMEOUT;

	fpv[0] = fs;
	fpv[1] = fc;
	/*
	 * "fs" and/or "fc" may be connected with pipe to external filter
	 * so PollIns should be replaced with ..?.. on Win32
	 */
	Verbose("%s: start PollIns=[%d,%d]\n",what,fileno(fs),fileno(fc));
DOPOLL:
	nready = fPollIns(timeout*1000,2,fpv,rds);
	serrno = errno;
	if( nready <= 0 || rds[0] != 0 ){ /* timeout or server is ready */
		sv1log("%s: exit PollIns=%d[sv=%d,cl=%d] timeout=%d e%d\n",
			what,nready,rds[0],rds[1],timeout,serrno);
		if( ConnType == 'y' && nready < 0 && serrno == EINTR ){
			sv1log("----yyFTP got INTR\n");
			goto DOPOLL;
		}
		if( rds[0] == 0 ) /* timeout */
			IGNRETP write(fileno(fs),"QUIT\r\n",6);
		if( 0 < nready )
			return nready;
		else	return -1;
	}
	return nready;
}

#define STATCACHE ".-_-."

void ftpc_dirext(PVStr(path))
{
	if( strtailchr(path) != '/' )
		strcat(path,"/");
	Xsprintf(TVStr(path),"%s/%s:%s:",STATCACHE,
		FTP_LIST_COM,FTP_LIST_OPT);
}
void ftpc_ext(PVStr(path),PVStr(ext),PCStr(xtype),PCStr(com),PCStr(opt),PCStr(arg))
{	const char *dp;
	CStr(name,1024);

	setVStrEnd(ext,0);
	if( strcaseeq(com,"CWD") || strcaseeq(com,"LOGIN") ){
		sprintf(ext,"/%s/%s:",STATCACHE,com);
	}else
	/*
	if( strcaseeq(com,"LIST") || strcaseeq(com,"NLST") ){
	*/
	if( comeq(com,"LIST") || comeq(com,"NLST")
	 || comeq(com,"MLST") || comeq(com,"MLSD")
	){
		if( arg[0] == 0 || streq(arg,".") )
			if( strtailchr(path) != '/' )
				strcat(path,"/");

		if( dp = strrchr(path,'/') ){
			strcpy(name,dp+1);
			((char*)dp)[1] = 0;
		}else{
			strcpy(name,path);
			setVStrEnd(path,0);
		}
		sprintf(ext,"%s/%s:%s:%s",STATCACHE,com,opt,name);
	}else{
		if( xtype == NULL || xtype[0] == 0 )
			xtype = "A";
		if( xtype[0] != 'I' )
			sprintf(ext,"#[%c]",xtype[0]);
	}
}

static FILE *ifNotModified(FtpStat *FS,PCStr(host),int port,PCStr(path),PCStr(cpath),FileSize csize,int cmtime)
{	CStr(stat,1024);
	const char *line;
	CStr(nmtimes,128);
	CStr(nname,128);
	CStr(snname,128);
	CStr(abspath,2048);
	FileSize nsize;
	int nmtime;
	FILE *ts,*fs,*cfp;

	if( csize < 0 || cmtime < 0 )
		return NULL;

	if( FCF.fc_maxreload && csize <= FCF.fc_maxreload )
		return NULL; /* re-loading will not cost so much */

	nmtime = -1;
	nsize = -1;

	strcpy(abspath,FS->fs_logindir);
	chdir_cwd(AVStr(abspath),path,1);

	ts = FS->fs_ts;
	fs = FS->fs_fs;
	if( ts == NULL || fs == NULL ){
		/* 9.9.8 can occur on STOR with expired cache */
		return NULL;
	}

	fprintf(ts,"MDTM %s\r\n",abspath);
	fflush(ts);
	get_resp(fs,NULL,AVStr(stat),sizeof(stat));
	if( atoi(stat) == 550 ){
		sv1log("## VALIDATE(cache/original): removed %s\n",cpath);
		return NULL;
	}else
	if( atoi(stat) == 213 ){
		Xsscanf(stat,"%*d %s",AVStr(nmtimes));
		nmtime = scanYmdHMS_GMT(nmtimes);
		fprintf(ts,"SIZE %s\r\n",abspath);
		fflush(ts);
		get_resp(fs,NULL,AVStr(stat),sizeof(stat));
		if( atoi(stat) == 213 ){
			Xsscanf(stat,"%*d %lld",&nsize);
		}
	}else
	/* STAT is no good because
	 * - time is not in GMT but in local to the server's time zone
	 * - size does not reflect the difference of TYPE {ASCII,BINARY}
	 */
	{
		fprintf(ts,"STAT %s\r\n",abspath);
		fflush(ts);
		get_resp(fs,NULL,AVStr(stat),sizeof(stat));
		if( strchr(stat,'\n') == 0 ){
			line = stat;
		}else
		line = strchr(stat,'\n') + 1;
		scan_ls_l(line,VStrNULL,NULL,VStrNULL,VStrNULL,&nsize,
			AVStr(nmtimes),AVStr(nname),AVStr(snname));
		nmtime = LsDateClock(nmtimes,time(0));
		sv1log("## size=%lld [%s]%d %s\n",nsize,nmtimes,nmtime,stat);
	}

	sv1log("## VALIDATE(cache/original): size=%lld/%lld age=%d/%d %s\n",
		csize,nsize, ll2i(time(0)-cmtime),ll2i(time(0)-nmtime),cpath);

	if( nsize != csize || cmtime < nmtime )
		return NULL;

	/*
	 * touch and reuse the cache file if size and age is not changed ...
	 */
	File_touch(cpath,time(0));
	return fopen(cpath,"r");
}

static FILE *fopen_cache(int create,Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg),PVStr(path),PVStr(cpath),xPVStr(xcpath))
{	const char *host = FS->fs_host;
	const char *user = FS->fs_USER;
	int port = FS->fs_port;
	CStr(opt,256);
	CStr(ext,256);
	FILE *cfp;
	FileSize csize;
	int isdir,cmtime;
	int exp;

	if( without_cache() )
		return NULL;

	strcpy(path,FS->fs_CWD);
	opt[0] = 0;
	/*
	if( strcaseeq(com,"LIST") || strcaseeq(com,"NLST") ){
	*/
	if( comeq(com,"LIST") || comeq(com,"NLST")
	 || comeq(com,"MLST") || comeq(com,"MLSD")
	){
		isdir = 1;
		if( arg[0] == '-' )
		{
			arg = wordScan(arg,opt);
			if( isspace(*arg) )
				arg++;
		}
	}else	isdir = -1;

	chdir_cwd(AVStr(path),arg,1);
	ftpc_ext(AVStr(path),AVStr(ext),FS->fs_TYPE,com,opt,arg);

	if( create ){
		cfp = CTX_creat_ftpcache(Conn,user,
			host,port,path,ext,AVStr(cpath),AVStr(xcpath));
	}else{
		if( 0 < FS->fs_nocache )
			exp = 0;
		else	exp = ftp_EXPIRE(Conn);
		cfp = fopen_ftpcache0(Conn,exp,host,port,path,ext,AVStr(cpath),
			&isdir,&csize,&cmtime);

		if( cfp == NULL && isdir < 0 )
		cfp = ifNotModified(FS,host,port,path,cpath,csize,cmtime);

		setPStr(xcpath,"",0);
	}
	sv1log("FTP-CACHE: %s [%s] = [%s][%s]:%x\n",com,arg,cpath,xcpath,p2i(cfp));
	return cfp;
}

static int isMounted(FtpStat *FS);
int MLSTtoFacts(PCStr(statresp),PVStr(facts),int fsize);
int vnodeSetMLSTfacts(PCStr(file),PCStr(facts));
static void putvnode(FtpStat *FS,PCStr(com),PCStr(arg),PCStr(statresp)){
	CStr(rpath,1024);
	CStr(vpath,1024);
	CStr(vnode,1024);
	CStr(facts,1024);

	if( FCF.fc_uno == 0 )
		return;

	MLSTtoFacts(statresp,AVStr(facts),sizeof(facts));
	strcpy(rpath,FS->fs_CWD);
	chdir_cwd(AVStr(rpath),arg,0);
	getVUpathX(FS,rpath,AVStr(vpath),1);
	if( strtailchr(vpath) == '/' ){
		setVStrEnd(vpath,strlen(vpath)-1);
	}
	sprintf(vnode,"%s%s",FCF.fc_uno,vpath);
	vnodeSetMLSTfacts(vnode,facts);
}
static void put_statcache(Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg),PCStr(statresp))
{	FILE *cachefp;
	CStr(path,1024);
	CStr(cpath,1024);
	CStr(xcpath,1024);

	if( comeq(com,"MLST") /*&& isMounted(FS)*/ ){
		putvnode(FS,com,arg,statresp);
	}

	cachefp = fopen_cache(1,Conn,FS,com,arg,AVStr(path),AVStr(cpath),AVStr(xcpath));
	if( cachefp == NULL )
		return;
	fputs(statresp,cachefp);
	fflush(cachefp);
	cache_done(1,cachefp,cpath,xcpath);
}
static int get_statcache(Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg),FILE *tc){
	FILE *cachefp;
	CStr(path,1024);
	CStr(cpath,1024);
	CStr(xcpath,1024);
	CStr(statresp,1024);

	cachefp = fopen_cache(0,Conn,FS,com,arg,AVStr(path),AVStr(cpath),AVStr(xcpath));
	if( cachefp == NULL )
		return 0;

	fputsMLST(FS,1,cachefp,tc,AVStr(statresp));
	fflush(tc);

	if( comeq(com,"MLST") /*&& isMounted(FS)*/ ){
		putvnode(FS,com,arg,statresp);
	}
	return 1;
}

static int relay_data(FtpStat *FS,Connection *Conn,FILE *ts,FILE *fs,FILE *tc,FILE *fc,PCStr(com),PCStr(arg),int err,PVStr(resp),int rsize)
{	int rcode = 0;	
	const char *dport       = FS->fs_dport;
	int XDCforSV      = FS->fs_XDCforSV;
	int XDCforCL      = FS->fs_XDCforCL;
	int dsvsock       = FS->fs_dsvsock;
	int psvsock       = FS->fs_psvsock;
	int pclsock       = FS->fs_pclsock;
	int PORTforPASV   = FS->fs_PORTforPASV;
	int PASVforPORT   = FS->fs_PASVforPORT;
	int ssock,csock,psock,dsock;
	int start;
	FileSize xc;
	CStr(path,1024);
	CStr(cachepath,1024);
	CStr(xcachepath,1024);
	FILE *cachefp;
	int STOR = comUPLOAD(com);
	const char *dp;

	EmiSetupMD5(Conn,"relay_data");

	FS->fs_dsize = 0;
	if( dp = strstr(resp," bytes)") ){
		for( dp--; resp <= dp; dp-- ){
			if( *dp == '(' ){
				Xsscanf(dp+1,"%lld",&FS->fs_dsize);
				sv1log("[%lld]%s",FS->fs_dsize,resp);
				break;
			}
			if( !isspace(*dp) && !isdigit(*dp) && *dp != '-' )
				break;
		}
	}

	strcpy(D_SELECTOR,FS->fs_CWD); /* D_SELECTOR for the path in server */
	chdir_cwd(AVStr(D_SELECTOR),arg,0);
	wordScan(com,ClientAuth.i_meth);

	if( err ){
		sv1log("#### close data connection because of error.\n");
		wordScan(com,FS->fs_dataError);
/*
DONT close the date socket to the server, the client (ex. Mozaic)
may expect to reuse already connected PORT and will not issue
another PORT for the next retreaval command.
Such conn. should be reused on next PORT command (and may be
closed at the end of a FTPCC session ?).

		if( 0 <= FS->fs_dsvsock ) close(FS->fs_dsvsock);
		if( 0 <= FS->fs_psvsock ) close(FS->fs_psvsock);
		FS->fs_dsvsock = FS->fs_psvsock = -1;
*/

/*
DONT close the socket to accept PASV connection by a client, the client
(e.x. Mozilla) may have connected it and may be going to reuse it
for the next retrieval command...
Such PASV conn. should be closed on the next PASV if it is not used...
(This may be done at setupPASV() by polling existing connection ...)
 
		if( 0 <= FS->fs_pclsock ) close(FS->fs_pclsock);
		FS->fs_pclsock = -1;
*/
		return 0;
	}

	xc = 0;
	start = time(0);

	if( FCF.fc_nodata ){
		get_resp(fs,tc,AVStr(resp),rsize);
		goto EXIT;
	}

	if( FS->fs_REST ){
		cachefp = NULL;
		sv1log("don't cache: REST %lld\n",FS->fs_REST);
		FS->fs_REST = 0;
	}else
	cachefp = fopen_cache(1,Conn,FS,com,arg,AVStr(path),AVStr(cachepath),AVStr(xcachepath));
	setVStrEnd(resp,0);

	FS->fs_relaying_data = 1;
	if( XDCforSV && XDCforCL ){
		sv1log("-- XDC to XDC\n");
		get_resp(fs,NULL,AVStr(resp),rsize);
		fputs(resp,tc);
		xc = cpyMessageFX(fs,tc,cachefp,FS->fs_XDCencCL);
		get_resp(fs,NULL,AVStr(resp),rsize);
		putPostStatus(tc,resp);
		fputs(resp,tc);
		fflush(tc);
	}else
	if( XDCforSV && psvsock < 0 ){
		sv1log("-- XDCserv to %sclnt\n",0<=pclsock?"PASV":"PORT");
		xc = XDCrelayClnt(Conn,FS,STOR,ts,fs,tc,fc,
			cachefp,AVStr(resp),rsize);
		if( 0<=pclsock )
			close(pclsock);
	}else
	if( PASVforPORT && 0 <= psvsock && XDCforCL ){
		sv1log("-- PASVserv to XDCclnt\n");
		xc = XDCrelayServ(FS,STOR,ts,fs,tc,fc,psvsock,dport,
			cachefp,AVStr(resp),rsize);
	}else
	if( PORTforPASV && 0 <= dsvsock && 0 <= pclsock ){
		ssock = ACCEPT_SVPORT(dsvsock,0);
		Verbose("Start accept on port of PASV for client\n");
		csock = ACCEPTdc(pclsock,1);
		close(dsvsock);
		close(pclsock);
		Verbose("PORTforPASV: accept[%d][%d] data[%d][%d]\n",
			dsvsock,pclsock,ssock,csock);

		xc = PASVrelay(Conn,FS,STOR,ssock,csock,cachefp,fs,tc,AVStr(resp),rsize);
	}else
	if( 0 <= psvsock ){
		if( PASVforPORT ){
			psock = makeDataConn(Conn,dport,ClientSock,0);
			Verbose("PASVforPORT: [%d][%d]\n",psvsock,psock);
			/*
			PASVforPORT = 0;
			*/
			FS->fs_PASVforPORT = 0;
		}else{
			Verbose("Start accept on PASV port\n");
			psock = ACCEPTdc(pclsock,1);
			close(pclsock);
		}
		if( 0 <= psock ){
			xc = PASVrelay(Conn,FS,STOR,psvsock,psock,cachefp,fs,tc,AVStr(resp),rsize);
		}else{
			rcode = -1;
			close(psvsock);
		}
	}else{
		dsock = ACCEPT_SVPORT(dsvsock,0);
		close(dsvsock);
		if( dsock < 0 )
			Finish(1);

		xc = PORTrelay(Conn,FS,STOR,dsock,ts,fs,tc,fc,dport,XDCforCL,
			cachefp,AVStr(resp),rsize);
	}

	FS->fs_relaying_data = 0;
	FS->fs_dsvsock = FS->fs_psvsock = FS->fs_pclsock = -1;
	FS->fs_dclsock = -1;
	FS->fs_dport[0] = FS->fs_mport[0] = 0;

	if( cachefp ){
		int OK;

		fflush(cachefp);
		OK = atoi(resp) == 226 && file_sizeX(fileno(cachefp)) == xc;

		if( !OK )
		sv1log("FTP-CACHE-ERROR: %lld/%lld %s",file_sizeX(fileno(cachefp)),xc,resp);

		cache_done(OK,cachefp,cachepath,xcachepath);
		sv1log("FTP-CACHE: written=%d %lld bytes [%s]\n",OK,xc,cachepath);
	}

EXIT:
	if( FS->fs_cstat == NULL )
		FS->fs_cstat = "W";

	EmiFinishMD5(Conn,"relay_data",0);
	putXferlog(Conn,FS,com,arg,start,xc,"");
	return rcode;
}

void putXferlog(Connection *Conn,FtpStat *FS,PCStr(com),PCStr(arg),FileSize start,FileSize xc,PCStr(cstat))
{	CStr(clnt,MaxHostNameLen);
	CStr(url,2048);
	const char *auser;
	const char *dp;
	CStr(auserb,256);
	int bin,anon;
	int STOR = comUPLOAD(com);
	IStr(md5a,64);

	if( !strcaseeq(com,"RETR") && !comUPLOAD(com) )
		return;

	anon = FS->fs_anonymous;
	/*if( FS->fs_imProxy )*/
	{	CStr(fpath,2048);

		fpath[0] = 0;
		if( FS->fs_CWD[0] ){
			if( FS->fs_CWD[0] != '/' )
				strcat(fpath,"/");
			strcat(fpath,FS->fs_CWD);
		}
		if( strtailchr(fpath) != '/' )
			strcat(fpath,"/");
		strcat(fpath,arg);

		if( FS->fs_islocal ){
			strcpy(url,fpath);
		}else
		if( strncmp(fpath,"//",2) == 0 ){
			strcpy(url,fpath);
		}else{
			if( strcmp(DST_PROTO,"ftp") != 0 )
				sprintf(url,"%s://",DST_PROTO);
			else	strcpy(url,"//");
			if( !anon )
				Xsprintf(TVStr(url),"%s@",FS->fs_USER);
			strcat(url,DST_HOST);
			if( DST_PORT != serviceport("ftp") )
				Xsprintf(TVStr(url),":%d",DST_PORT);
			if( strncmp(arg,"https:",6) != 0 )
			strcat(url,fpath);
		}
	}
	/*else{
		if( FS->fs_CWD[0] )
			sprintf(url,"%s/%s",FS->fs_CWD,arg);
		else	strcpy(url,arg);
	}*/
	/*
	getClientHostPort(Conn,clnt);
	*/
	strfConnX(Conn,"%h",AVStr(clnt),sizeof(clnt)); /* with ".-.ridentClientHost" extension */
	bin = FS->fs_TYPE[0] == 'I';
	/* OR 'i' ? */

	if( FS->fs_auth == 0 ){
		FS->fs_auth = 1;
		getClientUserMbox(Conn,AVStr(FS->fs_auser));
		if( dp = strchr(FS->fs_auser,'@') )
			truncVStr(dp);
	}
	if( FS->fs_auser[0] && strcmp(FS->fs_auser,"?") != 0 )
		auser = FS->fs_auser;
	else
	if( ClientAuthUser[0] ){
		sprintf(auserb,"%s@%s",ClientAuthUser,ClientAuthHost);
		auser = auserb;
	}
	else	auser = NULL;

	EmiPrintMD5(Conn,AVStr(md5a));

	/*
	ftp_xferlog(start,clnt,xc,url,bin,STOR,
	*/
	/*
	ftp_xferlog(start,clnt,FS->fs_RESTed,xc,url,bin,STOR,
	*/
	ftp_xferlog(start,clnt,FS->fs_RESTed,xc,md5a,
		url,bin,STOR,
		anon,anon?FS->fs_PASS:FS->fs_USER,auser,
		(FS->fs_cstat!=NULL)?FS->fs_cstat:"N");
}
void gwputXferlog(Connection *Conn,PCStr(user),PCStr(pass),PCStr(path),FileSize start,int chit,FileSize xc)
{	FtpStat FSbuf,*FS = &FSbuf;

	bzero(&FSbuf,sizeof(FSbuf));
	if( FS->fs_anonymous = is_anonymous(user) )
		strcpy(FS->fs_PASS,pass);
	else	strcpy(FS->fs_USER,user);
	strcpy(FS->fs_TYPE,"I");
	if( chit )
		FS->fs_cstat = "H";
	putXferlog(Conn,FS,"RETR",path,start,xc,"");
}

static int controlCWD(FtpStat *FS,FILE *tc,PCStr(dir))
{
	if( strcaseeq(dir,".") ){
		FS->fs_nocache = !FS->fs_nocache;
		fprintf(tc,"250 CACHE %s.\r\n",FS->fs_nocache?"disabled":"enabled");
		sv1log("RELOAD %d\n",FS->fs_nocache);
		fflush(tc);
		return 1;
	}
	/* if .control ... then enter control mode ??? */
	return 0;
}

void xdatamsg(FtpStat *FS,PVStr(msg),int datafd,PCStr(com),PCStr(path),FileSize dsize)
{	FileSize fsize;
	const char *what;
	CStr(mode,32);

	if( FS->fs_TYPE[0] == 0 || FS->fs_TYPE[0] == 'A' )
		strcpy(mode,"ASCII");
	else	strcpy(mode,"BINARY");
	if( 0 <= dsize )
		fsize = dsize;
	else
	fsize = file_sizeX(datafd);

	if( strcaseeq(com,"RETR") ){
		if( what = strrchr(path,'/') )
			what = what + 1;
		else	what = path;
	}else	what = com;

	FS->fs_dsize = file_sizeX(datafd);
	sprintf(msg,"Opening %s mode data connection for %s (%lld bytes).",
		mode,what,fsize);
}

static int connect_data(PCStr(where),FtpStat *FS,PVStr(port),int cntrlsock)
{	int cdsock;

	cdsock = -1;
	if( FS->fs_dport[0] ){
		strcpy(port,FS->fs_dport);
		sv1log("%s: connecting to client's PORT %s\n",where,port);
/*
		cdsock = makeDataConn(FS->fs_Conn,FS->fs_dport,cntrlsock,1);
*/
		cdsock = makeDataConn(FS->fs_Conn,FS->fs_dport,cntrlsock,0);
		FS->fs_dport[0] = 0;
	}else
	if( 0 < FS->fs_pclsock ){
		strcpy(port,FS->fs_mport);
		sv1log("%s: accepting client's PASV %s\n",where,port);
		cdsock = ACCEPTdc(FS->fs_pclsock,1);
		close(FS->fs_pclsock);
		FS->fs_pclsock = -1;
	}
	return cdsock;
}
static void getupath(FtpStat *FS,PCStr(arg),PVStr(path))
{	const char *dp;
	CStr(tmp,1024);

	strcpy(path,FS->fs_CWD);
	strcpy(tmp,arg);
	if( dp = strrchr(tmp,'/') ){
		truncVStr(dp);
		chdir_cwd(AVStr(path),tmp,1);
	}
	chdir_cwd(AVStr(path),STATCACHE,1);
	chdir_cwd(AVStr(path),"UPDATED",1);
}
void mark_updated(FtpStat *FS,PCStr(com),PCStr(arg))
{	CStr(path,1024);
	CStr(cpath,1024);
	CStr(xcpath,1024);
	FILE *cfp;

	getupath(FS,arg,AVStr(path));
	cfp = CTX_creat_ftpcache(FS->fs_Conn,FS->fs_USER,
		FS->fs_host,FS->fs_port,
		path,"",AVStr(cpath),AVStr(xcpath));
	if( cfp ){
		sv1log("#UPDATED %s\n",path);
		fprintf(cfp,"%s %s\n",com,arg);
		cache_done(1,cfp,cpath,xcpath);
	}
}
extern int FTP_CACHE_ANYUSER;
static int lookaside_cache(Connection *Conn,FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),int remote)
{	CStr(path,1024);
	CStr(cpath,1024);
	CStr(cdate,32);
	int found,start;
	FileSize xc;
	FILE *cfp;
	int cdsock;
	CStr(port,128);
	CStr(msg,256);
	int islocal;
	int viaICP;
	FileSize dsize;
	int dtime;
	int modeXDC;

	if( FCF.fc_nodata )
		return 0;

	start = time(0);
	islocal = 0;
	viaICP = 0;
	dsize = -1;
	dtime = -1;

	modeXDC = usemodeXDCtoCL(FS);

	if( remote == 0 ){
	/*
	if( strcaseeq(com,"LIST") || strcaseeq(com,"NLST") )
	*/
	if( comeq(com,"LIST") || comeq(com,"NLST")
	 || comeq(com,"MLSD")
	)
	if( cfp = localLIST(FS,tc,com,arg,AVStr(path)) ){
		strcpy(cpath,path);
		islocal = 1;
		goto OPENED;
	}
	if( strcaseeq(com,"RETR") )
	if( cfp = localRETR(FS,tc,com,arg,AVStr(path)) ){
		strcpy(cpath,path);
		islocal = 1;
		goto OPENED;
	}
	}
	if( without_cache() ){
		/* 9.9.1 not local, disable the cache for MOUNTed server */
		return 0;
	}

	if( !FTP_CACHE_ANYUSER && !FS->fs_anonymous )
		return 0;

	if( FS->fs_REST ){
		Verbose("ignore cache: set REST %lld\n",FS->fs_REST);
		return 0;
	}
	cfp = fopen_cache(0,Conn,FS,com,arg,AVStr(path),AVStr(cpath),VStrNULL);

	if( cfp == NULL && strcaseeq(com,"RETR") ){
		CStr(url,2048);
		sprintf(url,"ftp://%s:%d/%s",FS->fs_host,FS->fs_port,path);
		cfp = fopen_ICP(Conn,url,&dsize,&dtime);
		if( cfp != NULL )
			viaICP = 1;
	}
	if( cfp == NULL ){
		FS->fs_cstat = "N";
		return 0;
	}

	/*
	if( comeq(com,"LIST") || comeq(com,"NLST") ){
	*/
	if( comeq(com,"LIST") || comeq(com,"NLST")
	 || comeq(com,"MLSD")
	){
		CStr(upath,1024);
		CStr(cupath,1024);
		int ltime,utime;

		getupath(FS,arg,AVStr(upath));

		nonxalpha_escapeX(upath,AVStr(cupath),sizeof(cupath));
		strcpy(upath,cupath);
		CTX_cache_path(Conn,"ftp",FS->fs_host,FS->fs_port,upath,AVStr(cupath));
		utime = File_mtime(cupath);
		if( 0 < utime ){
			ltime = file_mtime(fileno(cfp));
			if( ltime < utime ){
				sv1log("#UPDATED [%s][%s] %d < %d\n",
					cpath,upath,ltime,utime);
				fclose(cfp);
				return 0;
			}
		}
	}

OPENED:
	if( comUPLOAD(com) ){
		fclose(cfp);
		sv1log("FTP-CACHE: STOR remove the cache [%s]\n",cpath);
		unlink(cpath);
		/* unlink the directory */
		FS->fs_cstat = "W";
		return 0;
	}

	found = 0;
	if( modeXDC ){
		strcpy(port,FS->fs_dport);
		cdsock = 0;
	}else
	cdsock = connect_data("FTP-CACHE",FS,AVStr(port),ClientSock);

	if( 0 <= cdsock ){
		if( dtime < 0 )
			dtime = file_mtime(fileno(cfp));
		rsctime(dtime,AVStr(cdate));

		xdatamsg(FS,AVStr(msg),fileno(cfp),com,path,dsize);
		fprintf(tc,"150- %s\r\n",msg);
		fprintf(tc,"150  DeleGate Port(%s) Cached(%s)\r\n",
			port,cdate);

		fflush(tc);
		wordScan(com,ClientAuth.i_meth);
		if( modeXDC ){
			CStr(resp,256);
			xc = XDCrelayServ(FS,0,NULL,NULL,tc,NULL,
				fddup(fileno(cfp)),port,NULL,AVStr(resp),sizeof(resp));
		}else{
			int xf = FS->fs_dataConn.xf_filters & XF_SERVER;
			/* 8.10.4 xf_filters is cleared in FTP_data_relay()
			 * ignoring FSV filter which is kept alive in
			 * this case (relaying from cache rather than server)
			 */

			xc = FTP_data_relay(Conn,FS,fileno(cfp),cdsock,NULL,0);
			close(cdsock);
			FS->fs_dataConn.xf_filters = xf;
		}

		putXcomplete(Conn,FS,tc,xc);
		fflush(tc);

		if( viaICP )
			FS->fs_cstat = "i";
		else
		if( islocal )
			FS->fs_cstat = "L";
		else	FS->fs_cstat = "H";
		putXferlog(Conn,FS,com,arg,start,xc,"");
		found = 1;
		sv1log("FTP-CACHE HIT: [%d] %s\n",fileno(cfp),cpath);
	}else	FS->fs_cstat = "N";
		

	fclose(cfp);
	return found;
}

/*
 *	setup data connection to the server
 */
static void setWithPASV(FtpStat *FS)
{
	if( FS->fs_serverWithPASV == 0 ){
		if( 0 <= FS->fs_psvsock ){
			FS->fs_serverWithPASV = 1;
			sv1log("-- with PASV\n");
		}else{
			FS->fs_serverWithPASV = -1;
			sv1log("-- without PASV\n");
		}
	}
}
static const char *IFUPM = "InheritingFromUnboundProxyMode";
int bound_ftp_data(DGC *Conn,int cntrlsock,int datasock,int epsv,PVStr(mport));
static int setupPASV(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,FILE *tc,PCStr(arg))
{	CStr(resp,2048);
	const char *pasvcase;
	MrefQStr(mport,FS->fs_mport); /**/
	CStr(dbg,64);

	pasvcase = 0;
	if( fs != NULL )
	if( FCF.fc_nodata ){
		put_get(ts,fs,AVStr(resp),sizeof(resp),"PASV\r\n");
		goto EXIT;
	}
	if( FCF.fc_doepsvCL && strcaseeq(FS->fs_curcom,"EPSV") ){
	}else
	if( FCF.fc_nopasvCL ){
		sprintf(resp,"500 PASV is disabled.\r\n");
		goto EXIT;
	}
	if( FCF.fc_noepsvCL && strcaseeq(FS->fs_curcom,"EPSV") ){
		sprintf(resp,"500 EPSV is disabled.\r\n");
		goto EXIT;
	}

	/* cannot accept multiple times via SOCKS */
	if( tc != NULL )
	if( 0 <= FS->fs_pclsock )
	if( 1 < peerPort(FS->fs_pclsock) ) /* it is connected */
	if( 0 < PollIn(FS->fs_pclsock,1) ) /* ready to accept */
	{
		sv1log("## discard previous (unused) PASV sock via SOCKS: %d\n",
			FS->fs_pclsock);
		close(FS->fs_pclsock);
		FS->fs_pclsock = -1;
	}

	if( FS->fs_pclsock < 0 ){
		if( Conn->xf_filters & XF_CLIENT )
		if( ToC != ClientSock )
		sv1log("## viaCFI: ToC=%d ClientSock=%d\n",ToC,ClientSock);

		FS->fs_pclsock =
		make_ftp_data(Conn,AVStr(mport),FS->fs_myaddr,FS->fs_myport,ClientSock,1,1);
/*
		make_ftp_data(Conn,AVStr(mport),FS->fs_myhost,FS->fs_myport,ClientSock,1,1);
*/
	}else
	if( tc == NULL )
	{
		;/* inheriting from unbound mode proxy */
		/*
		mport = "InheritingFromUnboundProxyMode";
		*/
		mport = (char*)IFUPM; /* don't leave it in mport[] by strcpy() */
	}
	else
	if( lPASV_REUSE() && (0 <= FS->fs_pclsock || 0 <= FS->fs_psvsock) ){
		/* -Efp: fixed port number safe, for port number reusing
		 *  (not for socket reusing)
		 * -Efp will be the default in 10.X
		 */
		int pcs = FS->fs_pclsock;
		int clrdy = 0;
		int svrdy = 0;
		if( 0 <= FS->fs_pclsock )
		if( (clrdy = inputReady(pcs,NULL)) != 0 ){
			/* 9.9.5 don't reuse the PASV socket with backlog.
			 * the client might try re-connect from the same
			 * src-port to the same dst-port to cause freezing.
			 * Also discard the backlog without accept(), not to
			 * let them stay as a zombi connections?
			 * ...remaining previous PASV not accepted...
			/* accept() may cause blocking ther port number */
			close(FS->fs_pclsock);
			FS->fs_pclsock = make_ftp_data(Conn,AVStr(mport),
				FS->fs_myaddr,FS->fs_myport,ClientSock,1,1);
			sv1log("-Efp ## DISCARD PASV to CL\n");
		}else{
		}
		if( 0 <= FS->fs_psvsock )
		if( (svrdy = PollIn(FS->fs_psvsock,100)) != 0 ){
			Connection *Conn = &FS->fs_dataConn;
			sv1log("-Efp ## DISCARD PASV to SV: %X %X [%d][%d]\n",
				ServerFlags,Conn->xf_filters,ToS,FS->fs_psvsock);
			closed("FTP-PASV",FS->fs_psvsock,-1);
			close(FS->fs_psvsock);
			FS->fs_psvsock = -1;
			if( Conn->xf_filters & XF_FSV ){
				Conn->xf_filters &= ~XF_FSV;
			}
			if( ServerFlags & PF_STLS_ON ){
				ServerFlags &= ~PF_STLS_ON;
			}
		}else{
			/* the PASV connection seems still valid in
			 * the server and reusable.
			 * retrying the connection establishment with
			 * the same src-dst pair will cause freezing.
			 */
		}
		sv1log("-Efp ## PASV %s[%d][%d]%d {%s}[%d]%d\n",
			FS->fs_mport,FS->fs_pclsock,pcs,clrdy,
			FS->fs_dataError,FS->fs_psvsock,svrdy
		);
		FS->fs_dataError[0] = 0;
	}else
	while( 0 < PollIn(FS->fs_pclsock,1) ){
		int psock;
		if( (psock = ACCEPT(FS->fs_pclsock,0,-1,1)) < 0 )
			break;
		sv1log("## discard previous (unused) PASV sock: %d -> %d\n",
			FS->fs_pclsock,psock);
		close(psock);

		/* detected a connection to a PASV port to be reused before
		 * returning new response to PASV.  It must be a connection
		 * for previous unused PASV, which is not used because of
		 * error on a retreval command like unknown file.
		 */
		if( FS->fs_dataError[0] ){
			if( 0 <= FS->fs_psvsock ){
		sv1log("## discard previous PASV sock to serv[%s] %d\n",
			FS->fs_dataError,FS->fs_psvsock);
				close(FS->fs_psvsock);
				FS->fs_psvsock = -1;
			}
			if( 0 <= FS->fs_dsvsock ){
			/* should try discard PORT connection with server ? */
		sv1log("## discard previous PORT sock to serv[%s] %d %d\n",
			FS->fs_dataError,FS->fs_dsvsock,PollIn(FS->fs_dsvsock,1));
			}
			FS->fs_dataError[0] = 0;
			if( FS->fs_dataConn.xf_filters & XF_FSV ){
				Connection *Conn = &FS->fs_dataConn;
				/* 8.10.4 enable re-insertion of FSV */
				Conn->xf_filters &= ~XF_FSV;
				if( 0 <= ToS ){
					close(ToS);
					ToS = -1;
				}
			}
		}
	}
	if( mport == IFUPM ){
		/* with tc==NULL, no port info. need to be generated nor set */
		sv1log("--PASV [%s] %s %s\n",FS->fs_curcom,FS->fs_mport,mport);
	}else
	if( 0 <= FS->fs_pclsock ){
		int epsvnow = strcaseeq(FS->fs_curcom,"EPSV");
		int portnow = strcaseeq(FS->fs_curcom,"PORT");
		int wasepsv = mport[0] == '|';
		int wasport = mport[0] != 0 && mport[0] != '|';

		if( epsvnow && wasepsv || portnow && wasport ){
			/* reuse it */
		}else
		if( 0 <= bound_ftp_data(Conn,ClientSock,FS->fs_pclsock,epsvnow,
			AVStr(mport))
		){
			sv1log("## [%s] restored (%s)\n",FS->fs_curcom,mport);
		}else
		/* 9.8.2 the followings are replaced with bound_ftp_data() */
		if( strcaseeq(FS->fs_curcom,"EPSV") && mport[0] != '|' ){
			VSAddr addr;
			int port;
			VSA_ftptosa(&addr,mport);
			port = VSA_port(&addr);
			/* it might be bound via SOCKS, so use the mport  */
			if( 0 < port ){
				sprintf(mport,"|||%d|",port);
			}else
			sprintf(mport,"|||%d|",sockPort(FS->fs_pclsock));
		}else
		if( strcaseeq(FS->fs_curcom,"PASV") && mport[0] == '|' ){
			sv1log("## BAD PASV (%s)\n",mport);
		}
		else
		if( mport[0] == 0 ){
			/* this can be happen when change_server() is done
			 * by PATHCOM, preceded PASV, and the PASV is not
			 * used because of login error.
			 */
			VSAddr sa;
			int salen = sizeof(sa);
			getsockname(FS->fs_pclsock,(SAP)&sa,&salen);
			VSA_prftp(&sa,AVStr(mport));
			sv1log("## %s restored [%s]\n",FS->fs_curcom,mport);
		}
	}

	pasvcase = 0;
	if( FS->fs_pclsock < 0 ){
		sprintf(resp,"500 Can't create Passive Mode socket.\r\n");
	}else
	if( ts == NULL ){
		pasvcase = "X";
	}else
	if( 0 <= FS->fs_psvsock || 0 <= FS->fs_dsvsock ){
		pasvcase = "A";
	}else
	if( FS->fs_XDCforSV ){
		put_get(ts,fs,AVStr(resp),sizeof(resp),"PORT %s\r\n",XDC_PASV_PORT);
		pasvcase = "XDC";
	}else
	if( 0 <= FS->fs_serverWithPASV
	 && 0 <= (FS->fs_psvsock = connectPASV(Conn,FS,ts,fs,AVStr(resp),sizeof(resp))) ){
		setWithPASV(FS);
		pasvcase = "B";
	}else
	if( 0 <= (FS->fs_dsvsock = mkdsockPORT(Conn,DFLT_HOST,ts,fs)) ){
		FS->fs_PORTforPASV = 1;
		pasvcase = "C";
	}else{
		sprintf(resp,"500 PASV failed.\r\n");
	}
	if( pasvcase != NULL ){
		if( FCF.fc_pasvdebug )
			sprintf(dbg," DeleGate[%s]",pasvcase);
		else	dbg[0] = 0;
		if( strchr(mport,'|') != 0 ){
		sprintf(resp,"229 Entering Extended Passive Mode (%s)\r\n",
			mport);
		}else
		sprintf(resp,"227 Entering Passive Mode (%s)%s.\r\n",
			mport,dbg);
	}

EXIT:
	if( tc != NULL ){
		fputs(resp,tc);
		fflush(tc);
	}
	if( FCF.fc_pasvdebug == 0 && pasvcase )
		sv1log("PASV [%s][%s] >> %s",pasvcase,mport,resp);
	else
	sv1log("PASV [%s] >> %s",mport,resp);
	if( atoi(resp) == 227 )
		return 0;
	if( atoi(resp) == 229 )
		return 0;
	else	return EOF;
}
static int setupPORTi(Connection *Conn,FtpStat *FS,FILE *tc,PVStr(resp)){
	int dsock;
	CStr(port,128);

	if( FS->fs_dport[0] == 0 )
		return 0;
	if( streq(FS->fs_dport,XDC_PASV_PORT) )
		return 0;

	strcpy(port,FS->fs_dport);
	dsock = connect_data("FTP-LOCAL",FS,AVStr(FS->fs_dport),ClientSock);
	sv1log("#### DBG IMMPORT %d [%s] L=%d\n",dsock,port,FS->fs_islocal);
	truncVStr(FS->fs_dport);
	if( 0 <= dsock ){
		sprintf(resp,"200 PORT command successful.\r\n");
		FS->fs_dclsock = dsock;
		return 1;
	}else{
		sprintf(resp,"501 cannot connect your PORT.\r\n");
		FS->fs_dclsock = -1;
		return -1;
	}
}

int rejectMethod(Connection*,PCStr(p),PCStr(m),PCStr(dh),int dp,PCStr(sh),int sp);
int VSA_rejectMethod(Connection *Conn,PCStr(method),PCStr(proto),VSAddr *port){
	int rej;
	Connection XConn;

	XConn = *Conn;
	set_realserver(&XConn,proto,VSA_ntoa(port),VSA_port(port));
	CTX_pushClientInfo(Conn);
	rej = rejectMethod(&XConn,proto,method,
		VSA_ntoa(port),VSA_port(port),Client_Host,Client_Port);
	HL_popClientInfo();
	return rej;
}
int getsockVSAddr(int sock,VSAddr *vsa);
int getpeerVSAddr(int sock,VSAddr *vsa);
/*
 * FTP bounce control
 * http://www.cert.org/advisories/CA-1997-27.html
 */
static int checkPORTdst(Connection *Conn,FtpStat *FS,PVStr(parg),PVStr(resp)){
	VSAddr peer;
	VSAddr sock;
	VSAddr zero;
	VSAddr port;
	IStr(speer,128);
	IStr(ssock,128);
	IStr(szero,128);
	IStr(sport,128);
	Connection dataConn;

	if( FCF.fc_bounce & FB_TH ){
		return 0;
	}
	getpeerVSAddr(ClientSock,&peer);
	getsockVSAddr(ClientSock,&sock);
	VSA_ftptosa(&zero,"255,255,255,255,0,0");
	VSA_ftptosa(&port,"255,255,255,255,0,0");
	VSA_ftptosa(&port,parg);

	if( VSA_rejectMethod(Conn,FS->fs_curcom,"ftp-data",&port) ){
		sprintf(resp,"500 forbidden.\r\n");
		return -1;
	}

	sprintf(speer,"%s:%d",VSA_ntoa(&peer),VSA_port(&peer));
	sprintf(ssock,"%s:%d",VSA_ntoa(&sock),VSA_port(&sock));
	sprintf(sport,"%s:%d",VSA_ntoa(&port),VSA_port(&port));
	Verbose("--port {%s %s}{%s} <= {%s}{%s}[%d]\n",
		FS->fs_curcom,parg,sport,speer,ssock,ClientSock);

	if( VSA_port(&port) == 0 ){
		if( FS->fs_XDCforCL ){
			return 0;
		}
		sprintf(resp,"500 invalid address/port\r\n");
		return -2;
	}
	if( VSA_addrcomp(&port,&zero) == 0 && parg[0] == '|' ){
		return 0; /* empty address, EPSV |||xxxx|  */
	}
	if( VSA_addrcomp(&port,&peer) == 0 ){
		return 0; /* matched with client's address */
	}
	/* should check ORIGINAL_SRC ? */
	sv1log("--PORT {%s %s}{%s} <= {%s}\n",FS->fs_curcom,parg,sport,speer);
	if( FCF.fc_bounce & FB_CB ){
		sprintf(parg,"|||%d|",VSA_port(&port));
		return 0;
	}
	if( FCF.fc_bounce & FB_DO ){
		return 0;
	}
	if( (FCF.fc_bounce & FB_RL) == 0 ){
		/* the reason of the unmatch can be because
		 * the client is behind NAT
		sprintf(resp,"500 forbidden address\r\n");
		 */
		sprintf(resp,"500 forbidden PORT address (try PASV instead)\r\n");
		FS->fs_dport[0] = 0; /* fix-140506d not to try the PORT */
		return -3;
	}
	if( VSA_rejectMethod(Conn,FS->fs_curcom,"ftp-bounce",&port) ){
		/*
		sprintf(resp,"500 forbidden address\r\n");
		*/
		sprintf(resp,"500 forbidden PORT address (try PASV instead)\r\n");
		FS->fs_dport[0] = 0; /* fix-140506d not to try the PORT */
		return -4;
	}
	return 0;
}
static int setupPORT(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,FILE *tc,PCStr(arg))
{	CStr(resp,2048);
	VSAddr vaddr;

	wordScan(arg,FS->fs_dport);

	if( FCF.fc_noportCL ){
		sprintf(resp,"500 PORT is disabled.\r\n");
	}else
	if( checkPORTdst(Conn,FS,AVStr(FS->fs_dport),AVStr(resp)) != 0 ){
		/* 9.9.8 forbidden PORT/EPRT address */
	}else
	if( ts == NULL ){
		if( FCF.fc_immportCL && setupPORTi(Conn,FS,tc,AVStr(resp)) ){
			sv1log("#### %s",resp);
		}else{
	/* THIS MUST BE CHECKED FIRST not to do put_serv(NULL) */
		sv1log("#### 200 PORT command successful [delaying].\r\n");
		sprintf(resp,"200 PORT command successful [delaying].\r\n");
		}
	}else
	if( FCF.fc_nodata ){
		put_get(ts,fs,AVStr(resp),sizeof(resp),"PORT %s\r\n",arg);
	}else
	if( getenv("THRUPORT")
	 && 0 <= (FS->fs_dsvsock = mkdsockPORT(Conn,DFLT_HOST,ts,NULL)) ){
		get_resp(fs,NULL,AVStr(resp),sizeof(resp));
		if( 0 <= FS->fs_psvsock ){
			close(FS->fs_psvsock);
			FS->fs_psvsock = -1;
		}
	}else
	if( FS->fs_XDCforSV ){
		put_serv(MODE(FS),ts,"PORT %s\r\n",arg);
		get_resp(fs,NULL,AVStr(resp),sizeof(resp));
	}else
	if( 0 <= FS->fs_psvsock || 0 <= FS->fs_dsvsock ){
		sv1log("#### DSV[%d] PSV[%d]\n",FS->fs_dsvsock,FS->fs_psvsock);
		sprintf(resp,"200 PORT command successful [reusing].\r\n");
	}else
	if( 0 <= FS->fs_serverWithPASV
	 && 0 <= (FS->fs_psvsock = connectPASV(Conn,FS,ts,fs,AVStr(resp),sizeof(resp))) ){
		setWithPASV(FS);
		FS->fs_PASVforPORT = 1;
		sprintf(resp,"200 PORT command successful [%s].\r\n",
			"translated to PASV by DeleGate");
	}else
	if( 0 <= (FS->fs_dsvsock = mkdsockPORT(Conn,DFLT_HOST,ts,NULL)) ){
		get_resp(fs,NULL,AVStr(resp),sizeof(resp));
		/*
		if( atoi(resp) == 200 ){
			sprintf(resp,"200 PORT command successful [new].\r\n");
		}
		*/
	}else{
		sprintf(resp,"500 PORT failed.\r\n");
	}
	if( tc != NULL ){
		fputs(resp,tc);
		fflush(tc);
	}
	sv1log("PORT [%s] >> %s",FS->fs_dport,resp);
	if( atoi(resp) == 200 )
		return 0;
	else	return EOF;
}

extern int DELAY_REJECT_P;

void FTP_delayReject(Connection *Conn,int chgsv,PCStr(req),PCStr(stat),int self,PCStr(user),PCStr(pass))
{	CStr(method,128);
	CStr(shost,MaxHostNameLen);
	int sport;

	sport = getClientHostPort(Conn,AVStr(shost));
	if( !is_anonymous(user) && *pass != 0 )
		pass = "****";
	addRejectList(Conn,req,"","",user,pass,stat);
	sv1log("## FTP_delayReject.%d %s [%s][%s]\n",chgsv,req,user,pass);

	if( DELAY_REJECT_P == 0 )
		DELAY_REJECT_P = FTP_DELAY_REJECT_P;
	delayRejectX(Conn,self,"ftp",shost,sport,FromC);
}

static int gatewayLogin(Connection *Conn,FtpStat *FS,FtpConn *pFC,FILE *ts,FILE *fs){
	CStr(resp,1024);
	if( streq(GatewayProto,"ftp") && GatewayUser[0] ){
		_put_get(MODE(FS),ts,fs,AVStr(resp),sizeof(resp),
			"USER %s\r\n",GatewayUser);
		_put_get(MODE(FS),ts,fs,AVStr(resp),sizeof(resp),
			"PASS %s\r\n",GatewayPass);
		return 0;
	}
	return -1;
}
static int proxyLogin(Connection *Conn,FtpStat *FS,FtpConn *pFC,PCStr(xuser),PVStr(resp),int rsize,FILE *ts,FILE *fs)
{	refQStr(RESP,resp); /**/
	int rcode;
	CStr(user,128);

	Verbose("proxyLogin(%s,%s,%s,%s)\n",
		pFC->fc_user,pFC->fc_pass,pFC->fc_Path,pFC->fc_type);

	rcode = 0;

	user[0] = 0;
	wordScan(pFC->fc_acct,FS->fs_acct);

	if(pFC->fc_user[0]){
		rsize -= strlen(RESP);
		SSEEK(RESP);
		if( xuser[0] == 0 )
			xuser = pFC->fc_user;

		/*
		if( strpbrk(xuser,"~/") ){
			scan_namebody(xuser,AVStr(user),sizeof(user),"~/",
		8.6.0 "/" used for test, but not documented in the Manual.htm
		9.4.4 "/" could be a part of username (8.0.3)
		*/
		if( strpbrk(xuser,"~") ){
			scan_namebody(xuser,AVStr(user),sizeof(user),"~",
				AVStr(FS->fs_acct),sizeof(FS->fs_acct),"");
			sv1log("##ACCT got[%s] USER[%s]\n",FS->fs_acct,xuser);
			xuser = user;
		}

		_put_get(MODE(FS),ts,fs,AVStr(RESP),rsize,
			"USER %s\r\n",xuser);
		rcode = atoi(RESP);
		if( atoi(RESP) == 530 )
			FTP_delayReject(Conn,1,"USER",RESP,0,pFC->fc_user,pFC->fc_pass);
		if( *RESP == '5' || *RESP == '4' )
			goto xERROR;
		strcpy(FS->fs_USER,pFC->fc_user);
		FS->fs_anonymous = is_anonymous(FS->fs_USER);
		FS->fs_rcUSER = stralloc(RESP);
	}
	if( rcode == 230 ){
	}else
	if(pFC->fc_pass[0]){
		rsize -= strlen(RESP);
		SSEEK(RESP);
		if( FS->fs_anonymous && anonPASS(Conn,NULL,pFC->fc_user,AVStr(pFC->fc_pass))!=0 )
			Xsprintf(QVStr(RESP,resp),"530 Invalid/Forbidden <%s>\r\n",pFC->fc_pass);
		else
		{
		_put_get(MODE(FS),ts,fs,AVStr(RESP),rsize,
			"PASS %s\r\n",pFC->fc_pass);

			if( atoi(RESP) == 332 )
			if( FS->fs_acct[0] != 0 ){
				sv1log("##ACCT put[%s]\n",FS->fs_acct);
				_put_get(MODE(FS),ts,fs,AVStr(RESP),rsize,
					"ACCT %s\r\n",FS->fs_acct);
			}
		}

		if( atoi(RESP) == 530 )
			FTP_delayReject(Conn,1,"PASS",RESP,0,pFC->fc_user,pFC->fc_pass);
		if( *RESP == '5' || *RESP == '4' )
			goto xERROR;
		strcpy(FS->fs_PASS,pFC->fc_pass);
		FS->fs_rcPASS = stralloc(RESP);
	}
	else
	if( rcode == 331 ){
		/*
		if( strcmp(PFC->fc_swcom,"USER") != 0 ){
		*/
		if( !strcaseeq(PFC->fc_swcom,"USER") ){
		/* not USER thus no chance to give password from client */
		sv1log("Required password for '%s' not given.\n",pFC->fc_user);
		return -1;
		}
	}

	if(pFC->fc_type[0]){
		rsize -= strlen(RESP);
		SSEEK(RESP);
		_put_get(MODE(FS),ts,fs,AVStr(RESP),rsize,
			"TYPE %s\r\n",pFC->fc_type);
		if( *RESP == '5' || *RESP == '4' )
			goto xERROR;
		strcpy(FS->fs_TYPE,pFC->fc_type);
	}

if(pFC->fc_pass[0])
if( strstr(resp,"\n332") == 0 )
	setLoginPWD(FS,ts,fs);
	return 0;
xERROR:
	return -1;
}

static void setConnTimeout(Connection *Conn)
{	int timeout;

	if( ConnDelay == 0 )
		return;

	timeout = (int)(1 + (ConnDelay * 10));
	if( timeout < CON_TIMEOUT ){
/*
daemonlog("D","Estimated FTP data connetion timeout = (1+10*%4.2f) %d < %d\n",
			ConnDelay,timeout,CON_TIMEOUT);
*/
		CON_TIMEOUT_DATA = timeout;
	}else	CON_TIMEOUT_DATA = CON_TIMEOUT;
}

static int isMounted(FtpStat *FS)
{	CStr(vpath,1024);

	return getVUpath(FS,FS->fs_CWD,AVStr(vpath)) != NULL;
}
static int presetLogin(FtpStat *FS,AuthInfo *ident,PVStr(path))
{	CStr(vurl,1024);

	if( getVUpath(FS,FS->fs_CWD,AVStr(vurl)) )
		return CTX_preset_loginX(FS->fs_Conn,"GET",AVStr(vurl),ident,AVStr(path));
	else	return 0;
}
static int dontREINitialize(FtpStat *FS)
{
	if( presetLogin(FS,NULL,VStrNULL) )
		return 1;
	return 0;
}

int service_ftp1(Connection *Conn,FtpStat *FS,int mounted);
int service_ftp(Connection *Conn)
{	FtpStat FSbuf,*FS = &FSbuf;
	int mounted;

	static FtpConf *fcf = 0;
	int rcode;
	if( fcf == 0 ){
		fcf = (FtpConf*)malloc(sizeof(FtpConf));
		*fcf = FCF; /* save the common config. */
	}else{
		FCF = *fcf; /* restore the common config. */
	}
	setupFCF(Conn);

	PageCountUpURL(Conn,CNT_TOTALINC,"#sessions",NULL);
	/*
	if( FCF.fc_init == 0 )
		scan_REJECT(Conn,"ftp//EPSV");
	*/
	init_conf();
	init_FS(FS,Conn);
	mounted = Mounted();
	/*
	return service_ftp1(Conn,FS,mounted);
	*/

	FtpTLSX->ctx_id = Conn->cx_magic;
	rcode = service_ftp1(Conn,FS,mounted);
	FtpTLSX->ctx_id = 0;
	FCF = *fcf; /* restore the common config. */
	return rcode;
}
int service_ftps(Connection *Conn){
	/*
	int rcode;
	ServerFlags |= (PF_SSL_IMPLICIT | PF_STLS_DO);
	rcode = service_ftp(Conn);
	ServerFlags &= ~(PF_SSL_IMPLICIT | PF_STLS_DO);
	return rcode;
	*/
	return service_ftp(Conn);
}
void chdirHOME(FtpStat *FS,FILE *ts,FILE *fs,PVStr(resp),int rsize)
{
	put_get(ts,fs,AVStr(resp),rsize,"CWD %s\r\n",FS->fs_logindir);
	FS->fs_CWD[0] = 0;
	/* fs_CWD is a relative path in the target server... */
}
static int restoreCWD(FtpConn *pFC,FtpStat *FS)
{	FtpStat *caller;
	CStr(prevurl,1024);
	const char *opts;
	CStr(curserv,1024);
	Connection *Conn = FS->fs_Conn;

	caller = pFC->fc_callersFS;
	strcpy(prevurl,caller->fs_prevVWD);
	opts = CTX_mount_url_to(caller->fs_Conn,NULL,"GET",AVStr(prevurl));

	if( opts == 0 ){
		sv1log("restoreCWD(1) -- NO ROOT MOUNT[%s](%s)\n",
			FS->fs_CWD,prevurl);
		FS->fs_islocal = 1;
		return 1;
	}

	if( strncmp(prevurl,"file://localhost/",17) == 0 ){
		/*
		FS->fs_islocal = 1;
		*/
		FS->fs_islocal = IS_PXLOCAL;
		strcpy(FS->fs_CWD,prevurl+16);
		sv1log("restoreCWD(2) -- ROOT MOUNT IS LOCAL[%s](%s)\n",
			FS->fs_CWD,prevurl);
		return 1;
	}

	if( streq(prevurl,"ftp://") ){ /* MOUNT="/* ftp://*" */
		sv1log("restoreCWD(4) -- NO ROOT MOUNT[%s](%s)\n",
			FS->fs_CWD,prevurl);
		return 1;
	}

	if( FS->fs_USER[0] && strchr(prevurl,'@') == 0 ){
		if( strncmp(prevurl,"ftp://",6) == 0 ){
			Strins(QVStr(prevurl+6,prevurl),"@");
			Strins(QVStr(prevurl+6,prevurl),FS->fs_USER);
		}
	}
	strcpy(curserv,"ftp://");
	if( !is_anonymous(FS->fs_USER) || strchr(prevurl,'@') != 0 ){
		if( FS->fs_USER[0] == 0 ){
			CStr(user,64);
			get_dfltuser(AVStr(user),sizeof(user));
			Xsprintf(TVStr(curserv),"%s@",user);
		}else	Xsprintf(TVStr(curserv),"%s@",FS->fs_USER);
	}
	HostPort(TVStr(curserv),DST_PROTO,DST_HOST,DST_PORT);

	if( strstr(prevurl,curserv) == prevurl ){
		sv1log("restoreCWD(3) -- TO SAME HOST[%s](%s)[%s]\n",
			FS->fs_CWD,prevurl,caller->fs_CWD);
		return 1;
	}

	return 0;
}

static int ftp_beBoundProxy(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,PCStr(cuser),int mounted);
int connect_to_servX(Connection *Conn, int fromC,int toC, int relay_input, int do_filter);

/* 9.9.2 */
static FILE *pushfp(FILE *tc,FILE **tcsav){
	FILE *ntc;
	*tcsav = tc;
	ntc = TMPFILE("PushFp");
	if( ntc == NULL ){
		return tc;
	}
	return ntc;
}
static FILE *popfp(FILE *tc,FILE **tcsav){
	int cc;

	if( *tcsav == 0 || *tcsav == tc ){
		return tc;
	}
	fflush(tc);
	fseek(tc,0,0);
	cc = copyfile1(tc,*tcsav);
	sv1log("# popfp cc=%d\n",cc);
	fclose(tc);
	tc = *tcsav;
	return tc;
}

int service_ftp1(Connection *Conn,FtpStat *FS,int mounted)
{	FILE *tc,*fc,*ts,*fs;
	CStr(req,1024);
	CStr(com,1024);
	CStr(arg,1024);
	const char *dp;
	CStr(resp,0x8000);
	const char *swcom;
	int rcode,scode;
	CStr(cserv,1024);
	CStr(ctype,32);
	CStr(cuser,128);
	CStr(cpass,128);
	AuthInfo ident;
	CStr(cpath,1024);
	int nUSER = 0,nPASS = 0;
	CStr(sav_cwd,1024);
	CStr(sav_pwd,1024);
	int sav_islocal;
	CStr(xuser,128);
	CStr(xserv,128);
	void (*sigpipe)(int);
	int server_eof = 0;
	ACStr(reqQs,16,256);
	int reqQn = 0, reqQi;
	int noSTOR;
	int enable_mount;
	int login_done = 0;
	int nosvsw;
	int sftp = 0;

	sv1log("FTP server ftp://%s:%d/%s\n",DFLT_HOST,DFLT_PORT,D_SELECTOR);
	if( isMYSELF(DFLT_HOST) ){
		proxyFTP(Conn);
		return -1;
	}

	/*
	 * must do change_server() with presetLogin() before doing
	 * connect_to_serv()
	 */
	/* this is necessary for presetLogin() */{
		strcpy(FS->fs_host,DST_HOST);
		FS->fs_port = DST_PORT;
	}
	if( PFC == NULL && presetLogin(FS,&ident,AVStr(cpath)) ){
		sprintf(cserv,"%s:%d/%s",DST_HOST,DST_PORT,cpath);
		tc = fdopen(ToC,"w");
		fc = fdopen(FromC,"r");
		return change_server(Conn,FS,fc,tc,"OPEN",cserv,ident.i_user,ident.i_pass,"");
	}

	/* PFS is necessary to inherit established PASV/PORT environment
	 * to a switched (MOUNTed) server ...
	 */
	if( PFS == NULL )
		PFS = FS;

	D_FTPHOPS++;
	sv1log("FTPHOPS: %d [%d/%d - %d/%d]%s\n",D_FTPHOPS,ToC,FromC,ToS,FromS,
		FS->fs_IAMCC?"FTPCC":"");

	if( FS->fs_IAMCC ){
		/* can be ToS == FromS == 0 on FTPCC/TUNNEL ... */
	}else
	if( ToS <= 0 || FromS <= 0 )
	{
		if( strcaseeq(REAL_PROTO,"sftp") ){
			const char *user;
			int fromC = -1;
			if( PFC && PFC->fc_user[0] )
				user = PFC->fc_user;
			else	user = "anonymous";
			if( PFC ){
				/* to close fddup(FromC) (in proxyFTP()) */
				fromC = fileno(PFC->fc_fc);
			}
			/*
			connectToSftpX(Conn,DST_HOST,DST_PORT,user,ToC);
			*/
			connectToSftpXX(Conn,DST_HOST,DST_PORT,user,ToC,fromC);
			sv1log("-SFTPGW:connect_serv REAL_PROTO=sftp ->FS\n");
			strcpy(FS->fs_proto,"sftp");
			sftp = 1;
		}else
		/*
		connect_to_serv(Conn,FromC,ToC,0);
		*/
		{	int toSX;
			ToSX = -1;
			ServerFlags &= PF_SSL_IMPLICIT;
			connect_to_servX(Conn,FromC,ToC,0,0);
			toSX = ToSX;
			insert_FSERVER(Conn,FromC);
			if( ServerFlags & PF_SSL_ON ){
				/* ToSX is cleared in insert_FSERVER() */
				ToSX = toSX;
			}
		}
	}
	setConnTimeout(Conn);
	if( PFC ){
		if( ClientFlags & PF_AS_PROXY ){
			sv1log("inherited AsProxy: %X\n",ClientFlags);
		}
		if( FS->fs_timeout == 0 && PFC->fc_callersFS ){
			FS->fs_timeout = PFC->fc_callersFS->fs_timeout;
		}
	}

	if( ToS < 0 || FromS < 0 ){
		if( PFC )
			scode = PFC->fc_ERRcode;
		else	scode = 421;
		sprintf(resp,"%d ;-< Proxy failed to connect with `%s'\r\n",
			scode,DST_HOST);
		IGNRETP write(ToC,resp,strlen(resp));
		sv1log("cannot connect `%s'\n",DST_HOST);
		return -1;
	}

	if( toMaster && D_FTPHOPS != 1 ){
		/* and if in MODE XDC, then no extra data connection ...*/
		/*if( sockFromMyself(ToS) )*/
		{
			sv1log("FTP simple relay.\n");
			relay_svcl(Conn,FromC,ToC,FromS,ToS /*,1,512*/);
			return -1;
		}
	}

	strcpy(FS->fs_host,DST_HOST);
	FS->fs_port = DST_PORT;

	if( PFC ){
		tc = PFC->fc_tc;
		fc = PFC->fc_fc;
	}else{
		tc = fdopen(ToC,"w");
		fc = fdopen(FromC,"r");
	}
	if( tc == NULL || fc == NULL ){
		sv1log("#### cannot fopen tc=%X/%d fc=%X/%d\n",p2i(tc),ToC,p2i(fc),FromC);
		return -1;
	}
/*
	if( PFC == NULL && presetLogin(FS,&ident,cpath) ){
		sprintf(cserv,"%s:%d/%s",DST_HOST,DST_PORT,cpath);
		return change_server(Conn,FS,fc,tc,"OPEN",cserv,ident.i_user,ident.i_pass,"");
	}
*/

	if( FS->fs_IAMCC ){
		fs = FS->fs_fs;
		ts = FS->fs_ts;
	}else{
		fs = fdopen(FromS,"r");
		ts = fdopen(ToS,"w");
		FS->fs_ts = ts;
		FS->fs_fs = fs;
	}

	sigpipe = Vsignal(SIGPIPE,sigPIPE);
	ftp_env_name = "service_ftp";
	if( setjmp(ftp_env) != 0 ){
		sv1log("## service_ftp: error return from setjmp.\n");
		Vsignal(SIGPIPE,sigpipe);
		resetServer(Conn,FS,ts,fs);
		if( FS->fs_relaying_data ){
			FS->fs_relaying_data = 0;
			fprintf(tc,"451 data transfer aborted.\r\n");
			fflush(tc);
		}
		if( PFC != NULL ){
			fprintf(tc,"500 server disconnected (SIGPIPE).\n");
			fflush(tc);
		}
		goto SERVER_EOF;
	}

	if( ClientFlags & PF_AS_PROXY )
	if( ServerFlags & PF_STLS_DO ) /* with STLS=fsv */
	if( 0 <= STLS_fsvim_wait(0.0) ) /* not STLS=fsv,-im */
	if( (ServerFlags & PF_SSL_IMPLICIT) == 0 ) /* not STLS=fsv/im */
	if( (ServerFlags & PF_SSL_ON) == 0 ){
		/* 9.9.4 force STLS=fsv/im,im=10.0 */
		double waits = STLS_fsvim_wait(10.0);
		double St = Time();
		if( fPollIn(fs,(int)(waits*1000)) == 0 ){
			sv1log("## implicit SSL for FTPS? STLS=fsv,im=%.2f (%.2f)\n",
				waits,Time()-St);
			ServerFlags |=  PF_SSL_IMPLICIT | PF_STLS_SSL;
			FTP_STARTTLS_withSV(Conn,ts,fs);
		}
	}

	if( FS->fs_IAMCC ){
		strcpy(resp,FS->fs_opening);
		rcode = atoi(resp);
	}else{
		rcode = get_resp(fs,NULL,AVStr(resp),sizeof(resp));
		/* some server respond in local char-code with 8bits,
	 	   which breaks some client like Mosaic... */
		for( dp = resp; *dp; dp++  )
			if( *dp & 0x80 )
				*(char*)dp = ' ';

		FS->fs_opening = stralloc(resp);
	}

	scode = atoi(resp);
	if( scode == 421 )
		rcode = EOF;

	if( PFC ){
		if( scode == 220 )
			scode = PFC->fc_SUCcode;
		else	scode = PFC->fc_ERRcode;
	}
	if( rcode == EOF ){
		if( PFC )
			swcom = PFC->fc_swcom;
		else	swcom = "opening";
		sv1log("closed from the server [%s] %s",
			swcom,resp[0]?resp:"\n");
		fprintf(tc,"%d- %s for %s.\r\n",scode,swcom,DST_HOST);
		escape_scode(AVStr(resp),tc);
		fprintf(tc,"%d ;-< proxy connection to `%s' rejected.\r\n",
			scode,DST_HOST);
		goto SERVER_EOF;
	}

	if( FTP_STARTTLS_withSV(Conn,ts,fs) < 0 ){
		fprintf(tc,"421 failed starting TLS with the server\r\n");
		goto SERVER_EOF;
	}

	/* XDC usage with the server should be checked
	 * before relaying prefetched PASV/PORT to the server
	 */
	set_modeXDCtoSV(Conn,FS,ts,fs);

	FS->fs_myport = ClientIF_name(Conn,FromC,AVStr(FS->fs_myhost));
	ClientIF_addr(Conn,FromC,AVStr(FS->fs_myaddr));

	cserv[0] = cuser[0] = cpass[0] = ctype[0] = 0;

	xuser[0] = xserv[0] = 0;
	if( toProxy ){
		CStr(hostport,MaxHostNameLen);

		if( DST_PORT == serviceport("ftp") )
			strcpy(hostport,DST_HOST);
		else	sprintf(hostport,"%s:%d",DST_HOST,DST_PORT);

		if( PFC == 0 ){
			strcpy(xserv,hostport);
			sv1log("#### to FTP-Proxy THRU [%s]\n",xserv);
		}else{
			if( PFC->fc_user[0] )
				strcpy(xuser,PFC->fc_user);
			else	strcpy(xuser,"anonymous");
			if( (ServerFlags & PF_VIA_CONNECT) ){
				/* already connected with the server */
			}else{
			Xsprintf(TVStr(xuser),"@%s",hostport);
				if( gatewayLogin(Conn,FS,PFC,ts,fs) != 0 ){
				}
			}
			sv1log("#### to FTP-Proxy [%s]\n",xuser);
		}
	}
	if( PFC ){
		refQStr(RESP,resp); /**/
		const char *retrresp = NULL;
		int retrrespcode = 0;
		CStr(fc_path,1024);

		FS->fs_imProxy = 1;
		if( proxyLogin(Conn,FS,PFC,xuser,AVStr(resp),sizeof(resp),ts,fs) < 0 ){
			if( PFS ){
				PFC->fc_ERRcode = 530;

				/* just to be copied back in save_FS() ... */
				FS->fs_pclsock = PFS->fs_pclsock;
				strcpy(FS->fs_dport,PFS->fs_dport);
			}
			goto PROXY_ERROR;
		}
		if( strstr(resp,"\n332") != 0 )
			scode = 332;
		else
		if( PFC->fc_pass[0] )
			login_done = 1;

		if( PFS && 0 <= PFS->fs_pclsock ){
			FS->fs_pclsock = PFS->fs_pclsock;
			PFS->fs_pclsock = -1;
			wordScan(PFS->fs_mport,FS->fs_mport);
			PFS->fs_mport[0] = 0;
			if( setupPASV(Conn,FS,ts,fs,NULL,"") == EOF ){
				fprintf(tc,"500 PASV failed.\r\n");
				goto PROXY_ERROR;
			}
		}else
		if( PFS && PFS->fs_dport[0] ){
			/* after XDC is set by set_modeXDCtoSV() ... */
			if( setupPORT(Conn,FS,ts,fs,NULL,PFS->fs_dport)==EOF ){
				fprintf(tc,"500 PORT failed.\r\n");
				goto PROXY_ERROR;
			}
			PFS->fs_dport[0] = 0;
		}

		if( PFS ){
			FS->fs_XDCforCL = PFS->fs_XDCforCL;
			FS->fs_XDCencCL = PFS->fs_XDCencCL;
		}
		RESP = resp;
		if( PFS && PFS->fs_REST ){
			_put_get(MODE(FS),ts,fs,AVStr(RESP),sizeof(resp),"%s %lld\r\n",
				"REST",PFS->fs_REST);
			FS->fs_REST = PFS->fs_REST;
			PFS->fs_REST = 0;
		}

		if( MountOptions && isinList(MountOptions,"logindir") )
		if( !PATHCOMS(PFC->fc_swcom) /* PASS for login */
		 || PFC->fc_swarg[0] != '/'  /* CWD, LIST, RETR, ... */
		){	IStr(arg,128);

			/* 9.9.1 logindir: force to start at the logindir */
			FS->fs_onLoginDir = 1;
			if( strcaseeq(PFC->fc_swcom,"PASS") )
				strcpy(arg,"****");
			else	strcpy(arg,PFC->fc_swarg);
			sv1log("#onLoginDir(%s)(%s %s)\n",FS->fs_logindir,
				PFC->fc_swcom,arg);
			strcpy(FS->fs_CWD,FS->fs_logindir);
			strcpy(PFC->fc_Path,FS->fs_logindir);
			if( PATHCOMS(PFC->fc_swcom) ){
				chdir_cwd(AVStr(PFC->fc_Path),arg,1);
			}
		}

		if( !FCF.fc_nounesc )
			nonxalpha_unescape(PFC->fc_Path,AVStr(fc_path),1);
		else	strcpy(fc_path,PFC->fc_Path);
		RESP = resp + strlen(resp);
		if( PATHCOMS(PFC->fc_swcom) ){
			CStr(arg,1024);
			if( FS->fs_onLoginDir && DIRCOMS(PFC->fc_swcom) ){
				/* 9.9.1 msut stay on the login directory */
				if( streq(fc_path,FS->fs_logindir) 
				 || streq(fc_path,".") ){
				/* 9.9.1 FTP-serv/MacOSX does not accept it */
					strcpy(fc_path,"");
				}
			}else
			/* if MOUNTed onto non-{root,logindir} at the target */{
				CStr(uroot,512);
				CStr(site,512);
				CStr(root,512);
				CStr(oroot,512);
				AuthInfo ident;
				strcpy(uroot,"/");
				CTX_mount_url_to(Conn,NULL,"GET",AVStr(uroot));
				decomp_absurl(uroot,VStrNULL,AVStr(site),AVStr(root),sizeof(root));
				decomp_ftpsite(FS,AVStr(site),&ident);
				if( sameident(FS,&ident) )
				if( root[0] != 0 )
				if( strncmp(PFC->fc_Path,root,strlen(root))==0 ){
					wordScan(root,oroot);
					if( !FCF.fc_nounesc )
						nonxalpha_unescape(root,AVStr(root),1);
					_put_get(MODE(FS),ts,fs,AVStr(RESP),sizeof(resp),
						"CWD %s\r\n",root);
					chdir_cwd(AVStr(FS->fs_CWD),oroot,1);
					ovstrcpy(fc_path,fc_path+strlen(root));
				}
			}
			arg[0] = 0;
			if( PFC->fc_opts[0] ){
				strcpy(arg," ");
				strcat(arg,PFC->fc_opts);
			}
			if( fc_path[0] ){
				strcat(arg," ");
				strcat(arg,fc_path);
			}
			/* should lookup cache here for RETRCOMS ... */
			_put_get(MODE(FS),ts,fs,AVStr(RESP),sizeof(resp),"%s%s\r\n",
				PFC->fc_swcom,arg);
			/*
			if( *RESP == '5' || *RESP == '4' )
			if( RETRCOMS(PFC->fc_swcom) )
				goto PROXY_ERROR;
			*/
			if( *RESP == '5' || *RESP == '4' )
				scode = PFC->fc_ERRcode;
			retrresp = stralloc(RESP);
			retrrespcode = atoi(RESP);
		}else
		if( PFC->fc_Path[0] ){
			_put_get(MODE(FS),ts,fs,AVStr(RESP),sizeof(resp),
				"CWD %s\r\n",fc_path);
			if( *RESP == '5' || *RESP == '4' )
			{
				if( restoreCWD(PFC,FS) ){
					scode = PFC->fc_ERRcode;
				}else
				goto PROXY_ERROR;
			}else
			chdir_cwd(AVStr(FS->fs_CWD),PFC->fc_Path,1);
		}

		strcpy(cuser,PFC->fc_user);
		strcpy(cpass,PFC->fc_pass);
		strcpy(ctype,PFC->fc_type);
		
		arg[0] = 0;
		if( dp = strstr(resp,"\n331") )
			lineScan(dp+1,arg);
		else
		if( scode == 331 ){
			if( dp = strstr(resp,"\n230") )
			/*
			if( isspace(dp[4]) ){
			*/
			if( isspace(dp[4]) || dp[4] == '-' ){
				lineScan(dp+1,com);
				sv1log("no password required: %s\n",com);
				scode = 230;
			}
		}

		if( strcasestr(arg," otp-") != NULL ){
			fprintf(tc,"%s\r\n",arg);
		}else
		if( comeq(PFC->fc_swcom,"RETR")
		 || comeq(PFC->fc_swcom,"SIZE")
		 || comeq(PFC->fc_swcom,"MDTM")
		 || scode == 150 && retrrespcode == 150 && ftpDEBUG(0x10)
		){
			/* thru "150 Opening .... path (DDDD bytes)"
			 * MOUNTed path name should be rewriten ...
			 */
			fputs(retrresp,tc);
		}else
		if( comeq(PFC->fc_swcom,"MLST") ){
			putvnode(FS,"MLST",PFC->fc_Path,retrresp);
			relayMLST(FS,retrresp,tc);
		}else
		if( ftpDEBUG(0x40) ){
			if( retrrespcode == scode ){
				fputs(retrresp,tc);
			}else{
				fprintf(tc,"%d-\r\n",scode);
				escape_scode(AVStr(resp),tc);
				fprintf(tc,"%d \r\n",scode);
			}
		}else
		if( ftpDEBUG(0x80) ){
			fprintf(tc,"%d \r\n",scode);
		}else
		if( FCF.fc_hideserv ){
			fprintf(tc,"%d--  @ @ \r\n",scode);
			fprintf(tc,"%d  \\( x )/ -- { %s }\r\n",scode,
				"connected to a FTP server");
		}else
		if( scode == 150 && retrrespcode == 150 && ftpDEBUG(0x0F) ){
			if( ftpDEBUG(0x01) ){
				CStr(rresp,1024);
				strcpy(rresp,retrresp);
				escape_scode(AVStr(rresp),tc);
			}
			fprintf(tc,"%d-- %s for %s@%s.\r\n",scode,
				PFC->fc_swcom,PFC->fc_user,DST_HOST);
			if( ftpDEBUG(0x04) == 0 ){
				escape_scode(AVStr(resp),tc);
			}
			if( ftpDEBUG(0x08) == 0 ){
				fprintf(tc,"%d-   @ @  \r\n",scode);
				fprintf(tc,"%d- \\( - )/ -- { %s `%s' %s}\r\n",
					scode, "connected to",
					DST_HOST,toProxy?"(via FTP-Proxy) ":"");
			}
			if( ftpDEBUG(0x02) ){
				fprintf(tc,"%d--\r\n",scode);
				fputs(retrresp,tc);
			}else{
				fprintf(tc,"%d \r\n",scode);
			}
		}else{
			FILE *tcsav = 0;
			if( ClientFlags & PF_STLS_ON ){
				/* 9.9.2 not to split into records over SSL */
				tc = pushfp(tc,&tcsav);
			}
			fprintf(tc,"%d-- %s for %s@%s.\r\n",scode,
				PFC->fc_swcom,PFC->fc_user,DST_HOST);
			escape_scode(AVStr(resp),tc);
/*
 fprintf(tc,"%s %s\r\n",XDC_OPENING,FS->fs_myhost);
*/
			if( ServerFlags & PF_SSL_ON )
			fprintf(tc,"%d--  @ @  --((SSL))--\r\n",scode);
			else
			fprintf(tc,"%d--  @ @  \r\n",scode);
			fprintf(tc,"%d  \\( - )/ -- { %s `%s' %s}\r\n",
				scode, "connected to",
				DST_HOST,toProxy?"(via FTP-Proxy) ":"");
			if( ClientFlags & PF_STLS_ON ){
				tc = popfp(tc,&tcsav);
			}
		}

		if( RETRCOMS(PFC->fc_swcom) )
		if( *retrresp != '5' && *retrresp != '4' ){
			fflush(tc);
			if( relay_data(FS,Conn,ts,
				fs,tc,fc,PFC->fc_swcom,PFC->fc_Path,0,
				AVStr(resp),sizeof(resp)) < 0 )
					goto PROXY_ERROR;
		}
		if( retrresp )
			free((char*)retrresp);

		if( PATHCOMS(PFC->fc_swcom) ){
			/* Server switching is invoked not by CWD but by
			 * some retrieval or store commands, thus the
			 * current directory is still in previous server.
			 * Thus relative argument here after can be miss-
			 * interpreted by DeleGate,
			 * unless the current directory is local
			 */
			if( !restoreCWD(PFC,FS) ){
				sv1log("## EXIT onetime [%s]\n",PFC->fc_swcom);
				if( sftp ){
					sv1log("SFTPGW:EXIT disabled\n");
					/* don't exit because forking SFTPGW
					 * is not light
					 */
				}else
				goto EXIT;
			}
			strcpy(FS->fs_prevVWD,PFC->fc_callersFS->fs_prevVWD);
		}
	}else{
		const char *opening;
		Verbose("D_FTPHOPS (%d) %s\n",D_FTPHOPS,FS->fs_myhost);
		opening = FCF.fc_noxdcCL?XDC_OPENING_NONE:XDC_OPENING_B64,
		fprintf(tc,"%s[PIPELINE] (%d) %s\r\n",
			opening,
			D_FTPHOPS,FS->fs_myhost);
		scode = atoi(opening);
		escape_scode(AVStr(resp),tc);
		fprintf(tc,"%d \r\n",scode);
	}
	fflush(tc);

	noSTOR = permitted_readonly(Conn,DST_PROTO);
	/*
	 * Disable MOUNTing if it's generated by SERVER=ftp://Server/
	 * (as MOUNT="/* ftp://Server/*") and the current server is not Server.
	 * User's "CWD /path" should be intended to be local to the current
	 * server ftp://server/path, not to switch to another server
	 * ftp://Server/path.
	 */
	if( enable_mount = mounted )
	if( !isMYSELF(iSERVER_HOST) )
	if( !streq(iSERVER_HOST,FS->fs_host) || iSERVER_PORT != FS->fs_port )
	/*
	 * Maybe this disabling is intended for *interactive* human user
	 * who knows each MOUNTed server as an origin server.
	 * - if the (current) ftp-server is not in MOUNT list
	 * - (when the user changed server explicitly with "CWD //ftp-server")
	 */
	if( !isMounted(FS) ){
		sv1log("MOUNT is disabled in NON-MOUNTed server [%s:%d]\n",
			FS->fs_host,FS->fs_port);
		enable_mount = 0;
	}

	/*
	 * disable server switching by "USER user@host" when acting as a
	 * MASTER-DeleGate which should be passive (or circuit level) in
	 * connection establishment to server.
	 */
	nosvsw = ImMaster && FCF.fc_swMaster==0;

	com[0] = 0;
	reqQi = 0;
	for(;;){
		if( FS->fs_REST && !comeq(com,"REST") ){
			sv1log("%s: cleared REST %lld\n",com,FS->fs_REST);
			FS->fs_REST = 0;
		}

		FS->fs_cstat = NULL;

		if( reqQn != 0 && reqQi == reqQn )
			reqQi = reqQn = 0;

		if( reqQn != 0 && reqQi < reqQn ){ /* dequeue */
			strcpy(req,reqQs[reqQi++]);
			Verbose("[%d/%d] %s",reqQi,reqQn,req);
		}else{
			if( feof(ts) || feof(fs) )
				goto SERVER_EOF;

			ProcTitle(Conn,"ftp://%s/",DST_HOST);
			/*
			if( pollSC("service_ftp",FTP_FROMCLNT_TIMEOUT,fs,fc) <= 0 )
			*/
			if( pollSC(FS,"service_ftp",fs,fc) <= 0 )
			{
				ConnError |= CO_TIMEOUT;
				goto SERVER_EOF;
			}

			if( fgetsTimeout(AVStr(req),sizeof(req),fc,1) == NULL )
			{
				sv1log("disconnected from the client\n");
				goto EXIT;
			}
		}

	GOTREQ:
		CCXreq(Conn,FS,req,AVStr(req),sizeof(req));

		dp = wordScan(req,com);
		if( !method_permitted(Conn,"ftp",com,1) ){
			fprintf(tc,"500 forbidden command: %s\r\n",com);
			fflush(tc);
			continue;
		}
		if( *dp == ' ' ){
			textScan(dp+1,arg);
		}else
		lineScan(dp,arg);
		strcpy(FS->fs_curcom,com);
		strcpy(FS->fs_curarg,arg);
		if( streq(com,"USER") )
			strcpy(FS->fs_OUSER,arg);

		if( FTP_STARTTLS_withCL(Conn,tc,fc,com,arg) ){
			fflush(tc);
			continue;
		}
		if( strcaseeq(com,"XECHO") ){
			fprintf(tc,"%s\r\n",arg);
			fflush(tc);
			continue;
		}
		if( strcaseeq(com,"USER") )
			if( unescape_user_at_host(AVStr(arg)) )
				sprintf(req,"%s %s\r\n",com,arg);

		if( strcaseeq(com,"USER") )
		if( (dp = strpbrk(arg,"?/@")) && (*dp == '?' || *dp == '/') ){
			url_escapeX(arg,AVStr(arg),sizeof(arg),"%%/?",":@");
			sprintf(req,"%s %s\r\n",com,arg);
		}
		if( strcaseeq(com,"USER") )
		if( (dp = strpbrk(arg,"~/@")) && (*dp == '~' || *dp == '/') ){
			const char *tp;
			wordscanY(dp+1,MVStrSiz(FS->fs_acct),"^@");
			sv1log("##ACCT got[%s] USER=%s\n",FS->fs_acct,arg);
			if( tp = strpbrk(dp+1,"@") )
				ovstrcpy((char*)dp,tp);
			else	truncVStr(dp);
			sprintf(req,"%s %s\r\n",com,arg);
		}

		/* pipelining should be implicit rathar than explicit
		 * with explicit PIPELINE command ...
		 */
		if( strcaseeq(com,"PIPELINE") ){
			reqQn = 0;
			for( reqQi = 0; ; reqQi++ ){
				if( fgets(req,sizeof(req),fc) == NULL )
					goto SERVER_EOF;
				if( req[0] == '.' && (req[1] == '\r' || req[1] == '\n') )
					break;

				Xstrcpy(EVStr(reqQs[reqQn]),req);
				reqQn++;
				if( !FS->fs_IAMCC || strncasecmp(req,"PWD",3) == 0 )
					fputs(req,ts);
			}
			fflush(ts);
			reqQi = 0;
			sv1log("PIPELINE: %d\n",reqQn);
			continue;
		}

		incRequestSerno(Conn);
		ProcTitle(Conn,"ftp://%s/",DST_HOST);

		if( PFC == NULL )
		if( strcasecmp(com,"QUIT") == 0 ){
 			fprintf(tc,"221 Goodbye.\r\n");
			fflush(tc);
			goto EXIT;
		}
		if( strcasecmp(com,"QUIT") == 0 )
			ConnError |= CO_CLOSED;

		if( strcasecmp(com,"PASS") == 0 )
			Verbose("#### PASS ******\n");
		else	Verbose("#### %s",req);

		if( strcaseeq(com,"CWD") && controlCWD(FS,tc,arg) )
			continue;

		if( strcaseeq(com,"CWD") || strcaseeq(com,"PWD") || login_done )
		if( FS->fs_logindir_isset == 0 ){
			if( FS->fs_logindir[0] == 0 )
				if( reqQn == 0 )
				{
					setLoginPWD(FS,ts,fs);
					FS->fs_logindir_isset = 1;
				}
		}

		SERVREQ_SERNO++;

		sav_islocal = FS->fs_islocal;/* can be changed in rewrite_CWD */
		strcpy(sav_cwd,FS->fs_CWD);
		sav_pwd[0] = 0;

		if( !ImMaster /* && it's not for me (as a FTP server) */ )
		if( !toProxy )
		if( enable_mount ){
			if( strcaseeq(com,"CDUP") ){
				strcpy(com,"CWD");
				strcpy(arg,"..");
				sprintf(req,"%s %s\r\n",com,arg);
			}
			if( strcasecmp(com,"CWD") == 0 )
				if( rewrite_CWD(FS,AVStr(req),AVStr(arg),tc) )
					continue;

			if( strcasecmp(com,"PWD") == 0 )
				if( rewrite_PWD(FS,req,arg,tc) )
					continue;
		}

		if( noSTOR && comCHANGE(com) ){
			sv1log("--F 553 Permission denied by DeleGate.\r\n");
			fprintf(tc,"553 Permission denied by DeleGate.\r\n");
			fflush(tc);
			continue;
		}

		if( strcaseeq(com,"CWD") && remote_path(arg) ){
			const char *path;
			decomp_ftpsite(FS,QVStr(arg+2,arg),&ident);

			/* "CWD //host/path" is performed with the sequence
			 * of "CWD logindir";"CWD path" to make the CWD
			 * without the knowledge about the path name
			 * delimiter in the FTP server.
			 */
			if( sameident(FS,&ident) ){ 
				getPWD(FS,AVStr(sav_pwd),sizeof(sav_pwd));
				chdirHOME(FS,ts,fs,AVStr(resp),sizeof(resp));
				path = strchr(arg+2,'/');

				/* allow absolute /path name under the current
				 * working directory at the target server
				 * even if the /path is MOUNTed ... (why?)
				 */
				if( path != NULL ){
					const char *ldir = FS->fs_logindir;
					int len;
					len = strlen(ldir);
					if( strncmp(path,ldir,len) == 0 )
					{
					sv1log("[%s] thru. CWD %s\n",ldir,path);
						ovstrcpy((char*)path,path+len);
					}
				}

				if( path == NULL || path[0] == 0 || strcmp(path,"/") == 0 ){
					fputs(resp,tc);
					fflush(tc);
					if( ftpDEBUG(0x200) == 0 )
					if( (ClientFlags & PF_AS_PROXY) == 0 ){
						Verbose("(setAsProxy(%s,%s))\n",
							com,arg);
						ClientFlags |= PF_AS_PROXY;
					}
					continue;
				}
				if( path[0] == '/' )
					strcpy(arg,path+1);
				else	strcpy(arg,path);
				sprintf(req,"%s %s\r\n",com,arg);
			}else{
				strcpy(cserv,arg+2);
				if( check_server(cserv,com,tc) == 0 )
				{
					if( sftp /* is not anonymous */ ){
					sv1log("SFTPGW:SWSERV/CWD disalbed\n");
					/* changing server by CWD is not safe
					 * sending username/password to another
					 * server withtout user's notice
					 */
					}else
					goto SWSERV;
				}
				else	continue;
			}
		}else
/*
		if( strcasecmp(com,"USER") == 0 && strchr(req,'@') ){
*/
		if( strcasecmp(com,"USER") == 0 && strchr(req,'@') && !nosvsw ){
			lineScan(req+5,cserv);
			if( check_server(cserv,com,tc) == 0 )
				goto SWSERV;
			else	continue;
		}else
		if( strcasecmp(com,"USER") == 0 && xserv[0] ){
			sprintf(cserv,"%s@%s",arg,xserv);
			if( check_server(cserv,com,tc) == 0 )
			{
				if( toProxy ){
					Xsprintf(TVStr(arg),"@%s",xserv);
					sprintf(req,"%s %s\r\n",com,arg);
				}else
				goto SWSERV;
			}
			else	continue;
		}else
		if( strncasecmp(req,"MODE ",5) == 0 ){
			set_client_mode(FS,arg);
			if( FS->fs_XDCforCL ){
				if( FS->fs_XDCforSV == 0 ){
					set_modeXDCtoSV(Conn,FS,ts,fs);
				}
				fprintf(tc,"200 MODE %s ok.\r\n",arg);
				fflush(tc);
				continue;
			}
		}else
		if( strncasecmp(req,"USER ",5) == 0 ){
			wordScan(req+5,cuser);
			replace_atmark("USER",cuser);
			FS->fs_anonymous = is_anonymous(cuser);
		}else
		if( strncasecmp(req,"PASS ",5) == 0 ){
			wordScanY(req+5,cpass,"^\r\n");
			if( FS->fs_anonymous ){
				replace_atmark("ANON-PASS",cpass);
				if( anonPASS(Conn,tc,cuser,AVStr(cpass)) != 0 ){
					cpass[0] = 0;
					continue;
				}
				/* cpass may be rewriten to canonical form */
		  		strcpy(arg,cpass);
				Xsprintf(DVStr(req,5),"%s\r\n",arg);
			}
		}else
		if( strncasecmp(req,"TYPE ",5) == 0 )
			wordScan(req+5,ctype);

		/*
		 *	catch commands which use data connection
		 */

		if( PATHCOMS(com) ){
			int rem = 0;
			if( enable_mount || remote_path(arg) ){
				if( swRemote(FS,com,AVStr(arg),AVStr(cserv),&rem) ){
					if( sftp /* is not anonymous */ ){
					sv1log("SFTPGW:SWSERV disabled\n");
					}else
					goto SWSERV;
				}
				if( FS->fs_authERR ){
					fprintf(tc,"530 not authorized\r\n");
					fflush(tc);
					FS->fs_authERR = 0;
					continue;
				}
				/*
				if( !rem && comeq(com,"STAT") ){
				*/
				if( !rem )
				if( comeq(com,"STAT") || comeq(com,"MLST") ){
					if( localSTAT(FS,tc,com,arg,0) ){
						fflush(tc);
						continue;
					}
				}
				if( comeq(com,"MLST") ){
					if( get_statcache(Conn,FS,com,arg,tc) ){
						continue;
					}
				}
				/* arg may be rewriten in swRemote() */
				if( *arg )
					sprintf(req,"%s %s\r\n",com,arg);
				else	sprintf(req,"%s\r\n",com);
			}

			if( RETRCOMS(com) )
			if( lookaside_cache(Conn,FS,tc,com,arg,rem) )
			/*
			if( lookaside_cache(Conn,FS,tc,com,arg) )
			*/
			{
				if( FS->fs_REST ){
					FS->fs_REST = 0;
				/* REST sent to the target server should
				 * be cancelled here, by NOOP or so...
				 * but usually it will be done automatically
				 * by some commands before next RETR like
				 * PORT,PASV,PWD,...
				 */
				}
				continue;
			}
		}

		if( strcaseeq(com,"PASV") ){
			setupPASV(Conn,FS,ts,fs,tc,arg);
			continue;
		}
		if( strcaseeq(com,"EPSV") ){
			setupPASV(Conn,FS,ts,fs,tc,arg);
			continue;
		}
		if( strcaseeq(com,"PORT") ){
			setupPORT(Conn,FS,ts,fs,tc,arg);
			continue;
		}
		if( strcaseeq(com,"EPRT") ){
			setupPORT(Conn,FS,ts,fs,tc,arg);
			continue;
		}

		if( comeq(com,"USER") || comeq(com,"PASS") )
		if( dontREINitialize(FS) ){
			/* ftp://user:pass@host */
			if( comeq(com,"USER") ) nUSER++;
			if( comeq(com,"PASS") ) nPASS++;

			if( login_done ){
			if( 1 < nUSER || 1 < nPASS )
				fprintf(tc,"530 Already logged in.\r\n");
			else	fprintf(tc,"230 Already logged in.\r\n");
			}else{
				/* no password in URL as "ftp://user@host" */
				if( comeq(com,"USER") ){
					presetLogin(FS,&ident,VStrNULL);
					sprintf(req,"USER %s\r\n",ident.i_user);
				}else
				if( comeq(com,"PASS") ){
					sprintf(req,"PASS %s\r\n",arg);
				}
				_put_get(MODE(FS),ts,fs,AVStr(resp),sizeof(resp),"%s",req);
				if( FCF.fc_hideserv )
					fprintf(tc,"%d \r\n",atoi(resp));
				else	fputs(resp,tc);
				if( atoi(resp) == 230 )
					login_done = 1;
			}
			fflush(tc);
			continue;
		}

		if( FS->fs_IAMCC ){
			if( comeq(com,"USER") ){
				if( strcmp(arg,FS->fs_USER) != 0 ){
					strcpy(cserv,DST_HOST);
					strcpy(cuser,arg);
					cpass[0] = 0;
					ctype[0] = 0;
					goto SWSERV;
				}
				if( FS->fs_rcUSER && streq(FS->fs_USER,arg) )
					fputs(FS->fs_rcUSER,tc);
				else
				fprintf(tc,"331 Password required for %s.\r\n",arg);
				fflush(tc);
				continue;
			}
			if( comeq(com,"PASS") ){
				if( FS->fs_rcPASS && streq(FS->fs_PASS,arg) )
					fputs(FS->fs_rcPASS,tc);
				else
				fprintf(tc,"230 User %s logged in.\r\n",cuser);
				fflush(tc);
				login_done = 1;
				continue;
			}
			if( comeq(com,"SYST") && arg[0] == 0 && FS->fs_rcSYST ){
				fputs(FS->fs_rcSYST,tc);
				fflush(tc);
				continue;
			}
			if( comeq(com,"TYPE") && comeq(arg,FS->fs_qcTYPE) && FS->fs_rcTYPE ){
				fputs(FS->fs_rcTYPE,tc);
				fflush(tc);
				continue;
			}
		}

		if( reqQn == 0 )
		{
			if( !FCF.fc_nounesc )
			if( PATHCOMS(com) || comeq(com,"CWD") )
				nonxalpha_unescape(req,AVStr(req),1);
			put_serv(MODE(FS),ts,"%s",req);
		}

		if( feof(ts) ){
			sprintf(resp,"421 server closed ;-<\r\n");
			rcode = EOF;
			fputs(resp,tc);
			fflush(tc);
		}else{
			rcode = get_resp(fs,NULL,AVStr(resp),sizeof(resp));
			CCXresp(Conn,FS,resp,AVStr(resp),sizeof(resp));

			if( comeq(com,"PASS") )
			if( atoi(resp) == 332 )
			if( FS->fs_acct[0] != 0 ){
				sv1log("##ACCT put[%s]\n",FS->fs_acct);
				sprintf(req,"ACCT %s\r\n",FS->fs_acct);
				goto GOTREQ;
			}
			if( comeq(com,"MLST") ){
				relayMLST(FS,resp,tc);
			}else
			fputs(resp,tc);
			fflush(tc);
			/*
			rcode = get_resp(fs,tc,AVStr(resp),sizeof(resp));
			*/
			/* path name in (error) resp like that for CWD
			 * command should be rewriten by reverse-MOUNT ...
			 */
		}

		if( rcode != EOF ){
			if( strcaseeq(com,"REST") ){
				Xsscanf(arg,"%lld",&FS->fs_REST);
				sv1log("set REST %lld\n",FS->fs_REST);
			}
			if( strcaseeq(com,"PWD") ){
				if( FS->fs_logindir[0] == 0 )
					setLoginPWD0(FS,resp);
			}else
			if( strcasecmp(com,"USER") == 0 ){
				/*
				strcpy(FS->fs_USER,arg);
				*/
				lineScan(arg,FS->fs_USER);
				FS->fs_rcUSER = stralloc(resp);
			}else
			if( strcasecmp(com,"PASS") == 0 ){
				/*
				strcpy(FS->fs_PASS,arg);
				*/
				wordscanY(req+5,MVStrSiz(FS->fs_PASS),"^\r\n");
				FS->fs_rcPASS = stralloc(resp);
				if( atoi(resp) != 332 )
				login_done = 1;
			}else
			if( strcasecmp(com,"ACCT") == 0 ){
				login_done = 1;
			}else
			if( strcasecmp(com,"TYPE") == 0 ){
				strcpy(FS->fs_TYPE,arg);
			}else
			if( comeq(com,"MLST") ){
				put_statcache(Conn,FS,"MLST",arg,resp);
			}else
			if( strcasecmp(com,"CWD")  == 0 ){
				IStr(dir,1024);
				chdir_cwd(AVStr(dir),arg,1);
				if( !FCF.fc_nounesc
				 && strcaseeq(FS->fs_CWD,"%2F")
				 && dir[0] != '/'
				){
					strcat(FS->fs_CWD,arg);
					/* 9.9.1 not to generate //arg */
				}else
				chdir_cwd(AVStr(FS->fs_CWD),arg,1);
				/*put_statcache(Conn,FS,"CWD","",resp);*/
			}else
			if( strcaseeq(com,"CDUP") ){
				chdir_cwd(AVStr(FS->fs_CWD),"..",1);
			}
		}
		if( rcode == EOF ){
		  if( comeq(com,"USER") ){
			FTP_delayReject(Conn,0,"USER",resp,0,arg,"");
			login_done = 0;
		  }else
		  if( comeq(com,"PASS") ){
			FTP_delayReject(Conn,0,"PASS",resp,0,FS->fs_USER,arg);
			login_done = 0;
		  }else
		  if( strcaseeq(com,"CWD") ){
			FS->fs_islocal = sav_islocal;
			strcpy(FS->fs_CWD,sav_cwd);
			if( sav_pwd[0] ){
				/* did temporary CWD on the target server */
				put_get(ts,fs,AVStr(resp),sizeof(resp),
					"CWD %s\r\n",sav_pwd);
			}
		  }
		}

		if( RETRCOMS(com) ){
		    if( enable_mount ){ /* remove `-> symlink' in LIST */ }

		    if( relay_data(FS,Conn,ts,fs,tc,fc,com,arg,rcode==EOF,
				AVStr(resp),sizeof(resp)) < 0 )
			goto SERVER_EOF;
		}

		if( rcode != EOF && comCHANGE(com) )
			mark_updated(FS,com,arg);

		if( comeq(com,"SYST") && arg[0] == 0 )
			Strdup((char**)&FS->fs_rcSYST,resp);
		else
		if( resp[0] == '2' ){
			if( comeq(com,"TYPE") ){
				lineScan(arg,FS->fs_qcTYPE);
				Strdup((char**)&FS->fs_rcTYPE,resp);
			}
		}
		if( strncasecmp(resp,"221",3) == 0 ) /* Goodbye */
			goto SERVER_EOF;
	}

SERVER_EOF:
	server_eof = 1;
	resetServer(Conn,FS,ts,fs);
EXIT:
	fflush(tc);
	if( PFC == NULL ){
		set_linger(fileno(tc),DELEGATE_LINGER);
		fclose(tc);
		fclose(fc);
	}
	D_FTPHOPS--;

	if( !login_done ){
	}else
	if( server_eof ){
		Verbose("NO FTPCC(0) server-EOF PFC=%x\n",p2i(PFC));
	}else
	if( BORN_SPECIALIST && ( getVUpath(FS,FS->fs_CWD,AVStr(arg)) != NULL
	 || hostcmp(iSERVER_HOST,FS->fs_host)==0 && iSERVER_PORT==FS->fs_port
	) ){
		/* current server is the one specified in SERVER=ftp://server
 		 * and/or MOUNT="/path... ftp://server"
		 * Maybe it's a ``local'' or ``domestic'' ftp server to
		 * which FTPCC is not necessary (maybe not desireble)...
		 */
		Verbose("NO FTPCC(1)\n");
	}else
	if( PFC != NULL ){
		Verbose("NO FTPCC(2)\n");
		/* Then client socket may be fddup()ed in calling functions.
		 * Those should be closed to finish the connection and
		 * become a server for other clients...
		.*/
/*
 * close any file descriptors duplicated from client's socket ...
 */
/*
 * should become FTPCC if this session is closed by
 * QUIT command or EOF from the client.
 */
	}else
	if( DontKeepAliveServ(Conn,"FTPCC") ){
	}else{
		int rcode;
		/*
		if( ftp_beBoundProxy(Conn,FS,ts,fs,cuser,mounted) == 0 )
		*/
		rcode = ftp_beBoundProxy(Conn,FS,ts,fs,cuser,mounted);
		if( rcode == 0 )
			return 0;
		if( 0 < rcode ){ /* was IAMCC */
			if( ToS < 0 ){ /* did SWSERV */
				/* ts and fs is cosed already at SWSERV: */
				sv1log("seems FTPCC return after SWSERV.\n");
				goto ExIT;
			}
		}
	}
nocc:
	if( Conn->xf_filters ){
		/* socket for the control-connection may be inherited to a
		 * filter-process and kept open to block the server to
		 * detect the disconnection of the client.
		 * ex. filter-process is a SSLway pending in ssl_connect()
		 */
		Verbose("SV ShutdownSocket[%d %d]\n",ToS,ToSX);
		ShutdownSocket(ToS);
		ShutdownSocket(ToSX);
	}
	FS->fs_IAMCC = 0;
	finishServYY(FL_ARG,Conn);
	fclose(ts);
	fclose(fs);
	ToS = FromS = -1;
ExIT:
	Vsignal(SIGPIPE,sigpipe);
	ftp_env_name = "FTP_EXIT";
	return 0;

PROXY_ERROR:
	if( PFC )
		scode = PFC->fc_ERRcode;
	else	scode = 500;
	fprintf(tc,"%d-- %s for %s.\r\n",scode,PFC->fc_swcom,DST_HOST);
	escape_scode(AVStr(resp),tc);
	fprintf(tc,"%d ;-<\r\n",scode);
	save_FS(FS);
	goto EXIT;

SWSERV:
	FS->fs_IAMCC = 0;
	finishServYY(FL_ARG,Conn);
	fclose(ts);
	fclose(fs);
	FromS = ToS = -1;
	toProxy = toMaster = 0;
	D_FTPHOPS--;
	Vsignal(SIGPIPE,sigpipe);
	ftp_env_name = "FTP_SWSERV";

	save_FS(FS);
	if( strchr(cserv,'@') ){
		CStr(nuser,64);
		wordScanY(cserv,nuser,"^@");
		Verbose("USER [%s]->[%s]\n",cuser,nuser);
		if( is_anonymous(cuser) ){
			if( !is_anonymous(nuser) )
				cpass[0] = 0;
		}else{
			if( strcmp(nuser,cuser) != 0 )
				cpass[0] = 0;
		}
	}
	change_server(Conn,FS,fc,tc,com,cserv,cuser,cpass,ctype);
	return -1;
}

static int ftpcc(Connection *Conn,FtpStat *FS,FILE *fs,FILE *ts,int mounted)
{	CStr(resp,1024);

	chdirHOME(FS,ts,fs,AVStr(resp),sizeof(resp));
	FS->fs_PORTforPASV = 0;
	FS->fs_PASVforPORT = 0;
	FS->fs_XDCforCL = 0;
	FS->fs_XDCencCL = "";

	service_ftp1(Conn,FS,mounted);

	if( FS->fs_IAMCC && !feof(fs) )
		return 0;
	else	return -1;
}

static int ftp_beBoundProxy(Connection *Conn,FtpStat *FS,FILE *ts,FILE *fs,PCStr(cuser),int mounted)
{	CStr(resp,1024);
	void (*sigpipe)(int);
	int rcode;

	sigpipe = Vsignal(SIGPIPE,SIG_IGN);
	rcode = put_get(ts,fs,AVStr(resp),sizeof(resp),"NOOP\r\n");
	Vsignal(SIGPIPE,sigpipe);
	/*
	if( put_get(ts,fs,AVStr(resp),sizeof(resp),"NOOP\r\n") == EOF )
	*/
	if( rcode == EOF )
		return -1;

	if( FS->fs_IAMCC )
		return 0;

	if( FS->fs_anonymous ){
		FS->fs_IAMCC = 1;
		if( cuser[0] ) strcpy(FS->fs_USER,cuser);
		if( PFC ){
			close(ToC);
			close(FromC);
		}
		beBoundProxy(Conn,"anonymous",CC_TIMEOUT_FTP,
			(iFUNCP)ftpcc,FS,fs,ts,mounted);
	}
	return 1;
}

static char *linecpy(xPVStr(to),PCStr(from),int size)
{	int lx;
	int ch;

	for( lx = 1; lx < size; lx++ ){
		ch = *from++;
		setVStrPtrInc(to,ch);
		if( ch == '\n' )
			break;
	}
	setVStrEnd(to,0);
	return (char*)to;
}

int ftp_login(Connection *Conn,FILE *ts,FILE *fs,xPVStr(resp),int rsize,PCStr(user),PCStr(pass),int TypeSyst)
{

#define GET_RESP(fs,tc,rs,sz) \
    ( do_sync ? rx <= ri ? EOF \
	: *linecpy(QVStr(rs,resp),rv[ri++],sz)=='5' ? EOF : 0 \
	: get_resp(fs,tc,QVStr(rs,resp),sz))

#define SYNC() \
    if( do_sync ){ \
	fflush(ts); \
	rv[rx++] = rp; strcpy(rp,"500 closed.\r\n"); \
	if( get_resp(fs,NULL,AVStr(rp),sizeof(srb)-(rp-srb)) == EOF ) \
		goto endreq; \
	else	rp += strlen(rp); \
    }


	int rcode = 0;
	int tcode;
	int mode;
	CStr(respb,4096);
	CStr(path,1024);
	int rleng;
	int do_pipeline;
	int do_sync = 0;
	int rx;
	int ri;
	const char *rv[8]; /**/
	CStr(srb,4096);
	refQStr(rp,srb);
	int scode;

	if( resp == NULL ){
		setPStr(resp,respb,sizeof(respb));
		rsize = sizeof(respb);
	}

	mode = 0;
	if( is_anonymous(user) ){
		mode = PS_ANON;
		IsAnonymous = 1;
	}

	if( _put_get(mode,ts,fs,AVStr(resp),rsize,NULL) == EOF )
		return EOF;
	if( strstr(resp,XDC_OPENING) )
		rcode = 1;

	if( toTunnel(Conn) ){
		FtpStat FSbuf, *FS = &FSbuf;
		init_FS(FS,Conn);
		D_FTPHOPS = 1;
		FS->fs_opening = stralloc(resp);
		set_modeXDCtoSV(Conn,FS,ts,fs);
	}

	mode |= PS_BUFF;
		/* This is meaningless if stelinebuf(ts) has done ... */

	do_pipeline = ServViaCc
		&& strstr(resp,"[PIPELINE]");

	if( do_pipeline )
		put_serv(mode,ts,"PIPELINE\r\n");
	else{
		/*
		if( strstr(resp,"Microsoft FTP") ){
		*/
		if( strstr(resp,"Microsoft FTP")
		 || strstr(resp,"spftp/")
		){
			do_sync = 1;
			rp = srb;
			ri = rx = 0;
		}
	}
	tcode =
	FTP_STARTTLS_withSV(Conn,ts,fs);
	if( tcode < 0 ){
		sv1log("##ftp_login: TLS error: %d SF=%X\n",tcode,ServerFlags);
		sprintf(resp,"421 failed starting TLS with the server\r\n");
		return EOF;
	}

	put_serv(mode,ts,"USER %s\r\n",user); SYNC();
	put_serv(mode,ts,"PASS %s\r\n",pass); SYNC();
	if( TypeSyst ){
		fflush(ts);
		fPollIn(fs,1000);
		put_serv(mode,ts,"TYPE %s\r\n","I"); SYNC();
	}
endreq:

	if( do_pipeline )
		put_serv(mode,ts,".\r\n");

	fflush(ts);

	rleng = 0;
	if( GET_RESP(fs,NULL,resp+rleng,rsize-rleng) == EOF ){ /* USER */
		if( resp && atoi(resp)/100 == 5 ){
			const char *tmp;
			tmp = stralloc(resp);
			sprintf(resp,"%d-COMMAND: USER %s\r\n%d-\r\n%s",
				atoi(tmp),user,atoi(tmp),tmp);
			free((char*)tmp);
		}
		addRejectList(Conn,"USER","","",user,"",resp);
		return EOF;
	}
	scode = atoi(resp);
	if( GET_RESP(fs,NULL,resp+rleng,rsize-rleng) == EOF ){ /* PASS */
		if( scode != 230 ){
		addRejectList(Conn,"PASS","","",user,pass,resp);
		return EOF;
		}
	}

	if( TypeSyst == 0 )
		return rcode;

	if( GET_RESP(fs,NULL,resp+rleng,rsize-rleng) == EOF ) /* TYPE */
		rcode = EOF;

	return rcode;
}

int ftp_auth(FILE *ts,FILE *fs,PVStr(resp),int rsize,PCStr(user),PCStr(pass))
{
	const char *nl= "\n";
	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF ) return EOF;
	if( strtailstr(resp,"\r\n") )
		nl = "\r\n";
	sv1log("ftp_auth << %s",resp);
	/*
	fprintf(ts,"USER %s\r\n",user);
	*/
	fprintf(ts,"USER %s%s",user,nl);
	fflush(ts); /* for Microsoft FTP server */
	fprintf(ts,"PASS %s%s",pass,nl);
	/*
	fprintf(ts,"PASS %s\r\n",pass);
	*/
	fflush(ts);
	/*
	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF ) return EOF;
	*/
	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF ) return EOF;
	if( get_resp(fs,NULL,AVStr(resp),rsize) == EOF ) return EOF;
	return 0;
}

static FILE *cache_verify(Connection *Conn,FILE *ts,FILE *fs,PCStr(path),PVStr(resp),int rsize,int *isdirp)
{	FtpStat FSbuf, *FS = &FSbuf;
	CStr(ipath,1024);
	CStr(cpath,1024);
	CStr(xcpath,1024);
	FILE *cfp;

	init_FS(FS,Conn);
	FS->fs_ts = ts;
	FS->fs_fs = fs;
	wordScan(DST_HOST,FS->fs_host);
	FS->fs_port = DST_PORT;
	strcpy(FS->fs_TYPE,"I");
	cfp = fopen_cache(0,Conn,FS,"RETR",path,AVStr(ipath),AVStr(cpath),AVStr(xcpath));
	if( cfp != NULL ){
		sprintf(resp,"150 Opening cached verified data (%lld bytes)\r\n",
			file_sizeX(fileno(cfp)));
		Conn->sv.p_range[2] = file_sizeX(fileno(cfp));
		*isdirp = 0;
		return cfp;
	}
	return NULL;
}
int pushPFilter(Connection *Conn,PCStr(proto),PFilter *aPf);
FILE *ftp_fopen(Connection *Conn,int put,int server,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp,FILE *fsc)
{	FILE *fs,*ts;
	FILE *dfp;
	int dsock;
	CStr(mport,256);
	int typesyst = 1;
	int usePASV = 1;

	IStr(xpath,1024);
	FtpGw Fgb,*Fg = &Fgb;
	bzero(&Fgb,sizeof(FtpGw));
	Fg->fg_Conn = Conn;

	if( isinFTPxHTTP(Conn) ){
		refQStr(xp,xpath);
		IStr(xctype,128);

		RequestFlags |= QF_FTPXHTTP;
		strcpy(xpath,path);
		if( xp = strchr(xpath,'?') ){
			setVStrPtrInc(xp,0);
			path = xpath;
			scanFTPxHTTP(Conn,xp,AVStr(Fg->fg_cmd),AVStr(Fg->fg_opt),AVStr(xctype));
		}
		sv1log("---FTPxHTTP FxH=%X (%s) QF=%X {%s}\n",
			isinFTPxHTTP(Conn),Fg->fg_cmd,RequestFlags,xp?xp:"");
		if( STATCOMS(Fg->fg_cmd) ){
			Fg->fg_statfp = TMPFILE("FTPxHTTP");
		}else
		if( isinListX("STAT,MLST",Fg->fg_cmd,"c") ){
			Fg->fg_statfp = TMPFILE("FTPxHTTP");
		}
		if( isinListX("LIST,NLST,MLSD",Fg->fg_cmd,"c") ){
			/* list should be in TYPE A */
			typesyst = 0;
		}
	}

	init_conf();
	fs = ts = dfp = NULL;

	if( fsc ){
		fs = fsc;
	}else
	if( Conn->xf_filters & XF_FFROMSV ){
		fs = fdopen(FromS,"r");
	}else
	fs = fdopen(server,"r");
	if( fs == NULL ){
		sv1log("FTP: cannot fdopen server sock[%d]\n",server);
		goto EXIT;
	}
	setlinebuf(fs);

	if( Conn->xf_filters & XF_FTOSV ){
		ts = fdopen(ToS,"w");
	}else
	ts = fdopen(server,"w");
	if( ts == NULL ){
		goto EXIT;
	}
	setlinebuf(ts);

	/*
	if( ftp_login(Conn,ts,fs,AVStr(resp),rsize,user,pass,1) == EOF )
	*/
	if( ftp_login(Conn,ts,fs,AVStr(resp),rsize,user,pass,typesyst) == EOF )
	{
		IStr(xresp,1024);
		put_get(ts,fs,AVStr(xresp),sizeof(xresp),"QUIT\r\n");
		goto EXIT;
	}

	if( dfp = cache_verify(Conn,ts,fs,path,AVStr(resp),rsize,isdirp) )
	{
		if( 0 < reqPART_FROM ){
			fseek(dfp,reqPART_FROM,0); /* should be FileSize */
			Lseek(fileno(dfp),reqPART_FROM,0);
			gotPART_FROM = reqPART_FROM;
		}
		goto EXIT;
	}

	setConnTimeout(Conn);
	if( FCF.fc_nopasvSV ) usePASV = 0;
	dsock = data_open(Fg,put,usePASV,-1,host,ts,fs,path,isdirp,AVStr(resp),rsize);
	if( ServerFlags & (PF_STLS_ON|PF_SSL_ON) )
	if( (ConnectFlags & COF_NODATASSL) == 0 ){
	    if( dsock < 0 ){
	    }else{
		Connection dataConn;
		dataConn = *Conn;
		clearSTLS(&dataConn);
		{
			Connection *Conn = &dataConn;
			ToS = FromS = dsock;
			strcpy(REAL_PROTO,"ftp-data");
		}
		sv1log("--FTP STARTTLS DATA[%s][%d] %X\n",DST_PROTO,dsock,ConnectFlags);
		FTP_dataSTLS_FSV(Conn,&dataConn,dsock);
		pushPFilter(Conn,"ftp-data",&dataConn.sv.p_filter[0]);
		Verbose("----sockets SV[%d][%d][%d][%d] [%d]\n",ServerSock,
			ToS,ToSX, ToSF,FromS);
		/* SSLway thread should be cleared later */
	    }
	}

	if( Fg->fg_statfp ){
		dfp = Fg->fg_statfp;
		if( 0 <= dsock ){
			close(dsock);
			dsock = -1;
		}
	}else
	if( 0 <= dsock ){
		if( put )
			dfp = fdopen(dsock,"w");
		else	dfp = fdopen(dsock,"r");
	}
EXIT:
	if( fs == fsc ){
		/* return the response from server buffered in fsc */
	}else
	if( fs ) fcloseFILE(fs);
	if( ts ) fcloseFILE(ts);
	return dfp;
}

FILE *ftp_fopen0(int put,int svsock,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp)
{	Connection ConnBuf, *Conn = &ConnBuf;

	bzero(Conn,sizeof(Connection));
	ClientSock = -1;
	ToS = ToSX = -1;
	strcpy(DFLT_PROTO,"ftp");
	return
	ftp_fopen(Conn,put,svsock,host,user,pass,path,AVStr(resp),rsize,isdirp,0);
}

int unescape_path(PCStr(path),PVStr(xpath))
{
	nonxalpha_unescape(path,AVStr(xpath),1);
	if( strcmp(path,xpath) != 0 ){
		Verbose("path-unescaped> %s\n",xpath);
		return 1;
	}
	return 0;
}
static FileSize getFsize(PCStr(resp))
{	FileSize fsize;
	const char *sp;

	fsize = -1;
	if( sp = strstr(resp,"bytes)") ){
		while( resp < sp && *sp != '(' )
			sp--;
		if( *sp == '(' )
			fsize = Xatoi(sp+1);
			/*
			Xsscanf(sp,"(%lld",&fsize);
			*/
	}
	return fsize;
}
FileSize FTP_datasize(PCStr(stat))
{	const char *dp;

	if( dp = strstr(stat,"150") )
	if( dp == stat || dp[-1] == '\n' )
		return getFsize(dp);
	return -1;
}

/*
 * SERVER=ftp
 * REMITTABLE=+,https
 * PERMIT=https:*:srcHostList
 * MOUNT="/MagicPath* https://-/*"
 */
int ftp_https_server(Connection *Conn,FtpStat *FS,FILE *ctc,FILE *cfc,int clsock,PCStr(com),PCStr(path))
{	FILE *tc;
	const char *dp;
	int start,xc;

	start = time(0);
	sv1log("FTP-HTTPS[%d] %s\n",clsock,path);
	tc = fdopen(clsock,"w");
	if( dp = strstr(path,"--") ){
		strcpy(DFLT_PROTO,"tcprelay");
		Xsscanf(dp+2,"%[^:]:%d",AVStr(DFLT_HOST),&DFLT_PORT);
	}else{
		strcpy(DFLT_PROTO,"https");
		strcpy(DFLT_HOST,"-");
		DFLT_PORT = 0;
	}
strcpy(iSERVER_PROTO,"http"); /* not to be rejected as "Protocol Mismatch" */
Conn->no_dstcheck = 1; /* not to be rejected as "Method Not Allowed" */
IO_TIMEOUT = 0;
	execSpecialist(Conn,clsock,tc,-1);
xc = 1;
FS->fs_islocal = 0;
	putXferlog(Conn,FS,com,path,start,xc,"");
	Finish(0);
	return -1;
}
/*
 * CONNECT=f
 * FTPTUNNEL=host:port:MagicPath[:cmap]
 */
static SStr(thost,32);
static SStr(tpath,32);
static int tport;
int scan_FTPTUNNEL(Connection *Conn,PCStr(spec))
{	const char *dp;
	CStr(buf,32);

	dp = wordscanY(spec,MVStrSiz(thost),"^:");
	if( *dp != ':' )
		return -1;
	dp = wordScanY(dp+1,buf,"0123456789");
	tport = atoi(buf);
	if( *dp == ':' ){
		wordscanY(dp+1,MVStrSiz(tpath),"^:");
	}
	return 0;
}

int ConnectViaFtp(Connection *Conn)
{	FILE *ts,*fs;
	int serv;
	CStr(path,256);
	CStr(req,256);
	CStr(resp,256);
	int isdir;

	serv = client_open("ConnectViaFtp","ftp",thost,tport);
	if( serv < 0 )
		return -1;
	sprintf(path,"/%s",tpath);
	ts = ftp_fopen(Conn,1,serv,"LocalHost","ftp",getADMIN(),path,AVStr(resp),sizeof(resp),&isdir,0);
	close(serv);
	if( ts == NULL )
		return -1;
	serv = fileno(ts);

	/* ConnectViaSSLtunnel */
	fs = fdopen(serv,"r");
	sprintf(req,"CONNECT %s:%d HTTP/1.0\r\n\r\n",DST_HOST,DST_PORT);
	fputs(req,ts);
	fflush(ts);
	sv1log(">> %s",req);
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		sv1log("<< %s",resp);
		if( *resp == '\r' || *resp == '\n' )
			break;
	}
	fcloseFILE(ts);
	fcloseFILE(fs);
	return serv;
}

/*
 * FTPxHTTP
 */
int isFTPxHTTP(PCStr(proto)){
	return strcaseeq(proto,"ftpxhttp")
	    || strcaseeq(proto,"ftpxhttps");
}
int isinFTPxHTTP(Connection *Conn){
	int isin = 0;
	if( GatewayFlags & GW_FTPXHTTP )
		isin |= 1;
	if( isFTPxHTTP(iSERVER_PROTO) )
		isin |= 2;
	if( isFTPxHTTP(CLNT_PROTO) )
		isin |= 4;
	if( MountOptions && isinListX(MountOptions,"ftpxhttp","ch") )
		isin |= 8;
	return isin;
}
int scanFTPxHTTP(Connection *Conn,PCStr(cmdopt),PVStr(xcmd),PVStr(xopt),PVStr(xctype)){
	const char *dp;
	IStr(buf,128);
	int flags = 0;

	if( dp = strstr(cmdopt,"ftpxcmd=") ){
		wordScanY(dp+8,buf,"^&");
		strcpy(xcmd,buf);
		if( isinListX("RETR,MLST,STAT",xcmd,"-c") ){
			RequestFlags |= (flags |= QF_FTP_COMRETR);
		}
		if( isinListX("STOR",xcmd,"-c") ){
			RequestFlags |= (flags |= QF_FTP_COMSTOR);
		}
		if( isinListX("LIST,NLST,MLSD,MLST,STAT",xcmd,"-c") ){
			RequestFlags |= (flags |= QF_FTP_COMLIST);
		}
	}
	if( xcmd[0] ){
		sprintf(xctype,"text/x-ftpx-%s",xcmd);
	}else{
		sprintf(xctype,"text/x-ftpx-%s","LIST");
	}
	if( dp = strstr(cmdopt,"ftpxopt=") ){
		wordScanY(dp+8,buf,"^&");
		strcpy(xopt,buf);
	}
	return flags;
}
static int scanHead(FILE *fs,PVStr(head)){
	refQStr(hp,head);
	IStr(line,1024);

	while( fgets(line,sizeof(line),fs) ){
		if( *line == '\r' || *line == '\n' ){
			return 1;
		}
		if( head ){
			strcpy(hp,line);
			hp += strlen(hp);
		}
	}
	return 0;
}
static int ftpxhttpURL(FtpStat *FS,PCStr(com),PCStr(arg),PVStr(url)){
	const char *file;
	IStr(fopt,1024);
	IStr(path,1024);
	IStr(vurl,1024);
	const char *upath = path;
	const char *up;
	const char *mopts;

	file = scanLISTarg(com,arg,AVStr(fopt));
	if( *file == '/' ){
		strcpy(path,file);
	}else{
		strcpy(path,"/");
		chdir_cwd(AVStr(path),FS->fs_CWD,0);
		chdir_cwd(AVStr(path),file,0);
	}

	/* client-side MOUNT onto non-root path */
	if( mopts = mount_ftparg(FS,com,path,AVStr(vurl)) )
	if( strncaseeq(vurl,"ftpxhttp://",11) ){
		if( up = strchr(vurl+11,'/') ){
			upath = up;
		}
	}

	/* strip "ftpx" prefix for "http" or "https" */
	sprintf(url,"%s://%s:%d%s",FS->fs_proto+4,FS->fs_host,FS->fs_port,upath);
	if( com[0] ){
		Xsprintf(TVStr(url),"?ftpxcmd=%s",com);
		if( fopt[0] ){
			Xsprintf(TVStr(url),"&ftpxopt=%s",fopt);
		}
		if( FS->fs_RNFR[0] ){
			Xsprintf(TVStr(url),"&ftpxopt=RNFR/%s",FS->fs_RNFR);
		}
		if( strcaseeq(com,"RNFR") ){
			strcpy(FS->fs_RNFR,arg);
		}else{
			clearVStr(FS->fs_RNFR);
		}
	}
	sv1log("## ftpxhttpURL %s\n",url);
	return 1;
}
FILE *ftp_localLIST(Connection *Conn,FILE *tc,PCStr(com),PCStr(arg),PVStr(path)){
	FtpStat FSbuf, *FS = &FSbuf;
	FILE *fp;
	IStr(file,1024);

	init_conf();
	init_FS(FS,Conn);
	FS->fs_islocal = 1;
	fp = TMPFILE("FTHT");
	strcpy(file,path);

	putlist(FS,fp,com,arg,path,file);
	fflush(fp);
	fseek(fp,0,0);
	return fp;
}
int ftpxhttpLIST(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path),PVStr(head)){
	FILE *fp;
	Connection *Conn = FS->fs_Conn;
	IStr(url,1024);
	IStr(resp,128);
	int hcode = 0;
	int off;
	int len;

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	ftpxhttpURL(FS,com,arg,AVStr(url));

	sprintf(D_EXPIRE,"8s");
	RequestFlags = 0;
	RequestFlags |= QF_AUTH_FORW;
	RequestFlags |= QF_FTPXHTTP;
	RequestFlags |= QF_NO_AUTH;
	if( tc == NULL ){
		RequestFlags |= QF_URLGET_HEAD;
		RequestFlags |= QF_URLGET_RAW;
	}else{
		RequestFlags |= QF_URLGET_THRU;
	}
	fp = CTX_URLget(Conn,0,url,0,NULL);
	fflush(fp);

	fseek(fp,0,0);
	fgets(resp,sizeof(resp),fp);
	sscanf(resp,"HTTP/%*s %d",&hcode);
	scanHead(fp,BVStr(head));
	off = ftell(fp);
	fseek(fp,0,0); /* flush buffered data for copyfile1() */
	fseek(fp,off,0);
	Lseek(fileno(fp),off,0); /* set offset for putToClient() */

	if( tc != NULL ){
		if( hcode == 404 ){
			fprintf(tc,"550 No such directory\r\n");
		}else
		if( hcode == 401 ){
			fprintf(tc,"530 Forbidden.\r\n");
		}else
		if( isinListX("STAT,MLST",com,"c") ){
			len = copyfile1(fp,tc);
		}else{
			putToClient(Conn,FS,tc,com,NULL,fileno(fp),NULL,0,path);
		}
	}
	fclose(fp);
	return hcode;
}
int ftpxhttpRETR(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg),PVStr(path)){
	Connection *Conn = FS->fs_Conn;
	IStr(hresp,1024);
	int hcode = 0;
	IStr(url,1024);
	int start = time(0);
	FILE *fp;
	int xc;

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	ftpxhttpURL(FS,com,arg,AVStr(url));

	RequestFlags = 0;
	RequestFlags |= QF_AUTH_FORW;
	RequestFlags |= QF_URLGET_THRU;
	RequestFlags |= QF_FTPXHTTP;
	RequestFlags |= QF_NO_AUTH;
	sprintf(D_EXPIRE,"8s");
	fp = CTX_URLget(Conn,0,url,0,NULL);
	fflush(fp);

	fseek(fp,0,0);
	fgets(hresp,sizeof(hresp),fp);
	sscanf(hresp,"HTTP/%*s %d",&hcode);
	fseek(fp,0,0);
	scanHead(fp,VStrNULL);
	Lseek(fileno(fp),ftell(fp),0);

	if( hcode == 200 ){
		xc = putToClient(Conn,FS,tc,com,NULL,fileno(fp),NULL,0,url);
		FS->fs_cstat = "L";
		putXferlog(Conn,FS,com,arg,start,xc,"");
	}else{
		if( hcode == 404 ){
			fprintf(tc,"550 No such file\r\n");
		}else
		if( hcode == 401 ){
			fprintf(tc,"530 Forbidden.\r\n");
		}else{
			putToClient(Conn,FS,tc,com,NULL,-1,NULL,0,"(error)");
		}
	}
	fclose(fp);
	return 1;
}
void scan_realserver(Connection *Conn,PCStr(url),PVStr(upath));
int shutdownWR(int fd);
static void ignsigPIPE(int sig){
	sv1log("--FTPxHTTP SIGPIPE\n");
}
int ftpxhttpSTOR(FtpStat *FS,FILE *tc,FILE *fc,PCStr(com),PCStr(arg),PVStr(path)){
	Connection ConnBuf,*Conn = &ConnBuf; IStr(url,1024);
	IStr(upath,1024);
	IStr(port,256);
	IStr(resp,256);
	FILE *fp;
	int xc;
	FILE *ts,*fs;
	int cdsock;
	FILE *dfp;
	FileSize siz = -9;
	int hcode = 999;
	IStr(stat,256);
	IStr(auth,256);
	double St;
	void (*sigpipe)(int);

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	cdsock = connect_data("ftp-data-CL",FS,AVStr(port),ClientSock);
	if( cdsock < 0 ){
		fprintf(tc,"550 cannot connect with you.\r\n");
		return -1;
	}
	fprintf(tc,"150 Data connection established\r\n");
	fflush(tc);

	ftpxhttpURL(FS,com,arg,AVStr(url));
	*Conn = *FS->fs_Conn; /* copy Auth. */
	scan_realserver(Conn,url,AVStr(upath));
	Conn->no_dstcheck_proto = serviceport(DST_PROTO);

	/*
	int reusing = 0;
	int getServ(Connection *Conn);
	if( reusing = getServ(FS->fs_Conn) ){
		1) Serv. cache is stored in the way impossible to
		   be reused in Conn. context other than original.
		2) POST will shutdown the keep-alive to the server.
	}
	*/
	if( ToS < 0 )
	connect_to_servX(Conn,-1,-1,0,0);
	if( ToS <= 0 ){
		fprintf(tc,"550 cannot connect to server\r\n");
		close(cdsock);
		return -1;
	}
	ts = fdopen(ToS,"w");
	fs = fdopen(FromS,"r");

	sigpipe = Vsignal(SIGPIPE,ignsigPIPE);
	if( toProxy ){
		fprintf(ts,"POST %s HTTP/1.0\r\n",url);
		/* Content-Length with buff. or chunked */
	}else
	fprintf(ts,"POST /%s HTTP/1.0\r\n",upath);
	if( makeAuthorization(Conn,AVStr(auth),0) ){
		fprintf(ts,"Authorization: %s\r\n",auth);
	}
	/* should with Content-Length or Content-Encoding */
	/* currently, it is indicated by EOS with shutdownWR() */
	fprintf(ts,"\r\n");
	/*
	 * bad for proxy-HTTP-DeleGate
	fflush(ts);
	 */

	if( dfp = fdopen(cdsock,"r") ){
		siz = copyfile1(dfp,ts); /* might cause SIGPIPE */
		fclose(dfp);
	}
	fflush(ts);
	if( toProxy ){
		/* wait proxy starts POST relay before shutdown detection.
		 * proxy-HTTP-DeleGate will immediately stop relaying POST
		 * if without Content-Length and without buffered data.
		 */
		msleep(300);
	}
	shutdownWR(fileno(ts));
	Vsignal(SIGPIPE,sigpipe);

	St = Time();
	if( 0 < fPollIn(fs,15*1000) ){
		fgets(resp,sizeof(resp),fs);
	}
	Xsscanf(resp,"HTTP/%*s %d %[^\r\n]",&hcode,AVStr(stat));
	sv1log("## FTPxHTTP %d {%s}(%.3f)\n",hcode,stat,Time()-St);
	fcloseFILE(ts);
	fclose(fs);

	if( 200 <= hcode && hcode < 300 ){
		fprintf(tc,"226 Transfer complete (%lld bytes)\r\n",siz);
	}else{
		fprintf(tc,"550 Transfer failed (HTTP %d %s)\r\n",hcode,stat);
	}
	fflush(tc);
	return 1;
}
static int ftpxhttpCHANGE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg)){
	int hcode;
	IStr(path,512);
	IStr(head,8*1024);
	IStr(fopt,128);
	const char *file;
	IStr(stat,128);
	IStr(xcode,128);
	IStr(xstat,128);
	int icode;
	int rcode = 1;
	IStr(resp,256);

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	file = scanLISTarg(com,arg,AVStr(fopt));
	hcode = ftpxhttpLIST(FS,NULL,com,file,AVStr(path),AVStr(head));
	getFieldValue2(head,"X-FTPxHTTP-Status",AVStr(xcode),sizeof(xcode));
	icode = atoi(xcode);
	if( 100 <= icode && icode <= 999 ){
		Xsscanf(xcode,"%*d %[^\r\n]",AVStr(xstat));
		sprintf(resp,"%d %s",icode,xstat);
		if( 400 <= icode ){
			rcode = -1;
		}
	}else
	if( strcaseeq(com,"CWD") && (300 <= hcode && hcode <= 303) ){
		/* the server is SERVER=ftpxhttp with local dir. */
		sprintf(resp,"250 CWD command successful");
	}else
	if( hcode == 200 ){
		if( strcaseeq(com,"CWD") ){
			sprintf(resp,"250 CWD ok");
		}else
		if( strcaseeq(com,"DELE") ){
			sprintf(resp,"250 file removed");
		}else
		if( strcaseeq(com,"MKD") ){
			sprintf(resp,"257 directory created");
		}else
		if( strcaseeq(com,"RMD") ){
			sprintf(resp,"250 directory removed");
		}else{
			sprintf(resp,"500 FTPxHTTP unknown");
			rcode = -2;
		}
	}else{
		sprintf(resp,"500 FTPxHTTP error");
		rcode = -3;
	}
	if( tc ){
		fprintf(tc,"%s\r\n",resp);
		fflush(tc);
	}
	return rcode;
}
static int ftpxhttpSTAT(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg)){
	int hcode;
	IStr(path,512);
	IStr(head,8*1024);
	IStr(fopt,128);
	const char *file;
	FILE *tmp;
	IStr(stat,128);

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	file = scanLISTarg(com,arg,AVStr(fopt));
	tmp = TMPFILE("ftpxhttpSTAT");
	hcode = ftpxhttpLIST(FS,tmp,com,file,AVStr(path),AVStr(head));
	fflush(tmp);
	fseek(tmp,0,0);
	fgets(stat,sizeof(stat),tmp);
	fseek(tmp,0,0);

	if( hcode == 200 && atoi(stat) != 211 ){
		fprintf(tc,"211-status\r\n");
		copyfile1(tmp,tc);
		fprintf(tc,"211 end\r\n");
	}else{
		copyfile1(tmp,tc);
	}
	fclose(tmp);
	fflush(tc);
	return 1;
}
static int ftpxhttpSIZE(FtpStat *FS,FILE *tc,PCStr(com),PCStr(arg)){
	Connection *Conn = FS->fs_Conn;
	IStr(head,8*1024);
	IStr(buf,128);
	IStr(file,512);
	IStr(path,512);
	int hcode;
	int mtime;
	IStr(sm,128);
	FileSize cleng = 0;
	IStr(fcode,128);
	IStr(fstat,128);
	int icode;

	if( !isFTPxHTTP(FS->fs_proto) ){
		return 0;
	}
	strcpy(file,arg);
	if( strtailchr(file) == '/' ){
		setVStrEnd(file,strlen(file)-1);
	}
	/*
	hcode = ftpxhttpLIST(FS,NULL,"",file,AVStr(path),AVStr(head));
	*/
	hcode = ftpxhttpLIST(FS,NULL,com,file,AVStr(path),AVStr(head));
	if( tc == NULL ){
		return hcode;
	}
	getFieldValue2(head,"X-FTPxHTTP-Status",AVStr(fcode),sizeof(fcode));
	icode = atoi(fcode);
	if( hcode == 401 || icode == 530 ){
		fprintf(tc,"530 please login.\r\n");
	}else
	if( hcode == 301 || hcode == 302 || hcode == 303 ){
		fprintf(tc,"550 not a plain file\r\n");
	}else
	if( 300 <= hcode && 300 <= icode && icode <= 999 ){
		Xsscanf(fcode,"%*d %[^\r\n]",AVStr(fstat));
		fprintf(tc,"%d %s\r\n",icode,fstat);
	}else
	if( strcaseeq(com,"MDTM") ){
		if( getFieldValue2(head,"Last-Modified",AVStr(buf),sizeof(buf)) ){
			mtime = scanHTTPtime(buf);
			StrftimeGMT(AVStr(sm),sizeof(sm),"%Y%m%d%H%M%S",mtime,0);
		}
		fprintf(tc,"213 %s\r\n",sm);
	}else
	if( strcaseeq(com,"SIZE") ){
		if( getFieldValue2(head,"Content-Length",AVStr(buf),sizeof(buf)) ){
			Xsscanf(buf,"%lld",&cleng);
		}
		fprintf(tc,"213 %lld\r\n",cleng);
	}else{
		fprintf(tc,"550 %s: No such file\r\n",arg);
	}
	return hcode;
}
static int ftpxhttpAUTH(FtpStat *FS,PCStr(com),PCStr(arg)){
	Connection *Conn = FS->fs_Conn;
	IStr(path,128);
	int hcode;

	RequestFlags = QF_AUTH_FORW;
	ClientAuth.i_stat = AUTH_FORW;
	if( strcaseeq(com,"USER") ){
		wordScan(arg,ClientAuth.i_user);
	}else{
		textScan(arg,ClientAuth.i_pass);
	}
	hcode = ftpxhttpLIST(FS,NULL,"NLST","",AVStr(path),VStrNULL);
	return hcode;
}
