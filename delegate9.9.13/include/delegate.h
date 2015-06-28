/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato
Copyright (c) 1994-2000 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use, copy, and distribute (via publically accessible
on-line media) this material for any purpose and without fee is hereby
granted, provided that the above copyright notice and this permission
notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	delegate.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	May1994	created
//////////////////////////////////////////////////////////////////////#*/
#ifndef _DELEGATE_H_
#define _DELEGATE_H_

#include "dgctx.h"
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "ysocket.h"
#include "vaddr.h"
#include "url.h"
#include "log.h"
#include "dglib.h"

extern const char *MYSELF;	/* -.- */

extern const char *DELEGATE_CONFIG;
extern const char *DELEGATE_CONF;
extern const char *DELEGATE_ADMIN_DFLT; /* ADMIN at compile time */
extern const char *DELEGATE_ADMIN;
extern const char *DELEGATE_ADMINPASS;
extern const char *builtin_ADMINPASS;
extern const char *DELEGATE_OWNER;
extern const char *DELEGATE_G_PERMIT;
extern const char *DELEGATE_S_PERMIT;
extern const char *DELEGATE_HTTP_PERMIT;
extern const char *DELEGATE_SOCKS_PERMIT;
extern const char *DELEGATE_TELNET_PERMIT;
extern const char *DELEGATE_RELAY;
extern const char *DELEGATE_RELIABLE;
extern const char *DELEGATE_DGPATH;

extern char SERV_HTTP[];

#define DELEGATE_LINGER LIN_TIMEOUT
extern int   DELEGATE_LINGER;
extern const char *DELEGATE_DGROOT;
extern const char *DELEGATE_LDPATH;
extern const char *DELEGATE_LIBDIR;
extern const char *DELEGATE_LIBPATH;
extern const char *DELEGATE_DATAPATH;
extern const char *DELEGATE_WORKDIR;
extern const char *DELEGATE_VARDIR;
extern const char *DELEGATE_LOGDIR;
extern const char *DELEGATE_ADMDIR;
extern const char *DELEGATE_ETCDIR;
extern const char *DELEGATE_CERTDIR;
extern const char *DELEGATE_UASFILE;
extern const char *DELEGATE_LOGFILE;
extern const char *DELEGATE_EXPIRELOG;
extern const char *DELEGATE_ABORTLOG;
extern const char *DELEGATE_PROTOLOG;
extern const char *DELEGATE_PARAMFILE;
extern const char *DELEGATE_ACTDIR;
extern const char *DELEGATE_TMPDIR;
extern const char *DELEGATE_PIDFILE;
extern const char *DELEGATE_STATFILE;
extern int   DELEGATE_syncro;
extern const char *DELEGATE_IMAGEDIR;
extern int   GOPHER_ON_HTTP;
extern int   GOPHER_EXPIRE;
extern const char *GOPHER_CACHE_ITEM;

extern const char *CCV_TOCL;
extern const char *CCV_TOSV;
extern int   LOGIN_TIMEOUT;
extern int   DELEGATE_LISTEN;

extern const char *TIMEFORM_mdHMS;
extern const char *TIMEFORM_HTTPD;
extern const char *TIMEFORM_GOPHER;
extern const char *TIMEFORM_RFC822;

extern int   ENCODE_HTML_ENTITIES;
extern int   DECODE_HTML_ENTITIES;

extern const char *DELEGATE_CACHEDIR;
extern int   CACHE_RDRETRY_INTERVAL;
extern int   CACHE_WRRETRY_INTERVAL;

extern char D_SERVICE_BYPORT[];

typedef struct {
	MStr(	de_EXEC_PATH,1024);
	struct {
		MStr(	PROTO,64);
		MStr(	HOST,256);
		int	PORT;
	} de_iSERVER;
	int	de_RESTART_NOW;
	int	de_REQUEST_SERNO;
	int	de_SERVREQ_SERNO;
} DeleGateEnv;
extern DeleGateEnv *deleGateEnv;
#define EXEC_PATH	deleGateEnv->de_EXEC_PATH
/**/
#define iSERVER_PROTO	deleGateEnv->de_iSERVER.PROTO
/**/
#define iSERVER_HOST	deleGateEnv->de_iSERVER.HOST
/**/
#define iSERVER_PORT	deleGateEnv->de_iSERVER.PORT
#define RESTART_NOW	deleGateEnv->de_RESTART_NOW
#define REQUEST_SERNO	deleGateEnv->de_REQUEST_SERNO
#define SERVREQ_SERNO	deleGateEnv->de_SERVREQ_SERNO

typedef struct {
	int	_acceptSock;	/* current socket for -Pxxx */
	int	_acceptPort;	/* current port#, xxx of -Pxxx */
	int	_portProto;	/* -Pxxx/proto for SERVER=proto */
	int	_isAdmin;	/* current socket with -Pxxx/admin */
	int	_withAdmin;	/* the socket of -Pxxx/admin if exists */
	int	_adminPort;	/* xxx of -Pxxx/admin, port# for admin. */
	int	_userPort;	/* yyy of -Pyyy, port# for users */
	int	_yshPort;	/* zzz of -Pzzz/ysh, port# for remote console*/
	int	_portFlags;	/* flags in -Pxxx/flags as rident */
	double	_ACCEPT_TIME;
} ClPort;

typedef struct {
	int	_closed;
	int	_randfd;
	int	_screened;
	int	_fd;
	ClPort	_clif;
	int	_remote;
	MStr(	_sockname,256);
	MStr(	_peername,256);
	VAddr	_origdst;
} Efd;
#define setEfd(efd,fd,sockname,peername,remote) \
	(efd==NULL?-1:((efd->_closed=0),(efd->_fd=fd),\
		(efd->_randfd=0), \
		(efd->_screened=0), \
		strcpy(efd->_sockname,sockname), \
		strcpy(efd->_peername,peername), (efd->_remote=remote)))
#define getEfd(efd) \
	(efd==NULL?-1:(efd->_closed?-1: efd->_fd))
#define closeEfd(efd) \
	(efd==NULL?-1:(efd->_closed?-1:((efd->_closed=1),close(efd->_fd))))
#define SocknameOf(efd)	(efd->_sockname)
#define PeernameOf(efd)	(efd->_peername)

typedef struct {
	int	f_ftype;
	int	f_tid; /* thread id */
	int	f_owner; /* owner thread id */
	int	f_pid;
	int	f_svsock;
	int	f_clsock;
	int	f_error;
	int	f_fid;
} PFilter;

typedef struct {
	int	p_reqserno; /* serial number of requests on the connetion */
	int	p_bound;
	int	p_connected;
	int	p_closed;
	double	p_connTime;
	double	p_saveTime;
	int	p_connType; /* the type of current CONNECTION {c,m,p,d,v,s,...} */
	int	p_connError;
	int	p_viaCc;	/* via a connection cache proxy */
	int	p_viaVSAP;
	int	p_viaSocks;
	int	p_viaProxy;
	int	p_viaMaster;
	int	p_dontKeepAlive;
	int	p_wantKeepAlive;
	int	p_willKeepAlive;
	int	p_sentKeepAlive;
	int	p_stopKeepAlive;
	int	p_port;
	int	p_anonymous;
	int	p_flags;
	int	p_fd[8];
	PFilter	p_filter[2];
       FileSize	p_range[4]; /* Range: from-to/size + leng */
	MStr(	p_sstring0,64);
	MStr(	p_sstring1,64);
	MStr(	p_sstring2,64);
	MStr(	p_sstring3,64);
	MStr(	p_lstring0,256);
	MStr(	p_lstring1,256);
	MStr(	p_lstring2,256);
	MStr(	p_lstring3,256);
      AuthInfo *p_auth;
} Port;
typedef struct {
	char   *cb_buff;
	int	cb_size;
	int	cb_fill;
	int	cb_peak;
	int	cb_read;
} CBuf;

#define	p_sock	p_fd[0] /* directly connected with the peer{client,server,proxy,..} */
#define p_SOCKSCTL p_fd[1] /* SOCKS server (control conn./TCP for UDP ASSOC) */
#define p_rfd	p_fd[2]
#define p_wfd	p_fd[3]
#define p_rfdx	p_fd[4] /* escaped when FFROMXX filter inserted */
#define p_wfdx	p_fd[5]	/* escaped when FTOXX filter inserted */
#define p_wfdf	p_fd[6]	/* escaped when FSV filter inserted */
#define p_SockX	p_fd[7] /* saved ServerSock / ClientSock */

#define p_connFname	p_sstring0 /* Connection or Proxy-Connection */
#define p_proto		p_sstring1
#define p_viaMasterVer	p_sstring2
#define p_SOCKSADDR	p_sstring2 /* SOCKS port for UDP ASSOC */
#define p_ccxbuf	p_sstring3
/**/
/**/

#define p_site		p_lstring0 /* [user [:pass] @] host [:port] */
#define p_host		p_lstring1
#define p_user		p_lstring2
#define p_whyclosed	p_lstring3
#define p_SRCIF		p_lstring3 /* SRCIF to serv. in KeepAlive */
/**/

#define DG_MAXHEAD	32
#define DG_MAXCLIN	16

#define setDGFL()	(Conn->dg_F = __FILE__),(Conn->dg_L = __LINE__)
#define getDGFL()	Conn->dg_F,Conn->dg_L	

typedef struct {
	int	 f_tid;
	int	 f_ptid;
   struct DGCtx *f_Conn;
	FILE	*f_ioin;
	int	 f_Sync[2]; /* not used anymore */
	FILE	*f_out;
    CriticalSec  f_FThreadCSC;
} FilterThread;
#define FTenv	Conn->dg_fthread
#define FThreadCSC   Conn->dg_fthread.f_FThreadCSC
#define ConnCSC      Conn->dg_ConnCSC

/* the context of a session thread to be kept persistently */
typedef struct {
	int	st_svtid;	/* the session thread (thread group-id) */
	int	st_svtix;
	int	st_svacc;
	int	st_svser;
	double	st_lastacc;
	int	st_lev;		/* mem. level */
  const char   *st_F;
	int	st_L;
	void   *st_adminCtx;
	CBuf	st_cbuf;
	UTag	st_REQUESTtag;
	Efd	st_clSock;
	int	st_filterThreads[32];
	int	st_yymux;
	defQStr(st_uri);
	PFilter	st_PFpushed[8];
} SessionThread;
#define STX_tid	Conn->dg_sthread.st_svtid
#define STX_tix	Conn->dg_sthread.st_svtix
#define STX_acc	Conn->dg_sthread.st_svacc
#define STX_ser	Conn->dg_sthread.st_svser
#define STX_atm	Conn->dg_sthread.st_lastacc
#define STX_lev	Conn->dg_sthread.st_lev
#define STX_F	Conn->dg_sthread.st_F
#define STX_L	Conn->dg_sthread.st_L
#define STX_adminCtx Conn->dg_sthread.st_adminCtx
#define STX_cb	Conn->dg_sthread.st_cbuf
#define STX_QUt	Conn->dg_sthread.st_REQUESTtag
#define STX_clSock	Conn->dg_sthread.st_clSock
#define STX_fth	Conn->dg_sthread.st_filterThreads
#define STX_yy	Conn->dg_sthread.st_yymux
#define STX_uri	Conn->dg_sthread.st_uri

typedef struct {
	int	pm_portmap;
	int	pm_type;
} PortMap;

typedef struct {
	int	ci_ix;		/* index in connection cache */
	int	ci_id;		/* connection id */
	int	ci_para;	/* active connections to the server */
	VSAddr	ci_svaddr;	/* server addr. */
	VSAddr	ci_ifaddr;	/* conn. interface addr. */
	double	ci_connSt;	/* first connection time */
	int	ci_reused;	/* reuse count of the conn. */
	int	ci_reusing;	/* did reuse in this session */
} CcSv;
typedef struct {
	int	md_md5;
	char	md_md5ctx[128];
	char	md_md5b[16];
       FileSize md_leng;
} MD5ctx;
typedef struct _ConnDepth {	/* v9.9.12 Connection chain on the stack */
	DGCtx  *cd_prevConn;	/* previous (caller's) Connection */
	int	cd_curdepth;	/* current depth of URLget() for SSI include */
	int	cd_peekdepth;	/* maximum depth reached */
	int	cd_overflow;	/* depth when overflow is prevented */
	int	cd_putlog;	/* delayed log after stack shrinked */
} ConnDepth_00;
#define connDepth ConnDepth_00
#define ConnDepth Conn->co_depth

typedef struct DGCtx {
	int	cx_magic;	/* to detect this is not initialized or not */
 SessionThread  dg_sthread;
  FilterThread  dg_fthread;
  CriticalSec   dg_ConnCSC;

	MStr(	cx_where,32);	/* something describes the "caller" */
	int	inv_stats;	/* Invocation Status */
	Port	sv;
	Port	sv_dflt;	/* default server */
	Port	sv_dfltsav;
	PortMap	sv_pm;	/* relative to incoming port: 0<N:inc N<0:dec */
	Port	sv_remote;	/* http://H:P/...=@=Rp:RH:RP */
	ClPort	clif;
	int	me_iamgw;
	int	me_norelay;
	FILE   *sv_toServ;
	int	sv_imCC;	/* server connection holder */
	int	sv_imResponseFilter;
	int	sv_imMaster;
	int	sv_imProxy;
	int	sv_mounted;
	int	sv_isvhost;
	int	sv_proxyOnly;
	int	sv_retry;

	int	sv_reusing;
	int	sv_ka_timeout;
	int	sv_ka_remalive;

	int	ma_private;
	char	ma_sayhello;
	char	ma_saidhello;
	char	ma_doack;	/* return ACK */
	char	ma_noack;	/* don't return ACK */
	char	cl_nosync;	/* don't flush DeleGate-HELLO */
	char	cl_noflush;
	MStr(	rident_sockhost,256);
	int	rident_sockport;
	MStr(	rident_peerhost,256);
	MStr(	rident_peeraddr,64);
	int	rident_peerport;
	int	rp_sock;	/* RPORT: socket for response connection */
	int	rp_udp;

	Port	cl;
  const	char   *cl_user;
	VAddr	cl_peerAddr;	/* cache for getpeername(ClientSock) */
       AuthInfo	cl_Ident;	/* cache for Ident */
	int	cl_count;
	int	xf_reqrecv;	/* HTTP request has been received */
	int	xf_filters;
	int	xf_pidFFROMCL;	/* the (pre-)filter process for FFROMCL */
	int	xf_filtersCFI;	/* inserted filter is CFIscript */
	int	xf_clprocs;	/* spawned process with client-side socket */
	int	xf_mounted;
	int	xf_isremote;
	int	xf_echoreq;
	int	xf_stderr2out;
	FILE   *xf_fp[16];
	int	xf_codes[16];
	MStr(	cl_reqmethod,32);
	int	cl_reqlength;
	void   *cl_reqbuf;
	int	cl_reqbufsize;
	int	xf_sync[2];	/* CFI_SYNC pipe for sync. from the filter */

       AuthInfo cl_certauth;
       AuthInfo sv_certauth;
	MStr( 	cl_cert,256);
	MStr(	sv_cert,256);

	MStr(	cl_myhp,128);	/* client side interface */
	int	cl_tcCLOSED;
	VAddr	cl_origHOST;	/* SO_ORIGINAL_DST */
	VAddr	cl_sockHOST;	/* cache for getsockname(), DeleGate side IP */
	VAddr	sv_sockHOST;
	char	cl_nocache;
	char	cl_reload;
	MStr(	cl_expire,128); /* EXPIRE specified at client side */
	MStr(	cl_baseurl,128);/* base of referer's url-path */
	UrlX	my_vbase; /* decomposed cl_baseurl when it is full-URL */
	UrlX	rq_vbase;	/* v9.9.11 temporary BASEURL (SSI vbase) */

	MStr(	dg_clsession,128);
	MStr(	dg_pxcontrols,256); /* URL?_?proxyControl */
	MStr(	dg_modifier,256);
	MStr(	dg_putpart,32);
	MStr(	dg_iconbase,128); /* maybe obsoleted by BASEURL and MOUNT=/-/builtin/icons */
	MStr(	cl_rport,256);	/* RPORT specified by the client DeleGate */

	int	oc_isset;
	int	oc_norewrite;	/* the client seems to expect proxy server */
	int	oc_bydelegate;	/* accessed by /-_-URL notation */
	MStr(	oc_proto,64);	/* that of the real originator client, */
	MStr(	oc_proxy,128);	/* which is not proxy */

	int	dg_HOPS;
	int	dg_FTPHOPS;

	MStr(	ma_SERVER,256);
  const	char   *cl_headerB[DG_MAXHEAD];
	int	cl_headerX;
  const	char   *cl_inputsB[DG_MAXCLIN];
	int	cl_inputsX;

       AuthInfo	cl_auth; /* for password authentication */
	int	cl_noauth;
	int	cl_proxyAuth;	/* use Proxy-Auth in non-HTTP/HTTP gw. */

	Port	gw;
  const	char   *gw_path;

  const	char   *ca_objbuff;
	int	ca_objsize;

	int	ca_flags;
	int	ca_control;
	int	ca_dontuse;
	int	ca_dontread;
	int	ca_dontwait;
	int	ca_dontwrite;
	int	ca_readonly;
	int	ca_only;
	int	ca_mtime;
	int	ca_lastmod;
	int	ca_reqwithcookie;
	int	ca_respwithcookie;

	int	ca_distsock;
	int	ca_distsock_open;
	int	ca_curoff;
	int	ca_receptorN;
	short	ca_rcptflags[64];
	short	ca_receptors[64]; /* should be FD_SETSIZE */
	int	ca_putoff[64];

	int	co_setup;
	int	co_routex;
	int	co_nonet;
	int	co_nointernal;
	int	co_internal;
	int	co_local;
	int	co_mask; /* CONN_NOPROXY, CONN_NOMASTER, ... */
	double	co_start;
	double	co_done;
	double	co_delay;

	int	born_specialist;
	int	act_generalist;
	int	meta_specialist;
	int	act_specialist;
	int	act_translator;
	int	relay_thru;
	int	path_added;
	Port	dl; /* born as GENERALIST but act as SPECIALIST */

	int	resp_with_body;
	int	body_only;	/* for HTTP ... */
	int	from_myself;
	int	from_client;	/* the request is issued by a client */
	int	from_cached;	/* peer address is cached in cl_peerAddr */
	int	no_authcheck;
	int	no_dstcheck;
	int	no_dstcheck_proto; /* destination protocol when MOUNTed */
	int	no_dstcheck_port; /* as an origin server */
	int	no_permission; 	/* error code ... */
	int	auth_check;
	int	permitGlobal;
	int	toMyself;
	int	statcode;
	MStr(	Rstat,64);

	int	ht_PadCRLF;
	int	ht_SimpleContType;
  const	char   *ht_LockedByClient;
	char	ht_stat;
	char	ht_statx;
	MStr(	ht_genETag,64);
	MStr(	ht_addRespHeaders,256);
	MStr(	ht_flags,128);
	MStr(	ht_qmd5,16);
	MStr(	ht_rmd5,16);
	MStr(	ht_sign,16);

  const char   *mo_options;	/* MOUNTed, its options */
  const char   *mo_optionsX;	/* MountOptions to be passed to URLget() */
	Port	mo_master;	/* MASTER just for current MOUNT point */
	Port	mo_proxy;	/* PROXY just for current MOUNT point */
	MStr(	mo_authorizer,128);
	int	mo_flags;	/* MOUNT control options */
	int	req_flags;	/* flags to control the current request */
	int	gw_flags;
	int	cf_flags;	/* static configuration */
	int	html_flags;	/* HTML parsing and generation */
struct namvals *html_namvals;	/* HTML stack for name=value pairs */

	iFUNCP	fi_func;
	int	fi_arglen;
	int	fi_iomode;	/* 0:input-filter, 1:output filter */
	short	fi_topeer;	/* the peer side connection (socket or pipe) */
	short	fi_issock;	/* fi_topeer is socket */
	short	fi_dupclsock;	/* do copy fi_topeer to cl_sockFd */
	short	fi_logfd;

	MStr(	fi_what,32);
	short	fi_isresp;

	int	fi_builtin;	/* with builtin-filter (openHttpResponse) */
	int	fi_pid;		/* pid by openFilter() */

	void	*cc_conv[2];	/* CCX context */
	int	cl_setccx;	/* CCX is set by client */
	MStr(	sv_rcharset,32); /* charset of server response */
	MStr(	sv_bcharset,32); /* META HTTP-EQUIVE=Content-Type */
	MStr(	sv_lang,32);	/* Content-Language in header or META */

	MStr(	dd_from,256);
	MStr(	dd_user,256);
	MStr(	dd_gtype,2);
	MStr(	dd_selector,1024);
	MStr(	dd_path,512);
	MStr(	dd_rport,128);
	MStr(	dd_override,256);

	char	sv_hasmaster;
	MStr(	cl_modifiers,256);
	MStr(	cl_if_hostport,256);
	MStr(	cl_if_host,256);
	int	cl_if_port;
	MStr(	sv_genhost,256);	/* Host: field to be forwarded */
	int	cl_auth_stat;

	int	forreject; /* on:REJECT off:PERMIT */
	MStr(	reject_reason,256);
	int	_isFunc;

	MStr(	my_Rusage,sizeof(long)*20);

	struct {
		FILE   *e_fp;
		int	e_ln;
	} dg_Efiles[16];
	int	dg_Efilex;
	int	dg_urlcrc; /* CRC32(url) of URLget(url) for loop detect */

	int	ss_break;
	int	nn_nsid;
	double	ac_timeout;
	double	io_timeout; /* I/O timeout specific to this session */

	int	proto_ctx[8];
	int	gw_maxbps;

	CcSv	ccsv;		/* -Ecc */
	MD5ctx	md_in;		/* -Emi MD5 for input data */
	int	thread_flags;
	VAddr	rident_peer;	/* RIDENT=client */
	int	cx_pid;
	int	connect_flags;
	MStr(	cm_method,32); /* obsolete */

	connDepth co_depth;	/* v9.9.12 fix-140814c, depth of Connection */
} Connection_01;
#define Connection Connection_01

#define CMAPmethod	Conn->cm_method

#define ThreadFlags	Conn->thread_flags
#define TH_MTSS_PUTENV	0x00000001
#define tMTSS_PUTENV()	(ThreadFlags & TH_MTSS_PUTENV)

#define setAccTimeout(t) (Conn->ac_timeout = t+1)
#define getAccTimeout()	(Conn->ac_timeout - 1)
#define ACCEPT_TIME	Conn->clif._ACCEPT_TIME
#define BreakSticky	Conn->ss_break

#define Efiles		Conn->dg_Efiles
#define Efilex		Conn->dg_Efilex

#define MO_OFF_REQ	1 /* suppress MOUNT for request */
#define MO_BI_EXTERN	0x00000002 /* external builtin */
#define MO_MD5_ADD	0x00000010 /* add CRC in header */
#define MO_MD5_SIGN	0x00000020 /* add CRC sign */
#define MO_MD5_VERIFY	0x00000040 /* verify CRC */
#define MO_MD5_SET	0x00000080 /* md5 is set in ht_md5[] */

#define ClientAuth	Conn->cl_auth
#define ClientAuthUser	Conn->cl_auth.i_user
/**/
#define ClientAuthHost	Conn->cl_auth.i_addr.a_name
/**/
#define ClientAuthPass	Conn->cl_auth.i_pass
/**/
#define ClientAuthPort	Conn->cl_auth.i_addr.a_port
#define ClientCert	Conn->cl_certauth
#define AuthStat	Conn->cl_auth_stat
#define GEN_VHOST	Conn->sv_genhost
/**/
#define D_FROM		Conn->dd_from
/**/
#define D_USER		Conn->dd_user
#define D_SELECTOR	Conn->dd_selector
/**/
#define D_GTYPE		Conn->dd_gtype
#define D_PATH		Conn->dd_path
/**/
#define D_RPORT		Conn->dd_rport
/**/
#define D_OVERRIDE	Conn->dd_override
/**/

#define HAS_MASTER	Conn->sv_hasmaster
#define MODIFIERS	Conn->cl_modifiers
/**/
#define CLIF_HOSTPORT	Conn->cl_if_hostport
/**/
#define CLIF_HOST	Conn->cl_if_host
/**/
#define CLIF_PORT	Conn->cl_if_port

#define CCX0		(Conn->cc_conv[0])
#define CCX_TOCL	((CCXP)Conn->cl.p_ccxbuf)
#define CCX_TOSV	((CCXP)Conn->sv.p_ccxbuf)
#define CCX_SIZE	sizeof(Conn->cl.p_ccxbuf)
#define SVRespCharset	Conn->sv_rcharset
#define InCharset	Conn->sv_bcharset
#define InLang		Conn->sv_lang
/**/

#define ToMyself	Conn->toMyself
#define ToInternal	(Conn->toMyself & 2)
#define setToInternal()	(Conn->toMyself |= 2)
#define CLIENTS_PROXY	Conn->oc_proxy
/**/
#define CLIENTS_PROTO	Conn->oc_proto
/**/
#define DONT_REWRITE	Conn->oc_norewrite
#define DO_DELEGATE	Conn->oc_bydelegate
#define IAM_GATEWAY	Conn->me_iamgw
#define RelayForbidden	Conn->me_norelay
#define RPORTsock	Conn->rp_sock
#define RPORTudp	Conn->rp_udp
#define TelesockHost	Conn->rident_sockhost
/**/
#define TelesockPort	Conn->rident_sockport
#define TeleportHost	Conn->rident_peerhost
/**/
#define TeleportAddr	Conn->rident_peeraddr
/**/
#define TeleportPort	Conn->rident_peerport
#define Rident_VAddr	(&Conn->rident_peer)
#define RespNOSYNC	Conn->cl_nosync
#define RespNOFLUSH	Conn->cl_noflush

#define ClientSession	Conn->dg_clsession
/**/
#define ProxyControls	Conn->dg_pxcontrols
#define Modifier	Conn->dg_modifier
/**/
#define	D_HOPS		Conn->dg_HOPS
#define	D_FTPHOPS	Conn->dg_FTPHOPS

#define	FromCbuff	STX_cb.cb_buff
#define	FromCsize	STX_cb.cb_size
#define	FromCfill	STX_cb.cb_fill
#define	FromCpeak	STX_cb.cb_peak
#define	FromCread	STX_cb.cb_read
#define D_REQUESTtag	STX_QUt

#define headerB		Conn->cl_headerB
#define headerX		Conn->cl_headerX
#define inputsB		Conn->cl_inputsB
#define inputsX		Conn->cl_inputsX
#define D_SERVER	Conn->ma_SERVER
/**/
#define D_EXPIRE	Conn->cl_expire
/**/
#define PragmaNoCache	Conn->cl_nocache
#define HttpReload	Conn->cl_reload
#define D_RPORTX	Conn->cl_rport

#define ToServ		Conn->sv_toServ
#define FromSX		Conn->sv.p_rfdx
#define ToSX		Conn->sv.p_wfdx
#define ToSF		Conn->sv.p_wfdf
#define FromS		Conn->sv.p_rfd
#define ToS		Conn->sv.p_wfd
#define FromC		Conn->cl.p_rfd
#define FromCX		Conn->cl.p_rfdx
#define ToC		Conn->cl.p_wfd
#define ToCX		Conn->cl.p_wfdx
#define ImResponseFilter Conn->sv_imResponseFilter
#define IsMounted	Conn->sv_mounted
#define IsVhost		Conn->sv_isvhost
#define ImCC		Conn->sv_imCC
#define IsAdmin		(0 <= Conn->clif._withAdmin \
			   && Conn->clif._withAdmin == Conn->clif._isAdmin)
#define Admin_Port	Conn->clif._adminPort
#define User_Port	Conn->clif._userPort
#define Console_Port	Conn->clif._yshPort
#define Port_Proto	Conn->clif._portProto

#define tryProxyOnly	Conn->sv_proxyOnly
#define toProxy		Conn->sv.p_viaProxy
#define toMaster	Conn->sv.p_viaMaster
#define MediatorVer	Conn->sv.p_viaMasterVer
/**/
#define	MasterIsPrivate	Conn->ma_private
#define ImProxy		Conn->sv_imProxy

#define ServViaCc	Conn->sv.p_viaCc
#define ServViaSocks	Conn->sv.p_viaSocks
#define ServViaVSAP	Conn->sv.p_viaVSAP

#define ImMaster	Conn->sv_imMaster
#define ClientVER	Conn->cl.p_viaMasterVer /* client DeleGate version if ImMaster */
/**/
#define SayHello	Conn->ma_sayhello
#define SaidHello	Conn->ma_saidhello
#define ReturnACK	Conn->ma_doack
#define NoACK		Conn->ma_noack

#define GatewayProto	Conn->gw.p_proto
/**/
#define GatewayHost	Conn->gw.p_host
/**/
#define GatewayPort	Conn->gw.p_port
#define GatewayPath	Conn->gw_path
#define GatewayAuth	Conn->gw.p_auth
#define GatewayUser	(GatewayAuth?GatewayAuth->i_user:"")
#define GatewayPass	(GatewayAuth?GatewayAuth->i_pass:"")

#define NoAuth		Conn->cl_noauth
#define ProxyAuth	Conn->cl_proxyAuth

#define CacheFlags	Conn->ca_flags
#define DontUseCache	Conn->ca_dontuse
#define DontReadCache	Conn->ca_dontread
#define DontWaitCache	Conn->ca_dontwait
#define DontWriteCache	Conn->ca_dontwrite
#define CacheControl	Conn->ca_control
#define CacheReadOnly	Conn->ca_readonly
#define CacheOnly	Conn->ca_only
#define CacheMtime	Conn->ca_mtime
#define CacheLastMod	Conn->ca_lastmod
#define ReqWithCookie	Conn->ca_reqwithcookie
#define RespWithCookie	Conn->ca_respwithcookie

#define ServConnTime	Conn->sv.p_connTime
#define ClntConnTime	Conn->cl.p_connTime

extern int BORN_SPECIALIST; /* communicates with a real client */

#define ACT_GENERALIST	Conn->act_generalist
#define META_SPECIALIST	Conn->meta_specialist
#define	ACT_SPECIALIST	Conn->act_specialist
#define	DELEGATE_LHOST	Conn->dl.p_host/* specialist directly interface with client */
/**/
#define RelayTHRU	Conn->relay_thru
#define	DELEGATE_LPORT	Conn->dl.p_port
#define ACT_TRANSLATOR	Conn->act_translator

#define ClientEOF	Conn->cl.p_closed
#define tcCLOSED	Conn->cl_tcCLOSED
#define cl_sockFd	cl.p_sock	
#define ClientSock	Conn->cl_sockFd
#define ClientSockX	Conn->cl.p_SockX
#define AcceptSock	Conn->clif._acceptSock
#define CLNT_PROTO	Conn->cl.p_proto
/**/
#define CLNT_HOST	Conn->cl.p_host
/**/
#define CLNT_PORT	Conn->cl.p_port

#define InvokeStats	Conn->inv_stats

#define RequestFlags	Conn->req_flags
#define ClientFlags	Conn->cl.p_flags
#define ServerFlags	Conn->sv.p_flags
#define ServerSock	Conn->sv.p_sock
#define ServerSockX	Conn->sv.p_SockX

#define ClientFilter	Conn->cl.p_filter[0]
#define ServerFilter	Conn->sv.p_filter[0]

#define PF_RIDENT	0x0001
#define PF_RIDENT_SENT	0x0002
#define PF_RIDENT_OFF	0x0004
#define PF_RIDENT_RECV	0x0008
#define PF_STLS_CHECKED	0x0010
#define PF_STLS_DO	0x0020
#define PF_STLS_OPT	0x0040
#define PF_STLS_SSL	0x0080
#define PF_STLS_ON	0x0100
#define PF_SSL_ON	0x0200 /* sslway inserted */
#define PF_STLS_CAP	0x0400 /* the peer server announces STARTTLS capable */
#define PF_STLS_DONTTRY	0x0800 /* don't try STARTTLS if not announced */
#define PF_ADMIN_SW	0x1000 /* switched to HTTP for /-/admin/ */
#define PF_ADMIN_ON	0x2000 /* executing /-/admin/ */
#define PF_WITH_YYMUX	0x4000 /* with YYMUX */
#define PF_UA_MSIE	0x8000 /* the client is MSIE ;-< */
#define PF_AS_PROXY	0x00010000 /* acting as a proxy */
#define PF_SSL_IMPLICIT	0x00020000 /* SSL implied */
#define PF_MITM_DO	0x00040000 /* SSL man-in-the-middle mode */
#define PF_MITM_ON	0x00080000 /* SSL man-in-the-middle mode */
#define PF_MITM_SPOT	0x00800000 /* spot MITM by -mitm.host.domain */
#define PF_UDP		0x00400000 /* the port is in UDP */
#define PF_WITH_CCX	0x00200000 /* conditional CHARSET is set */
#define PF_DO_STICKY	0x00100000 /* force StickyServer */
#define PF_DO_PREFILTER	0x01000000 /* insert pre-filter even for CFI */
#define PF_NO_CFI_DELAY	0x02000000 /* don't delay inserting (response) CFI */
#define PF_CFI_DELAY_ON 0x04000000 /* delaying insertion of CFI */
#define PF_VIA_CONNECT	0x08000000 /* connected via the CONNECT method */
#define PF_IS_MASTER	0x10000000 /* ImMaster / toMaster */
#define PF_IS_DISTRIB	0x20000000 /* caching distributor */
#define PF_CREDHY_ON	0x40000000 /* Credhy encription is ON */
#define PF_DO_RESPBUFF	0x80000000 /* do response buffering */

#define ConnFname	Conn->cl.p_connFname
#define DontKeepAlive	Conn->cl.p_dontKeepAlive
#define ClntKeepAlive	Conn->cl.p_wantKeepAlive
#define WillKeepAlive	Conn->cl.p_willKeepAlive
#define SentKeepAlive	Conn->cl.p_sentKeepAlive
#define StopKeepAlive	Conn->cl.p_stopKeepAlive
#define WhyClosed	Conn->cl.p_whyclosed
/**/
#define ServKeepAlive	Conn->sv.p_sentKeepAlive

#define CFI_SYNC	Conn->xf_sync
#define EchoRequest	Conn->xf_echoreq
#define CLNT_USER	Conn->cl_user

#define Client_VAddr	(&Conn->cl_peerAddr)
#define Client_Addr(a)	VA_inetNtoah(Client_VAddr,AVStr(a))
#define Client_Host	Conn->cl_peerAddr.a_name
/**/
#define Client_Port	Conn->cl_peerAddr.a_port
#define Client_Ident	Conn->cl_Ident

#define Origdst_VAddr	(&Conn->cl_origHOST)
#define Origdst_Addr(a)	VA_inetNtoah(Origdst_VAddr,AVStr(a))
#define Origdst_Host	Origdst_VAddr->a_name
#define Origdst_Port	Origdst_VAddr->a_port

#define RequestMethod	Conn->cl_reqmethod
#define RequestLength	Conn->cl_reqlength
#define RequestSerno	Conn->cl.p_reqserno
#define ServReqSerno	Conn->sv.p_reqserno
#define CKA_Timeout	Conn->sv_ka_timeout
#define CKA_RemAlive	Conn->sv_ka_remalive

#define SvPortMap	Conn->sv_pm
#define SvPortMapType	Conn->sv_pm.pm_type
#define SVPM_CLIF	1
#define SVPM_CLIENT	2
#define SVPM_ORIGDST	3
#define SVPM_ORIGSRC	4
#define sv_portmap	sv_pm.pm_portmap

#define DFLT_PROTO	Conn->sv_dflt.p_proto
/**/
#define DFLT_HOST	Conn->sv_dflt.p_host
/**/
#define DFLT_PORT	Conn->sv_dflt.p_port
#define DFLT_SITE	Conn->sv_dflt.p_site
#define DFLT_PORTMAP	Conn->sv_portmap
#define DFLT_AUTH	Conn->sv_dflt.p_auth
#define DFLT_USER	(DFLT_AUTH?DFLT_AUTH->i_user:"")
#define DFLT_PASS	(DFLT_AUTH?DFLT_AUTH->i_pass:"")

#define REAL_PROTO	Conn->sv.p_proto
/**/
#define REAL_HOST	Conn->sv.p_host
/**/
#define REAL_PORT	Conn->sv.p_port
#define REAL_USER	Conn->sv.p_user
#define REAL_SITE	Conn->sv.p_site
#define DST_USER	(REAL_USER[0] ? REAL_USER : NULL)
#define IsAnonymous	Conn->sv.p_anonymous

#define DST_PROTO	(REAL_HOST[0] ? REAL_PROTO : DFLT_PROTO)
/**/
#define DST_HOST	(REAL_HOST[0] ? REAL_HOST  : DFLT_HOST)
#define DST_PORT	(REAL_HOST[0] ? REAL_PORT  : DFLT_PORT)

#define REMOTE_PROTO	Conn->sv_remote.p_proto
/**/
#define REMOTE_HOST	Conn->sv_remote.p_host
/**/
#define REMOTE_PORT	Conn->sv_remote.p_port

#define ConnType	Conn->sv.p_connType
#define ConnError	Conn->sv.p_connError
#define IsInternal	Conn->co_internal
#define IsLocal		Conn->co_local
#define CONN_START	Conn->co_start
#define CONN_DONE	Conn->co_done
#define ConnDelay	Conn->co_delay
#define PERMIT_GLOBAL	Conn->permitGlobal

#define PadCRLF		Conn->ht_PadCRLF
#define SimpleContType	Conn->ht_SimpleContType
#define LockedByClient	Conn->ht_LockedByClient
#define httpStat	Conn->ht_stat
#define httpStatX	Conn->ht_statx
#define genETag		Conn->ht_genETag
#define addRespHeaders	Conn->ht_addRespHeaders
#define DELEGATE_FLAGS	Conn->ht_flags
/**/
#define RespWithBody	Conn->resp_with_body

#define reqPARTIAL	(0 < Conn->cl.p_range[0] || 0 < Conn->cl.p_range[1])
#define reqPART_FROM    (0 < Conn->cl.p_range[0] ? Conn->cl.p_range[0] : 0)
#define reqPART_TO	(0 < Conn->cl.p_range[1] ? Conn->cl.p_range[1] : 0)
/* FileSize reqPART_FROM,reqPART_TO; */
#define gotPART_FROM	Conn->sv.p_range[0]
#define gotPART_TO	Conn->sv.p_range[1]
#define gotPART_SIZE	Conn->sv.p_range[2]

#define CO_REJECTED	1
#define CO_CANTRESOLV	2
#define CO_CANTCONN	4
#define CO_TIMEOUT	8
#define CO_REFUSED	0x10
#define CO_UNREACH	0x20
#define CO_NOROUTE	0x40 /* no available route in CONNECT */
#define CO_CLOSED	0x100 /* logically closed (eg. by QUIT command) */

/*
#define MountOptions	Conn->mo_options
*/
extern const char *getMountOptions(FL_PAR,Connection *Conn);
extern const char *setMountOptions(FL_PAR,Connection *Conn,PCStr(opts));
#define MountOptions	getMountOptions(FL_ARG,Conn)
#define MO_MasterHost	Conn->mo_master.p_host
/**/
#define MO_MasterPort	Conn->mo_master.p_port
#define MO_ProxyHost	Conn->mo_proxy.p_host
/**/
#define MO_ProxyPort	Conn->mo_proxy.p_port
#define MO_Authorizer	Conn->mo_authorizer
/**/
#define withTmpProxy()	(MO_ProxyHost[0] && MO_ProxyPort)
#define withTmpMaster()	(MO_MasterHost[0] && MO_MasterPort)

#define PN_LONG		"host=%A (%H); port=%P;"
#define PN_ADDRHOSTPORT	"%A %H %P"
#define PN_HOSTPORT	"%H:%P"
#define PN_ADDRPORT	"%A:%P"
#define PN_HOST		"%H"
#define PN_PORT		"%P"
#define PN_ADDR		"%A"

#define CONN_NOPROXY	1
#define CONN_NOMASTER	2
#define CONN_NOSOCKS	4
#define CONN_DIRECTONLY	8

#define SV_RETRY_DO	0x1000
#define SV_RETRY_DONE	0x2000

#endif
