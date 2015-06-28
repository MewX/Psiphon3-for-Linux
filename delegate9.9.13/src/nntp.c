/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	nntp.c (NNTP proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	March94	created
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
static void recvMssg(FILE *fs,FILE *afp,int withEOR){
	char line[1024];
	while( fgets(line,sizeof(line),fs) != NULL ){
		if( line[0] == '.' )
		if( line[1] == '\r' || line[1] == '\n' ){
			if( afp && withEOR )
				fputs(line,afp);
			break;
		}
		if( afp )
			fputs(line,afp);
	}
}

#include "ystring.h"
#include "delegate.h"
#include "filter.h"
#include "yselect.h" /* FD_SETSIZE */
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "auth.h"

int commandMount(Connection *Conn,PVStr(req),PVStr(com),PVStr(arg)){
	const char *opts;
	IStr(xreq,1024);
	IStr(crlf,8);
	refQStr(np,req);
	IStr(xcom,128);
	IStr(xarg,1024);
	int slen;

	sprintf(xreq,"command:%s/%s",com,arg);
	if( req ){
		if( strpbrk(arg,"\r\n") == 0 ){
			if( np = strpbrk(req,"\r\n") ){
				strcpy(crlf,np);
			}
		}
	}

	strsubst(AVStr(xreq)," ","%20");
	opts = CTX_mount_url_to(Conn,"",com,AVStr(xreq));
	if( opts == 0 )
		return 0;

	if( strneq(xreq,"data:;,",slen=7)
	 || strneq(xreq,"command:",slen=8)
	){
		strsubst(AVStr(xreq),"%20"," ");
		Xsscanf(xreq+slen,"%[^/]/%[^\r\n]",AVStr(xcom),AVStr(xarg));
		if( xcom[0] ){
			sv1log("##CM [%s][%s]->[%s][%s]\n",com,arg,xcom,xarg);
			strcpy(com,xcom);
			strcpy(arg,xarg);
			if( req ){
				sprintf(req,"%s %s%s",xcom,xarg,crlf);
			}
			return 1;
		}
	}
	return 0;
}
static void RecvMssg(FILE *fs,FILE *afp,int withEOR){
	recvMssg(fs,afp,withEOR);
}

#undef fopen
#define fopen(file,mode) news_fopen(__FILE__,__LINE__,file,mode)
FILE *news_fopen(const char *F,int L,const char *file,const char *mode);
const char *strid_alloc(PCStr(str));
int getClientSockPeer(PVStr(sockname),PVStr(peername));
void setOriginIdent(Connection *Conn,PCStr(sockname),PCStr(peername));

void ENEWS_addspool(PCStr(dir),int recursive);
FILE *ENEWS_article(PCStr(msgid),PCStr(group),int anum);
int ENEWS_group(PCStr(group),int *total,int *min,int *max);
int ENEWS_list(FILE *out,int is_filegroup);
int ENEWS_listX(FILE *out,int is_filegroup,int date);
void ENEWS_newnews(FILE *out,PCStr(group),int date);
int ENEWS_path(PCStr(msgid),PVStr(artpath),int is_filegroup);
int ENEWS_post(PVStr(stat),FILE *afp,PCStr(agroup),PCStr(asubj),PCStr(afrom));

extern const char *MIME_transAddrSpec;
extern const char *MIME_nomapMailAddrs;
extern const char *MIME_mapPosterBase;

int LIST_compress(FILE *in,FILE *out,int isactive,int level);
int LIST_uncompress(FILE *in,FILE *out,int isactive);

#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)
#define getFV(str,fld,buf)             getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
extern int IO_TIMEOUT;

/*
#define MAXGROUPS	100000
*/
#define MAXGROUPS	300000
#define LINESIZE	4095
#define IOBSIZE		(32*1024)

#define	NSERVER		16
#define NMOUNT		128

#define S_RESUME	0
#define S_NOSUSP	1
#define S_TOBECC	2
#define S_TOQUIT	3
#define S_TOCLOSE	4
#define S_ERROR	       -1
#define S_CLEOF        -2

typedef struct _pathHosts {
	struct {
	  const	char	*ph_server;	/* real name */
	  const	char	*ph_pathhost;	/* path name */
	} ph_hosts[64]; /**/
	int	ph_hostN;
} pathHosts;

typedef struct _tmpFile {
	FILE   *tf_fp;
	int	tf_owner;
	int	tf_session;
} tmpFile;

typedef struct _RequestQ {
struct _Request	*rq_top;
struct _Request *rq_tail;
	int	 rq_leng;
} RequestQ;
#define QueueLeng	reqQue.rq_leng
#define QueueTop	reqQue.rq_top
#define QueueTail	reqQue.rq_tail

typedef struct _NNTPenv {
	int	ne_dispensable;	/* NNTPCONF=dispensable */
	int	ne_NICE_VAL;	/* NNTPCONF=nice:N */
	int	ne_qlog;	/* NNTPCONF=log:Q */
  const	char   *ne_RESPLOG;	/* NNTPCONF=resplog:... */

struct _pathHosts ne_pathHosts;	/* NNTPCONF=pathhost:... or opening mssg. */
	int	ne_needAuthClnt;/* NNTPCONF=auth:... list of client hosts which
				 * must do Authentication to start a sesssion */
	int	ne_needAuthCom;	/* NNTPCONF=authcom:... is specified */
	int	ne_withAuth;	/* the client or at least one of servers is
				 * with AUTHINFO */
	int	ne_needProxyAuth; /* with AUTHORIZER */
	int	ne_proxyAuthOK;
	MStr(	ne_proxyUSER,64); /* which may be forwarded to server asis. */
	MStr(	ne_proxyPASS,64); /* which may be forwarded to server asis. */

	int	ne_group_nameid;/* group name to group id trans. tab. */
	int	ne_permitted_nsid; /* group to nsid translation table */
struct _Mount  *ne_Mounts;	/* mount table */
	int	ne_MountN;	/* total number of newsgroup Mounts */
struct _Server *ne_Servers;	/* server table */
	int	ne_NserverN;	/* total number of Servers */
	int	ne_restricted;	/* Mounts with restriction of groups */
	int	ne_mounted;	/* Mounts with group rewriting */
	int	ne_hidden;	/* Mounts with "hide" option */
	int	ne_writable;	/* Moonts withtout read-only (POSTable) */

	int	ne_initialized;	/* servers are initialized */
	int	ne_server_done;
	int	ne_no_activesv;	/* no active servers */
	int	ne_resp_errors;	/* the current number of continuous errors */
	int	ne_imCC;	/* I'm acting as a NNTPCC server */
	int	ne_compressLIST; /* do COMPRESS LIST for the client */

	int	ne_FSlineCNT;	/* total count of lines got from servers */
  const	char   *ne_LAST_ERROR;	/* the last error stat. from servers */
	int	ne_penalty;	/* accumulated penalty */
	int	ne_lastPenaltySleep; /* the time of last penalty sleep */

	struct {
	defQStr(ne_CGroup);	/* curGroup buffer */
	} ne_CGroup;
	struct {
	defQStr(ne_PGroup);	/* prevGroup buffer */
	} ne_PGroup;
	MStr(	ne_LastGroup,256); /* group-name -> server-id cache */
	char	ne_LastServerx;	/* ID of LastGroup */

struct _RequestQ ne_reqQue;	/* queue of requests expected for responses */

	int	ne_curNsid;	/* current server (for current response) */
	MStr(	ne_curCommand,256); /* current command line (for the response) */
	MStr(	ne_curComd,64);	/* current command (for current response) */
	int	ne_curAnum;	/* current article (for current response) */

	MStr(	ne_clientIF_FQDN,128); /* FQDN of client-side net. interface */
	int	ne_clientID;	/* session ID in this DeleGate process */

	tmpFile	ne_tmpFiles[8];	/**//* reusable temporary files */

	int	ne_doProtoLog;
	int	ne_lastRcode;

    const char *ne_ondemand;	/* 9.9.5 NNTPCONF="ondemand" */
	char	ne_redirecting_serv[64]; /* stat. for sync. in redirection */
	int	ne_redirecting_tid[64]; /* tid of the exiting stab server */
} NNTPenv;

static NNTPenv *NNTP_context;
#define NX	NNTP_context[0]

void minit_nntp(){
	if( NNTP_context == 0 )
		NNTP_context = NewStruct(NNTPenv);
}

#define NE_dispensable	NX.ne_dispensable
#define NICE_VAL	NX.ne_NICE_VAL
#define qlog		NX.ne_qlog
#define Qlog qlog==0?0:sv1log
#define RESPLOG		NX.ne_RESPLOG

#define pathhosts	NX.ne_pathHosts.ph_hosts
#define pathhostN	NX.ne_pathHosts.ph_hostN

#define needAuthClnt	NX.ne_needAuthClnt
#define needAuthCom	NX.ne_needAuthCom
#define withAuth	NX.ne_withAuth
#define needProxyAuth	NX.ne_needProxyAuth
#define proxyAuthOK	NX.ne_proxyAuthOK
#define proxyUSER	NX.ne_proxyUSER
/**/

#define group_nameid	NX.ne_group_nameid
#define permitted_nsid	NX.ne_permitted_nsid
#define Mounts		NX.ne_Mounts
#define MountN		NX.ne_MountN
#define _NS		NX.ne_Servers
#define Nservers \
	(_NS ? _NS : (_NS = (NewsServer*)calloc(NSERVER,sizeof(NewsServer))))
#define NserverN	NX.ne_NserverN
#define restricted	NX.ne_restricted
#define mounted		NX.ne_mounted
#define hidden		NX.ne_hidden
#define writable	NX.ne_writable
#define COMPLEX	(1 < NserverN || restricted || hidden || mounted)

#define initialized	NX.ne_initialized
#define server_done	NX.ne_server_done
#define no_activesv	NX.ne_no_activesv
#define resp_errors	NX.ne_resp_errors
#define imCC		NX.ne_imCC
#define compressLIST	NX.ne_compressLIST

#define _CGroup		NX.ne_CGroup.ne_CGroup
#define _PGroup		NX.ne_PGroup.ne_PGroup
#define curGroup	(_CGroup ? _CGroup : (setQStr(_CGroup,(char*)calloc(512,1),512)))
#define prevGroup	(_PGroup ? _PGroup : (setQStr(_PGroup,(char*)calloc(512,1),512)))
/**/ 
/**/ 
/*
#define curGroup	(_CGroup ? _CGroup : (_CGroup = (char*)calloc(512,1)))
#define prevGroup	(_PGroup ? _PGroup : (_PGroup = (char*)calloc(512,1)))
*/
#define LastGroup	NX.ne_LastGroup
/**/
#define LastServerx	NX.ne_LastServerx

#define reqQue		NX.ne_reqQue

#define FSlineCNT	NX.ne_FSlineCNT
#define LAST_ERROR	NX.ne_LAST_ERROR
#define penalty		NX.ne_penalty
#define lastPenaltySleep	NX.ne_lastPenaltySleep

#define curNsid		NX.ne_curNsid
#define curCommand	NX.ne_curCommand
#define curComd		NX.ne_curComd
/**/
#define curAnum		NX.ne_curAnum

#define clientIF_FQDN	NX.ne_clientIF_FQDN
/**/
#define clientID	NX.ne_clientID

#define TF_LISTTMP1	1 /* tmpfile for mergeLIST() */
#define TF_LISTTMP2	2 /* tmpfile for mergeLIST() */
#define TF_DELTAORIG	3 /* last original LIST used to make delta LIST */
#define TF_DELTABUFF	4 /* current delta LIST */
#define TF_ARTICLE	5 /* result of openArticle() (duplicated before use) */
#define lastLIST	NX.ne_tmpFiles[TF_DELTAORIG].tf_fp

#define doProtoLog	NX.ne_doProtoLog
#define lastRcode	NX.ne_lastRcode

typedef struct {
	MStr(	s_stdobuf,IOBSIZE);
	MStr(	s_reqbuf,1024);
} Session;
#define ReqBuf	Sp->s_reqbuf
/**/

/*
 * if owner process has changed, closed and open new file (don't share).
 * if session has changed with the same owner, clear previous content
 */
static FILE *getTmpfile(PCStr(what),int which,int session,int bsize)
{	FILE *tfp;
	int owner;
	tmpFile *tf;
	const char *tmpiob;

	owner = getpid();
	tf = &NX.ne_tmpFiles[which];
	tfp = tf->tf_fp;

	if( tfp != NULL && tf->tf_owner == owner ){
		fseek(tfp,0,0);
		if( tf->tf_session != session ){
			Ftruncate(tfp,0,0);
			tf->tf_session = session;
		}
	}else{
		if( tfp != NULL )
			fclose(tfp);
		tfp = TMPFILE(what);
		if( tfp == NULL ){
			return NULL;
		}
		if( bsize ){
			tmpiob = (char*)malloc(bsize);
			setbuffer(tfp,(char*)tmpiob,bsize);
		}
		tf->tf_fp = tfp;
		tf->tf_owner = owner;
		tf->tf_session = session;
	}
	return tfp;
}


#include <ctype.h>
#define IS_GROUPNAMECH(ch) (isalnum(ch) || ch=='-' || ch=='.' || ch=='_')

static void putIdent(FILE *tc,PCStr(msg))
{	CStr(host,128);

	gethostName(fileno(tc),AVStr(host),PN_HOST);
	fprintf(tc,"200 %s PROXY NNTP server %s DeleGate/%s READY.\r\n",
		host,msg,DELEGATE_ver());
}

#define isEOH(resp)	(resp[0]=='\r' || resp[0]=='\n')
#define isEOR(resp)	(resp[0]=='.' && (resp[1]=='\r'||resp[1]=='\n'))

#define Upconf		0 /* configuration check interval */
#define Upacts		1
#define Upact_some	1 /* got by someone else (at invocation) */
#define Upact_mine	2 /* got by myself (reloading) */
#define Upact_post	3 /* force upact after POST */
#define Cc_timeout	4 /* connection timeout to server in client side CC */
#define Popcc_time	5 /* timeout in POP-CC */
#define Xover_max	6 /* max articles in XOVER range */
#define Penalty_sl	7 /* do sleep as penalty */
#define Penalty_ex	8 /* exit on errors */
#define NntpCc		9 /* do Connection Cache */
#define NntpPopCc	10 /* do Connection Cache for POP/NNTP */
#define MaxConnHold	11

typedef struct {
	int	sciv[16];
} ServConf;
static ServConf NNTP_tab_globalNumConf = {
	30*60,	/* Upconf */
	600,	/* Upact_some */
	300,	/* Upact_mine */
	60,	/* Upact_post */
	10,	/* Cc_timeout */
	120,	/* Popcc_time */
	2000,	/* Xover_max */
	0,	/* Penalty_sl */
	0,	/* Penalty_ex */
	1,	/* NntpCc */
	1,	/* NntpPopCc */
	180,	/* MaxConnHold */
};
#define globalNumConf	NNTP_tab_globalNumConf
#define UPCONF		globalNumConf.sciv[Upconf]
#define UPACTS		globalNumConf.sciv[Upacts]
#define CLCC_TIMEOUT	globalNumConf.sciv[Cc_timeout]
#define POPCC_TIMEOUT	globalNumConf.sciv[Popcc_time]
#define XOVER_MAX	globalNumConf.sciv[Xover_max]
#define PENALTY_SLEEP	globalNumConf.sciv[Penalty_sl]
#define EXIT_ON_ERRORS	globalNumConf.sciv[Penalty_ex]
#define NNTP_CC		globalNumConf.sciv[NntpCc]
#define NNTP_POPCC	globalNumConf.sciv[NntpPopCc]
#define MAX_CONNHOLD	globalNumConf.sciv[MaxConnHold]


#define UPACT_SOME	ns->ns_myconf.sciv[Upact_some]
#define UPACT_MINE	ns->ns_myconf.sciv[Upact_mine]
#define UPACT_POST	ns->ns_myconf.sciv[Upact_post]

static struct {
  const	char	*cs_lib;	/* name of lib dir */
  const	char	*cs_spool;	/* name of spool dir */
  const	char	*cs_xover;	/* name of xover dir */
  const	char	*cs_overview_fmt;
  const	char	*cs_XCACHE_usage;
} NNTP_tab_globalStrConf = {
	"lib",
	"spool",
	"xover",
	"Subject,From,Date,Message-ID,References,Bytes,Lines",
	"XCACHE FETCH|EXPIRE [range|yymmdd hhmmss|message-id]",
};
#define globalStrConf	NNTP_tab_globalStrConf
#define DIR_LIB		globalStrConf.cs_lib
#define DIR_SPOOL	globalStrConf.cs_spool
#define DIR_XOVER	globalStrConf.cs_xover
#define overview_fmt	globalStrConf.cs_overview_fmt
#define XCACHE_usage	globalStrConf.cs_XCACHE_usage

typedef struct _ListCache {
	char	 *lc_path;
	FILE	 *lc_fp;
	char	 *lc_iobuf;
	int	  lc_timeoff;	/* if on NFS with time difference */
	int	  lc_lastcheck;	/* mtime of the one I checked last */
	int	  lc_origmtime;	/* date of original one of the copy */
	int	  lc_private;	/* is a private cache */
} LCache;

#define LCpath(ns,li)		ns->ns_Lists[li].lc_path
#define LCiobuf(ns,li)		ns->ns_Lists[li].lc_iobuf
#define LCfp(ns,li)		ns->ns_Lists[li].lc_fp
#define LClastcheck(ns,li)	ns->ns_Lists[li].lc_lastcheck
#define LCisprivate(ns,li)	ns->ns_Lists[li].lc_private
#define LCorigmtime(ns,li)	ns->ns_Lists[li].lc_origmtime
#define LCtimeoff(ns,li)	ns->ns_Lists[li].lc_timeoff

#define LI_ACTIVE	0
#define LI_NGS		1
static const char *NNTP_tab_list_types[] = {
	"active",
	"newsgroups",
	0
};
#define lists	NNTP_tab_list_types

typedef struct _Mount {
	int	 nm_nsid;
  const	char	*nm_user;
  const	char	*nm_pass;
  const	char	*nm_base;
  const	char	*nm_group;
  const	char   **nm_hide;
  const	char	*nm_rewaddr;
  const char    *nm_rewposter;
  const	char	*nm_hideop;
	short	 nm_baselen;
	short	 nm_grouplen;
	int	 nm_flags;
} NgMount;
#define MF_RO		1
#define MF_NOCLMIME	2
#define MF_NOSVMIME	4

/* { -1, 0, 1 } */
#define V_DISABLED ((char)-1)
#define V_UNINIT	  0
#define	V_TURE		  1

typedef struct _Server {
	/* counters */
	short	  ns_nsid;
	short	  ns_mountn;
	short	  ns_mounted;
	short	  ns_mounted_file;
	short	  ns_restricted;
	short	  ns_hidden;
	short	  ns_ro;
	short	  ns_rw;
	int	  ns_respcnt;

	/* 0, 1 */
	char	  ns_isself;
	char	  ns_islocal;
	char	  ns_isdummy;
	char	  ns_isCC;
	char	  ns_gotpathhost;
	char	  ns_noact;
	char	  ns_nocache;
	char	  ns_emulate;

	/* -1, 0, 1 */
	char	  ns_dispensable; /* 0:indispensable, 1:active, -1:disabled */
	char	  ns_withXPATH;
	char	  ns_withCOMPRESS;
	char	  ns_withLISTwildmat; /* with LIST ACTIVE [wildmat] */

	ServConf  ns_myconf;

  const	char	 *ns_rewaddr;
  const	char	 *ns_rewposter;
	MStr(	  ns_proto,32);
  const	char	 *ns_host;
  const	char	 *ns_hostFQDN;
	int	  ns_port;
  const	char	 *ns_auser;
  const	char	 *ns_apass;
	int	  ns_needAuth;
	int	  ns_authOK;
	int	  ns_authERR;
	FILE	 *ns_rfp;
	FILE	 *ns_wfp;
  const	char	 *ns_openingmsg;
  const	char	 *ns_helpmsg;

  const	char	 *ns_GROUP;
  const	char	 *ns_GROUP_RESP;

	LCache	  ns_Lists[4]; /**/

	int	  ns_OPENtime;
	int	  ns_POSTtime;
	int	  ns_LISTtime;
	int	  ns_lastGROUP;
	int	  ns_posted;
	NgMount	**ns_mounts;
  const	char	 *ns_curgroupR;
  const	char	 *ns_curgroup;
	int	  ns_curanum;
	int	  ns_cacheused;
	int	  ns_artcache;
     Connection  *ns_Conn;
	int	  ns_serverFlags;
	MStr(	  ns_client_Addr,128);

	int	  ns_ondemand; /* MountOption "ondemand" */
	int	  ns_ondemand_tid; /* the thread for a stab server */
	int	  ns_ondemand_yet; /* not connected to the server yet */
	char	  ns_NEWGROUPS_gen; /* generated empty NEWGROUPS */
	char	 *ns_actcache[2][128]; /* ACTIVE list cache */
} NewsServer;

#define TRACE syslog_ERROR
typedef struct {
	int	 f_sv[2];
	FILE	*f_tcx;
	FILE	*f_tci;
	int	 f_tid;
} FilterDesc;
int clearFD(FilterDesc *FD);
int setupFD(FilterDesc *FD);
int closeFD(FilterDesc *FD);
static int setOnDemand(PCStr(opts));
static int ondemandServ(Connection *Conn,NewsServer *ns,int dmndsv[2]);
static int waitRequest(Connection *Conn,FILE *fc,FILE *tc);
static int ondemand_serv(Connection *Conn,int svsock,int clsock,NewsServer *ns);
static int waiting_ondemand_serv(FL_PAR,FILE *fs);
static int clearActCache(NewsServer *ns);
static int isServerOfX(NewsServer *ns,FILE *lf,PCStr(group));
static int putGROUPcache(NewsServer *ns,PCStr(stat));
static int relayLIST(FILE *tci,FILE *tc,int dofilter);
static int updateNEWGROUPS(NewsServer *ns,PCStr(qdates),int ngop);
#define NGOP_TO_UPDATE	10 /* true if to be updated for a date */
#define NGOP_GOT_EMPTY	20 /* found no update after a date */
#define NGOP_GOT_UPDATE	30 /* found updated after a date */
static int hostcmpX(PCStr(h1),PCStr(h2));
#define hostcmp(h1,h2) hostcmpX(h1,h2)

#define CACHE_ARTICLE	1
#define CACHE_OVERVIEW	2
#define CACHE_LIST	4
#define CACHE_ALL	0xFF

#define EMULATE_XHDR	1
#define EMULATE_XOVER	2
#define EMULATE_ALL	0xFF

static void setListcache(NewsServer *ns,int li,FILE *lfp,int timeoff,int xprivate)
{
	LCfp(ns,li) = lfp;
	LCtimeoff(ns,li) = timeoff;
	LCisprivate(ns,li) = xprivate;
}

typedef struct _Client {
     Connection *nc_Conn;
	FILE	*nc_rfp;
	FILE	*nc_wfp;
	int	 nc_do_afterflush;
	NewsServer *nc_do_ns;
	struct {
		MStr(	r_req,512);
		MStr(	r_com,256);
		MStr(	r_arg,256);
	} nc_do_req;
	struct {
		MStr(	D_group,1024);
		MStr(	D_rgroup,1024);
		MStr(	D_status,1024);
		int	nsid;
		NewsServer *ns;
	} nc_do_GRP; /* for private GROUP */
} NewsClient;
#define DO_afterflush	nc->nc_do_afterflush
#define DO_ns		nc->nc_do_ns
#define DO_req		nc->nc_do_req.r_req
/**/
#define DO_com		nc->nc_do_req.r_com
/**/
#define DO_arg		nc->nc_do_req.r_arg
/**/
#define GRP		nc->nc_do_GRP

extern char mailClientId[16];
extern char mailClientAddr[32];
extern char mailPosterId[16];
void getClientAddrId(Connection *Conn,PVStr(saddr),PVStr(sid));
const char *getClientRident(Connection *Conn,PVStr(clntb));

static void nntplog(NewsClient *nc,NewsServer *ns,int code,PCStr(group)){
	Logfile *log;
	CStr(line,1024);
	CStr(sdate,1024);
	const char *clnt;
	CStr(clntb,256);
	Connection *Conn = nc->nc_Conn;

	if( doProtoLog < 0 )
		return;
	log = LOG_which("nntp",LF_PROTOLOG,0);
	if( log == 0 ){
		doProtoLog = -1;
		return;
	}
	clnt = getClientRident(Conn,AVStr(clntb));
	StrftimeLocal(AVStr(sdate),sizeof(sdate),"%Y%m%d-%H%M%S",time(0),0);
	sprintf(line,"%s %d %s-%s %s %s %d %s:%d \"%s\"\n",sdate,getpid(),
		mailPosterId,mailClientId,clnt,proxyUSER[0]?proxyUSER:"-",
		code,curGroup,curAnum,curCommand);
	LOG_write(log,line,strlen(line));
	LOG_flushall();
}

#define DO_RELOAD	 0

#define WITH_CACHE	 1
#define NO_CACHE	-1

#define NO_EXPIRE	-1
#define CACHE_ONLY	-2
#define CACHE_MAKE	-3
#define CACHE_ANY(exp)	(exp == NO_EXPIRE || exp == CACHE_ONLY)

#define DONTCACHE(ns)	(ns->ns_isCC || ns->ns_isdummy)

static NgMount *Mount(int mx)
{
	if( Mounts == NULL )
		Mounts = (NgMount*)calloc(NMOUNT,sizeof(NgMount));
	return &Mounts[mx];
}

#define toNSX(nsid)	(nsid-1)
#define toNS(nsid)	(&Nservers[nsid-1])
#define toNSID(nsx)	(nsx+1)
#define FPUTS(s,fp)	(fp != NULL ? Fputs(s,fp) : EOF)
#define FFLUSH(fp)	(fp != NULL ? fflush(fp) : 0)

typedef struct {
	int	 rs_code;
	int	 rs_resp;
	int	 rs_senddata;
	int	 rs_coding;
  const	char	*rs_name;
} RespStatus;

#define D_THRU	0
#define D_HEAD	1
#define D_BODY	2
#define D_MIME	3
#define D_OVER	5

/*
 *	Status codes followd by a response body
 */

#define RC_OK_COMPRESS	290
#define RC_NO_ACTIVES	509

static RespStatus NNTP_tab_resp_stats[] = {
	{100,1,0,D_THRU, "HELP"},
	{199,1,0,D_THRU, "DEBUG"},
	{215,1,0,D_THRU, "LIST"},
	{220,1,0,D_MIME, "ARTICLE"},
	{221,1,0,D_HEAD, "HEAD"},
	{222,1,0,D_BODY, "BODY"},
	{224,1,0,D_OVER, "XOVER"},
	{230,1,0,D_THRU, "NEWNEWS"},
	{231,1,0,D_THRU, "NEWGROUPS"},
	{335,0,1,D_THRU, "XFER"},
	{380,0,1,D_THRU, "AUTHINFO"},
	0
};
#define nntp_stats	NNTP_tab_resp_stats

static int match_pathhost(PCStr(server),PCStr(pathhost))
{	int pi;
	const char *s1;

	for( pi = 0; pi < pathhostN; pi++ ){
		s1 = pathhosts[pi].ph_server;
		if( hostcmp(s1,server) == 0 )
		if( strcasecmp(pathhosts[pi].ph_pathhost,pathhost) == 0 )
			return 1;
	}
	return 0;
}
static void add_pathhost1(PCStr(server),PCStr(pathhost))
{
	if( match_pathhost(server,pathhost) )
		return;

	if( elnumof(pathhosts) <= pathhostN ){
		return;
	}
	pathhosts[pathhostN].ph_server = stralloc(server);
	pathhosts[pathhostN].ph_pathhost = stralloc(pathhost);
	pathhostN++;
	return;
}
static void add_pathhost(PCStr(pair))
{	CStr(server,128);
	CStr(pathhost,1024);

	if( Xsscanf(pair,"%[^/]/%s",AVStr(server),AVStr(pathhost)) != 2 ){
		sv1log("ERROR NNTPCONF=pathhost:%s\n",pair);
		return;
	}
	add_pathhost1(server,pathhost);

	sv1log("NNTPCONF=pathhost:%s/%s\n",server,pathhost);
	if( !IsResolvable(server) )
		sv1log("WARNING -- unknown host[%s]\n",server);
}

static void scan_upacts(PCStr(what),PCStr(value),int upacts[])
{	int invoke,reload,posted;

	invoke = reload = posted = -1;
	sscanf(value,"%d/%d/%d",&invoke,&reload,&posted);
	if( 0 <= invoke ) upacts[0] = invoke;
	if( 0 <= reload ) upacts[1] = reload;
	if( 0 <= posted ) upacts[2] = posted;
	sv1log("%s=upact:%d/%d/%d\n",what,upacts[0],upacts[1],upacts[2]);
}

static void setNeedAuthMethod(PCStr(methods));
static int nservers_remote();
static void closeSVStream(NewsServer *ns);
static int wait_resume(NewsServer *ns,FILE *fc,int timeout);
static int suspend(Connection *Conn,int timeout,FILE *fc,FILE *tc,int nserv,NewsServer *servers);
static int canbeNNTPCC(Connection *Conn);
void service_nntpX(Connection *Conn,Session *Sp);
void NNTP_XOVER(FILE *fc,FILE *tc,int nsid,PCStr(group),PCStr(arg));
FILE *NNTP_openARTICLEC(int nsid,int expire,PCStr(group),int anum,PVStr(cpath));
FILE *NNTP_openARTICLE(int nsid,int expire,PCStr(group),int anum,PVStr(cpath));
static FILE *spoolArticle(int nsid,FILE *afp,PCStr(group),int anum);
void expireArticle(PCStr(cpath));
void insertField(FILE *afp,PCStr(fname),PCStr(fvalue));
void NNTP_getGROUP(int nsid,int expire,PCStr(group),int *nart,int *min,int *max);
static void NNTP_CACHE(NewsServer *ns,NewsClient *nc,PCStr(group),PCStr(com),PCStr(arg));
static int POP_findMessageid(FILE *ts,FILE *fs,PCStr(mid));
static void PopNntp(Connection *Conn,PVStr(user));
int connect_to_popgw(Connection *Conn,int fromC,int toC);
extern int EXPIRE_LIST;

static scanListFunc scan1(PCStr(conf),Connection *Conn)
{	CStr(what,128);
	CStr(value,2048);

	value[0] = 0;
	Xsscanf(conf,"%[^:]:%s",AVStr(what),AVStr(value));
	if( strcaseeq(what,"upconf") ){
		UPCONF = atoi(value);
	}else
	if( strcaseeq(what,"nntpcc") ){
		NNTP_CC = atoi(value);
	}else
	if( strcaseeq(what,"popcc") ){
		NNTP_POPCC = atoi(value);
	}else
	if( strcaseeq(what,"upact") ){
		scan_upacts("NNTPCONF",value,&UPACTS);
	}else
	if( strcaseeq(what,"expire.list") ){
		EXPIRE_LIST = (int)Scan_period(value,'s',10*60);
	}else
	if( strcaseeq(what,"pathhost") ){
		add_pathhost(value);
	}else
	if( strcaseeq(what,"overview.fmt") ){
		overview_fmt = stralloc(value);
	}else
	if( strcaseeq(what,"server") ){
		CStr(url,1024);
		sprintf(url,"nntp://%s",value);
		set_MOUNT(Conn,"=",url,"");
	}else
	if( strcaseeq(what,"log") ){
		if( strchr(value,'Q') )
			qlog = 1;
	}else
	if( strcaseeq(what,"resplog") ){
		RESPLOG = stralloc(value);
	}else
	if( strcaseeq(what,"xover") ){
		XOVER_MAX = atoi(value);
	}else
	if( strcaseeq(what,"nice") ){
		NICE_VAL = atoi(value);
	}else
	if( strcaseeq(what,"auth") ){
		if( *value == 0 ) strcpy(value,"*");
		needAuthClnt = makePathList("NNTP-AUTH",value);
	}else
	if( strcaseeq(what,"authcom") ){
		setNeedAuthMethod(value);
	}else
	if( strcaseeq(what,"penalty") ){
		PENALTY_SLEEP = atoi(value);
		sv1log("NNTPCONF=penalty:%d\n",PENALTY_SLEEP);
	}else
	if( strcaseeq(what,"xerrors") ){
		EXIT_ON_ERRORS = atoi(value);
	}else
	if( strcaseeq(what,"dispensable") ){
		NE_dispensable = 1;
	}else
	if( strcaseeq(what,"ondemand") ){
		/* 9.9.5 connecting target servers on demand */
		setOnDemand(value);
	}else
	if( strcaseeq(what,"posterbase") ){
		MIME_mapPosterBase = stralloc(value);
	}else
	if( strcaseeq(what,"nomapemail") ){
		MIME_nomapMailAddrs = stralloc(value);
	}else{
		sv1log("ERROR: unknown config. `%s'\n",conf);
	}
	return 0;
}
void scan_NNTPCONF(Connection *Conn,PCStr(conf))
{
	minit_nntp();
	scan_commaListL(conf,0,scanListCall scan1,Conn);
}
int NNTP_needAuth(Connection *Conn)
{	CStr(host,128);
	int port;

	if( needAuthClnt == 0 )
		return 0;

	port = getClientHostPort(Conn,AVStr(host));
	if( matchPath1(needAuthClnt,"-",host,port) ){
		sv1log("#### AUTHINFO required: %s\n",host);
		return 1;
	}
	return 0;
}
static int proxyAuth(Connection *Conn,PVStr(userpass),PVStr(host))
{	FILE *xtc;
	int rcode;

	xtc = TMPFILE("NNTP-AUTHORIZER");
	rcode = doAUTH(Conn,NULL,xtc,"nntp","-",0,AVStr(userpass),AVStr(host),NULL,NULL);
	fclose(xtc);
	return rcode;
}
int NNTP_authERROR(int nsid)
{	int error;

	error = toNS(nsid)->ns_authERR;
	Verbose("authERROR[%d] = %d\n",nsid,error);
	return error;
}

static int isServerOf(NewsServer *ns,PCStr(group))
{	int glen;
	FILE *lf;
	CStr(line,1024);

	if( !COMPLEX )
		return 1;

	glen = strlen(group);
	if( LClastcheck(ns,LI_ACTIVE) == 0 ){
		sv1log("#### isServerOf(%d,%s): LIST CACHE NOT INITIALIZED\n",
			ns->ns_nsid,group);
		return 0;
	}
	lf = LCfp(ns,LI_ACTIVE);
	fseek(lf,0,0);
	if( NX.ne_ondemand || ns->ns_ondemand ){
		/* 9.9.5 faster ACTIVE LIST matching with cache */
		return isServerOfX(ns,lf,group);
	}
	while( fgets(line,sizeof(line),lf) != NULL )
		if( strncmp(line,group,glen) == 0 && isspace(line[glen]) )
			return 1;
	return 0;
}
static int hidden_group(NgMount *nm,PCStr(group))
{	const char *hide;
	const char *tail;
	int hi;
	int match;

	if( nm->nm_hide == NULL )
		return 0;

	if( nm->nm_hideop[0] == '!' )
		match = 1;
	else	match = 0;

	for( hi = 0; hide = nm->nm_hide[hi]; hi++ ){
		tail = frex_match((struct fa_stat*)hide,group);
		if( tail && *tail == 0 ){
			if( nm->nm_hideop[hi] == '!' )
				match = 0;
			else	match = 1;
		}
	}
	return match;
}

static int permitted_group1(int sx,int making_list,PCStr(group))
{	NewsServer *ns;
	NgMount *nm;
	int mi;

	ns = &Nservers[sx];

	for( mi = 0; mi < ns->ns_mountn; mi++ ){
		nm = ns->ns_mounts[mi];

		if( nm->nm_hide != NULL )
		if( hidden_group(nm,group) )
			return 0;

		if( nm->nm_grouplen == 0 ){
			if( making_list ){
				/* this group is on the server because the very
				 * LIST of the server is being processed here.
				 */
				return toNSID(sx);
			}
		}else{
			if( strncmp(group,nm->nm_group,nm->nm_grouplen) == 0 )
				if( making_list || isServerOf(ns,group) )
					return toNSID(sx);
		}
	}
	if( !making_list )
	if( ns->ns_restricted == 0 )
	if( isServerOf(ns,group) ){
		sv1log("Permitted: %s [%s,M=%d,R=%d]\n",
			group,ns->ns_host,ns->ns_mountn,ns->ns_restricted);
		return toNSID(sx);
	}
	return 0;
}
static int findServer(int nserv,NewsServer *servers,PCStr(group))
{	int si,serverx;
	/*NewsServer *ns;*/

	serverx = -1;
	for( si = 0; si < nserv; si++ ){
		/*ns = &servers[si];*/
		if( permitted_group1(si,0,group) )
		/*if( isServerOf(ns,group) )*/
		{
			serverx = si;
			break;
		}
	}
	return serverx;
}
static int getLISTwildmat(NewsServer *ns,PVStr(wildmat))
{	int mx;
	NgMount *nm;
	refQStr(wp,wildmat); /**/

	cpyQStr(wp,wildmat);
	for( mx = 0; mx < MountN; mx++ ){
		nm = Mount(mx);
		if( nm->nm_nsid == ns->ns_nsid ){
			if( nm->nm_group[0] == 0 ){
				setVStrEnd(wildmat,0);
				break;
			}
			if( wp != wildmat )
				setVStrPtrInc(wp,',');
			strcpy(wp,nm->nm_group);
			wp += strlen(wp);
			setVStrPtrInc(wp,'*');
			setVStrEnd(wp,0);
		}
	}
	return wp - wildmat;
}
static int select_mount(int nserv,NewsServer servers[],PCStr(group),int post)
{	int sx,mx,pmx;
	NgMount *nm;
	NewsServer *ns;

	pmx = -1;
	for( mx = 0; mx < MountN; mx++ ){
	    nm = Mount(mx);
	    if( nm->nm_baselen ){
		if( strncmp(group,nm->nm_base,nm->nm_baselen) == 0 ){
			CStr(rgroup,1024);
			strcpy(rgroup,nm->nm_group);
			strcat(rgroup,group+nm->nm_baselen);
			if( isServerOf(toNS(nm->nm_nsid),rgroup) )
				return mx;
		}
	    }else{
		sx = findServer(nserv,servers,group+nm->nm_grouplen);
		if( toNSID(sx) == nm->nm_nsid )
			return mx;
	    }
	    if( post && pmx < 0 ){
		ns = toNS(nm->nm_nsid);
		if( ns->ns_isself )
			pmx = mx;
	    }
	}
	return pmx;
}
static int select_server_list(NewsClient *nc,int nserv,NewsServer *servers,PCStr(command),PCStr(groups),int sxs[])
{	int mx,sx,nsid;
	CStr(group1,LINESIZE);
	const char *dp;
	Connection *Conn = nc->nc_Conn;

	strcpy(group1,groups);
	if( dp = strchr(group1,',') )
		truncVStr(dp);

	mx = select_mount(nserv,servers,group1,1);
	if( mx < 0 ){
		sv1log("POST Forbidden: unknown newsgroup: %s, NS=%d\n",
			group1,nserv);
		return 0;
	}

	if( Mount(mx)->nm_flags & MF_RO ){
		sv1log("POST Forbidden: READ ONLY: %s (%s)\n",group1,
			Client_Host);
		return 0;
	}

	nsid = Mount(mx)->nm_nsid;
	sxs[0] = toNSX(nsid);
	return 1;
}

static int mountedARTICLE(FILE *tc,PCStr(mid))
{	CStr(what,1024);
	CStr(data,LINESIZE);
	const char *tp;
	int bytes;

	wordScan(mid,what);
	if( *what == '<' ){
		ovstrcpy(what,what+1);
/*
		if( tp = strchr(what,'@') )
			*tp = 0;
*/
		if( tp = strchr(what,'>') )
			truncVStr(tp);
	}

	/* if the URL is mounted, put the content to tc ... */

	return 0;
}

typedef struct {
	char	 qm_permit;
	int	 qm_needAuth;
  const	char	*qm_name;
  const	char	*qm_filter;
	int	 qm_needAuthCustomized;
} ReqMethod;
static ReqMethod NNTP_tab_commands[] = {
	{0,1,"POST",	},
	{0,1,"IHAVE",	},
	{1,0,"MODE",	},
	{1,0,"HELP",	},
	{1,0,"LIST",	},
	{1,0,"NEWGROUPS",},
	{1,1,"GROUP",	},
	{1,1,"ARTICLE",	},
	{1,1,"HEAD",	},
	{1,1,"LAST",	},
	{1,1,"NEXT",	},
	{1,1,"STAT",	},
	{1,0,"QUIT",	},
	{0,1,"BODY",	},
	{1,0,"LISTGROUP",},
	{1,0,"AUTHINFO",},
	{1,1,"XOVER",	},
	{1,1,"XHDR",	},
	{1,1,"XPATH",	},
	{1,0,"COMPRESS",},
	{1,1,"XCACHE",	},
	{1,0,"RIDENT",	},
	0
};
#define methods	NNTP_tab_commands

static scanListFunc noauth1(PCStr(method))
{	int mi;
	const char *m1;

	for( mi = 0; m1 = methods[mi].qm_name; mi++ )
		if( strcasecmp(method,m1) == 0 ){
			methods[mi].qm_needAuthCustomized = 1;
		}
	return 0;
}
static void setNeedAuthMethod(PCStr(methods))
{	int mi;

	needAuthCom = 1;
	scan_commaList(methods,0,scanListCall noauth1);
}
static int needAuthMethod(PCStr(method))
{	int mi;
	const char *m1;

	for( mi = 0; m1 = methods[mi].qm_name; mi++ )
		if( strcasecmp(method,m1) == 0 )
		{
			if( needAuthCom )
				return methods[mi].qm_needAuthCustomized;
			return methods[mi].qm_needAuth;
		}
	return 0;
}

static int permitted_command(NewsServer *ns,PCStr(com),PCStr(arg))
{	int mi;

	if( !restricted )
		return 1;

	for( mi = 0; methods[mi].qm_name; mi++ )
		if( methods[mi].qm_permit )
			return 1;

	if( strcasecmp(com,"POST") == 0 ){
		if( 0 < writable )
			return 1;
		else	return 0;
	}
	if( strcasecmp(com,"IHAVE") == 0 ){
		if( 0 < writable )
			return 1;
		else	return 0;
	}
	/* BODY <message-id> should be filtered */
	if( strcasecmp(com,"BODY") == 0 )
	if( *arg != '<' )
		return 1;

	return 0;
}
static void mount_group_to1(NewsServer *ns,PCStr(group),PVStr(rgroup))
{	NgMount *nm;
	int mi;

	strcpy(rgroup,group);

	if( !mounted )
		return;

	if( ns == NULL )
		return;

	for( mi = 0; mi < ns->ns_mountn; mi++ ){
		nm = ns->ns_mounts[mi];

		if( strncmp(group,nm->nm_base,nm->nm_baselen) == 0 ){
			strcpy(rgroup,nm->nm_group);
			strcat(rgroup,group+nm->nm_baselen);
			break;
		}
	}
}
static scanListFunc mount1(PCStr(group1),PVStr(rgb),char **rgp,int nserv,NewsServer *servers)
{	int mx;
	NewsServer *ns;
	NgMount *nm;
	refQStr(rg,rgb); /**/
	CStr(rgroup1,1024);

	rg = *rgp;
	mx = select_mount(nserv,servers,group1,0);
	if( 0 <= mx ){
		nm = Mount(mx);
		ns = toNS(nm->nm_nsid);
		mount_group_to1(ns,group1,AVStr(rgroup1));
		strcpy(rg,rgroup1);
	}else	strcpy(rg,group1);
	rg += strlen(rg);
	setVStrPtrInc(rg,',');
	*rgp = (char*)rg;
	return 0;
}
static void mount_groups_to(PCStr(groups),PVStr(rgroups),int nserv,NewsServer *servers)
{	const char *rgp;

	setVStrEnd(rgroups,0);
	rgp = rgroups;
	scan_commaList(groups,0,scanListCall mount1,AVStr(rgroups),&rgp,nserv,servers);
	if( rgroups < rgp && rgp[-1] == ',' )
		((char*)rgp)[-1] = 0;
}

static long int permitted_group(PCStr(line))
{	CStr(group,1024);
	int si;
	long int nsid;

	if( !restricted && !hidden )
		return 1;

	if( permitted_nsid == 0 )
		permitted_nsid = Hcreate(MAXGROUPS,0);

	wordScan(line,group);
	if( nsid = (long int)Hsearch(permitted_nsid,group,0) )
		return nsid;

	for( si = 0; si < NserverN; si++ ){
		if( nsid = permitted_group1(si,0,group) ){
			Hsearch(permitted_nsid,group,(char*)nsid);
			return nsid;
		}
	}
	return 0;
}
static NgMount *mount_group_fromx(NewsServer *ns,PCStr(ng))
{	NgMount *nm;
	int mi;

	for( mi = 0; mi < ns->ns_mountn; mi++ ){
		nm = ns->ns_mounts[mi];

/*
 seeing nm_baselen is bad for
 MOUNT="LOCALNEWS.* nntp://localnews/*"
 MOUNT="= nntp://news.aist.go.jp/*"
 */
		if( nm->nm_grouplen != 0 || nm->nm_baselen != 0 )
		if( strncmp(ng,nm->nm_group,nm->nm_grouplen) == 0 ){
			/*
			Strrplc(ng,nm->nm_grouplen,nm->nm_base);
			return 1;
			*/
			return nm;
		}
	}
	return 0;
}
static int mount_group_from1(int sx,PVStr(ng))
{	NewsServer *ns;
	NgMount *nm;

	ns = &Nservers[sx];
	if( nm = mount_group_fromx(ns,ng) ){
		Strrplc(AVStr(ng),nm->nm_grouplen,nm->nm_base);
		return 1;
	}
	return 0;
}

static char *fgetsFSline(PVStr(str),int size,FILE *svfp)
{	const char *resp;
	int pid;

	FSlineCNT++;
	resp = fgetsTIMEOUT(BVStr(str),size,svfp);
	if( resp == NULL && waiting_ondemand_serv(FL_ARG,svfp) ){
		/* 9.9.5 caused by the redirection to the real-server */
		resp = fgetsTIMEOUT(BVStr(str),size,svfp);
	}
	if( resp == NULL ){
		if( !file_isreg(fileno(svfp)) ){ /* not from cache */
			server_done = 1;
			pid = NoHangWait();
			sv1log("NNTP S-C EOF[%d](%d).\n",fileno(svfp),pid);
			if( 0 < pid )
				sv1log("cleaned up zombi: %d (EOF)\n",pid);
		}
	}
	return (char*)resp;
}
static char *fgetsFS(PVStr(str),int size,FILE *svfp)
{	const char *resp;

	setVStrEnd(str,0);
	resp = fgetsFSline(AVStr(str),size,svfp);
	if( resp == NULL ){
		if( LAST_ERROR && atoi(LAST_ERROR) == 503 ){
			sprintf(str,"%s (server closed)\r\n",LAST_ERROR);
		}else
		sprintf(str,"400 server closed (%s)\r\n",
			LAST_ERROR?LAST_ERROR:"");
	}
	if( !imCC ){
		CStr(msg,1024);
		lineScan(str,msg);
		if( str[0] == '1' || str[0] == '2' )
			Verbose("## S-C %s [%s][%s]\n",msg,curGroup,curCommand);
		else{
			sv1log("## S-C %s [%s][%s]\n",msg,curGroup,curCommand);
			if( resp != NULL )
				Strdup((char**)&LAST_ERROR,msg);
		}
	}
	return (char*)resp;
}
static int get_resp(NewsServer *ns,PVStr(resp),int size)
{
	setVStrEnd(resp,0);
	if( fgetsFS(AVStr(resp),size,ns->ns_rfp) != NULL ){
		if( atoi(resp) == RC_NO_ACTIVES )
			ns->ns_noact = 1;
		return atoi(resp);
	}else	return 400;
}

static int checkAuthResp(int nsid,PCStr(com),PCStr(arg),PCStr(resp))
{	NewsServer *ns;
	int rcode,err;

	rcode = atoi(resp);
	ns = toNS(nsid);
	err = 0;
	switch( rcode ){
		case 503:
			sv1log("[%s][%s] >> %s",com,arg,resp);
			ns->ns_authERR = 503;
			err = -1;
			break;
		case 502:
		case 480:
			ns->ns_authERR = 1;
			ns->ns_authOK = 0;
			err = -1;
			sv1log("[%s][%s] >> %s",com,arg,resp);
			break;
		case 281:
			ns->ns_authOK = 1;
			ns->ns_authERR = 0;
			break;
		case 400:
			break;
		default:
			ns->ns_authERR = 0;
			break;
	}
	return err;
}
static int getAUTHINFO(FILE *tc,FILE *fc,PVStr(user),PVStr(pass))
{	CStr(req,1024);

	if( *user == 0 || streq(user,"*") || streq(user,"-") )
	for(;;){
		if( fgets(req,sizeof(req),fc) == NULL )
			return -1;
		if( strncasecmp(req,"AUTHINFO USER ",14) == 0
		 && Xsscanf(req+14,"%[^\r\n]",AVStr(user)) == 1 ){
			sv1log("AUTHINFO USER %s\n",user);
			break;
		}
		fprintf(tc,"480 Authentication required\r\n");
		fflush(tc);
	}

	fprintf(tc,"381 Password for '%s' required\r\n",user);
	fflush(tc);
	for(;;){
		if( fgets(req,sizeof(req),fc) == NULL )
			return -2;
		if( strncasecmp(req,"AUTHINFO PASS ",14) == 0
		 && Xsscanf(req+14,"%[^\r\n]",AVStr(pass)) == 1 ){
			sv1log("AUTHINFO PASS ****\n");
			/*fprintf(tc,"281 OK\r\n");*/
			break;
		}
		fprintf(tc,"381 Password for '%s' required\r\n",user);
		fflush(tc);
	}
	return 0;
}
static int putAUTHINFO(FILE *ts,FILE *fs,PCStr(user),PCStr(pass))
{	CStr(resp,1024);

	sv1log("#### AUTHINFO: USER %s\n",user);
	fprintf(ts,"AUTHINFO USER %s\r\n",user);
	fflush(ts);
	fgetsFS(AVStr(resp),sizeof(resp),fs);
	if( atoi(resp) == 381 ){
		fprintf(ts,"AUTHINFO PASS %s\r\n",pass);
		fflush(ts);
		fgetsFS(AVStr(resp),sizeof(resp),fs);
	}
	sv1log("#### AUTHINFO-RESP: %s",resp);
	if( atoi(resp) == 503 ){
		return 503;
	}
	return atoi(resp) == 281 ? 0 : -1;
}
static int doNntpAUTH(NewsServer *ns)
{	const char *user;
	const char *pass;
	Connection *Conn;
	int rcode;

	user = ns->ns_auser;
	pass = ns->ns_apass;
	Conn = ns->ns_Conn;

	if( user[0] == 0 || pass[0] == 0 ){
		if( ns->ns_needAuth ){
			ns->ns_authERR = 1;
			ns->ns_authOK = 0;
			return -1;
		}else{
			return 0;
		}
	}else{
		/*
		if( putAUTHINFO(ns->ns_wfp,ns->ns_rfp,user,pass) != 0 ){
		*/
		rcode = putAUTHINFO(ns->ns_wfp,ns->ns_rfp,user,pass);
		if( rcode == 503 ){
			ns->ns_authERR = 503;
			return -1;
		}else
		if( rcode != 0 ){
			ns->ns_authERR = 1;
			ns->ns_authOK = 0;
			return -1;
		}else{
			CTX_auth_cache(ns->ns_Conn,1,180,"nntp",user,pass,DST_HOST,DST_PORT);
			ns->ns_authERR = 0;
			ns->ns_authOK = 1;
			withAuth = 1;
			return 0;
		}
	}
}

static int filter_active(int dofilter,int si,int nserv,NewsServer *servers,FILE *fs,FILE *tc)
{	NewsServer *ns;
	CStr(line,1024);
	CStr(group,1024);
	int pass,cc;
	int dupcheck;

	dupcheck = (2 <= nserv);
	if( dupcheck ){
		if( group_nameid == 0 )
			group_nameid = strid_create(MAXGROUPS);
	}

	ns = &servers[si];
	cc = 0;

	while( fgetsFSline(AVStr(line),sizeof(line),fs) != NULL ){
		if( isEOR(line) )
			break;

		cc += strlen(line);

		if( tc != NULL && tc != NULLFP() ){
			wordScan(line,group);
			if( !dofilter )
				pass = 1;
			else
			if( !ns->ns_restricted && !ns->ns_hidden )
				pass = 1;
			else	pass = permitted_group1(si,1,group);
			if( pass ){
				if( mounted ){
					mount_group_from1(si,AVStr(line));
					wordScan(line,group);
				}
				if( dupcheck && 0 < group_nameid ){
					if( strid(group_nameid,group,si) != si )
						continue;
				}
				fputs(line,tc);
			}
		}
	}
	if( dupcheck && 0 < group_nameid )
		strid_stat(group_nameid);
	return cc;
}

static scanListFunc wild1(PCStr(wildmat),PCStr(com),NewsServer *ns,int *nwild)
{	CStr(wreq,1024);

	sprintf(wreq,"%s %s\r\n",com,wildmat);
	FPUTS(wreq,ns->ns_wfp);
	(*nwild) += 1;
	return 0;
}
static int sendWildmats(NewsServer *ns,PCStr(com),PCStr(wildmats))
{	int nwild;

	nwild = 0;
	scan_commaList(wildmats,0,scanListCall wild1,com,ns,&nwild);
	sv1log("#### LIST ACTIVE wildmats[%d] %s\n",nwild,wildmats);
	return nwild;
}
static void recvLISTs(NewsServer *ns,PCStr(com),PCStr(arg),FILE *tmp,int isactive,int nwild)
{	int cc,wx;
	CStr(line,1024);

	if( ns->ns_isself )
		if( strcaseeq(com,"NEWGROUPS") ){
			int date;
			date = YMD_HMS_toi(arg);
			cc = ENEWS_listX(tmp,ns->ns_mounted_file,date);
		}else
		cc = ENEWS_list(tmp,ns->ns_mounted_file);
	else	cc = LIST_uncompress(ns->ns_rfp,tmp,isactive);
	Verbose("LIST: got %d bytes\n",cc);
	if( strcaseeq(com,"NEWGROUPS") ){
		/* 9.9.5 update "not-modifide-since" cache for NEWGROUPS */
		updateNEWGROUPS(ns,arg,cc==0?NGOP_GOT_EMPTY:NGOP_GOT_UPDATE);
	}

	for( wx = 1; wx < nwild; wx++ ){
		get_resp(ns,AVStr(line),sizeof(line));
		if( line[0] == '2' ){
			cc = LIST_uncompress(ns->ns_rfp,tmp,isactive);
			Verbose("LIST: got %d bytes\n",cc);
		}
	}
}

/*
 *  TODO:
 *    DeleGate keeps snapshots of LIST every minutes / hours in caches.
 *    Clients request with
 *
 *        LIST ACTIVE [wildmat] [++TIME]
 *
 *    (If-Modified-Since TIME)
 *    DeleGate will respond with DELTA LIST from cached LIST at the
 *    time nearest to TIME.
 *    This should be utilized as COMPRESS LIST/X in DeleGate-DeleGate
 *    communication.
 */
static FILE *make_DELTA_LIST(FILE *cur)
{	CStr(linep,2048);
	CStr(linec,2048);
	int scc,dcc,cc;
	FILE *lastL,*delta;

	lastL = getTmpfile("LIST-DELTA-ORIG",TF_DELTAORIG,clientID,0);
	delta = getTmpfile("LIST-DELTA-BUFF",TF_DELTABUFF,0,0);

	scc = dcc = 0;
	while( fgets(linec,sizeof(linec),cur) != NULL ){
		if( !feof(lastL) )
			fgets(linep,sizeof(linep),lastL);

		scc += (cc = strlen(linec));
		if( strcmp(linep,linec) != 0 ){
			fputs(linec,delta);
			dcc += cc;
		}
	}

	fflush(delta);
	Ftruncate(delta,0,1);
	fseek(delta,0,0);

	if( dcc ){
		fseek(cur,0,0);
		fseek(lastL,0,0);
		cc = copyfile1(cur,lastL);
		Ftruncate(lastL,0,1);
	}

	sv1log("LIST-DELTA: %d / %d bytes\n",dcc,scc);
	return delta;
}

static void putLISTcache(NewsServer *ns,int si,int li,FILE *tmp,FILE *cachefp,int private_cache)
{	int rcode,cc;
	int start,emsec;
	const char *cpath;
	int lkfd;
	int updating_shared;

	if( DONTCACHE(ns) ) /* is a client side CC or a dummy server */
		return;

	cpath = LCpath(ns,li);
	updating_shared = 0;
	if( tmp == cachefp && private_cache ){
		cachefp = fopen(cpath,"r+");
		if( cachefp == NULL )
			cachefp = fopen(cpath,"w+");
		if( cachefp != NULL ){
			updating_shared = 1;
			sv1log("#### update the shared LIST cache: %s [%d]\n",
				cpath,fileno(cachefp));
		}
	}

	if( cachefp == NULL ){
		sv1log("putLISTcache[%d][%d] none\n",si,li);
		return;
	}

	if( tmp == cachefp)
		sv1log("#### TMPFILE == CACHEFILE == %x ? [%d] private=%d\n",
			p2i(tmp),li,private_cache);

	rcode = local_lockTO(1,cpath,cachefp,10*1000,&emsec,&lkfd);
	if( rcode != 0 ){
		sv1log("LIST: [%d] CANT EXCLUSIVE LOCK active-LIST %s\n",
			si,cpath);
		if( updating_shared )
			fclose(cachefp);
		return;
	}
	sv1log("LIST: [%d] write lock=0 (%dms) %s\n",si,emsec,cpath);
	start = time(0);

	fseek(tmp,0,0);
	cc = copyfile1(tmp,cachefp);
	fflush(cachefp);
	Ftruncate(cachefp,0,1);
	lock_unlock(lkfd);
	if( lkfd != fileno(cachefp) )
		close(lkfd);
	if( updating_shared )
		fclose(cachefp);

	sv1log("LIST: [%d] wrote: %d bytes / %d sec.\n",si,cc,ll2i(time(0)-start));
}
static void getLISTcache(NewsServer *ns,int si,int li,FILE *cachefp,FILE *tmp)
{	int rcode,cc;
	int emsec;
	const char *cpath;
	int lkfd;

	if( cachefp == NULL ){
		sv1log("getLISTcache[%d][%d] none\n",si,li);
		return;
	}

	cpath = LCpath(ns,li);
	rcode = local_lockTO(0,cpath,cachefp,10*1000,&emsec,&lkfd);
	if( rcode != 0 ){
		sv1log("LIST: [%d] CANT SHARE LOCK active-LIST %s\n",
			si,cpath);
	}

	fseek(tmp,0,0);
	cc = copyfile1(cachefp,tmp);
	fflush(tmp);
	Ftruncate(tmp,0,1);
	lock_unlock(lkfd);
	if( lkfd != fileno(cachefp) )
		close(lkfd);

	fseek(tmp,0,0);
	sv1log("LIST: [%d] read lock=%d (%dms), got=%d\n",si,rcode,emsec,cc);
}
static void setLISTprivate(NewsServer *ns)
{	FILE *lfp,*nlfp;
	int li,lcc;
	int mtime;

	for( li = 0; li < 4; li++ )
	if( lfp = LCfp(ns,li) ){
	    if( LCisprivate(ns,li) == 0 ){
		mtime = file_mtime(fileno(lfp)) + LCtimeoff(ns,li);
		LCorigmtime(ns,li) = mtime;

		nlfp = TMPFILE("nntp-LIST-private");
		fseek(lfp,0,0);
		lcc = copyfile1(lfp,nlfp);
		fflush(nlfp);
		fclose(lfp);
		setListcache(ns,li,nlfp,file_timeoff(fileno(nlfp),1),1);
		sv1log("create PRIVATE LIST cache: timeoff=%d age=%d\n",
			LCtimeoff(ns,li),ll2i(time(0)-mtime));
	    }else{
		sv1log("reuse already PRIVATE LIST cache: timeoff=%d\n",
			LCtimeoff(ns,li));
	    }
	}
}
static void setLISTcachepath(NewsServer *ns,int li,int wildmat)
{	CStr(lcpath,1024);
	CStr(cachepath,1024);

	sprintf(lcpath,"LIST/%s",lists[li]);
	if( wildmat && ns->ns_restricted ){
		strcat(lcpath,":");
		getLISTwildmat(ns,TVStr(lcpath));
	}
	cache_path("nntp",ns->ns_host,ns->ns_port,lcpath,AVStr(cachepath));
	Strdup((char**)&LCpath(ns,li),cachepath);
}
static void closeLIST1(NewsServer *ns,int li)
{
	if( LCfp(ns,li) == NULL )
		return;

	fclose(LCfp(ns,li));
	setListcache(ns,li,NULL,0,0);
	LClastcheck(ns,li) = 0;
	LCtimeoff(ns,li) = 0;
	LCorigmtime(ns,li) = 0;
}
static void closeLISTcache(NewsServer *ns)
{	int li;

	for( li = 0; li < 2; li++ )
		closeLIST1(ns,li);
}
static void setLISTcache(NewsServer *ns,int li)
{	char *cachepath; /**/
	FILE *lfp;
	int reopen,timeoff,was_private,created_now,xprivate;

	reopen = 0;
	timeoff = 0;
	was_private = 0;
	xprivate = 0;
	created_now = 0;

	if( LCfp(ns,li) != NULL ){
		reopen = 1;
		timeoff = LCtimeoff(ns,li);
		was_private = LCisprivate(ns,li);
		sv1log("CLOSE previous cache: private=%d TIMEOFF=%d %s\n",
			was_private,timeoff,LCpath(ns,li));
		closeLIST1(ns,li);
	}
	if( LCiobuf(ns,li) == NULL )
		LCiobuf(ns,li) = (char*)malloc(IOBSIZE);

	lfp = NULL;
	cachepath = LCpath(ns,li);
	if( cachepath[0] ){
		if( (lfp = fopen(cachepath,"r+")) == NULL )
		if( lfp = dirfopen("LIST.active",ZVStr(cachepath,1024),"w+") )
			created_now = 1;
	}
	if( lfp == NULL ){
		xprivate = 1;
		if( lfp = TMPFILE("nntp-LIST-private") )
			created_now = 1;
	}
	if( lfp != NULL ){
		setbuffer(lfp,LCiobuf(ns,li),IOBSIZE);
		if( reopen && was_private == xprivate )
			/* reuse previous timeoff for the same cache */;
		else	timeoff = file_timeoff(fileno(lfp),created_now);
		setListcache(ns,li,lfp,timeoff,xprivate);
		sv1log("setLISTcache: private=%d created=%d TIMEOFF=%d %s\n",
			xprivate,created_now,timeoff,cachepath);
	}
}
static int listMtime(NewsServer *ns,int li,int set)
{	const char *cpath;
	CStr(ucpath,1024);
	FILE *fp;
	int mtime;

	cpath = LCpath(ns,li);
	sprintf(ucpath,"%s.changed",cpath);
	if( set ){
		if( fp = fopen(ucpath,"w") ){
			fprintf(fp,"%d %d\r\n",itime(0),getpid());
			fclose(fp);
			return time(0);
		}
	}else{
		mtime = File_mtime(ucpath);
		if( 0 < mtime )
			return mtime + LCtimeoff(ns,li);
	}
	return 0;
}
static void setForceRefresh(NewsServer *ns,int li,int posttime)
{
	ns->ns_posted = posttime;
	listMtime(ns,li,1);
}
static int getForceRefresh(NewsServer *ns,int li,int mycachetime)
{	int force;
	int now,mtime;

	force = 0;
	now = time(0);

	/* refresh ACTIVE after POST by self */
	if( mtime = ns->ns_posted ){
		if( now < mtime + UPACT_POST ){
			force = 1;
			sv1log("ForceRefresh-1: %d < %d (%d < %d)\n",
				now,mtime+UPACT_POST,now-mtime,UPACT_POST);
		}else	ns->ns_posted = 0;
	}

	if( force == 0 )
	if( mtime = listMtime(ns,li,0) ){
		if( mycachetime < mtime )
		if( now < mtime + UPACT_POST ){
			sv1log("ForceRefresh-2: %d < %d (%d < %d)\n",
				mycachetime,mtime,now-mtime,UPACT_POST);
			force = 1;
		}
	}
	return force;
}

static void mergeLIST(PVStr(req),PCStr(com),PVStr(arg),FILE *tc,int nserv,NewsServer *servers)
{	NewsServer *ns;
	int si,li;
	CStr(line,1024);
	CStr(group,1024);
	FILE *fs;
	FILE *list;
	int isactive_delta,reqsend;
	int isactive,dofilter,cachable,reuseit[NSERVER],dontsend[NSERVER];
	int wildmats[NSERVER];
	int isactive_wildmat;
	const char *msg;
	CStr(emsg,1024);
	int fatal;
	int now;
	int off;
	FILE *tmp1,*tmp2;

	int wilds = 0;
	FilterDesc FD;
	clearFD(&FD);

	tmp1 = getTmpfile("mergeLIST/1",TF_LISTTMP1,0,IOBSIZE);
	tmp2 = getTmpfile("mergeLIST/2",TF_LISTTMP2,0,IOBSIZE);

	fatal = 0;
	isactive = 0;
	isactive_wildmat = 0;
	isactive_delta = 0;
	reqsend = 0;
	dofilter = 0;
	cachable = 0;
	li = 0;
	msg = "215 List follows.\r\n";
	now = time(0);

	if( strcasecmp(com,"LIST") == 0 ){
		if( strncasecmp(arg,"ACTIVE ++",9) == 0 ){
			isactive_delta = 1;
			strcpy(arg,"ACTIVE");
			sprintf(req,"%s %s\r\n",com,arg);
		}
		if( arg[0] == 0 || strcasecmp(arg,"active") == 0 ){
			isactive = 1;
			dofilter = 1;
			cachable = 1;
			li = LI_ACTIVE;
			msg = "215 Newsgroups in form \"group high low flags\".\r\n";
		}else
		if( strncasecmp(arg,"active ",7) == 0 ){
			sv1log("THRU: [%s %s]\n",com,arg);
			isactive_wildmat = 1;
		}else
		if( strcasecmp(arg,"newsgroups") == 0 ){
			dofilter = 1;
			cachable = 1;
			li = LI_NGS;
		}
	}else{
		if( strcasecmp(com,"NEWGROUPS") == 0 ){
			msg = "231 List follows.\r\n";
			dofilter = 1;
		}
	}

	for( si = 0; si < nserv; si++ ){
		int cachefd,lastcheck,mtime,age,size,forceup;
		CStr(wm,1024);

		dontsend[si] = 0;
		wildmats[si] = 0;
		ns = &servers[si];
		if( ns->ns_dispensable == V_DISABLED ){
			dontsend[si] = 1;
			continue;
		}
		if( cachable && !strcaseeq(ns->ns_proto,"pop") ){
			if( LCpath(ns,li) == NULL )
				setLISTcachepath(ns,li,0);
			if( LCfp(ns,li) == NULL )
				setLISTcache(ns,li);

			cachefd = fileno(LCfp(ns,li));
			if( mtime = LCorigmtime(ns,li) ){
				/* maybe a private copy in NNTPCC */
			}else	mtime = file_mtime(cachefd) + LCtimeoff(ns,li);
			lastcheck = LClastcheck(ns,li);
			LClastcheck(ns,li) = mtime;
			age = now - mtime;
			size = file_size(cachefd);

sv1log(
"LIST: [%d] age=%d/%d,%d size=%d last=%d [priv=%d toff=%d omtm=%d] %s\n",
si,age,UPACT_MINE,UPACT_SOME,size,lastcheck?ll2i((time(0)-lastcheck)):-1,
LCisprivate(ns,li),LCtimeoff(ns,li),LCorigmtime(ns,li),LCpath(ns,li));

			if( ns->ns_isself && lastcheck == 0 )
				forceup = 1;
			else	forceup = getForceRefresh(ns,li,mtime);
			if( NX.ne_ondemand && (isactive_delta && 15<=age) ){
				/* 9.9.5 for vin/cosmos to be age<15 */
				age = 0;
			}

			if( ns->ns_nocache & CACHE_LIST ){
				/* but LIST cache is necessary for isServerOf */
			}else
			if( !forceup )
			if( 0 < size )
			if( !isactive_delta || (isactive_delta && age < 15) )
			if( age < UPACT_MINE
			 || age < UPACT_SOME && lastcheck == 0 /* cached by others */
			){
				reuseit[si] = 1;
				continue;
			}
		}
		reuseit[si] = 0;
		if( isactive_wildmat && ns->ns_withLISTwildmat == V_DISABLED ){
			fatal++;
			sprintf(emsg,"501 [wildmat] is not supported\r\n");
			msg = emsg;
			dontsend[si] = 1;
			continue;
/* it should be supported by DeleGate by proxy of the server ... */
		}

		reqsend++;
		if( isactive_wildmat && 0 < ns->ns_withLISTwildmat ){
			Xsscanf(arg,"%*s %[^\r\n]",AVStr(wm));
			wildmats[si] = sendWildmats(ns,"LIST ACTIVE",wm);
			wilds++;
		}else
		if( isactive && 0 < ns->ns_withLISTwildmat && getLISTwildmat(ns,AVStr(wm)) )
		{
			wildmats[si] = sendWildmats(ns,"LIST ACTIVE",wm);
			wilds++;
		}
		else	FPUTS(req,ns->ns_wfp);
	}

	if( reqsend == 0 )
	if( fatal || isactive_delta && lastLIST != NULL ){
		sv1log("NO/EMPTY LIST RESPONSE TO BE RELAYED%s [%d] %s",
			fatal?"(FATAL)":"",(lastLIST?fileno(lastLIST):-1),msg);
		fputs(msg,tc);
		if( !fatal )
			Fputs(".\r\n",tc);
		fflush(tc);
		return;
	}

	for( si = 0; si < nserv; si++ ){
		if( dontsend[si] || reuseit[si] )
			continue;
		else{
			ns = &servers[si];
			if( ns->ns_isself )
				continue;

			ns->ns_LISTtime = time(0);
			get_resp(ns,AVStr(line),sizeof(line));
			if( line[0] != '2' ){
				sv1log("LIST: [%d] ERROR: %s",si,line);
				if( atoi(line) == RC_NO_ACTIVES ){
					ns->ns_noact = 1;
				}else
				if( nserv == 1 || li == LI_ACTIVE ){
					fatal++;
					strcpy(emsg,line);
					msg = emsg;
				}
				dontsend[si] = 1;
			}
		}
	}

	if( NX.ne_ondemand ){
		/* 9.9.5 on-the-fly streaming of ACTIVE LISTs to the client */
		if( 0 < wilds ){
			/* wild. filter is not implemented in relayLIST */
		}else{
			setupFD(&FD);
			FD.f_tid = thread_fork(0x100000,0,"ActLIST",
				(IFUNCP)relayLIST,FD.f_tci,tc,dofilter);
			fputs(msg,FD.f_tcx);
			fflush(FD.f_tcx);
		}
	}
	fseek(tmp1,0,0);
	for( si = 0; si < nserv; si++ ){
		FILE *cachefp;
		FILE *tocache;
		int cc;
		int private_cache;

		if( dontsend[si] )
			continue;
		ns = &servers[si];

		cachefp = LCfp(ns,li);
		if( cachable && !strcaseeq(ns->ns_proto,"pop") )
			fseek(cachefp,0,0);

		if( FD.f_tcx ){
		    if( reuseit[si] ){
			if( fatal == 0 ){
				getLISTcache(ns,si,li,cachefp,FD.f_tcx);
			}
		    }else{
			if( cachable ) /* switch the cache file for LIST */
			    fprintf(FD.f_tcx,"#>CACHE %s\r\n",LCpath(ns,li));
			recvLISTs(ns,com,arg,FD.f_tcx,isactive,wildmats[si]);
			if( cachable )
			    fprintf(FD.f_tcx,"#>CACHE .\r\n");
			LCorigmtime(ns,li) = 0;
			clearActCache(ns);
		    }
		    continue;
		}
		if( reuseit[si] ){
			if( fatal != 0 || tc == NULLFP() )
				continue;

			getLISTcache(ns,si,li,cachefp,tmp2);
			cc = filter_active(dofilter,si,nserv,servers,tmp2,tmp1);
			sv1log("LIST: [%d] read: %d bytes\n",si,cc);
			continue;
		}
		if( cachable && LCisprivate(ns,li) ){
			tocache = cachefp;
			private_cache = 1;
		}else{
			tocache = tmp2;
			private_cache = 0;
		}
		fseek(tocache,0,0);
		recvLISTs(ns,com,arg,tocache,isactive,wildmats[si]);
		fflush(tocache);
		Ftruncate(tocache,0,1);
		fseek(tocache,0,0);

		LCorigmtime(ns,li) = 0;

		if( fatal == 0 && tc != NULLFP() )
			filter_active(dofilter,si,nserv,servers,tocache,tmp1);

		if( cachable )
			putLISTcache(ns,si,li,tocache,cachefp,private_cache);
	}
	if( FD.f_tcx ){
		Fputs(".\r\n",FD.f_tcx);
		closeFD(&FD);
		return;
	}

	if( tc == NULLFP() )
		return;

	fputs(msg,tc);
	if( fatal == 0 ){
		int cc,start;

		Ftruncate(tmp1,0,1);
		fflush(tmp1);
		fseek(tmp1,0,0);
		start = time(NULL);

		if( isactive_delta )
			list = make_DELTA_LIST(tmp1);
		else	list = tmp1;

		cc = LIST_compress(list,tc,isactive,compressLIST);
		sv1log("LIST: put %d bytes / %d seconds\n",cc,ll2i(time(NULL)-start));
		Fputs(".\r\n",tc);
	}else{
		sv1log("LIST: put 0 bytes, FATAL=%d RESP=%s",fatal,msg);
		fflush(tc);
	}
}
static int file_age(PCStr(path),FILE *fp)
{	int fd,timeoff,age;

	fd = fileno(fp);
	timeoff = file_timeoff(fd,0);
	age = time(0) - file_mtime(fd) + timeoff;
	Verbose("age=%d timeoff=%d %s\n",age,timeoff,path);
	return age;
}
static void put_cache(NewsServer *ns,PCStr(where),PCStr(what),PCStr(msg))
{	CStr(cpath,1024);
	FILE *cfp;
	int age;

	if( !DONTCACHE(ns) )
	if( cache_path("nntp",ns->ns_host,ns->ns_port,what,AVStr(cpath)) ){
		if( cfp = dirfopen(where,AVStr(cpath),"r") ){
			age = file_age(cpath,cfp);
			fclose(cfp);
			if( 0 <= age && age <= 10 ){
				sv1log("shared with parent? : %s\n",cpath);
				return;
			}
		}
		if( cfp = dirfopen(where,AVStr(cpath),"w") ){
			fputs(msg,cfp);
			fclose(cfp);
		}
	}
}
static int get_cache(PCStr(where),PCStr(host),int port,PCStr(what),PVStr(msg),int size)
{	CStr(cpath,1024);
	FILE *cfp;
	int rcc;

	if( cache_path("nntp",host,port,what,AVStr(cpath)) ){
		if( cfp = dirfopen(where,AVStr(cpath),"r") ){
			alertVStr(msg,size);
			rcc = fread((char*)msg,1,QVSSize(msg,size-1),cfp);
			setVStrEnd(msg,rcc); /**/
			fclose(cfp);
			return 1;
		}
	}
	return 0;
}
static int getHELP(NewsServer *ns)
{	CStr(resp,1024);
	CStr(help,0x8000);
	refQStr(hp,help); /**/

	if( ns->ns_helpmsg != NULL )
		return 0;

	sv1log("getting HELP from %s...\n",ns->ns_host);
	fputs("HELP\r\n",ns->ns_wfp);
	fflush(ns->ns_wfp);
	get_resp(ns,AVStr(resp),sizeof(resp));

	if( atoi(resp) != 100 )
		return -1;

	hp = help;
	strcpy(hp,resp);
	hp += strlen(hp);
	while( fgetsFSline(AVStr(hp),&help[sizeof(help)]-hp,ns->ns_rfp) != NULL ){
		if( *hp == 0 )
			break;
		if( isEOR(hp) )
			break;
		hp += strlen(hp);
	}
	setVStrEnd(hp,0);
	ns->ns_helpmsg = stralloc(help);
	Verbose("## got HELP:\n%s",help);

	put_cache(ns,"NNTP-HELP","lib/HELP",help);
	return 0;
}

static void freeGROUP(NewsServer *ns)
{
	if( ns->ns_GROUP ){
		free((char*)ns->ns_GROUP); ns->ns_GROUP = 0;
		free((char*)ns->ns_GROUP_RESP); ns->ns_GROUP_RESP = 0;
	}
}
static char *getGROUP(int nsid,FILE *ts,FILE *fs,PCStr(group),PVStr(resp),int size)
{	NewsServer *ns;
	const char *rcode;

	ns = toNS(nsid);
	if( ns->ns_GROUP && strcmp(ns->ns_GROUP,group) == 0 ){
		strcpy(resp,ns->ns_GROUP_RESP);
		return (char*)resp;
	}
	fprintf(ts,"GROUP %s\r\n",group);
	fflush(ts);
	rcode = fgetsFS(AVStr(resp),size,fs);
	if( checkAuthResp(nsid,"GROUP",group,resp) == 0 ){
	ns->ns_GROUP = stralloc(group);
	ns->ns_GROUP_RESP = stralloc(resp);
	}
	return (char*)rcode;
}
static int get_pathhost1(FILE *ts,FILE *fs,PVStr(pathhost))
{	CStr(line,1024);

	while( fgetsFSline(AVStr(line),sizeof(line),fs) != NULL ){
		if( isEOR(line) )
			break;
		if( strncasecmp(line,"Path:",5) == 0 )
			Xsscanf(line,"%*s %[^!]",AVStr(pathhost));
	}
	return pathhost[0] != 0;
}
static int get_pathhost0(NewsServer *ns,PVStr(pathhost),PCStr(group))
{	CStr(resp,1024);
	int min,max,xtry;

	sv1log("checking pathhost of %s in %s...\n",ns->ns_host,group);

	getGROUP(ns->ns_nsid,ns->ns_wfp,ns->ns_rfp,group,AVStr(resp),sizeof(resp));
	if( atoi(resp) != 211 )
		return 0;
	min = max = 0;
	sscanf(resp,"%*d %*d %d %d",&min,&max);

	fprintf(ns->ns_wfp,"NEXT\r\nHEAD\r\n",group);
	fflush(ns->ns_wfp);
	get_resp(ns,AVStr(resp),sizeof(resp));
	get_resp(ns,AVStr(resp),sizeof(resp));

	setVStrEnd(pathhost,0);
	if( atoi(resp) == 221 )
		get_pathhost1(ns->ns_wfp,ns->ns_rfp,AVStr(pathhost));

	if( pathhost[0] == 0 ){
		for( xtry = 0; xtry < 5 && min <= max-xtry; xtry++ ){
			fprintf(ns->ns_wfp,"HEAD %d\r\n",max-xtry);
			fflush(ns->ns_wfp);
			get_resp(ns,AVStr(resp),sizeof(resp));
			if( atoi(resp) == 221 )
			if( get_pathhost1(ns->ns_wfp,ns->ns_rfp,AVStr(pathhost)) )
				break;
		}
	}
	if( pathhost[0] == 0 )
		return 0;
	else	return 1;
}
static void set_pathhost(NewsServer *ns,PCStr(pathhost))
{
	if( strcmp(ns->ns_host,pathhost) != 0 ){
	  Verbose("automatic NNTPCONF=pathhost:%s/%s\n",ns->ns_host,pathhost);
	  add_pathhost1(ns->ns_host,pathhost);
	}
	ns->ns_gotpathhost = 1;
}
static void get_pathhost(NewsServer *ns,PVStr(pathhost))
{	CStr(cpath,1024);
	FILE *phfp;
	int age;

	if( ns->ns_gotpathhost )
		return;
	ns->ns_gotpathhost = V_DISABLED;
	if( strcasecmp(ns->ns_proto,"pop") == 0 )
		return;

	if( cache_path("nntp",ns->ns_host,ns->ns_port,"lib/pathhost",AVStr(cpath)) )
	if( (phfp = fopen(cpath,"r")) != NULL ){
		age = file_age(cpath,phfp);
		setVStrEnd(pathhost,0);
		Fgets(AVStr(pathhost),64,phfp);
		fclose(phfp);
		if( pathhost[0] && age < UPCONF ){
			sv1log("reuse pathost[%s] in [age=%d] %s\n",pathhost,age,cpath);
			goto ADD;
		}
	}
	if( ns->ns_ondemand_yet ){
		/* 9.9.5 don't initiate connection to server */
		sv1log("==== don't try PATHHOST in on-demand %s:%d\n",
			ns->ns_host,ns->ns_port);
		return;
	}

	if( get_pathhost0(ns,AVStr(pathhost),"junk") == 0 )
	if( get_pathhost0(ns,AVStr(pathhost),"control") == 0 )
		return;

	if( phfp = dirfopen("PATHHOST",AVStr(cpath),"w") ){
		fprintf(phfp,"%s\n",pathhost);
		fclose(phfp);
	}

ADD:
	set_pathhost(ns,pathhost);
}
static int with_compressLIST(NewsServer *ns)
{	CStr(resp,1024);

	if( ns->ns_withCOMPRESS ){
		if( 0 < ns->ns_withCOMPRESS )
			return 1;
		else	return 0;
	}

	ns->ns_withCOMPRESS = V_DISABLED;
	if( ns->ns_helpmsg && strstr(ns->ns_helpmsg,"NNTP/DeleGate") ){
		fputs("COMPRESS LIST/1\r\n",ns->ns_wfp);
		fflush(ns->ns_wfp);
		get_resp(ns,AVStr(resp),sizeof(resp));
		sv1log("COMPRESS LIST/1 >> %s",resp);
		if( atoi(resp) == RC_OK_COMPRESS )
			ns->ns_withCOMPRESS = 1;
	}
	return with_compressLIST(ns);
}

static void check_LISTwildmat(NewsServer *ns)
{	CStr(resp,1024);
	CStr(cpath,1024);
	FILE *lfp;
	int rcode,age;

	if( ns->ns_withLISTwildmat )
		return;

	rcode = 0;
	if( cache_path("nntp",ns->ns_host,ns->ns_port,"lib/wildmat",AVStr(cpath)) )
	if( (lfp = fopen(cpath,"r")) != NULL ){
		age = file_age(cpath,lfp);
		resp[0] = 0;
		fgets(resp,sizeof(resp),lfp);
		fclose(lfp);
		if( resp[0] && age < UPCONF ){
			sv1log("reuse LIST [wildmat][age=%d] %s",age,resp);
			rcode = atoi(resp);
			if( rcode == 400 || rcode == 401 ){
				rcode = 0; /* 9.9.5 ignore temp. error */
			}
		}
	}

	if( rcode == 0 ){
		fprintf(ns->ns_wfp,"LIST ACTIVE control\r\n");
		fflush(ns->ns_wfp);
		rcode = get_resp(ns,AVStr(resp),sizeof(resp));
		if( rcode / 100 == 2 )
			RFC821_skipbody(ns->ns_rfp,NULL,VStrNULL,0);

		if( !DONTCACHE(ns) )
		if( resp[0] ){
			if( lfp = dirfopen("PATHHOST",AVStr(cpath),"w") ){
				fputs(resp,lfp);
				fclose(lfp);
			}
		}
	}

	if( rcode / 100 == 2 ){
		ns->ns_withLISTwildmat = 1;
		setLISTcachepath(ns,LI_ACTIVE,1);
		setLISTcache(ns,LI_ACTIVE);
		sv1log("with LIST ACTIVE [wildmat] = %s\n",
			LCpath(ns,LI_ACTIVE));
	}else{
		ns->ns_withLISTwildmat = V_DISABLED;
		if( resp[0] == 0 )
			ns->ns_noact = 1;
		sv1log("without LIST ACTIVE [wildmat]: %d\n",atoi(resp));
	}
}
static int with_XPATH(int nsid)
{	const char *wp;
	CStr(word,1024);
	NewsServer *ns;

	ns = toNS(nsid);
	if( ns->ns_withXPATH ){
		if( 0 < ns->ns_withXPATH )
			return 1;
		else	return 0;
	}
	ns->ns_withXPATH = V_DISABLED;
	wp = ns->ns_helpmsg;

	if( wp == NULL ){
		sv1log("with_XPATH? NO helpmsg\n\n");
		return 0;
	}

	while( (wp = wordScan(wp,word)) && word[0] != 0 ){ 
		if( strcasecmp(word,"XPATH") == 0 ){
			sv1log("with XPATH\n");
			ns->ns_withXPATH = 1;
			break;
		}
	}
	return with_XPATH(nsid);
}
static void getCONFIG(NewsServer *ns)
{	CStr(pathhost,256);

	if( ns->ns_dispensable == V_DISABLED ){
		sv1log("## skipped getCONGIG [%s]\n",ns->ns_host);
		return;
	}
	if( ns->ns_isself ){
		return;
	}
	/*
	doNntpAUTH(ns);
	*/
	if( NX.ne_ondemand ){
		/* 9.9.5 do auth. on demand */
	}else
	if( doNntpAUTH(ns) != 0 ){
		sv1tlog("-- NO getCONFIG on ERROR %d\n",ns->ns_authERR);
		return;
	}
	getHELP(ns);
	check_LISTwildmat(ns);
	with_compressLIST(ns);
	get_pathhost(ns,AVStr(pathhost));
}
static void getCONFIGs(int nserv,NewsServer *servers)
{	int si;
	NewsServer *ns;

	for( si = 0; si < nserv; si++ ){
		ns = &servers[si];
		getCONFIG(ns);
	}
}

static scanListFunc permitted1(PCStr(group))
{
	const char *dp;
	CStr(buf,512);

	if( permitted_group(group) )
		return 1;

	/* care the result of XPATH with the format "groupname.number"  */
	if( (dp = strrchr(group,'.')) && isdigits(dp+1) ){
		group = strcpy(buf,group);
		*(char*)strrchr(group,'.') = 0;
	return permitted_group(group);
	}
	return 0;
}
static int permitted_groups(PCStr(groups))
{
	return scan_commaList(groups,0,scanListCall permitted1);
}

static int mount_group_from(int nserv,NewsServer *servers,xPVStr(ngs))
{	int matched,match1;
	int si;
	char ch;

	matched = 0;
	for(;;){
		match1 = 0;
		for(;;){
			ch = *ngs;
			if( ch == 0 || ch == '\r' || ch == '\n' )
				goto EXIT;
			if( IS_GROUPNAMECH(ch) && ch != '.' )
				break;
			ngs++;
		}
		if( curNsid )
			match1 = mount_group_from1(toNSX(curNsid),AVStr(ngs));

		if( match1 == 0 )
			for( si = 0; si < nserv; si++ )
				if( match1 = mount_group_from1(si,AVStr(ngs)) )
					break;
		matched += match1;

		for(; ch = *ngs; ngs++){
			if( !IS_GROUPNAMECH(ch) )
				break;
		}
	}
EXIT:
	return matched;
}

static int bad_article(FILE *afp,PCStr(apath),PCStr(com),PCStr(arg))
{	char endch;
	CStr(ngs,LINESIZE);

	if( file_size(fileno(afp)) <= 0 ){
		sv1log("empty cache [%s %s]\n",com,arg);
		return 1;
	}
	if( fgetsHeaderField(afp,"Newsgroups",AVStr(ngs),sizeof(ngs)) == 0 ){
		sv1log("no Newsgroups in cached article [%s %s]\n",com,arg);
		return 1;
	}

	fseek(afp,-1,2);
	endch = getc(afp);
	fseek(afp,0,0);

	if( endch != '\n' ){
		sv1log("#### malformed article file[%s %s] %s\n",com,arg,apath);
		return 1;
	}
	return 0;
}
static FILE *lookaside_cache(int nsid,PCStr(group),PCStr(com),PCStr(arg))
{	FILE *afp;
	int anum;
	CStr(cpath,1024);
	CStr(mid,1024);
	const char *dp;
	NewsServer *ns;
	CStr(line,1024);

	ns = toNS(nsid);
	afp = NULL;

	if( ns->ns_nocache & CACHE_ARTICLE ){
	}else
	if( arg[0] == '<' ){
		strcpy(mid,arg+1);
		anum = ns->ns_curanum;
		if( dp = strchr(mid,'>') )
			truncVStr(dp);
		if( ns->ns_isself )
		if( afp = ENEWS_article(mid,group,anum) )
			return afp;

		afp = NNTP_openARTICLEC(nsid,CACHE_ONLY,mid,0,AVStr(cpath));

		if( afp == NULL ){
			/* try ICP HIT_OBJ */
		}
	}else
	if( group[0] ){
		if( *arg == 0 )
			anum = ns->ns_curanum;
		else	anum = atoi(arg);
		if( anum <= 0 )
			return NULL;

		if( ns->ns_isself )
		if( afp = ENEWS_article(NULL,group,anum) )
			return afp;

		afp = NNTP_openARTICLEC(nsid,CACHE_ONLY,group,anum,AVStr(cpath));
	}
	if( afp != NULL ){
		if( bad_article(afp,cpath,com,arg) ){
			fclose(afp);
			afp = NULL;
		}
	}
	return afp;
}

void rewriteHeader(NewsServer *ns,PVStr(head),PCStr(fnam)){
	MIME_rewriteHeader(ns->ns_rewposter,ns->ns_rewaddr,AVStr(head),fnam);
}
char *RFC822_readHeader(FILE *in,int seeEOR);
static void rewriteMessageId(NewsServer *ns,FILE *afp,PVStr(mid),int msiz);
/*
static FILE *makeArtResponse(PVStr(statresp),PCStr(req),int curanum,FILE *afp)
*/
static FILE *makeArtResponse(PVStr(statresp),PCStr(req),NewsServer*ns,FILE*afp)
{	CStr(com,1024);
	CStr(arg,1024);
	CStr(mid,256);
	int rcode;
	int anum;
	int curanum = ns->ns_curanum;

	com[0] = arg[0] = 0;
	Xsscanf(req,"%s %s",AVStr(com),AVStr(arg));

	if( strcasecmp(com,"ARTICLE") == 0 ) rcode = 220; else
	if( strcasecmp(com,"HEAD"   ) == 0 ) rcode = 221; else
	if( strcasecmp(com,"BODY"   ) == 0 ) rcode = 222; else
	if( strcasecmp(com,"XOVER"  ) == 0 ) rcode = 224; else
					     rcode = 500;

	if( arg[0] == '<' )
		anum = 0;
	else{
		anum = atoi(arg);
		if( anum == 0 && arg[0] == 0 )
			anum = curanum;
	}

	fgetsHeaderField(afp,"Message-ID",AVStr(mid),sizeof(mid));
	rewriteMessageId(ns,afp,AVStr(mid),sizeof(mid));

	sprintf(statresp,"%d %d %s %s\r\n",rcode,anum,mid,com);

	if( rcode == 222 )
		RFC821_skipheader(afp,NULL,NULL);

	return afp;
}

static int nmatch(PCStr(n1),PCStr(n2))
{	int match;

	if( strstr(n1,n2) == n1 || strstr(n2,n1) == n2 )
		match = 1;
	else
	if( hostcmp(n1,n2) == 0 )
		match = 1;
	else
	if( match_pathhost(n1,n2) )
		match = 1;
	else	match = 0;
	return match;
}

static void xref_from(PCStr(nodename),PCStr(xr),PVStr(nxref))
{	CStr(pathhost,256);
	const char *xp;
	refQStr(nxp,nxref); /**/
	CStr(xref1,1024);
	CStr(group,1024);
	int anum,permitted;
	int sx;
	NewsServer *ns;

	xp = wordScan(xr,pathhost);
	ns = toNS(curNsid);
	sx = toNSX(curNsid);
	nxp = nxref+strlen(nxref);

	if( !nmatch(ns->ns_host,pathhost) )
		return;

	while( xp = wordScan(xp,xref1) ){
		if( *xref1 == 0 )
			break;
		if( Xsscanf(xref1,"%[^:]:%d",AVStr(group),&anum) != 2 )
			continue;

		if( ns->ns_mounted )
			permitted = mount_group_from1(sx,AVStr(group));
		else	permitted = 1;

		if( !permitted )
			continue;

		if( nxp != nxref )
			nxp += strlen(strcpy(nxp," "));
		sprintf(nxp,"%s:%d",group,anum);
		nxp += strlen(nxp);
	}
}

static int mounted_permitted_groups(PVStr(ngf),PCStr(ngs))
{	int permitted;

	if( restricted )
		permitted = 0;
	else	permitted = 1;

	permitted |= mount_group_from(NserverN,Nservers,AVStr(ngf));

	if( permitted == 0 )
		permitted = permitted_groups(ngs);

	if( permitted == 0 )
		sv1log("Forbidden article: %s\n",ngs);

	return permitted;
}
static void rewriteXPATH(NewsServer *ns,PVStr(line))
{	CStr(code,16);
	CStr(groups,LINESIZE);
	const char *dp;
	char ch;
	int permitted;

	dp = wordScan(line,code);
	lineScan(dp,groups);

	if( ns->ns_mounted_file ){
		mount_group_from1(toNSX(ns->ns_nsid),AVStr(groups));
	}else{
		for( dp = groups; ch = *dp; dp++ ){
			if( ch == '/' ) *(char*)dp = '.'; else
			if( ch == ' ' ) *(char*)dp = ',';
		}
		if( ns->ns_isself ){
			mount_group_from1(toNSX(ns->ns_nsid),AVStr(groups));
			permitted = 1;
		}else	permitted = mounted_permitted_groups(AVStr(groups),groups);
		if( permitted == 0 ){
			sprintf(line,"430 Don't have it (DeleGate)\r\n");
			return;
		}
		for( dp = groups; ch = *dp; dp++ ){
			if( ch == '.' ) *(char*)dp = '/'; else
			if( ch == ',' ) *(char*)dp = ' ';
		}
	}
	sprintf(line,"%s %s\r\n",code,groups);
}

int ACL_get(PCStr(pr),PCStr(ho),int po,PCStr(upath),PCStr(nam),PVStr(val));
int MC_scanMasks(PCStr(masks));
int MC_setMasks(int mask);
int MC_getMasks();
int MC_scanAnons(PCStr(masks));
int MC_setAnons(int mask);
int MC_getAnons();
int makeAdminKey(PCStr(from),PVStr(key),int siz);
FILE *ACL_fopen(PCStr(proto),PCStr(host),int port,PCStr(upath),int wr,PVStr(cpath));
int ACL_edit(FILE *fp,int op,PCStr(name),PVStr(value));

void MIME_anon2list(int mask,PVStr(list));
const char *setFilterAnons(PCStr(rewaddr)){
	const char *dp;
	CStr(list,256);
	CStr(spec,256);

/*
 fprintf(stderr,"---sFA--- rewaddr=%X[%s]\n",rewaddr,rewaddr?rewaddr:"");
*/
	if( rewaddr == NULL || *rewaddr == 0 ){
		return rewaddr;
	}
	truncVStr(list);
	dp = wordScanY(rewaddr,list,"^:");
/*
 fprintf(stderr,"----- orig list[%s]\n",list);
*/
	if( *dp != ':' ){
		MIME_transAddrSpec = strid_alloc(rewaddr);
/*
 fprintf(stderr,"++++++ 1 set tas=%X[%s]\n",MIME_transAddrSpec,MIME_transAddrSpec);
*/
	}

	MIME_anon2list(MC_getAnons(),AVStr(list));
/*
 fprintf(stderr,"--C ANON:%X\n",MC_getAnons());
 fprintf(stderr,"--C1[%s][%s]\n",list,MIME_transAddrSpec?MIME_transAddrSpec:"");
 fprintf(stderr,"--C2[%s][%s]\n",list,rewaddr?rewaddr:"");
*/
	if( list[0] != 0 ){
		sprintf(spec,"%s%s",list,dp);
		MIME_transAddrSpec = strid_alloc(spec);
/*
 fprintf(stderr,"++++++ 2 set tas=%X[%s]\n",MIME_transAddrSpec,MIME_transAddrSpec);
*/
	}else{
		MIME_transAddrSpec = strid_alloc(rewaddr);
/*
 fprintf(stderr,"++++++ 3 set tas=%X[%s]\n",rewaddr,rewaddr?rewaddr:"");
*/
	}
	return MIME_transAddrSpec;
}
static int MC_ART_MASK;
static int MC_ART_ANON;
int setArticleMasks(PCStr(opts),PCStr(host),int port,PCStr(group),int anum){
	CStr(cpath,1024);
	CStr(path,1024);
	CStr(mask,1024);
	int mmask = 0;
	int amask = 0;
	FILE *fp;

	/* proxy server mask */
	if( opts && *opts ){
		const char *dp;
		CStr(list,256);
		truncVStr(list);
		dp = wordScanY(opts,list,"^:");
		amask = MC_scanAnons(list);
/*
 fprintf(stderr,"---- proxy acl[%s][%s] %X taS %X[%s]\n",list,dp,amask,
MIME_transAddrSpec,
MIME_transAddrSpec?MIME_transAddrSpec:""
);
*/
	}

	/* origin server mask */
	if( fp = ACL_fopen("nntp",host,port,"",0,AVStr(cpath)) ){
		if( ACL_edit(fp,0,"Mask",AVStr(mask)) ){
			mmask |= MC_scanMasks(mask);
		}
		fseek(fp,0,0);
		if( ACL_edit(fp,0,"Anon",AVStr(mask)) ){
			amask |= MC_scanAnons(mask);
		}
		fclose(fp);
	}

	/* article mask */
	MC_ART_MASK = 0;
	MC_ART_ANON = 0;
	sprintf(path,"%s/%03d/%02d",group,anum/100,anum%100);
	strsubst(AVStr(path),".","/");
	if( fp = ACL_fopen("nntp",host,port,path,0,AVStr(cpath)) ){
		if( ACL_edit(fp,0,"Mask",AVStr(mask)) ){
			MC_ART_MASK = MC_scanMasks(mask);
			mmask |= MC_ART_MASK;
		}
		fseek(fp,0,0);
		if( ACL_edit(fp,0,"Anon",AVStr(mask)) ){
			MC_ART_ANON = MC_scanAnons(mask);
			amask |= MC_ART_ANON;
		}
		fclose(fp);
	}
	MC_setMasks(mmask);
	MC_setAnons(amask);
/*
 fprintf(stderr,"++++ articleacl MASK:%X ANON:%X %s [%s]\n",mmask,amask,path,
MIME_transAddrSpec?MIME_transAddrSpec:"");
*/
	return mmask;
}
int setPosterMasks(PCStr(From)){
	CStr(key,128);
	CStr(cpath,1024);
	CStr(mask,256);
	int imask;
	FILE *fp;
	int nmod = 0;
	CStr(list,256);

	makeAdminKey(From,AVStr(key),sizeof(key));
	fp = ACL_fopen("smtp","-.-",25,key+16,0,AVStr(cpath));
/*
 fprintf(stderr,"---- poster_acl %X [%s]\n",fp,key);
*/
	if( fp == NULL )
		return 0;

	if( ACL_edit(fp,0,"XMask",AVStr(mask)) ){
		if( imask = MC_scanMasks(mask) ){
int omask = MC_getMasks();
			MC_setMasks(MC_getMasks() & ~imask);
/*
 fprintf(stderr,"----- XMask[%s] %X %X -> %X\n",mask,imask,omask,MC_getMasks());
*/
			nmod++;
		}
	}
	fseek(fp,0,0);
	if( ACL_edit(fp,0,"Mask",AVStr(mask)) ){
		if( imask = MC_scanMasks(mask) ){
			MC_setMasks(MC_getMasks() | imask);
			nmod++;
		}
	}
	fseek(fp,0,0);
	if( ACL_edit(fp,0,"XAnon",AVStr(mask)) ){
		if( imask = MC_scanAnons(mask) ){
			MC_setAnons(MC_getAnons() & ~imask);
			nmod++;
		}
	}
	fseek(fp,0,0);
	if( ACL_edit(fp,0,"Anon",AVStr(mask)) ){
		if( imask = MC_scanAnons(mask) ){
			MC_setAnons(MC_getAnons() | imask);
			nmod++;
		}
	}
/*
 fprintf(stderr,"--++ poster_acl Mask:%X Anon:%X %s [%s] [%s]\n",
MC_getMasks(),MC_getAnons(),key+16,From?From:"--EMPTY--",
MIME_transAddrSpec?MIME_transAddrSpec:"");
*/
	if( MC_ART_MASK || MC_ART_ANON ){
		MC_setMasks(MC_getMasks()|MC_ART_MASK);
		MC_setAnons(MC_getAnons()|MC_ART_ANON);
/*
 fprintf(stderr,"-+++ poster_acl Mask:%X Anon:%X %s [%s] [%s]\n",
MC_getMasks(),MC_getAnons(),key+16,From?From:"--EMPTY--",
MIME_transAddrSpec?MIME_transAddrSpec:"");
*/
	}

	fclose(fp);
	return nmod;
}
static void rewriteMessageId(NewsServer *ns,FILE *afp,PVStr(mid),int msiz){
	CStr(xref,256); /* to be used as <_Axxxx@..._> */
	CStr(from,256);
	CStr(head,512);
	int ma;

	ma = MC_getAnons();
	fgetsHeaderField(afp,"From",AVStr(from),sizeof(from));
	setPosterMasks(from);
	fgetsHeaderField(afp,"Xref",AVStr(xref),sizeof(xref));
	sprintf(head,"Xref: %s\r\nMessage-ID: %s\r\n\r\n",xref,mid);
	MIME_rewriteHeader("",ns->ns_rewaddr,AVStr(head),NULL);
	getFieldValue(head,"Message-ID",BVStr(mid),msiz);
	MC_setAnons(ma);
}

int (*MIME_setPosterMasks)(PCStr(from)) = setPosterMasks;
extern int MIME_disableTransHead;

static FILE *permitted_head(PVStr(head),FILE *tc,FILE *cache)
{	refQStr(ng,head); /**/
	CStr(ngs,LINESIZE);
	refQStr(ft,head); /**/
	int permitted;
	NewsServer *ns;
	const char *shead;

MIME_disableTransHead = 0;

	if( ft = findFieldValue(head,"X-From-Fp") ){
		CStr(XFromFp,256);
		CStr(mask,128);
		int imask;
		lineScan(ft,XFromFp);
		truncVStr(mask);
		if( ACL_get("smtp","-.-",25,XFromFp,"Mask",AVStr(mask)) ){
			if( imask = MC_scanMasks(mask) )
				MC_setMasks(imask);
			if( isinList(mask,"From") )
			if( ft = findFieldValue(head,"From") ){
				CStr(from,256);
				CStr(ab,256);
				lineScan(ft,from);
				RFC822_addresspartX(from,AVStr(ab),sizeof(ab));
				sprintf(from,"%s (((Masked-From)))",ab);
				replaceFieldValue(BVStr(head),"From",from);
			}
		}
	}

	ns = toNS(curNsid);

	if( !restricted && !hidden && !mounted ){
		permitted = 1;
		goto XREF_FILTER;
	}
	if( ns->ns_isself ){
	/* maybe a folder saving articles from arbitrary real Newsgroups */
		permitted = 1;
		goto XREF_FILTER;
	}

	if( ng = findFieldValue(head,"Newsgroups") ){
		lineScan(ng,ngs);
		permitted = mounted_permitted_groups(AVStr(ng),ngs);
	}else{
		shead = stralloc(head);
		sprintf(head,"Newsgroups: %s\r\n",ns->ns_curgroup);
		strcat(head,shead);
		free((char*)shead);
		permitted = 1;
	}

	if( !permitted )
		goto EXIT;

	if( ft = findFieldValue(head,"Followup-To") )
		mount_group_from(NserverN,Nservers,AVStr(ft));

XREF_FILTER:
	if( !strcaseeq(curComd,"HEAD") && !strcaseeq(curComd,"ARTICLE") )
		goto EXIT;
{
	CStr(Path,LINESIZE);
	CStr(pathhost,256);
	CStr(servname,256); /* pathhost from the client view */
	const char *xr;
	const char *xrv;
	CStr(nxref,LINESIZE);

	if( 1 < NserverN )
		strcpy(servname,clientIF_FQDN);
	else	strcpy(servname,ns->ns_hostFQDN);

	pathhost[0] = 0;
	if( getFV(head,"Path",Path) )
		Xsscanf(Path,"%[^!]",AVStr(pathhost));

	if( pathhost[0] != 0 && nmatch(servname,pathhost) )
		strcpy(servname,pathhost);

	nxref[0] = 0;
	while( xrv = findFieldValue(head,"Xref") ){
		const char *rp;

		for( xr = xrv; head < xr; xr-- )
			if( xr[-1] == '\n' )
				break;

		ng = strchr(xrv,'\n');
		if( ng == NULL )
			break;
		truncVStr(ng); ng++;

		if( rp = strchr(xrv,'\r') )
			truncVStr(rp);

		while( *xrv && isspace(*xrv) )
			xrv++;
		if( *xrv )
			xref_from(pathhost,xrv,AVStr(nxref));

		ovstrcpy((char*)xr,ng);
	}

	/* generate temporary Xref */
	if( nxref[0]==0 && findFieldValue(head,"Xref")==0 && curAnum != 0 )
		sprintf(nxref,"%s:%d",ns->ns_curgroup,curAnum);

	if( nxref[0] ){
		shead = stralloc(head);
		Verbose("INSERTED-1: Xref: %s %s\n",servname,nxref);
		sprintf(head,"Xref: %s %s\r\n",servname,nxref);
		strcat(head,shead);
		free((char*)shead);
	}
	if( strcmp(servname,pathhost) != 0 ){
		refQStr(path,head); /**/
		if( path = findFieldValue(head,"Path") ){
			shead = stralloc(path);
			sprintf(path,"%s!",servname);
			strcat(path,shead);
			free((char*)shead);
		}
	}

	/* if not Logged In ... */
	if( ns->ns_rewaddr ){
		NgMount *nm;
		const char *rewaddr = ns->ns_rewaddr;
		const char *rewposter = ns->ns_rewposter; 

		if( ng = findFieldValue(head,"Newsgroups") ){
			lineScan(ng,ngs);
			if( nm = mount_group_fromx(ns,ngs) )
			{
				rewaddr = nm->nm_rewaddr;
				rewposter = nm->nm_rewposter;
			}
		}
		/*
		MIME_rewaddrs(rewaddr,AVStr(head));
		*/
/*
 fprintf(stderr,"--A %X REWH=[%s] ra=[%s]\n",
MC_getAnons(),MIME_transAddrSpec?MIME_transAddrSpec:"",rewaddr);
*/
		rewaddr = setFilterAnons(rewaddr);
		MIME_rewriteHeader(rewposter,rewaddr,AVStr(head),NULL);
/*
 fprintf(stderr,"--B %X REWH=[%s] ra=[%s]\n",
MC_getAnons(),MIME_transAddrSpec?MIME_transAddrSpec:"",rewaddr);
		setFilterAnons(rewaddr);
*/
/*
 fprintf(stderr,"--C %X REWH=[%s] ra=[%s]\n",
MC_getAnons(),MIME_transAddrSpec?MIME_transAddrSpec:"",rewaddr);
*/
	}
}
EXIT:
	if( permitted )
		return tc;
	else	return NULL;
}

static int select_server(int nserv,NewsServer servers[],PCStr(curgroup),PCStr(com),PCStr(arg))
{	const char *group;
	int mx,serverx;

	if( nserv == 0 )
		return -1;
	if( nserv == 1 )
		return 0;

	if( strcasecmp(com,"GROUP") == 0 )
		group = arg;
	else	group = curgroup;

	if( group[0] == 0 && LastGroup[0] == 0 )
		for( serverx = 0; serverx < nserv; serverx++ )
			if( !servers[serverx].ns_noact )
				if( servers[serverx].ns_dispensable == V_DISABLED ){
					sv1vlog("## select_server: ignore [%s]\n",
						servers[serverx].ns_host);
					continue;
				}else
				return serverx;

	if( strcmp(group,LastGroup) == 0 )
		return LastServerx;

	serverx = -1;
	if( 0 <= (mx = select_mount(nserv,servers,group,0)) )
		serverx = toNSX(Mount(mx)->nm_nsid);

	if( serverx < 0 )
		serverx = findServer(nserv,servers,group);

	if( serverx < 0 )
		serverx = 0;

	strcpy(LastGroup,group);
	LastServerx = serverx;
	return serverx;
}

const char *setHeadMask(PCStr(hmask));
static FILE *getPOST(FILE *fc,FILE *artfp,PVStr(groups),int size)
{
	const char *xas;
	const char *shm;

	shm = setHeadMask(NULL);
	xas = MIME_transAddrSpec;
	MIME_transAddrSpec = 0;
	PGPencodeMIME(fc,artfp);
	setHeadMask(shm);
	MIME_transAddrSpec = xas;
	fflush(artfp);

	setVStrEnd(groups,0);
	fseek(artfp,0,0);
	fgetsHeaderField(artfp,"Newsgroups",AVStr(groups),size);
	return artfp;
}
static const char *ng_field(PCStr(line))
{
	if( strncasecmp(line,"Newsgroups:", 11)==0 ) return "Newsgroups:"; else
	if( strncasecmp(line,"Followup-To:",12)==0 ) return "Followup-To:";
	return 0;
}

static void putPOST(NewsServer *ns,int nserv,NewsServer *servers,FILE *artfp,FILE *ts)
{	CStr(line,LINESIZE);
	CStr(groups,LINESIZE);
	CStr(rgroups,LINESIZE);
	const char *fname;

	if( filter_withCFI(ns->ns_Conn,XF_FTOSV) )
		putMESSAGEline(ts,"mime","POST");

	while( fgets(line,sizeof(line),artfp) != NULL ){
	    if( fname = ng_field(line) ){
		lineScan(line+strlen(fname),groups);
		mount_groups_to(groups,AVStr(rgroups),nserv,servers);
		fprintf(ts,"%s %s\r\n",fname,rgroups);
	    }else{
		if( isEOH(line) || isEOR(line) ){
			Connection *Conn = ns->ns_Conn;
			if( !ImCC )
			fprintf(ts,"X-Forwarded: by - (DeleGate/%s)\r\n",DELEGATE_ver());
			fputs(line,ts);
			break;
		}
		fputs(line,ts);
	    }
	}
	RFC821_skipbody(artfp,ts,AVStr(line),sizeof(line));
	fflush(ts);
	daemonlog("E","POST ended with: %s\n",line);
	fputs(line,ts);
}

int sendAdminMail(Connection *Conn,FILE *mfp,FILE *afp,PCStr(key),PCStr(ctrl),PCStr(to),PCStr(desc));
int replyToPoster(Connection *Conn,FILE *qfp,int nsid,PCStr(ctrl),PVStr(stat)){
	int rcode = -1;
	FILE *afp = 0;
	CStr(group,1024);
	int anum;
	NewsServer *ns;
	CStr(cpath,1024);
	CStr(from,1024);
	CStr(key,128);
	CStr(desc,1024);
	CStr(qfrom,256);
	CStr(qaddr,256);
	CStr(aaddr,256);

	if( fgetsHeaderField(qfp,"From",AVStr(qfrom),sizeof(qfrom)) == 0 ){
		sprintf(stat,"441 POST no From: field\r\n");
		goto EXIT;
	}
	truncVStr(group);
	anum = -1;
	Xsscanf(ctrl,"%*s %s %d",AVStr(group),&anum);
	ns = toNS(nsid);
	if( ns->ns_isself ){
		afp = ENEWS_article(NULL,group,anum);
	}else	afp = NNTP_openARTICLE(nsid,-1,group,anum,AVStr(cpath));
	if( afp == NULL ){
		sprintf(stat,"441 POST cannot open: %s:%d\r\n",group,anum);
		goto EXIT;
	}
	if( fgetsHeaderField(afp,"From",AVStr(from),sizeof(from)) == 0 ){
		sprintf(stat,"441 POST cannot get From: %s:%d\r\n",group,anum);
		goto EXIT;
	}
	RFC822_addresspartX(qfrom,AVStr(qaddr),sizeof(qaddr));
	RFC822_addresspartX(from,AVStr(aaddr),sizeof(aaddr));
	if( !strcaseeq(qaddr,aaddr) ){
		sprintf(stat,"441 POST wrong From: '%s'\r\n",qaddr);
		sv1log("ToPoster: %d: Wrong From [%s][%s]\n",rcode,qaddr,aaddr);
		goto EXIT;
	}
	if( fgetsHeaderField(qfp,"X-Auth-Key",AVStr(key),sizeof(key)) == 0 ){
	}else{
	}
	sprintf(desc,"the poster of: %s:%d",group,anum);
	sendAdminMail(Conn,qfp,afp,key,ctrl,from,desc);
	sprintf(stat,"240 Article posted\r\n");
	rcode = 0;
EXIT:
	if( afp ) fclose(afp);

	sv1log("ToPoster: %d: %s",rcode,stat);
	return rcode;
}

const char NN_ForwardToPoster[] = "forward-to-poster";
int NNTP_replyToPoster(Connection *Conn,int nsid,PCStr(grp),int ano,FILE *qfp,PVStr(stat)){
	CStr(ctrl,256);
	int code;

	sprintf(ctrl,"%s %s %d\r\n",NN_ForwardToPoster,grp,ano);
	code = replyToPoster(Conn,qfp,nsid,ctrl,AVStr(stat));
	return code;
}

static int NNTP_POST(NewsClient *nc,FILE *fc,FILE *tc,PCStr(curgroup),int nserv,NewsServer *servers)
{	CStr(stat,256);
	CStr(groups,LINESIZE);
	int sx,sxn,sxs[8];
	NewsServer *ns;
	FILE *fs,*ts;
	FILE *artfp;
	int rcode = 0;
	Connection *Conn = nc->nc_Conn;

	sv1log("NNTP POST\n");
	Fputs("340 ok (POST via DeleGate).\r\n",tc);

	artfp = TMPFILE("NNTP_POST");
	getPOST(fc,artfp,AVStr(groups),sizeof(groups));

	sxn = select_server_list(nc,nserv,servers,"POST",groups,sxs);
	if( sxn <= 0 ){
		sprintf(stat,"441 POST forbidden by DeleGate: %s\r\n",groups);
		goto EXIT;
	}
	sx = sxs[0];
	ns = &servers[sx];

	/* with Control:forward-to-poster */
	/* or when the group is mounted to SMTP://server */
	{	CStr(ctl,1024);
		if( fgetsHeaderField(artfp,"Control",AVStr(ctl),sizeof(ctl)) )
		if( strneq(ctl,NN_ForwardToPoster,strlen(NN_ForwardToPoster)) ){
			replyToPoster(Conn,artfp,toNSID(sx),ctl,AVStr(stat));
			goto EXIT;
		}
	}

	if( ns->ns_isself ){
		FILE *tmp;
		CStr(rgroups,LINESIZE);
		mount_groups_to(groups,AVStr(rgroups),nserv,servers);
		sv1log("POST to local[%d] %s [%s]\n",sx,groups,rgroups);
		tmp = TMPFILE("POST-self");
		putPOST(ns,nserv,servers,artfp,tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		if( 0 < ENEWS_post(AVStr(stat),tmp,rgroups,"","") )
			setForceRefresh(ns,LI_ACTIVE,time(0));
		fclose(tmp);
		goto EXIT;
	}

	sv1log("POST to server[%d][%s] %s\n",sx,ns->ns_host,groups);
	fs = ns->ns_rfp;
	ts = ns->ns_wfp;
	ns->ns_POSTtime = time(0);

	if( Fputs("POST\r\n",ts) == EOF )
		return -1;
	if( fgetsFS(AVStr(stat),sizeof(stat),fs) == NULL )
		return -1;
	sv1log("NNTP POST: %s",stat);

	if( atoi(stat) == 340 ){
		putPOST(ns,nserv,servers,artfp,ts);
		fflush(ts);
		if( fgetsFS(AVStr(stat),sizeof(stat),fs) == NULL )
			sprintf(stat,"441 server closed.\r\n");
		setForceRefresh(ns,LI_ACTIVE,time(0));
	}else
	if( atoi(stat) == 480 ){
		/* Through pass "480 Authorization required" response */
	}else{
		sprintf(stat,"441 POST forbidden by the server.\r\n");
	}

EXIT:
	Fputs(stat,tc);
	fclose(artfp);
	sv1log("## D-C %s",stat);
	return rcode;
}
static int NNTP_IHAVE(NewsClient *nc,FILE *fc,FILE *tc,PCStr(curgroup),int nserv,NewsServer *servers)
{	int rcode = 0;
	FILE *afp;
	CStr(groups,1024);
	CStr(stat,1024);
	NewsServer *ns = DO_ns;
	int toSMTP = 0;

	if( ns != NULL && strcasecmp(ns->ns_proto,"pop") == 0 ){
		sv1log("#### IHAVE to SMTP/NNTP [%s]\n",ns->ns_host);
		toSMTP = 1;
	}else
	if( ns == NULL || !ns->ns_isself ){
		fprintf(tc,"435 article not wanted - do not send it. (1)\r\n");
		return 0;
	}
	else

	if( afp = lookaside_cache(ns->ns_nsid,DO_arg,DO_com,DO_arg) ){
		fclose(afp);
		fprintf(tc,"435 article not wanted - do not send it. (2)\r\n");
		return 0;
	}

	fprintf(tc,"335 send article to be transferred.\r\n");
	fflush(tc);

	afp = TMPFILE("NNTP_IHAVE");
	getPOST(fc,afp,AVStr(groups),sizeof(groups));
	if( toSMTP ){
		sv1log("#### group = %s\n",groups);
		strcpy(stat,"200\r\n");
	}else	ENEWS_post(AVStr(stat),afp,groups,"","");
	fclose(afp);

	if( stat[0] == '2' )
		fprintf(tc,"235 article accepted.\r\n");
	else	fprintf(tc,"437 article rejected.\r\n");
	return 0;
}


#define DO_INIT		1
#define DO_POST		2
#define DO_LIST		3
#define DO_XOVER	4
#define DO_NEXT		5
#define DO_LAST		6
#define DO_QUIT		7
#define DO_GROUP	8
#define DO_MODE		9
#define DO_IHAVE	10
#define WAIT_GROUP	11
#define DO_SUSPEND	12
#define DO_PENALTY	13
#define DO_CACHE	14
#define DO_ECHO		15
#define DO_SYNC		16

typedef struct _Request {
	int	 q_nsx;
  const	char	*q_group;
  const	char	*q_req;
	int	 q_thru;
	int	 q_bcast;
	FILE	*q_cache;
 struct _Request *q_next;
} Request;

static void enqRequest(int nsx,PCStr(curgroup),PCStr(req),PCStr(com),PCStr(arg),FILE *cache)
{	Request *rp;

	Qlog("NNTP REQUEST [%d]+%d < %s",nsx,QueueLeng,req);
	QueueLeng++;

	rp = (Request*)calloc(1,sizeof(Request));
	rp->q_thru = 0;
	rp->q_cache = cache;

	if( strcasecmp(com,"XHDR") == 0 )
	if( strcasecmp(arg,"Lines") == 0 )
		rp->q_thru = 1;
	if( strcasecmp(com,"LISTGROUP") == 0 )
		rp->q_thru = 1;
	if( strcasecmp(com,"QUIT") == 0 )
		rp->q_bcast = 1;

	rp->q_nsx = nsx;
	rp->q_group = stralloc(curgroup);
	rp->q_req = stralloc(req);
	rp->q_next = NULL;
	if( QueueTop == NULL )
		QueueTop = rp;
	if( QueueTail != NULL )
		QueueTail->q_next = rp;
	QueueTail = rp;
}
static FILE *cachedResponse(int *nsxp)
{	Request *rp;
	FILE *afp;

	if( rp = QueueTop ){
		if( afp = rp->q_cache ){
			*nsxp = rp->q_nsx;
			return afp;
		}
	}
	return NULL;
}
static int cur_serverx(){
	if( QueueLeng <= 0 || QueueTop == NULL || QueueTop->q_bcast )
		return -1;
	else	return QueueTop->q_nsx;
}
static void deqRequest(int nsx,PVStr(group),PVStr(req),int *rthru)
{	Request *rp;

	if( 0 < QueueLeng )
		QueueLeng--;

	rp = QueueTop;
	if( rp == NULL ){
		setVStrEnd(group,0);
		setVStrEnd(req,0);
		*rthru = 0;
		return;
	}

	strcpy(group,rp->q_group);
	strcpy(req,rp->q_req);
	*rthru = rp->q_thru;

	Qlog("NNTP RESPONSE[%d]+%d < [%s] %s",rp->q_nsx,
		QueueLeng,rp->q_group,rp->q_req);
	QueueTop = QueueTop->q_next;
	QueueTop = rp->q_next;
	if( QueueTail == rp )
		QueueTail = NULL;
	free((char*)rp->q_group);
	free((char*)rp->q_req);
	free(rp);

	curNsid = toNSID(nsx);
}

static void putHelp(FILE *tc)
{
	fprintf(tc,"##### NNTP proxy information #### BEGIN\r\n");
	fprintf(tc,"NNTP-%s\r\n",DELEGATE_verdate());
	fprintf(tc,"XLIST [difference]  -- LIST ACTIVE by delta.\r\n");
	fprintf(tc,"%s\r\n",XCACHE_usage);
	fprintf(tc,"Report problems to <%s>\r\n",DELEGATE_ADMIN);
	fprintf(tc,"%s\r\n",DELEGATE_copyright());
	fprintf(tc,"WWW: %s\r\n",DELEGATE_homepage());
	fprintf(tc,"##### NNTP proxy information #### END\r\n");
}

static void INNsetup(NewsServer *ns,PVStr(msg))
{	CStr(pathhost,128);
	const char *dp;
	CStr(resp,1024);
	int code;

	if( strstr(msg,"InterNetNews")
	 || strstr(msg,"INN")
	 || strstr(msg,"Netscape-Collabra")
	){
		dp = wordScan(msg,pathhost);
		wordScan(dp,pathhost);
		set_pathhost(ns,pathhost);

		if( strstr(msg," NNRP ") == NULL ){
			fputs("MODE READER\r\n",ns->ns_wfp);
			fflush(ns->ns_wfp);
			code = get_resp(ns,AVStr(resp),sizeof(resp));
			sv1log("MODE READER >> %s",resp);
			if( code == 200 || code == 201 )
				strcpy(msg,resp);
		}
	}
}
static void set_opening(NewsServer *ns,PVStr(msg))
{	const char *okword;
	refQStr(postok,msg); /**/
	CStr(rem,128);

	ns->ns_OPENtime = time(0);

	if( ns->ns_openingmsg != NULL && strcmp(msg,ns->ns_openingmsg) == 0 )
		return;

	sv1log("## S-C %s",msg);
	INNsetup(ns,AVStr(msg));
	if( ns->ns_ondemand_yet ){
		/* 9.9.5 don't cache msg. generated by a stab server */
	}else
	put_cache(ns,"NNTP-open","lib/opening",msg);

	if( ns->ns_rw == 0 ){
		okword = "(posting ok)";
		if( postok = strstr(msg,okword) ){
			strcpy(rem,postok+strlen(okword));
			sprintf(postok,"(no posting)%s",rem);
			Verbose("## S-C %s",msg);
		}
	}
	Strdup((char**)&ns->ns_openingmsg,msg);
}
static int tobecached(int nsid,PCStr(group),int anum)
{	NewsServer *ns;

	ns = toNS(nsid);
	if( DONTCACHE(ns) )
		return 0;

	if( strcasecmp(ns->ns_proto,"pop") == 0 )
		return 0;
	if( ns->ns_islocal )
		return 0;
	return 1;
}

void setCurGroup(int nsid,NewsServer *ns,PCStr(ngroup),PCStr(rgroup))
{
	Strdup((char**)&ns->ns_curgroup,ngroup);
	Strdup((char**)&ns->ns_curgroupR,rgroup);

	ns->ns_curanum = 0;
	ns->ns_artcache = 0;

	if( !imCC ){
		if( nsid != curNsid || strcmp(ngroup,curGroup) != 0 )
		sv1log("Switched GROUP %s [%s:%d] [%d]\n",ns->ns_curgroup,
			ns->ns_host,ns->ns_port,nsid);
	}

	Xstrcpy(ZVStr(curGroup,512),ngroup);
	curNsid = nsid;
}


static int get_decoding(RespStatus *stats,int code)
{	int si,decoding;

	decoding = -1;
	for( si = 0; stats[si].rs_code; si++ ){
		if( code == stats[si].rs_code ){
			decoding = stats[si].rs_coding;
			break;
		}
	}
	return decoding;
}

static
int NNTPrelay_response(NewsClient *nc,PCStr(statresp),PCStr(group),PCStr(com),int thru,RespStatus *stats,int sx,int nserv,NewsServer *servers,FILE *fs,FILE *tc)
{	CStr(line,2048);
	CStr(ngroup,1024);
	int code;
	int filter,decoding,enHTML;
	NewsServer *ns;
	int nsid;
	FILE *cache;

	ns = &servers[sx];
	nsid = toNSID(sx);
	ns->ns_respcnt++;

	if( statresp != NULL )
		strcpy(line,statresp);
	else{
		if( fgetsFS(AVStr(line),sizeof(line),fs) == NULL ){
			if( ns->ns_dispensable == V_DISABLED ){
				fprintf(tc,"436 [%s] not available temporarily\r\n",com);
			}else
			if( NE_dispensable ){
				/* replace with cached_nntpserver ?  */
				sv1log("## ignore SC-EOF[%s] %s",ns->ns_host,line);
				ns->ns_dispensable = V_DISABLED;
			}else
			fputs(line,tc);
			return -1;
		}
	}

	Verbose("NNTP[%d]+%d%s [%s] > %s",sx,QueueLeng,statresp?"*":" ",
		group,line);

	code = atoi(line);
	lastRcode = code;
	if( code == 200 || code == 201 ){
		set_opening(ns,AVStr(line));
		if( ns->ns_ondemand_yet ){
			/* 9.9.5 don't initiate connection to server */
			sv1log("==== don't DATE for on-demand %s:%d\n",
				ns->ns_host,ns->ns_port);
		}else
		if( 1 < nservers_remote() ){
			CStr(resp,256);
			fprintf(ns->ns_wfp,"DATE\r\n");
			fflush(ns->ns_wfp);
			fgetsFS(AVStr(resp),sizeof(resp),fs);
			sv1log("#DATE> %s",resp);
		}
		if( NX.ne_ondemand && strcaseeq(com,"MODE") ){
			/* 9.9.5 should put it into MODE-cache */
		}
		if( nservers_remote() != 1 )
			return 0;
		if( NX.ne_ondemand && !strcaseeq(com,"MODE") ){
			/* 9.9.5 greeting was put at the beginning */
			return 0;
		}
	}
	else
	if( NE_dispensable ){
		if( code == 400 || code == 502 /* the first resp. (greeting) */
		 || code == 401 /* timeout ? */
		){
			sv1log("## ignore SC-ERR[%s] %s",ns->ns_host,line);
			ns->ns_dispensable = V_DISABLED;
/*
closeSVStream(ns);
freeGROUP(ns);
*/
			return -1;
		}
	}

	if( code == 281 ){
		ns->ns_authOK = 1;
		ns->ns_authERR = 0;
	}else
	if( code == 502 ){
		ns->ns_authOK = 0;
		ns->ns_authERR = 1;
	}

	if( (code == 503 || code == 401) && QueueLeng == 0 ){
		/* Connection is closed because the server has been idle for
		 * long time. It is resumable closing caused by timeout
		 * if command queue is empty (i.e. without pending status...)
		 */
		closeSVStream(ns);
		freeGROUP(ns);
		if( wait_resume(ns,nc->nc_rfp,IO_TIMEOUT) == S_RESUME ){
			sv1log("NNTPCC: RESUME on response: %s",line);
			return 0;
		}
	}
	if( code == 400 || code == 401 ){
		fputs(line,tc);
		return -1;
	}
	if( 400 < code ){
		penalty += 500;
		if( 1 < ++resp_errors ){
			if( EXIT_ON_ERRORS ){
				sv1log("#### delay on repetitive error [%d] %s",
					resp_errors,line);
				sleep(1+resp_errors/3);
			}
		}
	}else	resp_errors = 0;

	/* rewrite GROUP response */
	if( code == 211 ){
		int num,min,max;
		CStr(rgroup,1024);
		CStr(remain,1024);

		if( NX.ne_ondemand && !ns->ns_ondemand_yet ){
			/* 9.9.5 put into the GROUP cache */
			putGROUPcache(ns,line);
		}
		rgroup[0] = ngroup[0] = remain[0] = 0;
		Xsscanf(line,"%*d %d %d %d %[^ \r\n]%[^\r\n]",&num,&min,&max,AVStr(rgroup),AVStr(remain));
		if( rgroup[0] ){
			strcpy(ngroup,rgroup);
			mount_group_from1(sx,AVStr(ngroup));
			sprintf(line,"%d %d %d %d %s%s\r\n",code,num,min,max,
				ngroup,remain);
		}else{
			strcpy(rgroup,group);
			strcpy(ngroup,group);
		}
		setCurGroup(nsid,ns,ngroup,rgroup);
	}else
	if( code == 223 && strcasecmp(com,"XPATH") == 0 ){
		rewriteXPATH(ns,AVStr(line));
	}else
	if( code == 411 )
		((char*)curGroup)[0] = 0;

	decoding = get_decoding(stats,code);
	if( code == 100 ){
		Verbose("(100) decoding[%d->%d]\n",decoding,D_THRU);
		decoding = D_THRU;
	}else
	if( thru ){
		Verbose("(thru) decoding[%d->%d]\n",decoding,D_THRU);
		decoding = D_THRU;
	}else
	if( code == 221 && strcasecmp(com,"XHDR") == 0 ){
		Verbose("(XHDR) decoding[%d->%d]\n",decoding,D_OVER);
		decoding = D_OVER;
	}

	if( filter_withCFI(ns->ns_Conn,XF_FTOCL) ){
	    switch( decoding ){
		default:     putMESSAGEline(tc,"line",com); break;
		case D_HEAD: putMESSAGEline(tc,"head",com); break;
		case D_MIME: putMESSAGEline(tc,"mime",com); break;
		case D_THRU:
		case D_BODY:
		case D_OVER: putMESSAGEline(tc,"body",com); break;
	    }
	}

/*
 fprintf(stderr,"####RESP %s",line);
*/
	/* should be after rewriting of GROUP response */
	if( code == 220/*ARTICLE*/ && strcaseeq(com,"BODY") ){
	}else
	if( fputs(line,tc) == EOF )
		return -1;

	if( code == 100 )
		putHelp(tc);  /* must be after status code */

	enHTML = ENCODE_HTML_ENTITIES;
	cache = NULL;
	filter = 0;
	curAnum = 0;
	strcpy(curComd,com);

	if( code==220 || code==221 || code==222 || code==223 ){
		if( strcasecmp(com,"XHDR") != 0 ){
			sscanf(line,"%*d %d",&curAnum);
			if( curAnum )
				ns->ns_curanum = curAnum;
		}
		if( !(ns->ns_nocache & CACHE_ARTICLE) )
		if( code == 220 ) /* ARTICLE */
		if( statresp == NULL ) /* not from cache */
		if( cachedir() != NULL )
			cache = TMPFILE("-NNTP_relay_reaponse");

		if( code == 221 )
			filter = (1|0|0|8);
		else	filter = (1|2|4|8);
		if( statresp != NULL ) /* from cache */
			filter = (filter & (1|2|4));
	}
	/*
	if( code == 224 ){
		if( strcasecmp(com,"XOVER") == 0 )
		if( !(ns->ns_nocache & CACHE_OVERVIEW) )
			cache = TMPFILE("-NNTP_relay_response_XOVER");
	}
	*/

	if( !imCC ){
		if( RESPLOG ){
			sv1log("RESPLOG/%s:%d/%s=%s",group,curAnum,com,line);
		}
	}

	/*
	MIME_rewaddrs(NULL,VStrNULL);
	*/
setArticleMasks(ns->ns_rewaddr,ns->ns_host,ns->ns_port,curGroup,curAnum);
MIME_disableTransHead = 1;

	if( code == 220/*ARTICLE*/ && strcaseeq(com,"BODY") && cache ){
		sv1log("##BA resp <<< %s",line);
		setVStrElem(line,2,'2'); /* 220 ARTICLE -> 222 BODY */
		strsubst(AVStr(line)," ARTICLE\r\n"," BODY\r\n");
		sv1log("##BA resp >>> %s",line);
		fputs(line,tc);
		filter = (4|8); /* body part and EOR only to the client */
		PGPdecodeMIME(fs,tc,cache,filter,1,enHTML);
	}else
	switch( decoding ){
	case D_THRU: thruRESP(fs,tc); break;
	case D_HEAD:
	case D_MIME: PGPdecodeMIME(fs,tc,cache,filter,1,enHTML); break;
	case D_BODY: decodeBODY(fs,tc,filter,NULL,NULL,enHTML); break;
	case D_OVER: decodeTERM(fs,tc,0); break;
	}
	Verbose("%d response done (decode=%d).\n",code,decoding);
/*
 fprintf(stderr,"####RELAYED [%s]trh=%d ANON=%X\n",com,MIME_disableTransHead,MC_getAnons());
*/
	MC_setMasks(0);
	MC_setAnons(0);

	if( statresp != NULL )
		fflush(tc);

	if( cache != NULL ){
	    if( tobecached(nsid,ns->ns_curgroupR,curAnum) ){
		fflush(cache);
		fseek(cache,0,0);
		cache = spoolArticle(nsid,cache,ns->ns_curgroupR,curAnum);
	    }
	    fclose(cache);
	}
	return 0;
}

static
int NNTPrelay_responseX(NewsClient *nc,PCStr(statresp),PCStr(group),PCStr(com),int thru,RespStatus *stats,int sx,int nserv,NewsServer *servers,FILE *fs,FILE *tc){	int rcode;
	const char *ta;
	int ma;

	lastRcode = 0;
	ta = MIME_transAddrSpec;
	ma = MC_getAnons();

	rcode = NNTPrelay_response(nc,statresp,group,com,thru,stats,sx,nserv,servers,fs,tc);
	nntplog(nc,&servers[sx],lastRcode,group);

	MC_setAnons(ma);
	MIME_transAddrSpec = ta;
	return rcode;
}

static int relayResp1(NewsClient *nc,int si,int nserv,NewsServer *servers)
{	CStr(rgroup,1024);
	CStr(rreq,1024);
	CStr(rcom,1024);
	int rthru;
	FILE *rfp;
	FILE *tc = nc->nc_wfp;

	deqRequest(si,AVStr(rgroup),AVStr(rreq),&rthru);
	lineScan(rreq,curCommand);
	wordScan(rreq,rcom);
	rfp = servers[si].ns_rfp;

	/*
	if( NNTPrelay_response(nc,NULL,rgroup,rcom,rthru,
	*/
	if( NNTPrelay_responseX(nc,NULL,rgroup,rcom,rthru,
	    nntp_stats,si,nserv,servers,rfp,tc) < 0 )
		return 1;

	return 0;
}

static int nservers_remote()
{	int si,ns;

	ns = 0;
	for( si = 0; si < NserverN; si++ )
		if( !Nservers[si].ns_isself )
		if( Nservers[si].ns_dispensable != V_DISABLED )
			ns++;
	return ns;
}
static int nservers_active(int ign_self)
{	int si,nsa;
	NewsServer *ns;

	nsa = 0;
	for( si = 0; si < NserverN; si++ ){
		ns = &Nservers[si];
		if( !ign_self || !ns->ns_isself )
		if( !ns->ns_noact )
			nsa++;
	}
	return nsa;
}
static int nservers_POP()
{	int si,ns;

	ns = 0;
	for( si = 0; si < NserverN; si++ )
		if( strcmp(Nservers[si].ns_proto,"pop") == 0 )
			ns++;
	return ns;
}
static int server1()
{	int si;

	for( si = 0; si < NserverN; si++ )
		if( !Nservers[si].ns_isself )
			return si;
	return 0;
}
int NNTPserver(PVStr(host))
{
	if( 0 < NserverN ){
		strcpy(host,Nservers[0].ns_host);
		return Nservers[0].ns_port;
	}
	return 0;
}
static void asaServer(FILE *tc,PCStr(req),PCStr(com))
{
	if( strcasecmp(com,"HELP") == 0 ){
		fprintf(tc,"100 Legal commands\r\n");
		fprintf(tc,"HELP LIST GROUP DATE NEWNEWS\r\n");
		fprintf(tc,"ARTICLE HEAD BODY XOVER XPATH\r\n");
		fprintf(tc,"QUIT\r\n");
		fprintf(tc,"Report problems to <%s>\r\n",DELEGATE_ADMIN);
		fprintf(tc,"--\r\n");
		fprintf(tc,"NNTP-%s\r\n",DELEGATE_verdate());
		fprintf(tc,"%s\r\n",DELEGATE_copyright());
		fprintf(tc,".\r\n");
		return;
	}
	fprintf(tc,"500 What?\r\n");
}

static void selfNEXT(NewsServer *ns,FILE *tc,int do_now)
{	int anum;
	FILE *afp;
	int ai;

	if( do_now == DO_NEXT ){
		anum = ns->ns_curanum + 1;
		for( ai = 0; ai < 8; ai++ ){
			if( afp = ENEWS_article(NULL,curGroup,anum+ai) ){
				fclose(afp);
				fprintf(tc,"223 %d\r\n",anum+ai);
				ns->ns_curanum = anum+ai;
				return;
			}
		}
		/*
		if( afp = ENEWS_article(NULL,curGroup,anum) ){
			fclose(afp);
			fprintf(tc,"223 %d\r\n",anum);
			ns->ns_curanum = anum;
			return;
		}
		*/
	}
	if( do_now == DO_LAST ){
		anum = ns->ns_curanum - 1;
		for( ai = 0; ai < 8; ai++ ){
			if( afp = ENEWS_article(NULL,curGroup,anum-ai) ){
				fclose(afp);
				fprintf(tc,"223 %d\r\n",anum-ai);
				ns->ns_curanum = anum-ai;
				return;
			}
		}
	}
	fprintf(tc,"412 Not in a group\r\n");
}
static int selfSTAT(NewsServer *ns,PCStr(com),PCStr(arg),FILE *tc){
	int anum;
	FILE *afp;
	CStr(msgid,256);
	CStr(line,256);

	if( *arg == 0 )
		anum = ns->ns_curanum;
	else	anum = atoi(arg);
	if( anum <= 0 )
		return 0;

	if( afp = ENEWS_article(NULL,ns->ns_curgroup,anum) ){
		fgetsHeaderField(afp,"Message-ID",AVStr(msgid),sizeof(msgid));
		fclose(afp);
		sprintf(line,"223 %d %s\r\n",anum,msgid);
		fputs(line,tc);
		return 1;
	}
	return 0;
}

static int PenaltySleep(Connection *Conn,PCStr(com),PCStr(group))
{	int weight;
	double Now;

	Now = Time();

	/* long time connection penalty */
	if( MAX_CONNHOLD < Now - ServConnTime )
	if( lastPenaltySleep == 0 || MAX_CONNHOLD < Now - lastPenaltySleep )
		return 1;

	if( strstr(group,".sex") || strstr(group,".erotica") )
		weight = 100;
	else	weight = 1;

	if( strcaseeq(com,"LIST"   ) )  penalty += 200;      else
	if( strcaseeq(com,"GROUP"  ) ){
		if( strcmp(prevGroup,group) != 0 ){
			penalty += 100;
			Xstrcpy(ZVStr(prevGroup,512),group);
		}
	}else
	if( strcaseeq(com,"ARTICLE") )  penalty += weight*2; else
	if( strcaseeq(com,"HEAD"   ) )  penalty += weight;

	return 1000 < penalty;
}

static void setMODE(NewsClient *nc,int nserv,NewsServer *servers)
{	FILE *tc = nc->nc_wfp;
	const char *req = nc->nc_do_req.r_req;
	FILE *rfp;
	int si;

	for( si = 0; si < nserv; si++ )
		FPUTS(req,servers[si].ns_wfp);

	for( si = 0; si < nserv; si++ ){
		if( rfp = servers[si].ns_rfp )
		NNTPrelay_response(nc,NULL,"","MODE",0,
			nntp_stats,si,nserv,servers,rfp,NULLFP());
	}
	putIdent(tc,"");
}

static void sched_action(Connection *Conn,PCStr(action))
{	int si;
	NewsServer *ns;
	CStr(resp,1024);

sv1log("####NNTP_SCHED_ACTION: %s [%d]\n",action,NserverN);
	if( streq(action,"ping") ){
		for( si = 0; si < NserverN; si++ ){
			FPUTS("date\r\n",Nservers[si].ns_wfp);
		if( fgetsFS(AVStr(resp),sizeof(resp),Nservers[si].ns_rfp) == NULL )
			break;
sv1log("####[%d] %s",si,resp);
		}
	}else
	if( streq(action,"cache") ){
	}
}

#define C_CONT	 0
#define C_THRU	 1
#define C_RESUME 2
#define C_EXIT	-1

static int do_sync(Connection *Conn,NewsClient *nc,int nserv,NewsServer *servers)
{	int do_now;
	FILE *tc = nc->nc_wfp;
	FILE *fc = nc->nc_rfp;
	int sx;
	NewsServer *ns;

	if( DO_afterflush == 0 )
		return C_THRU;
	if( QueueLeng != 0 && nservers_remote() != 0 )
		return C_THRU;
	for( sx = 0; sx < nserv; sx++ ){
		ns = &servers[sx];
		if( ns->ns_dispensable != V_DISABLED )
		if( !ns->ns_isself && ns->ns_openingmsg == NULL ){
			sv1log("delay do_sync(%d) untill all servers(%d) up, Q=%d\n",
				DO_afterflush,nservers_remote(),QueueLeng);
			return C_THRU;
		}
	}

	fflush(tc);
	do_now = DO_afterflush;
	DO_afterflush = 0;

	if( do_now == DO_SYNC ){
		return C_CONT;
	}else
	if( do_now == DO_INIT ){
		if( NNTP_CC && initialized ){
			Verbose("NNTPCC: DONT REPEAT INITIALIZE\n");
		}else{
			sv1log("DO_INIT\n");
			getCONFIGs(nserv,servers);
			if( COMPLEX ){
				CStr(req,1024);
				CStr(com,1024);
				CStr(arg,1024);
				/* this is not necessary for simple relay */
				strcpy(req,"LIST\r\n");
				strcpy(com,"LIST");
				arg[0] = 0;
				mergeLIST(AVStr(req),com,AVStr(arg),NULLFP(),nserv,servers);
			}
			initialized = 1;
		}
		return C_CONT;
	}else
	if( do_now == DO_MODE ){
		setMODE(nc,nserv,servers);
		return C_CONT;
	}else
	if( do_now == DO_POST ){
		if( NNTP_POST(nc,fc,tc,curGroup,nserv,servers) < 0 )
			return C_EXIT;
		else	return C_CONT;
	}else
	if( do_now == DO_IHAVE ){
		if( NNTP_IHAVE(nc,fc,tc,curGroup,nserv,servers) < 0 )
			return C_EXIT;
		else	return C_CONT;
	}else
	if( do_now == DO_LIST ){
		mergeLIST(AVStr(DO_req),DO_com,AVStr(DO_arg),tc,nserv,servers);
		return C_CONT;
	}else
	if( do_now == DO_XOVER ){
		int serverx;
		int nsid;
		CStr(rgroup,1024);

		serverx = select_server(nserv,servers,curGroup,DO_com,DO_arg);
		nsid = toNSID(serverx);
		mount_group_to1(toNS(nsid),curGroup,AVStr(rgroup));
		NNTP_XOVER(fc,tc,nsid,rgroup,DO_arg);
		return C_CONT;
	}else
	if( do_now == DO_NEXT || do_now == DO_LAST ){
		CStr(resp,1024);
		int serverx;
		NewsServer *ns;

		serverx = select_server(nserv,servers,curGroup,DO_com,DO_arg);
		ns = &servers[serverx];

		if( ns->ns_isself )
			selfNEXT(ns,tc,do_now);
		else{
			fprintf(ns->ns_wfp,"STAT %d\r\n",ns->ns_curanum);
			fflush(ns->ns_wfp);
			fgetsFS(AVStr(resp),sizeof(resp),ns->ns_rfp);
			fprintf(ns->ns_wfp,"%s\r\n",DO_com);
			enqRequest(serverx,curGroup,DO_req,DO_com,"",NULL);
		}
		return C_CONT;
	}else
	if( do_now == DO_GROUP ){
		sv1log("DO_GROUP\n");
		setCurGroup(GRP.nsid,GRP.ns,GRP.D_group,GRP.D_rgroup);
		fputs(GRP.D_status,tc);
		return C_CONT;
	}else
	if( do_now == WAIT_GROUP ){
/*
XOVER, HEAD, BODY, ARTICLE
should wait completion of pending GROUP
*/
	}else
	if( do_now == DO_QUIT ){
		sv1log("DO_QUIT\n");
		fprintf(tc,"205 bye.\r\n");
		return C_EXIT;
	}else
	if( do_now == DO_SUSPEND || do_now == DO_PENALTY ){
		int timeout;
		FILE *FC;
		if( do_now == DO_PENALTY ){
			timeout = PENALTY_SLEEP;
			FC = NULL;
			sv1log("penalty sleep(%d) %d * %s\n",
				timeout,penalty,curGroup);
			lastPenaltySleep = (int)(Time() + timeout);
		}else{
			timeout = IO_TIMEOUT;
			FC = fc;
		}
		switch( suspend(Conn,timeout,FC,tc,nserv,servers) ){
		    case S_NOSUSP: if( do_now == DO_PENALTY )
					sleep(timeout);
				   return C_RESUME;
		    case S_RESUME: return C_RESUME;
		    case S_TOBECC: return C_EXIT;
		    case S_TOQUIT: fputs("205 bye.\r\n",tc);
				   return C_EXIT;
		    case S_TOCLOSE:
			fputs("401 connection closed by timeout-2.\r\n",tc);
		    default:
			if( do_now == DO_SUSPEND )
				sv1log("TIMEOUT max idle-2 (%d)\n",timeout);
			else	sv1log("closed in penalty sleep.\n");
			return C_EXIT;
		}
	}else
	if( do_now == DO_ECHO ){
		fprintf(tc,"%s\r\n",DO_arg);
		return C_CONT;
	}else
	if( do_now == DO_CACHE ){
		int serverx;
		NewsServer *ns;
		serverx = select_server(nserv,servers,curGroup,DO_com,DO_arg);
		ns = &servers[serverx];

		if( !localsocket(ClientSock) )
			fprintf(tc,"500 XCACHE by remote is forbidden.\r\n");
		else	NNTP_CACHE(ns,nc,curGroup,DO_com,DO_arg);
		return C_CONT;
	}
else
{
if( !ServViaCc ) /* tentative */
DELEGATE_session_sched_execute(time(0),(iFUNCP)sched_action,Conn);
}
	return C_THRU;
}

static void flushallSV(int nserv,NewsServer *servers)
{	int si;

	for( si = 0; si < nserv; si++ )
		FFLUSH(servers[si].ns_wfp);
}
#define setSync(do_com) {\
	flushallSV(nserv,servers); \
	DO_afterflush = do_com; \
	DO_ns = ns; \
	strcpy(DO_req,ReqBuf); \
	strcpy(DO_com,com); \
	strcpy(DO_arg,arg); \
}

static void putField1(NewsServer *ns,PCStr(group),int anum,FILE *afp,FILE *tc,PCStr(field)){
	CStr(from,1024);
	CStr(line,1024);
	CStr(xline,1024);
	const char *rewaddr;

	if( fgetsHeaderField(afp,field,AVStr(line),sizeof(line)) == NULL )
		return;
	strsubst(AVStr(line),"\n"," ");
	strsubst(AVStr(line),"\r\n"," ");
	/* should check if the field is Masked or no ... */
	if( rewaddr = ns->ns_rewaddr ){
		/* should see nm_rewaddr */
		setArticleMasks(rewaddr,ns->ns_host,ns->ns_port,group,anum);
		if( fgetsHeaderField(afp,"From",AVStr(from),sizeof(from)) ){
			setPosterMasks(from);
		}
	}
	MIME_strHeaderDecode(line,AVStr(xline),sizeof(xline));
	rewriteHeader(ns,AVStr(xline),field);
	fputs(xline,tc);
}
/*
static void putXHDR1(FILE *tc,FILE *fc,PCStr(field),PCStr(range), int isself,FILE *ts,FILE *fs,PCStr(proto),PCStr(rgroup),int ranum)
*/
static void putXHDR1(NewsServer *ns,FILE *tc,FILE *fc,PCStr(field),PCStr(range), int isself,FILE *ts,FILE *fs,PCStr(proto),PCStr(rgroup),int ranum)
{	int artnum1,artnum2,anum;
	CStr(resp,1024);
	FILE *afp;

	if( range[0] == '<' ){
		if( strcmp(proto,"pop") == 0 )
			artnum1 = POP_findMessageid(ts,fs,range);
		else	artnum1 = 0;
		artnum2 = artnum1;
	}else{
		artnum1 = artnum2 = 0;
		sscanf(range,"%d-%d",&artnum1,&artnum2);
		if( artnum1 == 0 ) artnum1 = ranum;
		if( artnum2 == 0 ) artnum2 = artnum1;
	}

	fprintf(tc,"221 %s fields follow\r\n",field);
	for( anum = artnum1; anum <= artnum2; anum++ ){
		if( strcmp(proto,"pop") == 0 ){
			fprintf(ts,"RETR %d\r\n",anum);
			fflush(ts);
			if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
				break;
			if( resp[0] != '+' )
				break;
			fprintf(tc,"%d ",anum);
			if( RFC821_skipheader(fs,tc,field) != EOF )
			    RFC821_skipbody(fs,NULL,AVStr(resp),sizeof(resp));
		}else
		if( isself ){
			if( afp = ENEWS_article(NULL,rgroup,anum) ){
				fprintf(tc,"%d ",anum);
				if( ns && ns->ns_rewaddr ){
					putField1(ns,rgroup,anum,afp,tc,field);
				}else
				RFC821_skipheader(afp,tc,field);
				fclose(afp);
			}
		}else{
		}
		fprintf(tc,"\r\n");
	}
	fprintf(tc,".\r\n");
}
static void putXHDR(NewsServer *ns,FILE *tc,FILE *fc,PCStr(field),PCStr(range))
{
	/*
	putXHDR1(tc,fc,field,range,
	*/
	putXHDR1(ns,tc,fc,field,range,
		ns->ns_isself,ns->ns_wfp,ns->ns_rfp,ns->ns_proto,
		ns->ns_curgroupR,ns->ns_curanum);
}

static int cancelled_article(NewsServer *ns,FILE *afp,PCStr(group),PCStr(com),PCStr(req))
{	int age;
	int anum;
	CStr(resp,1024);
	int last;

	if( afp == NULL )
		return 0;
	age = file_age("",afp);

	last = 0;
	if( last < ns->ns_OPENtime ) last = ns->ns_OPENtime;
	if( last < ns->ns_LISTtime ) last = ns->ns_LISTtime;
	if( last < ns->ns_POSTtime ) last = ns->ns_POSTtime;

	if( age < time(0) - last )
		return 0;

	if( !strcaseeq(com,"ARTICLE")
	 && !strcaseeq(com,"HEAD")
	 && !strcaseeq(com,"BODY")
	)	return 0;

	anum = 0;
	sscanf(req,"%*s %d",&anum);
	if( anum <= 0 )
		return 0;

	fprintf(ns->ns_wfp,"STAT %d\r\n",anum);
	fflush(ns->ns_wfp);
	resp[0] = 0;
	fgets(resp,sizeof(resp),ns->ns_rfp);
	sv1log("age=%d [%s][%s %d] STAT=%s",age,group,com,anum,resp);

	if( atoi(resp) == 423 )
		return 1;

	ftouch(afp,time(0));
	return 0;
}

static void NNTPrelay_request(Connection *Conn,Session *Sp,NewsClient *nc,int nserv,NewsServer *servers)
{	NewsServer *ns;
	FILE *tc = nc->nc_wfp;
	FILE *fc = nc->nc_rfp;
	FILE *fps[1+NSERVER],*afp;
	int si,nact,ri,nready,rdv[1+NSERVER],siv[1+NSERVER],pollstart;
	CStr(com,128);
	CStr(arg,128);
	const char *dp;
	int gotEOF,gotEOF1;
	int serverx,rserverx;

	getClientAddrId(Conn,FVStr(mailClientAddr),FVStr(mailClientId));

	if( NICE_VAL )
		IGNRETZ nice(NICE_VAL);

	fps[0] = fc;
	siv[0] = -1;

	penalty = 0;
	resp_errors = 0;
	((char*)curGroup)[0] = 0;
	curCommand[0] = 0;
	curNsid = 0;

	set_HEAD_filter(permitted_head);

	for(;;){
	RESUME:
		if( 10 < resp_errors ){
			if( EXIT_ON_ERRORS ){
				sv1log("#### exit on repetitive error [%d]\n",
					resp_errors);
				break;
			}
		}

		/* soft EOF by NO_ACTIVES may returned from the upper stream */
		if( NserverN != 0 && nservers_active(0) == 0 ){
			sv1log("No active servers (%d)\n",NserverN);
			fprintf(tc,"%d No active server (DeleGate).\r\n",
				RC_NO_ACTIVES);
			fflush(tc);
			break;
		}

		nact = 0;
		if( 0 <= (si = cur_serverx()) ){
			if( !servers[si].ns_isself ){
				siv[1+nact] = si;
				fps[1+nact] = servers[si].ns_rfp;
				nact++;
			}
			incRequestSerno(Conn);
		}else
		for( si = 0; si < nserv; si++ ){
			if( servers[si].ns_dispensable == V_DISABLED ){
				/* ignore */
			}else
			if( !servers[si].ns_isself ){
				siv[1+nact] = si;
				fps[1+nact] = servers[si].ns_rfp;
				nact++;
			}
		}

		/* FLUSH the response to the client if no response
		 * from servers is ready.
		 */
		nready = 0;
		for( ri = 1; ri < 1+nact; ri++ ){
			if( fps[ri] == NULL ){
				sv1log("EXIT: server[%d] closed?\n",ri);
				goto EXIT;
			}
			if( 0 < ready_cc(fps[ri]) )
				nready++;
		}
		if( nready == 0 )
			fflush(tc);

		/* FLUSH requests to servers if no request from the
		 * client is ready.
		 */
		if( ready_cc(fc) == 0 || DO_afterflush )
			for( si = 0; si < nserv; si++ )
				FFLUSH(servers[si].ns_wfp);

		switch( do_sync(Conn,nc,nserv,servers) ){
			case C_CONT:	continue;
			case C_RESUME:	goto RESUME;
			case C_EXIT:	goto EXIT;
			default:	sv1log("### unknown code do_sync()\n");
			case C_THRU:	break;
		}

		if( afp = cachedResponse(&rserverx) ){
			CStr(rgroup,1024);
			CStr(rreq,1024);
			CStr(rcom,1024);
			int rthru;
			CStr(statresp,1024);

			deqRequest(rserverx,AVStr(rgroup),AVStr(rreq),&rthru);
			wordScan(rreq,rcom);
			ns = &servers[rserverx];

			if( strcasecmp("HELP",rcom) == 0 ){
				fprintf(tc,"%s",ns->ns_helpmsg);
				putHelp(tc);
				fprintf(tc,".\r\n");
				continue;
			}
			if( afp == NULLFP() ){
				fprintf(tc,"423 Bad article number (1)\r\n");
				continue;
			}

			if( cancelled_article(ns,afp,rgroup,rcom,rreq) ){
				fclose(afp);
				fprintf(tc,"423 Bad article number (2)\r\n");
				continue;
			}

			/*
			afp = makeArtResponse(AVStr(statresp),rreq,ns->ns_curanum,afp);
			*/
			afp = makeArtResponse(AVStr(statresp),rreq,ns,afp);
			/*
			if( NNTPrelay_response(nc,statresp,rgroup,rcom,rthru,
			*/
			lineScan(rreq,curCommand);
			if( NNTPrelay_responseX(nc,statresp,rgroup,rcom,rthru,
				nntp_stats,rserverx,nserv,servers,afp,tc) < 0 ){
					gotEOF = 1;
					break;
			}
			fprintf(tc,".\r\n");
			fclose(afp);
			continue;
		}

		pollstart = time(0);
		for(;;){
			int timeout1,start,elapsed,idle;

			if( initialized )
				timeout1 = 10*1000;
			else	timeout1 = 60*1000;

			start = time(0);
			if( DO_afterflush )
				nready = fPollIns(timeout1,nact,fps+1,rdv+1);
			else	nready = fPollIns(timeout1,nact+1,fps,rdv);

			if( 0 < nready )
				break;
 if( !ServViaCc ){ /* tentative */
 DELEGATE_session_sched_execute(time(0),(iFUNCP)sched_action,Conn);
 }

			elapsed = time(0) - start;
			if( nready < 0 && waiting_ondemand_serv(FL_ARG,0) ){
				/* 9.9.5 redirected to the real-server */
				continue;
			}
			if( nready < 0 || nready == 0 && elapsed == 0 ){
				sv1log("EXIT: NO ready stream. %d/%d\n",
					nready,elapsed);
				no_activesv = 1;
				goto EXIT;
			}

			idle = time(0) - pollstart;
			if( 0 < IO_TIMEOUT && IO_TIMEOUT <= idle ){
				sv1log("TIMEOUT max idle-1 (%d)\n",IO_TIMEOUT);
				fputs("401 connection closed by timeout-1.\r\n",tc);
				fflush(tc);
				goto EXIT;
			}
			clrAbortLog();

			/* Suspend server connecion on long client's idle in
			 * the client-side CC.
			 * Don't suspend before server initialization.
			 * Don't suspend in the server-side CC.
			 */
			if( initialized )
			if( DO_afterflush == 0 )
			if( 0 < CLCC_TIMEOUT && CLCC_TIMEOUT <= idle )
			if( !ImCC && nservers_active(1) == 1 ){
				if( QueueLeng != 0 )
					sv1log("NNTPCC: do SUSPEND, QL=%d\n",QueueLeng);
				setSync(DO_SUSPEND);
				goto RESUME;
			}
		}

		gotEOF = 0;
		for( ri = 1; ri < 1+nact; ri++ ){
			if( 0 < rdv[ri] ){
				si = siv[ri];
				gotEOF1 = relayResp1(nc,si,nserv,servers);
				if( gotEOF1 ){
					ns = &servers[si];
					if( NE_dispensable || ns->ns_dispensable == 1 ){
						sv1log("## dismounted [%d] %s\n",
							ns->ns_nsid,ns->ns_host);
						ns->ns_dispensable = V_DISABLED;
						rdv[ri] = 0;
						gotEOF1 = 0;
					}
				}
				gotEOF |= gotEOF1;
				if( gotEOF1 )
					sv1log("EOF from server[%d]\n",si);
			}
		}
		if( gotEOF ){
			sv1log("EOF from servers\n");
			break;
		}

		if( DO_afterflush || rdv[0] <= 0 )
			continue;

		if( Xfgets(AVStr(ReqBuf),sizeof(ReqBuf),fc) == NULL ){
			if( !imCC )
				sv1log("CS-EOF. eof=%d err=%d\n",feof(fc),errno);
			if( NNTP_CC )
				Verbose("NNTPCC: DONT RELAY QUIT(1)\n");
			else{
				for( si = 0; si < nserv; si++ )
					FPUTS("QUIT\r\n",servers[si].ns_wfp);
			}
			break;
		}
		if( ReqBuf[0] == '\r' || ReqBuf[0] == '\n' )
			continue;
		Verbose("## C-S %s",ReqBuf);

		if( dp = wordScan(ReqBuf,com) )
			lineScan(dp,arg);
		else	arg[0] = 0;
		if( 1 ){
			commandMount(Conn,AVStr(ReqBuf),AVStr(com),AVStr(arg));
		}

		if( !ImCC && nservers_active(1) == 1 )
		if( PENALTY_SLEEP )
		if( DO_afterflush == 0 ){
			if( PenaltySleep(Conn,com,curGroup) ){
				setSync(DO_PENALTY);
				penalty = 0;
				/*continue;*//* NO! must relay the request */
			}
		}

		if( needProxyAuth && proxyAuthOK == 0 )
		if( !strcaseeq(com,"QUIT") ){
			CStr(com1,64);
			CStr(arg1,64);
			CStr(user,128);
			CStr(host,64);

			if( strcaseeq(com,"AUTHINFO") ){
			    dp = wordScan(arg,com1);
			    wordScan(dp,arg1);
			    if( strcaseeq(com1,"USER") ){
				strcpy(proxyUSER,arg1);
				fprintf(tc,"381 PASS required [DeleGate]\r\n");
				continue;
			    }
			    if( strcaseeq(com1,"PASS") ){
				if( proxyUSER[0] == 0 ){
					fprintf(tc,"482 USER required.\r\n");
					continue;
				}
				sprintf(user,"%s:%s",proxyUSER,arg1);
				host[0] = 0;
				if( proxyAuth(Conn,AVStr(user),AVStr(host)) == EOF ){
					sv1log("AUTHINFO ERR[%s].\n",proxyUSER);
					fprintf(tc,"502 Auth. ERROR.\r\n");
					break;
				}else{
					sv1log("AUTHINFO OK [%s].\n",proxyUSER);
					fprintf(tc,"281 OK [DeleGate]\r\n");
					proxyAuthOK = 1;
				}
				continue;
			    }
			}
			/* ask AUTHINFO here if the command is in explicitly
			 * specified NNTPCONF=authcom:comList
			 * or this DeleGate is not an origin server.
			 */
			if( needAuthCom && needAuthMethod(com)
			|| !needAuthCom && nservers_remote()
			){
			sv1log("#### require AUTHINFO for '%s'\n",com);
			fprintf(tc,"480 Authentication required[DeleGate]\r\n");
			continue;
			}
		}

		if( strcasecmp(com,"XECHO") == 0 ){
			setSync(DO_ECHO);
			continue;
		}
		if( strcasecmp(com,"XSUSPEND") == 0 ){
			fprintf(tc,"200 suspending...\r\n");
			fflush(tc);
			setSync(DO_SUSPEND);
			goto RESUME;
		}
		if( strcasecmp(com,"XLIST") == 0 ){
			strcpy(com,"LIST");
			if( strcasecmp(arg,"difference") == 0 )
				strcpy(arg,"ACTIVE ++");
			sprintf(ReqBuf,"%s %s\r\n",com,arg);
		}

		if( NserverN == 0 ){
			if( strcasecmp(com,"QUIT") == 0 ){
				sv1log("QUIT, NserverN==0\n");
				break;
			}
			fprintf(tc,"%d No active server (DeleGate).\r\n",
				RC_NO_ACTIVES);
			continue;
		}

		serverx = select_server(nserv,servers,curGroup,com,arg);
		if( 0 <= serverx )
			ns = &servers[serverx];
		else	ns = NULL;

		if( !permitted_command(ns,com,arg) ){
			fprintf(tc,"500 Forbidden command [%s].\r\n",com);
			sv1log("Forbidden command [%s]\n",com);
			continue;
		}
		if( method_permitted(Conn,"nntp",com,1) == 0 ){
			fprintf(tc,"500 forbidden NNTP/%s\r\n",com);
			sv1log("forbidden NNTP/%s\n",com);
			continue;
		}

		if( ns && ns->ns_needAuth && ns->ns_authOK == 0 )
		if( ns->ns_isself && proxyAuthOK ){
			ns->ns_authOK = 1;
		}else
		if( 0 <= CTX_auth(Conn,"","") ){
			sv1log("#### ACCEPT without AUTHINFO\n");
			ns->ns_authOK = 2;
		}else
		if( needAuthMethod(com) ){
			sv1log("#### require AUTHINFO for '%s'\n",com);
			fprintf(tc,"480 Authentication required.\r\n");
			continue;
		}

		if( strcasecmp(com,"RIDENT") == 0 ){
			CStr(peer,128);
			CStr(sock,128);

			if( (ClientFlags & PF_RIDENT_RECV) == 0 ){
				sv1log("NNTP RIDENT recv [%s] NONE\n",arg);
				fprintf(tc,"500 NO RIDENT\r\n");
				continue;
			}
			Xsscanf(arg,"%s %s",AVStr(sock),AVStr(peer));
			setOriginIdent(Conn,sock,peer);
			fprintf(tc,"200 OK\r\n");
			sv1log("NNTP RIDENT recv [%s][%s]<-[%s][%s]\n",
				sock,peer,TelesockHost,TeleportHost);
			continue;
		}
		if( strcasecmp(com,"XCACHE") == 0 ){
			sv1log("XCACHE after response flush (%d)\n",QueueLeng);
			setSync(DO_CACHE);
			continue;
		}
		if( strcasecmp(com,"POST") == 0 ){
			sv1log("POST after response flush (%d)\n",QueueLeng);
			setSync(DO_POST);
			continue;
		}
		if( strcasecmp(com,"IHAVE") == 0 ){
			sv1log("IHAVE after response flush (%d)\n",QueueLeng);
			setSync(DO_IHAVE);
			continue;
		}
		if( strcaseeq(com,"LIST") || strcaseeq(com,"NEWGROUPS") ){
			Verbose("LIST after response flush (%d)\n",QueueLeng);
			setSync(DO_LIST);
			continue;
		}
		if( strcaseeq(com,"COMPRESS") ){
			CStr(client,1024);

			compressLIST = 1;
			fprintf(tc,"%d compression set [%s]\r\n",
				RC_OK_COMPRESS,arg);
			getClientHostPort(Conn,AVStr(client));

			if( !imCC )
			sv1log("COMPRESS %s requested from %s\n",arg,client);
			continue;
		}
		if( strcasecmp(com,"MODE") == 0 && nserv != 1 ){
			Verbose("MODE after response flush (%d)\n",QueueLeng);
			setSync(DO_MODE);
			continue;
		}
		if( strcaseeq(com,"XOVER") ){
			if( curGroup[0] == 0 ){
				fprintf(tc,"412 Not in a newsgroup\r\n");
				continue;
			}
			if( ns )
			if( ns->ns_isself
			 || streq(ns->ns_proto,"pop")
			 || (ns->ns_emulate & EMULATE_XOVER)
			){
				sv1log("XOVER %s after response flush (%d)\n",
					arg,QueueLeng);
				setSync(DO_XOVER);
				continue;
			}
		}

		if( strcasecmp(com,"HELP") == 0 && ns && ns->ns_helpmsg != NULL ){
			enqRequest(serverx,curGroup,ReqBuf,com,arg,NULLFP());
			continue;
		}

		if( strcasecmp(com,"HEAD") == 0
		 || strcasecmp(com,"BODY") == 0
		 || strcasecmp(com,"ARTICLE") == 0
		 /*|| strcasecmp(com,"XOVER") == 0*/
		){
			int nsid;
			const char *groupR;

			nsid = toNSID(serverx);
			if( (groupR = ns->ns_curgroupR) == 0 )
				groupR = curGroup;

			if( curGroup[0] || arg[0] == '<' )
				afp = lookaside_cache(nsid,groupR,com,arg);
			else	afp = NULL;

			if( afp != NULL ){
				enqRequest(serverx,curGroup,ReqBuf,com,arg,afp);
				ns->ns_cacheused++;
				continue;
			}
			if( ns->ns_isself ){
				enqRequest(serverx,curGroup,ReqBuf,com,arg,
					NULLFP());
				continue;
			}

		}
		if( strcaseeq(com,"AUTHINFO") ){
			if( withAuth == 0 )
				sv1log("#### withAuth=1 suppress NNTPCC\n");
			withAuth = 1;
		}
		if( strcaseeq(com,"STAT") ){
			if( ns->ns_isself ){
				CStr(path,128);
				CStr(line,1024);

				if( arg[0] == '<' ){
				 if( ENEWS_path(arg,AVStr(path),ns->ns_mounted_file) ){
					sprintf(line,"223 0 <%s>\r\n",arg);
					fputs(line,tc);
					continue;
				 }
				}
				if( selfSTAT(ns,com,arg,tc) ){
					continue;
				}
				fprintf(tc,"430 not found.\r\n");
				continue;
			}
		}
		if( strcaseeq(com,"XPATH") ){
			if( ns->ns_isself ){
				CStr(path,128);
				CStr(line,1024);
				if( ENEWS_path(arg,AVStr(path),ns->ns_mounted_file) ){
					sprintf(line,"223 %s\r\n",path);
					rewriteXPATH(ns,AVStr(line));
					fputs(line,tc);
				}else	fprintf(tc,"430 not found.\r\n");
				continue;
			}
		}
		if( strcasecmp(com,"ARTICLE") == 0 ){
			if( mountedARTICLE(tc,ReqBuf+7) )
				continue;
		}
		if( strcasecmp(com,"XHDR") == 0 ){
			CStr(field,128);
			CStr(range,128);
			range[0] = 0;
			if( curGroup[0] == 0 ){
				fprintf(tc,"412 Not in a newsgroup\r\n");
				continue;
			}
			if( 1 <= Xsscanf(arg,"%s %s",AVStr(field),AVStr(range)) )
			if( ns->ns_isself ){
				putXHDR(ns,tc,fc,field,range);
				continue;
			}
		}


		if( strcasecmp(com,"GROUP") == 0 ){
			CStr(group,256);
			CStr(rgroup,256);
			int nsid;

			wordScan(ReqBuf+5,group);
			mount_group_to1(ns,group,AVStr(rgroup));
			nsid = permitted_group(rgroup);

			if( nsid == 0 ){
				fprintf(tc,"500 Forbidden group [%s].\r\n",
					group);
				sv1log("Forbidden GROUP [%s]\n",group);
				continue;
			}
			if( restricted || hidden )
			if( strcmp(group,curGroup) != 0 )
				sv1log("GROUP %s == %s@%s:%d [%d]\n",group,rgroup,
				ns->ns_host,ns->ns_port,serverx);

			sprintf(ReqBuf,"GROUP %s\r\n",rgroup);
			ns->ns_lastGROUP = time(0);

			if( ns->ns_isself ){
			int total,min,max;
			if( ENEWS_group(rgroup,&total,&min,&max) ){
				setSync(DO_GROUP);
				GRP.nsid = nsid;
				GRP.ns = ns;
				strcpy(GRP.D_group,group);
				strcpy(GRP.D_rgroup,rgroup);
				sprintf(GRP.D_status,"211 %d %d %d %s\r\n",
					total,min,max,group);
				continue;
			}
			}

			/* 9.4.1 to get the cached article on pipelined
			 * GROUP+ARTICLE, curGroup[] need to be set
			 * before the interpretation of ARTICLE
			 */
			setSync(DO_SYNC);
		}
		if( strcaseeq(com,"NEWNEWS") ){
			CStr(group,256);
			CStr(rgroup,256);
			const char *xarg;
			int sx,date;
			NewsServer *Ns;
			FILE *tmp;

			xarg = wordScan(arg,group);
			sx = select_server(nserv,servers,group,com,arg);
			if( 0 <= sx ){
				Ns = &servers[sx];
				if( Ns->ns_isself ){
					date = YMD_HMS_toi(xarg);
					tmp = TMPFILE("NENEWS");
					mount_group_to1(Ns,group,AVStr(rgroup));
					ENEWS_newnews(tmp,rgroup,date);
					fflush(tmp);
					fseek(tmp,0,0);
					fprintf(tc,"230 New news follows\r\n");
					copyfile1(tmp,tc);
					fprintf(tc,".\r\n");
					fclose(tmp);
					continue;
				}
			}
		}
		if( strcaseeq(com,"DATE") ){
			if( ns->ns_isself || streq(ns->ns_proto,"pop") ){
				CStr(sdate,32);
				StrftimeGMT(AVStr(sdate),sizeof(sdate),"%Y%m%d%H%M%S",
					time(0),0);
				fprintf(tc,"111 %s\r\n",sdate);
				continue;
			}
		}

		/* <STAT curanum> should be sent before NEXT/LAST command */
		/*
		this code was introduced in 2.9.3 just to process NEXT locally
		without forwarding the NEXT command to the server
		if( ns->ns_cacheused )
		*/
		if( ns->ns_cacheused || ns->ns_isself )
		if( strcasecmp(com,"NEXT") == 0
		 || strcasecmp(com,"LAST") == 0
		){
			if( strcasecmp(com,"NEXT") == 0 ){
				setSync(DO_NEXT);
			}else	setSync(DO_LAST);
			ns->ns_cacheused = 0;
			continue;
		}

		if( strcasecmp(com,"QUIT") == 0 ){
			if( NNTP_CC )
				Verbose("NNTPCC: DONT RELAY QUIT(2)\n");
			else{
				sv1log("QUIT after response flush (%d)\n",QueueLeng);
				for( si = 0; si < nserv; si++ )
					FPUTS(ReqBuf,servers[si].ns_wfp);
			}
			setSync(DO_QUIT);
			continue;
		}
		if( ns->ns_isself ){
			asaServer(tc,ReqBuf,com);
			continue;
		}

		enqRequest(serverx,curGroup,ReqBuf,com,arg,NULL);
		if( strcaseeq(com,"BODY") ){
			if( !ns->ns_islocal )
			if( cachedir() && !(ns->ns_nocache & CACHE_ARTICLE) ){
				sv1log("##BA send ARTICLE for BODY %s\n",arg);
				sprintf(ReqBuf,"ARTICLE %s\r\n",arg);
			}
		}

		if( 0 < nserv ){
			CStr(hostport,MaxHostNameLen);

			Verbose("put[%d] %s",serverx,ReqBuf);
			HostPort(AVStr(hostport),"nntp",ns->ns_host,ns->ns_port);
			ProcTitle(Conn,"nntp://%s/",hostport);
			if( FPUTS(ReqBuf,servers[serverx].ns_wfp) == EOF ){
				sv1log("cannot put server: %s",ReqBuf);
				break;
			}
		}
	}

EXIT:	return;
}

static int POP_getField(FILE *ts,FILE *fs,int mno,PCStr(field),PVStr(value))
{	CStr(resp,1024);
	int flen;

	flen = strlen(field);
	fprintf(ts,"RETR %d\r\n",mno);
	fflush(ts);
	if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
		return -1;
	if( resp[0] != '+' )
		return -1;

	for(;;){
		if( fgetsFSline(AVStr(resp),sizeof(resp),fs) == NULL )
			return -1;
		if( isEOR(resp) )
			break;
		if( isEOH(resp) ){
			thruRESP(fs,NULLFP());
			break;
		}
		if( strncasecmp(resp,field,flen) == 0 && resp[flen] == ':' ){
			thruRESP(fs,NULLFP());
			strcpy(value,resp+flen+1);
			return 1;
		}
	}
	return 0;
}

typedef struct {
	int	 mno;
  const	char	*mid;
} Msg;
static struct {
	Msg    *mc_mids;
	int	mc_midsN;
	int	mc_midsF;
} NNTP_midCache;
#define mids	NNTP_midCache.mc_mids
#define midsN	NNTP_midCache.mc_midsN
#define midsF	NNTP_midCache.mc_midsF

static void cacheit(int mno,PCStr(amid))
{	int nsize;

	if( midsN <= midsF ){
		nsize = midsN + 128;
		if( mids == NULL )
			mids =(Msg*)malloc((nsize+1)*sizeof(Msg));
		else	mids =(Msg*)realloc(mids,(nsize+1)*sizeof(Msg));
		midsN = nsize;
	}
	mids[midsF].mno = mno;
	mids[midsF].mid = stralloc(amid);
	midsF++;
}
static const char *cachedmid(int mno)
{	int mx;

	for( mx = 0; mx < midsF; mx++ )
		if( mids[mx].mno == mno ) 
			return mids[mx].mid;
	return 0;
}
static int cachedmno(PCStr(mid))
{	int mx;
	Msg *mp;

	for( mx = 0; mx < midsF; mx++ ){
		mp = &mids[mx];
		if( mp->mid != NULL && strstr(mp->mid,mid) )
			return mp->mno;
	}
	return 0;
}
static FILE *openLIST(PCStr(which),PCStr(host),int port)
{	CStr(cachepath,1024);
	FILE *actfp;
	int li,lx;

	li = LI_ACTIVE;
	for( lx = 0; lists[lx]; lx++ ){
		if( strcasecmp(which,lists[lx]) == 0 ){
			li = lx;
			break;
		}
	}
/*
	cache_path("nntp",host,port,"LIST/%s",cachepath,lists[li]);
*/
	{
	CStr(lcpath,1024);
	sprintf(lcpath,"LIST/%s",lists[li]);
	cache_path("nntp",host,port,lcpath,AVStr(cachepath));
	}
	actfp = fopen(cachepath,"r");
	return actfp;
}

void cached_nntpserver(Connection *Conn,FILE *in,FILE *out,PCStr(server))
{	CStr(cachepath,1024);
	CStr(host,128);
	int port;
	FILE *actfp;
	CStr(req,1024);
	const char *dp;
	CStr(com,1024);
	CStr(arg,1024);
	CStr(opening,1024);
	CStr(msg,0x2000);
	int nready;
	int pollstart;

	minit_nntp();
	Xsscanf(server,"%[^:]:%d",AVStr(host),&port);
	sv1log("**** cache-only proxy server for nntp://%s:%d\n",host,port);
	proc_title("DeleGate(cache-only-NNTP-proxy)");

	if( get_cache("NNTP-cache",host,port,"lib/opening",AVStr(msg),sizeof(msg)) )
		strcpy(opening,msg);
	else	sprintf(opening,"200 cache-only proxy NNTP/DeleGate\r\n");

	pollstart = time(0);
	fputs(opening,out);
	for(;;){
		fflush(out);
		nready = fPollIn(in,10*1000);
		if( nready < 0 ){
			sv1log("CS-EOF cached_nntpserver()\n");
			break;
		}
		if( nready == 0 ){
			/* retry connection to the server, and relay
			 * if connected.
			 */
			if( IO_TIMEOUT < time(0) - pollstart ){
				sv1log("TIMEOUT max idle-1 (%d)\n",IO_TIMEOUT);
				fputs("401 connection closed by timeout-1.\r\n",out);
				fflush(out);
				break;
			}
			continue;
		}
		if(fgets(req,sizeof(req),in) == NULL )
			break;
		dp = wordScan(req,com);
		lineScan(dp,arg);

		if( strcasecmp(com,"MODE") == 0 ){
			fputs(opening,out);
			continue;
		}
		if( strcasecmp(com,"QUIT") == 0 ){
			fputs("205 bye.\r\n",out);
			sv1log("QUIT cached_nntpserver()\n");
			break;
		}
		if( strcasecmp(com,"HELP") == 0 )
		if( get_cache("NNTP-cache",host,port,"lib/HELP",AVStr(msg),sizeof(msg)) )
		if( atoi(msg) == 100 ){
			fputs(msg,out);
			if( strtailchr(msg) != '\n' )
				fputs("\r\n",out);
			fputs(".\r\n",out);
			continue;
		}

		if( strcasecmp(com,"LIST") == 0 )
		if( actfp = openLIST(arg,host,port) ){
			fprintf(out,
			"215 Newsgroups in form \"group high low flags\".\r\n");
			copyfile1(actfp,out);
			fputs(".\r\n",out);
			fclose(actfp);
			continue;
		}
		else
		if( NE_dispensable ){
			fprintf(out,"215 no cached newsgroups...\r\n");
			fputs(".\r\n",out);
			continue;
		}

		fprintf(out,"436 [%s] not available temporarily\r\n",com);
	}
	Finish(0);
}

static int connect_to_nntpserver(Connection *Conn,NewsServer *ns,int fromC,int toC)
{	int sock;
	int froms[2];
	FILE *fs,*ts;
	CStr(server,128);
	int pid;

	ns->ns_authERR = 0;
	ns->ns_authOK = 0;
	ns->ns_isdummy = 0;
	ns->ns_isCC = 0;
	ServViaCc = 0;

	if( strcaseeq(ns->ns_proto,"pop") )
		sock = connect_to_popgw(Conn,fromC,toC);
	else	sock = connect_to_serv(Conn,fromC,toC,0);

	if( 0 <= sock ){
		ns->ns_isCC = ServViaCc;
		return sock;
	}
	if( ConnError == CO_REJECTED )
		return sock;

	pid = NoHangWait(); /* previous cached_nntpserver ... */
	if( 0 < pid )
		sv1log("cleaned up zombi: %d (new dummyNNTP)\n",pid);

	/*
	pipe(froms);
	*/
	Socketpair(froms);
	fs = fdopen(froms[1],"w");
	sprintf(server,"%s:%d",DST_HOST,DST_PORT);
	setCloseOnExecSocket(froms[0]);
	ts = openFilter(Conn,"dummyNNTP",(iFUNCP)cached_nntpserver,fs,server);
	clearCloseOnExecSocket(froms[0]);
	fclose(fs);
	ToS = fileno(ts);
	FromS = froms[0];
	ServConnTime = Time();

	ns->ns_isdummy = 1;
	NNTP_CC = 0;
	return ToS;
}

static int reconnect(NewsServer *ns,PVStr(resp),int size)
{	Connection *Conn;

	Conn = ns->ns_Conn;
	set_realsite(Conn,"nntp",ns->ns_host,ns->ns_port);
	if( connect_to_nntpserver(Conn,ns,-1,-1) < 0 )
		return S_TOCLOSE;

	ns->ns_wfp = fdopen(ToS,"w");
	ns->ns_rfp = fdopen(FromS,"r");
	ns->ns_serverFlags = ServerFlags;
	Client_Addr(ns->ns_client_Addr);

	get_resp(ns,AVStr(resp),size);
	if( resp[0] != '2' )
		return S_TOCLOSE;
	else	return S_RESUME;
}
static int getsv(int nsid,FILE **ts,FILE **fs)
{	NewsServer *ns;
	CStr(resp,1024);

	if( nsid <= 0 )
		return 0;

	ns = toNS(nsid);
	if( ns->ns_wfp == NULL ){
		if( reconnect(ns,AVStr(resp),sizeof(resp)) != S_RESUME )
			return 0;
		Verbose("NNTP OpenServer(%d)[%d]\n",nsid,fileno(ns->ns_wfp));
		set_opening(ns,AVStr(resp));
		getCONFIG(ns);
	}
	*ts = ns->ns_wfp;
	*fs = ns->ns_rfp;

	if( ns->ns_serverFlags & PF_RIDENT_SENT ){
		Connection *Conn = ns->ns_Conn;
		CStr(cla,128);
		CStr(sock,128);
		CStr(peer,128);
		if( strcmp(Client_Addr(cla),ns->ns_client_Addr) != 0 )
		if( getClientSockPeer(AVStr(sock),AVStr(peer)) == 0 )
		{
			fprintf(ns->ns_wfp,"RIDENT %s %s\r\n",sock,peer);
			fflush(ns->ns_wfp);
			get_resp(ns,AVStr(resp),sizeof(resp));
			strcpy(ns->ns_client_Addr,cla);
			sv1log("NNTP sent RIDENT [%s][%s] %s",sock,peer,resp);
		}
	}

	return 1;
}
static void closeSVStream(NewsServer *ns)
{
	if( ns->ns_wfp ){
		Connection *Conn = ns->ns_Conn;
		if( fileno(ns->ns_wfp) == ToS ){
		close_FSERVER(ns->ns_Conn,1);
		}else{
		/* don't close filter for another server */
		}
		fclose(ns->ns_wfp); ns->ns_wfp = NULL;
		fclose(ns->ns_rfp); ns->ns_rfp = NULL;
	}
}
static int resume(NewsServer *ns)
{	CStr(resp,1024);
	int rcode;
	int pid;

	server_done = 1;
	closeSVStream(ns);
	if( (rcode = reconnect(ns,AVStr(resp),sizeof(resp))) != S_RESUME )
		return rcode;

	INNsetup(ns,AVStr(resp));
	if( ns->ns_curanum && ns->ns_curgroupR ){
		fprintf(ns->ns_wfp,"GROUP %s\r\n",ns->ns_curgroupR);
		fprintf(ns->ns_wfp,"STAT %d\r\n",ns->ns_curanum);
		fflush(ns->ns_wfp);
		get_resp(ns,AVStr(resp),sizeof(resp));
		get_resp(ns,AVStr(resp),sizeof(resp));
	}
	sv1log("reseumed\n");
	server_done = 0;

	while( 0 < (pid = NoHangWait()) ){
		sv1log("cleaned up zombi: %d (previous NNTPCC ?)\n",pid);
	}
	return S_RESUME;
}
static int waitclient(NewsServer *ns,FILE *fc,int timeout)
{	CStr(req,1024);
	int ch;

	if( fc == NULL ){
		sleep(timeout);
		return S_RESUME;
	}

	if( fPollIn(fc,timeout*1000) <= 0 )
		return S_TOCLOSE;

	if( file_ISSOCK(fileno(fc)) ){ /* no Conn->xf_filters & XF_CLIENTS ... */
		if( Peek1(fileno(fc)) <= 0 )
			return S_TOCLOSE;
		if( !IsConnected(fileno(fc),NULL) )
			return S_CLEOF;
		if( 0 < recvPeekTIMEOUT(fileno(fc),AVStr(req),sizeof(req)) ){
			if( strncasecmp(req,"QUIT",4) == 0 ){
				sv1log("NNTPCC: don't RESUME server to QUIT\n");
				return S_TOQUIT;
			}
		}
	}else{
		ch = fgetc(fc);
		if( ch == EOF ){
			sv1log("NNTPCC: don't RESUME server on EOF from client\n");
			return S_CLEOF;
		}else{
			ungetc(ch,fc);
		}
	}
	return S_RESUME;
}
static int wait_resume(NewsServer *ns,FILE *fc,int timeout)
{	int rcode;

	if( (rcode = waitclient(ns,fc,timeout)) != S_RESUME )
		return rcode;
	else	return resume(ns);
}
static int suspend(Connection *Conn,int timeout,FILE *fc,FILE *tc,int nserv,NewsServer *servers)
{	NewsServer *ns;
	CStr(stat,1024);
	int si,found;

	found = 0;
	for( si = 0; si < NserverN; si++ ){
		ns = &Nservers[si];
		if( found = !ns->ns_isself )
			break;
	}
	if( !found )
		return S_TOCLOSE;

/* if the server in EOF, S_ERROR ... */

	/* If this is a server-side CC, don't suspend. */
	if( ImCC )
		return S_RESUME;
	if( 1 < nservers_active(1) )
		return S_NOSUSP;

	/* If this is NOT a client-side CC, spawn a server-side CC
	 * before suspend where the established connection to the server
	 * will be discarded.
	 * In the situation where NNTPCC is not applicable, suspend may
	 * require high cost, so don't try it.
	 */
	if( !ServViaCc ){
		if( !INHERENT_fork() )
			return S_NOSUSP;
		if( !canbeNNTPCC(Conn) )
			return S_NOSUSP;
	}

	fputs("STAT\r\n",ns->ns_wfp);
	fflush(ns->ns_wfp);
	get_resp(ns,AVStr(stat),sizeof(stat));
	if( !ServViaCc ){
		if( Fork("NNTPCC") == 0 )
			return S_TOBECC;
	}
	server_done = 1;
	closeSVStream(ns);
	freeGROUP(ns);

	if( ns->ns_curgroupR != NULL && atoi(stat) == 223 ){
		sscanf(stat,"%*d %d",&ns->ns_curanum);
		sv1log("NNTPCC: SUSPEND at [%s:%d]\n",
			ns->ns_curgroupR,ns->ns_curanum);
	}else{
		sv1log("NNTPCC: SUSPEND\n");
		if( atoi(stat) == 401 )
			sv1log("NNTPCC: the server also SUSPENDed.\n");
		else	ns->ns_curanum = 0;
	}
	return wait_resume(ns,fc,timeout);
}

int CTX_closedX(FL_PAR,PCStr(wh),Connection *Conn,int fd1,int fd2,int force);
void NNTP_closeServerFds(Connection *Conn,int nsid){
	NewsServer *ns;

	if( ns = toNS(nsid) )
	if( ns->ns_wfp ){
		CTX_closedX(FL_ARG,"closeSvFd",Conn,fileno(ns->ns_wfp),
			fileno(ns->ns_rfp),1);
	}
}
int NNTP_closeServerX(Connection *Conn,int nsid);
void NNTP_closeServer(int nsid)
{
	NNTP_closeServerX(MainConn(),nsid);
}
int NNTP_closeServerX(Connection *Conn,int nsid)
{	NewsServer *ns;

	ns = toNS(nsid);

	if( ns->ns_wfp ){
		CStr(resp,256);
		fputs("QUIT\r\n",ns->ns_wfp);
		fflush(ns->ns_wfp);
		resp[0] = 0;
		fgets(resp,sizeof(resp),ns->ns_rfp);
		sv1log("## NNTP_closeServer: %s",resp[0]?resp:"(EOF)\n");

		Verbose("NNTP CloseServer(%d)[%d]\n",nsid,fileno(ns->ns_wfp));
		CTX_closedX(FL_ARG,"closeSv",Conn,fileno(ns->ns_wfp),
			fileno(ns->ns_rfp),1);
		closeSVStream(ns);
		closeLISTcache(ns);
		freeGROUP(ns);
		ns->ns_Conn = 0;
		{
			int xpid;
			while( 0 < (xpid = NoHangWait()) ){
				sv1log("## NNTP_closeServer: exited pid=%d\n",
					xpid);
			}
		}
		return 1;
	}
	return 0;
}
static int allocServer()
{	int nsx;

	for( nsx = 0; nsx < NserverN; nsx++ )
		if( Nservers[nsx].ns_Conn == 0 )
			return nsx;
	nsx = NserverN++;
	return nsx;
}

static int isServer(PCStr(proto),PCStr(host),int port)
{	int nsx;
	NewsServer *ns;

	for( nsx = 0; nsx < NserverN; nsx++ ){
		ns = &Nservers[nsx];
		if( strcmp(proto,ns->ns_proto) == 0
		 && strcmp(proto,"pop") != 0
		 && strcmp(host,ns->ns_host) == 0
		 && port == ns->ns_port
		){
		sv1log("[%d] (reuse) newServer = %s://%s:%d (LISTwild=%d)\n",
				nsx,proto,host,port, ns->ns_withLISTwildmat);
			return toNSID(nsx);
			/* POP server should be reopened */
		}
	}
	return 0;
}

static void setAuth(NewsServer *ns,PCStr(user),PCStr(pass))
{
	if( user != 0 ){
	CStr(userX,256);
	CStr(userY,256);
	strcpy(userX,user);
	url_unescape(AVStr(userX),AVStr(userX),sizeof(userX),"=.%@*#");
	str_fromqp(userX,strlen(userX),AVStr(userY),sizeof(userY));
	user = userY;
	}

	ns->ns_authOK = 0;
	ns->ns_authERR = 0;
	Strdup((char**)&ns->ns_auser, (char*)(user?user:""));
	Strdup((char**)&ns->ns_apass, (char*)(pass?pass:""));
}

int NNTP_newServer(Connection *Conn,PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port,int fromC,int toC,int fromS,int toS)
{	int nsx,nsid;
	NewsServer *ns;
	CStr(cachepath,1024);
	CStr(hostFQDN,256);

	if( nsid = isServer(proto,host,port) ){
		ns = toNS(nsid);
		setAuth(ns,user,pass);
		ns->ns_Conn = Conn;
		return nsid;
	}

	if( isMYSELF(host) ){
		if( *clientIF_FQDN )
			strcpy(hostFQDN,clientIF_FQDN);
		else	ClientIF_name(Conn,ClientSock,AVStr(hostFQDN));
	}else{
		strcpy(hostFQDN,host);
	}
	getFQDN(hostFQDN,AVStr(hostFQDN));
	sv1log("FQDN: %s\n",hostFQDN);

	nsx = allocServer();
	sv1log("[%d] newServer = %s://%s:%d\n",nsx,proto,host,port);
	ns = &Nservers[nsx];

	if( ns->ns_nsid != 0 ){
		sv1log("#### NNTP ERROR: overwriting server [%d]\n",nsx);
		/*
		 * possiblly another server has been already connected
		 * in MASTER-DeleGate ...
		 *
		 */
		closeLIST1(ns,LI_ACTIVE);
		freeGROUP(ns);
	}

	ns->ns_nsid = toNSID(nsx);
	ns->ns_Conn = Conn;
	ns->ns_myconf = globalNumConf;
	strcpy(ns->ns_proto,proto);
	ns->ns_host = stralloc(host);
	ns->ns_hostFQDN = stralloc(hostFQDN);
	ns->ns_port = port;
	ns->ns_mounts = (NgMount**)calloc(NMOUNT,sizeof(NgMount*));
	ns->ns_mountn = 0;
	ns->ns_curgroup = stralloc("");
	ns->ns_isself = isMYSELF(host) != 0;
	ns->ns_isself |= strcaseeq(proto,"file");

	ns->ns_needAuth = NNTP_needAuth(Conn);
	setAuth(ns,user,pass);

	if( 0 <= fromS ) ns->ns_rfp = fdopen(fromS,"r");
	if( 0 <= toS )   ns->ns_wfp = fdopen(toS,"w");
	ns->ns_islocal = hostismyself(host,ns->ns_wfp) != 0;
	sv1log("islocal = %d\n",ns->ns_islocal);

	if( strcaseeq(proto,"pop") )
		LCpath(ns,LI_ACTIVE) = stralloc("");
	else	setLISTcachepath(ns,LI_ACTIVE,0);
	return toNSID(nsx);
}

static int addServer1(Connection *Conn,PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port,int fromC,int toC,int fromS,int toS)
{	NewsServer *ns;
	int nsid;

	nsid = NNTP_newServer(Conn,proto,user,pass,host,port,fromC,toC,fromS,toS);
	ns = toNS(nsid);
	if( LCfp(ns,LI_ACTIVE) == NULL )
		setLISTcache(ns,LI_ACTIVE);
	ns->ns_isCC = ServViaCc;
	if( ns->ns_auser == 0 || *ns->ns_auser == 0 ){
		IStr(auth,256);
		if( get_MYAUTH(Conn,AVStr(auth),"nntp",host,port) ){
			IStr(user,256);
			IStr(pass,256);
			Xsscanf(auth,"%[^:]:%[^\r\n]",AVStr(user),AVStr(pass));
			setAuth(ns,user,pass);
		}
	}
	return nsid;
}

static scanListFunc hide1(PCStr(hide1),int *hcp,int mac,void *hv[],char ops[])
{	char op;

	if( mac <= *hcp ){
		return -1;
	}
	if( *hide1 == '!' )
		op = *hide1++;
	else	op = ' ';
	ops[*hcp] = op;
	hv[*hcp] = frex_create(hide1);
	(*hcp) += 1;
	return 0;
}

static void make_hidev(NgMount *nm,PCStr(hides))
{	const char *hv[256]; /**/
	const char **nhv;
	CStr(ops,256);
	int hc,hi;

	hc = 0;
	scan_commaListL(hides,0,scanListCall hide1,&hc,256,hv,ops);
	hv[hc] = 0;
	setVStrEnd(ops,hc);
	nhv = (const char**)malloc(sizeof(char*)*(hc+1));
	for( hi = 0; hi <= hc; hi++ )
		nhv[hi] = hv[hi];
	nm->nm_hide = nhv;
	nm->nm_hideop = stralloc(ops);
}
static scanListFunc scanopt(PCStr(opt1),NgMount *nm,NewsServer *ns)
{
	if( strstr(opt1,"ro") == opt1 && (opt1[2]==0 || opt1[2]=='=') ){
		nm->nm_flags |= MF_RO;
	}else
	if( strstr(opt1,"nonlocal") ){
		if( ns->ns_islocal ){
			/* force caching for a local server */
			sv1log("## nonlocal: %s\n",ns->ns_host);
			ns->ns_islocal = 0;
		}
	}else
	if( strstr(opt1,"rewaddr=") ){
		nm->nm_rewaddr = stralloc(opt1+8);
		ns->ns_rewaddr = nm->nm_rewaddr;
	}else
	if( strstr(opt1,"rewposter=") ){
		nm->nm_rewposter = stralloc(opt1+10);
		ns->ns_rewposter = nm->nm_rewposter;
	}else
	if( strstr(opt1,"pathhost=") == opt1 ){
	}else
	if( strstr(opt1,"src=") == opt1 ){
	}else
	if( strstr(opt1,"ftocl=!mime") == opt1 )
		nm->nm_flags |= MF_NOCLMIME;
	else
	if( strstr(opt1,"ftosv=!mime") == opt1 )
		nm->nm_flags |= MF_NOSVMIME;
	else
	if( strstr(opt1,"hide=") == opt1 )
		make_hidev(nm,opt1+5);
	else
	if( strstr(opt1,"cache=no") == opt1 )
		if( opt1[8] == '-' ){
			switch( opt1[9] ){
			case 'a': ns->ns_nocache |= CACHE_ARTICLE; break;
			case 'o': ns->ns_nocache |= CACHE_OVERVIEW; break;
			case 'l': ns->ns_nocache |= CACHE_LIST; break;
			}
		}else{
			ns->ns_nocache = CACHE_ALL;
		}
	else
	if( strstr(opt1,"emulate=") == opt1 ){
		switch( opt1[8] ){
			case 0:
			case '*': ns->ns_emulate = EMULATE_ALL; break;
			case 'x':
			  switch( opt1[9] ){
			    case 'o': ns->ns_emulate |= EMULATE_XOVER; break;
			    case 'h': ns->ns_emulate |= EMULATE_XHDR; break;
			  }
			  break;
		}
	}else
	if( strstr(opt1,"upact:") == opt1 ){
		scan_upacts("MOUNT-OPTION",opt1+6,
			&ns->ns_myconf.sciv[Upacts]);
	}
	else
	if( strcmp(opt1,"dispensable") == 0 ){
		ns->ns_dispensable = 1;
	}
	return 0;
}
static scanListFunc addGroup1(PCStr(group),int nsid,PCStr(abase),PCStr(opts))
{	NewsServer *ns;
	NgMount *nm;
	CStr(base,256);
	int mx;

	if( abase )
		strcpy(base,abase);
	else	base[0] = 0;

	if( streq(base,"=") )
		base[0] = 0;

	if( strtailchr(group) == '*' )
		((char*)group)[strlen(group)-1] = 0; /* not "const" but fixed */

	for( mx = 0; mx < MountN; mx++ ){
		nm = Mount(mx);
		ns = toNS(nm->nm_nsid);
		if( nm->nm_nsid == nsid
		 && streq(group,nm->nm_group) 
		 && streq(base,nm->nm_base)
		){
			Verbose("dup. MOUNT[%d] %s %s\n",mx,ns->ns_host,group);
			return 0;
		}
	}

	ns = toNS(nsid);
	nm = Mount(mx = MountN++);
	ns->ns_mounts[ns->ns_mountn++] = nm;

	if( base[0] ){
		mounted++;
		ns->ns_mounted++;
	}
	if( base[0] == 0 && group[0] != 0 )
		strcpy(base,group);

	sv1log("MOUNT[%d] %s[%d] %s %s\n",mx,ns->ns_host,ns->ns_mountn,base,group);
	nm->nm_base = stralloc(base);
	nm->nm_baselen = strlen(base);
	nm->nm_group = stralloc(group);
	nm->nm_grouplen = strlen(group);
	nm->nm_nsid = nsid;

	if( nm->nm_grouplen ){
		restricted++;
		ns->ns_restricted++;
	}else{
		restricted -= ns->ns_restricted;
		ns->ns_restricted = 0;
	}

	scan_commaListL(opts,0,scanListCall scanopt,nm,ns);
	if( (nm->nm_flags & MF_RO) == 0 ){
		writable++;
		ns->ns_rw++;
	}else	ns->ns_ro++;

	sv1log("MOUNT[%d] %s[%d] %s\n",mx,ns->ns_host,ns->ns_mountn,
		nm->nm_flags & MF_RO ? "ro":"rw");

	if( nm->nm_hide ){
		ns->ns_hidden++;
		hidden++;
	}

	return 0;
}

static int connect_serv(Connection *Conn,NewsServer *ns)
{	CStr(clhost,256);
	CStr(msg,1024);
	int stat;

	stat = connect_to_nntpserver(Conn,ns,FromC,ToC);

	getClientHostPort(Conn,AVStr(clhost));
	sprintf(msg,"NNTP-LOGIN; from=%s; to=%s:%d; %s",
		clhost,DST_HOST,DST_PORT, stat<0?"REJECTED":"ACCEPTED");
	sv1log("%s\n",msg);
	fputLog(Conn,"Login","%s\n",msg);

	return stat;
}

int serverWithEquiv(PCStr(h1),int p1,PCStr(h2),int p2,int *rand);
static scanListFunc addServer(Connection *Conn,PCStr(base),PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port,PCStr(group),PCStr(opts))
{	NewsServer *ns;
	int si,nsid;
	CStr(spoolpath,1024);
	int mounted_file;

	if( host[0] == 0 )
		return 0;

	Conn->no_dstcheck_proto = serviceport(proto);

	if( isMYSELF(host) && strchr(host,'.') == NULL )
		return 0;

	if( isMYSELF(host) && service_permitted(Conn,DST_PROTO) == 0 )
		return 0;

	if( strcaseeq(proto,"http") ){
		/* if not {nntp,pop,file} ... */
		return 0;
	}

	mounted_file = 0;
	if( strcaseeq(proto,"file") ){
		if( !isFullpath(group) ){
			sprintf(spoolpath,"/%s",group);
			group = spoolpath;
			/*
			 * MOUNT="group file:/path" single group
			 * MOUNT="group.* file:/path/*" should be recursive...
			 */
			ENEWS_addspool(group,0);
			mounted_file = 1;
		}
	}

	strcpy(DFLT_HOST,host);
	DFLT_PORT = port;

	for( si = 0; si < NserverN; si++ ){
		ns = &Nservers[si];
		if( strcmp(proto,"pop") != 0 )
		if( strcmp(proto,ns->ns_proto) == 0 )
		if( strcmp(host,ns->ns_host) == 0 )
		if( port == ns->ns_port )
			break;

		if( serverWithEquiv(host,port,ns->ns_host,ns->ns_port,0) ){
			sv1log("EQSV NNTP[%s:%d][%s:%d]\n",host,port,
				ns->ns_host,ns->ns_port);
			break;
		}
	}
	nsid = toNSID(si);
	ns = toNS(nsid);
	if( mounted_file )
		ns->ns_mounted_file++;

	if( si == NserverN ){
		int dmndsv[2] = {-1,-1};

		set_realserver(Conn,"nntp",host,port);
		if( isMYSELF(host) ){
			FromS = ToS = -1;
		}else
		if( strcaseeq(proto,"file") ){
			FromS = ToS = -1;
		}else
		if( strcmp(opts,"delay") == 0 ){
			FromS = ToS = -1;
			opts = "";
		}else
		if( NX.ne_ondemand || isinListX(opts,"ondemand","ch") ){
			/* 9.9.5 init. with a socketpair to a stab server */
			Socketpair(dmndsv);
			FromS = ToS = dmndsv[1];
			strcpy(ns->ns_proto,proto);
			ns->ns_ondemand = 1;
		}else{
			strcpy(ns->ns_proto,proto);
			if( connect_serv(Conn,ns) < 0 )
				return 0;
		}

		nsid = addServer1(Conn,proto,user,pass,host,port,FromC,ToC,FromS,ToS);
		ns = toNS(nsid);
		if( 0 <= dmndsv[0] ){
			/* 9.9.5 insert a stab server as a thread */
			ondemandServ(Conn,ns,dmndsv);
		}
	}
	else{
		/* SERVER=nntp://user:pass@server/ */
		if( ns->ns_auser == NULL || *ns->ns_auser == 0 )
		setAuth(ns,user,pass);
	}

	if( base == NULL )
		base = "";
	if( group == NULL )
		group = "";

	sv1log("[%d][%d] %s <=> %s://%s:%s@%s:%d/%s\n",
		si,ns->ns_mountn,base,proto,
		user?user:"",pass?pass:"",host,port,group?group:"");

	if( group[0] )
		scan_commaList(group,1,scanListCall addGroup1,nsid,base,opts);
	else	addGroup1(group,nsid,base,opts);
	return 0;
}
int NNTP_getServer(Connection *Conn,int fromC,int toC,PCStr(group),const char **host,int *port)
{	int si,nsid;
	NewsServer *ns;

	if( NserverN == 0 )
		CTX_scan_mtab(Conn,(iFUNCP)addServer,Conn);

	for( si = 0; si < NserverN; si++ ){
		ns = &Nservers[si];
		if( ns->ns_host[0] == 0 )
			continue;

		nsid = NNTP_newServer(Conn,"nntp","","",
			ns->ns_host,ns->ns_port,fromC,toC,-1,-1);

		if( 0 < nsid ){
			set_realsite(Conn,"nntp",ns->ns_host,ns->ns_port);
			*host = ns->ns_host;
			*port = ns->ns_port;
			return nsid;
		}
	}
	return 0;
}

int NNTP_holding(){
	if( NNTP_CC && initialized && !withAuth && !server_done && !no_activesv )
		return nservers_active(1);
	else	return 0;
}

static int addCurrent(Connection *Conn)
{	NewsServer nsb;

	if( isMYSELF(DFLT_HOST) )
		return 0;

	if( ToS < 0 || FromS < 0 ){
		strcpy(nsb.ns_proto,DST_PROTO);
		connect_serv(Conn,&nsb);
	}
	if( ToS < 0 || FromS < 0 )
		return -1;

/* DST_USER,DST_PASS sould be supported in delegate.h and service.c */
	addServer1(Conn,DST_PROTO,NULL,NULL,DST_HOST,DST_PORT,
		FromC,ToC,FromS,ToS);
	return 1;
}
static void closeServers(Connection *Conn){
	int si;
	FILE *fp;
	NewsServer*ns;

	for( si = 0; si < NserverN; si++ ){
		ns = &Nservers[si];
		if( ns->ns_Conn ) close_FSERVER(ns->ns_Conn,1);
		if( ConnType == 'y' ){
			if( fp = ns->ns_wfp ){
				/* 9.9.7 to wait YYMUX do SHUT */
				int fd;
				fflush(fp);
				fd = fileno(fp);
				if( fd == ToS ){
					finishServYY(FL_ARG,Conn);
				}else{
					int shutdownWR(int fd);
					int rdy;
					shutdownWR(fd);
					rdy = PollIn(fd,100);
					sv1log("##NNTP closeServer(%d) rdy=%d\n",fd,rdy);
				}
			}
		}
		if( fp = ns->ns_rfp ) fclose(fp);
		if( fp = ns->ns_wfp ) fclose(fp);
	}
	server_done = 1;
}

static int canbeNNTPCC(Connection *Conn)
{
	Verbose("canbeNNTPCC? K%d H%d M%d(%d) N%d(%d) P%d V%d\n",
		!DontKeepAliveServ(Conn,"NNTPCC"),
		NNTP_holding(),
	    	MountedConditional() == 0,MountedConditional(),
		NserverN == 1,NserverN,
		nservers_POP() == 0,
		!ServViaCc
	);

	if( DontKeepAliveServ(Conn,"NNTPCC") )
		return 0;

	return NNTP_holding()
	    && MountedConditional() == 0
	    && NserverN == 1
	    && nservers_POP() == 0
	    && !ServViaCc;
}
int CC_TIMEOUT_NNTP = 300;
static int nntpcc(Connection *Conn,Session *Sp)
{	FILE *fc,*tc;
	NewsServer *ns;
	NewsClient ncb,*nc = &ncb;
	int fd; int s1 = server1();

	ns = &Nservers[s1];
	if( ns->ns_openingmsg == NULL ){
		sv1log("#### nntpcc: no opening msg (shold not be NNTPCC) \n");
		return -1;
	}

	if( ToS != (fd = fileno(ns->ns_wfp)) ){
		sv1log("#### nntpcc: ToS changed %d->%d\n",fd,ToS);
		ns->ns_wfp = fdopen(ToS,"w");
	}
	if( FromS != (fd = fileno(ns->ns_rfp)) ){
		sv1log("#### nntpcc: FromS changed %d->%d\n",fd,ToS);
		ns->ns_rfp = fdopen(FromS,"r");
	}
	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");
	setbuffer(tc,Sp->s_stdobuf,IOBSIZE);
	fputs(ns->ns_openingmsg,tc);

	nc->nc_Conn = Conn;
	nc->nc_rfp = fc;
	nc->nc_wfp = tc;
	DO_afterflush = DO_INIT;

	setLISTprivate(ns);

	hidden = 0;
	ns->ns_hidden = 0;
	mounted = 0;
	ns->ns_mounted = 0;
	restricted = 0;
	ns->ns_restricted = 0;

	imCC = 1;
	NNTPrelay_request(Conn,Sp,nc,NserverN,Nservers);
	imCC = 0;
	fclose(fc);
	fclose(tc);
	if( NNTP_holding() )
		return 0;
	else	return -1;
}

int service_nntp(Connection *Conn)
{	UTag sut;
	Session *sp;

	PageCountUpURL(Conn,CNT_TOTALINC,"#sessions",NULL);
	minit_nntp();
	sut = UTalloc(SB_CONN,sizeof(Session),8);
	service_nntpX(Conn,(Session*)sut.ut_addr);
	UTfree(&sut);
	return 0;
}
void service_nntpX(Connection *Conn,Session *Sp)
{	FILE *tc,*fc;
	NewsClient ncb,*nc = &ncb;

	/* This is necessary for searching available newsgroups for POST.
	 * It will not be a problem at MASTER for multiple NNTP server
	 * because it will become a NNTPCC devoted a single server ...
	 */
	if( ImMaster && Mounted() == 0 ){
		CStr(mount,256);
		sprintf(mount,"%s://%s:%d/*",DST_PROTO,DST_HOST,DST_PORT);
		set_MOUNT(Conn,"=",mount,"");
		init_mtab();
	}

	clientID++;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,"w");
	setsockbuf(ToC,0,IOBSIZE);
	setbuffer(tc,Sp->s_stdobuf,IOBSIZE);

	nc->nc_Conn = Conn;
	nc->nc_rfp = fc;
	nc->nc_wfp = tc;
	DO_afterflush = DO_INIT;

	if( NNTP_holding() )
	if( !isMYSELF(DST_HOST) && !isServer(DST_PROTO,DST_HOST,DST_PORT) )
		closeServers(Conn); /* abandon holding */

	if( NNTP_holding() )
		Verbose("NNTPCC: DONT CLEAR SERVER[%d]\n",NserverN);
	else{
		NserverN = 0;
		withAuth = 0;
		initialized = 0;
		server_done = 0;
		no_activesv = 0;
	}
	compressLIST = 0;

	if( NX.ne_ondemand ){
		/* 9.9.5 let servers connected on demand */
		putIdent(tc,"");
		fflush(tc);
		if( waitRequest(Conn,fc,tc) != 0 ){
			fcloseFILE(tc);
			fclose(fc);
			return;
		}
	}
	if( NserverN == 0 ){
		if( NX.ne_ondemand ){
			/* 9.9.5 no imm. connect_serv() for SERVER=nntp://serv */
		}else
		if( addCurrent(Conn) < 0 )
			goto rejected;

		CTX_scan_mtab(Conn,(iFUNCP)addServer,Conn);
		if( ConnError == CO_REJECTED )
			goto rejected;

		QueueLeng = nservers_remote();
	}else{
		QueueLeng = 0;
		if( nservers_remote() == 1 ){ int s1 = server1();
			if( NX.ne_ondemand == 0 )
			fputs(Nservers[s1].ns_openingmsg,tc);
			fflush(tc);
		}
	}
	if( NX.ne_ondemand ){
	}else
	if( nservers_remote() != 1 )
		putIdent(tc,"");

	needProxyAuth = proxyAuth(Conn,CVStr("proxy-user:pass"),CVStr("host-xxxx")) == EOF;

	ClientIF_name(Conn,ClientSock,AVStr(clientIF_FQDN));
	getFQDN(clientIF_FQDN,AVStr(clientIF_FQDN));
	NNTPrelay_request(Conn,Sp,nc,NserverN,Nservers);
	strcpy(clientIF_FQDN,"(client)");

	fclose(tc);
	fclose(fc);

	if( canbeNNTPCC(Conn) ){
		sv1log("NNTP: DONE (become a NNTPCC)\n");
/*
		flushResponses();
*/
		beBoundProxy(Conn,"",CC_TIMEOUT_NNTP,(iFUNCP)nntpcc,Sp);
	}
	closeServers(Conn);
	sv1log("NNTP: DONE %s\n",ImCC?"(exit NNTPCC)":"");

	/* should wait() children which may be Forked as NNTPCC ... */
	return;

rejected:
	fprintf(tc,"502 access denied.\r\n");
	fclose(tc);
	fclose(fc);
}

static void toQP(PCStr(src),PVStr(dst))
{	refQStr(xp,dst); /**/
	const char *lp;
	char ch;

	cpyQStr(xp,dst);
	for( lp = src; ch = *lp; lp++ ){
		assertVStr(dst,xp+3);
		if( ch <= 0x20 || 0x7F <= ch || strchr("=./'\"",ch) ){
			sprintf(xp,"=%02x",ch & 0xFF);
			xp += 3;
		}else	setVStrPtrInc(xp,ch);
	}
	setVStrEnd(xp,0);
}

static void midPath(PVStr(ngarpath),PCStr(msgid))
{	const char *domain;
	CStr(rdomain,1024);
	CStr(localpart,1024);
	CStr(xlocalpart,1024);

	if( 0 ){
		IStr(md5,128);
		toMD5(msgid,md5);
		sprintf(ngarpath,"%s/%s/%s",md5,md5,md5);
		return;
	}
	domain = strchr(msgid,'@');
	if( domain == msgid || domain == 0 || domain[1] == 0 ){
		sprintf(ngarpath,"msgid-without-atmark.%s",msgid);
		return;
	}
	reverseDomain(domain+1,AVStr(rdomain));
	Xsscanf(msgid,"%[^@]",AVStr(localpart));
	toQP(localpart,AVStr(xlocalpart));
	sprintf(ngarpath,"%s.%s",rdomain,xlocalpart);
}
void NNTP_midpath(PVStr(path),PCStr(msgid))
{	const char *pp; /* not "const" but fixed */

	midPath(AVStr(path),msgid);
	for( pp = path; *pp; pp++ )
		if( *pp == '.' )
			*(char*)pp = '/';
}
static void art_cache_path(int nsid,PCStr(vol),PCStr(group),int anum,PVStr(cachepath))
{	CStr(ngarpath,1024);
	const char *pp; /* not "const" but fixed */
	NewsServer *ns;
	int ismsgid;

	ismsgid = strchr(group,'@') != NULL;

	if( ismsgid )
		midPath(AVStr(ngarpath),group);
	else	sprintf(ngarpath,"%s/%s/%d",vol,group,anum);

	for( pp = ngarpath; *pp; pp++ )
		if( *pp == '.' )
			*(char*)pp = '/';

	if( nsid && !ismsgid ){
		ns = toNS(nsid);
		cache_path("nntp",ns->ns_host,ns->ns_port,ngarpath,AVStr(cachepath));
	}else	cache_path("nntp","all",119,ngarpath,AVStr(cachepath));
}
static FILE *openCACHE(int nsid,int create,int expire,PCStr(vol),PCStr(group),int anum,PVStr(cachepath))
{	FILE *cfp;
	int age,size;

	art_cache_path(nsid,vol,group,anum,AVStr(cachepath));
	if( cachepath[0] == 0 ){
		if( create )
			return TMPFILE("openCACHE-1");
		else	return NULL;
	}

	if( cfp = fopen(cachepath,"r+") ){
		age = file_age(cachepath,cfp);
		if( CACHE_ANY(expire) || age < expire ){
			size = file_size(fileno(cfp));
			Verbose("reuse [%d bytes][age=%d] %s\n",size,age,cachepath);
			return cfp;
		}
	}
	if( !create ){
		if( cfp != NULL )
			fclose(cfp);
		return NULL;
	}

	if( cfp == NULL )
		cfp = dirfopen("NNTP",AVStr(cachepath),"w+");
	if( cfp != NULL )
		sv1log("openCACHE: create %s\n",cachepath);
	else{
		setVStrEnd(cachepath,0);
		cfp = TMPFILE("openCACHE-2");
	}
	return cfp;
}
int NNTP_withCACHE(int nsid,PCStr(vol))
{	FILE *afp;
	NewsServer *ns;
	int artcache;
	CStr(cachepath,1024);

	ns = toNS(nsid);
	if( ns->ns_artcache == WITH_CACHE )
		return 1;
	if( ns->ns_artcache == NO_CACHE )
		return 0;

	afp = openCACHE(nsid,1,NO_EXPIRE,vol,ns->ns_curgroup,0,AVStr(cachepath));
	fclose(afp);
	if( cachepath[0] ){
		unlink(cachepath);
		ns->ns_artcache = WITH_CACHE;
		return 1;
	}else{
		ns->ns_artcache = NO_CACHE;
		return 0;
	}
}

int NNTP_getMessageID(int nsid,PCStr(group),int anum,PVStr(msgid))
{	FILE *afp;
	FILE *ts,*fs;
	CStr(cachepath,1024);
	CStr(resp,1024);
	const char *dp;

	setVStrEnd(msgid,0);
	if( afp = openCACHE(nsid,0,NO_EXPIRE,DIR_SPOOL,group,anum,AVStr(cachepath)) ){
		if( fgetsHeaderField(afp,"Message-ID",AVStr(resp),sizeof(resp)) != NULL )
			Xsscanf(resp,"%[^ \t\r\n]",AVStr(msgid));
		fclose(afp);
		return 0;
	}
	if( getsv(nsid,&ts,&fs) == 0 )
		return -1;

	getGROUP(nsid,ts,fs,group,AVStr(resp),sizeof(resp));
	fprintf(ts,"STAT %d\r\n",anum);
	fflush(ts);
	fgetsFS(AVStr(resp),sizeof(resp),fs);

	if( atoi(resp) == 223 ){
		Xsscanf(resp,"%*d %*d %[^ \t\r\n]",AVStr(msgid));
		return 0;
	}else	return -1;
}
static int search1(int nsid,PCStr(msgid),PCStr(group),int anum1,int anum2,PVStr(rgroup))
{	int anum,inc;
	CStr(stat,1024);

	if( anum1 < anum2 )
		inc = 1;
	else	inc = -1;
	for( anum = anum1; ;anum += inc ){
		NNTP_getMessageID(nsid,group,anum,AVStr(stat));
		if( strstr(stat,msgid) ){
			strcpy(rgroup,group);
			return anum;
		}
		if( anum == anum2 )
			break;
	}
	return 0;
}


static char *put1(xPVStr(lp),PCStr(head),PCStr(field))
{	CStr(value,0x4000);
	char ch;
	const char *vp;
	const char *dp;

	setVStrPtrInc(lp,'\t');
	if( getFV(head,field,value) ){
		if( strcmp(field,"References") == 0 ){
			if( dp = strrchr(value,' ') )
				ovstrcpy(value,dp);
		}
		for( vp = value; ch = *vp; vp++ ){
			assertVStr(lp,lp+1);
			if( ch == '\t' )
				ch = ' ';
			setVStrPtrInc(lp,ch);
		}
	}
	setVStrEnd(lp,0);
	return (char*)lp;
}
static scanListFunc putxover1(PCStr(fname),PVStr(line),char **lpp,PCStr(head),int bytes)
{	refQStr(lp,line); /**/

	lp = *lpp;
	if( strcaseeq(fname,"Bytes") )
		lp = Sprintf(AVStr(lp),"\t%d",bytes);
	else	lp = put1(AVStr(lp),head,fname);
	*lpp = (char*)lp;
	return 0;
}

static int getXOVER(int nsid,PCStr(group),int anum,PVStr(line),int size)
{	FILE *xfp;
	CStr(cachepath,1024);

	if( toNS(nsid)->ns_nocache & CACHE_OVERVIEW ){
		setVStrEnd(line,0);
		return 0;
	}
	if( xfp = openCACHE(nsid,0,NO_EXPIRE,DIR_XOVER,group,anum,AVStr(cachepath)) ){
		fgets(line,size,xfp);
		fclose(xfp);
		return 1;
	}else{
		setVStrEnd(line,0);
		return 0;
	}
}
static void putXOVER(int nsid,PCStr(group),int anum,PCStr(line),int size)
{	FILE *xfp;
	CStr(cachepath,1024);

	if( toNS(nsid)->ns_nocache & CACHE_OVERVIEW )
		return;

	/* if( tobecached(nsid,group,anum) ) */
	if( !streq(toNS(nsid)->ns_proto,"pop") )
	if( xfp = openCACHE(nsid,1,NO_EXPIRE,DIR_XOVER,group,anum,AVStr(cachepath)) ){
		fputs(line,xfp);
		fclose(xfp);
	}
}
static int makeXOVER(int nsid,PCStr(group),int anum,PVStr(line),int size)
{	CStr(cpath,1024);
	CStr(xhead,0x8000);
	CStr(head,0x8000);
	refQStr(hp,xhead); /**/
	CStr(value,0x8000);
	refQStr(lp,line); /**/
	FILE *afp;
	int bytes;
	NewsServer *ns;

	if( toNS(nsid)->ns_isself ){
		if( afp = ENEWS_article(NULL,group,anum) )
			bytes = file_size(fileno(afp));
		else	bytes = -1;
	}else
	if( afp = NNTP_openARTICLE(nsid,NO_EXPIRE,group,anum,AVStr(cpath)) )
		bytes = file_size(fileno(afp));
	else	bytes = -1;

	if( bytes <= 0 ){
		if( afp ) fclose(afp);
		return 0;
	}

	hp = xhead;
	xhead[0] = 0;
	while( fgets(hp,&xhead[sizeof(xhead)]-hp,afp) != NULL ){
		if( *hp == '\r' || *hp == '\n' || *hp == 0 )
			break;
		hp += strlen(hp);
	}
	fclose(afp);

	MIME_strHeaderDecode(xhead,AVStr(head),sizeof(head));
	ns = toNS(nsid);
	if( ns->ns_rewaddr ){
		rewriteHeader(ns,AVStr(head),NULL);
	}
	cpyQStr(lp,line);
	lp = Sprintf(AVStr(lp),"%d",anum);
	scan_commaListL(overview_fmt,0,scanListCall putxover1,AVStr(line),&lp,head,bytes);
	lp = Sprintf(AVStr(lp),"\r\n");

	putXOVER(nsid,group,anum,line,size);
	return 1;
}

void NNTP_XOVER(FILE *fc,FILE *tc,int nsid,PCStr(group),PCStr(arg))
{	int anum1,anum2,anum;
	int now,lastflush;
	NewsServer *ns;
	CStr(xover,0x4000);
	CStr(xxover,0x4000);
	int ok,err;

	Verbose("XOVER %s\n",arg);
	ns = toNS(nsid);

	if( ns->ns_curgroup == NULL ){
		fprintf(tc,"412 Not in a newsgroup\r\n");
		fflush(tc);
		return;
	}

	anum1 = anum2 = 0;
	sscanf(arg,"%d-%d",&anum1,&anum2);

	if( anum1 == 0 && anum2 == 0 )
		anum1 = ns->ns_curanum;
	if( anum1 == 0 )
		anum1 = 1;
	if( anum2 == 0 )
		anum2 = anum1;

	if( XOVER_MAX < anum2 - anum1 ){
		sv1log("REJECT XOVER [%d-%d] -- too wide range\n",anum1,anum2);
		fprintf(tc,"502 no permission (too wide range)\r\n");
		fflush(tc);
		return;
	}

	ok = err = 0;
	lastflush = time(0);
	fprintf(tc,"224 data follows\r\n");
	for( anum = anum1; anum <= anum2; anum++ ){
		if( getXOVER(nsid,group,anum,AVStr(xover),sizeof(xover))
		|| makeXOVER(nsid,group,anum,AVStr(xover),sizeof(xover)) ){
			decodeTERM1(xover,AVStr(xxover));
			if( fputs(xxover,tc) == EOF )
				break;

			now = time(0);
			if( 8 < now - lastflush ){
				if( fflush(tc) == EOF )
					break;
				lastflush = now;
			}
			ok++;
		}else{
			err++;
			if( err % 10 == 0 ){
				if( !IsConnected(fileno(tc),NULL) ){
					sv1log("client closed during XOVER\n");
					break;
				}
				if( PENALTY_SLEEP ){
					sv1log("penalty sleep: XOVER %d:%d\n",
						ok,err);
					sleep(PENALTY_SLEEP);
				}
			}
		}
	}
	fprintf(tc,".\r\n");
	fflush(tc);
}

static int matchMsgid(PCStr(msgid),PCStr(group),PVStr(rgroup),PCStr(xover))
{	int anum,fanum = 0;
	CStr(msgid1,1024);

	msgid1[0] = 0;
	Xsscanf(xover,"%d\t%*[^\t]\t%*[^\t]\t%*[^\t]\t%s",&anum,AVStr(msgid1));
	if( strstr(msgid1,msgid) ){
		strcpy(rgroup,group);
		fanum = anum;
	}
	return fanum;
}
static int scanXOVER(FILE *ts,FILE *fs,int nsid,PCStr(msgid),PCStr(group),int anum0,PVStr(rgroup))
{	CStr(resp,1024);
	int nart,min,max;
	int anum1,anum2,fanum,ranum,anum;
	CStr(xover,0x4000);

	NNTP_getGROUP(nsid,NO_EXPIRE,group,&nart,&min,&max);

	anum1 = anum0 - 100;
	if( anum1 < min ) anum1 = min;
	anum2 = anum0 + 20;
	if( max < anum2 ) anum2 = max;

	fanum = 0;
	for( anum = anum1; anum <= anum2; anum++ ){
		if( getXOVER(nsid,group,anum,AVStr(xover),sizeof(xover)) ){
			if( fanum = matchMsgid(msgid,group,AVStr(rgroup),xover) )
				return fanum;
			anum1 = anum;
		}else	break;
	}
		
	fprintf(ts,"XOVER %d-%d\r\n",anum1,anum2);
	fflush(ts);
	fgetsFS(AVStr(resp),sizeof(resp),fs);
	if( atoi(resp) != 224 )
		return 0;

	sv1log("search XOVER %d-%d [%d-%d]\n",anum1,anum2,min,max);

	while( fgetsFSline(AVStr(xover),sizeof(xover),fs) != NULL ){
		if( isEOR(xover) )
			break;

		anum = atoi(xover);
		putXOVER(nsid,group,anum,xover,sizeof(xover));

		if( fanum != 0 )
			continue;
		fanum = matchMsgid(msgid,group,AVStr(rgroup),xover);
	}
	return fanum;
}

const char *someGroup(){ return "*"; }

/*
 * When the cache is shared among more than two DeleGates,
 * where the MASTER NNTP DeleGate rewrite the name of newsgroups,
 * and the client DeleGate get the article file directly from the cache
 * retrieved by Message-ID,
 * the names in Newsgroups in the article file will not much with
 * the one which this DeleGate should receive from the MASTER.
 */
FILE *NNTP_openARTICLEC(int nsid,int expire,PCStr(group),int anum,PVStr(cpath))
{	FILE *afp;

	if( toNS(nsid)->ns_islocal )
	if( strchr(group,'@') && anum == 0 ){
		/* DON'T USE CACHE FOR LOCAL SERVER */
		return NULL;
	}

	if( afp = openCACHE(nsid,0,expire,DIR_SPOOL,group,anum,AVStr(cpath)) )
		return afp;
	if( expire == CACHE_ONLY )
		return NULL;
	if( expire == CACHE_MAKE ){
		unlink(cpath);
		return openCACHE(nsid,1,expire,DIR_SPOOL,group,anum,AVStr(cpath));
	}
	return NULL;
}

static int activeArticle(PVStr(statresp),int anum)
{	int stat,nart,min,max;

	if( sscanf(statresp,"%d %d %d %d",&stat,&nart,&min,&max) == 4 )
		if( min <= anum && anum <= max )
			return 1;
	return 0;
}

FILE *NNTP_openArticle(int nsid,int expire,PCStr(msgid),PCStr(group),int anum,PVStr(cpath))
{	FILE *afp,*tmp;
	FILE *ts,*fs;
	FILE *artTmp;
	CStr(resp,1024);

	if( afp = NNTP_openARTICLEC(nsid,expire,group,anum,AVStr(cpath)) )
		return afp;

	if( getsv(nsid,&ts,&fs) == 0 ){
		if( NNTP_authERROR(nsid) )
			return NULL;
		return openCACHE(nsid,0,NO_EXPIRE,DIR_SPOOL,group,anum,AVStr(cpath));
	}

	if( msgid != NULL && msgid[0] && anum == 0 ){
		if( group && group[0] && strcmp(group,"*") != 0 )
			getGROUP(nsid,ts,fs,group,AVStr(resp),sizeof(resp));
		fprintf(ts,"ARTICLE <%s>\r\n",msgid);
		fflush(ts);
	}else{
		if( getGROUP(nsid,ts,fs,group,AVStr(resp),sizeof(resp)) == NULL
		 || atoi(resp) == 411 || !activeArticle(AVStr(resp),anum) )
		if( expire == DO_RELOAD )
			return NULL;
		else	return openCACHE(nsid,0,NO_EXPIRE,DIR_SPOOL,group,anum,AVStr(cpath));

		fprintf(ts,"ARTICLE %d\r\n",anum);
		fflush(ts);
	}

	if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
		return openCACHE(nsid,0,NO_EXPIRE,DIR_SPOOL,group,anum,AVStr(cpath));

	if( atoi(resp) == 430 ){
		sv1log("<%s> No such article: don't create cache.\n",group);
		return NULL;
	}

	if( atoi(resp) == 423 ){
		expireArticle(cpath);
		return NULL;
	}

	if( resp[0] != '2' )
		return NULL;

	artTmp = getTmpfile("openARTICLE",TF_ARTICLE,0,0);
	if( artTmp == NULL )
		return NULL;
	afp = fdopen(dup(fileno(artTmp)),"r+");

	if( afp == NULL ){
		sv1log("cannot open ARTICLE tmp.\n");
		afp = NULLFP();
	}

	fseek(afp,0,0);

	RecvMssg(fs,afp,0);
	/*
	RFC821_skipbody(fs,afp,VStrNULL,0);
	*/

	fflush(afp);
	Ftruncate(afp,0,1);
	fseek(afp,0,0);

	if( tobecached(nsid,group,anum) )
		afp = spoolArticle(nsid,afp,group,anum);

	return afp;
}
FILE *NNTP_openARTICLE(int nsid,int expire,PCStr(group),int anum,PVStr(cpath))
{
	if( strchr(group,'@') )
		return NNTP_openArticle(nsid,expire,group,"",0,AVStr(cpath));
	else	return NNTP_openArticle(nsid,expire,"",group,anum,AVStr(cpath));
}

FILE *linkArticle(FILE *afp,PCStr(group),int anum,PCStr(apath),PCStr(msgid),PCStr(nodename))
{	CStr(xapath,1024);
	CStr(apath1,1024);
	CStr(oxref,LINESIZE);
	CStr(nxref,LINESIZE);
	int xsize;
	FILE *xafp,*nafp;

	if( anum == 0 )
		return afp;

	findXref(afp,nmatch,nodename,AVStr(oxref),sizeof(oxref));

	art_cache_path(0,"",msgid,0,AVStr(xapath));
	if( File_cmp(xapath,apath) == 0 )
		return afp;
	xsize = File_size(xapath);
	if( xafp = fopen(xapath,"r") ){
		if( bad_article(xafp,xapath,"link",msgid) )
			xsize = 0;
		fclose(xafp);
	}

	if( 0 < xsize ){
		/* article named with Message-ID exists, so linking to it
		 * from spool/group/anum ...
		 * but the one in Message-ID might be older than the one
		 * in spool/group/anum ...
		 */
		sprintf(apath1,"%s#",apath);
		if( linkRX(xapath,apath1) != 0 ){
			sv1log("#### linkR(%s,%s) failed(%d).\n",
				xapath,apath1,errno);
			return afp;
		}
		if( unlink(apath) != 0 ){
			sv1log("#### simultaneous linkArticle? %s\n",apath);
			unlink(apath1);
			return afp;
		}
		if( rename(apath1,apath) != 0 ){ 
			sv1log("#### cannot link (%d) %s\n",errno,apath);
			unlink(apath1);
			return afp;
		}
		nafp = fopen(apath,"r+");
		sv1log("LINKED-1 %x [%s] from [%s]\n",p2i(nafp),xapath,apath);

		if( nafp != NULL ){
			fclose(afp);
			afp = nafp;
			ftouch(afp,time(0));
		}else{
			sv1log("#### CANT OPEN (%d) %s\n",errno,apath);
			AbortLog();
		}
	}else{
		if( xsize == 0 )
			unlink(xapath);
		linkRX(apath,xapath);
		sv1log("LINKED-2 [%s] from [%s]\n",apath,xapath);
	}

	fseek(afp,0,0);
	findXref(afp,nmatch,nodename,AVStr(nxref),sizeof(nxref));
	fseek(afp,0,0);

	if( nxref[0] == 0 ){
		if( oxref[0] == 0 )
			sprintf(oxref,"%s %s:%d",nodename,group,anum);
		insertField(afp,"Xref",oxref);
		fseek(afp,0,0);
	}
	return afp;
}

static FILE *spoolArticle(int nsid,FILE *afp,PCStr(group),int anum)
{	CStr(cpath,1024);
	CStr(Path,LINESIZE);
	CStr(nodename,256);
	FILE *safp;
	CStr(msgid,1024);
	const char *mp;
	int wcc;

	msgid[0] = 0;
	fgetsHeaderField(afp,"Message-ID",AVStr(msgid),sizeof(msgid));
	if( mp = strchr(msgid,'<') ){
		ovstrcpy(msgid,mp+1);
		if( mp = strchr(msgid,'>') )
			truncVStr(mp);
	}

	if( anum == 0 )
		group = msgid;

	safp = NNTP_openARTICLEC(nsid,CACHE_MAKE,group,anum,AVStr(cpath));
	if( safp == NULL ){
		sv1log("cannot open file [%s]\n",cpath);
		return afp;
	}
	if( cpath[0] == 0 ){
		sv1log("cannot get artcile spool %s:%d [%s]\n",
			group,anum,cpath);
		fclose(safp);
		return afp;
	}
	if( file_nlink(fileno(safp)) != 1 ){
		fclose(safp);
		if( unlink(cpath) != 0 ){
			sv1log("cannot unlink %s\n",cpath);
			return afp;
		}
		sv1log("#### unlinked: %s\n",cpath);
		safp = fopen(cpath,"w+");
		if( safp == NULL ){
			sv1log("cannot open w+ [%s]\n",cpath);
			return afp;
		}
	}

	lock_exclusiveTO(fileno(safp),2000,NULL);
	wcc = RFC821_skipbody(afp,safp,VStrNULL,0);
	fflush(safp);
	Ftruncate(safp,0,1);
	lock_unlock(fileno(safp));
	fclose(afp);
	sv1log("#### article spool wrote [%d bytes] %s\n",wcc,cpath);

	fseek(safp,0,0);
	strcpy(nodename,toNS(nsid)->ns_host);
	if( fgetsHeaderField(safp,"Path",AVStr(Path),sizeof(Path)) )
		Xsscanf(Path,"%[^!]",AVStr(nodename));

	safp = linkArticle(safp,group,anum,cpath,msgid,nodename);
	fseek(safp,0,0);
	return safp;
}

void expireArticle(PCStr(cpath))
{	CStr(xrefs,0x10000);
	refQStr(xp,xrefs); /**/
	FILE *cfp;

	cfp = fopen(cpath,"r+");
	if( cfp == NULL )
		return;

	/*
	 *	should leave Xref field(s) undeleted
	 */
	xrefs[0] = 0;
	xp = xrefs;
	while( fgets(xp,sizeof(xrefs),cfp) != NULL ){
		if( strncasecmp(xp,"Xref:",5) == 0 )
			xp += strlen(xp);
	}
	fseek(cfp,0,0);
	fputs(xrefs,cfp);
	Ftruncate(cfp,0,1);
	fclose(cfp);
}

void insertField(FILE *afp,PCStr(fname),PCStr(fvalue))
{	int size,rcc;
	const char *tmpbuf;
	FILE *tmpfp;

	fflush(afp);
	fseek(afp,0,2);
	size = ftell(afp);

	fseek(afp,0,0);
	if( size < 0x20000){
		tmpbuf = (char*)malloc(size);
		rcc = fread((char*)tmpbuf,1,size,afp); /**/
	}else{
		tmpbuf = NULL;
		tmpfp = TMPFILE("insertField");
		copyfile1(afp,tmpfp);
		fflush(tmpfp);
		fseek(tmpfp,0,0);
	}

	fseek(afp,0,0);
	lock_shared(fileno(afp));
	fprintf(afp,"%s: %s\r\n",fname,fvalue);
	if( tmpbuf != NULL ){
		fwrite(tmpbuf,1,rcc,afp);
		free((char*)tmpbuf);
	}else{
		copyfile1(tmpfp,afp);
		fclose(tmpfp);
	}
	fflush(afp);
	Ftruncate(afp,0,1);
	lock_unlock(fileno(afp));

	fseek(afp,0,0);
	Verbose(">>>> INSERTED-2 %s: %s\n",fname,fvalue);
}

void NNTP_selectXref(int nsid,PCStr(xref1),PVStr(xref2))
{	NewsServer *ns;

	ns = toNS(nsid);
	selectXref(ns->ns_host,xref1,AVStr(xref2));
}

static int GroupanumbyXPATH(int nsid,PCStr(msgid),PCStr(group),PVStr(rgroup))
{	FILE *ts,*fs;
	CStr(resp,2048);
	CStr(path1,1024);
	const char *dp;
	const char *lastdp;
	const char *xp;
	CStr(xpath1,1024);
	int ranum,plen;

	if( getsv(nsid,&ts,&fs) == 0 )
		return 0;

	if( with_XPATH(nsid) == 0 )
		return 0;

	fprintf(ts,"XPATH <%s>\r\n",msgid);
	fflush(ts);
	fgetsFS(AVStr(resp),sizeof(resp),fs);
	if( atoi(resp) != 223 )
		return 0;

	strcpy(path1,group);
	for( dp = path1; *dp; dp++ ){
		if( *dp == '.' )
			*(char*)dp = '/';
	}
	strcat(path1,"/");
	plen = strlen(path1);

	xp = wordScan(resp,xpath1);
	wordscanX(xp,AVStr(rgroup),256);
	while( xp = wordScan(xp,xpath1) ){
		if( xpath1[0] == 0 )
			break;
		if( strncmp(path1,xpath1,plen) == 0 )
		if( isdigits(xpath1+plen) ){
			strcpy(rgroup,xpath1);
			break;
		}
	}
	lastdp = 0;
	for( dp = rgroup; *dp; dp++ ){
		if( *dp == '/' ){
			*(char*)dp = '.';
			lastdp = dp;
		}
	}
	if( lastdp ){
		truncVStr(lastdp); lastdp++;
		ranum = atoi(lastdp);
		return ranum;
	}
	return 0;
}
			
int anomidToGroup(PCStr(msgid),PVStr(rgroup));
int NNTP_getGroupAnum(int nsid,PCStr(msgid),PCStr(group),int anum1,PVStr(rgroup))
{	FILE *afp,*ts,*fs;
	int anum,notinNG;
	CStr(cpath,1024);
	CStr(line,1024);

	setVStrEnd(rgroup,0);
	anum = 0;
	notinNG = 0;

	if( anum = anomidToGroup(msgid,BVStr(rgroup)) ){
		return anum;
	}

	if( afp = NNTP_openArticle(nsid,NO_EXPIRE,msgid,group,0,AVStr(cpath)) ){
		CStr(xref,LINESIZE);
		const char *dp;
		NewsServer *ns;

		ns = toNS(nsid);
		if( findXref(afp,nmatch,ns->ns_host,AVStr(xref),sizeof(xref)) ){
			if( dp = strstr(xref,group) )
			if( dp[strlen(group)] == ':' ){
				anum = atoi(&dp[strlen(group)+1]);
				strcpy(rgroup,group);
			}
			if( anum == 0 ){
				if( dp = strchr(xref,' ') )
					Xsscanf(dp+1,"%[^:]:%d",AVStr(rgroup),&anum);
			}

		}else{
			CStr(ngs,LINESIZE);
			fseek(afp,0,0);
			fgetsHeaderField(afp,"Newsgroups",AVStr(ngs),sizeof(ngs));
			if( strstr(ngs,group) == 0 )
				notinNG = 1;
		}
		fclose(afp);
	}

	if( anum ){
		sv1log("search hit by Xref: %s:%d\n",rgroup,anum);
		return anum;
	}
	if( anum = GroupanumbyXPATH(nsid,msgid,group,AVStr(rgroup)) ){
		sv1log("serach hit by XPATH: <%s> = %s:%d\n",msgid,rgroup,anum);
		return anum;
	}
	if( notinNG ){
		sv1log("Not in the newsgroup: %s\n",group);
		return 0;
	}
	if( strcmp(group,someGroup()) == 0 )
		return 0;

	if( getsv(nsid,&ts,&fs) ){
		CStr(xmsgid,1024);
		sprintf(xmsgid,"<%s>",msgid);

		anum = scanXOVER(ts,fs,nsid,xmsgid,group,anum1,AVStr(rgroup));
		if( 0 < anum ){
			sv1log("search hit by XOVER: %s/%d\n",rgroup,anum);
			return anum;
		}
		return 0;
	}

	if( anum = search1(nsid,msgid,group,anum1,anum1-40,AVStr(rgroup)) )
		return anum;
	if( anum = search1(nsid,msgid,group,anum1,anum1+10,AVStr(rgroup)) )
		return anum;
	return 0;
}

static int cmpstr(char **s1p,char **s2p)
{
	return strcmp(*s1p,*s2p);
}

#define LIST_GROUP	"active.sorted"
FILE *NNTP_openLIST(int nsid,int expire,PCStr(what))
{	CStr(resp,1024);
	FILE *lfp;
	FILE *ts,*fs,*tmp;
	const char *lines[MAXGROUPS]; /**/
	int nlines,li;
	CStr(cache,1024);
	int ganum;

	ganum = 1;
	if( lfp = openCACHE(nsid,0,expire,DIR_LIB,LIST_GROUP,ganum,AVStr(cache)) )
		return lfp;
	if( expire == CACHE_ONLY )
		return NULL;

	if( getsv(nsid,&ts,&fs) == 0 ){
		if( NNTP_authERROR(nsid) )
			return NULL;
		return openCACHE(nsid,0,NO_EXPIRE,DIR_LIB,LIST_GROUP,ganum,AVStr(cache));
	}

/*
	with_compressLIST(toNS(nsid));
*/

	fprintf(ts,"LIST\r\n");
	fflush(ts);
	resp[0] = 0;
	if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL || resp[0] != '2' ){
		if( checkAuthResp(nsid,"LIST","",resp) != 0 )
			return NULL;
		return openCACHE(nsid,0,NO_EXPIRE,DIR_LIB,LIST_GROUP,ganum,AVStr(cache));
	}

	tmp = TMPFILE("openLIST");
	LIST_uncompress(fs,tmp,1);
	fflush(tmp);
	fseek(tmp,0,0);
	for( nlines = 0; ; nlines++ ){
		if( fgets(resp,sizeof(resp),tmp) == NULL )
			break;
		if( isEOR(resp) )
			break;
		if( elnumof(lines) <= nlines )
			continue;
		lines[nlines] = stralloc(resp);
	}
	fclose(tmp);
	if( MAXGROUPS < nlines ){
		daemonlog("F","#### FATAL: LIST larger than MAXGROUPS: %d > %d\n",
			nlines,MAXGROUPS);
		nlines = MAXGROUPS;
	}

	qsort(lines,nlines,sizeof(char*),(sortFunc)cmpstr);
	lfp = openCACHE(nsid,1,NO_EXPIRE,DIR_LIB,LIST_GROUP,ganum,AVStr(cache));
	for( li = 0; li < nlines; li++ ){
		fputs(lines[li],lfp);
		free((char*)lines[li]);
	}
	sv1log("sorted LIST wrote [%d lines][%d bytes] %s\n",
		nlines,iftell(lfp),cache);
	Ftruncate(lfp,0,1);
	fseek(lfp,0,0);
	return lfp;
}

void NNTP_getGROUP(int nsid,int expire,PCStr(group),int *nart,int *min,int *max)
{	FILE *ts,*fs;
	int stat;
	CStr(resp,1024);
	FILE *lfp;
	int len;
	CStr(cachepath,1024);
	NewsServer *ns;

	*nart = *min = *max = 0;
	*nart = -1; /* 8.10.4 return "nart = -1" for inaccessible group */

	ns = toNS(nsid);
	if( ns->ns_wfp != NULL ){
		getGROUP(nsid,ns->ns_wfp,ns->ns_rfp,group,AVStr(resp),sizeof(resp));
		sscanf(resp,"%d %d %d %d",&stat,nart,min,max);
		return;
	}

	/* causing LIST reloading with establishing connection to the server
	 * is not desirable. */
	if( expire != 0 ) /* not in reloading. */
	if( lfp = NNTP_openLIST(nsid,expire,"NNTP_getGROUP") ){
		len = strlen(group);
		while( fgets(resp,sizeof(resp),lfp) != NULL ){
			if( strncmp(resp,group,len) == 0 ){
				sscanf(resp,"%*s %d %d",max,min);
				if( *max != 0 )
					*nart = *max - *min + 1;
				else	*nart = 0;
				break;
			}
		}
		fclose(lfp);
		return;
	}

	if( getsv(nsid,&ts,&fs) == 0 )
		return;

	getGROUP(nsid,ts,fs,group,AVStr(resp),sizeof(resp));
	sscanf(resp,"%d %d %d %d",&stat,nart,min,max);
}

/*
 * - initial commands to be executed on the daemon invocation
 * - housekeeping command executed periodically
 *
 *     XCACHE FETCH
 *     XCACHE EXPIRE
 *
 * DeleGate as cron-server for itself
 *     CRON=M:H:d:m:w:command
 *     CRON=0:*:*:*:*:input XCACHE FETCH
 */
static void NNTP_CACHE(NewsServer *ns,NewsClient *nc,PCStr(group),PCStr(com),PCStr(arg))
{	FILE *tc = nc->nc_wfp;
	FILE *ts = ns->ns_wfp;
	FILE *fs = ns->ns_rfp;
	int nsid = ns->ns_nsid;
	CStr(subcom,256);
	CStr(subarg,256);
	int from,to;
	int min,max,anum;
	CStr(resp,1024);
	int size;
	CStr(cpath,1024);
	FILE *afp;
	int cnt,cached;
	int lastgot;

	subcom[0] = subarg[0] = 0;
	Xsscanf(arg,"%s %[^\r\n]",AVStr(subcom),AVStr(subarg));

	if( strcasecmp(subcom,"FETCH") != 0 
	 && strcasecmp(subcom,"EXPIRE") != 0 ){
		fprintf(tc,"501 %s\r\n",XCACHE_usage);
		return;
	}

	size = 0;
	if( subarg[0] == '<' ){
		fprintf(tc,"223 0 fetched %s (%d bytes)\r\n",subarg,size);
		return;
	}
	if( group[0] == 0 ){
		fprintf(tc,"412 Not in a newsgroup\r\n");
		return;
	}

	getGROUP(nsid,ts,fs,group,AVStr(resp),sizeof(resp));
	min = max = 0;
	sscanf(resp,"%*d %*d %d %d",&min,&max);

	from = to = 0;
	if( subarg[0] == 0 ){
		from = min;
		to = max;
	}else{
		switch( sscanf(subarg,"%d-%d",&from,&to) ){
			case 0:	fprintf(tc,"501 %s\r\n",XCACHE_usage);
				return;
			case 1:	to = from;
		}
		if( from < min && to < min || max < from && max < to ){
			fprintf(tc,"501 range errror [%d-%d] [%d-%d]\r\n",
				from,to,min,max);
			return;
		}
		if( from < min )
			from = min;
		if( max < to )
			to = max;
	}
	if( from == to ){
		fprintf(tc,"223 %d fetched (%d bytes)\r\n",from,size);
		return;
	}

	fprintf(tc,"230 List of fetched articles \"num size\" follows.\r\n");
	fflush(tc);
	for( anum = to; from <= anum; anum-- ){
		fprintf(ts,"STAT %d\r\n",anum);
		fflush(ts);
		if( fgets(resp,sizeof(resp),fs) == NULL )
			goto EXIT;
		if( atoi(resp) == 223 )
			break;
	}
	cached = 0;
	lastgot = 0;
	while( from <= anum ){
		cnt = FSlineCNT;
		afp = NNTP_openARTICLE(nsid,NO_EXPIRE,group,anum,AVStr(cpath));
		if( afp == NULL ){
			/* something wrong ? */
			break;
		}

		/* no server communication because already cached */
		if( cnt == FSlineCNT ){
			fclose(afp);
			if( 50 < ++cached )
				break;
			if( lastgot && 5 < time(0)-lastgot )
				break;
		}else{
			cached = 0;
			lastgot = time(0);
			size = file_size(fileno(afp));
			fclose(afp);
			fprintf(tc,"%d %d\r\n",anum,size);
			fflush(tc);
		}

		fprintf(ts,"LAST\r\n");
		fflush(ts);
		if( fgets(resp,sizeof(resp),fs) == NULL )
			goto EXIT;
		if( atoi(resp) != 223 )
			break;
		sscanf(resp,"%*d %d",&anum);

		if( !IsConnected(fileno(tc),NULL) )
			break;
	}
EXIT:
	fprintf(tc,".\r\n");
}



static int POP_findMessageid(FILE *ts,FILE *fs,PCStr(mid))
{	int mno;
	CStr(amid,1024);
	int rcode;

	if( mno = cachedmno(mid) )
		return mno;

	for( mno = 1;; mno++ ){
		if( cachedmid(mno) )
			continue;

		rcode = POP_getField(ts,fs,mno,"Message-Id",AVStr(amid));
		if( rcode < 0 )
			break;
		if( rcode == 0 )
			continue;

		cacheit(mno,amid);
		if( strstr(amid,mid) )
			return mno;
	}
	return 0;
}
static void PopNntpPost(FILE *ts,FILE *fs,FILE *fc,FILE *tc)
{	FILE *artfp;
	CStr(groups,LINESIZE);
	CStr(control,LINESIZE);
	CStr(cmd,128);
	CStr(arg,1024);
	int mno;
	CStr(resp,LINESIZE);

	sv1log("POP/NNTP POST\n");
	Fputs("340 ok (POP/NNTP POST via DeleGate).\r\n",tc);

	artfp = TMPFILE("POP/NNTP_POST");
	getPOST(fc,artfp,AVStr(groups),sizeof(groups));

	if( fgetsHeaderField(artfp,"Control",AVStr(control),sizeof(control)) ){
		sv1log("POP/NNTP %s\n",control);
		arg[0] = 0;
		Xsscanf(control,"%s %s",AVStr(cmd),AVStr(arg));
		if( strcaseeq(cmd,"cancel") ){
			if( mno = POP_findMessageid(ts,fs,arg) ){
				fprintf(ts,"DELE %d\r\n",mno);
				fflush(ts);
				fgetsFS(AVStr(resp),sizeof(resp),fs);
				sv1log("%s",resp);
			}
		}
	}

	fclose(artfp);
	fprintf(tc,"240 Article posted\r\n");
}
static int POP_active(FILE *fs,FILE *ts)
{	CStr(resp,1024);
	int nact;

	fprintf(ts,"LIST\r\n");
	fflush(ts);
	if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
		return -1;

	if( resp[0] == '-' )
		return -1;

	nact = 0;
	while( fgetsFSline(AVStr(resp),sizeof(resp),fs) ){
		if( isEOR(resp) || isEOH(resp) )
			break;
		nact = atoi(resp);
	}
	return nact;
}
static scanListFunc list1(PCStr(fname),FILE *fp)
{
	fprintf(fp,"%s:\r\n",fname);
	return 0;
}

static int popcc(Connection *Conn,PVStr(user))
{
	PopNntp(Conn,AVStr(user));
	return 0;
}

static void PopNntp(Connection *Conn,xPVStr(user))
{	FILE *fc,*tc,*fs,*ts;
	CStr(userb,256);
	CStr(pass,256);
	const char *host = DST_HOST;
	int clsock = FromC;
	CStr(msg,256);
	CStr(req,256);
	const char *dp;
	CStr(com,256);
	CStr(arg1,1024);
	CStr(arg2,1024);
	CStr(resp,1024);
	CStr(banner,256);
	CStr(ng,256);
	int CURRENT,LAST;
	int NACT;
	int artnum1,artnum2;
	CStr(seed,256);
	CStr(uid,256);
	CStr(tmp,256);
	int svsock;

	fc = fdopen(clsock,"r");
	tc = fdopen(clsock,"w");

	if( !ImCC ){
		strcpy(msg,"(Gateway for POP)");
		putIdent(tc,msg);
		fflush(tc);
		setPStr(user,userb,sizeof(userb));
		setVStrEnd(pass,0);
		setVStrEnd(user,0);
		if( getAUTHINFO(tc,fc,AVStr(user),AVStr(pass)) != 0 )
			return;

		sprintf(tmp,"%s:%d:%s:%s",DST_HOST,DST_PORT,user,pass);
		toMD5(tmp,uid);

		if( FromS < 0 ){
			if( connectToCache(Conn,uid,&svsock) ){
				int timeout = IO_TIMEOUT * 1000;
				sv1log("## connected to POPCC (%s@%s:%d)\n",
					user,DST_HOST,DST_PORT);
				tcp_relay2(timeout,clsock,svsock,svsock,clsock);
				return;
			}else
			if( connect_to_serv(Conn,clsock,clsock,0) < 0 )
				return;
		}
	}else{
		sv1log("## POPCC restart (%s@%s:%d)\n",user,DST_HOST,DST_PORT);
	}

	//expsockbuf(FromS,0x1000,0);
	fs = fdopen(FromS,"r");
	ts = fdopen(ToS,"w");

	if( !ImCC && !ServViaCc ){
		if( fgetsFS(AVStr(banner),sizeof(banner),fs) == NULL )
			return;
		getPOPcharange(banner,AVStr(seed));
		if(doPopAUTH(Conn,&ts,&fs,seed,user,pass,AVStr(resp),sizeof(resp))!=0){
			if( strstr(resp,"Can't get lock")
			){
				sv1log("failure in AUTH (X) %s",resp);
				fprintf(tc,"503 %s",resp);
				return;
			}
			sv1log("AUTH failure (X)\n");
			fprintf(tc,"502 %s",resp);
			return;
		}
	}
	fprintf(tc,"281 OK\r\n");

	{
	CStr(userX,256);
	CStr(userY,256);
	void str_setqp(PCStr(qpchars));
	str_setqp("=.%");
	str_toqp(user,strlen(user),AVStr(userX),sizeof(userX));
	url_escapeX(userX,AVStr(userY),sizeof(userY),"@*#",NULL);
	sprintf(ng,"+pop.%s.%s",userY,host);
	}
/*
	sprintf(ng,"+pop.%s.%s",user,host);
*/

	LAST = 0;
	CURRENT = 0;
	NACT = 0;

	for(;;){
		incRequestSerno(Conn);
		fflush(tc);
		if( fgets(req,sizeof(req),fc) == NULL )
			goto QUIT;

		dp = wordScan(req,com);
		dp = wordScan(dp,arg1);
		dp = lineScan(dp,arg2);

		if( strcaseeq(com,"AUTHINFO") && strcaseeq(arg1,"PASS") )
			Verbose("C-S AUTHINFO PASS ****\r\n");
		else	Verbose("C-S %s %s %s\n",com,arg1,arg2);

		if( strcaseeq(com,"MODE") ){
			putIdent(tc,msg);
			continue;
		}
		if( strcaseeq(com,"HELP") ){
			fprintf(tc,"100 Legal commands.\r\n");
			fprintf(tc,"AUTHINFO HELP LIST NEWGROUPS QUIT\r\n");
			fprintf(tc,"ARTICLE HEAD BODY GROUP LAST NEXT\r\n");
			fprintf(tc,".\r\n");
			continue;
		}
		if( strcaseeq(com,"QUIT") ){
			goto QUIT;
		}
		if( strcaseeq(com,"AUTHINFO") ){
		    if( strcaseeq(arg1,"USER") || strcaseeq(arg1,"PASS") ){
			fprintf(ts,"%s %s\r\n",arg1,arg2);
			fflush(ts);
			if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
				break;
			if( resp[0] == '-' ){
				sv1log("AUTH failure (Y)\n");
				fprintf(tc,"502 %s",resp);
				break;
			}

			if( strcaseeq(arg1,"USER") ){
				strcpy(user,arg2);
/*
does this happen?
		url_escapeX(user,AVStr(userX),sizeof(userX),"@*#.",NULL);
*/
				sprintf(ng,"+pop.%s.%s",user,host);
				fprintf(tc,"381 PASS required.\r\n");
			}else	fprintf(tc,"281 OK.\r\n");
			continue;
		    }
		}
		if( strcaseeq(com,"LIST") ){
			if( streq(arg1,"overview.fmt") ){
				fprintf(tc,"215 Order of fields in XOVER.\r\n");
				scan_commaListL(overview_fmt,0,scanListCall list1,tc);
				fprintf(tc,".\r\n");
				continue;
			}
			if( arg1[0] != 0 ){
				fprintf(tc,"215 List follows.\r\n");
				fprintf(tc,".\r\n");
				continue;
			}
			NACT = POP_active(fs,ts);
			if( NACT < 0 )
				break;
			fprintf(tc,"215 List follows.\r\n");
			fprintf(tc,"%s %d 1 y\r\n",ng,NACT);
			fprintf(tc,".\r\n");
			continue;
		}
		if( strcaseeq(com,"NEWGROUPS") ){
			fprintf(tc,"231 newgroups\r\n");
			fprintf(tc,"%s\r\n",ng);
			fprintf(tc,".\r\n");
			continue;
		}
		if( strcaseeq(com,"GROUP") ){
			if( NACT == 0 )
				NACT = POP_active(fs,ts);
			fprintf(tc,"211 %d %d %d %s\r\n",NACT,1,NACT,ng);
			LAST = 0;
			CURRENT = 1;
			continue;
		}
		if( strcaseeq(com,"LAST") ){
			if( LAST == 0 )
				fprintf(tc,"422 No previous to retrieve.\r\n");
			else	fprintf(tc,"223 %d\r\n",LAST); /* wrong */
			continue;
		}
		if( strcaseeq(com,"NEXT") ){
			if( CURRENT == 0 )
				CURRENT = 2;
			else	CURRENT++;
			fprintf(tc,"223 %d\r\n",CURRENT); /* insufficient */
			continue;
		}
		if( strcaseeq(com,"XHDR") ){
			/*
			putXHDR1(tc,fc,arg1,arg2, 0,ts,fs,"pop","",CURRENT);
			*/
			putXHDR1(NULL,tc,fc,arg1,arg2, 0,ts,fs,"pop","",CURRENT);
			continue;
		}

		if( strcaseeq(com,"ARTICLE")
		 || strcaseeq(com,"HEAD")
		 || strcaseeq(com,"BODY") ){
			if( arg1[0] == '<' ){
				artnum1 = POP_findMessageid(ts,fs,arg1);
				if( artnum1 == 0 ){
					fprintf(tc,"430 No such article\r\n");
					continue;
				}
			}else{
				if( arg1[0] != 0 )
					artnum1 = atoi(arg1);
				else	artnum1 = CURRENT;
				if( artnum1 == 0 ){
					fprintf(tc,
					"423 invalid article number: %d\r\n",
						artnum1);
					continue;
				}
			}
			CURRENT = artnum1;

			fprintf(ts,"RETR %d\r\n",artnum1);
			fflush(ts);
			if( fgetsFS(AVStr(resp),sizeof(resp),fs) == NULL )
				break;
			if( resp[0] != '+' ){
				fprintf(tc,"430 No such article\r\n");
				continue;
			}

			if( strcaseeq(com,"ARTICLE") ){
				fprintf(tc,"220 %d article\r\n",artnum1);
				fprintf(tc,"Newsgroups: %s\r\n",ng);
				RecvMssg(fs,tc,1);
				/*
				thruRESP(fs,tc);
				*/
			}else
			if( strcaseeq(com,"HEAD") ){
				fprintf(tc,"221 %d head\r\n",artnum1);
				fprintf(tc,"Newsgroups: %s\r\n",ng);
				while( fgetsFSline(AVStr(resp),sizeof(resp),fs) ){
					if( isEOR(resp) )
						break;
					if( isEOH(resp) ){
						thruRESP(fs,NULLFP());
						break;
					}
					fputs(resp,tc);
				}
				fprintf(tc,".\r\n");
			}else
			if( strcaseeq(com,"BODY") ){
				fprintf(tc,"222 %d body\r\n",artnum1);
				while( fgetsFSline(AVStr(resp),sizeof(resp),fs) ){
					if( isEOR(resp) ){
						fprintf(tc,".\r\n");
						break;
					}
					if( isEOH(resp) ){
						thruRESP(fs,tc);
						break;
					}
				}
			}
			continue;
		}
		if( strcaseeq(com,"POST") ){
			PopNntpPost(ts,fs,fc,tc);
			continue;
		}
		fprintf(tc,"500 POP/NNTP unknown [%s]\r\n",com);
	}

EXIT:
	fflush(tc);
	sv1log("POP/NNTP gateway done.\n");
	return;

QUIT:
	if( ImCC )
	{
		sv1log("## PopNntp DONE (as POPCC)\n");
		if( !feof(fc) )
			fprintf(tc,"205 bye.\r\n");
		fclose(tc);
		return;
	}

	if( NNTP_POPCC ){
		sv1log("## PopNntp DONE (to be POPCC)\n");
		if( !feof(fc) )
		fprintf(tc,"205 bye.\r\n");
		fclose(tc);
		fclose(fc);
		beBoundProxy(Conn,uid,POPCC_TIMEOUT,(iFUNCP)popcc,AVStr(user));
		return;
	}

	fprintf(ts,"QUIT\r\n");
	fflush(ts);
	fgetsFS(AVStr(resp),sizeof(resp),fs);
	sv1log("POP/NNTP %s",resp);
	if( !feof(fc) )
	fprintf(tc,"205 bye.\r\n");
	fclose(tc);
	sv1log("## PopNntp DONE\n");
	goto EXIT;
}

static void call_popgw(Connection *Conn,int clsock,int svsock,int ac,char *av[],PCStr(arg))
{
	minit_nntp();
	Xsscanf(arg,"%s %s %d",AVStr(REAL_PROTO),AVStr(REAL_HOST),&REAL_PORT);
	strcpy(DFLT_PROTO,REAL_PROTO);
	DFLT_PORT = REAL_PORT;

	ClientSock = FromC = ToC = clsock;
	FromS = ToS = svsock;
	PopNntp(Conn,VStrNULL);
}

int closeClientSockets(Connection *Conn);
extern int DUP_ToC;
int connect_to_popgw(Connection *Conn,int fromC,int toC)
{	int csv[2];
	CStr(arg,1024);

	Socketpair(csv);
	if( INHERENT_fork() && getenv("NOFORK") == NULL ){
		if( Fork("POP/NNTP translator") == 0  ){
			close(ClientSock);
			close(FromC);
			close(ToC);
			close(DUP_ToC);
			close(fromC);
			if( toC != fromC ) close(toC);
			close(csv[0]);
			closeClientSockets(Conn);
			strcpy(REAL_PROTO,"pop");
			strcpy(DFLT_PROTO,"pop");
			FromC = ToC = csv[1];
			PopNntp(Conn,VStrNULL);
			Finish(0);
		}
	}else{
		setCloseOnExecSocket(ClientSock);
		setCloseOnExecSocket(csv[0]);
		setCloseOnExecSocket(DUP_ToC);
		sprintf(arg,"%s %s %d","pop",DST_HOST,DST_PORT);
		execFunc(Conn,csv[1],ToS,(iFUNCP)call_popgw,arg);
		clearCloseOnExecSocket(ClientSock);
		clearCloseOnExecSocket(csv[0]);
		clearCloseOnExecSocket(DUP_ToC);
	}
	close(csv[1]);
	//expsockbuf(csv[0],0x1000,0);
	return ToS = FromS = csv[0];
}

int NNTP_mailToPoster(Connection *Conn,int nsid,PCStr(grp),int ano,PCStr(key),FILE *mfp,PVStr(res),int siz){
	NewsServer *ns;
	FILE *ts,*fs;
	CStr(authb,128);
	refQStr(usr,authb);
	refQStr(pas,authb);

	truncVStr(res);
	if( getsv(nsid,&ts,&fs) == 0 ){
		sprintf(res,"500 no server\r\n");
		return -1;
	}
	ns = toNS(nsid);
	pas = 0;
	Conn->from_myself = 1;
	CTX_pushClientInfo(Conn);
	if( get_MYAUTH(Conn,AVStr(authb),"nntp",ns->ns_host,ns->ns_port) ){
		if( pas = strchr(authb,':') ){
			setVStrPtrInc(pas,0);
		}
	}
	HL_popClientInfo();
	Conn->from_myself = 0;
	if( pas ){
		fprintf(ts,"AUTHINFO USER %s\r\n",usr);
		fflush(ts);
		if( fgets(res,siz,fs) == NULL || '4' <= res[0] ){
			return -2;
		}
		fprintf(ts,"AUTHINFO PASS %s\r\n",pas);
		fflush(ts);
		if( fgets(res,siz,fs) == NULL || '4' <= res[0] ){
			return -3;
		}
	}
	fprintf(ts,"POST\r\n");
	fflush(ts);
	if( fgets(res,siz,fs) == NULL || res[0] != '3' ){
		return -4;
	}
	fprintf(ts,"Control: %s %s %d\r\n",NN_ForwardToPoster,grp,ano);
	fprintf(ts,"X-Auth-Key: %s\r\n",key);
	copyfile1(mfp,ts); /* must escape .CRLF */
	fprintf(ts,".\r\n");
	fflush(ts);
	if( fgets(res,siz,fs) == NULL || res[0] != '2' ){
		return -5;
	}
	return 0;
}
int enBase32(PCStr(src),int slen,PVStr(dst),int dsiz);
int relayHeader(FILE *fs,FILE *tc,PCStr(mask),PVStr(buf),int siz);
#define HeadList "Subject,From,Date,Message-ID,Lines,Organization,References,Content-Type"
void sendmail1(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log);
int sendAdminMail(Connection *Conn,FILE *mfp,FILE *afp,PCStr(key),PCStr(ctrl),PCStr(to),PCStr(desc)){
	FILE *tmp;
	CStr(head,64*1024);
	CStr(xkey,128);
	CStr(bnd,128);

	makeAdminKey(to,AVStr(xkey),sizeof(xkey));
	setVStrEnd(xkey,8);

	StrftimeGMT(AVStr(bnd),sizeof(bnd),"%Y%m%d.%H%M%S",time(0),0);
	Xsprintf(TVStr(bnd),".%s.%d",mailClientId,getpid());

	tmp = TMPFILE("AdminMail");
	fprintf(tmp,"Message-Id: <%s.adm-%s>\r\n",mailClientId,DELEGATE_ADMIN);
	fprintf(tmp,"To: %s\r\n",to);
	fprintf(tmp,"From: %s\r\n",DELEGATE_ADMIN);
	fprintf(tmp,"Subject: To %s\r\n",desc);
	fprintf(tmp,"Content-Type: multipart/mixed; boundary=\"%s\"\r\n",bnd);
	fprintf(tmp,"\r\n");

	if( strneq(ctrl,NN_ForwardToPoster,strlen(NN_ForwardToPoster)) ){
		fprintf(tmp,"--%s\r\n",bnd);
		fprintf(tmp,"X-Auth-Key: %s\r\n",xkey);
		fprintf(tmp,"\r\n");
		fprintf(tmp,"This is a message generated by DeleGate/%s\r\n",
			DELEGATE_ver());
		fprintf(tmp,"sending to %s\r\n",desc);
		fprintf(tmp,"initiated by: %s\r\n\r\n",mailClientAddr);
		fprintf(tmp,"  Your Email-Address: %s\r\n",to);
		fprintf(tmp,"  Your Auth-Key: %s\r\n",xkey);
		fprintf(tmp,"\r\n");
	}
	fprintf(tmp,"--%s\r\n",bnd);
	fprintf(tmp,"Content-Description: Your Request\n");
	RFC821_skipbody(mfp,tmp,VStrNULL,0);
	fprintf(tmp,"\r\n");

	if( strcaseeq(key,xkey) ){
		fprintf(tmp,"--%s\r\n",bnd);
		fprintf(tmp,"Content-Description: Your Original Article\r\n");
		fprintf(tmp,"Content-Type: message/rfc822\r\n");
		fprintf(tmp,"\r\n");
		relayHeader(afp,NULL,HeadList,AVStr(head),sizeof(head));
		fprintf(tmp,"%s\r\n",head);
		RFC821_skipbody(afp,tmp,VStrNULL,0);
		fprintf(tmp,"\r\n");
	}
	fprintf(tmp,"--%s--\r\n",bnd);
	fflush(tmp);
	fseek(tmp,0,0);
	sendmail1(Conn,to,DELEGATE_ADMIN,tmp,NULL);
	sv1log("NNTP: [%s] ForwardToPoster: %s\n",mailClientAddr,to);
	/* should make dedicated log (MBOX) for this */

	fclose(tmp);
	return 0;
}

int closeClientSockets(Connection *Conn){
	int closed = 0;
	int fd;
	IStr(host,MaxHostNameLen);
	int port;

	checkCloseOnTimeout(0); /* close -Pxxx ports */
	if( ClientFlags & PF_SSL_ON ){
		/* left connected with the client in the thread for SSL */
		for( fd = 0; fd < FD_SETSIZE; fd++ ){
			if( 0 < file_issock(fd) )
			if( sockPort(fd) == CLIF_PORT ){
				port = gethostNAME(fd,AVStr(host));
				sv1log("close clnt sock[%d] %s:%d (%s)\n",
					fd,host,port,CLIF_HOST);
				{
					if( close(fd) == 0 )
						closed++;
				}
			}
		}
	}
	return closed;
}

/*
 * 9.9.5 on-demand server
 */
static CriticalSec connCSC;
static int setOnDemand(PCStr(opts)){
	NX.ne_ondemand = stralloc(opts);
	return 0;
}
int clearFD(FilterDesc *FD){
	bzero(FD,sizeof(FilterDesc));
	return 0;
}
int setupFD(FilterDesc *FD){
	IGNRETZ pipe(FD->f_sv);
	FD->f_tci = fdopen(FD->f_sv[0],"r");
	FD->f_tcx = fdopen(FD->f_sv[1],"w");
	return 0;
}
int closeFD(FilterDesc *FD){
	fclose(FD->f_tcx);
	thread_wait(FD->f_tid,3*1000);
	fclose(FD->f_tci);
	return 0;
}
/* real hostcmp() could be too heavy */
#undef hostcmp
static int hostcmpX(PCStr(h1),PCStr(h2)){
	if( NX.ne_ondemand ){
		if( strcasecmp(h1,h2) == 0 ){
			return 0;
		}
		return -1;
	}else{
		return hostcmp(h1,h2);
	}
}
static int clearActCache1(NewsServer *ns,int neg){
	int ai;
	const char *act1;
	int nclr = 0;

	for( ai = 0; ai < elnumof(ns->ns_actcache[0]); ai++ ){
		if( act1 = ns->ns_actcache[neg][ai] ){
			free((char*)act1);
			ns->ns_actcache[neg][ai] = 0;
			nclr++;
		}
	}
	return nclr;
}
static int clearActCache(NewsServer *ns){
	int nclr = 0;
	nclr += clearActCache1(ns,0);
	nclr += clearActCache1(ns,1);
	if( nclr ){
		TRACE("---- cleared active cache (%d)\n",nclr);
	}
	return 0;
}
#define IsDelim(ch) (isspace(ch) || ch == 0)
static int putActCache(PCStr(wh),NewsServer *ns,PCStr(grp),PCStr(act),int neg){
	int glen = strlen(grp);
	const char *act1;
	IStr(actb,256);
	int ai;
	int asiz;
	int ni = ns->ns_nsid;

	if( neg ) neg = 1;
	lineScan(act,actb);
	for( ai = 0; ai < elnumof(ns->ns_actcache[neg]); ai++ ){
		act1 = ns->ns_actcache[neg][ai];
		if( act1 == 0 ){
			ns->ns_actcache[neg][ai] = stralloc(actb);
			TRACE("--AC %s[%d] ADD[%d] %s\n",wh,ni,ai,actb);
			return 2;
		}
		if( strncmp(act1,grp,glen) == 0 && IsDelim(act1[glen]) ){
			TRACE("--AC %s[%d] DUP[%d] %s\n",wh,ni,ai,actb);
			return 1;
		}
	}
	return 0;
}
static int getActCache(PCStr(wh),NewsServer *ns,PCStr(grp),PVStr(act),int neg){
	int glen = strlen(grp);
	const char *act1;
	int ai;
	int ni = ns->ns_nsid;

	if( neg ) neg = 1;
	for( ai = 0; ai < elnumof(ns->ns_actcache[neg]); ai++ ){
		act1 = ns->ns_actcache[neg][ai];
		if( act1 == 0 ){
			continue;
		}
		if( strncmp(act1,grp,glen) == 0 && IsDelim(act1[glen]) ){
			sprintf(act,"%s\r\n",act1);
			if( neg )
				TRACE("--AC %s/%d NEG[%d] %s\n",wh,ni,ai,act1);
			else	TRACE("--AC %s/%d HIT[%d] %s\n",wh,ni,ai,act1);
			return 1;
		}
	}
	return 0;
}
static int getGROUPcache(NewsServer *ns,PCStr(group),PVStr(stat));
static int isServerOfX(NewsServer *ns,FILE *lf,PCStr(grp)){
	IStr(act1,1024);
	double St = Time();
	int glen = strlen(grp);
	int siz = 0;

	/* should use Hsearch() or shared-memory for a large list */
	if( getActCache("isServer",ns,grp,AVStr(act1),0) ){
		return 2;
	}
	if( getActCache("isServer",ns,grp,AVStr(act1),1) ){
		return 0;
	}
	if( getGROUPcache(ns,grp,AVStr(act1)) ){
		if( act1[0] == '2' ){
			TRACE("--GC HIT[%d] %s",ns->ns_nsid,act1);
			return 1;
		}
	}
	while( fgets(act1,sizeof(act1),lf) != NULL ){
		siz += strlen(act1);
		if( act1[0] == grp[0] )
		if( strncmp(act1,grp,glen) == 0 && isspace(act1[glen]) ){
			TRACE("## FOUND[%d] %.2f %s\n",ns->ns_nsid,Time()-St,
				grp);
			putActCache("isServerOf",ns,grp,act1,0);
			return 1;
		}
	}
	putActCache("isServerOf",ns,grp,grp,1);
	TRACE("## NOT FOUND[%d] %.2f '%s'\n",ns->ns_nsid,Time()-St,grp);
	return 0;
}
static int relayLIST(FILE *tci,FILE *tc,int dofilter){
	IStr(line,1024);
	int li;
	int size = 0;
	double St = Time();
	double PSt;
	FILE *cfp = 0;
	IStr(path,256);
	IStr(cpath,256);

	PSt = St;
	for( li = 0; ; li++ ){
		if( fgets(line,sizeof(line),tci) == NULL ){
			break;
		}
		if( line[0] == '#' && line[1] == '>' ){
			TRACE(">>>> %s",line);
			clearVStr(path);
			Xsscanf(line,"#>CACHE %[^\r\n]",AVStr(path));
			if( path[0] ){
				if( cfp ){
					TRACE(">>>> done=%d %s\n",iftell(cfp),
						cpath);
					fclose(cfp);
					cfp = 0;
				}
				if( streq(path,".") ){
				}else{
					strcpy(cpath,path);
					cfp = fopen(cpath,"r+");
					if( cfp == 0 ){
						cfp = fopen(cpath,"w");
					}
					TRACE(">>>> start %X %s\n",p2i(cfp),cpath);
				}
			}
			continue;
		}
		/* should do filter_active() before cache & relay */

		if( cfp ){
			fputs(line,cfp);
		}
		fputs(line,tc);
		size += strlen(line);
		if( (li % 2000) == 0 && 2 < (Time()-PSt) ){
			TRACE(">>>> LIST %d %d %.1fK/s (%.2f)\n",li,
				size,(size/(Time()-St))*0.001,Time()-St);
			PSt = Time();
		}
	}
	if( cfp ){
		TRACE(">>>> done=%d %s\n",iftell(cfp),cpath);
		fclose(cfp);
	}
	TRACE(">>>> LIST %d %d (%.2f) DONE\n",li,size,Time()-PSt);
	return 0;
}
/* the "not-modified-since" cache of NEWGROUPS to suppress connection
 * to the server initiated by NEWGROUPS.
 */
static int updateNEWGROUPS(NewsServer *ns,PCStr(qdates),int ngop){
	int qdate;
	FILE *dfp;
	IStr(path,1024);
	IStr(cdates,1024);
	int age = -1;
	int cdate = -1; /* known "not-modified-since" of NEWGROUPS */
	int rcode = -1;
	int Lexpire = UPACT_SOME;
	int update; /* to be updated for TO_UPDATE and GOT_EMPTY */

	cache_path("nntp",ns->ns_host,ns->ns_port,"NEWGROUPS-date",AVStr(path));
	if( dfp = dirfopen("NG",AVStr(path),"r+") ){
		age = file_age(path,dfp);
		Fgets(AVStr(cdates),sizeof(cdates),dfp);
		cdate = YMD_HMS_toi(cdates);
	}else{
		dfp = dirfopen("NG",AVStr(path),"w+");
	}
	if( dfp == NULL ){
		return -1;
	}
	fseek(dfp,0,0);
	qdate = YMD_HMS_toi(qdates);
	update = 0;
	switch( ngop ){
	    case NGOP_TO_UPDATE:
		/* inquired date older than the known "not-modified-since" */
		if( cdate == -1   ) update = 11; else
		if( qdate < cdate ) update = 12; else
		if( Lexpire < age ) update = 13;
		rcode = update;
		break;
	    case NGOP_GOT_EMPTY:
		if( ns->ns_NEWGROUPS_gen ){
			/* ignore the generated resp. from self */
		}else
		if( cdate == -1   ) update = 21; else
		if( qdate < cdate ) update = 22; else
		if( Lexpire < age ) update = 23;
		if( update ){
			TRACE("## NGRP empty Q-%X C=%X\n",qdate,cdate);
			fprintf(dfp,"%s\r\n",qdates);
			Ftruncate(dfp,0,1);
		}
		break;
	    case NGOP_GOT_UPDATE:
		if( cdate < qdate ){
			/* "not-modified-since" has become unknown */
			TRACE("## NGRP updated Q-%X C=%X\n",qdate,cdate);
			Ftruncate(dfp,0,0);
			update = 30;
		}
		break;
	}
	TRACE("## NGRP %d %d age=%d update=%d Q[%s]%X C[%s]%X %s\n",ngop,
		ns->ns_NEWGROUPS_gen,age,update,qdates,qdate,cdates,cdate,path);
	fflush(dfp);
	return rcode;
}
static int waiting_ondemand_serv(FL_PAR,FILE *fs){
	int wi;
	int terr = -2,tid;
	int fx;

	if( fs && file_isreg(fileno(fs)) ){
		return 0;
	}
	if( fs == 0 ){
		/* 9.9.7 PollIn()< 0, EINTR, by YYMUX SIGINT */
		int rv = 0;
		sv1log("#### waiting_ondemand(%s:%d,0) e%d ####\n",
			FL_BAR,errno);
		for( fx = 0; fx < elnumof(NX.ne_redirecting_serv); fx++ ){
			if( rv = NX.ne_redirecting_serv[fx] ){
				sv1log("#### waiting_ondemand[%d] ####\n",fx);
				break;
			}
		}
		if( rv == 0 ){
			sv1log("#### waiting_ondemand: none ####\n");
			return 0;
		}
	}else
	fx = fileno(fs) % elnumof(NX.ne_redirecting_serv);
	TRACE("==== waiting_ondemand[%d] %s:%d (%d) EOF=%d\n",fx,
		FL_BAR,NX.ne_redirecting_serv[fx],fs?feof(fs):0);
	if( NX.ne_redirecting_serv[fx] == 0 ){
		return 0;
	}
	for( wi = 0; wi < 50; wi++ ){
		if( NX.ne_redirecting_serv[fx] == 2 ){
			if( fs ){
				clearerr(fs);
			}
			if( tid = NX.ne_redirecting_tid[fx] ){
				terr = thread_wait(tid,500);
				NX.ne_redirecting_tid[fx] = 0;
			}
			TRACE("==== waiting_ondemand %s:%d (%d) OK %X/%d\n",
				FL_BAR,NX.ne_redirecting_serv[fx],tid,terr);
			NX.ne_redirecting_serv[fx] = 0;
			return 1;
		}
		msleep(100);
	}
	TRACE("==== waiting_ondemand %s:%d ERR sync (%d)\n",FL_BAR,
		NX.ne_redirecting_serv[fx]);
	return 1;
}
static int putGROUPbyLIST(NewsServer *ns,FILE *lfp,PCStr(group),FILE *tc){
	IStr(line,256);
	int len;
	int age = file_age(group,lfp);
	double St = Time();
	int li;
	int min,max,total;

	TRACE("==== [%d] LIST age=%d %s\n",ns->ns_nsid,age,group);
	len = strlen(group);
	if( getActCache("getGL",ns,group,AVStr(line),0) ){
		goto FOUND;
	}
	if( getActCache("getGL",ns,group,AVStr(line),1) ){
		return 0;
	}
	for( li = 0; fgets(line,sizeof(line),lfp) != NULL; li++ ){
		if( line[0] == group[0] )
		if( strncmp(line,group,len) == 0 ){
			TRACE("==== [%d] gc GOT (%d %.2f) %s",ns->ns_nsid,
				li,Time()-St,line);
			putActCache("getGL",ns,group,line,0);
			goto FOUND;
		}
	}
	TRACE("==== [%d] not in LIST (%d %.2f) age=%d %s\n",
		ns->ns_nsid,li,Time()-St,age,group);
	putActCache("getGL",ns,group,group,1);
	return 0;
FOUND:
	min = max = total = -1;
	sscanf(line,"%*s %d %d",&max,&min);
	if( max != 0 )
		total = max - min + 1;
	else	total = 0;
	if( 0 < max ){
		TRACE("==== GROUP 211 %d %d %d %s\n",total,min,max,group);
		fprintf(tc,"211 %d %d %d %s\r\n",total,min,max,group);
		return 1;
	}
	return 0;
}
/* forward the current status to the real server */
static void resume0(NewsServer *ns,FILE *ts,FILE *fs){
	IStr(resp,256);
	const char *group = ns->ns_curgroupR?ns->ns_curgroupR:"";
	int anum = ns->ns_curanum;

	TRACE("==== curgroup[%s:%d]\n",group,anum);
	if( ns->ns_auser && *ns->ns_auser ){
		NewsServer nsb;
		int aok;
		nsb = *ns;
		nsb.ns_wfp = ts;
		nsb.ns_rfp = fs;
		aok = doNntpAUTH(&nsb);
	}
	if( *group ){
		fprintf(ts,"GROUP %s\r\n",group);
		fflush(ts);
		fgets(resp,sizeof(resp),fs);
		if( resp[0] == 0 ) strcpy(resp,"\n");
		TRACE("==== [%s:%d] rdy=%d %s",group,anum,ready_cc(fs),resp);
	}
	if( anum ){
		fprintf(ts,"STAT %d\r\n",anum);
		fflush(ts);
		fgets(resp,sizeof(resp),fs);
		if( resp[0] == 0 ) strcpy(resp,"\n");
		TRACE("==== [%s:%d] rdy=%d %s",group,anum,ready_cc(fs),resp);
	}
}
static int getStatusCache(NewsServer *ns,PCStr(gpath),PVStr(stat)){
	IStr(cpath,256);
	IStr(sta1,256);
	refQStr(sp,sta1);
	FILE *gfp;
	int code;
	int age;

	cache_path("nntp",ns->ns_host,ns->ns_port,gpath,AVStr(cpath));
	if( gfp = dirfopen("StatusCache",AVStr(cpath),"r") ){
		age = file_age(cpath,gfp);
		fgets(sta1,sizeof(sta1),gfp);
		if( sp = strpbrk(sta1,"\r\n") )
			clearVStr(sp);
		fclose(gfp);
		code = atoi(sta1);
		sprintf(stat,"%s\r\n",sta1);
		if( UPACT_SOME < age ){
			TRACE("---- exp cache age=%d: %s",age,stat);
			return 0;
		}
		if( 100 <= code && code < 999 ){
			TRACE("---- got cache age=%d: %s",age,stat);
			return 1;
		}
	}
	return 0;
}
static int toGpath(PCStr(base),PCStr(group),int ncol,PVStr(gpath)){
	IStr(md5,64);
	toMD5(group,md5);
	setVStrEnd(md5,ncol);
	sprintf(gpath,"%s/=%s/%s",base,md5,group);
	return 0;
}
static int getGROUPcache(NewsServer *ns,PCStr(group),PVStr(stat)){
	IStr(gpath,256);
	toGpath("GROUP",group,2,AVStr(gpath));
	return getStatusCache(ns,gpath,BVStr(stat));
}
static int putGROUPcache(NewsServer *ns,PCStr(stat)){
	IStr(group,256);
	IStr(gpath,256);
	IStr(cpath,256);
	FILE *gfp;

	Xsscanf(stat,"%*d %*d %*d %*d %s",AVStr(group));
	toGpath("GROUP",group,2,AVStr(gpath));
	cache_path("nntp",ns->ns_host,ns->ns_port,gpath,AVStr(cpath));
	if( gfp = dirfopen("GROUPcache",AVStr(cpath),"w") ){
		TRACE("---- put cache: %s",stat);
		fprintf(gfp,"%s",stat);
		fclose(gfp);
		return 0;
	}
	return -1;
}
static int putActLIST(NewsServer *ns,PCStr(arg),FILE *tc){
	FILE *lfp;

	if( *arg && !strcaseeq(arg,"ACTIVE") ){
		return 0;
	}
	lfp = LCfp(ns,LI_ACTIVE);
	if( lfp == 0 ){
		return 0;
	}
	TRACE("==== [%d] LIST[%s] age=%d\n",ns->ns_nsid,arg,file_age(arg,lfp));
	fprintf(tc,"215 Newsgroups in form \"group high low flags\".\r\n");
	fseek(lfp,0,0);
	copyfile1(lfp,tc);
	fputs(".\r\n",tc);
	return 1;
}
static int putArtSTAT(NewsServer *ns,PCStr(arg),FILE *tc){
	FILE *afp;
	IStr(path,256);
	IStr(msgid,256);
	int anum = atoi(arg);

	afp = NNTP_openARTICLE(ns->ns_nsid,-1,
		ns->ns_curgroupR,anum,AVStr(path));
	if( afp == 0 ){
		return 0;
	}
	fgetsHeaderField(afp,"Message-ID",AVStr(msgid),sizeof(msgid));
	fclose(afp);
	fprintf(tc,"223 %d %s\r\n",anum,msgid);
	return 1;
}
#define Get_Cache(host,port,path,msg) \
	get_cache("NNTP-cache",host,port,path,AVStr(msg),sizeof(msg))
int ShutdownSocket(int);
static int inconnect;
static int connect_servCSC(Connection *ConnX,NewsServer *ns){
	int mok;
	int ntry = 0;
	int toS;
	double St = Time();
	Connection ConnBuf,*Conn = &ConnBuf;

	ConnBuf = *ConnX;
	mok = enterCSCX(connCSC,10*1000);
	while( 0 < inconnect ){ /* maybe running on a OS without mutex */
		msleep(300);
		if( 30 < Time()-St ){
			TRACE("==== #### TIMEOUT waiting connect(%d)...[%X]\n",
				inconnect,PRTID(ns->ns_nsid));
			return -1;
		}
		ntry++;
	}
	inconnect++;
	strcpy(REAL_PROTO,ns->ns_proto);
	strcpy(REAL_HOST,ns->ns_host);
	REAL_PORT = ns->ns_port;
	toS = connect_serv(Conn,ns);
	inconnect--;
	leaveCSC(connCSC);
	TRACE("==== connected [%d] mutex=%d,%d (%.2f) => %s:%d\n",
		toS,mok,ntry,Time()-St,ns->ns_host,ns->ns_port);
	return toS;
}
static int ondemand_serv(Connection *Conn,int svsock,int clsock,NewsServer *ns){
	FILE *tc,*fc;
	IStr(msg,256);
	IStr(req,256);
	IStr(com,256);
	IStr(arg,256);
	const char *dp;
	const char *host = ns->ns_host;
	int port = ns->ns_port;
	int nsvsock;
	IStr(path,1024);
	int didputopen = 0;
	FILE *lfp;
	int Lexpire = UPACT_SOME;
	int fx = clsock % elnumof(NX.ne_redirecting_serv);

	ns->ns_ondemand_yet = 1;
	fc = fdopen(svsock,"r");
	tc = fdopen(svsock,"w");
	TRACE("==== stab #### [%d] SERVER=nntp://%s:%d\n",
		ns->ns_nsid,host,port);
	if( Get_Cache(host,port,"lib/opening",msg) ){
		didputopen = 1;
		fprintf(tc,"%s",msg);
	}else{
		goto DO_CONNECT;
	}
	for(;;){
		fflush(tc);
		if( fgets(req,sizeof(req),fc) == 0 ){
			TRACE("==== stab Q: EOS\n");
			break;
		}
		TRACE("==== stab [%d] Q: [%s] %s",
			ns->ns_nsid,ns->ns_curgroupR?ns->ns_curgroupR:"",req);
		dp = wordScan(req,com);
		lineScan(dp,arg);

		if( strcaseeq(com,"MODE") ){
			if( strcaseeq(arg,"READER") ){
				if( 0 ){
					/* if cached in MODE-cache */
				}else{
					fprintf(tc,"200 ==== enabled\r\n");
				}
				continue;
			}
		}
		if( strcaseeq(com,"HELP") ){
			if( Get_Cache(host,port,"lib/HELP",msg) ){
				fprintf(tc,"%s\r\n.\r\n",msg);
				continue;
			}else{
				break;
			}
		}
		if( strcaseeq(com,"DATE") ){
			CStr(sdate,32);
			StrftimeGMT(AVStr(sdate),sizeof(sdate),"%Y%m%d%H%M%S",
				time(0),0);
			fprintf(tc,"111 %s\r\n",sdate);
			continue;
		}
		if( strcaseeq(com,"NEWGROUPS") ){
			if( updateNEWGROUPS(ns,arg,NGOP_TO_UPDATE) ){
				ns->ns_NEWGROUPS_gen = 0;
				break;
			}else{
				ns->ns_NEWGROUPS_gen = 1;
				fprintf(tc,"231 not-modified.\r\n");
				fprintf(tc,".\r\n");
				continue;
			}
		}
		if( strcaseeq(com,"STAT") ){
			if( putArtSTAT(ns,arg,tc) ){
				continue;
			}
		}
		if( strcaseeq(com,"LIST") ){
			/*
			if( putActLIST(ns,arg,tc) ){
				continue;
			}
			*/
		}
		if( strcaseeq(com,"GROUP") ){
			if( getGROUPcache(ns,arg,AVStr(msg)) ){
				fputs(msg,tc);
				continue;
			}
			lfp = LCfp(ns,LI_ACTIVE);
			if( lfp ){
				int age;
				if( Lexpire < (age=file_age("LIST",lfp)) ){
					TRACE("==== LIST-cache age=%d > %d\n",
						age,Lexpire);
				}else{
					fseek(lfp,0,0);
					if( putGROUPbyLIST(ns,lfp,arg,tc) ){
						continue;
					}
				}
			}else{
				TRACE("==== GROUP %s not-in-LIST-cache\n",arg);
			}
			if( streq(arg,"junk") || streq(arg,"control") ){
				sprintf(msg,"500 ign. %u GROUP %s",itime(0),arg);
				TRACE("%s\n",msg);
				fprintf(tc,"%s\r\n",msg);
				continue;
			}
		}
		break;
	}

DO_CONNECT:
	ns->ns_ondemand_yet = 0;
	if( feof(fc) || !IsAlive(ClientSock) ){
		goto EXIT;
	}
	TRACE("==== stab #### [%d] CONNECTING to '%s:%d' for: %s%s",
		ns->ns_nsid,ns->ns_host,ns->ns_port,req,
		strchr(req,'\n')?"":"\n");

	if( (nsvsock = connect_servCSC(Conn,ns)) < 0 ){
		TRACE("==== stab ERROR, connection failed.\n");
		fprintf(tc,"400 ondemand-connect failed.\r\n");
	}else{
		int tmpsv;
		FILE *fs,*ts;

		tmpsv = dup(nsvsock);
		fs = fdopen(tmpsv,"r");
		TRACE("==== sockets [%d %d] [%d %d] [%d] %X\n",
			svsock,clsock, nsvsock,tmpsv,ToSX,p2i(fs));
		if( fs == NULL ){
			TRACE("==== #### fdopen[%d][%d]%X\n",nsvsock,tmpsv,p2i(fs));
			_Finish(-1);
		}
		setbuffer(fs,0,0);
		ts = fdopen(tmpsv,"w");
		setbuffer(ts,0,0); /* for FC6 and Deb3 */
		/* should do fPollIns(fc,fs) here */
		fgets(msg,sizeof(msg),fs);
		TRACE("==== stab server SAYS: %s",msg);
		if( msg[0] == '2' ){
			put_cache(ns,"NNTP-open","lib/opening",msg);
		}
		if( didputopen == 0 || msg[0] != '2' ){
			fputs(msg,tc);
			fflush(tc);
			if( msg[0] != '2' ){
				TRACE("#### real server says: %s",msg);
				goto EXIT;
			}
		}
		resume0(ns,ts,fs);
		if( req[0] ){
			fputs(req,ts);
			TRACE("==== forw-1 %s",req);
		}
		while( 0 < fPollIn(fc,1000) ){ /* pipelined requests */
			if( fgets(req,sizeof(req),fc) ){
				fputs(req,ts);
				TRACE("==== forw-2 %s",req);
			}else{
				break;
			}
		}
		fcloseFILE(ts);
		fclose(fs);

		NX.ne_redirecting_tid[fx] = ns->ns_ondemand_tid;
		NX.ne_redirecting_serv[fx] = 1;
		ShutdownSocket(svsock);
		/* should wait receiver to exit from select(clsock) or
		 * recv(clsock) and start waiting_ondemand_serv() ...
		 */
		msleep(100);
		dup2(nsvsock,clsock); /* might interrupt select(clsock) */
		close(nsvsock);
		TRACE("==== stab OK, connected.\n");
	}
EXIT:
	TRACE("==== stab done %X\n",TID);
	fcloseFILE(tc);
	fclose(fc);
	NX.ne_redirecting_serv[fx] = 2;
	return 0;
}
static int ondemandServ(Connection *Conn,NewsServer *ns,int dmndsv[2]){
	int tid;

	setupCSC("ActLIST",connCSC,sizeof(connCSC));
	ns->ns_islocal = 0;
	tid = thread_fork(0x100000,0,"NNTP-on-demand",(IFUNCP)ondemand_serv,
		Conn,dmndsv[0],dmndsv[1],ns);
	TRACE("==== stab SERVER=nntp://%s:%d [%X]\n",
		ns->ns_host,ns->ns_port,tid);
	ns->ns_ondemand_tid = tid;
	return 0;
}
/* Thunderbird makes connections without sending requests other than "QUIT" */
int recvPEEK(int sock,PVStr(buf),int size);
static int waitRequest(Connection *Conn,FILE *fc,FILE *tc){
	double Start = Time();
	IStr(com,128);
	IStr(mod,128);
	IStr(req,128);
	int nready;
	int rcc;

	if( (nready = fPollIn(fc,3*1000)) == 0 ){
		nready = fPollIn(fc,30*1000);
	}
	if(  0 < nready ){
		rcc = recvPEEK(FromC,AVStr(req),sizeof(req)-1);
		if( rcc <= 0 ){
			nready = -2;
		}else
		if( 0 < rcc ){
			setVStrEnd(req,rcc);
			lineScan(req,com);
			if( strcaseeq(com,"QUIT") ){
				fprintf(tc,"205\r\n");
				nready = -3;
			}
			if( strcaseeq(com,"MODE READER") ){
				TRACE("==== %s\n",com);
				nready = 3;
			}
		}
	}
	if( nready <= 0 ){
		TRACE("---- reset without request (%d) %.2f [%s][%s]\n",
			nready,Time()-Start,mod,com);
		return 1;
	}
	return 0;
}
