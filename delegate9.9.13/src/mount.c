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
Program:	mount.c (mount URL to/from)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	MOUNT="virtualUrl realUrl optionList"

	=://=:=/*	... ///*
	=://=/*		... //=:0/*
	=://hostX/*	... //hostX:0/*
	=://hostX:=/*   ... //hostX:=/*
	=://=:portX/*   ... //=:portX/*

History:
	940806	created
	9907xx	full-URL in the left-hand (host name/addr matching)
		wild-card hostList like http://192.31.200.* in left-hand
		MOUNT="/-_-* * dstproto={protoList},dst={siteList}"
		MOUNT="/path/* http://* dst={siteList}"
ToDo:

	- proto1://site1/path1 proto2://site2/path2
	  where site1 is a "name of a hostList" (or Site in terms of URL)
	- proto1://+siteList/path1 proto2://site2/path2 vhost=siteList
	- MOUNT="http:// * /path1 http:// * /path2"
	- reverse matching in left hand (ex. *.gif)

//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include "ystring.h"
#include "dglib.h"
#include "file.h"
#include "url.h"

void Bsort(char base[],int nel,int width,int (*compar)(const char*,const char*));
const char *gethostaddr_fromcache(PCStr(host));
int getCondition(DGC*ctx);
int evalCondition(DGC*ctx, int condid);
int portMap(DGC*Conn,PCStr(proto),PCStr(host),PCStr(portspec));
void sethostcache_predef(PCStr(name),PCStr(addr),int len,int type);
int url_strstrX(PCStr(url),PCStr(pat),int nocase);
int urlpath_normalize(PCStr(url),PVStr(rurl));
int matchFROM(DGC*Conn,int hlid);
int matchAUTH(DGC*Conn,int hlid);
int CTX_matchPATHs(DGC*Conn,int hlid,PCStr(path));
int CTX_matchPATH1(DGC*Conn,int hlid,PCStr(path),PCStr(user));
int CTX_withSSL(DGC*Conn);
const char *CTX_dst_proto(DGC*Conn);
const char *CTX_clif_proto(DGC*Conn);
const char *CTX_CLNT_PROTO(DGC*Conn);
const char *CTX_reqstr(DGC*Conn);
const char *CTX_clif_host(DGC*Conn);
const char *CTX_clif_hostport(DGC*Conn);
int CTX_clif_port(DGC*Conn);
int CTX_vhost(DGC*Conn,PVStr(host));
const char *CTX_Rstat(DGC*Conn);
const char *topofPath1(int hlid,PCStr(hostport),PVStr(rbuff));
void dumpstacksize(PCStr(what),PCStr(fmt),...);
int myfile_path(PCStr(path),PVStr(apath));
int CTX_asproxy(DGC*Conn);
int CTX_rootdir(DGC*Conn,PVStr(rootdir));
int makePathListX(PCStr(what),PCStr(path),PCStr(opts));
int CTX_getodstAddrName(DGC*ctx,PVStr(odaddr),PVStr(odname));
int CTX_getodstAddr(DGC*ctx,PVStr(odaddr));
int mapPort1(PCStr(portspec),int port);
extern const char *ORIGDST_HOST;
int pilsner(DGC*ctx,const char *src,char *dst,int dsz);

const char _OPT_NVSERV[] = "nvserv";
const char *OPT_NVSERV   = _OPT_NVSERV;
const char _OPT_AVSERV[] = "avserv";
const char *OPT_AVSERV   = _OPT_AVSERV;
const char _OPT_RSERV[]  = "rserv";
const char *OPT_RSERV    = _OPT_RSERV;

#ifndef NULL
#define NULL 0L
#endif

#ifndef FILE
#define FILE void
#endif
#include "log.h"
#define debug	((LOG_type&L_MOUNT)==0)?0:putLog0

#ifndef MTAB_SIZE
#define MTAB_SIZE	256
#endif

#ifdef DONT_SORT_MTAB
#define DO_MTAB_SORT 0
#else
#define DO_MTAB_SORT 1
#endif

#define ASIS		"="

#define C_CLHOST	       0x1
#define C_CLFROM	       0x2
#define C_CLVIA		       0x4
#define C_CLPATH	       0x8
#define C_CLAUTH	      0x10
#define C_CLCONDS	      0x1F
#define C_METHOD	      0x20
#define C_WITHQUERY	      0x40
#define C_ASPROXY	      0x80
#define C_DIRECTION	     0x100
#define C_DSTPROTO	     0x200
#define C_QHOST		     0x400 /* destination host in the request URL */
#define C_RHOST		     0x800 /* destination host in the response */
#define C_DSTHOST	(C_QHOST|C_RHOST)
#define C_DEFAULT	    0x1000 /* default mount derived from SERVER param.*/
#define C_VHOST		    0x2000
#define C_REQMATCH	    0x4000 /* mathing by the contents of request */
#define C_NOCASE	    0x8000 /* ignore upper/lower case in matching */
#define C_FILEIS	   0x10000 /* fileis[:reg,dir] */
#define C_WITH_SSL	   0x20000
#define C_UDST		0x00400000 /* destination host in the request URL */
#define C_ALL		  0x43FFFF
/*
#define C_ALL		   0x3FFFF
*/

#define U_MOUNT		0x80000000
#define U_MOVED_TO	0x40000000
#define U_USE_PROXY	0x20000000
#define U_RECURSIVE	0x10000000
#define U_DISPPORT	0x08000000
#define U_PORTMAP	0x04000000
#define U_RESOLV	0x02000000
#define U_MYFILE	0x01000000
#define U_MYBASE	0x00800000
/*
#define U_REQDUMP	0x00400000
*/
#define U_AGAIN		0x00200000
#define U_PRIORITY	0x00100000
/*
#define U_IF_RCODE	0x00080000
*/
#define U_WHERE		0x00080000 /* rewriting rule for Referer only */
#define U_ON_ERROR	0x00040000
#define U_ALL		0xFFFC0000

#define VSERV_NVSERV	0x1 /* "nvserv=host" the server does virtual hosting */
#define VSERV_RSERV	0x2 /* "nvserv" guessed with "rserv=host" */
#define VSERV_AUTO	0x4 /* "nvserv" guessed */
#define VSERV_BYNAME	0x7 /* do textual hostname matching only */
#define VSERV_BYANY	0x8 /* "avserv" to negate "nvserv" */
#define VSERV_AVSERV	0x8 /* "avserv=host" */
#define VSERV_THRU	0x10 /* "nvserv=-thru" */
#define VSERV_ORIGDST	0x20 /* proto://odst.- */
#define VHOST_BYNAME	0x1 /* "nvhost=hostList" */
#define VHOST_ORIGDST	0x2 /* "odst=hostList" */
#define VHOST_AVHOST	0x4 /* "avhost=hostList" */
#define VHOST_TLSSNI	0x8 /* "sni=hostList" */

typedef struct {
  const	char	*u_src;
	int	 u_fullurl;
	int	 u_isurn;
	int	 u_remain;
	int	 u_uvfmt;
  const char	*u_format;
	int	 u_format_toEOL; /* matching to the End Of Line */
  const char	*u_rformat; /* reversed format for Dst match & Src gen. */
  const	char	*u_prefix;
	int	 u_subst;	/* with "#{src:fmt}" format specifiers */
	int	 u_emptysite;
	int	 u_path2site;	/* "/path/* scheme://*"	*/
	int	 u_any;		/* "/path/* *"		*/

  const	char	*u_proto;
  const	char	*u_userpass;
  const	char	*u_user;
  const	char	*u_pass;

/* caching and matching of host/addr should be done in hostlist.c */
	int	 u_hostList;
  const	char	*u_hostn;
  const	char	*u_hosta;
	int	 u_iport;
	int	 u_stdport;
  const	char	*u_portmap;
	int	 u_iport_mapped;

  const	char	*u_path;
	int	 u_plen;
  const	char	*u_query;
	int	 u_qlen;
	int	 u_asis;
	int	 u_proto_ASIS;
	int	 u_host_ASIS;
	int	 u_port_ASIS;
	int	 u_dhost; /* dynamically assigned host:port */
	int	 u_vserv;
  const char	*u_genvhost;
} Url;

#define DH_VHOST	0x01
#define DH_VPORT	0x02
#define DH_VHOSTPORT	0x03
#define DH_IHOST	0x04
#define DH_IPORT	0x08
#define DH_IHOSTPORT	0x0C
#define DH_PHOST	0x10 /* making hostname from URL-path */

typedef struct {
	int	c_direction;
	int	c_type;
	union {
  const	char   *c_STR;
	int	c_INT;
	void   *c_REX;
	} c_val;
} Cond1;
#define c_str	c_val.c_STR
#define c_int	c_val.c_INT
#define c_rex	c_val.c_REX

typedef struct {
	int	 u_serno;
	int	 u_compiled;
	int	 u_disabled;
	int	 u_flags;
	double	 u_priority;
	int	 u_dirmatch;

	int	 u_conds;
	int	 u_conds_neg; /* negated with "!" prefix */
	int	 u_conds_value;
  const	char	*u_conds_param;
	char	 u_conds_param_md5[16];

	Cond1	 u_condList[21]; /**/
	Url	 Src;
	Url	 Dst;
	int	 u_xcond;
	int	 u_timeout;
} Mtab;
#define DIRMATCH	2 /* redirect "/p" by MOUNT="/p/* http://s/q/*" */

#define	L_VIA		1
#define L_PATH		2
#define L_CLIF		3
#define L_FROM		4
#define L_AUTH		12
#define L_UDST		15
#define L_DST		5
#define L_VHOST		6
#define viaList		u_condList[L_VIA].c_int
#define pathList	u_condList[L_PATH].c_int
#define clifList	u_condList[L_CLIF].c_int
#define D_clifList	u_condList[L_CLIF].c_direction
#define fromList	u_condList[L_FROM].c_int
#define authList	u_condList[L_AUTH].c_int
#define udstList	u_condList[L_UDST].c_int
#define dstList		u_condList[L_DST].c_int
#define vhostList	u_condList[L_VHOST].c_int
#define D_vhostList	u_condList[L_VHOST].c_direction

#define R_REQMATCH	7

#define S_OPTIONS	8
#define S_USEPROXY	9
#define S_METHOD	10
#define S_DSTPROTO	11
/*
#define S_FTOCL		12
*/
#define S_WHOLE		13
#define S_MYBASE	14
/*
#define S_REQDUMP	15
*/

#define u_reqpat	u_condList[R_REQMATCH].c_rex
#define u_opts		u_condList[S_OPTIONS].c_str
#define u_useproxy	u_condList[S_USEPROXY].c_str
#define u_method	u_condList[S_METHOD].c_str
#define u_D_method	u_condList[S_METHOD].c_direction
#define u_dstproto	u_condList[S_DSTPROTO].c_str
/*
#define u_ftocl		u_condList[S_FTOCL].c_str
*/
#define u_whole		u_condList[S_WHOLE].c_str
#define u_mybase	u_condList[S_MYBASE].c_str

#define S_ON_ERROR	16
#define u_onerror	u_condList[S_ON_ERROR].c_str

/* the order in enumlist[] = {DIRECTION,MOVED_TO,WITH_SSL,WHERE} */
#define ENUMBASE	17
#define N_DIRECTION	17
#define u_direction	u_condList[N_DIRECTION].c_int

#define N_MOVED_TO	18
#define u_moved		u_condList[N_MOVED_TO].c_int

#define N_WITH_SSL	19
#define c_withssl	u_condList[N_WITH_SSL].c_int

#define N_WHERE		20
#define u_where		u_condList[N_WHERE].c_int


typedef struct {
	int	 me_do_sort;
	Mtab	*me_mtab[MTAB_SIZE]; /**/
	int	 me_mtabN;
	int	 me_init_from;
	int	 me_last_hit;
	int	 me_last_forw;
	MStr(	 me_myhost,MaxHostNameLen); /* myself(vhost) of the last forward MOUNT */
	int	 me_myport;
} MountEnv;
static MountEnv *mountEnv;
#define mount mountEnv[0]
void minit_mount()
{
	if( mountEnv == 0 ){
		mountEnv = NewStruct(MountEnv);
		mount.me_do_sort = DO_MTAB_SORT; 
		mount.me_last_forw = -1;
	}
}

#define mtab		mount.me_mtab
#define mtabN		mount.me_mtabN
#define do_MTAB_SORT	mount.me_do_sort
#define init_from	mount.me_init_from
#define last_hit	mount.me_last_hit
#define last_forw	mount.me_last_forw
#define my_h		mount.me_myhost
/**/
#define my_p		mount.me_myport

void clear_mtab(){
	mtabN = 0;
	init_from = 0;
	last_hit = 0;
	if( mtab[0] ){
		mtab[0] = 0;
	}
}

#define D_FORWONLY	1 /* fo: left to right only */
#define D_BACKONLY	2 /* bo: right to left only */
#define D_BACKIFFORW	3 /* bif: right to left if left to right */
#define V_DIRECTION	"fo,bo,bif"
static int I_DIRECTION[] = {D_FORWONLY,D_BACKONLY,D_BACKIFFORW};

#define W_ANY		0xFF /* URLs anywhere including Referer */
#define W_REQUEST	0x0F
#define W_REQURL	0x01
#define W_REFERER	0x02 /* applied to Referer: only */
#define W_REQVIA	0x04
#define W_COOKIE	0x08
#define W_RESPONSE	0xF0
#define W_LOCATION	0x10
#define V_WHERE		",any,req,ref,via,coo,res,loc"
static int I_WHERE[] = {W_REFERER,W_ANY,W_REQUEST,
			W_REFERER,W_REQVIA,W_COOKIE,W_RESPONSE,W_LOCATION};

#define V_MOVED_TO	",300,301,302,303"
static int I_MOVED_TO[] = {302,300,301,302,303};

#define S_WITHCL	1
#define S_WITHSV	2
#define S_WITHOUTCL	4
#define S_WITHOUTSV	8
#define V_WITH_SSL	",cl,sv,nocl,nosv"
static int I_WITH_SSL[] = {S_WITHCL,S_WITHCL,S_WITHSV,S_WITHOUTCL,S_WITHOUTSV};

static struct enumlist {
  const	char	*e_list;
	int	*e_value;
} enumlist[] = {
	{V_DIRECTION,	I_DIRECTION},
	{V_MOVED_TO,	I_MOVED_TO},
	{V_WITH_SSL,	I_WITH_SSL},
	{V_WHERE,	I_WHERE},
};
static int enumopt(int lidx,PCStr(name),PCStr(val))
{	const char *enums;
	int vidx,ival;
	struct enumlist *ep;

	ep = &enumlist[lidx-ENUMBASE];
	enums = ep->e_list;
	vidx = isinList(enums,val);
	if( 0 < vidx ){
		if( ep->e_value )
			ival = ep->e_value[vidx-1];
		else	ival = vidx;
		return ival;
	}
	sv1log("ERROR: %s='%s' ? must be one of {%s}\n",name,val,enums);
	return 0;
}

#define CFO	1	/* "-f.condition" applied to forwarding request */
#define CBO	2	/* "-b.condition" applied to backwarded response */
#define CFB	3	/* "condition" applied to both direction (default) */

static struct {
	int	 o_direction; /* forced direction overriding -f,-b context */
  const	char	*o_name;
	int	 o_flags;
	int	 o_value;
	int	 o_listx;
	char	 o_enum;
	int	 o_rex;
} mount_opts[] = {
	{0,  "default",	C_DEFAULT},
	{0,  "pri",	U_PRIORITY},
	{0,  "dstproto",C_DSTPROTO,	S_DSTPROTO	},
	{0,  "dst",	C_DSTHOST,	0,L_DST		},
	{0,  "odst",	C_DSTHOST,	0,L_DST		}, /* SO_ORIGINAL_DST */
	{CFO,"udst",	C_UDST,		0,L_UDST	},
	{0,  "qhost",	C_QHOST,	0,L_DST		},
	{0,  "rhost",	C_RHOST,	0,L_DST		},
	{CFO,"vhost",	C_VHOST,	0,L_VHOST	},
	{CFO,"avhost",	C_VHOST,	0,L_VHOST	},
	{CFO,"nvhost",	C_VHOST,	0,L_VHOST	},
	{CFO,"sni",	C_VHOST,	0,L_VHOST	},
	{0,  "from",	C_CLFROM,	0,L_FROM	},
	{0,  "auth",	C_CLAUTH,	0,L_AUTH	},
	{0,  "host",	C_CLHOST,	0,L_CLIF	},
	{0,  "path",	C_CLPATH,	0,L_PATH	},
	{0,  "src",	C_CLVIA,	0,L_VIA		},
	{0,  "via",	C_CLVIA,	0,L_VIA		},
	{0,  "method",	C_METHOD,	S_METHOD	},
	{0,  "direction",C_DIRECTION,	0,0,N_DIRECTION	},
	{0,  "asproxy",	C_ASPROXY,			},
	{0,  "withquery",C_WITHQUERY,			},
	{0,  "ident",	}, /* client's user name got from Ident server */
	{0,  "qmatch",	C_REQMATCH,	0,0,0,R_REQMATCH},
	{0,  "nocase",	C_NOCASE,			},

	{0,  "withssl",	C_WITH_SSL,	0,0,N_WITH_SSL	}, /* SSL */
	{0,  "srcproto",	}, /* client protocol */

	{0,  "onerror",	U_ON_ERROR,	S_ON_ERROR	}, /* onerror[={listOfErrorCodes}] */
	{0,  "moved",	U_MOVED_TO,	0,0,N_MOVED_TO	},
	{0,  "where",	U_WHERE,	0,0,N_WHERE	},
	{0,  "referer",	U_WHERE,	0,0,N_WHERE	},
	{0,  "useproxy",U_USE_PROXY,	S_USEPROXY	},
	{0,  "resolv",	U_RESOLV,			},
	{0,  "again",	U_AGAIN				},
	{0,  "mybase",	U_MYBASE,	S_MYBASE	},
/*
	{0,  "qdump",	U_REQDUMP,	S_REQDUMP	},
*/

	{0,  "htmlconv",	},/* META, SSI, DHTML */
	{0,  "uriconv",		},

/*
	{0,  "ftocl",	0,		S_FTOCL		},
*/
	{0,  "ftocl",		},
	{0,  "ftosv",		},
	{0,  "ro",		},/* read only */
	{0,  "rw",		},/* read & write (FTP) */

	{0,  "-f",		},/* conditions for forward follows */
	{0,  "-b",		},/* conditions for backward follows */

	{0,  "owner",		},/* dynamic mount from remote */

	{0,  "delay",		},/* scheduling, priority, ... */
	{0,  "forbidden",	},/* equiv. rcode=403 for HTTP */
	{0,  "unknown",		},/* equiv. rcode=404 for HTTP */

	/* file: */
	{0,  "fileis",	C_FILEIS,	0,0 /*,N_FILETYPE*/	},

	/* cache control */
	{0,  "expire",		},
	{0,  "cache",		},
	{0,  "expires",		},/* Expires: field is added into HTTP header */

	/* routing by MOUNT ? */
	{0,  "master",		},
	{0,  "proxy",		},

	/* authentication */
	{0,  "authru",		},/* through pass user@domain (for FTP,POP,NNTP) */

	/* HTTP */
	{0,  "cgi"		},
	{0,  "genvhost",	},/* generate Host: in forwarding req. */
	{0,  _OPT_AVSERV,	},/* notate a address-based virtual server */
	{0,  _OPT_NVSERV,	},/* notate a virtual hosting server */
	{0,  _OPT_RSERV,	},/* real server name or address of the target server */
	{0,  "robots",		},/* /robots.txt control */
	{0,  "charcode",	},
	{0,  "rcode",		},/* response code */
	{0,  "rhead",		},/* response header in MIME format */
	{0,  "authorizer",	},/* AUTHORIZER parameter */
	{0,  "thru",		},/* RelayTHRU */
	{0,  "sign",		},/* sign Content-MD5 with password or RSA */
	{0,  "verify",		},/* verify Content-MD5 with password or RSA */

	/* NNTP */
	{0,  "hide",		},/* NNTP group mask */
	{0,  "upact",		},
	{0,  "pathhost",	},
	0
};

static int optmatch(PCStr(opt1),PCStr(name),PVStr(value)){
	int len = strlen(name);
	if( strncasecmp(opt1,name,len) == 0 ){
		if( opt1[len] == 0 ){
			strcpy(value,"");
			return 1;
		}
		if( opt1[len] == '=' ){
			if( opt1[len+1] == '{' && strtailchr(opt1) == '}' )
				QStrncpy(value,opt1+len+2,strlen(opt1+len+2));
			else	strcpy(value,opt1+len+1);
			return 2;
		}
	}
	return 0;
}
int getOpt1(PCStr(opts),PCStr(name),PVStr(value)){
	int found;

	strcpy(value,"");
	found = scan_commaListL(opts,0,scanListCall optmatch,name,BVStr(value));
	return found;
}
int getOpt1Vserv(DGC*ctx,PCStr(opts),PVStr(vserv)){
	int found;
	if( found = getOpt1(opts,"genvhost",BVStr(vserv)) ){
	}else
	if( found = getOpt1(opts,OPT_AVSERV,BVStr(vserv)) ){
	}else
	if( found = getOpt1(opts,OPT_NVSERV,BVStr(vserv)) ){
		if( *vserv == 0 )
			found = 0;
	}
	if( found ){
		if( streq(vserv,"-thru") ){
			IStr(vhost,MaxHostNameLen);
			int vport;
			vport = CTX_vhost(ctx,AVStr(vhost));
			HostPort(AVStr(vserv),CTX_dst_proto(ctx),vhost,vport);
			/* shuold do port mapping with +:- prefix as -thru:-8000 */
		}
		return found;
	}
	return 0;
}
int getOpt1Rserv(DGC*ctx,PCStr(opts),PVStr(rserv)){
	int found;
	if( found = getOpt1(opts,OPT_RSERV,BVStr(rserv)) ){
		const char *pp;
		if( pp = strheadstrX(rserv,ORIGDST_HOST,1) ){
			IStr(odaddr,64);
			int odport;
			int mport;
			odport = CTX_getodstAddr(ctx,AVStr(odaddr));
			mport = odport;
			if( *pp == ':' ){
				mport = mapPort1(pp+1,odport);
			}
			sprintf(rserv,"%s:%d",odaddr,mport);
		}
		return found;
	}
	return 0;
}
static int replo1(PCStr(opt1),PCStr(name),PCStr(value),PVStr(nopts),const char **npp){
	refQStr(np,nopts);
	const char *vp;

	np = (char*)*npp;
	if( nopts < np )
		Rsprintf(np,",");
	vp = strheadstrX(opt1,name,1);
	if( vp && (*vp == 0 || *vp == '=') ){
		if( value ){
			if( *value )
				Rsprintf(np,"%s=%s",name,value);
			else	Rsprintf(np,"%s",name);
		}
	}else{
		Rsprintf(np,"%s",opt1);
	}
	*npp = np;
	return 0;
}
int replaceOpt1(PVStr(opts),PCStr(name),PCStr(val)){
	IStr(nopts,1024);
	const char *np = nopts;

	scan_commaListL(opts,0,scanListCall replo1,name,val,AVStr(nopts),&np);
	if( !streq(opts,nopts) ){
		strcpy(opts,nopts);
		return 1;
	}
	return 0;
}

static scanListFunc scanopt(PCStr(opt),Mtab *mt,int *directp)
{	CStr(buf,1024);
	const char *val;
	const char *nam1;
	CStr(what,32);
	int oi,flag1,val1,list1;
	char direction;
	const char *op;
	char d1;
	char d2;
	int neg;

	direction = *directp;
	d1 = 0;
	if( *opt == '-' ){
		switch( opt[1] ){
			case 'f': direction = CFO; break;
			case 'b': direction = CBO; break;
			case 'x': direction = CFB; break;
		}
		if( opt[2] == 0 ){
			*directp = direction;
			return 0;
		}
		if( op = strchr(opt,'.') ){
			op++;
			opt = op; /* 9.8.3 for -f.cond and -b.cond */
			d1 = direction;
		}else{
			sv1log("ERROR: MountOption ? %s\n",opt);
			return 0;
		}
	}
	if( neg = *opt == '!' ){
		opt++;
	}

	strcpy(buf,opt);
	if( val = strchr(buf,'=') ){
		truncVStr(val); val++;
	}else	val = "";

	for( oi = 0; nam1 = mount_opts[oi].o_name; oi++ ){
		if( !streq(buf,nam1) )
			continue;

		if( d1 == 0 )
		if( d2 = mount_opts[oi].o_direction )
			direction = d2;

		if( flag1 = (mount_opts[oi].o_flags & U_ALL) )
			mt->u_flags |= flag1;
		if( flag1 = (mount_opts[oi].o_flags & C_ALL) )
		{
			mt->u_conds |= flag1; 
			if( neg ) mt->u_conds_neg |= flag1;
		}

		if( mount_opts[oi].o_flags == U_PRIORITY ){
			sscanf(val,"%lf",&mt->u_priority);
			continue;
		}
		if( val1 = mount_opts[oi].o_value ){
			mt->u_condList[val1].c_str = StrAlloc(val);
			mt->u_condList[val1].c_direction = direction;
		}
		if( list1 = mount_opts[oi].o_listx ){
			sprintf(what,"MOUNT.%s",buf);
			if( streq(nam1,"odst") ){
				mt->Src.u_vserv |= VHOST_ORIGDST;
			}
			if( streq(nam1,"avhost") ){
				mt->Src.u_vserv |= VHOST_AVHOST;
			}
			if( streq(val,"-thru") ){
				/* "nvhost=-thru" not a real hostList */
			}else
			if( streq(nam1,"nvhost")
			){
				mt->Src.u_vserv |= VHOST_BYNAME;
			mt->u_condList[list1].c_int = makePathListX(what,StrAlloc(val),"n");
			}else
			if( streq(nam1,"sni") ){
				mt->Src.u_vserv |= VHOST_TLSSNI;
				mt->u_condList[list1].c_int =
					makePathListX(what,StrAlloc(val),"n");
			}else
			mt->u_condList[list1].c_int = makePathList(what,StrAlloc(val));
			mt->u_condList[list1].c_direction = direction;
		}
		if( val1 = mount_opts[oi].o_enum ){
			mt->u_condList[val1].c_int = enumopt(val1,nam1,val);
			mt->u_condList[val1].c_direction = direction;
		}
		if( val1 = mount_opts[oi].o_rex ){
			nonxalpha_unescape(val,AVStr(buf),1);
			val = buf;
			mt->u_condList[val1].c_rex = frex_create(val);
			mt->u_condList[val1].c_direction = direction;
		}
		break;
	}
	return 0;
}
int mount_disable_lasthit(){
	if( last_hit ){
		mtab[last_hit-1]->u_disabled = 1;
		return last_hit;
	}
	return 0;
}
void mount_enable(int last){
	if( last )
		mtab[last-1]->u_disabled = 0;
}
void mount_nodefaults(PCStr(iproto),int on)
{	int mi;
	Mtab *mt;

	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		if( mt->u_conds & C_DEFAULT ){
			mt->u_disabled = on;
		}
	}
}
Mtab *opts2mt(PCStr(opts))
{	int mi;

	for( mi = 0; mi < mtabN; mi++ ){
		if( mtab[mi]->u_opts == opts )
			return mtab[mi];
	}
	return 0;
}
const char *MountVbase(PCStr(opts))
{	Mtab *mt;

	if( opts == 0 )
		return 0;
	if( mt = opts2mt(opts) )
		return mt->Src.u_src;
	return 0;
}
const char *MountRpath(PCStr(opts))
{	Mtab *mt;

	if( mt = opts2mt(opts) )
		return mt->Dst.u_path;
	return 0;
}
int MountSerno(PCStr(opts)){
	Mtab *mt;
	if( mt = opts2mt(opts) )
		return mt->u_serno;
	return 0;
}
const char *MountSernoOpts(int serno){
	Mtab *mt;
	if( 0 < serno && serno <= mtabN ){
		mt = mtab[serno-1];
		return mt->u_opts;
	}
	return 0;
}

int nondefaultMounted()
{	int mi,mn;

	mn = 0;
	for( mi = 0; mi < mtabN; mi++ ){
		if( !mtab[mi]->Dst.u_asis ){
			if( mtab[mi]->u_conds & C_DEFAULT ){
			}else{
				mn++;
			}
		}
	}
	return mn;
}
int Mounted()
{	int mi,mn;

	mn = 0;
	for( mi = 0; mi < mtabN; mi++ )
		if( !mtab[mi]->Dst.u_asis )
		/*
		if( mtab[mi]->u_conds & C_DEFAULT ){
			can be stab for FTP ...
		}else
		*/
			mn++;
	return mn;
}
int RefererMounts(){
	int mi,mn = 0;
	for( mi = 0; mi < mtabN; mi++ )
		if( mtab[mi]->u_flags & U_WHERE )
			if( mtab[mi]->u_where & W_REFERER )
				mn++;
	return mn;
}

int MountedByAuth()
{	int mi;

	for( mi = 0; mi < mtabN; mi++ )
		if( mtab[mi]->authList )
			return 1;
	return 0;
}
int MountedConditional()
{	int mi,mn;
	Mtab *mt;

	mn = 0;
	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		if( mt->u_conds & C_CLCONDS )
			mn++;
	}
	return mn;
}
void set_MOUNT(DGC*Conn,PCStr(src),PCStr(dst),PCStr(opts));
void scan_MOUNT(DGC*Conn,PCStr(spec))
{	CStr(src,1024);
	CStr(dst,1024);
	CStr(opts,1024);
	CStr(xdst,1024);
	refQStr(op,opts);

	opts[0] = 0;
	/*
	if( Xsscanf(spec,"%s %s %s",AVStr(src),AVStr(dst),AVStr(opts)) < 2 )
	*/
	if( Xsscanf(spec,"%s %s %[^\r\n]",AVStr(src),AVStr(dst),AVStr(opts)) < 2 )
	{
		sv1log("MOUNT=\"%s\" ? (missing right hand)\n",spec);
		return;
	}
	Verbose("%s\n",spec);

	if( (op = strchrX(opts,' ',"{(",")}"))
	 || (op = strchrX(opts,'\t',"{(",")}")) ){
		setVStrEnd(op,0);
		/* ignore comment or so */
	}
	set_MOUNT(Conn,src,dst,opts);
}
const char *getMountSrcByDst(PCStr(dst))
{	Mtab *mt;
	int mi;

	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		if( streq(mt->Dst.u_src,dst) )
			return mt->Src.u_src;
	}
	return NULL;
}

static int nvserv_all;
static int nvserv_gen;
static int nvserv_alias;
static int nvserv_none;
int MOUNT_setvhosts(int none,int all,int gen,int alias){
	nvserv_none = none;
	nvserv_all = all;
	nvserv_gen = gen;
	nvserv_alias = alias;
	return 0;
}
void set_MOUNT(DGC*Conn,PCStr(src),PCStr(dst),PCStr(opts))
{	Mtab *mt;
	int mi;
	int len;
	CStr(dstbuf,1024);
	CStr(whole,1024);
	const char *dp;
	int direction;

	if( mtab[0] == NULL ){
		mtab[0] = (Mtab*)-1;

		/* These patterns should be able to be re-defined by user ... */
		/*
		set_MOUNT(Conn,"/-*",ASIS,"");
		set_MOUNT(Conn,"/=*",ASIS,"");
		if( streq(src,"/-*") && streq(dst,ASIS) && opts[0]==0 ) return;
		if( streq(src,"/=*") && streq(dst,ASIS) && opts[0]==0 ) return;
		*/
		set_MOUNT(Conn,"/-*",ASIS,"default");
		set_MOUNT(Conn,"/=*",ASIS,"default");
	}

	sprintf(whole,"%s %s %s",src,dst,opts);
	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		if( streq(mt->u_whole,whole) ){
			Verbose("IGNORE DUPLICATE MOUNT[%d] %s\n",mi,whole);
			return;
		}
	}

	if( elnumof(mtab) <= mtabN ){
		return;
	}
	mt = NewStruct(Mtab);
	if( mt == NULL )
		return;

	mtab[mtabN++] = mt;
	mt->u_whole = StrAlloc(whole);
	mt->u_serno = mtabN;
	mt->u_xcond = getCondition(Conn);

	mt->Src.u_src = StrAlloc(src);
	mt->Src.u_fullurl = isFullURL(src);
	mt->Src.u_isurn = isURN(src);
	len = strlen(src);

	if( dp = strstr(mt->Src.u_src,"*%") ){
		truncVStr(dp);
		mt->Src.u_remain = 1;
		mt->Src.u_uvfmt = 1;
		if( strtailchr(dp+1) == '$' ){
			*strtail(dp+1) = 0;
			mt->Src.u_format_toEOL = 1;
		}
		mt->Src.u_format = StrAlloc(dp+1);
	}else
	if( mt->Src.u_src[len-1] == '*' ){
		((char*)mt->Src.u_src)[len-1] = 0;
		mt->Src.u_remain = 1;
		if( 1 < len && mt->Src.u_src[len-2] == ']' ){
			if( dp = strrchr(mt->Src.u_src,'[') ){
				mt->Src.u_format = StrAlloc(dp);
				truncVStr(dp);
			}
		}
	}

	if( strncmp(dst,"///",3) == 0 ){
		sprintf(dstbuf,"%s://%s:%s/%s",ASIS,ASIS,ASIS,dst+3);
		dst = dstbuf;
	}else
	if( strncmp(dst,"//",2) == 0 ){
		sprintf(dstbuf,"%s://%s",ASIS,dst+2);
		dst = dstbuf;
	}else
	if( *dst == '/' ){
		sprintf(dstbuf,"file://%s",dst);
		dst = dstbuf;
	}
	mt->Dst.u_src = StrAlloc(dst);
	if( dp = strstr(mt->Dst.u_src,"#{") ){
		if( strchr(dp+2,'}') ){
			mt->Dst.u_subst = 1;
		}
	}
	if( dp = strstr(mt->Dst.u_src,"*%") ){
		truncVStr(dp);
		mt->Dst.u_remain = 1;
		mt->Dst.u_uvfmt = 1;
		if( strtailchr(dp+1) == '$' ){
			*strtail(dp+1) = 0;
			mt->Dst.u_format_toEOL = 1;
		}
		mt->Dst.u_format = StrAlloc(dp+1);
		if( mt->Src.u_format == NULL ){
			if( streq(mt->Src.u_src,ASIS) )
				mt->Src.u_format = mt->Dst.u_format;
			else	mt->Src.u_format = mt->Src.u_src;
		}
		uvfmtreverse(mt->Src.u_format,mt->Dst.u_format,
			&mt->Src.u_rformat,&mt->Dst.u_rformat);
	}else{
	len = strlen(dst);
	if( mt->Dst.u_src[len-1] == ']' ){
		const char *dp;
		if( dp = strrchr(mt->Dst.u_src,'[') )
		if( mt->Dst.u_src < dp && dp[-1] == '*' ){
			truncVStr(dp);
			len = strlen(mt->Dst.u_src);
			mt->Dst.u_format = StrAlloc(dp+1);
			*(char*)strchr(mt->Dst.u_format,']') = 0;
		}
	}
	if( mt->Dst.u_src[len-1] == '*' ){
		((char*)mt->Dst.u_src)[len-1] = 0;
		mt->Dst.u_remain = 1;
	}
	}

/*
	mt->u_opts = StrAlloc(opts);
*/
	mt->u_opts = stralloc(opts);

	if( !nvserv_none ){ /* substitute nvhost=-thru */
		IStr(vhost,256);
		IStr(vproto,64);
		IStr(vserv,256);
		IStr(nopts,1024);
		if( getOpt1(opts,"nvhost",AVStr(vhost)) )
		if( streq(vhost,"-thru") ){
			getOpt1(opts,OPT_NVSERV,AVStr(vserv));
			if( vserv[0] == 0 )
				getOpt1(opts,OPT_AVSERV,AVStr(vserv));
			if( vserv[0] == 0 )
				getOpt1(opts,"genvhost",AVStr(vserv));
			if( vserv[0] == 0 )
				decomp_absurl(mt->Dst.u_src,AVStr(vproto),
					AVStr(vserv),VStrNULL,0);
			strcpy(nopts,opts);
			if( replaceOpt1(AVStr(nopts),"nvhost",vserv) ){
				mt->u_opts = stralloc(nopts);
				opts = mt->u_opts;
				InitLog("replaced nvhost=-thru: %s\n",nopts);
			}
		}
	}
	direction = CFB;
	scan_commaList(opts,1,scanListCall scanopt,mt,&direction);
}
int set_MOUNT_ifndef(DGC*Conn,PCStr(src),PCStr(dst),PCStr(opts))
{	int mi;
	CStr(srcbuf,1024);
	int len,remain;

	strcpy(srcbuf,src);
	len = strlen(src);
	if( srcbuf[len-1] == '*' ){
		setVStrEnd(srcbuf,len-1);
		remain = 1;
	}else	remain = 0;

	for( mi = 0; mi < mtabN; mi++ ){
		if( strcmp(mtab[mi]->Src.u_src,srcbuf) == 0 )
		if( strcmp(mtab[mi]->u_opts,opts) == 0 )
			/* if ``cond'' are different */
			return 0;
	}
	if( *opts == 0 )
		opts = "default";
	set_MOUNT(Conn,src,dst,opts);
	return 1;
}

/*
 *  - A rule with a left hand ``Path1*'' should be after the rule with
 *    a left hand ``Path1Path2''.
 *  - In rules of the same left hand ``Path1'' with each other should be
 *    sorted (or overwritten if without any condition) in reverse order
 *    of the definition.
 *
 *  return S1_S2;  s1 should be before than s2
 *  return S2_S1;  s2 should be before than s1
 */

#define S2_S1	 1
#define S1_S2	-1

static int mtabcomp(Mtab **mt1p,Mtab **mt2p)
{	Mtab *mt1,*mt2;
	const char *s1;
	const char *s2;
	const char *fs1;
	const char *fs2;
	int r1,r2;
	int comp;

	mt1 = *mt1p; if( mt1 == NULL ) return S2_S1;
	mt2 = *mt2p; if( mt2 == NULL ) return S1_S2;

	if( mt1->u_priority < mt2->u_priority )
		return S2_S1;
	if( mt2->u_priority < mt1->u_priority )
		return S1_S2;

	s1 = mt1->Src.u_src;
	s2 = mt2->Src.u_src;
	r1 = mt1->Src.u_remain;
	r2 = mt2->Src.u_remain;

	/*if( mt1->Dst.u_asis && mt2->Dst.u_asis )*/
/*
	if( streq(s1,ASIS) && streq(s2,ASIS) )
	{
		s1 = mt1->Dst.u_src;
		s2 = mt2->Dst.u_src;
		r1 = mt1->Dst.u_remain;
		r2 = mt2->Dst.u_remain;
	}
*/

	comp = strcmp(s1,s2);

	if( comp == 0 ){
		if( r1 && !r2 ) return S2_S1;
		if( r2 && !r1 ) return S1_S2;

		/* rule with rexp-prefix first */
		if(  mt1->Src.u_format && !mt2->Src.u_format ) return S1_S2;
		if( !mt1->Src.u_format &&  mt2->Src.u_format ) return S2_S1;

		/* rule with scanf() matching pattern */
		if( (fs1 = mt1->Src.u_format) && (fs2 = mt2->Src.u_format) ){
			if( strstr(fs1,fs2) ) return S1_S2;
			if( strstr(fs2,fs1) ) return S2_S1;
		}

		/* default rule last */
		if( mt1->u_conds & C_DEFAULT ) return S2_S1;
		if( mt2->u_conds & C_DEFAULT ) return S1_S2;

		/* rule with src=xxx first */
		if( mt1->u_conds > mt2->u_conds ) return S1_S2;
		if( mt1->u_conds < mt2->u_conds ) return S2_S1;

		/* reverse entry order for overwriting */
		if( mt1->u_serno < mt2->u_serno )
			return S2_S1;
		else	return S1_S2;
	}else{	
		if( strstr(s1,s2) && r2) return S1_S2;
		if( strstr(s2,s1) && r1) return S2_S1;

		/* entry order */
		if( mt1->u_serno < mt2->u_serno )
			return S1_S2;
		else	return S2_S1;
	}
}
static void sort_mtab()
{
	Bsort((char*)mtab,mtabN,sizeof(Mtab*),(int (*)(const char*,const char*))mtabcomp);
}
static void dump_mtab()
{	int mi;
	Mtab *mt;

	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		InitLog("MOUNT[%d]%s[%d] %s%s%s %s%s%s %s\n",
			mi,
			mi != mt->u_serno-1 ? "X":"=",
			mt->u_serno-1,
			mt->Src.u_src,mt->Src.u_remain?"*":"",
			mt->Src.u_format?mt->Src.u_format:"",
			mt->Dst.u_src,mt->Dst.u_remain?"*":"",
			mt->Dst.u_format?mt->Dst.u_format:"",
			mt->u_opts);
	}
}

int backToSlash(PVStr(path)){
	refQStr(pp,path);
	int nb = 0;

	for( pp = path; *pp; pp++ ){
		if( *pp == '\\' ){
			setVStrElem(pp,0,'/');
			nb++;
		}
	}
	return nb;
}
int toMountSafePath(PVStr(path),int size){
	if( strtailchr(path) == '\\' ){
		/* file:* not to gen MovedTo for -dir.html */
		backToSlash(BVStr(path));
	}
	/*
	9.9.1: added (in 9.8.2) for Win but it disables MOUNT for CGI
	url_escapeX(path,BVStr(path),size," \t*%?#",0);
	*/
	url_escapeX(path,BVStr(path),size," \t*%#",0);
	return 0;
}

static int eqservname(Mtab *m1,Mtab *m2){
	const char *n1,*n2;
	if( n1 = m1->Dst.u_hostn ){
		if( n2 = m2->Dst.u_hostn )    if( strcaseeq(n1,n2) ) return 1;
		if( n2 = m2->Dst.u_genvhost ) if( strcaseeq(n1,n2) ) return 2;
	}
	if( n1 = m1->Dst.u_genvhost ){
		if( n2 = m2->Dst.u_hostn )    if( strcaseeq(n1,n2) ) return 3;
		if( n2 = m2->Dst.u_genvhost ) if( strcaseeq(n1,n2) ) return 4;
	}
	return 0;
}
int MOUNT_markvhosts1(int none,int all,int gen,int alias){
	int mi,mj,nvhost,mvhost,eqs;
	Mtab *mti,*mtj;

	all |= nvserv_all;
	gen |= nvserv_gen;
	alias |= nvserv_alias;
	if( all == 0 && gen == 0 && alias == 0 ){
		return 0;
	}

	mvhost = 0;
	for(mi = 0; mi < mtabN; mi++ ){
		mti = mtab[mi];
		if( gen && mti->Dst.u_genvhost ){
			if( mti->Dst.u_vserv & (VSERV_BYNAME|VSERV_BYANY) ){
			}else{
				mti->Dst.u_vserv |= VSERV_AUTO;
				InitLog("[%d] vserv-g %s %s\n",
					mi,mti->Dst.u_hostn,mti->u_opts);
			}
		}
		if( mti->Dst.u_hosta
		 && streq(mti->Dst.u_hostn,mti->Dst.u_hosta)
		 && mti->Dst.u_genvhost == 0
		){
			/* MOUNT to a server by IP address */
			continue;
		}

		if( alias ){
			nvhost = 0;
			for( mj = 0; mj < mtabN; mj++ ){
				if( mj == mi )
					continue;
				mtj = mtab[mj];
				if( mtj->Dst.u_vserv & (VSERV_BYNAME|VSERV_BYANY) ){
					continue;
				}
				if( mtj->Dst.u_hosta )
				if( streq(mti->Dst.u_hosta,mtj->Dst.u_hosta) ){
					InitLog("[%d][%d] vserv-a %s\n",
						mi,mj,mtj->Dst.u_hostn);
					mtj->Dst.u_vserv |= VSERV_AUTO;
					nvhost++;
				}
			}
			if( mti->Dst.u_vserv & VSERV_BYANY ){
			}else
			if( nvhost ){
				mvhost += nvhost;
				InitLog("[%d][%d] vserv-A %s %s\n",
					mi,mi,mti->Dst.u_hostn,mti->u_opts);
				mti->Dst.u_vserv |= VSERV_AUTO;
			}
		}
		if( mti->Dst.u_vserv & VSERV_BYNAME ){
			/* copy the flag to MOUNTs with the same server name */
			for( mj = 0; mj < mtabN; mj++ ){
				if( mj == mi )
					continue;
				mtj = mtab[mj];
				if( mtj->Dst.u_vserv & (VSERV_BYNAME|VSERV_BYANY) ){
					continue;
				}
				if( eqs = eqservname(mti,mtj) ){
					InitLog("[%d][%d] vserv-c %s (%d)\n",
						mi,mj,mtj->Dst.u_hostn,eqs);
					mtj->Dst.u_vserv |= VSERV_AUTO;
					nvhost++;
				}
			}
		}
	}
	return mvhost;
}
int MOUNT_markvhosts(int none,int all,int gen,int alias){
	int mvhost;
	int mi;
	Mtab *mti;
	mvhost = MOUNT_markvhosts1(none,all,gen,alias);
	for(mi = 0; mi < mtabN; mi++ ){
		mti = mtab[mi];
		if( mti->Dst.u_vserv & VSERV_BYANY ){
			mti->Dst.u_vserv &= ~VSERV_BYNAME;
		}
		if( mti->Dst.u_vserv & VSERV_BYNAME ){
			InitLog("##[%d] vserv %s %s\n",mi,mti->Dst.u_src,mti->u_opts);
		}
	}
	return mvhost;
}
int MOUNT_nvserv(PCStr(opts)){
	Mtab *mt;

	if( opts == 0 ){
		/* to be the default value by nvserv_all ? */
		/* only when acting as a proxy ? */
		return 0;
	}
	if( mt = opts2mt(opts) ){
		if( mt->Dst.u_vserv & VSERV_BYNAME ){
			return 1;
		}
	}
	return 0;
}

void init_mtab(){
	int mi;
	const char *ssrc;
	const char *dsrc;
	CStr(proto,64);
	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	CStr(port,256);
	CStr(path,1024);
	CStr(prefix,64);
	int plen;
	const char *addr;
	const char *dpath;
	CStr(login,MaxHostNameLen);
	const char *dp;
	CStr(userpass,256);
	CStr(user,64);
	CStr(pass,64);
	CStr(loginpath,1024);
	int iport;
	Mtab *mt;
	const char *opts;
	CStr(dproto,256);
	const char *upath;
	const char *query;
	int dhost;

	if( mtabN <= init_from )
		return;
	mi = init_from;
	init_from = mtabN;

	if( do_MTAB_SORT )
		sort_mtab();
	dump_mtab();

	for(mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];
		if( mt->u_compiled )
			continue;
		mt->u_compiled = 1;

		ssrc = mt->Src.u_src;
		if( streq(ssrc,ASIS) )
			mt->Src.u_asis = 1;
		else
		if( isFullURL(ssrc) ){
			CStr(norm_url,1024);
			CStr(hostport,1024);
			int nc;
			nc =
			decomp_absurl(ssrc,AVStr(proto),AVStr(login),AVStr(path),sizeof(path));
			mt->Src.u_proto = StrAlloc(proto);
			if( login[0] ){
			iport = scan_hostport(proto,login,AVStr(host));
			sprintf(hostport,"%s:%d",host,iport);
			/*
			mt->Src.u_hostList = makePathList("MOUNT.vhost",
				StrAlloc(hostport));
			*/
			mt->Src.u_path = StrAlloc(path);
			mt->Src.u_plen = strlen(path);

			if( nc <= 2 && path[0] == 0 && mt->Src.u_remain ){
				/* rURL = http://host* */
				InitLog("## MOUNT vURL* [%s*] rem=%d nc=%d\n",
					ssrc,mt->Src.u_remain,nc);
			}else{
			mt->Src.u_hostList = makePathList("MOUNT.vhost",
				StrAlloc(hostport));

			if( IsResolvable(host) ){
				sethostcache(host,1);
				sethostcache_predef(host,NULL,0,0);
			}
			}
			InitLog("## MOUNT FULL-URL-SRC [%s]://[%s:%d]/[%s]\n",
				proto,host,iport,path);
			/* normalize URL string ... */
			}
		}

		proto[0] = path[0] = 0;
		dpath = path;
		dsrc = mt->Dst.u_src;

		dproto[0] = 0;
		scan_URI_scheme(dsrc,AVStr(dproto),sizeof(dproto));

		if( mt->u_opts )
			opts = mt->u_opts;
		else	opts = "";

		if( streq(dsrc,ASIS) ){
			mt->Dst.u_asis = 1;
			continue;
		}else
		if( dsrc[0] == 0 && mt->Dst.u_remain ){
			mt->Dst.u_any = 1;
			continue;
		}else
		if( strneq(dsrc,"vurl:",5) ){
			strcpy(proto,dproto);
			truncVStr(login);
			ovstrcpy(path,dsrc+5);
			dpath = path;
			mt->u_flags |= U_RECURSIVE;
		}else
		if( strneq(dsrc,"file::",6) ){
			strcpy(proto,dproto);
			login[0] = 0;
			ovstrcpy(path,dsrc+5);
			dpath = path;
			mt->u_flags |= U_MYFILE;
		}else
		if( plen = isURN(dsrc) ){
			strcpy(proto,dproto);
			login[0] = 0;
			strcpy(path,dsrc+strlen(proto)+1);
			dpath = path;
		}else
		if( mt->Dst.u_remain && streq(dsrc+strlen(dproto),"://") ){
			mt->Dst.u_path2site = 1;
			strcpy(proto,dproto);
			login[0] = 0;
			dpath = "";
		}else
		if( localPathProto(dproto) ){
			if( upath = file_hostpath(dsrc,AVStr(proto),AVStr(login)) ){
				if( login[0] == 0 )
					strcpy(login,"localhost");
				if( upath[0] == '/' )
					strcpy(path,upath+1);
				else
				if( !isFullpath(upath) ){
					CStr(xupath,1024);
					const char *query;
					if( query = strchr(upath,'?') )
						truncVStr(query);
					/*
					if( upath[0] == 0 ){
						CTX_rootdir(NULL,AVStr(path));
						strcat(path,"/");
					}else
					*/
					if( fullpathDATA(upath,"r",AVStr(xupath)) ){
						strcpy(path,xupath);
					}else{
						IGNRETS getcwd(path,sizeof(path));
					chdir_cwd(AVStr(path),upath,0);
					strcat(path,"/");
					}
					if( query ){
						*(char*)query = '?';
						strcat(path,query);
					}
					sv1log("MOUNT relative file:%s -> %s\n",
						upath,path);
					if( *path == '/' )
						ovstrcpy(path,path+1);
				}
				else	strcpy(path,upath);
				toMountSafePath(AVStr(path),sizeof(path));
				dpath = path;
			}
		}else
		if( Xsscanf(dsrc,"%[^:]://%s",AVStr(proto),AVStr(loginpath)) == 2 ){
			if( loginpath[0] == '/' || loginpath[0] == '?' ){
				mt->Dst.u_emptysite = 1;
				login[0] = 0;
				strcpy(path,loginpath+1);
			}else{
				Xsscanf(loginpath,"%[^/?]%s",AVStr(login),AVStr(path));
				if( path[0] == '/' )
					dpath = path+1;
				else	dpath = path;
			}
		}else{
			sv1log("ERROR MOUNT=\"%s %s\", right hand must be full-URL\n",
				mt->Src.u_src,mt->Dst.u_src);
			mt->u_disabled = 1;
			continue;
		}

		decomp_URL_siteX(login,AVStr(userpass),AVStr(user),AVStr(pass),AVStr(hostport),AVStr(host),AVStr(port));
		mt->Dst.u_userpass = StrAlloc(userpass);
		mt->Dst.u_user = StrAlloc(user);
		mt->Dst.u_pass = StrAlloc(pass);

		if( !nvserv_none ){
			IStr(vhost,256);
			if( getOpt1(opts,"genvhost",AVStr(vhost)) ){
				mt->Dst.u_genvhost = StrAlloc(vhost);
				if( streq(vhost,"-thru") ){
					mt->Dst.u_vserv |= VSERV_THRU;
				}
			}
			if( getOpt1(opts,OPT_NVSERV,AVStr(vhost)) ){
			    mt->Dst.u_vserv |= VSERV_NVSERV;
			    if( vhost[0] ){
				mt->Dst.u_genvhost = StrAlloc(vhost);
				if( streq(vhost,"-thru") ){
					mt->Dst.u_vserv |= VSERV_THRU;
				}
			    }
			}
		}
		if( 1 ){
			IStr(vhost,256);
			IStr(rserv,256);
			if( getOpt1(opts,OPT_AVSERV,AVStr(vhost)) ){
			    mt->Dst.u_vserv |= VSERV_BYANY;
			    if( vhost[0] ){
				mt->Dst.u_genvhost = StrAlloc(vhost);
				if( streq(vhost,"-thru") ){
					mt->Dst.u_vserv |= VSERV_THRU;
				}
			    }
			}
			if( getOpt1(opts,OPT_RSERV,AVStr(rserv)) ){
			    mt->Dst.u_vserv |= VSERV_RSERV;
			}
		}
		if( streq(host,ORIGDST_HOST) ){
			mt->Dst.u_vserv |= VSERV_ORIGDST;
			mt->Dst.u_vserv |= VSERV_RSERV;
		}

		url_rmprefix(AVStr(proto),AVStr(prefix));
		mt->Dst.u_prefix = StrAlloc(prefix);

		dhost = 0;
		if( streq(host,"-") )	dhost |= DH_VHOSTPORT; else
		if( streq(host,ASIS) )	dhost |= DH_VHOST; else
		if( streq(host,"-P") || streq(host,".i") )
					dhost |= DH_IHOST;
		if( streq(port,ASIS) )	dhost |= DH_VPORT; else
		if( streq(port,"-P") || streq(host,".i") )
					dhost |= DH_IPORT;
		if( dhost == 0 ){
			if( mt->Dst.u_plen == 0 && mt->Dst.u_remain )
			if( strtailchr(host) == '.' )
				/* incomplete hostname to be completed */
			{
				dhost = DH_PHOST;
			}
		}
		mt->Dst.u_dhost = dhost;

		if( login[0] ){
			iport = scan_hostport(proto,hostport,AVStr(host));
			if( mt->Dst.u_vserv & VSERV_RSERV ){
				addr = "";
			}else
			if( mt->Dst.u_dhost ){
				addr = "";
			}else
			if( host[0] == '-' && isMYSELF(host) ){
				addr = "";
			}else
			if( host[0] == '-' && host[1] != 0 ){
				/* the destination host is a virtual host,
				 * so disable matching by IP-address
				 */
				ovstrcpy(host,host+1);
				addr = "";
			}else
			if( addr = gethostaddr(host) )
				mt->Dst.u_hosta = StrAlloc(addr);
			else	addr = "";
			Verbose("MOUNT HOST %s=%s\n",host,addr);
			/* multiple address should be cared ... */
		}else{
			host[0] = 0;
			iport = 0;
			addr = "";
		}

		if( mt->Dst.u_vserv & VSERV_RSERV ){
			/* maybe "hostport" is not a real hostport.
			 * "u_hostList" is used just for full-url MOUNT
			 * (and will not used together with vserv/rserv?)
			 */
		}else
		if( mt->Dst.u_dhost == 0 )
		mt->Dst.u_hostList = makePathList("MOUNT.rhost",
			StrAlloc(hostport));

		mt->Dst.u_proto = StrAlloc(proto);
		mt->Dst.u_hostn = StrAlloc(host);
		mt->Dst.u_stdport = serviceport(proto);
		mt->Dst.u_iport = iport;

		if( streq(proto,ASIS) ) mt->Dst.u_proto_ASIS = 1;
		if( streq(host,ASIS) ) mt->Dst.u_host_ASIS = 1;
		if( streq(port,ASIS) ) mt->Dst.u_port_ASIS = 1;

		if( dp = strchr(hostport,':') ){
			mt->u_flags |= U_DISPPORT;
			if( dp[1] == '+' || dp[1] == '-' ){
				mt->u_flags |= U_PORTMAP;
				mt->Dst.u_portmap = StrAlloc(dp+1);
			}
		}

		if( query = strchr(dpath,'?') ){
			truncVStr(query); query++;
			mt->Dst.u_query = StrAlloc(query);
			mt->Dst.u_qlen = strlen(query);
		}
		mt->Dst.u_path = StrAlloc(dpath);
		mt->Dst.u_plen = strlen(dpath);

		/*
		 * restrict DIRMATCH only to MOUNT="Rurl/* Lurl/*" pattern
		 */
		if( mt->Src.u_remain && strtailchr(mt->Src.u_src)=='/' )
		if( mt->Dst.u_remain && strtailchr(mt->Dst.u_src)=='/' )
		if( (mt->u_flags & U_WHERE) && (mt->u_where & W_REQURL) == 0 ){
			/* not to be used for redirection of request-URL */
		}else
		{
			mt->u_dirmatch = 1;
			mt->u_moved = 302;
		}

		if( login[0] )
			Verbose("[%d] MOUNT=%s %s%s://%s[%s]:%d%s %s\n",
				mi,mt->Src.u_src,prefix,proto,
				host,addr,iport,path,opts);
		else	Verbose("[%d] MOUNT=%s %s%s:%s %s\n",
				mi,mt->Src.u_src,prefix,proto,path,opts);


		if( mt->Dst.u_dhost == 0 )
		if( mt->Dst.u_vserv & VSERV_RSERV ){
			/* maybe "host" is not a real hostname */
		}else
		if( IsResolvable(host) ){
			sethostcache(host,1);
			sethostcache_predef(host,NULL,0,0);
			/* preload cache from all of RESOLV=dns,nis,file ... */
		}
	}
	MOUNT_markvhosts(0,0,0,0);
}
static char *rewrite_path(DGC*ctx,PVStr(out),PCStr(fmt),PCStr(in))
{	const char *fp;
	char fc;
	CStr(urlbuf,4096);
	const char *uv[256]; /**/
	int un,u1,u2,ui,tailis;
	refQStr(op,out); /**/
	const char *ox;
	int omax;

	omax = strlen(in) + 64;
	if( omax < 256 )
		omax = 256;
	ox = out + omax;
	lineScan(in,urlbuf);
	tailis = strtailchr(urlbuf) == '/';
	un = stoV(urlbuf,256,uv,'/');

	for( fp = fmt; fc = *fp; fp++ ){
		if( ox <= op )
			break;

		if( fc != '%' ){
			setVStrPtrInc(op,fc);
			continue;
		}
		fc = *++fp;
		if( fc == 0 )
			break;

		if( '0' <= fc && fc <= '9' ){
			u1 = fc - '0';
			u2 = u1;
			if( fp[1] == '-' ){
				fp++;
				u2 = un;
			}
			ui = u1;
			if( ui < un ) do {
				if( u1 < ui )
					setVStrPtrInc(op,'/');
				strcpy(op,uv[ui]);
				op += strlen(op);
			} while ( ++ui < u2 );
			if( u2 == un && tailis )
				setVStrPtrInc(op,'/');
		}
	}
	setVStrEnd(op,0);
	return (char*)op;
}

typedef struct {
	DGC	*mo_ctx;
	int	 mo_qtype;
	int	 mo_rtype;
	int	 mo_reclev;
     const char *mo_method;
} MountArgs;
/*
static int setupMOA(MountArgs *moa,DGC *ctx,int qtype){
*/
static int setupMOA(MountArgs *moa,DGC *ctx,int qtype,PCStr(method)){
	bzero(moa,sizeof(MountArgs));
	moa->mo_ctx = ctx;
	moa->mo_qtype = qtype;
	moa->mo_method = method;
	return 0;
}

/*
static int dstNoMatch(DGC*ctx,Mtab *mt,PCStr(clif),PCStr(srcurl))
*/
/*
static int dstNoMatch(DGC*ctx,Mtab *mt,int dstL,PCStr(clif),PCStr(srcurl))
*/
static int dstNoMatch(MountArgs *moa,Mtab *mt,int dstL,PCStr(clif),PCStr(srcurl))
{	CStr(site,MaxHostNameLen);
	CStr(proto,256);
	CStr(host,MaxHostNameLen);
	CStr(port,256);
	int porti;
	int got;
	DGC *ctx = moa->mo_ctx;

	/* odst=hostList */
	if( mt->Src.u_vserv & VHOST_ORIGDST ){
		IStr(odaddr,64);
		int odport;
		odport = CTX_getodstAddr(ctx,AVStr(odaddr));
		if( 0 < odport ){
			if( matchPath1(mt->dstList,"-",odaddr,odport) )
				return 0;
		}
		return 1;
	}

	/* except for MOUNTs which extract destination server information
	 * from vURL dynamically, the destination is in rURL statically.
	 */
	if( !mt->Dst.u_path2site && *srcurl == '/' ){
		if( mt->Dst.u_hostn )
		if( mt->Dst.u_hostn[0] )
		if( matchPath1(mt->dstList,"-",mt->Dst.u_hostn,mt->Dst.u_iport))
			return 0;

		/* match dst=host with virtual host name in "Host:host" */
		if( clif != NULL ){
			wordScan(CTX_clif_proto(ctx),proto);
			decomp_URL_site(clif,AVStr(host),AVStr(port));
			got = 1;
			goto DOMATCH;
		}
		return 1;
	}

	if( mt->Dst.u_path2site ){
		got = 0;
		scan_URI_site(srcurl+strlen(mt->Src.u_src),AVStr(site),sizeof(site));
		if( *site ){
			got = 1;
			strcpy(proto,mt->Dst.u_proto);
			decomp_URL_site(site,AVStr(host),AVStr(port));
		}
	}else{
		got = scan_protositeport(srcurl,AVStr(proto),AVStr(host),AVStr(port));
		if( got == 0 )
		if( moa->mo_method && strcaseeq(moa->mo_method,"CONNECT") ){
			clearVStr(port);
			decomp_URL_site(srcurl,AVStr(host),AVStr(port));
			if( 0 < atoi(port) ){
				got = 2;
			}
		}
	}

DOMATCH:
	if( got ){
		if( *port == 0 )
			porti = serviceport(proto);
		else	porti = atoi(port);
		/*
		if( !matchPath1(mt->dstList,"-",host,porti) )
		*/
		if( !matchPath1(dstL,"-",host,porti) )
			return 1;
	}
	return 0;
}
static int evalCond1X(MountArgs *moa,int direction,Mtab *mt,PCStr(clif),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport);
static int evalCond1(DGC*ctx,int direction,Mtab *mt,PCStr(clif),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport)
{
	MountArgs moa;
	setupMOA(&moa,ctx,0,method);

	return evalCond1X(&moa,direction,mt,clif,method,srcurl,rhost,rport);
}
static int evalCond1X(MountArgs *moa,int direction,Mtab *mt,PCStr(clif),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport)
{	CStr(host,MaxHostNameLen);
	int port;
	DGC *ctx = moa->mo_ctx;

	if( mt->fromList && !matchFROM(ctx,mt->fromList) )
		return 0;

	if( mt->authList && !matchAUTH(ctx,mt->authList) )
		return 0;

	if( direction & mt->D_vhostList )
	if( mt->vhostList && clif != NULL ){
		if( mt->Src.u_vserv & VHOST_TLSSNI ){
			const char *tlssni();
			clif = tlssni();
		}else
		if( (mt->Src.u_vserv & VHOST_AVHOST) /* avhost=host */
		 && clif[0] == '-'
		){
			/* in matching HTTP request by vmount*(),
			 * clif is set to Host:host prefixed with "-"
			 * but it must be matched without "-" for "avhost"
			 */
			clif++;
		}else
		if( mt->D_vhostList == CFB /* -x.nvhost */
		 && (mt->Src.u_vserv & VHOST_BYNAME)
		 && direction == CBO /* called by mount_url_from() */
		 && clif[0] != '-'
		){
			/* in matching HTTP response by mount_url_from(),
			 * clif is set to Host:host without "-"
			 * in setReferer()
			 */
		}else
		if( clif[0] != '-' )
			return 0;
		port = scan_Hostport1(clif,host);
		if( !matchPath1(mt->vhostList,"-",host,port) )
			return 0;
	}

	if( direction & mt->D_clifList )
	if( mt->clifList && clif != NULL ){
		port = scan_Hostport1(clif,host);
		if( !matchPath1(mt->clifList,"-",host,port) )
			return 0;
	}

	if( mt->udstList && srcurl != NULL ){
		if( (mt->u_conds & C_UDST) == 0 )
			return 0;
		if( dstNoMatch(moa,mt,mt->udstList,clif,srcurl) )
			return 0;
	}
	if( mt->dstList && srcurl != NULL ){
		if( (mt->u_conds & C_QHOST) == 0 )
			return 0;
		/*
		if( dstNoMatch(ctx,mt,clif,srcurl) )
		*/
		if( (moa->mo_qtype & U_WHERE) && (moa->mo_rtype & W_REFERER) ){
			/* udst should be used to match with URL in full-url */
			if( dstNoMatch(moa,mt,mt->dstList,clif,"/") )
				return 0;
		}else
		if( dstNoMatch(moa,mt,mt->dstList,clif,srcurl) )
			return 0;
	}

	if( mt->dstList && rhost != NULL ){
		int nomatch,co;
		if( (mt->u_conds & C_RHOST) == 0 )
			return 0;
		co = RES_CACHEONLY(1);
		nomatch = !matchPath1(mt->dstList,"-",rhost,rport);
		RES_CACHEONLY(co);
		if( nomatch )
			return 0;
	}

	if( direction & mt->u_D_method )
	if( mt->u_method && method != NULL ){
		/*sv1log("### MOUNT METHOD [%s][%s]\n",mt->u_method,method);*/
		if( strcmp(mt->u_method,"*") != 0 )
		if( strcasestr(mt->u_method,method) == NULL )
			return 0;
	}

	if( mt->pathList && !CTX_matchPATHs(ctx,mt->pathList,NULL) )
		return 0;

	if( mt->viaList && !CTX_matchPATH1(ctx,mt->viaList,NULL,"-") )
		return 0;

	if( mt->u_xcond && evalCondition(ctx,mt->u_xcond) == 0 )
		return 0;

	return 1;
}

#undef Strcpy
#define Strcpy(d,s)	(Xstrcpy(QVStr(d,param),s), d+strlen(d))

static int evalCondX(MountArgs *moa,int direction,Mtab *mt,PCStr(clif),PCStr(dstproto),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport);
static int evalCond(DGC*ctx,int direction,Mtab *mt,PCStr(clif),PCStr(dstproto),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport)
{
	MountArgs moa;
	setupMOA(&moa,ctx,0,method);

	return
	evalCondX(&moa,direction,mt,clif,dstproto,method,srcurl,rhost,rport);
}
void toMD5X(PCStr(key),int klen,char digest[]);
static int evalCondX(MountArgs *moa,int direction,Mtab *mt,PCStr(clif),PCStr(dstproto),PCStr(method),PCStr(srcurl),PCStr(rhost),int rport)
{	int value;
	CStr(param,1024);
	refQStr(pp,param); /**/
	DGC *ctx = moa->mo_ctx;
	char md5[16];

	/* odst=hostList or http://odst.- (or rserv=odst.-) */
	if( (mt->Src.u_vserv & VHOST_ORIGDST)
	 || (mt->Dst.u_vserv & VSERV_ORIGDST)
	){
		IStr(odaddr,64);
		int odport;
		odport = CTX_getodstAddr(ctx,AVStr(odaddr));
		if( odport <= 0 ){
			return 0;
		}
	}
	if( mt->u_dstproto && dstproto ){
		if( !wordIsinList(mt->u_dstproto,dstproto) )
			return 0;
	}

	param[0] = 0;
	setVStrPtrInc(pp,'0' + direction); setVStrPtrInc(pp,'/');
	if( clif && (mt->clifList||mt->vhostList||mt->dstList) )
		pp = Strcpy(pp,clif);
	setVStrPtrInc(pp,'/');
	if( rhost  && mt->dstList  ) pp = Strcpy(pp,rhost); setVStrPtrInc(pp,'/');
	if( method && mt->u_method ) pp = Strcpy(pp,method);setVStrPtrInc(pp,'/');
	if( srcurl && mt->udstList ){
		decomp_absurl(srcurl,VStrNULL,AVStr(pp),VStrNULL,0);
		pp += strlen(pp);
		setVStrPtrInc(pp,'/');
	}
	setVStrEnd(pp,0);
	if( srcurl && mt->dstList  ) QStrncpy(pp,srcurl,pp-param);

	if( mt->u_reqpat ){
		const char *req;
		if( req = CTX_reqstr(ctx) ){
			if( frex_match((struct fa_stat*)mt->u_reqpat,req) == 0 )
				return 0;
		}
	}

	if( lMULTIST() ){
	    toMD5X(param,strlen(param),md5);
	    if( value = mt->u_conds_value )
	    if( bcmp(mt->u_conds_param_md5,md5,sizeof(md5)) == 0 ){
		return 0 < value ? 1 : 0;
	    }
	}else
	if( mt->u_conds_value )
	if( strcmp(param,mt->u_conds_param) == 0 )
		return 0 < mt->u_conds_value ? 1 : 0;
		/* should check if input parameters (clif,method,srcurl)
		 * is identical with the previous evaluation...
		 */

	/*
	value = evalCond1(ctx,direction,mt,clif,method,srcurl,rhost,rport);
	*/
	value = evalCond1X(moa,direction,mt,clif,method,srcurl,rhost,rport);
	if( clif ){
		if( value )
			mt->u_conds_value = 1;
		else	mt->u_conds_value = -1;
		if( lMULTIST() ){
			/* 9.9.8 to avoid malloc/free jam in multi-threads */
			bcopy(md5,mt->u_conds_param_md5,sizeof(md5));
		}else
		Strdup((char**)&mt->u_conds_param,param);
	}
	return value;
}
void reset_MOUNTconds()
{	int mi;

	for( mi = 0; mi < mtabN; mi++ ){
		mtab[mi]->u_conds_value = 0;
		mtab[mi]->Dst.u_iport_mapped = 0;
	}
	last_forw = -1;
}
static int portmap(DGC*ctx,Mtab *mt)
{	int mport;
	Url *dst;

	dst = &mt->Dst;
	if( mport = dst->u_iport_mapped )
		return mport;

	if( mt->Dst.u_vserv & VSERV_ORIGDST ){
		IStr(odaddr,256);
		int odport;
		odport = CTX_getodstAddr(ctx,AVStr(odaddr));
		mport = mapPort1(dst->u_portmap,odport);
	}else
	mport = portMap(ctx,dst->u_proto,dst->u_hostn,dst->u_portmap);
	dst->u_iport_mapped = mport;
	return mport;
}

int CTX_evalMountCond(DGC*ctx,PCStr(opts),PCStr(user),PCStr(chost),int cport,PCStr(ihost),int iport)
{	int List;
	int match = 0;
	CStr(path,1024);

	sprintf(path,"%s:%d!%s:%d",ihost,iport,chost,cport);

	if( strncmp(opts,"from=",5) == 0 ){
		List = makePathList("SERVER.from",opts+5);
		match = matchPath1(List,user,chost,cport);
	}else
	if( strncmp(opts,"host=",5) == 0 ){
		List = makePathList("SERVER.clif",opts+5);
		match = matchPath1(List,user,ihost,iport);
	}else
	if( strncmp(opts,"path=",5) == 0 ){
		List = makePathList("SERVER.path",opts+5);
		match = CTX_matchPATHs(ctx,List,path);
	}else{
		if( strncmp(opts,"via=",4)==0 || strncmp(opts,"src=",4)==0 )
			opts += 4;
		List = makePathList("SERVER.via",opts);
		match = CTX_matchPATH1(ctx,List,path,user);
	}
	return match;
}
static int matchHost(Url *up,PCStr(host))
{	const char *ahostn;
	const char *ahosta;
	const char *hosta;

	ahostn = up->u_hostn;
	ahosta = up->u_hosta;
	if( strcaseeq(host,ahostn) || ahosta && streq(host,ahosta) ) 
		return 1;

	if( ahosta )
	if( hosta = gethostaddr_fromcache(host) )
		if( streq(hosta,ahosta) )
			return 1;

	/* when the host have several addresses ...
	 * `matchhostaddr_incache(host,ahosta)' is necessary ?
	 */
	return 0;
}

#define url_strstr(whole,sub) \
	url_strstrX(whole,sub,mt->u_conds&C_NOCASE)

/*
static matchURL(up,url)
*/
#define matchURL(up,url) matchURLX(mt,up,url)
static int matchURLX(Mtab *mt,Url *up,PCStr(url))
{	CStr(proto,128);
	CStr(login,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	CStr(upath,1024);
	int iport;
	int hlen,plen;

	hlen = plen = 0;
	decomp_absurl(url,AVStr(proto),AVStr(login),AVStr(upath),sizeof(upath));
	iport = scan_hostport(proto,login,AVStr(host));

	if( up->u_hostList )
	if( streq(proto,up->u_proto) )
	if( matchPath1(up->u_hostList,"-",host,iport) )
	{
		hlen = strlen(url) - strlen(upath);
		plen = url_strstr(upath,up->u_path);
		Verbose("## MATCH FULL-URL-SRC [%s][%s] %d+%d\n",
			up->u_src,url,hlen,plen);
	}
	return hlen + plen;
}
static int dirmatch(Mtab *mt,PCStr(patn),PCStr(url))
{	int dlen;

	if( mt->u_dirmatch )
	if( strtailchr(url) != '/' )
	if( dlen = url_strstr(patn,url) )
	if( patn[dlen] == '/' && patn[dlen+1] == 0 )
	{
		sv1log("MOUNT DIRMATCH patn[%s] url[%s] %d\n",patn,url,dlen);
		return dlen;
	}
	return 0;
}
static int xmatch(Mtab *mt,PCStr(patn),PCStr(url),int *lenp)
{
	*lenp = 0;
	if( *patn == 0 || (*lenp = url_strstr(url,patn)) ){
		if( mt->Src.u_remain || url[*lenp] == 0 )
			return 1;
	}
	if( *lenp = dirmatch(mt,patn,url) ){
		return DIRMATCH;
	}
	return 0;
}

#undef Strcpy
#define Strcpy(d,s)	(Xstrcpy(QVStr(d,url),s), d+strlen(d))
int mount_lastforw(){ return last_forw; }

static const char *mount_url_toXX(MountArgs *moa,DGC*ctx,PCStr(clif),PCStr(method),PVStr(url),int qtype,Mtab **rmt);
static const char *mount_url_toX(DGC*ctx,PCStr(clif),PCStr(method),PVStr(url),int qtype,Mtab **rmt)
{	MountArgs moa;

	bzero(&moa,sizeof(moa));
	setupMOA(&moa,ctx,qtype,method);
	moa.mo_reclev = 0;
	return mount_url_toXX(&moa,ctx,clif,method,BVStr(url),qtype,rmt);
}
static const char *mount_url_toXX(MountArgs *moa,DGC*ctx,PCStr(clif),PCStr(method),PVStr(url),int qtype,Mtab **rmt)
{	refQStr(up,url); /**/
	CStr(origin_iurl,URLSZ);
	const char *rp;
	CStr(src_rest,1024);
	refQStr(iurl,origin_iurl);
	CStr(nocase_iurl,URLSZ);
	refQStr(iupath,origin_iurl); /**/
	int isfull;
	const char *ourl;
	int match;
	int ai;
	const char *addr;
	int len;
	Mtab *mt;
	int delput;
	const char *dstproto;
	CStr(protob,128);
	const char *dp;
	UTag *uv[33],ub[32];
	int uc;
	const char *myhostport;
	const char *dproto;
	int asproxy = CTX_asproxy(ctx);
	const char *CLproto;
	int CLprotoNFA;
	int match_urnonly = 0;
	int rtype = moa->mo_rtype;

	dumpstacksize("MOUNTforw","");
	if( rmt ) *rmt = 0;

	CLproto = CTX_clif_proto(ctx);
	CLprotoNFA = isinListX("smtp,pop,imap,nntp",CLproto,"c");

	my_h[0] = 0;
	if( clif == NULL )
		clif = CTX_clif_hostport(ctx);
	myhostport = clif;
	if( *myhostport == '-' )
		myhostport++;

	cpyQStr(iurl,origin_iurl);
	rp = wordscanY(url,AVStr(origin_iurl),sizeof(origin_iurl),"^ \t\r\n");
	FStrncpy(src_rest,rp);

	isfull = isFullURL(iurl);
	/* must care full-path MOUNT ...
	if( isfull ){
		iupath = ...
	}else
	 */
	cpyQStr(iupath,iurl);
	if( urlpath_normalize(iupath,QVStr(iupath,origin_iurl)) )
		Verbose("MOUNT url-path normalized [%s]>[%s]\n",url,iurl);

	nocase_iurl[0] = 0;

	if( strneq(url,"command:",8)
	 || strneq(url,"string:",7)
	){
		/* full-URL or URN should match only with  full-URL/URN */
		/* especially URN should not match with "*" in rURL */
		match_urnonly = 1;
	}
	for( ai = 0; ai < mtabN; ai++ ){
		mt = mtab[ai];
		if( mt->Src.u_asis || mt->u_disabled )
			continue;
		if( mt->u_direction == D_BACKONLY )
			continue;
		if( match_urnonly ){
			if( mt->Src.u_isurn == 0 ){
				continue;
			}
		}

		if( mt->u_conds & C_WITH_SSL ){
			if( CTX_withSSL(ctx) ){
				if( mt->c_withssl & (S_WITHOUTCL|S_WITHOUTSV) )
					continue;
			}else{
				if( mt->c_withssl & (S_WITHCL|S_WITHSV) )
					continue;
			}
		}
		if( mt->u_conds & C_NOCASE ){
			if( nocase_iurl[0] == 0 )
				strtolower(iurl,nocase_iurl);
			cpyQStr(iurl,nocase_iurl);
		}else	cpyQStr(iurl,origin_iurl);

		match = xmatch(mt,mt->Src.u_src,iurl,&len);
		if( !match && mt->Src.u_proto && isfull ){
			int hlen;
			if( hlen = matchURL(&mt->Src,iurl) )
			if( match = xmatch(mt,mt->Src.u_path,iurl+hlen,&len) )
				len += hlen;
		}

		if( !match )
			continue;

		if( lSINGLEP() ) /* to be genric after tested enough */
		if( CLprotoNFA ) /* the client is not a file access protocol */
		if( mt->Dst.u_proto ) /* if the server is for file access */
		if( isinListX("file,ftp,http,https",mt->Dst.u_proto,"c") ){
			/* maybe this MOUNT is not applied to the current
			 * client protocol. (except POP/FTP gw. for auth.?)
			 * (should be controled by srcproto={x,y,z})
			 */
			continue;
		}

#if 0
		if( mt->u_flags & U_REQDUMP ){
/*
CTX_dump_request(ctx);
			const char *req;
			FILE *lfp;
			if( req = CTX_reqstr(ctx) ){
				if( lfp = fopen("/tmp/reqlog","a") ){
					fputs(req,lfp);
					fclose(lfp);
				}
			}
*/
		}
#endif

		if( mt->Dst.u_any ){
			ourl = iurl + strlen(mt->Src.u_src);
			scan_URI_scheme(ourl,AVStr(protob),sizeof(protob));
			dstproto = protob;
		}else{
			ourl = iurl;
			dstproto = NULL;
		}
		/*
		if( evalCond(ctx,CFO,mt,clif,dstproto,method,ourl,NULL,0)==0 )
		*/
		if( evalCondX(moa,CFO,mt,clif,dstproto,method,ourl,NULL,0)==0 )
			continue;

		if( mt->Src.u_format )
		{
			if( mt->Src.u_uvfmt ){
				const char *rsp;
				const char *rfp;
				uvinit(uv,ub,32);
				uc = uvfromsfX(&iurl[len],0,mt->Src.u_format,uv,&rsp,&rfp);
				if( uc < 1 || *rsp != 0 )
					continue;
/*
				if( *rfp != 0 && !streq(rfp,"$") && strtailchr(rfp)=='$' )
*/
				if( mt->Src.u_format_toEOL && *rfp != 0 )
					continue; /* not complete match */
			}else
			if( !RexpMatch(&iurl[len],mt->Src.u_format) )
				continue;
		}

		if( mt->u_conds & C_WITHQUERY )
		if( strchr(iurl,'?') == NULL )
			continue;

		if( mt->u_conds & C_ASPROXY )
		{
			if( mt->u_conds_neg & C_ASPROXY ){
				if( asproxy ) continue;
			}else{
				if(!asproxy ) continue;
			}
		}
		/*
		if( !isfull )
			continue;
		*/

		/*
		 * input URL matched with the URL pattern of this MOUNT point
		 */

		if( qtype & U_ON_ERROR ){
			if( (mt->u_flags & U_ON_ERROR) == 0 ){
				continue;
			}
			if( mt->u_onerror && *mt->u_onerror )
			if( !isinList(mt->u_onerror,CTX_Rstat(ctx)) ){
				continue;
			}
		}else{
			if( (mt->u_flags & U_ON_ERROR) != 0 ){
				continue;
			}
		}

		/* myhostport should be BASEURL=http://HP if exists */
/*
fprintf(stderr,"--- --- --- me[%s] opts[%s]\n",myhostport,mt->u_opts);
*/

		if( qtype & U_MOVED_TO ){
			if( (match & DIRMATCH)
			 || mt->Dst.u_path2site && strchr(iurl+len,'/')==0
			){
				if( asproxy ){
					/* maybe this "gen MovedTo" for
					 *   http://site -> http://site/
					 * is not necessary in this case (asproxy)
					 */
					sprintf(url,"%s/",iurl);
				}else
				sprintf(url,"%s://%s%s/",CTX_clif_proto(ctx),
					myhostport,iurl);
				sv1log("MOUNT DIRMATCH gen MovedTo: %s\n",url);
				goto EXIT;
			}
		}

		if( (qtype & U_WHERE) )
		if( (mt->u_flags & U_WHERE) == 0 || (mt->u_where & rtype)==0 ){
			sv1log("[%d] URL Matched but not for Ref[%x/%x]:%s\n",
				ai,rtype,mt->u_where,iurl);
			goto FOUND;
		}
		if( (qtype & U_WHERE) == 0 )
		if( (mt->u_flags & U_WHERE) && (mt->u_where & W_REQURL) == 0 ){
			sv1log("[%d] URL Matched but for Ref[%x/%x]:%s\n",
				ai,rtype,mt->u_where,iurl);
			goto FOUND;
		}

		if( (qtype & U_MOVED_TO ) && (mt->u_flags & U_MOVED_TO ) == 0
		 || (qtype & U_USE_PROXY) && (mt->u_flags & U_USE_PROXY) == 0
		){
			Verbose("[%d] URL Matched but not for MovedTo[%x]:%s\n",
				ai,qtype,iurl);
			/* must exit without rewriting */
			goto FOUND;
		}
		if( (qtype & U_MOVED_TO ) == 0 && (mt->u_flags & U_MOVED_TO)
		 || (qtype & U_USE_PROXY) == 0 && (mt->u_flags & U_USE_PROXY)
		){
			Verbose("[%d] URL Matched but for MovedTo[%x]:%s\n",
				ai,qtype,iurl);
			/* must exit without rewriting */
			goto FOUND;
		}

		if( mt->Dst.u_asis ){
			Verbose("[%d] MOUNT ASIS: %s\n",ai,mt->Src.u_src);
			if( mt->u_conds & C_DEFAULT ){
				/* treat "ASIS by default" as Not-Mounted */
			}else
			if( mt->u_opts && mt->u_opts[0] )
			{
				sv1log("*** %s = *** %s\n",iurl,mt->u_opts);
				goto FOUND;
			}
			break;
		}

		if( mt->Dst.u_any ){
			up = Strcpy((char*)url,iurl+len);
			up = Strcpy(up,src_rest);
			goto FOUND;
			break;
		}

		if( mt->u_flags & U_RECURSIVE ){
			up = url;
			delput = 1;
			goto PUTPATH;
		}

		if((mt->u_flags & U_RESOLV) && mt->Dst.u_hosta)
			addr = mt->Dst.u_hosta;
		else	addr = mt->Dst.u_hostn;

		up = Strcpy((char*)url,mt->Dst.u_prefix);
/*
		if( mt->Dst.u_proto_ASIS )
			up = Strcpy(up,CTX_clif_proto(ctx));
		else
		up = Strcpy(up,mt->Dst.u_proto);
*/
		if( mt->Dst.u_proto_ASIS )
			dproto = CTX_clif_proto(ctx);
		else	dproto = mt->Dst.u_proto;
		up = Strcpy(up,dproto);
		setVStrPtrInc(up,':');

		if( addr[0] ){ 
			CStr(vh,MaxHostNameLen);
			CStr(ih,MaxHostNameLen);
			int vp,ip;
			if( mt->Dst.u_dhost & DH_VHOSTPORT )
				vp = scan_hostport(dproto,myhostport,AVStr(vh));
			if( mt->Dst.u_dhost & DH_IHOSTPORT ){
				strcpy(ih,CTX_clif_host(ctx));
				ip = CTX_clif_port(ctx);
			}

			up = Strcpy(up,"//");
			if( *mt->Dst.u_userpass ){
				up = Strcpy(up,mt->Dst.u_userpass);
				up = Strcpy(up,"@");
			}
			if( mt->Dst.u_vserv & VSERV_ORIGDST ){
				IStr(odaddr,256);
				int odport;
				int mp;
				odport = CTX_getodstAddr(ctx,AVStr(odaddr));
				up = Strcpy(up,odaddr);
				if( mt->Dst.u_portmap )
					mp = mapPort1(mt->Dst.u_portmap,odport);
				else	mp = mt->Dst.u_iport;
				if( (mt->u_flags & U_DISPPORT)
				 || mp != serviceport(dproto) ){
					Rsprintf(up,":%d",mp);
				}
			}else
			/*
			if( addr[0] == '-' && addr[1] == 0 ){
				my_p = scan_hostport(dproto,myhostport,my_h);
			*/
			if( (mt->Dst.u_dhost&DH_VHOSTPORT) == DH_VHOSTPORT ){
				CStr(mh,MaxHostNameLen);
				int mp;

				strcpy(my_h,vh);
				my_p = vp;

				mp = scan_hostport(dproto,myhostport,AVStr(mh));
				if( mp == serviceport(dproto) )
					up = Strcpy(up,mh);
				else
				up = Strcpy(up,myhostport);
			}else{
				/*
				if( mt->Dst.u_host_ASIS ){
					up = Strcpy(up,CTX_clif_host(ctx));
				*/
				if( mt->Dst.u_dhost & DH_VHOST ){
					strcpy(my_h,vh);
					up = Strcpy(up,vh);
				}else
				if( mt->Dst.u_dhost & DH_IHOST ){
					strcpy(my_h,ih);
					up = Strcpy(up,ih);
					if( (mt->u_flags & U_DISPPORT)==0 ){
						my_p = ip;
						sprintf(up,":%d",my_p);
					}
					up += strlen(up);
				}else
				up = Strcpy(up,addr);
				if( mt->u_flags & U_DISPPORT ){
					int mport;
					/*
					if( mt->Dst.u_port_ASIS ){
						mport = CTX_clif_port(ctx);
					*/
					if( mt->Dst.u_dhost & DH_VPORT ){
						mport = my_p = vp;
					}else
					if( mt->Dst.u_dhost & DH_IPORT ){
						mport = my_p = ip;
					}else
					if( mt->u_flags & U_PORTMAP )
						mport = portmap(ctx,mt);
					else	mport = mt->Dst.u_iport;
					sprintf(up,":%d",mport);
					up += strlen(up);
				}
			}
			if( mt->Dst.u_dhost & DH_PHOST ){
				/* in the middle of hostname as u_path2site */
				delput = 1;
			}else
			delput = 0;
		}else
		if( mt->Dst.u_emptysite ){
			up = Strcpy(up,"//");
			delput = 0;
		}else
		if( mt->Dst.u_path2site ){
			up = Strcpy(up,"//");
			delput = 1;
		}else{
			delput = 1;
		}

PUTPATH:
		if( mt->Dst.u_path ){
			if( !delput ){
				up = Strcpy(up,"/");
				delput = 1;
			}
			up = Strcpy(up,mt->Dst.u_path);
			if( match & DIRMATCH ){
				*(char*)--up = 0;
			}
			delput = 1;
		}
		if( mt->Dst.u_query ){
			setVStrPtrInc(up,'?');
			up = Strcpy(up,mt->Dst.u_query);
			delput = 1;
		}
		if( mt->Dst.u_subst ){
			IStr(buf,256);
			if( pilsner(ctx,url,(char*)buf,sizeof(buf)) ){
				strcpy(url,buf);
				up = url+strlen(url);
			}
		}

		if( iurl[len] )
		if( mt->Dst.u_remain ){
			if( 0 ) /* 9.0.5 this is bad for real /mlb/mlb/ */
			if( URL_SEARCH & URL_IN_SCRIPTs ){
				/* /v/v/.. might be generated by "/v/.. /.." */
				const char *su = mt->Src.u_src;
				int sl;
				sl = strlen(su);
				if( strncmp(iurl+len,su,sl)==0 )
					len += sl;
				else
				if( *su=='/' && strncmp(iurl+len,su+1,sl-1)==0 )
					len += sl-1;
			}
			if( !delput ){
				up = Strcpy(up,"/");
				delput = 1;
			}
			if( mt->Src.u_uvfmt && mt->Dst.u_uvfmt ){
				uvtosf(QVStr(up,url),URLSZ-(up-url),mt->Dst.u_format,uv);
				up += strlen(up);
			}else
			if( mt->Dst.u_format )
				up = rewrite_path(ctx,QVStr(up,url),mt->Dst.u_format,iurl+len);
			else	up = Strcpy(up,iurl+len);
		}

		Verbose("*** %s MOUNTED TO[%d] %s ***\n",
			mt->Src.u_src,ai,mt->Dst.u_src);
		sv1log("*** %s => %s ***\n",iurl,url);

		if( mt->u_flags & U_MYFILE ){
			myfile_path(url,AVStr(url));
if( lMOUNT() ) fprintf(stderr,"-- FIS=%d myfile %s\n",mt->u_conds&C_FILEIS,url);
		}
		if( mt->u_conds & C_FILEIS ){
			if( !strneq(url,"file:",5) ){
if( lMOUNT() ) fprintf(stderr,"-- fileis? BAD %s\n",url);
				continue;
			}else
			if( File_is(url+5) ){
if( lMOUNT() ) fprintf(stderr,"-- fileis? YES %s\n",url);
				if( url[5] == '/' && url[6] != '/' ){
					Strins(DVStr(url,5),"//localhost");
				}
if( lMOUNT() ) fprintf(stderr,"-- fileis? YES %s\n",url);
			}else{
if( lMOUNT() ) fprintf(stderr,"-- fileis? NO %s\n",url);
				continue;
			}
		}

		if( src_rest[0] )/* not a part of the URL */
			up = Strcpy(up,src_rest);
		last_hit = ai+1;

		/*
		if( mt->u_flags & U_RECURSIVE ){
		*/
		if( mt->u_flags & (U_RECURSIVE|U_AGAIN) ){
			if( 8 < ++moa->mo_reclev ){
				sv1log("mount: too deep recursions\n");
			}else
		return mount_url_toXX(moa,ctx,clif,method,BVStr(url),qtype,rmt);
		}
		goto FOUND;
	}
	return 0;

FOUND:
	/*
	 * MOVED_TO and USE_PROXY are not matching conditions about URL
	 * but the interpretations of the rule when the URL is matched.
	 * So they are here.
	 */
	if( qtype & U_MOVED_TO ){
		if((mt->u_flags & U_MOVED_TO) == 0)
		{
			/* matched non_MOVED MOUNT */
			if( rmt ) *rmt = mt;
			return 0;
		}
	}else
	if( qtype & U_WHERE ){
		if( strneq(url,"string:",7) ){
			ovstrcpy((char*)url,url+7);
		}
		if( (mt->u_where & rtype) == 0 )
			return 0;
	}else
	if( qtype & U_USE_PROXY ){
		if((mt->u_flags & U_USE_PROXY) == 0)
			return 0;
	}else{
		if( mt->u_flags & (U_MOVED_TO|U_USE_PROXY) )
		{
			return 0;
		}
	}
EXIT:
	last_forw = ai;
	if( rmt ) *rmt = mt;
	return mt->u_opts;
}
const char *CTX_mount_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url))
{
	return mount_url_toX(ctx,myhostport,method,AVStr(url),U_MOUNT,NULL);
}
int non_MOVED(){ return 100; }
int CTX_moved_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url))
{	Mtab *mt;

	if( mount_url_toX(ctx,myhostport,method,AVStr(url),U_MOVED_TO,&mt) ){
		return mt->u_moved;
	}
	if( mt != 0 ){
		/* matched non_MOVED MOUNT */
		return non_MOVED();
	}
	return 0;
}
const char *CTX_rewrite_referer(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url)){
	MountArgs moa;
	const char *opts;
	Mtab *mt;

	bzero(&moa,sizeof(moa));
	setupMOA(&moa,ctx,U_WHERE,method);
	moa.mo_rtype = W_REFERER;
	opts = mount_url_toXX(&moa,ctx,myhostport,method,AVStr(url),U_WHERE,&mt);
	if( opts ){
		return opts;
	}
	return 0;
}
const char *CTX_changeproxy_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url),PVStr(proxy))
{	Mtab *mt;
	const char *opt;

	setVStrEnd(proxy,0);
	if( opt = mount_url_toX(ctx,myhostport,method,AVStr(url),U_USE_PROXY,&mt) )
	if( mt->u_useproxy )
		strcpy(proxy,mt->u_useproxy);
	return opt;
}
const char *CTX_onerror_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url)){
	const char *opt;
	Mtab *mt;
	opt = mount_url_toX(ctx,myhostport,method,AVStr(url),U_ON_ERROR,&mt);
	if( opt )
		return opt;
	return 0;
}

static int dstmatch(DGC*ctx,Mtab *mt,PCStr(proto),PCStr(host),int iport,PCStr(path),int plen)
{	const char *aproto;
	const char *ahost;
	int mport;

	if( mt->Dst.u_proto_ASIS )
		aproto = CTX_clif_proto(ctx);
	else	aproto = mt->Dst.u_proto;
	if( !streq(proto,aproto) )
		return 0;

	if( mt->Dst.u_vserv & (VSERV_BYNAME|VSERV_AVSERV) )
	if( mt->Dst.u_genvhost ){ /* with [an]vserv=host */
		const char *vserv,*pp;
		IStr(vhost,256);
		int vport;
		vserv = mt->Dst.u_genvhost;

		if( mt->Dst.u_vserv & VSERV_THRU ){
			/* vserv=-thru => Host:host */
			vport = CTX_vhost(ctx,AVStr(vhost));
			if( mt->vhostList ){
			    /* vserv=-thru,vhost=host */
			    if( matchPath1(mt->vhostList,"-",vhost,vport) ){
				goto PATHMATCH;
			    }
			}else{
			    if( vport == iport ){
				if( mt->Dst.u_vserv & VSERV_AVSERV ){
					/* avserv=-thru */
					if( hostcmp(vhost,host) == 0 ){
						goto PATHMATCH;
					}
				}else{
					/* nvserv=-thru */
					if( strcaseeq(vhost,host) ){
						goto PATHMATCH;
					}
				}
			    }
			}
		}else{
			int stdport = mt->Dst.u_stdport;
			/* 9.9.8 "iport" shows the port number in the
			 * candidate URL (cURL = cproto://host:iport).
			 * Here, the protocol in the rURL and that in cURL are
			 * confirmed to be equal by "streq(proto,aproto)"
			 * And "*pp == 0" means no :port part in "nvserv=vhost".
			 * Thus there are two cases to be here with "*pp == 0":
			 * cURL=http://host:iport  for rURL=http:  nvserv=vhost
			 * cURL=https://host:iport for rURL=https: nvserv=vhost
			 * "stdport" is the std. port of the protocol of rURL
 			 */
			if( mt->Dst.u_vserv & VSERV_AVSERV ){
				/* avserv=host */
				pp = wordScanY(vserv,vhost,"^:");
				if( hostcmp(vhost,host) == 0 ){
					/*
					if( *pp == 0   && iport == 80
					*/
					if( *pp == 0   && iport == stdport
					 || *pp == ':' && iport == atoi(pp+1)
					){
						goto PATHMATCH;
					}
				}
			}else{
				/* nvserv=host */
				if( pp = strheadstrX(vserv,host,1) ){
					/*
					if( *pp == 0   && iport == 80
					*/
					if( *pp == 0   && iport == stdport
					 || *pp == ':' && iport == atoi(pp+1)
					){
						goto PATHMATCH;
					}
				}
			}
		}
		return 0;
	}

	if( mt->u_flags & U_PORTMAP )
		mport = portmap(ctx,mt);
	else	mport = mt->Dst.u_iport;
	if( mport != 0 && mport != iport )
		return 0;

	ahost = mt->Dst.u_hostn;
	/*
	if( strcmp(ahost,"-") == 0 && iport == my_p && strcmp(host,my_h) == 0 ){
	*/
	if( mt->Dst.u_dhost
	 && (iport == mport || iport == my_p )
	 && hostcmp_incache(host,my_h) == 0
	){
		Verbose("** UNMOUNT[//-] %s:%d==%s:%d\n",host,iport,my_h,my_p);
	}else
	if( mt->Dst.u_vserv & VSERV_BYNAME ){
		/* textual-only matching for a virtual hosting servrer */
		/* applied to auto-nvserv without genvserv */
		if( !strcaseeq(host,ahost) ){
			return 0;
		}
	}else
	if( ahost[0] != 0 && !matchHost(&mt->Dst,host) )
		return 0;

PATHMATCH:
	if( plen != 0 && strncmp(path,mt->Dst.u_path,plen) != 0 )
	{
		if( dirmatch(mt,mt->Dst.u_path,path) ){
			return DIRMATCH;
		}
		return 0;
	}

	return 1;
}

const char *CTX_mount_url_fromL(DGC*ctx,PVStr(url),PCStr(proto),PCStr(hostport),PCStr(path),PCStr(search),PCStr(dproto),PCStr(delegate))
{	refQStr(up,url); /**/
	const char *dp1;
	const char *dp2;
	CStr(dhost,128);
	int ai;
	int plen;
	Mtab *mt;
	CStr(host,128);
	CStr(xpath,1024);
	int iport;
	int match;
	int mport;
	CStr(mybase,128);
	int asproxy = CTX_asproxy(ctx);

	dumpstacksize("MOUNTback","");
	if( path == 0 )
		path = "";
	debug("{M} %s://%s/%s ?%s\n",proto,hostport,path,search?search:"");

	if( proto == 0 || hostport == 0 )
		return 0;

	if( dproto == 0 || dproto[0] == 0 )
		dproto = "http";

	if( hostport[0] == 0 ){
		host[0] = 0;
		iport = 0;
	}else	iport = scan_hostport(proto,hostport,AVStr(host));

	for( ai = 0; ai < mtabN; ai++ ){
		mt = mtab[ai];
		if( mt->Dst.u_asis || mt->u_disabled )
			continue;

		if( (mt->u_flags & U_WHERE) && (mt->u_where & W_RESPONSE) == 0 ){
			continue;
		}
		if( mt->u_flags & (U_MOVED_TO|U_USE_PROXY) )
			continue;
		if( mt->u_direction == D_FORWONLY )
			continue;
		if( mt->u_direction == D_BACKIFFORW && last_forw != ai )
			continue;

		if( mt->u_conds & C_ASPROXY ){
			if( mt->u_conds_neg & C_ASPROXY ){
				if( asproxy ) continue;
			}else{
				if(!asproxy ) continue;
			}
		}

		plen = mt->Dst.u_plen;

		match = 0;
		if( mt->Dst.u_any )
			match = 1;
		else	match = dstmatch(ctx,mt,proto,host,iport,path,plen);
		if( match & DIRMATCH ){
			plen--;
		}

		if( !match )
			continue;

		if( mt->Dst.u_qlen != 0 ){
			if( search == 0 )
				continue;
			if( strncmp(search,mt->Dst.u_query,mt->Dst.u_qlen) != 0 )
				continue;
		 	if( !mt->Dst.u_remain && search[mt->Dst.u_qlen] != 0 )
				continue;
		}

		if( evalCond(ctx,CBO,mt,delegate,proto,NULL,NULL,host,iport)==0 )
			continue;

		if( mt->u_flags & U_MYBASE ){
			delegate = mt->u_mybase;
			/* should set proto also if u_mybase is in
			 * "proto://server" format ..
			 */
		}else
		if( mt->u_conds & C_VHOST ){
			/* this code has been since 7.4.0 in which "vhost" was
			 * introduced, maybe to unify non-name-based vhost ?
			 */
			/* this is necessary for rew. of non-current nvhost
			if( mt->Src.u_vserv & VHOST_BYNAME ){
			}else
			*/
			if( mt->vhostList == 0 ){
				/* "delegate" is vhost on "vhost=-thru" */
			}else
			delegate = topofPath1(mt->vhostList,delegate,AVStr(mybase));
		}

		if( !mt->Dst.u_remain && path[plen] != 0 )
			continue;

		if( mt->Dst.u_rformat ){
			UTag *uv[33],ub[32];
			const char *rp;
			const char *rsp;
			const char *rfp;
			int uc,mlen;
			uvinit(uv,ub,32);
			uc = uvfromsfX(path,0,mt->Dst.u_rformat,uv,&rsp,&rfp);
			if( 0 < uc && *rfp == 0 ){
				if( mt->Dst.u_format_toEOL && *rsp != 0 )
					continue; /* not complete match */
				mlen = rsp - path;
				if( strchr(" \t\r\n",path[mlen]) ){
					uvtosf(AVStr(xpath),URLSZ,mt->Src.u_rformat,uv);
					strcat(xpath,&path[mlen]);
					Verbose("** %s -> %s\n",path,xpath);
					path = xpath;
				}
			}
			else{
				continue;
			}
		}

		if( mt->Src.u_asis )
			break;

		Verbose("** %s UNMOUNTED FROM %s **\n",
			mt->Src.u_src,mt->Dst.u_src);

		if( dp1 = strchr(delegate,':') ){
			if( atoi(dp1+1) == serviceport(dproto) ){
				int hl;
				wordscanY(delegate,AVStr(dhost),sizeof(dhost),"^:");
				hl = strlen(dhost);
				if( dp2 = strchr(dp1,'/') )
					wordscanX(dp2,QVStr(dhost+hl,dhost),sizeof(dhost)-hl);
				delegate = dhost;
			}
		}

		if( !mt->Src.u_fullurl ){
			sprintf(up,"%s://%s",dproto,delegate);
			up += strlen(up);
		}
		up = Strcpy(up,mt->Src.u_src);
		if( match & DIRMATCH ){
			*(char*)--up = 0;
		}
		if( mt->Dst.u_proto == 0 ){
			sprintf(up,"%s://%s/",proto,hostport);
			up += strlen(up);
		}
		if( mt->Dst.u_path2site ){
			if( strcmp(hostport,delegate) == 0 ){
				sv1log("MOUNT loop to self? %s[%s/]%s\n",
					url,delegate,path+plen);
			}else
			if( hostport[0] ){
				sprintf(up,"%s/",hostport);
				up += strlen(up);
			}
		}

		if( streq(proto,"gopher") ){
			if( up[-1] == '/' )
				up = Strcpy(up,"1");
			else	up = Strcpy(up,"/1");
		}

		if( plen )
			path += plen;
		up = Strcpy(up,path);

		if( search ){
			if( mt->Dst.u_qlen ){
				up = Strcpy(up,search+mt->Dst.u_qlen);
			}else{
				setVStrPtrInc(up,'?');
				up = Strcpy(up,search);
			}
		}
		last_hit = ai+1;
		return mt->u_opts;
	}
	return 0;
}
void CTX_scan_mtab(DGC*ctx,iFUNCP func,void *arg)
{	Mtab *mt;

	CTX_scan_mtabX(ctx,0,func,arg);
}
void CTX_scan_mtabX(DGC*ctx,PCStr(vhost),iFUNCP func,void *arg)
{	Mtab *mt;
	int mi;
	const char *clif;

	clif = CTX_clif_hostport(ctx);
	for( mi = 0; mi < mtabN; mi++ ){
		mt = mtab[mi];

		if( vhost && *vhost && mt->vhostList ){
			/* 9.9.1 for /robots.txt filtering by nvhost,avhost */
			if( evalCond(ctx,CFB,mt,vhost,0,0,0,0,0) == 0 ){
				continue;
			}
			if( mt->clifList ){
				/* filtering both with host and [na]vhost
				 * should be checked but not implemented
				 */
			}
		}else
		if( evalCond(ctx,CFB,mt,clif,NULL,NULL,NULL,NULL,0) == 0 )
			continue;

if( mt->Dst.u_hostn )
/* scanned but not compiled, caused by duplicat set of MOUNT list X-< */
		(*func)(arg,
			mt->Src.u_src,
			mt->Dst.u_proto,
			mt->Dst.u_user,
			mt->Dst.u_pass,
			mt->Dst.u_hostn,
			mt->Dst.u_iport,
			mt->Dst.u_path,
			mt->u_opts);
	}
}

void trans_url(PVStr(nurl),PCStr(ourl),PCStr(fmt))
{
	strcpy(nurl,fmt);
	sv1log("Transform-URL: %s -> %s\n",ourl,nurl);
}
