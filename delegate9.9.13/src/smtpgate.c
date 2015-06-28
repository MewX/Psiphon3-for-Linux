/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	smtpgw.c (SMTP to NNTP gateway)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    WHAT IS THIS ?

	SMTP->{NNTP,SMTP} relay

		will be extended to

		NNTP->{NNTP,SMTP}
		SMTP->FTP
		...

    CONFIGURATION FILES

	DELEGATE_SMTPGATE/{admin,users}/To/conf  -- configuration file
	DELEGATE_SMTPGATE/{admin,users}/To/count -- counter file
	DELEGATE_SMTPGATE/{admin,users}/To/log   -- log file ?
	DELEGATE_SMTPGATE/admin/@default/conf    -- default configuration file

    QUESTION ?

	SERVER: nntp://host:port/newsgroup
		- partial inheritance becomes difficult in this format...

OWNER ... execute in the list owners effective UID ?

History:
	970829	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"
#include "delegate.h"
#include "proc.h"
#include "fpoll.h"
#include "file.h"
#include "auth.h"

#define LNSIZE  1024
#define lfprintf	SMTP_lfprintf
void SMTP_lfprintf(FILE *log,FILE *tosc,PCStr(fmt),...);
int SMTP_openX(Connection *Conn,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log,PVStr(rresp));
void SMTP_putserv(FILE *log,FILE *fs,FILE *ts,PVStr(resp),PCStr(fmt),...);
int SMTP_relay_stat(FILE *fs,FILE *tc,xPVStr(resp));
FILE *SMTP_getEXPN(PCStr(addr));
int relayMSGdata(FILE *in,FILE *out,int anl,int eom);
void smtp_datamark(Connection *Conn,FILE *ts);
int RFC822_getSeqno(FILE *mfp);
void smtplog(Connection *Conn,PCStr(fmt),...);

typedef struct {
	struct { defQStr(ereason); } sg_ereason;
	int	sg_starttime;
} SmtpGateEnv;
static SmtpGateEnv smtpGateEnvs[MAX_THREADS];
#define smtpGateEnv smtpGateEnvs[getthreadgix(0)]
#define ereason   smtpGateEnv.sg_ereason.ereason
#define starttime smtpGateEnv.sg_starttime
/*
static struct { defQStr(ereason); } ereason;
*/
static void lfprintfx(FILE *log,FILE *tc,PCStr(fmt),...)
{
	VARGS(8,fmt);

	lfprintf(log,tc,fmt,VA8);
	if( ereason )
	sprintf(ereason,fmt,VA8);
}

#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)
#define getFV(str,fld,buf)       getFieldValue2(str,fld,AVStr(buf),sizeof(buf))

extern const char *DELEGATE_ADMIN;

#define POSTNEWS	"postnews"
#define SENDMAIL	"sendmail"
#define SPOOLER		"spooler"
#define FTPMAIL		"ftpmail"
#define HTTPMAIL	"httpmail"
#define SMMDGATE	"smmdgate"
#define RESPONDER	"responder"

#define DEFAULT		"@default"
#define _COMMON_CONF	"@common"
static char COMMON_CONF[] = _COMMON_CONF;

#define V_SENDER	"${sender}"
#define V_FROM		"${from}"
#define V_UNIXFROM	"${unixfrom}"
#define V_RECIPIENT	"${recipient}"
#define V_RECNAME	"${recipient.name}"
#define V_RECMX		"${recipient.mx}"
#define V_SUBJECT	"${subject}"
#define V_CLEANSUBJ	"${subject:hc}"
#define V_ORIGSEQNO	"${origseqno}"
#define V_SEQNO		"${seqno}"
#define V_SEQNO10	"${seqno/10}"
#define V_SEQNO100	"${seqno/100}"
#define V_TIMEFORM	"${date+"
#define V_ERRORSTAT	"${error.status}"
#define V_ORIGHEADER	"${header."
#define V_PID		"${pid}"
#define V_SELF		"${self}"
#define V_MESSAGEID	"${message-id}"
#define V_REWADDR	"${rewaddr:"


#define GWTYPE			 0
#define INHERIT			 1

#define ACC_SENDER		 2
#define ACC_RECIPIENT		 3
#define ACC_FROM		 4
#define ACC_TO			 5

#define OUT_NEWSGROUPS		 6
#define OUT_DISTRIBUTION	 7
#define OUT_REPLY_TO		 8
#define OUT_TO			 9
#define OUT_SUBJECT		10
#define OUT_HEADER		11
#define OUT_FILTER		12

#define CTL_RECIPIENT		13
#define BCC			14
#define OPTION			15
#define SERVPROTO		16
#define SERVHOST		17
#define SERVPORT		18
#define COUNTER			19
#define ARCHIVE			20

#define ACC_MAX_BYTES		21
#define ACC_MIN_BYTES		22
#define ACC_MIN_BODY_BYTES	23
#define ACC_MAX_EXCLAMS		24
#define ACC_CLIENT_HOST		25
#define ACC_MESSAGE_ID		26
#define ACC_USERTEXT		27
#define ACC_CONTTYPE		28

#define CTL_SENDER		29
#define CTL_MYAUTH		30
#define CTL_ETO			31

#define DELAY_SENDER		32
#define DELAY_RECIPIENT		33
#define DELAY_FROM		34
#define DELAY_TO		35
#define DELAY_Subject		36
#define DELAY_MESSAGE_ID	37
#define DELAY_CONTTYPE		38
#define DELAY_USERTEX		39

#define OUT_FROM		40
#define OUT_MESSAGE_ID		41
#define CTL_REJTO		42

#define ACC_HEADER		43
#define NPARAMS			44 /* last element above + 1 */

#define REJ_USERTEXT		(NPARAMS+ACC_USERTEXT)
#define REJ_CONTTYPE		(NPARAMS+ACC_CONTTYPE)
#define REJ_HEADER		(NPARAMS+ACC_HEADER)

typedef struct {
  const	char	*p_abbr;
	char	 p_pfix_opt;	/* prefix is optional */
  const	char	*p_pfix;
  const	char	*p_name;
} PSPEC;

static PSPEC param_spec[NPARAMS] = {
	{"gw",	1,"CONTROL",	"GATEWAY-TYPE"	},
	{"ih",	1,"CONTROL",	"INHERIT"	},

	{"se",	1,"ACCEPT",	"Sender"	},
	{"re",	0,"ACCEPT",	"Recipient"	},
	{"fr",	1,"ACCEPT",	"From"		},
	{"to",	0,"ACCEPT",	"To"		},

	{"ng",	1,"OUTPUT",	"Newsgroups"	},
	{"db",	1,"OUTPUT",	"Distribution"	},
	{"rt",	1,"OUTPUT",	"Reply-To"	},
	{"ot",  1,"OUTPUT",	"To"		},
	{"os",  1,"OUTPUT",	"Subject"	},
	{"oh",  1,"OUTPUT",	"Header"	},
	{"of",  1,"OUTPUT",	"FILTER"	},

	{"rp",	1,"CONTROL",	"RECIPIENT"	},
	{"bc",	1,"CONTROL",	"BCC"		},
	{"op",	1,"CONTROL",	"OPTION"	},
	{"sv",	1,"CONTROL",	"SERVER-PROTO"	},
	{"sh",	1,"CONTROL",	"SERVER-HOST"	},
	{"sp",	1,"CONTROL",	"SERVER-PORT"	},

	{"ct",	1,"CONTROL",	"COUNTER"	},
	{"ar",  1,"CONTROL",	"ARCHIVE"	},
	{"sz",	1,"ACCEPT",	"Max-Bytes"	},
	{"mb",	1,"ACCEPT",	"Min-Bytes"	},
	{"nb",	1,"ACCEPT",	"Min-Body-Bytes"},
	{"me",	1,"ACCEPT",	"Max-Exclams"	},
	{"ch",	1,"ACCEPT",	"Client-Host"	},
	{"mi",	1,"ACCEPT",	"Message-Id"	},
	{"at",  1,"ACCEPT",	"User-Text"	},
	{"ac",	1,"ACCEPT",	"Content-Type"	},

	{"cs",	0,"CONTROL",	"SENDER"	},
	{"ma",	1,"CONTROL",	"MYAUTH"	},
	{"et",	1,"CONTROL",	"Errors-To"	},

	{"ds",	0,"DELAY",	"Sender"	},
	{"dr",	0,"DELAY",	"Recipient"	},
	{"df",	0,"DELAY",	"From"		},
	{"dt",	0,"DELAY",	"To"		},
	{"dj",	0,"DELAY",	"Subject"	},
	{"dm",	0,"DELAY",	"Message-Id"	},
	{"dc",	0,"DELAY",	"Content-Type"	},
	{"du",	0,"DELAY",	"User-Text"	},

	{"oF",	0,"OUTPUT",	"From"		},
	{"oM",	0,"OUTPUT",	"Message-Id"	},
	{"rt",	0,"CONTROL",	"Reject-To"	},

	{"ah",	0,"ACCEPT",	"HEADER"	},
};
static int param_idx(PCStr(pname))
{	int px;
	PSPEC *ps;
	const char *dp;
	CStr(pfix,128);
	CStr(name,128);
	int reject;

	pfix[0] = name[0] = 0;
	if( dp = strchr(pname,'/') )
		Xsscanf(pname,"%[^/]/%s",AVStr(pfix),AVStr(name));
	else	strcpy(name,pname);
	reject = 0;
	if( strcaseeq(pfix,"REJECT") ){
		strcpy(pfix,"ACCEPT");
		reject = 1;
	}

	for( px = 0; px < NPARAMS; px++ ){
		ps = &param_spec[px];
		if( pfix[0] == 0 ){
			if( !ps->p_pfix_opt )
				continue;
		}else{
			if( !strcaseeq(pfix,ps->p_pfix) )
				continue;
		}
		if( strcasecmp(name,ps->p_name) == 0 )
		{
			if( reject )
				return NPARAMS+px;
			return px;
		}
		if( strcasecmp(name,ps->p_abbr) == 0 )
			return px;
	}
	return -1;
}

typedef struct gateway {
  const	char	*g_pv[NPARAMS*2]; /**/
  const	char	 g_dontovw[NPARAMS];	/**//* don't overwrite */
  const	char	*g_outheaders[32]; /**/
	int	 g_outheaderN;
struct gateway	*g_parent;		/* parent class ... */

  const	char	*g_sender;
  const	char	*g_recipient;
  const	char	*g_rname; /* [xxx%] LOCAL [@domain] part of g_recipient */

	int	 g_option;
	MStr(	 g_gwt,32);
	int	 g_count;
	int	 g_origSeqno;

	FILE	*g_ts;
	FILE	*g_fs;
  const char	*g_filter; /* saved global filter environment */
	MStr(	 g_replyto,LNSIZE);
	MStr(	 g_subject,LNSIZE);
	int	 g_doBcc;
} Gateway;

#define gv(px)		Gw->g_pv[px]
#define getp(px)	(gv(px) ? gv(px) : NULL)
#define getv(px)	((gv(px) && *gv(px)) ? gv(px) : NULL)

#define Option		Gw->g_option
#define Gwt		Gw->g_gwt
/**/
#define Sender		Gw->g_sender
#define Recipient	Gw->g_recipient
#define Rname		Gw->g_rname
#define Seqno		Gw->g_count
#define OrigSeqno	Gw->g_origSeqno
#define TS		Gw->g_ts
#define FS		Gw->g_fs
#define GFILTER		Gw->g_filter
#define ReplyTo		Gw->g_replyto
/**/
#define Subject		Gw->g_subject
/**/
#define DoBCC		Gw->g_doBcc


static const char *builtin_src[][8] = {
	/* MAIL TO NEWS */
	{
		"GATEWAY-TYPE: postnews",
		"SERVER-PROTO: nntp",
		"SERVER-HOST:  localhost",
		"Newsgroups:   junk",
		"Distribution: local",
	},
	/* MAIL TO MAIL */
	{
		"GATEWAY-TYPE: sendmail",
		"SERVER-PROTO: smtp",
		"SERVER-HOST:  localhost",
	},
	/* MAIL TO FTP */
	{
		"GATEWAY-TYPE: ftpmail",
		"SERVER-PROTO: ftp",
		"SERVER-HOST:  localhost",
	},
	/* MAIL TO HTTP */
	{
		"GATEWAY-TYPE: httpmail",
		"SERVER-PROTO: http",
		"SERVER-HOST:  localhost",
	},
	/* JUST SPOOL */
	{
		"GATEWAY-TYPE: spooler",
	},
	/* SMMDGATE */
	{
		"GATEWAY-TYPE: smmdgate",
	},
	/* RESPONDER */
	{
		"GATEWAY-TYPE: responder",
	},
	0
};
static Gateway *builtins;


static Gateway *new_conf()
{
	return (Gateway*)calloc(sizeof(Gateway),1);
}
static Gateway *builtinGw(PCStr(gwname),int silent)
{	int gwi,pi,px;
	int nlen;
	const char *gname1;

	if( gwname == NULL ){
		sv1log("#### NO GATEWAY TYPE SPECIFIED\n");
		return NULL;
	}
	if( builtins == NULL ){
		builtins = (Gateway*)calloc(sizeof(Gateway),8);
	}
	if( builtins[0].g_pv[0] == NULL ){
		const char **lines;
		const char *line;
		CStr(name,256);
		CStr(value,256);
		const char *vp;

		for( gwi = 0; (lines = builtin_src[gwi])[0]; gwi++ )
		for( pi = 0; line = lines[pi]; pi++ ){
			RFC822_decompField2(line,AVStr(name),AVStr(value),sizeof(value));
			vp = strip_spaces(value);
			px = param_idx(name);
			Verbose("SMTPGATE[%d][%d]=[%2d:%14s]=[%s]\n",
				gwi,pi,px,name,vp);
			if( px < 0 ){
				sv1log("#### UNKNOWN FILED IN BUILTIN SPEC: %s\n",
					line);
				return NULL;
			}
			builtins[gwi].g_pv[px] = stralloc(vp);
		}
	}

	for( gwi = 0; gname1 = builtins[gwi].g_pv[GWTYPE];  gwi++ ){
		nlen = strlen(gname1);
		if( strncasecmp(gwname,gname1,nlen) == 0 )
			if( gwname[nlen] == ':' || gwname[nlen] == 0 )
				return &builtins[gwi];
	}
	if( !silent )
		sv1log("#### unknown GATEWAY TYPE: %s\n",gwname);
	return NULL;
}
static void copy_ifundef(Gateway *Gw,Gateway *Gws)
{	int pi;
	const char *p1;
	const char *d1;

	for( pi = 1; pi < NPARAMS; pi++ )
		if( (p1 = getp(pi)) == NULL && (d1 = Gws->g_pv[pi]) )
			Gw->g_pv[pi] = (char*)d1;
}

const char *File_load(FILE *fp,int *sizep){
	int size,rcc;
	const char *buff;

	size = file_size(fileno(fp));
	buff = (char*)malloc(size+1);
	rcc = fread((char*)buff,1,size,fp);
	((char*)buff)[rcc] = 0;
	if( sizep )
		*sizep = rcc;
	return buff;
}

static void scan_conf(Gateway *Gw,FILE *fp,FILE *log)
{
	const char *buff;
	const char *line;
	const char *next;
	CStr(lbuf,1024);
	const char *comment;
	CStr(name,1024);
	const char *np;
	/*
	CStr(value,2048);
	*/
	CStr(value,8*1024);
	refQStr(vp,value);
	/*
	const char *vp;
	*/
	int px;

	buff = File_load(fp,NULL);

	for( line = buff; line && *line; line = next ){
		next = nextField(line,1);
		if( (comment = strpbrk(line,"#\r\n")) && *comment == '#' ){
			if( comment == line )
				continue;
			else	truncVStr(comment);
		}

		RFC822_decompField2(line,AVStr(name),AVStr(value),sizeof(value));
		if( np = strchr(name,'/') )
			np = np + 1;
		else	np = name;
		vp = strip_spaces(value);

		if( 0 <= (px = param_idx(name)) ){
			if( px == OUT_HEADER ){
				lfprintf(log,NULL,"conf + %s/%s[%d]:%s\r\n",
					param_spec[px].p_pfix,param_spec[px].p_name,
					Gw->g_outheaderN,vp);
				if( elnumof(Gw->g_outheaders) <= Gw->g_outheaderN ){
				lfprintf(log,NULL,"ignored too many OUTPUT\n");
				}else
				Gw->g_outheaders[Gw->g_outheaderN++] = stralloc(vp);
			}else
			if( NPARAMS <= px ){
				if( Gw->g_pv[px] ){
					/* 9.9.8 to add REJECT/USER-TEXT */
					/* REJECT/HEADER cannot be catenated */
					Xsprintf(TVStr(vp),",%s",Gw->g_pv[px]);
					free((char*)Gw->g_pv[px]);
				}
				Gw->g_pv[px] = stralloc(vp);
				if( 128+4 <= strlen(vp) ){
					/* 9.9.1 don't make too large log ... */
					Xstrcpy(DVStr(vp,128)," ...");
				}
				lfprintf(log,NULL,"conf + %s/%s:%s\r\n",
					"REJECT",param_spec[px-NPARAMS].p_name,vp);
			}else
			if( Gw->g_pv[px] == 0 || px == INHERIT ){
				lfprintf(log,NULL,"conf + %s/%s:%s\r\n",
					param_spec[px].p_pfix,param_spec[px].p_name,vp);
				Gw->g_pv[px] = stralloc(vp);
			}else{
				lfprintf(log,NULL,"conf - %s:%s\r\n",name,vp);
			}
		}else{
			lfprintf(log,NULL,"unknown -- %s:%s\r\n",name,vp);
		}
	}

	free((char*)buff);
}

static const char *user_class[8] = {
	"admin",
	"users",
	"",
	0
};

extern const char *DELEGATE_SMTPGATE;
static const char *SMTPGATE_DIR;
int toSafeFileName(PCStr(name),PVStr(xname));

FILE *open_file(PCStr(name),PCStr(type),PCStr(mode),PVStr(rpath))
{	CStr(cpath,1024);
	const char *xclass;
	FILE *fp;
	int ui;
	CStr(xname,1024);

	if( SMTPGATE_DIR == NULL ){
		sv1log("No SMTPGATE directory specified.\n");
		return NULL;
	}

	toSafeFileName(name,AVStr(xname));
	for( ui = 0; xclass = user_class[ui]; ui++ ){
		/*
		sprintf(rpath,"%s/%s/%s",xclass,name,type);
		*/
		sprintf(rpath,"%s/%s/%s",xclass,xname,type);
		sprintf(cpath,"%s/%s",SMTPGATE_DIR,rpath);
		if( fp = fopen(cpath,mode) )
			return fp;
	}
	return NULL;
}

static int load_conf(Connection *Conn,Gateway *Gw,PCStr(name),FILE *afp,PCStr(sender),PCStr(recipient),FILE *log)
{	CStr(rpath,1024);
	FILE *cfp;

	if( SMTPGATE_DIR == NULL ){
		lfprintf(log,NULL,"No SMTPGATE directory specified.\n");
		return 0;
	}

	cfp = open_file(name,"conf","r",AVStr(rpath));
	if( cfp != NULL ){
		lfprintf(log,NULL,"load config. file -- SMTPGATE/%s\n",rpath);
		scan_conf(Gw,cfp,log);
		fclose(cfp);
		return 1;
	}else{
		lfprintf(log,NULL,"cannot read config. file -- SMTPGATE/%s\n",
			rpath);
		return 0;
	}
}

/*
 *	SMTPGATE=dir[:list-of-subdirs]
 */
extern substFile *LOG_substfile;
int scan_SMTPGATE(Connection *Conn,PCStr(conf))
{	CStr(pb,1024);
	const char *pv[NPARAMS+1]; /**/
	const char *p0;
	const char *p1;
	int pc,pi;
	int gwi;
	CStr(dir,1024);

	if( builtinGw(POSTNEWS,0) == NULL ){
		sv1tlog("ERROR IN BUILTIN SPECIFICATION\n");
		Finish(1);
	}

	strcpy(pb,conf);
	pc = stoV(pb,NPARAMS,pv,':');
	p0 = pv[0];
	p1 = pv[1];

	strcpy(dir,p0);
	Substfile(dir);
	if( !fileIsdir(dir) ){
		sv1tlog("Warning: non existent SMTPGATE=%s [%s]\n",conf,dir);
		return -1;
	}else{
		sv1tlog("SMTPGATE=%s [%s]\n",conf,dir);
		SMTPGATE_DIR = stralloc(dir);
		return 0;
	}
}

/*
 * OPTION
 */
#define RXO	0x01	/* Remove X-Original headers */
#define AXO	0x02	/* Append X-Original headers */
#define RES	0x04	/* Reject Empty Subject */
#define RNI	0x08	/* Reject No message-ID message */
#define REB	0x10	/* Reject Empby Body */
#define GWT	0x20	/* GateWay Trace */
#define ISN	0x40	/* Increment Sequence Number */
#define INH	0x80	/* INHibit to accepting at this name */
#define NTR	0x100	/* do NOT add trace field (Received:) */

#define CHK_ACC_TO	"tmn"	/* check To: name matching */
#define MSG_NUMBER	"msn"	/* message number by posted article number */

static int scan_options(PCStr(opts),PVStr(gwt),FILE *log)
{	int opti;
	CStr(optb,1024);
	const char *ov[32]; /**/
	const char *o1;
	int oc,oi;
	CStr(msg,1024);

	opti = 0;
	strcpy(optb,opts);
	if( strchr(optb,',') )
		oc = stoV(optb,32,ov,',');
	else	oc = stoV(optb,32,ov,'.');

	for( oi = 0; oi < oc; oi++ ){
		o1 = strip_spaces(ov[oi]);

		if( strcaseeq(o1,"res") ){
			sprintf(msg,"Reject-Empty-Subject");
			opti |= RES;
		}else
		if( strcaseeq(o1,"reb") ){
			sprintf(msg,"Reject-Empty-Body");
			opti |= REB;
		}else
		if( strcaseeq(o1,"rni") ){
			sprintf(msg,"Reject-No-messegaeID");
			opti |= RNI;
		}else
		if( strcaseeq(o1,"rxo") ){
			sprintf(msg,"Remove-X-Original");
			opti |= RXO;
		}else
		if( strcaseeq(o1,"axo") ){
			sprintf(msg,"Append-X-Original");
			opti |= AXO;
		}else
		if( strcaseeq(o1,"gwt") ){
			sprintf(msg,"Gateway-Trace");
			opti |= GWT;
			strcpy(gwt,o1);
		}else
		if( strcaseeq(o1,"isn") ){
			sprintf(msg,"Increment-Sequence-Number");
			opti |= ISN;
		}else
		if( strcaseeq(o1,"ntr") ){
			sprintf(msg,"DoNOT-add-Trace-Field");
			opti |= NTR;
		}else{
			sprintf(msg,"unknown, ignored.",o1);
		}
		lfprintf(log,NULL,"OPTION: %s -- %s ON\r\n",o1,msg);
	}
	return opti;
}

static void append_log(Connection *Conn,Gateway *Gw,FILE *ts,FILE *log)
{	CStr(proto,32);
	const char *what;

	if( (Option & GWT) == 0 )
		return;

	fflush(log);
	Ftruncate(log,0,2);
	fseek(log,0,0);

	strtoupper(DST_PROTO,proto);
	if( strcasecmp(proto,"smtp") != 0 )
		what = "gateway";
	else	what = "relay";

fprintf(ts,"\r\n");
fprintf(ts,"--MAILGATE %s/SMTP %s DeleGate/%s--\r\n",proto,what,DELEGATE_ver());
fprintf(ts,"Comment: This part including the CRLF at two lines above is a trace\r\n");
fprintf(ts,"  information appended by DeleGate which relayed this messaged from\r\n");
fprintf(ts,"  SMTP to %s.  The tracing is activated\r\n",proto);
 if( Gwt[0] ){
 fprintf(ts,"  by set \"gateway-trace\" option (%s) specified in the\r\n",Gwt);
 fprintf(ts,"  gateway for recipient address <%s>.\n",Recipient);
 }else{
 fprintf(ts,"  by a\r\n");
 fprintf(ts,"   X-Gateway-Control: trace-on\r\n");
 fprintf(ts,"  field included in the original message.\r\n");
 }
fprintf(ts,"\r\n");
copyfile1(log,ts);
fprintf(ts,"--\r\n");
}


void subject_stripPrefix(PVStr(subj),int maxDelBracket,int leaveBracket1);
void subject_headclean(PVStr(subj))
{
	subject_stripPrefix(BVStr(subj),1,0);
}
void subject_stripPrefix(PVStr(subj),int maxDelBracket,int leaveBracket1)
{	char sc;
	const char *sp;
	CStr(tmp,2048);
	IStr(bracket1,128);
	refQStr(bp,bracket1);
	int withRe,numBracket;

	withRe = 0;
	numBracket = 0;

	for( sp = subj; sc = *sp; ){
		if( sc == ' ' || sc == '\t' ){
			sp++;
		}else
		/*
		if( sc == '[' && numBracket == 0 ){
			numBracket = 1;
		*/
		if( sc == '[' && numBracket < maxDelBracket ){
			numBracket += 1;
			for( sp++; sc = *sp; sp++ )
			{
				if( sc == ']' ){
					sp++;
					break;
				}
				if( numBracket == 1 ){
					setVStrPtrInc(bp,sc);
				}
			}
			if( numBracket == 1 ){
				setVStrPtrInc(bp,0);
			}
		}else
		if( strncasecmp(sp,"AW:",3) == 0 ){
			withRe++;
			sp += 3;
		}else
		if( strncasecmp(sp,"Fw:",3) == 0 ){
			withRe++;
			sp += 3;
		}else
		if( strncasecmp(sp,"Fw",2) == 0 && isdigit(sp[2]) ){
			withRe++;
			for( sp += 3; *sp && isdigit(*sp); sp++ )
				;
			if( *sp == ':' )
				sp++;
		}else
		if( strncasecmp(sp,"Fwd:",4) == 0 ){
			withRe++;
			sp += 4;
		}else
		if( strncasecmp(sp,"Re[",3) == 0 ){
			withRe++;
			sp += 3;
			for( sp += 3; *sp && isdigit(*sp); sp++ )
				;
			if( *sp == ']' )
				sp++;
			if( *sp == ':' )
				sp++;
		}else
		if( strncasecmp(sp,"Re:",3) == 0 ){
			withRe++;
			sp += 3;
		}else
		if( strncasecmp(sp,"Re^",3) == 0 ){
			withRe++;
			for( sp += 3; *sp && isdigit(*sp); sp++ )
				;
			if( *sp == ':' )
				sp++;
		}else{
			break;
		}
	}
EXIT:
	strcpy(tmp,sp);
	setVStrEnd(subj,0);
	if( leaveBracket1 ){
		sprintf(subj,"[%s] ",bracket1);
	}
	if( withRe )
		strcat(subj,"Re: ");
	strcat(subj,tmp);
}

static void make_unixfrom(PVStr(unixfrom),PCStr(sender))
{	CStr(stime,128);

	StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_ANSI_C,starttime,0);
	sprintf(unixfrom,"%s %s",sender,stime);
}
extern const char *SMTP_myname;
static void put_trace(Connection *Conn,Gateway *Gw,FILE *log,FILE *ts,PCStr(recipients))
{	CStr(stime,128);
	CStr(clif,MaxHostNameLen);

	StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_RFC822,time(0),0);
	if( SMTP_myname )
		wordScan(SMTP_myname,clif);
	else
	ClientIF_name(Conn,FromC,AVStr(clif));
	lfprintf(log,ts,
		/* v9.9.12 fix-140821e, folding long field
		"Received: from %s by %s (DeleGate/%s) for %s (%s); %s\r\n",
		 */
"Received: from %s\r\n\
	by %s (DeleGate/%s)\r\n\
	for <%s>\r\n\
	(%s);\r\n\
	%s\r\n",
		Client_Host,clif,DELEGATE_ver(),recipients,Recipient,stime);
}

/*
 *  PATH NAME SUBSTITUTION
 *
 *     %5${seqno}
 *     %5${seqno/100}
 */
static void subst_path(Gateway *Gw,PCStr(fmt),PVStr(spath))
{	const char *fp;
	const char *np;
	CStr(val,1024);
	CStr(numb,2);
	int width,num;
	refQStr(op,spath); /**/

	for( fp = fmt; *fp; fp = np ){
		assertVStr(spath,op+10);
		width = 0;
		np = fp;
		if( *fp == '%' && isdigit(fp[1]) ){
			numb[0] = fp[1];
			numb[1] = 0;
			width = atoi(numb);
			np = fp + 2;
		}

		if( strncmp(np,V_PID,strlen(V_PID)) == 0 ){
			np += strlen(V_PID);
			num = getpid();
			goto PUTNUM;
		}
		if( strncmp(np,V_ORIGSEQNO,strlen(V_ORIGSEQNO)) == 0 ){
			np += strlen(V_ORIGSEQNO);
			num = OrigSeqno;
			goto PUTNUM;
		}
		if( strncmp(np,V_SEQNO,strlen(V_SEQNO)) == 0 ){
			np += strlen(V_SEQNO);
			num = Seqno;
			goto PUTNUM;
		}
		if( strncmp(np,V_SEQNO10,strlen(V_SEQNO10)) == 0 ){
			np += strlen(V_SEQNO10);
			num = (Seqno/10)*10;
			goto PUTNUM;
		}
		if( strncmp(np,V_SEQNO100,strlen(V_SEQNO100)) == 0 ){
			np += strlen(V_SEQNO100);
			num = (Seqno/100)*100;
			goto PUTNUM;
		}
		if( strncmp(np,V_TIMEFORM,strlen(V_TIMEFORM)) == 0 ){
			CStr(tfmt,1024);
			refQStr(tp,tfmt); /**/
			for( np += strlen(V_TIMEFORM); *np; np++ ){
				assertVStr(tfmt,tp+1);
				if( *np == '}' )
					break;
				setVStrPtrInc(tp,*np);
			}
			if( *np == '}' ){
				setVStrEnd(tp,0);
				StrftimeLocal(AVStr(val),sizeof(val),tfmt,time(0),0);
				np++;
				goto xPUTSTR;
			}
		}
		setVStrPtrInc(op,*fp);
		np = fp + 1;
		continue;

	PUTNUM:
		if( width )
			sprintf(val,"%0*d",width,num);
		else	sprintf(val,"%d",num);
	xPUTSTR:
		strcpy(op,val);
		op += strlen(op);
	}
	setVStrEnd(op,0);
}

static int rewriteHeader(PCStr(fnam),PVStr(fval),PCStr(fmt)){
	CStr(addr,MaxHostNameLen);
	CStr(xaddr,MaxHostNameLen);

	RFC822_addresspartX(fval,AVStr(addr),sizeof(addr));
	strcpy(xaddr,addr);
	MIME_rewriteHeader(NULL,fmt,AVStr(xaddr),fnam);
	strsubst(BVStr(fval),addr,xaddr);
	return  1;
}

static void substitute(Gateway *Gw,FILE *mfp,PCStr(src),PVStr(dst),FILE *log,PCStr(sender))
{	CStr(tmp,1024);
	CStr(val,1024);
	CStr(unixfrom,1024);
	const char *bp;
	const char *ep;
	const char *sp;
	const char *dp;

	strcpy(dst,src);
	strcpy(tmp,dst);

	if( strstr(dst,V_ERRORSTAT) ){
		strsubst(AVStr(dst),V_ERRORSTAT,"something wrong...");
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_RECIPIENT) ){
		strsubst(AVStr(dst),V_RECIPIENT,Recipient);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_RECNAME) ){
		strsubst(AVStr(dst),V_RECNAME,Rname);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_SENDER) ){
		strsubst(AVStr(dst),V_SENDER,sender);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_UNIXFROM) ){
		make_unixfrom(AVStr(unixfrom),sender);
		strsubst(AVStr(dst),V_UNIXFROM,unixfrom);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_ORIGSEQNO) ){
		if( OrigSeqno == 0 ){
			OrigSeqno = RFC822_getSeqno(mfp);
		}
		sprintf(val,"%d",OrigSeqno);
		strsubst(AVStr(dst),V_ORIGSEQNO,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_SEQNO) ){
		sprintf(val,"%d",Seqno);
		strsubst(AVStr(dst),V_SEQNO,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_FROM) ){
		fgetsHeaderField(mfp,"From",AVStr(val),sizeof(val));
		strsubst(AVStr(dst),V_FROM,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( sp = strstr(dst,V_REWADDR) )
	if( dp = strchr(sp,'}') ){
		CStr(fnam,256);
		CStr(ffmt,256);
		CStr(sfmt,256);
		truncVStr(fnam);
		truncVStr(ffmt);
		Xsscanf(sp+strlen(V_REWADDR),"%[^:}]:%[^}]",AVStr(fnam),AVStr(ffmt));
		fgetsHeaderField(mfp,fnam,AVStr(val),sizeof(val));
		rewriteHeader(fnam,AVStr(val),ffmt);
		QStrncpy(sfmt,sp,dp-sp+2);
		strsubst(AVStr(dst),sfmt,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_SUBJECT) ){
		fgetsHeaderField(mfp,"Subject",AVStr(val),sizeof(val));
		strsubst(AVStr(dst),V_SUBJECT,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_CLEANSUBJ) ){
		fgetsHeaderField(mfp,"Subject",AVStr(val),sizeof(val));
		subject_headclean(AVStr(val));
		strsubst(AVStr(dst),V_CLEANSUBJ,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( strstr(dst,V_MESSAGEID) ){
		fgetsHeaderField(mfp,"Message-Id",AVStr(val),sizeof(val));
		strsubst(AVStr(dst),V_MESSAGEID,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
	if( sp = strstr(dst,V_ORIGHEADER) )
	if( dp = strchr(sp,'}') ){
		CStr(vname,256);
		CStr(fname,256);
		int len;
		len = dp + 1 - sp;
		Bcopy(sp,vname,len); setVStrEnd(vname,len);
		Xsscanf(vname+strlen(V_ORIGHEADER),"%[^}]",AVStr(fname));
		fgetsHeaderField(mfp,fname,AVStr(val),sizeof(val));
		strsubst(AVStr(dst),vname,val);
		lfprintf(log,NULL,"substitute -- %s => %s\n",tmp,dst);
	}
}

static void rewrite_header(Connection *Conn,Gateway *Gw,FILE *mfp,FILE *ts,PCStr(sender),FILE *log)
{	const char *p1;
	int hi;
	CStr(line,LNSIZE);

	if( p1 = getv(OUT_REPLY_TO) ){
		substitute(Gw,mfp,p1,AVStr(ReplyTo),log,sender);
		lfprintf(log,ts,"Reply-To: %s\r\n",ReplyTo);
	}
	if( p1 = getv(OUT_SUBJECT) ){
		substitute(Gw,mfp,p1,AVStr(Subject),log,sender);
		lfprintf(log,ts,"Subject: %s\r\n",Subject);
	}

	if( p1 = getv(OUT_FROM) ){
		substitute(Gw,mfp,p1,AVStr(line),log,sender);
		lfprintf(log,ts,"From: %s\r\n",line);
	}
	if(p1 = getv(OUT_MESSAGE_ID) ){
		substitute(Gw,mfp,p1,AVStr(line),log,sender);
		lfprintf(log,ts,"Message-Id: %s\r\n",line);
	}

	if( 0 < Gw->g_outheaderN ){
		for( hi = 0; hi < Gw->g_outheaderN; hi++ ){
			substitute(Gw,mfp,Gw->g_outheaders[hi],AVStr(line),log,sender);
			lfprintf(log,ts,"%s\r\n",line);
		}
	}
}

static void normalize_folding(PVStr(line))
{	const char *dp;
	const char *body;

	dp = strchr(line,':');
	if( dp == NULL )
		return;

	body = ++dp;
	while( *dp == ' ' || *dp == '\t' )
		dp++;
	if( *dp == '\r' || *dp == '\n' ){
		while( *dp == '\r' || *dp == '\n' )
			dp++;
		if( *dp == ' ' || *dp == '\t' ){
			sv1log("Removing unnecessary folding... %s",line);
			ovstrcpy((char*)body,dp);
		}
	}
}

static int tobe_rejected(FILE *tc,PCStr(what),PCStr(addr),PCStr(acli),FILE *log);

static int checkhead(Connection *Conn,Gateway *Gw,PCStr(fname),PCStr(line),FILE *tc,FILE *log)
{	CStr(fvalue,1024);
	const char *p1;

	/*
	if( strcmp(fname,"To")   == 0 && (p1 = getv(ACC_TO))
	||  strcmp(fname,"From") == 0 && (p1 = getv(ACC_FROM))
	*/
	if( strcaseeq(fname,"To")   && (p1 = getv(ACC_TO))
	||  strcaseeq(fname,"From") && (p1 = getv(ACC_FROM))
	){
		getFV(line,fname,fvalue);
		RFC822_addresspartX(fvalue,AVStr(fvalue),sizeof(fvalue));
		if( tobe_rejected(tc,fname,fvalue,p1,log) != 0 )
			return -1;
	}
	return 0;
}
static int checkHead(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PVStr(EOH),FILE *log)
{	CStr(line,LNSIZE);
	CStr(fname,64);

	for(;;){
		if( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),mfp) == NULL )
			break;

		normalize_folding(AVStr(line));

		if( line[0] == '\r' || line[0] == '\n' ){
			if( EOH )
				strcpy(EOH,line);
			break;
		}

		wordScanY(line,fname,"^: ");
		if( checkhead(Conn,Gw,fname,line,tc,log) < 0 )
			return -1;
	}
	return 0;
}

/*
 *   MAIL_TO_NEWS
 *	"tc" is a stream connected to the SMTP client
 *	"mfp" is a file containing the data sent by DATA command.
 *	"ts" is a stream connected to the NNTP server
 */
static int mail_to_news(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log)
{	CStr(line,1024);
	CStr(tmp,1024);
	CStr(fname,1024);
	CStr(fvalue,1024);
	CStr(myhost,MaxHostNameLen);
	CStr(clifhost,MaxHostNameLen);
	CStr(clhost,MaxHostNameLen);
	const char *dp;
	CStr(path0,128);
	CStr(To,1024);
	const char *to;
	CStr(From,1024);
	CStr(Newsgroups,1024);
	CStr(Distribution,1024);
	CStr(EOH,8);
	const char *p1;

	Newsgroups[0] = 0;
	Distribution[0] = 0;

	To[0] = 0;
	From[0] = 0;
	EOH[0] = 0;

	gethostname(myhost,sizeof(myhost));
	getFQDN(myhost,AVStr(myhost));
	ClientIF_name(Conn,FromC,AVStr(clifhost));
	getClientHostPort(Conn,AVStr(clhost));

	if( (dp = strchr(sender,'@')) && dp[1] ){
		strcpy(path0,dp+1);
		strcat(path0,"!");
		Xsscanf(sender,"%[^@]",TVStr(path0));
	}else	strcpy(path0,sender);
	lfprintf(log,TS,"Path: %s!SMTP-DeleGate%s!%s!%s!%s\r\n",
		myhost,DELEGATE_ver(),clifhost,clhost,path0);

	lfprintf(log,TS,
		"X-Forwarded: by %s (NNTP/SMTP gateway DeleGate/%s)\r\n",
		myhost,DELEGATE_ver());

	if( p1 = getv(OUT_NEWSGROUPS) ){
		substitute(Gw,mfp,p1,AVStr(Newsgroups),log,sender);
		lfprintf(log,TS,"Newsgroups: %s\r\n",Newsgroups);
	}
	if( p1 = getv(OUT_DISTRIBUTION) ){
		substitute(Gw,mfp,p1,AVStr(Distribution),log,sender);
		lfprintf(log,TS,"Distribution: %s\r\n",Distribution);
	}

	rewrite_header(Conn,Gw,mfp,TS,sender,log);

	/*
	 * should do MIME conversion ...
	 */
	for(;;){
		if( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),mfp) == NULL )
			break;
		normalize_folding(AVStr(line));

		if( line[0] == '\r' || line[0] == '\n' ){
			strcpy(EOH,line);
			break;
		}

		Xsscanf(line,"%[^: ]",AVStr(fname));

		if( checkhead(Conn,Gw,fname,line,tc,log) < 0 )
			return -1;

		if( strcasecmp(fname,"X-Gateway-Control") == 0 ){
			lfprintf(log,NULL,"control -- %s",line);
			if( strcasestr(line,"trace-on") )
				Option |=  GWT;
			else	Option &= ~GWT;
		}

		if( strcasecmp(fname,"Date") == 0 ){
			CStr(oline,128);
			RFC822_strip_commentX(line,AVStr(oline),sizeof(oline));
			if( strcmp(line,oline) != 0 ){
			lfprintf(log,NULL,"time zone erased -- %s",line);
			strcpy(line,oline);
			lfprintf(log,NULL,"time zone erased -- %s",line);
			}
		}

		if( strcasecmp(fname,"From") == 0 )
			getFV(line,"From",From);

		if( strncasecmp(fname,"X-Original-",11) == 0 ){
			if( (Option&RXO) ){
				lfprintf(log,NULL,"removed -- %s",line);
				continue;
			}
		}

		if( strcaseeq(fname,"Path")
		 || Newsgroups[0]   && strcaseeq(fname,"Newsgroups")
		 || Distribution[0] && strcaseeq(fname,"Distribution")
		 || ReplyTo[0]      && strcaseeq(fname,"Reply-To")
		 || Subject[0]      && strcaseeq(fname,"Subject")
		 || strcaseeq(fname,"NNTP-Posting-Host")
		 || strcaseeq(fname,"Errors-To")
		 || strcaseeq(fname,"Return-Receipt-To")
		 || strcaseeq(fname,"Return-Path")
		 || strcaseeq(fname,"Received")
		 || strcaseeq(fname,"Apparently-To")
		 || strcaseeq(fname,"To")
		 || strcaseeq(fname,"Cc")
		){
			if( !(Option&AXO) ){
				lfprintf(log,NULL,"removed -- %s",line);
				continue;
			}

			lfprintf(log,NULL,"escaped -- X-Original-%s",line);
			fputs("X-Original-",TS);
		}
		if( strcaseeq(fname,"Sender") ){
			lfprintf(log,NULL,"escaped -- X-Original-%s",line);
			fputs("X-Original-",TS);
		}

		fputs(line,TS);

		if( strcasecmp(fname,"Subject") == 0 && Subject[0] == 0 )
			strcpy(Subject,line);
	}
	if( EOH[0] ){
		const char *admin;

		if( From[0] && strcmp(From,sender) != 0 )
			lfprintf(log,TS,"Sender: %s\r\n",sender);

		if( admin = DELEGATE_ADMIN )
			lfprintf(log,TS,"Resent-Sender: %s\r\n",admin);

		if( Subject[0] == 0 && !(Option&RES) )
			lfprintf(log,TS,"Subject: (no subject)\r\n");

		fputs(EOH,TS);
	}

	for(;;){
		if( fgets(line,sizeof(line),mfp) == NULL )
			break;
		fputs(line,TS);
	}

	append_log(Conn,Gw,TS,log);
	return 0;
}

static int nntp_post(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log)
{	CStr(stat,1024);
	CStr(msgid,1024);
	const char *dp;
	int off;
	FILE *sTS,*xfp;
	int rcode;

	if( fgetsHeaderField(mfp,"Message-Id",AVStr(msgid),sizeof(msgid)) ){
		if( (dp = strchr(msgid,'@')) == NULL || dp[1] == 0 ){
			lfprintfx(log,tc,"554 illegal Messae-ID: %s\r\n",msgid);
			return -1;
		}

		lfprintf(log,TS,"STAT %s\r\n",msgid);
		fflush(TS);

		fgets(stat,sizeof(stat),FS);
		lfprintf(log,NULL,"<<< %s",stat);
		if( atoi(stat) == 223 ){
			lfprintfx(log,tc,"554 duplicate Mesage-ID: %s",stat);
			return -1;
		}
		lfprintf(log,NULL,"ok - Mesage-ID: %s\r\n",msgid);
	}else{
		if( Option & RNI ){
			lfprintfx(log,tc,"554 no Message-Id\r\n");
			return -1;
		}
		lfprintf(log,NULL,"no original Message-Id\r\n");
	}

	sTS = TS;
	TS = xfp = TMPFILE("MailToNews");
	rcode = mail_to_news(Conn,Gw,tc,mfp,sender,recipient,log);
	TS = sTS;
	if( rcode != 0 ){
		fclose(xfp);
		return rcode;
	}

	lfprintf(log,TS,"POST\r\n");
	fflush(TS);

	/*
	if( fgets(stat,sizeof(stat),FS) == NULL ){
	*/
	if( fPollIn(FS,60*1000) <= 0 ){
		lfprintf(log,tc,"421 NNTP server didn't respond for POST.\r\n");
		return -1;
	}else
	if( fgetsTimeout(AVStr(stat),sizeof(stat),FS,60) == NULL ){
		lfprintf(log,tc,"421 NNTP server closed before POST.\r\n");
		return -1;
	}else{
		lfprintf(log,NULL,"<<< %s",stat);
	}
	if( atoi(stat) != 340 ){
		fprintf(tc,"554 posting failed: %s",stat);
		fflush(tc);
		return -1;
	}

	/*
	if( mail_to_news(Conn,Gw,tc,mfp,sender,recipient,log) < 0 )
		return -1;
	*/
	/*
	{
		FILE *sTS,*xfp;
		int rcode;

		sTS = TS;
		TS = xfp = TMPFILE("MailToNews");
		rcode = mail_to_news(Conn,Gw,tc,mfp,sender,recipient,log);
		TS = sTS;
		if( rcode == 0 ){
			fseek(xfp,0,0);
			copyfile1(xfp,TS);
		}
		fclose(xfp);
		if( rcode != 0 ){
			return rcode;
		}
	}
	*/
	fseek(xfp,0,0);
	copyfile1(xfp,TS);
	fclose(xfp);

	lfprintf(log,TS,".\r\n");
	fflush(TS);

	if( fgets(stat,sizeof(stat),FS) == NULL ){
		lfprintfx(log,tc,"421 NNTP server closed during POST.\r\n");
		return -1;
	}

	lfprintf(log,NULL,"<<< %s",stat);
	if( atoi(stat) != 240 ){
		fprintf(tc,"554 posting failed: %s",stat);
		fflush(tc);
		return -1;
	}

	return 0;
}
static int setFilter(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,FILE *log);

static int nntp_open(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(recipient),int pc,const char *pv[],FILE *log) 
{	int pi;
	const char *p1;
	const char *host;
	int port;
	CStr(stat,1024);
	int server;
	const char *auth;
	CStr(authb,128);
	CStr(user,128);
	CStr(pass,128);

	for( pi = 0; pi < pc; pi++ ){
		const char *p1;
		CStr(tag,128);
		CStr(val,128);
		int px;

		p1 = pv[pi];
		Xsscanf(p1,"%[^.].%s",AVStr(tag),AVStr(val));
		px = param_idx(tag);
		if( px < 0 ){
			lfprintf(log,tc,"config. error -- unknown [%s]\n",p1);
			return -1;
		}
		Gw->g_pv[px] = stralloc(val);
	}

	host = getv(SERVHOST);
	if( p1 = getv(SERVPORT) )
		port = atoi(p1);
	else	port = 0;
	if( port == 0 )
		port = 119;

	lfprintf(log,NULL,"connecting to -- nntp://%s:%d\r\n",host,port);
	set_realserver(Conn,"nntp",host,port);
	Conn->no_dstcheck_proto = serviceport("nntp");

	if( setFilter(Conn,Gw,tc,mfp,log) != 0 )
		return -1;
	server = connect_to_serv(Conn,FromC,ToC,0);
	setFTOSV(GFILTER);
	if( server < 0 ){
		if( ConnError & CO_REJECTED )
			lfprintfx(log,tc,"554 cannot connect NNTP (Forbidden)\r\n");
		else	lfprintfx(log,tc,"421 %s... cannot connect NNTP\r\n",recipient);
		fflush(tc);
		return -1;
	}

	FS = fdopen(FromS,"r");
	TS = fdopen(ToS,"w");

	fgets(stat,sizeof(stat),FS);
	lfprintf(log,NULL,"<<< %s",stat);

	if( auth = getv(CTL_MYAUTH) ){
		nonxalpha_unescape(auth,AVStr(authb),1);
		auth = authb;
	}else
	if( get_MYAUTH(Conn,AVStr(authb),"nntp",host,port) )
		auth = authb;
	if( auth ){
		fieldScan(auth,user,pass);
		fprintf(TS,"AUTHINFO USER %s\r\n",user);
		fflush(TS);
		fgets(stat,sizeof(stat),FS);
		lfprintf(log,NULL,"AUTHINFO USER %s -> %s",user,stat);
		fprintf(TS,"AUTHINFO PASS %s\r\n",pass);
		fflush(TS);
		fgets(stat,sizeof(stat),FS);
		lfprintf(log,NULL,"AUTHINFO PASS **** -> %s",stat);
	}

	return 0;
}
static int postnews(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),int pc,const char *pv[],FILE *log)
{	int size;

	/* must skip header and see the size of body ... */
	size = file_size(fileno(mfp)) - ftell(mfp);
	lfprintf(log,NULL,"#### BODY SIZE = %d\n",size);
	if( size == 0 && Option & REB ){
		/* ... */
	}

	if( nntp_open(Conn,Gw,tc,mfp,recipient,pc,pv,log) != 0 )
		return -1;
	else
	if( nntp_post(Conn,Gw,tc,mfp,sender,recipient,log) != 0 )
		return -1;

	DoBCC = 1;
	fputs("QUIT\r\n",TS);
	fflush(TS);

	return 0;
}


int issue_capskey(FILE *out,PVStr(capsresp),PVStr(retTo),PCStr(req),PCStr(from),PCStr(to));
static void capsgen(FILE *in,FILE *out,FILE *log,PCStr(from),PCStr(to),PVStr(retTo)){
	IStr(line,1024);
	int incaps = 0;
	IStr(capsreq,4*1024);
	refQStr(cp,capsreq);
	IStr(capsresp,4*1024);

	for(;;){
		if( fgets(line,sizeof(line),in) == 0 )
			break;
		if( strheadstrX(line,"-----BEGIN CAPS",0) ){
			fprintf(out,"%s",line);
			Rsprintf(cp,"%s",line);
			incaps = 1;
		}else
		if( strheadstrX(line,"-----END CAPS",0) ){
			fprintf(out,"%s",line);
			Rsprintf(cp,"%s",line);
			incaps = 0;
			lfprintf(log,NULL,"CAPS REQUEST\n%s",capsreq);
			fprintf(out,"\r\n");
			issue_capskey(out,AVStr(capsresp),AVStr(retTo),capsreq,from,to);
			lfprintf(log,NULL,"CAPSKEY\n%s",capsresp);
		}else
		if( incaps ){
			fprintf(out,"%s",line);
			Rsprintf(cp,"%s",line);
		}
	}
}
static int ftpmail(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log)
{	FILE *fpv[2],*ts,*fs;
	CStr(host,MaxHostNameLen);
	IStr(stime,128);
	int port;
	int rsock;
	CStr(resp,1024);
	IStr(subj,1024);
	IStr(retTo,128);
	const char *reta;
	IStr(cte,128);
	FILE *xqfp = 0; /* decoded request mail */
	FILE *qfp;
	FILE *tmp;
	int moff;

	qfp = TMPFILE("reqmail");
	moff = ftell(mfp);
	fseek(mfp,0,0);

	fgetsHeaderField(mfp,"Content-Transfer-Encoding",AVStr(cte),sizeof(cte));
	if( strcaseeq(cte,"quoted-printable") ){
		IStr(line,1024);
		IStr(xline,1024);
		xqfp = TMPFILE("QP-MAIL");
		for(;;){
			if( fgets(line,sizeof(line),mfp) == 0 )
				break;
			str_fromqp(line,strlen(line),AVStr(xline),sizeof(xline));
			fputs(xline,xqfp);
		}
		fflush(xqfp);
		fseek(xqfp,0,0);
		fseek(mfp,0,0);
	}
	copyfile1(mfp,qfp);
	fseek(qfp,0,0);
	fseek(mfp,moff,0);

	tmp = TMPFILE("ftpmail");

	fgetsHeaderField(mfp,"Subject",AVStr(subj),sizeof(subj));
	if( strcasestr(recipient,"capsreq") ){
		Strins(AVStr(subj),"[CAPS] Re: ");
	}else{
		Strins(AVStr(subj),"Re: ");
	}
	fprintf(tmp,"Subject: %s\r\n",subj);
	fprintf(tmp,"From: %s\r\n",recipient);
	fprintf(tmp,"To: %s\r\n",sender); /* should be "retTo" */
	fprintf(tmp,"\r\n");

	moff = ftell(mfp);
	fseek(mfp,0,0);
	if( xqfp ){
		capsgen(xqfp,tmp,log,sender,recipient,AVStr(retTo));
		fclose(xqfp);
		xqfp = 0;
	}else
	capsgen(mfp,tmp,log,sender,recipient,AVStr(retTo));
	fseek(mfp,moff,0);

	fprintf(tmp,"\r\n");
	if( !streq(retTo,sender) ){
		IStr(from,128);

		fgetsHeaderField(mfp,"From",AVStr(from),sizeof(from));
		sv1log("## Sender=%s From=%s ADMIN=%s\n",sender,from,retTo);
		fprintf(tmp,"\r\n");
		fprintf(tmp,"**** WARNING: inconsistent MIME/SMTP/CAPS\r\n");
		fprintf(tmp,"SMTP-Sender:%s\r\n",sender);
		fprintf(tmp,"MIME-From:%s\r\n",from);
		fprintf(tmp,"ADMIN=%s\r\n",retTo);
		fprintf(tmp,"****\r\n");
	}

	fprintf(tmp,"\r\n");
	fprintf(tmp,"\r\n-----BEGIN YOUR SMTP REQUEST-----\r\n");
	StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_ANSI_C,time(0),0);
	fprintf(tmp,"Date: %s\r\n",stime);
	fprintf(tmp,"Your-Host: %s\n",Client_Host);
	fprintf(tmp,"\r\n");
	copyfile1(qfp,tmp);
	fprintf(tmp,"\r\n-----END YOUR SMTP REQUEST-----\r\n");

	rsock = -1;
	port = 25;
	if( !localsocket(ClientSock) ){
		getClientHostPort(Conn,AVStr(host)); /* should use HELO ? */
		rsock = SMTP_open(Conn,fpv,host,port,retTo,recipient,1,log);
		if( rsock < 0 )
		if( strcasestr(recipient,"capsreq") ){
			int generic_domain_email(PVStr(ghost));
			IStr(ghost,MaxHostNameLen);
			strcpy(ghost,host);
			if( generic_domain_email(AVStr(ghost)) ){
				rsock = SMTP_open(Conn,fpv,ghost,port,retTo,recipient,1,log);
			}
			if( rsock < 0 ){
				/* restricting not to be used for SPAM or DoS
				 * generation, but maybe, should try SMTP of
				 * MAIL:From or From: in the header ...
				 */
			}
		}
	}
	if( rsock < 0 ){
		gethostname(host,sizeof(host));
		rsock = SMTP_open(Conn,fpv,host,port,retTo,recipient,1,log);
	}
	if( rsock < 0 ){
		lfprintf(log,tc,"421 cannot open SMTP for response.\r\n");
		fclose(tmp);
		fclose(qfp);
		return -1;
	}

	fs = fpv[0];
	ts = fpv[1];

	fseek(tmp,0,0);
	copyfile1(tmp,ts);
	lfprintf(log,ts,".\r\n");
	fflush(ts);
	SMTP_relay_stat(fs,NULL,AVStr(resp));

	lfprintf(log,ts,"QUIT\r\n");
	fflush(ts);
	SMTP_relay_stat(fs,NULL,AVStr(resp));

	fseek(mfp,0,2);
	fprintf(mfp,"\r\n----------BEGIN RESPONSE----------\r\n");
	fseek(tmp,0,0);
	copyfile1(tmp,mfp);
	fprintf(mfp,"\r\n----------END RESPONSE----------\r\n");
	DoBCC = 1;

	if( strcasestr(recipient,"capsreq") ){
		fseek(mfp,0,0);
		fseek(tmp,0,0);
		while( fgets(resp,sizeof(resp),mfp) != NULL ){
			if( resp[0]=='.' && (resp[1]=='\r' || resp[1]=='\n') )
				break;
			if( strheadstrX(resp,"Subject:",1) ){
				Strins(DVStr(resp,8)," BCC: [CAPS] Re:");
			}
			if( strheadstrX(resp,"Content-Transfer-Encoding:",1) ){
				/* suppress quoted-pritable for PARAM=VALUE */
				Strins(AVStr(resp),"X-Original-");
			}
			fputs(resp,tmp);
		}
		copyfile1(mfp,tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		fseek(mfp,0,0);
		copyfile1(tmp,mfp);
	}
	fclose(tmp);
	fclose(qfp);
	return 0;
}
static int responder(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log){
	int rcode;
	rcode = ftpmail(Conn,Gw,tc,mfp,sender,recipient,log);
	return rcode;
}

static void rewrite_maildata(Connection *Conn,Gateway *Gw,FILE *ts,FILE *mfp,FILE *log)
{	CStr(line,LNSIZE);
	CStr(fname,LNSIZE);
	int off = ftell(mfp);

	if( CCXactive(CCX_TOSV) ){
		MimeEnv me;
		int oc;
		const char *ics;
		const char *ocs;
		CStr(xline,8*1024);
		CCXP ccx = CCX_TOSV;
		FILE *tmp;
		int osize;
		int nsize;

		if( (tmp = TMPFILE("SMTP-CCX")) == 0 ){
			return;
		}
		me.me_filter = 0xF; /* O_ALL */
		me.me_ccx = ccx;
		fflush(mfp);
		osize = file_size(fileno(mfp));
		fseek(mfp,off,0);
		PGPencodeMIMEXX(&me,mfp,tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		fseek(mfp,off,0);
		copyfile1(tmp,mfp);
		fclose(tmp);
		fflush(mfp);
		Ftruncate(mfp,0,1);
		fseek(mfp,off,0);
		nsize = file_size(fileno(mfp));

		CCXoutcharset(ccx,&ocs);
		if( ocs == 0 ) ocs = "";
		ics = CCXident(ccx);
		sv1log("SMTP-CCX [%s] -> [%s] %d -> %d\n",ics,ocs,osize,nsize);
	}

	rewrite_header(Conn,Gw,mfp,ts,Sender,log);
	for(;;){
		if( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),mfp) == NULL )
			break;

		Xsscanf(line,"%[^: ]",AVStr(fname));
		if( strcaseeq(fname,"Subject" ) && Subject[0]
		 || strcaseeq(fname,"Reply-To") && ReplyTo[0]
		){
			fprintf(ts,"X-Original-");
		}
		if( strcaseeq(fname,"From") && getv(OUT_FROM) )
			continue;
		if( strcaseeq(fname,"Message-ID") && getv(OUT_MESSAGE_ID) )
			continue;

		fputs(line,ts);
		if( line[0] == '\r' || line[0] == '\n' )
			break;
	}
	relayMSGdata(mfp,ts,1,0);
}
static int put_maildata(Connection *Conn,Gateway *Gw,FILE *ts,FILE *fs,FILE *mfp,PCStr(recipients),PVStr(resp),FILE *log)
{
	SMTP_putserv(log,fs,ts,AVStr(resp),"DATA\r\n");
	if( atoi(resp) != 354 )
		return -1;

	smtp_datamark(Conn,ts);

	if( (Option & NTR) == 0 )
		put_trace(Conn,Gw,log,ts,recipients);
	rewrite_maildata(Conn,Gw,ts,mfp,log);
	
	append_log(Conn,Gw,ts,log);
	lfprintf(log,ts,".\r\n");
	fflush(ts);
	SMTP_relay_stat(fs,NULL,AVStr(resp));

	if( atoi(resp) == 250 ){
		PageCountUpURL(Conn,CNT_TOTALINC,"#sent",NULL);
	}
	return atoi(resp);
}

static int mxaddr(PCStr(host),PVStr(saddr))
{	const char *dp;
	CStr(rechost,MaxHostNameLen);
	CStr(mxhost,MaxHostNameLen);
	const char *mxaddr;

	if( (dp = strchr(host,'@')) == 0 ){
		if( saddr )
			strcpy(saddr,"0.0.0.0");
		return 0;
	}
	Xsscanf(dp+1,"%[-.A-Za-z0-9]",AVStr(rechost));
	sprintf(mxhost,"-MX.%s",rechost);
	if( mxaddr = gethostaddr(mxhost) )
		Verbose("#### MX-HOST(%s) = %s\n",host,mxaddr);
	else
	if( mxaddr = gethostaddr(rechost) ){
	}else{
		mxaddr = "255.255.255.255";
	}
	if( saddr )
		strcpy(saddr,mxaddr);
	return _inet_addrV4(mxaddr);
}
static int sortbymx(PCStr(a1),PCStr(a2))
{	int i1,i2;
	int rcode;

	i1 = mxaddr(a1,VStrNULL);
	i2 = mxaddr(a2,VStrNULL);
	if( i1 == i2 )
		return strcmp(a1,a2);
	else	return i1 - i2;
}

int sendmail_at(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(host),int port,PCStr(recipients),PCStr(sender),FILE *log);

static int sendmail_mx(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log)
{	const char *recb;
	const char *recv[0x4000]; /**/
	int rc,ri,rj,rx;
	int st,rcode;
	CStr(rechost,MaxHostNameLen);
	CStr(mxhost,MaxHostNameLen);
	CStr(addr,MaxHostNameLen);
	const char *dp;
	CStr(reclist,256);
	int port;

	recb = stralloc(recipient);
	rc = list2vect(recb,',',0x4000,recv);
	if( rc == 0 ){
		lfprintf(log,tc,"554 no recipient\r\n");
		fflush(tc);
		return -1;
	}
	qsort(recv,rc,sizeof(char*),(sortFunc)sortbymx);

	rcode = 0;
	port = 25;

	for( ri = 0; ri < rc; ri = rj + 1 ){
		for( rj = ri; rj < rc-1; rj++ )
		if( mxaddr(recv[rj],VStrNULL) != mxaddr(recv[rj+1],VStrNULL) )
			break;

		{	refQStr(rp,reclist); /**/
			reclist[0] = 0;
			for( rx = ri; rx <= rj; rx++ ){
				assertVStr(reclist,rp+1+strlen(recv[rx]));
				if( ri < rx )
					setVStrPtrInc(rp,',');
				strcat(rp,recv[rx]);
				rp += strlen(rp);
			}
		}
		if( dp = strchr(recv[ri],'@') ){
			wordScan(dp+1,rechost);
			Xsscanf(rechost,"%[-.A-Za-z0-9]",AVStr(addr));
		}else
		mxaddr(recv[ri],AVStr(addr));
		st = sendmail_at(Conn,Gw,tc,mfp,addr,port,reclist,sender,log);
		if( st != 0 )
			rcode = -1;
	}
	free((char*)recb);
	return rcode;
}

int sendmail_at(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(host),int port,PCStr(recipients),PCStr(sender),FILE *log)
{	FILE *RCPT;
	CStr(recipient,1024);
	const char *np;
	FILE *fpv[2],*ts,*fs;
	int rsock;
	CStr(resp,1024);
	int nrec,nrec1,nerr,ri;
	int rcode = 0;

	RCPT = expand_aliases(recipients,log);
	if( RCPT == NULL ){
		lfprintf(log,tc,"421 error in alias expansion\r\n");
		return -1;
	}
	fgets(recipient,sizeof(recipient),RCPT);
	if( np = strpbrk(recipient,"\r\n") )
		truncVStr(np);
	/*
	rsock = SMTP_open(Conn,fpv,host,port,recipient,sender,0,log);
	*/
	rsock = SMTP_openX(Conn,fpv,host,port,recipient,sender,0,log,AVStr(resp));
	setFTOSV(GFILTER);
	if( rsock < 0 ){
		if( 400 <= atoi(resp) ){
			lfprintf(log,tc,"%s",resp);
			return -1;
		}
		lfprintf(log,tc,"421- cannot open SMTP for forwarding.\r\n");
		lfprintf(log,tc,"421  server = %s:%d.\r\n",host,port);
		return -1;
	}

	fs = fpv[0];
	ts = fpv[1];
	nrec = 1;
	nerr = 0;

	while( !feof(RCPT) ){
		for( nrec1 = 0; nrec1 < 64; nrec1++ ){
			if( fgets(recipient,sizeof(recipient),RCPT) == NULL )
				break;
			if( np = strpbrk(recipient,"\r\n") )
				truncVStr(np);
			lfprintf(log,ts,"RCPT To: %s\r\n",recipient);
			nrec++;
		}
		fflush(ts);
		for( ri = 0; ri < nrec1; ri++ ){
			SMTP_relay_stat(fs,NULL,AVStr(resp));
			if( atoi(resp) != 250 ){
				lfprintf(log,NULL,"[%d] %s",ri,resp);
				nerr++;
			}
		}
	}
	if( nerr != 0 ){
		lfprintf(log,tc,"421 NOT sent: RCPT errors %d/%d\r\n",nerr,nrec);
		rcode = -1;
	}else{
		put_maildata(Conn,Gw,ts,fs,mfp,recipients,AVStr(resp),log);
		lfprintf(log,NULL,"Sent to %d recipients\r\n",nrec);
		if( 400 <= atoi(resp) ){
			lfprintf(log,tc,"%s",resp);
			rcode = -1;
		}
	}

	lfprintf(log,ts,"QUIT\r\n");
	fflush(ts);
	SMTP_relay_stat(fs,NULL,AVStr(resp));

	YYfinishSV(FL_ARG,Conn);
	if( lMULTIST() ){
		CTX_fcloses(FL_ARG,"SMTPGATE",Conn,fpv[1],fpv[0]);
	}else{
	fclose(fpv[1]);
	fclose(fpv[0]);
	}
	FromS = ToS = -1;
	fclose(RCPT);

	return rcode;
}
static int smmdgate(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log){
	CStr(subj,256);
	CStr(from,MaxHostNameLen);
	CStr(addr,256);
	CStr(com,256);
	CStr(arg1,256);
	CStr(arg2,256);
	CStr(arg3,256);
	const char *dp;
	FILE *gmfp;
	const char *mjdm;
	const char *auth;
	CStr(authb,256);
	CStr(user,256);
	CStr(pass,256);
	int rcode;
	FILE *gwlog;
	CStr(rpath,1024);

	fgetsHeaderField(mfp,"From",AVStr(from),sizeof(from));
	fgetsHeaderField(mfp,"Subject",AVStr(subj),sizeof(subj));

	if( gwlog = open_file(Rname,"smmdgate.log","a",AVStr(rpath)) ){
		CStr(st,128);
		StrftimeLocal(AVStr(st),sizeof(st),"%Y%m%d-%H%M%S",time(0),0);
		fprintf(gwlog,"%s (%s) (%s) %s\n",st,sender,from,subj);
		fclose(gwlog);
	}

	if( *from == 0 ){
		lfprintf(log,tc,"554 no From\r\n");
		fflush(tc);
		return -1;
	}
	if( *subj == 0 ){
		lfprintf(log,tc,"554 no Subject\r\n");
		fflush(tc);
		return -1;
	}
	RFC822_addresspartX(from,AVStr(addr),sizeof(addr));
	if( strchr(addr,'@') == 0 ){
		lfprintf(log,tc,"554 bad From\r\n");
		fflush(tc);
		return -1;
	}

	truncVStr(com);
	truncVStr(arg1);
	truncVStr(arg2);
	truncVStr(arg3);
	Xsscanf(subj,"%s %s %s %[^\r\n]",AVStr(com),AVStr(arg1),AVStr(arg2),AVStr(arg3));
	if( strcaseeq(com,"listserv") ){
		strcpy(com,arg1);
		strcpy(arg1,arg2);
	}
	if( strcaseeq(com,"subscribe")
	 || strcaseeq(com,"unsubscribe")
	){
		if( arg1[0] == 0 ){
			lfprintf(log,tc,"554 no listname\r\n");
			fflush(tc);
			return -1;
		}
	}else{
		lfprintf(log,tc,"554 unknown command\r\n");
		fflush(tc);
		return -1;
	}

	if( (mjdm = getv(OUT_TO)) == 0
	 && (mjdm = getv(CTL_RECIPIENT)) == 0
	){
		lfprintf(log,tc,"554 config-error R\r\n");
		fflush(tc);
		return -1;
	}
	if( (auth = getv(CTL_MYAUTH)) == 0 ){
		lfprintf(log,tc,"554 config-error P\r\n");
		fflush(tc);
		return -1;
	}
	nonxalpha_unescape(auth,AVStr(authb),1);
	fieldScan(authb,user,pass);
	gmfp = TMPFILE("SMMDGATE");
	if( (sender = getv(CTL_SENDER)) == 0 )
		sender = DELEGATE_ADMIN;

	fprintf(gmfp,"Subject: ServiceMail to Majordomo gateway\r\n");
	fprintf(gmfp,"From: %s\r\n",sender);
	fprintf(gmfp,"To: %s\r\n",mjdm);
	fprintf(gmfp,"\r\n");
	fprintf(gmfp,"approve %s %s %s %s\r\n",pass,com,arg1,addr);
	fflush(gmfp);
	fseek(gmfp,0,0);

	rcode = sendmail_mx(Conn,Gw,tc,gmfp,sender,mjdm,log);
	fclose(gmfp);
	return rcode;
}
static int sendmail(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,PCStr(sender),PCStr(recipient),FILE *log)
{	const char *p1;
	const char *host;
	int port;
	const char *to;
	CStr(tobuf,0x10000);
	const char *rp;
	int off;
	const char *from;

	if( from = getv(CTL_SENDER) )
		sender = from;

	to = getv(OUT_TO);
	rp = getv(CTL_RECIPIENT);
	if( (to == NULL || *to == 0) && (rp == NULL || *rp == 0) ){
		lfprintf(log,tc,"554 no forwarding info.\r\n");
		fflush(tc);
		return -1;
	}
	if( rp != NULL && *rp != 0 )
		substitute(Gw,mfp,rp,AVStr(tobuf),log,sender);
	else	substitute(Gw,mfp,to,AVStr(tobuf),log,sender);
	to = tobuf;

	host = getv(SERVHOST);
	if( streq(host,V_RECMX) ){
		off = ftell(mfp);
		if( sendmail_mx(Conn,Gw,tc,mfp,sender,to,log) < 0 )
			return -1;
		fseek(mfp,off,0);
	}else{
		if( p1 = getv(SERVPORT) ) 
			port = atoi(p1);
		else	port = 0;
		if( port == 0 )
			port = 25;

		if( setFilter(Conn,Gw,tc,mfp,log) != 0 )
			return -1;

		off = ftell(mfp);
		if( sendmail_at(Conn,Gw,tc,mfp,host,port,to,sender,log) < 0 )
			return -1;
		fseek(mfp,off,0);
	}
	DoBCC = 1;

	return 0;
}

/*
 *	BCC: <user@host.domain:port>
 *
 *	TO-DO: multiple recipients which should be sent to the same SMTP
 *	server in BCC should be grouped in a single SMTP transmission...
 */
static scanListFunc sendBCC1(PCStr(bcc),Connection *Conn,Gateway *Gw,FILE *mfp,FILE *log)
{	CStr(host,MaxHostNameLen);
	const char *sender;
	int port;
	int off;
	int i1;
	CStr(addr,64);

	host[0] = 0;
	port = 0;

	while( *bcc == ' ' || *bcc == '\t' )
		bcc++;

	Xsscanf(bcc,"%*[^@]@%[^:]:%d",AVStr(host),&port);
	if( host[0] == 0 )
		strcpy(host,"localhost");
	if( port == 0 )
		port = 25;
	sender = DELEGATE_ADMIN;

	if( i1 = mxaddr(bcc,AVStr(addr) ))
	if( i1 != _inet_addrV4("255.255.255.255") ){
	lfprintf(log,NULL,"sending BCC -- %s [smtp://%s] MX=[%s]\n",
			bcc,host,addr);
		strcpy(host,addr);
	}

	lfprintf(log,NULL,"sending BCC -- %s [smtp://%s:%d] sender=%s\n",
		bcc,host,port,sender);

	off = ftell(mfp);
	sendmail_at(Conn,Gw,log,mfp,host,port,bcc,sender,log);
	fseek(mfp,off,0);
	return 0;
}
static void sendBCC(Connection *Conn,Gateway *Gw,FILE *mfp,FILE *log)
{	const char *bcc;
	CStr(name,1024);
	CStr(rpath,1024);

	bcc = getv(BCC);
	if( bcc == NULL )
		return;
	scan_commaList(bcc,0,scanListCall sendBCC1,Conn,Gw,mfp,log);
}

static int lock_counter1(FILE *counter,PCStr(rpath),int timeout)
{
	if( lock_exclusiveTO(fileno(counter),timeout,NULL) == 0 )
		return 0;
	sv1log("#### cannot lock COUNTER: %s\r\n",rpath);
	return -1;
}
static FILE *lock_counter(PCStr(name),FILE *mfp,int *countp,FILE *log)
{	CStr(rpath,1024);
	FILE *counter;
	int opid,otime;
	CStr(line,1024);
	int count;

	*countp = 0;
	if( *name == 0 )
		return NULL;

	if( counter = open_file(name,"count","r+",AVStr(rpath)) ){
		if( lock_counter1(counter,rpath,60*1000) != 0 ){
			fclose(counter);
			return NULL;
		}
		count = 0;
		opid = 0;
		fgets(line,sizeof(line),counter);
		sscanf(line,"%d pid=%d time=%d",&count,&opid,&otime);
		if( count == 0 )
			count = 1;
	}else
	if( counter = open_file(name,"count","w+",AVStr(rpath)) ){
		if( lock_counter1(counter,rpath,1) != 0 ){
			fclose(counter);
			return NULL;
		}
		lfprintf(log,NULL,"created counter -- SMTPGATE/%s\r\n",rpath);
		fprintf(counter,"1 pid=%d\r\n",getpid());
		fflush(counter);
		count = 1;
		opid = getpid();
		otime = time(0);
	}else{
		sv1log("#### cannot open COUNTER: %s\r\n",rpath);
		return NULL;
	}

	lfprintf(log,NULL,"got Counter -- %d : SMTPGATE/%s\n",count,rpath);
	*countp = count;
	return counter;
}
static void unlock_counter(FILE *counter,int count,int inc,FILE *log)
{
	if( inc ){
		fseek(counter,0,0);
		count += inc;
		fprintf(counter,"%d pid=%d time=%d\r\n",
			count,getpid(),itime(0));
		fflush(counter);
		lfprintf(log,NULL,"set Counter -- %d\r\n",count);
	}
	fclose(counter);
}

static void lfprintf1(FILE *log,PCStr(fmt),...)
{
	VARGS(8,fmt);
	lfprintf(log,NULL,fmt,VA8);
}

static int match_aclfile(PCStr(what),PCStr(addr),PCStr(acladdr),FILE *afp,FILE *log)
{	CStr(line,1024);
	const char *dp;
	int nlines;

	for( nlines = 1; fgets(line,sizeof(line),afp) != NULL; nlines++ ){
		if( strcasestr(line,addr) == NULL )
			continue;

		sv1log("#### found -- <%s> at line#%d of %s\n",addr,nlines,acladdr);
		if( dp = strpbrk(line,"\r\n") )
			truncVStr(dp);
		lfprintf(log,NULL,"accept %s -- <%s> is in the ACL as '%s'\r\n",
			what,addr,line);
		return 1;
	}
	sv1log("#### not found -- <%s> in %s\n",addr,acladdr);
	return 0;
}
static int check_infile(FILE *tc,PCStr(what),PCStr(addr),PCStr(acl),FILE *log)
{	FILE *afp;

	afp = fopen(acl,"r");
	if( afp == NULL ){
		lfprintf(log,tc,"554 cannot open the ACL file.\n");
		fflush(tc);
		return -1;
	}
	return match_aclfile(what,addr,acl,afp,log);
}
static int check_byexpn(FILE *tc,PCStr(what),PCStr(addr),PCStr(acladdr),FILE *log)
{	FILE *afp;

	afp = SMTP_getEXPN(acladdr);
	if( afp == NULL ){
		lfprintf(log,tc,"554 cannot get EXPN <%s>\n",addr);
		fflush(tc);
		return -1;
	}
	return match_aclfile(what,addr,acladdr,afp,log);
}
static int tobe_rejected(FILE *tc,PCStr(what),PCStr(addr),PCStr(acli),FILE *log)
{	const char *av[256]; /**/
	const char *acla;
	const char *aclb;
	defQStr(aclc); /*alloc*/
	const char *acl0;
	const char *acl1;
	CStr(acladdr,256);
	int ac,ai,negate,match,subst;
	defQStr(aclp); /*alloc*//**/

	acla = stralloc(acli);
	aclb = stralloc(acli);
	setQStr(aclc,(char*)malloc(strlen(acli)+1),strlen(acli)+1);
	cpyQStr(aclp,aclc);
	ac = stoV(acla,256,av,',');

	for( ai = 0; ai < ac; ai++ ){
		acl1 = av[ai];
		acl1 = acl0 = strip_spaces(acl1);
		if( negate = (*acl1 == '!') )
			acl1++;

		if( subst = isFullpath(acl1) ){
			match = check_infile(tc,what,addr,acl1,log);
			if( match < 0 )
			{
				sv1log("ACL ERROR: [%s]\n",acl1);
				goto EXIT;
			}
		}else
		if( subst = (strncmp(acl1,"${expn:",7)==0) ){
			acladdr[0] = 0;
			Xsscanf(acl1,"${expn:%[^}]}",AVStr(acladdr));
			match = check_byexpn(tc,what,addr,acladdr,log);
			if( match < 0 )
				goto EXIT;
		}
		if( subst ){
			if( match ){
				if( aclp != aclc)
					setVStrPtrInc(aclp,',');
				if( negate )
					setVStrPtrInc(aclp,'!');
				strcpy(aclp,"*");
			}
		}else{
			if( aclp != aclc) setVStrPtrInc(aclp,',');
			strcpy(aclp,acl0);
		}
		aclp += strlen(aclp);
	}
	lfprintf(log,NULL,"preprocessed ACL: [%s] -> [%s]\n",acli,aclc);

	if( match = strmatch_list(addr,aclc,"",(iFUNCP)lfprintf1,log) ){
		lfprintf(log,NULL,"accept %s -- %s is in [%s]\r\n",
			what,addr,aclc);
	}else{
		lfprintfx(log,NULL,"reject %s -- %s is not in [%s]\r\n",
			what,addr,aclc);
		lfprintf(log,tc,"554 Forbidden by rule\r\n");
		fflush(tc);
	}
EXIT:
	free((char*)acla);
	free((char*)aclb);
	free((char*)aclc);
	return match ? 0 : -1;
}

static int setFilter(Connection *Conn,Gateway *Gw,FILE *tc,FILE *mfp,FILE *log)
{	const char *filter;

	filter = getv(OUT_FILTER);
	if( filter == NULL )
		return 0;

	lfprintf(log,NULL,"FILTER: %s\r\n",filter);
	/*
	scan_FTOSV(filter);
	*/
	scan_FTOSV(Conn,filter);
	return 0;
}

/*
 * split an incomplete line to the current line part and the part to be
 * processed as the next line.
 */
const char *QPsplitLine(int QP,PVStr(line),int *nextch){
	refQStr(tp,line);
	refQStr(bp,line);
	int ch;

	if( *line == 0 )
		return 0;
	for( tp = line; tp[1]; tp++ );
	if( QP ){
		bp = tp;
		if( line < bp && *bp-- == '\n' ){
			if( line < bp && *bp == '\r' )
				bp--;
			if( line < bp && *bp == '=' ){
				clearVStr(bp);
				tp = bp - 1;
			}
		}
	}
	if( *tp == '\n' ){
		/* complete line */
		return 0;
	}
	for( tp--; line < tp; tp-- ){
		ch = *tp;
		if( isspace(ch)
		 || ch == '&' || ch == '?'
		 || ch == '"' || ch == '>'
		){
			if( nextch ) *nextch = ch;
			clearVStr(tp);
			return tp+1;
		}
	}
	return 0;
}

static int find_usertext(FILE *tc,FILE *mfp,int soff,FILE *log,PCStr(p1))
{	CStr(line,128);
	int match;
	int QP = 0;

	match = 0;
	if( fgetsHeaderField(mfp,"Subject",AVStr(line),sizeof(line)) != 0 )
	{
		match = strmatch_list(line,p1,"",NULL,NULL);
		if( match == 0 && strstr(line,"=?") ){
			CStr(xline,128);
			MIME_strHeaderDecode(line,AVStr(xline),sizeof(xline));
			match = strmatch_list(xline,p1,"",NULL,NULL);
		}
	}
	if( match == 0 ){
		IStr(cte,128);
		IStr(pending,2*sizeof(line)); /* split line */
		const char *last;
		const char *next;
		int nextch;

		fgetsHeaderField(mfp,"Content-Transfer-Encoding",
			AVStr(cte),sizeof(cte));
		if( strcasestr(cte,"quoted-printable") ){
			QP = 1;
		}

		RFC821_skipheader(mfp,NULL,NULL);
		while( fgets(line,sizeof(line),mfp) != NULL ){
			if( pending[0] == 0 )
			if( strheadstrX(line,"Content-Transfer-Encoding:",1) ){
				if( strstr(line+26,"quoted-printable") ){
					QP = 2;
				}
			}
			next = QPsplitLine(QP,AVStr(line),&nextch);
			if( pending[0] ){
				/* 9.9.1 don't miss the text at buff. or QP
				 * boundary.  So try to find a text in a window
				 * rather than a line.
				 */
				strcat(pending,line);
				if( strmatch_list(pending,p1,"",NULL,NULL) ){
					sv1log("found in split line: %d\n",QP);
					match = 2;
					break;
				}
				clearVStr(pending);
			}else
			if( strmatch_list(line,p1,"",NULL,NULL) ){
				match = 1;
				break;
			}
			if( next ){
				if( last = QPsplitLine(0,AVStr(line),0) ){ 
					/* see the last word too in the next */
				}else{
					last = "";
				}
				sprintf(pending,"%s%c%s",last,nextch,next);
			}
		}
		fseek(mfp,soff,0);
	}
	return match;
}

/*
 *  REJECT/HEADER:554:fieldname:value
 *  REJECT/HEADER:554,wcs:fieldname: val1, val2 ... substring match,ign. spaces
 *  REJECT/HEADER:554:fieldname:val1,val2,...
 *  REJECT/HEADER:554:head1,head2,...:val1,val2,...
 */
static int find_header(FILE *tc,FILE *mfp,int soff,FILE * log,PCStr(p1)){
	CStr(code,32);
	CStr(fnam,128);
	CStr(fval,1024);
	CStr(value,1024);

	scan_field1(p1,AVStr(code),sizeof(code),AVStr(value),sizeof(value));
	scan_field1(value,AVStr(fnam),sizeof(fnam),AVStr(fval),sizeof(fval));
	if( fnam[0] == 0 ){
		sv1log("SMTPGATE ERROR ACCEPT/Header:%s\n",p1);
		return 0;
	}
	if( fgetsHeaderField(mfp,fnam,AVStr(value),sizeof(value)) ){
		const char *opt;
		/*
		if( isinListX(fval,value,"w") ){
		*/
		if( opt = strchr(code,',') )
			opt++;
		else	opt = "w";
		if( isinListX(fval,value,opt) ){
			lfprintf(log,NULL,"find_header[%s][%s][%s][%s]\n",
				p1,fnam,fval,value);
			return atoi(code);
		}
	}
	fseek(mfp,soff,0);
	return 0;
}

#undef lfprintf
#define lfprintf lfprintfx

#define DEFAULT_CONF "/-/builtin/config/smtpgate/@default/conf";

static void freeGw(Gateway *Gw){
	if( lMULTIST() == 0 )
		return;
	if( Gw == 0 )
		return;
	free(Gw);
}
int SMTPgateway(Connection *Conn,FILE *tc,FILE *mfp,PCStr(md5),PCStr(hello),PCStr(sender),PCStr(recipient),FILE *log)
{	Gateway *Gw,*BGw;
	CStr(local,1024);
	CStr(domain,1024);
	const char *pv[128]; /**/
	CStr(pb,1024);
	const char *p1;
	const char *gwname;
	const char *parent;
	int pc,pi;
	CStr(params,1024);
	const char *local1;
	const char *local2;
	int lev;
	int rcode = 0;
	int delay = 0;
	FILE *counter,*log1;
	int soff;
	CStr(ereasonb,1024);
	const char *mgw;
	CStr(mgwb,128);
	CStr(mTo,256);
	CStr(mFrom,256);
	int mSize = -1;
	int mBody = -1;

	Gw = 0;
	setQStr(ereason,ereasonb,sizeof(ereasonb));
	setVStrEnd(ereason,0);

	starttime = time(0);
	soff = ftell(mfp);
	/*
	 *  search and select configuration file baed on
	 *  "sender", "recipients" and "mfp"
	 */
	local[0] = domain[0] = 0;
	Xsscanf(recipient,"%[^@]@%s",AVStr(local),AVStr(domain));
	strcpy(pb,local);
	pc = stoV(pb,128,pv,'%');
	if( pc < 1 ){
		lfprintf(log,NULL,"ERROR -- no local part ? [%s]\n",recipient);
		return 0;
	}
	gwname = local1 = local2 = pv[--pc];
	if( gwname == NULL )
		return 0;

	{	refQStr(pp,params); /**/
		params[0] = 0;
		for( pi = 0; pi < pc; pi++ ){
			sprintf(pp,"[%s]",pv[pi]);
			pp += strlen(pp);
		}
	}
	lfprintf(log,NULL,"GWNAME = %s %s\n",gwname,params);
	if( MountOptions && (mgw = strstr(MountOptions,"gateway=")) ){
		wordScanY(mgw+8,mgwb,"^,");
		gwname = local1 = local2 = mgwb;
		lfprintf(log,NULL,"MOUNTED GWNAME = %s %s\n",gwname,params);
	}
	lfprintf(log,NULL,"Content-MD5 = %s\n",md5);

	Gw = new_conf();
	Sender = stralloc(sender);
	Recipient = stralloc(recipient);
	Rname = stralloc(local1);
	fgetsHeaderField(mfp,"To",AVStr(mTo),sizeof(mTo));
	fgetsHeaderField(mfp,"From",AVStr(mFrom),sizeof(mFrom));
	mSize = file_size(fileno(mfp));

	if( load_conf(Conn,Gw,COMMON_CONF,mfp,sender,recipient,log) ){
		/* 9.9.8 to share REJECT/USER-TEXT */
	}
	if( load_conf(Conn,Gw,gwname,mfp,sender,recipient,log) == 0 ){
		lfprintf(log,NULL,"GWNAME = %s (default gateway)\n",DEFAULT);
		if( load_conf(Conn,Gw,DEFAULT,mfp,sender,recipient,log) ){
			if( parent = getv(INHERIT) )
				gwname = parent;
			lfprintf(log,NULL,"GWNAME = %s\n",gwname);
			local2 = DEFAULT;
		}else{
			const char *aurl;
			CStr(rurl,256);
			CStr(buf,2048);
			FILE *fp;
			aurl = DEFAULT_CONF;
			Verbose("SMTPGATE: loading builtin @default/conf ..\n");
			getBuiltinData(Conn,"SMTPGATE",aurl,AVStr(buf),sizeof(buf),AVStr(rurl));
			fp = TMPFILE("SMTPGATE"); fputs(buf,fp); fflush(fp);
			fseek(fp,0,0);
			scan_conf(Gw,fp,log);
			fclose(fp);
		}
	}
	Gw->g_pv[GWTYPE] = stralloc(gwname);

	/*
	 *  load parent if exists
	 */
	for( lev = 0; lev < 4; lev++ ){
		parent = getv(INHERIT);
		if( parent == NULL )
			break;

		if( BGw = builtinGw(parent,1) ){
			gwname = parent;
			break;
		}

		lfprintf(log,NULL,"GWNAME = %s\n",parent);
		if( load_conf(Conn,Gw,parent,mfp,sender,recipient,log) == 0 )
			break;
		parent = getv(INHERIT);
		if( parent != NULL )
			gwname = parent;
	}

	/*
	 *  builtin class
	 */
	if( (BGw = builtinGw(gwname,0)) == NULL ){
		lfprintf(log,NULL,"unknown Gateway Name -- %s\r\n",gwname);
		freeGw(Gw);
		return 0;
	}
	Gw->g_parent = BGw;
	copy_ifundef(Gw,Gw->g_parent);
	lfprintf(log,NULL,"GWNAME = %s (built-in)\n",gwname);

	/*
	 *  access control
	 */
	if( p1 = getv(ACC_CLIENT_HOST) ){
		int hl,match;

		hl = makePathList("SMTPGATE",p1);
		match = matchPath1(hl,"",Client_Host,Client_Port);
		if( !match ){
			lfprintf(log,NULL,"Forbidden Client-Host -- %s\r\n",
				Client_Host);
			lfprintf(log,tc,"554 Forbidden by rule\r\n");
			fflush(tc);
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(ACC_SENDER) ){
		CStr(acc_sender,1024);
		substitute(Gw,mfp,p1,AVStr(acc_sender),log,sender);
		if( tobe_rejected(tc,"Sender",sender,acc_sender,log) != 0 ){
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(ACC_RECIPIENT) ){
		if( tobe_rejected(tc,"Recipient",recipient,p1,log) != 0 ){
			rcode = -1;
			goto EXIT;
		}
	}
	if( mTo[0] == 0 )
	if( p1 = getv(ACC_TO) ){ /* case of lacking To: */
			if( tobe_rejected(tc,"To","",p1,log) != 0 ){
				rcode = -1;
				goto EXIT;
			}
	}
	if( getv(ACC_TO) || getv(ACC_FROM) ){
		if( checkHead(Conn,Gw,tc,mfp,VStrNULL,log) < 0 ){
			rcode = -1;
			goto EXIT;
		}
		fseek(mfp,soff,0);
	}
	if( p1 = getv(ACC_MESSAGE_ID) ){
		CStr(id,128);
		if( fgetsHeaderField(mfp,"Message-Id",AVStr(id),sizeof(id)) != 0 ){
			if( tobe_rejected(tc,"Message-Id",id,p1,log) != 0 ){
				rcode = -1;
				goto EXIT;
			}
		}
	}
	if( p1 = getv(ACC_CONTTYPE) ){
		CStr(ty,128);
		if( fgetsHeaderField(mfp,"Content-Type",AVStr(ty),sizeof(ty)) != 0 ){
			if( tobe_rejected(tc,"Content-Type",ty,p1,log) != 0 ){
				rcode = -1;
				goto EXIT;
			}
		}
	}
	if( p1 = getv(ACC_MAX_BYTES) ){
		int max,siz;
		max = kmxatoi(p1);
		siz = file_size(fileno(mfp)) - soff;
		if( max < siz ){
			lfprintf(log,NULL,"reject %s -- Max-Bytes: %d < %d\r\n",
				"TOO LARG",max,siz);
			lfprintf(log,tc,"554 message too large (%d < %d)\r\n",
				max,siz);
			fflush(tc);
			rcode = -1;
			goto EXIT;
		}
		lfprintf(log,NULL,"accept -- Max-Bytes: %d > %d bytes\r\n",
			max,siz);
	}
	if( p1 = getv(ACC_MIN_BYTES) ){
		int min,siz;
		min = kmxatoi(p1);
		siz = file_size(fileno(mfp)) - soff;
		if( siz < min ){
			lfprintf(log,NULL,"reject %s -- Min-Bytes: %d > %d\r\n",
				"TOO SMALL",min,siz);
			lfprintf(log,tc,"554 message too small (%d > %d)\r\n",
				min,siz);
			fflush(tc);
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(ACC_MIN_BODY_BYTES) ){
		int min,siz;
		min = kmxatoi(p1);
		RFC821_skipheader(mfp,NULL,NULL);
		siz = file_size(fileno(mfp)) - ftell(mfp);
		fseek(mfp,soff,0);
		if( siz < min ){
			lfprintf(log,NULL,
				"reject %s -- Min-Body-Bytes: %d > %d\r\n",
				"TOO SMALL",min,siz);
			lfprintf(log,tc,"554 message too small (%d > %d)\r\n",
				min,siz);
			fflush(tc);
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(ACC_USERTEXT) ){
		if( find_usertext(tc,mfp,soff,log,p1) == 0 ){
			lfprintf(log,tc,"554 not include keyword\r\n");
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(REJ_USERTEXT) ){
		if( find_usertext(tc,mfp,soff,log,p1) ){
			lfprintf(log,tc,"554 include forbidden keyword\r\n");
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(REJ_HEADER) ){
		int rc;
		if( rc = find_header(tc,mfp,soff,log,p1) ){
			lfprintf(log,tc,"%d includes forbidden header\r\n",rc);
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(ACC_MAX_EXCLAMS) ){
		int chcount[256],max;

		max = atoi(p1);
		msg_charcount(mfp,chcount);
		if( max < chcount['!'] ){
			lfprintf(log,NULL,"reject %s -- Max-Exclams: %d<%d\r\n",
				"TOO MANY EXCLAMATIONS",max,chcount['!']);
			lfprintf(log,tc,"554 too many exclamations\r\n");
			rcode = -1;
			goto EXIT;
		}
	}
	if( p1 = getv(DELAY_MESSAGE_ID) ){
		CStr(id,128);
		if( fgetsHeaderField(mfp,"Message-Id",AVStr(id),sizeof(id)) == 0 )
			id[0] = 0;
		if( strmatch_list(id,p1,"",NULL,NULL) ){
			lfprintf(log,NULL,"DO DELAY %s: %s\n","Message-Id",id);
			delay = 1;
		}
	}

	/*
	 *  save FTOSV filter
	 */
	GFILTER = getFTOSV(Conn);

	/*
	 *  call gateways
	 */
	if( p1 = getv(OPTION) )
		Option = scan_options(p1,AVStr(Gwt),log);
	else	Option = 0;
	counter = NULL;

	if( Option & ISN ){
		counter = lock_counter(local2,mfp,&Seqno,log);
		if( counter == NULL ){
			lfprintf(log,tc,"421 cannot open/lock counter.\r\n");
			rcode = -1;
			goto EXIT;
		}
	}

	DoBCC = 0;
	if( strcaseeq(gwname,POSTNEWS) ){
		if( postnews(Conn,Gw,tc,mfp,sender,recipient,pc,pv,log) == 0 )
			rcode =  1;
		else	rcode = -1;
	}else
	if( strcaseeq(gwname,SENDMAIL) ){
		if( sendmail(Conn,Gw,tc,mfp,sender,recipient,log) == 0 )
			rcode =  1;
		else	rcode = -1;
	}else
	if( strcaseeq(gwname,SPOOLER) ){
		rcode =  1;
	}else
	if( strcaseeq(gwname,SMMDGATE) ){
		if( smmdgate(Conn,Gw,tc,mfp,sender,recipient,log) == 0 )
			rcode = 1;
		else	rcode = -1;
	}else
	if( strcaseeq(gwname,RESPONDER) ){
		if( responder(Conn,Gw,tc,mfp,sender,recipient,log) == 0 )
			rcode =  1;
		else	rcode = -1;
	}else
	if( strcaseeq(gwname,FTPMAIL) ){
		if( ftpmail(Conn,Gw,tc,mfp,sender,recipient,log) == 0 )
			rcode =  1;
		else	rcode = -1;
	}

	if( counter != NULL  )
		unlock_counter(counter,Seqno,rcode==1,log);

	if( DoBCC ){
		fseek(mfp,soff,0);
		sendBCC(Conn,Gw,mfp,log);
	}

	if( rcode == 1 ){
		CStr(stime,1024);
		CStr(spath,1024);
		CStr(rpath,1024);
		CStr(unixfrom,1024);
		FILE *sfp;
		int toff;
		const char *arcspec;

		StrftimeLocal(AVStr(stime),sizeof(stime),"%Y%m%d-%H%M%S",starttime,0);
		sprintf(spath,"spool/%05d-%s-%05d",Seqno,stime,getpid());
		make_unixfrom(AVStr(unixfrom),sender);

		if( sfp = open_file(local2,spath,"w",AVStr(rpath)) ){
			fprintf(sfp,"UNIX-From: %s\r\n",unixfrom);
			toff = ftell(mfp);
			fseek(mfp,soff,0);
			copyfile1(mfp,sfp);
			fclose(sfp);
			fseek(mfp,toff,0);
			Verbose("## wrote spool %s : %s\n",local1,rpath);
		}else{
			Verbose("## cannot open spool %s : %s\n",local1,rpath);
		}

		if( arcspec = getv(ARCHIVE) ){
			if( OrigSeqno == 0 && strstr(arcspec,V_ORIGSEQNO)!=0 ){
				OrigSeqno = RFC822_getSeqno(mfp);
			}

			subst_path(Gw,arcspec,AVStr(spath));
			if( sfp = open_file(local2,spath,"a",AVStr(rpath)) ){
				fprintf(sfp,"From %s\r\n",unixfrom);
				fseek(mfp,soff,0);
				rewrite_maildata(Conn,Gw,sfp,mfp,NULL);
				fclose(sfp);
				fseek(mfp,toff,0);
			}
		}
	}

EXIT:
	setQStr(ereason,NULL,0);
	lfprintf(log,NULL,"END(%d) %s <- %s\n",rcode,recipient,sender);
	smtplog(Conn,"SENT[%d] [%s|%s] [%s|%s] %s %d",rcode,
		sender,mFrom,recipient,mTo,md5,mSize);
	if( rcode != 0 ){
		CStr(rpath,1024);
		CStr(rfile,64);
		FILE *rfp;
		if( log1 = open_file(local2,"log","a",AVStr(rpath)) ){
			fflush(log);
			fseek(log,0,0);
			copyfile1(log,log1);
			fclose(log1);
			fseek(log,0,2);
			Verbose("## wrote logfile of %s : %s\n",local1,rpath);
		}else{
			Verbose("## cannot open logfile of %s : %s\n",local1,rpath);
		}
	    if( 0 < rcode ){
		CStr(xRname,128);
		CStr(xgwname,128);
		PageCountUpURL(Conn,CNT_TOTALINC,Rname,NULL);
		sprintf(xgwname,"@%s",gwname);
		PageCountUpURL(Conn,CNT_TOTALINC,xgwname,NULL);
	    }
	    if( rcode < 0 ){
		PageCountUpURL(Conn,CNT_ERRORINC,"#rejected",NULL);
		StrftimeLocal(AVStr(rfile),sizeof(rfile),"rejected/%y%m%d-%H%M%S",
			starttime,0);
		if( rfp = open_file(local2,rfile,"a",AVStr(rpath)) ){
			/*
			fprintf(rfp,"--%s--\n",rfile);
			*/
			fprintf(rfp,"--%s-- %s <- %s %s\n",
				rfile,recipient,sender,ereasonb);
			fseek(mfp,0,0);
			copyfile1(mfp,rfp);
			fclose(rfp);
		}
		if( p1 = getv(CTL_REJTO) ){
		    fseek(mfp,soff,0);
		    if( rfp = TMPFILE("Reject-To") ){
			CStr(buf,256);
			fprintf(rfp,"X-Rejected:");
			getClientHostPort(Conn,AVStr(buf));
			fprintf(rfp," client=%s;",buf);
			lineScan(ereasonb,buf);
			fprintf(rfp," reason=%s;",buf);
			fprintf(rfp," HELO=%s;",hello);
			fprintf(rfp," FROM=%s;",sender);
			fprintf(rfp," RCPT=%s;",recipient);
			fprintf(rfp," ver=DeleGate/%s;",DELEGATE_ver());
			fprintf(rfp,"\r\n");
			copyfile1(mfp,rfp);
			fflush(rfp);
			fseek(rfp,0,0);
			scan_commaList(p1,0,scanListCall sendBCC1,Conn,Gw,rfp,log);
			fclose(rfp);
		    }
		}
		if( p1 = getv(CTL_ETO) ){
		    fseek(mfp,soff,0);
		    if( rfp = TMPFILE("Errors-To") ){
			CStr(buf,256);
			lineScan(ereasonb,buf);
			fprintf(rfp,
				"Subject: --Rejected:%s (by DeleGate/%s)\r\n",
				buf,DELEGATE_ver());
			StrftimeLocal(AVStr(buf),sizeof(buf),TIMEFORM_RFC822,
				starttime,0);
			fprintf(rfp,"Date: %s\r\n",buf);
			getClientHostPort(Conn,AVStr(buf));
			fprintf(rfp,"Summary: HELO:%s POSTED-BY:%s\r\n",
				hello,buf);
			fprintf(rfp,"From: %s (%s)(%s)\r\n",sender,buf,hello);
			fprintf(rfp,"To: %s\r\n",recipient);
			fprintf(rfp,"Content-Type: message/rfc822\r\n");
			fprintf(rfp,"\r\n");
			copyfile1(mfp,rfp);
			fflush(rfp);
			fseek(rfp,0,0);
			scan_commaList(p1,0,scanListCall sendBCC1,Conn,Gw,rfp,log);
			fclose(rfp);
		    }
		}
	    }
	}
	/*
	return rcode;
	*/
	freeGw(Gw);
	return (delay<<4) | rcode; /* return value shold be SmtpStat */
}
