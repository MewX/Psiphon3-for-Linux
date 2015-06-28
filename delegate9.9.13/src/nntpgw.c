/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	nntpgw.c (NNTP / HTTP gateway)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950903	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "delegate.h"
#include "ystring.h"
#include "htswitch.h"
#include "file.h"
#include "http.h"
#include "auth.h"

void minit_nntp();
const char *someGroup();
void subject_headclean(PVStr(subj));
void setProtoOfClient(Connection *Conn,PCStr(proto));
void httpAdmin(Connection *Conn,PVStr(user),FILE *tc,PCStr(group),PVStr(search),void *env,iFUNCP prfunc,sFUNCP ckfunc,PVStr(adminid));
int getSubscription(Connection *Conn,FILE *tc,PCStr(userclass),PCStr(newsgroup),int *subp,int *unsp);

void NNTP_selectXref(int nsid,PCStr(xref1),PVStr(xref2));
FILE *NNTP_openLIST(int nsid,int expire,PCStr(what));
FILE *NNTP_openArticle(int nsid,int expire,PCStr(msgid),PCStr(group),int anum,PVStr(cpath));
int NNTP_newServer(Connection *Conn,PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port,int fromC,int toC,int fromS,int toS);
int NNTP_needAuth(Connection *Conn);
int NNTP_getServer(Connection *Conn,int fromC,int toC,PCStr(group),const char **host,int *port);
int NNTP_getGroupAnum(int nsid,PCStr(msgid),PCStr(group),int anum1,PVStr(rgroup));
void NNTP_getGROUP(int nsid,int expire,PCStr(group),int *nart,int *min,int *max);
int NNTP_closeServerX(Connection *Conn,int nsid);
#define NNTP_closeServer(nsid) NNTP_closeServerX(Conn,nsid)
void NNTP_closeServerFds(Connection *Conn,int nsid);
int NNTP_authERROR(int nsid);
const char *MailGate(Connection *Conn);
int HTSWresponse(Connection *Conn,HtSwitch *swv[],PCStr(query),PCStr(cookie),FILE *fc,FILE *tc,PCStr(urlself),PCStr(urlrealm));
int setPosterMasks(PCStr(from));

extern int DELEGATE_LastModified;

#define LINESIZE	4095

extern int ACLMAX;

int EXPIRE_ART = 24*3600;
int EXPIRE_LIST = 600;
int HTTP_putmenu = 1;

static int xPSIZE = 10;
int ALIST_WINDOW = 10;
int ALIST_MAXWIN = 100;

extern const char *MLHOST;
extern const char *MLSOLT;
extern const char *MLADMIN;
static const char *MyProto = "http";  /* client's protocol (http or https) */

#define HIDE_ANON	0x0001
#define HIDE_NOLOGIN	0x0002
#define HIDE_FROM	0x0010
#define HIDE_BODY	0x0020
#define HIDE_HREF	0x0040
static int isANON;

typedef struct {
	int	 printMode;
	int	 mounted;
	int	 layered;
	int	 e_digestLen;
	int	 source;
	int	 no_tailer;
	int	 isHTML;
	int	 e_insNonJP;
	int	 viewAsis;
	MStr(	 e_cookie,256);
	int	 expires;
	int	 expireA;
	int	 lastMod;
	MemFile	 eTagsrc;
	MStr(	 e_error_reason,0x1000);

	int	 start;
	int	 nsid;
	MStr(	 e_hostport,MaxHostNameLen);
	FILE	*tmpfp;
	MStr(	 e_urlFullSelf,1024);
	MStr(	 e_urlSelf,1024);
	MStr(	 e_urlbase,1024);
	MStr(	 e_search,1024);
	MStr(	 e_iconbase,1024);
	MStr(	 e_iconform,1024);

	FILE	*lfp;
	MStr(	 e_group,1024);
	MStr(	 e_rgroup,1024);
	MStr(	 e_prgroup,1024);
	MStr(	 e_upgroup,1024);
	int	 nhit;
	int	 nact;
	int	 nall;
	int	 nempty;
	int	 min1;
	int	 max1;
	int	 nact1;
	int	 nchild1;
	MStr(	 e_group1,1024);
	MStr(	 e_grouphint,1024);

	int	 min;
	int	 max;
	int	 anum1;
	int	 anum2;
	MStr(	 e_msgid,1024);
	MStr(	 e_emptyarts,1024);

	MStr(	 e_aclid,128);
	MStr(	 e_aclurl,1024);
	MStr(	 e_userclass,64);
	int	 nadmin;
	int	 nunsub;
	int	 nsubsc;
	int	 subscribe;

	MStr(	e_hbase,1024);
	MStr(	e_self,1024);
	MStr(	e_top,64);
	MStr(	e_end,64);
	MStr(	e_purl1,1024);
	MStr(	e_purlp,1024);
	MStr(	e_nurl1,1024);
	MStr(	e_nurlp,1024);
	MStr(	e_center,64);
	MStr(	e_wide,64);
	MStr(	e_narrow,64);

	FILE	*afp;
	int	anum;
	MStr(	e_title,256);
	MStr(	e_subject,2048);
	MStr(	e_ssubj,256);
	MStr(	e_charset,64);
	MStr(	e_reply_to,1024);
	MStr(	e_summary,LINESIZE);
	MStr(	e_date,128);
	MStr(	e_from,512);
	MStr(	e_origfrom,256);
	MStr(	e_x_from_fp,128);
	MStr(	e_message_id,256);
	MStr(	e_organization,512);
	MStr(	e_newsgroups,LINESIZE);
	MStr(	e_references,LINESIZE);
	MStr(	e_n_lines,128);
	MStr(	e_xref,LINESIZE);

	MStr(	e_xrefList,64);
	MStr(	e_sDate,64);
	MStr(	e_sTime,64);
	/*
	MStr(	e_newSubj,256);
	*/
	MStr(	e_newSubj,2048);

	int	e_fac;
    const char *e_fav[64];
	MStr(	e_admResp,1024);
	MStr(	e_nccx,64);

	int	e_nomarkup;
	int	e_nullline;
	int	e_incite;
} NewsEnv;

#define NH_NOBUTTON	0x01
#define NH_NOHREF	0x02
#define	NH_NOIIMG	0x04
#define NH_NOCITE	0x08
#define NH_NOMARKUP	0x10
#define NH_NOANON	0x20
#define NH_NOADMIN	0x40
#define NH_NORANGE	0x80

static void clearNewsEnv(NewsEnv *env)
{
	env->printMode	= 0;
	env->mounted	= 0;
	env->layered	= 0;
	env->e_digestLen = 0;
	env->no_tailer	= 0;
	env->source	= 0;
	env->isHTML	= 0;
	env->e_insNonJP	= 0;
	env->viewAsis   = 0;
	env->e_cookie[0]  = 0;
	env->expires	= 0;
	env->expireA	= 0;
	env->e_charset[0] = 0;
	env->lastMod	= 0;
	env->e_fac	= 0;
	env->e_fav[0]	= 0;
	env->e_origfrom[0] = 0;
	CCXcreate("*","a-b-r-",(CCXP)env->e_nccx);
}

#define PrintMode env->printMode
#define Start	env->start
#define Nsid	env->nsid
#define Tmpfp	env->tmpfp
#define UrlSelf	env->e_urlSelf
/**/
#define UrlFullSelf env->e_urlFullSelf
/**/
#define UrlBase	env->e_urlbase
/**/
#define Search	env->e_search
/**/
#define Hostport env->e_hostport
/**/
#define Iconbase env->e_iconbase
/**/
#define Iconform env->e_iconform
/**/

#define	Mounted	env->mounted
#define Layered	env->layered
#define digestLen env->e_digestLen
#define NoTailer env->no_tailer
#define Lfp	env->lfp
#define Rgroup	env->e_rgroup
/**/
#define Prgroup	env->e_prgroup
/**/
#define Upgroup	env->e_upgroup
/**/
#define Expires	env->expires
#define Nhit	env->nhit
#define Nact	env->nact
#define Nall	env->nall
#define Nempty	env->nempty
#define Min1	env->min1
#define Max1	env->max1
#define Nact1	env->nact1
#define Nchild1	env->nchild1
#define Group1	env->e_group1
/**/
#define GroupHint env->e_grouphint
/**/

#define AclID	env->e_aclid
/**/
#define AclURL	env->e_aclurl
#define UserClass env->e_userclass
/**/
#define Nadmin	env->nadmin
#define Nsubsc	env->nsubsc
#define Nunsub	env->nunsub
#define Subscribe env->subscribe

#define Hbase	env->e_hbase
/**/
#define Self	env->e_self
/**/
#define Group	env->e_group
/**/
#define Anum1	env->anum1
#define Anum2	env->anum2
#define Min	env->min
#define Max	env->max
#define LastMod	env->lastMod
#define ErrorReason env->e_error_reason
#define ETagsrc	env->eTagsrc
#define ExpireA	env->expireA
#define Source	env->source
#define Msgid	env->e_msgid
/**/
#define Emptyarts env->e_emptyarts
/**/

#define Top	env->e_top
/**/
#define End	env->e_end
/**/
#define Purl1	env->e_purl1
/**/
#define Purlp	env->e_purlp
/**/
#define Nurl1	env->e_nurl1
/**/
#define Nurlp	env->e_nurlp
/**/
#define Center	env->e_center
/**/
#define Wide	env->e_wide
/**/
#define Narrow	env->e_narrow
/**/

#define Afp		env->afp
#define Anum		env->anum
#define Reply_To	env->e_reply_to
/**/
#define Title		env->e_title
#define Subject		env->e_subject
/**/
#define SSubj		env->e_ssubj
/**/
#define Charset		env->e_charset
/**/
#define Date		env->e_date
#define From		env->e_from
#define OrigFrom	env->e_origfrom
#define XFromFp		env->e_x_from_fp
#define Organization	env->e_organization
#define Newsgroups	env->e_newsgroups
#define References	env->e_references
#define Lines		env->e_n_lines
#define Xref		env->e_xref
#define Message_ID	env->e_message_id
/**/
#define Summary		env->e_summary

#define XrefList	env->e_xrefList
/**/
#define SDate		env->e_sDate
/**/
#define STime		env->e_sTime
/**/
#define NewSubj		env->e_newSubj
/**/
#define IsHTML		env->isHTML
#define insNonJP	env->e_insNonJP
#define ViewAsis	env->viewAsis
#define Cookie		env->e_cookie
/**/

#define Fac		env->e_fac
#define Fav		env->e_fav
#define admResp		env->e_admResp
#define NCcx		(CCXP)env->e_nccx

/*
 * MHGWCONF=hide:From:from1,from2,...[:[user1,user2,...]][:from,body,ref]
 */
typedef struct {
	char	*h_fname;
	char	*h_vlist;
	char	*h_users;
	char	*h_hides;
} Hidden;
static Hidden hidden[8];
static int hiddenx;

static int hide(Connection *Conn,PCStr(name),PCStr(value)){
	int hi;
	const char *user = ClientAuthUser;
	const char *users;
	int hide;

	if( strcaseeq(name,"Subject") ){
		if( strncasecmp(value,"Re:",3) == 0 )
			value += 3;
	}
	while( isspace(*value) )
		value++;

	if( *user == 0 )
		user = "anonymous";

	for( hi = 0; hi < hiddenx; hi++ ){
		if( hidden[hi].h_fname[0] )
		if( !strcaseeq(name,hidden[hi].h_fname) )
			continue;

		users = hidden[hi].h_users;
		if( *users == 0 )
			users = "anonymous";

		hide = 0;
		if( !streq(users,"*") ){
			if( !strmatch_list(user,users,"",NULL,NULL) )
				continue;
			if( streq(user,"anonymous") )
				hide |= HIDE_NOLOGIN;
		}

		if( hidden[hi].h_vlist[0] )
		if( !strmatch_list(value,hidden[hi].h_vlist,"",NULL,NULL) )
			continue;

		return hide | (HIDE_FROM|HIDE_BODY|HIDE_HREF);
	}
	return 0;
}
void scan_MHGWCONF(Connection *Conn,PCStr(conf))
{       CStr(what,128);
        CStr(value,2048);
	CStr(fname,32);
	CStr(fvalue,2048);
	CStr(users,1024);
	const char *av[4];

	fieldScan(conf,what,value);
	if( strcaseeq(what,"hide") ){
		if( hiddenx < elnumof(hidden) ){
			av[0] = av[1] = av[2] = av[3] = "";
			list2vect(value,':',4,av);
			hidden[hiddenx].h_fname = strdup(av[0]);
			hidden[hiddenx].h_vlist = strdup(av[1]);
			hidden[hiddenx].h_users = strdup(av[2]);
			hidden[hiddenx].h_hides = strdup(av[3]);
			hiddenx++;
		}
	}else
	if( strcaseeq(what,"winsize") ){
	}else{
	}
}

static void dispExpire(PVStr(se),int start,int done,int expires)
{	CStr(now,128);
	CStr(exp,128);

	StrftimeLocal(AVStr(now),sizeof(now),TIMEFORM_mdHMS,done,0);
	StrftimeLocal(AVStr(exp),sizeof(exp),TIMEFORM_mdHMS,expires,0);
	sprintf(se,"Generated:%s (%d sec) Expires:%s",now,done-start,exp);
}

#define HTATMARK	"<kbd>@</kbd>"

static char *mark_atmark(PCStr(src),PVStr(out),int osiz)
{	const char *rp;
	refQStr(dp,out); /**/
	const char *ep;
	const char *xp;
	const unsigned char *up;

	xp = out + (osiz - 1);
	for( rp = src; rp && *rp; rp = ep+1 ){
		if( (ep = strpbrk1B(rp,"<@",(char**)&dp,BVStr(out))) == NULL )
			break;
		if( *ep == '<' ){ /* dont escape atmark in tag */
			setVStrPtrInc(dp,*ep++);
			if( (ep = strpbrk1B(ep,">",(char**)&dp,BVStr(out))) == NULL )
				break;
			if( *ep == '>' )
				setVStrPtrInc(dp,*ep);
			continue;
		}
		up = (unsigned char *)ep;
		if( ep==src || !isalnum(up[-1]) || !isalnum(up[1]) ){
			setVStrPtrInc(dp,'@');
			continue;
		}
		if( xp <= dp+sizeof(HTATMARK) )
			break;
		strcpy(dp,HTATMARK);
		dp += strlen(dp);
	}
	XsetVStrEnd(AVStr(dp),0);
	return (char*)dp;
}

int putLastRef(Connection *Conn,NewsEnv *env,FILE *tc);
int putXreflist(Connection *Conn,NewsEnv *env,FILE *tc);
static int putDigest(Connection *Conn,NewsEnv *env,FILE *afp,FILE *tc);
int putArt1(Connection *Conn,NewsEnv *env,FILE *afp,FILE *tc);
int putArts(Connection *Conn,FILE *tc,NewsEnv *env);
static int putLIST(Connection *Conn,NewsEnv *env,FILE *lfp,FILE *tc,PCStr(hostport),int mounted,PCStr(groups),int layered,int *nactp,int *nallp,int *nemptyp);
static int setArtAttrs(Connection *Conn,NewsEnv *env,int anum);
static int matchgroup(FILE *lfp,PCStr(group));
void newsAdmin(Connection *Conn,PVStr(user),FILE *tc,NewsEnv *env,PCStr(group),PVStr(search));
void encIntB32(int iv,PVStr(str),int siz);
int decIntB32(PCStr(str));

FILE *ENEWS_article(PCStr(msgid),PCStr(group),int anum);
int sendmail1X(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log);
int RFC821_skipheader(FILE *afp,FILE *out,PCStr(field));
void relayRESPBODY(FILE *fs,FILE *tc,PVStr(line),int size);
const char *DELEGATE_verdate();
int enCreys(PCStr(opts),PCStr(pass),PCStr(data),PVStr(edata),int esize);
int deCreys(PCStr(opts),PCStr(pass),PCStr(data),PVStr(ddata),int dsize);

/*
#define put1s	HTML_put1s
#define put1d	HTML_put1d
*/
#define put1s(fp,fmt,val) HTML_put1sY(Conn,fp,fmt,val)
#define put1d(fp,fmt,val) HTML_put1dY(Conn,fp,fmt,val)

static int printItem(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),NewsEnv *env)
{	int rcode;

	int print = 0;
	CStr(pp1,128);
	CStr(pn1,128);
	const char *pn2;
	const char *pa;

	if( strneq(name,"print%",6) ){
		print = 1;
		arg = wordScanY(arg,pp1,"^.");
		name = pp1;
		if( *arg == '.' ){
			arg++;
		}
	}
	if( streq(name,"formv") ){
		pn2 = wordScanY(arg,pn1,"^.");
		if( streq(pn1,"_admresp_") )
			pa = admResp;
		else	pa = getv(Fav,pn1);
		if( pa != 0 && *pa != 0 ){
			if( *pn2 == '.' ){
				pn2++;
				if( *pn2 == '*' ){
					return strstr(pa,pn2+1) != 0;
				}else	return isinList(pn2,pa);
			}else{
				if( print )
					return put1s(fp,fmt,pa);
				else	return 1;
			}
		}else{
			return 0;
		}
	}else
	if( streq(name,"checkbox") ){
		CStr(attr,32);
		CStr(rem,32);
		truncVStr(rem);
		Xsscanf(arg,"%[-_.a-zA-Z0-9] %s",AVStr(attr),AVStr(rem));
		fprintf(fp,"<INPUT type=checkbox name=%s",attr);
		if( (pa = getv(Fav,attr)) && strcaseeq(pa,"on") )
			fprintf(fp," checked");
		if( *rem ){
			fprintf(fp," %s",rem);
		}
		fprintf(fp,">");
		return 1;
	}else
	if( streq(name,"admin") ){
		if( streq(arg,"mssg") ){
			return put1s(fp,fmt,admResp);
		}
	}else
	if( streq(name,"client") ){
		if( streq(arg,"pass") ){
			CStr(pass,32);
			encIntB32(time(0),AVStr(pass),sizeof(pass));
			return put1s(fp,fmt,pass);
		}
	}else
	if( streq(name,"req") ){
		if( strncmp(arg,"search",6) == 0 ){
			if( arg[6] == 0 )	return put1s(fp,fmt,Search);
			if( arg[6] == '.' )	return streq(arg+7,Search);
		}
	}else
	if( streq(name,"grp") ){
		if( streq(arg,"list") ){
			Nhit = putLIST(Conn,env,Lfp,fp,Hostport,Mounted,Group,Layered,
				&Nact,&Nall,&Nempty);
			return 1;
		}
		if( streq(arg,"acl") )
			return getSubscription(Conn,fp,UserClass,Group,NULL,NULL);

		if( streq(arg,"Layered") )	return put1d(fp,fmt,Layered);
		if( streq(arg,"name") )		return put1s(fp,fmt,Group);
		if( streq(arg,"real") )		return put1s(fp,fmt,Rgroup);
		if( streq(arg,"print") )	return put1s(fp,fmt,Prgroup);
		if( streq(arg,"up") )		return put1s(fp,fmt,Upgroup);
		if( streq(arg,"Max1") )		return put1d(fp,fmt,Max1);
		if( streq(arg,"Min1") )		return put1d(fp,fmt,Min1);
		if( streq(arg,"Nact1") )	return put1d(fp,fmt,Nact1);
		if( streq(arg,"Nchild1") )	return put1d(fp,fmt,Nchild1);
		if( streq(arg,"Group1") )	return put1s(fp,fmt,Group1);

		if( streq(arg,"Nadmin") )	return put1d(fp,fmt,Nadmin);
		if( streq(arg,"Nunsub") )	return put1d(fp,fmt,Nunsub);
		if( streq(arg,"Nsubsc") )	return put1d(fp,fmt,Nsubsc);
		if( streq(arg,"Subscribe") )	return put1d(fp,fmt,Subscribe);
	}else
	if( streq(name,"acl") ){
		if( streq(arg,"id") )		return put1s(fp,fmt,AclID);
		if( streq(arg,"url") )		return put1s(fp,fmt,AclURL);
		if( streq(arg,"max") )		return put1d(fp,fmt,ACLMAX);
		if( streq(arg,"mailgate") )	return put1s(fp,fmt,MailGate(Conn));
	}else
	if( streq(name,"printmode") ){
		if( streq(arg,"on") ){
			PrintMode = 1;
			return 1;
		}
		return PrintMode;
	}else
	if( streq(name,"nobutton") ){
		return env->e_nomarkup & NH_NOBUTTON;
	}else
	if( streq(name,"noadmin") ){
		return env->e_nomarkup & NH_NOADMIN;
	}else
	if( streq(name,"norange") ){
		return env->e_nomarkup & NH_NORANGE;
	}else
	if( streq(name,"num") ){
		if( streq(arg,"article") )	return put1d(fp,fmt,Nact);
		if( streq(arg,"match") )	return put1d(fp,fmt,Nhit);
		if( streq(arg,"all") )		return put1d(fp,fmt,Nall);
		if( streq(arg,"empty") )	return put1d(fp,fmt,Nempty);
		if( streq(arg,"anum1") )	return put1d(fp,fmt,Anum1);
		if( streq(arg,"anum2") )	return put1d(fp,fmt,Anum2);
		if( streq(arg,"min")   )	return put1d(fp,fmt,Min);
		if( streq(arg,"max")   )	return put1d(fp,fmt,Max);
						return put1d(fp,fmt,0);
	}else
	if( streq(name,"art") ){
		if( streq(arg,"Anum") )		return put1d(fp,fmt,Anum);
		if( streq(arg,"IsHTML") )	return put1d(fp,fmt,IsHTML);
		if( streq(arg,"Date") )		return put1s(fp,fmt,Date);
		/*
		if( streq(arg,"From") )		return put1s(fp,fmt,From);
		*/
		if( streq(arg,"From") ){
			CStr(buf,512);
			mark_atmark(From,AVStr(buf),sizeof(buf));
			return put1s(fp,fmt,buf);
		}
		if( streq(arg,"Reply_To") )	return put1s(fp,fmt,Reply_To);
		if( streq(arg,"title") )	return put1s(fp,fmt,Title);
		if( streq(arg,"Subject") )	return put1s(fp,fmt,Subject);
		if( streq(arg,"SSubj") )	return put1s(fp,fmt,SSubj);
		if( streq(arg,"NewSubj") )	return put1s(fp,fmt,NewSubj);
		if( streq(arg,"Newsgroups") && *Newsgroups == 0 )
						return put1s(fp,fmt,Prgroup);
		if( streq(arg,"Newsgroups") )	return put1s(fp,fmt,Newsgroups);
		if( streq(arg,"Lines") )	return put1s(fp,fmt,Lines);
		if( streq(arg,"XrefList"))	return put1s(fp,fmt,XrefList);
		if( streq(arg,"SDate"))		return put1s(fp,fmt,SDate);
		if( streq(arg,"STime"))		return put1s(fp,fmt,STime);
		if( streq(arg,"Msgid") )	return put1s(fp,fmt,Msgid);
		if( streq(arg,"References") )	return put1s(fp,fmt,References);
		if( streq(arg,"Organization"))	return put1s(fp,fmt,Organization);
		if( streq(arg,"Message_ID") )	return put1s(fp,fmt,Message_ID);
		if( streq(arg,"Summary") )	return put1s(fp,fmt,Summary);
		if( streq(arg,"xreflist") )	return putXreflist(Conn,env,fp);
		if( streq(arg,"lastref") )	return putLastRef(Conn,env,fp);
		if( streq(arg,"body") )		return putArt1(Conn,env,Afp,fp);
		if( streq(arg,"list") )		return putArts(Conn,fp,env);
		if( streq(arg,"emptys") )	return put1s(fp,fmt,Emptyarts);
		if( streq(arg,"putDigest") ){
			return 0 < digestLen &&
			  !((isANON & HIDE_BODY) && (isANON & HIDE_NOLOGIN));
		}
		if( streq(arg,"stddigest") )	return digestLen == 4;
		if( streq(arg,"digestlen") )	return put1d(fp,fmt,digestLen);
		if( streq(arg,"digest") )	return putDigest(Conn,env,Afp,fp);
	}else
	if( streq(name,"hide") ){
		if( streq(arg,"href") )	return isANON & HIDE_HREF;
	}else
	if( streq(name,"arturl") ){
		const char *src;
		CStr(buff,2048);

		if( env->e_nomarkup & NH_NOHREF ){
			return 1;
		}
		src = NULL;
		if( streq(arg,"Message_ID_md5dots") ){
			CStr(mid,2048);
			sprintf(mid,"<%s>",Message_ID);
			toMD5dots("",mid,AVStr(buff),8);
			src = buff;
		}else
		if( streq(arg,"Message_ID") )	src = Message_ID; else
		if( streq(arg,"Reply_To") )	src = Reply_To; else
		if( streq(arg,"From") )		src = From;
		if( streq(arg,"Subject") )	src = Subject;
		if( src ){
			CStr(tmp1,2048);
			CStr(tmp2,2048);
			/* decode entities encoded in getFV_D() ... :-O */
			if( streq(arg,"From") || streq(arg,"Subject") ){
				decodeEntities(src,AVStr(tmp1),1);
				src = tmp1;
			}
			MIME_strHeaderEncode(src,AVStr(tmp2),sizeof(tmp2));
			src = tmp2;
			safe_escapeX(src,AVStr(buff),sizeof(buff));
			return put1s(fp,fmt,buff);
		}
	}else
	if( streq(name,"ref") ){
		if( env->e_nomarkup & NH_NOHREF ){
			return 1;
		}
		put1s(fp,fmt,Hbase);
		if( streq(arg,"self") )		return put1s(fp,fmt,Self);
		if( streq(arg,"top")    )	return put1s(fp,fmt,Top);
		if( streq(arg,"end")    )	return put1s(fp,fmt,End);
		if( streq(arg,"purl1")  )	return put1s(fp,fmt,Purl1);
		if( streq(arg,"purlp")  )	return put1s(fp,fmt,Purlp);
		if( streq(arg,"nurl1")  )	return put1s(fp,fmt,Nurl1);
		if( streq(arg,"nurlp")  )	return put1s(fp,fmt,Nurlp);
		if( streq(arg,"center") )	return put1s(fp,fmt,Center);
		if( streq(arg,"wide")   )	return put1s(fp,fmt,Wide);
		if( streq(arg,"narrow") )	return put1s(fp,fmt,Narrow);
	}else
	if( streq(name,"tailer") ){
		if( streq(arg,"off") ){	return NoTailer = 1; }
	}else
	if( streq(name,"icon") ){
		CStr(url,1024);
		if( env->e_nomarkup & NH_NOIIMG ){
			return 1;
		}
		sprintf(url,"%s/%s",Iconbase,arg);
						return put1s(fp,fmt,url);
	}else
	if( streq(name,"url") ){
		if( streq(arg,"base") )		return put1s(fp,fmt,UrlBase);
		if( streq(arg,"self") )		return put1s(fp,fmt,UrlSelf);
		if( streq(arg,"fullself") )	return put1s(fp,fmt,UrlFullSelf);
	}else
	if( streq(name,"serv") ){
		if( streq(arg,"hostport") )	return put1s(fp,fmt,Hostport);
	}else
	if( streq(name,"user") ){
		if( streq(arg,"class") )	return put1s(fp,fmt,UserClass);
	}else
	if( streq(name,"expires") ){
		CStr(sexpire,128);
		if( Expires ){
			dispExpire(AVStr(sexpire),Start,time(0),Expires);
			put1s(fp,fmt,sexpire);
		}
		return Expires;
	}else
	if( streq(name,"putmenu") ){
		return HTTP_putmenu;
	}else
	if( streq(name,"ver") ){
		return put1s(fp,fmt,DELEGATE_ver());
	}
	else
	if( streq(name,"error") ){
		if( streq(arg,"reason") ){
			put1s(fp,fmt,ErrorReason);
			return 1;
		}else{
			return 0;
		}
	}else
	if( streq(name,"estamp") ){
		if( streq(arg,"short") ){
			IStr(stamp,128);
			IStr(estamp,128);

			sprintf(stamp,"%X",time(0));
			enCreys("",MLSOLT,stamp,AVStr(estamp),sizeof(estamp));
			ovstrcpy(estamp,estamp+2);
			setVStrEnd(estamp,6);
			put1s(fp,fmt,estamp);
			return 1;
		}else
		if( streq(arg,"shortok") ){
			int i;
			int now = time(0);
			IStr(stamp,128);
			IStr(estamp,128);

			const char *echo = getv(Fav,"echo");
			for( i = 0; i < 120; i++ ){
				sprintf(stamp,"%X",now-i);
				enCreys("",MLSOLT,stamp,AVStr(estamp),sizeof(estamp));
				ovstrcpy(estamp,estamp+2);
				setVStrEnd(estamp,6);
				if( streq(echo,estamp) ){
					return 1;
				}
			}
			sprintf(ErrorReason,"the echoed key unmatch");
			return 0;
		}else
		if( streq(arg,"gen") ){
			IStr(stamp,128);
			IStr(estamp,128);
			sprintf(stamp,"%s\n%x",MLSOLT,time(0));
			enCreys("",MLSOLT,stamp,AVStr(estamp),sizeof(estamp));
			put1s(fp,fmt,estamp);
			return 1;
		}else
		if( streq(arg,"ok") ){
			const char *estamp;
			estamp = getv(Fav,"estamp");
			if( estamp){
				IStr(solt,128);
				int date = 0;
				sscanf(estamp,"%[^\n]\n%X",solt,&date);
				sv1log("----estamp[%s %X]\n",solt,date);
				if( time(0)-date < 60 ){
					return 1;
				}else{
					strcpy(ErrorReason,"stale stamp, retry after reloading the get-password page");
					return 0;
				}
			}else{
				strcpy(ErrorReason,"no stamp");
			}
			return 0;
		}
		return 0;
	}else
	if( streq(name,"Sendpass") ){ /* new-140504b */
		int rcode;
		FILE *afp;
		FILE *mfp;
		FILE *log;
		IStr(mid,256);
		IStr(rto,256);
		IStr(mlname,256);
		IStr(md5,256);
		int rc;
		IStr(buf,0x10000);
		IStr(mad,256);
		IStr(client,256);

		afp = ENEWS_article(getv(Fav,"msgid"),NULL,0);
		if( afp != NULL ){
			fgetsHeaderField(afp,"Reply-To",    AVStr(rto),sizeof(rto));
			fclose(afp);
		}
		sscanf(rto,"%[^@]",mlname);
		sprintf(mad,"%s@%s",mlname,MLHOST);

		StrftimeGMT(AVStr(mid),sizeof(mid),"%y%m%d-%H%M%S",time(NULL),0);
		sv1log("----${Sendpass}----(%s)(em=%s)(mi=%s)\n",
			mad,
			getv(Fav,"email"),
			mid
		);
		mfp = TMPFILE("NNTP/HTTP-Sendpass-art");
		fprintf(mfp,"To: %s\r\n",getv(Fav,"email"));
		fprintf(mfp,"From: %s\r\n",mad);
		fprintf(mfp,"Reply-To: <noreply>\r\n");
		fprintf(mfp,"Subject: Your password for %s\r\n",mad);
		fprintf(mfp,"Message-ID: <%s.sendpass.%s>\r\n",mid,mad);
		fprintf(mfp,"Content-Type: text/plain\r\n");
		fprintf(mfp,"X-DeleGate-Version: %s\r\n",DELEGATE_verdate());
		fprintf(mfp,"\r\n");

		sprintf(buf,"%s:%s:%s",MLSOLT,mad,getv(Fav,"email"));
		toMD5(buf,md5);
		setVStrEnd(md5,8);
		fprintf(mfp,"Your password: %s\r\n",md5);
		fprintf(mfp,"\r\n");
		fprintf(mfp,"Requested from the client host: %s\r\n",Client_Host);
		fprintf(mfp,"Administrator: %s\r\n",MLADMIN);
		fflush(mfp);
		fseek(mfp,0,0);

		log = TMPFILE("NNTP/HTTP-Sendpass-log");
		rcode = sendmail1X(Conn,getv(Fav,"email"),mad,mfp,log);
		fflush(log);
		fseek(log,0,0);
		rc = fread(buf,1,sizeof(buf),log);
		setVStrEnd(buf,rc);

		fclose(mfp);
		fclose(log);
		if( rcode < 0 ){
			sprintf(ErrorReason,"SMTP error: %s",buf);
			return 0;
		}else	return 1;
	}else
	if( streq(name,"Sendmail") ){ /* new-140504a */
		int rcode;
		FILE *afp;
		FILE *mfp;
		FILE *log;
		IStr(buf,0x10000);
		IStr(md5,128);
		IStr(line,1024);
		IStr(xcc,1024);
		IStr(sbj,1024);
		IStr(frm,1024);
		IStr(dat,1024);
		IStr(mid,1024);
		IStr(mmv,1024);
		IStr(cty,1024);
		IStr(cte,1024);
		IStr(spf,1024);
		IStr(rto,1024);
		int rc;
		IStr(mlname,256);
		IStr(mad,256);

		afp = ENEWS_article(getv(Fav,"msgid"),NULL,0);
		if( afp != NULL ){
			fgetsHeaderField(afp,"MIME-Version",AVStr(mmv),sizeof(mmv));
			fgetsHeaderField(afp,"Content-Type",AVStr(cty),sizeof(cty));
			fgetsHeaderField(afp,"Content-Transfer-Encoding",AVStr(cte),sizeof(cte));
			fgetsHeaderField(afp,"Subject",     AVStr(sbj),sizeof(sbj));
			fgetsHeaderField(afp,"From",        AVStr(frm),sizeof(frm));
			fgetsHeaderField(afp,"Reply-To",    AVStr(rto),sizeof(rto));
			fgetsHeaderField(afp,"Date",        AVStr(dat),sizeof(dat));
			fgetsHeaderField(afp,"Message-ID",  AVStr(mid),sizeof(mid));
			fgetsHeaderField(afp,"X-Cc",        AVStr(xcc),sizeof(xcc));
			fgetsHeaderField(afp,"Received-SPF",AVStr(spf),sizeof(spf));
		}
		sscanf(rto,"%[^@]",mlname);
		sprintf(mad,"%s@%s",mlname,MLHOST);
		sprintf(buf,"%s:%s:%s",MLSOLT,mad,getv(Fav,"email"));
		toMD5(buf,md5);
		setVStrEnd(md5,8);
		if( !streq(md5,getv(Fav,"passw")) ){
			sprintf(ErrorReason,"Bad Password");
			if( afp ) fclose(afp);
			return 0;
		}
		sv1log("----${Sendmail}----(%s)(em=%s)(pw=%s)(id=%s) %X (%s) %s (Cc:%s)\n",
			mad,
			getv(Fav,"email"),
			getv(Fav,"passw"),
			getv(Fav,"msgid"),
			afp,
			cty,
			mid,
			xcc
		);

		mfp = TMPFILE("NNTP/HTTP-Sendmail-art");
		fprintf(mfp,"To: %s\r\n",getv(Fav,"email"));
		if( xcc[0] )
			fprintf(mfp,"Cc: %s\r\n",xcc);
		fprintf(mfp,"Cc: %s\r\n",frm);
		fprintf(mfp,"Cc: %s\r\n",getv(Fav,"email"));
		fprintf(mfp,"From: %s\r\n",mad);
		if( dat[0] )
			fprintf(mfp,"Date: %s\r\n",dat);
		fprintf(mfp,"Reply-To: %s\r\n",mad);
		fprintf(mfp,"Subject: %s\r\n",sbj);
		fprintf(mfp,"Message-ID: %s\r\n",mid);
		if( cty[0] )
			fprintf(mfp,"Content-Type: %s\r\n",cty);
		else	fprintf(mfp,"Content-Type: text/plain\r\n");
		if( cte[0] )
			fprintf(mfp,"Content-Transfer-Encoding: %s",cte);
		fprintf(mfp,"X-DeleGate-Version: %s\r\n",DELEGATE_verdate());
		fprintf(mfp,"\r\n");
		if( afp ){
			RFC821_skipheader(afp,NULL,NULL);
			relayRESPBODY(afp,mfp,AVStr(line),sizeof(line));
		}
		fflush(mfp);
		fseek(mfp,0,0);

		log = TMPFILE("NNTP/HTTP-Sendmail-log");
		rcode = sendmail1X(Conn,getv(Fav,"email"),mad,mfp,log);
		fflush(log);
		fseek(log,0,0);
		rc = fread(buf,1,sizeof(buf),log);
		setVStrEnd(buf,rc);

		fclose(mfp);
		fclose(log);

		if( rcode < 0 ){
			sprintf(ErrorReason,"SMTP error: %s",buf);
			return 0;
		}else	return 1;
	}
	{
	CStr(val,256);
	sprintf(val,"%s.%s",name,arg);
	return put1s(fp,"(unknown %s)",val);
	}
}

static NewsEnv *curEnv;
int DHTML_printNntpgw(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg)){
	if( curEnv )
		return printItem(Conn,fp,fmt,name,arg,curEnv);
	else	return 0;
}

static void putLayered(Connection *Conn,NewsEnv *env,FILE *tc,int nactive,int nchildren,PCStr(base),PCStr(del),PCStr(group),PCStr(ogroup))
{	const char *dp;
	CStr(pgroup,1024);

	if( nchildren && nactive ){
		if( nchildren == 1 ){
			sprintf(Group1,"%s/",ogroup);
		}else{
			if( base[0] == 0 || group[0] == 0 )
				dp = "";
			else	dp = del;
			sprintf(Group1,"%s%s%s",base,dp,group);
		}

Nchild1 = nchildren;
Nact1 = nactive;
Min1 = 0;
Max1 = 0;
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-NGLine","news/ngline.dhtml",NULL,(iFUNCP)printItem,env);

	}
}

static int scanLIST1(PCStr(line),PVStr(group),int *minp,int *maxp)
{	const char *lp;
	CStr(buf,32);

	/* return sscanf (line,"%s %d %d",group,maxp,minp); */
	lp = line;
	if( (lp = wordscanX(lp,AVStr(group),256)) == 0) return 0;
	if( (lp = wordScan(lp,buf)) == 0) return 1;
	*maxp = atoi(buf);
	if( (lp = wordScan(lp,buf)) == 0) return 2;
	*minp = atoi(buf);
	return 3;
}
static void scanName1(PCStr(name),PVStr(name1))
{	char ch;
	const char *sp;
	refQStr(dp,name1); /**/

	for( sp = name; ch = *sp; sp++ ){
		if( ch == '.' )
			break;
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
}


#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)
#define getFV(str,fld,buf)   getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
#define getFv(str,fld,buf)   getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
#define getFV_D(str,fld,buf) getFieldValue_D(Conn,str,fld,AVStr(buf),sizeof(buf))
#define getFv_D(str,fld,buf) getFieldValue_D(Conn,str,fld,AVStr(buf),sizeof(buf))

static void codeconv(Connection *Conn,PCStr(src),PVStr(dst),PCStr(ctype))
{
	if( CCXactive(CCX_TOCL) )
	{
		CCXexec(CCX_TOCL,src,strlen(src),AVStr(dst),LINESIZE*2);
		CCXexec(CCX_TOCL,"",0,TVStr(dst),LINESIZE*2-strlen(dst));
		/* ... to flush ESC(B */
	}
	else	CTX_line_codeconv(Conn,src,AVStr(dst),"text/plain");
}

static void getFieldValue_D(Connection *Conn,PCStr(head),PCStr(field),PVStr(value_D),int size)
{	CStr(value,LINESIZE*2);

/*
	getFieldValue(head,field,AVStr(value_D),size);
*/
	getFieldValue(head,field,AVStr(value),size);
	MIME_strHeaderDecode(value,AVStr(value_D),size);
	codeconv(Conn,value_D,AVStr(value),"text/plain");
	encodeEntitiesX(value,AVStr(value_D),size);
}

static int numXref(PCStr(xref))
{	const char *xp;
	int nx;

	nx = 0;
	for(xp = strpbrk(xref," \t\r\n"); xp; xp = strpbrk(xp+1," \t\r\n") )
		nx++;
	return nx;
}
static void xrefnext(PCStr(xref),PCStr(group),PVStr(next))
{	CStr(xb,LINESIZE);
	const char *xv[128]; /**/
	const char *x1;
	int nx,xi;
	int glen;

	strcpy(xb,xref);
	nx = 0;
	for( x1 = strpbrk(xb," \t\r\n"); x1; x1 = strpbrk(x1," \t\r\n") ){
		if( elnumof(xv)-1 <= nx ){
			break;
		}
		truncVStr(x1); x1++;
		while( strchr(" \t\r\n",*x1) )
			x1++;
		xv[nx++] = x1;
	}
	xv[nx] = 0;

	sprintf(next,"");
	glen = strlen(group);
	for( xi = 0; xi < nx; xi++ ){
		if( strncmp(xv[xi],group,glen) == 0 && xv[xi][glen] == ':' ){
			if( xv[xi+1] )
				strcpy(next,xv[xi+1]);
			else	strcpy(next,xv[0]);
			break;
		}
	}
}

static int maybe_username(PCStr(name))
{	const char *np;
	char ch;
	int na,nd,ns;

	na = nd = ns = 0;
	for( np = name; ch = *np; np++ ){
		if( ch == '@' )  break;
		if( isalpha(ch)) na++; else
		if( isdigit(ch)) nd++; else
		if( ch == '-' )  ns++; else
		if( ch == '.' )  ns++; else
			return 0;
	}
	if( na + nd + ns <= 8 )
	if( ns <= 1 )
	if( nd < na || isalpha(*name) )
		return 1;
	return 0;
}

static void markup1(Connection *Conn,NewsEnv *env,int nsid,PVStr(dst),PCStr(src),PCStr(references),PCStr(mailboxes),PCStr(group),int anum)
{	CStr(msgid,1024);

	if( src[0] != '<' || src[strlen(src)-1] != '>' ){
		strcpy(dst,src);
		return;
	}

	strcpy(msgid,src+1);
	setVStrEnd(msgid,strlen(msgid)-1);
	if( env->e_nomarkup & NH_NOMARKUP ){
		if( strchr(msgid,'@') && *msgid != '_' ){
			strcpy(dst,"@");
		}else{
			sprintf(dst,"&lt;%s&gt;",msgid);
		}
		return;
	}

	if( strncasecmp(msgid,"URL:",4) == 0 ){
		sprintf(dst,"<A HREF=\"%s\"><I>&lt;%s&gt;</I></A>",
			msgid+4,msgid);
	}else
	if( HTTP_putmenu && strchr(msgid,'@') ){
		CStr(href,1024);
		CStr(xmsgid,1024);

		url_escapeX(msgid,AVStr(xmsgid),sizeof(xmsgid),"/*%",NULL);
		if( anum )
			sprintf(href,"../%s/%s?Base=%s/%d",someGroup(),xmsgid,
				group,anum);
		else	sprintf(href,"../%s/%s",someGroup(),xmsgid);

		if( isANON & HIDE_HREF ){
			sprintf(dst,"&lt;%s&gt;",msgid);
		}else
		if( strstr(references,src) )
			sprintf(dst,"<A HREF=\"%s\"><I>&lt;%s&gt;</I></A>",href,msgid);
		else
		if( strstr(mailboxes,msgid) == 0 && !maybe_username(msgid) )
			sprintf(dst,"<A HREF=\"%s\">&lt;%s&gt;</A>",href,msgid);
		else	sprintf(dst,"&lt;%s&gt;",msgid);
	}else
	if( strstr(msgid,"://") ){
		sprintf(dst,"<A HREF=\"%s\"><I>&lt;%s&gt;</I></A>",msgid,msgid);
	}else	sprintf(dst,"<I>&lt;%s&gt;</I>",msgid);
}

#define isIDCHAR(ch)	( 0x20 < ch && ch < 0x7F && ch != '<' && ch != '>' )

static void markup_reference(Connection *Conn,NewsEnv *env,int nsid,PCStr(references),PCStr(mailboxes),PCStr(group),int anum,PCStr(resp),PVStr(xresp))
{	unsigned char ch;
	const char *rp;
	const char *sp;
	const char *ep;
	CStr(tmp,4096);
	refQStr(tp,tmp); /**/
	refQStr(xp,xresp); /**/
	int sx,notid;

	IStr(mresp,LINESIZE);
	if( env->e_nomarkup & NH_NOCITE ){
		void skipCitation(NewsEnv *env,PVStr(ostr),PCStr(istr));
		skipCitation(env,AVStr(mresp),resp);
		resp = mresp;
	}

	setVStrEnd(xp,0);
	for( rp = resp; rp && *rp; rp = ep ){
		/*
		if( (sp = strpbrk1B(rp,"<>&",&xp,BVStr(xresp))) == NULL )
			break;
		if( *sp == '>' || *sp == '&' ){
		*/
		if( (sp = strpbrk1B(rp,"<>&@",(char**)&xp,BVStr(xresp))) == NULL )
			break;
		if( *sp == '>' || *sp == '&' || *sp == '@' ){
			switch( *sp ){
			case '>': strcpy(xp,"&gt;"); break;
			case '&': strcpy(xp,"&amp;"); break;
			case '@':
			  if( sp==resp || !isalnum(sp[-1]) || !isalnum(sp[1]) )
				strcpy(xp,"@");
			  else	strcpy(xp,HTATMARK);
			  break;
			}
			xp += strlen(xp);
			ep = sp + 1;
			continue;
		}

		tmp[0] = '<';
		tp = tmp + 1;
		notid = 0;
		if( (ep = strpbrk1B(sp+1,"<>",(char**)&tp,AVStr(tmp))) == NULL )
			notid = 1;
		else
		if( *ep == '<' )
			notid = 2;
		else
		/* ep == '>' */
		{
			ep++;
			for( sx = 1; ch = tmp[sx]; sx++ ){
				if( !isIDCHAR(ch) ){
					strcat(tmp,"&gt;");
					notid = 3;
					break;
				}
			}
		}
		if( notid ){
			strcpy(xp,"&lt;");
			strcat(xp,tmp+1);
			xp += strlen(xp);
			continue;
		}

		strcat(tmp,">");
		markup1(Conn,env,nsid,AVStr(xp),tmp,references,mailboxes,group,anum);
		xp += strlen(xp);
	}
	XsetVStrEnd(AVStr(xp),0);
}
int putLastRef(Connection *Conn,NewsEnv *env,FILE *tc)
{	const char *sp;
	const char *tp;
	CStr(mark,1024);
	CStr(msgid,1024);
	int len;

	if( References[0] == 0 )
		return 0;

	msgid[0] = 0;
	if( tp = strrchr(References,'>') ){
	for( sp = tp - 1; References <= sp; sp-- )
		if( *sp == '<' ){
			len = tp - sp + 1;
			strncpy(msgid,sp,len); XsetVStrEnd(EVStr(msgid),len);
			break;
		}
	}
	if( msgid[0] ){
		markup1(Conn,env,Nsid,AVStr(mark),msgid,References,From,Group,Anum);
		fprintf(tc,"%s",mark);
	}
	if( (isANON & HIDE_HREF) && (isANON & HIDE_NOLOGIN) ){
		if( env->e_nomarkup & NH_NOANON ){
			fprintf(tc,"((<FONT COLOR=red>(Hidden)</FONT>))");
		}else
		fprintf(tc,
		"<FONT COLOR=RED>(((<A HREF=?Login>LOGIN</A>)))</FONT>");
	}
	return 1;
}

static void putXref(Connection *Conn,FILE *tc,PCStr(form),PCStr(hostport),PCStr(basegroup),PCStr(xref))
{	CStr(xref1,1024);
	const char *nxref;
	CStr(group,1024);
	const char *dp;
	CStr(url,1024);
	CStr(anchor,1024);
	int anum;

	nxref = wordScan(xref,xref1);
	if( Xsscanf(xref1,"%[^:]:%d",AVStr(group),&anum) == 2 ){
		if( CTX_mount_url_fromL(Conn,AVStr(url),"nntp",hostport,group,NULL,MyProto,"-.-") )
		if( dp = strrchr(url,'/') )
			strcpy(group,dp+1);

sprintf(anchor,"<A HREF=\"../%s/%d\">%s/%d</A>",group,anum,group,anum);
 fprintf(tc,form,anchor);
	}
	if( nxref && *nxref )
		putXref(Conn,tc,form,hostport,basegroup,nxref);
}
int putXreflist(Connection *Conn,NewsEnv *env,FILE *tc)
{	int nxref;

	if( Xref[0] == 0 )
		return 0;

	if( strcmp(Search,"Xref") == 0 ){

 fprintf(tc,"<UL>\r\n");
putXref(Conn,tc,"<LI> %s\r\n",Hostport,Group,Xref);
 fprintf(tc,"</UL>\r\n");

	}else{
		nxref = numXref(Xref);
		if( nxref == 1 && Msgid[0] ){

putXref(Conn,tc,"[%s]\r\n",Hostport,Group,Xref);

		}else
		if( 2 <= nxref )

 fprintf(tc,"<A HREF=\"%s?Xref\">[Xref*%d]</A>\r\n",Self,nxref);

	}
	return 1;
}

void stripBracket(PVStr(str))
{	const char *tp;
	const char *ep;
	int len;

	if( tp = strchr(str,'<') )
	if( ep = strchr(tp,'>') ){
		len = ep - tp;
		QStrncpy(str,tp+1,len); /**/
	}
}
static void stripDomain(PVStr(str)){
	refQStr(dp,str);
	const char *sp;
	char ch;
	for( sp = str; ch = *sp; ){
		if( ch == '@' ){
			for( sp++; ch = *sp; sp++ ){
				if( !isalnum(ch) && ch != '-' && ch != '.' )
					break;
			}
			continue;
		}
		setVStrPtrInc(dp,ch);
		sp++;
	}
	setVStrEnd(dp,0);
}

static const char *skipRe(PCStr(sp))
{
	while( strncasecmp(sp,"Re:",3) == 0 ){
		sp += 3;
		while( *sp == ' ' )
			sp++;
	}
	return sp;
}
static const char *toEOL(PCStr(line)){
	const char *sp;
	for( sp = line; *sp; sp++ ){
		if( *sp == '\n' ){
			return sp;
		}
	}
	return sp;
}
void skipCitation(NewsEnv *env,PVStr(ostr),PCStr(istr)){
	const char *sp = istr;
	refQStr(dp,ostr);
	int ch;
	int cols = 0;
	for( sp = istr; ch = *sp; sp++ ){
		if( cols == 0 ){
			if( ch == '>' || (ch == ' ' && sp[1] == '|') ){
				sp = toEOL(sp);
				if( env->e_incite++ == 0 ){
					strcpy(dp,">>cite-snip<<\n");
					dp += strlen(dp);
				}
				if( *sp == 0 )
					break;
				continue;
			}
		}
		env->e_incite = 0;
		setVStrPtrInc(dp,ch);
		if( ch == '\n' ){
			cols = 0;
		}else{
			cols++;
		}
	}
	setVStrPtrInc(dp,0);
}

void CCX_resetincode(CCXP);
#define CCXinsNonJP(ccx) (CCXnonJP(ccx)|CCX_converror(ccx))

static int getArtAttrs(Connection *Conn,NewsEnv *env,FILE *afp)
{	CStr(head,0x2000);
	refQStr(hp,head); /**/
	const char *dp;
	int flen,getit;
	CStr(xrefs,LINESIZE);
	CStr(contenttype,512);
	CStr(ssubj,256);
	int li;
	int idate;

	if( afp == NULL )
		return -1;

	Afp = Tmpfp;

	getit = 0;

	Verbose("getArtAttrs(%s,%d) %s/%s\n",Group,Anum,GroupHint,Msgid);
	for( li = 0;;li++ ){
		if( fgets(hp,&head[sizeof(head)]-hp,afp) == NULL )
			break;
		if( li == 0 && strncmp(hp,"From ",5) == 0 ) /* unix format header */
			continue;

		if( strncaseeq(hp,"From:",5) ){
			lineScan(hp+5,OrigFrom);
		}
		/*
		//int MIME_rewriteAddr(PVStr(buf),int inHead);
		//MIME_rewriteAddr(AVStr(hp),1);
		// and do Mask the realname in From
		*/

		if( *hp == '\r' || *hp == '\n' || *hp == 0 )
			break;

		if( *hp == ' ' || *hp == '\t' ){
			if( getit )
				hp += strlen(hp);
			continue;
		}
		dp = strpbrk(hp," \t:");
		if( dp == 0 )
			continue;
		flen = dp - hp;

		if(
		    strncasecmp(hp,"Subject",flen) == 0
		||  strncasecmp(hp,"Summary",flen) == 0
		||  strncasecmp(hp,"Date",flen) == 0
		||  strncasecmp(hp,"Content-Type",flen) == 0
		||  strncasecmp(hp,"From",flen) == 0
		||  strncasecmp(hp,"Reply-To",flen) == 0
		||  strncasecmp(hp,"Lines",flen) == 0
		||  strncasecmp(hp,"Organization",flen) == 0
		||  strncasecmp(hp,"Newsgroups",flen) == 0
		||  strncasecmp(hp,"Message-ID",flen) == 0
		||  strncasecmp(hp,"References",flen) == 0
		||  strncasecmp(hp,"Xref",flen) == 0
		||  strncasecmp(hp,"X-From-Fp",flen) == 0
		){
			getit = 1;
			hp += strlen(hp);
		}else	getit = 0;
	}

	insNonJP |= CCXinsNonJP(CCX_TOCL);
	CCX_resetincode(CCX_TOCL);
	getFv(head,"Content-Type",contenttype);
	if( contenttype[0] ){
		CStr(cset,64);
		truncVStr(cset);
		get_charset(contenttype,AVStr(cset),sizeof(cset));
		if( cset[0] ){
			if( CCXguessing(CCX_TOCL) ){
				/* Encoded-word in MIME header might be
				 * decoded into code different from body.
				 * So it must be coverted to the body code
				 * in getFV_D()
				 */
				CCXcreate(cset,cset,CCX_TOCL);
			}else{
				CCX_setincode(CCX_TOCL,cset);
			}
		}
	}

	getFV_D(head,"Subject",Subject);
	lineScan(Subject,ssubj);
	/*
	MIME_strHeaderDecode(ssubj,AVStr(SSubj),sizeof(SSubj));
	*/
	strcpy(SSubj,ssubj);
	subject_headclean(AVStr(SSubj));
	getFV_D(head,"Summary",Summary);
	getFV_D(head,"From",From);
	setPosterMasks(From);
	getFV_D(head,"X-From-Fp",XFromFp);

	isANON &= (HIDE_ANON | HIDE_HREF | HIDE_NOLOGIN);
	isANON |= hide(Conn,"From",From);
	isANON |= hide(Conn,"Subject",SSubj);
	if( isANON & HIDE_FROM )
		stripDomain(AVStr(From));

	getFV(head,"Reply-To",Reply_To);
	if( Reply_To[0] == 0 )
		getFV(head,"From",Reply_To);
	RFC822_addresspartX(Reply_To,AVStr(Reply_To),sizeof(Reply_To));

	getFV_D(head,"Organization",Organization);
	getFV(head,"Date",Date);
	getFV(head,"Newsgroups",Newsgroups);
	getFV(head,"Lines",Lines);
	getFV(head,"References",References);
	getFV(head,"Message-ID",Message_ID);
	stripBracket(AVStr(Message_ID));

	getFv(head,"Content-Type",contenttype);
	if( strncasecmp(contenttype,"text/html",9) == 0 )
		IsHTML = 1;
	else	IsHTML = 0;

	if( Charset[0] == 0 || strcaseeq(Charset,"US-ASCII") )
		get_charset(contenttype,AVStr(Charset),sizeof(Charset));

	idate = scanNNTPtime(Date);
	if( idate != -1 )
		LastMod = idate;

	NNTP_selectXref(Nsid,head,AVStr(xrefs));
	getFV(xrefs,"Xref",Xref);

	if( idate == -1 ){
		wordScan(Date,STime);
		wordScan(Date,SDate);
	}else{
		StrftimeLocal(AVStr(STime),sizeof(STime),"%m/%d-%H:%M",idate,0);
		StrftimeLocal(AVStr(SDate),sizeof(SDate),"%y%b%d",idate,0);
	}
	return idate;
}
static void putARTICLE(Connection *Conn,NewsEnv *env,FILE *afp,FILE *tc,int withbody,PVStr(prevsubj))
{	int idate;

	idate = getArtAttrs(Conn,env,afp);

	if( Date[0] == 0 && From[0] == 0 && Message_ID[0] == 0 ){
		if( withbody )
 fprintf(tc,"<H2>no article</H2>\r\n");

		Verbose("Bad article: Date[%s] From[%s]\n",Date,From);
		return;
	}else
	if( withbody ){
/*
#fprintf(tc,"<A HREF=\"%d?Referer\">[Referer]</A>\r\n",Anum);
#if( Anum && strcmp(Group,someGroup()) != 0 ){
#fprintf(tc,"<A HREF=%d?PrevSubj>%s/prev.gif\"></A>\r\n",Anum,Iconform);
#fprintf(tc,"<A HREF=%d?NextSubj>%s/next.gif\"></A>\r\n",Anum,Iconform);
#}
*/

putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-ARTHead","news/arthead.dhtml",NULL,(iFUNCP)printItem,env);

	}else{
		const char *sp;
		const char *np;
		char ch;
		CStr(prntsubj,1024);
		CStr(normsubj,1024);
		refQStr(pp,prntsubj); /**/
		const char *px = &prntsubj[sizeof(prntsubj)-1];

		sp = Subject;
		sp = skipRe(sp);
		if( sp[0] == '[' && (np = strchr(sp+1,']')) ){
			do {
				if( px <= pp )
					break;
				setVStrPtrInc(pp,*sp++);
			} while(sp <= np);
			while( *sp == ' ' )
				sp++;
		}
		sp = skipRe(sp);
		if( *sp ){
			refQStr(np,normsubj); /**/
			if( pp != prntsubj )
				setVStrPtrInc(pp,' ');
			strcpy(pp,sp);
			/*
			strcpy(normsubj,sp);
			*/
			for(;;){
				if( strncaseeq(sp,"Re:",3) ){
					sp += 3;
				}else
				if( isspace(sp[0]) ){
					sp++;
				}else
				if( sp[0] == '[' && (np = strchr(sp+1,']')) ){
					sp = np + 1;
				}else{
					break;
				}
			}
			CCX_resetincode(NCcx);
			CCXexec(NCcx,sp,strlen(sp),AVStr(normsubj),sizeof(normsubj));
			strip_ISO2022JP(AVStr(normsubj));
			np = normsubj;
			for( sp = normsubj; ch = *sp++; )
				if( ch != ' ' )
					setVStrPtrInc(np,ch);
			setVStrEnd(np,0);
		}else{
			if( Subject[0] == 0 )
				strcpy(prntsubj,"(empty subject)");
			else	strcpy(prntsubj,Subject);
			strcpy(normsubj,prntsubj);
		}

		if( strcmp(prevsubj,normsubj) != 0 ){
			strcpy(prevsubj,normsubj);
			if( prntsubj[0] == '[' ){
				CStr(tag,128);
				wordScanY(prntsubj+1,tag,"^]");
				if( strcasestr(UrlSelf,tag) ){
					const char *dp;
					if( dp = strchr(prntsubj+1,']') ){
						dp++;
						if( *dp == ' ' )
							dp++;
						ovstrcpy(prntsubj,dp);
					}
				}
			}
			strcpy(NewSubj,prntsubj);
		}else	NewSubj[0] = 0;


		if( idate == -1 )
			strcpy(SDate,Date);
		else	StrftimeLocal(AVStr(SDate),sizeof(SDate),"%m/%d-%H:%M",idate,0);

		if( Xref[0] && 2 <= numXref(Xref) ){
			CStr(next,1024);
			const char *dp;
			int anum;

			xrefnext(Xref,Group,AVStr(next));
			anum = 0;
			if( dp = strchr(next,':') ){
				*(char*)dp = '/'; /**/
				anum = atoi(dp+1);
			}
			sprintf(XrefList,"../%s-%d",next,anum+10);
		}else	XrefList[0] = 0;

putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-ARTLine","news/artline.dhtml",NULL,(iFUNCP)printItem,env);

	}
}
char *RFC821_recvline(PVStr(line),int size,FILE *fp)
{	int ch;
	const char *rs;

	setVStrElem(line,0,ch = fgetc(fp));
	setVStrEnd(line,1);
	if( ch == EOF ){
		setVStrEnd(line,0);
		rs = NULL;
	}else
	if( ch == '.' ){
		rs = fgets(line,size,fp);
		if( line[0] == '\r' || line[0] == '\n' ){
			setVStrEnd(line,0);
			return NULL;
		}
	}else{
		if( line[0] == '\n' )
			rs = line;
		else
		rs = Xfgets(DVStr(line,1),size-1,fp);
	}
	return (char*)rs;
}
void RFC821_recvdata(FILE *afp,FILE *tc)
{	CStr(line,1024);

	while( RFC821_recvline(AVStr(line),sizeof(line),afp) != NULL )
		fputs(line,tc);
}

int HTMLtoTEXT(FILE *ain,FILE *aout,int toHtml);
int makeDigest(PVStr(digest),int size,FILE *in);
static int putDigest(Connection *Conn,NewsEnv *env,FILE *afp,FILE *tc){
	CStr(digest,1024);
	CStr(xdigest,2048);
	CStr(ydig,2048);
	int dlen;
	const char *dp;
	int ccx[16];
	const char *fa1;

	if( (isANON & HIDE_BODY) && (isANON & HIDE_NOLOGIN) )
		return 0;

	if( fa1 = getv(Fav,"digest") ){
		dlen = atoi(fa1);
	}else
		dlen = 4;
	dlen *= 50;
	if( sizeof(digest) <= dlen )
		dlen = sizeof(digest);

	if( IsHTML ){
		FILE *tmp;
		tmp = TMPFILE("HTMLtoTEXT");
		HTMLtoTEXT(afp,tmp,0);
		fflush(tmp);
		fseek(tmp,0,0);
		makeDigest(AVStr(digest),dlen,tmp);
		fclose(tmp);
	}else{
	makeDigest(AVStr(digest),dlen,afp);
	}
	encodeEntitiesX(digest,AVStr(xdigest),sizeof(xdigest));

	if( CCXguessing((CCXP)CCX_TOCL) ){
		CCXcreate("EUC-JP",CCXident(CCX_TOCL),(CCXP)ccx);
	}else{
		memcpy(ccx,CCX_TOCL,sizeof(ccx));
		CCX_setincode((CCXP)ccx,"EUC-JP"); /* digest is in EUC-JP */
		CCX_setindflt((CCXP)ccx,"EUC-JP"); /* 9.6.0 for guessCode() */
	}
	CCXexec((CCXP)ccx,xdigest,strlen(xdigest),AVStr(digest),sizeof(digest));
	return put1s(tc,"%s",digest);
}
int putArt1(Connection *Conn,NewsEnv *env,FILE *afp,FILE *tc)
{
	CStr(resp,LINESIZE);
	CStr(xresp,LINESIZE*2);
	CStr(yresp,LINESIZE*2);
	int lines;

	if( (isANON & HIDE_BODY) && (isANON & HIDE_NOLOGIN) ){
		if( env->e_nomarkup & NH_NOANON ){
			fprintf(tc,"((<FONT COLOR=red>(Hidden)</FONT>))");
		}else
		fprintf(tc,
"<BR><FONT COLOR=RED>(((<A HREF=?Login>LOGIN TO READ MORE</A>)))</FONT><BR>");
		return 1;
	}

	if( IsHTML && !ViewAsis ){
		HTMLtoTEXT(afp,tc,1);
		return 1;
	}

	lines = 0;
	for(;;){
		if( RFC821_recvline(AVStr(resp),sizeof(resp),afp) == NULL )
			break;

		if( env->e_nomarkup & NH_NOCITE ){
			if( resp[0] == '\r' || resp[0] == '\n' ){
				if( env->e_nullline == 0 )
					fputs(resp,tc);
				env->e_nullline++;
				continue;
			}
		}
		if( resp[0] == '\r' || resp[0] == '\n' ){
			fputs(resp,tc);
			continue;
		}
		lines++;
		if( ViewAsis )
			strcpy(xresp,resp);
		else
		if( IsHTML )
			encodeEntitiesX(resp,AVStr(xresp),sizeof(xresp));
		else	markup_reference(Conn,env,Nsid,References,From,Group,Anum,resp,AVStr(xresp));
		codeconv(Conn,xresp,AVStr(yresp),"text/html");
		fputs(yresp,tc);
		if( env->e_nomarkup & NH_NOCITE ){
			if( yresp[0] != 0 ){
				env->e_nullline = 0;
			}
		}
	}
	return 1;
}


static int putLIST(Connection *Conn,NewsEnv *env,FILE *lfp,FILE *tc,PCStr(hostport),int mounted,PCStr(groups),int layered,int *nactp,int *nallp,int *nemptyp)
{	CStr(resp,1024);
	CStr(group,1024);
	CStr(group1,1024);
	CStr(ogroup1,1024);
	CStr(ogroup,1024);
	int max,min;
	int cactive,cchildren;
	int nactive,nall,nhit,nempty;
	int lbaselen;
	CStr(obase,1024);
	const char *dp;
	const char *del;

	ogroup[0] = 0;
	ogroup1[0] = 0;
	if( mounted ){
		if( dp = strrchr(groups,'/') )
			strcpy(obase,dp+1);
		else	strcpy(obase,groups);
	}else	strcpy(obase,groups);
	sv1log("putLIST(%s) [%s]\n",groups,obase);

	lbaselen = strlen(groups);

	cactive = 0;
	cchildren = 0;
	nall = 0;
	nhit = 0;
	nempty = 0;
	nactive = 0;

	del = "";
	while( !feof(lfp) ){
		if( fgets(resp,sizeof(resp),lfp) == NULL ){
			if( layered )
putLayered(Conn,env,tc,cactive,cchildren,obase,del,ogroup1,ogroup);
			break;
		}

		nall++;

		scanLIST1(resp,AVStr(group),&min,&max);
		if( mounted ){
			CStr(url,1024);
			if( CTX_mount_url_fromL(Conn,AVStr(url),"nntp",hostport,group,NULL,MyProto,"-.-") )
				strcpy(group,url);
		}

		if( groups[0] == 0
		/* || groups[0] == '*' && strstr(resp,groups+1) */
		 || obase[0] == '*' && strstr(resp,obase+1)
		 || strstr(group,groups) == group
		){
		    if( layered ){
			if( groups[0] == 0
			 || strstr(group,groups) == group
			 &&
( groups[lbaselen-1] == '/'
|| group[lbaselen] == '/' || group[lbaselen] == '.' || group[lbaselen] == 0 )
			){
				nhit++;
				if( mounted ){
					CStr(tmp,1024);
					const char *gp;

					gp = &group[lbaselen];
					if( *gp == '.' )
					{
						del = ".";
						scanName1(gp+1,AVStr(group1));
					}
					else	scanName1(gp,AVStr(group1));
					if( dp = strrchr(group,'/') )
						strcpy(group,dp+1);
/*
					ovstrcpy(group,group+lbaselen);
					if( group[0] == '.' )
						scanName1(group+1,AVStr(group1));
					else	scanName1(group,AVStr(group1));
					strcpy(tmp,group);
					strcpy(group,obase);
					strcat(group,tmp);
*/
				}else
				if( groups[0] == 0 )
					scanName1(group,AVStr(group1));
				else
				if( group[lbaselen] == '.' )
				{
					del = ".";
					scanName1(group+lbaselen+1,AVStr(group1));
				}
				else	group1[0] = 0;

				if( strcmp(ogroup1,group1) == 0 ){
					if( min != 0 && max != 0 && min <= max ){
						cactive += max - min + 1;
						nactive += max - min + 1;
					}else	nempty++;
					cchildren++;
				}else{
putLayered(Conn,env,tc,cactive,cchildren,obase,del,ogroup1,ogroup);
					strcpy(ogroup1,group1);
					if( min != 0 && max != 0 && min <= max ){
						cactive = max - min + 1;
						nactive += max - min + 1;
					}else	cactive = 0;
					cchildren = 1;
				}
				strcpy(ogroup,group);
			}
		    }else{
			if( min != 0 && max != 0 && min <= max ){
				nhit++;

				nactive += max - min + 1;
				if( dp = strrchr(group,'/') )
					strcpy(group,dp+1);
Min1 = min;
Max1 = max;
strcpy(Group1,group);
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-NGLine","news/ngline.dhtml",NULL,(iFUNCP)printItem,env);

			}else	nempty++;
		    }
		}
	}
	if( nactp ) *nactp = nactive;
	if( nallp ) *nallp = nall;
	if( nemptyp ) *nemptyp = nempty;
	return nhit;
}

static const char *vdanger = "\
<small>*Note that the message content can be harmful for your browser \
especially when it contains text/html part.*</small>";

static int putViewerControl(Connection *Conn,NewsEnv *env,FILE *fc,FILE *tc,int *stcodep)
{	HtSwitch *sw;
	HtSwitch *swv[5]; /**/
	HtSwitch swb[5]; /**/
	HtSwitch *cntrl,*sview,*xview,*asisv;
	CStr(urlrealm,256);
	const char *dp;

	swv[0] = cntrl = &swb[0];
	swv[1] = sview = &swb[1];
	swv[2] = xview = &swb[2];
	swv[3] = asisv = &swb[3];
	swv[4] = 0;

	bzero(cntrl,sizeof(HtSwitch));
	cntrl->s_swdesc = "Controlling MIME message Viewer";
	cntrl->s_blabel = "ViewerControl";
	cntrl->s_requrl = "ViewerControl";
	cntrl->s_reqcmd = "ViewerControl";
	cntrl->s_ctlurl = "ViewerControl";
	cntrl->s_maxage = 0;
	cntrl->s_bcmmnt = 0;
	sview->s_ctlsw = 0;

	bzero(sview,sizeof(HtSwitch));
	sview->s_swdesc =
	"Displaying the source text of message (MIME header and body)";
	sview->s_blabel = "Source";
	sview->s_requrl = "Source";
	sview->s_reqcmd = "Source";
	sview->s_ctlurl = "ViewerControl";
	sview->s_maxage = 0;
	sview->s_bcmmnt = 0;
	sview->s_ctlsw = cntrl;

	bzero(xview,sizeof(HtSwitch));
	xview->s_swdesc =
	"Displaying Internet mail/news (MIME message) by your browser itself";
	xview->s_blabel = "Viewer";
	xview->s_requrl = "Viewer";
	xview->s_reqcmd = "Viewer";
	xview->s_ctlurl = "ViewerControl";
	xview->s_maxage = 60;
	xview->s_bcmmnt = vdanger;
	xview->s_ctlsw = cntrl;

	bzero(asisv,sizeof(HtSwitch));
	asisv->s_swdesc =
	"Embedding an original message body <I>asis</I> into a generated page by DeleGate";
	asisv->s_blabel = "ViewerAsis";
	asisv->s_requrl = "ViewerAsis";
	asisv->s_reqcmd = "ViewerAsis";
	asisv->s_ctlurl = "ViewerControl";
	asisv->s_maxage = 300;
	asisv->s_bcmmnt = vdanger;
	asisv->s_ctlsw = cntrl;

	wordScan(UrlSelf,urlrealm);
	if( dp = strrchr(urlrealm,'/') )
		((char*)dp)[1] = 0;

	return HTSWresponse(Conn,swv,Search,Cookie,fc,tc,UrlSelf,urlrealm);
}

#define ICON	"-/builtin/icons/ysato"

#define scanPOPgroup(g,puh) (uvfromsf(g,0,"+%[^.].%[^.].%[^/?]",puh)==3)
#define scanPOPauser(a,uhp) (uvfromsf(a,0,"%[^@]@%[^\r\n]",uhp)==2)

int DUP_ToC = -1;
/* DUP_ToC is introduced in 5.6.4 for POP/NNTP gw. */

/* user and pass should be "const" */
static Connection *curConn;
extern CCXP MIMEHEAD_CCX;

int HttpNews0(Connection *Conn,int vno,FILE *fc,int sv,PCStr(host),int port,PCStr(groupanumsearch),PCStr(req),xPVStr(user),PVStr(pass),int KeepAlive,int *stcodep);
int HttpNews(Connection *Conn,int vno,FILE *fc,int sv,PCStr(host),int port,PCStr(groupanumsearch),PCStr(req),xPVStr(user),PVStr(pass),int KeepAlive,int *stcodep)
{
	int total;

	if( !CCXactive(CCX_TOCL) ){
		/* ncessary to unify output code from articles of
		 * possibly different coding
		 */
		CCXcreate("*","guess-and-set",CCX_TOCL);
	}
	MIMEHEAD_CCX = CCX_TOCL;
	total = HttpNews0(Conn,vno,fc,sv,host,port,groupanumsearch,req,
		BVStr(user),BVStr(pass),KeepAlive,stcodep);
	MIMEHEAD_CCX = 0;
	return total;
}
static void scanRange(NewsEnv *env,PCStr(range)){
	CStr(anum1,32);
	CStr(anum2,32);
	anum1[0] = anum2[0] = 0;
/*
	Xsscanf(range,"%[^-]-%s",AVStr(anum1),AVStr(anum2));
*/
	Xsscanf(range,"%[$0-9]-%[$0-9]",AVStr(anum1),AVStr(anum2));
	if( *anum1 == '$' )
		Anum1 = -atoi(anum1+1) -1;
	else	Anum1 = atoi(anum1);
	if( *anum2 == '$' )
		Anum2 = -atoi(anum2+1) -1;
	else	Anum2 = atoi(anum2);
}
static void setupRange(NewsEnv *env,int psize){
	int npsize,nanum1,nanum2;

	npsize = psize + xPSIZE;
	if( (nanum2 = Anum2) < Max ){
		nanum2 = (Anum1 / xPSIZE) * xPSIZE + npsize;
			if( Max < nanum2 )
			nanum2 = Max;
		nanum1 = Anum1;
	}else
	if( (nanum1 = Anum1) > Min ){
		nanum1 = ((Anum2+xPSIZE-1) / xPSIZE) * xPSIZE - npsize;
		if( nanum1 < Min )
			nanum1 = Min;
		nanum2 = Anum2;
	}
	sprintf(Wide,"%d-%d",nanum1,nanum2);

	npsize = psize - xPSIZE;
	if( npsize < xPSIZE )
		npsize = xPSIZE;
	nanum2 = (Anum1 / xPSIZE) * xPSIZE + npsize;
	if( Max < nanum2 )
		nanum2 = Max;
	sprintf(Narrow,"%d-%d",Anum1,nanum2);
}
static int setupPAGESIZE(NewsEnv *env){
	int n1,n2;
	int psize;

	psize = ALIST_WINDOW;
	if( Msgid[0] ){
		if( Anum1 == 0 )
			Min = Max = 0;
	}else
	if( Anum1 == 0 ){
		Anum2 = Max;
		Anum1 = ((Max-1) / psize) * psize;
		if( Anum1 <= 0 ) Anum1 = 1;

	}else
	if( Anum2 == 0 ){
		Anum2 = Anum1;
	}else{
		n1 = (Anum1 / xPSIZE) * xPSIZE;
		n2 = ((Anum2+xPSIZE-1) / xPSIZE) * xPSIZE;
		psize = ((n2 - n1) / xPSIZE) * xPSIZE; 
		if( psize < xPSIZE )
			psize = xPSIZE;
	}

	sprintf(Top,   "%d",   Min);
	sprintf(End,   "%d",   Max);
	sprintf(Purl1, "%d",   Anum1-1);

	n1 = ((Anum1-1) / psize) * psize;
	n2 = n1 +  psize;
	if( n1 <= 0 ) n1 = 1;
	if( n2 > Max ) n2 = Max;
	sprintf(Purlp,"%d-%d",n1,n2);
	if( getv(Fav,"digest") ){
		Xsprintf(TVStr(Purlp),"?%s",Search);
	}
	sprintf(Nurl1, "%d",   Anum2+1);

	n1 = ((Anum2+1) / psize) * psize;
	n2 = n1 + psize;
	if( n1 <= 0 ) n1 = 1;
	if( n2 > Max ) n2 = Max;
	sprintf(Nurlp,"%d-%d",n1,n2);
	if( getv(Fav,"digest") ){
		Xsprintf(TVStr(Nurlp),"?%s",Search);
	}
	sprintf(Center,"%d",   Anum1);
	return psize;
}
static int tooWideRange(Connection *Conn,NewsEnv *env,FILE *tc){
	if( ALIST_MAXWIN < Anum2 - Anum1 ){
		sv1log("## too wide range: %d-%d\n",Anum1,Anum2);
		/* should do penalty sleep ... */
		sleep(30);

		fprintf(tc,"HTTP/1.0 500 too wide range.\r\n");
		fprintf(tc,"MIME-Version: 1.0\r\n");
		fprintf(tc,"Content-Type: text/plain\r\n");
		fprintf(tc,"\r\n");
		fprintf(tc,"Too wide range [%d-%d]\r\n",Anum1,Anum2);
		return 1;
	}
	return 0;
}

void Form_conv_namevalue(int argc,const char *argv[]);
int HttpNews0(Connection *Conn,int vno,FILE *fc,int sv,PCStr(host),int port,PCStr(groupanumsearch),PCStr(req),xPVStr(user),PVStr(pass),int KeepAlive,int *stcodep)
{	FILE *tc,*tc_sav = NULL;
	int anum;
	CStr(resp,1024);
	const char *ctype;
	CStr(xctype,256);
	int totalc;
	const char *status = NULL;
	int stat,nart;
	CStr(groupanum,1024);
	const char *fp;
	const char *mp;
	CStr(murl,1024);
	int expireL;
	int isart;
	CStr(url,1024);
	const char *dp;
	const char *ep;
	int psize;
	CStr(sexpire,128);
	NewsEnv newsEnv,*env = &newsEnv;
	int length;
	int sub,uns;
	CStr(myhp,1024);
	CStr(gas,1024);
	int dontReadCache;
	int cached_authOK = 0;
	CStr(proto,256);
	CStr(protob,256);
	CStr(userb,256);
	CStr(hostb,MaxHostNameLen);
	const char *hostp;
	CStr(etagsrcbuf,2048);
	UTag *uv[5],uvb[4];
	int notfound;
	CStr(fab,1024);
	const char *fa1;
	IStr(auser,256);

	minit_nntp();
	if( isinList(ProxyControls,"nomenu") ){
		HTTP_putmenu = 0;
	}
	if( MountOptions && isinList(MountOptions,"nomenu") ){
		HTTP_putmenu = 0;
	}
	bzero(&newsEnv,sizeof(newsEnv));
	if( MountOptions ){
		/* disable anchors mainly for robots */
		if( isinList(MountOptions,"nobutton") ){
			newsEnv.e_nomarkup |= NH_NOBUTTON;
		}
		if( isinList(MountOptions,"nohref") ){
			newsEnv.e_nomarkup |= NH_NOHREF;
		}
		if( isinList(MountOptions,"noiimg") ){
			newsEnv.e_nomarkup |= NH_NOIIMG;
		}
		/* to be served via the cache in a search engine */
		if( isinList(MountOptions,"nocite") ){
			newsEnv.e_nomarkup |= NH_NOCITE;
		}
		if( isinList(MountOptions,"nomarkup") ){
			newsEnv.e_nomarkup |= NH_NOMARKUP;
		}
		if( isinList(MountOptions,"noanon") ){
			newsEnv.e_nomarkup |= NH_NOANON;
		}
		if( isinList(MountOptions,"noadmin") ){
			newsEnv.e_nomarkup |= NH_NOADMIN;
		}
		if( isinList(MountOptions,"norange") ){
			newsEnv.e_nomarkup |= NH_NORANGE;
		}
	}

	if( strcaseeq(ClientAuthUser,"anonymous") )
		isANON = HIDE_ANON | HIDE_HREF | HIDE_NOLOGIN;
	else	isANON = 0;

	str_sopen(&ETagsrc,"nntpgw",etagsrcbuf,sizeof(etagsrcbuf),0,"w");
	str_sprintf(&ETagsrc,"NNTP/HTTP:%s:",groupanumsearch);
	str_sprintf(&ETagsrc,"%d:",DELEGATE_LastModified);

	curConn = Conn;
	curEnv = env;
	strcpy(proto,DST_PROTO);
	strcpy(auser,user);

	if( user[0] ){
		if( strstr(groupanumsearch,"+auth+") ){
			strcpy(gas,groupanumsearch);
			strsubst(AVStr(gas),"+auth+",user);
			strsubst(AVStr(gas),"@",".");
			groupanumsearch = gas;
		}
	}

	uvinit(uv,uvb,4);
	if( scanPOPgroup(groupanumsearch,uv) ){
		if( ustrcmp(uv[0],"pop") == 0 ){
			utosX(uv[0],AVStr(REAL_PROTO),sizeof(REAL_PROTO));
			Utos(uv[0],proto);

			Utos(uv[1],userb);
			Utos(uv[2],hostb);
			utosX(uv[2],AVStr(REAL_HOST),sizeof(REAL_HOST));

			REAL_PORT = port = serviceport(proto);
			setPStr(user,userb,sizeof(userb));
			host = hostb;
		}
	}else
	if( streq(proto,"pop") ){
		uvinit(uv,uvb,4);
		if( AuthThru(Conn,user) ){
		}else
		if( scanPOPauser(user,uv) ){
			Utos(uv[0],userb);
			Utos(uv[1],hostb);
			utosX(uv[1],AVStr(REAL_HOST),sizeof(REAL_HOST));

			REAL_PORT = port = serviceport(proto);
			setPStr(user,userb,sizeof(userb));
			host = hostb;
		}
	}

	if( strchr(host,'@') )
	if( user[0] == 0 || pass[0] == 0 ){
		CStr(usert,256);
		CStr(passt,256);
		scan_url_userpass(host,AVStr(usert),AVStr(passt),"");
		if( usert[0] && passt[0] ){
			strcpy(user,usert);
			strcpy(pass,passt);
			sv1log("URL> user[%s] pass[*%d]\n",user,istrlen(pass));
		}
	}

	if( hostp = strchr(host,'@') )
		hostp += 1;
	else	hostp = host;
	if( streq(proto,"pop") )
	if( user[0] == 0 || pass[0] == 0 || hostp[0] == 0 || isMYSELF(hostp) ){
		CStr(msg,1024);

		sv1log("NotAuthorized: proto[%s] user[%s] pass[%s] host[%s]\n",
			proto,user,pass[0]?"****":"",host);

		sprintf(msg,"<P><HR>POP/HTTP: you must send Authorization (username as user@host and password) or specify URL as +pop.USER.HOST<HR>\r\n");
		tc = fdopen(ToC,"w");
		totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,msg);
		fcloseFILE(tc);
		*stcodep = 401;
		return totalc;
	}
	host = hostp;

	if( NNTP_needAuth(Conn) && user[0] == 0 ){
		tc = fdopen(ToC,"w");
		totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,"");
		fcloseFILE(tc);
		*stcodep = 401;
		sv1log("NotAuthorized: need auth fot the client\n");
		return totalc;
	}

	if( CLNT_PROTO[0] )
		MyProto = CLNT_PROTO;
	else	MyProto = "http";

	clearNewsEnv(env);
	HTTP_getRequestField(Conn,"Cookie",AVStr(Cookie),sizeof(Cookie));

	HTTP_originalURLx(Conn,AVStr(UrlSelf),sizeof(UrlSelf));
	if( dp = strchr(UrlSelf,'?') )
		truncVStr(dp);

	HTTP_ClientIF_HP(Conn,AVStr(myhp));
	sprintf(UrlFullSelf,"%s://%s%s",MyProto,myhp,UrlSelf);

	Start = time(0);
	if( streq(host,"*") && streq(proto,"nntp") ){
		if( strcmp(groupanumsearch,"*") == 0 )
			groupanumsearch = "";
		Nsid = NNTP_getServer(Conn,FromC,ToC,groupanumsearch,&host,&port);
		if( strchr(groupanumsearch,'@') ){
			sprintf(gas,"*/%s",groupanumsearch);
			groupanumsearch = gas;
		}
	}else{
		/* this must be under mutex with lMULTIST() */
		Nsid = NNTP_newServer(Conn,DST_PROTO,user,pass,host,port,
			FromC,ToC,FromS,ToS);
	}
	Conn->nn_nsid = Nsid;

	sv1log("NNTPGW: [%s:%d]=%d=%d UserPass=[%s:%s] GroupAnumSrch=[%s] %s\n",
		host,port,Nsid,sv, user,pass[0]?"******":"",groupanumsearch,
		KeepAlive?"KeepAlive":"");
	setProtoOfClient(Conn,MyProto);
	sprintf(Hostport,"%s:%d",host,port);
	/*
	HostPort(Hostport,DST_PROTO,host,port);
	*/

	HTTP_baseURLrelative(Conn,ICON,AVStr(Iconbase));
	if( CTX_mount_url_fromL(Conn,AVStr(murl),"file","localhost",ICON,NULL,MyProto,"-.-") )
	/* this stuff is introduced at 5.5.0, to customize icon-server by
	 *   MOUNT="http://icon-server/icons/* /-/builtin/icons/*"
	 * without traffic for redirection like
	 *   MOUNT="/-/builtin/icons/* http://icons-server/icons/* moved"
	 * but is harmful for MOUNTing NNTP together with MOUNT for "file:"
	 * generating URL like "http://-.-/" acting as an origin HTTP-DeleGate.
	 * The specification should have been like:
	 *   MOUNT="http://icon-server/icons/* builtin:/-/builtin/icons/*"
	 * or so... and the mechanism should be generalized to be
	 * applicable to any builtin-data and protocols... */
	if( strncmp(murl,MyProto,strlen(MyProto)) != 0
	 || strncmp(murl+strlen(MyProto),"://-.-/",7) != 0 )
		strcpy(Iconbase,murl);
	sprintf(Iconform,"<IMG SRC=\"%s",Iconbase);

	PrintMode = 0;
	Expires = 0;
	Layered = 1; 
	Source = 0;

	Search[0] = 0;
	strcpy(groupanum,groupanumsearch);
	Fav[0] = 0;
	if( fp = strchr(groupanum,'?') ){
		strcpy(Search,fp+1);
		truncVStr(fp);
		strcpy(fab,fp+1);
		Fac = form2v(AVStr(fab),elnumof(Fav),Fav);
		Form_conv_namevalue(Fac,Fav);
	}
	if( streq(Search,"Logout") ){
		if( isANON || ClientAuthUser[0] == 0 ){
		}else{
			tc = fdopen(ToC,"w");
			totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,"");
			*stcodep = 401;
			fcloseFILE(tc);
			return totalc;
		}
	}
	if( streq(Search,"Login") ){
		tc = fdopen(ToC,"w");
		if( isANON || ClientAuthUser[0] == 0 ){
			totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,"");
			*stcodep = 401;
		}else{
			sprintf(url,"%s?Refresh",UrlSelf);
			totalc = putMovedTo(Conn,tc,url);
			*stcodep = 302;
		}
		fcloseFILE(tc);
		return totalc;
	}
	UrlBase[0] = 0;
	Group[0] = 0;
	Anum1 = Anum2 = 0;

	Msgid[0] = 0;
	GroupHint[0] = 0;
/*
	if( (mp = strchr(groupanum,'*')) && mp[1] == '/' ){
		strcpy(Group,"*");
		strcpy(Msgid,mp+2);
	}
*/
	if( strchr(groupanum,'@') && (mp = strchr(groupanum,'/')) ){
		wordscanY(groupanum,AVStr(GroupHint),sizeof(GroupHint),"^/");
		strcpy(Group,someGroup());
		strcpy(Msgid,mp+1);
	}else
	if( strncmp(groupanum,"++",2) == 0 ){
		if( user[0] == 0 || strcmp(groupanum+2,user) == 0 ){
			tc = fdopen(ToC,"w");
			totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,"");
			fcloseFILE(tc);
			*stcodep = 401;
			return totalc;
		}
		groupanum[0] = 0;
		/*sscanf (groupanum,"++%[^/]/%d-%d",group,&Anum1,&Anum2);*/
	}else{
		dp = wordscanY(groupanum,AVStr(Group),sizeof(Group),"^/");
		if( *dp == '/' ){
			scanRange(env,dp+1);
		}
		if( strchr(groupanum,'/') == 0 )
			strcpy(UrlBase,Group);
	}

	/* hereafter, fclose(tc) should be done at EXIT_3 before return; */
	DUP_ToC = dup(ToC);
	tc = fdopen(DUP_ToC,"w");
	Tmpfp = TMPFILE("NNTP/HTTP");

	isart = 0;
	if( Anum1 != 0 && Anum2 == 0 ) isart = 1;
	if( Anum1 == 0 && Anum2 == 0 && Msgid[0] ) isart = 1;

	ctype = "text/html";

	dontReadCache = DontReadCache;
	if( dontReadCache && !PragmaNoCache )
	if( DontWriteCache )
	if( CTX_auth_cache(Conn,0,EXPIRE_LIST,"nntp",user,pass,DST_HOST,DST_PORT) ){
		/* dontRead seems be set because Authorization is given
		 * in the HTTP request (because dontWrite is set).
		 * But because the Authorization is OK, may be cached LIST
		 * is available for the user. (but ARTICLE may be dangerous ... )
		 * But some server may be filtering the LIST per 
		 * authenticated user.
		 * (Thus the LIST should be cached per each user...)
		 */
		sv1log("#### AUTHINFO [%s:****] matches with cached one.\n",user);
		dontReadCache = 0;
		cached_authOK = 1;
	}

	/*
	8.10.4 test for uninit. buff. ref. on access to "/base/unknown-group/"
	memset(From,'-',sizeof(From));
	*/

	if( isart ){
		Expires = 0;
		expireL = EXPIRE_LIST;

		if( dontReadCache ){
			ExpireA = 0;
			expireL = 0; /* force using GROUP command */
		}else	ExpireA = EXPIRE_ART;

		/*
		if( strcmp(Search,"Source") == 0 ){
		*/
		if( strncmp(Search,"Source",6) == 0 ){
			if( totalc = putViewerControl(Conn,env,fc,tc,stcodep) ){
				goto EXIT;
			}
			Source = 1;
			ctype = "text/plain";
		}
		if( strncmp(Search,"Viewer",6) == 0 ){
			if( totalc = putViewerControl(Conn,env,fc,tc,stcodep) ){
				goto EXIT;
			}
/*
			if( ViewAsis ){
*/
			if( strncmp(Search,"ViewerAsis",10) == 0 ){
				ViewAsis = 1;
			}else{
				Source = 1;
				ctype = "message/rfc822";
			}
		}
	}else{
		if( Anum1 == 0 && Anum2 == 0 ) /* article.list/ and news.groups */
			Expires = time(0) + EXPIRE_LIST;
		else	Expires = time(0) + 6*60*60;
		ExpireA = -1;

		if( dontReadCache ){
			if( Anum1 == 0 && Anum2 == 0 )	/* group list or latest art. list */
				expireL = 0;
			else	expireL = EXPIRE_LIST;
		}else	expireL = EXPIRE_LIST;

		if( tooWideRange(Conn,env,tc) ){
			tc_sav = NULL;
			totalc = 0;
			goto EXIT;
		}
	}
	if( strstr(Search,"Expire") ){
		sv1log("forced Expire\n");
		expireL = 0;
	}
	if( strstr(Search,"Refresh") ){
		Expires = time(0);
	}
	digestLen = 4;
	if( fa1 = getv(Fav,"digest") ){
		digestLen = atoi(fa1);
	}

	if( Msgid[0] ){
		CStr(xmsgid,1024);
		CStr(rgroup,1024);
		CStr(tgroup,1024);
		int tanum;

		nonxalpha_unescape(Msgid,AVStr(xmsgid),0);
		strcpy(Msgid,xmsgid);
		if( strncmp(Search,"Base=",5) == 0 )
		{
			Xsscanf(Search+5,"%[^/]/%d",AVStr(tgroup),&tanum);
		}
		else{
			strcpy(tgroup,GroupHint);
			tanum = 0;
		}
		Anum1=Anum2= NNTP_getGroupAnum(Nsid,Msgid,tgroup,tanum,AVStr(rgroup));
		if( Anum1 )
			strcpy(Group,rgroup);
	}

	strcpy(Prgroup,Group);
	if( CTX_mount_url_fromL(Conn,AVStr(url),"nntp",Hostport,Group,NULL,MyProto,"-.-") ){
		Mounted = 1;
		if( dp = strrchr(url,'/') )
			strcpy(Prgroup,dp+1);
	}

	strcpy(Upgroup,Prgroup);
	if( Prgroup[0] == 0 )
		strcpy(Prgroup,"./");

	if( streq(proto,"pop") ){
	}else
	for( dp = &Upgroup[strlen(Upgroup)-1];; dp-- ){
		if( dp <= Upgroup ){ strcpy(Upgroup,"./"); break; }
		if( *dp == '.' ){ truncVStr(dp); break; }
		if( *dp == '/' ){ ((char*)dp)[1] = 0; break; }
	}

	/*
	 * check authentication to the server before sending NNTP/HTTP
	 * response header with status "200 OK" to the client.
	 * duplicated operation for LIST or GROUP should be erased in future. 
	 */
	notfound = 0;
	if( Msgid[0] == 0 &&  Anum1 == 0 && strchr(groupanum,'/') == NULL ){
		if( Lfp = NNTP_openLIST(Nsid,expireL,"active") )
		{
			if( notfound = matchgroup(Lfp,Group) <= 0 )
				sv1log("## Unknown Group: %s\n",Group);
			fclose(Lfp);
		}
	}else{
		NNTP_getGROUP(Nsid,expireL,Group,&nart,&Min,&Max);

		if( Anum1 < 0 || Anum2 < 0 ){ /* $N for Nth before the Max */
			if( Anum1 < 0 ){
				Anum1 += 1 + Max;
				if( Anum1 < Min ) Anum1 = Min;
			}
			if( Anum2 < 0 ){
				Anum2 += 1 + Max;
				if( Anum2 < Min ) Anum2 = Min;
			}
		}
		if( tooWideRange(Conn,env,tc) ){
			tc_sav = NULL;
			totalc = 0;
			goto EXIT;
		}

		if( notfound = nart < 0 ){ /* 8.10.4 */
			sv1log("## Unknown or Inactive Group: %s\n",Group);
		}else
		if( Max < Min || Min == 0 && Max == 0 ){
			/* empty group indicated by NNTP commands as
			 * Max < Min by LIST ACTIVE, or
			 * Min == 0 && Max == 0 by GROUP.
			 */
		}else
		if( notfound = Max <= 0 )
			sv1log("## Unknown or Inactive Group: %s\n",Group);
		else
		if( Anum1 == 0 && Anum2 == 0 ){
			/* latest art. list */
		}else
		if( notfound = (Anum1<Min && Anum2<Min) || (Max<Anum1 && Max<Anum2) )
			sv1log("## OutRange: %s[%d-%d] %d-%d\n",Group,
				Min,Max,Anum1,Anum2);
	}
	switch( NNTP_authERROR(Nsid) ){
		case 503:
			fprintf(tc,"HTTP/1.0 503\r\n");
			fprintf(tc,"\r\n");
			fprintf(tc,"503 Not available (A)[%d]\r\n",getpid());
			*stcodep = 503;
			tc_sav = NULL;
			goto EXIT;
	}
	if( notfound ){
		if( HTTP_setRetry(Conn,req,404) ){
			*stcodep = 404;
			/*
			return 0;
			must close server socket and duplicated client socket
			*/
			totalc = 0;
			if( 0 <= ToS )
				goto EXIT_2;
			else	goto EXIT_3;
		}

		NNTP_getGROUP(Nsid,expireL,Group,&nart,&Min,&Max);
		if( Msgid[0] == 0 && Anum1 == 0 ) /* access to group */
		if( 0 < Max && strtailchr(UrlSelf) != '/' ){
			sprintf(url,"%s/",UrlSelf);
			if( Search[0] )
				Xsprintf(TVStr(url),"?%s",Search);
			totalc = putMovedTo(Conn,tc,url);
			*stcodep = 302;
		}else{
		totalc = putUnknownMsg(Conn,tc,req);
		*stcodep = 404;
		}
		else{ /* access to article */
			if( NNTP_authERROR(Nsid) ){
				totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,"Authentication Failure.\r\n");
				*stcodep = 401;
			}else{
				totalc = putUnknownMsg(Conn,tc,req);
				*stcodep = 404;
			}
		}
		tc_sav = NULL;
		goto EXIT;
	}
	if( NNTP_authERROR(Nsid) && streq(proto,"pop") ){
		IStr(msg,1024);
		refQStr(mp,msg);
		Rsprintf(mp,"Invalid username or password.\r\n");
		if( IsMounted && strchr(auser,'@') ){
			Rsprintf(mp,"Might be configured to pass through your auth. info.");
			Rsprintf(mp," with the 'authru' MountOption.\r\n");
		}
		totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,msg);
		*stcodep = 401;
		tc_sav = NULL;
		goto EXIT;
	}
	if( NNTP_authERROR(Nsid) ){
		totalc = putNotAuthorized(Conn,tc,req,ProxyAuth,NULL,
"Requried username and password to access the news-server.\r\n");
		*stcodep = 401;
		tc_sav = NULL;
		goto EXIT;
	}
	if( fa1 = getv(Fav,"JumpTo") ){
		truncVStr(url);
		strcpy(url,UrlSelf);
		if( dp = strrchr(url,'/') ){
			dp++;
			truncVStr(dp);
		}
		psize = setupPAGESIZE(env);
		if( strneq(fa1,"range.",6) ){
			scanRange(env,fa1+6);
			Xsprintf(TVStr(url),"%d-%d",Anum1,Anum2);
		}else
		if( streq(fa1,"wider") ){
			setupRange(env,psize);
			strcat(url,Wide);
		}else
		if( streq(fa1,"narrower") ){
			setupRange(env,psize);
			strcat(url,Narrow);
		}else
		if( streq(fa1,"next") ){
		}else
		if( streq(fa1,"prev") ){
		}
		if( url[0] ){
			if( digestLen != 4 ){
				Xsprintf(TVStr(url),"?digest=%d",digestLen);
			}
			totalc = putMovedTo(Conn,tc,url);
			*stcodep = 302;
			goto EXIT_2; /* for closeServer() and DUP_ToC */
			/*
			return totalc;
			*/
		}
	}

	totalc = 0;
	tc_sav = tc;
	tc = TMPFILE("NNTP/HTTP-response");

/*
if( user[0] ) fprintf(tc,"User[%s]<BR>\r\n",user);
*/

	strcpy(UserClass,"anonymous");
	Nadmin = getSubscription(Conn,NULL,UserClass,Group,&Nsubsc,&Nunsub);
	Subscribe = Nunsub <= Nsubsc;
	if( strncmp(Search,"Admin",5) == 0 || getv(Fav,"Admin") ){
		if( Anum1 != Anum2 ){
			setupRange(env,psize);
			setArtAttrs(Conn,env,Anum1);
			if( strneq(req,"POST",4) ){
			Fac += HTTP_form2v(Conn,fc,elnumof(Fav)-Fac,Fav+Fac);
			}
		}
		newsAdmin(Conn,AVStr(UserClass),tc,env,Group,AVStr(Search));
		goto EXIT;
	}

	if( Msgid[0] == 0 )
	if( Anum1 == 0 && strchr(groupanum,'/') == NULL ){
		Lfp = NNTP_openLIST(Nsid,expireL,"active");

		if( Lfp != NULL ){
			int lbaselen;
			int nact,nall,nhit,nempty;
			CStr(url,1024);
			const char *dp;

			LastMod = file_mtime(fileno(Lfp));
			if( strstr(groupanum,"Jump") && strcmp(Search,"Menu") == 0 ){
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-Top","news/top.dhtml",NULL,(iFUNCP)printItem,env);
				putFrogForDeleGate(Conn,tc,"");
				goto EXIT;
			}
			if( strstr(groupanum,"Jump") && strcmp(Search,"Menu") != 0 ){
				unescape_specials(Search,"/","");
				if( Search[0] == 0 || strchr(Search,'/') ){
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-Jump","news/jump.dhtml",NULL,(iFUNCP)printItem,env);
					putFrogForDeleGate(Conn,tc,"");
					goto EXIT;
				}
				strcpy(Group,Search);
				if( Group[0] == '*' )
					Layered = 0;
			}
			if( CTX_mount_url_fromL(Conn,AVStr(url),"nntp",Hostport,Group,NULL,MyProto,"-.-") ){
				Mounted = 1;
				strcpy(Group,url);
				if( dp = strrchr(Group,'/') )
					strcpy(Rgroup,dp+1);
				else	Rgroup[0] = 0;
			}else{
				Mounted = 0;
				strcpy(Rgroup,Group);
			}

			lbaselen = strlen(Group);
			if( strcmp(Search,"Flat") == 0 )
				Layered = 0;

putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-NGList","news/nglist.dhtml",NULL,(iFUNCP)printItem,env);

			fclose(Lfp);
			putFrogForDeleGate(Conn,tc,"");

		}else{
			if( !NNTP_authERROR(Nsid) ){
				fprintf(tc,"cannot get active list.\r\n");
				putFrogForDeleGate(Conn,tc,"");
			}
		}
		goto EXIT;
	}


	if( !Subscribe ){
		fprintf(tc,
		"This newsgroup `%s'is unsubscribed for <I>anonymous</I> users.\r\n",
			Group);
		fprintf(tc,"See <A HREF=?Admin>Administration<A>.");
		goto EXIT;
	}

	NNTP_getGROUP(Nsid,expireL,Group,&nart,&Min,&Max);
	if( Anum1 < 0 ) Anum1 += 1 + Max;
	if( Anum2 < 0 ) Anum2 += 1 + Max;

	if( NNTP_authERROR(Nsid) )
		goto EXIT;
	else{
		psize = setupPAGESIZE(env);
	}

	if( Source ){
		putArts(Conn,tc,env);
	}else{
		sprintf(Hbase,"");
		if( Msgid[0] ){
			if( Anum1 != 0 ){
				sprintf(Hbase,"../%s/",Prgroup);
				sprintf(Self,"../%s/%d",Prgroup,Anum1);
			}else	sprintf(Self,"../%s/%s",someGroup(),Msgid);
		}else{
			if( Anum1 == Anum2 )
				sprintf(Self,"%d",Anum1);
			else	sprintf(Self,"%d-%d",Anum1,Anum2);
		}

		if( Anum1 != Anum2 ){
			setupRange(env,psize);
			setArtAttrs(Conn,env,Anum1);
		}else{
			Wide[0] = 0;
			Narrow[0] = 0;
			if( setArtAttrs(Conn,env,Anum1) < 0 ){
				/*
				if( tc_sav != NULL ){
					fclose(tc);
					tc = tc_sav;
					tc_sav = NULL;
				}
				totalc = putUnknownMsg(Conn,tc,req);
				*stcodep = 404;
				goto EXIT;
				*/
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Nonexistent-Art","news/artnone.dhtml",NULL,(iFUNCP)printItem,env);
				*stcodep = 404;
				status = "404 bad article";
				goto TAIL;
			}
		}
		if( NNTP_authERROR(Nsid) == 503 ){
			goto EXIT;
		}
putBuiltinHTML(Conn,tc,"NNTP/HTTP-Gateway-ARTList","news/artlist.dhtml",NULL,(iFUNCP)printItem,env);

	TAIL:
		if( !PrintMode )
		if( !NoTailer )
			putFrogForDeleGate(Conn,tc,"");
	}

EXIT:
	if( tc_sav != NULL ){
		if( NNTP_authERROR(Nsid) == 503 ){
			fprintf(tc_sav,"HTTP/1.0 503\r\n");
			fprintf(tc_sav,"\r\n");
			fprintf(tc_sav,"503 Not available (B)[%d]\r\n",getpid());
			*stcodep = 503;
		}else
		if( !cached_authOK && NNTP_authERROR(Nsid) ){
			putNotAuthorized(Conn,tc_sav,req,ProxyAuth,NULL,"");
			*stcodep = 401;
		}else{
			fflush(tc);
			fseek(tc,0,0);
			length = file_size(fileno(tc));

			if( Charset[0] ){
				const char *cset;
				strcpy(xctype,ctype);
				if(!CCXguessing(CCX_TOCL)
				 && CCXoutcharset(CCX_TOCL,&cset) ){
					int isKnownCharset(PCStr(name));
					if( cset && isKnownCharset(cset) ){
						CCX_setindflt(CCX_TOCL,cset);
					}
				replace_charset_value(AVStr(xctype),cset,1);
				}else
				replace_charset_value(AVStr(xctype),Charset,1);
				ctype = xctype;
			}
			if( insNonJP || CCXinsNonJP(CCX_TOCL) ){
				/* CCX is disalbed by nonJP, so it must not be
				 * converted as JP in
				 * putHttpMssg() -> CCV_relay_text()
				 * ... nonJP strings should have been converted
				 * into ASCII as {#CCX:unknown-charset:...}
				 * article (non-article list)
				 */
				CCX_setincode(CCX_TOCL,"nonJP");
			}else
			CCX_resetincode(CCX_TOCL);
			/* duplicated CCX in putHttpMssg()->relay_texts()
			 * shold be suppressed...
			 */

			if( LastMod <= 0 )
				LastMod = DELEGATE_LastModified;
			toMD5(etagsrcbuf,genETag);

			/* new-140504c Pragma: no-cache */
			if( fa1 = getv(Fav,"Pragma") ){
				if( streq(fa1,"no-cache") ){
					strcat(addRespHeaders,"Pragma: no-cache\r\n");
					strcat(addRespHeaders,"Cache-Control: no-cache\r\n");
				}
			}

			totalc = putHttpMssg(Conn,tc_sav,tc,req,vno,NULL,ctype,
				NULL,length,LastMod,Expires,status);
			/*
				NULL,length,LastMod,Expires,NULL);
			*/
		}
		fclose(tc);
		tc = tc_sav;
	}

EXIT_2:
	fflush(tc);
	if( streq(proto,"pop") ){
		CStr(rusg,128);
		NNTP_closeServer(Nsid);
		strfRusage(AVStr(rusg),"%uu %ss %SS %RR %ii %oo %sx",3,NULL);
		sv1log("Rusage: %s\n",rusg);
	}else
	/* connection should be held in the Private-MASTER */
	/* but the initialization is heavy ... */
	/* 961125 3.0.59: Now the cost for connection is not so heavy
	 * because the Private-MASTER has become a StickyServer,
	 * initializations are suppressed on reuse...
	 */
	if( *stcodep == 401 ){
		NNTP_closeServer(Nsid);
	}else
	if( lSINGLEP() ){
		sv1log("reuse serv(%d) in single-process mode\n",Conn->nn_nsid);
		/* just clear file-descriptor values in Conn. */
		NNTP_closeServerFds(Conn,Conn->nn_nsid);
		Conn->nn_nsid = 0;
	}else
	if( KeepAlive ){
		/* the connection to the client will be kept-alive,
		 * thus keep alive the connection to the server also.
		 */
	}else
	/*if( MasterIsPrivate || Conn->sv_viaCc )
	 *  This connection will not reused so effectively when this 
	 *  proxy is shared by many clients for many servers.
	 *  Also, unexpected EOF from the server may occur.
	 */
	{
		/* when the connection is not expensive, the connection
		 * should be closed so that it will be reused by others.
		 */
		NNTP_closeServer(Nsid);
	}

EXIT_3:
	fclose(Tmpfp);
	fclose(tc);
	DUP_ToC = -1;
	return totalc;
}
int closeNNTPserver(Connection *Conn){
	int nsid;
	if( (nsid = Conn->nn_nsid) <= 0 ){
		return 0;
	}
	NNTP_closeServer(nsid);
	Conn->nn_nsid = 0;
	return 1;
}

static NewsEnv *env1;
static scanListFunc phead(PCStr(group),Connection *Conn)
{	CStr(url,1024);

	if( CTX_mount_url_fromL(Conn,AVStr(url),"nntp",env1->e_hostport,group,NULL,MyProto,"-.-") )
		return 1;
	return 0;
}

static FILE *permitted_head(PVStr(head),FILE *tc,FILE *cache)
{	const char *ng;
	CStr(groups,1024);
	int permitted;

	if( env1->mounted )
	if( ng = findFieldValue(head,"Newsgroups") ){
		lineScan(ng,groups);
		permitted = scan_commaList(groups,0,scanListCall phead,curConn);
		if( !permitted ){
			sv1log("#### Not allowed: %s\n",groups);
			/* this causes duplicate fclose()
			fclose(tc);
			*/
			return NULL;
		}
	}
	return tc;
}

int MC_setMasks(int mask);
int MC_setAnons(int mask);
int setArticleMasks(PCStr(opts),PCStr(host),int port,PCStr(group),int anum);
const char *setFilterAnons(PCStr(rewaddr));

extern char mailClientId[16];
extern char mailClientAddr[32];
void getClientAddrId(Connection *Conn,PVStr(saddr),PVStr(sid));

static FILE *openArt1(Connection *Conn,NewsEnv *env)
{	FILE *afp;
	CStr(cpath,1024);

	MC_setMasks(0);
	MC_setAnons(0);
	if( 0 < Anum ){
		CStr(rewa,256);
		if( MountOptions )
			getOpt1(MountOptions,"rewaddr",AVStr(rewa));
		else	strcpy(rewa,"");
		setArticleMasks(rewa,"-.-",119,Group,Anum);
		if( OrigFrom[0] )
		setPosterMasks(OrigFrom);
		setFilterAnons(rewa);
		getClientAddrId(Conn,FVStr(mailClientAddr),FVStr(mailClientId));
	}

	if( Msgid[0] && Anum == 0 )
		afp = NNTP_openArticle(Nsid,ExpireA,Msgid,GroupHint,0,AVStr(cpath));
	else	afp = NNTP_openArticle(Nsid,ExpireA,Msgid,Group,Anum,AVStr(cpath));
	return afp;
}

static int setArtAttrs(Connection *Conn,NewsEnv *env,int anum)
{	FILE *afp;

	Anum = anum;
	if( afp = openArt1(Conn,env) ){
		getArtAttrs(Conn,env,afp);
		fclose(afp);
		return 0;
	}
	strcpy(Subject,"{#uninit-Subject#}");
	return -1;
}

int putArts(Connection *Conn,FILE *tc,NewsEnv *env)
{	MrefQStr(ep,Emptyarts); /**/
	FILE *afp;
	CStr(prevsubj,2048);

	prevsubj[0] = 0;

	Emptyarts[0] = 0;
	ep = Emptyarts;

	set_HEAD_filter(permitted_head);
	env1 = env;

sv1log("putARTICLE(%s,%d-%d) %s/%s\n",Group,Anum1,Anum2,GroupHint,Msgid);

	/* if( Anum1 < Min ) Anum1 = Min; can be left in cache ?? */
	if( Max < Anum2 ) Anum2 = Max;

	for( Anum = Anum1; Anum <= Anum2; Anum++ ){
		afp = openArt1(Conn,env);
		if( afp != NULL ){
			if( Source && Anum1 == Anum2 ){
				if( isANON & HIDE_BODY ){
					ep = Sprintf(AVStr(ep),"((((HIDDEN)))");
					continue;
				}
				str_sprintf(&ETagsrc,"%d",Anum);
/* #### copy charset */
if( Charset[0] == 0 || strcaseeq(Charset,"US-ASCII") ){
	CStr(ctype,256);
	if( fgetsHeaderField(afp,"Content-Type",AVStr(ctype),sizeof(ctype)) ){
		get_charset(ctype,AVStr(Charset),sizeof(Charset));
		sv1log("Source Cotent-Type: charset=%s\n",Charset);
	}
 }
/*
				copy_file(afp,tc,NULL);
*/
				RFC821_recvdata(afp,tc);
			}else{
				str_sprintf(&ETagsrc,"%d,",Anum);
				fseek(Tmpfp,0,0);
				PGPdecodeMIME(afp,Tmpfp,NULL,0x2FF,0,0);
				Ftruncate(Tmpfp,0,1);
				fseek(Tmpfp,0,0);

putARTICLE(Conn,env,Tmpfp,tc,Anum1==Anum2,AVStr(prevsubj));

			}
			fclose(afp);
		}else{
			LastMod = Start;
			ep = Sprintf(AVStr(ep),"[%d]",Anum);
			Verbose("No article: %s:%d\n",Group,Anum);
		}
	}
	env1 = NULL;
	return 1;
}

static int matchgroup(FILE *lfp,PCStr(group))
{	CStr(act,2048);
	int len;

	if( group[0] == 0 )
		return 1;

	len = strlen(group);
	while( fgets(act,sizeof(act),lfp) != NULL ){
/*
matching tail string of group name should be supported...
		if( *group == '*' ){
			if( strstr(act,group+1) )
				return 1;
		}
*/
		if( strncmp(act,group,len) == 0 )
/*
matching by any length of substrings can be useful.
		if( act[len] == '.'  || act[len] == ' ' )
*/
			return 1;
	}
	return 0;
}

static const char *checkng(NewsEnv *env,PCStr(base),PCStr(group))
{	int len;
	CStr(act,2048);
	const char *err;
	FILE *lfp;

	lfp = NNTP_openLIST(Nsid,-1,"active");
	if( lfp == NULL )
		return "no active file";

	err = "unknown newsgroup";
	len = strlen(group);

	fseek(lfp,0,0);
	while( fgets(act,sizeof(act),lfp) ){
		if( strncmp(act,group,len) == 0 ){
			if( act[len] == ' ' ){
				err = NULL;
				break;
			}
			if( act[len] == '.' )
				err = "meta newsgroup";
		}
	}

	fclose(lfp);
	return err;

}

int NNTP_mailToPoster(Connection *Conn,int nsid,PCStr(grp),int ano,PCStr(key),FILE *mfp,PVStr(res),int siz);
int NNTP_replyToPoster(Connection *Conn,int nsid,PCStr(grp),int ano,FILE *qfp,PVStr(stat));
int makeAdminKey(PCStr(from),PVStr(key),int siz);
FILE *ACL_fopen(PCStr(proto),PCStr(host),int port,PCStr(upath),int wr,PVStr(p));
int ACL_edit(FILE *fp,int op,PCStr(nam),PVStr(val));
int ACL_get(PCStr(pr),PCStr(ho),int po,PCStr(upath),PCStr(nam),PVStr(val));

static const char *MC_GECOS = "_GECOS";
static const char *MC_BODY  = "_Body";
static const char *MC_SIGNA = "_Signature";
static const char *MC_POSTER= "_Poster";
static const char *MC_MSGID = "_MessageID";
static const char *MC_EMAIL = "_Email";
static const char *MC_PHONE = "_Phone";

static const char *MC_MGECOS  = "maskFrom";
static const char *MC_MBODY   = "maskBody";
static const char *MC_MSIGNA  = "maskSign";
static const char *MC_APOSTER = "anonFrom";
static const char *MC_AMSGID  = "anonMsgid";
static const char *MC_AEMAIL  = "anonEmail";
static const char *MC_APHONE  = "anonPhone";

static void __strcat(PVStr(dstr),PCStr(sstr)){
	if( dstr[0] != 0 )
		strcat(dstr,",");
	strcat(dstr,sstr);
}
#define _strcat(d,s) __strcat(AVStr(d),s)
static void addMask(NewsEnv *env,PCStr(prx),PCStr(mflag)){
	CStr(fv,128);
	sprintf(fv,"%s%s=on",prx,mflag);
	if( lHTMLGEN() ){
		fprintf(stderr,"-- [%2d] %s\n",Fac,fv);
	}
	Fav[Fac++] = strid_alloc(fv);
	Fav[Fac] = 0;
}
static void getAnon1(NewsEnv *env,PCStr(mask),PCStr(mflag)){
	if( streq(mask,"*") )
		mask = "_Poster,_MessageID,_Email,_Phone";
	if( isinList(mask,MC_POSTER)) addMask(env,MC_APOSTER,mflag);
	if( isinList(mask,MC_MSGID) ) addMask(env,MC_AMSGID, mflag);
	if( isinList(mask,MC_EMAIL) ) addMask(env,MC_AEMAIL, mflag);
	if( isinList(mask,MC_PHONE) ) addMask(env,MC_APHONE, mflag);
}
static void getAnons(NewsEnv *env,PCStr(proto),PCStr(host),int port,PCStr(path),PCStr(mname),PCStr(mflag)){
	CStr(mask,256);
	if( ACL_get(proto,host,port,path,mname,AVStr(mask)) == 0 )
		return;
	if( lHTMLGEN() )
		fprintf(stderr,"-- GOT %5s %s[%s] %s\n",mname,mflag,mask,path);
	getAnon1(env,mask,mflag);
}
static void getMasks(NewsEnv *env,PCStr(proto),PCStr(host),int port,PCStr(path),PCStr(mname),PCStr(mflag)){
	CStr(mask,256);
	if( ACL_get(proto,host,port,path,mname,AVStr(mask)) == 0 )
		return;
	if( lHTMLGEN() )
		fprintf(stderr,"-- GOT %5s %s[%s] %s\n",mname,mflag,mask,path);
	if( isinList(mask,MC_GECOS) ) addMask(env,MC_MGECOS,mflag);
	if( isinList(mask,MC_BODY ) ) addMask(env,MC_MBODY, mflag);
	if( isinList(mask,MC_SIGNA) ) addMask(env,MC_MSIGNA,mflag);
}
static const char *getvF(const char *av[],PCStr(fn),PCStr(ff)){
	CStr(fname,256);
	sprintf(fname,"%s%s",fn,ff);
	return getv(av,fname);
}
static void putMasks(NewsEnv *env,PCStr(proto),PCStr(host),int port,PCStr(path),PCStr(mname),PCStr(mflag)){
	FILE *afp;
	CStr(mask,256);
	CStr(cpath,1024);

	if( (afp = ACL_fopen(proto,host,port,path,1,AVStr(cpath))) == NULL )
		return;
	truncVStr(mask);

	if( getvF(Fav,MC_MGECOS,mflag) ) _strcat(mask,MC_GECOS);
	if( getvF(Fav,MC_MBODY, mflag) ) _strcat(mask,MC_BODY);
	if( getvF(Fav,MC_MSIGNA,mflag) ) _strcat(mask,MC_SIGNA);

	if( lHTMLGEN() )
		fprintf(stderr,"-- SET %5s %s[%s] %s\n",mname,mflag,mask,cpath);
	ACL_edit(afp,3,mname,AVStr(mask));
	fclose(afp);
}
static void putAnons(NewsEnv *env,PCStr(proto),PCStr(host),int port,PCStr(path),PCStr(mname),PCStr(mflag)){
	FILE *afp;
	CStr(mask,256);
	CStr(cpath,1024);

	if( (afp = ACL_fopen(proto,host,port,path,1,AVStr(cpath))) == NULL )
		return;
	truncVStr(mask);

	if( getvF(Fav,MC_APOSTER,mflag) ) _strcat(mask,MC_POSTER);
	if( getvF(Fav,MC_AMSGID, mflag) ) _strcat(mask,MC_MSGID);
	if( getvF(Fav,MC_AEMAIL, mflag) ) _strcat(mask,MC_EMAIL);
	if( getvF(Fav,MC_APHONE, mflag) ) _strcat(mask,MC_PHONE);
	ACL_edit(afp,3,mname,AVStr(mask));
	fclose(afp);
}

static void artAdmin(Connection *Conn,NewsEnv *env){
	FILE *tmp;
	const char *key;
	const char *com;
	CStr(stat,1024);
	int code;
	const char *cpasq;
	const char *cpasa;
	const char *froma = 0;
	CStr(authb,128);
	const char *comment;
	CStr(addrQ,128);
	CStr(addrA,128);
	CStr(path,1024);
	CStr(mask,128);
	CStr(emaddr,128);
	CStr(emhost,128);
	CStr(emname,128);
	int noXFromFp = 0;

	if( XFromFp[0] == 0 ){
		CStr(akey,128);
		noXFromFp = 1;
		makeAdminKey(OrigFrom,AVStr(akey),sizeof(akey));
		strcpy(XFromFp,akey+16);
		if( lHTMLGEN() )
			fprintf(stderr,"-- KEY GENERATED [%s][%s]\n",akey,
				OrigFrom);
	}

	com = getv(Fav,"com");
	key = getv(Fav,"authKey");
	cpasq = getv(Fav,"clientPassQ");
	cpasa = getv(Fav,"clientPassA");
	froma = getv(Fav,"adminEmail");

	strcpy(path,Group);
	strsubst(AVStr(path),".","/");
	Xsprintf(TVStr(path),"/%03d/%02d",Anum1/100,Anum1%100);

	if( com == 0 || *com == 0 ){
		/* GET */
	}else
	if( strcaseeq(com,"refresh") ){
	}else
	if( strcaseeq(com,"sendkey")
	 || strcaseeq(com,"sendarticle")
	 || strcaseeq(com,"sendcomment")
	){
	    if( froma == 0 || *froma == 0 ){
		sprintf(admResp,"- ERROR: specify Email-Address\n");
	    }else
	    if( cpasq==0 || cpasa==0 || !strcaseeq(cpasq,cpasa) ){
		sprintf(admResp,"- ERROR: bad passString\n");
		if( lHTMLGEN() ){
			fprintf(stderr,"pass-String[%s][%s]\n",
				cpasq?cpasq:"",cpasa?cpasa:"");
		}
	    }else{
		int times = decIntB32(cpasa);
		if( times <= time(0)-120 || time(0) < times ){
			sprintf(admResp,"- ERROR: stale passString\n");
			goto EXIT;
		}

		tmp = TMPFILE("NewsAdmin");
		if( froma ){
			fprintf(tmp,"From: %s\r\n",froma);
		}
		if( comment = getv(Fav,"comment") ){
			fprintf(tmp,"\r\nComment:\n %s\r\n",comment);
			/* copy data indenting, with size limitation, ... */
		}
		fflush(tmp);
		fseek(tmp,0,0);

		truncVStr(stat);
		if( noXFromFp ){
			code = NNTP_replyToPoster(Conn,Nsid,Group,Anum1,tmp,
				AVStr(stat));
		}else{
			code = NNTP_mailToPoster(Conn,Nsid,Group,Anum1,key,tmp,
				AVStr(stat),sizeof(stat));
		}
		if( code == 0 ){
			sprintf(admResp,"+ OK\n");
		}else{
			sprintf(admResp,"- ERROR: %s\n",stat);
		}
		fclose(tmp);
	    }
	}else
	if( strcaseeq(com,"submit") ){
		int authERR = 1;
		if( key == 0 || *key == 0 ){
			sprintf(admResp,"- ERROR: no Auth-Key\n");
			return;
		}
		if( froma ){
			CStr(keyR,128);
			makeAdminKey(froma,AVStr(keyR),sizeof(keyR));
if( lHTMLGEN() )
fprintf(stderr,"-- KEY for [%s] [%s][%s] %s\n",froma,key,keyR,XFromFp);
			if( strtailstr(keyR,XFromFp) == 0 ){
				sprintf(admResp,"- ERROR: bad Email-Address\n");
				/*
				return;
				*/
			}
			else
			if( strncmp(keyR,key,8) != 0 ){
				sprintf(admResp,"- ERROR: bad Auth-Key\n");
			}
			else{
				authERR = 0;
			}
		}
		if( OrigFrom[0] ){
			CStr(keyR,128);
			makeAdminKey(OrigFrom,AVStr(keyR),sizeof(keyR));
if( lHTMLGEN() )
fprintf(stderr,"-- KEY for [%s] [%s][%s]\n",OrigFrom,key,keyR);
			if( strncmp(keyR,key,8) != 0 ){
				sprintf(admResp,"- ERROR: bad Auth-Key\n");
			}
			else{
				authERR = 0;
			}
		}
		if( authERR ){
			return;
		}else{
			sprintf(admResp,"+ OK\n");
		}

		putMasks(env,"smtp","-.-",25, XFromFp, "Mask","P");
		putMasks(env,"smtp","-.-",25, XFromFp,"XMask","X");
		putMasks(env,"nntp","-.-",119,path,    "Mask","A");

		putAnons(env,"smtp","-.-",25, XFromFp, "Anon","P");
		putAnons(env,"smtp","-.-",25, XFromFp,"XAnon","X");
		putAnons(env,"nntp","-.-",119,path,    "Anon","A");
	}else{
		sprintf(admResp,"- ERROR: not supported yet\n");
	}

EXIT:
    {
	int ai;
	int ax = 0;
	const char *fa1;
	for( ai = 0; ai < Fac; ai++ ){
		fa1 = Fav[ai];
		if( !(strneq(fa1,"mask",4) && strtailstr(fa1,"=on"))
		 && !(strneq(fa1,"anon",4) && strtailstr(fa1,"=on")) ){
			Fav[ax++] = fa1;
		}
	}
	Fac = ax;
    }

	getMasks(env,"smtp","-.-",25, XFromFp, "Mask","P");
	getMasks(env,"smtp","-.-",25, XFromFp,"XMask","X");
	getMasks(env,"nntp","-.-",119,"",      "Mask","S");
	getMasks(env,"nntp","-.-",119,path,    "Mask","A");
	if( MountOptions ){
		CStr(rewa,128);
		getOpt1(MountOptions,"rewaddr",AVStr(rewa));
		scan_ListElem1(rewa,':',AVStr(mask));
		getAnon1(env,mask,"S");
	}
	getAnons(env,"smtp","-.-",25, XFromFp, "Anon","P");
	getAnons(env,"smtp","-.-",25, XFromFp,"XAnon","X");
	getAnons(env,"nntp","-.-",119,"",      "Anon","S");
	getAnons(env,"nntp","-.-",119,path,    "Anon","A");
}

void newsAdmin(Connection *Conn,PVStr(user),FILE *tc,NewsEnv *env,PCStr(group),PVStr(search))
{
	int ai;
	const char *fa1;

	if( lHTMLGEN() ){
		for( ai = 0; ai < Fac; ai++ ){
			fprintf(stderr,"[%d] %s\n",ai,Fav[ai]);
		}
	}
	truncVStr(admResp);
	if( Anum1 == Anum2 || 0 < Anum1 && Anum2 == 0 ){
		artAdmin(Conn,env);
		strcat(addRespHeaders,"Pragma: no-cache\r\n");
	}
	httpAdmin(Conn,AVStr(user),tc,group,AVStr(search),env,(iFUNCP)printItem,(sFUNCP)checkng,AVStr(AclID));
}

int creyInt32(int val,int dec);
int enBase32(PCStr(src),int sbits,PVStr(dst),int dsiz);
void encIntB32(int iv,PVStr(str),int siz){
	int now;
	int eiv;
	CStr(bi,5);

	eiv = creyInt32(iv,0);
	setVStrElem(bi,0,eiv>>24);
	setVStrElem(bi,1,eiv>>16);
	setVStrElem(bi,2,eiv>>8);
	setVStrElem(bi,3,eiv);
	enBase32(bi,32,AVStr(str),siz);
/*
	strtolowerX(str,AVStr(str),siz);
*/
}
int deBase32(PCStr(src),int slen,PVStr(dst),int dsiz);
int decIntB32(PCStr(str)){
	CStr(bi,8);
	const unsigned char *u = (const unsigned char*)bi;
	int eiv,iv;

	deBase32(str,strlen(str),AVStr(bi),sizeof(bi));
	eiv = u[0]<<24 | u[1]<<16 | u[2]<<8 | u[3];
	iv = creyInt32(eiv,1);
	return iv;
}
