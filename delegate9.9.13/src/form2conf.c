/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005-2006 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	form2conf.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	HTML Form to/from DeleGate configuration data
History:
	950913	extracted from admin.c
//////////////////////////////////////////////////////////////////////#*/
#include "dglib.h"
#include "delegate.h"
#include "param.h"
#include "file.h"
#include "proc.h"
#include "htadmin.h"

const char *DHTML_ENC = "&'\"\\<>%{}:?|~";

int encodeEntitiesY(PCStr(src),PVStr(dst),int dsize,PCStr(cset),int anywhere){
	const char *sp;
	refQStr(dp,dst);
	int ch;

	for( sp = src; ch = *sp; sp++ ){
		if( strchr(cset,ch) ){
			switch( ch ){
				case '<': strcpy(dp,"&lt;"); break;
				case '>': strcpy(dp,"&gt;"); break;
				case '&': strcpy(dp,"&amp;"); break;
				case '"': strcpy(dp,"&quot;"); break;
/*
MSIE does not recognize this.
				case '\'': strcpy(dp,"&apos;"); break;
*/
				default: sprintf(dp,"&#%d;",ch); break;
			}
			dp += strlen(dp);
		}else{
			setVStrPtrInc(dp,ch);
		}
	}
	setVStrEnd(dp,0);
/*
if(!streq(src,dst)) fprintf(stderr,"<<<< %s\n>>>> %s\n",src,dst);
*/
	return 0;
}

#define E1SIZ(mask)		(sizeof(mask[0])*8)
#define MaskDoSet(mask,fx)	(mask[fx/E1SIZ(mask)] |= (1<<(fx%E1SIZ(mask))))
#define MaskUnset(mask,fx)	(mask[fx/E1SIZ(mask)] &= ~(1<<(fx%E1SIZ(mask))))
#define MaskIsSet(mask,fx)	(mask[fx/E1SIZ(mask)] &  (1<<(fx%E1SIZ(mask))))
static int maskIsZero(int mask[],int size){
	int i;
	for( i = 0; i < size; i++ ){
		if( mask[i] != 0 )
			return 0;
	}
	return 1;
}
#define MaskIsZero(mask)	maskIsZero(mask,elnumof(mask))
#define MaskClear(m)		{int i;for(i=0;i<elnumof(m);i++)m[i]=0;}
#define MaskReverse(m)		{int i;for(i=0;i<elnumof(m);i++)m[i]= ~m[i];}

int check_paramX(PCStr(param),int warn,PVStr(diag));
int HTML_scan1(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
int HTML_ccxput1s(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
int HTML_put1sX(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
#define put1sX HTML_put1sX
char *strfLoadStatX(PVStr(str),int size,PCStr(fmt),int now,int fd);
int getpidof(PCStr(name));
int admin_authok(Connection *Conn);

extern const char *config_self;
char *getConfigData(Connection *Conn,PCStr(serv),PCStr(pfx),int *datep);
int getConfigList(int mac,const char *av[],PCStr(neg));
int getServerList(int mac,const char *av[],PCStr(neg));
FILE *fopenSvstats(PCStr(port),PCStr(mode));
typedef FILE *(*fileFunc)(PCStr(port),PCStr(mode));
FILE *fopenXDGfile(Connection *Conn,PCStr(serv),PCStr(mode),fileFunc func);

static char CP_conf_ERROR[]	= "conf-ERROR";
static char CP_conf_checked[]	= "conf-checked";
static char CP_confdata[]	= "confdata";
static char CP_conf_data[]	= "conf-data";
static char CP_conf_protocol[]	= "conf-protocol";
static char CP_conf_server[]	= "conf-server";
static char CP_conf_serverx[]	= "conf-serverx";
static char CP_conf_usrport[]	= "conf-usrport";
static char CP_conf_usrpadr[]	= "conf-usrpadr";
static char CP_conf_usrpadrx[]	= "conf-usrpadrx";
static char CP_conf_ssl[]	= "conf-ssl";
static char CP_conf_CHROOTx[]	= "conf-CHROOTx";
static char CP_conf_DGROOTx[]	= "conf-DGROOTx";
static char CP_conf_DGROOT[]	= "conf-DGROOT";
static char CP_conf_VARDIRx[]	= "conf-VARDIRx";
static char CP_conf_VARDIR[]	= "conf-VARDIR";
static char CP_conf_TMPDIRx[]	= "conf-TMPDIRx";
static char CP_conf_TMPDIR[]	= "conf-TMPDIR";
static char CP_conf_ADMIN[]	= "conf-ADMIN";
static char CP_conf_admin[]	= "conf-admin";
static char CP_conf_admport[]	= "conf-admport";
static char CP_conf_admuser[]	= "conf-admuser";
static char CP_conf_admpass[]	= "conf-admpass";
static char CP_conf_loglev[]	= "conf-loglev";
static char CP_conf_REACH[]	= "conf-REACH";
static char CP_conf_REACH_list[]= "conf-REACH-list";
static char CP_conf_AUTHORIZER[]= "conf-AUTHORIZER";
static char CP_conf_servlist[]	= "conf-servlist";
static char CP_conf_userlist[]	= "conf-userlist";
static char CP_conf_logaging[]	= "conf-logaging";
static char CP_conf_logagingx[]	= "conf-logagingx";
static char CP_conf_REL[]	= "conf-REL";
static char CP_conf_RELIABLE[]	= "conf-RELIABLE";
static char CP_conf_MOUNT[]	= "conf-MOUNT";
static char CP_conf_MAXIMA[]	= "conf-MAXIMA";
static char CP_conf_MAXIMA_value[]="conf-MAXIMA-value";
static char CP_conf_TIMEOUT[]	= "conf-TIMEOUT";
static char CP_serv_showall[]	= "serv-showall";

static const char *conf_params[] ={
	CP_conf_ERROR,
	CP_conf_checked,
	CP_confdata,
	"conf-dumpform",
	"conf-type",
	CP_conf_data,
	CP_conf_protocol,
	CP_conf_server,
	CP_conf_serverx,
	CP_conf_usrport,
	CP_conf_usrpadr,
	CP_conf_usrpadrx,
	CP_conf_ssl,
	CP_conf_CHROOTx,
	CP_conf_DGROOTx,
	CP_conf_DGROOT,
	CP_conf_VARDIRx,
	CP_conf_VARDIR,
	CP_conf_TMPDIRx,
	CP_conf_TMPDIR,
	CP_conf_ADMIN,
	CP_conf_admin,
	CP_conf_admport,
	CP_conf_admuser,
	CP_conf_admpass,
	CP_conf_loglev,
	CP_conf_REL,
	CP_conf_RELIABLE,
	CP_conf_REACH,
	CP_conf_REACH_list,
	CP_conf_AUTHORIZER,
	CP_conf_servlist,
	CP_conf_userlist,
	CP_conf_logaging,
	CP_conf_logagingx,
	CP_conf_MOUNT,
	CP_conf_MAXIMA,
	CP_conf_MAXIMA_value,
	CP_conf_TIMEOUT,
	0,
};
/*
not conf_param, but env_params, to be inherited after "decompose,load"
	"com",
	"prevcom",
	"conf-servname",
*/

static int confnamex(PCStr(confname)){
	int ci;
	const char *name;
	for( ci = 0; name = conf_params[ci]; ci++ ){
		if( streq(name,confname) ){
			return ci;
		}
	}
/*
 fprintf(stderr,"-- unknown confname(%s)\n",confname);
*/
	return 0;
}

#define SetConfMask(mask,name)	MaskDoSet(mask,confnamex(name))
void clear_conferrorX(Connection *Conn){
	MaskClear(config_errors);
	MaskClear(admin_getv_mask);
}
void set_conferrorX(Connection *Conn,PCStr(confname)){
	SetConfMask(config_errors,confname);
if( lHTMLGEN() )
 fprintf(stderr,"++ CONFIG ERROR %08X %08X %3d/%s\n",
	config_errors[1],config_errors[0],confnamex(confname),confname);
}

static int get_conferrorX(Connection *Conn,PCStr(confname)){
	int ci;

	if( *confname == 0 ){
		return !MaskIsZero(config_errors);
	}
	if( strchr(confname,',') ){
		int ci;
		const char *name;
		for( ci = 1; name = conf_params[ci]; ci++ ){
			if( MaskIsSet(config_errors,ci) ){
				if( isinList(confname,name) ){
					return 1;
				}
			}
		}
		return 0;
	}
	return MaskIsSet(config_errors,confnamex(confname));
}

const char *admin_getvX(Connection *Conn,PCStr(name)){
	const char *fv;

	if( !MaskIsZero(admin_getv_mask) ){
/*
if( streq(name,"com") ){}else
if( streq(name,"conf-servname") ){
}else
*/
		if( MaskIsSet(admin_getv_mask,confnamex(name)) ){
			return 0;
		}
	}
	fv = getv(admin_genv,name);
	if( fv == 0 ){
		fv = getv(Form_argv,name);
	}
	return fv;
}
static int admin_getvuniq1(PCStr(name),const char **vp,int ac,const char *av[]){
	int ai;
	int len;
	int na = 0;
	const char *a1;
	const char *val = *vp;

	len = strlen(name);
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( strneq(a1,name,len) && a1[len] == '=' ){
			na++;
			if( val == 0 )
				val = &a1[len+1];
			else{
				if( !streq(val,&a1[len+1]) )
					return -1;
			}
		}
	}
	*vp = val;
	return na;
}
#define admin_getvuniq(nm)	admin_getvuniqX(Conn,nm)
int admin_getvuniqX(Connection *Conn,PCStr(name)){
	int na1;
	int na2;
	const char *val = 0;
	if( (na1 = admin_getvuniq1(name,&val,admin_genc,admin_genv)) < 0 )
		return 0;
	if( (na2 = admin_getvuniq1(name,&val,Form_argc,Form_argv)) < 0 )
		return 0;
	return na1 + na2;
}


static int testport(Connection *Conn,PVStr(msg),PCStr(what),PCStr(confname),PCStr(port)){
	int pn;

	if( port == 0 || *port == 0 ){
		const char *a1;
		a1 = admin_getv("conf-type");
		if( a1 == 0 || !streq(a1,"sub") ){
			putMssg(BVStr(msg),"@ADM - no %s specified\n",what);
			set_conferror(confname);
			return 1;
		}
	}else{
		pn = atoi(port);
		if( pn == 0 || pn <= 0 || 0x10000 <= pn ){
			putMssg(BVStr(msg),"@ADM - bad %s, port number '%s', must be in [%d-%d]\n",
			what,port,1,0x10000-1);
			set_conferror(confname);
			return 2;
		}
	}
	return 0;
}
/*
#define PutLn(fp)	(ln<0||fp==NULL)?0:fprintf(fp,"%d: ",++ln)
*/
static int putConf1(FILE *fp,int toHTML,PCStr(name),PCStr(fmt),...){
	CStr(line,1024);
	CStr(xline,1024);
	VARGS(8,fmt);

	if( name[0] == '-' )
		strcpy(line,name);
	else	sprintf(line,"%s=",name);
	if( fmt ){
		Xsprintf(TVStr(line),fmt,VA8);
	}
	if( toHTML ){
		encodeEntitiesY(line,AVStr(xline),sizeof(xline),"<>",1);
		fprintf(fp,"%s\n",xline);
if( lHTMLGEN() )
if( !streq(line,xline) )
 fprintf(stderr,"--- %s\n+++ %s\n",line,xline);
	}else{
		fprintf(fp,"%s\n",line);
	}
	return 0;
}

int form2confX(Connection *Conn,PVStr(msg),FILE *tc,int toHTML,int ln){
	int ai;
	CStr(buff,256);
	CStr(port,256);
	CStr(admin,256);
	CStr(tmp,256);
	CStr(server,MaxHostNameLen);
	const char *a1,*a2,*a3,*a4;
	const char *com;
	refQStr(mp,msg);
	int ismain;

	com = getv(Form_argv,"com");
	truncVStr(server);

	a1 = admin_getv("conf-type");
	if( a1 != 0 && streq(a1,"sub") ){
		putConf1(tc,toHTML,P_CONFOPT,"type:sub");
		ismain = 0;
	}else	ismain = 1;

	a1 = admin_getv(CP_conf_DGROOTx);
	if( a1 && streq(a1,"on") ){
		a1 = admin_getv(CP_conf_DGROOT);
		if( a1 && *a1 ){
			putConf1(tc,toHTML,P_DGROOT,"%s",a1);
			a1 = admin_getv(CP_conf_CHROOTx);
			if( a1 && streq(a1,"on") ){
				putConf1(tc,toHTML,P_CHROOT,"/");
			}
		}
	}
	a1 = admin_getv(CP_conf_VARDIRx);
	if( a1 && streq(a1,"on") ){
		a1 = admin_getv(CP_conf_VARDIR);
		if( a1 && *a1 ){
			putConf1(tc,toHTML,P_VARDIR,"%s",a1);
		}
	}
	a1 = admin_getv(CP_conf_TMPDIRx);
	if( a1 && streq(a1,"on") ){
		a1 = admin_getv(CP_conf_TMPDIR);
		if( a1 && *a1 ){
			putConf1(tc,toHTML,P_TMPDIR,"%s",a1);
		}
	}

	a1 = admin_getv(CP_conf_protocol);
	if( a1 && *a1 ){
		sprintf(server,"%s",a1?a1:"");
		a2 = admin_getv(CP_conf_serverx);
		if( a2 && *a2 ){
			a2 = admin_getv(CP_conf_server);
			if( a2 && *a2 )
				Xsprintf(TVStr(server),"://%s",a2);
		}
		putConf1(tc,toHTML,P_SERVER,"%s",server);
	}

	truncVStr(port);
	a1 = admin_getv(CP_conf_usrport);
	if( com && *com ){
		testport(Conn,AVStr(mp),"user port",CP_conf_usrport,a1);
	}
	a2 = admin_getv(CP_conf_admport);
	a3 = admin_getv(CP_conf_admin);
	a4 = admin_getv(CP_conf_usrpadr);
	if( a3 && streq(a3,"on") ){
		testport(Conn,AVStr(mp),"administrator port",CP_conf_admport,a2);
	}
	if( a1 && *a1 ){
		if( a3 && streq(a3,"on") ){ /*admin_getv(CP_conf_admin)*/
			if( a2 && *a2 && !streq(a1,a2) )
				sprintf(port,"%s,%s/admin",a1,a2);
			else
			if( a2 && *a2 && streq(a1,a2) )
				sprintf(port,"%s/admin",a1);
			else	sprintf(port,"%s",a1);
		}else{
			sprintf(port,"%s",a1);
		}
		if( a4 && *a4 ){
			if( !VSA_strisaddr(a4) && !IsResolvable(a4) ){
	putMssg(BVStr(msg),"@ADM - not IP address or unknown host: %s\n",a4);
			}
			Strins(AVStr(port),":");
			Strins(AVStr(port),a4);
		}
		putConf1(tc,toHTML,"-P",port);
	}
	a1 = admin_getv(CP_conf_ssl);
	if( a1 && *a1 ){
		if( streq(a1,"no") ){
		}else
		if( streq(a1,"accept") ){
			putConf1(tc,toHTML,P_STLS,"-fcl");
		}else
		if( streq(a1,"only") ){
			putConf1(tc,toHTML,P_STLS,"fcl");
		}
	}

	a1 = admin_getv(CP_conf_loglev);
	if( a1 && *a1 ){
		strcpy(buff,"");
		if( streq(a1,"d") ) sprintf(buff,"-vd"); else
		if( streq(a1,"t") ) sprintf(buff,"-vt"); else
		if( streq(a1,"s") ) sprintf(buff,"-vs");
		if( buff[0] ){
			putConf1(tc,toHTML,buff,"");
		}
	}

	truncVStr(admin);
	a1 = admin_getv(CP_conf_ADMIN);
	if( a1 == 0 || *a1 == 0 ){
		if( ismain ) a1 = DELEGATE_ADMIN;
	}
	if( a1 && *a1 ){
		putConf1(tc,toHTML,P_ADMIN,"%s",a1);
	}
/*
validation phase shuld be after
	if( validateEmailAddr(a1,0) < 0 ){
		putMssg(BVStr(msg),"@ADM - invalid Email address '%s'\n",a1);
		set_conferror(CP_conf_ADMIN);
	}
*/

	a1 = admin_getv(CP_conf_logaging);
	if( a1 && *a1 ){
		strcpy(buff,"");
		if( streq(a1,"off") ){
		}else
		if( streq(a1,"byday") )
			sprintf(buff,"log[date+/%%Y/%%m/%%d]");
		else
		if( (a2 = admin_getv(CP_conf_logagingx)) && *a2 )
			sprintf(buff,"log[date+/%s]",a2);
		if( buff[0] ){
			putConf1(tc,toHTML,P_LOGDIR,"%s",buff);
		}
	}

	a1 = admin_getv(CP_conf_REL);
	if( a1 != 0 && *a1 != 0 ){
		if( streq(a1,"_any") ){
			putConf1(tc,toHTML,P_RELIABLE,"*");
		}
	}
	if( a1 == 0 || *a1 == 0 || streq(a1,"_custom") ){
		a2 = admin_getv(CP_conf_RELIABLE);
		if( a2 != 0 && *a2 != 0 ){
			putConf1(tc,toHTML,P_RELIABLE,"%s",a2);
		}
	}
	a1 = admin_getv(CP_conf_REACH);
	if( a1 != 0 && *a1 != 0 ){
		if( streq(a1,"localnet") ){
			putConf1(tc,toHTML,P_REACHABLE,".localnet");
		}else
		if( streq(a1,"none") ){
			putConf1(tc,toHTML,P_REACHABLE,"");
		}else
		if( streq(a1,"custom") ){
			a2 = admin_getv(CP_conf_REACH_list);
			if( a2 && *a2 ){
				putConf1(tc,toHTML,P_REACHABLE,"%s",a2);
			}
		}
	}

	a1 = admin_getv(CP_conf_AUTHORIZER);
	if( a1 != 0 && *a1 != 0 ){
		if( streq(a1,"pam") ){
			a2 = admin_getv(CP_conf_servlist);
			if( a2 && *a2 )
				sprintf(tmp,"-pam/%s",a2);
			else	sprintf(tmp,"-pam");
			putConf1(tc,toHTML,P_AUTHORIZER,"%s",tmp);
		}else
		if( streq(a1,"list") ){
			a2 = admin_getv(CP_conf_userlist);
			if( a2 ){
				sprintf(tmp,"-list{%s}",a2);
				putConf1(tc,toHTML,P_AUTHORIZER,"%s",tmp);
			}
		}else{
			putConf1(tc,toHTML,P_AUTHORIZER,"%s",a1);
		}
	}

if( !MaskIsSet(admin_getv_mask,confnamex(CP_conf_MOUNT)) ){
 int ai;
 int mn = 0;
 for( ai = 0; ai < admin_genc; ai++ ){
	a1 = admin_genv[ai];
	if( strneq(a1,"conf-MOUNT=",11) ){
		mn++;
		if( a1[11] ){
			putConf1(tc,toHTML,P_MOUNT,"%s",a1+11);
		}
	}
 }
 if( mn == 0 )
 for( ai = 0; ai < Form_argc; ai++ ){
	a1 = Form_argv[ai];
	if( strneq(a1,"conf-MOUNT=",11) ){
		if( a1[11] ){
			putConf1(tc,toHTML,P_MOUNT,"%s",a1+11);
		}
	}
 }
 }

	a1 = admin_getv(CP_conf_admin);
	if( a1 && streq(a1,"on") ){
		CStr(user,128);
		CStr(pass,64);
		CStr(md5,64);
		a1 = admin_getv(CP_conf_admuser);
		a2 = admin_getv(CP_conf_admpass);
		if( a1 == 0 || *a1 == 0 ){
			if( AdminUser && *AdminUser ){
				strcpy(user,AdminUser);
				a2 = AdminPass;
			}else{
				getUsername(getuid(),AVStr(user));
			}
			a1 = user;
		}
		if( a2 == 0 || *a2 == 0 ){
			strcpy(pass,"");
			putMssg(BVStr(msg),"@ADM - no admin password\n");
			set_conferror(CP_conf_admpass);
		}else{
			if( strneq(a2,"MD5:",4) ){
				strcpy(pass,a2);
			}else
			if( admin_getvuniq(CP_conf_admpass) < 2 ){
				strcpy(pass,"");
				putMssg(BVStr(msg),"@ADM - inconsistent password\n");
				set_conferror(CP_conf_admpass);
		MaskDoSet(admin_getv_mask,confnamex(CP_conf_admpass));
			}else{
				toMD5(a2,md5);
				sprintf(pass,"MD5:%s",md5);
			}
		}
		sprintf(admin,"admin:-list{%s:%s}",a1,pass);
		putConf1(tc,toHTML,P_AUTH,"%s",admin);
	}
	return ln;
}

static char *addConf1(Connection *Conn,PVStr(pbuf),int issets[],PCStr(name),PCStr(val)){
	refQStr(pp,pbuf);
	SetConfMask(issets,name);
	admin_genv[admin_genc++] = pp;
	sprintf(pp,"%s=%s",name,val);
	pp += strlen(pp) + 1;
	return (char*)pp;
}
#define AddConf1(name,val)	pp = addConf1(Conn,AVStr(pp),issets,name,val)

int conf2formX(Connection *Conn,PVStr(msg),PCStr(conf),int mac,const char *av[]){
	int ai = 0;
	refQStr(mp,msg);
	CStr(ereason,256);
	const char *lp;
	const char *sp;
	const char *np;
	const char *dp;
	CStr(line,1024);
	defQStr(params);
	defQStr(pp);
	CStr(nam,128);
	CStr(val,1024);
	CStr(ext,16*1024);
	refQStr(xp,ext);
	int psize;
	int li;
	int issets[4];
	int ci;

	if( strchr(conf,'\033') )
	TO_euc(conf,ZVStr((char*)conf,strlen(conf)+1),strlen(conf)+1);

	MaskClear(issets);
	if( getv(admin_genv,CP_confdata) ){
		SetConfMask(issets,CP_confdata);
/*
 fprintf(stderr,"-- admin_genc=%d ISSET=%X\n",admin_genc,issets[0]);
*/
	}

	if( conf == 0 ){
		sprintf(msg,"- no conf data given");
		av[0] = 0;
		return 0;
	}
	psize = 1024 + strlen(conf) + 1;
	setQStr(params,malloc(psize),psize);
	cpyQStr(pp,params);
	truncVStr(pp);

	li = 0;
	for( sp = conf; *sp; sp = np ){
		np = lineScan(sp,line);
		if( elnumof(admin_genv)-1 <= admin_genc ){
			break;
		}
		li++;
		truncVStr(nam);
		truncVStr(val);

		lp = line;
		if( '0' <= *lp && *lp <= '9' ){
			while( '0' <= *lp && *lp <= '9' )
				lp++;
			if( *lp == ':' )
				lp++;
			else{
		putMssg(BVStr(msg),"@ADM - %d: syntax error: %s\n",li,line);
		set_conferror(CP_confdata);
				goto Unknown;
			}
		}
		while( *lp == ' ' || *lp == '\t' )
			lp++;
		if( *lp == 0 )
			goto Next;
		if( *lp == '#' ){
/*
			if( strneq(lp,"## Created:",11) ){
				admin_genv[admin_genc++] = pp;
				sprintf(pp,"conf-created=%s",lp);
				pp += strlen(pp) + 1;
			}
*/
			goto Next;
		}
		if( *lp == '-' ){
			strcpy(nam,line);
		}else
		if( Xsscanf(lp,"%[^=]=\"%[^\"]",AVStr(nam),AVStr(val)) != 2 )
		if( Xsscanf(lp,"%[^=]=%[^\n]",AVStr(nam),AVStr(val)) != 2 ){
			int len;
			if( Xsscanf(lp,"%[A-Z]",AVStr(nam)) == 1 )
			if( lp[strlen(nam)] == '=' ){
				truncVStr(val);
				goto OK;
			}
			putMssg(BVStr(msg),"@ADM - %d: syntax error: %s\n",li,lp);
			set_conferror(CP_confdata);
			goto Unknown;
		}
/*
 fprintf(stderr,"--- CONF [%s][%s] %s\n",nam,val,lp);
*/
		OK:


		if( *nam != '-' && check_paramX(lp,0,AVStr(ereason)) < 0 ){
			putMssg(BVStr(msg),"@ADM - %d: %s\n",li,ereason);
			set_conferror(CP_confdata);
			goto Unknown;
		}
		if( streq(nam,P_CONFOPT) ){
			if( strneq(val,"type:",5) ){
				SetConfMask(issets,"conf-type");
				admin_genv[admin_genc++] = pp;
				sprintf(pp,"conf-type=%s",val+5);
				pp += strlen(pp) + 1;
			}
		}else
		if( strneq(nam,"-v",2) ){
			const char *vl;
			switch( nam[2] ){
				case 's': vl = "s"; break;
				case 't': vl = "t"; break;
				case 'd': vl = "d"; break;
				default:
				putMssg(BVStr(msg),"@ADM - %d: ??? %s\n",li,line);
				set_conferror(CP_confdata);
				goto Unknown;
			}
			AddConf1(CP_conf_loglev,vl);
		}else
		if( strneq(nam,"-P",2) ){
			CStr(p1,MaxHostNameLen);
			CStr(p2,MaxHostNameLen);
			CStr(hi,256);
			const char *dp;
			truncVStr(p1);
			if( Xsscanf(nam+2,"%[^,],%s",AVStr(p1),AVStr(p2))==2 ){
			    if( dp = strstr(p2,"/admin") ){
				truncVStr(dp);
				AddConf1(CP_conf_admport,p2);
			    }
			}
			if( p1[0] ){
				if( dp = strchr(p1,':') ){
					Xsscanf(p1,"%[^:]",AVStr(hi));
					ovstrcpy(p1,dp+1);
					AddConf1(CP_conf_usrpadr,hi);
					AddConf1(CP_conf_usrpadrx,"on");
				}
				if( dp = strstr(p1,"/admin") ){
					truncVStr(dp);
					AddConf1(CP_conf_admport,p1);
				}
				AddConf1(CP_conf_usrport,p1);
			}
		}else
		if( streq(nam,P_CHROOT) ){
			if( streq(val,"/") ){
				AddConf1(CP_conf_CHROOTx,"on");
			}else	goto Unknown;
		}else
		if( streq(nam,P_DGROOT) ){
			AddConf1(CP_conf_DGROOTx,"on");
			AddConf1(CP_conf_DGROOT,val);
		}else
		if( streq(nam,P_TMPDIR) ){
			AddConf1(CP_conf_TMPDIRx,"on");
			AddConf1(CP_conf_TMPDIR,val);
		}else
		if( streq(nam,P_VARDIR) ){
			AddConf1(CP_conf_VARDIRx,"on");
			AddConf1(CP_conf_VARDIR,val);
		}else
		if( streq(nam,P_STLS) ){
			if( streq(val,"fcl") ) strcpy(val,"only");
			if( streq(val,"-fcl") ) strcpy(val,"accept");
			AddConf1(CP_conf_ssl,val);
		}else
		if( streq(nam,P_ADMIN) ){
			AddConf1(CP_conf_ADMIN,val);
		}else
		if( streq(nam,P_SERVER) ){
			CStr(proto,32);
			CStr(server,MaxHostNameLen);

			strcpy(proto,"");
			strcpy(server,"");
			Xsscanf(val,"%[^:]://%s",AVStr(proto),AVStr(server));

			AddConf1(CP_conf_protocol,proto);
			if( server[0] ){
				AddConf1(CP_conf_serverx,"on");
				AddConf1(CP_conf_server,server);
			}
		}else
		if( streq(nam,P_AUTHORIZER) ){
			CStr(list,1024);
			truncVStr(list);

			if( strneq(val,"-pam",4) ){
				AddConf1(CP_conf_AUTHORIZER,"pam");
				if( Xsscanf(val,"-pam/%s",AVStr(list)) ){
					AddConf1(CP_conf_servlist,list);
				}
			}else
			if( strneq(val,"-list{",6) ){
				AddConf1(CP_conf_AUTHORIZER,"list");
				if( Xsscanf(val,"-list{%[^}]",AVStr(list)) ){
					AddConf1(CP_conf_userlist,list);
				}
			}else{
				AddConf1(CP_conf_AUTHORIZER,val);
			}
		}else
		if( streq(nam,P_LOGDIR) ){
			CStr(pat,256);
			if( streq(val,"log[date+/%Y/%m/%d]") ){
				AddConf1(CP_conf_logaging,"byday");
			}else{
				AddConf1(CP_conf_logaging,"custom");
				truncVStr(pat);
				if( Xsscanf(val,"log[date+/%[^]]",AVStr(pat)) ){
					AddConf1(CP_conf_logagingx,pat);
				}else	goto Unknown;
			}
		}else
		if( streq(nam,P_MOUNT) ){
			AddConf1(CP_conf_MOUNT,val);
		}else
		if( streq(nam,P_RELIABLE) ){
			if( streq(val,"*") ){
				AddConf1(CP_conf_REL,"_any");
			}else
			if( streq(val,".localnet") ){
				AddConf1(CP_conf_REL,"_localnet");
			}else{
				AddConf1(CP_conf_REL,"_custom");
				AddConf1(CP_conf_RELIABLE,val);
			}
		}else
		if( streq(nam,P_REACHABLE) ){
			if( streq(val,"") ){
				AddConf1(CP_conf_REACH,"none");
			}else
			if( streq(val,".localnet") ){
				AddConf1(CP_conf_REACH,"localnet");
			}else{
				AddConf1(CP_conf_REACH,"custom");
				AddConf1(CP_conf_REACH_list,val);
			}
		}else
		if( streq(nam,P_AUTH) && strneq(val,"admin:",5)
		 && (val[5]==':' || val[5]==0) ){
			CStr(asb,256);
			CStr(aub,256);
			CStr(apb,256);
			if( streq(val,"admin") ){
				AddConf1(CP_conf_admin,"on");
				if( AdminUser ){
					AddConf1(CP_conf_admuser,AdminUser);
					AddConf1(CP_conf_admpass,AdminPass);
					AddConf1(CP_conf_admpass,AdminPass);
if( lHTMLGEN() )
 fprintf(stderr,"--- admin[%s] User[%s] Pass[%s]\n",val,AdminUser?AdminUser:"",AdminPass?AdminPass:"");
				}
				goto Next;
			}

			truncVStr(asb);
			truncVStr(aub);
			truncVStr(apb);
			scan_Listlist(val+6,':',AVStr(asb),AVStr(aub),
				VStrNULL,VStrNULL,VStrNULL);
			/*
			AddConf(CP_conf_authserv,asb);
			*/
			if( strneq(asb,"-list{",6) ){
			Xsscanf(asb+6,"%[^:,}]:%[^}]",AVStr(aub),AVStr(apb));
				if( !strneq(apb,"MD5:",4) )
					truncVStr(apb);
			}

			AddConf1(CP_conf_admuser,aub);
			if( apb[0] )
			AddConf1(CP_conf_admpass,apb);
			AddConf1(CP_conf_admin,"on");
		}else{
	Unknown:
			sprintf(xp,"%s\n",line);
			xp += strlen(xp);
		}
	Next:
		if( *np == '\r' ) np++;
		if( *np == '\n' ) np++;
	}
	if( ext < xp ){
		setVStrEnd(xp,0);
		AddConf1(CP_conf_data,ext);
	}
	for( ci = 1; conf_params[ci]; ci++ ){
		if( elnumof(admin_genv) <= admin_genc ){
			break;
		}
		if( MaskIsSet(issets,ci) ){
		}else{
			admin_genv[admin_genc++] = pp;
			sprintf(pp,"%s=",conf_params[ci]);
			pp += strlen(pp) + 1;
		}
	}
	admin_genv[admin_genc] = 0;
	return ai;
}

static int dumpform1(Connection *Conn,FILE *fp,PCStr(nfilter),PCStr(pfilter),int url,PCStr(fmt),int argc,const char *argv[]){
	int nput = 0;
	const char *av1;
	const char *vp;
	CStr(name,64);
	CStr(line,1024);
	CStr(uv,1024);
	int ai;

	for( ai = 0; ai < argc; ai++ ){
if(fmt){
//fprintf(stderr,"#### fmt[%s] [%d]%s\n",fmt,ai,argv[ai]);
 }
		av1 = argv[ai];
		if( vp = strchr(av1,'=') ){
			vp++;
		}else	vp = "";
		if( *vp == 0 ){
			continue;
		}
		truncVStr(name);
		Xsscanf(av1,"%[^=]",AVStr(name));
		if( !MaskIsZero(admin_getv_mask) ){
			if( MaskIsSet(admin_getv_mask,confnamex(name)) ){
				continue;
			}
		}

		if( *nfilter && isinList(nfilter,name) ){
if( lHTMLGEN() )
 fprintf(stderr,"-- dont dumpformv[%s]\n",name,nfilter);
			continue;
		}
		if( *pfilter && !isinList(pfilter,name) ){
			continue;
		}

		/*
		strcpy(uv,vp);
		strsubst(AVStr(uv),"<","&lt;");
		strsubst(AVStr(uv),">","&gt;");
		strsubst(AVStr(uv),"\"","&quot;");
		*/
		encodeEntitiesY(vp,AVStr(uv),sizeof(uv),"\"<>",0);

		if( fmt && *fmt ){
			strcpy(line,fmt);
			strsubst(AVStr(line),"%V",vp);
			strsubst(AVStr(line),"%_V",uv);
			put1sX(Conn,fp,"%s",line);
		}else
		if( url ){
			sprintf(line,"%s%s=%s",nput?"&":"",name,uv);
			put1sX(Conn,fp,"%s",line);
		}else{
			fprintf(fp,"<INPUT type=hidden name=%s value=\"%s\">\n",
				name,uv);
		}
		nput++;
	}
	return nput;
}
static int dumpform(Connection *Conn,FILE *fp,PCStr(nfilter),PCStr(pfilter),int url,PCStr(fmt)){
	int nput = 0;
	const char *com = getv(Form_argv,"com");

	if( com && streq(com,"decompose") && fmt ){
	nput = dumpform1(Conn,fp,nfilter,pfilter,url,fmt,admin_genc,admin_genv);
	}else
	if( com && streq(com,"load") ){
	nput = dumpform1(Conn,fp,nfilter,pfilter,url,fmt,admin_genc,admin_genv);
	}else{
	nput = dumpform1(Conn,fp,nfilter,pfilter,url,fmt,Form_argc,Form_argv);
	}
	return nput;
}

static void altcolor(PCStr(src),PVStr(dst),PCStr(clist)){
	refQStr(dp,dst);
	const char *sp;
	const char *altc;
	int ai = 0;

	dp = dst;
	for( sp = src; *sp; sp++ ){
		if( strneq(sp,"<!RB",4) ){
			if( ai++ % 2 )
				altc = "E0E0E0";
			else	altc = "C0FFC0";
			sprintf(dp,"<TR><TD bgcolor=#%s",altc);
			dp += strlen(dp);
			sp += 3;
		}else
		if( strneq(sp,"<!RE>",5) ){
			strcpy(dp,"</TD></TR>");
			dp += strlen(dp);
			sp += 4;
		}else
		if( sp[0] == '%' && sp[1] == '#' ){
			if( ai++ % 2 )
				altc = "E0E0E0";
			else	altc = "C0FFC0";
			strcpy(dp,altc);
			dp += strlen(dp);
			sp++;
		}else{
			setVStrPtrInc(dp,*sp);
		}
	}
	setVStrEnd(dp,0);
}

int confsumm(Connection *Conn,PCStr(name),PVStr(summ),int size){
	CStr(line,1024);
	refQStr(dp,summ);
	const char *data;
	const char *lp;
	const char *sp;
	const char *np;
	int date;
	int rem;

	data = getConfigData(Conn,name,"",&date);
	if( data ){
		int len = strlen(data);
		if( CCXactive(CCX_TOCL) ){
			TO_euc(data,ZVStr((char*)data,len+1),len+1);
		}
		rem = size - 1;
		for( sp = data; *sp; sp = np ){
			np = lineScan(sp,line);
			lp = line;
			if( *lp != '#' ){
				if( strneq(lp,"SERVER=",7)
				 || strneq(lp,"DGROOT=",7)
				/*
				 || strneq(lp,"ADMIN=",6)
				*/
				 || strneq(lp,"STLS=",5)
				 || strneq(lp,"-",1)
				){
					sprintf(dp,"%s ",lp);
					dp += strlen(dp);
				}
			}
			if( *np == '\r' ) np++;
			if( *np == '\n' ) np++;
		}
		free((char*)data);
		setVStrEnd(dp,0);
		return date;
	}else{
		strcpy(summ,"(empty)");
		return -1;
	}
}

static void freeFileList(PCStr(wh),int ac,const char *av[]){
	int ai;
	for( ai = 0; ai < ac && av[ai]; ai++ ){
		free((char*)av[ai]);
	}
}
int getSvStats(int fd,int *pid,int *stime,int *utime);
static int foreachserv(Connection *Conn,FILE *fp,PCStr(pma1),PCStr(pma2)){
	int ai,ac;
	const char *av[64];
	const char *name;
	CStr(pname,128);
	FILE *svstfp;
	CStr(fmt,8*1024);
	CStr(line,8*1024);
	CStr(xline,8*1024);
	int pid;
	int stime;
	int utime;
	int now = time(0);
	int idle;
	int maxidle = 10;

	strcpy(fmt,pma2);
	strsubst(AVStr(fmt),"%{","${"); /* to be evaluated in scan1()*/

	sscanf(pma1,"idle/%d",&maxidle);
	if( maxidle <= 0 )
		maxidle = 10;
	if( admin_getv(CP_serv_showall) )
		maxidle = 0;

	ac = getServerList(elnumof(av),av,pma1);
	for( ai = 0; ai < ac; ai++ ){
		name = av[ai];
		encodeEntitiesX(name,AVStr(pname),sizeof(pname));
		if( name[0] != '_' || strtailchr(name) != '_' ){
			const char *data;
			int date;
			if( data = getConfigData(Conn,name,"",&date) ){
				free((char*)data);
			}else{
				/* no corresponding active configuration */
				continue;
			}
		}
		svstfp = fopenSvstats(name,"r");
		if( svstfp ){
			if( getSvStats(fileno(svstfp),&pid,&stime,&utime) < 0 ){
				goto Next;
			}

/*
fprintf(stderr,"----[%2d]fd=%2d pid=%5d(%5d) %8x %8x(%8x) %s\n",
ai,fileno(svstfp),
pid,getpidof(name),
stime,
utime,file_mtime(fileno(svstfp)),
name);
*/

			if( maxidle ){
				idle = now - utime;
				if( maxidle*60 < idle ){
					goto Next;
				}
			}
			if( !admin_authok(Conn) ){
				if( pid != serverPid() ){
					goto Next;
				}
			}

			strcpy(line,fmt);
			if( name[0] == '_' ){
				if( pid == serverPid() ){
					strsubst(AVStr(line),"%xn",config_self);
				}
			}
			strfLoadStatX(AVStr(xline),sizeof(xline),line,now,
				fileno(svstfp));
			strsubst(AVStr(xline),"%xn",pname);
			altcolor(xline,AVStr(line),"");
			HTML_scan1(Conn,fp,"%s",line);

		Next:
			fclose(svstfp);
		}
	}
	freeFileList("Server",ac,av);
	return 0;
}

static int foreachconf(Connection *Conn,FILE *fp,PCStr(pma1),PCStr(pma2)){
	int ai,ac;
	int aa = 0; /* allocated */
	const char *av[64];
	int isself[64];
	CStr(name,256);
	CStr(summ,1024);
	CStr(xsumm,1024);
	CStr(sdate,64);
	CStr(slock,64);
	CStr(path,1024);
	CStr(line,4*1024);
	CStr(xline,4*1024);
	int date;
	FILE *lfp;
	const char *a1;
	int checkall = 0;
	int now;
	int leng = 0;
	refQStr(ep,line);
	const char *dp;
	const char *selfname = 0;

	ac = 0;
	if( isinList(pma1,config_self) ){
		int il;
		av[0] = config_self;
		ac = 1;
		il = strlen(config_self);
		if( strneq(pma1,config_self,il) ){
			if( pma1[il] == 0 )
				pma1 = "";
			else
			if( pma1[il] == ',' )
				pma1 = pma1+il+1;
		}
	}
	if( *pma1 ){
		aa = ac;
		ac += getConfigList(elnumof(av)-ac,&av[ac],pma1);
		for( ai = 1; ai < ac; ai++ ){
			a1 = av[ai];
			if( getpidof(a1) == serverPid() ){
				isself[ai] = 1;
				selfname = a1;
			}else{
				isself[ai] = 0;
			}
		}
	}
	/*
	if( ac == 1 ) checkall = 1; else
	*/
	{
		const char *com;
		com = admin_getv("com");
		if( com && streq(com,"checkall") )
			checkall = 1;
	}
	now = time(0);
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		if( !admin_authok(Conn) ){
			if( !streq(a1,config_self) )
			if( getpidof(a1) != serverPid() ){
				continue;
			}
		}
		if( lfp = fopen_lockconf(VStrNULL,a1,"r+",AVStr(path),0) ){
			fclose(lfp);
			strcpy(slock,"no");
		}else{
			strcpy(slock,"yes");
		}
		encodeEntitiesY(a1,AVStr(name),sizeof(name),DHTML_ENC,0);

		/*
		if( 0 < ai && isself[ai] ){
			Xsprintf(TVStr(name)," (%s)",config_self);
		}
		*/

		strcpy(line,pma2);
		strsubst(AVStr(line),"%N",name);
		date = confsumm(Conn,a1,AVStr(summ),sizeof(summ));
		encodeEntitiesY(summ,AVStr(xsumm),sizeof(xsumm),DHTML_ENC,0);
		strsubst(AVStr(line),"%X",xsumm);

		if( date < 0 )
			strcpy(sdate,"-");
		else	rsctime(date,AVStr(sdate));
		strsubst(AVStr(line),"\\n","\n");
		strsubst(AVStr(line),"%T",sdate);
		strsubst(AVStr(line),"%K",slock);
		strsubst(AVStr(line),"%C",(!streq(a1,config_self)&&checkall)?"checked":"");
		altcolor(line,AVStr(xline),"");
		strcpy(line,xline);
		strsubst(AVStr(line),"%{","${"); /* to be evaluated in scan1()*/

		/* %s %n %a %r %l %L */
		if( strstr(line,"%s") || strstr(line,"%x") ){
			if( streq(a1,config_self) ){
strfLoadStat(AVStr(xline),sizeof(xline),line,now);
				strcpy(line,xline);
			}else{
				FILE *svstfp;
				svstfp = fopenXDGfile(Conn,a1,"r",fopenSvstats);
strfLoadStatX(AVStr(xline),sizeof(xline),line,now,svstfp?fileno(svstfp):-1);
				strcpy(line,xline);
				if( svstfp )
					fclose(svstfp);
			}
		}
		leng += HTML_scan1(Conn,fp,"%s",line);
	}
	if( 0 < aa ){
		freeFileList("Config",ac-aa,av+aa);
	}
	return leng;
}

int dump_confdata(PVStr(msg),Connection *Conn,FILE *fp,PCStr(fmt)){
	const char *com;
	const char *conf;
	const char *a1;
	int ln = 0;
	CStr(stime,64);
	CStr(line,128);

	com = getv(Form_argv,"com");
	if( com == 0 )
		com = "";
	conf = admin_getv(CP_confdata);

	if( streq(com,"clear") ){
		conf = "\n";
	}else
	if( conf == 0 || *conf == 0 ){
		if( streq(com,"load") && get_conferror("conf-servname") ){
			conf = "\n";
		}else
		if( streq(com,"decompose") || streq(com,"load") ){
			conf = getv(Form_argv,CP_confdata);
			/* confdata is cleared in form2conf ... */
			/* "load" is decomposed to main_argv[] too ... */

if( conf == 0 ){
int ai;
 fprintf(stderr,"--- mask=[%X %X]\n",admin_getv_mask[0],admin_getv_mask[1]);
for( ai = 0; ai < admin_genc; ai++ )
 fprintf(stderr,"GEN[%d] %s\n",ai,admin_genv[ai]);
for( ai = 0; ai < Form_argc; ai++ )
 fprintf(stderr,"ARG[%d] %s\n",ai,Form_argv[ai]);
 }
		}
	}

/*
a1 = getv(admin_genv,"conf-created");
if( a1 && *a1 ){
	sprintf(line,"%s\n",a1);
	HTML_ccxput1s(Conn,fp,"%s",line);
 }else{
 }
if( com && streq(com,"compose") ){  "or no confdata ?"
StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,time(0),0);
sprintf(line,"## Created: %s\n",stime);
HTML_ccxput1s(Conn,fp,"%s",line);
 }
*/
/* and changed */
/*
if( com && (streq(com,"compose")||streq(com,"decompose")) ){
StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,time(0),0);
sprintf(line,"## Modified: %s\n",stime);
HTML_ccxput1s(Conn,fp,"%s",line);
 }
*/

	if( com &&
(streq(com,"decompose")||streq(com,"load")||streq(com,"store")||streq(com,"refresh")||streq(com,"list")||streq(com,"upload")||streq(com,"clear")) ){
		if( conf == 0 || *conf == 0 ){
fprintf(stderr,"!!!!! decompose with confdata=%X com[%s]\n",p2i(conf),com);
fprintf(stderr,"!!!!! decompose with confdata=%X com[%s] gen=%X arg=%X\n",
p2i(conf),com,p2i(getv(admin_genv,CP_confdata)),p2i(getv(Form_argv,CP_confdata)));
		}
	}
	if( conf && *conf
	 && com &&
(streq(com,"decompose")||streq(com,"load")||streq(com,"store")||streq(com,"refresh")||streq(com,"list")||streq(com,"upload")||streq(com,"clear")) ){
/*
CStr(buf,16*1024);
strcpy(buf,conf);
HTML_ccxput1s(Conn,fp,fmt,buf);
*/
		HTML_ccxput1s(Conn,fp,fmt,conf);
	}else{
		sprintf(line,"## synthesized parameters\n");
		HTML_ccxput1s(Conn,fp,"%s",line);

		ln = form2conf(BVStr(msg),fp,1,ln);
		HTML_ccxput1s(Conn,fp,"%s","\n");

		a1 = admin_getv(CP_conf_data);
		if( a1 && *a1 ){
			HTML_ccxput1s(Conn,fp,"%s","## other (not interpreted)\n");
			HTML_ccxput1s(Conn,fp,fmt,a1);
		}
	}
	return ln;
}

int DHTML_printForm2conf(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(pm),PCStr(pma1),PCStr(pma2),int *clengp){
	int cleng = 0;

	if( streq(pm,"conferr") ){
		cleng = get_conferror(pma1);
	}else
	if( streq(pm,"mask-formv") ){
		if( pma1[0] ){
			MaskDoSet(admin_getv_mask,confnamex(pma1));
		}else{
			MaskClear(admin_getv_mask);
			MaskReverse(admin_getv_mask);
		}
	}else
	if( streq(pm,"dumpform") ){
		int ai;
		for( ai = 0; ai < Form_argc; ai++ ){
			HTML_ccxput1s(Conn,fp,fmt,Form_argv[ai]);
			fputs("\n",fp);
		}
	}else
	if( streq(pm,"dumpformvu") ){
		dumpform(Conn,fp,pma1,pma2,1,"");
	}else
	if( streq(pm,"dumpformv") ){
		dumpform(Conn,fp,pma1,pma2,0,"");
	}else
	if( streq(pm,"altcolor") ){
		CStr(xline,2048);
		altcolor(pma2,AVStr(xline),pma1);
		cleng = HTML_scan1(Conn,fp,fmt,xline);
	}else
	if( streq(pm,"foreachconf") ){
		cleng = foreachconf(Conn,fp,pma1,pma2);
	}else
	if( streq(pm,"foreachserv") ){
		cleng = foreachserv(Conn,fp,pma1,pma2);
	}else
	if( streq(pm,"foreach") ){
fprintf(stderr,"----------- foreach [%s][%s]\n",pma1,pma2);
		dumpform(Conn,fp,"-",pma1,0,pma2);
		/* should be put with HTML_scan1() rathar than put1sX() */
	}else
	if( streq(pm,"setformv") ){
		CStr(line,1024);
		sprintf(line,"%s=%s",pma1,pma2);
fprintf(stderr,"############# SET GEN[%d] %s\n",admin_genc,line);
		admin_genv[admin_genc++] = stralloc(line);
	}else
	if( streq(pm,"copyformv") ){
		const char *a1;
		const char *a2;
		CStr(line,1024);
		if( a1 = admin_getv(pma2) ){
			sprintf(line,"%s=%s",pma1,a1);
fprintf(stderr,"############# COPY GEN[%d] %s\n",admin_genc,line);
			admin_genv[admin_genc++] = stralloc(line);
		}
	}else
	if( streq(pm,"formvs") ){
		int ai;
		int len;
		const char *a1;
		len = strlen(pma1);
		for( ai = 0; ai < Form_argc; ai++ ){
			a1 = Form_argv[ai];
			if( strneq(pma1,a1,len) ){
				if( a1[len] == '=' )
				if( isinList(pma2,a1+len+1) ){
					cleng = 1;
					break;
				}
			}
		}
	}else
	if( streq(pm,"formv") ){
		const char *a1;
		if( *pma1 ){
			a1 = admin_getv(pma1);
			if( a1 == 0 ){
				if( 'A' <= *pma1 && *pma1 <= 'Z' ){
				}else
				if( 0 < confnamex(pma1) ){
				}else{
if( lHTMLGENV() )
 fprintf(stderr,"-- unknown formv[%s]\n",pma1);
				}
			}
			if( *pma2 ){
				if( a1 ){
/*
 fprintf(stderr,"-=-1 param[%s] %s/%s/%s [%s]%d\n",param,pm,pma1,pma2,a1?a1:"",isinList(pma2,a1));
*/
					cleng = isinList(pma2,a1);
				}else{
/*
 fprintf(stderr,"-=-2 param[%s] %s/%s/%s [%s]\n",param,pm,pma1,pma2,a1?a1:"");
*/
					cleng = 0;
				}
			}else{
				if( a1 && *a1 ){
					if( streq(pma1,CP_conf_admpass) ){
					    if( !strneq(a1,"MD5:",4) ){
						CStr(md5,64);
						CStr(val,64);
fprintf(stderr,"---------- MUST ENCODE IN MD5: %s\n",a1);
						toMD5(a1,md5);
						sprintf(val,"MD5:%s",md5);
						HTML_ccxput1s(Conn,fp,fmt,val);
fprintf(stderr,"---------- MUST ENCODE IN MD5: %s\n",val);
						cleng = 1;
						goto EXIT;
					    }
					}
/*
 fprintf(stderr,"-T- param[%s] %s/%s/%s [%s]\n",param,pm,pma1,pma2,a1);
*/
					HTML_ccxput1s(Conn,fp,fmt,a1);
					cleng = 1;
				}else{
/*
 fprintf(stderr,"-F- param[%s] %s/%s/%s [%s]\n",param,pm,pma1,pma2,a1?a1:"");
*/
					cleng = 0;
				}
			}
		}
	}else{
		return 0;
	}
EXIT:
	*clengp = cleng;
	return 1;
}
