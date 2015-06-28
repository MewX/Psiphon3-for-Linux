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
Program:	reshost.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950817	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <time.h>
#include "ystring.h"
#include "vsignal.h"
#include "vsocket.h"
#include "dns.h"
void RES_init();
void res_log(int which,int byname,PCStr(name),char *rv[],PCStr(cname));
void sort_ipaddrs(const char *addrs[]);

int ipv6_domain(PCStr(caddr),PVStr(name));
int gethostbynameaddr_dns(PCStr(ns),PCStr(name),int qtype,int rrc,char *rrv[],PVStr(rrb),PVStr(cname));
int gethostbynameaddr_sys(PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname));
int gethostbynameaddr_dnsrch(PCStr(where),PCStr(ns),PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname));
int gethostbynameaddr_cache(PCStr(dir),PCStr(name),int rrc,char *rv[],PVStr(rb),int byname,PVStr(cname),int noexpire);
void puthost_cache(PCStr(nameaddr),char *rv[],int byname,PVStr(cname),int len,int type);
int rem_unknown(char *rv[],PCStr(unknown),int leng);
int gethostbyname_all(PCStr(where),char rwhere[],PCStr(name),int rrc,char *rv[],PVStr(rb),PVStr(cname));
int gethostbynameaddr_file(PCStr(path),PCStr(name),int rrc,char *rv[],PVStr(rb),int byname,PVStr(cname));
int gethostbynameaddr_nis(PCStr(map),PCStr(domain),PCStr(name),int rrc,char *rv[],PVStr(rb),int byname,PVStr(cname));

int File_mtime(PCStr(path));

typedef struct {
  const	char	*h_path;
	int	 h_date;
	int	 h_size;
	defQStr(h_buff);
} HostFile;

typedef struct {
  struct hostent h_ent;
	char	*namev[64]; /**/
	MStr(	 e_nameb,1024);
	char	*addrv[64]; /**/
	MStr(	 e_addrb,1024);
	HostFile he_hosts[4];
} HostentEnv;

static HostentEnv *hostentEnv;
#define Rhostent hostentEnv[0]
#define Hosts	Rhostent.he_hosts
#define Rnamev	Rhostent.namev
#define Rnameb	Rhostent.e_nameb
/**/
#define Raddrv	Rhostent.addrv
#define Raddrb	Rhostent.e_addrb
/**/

void minit_reshost()
{	struct hostent *he;

	if( hostentEnv == 0 ){
		hostentEnv = NewStruct(HostentEnv);
		he = &hostentEnv->h_ent;
		he->h_name = Rnameb;
		he->h_aliases = &Rnamev[1];
		he->h_addrtype = 0; /* AF_INET */
		he->h_length = 4;
		he->h_addr_list = Raddrv;
	}
}

#if !defined(_MSC_VER)
struct hostent *gethostbyname2X(const char *name,int af);
#define gethostbyname2(n,a) gethostbyname2X(n,a)
#endif
int with_gethostbyname2(){
	struct hostent *ht;
	ht = gethostbyname2("::",AF_INET6);
	return ht != NULL;
}

int RES_NOSYS;
int gethostbynameaddr_sys(PCStr(name),int qtype,int rrc,char *rv[],xPVStr(rb),PVStr(cname))
{	struct hostent *ht;
	int ac;
	const char *ap;
	int ax;

	if( RES_NOSYS )
		return 0;

	if( qtype == TY_A )
		ht = EX_GETHOSTBYNAME(name);
	else
	if( qtype == TY_AAAA ){
		ht = gethostbyname2(name,AF_INET6);
	}
	else{
		VSAddr sab;
		const char *baddr;
		int bleng,btype;
		VSA_atosa(&sab,0,name);
		bleng = VSA_decomp(&sab,&baddr,&btype,NULL);
		ht = EX_GETHOSTBYADDR(baddr,bleng,btype);
	}
	if( ht == NULL )
		return 0;

	/*
	if( qtype == TY_A ){
	*/
	if( qtype == TY_A || qtype == TY_AAAA ){
		for( ac = 0; ap = ht->h_addr_list[ac]; ac++ ){
			if( rrc-1 <= ac ){
				break;
			}
			/*
			Bcopy(ap,rb,4);
			*/
			Bcopy(ap,rb,ht->h_length);
			rv[ac] = (char*)rb;
			rb += ht->h_length;
			/*
			rb += 4;
			*/
		}
	}else{
		ac = 0;
		if( ht->h_name ){
			strcpy(rb,ht->h_name);
			rv[ac++] = (char*)rb;
			rb += strlen(rb) + 1;
		}
		if( ht->h_aliases )
		for( ax = 0; ap = ht->h_aliases[ax]; ax++ ){
			if( rrc-1 <= ac ){
				break;
			}
			strcpy(rb,name);
			rv[ac++] = (char*)rb;
			rb += strlen(rb) + 1;
		}
	}
	if( cname ){
		if( ht->h_name )
			strcpy(cname,ht->h_name);
		else	setVStrEnd(cname,0);
	}
	return ac;
}

int RES_next_res(PCStr(where),int ri,PVStr(res),PVStr(arg));
int (*RES_hlmatch)(PCStr(hlist),PCStr(host));
const char *RES_client;
int RES_client_dependent;
static int clientmatch(PCStr(host),PCStr(where),PCStr(res1),PVStr(arg)){
	int match = 1;
	refQStr(client,arg);

	client = strchr(arg,'<');
	if( client == 0 ){
		return -1;
	}
	setVStrPtrInc(client,0);
	if( RES_client == 0 ){
		return 0;
	}
	RES_client_dependent = 1;
	match = (*RES_hlmatch)(client,RES_client);
	return match;
}
static int dommatch(PCStr(host),PCStr(where),PCStr(res1),PVStr(arg)){
	int match = 1;
	refQStr(dom,arg);

	if( RES_hlmatch == 0 )
		return 1;

	dom = strchr(arg,'#');
	if( dom == 0 ){
		return 1;
	}
	setVStrPtrInc(dom,0);
	match = (*RES_hlmatch)(dom,host);
	return match;
}
/*
static int dnsrch1(PCStr(dname),PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname))
*/
static int dnsrch1(PCStr(where),PCStr(dname),PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname))
{	CStr(fqdn,512);
	int ac;
	int ri;
	CStr(res1,512);
	CStr(arg,512);

	if( dname == NULL )
		strcpy(fqdn,name);
	else
	if( strcmp(dname,".") == 0 )
		sprintf(fqdn,"%s.",name);
	else	sprintf(fqdn,"%s.%s",name,dname);

	/*
	ac = gethostbynameaddr_dns(fqdn,qtype,rrc,rv,AVStr(rb),AVStr(cname));
		should call gethosbyname_all() to match xxx.domain not
		in DNS resolver ?
	*/
	ac = 0;
	for( ri = 0; ri = RES_next_res(where,ri,AVStr(res1),AVStr(arg)); ){
		if( res1[0] != RT_DNS )
			continue;
		if( dommatch(fqdn,where,res1,AVStr(arg)) == 0 ){
			continue;
		}
		ac = gethostbynameaddr_dns(arg,fqdn,qtype,rrc,rv,AVStr(rb),AVStr(cname));
		if( 0 < ac )
			break;
	}

	if( 0 < ac ){
		if( cname != NULL && *cname == 0 )
		if( strcmp(name,fqdn) != 0 )
			strcpy(cname,fqdn);
	}
	return ac;
}

extern int MIN_ABSNDOTS;
extern char **res_DNSRCH();
extern char *res_DEFDNAME();
int RES_ASIS;
int RES_CACHED_UNKNOWN;

/*
int gethostbynameaddr_dnsrch(PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname))
*/
int gethostbynameaddr_dnsrch(PCStr(where),PCStr(ns),PCStr(name),int qtype,int rrc,char *rv[],PVStr(rb),PVStr(cname))
{	int ndots,tryabs,abstrial;
	int ac,si;
	const char *np;
	const char *dname;
	char **dnsrch;

	if( RES_ASIS ){
		ac = gethostbynameaddr_dns(ns,name,qtype,rrc,rv,AVStr(rb),AVStr(cname));
		if( 0 < ac )
			return ac;
		else	return -1;
	}

	ndots = 0;
	for( np = name; *np; np++ )
		if( *np == '.' )
			ndots++;

	tryabs = MIN_ABSNDOTS <= ndots;
	abstrial = 0;

	if( tryabs ){
		abstrial++;
		if( 0 < (ac = dnsrch1(where,NULL, name,qtype,rrc,rv,AVStr(rb),AVStr(cname))) )
			return ac;
	}
	if( dnsrch = res_DNSRCH() ){
	    for( si = 0; dname = dnsrch[si]; si++ ){
		if( strcmp(dname,".") == 0 )
			abstrial++;
		debug(DBG_ANY,"DNSRCH[%d] = %s\n",si,dname);
		if( 0 < (ac = dnsrch1(where,dname,name,qtype,rrc,rv,AVStr(rb),AVStr(cname))) )
			return ac;
	    }
	}else
	if( dname = res_DEFDNAME() ){
		debug(DBG_ANY,"DEFDNAME = %s\n",dname);
		if( 0 < (ac = dnsrch1(where,dname,name,qtype,rrc,rv,AVStr(rb),AVStr(cname))) )
			return ac;
	}
	if( abstrial == 0 ){
		if( 0 < (ac = dnsrch1(where,NULL, name,qtype,rrc,rv,AVStr(rb),AVStr(cname))) )
			return ac;
	}
	return -1;
}
int RES_next_res(PCStr(where),int ri,PVStr(res),PVStr(arg))
{	int ro,ch;

	setVStrEnd(res,0);
	if( arg != NULL ) setVStrEnd(arg,0);

	if( where[ri] == ',' )
		ri++;
	if( where[ri] == 0 )
		return 0;

	ro = 0;
	setVStrElemInc(res,ro,where[ri++]); /**/
	if( where[ri] == ':' ){
		setVStrElemInc(res,ro,where[ri++]); /**/
		while( (ch = where[ri]) && ch != ',' ){
			assertVStr(res,res+ro+1);
			setVStrElemInc(res,ro,where[ri++]); /**/
		}
		if( ch != 0 && ch != ',' )
		while( (ch = where[ri]) && ch != ',' )
				ri++;
	}
	setVStrEnd(res,ro);
	if( arg != NULL && res[1] == ':' && res[2] != 0 )
		strcpy(arg,res+2);
	return ri;
}

int RES_NOINET6 = 0; /* don't retry AAAA for A */
int RES_QTYPE = 0; /* can be AF_INET6 */

static int caching(int lastres,int ac,PCStr(nameaddr),char *rv[],int byname,PVStr(cname),PCStr(unknown_mark),int marklen)
{
	/* don't cache the result from the cache */
	if( lastres != RT_CACHE ){
		int len,type;
		/*
		puthost_cache(nameaddr,rv,byname,AVStr(cname));
		*/
		if( RES_QTYPE == AF_INET6 ){
			len = 16;
			type = AF_INET6;
		}else{
			len = 4;
			type = AF_INET;
		}
		if( byname && RES_QTYPE == AF_INET6 )
			byname = AF_INET6;
		puthost_cache(nameaddr,rv,byname,AVStr(cname),len,type);
	}else{
		int iac = ac;
		ac = rem_unknown(rv,unknown_mark,marklen);
		if( 0 < iac && ac == 0 ){
			/* should return 2 for byname & IPv6 */
			RES_CACHED_UNKNOWN = 1;
		}
	}
	return ac;
}

int gethostbyname_all(PCStr(where),char rwhere[],PCStr(name),int rrc,char *rv[],PVStr(rb),PVStr(cname))
{	int ri,res,ac;
	CStr(res1,512);
	CStr(arg,512);
	int lastres;
	int with_cache = 0;
	int leng;
	int byname = (RES_QTYPE == AF_INET6) ? AF_INET6 : 1;
	int clmatch = 0;

	res_log(0,0,0,0,0);

	if( 256 <= (leng = strlen(name)) ){
		debug(DBG_FORCE,"Host name too long(%d): %s\n",leng,name);
		if( 500 < leng )
			return 0;
	}

	ac = 0;
	res = 0;
	lastres = 0;
	rwhere[0] = rwhere[1] = 0;
	setVStrEnd(cname,0);

	for( ri = 0; ri = RES_next_res(where,ri,AVStr(res1),AVStr(arg)); ){
	  debug(DBG_ANY,"        RES[%s] %s\n",res1,where);
	  res = res1[0];

	  if( (clmatch = clientmatch(name,where,res1,AVStr(arg))) == 0 ){
		continue;
	  }
	  if( !RES_ASIS && res == RT_DNS ){
		/* will be filtered in dnsrch() after extented with DEFDNAME */
	  }else
	  if( dommatch(name,where,res1,AVStr(arg)) == 0 ){
		continue;
	  }
	  lastres = res;
	  switch(res){
	    case RT_UNKNOWN: /* emulate cached unknown */
		rv[0] = 0;
		RES_CACHED_UNKNOWN = 3 /* UNKNOWN_V4|UNKNOWN_V6 */;
		debug(DBG_NS,"Hit: 0 (forced Unknown for '%s')\n",name);
		return 0;

	    case RT_CACHE:
		with_cache = 1;
		ac = gethostbynameaddr_cache(arg,name,rrc,rv,AVStr(rb),byname,AVStr(cname),0);

/*
		ac = gethostbynameaddr_cache(arg,name,rrc,rv,AVStr(rb),1,AVStr(cname),0);
*/
		break;
	    case RT_FILE:
		ac = gethostbynameaddr_file(arg,name,rrc,rv,AVStr(rb),byname,AVStr(cname));
		/*
		ac = gethostbynameaddr_file(arg,name,rrc,rv,AVStr(rb),1,AVStr(cname));
		*/
		break;
	    case RT_NIS:
		ac = gethostbynameaddr_nis(_NISMAP_NAME,arg,name,rrc,rv,AVStr(rb),byname,AVStr(cname));
		/*
		ac = gethostbynameaddr_nis(_NISMAP_NAME,arg,name,rrc,rv,AVStr(rb),1,AVStr(cname));
		*/
		break;
	    case RT_DNS:
		if( RES_QTYPE == AF_INET6 ){
		ac = gethostbynameaddr_dnsrch(where,arg,name,TY_AAAA,rrc,rv,AVStr(rb),AVStr(cname));
		}else
		ac = gethostbynameaddr_dnsrch(where,arg,name,TY_A,rrc,rv,AVStr(rb),AVStr(cname));
		break;
	    case RT_SYS:
		if( RES_QTYPE == AF_INET6 ){
ac = gethostbynameaddr_sys(name,TY_AAAA,rrc,rv,AVStr(rb),AVStr(cname));
		}else
		ac = gethostbynameaddr_sys(name,TY_A,rrc,rv,AVStr(rb),AVStr(cname));
		break;
	  }
	  putResTrace("N{%c%d}",res,ac);
	  if( 0 < ac ){
		rwhere[0] = res;
		break;
	  }
	  res = 0;
	}
	if( 0 < ac )
		rv[ac] = 0;
	else	rv[0] = 0;

	RES_CACHED_UNKNOWN = 0;
	if( with_cache && lastres )
	if( RES_client_dependent ){
		/* don't cache client dependent result */
	}
	else
		ac = caching(lastres,ac,name,rv,1,AVStr(cname),UNKNOWN_HOSTADDR,4);

	debug(DBG_NS,"Hit: %d\n",ac);
	res_log(res?res:'-',1,name,rv,cname);
	return ac;
}

/*
 * exclude elements from given host name list "namev[namec]"
 * if the IP address of a element does not match "caddr".
 */
static int isHostnameOf(int namec,char *namev[],PCStr(nameb),PCStr(caddr))
{	char *av[32]; /**/
	CStr(ab,1024);
	CStr(cn,512);
	CStr(addr1,32);
	const unsigned char *a1;
	int ia[4];
	CStr(oa,4);
	int na,ai,aj,ok;

	sscanf(caddr,"%d.%d.%d.%d",&ia[0],&ia[1],&ia[2],&ia[3]);
	oa[0]=ia[0]; oa[1]=ia[1]; oa[2]=ia[2]; oa[3]=ia[3];

	ok = 0;
	for( ai = 0; ai < namec; ai++ ){
		na = gethostbynameaddr_dns("",namev[ai],TY_A,elnumof(av),av,AVStr(ab),AVStr(cn));
		if( na == 0 ){
			debug(DBG_FORCE,"DNS INCONSISTENT: %s -> %s -> ?\n",
				caddr,namev[ai]);
		}else
		for( aj = 0; aj < na; aj++ ){
			a1 = (unsigned char*)av[aj];
			if( bcmp(oa,a1,4) == 0 ){
				namev[ok++] = namev[ai];
				break;
			}
			sprintf(addr1,"%d.%d.%d.%d",a1[0],a1[1],a1[2],a1[3]);
			debug(DBG_FORCE,"DNS INCONSISTENT: %s -> %s -> %s\n",
				caddr,namev[ai],addr1);
		}
	}
	return ok;
}

int gethostbyaddr_all(PCStr(where),char rwhere[],PCStr(caddr),int rrc,char *rv[],PVStr(rb))
{	int ri,res,ac;
	int lastres;
	CStr(res1,512);
	CStr(arg,512);
	int with_cache = 0;
	int clmatch = 0;

	res_log(0,0,0,0,0);

	ac = 0;
	res = 0;
	lastres = 0;
	rwhere[0] = 0;

	if( isWindowsCE() ){
		if( strheadstrX(caddr,"192.168.",0)
		 || strheadstrX(caddr,"127.0.0.",0)
		){
			putResTrace("IGN{%s/%s}",caddr,where);
			return 0;
		}
	}
	for( ri = 0; ri = RES_next_res(where,ri,AVStr(res1),AVStr(arg)); ){
	  debug(DBG_ANY,"        RES[%s] %s\n",res1,where);
	  if( (clmatch = clientmatch(caddr,where,res1,AVStr(arg))) == 0 ){
		continue;
	  }
	  if( dommatch(caddr,where,res1,AVStr(arg)) == 0 ){
		continue;
	  }
	  res = res1[0];
	  lastres = res;
	  switch(res){
	    case RT_UNKNOWN: /* emulate cached unknown */
		rv[0] = 0;
		RES_CACHED_UNKNOWN = 3;
		debug(DBG_NS,"Hit: 0 (forced Unknown for '%s')\n",caddr);
		return 0;

	    case RT_CACHE:
		with_cache = 1;
		ac = gethostbynameaddr_cache(arg,caddr,rrc,rv,AVStr(rb),0,VStrNULL,0);
		break;
	    case RT_FILE:
		ac = gethostbynameaddr_file(arg,caddr,rrc,rv,AVStr(rb),0,VStrNULL);
		break;
	    case RT_NIS:
		ac = gethostbynameaddr_nis(_NISMAP_ADDR,arg,caddr,rrc,rv,AVStr(rb),0,VStrNULL);
		break;
	    case RT_DNS:
	    case RT_SYS:
		{
		int a1,a2,a3,a4;
		CStr(name,256);
		if( VSA_strisaddr(caddr) == AF_INET6 ){
			ipv6_domain(caddr,AVStr(name));
		}else{
		sscanf(caddr,"%d.%d.%d.%d",&a1,&a2,&a3,&a4);
		sprintf(name,"%d.%d.%d.%d.%s.",a4,a3,a2,a1,REVERSE_DOM);
		}
		if( res == RT_DNS )
			ac = gethostbynameaddr_dns(arg,name,TY_PTR,rrc,rv,AVStr(rb),VStrNULL);
		else	ac = gethostbynameaddr_sys(caddr,TY_PTR,rrc,rv,AVStr(rb),VStrNULL);
		if( ac == 1 && rv[0] != NULL && rv[0][0] == 0 ){
			debug(DBG_FORCE,"### ignored empty for byaddr()\n");
			ac = 0;
		}
		if( 0 < ac && RES_VERIFY )
			ac = isHostnameOf(ac,rv,rb,caddr);
		}
		break;
	  }
	  putResTrace("A{%c%d}",res,ac);
	  if( 0 < ac ){
		rwhere[0] = res;
		break;
	  }
	  res = 0;
	}
	if( 0 < ac )
		rv[ac] = 0;
	else	rv[0] = 0;

	RES_CACHED_UNKNOWN = 0;
	if( with_cache && lastres )
	if( RES_client_dependent ){
		/* don't cache client dependent result */
	}
	else
		ac = caching(lastres,ac,caddr,rv,0,VStrNULL,UNKNOWN_HOSTNAME,0);

	debug(DBG_NS,"Hit: %d\n",ac);
	res_log(res?res:'-',0,caddr,rv,NULL);
	return ac;
}

const char *RES_AF = "46";
int strcanbeHostname(int af,PCStr(name));
struct hostent *RES_gethostbyaddr(PCStr(baddr), int len, int type);
struct hostent *RES_gethostbyname(PCStr(name))
{	int ac;
	CStr(caddr,64);
	CStr(cname,512);
	CStr(where,8);
	const char *types;
	const char *tp;
	int qtype;
	IStr(resolvers,RESOLVERS_SIZ);

	RES_init();
	debug(DBG_ANY,"gethostbyname(%s)\n",name);

	if( isinetAddr(name) ){
		int bleng,btype;
		CStr(baddr,IPV6_ADDRLENG);
		/*
		CStr(baddr,16);
		*/
		bleng = VSA_atob(name,AVStr(baddr),&btype);
		return RES_gethostbyaddr(baddr,bleng,btype);
	}

	if( strcasestr(name,"IN-ADDR.ARPA") || strcasestr(name,"IP6.INT") ){
		debug(DBG_FORCE,"don't search getbyhostname(%s)\n",name);
		return NULL;
	}

	types = RES_AF;
	if( strncmp(name,"_-",2) == 0 ){
		/* host prefix for the upper layer (DeleGate) */
		if( tp = strchr(name+2,'.') ){
			name = tp+1;
		}
	}
	if( strncmp(name,"-AAAA.",6) == 0 ){ types = "6"; name += 6; }else
	if( strncmp(name,"_4.", 3) == 0 ){ types = "4";  name += 3; }else
	if( strncmp(name,"_6.", 3) == 0 ){ types = "6";  name += 3; }else
	if( strncmp(name,"_64.",4) == 0 ){ types = "64"; name += 4; }else
	if( strncmp(name,"_46.",4) == 0 ){ types = "46"; name += 4; }

	if( !strcanbeHostname(0,name) ){
		debug(DBG_ANY,"---- RES_gethostbyname(%s) not a name\n",name);
		return NULL;
	}
	RES_resolvers(AVStr(resolvers));
	ac = 0;
	for( tp = types; *tp; tp++ ){
		if( *tp == '6' )
			RES_QTYPE = AF_INET6;
		else	RES_QTYPE = 0;
		ac = gethostbyname_all(resolvers,where,name,elnumof(Raddrv),Raddrv,AVStr(Raddrb),AVStr(cname));

		if( RES_CACHED_UNKNOWN == 3 ){
			/* don't try anymore for forced unknown */
			break;
		}
		if( 0 < ac )
			break;
		if( *name == '_' ) /* retrieved _service not A/AAAA */
			break;
		if( tp[1] ){
			debug(DBG_FORCE,"retrying %s [%s]\n",
				tp[1]=='6'?"AAAA":"A",name);
		}
	}
	qtype = RES_QTYPE;
	RES_QTYPE = 0;

	if( ac <= 0 )
		return NULL;

	Raddrv[ac] = 0;

	if( cname[0] != 0 && strcmp(cname,name) != 0 ){
		Rnamev[0] = Rnameb; Xstrcpy(NVStr(Rnameb) Rnamev[0],cname);
		Rnamev[1] = Rnameb+strlen(Rnameb)+1; Xstrcpy(NVStr(Rnameb) Rnamev[1],name);
		Rnamev[2] = 0;
	}else{
		Rnamev[0] = Rnameb; strcpy(Rnameb,name);
		Rnamev[1] = 0;
	}
	if( qtype == AF_INET6 ){
		Rhostent.h_ent.h_addrtype = AF_INET6;
		Rhostent.h_ent.h_length = 16;
	}else{
	if( 1 < ac )
		sort_ipaddrs((const char**)Raddrv);

	Rhostent.h_ent.h_addrtype = AF_INET;
	Rhostent.h_ent.h_length = 4;
	}
	return &Rhostent.h_ent;
}

struct hostent *RES_gethostbyaddr(PCStr(baddr), int len, int type)
{	CStr(caddr,64);
	CStr(cname,512);
	CStr(where,8);
	CStr(where2,8);
	int ac;
	const unsigned char *ba = (const unsigned char *)baddr;
	IStr(resolvers,RESOLVERS_SIZ);

	RES_init();
	if( type == AF_INET6 ){
		strcpy(caddr,VSA_ltoa((unsigned char*)baddr,len,type));
	}else
	sprintf(caddr,"%d.%d.%d.%d",ba[0],ba[1],ba[2],ba[3]);
	debug(DBG_ANY,"gethostbyaddr(%s)\n",caddr);

	RES_resolvers(AVStr(resolvers));
	ac = gethostbyaddr_all(resolvers,where,caddr,elnumof(Rnamev),Rnamev,AVStr(Rnameb));
	if( ac <= 0 )
		return NULL;

	Rhostent.h_ent.h_length = len;
/*
	int ai;
	for( ai = 0; ai < ac; ai++ ){
		Rhostent.h_ent.h_addr_list[ai] = len;
	}
*/

	Raddrv[0] = Raddrb;
	bcopy(baddr,Raddrb,len);
	Raddrv[1] = 0;

/*
if( where[0] == 'D' ){
	ac = gethostbyname_all(where,where2, Rnameb,Raddrv,AVStr(Raddrb),AVStr(cname));
	if( 1 < ac )
		sort_ipaddrs(Raddrv);
}
*/
	Rhostent.h_ent.h_addrtype = type;
	return &Rhostent.h_ent;
}

void RES_sethostent(int stayopen)
{
}
void RES_endhostent()
{
}
struct hostent *RES_gethostent()
{
	return NULL;
}

int RES_matchLine(PCStr(what),int byname,PCStr(name),PCStr(line),int rrc,char *rv[],xPVStr(rb),PVStr(cname))
{	const char *lp;
	CStr(addr,64);
	CStr(host,512);
	CStr(host1,512);
	const char *ap;
	int iaddr;
	int ac;

	ac = 0;

	if( lp = strchr(line,'#') ){
		if( lp == line )
			goto EXIT;
		truncVStr(lp);
	}
	if( lp = strchr(line,'\n') )
		truncVStr(lp);

	lp = wordScan(line,addr);
	if( addr[0] == 0 )
		goto EXIT;

	if( byname ){
		wordScan(lp,host1);
		for(;;){
			if( rrc-1 <= ac ){
				debug(DBG_FORCE,"ADDR OVERFLOW %d/%d\n",ac,rrc);
				break;
			}
			lp = wordScan(lp,host);
			if( host[0] == 0 )
				break;
					
			/*
			if( strcasecmp(host,name) == 0 ){
			*/
			if( strcasecmp(host,name) == 0
			 || rexpmatchX(host,name,"c")
			){
				/*
				CStr(baddr,16);
				*/
				CStr(baddr,IPV6_ADDRLENG);
				int bleng;
				debug(DBG_ANY,"RES: <%s> %s\n",what,line);
				bleng = VSA_atob(addr,AVStr(baddr),NULL);
				if( byname != AF_INET6 && 16 <= bleng ){
					continue;
				}else
				if( bleng == 4 &&
				    bcmp(baddr,UNKNOWN_HOSTADDR,bleng) == 0 ){
				}else
				if( byname == AF_INET6 && bleng < 16 ){
					continue;
				}
				rv[ac++] = (char*)rb;
				Bcopy(baddr,rb,bleng);
				rb += bleng;
				strcpy(cname,host1);
				break;
			}
		}
	}else{
		if( strcmp(addr,name) == 0 ){
			debug(DBG_ANY,"RES: <%s> %s\n",what,line);
			for(;;){
				if( rrc-1 <= ac ){
				debug(DBG_FORCE,"NAME OVERFLOW %d/%d\n",ac,rrc);
					break;
				}
				lp = wordScan(lp,host);
				if( host[0] == 0 )
					break;
				rv[ac++] = (char*)rb;
				strcpy(rb,host);
				rb += strlen(rb) + 1;
			}
		}
	}
EXIT:
	rv[ac] = (char*)rb;
	return ac;
}

static void readhosts1(PCStr(path),FILE *fp,HostFile *hp)
{	defQStr(datap); /*alloc*//**/
	const char *cp;
	int mtime,peak,leng;

	debug(DBG_ANY,"HOSTS: %s\n",path);
	if( hp->h_path && hp->h_path[0] == '/' ){
		mtime = File_mtime(hp->h_path); 
		if( 0 < mtime && mtime <= hp->h_date ){
			debug(DBG_ANY,"HOSTS: no change in %s\n",path);
			hp->h_date = time(0);
			return;
		}
	}

	hp->h_path = (char*)stralloc(path);
	hp->h_date = time(0);

	peak = 0;
	for(;;){
		if( hp->h_size <= peak+2+1024+1 ){
			hp->h_size += 64*1024;
			setQStr(hp->h_buff,Malloc((char*)hp->h_buff,hp->h_size),hp->h_size);
		}

		cpyQStr(datap,hp->h_buff);
		datap = (char*)&hp->h_buff[peak+2];
		if( fgets(datap,1024,fp) == NULL )
			break;
		if( strneq(datap,"#!",2) ){
		}else
		if( cp = strpbrk(datap,"#\r\n") ){
			truncVStr(cp); cp--;
			while( datap <= cp && (*cp == ' ' || *cp == '\t') ){
				truncVStr(cp); cp--;
			}
		}
		if( datap[0] == 0 )
			continue;

		leng = strlen(datap);
		setVStrElem(hp->h_buff,peak+0,leng >> 8);
		setVStrElem(hp->h_buff,peak+1,leng);
		peak += 2 + leng + 1;
	}
	setVStrEnd(hp->h_buff,peak+0);
	setVStrEnd(hp->h_buff,peak+1);
}

int gethostbynameaddr_file(PCStr(path),PCStr(name),int rrc,char *rv[],xPVStr(rb),int byname,PVStr(cname))
{	FILE *fp;
	int now,ac;
	HostFile *hp;
	const char *lp;
	int leng;
	int hi;
	int opt_addr_max = -1;

	hp = &Hosts[0];
	for( hi = 0; hi < elnumof(Hosts)-1; hi++ ){
		hp = &Hosts[hi];
		if( hp->h_path == 0 )
			break;
		if( streq(hp->h_path,path) )
			break;
	}

	now = time(0);
	if( hp->h_buff == NULL || 60 < (now-hp->h_date) ){
		if( path == NULL || path[0] == 0 )
			path = _HOSTSFILE;

		if( strncmp(path,"sh:",3) == 0 )
			fp = popen(path+3,"r");
		else	fp = fopen(path,"r");

		if( fp == NULL ){
			debug(DBG_ANY,"cannot open %s\n",path);
			return -1;
		}

		/*
		readhosts1(path,fp,&Hosts[0]);
		*/
		readhosts1(path,fp,hp);

		if( strncmp(path,"sh:",3) == 0 )
			pclose(fp);
		else	fclose(fp);
	}

	ac = 0;
	for( lp = hp->h_buff; leng = (lp[0]<<8|lp[1]&0xFF); lp += leng+3 ){
		if( lp[2] == '#' ){
			if( strneq(lp+2,"#!",2) ){
				if( strneq(lp+2+2,"max=",4) ){
					opt_addr_max = atoi(lp+2+2+4);
				}
			}
		}
		if( 0 <= opt_addr_max && opt_addr_max <= ac ){
			break;
		}
		ac += RES_matchLine(path,byname,name,lp+2,rrc-ac,&rv[ac],AVStr(rb),AVStr(cname));
		rb = rv[ac];
	}
	return ac;
}

double RES_NIS_TIMEOUT = 3.0;
static sigjmp_buf jmpEnv;
static void sigALRM(int sig){ siglongjmpX(jmpEnv,SIGALRM); }

int gethostbynameaddr_nis(PCStr(map),PCStr(domain),PCStr(name),int rrc,char *rv[],xPVStr(rb),int byname,PVStr(cname))
{	const char *ypdomain;
	const char *key;
	const char *val;
	CStr(line,1024);
	const char *lp;
	int klen,vlen;
	int rcode;
	int ac;
	int timer;
	double St = Time();
	double Et;

	if( domain != NULL && domain[0] != 0 )
		ypdomain = domain;
	else{
		ypdomain = NULL;
		rcode = yp_get_default_domain((char**)&ypdomain);
		if( rcode != 0 || ypdomain == NULL || *ypdomain == 0 )
			return -1;
		if( strcmp(ypdomain,"(none)") == 0 )
			return -1;
	}

	/* fix-150506c */
	if( 0 < RES_NIS_TIMEOUT ){
		timer = pushTimer("yp_match",sigALRM,(int)RES_NIS_TIMEOUT);
	}
	rcode = -1;
	if( sigsetjmpX(jmpEnv,1) != 0 ){
	}else{
	rcode = yp_match(ypdomain,(char*)map,name,strlen(name),(char**)&val,&vlen);
	}
	if( 0 < RES_NIS_TIMEOUT ){
		popTimer(timer);
	}
	Et = Time() - St;
	if( rcode == -1 || RES_NIS_TIMEOUT < Et ){
		syslog_ERROR("---- ERROR RESOLV=nis: yp_match(%s)=%d (%.3f/%.2f)\n",
			name,rcode,Et,RES_NIS_TIMEOUT);
	}
	if( rcode != 0 )
		return -1;

	ac = 0;
	for( lp = val; *lp; ){
		lineScan(lp,line);
		ac += RES_matchLine(map,byname,name,line,rrc-ac,&rv[ac],AVStr(rb),AVStr(cname));
		rb = rv[ac];
		if( lp = strchr(lp,'\n') )
			lp++;
		else	break;
	}
	return ac;
}
