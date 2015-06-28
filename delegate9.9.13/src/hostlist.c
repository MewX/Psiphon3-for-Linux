/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	hostlist.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    Each element in HostList is one of follows:

	IP-address matching with mask:
		host/255.255.255.0
		host/@C

	IP-address range:
		192.31.200.[65-94]
		192.31.[197-206]
		150.29.[0-255]

	Domain name pattern macthing by name:
		*.ac.jp
		*.jp

    A special host-name "?" matches with hosts which name cannot be
    retrieved with DNS, thus unknown.

    Each element can be prefixed with UserList.
    A special user-name "?" matches when the user cannot be
    identified with IDENTd.

    Special elements which add a flavor of composit operation :-)

	AND: A,&,B -- if A is false, false as a whole (can be "&{A,B}" ???)
	OR : A,|,B -- if A is true, ture as a whole (short cut evaluation)
	NEG: A,!,B -- negate the result of A, then evaluate B (can be "!{A,B}")

History:
	940623	added simple masking (suggested by <yoko@huie.hokudai.ac.jp>)
	940807	separated from access.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <ctype.h>
#include "ystring.h"
#include "vsocket.h" /* for VSAddr */
#include "dglib.h"
int dumpHostCache(FILE *tc);

#include "hostlist.h"
#define FILE void

#include "log.h"
#undef Verbose
#define Verbose (LOG_type&L_HOSTMATCH)==0?0:putLog0

/*
#define inAddr(addr)	VA_inAddr(addr)
*/
#define inAddr(addr)	((addr)->I3==HEURISTIC_MASK?".":VA_inAddr(addr))
const char *hostmatch_asisaddr = "/a";
const char *hostmatch_withauth = "/u";
const char *hostmatch_exrandom = "/R";
const char *hostmatch_ignauth = "*";

#define HL_INCSIZE	8
#define HL_MAXDEPTH	10

static char opsyms[] = "+!-?";
#define ON_EQ	0	/* ON  if matched */
#define ON_NEQ	1	/* ON  if not matched */
#define OFF_EQ	2	/* OFF if matched */
#define OFF_NEQ	3	/* OFF if not matched */

#define OP_AND	4
#define OP_OR	5
#define OP_NEG	6
#define OP_HOUR	7

#define	DO_NOP	0
#define	DO_ON	1
#define DO_OFF	2

typedef struct {
	int	ht_size;
	int	ht_id;
	int	ht_hash;
     HostList **ht_list;
} HostListTab;
typedef struct {
	HostList	he_lexHosts;
	HostList	he_virtualHosts;
	HostListTab	he_listTab;
	ClientInfo	he_clientInfo;
	ClientInfo	he_ridentInfo;
} HostListEnv;
static HostListEnv *hostListEnv;
static char LexHosts[] = "LexHosts";
#define lexHosts	(&hostListEnv->he_lexHosts)
#define virtualHosts	(&hostListEnv->he_virtualHosts)
#define hostListTab	hostListEnv->he_listTab
#define hostListTabHash	hostListEnv->he_listTab.ht_hash
#define hostListName(id) hostListEnv->he_listTab.ht_list[id]->hl_what
static ClientInfo *clientInfop;
void minit_hostlist()
{
	if( hostListEnv == 0 )
	{
		hostListEnv = NewStruct(HostListEnv);
		hostListEnv->he_lexHosts.hl_what = LexHosts;
		hostListEnv->he_virtualHosts.hl_what = "virtualHosts";
		hostListEnv->he_virtualHosts.hl_flags |= HL_BYNAMEONLY;
		clientInfop = &hostListEnv->he_clientInfo;
	}
}
scanListFunc addHostList1(PCStr(hostmask),HostList *hostlist);
extern const char *DELEGATE_LOCALNET;
static void resize_hostlisttab(HostListTab *ht)
{	int newsize,li;
	HostListTab oht;
	HostList *HL;

	oht = *ht;
	if( oht.ht_size ){
		newsize = oht.ht_size * 2;
	}else	newsize = 16;
	Verbose("HOSTLIST resized [%d -> %d]\n",oht.ht_size,newsize);
	ht->ht_size = newsize;
	ht->ht_list = (HostList**)calloc(sizeof(HostList*),newsize);
	ht->ht_hash = strid_create(newsize*2);
	if( oht.ht_size ){
		for( li = 1; li < oht.ht_size; li++ ){
			ht->ht_list[li] = HL = oht.ht_list[li];
			strid(ht->ht_hash,HL->hl_what,li);
		}
		/* free(oht.ht_list); might be referred by self redefinition */
	}
}
void putHostListTab(PCStr(aname),HostList *HL)
{	int listid;

	listid = strid(hostListTabHash,aname,-1);
	if( listid < 0 ){
		listid = ++hostListTab.ht_id;
		strid(hostListTabHash,aname,listid);
		hostListTab.ht_list[listid] = HL;
	}
}
void addHostListTab(PCStr(dname),PCStr(dhostlist))
{	int listid,apptype,applist,noresolv;
	const char *aname;
	CStr(anameb,64);
	const char *aflags;
	const char *ahostlist;
	HostList *HL,OHL;

	if( noresolv = *dname == '-' )
		dname++;
	if( aflags = strchr(dname,'/') ){
		wordscanY(dname,AVStr(anameb),sizeof(anameb),"^/");
		aname = anameb;
		aflags++;
	}else{
		aname = dname;
		aflags = "";
	}
	apptype = strchr(aflags,'+') != NULL;
	applist = strncmp(dhostlist,"+,",2) == 0;
	if( applist )
		ahostlist = dhostlist + 2;
	else	ahostlist = dhostlist;

	listid = strid(hostListTabHash,aname,-1);
	if( 0 < listid ){
		HL = hostListTab.ht_list[listid];
		if( HL->hl_flags & HL_PROTECT ){
			sv1log("ERROR HOSTLIST=%s protected\n",aname);
		}else
		if( (HL->hl_flags & HL_APPEND) || apptype || applist ){
		}else{
			OHL = *HL;
			bzero(HL,sizeof(HostList));
			HL->hl_what = OHL.hl_what;
			HL->hl_flags = OHL.hl_flags;
			sv1log("[%d] HOSLIST=%s overwrite\n",listid,aname);
		}
	}else{
		listid = ++hostListTab.ht_id;
		if( hostListTab.ht_size <= listid )
			resize_hostlisttab(&hostListTab);
		strid(hostListTabHash,aname,listid);
		HL = NewStruct(HostList);
		HL->hl_what = StrAlloc(aname);
		if( apptype )
			HL->hl_flags |= HL_APPEND;
		hostListTab.ht_list[listid] = HL;
	}
	if( strchr(aflags,'p') )
		HL->hl_flags |= HL_PROTECT;
	if( strchr(aflags,'c') )
		HL->hl_flags |= HL_BYCLHOST;
	if( strchr(aflags,'i') )
		HL->hl_flags |= HL_NOIDENT;
	if( strchr(aflags,'r') || noresolv )
		HL->hl_flags |= HL_NORESOLV;
	if( strchr(aflags,'a') )
		HL->hl_flags |= HL_BYADDR;
	if( strchr(aflags,'u') )
		HL->hl_flags |= HL_BYAUTH;
	if( strchr(aflags,'A') )
		HL->hl_flags |= HL_BYAGENT;
	scan_commaListL(ahostlist,0,scanListCall addHostList1,HL);
	Verbose("[%d] HOSLIST=%s:%s\n",listid,dname,dhostlist);
}
static void init_hostListTab()
{
	if( hostListTabHash == 0 ){
		resize_hostlisttab(&hostListTab);
		addHostListTab(".localnet",DELEGATE_LOCALNET);
		addHostListTab(".RELIABLE","*");
		addHostListTab(".socksdst","!.localnet");
	}
}
void scan_HOSTLIST(DGC*ctx,PCStr(listdef))
{	const char *dp;
	CStr(name,32);

	dp = strchr(listdef,':');
	if( dp == 0 ){
		return;
	}
	wordscanY(listdef,AVStr(name),sizeof(name),"^:");
	init_hostListTab();
	addHostListTab(name,dp+1);
}

#define ridentInfo	hostListEnv->he_ridentInfo
#define RidentHost	ridentInfo.clientSockHost
#define RidentPeer	ridentInfo.clientsideHost

/*
#define clientInfo	hostListEnv->he_clientInfo
*/
#define clientInfo	(*clientInfop)
#define CurrentTime	clientInfo.currentTime
#define ClientsideHost	clientInfo.clientsideHost
#define ClientSockHost	clientInfo.clientSockHost
#define ClientHost	clientInfo.clientHost
#define ClientAgent	clientInfo.e_agentname
#define fromSelf	clientInfo._fromself
/*
void VA_HL_pushClientInfo(double Now,VAddr *peerhost,VAddr *sockhost)
*/
void VA_HL_pushClientInfo(double Now,VAddr *peerhost,VAddr *sockhost,int _self)
{
	CurrentTime = Now;
	ClientsideHost = *peerhost;
	ClientSockHost = *sockhost;
	fromSelf = _self;
}
void HL_setClientAgent(PCStr(agent))
{
	linescanX(agent,AVStr(clientInfo.e_agentname),sizeof(clientInfo.e_agentname));
}
void HL_setClientIF(PCStr(addr),int port,int remote)
{
	if( addr )
		VA_setVAddr(&ClientSockHost,addr,port,remote);
	else	ClientSockHost = AddrNull;
}
void HL_popClientInfo()
{
	ClientsideHost = AddrNull;
	ClientSockHost = AddrNull;
	fromSelf = 0;
}
void HL_setClientInfo(VAddr *peerhost)
{
	ClientHost = *peerhost;
}
void HL_setRidentInfo(VAddr *peer,VAddr *host){
	if( peer == NULL ){
		RidentPeer.a_flags = 0;
		RidentHost.a_flags = 0;
	}else{
		RidentPeer = *peer;
		RidentHost = *host;
	}
}

static int matchProto(const char *protolist[],PCStr(proto))
{	int isin,pi;
	const char *proto1;
	int op,match;

	if( *protolist[0] == '!' )
		isin = 1;
	else	isin = 0;

	for( pi = 0; proto1 = protolist[pi]; pi++ ){
		if( *proto1 == '!' ){
			proto1++;
			op = OFF_EQ;
		}else	op = ON_EQ;

		if( streq(proto1,"*") )
			match = 1;
		else	match = streq(proto1,proto);

		if( match && op == ON_EQ )	isin = 1; else
		if( match && op == OFF_EQ )	isin = 0;
		Verbose("--> %d : %d : %s : %s : %s\n",
			isin, match, op==OFF_EQ?"NEQ":"EQ",
			proto, proto1);
	}
	return isin;
}
static char **makeUserRexp(int uc,const char *userlist[])
{	char **rexpv;
	const char *user;
	int ui;

	rexpv = (char**)StructAlloc(sizeof(char*)*uc);
	for( ui = 0; ui < uc; ui++ ){
		user = userlist[ui];
		if( *user == '!' )
			user++;
		if( !streq(user,"*") && strpbrk(user,"*[") ){
			sv1log("##REGEXP COMPILED: %s\n",user);
			rexpv[ui] = (char*)frex_create(user);
		}else	rexpv[ui] = 0;
	}
	return rexpv;
}
static int matchUser(const char *userlist[],const char *rexplist[],PCStr(username))
{	int isin,ui;
	const char *user;
	const char *rexp;
	const char *tail;
	int op,match;

	if( *userlist[0] == '!' )
		isin = 1;
	else	isin = 0;

	for( ui = 0; user = userlist[ui]; ui++ ){
		if( *user == '!' ){
			user++;
			op = OFF_EQ;
		}else	op = ON_EQ;

		if( streq(user,"*") )
			match = 1;
		else
		if( rexp = rexplist[ui] ){
			tail = frex_match((struct fa_stat*)rexp,username);
			match = tail && *tail == 0;
			sv1log("##REGEXP EXECUTED ==> %d : %s : %s\n",
				match,username,user);
		}
		else	match = strcmp(user,username) == 0;

		if( match && op == ON_EQ )	isin = 1; else
		if( match && op == OFF_EQ )	isin = 0;
		Verbose("--> %d : %d : %s : %s : %s\n",
			isin, match, op==OFF_EQ?"NEQ":"EQ",
			username,user);
	}
	return isin;
}
static int matchPort(const char *portlist[],int portnum)
{	int isin,pi;
	const char *ports;
	int op,match;
	int port0,port1;

	if( portlist[0] == 0 ){
		/* empty port list */
		isin = 0;
	}else
	if( *portlist[0] == '!' )
		isin = 1;
	else	isin = 0;

	for( pi = 0; ports = portlist[pi]; pi++ ){
		if( *ports == '!' ){
			ports++;
			op = OFF_EQ;
		}else	op = ON_EQ;

		if( streq(ports,"*") )
			match = 1;
		else{
			switch( sscanf(ports,"%d-%d",&port0,&port1) ){
			default: /* can be EOF */
			case 0: match = 0; break;
			case 1: match = port0 == portnum; break;
			case 2: match = port0 <= portnum && portnum <= port1;
				break;
			}
		}

		if( match && op == ON_EQ )	isin = 1; else
		if( match && op == OFF_EQ )	isin = 0;
		Verbose("--> %d : %d : %s : %d : %s\n",
			isin, match, op==OFF_EQ?"NEQ":"EQ",
			portnum,ports);
	}
	return isin;
}

static int match_addrrange(Host *Hp,VAddr *Vaddr)
{	int ai;
	int addr = Vaddr->I3;
	Uchar a1;

	for(ai = 0; ai < 4; ai++){
		a1 = (addr >> ((3-ai)*8)) & 0xFF;
		if( a1 < Hp->ranges[ai].h_low || Hp->ranges[ai].h_high < a1 )
			return 0;
	}
	return 1;
}

/* RFC1597 private IP address */
#define PRIVATEC	((192<<24)|(168<<16))
#define PRIVATEBL	((172<<24)|(16<<16))
#define PRIVATEBH	((172<<24)|(31<<16))
#define PRIVATEA	(10<<24)

#define isV6(a) ((a)->I0 || (a)->I1 || (a)->I2)

static int default_netmask(VAddr *Mask,VAddr *Vaddr)
{	unsigned int ip4c,mask1;
	unsigned int ip4,net;

	if( isV6(Vaddr) ){
		if( Mask->I3 == HEURISTIC_MASK ){
			Mask->I2 = 0;
			Mask->I3 = 0;
		}
		return 0;
	}

	if( Mask->I3 != CLASS_MASK )
	if( Mask->I3 != HEURISTIC_MASK )
		return 0;

	ip4c = (Vaddr->I3 >> 24) & 0xFF;
	if( ip4c < 128 ) mask1 = 0xFF000000; else
	if( ip4c < 192 ) mask1 = 0xFFFF0000; else
	       mask1 = 0xFFFFFF00;

	if( Mask->I3 == HEURISTIC_MASK ){
		ip4 = Vaddr->I3;
		net = ip4 & mask1;
		if( net == PRIVATEC 
		 || PRIVATEBL <= net && net <= PRIVATEBH
		 || net == PRIVATEA ){
			/* use class mask for private address */ 
		}else
		if( ip4c < 128 )/* class A */
		{
			mask1 = 0xFFFFFF00;
			*Mask = MaskZero;
			Mask->I3 = mask1;
			sv1log("default netmask %s/. = %X\n",
				VA_inAddr(Vaddr),mask1);
		}
	}

	*Mask = MaskZero;
	Mask->I3 = mask1;
	return 1;
}

static int WHMtoi(PCStr(st),PCStr(dflt))
{	CStr(buf,8);
	char sc;
	int si;

	strcpy(buf,dflt);
	for( si = 0; sc = st[si]; si++ ){
		if(sizeof(buf) <= si)
			break;
		setVStrElem(buf,si,sc); /**/
	}
	return atoi(buf);
}
static int matchTimePeriod(PCStr(period),int mask)
{	CStr(hour,8);
	int hc,h1,h2;
	int mc,m1,m2;
	const char *fmt;
	const char *smin;
	const char *smax;
	CStr(sh1,32);
	CStr(sh2,32);
	const char *pp;
	int min,max,mod;

	/*
	 * -T.000-499/1000
	 * -T.0-4/10
	 */
	if( 0 < mask ){
		sscanf(period,"%d-%d",&m1,&m2);
		mc = (int)((CurrentTime - (int)CurrentTime) * mask) % mask;
		if( m1 <= mc && mc <= m2 )
			return 1;
		else	return 0;
	}

	pp = period;
	switch( *pp ){
		case 'w': fmt = "%w%H%M"; smin = "00000"; smax = "62359"; pp++;
			  mod = 70000; break;
		case 'u': fmt = "%u%H%M"; smin = "10000"; smax = "72359"; pp++;
			  mod = 80000; break;
		default:  fmt =   "%H%M"; smin =  "0000"; smax =  "2359";
			  mod = 10000; break;
	}
	switch( Xsscanf(pp,"%[0-9]-%[0-9]",AVStr(sh1),AVStr(sh2)) ){
		default: /* can be EOF */
		case 0: return 0;
		case 1: h1 = WHMtoi(sh1,smin); h2 = WHMtoi(sh1,smax); break;
		case 2: h1 = WHMtoi(sh1,smin); h2 = WHMtoi(sh2,smax); break;
	}
	min = atoi(smin);
	max = atoi(smax);
	h1 = h1 % mod;
	h2 = h2 % mod;

	StrftimeLocal(AVStr(hour),sizeof(hour),fmt,(int)CurrentTime,0);
	hc = atoi(hour);

	Verbose("-T %d < %d-[%d]-%d < %d ?\n",min,h1,hc,h2,max);

	if( h1 <= h2 ){
		if( h1 <= hc && hc <= h2 )
			return 1; 
	}else{
		if( h1 <= hc && hc <= max || min <= hc && hc <= h2 )
			return 1;
	}
	return 0;
}

static int notResolved(VAddr *Vaddr,PCStr(name))
{
	if( AddrInvalid(*Vaddr) )
		return 1;

	if( isinetAddr(name) != 0 ) /* name is in "dd.dd.dd.dd" IP-address */
		return 1;
	return 0;
}
static int notResolvable(VAddr *Vaddr,PCStr(name)){
	if( Vaddr->a_flags & (VA_RSLVERR|VA_RSLVINVERR) ){
		return 4;
	}
	if( notResolved(Vaddr,name) ){
		return 1;
	}
	if( strtailstrX(name,".in-addr.arpa",1)
	 || strtailstrX(name,".ip6.int",1) ){
		return 2;
	}
	if( !hostIsResolvable(name) ){
		return 3;
	}
	return 0;
}

static const char *scanVdomain(PCStr(hostname),PVStr(hostnameb),PVStr(vdomain))
{	const char *vdom;
	const char *vp;
	const char *sp; /**/
	refQStr(dp,vdomain); /**/
	char ch;

	setVStrEnd(vdomain,0);
	vdom = strstr(hostname,".-");
	if( vdom == 0 )
		return 0;

	strcpy(hostnameb,hostname);
	hostname = hostnameb;
	vp = sp = strstr(hostname,".-");
	cpyQStr(dp,vdomain);
	for( vp += 2; ch = *vp; vp++ ){
		assertVStr(vdomain,dp+1);
		if( isalnum(ch) )
			setVStrPtrInc(dp,ch);
	}
	if( dp == vdomain )
		return 0;

	setVStrEnd(dp,0);
	while( *(char*)sp++ = *vp++ );
	return vdom;
}

int addrGroup(PCStr(macpat),PCStr(hostname),VAddr *hostaddr);
int matchHostSetX(const char *hostset,VAddr *ahost,VAddr *hosti,VAddr *mask,int expire);

#define HostOutgoingIF(hp)	(hp[0]=='.' && hp[1]=='o' && hp[2]==0)
#define HostIncomingIF(hp)	(hp[0]=='.' && hp[1]=='i' && hp[2]==0\
			      || hp[0]=='-' && hp[1]==0)
#define HostIncomingIFX(hp)	(hp[0]=='-' && hp[1]=='P') \
			      ||(hp[0]=='-' && hp[1]=='Q')
#define HostOnClientside(hp)	(hp[0]=='-' && hp[1]=='C' && hp[2]==0\
			      || hp[0]=='.' && hp[1]=='C' && hp[2]==0)
#define TimePeriod(hp)		(hp[0]=='-' && hp[1]=='T' && hp[2]=='.')
#define HostUnknown(hp)		(hp[0]=='?' && hp[1]==0)
#define CantResolve(hp)		(hp[0]=='?' && hp[1]=='*' && hp[2]==0)
#define HostMatchExactly(hp,hn)	(strcasecmp(hp,hn) == 0)

int hostListIsAny(HostList *hostlist){
	Host *Hp;
	if( hostlist && hostlist->hl_cnt == 1 ){
		Hp = hostlist->hl_List[1];
		if( streq(Hp->h_name,"*") ){
			return 1;
		}
	}
	return 0;
}
int CTX_getClientInfo(DGC*,ClientInfo *local,ClientInfo *rident);
int VA_resolv(VAddr *vaddr);
static int VA_hostIsinListX(void*ctx,HostList *hostlist,PCStr(proto),PCStr(cname),PCStr(alias),VAddr *Vaddr,PCStr(username),int ac,AuthInfo *av[],int lev)
{	int portnum = Vaddr->a_port;
	int hi,nhosts;
	VAddr hosti,mask,ahost,chost;
	Host *Hp;
	const char *hostpat;
	int op;
	int isin,match,do_onoff;
	const char *domhost;
	CStr(hostnameb,MaxHostNameLen);
	const char *vdom;
	CStr(vdomb,MaxHostNameLen);
	const char *vdom1;
	const char *hostname;
	const char *scname = cname;
	const char *salias = alias;
	int byauth;
	int byagent;
	int exp = 0; /* expire for matchHostListX() */

	ClientInfo my_clientInfo;
	ClientInfo my_ridentInfo;
	ClientInfo *clientInfop = &hostListEnv->he_clientInfo;
	if( lMULTIST() ){ 
		CTX_getClientInfo((DGC*)ctx,&my_clientInfo,&my_ridentInfo);
		clientInfop = &my_clientInfo;
	}

	hosti = *Vaddr;

	if( hostlist->hl_flags & HL_BYCLHOST ){
		hosti = ClientHost;
		cname = ClientHost.a_name;
		alias = 0;
		Verbose("BYCLHOST: %s %s\n",hostlist->hl_what,cname);
	}
	if( byauth = (hostlist->hl_flags & HL_BYAUTH) ){
		if( ac == 0 ){
			Verbose("BYAUTH[%s]: no authinfo: %s\n",
				hostlist->hl_what,cname);
			return 0;
		}
	}
	byagent = hostlist->hl_flags & HL_BYAGENT;

	if( scanVdomain(cname,AVStr(hostnameb),AVStr(vdomb)) ){
		cname = hostnameb;
		vdom = vdomb;
	}else	vdom = 0;

	strtolower(cname,hostnameb);
	cname = hostnameb;

	op = 0;
	isin = 0;
	nhosts = hostlist->hl_cnt;

	for( hi = 1; hi <= nhosts; hi++ ){
		Hp = hostlist->hl_List[hi];
		op = Hp->h_op;
		if( op == OP_AND ){
			if( isin ){
				Verbose("[%d/%d] &=> 1 AND succeed, cont.\n",
					hi,nhosts);
				isin = 0;
				continue;
			}else{
				Verbose("[%d/%d] &=> 0 AND failed, break\n",
					hi,nhosts);
				for( hi++; hi <= nhosts; hi++ ){
					Hp = hostlist->hl_List[hi];
					op = Hp->h_op;
					if( Hp->h_op == OP_OR )
						break;
				}
				if( op != OP_OR )
					break;
				Verbose("[%d/%d] |=> found OR.\n",hi,nhosts);
				continue;
			}
		}
		if( op == OP_OR ){
			if( isin ){
				Verbose("[%d] |=> OR 1 succeed, break\n",hi);
				break;
			}else{
				Verbose("[%d] |=> OR 0 ineffective, cont.\n",hi);
				continue;
			}
		}
		if( op == OP_NEG ){
			isin = !isin;
			Verbose("[%d/%d] !=> %d NEGATE\n",hi,nhosts,isin);
			continue;
		}

		vdom1 = Hp->h_vdomain;
		if( vdom == 0 && vdom1 != 0
		 || vdom != 0 && vdom1 == 0
		 || vdom != 0 && vdom1 != 0 && !streq(vdom,vdom1) )
			continue;

		if( isin && (op == ON_EQ || op == ON_NEQ) ||
		   !isin && (op ==OFF_EQ || op==OFF_NEQ) ){
			/* nothing will happen */
			continue;
		}
		match = 0;

		if( *Hp->h_name == '-' && strneq(Hp->h_name,"--expire.",9) ){
			exp = atoi(Hp->h_name+9);
			continue;
		}
		if( byagent || Hp->h_type == HT_BYAGENT ){
			match = strstr(ClientAgent,Hp->h_name) != 0;
			Verbose("User-Agent: %s ==> %d\n",Hp->h_name,match);
			hostname = ClientAgent;
			goto ACCUM;
		}
		if( Hp->h_type & (HT_IPV4|HT_IPV6) ){
			if( AddrEQ((*Vaddr),AddrNull) ){
				continue;
			}

			Verbose("[%d/%d] %s.%s %s[%s]=%s\n",
				hi,nhosts,(Hp->h_type&HT_IPV6)?"_6":"_4",
				Hp->h_name,cname,inAddr(Vaddr),
				isV6(Vaddr)?"V6":"V4"
			);

			if( (Hp->h_type & HT_IPV4) &&  isV6(Vaddr) ){
				continue;
			}else
			if( (Hp->h_type & HT_IPV6) && !isV6(Vaddr) ){
				continue;
			}
		}

		mask = Hp->h_mask;
		hostpat = Hp->h_name;

		domhost = 0;
		if( hostpat[0] == '*' && hostpat[1] == '.' )
			domhost = hostpat + 2;

		if( Hp->h_asis && alias )
			hostname = alias;
		else	hostname = cname;

		if( Hp->h_listid ){
			int listid = Hp->h_listid;
			if( HL_MAXDEPTH < lev ){
				sv1log("ERROR: HostList too deep (%d): %s\n",
					lev,hostlist->hl_what);
				return 0;
			}
			match = VA_hostIsinListX(ctx,hostListTab.ht_list[listid],
				proto,scname,salias,Vaddr,username,ac,av,lev+1);
				/*
				proto,scname,salias,Vaddr,username,0,NULL,lev+1);
				 * 9.9.8 to enable user in HOSTLIST="N:user@H"
				 * 8.0.6 "0,NULL" just for backward equiv.?
				 */
			Verbose("[%d/%d] HOSTLIST[%d]:%s(%s) -> %d\n",hi,nhosts,
				listid,Hp->h_name,hostListName(listid),match);
			goto USERPORT;
		}
		if( TimePeriod(hostpat) ){
			match = matchTimePeriod(hostpat+3,mask.I3);
			Verbose("[%d/%d] TimePeriod = %s / %d = %d\n",
				hi,nhosts,hostpat,mask.I3,match);
			goto ACCUM;
		}
		if( strcaseeq(hostpat,"--self") ){
			/* generated woking as a gateway */
			match = fromSelf;
			goto ACCUM;
		}

		if( strncaseeq(hostpat,"_mx",3) ){
			CStr(mx,MaxHostNameLen);
			sprintf(mx,"-MX.%s",hostname);
			match = hostIsResolvable(mx);
			Verbose("[%d/%d] _MX ? %s\n",hi,nhosts,mx);
			goto ACCUM;
		}
		if( strtailstr(hostpat,".mac.list.-")
		 || strtailstr(hostpat,".ip4.list.-")
		 || strtailstr(hostpat,".ip6.list.-")
		 || strtailstr(hostpat,".ima.list.-")
		){
			match = addrGroup(hostpat,hostname,&hosti);
			goto ACCUM;
		}
		if( HostOnClientside(hostpat) ){
			Verbose("[%d/%d] -C (ClientHost) = %s\n",hi,nhosts,
				inAddr(&ClientsideHost));
			default_netmask(&mask,&ClientsideHost);
			AddrAND(chost,mask,ClientsideHost);
		}else
		if( HostOutgoingIF(hostpat) ){
			VAddr ohost;
			if( AddrInvalid(hosti) ){
				chost = hosti; /* any different from hosti */
				chost.I3 = ~chost.I3;
				ohost = chost;
				mask = AddrNull;
			}else{
				default_netmask(&mask,&hosti);
				VA_hostIFto(&hosti,&mask,&ohost);
				AddrAND(chost,ohost,mask);
			}
			Verbose("[%d/%d] .o (OutgoingIF) = %s -> %s\n",hi,nhosts,
				inAddr(&ohost),inAddr(&hosti));
		}else
		if( Hp->h_type & HT_CLIF ){
			Verbose("[%d/%d] -P (IncomingIFX) = %s\n",hi,nhosts,
				inAddr(&ClientSockHost));
			default_netmask(&mask,&ClientSockHost);
			if( !AddrEQ(Hp->h_Addr,AddrZero) ){
				AddrAND(chost,mask,Hp->h_Addr);
			}else
			AddrAND(chost,mask,ClientSockHost);
			/*
			 * -P<port> alwayes checks if the incomming port is
			 * -P<port>, unconditionally on what host is tested
			 */
			hosti = ClientSockHost;
			hostname = ClientSockHost.a_name;
			portnum = ClientSockHost.a_port;
		}else
		if( Hp->h_type & HT_RIDPEER ){
			if( (RidentPeer.a_flags & VA_REMOTE) == 0 )
				continue;
			AddrAND(chost,mask,Hp->h_Addr);
			if( (RidentPeer.a_flags & VA_RSLVED) == 0 ){
				VA_resolv(&RidentPeer);
			}
			hosti = RidentPeer;
			hostname = RidentPeer.a_name;
			portnum = RidentPeer.a_port;
			sv1log("[%d/%d] -R/%s (RIDENT) = %s/%s\n",hi,nhosts,
				hostpat,hostname,inAddr(&RidentPeer));
		}else
		if( HostIncomingIF(hostpat) ){
			Verbose("[%d/%d] .i (IncomingIF) = %s\n",hi,nhosts,
				inAddr(&ClientSockHost));
			if( AddrInvalid(ClientSockHost) ){
				/* 9.9.4 should not match with undef. value */
				syslog_DEBUG("##IncomingIF N/A: %s\n",
					hostlist->hl_what);
				continue;
			}
			default_netmask(&mask,&ClientSockHost);
			AddrAND(chost,mask,ClientSockHost);
		}else	AddrAND(chost,mask,Hp->h_Addr);
		AddrAND(ahost,hosti,mask);

		/*
		if( byauth ){
		*/
		if( byauth && (Hp->h_type&HT_CLIF)==0 ){
			goto AUTHMATCH;
		}
		if( (Hp->h_type & HT_BYFILE) != 0 ){
			match = matchHostSetX(hostpat,&ahost,&hosti,&mask,exp);
			Verbose("[%d/%d] ADDRMAP BY FILE: %s %c= %s -> %d\n",
				hi,nhosts,hostname,opsyms[op],hostpat,match);
			goto ACCUM;
		}
		if( (Hp->h_type & HT_BYHOST) == 0 ){
			goto EXIT_BYHOST;
		}
		if( CantResolve(hostpat) || (Hp->h_type & HT_UNKNOWN) ){
			match = notResolvable(&hosti,hostname);
			Verbose("UNRESOLVABLE=%d: %s\n",match,hostname);
		}else
		if( HostUnknown(hostpat) && notResolved(&hosti,hostname) ){
			Verbose("UNKNOWN HOST\n");
			match = 1;
		}else
		if( domhost && HostMatchExactly(domhost,hostname) ){
			Verbose("[%d/%d] HOST==DOMAIN MATCH: %s %c= %s ?\n",
				hi,nhosts,hostname,opsyms[op],hostpat);
			match = 1;
		}else
		if( HostMatchExactly(hostpat,hostname) ){
			Verbose("[%d/%d] EXACT NAME MATCH: %s %c= %s ?\n",
				hi,nhosts,hostname,opsyms[op],hostpat);
			match = 1;
		}else
		if( !AddrEQ(ahost,AddrZero) && !AddrEQ(chost,AddrZero) ){
			Verbose("[%d/%d] ADDR MATCH: %s %c= %s ?\n",hi,nhosts,
				inAddr(&ahost),opsyms[op],inAddr(&chost));
			match = AddrEQ(ahost,chost);
		}else
		if( !AddrEQ(ahost,AddrZero) && Hp->ranges[0].h_high ){
			Verbose("[%d/%d] ADDR RANGE: %s[%s] %c= %s ?\n",hi,nhosts,
				hostname,inAddr(&ahost),opsyms[op],hostpat);
			match = match_addrrange(Hp,&ahost);
		}else
		if( !match ){
			Verbose("[%d/%d] REGEXP NAME MATCHING: %s %c= %s ?\n",
				hi,nhosts,hostname,opsyms[op],hostpat);
			match = rexpmatch(hostpat,hostname)
		     		|| streq(hostpat,hostname);

			if( !match )
			if( hostname != alias )
			if( alias != NULL )
			if( !strcaseeq(alias,cname) ){
				Verbose("[%d/%d] ALIAS MATCHING: %s %c= %s ?\n",
					hi,nhosts,alias,opsyms[op],hostpat);
				match = rexpmatch(hostpat,alias)
					|| strcaseeq(hostpat,alias);

				if( !match )
				if( domhost )
					match = strcaseeq(domhost,alias);
			}
		}
USERPORT:
		if( match && Hp->h_proto ){
			if( proto != ANYP && !matchProto(Hp->h_proto,proto) ){
				Verbose("--> proto name unmatch: %s\n",proto);
				match = 0;
			}
		}
		if( match && Hp->h_port ){
			if( portnum && !matchPort(Hp->h_port,portnum) ){
				Verbose("--> port num. unmatch: %d\n",portnum);
				match = 0;
			}
		}
		if( match && Hp->h_user ){
			if( username == 0 )
				username = "?";
			if( !matchUser(Hp->h_user,Hp->h_userRexp,username) ){
				Verbose("--> user name unmatch: %s\n",username);
				match = 0;
			}
		}

EXIT_BYHOST:
		/*
		if( !match && Hp->h_user
		*/
		if( !match && HT_BYUSER(Hp) && ac <= 0
		 && username && streq(username,hostmatch_ignauth) ){
			/* postpone matching until auth. info. is got.
			 * "hostmatch_ignauth" might be replaced with "ac == 0"
			 */
			match = 1;
		}else
		/*
		 * + /u,hostList ... byauth
		 * + user@host
		 * + -a/authhost
		 * + -c/domain
		 *
		if( !match && (byauth || Hp->h_user) && 0 < ac ){
		*/
		if( !match && (byauth || HT_BYUSER(Hp)) && 0 < ac ){
			int ai;
			AuthInfo *ap;
		AUTHMATCH:
			for( ai = 0; ai < ac; ai++ ){
				int type;
				ap = av[ai];
				if( ap->i_stat & AUTH_SET )
					type = HT_BYAUTH;
				else	type = HT_BYCERT;
				if( (Hp->h_type & type) == 0 ){
					continue;
				}

				if( Hp->h_user )
				match = matchUser(Hp->h_user,Hp->h_userRexp,ap->i_user);
				else	match = 1;
				if( match ){
					match = streq(hostpat,ap->i_Host)
					     || rexpmatch(hostpat,ap->i_Host)
					     || hostcmp(hostpat,ap->i_Host) == 0 ;
				}
				if( match && Hp->h_port && 0 < ap->i_Port )
				if( !matchPort(Hp->h_port,ap->i_Port) ){
					Verbose("--> port num. unmatch: %d\n",
						ap->i_Port);
					match = 0;
				}
				Verbose("#### AUTHMATCH %s@%s --> %d\n",
					ap->i_user,ap->i_Host,match);
				if( match )
					break;
			}
		}

ACCUM:
		if( match && op == ON_EQ  || !match && op == ON_NEQ )
			do_onoff = DO_ON;
		else
		if( match && op == OFF_EQ || !match && op == OFF_NEQ )
			do_onoff = DO_OFF;
		else	do_onoff = DO_NOP;

		switch( do_onoff ){
			case DO_ON:	isin = 1; break;
			case DO_OFF:	isin = 0; break;
		}
		Verbose("[%d/%d] ==> %d (%s %s)\n",
			hi,nhosts,isin,hostlist->hl_what,hostname);
	}
	return isin ? hi : 0;
}
int CTX_hostIsinListX(void*ctx,HostList *hostlist,PCStr(proto),PCStr(hostname),int portnum,PCStr(username),int ac,AuthInfo *av[]);
static int VA_hostIsinList(HostList *hostlist,PCStr(proto),PCStr(cname),PCStr(alias),VAddr *Vaddr,PCStr(username),int lev)
{
	return
	VA_hostIsinListX(0,hostlist,proto,cname,alias,Vaddr,username,0,NULL,lev);
}
int hostIsinList(HostList *hostlist,PCStr(proto),PCStr(hostname),int portnum,PCStr(username))
{
	return CTX_hostIsinListX(0,hostlist,proto,hostname,portnum,username,0,NULL);
}
int CTX_hostIsinListX(void*ctx,HostList *hostlist,PCStr(proto),PCStr(hostname),int portnum,PCStr(username),int ac,AuthInfo *av[])
{	VAddr Vaddr;
	const char *vdom;
	CStr(vdomb,MaxHostNameLen);
	CStr(hostnameb,512);
	const char *rhostname;
	const char *vhost;
	CStr(primaryname,512);
	VAddr Vaddrasis;

	if( vdom = scanVdomain(hostname,AVStr(hostnameb),AVStr(vdomb)) )
		rhostname = hostnameb;
	else	rhostname = hostname;

	if( hostname[0] == '-' && !isMYSELF(hostname) ){
		vhost = hostname + 1;
		hostname += 1;
		VA_strtoVAddr(hostname,&Vaddr); /* AddrNull is set for non addr */
		/*
		Vaddr = AddrNull;
		*/
	}else
	if( (hostlist->hl_flags & HL_BYNAMEONLY) && !isMYSELF(hostname) ){
		vhost = hostname;
		VA_strtoVAddr(hostname,&Vaddr);
	}else{
		vhost = rhostname;
		primaryname[0] = 0;
		VA_gethostVAddr(0,rhostname,AVStr(primaryname),&Vaddr);

		if( hostlist->hl_flags & HL_BYADDR )
		if( VA_strtoVAddr(rhostname,&Vaddrasis) ){
			Vaddr.a_ints = Vaddrasis.a_ints;
		}
		if( lADDRMATCH() ) /* -EHa option */
		if( VSA_strisaddr(rhostname) ){
			/* 9.9.6 inconsistent resolution with/without cache */
			sv1log("## %s => %s => %s\n",rhostname,primaryname,
				inAddr(&Vaddr));
			dumpHostCache(curLogFp());
			if( VA_strtoVAddr(rhostname,&Vaddrasis) )
			if( !AddrEQ(Vaddr,Vaddrasis) ){
				sv1log("## %s => %s => %s/ignored\n",
					rhostname,primaryname,inAddr(&Vaddr));
				Vaddr.a_ints = Vaddrasis.a_ints;
			}
		}
		if( primaryname[0] ){
			hostname = primaryname;
			if( vdom ) strcat(primaryname,vdom);
		}
	}
	Vaddr.a_port = portnum;
	return VA_hostIsinListX(ctx,hostlist,proto,hostname,vhost,&Vaddr,username,ac,av,0);
	/*
	return VA_hostIsinList(hostlist,proto,hostname,vhost,&Vaddr,username,0);
	*/
}
int isinHOSTLIST(PCStr(lname),PCStr(proto),PCStr(host),int port,PCStr(user)){
	int listid;
	int match = 0;
	HostList *HL;

	listid = strid(hostListTabHash,lname,-1);
	if( 0 < listid ){
		HL = hostListTab.ht_list[listid];
		match = hostIsinList(HL,proto,host,port,user);
	}else{
		return -1;
	}
	return match;
}
void pathIsinList(HostList *hostlist,char *path[])
{
}

static scanListFunc addUSER1(PCStr(user),int mac,const char *uv[],int *uc)
{
	if( mac <= *uc ){
		return -1;
	}
	uv[*uc] = user;
	*uc += 1;
	return 0;
}
static scanListFunc addStrVec1(PCStr(str),int mac,const char *sv[],int *sc)
{
	if( mac <= *sc ){
		return -1;
	}
	sv[*sc] = str;
	*sc += 1;
	return 0;
}

static int scan_addrrange(Host *Hp,PCStr(addr))
{	CStr(abuf,128);
	const char *ap;
	const char *dp;
	int ai,iaddr,lo,hi;

	strcpy(abuf,addr);
	ap = abuf;
	for( ai = 0; ai < 4;  ){
		if( dp = strchr(ap,'.') ){
			truncVStr(dp); dp++;
		}
		if( *ap == '[' ){
			if( sscanf(ap+1,"%d-%d",&lo,&hi) != 2 )
				goto error;
		}else	lo = hi = atoi(ap);

		Hp->ranges[ai].h_low = lo;
		Hp->ranges[ai].h_high = hi;
		ai++;
		if( dp == 0 )
			break;
		else	ap = dp;
	}
	for(; ai < 4; ai++ ){
		Hp->ranges[ai].h_low = 0;
		Hp->ranges[ai].h_high  = 255;
	}
	return 0;
error:
	sv1log("ERROR address range syntax: %s\n",addr);
	return -1;
}

static scanListFunc addHL1(PCStr(hostmask),HostList *hostlist,int op,PCStr(users))
{	CStr(op_hostmask,2048);

	if( users )
		sprintf(op_hostmask,"%c%s@%s",op,users,hostmask);
	else	sprintf(op_hostmask,"%c%s",op,hostmask);
	addHostList1(op_hostmask,hostlist);
	return 0;
}
static const char *hostpart(PCStr(hostmask),int split)
{	const char *dp;

	if( dp = strchr(hostmask,'@') )
	if( dp == hostmask || dp[-1] != '/' ){ /* NOT host/@Cn */
		if( split )
			truncVStr(dp);
		return dp + 1;
	}
	return 0;
}

static int addHL(PCStr(hostmask),HostList *hostlist)
{	CStr(list,2048);
	const char *dp;
	int op;
	const char *hosts;
	const char *users;

	if( strchr(opsyms,*hostmask) )
		op = *hostmask++;
	else	op = '+';
	strcpy(list,hostmask);

	if( dp = hostpart(list,1) ){
		hosts = dp;
		users = list;
	}else{
		hosts = list;
		users = 0;
	}

/*
	if( streq(hosts,".localnet") ){
		strcpy(list,DELEGATE_LOCALNET);
		hosts = list;
	}else
*/
	if( *hosts != '{' )
		return 0;
	if( strtailchr(hosts) != '}' ){
		sv1log("ERROR ignored malformed list: %s\n",hostmask);
		return 0;
	}

	Verbose("addHL: %c [ %s ] @ [ %s ]\n",op,users?users:"*",hosts);
	scan_commaListL(hosts,0,scanListCall addHL1,hostlist,op,users);
	return 1;
}

void makeHost(HostList *hostlist,Host *Hp,int lev,PCStr(hostmask));
scanListFunc addHostList1(PCStr(hostmask),HostList *hostlist)
{	int idx,siz,nsiz;
	Host *Hp,**oHlist,**nHlist;

	if( strcmp(hostmask,hostmatch_asisaddr) == 0 ){
		hostlist->hl_flags |= HL_BYADDR;
		return 0;
	}
	if( strcmp(hostmask,hostmatch_withauth) == 0 ){
		hostlist->hl_flags |= HL_BYAUTH;
		return 0;
	}
	if( strcmp(hostmask,hostmatch_exrandom) == 0 ){
		hostlist->hl_flags |= HL_XRANDOM;
		return 0;
	}
	if( hostmask[0] == '!' && hostmask[1] == '!' )
		hostmask += 2;
	if( hostmask[0] == '+' && hostmask[1] == '!' )
		hostmask += 1;
	if( addHL(hostmask,hostlist) )
		return 0;
	if( hostlist->hl_cnt == 0 && *hostmask == '!' )
		if( strcmp(hostmask,"!*") != 0 )
		addHostList1("*",hostlist);

	Hp = NewStruct(Host);
	idx = ++hostlist->hl_cnt;
	siz = hostlist->hl_size;
	if( siz <= idx ){
		oHlist = hostlist->hl_List;
		if( hostlist->hl_inc )
			nsiz = siz + hostlist->hl_inc;
		else	nsiz = siz + HL_INCSIZE;
		while( nsiz <= idx )
			nsiz++;
		hostlist->hl_size = nsiz;
		if( oHlist == (Host**)0 )
			nHlist = (Host**)calloc(nsiz,sizeof(Host*));
		else	nHlist = (Host**)realloc(oHlist,nsiz*sizeof(Host*));
		hostlist->hl_List = nHlist;
	}
	hostlist->hl_List[idx] = Hp;
	makeHost(hostlist,Hp,0,hostmask);
	return 0;
}

void canonWildcardAddr(PVStr(hostname))
{	const char *hp;
	char ch;
	int noct,octv,olen,isdg;

	if( strchr(hostname,'*') && strchr(hostname,'.') ){
		CStr(addr,128);
		refQStr(ap,addr); /**/
		hp = hostname;
		noct = 0;

		while( *hp ){
			CStr(buff,128);
			refQStr(bp,buff); /**/
			const char *xp;
			xp = &buff[sizeof(buff)-1];
			isdg = 1;
			while( ch = *hp ){
				if( xp <= bp )
					break;
				hp++;
				setVStrPtrInc(bp,ch);
				if( ch == '.' ) 
					break;
				if( !isdigit(ch) )
					isdg = 0;
			}
			setVStrEnd(bp,0);

			if( buff[0]=='*' && (buff[1]==0||buff[1]=='.') ){
				sprintf(ap,"[0-255]%c",buff[1]);
			}else
			if( isdigit(buff[0]) && isdg ){
				octv = atoi(buff);
				if( octv < 0 || 255 < octv )
					goto NOTADDR;
				strcpy(ap,buff);
			}else	goto NOTADDR;
			ap += strlen(ap);

			noct++;
			if( 4 <= noct && *hp != 0 )
				goto NOTADDR;
		}
		if( 2 <= noct && noct <= 4 ){
			XsetVStrEnd(QVStr(ap,addr),0);
			strcpy(hostname,addr);
		}
	} NOTADDR:;
}

static int isnetmasklen(PCStr(mask))
{	int masklen;

	if( isdigit(mask[0]) && mask[1] == 0
	 || isdigit(mask[0]) && isdigit(mask[1]) && mask[2] == 0 ){
		masklen = atoi(mask);
		if( 1 <= masklen && masklen <= 31 )
			return masklen;
	}
	return 0;
}

void makeHost(HostList *hostlist,Host *Hp,int lev,PCStr(hostmask))
{	const char *mp;
	CStr(hostnameb,1024);
	CStr(primaryname,512);
	VAddr addr,mask;
	int submask,mask1;
	CStr(proto,256);
	CStr(hostmaskb,1024);
	CStr(hostmaskb2,1024);
	CStr(vdomain,MaxHostNameLen);
	const char *route;
	int listid;

	init_hostListTab();

	proto[0] = 0;
	if( strstr(hostmask,"://") ){
		Xsscanf(hostmask,"%[^:]://%s",AVStr(proto),AVStr(hostmaskb));
		hostmask = hostmaskb;
	}
	if( route = strstr(hostmask,"//") ){
		truncVStr(route);
		Hp->h_route = (Host*)calloc(sizeof(Host),1);
		makeHost(hostlist,Hp->h_route,lev+1,route+2);
	}

	if( hostmask[0] == '&' && hostmask[1] == 0 ){
		Hp->h_op = OP_AND;
		return;
	}
	if( hostmask[0] == '|' && hostmask[1] == 0 ){
		Hp->h_op = OP_OR;
		return;
	}
	if( hostmask[0] == '!' && hostmask[1] == 0 ){
		Hp->h_op = OP_NEG;
		return;
	}

	if( hostmask[0] == '!' && hostmask[1] == '!' )
		hostmask += 2;

	if( *hostmask == '!' ){ Hp->h_op = OFF_EQ;  hostmask++; }else
/*
	if( *hostmask == '!' ){ Hp->h_op = ON_NEQ;  hostmask++; }else
	if( *hostmask == '?' ){ Hp->h_op = OFF_NEQ; hostmask++; }else
	if( *hostmask == '-' ){ Hp->h_op = OFF_EQ;  hostmask++; }else
*/
			      { Hp->h_op = ON_EQ;
				if(*hostmask=='+')  hostmask++; }

	vdomain[0] = 0;
	if( scanVdomain(hostmask,AVStr(hostmaskb2),AVStr(vdomain)) )
		hostmask = hostmaskb2;

	if( *hostmask == '-' ){
		int mtype = 0;
		const char *dp;
		for( dp = hostmask+1; *dp; dp += 2 ){
			if( strneq(dp,"*/",2) ) mtype |= HT_BYANY; else
			if( strneq(dp,"R/",2) ) mtype |= HT_RIDPEER; else
			if( strneq(dp,"U/",2) ) mtype |= HT_UNKNOWN; else
			if( strneq(dp,"A/",2) ) mtype |= HT_BYAGENT; else
			if( strneq(dp,"a/",2) ) mtype |= HT_BYAUTH; else
			if( strneq(dp,"c/",2) ) mtype |= HT_BYCERT; else
			if( strneq(dp,"h/",2) ) mtype |= HT_BYHOST; else break;
		}
		if( mtype ){
			hostmask = dp;
			Hp->h_type |= mtype;
		}
	}

	if( (hostlist->hl_flags & HL_BYAGENT) || (Hp->h_type & HT_BYAGENT) ){
		Hp->h_name = StrAlloc(hostmask);
		return;
	}

	mask = MaskZero;
	if( mp = strchr(hostmask,'/') ){
		truncVStr(mp); mp++;
		if( TimePeriod(hostmask) ){
			mask.I3 = atoi(mp);
		}else
		if( submask = isnetmasklen(mp) ){
			mask.I3 = 0xFFFFFFFF << (32-submask);
		}else
		if( strcmp(mp,".") == 0 ){
			mask.I3 = HEURISTIC_MASK;
		}else
		if( strchr(mp,'.') ) /* address in dot-notaion */
			VA_strtoVAddr(mp,&mask);
		else
		if( VSA_strisaddr(mp) ){
			VA_strtoVAddr(mp,&mask);
		}else
		if( mp[0] == '@' ){
			switch( mp[1] ){
			    case 'A': mask1 = 0xFF000000; break;
			    case 'B': mask1 = 0xFFFF0000; break;
			    case 'C': mask1 = 0xFFFFFF00; break;
			    default:  mask1 = CLASS_MASK; break;
			}
			mask.I3 = mask1;
			if( submask = atoi(&mp[2]) )
				mask.I3 = mask.I3 >> submask;
		}else{
			sscanf(mp,"%x",&mask.I3);
		}
	}else{
		mask.I0 = 0xFFFFFFFF;
		mask.I1 = 0xFFFFFFFF;
		mask.I2 = 0xFFFFFFFF;
		mask.I3 = 0xFFFFFFFF;
	}
	Hp->h_mask = mask;

	strcpy(hostnameb,hostmask);

	if( streq(hostmask,".") ){
		CStr(me,128);
		GetHostname(AVStr(me),sizeof(me));
		strcpy(hostnameb,me);
	}

	{	const char *dp;
		const char *uv[128]; /**/
		CStr(users,2048);
		int ui;

		if( dp = strchr(hostnameb,'@') ){
			if( hostnameb[0] == '{' ){
				const char *pp;
				strcpy(users,hostnameb+1);
				if( pp = strchr(users,'}') )
					truncVStr(pp);
				else	*strchr(users,'@') = 0;
			}else{
				strcpy(users,hostnameb);
				*strchr(users,'@') = 0;
			}
			ui = 0;
			scan_commaList(users,2,scanListCall addUSER1,elnumof(uv),uv,&ui);
			uv[ui] = 0;
			Hp->h_user = dupv(uv,0);
			Hp->h_userRexp = (const char**)makeUserRexp(ui,uv);

			strcpy(hostnameb,dp+1);

			if( (Hp->h_type&HT_BYANY)==0 || (Hp->h_type&HT_BYHOST) )
			if( !hostlist->hl_noIdent )
			if( hostnameb[0] != '!' )
				enableClientIdent(hostnameb);

			if( hostnameb[0] == '!' ){
				ovstrcpy(hostnameb,hostnameb+1);
				if( Hp->h_op == ON_EQ )
					Hp->h_op = OFF_EQ;
				else	Hp->h_op = ON_EQ;
			}
			/* USER part of USER@!host should be ignored ?? */
		}

		/* if no explicit "-I/" prefixed */
		if( (Hp->h_type & HT_BYANY) == 0 ){
			if( Hp->h_user == 0 )
				Hp->h_type |= HT_BYHOST;
			else	Hp->h_type |= HT_BYANY;
		}
	}
	if( HostIncomingIFX(hostnameb) ){
		if( hostnameb[2] && strchr(hostnameb+2,':') == 0 ){
			Strins(QVStr(hostnameb+2,hostnameb),"*:"); /* -Pnum -> -P*:num */
		}
	}
	{	const char *dp;
		const char *pv[128]; /**/
		CStr(ports,2048);
		int pi;

		/*
		if( dp = strchr(hostnameb,':') ){
			truncVStr(dp); dp++;
		*/
		if( (dp = strchr(hostnameb,':'))
		 || (dp = strstr(hostnameb,".."))&&(isdigit(dp[2])||dp[2]=='{')
		){
			if( *dp == ':' ){
				truncVStr(dp);
				dp++;
			}else{
				truncVStr(dp);
				dp += 2;
			}
			strcpy(ports,dp);
			pi = 0;
			scan_commaList(ports,2,scanListCall addStrVec1,elnumof(pv),pv,&pi);
			pv[pi] = 0;
			Hp->h_port = dupv(pv,0);
		}
	}
	if( proto[0] != 0 ){
		const char *pv[128]; /**/
		CStr(protos,2048);
		int pi;

		pi = 0;
		strcpy(protos,proto);
		scan_commaList(protos,2,scanListCall addStrVec1,elnumof(pv),pv,&pi);
		pv[pi] = 0;
		Hp->h_proto = dupv(pv,0);
	}

	primaryname[0] = 0;
	canonWildcardAddr(AVStr(hostnameb));

	if( hostnameb[0] == '_' )
	if( hostnameb[1] == '4' || hostnameb[1] == '6' )
	if( hostnameb[2] == '.' || hostnameb[2] == 0 )
	{
		if( hostnameb[1] == '4' )
			Hp->h_type |= HT_IPV4;
		else	Hp->h_type |= HT_IPV6;
		if( hostnameb[2] == 0 )
			strcpy(hostnameb,"*");
		else	ovstrcpy(hostnameb,hostnameb+3);
	}

	if( strneq(hostnameb,"--expire.",9) ){
	}else
	if( 0 < (listid = strid(hostListTabHash,hostnameb,-1)) ){
		Verbose("%s[%d]: %c HOSTLIST[%d]:%s(%s)\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],listid,hostnameb,hostListName(listid));
		Hp->h_listid = listid;
	}else
	if( HostOnClientside(hostnameb) ){
		Verbose("%s[%d]: %c (ClientHost) = -C / %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],inAddr(&Hp->h_mask));
	}else
	if( HostIncomingIFX(hostnameb) ){
		ovstrcpy(hostnameb,hostnameb+2);
		Verbose("%s[%d]: %c (IncomingIFX) = -P%s / %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb,inAddr(&Hp->h_mask));
		Hp->h_type |= HT_CLIF;

		if( strchr(hostnameb,'*') == 0 )
		if( VA_strtoVAddr(hostnameb,&addr) ){
			Hp->h_Addr = addr;
		}
	}else
	if( HostIncomingIF(hostnameb) ){
		Verbose("%s[%d]: %c (IncomingIF) = %s / %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb,inAddr(&Hp->h_mask));
	}else
	if( HostOutgoingIF(hostnameb) ){
		Verbose("%s[%d]: %c (OutgoingIF) = %s / %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb,inAddr(&Hp->h_mask));
	}else
	if( TimePeriod(hostnameb) ){
		Verbose("%s[%d]: %c (TimePeriod) = %s / %d\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb,Hp->h_mask.I3);
	}else
	if( hostnameb[0] == '-' && !isMYSELF(hostnameb) ){
		Verbose("%s[%d]: %c %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op], hostnameb);
		if( VA_strtoVAddr(hostnameb+1,&addr) )
			Hp->h_Addr = addr;
		else
		if( hostlist->hl_flags & HL_BYNAMEONLY ){
			Hp->h_asis = 1;
			ovstrcpy(hostnameb,hostnameb+1);
			if( hostlist != virtualHosts )
				addHostList1(hostnameb,virtualHosts);
		}
		else{
			Hp->h_asis = 1;

			if( hostlist->hl_what != LexHosts )
				addHostList1(hostnameb,lexHosts);

			ovstrcpy(hostnameb,hostnameb+1);
			if( strchr(hostnameb,'*') ){
				sv1log("Host Name Pattern: '%s'\n",hostnameb);
			}else
			/* to suppress resolution on reload which will
			 * always result in 'unknown' */
			if( !VA_gethostVAddr(0,hostnameb,AVStr(primaryname),NULL) ){
				sv1log("Virtual Host Name: '%s'\n",hostnameb);
				sethostcache_predef(hostnameb,NULL,0,0);
			}
		}
	}else
	if( hostnameb[0] == '_' && hostnameb[1] == '_' ){
		ovstrcpy(hostnameb,hostnameb+2);
		Verbose("%s[%d]: %c HostSet[%s]\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb);
		Hp->h_type |= HT_BYFILE;
	}else
	if( strchr(hostnameb,'[') ){
		if( scan_addrrange(Hp,hostnameb) == 0 )
		Verbose("%s[%d]: %c %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op],hostnameb);
	}else
	if( strchr(hostnameb,'*') || streq(hostnameb,"?") ){
		Verbose("%s[%d]: %c %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op], hostnameb);
	}else
	if( strtailstr(hostnameb,".-") ){ /* "-.-" and "odst.-" */
		Verbose("%s[%d]: %c %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op], hostnameb);
	}else
	if( hostlist->hl_flags & HL_BYNAMEONLY ){
		Hp->h_asis = 1;
		if( hostlist != virtualHosts )
			addHostList1(hostnameb,virtualHosts);
	}else
	if( !VA_gethostVAddr(0,hostnameb,AVStr(primaryname),&addr) ){
		sv1log("ERROR %s[%d] %s ? unknown\n",
			hostlist->hl_what,hostlist->hl_cnt, hostnameb);
	}else{
		if( primaryname[0] )
			strcpy(hostnameb,primaryname);
		Hp->h_Addr = addr;
		default_netmask(&Hp->h_mask,&addr);

		Verbose("%s[%d]: %c %s = %s / %s\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op], hostnameb,
			inAddr(&addr),inAddr(&Hp->h_mask));
		/*
		Verbose("%s[%d]: %c %s = %x / %x\n",
			hostlist->hl_what,hostlist->hl_cnt,
			opsyms[Hp->h_op], hostnameb,
			addr.I3,Hp->h_mask.I3);
		*/
	}

	Hp->h_name = StrAlloc(hostnameb);
	Hp->h_vdomain = vdomain[0] ? StrAlloc(vdomain) : 0;
}


/*
 * A name/address to be compared its identity only with its lexical
 * representation without resolved (possibly unified) name/address.
 * When a host is referred as such one (prefixed with "-" like "-host"
 * or "-10.0.0.1"), it should be compared lexically anytime.
 */
int hostcmp_lexical(PCStr(h1),PCStr(h2),int cacheonly)
{
	/*
	if( VA_hostIsinList(lexHosts,"*",h1,h1,&AddrNull,"",0) )
	if( VA_hostIsinList(lexHosts,"*",h2,h2,&AddrNull,"",0) ){
	*/
	if( virtualHosts->hl_cnt )
	if( VA_hostIsinList(virtualHosts,"*",h1,h1,&AddrNull,"",0)
	 || VA_hostIsinList(virtualHosts,"*",h2,h2,&AddrNull,"",0)
	){
		return strcasecmp(h1,h2);
	}
	if( VA_hostIsinList(lexHosts,"*",h1,h1,&AddrNull,"",0)
	 || VA_hostIsinList(lexHosts,"*",h2,h2,&AddrNull,"",0)
	){
		return strcasecmp(h1,h2);
	}
	if( cacheonly )
		return hostcmp_incache(h1,h2);
	else	return hostcmp(h1,h2);
}

typedef struct {
  const	char	 *name;
  const	char	 *path;
  const char	 *opts;
	HostList *hlist;
} PathList; 
static PathList *pathlists;
static int pathlists_siz;
static int pathlists_cnt;

int makePathListX(PCStr(what),PCStr(path),PCStr(opts));
int makePathList(PCStr(what),PCStr(path))
{
	return makePathListX(what,path,"");
}
int makePathListX(PCStr(what),PCStr(path),PCStr(opts))
{	HostList *HL;
	PathList *PL;
	int nsize,hi;

	if( pathlists_siz <= pathlists_cnt ){
		pathlists_siz += 32;
		nsize = sizeof(PathList) * pathlists_siz;
		pathlists = (PathList*)Malloc((char*)pathlists,nsize);
	}
	for( hi = 0; hi < pathlists_cnt; hi++ )
		if( strcmp(path,pathlists[hi].path) == 0 )
		if( strcmp(opts,pathlists[hi].opts) == 0 )
			return hi+1;

	HL = NewStruct(HostList);
	HL->hl_what = StrAlloc(what);
	if( strchr(opts,'n') ){
		HL->hl_flags |= HL_BYNAMEONLY;
	}

	scan_commaListL(path,0,scanListCall addHostList1,HL);

	PL = &pathlists[pathlists_cnt++];
	PL->hlist = HL;
	PL->path = StrAlloc(path);
	PL->opts = StrAlloc(opts);

	return pathlists_cnt;
}
void matchPathList(int hlid,PCStr(path))
{
}
int matchPath1(int hlid,PCStr(user),PCStr(host),int port)
{	HostList *HL;
	int match;

	/*
	if( hlid < 1 ){
	*/
	if( hlid < 1 || pathlists_cnt < hlid ){
		sv1log("##FATAL: matchPath1(%d) %s@%s:%d\n",hlid,user,host,port);
		return 0;
	}
	HL = pathlists[hlid-1].hlist;
	match = hostIsinList(HL,"*",host,port,user);
Verbose("###### matchPath1(%d,%s,%s:%d) = %d\n",hlid,user,host,port,match);
	return match;
}
unsigned int trand1(unsigned int max);
int getHostInList(int hlid,int hi,const char **host,PVStr(addr),int *port){
	HostList *HL;
	Host *Hp;

	if( hlid < 1 || pathlists_cnt < hlid ){
		return -1;
	}
	HL = pathlists[hlid-1].hlist;
	if( hi < 0 || HL->hl_cnt < hi ){
		return -1;
	}
	if( HL->hl_flags & HL_XRANDOM ){
		if( (HL->hl_flags & HL_XRANDSET) == 0 ){
			HL->hl_flags |= HL_XRANDSET;
			HL->hl_base = trand1(1024);
		}
		if( lTHREAD() )
		sv1log("RANDOM[%s] %d+%d=%d/%d\n",HL->hl_what,HL->hl_base,
			hi,(hi+HL->hl_base)%HL->hl_cnt,HL->hl_cnt);
		Hp = HL->hl_List[(hi+HL->hl_base)%HL->hl_cnt+1];
	}else	Hp = HL->hl_List[hi+1];
	if( host ) *host = Hp->h_name;
	if( addr ) strcpy(addr,inAddr(&Hp->h_Addr));
	if( port ) *port = 0;
	if( Hp->h_port && Hp->h_port[0] ){
		if( port ) *port = atoi(Hp->h_port[0]);
	}
	return 0;
}
int getHostListSize(int hlid,int *rand){
	HostList *HL;
	if( hlid < 1 || pathlists_cnt < hlid ){
		return -1;
	}
	HL = pathlists[hlid-1].hlist;
	if( rand ) *rand = HL->hl_flags & HL_XRANDOM;
	return HL->hl_cnt;
}

const char *topofPath1(int hlid,PCStr(hostport),PVStr(rbuff))
{	HostList *HL;
	Host *Hp;
	const char *host;
	const char *dp;
	CStr(hostb,128);
	VAddr va;

	va = AddrNull;
	if( strchr(hostport,':') ){
		host = hostb;
		dp = wordscanY(hostport,AVStr(hostb),sizeof(hostb),"^:");
		if( *dp == ':' )
			va.a_port = atoi(dp+1);
	}else	host = hostport;

	HL = pathlists[hlid-1].hlist;
	if( VA_hostIsinList(HL,"*",host,host,&va,"",0) )
		return (char*)hostport;

	Hp = HL->hl_List[1];
	if( Hp->h_port == 0 )
		return Hp->h_name;
	if( Hp->h_port[0] == 0 ){
		/* empty port list */
		sprintf(rbuff,"%s",Hp->h_name);
	}else
	sprintf(rbuff,"%s:%d",Hp->h_name,atoi(Hp->h_port[0]));
	return rbuff;
}
int VAtoVSA(VAddr *va,VSAddr *vsa,int port);
static int addvsa(HostList *HL,int port,int max,int ac,VSAddr va[]){
	Host *Hp;
	int hi;
	int p1;

	for( hi = 1; hi <= HL->hl_cnt; hi++ ){
		if( max <= ac )
			return ac;
		Hp = HL->hl_List[hi];
		if( Hp->h_listid ){
			int li = Hp->h_listid;
			ac += addvsa(hostListTab.ht_list[li],port,max,ac,va);
		}else{
			p1 = 0;
			if( Hp->h_port )
			if( Hp->h_port[0] == 0 ){
				/* empty port list */
			}else{
				p1 = atoi(Hp->h_port[0]);
			}
			if( p1 == 0 )
				p1 = port;
			if( VAtoVSA(&Hp->h_Addr,&va[ac],p1) ){
				ac++;
			}
		}
	}
	return ac;
}
int HL2VSA(int hlid,int port,int mac,VSAddr va[]){
	HostList *HL;
	int ac;

	if( hlid < 1 || pathlists_cnt < hlid )
		return 0;
	HL = pathlists[hlid-1].hlist;
	ac = addvsa(HL,port,mac,0,va);
	return ac;
}
