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
Program:	master.c (routing and access control)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	March94	created
	941002	merged proxy.c(created 940316)
	990824	integrated all routing tables into a single structure
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "delegate.h"
#include "hostlist.h"
#include "auth.h"
#include "url.h"
#include "filter.h"
#include "fpoll.h"
#include "proc.h"

#define MAXPROTO	64
/* protoV should be realized as a bit-map for screening ... */

#define Ident()	getClientUserC(Conn)
extern int DO_METHOD_FILTER;

typedef struct {
  const	char	 *p_name;
	int	  p_portN;
	int	 *p_portV;
	int	  p_negate;
  const	char	 *p_methods;
} Server;

typedef struct {
  const	char	 *m_gw_proto;	/* client side protocol of the gateway */
  const	char	 *m_gw_host;	/* host name of the gateway */
	int	  m_gw_port;	/* port number of the gateway */
  const	char	 *m_gw_path;	/* base path of the gateway */
	AuthInfo *m_gw_auth;
  const	char	 *m_conn;
	Server	 *m_protoV;
	int	  m_protoV_NonHTTP;
	HostList  m_hostlist[2]; /**//* should be URLs ? */
	int	  m_teleport;
	int	  m_cacheonly;
	int	  m_ConnectFlags;
  const	char	 *m_owner;
  const	char	 *m_Version;
  const	char	 *m_SERVER;
} Route;

#define RX_DST	0
#define RX_SRC	1
#define m_dsts	m_hostlist[RX_DST]
#define m_srcs	m_hostlist[RX_SRC]

#define RT_INCSIZE	16
typedef struct {
  const	char   *rt_name;
	int	rt_size;
	int	rt_filled;
	int	rt_withsrc;
	Route **rt_routes;
} RouteTab;

static RouteTab routeTabs[] = {
	{ "REMITTABLE"	},
	{ "REACHABLE"	},
	{ "RELIABLE"	},
	{ "USERIDENT"	},
	{ "CMAP"	},
	{ "PERMIT"	},
	{ "MASTER"	},
	{ "CONNECT"	},
	{ "ROUTE"	},
	{ "UCPROXY"	},
	{ "OWNER"	},
	{ "NOTIFYPLTFM"	},
	{ "SRCIF"	},
	{ "REJECT"	},
};
#define R_REMITTABLE	0	/* List of acceptable protocols */
#define R_REACHABLE	1	/* Hosts acceptable as destination */
#define R_RELIABLE	2	/* Hosts acceptable as source */
#define R_USERIDENT	3	/* Hosts with Ident */
#define R_CMAP		4	/* general CMAP */
#define R_PERMIT	5	/* acceptable proto:dst:src */
#define R_MASTER	6	/* route for master */
#define R_CONNECT	7	/* order of connection trials */
#define R_ROUTE		8	/* route for gateways */
#define R_PROXY		9	/* unconditional PROXY */
#define R_OWNER		10	/* changing process owner */
#define R_NOTIFYPLTFM	11	/* notify platform of DeleGate */
#define R_SRCIF		12	/* source address of connection */
#define R_REJECT	13	/* reject proto:dst:src */

#define RT_ROUTE(rtx)	(&routeTabs[rtx])
#define RT_INDEX(rtx)	routeTabs[rtx].rt_filled
#define RT_TABLE(rtx)	routeTabs[rtx].rt_routes

#define RemittableRoute	RT_ROUTE(R_REMITTABLE)
#define RemittableV	RT_ROUTE(R_REMITTABLE)->rt_routes[0]->m_protoV
#define Remittable	(RT_ROUTE(R_REMITTABLE)->rt_routes?RemittableV:0)

#define MasterRoute	RT_ROUTE(R_MASTER)
#define MasterX		RT_INDEX(R_MASTER)
#define Masters		RT_TABLE(R_MASTER)

#define MapRoute	RT_ROUTE(R_CMAP)
#define MapX		RT_INDEX(R_CMAP)
#define Maps		RT_TABLE(R_CMAP)

#define ForwardRoute	RT_ROUTE(R_ROUTE)
#define ForwardX	RT_INDEX(R_ROUTE)
#define Forwards	RT_TABLE(R_ROUTE)

#define PermitRoute	RT_ROUTE(R_PERMIT)
#define PermitX		RT_INDEX(R_PERMIT)
#define Permits		RT_TABLE(R_PERMIT)

#define ConnectRoute	RT_ROUTE(R_CONNECT)
#define ConnectX	RT_INDEX(R_CONNECT)
#define Connects	RT_TABLE(R_CONNECT)

#define OwnerRoute	RT_ROUTE(R_OWNER)
#define OwnerX		RT_INDEX(R_OWNER)
#define Owners		RT_TABLE(R_OWNER)

#define SrcifRoute	RT_ROUTE(R_SRCIF)
#define SrcifX		RT_INDEX(R_SRCIF)
#define Srcif		RT_TABLE(R_SRCIF)

#define RejectRoute	RT_ROUTE(R_REJECT)
#define RejectX		RT_INDEX(R_REJECT)
#define Rejects		RT_TABLE(R_REJECT)


static int newRoute(RouteTab *rt)
{	int osize,nsize,nbytes,ri,rx;
	Route **routes;

	if( rt->rt_size <= rt->rt_filled ){
		osize = rt->rt_size;
		nsize = osize + RT_INCSIZE;
		nbytes = nsize * sizeof(Route*);
		routes = (Route**)Malloc((char*)rt->rt_routes,nbytes);
		bzero(&routes[osize],(nsize-osize)*sizeof(Route*));
		rt->rt_routes = routes;
		rt->rt_size = nsize;
	}
	rx = rt->rt_filled++;
	rt->rt_routes[rx] = NewStruct(Route);
	Verbose("#### newRoute[%s] %d/%d\n",rt->rt_name,rx,rt->rt_size);
	return rx;
}

static int scanProtoPort(PCStr(protoport),PVStr(proto),PVStr(ports),PVStr(methods))
{	CStr(buf,1024);
	const char *pv[4]; /**/
	int ne;

	strcpy(buf,protoport);
	if( strchr(buf,':') )
		ne = stoV(buf,3,pv,':');
	else	ne = stoV(buf,3,pv,'/');
	setVStrEnd(methods,0);
	setVStrEnd(ports,0);
	setVStrEnd(proto,0);
	if( 1 <= ne ) strcpy(proto,pv[0]);
	if( 2 <= ne ) strcpy(ports,pv[1]);
	if( 3 <= ne ) strcpy(methods,pv[2]);
	return ne;
}
static Server *makeProtoV(Server *protoV,const char **protov)
{	int ni,np,nj,nn,nx;
	const char *proto1;
	const char *p1;
	CStr(proto,64);
	CStr(ports,1024);
	CStr(methods,512);
	int match,neg;

	for( np = 0; protov[np]; np++);
	if( protoV != NULL ){ /*this case is not used currently*/
		const char *nprotov[MAXPROTO]; /**/
		for( nx = 0; protoV[nx].p_name; nx++ );
		nn = 0;
		for( ni = 0; ni < np; ni++ ){
			p1 = protov[ni];
			match = 0;
			for( nj = 0; nj < nx; nj++ ){
				if( strcaseeq(protov[ni],protoV[nj].p_name) ){
					match = 1;
					break;
				}
			}
			if( !match ){
				if( MAXPROTO-1 <= nn )
					break;
				nprotov[nn++] = (char*)p1;
			}
		}
		if( nn == 0 )
			return protoV;
		protov = nprotov;
		np = nn;
		protoV = (Server*)realloc(protoV,sizeof(Server)*(nx+nn+1));
	}else{
		protoV = (Server*)calloc(sizeof(Server),np+1);
		nx = 0;
	}

	for( ni = 0; ni < np; ni++ ){
		proto1 = protov[ni];
		if( neg = *proto1 == '-' )
			proto1++;
		scanProtoPort(proto1,AVStr(proto),AVStr(ports),AVStr(methods));
		if( neg ){
			/* remove if in the protoV */
			continue;
		}
		protoV[nx].p_name = StrAlloc(proto);
		if( ports[0] && strcmp(ports,"*") != 0 ){
			const char *portv[MAXPROTO]; /**/
			if( ports[0] == '{' )
				ovstrcpy(ports,ports+1);
			nn = stoV(ports,MAXPROTO,portv,',');
			protoV[nx].p_portN = nn;
			protoV[nx].p_portV = (int*)calloc(sizeof(int*),nn);
			for( nj = 0; nj < nn; nj++ )
				protoV[nx].p_portV[nj] = atoi(portv[nj]);
		}
		if( methods[0] )
		{
			DO_METHOD_FILTER++;
			protoV[nx].p_methods = StrAlloc(methods);
		}
		if( !neg )
			nx++;
	}
	protoV[nx].p_name = 0;
	return protoV;
}
static void sprintProtoV(Server *protoV,PVStr(protolist))
{	int ni,nj,np;
	const char *proto1;
	refQStr(pp,protolist); /**/
	const char *mp;

	setVStrEnd(protolist,0);
	if( protoV == 0 )
		return;

	setVStrEnd(pp,0);
	for( ni = 0; proto1 = protoV[ni].p_name; ni++ ){
		if( 0 < ni )
			setVStrPtrInc(pp,',');

		strcpy(pp,proto1);
		pp += strlen(pp);

		if( np = protoV[ni].p_portN ){
			setVStrPtrInc(pp,'/');
			if( 1 < np )
				setVStrPtrInc(pp,'{');

			for( nj = 0; nj < protoV[ni].p_portN; nj++ ){
				if( 0 < nj )
					setVStrPtrInc(pp,',');
				sprintf(pp,"%d",protoV[ni].p_portV[nj]);
				pp += strlen(pp);
			}
			if( 1 < np )
				setVStrPtrInc(pp,'}');
			setVStrEnd(pp,0);
		}
		if( mp = protoV[ni].p_methods ){
			if( np == 0 ){
				setVStrPtrInc(pp,'/');
				setVStrPtrInc(pp,'*');
			}
			setVStrPtrInc(pp,'/');
			strcpy(pp,mp);
			pp += strlen(pp);
		}
	}
}
static void subProto1(char *pv[],PCStr(proto),PCStr(ports),PVStr(portb),char **portp)
{	int pi,px,match0,match;
	char *proto1; /**/
	CStr(ports1,256);
	int len;

	px = 0;
	match0 = 0;
	if( strcmp(proto,"*") == 0 || strcmp(proto,"all") == 0 )
		match0 = 1;
	len = strlen(proto);
	for( pi = 0; proto1 = pv[pi]; pi++ ){
		match = match0;
		if( strncmp(proto,proto1,len) == 0 ){
			if( proto1[len] == 0 )
				match = 1;
			else
			if( proto1[len] == '/' ){
				subSetList(&proto1[len+1],ports,AVStr(ports1));
				if( *ports1 == 0 )
					match = 1;
				else{
					Xstrcpy(QVStr(*portp,portb),proto1);
					proto1 = *portp;
					Xstrcpy(QVStr(&proto1[len+1],portb),ports1);
					*portp += strlen(proto1) + 1;
				}
			}
		}
		if( match )
			continue;
		pv[px++] = proto1;
	}
	pv[px] = 0;
}

typedef int (*icFUNCP)(const void*,...);
int foreach_eqproto(PCStr(proto),icFUNCP func,...);
static scanListFunc addProto1(PCStr(protoport),char *tv[],char *pv[],PVStr(portb),char **portp,PCStr(iproto))
{	int pi,ti,px,match0,match;
	CStr(proto,64);
	CStr(ports,256);
	CStr(protoportb,256);
	CStr(methods,512);
	const char *proto1;
	int len;

	if( strcmp(protoport,".") == 0 ){
		if( foreach_eqproto(iproto,(icFUNCP)addProto1,tv,pv,AVStr(portb),portp,iproto) )
			return 0;
	}

	scanProtoPort(protoport,AVStr(proto),AVStr(ports),AVStr(methods));

	if( proto[0] == '!' || proto[0] == '-' ){
		subProto1(pv,proto+1,ports,AVStr(portb),portp);
		return 0;
	}

	if( strcmp(proto,".") == 0 )
		strcpy(proto,iproto);

	if( strcmp(proto,"*") == 0 || strcmp(proto,"all") == 0 ){
		px = 0;
		for( ti = 0; tv[ti]; ti++ )
		{
			if( 0 <= serviceport(tv[ti]) ) /* not VPROTO */
			{
				if( MAXPROTO-1 <= px ){
					/* 9.9.4 MAXPROTO should be NSERVICES ... */
					porting_dbg("IGNORED protoList[%d][%d] %s",ti,px,tv[ti]);
				}else
				pv[px++] = tv[ti];
			}
		}
		pv[px] = 0;
		return 0;
	}else{
		match = 0;
		for( ti = 0; tv[ti]; ti++ )
			if( match = (strcasecmp(proto,tv[ti])==0) )
				break;

		if( match ){
			for( pi = 0; pv[pi]; pi++){
				if( MAXPROTO-1 <= pi ){
					return -1;
				}
			}
			pv[pi+1] = 0;

			pv[pi] = *portp;
			Xstrcpy(QVStr(*portp,portb),proto);
			*portp += strlen(*portp);
			if( ports[0] == 0 && methods[0] )
				strcpy(ports,"*");
			if( ports[0] ){
				Xsprintf(QVStr(*portp,portb),"/%s",ports);
				*portp += strlen(*portp);
			}
			if( methods[0] ){
				Xsprintf(QVStr(*portp,portb),"/%s",methods);
				*portp += strlen(*portp);
			}
			*portp += 1;
			return 0;
		}
	}
	sv1log("ERROR protocol inhibited: %s\n",proto);
	sv1log("#### ERROR forbidden protocol: %s ####\n",proto);
	return 0;
}
static int portMatch(Server *protoV,int port)
{	int ni;

	if( protoV->p_portV == NULL )
		return 1;

	for( ni = 0; ni < protoV->p_portN; ni++ )
		if( protoV->p_portV[ni] == port )
			return 1;
	return 0;
}
static Server *protoMatch1(Connection *Conn,Server *protoV,PCStr(proto),int port)
{	int px;
	const char *aproto;
	int px0 = -1;
	int pxn = 0;

	for( px = 0; aproto = protoV[px].p_name; px++ ){
		/*
		if( strcasecmp(proto,aproto)==0 )
		*/
		if( *proto=='*' || *aproto=='*' || strcasecmp(proto,aproto)==0 )
			if( portMatch(&protoV[px],port) )
				return &protoV[px];
			else{
				pxn++;
				px0 = px;
			}
	}
	if( Conn->no_dstcheck_port && 0 <= px0 ){
		/* 9.9.7 permit origin server's -Pxxx */
		syslog_ERROR("IGN -P%d protoMatch1(%d)[%s][%s]\n",port,pxn,
			proto,protoV[px0].p_name);
		return &protoV[px0];
	}
	return NULL;
}
/*
char CMAPmethod[32];
static int protoMatch2(Server *protoV,PCStr(proto))
*/
static int protoMatch2(Connection *Conn,Server *protoV,PCStr(proto),FL_PAR)
{	int px;
	const char *aproto;
	int exactmatch = 0;

	if( protoV == NULL )
		return 1;

	if( *proto == '-' ){
		exactmatch = 1;
		proto++;
	}

	for( px = 0; aproto = protoV[px].p_name; px++ ){
		if( exactmatch && *aproto == '*' ){
			continue;
		}
		if( *proto=='*' || *aproto=='*' || strcasecmp(proto,aproto)==0 )
		{
			if( Conn == 0 ){
				sv1log("##protoMatch2(%s)Conn==NULL <= %s:%d\n",
					proto,FL_BAR);
			}else
			if( protoV[px].p_methods && CMAPmethod[0] ){
				if( isinList(protoV[px].p_methods,CMAPmethod) ){
					return 1;
				}else{
					return 0;
				}
			}
			return 1;
		}
	}
	return 0;
}
static int protoMatch3(Server *protoV,PCStr(proto))
{	int px;
	const char *aproto;
	int exactmatch = 0;

	if( *proto == '-' ){
		/* 9.9.8 for "-dns" via SRCIFfor/findRoute */
		exactmatch = 1;
		proto++;
	}
	for( px = 0; aproto = protoV[px].p_name; px++ ){
		if( exactmatch && *aproto == '*' ){
			continue;
		}
		if( *proto=='*' || *aproto=='*' || strcasecmp(proto,aproto)==0 )
			return 1;
	}
	return 0;
}
static int methodMatch(Connection *Conn,Server *protoV,PCStr(method))
{	const char *methods = protoV->p_methods;

	if( methods == NULL || *methods == 0 || strcmp(methods,"*") == 0 )
		return 1;

	if( methods != NULL && *methods == '{' ){
		/* 9.9.7 to cope with "*" in list as in "starttls://{*}:*:*" */
		if( isinListX(methods,"*","") ){
			return 1;
		}
	}

	if( method && streq(method,".REJECT") ){
		/* pseudo method to check the existence of methodList */
		return 0;
	}
	if( strcmp(methods,"readonly") == 0 ){
		/* "readonly" is a pseudo method name which represents any
		 * methods excluding ones for modification.  Since it depends
		 * on each application protocol, it is regarded as permitting
		 * arbitrary methods.
		 */
		return Conn->forreject ? 0 : 1;
	}

	if( method == NULL || *method == 0 ){
		/* empty method means connecting to server,
		 * which should not be rejected without condition,
		 * and should be permitted without condition.
		 */
		return Conn->forreject ? 0 : 1;
	}
	if( method  == NULL || *method  == 0 || strcmp(method, "*") == 0 )
		return 1;
/*
	if( strstr(methods,method) )
*/
	if( isinList(methods,method) )
		return 1;
	return 0;
}

static Route *addRoute1X(RouteTab *RT,PCStr(proto),AuthInfo *auth,PCStr(host),int port,PCStr(path),PCStr(conn),const char **protov,PCStr(dstlist),PCStr(srclist));
static Route *addRoute1(RouteTab *RT,PCStr(proto),PCStr(host),int port,PCStr(path),PCStr(conn),const char **protov,PCStr(dstlist),PCStr(srclist))
{
	return addRoute1X(RT,proto,0,host,port,path,conn,protov,dstlist,srclist);
}
static Route *addRoute1X(RouteTab *RT,PCStr(proto),AuthInfo *auth,PCStr(host),int port,PCStr(path),PCStr(conn),const char **protov,PCStr(dstlist),PCStr(srclist))
{	const char *what;
	int idx;
	Route *Rp;
	CStr(tabid,64);
	CStr(protolist,1024);
	CStr(hostb,MaxHostNameLen);

	what = RT->rt_name;
	idx = newRoute(RT);
	Rp = RT->rt_routes[idx];
	Rp->m_gw_proto = StrAlloc(proto);
	Rp->m_gw_host = StrAlloc(host);
	Rp->m_gw_port = port;
	Rp->m_gw_path = StrAlloc(path);
	Rp->m_conn = StrAlloc(conn);
	if( auth && (auth->i_user[0]||auth->i_pass[0]) ){
		Rp->m_gw_auth = (AuthInfo*)malloc(sizeof(AuthInfo));
		*Rp->m_gw_auth = *auth;
		sprintf(hostb,"%s:%s@%s",auth->i_user,auth->i_pass,host);
		host = hostb;
	}
	if( streq(what,"ROUTE") ){ /* ROUTE and FORWARD */
		/* 9.9.7 using the URL path part for ConnectFlags
		 * as ROUTE=socks://host:port/ssl
		 */
		Verbose("----[%s] path part as ConnectFlags {%s}\n",
			what,path);
		Rp->m_ConnectFlags = scanConnectFlags(what,path,0);
	}

	sprintf(tabid,"%s/DST",what);
	Rp->m_dsts.hl_what = StrAlloc(tabid);
	Rp->m_dsts.hl_noIdent = 1;
/* Rp->m_dsts.hl_list = &filterHosts[HostsX]; */
	scan_commaListL(dstlist,STR_ALLOC,scanListCall addHostList1,&Rp->m_dsts);
/* HostsX += Rp->m_dsts.hl_cnt; */

	sprintf(tabid,"%s/SRC",what);
	Rp->m_srcs.hl_what = StrAlloc(tabid);
/* Rp->m_srcs.hl_list = &filterHosts[HostsX]; */
	scan_commaListL(srclist,STR_ALLOC,scanListCall addHostList1,&Rp->m_srcs);
/* HostsX += Rp->m_srcs.hl_cnt; */

	if( protov != NULL ){
		protolist[0] = 0;
		Rp->m_protoV = makeProtoV(NULL,protov);
		sprintProtoV(Rp->m_protoV,AVStr(protolist));
		Verbose("[%d] %s={%s}%s{%s}:{%s}:{%s}\n",
			idx,what,path,host,protolist,dstlist,srclist);
	}else	Verbose("[%d] %s=%s://%s:%d%s-_-{%s}:{%s}\n",
			idx,what,proto,host,port,path,dstlist,srclist);
	return Rp;
}

static CriticalSec hlistCSC;
static HostList *hlist(int rtx,int srcdst){
	setupCSC("hlist",hlistCSC,sizeof(hlistCSC));
	enterCSC(hlistCSC);
	if( routeTabs[rtx].rt_routes == 0 )
		addRoute1(&routeTabs[rtx],"","",0,"","",NULL,"","");
	leaveCSC(hlistCSC);
	return &routeTabs[rtx].rt_routes[0]->m_hostlist[srcdst];
}

HostList *ReliableHosts(){	return hlist(R_RELIABLE,RX_SRC); }
HostList *ReachableHosts(){	return hlist(R_REACHABLE,RX_DST); }
HostList *IdentHosts(){		return hlist(R_USERIDENT,RX_SRC); }

void scan_RELIABLE(Connection *Conn,PCStr(rels))
{
	/* V8.0.1 RELIABLE="" -> RELIABLE="!*" */
	if( *rels == 0 ) rels = "!*";

	scan_commaList(rels,1,scanListCall addHostList1,ReliableHosts());
	putHostListTab(".RELIABLE",ReliableHosts());
}
void scan_REACHABLE(Connection *Conn,PCStr(list))
{
	/* V8.0.1 REACHABLE="" -> REACHABLE="!*" */
	if( *list == 0 ) list = "!*";

	ReachableHosts()->hl_noIdent = 1;
	scan_commaList(list,1,scanListCall addHostList1,ReachableHosts());
}
void enableClientIdent(PCStr(host))
{
	Verbose("-- ident: ENABLE{%s}\n",host);
	scan_commaList(host,1,scanListCall addHostList1,IdentHosts());
}

extern const char *NOTIFY_PLATFORM;
HostList *NotifyPltfrmHosts(){
	HostList *hl;

	hl = hlist(R_NOTIFYPLTFM,RX_DST);
	if( hl->hl_cnt == 0 && *NOTIFY_PLATFORM )
		scan_commaList(NOTIFY_PLATFORM,1,scanListCall addHostList1,hl);
	return hl;
}

static int NonHTTP(Route *Rp,PCStr(proto))
{
	if( Rp->m_protoV_NonHTTP ){
		if( strncasecmp(proto,"http",4) == 0 )
			return 1;
	}
	return 0;
}

/*
 *	CMAP=output:mapname:protoList:dstHostList:srcHostList
 */
#define M_OUT	0
#define M_NAME	1
#define M_PROTo	2
#define M_DSTH	3
#define M_SRCH	4

int scan_CMAPi(PCStr(map),int mx0,const char **strp)
{	int mx;
	Route *Rp;

	for( mx = mx0; mx < MapX; mx++ ){
		Rp = Maps[mx];
		if( strcmp(map,Rp->m_gw_host) == 0 ){
			*strp = Rp->m_gw_path;
			return mx;
		}
	}
	return -1;
}
static scanListFunc scanmap1(PCStr(map1),int mac,const char *mapv[],int *mapc)
{
	if( mac <= *mapc )
		return -1;
	mapv[*mapc] = map1;
	*mapc = *mapc + 1;
	return 0;
}
void scan_CMAPX(Connection *Conn,PCStr(map),int reverse,int defaultOK);
void scan_CMAP(Connection *Conn,PCStr(map))
{
	scan_CMAPX(Conn,map,0,0);
}
void scan_CMAP2(Connection *Conn,PCStr(name),PCStr(map))
{	CStr(cmap,1024);

	sprintf(cmap,"%s:%s",name,map);
	scan_CMAPX(Conn,cmap,1,1);
}
void scan_CMAPX(Connection *Conn,PCStr(map),int reverse,int defaultOK)
{	CStr(mapb,1024);
	const char *mapv[8]; /**/
	const char *map1;
	int mapc,mapi;
	const char *protoV[32]; /**/
	int outx,namex;

	strcpy(mapb,map);
	for( mapi = 0; mapi < 8; mapi++ )
		mapv[mapi] = "";

	mapc = 0;
	scan_ListL(mapb,':',STR_ALLOC,scanListCall scanmap1,8,mapv,&mapc);

	if( defaultOK )
	for( mapi = 0; mapi < 8; mapi++ )
		if( mapv[mapi][0] == 0 )
			mapv[mapi] = "*";

	protoV[0] = 0;
	stoVX(mapv[M_PROTo],32,protoV,',',1);
	/*
	stoV(mapv[M_PROTo],32,protoV,',');
	*/

	for( mapi = 0; mapi < mapc; mapi++ ){
		map1 = mapv[mapi];
		if( map1[0] == '{' && strtailchr(map1) == '}' ){
			ovstrcpy((char*)map1,map1+1);
			((char*)map1)[strlen(map1)-1] = 0;
		}
	}

	if( reverse ){
		namex = M_OUT;
		outx = M_NAME;
	}else{
		namex = M_NAME;
		outx = M_OUT;
	}
	addRoute1(MapRoute,
		"CMAP",mapv[namex],0,mapv[outx],"-",
		protoV, mapv[M_DSTH], mapv[M_SRCH]);
}
const char *getCMAPi(int mi){
	if( MapX <= mi )
		return 0;
	return Maps[mi]->m_gw_path;
}
const char *getCMAPiMap(int mi){
	if( MapX <= mi )
		return 0;
	return Maps[mi]->m_gw_host;
}
static int find_CMAPXi(Connection *Conn,PCStr(map),int i,PVStr(str),PCStr(proto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser),int ac,AuthInfo *av[])
{	int mx;
	Route *Rp;
	int nd,ns;

	for( mx = i; mx < MapX; mx++ ){
		Rp = Maps[mx];

		if( strcmp(map,Rp->m_gw_host) != 0 )
			continue;

		if( NonHTTP(Rp,proto) )
			continue;

		if( !protoMatch2(Conn,Rp->m_protoV,proto,whStr(str)) )
			continue;

		if( Conn )
		if( ClientAuth.i_meth[0] ){
			Server *pl;
			if( pl = protoMatch1(Conn,Rp->m_protoV,proto,dport) ){
				const char *method = ClientAuth.i_meth;
				if( !methodMatch(Conn,pl,method) )
					continue;
			}
		}

		HLdebug("{HL} CMAP/%s %d/%d\n",map,mx,MapX);
		nd = Rp->m_dsts.hl_cnt;
		ns = Rp->m_srcs.hl_cnt;
		/*
		if(!nd || hostIsinList(&Rp->m_dsts,proto,dhost,dport,NULL) )
		if(!ns || hostIsinList(&Rp->m_srcs,ANYP,shost,sport,suser) ){
		*/
		if(!nd || hostIsinListX(&Rp->m_dsts,proto,dhost,dport,NULL,ac,av) )
		if(!ns || hostIsinListX(&Rp->m_srcs,ANYP,shost,sport,suser,ac,av) ){
			strcpy(str,Rp->m_gw_path);
			if( lHOSTMATCH() ){
				sv1log("findCMAP(%s) %s://%s:%d <= %s {%s}\n",
					map,proto,dhost,dport,shost,str);
			}
			return mx;
		}
	}
	setVStrEnd(str,0);
	if( lHOSTMATCH() ){
		sv1log("findCMAP(%s) %s://%s:%d <= %s NOT FOUND\n",
			map,proto,dhost,dport,shost);
	}
	return -1;
}
int find_CMAPi(Connection *Conn,PCStr(map),int i,PVStr(str))
{	const char *proto;
	const char *dhost;
	CStr(shost,MaxHostNameLen);
	int dport,sport;
	const char *suser;
	int ac;
	AuthInfo *av[4]; /**/

/*
	proto = DST_PROTO;
*/
	if( REAL_PROTO[0] )
		proto = REAL_PROTO;
	else
	if( streq(DFLT_PROTO,"http") ){
		/* do not apply destination protocol dependent CFI
		 * before destination server's protocol is recognized.
		 */
		proto = "ANYP";
	}else
	if( DFLT_PROTO[0] )
		proto = DFLT_PROTO;
	else	proto = "ANYP";

	dhost = DST_HOST;
	dport = DST_PORT;
	sport = getClientHostPort(Conn,AVStr(shost));
	suser = Ident();

	ac = getClientAuthList(Conn,4,av);
	return find_CMAPXi(Conn,map,i,BVStr(str),proto,dhost,dport,shost,sport,suser,ac,av);
}
int find_CMAPX(Connection *Conn,PCStr(map),PVStr(str),PCStr(proto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser))
{
	return find_CMAPXi(Conn,map,0,BVStr(str),proto,dhost,dport,shost,sport,suser,0,NULL);
}
int find_CMAPXX(Connection *Conn,PCStr(map),PVStr(str),PCStr(proto),PCStr(method),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser))
{
	IStr(ometh,128);
	int midx;

	/* 9.9.7 checking method (half-done in 8.10.4-pre2).  This func. is
	 * used just by by withFilter() for proto="starttls" with method=proto
	 * for STLS=fxx:proto, thus the real method can be ignored.
	 * (though it's better that STLS is conditional on the real method...)
	 */
	strcpy(ometh,ClientAuth.i_meth);
	strcpy(ClientAuth.i_meth,method);
	midx = find_CMAPXi(Conn,map,0,AVStr(str),proto,dhost,dport,shost,sport,suser,0,NULL);
	strcpy(ClientAuth.i_meth,ometh);
	return midx;
	/*
	return find_CMAPXi(Conn,map,0,AVStr(str),proto,dhost,dport,shost,sport,suser,0,NULL);
	*/
}
int find_CMAP(Connection *Conn,PCStr(map),PVStr(str))
{
	return find_CMAPi(Conn,map,0,BVStr(str));
}

/*
 *	ROUTE=proto://host:port/path-_-{dstHostList}:{srcHostList}
 */
#define DELMARK	"-_-"
void scan_ROUTE(Connection *Conn,PCStr(forward))
{	CStr(gateway,MaxHostNameLen);
	const char *cmap;
	CStr(proto,32);
	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	CStr(path,128);
	int port;
	CStr(dstlist,2048);
	CStr(srclist,2048);
	const char *dp;
	const char *np;
	const char *srcp;
	int na;
	AuthInfo au;

	if( (dp = strstr(forward,DELMARK)) == 0 )
	{
		/*
		goto error;
		*/
		strcpy(gateway,forward);
		cmap = "";
	}else{
	strncpy(gateway,forward,dp-forward); setVStrEnd(gateway,dp-forward);
		cmap = dp + strlen(DELMARK);
	}

	path[0] = 0;
	truncVStr(hostport);
	if( Xsscanf(gateway,"%[^:]://%[^/]%s",AVStr(proto),AVStr(hostport),AVStr(path)) < 2 )
	if( streq(proto,"direct") || streq(proto,"noroute") ){
	}else
		goto error;
	/*
	if( Xsscanf(hostport,"%[^:]:%d",AVStr(host),&port) < 2 )
		port = serviceport(proto);
	*/
	bzero(&au,sizeof(AuthInfo));
	port = decomp_siteX(proto,hostport,&au);
	strcpy(host,au.i_Host);

	/*
	dp += strlen(DELMARK);
	*/
	dp = cmap;

	srcp = 0;
	dstlist[0] = srclist[0] = 0;

	if( *dp == '{' ){
		dp++;
		if( (np = strchr(dp,'}')) == 0 )
			goto error;
		strncpy0(AVStr(dstlist),dp,np-dp);
		switch( np[1] ){
			case 0:	  goto done;
			case ':': srcp = np + 2; break;
			default:  goto error;
		}
	}else{
		if( np = strchr(dp,':') ){
			strncpy0(AVStr(dstlist),dp,np-dp);
			srcp = np + 1;
		}else{
			strcpy(dstlist,dp);
			goto done;
		}
	}
	if( *srcp == '{' ){
		srcp++;
		if( (np = strchr(srcp,'}')) == 0 )
			goto error;
		strncpy0(AVStr(srclist),srcp,np-srcp);
	}else{
		strcpy(srclist,srcp);
	}
done:
	/*
	addRoute1(ForwardRoute,proto,host,port,path,"",
	*/
	addRoute1X(ForwardRoute,proto,&au,host,port,path,"",
		NULL,dstlist,srclist);
	return;
error:
	sv1log("ROUTE ? %s\n",forward);
	return;
}
void scan_FORWARDX(Connection *Conn,PCStr(forward),int withproto);
void scan_FORWARD(Connection *Conn,PCStr(forward))
{
	scan_FORWARDX(Conn,forward,1);
}
void scan_GATEWAY(Connection *Conn,PCStr(gateway)){
	scan_FORWARD(Conn,gateway);
}
static scanListFunc conn1(PCStr(co1),const char *connv[],int *connc,int mac)
{
	if( mac <= *connc ){
		return -1;
	}
	if( *co1 )
		connv[*connc] = co1;
	else	connv[*connc] = "*";
	*connc += 1;
	return 0;
}
void scan_FORWARDX(Connection *Conn,PCStr(forward),int withproto)
{	CStr(gateway,MaxHostNameLen);
	CStr(proto,32);
	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	CStr(path,128);
	CStr(portb,32);
	int port;
	const char *dp;
	const char *cmap;
	int connc;
	const char *connv[4]; /**/
	const char *svproto;
	const char *dst;
	const char *src;
	const char *protoV[MAXPROTO]; /**/
	AuthInfo au;
	IStr(hostb,MaxHostNameLen);

	if( dp = strstr(forward,DELMARK) ){
	strncpy(gateway,forward,dp-forward); setVStrEnd(gateway,dp-forward);
		cmap = dp + strlen(DELMARK);
	}else{
		strcpy(gateway,forward);
		cmap = "";
	}

	decomp_absurl(gateway,AVStr(proto),AVStr(hostport),AVStr(path),sizeof(path));
	if( proto[0] == 0 || hostport[0] == 0 )
	if( streq(proto,"direct") || streq(proto,"noroute") ){
	}else
		goto error;
	bzero(&au,sizeof(AuthInfo));
	port = decomp_siteX(proto,hostport,&au);
	strcpy(host,au.i_Host);

	/*
	decomp_URL_site(hostport,AVStr(host),AVStr(portb));
	*/
	decomp_URL_site(hostport,AVStr(hostb),AVStr(portb));
	port = atoi(portb);
	if( port == 0 )
		port = serviceport(proto);

	connc = 0;
	connv[0] = connv[1] = connv[2] = "*";
	scan_ListL(cmap,':',STR_ALLOC,scanListCall conn1,connv,&connc,4);
	if( withproto ){
		svproto = connv[0];
		dst = connv[1];
		src = connv[2];
	}else{
		svproto = "*";
		dst = connv[0];
		src = connv[1];
	}
	sv1log("FORWARD=%s://%s:%d/%s-_-{%s}:{%s}:{%s}\n",proto,host,port,path,
		svproto,dst,src);
	stoV(svproto,MAXPROTO,protoV,',');
	/*
	addRoute1(ForwardRoute,proto,host,port,path,"",protoV,dst,src);
	*/
	addRoute1X(ForwardRoute,proto,&au,host,port,path,"",protoV,dst,src);
	return;
error:
	sv1log("FORWARD ? %s\n",forward);
	return;
}

static int findRoute(Connection *Conn,Route *routes[],int startX,int endX,PCStr(proto),PCStr(dsthost),PCStr(srchost))
{	int cx,nd,ns;
	Route *Rp;
	int found = -1;

	CTX_pushClientInfo(Conn);
	for( cx = startX; cx < endX; cx++ ){
		Rp = routes[cx];

		if( NonHTTP(Rp,proto) )
			continue;

		if( !protoMatch3(Rp->m_protoV,proto) )
			continue;

		nd = Rp->m_dsts.hl_cnt;
		ns = Rp->m_srcs.hl_cnt;
		if(!nd || hostIsinList(&Rp->m_dsts,proto,dsthost,0,NULL) )
		if(!ns || hostIsinList(&Rp->m_srcs,ANYP,srchost,0,Ident()))
		{
			found = cx;
			break;
		}
	}
	HL_popClientInfo();
	return found;
}

/*
 *	PERMIT=proto1/{port1,port2}/{com1,com2}:dstHostList:srcHostList
 */
void scan_PERMITV(Connection *Conn,PCStr(list),const char *protov[])
{	CStr(protoL,2048);
	CStr(dstL,2048);
	CStr(srcL,2048);
	const char *protoV[MAXPROTO]; /**/
	const char *pprotov[MAXPROTO]; /**/
	CStr(portb,2048);
	const char *portp = portb;
	int pc;
	const char *iproto;
	int withsrc;

	protoL[0] = dstL[0] = srcL[0] = 0;
	pc = scan_Listlist(list,':',AVStr(protoL),AVStr(dstL),AVStr(srcL),VStrNULL,VStrNULL);
	iproto = DFLT_PROTO;
	protoV[0] = 0;

	if( !Conn->forreject )
	if( pc <= 1 ){
		CStr(protolist,1024);
		protolist[0] = 0;
		if( Remittable ){
			sprintProtoV(Remittable,AVStr(protolist));
			if( *protolist && *protoL )
				strcat(protolist,",");
		}
		strcat(protolist,protoL);
		strcpy(protoL,protolist);

		scan_commaListL(protoL,STR_VOLA,scanListCall addProto1,protov,protoV,AVStr(portb),&portp,iproto);
		if( Remittable )
			RemittableV = makeProtoV(NULL,protoV);
		else	addRoute1(RemittableRoute,"","",0,"","",protoV,"*","*");
		sprintProtoV(Remittable,AVStr(protolist));
		InitLog("REMITTABLE = %s\n",protolist);
		return;
	}

	if( Conn->forreject /* && strneq(protoL,"admin",5) */ ){
		/* for "admin" protocol to judge by REJECT=admin//xxx alone
		 * without REMITTABLE=+,admin ... "admin" should be added
		 * to REMITTABLE when AUTH=admin is specified...
		 */
	}else
	if( Remittable != NULL ){
		int pi;
		for( pi = 0; pprotov[pi] = RemittableV[pi].p_name; pi++ ){
			if( elnumof(pprotov)-2 <= pi ){
				pprotov[++pi] = 0;
				break;
			}
		}
		protov = pprotov; /* arary of available protocos */
	}
	scan_commaListL(protoL,STR_VOLA,scanListCall addProto1,protov,protoV,AVStr(portb),&portp,iproto);

	withsrc = srcL[0] != 0;
	if( dstL[0] == 0 ) strcpy(dstL,"*");
	if( srcL[0] == 0 ) strcpy(srcL,DELEGATE_RELIABLE);

	if( Conn->forreject ){
		addRoute1(RejectRoute,"","",0,"","",protoV,dstL,srcL);
		RejectRoute->rt_withsrc += withsrc ? 1 : 0;
	}else{
	addRoute1(PermitRoute,"","",0,"","",protoV,dstL,srcL);
	PermitRoute->rt_withsrc += withsrc ? 1 : 0;
	}
}
int PERMIT_withSrc(){ return PermitRoute->rt_withsrc; }

int withREMITTABLE(){
	return Remittable != NULL;
}
int notREMITTABLE(Connection *Conn,PCStr(proto),int port)
{
	if( Remittable != NULL )
		if( protoMatch1(Conn,Remittable,proto,port) == NULL )
			return 1;
	return 0;
}

int DELEGATE_permitM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport);
int DELEGATE_rejectM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport)
{	int match;

	if( RejectX <= 0 )
		return 0;

	Conn->forreject = 1;
	match = DELEGATE_permitM(Conn,proto,method,dsthost,dport,srchost,sport);
	Conn->forreject = 0;
	return match;
}

int rejectMethod(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport){
	int nchk = Conn->no_dstcheck;
	int nchkp = Conn->no_dstcheck_proto;
	int rej;

	Conn->no_dstcheck = 0;
	Conn->no_dstcheck_proto = 0;
	rej = DELEGATE_rejectM(Conn,proto,method,dsthost,dport,srchost,sport);
	Conn->no_dstcheck = nchk;
	Conn->no_dstcheck_proto = nchkp;
	return rej;
}

extern const char *hostmatch_ignauth;
static int DELEGATE_permitMX(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport,PCStr(suser),int ac,AuthInfo *av[]);
int DELEGATE_permitM(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport)
{	const char *suser;
	int ac;
	AuthInfo *av[4]; /**/

	suser = Ident();
	if( suser == 0 && Conn->no_authcheck )
		suser = hostmatch_ignauth;
	ac = getClientAuthList(Conn,4,av);
	return DELEGATE_permitMX(Conn,proto,method,dsthost,dport,srchost,sport,suser,ac,av);
}
static int DELEGATE_permitMX(Connection *Conn,PCStr(proto),PCStr(method),PCStr(dsthost),int dport,PCStr(srchost),int sport,PCStr(suser),int ac,AuthInfo *av[])
{	Route *Rp;
	int pi;
	Server *pl;
	const char *duser = DST_USER;
	const char *dstproto = proto;
	
	int permitX;
	Route **permits;

	if( Conn->forreject ){
		if( Conn->no_dstcheck ){
			/* ignore REJECT=prt:dst:src for source_permit() */
			/* 9.0.3 REJECT should not be ignored even in
			 * source_permit()
			 * The ignorance of REJECT was introdued in 8.4.0,
			 * where REJECT=proto//method is intrdoduced,
			 * maybe to bypass checking about method.
			return 0;
			 */
		}
		permitX = RejectX;
		permits = Rejects;
	}else{
		permitX = PermitX;
		permits = Permits;
	}

	if( Conn->no_dstcheck_proto
	 && Conn->no_dstcheck_proto == serviceport(proto) )
	{
	    if( Conn->forreject ){
		/* v9.9.12 fix-140828g, don't REJECT all MOUNTed destination.
		 * HISTORY: this code was introduced in v8.4.0 (Feb. 2003)
		 *  shortly after REJECT is introduced in v8.0.0 (Sep. 2002)
		 *  and "no_dstcheck_proto" is used limitedly
		 * SITUATION: "no_dstcheck_proto" is set basically for a
		 *  MOUNTed destination of HTTP, or in a protocol gateway
		 *  in many protocols, maybe to bypass the access restriction
		 *  by the default REMITTABLE of each SERVER=protocol.
		 > PROBLEM: skipping the matching of destination protocol makes
		 >  a REJECT=proto:serv:clent work like REJECT=*:serv:clnt
		 >  so that if a REJECT is defined, any access is forbidden
		 >  for a MOUNTed destination, "-Dst" option to allow
		 >  "ssltunnel" does not work, etc.
		 * FIX: don't apply this code to a REJECT parameter. 
		 */
		sv1log("## REJECT don't ignore protocol matching [%s]\n",proto);
	    }else{
		/* skip checking destination protocol for MOUNTed server */
		dstproto = "*";
	    }
	}

	if( !Conn->forreject )
	if( !Conn->no_dstcheck )
	if( Remittable != NULL ){
		if( (pl = protoMatch1(Conn,Remittable,dstproto,dport)) == NULL )
		{
			sprintf(Conn->reject_reason,"'%s' is not REMITTABLE",
				proto);
			return 0;
		}
		if( !methodMatch(Conn,pl,method) )
			return 0;
	}

	if( permitX == 0 )
		return 1;

	for( pi = 0; pi < permitX; pi++ ){
		Rp = permits[pi];
		pl = NULL;

		if( lACCESSCTL() ){
			HostList *dhl = &Rp->m_dsts;
			HostList *shl = &Rp->m_srcs;
			Host *dhp;
			Host *shp;
			dhp = dhl ? dhl->hl_List[1] : 0;
			shp = shl ? shl->hl_List[1] : 0;
			sv1log("-dA %s[%d/%d] %s%s %s[%s] %s[%s]\n",
				dhl->hl_what,pi,permitX,
				Conn->no_dstcheck?"D":"",
				Conn->forreject?"R":"",
				dhp?dhp->h_name:"",dsthost,
				shp?shp->h_name:"",srchost
			);
		}

		/* 9.0.3 when destination info. must be ignored, the default
		 * should be "permitted" by default, as long as the source
		 * matches.  So for PERMIT, protoV//method can be ignored when
		 * dest. info. is not cared (in source_permitted())
		 * But it is not the case for REJECT with protoV//method.
		 * A REJECT with protoV//method should be ignored when dest.
		 * info. (and/or method) must be ignored (or not available).
		if( !Conn->no_dstcheck )
		 */
		if( !Conn->no_dstcheck || Conn->forreject )
		if( Rp->m_protoV )
		if( (pl = protoMatch1(Conn,Rp->m_protoV,dstproto,dport)) == NULL )
			continue;

		HLdebug("{HL} %s %d/%d\n",Conn->forreject?"REJECT":"PERMIT",
			pi,permitX);

		if( Conn->forreject ) /* REJECT */
		if( Conn->no_dstcheck ) /* source_permitted() */
		if( lDOSRCREJECT() ){
			/* 9.8.6 -Ers option to downgrade to 9.8.5 or before.
			 * partial matching as source_permitted() is used to
			 * screening accesses "possibly be permitted" by PERMIT
			 * but it must not reject ones "possibly be rejected" by
			 * REJECT="*:dst:*" (when dst is not yet known) except for
			 * REJECT="proto:*:src" which is unconditional on dst.
			 */
		}else{
			int hostListIsAny(HostList *hostlist);
			if( hostListIsAny(&Rp->m_dsts) ){
				/* dst will not be checked but it's true anyway */
			}else{
				/* don't reject "possibly be rejected" */
				continue;
			}
		}

		if( Conn->no_dstcheck
		 || hostIsinList(&Rp->m_dsts,proto,dsthost,dport,duser) )
		if( hostIsinListX(&Rp->m_srcs,ANYP,srchost,sport,suser,ac,av) ){
			if( pl == NULL )
				return 1;
			else	return methodMatch(Conn,pl,method);
		}
	}
	return 0;
}

/*
 *	OWNER=owner:srcHostList
 */
int scan_OWNER(Connection *Conn,PCStr(ownerspec))
{	CStr(user,1024);
	CStr(from,1024);
	Route *Rp;

	user[0] = from[0] = 0;
	Xsscanf(ownerspec,"%[^:]:%s",AVStr(user),AVStr(from));
	if( from[0] != 0 ){
		Rp = addRoute1(OwnerRoute,"","",0,"","",NULL,"",from);
		Rp->m_owner = StrAlloc(user);
	}
	return 0;
}
int set_Owner(int real,PCStr(aowner),int file);
int set_OWNER(Connection *Conn,PCStr(host),int port,PCStr(user))
{	int oi;
	Route *Rp;
	const char *owner;

	if( OwnerX == 0 )
		return 0;

	owner = 0;
	for( oi = 0; oi < OwnerX; oi++ ){
		Rp = Owners[oi];
		if( hostIsinList(&Rp->m_srcs,ANYP,host,port,user) ){
			owner = Rp->m_owner;
			break;
		}
	}
	if( owner ){
		if( streq(owner,"*") )
			owner = user;
		sv1log("OWNER=%s <= %s@%s:%d\n",owner,user,host,port);
		set_Owner(1,owner,-1); /* Identd doesn't look effective UID ... */
		return 0;
	}
	sv1log("#### set_OWNER: failed <= %s@%s:%d\n",user,host,port);
	return -1;
}

/*
 * when running in euid()==root by set-uid-on-exec flag of the
 * executable file, it should run in the original user's identity.
 * at least it must not be used to be OWNER="arbitrary-user"
 */
int dosetUidOnExec(PCStr(what),PCStr(owner),int *uid,int *gid){
	/*
	if( geteuid() == 0 && (getuid() != 0 || getgid() != 0) ){
	*/
	if( geteuid() == 0 )
	/*
	if( getuid() != 0 || getgid() != 0 && getgid() != 1 ){
	*/
	if( getuid() != 0 || getgid() != 0 && getgid() != 1 && getgid() != 3 ){
		/*
		 * see if an explicit OWNER (in owner para.) is set.
		 * if set, and it is in the possible uid list of SUDOAUTH
		 * then folows the specification of the OWNER.
		 */
		if( owner && getUserId(owner) != getuid() ){
			fprintf(stderr,
			"-- %s: cannot be OWNER=%s with set-uid-on-exec\n",
				what,owner);
		}
		if( uid ) *uid = getuid();
		if( gid ) *gid = getgid();
		return 1;
	}
	return 0;
}
int set_Owner(int real,PCStr(aowner),int file)
{	const char *owner;
	int uid,gid;
	CStr(names,128);

	if( aowner != NULL && strchr(aowner,':') )
		return 0;

	if( dosetUidOnExec("set_OWNER",aowner,&uid,&gid) ){
		CStr(downer,128);
		sprintf(downer,"#%d/#%d",uid,gid);
		sv1log("SetUidOnExec OWNER=%s -> %s\n",aowner?aowner:"",downer);
		aowner = downer;
	}
	if( (owner = aowner) == NULL )
		owner = DELEGATE_OWNER;

	if( scan_guid(owner,&uid,&gid) != 0 ){
		if( aowner != NULL ){
			ERRMSG("ERROR: Unknown OWNER: %s\n",owner);
			return -1;
		}
	}else{
		if( 0 <= file && !isatty(file) )
		if( INHERENT_fchown() )
			IGNRETZ fchown(file,uid,gid);
		/* chown() should be tried if it is available... */

		if( real ){
			if( gid != -1 ) setgid(gid);
			setuid(uid);
		}else{
			if( gid != -1 ) setegid(gid);
			seteuid(uid);
		}
		sv0log("OWNER=%s => OWNER=%s\n",owner,getusernames(AVStr(names)));
	}
	return 0;
}

/*
 * SRCIF=host[:port[:dstProto[:dstHost[:srcHost]]]]
 */
void scan_SRCIF(Connection *Conn,PCStr(ifspec))
{	CStr(specb,1024);
	const char *specv[5]; /**/
	const char *shost;
	const char *protov[64]; /**/
	int sc,si,sport;
	int p1,p2;

	lineScan(ifspec,specb);
	sc = stoV(specb,5,specv,':');
	for( si = sc; si < 5; si++ )
		specv[si] = "*";
	shost = specv[0];
	if( sscanf(specv[1],"%d-%d",&p1,&p2) == 2 ){
		sport = (p1 << 16) | p2;
	}else
	if( strcmp(specv[1],"0") == 0 )
		sport = 0xFFFF0000;
	else
	sport = atoi(specv[1]);
	stoV(specv[2],64,protov,',');
	addRoute1(SrcifRoute,"",shost,sport,"","",protov,specv[3],specv[4]);
}
int print_SRCIF(PVStr(hostport),PCStr(host),int port){
	refQStr(ports,hostport);

	if( host[0] == 0 )
		strcpy(hostport,"*");
	else	strcpy(hostport,host);
	ports = hostport + strlen(hostport);
	setVStrPtrInc(ports,':');
	if( 0xFFFF0000 & port )
		sprintf(ports,"%d-%d",0xFFFF&(port>>16),0xFFFF&port);
	else
	if( port == 0 )
		sprintf(ports,"-");
	else	sprintf(ports,"%d",port);
	return 0;
}

void set_SRCPORT(PCStr(host),int port);
const char *isCLIFHOST(Connection *Conn,PCStr(host)){
	if( strtailstr(host,"clif.-") ){
		if( CLIF_HOST[0] ){
			return CLIF_HOST;
		}
	}
	return 0;
}
void set_SRCIF(Connection *Conn,PCStr(proto),PCStr(host),int port)
{	const char *shost;
	int routex;
	Route *Rp;

	shost = Client_Host;
	routex = findRoute(Conn,Srcif,0,SrcifX,proto,host,shost);
	if( 0 <= routex ){
		Rp = Srcif[routex];
		if( isCLIFHOST(Conn,Rp->m_gw_host) ){
		    sprintf(Conn->sv.p_SRCIF,"%s:%X",CLIF_HOST,Rp->m_gw_port);
		}else
		sprintf(Conn->sv.p_SRCIF,"%s:%X",Rp->m_gw_host,Rp->m_gw_port);
		set_SRCPORT(Rp->m_gw_host,Rp->m_gw_port);
	}else{
		strcpy(Conn->sv.p_SRCIF,"");
		set_SRCPORT("",0);
	}
	/*
	}else	set_SRCPORT("",0);
	*/
}
int SRCIFHPfor(Connection *Conn,PCStr(proto),PCStr(host),int port,PVStr(lhp)){
	const char *shost;
	int routex;
	Route *Rp;

	shost = Client_Host;
	routex = findRoute(Conn,Srcif,0,SrcifX,proto,host,shost);
	if( 0 <= routex ){
		Rp = Srcif[routex];
		if( isCLIFHOST(Conn,Rp->m_gw_host) ){
			sprintf(lhp,"%s:%X",CLIF_HOST,Rp->m_gw_port);
		}else
		sprintf(lhp,"%s:%X",Rp->m_gw_host,Rp->m_gw_port);
		return 1;
	}else{
		return 0;
	}
}
int SRCIFfor(Connection *Conn,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport)
{	int routex;
	Route *Rp;
	CStr(ports,32);

	routex = findRoute(Conn,Srcif,0,SrcifX,proto,rhost,Client_Host);
	if( 0 <= routex ){
		Rp = Srcif[routex];
		if( Rp->m_gw_port == 0 )
			strcpy(ports,"*");
		else
		if( Rp->m_gw_port == 0xFFFF0000 )
			strcpy(ports,"0");
		else
		if( Rp->m_gw_port & 0xFFFF0000 )
			sprintf(ports,"%d-%d",
			(Rp->m_gw_port>>16)&0xFFFF,(Rp->m_gw_port)&0xFFFF);
		else	sprintf(ports,"%d",Rp->m_gw_port);
		
		sv1log("SRCIF=%s:%s [%s://%s:%d]\n",Rp->m_gw_host,ports,
			proto,rhost,rport);

		if( lhost && isCLIFHOST(Conn,Rp->m_gw_host) ){
			strcpy(lhost,CLIF_HOST);
		}else
		if( lhost && *Rp->m_gw_host != '*' ) strcpy(lhost,Rp->m_gw_host);
		if( lport && Rp->m_gw_port ) *lport = Rp->m_gw_port;
		return 1;
	}
	return 0;
}

/*
 *	cache/expire
 *	direct/socks
 *	master/private
 *	master/socks
 *	proxy/socks
 */

#define C_CACHE		'c'
#define C_ICP		'i'
#define C_FTP		'f'
#define C_SSLTUNNEL	'h'
#define C_MASTER	'm'
#define C_MASTERP	'm'
#define C_PROXY		'p'
#define C_DIRECT	'd'
#define C_VSAP		'v'
#define C_SOCKS		's'
#define C_YYMUX		'y'
#define C_TELEPORT	't'
#define C_UDP		'u'
#define C_INTERNAL	'l'
#define C_NONE_		'N'
#define C_GATEWAY	'g'

typedef struct {
	char	*c_orders; /**/
	int	 c_orderZ;
	int	 orderx;
	int	*expires;
} connArg; 

void enable_cache();
void disable_cache();
static scanListFunc connect1(PCStr(conn),Connection *Conn,connArg *Ca)
{	const char *expire;
	const char *dp;
	int ctype;

	switch( *conn ){
	    case 'c':	enable_cache();
			if( expire = strchr(conn,'/') ){
				expire++;
			}
			ctype = C_CACHE;    break;
	    case 'i':	ctype = C_ICP;      break;
	    case 'd':	ctype = C_DIRECT;   break;
	    case 'f':	ctype = C_FTP;	    break;
	    case 'h':	ctype = C_SSLTUNNEL;break;
	    case 'p':	ctype = C_PROXY;    break;
	    case 'm':	ctype = C_MASTER;
			if( dp = strchr(conn,'/') )
				if( dp[1] == 'p' )
					ctype = C_MASTERP;
			break;
	    case 'v':	ctype = C_VSAP;
			if( dp = strchr(conn,'/') ){
				CStr(vsap,1024);
				sprintf(vsap,"%s/CONNECT",dp+1);
				scan_VSAP(Conn,vsap);
			}
			break;
	    case 'y':	ctype = C_YYMUX;    break;
	    case 's':	ctype = C_SOCKS;    break;
	/*
	    case 't':	ctype = C_TELEPORT; break;
	*/
	    case 't':	if( streq(conn,"tcp") )
			ctype = C_DIRECT; else
			ctype = C_TELEPORT; break;
	    case 'u':	ctype = C_UDP; break;
	    case 'l':	ctype = C_INTERNAL; break;
	    case 'N':   ctype = C_NONE_; break;
	    case 'g':	ctype = C_GATEWAY; break;
	    default:	sv1log("CONNECT=%s ?\n",conn);
			return -1;
	}

	if( Ca->c_orderZ-1 <= Ca->orderx ){
		return -1;
	}
	Ca->c_orders[Ca->orderx++] = ctype;
	return 0;
}
void scan_CONNECT(Connection *Conn,PCStr(connlist))
{	const char *clist;
	const char *proto;
	const char *dst;
	const char *src;
	const char *protoV[MAXPROTO]; /**/
	CStr(orders,32);
	int expires[32];
	connArg ca;
	const char *connv[4]; /**/
	int conni,connc;

	clist = stralloc(connlist);
	for( conni = 0; conni < 4; conni++ )
		connv[conni] = "*";
	connc = 0;
	scan_List(clist,':',STR_OVWR,scanListCall conn1,connv,&connc,4);
	proto = connv[1];
	dst = connv[2];
	src = connv[3];

	ca.c_orders = orders;
	ca.c_orderZ = sizeof(orders);
	ca.orderx = 0;
	ca.expires = expires;
	if( scan_commaListL(connv[0],STR_VOLA,scanListCall connect1,Conn,&ca) < 0 ){
		ERRMSG("unknown CONNECT=%s ?\r\n",clist);
		Finish(1);
	}
	ca.c_orders[ca.orderx] = 0;
	Verbose("CONNECT={%s}:{%s}:{%s}:{%s}\n",orders,proto,dst,src);

	stoV(proto,MAXPROTO,protoV,',');
	addRoute1(ConnectRoute,"","",0,"",orders,protoV,dst,src);
	free((char*)clist);
}
void initConnect(Connection *Conn)
{
	Conn->co_setup = 0;
}

int remote_access(Connection *Conn);
int setupConnect(Connection *Conn)
{	int routex;
	CStr(shost,MaxHostNameLen);
	int sporti;
	Route *Rp;
	const char *orders;

	if( ConnectX == 0 )
		return 0;
	if( Conn->co_setup )
		return 1;
	Conn->co_setup = 1;

	if( remote_access(Conn) ){
		sv1log("====> remote access\n");
		ConnectX = 0; /* should set remote access explicitly ? */
		Conn->co_nonet = 0;
		return 0;
	}

	if( Conn->from_myself && !Conn->from_client ){
		shost[0] = 0;
		sporti = 0;
	}else
	if( Conn->from_cached ){
		/* udprelay */
		sporti = getClientHostPortAddr(Conn,AVStr(shost),VStrNULL);
		if( sporti == 0 )
			return 0;
	}else
	if( (sporti = getpeerNAME(ClientSock,AVStr(shost))) == 0 )
		return 0;

	routex = findRoute(Conn,Connects,0,ConnectX,DST_PROTO,DST_HOST,shost);
	Conn->co_routex = routex;
	if( routex < 0 ){
		Verbose("====> NO CONNECT was specified for: %s:%s\n",
			DST_HOST,shost);
		return 0;
	}

	Rp = Connects[routex];
	orders = Rp->m_conn;

	if( strchr(orders,C_INTERNAL) && orders[0] != C_INTERNAL ){
		Verbose("CONNECTION: NO INTERNAL\n");
		Conn->co_nointernal = 1;
	}
	if( strchr(orders,C_CACHE) == 0 ){
		disable_cache();
	}else{
		enable_cache();
		/*scan_EXPIRE();*/
		if( orders[0] == C_CACHE && orders[1] == 0 )
			Conn->co_nonet = 1;
	}
	return 0;
}

int open_master(Connection *Conn,int try_direct,PCStr(server),int svport,int sendhead,int relay_input);
int ConnectViaSSLtunnel(Connection *Conn,PCStr(host),int port);
int ConnectViaICP(Connection *Conn,PCStr(dsturl));
int ConnectViaFtp(Connection *Conn);
int forwardit(Connection *Conn,int fromC,int relay_input);

int tryCONNECT(Connection *Conn,void *cty,int relay_input,int *svsockp)
{	int cx,ci,svsock;
	char contype;
	const char *order;

	*svsockp = -1;
	Conn->ca_objsize = -1;

	if( ConnectX == 0 )
		return 0;
	if( Conn->co_setup == 0 )
		setupConnect(Conn);
	if( Conn->co_routex < 0 )
		return 0; /* default connection will be tried */
	if( Conn->co_nonet )
		return -1;

	svsock = -1;
	cx = Conn->co_routex;
	order = Connects[cx]->m_conn;

	for( ci = 0; svsock == -1 && order[ci]; ci++ ){
	    contype = order[ci];
	    if( contype == C_NONE_ ){
		ConnType = 'N';
		return -1;
	    }

	    if( tryProxyOnly )
	    switch( contype ){
	      case C_CACHE:
	      case C_ICP:
	      case C_PROXY:
	      case C_MASTER:
		break;
	      default:
		Verbose("tryProxyOnly:NO. prefer [%c] to proxy\n",contype);
		return -1;
	    }

	    switch( contype ){
	      case C_CACHE:
		Verbose("-[%d,%d]- TRY CACHE ...\n",cx,ci);
		break;
	      case C_ICP:
		Verbose("-[%d,%d]- TRY ICP ...\n",cx,ci);
		svsock = ConnectViaICP(Conn,NULL);
		break;
	      case C_SSLTUNNEL:
		Verbose("-[%d,%d]- TRY SSLtunnel/HTTP ...\n",cx,ci);
		svsock = ConnectViaSSLtunnel(Conn,DST_HOST,DST_PORT);
		break;
	      case C_FTP:
		Verbose("-[%d,%d]- TRY FTP-DATA ...\n",cx,ci);
		svsock = ConnectViaFtp(Conn);
		break;
	      case C_GATEWAY:
		Verbose("-[%d,%d]- TRY GATEWAY ...\n",cx,ci);
		if( forwardit(Conn,-1,relay_input) ){
			svsock = ToS;
		}
		break;
	      case C_PROXY:
	      case C_MASTER:
		Verbose("-[%d,%d]- TRY PROXY ...\n",cx,ci);
		if( forwardit(Conn,-1,relay_input) ){
			svsock = ToS;
			if( ConnType=='d' || ConnType=='s' || ConnType=='h' ){
			}else
			if( toProxy )
				ConnType = 'p';
			else	ConnType = 'm';
		}
		if( 0 <= svsock || contype == C_PROXY )
			break;
		Verbose("-[%d,%d]- TRY MASTER ...\n",cx,ci);
		svsock = open_master(Conn,1,DST_HOST,DST_PORT,1,relay_input);
		break;
	      case C_DIRECT:
		Verbose("-[%d,%d]- TRY DIRECT ...\n",cx,ci);
/* should get rid of SOCKS access */
		svsock = ConnectToServer(Conn,relay_input);
		break;
	      case C_VSAP:
	      { CStr(sockname,MaxHostNameLen);
		CStr(peername,MaxHostNameLen);
		sockname[0] = 0;
		sprintf(peername,"%s:%d",DST_HOST,DST_PORT);
		Verbose("-[%d,%d]- TRY VSAP ...\n",cx,ci);
		svsock = CTX_VSAPconnect(Conn,AVStr(sockname),AVStr(peername));
		if( 0 <= svsock )
			ServViaVSAP = 1;
		break;
	      }
	      case C_YYMUX:
		svsock = ConnectViaYYMUX(Conn,cty,relay_input);
		break;
	      case C_SOCKS:
	      {
		int socksonly,nodstcheck;
		/*
		if( GetViaSocks(Conn,DST_HOST,DST_PORT) ){
		*/
		if( (socksonly = (ci == 0 && order[ci+1] == 0))
		 || GetViaSocks(Conn,DST_HOST,DST_PORT) ){
			Verbose("-[%d,%d]- TRY SOCKS ...\n",cx,ci);
			if( socksonly ){
				nodstcheck = Conn->no_dstcheck;
				Conn->no_dstcheck |= 0x8;/*NO_SOCKSDST_CHECK*/
			}
			svsock = ConnectViaSocks(Conn,relay_input);
			if( socksonly ){
				Conn->no_dstcheck = nodstcheck;
			}
			if( 0 <= svsock )
				ServViaSocks = 1;
		}else{
			Verbose("-[%d,%d]- DON'T TRY SOCKS (conditional)\n",cx,ci);
			svsock = -1;
		}
		break;
	      }
	      case C_UDP:
		svsock = UDP_client_open1("connect",DST_PROTO,DST_HOST,DST_PORT,
			NULL,0);
		break;
	      case C_INTERNAL:
		Verbose("-[%d,%d]- TRY INTERNAL ... not supported\n",cx,ci);
		break;
	      case C_TELEPORT:
		Verbose("-[%d,%d]- TRY TELEPORT ...\n",cx,ci);
/*
		svsock = teleport_open(Conn,DST_HOST,relay_input);
*/
		break;
	    }
	}
	if( 0 <= svsock )
		ConnType = contype;

	*svsockp = svsock;
	return 1;
}

int CLALGconn(Connection *Conn,PCStr(command),int sock,PCStr(remote),PCStr(options));
int newSocket(PCStr(what),PCStr(opts));
extern int ACC_TIMEOUT;
int setREUSEADDR(int on);

int VSocket(Connection *Conn,PCStr(command),int sock,PVStr(local),xPVStr(remote),PCStr(options))
{	CStr(rhost,MaxHostNameLen);
	CStr(lhost,MaxHostNameLen);
	int rport,lport;
	int nlisten,nsock;
	int reuse;
	const char *dp;
	const char *rproto;
	CStr(rprotob,32);
	CStr(type,32);

	CStr(xremote,MaxHostNameLen);
	nonxalpha_escapeX(remote,AVStr(xremote),sizeof(xremote));
	if( strcmp(remote,xremote) != 0 ){
		sv1log("## escape host-name before Vsocket %s: %s\n",
			command,xremote);
		setPStr(remote,xremote,sizeof(xremote));
	}

	if( isinList(options,"self") )
		Conn->from_myself = 1;

	switch( *command ){
	  case 'q':
	  case 'Q':
		*(char*)options = 0; /* shoud be "const" */
		getpairName(sock,AVStr(local),AVStr(remote));
		break;

	/* ACCEPT */
	  case 'a':
	  case 'A':
		if( isUDPsock(sock) ){
			nsock = UDPaccept(sock,-1,ACC_TIMEOUT);
		}else
		nsock = ACCEPT(sock,0,-1,ACC_TIMEOUT);
		sock = nsock;
		if( 0 <= sock )
		{
			gethostName(sock,AVStr(local),"%A:%P");
			getpeerName(sock,AVStr(remote),"%A:%P");
		}
		break;

	 /* BIND */
	  case 'b':
	  case 'B':
		reuse = -1;
		if( isinList(options,"noreuseaddr") )
			reuse = setREUSEADDR(0);

		rport = 0;
		Xsscanf(remote,"%[^:]:%d",AVStr(rhost),&rport);
		lport = 0;
		Xsscanf(local,"%[^:]:%d",AVStr(lhost),&lport);
		if( lhost[0] == 0 || lhost[0] == '*' )
		if( rhost[0] != 0 && rhost[0] != '*' )
			hostIFfor(rhost,AVStr(lhost));
		nlisten = 0;
		if( strstr(options,"protocol=udp") )
			nlisten = -1;
		else
		if( strstr(options,"listen=") )
			sscanf(options,"listen=%d",&nlisten);
		{
		const char *proto;
		if( nlisten < 0 )
			proto = "udpbind";
		else	proto = "tcpbind";
		SRCIFfor(Conn,proto,rhost,rport,AVStr(lhost),&lport);
		}
		if( *lhost == '*' )
			lhost[0] = 0;
		if( 0 <= sock ){
			sv1log("VSocket: given socket[%d]\n",sock);
		}else
		sock = server_open("VSocket",AVStr(lhost),lport,nlisten);
		if( sock < 0 ){
			sock = ReservedPortSock(lhost,lport);
			if( 0 <= sock ){
				sv1log("VSocket: reserved port [%s:%d]\n",
					lhost,lport);
			}
		}
		if( 0 <= sock )
		{
		const char *proto;
			gethostName(sock,AVStr(local),"%A:%P");
			Xsscanf(local,"%[^:]:%d",AVStr(lhost),&lport);
			if( nlisten < 0 )
				proto = "udpbound";
			else	proto = "tcpbound";
			if( SRCIFfor(Conn,proto,rhost,rport,AVStr(lhost),&lport) )
				sprintf(local,"%s:%d",lhost,lport);
		}

		if( reuse != -1 )
			setREUSEADDR(reuse);
		break;

	/* CONNECT */
	  case 'c':
	  case 'C':
		/* Xsscanf(remote,"%[^:]:%d",AVStr(rhost),&rport); */
		type[0] = 0;
		Xsscanf(remote,"%[^:]:%d.%s",AVStr(rhost),&rport,AVStr(type));
		/*
		set_realserver(Conn,"tcprelay",rhost,rport);
		*/
		if( dp = strstr(options,"proto=") ){
			wordscanY(dp+6,AVStr(rprotob),sizeof(rprotob),"^,");
			rproto = rprotob;
		}else	rproto = "tcprelay";
		set_realserver(Conn,rproto,rhost,rport);

		if( 0 <= (sock = CLALGconn(Conn,command,sock,remote,options)) ){
		}else
		if( streq(type,"udp") || streq(rproto,"udprelay") ){
			sock = UDP_client_open(command,rproto,rhost,rport);
		}else
		sock = connect_to_serv(Conn,FromC,ToC,0);
		if( 0 <= sock )
		{
			gethostName(sock,AVStr(local),"%A:%P");
			if( isinList(options,"FSV") )
				insertFSV(Conn,FromC,sock);
		}
		break;

	  case 'n':
	  case 'N':
		if( sock < 0 )
			sock = newSocket(command,options);
		break;
	}
	sv1tlog("VSocket %s %s %s %s = %d\n",command,local,remote,options,sock);
	return sock;
}
int CTX_ToS(Connection *Conn){
	return ToS;
}
int CTX_FromS(Connection *Conn){
	return FromS;
}


int DELEGATE_forwardX(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,AuthInfo **rauth,const char **rhost,int *rport,const char **rpath);
int DELEGATE_forward(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,const char **rhost,int *rport,const char **rpath)
{
	return DELEGATE_forwardX(Conn,proto,dsthost,dstport,srchost,rproto,NULL,rhost,rport,rpath);
}
int DELEGATE_forwardX(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,AuthInfo **rauth,const char **rhost,int *rport,const char **rpath)
{	Route *Rp;
	int nd,ns,fi,fj;
	Server *pl;
	int found = 0;

	if( ForwardX == 0 )
		return 0;

	CTX_pushClientInfo(Conn); /* 9.9.7 for srcList=-Pxxx */
	for( fi = 0; fi < ForwardX; fi++ ){
	  Rp = Forwards[fi];
	  nd = Rp->m_dsts.hl_cnt;
	  ns = Rp->m_srcs.hl_cnt;

	  if( !Conn->no_dstcheck )
	  if( Rp->m_protoV )
	  if( (pl = protoMatch1(Conn,Rp->m_protoV,proto,dstport)) == NULL ){
		continue;
	  }
	  else{
		/*
		 * 9.9.3 filtering route by request method as
		 * FORWARD="delegate://Host:Port-_-http//POST"
		 */
		if( DO_METHOD_FILTER ){
			if( *RequestMethod ){
				if( methodMatch(Conn,pl,RequestMethod) == 0 ){
					continue;
				}
			}
		}
	  }

	  if( !nd || hostIsinList(&Rp->m_dsts,proto,dsthost,dstport,NULL) )
	  if( !ns || hostIsinList(&Rp->m_srcs,ANYP,srchost,0,Ident()) )
	    {
		*rproto = Rp->m_gw_proto;
		if( rauth )
		*rauth  = Rp->m_gw_auth;
		*rhost  = Rp->m_gw_host;
		*rport  = Rp->m_gw_port;
		*rpath  = Rp->m_gw_path;
		setConnectFlags("forward",Conn,Rp->m_ConnectFlags);
		found = 1;
		break;
		/*
		return 1;
		*/
	    }
	}
	HL_popClientInfo();
	return found;
	/*
	return 0;
	*/
}

int bindTeleportVehicle(int tx,int clsocks[],PCStr(host),int port,PCStr(tunnel),PCStr(invites));
int TeleportServer(PCStr(tunnel),PCStr(invites))
{	const char *host;
	int port;
	int pid;
	int mi;
	Route *Rp;

	pid = 0;
	for( mi = 0; mi < MasterX; mi++ ){
		Rp = Masters[mi];
		if( Rp->m_teleport == 0 )
			continue;

		host = Rp->m_gw_host;
		port = Rp->m_gw_port;
		pid = bindTeleportVehicle(mi+1,NULL,host,port,tunnel,invites);
		sv1log(">>>>>> Teleport[%d] <<<<<< %s:%d\n",pid,host,port);
	}
	return pid;
}

static void scan_MASTER0(Connection *Conn,PCStr(host),int port,PCStr(route),PCStr(filter))
{	int mi;
	Route *Rp;
	const char *host1;

	for( mi = 0; mi < MasterX; mi++){
		Rp = Masters[mi];
		host1 = Rp->m_gw_host;
		if( streq(host1,host) )
		if( Rp->m_gw_port == port ){
			Verbose("warning MASTER=%s duplicate\n",host);
			/*return;*/
		}
	}

	if( route )
		Verbose("MASTER=%s:%d/%s:%s\n",host,port,route,filter);
	else	Verbose("MASTER=%s:%d:%s\n",host,port,filter);

	mi = newRoute(MasterRoute);
	Rp = Masters[mi];

	if( route[0] ){
		if( isinListX(route,"ssl","/") ){
			Rp->m_ConnectFlags = scanConnectFlags("MASTER",
				route,Rp->m_ConnectFlags);
		}else
		if( strcasecmp(route,"NonHTTP") == 0 ){
			Rp->m_protoV_NonHTTP = 1;
		}else
		if( strcasecmp(route,"teleport") == 0 ){
			Rp->m_teleport = 1;
		}else
		if( strcasecmp(route,"cache") == 0 ){
			Rp->m_cacheonly = 1;
		}else
		sv1log("ERROR MASTER=%s:%d'/%s'?\n",host,port,route);
	}
	Rp->m_dsts.hl_what = StrAlloc("MASTER/FILTER");
	scan_commaListL(filter,STR_ALLOC,scanListCall addHostList1,&Rp->m_dsts);

	Rp->m_gw_host = StrAlloc(host);
	Rp->m_gw_port = port;

	if( !(Rp->m_teleport && streq(host,"tty7")) )
	if( !IsResolvable(host) )
		sv1log("ERROR unknown host MASTER=%s\n",host);

}
void scan_MASTER(Connection *Conn,PCStr(master))
{	CStr(host,1024);
	const char *dp;
	CStr(ports,1024);
	CStr(route,1024);
	CStr(filter,2048);
	int port;

	route[0] = 0;
	filter[0] = 0;
	if( *master == '*' ){
		Xsscanf(master,"*:%s",AVStr(filter));
		strcpy(host,"*");
		port = 0;
	}else
	if( Xsscanf(master,"%[^:]:%[^:]:%s",AVStr(host),AVStr(ports),AVStr(filter)) < 2 ){
		sv1log("ERROR MASTER=%s\n",master);
		return;
	}
	if( (dp = strchr(host,'/')) && dp != host ){
		truncVStr(dp); dp++;
		strcpy(route,dp);
	}
	if( dp = strchr(ports,'/') ){
		truncVStr(dp); dp++;
		strcpy(route,dp);
	}
	port = atoi(ports);
	scan_MASTER0(Conn,host,port,route,filter);
}
void scan_DIRECT(Connection *Conn,PCStr(hosts))
{
	scan_MASTER0(Conn,"@",0,"",hosts);
}

extern int FromTeleport;
extern int MASTER_ROUND_ROBIN;
int SERNO();
int nMASTERS(){ return MasterX; }
int DELEGATE_master(Connection *Conn,int ms,const char **master,int *mport,int *teleport,int *cacheonly)
{	int mn,mi;
	Route *Rp;

	mn = MasterX;
	if( mn == 0  ) return 0;
	if( mn <= ms ) return 0;

	if( MASTER_ROUND_ROBIN )
		mi = (SERNO() + ms) % mn;
	else	mi = ms % mn;
	Rp = Masters[mi];

/*
FromTeleport should be inherited via exec()
also MASTER_delegated table should be ...
(currently MASTER=tty7/teleport is not inherited, thus the problem will not occur)
	sv1log("FromTeleport:%d [%d]%x\n",FromTeleport,
		Rp->m_teleport);
*/
	if( FromTeleport && Rp->m_teleport ){
		sv1log("DONT LOOPBACK TO Teleport.\n");
		*master = NULL;
	}else
	{
		*master = Rp->m_gw_host;
		*mport  = Rp->m_gw_port;
		*teleport = Rp->m_teleport;
		*cacheonly = Rp->m_cacheonly;
		setConnectFlags("MASTER",Conn,Rp->m_ConnectFlags);
	}
	return mi+1;
}
int get_masterenv(int mx,const char **version,const char **server)
{	Route *Rp;

	Rp = Masters[mx-1];
	if( Rp->m_Version ){
		*version = Rp->m_Version;
		*server = Rp->m_SERVER;
		return 1;
	}else	return 0;
}
void set_masterenv(int mx,PCStr(version),PCStr(server))
{	Route *Rp;

	Rp = Masters[mx-1];
	Strdup((char**)&Rp->m_Version,version);
	Strdup((char**)&Rp->m_SERVER,server);
}

int DELEGATE_Filter(int mi,PCStr(dstproto),PCStr(dsthost),int dstport)
{	HostList *hostlist;
	int rcode;
	Route *Rp;

	Rp = Masters[mi-1];

	if( NonHTTP(Rp,dstproto) )
		return -1;

	hostlist = &Rp->m_dsts;
	if( hostlist->hl_cnt == 0 )
		return 0;

	if( hostIsinList(hostlist,dstproto,dsthost,dstport,NULL) )
		rcode = 0;
	else	rcode = -1;
	Verbose("filter[%d]: %s = %d\n",mi,dsthost,rcode);
	return rcode;
}


/*///////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	proxy.c (client for URL proxy server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940316	created
//////////////////////////////////////////////////////////////////////#*/

void scan_PROXY(Connection *Conn,PCStr(proxy))
{	const char *proto;
	CStr(host,MaxHostNameLen);
	CStr(proxyb,2048);
	CStr(protob,128);
	int port;
	CStr(filter,2048);
	CStr(route,2048);

	if( GatewayFlags & GW_IN_CLALG ){
		proto = REAL_PROTO;
	}else
	if( DFLT_PROTO[0] )
		proto = DFLT_PROTO;
	else	proto = "http";
	if( strstr(proxy,"://") ){
		Xsscanf(proxy,"%[^:]",AVStr(protob));
		if( 0 < (port = serviceport(protob)) ){
			proto = protob;
			proxy += strlen(proto) + strlen("://");
			if( strcaseeq(proto,"delegate") ){
				sv1log("MASTER=%s\n",proxy);
				scan_MASTER(Conn,proxy);
				return;
			}
			sv1log("PROXY = [%d/%s] %s\n",port,proto,proxy);
		}
	}

	port = 8080;
	strcpy(filter,"*");
	if( Xsscanf(proxy,"%[^:]:%d:%s",AVStr(host),&port,AVStr(filter)) == 0 ){
		syslog_ERROR("PROXY=%s ?\n",proxy);
	}else{
		if( *filter == '{' ){
			int len;
			ovstrcpy(filter,filter+1);
			len = strlen(filter);
			if( 0 < len && filter[len-1] == '}' )
				setVStrEnd(filter,len-1);
		}
		sprintf(route,"%s://%s:%d/%s{%s}:{%s}",
			proto,host,port,DELMARK,filter,"*");
		scan_ROUTE(Conn,route);
	}
}

/*
 * SOCKMUX=hort:port[:con,ssl,other-SOCKSCONF]
 */
static int Rsoxacc;
static const char *Rsoxhost;
static const char *Rsoxopts;
static int Rsoxport;
static const char *Lsoxhost;
static int Lsoxport;
static int Lsoxsock = -1;

int closeSoxLocal(){

	sv1log("## closeSoxLocal:%X:%d[%d]\n",p2i(Lsoxhost),Lsoxport,Lsoxsock);
	if( 0 < Lsoxport ){
		Lsoxhost = 0;
		Lsoxport = 0;
		close(Lsoxsock);
		Lsoxsock = -1;
	}
	return 0;
}

static int mySoxTid;
int stopSoxThread(){
	int tid;
	int err;
	if( tid = mySoxTid ){
		mySoxTid = 0;
		err = thread_destroy(tid);
		return err;
	}
	return -1;
}

static int mySoxPid;
static int mySoxSync[2] = {-1,-1};
int closeSoxSync(){
	int ss[2];
	if( 0 <= mySoxSync[0] ){
		ss[0] = mySoxSync[0]; mySoxSync[0] = -1;
		ss[1] = mySoxSync[1]; mySoxSync[1] = -1;
		close(ss[0]);
		close(ss[1]);
		return 1;
	}
	return 0;
}

void scan_SOCKMUX(Connection *Conn,PCStr(conf)){
	CStr(what,32);
	CStr(host,MaxHostNameLen);
	CStr(ports,128);
	CStr(opts,2048);
	int port;

	truncVStr(host);
	truncVStr(ports);
	truncVStr(opts);
	Xsscanf(conf,"%[^:]:%[^:]:%[^\n]",AVStr(host),AVStr(ports),AVStr(opts));
	port = atoi(ports);
	if( isinListX(opts,"acc","cw") ){
		Rsoxacc = 1;
	}else{
	}
	Rsoxhost = stralloc(host);
	Rsoxport = port;
	Rsoxopts = stralloc(opts);
}

#include "param.h"
char OutboundHTMUX[] = "-:0";
int allowOutboundHTMUX(int clnt);
int AccViaHTMUX;
extern int SoxOutPort;
static int SoxViaHTMUX;
int addServPort1(int sock,int port,int priv,int rident);
static int setSoxOutPort(){
	CStr(lhost,128);
	int xport = 0;
	int xsock = -1;

	if( 0 < SoxOutPort ){
		return -1;
	}
	strcpy(lhost,"localhost");
	xsock = server_open("PrivateSockMux",AVStr(lhost),0,20);
	xport = sockPort(xsock);
	SoxOutPort = xport;
	sv1log("%s[%d/%d] acc=%d\n",P_SOXOUTPORT,xport,xsock,Rsoxacc);
	addServPort1(xsock,SoxOutPort,1,1);
	return 0;
}
int openHTMUXproxy(Connection *Conn,PCStr(rport)){
	int psock;
	IStr(dhost,MaxHostNameLen);
	int dport;
	IStr(proxy,1024);
	IStr(opts,128);
	IStr(phost,MaxHostNameLen);
	int pport;
	int mapi;

	Xsscanf(rport,"%[^:]:%d",AVStr(dhost),&dport);
	mapi = find_CMAPX(Conn,"HTMUX_PROXY",AVStr(proxy),"http",dhost,dport,
		Client_Host,Client_Port,ClientAuthUser);
	if( mapi < 0 ){
		return -1;
	}
	Xsscanf(proxy,"%[^:]:%[^:]:%d",AVStr(opts),AVStr(phost),&pport);
	psock = client_open("HTMUX_proxy","HTMUX",phost,pport);
	return psock;
}
int iamServer();
void scan_HTMUX(Connection *Conn,PCStr(conf)){
	IStr(arg,MaxHostNameLen);
	IStr(opts,128);
	IStr(port,MaxHostNameLen);
	IStr(map,MaxHostNameLen);

	Xsscanf(conf,"%[^:]:%s",AVStr(opts),AVStr(port));
	if( isinList(opts,"px") ){
		ConfigFlags |= CF_HTMUX_PROXY;
		LOG_type4 |= L_HTTPACCEPT;
		sprintf(map,"{%s}:http:*:*",conf);
		scan_CMAP2(Conn,"HTMUX_PROXY",map);
		return;
	}
	if( isinList(opts,"sv") ){
		ConfigFlags |= CF_HTMUX_SERVER;
		LOG_type4 |= L_HTTPACCEPT;
		SoxViaHTMUX |= 1;
		sprintf(map,"{%s}:http:*:*",conf);
		scan_CMAP2(Conn,"HTMUX_SERVER",map);
	}
	if( isinList(opts,"cl") ){
		ConfigFlags |= CF_HTMUX_CLIENT;
		SoxViaHTMUX |= 2;
		AccViaHTMUX |= 2;
	}
	if( !iamServer() ){
		/* HTMUX port preparation must be only in the server */
		return;
	}
	if( isinList(opts,"sv") ){
		setSoxOutPort();
	}else{
		if( strchr(port,':') ){
			sprintf(arg,"%s/http",port);
			scan_VSAP(Conn,arg);
			sprintf(arg,"%s:con",port);
			scan_SOCKMUX(Conn,arg);
		}else{
		}
	}
}

int sox_main(int ac,const char *av[],DGC*ctx,int svsock,int svport);
static int mysox(int ac,const char *av[],int sock,int port){
	Connection ConnBuf,*Conn = &ConnBuf;
	ConnInit(Conn);
	Conn->co_mask |= CONN_NOPROXY;
	Conn->co_mask |= CONN_DIRECTONLY;
	ConfigFlags |= CF_WITH_MYSOX;
	sox_main(ac,av,Conn,sock,port);
	return 0;
}
int isPrivateSox(Connection *Conn){
	return ConfigFlags & CF_WITH_MYSOX;
}

static char *tsprintf(PVStr(str),PCStr(fmt),...){
	const char *next;
	VARGS(16,fmt);

	sprintf(str,fmt,VA8);
	next = str + strlen(str) + 1;
	return (char*)next;
}
#define addarg	av[ac++] = ap; ap = tsprintf

int readTimeout(int fd,PVStr(b),int z,int tout);
int readReady(int fd,PVStr(buf),int siz){
	refQStr(bp,buf);
	const char *px;
	int cc1;
	int cc = 0;

	px = &buf[siz-1];
	for( bp = buf; bp < px && 0 < PollIn(fd,1); bp++ ){
		cc1 = readTimeout(fd,AVStr(bp),1,1);
		if( cc1 <= 0 )
			break;
		if( *bp == 0 ){
			break;
		}
		if( siz <= ++cc ){
			break;
		}
	}
	setVStrEnd(bp,0);
	return bp-buf;
}
int recvHTMUXnotify(int sync[2]){
	IStr(buf,128);
	int rcc;
	double St = Time();

	if( 0 < PollIn(sync[0],8*1000) ){
		rcc = readReady(sync[0],AVStr(buf),sizeof(buf));
		sv1log("#### SockMux Started: (%.2f) '%s'\n",Time()-St,buf);
	}else{
		rcc = -2;
		sv1log("#### SockMux Start Timeout: (%.2f)\n",Time()-St);
	}
	return rcc;
}

int TimeoutWait(double To);
int DELEGATE_copyEnvPM(int mac,const char *dav[],PCStr(name));
void scanServPort(PCStr(portspecs));
int startSockMux(){
	CStr(ab,2048);
	refQStr(ap,ab);
	const char *av[32];
	int ac,ai;
	int pid;
	int svsock;
	int svport;
	int sock;
	CStr(lhost,128);
	CStr(portarg,MaxHostNameLen);
	int asock = -1;
	int sync[2];

	if( Rsoxhost == 0 )
		return 0;

	/*
	 * a socekt to accept connections from SockMux
	 */
	svport = SERVER_PORT();
	if( AccViaHTMUX ){
		/* connect-only HTMUX client don't have a remote port */
	}else
	if( svport == 0 ){
		strcpy(lhost,"localhost");
		svsock = server_open("PrivateSockMux",AVStr(lhost),0,20);
		svport = sockPort(svsock);
		sprintf(portarg,"-Plocalhost:%d.sox/%d",svport,svsock);
		scanServPort(portarg+2);
	}

	strcpy(lhost,"localhost");
	sock = server_open("PrivateSockMux",AVStr(lhost),0,20);
	if( sock < 0 ){
		return -1;
	}
	Lsoxhost = "localhost";
	Lsoxport = sockPort(sock);
	Lsoxsock = sock;

	ac = 0;
	ap = ab;

	if( SoxViaHTMUX ){
		IStr(ports,1024);

		addarg(AVStr(ap),"-Fsockmux");
		if( svport )
			printServPort(AVStr(ports),"",0x0800); /* remote only */
		if( ports[0] == 0 ){
			/* no remote static port, outbound request only */
			strcpy(ports,OutboundHTMUX);
			allowOutboundHTMUX(1);
		}
		addarg(AVStr(ap),"%s=%s",P_SOXINPORTS,ports);
		setSoxOutPort();
		addarg(AVStr(ap),"%s=%d",P_SOXOUTPORT,SoxOutPort);
	}
	IGNRETZ pipe(sync);
	mySoxSync[0] = sync[0];
	mySoxSync[1] = sync[1];
	addarg(AVStr(ap),"%s=%d",P_SYNCHTMUX,sync[1]);

	if( Rsoxacc ){
		addarg(AVStr(ap),"SERVER=sockmux");
		addarg(AVStr(ap),"-P%s:%d",Rsoxhost,Rsoxport);
		if( lSINGLEP() ){
			IStr(xhost,128);
			strcpy(xhost,Rsoxhost);
			asock = server_open("SockMux",AVStr(xhost),Rsoxport,20);
		}
	}else{
		addarg(AVStr(ap),"SERVER=sockmux://%s:%d",Rsoxhost,Rsoxport);
	}
	if( isinListX(Rsoxopts,"ssl","wc") ){
		addarg(AVStr(ap),"SOXCONF=crypt:no");
		if( Rsoxacc ){
			addarg(AVStr(ap),"FCL=sslway");
		}else{
			addarg(AVStr(ap),"FSV=sslway");
		}
	}

	addarg(AVStr(ap),"SERVER=tcprelay://localhost:%d,-in",svport);
	addarg(AVStr(ap),"PORT=%s:%d/%d",Lsoxhost,Lsoxport,sock);
	if( Rsoxacc ){
	}else
	addarg(AVStr(ap),"RELIABLE=localhost");

	/* if SERVER=ppp -Pxxx and SOCKMUX=host:xxx:acc (shareing xxx) */
	if( Rsoxacc && SERVER_PORT() && SERVER_PORT() == Rsoxport ){
	addarg(AVStr(ap),"MAXIMA=service:1"); /* accept SockMux only once */
	}
	addarg(AVStr(ap),"SOXCONF=private"); /* accept SockMux only once */
	addarg(AVStr(ap),"SOXCONF=connauth"); /* auth for each conneciton */

	addarg(AVStr(ap),"DGROOT=%s",DELEGATE_DGROOT);
	addarg(AVStr(ap),"ADMIN=%s",getADMIN());
	addarg(AVStr(ap),"-L0x%X/%d",LOG_type,curLogFd());
	{
		IStr(logfile,1024);
		strcpy(logfile,DELEGATE_LOGFILE);
		Substfile(logfile);
		addarg(AVStr(ap),"LOGFILE=%s",logfile);
	}
	addarg(AVStr(ap),"-L20x%X",LOG_type2);
	addarg(AVStr(ap),"-L30x%X",LOG_type3);
	addarg(AVStr(ap),"-L40x%X",LOG_type4);
/* fix-120202a stop beDaemon() detected as "PrivateSox Failure" 9.9.0-pre2 */
addarg(AVStr(ap),"-f");

	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"SOXCONF");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"CONNECT");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"SOCKS");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"SSLTUNNEL");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"TUNNEL");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"TLSCONF");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"STLS");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"FSV");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"FCL");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],"CMAP");
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],P_MYAUTH);
	ac += DELEGATE_copyEnvPM(elnumof(av)-ac,&av[ac],P_TIMEOUT);
	av[ac] = 0;

	for( ai = 0; ai < ac; ai++ ){
		fprintf(stderr,"PrivateSOX[%d] %s\n",ai,av[ai]);
	}

	if( lSINGLEP() ){
		char **nav;
		nav = Dupv(av);
		if( Rsoxacc ){
			IStr(map,MaxHostNameLen);
			sprintf(map,"{tcprelay://localhost:%d,-in}:vp_in:*:/u",svport);
			scan_CMAP2(MainConn(),"XSERVER",map);
			mySoxTid =
	thread_fork(0x120000,0,"SockMux",(IFUNCP)mysox,ac,nav,asock,Rsoxport);
		}else
			mySoxTid =
	thread_fork(0x120000,0,"SockMux",(IFUNCP)mysox,ac,nav,sock,Lsoxport);
		recvHTMUXnotify(sync);
		return 0;
	}
	pid = spawnv_self1(ac,av);

	recvHTMUXnotify(sync);
	if( TimeoutWait(0.1) == pid ){
		porting_dbg("#### PrivateSox Failure  ####");
		Finish(0);
	}
	mySoxPid = pid;
	return pid;
}
void forward_RIDENT(Connection *Conn,int where,int svsock,PCStr(ident));
int connectToSox(Connection *Conn,PCStr(wh),PCStr(proto),PCStr(host),int port){
	int sock;
	if( Lsoxhost == 0 ){
		return -1;
	}
	/*
	if( client is from a SockMux ){
		return -1;
	}
	*/
	sock = client_open(wh,proto,Lsoxhost,Lsoxport);
	if( sock < 0 ){
	}

	forward_RIDENT(Conn,'x',sock,NULL);
	return sock;
}

int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock);
int connectViaUpper(Connection *Conn,PCStr(where),PCStr(proto),PCStr(host),int port){
	int sock;
	int routex;
	const char *shost = "";

	if( 0 <= (sock = connectToSox(Conn,where,proto,host,port)) )
		return sock;

	shost = Client_Host;
	routex = findRoute(Conn,Forwards,0,ForwardX,proto,host,shost);
	if( 0 <= routex ){
		Route *Rp;
		Rp = Forwards[routex];
		if( streq(Rp->m_gw_proto,"ssltunnel") ){
			sock = OpenServer("ToUpper",Rp->m_gw_proto,
				Rp->m_gw_host,Rp->m_gw_port);
			if( 0 <= sock ){
				Connection XConn = *Conn;
				SSLtunnelNego(&XConn,host,port,sock);
			}
			return sock;
		}
		if( streq(Rp->m_gw_proto,"socks") ){
		}
	}
	return -1;
}

int connectToUpper(Connection *Conn,PCStr(where),PCStr(proto),PCStr(host),int port)
{	int routex;
	const char *shost = "";
	const char *orders;
	int sock;

	if( 0 <= (sock = connectToSox(Conn,where,proto,host,port)) )
		return sock;

	shost = Client_Host;
	routex = findRoute(Conn,Connects,0,ConnectX,proto,host,shost);
	if( 0 <= routex ){
		orders = Connects[routex]->m_conn;
		if( strchr(orders,C_SOCKS) ){
			sock = connectViaSocks(Conn,host,port,VStrNULL,NULL);
			sv1log("%s '%s' via SOCKS = %d\n",where,proto,sock);
			return sock;
		}
		if( strchr(orders,C_SSLTUNNEL) ){
			sock = ConnectViaSSLtunnel(Conn,host,port);
			sv1log("%s '%s' via SSLtunnel = %d\n",where,proto,sock);
			return sock;
		}
	}
	return OpenServer("ToUpper",proto,host,port);
	/*
	return client_open(where,proto,host,port);
	*/
}

static const char *SSLTUNNEL_HOST;
static int SSLTUNNEL_PORT;
void scan_SSLTUNNEL(PCStr(spec))
{	CStr(host,MaxHostNameLen);
	int port;

	port = 8080;
	if( Xsscanf(spec,"%[^:]:%d",AVStr(host),&port) < 1 )
		return;
	if( !IsResolvable(host) ){
		sv1log("#### Unknown host -- SSLTUNNEL=%s:%d",host,port);
		return;
	}
	SSLTUNNEL_HOST = StrAlloc(host);
	SSLTUNNEL_PORT = port;
}

extern int HTTP11_toserver;
int ConnectViaSSLtunnelX(Connection *Conn,PCStr(host),int port,int svsock);
int ConnectViaSSLtunnel(Connection *Conn,PCStr(host),int port)
{
	return ConnectViaSSLtunnelX(Conn,host,port,-1);
}
int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock);
int ConnectViaSSLtunnelX(Connection *Conn,PCStr(host),int port,int svsock)
{	int sock;

	if( 0 <= svsock ){
		sock = svsock;
		GatewayPort = getpeerNAME(sock,AVStr(GatewayHost));
		if( ServerFlags & PF_IS_MASTER )
			strcpy(GatewayProto,"delegate");
		else	strcpy(GatewayProto,"ssltunnel");
	}else{
	if( SSLTUNNEL_HOST == NULL || SSLTUNNEL_PORT == 0 )
		return -1;
	sock = client_open("SSLtunnel","http",SSLTUNNEL_HOST,SSLTUNNEL_PORT);
	if( sock < 0 )
		return -1;

	strcpy(GatewayProto,"ssltunnel"); /* for makeAuthorization() */
	strcpy(GatewayHost,SSLTUNNEL_HOST);
	GatewayPort = SSLTUNNEL_PORT;
	}


	if( 0 <= SSLtunnelNego(Conn,host,port,sock) )
		return sock;

	close(sock);
	return -1;
}
int ConnectViaSSLtunnelXX(Connection *Conn,PCStr(shost),int sport,PCStr(host),int port){
	int sock;
	sock = client_open("SSLtunnel","http",shost,sport);
	if( 0 <= sock ){
		if( 0 <= SSLtunnelNego(Conn,host,port,sock) ){
			return sock;
		}
		close(sock);
	}
	return -1;
}
int ftpdataViaSSLtunnel(Connection *Conn,PCStr(host),int port){
	int lsock = -1;
	int ssock;

	if( ServerFlags & PF_VIA_CONNECT )
	if( GatewayHost[0] && GatewayPort )
	{
		ssock = client_open("SSLtunnel","http",GatewayHost,GatewayPort);
		if( 0 <= ssock ){
			lsock = SSLtunnelNego(Conn,host,port,ssock);
		}
	}
	return lsock;
}
int SSLtunnelNegoX(Connection *Conn,PCStr(host),int port,int sock,PVStr(rhost),PVStr(rpeer));
int SSLtunnelNego(Connection *Conn,PCStr(host),int port,int sock){
	return SSLtunnelNegoX(Conn,host,port,sock,VStrNULL,VStrNULL);
}
int SSLtunnelNegoX(Connection *Conn,PCStr(host),int port,int sock,PVStr(rhost),PVStr(rpeer)){
	CStr(genauth,1024);
	CStr(auth,1024);
	CStr(msg,1024);
	CStr(resp,4096);
	CStr(ver,1024);
	int wcc,rcc,rcode;
	const char *qver;
	int timeout;

	if( HTTP11_toserver == 3 )
		qver = "1.1";
	else	qver = "1.0";
	sprintf(msg,"CONNECT %s:%d HTTP/%s\r\n\r\n",host,port,qver);
	if( makeAuthorization(Conn,AVStr(genauth),1) ){
		sprintf(auth,"Proxy-Authorization: %s\r\n",genauth);
		RFC822_addHeaderField(AVStr(msg),auth);
	}
	set_nodelay(sock,1); /* to reduce delay on CONNECT + SSL nego. */

	sv1log("SSL-TUNNEL<< %s:%d\n",host,port);
	wcc = write(sock,msg,strlen(msg));

	timeout = 30*1000;
	if( PollIn(sock,timeout) <= 0 ){
		sv1log("SSL-TUNNEL<< %s:%d TIMEOUT(%d)\n",host,port,timeout);
		return -4;
	}
	rcc = RecvLine(sock,resp,sizeof(resp));
	if( rcc <= 0 )
		return -1;
	sv1log("SSL-TUNNEL>> %s",resp);
	if( Xsscanf(resp,"%s %d",AVStr(ver),&rcode) != 2 )
		return -2;
	if( rcode != 200 )
		return -3;

	if( rhost ) clearVStr(rhost);
	if( rpeer ) clearVStr(rpeer);
	for(;;){
		rcc = RecvLine(sock,resp,sizeof(resp));
		if( rcc <= 0 )
			return -3;
		sv1log("SSL-TUNNEL>> %s",resp);
		if( resp[0] == '\r' || resp[0] == '\n' )
			break;
		if( rhost && strneq(resp,"X-Host:",7) ){
			wordscanX(resp+7,BVStr(rhost),MaxHostNameLen);
		}
		if( rpeer && strneq(resp,"X-Peer:",7) ){
			wordscanX(resp+7,BVStr(rpeer),MaxHostNameLen);
		}
	}
	/* if this is the nearest upstream proxy ... */
	ServerFlags |= PF_VIA_CONNECT;
	return sock;
}

int RIDENT_sendX(int sock,PCStr(sockname),PCStr(peername),PCStr(ident));
int getClientSockPeer(PVStr(sockname),PVStr(peername));
void forward_RIDENT(Connection *Conn,int where,int svsock,PCStr(ident))
{	CStr(sockname,512);
	CStr(peername,512);

	if( ServerFlags & PF_RIDENT_OFF )
		return;
	if( RIDENT_SERVER == 0 && (ServerFlags & PF_RIDENT) == 0 )
		return;
	if( ServerFlags & PF_RIDENT_SENT )
		return;
	if( TeleportHost[0] && TeleportPort ){
		sprintf(sockname,"%s:%d",TelesockHost,TelesockPort);
		if( TeleportAddr[0] )
		sprintf(peername,"%s:%d",TeleportAddr,TeleportPort);
		else
		sprintf(peername,"%s:%d",gethostaddrX(TeleportHost),TeleportPort);
		/*
		sprintf(peername,"%s:%d",gethostaddr(TeleportHost),TeleportPort);
		*/
	}else
	if( (ClientFlags & PF_STLS_ON) && 0 < Client_Port ){
		/* ClientSock was overwritten by SSLway socket with dup2().
		 */
		if( getClientSockPeer(AVStr(sockname),AVStr(peername)) != 0 ){
			sprintf(sockname,"0.0.0.0:%d",Conn->clif._acceptPort);
			Client_Addr(peername);
			Xsprintf(TVStr(peername),":%d",Client_Port);
		}
		sv1log("#### RIDENT_sendX(%s,%s)\n",peername,sockname);
	}else{
		getpairName(ClientSock,AVStr(sockname),AVStr(peername));
	}

	RIDENT_sendX(svsock,sockname,peername,ident);
	ServerFlags |= PF_RIDENT_SENT;
}
void makeProxyRequest(Connection *Conn);
void connected_to_proxy(Connection *Conn,PCStr(req),int clsock)
{
	forward_RIDENT(Conn,'p',clsock,NULL);

	/* insert_FSERVER can already be done in ICP connect_to_serv()... */
	if( (Conn->xf_filters & XF_SERVER) == 0 )
		insert_FSERVER(Conn,ClientSock);

	if( (Conn->xf_filters & XF_FSV) && streq(DST_PROTO,"https") ){ 
		sv1log("## INSERTED FSV for HTTPS and CONNECT\n");
		return;
	}
	makeProxyRequest(Conn/*,req,req*/);
}

void redirect_url(Connection *Conn,PCStr(url),PVStr(durl))
{	CStr(turl,2048);
	CStr(myhost,MaxHostNameLen);
	int myport;
	int len;

	if( DONT_REWRITE || is_redirected_url(url) )
		strcpy(durl,url);
	else{
		if( url == durl ){
			strcpy(turl,url);
			url = turl;
		}

		if( Conn->my_vbase.u_proto ){
			len = CTX_url_rurlX(Conn,0,url,AVStr(durl),
				Conn->my_vbase.u_proto,
				Conn->my_vbase.u_host,Conn->my_vbase.u_port,
				Conn->my_vbase.u_path,DO_DELEGATE);
		}else{
			myport = HTTP_ClientIF_H(Conn,AVStr(myhost));
			len = CTX_url_rurlX(Conn,0,url,AVStr(durl),
				CLNT_PROTO,
				myhost,myport,Conn->cl_baseurl,DO_DELEGATE);
		}

		if( len == 0 )
			strcpy(durl,url);
	}
}

/*
 * translate a gopher selector to a URL
 */
void gopherreq_to_URL(PVStr(req),PVStr(url))
{	char gtype;
	CStr(sel,1024);
	CStr(search,1024);

	gtype = get_gtype(req,AVStr(req));
	sprintf(url,"%c%s",gtype,req);

	if( gtype == '7' )
	if( Xsscanf(url,"%[^\t]\t%[^\t\r\n]",AVStr(sel),AVStr(search)) == 2 ){
		nonxalpha_escapeX(sel,AVStr(sel),sizeof(sel));
		nonxalpha_escapeX(search,AVStr(search),sizeof(search));
		sprintf(url,"%s?%s",sel,search);
	}
}

int is_http_method(PCStr(method))
{
	if( 0 == strcasecmp(method,"GET") )  return 1;
	if( 0 == strcasecmp(method,"PUT") )  return 1;
	if( 0 == strcasecmp(method,"POST") ) return 1;
	if( 0 == strcasecmp(method,"HEAD") ) return 1;
	return 0;
}

void icp_server(int sock);
int service_icp(Connection *Conn,int sock,int port)
{
	icp_server(sock /*,port*/);
	return 0;
}

#define NUMPEER		32
#define IC_PARENT	0x01
#define PX_DELEGATE	0x10
#define PX_ORIGINPROXY	0x20
#define PX_ORIGINSERVER	0x40

extern int ICP_DEBUGLOG;

int icp_getconf(PCStr(conf),int icptypes[],const char *icpaddrs[],int icpports[],const char *pxaddrs[],int pxports[],double *timeout,PVStr(buff));

int icp_select(PCStr(url),int icpopts[],const char *svaddrs[],int svports[],double timeout,FILE *log,PVStr(sxaddr),int *sxport,int first,int *hitobj,PVStr(objbuf));
int icp_selectconf(PVStr(conf),PCStr(dproto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser));

int select_icpconf(Connection *Conn,xPVStr(icpconf))
{	CStr(shost,MaxHostNameLen);
	const char *suser;
	int sport;
	CStr(tmpbuf,1024);

	if( icpconf == NULL )
		setPStr(icpconf,tmpbuf,sizeof(tmpbuf));

	sport = getClientHostPort(Conn,AVStr(shost));
	suser = Ident();
	if( icp_selectconf(AVStr(icpconf),DST_PROTO,DST_HOST,DST_PORT,
		shost,sport,suser) < 0 )
		return 0;
	return 1;
}

void setToProxy(Connection *Conn,PCStr(proto),PCStr(host),int port);
int HTTP_getICPurl(Connection *Conn,PVStr(url));

int ConnectViaICP(Connection *Conn,PCStr(dsturl))
{	int sock;
	int icptypes[NUMPEER];
	const char *icpaddrs[NUMPEER]; /**/
	int icpports[NUMPEER];
	int nserv;
	int sx;
	CStr(url,URLSZ);
	CStr(sxaddr,64);
	int sxport;
	const char *pxhost;
	int pxport;
	int pxtype,pxtypes[NUMPEER];
	const char *pxaddrs[NUMPEER]; /**/
	int pxports[NUMPEER];
	double timeout;
	int *objsize;
	CStr(objbuff,URLSZ);
	CStr(icpconf,128);
	int parent;
	CStr(addrbuff,1024);
	CStr(msg,1024);
	double Start,Connect;
	FILE *log = stderr;
	CStr(urlhead,1024);

	if( !strcaseeq(iSERVER_PROTO,"http")
	 && !strcaseeq(iSERVER_PROTO,"nntp")
	 && !strcaseeq(iSERVER_PROTO,"ftp" )
	)	return -1;

	if( !select_icpconf(Conn,AVStr(icpconf)) )
		return -1;

	Start = Time();
	parent = 0;
	nserv = icp_getconf(icpconf,icptypes,icpaddrs,icpports,
		pxaddrs,pxports,&timeout,AVStr(addrbuff));

	for( sx = 0; sx < nserv; sx++ ){
		if( icptypes[sx] & IC_PARENT )
			parent++;
	}

	if( PragmaNoCache ){
		if( parent == 0 )
			return -1;
		else	objsize = NULL;
	}else{
		if( strcaseeq(DST_PROTO,"http") )
			objsize = &Conn->ca_objsize;
		else	objsize = NULL;
	}

	if( dsturl ){
		strcpy(url,dsturl);
	}else
	if( HTTP_getICPurl(Conn,AVStr(url)) != 0 ){
		if( parent == 0 )
			return -1;
		/* just to select the parent */
		sprintf(url,"%s://",DST_PROTO);
		HostPort(TVStr(url),DST_PROTO,DST_HOST,DST_PORT);
		objsize = NULL;
	}
	sprintf(urlhead,"%s://",DST_PROTO);
	HostPort(TVStr(urlhead),DST_PROTO,DST_HOST,DST_PORT);

	sx = icp_select(url,icptypes,icpaddrs,icpports,timeout,log,
		AVStr(sxaddr),&sxport,1,objsize,AVStr(objbuff));
	if( sx < 0 ){
		sprintf(msg,"(ICP-FAIL) %5.3f <%s>",Time()-Start,urlhead);
		sv1log("%s\n",msg);
		if( ICP_DEBUGLOG ) fprintf(log,"%s\n",msg);
		return -1;
	}

	if( 0 <= Conn->ca_objsize ){
		int io[2];
		Socketpair(io);
		setsockbuf(io[1],0,Conn->ca_objsize);
		IGNRETP write(io[1],objbuff,Conn->ca_objsize);
		close(io[1]);

		sprintf(msg,"(ICP-HITO) %5.3f [%s:%d] = %d <%s>",
			Time()-Start,
			icpaddrs[sx],icpports[sx],Conn->ca_objsize,urlhead);
		sv1log("%s\n",msg);
		if( ICP_DEBUGLOG ) fprintf(log,"%s\n",msg);
		return io[0];
	}

	if( strcmp(sxaddr,icpaddrs[sx]) == 0 )
		pxhost = pxaddrs[sx];
	else	pxhost = sxaddr;
	pxport = pxports[sx];
	pxtype = icptypes[sx];
	Connect = Time();

	sock = connectToUpper(Conn,"ICP-PROXY",DST_PROTO,pxhost,pxport);

	sprintf(msg,"(ICP-SUCC) %5.3f [%d][%s]>[%s]>%x[%s:%d]>(%d) %5.3f <%s>",
		Connect-Start,sx,icpaddrs[sx],sxaddr,
		pxtype,pxhost,pxport,sock,Time()-Connect,urlhead);
	sv1log("%s\n",msg);
	if( ICP_DEBUGLOG ) fprintf(log,"%s\n",msg);

	if( 0 <= sock ){
		if( pxtype & PX_ORIGINSERVER ){
		}else
		if( pxtype & PX_DELEGATE ){
			toMaster = 1;
		}else{
			setToProxy(Conn,"http",pxhost,pxport);
		}
	}

	return sock;
}

int ConnectViaICP(Connection *Conn,PCStr(dsturl));
FILE *fopen_ICP(Connection *Conn,PCStr(url),FileSize *sizep,int *datep)
{	int sock;
	FILE *ts,*fs;
	CStr(req,URLSZ);
	CStr(resp,128);
	const char *vp;

	sock = ConnectViaICP(Conn,url);

	if( 0 <= sock ){
		ts = fdopen(dup(sock),"w");
		fprintf(ts,"GET %s HTTP/1.0\r\n",url);
		fprintf(ts,"User-Agent: DeleGate/%s\r\n",DELEGATE_ver());
		fprintf(ts,"\r\n");
		fclose(ts);
		/*
		 * fgets () should be used but cannot be used because
		 * client FTP-DeleGate expects returned FILE pointing to
		 * the top of the target FILE and use read (fileno(FILE),...)
		 */
		while( 0 < RecvLine(sock,resp,sizeof(resp)) ){
			if( resp[0] == '\r' || resp[0] == '\n' )
				break;
			if( strncasecmp(resp,"Content-Length:",15) == 0 )
				Xsscanf(resp+15,"%lld",sizep);
			else
			if( strncasecmp(resp,"Date:",5) == 0 ){
				vp = resp+5;
				while( *vp == ' ' )
					vp++;
				*datep = scanHTTPtime(vp);
			}
		}
		sv1log("#### fopen_ICP(%s) = [%d] %lld %d\n",url,sock,*sizep,*datep);

		fs = fdopen(sock,"r");
		return fs;
	}
	return 0;
}
