const char *SIGN_winmo_c="{FILESIGN=wince.c:20141022165616+0900:d01288c8e9e396a8:Author@DeleGate.ORG:llE3jOZv6JViqir3ikBcwE4fh1HiYkmW4ucmBQ5MzDtEvmJ2W4iqQbtvaXNxrjVUcwyD+7qayaj0FOdCjsDP9ETZ9kpGLazHd1RhSEcUcy8izLd7W85OLVfCg98ItFXFs3npXKzbRdkSD7GlgEKKkloQDUjMIRcibrthg80lC+I=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2007-2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use,
without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	winmo.c (for Windows Mobile)
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
	- Connection management
	- Power management
	- Routing control
History:
	080523	extracted from wince.c
//////////////////////////////////////////////////////////////////////#*/
/* '"DiGEST-OFF"' */

/* FrOM-HERE
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */

#ifdef _MSC_VER /*{*/

#define UNICODE
#include <WINDOWS.H>
#include <WINBASE.H>
#include <Time.h>
#include "ystring.h"
#include "file.h"
#include "log.h"

#if 1400 <= _MSC_VER /*{*/

#define SECURITY_WIN32
#include <Security.h>
#include <Psapi.h>
#include <Iphlpapi.h>

#ifdef UNDER_CE
#include <Pm.h>
#include <PmPolicy.h>
#include <Connmgr.h>
#include <Connmgr_status.h>
#endif
#ifndef UNDER_CE
#include <Ras.h>
#endif

int gethostintMin(PCStr(host));
int gethostint_nboV4(PCStr(host));
int strCRC32(PCStr(str),int len);
static int noDfltRoute;
static int curRouteTab;

#define WINMO_DLL 1
#if defined(WINMO_DLL) /*{*/
#ifdef UNDER_CE
static HRESULT (WINAPI*PTR_ConnMgrQueryDetailedStatus)(CONNMGR_CONNECTION_DETAILED_STATUS *pStatBuf,DWORD *pcbBufSz);
static HRESULT (WINAPI*PTR_ConnMgrEnumDestinations)(int idx,CONNMGR_DESTINATION_INFO *pDi);
static HRESULT (WINAPI*PTR_ConnMgrMapURL)(LPTSTR pwszURL,GUID *pguid,DWORD *pdwIdx); 
static HRESULT (WINAPI*PTR_ConnMgrMapConRef)(ConnMgrConRefTypeEnum e,LPCTSTR szConRef,GUID *pGUID);
static HRESULT (WINAPI*PTR_ConnMgrReleaseConnection)(HANDLE hConn,LONG lCache);
static HRESULT (WINAPI*PTR_ConnMgrConnectionStatus)(HANDLE hConn,DWORD *pdwStat);
static HRESULT (WINAPI*PTR_ConnMgrEstablishConnection)(CONNMGR_CONNECTIONINFO *pConnInfo,HANDLE * phConn);
#endif
#ifndef UNDER_CE
static DWORD (WINAPI*PTR_RasGetConnectStatus)(HRASCONN rc,LPRASCONNSTATUS rcs);
static DWORD (WINAPI*PTR_RasEnumConnections)(LPRASCONN rc,LPDWORD cb,LPDWORD cC);
static BOOL (WINAPI*PTR_GetProcessMemoryInfo)(HANDLE,PROCESS_MEMORY_COUNTERS*,DWORD);
#endif

static BOOL (WINAPI*PTR_QuerySecurityContextToken)(CtxtHandle*,HANDLE);
static HANDLE (WINAPI*PTR_IcmpCreateFile)(); 
static DWORD (WINAPI*PTR_IcmpCloseHandle)(HANDLE ih); 
static DWORD (WINAPI*PTR_IcmpSendEcho)(HANDLE ih,IPAddr da,LPVOID qd,WORD qz,PIP_OPTION_INFORMATION qo,LPVOID rb,DWORD rz,DWORD to);

static DWORD (WINAPI*PTR_GetNetworkParams)(PFIXED_INFO pFixedInfo,PULONG pOutBufLen);
static DWORD (WINAPI*PTR_GetIfTable)(MIB_IFTABLE *pIfTab,ULONG *pdwSz,BOOL bOrder);
static DWORD (WINAPI*PTR_GetIfEntry)(MIB_IFROW *pIfRow);
static DWORD (WINAPI*PTR_GetIpNetTable)(PMIB_IPNETTABLE ipNetTab,PULONG Sz,BOOL Ord);
static DWORD (WINAPI*PTR_GetIpForwardTable)(MIB_IPFORWARDTABLE *pIpForwTab,ULONG *pdwSize,BOOL bOrder);
static DWORD (WINAPI*PTR_SendARP)(IPAddr dst,IPAddr src,PULONG macA,PULONG macL);

typedef DWORD (WINAPI*GetTcpTable_t)(MIB_TCPTABLE*,DWORD*,BOOL);
static DWORD (WINAPI*PTR_GetTcpTable)(MIB_TCPTABLE *TcpTable,DWORD *Sz,BOOL Ord);
static DWORD (WINAPI*PTR_GetTcpStatistics)(MIB_TCPSTATS *pStats);
static DWORD (WINAPI*PTR_GetIpStatistics)(MIB_IPSTATS *pStats);

static BOOL (WINAPI*PTR_PowerPolicyNotify)(DWORD dwMessage,DWORD dwData);

extern "C" {
	void *dlopen(const char *path,int mode);
	void *dlsym(void *handle,const char *symbol);
}
static struct {
	char *name;
	void *addr;
} symaddr[] = {
	{"PowerPolicyNotify",		&PTR_PowerPolicyNotify},
#ifdef UNDER_CE
	{"ConnMgrQueryDetailedStatus",	&PTR_ConnMgrQueryDetailedStatus},
	{"ConnMgrEnumDestinations",	&PTR_ConnMgrEnumDestinations},
	{"ConnMgrMapURL",		&PTR_ConnMgrMapURL},
	{"ConnMgrMapConRef",		&PTR_ConnMgrMapConRef},
	{"ConnMgrReleaseConnection",	&PTR_ConnMgrReleaseConnection},
	{"ConnMgrConnectionStatus",	&PTR_ConnMgrConnectionStatus},
	{"ConnMgrEstablishConnection",	&PTR_ConnMgrEstablishConnection},
#endif
#ifndef UNDER_CE
	{"RasGetConnectStatusW",	&PTR_RasGetConnectStatus},
	{"RasEnumConnectionsW",		&PTR_RasEnumConnections},
	{"GetProcessMemoryInfo",	&PTR_GetProcessMemoryInfo},
	{"QuerySecurityContextToken",	&PTR_QuerySecurityContextToken},
#endif
	{"IcmpCreateFile",		&PTR_IcmpCreateFile},
	{"IcmpCloseHandle",		&PTR_IcmpCloseHandle},
	{"IcmpSendEcho",		&PTR_IcmpSendEcho},
	{"GetNetworkParams",		&PTR_GetNetworkParams},
	{"GetIfTable",			&PTR_GetIfTable},
	{"GetIfEntry",			&PTR_GetIfEntry},
	{"GetIpNetTable",		&PTR_GetIpNetTable},
	{"SendARP",			&PTR_SendARP},
	{"GetIpForwardTable",		&PTR_GetIpForwardTable},
	{"GetTcpTable",			&PTR_GetTcpTable},
	{"GetTcpStatistics",		&PTR_GetTcpStatistics},
	{"GetIpStatistics",		&PTR_GetIpStatistics},
	0
};
static void dllinit(){
	static int diddll;
	void *dll[5];
	const char *sym;
	const void *addr;
	int **ap;
	int si;
	int ndll;

	if( diddll )
		return;
	diddll = 1;
	ndll = 0;
	bzero(dll,sizeof(dll));
	if( dll[ndll] = dlopen("coredll.dll",0) )
		ndll++;
	if( dll[ndll] = dlopen("cellcore.dll",0) )
		ndll++;
	if( dll[ndll] = dlopen("rasapi32.dll",0) )
		ndll++;
	if( dll[ndll] = dlopen("psapi.dll",0) )
		ndll++;
	if( dll[ndll] = dlopen("secur32.dll",0) )
		ndll++;
	if( dll[ndll] = dlopen("iphlpapi.dll",0) )
		ndll++;
	if( ndll == 0 ){
		return;
	}
	for( si = 0; sym = symaddr[si].name; si++ ){
		addr = dlsym(dll[0],sym);
		if( addr == 0 && dll[1] != 0 )
			addr = dlsym(dll[1],sym);
		if( addr == 0 && dll[2] != 0 )
			addr = dlsym(dll[2],sym);
		if( addr == 0 && dll[3] != 0 )
			addr = dlsym(dll[3],sym);
		if( addr == 0 && dll[4] != 0 )
			addr = dlsym(dll[4],sym);
		if( addr ){
			ap = (int**)symaddr[si].addr;
			*ap = (int*)addr;
		}
	}
}
#endif /*}*/
void winmo_dllstat(PVStr(stat),int all){
	refQStr(sp,stat);
	int si;
	const char *sym;

	dllinit();
	if( all ){
		int **ap;
		for( si = 0; sym = symaddr[si].name; si++ ){
			ap = (int**)symaddr[si].addr;
			Rsprintf(sp,"%X %s\n",*ap,sym);
		}
		return;
	}

	for( si = 0; sym = symaddr[si].name; si++ ){
		if( symaddr[si].addr == 0 )
			goto PRLIST;
	}
	clearVStr(sp);
	return;
PRLIST:
	for( si = 0; sym = symaddr[si].name; si++ ){
		Rsprintf(sp,"Unknown %s\n",sym);
	}
}

#ifndef UNDER_CE
DWORD DLL_RasGetConnectStatus(HRASCONN rc,LPRASCONNSTATUS rcs){
	dllinit();
	if( PTR_RasGetConnectStatus == 0 )
		return -1;
        return (*PTR_RasGetConnectStatus)(rc,rcs);
}
DWORD DLL_RasEnumConnections(LPRASCONN rc,LPDWORD cb,LPDWORD cC){
	dllinit();
	if( PTR_RasEnumConnections == 0 )
		return -1;
        return (*PTR_RasEnumConnections)(rc,cb,cC);
}
BOOL DLL_GetProcessMemoryInfo(HANDLE ph,PROCESS_MEMORY_COUNTERS *pmc,DWORD sz){
	dllinit();
	if( PTR_GetProcessMemoryInfo == 0 )
		return -1;
        return (*PTR_GetProcessMemoryInfo)(ph,pmc,sz);
}
#endif
SECURITY_STATUS DLL_QuerySecurityContextToken(CtxtHandle *ctx,HANDLE token){
	dllinit();
	if( PTR_QuerySecurityContextToken == 0 )
		return -1;
        return (*PTR_QuerySecurityContextToken)(ctx,token);
}

#ifdef UNDER_CE /*{*/
static HRESULT DLL_ConnMgrQueryDetailedStatus(CONNMGR_CONNECTION_DETAILED_STATUS *pStatBuf,DWORD *pcbBufSz){
	dllinit();
	if( PTR_ConnMgrQueryDetailedStatus == 0 )
		return -1;
	return (*PTR_ConnMgrQueryDetailedStatus)(pStatBuf,pcbBufSz);
}
static HRESULT DLL_ConnMgrEnumDestinations(int Index,CONNMGR_DESTINATION_INFO *pDestinfo){
	dllinit();
	if( PTR_ConnMgrEnumDestinations == 0 )
		return -1;
	return (*PTR_ConnMgrEnumDestinations)(Index,pDestinfo);
}
static HRESULT DLL_ConnMgrEstablishConnection(CONNMGR_CONNECTIONINFO *pConnInfo,HANDLE * phConn){
	dllinit();
	if( PTR_ConnMgrEstablishConnection == 0 )
		return -1;
	return (*PTR_ConnMgrEstablishConnection)(pConnInfo,phConn);
}
static HRESULT DLL_ConnMgrConnectionStatus(HANDLE hConn,DWORD *pdwStat){
	dllinit();
	if( PTR_ConnMgrConnectionStatus == 0 )
		return -1;
	return (*PTR_ConnMgrConnectionStatus)(hConn,pdwStat);
}
static HRESULT DLL_ConnMgrReleaseConnection(HANDLE hConn,LONG lCache){
	dllinit();
	if( PTR_ConnMgrReleaseConnection == 0 )
		return -1;
	return (*PTR_ConnMgrReleaseConnection)(hConn,lCache);
}
static HRESULT DLL_ConnMgrMapURL(LPTSTR pwszURL,GUID *pguid,DWORD *pdwIdx){
	dllinit();
	if( PTR_ConnMgrMapURL == 0 )
		return -1;
	return (*PTR_ConnMgrMapURL)(pwszURL,pguid,pdwIdx);
}
static HRESULT DLL_ConnMgrMapConRef(ConnMgrConRefTypeEnum e,LPCTSTR szConRef,GUID *pGUID){
	dllinit();
	if( PTR_ConnMgrMapConRef == 0 )
		return -1;
	return (*PTR_ConnMgrMapConRef)(e,szConRef,pGUID);
}
#endif /*}*/

static HANDLE DLL_IcmpCreateFile(){
	dllinit();
	if( PTR_IcmpCreateFile == 0 )
		return (HANDLE)-1;
	return (*PTR_IcmpCreateFile)();
}
static DWORD DLL_IcmpCloseHandle(HANDLE ih){
	dllinit();
	if( PTR_IcmpCloseHandle == 0 )
		return -1;
	return (*PTR_IcmpCloseHandle)(ih);
}
static DWORD DLL_IcmpSendEcho(HANDLE ih,IPAddr da,LPVOID qd,WORD qz,PIP_OPTION_INFORMATION qo,LPVOID rb,DWORD rz,DWORD to){
	dllinit();
	if( PTR_IcmpSendEcho == 0 )
		return -1;
	return (*PTR_IcmpSendEcho)(ih,da,qd,qz,qo,rb,rz,to);
}

static DWORD DLL_GetNetworkParams(PFIXED_INFO pFixedInfo,PULONG pOutBufLen){
	dllinit();
	if( PTR_GetNetworkParams == 0 )
		return -1;
	return (*PTR_GetNetworkParams)(pFixedInfo,pOutBufLen);
}
static DWORD DLL_GetIfTable(MIB_IFTABLE *pIfTab,ULONG *pdwSz,BOOL bOrder){
	dllinit();
	if( PTR_GetIfTable == 0 )
		return -1;
	return (*PTR_GetIfTable)(pIfTab,pdwSz,bOrder);
}
static DWORD DLL_GetIfEntry(MIB_IFROW *pIfRow){
	dllinit();
	if( PTR_GetIfEntry == 0 )
		return -1;
	return (*PTR_GetIfEntry)(pIfRow);
}
static DWORD DLL_GetIpForwardTable(MIB_IPFORWARDTABLE *pIpForwTab,ULONG *pdwSize,BOOL bOrder){
	dllinit();
	if( PTR_GetIpForwardTable == 0 )
		return -1;
	return (*PTR_GetIpForwardTable)(pIpForwTab,pdwSize,bOrder);
}
static DWORD DLL_GetIpNetTable(PMIB_IPNETTABLE ipNetTab,PULONG Sz,BOOL Ord){
	dllinit();
	if( PTR_GetIpNetTable == 0 )
		return -1;
	return (*PTR_GetIpNetTable)(ipNetTab,Sz,Ord);
}
static DWORD DLL_SendARP(IPAddr dst,IPAddr src,PULONG macA,PULONG macL){
	dllinit();
	if( PTR_SendARP == 0 )
		return -1;
	return (*PTR_SendARP)(dst,src,macA,macL);
}

static DWORD DLL_GetTcpTable(MIB_TCPTABLE *TcpTable,DWORD *Sz,BOOL Ord){
	dllinit();
	if( PTR_GetTcpTable == 0 )
		return -1;
	return (*PTR_GetTcpTable)(TcpTable,Sz,Ord);
}
static DWORD DLL_GetTcpStatistics(MIB_TCPSTATS *pStats){
	dllinit();
	if( PTR_GetTcpStatistics == 0 )
		return -1;
	return (*PTR_GetTcpStatistics)(pStats);
}
static DWORD DLL_GetIpStatistics(MIB_IPSTATS *pStats){
	dllinit();
	if( PTR_GetIpStatistics == 0 )
		return -1;
	return (*PTR_GetIpStatistics)(pStats);
}
static BOOL DLL_PowerPolicyNotify(DWORD dwMessage,DWORD dwData){
	dllinit();
	if( PTR_PowerPolicyNotify == 0 )
		return -1;
	return (*PTR_PowerPolicyNotify)(dwMessage,dwData);
}

#define	ConnMgrQueryDetailedStatus   DLL_ConnMgrQueryDetailedStatus
#define	ConnMgrEnumDestinations      DLL_ConnMgrEnumDestinations
#define ConnMgrEstablishConnection   DLL_ConnMgrEstablishConnection
#define ConnMgrConnectionStatus      DLL_ConnMgrConnectionStatus
#define ConnMgrReleaseConnection     DLL_ConnMgrReleaseConnection
#define ConnMgrMapURL                DLL_ConnMgrMapURL
#define ConnMgrMapConRef             DLL_ConnMgrMapConRef
#define GetNetworkParams             DLL_GetNetworkParams
#define GetIfTable                   DLL_GetIfTable
#define GetIfEntry                   DLL_GetIfEntry
#define GetIpForwardTable            DLL_GetIpForwardTable
#define GetIpNetTable                DLL_GetIpNetTable
#define SendARP                      DLL_SendARP
#define GetTcpTable                  DLL_GetTcpTable
#define GetTcpStatistics             DLL_GetTcpStatistics
#define GetIpStatistics              DLL_GetIpStatistics
#define PowerPolicyNotify            DLL_PowerPolicyNotify

static struct {
	double ConnDelay;
	MStr(lc_stat,256);
	MStr(HostName,256);
	MStr(RASconns,256);
	MStr(ConnMgr,256);
} lastConn;

int strtowstrX(int sz,WCHAR *dst,PCStr(src),int esc);
int wstrtostrX(int sz,char *dst,WCHAR *src,int esc);
#define wstrtostr(dst,src,e) wstrtostrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
#define strtowstr(dst,src,e) strtowstrX(sizeof(dst)/sizeof(dst[0]),dst,src,e)
int newSocket(PCStr(what),PCStr(opts));
int bindSocket(int sock,PCStr(host),int port);
int connectTimeout(int sock,PCStr(host),int port,int timeout);
int gethostName(int sock,PVStr(sockname),PCStr(form));
time_t SystemTimeToUnixTime(SYSTEMTIME *st);

static const char *guidtos(GUID *guid,PVStr(str)){
	BYTE *bp = guid->Data4;
	sprintf(str,"%X-%X-%X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid->Data1,guid->Data2,guid->Data3,
		bp[0],bp[1],bp[2],bp[3],bp[4],bp[5],bp[6],bp[7]);
	return str;
}
static void sprintAddr(PVStr(sm),int naddr,int nmask){
	int mask;
	int dest,d1,d2,d3,d4;

	dest = ntohl(naddr);
	mask = ntohl(nmask);

	d1 = 0xFF & (dest >> 24);
	d2 = 0xFF & (dest >> 16);
	d3 = 0xFF & (dest >>  8);
	d4 = 0xFF & (dest >>  0);

	switch( mask ){
	  case 0x00000000:
		if( dest == 0 )
			//strcpy(sm,"default");
			strcpy(sm,"*.*.*.*");
		else	sprintf(sm,"%d.%d.%d.%d",d1,d2,d3,d4); break;
		break;
	  case 0xFF000000:
		sprintf(sm,"%d.*.*.*",d1); break;
	  case 0xFFFF0000:
		sprintf(sm,"%d.%d.*.*",d1,d2); break;
	  case 0xFFFFFF00:
		sprintf(sm,"%d.%d.%d.*",d1,d2,d3); break;
	  case 0xFFFFFFFF:
		sprintf(sm,"%d.%d.%d.%d",d1,d2,d3,d4); break;
	  default:
		sprintf(sm,"%d.%d.%d.%d/%X",d1,d2,d3,d4,mask);
		break;
	}
}

#define GET_MACADDR
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr)){
	refQStr(pp,macaddr);
	IPAddr res;
	IPAddr src;
	ULONG maca[8];
	ULONG sz;
	const unsigned char *mac = (unsigned char*)maca;
	int pi;

	src = gethostint_nboV4(ipaddr);
	sz = sizeof(maca);
	res = SendARP(src,0,maca,&sz);
	if( res != NO_ERROR ){
		sprintf(macaddr,"(err=%d)",GetLastError());
		return (char*)macaddr;
	}
	for( pi = 0; pi < sz; pi++ ){
		Rsprintf(pp,"%s%X",0<pi?":":"",mac[pi]);
	}
	return (char*)pp;
}

#ifdef UNDER_CE /*{*/
static GUID DEST_dfltInternet;
static GUID DEST_dfltIntranet;
static GUID DEST_Internet;
static GUID DEST_Intranet;
static int listConnDst(PVStr(list),int showonly){
	refQStr(lp,list);
	IStr(desc,512);
	CONNMGR_DESTINATION_INFO dinfo;
	int di;
	int *ip;
	IStr(guid,128);
	int sguid;

	ip = (int*)&dinfo.guid;
	for( di = 0; di < 8; di++ ){
		bzero(&dinfo,sizeof(dinfo));
		if( ConnMgrEnumDestinations(di,&dinfo) != 0 )
			break;
		wstrtostr(desc,dinfo.szDescription,0);
		sguid = (dinfo.guid.Data1>>16)&0xFFFF;
		if( dinfo.guid.Data1 == 0x436EF144 ){
			if( showonly ){
				Rsprintf(lp,"D%d)%X %s\n",di,sguid,desc);
				continue;
			}
			DEST_Internet = dinfo.guid;
		}else
		if( dinfo.guid.Data1 == 0xA1182988 ){
			if( showonly ){
				Rsprintf(lp,"D%d)%X %s\n",di,sguid,desc);
				continue;
			}
			DEST_Intranet = dinfo.guid;
		}else
		if( dinfo.guid.Data1 == 0xADB0B001 ){
			if( showonly ){
				Rsprintf(lp,"D%d)%X %s\n",di,sguid,desc);
				continue;
			}
			DEST_dfltInternet = dinfo.guid;
		}else
		if( dinfo.guid.Data1 == 0x18AD9FBD ){
			if( showonly ){
				Rsprintf(lp,"D%d)%X %s\n",di,sguid,desc);
				continue;
			}
			DEST_dfltIntranet = dinfo.guid;
		}else{
			continue;
		}
		guidtos(&dinfo.guid,AVStr(guid));
		Rsprintf(lp,"[%s]%X ",desc,dinfo.guid.Data1);
		//Rsprintf(lp,"%X.%d ",dinfo.guid,dinfo.fSecure);
	}
	return lp - list;
}
const char *connstats(int stat){
 const char *st;
 switch( stat ){
  case CONNMGR_STATUS_UNKNOWN                :st="Unknown"; break;
  case CONNMGR_STATUS_CONNECTED              :st="Connected"; break;
  case CONNMGR_STATUS_DISCONNECTED           :st="Disconnected"; break;
  case CONNMGR_STATUS_CONNECTIONFAILED       :st="ConnFailed"; break;
  case CONNMGR_STATUS_CONNECTIONCANCELED     :st="Cancelled"; break;
  case CONNMGR_STATUS_CONNECTIONDISABLED     :st="Disabled"; break;
  case CONNMGR_STATUS_CONNECTIONLINKFAILED   :st="LinkFailed"; break;
  case CONNMGR_STATUS_NOPATHTODESTINATION    :st="NoPath"; break;
  case CONNMGR_STATUS_WAITINGFORPATH         :st="WaitingPath"; break;
  case CONNMGR_STATUS_WAITINGFORPHONE        :st="WaitingPhone"; break;
  case CONNMGR_STATUS_WAITINGCONNECTION      :st="WaitingConn"; break;
  case CONNMGR_STATUS_WAITINGFORRESOURCE     :st="WaitingBusy"; break;
  case CONNMGR_STATUS_WAITINGFORNETWORK      :st="WaitingPath"; break;
  case CONNMGR_STATUS_WAITINGDISCONNECTION   :st="WaitingReset"; break;
  case CONNMGR_STATUS_WAITINGCONNECTIONABORT :st="WaitingAbort"; break;
  case CONNMGR_STATUS_AUTHENTICATIONFAILED   :st="AuthFailed"; break;
  default: static IStr(stb,16); sprintf(stb,"(CM0x%X)",stat); st = stb; 
 }
 return st;
}
/*
int releaseConnection(PVStr(msg)){
	refQStr(mp,msg);
	CONNMGR_CONNECTIONINFO cinfo;
	HRESULT res;
	HANDLE conn;
	DWORD stat;
	double St = Time();
	int rcode;

	bzero(&cinfo,sizeof(cinfo));
	cinfo.cbSize = sizeof(cinfo);
	cinfo.dwParams = CONNMGR_PARAM_GUIDDESTNET;
	cinfo.dwPriority = CONNMGR_PRIORITY_USERINTERACTIVE;
	cinfo.dwFlags = CONNMGR_FLAG_PROXY_HTTP;
	cinfo.bExclusive = FALSE;
	cinfo.bDisabled = FALSE;
	cinfo.ulMaxConnLatency = 30*1000;

cinfo.guidDestNet = DEST_Internet;

	conn = 0;
	stat = -1;
	res = ConnMgrEstablishConnection(&cinfo,&conn);

	if( res != S_OK ){
		rcode = -1;
	}else{
		res = ConnMgrReleaseConnection(conn,TRUE);
		if( res != S_OK ){
			rcode = -2;
		}else{
			res = ConnMgrConnectionStatus(conn,&stat);
			if( res != S_OK )
				rcode = -3;
			else	rcode = 0;
		}
	}
	Rsprintf(mp," %2d: CM: %s release (%X %d %X %.1fs)",
		time(0)%60,rcode==0?"OK":"NG",
		res,stat,cinfo.guidDestNet.Data1,Time()-St);
	return rcode;
}
*/

typedef struct {
	GUID	d_dest;
	HANDLE	d_conn;
} DestCache;
static DestCache destCache[8];
static const char *connType(int ctype){
	switch( ctype ){
		case CM_CONNTYPE_UNKNOWN: return "UnknownCT";
		case CM_CONNTYPE_CELLULAR: return "Cellular";
		case CM_CONNTYPE_NIC: return "Nic";
		case CM_CONNTYPE_BLUETOOTH: return "Bluetooth";
		case CM_CONNTYPE_UNIMODEM: return "Unimodem";
		case CM_CONNTYPE_VPN: return "Vpn";
		case CM_CONNTYPE_PROXY: return "Proxy";
		case CM_CONNTYPE_PC: return "Pc";
	}
	return "Type?";
}
static const char *connSubtype(int type,int stype){
	switch( type ){
	    case CM_CONNTYPE_UNKNOWN:
		  default: return "UnknownCt";
		break;
	    case CM_CONNTYPE_NIC:
		switch( stype ){
		  case CM_CONNSUBTYPE_NIC_UNKNOWN:	return "UnknownNIC";
		  case CM_CONNSUBTYPE_NIC_ETHERNET:	return "Ethernet";
		  case CM_CONNSUBTYPE_NIC_WIFI:		return "WiFi";
		  case CM_CONNSUBTYPE_NIC_MAX:		return "Max";
		  default: return "UnknownNic";
		}
		break;
	    case CM_CONNTYPE_UNIMODEM:
		switch( stype ){
		  case CM_CONNSUBTYPE_UNIMODEM_UNKNOWN:	return "UnknownUM";
		  case CM_CONNSUBTYPE_UNIMODEM_CSD:	return "CSD";
		  case CM_CONNSUBTYPE_UNIMODEM_OOB_CSD:	return "OOB_CSD";
		  case CM_CONNSUBTYPE_UNIMODEM_NULL_MODEM: return "NULL";
		  case CM_CONNSUBTYPE_UNIMODEM_EXTERNAL_MODEM: return "EXT";
		  case CM_CONNSUBTYPE_UNIMODEM_INTERNAL_MODEM: return "INT";
		  case CM_CONNSUBTYPE_UNIMODEM_PCMCIA_MODEM: return "PCMCIA";
		  case CM_CONNSUBTYPE_UNIMODEM_IRCOMM_MODEM: return "IRCOMM";
		  case CM_CONNSUBTYPE_UNIMODEM_DYNAMIC_MODEM: return "DYNAMIC";
		  case CM_CONNSUBTYPE_UNIMODEM_DYNAMIC_PORT: return "DYNPORT";
		  case CM_CONNSUBTYPE_UNIMODEM_MAX:
		  default: return "UnknownUm";
		}
		break;
	    case CM_CONNTYPE_CELLULAR:
		switch( stype ){
		  case CM_CONNSUBTYPE_CELLULAR_UNKNOWN: return "UnknownCL";
		  case CM_CONNSUBTYPE_CELLULAR_CSD:	return "CSD";
		  case CM_CONNSUBTYPE_CELLULAR_GPRS:	return "GPRS";
		  case CM_CONNSUBTYPE_CELLULAR_1XRTT:	return "1XRTT";
		  case CM_CONNSUBTYPE_CELLULAR_1XEVDO:	return "1XEVDO";
		  case CM_CONNSUBTYPE_CELLULAR_1XEVDV:	return "1XEVDV";
		  case CM_CONNSUBTYPE_CELLULAR_EDGE:	return "EDGE";
		  case CM_CONNSUBTYPE_CELLULAR_UMTS:	return "UMTS";
		  case CM_CONNSUBTYPE_CELLULAR_VOICE:	return "VOICE";
		  case CM_CONNSUBTYPE_CELLULAR_PTT:	return "PTT";
		  case CM_CONNSUBTYPE_CELLULAR_HSDPA:	return "HSDPA";
		  case CM_CONNSUBTYPE_CELLULAR_MAX:	return "MAX";
		  default: return "UnknownCellular";
		}
		break;
	}
	return "?";
}
static const char *connFlags(int flags){
	static IStr(sflags,32);
	refQStr(sp,sflags);
	if( flags & CM_DSF_BILLBYTIME    ) Rsprintf(sp,"Bt");
	if( flags & CM_DSF_ALWAYSON      ) Rsprintf(sp,"Ao");
	if( flags & CM_DSF_SUSPENDRESUME ) Rsprintf(sp,"Sr");
	return sflags;
}
static const char *connParams(int params){
	static IStr(sparams,64);
	refQStr(sp,sparams);

	sp = sparams;
	if( params & CONNMGR_PARAM_GUIDDESTNET    ) Rsprintf(sp,"G");
	if( params & CONNMGR_PARAM_MAXCOST        ) Rsprintf(sp,"C");
	if( params & CONNMGR_PARAM_MINRCVBW       ) Rsprintf(sp,"R");
	if( params & CONNMGR_PARAM_MAXCONNLATENCY ) Rsprintf(sp,"L");
	return sparams;
}
int establishConnection(GUID *dstx,PCStr(dst),PVStr(msg),int release){
	refQStr(mp,msg);
	HRESULT res;
	HANDLE conn = 0;
	DWORD stat;
	double St = Time();
	int rcode = 0;
	int reu = 0;
	GUID dest;
	int dx = 0;

	if( dstx ){
		dest = *dstx;
		if( dest.Data1 == 0 ){
			sprintf(msg,"-CM empty GUID arg\n");
			return -2;
		}
	}else{
		WCHAR dsturl[256];
		strtowstr(dsturl,dst,0);
		ConnMgrMapURL(dsturl,&dest,0);
		if( dest.Data1 == 0 ){
			sprintf(msg,"-CM empty GUID arg [%s]\n",dst);
			return -3;
		}
	}
	int di;
	for( di = 0; di < elnumof(destCache); di++ ){
		if( dest == destCache[di].d_dest ){
			conn = destCache[di].d_conn;
			dx = di;
			break;
		}
		if( destCache[di].d_conn == 0 ){
			dx = di;
			break;
		}
	}

	CONNMGR_CONNECTIONINFO cinfo;
	bzero(&cinfo,sizeof(cinfo));
	if( conn ){
		res = ConnMgrConnectionStatus(conn,&stat);
		if( release ){
			if( res == S_OK
			 && stat == CONNMGR_STATUS_CONNECTED
			/* && if it is not shareable */
			/* && if it is not WiFi ? */
			){
			}else{
				release = 0;
			}
		}
		if( release == 0 )
		if( res == S_OK ){
			switch( stat ){
			  case CONNMGR_STATUS_UNKNOWN:
			  case CONNMGR_STATUS_CONNECTED:
			  case CONNMGR_STATUS_WAITINGCONNECTION:
			  case CONNMGR_STATUS_WAITINGDISCONNECTION:
			  case CONNMGR_STATUS_NOPATHTODESTINATION:
				reu = 1;
				goto EXIT;
			}
		}
		Rsprintf(mp," %2d:CM:previous %X (%d)%s\n",
			time(0)%60,conn,res,connstats(stat));
		if( res == S_OK ){
			switch( stat ){
			  case CONNMGR_STATUS_CONNECTIONCANCELED:
				break;
			}
		}
		res = ConnMgrReleaseConnection(conn,TRUE);
		destCache[di].d_conn = 0;
		Rsprintf(mp," %2d:CM:released %X (%d)%s\n",
			time(0)%60,conn,res,connstats(stat));
		if( release ){
			return res == S_OK;
		}
	}
	if( release ){
		return -1;
	}

	{
		cinfo.cbSize = sizeof(cinfo);
		cinfo.dwParams = CONNMGR_PARAM_GUIDDESTNET;
		cinfo.dwPriority = CONNMGR_PRIORITY_USERINTERACTIVE;
		//cinfo.dwFlags = CONNMGR_FLAG_PROXY_HTTP;
		cinfo.dwFlags = 0;
		cinfo.bExclusive = FALSE;
		cinfo.bDisabled = FALSE;
		cinfo.ulMaxConnLatency = 30*1000;
		cinfo.guidDestNet = dest;
		conn = 0;
		stat = -1;
		res = ConnMgrEstablishConnection(&cinfo,&conn);
	}

	if( res != S_OK ){
		rcode = -1;
	}else{
		res = ConnMgrConnectionStatus(conn,&stat);
		if( res != S_OK )
			rcode = -2;
		else{
			destCache[dx].d_dest = cinfo.guidDestNet;
			destCache[dx].d_conn = conn;
			rcode = 0;
		}
	}
EXIT:
	IStr(connmgr,256);
	sprintf(connmgr," %2d:CM:%s/%s %.1fs %X %X\n",
		time(0)%60,reu?"Ok":rcode==0?"OK":"NG",
		connstats(stat),Time()-St,
		res,dest.Data1
	);
	Rsprintf(mp,"%s",connmgr);
	strcpy(lastConn.ConnMgr,connmgr);
	return rcode;
}
static int LastSock;
int prevRouteTab;
static int ntest;
static int testconn1(PVStr(stat)){
	double St = Time();
	int rcode;
	int sock;
	int ecode = 0;

	if( ntest++ == 0 )
	if( 0 <= lastConn.ConnDelay )
	if( curRouteTab == prevRouteTab ){
		clearVStr(stat);
		if( lastConn.ConnDelay < 0 )
			return -1;
		else	return 0;
	}
	prevRouteTab = curRouteTab;
	sock = newSocket("test","");
	//rcode = bindSocket(sock,"60.254.236.170",0);
	LastSock = sock;
	rcode = connectTimeout(sock,"210.155.199.28",9820,3*1000);
	//rcode = connectTimeout(sock,"wince.delegate.org",9820,3*1000);
	if( 0 <= sock ){
		gethostName(sock,AVStr(lastConn.HostName),"%A:%P");
		close(sock);
	}
	if( rcode == 0 ){
		lastConn.ConnDelay = Time()-St;
		sprintf(stat," %2d:Latency:%.2fs <%s\n",
			ntest,lastConn.ConnDelay,lastConn.HostName);
	}else{
		ecode = -1;
		lastConn.ConnDelay = -1;
		sprintf(stat," %2d:Latency: Can't Connect\n",ntest);
	}
	strcpy(lastConn.lc_stat,stat);
	return ecode;
}

char *printRoutes(PVStr(buf),PCStr(ifp),PCStr(ipp),int all,int closeEther);
static char *printBestRoute(PCStr(dest),PVStr(buf));
static double PowerOff;
static int LastSucc;
static int Ipaddress(PVStr(addrlist),CONNMGR_CONNECTION_IPADDR *IPAddr){
	refQStr(ap,addrlist);
	int ai,aj;
	SOCKADDR_STORAGE *sa;
	unsigned char *ip;

	if( IPAddr == 0 ){
		return -1;
	}
	for( ai = 0; ai < 16 && ai < IPAddr->cIPAddr; ai++ ){
		sa = &IPAddr->IPAddr[ai];
		ip = ((unsigned char*)sa->__ss_pad1)+2;
		if( 0 < ai ) Rsprintf(ap," ");
		Rsprintf(ap,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	}
	return ai;
}
int withWaitingConnections(){
	CONNMGR_CONNECTION_DETAILED_STATUS dstats[32];
	DWORD dsz = sizeof(dstats);
	int ok;
	int nact = 0;
	CONNMGR_CONNECTION_DETAILED_STATUS *dsp;
	int di;

	ok = ConnMgrQueryDetailedStatus(dstats,&dsz);
	if( ok == S_OK ){
		dsp = &dstats[0];
		for( di = 0; dsp && di < elnumof(dstats); di++ ){
			switch( dsp->dwConnectionStatus ){
			  case CONNMGR_STATUS_WAITINGFORPATH         :
			  case CONNMGR_STATUS_WAITINGFORPHONE        :
			  case CONNMGR_STATUS_WAITINGCONNECTION      :
			  case CONNMGR_STATUS_WAITINGFORRESOURCE     :
			  case CONNMGR_STATUS_WAITINGFORNETWORK      :
			  case CONNMGR_STATUS_WAITINGDISCONNECTION   :
			  case CONNMGR_STATUS_WAITINGCONNECTIONABORT :
				nact++;
				break;
			}
			dsp = dsp->pNext;
		}
	}
	return nact;
}
int releaseConnections(PVStr(msg)){
	int di;
	int nrel = 0;
	HANDLE conn;
	int res;

	for( di = 0; di < elnumof(destCache); di++ ){
		if( conn = destCache[di].d_conn ){
			destCache[di].d_conn = 0;
			res = ConnMgrReleaseConnection(conn,TRUE);
			nrel++;
		}
	}
	return nrel;
}
int withActiveConnections(int op){
	CONNMGR_CONNECTION_DETAILED_STATUS dstats[32];
	DWORD dsz = sizeof(dstats);
	int ok;
	int nact = 0;
	CONNMGR_CONNECTION_DETAILED_STATUS *dsp;
	int di;
	HANDLE conn;

	ok = ConnMgrQueryDetailedStatus(dstats,&dsz);
	if( ok == S_OK ){
		dsp = &dstats[0];
		for( di = 0; dsp && di < elnumof(dstats); di++ ){
			switch( dsp->dwConnectionStatus ){
			  case CONNMGR_STATUS_CONNECTED:
				if( dsp->dwFlags & CM_DSF_BILLBYTIME ){
					nact++;
				}
				break;
			}
			dsp = dsp->pNext;
		}
		if( op )
		for( di = 0; di < elnumof(destCache); di++ ){
			if( conn = destCache[di].d_conn ){
				int res;
				res = ConnMgrReleaseConnection(conn,TRUE);
			}
		}
		return nact;
	}else{
		return -1;
	}
}
char *findConnMgr(PVStr(cstat),PCStr(fmt),PCStr(type),PCStr(subtype)){
	refQStr(sp,cstat);
	CONNMGR_CONNECTION_DETAILED_STATUS dstats[32];
	DWORD dsz = sizeof(dstats);
	int ok;
	int di;
	CONNMGR_CONNECTION_DETAILED_STATUS *dsp;
	const char *type1,*subtype1;
	IStr(addrlist,256);

	ok = ConnMgrQueryDetailedStatus(dstats,&dsz);
	if( ok != S_OK )
		return 0;
	dsp = &dstats[0];
	for( di = 0; dsp && di < 16; di++,(dsp=dsp->pNext) ){
		clearVStr(addrlist);
		Ipaddress(AVStr(addrlist),dsp->pIPAddr);
		type1 = connType(dsp->dwType);
		subtype1 = connSubtype(dsp->dwType,dsp->dwSubtype);
		if( *addrlist == 0 ){
			continue;
		}
		if( type && *type ){
			if( isinListX(type,type1,"c") == 0 )
				continue;
		}
		if( subtype && *subtype ){
			if( isinListX(subtype,subtype1,"c") == 0 )
				continue;
		}
		if( cstat < sp )
			Rsprintf(sp,",");
		Rsprintf(sp,"%s",addrlist);
	}
	return (char*)sp;
}

char *printnetif(PVStr(netif)){
	refQStr(sp,netif);
	CONNMGR_CONNECTION_DETAILED_STATUS dstats[32];
	DWORD dsz = sizeof(dstats);
	int ok;
	int di;
	CONNMGR_CONNECTION_DETAILED_STATUS *dsp;
	IStr(addrlist,256);

	winmo_dllstat(AVStr(sp),0);
	bzero(dstats,sizeof(dstats));
	ok = ConnMgrQueryDetailedStatus(dstats,&dsz);
	if( ok != S_OK ){
		return 0;
	}
	dsp = &dstats[0];
	clearVStr(netif);
	for( di = 0; dsp && di < 16; di++ ){
		if( dsp->dwConnectionStatus == CONNMGR_STATUS_CONNECTED ){
			Ipaddress(AVStr(addrlist),dsp->pIPAddr);
			if( *addrlist && *addrlist != ' ' ){
				if( netif < sp ){
					Rsprintf(sp," ");
				}
				Rsprintf(sp,"%s",addrlist);
			}
		}
		dsp = dsp->pNext;
	}
	return (char*)netif;
}

char *printConnMgr(PVStr(cstat),int showall,int simple,int doconn){
	refQStr(sp,cstat);
	CONNMGR_CONNECTION_DETAILED_STATUS dstats[32];
	DWORD dsz = sizeof(dstats);
	int ok;

winmo_dllstat(AVStr(sp),0);
sp += strlen(sp);

	bzero(dstats,sizeof(dstats));
	ok = ConnMgrQueryDetailedStatus(dstats,&dsz);
	if( ok == S_OK ){
		int found = 0;
		IStr(nap,128);
		IStr(nic,128);
		CONNMGR_CONNECTION_DETAILED_STATUS *dsp;
		int di;
		dsp = &dstats[0];
		for( di = 0; dsp && di < 16; di++ ){
			IStr(desc,256);
			IStr(adpt,256);
			int addr;

			if( dsp->szDescription )
				wstrtostr(desc,dsp->szDescription,0);
			else	clearVStr(desc);
			if( dsp->szAdapterName )
				wstrtostr(adpt,dsp->szAdapterName,0);
			else	clearVStr(adpt);

			if( showall == 0 )
			switch( dsp->dwType ){
				case CM_CONNTYPE_UNIMODEM:
				case CM_CONNTYPE_CELLULAR:
				case CM_CONNTYPE_NIC:
				case CM_CONNTYPE_BLUETOOTH:
				case CM_CONNTYPE_PC:
					break;
				default:
					dsp = dsp->pNext;
					continue;
			}
IStr(last,256);
int lastt;
lastt = SystemTimeToUnixTime(&dsp->LastConnectTime);
StrftimeLocal(AVStr(last),sizeof(last),"%H:%M",lastt,0);

			IStr(addrlist,256);
			Ipaddress(AVStr(addrlist),dsp->pIPAddr);

		if( simple ){
			IStr(stat,128);
			IStr(ctyp,128);
			if( dsp->dwConnectionStatus == CONNMGR_STATUS_CONNECTED ){
				strcpy(stat,addrlist);
			}else{
				strcpy(stat,connstats(dsp->dwConnectionStatus));
			}
			if( dsp->dwType == CM_CONNTYPE_UNIMODEM ){
				strcpy(ctyp,"Phone");
			}else
			if( dsp->dwType == CM_CONNTYPE_PC ){
				strcpy(ctyp,"USB");
			}else{
				strcpy(ctyp,connSubtype(dsp->dwType,dsp->dwSubtype));
			}
			Rsprintf(sp," %s: %s %s\n",ctyp,stat,desc);
		}else{
			Rsprintf(sp,"C%d)",di);
			if( dsp->guidDestNet.Data1 )
			Rsprintf(sp,"%X ",(dsp->guidDestNet.Data1>>16)&0xFFFF);
			Rsprintf(sp,"%s",last);
			Rsprintf(sp," %s",connstats(dsp->dwConnectionStatus));
			Rsprintf(sp," %s",desc);
			if( *addrlist ) Rsprintf(sp," %s",addrlist);
			Rsprintf(sp," %s/%s",connType(dsp->dwType),
				connSubtype(dsp->dwType,dsp->dwSubtype));
			if( adpt[0] )
				Rsprintf(sp,"(%s)",adpt);
			else	Rsprintf(sp," ");
			Rsprintf(sp,"%d",dsp->dwSignalQuality);
			Rsprintf(sp,"%s",dsp->dwVer==1?"":"?");
			Rsprintf(sp,"%s",connParams(dsp->dwParams));
			Rsprintf(sp,"%s",connFlags(dsp->dwFlags));
			Rsprintf(sp,"%s",dsp->dwSecure?"S":"-");
			if( dsp->guidSourceNet.Data1 )
			Rsprintf(sp," <%X",(dsp->guidSourceNet.Data1>>16)&0xFFFF);
			Rsprintf(sp,"\n");
		}

			if( dsp->dwType == CM_CONNTYPE_NIC ){
				strcpy(nic,desc);
			}
			if( found == 0 )
			if( dsp->dwType == CM_CONNTYPE_UNIMODEM
			 || dsp->dwType == CM_CONNTYPE_CELLULAR
			){
				found++;
				strcpy(nap,desc);
			}
			dsp = dsp->pNext;
		}
		if( doconn )
		if( found ){
			WCHAR wnap[128];
			GUID dest;
			int res = -1;

/*
dest = DEST_Internet;
establishConnection(&dest,"",AVStr(sp),1);
sp += strlen(sp);
*/
	if( 1 ){
			strtowstr(wnap,nic,0);
			dest.Data1 = 0;
			ok = ConnMgrMapConRef(ConRefType_NAP,wnap,&dest);
			if( dest.Data1 )
			res = establishConnection(&dest,"",AVStr(sp),1);
	}

			strtowstr(wnap,nap,0);
			dest.Data1 = 0;
			ok = ConnMgrMapConRef(ConRefType_NAP,wnap,&dest);
			if( dest.Data1 )
			res = establishConnection(&dest,"",AVStr(sp),0);
sp += strlen(sp);
Rsprintf(sp,"-CM MAP=%d %X > [%s] res=%d\n",ok,dest.Data1,nap,res);

		}
	}else{
		Rsprintf(sp,"--CMQDS %d, %d/%d\n",ok,dsz,sizeof(dstats));
	}
	if( simple ){
		if( strstr(cstat,"WiFi") == 0 ){
			strcat(cstat," WiFi: Disabled\n");
		}
	}else{
		listConnDst(TVStr(cstat),1);
	}
	return (char*)cstat;
}
int tryConnection(PCStr(dsturl),PVStr(cstat)){
	printConnMgr(TVStr(cstat),0,0,1);
	printRoutes(TVStr(cstat),0,0,0,1);

/*
GUID dest;
dest = IID_DestNetInternet;
establishConnection(&dest,dsturl,TVStr(cstat),0);
*/

	establishConnection(&DEST_Internet,dsturl,TVStr(cstat),0);
	return 0;
}
void testconn(PCStr(host),PVStr(cstat)){
	if( LastSucc == 0 ){
		LastSucc = time(0);
	}
	if( testconn1(TVStr(cstat)) == 0 ){
		printConnMgr(TVStr(cstat),0,0,0);
		if( strstr(lastConn.ConnMgr,"WaitingConn")
		 || strstr(lastConn.ConnMgr,"Unknown")
		){
			//establishConnection(&DEST_dfltInternet,
			establishConnection(0,
				"http://wince.delegate.org",TVStr(cstat),0);
		}
		strcat(cstat,lastConn.ConnMgr);
		LastSucc = time(0);
		PowerOff = 0;
		goto EXIT;
	}
	printConnMgr(TVStr(cstat),0,0,1);
	printRoutes(TVStr(cstat),0,0,0,1);
	//tryRASconn(1);
	establishConnection(&DEST_Internet,"http://wince.delegate.org",
		TVStr(cstat),0);
	/*
	sp += strlen(sp);
	establishConnection(&DEST_Intranet,"http://192.168.1.1",AVStr(sp),0);
	sp += strlen(sp);
	*/
	testconn1(TVStr(cstat));

EXIT:
	/*
	printBestRoute("192.168.1.0",TVStr(cstat));
	printBestRoute("wince.delegate.org",TVStr(cstat));
	*/
	return;

#if 0
static HRESULT pres;
if( PowerOff == 0 && 10 < time(0)-LastSucc ){
	refreshWinStatus = 1;
	PowerOff = Time()+120;
SCHEDULEDCONNECTIONINFO sci;
bzero(&sci,sizeof(sci));
sci.guidDest = DEST_Internet;
int now;
FILETIME fnow;
now = time(0);
now +=  5; UnixTimeToFileTime(now,&fnow);
sci.uiStartTime = (((UINT64)fnow.dwHighDateTime<<32))|fnow.dwLowDateTime;
now += 60; UnixTimeToFileTime(now,&fnow);
sci.uiStartTime = (((UINT64)fnow.dwHighDateTime<<32))|fnow.dwLowDateTime;
pres = ConnMgrRegisterScheduledConnection(&sci);
sp += strlen(sp);
}
if( PowerOff ){
Rsprintf(sp,"----PowerOff %X (%d)(%.1f)\n",
	pres,time(0)-LastSucc,Time()-PowerOff);
}
#endif

}

static char *printBestRoute(PCStr(host),PVStr(buf)){
	refQStr(bp,buf);
	MIB_IPFORWARDROW bestR;
	DWORD res;
	IStr(si,64);
	IStr(addr,64);
	int iaddr;
	WCHAR wurl[128];
	IStr(url,128);
	GUID destg;
	IStr(da,64);

	sprintf(url,"http://%s",host);
	bzero(&destg,sizeof(destg));
	strtowstr(wurl,url,0);
	ConnMgrMapURL(wurl,&destg,0);

	bzero(&bestR,sizeof(bestR));
	SetLastError(0);
	iaddr = gethostint_nboV4(host); 
	res = GetBestRoute(iaddr,0xFFFFFF00,&bestR);
	sprintAddr(AVStr(si),bestR.dwForwardNextHop,0);
	sprintAddr(AVStr(addr),iaddr,0);
	sprintAddr(AVStr(da),bestR.dwForwardDest,bestR.dwForwardMask);
	Rsprintf(bp,"BR:");
	if( res != 0 ){
		if( res == ERROR_CAN_NOT_COMPLETE )
			Rsprintf(bp,"Unavail ",res);
		else	Rsprintf(bp,"Undef(%d) ",res);
		Rsprintf(bp,"%s\n",host);
	}else{
		//Rsprintf(bp,"%04X ",(ntohl(destg.Data1)>>16)&0xFFFF);
		Rsprintf(bp,"%s/%s <%s\n",host,da,si);
	}
	return (char*)bp;
}
#endif /*}*/

int sortroute(const void *a,const void *b){
	MIB_IPFORWARDROW *ap,*bp;
	int dif;
	ap = (MIB_IPFORWARDROW*)a;
	bp = (MIB_IPFORWARDROW*)b;
	dif = ntohl(ap->dwForwardNextHop) - ntohl(bp->dwForwardNextHop);
	if( dif ) return dif;
	dif = ntohl(ap->dwForwardDest) - ntohl(bp->dwForwardDest);
	if( dif ) return dif;
	return 0;
}
int sortif(const void *a,const void *b){
	MIB_IFROW *ap,*bp;
	int dif;
	ap = (MIB_IFROW*)a;
	bp = (MIB_IFROW*)b;
	dif = ntohl(ap->dwIndex) - ntohl(bp->dwIndex);
	if( dif ) return -dif;
	return 0;
}
char *printRoutes(PVStr(buf),PCStr(ifp),PCStr(ipp),int all,int closeEther){
	refQStr(bp,buf);
	int ipb[4*1024];
	MIB_IPFORWARDTABLE *ipt = (MIB_IPFORWARDTABLE*)ipb;
	MIB_IPFORWARDROW *ipf;
	ULONG fz;
	int res;
	int ni;
	int fi;
	int ifn = 0;
	int nicIfIndex;
	int ifpx = -1;

	if( 0 ){
		int fbuff[1024];
		FIXED_INFO *finfo;
		ULONG len;
		finfo = (FIXED_INFO*)fbuff;
		len = sizeof(fbuff);
		res = GetNetworkParams(finfo,&len);
		if( res != 0 ){
			Rsprintf(bp,"Host: none (%d)\n",res);
		}else{
			IP_ADDR_STRING *ia;
			Rsprintf(bp,"Host: %s",finfo->HostName);
			if( finfo->DomainName[0] )
			Rsprintf(bp,"@%s",finfo->DomainName);
			Rsprintf(bp," %s,%d,%d,%d",
				finfo->NodeType?"DHCP":"",
				finfo->EnableRouting,finfo->EnableProxy,
				finfo->EnableDns);
			Rsprintf(bp,"\n");

			Rsprintf(bp,"DNS-Server:");
			ia = &finfo->DnsServerList;
			for(; ia != 0; ia = ia->Next ){
				Rsprintf(bp," %s",ia->IpAddress.String);
			}
			Rsprintf(bp,"\n");
		}
	}

	int ifb[4*1024];
	ULONG ifz = sizeof(ifb);
	MIB_IFTABLE *ift = (MIB_IFTABLE*)ifb;
	res = GetIfTable(ift,&ifz,0);
	if( res != NO_ERROR ){
		Rsprintf(bp,"If: none (%d)\n",res);
	}else{
		MIB_IFROW *ifw;
		int ii;
		IStr(iname,128);
		IStr(itype,32);
		ifn = ift->dwNumEntries;
		qsort(ift->table,ifn,sizeof(ift->table[0]),sortif);
		for( ii = 0; ii < ift->dwNumEntries; ii++ ){
			ifw = &ift->table[ii];
			wstrtostr(iname,ifw->wszName,0);
			if( iname[0] == 0 )
			if( GetIfEntry(ifw) == NO_ERROR ){
				wstrtostr(iname,ifw->wszName,0);
			}
			switch( ifw->dwType ){
				case IF_TYPE_ETHERNET_CSMACD:
					strcpy(itype,"eth"); break;
				case IF_TYPE_PPP:
					strcpy(itype,"ppp"); break;
				case IF_TYPE_SOFTWARE_LOOPBACK:
					strcpy(itype,"lo "); break;
				default:
					sprintf(itype,"%02d",ifw->dwType);
			}
			if( ifp ){
				if( streq(itype,ifp) ){
					ifpx = ifw->dwIndex;
				}
			}
			Rsprintf(bp,"I%d)%02d %s %d %s %ui %uo %s",
				ifw->dwIndex&0xFFFF,
				ifw->dwIndex>>16,
				itype,
				ifw->dwMtu,
				ifw->dwAdminStatus?"+":"-",
				ifw->dwInOctets,
				ifw->dwOutOctets,
				iname
			);
if( ifw->dwType == IF_TYPE_ETHERNET_CSMACD ){
	nicIfIndex = ifw->dwIndex;
/*
	if( closeEther )
		ifw->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
	else	ifw->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
*/
/*
	ifw->dwMtu = TCP_MSS+40;
	SetIfEntry(ifw);
*/
}
			Rsprintf(bp,"\n");
		}
	}

	noDfltRoute = 1;
	bzero(ipb,sizeof(ipb));
	fz = sizeof(ipb);
	res = GetIpForwardTable(ipt,&fz,1);
	curRouteTab = strCRC32((char*)ipb,fz);
	if( res != 0 ){
		Rsprintf(bp,"ROUTE error(%d)\n",res);
		return (char*)bp;
	}
	ni = ipt->dwNumEntries;
	//qsort(ipt->table,ni,sizeof(ipt->table[0]),sortroute);
	for( fi = 0; fi < 16 && fi < ni; fi++ ){
		ipf = &ipt->table[fi];
		if( !all ){
			if( ntohl(ipf->dwForwardNextHop) == 0x7F000001 )
				continue;
			if( ntohl(ipf->dwForwardDest) == 0xE0000000 )
				continue;
			if( ntohl(ipf->dwForwardDest) == 0xFFFFFFFF )
				continue;
			if( ntohl(ipf->dwForwardMask) == 0xFFFFFFFF )
				continue;
		}
		if( ipf->dwForwardDest == 0 ){
			noDfltRoute = 0;
		}

	IStr(sm,32);
	IStr(dm,64);
	sprintAddr(AVStr(sm),ipf->dwForwardDest,ipf->dwForwardMask);
	sprintAddr(AVStr(dm),ipf->dwForwardNextHop,0);

		if( ipp ){
			bp = buf;
			if( ifp ){
				if( ipf->dwForwardIfIndex != ifpx ){
					clearVStr(bp);
					continue;
				}
			}
			if( streq(sm,ipp) ){
				Rsprintf(bp,"%s",dm);
				break;
			}else{
				clearVStr(bp);
			}
			continue;
		}

		Rsprintf(bp,"R%d>I%d)%d%d %s<%s %d",
			fi,ipf->dwForwardIfIndex&0xFFFF,
			ipf->dwForwardType,ipf->dwForwardProto,
			sm,dm,ipf->dwForwardAge
		);
		//Rsprintf(bp," (%d)",ipf->dwForwardMetric1);
		/*
		if( ipf->dwForwardIfIndex == nicIfIndex ){
			if( closeEther ){
				int res;
				res = DeleteIpForwardEntry(ipf);
				Rsprintf(bp,"(del=%d)",res);
			}
		}
		*/
		Rsprintf(bp,"\n");
	}
	return (char*)bp;
}

const char *tcpstat(int stat){
	switch( stat ){
		case MIB_TCP_STATE_CLOSED:     return "CLD";
		case MIB_TCP_STATE_LISTEN:     return "LSN";
		case MIB_TCP_STATE_SYN_SENT:   return "SSN";
		case MIB_TCP_STATE_SYN_RCVD:   return "SRV";
		case MIB_TCP_STATE_ESTAB:      return "EST";
		case MIB_TCP_STATE_FIN_WAIT1:  return "FW1";
		case MIB_TCP_STATE_FIN_WAIT2:  return "FW2";
		case MIB_TCP_STATE_CLOSE_WAIT: return "CLW";
		case MIB_TCP_STATE_CLOSING:    return "CLN";
		case MIB_TCP_STATE_LAST_ACK:   return "LAK";
		case MIB_TCP_STATE_TIME_WAIT:  return "TMW";
		case MIB_TCP_STATE_DELETE_TCB: return "DTC";
	}
	return "?";
}
char *printTcpTable(PVStr(buf)){
	refQStr(bp,buf);
	int ttbuf[4*1024];
	MIB_TCPTABLE *tt = (MIB_TCPTABLE*)ttbuf;
	DWORD sz;
	DWORD err;
	int ti;
	MIB_TCPROW *tr;
	IStr(paddr,128);
	const char *stat = "";
	int tj;
	int nstat[16];
	int stat1;

	sz = sizeof(ttbuf);
	err = GetTcpTable((MIB_TCPTABLE*)ttbuf,&sz,1);
	if( err ){
		Rsprintf(bp,"TcpTable: err=%d %d/%d\n",err,sz,sizeof(ttbuf));
		return (char*)bp;
	}
	for( tj = 0; tj < elnumof(nstat); tj++ )
		nstat[tj] = 0;
	for( ti = 0; ti < tt->dwNumEntries; ti++ ){
		tr = &tt->table[ti];
		if( 0 <= tr->dwState && tr->dwState < elnumof(nstat) )
			nstat[tr->dwState]++;
	}
	Rsprintf(bp,"TcpTable: %d LST=%d EST=%d",tt->dwNumEntries,
		nstat[MIB_TCP_STATE_LISTEN],
		nstat[MIB_TCP_STATE_ESTAB],
		0
	);
	if( nstat[MIB_TCP_STATE_TIME_WAIT] )
		Rsprintf(bp," TMW=%d",nstat[MIB_TCP_STATE_TIME_WAIT]);
	if( nstat[MIB_TCP_STATE_CLOSE_WAIT] )
		Rsprintf(bp," CLW=%d",nstat[MIB_TCP_STATE_CLOSE_WAIT]);
	Rsprintf(bp,"\n");

	for( ti = 0; ti < tt->dwNumEntries; ti++ ){
		tr = &tt->table[ti];
		if( tr->dwLocalAddr == 0 ){
			continue;
		}
		if( (tr->dwLocalAddr & 0xFF) == 127 ){
			continue;
		}
		if( (tr->dwLocalAddr & 0xFF000000) == (127 << 24) ){
			continue;
		}
		if( tr->dwState == MIB_TCP_STATE_TIME_WAIT ){
			continue;
		}
		stat = tcpstat(tr->dwState);
		sprintAddr(AVStr(paddr),tr->dwRemoteAddr,0);
		Rsprintf(bp,"T%02d) %s %d:%d %s:%d\n",ti,stat,
			0xFF&tr->dwLocalAddr,ntohs(tr->dwLocalPort),
			paddr,ntohs(tr->dwRemotePort)
		);
	}
	return (char*)bp;
}
char *printNetstat(PVStr(buf)){
	refQStr(bp,buf);
	int res;
	MIB_TCPSTATS tst;
	MIB_IPSTATS ist;

	bzero(&tst,sizeof(tst));
	res = GetTcpStatistics(&tst);
	if( res != 0 ){
		return (char*)bp;
	}
	Rsprintf(bp,"\n");
	Rsprintf(bp,"Tcp-Status: Ret(%d %d %d) Con(%d)",res,
		tst.dwRtoAlgorithm,
		tst.dwRtoMin,
		tst.dwRtoMax,
		tst.dwMaxConn);
	Rsprintf(bp,
	" Open(%d %d) Fail(%d) Est(%d %d) IO(%d %d %d) Err(%d %d) C%d\n",
		tst.dwActiveOpens,
		tst.dwPassiveOpens,
		tst.dwAttemptFails,
		tst.dwEstabResets,
		tst.dwCurrEstab,
		tst.dwInSegs,
		tst.dwOutSegs,
		tst.dwRetransSegs,
		tst.dwInErrs,
		tst.dwOutRsts,
		tst.dwNumConns
	);

	res = GetIpStatistics(&ist);
	if( res != 0 )
		return (char*)bp;
	Rsprintf(bp,"Ip-Stat: ");
	Rsprintf(bp,"%s",ist.dwForwarding?"Forwading ":"");
	Rsprintf(bp,"TTL=%d ",ist.dwDefaultTTL);
	Rsprintf(bp,"In=%d ",ist.dwInReceives);
	Rsprintf(bp,"Out=%d ",ist.dwOutRequests);
	Rsprintf(bp,"NoRoute=%d ",ist.dwOutNoRoutes);
	Rsprintf(bp,"Discard=%d,%d ",ist.dwRoutingDiscards,ist.dwOutDiscards);
	Rsprintf(bp,"Ifs=%d ",ist.dwNumIf);
	Rsprintf(bp,"Addrs=%d ",ist.dwNumAddr);
	Rsprintf(bp,"Routes=%d ",ist.dwNumRoutes);
	Rsprintf(bp,"\n");

	return (char*)bp;
}

#ifdef UNDER_CE /*{*/
int setPowerBG(int bg){
	if( bg )
		PowerPolicyNotify(PPN_UNATTENDEDMODE,TRUE);
	else	PowerPolicyNotify(PPN_UNATTENDEDMODE,FALSE);
	return 0;
}
int setsyspower(const char *name,int flag,int *pflag){
	int nflag = -1;
	int err;

	SetLastError(0);
	if( name ){
		switch( *name ){
			case 'A': nflag = POWER_STATE_ON; break;
			case 'O': nflag = POWER_STATE_OFF; break;
			case 'C': nflag = POWER_STATE_CRITICAL; break;
			case 'B': nflag = POWER_STATE_BOOT; break;
			case 'I': nflag = POWER_STATE_IDLE; break;
			case 'S': nflag = POWER_STATE_SUSPEND; break;
			case 'R': nflag = POWER_STATE_RESET; break;
		}
	}else{
		nflag = flag;
	}
	if( pflag ){
		WCHAR wstat[128];
		DWORD istat = 1;
		GetSystemPowerState(wstat,sizeof(wstat),&istat);
		*pflag = istat;
	}
	if( 0 <= nflag ){
		err = SetSystemPowerState(0,nflag,POWER_FORCE);
		return err;
	}
	return -1;
}
char *syspwstat(PVStr(pwstat)){
	refQStr(sp,pwstat);
	WCHAR spwstat[128];
	DWORD ipwstat;
	IStr(stat,128);
	int res;

	res = GetSystemPowerState(spwstat,sizeof(spwstat),&ipwstat);
	if( res != ERROR_SUCCESS ){
		if( res == ERROR_SERVICE_DOES_NOT_EXIST )
			Rsprintf(sp,"Unsupported");
		else	Rsprintf(sp,"Err=%d");
		return (char*)sp;
	}

	int fi,flag1;
	const char *st = 0;
	for( fi = 0; fi < 32; fi++ ){
		flag1 = 1 << fi;
		if( ipwstat & flag1 ){
		  switch( flag1 ){
		    case POWER_STATE_ON: st = "On"; break;
		    case POWER_STATE_OFF : st = "Off"; break;
		    case POWER_STATE_CRITICAL: st = "Critical"; break;
		    case POWER_STATE_BOOT: st = "Boot"; break;
		    case POWER_STATE_IDLE: st = "Idle"; break;
		    case POWER_STATE_SUSPEND: st = "Suspend"; break;
		    case POWER_STATE_UNATTENDED: st = "Unattended"; break;
		    case POWER_STATE_RESET: st = "Reset"; break;
		    case POWER_STATE_USERIDLE: st = "UserIdle"; break;
		    case POWER_STATE_BACKLIGHTON: st = "BacklightOn"; break;
		    //case POWER_STATE_PASSWORD: st = "Password"; break;
		    default: st = 0;
		  }
		  if( st ){
			Rsprintf(sp,"%s ",st);
		  }
		}
	}
	wstrtostr(stat,spwstat,0);
	Rsprintf(sp,"(%s)",stat);
	return (char*)sp;
}
char *pwstatsym(CEDEVICE_POWER_STATE pwstat){
	switch( pwstat ){
		case PwrDeviceUnspecified: return "Unspecified";
		case D0: return "On";
		case D1: return "LowPower";
		case D2: return "Standby";
		case D3: return "Sleep";
		case D4: return "Off";
		case PwrDeviceMaximum: return "Max";
	}
	return "?";
}
char *devpwstat(PVStr(stat),PCStr(dev),int force){
	refQStr(sp,stat);
	CEDEVICE_POWER_STATE pwstat;
	WCHAR wdev[32];

	strtowstr(wdev,dev,0);
	if( 0 ){
		SetDevicePower(wdev,POWER_NAME,D1);
		SetPowerRequirement(wdev,D1,POWER_NAME|POWER_FORCE,NULL,0);
	}
	if( force )
		GetDevicePower(wdev,POWER_NAME|POWER_FORCE,&pwstat);
	GetDevicePower(wdev,POWER_NAME,&pwstat);
	sprintf(stat,"%s",pwstatsym(pwstat));
	return (char*)sp;
}
/*
#define GET_MACADDR
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr)){
	refQStr(pp,macaddr);
	IPAddr res;
	IPAddr src;
	ULONG maca[8];
	ULONG sz;
	const unsigned char *mac = (unsigned char*)maca;
	int pi;

	src = gethostint_nboV4(ipaddr);
	sz = sizeof(maca);
	res = SendARP(src,0,maca,&sz);
	if( res != NO_ERROR ){
		sprintf(macaddr,"(err=%d)",GetLastError());
		return (char*)macaddr;
	}
	for( pi = 0; pi < sz; pi++ ){
		Rsprintf(pp,"%s%X",0<pi?":":"",mac[pi]);
	}
	return (char*)pp;
}
*/

#include <icmpapi.h>
char *doPing(PCStr(addr),int timeout,int count,PVStr(stat)){
	refQStr(sp,stat);
	IPAddr dst;
	char *data;
	IP_OPTION_INFORMATION qopt,*pqopt=0;
	IStr(resp,1024);
	DWORD rsiz = sizeof(resp);
	int se = -1;
	double Start = Time();
	double Elp;
	int e1,e2;
	static HANDLE icmph;
	static int ok,ng;
	static double oks;
	static double ngs;

	dst = gethostint_nboV4(addr);
	SetLastError(0);
	if( icmph == 0 ){
		icmph = DLL_IcmpCreateFile();
	}
	e1 = GetLastError();
	SetLastError(0);
data = 0;
	se = DLL_IcmpSendEcho(icmph,dst,data,0,pqopt,resp,rsiz,timeout);
	e2 = GetLastError();
	/*
	DLL_IcmpCloseHandle(icmph);
	*/
	Elp = Time()-Start;
	if( e1 || e2 ){
		ng++;
		ngs += Elp;
		Rsprintf(sp,"Ping: %d-%d %.3f %s %X %d %d,%d\n",
			ok,ng,Elp,addr,icmph,se,e1,e2);
	}else{
		ok++;
		oks += Elp;
		Rsprintf(sp,"Ping: %d-%d %.3f %.3f %s\n",
			ok,ng,oks/ok,Elp,addr);
	}
	return (char*)sp;
}

#else /*}{*/
#endif /*}*/

char *listIpNetTab(PVStr(list),PCStr(fmt),PCStr(ipaddr)){
	refQStr(lp,list);
	int ipnetsb[1024];
	MIB_IPNETTABLE *ipnets;
	ULONG sz;
	int res;
	int ni;
	MIB_IPNETROW *ip;
	int pi;
	unsigned int i4;

	sz = sizeof(ipnetsb);
	ipnets = (MIB_IPNETTABLE*)ipnetsb;
	res = GetIpNetTable(ipnets,&sz,0);
	if( res != NO_ERROR ){
		Rsprintf(lp,"GetIpNetTable()=%d\n",res);
		return (char*)list;
	}
	for( ni = 0; ni < ipnets->dwNumEntries; ni++ ){
		ip = &ipnets->table[ni];
		Rsprintf(lp,"A%d)",ni);
		Rsprintf(lp,"I%d)",ip->dwIndex&0xFFFF);
		switch( ip->dwType ){
			case 4: Rsprintf(lp,"S"); break;
			case 3: Rsprintf(lp,"D"); break;
			case 2: Rsprintf(lp,"I"); break;
			case 1: Rsprintf(lp,"O"); break;
			default: Rsprintf(lp,"(%d)",ip->dwType); break;
		}
		Rsprintf(lp,"%d",ip->dwPhysAddrLen);
		Rsprintf(lp," ");
		for( pi = 0; pi < ip->dwPhysAddrLen; pi++ ){
			Rsprintf(lp,"%s%X",0<pi?":":"",ip->bPhysAddr[pi]);
		}
		i4 = (unsigned int)ntohl(ip->dwAddr);
		Rsprintf(lp," %d.%d.%d.%d ",
			i4>>24,0xFF&(i4>>16),0xFF&(i4>>8),0xFF&i4);
		Rsprintf(lp,"\n");
	}
	return (char*)lp;
}

#else /*}{ VC5 */
char *printRoutes(PVStr(buf),PCStr(ifp),PCStr(ipp),int all,int closeEther){
	clearVStr(buf);
	return (char*)buf;
}
char *printNetstat(PVStr(buf)){
	clearVStr(buf);
	return (char*)buf;
}
char *printTcpTable(PVStr(buf)){
	clearVStr(buf);
	return (char*)buf;
}
char *listIpNetTab(PVStr(list),PCStr(fmt),PCStr(ipaddr)){
	clearVStr(list);
	return (char*)list;
}
void winmo_dllstat(PVStr(stat),int all){
	clearVStr(stat);
}
#endif /*}*/
#ifndef GET_MACADDR
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr)){
	clearVStr(macaddr);
	return (char*)macaddr;
}
#endif
#endif /*}*/
