/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-1999 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1994-1999 Yutaka Sato

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	hostlist.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950225	extracted from delegated.h
//////////////////////////////////////////////////////////////////////#*/
#ifndef _HOSTLIST_H_
#define _HOSTLIST_H_

#include "vaddr.h"
#include "ystring.h"

typedef unsigned char Uchar;

typedef struct _Host {
	int	 h_asis; /* compare name as-is (alias, virtual-name, ...) */
  const	char	*h_name;
  const	char	*h_rexp;
	VAddr	 h_mask;
	VAddr	 h_Addr;
	struct {
	Uchar	 h_low;
	Uchar	 h_high;
	} ranges[4];
  const	char   **h_proto;
  const	char   **h_port;
  const	char   **h_user;
  const	char   **h_userRexp;
	int	 h_op;
struct _Host	*h_route;
	int	 h_listid; /* refer the HostList */
  const	char	*h_vdomain;
	int	 h_type;
} Host;
#define HT_CLIF 0x0001 /* client side interface (self port) */
#define HT_BYHOST 0x0010	/* by host identity only */
#define HT_BYAUTH 0x0020	/* by authenticated identity only */
#define HT_BYCERT 0x0040	/* by certificate only */
#define HT_BYANY  0x00F0
#define HT_BYAGENT 0x0100 /* by User-Agent (or server type) only */
#define HT_IPV4    0x0200
#define HT_IPV6    0x0400
#define HT_BYFILE  0x0800	/* ADMDIR/screen/NAME/ddd/aaa.bbb.ccc.ddd */
#define HT_RIDHOST 0x1000	/* match with RIDENT local host */
#define HT_RIDPEER 0x2000	/* match with RIDENT remote peer */
#define HT_UNKNOWN 0x4000

#define HT_BYUSER(h)	(h->h_type & (HT_BYAUTH|HT_BYCERT))

typedef struct _HostList {
  const	char	*hl_what;
	int	 hl_inc;
	int	 hl_size;
	int	 hl_cnt;
	Host   **hl_List;
	int	 hl_noIdent;
	int	 hl_flags;
	int	 hl_base; /* base for extracting in random order */
} HostList;
#define HL_APPEND	1 /* append by default */
#define HL_PROTECT	2 /* disable modification */
#define HL_NOIDENT	4 /* disable Ident protocol to get username */
#define HL_NORESOLV	8 /* disable host name resolution */
/* HostList flags NOIDENT,NORESOLV,... should be flags for each Host too... */
#define HL_BYHOST	0x10 /* mathichg based on peer host identity only */
#define HL_BYCLHOST	0x20 /* matching with the client host */
#define HL_BYADDR	0x40 /* matching with the address asis */
#define HL_BYAUTH	0x80 /* matching with Authentiation info. */
#define HL_BYCLIF	0x100 /* matching with the client side interface */
#define HL_BYAGENT	0x200
#define HL_XRANDOM	0x1000 /* extracted in random order */
#define HL_XRANDSET	0x2000 /* hl_base is set */
#define HL_BYNAMEONLY	0x4000 /* textual matching only(as prefixed with "-")*/

/*
typedef struct {
	char	**a_protos;
	Host	 *a_srchosts;
	int	  a_srcmaxport;
	int	  a_srcminport;
	char	**a_srcusers;
	Host	 *a_dsthosts;
	int	 *a_dstports;
	char	**a_urls;
} Access;
*/

/*
typedef struct {
	int	m_inhibit;
  const	char*	m_ssmask;
  const	char*	m_ssvalue;
	int	m_mask;
	int	m_value;
} Mask;

typedef struct {
	int	a_port;
	Mask	a_To;
	Mask	a_From;
} Access;
init_access(){
	int ai;
	Access *ap;
}
AccessOK(client,server)
{	int ai;
	Access *ap;
	int value;
}
*/


#define ANYP	0L

int hostIsinList(HostList *hostlist,PCStr(proto),PCStr(hostname),int portnum,PCStr(username));
int CTX_hostIsinListX(void *ctx,HostList *hostlist,PCStr(proto),PCStr(hostname),int portnum,PCStr(username),int ac,AuthInfo *av[]);
#define hostIsinListX(hl,pr,hn,pn,un,ac,av) CTX_hostIsinListX(Conn,hl,pr,hn,pn,un,ac,av)
int addHostList1(PCStr(hostmask),HostList *hostlist);
void putHostListTab(PCStr(aname),HostList *HL);
HostList *NotifyPltfrmHosts();

#endif
