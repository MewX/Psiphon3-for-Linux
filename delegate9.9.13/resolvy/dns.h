/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	dns.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950817	created
//////////////////////////////////////////////////////////////////////#*/

#define PORT_DNS 53

typedef unsigned char octet;
typedef unsigned short int octet2;

/*
 *	TYPE values
 */
#define TY_A	    1	/* a host address */
#define TY_NS	    2	/* an authoritative name server */
#define TY_MD	    3	/* a mail destination => MX */
#define TY_MF	    4	/* a mail forwarder => MX */
#define TY_CNAME    5	/* the canonical name for an alias */
#define TY_SOA	    6	/* marks the start of a zone of authority */
#define TY_MB	    7	/* a mailbox domain name (EXPERIMENTAL) */
#define TY_MG	    8	/* a mail group member (EXPERIMENTAL) */
#define TY_MR	    9	/* a mail rename domain name (EXPERIMENTAL) */
#define TY_NULL	   10	/* a null RR (EXPERIMENTAL) */
#define TY_WKS	   11	/* a well known service description */
#define TY_PTR	   12	/* a doman name pointer */
#define TY_HINFO   13	/* host information */
#define TY_MINFO   14	/* mailbox or mail list information */
#define TY_MX	   15	/* mail exchange */
#define TY_TXT	   16	/* text strings */
#define TY_XPTR	   20	/* a pointer for an alias */
#define TY_AAAA	   28	/* IPv6 */
#define TY_SRV     33	/* a service */
#define TY_A6	   38	/* IPv6 */
/*
 *	QTYPE values
 */
#define TY_QXFER	  252	/* a request for a transfer of an entire zone */
#define TY_QMAILB  253	/* a request for mailbox-related records (MB,MG,MR) */
#define TY_QMAILA  254	/* a request for mail agent RRs (Obsolete - see MX) */
#define TY_QALL	  255	/* a request for all records */

/*
 *	CLASS values
 */
#define CL_IN	    1	/* the Internet */
#define CL_CS	    2	/* the CSNET class (Obsolete) */
#define CL_CH	    3	/* the CHAOS class */
#define CL_HS	    4	/* Hesiod */
/*
 *	QCLASS values
 */
#define CL_QANY	  255	/* any class */

/*
 *	OPCODE values
 */
#define O_QUERY	    0
#define O_IQUERY    1
#define O_STATUS    2

#define uc(p,i,s)	(((octet*)p)[i]<<s)
#define getLeng(p)	(uc(p,0,8)|uc(p,1,0))
#define getShort(p,v)	{v = uc(p,0,8)|uc(p,1,0); p += 2;}
#define getLong(p,v)	{v = uc(p,0,24)|uc(p,1,16)|uc(p,2,8)|uc(p,3,0); p += 4;}

#define putShort(p,v)	{*p++ = v>> 8; *p++ = v;}
#define PutShort(p,v)	putShort((char*)p,v)
#define putLong(p,v)	{*p++ = v>>24; *p++ = v>>16; *p++ = v>>8; *p++ = v;}
#define PutLong(p,v)	putLong((char*)p,v)

typedef struct {
	octet2	id;
	octet2	M;
	octet2	qdcount;
	octet2	ancount;
	octet2	nscount;
	octet2	arcount;
} Header;

#define H_QR(M)     ((M & 0x8000) >> 15)
#define H_OPCODE(M) ((M & 0x7800) >> 11)
#define H_AA(M)     ((M & 0x0400) >> 10)
#define H_TC(M)     ((M & 0x0200) >>  9)
#define H_RD(M)     ((M & 0x0100) >>  8)
#define H_RA(M)     ((M & 0x0080) >>  7)
#define H_Z(M)      ((M & 0x0070) >>  4)
#define H_RCODE(M)  ( M & 0xF)

#define SET_QR(M,v)	(M = M & ~0x8000 | 0x8000 & (v << 15))
#define SET_OPCODE(M,v)	(M = M & ~0x7800 | 0x7800 & (v << 11))
#define SET_AA(M,v)	(M = M & ~0x0400 | 0x0400 & (v << 10))
#define SET_TC(M,v)	(M = M & ~0x0200 | 0x0200 & (v <<  9))
#define SET_RD(M,v)	(M = M & ~0x0100 | 0x0100 & (v <<  8))
#define SET_RA(M,v)	(M = M & ~0x0080 | 0x0080 & (v <<  7))
#define SET_Z(M,v)	(M = M & ~0x0070 | 0x0070 & (v <<  4))
#define SET_RCODE(M,v)	(M = M & ~0x000F | 0x000F & (v <<  0))


typedef struct rr {
	int	 rr_nid;
	int	 rr_type;
	int	 rr_class;
	int	 rr_ttl;
	int	 rr_rdlength;
	octet	*rr_data;
      struct rr *rr_next;
} RR;


/*
#define REVERSE_DOM	"IN-ADDR.ARPA"
*/
#define REVERSE_DOM	"in-addr.arpa"

#define RES_NSDOM0	"*"


#define RR_ANSWER	1
#define RR_SERVER	2
#define RR_ADDITIONAL	3

#define DBG_QANDR	0x01
#define DBG_NS		0x02
#define DBG_CON		0x04
#define DBG_HEAD	0x08
#define DBG_QUE		0x10
#define DBG_RR		0x20
#define DBG_CACHE	0x40
#define DBG_ALL		0xFF
#define DBG_ANY		0xFE
#define DBG_FORCE	-1
#define DBG_TRACE	0x100
#define DBG_DUMP	0x200

#define RT_CACHE 'C'
#define RT_FILE	'F'
#define	RT_NIS	'N'
#define RT_DNS	'D'
#define RT_SYS	'S'
#define RT_UNKNOWN 'U'
extern const char *_RSLV_CONF;
extern const char *_HOSTSFILE;
extern const char *_NISMAP_NAME;
extern const char *_NISMAP_ADDR;

extern int RSLV_TIMEOUT1;
extern int RSLV_TIMEOUT;
extern int RSLV_INV_TIMEOUT;
extern const char *RES_AF; /* "4", "6", "46", or "64" */
extern int RES_ASIS; /* don't try search with DNSRCH, DEFDNAME extensions */

extern const char *RES_HC_DIR;
extern int   RES_HC_EXPIRE;
#define UNKNOWN_HOSTNAME	"?"
#define UNKNOWN_HOSTADDR	"\377\377\377\377"

extern const char *RES_VERIFY;

#if defined(FMT_CHECK) /*{*/
#define res_debug(flag,fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#else
#define FMT_res_debug res_debug
int FMT_res_debug(int,const char*,...);
#endif /*}*/

#define debug res_debug

int DNS_putbyaddr(PCStr(addr));
int DNS_getbyaddr(PCStr(addr));
int DNS_putbyname(PCStr(name));
int DNS_getbyname(PCStr(name));
int DNS_parent(int nid);
int DNS_nodename(int nid,PVStr(name));
int DNS_putattr(int nid,int flag,int ttl,PCStr(data),int leng);
int DNS_getattr(int nid,int flag,int ttl,int ac,char *av[]);
int DNS_nodephase(int nid,int phase);
void DNS_nodedump(int nid);
void DNS_dump();

#define RESOLVERS_SIZ 512
char *RES_resolvers(PVStr(resolvers));

