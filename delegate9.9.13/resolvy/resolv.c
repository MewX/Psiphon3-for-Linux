/*///////////////////////////////////////////////////////////////////////
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
Program:	resolv.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950817	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "dns.h"
#include "log.h"

#define MAXRSIZ	2*1024

int DNS_dbgvul = 0;
int DNS_svtcp = 0;
int DNS_cltcp = 0;

static int Start;
static int Nsearch;
static int Nrecv;
static int Qlen;
static int Rlen;
static char ErrStat[128];
extern int DNS_debug;

#if defined(FMT_CHECK)
#define errlog(fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#else
#define errlog FMT_errlog
#endif

static void FMT_errlog(PCStr(fmt),...){
	CStr(msg,128);
	int rem;
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	rem = sizeof(ErrStat) - strlen(ErrStat) - 1;
	if( rem <= strlen(msg) )
		setVStrEnd(msg,rem);
	Xstrcat(FVStr(ErrStat),msg);
}
static void dump(PCStr(what),int inTCP,const void *str,int len){
	unsigned char *up = (unsigned char*)str;
	int i;

	if( (DNS_debug & DBG_DUMP) == 0 ){
		return;
	}
	if( inTCP )
		fprintf(stderr,"-- leng=%d/%d id=%d\n",len,(up[0]<<8)|up[1],
			(up[2]<<8)|up[3]);
	else	fprintf(stderr,"-- leng=%d id=%d\n",len,(up[0]<<8)|up[1]);
	for( i = 0; i < len; i++){
		if( i % 16 == 0 ){
			if( i != 0 )
				fprintf(stderr,"\n");
			fprintf(stderr,"%X %s: ",p2i(&up[i]),what);
		}
		fprintf(stderr,"%02X ",up[i]);
	}
	fprintf(stderr,"\n");
}

int setCloseOnExec(int fd);
int file_ISSOCK(int fd);
void msleep(int msec);

int RES_getns1(int nsi,VSAddr *sin);
int RES_proxy();
int VSA_comp(VSAddr*,VSAddr*);
static int getns1(int nid,int nsx,int nsc,VSAddr *nservv);

#define MAX_NS		10
#define MAX_NS_PARA	 1
#define MAX_RETRY	 2	/* retry for each server */
int RSLV_TIMEOUT1 =	 2;	/* timeout for current request packet */
int RSLV_TIMEOUT =	30;
int RSLV_INV_TIMEOUT =   6;

#define typemask(type)	(1<<type)

int RSLV_TIMEDOUT;

static const char *SYM_TYPE[] = {
	"TYPE=0?",	"A",		"NS",		"MD",
	"MF",		"CNAME",	"SOA",		"MB",
	"MG",		"MR",		"NULL",		"WKS",
	"PTR",		"HINFO",	"MINFO",	"MX",
	"TXT",		"TYPE=17?",	"TYPE=18?",	"TYPE=19?",
	"XPTR",		"TYPE=21?",	"TYPE=22?",	"TYPE=23?",
	"TYPE=24?",	"TYPE=25?",	"TYPE=26?",	"TYPE=27?",
	"AAAA",		"TYPE=29?",	"TYPE=30?",	"TYPE=31?",
	"TYPE=32?",	"SRV",		"TYPE=34?",	"TYPE=35?",
	"TYPE=36?",	"TYPE=37?",	"A6",		"TYPE=39?",
};
#define symTYPE(class)  ((0<=class&&class<=39) ? SYM_TYPE[class]:\
	(class==TY_QXFER  ? "QXFER": \
	(class==TY_QMAILB ? "QMAILB": \
	(class==TY_QMAILA ? "QMAILA": \
	(class==TY_QALL   ? "QALL":"?")))))

static const char *SYM_RCODE[] = {
	"No-error",	"Format-error",	"Server-failure", "Name-error",
     "Not-implemented",	"Refused",	"Error-6",	"Error-7",
	"Error-8",	"Error-9",	"Error-A",	"Error-B",
	"Error-C",	"Error-D",	"Error-E",	"Error-F",
};
static const char *SYM_RR[] = {
	"RR=0?",
	"ANS",
	"SER",
	"ADD",
};
static const char *SYM_CLASS[] = {
	"CLASS=0?",
	"IN",
	"CS",
	"CH",
	"HS",
};
#define symCLASS(class)	((0<=class&&class<=4) ? SYM_CLASS[class]:"CLASS-X")

static char *makeHeader(char head[],int id,int qr,int opcode,int aa,int tc,int rd,int ra,int z,int rcode,int qdc,int anc,int nsc,int arc)
{
	head[ 0] = (id>>8) & 0xFF;
	head[ 1] = id & 0xFF;
	head[ 2] = (qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd;
	head[ 3] = (ra << 7) | (z << 4) | rcode;
	head[ 4] = (qdc >> 8) & 0xFF;
	head[ 5] = qdc & 0xFF;
	head[ 6] = (anc >> 8) & 0xFF;
	head[ 7] = anc & 0xFF;
	head[ 8] = (nsc >> 8) & 0xFF;
	head[ 9] = nsc & 0xFF;
	head[10] = (arc >> 8) & 0xFF;
	head[11] = arc & 0xFF;
	return &head[12];
}
static const char *scanHeader(PCStr(head),Header *Hp)
{	const char *hp;

	hp = head;
	getShort(hp,Hp->id);
	getShort(hp,Hp->M);
	getShort(hp,Hp->qdcount);
	getShort(hp,Hp->ancount);
	getShort(hp,Hp->nscount);
	getShort(hp,Hp->arcount);
	return &head[12];
}
static const char *dumpHeader(PCStr(head),Header *Hp)
{	const char *mp;
	CStr(buf,1024);
	int M;

	mp = scanHeader(head,Hp);
	M = Hp->M;
	sprintf(buf,
	"ID=%d FLAGS=%08x QR=%d Opcode=%d AA=%d TC=%d RD=%d RA=%d Z=%d RCODE=%d ",
		Hp->id,
		M,
		H_QR(M),
		H_OPCODE(M),
		H_AA(M),
		H_TC(M),
		H_RD(M),
		H_RA(M),
		H_Z(M),
		H_RCODE(M)
	);
	Xsprintf(TVStr(buf),"QD=%d AN=%d NS=%d AR=%d",
		Hp->qdcount,
		Hp->ancount,
		Hp->nscount,
		Hp->arcount
	);
	debug(DBG_HEAD,"%s\n",buf);
	return mp;
}

static char *putName(xPVStr(qp),PCStr(name))
{	const char *np;
	CStr(label,64); /* must be in 6bits */
	refQStr(lp,label); /**/
	const char *lx;

	for( np = name; *np; np++ ){
		lp = label;
		if( *np == '.' ){
			/*
			debug(DBG_ANY,"FATAL ERROR: empty label [%s]\n",name);
			return NULL;
				... 9.0.3 NULL result from putName() is
				... not cared at several callers
			*/
			debug(DBG_FORCE,"FATAL ERROR: empty label [%s]\n",name);
			break;
		}
		lx = label + sizeof(label) - 1;
		while( *np && *np != '.' )
		{
			if( lx <= lp ){
				setVStrEnd(lp,0);
				debug(DBG_FORCE,"FATAL: label too long [%s]\n",
					label);
				break;
			}
			setVStrPtrInc(lp,*np++);
		}
		setVStrEnd(lp,0);
		setVStrPtrInc(qp,strlen(label));
		strcpy(qp,label);
		qp += strlen(qp);
		if( *np == 0 )
			break;
	}
	setVStrPtrInc(qp,0);
	return (char*)qp;
}
static char *makeQuestion(PVStr(question),PCStr(name),int type,int xclass)
{	refQStr(qp,question);

	cpyQStr(qp,question);
	qp = putName(QVStr(qp,question),name);
	if( qp == NULL )
		return NULL;
	if( question[0] == 0 )
		return NULL;

	setVStrPtrInc(qp,0xFF & (type >> 8));
	setVStrPtrInc(qp,0xFF & type);
	setVStrPtrInc(qp,0xFF & (xclass >> 8));
	setVStrPtrInc(qp,0xFF & xclass);
	return (char*)qp;
}
static const char *scanName(PCStr(msg),PCStr(ssp),PVStr(name),int siz,int lev)
{	refQStr(np,name);
	const octet *sp = (octet*)ssp;
	int len,low,off,here;

	cpyQStr(np,name);

	if( siz <= 1 || 32 <= lev ){
		errlog("InfiniteRecursion(lev=%d,rem=%d).",lev,siz);
debug(DBG_FORCE,"### pointer loop? (%d): %x %x\n",lev,p2i(msg),p2i(ssp));
		setVStrEnd(np,0);
		return (const char*)sp;
	}
	while( len = *sp++ ){
		if( len & 0xC0 ){
			/* This is a pointer (2 bytes).  First 2 bits should
			 * be one (11) in a pointer. 10 and 01 combinations
			 * are reserved for future use.
			 */
			if( (len & 0xC0) != 0xC0 ){
here = (char*)sp - msg;
debug(DBG_ANY,"### bad pointer(%d): %x: %x\n",lev,here,len);
				sprintf(np,"BAD-POINTER-%x",len);
				np += strlen(np);
				break;
			}
			low = *sp++;
			off = ((len & 0x3F) << 8) | low;

			here = (char*)sp - msg;
			if( here <= off ){
debug(DBG_ANY,"### bad pointer(%d): %d <= %d: %x %x\n",lev,here,off,len,low);
				errlog("ForwardPointer(%d/%d).",here,off);
				sprintf(np,"BAD-POINTER-%x-%x",len,low);
				np += strlen(np);
				break;
			}
			if( off < here && here-2 <= off
			 || ssp <= &msg[off]
			){
debug(DBG_FORCE,"### loop pointer: %d->%d: %X->%X\n",here,off,p2i(ssp),p2i(msg+off));
				errlog("LoopPointer(%d/%d).",here,off);
				sprintf(np,"LOOP-POINTER-%x",off);
				np += strlen(np);
				break;
			}
			scanName(msg,&msg[off],QVStr(np,name),siz-(np-name),lev+1);
			return (char*)sp;
		}else{
			if( siz-(np-name) < len+2 ){
debug(DBG_FORCE,"### name buffer overflow: lev=%d,len=%d,siz=%d\n",lev,len,siz);
				break;
			}
			Bcopy(sp,np,len);
			np += len;
			sp += len;
			if( *sp != 0 )
				setVStrPtrInc(np,'.');
		}
	}
	setVStrEnd(np,0);
	return (const char*)sp;
}
static const char *scanQuery(PCStr(msg),PCStr(question),PVStr(name),int nsiz,int *typep,int *classp)
{	const char *qp;

	qp = question;
	qp = scanName(msg,qp,AVStr(name),nsiz,0);
	getShort(qp,*typep);
	getShort(qp,*classp);
	return qp;
}
static const char *dumpQuestion(int qdi,PCStr(msg),int size,PCStr(question))
{	const char *qp;
	CStr(name,512);
	int type,xclass;
	int nid;

	if( msg+size <= question ){
		debug(DBG_FORCE,"ERROR: dumpQ Overrun [%2d]: %X <= %X\n",
			qdi,p2i(msg+size),p2i(question));
		return NULL;
	}
	qp = scanQuery(msg,question,AVStr(name),sizeof(name),&type,&xclass);

	nid = DNS_putbyname(name);
	debug(DBG_NS|DBG_QANDR,"QUE[%2d]%8s: <%d>%s %s %s\n",
		qdi,"",nid,name,symCLASS(xclass),symTYPE(type));
	DNS_putbyname(name);
	return qp;
}

static void hexd(PCStr(fmt),int col,octet *str,int len)
{	int i;
	for( i = 0; i < len; i++ ){
		if( (i % col) == 0 ){
			if( i != 0 )
				debug(DBG_ALL,"\n");
			debug(DBG_ALL,"%6d: ",i);
		}
		debug(DBG_ALL,fmt,str[i]);
	}
	debug(DBG_ALL,"\n");
}

#define putLongVStr(rp,iv) {\
	setVStrPtrInc(rp,0xFF & (iv >> 24)); \
	setVStrPtrInc(rp,0xFF & (iv >> 16)); \
	setVStrPtrInc(rp,0xFF & (iv >>  8)); \
	setVStrPtrInc(rp,0xFF & (iv >>  0)); \
}

static char LastSOAdom[128]; /* enough to hold x.x.x.x...IP6.INT */

static
char *dumpResourceRecord(int whatx,int rri,PCStr(msg),int size,PCStr(rr),int store)
{	CStr(name,512);
	CStr(rname,512);
	const char *mp;
	int type,xclass,ttl,rdlength;
	const char *what;
	const char *stype;
	const char *sclass;
	int nid,rnid;
	CStr(addr,64);
	CStr(rdata,512);
	refQStr(rp,rdata);
	int pref;
	int newput;

	if( 0 ){ /* 9.9.8 to emulate old implementation */
		store = 1;
	}
	what = SYM_RR[whatx];
	if( msg+size <= rr ){
		debug(DBG_FORCE,"ERROR: dumpR Overrun %s[%2d]: %X <= %X\n",
			what,rri,p2i(msg+size),p2i(rr));
		debug(DBG_ANY,"### %s[%2d]: %d >= size %d\n",
			what,rri,ll2i(rr-msg),size);
		return 0;
	}

	mp = scanName(msg,rr,AVStr(name),sizeof(name),0);
	nid = DNS_putbyname(name);

	getShort(mp,type);
	getShort(mp,xclass);
	getLong(mp,ttl);
	getShort(mp,rdlength);
	if( size-(mp-msg) < rdlength ){
		debug(DBG_FORCE,"ERROR: bad RRlength %d > %d\n",
			rdlength,ll2i(size-(mp-msg)));
	}

	if( type != TY_AAAA )
	if( type <= 0 || 16 < type || xclass <= 0 ||  4 < xclass ){
debug(DBG_ANY,"### %s[%2d]%8d: <%d>%d class=%x type=%x\n",
	what,rri,ttl,nid,p2i(name),xclass,type);
		return 0;
	}

	stype = symTYPE(type);
	sclass = symCLASS(xclass);

	debug(DBG_RR,"%s[%2d]%8d: <%d>%s %s %s\n",
		what,rri,ttl,nid,name,sclass,stype);

	rnid = 0;

	rp = rdata;
	setVStrPtrInc(rp,type);
	setVStrPtrInc(rp,xclass);

	switch( type ){
	    case TY_SRV:
		debug(DBG_FORCE,"SRV dump is not supported\n");
		break;

	    case TY_AAAA:
		strcpy(addr,VSA_ltoa((unsigned char*)mp,16,AF_INET6));
		rnid = DNS_putbyaddr(addr);
		Bcopy(mp,rp,16);
		rp += 16;
			if( store ){
		DNS_putattr(nid,typemask(type),ttl,rdata,rp-rdata);
			}
		debug(DBG_RR,"<%d>%s\n",rnid,addr);
		break;

	    case TY_A:
		strcpy(addr,VSA_ltoa((unsigned char*)mp,4,AF_INET));
		rnid = DNS_putbyaddr(addr);
		setVStrPtrInc(rp,mp[0]);
		setVStrPtrInc(rp,mp[1]);
		setVStrPtrInc(rp,mp[2]);
		setVStrPtrInc(rp,mp[3]);
			if( store ){
		DNS_putattr(nid,typemask(type),ttl,rdata,6);
			}
		debug(DBG_RR,"<%d>%s\n",rnid,addr);

/*
may be useful for inverse query, but could be bad for consistency...
 {
rp = rdata;
*rp++ = TY_PTR;
rp++;
*rp++ = 0xFF & (nid >> 24);
*rp++ = 0xFF & (nid >> 16);
*rp++ = 0xFF & (nid >>  8);
*rp++ = 0xFF & (nid >>  0);
DNS_putattr(rnid,typemask(TY_PTR),ttl,rdata,6);
debug(DBG_FORCE,"%s <%d>%d.%d.%d.%d\n",name,rnid,mp[0],mp[1],mp[2],mp[3]);
 }
*/
		break;

	    case TY_MX:
	    case TY_NS: case TY_CNAME: case TY_PTR:
		if( type != TY_MX )
			scanName(msg,mp,AVStr(rname),sizeof(rname),0);
		else	scanName(msg,mp+2,AVStr(rname),sizeof(rname),0);
		if( rname[0] == 0 ){
			debug(DBG_FORCE,"### ignored empty name for %s %s\n",
				stype,name);
			break;
		}

		rnid = DNS_putbyname(rname);
		setVStrPtrInc(rp,0xFF & (rnid >> 24));
		setVStrPtrInc(rp,0xFF & (rnid >> 16));
		setVStrPtrInc(rp,0xFF & (rnid >>  8));
		setVStrPtrInc(rp,0xFF & (rnid >>  0));
		if( type == TY_MX ){
			setVStrPtrInc(rp,mp[0]);
			setVStrPtrInc(rp,mp[1]);
			if( store ){
		DNS_putattr(nid,typemask(type),ttl,rdata,rp-rdata);
			}
		}
		else
			if( store ){
		DNS_putattr(nid,typemask(type),ttl,rdata,6);
    			}
		debug(DBG_RR,"%s <%d>%s\n",name,rnid,rname);
		break;
	    case TY_SOA:
{
CStr(mname,512);
CStr(rname,512);
int serial,refresh,retry,expire,minimum;
		const char *xmp = mp;
		int mnid,rnid;
		mp =
		scanName(msg,mp,AVStr(mname),sizeof(mname),0);
		mp =
		scanName(msg,mp,AVStr(rname),sizeof(rname),0);
		getLong(mp,serial);
		getLong(mp,refresh);
		getLong(mp,retry);
		getLong(mp,expire);
		getLong(mp,minimum);
		debug(DBG_RR,"%s %s %d %d %d %d %d\n",mname,rname,
			serial,refresh,retry,expire,minimum);
		if( mname[0] == 0 || rname[0] == 0 ){
			debug(DBG_FORCE,"### empty SOA name for %s %s\n",
				stype,name);
		}

		mnid = DNS_putbyname(mname);
		rnid = DNS_putbyname(rname);
		putLongVStr(rp,mnid);
		putLongVStr(rp,rnid);
		putLongVStr(rp,serial);
		putLongVStr(rp,refresh);
		putLongVStr(rp,retry);
		putLongVStr(rp,expire);
		putLongVStr(rp,minimum);
			if( store ){
		newput =
		DNS_putattr(nid,typemask(type),ttl,rdata,rp-rdata);
		if( newput ){
			debug(DBG_FORCE,"SOA got [%s][%s][%s] %d %d %d %d %d\n",
			name,mname,rname,serial,refresh,retry,expire,minimum);
		}
			}
		Xstrcpy(FVStr(LastSOAdom),name);
		mp = xmp;
}
		break;
	    default:
		if( debug(DBG_RR,"[%d]\n",rri) )
			/*hexd("[%d]",16,mp,rdlength)*/;
		break;
	}
	mp += rdlength;
	return (char*)mp;
}

/*
 *	Name Servers
 */

static VSAddr *Me;

DGC*MainConn();
const char *gethostaddrX(PCStr(host));
int SRCIFfor(DGC*Conn,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport);

int bindVSA_SRCIFfor(int sock,PCStr(proto),VSAddr *dst,VSAddr *srcif){
	const char *host = VSA_ntoa(dst);
	int port = VSA_port(dst);
	IStr(lhost,MaxHostNameLen);
	int lports,lport1,lport2,port1,ntry;
	IStr(laddr,64);
	int len;
	int rcode;

	lports = 0;
	if( SRCIFfor(MainConn(),proto,host,port,AVStr(lhost),&lports) ){
		if( lports == 0xFFFF0000 ){
			lport1 = lport2 = 0;
		}else{
			lport1 = 0xFFFF & (lports >> 16);
			lport2 = 0xFFFF & lports;
		}
		strcpy(laddr,gethostaddrX(lhost));
		VSA_atosa(srcif,0,laddr);
		ntry = 32;
		for( port1 = lport1; port1 <= lport2; port1++ ){
			VSA_setport(srcif,port1);
			len = VSA_size(srcif);
			rcode = bind(sock,(SAP)srcif,len);
			debug(DBG_FORCE,"## SRCIF %s:%d <= %s://%s:%d = %d\n",
				laddr,port1,proto,host,port,rcode);
			if( rcode == 0 ){
				return 0;
			}
			if( ntry-- < 0 ){
				break;
			}
		}
		return -2;
	}
	return -1;
}
static int inInitSRCIFforDNS;
static int bindSRCIFforDNS(int sock,VSAddr *Ns,VSAddr *srcif){
	int rcode;

	if( inInitSRCIFforDNS ){
		/* this loop must not happen */
		debug(DBG_FORCE,"FATAL #### loop in SRCIFforDNS (%d)\n",
			inInitSRCIFforDNS);
		return -9;
	}else{
		inInitSRCIFforDNS++;
		/* should suppress DNS resolver during the following call */
		/* "-dns" for exact matching with explicit SRCIF=H:P:"dns" */
		rcode = bindVSA_SRCIFfor(sock,"-dns",Ns,srcif);
		inInitSRCIFforDNS--;
		return rcode;
	}
}

static int makeMysock()
{	int len;
	int rcode;
	int mysock;
	int af;
	const char *me;
	VSAddr Ns;

	if( Me == 0 )
		Me = NewStruct(VSAddr);

	RES_getns1(0,&Ns);
	if( VSA_af(&Ns) == AF_INET6 ){
		af = AF_INET6;
	}else
	af = AF_INET;
	mysock = socket(af,SOCK_DGRAM,0);
	if( mysock < 0 ){
		debug(DBG_FORCE,"RESOLVY cannot get socket() [errno=%d]\n",
			errno);
		return mysock;
	}
	/*
	len = VSA_atosa(Me,0,"0.0.0.0");
	*/
	if( VSA_af(&Ns) == AF_INET6 ){
		me = "::";
	}else
	me = "0.0.0.0";
	len = VSA_atosa(Me,0,me);

	if( (rcode = bindSRCIFforDNS(mysock,&Ns,Me)) == 0 ){
		/* 9.9.8 bound by SRCIF=Host:Port:dns */
		/* the SRCIF (Me) for each Ns should be calculated in the
		 * init. and should be got as RES_getns1X(0,&Ns,Me).  Multiple
		 * ports for mixed IPv4/IPv6 servers should be supported too.
		 */
	}else
	rcode = bind(mysock,(SAP)Me,len);
	if( rcode < 0 ){
		debug(DBG_FORCE,"cannot bind() [errno=%d]\n",errno);
		close(mysock);
		return -1;
	}
	len = sizeof(VSAddr);
	getsockname(mysock,(SAP)Me,&len);
	debug(DBG_ANY,"DNS port = %d/udp [%d]\n",VSA_port(Me),mysock);
	return mysock;
}

static int RR_isin(PCStr(v1),char *rrv[],int rri)
{	int ri,vi,leng;
	const char *r1;

	for( ri = 0; ri < rri; ri++ ){
		r1 = rrv[ri];
		if( r1 == v1 )
			return 1;

		if( r1[0] == TY_A ){
			leng = 2+4;
			for( vi = 0; vi < leng; vi++ )
				if( r1[vi] != v1[vi] )
					break;
			if( vi == leng )
				return 1;
		}
	}
	return 0;
}

static int Phase;
static int lookupCache(int nid,int qtype,int rri,int rrc,char *rrv[])
{	CStr(dname,512);
	CStr(cdname,512);
	char *av[128]; /**/
	const octet *a1;
	const octet *ap;
	int ac,ai;
	int ival;
	int type,xclass;
	int cnid;
	int ttl = 0;

	++Phase;
	DNS_nodephase(nid,Phase);
	DNS_nodename(nid,AVStr(dname));
	if( 0 < Nsearch /* acting as a DNS server */
	 || lSINGLEP()
	){
		/* 9.9.8 expire persistent RR_cache on mem. by TTL */
		ttl = RES_HC_EXPIRE;
	}
	ac = DNS_getattr(nid,typemask(qtype)|typemask(TY_CNAME),ttl,128,av);
	/*
	ac = DNS_getattr(nid,typemask(qtype)|typemask(TY_CNAME),0,128,av);
	*/
	if( 0 < ac ){
		debug(DBG_CACHE,"lookup <%d>%s [%d]\n",nid,dname,ac);
		for( ai = 0; ai < ac; ai++ ){
			if( rrc <= rri ){
				debug(DBG_FORCE,"too many RR: %s\n",dname);
				break;
			}
			a1 = (octet*)av[ai];
			type = *a1++;
			xclass = *a1++;
			ap = a1;
			getLong(ap,ival);

			if( RR_isin(av[ai],rrv,rri) ){
				debug(DBG_ANY,"[%d][%d] ignore duplicate RR\n",
					rri,ai);
				continue;
			}

			if( type == TY_SOA ){
				DNS_nodename(ival,AVStr(dname));
				debug(DBG_CACHE,"[%d] SOA %s\n",ai,dname);
				rrv[rri++] = av[ai];
			}else
			if( type == TY_SRV ){
				debug(DBG_FORCE,"SRV lookup is not supprted\n");
			}else
			if( type == TY_AAAA ){
				debug(DBG_CACHE,"[%d] A %s\n",
					ai,VSA_ltoa(a1,16,AF_INET6));
				rrv[rri++] = av[ai];
			}else
			if( type == TY_A ){
				debug(DBG_CACHE,"[%d] A %d.%d.%d.%d\n",
					ai,a1[0],a1[1],a1[2],a1[3]);
				rrv[rri++] = av[ai];
			}else
			if( type == TY_PTR ){
				DNS_nodename(ival,AVStr(dname));
				debug(DBG_CACHE,"[%d] PTR %s\n",ai,dname);
				rrv[rri++] = av[ai];
			}else
			if( type == TY_CNAME ){
				DNS_nodename(ival,AVStr(cdname));
				if( DNS_nodephase(ival,Phase) == Phase ){
				debug(DBG_ANY,"LOOP[%d] in CNAME: %s -> %s\n",
						Phase,dname,cdname);
					continue;
				}
				debug(DBG_CACHE,"[%d] CNAME %s\n",ai,cdname);
				rrv[rri++] = av[ai];
				cnid = DNS_getbyname(cdname);
				rri = lookupCache(cnid,qtype,rri,rrc,rrv);
			}else
			if( type == TY_MX ){
				DNS_nodename(ival,AVStr(dname));
				debug(DBG_CACHE,"[%d] MX %s\n",ai,dname);
				rrv[rri++] = av[ai];
			}
		}
	}
	return rri;
}

void set_nameserver(PCStr(domain),PCStr(addr))
{	unsigned int nsnid,nsanid;
	CStr(rdata,6);
	unsigned int iaddr;

	nsnid = DNS_putbyname(domain);
	nsanid = DNS_putbyaddr(addr);
	rdata[0] = TY_NS;
	rdata[1] = CL_IN;
	rdata[2] = nsanid>>24;
	rdata[3] = nsanid>>16;
	rdata[4] = nsanid>>8;
	rdata[5] = nsanid;
	DNS_putattr(nsnid,typemask(TY_NS),3600,rdata,6);

	iaddr = inet_addrV4(addr);
	rdata[0] = TY_A;
	rdata[1] = CL_IN;
	rdata[2] = iaddr>>24;
	rdata[3] = iaddr>>16;
	rdata[4] = iaddr>>8;
	rdata[5] = iaddr;
	DNS_putattr(nsanid,typemask(TY_A),3600,rdata,6);
}

static int getns1(int nid,int nsx,int nsc,VSAddr *nservv)
{	VSAddr *ns;
	char *nsv[32]; /**/
	char *nsav[32]; /**/
	const char *ap; /* should be unsigend */
	int nns,nsi,na;
	int nsnid;
	int addr;

	CStr(dname,512);
	CStr(sname,512);

	DNS_nodename(nid,AVStr(dname));
	nns = DNS_getattr(nid,typemask(TY_NS),0,32,nsv);

	for( nsi = 0; nsi < nns; nsi++ ){
		ap = nsv[nns-1-nsi];
		ap += 2;
		getLong(ap,nsnid);
		DNS_nodename(nsnid,AVStr(sname));

		if( na = DNS_getattr(nsnid,typemask(TY_A),0,32,nsav) ){
			ap = nsav[0];
			ap += 2;

if( strcmp(".",dname) != 0 )
debug(DBG_NS,"        %s[%d] server=<%s %s[%d.%d.%d.%d]>\n",
dname,nsi,dname,sname,ap[0],ap[1],ap[2],ap[3]);

			ns = &nservv[nsx++];
			VSA_btosa(ns,AF_INET,(unsigned char*)ap,53);
			getLong(ap,addr);
			if( nsc <= nsx )
				break;
		}else{
			debug(DBG_ANY,"%s[%d] cannot get address of %s\n",
				dname,nsi,sname);
		}
	}
	return nsx;
}

#define NS_REQ	1
#define NS_RESP	2
void dumpns(PCStr(wh)){
	int nsi;
	ResStat *rs;
	VSAddr *ns1;
	for( nsi = 0; nsi < elnumof(LOGX_resStats); nsi++ ){
		rs = &LOGX_resStats[nsi];
		if( rs->rs_stat == 0 ){
			break;
		}
		ns1 = (VSAddr*)rs->rs_vsaddr;
		syslog_ERROR("##NS %s [%d] %s:%d Q%d-R%d (%u - %u)\n",wh,nsi,
			VSA_ntoa(ns1),VSA_port(ns1),rs->rs_req,rs->rs_resp,
			rs->rs_reqlast,rs->rs_resplast
		);
	}
}
void RES_addns(VSAddr *ns){
	int nsi;
	ResStat *rs;
	int nsx = -1;
	const char *status = "FULL";
	VSAddr *ns1 = 0;

	if( lDNS_SORT() == 0 ){
		return;
	}
	for( nsi = 0; nsi < elnumof(LOGX_resStats); nsi++ ){
		rs = &LOGX_resStats[nsi];
		if( VSA_comp(ns,(VSAddr*)rs->rs_vsaddr) == 0 ){
			nsx = nsi;
			ns1 = (VSAddr*)rs->rs_vsaddr;
			status = "DUP";
			goto EXIT;
		}else
		if( rs->rs_stat == 0 && nsx == -1 ){
			nsx = nsi;
		}
	}
	if( 0 <= nsx ){
		rs = &LOGX_resStats[nsx];
		rs->rs_stat = 1;
		bcopy(ns,rs->rs_vsaddr,sizeof(rs->rs_vsaddr));
		ns1 = (VSAddr*)rs->rs_vsaddr;
		status = "NEW";
	}
EXIT:
	syslog_ERROR("##NS-add %X siz=%d/%d %s:%d [%d]%s %s:%d\n",
		p2i(ns),VSA_size(ns),isizeof(VSAddr),VSA_ntoa(ns),VSA_port(ns),
		nsx,status,ns1?VSA_ntoa(ns1):"-",ns1?VSA_port(ns1):-1
	);
}
static ResStat *getrs(VSAddr *ns){
	int nsi;
	VSAddr *ns1;
	ResStat *rs;

	for( nsi = 0; nsi < elnumof(LOGX_resStats); nsi++ ){
		rs = &LOGX_resStats[nsi];
		if( rs->rs_stat == 0 ){
			continue;
		}
		if( VSA_comp(ns,(VSAddr*)rs->rs_vsaddr) == 0 ){
			return rs;
		}
	}
	return 0;
}
static void putnsStat(VSAddr *ns,int st){
	int nsi;
	ResStat *rs;
	VSAddr *ns1;

	if( lDNS_SORT() == 0 ){
		return;
	}
	for( nsi = 0; nsi < elnumof(LOGX_resStats); nsi++ ){
		rs = &LOGX_resStats[nsi];
		if( rs->rs_stat == 0 ){
			break;
		}
		if( VSA_comp(ns,(VSAddr*)rs->rs_vsaddr) == 0 ){
			switch( st ){
				case NS_REQ:
					rs->rs_req++;
					rs->rs_reqlast = time(0);
					break;
				case NS_RESP:
					rs->rs_resp++;
					rs->rs_resplast = time(0);
					break;
			}
			ns1 = (VSAddr*)rs->rs_vsaddr;
			return;
		}
	}
	syslog_ERROR("##NS-putnsStat %X %d [%d] %s:%d\n",p2i(ns),st,
		nsi,VSA_ntoa(ns),VSA_port(ns));
}
static void sortns(VSAddr *nsv,int nsn){
	int nsi;
	VSAddr *ns;
	VSAddr ns0;
	VSAddr *ns1;
	ResStat *rs;

	if( nsn <= 1 ){
		return;
	}
	if( lDNS_SORT() == 0 ){
		return;
	}
	ns = &nsv[0];
	if( rs = getrs(ns) ){
		if( 0 < rs->rs_req && rs->rs_resp == 0 ){
			ns0 = nsv[0];
			for( nsi = 0; nsi < nsn-1; nsi++ ){
				nsv[nsi] = nsv[nsi+1];
			}
			nsv[nsn-1] = ns0;
		}
		for( nsi = 0; nsi < nsn; nsi++ ){
			ns1 = &nsv[nsi];
			syslog_ERROR("##NS-sorted [%d] %s\n",nsi,VSA_ntoa(ns1));
		}
	}
}

static int getns(int nid,int nsc,VSAddr *nservv)
{	int nsx,nsi;
	int dnid;

	nsx = 0;
/*
	if( dnid = DNS_getbyname(RES_NSDOM0) )
		nsx = getns1(dnid,nsx,nsc,nservv);
*/
	/* recursive servers ? first */
	for( nsi = 0; ;nsi++ ){
		VSAddr *ns;

		ns = &nservv[nsx];
		if( RES_getns1(nsi,ns) == 0 )
			break;
		if( VSA_port(ns) == 0 ) /* under initialization ? */
			continue;

		debug(DBG_NS,"        %s[%d] server=<%s [%s:%d]>\n",
			RES_NSDOM0,nsx,RES_NSDOM0,
			VSA_ntoa(ns),VSA_port(ns));
		nsx++;
	}
	sortns(nservv,nsx);

	while( nid ){
		nsx = getns1(nid,nsx,nsc,nservv);
		nid = DNS_parent(nid);
	}
	return nsx;
}

extern struct _resolv_errmsg { defQStr(resolv_errmsg); } resolv_errmsg;
static int dumpResponse(int qidbase,PVStr(resp),int rc,Header *hp,PCStr(addr),int store)
{	const char *mp;
	CStr(qname,1024);
	int nqd,qdi,rri;
	const char *mx = &resp[rc-1];

	mp = dumpHeader(resp,hp);
	if( hp->id < qidbase )
		debug(DBG_NS,"OBSOLETE[%d<%d]from[%s]\n",hp->id,qidbase,addr);

	if( hp->id != qidbase ){
		debug(DBG_FORCE,"%s(%d) ID=Q%d:R%d QD=%d AN=%d NS=%d AR=%d\n",
			addr,rc,qidbase,hp->id,
			hp->qdcount,hp->ancount,hp->nscount,hp->arcount);
	}

	qname[0] = 0;
	if( nqd = hp->qdcount ){
		for( qdi = 0; mp && qdi < nqd; qdi++ ){
			if( !DNS_dbgvul && mx <= mp ){
			debug(DBG_FORCE,"### QD-Overrun %X %X %d\n",p2i(mx),p2i(mp),qdi);
			errlog("QD-Overrun(%d/%d/%d).",qdi,hp->qdcount,ll2i(mx-mp));
			return hp->ancount + hp->nscount + hp->arcount;
			}
			scanName(resp,mp,AVStr(qname),sizeof(qname),0);
			mp = dumpQuestion(qdi,resp,rc,mp);
		}
	}
	for( rri = 0; mp && rri < hp->ancount; rri++ )
	{
		if( !DNS_dbgvul && mx <= mp ){
			debug(DBG_FORCE,"### AN-Overrun %X %X %d\n",p2i(mx),p2i(mp),rri);
			errlog("AN-Overrun(%d/%d/%d).",rri,hp->ancount,ll2i(mx-mp));
			return hp->ancount + hp->nscount + hp->arcount;
		}
		mp = dumpResourceRecord(RR_ANSWER,rri,resp,rc,mp,store);
	}
	for( rri = 0; mp && rri < hp->nscount; rri++ )
	{
		if( !DNS_dbgvul && mx <= mp ){
			debug(DBG_FORCE,"### NS-Overrun %X %X %d\n",p2i(mx),p2i(mp),rri);
			errlog("NS-Overrun(%d/%d/%d).",rri,hp->nscount,ll2i(mx-mp));
			return hp->ancount + hp->nscount + hp->arcount;
		}
		mp = dumpResourceRecord(RR_SERVER,rri,resp,rc,mp,store);
	}
	for( rri = 0; mp && rri < hp->arcount; rri++ )
	{
		if( !DNS_dbgvul && mx <= mp ){
			debug(DBG_FORCE,"### AR-Overrun %X %X %d\n",p2i(mx),p2i(mp),rri);
			errlog("AR-Overrun(%d/%d/%d).",rri,hp->arcount,ll2i(mx-mp));
			return hp->ancount + hp->nscount + hp->arcount;
		}
		mp = dumpResourceRecord(RR_ADDITIONAL,rri,resp,rc,mp,store);
	}

setVStrEnd(resolv_errmsg.resolv_errmsg,0);
if( addr[0] )
	sprintf(resolv_errmsg.resolv_errmsg,"recv[%s](%d) ",addr,rc);
Xsprintf(TVStr(resolv_errmsg.resolv_errmsg),
"Q[%s] ID=%d/%d AA=%d RD=%d RA=%d RCODE=%d ans,ns,add=%d,%d,%d",
qname, hp->id,qidbase,
H_AA(hp->M),H_RD(hp->M),H_RA(hp->M),H_RCODE(hp->M),
hp->ancount,hp->nscount,hp->arcount);

	debug(DBG_NS|DBG_QANDR,"ANS: %s\n",resolv_errmsg.resolv_errmsg);
	return hp->ancount + hp->nscount + hp->arcount;
}
static int recvResponse(int mysock,int qidbase,VSAddr *from,Header *hp)
{	int fromlen;
	int rc;
	const char *mp;
	CStr(resp,MAXRSIZ);
	CStr(addr,64);

	fromlen = sizeof(*from);
	if( DNS_svtcp ){
		unsigned const char *up = (unsigned const char*)resp;
		int leng;
		getpeername(mysock,(SAP)from,&fromlen);
		rc = recv(mysock,(char*)resp,sizeof(resp),0);
		Rlen = rc;
		if( rc < 2 ){
			debug(DBG_FORCE,"failed TCP recv()=%d\n",rc);
			return -1;
		}
		if( 2048 < rc ){
			errlog("LargeResp(%d).",rc);
		}
		leng = (up[0] << 8) | up[1];
		bcopy(resp+2,(char*)resp,rc-2);
		if( leng+2 != rc ){
			errlog("InconsistentRespLen(rcc=%d/len=%d).",rc,leng);
		}
	}else{
rc = SOCKS_recvfrom(mysock,AVStr(resp),sizeof(resp),0,(SAP)from,&fromlen);
		dump("RECV",0,resp,rc);
	}
	if( rc <= 0 )
	{
		debug(DBG_FORCE,"recvfrom(%d)=%d [errno=%d]\n",mysock,rc,errno);
		return -1;
	}
	if( Nsearch ){
		Nrecv++;
	}
	if( fromlen <= 0 ){
		debug(DBG_FORCE,"recvResponse(%d): rc=%d fromlen=%d\n",
			mysock,rc,fromlen);
		return -1;
	}
	strcpy(addr,VSA_ntoa(from));
	return dumpResponse(qidbase,AVStr(resp),rc,hp,addr,1);
}

static int QID;
static int ownerPID;
static int mysock0;			/* background servers */
static int mysocks[MAX_NS_PARA];	/* connected to each foreground server 
					 * to detect UNREACHABLE error on recv
					 */

int initDNSconn(){
	int mypid;
	int nsi,mysock1;

	mypid = getpid();
	if( ownerPID == mypid )
	{
		if( file_ISSOCK(mysock0) )
		return mysock0;

		debug(DBG_FORCE,"DNS socket [%d] broken ??? %d/%d\n",
			mysock0,ownerPID,mypid);
		ownerPID = 0;
	}

	if( ownerPID != 0 ){
		debug(DBG_NS,"initDNSconn(): previous pid=%d close",
			ownerPID);
		close(mysock0);
		SOCKS_udpclose(mysock0);
		for( nsi = 0; nsi < MAX_NS_PARA; nsi++ ){
			mysock1 = mysocks[nsi];
			close(mysock1);
			SOCKS_udpclose(mysock1);
			debug(DBG_NS,"(%d)",mysock1);
		}
		debug(DBG_NS,"\n");
	}

	debug(DBG_NS,"initDNSconn(): pid=%d\n",mypid);
	ownerPID = mypid;
	QID = 0;

	mysock0 = makeMysock();
	if( mysock0 < 0 )
		return mysock0;
	setCloseOnExec(mysock0);
	for( nsi = 0; nsi < MAX_NS_PARA; nsi++ ){
		mysock1 = mysocks[nsi] = makeMysock();
		setCloseOnExec(mysock1);
	}
	return mysock0;
}

int RES_BACKGROUND = 1;

int (*RES_hltovsa)(PCStr(hlist),int ac,VSAddr av[]);
static int scanns(PCStr(ns),int mns,VSAddr servers[]){
	int nsx;

	if( *ns == '$' && RES_hltovsa ){
		nsx = (*RES_hltovsa)(ns+1,mns,servers);
		return nsx;
	}
	return 0;
}

int dialupTOX(PCStr(wh),int sock,void *addr,int leng,int timeout,PVStr(cstat));

int getRRbynameaddr(int timeout,PCStr(ns0),PCStr(name),int qtype,int rrc,char *rrv[])
{	int wc;
	int nid;
	int nhit;
	VSAddr servers[128],*ns,*xns;
	VSAddr qservers[128],qns;
	int qserverx[128],npns,pnsi,ntry;
	VSAddr rservers[128],rns;
	int salen;
	int nns,nsi,sns,nque,nrns,rnsi;
	int nsent,nrecv;
	int qidbase;
	CStr(qbuf,MAXRSIZ);
	refQStr(qp,qbuf);
	int qlen;
	int start;
	int mysock1;
	int timeout1;
	int fds[MAX_NS_PARA+1];
	int rdv[MAX_NS_PARA+1]; 
	VSAddr cns[MAX_NS_PARA+1];
	int resps[MAX_NS_PARA+1],nresp;
	Header Head;
	int M,gotAA;
	int gotRecovErr; /* got recoverable errors */
	int nturn;
	int ndialup = 0;
	int serrno = 0;

	if( *name == 0 ){
		/* should ignore any invalid name ? */
		debug(DBG_FORCE,"getRRbynameaddr(NULL)\n");
		return 0;
	}
	nid = DNS_putbyname(name);
	if( nhit = lookupCache(nid,qtype,0,rrc,rrv) )
	{
		if( lSINGLEP() ){
			putResTrace("{ignRR%d}",nhit);
		}else
		goto EXIT;
	}

	if( initDNSconn() < 0 )
		goto EXIT;

	QID = (QID + 1) & 0xFFFF;
	qidbase = QID;
	qp = makeHeader(qbuf,QID, 0,O_QUERY,0,0,1,0,0,0, 1,0,0,0);
	qp = makeQuestion(QVStr(qp,qbuf),name,qtype,CL_IN);
	if( qp == NULL )
		goto EXIT;

	qlen = (char*)qp - qbuf;

dumpHeader(qbuf,&Head);
dumpQuestion(0,qbuf,qlen,qbuf+12);
dump("SEND",0,qbuf,qlen);

	if( DNS_svtcp ){
		int connectTO(int sock,SAP addr,int leng,int timeout);
		int conx;
		int conok;
		int rsock;

		bcopy(qbuf,qbuf+2,qlen);
		setVStrElem(qbuf,0,qlen>>8);
		setVStrElem(qbuf,1,qlen);
		qlen += 2;

		if( ns0 && *ns0 && (nns=scanns(ns0,elnumof(servers),servers)) ){
			debug(DBG_FORCE,"SV[%s:%d] <- %s [%s]\n",
				VSA_ntoa(&servers[0]),VSA_port(&servers[0]),
				name,symTYPE(qtype));
		}else{
			nns = getns(nid,128,servers);
		}
		ns = &servers[0];
		nhit = 0;
		rsock = socket(VSA_af(ns),SOCK_STREAM,0);
		conok = 0;
		for( conx = 0; conx < 5; conx++ ){
			conok = connectTO(rsock,(SAP)ns,VSA_size(ns),1000)==0;
			if( conok ){
				break;
			}
			msleep(200);
			close(rsock);
			rsock = socket(VSA_af(ns),SOCK_STREAM,0);
		}
		if( conok ){
			int wcc;
			int nans;
			wcc = send(rsock,qbuf,qlen,0);
			Qlen = qlen;
			nans = recvResponse(rsock,qidbase,&rns,&Head);
			nhit = lookupCache(nid,qtype,0,rrc,rrv);
		}else{
			debug(DBG_FORCE,"cannot connect to server (%d)\n",
				rsock);
			if( Nsearch ) sleep(10);
		}
		close(rsock);
		return nhit;
	}

	gotAA = 0;
	gotRecovErr = 0;
	npns = 0;
	nrns = 0;
	nque = 0;
	nhit = 0;
	nsent = nrecv = 0;

	start = time(0);
	for( nturn = 0; ; nturn++ ){
		debug(DBG_NS,"queries=%d responses=%d\n",nque,nrns);

		if( nhit = lookupCache(nid,qtype,0,rrc,rrv) )
			goto EXIT;

		if( gotRecovErr ){
			debug(DBG_NS,"ERR=%d AA=%d\n",gotRecovErr,gotAA);
			if( 2 < gotRecovErr )
				goto EXIT;
			/* leave a small chance to avoid a mad server */
			timeout = RSLV_TIMEOUT1;
		}else
		if( gotAA ){
			debug(DBG_NS,"AA got (%d).\n",gotAA);
			goto EXIT;
		}
		if( timeout < (time(0) - start) ){
			debug(DBG_NS,"TIMEOUT: %d\n",timeout);
			break;
		}
		if( MAX_NS <= nrns ){
			debug(DBG_NS,"MAX_NS: %d <= %d\n",MAX_NS,nrns);
			break;
		}

		if( ns0 && *ns0 && (nns=scanns(ns0,elnumof(servers),servers)) ){
			debug(DBG_FORCE,"SV[%s:%d] <- %s [%s]\n",
				VSA_ntoa(&servers[0]),VSA_port(&servers[0]),
				name,symTYPE(qtype));
		}else
		nns = getns(nid,128,servers);
		if( nns <= 0){
			debug(DBG_NS,"no server\n");
			break;
		}

		if( 0 < nturn ){ /* to escape possible tight loop ... */
			debug(DBG_FORCE,"[%s]*%d q=%d,a=%d, s=%d,r=%d (%ds)\n",
				name,
				nturn,nque,nrns,nsent,nrecv,ll2i(time(0)-start));
			msleep(50);
		}

		fds[0] = mysock0;
		sns = 0;
		salen = 0;
		for( nsi = 0; nsi<nns && sns<MAX_NS_PARA; nsi++ ){
			xns = ns = &servers[nsi];
			for( rnsi = 0; rnsi < nrns; rnsi++ ){
				if( VSA_comp(xns,&rservers[rnsi]) == 0 )
					goto NEXT;
			}
			if( isWindowsCE() ){
				porting_dbg("DNS q=%d r=%d n=%X/%d l=%d e=%d",
					nque,nrns,p2i(ns),nns,salen,serrno);
				if( salen == 0 && ns != 0 ){
					salen = VSA_size(ns);
				} 
			}
			if( 0 < nque )
			if( nrns == 0 )
			if( 0 < salen )
			if( isWindowsCE() ) /* with dialup network */
			/*
			if( serrno == EHOSTUNREACH || serrno == ENETUNREACH )
			*/
			{
				IStr(cstat,256);
				errno = serrno;
				if( -1 <= dialupTOX("DNS",mysock1,ns,salen,30,
				  AVStr(cstat)) )
				  putResTrace("(DNSdialup%d,%d)",++ndialup,nsi);
			}
			for( pnsi = 0; pnsi < npns; pnsi++ ){
			    if( VSA_comp(xns,&qservers[pnsi]) == 0 ){
				ntry = qserverx[pnsi];
				qserverx[pnsi] += 1;
				if( MAX_RETRY <= ntry ){
if( RES_BACKGROUND )
if( ntry == MAX_RETRY ){
ns = &qservers[pnsi];
salen = VSA_size(ns);
SOCKS_sendto(mysock0,qbuf,qlen,0,(SAP)ns,salen);
serrno = errno;
debug(DBG_NS|DBG_QANDR,"sent BACKGROUND, ID=%d, sent=%d, recv=%d, time=%d, %s\n",
QID,nsent,nrecv,ll2i(time(0)-start),VSA_ntoa(ns));
putnsStat(ns,NS_REQ);
}
					goto NEXT;
				}
				break;
			    }
			}
			if( pnsi == npns ){
				qservers[pnsi] = *ns;
				qserverx[pnsi] = 1;
				npns++;
			}

			fds[sns+1] = mysock1 = mysocks[sns];
			cns[sns+1] = *ns;
			nque++;
			qns = *ns;
salen = VSA_size(ns);
wc = SOCKS_sendto(mysock1,qbuf,qlen,0,(SAP)ns,salen);
serrno = errno;
putnsStat(ns,NS_REQ);
			sns++;
			nsent++;

			if( wc < 0 )
				qserverx[pnsi] = MAX_RETRY;

			debug(DBG_NS|DBG_QANDR,"sent[%s] (%d) put=%d ID=%d\n",
				VSA_ntoa(ns),qserverx[pnsi],wc,
				QID);
		NEXT:;
		}

		timeout1 = RSLV_TIMEOUT1;
		if( sns == 0 ){
			int remain;
			remain = timeout - (time(0) - start);
			if( 0 < nque && 0 < remain ){
				timeout1 = remain;
				debug(DBG_NS,"no more server, wait %dsec.\n",
					remain);
			}else{
				debug(DBG_NS,"no more server, %d %d\n",
					remain,nque);
				break;
			}
		}

		nresp = 0;
		for( nsi = 0; nsi < sns+1; nsi++ )
			resps[nsi] = 0;

		for( nsi = 0; nsi < nque; nsi++ ){ 
			int nready, fdi;
			int nans;
			int timeout;

			timeout = 1;
			for( fdi = 0; fdi < sns+1; fdi++ ){
				if( resps[fdi] == 0 ){
					timeout = timeout1 * 1000;
					break;
				}
			}
			nready = PollIns(timeout,sns+1,fds,rdv);
			if( nready < 0 ){
				debug(DBG_FORCE,"poll()=%d [errno=%d] %d:%d,%d\n",
					nready,errno,sns+1,fds[0],fds[1]);
				goto EXIT;
			}
			if( nready <= 0 ){
				RSLV_TIMEDOUT = 1;
				break;
			}

			for( fdi = 0; fdi < sns+1; fdi++ ){
			    if( 0 < rdv[fdi] ){
				resps[fdi] = 1;
				nans=recvResponse(fds[fdi],qidbase,&rns,&Head);
				if( 0 <= nans ){
					putnsStat(&rns,NS_RESP);
				}

if( 0 <= nans && Head.id < qidbase ){
	debug(DBG_NS,"ignore result for former query (%d / %d)\n",
		Head.id, qidbase);
	continue;
}
				nrecv++;

if( fdi == 0 )
debug(DBG_NS,"recv BACKGROUND, ID=%d/%d, sent=%d, recv=%d, time=%d, %s\n",
Head.id,qidbase, nsent,nrecv,ll2i(time(0)-start),VSA_ntoa(&rns));

				if( nans < 0 ){
					rns = cns[fdi];
					debug(DBG_NS,"unreachable ? %s\n",
						VSA_ntoa(&rns));
				}else{
				    M = Head.M;
				    if( H_AA(M) )
					gotAA++;

				    if( H_AA(M) || H_RD(M) && H_RA(M) ){
					if( H_RCODE(M) == 3 ){
						debug(DBG_NS,"Non-existing domain.\n");
						goto EXIT;
					}
					if( H_RCODE(M) == 0 && nans == 0 ){
						debug(DBG_NS,"Nothing.\n");
						if( H_AA(M) )
							gotRecovErr += 2;
						else	gotRecovErr += 1;
					}
				    }
				}

				nresp++;
				if( nhit = lookupCache(nid,qtype,0,rrc,rrv) )
					goto EXIT;
				rservers[nrns++] = rns;
			    }
			}
		}
		nque -= nresp;
	}
EXIT:
	return nhit;
}

static int mxsort(char **rr1,char **rr2)
{	const char *rp1;
	const char *rp2;
	int pri1,pri2;

	rp1 = *rr1;
	rp2 = *rr2;
	if( *rp1 != TY_MX || *rp2 != TY_MX )
		return 0;

	rp1 = *rr1+6; getShort(rp1,pri1);
	rp2 = *rr2+6; getShort(rp2,pri2);
	return  pri1 - pri2;
}
int gethostbynameaddr_dns(PCStr(ns),PCStr(name),int qtype,int rrc,char *rrv[],PVStr(rrb),PVStr(cname))
{	const char *rp;
	int rri,rro;
	int ival;
	CStr(dname,512);
	CStr(CNAME,512);
	refQStr(rrp,rrb);
	int start;
	int timeout;
	int type;
	int mx,nmx,mxi,rmx;
	char *mxv[64]; /**/

	if( inInitSRCIFforDNS ){
		debug(DBG_FORCE,"----DNS in init, ignored Q [%s]\n",name);
		return 0;
	}

	putResTrace("DNS{%s}",name);
	if( strncasecmp(name,"_srv.",5) == 0 ){
		name += 5;
		qtype = TY_SRV;
	}

	mx = qtype == TY_A && strncmp(name,"-MX.",4) == 0;
	if( mx ){
		name += 4;
		nmx = gethostbynameaddr_dns(ns,name,TY_MX,rrc,rrv,AVStr(rrb),AVStr(cname));
		/* multiple MXs should be sorted by their preference...
		 * - returned in -PREFERENCE-VALUE.mx-host.domain
		 * - sort 
		 * - remove "-PREFERENCE-VALUE."
		 */
		if( nmx == 0 && cname[0] != 0 ){
			/* not MX but CNAME is cached */
			CStr(cn,512);
			strcpy(cn,cname);
			setVStrEnd(cname,0);
			nmx = gethostbynameaddr_dns(ns,cn,TY_MX,rrc,rrv,AVStr(rrb),AVStr(cname));
		}
		if( nmx <= 0 )
			return gethostbynameaddr_dns(ns,name,qtype,rrc,rrv,AVStr(rrb),AVStr(cname));

		if( elnumof(mxv) <= nmx )
			nmx = elnumof(mxv);
		for( mxi = 0; mxi < nmx; mxi++ ){
			mxv[mxi] = rrv[mxi];
		}
		rmx = 0;
		rrp = (char*)rrb;
		for( mxi = 0; mxi < nmx; mxi++ ){
			if( strncasecmp(mxv[mxi],"-MX",3) == 0 )
				continue;
			rmx += gethostbynameaddr_dns(ns,mxv[mxi],TY_A,
				rrc-rmx,rrv+rmx,AVStr(rrp),VStrNULL);
			rrp = rrv[rmx+1];
		}
		return rmx;
	}

	start = time(0);
	if( qtype == TY_A || qtype == TY_AAAA )
		timeout = RSLV_TIMEOUT;
	else	timeout = RSLV_INV_TIMEOUT;

	rrc = getRRbynameaddr(timeout,ns,name,qtype,rrc,rrv);
	rrp = (char*)rrb;

	if( qtype == TY_MX && 0 < rrc ){
		qsort(rrv,rrc,sizeof(char*),(sortFunc)mxsort);
	}

	rro = 0;
	CNAME[0] = 0;
	for( rri = 0; rri < rrc; rri++ ){
		type = rrv[rri][0];
		rp = rrv[rri] = &rrv[rri][2];
		rrv[rro] = rrv[rri];

		switch( type ){
		    case TY_AAAA:
			rrv[rro] = (char*)rrp;
			Bcopy(rp,rrp,16);
			rrp += 16;
			rro++;
			break;

		    case TY_A:
			/*printf("[%d] %d.%d.%d.%d\n",
				rri,rp[0],rp[1],rp[2],rp[3]);*/
			rrv[rro] = (char*)rrp;
			Bcopy(rp,rrp,4);
			rrp += 4;
			rro++;
			break;

		    case TY_MX:
		    case TY_CNAME:
			if( qtype == TY_PTR )
				break;

		    case TY_PTR:
			getLong(rp,ival);
			DNS_nodename(ival,AVStr(dname));
			if( type == TY_CNAME ){
				strcpy(CNAME,dname);
				if( cname != 0 )
					strcpy(cname,dname);
				if( qtype != TY_CNAME && qtype != TY_PTR )
					continue;
			}
			rrv[rro] = (char*)rrp;
			strcpy(rrp,dname);
			rrp += strlen(rrp)+1;
			rro++;
			break;
		}
	}
	rrv[rro] = 0;
	rrv[rro+1] = (char*)rrp; /* return value to MX search */

	debug(DBG_NS,"%d seconds, %d(%d) records\n",ll2i(time(0)-start),rro,rrc);

	if( rro == 0 && 0 < rri )
	if( qtype == TY_A || qtype == TY_AAAA )
	if( cname != 0 && CNAME[0] && strcasecmp(name,CNAME) != 0 )
	{
		debug(DBG_ANY,"search A/AAAA of '%s' for '%s'\n",CNAME,name);
		rro =
		gethostbynameaddr_dns(ns,CNAME,qtype,rrc,rrv,AVStr(rrb),VStrNULL);
	}
	return rro;
}


const char *DNS_DOMAIN;
const char *DNS_ORIGIN;
const char *DNS_ADMIN;
const char *DNS_MX;
int   DNS_SERIAL;
int   DNS_REFRESH;
int   DNS_RETRY;
int   DNS_EXPIRE;
int   DNS_MINTTL;

static struct hostent *gethostbyNX(PCStr(name),PCStr(af),PCStr(domain));
static struct hostent *gethostbyN(PCStr(name))
{
	return gethostbyNX(name,0,0);
}
extern int RES_client_dependent;
static char NXDOM[128];
static int nNXDOM;
static int NXDOM_RCU; /* cached RES_CACHED_UNKNOWN for NXDOM */
extern int RES_CACHED_UNKNOWN;

static struct hostent *gethostbyNX(PCStr(name),PCStr(af),PCStr(domain))
{	struct hostent *ht;
	CStr(xname,512);
	const char *dp;
	const char *saf = RES_AF;
	int asis;

	if( *name == 0 ){
		debug(DBG_FORCE,"Skip gethostbyNX(NULL)\n");
		return NULL;
	}

	if( streq(NXDOM,name) ){
		if( nNXDOM++ == 0 )
		debug(DBG_FORCE,"Skip retrying non-existent name [%s]\n",name);
		RES_CACHED_UNKNOWN = NXDOM_RCU;
		return NULL;
	}
	if( af ){
		saf = RES_AF;
		RES_AF = (char*)af;
	}

	ht = NULL;
	asis = RES_ASIS;
	RES_ASIS = 1;

	/*
	 * 1) xxx.Dom in file,NIS
	 * 2) xxx     in file,NIS,DNS if with .Dom in the query
	 * 3) xxx.Dom in DNS
	 * 4) xxx.Dom in file,NIS,DNS if without .Dom in the query
	 */
	if( !RES_proxy() ){ /* without DNS */
		ht = _GETHOSTBYNAME(name);
	}

	if( ht == NULL )
	if( DNS_DOMAIN[0] )
	if( dp = strcasestr(name,DNS_DOMAIN) )
	if( dp[strlen(DNS_DOMAIN)] == 0 ){
		strcpy(xname,name);
		dp = strcasestr(xname,DNS_DOMAIN);
		truncVStr(dp);
		if( xname < dp && dp[-1] == '.' )
			((char*)dp)[-1] = 0;
		ht = _GETHOSTBYNAME(xname);
	}
	if( ht == NULL )
	if( RES_proxy() ){ /* with DNS */
		ht = _GETHOSTBYNAME(name);
	}

	if( DNS_DOMAIN[0] )
	if( strtailstr(name,DNS_DOMAIN) == 0 )
	if( ht == NULL ){
		sprintf(xname,"%s.%s",name,DNS_DOMAIN);
		ht = _GETHOSTBYNAME(xname);
	}

	if( af ){
		RES_AF = (char*)saf;
	}

	if( RES_client_dependent ){
		/* don't cache client dependent result */
	}else
	if( ht == NULL ){
		if( strlen(name) < sizeof(NXDOM) ){
		Xstrcpy(FVStr(NXDOM),name);
		NXDOM_RCU = RES_CACHED_UNKNOWN;
		}
	}else{
		Xstrcpy(FVStr(NXDOM),"");
		NXDOM_RCU = 0;
	}
	nNXDOM = 0;
	RES_ASIS = asis;

	return ht;
}
static
char *putRR(PVStr(rrpa),PCStr(name),int type,int ttl,int length,PCStr(data))
{	refQStr(rrp,rrpa);

	rrp = putName(AVStr(rrp),name);
	putShort((char*)rrp,type);
	putShort((char*)rrp,CL_IN);
	putLong((char*)rrp,ttl);
	putShort((char*)rrp,length);
	Bcopy(data,rrp,length);
	rrp += length;
	return (char*)rrp;
}
static int putRR_A(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	struct hostent *ht;
	int anc,rttl,rrdlength;
	int ai;
	const char *baddr;

	rrp = *rrpp;
	ht = gethostbyNX(name,"4","");
	if( ht == NULL )
		return 0;

	if( ht->h_addrtype == AF_INET6 )
		return 0;

	anc = 0;
	rttl = DNS_MINTTL;
	rrdlength = ht->h_length;
	for( ai = 0; ht->h_addr_list[ai] != 0; ai++ ){
		baddr = ht->h_addr_list[ai];
		rrp = putRR(AVStr(rrp),name,TY_A,rttl,rrdlength,baddr);
		anc++;
	}

	*rrpp = (char*)rrp;
	return anc;
}
static int putRR_AAAA(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	struct hostent *ht;
	int anc,rttl,rrdlength;
	int ai;
	const char *baddr;
	CStr(xname,512);

	rrp = *rrpp;

	sprintf(xname,"-AAAA.%s",name);
	ht = gethostbyNX(xname,"6","");
	if( ht == NULL )
		return 0;

	anc = 0;
	rttl = DNS_MINTTL;
	rrdlength = ht->h_length;
	for( ai = 0; ht->h_addr_list[ai] != 0; ai++ ){
		baddr = ht->h_addr_list[ai];
		rrp = putRR(AVStr(rrp),name,TY_AAAA,rttl,rrdlength,baddr);
		anc++;
	}

	*rrpp = (char*)rrp;
	return anc;
}
static
int putRR_name(char **rrpp,xPVStr(rrp),struct hostent *ht,int type,PCStr(name))
{	int anc;
	int rttl,rrdlength;
	CStr(rbuff,512);
	refQStr(np,rbuff);

	anc = 0;
	rttl = DNS_MINTTL;

	if( type == TY_MX ){
		struct hostent *ht1;
		int ai,ax;
		const char *baddr;
		char baddrs[16][16]; /**/
		int bleng,btype;
		int pri;

		bleng = ht->h_length;
		btype = ht->h_addrtype;
		for( ax = 0; ax < 16 && (baddr = ht->h_addr_list[ax]); ax++ )
			bcopy(baddr,baddrs[ax],bleng);

		for( ai = 0; ai < ax; ai++ ){
			baddr = baddrs[ai];
			ht1 = _GETHOSTBYADDR(baddr,bleng,btype);
			if( ht1 == NULL )
				continue;
			pri = 0;
			np = rbuff;
			putShort((char*)np,pri);
			np = putName(QVStr(np,rbuff),ht1->h_name);
			rrdlength = np - rbuff;
			rrp = putRR(AVStr(rrp),name,type,rttl,rrdlength,rbuff);
			anc++;
		}
	}else{
		{
			np = rbuff;
			np = putName(QVStr(np,rbuff),ht->h_name);
			rrdlength = np - rbuff;
			rrp = putRR(AVStr(rrp),name,type,rttl,rrdlength,rbuff);
			anc++;
		}
	}

	*rrpp = (char*)rrp;
	return anc;
}
static int relay_cachedRRs(PVStr(rrb),char **rrrp,PCStr(name),int qtype);
static int putRR_SOA(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	CStr(rbuff,512);
	refQStr(np,rbuff);
	int anc,rttl,rrdlength;
	struct hostent *ht;
	int rrc;
	char *rrv[4];

	rrp = *rrpp;

debug(DBG_FORCE,"---- RR_SOA[%s][%s]\n",name,DNS_DOMAIN);
	if( strtailstr(name,DNS_DOMAIN) == NULL ){
		if( !RES_proxy() ){
			return 0;
		}
		rrc = getRRbynameaddr(RSLV_TIMEOUT,"",name,TY_SOA,4,rrv);
		anc = relay_cachedRRs(AVStr(rrb),rrpp,name,TY_SOA);
		if( 0 < anc )
		{
debug(DBG_FORCE,"---- RR_SOA[%s][%s] = %d\n",name,DNS_DOMAIN,anc);
			return anc;
		}
	}

	ht = gethostbyNX(name,"4","");
	if( ht == NULL )
		return 0;

	np = rbuff;
	np = putName(QVStr(np,rbuff),DNS_ORIGIN);
	np = putName(QVStr(np,rbuff),DNS_ADMIN);
	PutLong(np,DNS_SERIAL);
	PutLong(np,DNS_REFRESH);
	PutLong(np,DNS_RETRY);
	PutLong(np,DNS_EXPIRE);
	PutLong(np,DNS_MINTTL);
	rrdlength = np - rbuff;

	anc = 1;
	rttl = 0;
	rrp = putName(AVStr(rrp),DNS_DOMAIN);
	PutShort(rrp,TY_SOA);
	PutShort(rrp,CL_IN);
	PutLong(rrp,rttl);
	PutShort(rrp,rrdlength);
	Bcopy(rbuff,rrp,rrdlength);
	rrp += rrdlength;

	*rrpp = (char*)rrp;
	return anc;
}
static int relay_cachedRR(PVStr(rrb),char **rrrp,PCStr(name),int qtype)
{	int anc,nid,ac,ai,type,xclass,ival,pri,rttl,rrdlength;
	refQStr(rrp,rrb);
	CStr(rbuff,512);
	refQStr(np,rbuff);
	char *av[8]; /**/
	const char *a1;
	const char *ap;
	CStr(dname,512);

	anc = 0;
	rrp = *rrrp;

	if( nid = DNS_getbyname(name) )
	if( ac = DNS_getattr(nid,typemask(qtype),0,8,av) )
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		type = *a1++;
		if( type != qtype )
			continue;
		xclass = *a1++;
		ap = a1;
		getLong(ap,ival);
		np = rbuff;

		if( type == TY_SOA ){
			DNS_nodename(ival,AVStr(dname));
			np = putName(AVStr(np),dname);
			getLong(ap,ival);
			DNS_nodename(ival,AVStr(dname));
			np = putName(AVStr(np),dname);
			getLong(ap,ival); putLongVStr(np,ival);
			getLong(ap,ival); putLongVStr(np,ival);
			getLong(ap,ival); putLongVStr(np,ival);
			getLong(ap,ival); putLongVStr(np,ival);
			getLong(ap,ival); putLongVStr(np,ival);
			rttl = DNS_MINTTL;
			rrdlength = np - rbuff;
			rrp = putRR(AVStr(rrp),name,type,rttl,rrdlength,rbuff);
			anc++;
			continue;
		}
		/* MX */
		getShort(ap,pri); /* MX preference */
		putShort((char*)np,pri);

		DNS_nodename(ival,AVStr(dname));
		np = putName(QVStr(np,rbuff),dname);
		rttl = DNS_MINTTL;
		rrdlength = np - rbuff;
		rrp = putRR(QVStr(rrp,rrb),name,type,rttl,rrdlength,rbuff);
		anc++;
	}
	*rrrp = (char*)rrp;
	return anc;
}
static int relay_cachedRRs(PVStr(rrb),char **rrrp,PCStr(name),int qtype)
{	int anc;

	anc = relay_cachedRR(AVStr(rrb),rrrp,name,qtype);
	if( anc == 0 ){
		/* _nicname._tcp.domain _service._proto.domain RFC2782
		 * the RRs of it belongs to "domain", so find the domain
		 */
		if( *name == '_' ){
			const char *hp;
			const char *dp;
			for( hp = name; *hp == '_'; ){
				if( dp = strchr(hp,'.') )
					hp = dp + 1;
				else	break;
			}
			anc = relay_cachedRR(AVStr(rrb),rrrp,hp,qtype);
		}
		if( anc == 0 )
		if( LastSOAdom[0] && strtailstr(name,LastSOAdom) ){
			/* host.domain
			 * SOA record of the domain belongs to "domain", so...
			 */
			anc = relay_cachedRR(AVStr(rrb),rrrp,LastSOAdom,qtype);
		}
	}
	return anc;
}
static int putRR_SRV(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	int anc;
	int rrc;
	char *rrv[4];

	if( strtailstr(name,DNS_DOMAIN) != NULL ){
		anc = 0;
		return anc;
	}

	if( !RES_proxy() ){
		return 0;
	}
	rrp = *rrpp;
	rrc = getRRbynameaddr(RSLV_TIMEOUT,"",name,TY_SRV,elnumof(rrv),rrv);
	anc = relay_cachedRRs(AVStr(rrb),rrpp,name,TY_SRV);
	return anc;
}

/*
 * to be used in hosts or NIS as
 *    a1.a2.a3.a4 hostA -MX.hostB
 *    b1.b2.b3.b4 hostB
 */
static int putRR_MX(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	struct hostent *ht;
	CStr(mxname,512);
	int anc;

	rrp = *rrpp;

	sprintf(mxname,"-MX.%s",name);
	ht = gethostbyN(mxname);

	if( ht != NULL )
	if( anc = relay_cachedRR(AVStr(rrb),rrpp,name,TY_MX) )
		return anc;

	if( ht == NULL ){
		if( DNS_MX )
			ht = gethostbyN(DNS_MX);
		if( ht == NULL )
			ht = gethostbyN(name);
		if( ht == NULL )
			return 0;
	}

	return putRR_name(rrpp,AVStr(rrp),ht,TY_MX,name);
}
static int putRR_PTR(PVStr(rrb),char **rrpp,PCStr(name))
{	refQStr(rrp,rrb);
	struct hostent *ht;
	VSAddr sab;
	const char *baddr;
	int bleng,btype;

	rrp = *rrpp;

	if( strcasestr(name,REVERSE_DOM) == 0 )
	if( strcasestr(name,".IP6.INT") == 0 )
		return 0;

	if( VSA_dnstosa(&sab,0,name) <= 0 )
		return 0;
	bleng = VSA_decomp(&sab,&baddr,&btype,NULL);
	ht = _GETHOSTBYADDR(baddr,bleng,btype);
	if( ht == NULL )
		return 0;

	return putRR_name(rrpp,AVStr(rrp),ht,TY_PTR,name);
}

int dns_search(PVStr(reply),PCStr(query),int qcc,PCStr(froma),int fromp)
{	const char *qp;
	refQStr(rp,reply);
	Header Head,RHead;
	int QM,RM,qdc,anc,nsc,arc;
	int nauth;
	CStr(name,512);
	CStr(RRbuf,2048);
	refQStr(rrp,RRbuf);
	int qtype,qclass;
	int rtype,rclass,rttl,rrdlength;
	int rleng;
	int unknown = 0;
	int isauth = 0;
	refQStr(xrrp,RRbuf);
	int unsupported = 0;
	const char *rp0;

	if( Nsearch == 0 ){
		Start = time(0);
	}
	Nsearch++;
	ErrStat[0] = 0;
	dump("Q",DNS_cltcp,query,qcc);
	if( DNS_cltcp ){
		unsigned char *up = (unsigned char*)query;
		int len;
		len = (up[0] << 8) | up[1];
		if( len != qcc-2 ){
			debug(DBG_FORCE,"BAD LENGTH %d/%d\n",len,qcc);
		}
		bcopy(query+2,(char*)query,qcc-2);
		qcc -= 2;
	}

	/*
	 * should not do retry when acting as a recursive server
	 * because the retrial will be scheduled by the client
	 */
	RSLV_TIMEOUT = 10;

	qp = query;
	qp = scanHeader(qp,&Head);
	qp = scanQuery(query,qp,AVStr(name),sizeof(name),&qtype,&qclass);

	/*
	debug(DBG_FORCE,"QUERY %s %s %s ID=%d\n",
		name,symCLASS(qclass),symTYPE(qtype),Head.id);
	*/
	/*
	debug(DBG_FORCE,"QUERY (%d) %s %s %s ID=%d\n",
		H_OPCODE(Head.M),name,symCLASS(qclass),symTYPE(qtype),Head.id);
	*/
	debug(DBG_FORCE,"QUERY (%d) %s %s %s ID=%d <<%s:%d\n",
		H_OPCODE(Head.M),name,symCLASS(qclass),symTYPE(qtype),Head.id,
		froma,fromp);
	setVStrEnd(resolv_errmsg.resolv_errmsg,0);

	if( H_QR(Head.M) != 0 ){
		debug(DBG_FORCE,"Got response as query, ignored.\n");
		return -1;
	}

	rrp = RRbuf;

	anc = 0;
	nauth = 0;
	RES_CACHED_UNKNOWN = 0;

	if( 2 <= H_OPCODE(Head.M) ){
		errlog("NotSupported(op=%d).",H_OPCODE(Head.M));
		debug(DBG_FORCE,"Not supported, opcode=%d\n",H_OPCODE(Head.M));
		unsupported = 1;
		unknown = 1;
		isauth = 0;
		goto PUTRESP;
	}

	switch( qtype ){
	    case TY_SRV:anc += putRR_SRV(AVStr(RRbuf),(char**)&rrp,name); break;
/*
	    case TY_SOA:anc += putRR_SOA(AVStr(RRbuf),(char**)&rrp,name); break;
*/
	    case TY_A:  anc += putRR_A(AVStr(RRbuf),(char**)&rrp,name);   break;
	    case TY_AAAA:anc +=putRR_AAAA(AVStr(RRbuf),(char**)&rrp,name);break;
	    case TY_PTR:anc += putRR_PTR(AVStr(RRbuf),(char**)&rrp,name); break;

	    case TY_NS:
		break;
	    case TY_MX:
	    case TY_QMAILA:
		anc += putRR_MX(AVStr(RRbuf),(char**)&rrp,name); break;
		break;

	    case TY_QALL:
			anc += putRR_A(AVStr(RRbuf),(char**)&rrp,name);
			anc += putRR_AAAA(AVStr(RRbuf),(char**)&rrp,name);
			anc += putRR_MX(AVStr(RRbuf),(char**)&rrp,name);
			anc += putRR_SOA(AVStr(RRbuf),(char**)&rrp,name);
			anc += putRR_PTR(AVStr(RRbuf),(char**)&rrp,name);
			break;
	}
	if( RES_CACHED_UNKNOWN == 0 )
	if( anc == 0 || qtype == TY_SOA || qtype == TY_SRV ){
		nauth = putRR_SOA(AVStr(RRbuf),(char**)&rrp,name);
debug(DBG_FORCE,"---- SOA nauth=%d\n",nauth);
	}

	xrrp = rrp;
	if( qtype == TY_SOA || qtype == TY_SRV ){
		unknown = (anc == 0 && nauth == 0);
	}else{
	unknown = anc==0 && putRR_A(AVStr(RRbuf),(char**)&xrrp,name)==0 && putRR_PTR(AVStr(RRbuf),(char**)&xrrp,name)==0;
	}
	isauth = strtailstr(name,DNS_DOMAIN) != NULL;

PUTRESP:
	QM = Head.M;
	RM = 0;
	SET_QR(RM,1);
	SET_OPCODE(RM,H_OPCODE(QM));
	/*
	SET_AA(RM,1);
	*/
	if( !unknown || isauth )
		SET_AA(RM,1);
	else	SET_AA(RM,0);

	if( !RES_proxy() )
		SET_RD(RM,0);
	else
	SET_RD(RM,H_RD(QM));
	SET_RA(RM,0);
	if( anc == 0 )
	{
		if( unknown ){
		    if( isauth )
			SET_RCODE(RM,3); /* UNKNOWN */
		    else
		    if( RES_proxy() ){
			SET_RCODE(RM,3); /* acting as a proxy resolver */
		    }
		    else{
			debug(DBG_FORCE,"%s<-REFUSED %s (DNSCONF=domain:%s)\n",
				froma,name,DNS_DOMAIN);
			SET_RCODE(RM,5); /* REFUSED */
		    }
		}
		if( unsupported ){
			SET_RCODE(RM,4); /* UNSUPPORTED */
		}
	}
	qdc = 1;

	cpyQStr(rp,reply);
	putShort((char*)rp,Head.id);
	putShort((char*)rp,RM);
	putShort((char*)rp,qdc);
	putShort((char*)rp,anc);
	putShort((char*)rp,nauth);
	putShort((char*)rp,0);
	rp0 = rp;
	rp = makeQuestion(QVStr(rp,reply),name,qtype,qclass);
	if( rp == NULL ){
		rp = (char*)rp0;
		rp = makeQuestion(QVStr(rp,reply),"-",qtype,qclass);
		debug(DBG_FORCE,"makeQuesion(%s) = NULL -> %X\n",name,p2i(rp));
		if( rp == NULL ){
			return -1;
		}
	}

	if( anc || nauth ){
		Bcopy(RRbuf,rp,rrp-RRbuf);
		rp += (rrp-RRbuf);
	}

	rleng = rp - reply;
	/* 9.9.8 just for dump, don't cache it (maybe from stale cache) */
	dumpResponse(Head.id,AVStr(reply),rleng,&RHead,"",0);

	if( resolv_errmsg.resolv_errmsg[0] ){
		debug(DBG_FORCE,"ANSWER %s [ID=%d]\n",
			resolv_errmsg.resolv_errmsg,QID);
	}

	if( DNS_cltcp ){
		Xbcopy(reply,DVStr(reply,2),rleng);
		setVStrElem(reply,0,rleng>>8);
		setVStrElem(reply,1,rleng);
		rleng += 2;
	}
	dump("R",DNS_cltcp,reply,rleng);
	if( (DNS_debug & DBG_TRACE) != 0 ){
		fprintf(stderr,"-- %4d %4dQ %4dR %20s %dC %5d [%s]\n",
		ll2i(time(0)-Start),Nsearch-1,Nrecv-1,name,H_RCODE(RM),Rlen,ErrStat);
	}
	if( ErrStat[0] ){
		debug(DBG_FORCE,"ERROR [qid=%d][RES#%d] %s Code=%d %d [%s]\n",
			Nsearch-1,Nrecv-1,name,H_RCODE(RM),Rlen,ErrStat);
	}
	if( DNS_svtcp ){
		msleep(100); /* wait the test-case to finish */
	}
	return rleng;
}

void dns_server(int qsock,int rsock)
{	int icc,occ;
	CStr(ib,2048);
	CStr(ob,2048);

	icc = read(qsock,ib,sizeof(ib));
	occ = dns_search(AVStr(ob),ib,icc,"",0);
	IGNRETP write(rsock,ob,occ);
}
void (*RES_DNSSERVER)(int,int) = dns_server;
int (*RES_DNSSEARCH)(PVStr(r),const char*,int,const char*,int) = dns_search;
