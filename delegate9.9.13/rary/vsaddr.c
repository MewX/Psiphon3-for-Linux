/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	ins.c (INET socket)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	991112	extracted from inets.c, nbio.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "log.h"

typedef struct sockaddr_in SIN;
typedef struct sockaddr_in6 SIN6;
typedef struct sockaddr_un SUN;
typedef struct sockaddr SA;

int IPV6_unify4mapped = 1;

int VSA_port(VSAddr *sap);
int VSA_decomp(VSAddr *sap,const char **baddr,int *btype,const char **bport);
void path2hostlocal(PCStr(path),PVStr(host),int size);

int sock_isconnectedX(int sock,int sinonly);
int sock_isconnected(int sock){
	return sock_isconnectedX(sock,1);
}
int sock_isconnectedX(int sock,int sinonly){
	int len;
	VSAddr sin;

	((SUN*)&sin)->sun_family = 0;
	len = sizeof(sin);
	if( getpeername(sock,(SAP)&sin,&len) == 0 )
	if( len == sizeof(SIN) || len == sizeof(SIN6) )
	{
		if( VSA_port(&sin) != 0 )
			return 1;
	}
	else
	if( !sinonly ){
		if( 0 < len && ((SUN*)&sin)->sun_family == AF_UNIX ){
			return 1;
		}else
		if( len == 0 && ((SUN*)&sin)->sun_family == 0 ){
			/* maybe socketpair() */
			/* on MacOSX and Solaris10 */
			return 1;
		}
	}

	return 0;
}
int sock_peerfamlen(int sock){
	int len;
	VSAddr sin;

	((SUN*)&sin)->sun_family = 0;
	len = sizeof(sin);
	if( getpeername(sock,(SAP)&sin,&len) == 0 ){
		return ((SUN*)&sin)->sun_family * 1000 + len;
	}else{
		return -1;
	}
}
int sock_isv6(int sock){
	int len;
	VSAddr sin;

	len = sizeof(sin);
	if( getsockname(sock,(SAP)&sin,&len) == 0 )
		if( len == sizeof(SIN6) )
			return 1;
	return 0;
}
int sock_isAFUNIX(int sock){
	int len;
	SUN Sun;

	len = sizeof(Sun);
	if( getsockname(sock,(SAP)&Sun,&len) == 0 )
		if( Sun.sun_family == AF_UNIX )
			return 1;
	return 0;
}
extern int isUDPsock(int sock);
int strfSocket(PVStr(desc),int size,PCStr(fmt),int sock){
	CStr(tmp,1024);
	VSAddr ssa;
	VSAddr psa;
	SIN *sip = (SIN*)&ssa;
	int port;
	int len;

	if( isUDPsock(sock) )
		strcpy(desc,"UDP ");
	else	strcpy(desc,"TCP ");

	len = sizeof(ssa);
	bzero(&ssa,sizeof(ssa));
	if( getsockname(sock,(SAP)&ssa,&len) == 0 ){
		switch( sip->sin_family ){
			case AF_UNIX: Xsprintf(TVStr(desc),"AF_UNIX "); break;
			case AF_INET: Xsprintf(TVStr(desc),"AF_INET "); break;
			default:
			Xsprintf(TVStr(desc),"AF_%d ",sip->sin_family); break;
			break;
		}
		port = VSA_port(&ssa);
		Xsprintf(TVStr(desc),":%d ",port);
	}
	len = sizeof(psa);
	bzero(&psa,sizeof(psa));
	if( getpeername(sock,(SAP)&psa,&len) == 0 ){
		port = VSA_port(&psa);
		Xsprintf(TVStr(desc),"<< :%d ",port);
	}
	return 1;
}

static const char VSA_afunixdom[] = ".af-local";
static const char VSA_afunixaddr[] = "127.0.0.127";
int VSA_afunixport = 0xFFFF;

const char *VSA_afunixroot = 0;  /* can be like "/tmp" */
const char *VSA_hostlocal(){ return VSA_afunixdom; }
const char *VSA_hostlocaladdr(){ return VSA_afunixaddr; }
int VSA_hostlocalport(){ return VSA_afunixport; }

int VSA_afunix(VSAddr *sap,PVStr(host),int size)
{	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family != AF_UNIX )
		return 0;

	if( host != NULL ){
		path2hostlocal(sup->sun_path,BVStr(host),size);
		syslog_DEBUG("#### [%s]<-[%s]\n",host,sup->sun_path);
	}
	return 1;
}
void path2hostlocal(PCStr(path),PVStr(host),int size)
{	const char *sp;
	refQStr(dp,host); /**/
	CStr(buf,256);
	const char *root;

	sp = path;
	if( root = VSA_afunixroot ){
		if( strncmp(sp,root,strlen(root)) == 0 )
			sp += strlen(root);
	}
	if( *sp == '/' )
		sp++;
	reverseDomainX(sp,AVStr(buf),'/',"/");
	for( sp =  buf; *sp; sp++ ){
		assertVStr(host,dp+1);
		if( *sp == '/' )
			setVStrPtrInc(dp,'.');
		else
		if( *sp == '.' ){
			setVStrPtrInc(dp,'.');
			setVStrPtrInc(dp,'.');
		}else
		if( *sp == ':' ){
			sprintf(dp,"=%02X",*sp);
			sp += strlen(sp);
		}else{
			setVStrPtrInc(dp,*sp);
		}
	}
	setVStrEnd(dp,0);
	wordscanX(VSA_afunixdom,TVStr(host),size-strlen(host));
}
#define isB16(ch) ('0'<=ch&&ch<='9'||'a'<=ch&&ch<='z'||'A'<=ch&&ch<='Z')
int hostlocal2path(PCStr(host),PVStr(path),int size)
{	const char *sp;
	CStr(buf,256);
	refQStr(dp,buf); /**/
	const char *xp = &buf[sizeof(buf)-1];
	char ch;

	if( host == NULL )
		return 0;
	if( strtailstr(host,VSA_afunixdom) == NULL )
		return 0;

	wordscanX(host,BVStr(path),size);
	strtailstr(path,VSA_afunixdom)[1] = 0;
	for( sp = path; ch = *sp; sp++ ){
		if( xp <= dp ){
			break;
		}
		if( ch == '.' ){
			if( sp[1] == '.' )
				sp++;
			else	ch = '/';
		}
		if( ch == '=' || ch == '%' )
		if( isB16(sp[1]) && isB16(sp[2]) ){
			IStr(x2,3);
			int ich = '?';
			setVStrElem(x2,0,sp[1]);
			setVStrElem(x2,1,sp[2]);
			setVStrElem(x2,2,0);
			sscanf(x2,"%x",&ich);
			ch = ich;
			sp += 2;
		}
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
	reverseDomainX(buf,BVStr(path),'/',"/");

	if( VSA_afunixroot )
		Strins(BVStr(path),VSA_afunixroot);

	syslog_DEBUG("#### [%s]->[%s]\n",host,path);
	return 1;
}

int VSA_addrisANY(VSAddr *sap)
{	SIN *sip;
	SIN6 *sin6;
	int *ip;

	sin6 = (SIN6*)sap;
	/*
	if( sin6->sin6_family == AF_INET6 ){
	*/
	if( ((SIN*)sin6)->sin_family == AF_INET6 ){
		ip = (int*)&sin6->sin6_addr;
		return ip[0]==0 && ip[1]==0 && ip[2]==0 && ip[3]==0;
	}
	sip = (SIN*)sap;
	return sip->sin_addr.s_addr == INADDR_ANY;
}
int VSA_addr(VSAddr *sap)
{	SIN *sip;
	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family == AF_UNIX )
		return inet_addr(VSA_afunixaddr);
	if( sup->sun_family == AF_INET6 ){
		return ntohl(((int*)&(((SIN6*)sap)->sin6_addr))[3]);
	}

	sip = (SIN*)sap;
	return ntohl(sip->sin_addr.s_addr);
}
int VSA_addrX(VSAddr *sap,unsigned int ap[4]){
	SIN *sip;
	sip = (SIN*)sap;

	if( sip->sin_family == AF_UNIX ){
		ap[0] = ap[1] = ap[2] = 0;
		ap[3] = inet_addr(VSA_afunixaddr);
	}
	if( sip->sin_family == AF_INET ){
		ap[0] = ap[1] = ap[2] = 0;
		ap[3] = ntohl(sip->sin_addr.s_addr);
	}
	if( sip->sin_family == AF_INET6 ){
		int *ip = (int*)&((SIN6*)sap)->sin6_addr;
		ap[0] = ntohl(ip[0]);
		ap[1] = ntohl(ip[1]);
		ap[2] = ntohl(ip[2]);
		ap[3] = ntohl(ip[3]);

if(0)
		if( ip[0] == 0 && ip[1] == 0 && ip[2] == 0 ){
			if( ip[3] == 1 ){
				ip[3] = 0x7F000001; /* 127.0.0.1 */
			}
 fprintf(stderr,"#### >>>>> IPv6 %X %X %X %X\n",ip[0],ip[1],ip[2],ip[3]);
			return AF_INET;
		}
		/*
		if( ip[0] == 0 && ip[1] == 0 && ip[2] == 0xFFFF ){
			syslog_ERROR("## IPv4-mapped IPv6 [%X]\n",ip[3]);
			ip[2] = 0;
			return AF_INET;
		}
		*/
	}
	return sip->sin_family;
}

#ifdef _MSC_VER
#define NO_INET_NTOP 1
#undef inet_ntop
#define inet_ntop
#else
#define NO_INET_NTOP 0
#endif

/*
static char ntoa_buf[64];
*/
typedef struct {
	MStr(a_buf6,64);
	MStr(a_buf4,32);
} NtoaBuf;
static NtoaBuf ntoaBufs[32];
#define ntoa_buf4 ntoaBufs[getthreadgix(0)%elnumof(ntoaBufs)].a_buf4
#define ntoa_buf6 ntoaBufs[getthreadgix(0)%elnumof(ntoaBufs)].a_buf6

char *inet_ntoaX(struct in_addr in){
	char *aa;
	aa = inet_ntoa(in);
	if( aa ){
		strcpy(ntoa_buf4,aa);
		return ntoa_buf4;
	}
	return aa;
}
#define inet_ntoa(in) inet_ntoaX(in)

const char *VSA_ntoaX(VSAddr *sap);
const char *VSA_ntoa(VSAddr *sap)
{
	const char *aa;
	aa = VSA_ntoaX(sap);
	return aa;
}
const char *VSA_ntoaX(VSAddr *sap)
{	SIN *sip;
	const char *addr;
	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family == AF_UNIX )
	if( sup->sun_path[0] ){
		/* should convert to "xxx.af-loadl" format ? */
		return sup->sun_path;
	}else{
		return VSA_afunixaddr;
	}

	if( sup->sun_family == AF_INET6 ){
		CStr(hbuf,128);
		char *ap; /**/
		int id = ((SIN6*)sap)->sin6_scope_id;
		int ok;
		if( IPV6_unify4mapped ){
			SIN6 sab;
			int *ip;
			sab = *(SIN6*)sap;
			ip = (int*)&sab.sin6_addr;
			if( ip[0]==0 && ip[1]==0 && ip[2]==0xFFFF ){
				struct in_addr ia;
				ia.s_addr = ip[3];
				addr = inet_ntoa(ia);
				/*
				syslog_DEBUG("ntoa: IPv4-mapped %s\n",addr);
				*/
				return addr;
			}
		}

		ok = 0;
		if( ok == 0 ){
			int ix;
			const unsigned char *bp;
			bp = (unsigned char*)&((SIN6*)sap)->sin6_addr;
			for( ix = 0; ix < 15; ix++ ){
				if( bp[ix] != 0 )
					break;
			}
			if( ix == 15 )
			if( bp[ix] == 0 || bp[ix] == 1 ) 
			{
				if( bp[ix] != 0 )
					sprintf(hbuf,"::%d",bp[ix]);
				else	strcpy(hbuf,"::");
				ok = 1;
			}

			if( ok == 0 ){
				for( ix = 0; ix < 14; ix++ ){
					if( bp[ix] != 0xFF )
						break;
				}
				if( ix == 14 ){
					sprintf(hbuf,
					"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:%04X",
						(bp[14]<<8)|bp[15]);
					ok = 1;
				}
			}
		}

		if( ok == 0 )
		if( NO_INET_NTOP )
			ok = getnameinfo((SA*)sap,sizeof(SIN6),hbuf,sizeof(hbuf),NULL,0,NI_NUMERICHOST) == 0;
		else	ok = inet_ntop(AF_INET6,&((SIN6*)sap)->sin6_addr,hbuf,sizeof(hbuf)) != 0;

		if( ok ){
			for( ap = hbuf; *ap; ap++ ){
				if( *ap == ':' )
					*(char*)ap = '_';
			}
			if( id != 0 && strchr(hbuf,'%') == 0 ){
				Xsprintf(ZVStr(ap,sizeof(hbuf)-(ap-hbuf)),
					"%%%d",id);
			}

			strcpy(ntoa_buf6,hbuf);
			return ntoa_buf6;
		}
		return ":::::::";
	}

	sip = (SIN*)sap;
	addr = inet_ntoa(sip->sin_addr);
	return addr;
}
int VSA_getsockname(VSAddr *vsa,int sock){
	int len;

	len = sizeof(VSAddr);
	if( getsockname(sock,(SAP)vsa,&len) == 0 ){
		return VSA_port(vsa);
	}else{
		return 0;
	}
}
int VSA_getpeername(VSAddr *vsa,int sock){
	int len;

	len = sizeof(VSAddr);
	if( getpeername(sock,(SAP)vsa,&len) == 0 ){
		return VSA_port(vsa);
	}else{
		return 0;
	}
}
int VSA_gethostname(int sock,PVStr(addrb)){
	VSAddr vsa;
	int len;
	const char *addr;

	len = sizeof(VSAddr);
	if( getsockname(sock,(SAP)&vsa,&len) == 0 ){
		if( addr = VSA_ntoa(&vsa) ){
			strcpy(addrb,addr);
			return VSA_port(&vsa);
		}
	}
	return -1;
}
const char *VSA_htoa(struct hostent *hp)
{	SIN sin;
	SIN6 sin6;

	if( hp->h_addrtype == AF_INET6 ){
		bzero(&sin6,sizeof(SIN6));
		/*
		sin6.sin6_family = hp->h_addrtype;
		*/
		((SIN*)&sin6)->sin_family = hp->h_addrtype;
/* length=20 expecting sin6_scope_id[4] is immediately after sin6_addr */
		if( hp->h_length < 0 || IPV6_ADDRLENG < hp->h_length ){
			daemonlog("F","#### VSA_htoa() bad leng: %d\n",
				hp->h_length);
		}else
		bcopy(hp->h_addr,&sin6.sin6_addr,hp->h_length);/**/
		return VSA_ntoa((VSAddr*)&sin6);
	}
	sin.sin_family = hp->h_addrtype;
	Xbcopy(hp->h_addr,GVStr(&sin.sin_addr),hp->h_length); /**/
	return VSA_ntoa((VSAddr*)&sin);
}
const char *VSA_ltoa(const unsigned char *baddr,int len,int type)
{	SIN sin;

	if( baddr == 0 ){
		porting_dbg("#### VSA_ltoa(%X,%d,%X) NULL",p2i(baddr),len,type);
		return "0.0.0.255";
	}
	if( type == AF_INET6 ){
		SIN6 sin6;
		bzero(&sin6,sizeof(SIN6));
		/*
		sin6.sin6_family = type;
		*/
		((SIN*)&sin6)->sin_family = type;
/* length=20 expecting sin6_scope_id[4] is immediately after sin6_addr */
		if( len < 0 || IPV6_ADDRLENG < len ){
			daemonlog("F","#### VSA_htoa() bad leng: %d\n",len);
		}else
		bcopy(baddr,&sin6.sin6_addr,len); /**/
		return VSA_ntoa((VSAddr*)&sin6);
	}
	bzero(&sin,sizeof(SIN)); /* to set sin_len=0 if exists */
	sin.sin_family = type;
	Xbcopy(baddr,GVStr(&sin.sin_addr),len); /**/
	return VSA_ntoa((VSAddr*)&sin);
}
int VSA_af(VSAddr *sap){
	return ((SIN*)sap)->sin_family;
}
int VSA_port(VSAddr *sap)
{	SIN *sip;
	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family == AF_UNIX )
		return VSA_afunixport;

	if( sup->sun_family == AF_INET6 ){
		/*
		return ((SIN6*)sup)->sin6_port;
		*/
		return ntohs(((SIN6*)sup)->sin6_port);
	}
	sip = (SIN*)sap;
	return ntohs(sip->sin_port);
}
char *VSA_xtoap(VSAddr *sa,PVStr(buf),int siz)
{
	sprintf(buf,"%s:%d",VSA_ntoa(sa),VSA_port(sa));
	return (char*)buf;
}
int VSA_cto_(char addr[]){
	if( VSA_strisaddr(addr) == AF_INET6 ){
		char *cp; /**/
		for( cp = addr; *cp; cp++ ){
			if( *cp == ':' ){
				*cp = '_';
			}
		}
		return 6;
	}
	return 0;
}
static int _toc(PCStr(src),PVStr(dst)){
	refQStr(ap,dst);

	strcpy(dst,src);
	if( ap = strtailstr(dst,".ipv6") ){
		setVStrEnd(ap,0);
		for( ap = dst; *ap; ap++ ){
			if( *ap == '-' )
				setVStrElem(ap,0,':');
		}
	}
	else
	for( ap = dst; *ap; ap++ ){
		if( *ap == '_' )
			setVStrElem(ap,0,':');
		if( *ap == '%' )
			break;
	}
	return 0;
}
int xgetaddrinfo(PCStr(addr),PCStr(serv),const struct addrinfo *hi,struct addrinfo **res){
	CStr(xaddr,MaxHostNameLen);
	_toc(addr,AVStr(xaddr));
	addr = xaddr;
	return getaddrinfo(addr,serv,hi,res);
}

int Inet_pton(int af,const char *src,void *dst){
	struct in_addr ina;
	struct addrinfo hints;
	struct addrinfo *ai;
	bzero(&hints,sizeof(hints));
	hints.ai_family = af;
	/*
	hints.ai_flags = AI_NUMERICHOST;
	*/

	if( inet_aton(src,&ina) ){
		return 1;
	}

	if( strpbrk(src,":_") )
	if( getaddrinfo(src,NULL,&hints,&ai) == 0 ){
		if( ai->ai_family == AF_INET6 )
			bcopy((char*)&((SIN6*)ai->ai_addr)->sin6_addr,dst,16);
		else	bcopy((char*)&((SIN*)ai->ai_addr)->sin_addr,dst,4);
		freeaddrinfo(ai);
		return 1;
	}
	return 0;
}

#define isNum(c)   ('0' <= c && c <= '9')
#define isHex(c)   ('A' <= c && c <= 'F' || 'a' <= c && c <= 'f')
#define isAlpha(c) ('A' <= c && c <= 'X' || 'a' <= c && c <= 'z')
#define isAlnum(c) (isNum(c) || isAlpha(c))
int strcanbeHostname(int af,PCStr(name)){
	const char *np;
	char nc;

	for( np = name; nc = *np; np++ ){
		if( isAlnum(nc) )
			continue;
		if( nc == '-' )
			continue;
		if( nc == '_' ) /* might be _service or _protocol */
			continue;
		if( nc == '.' ){
			if( isAlnum(np[1]) || np[1] == 0 ) 
				continue;
		}
		return 0;
	}
	return 1;
}
int strcanbeHostaddr(int af,PCStr(addr)){
	const char *ap;
	char ac;
	char nac;
	int nd = 0;
	int nc = 0;

	for( ap = addr; ac = *ap; ap++ ){
		if( isNum(ac) )
			continue;
		nac = ap[1];
		if( ac == '.' ){
			if( isNum(nac) ){
				nd++;
				continue;
			}
		}
		if( af == AF_INET6 ){
			if( isHex(ac) )
				continue;
			if( ac == '_' || ac == ':' ){
				if( nac == '_' || nac == ':' || nac == 0
				 || isHex(nac) || isNum(nac)
				){
					nc++;
					continue;
				}
			}
			if( 2 <= nc && ac == '%' ){
				continue;
			}
		}
		return 0;
	}
	if( nd == 0 && nc == 0 || 0 < nd && nd != 3 || 0 < nc && nc < 2 ){
		return 0;
	}
	return 1;
}

int xinet_pton(int af,const char *src,void *dst){
	CStr(ab,MaxHostNameLen);

	if( !strcanbeHostaddr(af,src) ){
		P_LV("---- xinet_pton(%d,%s) not an address",af,src);
		return 0;
	}

	_toc(src,AVStr(ab));
	if( strchr(src,'_') || strchr(src,':') ){
		int rcode;
		P_LV("---- xinet_pton(%d,%s)...",af,src);
		rcode = inet_pton(af,ab,dst);
		P_LV("---- xinet_pton(%d,%s)=%d",af,src,rcode);
		return rcode;
	}
	return inet_pton(af,ab,dst);
}
int VSA_strisaddr(PCStr(addr))
{
	struct in_addr ina;
	char i6[16];
	CStr(iaddr,MaxHostNameLen);

	if( addr == 0 || *addr == 0 ){
		if( addr == 0 )
			syslog_ERROR("#### VSA_strisaddr() NULL ADDR\n");
		return 0;
	}

	if( 128 <= strlen(addr) ){
		return 0;
	}
	if( inet_aton(addr,&ina) )
		return 1;

	if( strchr(addr,'%') ){
		wordscanY(addr,AVStr(iaddr),sizeof(iaddr),"^%");
		addr = iaddr;
	}
	if( xinet_pton(AF_INET6,addr,i6) == 1 ){
		return AF_INET6;
	}
	return 0;
}
int VSA_isaddr(VSAddr *sap)
{	SIN *sip;

	sip = (SIN*)sap;
	if( sip->sin_family == AF_INET )
		return sip->sin_addr.s_addr != -1;
	if( sip->sin_family == AF_INET6 ){
		return 1;
	}
	return 0;
}
int VSA_stosa(VSAddr *sap,int atype,PCStr(socks))
{	SIN *sip;

	if( atype == AF_INET6 ){
		SIN6 *sip6;
		sip6 = (SIN6*)sap;
		bzero(sip6,sizeof(SIN6));
		((SIN*)sip6)->sin_family = atype;
		Xbcopy(socks,GVStr(&sip6->sin6_addr),16);
		Xbcopy(socks+16,GVStr(&sip6->sin6_port),2);
	}else{
		sip = (SIN*)sap;
		bzero(sip,sizeof(SIN));
		sip->sin_family = atype;
		Xbcopy(socks,GVStr(&sip->sin_addr),4);
		Xbcopy(socks+4,GVStr(&sip->sin_port),2);
	}
	return sizeof(SIN);
}
int VSA_btosa(VSAddr *sap,int atype,unsigned char *baddr,int port)
{	SIN *sip;

	sip = (SIN*)sap;
	bzero(sip,sizeof(SIN));
	if( atype == AF_INET6 ){
		SIN6 *sip6 = (SIN6*)sip;
		/*
		sip6->sin6_family = atype;
		*/
		((SIN*)sip6)->sin_family = atype;
		Xbcopy(baddr,GVStr(&sip6->sin6_addr),16);
		sip6->sin6_port = htons(port);
	}else{
	sip->sin_family = atype;
		Xbcopy(baddr,GVStr(&sip->sin_addr),4);
	sip->sin_port = htons(port);
	}
	return sizeof(SIN);
}
void VSA_setport(VSAddr *sap,int port)
{	SIN *sip;
	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family == AF_UNIX )
		return;

	if( sup->sun_family == AF_INET6 ){
		((SIN6*)sup)->sin6_port = htons(port);
		return;
	}
	sip = (SIN*)sap;
	sip->sin_port = htons(port);
}
int VSA_atosa(VSAddr *sa,int port,PCStr(addr))
{	SIN *sip;
	struct addrinfo *ip6;
	const char *sidp;
	int sid = 0;
	CStr(path,1024);

	if( addr == NULL ){
		syslog_ERROR("#### VSA_atosa() NULL ADDR\n");
		addr = "";
	}

	if( hostlocal2path(addr,AVStr(path),sizeof(path)) ){
		addr = path;
	}

	if( addr[0] == '/' || addr[0] == '\\'
	 || addr[1] == ':' &&(addr[2] == '\\' || addr[2] == '/')
	){
		SUN *sup;
		sup = (SUN*)sa;
		bzero(sup,sizeof(SUN));
		sup->sun_family = AF_INET;
		Xstrcpy(FVStr(sup->sun_path),addr);
		return sizeof(SUN);
	}

	if( (sidp = strchr(addr,'%')) )
		sid = atoi(sidp+1);

	if( strneq(addr,"__",2) ){
		const char *d1 = addr+2;
		if( streq(d1,"") || streq(d1,"0") || streq(d1,"1") ){
			SIN6 *sip = (SIN6*)sa;
			int len = sizeof(sip->sin6_addr);

			bzero(sip,sizeof(SIN6));
			/*
			sip->sin6_family = AF_INET6;
			*/
			((SIN*)sip)->sin_family = AF_INET6;
			sip->sin6_port = htons(port);
			sip->sin6_flowinfo = 0;
			((char*)&sip->sin6_addr)[15] = atoi(d1);
			sip->sin6_scope_id = sid;
			return sizeof(SIN6);
		}
	}

	if( sidp == 0 || 0 < sid/*numeric scope id*/ )
	if( VSA_strisaddr(addr) == AF_INET6 ){
		int i6[16];
		if( xinet_pton(AF_INET6,addr,i6) == 1 ){
			SIN6 *sip;
			sip = (SIN6*)sa;
			bzero(sip,sizeof(SIN6));
			/*
			sip->sin6_len = sizeof(SIN6);
			*/
			/*
			sip->sin6_family = AF_INET6;
			*/
			((SIN*)sip)->sin_family = AF_INET6;
			sip->sin6_port = htons(port);
			sip->sin6_flowinfo = 0;
			Xbcopy(i6,GVStr(&sip->sin6_addr),16); /*QA*/
			sip->sin6_scope_id = sid;
			return sizeof(SIN6);
		}
	}

	if( VSA_strisaddr(addr) == AF_INET6 ){
		struct addrinfo *ai;
		SIN6 *sip;
		int alen;

		struct addrinfo hints;
		bzero(&hints,sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_flags = AI_NUMERICHOST;

		if( xgetaddrinfo(addr,NULL,&hints,&ai) == 0 ){
			sip = (SIN6*)sa;
			bzero(sip,sizeof(SIN6));
			Xbcopy(ai->ai_addr,GVStr(sip),ai->ai_addrlen); /*QA*/
			sip->sin6_port = htons(port);
			/*
			sip->sin6_family = ai->ai_family;
			*/
			((SIN*)sip)->sin_family = ai->ai_family;

/*
 fprintf(stderr,"### atsa %X IS ADDR %s fa=%d len=%d (%d) FLOW=%X, SCOPE=%d\n",
sa,addr,ai->ai_family,ai->ai_addrlen,sizeof(SIN6),
sip->sin6_flowinfo,sip->sin6_scope_id);
*/

			alen = ai->ai_addrlen;
			freeaddrinfo(ai);
			return alen;
		}
	}

	sip = (SIN*)sa;
	bzero(sip,sizeof(SIN));
	sip->sin_family = AF_INET;
	if( addr == NULL ){
		syslog_ERROR("#### ERROR VSA_atosa(addr=NULL)\n");
		sip->sin_addr.s_addr = INADDR_None;
	}else	sip->sin_addr.s_addr = inet_addrV4(addr); 
	sip->sin_port = htons(port);
	return sizeof(SIN);
}
int VSA_aptosa(VSAddr *sa,PCStr(addrport)){
	CStr(addr,128);
	refQStr(pp,addr);
	int port;

	bzero(sa,sizeof(VSAddr));
	strcpy(addr,"");
	port = 0;
	if( strrchr(addrport,':') ){
		strcpy(addr,addrport);
		if( pp = strchr(addr,':') ){
			truncVStr(pp);
			port = atoi(pp+1);
		}
	}
	return VSA_atosa(sa,port,addr);
}
int VSA_satoap(VSAddr *sa,PVStr(addrport)){
	const char *addr;
	if( addr = VSA_ntoa(sa) ){
		sprintf(addrport,"%s:%d",addr,VSA_port(sa));
		return 0;
	}else{
		sprintf(addrport,"255.255.255.255:0");
		return -1;
	}
}

int VSA_htosa(VSAddr *sap,int port,struct hostent *hp,int hi)
{	SIN *sip;
	const char *baddr;

	sip = (SIN*)sap;
	bzero(sip,sizeof(SIN));
	baddr = hp->h_addr_list[hi];
	sip->sin_family = hp->h_addrtype;
	if( sip->sin_family == AF_INET6 ){
/* length=20 expecting sin6_scope_id[4] is immediately after sin6_addr */
		if( hp->h_length < 0 || IPV6_ADDRLENG < hp->h_length ){
			daemonlog("F","#### VSA_htoa() bad leng: %d\n",
				hp->h_length);
		}else
		bcopy(baddr,&((SIN6*)sip)->sin6_addr,hp->h_length);/**/
		((SIN6*)sip)->sin6_port = htons(port);
		((SIN6*)sip)->sin6_scope_id = 0;
		if( hp->h_length == IPV6_ADDRLENG ){
			bcopy(baddr+16,&((SIN6*)sip)->sin6_scope_id,4);
		}
	}else{
		Xbcopy(baddr,GVStr(&sip->sin_addr),hp->h_length); /**/
	sip->sin_port = htons(port);
	}
	return sizeof(SIN);
}
int VSA_size(VSAddr *sap)
{	SIN *sip;

	sip = (SIN*)sap;
	if( sip->sin_family == AF_INET6 ){
		return sizeof(SIN6);
	}
	return sizeof(SIN);
}
int VSA_atob(PCStr(aaddr),PVStr(baddrb),int *btypep)
{	VSAddr Addr;
	const char *baddr;
	int bleng;

	bzero(&Addr,sizeof(Addr));
	VSA_atosa(&Addr,0,aaddr);
	bleng = VSA_decomp(&Addr,&baddr,btypep,NULL);
	if( bleng == 16 ){
		bleng = IPV6_ADDRLENG;
		/* expecting sin6_scope_id is just after sin6_addr X-) */
	}
	Bcopy(baddr,baddrb,bleng);
	return bleng;
}
int VSA_decomp(VSAddr *sap,const char **baddr,int *btype,const char **bport)
{	SIN *sip;

	sip = (SIN*)sap;
	if(btype) *btype = sip->sin_family;
	if( sip->sin_family == AF_INET6 ){
		if(baddr) *baddr = (char*)&((SIN6*)sip)->sin6_addr;
		if(bport) *bport = (char*)&((SIN6*)sip)->sin6_port;
		return 16;
	}
	if(baddr) *baddr = (char*)&sip->sin_addr;
	if(bport) *bport = (char*)&sip->sin_port;
	return 4;
}
void VSA_prftp(VSAddr *sap,PVStr(mport))
{	SIN *sip;
	const unsigned char *sa;
	const unsigned char *sp; 
	SUN *sup;

	sup = (SUN*)sap;
	if( sup->sun_family == AF_UNIX ){
		sprintf(mport,"%s:%d",VSA_afunixaddr,VSA_afunixport);
		return;
	}
	if( sup->sun_family == AF_INET6 )
	{
		/*
		sprintf(mport,"|||%d|",((SIN6*)sap)->sin6_port);
		*/
		sprintf(mport,"|||%d|",ntohs(((SIN6*)sap)->sin6_port));
		return;
	}

	sip = (SIN*)sap;
	sa = (unsigned char*)&sip->sin_addr.s_addr;
	sp = (unsigned char*)&sip->sin_port;
	sprintf(mport,"%d,%d,%d,%d,%d,%d",sa[0],sa[1],sa[2],sa[3],sp[0],sp[1]);
}
void VSA_ftptosa(void *sap,PCStr(port))
{	SIN *sip;
	unsigned char *sa; /**/
	unsigned char *sp; /**/
	int ia[4],ip[2];

	if( strchr(port,'|') != 0 ){
		CStr(addr,64);
		SIN6 *sin6;
		int pn;

		if( strncmp(port,"|||",3) == 0 ){
			if( Xsscanf(port,"|||%d",&pn) == 1 ){
				/*
				((SIN6*)sap)->sin6_port = pn;
				*/
				((SIN6*)sap)->sin6_port = htons(pn);
				return;
			}
		}

		/* IPv6 */
		if( strncmp(port,"|2|",3) == 0 ){
			if( Xsscanf(port,"|2|%[^|]|%d",AVStr(addr),&pn)==2 ){
				VSA_atosa((VSAddr*)sap,pn,addr);
				return;
			}
		}
		/* IPv4 */
		if( strncmp(port,"|1|",3) == 0 ){
			if( Xsscanf(port,"|1|%[^|]|%d",AVStr(addr),&pn)==2 ){
				VSA_atosa((VSAddr*)sap,pn,addr);
				return;
			}
		}
	}

	sip = (SIN*)sap;
	bzero(sip,sizeof(SIN));
	sip->sin_family = AF_INET;
	sscanf(port,"%d,%d,%d,%d,%d,%d",&ia[0],&ia[1],&ia[2],&ia[3],&ip[0],&ip[1]);
	sa = (unsigned char*)&sip->sin_addr;
	sp = (unsigned char*)&sip->sin_port;
	sa[0] = ia[0]; sa[1] = ia[1]; sa[2] = ia[2]; sa[3] = ia[3];
	sp[0] = ip[0]; sp[1] = ip[1];
}
int domain_ipv6(PCStr(revaddr),SIN6 *sap);
int VSA_dnstosa(void *sap,int port,PCStr(revaddr))
{	SIN *sip;
	int ip[4];
	char *bp; /**/

	if( domain_ipv6(revaddr,(SIN6*)sap) ){
		/*
		((SIN6*)sap)->sin6_family = AF_INET6;
		*/
		((SIN*)sap)->sin_family = AF_INET6;
		((SIN6*)sap)->sin6_port = port;
		return sizeof(SIN6);
	}

	sip = (SIN*)sap;
	if( sscanf(revaddr,"%d.%d.%d.%d",&ip[0],&ip[1],&ip[2],&ip[3]) != 4 )
		return 0;
	bp = (char*)&sip->sin_addr;
	bp[0] = ip[3];
	bp[1] = ip[2];
	bp[2] = ip[1];
	bp[3] = ip[0];
	sip->sin_family = AF_INET;
	sip->sin_port = port;
	return sizeof(SIN);
}

void inet_itoaV4(int iaddr,PVStr(saddr))
{	SIN sin;

	sin.sin_addr.s_addr = htonl(iaddr);
	strcpy(saddr,inet_ntoa(sin.sin_addr));
}
void VSA_zero(VSAddr *sap)
{
	if( ((SIN*)sap)->sin_family == AF_INET6 )
		bzero(sap,sizeof(SIN6));
	else
	bzero(sap,sizeof(SIN));
}
void VSA_addrcopy(VSAddr *dst,VSAddr *src){
	if( ((SIN*)src)->sin_family == AF_INET6 )
		bcopy(&((SIN6*)src)->sin6_addr,&((SIN6*)dst)->sin6_addr,16);
	else	bcopy(&((SIN*)src)->sin_addr,&((SIN*)dst)->sin_addr,4);
}
void VSA_copy(VSAddr *dst,VSAddr *src)
{
	if( ((SIN*)src)->sin_family == AF_INET6 )
		bcopy(src,dst,sizeof(SIN6));
	else
	bcopy((SIN*)src,(SIN*)dst,sizeof(SIN));
}
/* 9.9.5 VSA_comp() is not for IPv6 ... */
int VSA_comp(VSAddr *vsa1,VSAddr *vsa2)
{	SIN *sa1 = (SIN*)vsa1;
	SIN *sa2 = (SIN*)vsa2;

	if( sa1->sin_family != sa2->sin_family )
		return 1;
	if( sa1->sin_port != sa2->sin_port )
		return 2;
	if( sa1->sin_addr.s_addr != sa2->sin_addr.s_addr )
		return 3;
	return 0;
}
int VSA_netcomp(VSAddr *vsa1,VSAddr *vsa2){
	SIN *sa1 = (SIN*)vsa1;
	SIN *sa2 = (SIN*)vsa2;
	if( sa1->sin_family != sa2->sin_family )
		return 1;
	if( sa1->sin_family == AF_INET ){
		int a1,a2;
		int mask = 0xFFFFFF00;
		a1 = mask & ntohl(sa1->sin_addr.s_addr);
		a2 = mask & ntohl(sa2->sin_addr.s_addr);
		if( a1 == a2 ){
			return 0;
		}
		return 2;
	}
	if( sa1->sin_family == AF_INET6 ){
	}
	return -1;
}
int VSA_addrcomp(VSAddr *vsa1,VSAddr *vsa2){
	SIN *sa1 = (SIN*)vsa1;
	SIN *sa2 = (SIN*)vsa2;

	if( sa1->sin_family != sa2->sin_family )
		return 1;
	if( sa1->sin_family == AF_INET ){
		if( sa1->sin_addr.s_addr == sa2->sin_addr.s_addr )
			return 0;
		else	return 3;
	}
	if( sa1->sin_family == AF_INET6 ){
		SIN6 *s61 = (SIN6*)sa1;
		SIN6 *s62 = (SIN6*)sa2;
		if( bcmp(&s61->sin6_addr,&s62->sin6_addr,16) == 0 )
			return 0;
		else	return 4;
	}
	return -1;
}
int VSA_islocal(VSAddr *vsa){
	if( ((SIN*)vsa)->sin_family == AF_INET6 ){
		int *ip = (int*)&((SIN6*)vsa)->sin6_addr;
		if( ip[0]==0 && ip[1]==0 && ip[2]==0 && ip[3]==1 )
			return 1;
		if( ip[0]==0 && ip[1]==0 && ip[2]==0xFFFF && ip[3]==0x7F000001 )
			return 1;
		return 0;
	}else{
		return ntohl(((SIN*)vsa)->sin_addr.s_addr) == 0x7F000001;
	}
}
int VSA_6to4(VSAddr *vsa){
	/*
	if( ((SIN6*)vsa)->sin6_family == AF_INET6 ){
	*/
	if( ((SIN*)vsa)->sin_family == AF_INET6 ){
		int *ip = (int*)&((SIN6*)vsa)->sin6_addr;
		int port = ((SIN6*)vsa)->sin6_port;
		if( ip[0]==0 && ip[1]==0 && ip[2]==0xFFFF ){
			((SIN*)vsa)->sin_family = AF_INET;
			((SIN*)vsa)->sin_addr.s_addr = ip[3];
			((SIN*)vsa)->sin_port = port;
			return 1;
		}
	}
	return 0;
}

void inetNtoa(int addr,PVStr(saddr))
{	SIN sin;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	strcpy(saddr,inet_ntoa(sin.sin_addr));
}

int getsocktype(int sock);
int dupSocket(int sock){
	int len;
	VSAddr sin;
	SIN *sinp;
	int nsock;
	int d,type,protocol;

	len = sizeof(sin);
	if( getsockname(sock,(SAP)&sin,&len) != 0 )
		return -1;
	sinp = (SIN*)&sin;
	d = sinp->sin_family;
	type = getsocktype(sock);
	nsock = socket(d,type,0);
	/* must bind the host-address if bound */
	return nsock;
}
int SocketPair(int d,int type,int protocol,int sv[2])
{	SIN ina;
	int asock,len;
	SAP sa;
	int salen;
	int rcode = 0;

	sv[0] = sv[1] = -1;
	if( d != AF_INET )
		return -1;

	errno = 0;
	asock = socket(d,type,protocol);
	if( asock < 0 )
	{
		syslog_ERROR("SocketPair:A socket(),errno=%d\n",errno);
		return -1;
	}

	sa = (SAP)&ina;
	salen = sizeof(ina);
	ina.sin_family = AF_INET;
	ina.sin_addr.s_addr = INADDR_ANY;
	ina.sin_port = 0;

	rcode |= bind(asock,sa,salen);
	if( rcode != 0 ){
		syslog_ERROR("SocketPair:A bind(%d),errno=%d\n",asock,errno);
		goto EXIT;
	}
	rcode |= listen(asock,2);
	if( rcode != 0 ){
		syslog_ERROR("SocketPair:A listn(%d),errno=%d\n",asock,errno);
		goto EXIT;
	}

	len = salen;
	getsockname(asock,sa,&len);
	if( d == AF_INET )
		ina.sin_addr.s_addr = inet_addrV4("127.0.0.1");

	sv[1] = socket(d,type,protocol);
	if( sv[1] < 0 ){
		syslog_ERROR("SocketPair:C socket(),errno=%d\n",errno);
		goto EXIT;
	}
	rcode |= connect(sv[1],sa,salen);
	if( rcode != 0 ){
		syslog_ERROR("SocketPair:C connect(),errno=%d\n",errno);
		goto EXIT;
	}

	len = salen;
	sv[0] = accept(asock,sa,&len);
	if( sv[0] < 0 ){
		syslog_ERROR("SocketPair:A accept(),errno=%d\n",errno);
		goto EXIT;
	}
EXIT:
	close(asock);

	if( sv[0] < 0 && 0 <= sv[1] )
		close(sv[1]);
	syslog_ERROR("SocketPair()=%d [%d,%d] %d\n",rcode,sv[0],sv[1],errno);
	return rcode;
}
char *_inet_ntoaV4I(INETADDRV4 ia)
{	struct in_addr in;

	in.s_addr = ia;
	return inet_ntoa(in);
}
INETADDRV4 _inet_addrV4(PCStr(cp))
{
	return inet_addr(cp);
}
int isinetAddr(PCStr(saddr))
{
	if( inet_addrV4(saddr) != -1 )
		return 4;
	if( VSA_strisaddr(saddr) == AF_INET6 )
		return AF_INET6;
	return 0;
}

int Inet_aton(PCStr(addr),struct in_addr *inap)
{	unsigned int rcode;

	inap->s_addr = rcode = inet_addr(addr);
	if( rcode == (unsigned int)-1 )
		return 0;
	return 1;
}

int domain_ipv6(PCStr(revaddr),SIN6 *sap){
	const char *dp;
	int nc;
	int i;
	int sx;
	int v[32];
	char *ap; /**/

	if( (dp = strcasestr(revaddr,".IP6.INT")) )
	if( dp[8] == 0 ){
		nc = sscanf(revaddr,
"%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x",
		&v[ 0],&v[ 1],&v[ 2],&v[ 3],&v[ 4],&v[ 5],&v[ 6],&v[ 7],
		&v[ 8],&v[ 9],&v[10],&v[11],&v[12],&v[13],&v[14],&v[15],
		&v[16],&v[17],&v[18],&v[19],&v[20],&v[21],&v[22],&v[23],
		&v[24],&v[25],&v[26],&v[27],&v[28],&v[29],&v[30],&v[31]
		);

		if( nc == 32 ){
			bzero(sap,sizeof(SIN6));
			ap = (char*)&sap->sin6_addr;
			sx = 31;
			for( i = 0; i < 16; i++ ){
				ap[i] = (v[sx] << 4) | v[sx-1];
				sx -= 2;
			}
			return 1;
		}
	}
	return 0;
}
int ipv6_domain(PCStr(addr),PVStr(dom)){
	char i6[16];

	strcpy(dom,"?");
	if( xinet_pton(AF_INET6,addr,i6) == 1 ){
		refQStr(dp,dom);
		int ax;
		const unsigned char *ap;

		ap = (unsigned char*)i6;
		for( ax = 16-1; 0 <= ax; ax-- ){
			sprintf(dp,"%x.%x.",0xF&ap[ax],ap[ax]>>4);
			dp += strlen(dp);
		}
		sprintf(dp,"IP6.INT");
		return 1;
	}
	return 0;
}
