/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2006 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	bcounter.c (built-in counter)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	20060506 extracted from cache.c
//////////////////////////////////////////////////////////////////////#*/

#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "ystring.h"
#include "dglib.h"
#include "log.h"

int CTX_cache_pathX(DGC*ctx,PCStr(base),PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath));

/*
 * ACCESS COUNTER
 *
 * TODO:
 *   COUNTER=specList[:dirPathfmt]
 *   COUNTER=serv -- server map as ADMDIR/maps/server#map for proxy-DeleGate
 *   COUNTER=spam -- SPAMmers map
 *   COUNTER=reload -- reload counter
 *   COUNTER=cachehit -- cache-hit counter
 *   COUNTER=rej  -- atackers map
 *   COUNTER=ua   -- counter of each User-Agent
 *   COUNTER=dom  -- counter of each client comain
 *   COUNTER=tcpacc,tcpcon -- TCP level counter, for arbitrary protocol
 *   counter in moving window as in load-average
 *   counter dir. for each user -- to be used as a personaly history / bookmark
 *   selectable map size
 *   sum or sub. between maps
 *   SHTML tag to specify the default counter format specification
 *   reference count (not access count) of each URL URL#referer/refURL
 *   query log of each URL?q=a+b as URL#query/q=a URL#query/q=b ...
 *   COUNTER as a MountOption
 *   COUNTER=mountv -- count up the mount point vURL
 *   COUNTER=mountr -- count up the mount point rURL
 *   dumping counter-list as a XML (might be RSS)
 *   automatic generation of sorted counter list -- under /-/admin/counters/
 *   a group of counters represented by reg. exp. as /bin/windows[/]*[/]*.zip
 *   CMAP="no:COUNTER:*:*:srcHostList"
 *   returning counter value in HTTP header as X-Counter: 1234
 *   use mmap()
 *   %F -- "FreshHit" count without If-Modified-Since, Pragma:no-cache, ...
 *   %R -- reload or partial read in HTTP and FTP
 *   version of counters and select it with var=COUNTER ver="ver"
 *   another MAP for LSB 10bits
 */

static int CNT_LRU = 1;
#define CNT_DBGLEV	(0xFF & CNT_flags)
#define CNT_DEBUG	(1 <= (0xFF&CNT_flags))
#define CNT_DEBUGV	(2 <= (0xFF&CNT_flags))
#define CNT_DEBUGVV	(3 <= (0xFF&CNT_flags))
static int CNT_flags = 0;

int gl_COUNTER = 0;
int mo_COUNTER = 0;
#define CNT_ALL (CNT_TOTALHITS|CNT_ACCESS|CNT_SSIPAGE|CNT_SSIINCLUDE|CNT_REFERER|CNT_ERROR|CNT_DESTINATION)

int scan_COUNTER1(DGC*ctx,int COUNTER,PCStr(spec)){
	CStr(spb,128);
	const char *sp1;
	const char *np;
	int neg;
	int flag1;

	np = spec;
	while( *np ){
		np = scan_ListElem1(np,',',AVStr(spb));
		if( *spb == '-' ){
			neg = 1;
			sp1 = spb + 1;
		}else{
			neg = 0;
			sp1 = spb;
		}
		flag1 = 0;

		if( strneq(sp1,"debug",5) ){
			int dl = 0;
			if( sp1[5] == 0 )
				dl = 1;
			else	sscanf(sp1+5,"%X",&dl);
			CNT_flags = (CNT_flags & ~0xFF) | (0xFF & dl);
		}else
		if( streq(sp1,"no") )
			COUNTER = 0;
		else
		if( streq(sp1,"do") )
			flag1 = CNT_ALL;
		else
		if( streq(sp1,"all") )
			flag1 = CNT_ALL;
		else
		if( strcaseeq(sp1,"mntpV") )
			flag1 = CNT_MOUNTVURL;
		else
		if( strcaseeq(sp1,"mntpR") )
			flag1 = CNT_MOUNTRURL;
		else
		if( streq(sp1,"total") )
			flag1 = CNT_TOTALHITS;
		else
		if( streq(sp1,"acc") )
			flag1 = CNT_ACCESS;
		else
		if( streq(sp1,"ssi") )
			flag1 = CNT_SSIPAGE;
		else
		if( streq(sp1,"ref") )
			flag1 = CNT_REFERER;
		else
		if( streq(sp1,"err") )
			flag1 = CNT_ERROR;
		else
		if( streq(sp1,"ro") )
			flag1 = CNT_READONLY;
		else
		if( streq(sp1,"inc") )
			flag1 = CNT_INCREMENT;
		else{
			fprintf(stderr,"ERROR: Unknown COUNTER=%s\n",sp1);
		}
		if( flag1 ){
			if( neg ){
				COUNTER &= ~flag1;
			}else	COUNTER |= flag1;
		}
	}
	return COUNTER;
}
void scan_COUNTER(DGC*ctx,PCStr(spec)){
	gl_COUNTER = scan_COUNTER1(ctx,gl_COUNTER,spec);
	if( CNT_DBGLEV == 0 ){
		if( lCOUNTER() ){
			CNT_flags |= 1;
		}
	}
}
#define COUNTER	((mo_COUNTER&CNT_MOUNTOPT)?mo_COUNTER:gl_COUNTER)

static int LastRequestSerno = -1;
int CTX_RequestSerno(DGC*ctx);

/*
 * int should be in the network byte order by htonl/ntohl
 * initializable and viewable manually ... "1000 500\n"
 */
#define Int32	int
int getClientAddr(DGC*ctx,PVStr(iaddr),int isize);
typedef struct {
	MStr(	c_count,36);   /* "%T %U %V %R" max. 34bytes ended with '\n' */
	MStr(	c_client,16);  /* (%U) last accessor's IP-address (IPv4/v6) */
	Int32	c_Rtime;       /* %tR counter update (last Reload) */
	Int32	c_Ttime;       /* %tT counter update */
	Int32	c_Utime;       /* %tU counter update */
	Int32	c_Xtime;       /* %tX counter update */
	Int32	c_ctime;       /* %c counter created */
	Int32	c_clientV[10]; /* (%V) last accessors's IP-addresses[10] */
unsigned char	c_ccountV[10];
unsigned short	c_nets;
	MStr(	c_rsvd,4);    /* reserved */
	MStr(	c_cmap,128);   /* bit-map of MSB 10bits of client's IP-addr. */
} Counter;
#define c_ncum	c_rsvd[0]

#define CNTV_TOTAL	1
#define CNTV_UNIQUE	2
#define CNTV_LAST10	4

static const char lmapc[13] = "-X0123456789";

static int getMap(Counter *cntp,PVStr(vmap)){
	int cnt = 0;
	int bi;
	int bx;
	int b8;
	refQStr(vp,vmap);
	unsigned int i4n;
	unsigned int i4;
	CStr(map,2048);
	refQStr(mp,map);
	char cmap[128][8];
	int mask;
	int li;

	for( bi = 0; bi < elnumof(cntp->c_cmap); bi++ ){
		b8 = (0xFF & cntp->c_cmap[bi]);
		if( vmap ){
			for( bx = 0; bx < 8; bx++ ){
				mask = 1 << bx;
				cmap[bi][bx] = (mask & b8)==0 ? lmapc[0]:lmapc[1];
			}
		}
		if( b8 ){
			for( bx = 0; bx < 8; bx++ ){
				if( (1 << bx) & b8 ){
					cnt++;
				}
			}
		}
	}
	if( vmap ){
		int i4;
		unsigned int i4n;
		int mapsize = 10;

		for( li = 0; li < elnumof(cntp->c_clientV); li++ ){
			i4 = cntp->c_clientV[li];
			i4n = (((unsigned int)i4) >> (32-mapsize)) & 0x3FF;
			bi = i4n >> 3;
			bx = i4n & 0x7;
			if( cmap[bi][bx] == 'X' ){
				cmap[bi][bx] = lmapc[2+li];
			}
		}
		for( bi = 0; bi < elnumof(cntp->c_cmap); bi++ ){
			if( elnumof(cntp->c_cmap)*7/8 <= bi ){
				/* class-D */
				break;
			}
			if( bi % 8 == 0 ){
				if( 0 < bi ){
					setVStrPtrInc(vp,'\n');
				}
			}
			if( bi % 8 == 0 ){
				i4n = (bi<<3);
				i4 = i4n << (32-10);
				sprintf(vp,"%3d.0.0.0",(i4>>24)&0xFF);
				vp += strlen(vp);
			}
			setVStrPtrInc(vp,' ');
			for( bx = 0; bx < 8; bx++ ){
				setVStrPtrInc(vp,cmap[bi][bx]);
			}
		}
		setVStrPtrInc(vp,'\n');
		setVStrPtrInc(vp,'\0');
	}
	return cnt;
}
static void putMap(Counter *cntp,int i4){
	int mapsize;
	int i4n;
	int bi;
	int b8;
	int bx;

	mapsize = 10; /* bitsw(sizeof(cntp->c_map)/8) */
	i4n = (((unsigned int)i4) >> (32-mapsize)) & 0x3FF;
	bi = i4n >> 3;
	bx = 1 << (i4n & 0x7);
	b8 = cntp->c_cmap[bi];
	if( (bx & b8) == 0 ){
		b8 |= bx;
		if( CNT_DEBUG )
		sv1log("CountUp: new net %08X %03X [%03d]%02X\n",i4,i4n,bi,bx);
		if( bi < sizeof(cntp->c_cmap) ){
			setVStrElem(cntp->c_cmap,bi,b8);
			cntp->c_nets = getMap(cntp,VStrNULL);
		}
	}
}

FILE *readCounter(DGC*ctx,int flags,PCStr(proto),PCStr(host),int port,PCStr(upath),PVStr(cpath),Counter *cntp){
	refQStr(dp,cpath);
	CStr(base,1024);
	const char *ext;
	FILE *fp;
	int rcc;

	bzero(cntp,sizeof(Counter));
	if( (COUNTER & CNT_ALL & flags) == 0 )
		return NULL;

	if( flags & CNT_REFERER )
		strcpy(base,"${ADMDIR}/counts/referer");
	else
	if( flags & CNT_ERROR )
		strcpy(base,"${ADMDIR}/counts/errors");
	else	strcpy(base,"${ADMDIR}/counts/access");
	Substfile(base);

	if( CTX_cache_pathX(ctx,base,proto,host,port,upath,BVStr(cpath))==0 ){
		return NULL;
	}
	if( dp = strchr(cpath,'?') )
		truncVStr(dp);

	strsubst(AVStr(cpath),"/%7E","/~");
	/* strsubst(AVStr(cpath),"#","%23"); */

	ext = "#count";
	switch( flags & CNT_ALL ){
		case CNT_REFERER:
		case CNT_REFERER|CNT_TOTALHITS:
			ext = "#count-ref";
			break;
		case CNT_ERROR:
			ext = "#count-err";
			break;
		case CNT_SSIPAGE:
			ext = "#count-ssi";
			break;
		case CNT_SSIINCLUDE:
			ext = "#count-inc";
			break;
	}
	strcat(cpath,ext);

	fp = dirfopen("Counter",BVStr(cpath),"r+");
	if( CNT_DEBUGVV ){
		sv1log("## Counter: fp=%X %s\n",p2i(fp),cpath);
	}
	if( fp == NULL ){
		if( (flags & CNT_INCREMENT) == 0 ){
			return NULL;
		}
		fp = dirfopen("Counter",BVStr(cpath),"w+");
		if( fp == NULL ){
			syslog_ERROR("## Cannot Create Counter: %s\n",cpath);
			return NULL;
		}
		syslog_ERROR("## Counter Created: %s\n",cpath);
		return fp;
	}

	rcc = read(fileno(fp),cntp,sizeof(Counter));
	if( cntp->c_count[0] != 0 ){
		if( !isdigit(cntp->c_count[0]) ){
			syslog_ERROR("## bad counter format: %s\n",cpath);
			fclose(fp);
			return NULL;
		}
	}
	return fp;
}

/* move the last entry to the top to be LRU */
static void pageOut(Counter *cntp,int ci){
	int cj;
	int ci4;
	int cnt;

	if( CNT_LRU && ci != 0 ){
		ci4 = cntp->c_clientV[ci];
		cnt = cntp->c_ccountV[ci];
		for( cj = ci; 0 < cj; cj-- ){
			cntp->c_clientV[cj] = cntp->c_clientV[cj-1];
			cntp->c_ccountV[cj] = cntp->c_ccountV[cj-1];
		}
		cntp->c_clientV[0] = ci4;
		cntp->c_ccountV[0] = cnt;
	}
}
int strCRC32(PCStr(str),int len);
static int putCounter(DGC*ctx,int flags,int now,PCStr(iaddr),FILE *fp,PCStr(cpath),Counter *cntp){
	int acnt,ucnt,vcnt;
	int fd = fileno(fp);
	int wcc;
	int serno = -9;
	int i4;

	acnt = ucnt = vcnt = 0;
	sscanf(cntp->c_count,"%d %d %d",&acnt,&ucnt,&vcnt);
	if( COUNTER & CNT_READONLY
	 || (CNT_ALL & flags & COUNTER) == 0
	){
		return acnt;
	}

	switch( flags & CNT_ALL ){
		case CNT_REFERER:
		case CNT_ERROR:
		case CNT_TOTALHITS:
		case CNT_TOTALHITS|CNT_REFERER:
		case CNT_DESTINATION:
			break;

		default:
		serno = CTX_RequestSerno(ctx);
		if( LastRequestSerno == serno ){
			/* - access count + SHTML PAGE_COUNT
			 * - duplicate PAGE_COUNT in a SHTML page
			 */
if(CNT_DEBUGV)
if(flags & CNT_INCREMENT)
sv1log("DBG CountUp DUP (%4X) %X %X [%x %x] %s\n",
flags,gl_COUNTER,mo_COUNTER,
LastRequestSerno,serno,cpath);
			return acnt;
		}
		LastRequestSerno = serno;
	}

if(CNT_DEBUGV)
if(flags & CNT_INCREMENT)
sv1log("DBG CountUp DO  (%4X) %X %X [%x %x] %s\n",
flags,gl_COUNTER,mo_COUNTER,
LastRequestSerno,serno,cpath);

	acnt++;
	if( bcmp(iaddr,cntp->c_client,sizeof(cntp->c_client)) != 0 ){
		ucnt += 1;
		cntp->c_Utime = now;
		Bcopy(iaddr,cntp->c_client,sizeof(cntp->c_client));
	}

	/* IP-address array for %V */
	{
		int ci;
		int ai;

		for( ai = 0; ai < 12; ai++ )
			if( iaddr[ai] != 0 )
				break;
		if( ai != 12 ){
			i4 = strCRC32(iaddr,16); /* IPv6 in 4 bytes */
		}else{
			bcopy(iaddr+12,&i4,sizeof(i4));
		}
		for( ci = 0; ci < elnumof(cntp->c_clientV); ci++ ){
			if( cntp->c_clientV[ci] == 0 ){
				break;
			}
			if( i4 == cntp->c_clientV[ci] ){
				cntp->c_ccountV[ci] += 1;
				pageOut(cntp,ci);
				goto V_FOUND;
			}
		}
		/* update %V */
		vcnt++;
		cntp->c_Xtime = now;
		for( ci = elnumof(cntp->c_clientV)-1; 0 < ci; ci-- ){
			cntp->c_ccountV[ci] = cntp->c_ccountV[ci-1];
			cntp->c_clientV[ci] = cntp->c_clientV[ci-1];
		}
		cntp->c_clientV[0] = i4;
		cntp->c_ccountV[0] = 0;
		putMap(cntp,i4);
	} V_FOUND:

	sprintf(cntp->c_count,"%d %d %d\n",acnt,ucnt,vcnt);
	if( cntp->c_ctime == 0 ){
		cntp->c_ctime = now;
	}
	cntp->c_Ttime = now;
	lseek(fd,0,0);
	wcc = write(fd,cntp,sizeof(Counter));

	if( CNT_DEBUG )
	syslog_ERROR("## CountUp: %08X %d %d %d %s\n",i4,acnt,ucnt,vcnt,cpath);
	return acnt;
}
/*
int PageCountUp(DGC*ctx,PCStr(proto),PCStr(host),int port,PCStr(upath),int inc,int ssi){
	CStr(cpath,1024);
	CStr(iaddr,16);
	Counter cntb;
	int acnt = 0;
	FILE *fp;
	int now = time(0);
	getClientAddr(ctx,AVStr(iaddr),sizeof(iaddr));

	fp = readCounter(ctx,flags,proto,host,port,upath,AVStr(cpath),&cntb);
	if( fp == NULL ){
		return -1;
	}
	if( inc ){
		acnt = putCounter(ctx,flags,now,iaddr,fp,cpath,&cntb);
	}
	fclose(fp);
	return acnt;
}
*/
const char *CTX_CLNT_PROTO(DGC*ctx);
const char *CTX_clif_proto(DGC*ctx);
int HTTP_ClientIF_H(DGC*ctx,PVStr(host));
int HTTP_original_H(DGC*ctx,PVStr(host));

#define _MAX_PATH 512

int PageCountUpURL(DGC*ctx,int flags,PCStr(url),void *vcntp){
	CStr(pro,64);
	CStr(host,MaxHostNameLen);
	int port = 0;
	CStr(up,1024);
	FILE *fp;
	CStr(cpath,1024);
	Counter *cntp;
	Counter cntb;
	int now = time(0);
	CStr(iaddr,16);
	IStr(urlb,_MAX_PATH);

if(CNT_DEBUGV)
if(flags&CNT_INCREMENT)
sv1log("DBG CountUp     (%4X) %X %X %s\n",flags,gl_COUNTER,mo_COUNTER,url);

	if( (COUNTER & CNT_ALL & flags) == 0 ){
		if( vcntp ){
			bzero(vcntp,sizeof(Counter));
		}
		return 0;
	}

	if( sizeof(up) <= strlen(url) ){ /* v9.9.11 fix-140807b */
		const char *CTX_Client_Host(DGC*ctx);
		daemonlog("F","COUNTER: truncated too long URL (%d)[%s]: %s\n",
			strlen(url),CTX_Client_Host(ctx),url);
		FStrncpy(urlb,url);
		url = urlb;
	}

	getClientAddr(ctx,AVStr(iaddr),sizeof(iaddr));

	cntp = (Counter*)vcntp;
	if( cntp == NULL )
		cntp = &cntb;

	if( (flags & CNT_ALL) == CNT_TOTALHITS ){
		/* independent of alias or virtual hostnames */
		strcpy(pro,CTX_CLNT_PROTO(ctx));
		port = HTTP_original_H(ctx,AVStr(host));
		strcpy(host,"_me_");
		strcpy(up,url);
	}else
	if( isFullURL(url) ){
		refQStr(pp,host);
		refQStr(dp,up);

		decomp_absurl(url,AVStr(pro),AVStr(host),AVStr(up),sizeof(up));
		if( pp = strchr(host,':') ){
			truncVStr(pp);
			port = atoi(pp+1);
		}
		/* Referer:URL might include # in it.  remove it
		 *   -- to reduce counters
		 *   -- to escape possible batting with #xxxx for control
		 */
		if( flags & CNT_REFERER ){
			if( dp = strchr(up,'#') ){
				truncVStr(dp);
			}
		}
		if( dp = strchr(up,'?') ){
			truncVStr(dp);
		}
		if( flags & CNT_TOTALHITS ){
			strcpy(up,"#total");
		}
	}else
	if( flags & CNT_REFERER ){
		sv1log("Non-Full-URL in Referer: %s\n",url);
		if( vcntp ){
			bzero(vcntp,sizeof(Counter));
		}
		return 0;
	}else{
		strcpy(pro,CTX_CLNT_PROTO(ctx));
		port = HTTP_original_H(ctx,AVStr(host));
		strcpy(up,url);
	}
	if( pro[0] == 0 ){
		strcpy(pro,CTX_clif_proto(ctx));
	}
	if( host[0] == 0 ){
		strcpy(host,"_me_");
	}
	if( port == 0 )
		port = serviceport(pro);
	/*
	 * real-URL should be reverse-MOUNTed ...
	 */

	fp = readCounter(ctx,flags,pro,host,port,up,AVStr(cpath),cntp);
	if( fp ){
		if( flags & CNT_INCREMENT ){
			putCounter(ctx,flags,now,iaddr,fp,cpath,cntp);
		}
		fclose(fp);
		return atoi(cntp->c_count);
	}else{
		daemonlog("E","NO COUNTER: %s\n",cpath);
		return 0;
	}
}

void sputNum(PVStr(str),PCStr(fmt),int sep,int num){
	CStr(buf,128);
	refQStr(bp,buf);
	const char *sp;
	int si;

	sprintf(str,fmt,num);
	if( sep ){
		sp = &str[strlen(str)-1];
		bp = &buf[sizeof(buf)-1];
		setVStrEnd(bp,0);
		bp--;
		for( si = 0; str <= sp && buf < bp; si++ ){
			if( 0 < si && (si % sep) == 0 )
			if( '0' <= *sp && *sp <= '9' )
			{
				setVStrElem(bp,0,',');
				bp--;
			}
			setVStrElem(bp,0,*sp);
			if( sp == str )
				break;
			sp--;
			bp--;
		}
		strcpy(str,bp);
	}
}

typedef struct {
	int	C_ncum;
	Counter	C_cum;
} CumCounter;

static Counter cum;
static Counter cum1;
static int doCum;
static void cumAdd(Counter *cum,Counter *cnt){
	int acnt,ucnt,vcnt;
	int ac,uc,vc;
	int bi;

	acnt = ucnt = vcnt = 0;
	sscanf(cnt->c_count,"%d %d %d",&acnt,&ucnt,&vcnt);
	ac = uc = vc = 0;
	sscanf(cum->c_count,"%d %d %d",&ac,&uc,&vc);
	sprintf(cum->c_count,"%d %d %d\n",acnt+ac,ucnt+uc,vcnt+vc);
	for( bi = 0; bi < elnumof(cum->c_cmap); bi++ ){
		cum->c_cmap[bi] |= cnt->c_cmap[bi];
	} 
	if( cum->c_Xtime < cnt->c_Xtime ) cum->c_Xtime = cnt->c_Xtime;
	if( cum->c_Utime < cnt->c_Utime ) cum->c_Utime = cnt->c_Utime;
	if( cum->c_Ttime < cnt->c_Ttime ) cum->c_Ttime = cnt->c_Ttime;
	if( cnt->c_ctime < cum->c_ctime|| cum->c_ctime == 0 )
		cum->c_ctime = cnt->c_ctime;
	if( cnt->c_ncum != 0 )
		cum->c_ncum += cnt->c_ncum;
	else	cum->c_ncum += 1;
}
static void cumSub(Counter *cum,Counter *cnt){
	int acnt,ucnt,vcnt;
	int ac,uc,vc;
	int bi;

	acnt = ucnt = vcnt = 0;
	sscanf(cnt->c_count,"%d %d %d",&acnt,&ucnt,&vcnt);
	ac = uc = vc = 0;
	sscanf(cum->c_count,"%d %d %d",&ac,&uc,&vc);
	sprintf(cum->c_count,"%d %d %d\n",acnt-ac,ucnt-uc,vcnt-uc);
}

int strfCounter(DGC*ctx,int flags,PCStr(url),PCStr(fmt),PCStr(timefmt),PVStr(buff),int bsize){
	const char *fp;
	char fc;
	int in2B = 0;
	refQStr(bp,buff);
	const char *bx = &buff[bsize-1];
	Counter cntb;
	int acnt,ucnt,vcnt;
	int now;
	int last;
	int mean;
	double etime = 1.0;
	int ptime;
	CStr(nfmt,32);
	refQStr(nf,nfmt);
	int nc;
	CStr(dfmt,32);
	CStr(urlb,1024);
	CStr(title,1024);
	CStr(pbuf,1024);
	const char *dp;
	int ci;
	int sep = 0;
	int iscum = 0;
/*
	int docum = 0;
*/

	truncVStr(title);
	if( dp = strstr(url,"#{") ){
		strcpy(urlb,url);
		url = urlb;
		if( dp = strstr(urlb,"#{") ){
			truncVStr(dp);
		}
		wordScanY(dp+2,title,"^}");
	}

	if( strneq(url,"##debug=",8) ){
		CNT_flags = (CNT_flags & ~0xFF) | (0xFF & atoi(url+8));
		sv1log("## CNT_flags=%X\n",CNT_flags);
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cuminit") ){
		bzero(&cum,sizeof(cum));
		doCum = 1;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumstop") ){
		doCum = 0;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumcont") ){
		doCum = 1;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumpush") ){
		cum1 = cum;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumpop") ){
		cum = cum1;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumswap") ){
		Counter cums;
		cums = cum;
		cum = cum1;
		cum1 = cums;
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumadd") ){
		cumAdd(&cum,&cum1);
		setVStrEnd(buff,0);
		return 0;
	}
	if( streq(url,"##cumsub") ){
		cumSub(&cum,&cum1);
		setVStrEnd(buff,0);
		return 0;
	}
	if( iscum = streq(url,"##cumget") ){
		cntb = cum;
	}else{
		PageCountUpURL(ctx,flags,url,&cntb);
	}
	acnt = ucnt = vcnt = 0;
	sscanf(cntb.c_count,"%d %d %d",&acnt,&ucnt,&vcnt);
	now = time(NULL);

	for( fp = fmt; fc = *fp; fp++ ){
		if( fc == 033 ){
			if( fp[1] == '$' ){
				in2B = 1;
			}else
			if( fp[1] == '(' ){
				in2B = 0;
			}
		}
		if( in2B ){
			setVStrPtrInc(bp,fc);
			setVStrEnd(bp,0);
			continue;
		}

		if( fc != '%' && fc != '$' ){
			setVStrPtrInc(bp,fc);
			setVStrEnd(bp,0);
			continue;
		}
		if( (fc = *++fp) == 0 )
			break;

		truncVStr(nfmt);
		nf = nfmt;
		while( fc == ',' || fc == '.' || fc == '-' || isdigit(fc) ){
			if( fc == ',' ){
				sep = atoi(nfmt);
				if( sep == 0 )
					sep = 3;
				nf = nfmt;
			}else	setVStrPtrInc(nf,fc);
			if( (fc = *++fp) == 0 )
				goto EXIT;
		}
		setVStrEnd(nf,0);

		if( fc == 't' ){
			int clock;
			if( (fc = *++fp) == 0 )
				goto EXIT;
			switch( fc ){
				case 'C': clock = cntb.c_ctime; break;
				case 'T': clock = cntb.c_Ttime; break;
				case 'U': clock = cntb.c_Utime; break;
				case 'X': clock = cntb.c_Xtime; break;
				default:
					continue;
					break;
			}
			StrftimeLocal(AVStr(bp),32,"%L",clock,0);
			bp += strlen(bp);
			continue;
		}
		if( mean = (fc == 'm') ){
			fc = *++fp;
			if( fc == 0 )
				break;
			ptime = 0;
			switch( fc ){
				case 'S': ptime = 1; break;
				case 'M': ptime = 60; break;
				case 'H': ptime = 60*60; break;
				case 'd': ptime = 60*60*24; break;
				case 'w': ptime = 60*60*24*7; break;
				case 'm': ptime = 60*60*24*31; break;
				case 'y': ptime = 60*60*24*365; break;
			}
			if( ptime != 0 ){
				if( (fc = *++fp) == 0 )
					goto EXIT;
			}else{
				ptime = 60*60*24;
			}
/*
			if( cntb.c_Ttime )
				last = cntb.c_Ttime;
			else	last = now;
*/
			/*
			 * don't update the mean value on every access
			 * update it every minute
			 */
			last = ((now + 59)/60)*60;
			etime = (last - cntb.c_ctime)/(double)ptime;
			if( etime == 0 ){
				etime = 1;
			}

			if( nfmt[0] )
				sprintf(dfmt,"%%%sf",nfmt);
			else	strcpy(dfmt,"%.1f");
		}else{
			if( nfmt[0] )
				sprintf(dfmt,"%%%sd",nfmt);
			else	strcpy(dfmt,"%d");
		}

		switch( fc ){
		  case '$': strcpy(bp,"$"); break;
		  case '%': strcpy(bp,"%"); break;
		  case 'n': strcpy(bp,"\n"); break;

		  case 'c': /* %cX for ##cum ? */
			if( (fc = *++fp) == 0 )
				goto EXIT;
			switch( fc ){
			case 'n':
				sputNum(AVStr(bp),dfmt,sep,cum.c_ncum);
				break;
			}
			break;

		  case 'u':
			encodeEntitiesX(url,AVStr(bp),bx-bp);
			break;
		  case 'v':
			encodeEntitiesX(url,AVStr(pbuf),sizeof(pbuf));
			sprintf(bp,"<A HREF=\"%s\">%s</A>",pbuf,pbuf);
			break;
		  case 'w':
			if( title[0] )
				strcpy(bp,title);
			else	encodeEntitiesX(url,AVStr(bp),bx-bp);
			break;
		  case 'y':
			strcpy(bp,title);
			break;

/*
		  case 'c':
			StrftimeLocal(AVStr(bp),32,"%L",cntb.c_ctime,0);
			break;
*/

		  case 'L':
			for( ci = 0; ci < elnumof(cntb.c_clientV); ci++ ){
				unsigned int i4 = cntb.c_clientV[ci];
				if( i4 == 0 )
					break;
				sprintf(bp,"LAST[%d][%3d] %08X %3d.%c\n",ci,
					cntb.c_ccountV[ci],
					i4 & 0xFFF000FF, /* to be encrypted */
					i4 >> 24,
					"ABCD"[3&(i4 >> 22)]
				);
				bp += strlen(bp);
			}
			break;

		  case 'M':
			getMap(&cntb,AVStr(bp));
			break;

		  case 'D':
		  case 'N':
			sputNum(AVStr(bp),dfmt,sep,getMap(&cntb,VStrNULL));
			break;

		  case 'T':
			if( mean )
				sprintf(bp,dfmt,acnt/etime);
			else	sputNum(AVStr(bp),dfmt,sep,acnt);
/*
docum |= CNTV_TOTAL;
*/
			break;
		  case 'U':
			if( mean )
				sprintf(bp,dfmt,ucnt/etime);
			else	sputNum(AVStr(bp),dfmt,sep,ucnt);
			break;
		  case 'V':
		  case 'X':
			if( mean )
				sprintf(bp,dfmt,vcnt/etime);
			else	sputNum(AVStr(bp),dfmt,sep,vcnt);
			break;

		  default:
			sv1log("-- strfPageCounter: unknown[%%%c]\n",fc);
			sprintf(bp,"unknown[%%%c]",fc);
		}
		bp += strlen(bp);
	}
EXIT:
	setVStrEnd(bp,0);
	if( doCum && !iscum /*&& docum*/ ){
		cumAdd(&cum,&cntb);
	}
	return 0;
}

/*
 * - symbolic dump of a counter in specified format
 * - restore a counter from a symbolic representation
 * - gather subsidary counters into #total
 * - a list of "TYPE TIME IPADDR URL\n" to counters, TIME={acc,ref}
 * - common-logfile-format to counters
 * - Xferlog to counters
 */
int counter_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	FILE *ifp = 0;
	CStr(line,1024);

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
	}
	if( ifp ){
		for(;;){
			if( fgets(line,sizeof(line),ifp) == NULL )
				break;
		}
	}
	return 0;
}
