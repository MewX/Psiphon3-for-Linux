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
Program:	ntod.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	Nov1994	created
ToDo:
	sort address list and binary search...
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "ystring.h"
#include "vaddr.h"
#include "dgctx.h"
#include "file.h"
void minit_timer();
void minit_resconf();
static int uinc_main(int ac,char *av[]);

int RES_order(PCStr(order),PVStr(porder));
void RES_verify(PCStr(verify));
int RES_1s(PCStr(addrhost),PVStr(addr_host));

static int scan4num(PCStr(addr),int *av)
{	const char *ap;
	char ch;
	int ai,ac,num;

	ap = addr;
	for( ac = 0; *ap && ac < 4; ac++ ){
		num = 0;
		while( ch = *ap ){
			ap++;
			if( ch == '.' )
				break;
			if( !isdigit(ch) )
				goto EXIT;
			num = num * 10 + (ch - '0');
		}
		av[ac] = num;
	}
EXIT:
	for( ai = ac; ai < 4; ai++ )
		av[ai] = 0;
	return ac;
}
static int inetADDR(PCStr(addr))
{	int av[4];
	char ac;
	const char *ap;

	for( ap = addr; ac = *ap; ap++ )
		if( ac != '.' && (ac < '0' || '9' < ac) )
			return 0;

	scan4num(addr,av);
	return (av[0] << 24) | (av[1] << 16) | (av[2] << 8) | av[3];
}
static unsigned long inet_addr(PCStr(addr))
{	int av[4];

	if( scan4num(addr,av) == 4 )
	return (av[0] << 24) | (av[1] << 16) | (av[2] << 8) | av[3];
	return (unsigned int)-1;
}

static int getMASK(unsigned int iaddr)
{	int a1,mask;

	a1 = (iaddr >> 24) & 0xFF;
	if( a1 < 128       ) mask = 0xFF000000; else
	if( a1 < 128+64    ) mask = 0xFFFF0000; else
	if( a1 < 128+64+32 ) mask = 0xFFFFFF00; else
			     mask = 0xFFFFFF00;
	return mask;
}

typedef struct {
	char	full;
	int	serno;
/*
	int	maskedL;
	int	maskedH;
*/
	unsigned int maskedL;
	unsigned int maskedH;
  const	char	*name;
} DName;

static DName DnTab[0x20000];
static int DnTabX;

/* decending order, narrower range first */
static int dacmp(DName *a,DName *b){
	if( a->maskedL != b->maskedL ){
		if( b->maskedL > a->maskedL )
			return 1;
		else	return -1;
	}else{
		if( a->maskedH == b->maskedH ){
			/* in the original order for netdom.hosts
			 * (older upper entry first)
			 */
			if( b->serno < a->serno )
				return 1;
			else	return -1;
		}else
		if( a->maskedH > b->maskedH )
			return 1;
		else	return -1;
	}
}
static void sort_dntab(){
qsort(DnTab,DnTabX,sizeof(DName),(int(*)(const void*,const void*))dacmp);
}
static void load_dn1(PCStr(addrL),PCStr(addrH),PCStr(name))
{	int addri;
	const char *np;
	DName *dnp;

	if( elnumof(DnTab) <= DnTabX ){
		fprintf(stderr,"---- ntod: DnTab[%d] Overflow\n",DnTabX);
		return;
	}
	dnp = &DnTab[DnTabX++];
	dnp->serno = DnTabX-1;
	if( inet_addr(addrL) != -1 ){
		dnp->full = 1;
		dnp->maskedL = inet_addr(addrL);
		dnp->maskedH = inet_addr(addrH);
	}else{
		fprintf(stderr,"NOT FULL %s %s %s\n",addrL,addrH,name);
		addri = inetADDR(addrL);
		dnp->maskedL = addri & getMASK(addri);
		addri = inetADDR(addrH);
		dnp->maskedH = addri & getMASK(addri);
	}
	dnp->name = stralloc(name);
	for( np = dnp->name; *np; np++ )
		*(char*)np = tolower(*np);
}

static void inet_range(PVStr(addr))
{	CStr(addr0,128);
	CStr(addrx,128);
	refQStr(ap,addrx); /**/
	int masklen,mask,addr1,addr2,mx,a1,a2;
	
	if( Xsscanf(addr,"%[^/]/%d",AVStr(addr0),&masklen) != 2 )
		return;
	if( masklen < 24 )
		fprintf(stderr,"Warning: too long mask ? %s\n",addr);

	addr1 = inetADDR(addr0);
	mask = 0;
	for( mx = 0; mx < (32-masklen); mx++ )
		mask |= (1 << mx);
	addr2 = addr1 + mask;

	setVStrEnd(ap,0);
	for( mx = 0; mx < 4; mx++ ){
		if( mx != 0 ){
			setVStrPtrInc(ap,'.');
			setVStrEnd(ap,0);
		}
		a1 = (addr1 >> (8*(3 - mx))) & 0xFF;
		a2 = (addr2 >> (8*(3 - mx))) & 0xFF;

		if( a1 == a2 ){
			sprintf(ap,"%d",a1);
			ap += strlen(ap);
		}else{
			sprintf(ap,"[%d-%d]",a1,a2);
			break;
		}
	}
	strcpy(addr,addrx);
}

static void fill(PCStr(net),PVStr(host),int mask)
{	char ch;
	const char *sp;
	refQStr(dp,host); /**/
	int ndot;

	ndot = 0;
	for( sp = net; ch = *sp; sp++ ){
		assertVStr(host,dp);
		if( ch == '.' ){
			if( sp[1] == 0 )
				break;
			ndot++;
		}
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
	for(; ndot < 3; ndot++ ){
		sprintf(dp,".%d",mask);
		dp += strlen(dp);
	}
}

static char dbfile0[1024];
static void load_dntab(PCStr(dbfile))
{	FILE *dntab;
	CStr(line,256);
	const char *dp;
	CStr(addr,128);
	CStr(name,128);
	CStr(min,128);
	CStr(max,128);
	int tabx;

	if( File_cmp(dbfile0,dbfile) == 0 )
		return;
	Xstrcpy(FVStr(dbfile0),dbfile);

	dntab = fopen(dbfile,"r");
	if( dntab == NULL )
		return;

	tabx = DnTabX;
	while( fgets(line,sizeof(line),dntab) != NULL ){
		if( dp = strchr(line,'#') )
			truncVStr(dp);
		if( line[0] == 0 )
			continue;

		dp = wordScan(line,addr);
		wordScan(dp,name);
		if( addr[0] == 0 || name[0] == 0 ){
			fprintf(stderr,"? %s",line);
			continue;
		}
		if( name[strlen(name)-1] == '.' ){
			fprintf(stderr,"? %s",line);
			setVStrEnd(name,strlen(name)-1);
		}

		if( dp = strchr(addr,'/') )
			inet_range(AVStr(addr));

		if( dp = strchr(addr,'[') ){
			CStr(addrC,128);
			CStr(addrL,128);
			CStr(addrH,128);
			int aH,aL;

			strcpy(addrC,addr);
			*strchr(addrC,'[') = 0;
			sscanf(dp+1,"%d-%d",&aL,&aH);
			sprintf(addrL,"%s%d",addrC,aL);
			sprintf(addrH,"%s%d",addrC,aH);
			fill(addrL,AVStr(min),0);
			fill(addrH,AVStr(max),255);
			load_dn1(min,max,name);
		}else{
			fill(addr,AVStr(min),0);
			fill(addr,AVStr(max),255);
			load_dn1(min,max,name);
		}
	}
	fclose(dntab);
	fprintf(stderr,"LOADED %s [%d] / %d / %d\n",dbfile,
		DnTabX-tabx,DnTabX,elnumof(DnTab));
}

static int addrHit;
static int addrMiss;
static int addrTries;
/*
static const char *getdomainbyaddr(int iaddr)
*/
static const char *getdomainbyaddrX(int iaddr,int ai,int inc,int maxs);
static const char *getdomainbyaddr(unsigned int iaddr)
{	int ma,ai;
	DName *dnp;
	const char *ap;
	int inc;
	int base;
	int dir = 1;
	int sbase;

	inc = DnTabX / 2;
	dir = 1;
	base = inc;
	while( 0 < inc ){
		if( base < 0 ){
			return NULL;
		}
		dnp = &DnTab[base];
		if( iaddr == dnp->maskedL ){
			dir = 0;
			break;
		}
		if( iaddr < dnp->maskedL ){
			base += inc;
			dir = 1;
		}else{
			base -= inc;
			dir = -1;
		}
		inc /= 2;
	}

	if( dir == 0 ){
		int i;
		for( i = base-1; 0 <= i; i-- ){
			dnp = &DnTab[i];
			if( iaddr != dnp->maskedL )
				break;
/*
fprintf(stderr,"--- . %d %d %d %s\n",dir,inc,base,DnTab[base].name);
fprintf(stderr,"--- p %d %d %d %s\n",dir,inc,i,DnTab[i].name);
*/
			base = i;
		}
		if( ap = getdomainbyaddrX(iaddr,base,1,1) ){
			addrHit++;
			return ap;
		}
	}else{
		sbase = base;
		if( dir < 0 ){
			int i;
			for( i = base; 0 < i; i-- ){
				dnp = &DnTab[i];
				if( iaddr<dnp->maskedL && iaddr<dnp->maskedH ){
					sbase = i;
					break;
				}
			}
		}
		if( ap = getdomainbyaddrX(iaddr,sbase,1,1024) ){
			addrHit++;
			return ap;
		}
	}

	addrMiss++;
	return getdomainbyaddrX(iaddr,0,1,0);
}
static const char *getdomainbyaddrX(int iaddr,int ai,int inc,int maxs)
/*
{	int si,ma;
*/
{	int si;
	unsigned int ma;
	DName *dnp;

/*
	ma = iaddr & getMASK(iaddr);
	for( ai = 0; ai < DnTabX; ai++ ){
*/
	ma = iaddr;
	for( si = 0; 0 <= ai && ai < DnTabX; ai += inc ){
		if( maxs && maxs <= si )
			break;
		si++;
		addrTries++;
		dnp = &DnTab[ai];
		if( dnp->full ){
			if( dnp->maskedL <= iaddr && iaddr <= dnp->maskedH )
			{
				return dnp->name;
			}
		}else{
			if( dnp->maskedL <= ma && ma <= dnp->maskedH )
			{
				return dnp->name;
			}
		}
		if( maxs ){
			if( inc < 0 ){
				if( ma < dnp->maskedL && ma < dnp->maskedH ){
					return 0;
				}
			}
		}
/*
if( si % 1000 == 0 )
fprintf(stderr,"--- %2d %2d %4d %8X [%8X - %8X]\n",si,inc,ai,ma,dnp->maskedL,dnp->maskedH);
*/
	}
	return 0;
}

static int is_inetaddr(PCStr(addr))
{	const char *ap;
	char ch;

	for( ap = addr; ch = *ap; ap++ ){
		if( ch != '.' && !isdigit(ch) )
			return 0;
		if( strchr(" \t\r\n",ch) )
			break;
	}
	return 1;
}
static void strip_inaddr(PVStr(host))
{	const char *sp;
	/*
	const char *psp;
	*/
	refQStr(psp,host);
	int a1,a2,a3,a4;
	int ndot = 0;

	if( (sp = strstr(host,".IN-ADDR.ARPA"))
	 || (sp = strstr(host,".in-addr.arpa")) ){
		psp = NULL;
		for( sp--; host < sp; sp-- ){
			if( *sp == '.' ){
				ndot++;
				/*
				if( sp[1] < '0' || '9' < sp[1] ){
				*/
				if( sp[1] < '0' || '9' < sp[1] || 4 < ndot ){
					/*
					truncVStr(psp);
					*/
		if( psp ){
			switch( sscanf(psp+1,"%d.%d.%d.%d",&a1,&a2,&a3,&a4) ){
			case 4:
				sprintf(host,"%d.%d.%d.%d",a4,a3,a2,a1);
				return;
			case 3:
				sprintf(host,"%d.%d.%d.%d",a3,a2,a1,0);
				return;
			}
		}
					strsubst(BVStr(host),".","-");
					strcat(host,".BROKEN");
					break;
				}
				psp = sp;
			}
		}
		if( sscanf(host,"%d.%d.%d.%d",&a1,&a2,&a3,&a4) == 4 )
			sprintf(host,"%d.%d.%d.%d",a4,a3,a2,a1);
	}
}

static const char *hostsfile;

int ntod_main(int ac,char *av[])
{	CStr(iline,4096);
	const char *sp;
	char sc;
	const char *dp;
	char xclass;
	CStr(hostaddr,1024);
	refQStr(hp,hostaddr);
	CStr(prefix,1024);
	const char *remain;
	int a1;
	int ina;
	const char *dom;
	const char *dbfile;
	const char *aliases;
	CStr(aliasb,1024);
	CStr(hostsdb,1024);
	int ai,add_host;
	int dump_tab = 0;
	int li;
	double Start,Prev,Now;
	int fskip = 0;

	if( strstr(av[0],"uinc") )
		return uinc_main(ac,av);

	add_host = getenv("ADDHOST") != NULL;
	for( ai = 1; ai < ac; ai++ ){
		if( av[ai][0] == '+' )
			add_host = 1;
		if( strcmp(av[ai],"-d") == 0 ){
			dump_tab = 1;
		}
		if( av[ai][0] == '-' && isdigit(av[ai][1]) )
			fskip = atoi(&av[ai][1]);
	}
	if( add_host )
		RES_verify("");

	dbfile = getenv("NETDOMDB");
	if( dbfile == NULL )
		dbfile = "./netdom";

	aliases = getenv("DOMALIAS");
	if( aliases == NULL ){
		strcpy(aliasb,dbfile);
		strcat(aliasb,".alias");
		aliases = aliasb;
	}

	hostsfile = getenv("HOSTSDB");
	if( hostsfile == NULL ){
		strcpy(hostsdb,dbfile);
		strcat(hostsdb,".hosts");
		hostsfile = hostsdb;
	}

	load_dntab(hostsfile);
	load_dntab(dbfile);
	sort_dntab();
	if( dump_tab ){
		int i;
		for( i = 0; i < DnTabX; i++ )
		printf("%8X - %8X %5d %5d %s\n",DnTab[i].maskedL,
			DnTab[i].maskedH,i,DnTab[i].serno,DnTab[i].name);
		// printf("%8X - %8X\n",DnTab[i].maskedL,DnTab[i].maskedH);
		exit(0);
	}

	RES_order("D",VStrNULL);

	Start = Prev = Time();
	li = 0;
	while( Fgets(AVStr(iline),sizeof(iline),stdin) != NULL ){
		li++;
		if( li % 50000 == 0 ){
			Now = Time();
			fprintf(stderr,"%6.1f %4.1f %6d ... %5d : %5d (%d)\n",
				Now-Start,Now-Prev,li,addrHit,addrMiss,addrTries);
			Prev = Now;
		}
		hp = hostaddr;
		prefix[0] = 0;
		sp = iline;
		if( fskip ){
			const char *dp,*np;
			int fi;
			dp = iline;
			for( fi = 0; fi < fskip; fi++ ){
				np = strchr(dp,' ');
				if( np == 0 )
					break;
				dp = np;
				while( *dp == ' ' )
					dp++;
			}
			if( iline < dp ){
				QStrncpy(prefix,iline,dp-iline+1);
			}
			sp = dp;
		}
		/*
		for( sp = iline; sc = *sp; sp++ ){
		*/
		for( ; sc = *sp; sp++ ){
			if( sc == '@' ){
				truncVStr(sp);
				strcpy(prefix,iline);
				strcat(prefix,"@");
				hp = hostaddr;
				continue;
			}
			if( sc==' '||sc=='\t'||sc=='\r'||sc=='\n' )
				break;
			if( sc==',' )
				break;

			if( sc == '.' && (sp[1] == 0 || isspace(sp[1])) ){
			}else
			if( isupper(sc) )
				setVStrPtrInc(hp,tolower(sc));
			else	setVStrPtrInc(hp,sc);
		}
		setVStrEnd(hp,0);
		remain = sp;

		if( dp = strstr(hostaddr,".-.") ) /* RIDENT forwarded */
			strcpy(hostaddr,dp+3);
		strip_inaddr(AVStr(hostaddr));

		if( *hostaddr == 0 )
			goto PUT;

		if( ina = inetADDR(hostaddr) )
		if( dom = getdomainbyaddr(ina) ){
			strcpy(hostaddr,dom);
		}else
		if( add_host ){
			CStr(addr_host,1024);
			CStr(addr,128);
			CStr(host,256);
			FILE *hostsdb_fp;

			if( RES_1s(hostaddr,AVStr(addr_host)) ){
				Xsscanf(addr_host,"%s %s",AVStr(addr),AVStr(host));
				strip_inaddr(AVStr(host));
				load_dn1(addr,addr,host);

				if( hostsdb_fp = fopen(hostsfile,"a") ){
					fprintf(stderr,"++ %s",addr_host);
					fputs(addr_host,hostsdb_fp);
					fclose(hostsdb_fp);
				}
				strcpy(hostaddr,host);
			}
		}

		if( is_inetaddr(hostaddr) ){
			fprintf(stderr,"?? %s\n",hostaddr);
			a1 = atoi(hostaddr);
			if( a1 < 128       ) xclass = 'A'; else
			if( a1 < 128+64    ) xclass = 'B'; else
			if( a1 < 128+64+32 ) xclass = 'C'; else
					     xclass = 'D';
			dp = hostaddr;
			dp = strchr(dp+1,'.');
			if( dp == NULL )
				goto PUT;
			if( xclass != 'A' ){
				if( dp == NULL )
					goto PUT;
				dp = strchr(dp+1,'.');
				if( dp == NULL )
					goto PUT;
				if( xclass != 'B' ){
					dp = strchr(dp+1,'.');
					if( dp == NULL )
						goto PUT;
				}
			}
			truncVStr(dp);
			printf("%c:",xclass);
		}else{
			generic_domain(AVStr(hostaddr));
		}
	PUT:
/*
		fseek(stdout,0,2);
*/
		if( prefix[0] != 0 )
			fprintf(stdout,"%s",prefix);
			/*
			fprintf(stdout,"%s@",prefix);
			*/
		fputs(hostaddr,stdout);
		fputs(remain,stdout);
		fputs("\n",stdout);
/*
		fflush(stdout);
*/
	}
	Now = Time();
	fprintf(stderr,"%6.1f %4.1f %6d ... %5d : %5d (%d) Finished\n",
		Now-Start,Now-Prev,li,addrHit,addrMiss,addrTries);
	return 0;
}

static int host_isisn(int hostid,PCStr(host),int *sernop);
static int uinc_main(int ac,char *av[])
{	int ai;
	const char *arg;
	CStr(line,1024);
	const char *dp;
	CStr(date,128);
	CStr(host,128);
	FILE *in,*out;
	int hostid,serno;
	int REV,rev;
	int all;

	in = stdin;
	out = stdout;

	serno = 0;
	all = 0;
	REV = 0;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-a") == 0 )
			all = 1;
		else
		if( strcmp(arg,"-r") == 0 )
			REV = 1;
	}

	hostid = strid_create(0x80000);

	while( fgets(line,sizeof(line),in) != NULL ){
		if( Xsscanf(line,"%s %*s %*s %[^,]",AVStr(date),AVStr(host)) == 2 ){
			rev = 1;
		}else
		if( Xsscanf(line,"%s %s",AVStr(host),AVStr(date)) == 2 ){
			rev = 0;
		}else{
			printf("????\n%s\n",line);
			break;
		}
		if( all || !host_isisn(hostid,host,&serno) ){
			if( !REV && rev )
				fprintf(out,"%s %s\n",host,date);
			else	fprintf(out,"%s %s\n",date,host);
		}
	}
	return 0;
}
static int host_isisn(int hostid,PCStr(host),int *sernop)
{	int len;
	const char *dp;
	const char *suff;
	CStr(alias,128);

	if( strid(hostid,host,-1) != -1 )
		return 1;

	len = strlen(host);
	if( 6 < len ){
		dp = &host[len-6];
		suff = 0;
		if( strncasecmp(dp,".or.jp",6) == 0 ) suff = ".ne.jp"; else
		if( strncasecmp(dp,".ne.jp",6) == 0 ) suff = ".or.jp";
		if( suff ){
			strcpy(alias,host);
			Xstrcpy(DVStr(alias,len-6),suff);
			if( strid(hostid,alias,-1) != -1 )
				return 1;
		}
	}

	*sernop += 1;
	strid(hostid,host,*sernop);
	return 0;
}

int main(int ac,char *av[])
{
	minit_resconf();
	minit_timer();
	ntod_main(ac,av);
	return 0;
}

//void Finish(int code){ exit(code); }
//void setBinaryIO(){ }
//void start_service(){}
//void WINthread(){}
//int WAIT_WNOHANG = -1;

int acceptViaSocks(int sock,PVStr(rhost),int *rport){ return -1; }
int bindViaSocks(DGC*Conn,PCStr(dsthost),int dstport,PVStr(rhost),int *rport){ return -1; }
int GetViaSocks(DGC*Conn,PCStr(host),int port){ return 0; }
int CTX_auth(DGC*ctx,PCStr(user),PCStr(pass)){ return 0; }
int VSA_getViaSocksX(DGC*ctx,PCStr(h),int p,VSAddr *sv,AuthInfo *au,VSAddr *lo){
        return 0;
}
int serverPid(){ return getpid(); }
void finishClntYY(FL_PAR,DGCTX){}
void finishServYY(FL_PAR,DGCTX){}
const char *gethostaddrX(PCStr(host)){ return "255.255.255.255"; }
int SRCIFfor(DGCTX,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport){ return 0; }
DGC*MainConn(){ return 0; }
