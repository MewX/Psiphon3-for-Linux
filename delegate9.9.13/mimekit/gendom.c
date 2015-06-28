/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	gendom.c (Generic domain)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	031021	extracted from ntod.c
ToDo:
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <ctype.h>
#include "ystring.h"


static void reverse(PCStr(line),PVStr(rline))
{	const char *pp;
	refQStr(rp,rline); /**/

	alertVStr(rline,strlen(line)+1);

	if( *line == 0 ){
		setVStrEnd(rline,0);
		return;
	}
	cpyQStr(rp,rline);
	for( pp = line; *pp; pp++ )
		;
	if( line < pp )
		pp--;
	do setVStrPtrInc(rp,*pp--); while( line <= pp );
	setVStrEnd(rp,0);
}

static struct {
	int	 d_lev;
  const	char	*d_name;
  const	char	*d_rev;
} domlev[] = {
	{3,	"arin"},    /* 140718c for ARIN whois to "netname.country.arin " */
	{3,	"apnic"},   /* 140718c for APNIC whois to "netname.country.apnic" */
	{3,	"afrinic"}, /* 140718c for AFRINIC whois to "netname.country.afrinic" */
	{3,	"jpnic"},   /* 140718c for JPNIC whois to "netname.country.jpnic " */
	{3,	"lacnic"},  /* 140718c for LACNIC whois to "netname.country.lacnic " */
	{3,	"ripe"},    /* 140705a for RIPE whois to "netname.country.ripe" */
	{2,     "kek.jp"},
	{2,     "ntt.jp"},
	{2, "nttdata.jp"},
/*
	{4, "*-unet.ocn.ne.jp"},
*/
	{3,       "=.jp"},
	{3,      "lg.jp"},
	{3,  "city.*.jp"},
	{3,  "pref.*.jp"},

	{4,         "aichi.jp"},
	{4,         "akita.jp"},
	{4,         "aomori.jp"},
	{4,         "chiba.jp"},
	{4,         "ehime.jp"},
	{4,         "fukui.jp"},
	{4,         "fukuoka.jp"},
	{4,         "fukushima.jp"},
	{4,         "gifu.jp"},
	{4,         "gunma.jp"},
	{4,         "hiroshima.jp"},
	{4,         "hokkaido.jp"},
	{4,         "hyogo.jp"},
	{4,         "ibaraki.jp"},
	{4,         "ishikawa.jp"},
	{4,         "iwate.jp"},
	{4,         "kagawa.jp"},
	{4,         "kagoshima.jp"},
	{4,         "kanagawa.jp"},
	{4,         "kochi.jp"},
	{4,         "kumamoto.jp"},
	{4,         "kyoto.jp"},
	{4,         "mie.jp"},
	{4,         "miyagi.jp"},
	{4,         "miyazaki.jp"},
	{4,         "nagano.jp"},
	{4,         "nagasaki.jp"},
	{4,         "nara.jp"},
	{4,         "niigata.jp"},
	{4,         "oita.jp"},
	{4,         "okayama.jp"},
	{4,         "okinawa.jp"},
	{4,         "osaka.jp"},
	{4,         "saga.jp"},
	{4,         "saitama.jp"},
	{4,         "shimane.jp"},
	{4,         "shizuoka.jp"},
	{4,         "shiga.jp"},
	{4,         "tochigi.jp"},
	{4,         "tokushima.jp"},
	{4,         "tokyo.jp"},
	{4,         "tottori.jp"},
	{4,         "toyama.jp"},
	{4,         "wakayama.jp"},
	{4,         "yamagata.jp"},
	{4,         "yamaguchi.jp"},
	{4,         "yamanashi.jp"},

	{4,         "kawasaki.jp"},
	{4,         "kitakyushu.jp"},
	{4,         "kobe.jp"},
	{4,         "nagoya.jp"},
	{4,         "sapporo.jp"},
	{4,         "sendai.jp"},
	{4,         "yokohama.jp"},

	{2,         "jp"},
	{3,       "=.ae"},
	{3,       "=.al"},
	{3,       "=.ao"},
	{3,       "=.ar"},
	{3,       "gv.at"},
	{3,       "=.at"},
	{3,       "=.au"},
	{3,      "oz.au"},
	{3,       "=.ba"},
	{3,       "=.bb"},
	{3,       "=.bd"},
	{3,       "=.be"},
	{3,       "=.bh"},
	{3,       "=.bo"},
	{3,       "=.bt"},
	{3,       "=.by"},
	{3,   "minsk.by"},
	{3,       "=.ca"},
	{3,       "ab.ca"},
	{3,       "bc.ca"},
	{3,       "mb.ca"},
	{3,       "nb.ca"},
	{3,       "ns.ca"},
	{3,       "nt.ca"},
	{3,       "on.ca"},
	{3,       "qc.ca"},
	{3,       "sk.ca"},
	{3,       "=.ci"},
	{3,       "=.ck"},
	{3,       "=.cl"},
	{3,       "=.co"},
	{3,       "=.cn"},
	{3,      "cq.cn"},
	{3,      "gd.cn"},
	{3,      "gx.cn"},
	{3,      "fj.cn"},
	{3,      "hb.cn"},
	{3,      "js.cn"},
	{3,      "jx.cn"},
	{3,      "ln.cn"},
	{3,      "sh.cn"},
	{3,      "sn.cn"},
	{3,      "sx.cn"},
	{3,      "zj.cn"},
	{3,       "=.cr"},
	{3,       "=.cu"},
	{3,       "=.cy"},
	{3,       "=.do"},
	{3,       "=.ec"},
	{3,       "=.ee"},
	{3,       "=.eg"},
	{3,       "=.er"},
	{3,       "=.fj"},
	{3,    "asso.fr"},
	{3,    "gouv.fr"},
	{3,      "tm.fr"},
	{3,       "=.ga"},
	{3,       "=.ge"},
	{3,       "=.gh"},
	{3,       "=.gn"},
	{3,       "=.gr"},
	{3,       "=.gt"},
	{3,       "=.gy"},
	{3,       "=.hk"},
	{3,       "=.hn"},
	{3,       "=.hu"},
	{3,       "=.id"},
	{3,       "=.ie"},
	{3,       "=.il"},
	{3,       "=.in"},
	{3,   "ernet.in"},
	{3,       "=.ir"},
	{3,      "fe.it"},
	{3,       "=.jo"},
	{3,       "=.ke"},
	{3,       "=.kh"},
	{3,       "=.kr"},
	{3,       "nm.kr"},
	{3,       "re.kr"},
	{3,       "=.kw"},
	{3,       "=.lb"},
	{3,       "=.lk"},
	{3,       "=.lv"},
	{3,       "=.ma"},
	{3,       "=.mg"},
	{3,       "=.mm"},
	{3,       "=.mo"},
	{3,       "=.mw"},
	{3,       "=.mz"},
	{3,     "af.mil"},
	{3,   "army.mil"},
	{3,   "navy.mil"},
	{3,   "disa.mil"},
	{3,       "=.mk"},
	{3,       "=.mt"},
	{3,       "=.mv"},
	{2,  "jaring.my"},
	{3,       "=.my"},
	{3,       "=.mx"},
	{3,     "uu.net"},
	{3,       "=.na"},
	{3,       "=.ng"},
	{3,       "=.ni"},
	{3,       "=.np"},
	{3,       "=.nz"},
	{3,       "=.om"},
	{3,       "=.pa"},
	{3,       "=.pe"},
	{3,       "=.pf"},
	{3,       "=.pg"},
	{3,       "=.pk"},
	{3,       "=.pl"},
	{3,       "=.ph"},
	{3,       "=.py"},
	{3,       "=.qa"},
	{3,       "=.ro"},
	{2,      "co.ru"},
	{3,       "=.ru"},
	{3,     "irk.ru"},
	{3,     "khv.ru"},
	{3,     "msk.ru"},
	{3,     "msk.su"},
	{3,     "nov.ru"},
	{3,     "nsc.ru"},
	{3,     "nsk.ru"},
	{3,     "nsk.su"},
	{3,     "spb.ru"},
	{3,     "spb.su"},
	{3,     "udm.ru"},
	{3,   "tomsk.ru"},
	{3,       "=.rw"},
	{3,       "=.sa"},
	{3,       "=.sb"},
	{3,       "=.sg"},
	{3,       "=.si"},
	{3,       "=.sk"},
	{3,       "=.sv"},
	{3,       "=.sy"},
	{3,       "=.tg"},
	{3,       "=.th"},
	{3,       "=.tr"},
	{3,       "=.tt"},
	{3,       "=.tw"},
	{3,       "=.uk"},
	{3,       "=.ua"},
	{3,      "cn.ua"},
	{3,      "cv.ua"},
	{3,      "dp.ua"},
	{3,      "km.ua"},
	{3,      "lg.ua"},
	{3,      "te.ua"},
	{3,      "zp.ua"},
	{3,    "kiev.ua"},
	{3,"uzhgorod.ua"},
	{3,       "=.ug"},
	{3,       "=.us"},
	{3,       "al.us"},
	{3,       "ar.us"},
	{3,       "az.us"},
	{3,       "ca.us"},
	{3,       "de.us"},
	{3,       "fl.us"},
	{3,       "ga.us"},
	{3,       "hi.us"},
	{3,       "ia.us"},
	{3,       "il.us"},
	{3,       "in.us"},
	{3,       "la.us"},
	{3,       "ks.us"},
	{3,       "ma.us"},
	{3,       "md.us"},
	{3,       "me.us"},
	{3,       "mi.us"},
	{3,       "mn.us"},
	{3,       "mo.us"},
	{3,       "ms.us"},
	{3,       "mt.us"},
	{3,       "nc.us"},
	{3,       "nj.us"},
	{3,       "nv.us"},
	{3,       "ny.us"},
	{3,       "oh.us"},
	{3,       "pa.us"},
	{3,       "tn.us"},
	{3,       "tx.us"},
	{3,       "ut.us"},
	{3,       "va.us"},
	{3,       "vt.us"},
	{3,       "wa.us"},
	{3,       "wi.us"},
	{3,       "=.uy"},
	{3,       "=.uz"},
	{3,       "=.ve"},
	{3,       "=.vn"},
	{3,       "=.ws"},
	{3,       "=.ye"},
	{3,       "=.yu"},
	{3,       "=.za"},
	{3,       "=.zw"},
	{3,       "=.br"},
	0,
};
static const char *attrs[16] = {
	"ac",
	"ad",
	"co",
	"ed",
	"go",
	"gr",
	"or",
	"ne",
	"com",
	"edu",
	"gov",
	"org",
	"net",
	0,
};
static const char *rattrs[16]; /**/
static int isattr(PCStr(dom))
{	const char *ap;
	const char *dn;
	char ac;
	char pc;
	CStr(rattr,16);
	int ai,alen;

	if( rattrs[0] == NULL ){
		for( ai = 0; ap = attrs[ai]; ai++ ){
			reverse(ap,AVStr(rattr));
			rattrs[ai] = stralloc(rattr);
		}
	}
	for( ai = 0; ap = rattrs[ai]; ai++ ){
		dn = dom;
		for( alen = 0;;alen++ ){
			pc = *ap++;
			ac = *dn++;
			if( pc == 0 && (ac == 0 || ac == '.') )
				return alen;
			if( pc != ac )
				break;
		}
	}
	return 0;
}

static int domain_level(PCStr(rfqdn))
{	int hi,hc;
	int alen;
	const char *qn;
	char qc;
	char sqc;
	const char *dn;
	CStr(rdn,128);

	if( domlev[0].d_rev == NULL ){
		for( hi = 0; dn = domlev[hi].d_name; hi++ ){
			reverse(dn,AVStr(rdn));
			domlev[hi].d_rev = stralloc(rdn);
		}
	}
	for( hi = 0; dn = domlev[hi].d_rev; hi++ ){
		qn = rfqdn;
		for(;;){
			hc = *dn++;
			qc = *qn++;
			if( hc == '*' ){
				sqc = *dn; /* may be "." */
				while( qc != 0 && qc != sqc )
					qc = *qn++;
				if( qc == 0 )
					return domlev[hi].d_lev;
				dn++;
				continue;
			}
			if( hc == '=' ){
				if( alen = isattr(qn-1) ){
					qn += alen-1;
					continue;
				}
			}
			if( hc == 0 && (qc == 0 || qc == '.') )
				return domlev[hi].d_lev;
			if( hc == '?' )
				continue;
			if( hc != qc )
				break;
			if( hc == 0 || qc == 0 )
				break;
		}
	}
	return 0;
}

void generic_domain(PVStr(hostaddr))
{	CStr(rhostaddr,4096);
	const char *dp;
	char dc;
	int lev,li;

	if( hostaddr[0] == 0 )
		return;

	reverse(hostaddr,AVStr(rhostaddr));
	strtolower(rhostaddr,rhostaddr);
	if( (lev = domain_level(rhostaddr)) == 0 )
		lev = 2;

	dp = rhostaddr;
	for( li = 0; li < lev; li++ ){
		for( dp++; dc = *dp; dp++ )
			if( dc == '.' )
				break;
		if( dc == 0 )
			return;
	}
	truncVStr(dp);
	reverse(rhostaddr,BVStr(hostaddr));
}

int generic_domainX(PVStr(hostaddr)){
	IStr(oha,MaxHostNameLen);

	strcpy(oha,hostaddr);
	generic_domain(BVStr(hostaddr));
	if( streq(oha,hostaddr) )
		return 0;
	else	return 1;
}
int generic_domain_email(PVStr(email)){
	refQStr(gendom,email);
	refQStr(dom,email);
	int rew;

	strcpy(gendom,email);
	if( dom = strchr(gendom,'@') ){
		dom++;
		rew = generic_domainX(AVStr(dom));
	}else{
		rew = generic_domainX(AVStr(gendom));
	}
	if( rew ){
		strcpy(email,gendom);
		return 1;
	}
	return 0;
}
int gendom_main(int ac,const char *av[]){
	IStr(gendom,MaxHostNameLen);
	IStr(line,MaxHostNameLen);
	IStr(rem,MaxHostNameLen);

	if( ac < 2 ){
		fprintf(stderr,"Usage: %s host.domain\n",av[0]);
		return -1;
	}
	if( streq(av[1],"-") ){
		for(;;){
			if( fgets(line,sizeof(line),stdin) == NULL ){
				break;
			}
			Xsscanf(line,"%[-.:a-zA-Z0-9]%[^\377]",AVStr(gendom),AVStr(rem));
			generic_domain_email(AVStr(gendom));
			fprintf(stdout,"%s%s",gendom,rem);
		}
		return 0;
	}
	strcpy(gendom,av[1]);
	generic_domain_email(AVStr(gendom));
	fprintf(stdout,"%s",gendom);
	fprintf(stdout,"\n");
	return 0;
}
