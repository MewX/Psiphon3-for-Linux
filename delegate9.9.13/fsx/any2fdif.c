/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2004-2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        any2fdif.c
Author:         Yutaka Sato <ysato@delegate.org>
Description:
History:
        040602  created
//////////////////////////////////////////////////////////////////////#*/
/* Copyright (c) 2004-2005 Yutaka Sato. All rights reserved.
 *
 * any2fdif.c
 *
 * 040602 created as a HTML to MAIL converter
 * 040609 extended to a FDIF generator taking generic input types
 *
 */
#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
/*
#include <sys/types.h>
#include <sys/stat.h>
*/
#include "ystring.h"
#include "mime.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include "vsocket.h"
#include "proc.h"
#include "yarg.h"
#include "credhy.h"
#include "dglib.h"
#include "log.h"
#include "url.h"

int HTMLtoTEXT(FILE *ain,FILE *aout,int toHtml);
int PdfToText(FILE *pdff,FILE *txtf);
typedef struct sed_env SedEnv;
int sed_compile(SedEnv *se,PCStr(command));
void sed_execute1(SedEnv *se,PCStr(in),PVStr(out),int err);
int relay_file(FILE *in,FILE *out,int sizemax,int timeout,int timemax);
int VA_url_permitted(VAddr *vaddr,AuthInfo *auth,PCStr(url));
FILE * VA_URLget(DGC*ctx,VAddr *vaddr,PCStr(url),int reload,FILE *out);

int scanAttrs(PCStr(src),int an,PCStr(nam1),PVStr(val1),int vsiz1,PCStr(nam2),PVStr(val2),int vsiz2);
static void scanUrls(FILE *flist,int optr,PCStr(strip),PCStr(pre),PCStr(conv),FILE *out,FILE *descf);
void updateSrt(PCStr(base),PCStr(strip),PCStr(pre));
int extractAuthor(PCStr(str),PCStr(top),PVStr(author),int size,PCStr(url),int dump);
int copy2auth(PCStr(copyr),PVStr(author),int size,PCStr(url),int force);
int fscanTag(FILE *in,int ch,PVStr(tag),int tsiz);
int isRFC822(FILE *fp);
const char *strskip(PCStr(s),PCStr(p));
char *wbstrcpy(PVStr(dst),PCStr(dx),PCStr(src),int len);
int scanMeta(PCStr(src),PVStr(nam),int nsiz,PVStr(con),int csiz);
void backseek(FILE *in, int disp);
int toUTF8(unsigned int uc,unsigned char *us);
int isUTF8chr(PCStr(str));
int ccxUchar(PCStr(ob),PVStr(xub),int siz);
void subject_stripPrefix(PVStr(subj),int maxDelBracket,int leaveBracket1);

void setnamedtmpbase(PCStr(path));
void removenamedtmpfiles();

static double Start;

#ifdef MAIN
int isFullURL(PCStr(url)){
	return 0;
}
FILE *URLget(PCStr(url),int reload,FILE *out){
	fprintf(stderr,"URLget() is not available.\n");
	return 0;
}
const char *DELEGATE_verdate(){
	return 0;
}

int serviceport(PCStr(service)){
	return 0;
}
int decomp_absurl(PCStr(url),PVStr(proto),PVStr(login),PVStr(upath),int ulen){
	*proto = *login = *upath = 0;
	return 0;
}
int scan_protositeport(PCStr(url),PVStr(proto),PVStr(userpasshost),PVStr(port)){
	*proto = *userpasshost = *port = 0;
	return 0;
}
char *html_nextTagAttrX(void *vBase,PCStr(html),PCStr(ctype),PVStr(rem),const char **tagp,const char **attrp,int *convmaskp){
	return 0;
}
const char *getURLgetURL(){
	return 0;
}

int any2fdif_main(int ac,const char *av[]);
int main(int ac,const char *av[]){
	return any2fdif_main(ac,av);
}
#endif

void fflushTmp(FILE *fp);
FILE *getTmp(int ti);
#define TMP0	0
#define TMP1	1
#define TMP2	2
#define TMP3	3
#define TMP4	4
#define TMP5	5
#define TMP6	6
#define TMP7	7

static int ccx_oututf;
static const char *ccx_outcode = "a-b-r-EUC-JP";
/*
static const char *hide_addr = "From:%l@%r..%c";
*/
/*
static const char *hide_addr = "From:%l@%r...";
static const char *hide_bodyaddr = "%l@%r...";
*/
static const char *hide_addr;
static const char *hide_bodyaddr;
static const char *indexbase = "freyasx/bank";

#define T_TEXT	1
#define T_MAIL	2
#define T_HTML	3
#define T_HTTP	4
#define T_JS	5
#define T_MBOX	6
#define T_CCODE	7

#define CH_COPYR	0xA9
static char thru8[32] = {CH_COPYR};
static int Itype = T_HTML;

#define UT_QUERY	0x0008

typedef struct {
	int	opt_v;
	int	opt_q;
	int	opt_d;
	int	opt_u;
	int	opt_a;
	int	opt_h; /* max hops */
	int	opt_urltype; /* URL types to be scanned */
	int	printIfText;
	int	NumAny;
	int	NumUrl;
	int	NumPut;
	int	MaxPut;
	int	Codes[1000];
	int	withAuthor;
	int	guessedAuthor;
	void	*UrlSed;
  const	char	*UrlMount[2]; /**/

	int	Fsize;
	int	Xtime; /* Date: transfered time */
	int	Mtime;
	int	Atime;

	FILE	*Out;
	FILE	*Descf;
	FILE	*Summf;

	MStr(	e_Url,1024);
	MStr(	e_Descr,1024);
	MStr(	e_Keywd,1024);
	MStr(	e_title,1024);
	MStr(	e_lang,128);
	MStr(	e_Heads,1024);
	MStr(	e_author,1024);
	MStr(	e_Address,1024);
	MStr(	e_Links,16*1024); /* mod-140524k 2048 -> 16k */
	MStr(	e_Location,1024);
	MStr(	e_Xuri,1024);
	MStr(	e_XRefs,1024);
	int	Ccx[64];
	int	CCXdisable;

	MStr(	e_baseDir,256);
	const char *e_baseUrlv[128]; /* base directories of "-r URL" options */
	MStr(	e_baseUrlb,128*128);
	VAddr	e_whoAmI;
} AFEnv;

static AFEnv *AFenv;
#define opt_v		AFenv->opt_v
#define opt_q		AFenv->opt_q
#define opt_d		AFenv->opt_d
#define opt_u		AFenv->opt_u
#define opt_a		AFenv->opt_a
#define opt_h		AFenv->opt_h
#define opt_urltype	AFenv->opt_urltype
#define printIfText	AFenv->printIfText
#define NumAny		AFenv->NumAny
#define NumUrl		AFenv->NumUrl
#define NumPut		AFenv->NumPut
#define MaxPut		AFenv->MaxPut
#define Codes		AFenv->Codes
#define withAuthor	AFenv->withAuthor
#define guessedAuthor	AFenv->guessedAuthor
#define UrlSed		AFenv->UrlSed
#define UrlMount	AFenv->UrlMount
#define Fsize		AFenv->Fsize
#define Xtime		AFenv->Xtime
#define Mtime		AFenv->Mtime
#define Atime		AFenv->Atime
#define Out		AFenv->Out
#define Descf		AFenv->Descf
#define Summf		AFenv->Summf
#define Url		AFenv->e_Url
#define Descr		AFenv->e_Descr
#define Keywd		AFenv->e_Keywd
#define Title		AFenv->e_title
#define Lang		AFenv->e_lang
/**/
#define Heads		AFenv->e_Heads
#define Author		AFenv->e_author
/**/
#define Address		AFenv->e_Address
#define Links		AFenv->e_Links
#define Location	AFenv->e_Location
#define XUri		AFenv->e_Xuri
/**/
#define XRefs		AFenv->e_XRefs
#define Ccx		AFenv->Ccx
#define CCXdisable	AFenv->CCXdisable
#define baseDir		AFenv->e_baseDir
#define baseUrlv	AFenv->e_baseUrlv
#define baseUrlb	AFenv->e_baseUrlb
#define whoAmI		(&AFenv->e_whoAmI)

#define MAX_TYPES	128
/*
 * screening by suffix of URL
 * this table should be loadable from any2fdif.conf
 */
static struct {
  const	char	*ext;
	int	 itype;
  const	char	*cnv;
	int	 cnt;
	int	 ixs[8];
} types[MAX_TYPES] = {
	{"",      T_HTTP}, /* undefined extensions */
	{"/",     T_HTML},
	{"/MAIL", T_MAIL},
	{"htm",   T_HTML},
	{"html",  T_HTML},
	{"shtml", T_HTML},
	{"dhtml", T_HTML},
	{"txt",   T_TEXT},
	{"cgi",   T_HTTP},
	{"asp",   T_HTTP},
	{"jsp",   T_HTTP},
	{"php",   T_HTTP},
	{"php3",  T_HTTP},
	{"fcg",   T_HTTP},
	{"exe",   T_HTTP},
	{"pl",    T_HTTP},
/*
	{"pdf",   T_TEXT},
*/
	{"pdf"},
	{"c",     T_CCODE},
	{"cc",    T_CCODE},
	{"h",     T_CCODE},
	{"xml",   T_HTML},
	{"rdf",   T_HTML},
	{"o"},
	{"a"},
	{"js"},

	{"gif"},
	{"tif"},
	{"jpg"},
	{"swf"},
	{"css"},
	{"png"},
	{"ico"},
	{"jpeg"},

	{"asx"},
	{"bmp"},
	{"curl"},
	{"dmg"},
	{"mov"},
	{"mid"},
	{"mpg"},
	{"pjpeg"},
	{"ram"},
	{"ras"},
	{"rm"},
	{"sit"},
	{"snd"},
	{"wav"},
	{"wmv"},
	{"xbm"},
	{"xpi"},
	
	{"bin"},
	{"bz2"},
	{"deb"},
	{"gz"},
	{"hqx"},
	{"img"},
	{"ipk"},
	{"iso"},
	{"lzh"},
	{"rpm"},
	{"tar"},
	{"taz"},
	{"tgz"},
	{"zip"},
	
	{"sxi"},
	{"sxw"},

	{"doc"},
	{"ecl"},
	{"md5"},
	{"ppt"},
	{"ps"},
	0
};
static void setConv(PCStr(ext),PCStr(cnv))
{	int xi;
	const char *cext;

	for( xi = 0; cext = types[xi].ext; xi++ ){
		if( strcaseeq(ext,cext) ){
			if( types[xi].itype == 0 ){
				types[xi].itype = T_TEXT;
				/* might be T_HTML or other ... */
			}
			types[xi].cnv = strdup(cnv);
			return;
		}
	}
	if( xi < MAX_TYPES ){
		types[xi].ext = ext;
		types[xi].itype = T_TEXT;
		types[xi].cnv = strdup(cnv);
	}
}
/*
static const char *getConv(PCStr(path))
*/
static const char *getConv(PCStr(path),int *itype)
{	const char *ext;
	const char *cext;
	int xi;

	*itype = 0;
	if( (ext = strrchr(path,'.')) == 0 )
		return 0;
	ext++;

	for( xi = 0; cext = types[xi].ext; xi++ ){
		if( strcaseeq(ext,cext) ){
			*itype = types[xi].itype;
			return types[xi].cnv;
		}
	}
	return 0;
}

static int doindextype(PCStr(url),int *ixp)
{	int xi;
	const char *ext;
	const char *cext;
	const char *dp;
	const char *qp;
	const char *cp;
	char cch;

	if( cp = strtailstr(url,"/@") ){
		cch = cp[1];
		((char*)cp)[1] = 0;
	}else
	if( cp = strtailstr(url,"/=") ){
		cch = cp[1];
		((char*)cp)[1] = 0;
	}
	if( qp = strchr(url,'?') )
		truncVStr(qp);

	ext = 0;
	if( strtailchr(url) == '/' )
		ext = "/"; 
	else
	if( dp = strrchr(url,'/') ){
		if( dp = strrchr(dp+1,'.') )
			ext = dp + 1;
		else	ext = "";
	}

	if( ext == 0 ){
		xi = 0;
		goto EXIT;
	}
	for( xi = 0; cext = types[xi].ext; xi++ ){
		if( *cext && strcaseeq(ext,cext) )
			goto EXIT;
	}
	xi = 0;
EXIT:
/*
if( xi == 0 && *ext != 0 ) fprintf(stderr,"+++ [%s] %s\n",ext,url);
*/
	if( cp ) ((char*)cp)[1] = cch; /**/
	if( qp ) *(char*)qp = '?'; /**/
	types[xi].cnt += 1;
	*ixp = xi;
	return types[xi].itype;
}

int m17n_Active();
static int CCX_nonASCII;
static int CCX_ASCII;
int CCXpending(CCXP ccx);
static MimeConv *Mcv;
static void setupM17N(MimeConv *Mcv,void *buf,int siz){
	M17N m17n;

	m17n = m17n_ccx_new(0,0,buf,siz);
	if( m17n == 0 )
		return;

	if( Mcv->c_icode && m17n_known_code(Mcv->c_icode) )
	if( Mcv->c_ocode && m17n_known_code(Mcv->c_ocode) )
	if( m17n_ccx_init(m17n,Mcv->c_icode,Mcv->c_ocode) == 0 ){
		Mcv->c_m17n = m17n;
	}
}
static int guessCharcode(PCStr(text),PVStr(charset)){
	int ccxb[64];
	IStr(buf,16*1024);
	CCXP ccx = (CCXP)ccxb;
	const char *gcode;

	CCXcreate("*","guess",ccx);
	CCXexec(ccx,text,strlen(text),AVStr(buf),sizeof(buf));
	gcode = CCXident(ccx);
	strcpy(charset,gcode);
	return 0;
}
/*
static int doCCX(CCXP ccx,PCStr(is),int il,PVStr(os),int oz){
*/
static int doCCX(MimeConv *Mcv,CCXP ccx,PCStr(is),int il,PVStr(os),int oz,int force){
	int ol;
	const char *sp;
	char ch;
	int ii;
	sp = is;

	if( Mcv == 0 ){
		/* makeDigest() called from nntpgw.c */
		goto CCXONLY;
	}

	if( !force )
	if( CCXdisable ){
		strcpy(os,is);
		return il;
	}
	if( Mcv && Mcv->c_m17n ){
		ol = m17n_ccx_string(Mcv->c_m17n,is,il,(char*)os,oz);
		if( 0 < ol ){
			if( lCHARSET() )
			fprintf(stderr,"##M17N## %d <= %d [%s]<=[%s]\n",
				ol,il,Mcv->c_ocode,Mcv->c_icode);
			setVStrEnd(os,ol);
			return ol;
		}
	}
	if( m17n_Active() ){
		/* with M17N=on to be applied, don't CCX dup.  */
		if( Mcv->c_icode == 0 || Mcv->c_icode[0] == 0 ){
			strcpy(os,is);
			return il;
		}
	}

CCXONLY:
	if( CCXpending(ccx) ){
		CCX_nonASCII += il;
		return CCXexec(ccx,is,il,BVStr(os),oz);
	}
	for( ii = 0; ii < il; ii++ ){
		ch = *sp++;
		if( ch == 033 || ch & 0x80 ){
			CCX_nonASCII += il;
			ol = CCXexec(ccx,is,il,BVStr(os),oz);
			if( Mcv && lCHARSET() ){
				fprintf(stderr,"##CCX## %d <= %d [%s]<=[%s]\n",
					ol,il,Mcv->c_ocode,Mcv->c_icode);
			}
			return ol;
		}
	}
	CCX_ASCII += il;
	strcpy(os,is);
	return il;
}
/*
#define CCXexec(ccx,is,il,os,oz) doCCX(ccx,is,il,os,oz)
*/
#define CCXexec(ccx,is,il,os,oz) doCCX(Mcv,ccx,is,il,os,oz,0)

#define E_OK		0
#define E_EOF		1
#define E_CTRL		2
#define E_ENCODED	3
#define E_NONTEXT	4
#define E_BINARY	5
#define E_EMPTY		6
#define E_DIR		7

static void dumptypes(){
	int xi,cnt;
	const char *cext;
	int i,total;

	total = 0;
	for( xi = 0; cext = types[xi].ext; xi++ ){
		total += types[xi].cnt;
	}

 fprintf(stderr,"suffix  count  ratio indexed ctrl ntxt encd  bin null  dir\n");
 fprintf(stderr,"------ ------ ------ ------- ---- ---- ---- ---- ---- ----\n");
	for( xi = 0; cext = types[xi].ext; xi++ ){
		if( cnt = types[xi].cnt ){
			fprintf(stderr,"%-6s %6d %5.1f%%",
				cext,cnt,(cnt*100)/(float)total);
			if( opt_a || types[xi].itype ){
				fprintf(stderr," %7d %4d %4d %4d %4d %4d %4d",
					types[xi].ixs[E_OK],
					types[xi].ixs[E_CTRL],
					types[xi].ixs[E_NONTEXT],
					types[xi].ixs[E_ENCODED],
					types[xi].ixs[E_BINARY],
					types[xi].ixs[E_EMPTY]+
					types[xi].ixs[E_EOF],
					types[xi].ixs[E_DIR]
					);
			}
			fprintf(stderr,"\n");
		}
	}

	if( Codes[200] || Codes[302] ){
		fprintf(stderr,"\n");
		fprintf(stderr,"  code  count\n");
		fprintf(stderr,"------ ------\n");
		for(i = 0; i < 1000; i++ ){
			if( Codes[i] ){
				fprintf(stderr,"%6d %6d\n",i,Codes[i]);
			}
		}
		fprintf(stderr,"\n");
	}

	fprintf(stderr,"Indexed: %d (with Author: %d+%d)\n",NumPut,
		withAuthor,guessedAuthor);
	fprintf(stderr,"in-ASCII: %d, non-ASCII: %d\n",CCX_ASCII,CCX_nonASCII);
}

static void Lap(int force,int outlen,PCStr(fmt),...);

typedef struct {
	FILE   *flist;
	int	flen;
	int	optr;
  const	char   *strip;
  const	char   *pre;
  const	char   *conv;
	FILE   *out;
	FILE   *descf;
} Opts;
static int optxN;
static const char *optxv[32];
static const char *optx; /* URLs to be excluded */
static const char *optX; /* symbolic link or link to another site */

/* new-140728j, '-y string' opttion */
static int opt_yN;
static const char *opt_yV[16]; /* pattern must be includede by URL */

static scanDirFunc scanfile(PCStr(file),PCStr(dir),Opts *opts,int optr)
{	CStr(path,1024);

	if( optr < 0 )
		return -1;

	if( strcmp(file,".") == 0 || strcmp(file,"..") == 0 )
		return 0;

	sprintf(path,"%s/%s",dir,file);
	if( fileIsdir(path) ){
		Scandir(path,scanDirCall scanfile,path,opts,optr-1);
	}else{
		fprintf(opts->flist,"%s\n",path);
		opts->flen++;
		if( opts->flen % 100 == 0 ){
			Lap(0,0,"%d files found\n",opts->flen);
		}
	}
	return 0;
}
static void scandir(PCStr(url),int optr,PCStr(strip),PCStr(pre),PCStr(conv),FILE *out,FILE *descf)
{	Opts opts;

	if( optr <= 0 ){
		return;
	}
	Lap(1,0,"scanning directory [%s]\n",url);
	opts.flist = tmpfile();
	opts.flen = 0;
	opts.optr = optr;
	opts.strip = strip;
	opts.pre = pre;
	opts.conv = conv;
	opts.out = out;
	opts.descf = descf;

	Scandir(url,scanDirCall scanfile,url,&opts,optr);
	Lap(1,0,"%d files under [%s]\n",opts.flen,url);
	Start = Time();

	fflush(opts.flist);
	fseek(opts.flist,0,0);
	scanUrls(opts.flist,optr-1,strip,pre,conv,out,descf);
	fclose(opts.flist);
}

typedef struct {
	char   *u_url;
	int	u_crc;
 unsigned char	u_done;
 unsigned short	u_hops;
	int	u_referer;
} UrlScan;
static UrlScan *Urls;
static int Urlx;
static int Urli;

static int findUrl(PCStr(url),int *crcp){
	int ui;
	int crc;
	int ulen;

	ulen = strlen(url);
	if( strtailchr(url) == '/' ){
		/* unify "/upath" and "/upath/" not to create dup. index.
		 * maybe it should be indexed with "/upath" always...
		 */
		ulen--;
	}
	crc = strCRC32(url,ulen);
	if( crcp ) *crcp = crc;
	for( ui = 0; ui < Urli; ui++ ){
		if( Urls[ui].u_crc == crc )
		if( strncmp(Urls[ui].u_url,url,ulen) == 0 ){
			return ui;
		}
	}
	return -1;
}

#define DONE_NOTYET	0x00
#define DONE_BASE	0x01
#define DONE_SCANNED	0x02
#define DONE_REDIRECT	0x03
#define DONE_REDIRECTED	0x04
#define DONE_EXCLUDE1	0x05
#define DONE_EXCLUDES	0x06
#define DONE_EXCTYPES	0x07
#define DONE_INDEXED	0x10

static int isdoneUrl(PCStr(url)){
	int uix;

	if( 0 <= (uix = findUrl(url,0)) ){
		if( Urls[uix].u_done ){
			return Urls[uix].u_done;
		}
	}
	return 0;
}
static int setdoneUrl(int uix,PCStr(url),unsigned int done){
	if( uix < 0 ){
		uix = findUrl(url,0);
	}
	if( 0 <= uix && uix < Urli ){
		if( Urls[uix].u_done == DONE_INDEXED ){
fprintf(stderr,"--- [%d] don't setdone %X -> %X %s\n",uix,Urls[uix].u_done,done,Urls[uix].u_url);
		}else{
			Urls[uix].u_done = done;
		}
		return 1;
	}
	return -1;
}
static int getHops(int uix,PCStr(url)){
	if( uix < 0 ){
		uix = findUrl(url,0);
	}
	if( 0 <= uix && uix < Urli ){
		return Urls[uix].u_hops;
	}
	return 0;
}
static int undoneUrls(PCStr(basedir)){
	int undone = 0;
	int blen = strlen(basedir);
	int ui;

	for( ui = 0; ui < Urli; ui++ ){
		if( strncmp(Urls[ui].u_url,basedir,blen) == 0 ){
fprintf(stderr,"--- undone[%d] %s %s\n",ui,basedir,Urls[ui].u_url);
			undone++;
			Urls[ui].u_done = 0;
		}
	}
	return undone;
}

/*
static void addUrl(PCStr(base),PCStr(url),int done)
*/
static int addUrl(int optr,int bhops,int basei,PCStr(base),PCStr(url),int done)
{	int i,crc;
	int uix;
	int ix;
	int urli;
	int hops;
	int maxhops;

	if( !doindextype(url,&ix) ){
		if( opt_a == 0 )
		{
			return -1;
			/*
			return;
			*/
		}
	}
	if( !VA_url_permitted(whoAmI,NULL,url) ){
		return -1;
	}

	if( 0 <= (uix = findUrl(url,&crc)) ){
		if( Urls[uix].u_done == 0 ){
			setdoneUrl(uix,url,done);
		}
		return uix;
	}
	if( Urlx <= Urli ){
		if( Urlx == 0 ){
			Urlx = 1024;
			Urls = (UrlScan*)malloc(Urlx*sizeof(Url));
		}else{
			Urlx = Urlx * 2;
			Urls = (UrlScan*)realloc(Urls,Urlx*sizeof(Url));
		}
	}

/* so tentative */{
	urli = Urli;
	if( 0 <= bhops ){
		hops = bhops;
	}else
	if( basei == 0 ){
		hops = 0;
	}else
	if( 0 < basei ){
		hops = Urls[basei].u_hops + 1;
	}else{
		hops = 2;
	}
	maxhops = opt_h;
	if( maxhops < hops ){
		/*
		fprintf(stderr,"TOO-FAR[%d] %d -> %s\n",hops,basei,url);
		*/
		return -1;
	}
	if( opt_v ){
		printf(" -> %d[%d]%d %s\n",basei,hops,Urli,url);
	}
	if( basei < 0 )
		Urls[Urli].u_referer = 1;
	else	Urls[Urli].u_referer = basei+1;
	Urls[Urli].u_hops = hops;
}

	Urls[Urli].u_url = strdup(url);
	Urls[Urli].u_crc = crc;
	Urls[Urli].u_done = done;
	Urli++;
	return urli;
}
/*
char *getnextlink(PVStr(url),int size)
char *getnextlink(PVStr(url),int size,const char **referer)
*/
char *getnextlink(PVStr(url),int size,const char **referer,int *uixp)
{	int i;
	int ref;

	for( i = 0; i < Urli; i++ ){
		if( Urls[i].u_done == DONE_NOTYET ){
			Urls[i].u_done = DONE_SCANNED;
			*uixp = i;
			QStrncpy(url,Urls[i].u_url,size);
			if( ref = Urls[i].u_referer ){
				*referer = Urls[ref-1].u_url;
			}else	*referer = "";
if( 0 < opt_h && !opt_q )
fprintf(stderr,"--- nextlink[%d] %d<-%d %s\n",Urls[i].u_hops,i,ref,*referer);

			return (char*)url;
		}
	}
	*uixp = -1;
	return NULL;
}
const char *getURLgetURL();
static void normalizeURL(PVStr(url),int siz)
{	CStr(proto,64);
	CStr(login,MaxHostNameLen);
	CStr(upath,1024);
	CStr(nupath,1024);
	const char *dp;

	decomp_absurl(url,AVStr(proto),AVStr(login),AVStr(upath),sizeof(upath));
	if( dp = strrchr(login,':') ){
		if( atoi(dp+1) == serviceport(proto) )
			truncVStr(dp);
	}
	if( dp = strchr(upath,'#') )
		truncVStr(dp);
	nupath[0] = 0;
	chdir_cwd(AVStr(nupath),upath,1);

	if( strtailchr(url) == '/' && strtailchr(nupath) != '/' )
		strcat(nupath,"/");

	/* this should be done in chdir_cwd() ... */ {
		refQStr(dp,upath); /**/
		const char *sp;
		char ch;
		char pch;
		dp = upath;
		pch = '/';
		for( sp = nupath; (ch = *sp); sp++ ){
			if( ch == '\\' )
				ch = '/';
			if( ch == '/' ){
				if( pch == '/' )
					continue;
			}
			setVStrPtrInc(dp,ch);
			pch = ch;
		}
		setVStrEnd(dp,0);
	}

	sprintf(url,"%s://%s/%s",proto,login,upath);
}
static int isFullUrl(PCStr(url));
int makeFullUrl(PCStr(baseurl),PVStr(url)){
	IStr(nurl,8*1024);
	IStr(proto,128);
	IStr(site,256);
	IStr(upath,8*1024);
	refQStr(up,upath);
	IStr(nupath,8*1024);
	const char *nup = nupath;
	IStr(rem,8*1024);

	if( isFullUrl(url) ){
		strcpy(nurl,url);
		normalizeURL(AVStr(nurl),sizeof(nurl));
		if( !streq(url,nurl) ){
 fprintf(stderr,"-- makeFullURL normalized [%s] <= [%s]\n",nurl,url);
			strcpy(url,nurl);
		}
		return 0;
	}

	/* normalilze url-path
	 * ending '/' is removed to be unified with the URL without '/'
	 */
	strcpy(nupath,"");
	chdir_cwd(AVStr(nupath),url,0);

	if( !streq(nupath,url) ){
		if( strneq(url,nupath,strlen(nupath))
		 && streq(url+strlen(nupath),"/") ){
			/* ending '/' is removed normally */
		}else{
 fprintf(stderr,"-- makeFullURL normalized [%s] <- [%s]\n",nupath,url);
		}
		strcpy(url,nupath);
	}
	decomp_absurl(baseurl,AVStr(proto),AVStr(site),AVStr(upath),sizeof(upath));
	if( *url == '/' ){
		sprintf(nurl,"%s://%s%s",proto,site,url);
		strcpy(url,nurl);
 if(0)
 fprintf(stderr,"-- makeFullURL from absolute %s\n",url);
		return 1;
	}
	if( up = strrchr(upath,'/') )
		setVStrEnd(up,0);

	strcpy(nupath,upath);
	chdir_cwd(AVStr(nupath),url,0);
	nup = nupath;
	if( *nup == '/' )
		nup++;

	sprintf(url,"%s://%s/%s",proto,site,nup);
 if(0)
  fprintf(stderr,"-- makeFullURL from relative %s\n",url);
	return 2;
}

static void getbase(PCStr(base),PVStr(basedir),int size)
{	CStr(proto,256);
	CStr(host,MaxHostNameLen);
	CStr(port,256);
	const char *dp;

	linescanX(base,AVStr(basedir),size);
	if( dp = strstr(basedir,"//") ){
		const char *tp;
		dp += 2;
		if( tp = strpbrk(dp,"?") )
			truncVStr(tp);
		if( tp = strchr(dp,'/') )
		{
			dp = tp + 1;
		if( tp = strrchr(dp,'/') )
			((char*)tp)[1] = 0;
			else{
				truncVStr(dp);
			}
		}else{
			strcat(basedir,"/");
		}
	}
}
static int isFullUrl(PCStr(url)){
	if( strneq(url,"http:",5) ) return 1;
	if( strneq(url,"https:",6) ) return 2;
	return 0;
}
static int file2basev(FILE *in,int ac,const char *av[],PVStr(ab),int az){
	int off = ftell(in);
	int an = 0;
	refQStr(ap,ab);
	const char *ax = ab + (az - 1);
	IStr(line,1024);
	refQStr(lp,line);

	while( fgets(line,sizeof(line),in) != NULL ){
		if( lp = strpbrk(line,"\r\n") )
			setVStrEnd(lp,0);
		if( isFullUrl(line) ){
			av[an++] = ap;
			getbase(line,AVStr(ap),(ax-ap)-1);
			ap += strlen(ap) + 1;
		}
	}
	av[an] = 0;
	fseek(in,off,0);
	return an;
}
static int headmatch(const char *headv[],const char *str){
	int hlen;
	int hi;

	for( hi = 0; headv[hi]; hi++ ){
		hlen = strlen(headv[hi]);
		if( strncmp(headv[hi],str,hlen) == 0 ){
			return 1;
		}
	}
	return 0;
}

typedef int AUFunc(void *ctx,PCStr(base),PCStr(url));
int HTML_scanLinks(FILE *in,int optr,PCStr(abase),AUFunc aufunc,void *ctx);
static int scanlinks(FILE *in,int optr,PCStr(abase))
{
	return HTML_scanLinks(in,optr,abase,0,0);
}
int HTML_scanLinks(FILE *in,int optr,PCStr(abase),AUFunc aufunc,void *ctx)
{	CStr(base,1024);
	CStr(line,1024);
	CStr(rem,1024);
	CStr(ctype,1024);
	const char *np;
	const char *tag;
	const char *attr;
	CStr(tagn,32);
	CStr(attrn,32);
	CStr(url,1024);
	CStr(proto,256);
	CStr(host,MaxHostNameLen);
	CStr(port,256);
	const char *dp;
	CStr(baseserv,1024);
	CStr(basedir,1024);
	int bhops = -1;
	int basei;

	strcpy(base,abase);
    if( aufunc != 0 ){
	basei = 0;
    }else{
	if( getURLgetURL() )
		strcpy(base,getURLgetURL());
	normalizeURL(AVStr(base),sizeof(base));
	basei = addUrl(optr,0,-1,abase,base,DONE_BASE);
    }

	if( fgets(line,sizeof(line),in) == NULL ){
/*
		fprintf(stderr,"## scanserv ... empty %s %s\n",abase,base);
*/
		return 0;
	}
	if( strncmp(line,"HTTP/",5) != 0 ){
/*
		fprintf(stderr,"## scanserv ... non-HTTP\n");
*/
		return 0;
	}
	ctype[0] = 0;
	for(;;){
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		if( strncmp(line,"Content-Type:",13) == 0 ){
			dp = line+13;
			while(isspace(*dp))
				dp++;
			wordscanY(dp,AVStr(ctype),sizeof(ctype),"^; \t\r\n");
		}
		if( *line == '\r' || *line == '\n' )
			break;
	}
	if( strncmp(ctype,"text/html",9) != 0 ){
/*
		fprintf(stderr,"## scanserv ... non-HTML [%s]%s\n",ctype,base);
*/
		return 0;
	}

	{
		scan_protositeport(base,AVStr(proto),AVStr(host),AVStr(port));
		sprintf(baseserv,"%s://%s",proto,host);
		if( *port ){
			Xsprintf(TVStr(baseserv),":%s",port);
		}
		getbase(base,AVStr(basedir),sizeof(basedir));
	}

	rem[0] = 0;
	for(;;){
		if( fgets(line,sizeof(line),in) == NULL ){
			break;
		}
		np = line;
		for(;;){
			bhops = -1;
			tag = 0;
			attr = 0;
			np = html_nextTagAttrX(NULL,np,ctype,AVStr(rem),&tag,&attr,NULL);
			if( np == 0 )
				break;
			if( tag )
				wordScan(tag,tagn);
			else	strcpy(tagn,"?");
			if( attr )
				wordscanY(attr,AVStr(attrn),sizeof(attrn),"^=");
			else	strcpy(attrn,"?");

			if( strncaseeq(tagn,"<A",2)
			 && strncaseeq(attrn,"HREF",4) ){
			}else
			if( strncaseeq(tagn,"<FRAME",6)
			 && strncaseeq(attrn,"SRC",3) ){
			}else{
				continue;
			}

			if( *np == '\\' ){
				continue;
			}
			wordscanY(np,AVStr(url),sizeof(url),"^\"\'> \t\r\n");
			if( dp = strchr(url,'#') )
				truncVStr(dp);

			if( *url == 0 ){
				continue;
			}
			if( strchr(url,'?') ){
				if( (opt_urltype & UT_QUERY) != 0 ){
					/*
					fprintf(stderr,"-- index script too: %s\n",url);
					*/
				}else
				continue;
			}
			if( strncasecmp(url,"javascript:",11) == 0 ){
				continue;
			}
			if( !isFullURL(url) ){
				if( *url == '/' ){
					Strins(AVStr(url),baseserv);
				}else{
					Strins(AVStr(url),basedir);
				}
			} 

			normalizeURL(AVStr(url),sizeof(url));
			if( aufunc != 0 ){
			}else
			if( optX != 0 ){
				if( strstr(url,optX) == 0 ){
					continue;
				}
			}else{
				if( headmatch(baseUrlv,url) ){
				 	/* mod-140703a it's under some baseDirs' realm.
					 * setting bhops=0 makes the URL be indexed
					 * regardless of the value of opt_h (maxhops)
					 */
					bhops = 0;
				}else
				if( strncmp(url,baseDir,strlen(baseDir))!=0 ){
					/* become useless by the above condition */
					/* not under the realm of current baseDir */
					if( opt_h <= 0 )
					continue;
				/* to be filtered in addUrl by hops */
				}
				else{
					bhops = 0;
				}
			}

			/*
			addUrl(abase,url,0);
			*/
			if( aufunc != 0 ){
				(*aufunc)(ctx,abase,url);
			}else
			addUrl(optr,bhops,basei,abase,url,DONE_NOTYET);

/*
			fprintf(stderr,"## %s %s=%s\n",tagn,attrn,url,line);
			usleep(100*1000);
*/
		}
	}
	return 0;
}

static int totallen;
int any2fdif(PCStr(pre),PCStr(strip),PCStr(apath),int mi,PCStr(sub),PCStr(conv),FILE *ain,FILE *out,FILE *descf,int *itypep);
void xany2fdif(int ix,PCStr(pre),PCStr(strip),PCStr(url),PCStr(xconv),FILE *in,FILE *out,FILE *descf,int *itypep)
{	int mi;
	int ixs;
	CStr(sub,1024);
	int poff = 0;
	int noff;
	int sItype = Itype;

	for( mi = 1;; mi++ ){
		sprintf(sub,"?n=%d&off=%d",mi,iftell(in));
		ixs = any2fdif(pre,strip,url,mi,sub,xconv,in,out,descf,itypep);

		noff = ftell(in);
		totallen += (noff - poff);
		poff = noff;
		Lap(0,totallen,0);

		if( ix == 0 && (*itypep == T_MAIL || *itypep == T_MBOX) ){
			types[0].cnt -= 1;
			ix = 2;
			types[ix].cnt += 1;
		}
		types[ix].ixs[ixs] += 1;

		if( *itypep == T_MBOX && !feof(in) ){
			Itype = T_MBOX;
			continue;
		}
		break;
	}
	Itype = sItype;
}

void clear_DGreq(DGC*ctx);
void HTTP_setReferer(DGC*ctx,PCStr(proto),PCStr(host),int port,PCStr(req),Referer *referer,PVStr(refbuf));

void setReferer(DGC*ctx,PCStr(url)){
	IStr(base,1024);
	IStr(proto,128);
	IStr(login,256);
	IStr(upath,1024);
	IStr(host,256);
	int port;
	Referer referer;
	IStr(req,2*1024);
	IStr(refbuf,2*1024);

	strcpy(base,url);
	normalizeURL(AVStr(base),sizeof(base));
	decomp_absurl(base,AVStr(proto),AVStr(login),AVStr(upath),sizeof(upath));
	port = scan_hostport1pX(proto,login,AVStr(host),sizeof(host));

	bzero(&referer,sizeof(Referer));
	sprintf(req,"GET %s HTTP/1.0\r\n",url);
	HTTP_setReferer(ctx,proto,host,port,req,&referer,AVStr(refbuf));
}
static void scanUrls(FILE *flist,int optr,PCStr(strip),PCStr(pre),PCStr(conv),FILE *out,FILE *descf)
{	CStr(url,1024);
	const char *dp;
	CStr(buff,0x10000);
	FILE *in;
	int size,octime,omtime,oatime;
	int ix;
	int itype;
	const char *fgot;
	const char *referer;
	const char *gotURL;
	int uix; /* index in Urls[] of current url */
	DGC *ctx = MainConn();

	/* letting each URL in "filst" be a basedir for other URLs in
	 * the same "flist" too
	 */
	file2basev(flist,elnumof(baseUrlv),baseUrlv,
		AVStr(baseUrlb),sizeof(baseUrlb));

	for(;;){
		referer = "";
		fgot = getnextlink(AVStr(url),sizeof(url),&referer,&uix);

		clear_DGreq(ctx);
		setReferer(ctx,referer);

		if( fgot == NULL ){
		fgot = fgets(url,sizeof(url),flist);
			if( fgot != NULL ){
				int uix0;
				if( dp = strpbrk(url,"\r\n") )
					truncVStr(dp);
				getbase(url,AVStr(baseDir),sizeof(baseDir));
				uix0 = findUrl(url,0);
				uix = addUrl(optr,0,0,url,url,DONE_SCANNED);
				if( isFullUrl(url) ){
					fprintf(stderr,"Root: %s (%d <- %d)\n",url,uix,uix0);
					fprintf(stderr,"Base: %s\n",baseDir);
				}
				/*
				undoneUrls(baseDir);
				*/
			}
		}
		Lap(fgot==NULL,totallen,0);

		if( fgot == NULL )
			break;
		if( dp = strpbrk(url,"\r\n") )
			truncVStr(dp);
		++NumAny;

		printIfText = 0;
		if( optx ){
			if( 1 < optxN ){
				int xi;
				const char *found = 0;
				for( xi = 0; xi < optxN; xi++ ){
					if( strstr(url,optxv[xi]) ){
						found = optxv[xi];
						break;
					}
				}
				if( found ){
					setdoneUrl(uix,url,DONE_EXCLUDE1);
					continue;
				}
			}else
			if( strstr(url,optx) ){
				setdoneUrl(uix,url,DONE_EXCLUDES);
				continue;
			}
		}
		if( 1 <= opt_yN ){ /* new-140728 */
			int yi;
			const char *found = 0;
			for( yi = 0; yi < opt_yN; yi++ ){
				if( strstr(url,opt_yV[yi]) ){
					found = opt_yV[yi];
					break;
				}
			}
			if( !found ){
				setdoneUrl(uix,url,DONE_EXCLUDE1);
				continue;
			}
		}
		if( !doindextype(url,&ix) ){
			if( opt_a == 0 )
			{
				setdoneUrl(uix,url,DONE_EXCTYPES);
				continue;
			}
			else	printIfText = 1;
		}
		if( !opt_q )
		{
			static int N;
			Lap(1,0,"%4d %s\n",++N,url);
		}

		in = NULL;
		if( isFullURL(url) ){
			size = 0;
			octime = 0;
			omtime = 0;
			oatime = 0;

			normalizeURL(AVStr(url),sizeof(url));
			in = VA_URLget(ctx,whoAmI,url,0,NULL);
			if( (gotURL = getURLgetURL()) && !streq(url,gotURL) ){ /* mod-140524g */
				/* set redirected and normalized url for xany2fdif() bellow */
				IStr(xurl,2*1024);
				strcpy(xurl,gotURL);
				int xuix; /* uix of xurl */

				normalizeURL(AVStr(xurl),sizeof(xurl));
				if( !streq(url,xurl) ){
					sv1log("---got redirected [%s][%s]\n",url,gotURL);
					sv1log("---< [%s]\n",url);
					sv1log("---> [%s]\n",gotURL);
					sv1log("---N [%s]\n",xurl);

					setdoneUrl(uix,url,DONE_REDIRECT);
					/* xuix == uxi when didirected form /dir/ to /dir/
					 * beause of normalized URL search in Urls[]
					 */
					if( (xuix = findUrl(xurl,0)) < 0 ){
						int hops = getHops(uix,url);
						/* should check if xurl is out of realm,
						 * should apply filters in HTML_scanLinks()
						 */
						xuix = addUrl(optr,hops,-1,baseDir,xurl,DONE_REDIRECTED);
					}
					setdoneUrl(xuix,xurl,DONE_REDIRECTED);

					/* make index by the redirected & normalized URL */
					strcpy(url,xurl);
					uix = xuix;
				}
			}
			if( in != NULL && !feof(in) ){
				size = file_size(fileno(in));
				fseek(in,0,0);
				itype = T_HTTP;
			}
		}else{
			if( fileIsdir(url) ){
				scandir(url,optr,strip,pre,conv,out,descf);
			}
		    if( File_sizetime(url,&size,&octime,&omtime,&oatime)==0 )
			in = fopen(url,"r");
		}
		if( in != NULL ){
			int code;
			int sItype = Itype;
			const char *xconv;
			Fsize = size;
			Mtime = omtime;
			Atime = oatime;
			itype = 0;

			/*
			xconv = getConv(url);
			*/
			xconv = getConv(url,&itype);
			if( Itype == T_HTML /*default*/ )
			if( itype != 0 )
				Itype = itype;
			if( xconv == 0 )
				xconv = conv;

			if( isdoneUrl(url) == DONE_INDEXED ){
			}else{
			xany2fdif(ix,pre,strip,url,xconv,in,out,descf,&itype);
				setdoneUrl(uix,url,DONE_INDEXED);
			}

			/* fix-140702d 
			 * must rescan links of the page bellow, possibly in
			 * diffent contexts (by multiple "-r http://root-URL")
			 */
			Itype = sItype;
			if( isFullURL(url) && 0 < optr ){
				fseek(in,0,0);
				clearerr(in);
				scanlinks(in,optr,url);
			}

			fclose(in);
			code = set_utimes(url,oatime,omtime);
		}

		if( MaxPut && MaxPut <= NumPut ){
			dumptypes();
			exit(0);
		}

	}
}

static void makedir(PCStr(dir))
{
	if( File_is(dir) ){
		if( File_isreg(dir) ){
			fprintf(stderr,"Is flat file: %s\n",dir);
			exit(-1);
		}
	}else{
		if( mkdir(dir,0750) != 0 ){
			fprintf(stderr,"Can't create: %s\n",dir);
			exit(-1);
		}
	}
}
static void scanFilelist(int outbase,PCStr(outname),PCStr(outmode),PCStr(strip),PCStr(pre),PCStr(conv),FILE *flist,int optr)
{	CStr(outdir,1024);
	CStr(path,1024);
	const char *dp;
	const char *dbname;
	CStr(outnameb,1024);
	const char *env;
	CStr(base,1024);

	if( strcmp(outname,"-") == 0 ){
		Out = stdout;
	}else{
		if( outbase || strchr(outname,'/') == 0 ){
			if( fileIsdir("bank") ){
				sprintf(base,"bank/%s/",outname);
				outname = base;
			}else
			if( env = getenv("FSXHOME") ){
				sprintf(base,"%s/bank/%s/",env,outname);
				outname = base;
			}else
			if( fileIsdir("../bank") ){
				sprintf(base,"../bank/%s/",outname);
				outname = base;
			}else{
			    sprintf(base,"%s/%s",getenv("HOME"),indexbase);
			    if( fileIsdir(base) ){
				Xsprintf(TVStr(base),"/%s/",outname);
				outname = base;
			    }
			}
		}
		if( strtailchr(outname) == '/' ){
			strcpy(outdir,outname);
			setVStrEnd(outdir,strlen(outdir)-1);
			makedir(outdir);
			if( dp = strrchr(outdir,'/') ){
				dbname = dp+1;
			}else	dbname = outdir;
			sprintf(outnameb,"%s/%s",outdir,dbname);
			outname = outnameb;
		}
		if( !opt_u ){
			sprintf(path,"%s.fdif",outname);
			Out = fopen(path,outmode);
			fprintf(stderr,"FDIF file: %s\n",path);

			sprintf(path,"%s.desc",outname);
			Descf = fopen(path,outmode);
			fprintf(stderr,"Desc file: %s\n",path);

			sprintf(path,"%s.summ",outname);
			Summf = fopen(path,outmode);
			fprintf(stderr,"Summary file: %s\n",path);
		}
	}
	if( opt_u ){
		updateSrt(outname,strip,pre);
		return;
	}
	if( Out == NULL ){
		fprintf(stderr,"Error: %s\n",outname);
		exit(-1);
	}
	setnamedtmpbase(outname);
	scanUrls(flist,optr,strip,pre,conv,Out,Descf);
}
void updateSrt(PCStr(base),PCStr(strip),PCStr(pre))
{	CStr(line,1024);
	CStr(path,1024);
	int off,size,mtime,atime,crc,nsize,nmtime,natime;
	int pi;
	FILE *summf;
	FILE *atimef;
	int plen = strlen(pre);
	int slen = strlen(strip);

	sprintf(path,"%s.sum",base);
	summf = fopen(path,"r");
	fprintf(stderr,"Summary file: %X %s\n",p2i(summf),path);
	if(summf == NULL){
		sprintf(path,"%s.summ",base);
		summf = fopen(path,"r");
		fprintf(stderr,"Summary file: %X %s\n",p2i(summf),path);
		if(summf == NULL){
			return;
		}
	}

	sprintf(path,"%s.atime.srt",base);
	atimef = fopen(path,"w");
	fprintf(stderr,"Atime file: %X %s\n",p2i(atimef),path);
	if(atimef == NULL)
		return;

 fprintf(stderr,"+++ update sort %X(%d)  summary %X(%d/%d)\n",
p2i(atimef),iftell(atimef),p2i(summf),iftell(summf),file_size(fileno(summf)));

	for( pi = 0;; pi++ ){
		if( fgets(line,sizeof(line),summf) == NULL )
			break;
		if( Xsscanf(line,"%x %x %x %x %d %[^\r\n]",&off,&atime,&mtime,&crc,&size,AVStr(path)) != 6 )
		{
			continue;
		}
		if(*pre && strncmp(path,pre,plen) == 0 ){
			bcopy(path+plen,path,strlen(path+plen)+1);
		}
		if(*strip){
			Strins(AVStr(path),strip);
		}
		if( File_sizetime(path,&nsize,NULL,&nmtime,&natime) == 0 ){
if( opt_v )
if( natime != atime )
printf(">%d (%5d) %X %X %s\n",atime!=natime,pi,atime,natime,path);
			natime = htonl(natime);
			fwrite(&natime,1,sizeof(natime),atimef);
		}else{
 fprintf(stderr,"BAD[%s]\n",path);
			fseek(atimef,4,1);
		}
	}
	fflush(atimef);
 fprintf(stderr,"#### %d / %d\n",iftell(atimef),file_size(fileno(atimef)));
}

static void usage(int ac,const char *av[],int code)
{	const char *ver = DELEGATE_verdate();
	if( ver ){
		fprintf(stderr,"Any2fdif on %s\n",ver);
	}
 fprintf(stderr,"\n");
 fprintf(stderr,
"Usage: %s [indexname] [[-c cnv] [-s spfx] [-p ppfx] [-f listfile]]*\n",
 av[0]);
 fprintf(stderr,"\n\
Generate a 'FDIF' file to be input to FreyaSX indexer 'findex'.  It outputs\n\
to a FDIF file named 'indexname' (or to stdout by default).  It inputs\n\
documents from files listed in 'listfile' (or stdin by default), then apply\n\
filter command 'cnv' for each file (if specified), then convert it to FDIF\n\
format to be output.  The name of each document can be full URL or name of\n\
local file.  When the name is that of local file, the URL for it can be\n\
created from each file name, stripping prefix string 'spfx' (if specified),\n\
and adding prefix string 'ppfx' (if specified).\n");
 fprintf(stderr,"\nExample:\n");
 fprintf(stderr,"\
  %% find /web/data -type f -name \"*.html\" -print > webidx.list\n");
 fprintf(stderr,"\
  %% %s webidx -s /web/data/ -p http://www.my.org/ -f web.list\n",av[0]);
 fprintf(stderr,"\
  %% findex webidx\n\n");
 fprintf(stderr,"\
  (doing above in a single step)\n\
  %% %s -r /web/data -s /web/data -p http://www.my.org/ | findex webidx\n\n",
av[0]);
 fprintf(stderr,"\
  %% find /web/data | %s | findex webidx\n",av[0]);
 fprintf(stderr,"\
  %% %s -r http://www.delegate.org/freyasx | findex sx\n",av[0]);
 fprintf(stderr,"\nOptions:\n\
  indexname        output to the indexname\n\
  -f listfile      scan each file listed in the listfile\n\
  -r directory     recursively scan files under the directory\n\
  -r URL           recursively scan HTML pages under the URL\n\
  -x pattern       exclude pages of which URL include the pattern\n\
  -y pattern       exclude pages of which URL does not include the pattern\n\
  -s prefix        strip the prefix from each file-name\n\
  -p prefix        insert the prefix string to be URL\n\
  -c 'command'     preprocess command (as a shell command)\n\
  -c.ext 'command' preprocess command for files with .ext extension\n\
  -v               verbose\n\
  -q               quiet\n\
");
	exit(code);
}

extern int MIME_CONV;
extern int MIME_SPACE_ENCODING;
const char *get_CHARCODE(DGCTX);

int xrealpath(PCStr(path),PVStr(rpath),int size);

int any2fdif_main(int ac,const char *av[])
{	int ai;
	const char *a1;
	const char *outname = "default";
	const char *outmode = "w";
	int outbase = 0;
	const char *pre = "";
	const char *strip = "";
	FILE *in = stdin;
	FILE *flist = NULL;
	FILE *tmp;
	CStr(execpath,256);
	const char *env;
	int numin = 0;
	int numout = 0;
	const char *conv = 0;
	FILE *Tmp4 = 0;
	int optr = 0;
	const char *ocode;

	if( ocode = get_CHARCODE(0) ){
		ccx_outcode = ocode;
		if( lCHARSET() ){
			fprintf(stderr,"## --ocode=%s\n",ocode);
		}
	}

	/* these are disalbed in delegated.c */
	MIME_CONV = 0xFFFFFFFF; /* enable all MIME conversion */
	MIME_SPACE_ENCODING = 2; /* default encoding -- typeB */

	AFenv = (AFEnv*)calloc(1,sizeof(AFEnv));

	scan_HOSTS(0,"{_any2fdif_,localhost}/127.0.0.1");
	bzero(whoAmI,sizeof(VAddr));
	VA_setVAddr(whoAmI,"127.0.0.1",1,0);
	strcpy(whoAmI->a_name,"_any2fdif_");

	Start = Time();
	toFullpathENV("PATH",av[0],"r",AVStr(execpath),sizeof(execpath));
	env = getenv("LIBPATH");
	if( env == 0 ){
		const char *dp;
		CStr(xd,256);
		CStr(rx,256);
		CStr(libenv,1024);
		if( dp = strrchr(execpath,'/') ){
			QStrncpy(xd,execpath,dp-execpath+1);
		}else	strcpy(xd,".");
		sprintf(libenv,"LIBPATH=%s:%s/../lib:%s/../etc",xd,xd,xd);

		if( xrealpath(execpath,AVStr(rx),sizeof(rx)) ){
			if( dp = strrchr(rx,'/') )
				truncVStr(dp);
		Xsprintf(TVStr(libenv),":%s:%s/../lib:%s/../etc",
				rx,rx,rx);
		}
		putenv(strdup(libenv));
	}

	if( ac < 2 ){
		if( isatty(fileno(stdin)) )
			usage(ac,av,-1);
	}

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strcmp(a1,"-v") == 0 ){
			opt_v = 1;
		}else
		if( strncmp(a1,"-q",2) == 0 ){
			opt_q = 1;
		}else
		if( strcmp(a1,"-a") == 0 ){
			opt_a = 1;
		}else
		if( strcmp(a1,"-o") == 0 || strcmp(a1,"-a") == 0 ){
			numout++;
			if( ai+1 < ac ){
				outname = av[++ai];
				if( strcmp(a1,"-o") == 0 )
					outmode = "w";
				else	outmode = "a";
				outbase = 0;
			}
		}else
		if( strcmp(a1,"-b") == 0 ){
			if( ai+1 < ac ){
				outname = av[++ai];
				outmode = "w";
				outbase = 1;
			}
		}else
		if( strncmp(a1,"-c",2) == 0 ){
			if( ai+1 < ac ){
				if( a1[2] == '.' ){
					setConv(a1+3,av[++ai]);
				}else{
					conv = av[++ai]; 
				}
			}
		}else
		if( strncmp(a1,"-f",2) == 0 ){
			numin++;
			if( ai+1 < ac )
				++ai;
		}else
		if( strcmp(a1,"-p") == 0 ){
			if( ai+1 < ac )
				pre = av[++ai];
		}else
		if( strcmp(a1,"-e") == 0 ){
			if( ai+1 < ac ){
				struct sed_env *sed_new();
				UrlSed = sed_new();
				sed_compile((SedEnv*)UrlSed,av[++ai]);
			}
		}else
		if( strcmp(a1,"-m") == 0 ){
			/* -m "http://%S/%S/%S/%d/%d http://%S/%S/%S/%S%S" */
			if( ai+1 < ac ){
				const char *mount = av[++ai];
				CStr(pat,256);
				const char *dp = wordScan(mount,pat);
				UrlMount[0] = strdup(pat);
				wordScan(dp,pat);
				UrlMount[1] = strdup(pat);
			}
		}else
		if( strncmp(a1,"-X",2) == 0 ){
			if( ai+1 < ac )
				optX = av[++ai];
		}else
		if( strncmp(a1,"-x",2) == 0 ){
			if( ai+1 < ac )
			{
				optx = av[++ai];
				if( optxN < elnumof(optxv)-1 ){
					optxv[optxN++] = optx;
				}
			}
		}else
		if( strncmp(a1,"-y",2) == 0 ){
			const char *opt_y;
			if( ai+1 < ac )
			{
				opt_y = av[++ai];
				if( opt_yN < elnumof(opt_yV)-1 ){
					opt_yV[opt_yN++] = opt_y;
				}
			}
		}else
		if( strncmp(a1,"-r",2) == 0 ){
			/* -r[N] recursion depth N */
			if( a1[2] )
				optr = atoi(&a1[2]);
			else	optr = 16;
		}else
		if( strncmp(a1,"-h",2) == 0 ){
			opt_h = atoi(&a1[2]);
		}else
		if( strcmp(a1,"-s") == 0 ){
			if( ai+1 < ac )
				strip = av[++ai];
		}else
		if( strcmp(a1,"-u") == 0 ){
			opt_u = 1;
			outmode = "r+";
		}else
		if( strneq(a1,"--any",5) ){
			opt_urltype = 0xFFFF;
		}else
		if( strneq(a1,"--yuc",5) ){
			ccx_outcode = "y-a-b-r-EUC-JP";
		}else
		if( strneq(a1,"--utf",5) ){
			ccx_outcode = "a-b-r-UTF-8";
		}else
		if( strneq(a1,"--ocode=",8) ){
			ccx_outcode = a1+8;
		}else
		if( a1[0] == '-' && isdigit(a1[1]) ){
			MaxPut = atoi(a1+1);
		}else
		if( a1[0] != '-' && ai == 1 ){
			outname = a1;
			outmode = "w";
			outbase = 1;
		}
	}
	if(opt_u){
		scanFilelist(outbase,outname,outmode,strip,pre,conv,flist,optr);
		return 0;
	}
	if( numout == 0 ){
		if( !isatty(fileno(stdout)) ){
			outname = "-";
			outmode = "a";
			outbase = 0;
			fprintf(stderr,"+++ -o -\n");
		}
	}

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strcmp(a1,"-v") == 0 ){
		}else
		if( strncmp(a1,"-q",2) == 0 ){
			opt_q = 1;
		}else
		if( strcmp(a1,"-a") == 0 ){
		}else
		if( strcmp(a1,"-o") == 0 ){
			if( ai+1 < ac ){
				++ai;
			}
		}else
		if( strcmp(a1,"-b") == 0 ){
			if( ai+1 < ac ){
				++ai;
			}
		}else
		if( strncmp(a1,"-c",2) == 0 ){
			if( ai+1 < ac ){
				if( a1[2] == '.' ){
					++ai;
				}else{
					conv = av[++ai]; 
				}
			}
		}else
		if( strncmp(a1,"-f",2) == 0 ){
			NumUrl = 0;
			switch(a1[2]){
				case 't': Itype = T_TEXT; break;
				case 'm': Itype = T_MAIL; break;
				case 'h': Itype = T_HTML; break;
			}
			if( ai+1 < ac ){
				if( strcmp(av[++ai],"-") == 0 )
					flist = stdin;
				else	flist = fopen(av[ai],"r");
				if( flist == NULL ){
					fprintf(stderr,"Error: %s\n",av[ai]);
					exit(-1);
				}
				scanFilelist(outbase,outname,outmode,strip,pre,conv,flist,optr);
				/* should make whole flist to be used as baseDirs
				 * then apply scanFilelist() for the flist ?
				 * or the baseDirs should be local to this flist ?
				 */
			}
		}else
		if( strcmp(a1,"-p") == 0 ){
			if( ai+1 < ac )
				pre = av[++ai];
		}else
		if( strcmp(a1,"-e") == 0 ){
			if( ai+1 < ac ){
				ai++;
			}
		}else
		if( strcmp(a1,"-m") == 0 ){
			if( ai+1 < ac ){
				ai++;
			}
		}else
		if( strncmp(a1,"-X",2) == 0 ){
			if( ai+1 < ac )
				optX = av[++ai];
		}else
		if( strncmp(a1,"-x",2) == 0 ){
			if( ai+1 < ac )
				optx = av[++ai];
		}else
		if( strncmp(a1,"-y",2) == 0 ){
			if( ai+1 < ac )
				ai++;
		}else
		if( strncmp(a1,"-r",2) == 0 ){
			/* -r[N] recursion depth N */
			if( a1[2] )
				optr = atoi(&a1[2]);
			else	optr = 16;
		}else
		if( strncmp(a1,"-h",2) == 0 ){
			opt_h = atoi(&a1[2]);
		}else
		if( strcmp(a1,"-s") == 0 ){
			if( ai+1 < ac )
				strip = av[++ai];
		}else
		if( a1[0] == '-' ){
		}else{
			if( ai == 1 ){
				/* regard 1st arg as -b arg */
				if( outbase == 0 ){
					fprintf(stderr,"+++ -b %s\n",a1);
					outname = a1;
					outmode = "w";
					outbase = 1;
				}
			}else{
				/* to be FILE *flist */
				if( Tmp4 == 0 )
					Tmp4 = getTmp(TMP4);
				fprintf(Tmp4,"%s\n",a1);
			}
		}
	}
	if( numin == 0 ){
		if( !isatty(fileno(stdin)) ){
			fprintf(stderr,"+++ -f -\n");
			flist = stdin;
			scanFilelist(outbase,outname,outmode,strip,pre,conv,flist,optr);
		}
	}
	if( Tmp4 != 0 ){
		fflushTmp(Tmp4);
		scanFilelist(outbase,outname,outmode,strip,pre,conv,Tmp4,optr);
	}
	dumptypes();
	removenamedtmpfiles();
	return 0;
}

typedef struct {
	int	crc;
	int	len;
} CRC;
static void addCRC(CRC *crc,PCStr(str),int len)
{
	crc->crc = strCRC32add(crc->crc,str,len);
	crc->len += len;
}

static int decuent(PCStr(uent),PVStr(utf8)){
	int len;
	int uch;
	unsigned IStr(up,64);

	if( ccx_oututf == 0 )
		return 0;
	if( strncaseeq(uent,"&agrave;",len=8) ){ uch = 0xE0; }else
	if( strncaseeq(uent,"&aacute;",len=8) ){ uch = 0xE1; }else
	if( strncaseeq(uent,"&acirc;", len=7) ){ uch = 0xE2; }else
	if( strncaseeq(uent,"&atilde;",len=8) ){ uch = 0xE3; }else
	if( strncaseeq(uent,"&ccedil;",len=8) ){ uch = 0xE7; }else
	if( strncaseeq(uent,"&egrave;",len=8) ){ uch = 0xE8; }else
	if( strncaseeq(uent,"&eacute;",len=8) ){ uch = 0xE9; }else
	if( strncaseeq(uent,"&ecirc;", len=7) ){ uch = 0xEA; }else
	if( strncaseeq(uent,"&icirc;", len=7) ){ uch = 0xEE; }else
	{
		return 0;
	}
	toUTF8(uch,up);
	strcpy(utf8,(char*)up);
	return len;
}
static int encodeEntitiesZ(PCStr(src),PVStr(dst),int dsz){
	const char *sp;
	int ch;
	refQStr(dp,dst);
	int nenc = 0;
	int len;

	for( sp = src; ch = *sp; sp++ ){
		if( dsz < (dp-dst)+6 ){ /* fix-140702b */
fprintf(stderr,"--- encodeEntitiesZ: too large string (%d)\n",dsz);
			break;
		}
		if( ch == '<' ){
			sprintf(dp,"&lt;");
			dp += strlen(dp);
			nenc++;
		}else
		if( ch == '>' ){
			sprintf(dp,"&gt;");
			dp += strlen(dp);
			nenc++;
		}else
		if( ch == '&' ){
			if( 0 < (len = decuent(sp,AVStr(dp))) ){
				sp += len - 1;
			}else{
				sprintf(dp,"&amp;");
			}
			dp += strlen(dp);
			nenc++;
		}else{
			setVStrPtrInc(dp,ch);
		}
	}
	setVStrPtrInc(dp,0);
	return nenc;
}
#define encodeEntitiesX(s,o,z) encodeEntitiesZ(s,o,z)

static void encEnt(CRC *crc,FILE *out,PCStr(tag),PCStr(attr),PCStr(buf))
{	IStr(outb,sizeof(Links)*2); /* fix-140524b, fix-140702b */

	addCRC(crc,buf,strlen(buf));
	addCRC(crc,"",1);

	if( 0 ){
		IStr(xbuf,1024);
		strcpy(xbuf,buf);
		strsubst(AVStr(xbuf),"&nbsp;","");
		buf = xbuf;
	}
	encodeEntitiesX(buf,AVStr(outb),sizeof(outb));
	fprintf(out,"<%s",tag);
	if( *attr ) fprintf(out," %s",attr);
	fprintf(out,">\n%s\n</%s>\n",outb,tag);
}

#define DESCBLOCKSIZE	256
typedef struct {
	int	d_size;
	int	d_date;
	int	d_lastmod;
	MStr(	d_url,DESCBLOCKSIZE-(3*sizeof(int)));
} DescRecord;
static void makeDesc(DescRecord *Desc,int fsize,int mtime,PCStr(digest))
{	int rsiz,ulen,alen,tlen,dlen;
	MrefQStr(dp,Desc->d_url); /**/
	const char *dx;

	Desc->d_size = htonl(fsize);
	Desc->d_date = 0;
	Desc->d_lastmod = htonl(mtime);

	rsiz = sizeof(DescRecord) - ((char*)Desc->d_url - (char*)Desc);
	ulen = strlen(Url) + 1; 
	alen = strlen(Author) + 1; 
	tlen = strlen(Title) + 1; 
	dlen = strlen(digest) + 1; 
	if( rsiz < ulen+alen+tlen )
		if( (rsiz*2)/3 < ulen ) ulen = (rsiz*2)/3;
	if( rsiz < ulen+alen+tlen )
		if( rsiz/3 < alen ) alen = rsiz/3;
	if( rsiz < ulen+alen+tlen )
		if( rsiz < tlen ) tlen = (rsiz*3)/4;
	if( rsiz < ulen+alen+tlen+dlen )
		dlen = rsiz - (ulen+alen+tlen);
	dp = Desc->d_url;
	dx = Desc->d_url + (sizeof(Desc->d_url)-1);
	dp = wbstrcpy(AVStr(dp),dx,Url,ulen);
	dp = wbstrcpy(AVStr(dp),dx,Author,alen);
	dp = wbstrcpy(AVStr(dp),dx,Title,tlen);
	dp = wbstrcpy(AVStr(dp),dx,digest,dlen);
}

#define SKIP_LINE		0x01
#define SKIP_HEAD		0x02
#define SKIP_PGPSIG		0x04
#define SKIP_PGPSIG_BEGIN	0x07
#define SKIP_PGPSIG_END		0x0F
static int skipLine(int itype,PCStr(line))
{	const char *dp;
	char ch;
	const char *lp;
	int nonspace;

	nonspace = 0;
	for( lp = line; ch = *lp; lp++ ){
		if( ch != '.' && ch != '-' && ch != '=' && ch != '#'
		 && !isspace(ch) ){
			nonspace = 1;
			break;
		}
	}
	if( nonspace == 0 )
		return 1;

	if( strncasecmp(line,"-----BEGIN PGP SIGNATURE",24)==0 )
		return SKIP_PGPSIG_BEGIN;

	if( strncasecmp(line,"-----END PGP SIGNATURE",22)==0 )
		return SKIP_PGPSIG_END;

	if( strncasecmp(line,"-----BEGIN",10)==0 )
		return 3;
	if( strncasecmp(line,"-----END",8)==0 )
		return 1;

	if( strncasecmp(line,"In message",10)==0
	 || strncasecmp(line,"In article",10)==0
	 || strncasecmp(line,"In <",4)==0
	 || strncasecmp(line,"On ",3)==0 && (
		   strstr(line,"wrote")
		|| strstr(line,")\n")
		|| strstr(line,">\n")
	    )
	 || ((dp = strskip(line,"wrote"  )) && strstr(dp,">\n"))
	 || ((dp = strskip(line,"said:"  )) && (*dp==' '||*dp=='\n'))
	 || ((dp = strskip(line,"wrote:" )) && (*dp==' '||*dp=='\n'))
	 || ((dp = strskip(line,"writes:")) && (*dp==' '||*dp=='\n'))
	)
		return 1;

	if( strncasecmp(line,"On ",3)==0 ){
		if( dp = strchr(line,':') )
		if( dp = strchr(dp+1,'(') )
		if( dp = strchr(dp+1,')') )
		if( dp[1] == ' ' || dp[2] == '\n' )
			return 1;
	}

	if( line[0] == '>'
	 || line[0] == '|'
	 || strncmp(line," >",2) == 0
	 || strncmp(line," |",2) == 0
	 || line[0] == '#' && itype == T_MAIL /* v9.9.12 new-140926b */
	)
		return 1;

	for( dp = line; ch = *dp; dp++ ){
		if( !isalnum(ch) && !isspace(ch)
		 && ch != '.' && ch != '-' && ch != '_' )
			break;
	}
	if( *dp == '>' )
		return 1;

	return 0;
}
int makeDigest(PVStr(digest),int size,FILE *in){
	int ite = 0;
	int ch;
	int skip;
	int oskip;
	int pch = -1;
	refQStr(dp,digest);
	CStr(inb0,1024);
	/*
	unsigned CStr(inb,1024);
	*/
	unsigned CStr(inb,8*1024);
	unsigned refQStr(ip,inb);
	const char *dx = &digest[size-2];
	int dccx[64];

	CCXcreate("*",ccx_outcode,(CCXP)dccx);
	oskip = 0;
	for(; dp < dx;){
		if( fgets(inb0,sizeof(inb0),in) == NULL )
			break;
		CCXexec((CCXP)dccx,inb0,strlen(inb0),AVStr(inb),sizeof(inb));
		for( ip = inb; ch = *ip; ip++ ){
			if( isspace(ch) && ch != '\n' )
			if( (oskip & SKIP_HEAD) && ch=='\r' && ip[1]=='\n' ){
				/* PGP header in body */
			}else
				*(char*)ip = ' ';
		}

		skip = skipLine(T_MAIL,(char*)inb);
		if( oskip == SKIP_PGPSIG_BEGIN ){
			if( skip == SKIP_PGPSIG_END ){
				oskip = 0;
			}
			skip = SKIP_LINE;
		}else
		if( oskip & SKIP_HEAD ){
			if( inb[0] == '\r' || inb[0] == '\n' )
				oskip &= ~SKIP_HEAD;
			skip = SKIP_LINE;
		}else{
			oskip = skip;
		}

		if( skip == 0 ){
			int issp,wassp;
			wassp = 1;
			for( ip = inb; ch = *ip; ip++ ){
				int nc = ip[1];
				if( (0x80 & ch) && (0x80 & nc) ){
					if( dp+1 < dx ){
						if( ch == 0xA8 ){
							/* keisen sohen */
						}else{
						setVStrPtrInc(dp,ch);
						setVStrPtrInc(dp,nc);
						}
						ip++;
						pch = ch;
					}else{
						goto EXIT;
					}
					wassp = 0;
					continue;
				}
				if( dx <= dp )
					break;
				if( issp = isspace(ch) )
					ch = ' ';
				if( !(wassp && issp) ){
					if( ch == pch && !isalnum(ch) )
						ite++;
					else	ite = 0;
					if( ite < 3 ){
						setVStrPtrInc(dp,ch);
						pch = ch;
					}
				}
				wassp = issp;
			}
		}
	}
EXIT:
	setVStrPtrInc(dp,' '); /* for safety to ended in ASCII when this is
				* converted to ISO-2022-JP
				*/
	setVStrEnd(dp,0);
	return 0;
}

void getCharset(PCStr(where),PVStr(charset),PCStr(fval));
static void scanHtml0(PCStr(inb),PVStr(charset))
{	const char *dp;
	CStr(nam,32);
	CStr(con,1024);
	int si,na;

	dp = inb;
	for( si = 0; si < 8 && (dp = strcasestr(dp,"<META")); si++ ){
		dp += 5;
		na = scanAttrs(dp,4, "HTTP-EQUIV",AVStr(nam),sizeof(nam),
			"CONTENT",AVStr(con),sizeof(con));
		if( na != 2 )
			continue;
		if( strcaseeq(nam,"Content-Type") ){
			getCharset("HTML",AVStr(charset),con);
		}
	}
}
static void makeUrl(PVStr(url),int usiz,PCStr(pre),PCStr(path))
{	refQStr(dp,url); /**/
	const char *sp;

	sprintf(url,"%s%s",pre,path);
	if( strtailstr(url,"/=") ){
		/* index.html or so cached by DeleGate */
		setVStrEnd(url,strlen(url)-1);
	}
	/* URL path is escaped to be used as a file name of cache */
	url_unescape(AVStr(url),AVStr(url),usiz,"*?%@=");

	for( sp = url; *sp; sp++ ){
		if( *sp == ':' ){
			sp++;
			if( *sp == '/' )
				sp ++;
			break;
		}
	}
	dp = (char*)sp;
	for(; *sp; sp++ ){
		setVStrPtrInc(dp,*sp);
		if( sp[0] == '/' ){
			while( sp[1] == '/' ){
				sp++;
			}
		}
	}
	setVStrEnd(dp,0);
	if( UrlSed ){
		CStr(buf,0x1000);
		sed_execute1((SedEnv*)UrlSed,url,AVStr(buf),0);
		QStrncpy(url,buf,usiz);
	}
	if( UrlMount[0] ){
		CStr(buf,0x1000);
		const char *rsp;
		const char *rfp;
		UTag *uv[33],ub[32];
		int uc;
		uvinit(uv,ub,32);
		FStrncpy(buf,url);
		uc = uvfromsfX(buf,0,UrlMount[0],uv,&rsp,&rfp);
		if(rsp[0] == 0 && rfp[0] == 0 ){
			uvtosf(AVStr(url),usiz,UrlMount[1],uv);
		}
	}
}

/* avoid multi-bytes char is broken in receiver line buffer (findex) */
/*
void
*/
int
fputsX(PCStr(str),FILE *out)
{	const char *sp;
	char ch;
	int pch = '\n';
	int len;
	int do_break = 0;
/*
	fputs(str,out);
*/
	len = 0;
	for( sp = str; (ch = *sp) != 0; sp++ ){
		if( ch == '\n' ){
			len = 0;
			do_break = 0;
		}else{
			if( do_break ){
				if( (ch & 0x80) == 0 ){
/*
 fprintf(stderr,"#### ADD NL-A ch=[%c] len=%d\n",ch,len);
*/
					putc('\n',out);
					len = 0;
					do_break = 0;
				}
			}else{
				if( 1024 < len ){
					do_break = 1;
				}
			}
			len++;
		}
		putc(ch,out);
		pch = ch;
	}
/*
	if( pch != '\n' ){
 fprintf(stderr,"#### ADD NL-B pch=%X len=%d\n",0xFF&pch,len);
		putc('\n',out);
	}
*/
	return pch;
}
int maskControl(PVStr(str),PCStr(apath)){
	int ci;
	int ch;
	int nm = 0;
	for( ci = 0; (ch = 0xFF & str[ci]); ci++ ){
		if( ch == 'Z'-0x40 ){
			/* control-Z is treated as EOF on VC++ */
fprintf(stderr,"--- ignored control-Z: %s\n",apath);
			((char*)str)[ci] = ' ';
			nm++;
		}
	}
	return nm;
}
int scanText(FILE *in,FILE *out,PVStr(charset),PCStr(apath))
{	CStr(inb,16*1024);
#if 0
	CStr(outb,32*1024); /* for SJIS 1byte kana -> EUC 2byte kana */
#endif
	CStr(outb,8*16*1024); /* for SJIS 1byte kana -> EUC 2byte kana */
	int nb,rcc,ri,ch;
	int bodysiz = 0;
	int pch = 0;
	int nz = 0;

	for( nb = 0; rcc = fread(inb,1,sizeof(inb)-1,in); nb++ ){
		setVStrEnd(inb,rcc);
		if( charset && charset[0] == 0 && nb == 0 ){
			scanHtml0(inb,AVStr(charset));
			if( charset[0] ){
				if( lCHARSET() )
				fprintf(stderr,"##2 cs[%s]\n",charset);
			}
			if( charset[0] == 0 ){
				guessCharcode(inb,AVStr(charset));
				if( charset[0] ){
					if( lCHARSET() )
					fprintf(stderr,"##3 cs[%s]\n",charset);
				}
			}
			if( charset[0] ){
				CCX_setincode((CCXP)Ccx,charset);
			}
		}
		for( ri = 0; ri < rcc; ri++){
			ch = 0xFF & inb[ri];
			if( ch == 0 && ++nz < 2 ){
				ch = ' ';
fprintf(stderr,"--- ignored #%d %d/%d '\\0'\n",nz,ri,rcc);
			}
			if( ch == 0 ){
				if( opt_v )
				fprintf(stderr,"binary file.\n",Url);
				return E_BINARY;
			}
		}
		CCXexec((CCXP)Ccx,inb,strlen(inb),AVStr(outb),sizeof(outb));
		maskControl(AVStr(outb),apath);
		bodysiz += rcc;
		pch =
		fputsX(outb,out);
	}
	if( pch != '\n' ){
		putc('\n',out);
	}
	if( bodysiz == 0 ){
		if( 1 /* without .txt or .html suffix */ ){
			if( opt_v )
			fprintf(stderr,"empty file.\n");
			return E_EMPTY;
		}
	}
	return 0;
}

int sysfilter(PCStr(conv),FILE *in,FILE *out);
void scanMail(FILE *in,FILE *out,PCStr(apath),int ismbox,int lev);
void scanHtml(FILE *in,FILE *tmp,PCStr(apath));

#define FA_IN	"^^i"
#define FA_OUT	"^^o"

static struct {
	FILE *t_fp;
	char *t_name;
	char *t_path;
} tmpfiles[8];
static char *tmpbase;
static int tmpfilex;
void setnamedtmpbase(PCStr(path)){
	int crc;
	const char *dp;
	CStr(base,128);
	crc = strCRC32(path,strlen(path));
	if( dp = strrpbrk(path,"/\\") )
		dp++;
	else	dp = path;
	sprintf(base,"%X-%s",crc,dp);
	tmpbase = stralloc(base);
}
void removenamedtmpfiles(){
	int fi;
	for( fi = 0; fi < tmpfilex; fi++ ){
		unlink(tmpfiles[fi].t_path);
		free(tmpfiles[fi].t_name);
		free(tmpfiles[fi].t_path);
	}
	tmpfilex = 0;
	if( tmpbase ){
		free(tmpbase);
		tmpbase = 0;
	}
}
FILE *namedtmpfile(FILE *ofp,PVStr(path),PCStr(name),PCStr(mode)){
	FILE *fp;
	CStr(tpath,1024);
	CStr(xpath,1024);
	refQStr(dp,xpath);
	const char *cpath = 0;
	int fi;

	for( fi = 0; fi < tmpfilex; fi++ ){
		if( strcmp(name,tmpfiles[fi].t_name) == 0 ){
			strcpy(path,tmpfiles[fi].t_path);
			fp = freopen(path,mode,ofp);
			return fp;
		} 
	}
	if( ofp ){
		fclose(ofp);
	}

	fp = TMPFILEX(AVStr(tpath));
	fclose(fp);
	strcpy(xpath,tpath);
	if( *name ){
		if( dp = strrpbrk(xpath,"/\\") ){
			dp++;
			strcpy(dp,name);
			if( tmpbase ){
				Xsprintf(TVStr(dp),"-%s",tmpbase);
			}
			if( rename(tpath,xpath) == 0 ){
				strcpy(tpath,xpath);
			}
		}
	}
	if( tmpfilex < elnumof(tmpfiles) ){
		tmpfiles[tmpfilex].t_name = stralloc(name);
		tmpfiles[tmpfilex].t_path = stralloc(tpath);
		tmpfilex++;
	}
	strcpy(path,tpath);
	fp = fopen(tpath,mode);
	return fp;
}

int m17n_MIMEdecodeWord(MimeConv *Mcv,PVStr(author)){
	IStr(buf,1024);
	refQStr(ap,Author);
	IStr(charset,64);
	MimeConv Mcwb,*Mcw = &Mcwb;
	int mconvb[128];
	IStr(ab,256);
	const char *CCXinputIsJP1(CCXP ccx);

	bzero(Mcw,sizeof(Mcwb));
	MIME_strHeaderDecodeX(Mcw,Author,AVStr(buf),sizeof(buf));
	if( Mcv->c_ocode && Mcv->c_ocode[0]
	 && Mcw->c_ewicode[0]
	 && Mcv->c_icode
	 && !strcaseeq(Mcv->c_ewicode,Mcv->c_icode)
	){
		Mcw->c_icode = Mcw->c_ewicode;
		Mcw->c_ocode = Mcv->c_ocode;
		setupM17N(Mcw,mconvb,sizeof(mconvb));
		CCXcreate(Mcw->c_ewicode,Mcw->c_ocode,(CCXP)Ccx);
		doCCX(Mcw,(CCXP)Ccx,buf,strlen(buf),AVStr(ab),sizeof(ab),1);
		strcpy(Author,ab);
		fprintf(stderr,"##ew [%s]/[%s]=>[%s] %s\n",
			Mcw->c_ewicode,Mcv->c_icode,Mcv->c_ocode,Author);
		return 1;
	}
	return 0;
}
int scanCCode(FILE *in,FILE *out,PCStr(apath));
int any2fdif(PCStr(pre),PCStr(strip),PCStr(apath),int mi,PCStr(sub),PCStr(conv),FILE *ain,FILE *out,FILE *descf,int *itypep)
{	FILE *in = ain;
	const char *path = apath;
	CStr(head,256);
	int ismbox = 0;
	CStr(date,64);
	struct tm *tm; int ch,issp,wassp;
	CStr(inb,16*1024);
	const char *ip;
	const char *op;
	CStr(outb,32*1024); /* for SJIS 1byte kana -> EUC 2byte kana */
	int topoff;
	int itype = 0;
	CStr(digest,256);
	refQStr(dp,digest); /**/
	const char *dx;
	const char *cp;
	int ic;
	DescRecord Desc;
	int skip,skiphead;
	int oskip;
	FILE *Tmp0,*Tmp1;
	CRC crcb = {0,0}, *crc = &crcb;
	int pch,ite;
	int off0;
	CStr(ctype,64);
	CStr(charset,64);
	MimeConv Mcvb;
	IStr(ccx_incode,64);
	int mconvb[128];
	int ctime,mtime,atime;
	int soff;
	CStr(prevb,1024);
	int noauth;
	int copymark;
	int ecode = 0;
	CStr(cwd,256);
	IGNRETS getcwd(cwd,sizeof(cwd));

	if( strncmp(path,strip,strlen(strip)) == 0 )
		path += strlen(strip);
	if( strncmp(path,"./",2) == 0 )
		path += 2;
	if( fileIsdir(path) ){
		return E_DIR;
	}
	if( conv != NULL ){
		FILE *Tmp3;
		static CStr(ifile,1024);
		static CStr(ofile,1024);
		static FILE *fin;
		static FILE *fout;
		CStr(xconv,1024);

		strcpy(xconv,conv);
		if( strstr(conv,FA_IN) ){
			fin = namedtmpfile(fin,AVStr(ifile),"fsx-i","w");
			relay_file(in,fin,0,0,0);
			IGNRETZ ftruncate(fileno(fin),(off_t)ftell(fin));
			strsubst(AVStr(xconv),FA_IN,ifile);
			fseek(fin,0,0); /*this is necessary for the first data
			  otherwise fgets(in) will fail by unknown reason ???*/
		}
		if( strstr(conv,FA_OUT) ){
			fout = namedtmpfile(fout,AVStr(ofile),"fsx-o","r");
			fclose(fout);
			strsubst(AVStr(xconv),FA_OUT,ofile);
			sysfilter(xconv,in,fout);
			fout = fopen(ofile,"r");
			if( fout == NULL ){
				fprintf(stderr,"cannot open %s\n",ofile);
				exit(0);
			}
			in = fout;
		}else{
		Tmp3 = getTmp(TMP3);
		IGNRETZ ftruncate(fileno(Tmp3),(off_t)0);
		/*
		sysfilter(conv,in,Tmp3);
		*/
		sysfilter(xconv,in,Tmp3);
		fseek(Tmp3,0,0);
		in = Tmp3;
		}
	}

	Lang[0] = 0;
	Title[0] = 0;
	Keywd[0] = 0;
	Descr[0] = 0;
	Heads[0] = 0;
	Author[0] = 0;
	Address[0] = 0;
	Links[0] = 0;
	Location[0] = 0;
	XUri[0] = 0;
	XRefs[0] = 0;
	ctype[0] = 0;
	charset[0] = 0;
	digest[0] = 0;

	Mcv = &Mcvb;
	bzero(Mcv,sizeof(MimeConv));
	Mcv->c_ocode = ccx_outcode;
	ccx_oututf = strcasestr(ccx_outcode,"utf") != 0;

	CCXcreate("*",ccx_outcode,(CCXP)Ccx);
	CCXthru8((CCXP)Ccx,thru8);
	CCXdisable = 0;
	if( streq(ccx_outcode,"thru") ){
		CCXdisable = 1;
	}

	topoff = ftell(in);
	soff = ftell(out);
	if( fgets(head,sizeof(head),in) == NULL ){
		return E_EOF;
	}
	if( strncmp(head,"From ",5) == 0 ){
		ismbox = 1;
	}

	itype = Itype;
	if( Itype == T_MBOX ){
		/* MBOX */
	}else
	if( strncmp(head,"HTTP/",5) != 0 ){
		int ismail;
		fseek(in,topoff,0);
		ismail = isRFC822(in);
		if( itype == T_MAIL ){
			if( ismail <= 0 ){
				return E_BINARY;
			}
		}else{
			if( 0 < ismail ){
/*
 fprintf(stderr,"#### ISMAIL %5d %s\n",ismail,apath);
*/
				itype = T_MAIL;
			}
		}
	}else{
		int code = 0;
		sscanf(head,"HTTP/%*s %d",&code);
		Codes[code%1000] += 1;
		if( code < 200 || 300 <= code ){
			if( opt_v )
			fprintf(stderr,"[%s%s] not user data (%d)\n",pre,path,
				code);
			return E_CTRL;
		}
		while( fgets(head,sizeof(head),in) != NULL ){
			CStr(fnam,64);
			CStr(fval,128);
			if( *head == '\r' || *head == '\n' ){
				Fsize -= ftell(in);
				break;
			}
			scan_field1(head,AVStr(fnam),sizeof(fnam),AVStr(fval),sizeof(fval));
			if( strcaseeq(fnam,"Content-Type") ){
				const char *sp;
				getCharset("HEAD",AVStr(charset),fval);
				strcpy(ccx_incode,charset);
				Mcv->c_icode = ccx_incode;
				setupM17N(Mcv,mconvb,sizeof(mconvb));
				if( charset[0] ){
					if( lCHARSET() )
					fprintf(stderr,"##1 cs[%s]\n",charset);
				}

				FStrncpy(ctype,fval);
				if( sp = strchr(fval,';') )
					truncVStr(sp);
				if( streq(fval,"text/html") )
					itype = T_HTML;
				else
				if( strstr(fval,"application/xhtml") )
					itype = T_HTML;
				else
				if( streq(fval,"text/plain") )
					itype = T_TEXT;
				else
				if( streq(fval,"application/x-javascript")
				 || streq(fval,"application/javascript")
				 || streq(fval,"text/javascript")
				)	itype = T_JS;
			}else
			if( strcaseeq(fnam,"Date") ){
				Xtime = scanHTTPtime(fval);
			}else
			if( strcaseeq(fnam,"Last-Modified") ){
				Mtime = scanHTTPtime(fval);
			}else
			if( strcaseeq(fnam,"Content-Encoding") ){
				if( opt_v )
				fprintf(stderr,"[%s%s] encoded (%s)\n",
					pre,path,fval);
				return E_ENCODED;
			}
		}
		if( itype == 0 || itype == T_JS ){
			if( strstr(ctype,"image/") == NULL )
			if( strstr(ctype,"text/css") == NULL )
			if( opt_v )
			fprintf(stderr,"[%s] not text [%s%s]\n",ctype,pre,path);
			return E_NONTEXT;
		}

		if( strncmp(path,"nntp/",5) == 0){
			pre = "nntp://";
			path += 5;
			itype = T_MAIL;
			fseek(in,topoff,0);
		}
		if( strncmp(path,"http/",5) == 0){
			pre = "http://";
			path += 5;
		}
		if( strncmp(path,"https/",6) == 0){
			pre = "http://";
			path += 6;
		}
	}

	makeUrl(AVStr(Url),sizeof(Url),pre,path);
	NumUrl++;
	if( NumUrl == 1 ){
		fprintf(stderr,"First URL: %s\n",Url);
		fprintf(stderr,"...\n");
	}
	if( opt_v ){
		fprintf(stderr,"%04d [%s] ",NumUrl,apath);
	}

	if( charset[0] ){
		CCX_setincode((CCXP)Ccx,charset);
	}

/*
	if( strtailstr(apath,".pdf") ){
		FILE *Tmp6;
		Tmp6 = getTmp(TMP6);
		PdfToText(in,Tmp6);
		fflush(Tmp6);
		ftruncate(fileno(Tmp6),(off_t)ftell(Tmp6));
		fseek(Tmp6,0,0);
		in = Tmp6;
	}
*/
	if( itype == T_HTML ){
		Tmp0 = getTmp(TMP0);
		if( ecode = scanText(in,Tmp0,AVStr(charset),apath) )
			return ecode;

		fflushTmp(Tmp0);
		if( !CCXdisable )
		if( (Mcv->c_icode==0 || Mcv->c_icode[0]==0) && charset[0] != 0 )
		if( Mcv->c_m17n == 0 )
		{
			Mcv->c_icode = charset;
			setupM17N(Mcv,mconvb,sizeof(mconvb));
			Tmp1 = getTmp(TMP1);
			if( ecode = scanText(Tmp0,Tmp1,AVStr(charset),apath) )
				return ecode;
			fflushTmp(Tmp1);
			fseek(Tmp0,0,0);
			copyfile1(Tmp1,Tmp0);
			Ftruncate(Tmp0,0,1);
			fseek(Tmp0,0,0);
		}

		in = Tmp0;
		CCXdisable = 1;
		/*
		CCXcounts((CCXP)Ccx);
		*/
	}

	Tmp1 = getTmp(TMP1);
	switch( itype ){
		case T_CCODE: ecode = scanCCode(in,Tmp1,apath); break;
		case T_TEXT: ecode = scanText(in,Tmp1,VStrNULL,apath); break;
		case T_HTML: scanHtml(in,Tmp1,apath); break;
		case T_MBOX:
		case T_MAIL: scanMail(in,Tmp1,apath,ismbox,0); break;
	}
	if( ecode != 0 ){
		return ecode;
	}
	fflushTmp(Tmp1);
	if( Location[0] ){
		makeUrl(AVStr(Url),sizeof(Url),pre,Location);
	}
	if( itype == T_MAIL && !feof(in) ){
		if( ismbox ){
			itype = T_MBOX;
			Lap(1,0,"MBOX %s\n",apath);
		}
	}
	if( itype == T_MBOX ){
		Xstrcat(AVStr(Url),sub);
	}

/*
	strCRC32add(crc,path,strlen(path));
	strCRC32add(crc,"",1);
*/
/* CRC only for content is desired ? */
	addCRC(crc,path,strlen(path));
	addCRC(crc,"",1);

	fprintf(out,"<DOC HREF=\"%s\">\n",Url); /* encEnt("URL") */
	{
		if( isFullpath(path) || isFullURL(path) ){
			fprintf(out,"<DOCPATH>%s</DOCPATH>\n",path);
		}else{
			CStr(fpath,2048);
			strcpy(fpath,cwd);
			chdir_cwd(AVStr(fpath),apath,1);
			fprintf(out,"<DOCPATH>%s</DOCPATH>\n",fpath);
		}
	}
	if( Lang[0] ){
		fprintf(out,"<METAX name=LANGUAGE>%s</METAX>\n",Lang);
	}
	if( ccx_outcode && CCXactive((CCXP)Ccx) ){
		const char *xcode = 0;
		CCXoutcharset((CCXP)Ccx,&xcode);
		if( xcode ){
			fprintf(out,"<METAX name=CHARCODE>%s</METAX>\n",xcode);
		}
	}
	if( charset[0] ){
		fprintf(out,"<METAX name=ORIG-CHARCODE>%s</METAX>\n",charset);
	}

	if( strncasecmp(Author,"mailto:",7) == 0 )
		ovstrcpy(Author,Author+7);
	if( Author[0] ){
		if( strstr(Author,"=?") ){
			CStr(buf,256);

			if( m17n_MIMEdecodeWord(Mcv,AVStr(Author)) ){
			}else{
			MIME_strHeaderDecode(Author,AVStr(buf),sizeof(buf));
			CCXexec((CCXP)Ccx,buf,strlen(buf),AVStr(Author),sizeof(Author));
			}
		}
		if( strchr(Author,033) == 0 ){
			refQStr(ap,Author);
			if( ap = strchr(Author,'<') ){
				truncVStr(ap);
			}
		}
	}
	if( Author[0] )
		withAuthor++;

	fprintf(out,"<TEXT WEIGHT=\"3\">\n"); /* encEnt("TEXTW3"); */

	dp = digest;
	dx = digest + (sizeof(digest)-1);
	if( Descr[0] ){
		wbstrcpy(AVStr(digest),dx,Descr,0);
		dp += strlen(digest);
		if( dp < dx )
			setVStrPtrInc(dp,' ');
	}

	skiphead = 0;
	oskip = 0;
	pch = -1;
	ite = 0;
	prevb[0] = 0;
	noauth = Author[0] == 0;
	copymark = 0;
	for( ic = 0; ; ic++ ){
		if( fgets(inb,sizeof(inb),Tmp1) == NULL )
			break;
		for( ip = inb; ch = *ip; ip++ ){
			if( isspace(ch) && ch != '\n' )
			if( (oskip & SKIP_HEAD) && ch=='\r' && ip[1]=='\n' ){
				/* PGP header in body */
			}else
				*(char*)ip = ' ';
		}
		addCRC(crc,inb,strlen(inb));
		if( 0 ){
			strsubst(AVStr(inb),"&nbsp;","");
		}
		encodeEntitiesX(inb,AVStr(outb),sizeof(outb));
		fputs(outb,out);

		if( noauth )
		if( Author[0] == 0 || copymark == 0 && strcasestr(inb,"&copy;") )
		if( prevb[0]
		 || itype == T_HTML && strcasestr(inb,"&copy;")
		 || strcasestr(inb,"Copyright")
		 || strcasestr(inb,"All Right")
		){
			CStr(auth,256);
			int mark = 0;
			auth[0] = 0;
			if( strlen(prevb) + strlen(inb) < sizeof(prevb) ){
				strcat(prevb,inb);
				if( strcasestr(prevb,"&copy;") )
					mark = 1;
				if( copy2auth(prevb,AVStr(auth),sizeof(auth),apath,0) ){
				}else{
					prevb[0] = 0;
				}
			}else{
				prevb[0] = 0;
			}
			if( auth[0] )
			if( Author[0] == 0 || strcmp(auth,Author) != 0 ){
				copymark = mark;				
				wbstrcpy(AVStr(Author),Author+(sizeof(Author)-1),auth,0);
			}
		}

		if( skiphead ){
			if( inb[0] == '\r' || inb[0] == '\n' )
				skiphead = 0;
		}else
		if( skiphead == 0 && dp < dx ){
			skip = skipLine(itype,inb);
			skiphead = skip & 2;

			if( oskip == SKIP_PGPSIG_BEGIN ){
				if( skip == SKIP_PGPSIG_END ){
					oskip = 0;
				}
				skip = SKIP_LINE;
			}else
			if( oskip & SKIP_HEAD ){
				if( inb[0] == '\r' || inb[0] == '\n' )
					oskip &= ~SKIP_HEAD;
				skip = SKIP_LINE;
			}else{
				oskip = skip;
			}

			if( skip == 0 ){
				wassp = 1;
				for( ip = inb; ch = *ip; ip++ ){
					int nc = ip[1];
					int ulen;

					if( 1 < (ulen = isUTF8chr(ip)) ){
						if( dp+ulen < dx ){
							strncpy(dp,ip,ulen+1);
							dp += ulen;
							ip += ulen-1;
							pch = 0;
						}
						wassp = 0;
						continue;
					}else
					if( (0x80 & ch) && (0x80 & nc) ){
						if( dp+1 < dx ){
							setVStrPtrInc(dp,ch);
							setVStrPtrInc(dp,nc);
							ip++;
							pch = ch;
						}
						wassp = 0;
					  	continue;
					}
					if( dx <= dp )
						break;
					if( issp = isspace(ch) )
						ch = ' ';
					if( !(wassp && issp) ){
						/*
						if( ch == pch )
				ignore iteration of a symbol in the digest
						*/
						if( ch == pch
						 && !isalnum(ch)
						)
							ite++;
						else	ite = 0;
						if( ite < 3 ){
							setVStrPtrInc(dp,ch);
							pch = ch;
						}
					}
					wassp = issp;
				}
			}
		}
	}
	setVStrEnd(dp,0);

	crc->crc = strCRC32end(crc->crc,crc->len);
	if( opt_v ){
		fprintf(stderr,"%08X\r\n",crc->crc);
	}
	fprintf(out,"\n</TEXT>\n");

	if( Author[0] == 0 )
	if( Address[0] != 0 )
	if( strcasestr(Address,"converted") == 0 )
	if( strcasestr(Address,"generated") == 0 )
	if( strstr(Address,"Exp") == 0 )
	{	const char *ap;

		if( ap = strcasestr(Address,"mail") ){
			ap += 4;
			if( *ap == ' ' )
				ap++;
			if( *ap == ':' )
				ap++;
			else	ap = Address;
		}else
		if( ap = strcasestr(Address," by ") ){
			ap += 4;
		}else{
			ap = Address;
		}
		copy2auth(ap,AVStr(Author),sizeof(Author),apath,1);
	}
	if( noauth && Author[0] ){
		guessedAuthor++;
	}
	if( XUri[0]  ) encEnt(crc,out,"URL","",XUri);
	if( Heads[0] ) encEnt(crc,out,"TEXT","WEIGHT=\"2\"",Heads);
	if( Descr[0] ) encEnt(crc,out,"TEXT","WEIGHT=\"1\"",Descr);
	if( XRefs[0] ) encEnt(crc,out,"LINK","",XRefs);
	if( Links[0] ) encEnt(crc,out,"LINK","",Links);
	if( digest[0]) encEnt(crc,out,"DIGEST","",digest);
	if( Author[0]) encEnt(crc,out,"AUTHOR","",Author);
	if( Title[0] ) encEnt(crc,out,"TITLE","",Title);
	if( Keywd[0] ) encEnt(crc,out,"KEYWORD","",Keywd);

	fprintf(out,"<METAX name=DATE>%X</METAX>\n",itime(NULL));
	fprintf(out,"<METAX name=LASTMODIFIED>%X</METAX>\n",Mtime);
	fprintf(out,"<METAX name=LASTACCESSED>%X</METAX>\n",Atime);
	fprintf(out,"<METAX name=SIZE>%X</METAX>\n",Fsize);
	fprintf(out,"<METAX name=CRC32>%08X</METAX>\n",crc->crc);
	fprintf(out,"</DOC>\n");
fflush(out);

	makeDesc(&Desc,Fsize,Mtime,digest);
	if(descf){
		fwrite(&Desc,1,sizeof(Desc),descf);
		fflush(descf);
	}

	NumPut++;
	if( printIfText ){
		fprintf(stderr,"IsText: %s\n",Url);
	}

	if(Summf){
		fprintf(Summf,"%08X %08X %08X %08X %8d %s\n",soff,Atime,Mtime,
		crc->crc,Fsize,apath);
	}
	if( itypep )
		*itypep = itype;
	return E_OK;
}

void toMD5dots(PCStr(pfx),PCStr(str),PVStr(dots),int len){
	CStr(md5,64);
	refQStr(dp,dots); /**/
	const char *sp;
	int i;
	toMD5(str,md5);

	sp = md5;
	cpyQStr(dp,dots);
	if( pfx && *pfx ){
		strcpy(dots,pfx);
		dp += strlen(dp);
	}
	for(i = 0; i < len && *sp; i++){
		if( 0 < i && i % 2 == 0){
			setVStrPtrInc(dp,'.');
		}
		setVStrPtrInc(dp,*sp++);
	}
	setVStrEnd(dp,0);
}
static void scanRefs(PCStr(irefs),PVStr(orefs),int osize){
	int ri;
	const char *xp;
	const char *rp;
	CStr(ref1,256);
	refQStr(op,orefs); /**/
	CStr(xref1,256);

	xp = orefs + (osize-1);
	rp = irefs;

	setVStrEnd(orefs,0);
	for( ri = 0; ; ri++ ){
		rp = strchr(rp,'<');
		if( rp == NULL )
			break;
		rp = wordscanY(rp,AVStr(ref1),sizeof(ref1),"^>");
		if( *rp == '>' ){
			if( 0 < ri && op < xp ){
				setVStrPtrInc(op,' ');
			}
			strcat(ref1,">");
			QStrncpy(op,ref1,xp-op);
			op += strlen(op);

			toMD5dots("x-uri.",ref1,AVStr(xref1),32);
			QStrncpy(op,xref1,xp-op);
			op += strlen(op);
		}
	}
}

void scanMail(FILE *in,FILE *out,PCStr(apath),int ismbox,int lev)
{	CStr(line,1024);
	CStr(xline,1024);
	CStr(fnam,32);
	CStr(fval,1024);
	CStr(yline,2*1024);
	const char *dp;
	const char *ep;
	int li;
	int inUU;
	int topoff;
	int deMime = 0;
	MrefQStr(lkp,Links); /**/
	const char *lkx = Links+(sizeof(Links)-1);
	int isHTML = 0;

	topoff = ftell(in);
	while( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),in) != NULL ){
		if( *line == '\r' || *line == '\n' )
			break;

		if( 0 ){
			fprintf(stderr,"--scanMail %s",line);
		}
		if( Mtime == 0 && strneq(line,"From ",5) ){
			Xsscanf(line,"%*s %[^\r\n]",AVStr(fval));
			Mtime = scanNNTPtime(fval);
		}

		scan_field1(line,AVStr(fnam),sizeof(fnam),AVStr(fval),sizeof(fval));
		if( strcaseeq(fnam,"Content-Type") ){
			if( strncaseeq(fval,"multipart/",10) ){
				if( lev == 0 ){
					deMime |= 1;
					break;
				}
			}
			else
			if( strncaseeq(fval,"text/html",9) ){
				isHTML = 1;
			}
		}else
		if( strcaseeq(fnam,"Content-Transfer-Encoding") ){
			if( strcasestr(fval,"quoted-printable")
			 || strcasestr(fval,"base64") ){
				if( lev == 0 ){
					deMime |= 2;
					break;
				}
			}
		}else
		if( strcaseeq(fnam,"Subject")
		 || strcaseeq(fnam,"From") ){
			if( hide_addr )
				MIME_rewriteHeader(0,hide_addr,AVStr(line),NULL);
			MIME_strHeaderDecode(line,AVStr(xline),sizeof(xline));
			if( CCXdisable ){
				scan_field1(xline,AVStr(fnam),sizeof(fnam),AVStr(fval),sizeof(fval));
			}else{
				CCXexec((CCXP)Ccx,xline,strlen(xline),AVStr(yline),sizeof(yline));
				scan_field1(yline,AVStr(fnam),sizeof(fnam),AVStr(fval),sizeof(fval));
			}
		}
		if( strcaseeq(fnam,"Message-Id") ){
			int len;
			linescanX(fval,AVStr(XUri),sizeof(XUri));

			len = strlen(XUri);
			toMD5dots("x-uri.",XUri,QVStr(XUri+len,XUri),32);
		}else
		if( strcaseeq(fnam,"References") ){
			scanRefs(fval,AVStr(XRefs),sizeof(XRefs));
		}else
		if( strcaseeq(fnam,"Subject") ){
			linescanX(fval,AVStr(Title),sizeof(Title));
			subject_stripPrefix(AVStr(Title),8,1);
		}else
		if( strcaseeq(fnam,"From") ){
			linescanX(fval,AVStr(Author),sizeof(Author));
		}else
		if( strcaseeq(fnam,"Date") ){
			Mtime = scanNNTPtime(fval);
			if( 0 ){
			fprintf(stderr,"--scanNNTPtime %X %s\n",Mtime,fval);
			}
		}
	}

	if( lev == 0 && deMime ){
		FILE *Tmp2;
		Tmp2 = getTmp(TMP2);
		fseek(in,topoff,0);

 if( ftell(in) != topoff ){
  fflush(in);
  fseek(in,topoff,0);
  fprintf(stderr,"## fseek retried: %d %d\n",topoff,iftell(in));
 }

		if( ismbox ){
			FILE *Tmp5 = getTmp(TMP5);
			int li;
			for(li = 0; fgets(line,sizeof(line),in) != NULL; li++){
				if( li != 0 )
				if( strncmp(line,"From ",5) == 0 ){
					backseek(in,strlen(line));
					break;
				}
				fputs(line,Tmp5);
			}
			fflushTmp(Tmp5);
			in = Tmp5;
		}

		PGPdecodeMIME(in,Tmp2,NULL,0x2FF,0,0);
		fflushTmp(Tmp2);
		scanMail(Tmp2,out,apath,ismbox,lev+1);
		return;
	}
	if( isHTML ){
		FILE *Tmp7 = getTmp(TMP7);
		HTMLtoTEXT(in,Tmp7,0);
		fflushTmp(Tmp7);
		in = Tmp7;
	}

	inUU = 0;
	for( li = 0; fgets(xline,sizeof(xline),in) != NULL; li++ ){
		if( ismbox ){
			if( strncmp(xline,"From ",5) == 0 ){
				backseek(in,strlen(xline));
				break;
			}
		}
		if( inUU == 0 ){
			if( strncmp(xline,"begin ",6) == 0 )
			if( isdigit(xline[6]) )
			{
				inUU = 1;
				continue;
			}
			if( dp = strstr(xline,"<URL:") ){
				dp += 5;
				if( ep = strchr(dp,'>') ){
					if( ep-dp+1 < lkx-lkp ){
						QStrncpy(lkp,dp,ep-dp+1);
						lkp += strlen(lkp);
						setVStrPtrInc(lkp,'\n');
						setVStrEnd(lkp,0);
					}
				}
			}
		}else{
			if( strncmp(xline,"end",3) == 0 ){
				inUU = 0;
				continue;
			}
			continue;
		}

		if( hide_bodyaddr )
			scanAddrInBody(-1,hide_bodyaddr,AVStr(xline));

		if( CCXdisable ){
			fputs(xline,out);
		}else{
			CCXexec((CCXP)Ccx,xline,strlen(xline),AVStr(yline),sizeof(yline));
			maskControl(AVStr(yline),apath);
			fputs(yline,out);
		}
	}
}
static void scanalpha(FILE *in,PVStr(str),int size)
{	int i,ch;

	for( i = 0; i < size-1; i++ ){
		ch = getc(in);
		if( !isalpha(ch) ){
			ungetc(ch,in);
			break;
		}
		setVStrElem(str,i,ch); /**/
	}
	setVStrEnd(str,i);
}

#define	BUFFED	(0x80000000|' ')

static int Isspace(PCStr(apath),int ch){ /* fix-140524a */
	if( ch == BUFFED ){
		return 0;
	}else
	if( (ch & 0xFF) != ch ){
		sv1log("---Isspace(%X) out of range [%s]\n",ch,apath);
		return 0;
	}else{
		return isspace(ch);
	}
}

int xstrrot13(PVStr(str));
int scanSRC(PCStr(src),PVStr(href),int size);
int scanHREF(PCStr(src),PVStr(href),int size);
int scanACTION(PCStr(src),PVStr(href),int size);
int scanLink(PCStr(src),PVStr(nam),int nsiz,PVStr(con),int csiz);
int skipComment(FILE *in,PVStr(comment),int siz);

void scanHtml(FILE *in,FILE *tmp,PCStr(apath))
{	int ch,pch,end,ech;
	const char *dp;
	CStr(tag,0x10000);
	CStr(tagn,32);
	CStr(attrn,32);
	CStr(nam,32);
	CStr(con,1024);
	int inHead = 0;
	int inTitle = 0;
	int inTableData = 0;
	int inAnchor = 0;
	int textWasPut = 0;
	int inScript = 0;
	int inStyle = 0;
	int inHeading = 0;
	int inAddress = 0;
	int inNoindex = 0; /* new-140527f <noindex>text</noindex>  */
	int preisspace = 0;
	MrefQStr(tip,Title); /**/
	const char *tix = Title+(sizeof(Title)-1);
	MrefQStr(htp,Heads); /**/
	const char *htx = Heads+(sizeof(Heads)-1);
	MrefQStr(adp,Author); /**/
	const char *adx = Author+(sizeof(Author)-1);
	MrefQStr(ddp,Address); /**/
	const char *ddx = Address+(sizeof(Address)-1);
	MrefQStr(lkp,Links); /**/
	const char *lkx = Links+(sizeof(Links)-1);
	int bodyoff = ftell(tmp);
	int pushch = -1;
	CStr(buffed,128);
	CStr(authcand,128);
	int asis = 0;
	int ic;
	CStr(buf,256);

	authcand[0] = 0;
	pch = 0;
	asis = 0;
	for( ic = 0; ; ic++ ){
	    if( pushch != -1 ){
		ch = pushch;
		pushch = -1;
		goto INCHAR;
	    }else
	    if( (ch = getc(in)) == EOF ){
		break;
	    }
	    if( asis ){
		asis = 0;
		goto INCHAR;
	    }

	    if( 0 < inScript || 0 < inStyle ){
		if( ch == '<' ){
			ch = getc(in);
			if( ch == '/' ){
				scanalpha(in,AVStr(tagn),8);
				if( inScript && strcasecmp(tagn,"SCRIPT") == 0
				 || inStyle  && strcasecmp(tagn,"STYLE") == 0
				){
					ch = getc(in);
					if( ch == '>' ){
						if( strcaseeq(tagn,"SCRIPT") )
							inScript--;
						if( strcaseeq(tagn,"STYLE") )
							inStyle--;
					}
				}
			}
		}
            }else
	    if( ch == '<' ){
		ch = getc(in);
		if( ch == EOF )
			break;
		if( ch == '!' ){
			/*
			CStr(comment,64);
			*/
			CStr(comment,128);
			if( skipComment(in,AVStr(comment),sizeof(comment)) == EOF )
				break;
			if( strcaseeq(comment,"--X-Body-of-Message--")
			 || strcaseeq(comment,"-- body=\"start\" --")
			 || strcaseeq(comment,"--beginarticle--")
			){
				fseek(tmp,bodyoff,0);
			}
			if( strheadstrX(comment,"--X-Date:",1) ){
				IStr(fval,64);
				Xsscanf(comment,"%*s %[^\n]",AVStr(fval));
				Mtime = scanNNTPtime(fval);
			}

			if( strncasecmp(comment,"-- email=",9) == 0 ){
				valuescanX(comment+9,AVStr(authcand),sizeof(authcand));
			}
			if( strncasecmp(comment,"--X-From-R13:",13) == 0 ){
				const char *xp;
				lineScan(comment+13,authcand);
				if( xp = strstr(authcand,"--") )
					truncVStr(xp);
				/*
				strrot13(authcand);
				 */
				xstrrot13(AVStr(authcand));
				strsubst(AVStr(authcand),"&#45;","-");
			}
			continue;
		}
		if( ch == '?' ){
			while( !feof(in) ){
				if( getc(in) == '?' )
				if( getc(in) == '>' )
					break;
			}
			continue;
		}

		if( end = (ch == '/') ){
			ch = getc(in);
		}
		if( !isalpha(ch) ){
			pushch = '<';
			ungetc(ch,in);
			if( end )
				ungetc('/',in);

			if( opt_d )
			fprintf(stderr,"## UNGET TAG <%s%c ##\n",end?"/":"",ch);
			continue;
		}
		ech = fscanTag(in,ch,AVStr(tag),sizeof(tag));
		if( ech != '>' ){
			if( opt_d )
			fprintf(stderr,"## UNGET TAG <%s%s ##\n",end?"/":"",tag);
		}
		/*
		dp = wordScan(tag,tagn);
		*/
		dp = wordScanY(tag,tagn,"^ \t\r\n.,:;'\"<>{}()[]\\/?&%=~^|@*`");

		if( strcasecmp(tagn,"noindex") == 0 ){
			inNoindex = end ? 0 : 1;
		}else
		if( strcasecmp(tagn,"A") == 0 ){
			inAnchor += end ? 0 : 1;
		}
		if( strcasecmp(tagn,"HEAD") == 0 ){
			inHead += end ? 0 : 1;
		}else
		if( strcasecmp(tagn,"TABLE") == 0 ){
			if( end ){
				inTableData = 0;
				inAnchor = 0;
			}
		}else
		if( strcasecmp(tagn,"TD") == 0 ){
			inTableData = end ? 0 : 1;
		}else
		if( strcasecmp(tagn,"SCRIPT") == 0 ){
			inScript += end ? -1 : 1;
		}else
		if( strcasecmp(tagn,"STYLE") == 0 ){
			inStyle += end ? -1 : 1;
		}else
		if( strcasecmp(tagn,"TITLE") == 0 ){
			inTitle = end ? 0 : 1;
			if( inTitle && (Title < tip) ){
				/* multiple TITLE tags */
				if( 1 )
				{ /* fix-140527e ignore secondary TITLE */
					inTitle = 0;
				}else
				if( !isspace(tip[-1]) ){
					setVStrPtrInc(tip,' ');
				}
			}
		}else
		if( (tagn[0]=='H' || tagn[0]=='h') && isdigit(tagn[1]) ){
			if( !end && htp != Heads && htp < htx )
				setVStrPtrInc(htp,',');
			inHeading = end ? 0 : atoi(tag+1);
		}else
		if( strcasecmp(tagn,"LINK") == 0 ){
			if( scanLink(dp,AVStr(nam),sizeof(nam),AVStr(con),sizeof(con))==0 )
			if( strcasecmp(nam,"MADE") == 0 ){
				decodeEntitiesX(con,AVStr(Author),sizeof(Author),1);
				if( adp = strchr(Author,'?') )
					setVStrPtrInc(adp,0);
				adp = Author + strlen(Author);
			}
		}else
		if( strcasecmp(tagn,"HTML") == 0 ){
			scanAttrs(dp,4,"LANG",AVStr(Lang),sizeof(Lang),NULL,VStrNULL,0);
		}else
		if( strcasecmp(tagn,"META") == 0 ){
			if( scanMeta(dp,AVStr(nam),sizeof(nam),AVStr(con),sizeof(con)) == 0 ){
			if( strcasecmp(nam,"AUTHOR") == 0 ){
				decodeEntitiesX(con,AVStr(Author),sizeof(Author),1);
				adp = Author + strlen(Author);
			}else
			if( strcasecmp(nam,"REVISED") == 0 ){
				Mtime = scanNNTPtime(con);
			}else
			if( strcasecmp(nam,"COPYRIGHT") == 0 ){
				decodeEntitiesX(con,QVStr(ddp,Address),ddx-ddp,1);
				ddp += strlen(ddp);
			}else
			if( strcasecmp(nam,"SUBJECT") == 0 ){
				decodeEntitiesX(con,AVStr(Title),sizeof(Title),1);
				tip += strlen(tip);
			}else
			if( strcasecmp(nam,"DESCRIPTION") == 0 ){
				decodeEntitiesX(con,AVStr(Descr),sizeof(Descr),1);
			}else
			if( strcasecmp(nam,"KEYWORDS") == 0 ){
				decodeEntitiesX(con,AVStr(Keywd),sizeof(Keywd),1);
			}
			else
			if( strcasecmp(nam,"Content-Location") == 0 ){
				decodeEntitiesX(con,AVStr(Location),sizeof(Location),1);
			}
			else
			if( strcasecmp(nam,"Last-Modified") == 0 ){
				int mtime = scanHTTPtime(con);
				if( mtime == 0 || mtime == -1 ){
					fprintf(stderr,"Illegal Date: %s %s\n",
						con,apath);
					Mtime = 1;
				}else{
					Mtime = mtime;
				}
			}
			}
		}else
		if( strcaseeq(tagn,"A") && scanHREF(dp,AVStr(con),sizeof(con))==0
		 /* new-140524j index FORM ACTON and SRC IMG too */
		 || strcaseeq(tagn,"FORM") && scanACTION(dp,AVStr(con),sizeof(con))==0
		 || strcaseeq(tagn,"IMG") && scanSRC(dp,AVStr(con),sizeof(con))==0
		 || strcaseeq(tagn,"FRAME") && scanSRC(dp,AVStr(con),sizeof(con))==0
		){
			/* new-140524l index relative URL too */
			if( !isFullURL(con) )
			if( *con != '#' )
			{
				makeFullUrl(apath,AVStr(con)); /* fix-140817e */
			}

			/*
			if( strncmp(con,"http://",7) == 0 )
			*/
			if( isFullURL(con) ) /* new-140524l */
			if( strlen(con) < lkx-lkp-1 ){
				if( isinListX(Links,con,"\n") ){ /* fix-140817f */
					/* don't add a link duplicatedly */
				}else
				if( 0 ){
					/* Should ignore links within the document?
					 * But it maybe useful if self?xxx and
					 * self#yyy can be searchable.
					 */
				}else{
					QStrncpy(lkp,con,lkx-lkp);
					lkp += strlen(lkp);
					setVStrPtrInc(lkp,'\n');
				}
			}
			else{
				sv1log("--Links buffer(%dKbytes) overflow, ignored: %s\n",
					sizeof(Links)/1024,con);
			}
			if( authcand[0] == 0 )
			/* if( inHead || inAddress ) */
			if( strncasecmp(con,"mailto:",7) == 0 ){
				const char *qp;
				if( qp = strchr(con,'?') )
					truncVStr(qp);
				wbstrcpy(AVStr(authcand),authcand+(sizeof(authcand)-1),con,0);
			}
		}else
		if( strcasecmp(tagn,"ADDRESS") == 0 ){
			inAddress = end ? 0 : 1;
		}
	    }else
	    if( ch == '&' ){
		CStr(buf,16);
		int bi = 0;
		setVStrElemInc(buf,bi,ch); /**/
		while( bi < sizeof(buf)-1 ){
			ch = getc(in);
			if( ch == EOF )
				break;
			setVStrElemInc(buf,bi,ch); /**/
			if( ch != '#' && !isalnum(ch) )
				break;
		}
		setVStrEnd(buf,bi);
		if( bi == 6
		 && ch != ';'
		 && strchr(" &<>",ch)
		 && strncaseeq(buf,"&nbsp",5)
		){
			pushch = BUFFED;
			strcpy(buffed," ");
			ungetc(ch,in); /* maybe typo */
		}else
		if( ch == ';' ){
			if( strcaseeq(buf,"&nbsp;") ){
				pushch = ' ';
			}else{
				CStr(ob,32);
				decodeEntitiesX(buf,AVStr(ob),sizeof(ob),1);
				if( ob[0] != '&' || ob[1] == 0 )
					pushch = ob[0];
				else{
					if( ob[1] == '#' ){
						IStr(xb,64);
						if( ccxUchar(ob,AVStr(xb),64) ){
							pushch = BUFFED;
							FStrncpy(buffed,xb);
						}
					}else{
						pushch = BUFFED;
						FStrncpy(buffed,buf);
					}
				}
			}
		}else{
			backseek(in,strlen(buf));
			asis = 1;
			if( opt_d )
			fprintf(stderr,"## UNGET ENT [%s%c] ##\n",buf,ch);
		}
	    }else INCHAR:{
		if( ch != '\n' && Isspace(apath,ch) && preisspace ){
		}else{
			preisspace = Isspace(apath,ch);
			if( inTitle ){
				if( ch == BUFFED ){
					strcpy(tip,buffed);
					tip += strlen(tip);
				}else
				if( tip < tix )
				if( ch != '\n' && ch != '\r' )
					setVStrPtrInc(tip,ch);
				continue;
			}
			if( inHeading ){
				if( ch == BUFFED ){
					strcpy(htp,buffed);
					htp += strlen(htp);
				}else
				if( htp < htx )
				if( ch != '\n' && ch != '\r' )
					setVStrPtrInc(htp,ch);
			}
			if( inAddress ){
				if( ch == BUFFED ){
					strcpy(ddp,buffed);
					ddp += strlen(ddp);
				}else
				if( ddp < ddx ){
					if( ch == '\n' || ch == '\r' )
						ch = ' ';
					if( ch != ' ' || pch != ' ' )
						setVStrPtrInc(ddp,ch);
				}
			}

			if( inNoindex ){
				/* new-140527f <noindex>text</noindex> */
			}else
			if( textWasPut == 0
			 && ((inTableData && inAnchor) || isspace(ch))
			){
				/* ignore heading spaces and anchors */
			}else
			/*
			if( ch == '\n' && ite ){
			*/
			if( ch == '\n' && pch == '\n' ){
			}else{
				if( ch == BUFFED ){
					fputs(buffed,tmp);
				}else{
					/*
					if(ch==CH_COPYR && !CCXwithJP((CCXP)Ccx)){
					*/
					if( !ccx_oututf
					 && ch == CH_COPYR
					 && !CCXwithJP((CCXP)Ccx)
					){
						fputs("&copy;",tmp);
					}else{
						putc(ch,tmp);
					}
				}
				pch = ch;
				textWasPut++;
			}
		}
	    }
	}
	setVStrEnd(tip,0);
	setVStrEnd(htp,0);
	setVStrEnd(adp,0);
	setVStrEnd(ddp,0);
	setVStrEnd(lkp,0);

	if( authcand[0] ){
		if( Author[0] ){
		}else{
			wbstrcpy(AVStr(Author),Author+(sizeof(Author)-1),authcand,0);
		}
	}
	if( Author[0] ){
		url_unescape(AVStr(Author),AVStr(Author),sizeof(Author),"\"@ <>/?");
	}
}

char *valuescanJ(PCStr(src),PVStr(buf),int siz){
	const char *sp = src;
	int sc;
	int in2B = 0;
	int qch = 0;
	refQStr(bp,buf);

	sp = src;
	while( isspace(*sp) )
		sp++;
	if( *sp == '"' || *sp == '\'' )
		qch = *sp++;
	else	qch = 0;

	for(; (sc = *sp); sp++ ){
		if( sc == 033 ){
			if( sp[1] == '$' )
				in2B = 1;
			else
			if( sp[1] == '(' )
				in2B = 0;
		}
		if( qch ){
			if( !in2B && sc == qch ){
				sp++;
				break;
			}
		}else{
			if( !in2B && isspace(sc) )
				break;
		}
		if( bp ){
			setVStrPtrInc(bp,sc);
		}
	}
	if( bp ){
		setVStrEnd(bp,0);
	}
	return (char*)sp;
}
char *valueskipJ(PCStr(sp)){
	char *se;
	se = valuescanJ(sp,VStrNULL,0);
	return (char*)se;
}

/* to be moved into library */
int scanAttrs(PCStr(src),int an,PCStr(nam1),PVStr(val1),int vsiz1,PCStr(nam2),PVStr(val2),int vsiz2)
{	const char *nam;
	refQStr(val,val1); /**/
	const char *dp;
	int ai,vsiz,got;
	int in2B = 0;

	got = 0;
	dp = src;
	for( ai = 0; ai < an; ai++ ){
		if( *dp == 033 ){
			if( dp[1] == '$' )
				in2B = 1;
			else
			if( dp[1] == '(' )
				in2B = 0;
		}
		if( in2B ){
			continue;
		}

		while( isspace(*dp) ) dp++;
		if( *dp == '/' && dp[1] == '>' ){
			/* "<META ... />" ? strange but used */
			break;
		}
		if( *dp == '>' )
			break;
		if( strncasecmp(dp,nam1,strlen(nam1)) == 0 ){
			nam = nam1; cpyQStr(val,val1); vsiz = vsiz1;
		}else
		if( nam2 && strncasecmp(dp,nam2,strlen(nam2)) == 0 ){
			nam = nam2; cpyQStr(val,val2); vsiz = vsiz2;
		}else{
			for(; *dp && *dp != '='; dp++ );
			if( *dp != '=' )
				break;
			dp = valueskipJ(dp+1);
			/*
			int qch;
			qch = *++dp;
			if( qch == '"' || qch == '\'' ){
				for( dp++; *dp && *dp != qch; dp++);
				if( *dp == qch )
					dp++;
			}else{
				for(; *dp && !isspace(*dp); *dp++);
			}
			*/
			continue;
		}

		dp += strlen(nam);
		while( isspace(*dp) ) dp++;
		if( *dp == '=' ){
			dp = valuescanJ(dp+1,AVStr(val),vsiz);
			/*
			dp++;
			while( isspace(*dp) ) dp++;
			dp = valuescanX(dp,ZVStr(val,vsiz),vsiz);
			if( *dp == '"' || *dp == '\'' )
				dp++;
			*/
			got++;
		}
	}
	return got;
}
int scanHREF(PCStr(src),PVStr(href),int size)
{
	setVStrEnd(href,0);
	if( scanAttrs(src,4, "HREF",AVStr(href),size, NULL,VStrNULL,0) == 1 )
		return 0;
	return -1;
}
int scanACTION(PCStr(src),PVStr(href),int size)
{
	setVStrEnd(href,0);
	if( scanAttrs(src,4, "ACTION",AVStr(href),size, NULL,VStrNULL,0) == 1 )
		return 0;
	return -1;
}
int scanSRC(PCStr(src),PVStr(href),int size)
{
	setVStrEnd(href,0);
	if( scanAttrs(src,4, "SRC",AVStr(href),size, NULL,VStrNULL,0) == 1 )
		return 0;
	return -1;
}
int scanLink(PCStr(src),PVStr(nam),int nsiz,PVStr(con),int csiz)
{ 
	setVStrEnd(con,0);
	setVStrEnd(nam,0);
	if( scanAttrs(src,4, "REL",AVStr(nam),nsiz, "HREF",AVStr(con),csiz) == 2
	 || scanAttrs(src,4, "REV",AVStr(nam),nsiz, "HREF",AVStr(con),csiz) == 2
	)
		return 0;
	return -1;
}
int scanMeta(PCStr(src),PVStr(nam),int nsiz,PVStr(con),int csiz)
{ 
	setVStrEnd(con,0);
	setVStrEnd(nam,0);
	if( scanAttrs(src,4, "NAME",AVStr(nam),nsiz, "CONTENT",AVStr(con),csiz) == 2 )
		return 0;
	if( scanAttrs(src,4, "HTTP-EQUIV",AVStr(nam),nsiz, "CONTENT",AVStr(con),csiz) == 2 )
		return 0;
	return -1;
}
int fscanTag(FILE *in,int ch,PVStr(tag),int tsiz)
{	refQStr(tp,tag); /**/
	const char *tx;
	char quote;
	int pch = 0;

	quote = 0;
	cpyQStr(tp,tag);
	tx = tag + (tsiz-1);
	while( tp < tx && ch != EOF ){
		if( ch == '\'' || ch == '"' ){
			if( quote && quote != ch ){
			}else
			if( quote == 0 )
				quote = ch;
			else	quote = 0;
		}
		if( quote == 0 && ch == '>' )
			break;

		if( ch == '\n' || ch == '\r' )
			ch = ' ';
		if( !(isspace(ch) && isspace(pch)) )
			setVStrPtrInc(tp,ch);
		pch = ch;
		ch = getc(in);
		if( pch == '>' && quote ){
			/* may be unbalanced quote */
			if( ch == '\r' || ch == '\n' )
			if( strncaseeq(tag,"META ",5) )
			if( strncaseeq(tag+5,"HTTP-EQUIV=",11) )
			{
				setVStrEnd(tp,0);
				fprintf(stderr,"???? <%s ????\n",tag);
				break;
			}
		}
	}
	setVStrEnd(tp,0);
	return ch;
}
int skipComment(FILE *in,PVStr(comment),int siz)
{	int ch1,ch,pch,comlev;
	refQStr(cp,comment); /**/
	const char *xp;

	ch1 = -1;
	pch = -1;
	comlev = 1;
	xp = comment + (siz-1);
	cpyQStr(cp,comment);
	while( (ch = getc(in)) != EOF ){
		if( ch1 == -1 )
			ch1 = ch;

		if( pch == '<' && (ch == '-' || ch1 != '-') ){
			comlev++;
		}else
		if( (pch == '-' || ch1 != '-') && ch == '>' ){
			comlev--;
			if( comlev == 0 )
				break;
		}
		pch = ch;
		if( cp < xp ){
			setVStrPtrInc(cp,ch);
		}
	}
	setVStrEnd(cp,0);
	return ch;
}
const char *strskip(PCStr(s),PCStr(p))
{	const char *tp;

	if( tp = strstr(s,p) )
		return tp + strlen(p);
	else	return 0;
}

static FILE *Tmps[8];
FILE *getTmp(int ti)
{
	if( Tmps[ti] == NULL )
		Tmps[ti] = tmpfile();
	else{
		clearerr(Tmps[ti]);
		fseek(Tmps[ti],0,0);
	}
	return Tmps[ti];
}
void fflushTmp(FILE *fp)
{
	fflush(fp);
	IGNRETZ ftruncate(fileno(fp),(off_t)ftell(fp));
	fseek(fp,0,0);
}
int sysfilter(PCStr(filter),FILE *in,FILE *out)
{	int sv0,sv1;
	FILE *pfp;
	int ac;
	const char *av[32];
	CStr(argb,1024);

	sv0 = dup(0); dup2(fileno(in),0);
	sv1 = dup(1); dup2(fileno(out),1);

	if( strncmp(filter,"-exec ",6) == 0 ){
		if( fork() == 0 ){
			ac = decomp_args(av,elnumof(av),filter,AVStr(argb));
			Execvp("sysfilter",av[1],&av[1]);
			exit(-1);
		}
	}else{
		IGNRETZ system(filter);
	}
	wait(0);
	dup2(sv1,1); close(sv1);
	dup2(sv0,0); close(sv0);
	return 0;
}

void getCharset(PCStr(where),PVStr(charset),PCStr(fval))
{	const char *dp;

	if( dp = strcasestr(fval,"charset=") ){
		valuescanX(dp+8,AVStr(charset),32);
		if( strcaseeq(charset,"none")
		 || strcaseeq(charset,"guess")
		){
			setVStrEnd(charset,0);
		}
	}
}
int extractAuthor(PCStr(str),PCStr(top),PVStr(author),int size,PCStr(url),int dump)
{	const char *cp;
	char ch;
	char pch;
	refQStr(dp,author); /**/

	cp = (char*)top; /* cp for top is "const" but reuse for non-const */
	while( isspace(*cp) )
		cp++;

	if( 128 < size )
		size = 128;
	wbstrcpy(AVStr(author),author+(size-1),cp,0);

	pch = 0;
	cpyQStr(dp,author);
	for( cp = author; ch = *cp; cp++ ){
		if( ch == '\n' && isspace(pch) )
			continue;
		if( isspace(ch) && pch == '\n' )
			continue;
		pch = ch;
		if( ch == '\n' )
			ch = ' ';
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);

	if( cp = strcasestr(author,"All Right") )
		truncVStr(cp);
	for( cp = author; *cp; cp++ ){
		if( strchr("0123456789/-.,() ",*cp) == 0 )
			break;
	}
	if( cp != author )
		strcpy(author,cp);

	for( cp = author; *cp; ){
		if( *cp == ':'
		 || *cp == ';'
		 || *cp == '('
		 || *cp == '|'
		 || *cp == '.' && cp[1] == ' '
		 || *cp == ' ' && cp[1] == ' '
		 || *cp == '-' && cp[1] == ' '
		){
			truncVStr(cp);
			break;
		}
		cp++;
	}
	for( cp = author+strlen(author)-1; author <= cp; cp-- ){
		ch = *cp;
		if( strchr(" ,.0123456789-/",ch) == 0 )
			break;
		if( isdigit(ch) && author < cp && isalpha(cp[-1]) )
			break;
		truncVStr(cp);
	}
	if( strncmp(author,"by ",3) == 0 )
		ovstrcpy((char*)author,author+3);
	if( strcmp(author,"by") == 0 )
		setVStrEnd(author,0);

	if( opt_d || dump )
	fprintf(stderr,"#%d#AUTHOR[%s]%d\n#%d#[%s]%s\n",
		NumPut,author,guessedAuthor, NumPut,str,url);

	if( author[0] != 0 ){
		int nsp = 0;
		const char *ap;
		for( ap = author; *ap; ap++ ){
			if( *ap == ' ' ){
				++nsp;
				if( 4 < nsp && 40 < (ap-author) ){
					truncVStr(ap);
					break;
				}
			}
		}
		return 0;
	}else{
		return 1;
	}
}
int copy2auth(PCStr(copyr),PVStr(author),int size,PCStr(url),int force)
{	const char *cp;
	const char *np;
	const char *acp;

	int ok = 0;
	int dump = 0;

	if( cp = strstr(copyr,"&copy;") ){
		ok = 1;
		acp = strstr(copyr,"by ");
		if( acp && acp < cp ){ /* by xxx &copy; */
			truncVStr(cp);
			cp = acp;
		}else{
			cp += 6;
			while( isspace(*cp) )
				cp++;
			if( strncaseeq(cp,"Copyright",9) )
				cp += 9;
		}
	}else
	if( cp = strcasestr(copyr,"Copyright") ){
		cp += 9;
		if( strneq(cp,"ed",2) )
			cp += 2;
		if( *cp == ':' )
			cp++;
		for(;;){
			while( isspace(*cp) )
				cp++;
			if( strncasecmp(cp,"(C)",3) == 0 ){
				cp += 3;
				ok = 1;
				break;
			}
			if( (0xFF & *cp) == CH_COPYR ){ /* &copy; */
				cp += 1;
				ok = 1;
				break;
			}
			if( isdigit(*cp) ){
				int y = atoi(cp);
				if( 1900 < y && y < 2100 ){
					cp += 4;
					ok = 1;
					continue;
				}
			}
			if( np = strcasestr(cp,"Copyright") ){
				cp = np + 9;
				continue;
			}
			break;
		}
		if( !ok ){
			if( strcasestr(cp,"All Right") != NULL ){
			/*
			fprintf(stderr,"#### ALLRIGHT %s",copyr);
			*/
			}else
			if( *cp == 0 ){
				return 1;
			}else{
				return 0;
			}
		}
	}else
	if( cp = strcasestr(copyr,"All Rights") ){
		while( isspace(*cp) )
			cp++;
		if( cp = strcasestr(cp,"Reserved by") ){
			cp += 11;
		}else{
			return 0;
		}
	}else
	if( force ){
		cp = (char*)copyr;
	}else{
		return 0;
	}
	return extractAuthor(copyr,cp,AVStr(author),size,url,dump);
}
/* if outcode==UTF8, or do ccx for each char ? */
int UTF8toEUC(CCXP ccx,PCStr(utf),PVStr(out),int siz);
int ccxUchar(PCStr(ob),PVStr(xub),int siz){
	unsigned int uch;
	unsigned IStr(ub,128);

	if( ob[2] == 'x' ){
		sscanf(ob+3,"%X",&uch);
	}else
	if( '0' <= ob[2] && ob[2] <= '9' ){
		sscanf(ob+2,"%d",&uch);
	}else{
		return 0;
	}
	toUTF8(uch,ub);
	if( ccx_oututf ){
		strcpy(xub,(char*)ub);
	}else{
		UTF8toEUC((CCXP)Ccx,(char*)ub,BVStr(xub),siz);
	}
	return 1;
}
static int isMultiBytesChar(const char *sp){
        unsigned const char *up;
        up = (unsigned const char*)sp;
        if( up[0] == (0x80|'$') && (up[1] == (0x80|')'))
         && up[2] == (0x80|'$') && (up[3] & 0x80)
         && up[4] == (0x80|'$') && (up[5] & 0x80)
         && up[6] == (0x80|'$') && (up[7] & 0x80)
         && up[8] == (0x80|'$') && (up[9] & 0x80)
        ){
                return 10;
        }
        return 0;
}
char *wbstrcpy(PVStr(dst),PCStr(dx),PCStr(src),int len)
{	refQStr(dp,dst); /**/
	const char *sp;
	char ch;
	int ic,in2B;
	int cleng;

/*
int l1,l2;
if(len == 0){
QStrncpy(dst,src,dx-dst+1);
l1 = strlen(dst);
}
*/
	cpyQStr(dp,dst);
	in2B = 0;
	ic = 1; /* reserve for terminator */
	for( sp = src; (len == 0 || ic < len) && (ch = *sp); sp++ ){
		if( cleng = isMultiBytesChar(sp) ){
			if( dx <= dp+cleng ){
				break;
			}
			strncpy(dp,sp,cleng+1);
			dp += cleng;
			sp += cleng - 1;
			continue;
		}
		/*
		if( dx <= dp )
		*/
		if( dx-1 <= dp )
			break;
		setVStrPtrInc(dp,ch);
		ic++;
		if( in2B == 0 ){
			if( ch & 0x80 )
				in2B = 1;
		}else{
			in2B = 0;
		}
	}
	if( in2B ){
		dp--;
	}
	setVStrPtrInc(dp,0);
/*
if(len == 0 ){
l2 = strlen(dst);
if(l1 != l2)printf("A=%d/B=%d/len=%d/in2B=%d\nA: %s\nB: %s\n",
l2,l1,strlen(src),in2B,src,dst);
}
*/
	return (char*)dp;
}

int toFullpathPATH(PCStr(searchpath),PCStr(file),PCStr(mode),PVStr(fullpath),int size)
{	CStr(pathenv,1024);
	const char **vpath;
	FILE *xfp;

	if( searchpath == 0 )
		return 0;
	lineScan(searchpath,pathenv);
	vpath = vect_PATH(pathenv);
	if( xfp = fopen_PATH(vpath,file,mode,AVStr(fullpath)/*,size*/) ){
		fclose(xfp);
		return 1;
	}
	return 0;
}
int toFullpathENV(PCStr(envname),PCStr(file),PCStr(mode),PVStr(execpath),int size)
{	const char *env;

	if( isFullpath(file) ){
		QStrncpy(execpath,file,size);
		return 3;
	}
	if( 0 <= File_size(file) ){
		IGNRETS getcwd((char*)execpath,size);
		chdir_cwd(AVStr(execpath),file,1);
		return 2;
	}
	linescanX(file,AVStr(execpath),size);
	if( env = getenv("PATH") ){
		return toFullpathPATH(env,execpath,"r",AVStr(execpath),size);
	}
	return 0;
}
int xrealpath(PCStr(path),PVStr(rpath),int size)
{	int len;
	const char *dp;
	CStr(link,256);

	len = readlink(path,link,QVZsizeof(link));
	if( len <= 0 )
		return 0;
	setVStrEnd(link,len);

	linescanX(path,AVStr(rpath),size);
	if( dp = strrchr(rpath,'/') ){
		if( dp[1] != 0 )
			truncVStr(dp);
	}
	chdir_cwd(AVStr(rpath),link,1);
	return 1;
}

int isRFC822(FILE *fp)
{	int off,non,fnam,nlen,nf,ic,ch,rcc,ufrom;
	CStr(head,5);

	nf = 0;
	non = 0;
	fnam = 1;
	nlen = 1;

	off = ftell(fp);
	rcc = fread(head,1,5,fp);
	if( rcc != 5 )
		goto EXIT;
	if( ufrom = (strncmp(head,"From ",5) == 0) ){ /* Unix mailbox format */
		for(;;){
			ch = getc(fp);
			if( ch == EOF )
				goto EXIT;
			if( ch == '\n' )
				break;
		}
		ic = ftell(fp) - off;
	}else{
		fseek(fp,off,0);

if(off != ftell(fp)){
  fprintf(stderr,"isRFC822: SEEK ERROR %d %d\n",iftell(fp),off);
  sleep(1);
}
		ic = 0;
	}

	for(; ic < 1024; ic++ ){
		ch = getc(fp);
		if( ch == EOF )
			break;
		if( ch == 0 ){
			non = 1;
			break;
		}
		if( ch == '\r' ){
			ch = getc(fp);
			if( ch != '\n' ){
				non = 2;
				break;
			}
			ungetc(ch,fp);
			continue;
		}
		if( fnam ){
			if( nlen == 0 && ch == '\n' ){
				break;
			}
			if( isalnum(ch) || 0<nlen && ch=='-' ){
				nlen++;
			}else
			if( ch == ':' ){
				if( nlen == 0 ){
					non = 3;
					break;
				}
				fnam = 0;
			}else{
				non = 4;
				break;
			}
		}else{
			if( ch == '\n' ){
				ch = getc(fp);
				if( ch == ' ' || ch == '\t' ){
					/* continue */
				}else{
					nf++;
					if( 5 < nf )
						break;
					ungetc(ch,fp);
					fnam = 1;
					nlen = 0;
				}
			}
		}
	}
EXIT:
	if( feof(fp) )
		clearerr(fp);
	fseek(fp,off,0);
	if( !non && 1 < nf )
		return ic;

/*
 fprintf(stderr,"## ufrom=%d non=%d nf=%d ch=%X nlen=%d\n",
 ufrom,non,nf,ch,nlen);
*/
	return -ic;
}

void backseek(FILE *in, int disp){
	int soff = ftell(in);
	int diff;

#ifndef _MSC_VER
	fflush(in); /* to avoid loop on Linux */
#endif
	fseek(in,-disp,1);

	diff = soff - ftell(in);
	if( diff != disp ){
		fprintf(stderr,"#### backseek error %d %d\n",
			diff,disp);
		usleep(100000);
	}
}

static double Prev;
static double Prev1;
static void Lap(int force,int outlen,PCStr(fmt),...)
{	double Now;
	VARGS(8,fmt);

	Now = Time();
	if( Prev == 0 )
	{
		Prev = Now;
		Prev1 = Now;
	}
	if( !force && (Now-Prev) < 5 )
		return;

	fprintf(stderr,"+++ %6.2f %4.2f ", Now-Start,Now-Prev1);
	if( 0 < outlen ){
		fprintf(stderr,
			"%5d %5d (%5.1f docs/s / %6d bytes/s) %d bytes\n",
			NumAny,NumPut, NumPut/(Now-Start),
			(int)(outlen/(Now-Start)), outlen);
	}else
	if( fmt ){
		fprintf(stderr,fmt,VA8);
	}
	if( force == 0 )
	Prev = Now;
	Prev1 = Now;
}

/*
 * @ABCDEFGHIJKLMNOPQRSTUVWXYZ[acdefghijklmnopqrstuvwxyz
 * NOPQRSTUVWXYZ[@ABCDEFGHIJKLMnopqrstuvwxyzacdefghijklm
 */
int xstrrot13(PVStr(str)){
	char *s = (char*)str;
	int ch;
	for( s = (char*)str; ch = *s; s++ ){
		if( '@' <= ch && ch <= 'M' ) *s = ch + 14; else
		if( 'N' <= ch && ch <= '[' ) *s = ch - 14; else
		if( 'a' <= ch && ch <= 'm' ) *s = ch + 13; else
		if( 'n' <= ch && ch <= 'z' ) *s = ch - 13;
	}
	return 0;
}

int fromUTF8(const unsigned char *us,unsigned int *uch)
{	unsigned char uc0,ucx;
	int leng,mask,lx;
	unsigned int uc4;

	uc4 = 0;
	uc0 = *us;
	if( (uc0 & 0x80) == 0 ){ leng = 1; }else
	if( (uc0 & 0x40) == 0 ){ leng = 1;
		uc0 = '?';
	}else
	if( (uc0 & 0x20) == 0 ){ leng = 2; }else
	if( (uc0 & 0x10) == 0 ){ leng = 3; }else
	if( (uc0 & 0x08) == 0 ){ leng = 4; }else
	if( (uc0 & 0x04) == 0 ){ leng = 5; }else
	if( (uc0 & 0x02) == 0 ){ leng = 6; }else{
		leng = 1;
	}
	if( leng == 1 ){
		uc4 = uc0;
	}else{
		mask = 0xFF >> (leng+1);
		uc4 = uc0 & mask;
		for( lx = 1; lx < leng; lx++ ){
			ucx = us[lx];
			if( (ucx & 0xC0) != 0x80 ){
				if( uch ) *uch = uc0;
				return leng;
			}
			uc4 = (uc4 << 6) | (0x3F & ucx);
		}
	}
	if( uch ) *uch = uc4;
	return leng;
}
int isUTF8chr(const char *sp){
	unsigned int uch;
	int leng;
	leng = fromUTF8((const unsigned char*)sp,&uch);
	return leng;
}
int isUTF8str(const char *sp){
	int si;
	unsigned int uch;
	int leng;
	for( si = 0; sp[si]; sp++ ){
		if( sp[si] & 0x80 ){
			leng = fromUTF8((const unsigned char*)sp,&uch);
			return leng;
		}
	}
	return 0;
}

int scanCCode(FILE *in,FILE *out,const char *apath){
	int ch;
	int nch;
	int ich;
	int pch = 0;
	int inComment = 0;
	int numComments = 0;

	while( (ch = getc(in)) != EOF ){
		if( inComment ){
			if( ch == '*' ){
				nch = getc(in);
				if( nch == '/' ){
					inComment = 0;
					continue;
				}else{
					ungetc(nch,in);
				}
			}
			if( numComments == 1 ){
				continue;
			}
			break;
		}else{
			if( ch == '/' ){
				nch = getc(in);
				if( nch == '*' ){
					numComments += 1;
					inComment = 1;
					continue;
				}else{
					ungetc(nch,in);
				}
			}
		}
		if( ch == '\n' ){
			nch = getc(in);
			if( nch == '#' ){
				ich = 0;
				while( (nch = getc(in)) != EOF ){
					if( nch == '\n' ){
						if( ich != '\\' ){
							ungetc(nch,in);
							break;
						}
					}
					ich = nch;
				}
				continue;
			}
			ungetc(nch,in);
		}
		if( ch != EOF ){
			if( pch == '\n' && ch == '\n' ){
			}else{
				putc(ch,out);
			}	
			pch = ch;
		}
	}
	while( (ch = getc(in)) != EOF ){
		putc(ch,out);
	}
	return 0;
}
