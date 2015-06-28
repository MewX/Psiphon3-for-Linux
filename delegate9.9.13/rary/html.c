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
Program:	html.c (HTML entity encoder/decoder)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	HTMLCONV=uri:{convTypeList}:{AttrList/EntityList}
	URICONV=convTypeList:AttrList/EntityList
	convType = {full,mount,normal,partial}

	EXAMPLE:
		URICONV="mount,normal,partial:+"
		URICONV="full:+,-HREF/BASE"

History:
	941002	extracted from http.c
	990331	extracted attrWithURL() and made it custmizable
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include <stdio.h>
#include <ctype.h>

#ifdef _MSC_VER
typedef unsigned __int64 SymIdInt;
#else
#ifdef __LONG_LONG_MAX__
typedef unsigned long long int SymIdInt;
#else
typedef unsigned long int SymIdInt;
#endif
#endif

/*
#define isAlpha(ch)	(isalpha(ch) || ch == '-')
*/
/*
#define isAlpha(ch)	(isalpha(ch) || ch == '-' || ch == '!' || ch == '#' )
*/
#define isAlpha(ch)	(isalpha(ch)|| ch=='-'|| ch=='!'|| ch=='#'|| ch=='?')

int DECODE_HTML_ENTITIES = 1;
int ENCODE_HTML_ENTITIES = 0;
int PLAIN_TO_HTML_PRE = 0;
int HTMLCONV_DEBUG = 0;
int URL_SEARCH;
static void addTAGelem(PCStr(name));
static void addTAGattr(PCStr(attr));
void setKillTags(PCStr(stags));
void setURIconv(PCStr(conv));
void setURICONVdefault(int force);
void dumpHTMLCONV();

static scanListFunc hconv1(PCStr(conv))
{	int onoff;

	if( *conv == '!' || *conv == '-' ){
		conv++;
		onoff = 0;
	}else	onoff = 1;

	if( streq(conv,"fullurl") ){
		setURIconv("mount:+");
		setURIconv("full:+,-HREF/BASE");
		return 0;
	}else
	if( streq(conv,"partial") ){
		setURIconv("partial");
		return 0;
	}else
	if( streq(conv,"normal") ){
		setURIconv("normal");
		return 0;
	}

	if( streq(conv,"debug") )  HTMLCONV_DEBUG = onoff; else
	if( streq(conv,"enent") )  ENCODE_HTML_ENTITIES = onoff; else
	if( streq(conv,"deent") )  DECODE_HTML_ENTITIES = onoff; else
	if( streq(conv,"pre")   )  PLAIN_TO_HTML_PRE    = onoff; else
	if( streq(conv,"dump")  )  dumpHTMLCONV(); else
	if( strncmp(conv,"defelem:",8) == 0 ) addTAGelem(conv+8); else
	if( strncmp(conv,"defattr:",8) == 0 ) addTAGattr(conv+8); else
	if( strncmp(conv,"uri:",4) == 0 ) setURIconv(conv+4); else
	if( strncmp(conv,"killtag:",8) == 0 ) setKillTags(conv+8); else
	syslog_ERROR("Error: unknown HTML conversion spec: %s\n",conv);
	return 0;
}
int scan_URICONV(void *_,PCStr(conv))
{
	if( streq(conv,"where:any") ) URL_SEARCH = /*ANY*/0xFFFF; else
	if( streq(conv,"dump") )	dumpHTMLCONV(); else
	if( streq(conv,"+") )		setURICONVdefault(0); else
	if( strneq(conv,"defelem:",8) )	addTAGelem(conv+8); else
	if( strneq(conv,"defattr:",8) )	addTAGattr(conv+8); else
					setURIconv(conv);
	return 0;
}
int scan_HTMLCONV(void *_,PCStr(clist))
{
	ENCODE_HTML_ENTITIES = 0;
	DECODE_HTML_ENTITIES = 0;
	scan_commaList(clist,0,scanListCall hconv1);
	return 0;
}

int NumBits(int i32)
{	int i,n,m;

	n = 0;
	m = 1;
	for( i = 0; i < 32; i++ ){
		if( i32 & m ) n++;
		m <<= 1;
	}
	return n;
}
int NumBitsSymId(SymIdInt id)
{	int i,n;
	SymIdInt m;

	n = 0;
	m = 1;
	for( i = 0; i < sizeof(id)*8; i++ ){
		if( id & m ) n++;
		m <<= 1;
	}
	return n;
}

typedef struct {
  const	char	*_sym;
	SymIdInt	 _id;
/*
	int	 _id;
*/
} SymID;
static scanListFunc addsym1(PCStr(sym),SymID *tab)
/*
{	int ai,id1,maxid,newid;
*/
{	int ai;
	SymIdInt id1,maxid,newid;
	const char *sym1;
	CStr(symb,128);
	const char *sp;
	char sc;

	strcpy(symb,sym);
	sym = symb;
	for( sp = sym; sc = *sp; sp++ )
		if( islower(sc) )
			*(char*)sp = toupper(sc); /**/

	maxid = 0;
	for( ai = 0; sym1 = tab[ai]._sym; ai++ ){
		if( strcasecmp(sym1,sym) == 0 )
			return 0;
		id1 = tab[ai]._id;
		/*
		if( NumBits(id1) == 1 )
		*/
		if( NumBitsSymId(id1) == 1 )
		if( (id1 & 0xF) != 0xF && maxid < id1 )
			maxid = id1;
	}
	/* 0x40000000 <= maxid, because of signed 32bits int comparison
	 * it must be long long int
	 */
	if( maxid != 0 )
		newid = maxid << 1;
	else	newid = 1;
	tab[ai]._sym = stralloc(sym);
	tab[ai]._id = newid;
	tab[ai+1]._sym = 0;
	syslog_ERROR("HTMLCONV ADDSYMID [%d][%s][%x]\n",ai,sym,ll2i(tab[ai]._id));
	return 0;
}
static void addsyms(SymID *tab,PCStr(syms))
{
	if( syms[0] == '+' && syms[1] == ',' )
		syms += 2;
	else	tab[2]._sym = 0; /* [0] for "*" and [1] for "+" */
	scan_commaListL(syms,0,scanListCall addsym1,tab);

/* consistency with rules must be checked after addsyms / clear symtab */
}
/*
static int sym2id(SymID *tab,PCStr(sym))
*/
static SymIdInt sym2id(SymID *tab,PCStr(sym))
{	int ai;
	const char *sym1;

	for( ai = 0; sym1 = tab[ai]._sym; ai++ )
		if( strcaseeq(sym,sym1) )
			return tab[ai]._id;
	return 0;
}
/*
static const char *id2sym0(SymID *tab,int id)
*/
static const char *id2sym0(SymID *tab,SymIdInt id)
{	int ai,id1;

	for( ai = 0; id1 = tab[ai]._id; ai++ )
		if( id == id1 )
			return tab[ai]._sym;
	return NULL;
}
/*
static const char *id2sym(SymID *tab,int id)
*/
static const char *id2sym(SymID *tab,SymIdInt id)
{	const char *sym;

	if( sym = id2sym0(tab,id) )
		return sym;
	else	return "";
}
/*
static scanListFunc sym1(PCStr(sym),SymID *tab,int *maskp)
*/
static scanListFunc sym1(PCStr(sym),SymID *tab,SymIdInt *maskp)
{
	*maskp |= sym2id(tab,sym);
	return 0;
}

/* Light weight screening of names to be cared.
 * Possible locations (Nth character in a name) of each character
 * in all of names to be cared are indicated as the Nth bits of
 * each (short) integer for each character.
 */
typedef struct {
	int	n_initDone;
	short	n_chars[256]; /**/
	int	n_maxLen;
} NameScreen;
static void initNameScreen(SymID *tab,NameScreen *nmap)
{	int ai,ci;
	const char *ap;
	char ac;

	for( ai = 0; ap = tab[ai]._sym; ai++ ){
		if( isAlpha(*ap) )
		for( ci = 0; ci < 16 && (ac = ap[ci]); ci++ )
			nmap->n_chars[toupper(ac) & 0xFF] |= (1 << ci);
		if( nmap->n_maxLen < ci )
			nmap->n_maxLen = ci;
	}
	nmap->n_initDone = 1;
}
static int scanNameScreen(SymID *tab,NameScreen *nmap,PCStr(astr),PVStr(asym))
{	refQStr(op,asym); /**/
	char uc,ac;
	int ci;
	int maxlen,alen;

	/*
	 *	Setup the table for screening attribute names
	 */
	if( nmap->n_initDone == 0 )
		initNameScreen(tab,nmap);

	/*
	 *	Screening attribute names
	 */
	uc = toupper(astr[0]);
	if( (nmap->n_chars[uc & 0xFF] & 1) == 0 )
		return 0;

	maxlen = nmap->n_maxLen;
	for( ci = 0; ci < maxlen && (ac = astr[ci]); ci++ ){
		if( !isAlpha(ac) )
			break;
		uc = toupper(ac);
		if( (nmap->n_chars[uc & 0xFF] & (1 << ci)) == 0 )
			return 0;
		setVStrPtrInc(op,uc);
	}
	if( op == asym )
		return 0;
	setVStrEnd(op,0);
	alen = op - asym;
	return alen;
}

#define NCONVS 64

/* type of URL conversions */
#define C_MOUNTF	0x0001	/* URLs in forwarding */
#define C_MOUNTR	0x0002	/* URLs in response */
#define C_MOUNTD	0x0004	/* -_- notation */
#define C_MOUNT		0x0007
#define C_NORMAL	0x0010
#define C_PARTIAL	0x0020
#define C_FULL		0x0040
#define C_ANY		0x0077
#define C_DEFAULTS	(C_MOUNT|C_NORMAL|C_PARTIAL)
#define C_DEFAULTA	(C_MOUNT|C_NORMAL)
#define C_REQ		0x0100	/* required */
#define C_SPL		0x0200	/* list separated with space */

#define C_XML		0x0800

#define C_SSI		0x1000
#define C_META		0x2000
#define C_APPLET	0x4000	/* conversion for APPLET */
#define C_JAVA		0x8000	/* conversion for Java {APPLET|OBJECT|EMBED} */
#define C_KILL		0x10000 /* disable tag */

int URICONV_MOUNTF =	C_MOUNTF;
int URICONV_MOUNTR =	C_MOUNTR;
int URICONV_MOUNTD =	C_MOUNTD;
int URICONV_MOUNT =	C_MOUNT;
int URICONV_NORMAL =	C_NORMAL;
int URICONV_PARTIAL =	C_PARTIAL;
int URICONV_FULL =	C_FULL;
int URICONV_ANY	=	C_ANY;
int TAGCONV_XML =	C_XML;
int TAGCONV_SSI =	C_SSI;
int TAGCONV_META =	C_META;
int TAGCONV_APPLET =	C_APPLET;
int TAGCONV_JAVA =	C_JAVA;
int TAGCONV_KILL =	C_KILL;

int URICONV_nMOUNTF;
int URICONV_nMOUNTR;
int URICONV_nMOUNTD;
int URICONV_nMOUNT;
int URICONV_nNORMAL;
int URICONV_nPARTIAL;
int URICONV_nFULL;
int TAGCONV_nKILL;

static SymID convsym[NCONVS] = {
	"*",		C_ANY,
	"mountF",	C_MOUNTF,
	"mountR",	C_MOUNTR,
	"mountD",	C_MOUNTD,
	"mount",	C_MOUNT,
	"normal",	C_NORMAL,
	"partial",	C_PARTIAL,
	"full",		C_FULL,
	"killtag",	C_KILL,
	"+",		C_DEFAULTS,

	"required",	C_REQ,
	"splist",	C_SPL,

	"xml",		C_XML,

	"ssi",		C_SSI,
	"meta",		C_META,
	"applet",	C_APPLET,
	"java",		C_JAVA,
	0,
};

/* tag's element names */
#define E_UNKNOWN	0x80000000
#define E_ANY		0xFFFFFFFF
#define E_A		0x00000001
#define E_APPLET	0x00000002
#define E_AREA		0x00000004
#define E_BASE		0x00000008
#define E_BLOCKQUOTE	0x00000010
#define E_BODY		0x00000020
#define E_DEL		0x00000040
#define E_FORM		0x00000080
#define E_FRAME		0x00000100
#define E_HEAD		0x00000200
#define E_IFRAME	0x00000400
#define E_IMG		0x00000800
#define E_INPUT		0x00001000
#define E_INS		0x00002000
#define E_LINK		0x00004000
#define E_OBJECT	0x00008000
#define E_Q		0x00010000
#define E_SCRIPT	0x00020000
#define E_EMBED		0x00040000

#define E_Header	0x00080000
#define E_X_META	0x00100000
/* HTTP header and META HTTP-EQUIV should be identified as a context ? */

#define E_DEFINEDS	0x001FFFFF

#define E_XML		0x00800000

#define E_X_ECHO	0x01000000
#define E_X_INCLUDE	0x02000000
#define E_X_FSIZE	0x04000000
#define E_X_FLASTMOD	0x08000000
#define E_X_EXEC	0x10000000
#define E_X_CONFIG	0x20000000
#define E_X_SSITAGS	0x3F000000
#define E_OTHER		0x40000000

static SymID elemsym[NCONVS] = {
	"*",		E_ANY,
	"+",		E_DEFINEDS,
	"A",		E_A,
	"APPLET",	E_APPLET,
	"AREA",		E_AREA,
	"BASE",		E_BASE,
	"BLOCKQUOTE",	E_BLOCKQUOTE,
	"BODY",		E_BODY,
	"DEL",		E_DEL,
	"EMBED",	E_EMBED,
	"FORM",		E_FORM,
	"FRAME",	E_FRAME,
	"HEAD",		E_HEAD,
	"IFRAME",	E_IFRAME,
	"IMG",		E_IMG,
	"INPUT",	E_INPUT,
	"INS",		E_INS,
	"LINK",		E_LINK,
	"OBJECT",	E_OBJECT,
	"Q",		E_Q,
	"SCRIPT",	E_SCRIPT,
	"Header",	E_Header,

	"?xml",		E_XML,

	"META",		E_X_META,
	"!--#echo",	E_X_ECHO,
	"!--#include",	E_X_INCLUDE,
	"!--#fsize",	E_X_FSIZE,
	"!--#flastmod",	E_X_FLASTMOD,
	"!--#exec",	E_X_EXEC,
	"!--#config",	E_X_CONFIG,
	"ssitags",	E_X_SSITAGS,

	"TABLE",	E_OTHER,
	"TR",		E_OTHER,
	"TD",		E_OTHER,
	0,
};
static void addTAGelem(PCStr(name)){ addsyms(elemsym,name); }

char TAGCONV_TAGEND[] =	"-"; /* pseudo attribute for end of tag */

/* tag's attribute names */
#define A_ANY		0xFFFFFFFF
#define A_ACTION	0x00000001
#define A_ARCHIVE	0x00000002
#define A_BACKGROUND	0x00000004
#define A_CITE		0x00000008
#define A_CLASSID	0x00000010
#define A_CODEBASE	0x00000020
#define A_DATA		0x00000040
#define A_HREF		0x00000080
#define A_LONGDESC	0x00000100
#define A_PROFILE	0x00000200
#define A_SRC		0x00000400
#define A_USEMAP	0x00000800
#define A_IMAGEMAP	0x00001000
#define A_SCRIPT	0x00002000
#define A_URL		0x00004000
#define A_Location	0x00008000
#define A_ContLocation	0x00010000
#define A_Set_Cookie	0x00020000
#define A_DEFINEDS	0x0003FFFF

#define A_CODE		0x00100000
#define A_END		0x00200000

#define A_ENCODING	0x00800000

#define A_X_HTTPEQUIV	0x01000000
#define A_X_VAR		0x02000000
#define A_X_FILE	0x04000000
#define A_X_VIRTUAL	0x08000000
#define A_X_FILES	(A_X_FILE|A_X_VIRTUAL)
#define A_X_CMD		0x10000000
#define A_X_CGI		0x20000000
#define A_X_CMDS	(A_X_CMD|A_X_CGI|A_X_VIRTUAL)
#define A_X_TIMEFMT	0x40000000
#define A_X_SIZEFMT	0x80000000
/*
#define A_X_CONFIGS	(A_X_TIMEFMT|A_X_SIZEFMT)
*/
#define A_X_CONFIGS	(A_X_TIMEFMT|A_X_SIZEFMT|A_X_VAR)

static SymID attrsym[NCONVS] = {
	"*",		A_ANY,
	"+",		A_DEFINEDS,
	"ACTION",	A_ACTION,
	"ARCHIVE",	A_ARCHIVE,
	"BACKGROUND",	A_BACKGROUND,
	"CITE",		A_CITE,
	"CLASSID",	A_CLASSID,
	"CODE",		A_CODE,
	"CODEBASE",	A_CODEBASE,
	"DATA",		A_DATA,
	"HREF",		A_HREF,
	"LONGDESC",	A_LONGDESC,
	"PROFILE",	A_PROFILE,
	"SRC",		A_SRC,
	"USEMAP",	A_USEMAP,
	"IMAGEMAP",	A_IMAGEMAP,
	"SCRIPT",	A_SCRIPT,
	"URL",		A_URL,
	"Location",	A_Location,
	"Content-Location",A_ContLocation,
	"Set-Cookie",	A_Set_Cookie,
	TAGCONV_TAGEND,	A_END,

	"encoding",	A_ENCODING,

	"HTTP-EQUIV",	A_X_HTTPEQUIV,
	"var",		A_X_VAR,
	"file",		A_X_FILE,
	"virtual",	A_X_VIRTUAL,
	"cgi",		A_X_CGI,
	"cmd",		A_X_CMD,
	"timefmt",	A_X_TIMEFMT,
	"sizefmt",	A_X_SIZEFMT,
	0,
};
static void addTAGattr(PCStr(attr)){ addsyms(attrsym,attr); }


#if 0
typedef struct {
	int	 a_convtype;
	int	 a_id; /* atrribute */
	int	 a_context; /* tag */
} Attr;
#endif
typedef struct {
	int	 a_convtype;
	SymIdInt a_id; /* atrribute */
	SymIdInt a_context; /* tag */
} Attr;

typedef struct {
	NameScreen a_AttrNames;
	Attr	r_Attr[NCONVS*2];
	int	r_AttrInit;
	int	r_AttrX;
	int	a_Serno;
} HtmlConv;
static HtmlConv *htmlConvs;
void minit_html()
{
	if( htmlConvs == 0 )
		htmlConvs = NewStruct(HtmlConv);
}
#define htmlConv	htmlConvs[0]
#define attrNames	htmlConv.a_AttrNames
#define	rewriteAttr	htmlConv.r_Attr
#define	rewriteAttrInit	htmlConv.r_AttrInit
#define	rewriteAttrX	htmlConv.r_AttrX
#define attrSerno	htmlConv.a_Serno

static Attr rewriteAttrDefault[NCONVS] = {
{C_DEFAULTS|C_REQ,A_ACTION,	E_FORM			},
{C_DEFAULTS|C_SPL,A_ARCHIVE,	E_OBJECT		},
{C_DEFAULTS,A_BACKGROUND,	E_BODY			},
{C_DEFAULTS,A_CITE,		E_BLOCKQUOTE |E_Q |E_DEL |E_INS},
{C_DEFAULTS,A_CLASSID,		E_OBJECT		},
{C_DEFAULTS,A_CODEBASE,		E_OBJECT |E_APPLET	},
{C_DEFAULTS,A_DATA,		E_OBJECT		},
{C_DEFAULTS,A_HREF,		E_A |E_AREA |E_LINK	},
{C_DEFAULTA,A_HREF,		E_BASE			},
{C_DEFAULTS,A_LONGDESC,		E_IMG |E_FRAME |E_IFRAME},
{C_DEFAULTS,A_PROFILE,		E_HEAD			},
{C_DEFAULTS|C_REQ,A_SRC,	E_IMG},
{C_DEFAULTS,A_SRC,		E_INPUT |E_SCRIPT |E_FRAME |E_IFRAME},
{C_DEFAULTS,A_USEMAP,		E_IMG |E_INPUT |E_OBJECT},

{C_DEFAULTA,A_IMAGEMAP,		E_ANY}, /* obsolete ? */
{C_DEFAULTA,A_SCRIPT,		E_ANY}, /* obsolete ? */
{C_DEFAULTA,A_URL,		E_ANY}, /* obsolete ? */

{C_DEFAULTA,A_ContLocation,	E_Header},
{C_DEFAULTA,A_Location,		E_Header}, /* to be supported ? */
{C_DEFAULTA,A_Set_Cookie,	E_Header}, /* to be supported ? */

{C_XML,     A_ENCODING,         E_XML},

{C_META,    A_X_HTTPEQUIV,      E_X_META},
{C_SSI,     A_X_VAR,		E_X_ECHO},
{C_SSI,     A_X_FILES,		E_X_INCLUDE},
{C_SSI,     A_X_FILES,		E_X_FSIZE},
{C_SSI,     A_X_FILES,		E_X_FLASTMOD},
{C_SSI,     A_X_CMDS,		E_X_EXEC},
{C_SSI,     A_X_CONFIGS,	E_X_CONFIG},

{C_JAVA,    A_CODE|A_END,	E_APPLET |E_EMBED |E_OBJECT},
{C_APPLET,  A_CODE|A_END,	E_APPLET},

{C_DEFAULTS,A_BACKGROUND,	E_OTHER},
0
};

static int list2mask(SymID *tab,PCStr(list))
/*
{	int mask;
*/
{	SymIdInt mask;

	mask = 0;
	scan_commaList(list,0,scanListCall sym1,tab,&mask);
	return mask;
}
static void mask2list(SymID *tab,int mask,PVStr(list))
{	int mi;
	refQStr(bp,list); /**/
	const char *sym;
	int flag;

	for( mi = 0; mi < 32; mi++ ){
		flag = 1 << mi;
		if( tab == convsym
		&& (flag & C_MOUNT) && (mask & C_MOUNT) == C_MOUNT ){
		  if( (1 << mi) == C_MOUNTF ){
			if( bp != list ) setVStrPtrInc(bp,',');
			sym = id2sym0(tab,C_MOUNT);
			strcpy(bp,sym);
			bp += strlen(bp);
		  }
		}else
		if( flag & mask ){
			if( bp != list ) setVStrPtrInc(bp,',');
			sym = id2sym0(tab,flag);
			strcpy(bp,sym);
			bp += strlen(bp);
		}
	}
	setVStrEnd(bp,0);
}

/*
static void uconv0(int convtype,int tags,int attr,int negate)
*/
static void uconv0(int convtype,SymIdInt tags,SymIdInt attr,int negate)
{	int ri;
	int found;
	Attr *ap;
	CStr(list,128);

	found = 0;
	for( ri = 0; ri < rewriteAttrX; ri++ ){
		ap = &rewriteAttr[ri];
		if( ap->a_context & tags )
		if( ap->a_id & attr ){
			found++;
			if( negate )
				ap->a_convtype &= ~convtype;
			else	ap->a_convtype |=  convtype;
		}
	}
	if( !negate && !found ){
		ap = &rewriteAttr[rewriteAttrX++];
		ap->a_id = attr;
		ap->a_context = tags;
		ap->a_convtype = convtype;

		mask2list(convsym,convtype,AVStr(list));

		if( HTMLCONV_DEBUG )
		syslog_DEBUG("URICONV[%d] %s:%s/%s (%x/%x)\n",
			rewriteAttrX,
			list,
			id2sym(attrsym,attr),
			id2sym(elemsym,tags),
			ll2i(attr),ll2i(tags));
	}
}
/*
static void uconvx(int convtype,int tags,int attr,int negate)
*/
static void uconvx(int convtype,SymIdInt tags,SymIdInt attr,int negate)
{	int ti,ai;
/*
	unsigned int amask,tmask;
*/
	SymIdInt amask,tmask,tm,am;

	tmask = tags;
	for( ti = 0; tmask; ti++ ){
		if( tmask & 1 ){
			amask = attr;
			for( ai = 0; amask; ai++ ){
				if( amask & 1 )
				{
					/*
					uconv0(convtype,(1<<ti),(1<<ai),negate);
					*/
					tm = 1; tm <<= ti;
					am = 1; am <<= ai;
					uconv0(convtype,tm,am,negate);
				}
				amask = (amask >> 1);
			}
		}
		tmask = (tmask >> 1);
	}
}
/*
static void uconvm(int convtype,int tags,int attr,int negate)
*/
static void uconvm(int convtype,SymIdInt tags,SymIdInt attr,int negate)
{	int lattr,ltags;
	Attr *ap;

	if( tags == E_ANY || attr == A_ANY ){
		uconv0(convtype,tags,attr,negate);
		return;
	}
	if( tags == E_DEFINEDS && attr == A_DEFINEDS ){
		for( ap = rewriteAttrDefault; ap->a_id; ap++ )
			if( ap->a_context == E_ANY )
				uconv0(convtype,ap->a_context,ap->a_id,negate);
			else	uconvx(convtype,ap->a_context,ap->a_id,negate);
		return;
	}
	if( tags == E_DEFINEDS && attr != A_DEFINEDS ){
		ltags = 0;
		for( ap = rewriteAttrDefault; ap->a_id; ap++ )
			if( ap->a_id == attr )
				ltags |= ap->a_context;
		tags = ltags;
	}else
	if( tags != E_DEFINEDS && attr == A_DEFINEDS ){
	}
	uconvx(convtype,tags,attr,negate);
}
static scanListFunc uconv1(PCStr(convspec),int convtype)
{	CStr(sconv,256);
	CStr(sattr,256);
	CStr(stags,256);
/*
	int attr,tags;
*/
	SymIdInt attr;
	SymIdInt tags;
	int negate;

	if( *convspec == '!' || *convspec == '-' ){
		negate = 1;
		convspec++;
	}else	negate = 0;
	majorminorScan(convspec,sattr,stags);
	if( *sattr == 0 ) strcpy(sattr,"+");
	if( *stags == 0 ) strcpy(stags,"+");

	tags = sym2id(elemsym,stags);
	attr = sym2id(attrsym,sattr);

	uconvm(convtype,tags,attr,negate);
	return 0;
}

static scanListFunc tagmask1(PCStr(stag),int *maskp)
/*
{	int itag;
*/
{	SymIdInt itag;

	itag = sym2id(elemsym,stag);
	*maskp |= itag;
	return 0;
}
int HTML_TagMask(PCStr(stags))
{	int itags;

	itags = 0;
	scan_commaListL(stags,0,scanListCall tagmask1,&itags);
	return itags;
}
static void count_convs(int convtype);
void setKillTags(PCStr(stags))
{	int itags;

	itags = HTML_TagMask(stags);
	count_convs(C_KILL);
	uconvm(C_KILL,itags,A_END,0);
}

static void setURIconvDefault(int convtypes)
{	int ri;
	Attr *ap;

	if( HTMLCONV_DEBUG )
		syslog_DEBUG("HTMLCONV: setURIconvDefault\n");

	for( ri = rewriteAttrX; ri < NCONVS; ri++ ){
		ap = &rewriteAttrDefault[ri];
		if( ap->a_convtype == 0 )
			break;
		count_convs(ap->a_convtype);
		uconvm(ap->a_convtype,ap->a_context,ap->a_id,0);
		if( rewriteAttr[ri].a_id == 0 )
			break;
	}
}
void setURICONVdefault(int force){
	if( force || rewriteAttrInit == 0 ){
		setURIconvDefault(0);
		rewriteAttrInit = 1;
	}
}
static void count_convs(int convtype)
{
	if( convtype & C_MOUNTF	) URICONV_nMOUNTF++;
	if( convtype & C_MOUNTR	) URICONV_nMOUNTR++;
	if( convtype & C_MOUNTD	) URICONV_nMOUNTD++;
	if( convtype & C_MOUNT	) URICONV_nMOUNT++;
	if( convtype & C_PARTIAL) URICONV_nPARTIAL++;
	if( convtype & C_FULL	) URICONV_nFULL++;
	if( convtype & C_KILL   ) TAGCONV_nKILL++;
	if( convtype & C_NORMAL	) URICONV_nNORMAL++;
}
void setURIconv(PCStr(conv))
{	CStr(sconvtype,128);
	CStr(convlist,1024);
	int attr;
	int convtype;

	rewriteAttrInit++;
	fieldScan(conv,sconvtype,convlist);
	if( *conv == 0 ){
		/* URICONV="" means clearing URICONV */
		return;
	}
	if( *sconvtype == 0 ) strcpy(sconvtype,"+");
	if( *convlist  == 0 ) strcpy(convlist,"+");

	convtype = list2mask(convsym,sconvtype);
	count_convs(convtype);
	scan_commaListL((const char*)convlist,0,scanListCall uconv1,convtype);
}

static int sym2tid(PCStr(tag))
{	CStr(tsym,32);
	refQStr(op,tsym); /**/
	const unsigned char *tp;
	const char *ox;
/*
	int tid;
*/
	SymIdInt tid;

/*
	tid = E_ANY;
*/
	tid = E_UNKNOWN;
	if( tag != 0 ){
		tp = (unsigned char *)tag;
		if( *tp == '<' ){
			tp++;
			if( *tp == '/' )
			{
/* | E_END */
				tp++;
			}
		}
		while( isspace(*tp) )
			tp++;
		ox = tsym + sizeof(tsym) - 1;
		while( isAlpha(*tp) )
		{	if( ox <= op )
				break;
			setVStrPtrInc(op,*tp++);
		}
		setVStrEnd(op,0);
		tid = sym2id(elemsym,tsym);
		if( tid == 0 )
/*
			tid = E_ANY;
*/
			tid = E_UNKNOWN;
	}
	return tid;
}

int HTML_attrTobeConv(PCStr(attr),PCStr(tag),int *uconvp)
{	int ai,ri;
	CStr(asym,32);
	int tid,aid,alen,aidmask;
	int uconv,ruconv;
	Attr *rp;
	int altno;

	setURICONVdefault(0);
	alen = scanNameScreen(attrsym,&attrNames,attr,AVStr(asym));
	if( alen <= 0 )
		return 0;
	aid = sym2id(attrsym,asym);

	/*
	 *	Searching a rule for the attribute
	 */
	if( uconvp ){
		uconv = *uconvp;
		*uconvp = 0;
	}else	uconv = URICONV_ANY;

	attrSerno++;
	altno = 0;
	tid = 0;

	for( ri = 0; ri < rewriteAttrX; ri++ ){
		rp = &rewriteAttr[ri];
		aidmask = rp->a_id;
		/* aid is 0 if not in A_DEFINEDS */
		if( (aidmask & aid) || aidmask == A_ANY ){
			if( tid == 0 )
				tid = sym2tid(tag);
			if( HTMLCONV_DEBUG ){
				syslog_DEBUG(
				"URICONV:%4d.%d %s <%-6s %-6s>[%5x/%5x]\n",
				attrSerno,++altno,
				rp->a_context & tid ? "*":" ",
				id2sym(elemsym,tid),
				id2sym(attrsym,rp->a_id),
				ll2i(rp->a_context),tid);
			}
			if( rp->a_context & tid ){
				ruconv = rp->a_convtype;
				if( ruconv & uconv ){
					if( uconvp )
					{
						if(URICONV_nFULL & 0x8000)
							ruconv |= URICONV_FULL;
						*uconvp = ruconv;
					}
					return alen;
				}
			}
		}
	}
	return 0;
}

void dumpHTMLCONV(){
	CStr(buff,4096);
	refQStr(bp,buff); /**/
	const char *sym;
/*
	int si,ri,ci,aid,ctx,nput;
*/
	int si,ri,ci,nput;
	SymIdInt aid;
	SymIdInt ctx;
	Attr *rp;

	if( ENCODE_HTML_ENTITIES ){
		strcpy(bp,"HTMLCONV=enent\n");
		bp += strlen(bp);
	}
	if( DECODE_HTML_ENTITIES ){
		strcpy(bp,"HTMLCONV=deent\n");
		bp += strlen(bp);
	}

	setURICONVdefault(0);

	bp += strlen(strcpy(bp,"URICONV=defelem:{"));
	for( si = 2; sym = elemsym[si]._sym; si++ ){
		if( 2 < si ) setVStrPtrInc(bp,',');
		bp += strlen(strcpy(bp,sym));
	}
	setVStrPtrInc(bp,'}');
	setVStrPtrInc(bp,'\n');
	bp += strlen(strcpy(bp,"URICONV=defattr:{"));
	for( si = 2; sym = attrsym[si]._sym; si++ ){
		if( 2 < si ) setVStrPtrInc(bp,',');
		bp += strlen(strcpy(bp,sym));
	}
	setVStrPtrInc(bp,'}');
	setVStrPtrInc(bp,'\n');
	for( ri = 0; ri < rewriteAttrX; ri++ ){
		rp = &rewriteAttr[ri];
		if( rp->a_convtype == 0 )
			continue;
		sprintf(bp,"URICONV=");
		bp += strlen(bp);
		mask2list(convsym,rp->a_convtype,AVStr(bp));
		bp += strlen(bp);
		setVStrPtrInc(bp,':');

		aid = rp->a_id;
		ctx = rp->a_context;
		if( ctx == E_ANY ){
			sprintf(bp,"%s/*",id2sym(attrsym,aid));
			bp += strlen(bp);
		}else{
		  nput = 0;
		  for( ci = 0; ci < 32; ci++ ){
		    if( (1 << ci) & ctx ){
			if( nput != 0 ) setVStrPtrInc(bp,',');
			sprintf(bp,"%s/%s",
			id2sym(attrsym,aid),id2sym(elemsym,(1<<ci)));
			bp += strlen(bp);
			nput++;
		    }
		  }
		}
		setVStrPtrInc(bp,'\n');
	}
	setVStrEnd(bp,0);
	syslog_ERROR("\n### HTMLCONV configuration:\n%s",buff);
	return;
}

/*######################################################################*/
static struct {
  const	char	*ee;
	char	 de;
} entities[] = {
	{"&lt;",	'<'},
	{"&gt;",	'>'},
	{"&amp;",	'&'},
	{"&quot;",	'"'},
/*
MSIE does not recognize this.
	{"&apos;",	'\''},
*/
	{"&#39;",	'\''},
/* ESC char for UTF-7 */
/*
	{"&#43;",	'+'},
*/
	0
};

int isHTMLentity(PCStr(str),int *chp)
{	int ei,ej;
	const char *es;
	char ec;
	const char *sp;
	int off;

	off = *str == '&' ? 0 : 1;
	for( ei = 0; es = entities[ei].ee; ei++ ){
		for( ej = 0; ec = es[off+ej]; ej++ ){
			if( ec != str[ej] )
				break;
			if( ec == ';' ){
				*chp = entities[ei].de;
				return ej+1;
			}
		}
	}
	return 0;
}

/*
 *  Decode mal-encoded entities in ISO-2022 multibyte charset text.
 */
void decodeEntities(const char*,PVStr(d),int);
void decodeEntitiesX(PCStr(src),PVStr(dst),int siz,int anywhere);
void decode_entities(PCStr(src),PVStr(dst))
{
	if( DECODE_HTML_ENTITIES == 0 ){
		strcpy(dst,src);
		return;
	}
	decodeEntities(src,BVStr(dst),0);
}
void decodeEntities(PCStr(src),PVStr(dst),int anywhere)
{
	decodeEntitiesX(src,BVStr(dst),strlen(src)+1,anywhere);
}
void decodeEntitiesX(PCStr(src),PVStr(dst),int siz,int anywhere)
{	const char *sp;
	refQStr(dp,dst); /**/
	int ei,len;
	const char *ee;
	int in2byte;
	const char *xp = dst + (siz - 1);

	in2byte = 0;
	for( sp = src; *sp; )
	{
		if( xp <= dp )
			break;
		if( *sp == 033 ){
			switch( sp[1] ){
				case '$': in2byte  = 1; break;
				case '(': in2byte  = 0; break;
			}
		}else
		if( (anywhere||in2byte) && *sp == '&' ){
			for( ei = 0; ee = entities[ei].ee; ei++ ){
				len = strlen(ee);
				if( strncmp(sp,ee,len) == 0 ){
					setVStrPtrInc(dp,entities[ei].de);
					sp += len;
					goto Next;
				}
			}
		}
		setVStrPtrInc(dp,*sp++);
	Next:;
	}
	setVStrEnd(dp,0);
}

int encodeEntitiesX(PCStr(src),PVStr(dst),int siz);
int encode_entitiesX(PCStr(src),PVStr(dst),int siz)
{
	alertVStr(dst,siz);
	if( ENCODE_HTML_ENTITIES == 0 ){
		QStrncpy(dst,src,siz); /**/
		return 0;
	}
	return encodeEntitiesX(src,BVStr(dst),siz);
}
static char entx[256];
int encodeEntitiesXX(PCStr(src),PVStr(dst),int siz,int opts);
int encodeEntitiesX(PCStr(src),PVStr(dst),int siz)
{
	return encodeEntitiesXX(src,BVStr(dst),siz,0);
}

int encodeEntitiesXX(PCStr(src),PVStr(dst),int siz,int opts)
{	int in2byte;
	const char *sp;
	const char *ep;
	refQStr(dp,dst); /**/
	char de;
	int ei,len;
	const char *xp;
	int nenc;
	char sc;

	alertVStr(dst,siz);
	nenc = 0;
	in2byte = 0;
	xp = dst + (siz - 1);

	if( entx[0] == 0 ) {
		for( ei = 0; ei < elnumof(entx); ei++ )
			entx[ei] = (char)-1;
		for( ei = 0; de = entities[ei].de; ei++ ){
			entx[0xFF & de] = ei;
		}
	}

	for( sp = src; sc = *sp; sp++ ){
		if( xp <= dp )
			break;
		if( !in2byte && (opts & HT_ISFORM)
		 && sc == '&' && sp[1] == '#' && isdigit(sp[2]) ){
			/* if encoding form-urlencoded */
			for( ep = sp+2; *ep; ep++ ){
				if( *ep == ';' )
					break;
				if( !isdigit(*ep) )
					break;
			}
			if( *ep == ';' ){
				for(; sp <= ep; sp++ ){
					setVStrPtrInc(dp,*sp);
					if( sp == ep )
						break;
				}
				continue;
			}
		}
		if( sc == 033 ){
			switch( sp[1] ){
				case '$': in2byte  = 1; break;
				case '(': in2byte  = 0; break;
			}
		}else
		if( !in2byte ){
			/*
			if( 0 <= (ei = entx[0xFF & sc]) ){
			*/
			ei = entx[0xFF & sc];
			if( 0 <= ei && ei < elnumof(entities)-1 ){
				strcpy(dp,entities[ei].ee);
				dp += strlen(dp);
				nenc++;
				goto Next;
			}
/*
			if( sc == '+' ){
				strcpy(dp,"&#43;");
				dp += strle(dp);
			}
*/
		}
		setVStrPtrInc(dp,sc);
	Next:;
	}
/*
	for( sp = src; *sp; sp++ ){
		if( xp <= dp )
			break;
		if( *sp == 033 ){
			switch( sp[1] ){
				case '$': in2byte  = 1; break;
				case '(': in2byte  = 0; break;
			}
		}else
		if( !in2byte ){
			for( ei = 0; de = entities[ei].de; ei++ ){
				if( *sp == de ){
					strcpy(dp,entities[ei].ee);
					dp += strlen(dp);
					nenc++;
					goto Next;
				}
			}
		}
		setVStrPtrInc(dp,*sp);
	Next:;
	}
*/
	setVStrEnd(dp,0);
	return nenc;
}

char *strpbrk1B(const void *src,PCStr(brks),char **dst,PVStr(dbuf))
{	const char *sp = (char*)src;
	char sch;
	refQStr(dp,dbuf); /**/
	char swch,bch;
	int si,bi;
	int in2byte = 0;
	int found = 0;

	dp = *dst;
	for( sp = (char*)src; sch = *sp; ){
		assertVStr(dbuf,dp+1);
		if( sch == 033 ){
			swch = sp[1];
			if( (swch == '$' || swch == '(') && sp[2] != 0 ){
				for( si = 0; si < 3; si++ )
					setVStrPtrInc(dp,*sp++);
				if( swch == '$' ) in2byte = 1; else
				if( swch == '(' ) in2byte = 0;
				continue;
			}
		}
		if( !in2byte ){
			for( bi = 0; bch = brks[bi]; bi++ )
				if( sch == bch ){
					found = 1;
					goto FOUND;
				}
		}
		setVStrPtrInc(dp,sch);
		sp++;
	}
FOUND:
	setVStrEnd(dp,0);
	*dst = (char*)dp;

	if( found )
		return (char*)sp;
	else	return 0;
}

void scan_html(PCStr(src),PVStr(dst),PCStr(stack))
{
}

#define HT_HEAD		0x0001
#define HT_PRE		0x0002
#define HT_BLOCKQUOTE	0x0004
#define HT_STYLE	0x0008

typedef struct {
	FILE *ht_in;
	FILE *ht_out;
	int ht_stat;
	int ht_inQuote;
	int ht_in2B;
	MStr(ht_tagname,128);
	int ht_inTag;
	int ht_inTagname;
	int ht_tags;
	int ht_bqlev;
	int ht_col;
	int ht_nnl;
	int ht_nsp;
	MStr(ht_inb,32);
	int ht_inbf;
	int ht_inbx;
	int ht_toHTML;
	int ht_inAttrname;
	MStr(ht_attrname,128);
	MStr(ht_attrvalue,4096);
	int ht_tagPUT;
	int ht_withCR;
} HTStat;

#define HS_TEXT		0x000000
#define HS_QUOTE	0x000001
#define HS_TAGNAME	0x000010
#define HS_ATTRNAME	0x000020
#define HS_ATTRNQUOTE	0x000120
#define HS_ATTRVALUE	0x000080
#define HS_ATTRVQUOTE	0x000180

#define htIn	Ht->ht_in
#define htOut	Ht->ht_out

#define htStat	Ht->ht_stat
#define inQuote	Ht->ht_inQuote
#define in2B	Ht->ht_in2B
#define inTag		(htStat & (HS_TAGNAME|HS_ATTRNAME|HS_ATTRVALUE))
#define inTagname	(htStat & HS_TAGNAME)
#define inAttrname	(htStat & HS_ATTRNAME)
#define inStyle		(htTags & HT_STYLE)

#define htTagname	Ht->ht_tagname
#define htTags	Ht->ht_tags
#define bqlev	Ht->ht_bqlev
#define htCol	Ht->ht_col
#define HtNnl	Ht->ht_nnl
#define HtNsp	Ht->ht_nsp
#define inb	Ht->ht_inb
#define inbf	Ht->ht_inbf
#define inbx	Ht->ht_inbx
#define Tgetc()	(inbx<inbf?(0xFF & inb[inbx++]) : getc(htIn))
#define toHTML	Ht->ht_toHTML
#define htAttrname	Ht->ht_attrname
#define htAttrvalue	Ht->ht_attrvalue
#define tagPUT	Ht->ht_tagPUT
#define withCR	Ht->ht_withCR

static int Htrace = 0;
#define HTRACE	Htrace==0?0:fprintf

static int setTags(HTStat *Ht){
	if( strcaseeq(htTagname,"head") )  htTags |=  HT_HEAD; else
	if( strcaseeq(htTagname,"/head") ) htTags &= ~HT_HEAD; else
	if( strcaseeq(htTagname,"body") )  htTags &=  HT_HEAD; else
	if( strcaseeq(htTagname,"pre") ){
		htTags |= HT_PRE;
		if( htCol != 0 ){
			if( withCR )
				putc('\r',htOut);
			putc('\n',htOut);
			htCol = 0;
		}
	}else
	if( strcaseeq(htTagname,"/pre") )   htTags &= ~HT_PRE; else
	if( strcaseeq(htTagname,"blockquote") )  htTags |= HT_BLOCKQUOTE; else
	if( strcaseeq(htTagname,"/blockquote") ) htTags &= ~HT_BLOCKQUOTE;

	if( strcaseeq(htTagname,"style") ) htTags |=  HT_STYLE; else
	if( strcaseeq(htTagname,"/style") ) htTags &= ~HT_STYLE;

	if( toHTML ){
		if( strcaseeq(htTagname,"b")
		 || strcaseeq(htTagname,"/b")
		 || strcaseeq(htTagname,"i")
		 || strcaseeq(htTagname,"/i")
		 || strcaseeq(htTagname,"p")
		 || strcaseeq(htTagname,"/p")
		 || strcaseeq(htTagname,"br")
		 || strcaseeq(htTagname,"/br")
		 || strcaseeq(htTagname,"pre")
		 || strcaseeq(htTagname,"/pre")
		 || strcaseeq(htTagname,"div")
		 || strcaseeq(htTagname,"/div")
		 || strcaseeq(htTagname,"font")
		 || strcaseeq(htTagname,"/font")
		 || strcaseeq(htTagname,"blockquote")
		 || strcaseeq(htTagname,"/blockquote")
		){
			fprintf(htOut,"<%s",htTagname);
			tagPUT = 1;
		}
	}else{
		if( strcaseeq(htTagname,"br") ){
			ungetc('\n',htIn);
		}
	}
/*
 fprintf(stderr,"-- %X %2d tag[%s]\n",htTags,htCol,htTagname);
*/
	return htTags;
}
static void doneAttr(HTStat *Ht){
	if( toHTML == 0 ){
		return;
	}
	if( htTags & HT_BLOCKQUOTE ){
		if( strcaseeq(htAttrname,"type") ){
			if( strcaseeq(htAttrvalue,"cite"))
				fputs(" TYPE=CITE",htOut);
		}
		/*
		if( strcaseeq(htAttrname,"cite") ){
			fprintf(htOut," CITE=\"%s\"",htAttrvalue);
		}
		*/
	}
	/*
	if( strcaseeq(htTagname,"font") ){
		if( strcaseeq(htAttrname,"face") )
			fprintf(htOut," FACE=\"%s\"",htAttrvalue);
	}
	*/
}

int HTMLtoTEXT(FILE *ain,FILE *aout,int toHtml){
	HTStat HtStat,*Ht = &HtStat;
	refQStr(tp,htTagname);
	refQStr(ap,htAttrname);
	refQStr(vp,htAttrvalue);
	int ch;
	int nch;

	bzero(&HtStat,sizeof(HtStat));
	htIn = ain;
	htOut = aout;
	toHTML = toHtml;

	while( 1 ){
		ch = Tgetc();
		if( ch == EOF ){
			break;
		}

		if( in2B ){
			putc(ch,htOut);
			if( ch == 033 ){
				ch = Tgetc();
				if( ch == '(' ){
					putc(ch,htOut);
					in2B = 0;
				}
			}
			continue;
		}
		if( ch == 033 ){
			putc(ch,htOut);
			ch = Tgetc();
			if( ch == '$' ){
				putc(ch,htOut);
				in2B = 1;
			}
			continue;
		}

		if( inTag ){
			if( ch == '>' ){
				if( inTagname ){
					setVStrEnd(tp,0);
					setTags(Ht);
HTRACE(stderr,"%d ->T tag[%s]\n",htStat,htTagname);
				}else
				if( inAttrname ){
					setVStrEnd(ap,0);
HTRACE(stderr,"%d ->N tag[%s] attr[%s]\n",htStat,htTagname,htAttrname);
				}else{
					setVStrEnd(vp,0);
					doneAttr(Ht);
HTRACE(stderr,"%d ->V tag[%s] attr[%s] val[%s]\n",
htStat,htTagname,htAttrname,htAttrvalue);
				}
				htStat = HS_TEXT;
				if( tagPUT ){
					putc('>',htOut);
					tagPUT = 0;
				}
				continue;
			}
			if( inTagname ){
				if( isspace(ch) ){
					setVStrEnd(tp,0);
					setTags(Ht);
					htStat = HS_ATTRNAME;
					ap = htAttrname;
					inQuote = 0;
				}else{
					setVStrPtrInc(tp,ch);
				}
			}else
			if( inAttrname ){
				if( ap == htAttrname
				 && (ch == '"' || ch == '\'') ){
					inQuote = ch;
				}else
				if( ch == inQuote ){
					setVStrEnd(ap,0);
					inQuote = 0;
HTRACE(stderr,"%d === valueonly[%s]\n",htStat,htAttrname);
					continue;
				}else
				if( inQuote ){
					setVStrPtrInc(ap,ch);
				}

				if( !inQuote )
				if( isspace(ch) || ch == '=' ){
					setVStrEnd(ap,0);
					ap = htAttrname;
					if( isspace(ch) ){
HTRACE(stderr,"%d === nameonly[%s]\n",htStat,htAttrname);
					}else{
						htStat = HS_ATTRVALUE;
						vp = htAttrvalue;
					}
HTRACE(stderr,"%d --- tag[%s] attr[%s]\n",
htStat,htTagname,htAttrname);
				}else{
					setVStrPtrInc(ap,ch);
				}
			}else{
				if( vp == htAttrvalue
				 && (ch == '"' || ch == '\'') ){
					inQuote = ch;
					continue;
				}else
				if( ch == inQuote ){
					setVStrEnd(vp,0);
					inQuote = 0;
HTRACE(stderr,"%d --Q tag[%s] attr[%s] value[%s]\n",
htStat,htTagname,htAttrname,htAttrvalue);
					doneAttr(Ht);
					htStat = HS_ATTRNAME;
					ap = htAttrname;
					continue;
				}else{
					if( !isspace(ch) )
						setVStrPtrInc(vp,ch);
				}
				if( !inQuote && isspace(ch) ){
					setVStrEnd(vp,0);
HTRACE(stderr,"%d --V tag[%s] attr[%s] value[%s]\n",
htStat,htTagname,htAttrname,htAttrvalue);
					doneAttr(Ht);
					htStat = HS_ATTRNAME;
					ap = htAttrname;
					inQuote = 0;
				}
			}
			continue;
		} /* TAG */
		if( ch == '<' ){
			htStat = HS_TAGNAME;
			tp = htTagname;
			continue;
		}
		if( htTags & HT_HEAD )
			continue;
		if( inStyle ){
			continue;
		}

		if( !toHTML ){
			if( ch == '&' ){
				int ei;
				inbf = inbx = 0;
				setVStrElem(inb,inbf,ch);
				inbf++;
				for( ei = 0; ei < 8; ei++ ){
					ch = getc(htIn);
					if( ch == EOF )
						break;
					setVStrElem(inb,inbf,ch);
					inbf++;
					if( ch == ';' ){
						break;
					}
				}
				setVStrElem(inb,inbf,0);
				if( ch == ';' ){
					int dch;
					if( isHTMLentity(inb,&dch) )
						putc(dch,htOut);
					inbf = 0;
					ch = ' ';
					continue;
				}
				inbx = 1;
				ch = '&';
			}
		}

		if( toHTML ){
			/* should prefetch and pack spaces ... */
			if( ch == ' ' ){
				if( 1 <= HtNsp )
					continue;
				HtNsp++;
			}else{
				HtNsp = 0;
			}
		}else{
			if( ch == '\r' && 2 <= HtNnl )
				continue;
			if( ch == '\n' ){
				if( 2 <= HtNnl )
					continue;
				HtNnl++;
			}else{
				if( HtNnl && !isspace(ch) ){
					HtNnl = 0;
				}
			}
			if( (htTags & HT_PRE) == 0 ){
				if( ch == ' ' ){
					if( 1 <= HtNsp )
						continue;
					HtNsp++;
				}else{
					HtNsp = 0;
				}
			}
		}

		if( htCol == 0 ){
			if( !toHTML ){
				if( htTags & HT_PRE ){
					if( htTags & HT_BLOCKQUOTE ){
						fputs("| ",htOut);
						htCol += 2;
					}
				}
			}
		}
		if( ch == '\r' )
			withCR = 1;
		putc(ch,htOut);
		if( ch == '\n' ){
			htCol = 0;
		}else{
			htCol++;
		}
	}
	if( in2B )
		fputs("\033(B",htOut);
	if( 1 ){
		if( withCR )
			putc('\r',htOut);
		putc('\n',htOut);
	}
	return 0;
}
int h2t_main(int ac,const char *av[]){
	int ai;
	int toHtml = 0;
	for( ai = 0; ai < ac; ai++ ){
		if( streq(av[ai],"-v") )
			Htrace = 1;
		else
		if( streq(av[ai],"-h") )
			toHtml = 1;
	}
	HTMLtoTEXT(stdin,stdout,toHtml);
	return 0;
}
