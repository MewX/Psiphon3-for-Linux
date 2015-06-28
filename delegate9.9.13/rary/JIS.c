/*///////////////////////////////////////////////////////////////////////
Copyright (c) 1993-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2007 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	JIS.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	930923	extracted from codeconv.c of cosmos
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "file.h"
/*
#include "log.h"
*/

int CCX_debug = 0;

#define CC_THRU		0
#define CC_ASCII	1
#define CC_JIS2B7	2
#define CC_JIS7K	3	/* with 7bit/1byte kana by ESC(I */
#define CC_SJIS		4
#define CC_EUCJP	5
#define CC_JIS7KANA	6
#define CC_JIS7ROMA	7
#define CC_UTF8		8
#define CC_GUESS	9
#define CC_ASIS		10
#define CC_NONJP	11
#define CC_EURO8	12
#define CC_JIS2B7X	13	/* JIS0212 by ESC(D */
#define CC_GUESSSET	14 /* guess charset, thenn convert to it after */
#define CC_UTF16	15
#define CC_JIS2B7X2	16 /* JIS0213 by ESC$(Q */
#define CC_JIS2B7X3	17 /* JIS0213 by ESC$(P */

#define CCX_OUTJA(ccx)	(  ccx->cc_OUT == CC_JIS2B7 \
			|| ccx->cc_OUT == CC_SJIS \
			|| ccx->cc_OUT == CC_EUCJP \
			|| ccx->cc_OUT == CC_UTF8 \
			|| ccx->cc_OUT == CC_JIS2B7X \
			)
#define CCX_NOCONV(ccx)	(ccx->cc_OUT == CC_GUESS || ccx->cc_OUT == CC_ASIS)

typedef struct _CCX {
 unsigned char	cc_size;
	char	cc_incode; /* incode specified by CCX_setincode() */
	char	cc_OUT;    /* target charcode of conversion */
	char	cc_out;    /* current output charcode */
	char	cc_outx;   /* chaset-name index in chasets[] */
	char	cc_indef;  /* default input charcode */
	char	cc_in;     /* current input charcode */
	char	cc_previn; /* previous non-ASCII input charcode */
	char	cc_symconv;
	char	cc_incc1;  /* first non-ASCII input charcode */
	char	cc_linecc; /* the first non-ASCII input in this line */
	char	cc_instat; /* detected status of input charcode */
	char	cc_inswitch[20]; /* detected input character type */
unsigned char	cc_pinb[8];
	int	cc_pinx;
	int	cc_nonASCII;
	short	cc_id;
	short	cc_flags;
	short	cc_sjis;
	short	cc_euc;
	short	cc_nonJP;
	short	cc_nonjp8;
unsigned char	cc_thru8[4]; /* total size of CCX must be <= 64 */
} CCX;
int CCXsize(){ return sizeof(CCX); }

/* cc_flags */
#define CCF_BAD1	1
#define CCF_BAD		2
#define CCF_TOSV	4
#define CCF_UTFLE	8 /* little endien */
#define CCF_INDEFSET	0x10
#define CCF_NOEUCX	0x20 /* disalbe EUC extended with 0x8F */
#define CCF_NOJISX	0x40 /* disable ESC$(D */
#define CCF_LOCK_OUT	0x80 /* lock output code */
#define CCF_IN_ANSI	0x100 /* input might be ANSI */
#define CCF_ESC_K	0x200 /* insert SP before ESC-[-K (MacOSX Terminal) */
#define CCF_YUC		0x400 /* non-Japanese to YUC */

#define CCI_BINARY	0x01 /* input seems binary */

static struct {
  const	char   *cs_name;
  const	char   *cs_formname;
	short	cs_charcode;
} charsets[] = {
	{0},
	{"jis",		"ISO-2022-JP",	CC_JIS2B7	},
	{"euc",		"EUC-JP",	CC_EUCJP	},
	{"x-euc-jp",	"x-euc-jp",	CC_EUCJP	},
	{"sjis",	"Shift_JIS",	CC_SJIS		},
	{"x-sjis",	"x-sjis",	CC_SJIS		},
	{"utf8",	"UTF-8",	CC_UTF8		},
	{"utf16",	"UTF-16",	CC_UTF16	},
	{"ascii",	"US-ASCII",	CC_ASCII	},
	{0},
}; 
int isKnownCharset(PCStr(name)){
	int ci;
	const char *n1;
	for( ci = 1; n1 = charsets[ci].cs_formname; ci++ ){
		if( strcaseeq(n1,name) )
			return ci;
		if( strcaseeq(charsets[ci].cs_name,name) )
			return ci;
	}
	return 0;
}

#define cc_UTF8		cc_inswitch[CC_UTF8]
#define cc_UTF16	cc_inswitch[CC_UTF16]
#define cc_SJIS		cc_inswitch[CC_SJIS]
#define cc_JIS7		cc_inswitch[CC_JIS2B7]
#define cc_EUCJP	cc_inswitch[CC_EUCJP]
#define cc_EURO8	cc_inswitch[CC_EURO8]

#define maybein(cs)	( ccx->cc_inswitch[cs] \
			|| ccx->cc_in == cs \
			|| ccx->cc_previn == cs \
			|| ccx->cc_indef == cs \
			)

#define CC_UNDEF(cs)	( cs == 0 || cs == CC_ASCII )
#define inccctx(ccx,cs) ( ccx->cc_indef == cs \
	  || CC_UNDEF(ccx->cc_indef) && ccx->cc_incc1 == cs )

/* cc_symconv */
#define SCtoJISZK	0x02 /* to zenkaku (full-width) kana */
#define SCtoASCII	0x04 /* multibyte alnum/symbol into to ASCII */
#define SCtoJIS2B	0x08
#define SCtoLF		0x10
#define SCtoCRLF	0x20
#define SCtoIGNBAD	0x40 /* ignore bad JIS sequence */
#define IGN_bad(ccx)	(ccx->cc_symconv & SCtoIGNBAD)
#define SCinURL		0x80
#define SCtoESC_K	0x200 /* insert SP before ESC-[-K */
#define SCtoYUC		0x400

#define JIS2B8(code)	(code == CC_SJIS || code == CC_EUCJP)
#define JIS2Bs(code)	(code == CC_JIS2B7 || code == CC_JIS2B7X)
#define JIS2B(code)	(code == CC_JIS2B7 || JIS2B8(code))

#define setlinecc(ccx,cc) { \
	if( cc != CC_ASCII && ccx->cc_linecc == 0 ){ \
		ccx->cc_linecc = cc; \
	} \
}
#define setccin(ccx,cc)	{ \
	if( ccx->cc_in != ccx->cc_previn && JIS2B(ccx->cc_in) )\
		ccx->cc_previn = ccx->cc_in; \
	ccx->cc_in = cc; \
	if( cc != CC_ASCII && ccx->cc_incc1 == 0 ){ \
		ccx->cc_incc1 = cc; \
	} \
	if( cc != CC_ASCII && ccx->cc_linecc == 0 ){ \
		ccx->cc_linecc = cc; \
	} \
	if( cc != CC_ASCII && ccx->cc_OUT == CC_GUESSSET ){ \
		ccx->cc_OUT = cc; \
	} \
	ccx->cc_nonASCII += (cc != CC_ASCII); \
	ccx->cc_inswitch[cc] |= 1; \
}

#define pushpending(ccx,ch) (ccx->cc_pinb[ccx->cc_pinx++] = ch)
#define EOB	-1
#define CHn(n) \
	((pilen <= pix+n) ? EOB : \
	(pix+n < pin) ? ccx->cc_pinb[pix+n] : cinb[pix+n-pin])
#define CH1 CHn(0)
#define CH2 CHn(0)
#define CH3 CHn(1)
#define CH4 CHn(2)
#define CH5 CHn(3)
#define CH6 CHn(4)

#define inNonASCII(ccx,code) \
	(  ccx->cc_in == code \
	|| ccx->cc_in == CC_ASCII && ccx->cc_previn == code )

#define CC_CHECKLEN	8
#define CC_BEEUC	4

/*---- CHARMAP ----*/
typedef struct {
	int	cm_flag;
	int	cm_from;
	int	cm_to;
	int	cm_offs;
} charMap;

int _mapCHAR(int dst,int ics,int csx,int code,int *mapped);
static int _mapJIS2B(int dst,int icset,int j212,int *ch1,int *ch2,int *mapped);

#define CCXDST(ccx)	((ccx->cc_flags & CCF_TOSV) ? CSD_TOSV:CSD_TOCL)
#define withCHARMAP(csx) (charmapxv[CCXDST(ccx)][csx])
#define mapCHAR(ics,csx,code) \
 (charmapxv[CCXDST(ccx)][csx]?_mapCHAR(CCXDST(ccx),ics,csx,code,0):code)
#define mapJIS2B(cs,j2,c1,c2) \
 (charmapxv[CCXDST(ccx)][CSM_JIS2JIS]?_mapJIS2B(CCXDST(ccx),cs,j2,c1,c2,0):0)

#define CM_SHIFT	0x0001
#define CSM_ASCII2ASCII	0
#define CSM_JIS2JIS	1
#define CSM_UCS2UCS	2
#define CSM_JIS2UCS	3
#define CSM_UCS2JIS	4
#define CSM_MAX		8

#define CSD_TOCL	0
#define CSD_TOSV	1

#define CS_ASCII	1
#define CS_JIS		2
#define CS_UCS		3

#define MAP_1B		1
#define MAP_JISX0201	2
#define MAP_JISX0208	4
#define MAP_JISX0212	8
#define MAP_JISX0213	0x10

static charMap *charmapsv[2][CSM_MAX];
static int charmapxv[2][CSM_MAX];

static int NoMap1 = 0x222E; /* No Unicode mapping */
static int NoMap2 = 0x2221; /* UCS larger than 16bits (not implemented yet) */
static int NoMap3 = 0x2223; /* EUC-JP extension */
static int NoMap4 = 0x2225; /* Shift_JIS local extension */
static int NoMap5 = 0x2227; /* ISO-2022-JP + JISX0212 */


/*
 *	STATUS CHANGE CODES
 */
#define ESC		'\033'
#define TO_2BCODE	'$'
#define TO_1BCODE	'('

#define IS_SJIS_LO(lo)	((0x40<=lo)&&(lo!=0x7F)&&(lo<=0xFC))
#define IS_SJIS_HI1(hi) ((0x81<=hi)&&(hi<=0x9F))	/* 1st lev. */
#define IS_SJIS_HI2(hi) ((0xE0<=hi)&&(hi<=0xEF))	/* 2nd lev. */
#define IS_SJIS_HI(hi)	(IS_SJIS_HI1(hi)||IS_SJIS_HI2(hi))
#define IS_SJIS_HIX(hi) ((0xFA<=hi)&&(hi<=0xFC))
#define IS_SJIS_2B(hi,lo,in_sjis)\
	(!IS_SJIS_LO(lo) ? 0:\
	IS_SJIS_HI1(hi) ? (in_sjis = 1):\
	in_sjis && IS_SJIS_HI2(hi))

#define IS_SJIS_1B(ch)	(0xA1 <= (ch) && (ch) <= 0xDF)
#define IS_SJIS_CH(ch1,ch2) \
	(IS_SJIS_LO(ch2) && IS_SJIS_HI(ch1)||IS_SJIS_1B(ch1))

#define SJIS_DAKUTEN	0xDE
#define SJIS_HANDAKU	0xDF
static const char *SJIS_1B_TO_JIS[] = {
/* 0xA1-A7 */       "!#", "!V", "!W", "!\"","!%", "%r", "%!",
/* 0xA8-AF */ "%#", "%%", "%'", "%)", "%c", "%e", "%g", "%C",
/* 0xB0-B7 */ "!<", "%\"","%$", "%&", "%(", "%*", "%+", "%-",
/* 0xB8-BF */ "%/", "%1", "%3", "%5", "%7", "%9", "%;", "%=",
/* 0xC0-C7 */ "%?", "%A", "%D", "%F", "%H", "%J", "%K", "%L",
/* 0xC8-CF */ "%M", "%N", "%O", "%R", "%U", "%X", "%[", "%^",
/* 0xD0-D7 */ "%_", "%`", "%a", "%b", "%d", "%f", "%h", "%i",
/* 0xD8-DF */ "%j", "%k", "%l", "%m", "%o", "%s", "!+", "!,"
};
static const char *SJIS_1B_TO_DAKUTEN[] = {
/* 0xA1-A7 */       0,    0,    0,    0,    0,    0,    0,
/* 0xA8-AF */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xB0-B7 */ 0,    0,    0,    "%t", 0,    0,    "%,", "%.",
/* 0xB8-BF */ "%0", "%2", "%4", "%6", "%8", "%:", "%<", "%>",
/* 0xC0-C7 */ "%@", "%B", "%E", "%G", "%I", 0,    0,    0,
/* 0xC8-CF */ 0,    0,    "%P", "%S", "%V", "%Y", "%\\",0,
/* 0xD0-D7 */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xD8-DF */ 0,    0,    0,    0,    0,    0,    0,    0
};
static const char *SJIS_1B_TO_HANDAKU[] = {
/* 0xA1-A7 */       0,    0,    0,    0,    0,    0,    0,
/* 0xA8-AF */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xB0-B7 */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xB8-BF */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xC0-C7 */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xC8-CF */ 0,    0,    "%Q", "%T", "%W", "%Z", "%]", 0,
/* 0xD0-D7 */ 0,    0,    0,    0,    0,    0,    0,    0,
/* 0xD8-DF */ 0,    0,    0,    0,    0,    0,    0,    0
};

static char JIS_dakuten(int ch1,int ch2,int ucs){
	int dch2 = 0;
	if( ch1 == '$' || ch1 == '%' ){
		if( ucs == 0x3099 || ucs == 0 )
		switch( ch2 ){
			case '+': case '-': case '/': case '1': case '3':
			case '5': case '7': case '9': case ';': case '=':
			case '?': case 'A': case 'D': case 'F': case 'H':
			case 'O': case 'R': case 'U': case 'X': case '[':
				dch2 = ch2 + 1;
				break;
		}
		if( ucs == 0x309A || ucs == 0 )
		switch( ch2 ){
			case 'O': case 'R': case 'U': case 'X': case '[':
				dch2 = ch2 + 2;
				break;
		}
	}
	return dch2;
}

#define EUC_HANKAKU_HI	0x8E
#define IS_EUC_HANKAKU(hi,lo)	(hi==EUC_HANKAKU_HI && IS_SJIS_1B(lo))

#define IS_EUC_LOS(lo)	((0x21<=lo)&&(lo<=0x7E))	/* standard */
#define IS_EUC_LOX(lo)	((0xA1<=lo)&&(lo<=0xFE))	/* extended */
#define IS_EUC_HI(hi)	((0xA1<=hi)&&(hi<=0xFE))
#define IS_EUC(hi,lo)\
	(IS_EUC_HANKAKU(hi,lo) || \
	IS_EUC_HI(hi) && (IS_EUC_LOS(lo) || IS_EUC_LOX(lo)))
#define IS_EUCJP(hi,lo)\
	(IS_EUC_HANKAKU(hi,lo) || IS_EUC_HI(hi) && IS_EUC_LOX(lo))
#define IS_EUC_CH(ch1,ch2,ch3) \
	(IS_EUC(ch1,ch2)||ch1==0x8F && IS_EUC(ch2,ch3))


int IS_SJIS_CHAR(int ch1,int ch2,int in_sjis)
{
	if( ch1 & 0x80 ){
		if( IS_SJIS_LO(ch2) ){
			if( IS_SJIS_HI1(ch1) || in_sjis && IS_SJIS_HI2(ch1) )
				return 2;
		}
		if( in_sjis && IS_SJIS_1B(ch1) )
			return 1;
	}
	return 0;
}
int IS_SJIS_STR(unsigned char *str)
{	const unsigned char *s;
	unsigned char ch;
	int is_sjis = 0;

	s = str;
	while( ch = *s++ ){
		if( ch & 0x80 )
			if( !IS_EUC_HANKAKU(ch,*s) )
			if( IS_SJIS_2B(ch,*s,is_sjis) )
				return 1;
	}
	return 0;
}

unsigned char *
SJIS_TO_JIS1(unsigned char HI, unsigned char LO, unsigned char *JCODE)
{
	HI -= (HI <= 0x9F) ? 0x71 : 0xB1;
	HI = (HI << 1) + 1;
	if( 0x7F < LO )
		LO--;
	if( 0x9E <= LO ){
		LO -= 0x7D;
		HI++;
	}else	LO -= 0x1F;
	JCODE[0] = HI;
	JCODE[1] = LO;
	return JCODE;
}
unsigned char *
JIS_TO_SJIS1(unsigned char HI,unsigned char LO,unsigned char *SJCODE)
{
	if( HI & 1 )
		LO += 0x1F;
	else	LO += 0x7D;
	if( 0x7F <= LO )
		LO++;

	HI = (((int)HI - 0x21) >> 1) + 0x81;
	if( 0x9F < HI )
		HI += 0x40;
	SJCODE[0] = HI;
	SJCODE[1] = LO;
	return SJCODE;
}

static const char *sjis_1b_to_jis(int ch1,int ch2,int *cat)
{	unsigned char c1,c2;
	const char *js;

	c1 = (0x80 | ch1) - 0xA1;
	c2 =  0x80 | ch2;

	if( elnumof(SJIS_1B_TO_DAKUTEN) <= c1 ){
		fprintf(stderr,"-- CCX SJ1toJ c1=%2X:%2X c2=%2X:%2X\n",
			ch1,c1,ch2,c2);
		return "\".";
	}

	if( c2 == SJIS_DAKUTEN && (js = SJIS_1B_TO_DAKUTEN[c1])
	 || c2 == SJIS_HANDAKU && (js = SJIS_1B_TO_HANDAKU[c1]) ){
		*cat = 1;
		return js;
	}else{
		*cat = 0;
		/*
		return SJIS_1B_TO_JIS[c1];
		*/
		js = SJIS_1B_TO_JIS[c1];
		if( js == NULL ){
			fprintf(stderr,"-- CCX SJ1toJ c1=%2X %X:%X\n",
				c1,ch1,ch2);
			js = "!)";
		}
		return js;
	}
}
static int EUC_hankaku_TO_JIS(unsigned char **spp,unsigned char **dpp,PVStr(db))
{	const unsigned char *sp;
	unsigned char *dp; /**/
	unsigned char ch1,ch2;
	const char *js;
	int cat;

	sp = *spp;
	dp = *dpp;
	if( !IS_EUC_HANKAKU(sp[0],sp[1]) )
		return 0;

	ch1 = sp[1];
	if( sp[2] && sp[3] )
		ch2 = sp[3];
	else	ch2 = 0;
	js = sjis_1b_to_jis(ch1,ch2,&cat);
	if( cat )
		sp += 2;

	Xstrcpy(QVStr(dp,db),js);
	dp += 2; *dpp = dp;
	sp += 2; *spp = (unsigned char*)sp;
	return 1;
}

#define IS_JIS_HI(c1)	(0x20 < (c1) && (c1) < 0x7F)
#define IS_JIS_LO(c1)	(0x20 < (c1) && (c1) < 0x7F)
#define	IS_JIS7(c1,c2)	(IS_JIS_HI(c1) && IS_JIS_LO(c2))
#define SO		('N'-0x40)
#define SI		('O'-0x40)
#define NBSP		0xA0	/* non-breaking space */


#define sputc(dp,ch)	(dp?(*(char*)dp++ = ch):ch)

static int istag(PCStr(str))
{	char ch;
	const char *s;

	for( s = str; ch = *s; s++ ){
		if( ch == '>' || isspace(ch) )
			return str < s;
		if( !isalpha(ch) )
			return 0;
	}
	return 0;
}

int FIX_2022(PCStr(src),PVStr(dst),PCStr(ctype))
{	int in2B;
	const char *sp;
	char ch1,ch2;
	refQStr(dp,dst); /**/
	int bad;
	int isHTML,len,ech;

	in2B = 0;
	sp = src;
	bad = 0;

	isHTML = strcasecmp(ctype,"text/html") == 0;

	while( ch1 = *sp++ ){
		assertVStr(dst,dp+3);
		if( ch1 == ESC ){
			if( *sp == TO_2BCODE ){
				if( sp[1] == 'B' || sp[1] == '@' ){
					in2B = 1;
					sputc(dp, ch1);
					sputc(dp, *sp++);
					sputc(dp, *sp++);
					continue;
				}
			}else
			if( *sp == TO_1BCODE ){
				if( sp[1] == 'B' || sp[1] == 'J' ){
					in2B = 0;
					sputc(dp, ch1);
					sputc(dp, *sp++);
					sputc(dp, *sp++);
					continue;
				}
			}
		}

		if( in2B ){
			ch2 = sp[0];
			if( ch1 <= 0x20
			||  ch2 <= 0x20
			||  isHTML && ch1=='<' && sp[0]=='/' && istag(&sp[1])
			||  isHTML && ch2=='<' && sp[1]=='/' && istag(&sp[2]) ){
				in2B = 0;
				sputc(dp, ESC);
				sputc(dp, TO_1BCODE);
				sputc(dp, 'B');
				sputc(dp, ch1);
				bad = 1;
				continue;
			}

			if( isHTML && ch1 == '&' )
			if( len = isHTMLentity(sp,&ech) )
			if( sp[len] != 0 ){
				ch1 = ech;
				sp += len;
				bad = 1;
			}

			ch2 = *sp++;

			if( isHTML && ch2 == '&' )
			if( len = isHTMLentity(sp,&ech) )
			if( sp[len] != 0 ){
				ch2 = ech;
				sp += len;
				bad = 1;
			}

			sputc(dp, ch1);
			sputc(dp, ch2);
		}else{
			sputc(dp, ch1);
		}
	}
	sputc(dp, 0);
	return bad;
}

static int is_EUC_JP(PCStr(euc))
{	const char *cp;
	int ch1,ch2;

	for( cp = euc; ch1 = *cp & 0xFF; cp++ ){
		if( ch1 & 0x80 ){
			ch2 = cp[1] & 0xFF;
			/*
			if( !IS_EUC(ch1,ch2) )
			*/
			if( !IS_EUCJP(ch1,ch2) )
				return 0;
			cp++;
		}
	}
	return 1;
}

/* v9.9.12 140826c, getting code length of a multi bytes character */
int JIS7_bytes(int ch1,int ch2){
	if( IS_JIS7(ch1,ch2) ){
		return 2;
	}
	return 0;
}
int SJIS_bytes(int ch1,int ch2){
	int in_sjis = 1;
	if( IS_SJIS_1B(ch1) ){
		return 1;
	}
	if( IS_SJIS_2B(ch1,ch2,in_sjis) ){
		return 2;
	}
	return 0;
}
int EUCJ_bytes(int ch1,int ch2,int ch3){
	if( ch1 == 0x8F ){
		if( IS_EUC(ch2,ch3) ){
			return 3;
		}
	}
	if( IS_EUC(ch1,ch2) ){
		return 2;
	}
	return 0;
}
static unsigned int fromUTF8(unsigned char *us,int *lengp,char **spp);
int UTF8_bytes(int ch1,int ch2,int ch3){
	unsigned char us[6];
	unsigned int ucs;
	int len = 0;

	us[0] = ch1;
	us[1] = ch2;
	us[2] = ch3;
	us[3] = 0;
	us[4] = 0;
	us[5] = 0;
	ucs = fromUTF8(us,&len,NULL);
	return len;
}

int CCXnonJP(CCX *ccx){
	return ccx->cc_nonJP;
}
int CCX_obviousJP(CCX *ccx){
	if( ccx->cc_nonJP == 0 )
	if( 0 < ccx->cc_JIS7
	 || 10 < ccx->cc_EUCJP
	 || 10 < ccx->cc_SJIS
	 || 10 < ccx->cc_UTF8
	 || 5 <= ccx->cc_sjis && ccx->cc_euc == 0
	 || 5 <= ccx->cc_euc && ccx->cc_sjis == 0
	)
	{
		return 1;
	}
	return 0;
}
static const char *csx2name(int csx);
const char *CCXgotincharcode(CCX *ccx){
	const char *cs;
	if( ccx->cc_incc1 ){
		if( cs = csx2name(ccx->cc_incc1) ){
			return cs;
		}
	}
	return 0;
}
int CCXstats(CCX *ccx,PVStr(buf)){
	refQStr(bp,buf);

	if( ccx->cc_incc1 ){
		const char *cs;
		if( cs = csx2name(ccx->cc_incc1) ){
			sprintf(bp,"(%s)",cs);
			bp += strlen(bp);
		}
	}
	if( ccx->cc_instat & CCI_BINARY ){
		sprintf(bp,"(BIN)");
		bp += strlen(bp);
	}
	if( ccx->cc_flags & CCF_BAD ){
		sprintf(bp,"BAD[%X]",ccx->cc_flags);
		bp += strlen(bp);
	}
	if( ccx->cc_nonJP ){
		sprintf(bp,"NONJP[%d]",ccx->cc_nonJP);
		bp += strlen(bp);
	}
	if( ccx->cc_EURO8 ){
		sprintf(bp,"EURO8[%d]",ccx->cc_EURO8);
		bp += strlen(bp);
	}
	if( ccx->cc_UTF8 ){
		sprintf(bp,"UTF8[%d]",ccx->cc_UTF8);
		bp += strlen(bp);
	}
	if( ccx->cc_JIS7 ){
		sprintf(bp,"JIS7[%d]",ccx->cc_JIS7);
		bp += strlen(bp);
	}
	if( ccx->cc_sjis ){
		sprintf(bp,"SJIS[%d/%d]",ccx->cc_SJIS,ccx->cc_sjis);
		bp += strlen(bp);
	}
	if( ccx->cc_euc ){
		sprintf(bp,"EUCJP[%d/%d]",ccx->cc_EUCJP,ccx->cc_euc);
		bp += strlen(bp);
	}
	if( ccx->cc_nonjp8 ){
		sprintf(bp,"NONJP[%d/%d]",ccx->cc_nonJP,ccx->cc_nonjp8);
		bp += strlen(bp);
	}
	setVStrEnd(bp,0);
	return bp - buf;
}
void CCXcounts(CCX *ccx)
{
	CStr(buf,256);
	CCXstats(ccx,AVStr(buf));
	fprintf(stderr,"%s\n",buf);
/*
	fprintf(stderr,"UTF8[%d]",ccx->cc_UTF8);
	fprintf(stderr,"JIS7[%d]",ccx->cc_JIS7);
	fprintf(stderr,"SJIS[%d/%d]",ccx->cc_SJIS,ccx->cc_sjis);
	fprintf(stderr,"EUCJP[%d/%d]\n",ccx->cc_EUCJP,ccx->cc_euc);
*/
}

/* distinguish SJIS from EUC */
static int guessCode(CCX *ccx, const unsigned char *cinb, int pix, int pin, int pilen)
{	int cn,ci,ch1,ch2;
	int cs = -1;
	int n2K = 0,n1K = 0,n2B = 0;
	int nJ8 = 0,nSJ = 0,nEJ = 0;
	int nL8;
	int as_sjis = 1;
	int is2B;
	int nES = 0; /* non-kanji symbols in EUC */
	int preL8 = -1;
	int isJP = ccx->cc_sjis + ccx->cc_euc;
	int cs1;

	nL8 = ccx->cc_nonJP; /* bias for tie break */
	if( ccx->cc_in == CC_EURO8 && 0 < nL8 ){
		return CC_EURO8;
	}
	if( 5 <= nL8 )
		return CC_NONJP;
	if( ccx->cc_in == CC_SJIS || ccx->cc_in == CC_EUCJP )
		isJP = 1;

	if( ccx->cc_nonASCII == 0 )
		cn = 1024;
	else	cn = 128;

	for( ci = 0; ci < cn; ){
		ch1 = CHn(ci);
		ch2 = 0;
		ci++;
		if( ch1 == EOB )
			break;

		if( ch1 == '\n' ){
			/* 9.5.0-pre5 might be different line by line */
			if( (nEJ || nSJ) && nEJ != nSJ )
				break;
		}

		if( ch1 == 033 ){
			if( nJ8 == 0 ){
				cs = CC_JIS2B7;
				break;
			}
		}
		if( ch1 == '\r' || ch1 == '\n' ){
			if( 0 < nJ8 && ccx->cc_nonASCII != 0 )
				break;
		}

		if( (ch1 & 0x80) == 0 )
			continue;

		ch2 = CHn(ci);
		ci++;
		if( ch2 == EOB )
			break;

		is2B = 0;
		cs1 = 0;

		if( ch1 == 0x8F ){
			/* HojoKanji */
			int ch3;
			ch3 = CHn(ci);
			if( nSJ == 0 || nJ8 == nEJ )
			if( IS_EUCJP(ch2,ch3) ){
				ci++;
				ch1 = ch2;
				ch2 = ch3;
			}
		}
		if( nJ8 == nEJ ){
			/*
			if( IS_EUC(ch1,ch2) ){
			*/
			if( IS_EUCJP(ch1,ch2) ){
				cs1 = CC_EUCJP;
				is2B = 1;
				nEJ++;
				if( ch2 & 0x80 )
					n2B++;
				if( IS_EUC_HANKAKU(ch1,ch2) )
					n2K++;
				if( ch1 == 0xA3 || ch1 == 0xA4 || ch1 == 0xA5 )
					nES++;
			}
			else
			if( 0 < nEJ ){
				nEJ = 0;
			}
		}
		if( nJ8 == nSJ ){
			if( IS_SJIS_2B(ch1,ch2,as_sjis) ){
				cs1 = CC_SJIS;
				is2B = 1;
				nSJ++;
				if( ch2 & 0x80 )
				n2B++;
			}
			if( IS_SJIS_1B(ch1) ){
				if( ch2 & 0x80 == 0
				 || IS_SJIS_1B(ch2)
				 || IS_SJIS_2B(ch2,CHn(ci),as_sjis)
				){
				cs1 = CC_SJIS;
				nSJ++;
				n1K++;
				if( !is2B )
					ci--;
				}
			}
			if( 0 < nSJ && cs1 != CC_SJIS ){
				nSJ = 0;
			}
		}
		if( n2B == 0 )
		if( isJP == 0 )
		{
			/* distinguish from SJIS where 8bit char. appear closely */
			if( (ch2 & 0x80) == 0 )
			if( preL8 < 0 || 2 < (ci-preL8) ){
				preL8 = ci;
				nL8++;
				if( nSJ < nL8 && nEJ < nL8 ){
					break;
				}
			}
		}
		nJ8++;

		if( 0 < n2B )
		/*
		if( nSJ != nEJ || nSJ < nJ8 || CC_CHECKLEN <= nJ8 )
		*/
		if( nSJ != nEJ && nSJ != nL8
		 || nSJ < nL8 && nEJ < nL8
		 || CC_CHECKLEN <= nJ8
		){
			break;
		}
	}
#ifdef lCHARSET
	if( lCHARSET() ){
		CStr(buf,128);
		refQStr(bp,buf);
		if( nJ8 ) bp = Sprintf(AVStr(bp),"J8=%d ",nJ8); 
		if( n2B ) bp = Sprintf(AVStr(bp),"2B=%d ",n2B); 
		if( nSJ ) bp = Sprintf(AVStr(bp),"SJ=%d ",nSJ); 
		if( nEJ ) bp = Sprintf(AVStr(bp),"EJ=%d ",nEJ); 
		if( nL8 ) bp = Sprintf(AVStr(bp),"L8=%d ",nL8); 
		if( n1K ) bp = Sprintf(AVStr(bp),"1K=%d ",n1K); 
		CCXlog("{C} guessCode %d %d/%d %s\n",pix,ci,cn,buf);
	}
#endif

/*
 fprintf(stderr,"#### nJ8=%d n2B=%d nSJ=%d nEJ=%d nL8=%d n1K=%d %d/%d\n",
nJ8,n2B,nSJ,nEJ,nL8,n1K,ci,cn);
*/
	if( nSJ < nL8 && nEJ < nL8 ){
		if( nSJ == 0 && nEJ == 0 )
			ccx->cc_nonJP = 5;
		cs = CC_NONJP;
	}else
	if( 0 < nJ8 ){
		if( n2B == 0 && nJ8 <= nL8 && nSJ <= nL8 && nEJ <= nL8 ){
/*
 fprintf(stderr,"#### EURO8? nJ8=%d n2B=%d nSJ=%d nEJ=%d nL8=%d %d/%d\n",
nJ8,n2B,nSJ,nEJ,nL8,ci,cn);
*/
			cs = CC_NONJP;
		}else
		if( nSJ == nEJ ){
			if( inNonASCII(ccx,CC_SJIS) ) cs = CC_SJIS; else
			if( inNonASCII(ccx,CC_EUCJP) ) cs = CC_EUCJP; else
			if( nJ8 == nSJ ){
				/*
				if( 1 < n2K ){
					cs = CC_EUCJP;
				}else
				*/
				if( ccx->cc_indef == CC_EUCJP
				 || ccx->cc_indef == CC_SJIS )
					cs = ccx->cc_indef;
				else
				if( n1K == nES )
					cs = CC_EUCJP;
				else
				/* long indistinguish SJIS is not likely to be */
				if( CC_BEEUC < nJ8 )
					cs = CC_EUCJP;
				else
				if( ccx->cc_OUT == CC_EUCJP ){
					cs = CC_EUCJP;
				}
				else	cs = CC_SJIS;
/*
 fprintf(stderr,
 "#### nJ8=%d n2B=%d nSJ=%d nEJ=%d nL8=%d n1K=%d n2K=%d %d/%d ind=%d %s\n",
 nJ8,n2B,nSJ,nEJ,nL8,n1K,n2K,ci,cn,ccx->cc_indef,cs==CC_SJIS?"SJIS":"EUC");
*/
			}
		}
		if( cs == -1 ){
			if( nJ8 == nSJ ){ cs = CC_SJIS; }else
			if( nJ8 == nEJ ){ cs = CC_EUCJP; }
		}
	}

	if( CCX_debug )
	fprintf(stderr,"#### %3d %3d <%02X %02X> J%d S%d(%d) E%d(%d)%d [%s]\n",
		ccx->cc_nonASCII,ci,ch1,ch2,
		nJ8, nSJ,n1K, nEJ,n2K,nES,
		cs==CC_SJIS?"SJIS":(cs==CC_EUCJP?"EUC":"?"));

/*
if( ccx->cc_nonJP && (cs == CC_SJIS|cs == CC_EUCJP) )
 fprintf(stderr,"## MISSED GUESS-A nJ8=%d n2B=%d nSJ=%d nEJ=%d nL8=%d %d\n",
nJ8,n2B,nSJ,nEJ,nL8,ci);
if( isJP && cs == CC_NONJP )
 fprintf(stderr,"## MISSED GUESS-B nJ8=%d n2B=%d nSJ=%d nEJ=%d nL8=%d %d\n",
nJ8,n2B,nSJ,nEJ,nL8,ci);
*/

	if( cs == CC_SJIS )
		ccx->cc_sjis++;
	if( cs == CC_EUCJP )
		ccx->cc_euc++;
	if( cs == CC_NONJP )
		ccx->cc_nonJP++;

	return cs;
}
static int is_SJIS(CCX *ccx,const unsigned char *cinb,int pix,int pin,int pilen)
{	int cs;

	cs = guessCode(ccx,cinb,pix,pin,pilen);
	return cs == CC_SJIS;
}

/*
static int UTF8toLocal(int ch1,int ch2,int ch3,int charset,unsigned char *op,const unsigned char *ox);
*/
static int UTF8toLocalX(CCX *ccx,int ch1,int ch2,int ch3,int ch4,int charset,unsigned char *op,const unsigned char *ox);
#define UTF8toLocal(c1,c2,c3,cset,op,ox) \
	UTF8toLocalX(ccx,c1,c2,c3,ch4,cset,op,ox)

/*
int JIS_TO_ASCII(int chset,int ch1,int ch2,int ch3)
*/
#define JIS_TO_ASCII(chset,ch1,ch2,ch3) JIS_TO_ASCIIX(ccx,chset,ch1,ch2,ch3,ch4) 
int JIS_TO_ASCIIX(CCX *ccx,int chset,int ch1,int ch2,int ch3,int ch4)
{	int chA;
	/*
	unsigned char j2[4];
	*/
	unsigned char j2[11]; /* for YUC */
	const unsigned char *j2x = &j2[sizeof(j2)-1];

	chA = 0;
	if( chset == CC_UTF8 ){
		if( UTF8toLocal(ch1,ch2,ch3,CC_EUCJP,j2,j2x) == 2 ){
			ch1 = j2[0];
			ch2 = j2[1];
			chset = CC_EUCJP;
		}
	}
	if( chset == CC_EUCJP ){
		ch1 = ch1 & 0x7F;
		ch2 = ch2 & 0x7F;
	}else
	if( chset == CC_SJIS ){
		SJIS_TO_JIS1(ch1,ch2,j2);
		ch1 = j2[0];
		ch2 = j2[1];
	}
	switch( ch1 ){
		case '!':
			switch( ch2 ){
				case '!': chA = ' '; break;
				case '$': chA = ','; break;
				case '%': chA = '.'; break;
				case '#': chA = '.'; break;
				case '\'': chA = ':'; break;
				case '(': chA = ';'; break;
				case ')': chA = '?'; break;
				case '-': chA = '\''; break;
				case '.': chA = '\''; break;
				case '*': chA = '!'; break;
				case '0': chA = '^'; break;
				case '1': chA = '~'; break;
				case '2': chA = '_'; break;
				case '=': chA = '-'; break;
				case '?': chA = '/'; break;
				case '@': chA = '\\'; break;
				case 'A': chA = '~'; break;
				case 'C': chA = '|'; break;
				case 'F': chA = '`'; break;
				case 'G': chA = '\''; break;
				case 'H': chA = '"'; break;
				case 'I': chA = '"'; break;
				case 'J': chA = '('; break;
				case 'K': chA = ')'; break;
				case 'N': chA = '['; break;
				case 'O': chA = ']'; break;
				case 'P': chA = '{'; break;
				case 'Q': chA = '}'; break;
				case 'R': chA = '<'; break;
				case 'S': chA = '>'; break;
				case '\\': chA = '+'; break;
				case 'Z': chA = '['; break;
				case '[': chA = ']'; break;
				case ']': chA = '-'; break;
				case 'a': chA = '='; break;
				case 'c': chA = '<'; break;
				case 'd': chA = '>'; break;
				case 'o': chA = '\\'; break;
				case 'p': chA = '$'; break;
				case 's': chA = '%'; break;
				case 't': chA = '#'; break;
				case 'u': chA = '&'; break;
				case 'v': chA = '*'; break;
				case 'w': chA = '@'; break;
			}
			break;
		case '#':
			if( isalnum(ch2) )
				chA = ch2;
			break;
	}
	return chA;
}

int CCXwithSJIS(CCX *ccx)
{
	return ccx->cc_SJIS;
}
int CCXwithJP(CCX *ccx)
{
	return ccx->cc_SJIS | ccx->cc_EUCJP | ccx->cc_JIS7 | ccx->cc_UTF8;
}
const char *CCXinputIsJP1(CCX *ccx){
	int nc = 0;
	const char *cc;
	if( ccx->cc_flags & CCF_BAD ) return 0;
	if( ccx->cc_SJIS  && ccx->cc_incc1==CC_SJIS  ){nc++;cc="Shift_JIS";  }
	if( ccx->cc_EUCJP && ccx->cc_incc1==CC_EUCJP ){nc++;cc="EUC-JP";     }
	if( ccx->cc_JIS7  && ccx->cc_incc1==CC_JIS2B7){nc++;cc="ISO-2022-JP";}
	if( nc == 1 ){
		return cc;
	}else{
		return 0;
	}
}
int CCX_converror(CCX *ccx){
	return ccx->cc_flags & CCF_BAD;
}
int CCX_inputIsJP(CCX *ccx){
	int cc;
	cc = ccx->cc_in;
	if( cc == 0 || cc == CC_ASCII )
		cc = ccx->cc_previn;
	if( cc == CC_SJIS || cc == CC_EUCJP || cc == CC_JIS2B7
	 || cc == CC_UTF8 )
		return 1;
	return 0;
}
void CCXthru8(CCX *ccx,PCStr(thru8))
{	int ti,tch;

	for(ti = 0; ti < sizeof(ccx->cc_thru8) && (tch = thru8[ti]); ti++)
		ccx->cc_thru8[ti] = tch;
	if( ti < sizeof(ccx->cc_thru8) )
		ccx->cc_thru8[ti] = 0;
}
static int isthru8(CCX *ccx, unsigned char ch)
{	int ti,tch;
	for(ti = 0; ti < sizeof(ccx->cc_thru8) && (tch = ccx->cc_thru8[ti]); ti++ )
		if( tch == ch )
			return ch;
	return 0;
}
int CCXinURL(CCX *ccx,int inURL){
	int oin = ccx->cc_symconv & SCinURL;

	if( inURL )
		ccx->cc_symconv |=  SCinURL;
	else	ccx->cc_symconv &= ~SCinURL;
	return oin;
}
void CCXclear(CCX *ccx)
{
	bzero(ccx,ccx->cc_size);
}
int CCXactive(CCX *ccx)
{
	return ccx->cc_OUT != CC_THRU;
}
int CCXguessing(CCX *ccx)
{
	return ccx->cc_OUT == CC_GUESS;
}
int CCXoutJP(CCX *ccx){
	switch( ccx->cc_OUT ){
		case CC_UTF8:	return 1;
		case CC_JIS2B7:	return 1;
		case CC_SJIS:	return 1;
		case CC_EUCJP:	return 1;
	}
	return 0;
}
int CCXoutcharset(CCX *ccx,const char **xcode)
{	const char *code = 0;

	switch( ccx->cc_OUT ){
		case CC_ASIS:	code = ""; break;
		case CC_ASCII:	code = "US-ASCII"; break;
/*
		case CC_UTF8:	code = "utf8"; break;
*/
		case CC_UTF8:	code = "UTF-8"; break;
		case CC_UTF16:	code = "UTF-16"; break;
		case CC_JIS2B7:	code = "iso-2022-jp"; break;
		case CC_SJIS:	code = "Shift_JIS"; break;
		case CC_EUCJP:	code = "EUC-JP"; break;
		case CC_GUESS:	code = "guess"; break;
	}
	if( xcode )
		*xcode = code;
	if( code != 0 )
		return 1 | ccx->cc_symconv;
	else	return 0;
}
const char *CCXcharset(CCX *ccx)
{
	if( ccx->cc_outx )
		return charsets[ccx->cc_outx].cs_formname;
	else	return 0;
}
static const char *csx2name(int csx){
	int ci;
	for( ci = 0; ci < elnumof(charsets); ci++ ){
		if( charsets[ci].cs_charcode == csx )
		if( charsets[ci].cs_name != NULL )
		{
			return charsets[ci].cs_formname;
		}
	}
	return 0;
}
const char *CCXident(CCX *ccx)
{
	if( 0 < ccx->cc_incc1 ){
		const char *cs;
		if( cs = csx2name(ccx->cc_incc1) ){
			return cs;
		}
	}
	if( ccx->cc_UTF8 ) return "UTF-8";
	if( ccx->cc_UTF16 ) return "UTF-16";
	/*
	if( ccx->cc_euc <= ccx->cc_sjis )
	*/
	if( ccx->cc_euc <= ccx->cc_sjis
	 || ccx->cc_EUCJP == 0 ) /* for SJISX not geussed as SJIS */
	if( ccx->cc_SJIS ) return "Shift_JIS";
	if( ccx->cc_EUCJP) return "EUC-JP";
	if( ccx->cc_JIS7 ) return "ISO-2022-JP";
	return "US-ASCII";
}
const char *CCX_getindflt(CCX *ccx){
	const char *cs;
	if( ccx->cc_indef ){
		if( cs = csx2name(ccx->cc_indef) )
			return cs;
	}
	return "*";
}
const char *CCXidentOut(CCX *ccx){
	const char *cs = 0;
	if( 0 < ccx->cc_incc1 ){
		cs = csx2name(ccx->cc_OUT);
	}
	if( cs == 0 && ccx->cc_indef ){
		cs = csx2name(ccx->cc_indef);
	}
	return cs;
}
static int scanFlags(PCStr(ccn),const char **nccn)
{	int flag = 0;

	for(; *ccn; ccn += 2 ){
		if( strneq(ccn,"z-",2) ) flag |= SCtoJISZK; else
		if( strneq(ccn,"a-",2) ) flag |= SCtoASCII; else
		if( strneq(ccn,"b-",2) ) flag |= SCtoIGNBAD; else
		if( strneq(ccn,"A-",2) ) flag |= SCtoJIS2B; else
		if( strneq(ccn,"r+",2) ) flag |= SCtoCRLF; else
		if( strneq(ccn,"r-",2) ) flag |= SCtoLF; else
		if( strneq(ccn,"u-",2) ) flag |= SCinURL; else
		if( strneq(ccn,"K-",2) ) flag |= SCtoESC_K; else
		if( strneq(ccn,"y-",2) ) flag |= SCtoYUC; else
		break;
	}
	if( nccn )
		*nccn = ccn;
	return flag;
}
static int ccx_codex(PCStr(ccn),int *cxp)
{	int cx,charcode;
	const char *name;

	scanFlags(ccn,&ccn);

	charcode = -1;
	for( cx = 1; name = charsets[cx].cs_name; cx++ ){
		if( strcaseeq(ccn,name)
		 || strcaseeq(ccn,charsets[cx].cs_formname) ){
			charcode = charsets[cx].cs_charcode;
			break;
		}
	}
	if( charcode == -1 ){
		if( strcaseeq(ccn,"guess") )
			    charcode = CC_GUESS;
		else
		if( strcaseeq(ccn,"guess-and-set") )
			    charcode = CC_GUESSSET;
	}
	if( charcode == -1 ){
		cx = 0;
		if( strcaseeq(ccn,"ISO-8859-1")
		 || strcaseeq(ccn,"windows-1252")
		){
			charcode = CC_EURO8;
		}else
		if( strncaseeq(ccn,"koi8",4) ){
		}else
		if( strncaseeq(ccn,"asis",4) ){
			charcode = CC_ASIS;
		}else
		if( strcaseeq(ccn,"Shift-JIS") ){
			charcode = CC_SJIS;
		}else
		if( strcaseeq(ccn,"ShiftJIS") ){
			charcode = CC_SJIS;
		}else
		if( strlen(ccn) <= 5 )
		switch( *ccn ){
			case 0:		    charcode = CC_ASIS;   break;
			case 'a':           charcode = CC_ASCII;  break;
			case 'u':           charcode = CC_UTF8;   break;
			case 'j': case 'J': charcode = CC_JIS2B7; break;
			case 'k': case 'K': charcode = CC_JIS7K;  break;
			case 's': case 'S': charcode = CC_SJIS;   break;
				  case 'U':
			case 'e': case 'E': charcode = CC_EUCJP;  break;
			case 't': case 'T': charcode = CC_THRU;   break;
			case '+':	    charcode = CC_GUESS;  break;
			default: return -1;
		}
	}
	*cxp = cx;
	return charcode;
}
int CCXcharsetcmp(PCStr(cs1),PCStr(cs2))
{	int Cs1,Cs2,cx;

	Cs1 = ccx_codex(cs1,&cx);
	Cs2 = ccx_codex(cs2,&cx);
	return Cs1 - Cs2;
}
static char incode[64]; /**/
void CCX_resetincode(CCX *ccx){
	int ii;
	ccx->cc_in = 0;
	ccx->cc_previn = 0;
	for( ii = 0; ii < 16; ii++ )
		ccx->cc_inswitch[ii] = 0;
	ccx->cc_nonASCII = 0;
	ccx->cc_sjis = 0;
	ccx->cc_euc = 0;
	ccx->cc_nonJP = 0;
	ccx->cc_nonjp8 = 0;
	ccx->cc_instat = 0;
}
static int dont_swccin(CCX *ccx,int charcode,int ch1,int ch2){
	if( charcode == CC_EUCJP )
	if( ccx->cc_incode && ccx->cc_incode != CC_EUCJP
 	 && (ccx->cc_SJIS || ccx->cc_sjis) )
	{
		syslog_ERROR("#CCX %s [%X %X][%d %d %d] S[%d/%d] E[%d/%d]\n",
			"IGNORED EUC ? in SJIS",ch1,ch2,
			ccx->cc_incode,ccx->cc_in,ccx->cc_previn,
			ccx->cc_SJIS,ccx->cc_sjis,
			ccx->cc_EUCJP,ccx->cc_euc,
			ccx->cc_incode
		);
		return 1;
	}
	return 0;
}
int CCX_setindflt(CCX *ccx,PCStr(from)){
	int icc,icx;
	icc = ccx_codex(from,&icx);

	if( *from == 0 && (ccx->cc_flags & CCF_INDEFSET) ){
		return ccx->cc_indef;
	}
	if( 0 < icc )
	{
		ccx->cc_indef = icc;
		ccx->cc_flags |= CCF_INDEFSET;
	}
	return icc;
}
const char *CCX_incodeisset(CCX *ccx){
	if( ccx->cc_incode )
		return csx2name(ccx->cc_incode);
	else	return 0;
}
void CCX_clearincode(CCX *ccx){
	ccx->cc_incode = 0;
}
void CCX_setincode(CCX *ccx,PCStr(ccn))
{	int charcode,cx;
	int ci;

	XStrncpy(ZVStr(incode,sizeof(incode)),ccn,sizeof(incode));
	charcode = ccx_codex(ccn,&cx);

	if( ccx->cc_incode != 0 ){
		/*
		syslog_ERROR("#CCX %s setincode(%s)[%d]<-[%d %d %d]\n",
		*/
		syslog_DEBUG("#CCX %s setincode(%s)[%d]<-[%d %d %d]\n",
			"IGNORED DUP",ccn,charcode,
			ccx->cc_incode,ccx->cc_in,ccx->cc_previn);
		return;
	}
	if( 0 <= charcode ){
		ccx->cc_incode = charcode;
		if( charcode == CC_JIS2B7 ){
			/* don't set current mode to be in 2B7 */
		}else{
		ccx->cc_in = charcode;
		}
		ccx->cc_previn = charcode;
		if( CC_UNDEF(ccx->cc_indef) ){
			/* 9.5.3 should be used as the context but might
			 * cause some side effect ?
			 */
#if 0
			ccx->cc_indef = charcode;
#endif
		}
		ccx->cc_nonASCII += (charcode != CC_ASCII);

for(ci = 0; ci < elnumof(ccx->cc_inswitch); ci++)
	ccx->cc_inswitch[ci] = 0;
ccx->cc_inswitch[charcode] = 10;
ccx->cc_nonJP = 0;
ccx->cc_instat = 0;

	}
	else{
		/* not to be converted */
		ccx->cc_nonJP = 10;
		if( strncasecmp(ccn,"iso-8859",8) == 0
		 || strncasecmp(ccn,"koi8",4) == 0
		){
			ccx->cc_in = CC_EURO8;
			ccx->cc_previn = CC_EURO8;
		}else{
			ccx->cc_in = CC_NONJP;
			ccx->cc_previn = CC_NONJP;
		}
	}
	/*
	if( ccx->cc_in == CC_EURO8 ){
		if( strcaseeq(ccn,"iso-8859-1")
		  || strcaseeq(ccn,"windows-1252")
		){
			ccx->cc_flags |= CCF_IN_ANSI;
		}
	}
	*/
}
#define isNotInNONJP(ccx) (ccx->cc_nonJP < 10)

static int CCXid;
int CCX_lockoutcode(CCX *ccx){
	int on = ccx->cc_flags & CCF_LOCK_OUT;
	ccx->cc_flags |= CCF_LOCK_OUT;
	return on;
}
int CCX_setoutcode(CCX *ccx,PCStr(ocs)){
	int ocharcode,ncharcode,cx;

	ocharcode = ccx->cc_OUT;
	if( (ccx->cc_flags & CCF_LOCK_OUT) == 0 )
	if( ocs && *ocs ){
		ncharcode = ccx_codex(ocs,&cx);
		if( 0 <= ncharcode ){
			ccx->cc_OUT = ncharcode;
			ccx->cc_outx = cx;
		}
	}
	return ocharcode;
}
int CCXcreate(PCStr(from),PCStr(to),CCX *ccx)
{	int charcode,icc;
	int cx,icx;

	if( 64 < sizeof(CCX) ){
		syslog_ERROR("#### FATAL: sizeof(CCX)=%d > 64\n",isizeof(CCX));
	}

	/*
	CCXlog("{C} CCXcreate(%s,%s,%X)\n",from,to,ccx);
	*/
	charcode = ccx_codex(to,&cx);
	if( charcode < 0 )
		return 0;

	incode[0] = 0;
	bzero(ccx,sizeof(CCX));
	ccx->cc_id = ++CCXid;
	ccx->cc_symconv = scanFlags(to,NULL);
	if( scanFlags(to,NULL) & SCtoESC_K ) ccx->cc_flags |= CCF_ESC_K;
	if( scanFlags(to,NULL) & SCtoYUC   ) ccx->cc_flags |= CCF_YUC;
	ccx->cc_size = sizeof(CCX);
	ccx->cc_OUT = charcode;
	ccx->cc_out = CC_ASCII;
	ccx->cc_outx = cx;
	icc = ccx_codex(from,&icx);
	if( icc < 0 )
		icc = CC_ASCII;
	ccx->cc_indef = icc;
	ccx->cc_in = icc;
	ccx->cc_previn = icc;

	ccx->cc_nonASCII = 0;
	ccx->cc_nonJP = 0;
	return sizeof(CCX);
}
CCX *CCXnew(PCStr(from),PCStr(to))
{	CCX ccxbuf,*ccx;
	int size;

	if( size = CCXcreate(from,to,&ccxbuf) ){
		ccx = (CCX*)malloc(size);
		bcopy(&ccxbuf,ccx,size);
		return ccx;
	}else	return NULL;
}
void CCXtosv(CCX *ccx,int tosv){
	if( tosv )
		ccx->cc_flags |=  CCF_TOSV;
	else	ccx->cc_flags &= ~CCF_TOSV;
}
void CCXnoeucx(CCX *ccx,int noeucx){
	if( noeucx )
		ccx->cc_flags |=  CCF_NOEUCX;
	else	ccx->cc_flags &= ~CCF_NOEUCX;
}
void CCXnojisx(CCX *ccx,int noeucx){
	if( noeucx )
		ccx->cc_flags |=  CCF_NOJISX;
	else	ccx->cc_flags &= ~CCF_NOJISX;
}

#define toJIS7(ccx,op) {\
	if( ccx->cc_out != CC_JIS2B7 ){ \
		*op++ = 033; \
		*op++ = '$'; \
		*op++ = 'B'; \
		ccx->cc_out = CC_JIS2B7; \
	}}

#define toJIS7X(ccx,op) {\
	if( ccx->cc_out != CC_JIS2B7X ){ \
		*op++ = 033; \
		*op++ = '$'; \
		*op++ = '('; \
		*op++ = 'D'; \
		ccx->cc_out = CC_JIS2B7X; \
	}}

#define toJIS7K(ccx,op) {\
	if( ccx->cc_out != CC_JIS7K ){ \
		*op++ = 033; \
		*op++ = '('; \
		*op++ = 'I'; \
		ccx->cc_out = CC_JIS7K; \
	}}

#define toASCII(ccx,op) { \
	if( ccx->cc_out == CC_JIS2B7 \
	 || ccx->cc_out == CC_JIS2B7X \
	 || ccx->cc_out == CC_JIS7K ) \
	if( !JIS2B8(ccx->cc_OUT) ){ \
		*op++ = 033; \
		*op++ = '('; \
		*op++ = 'B'; \
	} \
	ccx->cc_out = CC_ASCII; }

#define IS_UTF8_CONT(ch)	((ch & 0xC0) == 0x80)

/* followed with UTF-8 (non-SJIS, non-EUC) */
#define contUTF8(c1,c2) \
	(  c1 == EOB \
	|| (c1&0x80)==0 /* ASCII */ \
	|| (c1&0xF0)==0xE0 /* 2bytes < UTF-8 */ \
	|| (c1&0xE0)==0xC0 && (c2&0xC0)==0x80 /* 2bytes UTF-8 */ \
	|| (c1&0xF8)==0xF0 && (c2&0xC0)==0x80 /* 4bytes UTF-8 */ \
	)
#define canbeUTF8_2(c2)	((c2&0xC0)==0x80 || c2==EOB)

#define U_JIS0208	0x0000
#define U_SJIS		0x0080
#define U_JIS0212	0x8000

/*
static int EUCtoUTF8(int euc,unsigned char *us,const unsigned char *ux);
*/
int toUTF8(unsigned int uc,unsigned char *us);
static int toUTF8X(CCX *ccx,int euc,unsigned char *us,const unsigned char *ux);
#define EUCtoUTF8(e,u,x) toUTF8X(ccx,0x7F7F&(e),u,x)
#define EUC3toUTF8(e,u,x) toUTF8X(ccx,U_JIS0212|0x7F7F&(e),u,x)
/*
static int UTFis0212(int ch1,int ch2,int ch3);
static int UTF8toUCS(int ch1,int ch2,int ch3,int *lenp,unsigned int *eucp);
*/
static int UTFmapped(CCX *ccx,int ch1,int ch2,int ch3,int ch4);
static int UTF8toUCSX(CCX *ccx,int ch1,int ch2,int ch3,int ch4,int *lenp,unsigned int *eucp,int *mapped);
#define UTF8toUCS(ch1,ch2,ch3,lenp,eucp) \
	UTF8toUCSX(ccx,ch1,ch2,ch3,0,lenp,eucp,0)
static int ANSItoUCS(int ch1);

typedef unsigned char USChar;
static int EUCtoUCSHTML(CCX *ccx,int euc,USChar *us,const USChar *ux);
#define EUCtoHTML(euc) EUCtoUCSHTML(ccx,euc,op,ox)
static int UTF8toHTML(CCX *ccx,USChar ucsb[8],USChar *uu,const USChar *ux);
static int UCStoHTML(CCX *ccx,int ucs1,USChar *op,const USChar *ox);
static int SJISXtoJIS(CCX *ccx,int c1,int c2,USChar *op,const USChar *ox);
static int EUCXtoSJISX(CCX *ccx,int c1,int c2,USChar *op,const USChar *ox);

static unsigned int fromUTF8(unsigned char *us,int *lengp,char **spp);
static int isUTF8_2B(CCX *ccx,int ch1,int ch2,unsigned PCStr(cinb),int pix,int pin,int pilen){
	CCX ccxb;
	int cs;
	unsigned int ucs1,ucs2;
	unsigned int euc1,euc2;
	int len1,len2,len;

	ucs1 = UTF8toUCS(CHn(0),CHn(1),CHn(2),&len1,&euc1);
	if( euc1 != 0 && 2 <= len1 ){
		ucs2 = UTF8toUCS(CHn(len1),CHn(len1+1),CHn(len1+2),&len2,&euc2);
		len = len1 + len2;
/*
 fprintf(stderr,"---- %d:%X + %d:%X con=%d\n",len1,euc1,len2,euc2,
 contUTF8(CHn(len),CHn(len+1)));
*/
		if( 5 <= len ){
			return 1;
		}

		/* 2B in JIS0212 must be rare than EUC / JIS */
		if( (euc1 & 0x8080) != U_JIS0212 )
		if( (euc2 & 0x8080) != U_JIS0212 )
		if( 4 <= len && contUTF8(CHn(len),CHn(len+1)) )
		{
			return 1;
		}
	}
	bzero(&ccxb,sizeof(ccxb));
	cs = guessCode(&ccxb,cinb,pix,pin,pilen);
	if( cs == CC_EUCJP && ccxb.cc_euc != 0 && ccxb.cc_sjis == 0 ){
		return 0;
	}
	if( cs == CC_SJIS  && ccxb.cc_euc == 0 && ccxb.cc_sjis != 0 ){
		return 0;
	}
	return 4 <= len1+len2;
}
static int isUTF8_HANKAKU(int ch1,int ch2,int ch3){
	unsigned int ucs;
	int len;
	USChar us[8];

	if( ch1 == 0xEF && (ch2 == 0xBD || ch2 == 0xBE) ){
		us[0] = ch1;
		us[1] = ch2;
		us[2] = ch3;
		ucs = fromUTF8(us,&len,NULL);
		if( 0xFF61 <= ucs && ucs <= 0xFF9F ){
			return ucs - 0xFF61 + 0xA1;
		}
	}
	return 0;
}

#define canbeEUCJP(ccx) \
	(inNonASCII(ccx,CC_EUCJP)||guessCode(ccx,cinb,pix-1,pin,pilen)==CC_EUCJP)

#define IS_WORDS	0x01
#define IS_LINES	0x02
#define isSJIS(ccx,is,ib,px,pn,pl)     isSJISX(ccx,8,0,is,ib,px,pn,pl)
#define isSJISline(ccx,is,ib,px,pn,pl) isSJISX(ccx,128,IS_WORDS,is,ib,px,pn,pl)
#define isSJIS2Bline(ccx,is,ib,px,pn,pl) \
	(isSJISX(ccx,128,IS_WORDS,is,ib,px,pn,pl)&0xFFFF0000)
#define isEUCJP(ccx,ib,px,pn,pl)       isEUCJPX(ccx,8,0,ib,px,pn,pl)
#define isEUCJPline(ccx,ib,px,pn,pl)   isEUCJPX(ccx,128,IS_WORDS,ib,px,pn,pl)
#define isUTF8line(ccx,ib,px,pn,pl)    isUTF8X(ccx,128,IS_WORDS,ib,px,pn,pl)

static int isSJISX(CCX *ccx,int jlen,int flag,int insjis,unsigned PCStr(cinb),int pix,int pin,int pilen){
	int ci;
	int ch1,ch2;
	int sj = insjis;
	int issj = 0;

	sj = 0; /* 9.5.0-pre5 look forward only */

#if 0
	if( ccx->cc_indef == CC_UTF8
	 || ccx->cc_indef == CC_EUCJP
	){
		/* 9.5.3 non SJIS context */
		/* safer for less mixed text but not adaptive to mixed text */
	}else
#endif
	if( ccx->cc_linecc == CC_SJIS
	 || ccx->cc_linecc == 0 && (flag & IS_WORDS)
	){
		/* 9.5.3 pure SJIS context, ex. "hibo ya chusho" */
		sj = 1;
	}

	for( ci = 0; ci < jlen; ){
		ch1 = CHn(ci);
		if( ch1 == EOB )
			break;
		if( (ch1 & 0x80) == 0 ){
			if( ch1 == '\n' ){
				if( flag & IS_LINES ){
					ci++;
					continue;
				}
				break;
			}
			if( flag & IS_WORDS ){
				ci++;
				continue;
			}
			break;
		}
		if( IS_SJIS_1B(ch1) ){
			issj++;
			ci++;
			continue;
		}
		ch2 = CHn(ci+1);
		if( ch2 == EOB ){
			if( !IS_SJIS_HI(ch1) && !IS_SJIS_HIX(ch1) ){
				issj = 0;
			}
			break;
		}
		if( IS_SJIS_2B(ch1,ch2,sj) ){
			issj += 0x10000;
			ci += 2;
			continue;
		}
		issj = 0;
		break;
	}
	return issj;
}
static int isEUCJPX(CCX *ccx,int jlen,int flag,unsigned PCStr(cinb),int pix,int pin,int pilen){
	int ci;
	int ch1,ch2,ch3;
	int isej = 0;

	for( ci = 0; ci < jlen; ){
		ch1 = CHn(ci);
		if( ch1 == EOB )
			break;
		if( (ch1 & 0x80) == 0 ){
			if( ch1 == '\n' ){
				if( flag & IS_LINES ){
					ci++;
					continue;
				}
				break;
			}
			if( flag & IS_WORDS ){
				ci++;
				continue;
			}
			break;
		}
		ch2 = CHn(ci+1);
		if( ch1 == 0x92 )
		if( !ccx->cc_SJIS && !ccx->cc_UTF8 && !ccx->cc_EURO8 ){
			ch3 = CHn(ci+2);
			if( ch2 == EOB
			 || IS_EUC_HI(ch2) && ch3 == EOB
			 || IS_EUCJP(ch2,ch3)
			){
				/* 9.6.0 Emacs internal ? */
				ci++;
				continue;
			}
		}
		if( ch2 == EOB ){
			if( ch1 != 0x8F && !IS_EUC_HI(ch1) ){
				isej = 0;
			}
			break;
		}

		if( ccx->cc_EUCJP == 0 )
		if( ch1 == 0xA3 && (ch2 < 0xB0 || 0xBA <= ch2 & ch2 <= 0xBF)
		 || ch1 == 0xCF && (0xD3 < ch2)
		){
			/* 9.5.7 no JIS code assigned in this region, GB2312? */
			isej = 0;
			break;
		}
		if( ch1 == 0x8F ){
			ch3 = CHn(ci+2);
			if( ch3 == EOB ){
				if( !IS_EUC_HI(ch2) ){
					isej = 0;
				}
				break;
			}
			if( IS_EUCJP(ch2,ch3) ){
				isej++;
				ci += 3;
				continue;
			}
		}
		if( IS_EUCJP(ch1,ch2) ){
			isej += 2;
			ci += 2;
			continue;
		}
		isej = 0;
		break;
	}
	return isej;
}
static int EUCgtSJIS(CCX *ccx,unsigned PCStr(cinb),int pix,int pin,int pilen){
	int elen,slenx,slen;

	elen = isEUCJPline(ccx,cinb,pix-1,pin,pilen);
	slenx = isSJISline(ccx,0,cinb,pix-1,pin,pilen);
	slen = (0xFFFF & (slenx >> 16)) + (0xFFFF & slenx); 
	//syslog_ERROR("S:%X(%d) <= E:%d ?\n",slenx,slen,elen);
	if( slen < elen )
		return 1;
	if( slen == elen ){
		if( ccx->cc_indef == CC_EUCJP )
			return 2;
		if( ccx->cc_indef == CC_SJIS )
			return 0;
		if( maybein(CC_EUCJP) )
			return 3;
	}
	return 0;
}
static int isUTF8X(CCX *ccx,int jlen,int flag,unsigned PCStr(cinb),int pix,int pin,int pilen){
	int ci;
	int ch1;
	int chx;
	UCStr(us,8);
	int un,ui;
	int len;
	unsigned int ucs;
	int isu8 = 0;

	for( ci = 0; ci < jlen; ){
		ch1 = CHn(ci);
		if( ch1 == EOB )
			break;
		if( (ch1 & 0x80) == 0 ){
			if( ch1 == '\n' ){
				if( flag & IS_LINES ){
					ci++;
					continue;
				}
				break;
			}
			if( flag & IS_WORDS ){
				ci++;
				continue;
			}
			break;
		}
		setVStrElem(us,0,ch1);
		if( (ch1 & 0xE0) == 0xC0) un = 2; else
		if( (ch1 & 0xF0) == 0xE0) un = 3; else
		if( (ch1 & 0xF8) == 0xF0) un = 4; else
		if( (ch1 & 0xFC) == 0xF8) un = 5; else
		{
			isu8 = 0;
			break;
		}
		for( ui = 1; ui < un; ui++ ){
			chx = CHn(ci+ui);
			if( chx == EOB ){
				return isu8;
			}
			setVStrElem(us,ui,chx);
		}
		len = 0;
		ucs = fromUTF8(us,&len,NULL);
		if( len != un ){
fprintf(stderr,"--ccxU[%d] %d/%d %X BAD UTF-8 -------\n",getpid(),len,un,ucs);
			break;
		}
		if( 1 < len ){
			isu8 += len;
			ci += len;
			continue;
		}
		isu8 = 0;
		break;
	}
	return isu8;
}

#define isHex(c) ('A' <= c && c <= 'F' || 'a' <= c && c <= 'f')

static int CCXexecNonJP(CCX *ccx,unsigned int ch1,unsigned char *op,unsigned PCStr(ox)){
	int len = 0;
	int ucs;

	if( ccx->cc_OUT == CC_UTF8 )
	if( ccx->cc_flags & CCF_IN_ANSI )
	if( ccx->cc_in == CC_ASCII || ccx->cc_in == CC_EURO8 )
	if( !ccx->cc_EUCJP && !ccx->cc_SJIS && !ccx->cc_UTF8 )
	{
		switch( ccx->cc_OUT ){
		    case CC_UTF8:
			if( 0xA0 <= ch1 ){
				len = toUTF8(ch1,op);
			}else
			if( ucs = ANSItoUCS(ch1) ){
				len = toUTF8(ucs,op);
			}
			break;
		}
	}
	return len;
}

static int putJISch(CCX *ccx,int ichset,USChar ch1,USChar ch2,USChar *op,const USChar *ox){
	const USChar *oop = op;
	int ocset;

	if( ccx->cc_OUT == CC_GUESS || ccx->cc_OUT == CC_ASIS ){
		ocset = ichset;
	}else	ocset = ccx->cc_OUT;

	switch( ocset ){
		case CC_EUCJP:
			*op++ = 0x80 | ch1;
			*op++ = 0x80 | ch2;
			break;
		case CC_SJIS:
			JIS_TO_SJIS1(0x7F&ch1,0x7F&ch2,op);
			op += 2;
			break;
		case CC_JIS2B7:
			toJIS7(ccx,op);
			*op++ = 0x7F & ch1;
			*op++ = 0x7F & ch2;
			break;
		case CC_UTF8:
			op += EUCtoUTF8((ch1<<8)|ch2,op,ox);
			break;
		case CC_ASCII:
		case CC_EURO8:
			op += EUCtoHTML((ch1<<8)|ch2);
			break;
		default:
			*op++ = ch1;
			*op++ = ch2;
			break;
	}
	return op - oop;
}
static int putJISXch(CCX *ccx,int ichset,USChar ch1,USChar ch2,USChar *op,const USChar *ox){
	int code;
	const USChar *oop = op;
	int ocset;

	if( ccx->cc_OUT == CC_GUESS || ccx->cc_OUT == CC_ASIS ){
		ocset = ichset;
	}else	ocset = ccx->cc_OUT;

	switch( ocset ){
		case CC_UTF8:
			code = U_JIS0212|0x7F7F&((ch1<<8)|ch2);
			op += EUC3toUTF8(code,op,ox);
			break;
		case CC_ASCII:
		case CC_EURO8:
			code = U_JIS0212|0x7F7F&((ch1<<8)|ch2);
			op += EUCtoHTML(code);
			break;
		case CC_EUCJP:
			*op++ = 0x8F;
			*op++ = ch1;
			*op++ = ch2;
			break;
		case CC_SJIS:
			op += EUCXtoSJISX(ccx,ch1,ch2,op,ox);
			break;
		case CC_JIS2B7:
		case CC_JIS2B7X:
			toJIS7X(ccx,op);
			*op++ = 0x7F & ch1;
			*op++ = 0x7F & ch2;
			break;
		default:
			Xsprintf(ZVStr((char*)op,ox-op),
				"{#CCX:EUC3B:%X%X#}",ch1,ch2);
			op += strlen((char*)op);
			break;
	}
	return op - oop;
}
static int scanHTMLchent(CCX *ccx,const USChar *cinb,int pix,int pin,int ilen,int pilen,int *npix){
	int ci;
	int pixn;
	char chs[8];
	int hex = 0;
	int uc;
	int ch3;

	if( CHn(0) != '&' || CHn(1) != '#' )
		return -1;
	pixn = pix;
	pixn += 2;
	for( ci = 0; ci < elnumof(chs)-1; ci++ ){
		ch3 = CHn(2+ci);
		pixn++;
		if( ch3 == ';' ){
			break;
		}
		if( !isdigit(ch3) ){
			if( ci == 0 && ch3 == 'x' ){
				hex = 1;
			}else
			if( hex && isHex(ch3) ){
			}else{
				break;
			}
		}
		chs[ci] = ch3;
		chs[ci+1] = 0;
	}
	if( ch3 != ';' )
		return -1;

	*npix = pixn;
	if( chs[0] == 'x' ){
		uc = 0;
		sscanf(chs+1,"%x",&uc);
	}else{
		uc = atoi(chs);
	}
	return uc;
}

static const char YUCX[] = "+-/13JKLMNQTWZ]s";
static int putYUC(PVStr(op),int ucs){
	IStr(xuc,32);
	int xi;

	sprintf(xuc,"$)$%c$%c$%c$%c",
		YUCX[0xF&(ucs>>12)],
		YUCX[0xF&(ucs>>8)],
		YUCX[0xF&(ucs>>4)],
		YUCX[0xF&(ucs>>0)]
	);
	for( xi = 0; xuc[xi]; xi++ )
		xuc[xi] |= 0x80;
	Xstrcpy(BVStr(op),xuc);
	return 1;
}
static int xucd(int ch){
	switch( 0x7F & ch ){
		case '+': return 0x0;
		case '-': return 0x1;
		case '/': return 0x2;
		case '1': return 0x3;
		case '3': return 0x4;
		case 'J': return 0x5;
		case 'K': return 0x6;
		case 'L': return 0x7;
		case 'M': return 0x8;
		case 'N': return 0x9;
		case 'Q': return 0xA;
		case 'T': return 0xB;
		case 'W': return 0xC;
		case 'Z': return 0xD;
		case ']': return 0xE;
		case 's': return 0xF;
	}
	return 0;
}
static int isYUC(CCX *ccx,int ch1,unsigned PCStr(cinb),int pix,int pin,int pilen,int *chp){
	int ch;

	if( CHn(0) == (0x80|'$') && CHn(1) == (0x80|')') )
	if( CHn(2) == (0x80|'$') )
	if( CHn(4) == (0x80|'$') )
	if( CHn(6) == (0x80|'$') )
	if( CHn(8) == (0x80|'$') )
	{
		ch = (xucd(CHn(3))<<12)
		   | (xucd(CHn(5))<<8)
		   | (xucd(CHn(7))<<4)
		   | (xucd(CHn(9)));
		*chp = ch;
		return 1;
	}
	return 0;
}

int CCXpending(CCX *ccx){
	return ccx->cc_pinx;
}
int CCXexec(CCX *ccx,PCStr(scinb),int ilen,PVStr(sout),int osiz)
{	const unsigned char *cinb = (unsigned char *)scinb;
	UrefQStr(out,sout);
	int ch1,ch2,ch3,ch4;
	USChar ucsb[8];
	int pch;
	const unsigned char *pinb;
	unsigned char *op; /**/
	const unsigned char *ox;
	int pilen,pix,pin;
	int insjis;
	const char *js = 0;
	int cat;
	int codesw;
	int outlen;
	int len1;
	unsigned char *outtop; /**/
	unsigned char outbuf[2048]; /**/
	int chA;
	int badout = 0;
	int CH3b = -1;
	int CH4b = -1;
	int isUTF8tmp = 0;
	int isUCSch = 0;
	int mapped;
	int xch1,xch2;
	int ucs1,ucs2,ucs3;
	unsigned int euc1;

	if( out == cinb ){
		if( osiz <= sizeof(outbuf) )
			outtop = outbuf;
		else	outtop = (unsigned char*)malloc(osiz); 
	}else	outtop = (USChar*)out;
	op = outtop;
	ox = outtop + (osiz - 1);

	pin = ccx->cc_pinx; ccx->cc_pinx = 0;
	pinb = ccx->cc_pinb;
	pilen = pin + ilen;
	pix = 0;
	pch = -1;
	ch1 = -1;

	insjis = 0; /* 9.5.0-pre5 must be initialized */

	while( pix < pilen && op < ox ){
		/* 9.5.0-pre5 */
		if( pix < (op-outtop) ) /* in conversion ... */
		if( ox <= op+6 ) /* "ESC$(DAB" (6) might be added */
		{
			syslog_ERROR("%s:%d CCX ovf i:%d/%d o:%d/%d\n",
				whStr(sout),pix,pilen,ll2i(op-outtop),osiz);
			break;
		}
		pch = ch1;
		ch1 = CH1;
		pix++;
		ch2 = CH2;

		if( ccx->cc_flags & CCF_YUC ){
			/* 9.9.1 if is in EUC-JP */
			if( isYUC(ccx,ch1,cinb,pix-1,pin,pilen,&ucs1) ){
				op += toUTF8(ucs1,(unsigned char*)op);
				pix += 9;
				continue;
			}
		}

		if( (ccx->cc_instat & CCI_BINARY) == 0 )
		if( !ccx->cc_SJIS && !ccx->cc_EUCJP && !ccx->cc_UTF8 )
		if( !ccx->cc_JIS7 ) /* 9.8.4 */
		if( CCX_OUTJA(ccx) )
		{
			/* 9.5.0 maybe in binary */
			if( ccx->cc_EURO8 ){
				ccx->cc_instat |= CCI_BINARY;
			}
			if( ch1 == 0 && ch2 == 0 ){
				ccx->cc_instat |= CCI_BINARY;
			}
		}
		if( ccx->cc_instat & CCI_BINARY ){
			*op++ = ch1;
			continue;
		}
		if( ch1 == '\n' ){
			ccx->cc_linecc = 0;
		}

/*
 if( 0x80 & ch1 )
 fprintf(stderr,
 "--%X[%3d] ccxexec [%2X %2X %2X %2X] in%d/%d/%d E%d S%d U%d e%d %d\n",
 ccx,pix,0xFF&ch1,0xFF&ch2,0xFF&CH3,0xFF&CH4,
 ccx->cc_in,ccx->cc_linecc,ccx->cc_indef,
 ccx->cc_EUCJP,ccx->cc_SJIS,ccx->cc_UTF8,ccx->cc_EURO8,
 ccx->cc_symconv & SCinURL);
*/

		if( ccx->cc_incc1 == 0 ) /* or if at the top of file */
		if( pix == 1 ){
			if( ch1 == 0xFE && ch2 == 0xFF ){
				setccin(ccx,CC_UTF16);
				if( CCX_NOCONV(ccx) ){
					*op++ = ch1;
					*op++ = ch2;
				}
				pix++;
				continue;
			}
			if( ch1 == 0xFF && ch2 == 0xFE ){
				ccx->cc_flags |= CCF_UTFLE;
				setccin(ccx,CC_UTF16);
				if( CCX_NOCONV(ccx) ){
					*op++ = ch1;
					*op++ = ch2;
				}
				pix++;
				continue;
			}
		}
		if( ccx->cc_in == CC_UTF16 ){
			if( ch2 == EOB ){
				pushpending(ccx,ch1);
				break;
			}
			if( CCX_NOCONV(ccx) ){
				*op++ = ch1;
				*op++ = ch2;
				pix++;
				continue;
			}
			if( ccx->cc_flags & CCF_UTFLE )
				ucs1 = (ch2<<8)|ch1;
			else	ucs1 = (ch1<<8)|ch2;
			if( (ucs1 & 0xFC00) == 0xD800 ){
				ch3 = CH3;
				ch4 = CH4;
				if( ch3 == EOB || ch4 == EOB ){
					break;
				}
				if( ccx->cc_flags & CCF_UTFLE )
					ucs2 = (ch4<<8)|ch3;
				else	ucs2 = (ch3<<8)|ch4;
				if( (ucs2 & 0xFC00) != 0xDC00 ){
					syslog_ERROR("UCS16 ? %X %X %X %X\n",
						ch1,ch2,ch3,ch4);
					continue;
				}
				ucs1 &= 0x3FF;
				ucs2 &= 0x3FF;
				ucs3 = ((ucs1 << 10) | ucs2) + 0x10000;
				op += toUTF8(ucs3,(unsigned char*)op);
				pix += 3;
			}else{
				op += toUTF8(ucs1,(unsigned char*)op);
				pix++;
			}
			continue;
		}
		isUCSch = 0;
		if( ccx->cc_OUT != CC_GUESS )
		if( ccx->cc_OUT != CC_ASIS )
		if( ccx->cc_symconv & SCinURL )
		if( ch1 == '&' && ch2 == '#' ){
			int npix;
			int uc;
			uc = scanHTMLchent(ccx,cinb,pix-1,pin,ilen,pilen,&npix);
			if( 0 < uc ){
				len1 = toUTF8(uc,ucsb);
				ch1 = ucsb[0];
				if( 1 < len1 ) ch2 = ucsb[1];
				if( 2 < len1 ) CH3b = ucsb[2];
				if( 3 < len1 ) CH4b = ucsb[3];
				isUCSch = len1;
				pix = npix;
			}
		}

		if( ccx->cc_symconv & SCtoLF ){
			if( ch1 == '\r' && ch2 == '\n' ){
				continue;
			}
		}
		if( ccx->cc_symconv & SCtoCRLF ){
			if( pch != '\r' && ch1 == '\n' ){
				*op++ = '\r';
			}
		}

		if( isNotInNONJP(ccx) )
		if( ch1 == 033 ){
			/* single ESC from keyboard input must be passed
			 * thru ...  */
			if( ch2 == EOB /* && not buffer full ... */ ){
				pushpending(ccx,ch1);
				break;
			}
			if( ch2 == '$' || ch2 == '(' ){
				ch3 = CH3;
				if( ch3 == EOB ){
					pushpending(ccx,ch1);
					pushpending(ccx,ch2);
					break;
				}

				codesw = 0;
				if( ch2 == '$' ){
					if( ch3 == 'B' || ch3 == '@' )
						codesw = CC_JIS2B7;
					else
					if( ch3 == '(' ){
						if( CH4 == 'D' ){
							codesw = CC_JIS2B7X;
							setccin(ccx,codesw);
							pix += 3;
							if( ccx->cc_OUT == CC_GUESS ){
								*op++ = 033;
								*op++ = '$';
								*op++ = '(';
								*op++ = 'D';
							}
							continue;
						}
						if( CH4 == 'Q' ){
							/* 0213-1 like ESC$B */
							codesw = CC_JIS2B7X2;
						}
						if( CH4 == 'P' ){
							/* 0213-2 like ESC$(D */
							codesw = CC_JIS2B7X3;
						}
					}
				}else
				if( ch2 == '(' ){
					if( ch3 == 'B' ){
						codesw = CC_ASCII;
					}else
					if( ch3 == 'J' ){
						codesw = CC_ASCII;
						/* CC_JIS7ROMA */
					}else
					if( ch3 == 'I' ){
						codesw = CC_JIS7KANA;
					}
				}
				if( codesw ){
					setccin(ccx,codesw);
					if( JIS2B8(ccx->cc_OUT)
					 || ccx->cc_OUT == CC_UTF8
					 || ccx->cc_OUT == CC_JIS2B7
					 && codesw == CC_JIS7KANA
					){
						pix += 2;
						continue;
					}
					else
					if( ( ccx->cc_OUT == CC_EURO8
					    ||ccx->cc_OUT == CC_ASCII )
					 && (ccx->cc_symconv & SCinURL)
					){
						pix += 2;
						continue;
					}else
					if( ccx->cc_symconv & SCtoASCII ){
						pix += 2;
						continue;
					}
					else
					if( withCHARMAP(CSM_JIS2JIS)
					 || withCHARMAP(CSM_ASCII2ASCII)
					){
						pix += 2;
						continue;
					}
				}
			}
			/* cc_in will be set setccin(CC_ASCII) at the end */

			if( ccx->cc_flags & CCF_ESC_K ){
				/* 9.8.4 for MacOSX Terminal */
				if( CH2 == '[' && CH3 == 'K' ){
					*op++ = ' ';
					/*
					*op++ = '\b';
					*/
				}
			}
		}

		if( isNotInNONJP(ccx) )
		if( ccx->cc_in == CC_JIS7KANA )
		if( (ch1 & 0x80) == 0 && IS_SJIS_1B(ch1 | 0x80) ){
			switch( ccx->cc_OUT ){
			    case CC_JIS7K:
				*op++ = ch1;
				break;

			    case CC_JIS2B7:
				toJIS7(ccx,op);
				js = sjis_1b_to_jis(ch1,ch2,&cat);
				*op++ = js[0];
				*op++ = js[1];
				if( cat ) pix++;
				break;

			    case CC_EUCJP:
				*op++ = EUC_HANKAKU_HI;
				*op++ = 0x80 | ch1;
				break;

			    default:
				*op++ = 0x80 | ch1;
				break;
			}
			continue;
		}

		if( isNotInNONJP(ccx) )
		if( ccx->cc_in == CC_JIS2B7 && IS_JIS_HI(ch1) ){
			if( ch2 == EOB ){
				pushpending(ccx,ch1);
				break;
			}
			if( IS_JIS7(ch1,ch2) ){
				mapped = mapJIS2B(CC_JIS2B7,0,&ch1,&ch2);
				switch( mapped ){
					case MAP_1B:
						toASCII(ccx,op);
						*op++ = ch1;
						pix++;
						continue;
				}

				if( (ccx->cc_symconv & SCtoASCII)
				 && (chA = JIS_TO_ASCII(CC_JIS2B7,ch1,ch2,0)) )
				{
					toASCII(ccx,op);
					*op++ = chA;
				}else
				switch( ccx->cc_OUT ){
					case CC_SJIS:
						JIS_TO_SJIS1(ch1,ch2,op);
						op += 2;
						break;
					case CC_EUCJP:
						if( mapped == MAP_JISX0212 )
						*op++ = 0x8F;
						*op++ = 0x80 | ch1;
						*op++ = 0x80 | ch2;
						break;
					case CC_UTF8:
						op += EUCtoUTF8((ch1<<8)|ch2,op,ox);
						break;
					case CC_ASCII:
					case CC_EURO8:
						op += EUCtoHTML((ch1<<8)|ch2);
						break;

					default:
						if( mapped == MAP_JISX0212 ){
							toJIS7X(ccx,op);
						}else
						toJIS7(ccx,op);
						*op++ = ch1;
						*op++ = ch2;
						break;
				}
				pix++;
				continue;
			}
		}
		if( isNotInNONJP(ccx) )
		if( ccx->cc_in == CC_JIS2B7X && IS_JIS_HI(ch1) ){
			if( ch2 == EOB ){
				pushpending(ccx,ch1);
				break;
			}
			if( IS_JIS7(ch1,ch2) ){
				xch1 = 0x80|ch1;
				xch2 = ch2;
				mapped = mapJIS2B(CC_JIS2B7X,1,&xch1,&xch2);
				switch( mapped ){
					case MAP_1B:
						toASCII(ccx,op);
						*op++ = xch1;
						pix++;
						continue;
					default:	
						ch1 = xch1 & 0x7F;
						ch2 = xch2;
						break;
				}

				if( (ccx->cc_symconv & SCtoASCII)
				 && (chA = JIS_TO_ASCII(CC_JIS2B7,ch1,ch2,0)) )
				{
					toASCII(ccx,op);
					*op++ = chA;
				}else
				switch( ccx->cc_OUT ){
					default:
					case CC_GUESS:
						*op++ = ch1;
						*op++ = ch2;
						break;

					case CC_JIS2B7:
						if( mapped == MAP_JISX0208 ){
							toJIS7(ccx,op);
						}else	toJIS7X(ccx,op);
						*op++ = ch1;
						*op++ = ch2;
						break;
					case CC_SJIS:
						if( mapped != MAP_JISX0208 ){
							*op++ = '?';
							break;
						}
						JIS_TO_SJIS1(ch1,ch2,op);
						op += 2;
						break;
					case CC_EUCJP:
						if( mapped != MAP_JISX0208 )
						*op++ = 0x8F;
						*op++ = 0x80 | ch1;
						*op++ = 0x80 | ch2;
						break;
					case CC_UTF8:
						if( mapped != MAP_JISX0208 ){
						op += toUTF8X(ccx,U_JIS0212|(ch1<<8|ch2),op,ox);
						}else{
						op += toUTF8X(ccx,(ch1<<8|ch2),op,ox);
						}
						break;

					case CC_ASCII:
					case CC_EURO8:
						op += EUCtoHTML((ch1<<8)|ch2);
						break;
				}
				pix++;
				continue;
			}
		}

		if( ch1 == 0x92 )
		if( CCX_OUTJA(ccx) )
		if( !ccx->cc_SJIS && !ccx->cc_UTF8 && !ccx->cc_EURO8 ){
			/* 9.6.0 Emacs internal ? */
			if( ccx->cc_linecc == 0 ){
			    if( isEUCJPline(ccx,cinb,pix-1,pin,pilen) ){
				ccx->cc_linecc = CC_EUCJP;
		 		if( isSJIS(ccx,insjis,cinb,pix-1,pin,pilen) ){
					ccx->cc_EUCJP |= 1;
				}
			    }
			}
			if( ccx->cc_linecc == CC_EUCJP ){
				continue;
			}
		}

		/* care UTF-8 in Shift_JIS */
		/* rescue 3bytes of UTF-8 in EUC-JP */
		if( isUTF8tmp ){
			isUTF8tmp = 0;
			ccx->cc_UTF8 = 0;
		}
		if( ccx->cc_SJIS || ccx->cc_EUCJP )
		if( (ch1&0xF0) == 0xE0 && (ch2 & 0x80) ){
			int ucs,len;
			unsigned int euc;
			ucs = UTF8toUCS(ch1,ch2,CH3,&len,&euc);
/* 
 if( euc != 0 )
 fprintf(stderr,
 "-- %5d U8t=%d [%X %X %X %X %X %X] %4X %2X %4X S=%d/%d,E=%d/%d,U=%d\n",
 pix,isUTF8tmp,
 ch1,ch2,CH3,CH4,CH5,CH6,ucs,len,euc,
 ccx->cc_SJIS, ccx->cc_sjis,
 ccx->cc_EUCJP, ccx->cc_euc,
 ccx->cc_UTF8);
*/
			if( ccx->cc_linecc != 0
			 && ccx->cc_linecc != CC_UTF8
			 && ccx->cc_linecc != CC_EUCJP
			){
				/* 9.5.3 no "UTF-8 in EUCJP" in non-EUCJP */
			}else
			if( ccx->cc_EUCJP ){
				if( len != 3 || euc == 0 ){
				}else
				if( ccx->cc_in==CC_UTF8 && contUTF8(CH4,CH5) ){
					isUTF8tmp = 1;
				}else
				/*
				if( IS_EUC(ch1,ch2) && IS_EUC(CH3,CH4)
				 && IS_EUC(CH5,CH6)
				){
				*/
				if( isEUCJPline(ccx,cinb,pix-1,pin,pilen) ){
					/*
					c1c2c3 c4c5c6 / c1c2 c3c4 c5c6
					c3c4 or c5c6 might not be EUC
					*/
fprintf(stderr,"--ccxB[%d] %3d UTF8inEUC  %X %X %X %X %X\n",
getpid(),pix,ch1,ch2,CH3,CH4,CH5);
				}else
				if( !contUTF8(CH4,CH5) ){
				}else{
					isUTF8tmp = 1;
				}
				ccx->cc_UTF8 = 0;
			}
			if( ccx->cc_linecc != 0
			 && ccx->cc_linecc != CC_UTF8
			 && ccx->cc_linecc != CC_SJIS
			){
				/* 9.5.3 no "UTF-8 in SJIS" in non-SJIS */
			}else
			if( ccx->cc_SJIS ){
				if( len != 3 || euc == 0 ){
				}else
				/*
				if( isSJIS(ccx,insjis,cinb,pix-1,pin,pilen) ){
				*/
				/*
				if( isSJISline(ccx,insjis,cinb,pix-1,pin,pilen) ){
				*/
				if( isSJISline(ccx,insjis,cinb,pix-1,pin,pilen)
 				 && ( !inccctx(ccx,CC_UTF8) 
				   || !isUTF8line(ccx,cinb,pix-1,pin,pilen)
				 )
				){
					/* should be cared as SJIS */
				}else
				if( !contUTF8(CH4,CH5) ){
				}else{
					isUTF8tmp = 1;
				}
				ccx->cc_UTF8 = 0;
			}
		}

		/*
		*/
		if( isUCSch == 2 ){
			goto FromUTF8_2;
		}
		if( (ch1&0xE0) == 0xC0 && (ch2&0xC0) == 0x80 )
		if( contUTF8(CH3,CH4) )
		if( ccx->cc_UTF8
		 || !ccx->cc_SJIS && !ccx->cc_EUCJP && contUTF8(CH3,CH4)
		 && isUTF8_2B(ccx,ch1,ch2,cinb,pix-1,pin,ilen)
		 && isNotInNONJP(ccx)
		){
			/* 2bytes UTF-8 */
			setccin(ccx,CC_UTF8);
		FromUTF8_2:
			mapped = UTFmapped(ccx,ch1,ch2,0,0);
			if( mapped == MAP_1B ){
				*op++ = ch1;
			}else
			switch( ccx->cc_OUT ){
			    case CC_JIS2B7:
				op += UTF8toLocal(ch1,ch2,0,CC_JIS2B7,op,ox);
				break;
			    case CC_EUCJP:
				op += UTF8toLocal(ch1,ch2,0,CC_EUCJP,op,ox);
				break;
			    case CC_SJIS:
				op += UTF8toLocal(ch1,ch2,0,CC_SJIS,op,ox);
				break;
			    case CC_ASCII:
			    case CC_EURO8:
				ucsb[0] = ch1;
				ucsb[1] = ch2;
				ucsb[2] = 0;
				ucsb[3] = 0;
				op += UTF8toHTML(ccx,ucsb,op,ox);
				break;
			    default:
				*op++ = ch1;
				*op++ = ch2;
				break;
			}
			if( isUCSch ){
			}else
			pix++;
			continue;
		}

		if( isNotInNONJP(ccx) )
		/*
		if( !ccx->cc_SJIS && !ccx->cc_EUCJP || isUTF8tmp )
		if( (ch1&0xF0) == 0xE0 ){
		}
		*/
		if( !ccx->cc_SJIS && !ccx->cc_EUCJP || isUTF8tmp || isUCSch )
		if( (ch1&0xF0) == 0xE0
		 || (ch1&0xF8) == 0xF0 && canbeUTF8_2(ch2) /* 4bytes */
		){
			int isUTF8 = 0,insch = 0;
			int fromURL;

			if( fromURL = 0 <= CH3b ){
				ch3 = CH3b; CH3b = -1;
				ch4 = CH4b; CH4b = -1;
				if( ch4 != -1 )
					isUTF8 = 4;
				else	isUTF8 = 1;
				goto FromUTF8;
			}else{
			ch3 = CH3;
			ch4 = CH4;
			}
			if( ccx->cc_UTF8 )
			if( ch2 == EOB || ch3 == EOB
			 || ch4 == EOB && (ch2 == '\n' || ch3 == '\n') ){
				pushpending(ccx,ch1);
				if( ch2 != EOB ) pushpending(ccx,ch2);
				if( ch3 != EOB ) pushpending(ccx,ch3);
				break;
			}

			if( ch2 == '\n'
			 && !CCX_NOCONV(ccx)
			 && ch3 != EOB && IS_UTF8_CONT(ch3)
			 && ch4 != EOB && IS_UTF8_CONT(ch4)
			){
				syslog_DEBUG("##CCX UTF8-RECOVER[%x %x %x %x]\n",
					ch1,ch2,ch3,ch4);
				ch2 = ch3;
				ch3 = ch4;
				insch = CH2;
				isUTF8 = 1;
			}else
			if( ch3 == '\n'
			 && !CCX_NOCONV(ccx)
			 && ch2 != EOB && IS_UTF8_CONT(ch2)
			 && ch4 != EOB && IS_UTF8_CONT(ch4)
			){
				syslog_DEBUG("##CCX UTF8-RECOVER[%x %x %x %x]\n",
					ch1,ch2,ch3,ch4);
				ch3 = ch4;
				insch = CH3;
				isUTF8 = 1;
			}else
			if( ch2 != EOB && IS_UTF8_CONT(ch2) )
			if( ch3 != EOB && IS_UTF8_CONT(ch3) )
			/*
			if( ch4 == EOB || (ch4&0x80)==0 || (ch4&0xF0)==0xE0 ){
			}
			*/
			if( contUTF8(ch4,CH5) ){
				if( ccx->cc_UTF8 == 0
				 && !isUTF8line(ccx,cinb,pix-1,pin,pilen) ){
					/* 9.5.3 non-UTF8 in this line */
fprintf(stderr,"--ccx[%d] NOT UTF8 LINE A [%X %X %X][%X %X] U=%d\n",
getpid(),ch1,ch2,ch3,ch4,CH5,ccx->cc_UTF8);
				}else
				isUTF8 = 1;
			}
			else
			if( ch4 != EOF && IS_UTF8_CONT(ch4)
			&& (ch1 & 0xF8) == 0xF0
			){
				isUTF8 = 4;
			}

		FromUTF8:
			if( isUTF8 ){
			    if( !isUCSch )
			    setccin(ccx,CC_UTF8);

			  if( CCX_OUTJA(ccx) ){
			    ucs1 = UTF8toUCS(ch1,ch2,ch3,&len1,&euc1);
			    if( JIS_dakuten(0x7F&(euc1>>8),0x7F&euc1,0) ){
				int l1,c1,c2,cx;
				unsigned int e1;
				c1 = 0x7F & (euc1>>8);
				c2 = 0x7F & (euc1);
				ucs1 = UTF8toUCS(CH4,CH5,CH6,&l1,&e1);
			        if( cx = JIS_dakuten(c1,c2,ucs1) ){
					op += putJISch(ccx,CC_UTF8,c1,cx,op,ox);
					if( isUCSch ){
					}else	pix += 2;
					pix += l1;
					continue;
				}
			    }
			  }
			    if( (ccx->cc_symconv & SCtoJISZK)
			     || ccx->cc_OUT == CC_JIS2B7
			    )
			    if( op[0] = isUTF8_HANKAKU(ch1,ch2,ch3) ){
				int npix;
				if( isUCSch ){
					USChar u[8];
					ucs1 = scanHTMLchent(ccx,cinb,pix,
						pin,ilen,pilen,&npix);
					toUTF8(ucs1,u);
					op[1] = isUTF8_HANKAKU(u[0],u[1],u[2]);
				}else{
					op[1] = isUTF8_HANKAKU(CH4,CH5,CH6);
				}
				if( op[1] ){
					js = sjis_1b_to_jis(op[0],op[1],&cat);
					if( cat ){
						if( isUCSch ){
							pix = npix;
						}else	pix += 3;
					}
				}else{
					js = sjis_1b_to_jis(op[0],0,&cat);
				}
				op += putJISch(ccx,CC_UTF8,js[0],js[1],op,ox);
				if( isUCSch ){
				}else	pix += 2;
				continue;
			    }

			    mapped = UTFmapped(ccx,ch1,ch2,ch3,ch4);
			    if( mapped == MAP_1B ){
				toASCII(ccx,op);
			    	op += UTF8toLocal(ch1,ch2,ch3,ccx->cc_OUT,op,ox);
			    }else
			    if( (ccx->cc_symconv & SCtoASCII)
			    && (chA=JIS_TO_ASCII(CC_UTF8,ch1,ch2,ch3)) ){
				toASCII(ccx,op);
				*op++ = chA;
			    }else
			    switch( ccx->cc_OUT ){
				case CC_JIS2B7:
				    op += UTF8toLocal(ch1,ch2,ch3,CC_JIS2B7,op,ox);
				    break;
				case CC_EUCJP:
				    op += UTF8toLocal(ch1,ch2,ch3,CC_EUCJP,op,ox);
				    break;
				case CC_SJIS:
				    op += UTF8toLocal(ch1,ch2,ch3,CC_SJIS,op,ox);
				    break;

				case CC_ASCII:
				case CC_EURO8:
				    ucsb[0] = ch1;
				    ucsb[1] = ch2;
				    ucsb[2] = ch3;
				    ucsb[3] = ch4;
				    op += UTF8toHTML(ccx,ucsb,op,ox);
				    break;

				default:
				    *op++ = ch1;
				    *op++ = ch2;
				    *op++ = ch3;
				    if( isUTF8 == 4 ) *op++ = ch4;
				    break;
			    }
			if( isUCSch ){
				/* pix added already */
			}else
			if( fromURL ){
			    if( insch ){
				*op++ = insch;
			    }
			}else{
			    if( isUTF8 == 4 )
				pix += 1;
			    pix += 2;
			    if( insch ){
				*op++ = insch;
				pix += 1;
			    }
			}
			    continue;
			}
		}

		/* care wrong charset=UTF-8 */
		if( ccx->cc_UTF8 && (ch1 & 0x80) ){
			if( ccx->cc_UTF8 == 10 ) /* (ccx->cc_UT8&1) == 0 */
			if( IS_SJIS_HI(ch1) || IS_EUC_HI(ch1) )
			{
syslog_ERROR("##CCX %d NON-UTF8 [%X %X] (%d,%d,%d)\n",
	pix,ch1,ch2,ccx->cc_UTF8,ccx->cc_sjis,ccx->cc_euc);
				ccx->cc_UTF8 = 0;
			}
		}

		if( ch1 & 0x80 )
		if( isNotInNONJP(ccx) )
		/*
		if( ccx->cc_UTF8 == 0 )
		*/
		if( ccx->cc_UTF8
		 && !isSJIS(ccx,insjis,cinb,pix-1,pin,pilen)
		 && !isEUCJP(ccx,cinb,pix-1,pin,pilen)
		){
		}else
		if( IS_SJIS_HI(ch1) || IS_EUC_HI(ch1) ){
			if( ch2 == EOB ){
			    if( ccx->cc_SJIS && IS_SJIS_1B(ch1) && ilen == 0 ){
				/* flush pending */
			    }else{
				pushpending(ccx,ch1);
				break;
			    }
			}

			/*
			if( ccx->cc_EUCJP < 10 )
			*/
			/*
			if( ccx->cc_EUCJP == 0 )
			*/
			if( ccx->cc_EUCJP == 0 || 0 < ccx->cc_SJIS )
			if( IS_SJIS_1B(ch1) )
			if( ccx->cc_linecc == CC_EUCJP
			 && IS_EUC_CH(ch1,ch2,CH3)
			 || ccx->cc_linecc == 0
			 && EUCgtSJIS(ccx,cinb,pix-1,pin,pilen)
			){
				/* 9.7.2 EUCJP char in a EUCJP line */
			}else
			if( ccx->cc_in != CC_EUCJP )
			if( !isSJIS(ccx,insjis,cinb,pix-1,pin,pilen) ){
				/* 9.5.0-pre6 not SJIS-1 */
			}else
			if( 10 <= ccx->cc_EURO8 ){
				/* 9.5.0-pre7 not SJIS-1B in EURO8 */
			}else
			if( ccx->cc_SJIS < ccx->cc_EURO8
			 && isSJISline(ccx,insjis,cinb,pix-1,pin,pilen) < 8
			){
				/* 9.5.0-pre11 not SJIS-1B in EURO8 */
			}else
			/*
			if( !inNonASCII(ccx,CC_SJIS)
			 && !is_SJIS(ccx,cinb,pix-1,pin,pilen) ){
			}else
			*/
			if( !inNonASCII(ccx,CC_SJIS)
			 && !isSJIS2Bline(ccx,insjis,cinb,pix-1,pin,pilen)
			 && isEUCJPline(ccx,cinb,pix-1,pin,pilen)
			 && canbeEUCJP(ccx)
			){
				/* 9.5.0-pre8 maybe EUC-JP in NNTP/HTTP */
				/* no SJIS yet and no SJIS-2B in this line */
			}else
			if( (ccx->cc_in == CC_EUCJP
			    || maybein(CC_EUCJP) && !maybein(CC_SJIS))
			 && isEUCJP(ccx,cinb,pix-1,pin,pilen) ){
			}else{
				setccin(ccx,CC_SJIS);

				if( ccx->cc_symconv & SCtoJISZK ){
				  if( IS_SJIS_1B(ch2) ){
				  	js = sjis_1b_to_jis(ch1,ch2,&cat);
				  	if( cat ) pix += 1;
				  }else{
					js = sjis_1b_to_jis(ch1,0,&cat);
				  }
				  op += putJISch(ccx,CC_SJIS,js[0],js[1],op,ox);
				  continue;
				}
				if( (ccx->cc_symconv & SCtoASCII)
				 && (chA = JIS_TO_ASCII(CC_SJIS,ch1,ch2,0)) )
				{
					toASCII(ccx,op);
					*op++ = chA;
				}
				else
				switch( ccx->cc_OUT ){
				    case CC_JIS7K:
					toJIS7K(ccx,op);
					*op++ = 0x7F & ch1;
					break;
				    case CC_JIS2B7:
					toJIS7(ccx,op);
					js = sjis_1b_to_jis(ch1,ch2,&cat);
					*op++ = js[0];
					*op++ = js[1];
					if( cat ) pix++;
					break;

				    case CC_EUCJP:
					*op++ = EUC_HANKAKU_HI;
					*op++ = ch1;
					break;

				    case CC_UTF8:
					op += toUTF8(0xFF00|(ch1-0x40),op);
					break;

				    case CC_ASCII:
				    case CC_EURO8:
					ucs1 = 0xFF00|(ch1-0x40);
					op += UCStoHTML(ccx,ucs1,op,ox);
					break;

				    default:
					*op++ = ch1;
					break;
				}
				continue;
			}

			if( IS_EUC_HANKAKU(ch1,ch2) )
			if( ccx->cc_linecc == CC_SJIS && IS_SJIS_CH(ch1,ch2) ){
				/* 9.7.2 SJIS char ex.[8E D2] in SJIS line */
			}else
			if( inNonASCII(ccx,CC_EUCJP)
			 || !is_SJIS(ccx,cinb,pix-1,pin,pilen) ){
			inEUC_JP1:
				setccin(ccx,CC_EUCJP);
				ch3 = CH3;
				ch4 = CH4;
				pix++;

				if( ccx->cc_symconv & SCtoJISZK ){
				  if( IS_EUC_HANKAKU(ch3,ch4) ){
				  	js = sjis_1b_to_jis(ch2,ch4,&cat);
				  	if( cat ) pix += 2;
				  }else{
					js = sjis_1b_to_jis(ch2,0,&cat);
				  }
				  op +=putJISch(ccx,CC_EUCJP,js[0],js[1],op,ox);
				  continue;
				}
				switch( ccx->cc_OUT ){
				    case CC_SJIS:
					*op++ = ch2;
					break;

				    case CC_JIS7K:
					toJIS7K(ccx,op);
					*op++ = 0x7F & ch2;
					break;

				    case CC_JIS2B7:
					ch1 = ch2;
					if( IS_EUC_HANKAKU(ch3,ch4) )
						ch2 = ch4;
					else	ch2 = -1;

					toJIS7(ccx,op);
					js = sjis_1b_to_jis(ch1,ch2,&cat);
					*op++ = js[0];
					*op++ = js[1];
					if( cat ) pix += 2;
					break;

				    case CC_UTF8:
					op += toUTF8(0xFF00|(ch2-0x40),op);
					break;

				    case CC_ASCII:
				    case CC_EURO8:
					ucs1 = 0xFF00|(ch2-0x40);
					op += UCStoHTML(ccx,ucs1,op,ox);
					break;

				    default:
					*op++ = ch1;
					*op++ = ch2;
					break;
				}
				continue;
			}

			/*
			if( IS_EUC(ch1,ch2) )
			*/
			if( IS_EUCJP(ch1,ch2) )
			if( ccx->cc_linecc == CC_SJIS && IS_SJIS_CH(ch1,ch2) ){
				/* 9.7.2 SJIS char ex.[8E D2] in SJIS line */
			}else
			if( (ccx->cc_SJIS||ccx->cc_indef==CC_SJIS)
			 && ccx->cc_EUCJP == 0
			 && IS_SJIS_LO(ch2)
			 && (IS_SJIS_HI(ch1)||IS_SJIS_HIX(ch1))
			){
				/* could be EUC but in SJIS context */
			}else
			if( ccx->cc_euc < ccx->cc_sjis && (ch2&0x80)==0 ){
syslog_ERROR("#CCX NON-EUC-A (%d<%d) %X %X\n",ccx->cc_euc,ccx->cc_sjis,ch1,ch2);
			}else
			if( !canbeEUCJP(ccx) ){
				if( ccx->cc_linecc == CC_EUCJP
				 || isEUCJPline(ccx,cinb,pix-1,pin,pilen)
				){
					/* 9.5.3 "settei"+zenkakuSP in EUCJP */
					goto inEUC_JP;
				}
			}else
			/*
			if( inNonASCII(ccx,CC_EUCJP)
			 || guessCode(ccx,cinb,pix-1,pin,pilen)==CC_EUCJP )
			*/
			/*
			if( ccx->cc_SJIS && ccx->cc_EUCJP <= ccx->cc_SJIS
			 && dont_swccin(ccx,CC_EUCJP,ch1,ch2) ){
			}else
			*/
			if( ccx->cc_EURO8 && !maybein(CC_EUCJP) ){
				/* non-JIS char. have been detected */
			}else
			if( ccx->cc_incc1 == 0
			 && !maybein(CC_EUCJP)
			 && !isEUCJPline(ccx,cinb,pix-1,pin,pilen)
			){
				/* 9.5.7 the first non-ASCII, can be non-JIS */
			}else
			{
			inEUC_JP:
				if( ccx->cc_SJIS
				 && ccx->cc_EUCJP <= ccx->cc_SJIS
				 && dont_swccin(ccx,CC_EUCJP,ch1,ch2) ){
					/* 9.5.0-pre6 */
					setlinecc(ccx,CC_EUCJP); /* 9.7.2 */
				}else
				setccin(ccx,CC_EUCJP);
				if( mapJIS2B(CC_EUCJP,0,&ch1,&ch2) ){
					if( ch2 == 0 ){
						toASCII(ccx,op);
						*op++ = ch1;
						pix++;
						continue;
					}
				}
				pix++;
				ccx->cc_flags &= ~CCF_BAD1;

				if( (ccx->cc_symconv & SCtoASCII)
				 && (chA = JIS_TO_ASCII(CC_EUCJP,ch1,ch2,0)) )
				{
					toASCII(ccx,op);
					*op++ = chA;
				}
				else
				switch( ccx->cc_OUT ){
				    case CC_JIS2B7:
				    case CC_JIS7K:
					toJIS7(ccx,op);
					*op++ = 0x7F & ch1;
					*op++ = 0x7F & ch2;
					break;

				    case CC_SJIS:
					JIS_TO_SJIS1(0x7F&ch1,0x7F&ch2,op);
					op += 2;
					break;

				    case CC_UTF8:
					op += EUCtoUTF8((ch1<<8)|ch2,op,ox);
					break;

				    case CC_ASCII:
				    case CC_EURO8:
					op += EUCtoHTML((ch1<<8)|ch2);
					break;

				    default:
					*op++ = ch1;
					*op++ = ch2;
					break;
				}
				if( ccx->cc_flags&CCF_BAD1 && (ch2&0x80)==0 ){
					/* aoid destroying reseved char like
					 * <"> and "<" in HTML
					 */
					if( IS_SJIS_CHAR(ch1,ch2,1) ){
syslog_ERROR("#CCX NON-EUC-B (%d<%d) %X %X\n",ccx->cc_euc,ccx->cc_sjis,ch1,ch2);
						setccin(ccx,CC_SJIS);
						pix--;
					}
				}
				continue;
			}
			/*
			if( ccx->cc_EUCJP && ch1 == 0x8F ){
			}
			*/
			if( ch1 == 0x8F )
			if( ccx->cc_linecc == CC_SJIS
			 || (ch2 & 0x80) == 0
			 || (CH3 & 0x80) == 0
			){

if( ccx->cc_EUCJP
 || !ccx->cc_SJIS && !ccx->cc_UTF8
 && (  IS_EUC_HI(ch2) && CH3 == EOB
    || IS_EUCJP(ch2,CH3)
    && guessCode(ccx,cinb,pix-1,pin,pilen)==CC_EUCJP)
)
fprintf(stderr,"--ccx[%d] NOT EUC but SJIS %X %X %X %X i%d/%d/%d\n",
getpid(),ch1,ch2,CH3,CH4,
ccx->cc_in,ccx->cc_linecc,ccx->cc_incc1);
				/* 9.5.3 starts with 0x8F but non-EUC */
			}else
			if( ccx->cc_EUCJP
			 || !ccx->cc_SJIS && !ccx->cc_UTF8
			 && (  IS_EUC_HI(ch2) && CH3 == EOB
			    || IS_EUCJP(ch2,CH3)
			    && guessCode(ccx,cinb,pix-1,pin,pilen)==CC_EUCJP)
			){
				CStr(euc3,32);
				ch3 = CH3;
				if( ch3 == EOB ){
					pushpending(ccx,ch1);
					pushpending(ccx,ch2);
					break;
				}
				pix += 2;
/*
CCXlog("{C} 3bytes EUCJP %X %X %X\n",ch1,ch2,ch3);
*/
				ch1 = ch2;
				ch2 = ch3;

				if( mapJIS2B(CC_EUCJP,1,&ch1,&ch2) ){
					int j212;
					if( ch2 == 0 ){
						toASCII(ccx,op);
						*op++ = ch1;
						pix++;
						continue;
					}
					j212 = ch1 & 0x80;
					ch1 |= 0x80;
					ch2 |= 0x80;
					if( !j212 ){
						pix -= 1;
						goto inEUC_JP;
					}
				}
				/*
				op += putJISXch(ccx,CC_EUCJP,js[0],js[1],op,ox);
				*/
				op += putJISXch(ccx,CC_EUCJP,ch1,ch2,op,ox);

				continue;
			}


			insjis = inNonASCII(ccx,CC_SJIS);
			if( !insjis && ccx->cc_nonASCII == 0 )
				insjis = is_SJIS(ccx,cinb,pix-1,pin,pilen);
			if( !insjis )
			if( !ccx->cc_UTF8 && !ccx->cc_EUCJP && !ccx->cc_EURO8
			 || ccx->cc_linecc == 0
			){
				/* 9.5.3 pick SJIS lev.2 as the 1st 8bit ch. */
				insjis = isSJISline(ccx,0,cinb,pix-1,pin,pilen);
if( insjis )
if( ccx->cc_UTF8 || ccx->cc_EUCJP || ccx->cc_EURO8 )
fprintf(stderr,"--ccxS[%d] %3d SJIS-lev2 first %X %X [U%d S%d E%d R%d l%d]\n",
getpid(),pix,ch1,ch2,ccx->cc_UTF8,ccx->cc_SJIS,ccx->cc_EUCJP,ccx->cc_EURO8,
ccx->cc_linecc);
			}

			/*
			if( ccx->cc_EUCJP < 10 )
			*/
			if( ccx->cc_EUCJP < 10
			 || isSJIS(ccx,insjis,cinb,pix-1,pin,pilen)
			)
			if( IS_SJIS_2B(ch1,ch2,insjis) )
			if( 10 <= ccx->cc_EURO8 ){
				/* 9.5.0-pre7 not SJIS-2B in EURO8 */
			}else
			if( inNonASCII(ccx,CC_SJIS)
			 || is_SJIS(ccx,cinb,pix-1,pin,pilen) ){
				if( 10 <= ccx->cc_EUCJP ){
					/* 9.5.0-pre6 SJIS-2 in EUC-JP */
					setlinecc(ccx,CC_SJIS); /* 9.7.2 */
					if( ccx->cc_SJIS < 10 ) ccx->cc_SJIS++;
				}else
/*
				if( ccx->cc_UTF8 ){
					if( ccx->cc_SJIS < 10 ) ccx->cc_SJIS++;
				}else
*/
				setccin(ccx,CC_SJIS);
				pix++;

				SJIS_TO_JIS1(ch1,ch2,op);
				xch1 = op[0];
				xch2 = op[1];
				mapped = mapJIS2B(CC_SJIS,0,&xch1,&xch2);
				switch( mapped ){
					case MAP_1B:
						toASCII(ccx,op);
						*op++ = xch1;
						continue;
					default:
						JIS_TO_SJIS1(xch1,xch2,op);
						ch1 = op[0];
						ch2 = op[1];
						break;
				}

				if( (ccx->cc_symconv & SCtoASCII)
				 && (chA = JIS_TO_ASCII(CC_SJIS,ch1,ch2,0))){
					toASCII(ccx,op);
					*op++ = chA;
				}else
				switch( ccx->cc_OUT ){
				    case CC_JIS2B7:
				    case CC_JIS7K:
					toJIS7(ccx,op);
					SJIS_TO_JIS1(ch1,ch2,op);
					op += 2;
					break;

				    case CC_EUCJP:
					SJIS_TO_JIS1(ch1,ch2,op);
					*op++ |= 0x80;
					*op++ |= 0x80;
					break;

				    case CC_UTF8:
					SJIS_TO_JIS1(ch1,ch2,op);
					op += toUTF8X(ccx,U_SJIS|(op[0]<<8|op[1]),op,ox);
					break;

				    case CC_ASCII:
				    case CC_EURO8:
					SJIS_TO_JIS1(ch1,ch2,op);
					op +=EUCtoHTML(U_SJIS|(op[0]<<8|op[1]));
					break;

				    default:
					*op++ = ch1;
					*op++ = ch2;
					break;
				}
				continue;
			}

			if( !ccx->cc_EUCJP )
			if( ccx->cc_EURO8 && !maybein(CC_SJIS) ){
			}else
			if( !maybein(CC_SJIS) ){
			}else
			if( IS_SJIS_HIX(ch1) && IS_SJIS_LO(ch2) ){
				setccin(ccx,CC_SJIS);
				pix++;
				switch( ccx->cc_OUT ){
				    default: /* guess */
				    case CC_SJIS:
					*op++ = ch1;
					*op++ = ch2;
					break;
				    case CC_ASCII:
				    case CC_EURO8:
				    case CC_JIS2B7:
				    case CC_EUCJP:
				    case CC_UTF8:
					op += SJISXtoJIS(ccx,ch1,ch2,op,ox);
					break;
				}
				continue;
			}
		}
		if( ccx->cc_SJIS && !ccx->cc_EUCJP )
		if( 0xFD <= ch1 && ch2 <= 0xFF ){
			switch( ccx->cc_OUT ){
			    case CC_UTF8: /* Apple addition */
				switch( ch1 ){
				  case 0xFD: op += toUTF8(0x00A9,op); break;
				  case 0xFE: op += toUTF8(0x2122,op); break;
				  case 0xFF: op += toUTF8(0x2026,op); break;
				}
				continue;
				break;
			}
		}

		if( ccx->cc_OUT == CC_UTF8 )
		if( ccx->cc_flags & CCF_IN_ANSI )
		if( ch1 & 0x80 ){ /* iso-8859-1 */
			if( 0 < (len1 = CCXexecNonJP(ccx,ch1,op,ox)) ){
				if( ccx->cc_EURO8 < 127 ) ccx->cc_EURO8++;
				op += len1;
				continue;
			}
		}

		if( ch1 & 0x80 ){
			if( maybein(CC_EUCJP) || maybein(CC_SJIS) ){
				/* broken or mixed JIS / non-JIS ? */
			}else{
				if( ccx->cc_EURO8 < 127 ) ccx->cc_EURO8++;
			}
		}
		if( ccx->cc_in != CC_EURO8 )
		setccin(ccx,CC_ASCII);
		toASCII(ccx,op);

		ch1 = mapCHAR(CC_ASCII,CSM_ASCII2ASCII,ch1);

		if( IGN_bad(ccx) && (ch1&0x80) ){
			if( 0 < ccx->cc_UTF8 && (ch1&0xF0) != 0xE0 ){
			}else{

if( isNotInNONJP(ccx) && CCXwithJP(ccx) ){
	if( ccx->cc_nonjp8 == 0 ){
		/*
		fprintf(stderr,
			"---- [%s] BadJP8 %X %o %o nJ=%d utf=%d[%X]\n",
			incode,0xFF&ch1,0xFF&ch1,0xFF&ch2,
			ccx->cc_nonJP,ccx->cc_UTF8,(ch1&0xF0));
		*/
	}
	if( 16 < ox-op ){
		Xsprintf(ZVStr((char*)op,ox-op),"{BadJP8:%X,%X}",0xFF&ch1,0xFF&ch2);
		op += strlen((char*)op);
	}
}
				if( badout == 0 && isthru8(ccx,ch1) ){
					*op++ = ch1;
				}else{
					badout++;
				}
			}
			ccx->cc_nonjp8++;
		}else{
		*op++ = ch1;
		}
	}
	if( ilen == 0 )
	/* flush pending */
	{
		if( ccx->cc_pinx == 1 ){
			ch1 = ccx->cc_pinb[0];
			ccx->cc_pinx = 0;

			if( 0 < (len1 = CCXexecNonJP(ccx,ch1,op,ox)) ){
				op += len1;
			}else{
				*op++ = ch1;
			}
		}
		toASCII(ccx,op);
	}
	*op = 0;

	outlen = op - outtop;
	if( out == cinb ){
		Bcopy(outtop,out,outlen+1);
		if( outtop != outbuf )
			free(outtop);
	}else	outlen = op - out;
	return outlen;
}

void strip_ISO2022JP(PVStr(str))
{	char ch;
	const char *sp;
	refQStr(dp,str); /**/

	for( sp = str; ch = *sp++; ){
		if( ch == 033 )
		if( *sp == TO_2BCODE && (sp[1]=='@' || sp[1]=='B')
		 || *sp == TO_1BCODE && (sp[1]=='J' || sp[1]=='B')
		){
			sp += 2;
			continue;
		}
		setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
}


int utf8n;
int utf8err;

int fixUTF8(unsigned char *us,int leng)
{	int cx,uc4,ucs;
	int error;

	error = 0;
	for( cx = 1; cx < leng; cx++ ){
		uc4 = us[cx];
		if( (uc4&0xC0) != 0x80 ){
			if( uc4 == '\n' && (us[cx+1]&0xC0) == 0x80 ){
syslog_DEBUG("{#CCX:UTF-8:FIXED:%d/%d:%x,%x#}\n",cx+1,leng,uc4,us[cx+1]);
				us[cx] = us[cx+1];
				us[cx+1] = uc4;
			}else{
syslog_DEBUG("{#CCX:UTF-8:ERROR:%d/%d:%x,%x#}\n",cx+1,leng,uc4,us[cx+1]);
				error++;
				break;
			}
		}
	}
	return error;
}
static unsigned int fromUTF8(unsigned char *us,int *lengp,char **spp)
{	unsigned char uc0,ucx;
	int leng,mask,lx;
	unsigned int uc4;
	int len;
	CStr(buf,64);

	uc4 = 0;
	uc0 = *us;
	len = *lengp;
	if( (uc0 & 0x80) == 0 ){ leng = 1; }else
	if( (uc0 & 0x40) == 0 ){ leng = 1;
			if( spp ){
sprintf(buf,"{#CCX:UTF-8:ERROR:%d/%d:%x,%x#}",1,1,uc0,us[1]);
XStrncpy(ZVStr(*spp,len),buf,len); /**/
			utf8err++;
			*spp += strlen(*spp);
			uc0 = '?';
			}
	}else
	if( (uc0 & 0x20) == 0 ){ leng = 2; }else
	if( (uc0 & 0x10) == 0 ){ leng = 3; }else
	if( (uc0 & 0x08) == 0 ){ leng = 4; }else
	if( (uc0 & 0x04) == 0 ){ leng = 5; }else
	if( (uc0 & 0x02) == 0 ){ leng = 6; }else{
		leng = 1;
	}

	fixUTF8(us,leng);
	if( leng == 1 ){
		uc4 = uc0;
	}else{
		mask = 0xFF >> (leng+1);
		uc4 = uc0 & mask;
		for( lx = 1; lx < leng; lx++ ){
			ucx = us[lx];
			if( (ucx & 0xC0) != 0x80 ){
				return uc0;
			}
			uc4 = (uc4 << 6) | (0x3F & ucx);
		}
	}
	*lengp = leng;
	return uc4;
}
unsigned int FromUTF8(unsigned char *us,int *lengp){
	return fromUTF8(us,lengp,0);
}
int UTF8toUCS16(unsigned char *utf8,unsigned short *ucs16,int usiz){
	unsigned int uc2;
	unsigned char *utp;
	unsigned short *ucp;
	int len;
	int siz;

	siz = 1;
	ucp = ucs16;
	for( utp = utf8; *utp;){
		if( usiz <= siz ){
			break;
		}
		len = 0;
		uc2 = fromUTF8(utp,&len,0);
		if( len <= 0 || 2 < len ){
			break;
		}
		*ucp++ = uc2;
		utp += len;
	}
	*ucp = 0;
	return len;
}
int toUTF8(unsigned int uc,unsigned char *us)
{	int tag,leng,lx;

	if( uc < 0x0000080 ){ leng = 1; }else
	if( uc < 0x0000800 ){ leng = 2; }else
	if( uc < 0x0010000 ){ leng = 3; }else
	if( uc < 0x0200000 ){ leng = 4; }else
	if( uc < 0x4000000 ){ leng = 5; }else
			      leng = 6;
	if( leng == 1 ){
		*us++ = uc;
	}else{
		for( lx = leng-1; 0 < lx; lx-- ){
			us[lx] = 0x80 | (uc & 0x3F);
			uc = uc >> 6;
		}
		tag = 0x3F << (8-leng);
		us[0] = tag | uc;
	}
	return leng;
}

#define JUMAP	"jis-ucs.ccx"
typedef struct {
unsigned short	u_l2umap[0x10000];
unsigned short	u_u2lmap[0x10000];
	int	u_init;
} UcsX;
#define L2Umap	ucx->u_l2umap
#define U2Lmap	ucx->u_u2lmap
static UcsX **UcsXtab;
UcsX *UCSx(){
	if( UcsXtab == 0 )
		UcsXtab = (UcsX**)StructAlloc(8*sizeof(UcsX*));
	if( UcsXtab[0] == 0 )
		UcsXtab[0] = NewStruct(UcsX);
	return UcsXtab[0];
}

static int loadUnicodeMappings(PCStr(jumap),UcsX *ucx,unsigned short l2ucnt[],unsigned short u2lcnt[]);

static int UcxInit(UcsX *ucx)
{	unsigned short l2ucnt[0x10000];
	unsigned short u2lcnt[0x10000];
	int loaded;

	if( ucx->u_init == 0 ){
		bzero(l2ucnt,sizeof(l2ucnt));
		bzero(u2lcnt,sizeof(u2lcnt));
		loaded = loadUnicodeMappings(JUMAP,ucx,l2ucnt,u2lcnt);
		if( 0 < loaded )
			ucx->u_init = loaded;
		else	ucx->u_init = -1;
	}
	return ucx->u_init;
}
int UCSinit(){
	UcsX *ucx = UCSx();
	return UcxInit(ucx);
}
void UCSreset(){
	UcsX *ucx = UCSx();
	ucx->u_init = 0;
}

/*
static int UTF8toUCS(int ch1,int ch2,int ch3,int *lenp,unsigned int *eucp){
*/
static int UTF8toUCSX(CCX *ccx,int ch1,int ch2,int ch3,int ch4,int *lenp,unsigned int *eucp,int *mapped){
	UcsX *ucx = UCSx();
	CStr(buf,64);
	int len;
	unsigned int ucs;

	UcxInit(ucx);
	buf[0] = ch1;
	buf[1] = ch2;
	buf[2] = ch3;
	buf[3] = ch4;
	/*
	buf[3] = 0;
	*/
	buf[4] = 0;
	len = sizeof(buf);
	ucs = fromUTF8((unsigned char*)buf,&len,NULL);
	*lenp = len;

	if( mapped ) *mapped = 0;
	if( withCHARMAP(CSM_UCS2JIS) ){
		unsigned int euc;
		int map = 0;
		euc = _mapCHAR(CCXDST(ccx),CC_UTF8,CSM_UCS2JIS,ucs,&map);
		if( map ){
			if( mapped ) *mapped = map;
			*eucp = euc;
			return ucs;
		}
	}
	if( 0xFFFF < ucs ){
		syslog_DEBUG("UCS>16b not suppported: len=%d ucs=%X\n",len,ucs);
		*eucp = NoMap2;
	}else
	if( 0 <= ucs && ucs <= 0xFFFF )
	{
		ucs = mapCHAR(CC_UTF8,CSM_UCS2UCS,ucs);
		*eucp = U2Lmap[ucs];
		if( *eucp == 0 ){
			if( ucs == 0x2014 && U2Lmap[0x2015] ){
				/* Apple specific, DASH code */
				ucs = 0x2015;
				*eucp = U2Lmap[ucs];
			}
		}
	}
	else	*eucp = 0;
	return ucs;
}
static int UTF8toSJISX(CCX *ccx,USChar *op,const USChar *ox,unsigned int ucs){
	int euc;
	int len;
	UcsX *ucx = UCSx();
	int from = 0;

	if( ccx->cc_OUT == CC_SJIS )
		from = 0x8080;
	for( euc = from; euc < 0x10000; euc++){
		if( L2Umap[euc] != ucs )
			continue;

		/* I don't remember why the map for SJIS is detected with
		 * this 0x8080 but it works anyway X-)
		 */
		if( (euc & 0x8080) == 0x8080 ){
			switch( ccx->cc_OUT ){
			    case CC_SJIS:
				JIS_TO_SJIS1(0x7F&(euc>>8),0x7F&euc,op);
				op[0] |= 0x80;
				op += 2;
				len = 2;
				*op = 0;
				return len;
			}
		}else{
		}
	}
	return 0;
}
static int EUCXtoSJISX(CCX *ccx,int c1,int c2,USChar *op,const USChar *ox){
	int len,map;
	unsigned int euc,ucs;

	len = EUC3toUTF8((c1<<8)|c2,op,ox);
	if( 0 < len ){
		ucs = UTF8toUCSX(ccx,op[0],op[1],op[2],op[3],&len,&euc,&map);
		if( 0 < len ){
			len = UTF8toSJISX(ccx,op,ox,ucs);
			if( 0 < len ){
				return len;
			}
		}
	}
	JIS_TO_SJIS1(NoMap3>>8,NoMap3,op);
	return 2;
}
static int SJISXtoJIS(CCX *ccx,int c1,int c2,USChar *op,const USChar *ox){
	unsigned char j2[8];
	int len1,len2;
	int ch4 = 0;

	SJIS_TO_JIS1(c1,c2,j2);
	len1 = toUTF8X(ccx,U_SJIS|(j2[0]<<8|j2[1]),op,ox);
	switch( ccx->cc_OUT ){
		case CC_UTF8:
			return len1;
			break;
		case CC_ASCII:
		case CC_EURO8:
			len2 = UTF8toHTML(ccx,op,op,ox);
			return len2;
			break;
	}
	len2 = UTF8toLocal(op[0],op[1],op[2],ccx->cc_OUT,op,ox);
	return len2;
}

static int UTFmapped(CCX *ccx,int ch1,int ch2,int ch3,int ch4){
	unsigned int ucs0;
	int len;
	unsigned int euc0,euc1;
	int mapped0 = 0;
	int mapped1 = 0;

	ucs0 = UTF8toUCSX(ccx,ch1,ch2,ch3,ch4,&len,&euc0,&mapped0);
	if( withCHARMAP(CSM_JIS2JIS) ){
		euc1 = _mapCHAR(CCXDST(ccx),CC_UTF8,CSM_JIS2JIS,euc0,&mapped1);
	}else{
		euc1 = euc0;
	}
/*
 fprintf(stderr,"--mapped %d %d [%2X %2X %2X] %X %X\n",
 mapped0,mapped1, ch1,ch2,ch3, euc0,euc1);
*/
	if( mapped1 ) return mapped1;
	if( mapped0 ) return mapped0;
	/*
	if( (euc1 & 0x8080) == U_JIS0212 ){
	*/
	if( euc1 & U_JIS0212 ){
		return MAP_JISX0212;
	}
	return 0;
}
/*
static int UTFis0212(int ch1,int ch2,int ch3){
	unsigned int ucs,euc;
	int len;

	ucs = UTF8toUCS(ch1,ch2,ch3,&len,&euc);
	if( (euc & 0x8080) == U_JIS0212 )
		return 1;
	return 0;
}
static int UTF8toLocal(int ch1,int ch2,int ch3,int charset,unsigned char *op,const unsigned char *ox)
*/
static int UTF8toLocalX(CCX *ccx,int ch1,int ch2,int ch3,int ch4,int charset,unsigned char *op,const unsigned char *ox)
/*
*/
{	unsigned int ucs,euc;
	int len;
	int mapped = 0;
	unsigned char *oop = op;
	unsigned int oeuc;

	/*
	ucs = UTF8toUCS(ch1,ch2,ch3,&len,&euc);
	*/
	ucs = UTF8toUCSX(ccx,ch1,ch2,ch3,ch4,&len,&euc,&mapped);
	if( withCHARMAP(CSM_JIS2JIS) ){
		oeuc = euc;
		euc = _mapCHAR(CCXDST(ccx),CC_EUCJP,CSM_JIS2JIS,euc,&mapped);
		if( mapped ){
			if( mapped == MAP_1B ){
				*op++ = euc;
				len = 1;
				return len;
			}
			euc &= 0x7F7F;
		}
	}

	if( euc  ){
		if( (euc & 0x8080) == U_SJIS ){
			/* got from the SJIS/UTF-8 map */
			if( !mapped ) /* not mapped explicitly */
			if( charset == CC_JIS2B7 || charset == CC_EUCJP ){
			    /* map Shift_JIS only characters to JIS7 / EUC */
			    switch( ucs ){
				case 0x301D: euc = 0x2148; break;
				case 0x301F: euc = 0x2149; break;
			    }
			}

			JIS_TO_SJIS1(0x7F&(euc>>8),0x7F&euc,op);
			if( op[0] == 0x80 ){
				/* to cope with the error in conv. functions:
				 *   JIS_TO_SJIS1: 0x00XX -> 0x20YY
				 *   SJIS_TO_JIS1: 0x80XX <- 0x20YY
				 */
				unsigned char j2[2];
				int lc1;
				int sj1;
				const char *js;
				int cat;

				sj1 = 0xFF & op[1];
				SJIS_TO_JIS1(0,sj1,j2);
				lc1 = j2[0] << 8 | j2[1];
				lc1 |= U_SJIS;
				if( lc1 == euc ){
					len = 0;
					switch( charset ){
					case CC_JIS2B7:
						toJIS7(ccx,op);

						js = sjis_1b_to_jis(sj1,0,&cat);
						/* dakuten shoul be cared... */
						*op++ = js[0];
						*op++ = js[1];
						/*
						len = 2;
						*/
						len = op - oop;
						break;
					case CC_EUCJP:
						*op++ = EUC_HANKAKU_HI;
						*op++ = sj1;
						len = 2;
						break;
					case CC_SJIS:
						*op++ = sj1;
						len = 1;
						break;
					case CC_UTF8:
						*op++ = ch1;
						*op++ = ch2;
						*op++ = ch3;
						len = 3;
						break;
					default:
						break;
					}
					*op = 0;
					return len;
				}
			}
		}
		switch( charset ){
			case CC_JIS2B7:
				if( (euc & 0x8080) == (U_SJIS|U_JIS0212) ){
					/* mapped to SJIS, might be broken? */
					euc = NoMap4;
				}
				if( ccx->cc_flags & CCF_NOJISX ){
					euc = NoMap5;
				}else
				if( (euc & 0x8080) == U_JIS0212 ){
					op = oop;
					toJIS7X(ccx,op);
				}else{
					toJIS7(ccx,op);
				}
				*op++ = 0x7F & (euc >> 8);
				*op++ = 0x7F & euc;
				len = op - oop;
				/*
				len = 2;
				*/
				break;
			case CC_EUCJP:
				if( (euc & 0x8080) == (U_SJIS|U_JIS0212) ){
					/* mapped to SJIS, might be broken? */
					if( len = UTF8toSJISX(ccx,op,ox,ucs) ){
						op += len;
						return len;
					}
					euc = NoMap4;
				}else
				if( (euc & 0x8080) == U_SJIS ){
				}else
				if( (euc & 0x8080) == U_JIS0212 ){
					if( ccx->cc_flags & CCF_NOEUCX ){
						euc = NoMap3;
					}else{
					*op++ = 0x8F; 
					*op++ = 0x80 | (euc >> 8);
					*op++ = 0x80 | euc;
					len = 3;
					break;
					}
				}
				*op++ = 0x80 | (euc >> 8);
				*op++ = 0x80 | euc;
				len = 2;
				break;
			case CC_SJIS:
				/*
				*op++ = euc >> 8;
				*op++ = euc;
				*/
				if( (euc & 0x8080) == U_JIS0212 ){
					if( len = UTF8toSJISX(ccx,op,ox,ucs) ){
						op += len;
						return len;
					}

euc = _mapCHAR(CCXDST(ccx),CC_EUCJP,CSM_JIS2JIS,0,&mapped);
					if( mapped == MAP_1B ){
						*op++ = euc;
						len = 1;
						return len;
					}
					if( mapped )
						euc = 0x8080 | euc;
					else	euc = 0x8080 | NoMap1;
				}else
				if( (euc & 0x8080) == (U_SJIS|U_JIS0212) ){
					if( len = UTF8toSJISX(ccx,op,ox,ucs) ){
						op += len;
						return len;
					}
					euc = 0x8080 | NoMap4;
				}
				JIS_TO_SJIS1(0x7F&(euc>>8),0x7F&euc,op);
				op += 2;
				len = 2;
				break;
			default:
				len = 0;
				break;
		}
		*op = 0;
		return len;
	}else{
		CStr(buf,64);
		if( ucs == 0xF87F ){
			/* postfixed "variant tag" as 2026+F87F */
			return 0;
		}
		switch( charset ){
			case CC_JIS2B7:
				toJIS7(ccx,op);
				Xsprintf(ZVStr((char*)op,ox-op),"%c%c",
					NoMap1>>8,NoMap1);
				/*
				Xsprintf(ZVStr((char*)op,ox-op),"\".");
				*/
				break;

			case CC_EUCJP:
				if( ccx->cc_flags & CCF_YUC ){
					putYUC(ZVStr((char*)op,ox-op),ucs);
					break;
				}
				Xsprintf(ZVStr((char*)op,ox-op),"%c%c",
					0x80|(NoMap1>>8),0x80|(NoMap1));
				break;
			case CC_SJIS:
				JIS_TO_SJIS1(NoMap1>>8,NoMap1,op);
				op[2] = 0;
				break;

			default:
sprintf(buf,"{#CCX:UTF-8:NOMAP:UTF8toLocal:0x%04x:%x,%x,%x#}",ucs,ch1,ch2,ch3);
XStrncpy(ZVStr((char*)op,ox-op),(char*)buf,ox-op);
				break;
		}
		/*
		return strlen((char*)op);
		*/
		return strlen((char*)oop);
	}
}
int UTF8toEUC(CCX *ccx,PCStr(utf),PVStr(out),int siz){
	unsigned char *us = (unsigned char*)utf;
	unsigned char *os = (unsigned char*)out;
	unsigned char *ox;
	int len;

	ox = os + (siz-1);
	len = UTF8toLocalX(ccx,us[0],us[1],us[2],us[3],CC_EUCJP,os,ox);
	return len;
}
/*
static int EUCtoUTF8(int euc,unsigned char *us,const unsigned char *ux)
*/
static int toUTF8X(CCX *ccx,int euc,unsigned char *us,const unsigned char *ux)
{	UcsX *ucx = UCSx();
	unsigned int jis;
	unsigned int ucs;
	int len;
	CStr(buf,64);

	if( withCHARMAP(CSM_JIS2UCS) ){
		int mapped;
		ucs = _mapCHAR(CCXDST(ccx),CC_UTF8,CSM_JIS2UCS,euc,&mapped);
		if( mapped ){
			len = toUTF8(ucs,us);
			return len;
		}
	}

	UcxInit(ucx);

	ucs = 0;
	if( 0x8080 & euc )
	{
		ucs = L2Umap[euc];
	}

	if( ucs == 0 ){
		jis = euc & ~0x8080;
		ucs = L2Umap[jis];
		if( ucs == 0 ){
			ucs = L2Umap[0x0080 | jis];
			if( ucs == 0 ){
				ucs = L2Umap[0x8000 | jis];
				if( ucs == 0 ){
					ucs = L2Umap[0x8080 | jis];
				}
			}
		}
	}
/*
	ucs = L2Umap[euc];
	if( ucs == 0 ){
		if( (euc & 0x8080) == 0 )
			ucs = L2Umap[ 0x8080 | euc];
		else	ucs = L2Umap[~0x8080 & euc];
	}
*/

	if( ucs ){
		ucs = mapCHAR(CC_UTF8,CSM_UCS2UCS,ucs);
		len = toUTF8(ucs,us);
		return len;
	}else{
sprintf(buf,"{#CCX:UTF-8:NOMAP:LocalToUTF8:%x#}",euc);
XStrncpy(ZVStr((char*)us,ux-us),buf,ux-us);
		if( (euc & 0x7F) == 0x7D || (euc & 0x7F) == 0x7E ){
			syslog_ERROR("-- an indicator of EUC-JP? %X\n",euc);
		}else
		ccx->cc_flags |= CCF_BAD | CCF_BAD1;
		return strlen((char*)us);
	}
	return 0;
}

static int UCStoHTML(CCX *ccx,int ucs,USChar *op,const USChar *ox){
	Xsprintf(ZVStr((char*)op,ox-op),"&#%d;",ucs);
	return strlen((char*)op);
}
static int UTF8toHTML(CCX *ccx,USChar chs[],USChar *uu,const USChar *ux){
	int xlen,xmapped;
	unsigned int ucs,xeuc;

	ucs = UTF8toUCSX(ccx,chs[0],chs[1],chs[2],chs[3],&xlen,&xeuc,&xmapped);
	return UCStoHTML(ccx,ucs,uu,ux);
}
static int EUCtoUCSHTML(CCX *ccx,int euc,USChar *uu,const USChar *ux){
	USChar ucsb[128];

	toUTF8X(ccx,euc,ucsb,ucsb+sizeof(ucsb));
	return UTF8toHTML(ccx,ucsb,uu,ux);
}

static void dumpCharMapCompiled(PCStr(file),UcsX *ucx)
{	FILE *mfp;
	int lch,uch,rcc;
	CStr(buff,0x40000);

	if( mfp = fopen(file,"w") ){
		char *bp = buff; /**/
		for( lch = 0; lch < 0x10000; lch++ )
		if( uch = L2Umap[lch] ){
			*bp++ = lch >> 8; *bp++ = lch;
			*bp++ = uch >> 8; *bp++ = uch;
		}
		fwrite(buff,1,bp-buff,mfp);
		syslog_DEBUG("##CCX DUMPED %s %d\n",file,ll2i(bp-buff));
		fclose(mfp);
		chmodIfShared(file,0644);
	}
}
static int loadCharMap(PCStr(file),UcsX *ucx)
{	FILE *mfp;
	CStr(xpath,1024);
	int rcc;
	unsigned int lch,uch;
	unsigned char buff[0x40000];
	const unsigned char *bp;

	if( mfp = fopen_LIBPATH(file,"r",AVStr(xpath)) ){
		rcc = fread(buff,1,sizeof(buff),mfp);
		syslog_DEBUG("##CCX LOADED %s %d\n",xpath,rcc);
		for( bp = buff; bp < &buff[rcc]; bp += 4 ){
			lch = (bp[0] << 8) | bp[1];
			uch = (bp[2] << 8) | bp[3];
			L2Umap[lch] = uch;
			U2Lmap[uch] = lch;
		}
		fclose(mfp);
		return 1;
	}
	else{
		syslog_DEBUG("##CCX FAILED LOADING %s\n",file);
	}
	return 0;
}
static void statDump(unsigned short l2umap[], unsigned short l2ucnt[])
{	int filled,unified;
	unsigned int uc4,lc4;

	unified = 0;
	for( lc4 = 0; lc4 < 0x10000; lc4++ ){
		if( 0 < l2umap[lc4] && l2umap[lc4] < 0x100 ){
/*
syslog_ERROR("##CCX UNIFIED: %x -> %x\n",lc4,l2umap[lc4]);
*/
			unified++;
		}
	}
	filled = 0;
	for( uc4 = 0; uc4 < 0x10000; uc4++ ){
		if( 1 < l2ucnt[uc4] ){
/*
syslog_ERROR("##CCX DUPLICATE: %x (%d)\n",uc4,l2ucnt[uc4]);
*/
		}
		if( l2ucnt[uc4] == 1 )
			filled++;
	}
syslog_ERROR("##CCX UNIFIED=%d FILLED=%d\n",unified,filled);
}

static int loadMapping1(FILE *fp,PCStr(file),UcsX *ucx,unsigned short l2ucnt[],unsigned short u2lcnt[])
{	CStr(line,1024);
	unsigned int lc1,lc2,uc1;
	const char *desc;
	int uJIS = U_JIS0208;
	int dupLU = 0;
	int dupUL = 0;
	int ovrLU = 0;
	int ovrUL = 0;

	while( fgets(line,sizeof(line),fp) ){
		if( desc = strstr(line,"Column #") ){
			syslog_ERROR("#CCX %s %s",file,desc);
			if( strstr(line,"cp932") ) uJIS = U_SJIS;
			if( strstr(line,"shift-JIS") ) uJIS = U_SJIS;
			if( strstr(line,"JIS X 0212") ) uJIS = U_JIS0212;
		}
		if( sscanf(line,"0x%x 0x%x 0x%x",&lc1,&lc2,&uc1) == 3 ){
			/*
			lc1 = lc2 | 0x8080;
			*/
			lc1 = lc2;
		}else
		if( sscanf(line,"0x%x 0x%x",&lc1,&uc1) != 2 )
			continue;
		else{
			unsigned char j2[2];
			int olc1 = lc1;

			if( uJIS == U_SJIS ){
				SJIS_TO_JIS1(0xFF&(lc1>>8),0xFF&lc1,j2);
				lc1 = j2[0] << 8 | j2[1];
				if( L2Umap[lc1] == uc1 ) dupLU++;
				if( U2Lmap[uc1] == lc1 ) dupUL++;
				if( L2Umap[lc1] == uc1 && U2Lmap[uc1] == lc1 ){
					continue;
				}
				lc1 |= uJIS;
			}else
			if( uJIS == U_JIS0212 ){
				lc1 |= uJIS;
			}
		}

/*
		if( 0x80 <= uc1 )
*/
		{
			if( L2Umap[lc1] && L2Umap[lc1] != uc1 ){
				syslog_ERROR("##CCX L2U OVR: %4x -> %4x[%4x]\n",
					lc1,uc1,L2Umap[lc1]);
				ovrLU++;
			}
			l2ucnt[lc1] += 1;
			L2Umap[lc1] = uc1;

			if( U2Lmap[uc1] && U2Lmap[uc1] != lc1 ){
				syslog_DEBUG("##CCX U2L OVR: [%4x]%4x <- %4x\n",
					U2Lmap[uc1],lc1,uc1);
				ovrUL++;
			}
			u2lcnt[uc1] += 1;
			U2Lmap[uc1] = lc1;
		}
	}
	syslog_ERROR("##CCX Local to Unicode:\n"); statDump(L2Umap,l2ucnt);
	syslog_ERROR("##CCX Unicode to Local:\n"); statDump(U2Lmap,u2lcnt);
	syslog_ERROR("##CCX dupLU=%d,dupUL=%d ovrLtoU=%d,ovrUtoL=%d\n",
			dupLU,dupUL,ovrLU,ovrUL);
	syslog_ERROR("##CCX loaded: %s\n",file);
	return 1;
}
int CCX_JUmapCache(PCStr(jumap),PVStr(bpath)){
	const char *tmpdir;
	refQStr(xp,bpath); /**/
	int size;

	if( jumap == NULL )
		jumap = JUMAP;
	if( isFullpath(jumap) )
		strcpy(bpath,jumap);
	else{
		tmpdir = getTMPDIR();
		if( tmpdir == 0 )
			tmpdir = "/tmp";
		sprintf(bpath,"%s/%s",tmpdir,jumap);
	}
	if( (xp = strrpbrk(bpath,"./\\")) && *xp == '.' )
		strcpy(xp,".ccb");
	else	strcat(bpath,".ccb");
	size = File_size(bpath);
	return size;
}
static int loadMap1(PCStr(file),UcsX *ucx,unsigned short l2ucnt[],unsigned short u2lcnt[])
{	FILE *fp;
	CStr(xpath,1024);
	CStr(xfile,1024);

	sprintf(xfile,"codemap/%s",file);
	if( fp = fopen_LIBPATH(xfile,"r",AVStr(xpath)) ){
		loadMapping1(fp,xpath,ucx,l2ucnt,u2lcnt);
		fclose(fp);
		return 1;
	}
	return 0;
}
static int loadUnicodeMappings(PCStr(jumap),UcsX *ucx,unsigned short l2ucnt[],unsigned short u2lcnt[])
{	FILE *fp,*mfp;
	const char *map;
	int loaded = 0;
	CStr(bpath,1024);

	CCX_JUmapCache(jumap,AVStr(bpath));
	syslog_ERROR("##CCX %s %s\n",jumap,bpath);

	if( loadCharMap(bpath,ucx) ){
		loaded = 1;
		goto EXIT;
	}

	if( map = getenv("MAPUNICODE") )
		loaded += loadMap1(map,ucx,l2ucnt,u2lcnt);

	loaded += loadMap1(jumap,ucx,l2ucnt,u2lcnt);

	if( loaded == 0 )
	{
	loaded += loadMap1("SHIFTJIS.TXT",ucx,l2ucnt,u2lcnt);
	loaded += loadMap1("CP932.TXT",ucx,l2ucnt,u2lcnt);
	loaded += loadMap1("JIS0212.TXT",ucx,l2ucnt,u2lcnt);
	loaded += loadMap1("JIS0208.TXT",ucx,l2ucnt,u2lcnt);

/*	loaded += loadMap1("JIS0201.TXT",ucx,l2ucnt,u2lcnt); */
	}

	if( loaded )
		dumpCharMapCompiled(bpath,ucx);

EXIT:
	return loaded;
}

static void scanCharMapping(FILE *in,UcsX *ucx,unsigned short l2ucnt[],unsigned short u2lcnt[])
{	CStr(line,1024);
	unsigned CStr(map1,1024);
	const char *sp;
	unsigned int uc4,lc4;
	int len;

	while( fgets(line,sizeof(line),in) ){
	    for( sp = line; sp && *sp; sp = strpbrk(sp," \t\r\n") ){
		if( isspace(*sp) )
			sp++;
		*map1 = 0;
		Xsscanf(sp,"%s",AVStr(map1));
		if( *map1 == 0 )
			break;
		if( isxdigit(map1[0]) && map1[4] == ':' ){
			map1[4] = 0;
			sscanf((char*)map1,"%x",&lc4);
			len = sizeof(map1) - 5;
			uc4 = fromUTF8(&map1[5],&len,NULL);

if( (lc4 & 0x8080) == 0 && (lc4 & 0xFF00) != 0 ) lc4 |= 0x8080;

			l2ucnt[uc4] += 1;
			if( l2ucnt[uc4] == 1 )
				L2Umap[lc4] = uc4;
			u2lcnt[lc4] += 1;
			if( u2lcnt[lc4] == 1 )
				U2Lmap[uc4] = lc4;
		}
	    }
	}
	statDump(L2Umap,l2ucnt);
}
void dumpUTF8mapping(){
	unsigned int uc4;
	for( uc4 = 0x001; uc4 < 0x080; uc4++ ){
		printf("%04x:%c\r\n",uc4,uc4);
	}
	for( uc4 = 0x080; uc4 < 0x800; uc4++ ){
		printf("%04x:%c%c\r\n",
			uc4,
			0xC0|0x1F&(uc4>>6),
			0x80|0x3F&(uc4)
		);
	}
	for( uc4 = 0x800; uc4 < 0x10000; uc4++ ){
		printf("%04x:%c%c%c\r\n",
			uc4,
			0xE0|0x0F&(uc4>>12),
			0x80|0x3F&(uc4>>6),
			0x80|0x3F&(uc4)
		);
	}
}
void dumpJIS7mapping()
{	int ch,ch1,ch2,nc;

	nc = 0;
	for( ch = 0; ch < 0x8000; ch++ ){
		ch1 = 0xFF & (ch >> 8);
		ch2 = 0xFF & ch;
		if( !IS_JIS7(ch1,ch2) )
			continue;
		if( nc != 0 && nc % 8 == 0 )
			printf("\r\n");
		nc++;
		printf("%02x%02x:\033$B%c%c\033(B ",ch1,ch2,ch1,ch2);
	}
	printf("\r\n");
}
void dumpEUCJPmapping()
{	int ch,ch1,ch2,nc;

	nc = 0;
	for( ch = 0x8080; ch < 0x10000; ch++ ){
		ch1 = 0xFF & (ch >> 8);
		ch2 = 0xFF & ch;
		/*
		if( !IS_EUC(ch1,ch2) )
		*/
		if( !IS_EUCJP(ch1,ch2) )
			continue;
		if( nc != 0 && nc % 8 == 0 )
			printf("\r\n");
		nc++;
		printf("%02x%02x:%c%c ",ch1,ch2,ch1,ch2);
	}
	printf("\r\n");
}
void dumpCharMapping(PCStr(code))
{
	switch( *code ){
		case 'u': dumpUTF8mapping(); break;
		case 'j': dumpJIS7mapping(); break;
		case 'e': dumpEUCJPmapping(); break;
	}
}
void loadCharMapping(PCStr(code),FILE *ifp)
{	UcsX *ucx = UCSx();
	unsigned short l2ucnt[0x10000];
	unsigned short u2lcnt[0x10000];

	bzero(l2ucnt,sizeof(l2ucnt));
	bzero(u2lcnt,sizeof(u2lcnt));
/*
	scanCharMapping(ifp,ucx,L2Umap,l2ucnt,U2Lmap,u2lcnt);
*/
	scanCharMapping(ifp,ucx,L2Umap,l2ucnt);
	dumpCharMapCompiled(JUMAP,ucx);
}

/* Windows-1252 */
static int ANSItoUCS(int ch1){
	switch( ch1 ){
		case 0x80: return 0x20AC;
		case 0x82: return 0x201A;
		case 0x83: return 0x0192;
		case 0x84: return 0x201E;
		case 0x85: return 0x2026;
		case 0x86: return 0x2020;
		case 0x87: return 0x2021;
		case 0x88: return 0x02C6;
		case 0x89: return 0x2030;
		case 0x8A: return 0x0160;
		case 0x8B: return 0x2039;
		case 0x8C: return 0x0152;
		case 0x8E: return 0x017D;

		case 0x91: return 0x2018;
		case 0x92: return 0x2019;
		case 0x93: return 0x201C;
		case 0x94: return 0x201D;
		case 0x95: return 0x2022;
		case 0x96: return 0x2013;
		case 0x97: return 0x2014;
		case 0x98: return 0x02DC;
		case 0x99: return 0x2122;
		case 0x9A: return 0x0161;
		case 0x9B: return 0x203A;
		case 0x9C: return 0x0153;
		case 0x9E: return 0x017E;
		case 0x9F: return 0x0178;
	}
	return 0;
}

/*
 * CHARMAP=nomap:1/222E CHARMAP=nomap:2/2223
 * or
 * CHARMAP=ucsjis:nomap/222E
 * CHARMAP=jisucs:nomap/222E
 * or
 * CHARMAP=jis:0000/222E
 */

void scan_CHARMAPs(void *ctx,PCStr(maps)){
	const char *dp;
	int nmap = 1;
	charMap *cm;
	int ci;
	IStr(mapc,1024);
	CStr(map1,128);
	int ne;
	int from,to;
	int nfrom;
	int nto;
	const char *mp;
	CStr(c1,128);
	int ics;
	int csx;
	int dst = CSD_TOCL;
	int both = 0;

	maps = wordScanY(maps,c1,"^:");
	if( strcaseeq(c1,"ucsucs") || strcaseeq(c1,"uu")
	 || strcaseeq(c1,"u") || strcaseeq(c1,"ucs") ){
		ics = CS_UCS;
		csx = CSM_UCS2UCS;
	}else
	if( strcaseeq(c1,"ucsjis") || strcaseeq(c1,"uj") ){
		ics = CS_UCS;
		csx = CSM_UCS2JIS;
	}else
	if( strcaseeq(c1,"jisucs") || strcaseeq(c1,"ju") ){
		ics = CS_JIS;
		csx = CSM_JIS2UCS;
	}else
	if( strcaseeq(c1,"jisjis") || strcaseeq(c1,"jj")
	 || strcaseeq(c1,"j") || strcaseeq(c1,"jis") ){
		ics = CS_JIS;
		csx = CSM_JIS2JIS;
	}else{
		ics = CS_ASCII;
		csx = CSM_ASCII2ASCII;
	}
	if( *maps++ != ':' ){
		return;
	}
	maps = wordScanY(maps,mapc,"^:");
	if( streq(maps,":tosv") ){
		dst = CSD_TOSV;
		both = 0;
	}else
	if( streq(maps,":tocl") ){
		dst = CSD_TOCL;
		both = 0;
	}else
	if( streq(maps,":both") ){
		dst = CSD_TOCL;
		both = 1;
	}

	for( dp = maps; *dp; dp++ ){
		if( (dp = strchr(dp,',')) == 0 )
			break;
		dp++;
		nmap++;
	}
	charmapxv[dst][csx] = nmap;
	charmapsv[dst][csx] = (charMap*)malloc(sizeof(charMap)*nmap);
	if( both ){
		charmapxv[(dst+1)%2][csx] = nmap;
		charmapsv[(dst+1)%2][csx] = charmapsv[dst][csx];
	}

	ci = 0;
	for( dp = mapc; *dp; dp++ ){
		cm = &charmapsv[dst][csx][ci++];
		dp = wordScanY(dp,map1,"^,");
		cm->cm_flag = 0;
		from = -1;
		to = -1;
		nfrom = -1;
		nto = -1;

		mp = wordScanY(map1,c1,"^-/");
		if( c1[0] && c1[1] == 0 )
			from = c1[0];
		else	sscanf(c1,"%x",&from);
		if( ics == CS_JIS && (0x10000 & from) )
			from = 0x8000 | (from & 0xFFFF);
		cm->cm_from = from;

		if( *mp == '-' ){
			mp = wordScanY(mp+1,c1,"^/");
			if( c1[0] && c1[1] == 0 )
				to = c1[0];
			else	sscanf(c1,"%x",&to);
		}else{
			to = cm->cm_from;
		}
		if( ics == CS_JIS && (0x10000 & to) )
			to = 0x8000 | (to & 0xFFFF);
		cm->cm_to = to;

		if( *mp == '/' ){
			mp = wordScanY(mp+1,c1,"^-");
			if( c1[0] && c1[1] == 0 )
				nfrom = c1[0];
			else	sscanf(c1,"%x",&nfrom);
			if( ics == CS_JIS && (0x10000 & nfrom) )
				nfrom = 0x8000 | (nfrom & 0xFFFF);

			if( *mp == '-' ){
				mp = wordScanY(mp+1,c1,"^,");
				if( c1[0] && c1[1] == 0 )
					nto = c1[0];
				else	sscanf(c1,"%x",&nto);
				if( ics == CS_JIS && (0x10000 & nto) )
					nto = 0x8000 | (nto & 0xFFFF);
				cm->cm_flag |= CM_SHIFT;
			}else{
			}
		}
		if( nfrom != -1 ){
			cm->cm_offs = nfrom - cm->cm_from;
		}else{
			cm->cm_offs = 0x80000000;
		}
		if( *dp != ',' )
			break;
	}
	for( ci = 0; ci < charmapxv[dst][csx]; ci++ ){
		cm = &charmapsv[dst][csx][ci];
	}
}

int _mapCHAR(int dst,int ics,int csx,int code,int *mapped);
static int _mapJIS2B(int dst,int icset,int j212,int *ch1,int *ch2,int *mapped){
	int ichar,xchar;
	int map;

	ichar = 0x7F7F & ((*ch1 << 8) | *ch2);
	if( j212 ){
		ichar |= 0x8000;
	}
	xchar = _mapCHAR(dst,icset,CSM_JIS2JIS,ichar,&map);
	if( mapped ) *mapped = map;
	if( xchar != ichar ){
		if( (0xFF & xchar) == xchar ){
			*ch1 = 0xFF & (xchar);
			*ch2 = 0;
		}else{
			*ch1 = 0xFF & (xchar >> 8);
			*ch2 = 0xFF & (xchar);
		}
		if( icset == CC_EUCJP ){
			*ch1 |= 0x80;
		}else{
			*ch1 &= 0x7F;
		}
		return map;
	}
	return 0;
}
int _mapCHAR(int dst,int ics,int csx,int code,int *mapped){
	int ci;
	int mask = 0;
	charMap *cm;

	if( mapped )
		*mapped = 0;
	if( charmapxv[dst][csx] == 0 )
		return code;
	switch( csx ){
		case CSM_ASCII2ASCII:
		case CSM_UCS2UCS:
		case CSM_UCS2JIS:
			break;
		case CSM_JIS2JIS:
			mask = code & 0x0080;
		case CSM_JIS2UCS:
			code = code & ~0x0080;
			break;
	}
	for( ci = 0; ci < charmapxv[dst][csx]; ci++ ){
		cm = &charmapsv[dst][csx][ci];
		if( cm->cm_from <= code && code <= cm->cm_to ){
			if( cm->cm_offs == 0x80000000 ){
				code = '?';
			}else
			if( cm->cm_flag & CM_SHIFT )
				code = code + cm->cm_offs;
			else	code = cm->cm_from + cm->cm_offs;
			code &= 0xFFFF;
			if( mapped ){
				if( (code & 0xFF) == code )
					*mapped = MAP_1B;
				else
				if( (code & 0x8000) != 0 )
					*mapped = MAP_JISX0212;
				else	*mapped = MAP_JISX0208;
			}
			break;
		}
	}
	if( 0xFF00 & code )
		code |= mask;
	return code;
}


int TO_jis(PCStr(ichset),PCStr(src),PVStr(jis),int dsiz){
	CCX ccx;
	int len;

	CCXcreate("*","JIS",&ccx);
	CCX_setincode(&ccx,ichset);
	len = CCXexec(&ccx,(char*)src,strlen(src),BVStr(jis),dsiz);
	len += CCXexec(&ccx,"",0,DVStr(jis,len),dsiz-len);
	return len;
}
void CCX_TOXX(PCStr(src),int slen,PVStr(dst),int dsiz,PCStr(ctype),PCStr(chset))
{	CCX ccx;

	CCXcreate("*",chset,&ccx);
	CCXexec(&ccx,(char*)src,slen,AVStr(dst),dsiz);
}
void CCX_TOX(PCStr(src),PVStr(dst),PCStr(ctype),PCStr(chset))
{	int len;

	len = strlen((char*)src);
	CCX_TOXX(src,len,AVStr(dst),1024+len*2,ctype,chset);
}
void TO_EUC(PCStr(any),PVStr(euc),PCStr(ctype))
{
	CCX_TOX(any,AVStr(euc),ctype,"euc");
}
void TO_JIS(PCStr(any),PVStr(jis),PCStr(ctype))
{
	CCX_TOX(any,AVStr(jis),ctype,"jis");
}
void TO_SJIS(PCStr(any),PVStr(sjis),PCStr(ctype))
{
	CCX_TOX(any,AVStr(sjis),ctype,"sjis");
}
void TO_UTF8(PCStr(any),PVStr(utf8),PCStr(ctype))
{
	CCX_TOX(any,AVStr(utf8),ctype,"utf8");
}
void TO_euc(PCStr(in),PVStr(out),int osiz)
{	CCX ccx[1]; /**/

	CCXcreate("*","euc",ccx);
	CCXexec(ccx,(char*)in,strlen(in),BVStr(out),osiz);
}
FileSize CCXfile(PCStr(icharset),PCStr(ocharset),FILE *in,FILE *out)
{	CCX ccx[1]; /**/
	int rcc,wcc;
	FileSize icc,occ;
	CStr(buf,2*1024);
	CStr(xbuf,8*1024);

	CCXcreate(icharset,ocharset,ccx);
	icc = occ = 0;
	while( 0 < (rcc = fread(buf,1,sizeof(buf),in)) ){
		icc += rcc;
		wcc = CCXexec(ccx,buf,rcc,AVStr(xbuf),sizeof(xbuf));
		occ += wcc;
		fwrite(xbuf,1,wcc,out);
		if( ferror(out) )
			break;
	}
	return occ;
}
