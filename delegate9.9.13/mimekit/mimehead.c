/*///////////////////////////////////////////////////////////////////////
Copyright (c) 1992-2000 Yutaka Sato and ETL,AIST,MITI
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
Content-Type: program/C; charset=US-ASCII
Program:      mimehead.c (MIME header encoder/decoder)
Author:       Yutaka Sato <ysato@etl.go.jp>
Description:
    MIME PartII (RFC1522) encoder/decoder for multibyte ISO-2022 charsets
    -----------------------------------------------------------------------
    EN_FGETC ->[ Encode ->encode_word <= encode_one ]->EN_FPUTC ->EN_FPUTC1
               [        ->noencode_word             ]
   
    DE_FGETC ->[ Decode ->decord_word <= scan_eword ]
               [                      -> disp_word  ]
               [        ->nodecode_word             ]->DE_FPUTC ->DE_FPUTC1
    -----------------------------------------------------------------------
History:
        920515	extracted from mmsclient.c
	later history is moved into CHANGES
Bugs:
	Any linear-white-space between encoded-words should be ignored
	(example: E-W CR LF TAB CR LF E-W)
	Should support any charsets & encodings in ISO-2022 or ISO-8859
//////////////////////////////////////////////////////////////////////#*/

#include "mime.h"
#include "str_stdio.h"

#define MAX_LNSIZE	1024
typedef unsigned char MsgLine[MAX_LNSIZE];

#define DEBUG(a)
/*
#define DEBUG(a)	a
*/

#define ES_NONE	0
#define ES_IN	1	/* type-A encoding (not supported yet...) */
#define ES_OUT	2	/* type-B encoding */

int MIME_SPACE_ENCODING = ES_OUT;

/*/////////////////////////////////////////////////////////////////////#*/

#define MAXCOL			72
#define DISPCOLS		80
#define XDISPCOLS		128 /* reasonable for non-ASCII nowadays */
#define ENCODE_LWSPS		0 /* encode LWSPs in non-ASCII as is */

#define SPACECTL_LENG		4
#define SWCODE_LENG		4 /*length(encoded(charset sw ESC seq))*/
#define MIN_ENCODEDLEN		4 /* minimum length of encoded text(base64)*/

#define ENCODE_BEGIN		"=?"
#define CHARSET_DONE		'?'
#define ENCODING_DONE		'?'
#define ENCODE_DONE		"?="

#define LF			'\n'
#define NL			'\n'
#define CR			'\r'
#define TAB			'\t'
#define SPACE			' '
#define FORMFEED		'\f'

#define LWSP_CHAR(ch)		(ch == TAB || ch == SPACE)
#define FOLD_CHAR		SPACE
#define SPECIALS		"()<>@,;:\\\".[]"
#define DELIMITER(ch)		(ch==LF || LWSP_CHAR(ch) || strchr(SPECIALS,ch))
#define IS_PRE_DELIMITER(ch)	DELIMITER(ch)
#define IS_POST_DELIMITER(ch)	(ch==EOF || DELIMITER(ch))

#define NLNL			0x80000001
#define XC_EN_FOLD		0x80000002
#define XC_DE_UNFOLD		0x80000003
#define XC_DE_CATENATE		0x80000004
#define XC_DE_AFTER_EWORD	0x80000005 /* just after encoded-word now */
#define XC_DE_FORMFEED		0x80000006
#define XC_DE_DEL_LWSP		0x80000007
#define XC_DE_IGN_LWSP		0x80000008
#define XC_DE_OFLUSH		0x80000009
#define XC_DE_EWORD_SP		0x8000000A /* a original SPACE and TAB */
#define XC_DE_EWORD_TAB		0x8000000B /* - encoded in a encoded-word */
#define XC_DE_FIELD_TOP		0x8000000C /* new field starts */
#define XC_DE_TOOLONG		0xF0000001

#define ENCODE_NONE		 0
#define ENCODE_BASE64		"B"
#define	ENCODE_QP		"Q"

/*
 * ISO-2022 LOCAL
 */
#define DELSP_PRE	1	/* delete prefixed LWSP */
#define DELSP_POST	2	/* delete postfixed LWSP */
#define DELSP_BOTH	3	/* delete bothside LWSP */

/*/////////////////////////////////////////////////////////////////////#*/
/*	character sets
 */

/*
 *	ISO-2022 character set switch sequences
 */
#define ESC			033
#define GOTO_1BCODE		'('
#define GOTO_2BCODE		'$'

/*
 *	basic charset
 */
typedef struct {
	char	 iso2022[8];
  const	char	*name;
	int	 delspace;	/* as indication code for space deletion */
} Charset;


#define B_US_ASCII	1
#define B_JP_ASCII	2
#define B_JP_KANJI1	3
#define B_JP_KANJI2	4
#define B_UCS_2		5
#define B_EUC_JP	6
#define B_SHIFT_JIS	7
#define B_M17N		8

static Charset BasicCharsets[] = {
	{"",       "UNKNOWN"	},
	{"\033(B", "US_ASCII"	},
	{"\033(J", "JISX0201-R", DELSP_BOTH},
	{"\033$@", "JISX0208-1", DELSP_PRE },
	{"\033$B", "JISX0208-2", DELSP_POST},
	{"",       "UCS-2"	},
	{"",       "EUC-JP"     }, /* 9.9.9 fix-140605d */
	{"",       "Shift_JIS"  },
	{"",       "M17N"       },
	0
};
#define CODESW_SEQ(bset)	BasicCharsets[bset].iso2022
#define GOTO_ASCII_SEQ		BasicCharsets[B_US_ASCII].iso2022
#define GOTO_ASCII_SEQ_LEN	strlen(GOTO_ASCII_SEQ)

/*
static const char *DELSP_SEQUENCE[8] = {
*/
static const char *DELSP_SEQUENCE[16] = {
	0,
	BasicCharsets[B_JP_KANJI1].iso2022,
	BasicCharsets[B_JP_KANJI2].iso2022,
	BasicCharsets[B_JP_ASCII].iso2022,
	0
};
#define DELSP_OP(bset)		BasicCharsets[bset].delspace
#define DELSP_SEQ(delop)	DELSP_SEQUENCE[delop]


/*
 *	MIME charset (may include encoding system and several charsets)
 */
char M_US_ASCII[]	= "US-ASCII";
char M_ISO_8859_8[]	= "ISO-8859-8";
char M_ISO_2022_JP[]	= "ISO-2022-JP";
char M_UTF_8[]		= "UTF-8";
char M_EUC_JP[]		= "EUC-JP";
char M_SHIFT_JIS[]	= "Shift_JIS";
char M_M17N[]           = "M17N";

typedef struct {
	int	local;
	char	codesw;
  const	char   *mcharset;
	int	basic_charset;
  const	char   *encoding;
} MimeCharset;

static MimeCharset Codes1[16] = {
	{1, 'B', M_US_ASCII,	B_US_ASCII,  ENCODE_NONE	},
	{1, 'J', M_US_ASCII,	B_JP_ASCII,  ENCODE_NONE	},
	0
};
static MimeCharset Codes2[16] = {
	{1, '@', M_ISO_2022_JP,	B_JP_KANJI1, ENCODE_BASE64	},
	{1, 'B', M_ISO_2022_JP,	B_JP_KANJI2, ENCODE_BASE64	},
	{1, 0,   M_UTF_8,       B_UCS_2,     ENCODE_BASE64	},
	{1, 0,   M_EUC_JP,      B_EUC_JP,    ENCODE_BASE64	},
	{1, 0,   M_SHIFT_JIS,   B_SHIFT_JIS, ENCODE_BASE64	},
	0
};

const char *known8BMBcode(PCStr(code)){ /* v9.9.12 fix-140826c */
	if( strcaseeq(code,M_UTF_8)     ) return M_UTF_8;
	if( strcaseeq(code,M_EUC_JP)    ) return M_EUC_JP;
	if( strcaseeq(code,M_SHIFT_JIS) ) return M_SHIFT_JIS;
	return 0;
}
int noSpaceAmongWordsCharset(PCStr(charset)){
	if( strcaseeq(charset,M_ISO_2022_JP)
	 || strcaseeq(charset,M_EUC_JP)
	 || strcaseeq(charset,M_SHIFT_JIS)
	){
		return 1;
	}
	return 0;
}
static int nonASCII(PCStr(text)){
	const char *tp;
	for( tp = text; *tp; tp++ ){
		if( *tp & 0x80 ){
			return 1;
		}
	}
	return 0;
}
int noSpaceAmongWords(PCStr(incharset1),PCStr(incharset2),PCStr(itext),PCStr(outcharset)){
	if( noSpaceAmongWordsCharset(incharset1)
	 && noSpaceAmongWordsCharset(incharset2)
	){
		return 1;
	}
	if( nonASCII(itext) ){
		if( strcaseeq(incharset1,incharset2) ){ /* utf-8 typically */
			/*
			if( noSpaceAmongWordsCharset(outcharset) )
			*/
			{
				return 1;
			}
		}
	}
	return 0;
}
int MIME_localCharset(PCStr(mcharset))
{	int csi;
	const char *cs;

	for(csi = 0; cs = Codes1[csi].mcharset; csi++)
		if( strcasecmp(cs,mcharset) == 0 )
			return Codes1[csi].local;

	for(csi = 0; cs = Codes2[csi].mcharset; csi++)
		if( strcasecmp(cs,mcharset) == 0 )
			return Codes2[csi].local;
	return 0;
}

/*/////////////////////////////////////////////////////////////////////#*/
/*
 */
typedef struct {
	int	c_ch;		/* character code value */
  const char*	c_mcharset;	/* MIME charset */
	int	c_bcharset;	/* basic charset */
  const char*	c_encoding;	/* MIME e-word encoding */
} CHARx;
static CHARx NULL_CHAR = { 0,  M_US_ASCII, B_US_ASCII };

/*
 *	ROUND ROBBIN BUFFER
 */
#define RRBUFF_SIZE 8
typedef struct {
	CHARx	b_BUFF[RRBUFF_SIZE];
	int	b_putx;
	int	b_getx;
} RRBUFF;
static RRBUFF NULL_RRBUFF = {0};

typedef struct {
	FILE	*in_file;
	int	 in_column;
	MStr(	 in_ewcharset,64);	/* =?charset?e?x?= */
	int	 in_ewicodemix;		/* mixed charset enc-word */
	int	 in_ewiccxeach;		/* decode and CCX each enc-word */
  const char	*in_charcode8B;		/* default charset in 8bits */
  const char	*in_mcharset;		/* current MIME charset */
	int	 in_bcharset;		/* current basic charset */
	int	 in_bcharset_got;	/* bcharset was got explicitly */
  const	char	*in_encoding;		/* B or Q */
	int	 in_prevch;		/* EN_FGETC() / DE_FGETC() local */
	RRBUFF	 in_BUFF;		/* EN_FGETC() local */
	RRBUFF	 in_PUSHED;		/* EN_UNGETC() -> EN_FGETC() */

	FILE	*out_file;
	int	 out_column;
	int	 out_noccx;		/* disable CCX */
   const char	*out_charcode;		/* output charset */
	int	 out_lastputch;		/* EN_FPUTC() -> encode_word() */
	int	 out_whichASCII;	/* disp_word() -> DE_FPUTC(),C1() */
	int	 out_enLWSP;		/* EN_FPUTC() local */
	CHARx	 out_prevCHAR;		/* EN_FPUTC1() local */
	CHARx	 out_deLWSP[4];		/* DE_FPUTCX() local */
	int	 out_prev_bcharset;	/* DE_FPUTC1X() local */

	union { int all; struct { unsigned int
		 MIMEencoded :1,	/* I: this field is MIME encoded */
		 end_CRLF    :1,	/* I: line terminates with CRLF */
		 eat_SPACE   :2,	/* I: decoder space eraser */
		 ext_SPACE   :1,	/* O: external space encoding */
		 cat_ewords  :1,	/* O: catenate decoded e-words */
		 unfolding   :1,	/* O: unfold decoder output */
		 ign_SPACE   :1,	/* O: ignore postfix space */
		 gen_SPACE   :1,	/* O: just after space was generated */
		 after_eword :1;	/* O: just after eword has put */
	} mode; } io_MODES;
} INOUT;
#define ENCODE_EXT	io_MODES.mode.ext_SPACE

static void INOUT_init(INOUT *io,FILE *in,FILE *out)
{
	io->in_file           = in;
	io->in_column         = 0;
	clearVStr(io->in_ewcharset);
	io->in_ewicodemix     = 0;
	io->in_ewiccxeach     = 0;
	io->in_charcode8B     = 0;
	io->in_mcharset       = M_US_ASCII;
	io->in_bcharset       = B_US_ASCII;
	io->in_bcharset_got   = 0;
	io->in_encoding       = ENCODE_NONE;
	io->in_prevch         = EOF;
	io->in_BUFF           = NULL_RRBUFF;
	io->in_PUSHED         = NULL_RRBUFF;

	io->out_file          = out;
	io->out_column        = 0;
	io->out_noccx         = 0;
	io->out_charcode      = 0;
	io->out_lastputch     = 0;
	io->out_whichASCII    = B_US_ASCII;
	io->out_enLWSP        = 0;
	io->out_prevCHAR      = NULL_CHAR;
	io->out_deLWSP[0]     = NULL_CHAR;
	io->out_prev_bcharset = B_US_ASCII;

	io->io_MODES.all      = 0;
	io->io_MODES.mode.cat_ewords = 1;
	io->ENCODE_EXT        = MIME_SPACE_ENCODING == ES_OUT;
}

#define in_CODESW_SEQ(io)	CODESW_SEQ(io->in_bcharset)
#define MIME_ENCODED	io_MODES.mode.MIMEencoded
#define EAT_SPACE	io_MODES.mode.eat_SPACE
#define CAT_EWORDS	io_MODES.mode.cat_ewords
#define UNFOLD_LINE	io_MODES.mode.unfolding
#define IGN_POST_SPACE	io_MODES.mode.ign_SPACE
#define SPACE_WAS_GEN	io_MODES.mode.gen_SPACE
#define AFTER_EWORD	io_MODES.mode.after_eword


#define NEXT_RRBUFF(BP) (\
	((RRBUFF_SIZE <= ++(BP)->b_putx) ? ((BP)->b_putx = 0):0), \
	&(BP)->b_BUFF[(BP)->b_putx] \
	)

#define PUT_RRBUFF(BP,CH) (\
	/* must check full here */ \
		((RRBUFF_SIZE <= ++(BP)->b_putx) ? ((BP)->b_putx = 0):0), \
		((BP)->b_BUFF[(BP)->b_putx] = *CH) \
	)

#define GET_RRBUFF(BP,CH) (\
	((BP)->b_putx == (BP)->b_getx) ? 0 : (\
		((RRBUFF_SIZE <= ++(BP)->b_getx) ? ((BP)->b_getx = 0):0), \
		(*CH = (BP)->b_BUFF[(BP)->b_getx]), \
		&(BP)->b_BUFF[(BP)->b_getx] \
	))


static int end_CRLF;
static int NLfgetc(FILE *in)
{	int ch;

	ch = fgetc(in);
	if( ch == CR ){
		ch = fgetc(in);
		if( ch == LF ){
			end_CRLF = 1;
			ch = NL;
		}else{
			if( ch != EOF )
				ungetc(ch,in);
			ch = CR;
		}
	}else
	if( ch == LF ){
		end_CRLF = 0;
		ch = NL;
	}
	return ch;
}
static void NLfputc(int ch,FILE *out)
{
	if( ch == NL && end_CRLF )
		fputc(CR,out);
	fputc(ch,out);
}

static void EN_UNGETC(CHARx *CH,INOUT *io)
{
	/* v9.9.12 fix-140826e, UNGETC by push like round robin  */
	RRBUFF *BP = &io->in_PUSHED;
	int getx;

	BP->b_getx -= 1;
	if( BP->b_getx < 0 )
		BP->b_getx = RRBUFF_SIZE - 1;
	getx = BP->b_getx + 1;
	if( RRBUFF_SIZE <= getx )
		getx = 0;
	BP->b_BUFF[getx] = *CH;
	/*
	PUT_RRBUFF(&io->in_PUSHED,CH);
	*/
}

static CHARx *EN_FGETC(INOUT *io)
{	int ch;
	MimeCharset *csw;
	int ci;
	const char *mcharset;
	FILE *infile = io->in_file;
	CHARx *CH;
	RRBUFF *BP;

	/* getting a slot for CH (and CH2, CH3, ...) by round robin */ 
	BP = &io->in_BUFF;
	CH = NEXT_RRBUFF(BP);

	BP = &io->in_PUSHED;
	if( GET_RRBUFF(BP,CH) ){
		ch = CH->c_ch;
		/* 9.9.12 fix-140827c, should recover environment on pop */
		io->in_mcharset = CH->c_mcharset;
		io->in_bcharset = CH->c_bcharset;
		io->in_encoding = CH->c_encoding;
		/* should recover io->in_column too ? */
		goto EXIT;
	}

	*CH = NULL_CHAR;
GET1:
	ch = NLfgetc(infile);
GOT1:
	if( ch != ESC )
	{
		if( ch & 0x80 ){
			if( io->in_mcharset != M_UTF_8 )
			if( io->in_charcode8B == M_UTF_8 )
			{
				io->in_mcharset = M_UTF_8;
				io->in_bcharset = B_UCS_2;
				io->in_encoding = ENCODE_BASE64;
				goto exit;
			}
			if( io->in_charcode8B ){
				io->in_mcharset = io->in_charcode8B;
				io->in_bcharset = B_M17N;
				io->in_encoding = ENCODE_BASE64;
			}
		}
		goto exit;
	}

	/* got ESC character */
	if( (ch = fgetc(infile)) == EOF )
		goto exit;

	if( io->in_prevch == NL )
		if( LWSP_CHAR(ch) )
			goto GET1;

	switch( ch ){
		default:	goto exit;
		case GOTO_1BCODE: csw = Codes1; break;
		case GOTO_2BCODE: csw = Codes2; break;
	}
	if( (ch = fgetc(infile)) == EOF )
		goto exit;

	for( ci = 0; mcharset = csw[ci].mcharset; ci++ ){
		if( ch == csw[ci].codesw ){
			io->in_mcharset = mcharset;
			io->in_encoding = csw[ci].encoding;

			if( io->in_column == 0 && io->in_bcharset_got )
				io->EAT_SPACE = DELSP_OP(io->in_bcharset);

			io->in_bcharset_got = 1;
			io->in_bcharset = csw[ci].basic_charset;
			break;
		}
	}

	ch = NLfgetc(infile);
	if( ch == ESC )
		goto GOT1;
exit:
	CH->c_ch = ch;
	CH->c_mcharset = io->in_mcharset;
	CH->c_bcharset = io->in_bcharset;
	CH->c_encoding = io->in_encoding;

EXIT:
	io->in_prevch = ch;
	io->in_column++;
	if( ch == NL || ch == NLNL ){
		io->in_column = 0;
		io->EAT_SPACE = 0;
		io->MIME_ENCODED = 0;
		io->in_mcharset = M_US_ASCII;
		io->in_encoding = ENCODE_NONE;
		CH->c_mcharset = io->in_mcharset;
	}

	return CH;
}

static int ew_overhead(PCStr(charset),PCStr(encoding))
{	CStr(overhead,MAX_LNSIZE);

	sprintf(overhead,"=?%s?%s?x?= ",charset,encoding);
	return strlen(overhead) - 1;
}

static void EN_FPUTC0(int ch,INOUT *io)
{
	if( ch == NL ){
		io->SPACE_WAS_GEN = 0;
		io->out_column = 0;
	}else	io->out_column += 1;
	NLfputc(ch,io->out_file);
}

/*
 *	extra folding before a lengthy encoded-word
 *	put =?charset?encoding? at the beginning of non-ASCII
 *	put SPACE before it if the previous char is not DELIMITER
 *
 *	put ?= at the end of non-ASCII
 *	put SPACE after it if the next char is not DELIMITER
 */
static void EN_FPUTC1(int ch,INOUT *io,PCStr(charset),PCStr(encoding))
{	const unsigned char *cp;
	/*MsgLine line;*/
	unsigned CStr(line,MAX_LNSIZE);

	if( charset != io->out_prevCHAR.c_mcharset ){

		/* AT THE END OF A ENCODED WORD */
		if( io->out_prevCHAR.c_mcharset != M_US_ASCII ){
			for( cp = (unsigned char*)ENCODE_DONE; *cp; cp++ )
				EN_FPUTC0(*cp,io);

			if( !DELIMITER(ch) ){
				EN_FPUTC0(SPACE,io);
				io->SPACE_WAS_GEN = 1;
			}
		}

		/* AT THE BEGINNING OF A ENCODED WORD */
		if( charset != M_US_ASCII ){
			int reqlen,remlen;

			if( !DELIMITER(io->out_prevCHAR.c_ch) )
				EN_FPUTC0(SPACE,io);

			reqlen = ew_overhead(charset,encoding);
			remlen = MAXCOL - (io->out_column + reqlen);

			if( (remlen-SWCODE_LENG) < MIN_ENCODEDLEN ){
				EN_FPUTC0(NL,io);
				EN_FPUTC0(FOLD_CHAR,io);
			}
			Xsprintf(AVStr(line),"=?%s?%s?",charset,encoding);
			for( cp = line; *cp; cp++ )
				EN_FPUTC0(*cp,io);
			io->MIME_ENCODED = 1;
		}
	}

	if( ch != EOF ){
		if( ch != NL ){
			/* split at LWSP_CHAR ... */
			if( !encoding )
			if( io->MIME_ENCODED )
			if( MAXCOL <= io->out_column )
			if( LWSP_CHAR(ch) )
				EN_FPUTC0(NL,io);
		}
		EN_FPUTC0(ch,io);
	}
	io->out_prevCHAR.c_mcharset = (char*)charset;
	io->out_prevCHAR.c_ch = ch;
}

#define PENDING_LWSP out_enLWSP

static void EN_FPUTC(int ch,INOUT *io,PCStr(charset),PCStr(encoding))
{	int lwsp;

	if( (ch & 0xFF) == ch )
		io->out_lastputch = ch;

	if( ch == XC_EN_FOLD ){
		if( lwsp = io->PENDING_LWSP )
			io->PENDING_LWSP = 0;
		else{
			lwsp = SPACE;
			io->SPACE_WAS_GEN = 1;
		}
		EN_FPUTC1(NL,io,M_US_ASCII,ENCODE_NONE);
		EN_FPUTC1(lwsp,io,M_US_ASCII,ENCODE_NONE);
	}else{
		if( lwsp = io->PENDING_LWSP ){
			EN_FPUTC1(lwsp,io,M_US_ASCII,ENCODE_NONE);
			io->PENDING_LWSP = 0;
		}
		if(LWSP_CHAR(ch)&& charset==M_US_ASCII&& encoding==ENCODE_NONE)
			io->PENDING_LWSP = ch;
		else	EN_FPUTC1(ch,io,charset,encoding);
	}
}

/*
 *	PASS THROUGH AN ASCII WORD
 */
static int noencode_word(INOUT *io)
{	CHARx *CH,*NCH;
	int ch,inx;
	int canbe_folded;
	MsgLine line;

	canbe_folded = io->MIME_ENCODED;
	for(inx = 0; inx <= MAXCOL; inx++){
		CH = EN_FGETC(io);
		ch = CH->c_ch;

		if( io->in_mcharset != M_US_ASCII ){
			if( ch != EOF )
			EN_UNGETC(CH,io);
			break;
		}
		if( ch == EOF )
			break;
		if( ch == NL ){
			line[inx++] = NL;
			NCH = EN_FGETC(io);
			switch( NCH->c_ch ){
			    case NL:  ch = NLNL; break;
			    case EOF: break;
			    default: EN_UNGETC(NCH,io); break;
			}
			break;
		}
/*
if( canbe_folded )
if( DELIMITER(ch) )
*/
/* might be harmful for tools don't treat unfolding properly */
		if( LWSP_CHAR(ch) )
		{
			line[inx++] = ch;
			break;
		}
		line[inx] = ch;
	}
	line[inx] = 0;

	if( line[0] != NL )
	if( canbe_folded )/* safety for non-MIMEr like inews/Cnews */
	if( MAXCOL+2 < io->out_column+inx )
		EN_FPUTC(XC_EN_FOLD,io,M_US_ASCII,ENCODE_NONE);

	{	int ch,ci;
		for( ci = 0; ch = line[ci]; ci++ )
			EN_FPUTC(ch,io,M_US_ASCII,ENCODE_NONE);
	}
	return ch;
}
static int encode_one(PCStr(encoding),PCStr(ins),int ilen,PVStr(outs),int osize)
{	int len;

	if( encoding == NULL ){
		/* this must not happen, but should escape SEGV if happend */
		fprintf(stderr,"##encode_one() got NULL encoding\n");
		strncpy(outs,ins,ilen);
		len = ilen;
	}else
	if( strcasecmp(encoding,ENCODE_QP) == 0 )
		len = str_toqp(ins,ilen,AVStr(outs),osize);
	else
	if( strcasecmp(encoding,ENCODE_BASE64) == 0 )
		len = str_to64(ins,ilen,AVStr(outs),osize,0);
	else{
		strncpy(outs,ins,ilen);
		len = ilen;
	}
	setVStrEnd(outs,len);
	return len;
}

static int encode_word(INOUT *io)
{	const char *charset;	/* charset of this encoded-word */
	const char *encoding;	/* encoding of this encoded-word */
	CStr(Ins,MAX_LNSIZE);
	CStr(Outs,MAX_LNSIZE);
	refQStr(ins,Ins);
	refQStr(outs,Outs);
	int inx,outx,prefold;
	int char_bytes,nchar,reqlen,remlen,outlen;
	int nwspchar;
	char encoded_ch;
	int ch;
	int prech = 0;
	int postch = 0;
	int delop = 0;
	CHARx *CH;

	if( io->out_charcode == 0
	 || !strcaseeq(io->out_charcode,M_ISO_2022_JP)
	){
		io->ENCODE_EXT = 0; /* 9.9.9 fix-140606a  */
	}
	charset = io->in_mcharset;
	char_bytes = 2;
	encoding = io->in_encoding;
	reqlen = ew_overhead(charset,encoding);

	/*
	 *	firstly, add the code switch sequence in a encoded format
	 */
	strcpy(ins,in_CODESW_SEQ(io));
	inx = strlen(ins);

	if( io->ENCODE_EXT ){
		strcat(ins,in_CODESW_SEQ(io));
		outlen = encode_one(encoding,ins,strlen(ins),QVStr(outs,Outs),sizeof(Outs));
	}else	outlen = encode_one(encoding,ins,inx,QVStr(outs,Outs),sizeof(Outs));

	/*
	 *	if remaining length is not enough, fold the line
	 */
	remlen = MAXCOL - (io->out_column + reqlen);
	if( (remlen-outlen) <= MIN_ENCODEDLEN ){
		remlen = MAXCOL - (1 + reqlen);
		prefold = 1;
	}else	prefold = 0;

	/*
	 *	scan a word to be encoded expanding byte by byte.
	 *	every encoded-texts end with the switch to M_US_ASCII
	 */
	nwspchar = 0;
	for(nchar = 0; ;nchar++){
	    if( io->ENCODE_EXT ){
		Xstrcpy(QVStr(&ins[inx],Ins),GOTO_ASCII_SEQ);
		outlen = encode_one(encoding,ins,inx+GOTO_ASCII_SEQ_LEN,
			 QVStr(outs,Outs),sizeof(Outs));
	    }else{
		outlen = encode_one(encoding,ins,inx,
			 QVStr(outs,Outs),sizeof(Outs));
	    }

		CH = EN_FGETC(io);
		ch = CH->c_ch;
		if( ch == EOF || ch == NL || CH->c_mcharset != charset ){
			if( nchar == 0 && CH->c_mcharset != charset ){
				if( CH->c_mcharset != M_US_ASCII ){
					/* this can cause infinite loop */
					/* so discard the character */
					setVStrEnd(ins,inx);
					break;
				}
			}
			if( io->in_mcharset == M_US_ASCII )
				Xstrcpy(QVStr(&ins[inx],Ins),in_CODESW_SEQ(io));
				/* ASCII family like JIS-X0201-Roman */


			/* ENCODE A LWSP BETWEEN ENCODED-WORDS */
			/*if( 4 <= (remlen-outlen) )*/
			if( LWSP_CHAR(ch) ){
				CHARx *NCH;
				CStr(lwspb,4);
				int lwspx,cx;

				lwspb[0] = ch;
				for( lwspx = 1; lwspx < sizeof(lwspb); ){ 
					NCH = EN_FGETC(io);
					if( !LWSP_CHAR(NCH->c_ch) )
						break;
					if( ENCODE_LWSPS )
						setVStrElemInc(lwspb,lwspx,NCH->c_ch);  /**/
				}

				if( NCH->c_mcharset == charset ){
					EN_UNGETC(NCH,io);
					inx += strlen(&ins[inx]);
					for( cx = 0; cx < lwspx; cx++ )
						setVStrElemInc(ins,inx,lwspb[cx]);
					setVStrEnd(ins,inx);
					if( 12 <= (remlen-outlen) ){
/* TO BE CATENATED */
Xstrcpy(QVStr(&ins[inx],Ins),CODESW_SEQ(NCH->c_bcharset));
inx = strlen(ins);
nwspchar += lwspx;
continue;
					}
/* TO BE SPLITTED */
postch = ch;
break;
				}
				EN_UNGETC(NCH,io);
				EN_UNGETC(CH,io);
				break;
			}
			if( ch != EOF )
				EN_UNGETC(CH,io);

			postch = ch;
			break;
		}
		if( (nchar - nwspchar) % char_bytes == 0 && remlen <= outlen ){
			EN_UNGETC(CH,io);
			break;
		}
		if( ch == EOF )
			break;

		setVStrElemInc(ins,inx,ch);
		if( CH->c_mcharset ){
			/* v9.9.12 fix-140826c, not to split multi bytes char. */
			int JIS7_bytes(int ch1,int ch2);
			int SJIS_bytes(int ch1,int ch2);
			int EUCJ_bytes(int ch1,int ch2,int ch3);
			int UTF8_bytes(int ch1,int ch2,int ch3);
			CHARx *CH2,*CH3;
			int ch2,ch3;
			int len = 0;

			CH2 = EN_FGETC(io); ch2 = CH2->c_ch;
			CH3 = EN_FGETC(io); ch3 = CH3->c_ch;

			if( CH->c_mcharset == M_ISO_2022_JP ){
				len = JIS7_bytes(ch,ch2);
			}else
			if( CH->c_mcharset == M_SHIFT_JIS ){
				len = SJIS_bytes(ch,ch2);
			}else
			if( CH->c_mcharset == M_EUC_JP ){
				len = EUCJ_bytes(ch,ch2,ch3);
			}else
			if( CH->c_mcharset == M_UTF_8 ){
				len = UTF8_bytes(ch,ch2,ch3);
			}else{
			}
			if( 1 < len ){
				setVStrElemInc(ins,inx,ch2);
				nchar++;
				if( 2 < len ){
					setVStrElemInc(ins,inx,ch3);
					nchar++;
				}else{
					EN_UNGETC(CH3,io);
				}
			}else{
				EN_UNGETC(CH3,io);
				EN_UNGETC(CH2,io);
			}
		}
		setVStrEnd(ins,inx);
	}
	inx += strlen(&ins[inx]);

	if( nchar == 0 )
		return ch;

	if( prefold )
		EN_FPUTC(XC_EN_FOLD,io,M_US_ASCII,ENCODE_NONE);

	/*
	 *	output the scanned word
	 */
	if( io->ENCODE_EXT ){ /* external space encoding for ISO-2022-JP */
		delop = 0;
		prech = io->out_lastputch;

		/* if pre-SPACE will be inserted... X-), or was inserted */
		if( !IS_PRE_DELIMITER(prech) || io->SPACE_WAS_GEN && !prefold )
			delop |= DELSP_PRE;
		io->SPACE_WAS_GEN = 0;

		/* if post SPACE will be inserted... */
		if( !IS_POST_DELIMITER(postch) && postch != 0 )
			delop |= DELSP_POST;

		if( delop ){
			CStr(tmp,MAX_LNSIZE);

			strcpy(tmp,ins);
			strcpy(ins,DELSP_SEQ(delop));
			strcat(ins,tmp);
			inx = strlen(ins);
		}
	}

	outlen = encode_one(encoding,ins,inx,QVStr(outs,Outs),sizeof(Outs));
	for(outx = 0; outx < outlen; outx++){
		encoded_ch = outs[outx];
		if( encoded_ch == NL )
			continue;
		EN_FPUTC(encoded_ch,io,charset,encoding);
	}
	return ch;
}
/* it may be desirable to fold before an encoded-word, which length is
 *  shorter than MAXCOL, but will be splitted in current line.  */


int MIME_headerEncode0X(MimeConv *Mcv,FILE *in,FILE *out);
int MIME_headerEncode0(FILE *in,FILE *out)
{
	return MIME_headerEncode0X(0,in,out);
}
int MIME_headerEncode0X(MimeConv *Mcv,FILE *in,FILE *out)
{	INOUT iob,*io = &iob;
	CHARx *CH;
	int ch;

	INOUT_init(io,in,out);
	if( Mcv ){
		io->out_noccx = Mcv->c_noccx;
		if( Mcv->c_ocode ){
			io->out_charcode = Mcv->c_ocode;
		}
		if( Mcv->c_icode ){
			if( strcaseeq(Mcv->c_icode,M_UTF_8) ){
				io->in_charcode8B = M_UTF_8;
			}else{
				/* v9.9.12 fix-140826c, simplify comparation */
				io->in_charcode8B = known8BMBcode(Mcv->c_icode);
				if( io->in_charcode8B == 0 )
				io->in_charcode8B = Mcv->c_icode;
			}
		}
	}
	for(;;){
		CH = EN_FGETC(io);
		EN_UNGETC(CH,io);

		ch = CH->c_ch;
		if( CH->c_mcharset == M_US_ASCII ){
			ch = noencode_word(io);
			if( ch == EOF )
				break;
			if( ch == NLNL )
				break;
		}else{
			for(;;){
				ch = encode_word(io);
				if( io->in_mcharset == M_US_ASCII )
					break;
				if( ch == EOF )
					break;
			}
			if( ch == EOF )
				break;
		}
	}
	if( ch == EOF )
		EN_FPUTC(ch,io,M_US_ASCII,ENCODE_NONE);
	return ch;
}
int MIME_headerEncodeX(MimeConv *Mcv,FILE *in,FILE *out);
void MIME_headerEncode(FILE *in,FILE *out)
{
	MIME_headerEncodeX(0,in,out);
}
int MIME_headerEncodeX(MimeConv *Mcv,FILE *in,FILE *out)
{	int ch;
	CStr(line,MAX_LNSIZE);

	/*
	ch = MIME_headerEncode0(in,out);
	*/
	ch = MIME_headerEncode0X(Mcv,in,out);
	if( ch != EOF ){
		NLfputc(NL,out);
		while( fgets(line,sizeof(line),in) != NULL )
			fputs(line,out);
	}
	return 0;
}


/*
 *	FINAL OUTPUT WITH ISO-2022 CHARACTER SET SWITCH SEQUENCE
 */
static void DE_FPUTC1X(CHARx *CH,INOUT *Out)
{	FILE *out;
	int cset;
	int ch;

	out = Out->out_file;
	ch = CH->c_ch;
	if( ch == XC_DE_EWORD_SP  ) ch = SPACE; else
	if( ch == XC_DE_EWORD_TAB ) ch = TAB;
	cset = CH->c_bcharset;

	if( cset != Out->out_prev_bcharset ){
		fputs(CODESW_SEQ(cset),out);
		Out->out_prev_bcharset = cset;
	}
	Out->AFTER_EWORD = 0;

	switch( ch ){
		case EOF:			return;
		case XC_DE_OFLUSH:		return;
		case NL: Out->out_column = 0;	break;
		default: Out->out_column++;	break;
	}
	NLfputc(ch,out);
}

/*
 *	PUT ASCII (or CONTROL) CHARACTER IN A CURRENT ASCII FAMILY
 */
static void DE_FPUTC1(int ch,INOUT *io)
{	CHARx CH;

	CH.c_bcharset = io->out_whichASCII;
	CH.c_ch = ch;
	DE_FPUTC1X(&CH,io);
}

static void dumpDECODER(CHARx *CH,INOUT *io)
{	int i,ch;
	CStr(sym,16);

	switch( ch = CH->c_ch ){
		case NLNL:		strcpy(sym,"NLNL"); break;
		case XC_EN_FOLD:	strcpy(sym,"FOLD"); break;
		case XC_DE_UNFOLD:	strcpy(sym,"UNFOLD"); break;
		case XC_DE_CATENATE:	strcpy(sym,"CATENATE"); break;
		case XC_DE_AFTER_EWORD:	strcpy(sym,"AFTER_EWORD"); break;
		case XC_DE_FORMFEED:	strcpy(sym,"FORMFEED"); break;
		case XC_DE_DEL_LWSP:	strcpy(sym,"DEL_LWSP"); break;
		case XC_DE_IGN_LWSP:	strcpy(sym,"IGN_LWSP"); break;
		case XC_DE_OFLUSH:	strcpy(sym,"OFUSH"); break;
		case XC_DE_TOOLONG:	strcpy(sym,"TOOLONG"); break;
		case XC_DE_FIELD_TOP:	strcpy(sym,"FILED_TOP"); break;
		default:
			if( ch <= 0x20 || 0x7F <= ch )
				sprintf(sym,"0x%x",ch);
			else	sprintf(sym,"%c",ch);
	}
	syslog_ERROR("#### out %2d in [%-12s] IPS=%d AEW=%d UFL=%d Q=",
		io->out_column,sym,io->IGN_POST_SPACE,io->AFTER_EWORD,io->UNFOLD_LINE);

	if( io->out_deLWSP[0].c_ch ){
		for(i = 0; i < 4; i++ ){
			if( io->out_deLWSP[i].c_ch == 0 )
				break;
			syslog_ERROR("[%x]",io->out_deLWSP[i].c_ch);
		}
	}
	syslog_ERROR("\n");
}

/*
 *	PUT CHARACTER CONTROLLING "LWSP" AND UNFOLDING
 */
#define CLEAR_LWSP(io)	(io->out_deLWSP[0].c_ch = 0)

static void DE_FPUTCX(CHARx *CH,INOUT *io)
{	int ch;
	CHARx PCH;

	if( io == 0 )
		return;

	/*dumpDECODER(CH,io);*/

	ch = CH->c_ch;

	if( ch == XC_DE_DEL_LWSP ){
		CLEAR_LWSP(io);
		return;
	}
	if( ch == XC_DE_IGN_LWSP ){
		io->IGN_POST_SPACE = 1;
		return;
	}
	if( io->IGN_POST_SPACE ){
		if( LWSP_CHAR(ch) )
			return;

		if( (ch & 0xFF) == ch )
			io->IGN_POST_SPACE = 0;
	}
	if( ch == XC_DE_AFTER_EWORD ){
		io->AFTER_EWORD = 1;
		return;
	}
	if( ch == XC_DE_CATENATE ){
		/* REMOVE PENDING SPACE IF EXISTS */
		if( ! io->AFTER_EWORD ){
			PCH = io->out_deLWSP[0];
			if( PCH.c_ch == NL ){
				/* discard the NEWLINE */
				PCH = io->out_deLWSP[1];
			}
			if( PCH.c_ch )
				DE_FPUTC1X(&PCH,io);
		}
		CLEAR_LWSP(io);
		return;
	}
	if( ch == XC_DE_UNFOLD ){
		if( io->out_deLWSP[0].c_ch == NL ){
			PCH = io->out_deLWSP[1];
			if( PCH.c_ch ){
				DE_FPUTC1X(&PCH,io);
				CLEAR_LWSP(io);
			}
		}
		return;
	}
	if( ch == XC_DE_FORMFEED ){
		PCH = io->out_deLWSP[0];
		if( PCH.c_ch ){
			DE_FPUTC1X(&PCH,io);
			PCH = io->out_deLWSP[1];
			if( PCH.c_ch )
				DE_FPUTC1X(&PCH,io);
			CLEAR_LWSP(io);
		}
		DE_FPUTC1(FORMFEED,io);
		DE_FPUTC1(NL,io);
		fflush(io->out_file);
		return;
	}

	/* FLUSH LWSP */
	PCH = io->out_deLWSP[0];
	if( ch == XC_DE_FIELD_TOP ){
		if( PCH.c_ch == NL )
			DE_FPUTC1X(&PCH,io);
		CLEAR_LWSP(io);
		return;
	}
	if( PCH.c_ch ){
		if( ch == NL && PCH.c_ch == NL )
			return;
		if( ch == NL || LWSP_CHAR(ch) ){
			if( ch == NL && PCH.c_ch != NL ){
				if( !io->AFTER_EWORD )
					DE_FPUTC1X(&PCH,io);
				io->out_deLWSP[0] = *CH;
				io->out_deLWSP[1].c_ch = 0;
			}else{
				io->out_deLWSP[1] = *CH;
				io->out_deLWSP[2].c_ch = 0;
			}
			return;
		}
		DE_FPUTC1X(&PCH,io);
		PCH = io->out_deLWSP[1];
		if( PCH.c_ch )
			DE_FPUTC1X(&PCH,io);
		CLEAR_LWSP(io);
	}

	/* ENBUFFER LWSP */
	if( io->UNFOLD_LINE ){
		if( ch == NL || LWSP_CHAR(ch) ){
			io->out_deLWSP[0] = *CH;
			io->out_deLWSP[1].c_ch = 0;
			return;
		}
	}
	DE_FPUTC1X(CH,io);
}

/*
 *	PUT ASCII (or CONTROL) CHARACTER IN A CURRENT ASCII FAMILY
 */
static void DE_FPUTC(int ch,INOUT *io)
{	CHARx CH;

	CH.c_bcharset = io->out_whichASCII;
	CH.c_ch = ch;
	DE_FPUTCX(&CH,io);
}


static
int scan_eword(FILE *in,xPVStr(reads),PVStr(charset),PVStr(encoding),PVStr(text))
{	int i,cs;

	for(i = 0; ;i++){
		if( 32 <= i ){
			cs = XC_DE_TOOLONG;
			goto error;
		}
		cs = NLfgetc(in);
		if(cs==NL || cs==EOF) goto error;
		setVStrPtrInc(reads,cs); /**/
		if(cs==CHARSET_DONE) break;
		setVStrElem(charset,i,cs); /**/
		setVStrEnd(charset,i+1);
	}
	for(i = 0; ;i++){
		if( 32 <= i ){
			cs = XC_DE_TOOLONG;
			goto error;
		}
		cs = NLfgetc(in);
		if(cs==NL || cs==EOF) goto error;
		setVStrPtrInc(reads,cs); /**/
		if(cs==ENCODING_DONE) break;
		setVStrElem(encoding,i,cs); /**/
		setVStrEnd(encoding,i+1);
	}
	for(i = 0;;i++){
		/*
		if( 80 <= i ){
		*/
		if( 120 <= i ){
			cs = XC_DE_TOOLONG;
			goto error;
		}
		cs = NLfgetc(in);
		if(cs==NL || cs==EOF) goto error;
		setVStrPtrInc(reads,cs); /**/
		if(cs == ENCODE_DONE[0]){
			cs = NLfgetc(in);
			if(cs==NL || cs==EOF) goto error;
			setVStrPtrInc(reads,cs); /**/
			if( cs == ENCODE_DONE[1] ){
				setVStrEnd(text,i);
				break;
			}
			ungetc(cs,in);
			cs = ENCODE_DONE[0];
		}
		setVStrElem(text,i,cs); /**/
		setVStrEnd(text,i+1);
	}
	return 0;
error:
	setVStrEnd(reads,0);
	return cs;
}

static int disp_word(INOUT *Out,PCStr(dtext),int len)
{	FILE *DecodedText;
	INOUT tmpInb,*tmpIn = &tmpInb;
	int sdlen,dlen;
	int eat_space = 0;
	CHARx *CH;

	if( len <= 0 )
		return 0;

	if( Out )
		sdlen = disp_word(0,dtext,len);

	DecodedText = str_fopen((char*)dtext,len,"r");
	INOUT_init(tmpIn,DecodedText,NULL);

	dlen = 0;
	for(;;){
		CH = EN_FGETC(tmpIn);
		if( CH->c_ch == EOF )
			break;

		if( CH->c_ch == SPACE ) CH->c_ch = XC_DE_EWORD_SP; else
		if( CH->c_ch == TAB   ) CH->c_ch = XC_DE_EWORD_TAB;

		if( Out && dlen == 0 ){
			if( Out->ENCODE_EXT )
				eat_space = tmpIn->EAT_SPACE;
			else	eat_space = 0;

			if( eat_space & DELSP_PRE ){
				DE_FPUTC(XC_DE_DEL_LWSP,Out);
				DEBUG(DE_FPUTC('{',Out));
			}else{
				if( Out->out_column + sdlen < DISPCOLS )
					DE_FPUTC(XC_DE_CATENATE,Out);
				else	DE_FPUTC(XC_DE_OFLUSH,Out);
			}
		}
		if( Out )
			DE_FPUTCX(CH,Out);
		dlen++;
	}
	str_fclose(DecodedText);

	if(Out){
		DE_FPUTC(XC_DE_AFTER_EWORD,Out);
		Out->MIME_ENCODED = 1;
		Out->out_whichASCII = CH->c_bcharset; /* CH == EOF */

		if( eat_space & DELSP_POST ){
			DEBUG(DE_FPUTC(XC_DE_OFLUSH,Out));
			DEBUG(DE_FPUTC('}',Out));
			DE_FPUTC(XC_DE_IGN_LWSP,Out);
		}
	}
	return dlen;
}

CCXP MIMEHEAD_CCX;
int bad_etext(PCStr(charset),PCStr(dtext),int len);
static int decode_word(INOUT *io)
{	MsgLine reads,charset,encoding,itext;
	CStr(dtext,MAX_LNSIZE);
	int ilen,dsize,len,pad,dlen;
	int eow;
	int m17n_known = 0;
	const char *ocset = "ISO-2022-JP";

	*charset = *encoding = *itext = 0;

	eow = scan_eword(io->in_file,FVStr(reads),FVStr(charset),FVStr(encoding),FVStr(itext));

	if( eow == NL || eow == EOF || eow == XC_DE_TOOLONG ){
		DE_FPUTC(XC_DE_OFLUSH,io);
		fprintf(io->out_file,"=?%s",reads);
		if( eow == NL )
			ungetc(eow,io->in_file);
		return eow;
	}

	if( m17n_known_code((const char*)charset) ){
		m17n_known = 1;
		goto DECODE;
	}
	if( !MIME_localCharset((char*)charset) ){
BAD_EWORD:
		DE_FPUTC(XC_DE_OFLUSH,io);
		fprintf(io->out_file,"=?%s?%s?%s?=",charset,encoding,itext);
		if( eow )
			fprintf(io->out_file,"%c",eow);
		return 0;
	}

DECODE:
	ilen = strlen((char*)itext);
	dsize = sizeof(dtext);
	if( strcasecmp((char*)encoding,ENCODE_QP) == 0 ){
		len = str_fromqp((char*)itext,ilen,AVStr(dtext),dsize);
		if( bad_etext((char*)charset,dtext,len) )
			goto BAD_EWORD;
	}else
	if( strcasecmp((char*)encoding,ENCODE_BASE64) == 0 ){
		len = str_from64((char*)itext,ilen,AVStr(dtext),dsize);
		if( bad_etext((char*)charset,dtext,len) )
			goto BAD_EWORD;
	}else{
		strcpy(dtext,(char*)itext);
		len = ilen;
	}

	if( io->in_ewcharset[0] && !strcaseeq(io->in_ewcharset,(char*)charset) ){
		io->in_ewicodemix++;
	}
	if( io->out_noccx ){
	    ocset = (char*)charset;
	}else
	if( io->in_ewiccxeach || MIMEHEAD_CCX ){
	    const char *oc;
	    M17N m17n = 0;

	    if( MIMEHEAD_CCX
	     && !CCXguessing(MIMEHEAD_CCX)&&CCXoutcharset(MIMEHEAD_CCX,&oc)){
		ocset = oc;
	    }else
	    if( io->out_charcode ){
		ocset = io->out_charcode;
	    }
	    if( MIMEHEAD_CCX == 0 && m17n_known ){
		m17n = m17n_ccx_new((const char*)charset,ocset,0,0);
	    }
	    if( m17n ){
		CStr(mtext,MAX_LNSIZE);
		m17n_ccx_string(m17n,(const char*)dtext,len,(char*)mtext,sizeof(mtext));
		strcpy(dtext,mtext);
		len = strlen(dtext);
	    }else
	    if( strcaseeq((char*)charset,"Shift_JIS")
	     || strcaseeq((char*)charset,"EUC-JP")
	     || strcaseeq((char*)charset,"ISO-2022-JP")
	     || strcaseeq((char*)charset,"UTF-8")
	    )
	    /* it should be coverted to the charset of message body */
	    {
		int ccx[16];
		/* the body encoding might be different from the head encoding.
		 * but the encoding is not known here, so use ISO-2022-JP
		 * because it can be uniquely identified from others.
		 */
		CCXcreate((char*)charset,ocset,(CCXP)ccx);
		len = CCXexec((CCXP)ccx,dtext,len,AVStr(dtext),sizeof(dtext));
		len += CCXexec((CCXP)ccx,"",0,TVStr(dtext),sizeof(dtext)-len);
	    }
	}

	if( io->CAT_EWORDS ) /* 9.9.9 new-140606b catenate e-words */
	if( io->UNFOLD_LINE || io->out_column+strlen(dtext) < XDISPCOLS )
	if( io->out_column == 0 ){
		/* v9.9.12 fix-140826b, don't erase pending space for continuation */
	}else
	if( strcaseeq((char*)encoding,ENCODE_BASE64) ) /* imply without-ASCII */
	if( noSpaceAmongWords(io->in_ewcharset,(char*)charset,dtext,ocset) )
	{
		syslog_DEBUG("#MIMEHEAD Catenate ewords [%s]-[%s]->[%s] %d\n",
			io->in_ewcharset,charset,ocset,
			io->out_column+strlen(dtext));
		DE_FPUTC(XC_DE_DEL_LWSP,io);
	}
	strcpy(io->in_ewcharset,(char*)charset);

	disp_word(io,dtext,len);
	return 0;
}

int bad_etext(PCStr(charset),PCStr(dtext),int len)
{	int ci,ch;

	if( strcasecmp(charset,M_ISO_2022_JP) == 0 ){
		for( ci = 0; ci < len; ci++ ){
			ch = dtext[ci];
			if( ch < 0x20 )
			if( ch != SPACE && ch != TAB && ch != ESC )
			if( ch != 0xE && ch != 0xF ) /* SO, SI */
				return 1;
		}
		if( FIX_2022(dtext,VStrNULL,"text/plain") )
			return 1;
	}
	return 0;
}

static void nodecode_word(INOUT *io,int ch)
{
	if( io->MIME_ENCODED ){
		/* if the next noencoded-word ends before DISPCOLS ...*/
		if( io->out_column < MAXCOL ){
			if( LWSP_CHAR(ch) ){
				/* avoid pushing spaces between e-words */
			}else	DE_FPUTC(XC_DE_UNFOLD,io);
		}else{
			/* the following is experimental */
			if( LWSP_CHAR(ch) ){
				DE_FPUTC(XC_DE_OFLUSH,io);
				if( MAXCOL <= io->out_column ){
					DE_FPUTC(NL,io);

/* this ch shuld be put if the next character is not LWSP_CHAR... (?) */
	DE_FPUTC(ch,io);
	return;
				}
			}
		}
	}
	DE_FPUTC(ch,io);
}

static int DE_FGETC(INOUT *io)
{	FILE *in;
	int ch;

	in = io->in_file;
	ch = NLfgetc(in);
	if( ch == FORMFEED ){
		ch = NLfgetc(in);
		if( ch == NL )
			ch = XC_DE_FORMFEED;
		else{
			if( ch != EOF )
				ungetc(ch,in);
			ch = FORMFEED;
		}
		io->MIME_ENCODED = 0;
	}else
	if( ch == NL ){
		ch = NLfgetc(in);
		if( !LWSP_CHAR(ch) )/* at the top of a filed */
			io->MIME_ENCODED = 0;

		if( ch == NL )
			ch = NLNL;
		else{
			if( ch != EOF )
				ungetc(ch,in);
			ch = NL;
		}
	}
	io->in_prevch = ch;
	return ch;
}
int MIME_headerDecodeX(MimeConv *Mcv,FILE *in,FILE *out,int bodytoo);
void MIME_headerDecode(FILE *in,FILE *out,int bodytoo)
{
	MIME_headerDecodeX(0,in,out,bodytoo);
}
int MIME_headerDecodeX(MimeConv *Mcv,FILE *in,FILE *out,int bodytoo)
{	int ch,prev_ch,next_ch;
	INOUT iob,*io = &iob;

	INOUT_init(io,in,out);
	io->UNFOLD_LINE = 1;
	if( Mcv ){
		io->in_ewicodemix = Mcv->c_ewicodemix;
		io->in_ewiccxeach = Mcv->c_ewiccxeach;
		io->out_charcode = Mcv->c_ocode; 
		io->out_noccx = Mcv->c_noccx;
	}

	for(;;){
		prev_ch = io->in_prevch;
		ch = DE_FGETC(io);
		if( ch == EOF )
			break;

		if( ch == ENCODE_BEGIN[0] ){
			ch = NLfgetc(in);
			if( ch == EOF )
				break;
			if( ch == ENCODE_BEGIN[1] ){
				if( decode_word(io) == EOF )
					break;
			}else{
				DE_FPUTC(ENCODE_BEGIN[0],io);
				ungetc(ch,in);
			}
		}else{
			if( ch == NLNL ){
				/* real fix for 1.8 problem */
				DE_FPUTC(XC_DE_OFLUSH,io); /* flush LWSP buf. */
				io->UNFOLD_LINE = 0;
				DE_FPUTC(NL,io);
				DE_FPUTC(NL,io);
				break;
			}

			if( prev_ch == NL )
			if( ch != NL && !LWSP_CHAR(ch) )
				DE_FPUTC(XC_DE_FIELD_TOP,io);

			nodecode_word(io,ch);
		}
	}
	io->UNFOLD_LINE = 0;
	if( ch != EOF && bodytoo )
		while( (ch = NLfgetc(in)) != EOF )
			DE_FPUTC(ch,io);
	DE_FPUTC(EOF,io);

	if( Mcv ){
		strcpy(Mcv->c_ewicode,io->in_ewcharset);
		Mcv->c_ewicodemix = io->in_ewicodemix;
	}
	return 0;
}

int MIME_strHeaderDecodeX(MimeConv *Mcv,PCStr(ins),PVStr(outs),int osize);
void MIME_strHeaderDecode(PCStr(ins),PVStr(outs),int osize)
{
	MIME_strHeaderDecodeX(0,ins,BVStr(outs),osize);
}
int MIME_strHeaderDecodeX(MimeConv *Mcv,PCStr(ins),PVStr(outs),int osize)
{	FILE *In,*Out;
	int oi;

	In = str_fopen((char*)ins,strlen(ins),"r");
	Out = str_fopen((char*)outs,osize,"w");
	/*
	MIME_headerDecode(In,Out,1);
	*/
	MIME_headerDecodeX(Mcv,In,Out,1);
	fflush(Out);
	for(oi = 0; outs[oi]; oi++)
		if((outs[oi] & 0xFF) == 0xFF)
			ovstrcpy((char*)&outs[oi],&outs[oi+1]);
	str_fclose(In);
	str_fclose(Out);
	return 0;
}
void MimeCodeconv(MimeConv *Mcv,PCStr(src),PVStr(dst),int dsz,PCStr(ctype),int repair);
int MIME_strHeaderEncodeX(MimeConv *Mcv,PCStr(ins),PVStr(outs),int osize);
void MIME_strHeaderEncode(PCStr(ins),PVStr(outs),int osize)
{
	MIME_strHeaderEncodeX(0,ins,BVStr(outs),osize);
}
int MIME_strHeaderEncodeX(MimeConv *Mcv,PCStr(ins),PVStr(outs),int osize)
{	FILE *In,*Out;

	int xsiz = 0;
	char *xout = 0;
	MimeConv dMcvb,*dMcv=&dMcvb;

	if( Mcv && Mcv->c_ocode && strstr(ins,"=?") ){
		bzero(dMcv,sizeof(MimeConv));
		xsiz = strlen(ins)*2+1;
		xout = (char*)malloc(xsiz);
		dMcv->c_noccx = 1;
		MIME_strHeaderDecodeX(dMcv,ins,BVStr(outs),osize);
		dMcv->c_noccx = 0;
		if( dMcv->c_ewicode[0] ){
			dMcv->c_icode = dMcv->c_ewicode;
		}else{
			dMcv->c_icode = Mcv->c_icode;
		}
		dMcv->c_ocode = Mcv->c_ocode;
		if( m17n_known_code(dMcv->c_icode)
		 && m17n_known_code(dMcv->c_ocode) ){
			dMcv->c_m17n = m17n_ccx_new(dMcv->c_icode,dMcv->c_ocode,0,0);
		}
		MimeCodeconv(dMcv,outs,ZVStr(xout,xsiz),xsiz,"text/plain",0);
		if( xout[0] == 0
		 || streq(xout,"?")
		 || strchr(xout,'\n')==0 && strchr(ins,'\n')!=0
		){
			/* code conversion error in M17N */
			free(xout);
			xout = 0;
		}else{
			ins = xout;
			*dMcv = *Mcv;
			dMcv->c_icode = Mcv->c_ocode;
			Mcv = dMcv;
		}
	}
	In = str_fopen((char*)ins,strlen(ins),"r");
	Out = str_fopen((char*)outs,osize,"w");
	/*
	MIME_headerEncode(In,Out);
	*/
	MIME_headerEncodeX(Mcv,In,Out);
	fflush(Out);
	str_fclose(In);
	str_fclose(Out);
	if( xout ){
		free(xout);
	}
	return 0;
}

int is_MIME_header(FILE *fp)
{	CStr(line,MAX_LNSIZE);
	int off;

	off = ftell(fp);
	while( fgets(line,sizeof(line),fp) != NULL ){
		if( *line == NL )
			break;
		if( *line == CR && line[1] == NL )
			break;

		if( strstr(line,ENCODE_BEGIN) ){
			fseek(fp,off,0);
			return 1;
		}
	}
	fseek(fp,off,0);
	return 0;
}

FILE *MIME_tmpHeaderDecode(FILE *fp,int bodytoo)
{	FILE *tfp;

	if( fp == NULL )
		return NULL;

	if( fseek(fp,0,1) == 0 ){
		if( !is_MIME_header(fp) )
			return NULL;
	}

	tfp = tmpfile();
	MIME_headerDecode(fp,tfp,bodytoo);
	fflush(tfp);
	fseek(tfp,0,0);
	return tfp;
}
FILE *MIME_tmpHeaderEncode(FILE *fp)
{	FILE *tin,*tfp;
	CStr(line,MAX_LNSIZE);
	int ch;

	if( fp == NULL )
		return NULL;
	tin = tmpfile();
	while( fgets(line,sizeof(line),fp) != NULL ){
		fputs(line,tin);
		if(strcmp(line,".\n")==0 || strcmp(line,".\r\n")==0)
			break;
	}
	fflush(tin);
	fseek(tin,0,0);

	tfp = tmpfile();
	ch = MIME_headerEncode0(tin,tfp);
	if( ch == NLNL ){
		fputs("\r\n",tfp);
		while( fgets(line,sizeof(line),tin) != NULL )
			fputs(line,tfp);
	}
	fputs(".\r\n",tfp);
	fflush(tfp);
	fseek(tfp,0,0);

	fclose(tin);
	return tfp;
}

/*/////////////////////////////////////////////////////////////////////#*/
int MIME_localStrColumns(PCStr(str))
{	INOUT iob,*io = &iob;
	FILE *sfp;
	int len;
	CHARx *CH;

	sfp = str_fopen((char*)str,strlen(str),"r");
	INOUT_init(io,sfp,NULL);

	len = 0;

	for(;;){
		CH = EN_FGETC(io);
		if( CH->c_ch == EOF ) 
			break;
		len++;
	}

	str_fclose(sfp);
	return len;
}
