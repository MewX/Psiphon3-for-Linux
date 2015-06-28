/*///////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2014 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	mime.c (MIME header encoder/decoder)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941008	extracted from nntp.c
	950312	encode/decode parts in a multipart message
//////////////////////////////////////////////////////////////////////#*/

#define DOFGSZ
#include "mime.h"
#ifdef MIMEKIT
#define strid_alloc(s)	stralloc(s)
#endif

static int encodeMIMEpart(const char *boundaries[],FILE*fc,FILE*ts,FILE*cache,int filter,int _);
static int decodeMIMEpart(const char *boundaries[],FILE*fs,FILE*tc,FILE*cache,int filter,int enHTML);

const char *MimeKit_Version = "1.8";

#define FN_CTE		"Content-Transfer-Encoding"
#define FN_CTE_C	"Content-Transfer-Encoding:"

#define C_HEAD		0x00FF
#define C_HEAD_EW	0x0001
#define C_HEAD_CHAR	0x0002
#define C_HEAD_JREPAIR	0x0004
#define C_HEAD_SPENC	0x0008 /* space encoding in encoded-word */

#define C_BODY		0xFF00
#define C_BODY_CTE	0x0100
#define C_BODY_CHAR	0x0200
#define C_MIME2PGP	0x1000

#define C_CHAR		(C_HEAD_CHAR | C_BODY_CHAR | C_HEAD_JREPAIR)

#define C_ALL		0xFFFFFFFF
#define C_DECODE(f)	(f)
#define C_ENCODE(f)	((f) << 16)

#ifndef MIMECONV
#define MIMECONV	C_DECODE(C_HEAD|C_BODY) | C_ENCODE(C_HEAD|C_BODY)
#endif
int MIME_CONV = MIMECONV;

#define DECODE(flag)	(MIME_CONV & flag)
#define ENCODE(flag)	(MIME_CONV & (flag<<16))

/*
static int maybe_MIME;
static int maybe_NONASCII;
static int got_EOR;
*/
static int addQY;

#define DEBUG	syslog_DEBUG

/*
#define O_HEAD	1
#define O_DELIM	2
#define O_BODY	4
#define O_EOR	8
#define O_ALL	0xF
#define O_MIME2PGP	0x100
#define O_TEXTONLY	0x200
#define O_MULTIPART	0x400
*/

#define O_ALT_FIRST	0x80000000 /* MIMECONV=alt:first specified */
#define O_FIRSTALT	0x40000000 /* under selecting a part in alt. */
#define O_ALT_UNFOLD	0x20000000 /* MIMECONV=alt:unfold specified */
#define O_PLAINALT	0x10000000 /* under unfolding all parts of alt. */
#define O_IN_MPALT	0x08000000
#define O_SKIP_ALTS	0x04000000
#define ALT_FIRST(filter)	(filter & O_ALT_FIRST)
#define FIRSTALT(filter)	(filter & O_FIRSTALT)
#define ALT_UNFOLD(filter)	(filter & O_ALT_UNFOLD)
#define PLAINALT(filter)	(filter & O_PLAINALT)
#define UNFOLDMP(filter)	(FIRSTALT(filter)||PLAINALT(filter))

#define HEAD_ALSO(filter)	(filter & O_HEAD)
#define DELIM_ALSO(filter)	(filter & O_DELIM)
#define BODY_ALSO(filter)	(filter & O_BODY)
#define EOR_ALSO(filter)	(filter & O_EOR)

int MIME_FILTER;

#define MIME2PGP(filter)	((filter& O_MIME2PGP) && (PGP_DECR()||PGP_VRFY()))
#define TEXTONLY(filter)	(filter & O_TEXTONLY)
#define MULTIPART(filter)	(filter & O_MULTIPART)

#define C_SIGNED		"multipart/signed"
#define C_ENCRYPTED		"multipart/encrypted"
#define C_PGPSIGN		"application/pgp-signature"
#define C_PGPENCR		"application/pgp-encrypted"

#define C_TEXT		"text/"
#define C_TEXT_PLAIN	"text/plain"
static int is_text_plain(PCStr(ctype))
{
	return strncasecmp(ctype,C_TEXT_PLAIN,strlen(C_TEXT_PLAIN))==0;
}
static int is_text(PCStr(ctype))
{
	return strncasecmp(ctype,C_TEXT,strlen(C_TEXT))==0;
}

static const char *textorso[] = {
	"application/x-unknown-content-type",
	0
};
static int tobe_charconv(PCStr(ctype))
{	int ci;
	const char *ctype1;

	if( is_text(ctype) )
		return 1;
	for( ci = 0; ctype1 = textorso[ci]; ci++ )
		if( strncasecmp(ctype,ctype1,strlen(ctype1)) == 0 )
			return 1;
	return 0;
}
static int is8bitCharset(PCStr(charset))
{
	if( strcaseeq(charset,"x-sjis") )
		return 1;
	if( strcaseeq(charset,"Shift_JIS") )
		return 1;
	if( strcaseeq(charset,"x-euc-jp") )
		return 1;
	if( strcaseeq(charset,"EUC-JP") )
		return 1;
	if( strcaseeq(charset,"utf-8") )
		return 1;
	return 0;
}

const char *MIME_transAddrSpec;
int MC_scanAnons(PCStr(smask));
int MC_setAnons(int mask);
extern const char *MIME_nomapMailAddrs;
static scanListFunc conv1(PCStr(spec))
{
	if( strneq(spec,"rewaddr:",8) ){
		CStr(list,128);
		int amask;
		MIME_CONV = C_ENCODE(C_HEAD|C_BODY) | C_DECODE(C_HEAD|C_BODY);
		wordScanY(spec+8,list,"^:");
		amask = MC_scanAnons(list);
		MC_setAnons(amask);
		MIME_transAddrSpec = strid_alloc(spec+8);
	}else
	if( strneq(spec,"nomapemail:",11) ){
		MIME_nomapMailAddrs = strid_alloc(spec+11);
	}else
	if( streq(spec,"thru")) MIME_CONV = 0; else
	if( streq(spec,"all" )) MIME_CONV = C_ALL; else
	if( streq(spec,"enc" )) MIME_CONV |= C_ENCODE(C_HEAD|C_BODY); else 
	if( streq(spec,"dec" )) MIME_CONV |= C_DECODE(C_HEAD|C_BODY); else 
	if( streq(spec,"qy") )	addQY = 1; else
	if( streq(spec,"nospenc") )
				MIME_CONV &= ~C_ENCODE(C_HEAD_SPENC); else
	if( streq(spec,"charcode") )
				MIME_CONV = C_DECODE(C_CHAR)|C_ENCODE(C_CHAR);
	else
	if( streq(spec,"zero:none") ){
		FGSZ_flags = FGSZ_NONE;
	}else
	if( streq(spec,"zero:utf8") ){
		FGSZ_flags = FGSZ_UTF8;
	}else
	if( streq(spec,"zero:kill") ){
		FGSZ_flags = FGSZ_KILL;
	}
	else
	if( streq(spec,"textonly") ){
		MIME_FILTER |= O_TEXTONLY;
	}
	else
	if( strcaseeq(spec,"alt:first") ){
		MIME_FILTER |= O_ALT_FIRST;
	}
	else
	if( strcaseeq(spec,"alt:unfold") ){
		MIME_FILTER |= O_ALT_UNFOLD;
	}
	else	syslog_ERROR("#### ERROR: unknown MIMECONV=%s\n",spec);
	return 0;
}
extern int MIME_SPACE_ENCODING;
#define HM_TOMAIL "Date,Subject,From,Cc,Reply-To,X-Seqno,Organization,Xref,Newsgroups,Distribution,Message-ID,References,In-Reply-To,Lines,Content-Type,Content-Transfer-Encoding,MIME-Version,X-Mailer,X-From-Fp"
const char *MIME_headMask;
const char *setHeadMask(PCStr(hmask)){
	const char *ohm;
	ohm = MIME_headMask;
	if( hmask && streq(hmask,"") )
		MIME_headMask = HM_TOMAIL;
	else	MIME_headMask = hmask;
	return ohm;
}

void scan_MIMECONV(PCStr(convspec))
{
	if( strneq(convspec,"headmask:",9) ){
		if( streq(convspec+9,"-ng2ml") )
			MIME_headMask = HM_TOMAIL;
		else	MIME_headMask = stralloc(convspec+9);
		return;
	}
	if( *convspec == 0 )
		MIME_CONV = C_ENCODE(C_HEAD|C_BODY) | C_DECODE(C_HEAD|C_BODY);
	else	scan_commaList(convspec,0,scanListCall conv1);
	if( (MIME_CONV & C_ENCODE(C_HEAD_SPENC)) == 0 )
		MIME_SPACE_ENCODING = 0;
}

int MC_MASK;

int MC_scanMasks(PCStr(smask)){
	int imask = 0;
	if( isinList(smask,"_GECOS") )     imask |= MM_FROM;
	if( isinList(smask,"_Body") )      imask |= MM_BODY;
	if( isinList(smask,"_Signature") ) imask |= MM_SIGN;
	return imask;
}
int MC_setMasks(int mask){
	int omask;
	omask = MC_MASK;
	MC_MASK = (MC_MASK & 0xFFFF0000) | mask;
	return omask;
}
int MC_getMasks(){
	return MC_MASK & 0xFFFF;
}
int MC_scanAnons(PCStr(smask)){
	int imask = 0;
	if( streq(smask,"*") )
		smask = "_Poster,_MessageID,_Email,_Phone";
	if( isinList(smask,"Body") )	   imask |= MA_EMAIL;
	if( isinList(smask,"_Poster") )    imask |= MA_FROM;
	if( isinList(smask,"_MessageID") ) imask |= MA_MSGID;
	if( isinList(smask,"_Email") )	   imask |= MA_EMAIL;
	if( isinList(smask,"_Phone") )	   imask |= MA_PHONE;
	return imask;
}
int MC_setAnons(int mask){
	int omask;
	omask = MC_MASK;
	MC_MASK = (mask << 16) | (MC_MASK & 0xFFFF);
	return omask;
}
int MC_getAnons(){
	return (MC_MASK >> 16) & 0xFFFF;
}
static scanListFunc filt1(PCStr(l1),PVStr(lp),int *off){
	if( strcaseeq(l1,"_Poster") ) return 0;
	if( strcaseeq(l1,"_MessageID") ) return 0;
	if( strcaseeq(l1,"_Email") ) return 0;
	if( strcaseeq(l1,"_Phone") ) return 0;
	if( *off ){
		Xstrcat(DVStr(lp,*off),",");
		*off += 1;
	}
	Xstrcat(DVStr(lp,*off),l1);
	*off += strlen(l1);
	return 0;
}
void MIME_anon2list(int mask,PVStr(list)){
	int m1;
	const char *sm1;
	CStr(xlist,1024);
	refQStr(lp,xlist);
	int off = 0;

	truncVStr(xlist);
	scan_commaListL(list,0,scanListCall filt1,AVStr(xlist),&off);
	lp = xlist + strlen(xlist);

	for( m1 = 1; m1; m1 = m1 << 1 ){
		if( (m1 & mask) == 0 )
			continue;
		switch( m1 ){
			case MA_FROM:  sm1 = "_Poster"; break;
			case MA_MSGID: sm1 = "_MessageID"; break;
			case MA_EMAIL: sm1 = "_Email"; break;
			case MA_PHONE: sm1 = "_Phone"; break;
			default: continue;
		}
		if( xlist < lp ){
			sprintf(lp,",%s",sm1);
		}else{
			sprintf(lp,"%s",sm1);
		}
		lp += strlen(lp);
	}
	if( strcmp(list,xlist) != 0 ){
		strcpy(list,xlist);
	}
}
extern int (*MIME_setPosterMasks)(PCStr(from));
static char OrigFrom[256];
int MIME_disableTransHead;


int MIME_rewriteAddr(PVStr(buf),int inHead){
	int anons = MC_getAnons();
/*
CStr(sb,1024); strcpy(sb,buf);
*/
/*
if(strchr(buf,'@')) fprintf(stderr,"---H=%d U=%X [%s] %s",
inHead,anons,
MIME_transAddrSpec?MIME_transAddrSpec:"NULL",buf);
*/

	if( anons & MA_FROM )
	if( MIME_setPosterMasks && inHead ){
		if( strncaseeq(buf,"From:",5) ){
			CStr(Fb,1024);
			RFC822_addresspartX(buf+5,AVStr(Fb),sizeof(Fb));
			(*MIME_setPosterMasks)(Fb);
			Xstrcpy(FVStr(OrigFrom),Fb);
/*
 fprintf(stderr,"#### OrigFrom [%d] #### [%s]\n",getpid(),OrigFrom);
*/
		}
	}
	if( MIME_disableTransHead ){
		return 0;
	}

	if( MIME_transAddrSpec ){
		if( inHead ){
			MIME_rewriteHeader("",MIME_transAddrSpec,AVStr(buf),NULL);
/*
if(strcmp(buf,sb)) fprintf(stderr,"#tH %X %X %s",MC_getAnons(),MC_MASK,buf);
*/
		}else{
			const char *dp;
			if( dp = strchr(MIME_transAddrSpec,':') ){
				if( anons )
				scanAddrInBody(anons,dp+1,AVStr(buf));
			}
/*
if(strcmp(buf,sb)) fprintf(stderr,"#tB %X %X %s",MC_getAnons(),MC_MASK,buf);
*/
		}
	}
	return 0;
}
static int maskFrom(PVStr(head)){
	CStr(from,256);
	if( strncaseeq(head,"From:",5) ){
		RFC822_addresspartX(head+5,AVStr(from),sizeof(from));
		sprintf(head,"From: %s (((Masked-From)))\r\n",from);
		return 1;
	}
	return 0;
}
static int maskBody(PVStr(tmpa)){
	const char *t0;
	refQStr(tp,tmpa); /* before signature */
	char tc;

	if( MC_MASK_BODY ){
		strcpy(tmpa,"(((Masked-Body)))\r\n");
		return 1;
	}else
	if( MC_MASK_SIGNATURE ){
		t0 = tmpa + 4;
		tp = tmpa+strlen(tmpa)-1;
		tc = 0;
		for(; t0 < tp; tp-- ){
			tc = *tp;
			if( tc!=' ' && tc!='\t' && tc!='\r' && tc!='\n' )
				break;
		}
		for(; t0 < tp; tp-- ){
			if( strneq(tp-4,"\r\n\r\n",4) ){
				goto MASKBODY;
			}
			if( strneq(tp-2,"\n\n",2) ){
				goto MASKBODY;
			}
			if( strneq(tp-4,"\n--\r",4)||strneq(tp-4,"\n--\n",4) ){
				tp -= 3;
				goto MASKBODY;
			}
		}
	}
	return 0;
MASKBODY:
	strcpy(tp,"(((Masked-Signature)))\r\n");
	return 1;
}

static int xfputs(PCStr(wh),PCStr(buf),FILE *out){
	int fcode;
	fcode = fputs(buf,out);
	if( fcode == EOF ){
		syslog_ERROR("--MIME EOF on %s [%d/%X]\n",wh,fileno(out),p2i(out));
	}
	return fcode;
}
static char *fgetsTee(PVStr(buf),int size,FILE *in,FILE *out,FILE *cache,int inHead)
{	const char *rcode;

	setVStrEnd(buf,0);
	if( MIME_transAddrSpec ){
		/* 9.9.1 might be expanded in rewriteAddr() */
		size = (size * 7) / 8;
	}
	if( inHead )
		rcode = RFC822_fgetsHeaderField(BVStr(buf),size,in);
	else	rcode = fgets(buf,size,in);
	if( rcode ){
		if( !isEOR(buf) ){
			if( cache != NULL )
				fputs(buf,cache);
			MIME_rewriteAddr(BVStr(buf),inHead);
			if( out != NULL )
			{
				/*
				fputs(buf,out);
				*/
				if( xfputs("fgetsTee",buf,out) == EOF ){
					rcode = NULL;
				}
			}
		}
	}
	return (char*)rcode;
}
#define MP_EOF	-1	/* real EOF */
#define MP_EOR	-2	/* .<CR><LF> */
#define MP_EOP	-3	/* --boundary-- */
#define MP_EOC	-4	/* --boundary */

static void scan_boundary(PCStr(hp),PVStr(boundary),int size)
{	const char *bp;

	if( bp = strcasestr(hp,"boundary=") ){
		bp += strlen("boundary=");
		valuescanX(bp,AVStr(boundary),size);
	}
}
#define MAXDEPTH 32
static int push_boundary(const char *boundaries[],PCStr(boundary))
{	int bi;

	for( bi = 0; boundaries[bi]; bi++);
	if( MAXDEPTH-1 <= bi ){
		syslog_ERROR("## MIME FATAL: too deep boundrary (>%d)\n",bi);
		return bi-1;
	}
	boundaries[bi] = stralloc(boundary);
	boundaries[bi+1] = 0;
	return bi;
}
static int top_boundary(const char *boundaries[])
{	int bi;
	for( bi = 0; boundaries[bi]; bi++);
	return bi;
}
static int pop_boundary(const char *boundaries[],PCStr(line))
{	int blen,bi;
	const char *b1;
	const char *tp;

	if( line[0] == '-' && line[1] == '-' ){
		for( bi = 0; b1 = boundaries[bi]; bi++ ){
			/*
			blen = strlen(b1);
			if( strncmp(line+2,b1,blen) == 0 ){
				tp = &line[2+blen];
			*/
			if( tp = strheadstrX(line+2,b1,0) ){
				if( tp[0]=='-' && tp[1]=='-' ){
					free((char*)b1);
					boundaries[bi] = 0;
					return MP_EOP;
				}else
				if( strchr(" \t\r\n",*tp) )
					return MP_EOC;
			}
		}
	}
	if( isEOR(line) )
		return MP_EOR;
	return 0;
}

static const char *guess_charset(PCStr(text))
{	const char *sw;

	if( sw = strstr(text,"\033$") )
		if( sw[2] == '@' || sw[2] == 'B' )
			return "ISO-2022-JP";
	if( sw = strstr(text,"\033(") )
		if( sw[2] == 'J' )
			return "ISO-2022-JP";
	return 0;
}
#define BASE64CH(ch) (isalpha(ch) || isdigit(ch) || ch=='+' || ch=='/' || ch=='=' )

void str_from64_safe(PCStr(src),int leng,PVStr(dst),int size)
{	char ch;
	int sx,dx,Bx,cx,isB64,ls,ld,lb;
	const char *sp;

	Bx = -1;
	dx = 0;

	for( sx = 0; sx < leng; sx = cx ){
		isB64 = 1;
		for( cx = sx; cx < leng; ){
			ch = src[cx++];
			if( ch=='\n' || ch==0 )
				break;
			if( !BASE64CH(ch) && ch!='\r' && ch!=0 )
				isB64 = 0;
		}
		if( isB64 ){
			if( Bx == -1 )
				Bx = sx;
		}else{
			if( Bx != -1 ){
				lb = sx - Bx;
/* str_from64() before mimehead1.2.4 writes NULL at end of source string ... */
sp = src; /* not read-only but "const" */
ch = ((char*)sp)[Bx+lb];
				str_from64(&src[Bx],lb,QVStr(&dst[dx],dst),size);
((char*)sp)[Bx+lb] = ch; /**/
				Bx = -1;
				ld = strlen(&dst[dx]);
				dx += ld;
				size -= ld;
			}
			ls = cx - sx;
			Xstrncpy(DVStr(dst,dx),&src[sx],ls);
			dx += ls;
			setVStrEnd(dst,dx);
			size -= ls;
		}
	}
	if( Bx != -1 )
		str_from64(&src[Bx],leng-Bx,QVStr(&dst[dx],dst),size);
}

typedef void (*convFunc)(const char*,int,PVStr(s),int);
static int decodeLine(PCStr(line),PVStr(dline),PCStr(encoding))
{	convFunc conv;
	int len;

	if( strcasecmp(encoding,"quoted-printable") == 0 )
		conv = (convFunc)str_fromqp;
	else
	if( strcasecmp(encoding,"base64") == 0 )
		conv = str_from64_safe;
	else	return 0;

	len = strlen(line);
	(*conv)(line,len,AVStr(dline),len+1);

	{ /* bug of str_fromqp ? */
	unsigned char *sp; /**/
	for( sp = (unsigned char*)dline; *sp; sp++ )
		if( *sp == 0xFF )
			ovstrcpy((char*)sp,(char*)sp+1);
	}

	return 1;
}

static void scan_charset(PCStr(header),PVStr(chset),int len);
static void scan_ctype(PCStr(fvalue),PVStr(ctype),PVStr(ichset),PVStr(boundary),int bsize)
{	const char *dp;

	if( ctype[0] == 0 ){
		wordscanX(fvalue,AVStr(ctype),128);
		if( dp = strchr(ctype,';') )
			truncVStr(dp);
	}
	scan_charset(fvalue,AVStr(ichset),64);
	if( strncasecmp(ctype,"multipart/",10) == 0 )
		scan_boundary(fvalue,AVStr(boundary),bsize);
}

extern int (*MIME_makeAdminKey)(PCStr(from),PVStr(key),int siz);
static int readHeader(MimeConv *Mcv,FILE *fs,PVStr(buf),int size,FILE *cache,int filter,PVStr(ctype),PVStr(ichset),const char *boundaries[],PVStr(encoding),int enHTML)
{	refQStr(hp,buf); /**/
	const char *hs;
	char hc;
	int rem,len;
	CStr(cur_field,256);
	int conv_field;
	CStr(boundary,256);
	CStr(tmp,LINESIZE);
	int skipping = 0;

	maybe_MIME = 0;
	maybe_NONASCII = 0;
	got_EOR = 0;
	setVStrEnd(ctype,0);
	setVStrEnd(ichset,0);
	setVStrEnd(boundary,0);
	setVStrEnd(encoding,0);

	setVStrEnd(buf,0);
	conv_field = 0;
	cur_field[0] = 0;
	OrigFrom[0] = 0;

	for( rem = size; LINESIZE < rem; ){
		if( fgetsTee(AVStr(hp),LINESIZE,fs,NULL,cache,1) == NULL )
			break;
		if( got_EOR = isEOR(hp) ){
			if( !EOR_ALSO(filter) )
				setVStrEnd(hp,0);
			break;
		}
		if( isEOH(hp) ){
			if( !DELIM_ALSO(filter) )
				setVStrEnd(hp,0);
			break;
		}

		if( hp[0] == ' ' || hp[0] == '\t' ){
			if( strcasecmp(cur_field,"Content-Type") == 0 ){
				scan_ctype(hp+1,AVStr(ctype),AVStr(ichset),
					AVStr(boundary),sizeof(boundary));
			}
			if( skipping )
				continue;
		}else{
			if( MC_MASK_FROM ){
				maskFrom(AVStr(hp));
			}
			if( MIME_headMask ){
				CStr(fnam,64);
				wordScanY(hp,fnam,"^:");
				if( !isinListX(MIME_headMask,fnam,"wc") ){
					skipping = 1;
					continue;
				}
				
			}
			skipping = 0;

			/*
			wordscanY(hp,AVStr(cur_field),sizeof(cur_field),"^: \t\r\n");
			*/
			wordscanY(hp,AVStr(cur_field),sizeof(cur_field),"^: \300\t\r\n");
			conv_field = strncasecmp(hp,"Subject:",8) == 0
				  || strncasecmp(hp,"From:",5) == 0;

			if( strncasecmp(hp,"Content-Type:",13) == 0 ){
				scan_ctype(hp+13,AVStr(ctype),AVStr(ichset),
					AVStr(boundary),sizeof(boundary));
			}else
			if( strncasecmp(hp,FN_CTE_C,26)==0 )
				wordscanX(hp+26,AVStr(encoding),128);
			else
			if( strncasecmp(hp,"Date:",5) == 0 )
				canon_date(QVStr(hp+5,buf));
		}

		if( enHTML && conv_field ){
			encode_entitiesX(hp,AVStr(tmp),sizeof(tmp));
			strcpy(hp,tmp);
		}

		for(hs = buf; hc = *hs; hs++ ){
			if( hc == '=' && hs[1] == '?' )
			{
				maybe_MIME = 1;
				if( maybe_NONASCII == 0 ){
					maybe_NONASCII = 2;
				}
			}
			if( hc == 033 || hc & 0x80 )
				maybe_NONASCII = 1;
			if( hc == '$' && (hs[1] == 'B' || hs[1] == '@') )
				maybe_NONASCII = 1;
			if( hc == '(' && (hs[1] == 'B' || hs[1] == 'J') )
				maybe_NONASCII = 1;
		}
		len = strlen(hp);
		rem -= len;
		hp += len;
	}

	if( OrigFrom[0] && MIME_makeAdminKey ){
		CStr(eline,128);
		CStr(key,128);
		(*MIME_makeAdminKey)(OrigFrom,AVStr(key),sizeof(key));
		strcpy(eline,hp);
		sprintf(hp,"X-From-Fp: %s\r\n",key+16);
/*
 fprintf(stderr,"***** ##### %X %s [%s][%s]\n",MC_MASK,hp,OrigFrom,key);
*/
		len = strlen(hp);
		hp += len;
		rem -= len;
		strcpy(hp,eline);
		rem -= strlen(hp);
	}

	if( boundary[0] )
		push_boundary(boundaries,boundary);
	if( ctype[0] == 0 )
		strcpy(ctype,C_TEXT_PLAIN);
	return rem;
}
int relayHeader(FILE *fs,FILE *tc,PCStr(mask),PVStr(buf),int siz){
	int rem;
	const char *boundaries[1];
	CStr(cty,128);
	CStr(ics,128);
	CStr(enc,128);
	const char *omask;
	MimeConv Mcvb,*Mcv = &Mcvb;

	boundaries[0] = 0;
	omask = setHeadMask(mask);
	bzero(Mcv,sizeof(MimeConv));
	rem = readHeader(Mcv,fs,BVStr(buf),siz,tc,0,AVStr(cty),AVStr(ics),boundaries,AVStr(enc),0);
	setHeadMask(omask);
	return rem;
}

typedef int (*encdecFunc)(const char*[],FILE*,FILE*,FILE*,int,int);

static int fpeekch(FILE *fp){
	int ch;
	ch = getc(fp);
	ungetc(ch,fp);
	return ch;
}
static
int scan_multipart(const char *boundaries[],PVStr(endline),int size,encdecFunc func,FILE*src,FILE*dst,FILE*cache,int filter,int arg)
{	CStr(line,LINESIZE);
	int rcode;
	int top;
	int np;

	/* preamble */
	while( fgetsTee(AVStr(line),size,src,NULL,cache,0) != NULL ){
		if( !MIME2PGP(filter) )
		if( !TEXTONLY(filter) )
		if( UNFOLDMP(filter) ){
			/* skip the preamble of alt. part */
		}else
		fputs(line,dst);
		if( rcode = pop_boundary(boundaries,line) )
			break;
	}

	top = top_boundary(boundaries);

	for( np = 0; ; np++ ){
		if( feof(src) )
			rcode = MP_EOF;
		if( rcode != MP_EOF && ferror(dst) )
			rcode = MP_EOF;
		if( rcode==MP_EOF || rcode==MP_EOR || rcode==MP_EOP )
			break;
		if( top != top_boundary(boundaries) )
			break;
		if( PLAINALT(filter) && 0 < np ){
			if( 1 < top ){
				fprintf(dst,"--%s\r\n",boundaries[top-2]);
			}else{
				fprintf(dst,"--- --- --- ---\r\n");
			}
		}
		rcode = (*func)(boundaries,src,dst,cache,filter,arg);
		if( FIRSTALT(filter) ){
			/* skip other alternatives of alt. */
			/* only if the part is of text/* ? */
			dst = NULLFP();
		}
	}

	/*
	 * ``endline'' must return the closing line of the part,
	 * which must be empty in case of MP_EOR because it has been
	 * output already at (*func)(),  or it has really empty
	 * in case of MP_EOF, or ... ??
	 */
	setVStrEnd(endline,0);

	/* epilogue */
	if( rcode == MP_EOP ){
		for(;;){
			if( fgetsTee(AVStr(endline),size,src,NULL,cache,0) == NULL ){
				rcode = MP_EOF;
				break;
			}
			if( isEOR(endline) ){
				rcode = MP_EOR;
				break;
			}
			if( UNFOLDMP(filter) ){
				/* skip alt. epilogue to the next part CRLF-- */
				if( isEOH(endline) && fpeekch(src) == '-' ){
					break;
				}
			}else
			if( !TEXTONLY(filter) )
			if( !MIME2PGP(filter) )
			{
				/*
				fputs(endline,dst);
				*/
				if( xfputs("scan_mp",endline,dst) == EOF ){
					rcode = MP_EOF;
					break;
				}
			}
		}
	}
	return rcode;
}

static char *readPart(FILE*src,FILE*dst,FILE*cache,int filter,const char *boundaries[],PVStr(line),int *codep,int *lengp)
{	int rcode;
	int leng,len1,reqsize;
	CStr(buff,0x10000);
	refQStr(bp,buff);
	const char *bx = &buff[sizeof(buff)-256];
	FILE *bfile;
	FILE *odst = 0;

	rcode = 0;
	leng = 0;
	buff[0] = 0;
	bfile = NULL;

/*
 fprintf(stderr,"#### readPart %X [%s]\n",MC_MASK,
 MIME_transAddrSpec?MIME_transAddrSpec:"NONE");
*/

	if( TEXTONLY(filter) ){
		/* to skip ending boundary */
		odst = dst;
		dst = 0;
	}

	if( TEXTONLY(filter) )
	if( odst == 0 && cache == 0 && (filter & O_BODY_CTE) == 0 ){
	  /* 9.6.2 it's too heavy to copy large data line by line.
	   */
	  for(;;){
		if( rawfgets((char*)bp,sizeof(buff)-(bp-buff),src) == NULL ){
			rcode = MP_EOF;
			break;
		}
		len1 = strlen(bp);
		if( rcode = pop_boundary(boundaries,bp) ){
			truncVStr(bp);
			break;
		}
		leng += len1;
		if( filter & O_BODY_GET ){
			bp += len1;
			if( bx < bp ){
				/* should switch to normal input ? */
				bp = (char*)bx;
			}
		}
	  }
	  *lengp = leng;
	  *codep = rcode;
	  return stralloc(buff);
	}
	for(;;){
		setVStrEnd(line,0);
		if( fgetsTee(BVStr(line),LINESIZE,src,dst,cache,0) == NULL ){
			/*DEBUG("GotEOF: length=%d\n",leng);*/
			rcode = MP_EOF;
			break;
		}
		len1 = strlen(line);
		reqsize = leng + len1 + 1;

		if( rcode = pop_boundary(boundaries,line) )
			break;

		if( odst ){
			fputs(line,odst);
		}
		if( bfile == NULL && sizeof(buff) <= reqsize ){
			bfile = TMPFILE("readPart");
			fputs(buff,bfile);
		}
		if( bfile )
			fputs(line,bfile);
		else	Xstrcpy(DVStr(buff,leng),line);
		leng += len1;
	}
	*lengp = leng;
	*codep = rcode;
	if( bfile ){
		const char *tmp;
		DEBUG("### readPart: got large message (%d)\n",leng);
		fflush(bfile);
		fseek(bfile,0,0);
		tmp = (char*)malloc(leng+1);
		IGNRETP fread((char*)tmp,1,leng,bfile);
		((char*)tmp)[leng] = 0;
		fclose(bfile);
		return (char*)tmp;
	}else{
		return stralloc(buff);
	}
}

void MimeCodeconv(MimeConv *Mcv,PCStr(src),PVStr(dst),int dsz,PCStr(ctype),int repair){
	const char *icode;
	const char *ocode;
	int ccx[32];
	M17N m17n;

	if( Mcv && (icode = Mcv->c_icode) && (ocode = Mcv->c_ocode) ){
		if( m17n = Mcv->c_m17n ){
			m17n_ccx_string(m17n,src,strlen(src),(char*)dst,dsz);
		}else{
			if( strcaseeq(icode,"ISO-2022-JP") )
				icode = "*";
			CCXcreate((char*)icode,ocode,(CCXP)ccx);
			CCXexec((CCXP)ccx,src,strlen(src),AVStr(dst),dsz);
		}
	}else{
		codeconv_line(src,BVStr(dst),ctype,repair);
	}
}

#define JBSIZE(leng)	(leng*2+128)

static void scan_charset(PCStr(header),PVStr(chset),int len)
{	const char *cp;

	if( cp = strcasestr(header,"charset=") )
		valuescanX(cp+8,AVStr(chset),len);
}
static CCXP MIME_CCX = NULL;
static void external_charcode(MimeConv *Mcv,PCStr(src),PVStr(dst),int dlen,PCStr(ichset))
{	int ccx[32];

	if( Mcv && Mcv->c_icode && Mcv->c_ocode ){
		MimeCodeconv(Mcv,src,BVStr(dst),dlen,"text/plain",0);
		return;
	}
	if( strcaseeq(ichset,"ISO-2022-JP") )
		ichset = "*";
	CCXcreate((char*)ichset,"ISO-2022-JP",(CCXP)ccx);
	CCXexec((CCXP)ccx,src,strlen(src),AVStr(dst),dlen);
}
static void external_charcodeB(MimeConv *Mcv,PCStr(src),PVStr(dst),int dlen,PCStr(ichset)){
	if( MIME_CCX ){
		CCXexec((CCXP)MIME_CCX,src,strlen(src),BVStr(dst),dlen);
		CCXexec((CCXP)MIME_CCX,"",0,TVStr(dst),dlen-strlen(dst));
	}else{
		external_charcode(Mcv,src,BVStr(dst),dlen,ichset);
	}
}

static int encodeBODYpart(MimeConv *Mcv,FILE *fc,FILE *ts,PCStr(ctype),PCStr(ichset),int filter,const char *boundaries[],PCStr(encoding),const char **charsetp)
{
	CStr(endline,LINESIZE);
	const char *charset = 0;
	int rcode,leng;
	const char *tmpa;
	defQStr(tmpb); /*alloc*/
	defQStr(tmpc); /*alloc*/

	tmpa = readPart(fc,NULL,NULL,filter,boundaries,AVStr(endline),&rcode,&leng);
	setQStr(tmpb,(char*)malloc(JBSIZE(leng)),JBSIZE(leng));
	setQStr(tmpc,(char*)malloc(JBSIZE(leng)),JBSIZE(leng));

DEBUG("BODY-LENG1:%d+%d\n",istrlen(tmpa),istrlen(endline));

	if( !ENCODE(C_BODY_CHAR) ){
		strcpy(tmpc,tmpa);
		goto OUTx;
	}

	/* Decode C-T-E, convert charset, then identify charset.
	 * If the result charset is the one which can be
	 * transferred in "C-T-E: 7bit" (ISO-2022-JP in the current
	 * implementation) C-T-E will be replaced with "7bit".
	 * Otherwise the body is passed through as is.
	 */
	if( !decodeLine(tmpa,AVStr(tmpb),encoding) )
		strcpy(tmpb,tmpa);

	if( ENCODE(C_BODY_CHAR) )
		/*
		external_charcode(tmpb,AVStr(tmpc),JBSIZE(leng),ichset);
		*/
		external_charcodeB(Mcv,tmpb,AVStr(tmpc),JBSIZE(leng),ichset);
		if( Mcv->c_ocode ){
			charset = Mcv->c_ocode;
		}
	else	strcpy(tmpc,tmpb);
	if( Mcv ){
		const char *sp;
		for( sp = tmpc; *sp; sp++ ){
			if( *sp & 0x80 ){
				Mcv->c_8bits = 1;
				break;
			}
		}
	}
	if( charset == 0 ){
		if( charset = guess_charset(tmpc) )
			DEBUG("encodeBDOY[charset=%s]\n",charset);
		else
		if( MIME_CCX && CCXactive(MIME_CCX) ){
			const char *xcs;
			if( CCXoutcharset(MIME_CCX,&xcs) ){
				syslog_ERROR("#encodeBODY[charset=%s]\n",xcs);
				charset = xcs;
			}
		}
	}
	if( charset == NULL ) /* charset cannot be in "C-T-E: 7bit" */
		strcpy(tmpc,tmpa);
OUTx:
/*
	if( strcmp(tmpb,tmpc) == 0 )
		fputs(tmpa,ts);
	else	fputs(tmpc,ts);
*/
	if( tmpc[0] ){
		fputs(tmpc,ts);
		if( *strtail(tmpc) != '\n' )
			fputs("\r\n",ts);
	}

	if( UNFOLDMP(filter) && endline[0] == '-' ){
		/* skip the ending boundary line of alt. */
	}else
	if( !TEXTONLY(filter) )
	fputs(endline,ts);
	free((char*)tmpa);
	free((char*)tmpb);
	free((char*)tmpc);

	*charsetp = (char*)charset;
	return rcode;
}
int relayBODYpart(FILE *src,FILE *dst,const char *boundaries[],int extract,PVStr(endline))
{	const char *tmpa;
	const char *ep;
	int rcode,leng;

	tmpa = readPart(src,NULL,NULL,0,boundaries,AVStr(endline),&rcode,&leng);
	if( tmpa[0] && extract ){
		ep = &tmpa[strlen(tmpa)-1];
		if( *ep == '\n' ){
			truncVStr(ep);
			if( tmpa <= --ep && *ep == '\r' )
				truncVStr(ep);
		}
	}
	fputs(tmpa,dst);
	free((char*)tmpa);
	return rcode;
}

static int decodeBODYpart(MimeConv *Mcv,FILE *fs,FILE *tc,FILE *cache,PCStr(ctype),const char *boundaries[],int filter,PCStr(encoding),PCStr(decodeto),int do_enHTML,PVStr(endline))
{	int rcode,leng;
	defQStr(tmpa); /*alloc*/
	defQStr(tmpb); /*alloc*/
	int tsiz;
	int do_conv,plain2html;
	const char *xcharset;
	int len,elen;
	const char *eol = NULL;
	const char *beol = NULL;
	FILE *out_thru;

	do_conv = codeconv_get(ctype,&xcharset,&plain2html);

	setVStrEnd(endline,0);
	if( TEXTONLY(filter) ){
		out_thru = NULL;
		syslog_DEBUG("-- decodeBODYpart[%s] [%s]decodeto[%s]\n",
			ctype,encoding?encoding:"",decodeto?decodeto:"");
		if( strheadstrX(ctype,"text/",1) ){
			if( encoding
			 && !streq(encoding,"7bits")
			 && !streq(encoding,"8bit") ){
				if( decodeto == NULL || *decodeto == 0 ){
					decodeto = "8bit";
				}
				filter |= O_BODY_CTE;
			}else{
				filter |= O_BODY_GET;
			}
		}
	}else
	if( MC_MASK_SIGNATURE || MC_MASK_BODY ){
		out_thru = NULL;
	}else
	if( DECODE(C_BODY) == 0 )
		out_thru = tc;
	else	out_thru = NULL;
	tmpa = readPart(fs,out_thru,cache,filter,boundaries,AVStr(endline),&rcode,&leng);
	if( tmpa == NULL )
		return -1;
	if( leng == 0 )
	{
		if( out_thru && rcode != MP_EOR ){
			/* it is put already */
			truncVStr(endline);
		}
		goto EXIT;
	}

	/* guess the end-of-line character(string) of the message ... */
	if( beol = strpbrk(tmpa,"\r\n") ){
		if( *beol == '\r' )
			beol = "\r\n";
		else	beol = "\n";
	}
	if( out_thru ){
		/* message body was already relayed thru ... */
		/* end of body line (except EOR) was already put too */
		if( rcode != MP_EOR )
			setVStrEnd(endline,0);
		goto PUTEOL;
	}

	if( plain2html ){
		tsiz = leng * 10;
	}else{
		tsiz = JBSIZE(leng);
	}
	setQStr(tmpa,(char*)realloc((char*)tmpa,tsiz),tsiz);
	setQStr(tmpb,(char*)malloc(tsiz),tsiz);

	/*
	if( DECODE(C_BODY_CTE) && encoding != NULL && decodeto != NULL ){
	*/
	if( DECODE(C_BODY_CTE) || TEXTONLY(filter) )
	if( encoding != NULL && decodeto != NULL ){
		DEBUG("decode: %s -> %s\n",encoding,decodeto);
		if( decodeLine(tmpa,AVStr(tmpb),encoding) )
			strcpy(tmpa,tmpb);
	}
	if( DECODE(C_BODY_CHAR) && do_conv ){
		/*
		codeconv_line(tmpa,AVStr(tmpb),ctype,0);
		*/
		MimeCodeconv(Mcv,tmpa,AVStr(tmpb),tsiz,ctype,0);
		strcpy(tmpa,tmpb);
	}
	if( do_enHTML ){
		encode_entitiesX(tmpa,AVStr(tmpb),tsiz);
		strcpy(tmpa,tmpb);
	}
	free((char*)tmpb);
EXIT:
	maskBody(AVStr(tmpa));
	fputs(tmpa,tc);

PUTEOL:
	if( endline[0] )
		eol = strpbrk(endline,"\r\n"); /* maybe .CRLF via NNTP */
	if( eol == NULL )
		eol = beol;

	/* can be converted CRLF to/from LF */
	if( eol && (elen = strlen(eol)) )
	if( DECODE(C_BODY_CHAR) && do_conv ){
		CStr(xeol,LINESIZE);
		codeconv_line(eol,AVStr(xeol),ctype,0);
		if( strcmp((char*)eol,(char*)xeol) != 0 ){
			eol = xeol;
		}
	}

	if( eol && (elen = strlen(eol)) )
	if( len = strlen(tmpa) )
	if( len < elen || strcmp(&tmpa[len-elen],eol) != 0 ){
		fputs(eol,tc);
		DEBUG("supply missing <CR><LF> at the end of BODY part\n");
	}
	free((char*)tmpa);
	return rcode;
}

int decodeBODY(FILE *fs,FILE *tc,int filter,PCStr(encoding),PCStr(decodeto),int do_enHTML)
{	const char *boundaries[MAXDEPTH]; /**/
	const char *ctype = "text/plain";
	CStr(endline,LINESIZE);
	int rcode;
	MimeConv Mcvb,*Mcv = &Mcvb;

	boundaries[0] = 0;
	bzero(Mcv,sizeof(MimeConv));
	rcode = decodeBODYpart(Mcv,fs,tc,NULL,ctype,boundaries,
			filter,encoding,decodeto,do_enHTML,AVStr(endline));
	if( EOR_ALSO(filter) || endline[0] != '.' )
		fputs(endline,tc);
	return rcode;
}

static headFilter HEAD_filter;

headFilter set_HEAD_filter(headFilter filter)
{	headFilter ofilter;

	ofilter = HEAD_filter;
	HEAD_filter = filter;
	return ofilter;
}

extern FILE *NULLFP();

static int skipContentHead(const char *boundaries[],PVStr(head),int rcode){
	refQStr(dp,head);

	if( boundaries[0] && boundaries[1] == 0 ){
		/* top-level header (message/rfc822) */
		removeFields(BVStr(head),"Content-",1);
		if( rcode != MP_EOR ){
			if( dp = strSeekEOH(head) )
				setVStrEnd(dp,0);
		}
		return 1;
	}
	return 0;
}

static
int decodeMIMEpart(const char *boundaries[],FILE*fs,FILE*tc,FILE*cache,int filter,int enHTML)
{	ACStr(head,2,0x10000);
	CStr(ctype,128);
	CStr(ichset,64);
	CStr(encoding,128);
	const char *decodeto;
	int hi,nhi;
	int do_enHTML;
	int putPRE;
	int rcode;
	CStr(endline,LINESIZE);
	int do_conv,plain2html;
	const char *xcharset;
	FILE *ntc;
	int ismainpart;
	MimeConv Mcvb,*Mcv = &Mcvb;

	filter |= MIME_FILTER;

	ismainpart = boundaries[0] == 0;
	do_conv = codeconv_get(NULL,&xcharset,&plain2html);
	bzero(Mcv,sizeof(MimeConv));
	readHeader(Mcv,fs,FVStr(head[0]),sizeof(head[0]),
		cache,filter,AVStr(ctype),AVStr(ichset),boundaries,AVStr(encoding),enHTML);

	if( DECODE(C_HEAD_EW) )
	if( ichset[0] == 0 && do_conv && xcharset ){
		MIME_strHeaderDecodeX(Mcv,head[0],FVStr(head[1]),sizeof(head[1]));
		if( Mcv->c_ewicode[0] ){
			/* conv. non-ASCII in the raw code */
			strcpy(ichset,Mcv->c_ewicode);
			Mcv->c_ewiccxeach = 1;
			if( strcaseeq(ichset,"ISO-2022-JP") ){
				/* to escape the bug in m17n-lib <= 1.5.3 */
				strcpy(ichset,"EUC-JP");
			}
		}
	}
	if( DECODE(C_HEAD_EW) )
	if( ichset[0] != 0 && do_conv && xcharset ){
		Mcv->c_icode = ichset;
		Mcv->c_ocode = xcharset;
		if( m17n_known_code(ichset) ){
			Mcv->c_m17n = m17n_ccx_new(ichset,xcharset,0,0);
		}
	}

	if( got_EOR )
		rcode = MP_EOR;
	else	rcode = 0;

	/*
	if( HEAD_filter && boundaries[0] == NULL ){
	*/
	if( HEAD_filter && ismainpart ){
		ntc = (*HEAD_filter)(EVStr(head[0]),tc,cache);
		if( ntc != NULL )
			tc = ntc;
		else{
			if( EOR_ALSO(filter) )
				fputs(".\r\n",tc);
			tc = NULLFP();
		}
	}

	hi = 0;
	if( DECODE(C_HEAD_EW) )
	if( do_conv && Mcv->c_ewiccxeach ){
		nhi = (hi + 1 ) % 2;
		MimeCodeconv(Mcv,head[hi],FVStr(head[nhi]),sizeof(head[nhi]),C_TEXT_PLAIN,1);
		hi = nhi;
	}
	if( DECODE(C_HEAD_EW) )
	if( maybe_MIME ){
		nhi = (hi + 1 ) % 2;
		MIME_strHeaderDecodeX(Mcv,head[hi],FVStr(head[nhi]),sizeof(head[1]));
		hi = nhi;
		maybe_NONASCII = 1;
	}

	if( !plain2html )
	if( DECODE(C_HEAD_CHAR) )
	/*
	if( maybe_NONASCII && do_conv ){
	*/
	if( Mcv->c_ewiccxeach ){
		/* conv. done already above and in strHeaderDecodeX() */
	}else
	if( maybe_NONASCII && do_conv || (do_conv & 0xFFFE) ){
		nhi = (hi + 1 ) % 2;
		MimeCodeconv(Mcv,head[hi],FVStr(head[nhi]),sizeof(head[nhi]),C_TEXT_PLAIN,1);
		/*
		codeconv_line(head[hi],FVStr(head[nhi]),C_TEXT_PLAIN,1);
		*/
		hi = nhi;
	}

	if( strncasecmp(ctype,"multipart/",10) == 0 ){
		FILE *mtc;
		int ofilter;
		int mask = 0;

		ofilter = filter;
		if( TEXTONLY(filter) ){
			replaceContentType(FVStr(head[hi]),"text/plain");
			filter |= O_MULTIPART;
			mask = O_HEAD | O_DELIM;
		}

		if( strncaseeq(ctype,"multipart/alternative",21) ){
			if( ALT_FIRST(filter) ) filter |= O_FIRSTALT;
			if( ALT_UNFOLD(filter) ) filter |= O_PLAINALT;
		}
		if( HEAD_ALSO(filter) )
		if( UNFOLDMP(filter) ){
			/* skip the alt. header */
			if( skipContentHead(boundaries,FVStr(head[hi]),rcode) ){
				fputs(head[hi],tc);
			}
		}else
		fputs(head[hi],tc);

		if( rcode == MP_EOR )
			return rcode;

		if( PGP_DECR() || PGP_VRFY() ){
			if( substr(ctype,C_SIGNED) ){
				filter |= O_MIME2PGP;
				filter &= ~O_EOR;
			}else
			if( substr(ctype,C_ENCRYPTED) ){
				filter = 0;
			}
		}

		if( BODY_ALSO(filter) ){
			mtc = tc;
		}else{
			mtc = NULLFP();
			filter = O_ALL;
		}

		filter &= ~mask;
		rcode = scan_multipart(boundaries,AVStr(endline),sizeof(endline),
				decodeMIMEpart,fs,mtc,cache,filter,enHTML);
		filter = ofilter;
		goto EXIT;
	}

	putPRE = 0;
	if( is_text(ctype) ){ 
		do_enHTML = 0;
		if( is_text_plain(ctype) ){
			do_enHTML = enHTML;
			if( plain2html ){
				putPRE = 1;
				/*do_enHTML = 1;*/
				replaceContentType(FVStr(head[hi]),"text/html");
			}
		}

		if( DECODE(C_BODY_CHAR) && xcharset && is8bitCharset(xcharset)
		 || DECODE(C_BODY_CTE ) && strcaseeq(encoding,"quoted-printable")
	 	 || DECODE(C_BODY_CTE ) && strcaseeq(encoding,"base64") ){
			decodeto = "8bit";
			replaceFieldValue(FVStr(head[hi]),FN_CTE,decodeto);
			DEBUG("decodeMIME[encoding=%s]\n",decodeto);
		}else	decodeto = NULL;

		/*
		if( DECODE(C_BODY_CHAR) && xcharset ){
		*/
		if( DECODE(C_BODY_CHAR) && xcharset && *xcharset ){
			if( streq(xcharset,"guess") ){
				/* cannot guess ... */
			}else{
			replace_charset(FVStr(head[hi]),xcharset);
			DEBUG("decodeMIME[charset=%s]\n",xcharset);
			}
		}
	}else{
		do_enHTML = 0;
		decodeto = NULL;
	}

	if( HEAD_ALSO(filter) ){
	if( MIME2PGP(filter) ){
		if( !substr(ctype,C_PGPSIGN) )
			fputsCRLF(head[hi],tc);
	}else
	fputs(head[hi],tc);
	}

	/* EOR is included in the header buffer, thus a EOR immediately
	 * follows a header is put with the header.
	 */
	if( rcode == MP_EOR )
		return MP_EOR;

	endline[0] = 0;
	if( TEXTONLY(filter)
	 && MULTIPART(filter)
	 && strncasecmp(ctype,"text/plain",10) != 0 ){
		DEBUG("## TEXTONLY skip non text/plain: %s\n",ctype);
		rcode = decodeBODYpart(Mcv,fs,NULLFP(),cache,ctype,boundaries,
				filter,
				encoding,decodeto,do_enHTML,AVStr(endline));
	}else
	if( BODY_ALSO(filter) ){
		if( putPRE ) fprintf(tc,"<PRE>\n");
/*
		if( TEXTONLY(filter) && strncaseeq(ctype,"text/html",9) ){
			int HTMLtoTEXT(FILE *ain,FILE *aout,int toHtml);
			FILE *tmp;

			tmp = TMPFILE("HTMLtoTEXT");
			rcode = decodeBODYpart(Mcv,fs,tmp,cache,ctype,boundaries,
					filter,
					encoding,decodeto,do_enHTML,AVStr(endline));
			fflush(tmp);
			fseek(tmp,0,0);
			HTMLtoTEXT(tmp,tc,0);
			fclose(tmp);
		}else
*/
		if( MIME2PGP(filter) )
			if( substr(ctype,C_PGPSIGN) )
				rcode = relay_pgpSIGN(fs,tc,boundaries,AVStr(endline));
			else	rcode = relay_pgpSIGNED(fs,tc,boundaries,AVStr(endline));
		else
		rcode = decodeBODYpart(Mcv,fs,tc,cache,ctype,boundaries,
			filter,encoding,decodeto,do_enHTML,AVStr(endline));
		if( putPRE ) fprintf(tc,"</PRE>\n");
	}else{
		if( fseek(fs,0,0) == -1 ){
			DEBUG("skip body from stream input.\n");
			RFC821_skipbody(fs,NULL,AVStr(endline),sizeof(endline));
		}
	}
EXIT:
	if( UNFOLDMP(filter) && endline[0] == '-' ){
		/* skip the ending boundary line of alt. */
	}else
	if( TEXTONLY(filter) && (rcode == MP_EOP||rcode == MP_EOC) ){
	}else
	if( EOR_ALSO(filter) || endline[0] != '.' && !MIME2PGP(filter) )
		fputs(endline,tc);

/*
	if( addQY ){
		CStr(date,64);
		CStr(qy,128);
		int clock;
		if( getFieldValue2(head,"Date",date,sizeof(date)) ){
			clock = scanNNTPtime(date);
			makeQY(clock,qy,sizeof(qy));
		}
		fprintf(tc,"%s%s",qy,"\n");
	}
*/

	return rcode;
	/*
	 * Result (real) Encoding and Charcode should be set in the header
	 * after this decoding...
	 */
}
/*
makeQY(int clock,PVStr(qy),int siz)
{	CStr(year,64);
	CStr(mon,64);
	refQStr(yp,qy);
	int yi,mi,i;

	StrftimeLocal(year,sizeof(year),"%Y",clock);
	yi = atoi(year);
	StrftimeLocal(mon,sizeof(mon),"%m",clock);
	mi = atoi(mon);

	if( yi < 1990 ) yi = 0; else
	if( 2009 < yi ) yi = 20; else
		yi = yi - 1990; 

	yp = qy;
	for( i = 0; i < yi; i++ ){
		strcpy(yp,"qy ");
		yp += strlen(yp);
	}
	for( ; i < 20; i++ ){
		strcpy(yp,"yq ");
		yp += strlen(yp);
	}
	for( i = 1; i <= mi; i++ ){
		strcpy(yp,"qk ");
		yp += strlen(yp);
	}
	for( ; i <= 12; i++ ){
		strcpy(yp,"kq ");
		yp += strlen(yp);
	}
}
*/

void fputsCRLF(PCStr(str),FILE *out)
{	const char *bp;
	int ch,pch;

	pch = 0;
	for( bp = str; ch = *bp; bp++ ){
		if( ch == '\n' && pch != '\r' )
			putc('\r',out);
		putc(ch,out);
		if( ch == '\r' && bp[1] != '\n' )
			putc('\n',out);
		pch = ch;
	}
}

static
int encodeMIMEpart(const char *boundaries[],FILE*fc,FILE*ts,FILE*cache,int filter,int _)
{	ACStr(head,2,0x10000);
	int hi,nhi;
	FILE *tmp;
	const char *charset;
	CStr(ctype,128);
	CStr(ichset,64);
	CStr(encoding,128);
	int rcode;
	CStr(endline,LINESIZE);
	int isroot;
	MimeConv Mcvb,*Mcv = &Mcvb;

	isroot = boundaries[0] == 0;
	bzero(Mcv,sizeof(MimeConv));
	readHeader(Mcv,fc,FVStr(head[0]),sizeof(head[0]),
		cache,filter,AVStr(ctype),AVStr(ichset),boundaries,AVStr(encoding),0);
	if( got_EOR )
		rcode = MP_EOR;
	else	rcode = 0;

	if( MIME_CCX ) /* 9.9.9 fix-140615h */
	if( ichset[0] == 0 ){
	    /* 9.9.9 mod-140605c force char. conv. for multipart header */
	    const char *xchset = 0;
	    CCXoutcharset(MIME_CCX,&xchset);
	    if( xchset ){ /* CHARCODE=code:tosv wth SERVER=smtp */
		if( strncaseeq(ctype,"multipart/",10) ){
		    const char *iset = "utf-8";
		    syslog_ERROR("#encodeMIME [%s] assuming charset=%s\n",
			ctype,iset);
		    strcpy(ichset,iset);
		}
	    }
	}

	if( ichset[0] ){
		int do_conv,plain2html;
		int iknown = 0;
		const char *xchset = 0;

		iknown = m17n_known_code(ichset);
		if( MIME_CCX ){
			/* CHARCODE=code:tosv with SERVER=smtp */
			do_conv = 1;
			CCXoutcharset(MIME_CCX,&xchset);
			syslog_ERROR("#%s-M17N#MIME_CCX (%s <= %s)[%s]\n",
			    iknown?"with":"no",xchset?xchset:"",ichset,ctype);
			/*
			syslog_ERROR("#M17N%s#MIME_CCX (%s <= %s)\n",
				iknown?"+":"-",xchset?xchset:"",ichset);
			*/
		}else{
			/* CHARCODE=code with -FenMime */
			do_conv = codeconv_get(NULL,&xchset,&plain2html);
			if( xchset )
			syslog_ERROR("#%s-M17N#CHARCODE (%s <= %s)[%s]\n",
			    iknown?"with":"no",xchset?xchset:"",ichset,ctype);
			/*
			syslog_ERROR("#M17N%s#CHARCODE (%s <= %s)\n",
				iknown?"+":"-",xchset?xchset:"",ichset);
			*/
		}
		if( do_conv && xchset ){
			Mcv->c_icode = ichset;
			Mcv->c_ocode = xchset;
			if( iknown && m17n_known_code(xchset) ){
				Mcv->c_m17n = m17n_ccx_new(ichset,xchset,0,0);
			}else{
			}
		}
	}

	hi = 0;
	if( maybe_NONASCII ){
		if( ENCODE(C_HEAD_CHAR) )
		{
			external_charcode(Mcv,head[0],FVStr(head[1]),0x10000,ichset);
			if( Mcv->c_ocode && strcmp(head[0],head[1]) != 0 ){
				/* set the charset name to be shown
				 * in =?charset?e?x?= in strHeaderEncode()
				 */
				Mcv->c_icode = Mcv->c_ocode;
			}
		}
		else	Xstrcpy(EVStr(head[1]),head[0]);
		if( strcmp(head[0],head[1]) != 0 ){
			DEBUG("POST: code converted.\n");
		}
		if( ENCODE(C_HEAD_EW) )
		{
			MIME_strHeaderEncodeX(Mcv,head[1],FVStr(head[0]),sizeof(head[0]));
			/*
			MIME_strHeaderEncode(head[1],FVStr(head[0]),sizeof(head[0]));
			*/
		}
		else{
			hi = 1;
		}
	}

	if( strncasecmp(ctype,"multipart/",10) == 0 ){
		if( TEXTONLY(filter) && isroot ){
			replaceContentType(FVStr(head[hi]),"text/plain");
		}
		if( strncaseeq(ctype,"multipart/alternative",21) ){
			if( ALT_FIRST(MIME_FILTER) ) filter |= O_FIRSTALT;
			if( ALT_UNFOLD(MIME_FILTER) ) filter |= O_PLAINALT;
		}
		if( UNFOLDMP(filter) ){
			/* skip the alt. header */
			if( skipContentHead(boundaries,FVStr(head[hi]),rcode) ){
				fputs(head[hi],ts);
			}
		}else
		if( !TEXTONLY(filter) || isroot )
		fputs(head[hi],ts);
		rcode = scan_multipart(boundaries,AVStr(endline),sizeof(endline),
				encodeMIMEpart,fc,ts,cache,filter,0);

		if( UNFOLDMP(filter) && endline[0] == '-' ){
			/* skip the ending boundary line of alt. */
		}else
		if( !TEXTONLY(filter) )
		fputs(endline,ts);
		return rcode;
	}

	if( rcode == MP_EOR ){
		fputs(head[hi],ts);
		return rcode;
	}else
	if( TEXTONLY(filter) && !is_text(ctype) ){
		rcode = relayBODYpart(fc,NULLFP(),boundaries,0,AVStr(endline));
	}else
	if( is_text(ctype) || tobe_charconv(ctype) ){
		tmp = TMPFILE("encodeMIMEpart");
		charset = 0;
		rcode = encodeBODYpart(Mcv,fc,tmp,ctype,ichset,filter,boundaries,encoding,&charset);
		if( charset ){
			replace_charset(FVStr(head[hi]),charset);
			if( findField(head[hi],FN_CTE,NULL) )
				if( Mcv->c_8bits ){
			replaceFieldValue(FVStr(head[hi]),FN_CTE,"8bit");
				}else
			replaceFieldValue(FVStr(head[hi]),FN_CTE,"7bit");
		}
		fflush(tmp);
		fseek(tmp,0,0);
		if( !TEXTONLY(filter) )
		fputs(head[hi],ts);
		copyfile1(tmp,ts);
		fclose(tmp);
	}else{
		fputs(head[hi],ts);
		rcode = relayBODYpart(fc,ts,boundaries,0,AVStr(endline));
		if( UNFOLDMP(filter) && endline[0] == '-' ){
			/* skip the ending boundary line of alt. */
		}else
		fputs(endline,ts);
	}
	return rcode;
}

void thruRESP(FILE *fs,FILE *tc)
{	CStr(line,LINESIZE);

	relayRESPBODY(fs,tc,AVStr(line),sizeof(line));
	fputs(line,tc);
}

static void delWhites(PVStr(str))
{	char ch;
	const char *sp;
	refQStr(dp,str); /**/

	cpyQStr(dp,str);
	for( sp = str; ch = *sp; sp++ ){
		if( ch != '\t' && ch != '\r' && ch != '\n' )
			setVStrPtrInc(dp,ch);
	}
	setVStrEnd(dp,0);
}
void decodeTERM1(PCStr(line),PVStr(xline))
{	refQStr(xp,xline); /**/
	const char *tp;
	char dc;
	const char *np;
	int do_conv,plain2html;
	const char *xcharset;

	if( !DECODE(C_HEAD) ){
		strcpy(xline,line);
		return;
	}

	do_conv = codeconv_get(NULL,&xcharset,&plain2html);

	cpyQStr(xp,xline);

	for( tp = line; *tp; tp = np ){
		if( np = strpbrk(tp,"\t\r\n") ){
			dc = *np;
			*(char*)np = 0; /**/
		}
		if( *tp ){
			decodeHEAD1(tp,AVStr(xp),
				DECODE(C_HEAD_EW),
				DECODE(C_HEAD_CHAR) && !plain2html);
			xp += strlen(xp);
		}
		if( np ){
			*(char*)np++ = dc; /**/
			setVStrPtrInc(xp,dc);
		}else	break;
	}
	setVStrEnd(xp,0);
}

void decodeHEAD1(PCStr(tp),PVStr(xp),int decode,int cconv)
{	int convert;
	CStr(term,0x4000);
	CStr(xterm,0x4000);
	const char *ts;

	convert = 0;
	for( ts = tp; *ts; ts++ ){
		if( ts[0] == '=' && ts[1] == '?'
		 || ts[0] == '$' &&(ts[1] == 'B' || ts[1] == '@')
		 || ts[0] == 033
		 || ts[0] & 0x80
		){
			convert = 1;
			break;
		}
	}
	if( convert ){
		if( decode )
			MIME_strHeaderDecode(tp,AVStr(term),sizeof(term));
		else	strcpy(term,tp);

		/* remove possible white spaces
		 * insterted by MIME decoder (-_-; */
		delWhites(AVStr(term));

		if( cconv ){
			codeconv_line(term,AVStr(xterm),C_TEXT_PLAIN,1);
			strcpy(xp,xterm);
		}else	strcpy(xp,term);
	}else	strcpy(xp,tp);
}

void decodeTERM(FILE *fs,FILE *tc,int enHTML)
{	CStr(line,0x8000);
	CStr(xline,0x8000);

	while( fgets(line,sizeof(line),fs) != NULL){
		if( isEOR(line) ){
			fputs(line,tc);
			break;
		}
		if( DECODE(C_HEAD) ){
			decodeTERM1(line,AVStr(xline));
			fputs(xline,tc);
		}else	fputs(line,tc);
	}
}

void encodeMIME(FILE *fc,FILE *ts)
{
	encodeMIMEX(fc,ts,O_ALL);
}
void encodeMIMEX(FILE *fc,FILE *ts,int filter)
{	const char *boundaries[MAXDEPTH]; /**/

	boundaries[0] = 0;
	encodeMIMEpart(boundaries,fc,ts,NULL,filter,0);
}
int encodeMIMEXX(MimeEnv *me,FILE *fc,FILE *ts){
	const char *boundaries[MAXDEPTH]; /**/
	CCXP sav_ccx;

	sav_ccx = MIME_CCX;
	MIME_CCX = me->me_ccx;
	boundaries[0] = 0;
	encodeMIMEpart(boundaries,fc,ts,NULL,me->me_filter,0);
	MIME_CCX = sav_ccx;
	return 0;
}

void decodeMIME(FILE*fs,FILE*tc,FILE*cache, int filter,int codeconv,int enHTML)
{	const char *boundaries[MAXDEPTH]; /**/
	int ssc;

	ssc = codeconv_set(codeconv,NULL,-1);
	boundaries[0] = 0;
	decodeMIMEpart(boundaries,fs,tc,cache,filter,enHTML);
	codeconv_set(ssc,NULL,-1);
}

void deMime(int ac,const char *av[])
{
	decodeMIME(stdin,stdout,NULL,O_ALL,1,0);
}
void enMime(int ac,const char *av[])
{
	encodeMIMEX(stdin,stdout,O_ALL);
}
