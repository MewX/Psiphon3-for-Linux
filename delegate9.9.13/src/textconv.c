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
Program:	textconv.c (text / character code conversion)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    codeconv_spec = outcode [ "." incode ]

    outcode       = codename [ "_" extension ]

    incode        = codename [ "_" extension ]

    codename      = [0-9A-Za-z]+

    extension     = [0-9A-Za-z]+

    Example:

    	jis		== jis.jp : japanese input to  JIS (ISO-2022-JP)

History:
	941001 extracted from conf.c and gopher.c
	960105 introduced codeconv_spec and cascaded conversions

//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "fpoll.h"
int m17n_known_code(PCStr(name));

int suppress_codeconv;
extern int PLAIN_TO_HTML_PRE;

#define CC_THRU	'='	/* Through, without conversion (output only) */
#define CC_ANY	'*'	/* any encoding (input only) */
#define CC_HTML	'H'	/* HTML character encoding */
#define CC_EUC	'E'	/* EUC (EUC-JP) */
#define CC_euc	'e'	/* EUC-JP */
#define CC_JIS	'J'	/* JIS (ISO-2022-JP) */
#define CC_SJIS	'S'	/* SJIS (Shift-JIS, MS-Kanji) */
#define CC_sjis	's'	/* Shift_JIS */
#define CC_RECV	'R'	/* Recover lost ESCs */
#define CC_FIX	'F'	/* Fix lost ESC $ B */
#define CC_UTF8	'U'	/* utf-8 */
#define CC_M17N 'M'	/* something known by m17n */

static const char *codename(int code)
{
	switch( code ){
		case CC_JIS:  return "iso-2022-jp";
		case CC_EUC:  return "x-euc-jp";
		case CC_euc:  return "EUC-JP";
		case CC_SJIS: return "x-sjis";
		case CC_sjis: return "Shift_JIS";
		case CC_UTF8: return "utf-8";
	}
	return NULL;
}
#define CTX_codeconv_charset(Conn) codename(CTX_cur_codeconvCL(Conn,VStrNULL))

#define JIS_BUFSIZ(sz)	(sz * 2 + 1000)

typedef struct {
  const char	*cv_what; /* realm of the conversion */
  const	char	*cv_spec; /* conversion spec. source */
	int	 cv_occe; /* output charcode encoding */
  const	char	*cv_occs; /* output charcode spec. */
	int	 cv_icce; /* input charcode encoding */
  const	char	*cv_iccs; /* input charcode spec. */
} Conv;
typedef struct {
	Conv	te_CodeConv[32]; /**/
	Conv	te_cv0;
	int	te_globalCCX[16];
} TextConvEnv;
static TextConvEnv *textConvEnv;
#define CodeConv textConvEnv->te_CodeConv
#define cv0	textConvEnv->te_cv0
#define globalCCX (CCXP)textConvEnv->te_globalCCX
static Conv Conv0 = {"*","THRU",CC_THRU,"=",CC_ANY,"*"};
void minit_textconv()
{
	if( textConvEnv == 0 ){
		textConvEnv = NewStruct(TextConvEnv);
		CodeConv[0] = Conv0;
	}
}

#define CONVX0	1
int CodeConv_X = CONVX0;	/* global */
int CodeConv_x;		/* local to connection */
#define CONVX	(CodeConv_X + CodeConv_x)

int scan_CODECONV(PCStr(spec),PCStr(what),int local);
static scanListFunc scan_CHARCODE1(PCStr(charcode),int local)
{	CStr(ccb,256);
	const char *incode;
	const char *outcode;
	const char *dp;
	CStr(spec,256);

	strcpy(ccb,charcode);
	if( dp = strchr(ccb,'/') ){
		truncVStr(dp); dp++;
		outcode = dp;
		incode = ccb;
	}else
	if( dp = strchr(ccb,'.') ){
		truncVStr(dp); dp++;
		incode = dp;
		outcode = ccb;
	}else{
		incode = "JP";
		outcode = ccb;
	}

	sprintf(spec,"%s.%s",outcode,incode);
	scan_CODECONV(spec,CCV_TOCL,local);
	return 0;
}
char CCXTOSV[] = "CCXTOSV";
char CCXTOCL[] = "CCXTOCL";
void setCCX0(PCStr(what),PCStr(chset),CCXP ccx){
	IStr(ics,128);
	const char *ocs;

	sv1log("%s: %s\n",what,chset);
	ocs = wordScanY(chset,ics,"^/");
	if( *ocs == '/' ){	
		ocs++;
	}else{
		ocs = chset;
		strcpy(ics,"*");
		/* out-chaset of TOCL should be hinted to TOSV
		 * as it's input-charset ...
		 */
	}
	CCXcreate(ics,ocs,ccx);
	sv1log("{C} %s: %d [%s] [%s]->[%s]\n",
		what,CCXactive(ccx),chset,ics,ocs);
}
int scan_CCXTOCL(Connection *Conn){
	IStr(chset,128);
	if( (ConfigFlags & CF_WITH_CCXTOCL) == 0 )
		return 0;
	if( DST_HOST[0] == 0 || streq(DST_HOST,"-") ){
		/* not initialized. it's bad for dstHostList including
		 * "!host" to be matched unconditionally
		 */
		return 0;
	}
	if( ClientFlags & PF_WITH_CCX )
		if( CCXactive(CCX_TOCL) )
			return 0;
	ClientFlags |= PF_WITH_CCX;
	if( 0 <= find_CMAP(Conn,CCXTOCL,AVStr(chset)) ){
		setCCX0("CCXTOCL",chset,CCX_TOCL);
		return 1;
	}
	return 0;
}
int scan_CCXTOSV(Connection *Conn){
	IStr(chset,128);
	if( (ConfigFlags & CF_WITH_CCXTOSV) == 0 )
		return 0;
	if( ServerFlags & PF_WITH_CCX )
		if( CCXactive(CCX_TOSV) )
			return 0;
	ServerFlags |= PF_WITH_CCX;
	if( 0 <= find_CMAP(Conn,CCXTOSV,AVStr(chset)) ){
		setCCX0("CCXTOSV",chset,CCX_TOSV);
		CCXtosv(CCX_TOSV,1);
		return 1;
	}
	return 0;
}
const char *get_CHARCODE(Connection *Conn){
	const char *ocode = "";
	if( Conn == 0 )
		Conn = MainConn();
	if( CCXactive(CCX_TOCL) ){
		if( CCXoutcharset(CCX_TOCL,&ocode) ){
			return ocode;
		}
	}
	return 0;
}
void scan_CHARCODE(Connection *Conn,PCStr(charcodes))
{
	if( strchr(charcodes,':') ){
		IStr(ccx,128);
		IStr(dest,128);
		IStr(proto,128);
		IStr(dst,MaxHostNameLen);
		IStr(src,MaxHostNameLen);
		const char *map;
		CStr(xmap,MaxHostNameLen);
		int tosv = 0;

		scan_Lists5(charcodes,':',ccx,dest,proto,dst,src);
		if( streq(dest,"tosv") ){
			tosv = 1;
			map = CCXTOSV;
		}else	map = CCXTOCL;

		ConfigFlags |= map==CCXTOSV ? CF_WITH_CCXTOSV:CF_WITH_CCXTOCL;
			
		if( *proto == 0 ) strcpy(proto,"*");
		if( *dst   == 0 ) strcpy(dst,"*");
		if( *src   == 0 ) strcpy(src,"*");
		sprintf(xmap,"%s:%s:%s:%s:%s",ccx,map,proto,dst,src);
		scan_CMAP(Conn,xmap);
		return;
	}

	scan_commaList(charcodes,0,scanListCall scan_CHARCODE1,0);

	if( strchr(charcodes,'/') == 0 )
	if( strchr(charcodes,'.') == 0 ){
		CCXcreate("*",charcodes,globalCCX);
	}
	if( strchr(charcodes,'/') ){
		setCCX0("CHARCODE-with-/",charcodes,globalCCX);
	}
}
void scan_CHARMAPs(void *ctx,PCStr(maps));
void scan_CHARMAP(Connection *Conn,PCStr(maps)){
	scan_CHARMAPs(Conn,maps);
}
void getGlobalCCX(CCXP ccx,int siz)
{
	bcopy(globalCCX,ccx,siz);
}

static
void scan_codename(PCStr(str),PVStr(name))
{
	Xsscanf(str,"%[-_a-zA-Z0-9]",AVStr(name));
}
int scan_CODECONV(PCStr(spec),PCStr(what),int local)
{	Conv *cv;
	const char *dp;
	CStr(outcx,128);
	CStr(outcs,128);
	CStr(incx,128);
	CStr(incs,128);
	int oc,ic;

	if( elnumof(CodeConv) <= CONVX ){
		return -1;
	}
	if( 0 < CONVX && strcmp(CodeConv[CONVX-1].cv_spec,spec) == 0 ){
		sv1log("## ignored the same [%d] CODECONV=%s\n",CONVX,spec);
		return 0;
	}

	cv = &CodeConv[CONVX];

	Xsscanf(spec,"%[^.]",AVStr(outcx));
	scan_codename(spec,AVStr(outcs));

	strcpy(incs,"jp");
	strcpy(incx,"jp");
	if( dp = strchr(spec,'.') ){
		dp++;
		if( strncmp(dp,"cc=",3) == 0 )
			dp += 3;

		if( dp[0] ){
			Xsscanf(dp,"%[^.]",AVStr(incx));
			if( strncmp(dp,"cc=",3) == 0 )
				dp += 3;
			scan_codename(dp,AVStr(incs));
		}
	}

	cv->cv_what = what;
	cv->cv_spec = stralloc(spec);
	cv->cv_occs = stralloc(outcx);
	cv->cv_iccs = stralloc(incx);

	if( strcaseeq(outcs, "html") )	oc = CC_HTML;	else
	if( strcaseeq(outcs, "fix" ) )  oc = CC_FIX;	else
	if( strcaseeq(outcs, "jp"  ) )  oc = CC_JIS;	else
	if( strcaseeq(outcs, "iso-2022-jp")) oc = CC_JIS; else
	if( strcaseeq(outcs, "jis" ) )  oc = CC_JIS;	else
	if( strcaseeq(outcs, "x-euc-jp")) oc = CC_EUC;	else
	if( strcaseeq(outcs, "euc-jp")) oc = CC_euc;	else
	if( strcaseeq(outcs, "euc" ) )  oc = CC_euc;	else
/*
	if( strcaseeq(outcs, "euc" ) )  oc = CC_EUC;	else
*/
	if( strcaseeq(outcs, "shift_jis")) oc = CC_sjis; else
	if( strcaseeq(outcs, "x-sjis") )  oc = CC_SJIS;	else
	if( strcaseeq(outcs, "sjis") )  oc = CC_sjis;	else
/*
	if( strcaseeq(outcs, "sjis") )  oc = CC_SJIS;	else
*/
	if( strcaseeq(outcs, "utf-8") ) oc = CC_UTF8;	else
	if( strcaseeq(outcs, "utf8") )  oc = CC_UTF8;	else
	if( m17n_known_code(outcs) )	oc = CC_M17N;	else
					oc = CC_THRU;

	cv->cv_occe = oc;

	if( strcaseeq(incs, "html") )	ic = CC_HTML;	else
					ic = CC_JIS;
	cv->cv_icce = ic;

/*
	sv1log("CODECONV[%d](%s,%s,%s) => %s.%s\n",CONVX,
		local?"local":"global",what,spec, outcx, incx);
*/
	sv1log("CODECONV[%d](%s,%s,%s) => %s.%s [%s]\n",CONVX,
		local?"local":"global",what,spec, outcx, incx,
		codename(oc)?codename(oc):"?");

	if( local ){
		CodeConv_x++;
	}else{
		CodeConv_X++;
	}
	return 0;
}

static int convenv(Connection *Conn,PCStr(what),Conv *cvv[])
{	Conv *cv;
	int cvi,cvj,ncv;

	ncv = 0;

	/* for backward compatiblity */
	if( CONVX == CONVX0 ){
		int ic,oc;

		ic = oc = 0;
		if( strchr(DELEGATE_FLAGS,'e') ) oc = CC_euc;  else
		if( strchr(DELEGATE_FLAGS,'E') ) oc = CC_EUC;  else
		if( strchr(DELEGATE_FLAGS,'s') ) oc = CC_sjis; else
		if( strchr(DELEGATE_FLAGS,'S') ) oc = CC_SJIS; else
		if( strchr(DELEGATE_FLAGS,'J') ) oc = CC_JIS;

		if( ic != 0 || oc != 0 ){
			cv0 = CodeConv[0];
			if( ic ){ cv0.cv_icce = ic; }
			if( oc ){ cv0.cv_occe = oc; }
			cvv[ncv++] = &cv0;
		}
	}

	for( cvi = CONVX-1; 0 <= cvi; cvi-- ){
		cv = &CodeConv[cvi];
		if( cv->cv_occe == CC_THRU && 0 < ncv )
			break;

		for( cvj = 0; cvj < ncv; cvj++ )
			if( cvv[cvj]->cv_icce == cv->cv_icce )
				goto NEXT;

		cvv[ncv++] = cv;
		if( cv->cv_occe == CC_THRU )
			break;
	NEXT:;
	}

	return ncv;
}

int plain2html()
{	int ncv,cvi;

	if( PLAIN_TO_HTML_PRE )
		return 1;
	return 0;
}

static int codeconvs(Connection *Conn,PCStr(what),PVStr(cvenv))
{	Conv *cvv[16],*cv;
	int ncv,cvi;
	refQStr(sp,cvenv); /**/

	ncv = convenv(Conn,CCV_TOCL,cvv);
	if( cvenv ){
		cpyQStr(sp,cvenv);
		for( cvi = ncv-1; 0 <= cvi; cvi-- ){
			cv = cvv[cvi];
			sprintf(sp,"%s.%s",cv->cv_occs,cv->cv_iccs);
			sp += strlen(sp);
			if( 0 < cvi ){
				sprintf(sp,",");
				sp += strlen(sp);
			}
		}
		XsetVStrEnd(AVStr(sp),0);
	}
	return cvv[0]->cv_occe;
}

int CTX_cur_codeconvCL(Connection *Conn,PVStr(cvenv))
{	int occe;

	occe = codeconvs(Conn,CCV_TOCL,AVStr(cvenv));
	if( occe == 0 || occe == CC_THRU )
		return 0;
	else	return occe;
}

void CTX_codeconv_line(Connection *Conn,PCStr(src),PVStr(dst),PCStr(ctype),int repair)
{
	if( repair )
	{
		/* setup for repair broken JIS codes... obsoleted */
		CTX_line_codeconv(Conn,src,AVStr(dst),ctype);
	}
	else	CTX_line_codeconv(Conn,src,AVStr(dst),ctype);
}

void CTX_line_codeconv(Connection *Conn,PCStr(src),PVStr(dst),PCStr(ctype))
{	Conv *cvv[16],*cv;
	int ncv,cvi;
	const char *tmpv[2]; /**/
	int tmpx,tx;

	if( suppress_codeconv ){
		strcpy(dst,src);
		return;
	}
	if( src != dst )
		setVStrEnd(dst,0);

	ncv = convenv(Conn,CCV_TOCL,cvv);
	for( cvi = 0; cvi < ncv; cvi++ ){
		cv = cvv[cvi];
		tmpx = 0;
		if( src == dst )
			tmpv[tmpx++] = (const char*)(src = stralloc(src));

		switch( cv->cv_occe ){
		case CC_FIX:  FIX_2022(src,AVStr(dst),ctype);break;
		case CC_euc:
		case CC_EUC:  TO_EUC( src,AVStr(dst),ctype); break;
		case CC_sjis:
		case CC_SJIS: TO_SJIS(src,AVStr(dst),ctype); break;
		case CC_JIS:  TO_JIS( src,AVStr(dst),ctype); break;
		case CC_UTF8: TO_UTF8( src,AVStr(dst),ctype);break;
		/*
		default:      strcpy(dst,src);       break;
		*/
		default:
			if( CCXactive(globalCCX) ){
				CCXexec(globalCCX,src,strlen(src),
					AVStr(dst),strlen(src)*2);
			}else	strcpy(dst,src);
			break;
		}

	NEXT:	for( tx = 0; tx < tmpx; tx++ )
			free((char*)tmpv[tx]);
		src = dst;
	}
}

void CTX_do_codeconv(Connection *Conn,PCStr(ccode),PCStr(src),PVStr(dst),PCStr(ctype))
{
	if( ccode == CCV_TOCL )
		CTX_line_codeconv(Conn,src,AVStr(dst),ctype);
	else
	if( ccode == CCV_TOSV )
		TO_JIS(src,AVStr(dst),ctype);
	else
	switch( ccode[0]  ){
		case CC_FIX:  FIX_2022(src,AVStr(dst),ctype);break;
		case CC_euc:
		case CC_EUC:  TO_EUC(src,AVStr(dst),ctype);  break;
		case CC_sjis:
		case CC_SJIS: TO_SJIS(src,AVStr(dst),ctype); break;
		case CC_JIS:  TO_JIS(src,AVStr(dst),ctype);  break;
		case CC_UTF8: TO_UTF8(src,AVStr(dst),ctype); break;
		default:      strcpy(dst,src); break;
	}
}

int codeconv_bufsize(int ccode,int size)
{
	switch( ccode ){
		case CC_FIX:  return JIS_BUFSIZ(size);
		case CC_JIS:  return JIS_BUFSIZ(size);
		case CC_UTF8: return JIS_BUFSIZ(size);
		case CC_euc:
		case CC_EUC:  return size;
		case CC_sjis:
		case CC_SJIS: return size;
	}
	return size;
}

int CTX_check_codeconv(Connection *Conn,int dolog)
{	CStr(cvenv,128);
	int tocl;

	if( tocl = CTX_cur_codeconvCL(Conn,AVStr(cvenv)) ){
		if( dolog ){
			sv1log("Code Conversion [CHARCODE=%s]\n",cvenv);
		}
		return tocl;
	}
	return 0;
}

int CTX_codeconv_get(Connection *Conn,PCStr(ctype),const char **xcharset, int *p2h)
{
	const char *xchar;
	int f;

	if( CTX_cur_codeconvCL(Conn,VStrNULL) ){
		if( xcharset ) *xcharset = CTX_codeconv_charset(Conn);
		if( p2h      ) *p2h = plain2html();

		if( xcharset && *xcharset == 0 )
		if( CodeConv[1].cv_occe == CC_M17N ){
			*xcharset = CodeConv[1].cv_occs;
		}
		return 1;
	}else
	if( CCXactive(globalCCX) && (f = CCXoutcharset(globalCCX,&xchar)) ){
		if( xcharset ) *xcharset = xchar;
		if( p2h      ) *p2h = 0;
		return f;
	}else{
		if( xcharset ) *xcharset = 0;
		if( p2h      ) *p2h = 0;
		return 0;
	}
}
int CTX_codeconv_set(Connection *Conn,int enable,PCStr(charcode),int p2h)
{	int osupp;

	osupp = suppress_codeconv;
	if( enable != -1 )
		suppress_codeconv = !enable;
	if( charcode != NULL )
	{
		scan_CHARCODE1(charcode,0);
		if( strchr(charcode,'/') == 0 )
		if( strchr(charcode,'.') == 0 ){
			CCXcreate("*",charcode,globalCCX);
		}
	}
	if( p2h != -1 )
		PLAIN_TO_HTML_PRE = p2h;
	return !osupp;
}

int CTX_check_codeconvSP(Connection *Conn,int dolog)
{
	if( BORN_SPECIALIST || ACT_SPECIALIST || ACT_TRANSLATOR )
		return CTX_check_codeconv(Conn,dolog);
	else	return 0;
}

extern int CACHE_TAKEOVER;
extern int IO_TIMEOUT;
FileSize CCV_relay_textsX(Connection *Conn,FILE *ins[],FILE *out,FILE *dup,FileSize *wcc);
FileSize CCV_relay_texts(Connection *Conn,FILE *ins[],FILE *out,FILE *dup)
{	FileSize rcc,wcc;
	rcc = CCV_relay_textsX(Conn,ins,out,dup,&wcc);
	return rcc;
}
FileSize CCV_relay_textsX(Connection *Conn,FILE *ins[],FILE *out,FILE *dup,FileSize *wcc)
{	const char *rs;
	CStr(line,4096);
	CStr(xline,4096);
	FileSize totalc;
	int do_conv,do_ccx;
	FILE *in;
	int inx,pending;
	int start = time(0);
	int leng,isbin,fromcache,remleng;
	FileSize ototal = 0;
	int ilen;
	int alive = 0;

	if( lSINGLEP() ){
		alive = IsAlive(fileno(out));
	}
	if( CCXactive(CCX_TOCL) ){
		do_conv = 1;
		do_ccx = 1;
	}else{
		do_conv = CTX_check_codeconvSP(Conn,1);
		do_ccx = 0;
	}
	totalc = 0;

	inx = 0;
	if( in = ins[inx] )
		inx++;
	pending = 0;

	isbin = 0;
	fromcache = 0;
	while( in != NULL ){
		if( fPollIn(in,100) == 0 )
			fflushTIMEOUT(out);

		remleng = sizeof(line)-pending;
		rs = fgetsByBlock(QVStr(line+pending,line),remleng,in,
			0,IO_TIMEOUT*1000,1,fromcache,remleng,&leng,&isbin);
		if( isbin ){
			fwrite(line,1,pending+leng,out);
			totalc += leng;
			totalc += copy_fileTIMEOUT(in,out,dup);
			rs = NULL;
		}
/*
		rs = fgetsTIMEOUT(line+pending,sizeof(line)-pending,in);
*/
		if( rs == NULL ){
			if( in = ins[inx] ){
				inx++;
				continue;
			}
			if( pending == 0 )
				break;
		}else{
			if( line[pending] != 0 ) /* line buff. is not full */
			if( strpbrk(line,"\r\n") == 0 ){
				pending = strlen(line);
				continue;
			}
		}

		pending = 0;
		/*
		totalc += strlen(line);
		*/
		totalc += (ilen = strlen(line));
		EmiUpdateMD5(Conn,line,ilen);
		if( alive ){
			if( !IsAlive(fileno(out)) ){
				/* 9.9.5 */
				int dupclosed_FL(FL_PAR,int fd);
				sv1log("##relay_text ferr=%x alive=%d\n",
					ferror(out),IsAlive(fileno(out)));
				dupclosed_FL(FL_ARG,fileno(out));
				break;
			}
		}
		if( do_conv ){
			if( do_ccx )
				CCXexec(CCX_TOCL,line,strlen(line),AVStr(xline),sizeof(xline));
			else	CTX_line_codeconv(Conn,line,AVStr(xline),"*/*");
			fputs(xline,out);
			ototal += strlen(xline);
		}else	fputs(line,out);

		if( ferror(out) && dup == NULL ){
			sv1log("## CCX_relay_texts: write error & no-cache\n");
			break;
		}
		if( ferror(out) && dup != NULL )
		if( CACHE_TAKEOVER < time(0)-start ){
			sv1log("## CCX_relay_texts: write error.\n");
			break;
		}

		if( dup )
			fputs(line,dup);
	}
	if( wcc ){
		if( do_conv )
			*wcc = ototal;
		else	*wcc = totalc;
	}
	return  totalc;
}
FileSize CCV_relay_text(Connection *Conn,FILE *in,FILE *out,FILE *dup)
{	FILE *ins[2]; /**/

	ins[0] = in;
	ins[1] = NULL;
	return CCV_relay_texts(Conn,ins,out,dup);
}
FileSize CCV_relay_textXX(Connection *Conn,FILE *in,FILE *out,FILE *dup,FileSize *wcc)
{	FILE *ins[2]; /**/

	ins[0] = in;
	ins[1] = NULL;
	return CCV_relay_textsX(Conn,ins,out,dup,wcc);
}
FileSize CCV_relay_textX(PCStr(ccspec),FILE *in,FILE *out)
{	Connection ConnBuf, *Conn = &ConnBuf;

	ConnInit(Conn);
	CodeConv_X = CONVX0;
	CodeConv_x = 0;
	scan_CHARCODE(Conn,ccspec);
	ACT_TRANSLATOR = 1;
	return CCV_relay_text(Conn,in,out,NULL);
}


int *ccx_global;

void setCCX(Connection *Conn,PVStr(code),PVStr(stat))
{	const char *st;
	int thru = 0;

	if( code[0] == 0 )
		strcpy(code,"j");

	switch( code[0] ){
		case 'u': case 'U': st = ": UTF-8"; break;
		case 'j': case 'J': st = ": JIS7 (ISO-2022-JP)"; break;
		case 'k': case 'K': st = ": JIS7 + 7bit/1byte-Kana"; break;
/*
		case 's': case 'S': st = ": ShiftJIS"; break;
		case 'e': case 'E': st = ": EUCJP"; break;
*/
		case 's': case 'S': st = ": Shift_JIS"; break;
		case 'e': case 'E': st = ": EUC-JP"; break;
		case 't': case 'T': st = ": Through (No conversion)";
			thru = 1;
			break;
		default : st = "? Unknown. Select one of J,K,S,E or T";
			break;
	}
	if( CCX0 != NULL ){
		if( ccx_global == CCX0 )
			ccx_global = NULL;
		free(CCX0);
		CCX0 = NULL;
	}
	if( !thru )
		CCX0 = CCXnew("*",code);

	strcpy(stat,st);
}
void global_setCCX(Connection *Conn,PVStr(code),PVStr(stat))
{
	setCCX(Conn,AVStr(code),AVStr(stat));
	ccx_global = (int*)CCX0;
}

/*
 * for MIMEKit libary...
 */
static Connection *textconvCTX;
void set_textconvCTX(Connection *Conn)
{
	textconvCTX = Conn;
}
Connection *get_textconvCTX()
{
	if( textconvCTX == NULL )
		textconvCTX = NewStruct(Connection);
	return textconvCTX;
}
int codeconv_set(int enable,PCStr(charcode),int p2h)
{
	return CTX_codeconv_set(get_textconvCTX(),enable,charcode,p2h);
}
int codeconv_get(PCStr(ctype),const char **xcharset, int *p2h)
{
	return CTX_codeconv_get(get_textconvCTX(),ctype,xcharset, p2h);
}
int codeconv_line(PCStr(src),PVStr(dst),PCStr(ctype),int repair)
{
	CTX_codeconv_line(get_textconvCTX(),src,AVStr(dst),ctype,repair);
	return 0;
}

CCXP CCXtoCL(Connection *Conn){
	return CCX_TOCL;
}
int CCXwithEUCX(Connection *Conn){
	if( ServerFlags & PF_UA_MSIE ){
		return 0;
	}
	return 1;
}
