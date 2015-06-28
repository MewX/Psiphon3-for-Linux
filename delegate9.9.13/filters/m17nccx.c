/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2009 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	m17nccx.c (character code converter powered by m17n-lib)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
  Utilizing the m17n library just for character code conversion.

    typedef strucnt _M17N *M17N;
    int m17n_Init();
    int m17n_Fini();
    int m17n_known_code(const char *name);
    M17N m17n_ccx_new(const char *icode,const char *ocode,void *buf,int siz);
    int m17n_ccx_free(M17N m17n);
    int m17n_ccx_init(M17N m17n,const char *icode,const char *ocode);
    int m17n_ccx_opts(M17N m17n,const char *opts);
    int m17n_ccx_filter(M17N m17n,FILE *in,FILE *out);
    int m17n_ccx_string(M17N m17n,const char *istr,int len,char *ostr,int siz);

  as a command:
    delegated -FdeMime CHARCODE=iso-2022-jp
    delegated -Fm17n -iutf-8 -oiso-2022-jp
  as a filter of DeleGate server:
    FTOCL="-m17n -iutf-8 -oiso-2022-jp"
  as a filter in CFI:
    Body-Filter: -m17n -iutf-8 -oiso-2022-jp
  as a server:
    delegated SERVER=m17n M17N="-iutf-8 -oiso-2022-jp"

History:
	090103	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "dglib.h"

/*BEGIN_STAB(m17n)*/
#ifdef __cplusplus
extern "C" {
#endif
	typedef void *MSymbol;
	extern MSymbol Mcoding_utf_8;
	typedef void MText;
	MSymbol msymbol(const char *sym);
	MText *mtext();
	typedef struct {
		int	lenient;
		int	last_block;
	       unsigned at_most;
		int	nchars;
		int	nbytes;
		int	result;
	} MConverter;
	void m17n_init();
	MSymbol mconv_resolve_coding(MSymbol symbol);
	MConverter *mconv_stream_converter(MSymbol coding,FILE *fp);
	MConverter *mconv_buffer_converter(MSymbol coding,const unsigned char *buf,int n);
	MText *mconv_decode(MConverter *converter,MText *mt);
	int mconv_encode(MConverter *converter,MText *mt);
	void mconv_free_converter(MConverter *converter);
	int m17n_object_unref(void *object);
	void m17n_fini();
	enum MErrorCode { MERROR_NONE };
	/*
	extern MErrorCode merror_code;
	*/
#ifdef __cplusplus
}
#endif
/*END_STAB*/

static int m17n_enabled = 0;
void scan_M17N(DGC*ctx,PCStr(conf)){
	IStr(nam,128);
	IStr(val,128);
	fieldScan(conf,nam,val);
	if( strcaseeq(nam,"on") ){
		m17n_enabled = 1;
	}
	else
	if( strcaseeq(nam,"off") ){
		m17n_enabled = 0;
	}
	else
	if( strcaseeq(nam,"lib") ){
		/* add the path to the default search path of dylib */
	}
}

int dl_library(const char *libname,DLMap *dlmap,const char *mode);
static int m17n_dlstat;
int m17n_lib_init(){
	if( m17n_enabled == 0 ){
		return -3;
	}
	if( m17n_dlstat < 0 ){
		return -2;
	}
	if( m17n_dlstat == 0 ){
		int code;
		code = dl_library("m17n",dlmap_m17n,"");
		if( code != 0 ){
			fprintf(stderr,"--M17n cannot load m17n dylib.\n");
			m17n_dlstat = -1;
			return -1;
		}
		m17n_dlstat = 1;
	}
	return 0;
}
static int m17n_stat;
int m17n_Active(){
	return 0 < m17n_stat;
}
int m17n_Init(){
	if( m17n_stat < 0 )
		return -1;
	if( m17n_stat == 0 ){
		m17n_init();
		/*if( merror_code != MERROR_NONE )*/
		if( mconv_resolve_coding(msymbol("iso-2022-jp")) == 0 ){
			fprintf(stderr,"--M17n Failed to initialize");
			m17n_stat = -1;
		}else{
			m17n_stat = 1;
		}
	}
	return 0 < m17n_stat;
}
int m17n_Fini(){
	if( 0 < m17n_stat ){
		m17n_stat = 0;
		return 0;
	}
	return -1;
}
int m17n_known_code(const char *name){
	if( m17n_lib_init() < 0 ){
		return 0;
	}
	m17n_Init();
	if( mconv_resolve_coding(msymbol(name)) ){
		return 1;
	}else{
		return 0;
	}
}

typedef struct _M17N {
	void	    *m_ctx;   /* opaque */
	double       m_alloc; /* to be free() on finish */
	int	     m_trace;
	double       m_Start;
	const char  *m_icnam; /* the name of the input code */
	const char  *m_ocnam; /* the name of the output code */
	MSymbol	     m_icode;
	MSymbol	     m_ocode;
	MConverter  *m_dec;
	MConverter  *m_enc;
	MText       *m_mtext;
} M17nCCX;
static void Lap(M17nCCX *m17n,const char *wh){
	if( m17n->m_trace ){
		fprintf(stderr,"--M17N %.3f %s\n",
			Time()-m17n->m_Start,wh);
	}
}
#define LAP(wh) Lap(m17n,wh)

int m17n_ccx_init(M17nCCX *m17n,const char *icode,const char *ocode);
M17nCCX *m17n_ccx_new(const char *icode,const char *ocode,void *buf,int siz){
	M17nCCX *m17n;
	if( buf ){
		if( siz < sizeof(M17nCCX) ){
			fprintf(stderr,"--M17n buf. size %d < %d\n",
				siz,isizeof(M17nCCX));
			return 0;
		}
		m17n = (M17nCCX*)buf;
		bzero(m17n,sizeof(M17nCCX));
	}else{
		m17n = (M17nCCX*)malloc(sizeof(M17nCCX));
		bzero(m17n,sizeof(M17nCCX));
		m17n->m_alloc = 1;
	}
	if( icode && ocode ){
		m17n_ccx_init(m17n,icode,ocode);
	}
	return m17n;
}
int m17n_ccx_free(M17nCCX *m17n){
	if( m17n->m_alloc ){
		free(m17n);
		m17n->m_alloc = 0;
	}
	return 0;
}
int m17n_ccx_init(M17nCCX *m17n,const char *icode,const char *ocode){
	m17n->m_Start = Time();
	if( m17n_lib_init() < 0 ){
		return -1;
	}
	LAP("dylib-done");
	m17n_Init();
	LAP("init-done");
	if( icode == 0 ) icode = "utf-8";
	if( (m17n->m_icode = mconv_resolve_coding(msymbol(icode))) == 0 ){
		fprintf(stderr,"--M17N unknown code: %s\n",icode);
		return -2;
	}
	if( ocode == 0 ) ocode = "utf-8";
	if( (m17n->m_ocode = mconv_resolve_coding(msymbol(ocode))) == 0 ){
		fprintf(stderr,"--M17N unknown code: %s\n",ocode);
		return -3;
	}
	LAP("ccx-init-done");
	return 0;
}
int m17n_ccx_opts(M17nCCX *m17n,const char *opts){
	return -1;
}
int m17n_ccx_freeconv(M17nCCX *m17n){
	if( m17n->m_mtext ){
		m17n_object_unref(m17n->m_mtext);
		m17n->m_mtext = 0;
	}
	if( m17n->m_dec ){
		mconv_free_converter(m17n->m_dec);
		m17n->m_dec = 0;
	}
	if( m17n->m_enc ){
		mconv_free_converter(m17n->m_enc);
		m17n->m_enc = 0;
	}
	return 0;
}
int m17n_ccx_string(M17nCCX *m17n,const char *istr,int len,char *ostr,int siz){
	const unsigned char *uistr = (const unsigned char*)istr;
	const unsigned char *uostr = (const unsigned char*)ostr;
	int rcode = -1;
	int ecode;
	int oleng = 1;

	m17n->m_mtext = 0;
	m17n->m_dec = mconv_buffer_converter(m17n->m_icode,uistr,len);
	if( m17n->m_dec == 0 ){
		m17n_ccx_freeconv(m17n);
		return -1;
	}
	m17n->m_enc = mconv_buffer_converter(m17n->m_ocode,uostr,siz-1);
	if( m17n->m_enc == 0 ){
		m17n_ccx_freeconv(m17n);
		return -2;
	}
	LAP("converter-set");

	m17n->m_mtext = mtext();
	m17n->m_dec->lenient = 1;
	mconv_decode(m17n->m_dec,m17n->m_mtext);
	LAP("decoded");
	m17n->m_enc->lenient = 1;
	m17n->m_enc->last_block = 1;
	ecode = mconv_encode(m17n->m_enc,m17n->m_mtext);

	oleng = m17n->m_enc->nbytes;
	ostr[oleng] = 0;
	rcode = oleng;

	LAP("encoded");
	m17n_ccx_freeconv(m17n);
	LAP("filter-done");
	return rcode;
}
int m17n_ccx_filter(M17nCCX *m17n,FILE *in,FILE *out){
	int rcode = -1;
	int ecode;

	m17n->m_mtext = 0;
	m17n->m_dec = mconv_stream_converter(m17n->m_icode,in);
	if( m17n->m_dec == 0 ){
		m17n_ccx_freeconv(m17n);
		return -1;
	}
	m17n->m_enc = mconv_stream_converter(m17n->m_ocode,out);
	if( m17n->m_enc == 0 ){
		m17n_ccx_freeconv(m17n);
		return -2;
	}

	LAP("converter-set");
	m17n->m_mtext = mtext();
	m17n->m_dec->lenient = 1;
	mconv_decode(m17n->m_dec,m17n->m_mtext);
	LAP("decoded");
	m17n->m_enc->lenient = 1;
	m17n->m_enc->last_block = 1;
	ecode = mconv_encode(m17n->m_enc,m17n->m_mtext);
	rcode = 0;

	LAP("encoded");
	m17n_ccx_freeconv(m17n);
	LAP("filter-done");
	return rcode;
}

int m17n_mainX(int ac,const char *av[],FILE *in,FILE *out){
	int ai;
	const char *arg;
	M17nCCX *m17n;
	int fini = 0;

	m17n = (M17nCCX*)m17n_ccx_new(0,0,0,0);
	m17n->m_icnam = "iso-2022-jp";
	m17n->m_ocnam = "iso-2022-jp";
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strneq(arg,"-i",2) ){
			m17n->m_icnam = arg+2;
		}else
		if( strneq(arg,"-o",2) ){
			m17n->m_ocnam = arg+2;
		}else
		if( strneq(arg,"-d",2) ){
			sscanf(arg+2,"%X",&m17n->m_trace);
		}else
		if( strneq(arg,"-x",2) ){
			fini = 1;
		}
	}
	if( m17n_ccx_init(m17n,m17n->m_icnam,m17n->m_ocnam) != 0 ){
		return -1;
	}
	m17n_ccx_filter(m17n,in,out);
	if( fini ){
		m17n_Fini();
	}
	m17n_ccx_free(m17n);
	LAP("finish");
	fflush(out);
	return 0;
}
int m17n_main(int ac,const char *av[]){
	return m17n_mainX(ac,av,stdin,stdout);
}
int m17n_ccx_Filter(PCStr(filter),FILE *in,FILE *out){
	IStr(ab,1024);
	const char *av[32];
	int ac;
	int ai;

	ac = decomp_args(av,elnumof(av),filter,AVStr(ab));
	for( ai = 0; ai < ac; ai++ ){
		syslog_DEBUG("-m17n[%d] %s\n",ai,av[ai]);
	}
	m17n_mainX(ac,av,in,out);
	return 1;
}
