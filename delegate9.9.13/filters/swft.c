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
Content-Type:	program/C; charset=US-ASCII
Program:	swft.c (SWF translator)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	040221	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "dgctx.h"

#define TRACE	syslog_ERROR
int reverseMOUNT(DGC*ctx,PVStr(url),int siz);

/*
static char REC_DefineButton2[] = {34,UI16,UI8,UI16,BRREC,UI8,ACTIONS};
*/
typedef struct {
	DGC	*s_ctx;

	int	 s_hsig[3];
	int	 s_hver;
	int	 s_leng;
	int	 s_frate;
	int	 s_fcount;

	FILE	*s_in;
	FILE	*s_out;
	int	 s_ioff;
	int	 s_ich;
	MStr(	 s_ibuf,0x10000);
	int	 s_ibrem;
	int	 s_ibi;

  const	char	*s_path_base;
	int	 s_nrew;
	int	 s_ninc;

	int	 s_ooff;
} Swf;

#define PUTC(ch)	(swf->s_ooff++, (swf->s_out ? putc(ch,swf->s_out):0))

static int byf = 0;
static int GETCF(Swf *swf)
{ 
	swf->s_ich = getc(swf->s_in);
	if( swf->s_ich != EOF ){
		swf->s_ioff++;
		if( 0 < swf->s_ibrem ){
			swf->s_ibuf[swf->s_ibi++] = swf->s_ich;
			swf->s_ibrem--;
		}
	}
	return swf->s_ich;
}
#define GETCM(swf) \
		(swf->s_ioff++, \
		(swf->s_ich = getc(swf->s_in)), PUTC(swf->s_ich), swf->s_ich)

#define GETC()	((0<swf->s_ibrem) ? GETCF(swf):GETCM(swf))
/*
#define GETC()	GETCF(swf)
*/

#define GETUI8()	(GETC())
#define GETUI16()	(GETC() | (GETC()<<8))
#define GETUI32()	(GETC() | (GETC()<<8) | (GETC()<<16) | (GETC()<<24))

#define PUTUI32(obuf,olen) {\
	obuf[0] = olen; \
	obuf[1] = olen >> 8; \
	obuf[2] = olen >> 16; \
	obuf[3] = olen >> 24; \
}

static void swf_MOUNT(Swf *swf,int code,int alen,PVStr(urlp))
{	int rewrite,inc;
	refQStr(up,urlp); /**/
	CStr(ourl,8);

	swf->s_ibuf[swf->s_ibi] = 0;
	up = (char*)urlp + 3;
	strncpy(ourl,up,sizeof(ourl)); setVStrEnd(ourl,sizeof(ourl)-1);

	rewrite = 0;
	if( reverseMOUNT(swf->s_ctx,QVStr(up,urlp),256) ){
		rewrite = 1;
		inc = strlen(up) - alen;
	}else
	if( *up == '/' ){
		const char *rp;
		int rplen;

		rewrite = 2;
		if( rp = swf->s_path_base ){
			if( rp[strlen(rp)-1] == '/' )
				inc = strlen(rp) - 1;
			else	inc = strlen(rp);
		}else{
			rp = ".";
			inc = 1;
		}
		rplen = strlen(rp);
		bcopy(up,(char*)up+inc,alen+1);
		Bcopy(rp,up,rplen);
	}
	if( rewrite ){
		swf->s_ibi += inc;
		alen += inc;
		setVStrElem(urlp,1,alen);
		setVStrElem(urlp,2,alen << 8);

		swf->s_nrew++;
		swf->s_ninc += inc;

		TRACE("GetURL: %s... -> %s\n",ourl,up);
	}else{
		TRACE("GetURL: %s\n",up);
	}
}

static void swf_rect(Swf *swf)
{	int ch,blen,bits,by,bi;

	ch = GETC();
	blen = ch>>3;
	bits = 5 + blen*4;
	by = (bits+7)/8;
	for( bi = 1; bi < by; bi++ )
		GETC();
}
static void swf_pr_head(Swf *swf)
{
	TRACE("SWF Version: %d\n",swf->s_hver);
	TRACE("SWF File-Length: %d\n",swf->s_leng);
	/*
	TRACE("SWF Frame-Rate: %d.%d\n",
		0xFF&(swf->s_frate>>8),0xFF&swf->s_frate);
	TRACE("SWF Frame-Count: %d\n",swf->s_fcount);
	*/
}
static int swf_head(Swf *swf)
{ 
	swf->s_hsig[0] = GETUI8();
	swf->s_hsig[1] = GETUI8();
	swf->s_hsig[2] = GETUI8();
	swf->s_hver = GETUI8();
	swf->s_leng = GETUI32();
	swf_rect(swf);
	swf->s_frate = GETUI16();
	swf->s_fcount = GETUI16();
	swf_pr_head(swf);

	if( swf->s_hsig[0] != 'F' && swf->s_hsig[0] != 'C' ) return -1;
	if( swf->s_hsig[1] != 'W' ) return -1;
	if( swf->s_hsig[2] != 'S' ) return -1;
	return 0;
}
static void swf_action(Swf *swf,int end)
{	int acti,alen,code,di;
	MrefQStr(urlp,swf->s_ibuf); /**/

	for( acti = 0;; acti++ ){
		urlp = swf->s_ibuf+swf->s_ibi;
		code = GETC();
		alen = 0;
		if( code == 0 )
			break;
		if( code & 0x80 )
			alen = GETUI16();
		if( 0 < alen ){
			for( di = 0; di < alen; di++ ){
				GETC();
			}
			if( code == 0x83 && swf->s_out != NULL ){ 
				swf_MOUNT(swf,code,alen,AVStr(urlp));
			}
		}
	}
}
static void swf_bcaction(Swf *swf,int end)
{	int size;

	size = GETUI16();
	GETUI8(); /* UB[1]*8 */
	GETUI8(); /* UB[7]+UB[1] */
	swf_action(swf,end);
}
static void swf_definebutton2(Swf *swf,int end)
{	int bi,actoff;

	GETUI16(); /* ID */
	GETUI8(); /* UI7 + UI1 */
	actoff = GETUI16(); /* offset to action if exist */
	if( 0 < actoff ){
		for( bi = 0; bi < actoff-2; bi++ ){
			GETC();
		}
		for(;;){
			swf_bcaction(swf,end);
			if( end <= swf->s_ioff ){
				break;
			}
		}
	}else{
		for(;;){
			if( GETC() <= 0 )
				break;
		}
	}
}
static int swf_tag(Swf *swf)
{	int ch1,ch2,tag,ttyp,tlen,tend,bi,ooff,olen;

	swf->s_ibrem = sizeof(swf->s_ibuf);
	swf->s_ibi = 0;

	ch1 = GETC();
	if( ch1 < 0 )
		return 0;
	ch2 = GETC();
	if( ch1 < 0 )
		return 0;
	tag = (ch2 << 8) | ch1;
	ttyp = tag >> 6;
	tlen = tag & 0x3F;
	if( tlen == 0x3F )
		tlen = GETUI32();
	ooff = swf->s_ibi;
	tend = swf->s_ioff + tlen;

	switch( ttyp ){
		case 12: swf_action(swf,tend); break;
		case 34: swf_definebutton2(swf,tend); break;
		default:
			for( bi = 0; bi < tlen; bi++ )
				GETC();
	}
	olen = swf->s_ibi - ooff;
	if( olen == tlen ){
		fwrite(swf->s_ibuf,1,swf->s_ibi,swf->s_out);
		swf->s_ooff += swf->s_ibi;
	}else{
		if( olen < 0x3F ){
			ch1 = (ch1 & ~0x3F) | olen;
			PUTC(ch1);
			PUTC(ch2);
		}else{
			CStr(obuf,4);
			ch1 |= 0x3F;
			PUTC(ch1);
			PUTC(ch2);
			PUTUI32(obuf,olen);
			fwrite(obuf,1,4,swf->s_out);
			swf->s_ooff += 4;
		}
		fwrite(swf->s_ibuf+ooff,1,olen,swf->s_out);
		swf->s_ooff += olen;
	}

	if( ttyp == 0 )
		return 0;
	return 1;
}

#define SIZEINC	256 /* max. increased size of .swf by rewritig URL */

FileSize copyfile1(FILE*in,FILE*out);
void swfFilter(DGC*ctx,FILE *in,FILE *out,PCStr(arg))
{	Swf swfb,*swf = &swfb;
	int nt,ch,xleng;
	char *lenp; /**/

	bzero(swf,sizeof(Swf));
	swf->s_ctx = ctx;
	swf->s_path_base = getenv("SCRIPT_NAME_BASE");
	swf->s_in = in;
	swf->s_out = out;
	swf->s_ioff = 0;
	swf->s_ibi = 0;
	swf->s_ibrem = 0;
	swf->s_ooff = 0;

	swf->s_ibrem = sizeof(swf->s_ibuf);
	swf->s_ibi = 0;
	if( swf_head(swf) < 0 )
		return;

	if( swf->s_ibuf[0] == 'C' ){
		TRACE("Not supported Compressed SWF: %d\n",swf->s_hver);
		if( 0 < swf->s_ibi ){
			fwrite(swf->s_ibuf,1,swf->s_ibi,out);
		}
		copyfile1(in,out);
		return;
	}
	if( swf->s_hver < 5 ){
		TRACE("Not supported Ver? %d (%d)\n",swf->s_hver,swf->s_ibi);
		if( 0 < swf->s_ibi ){
			fwrite(swf->s_ibuf,1,swf->s_ibi,out);
		}
		copyfile1(in,out);
		return;
	}

	/* the real-length should be rewriten after conversion,
	 * if the output file is not stream (seekable)
	 */
	xleng = swf->s_leng+SIZEINC;
	lenp = swf->s_ibuf+4;
	PUTUI32(lenp,xleng);

	fwrite(swf->s_ibuf,1,swf->s_ibi,swf->s_out);
	swf->s_ibrem = 0;
	swf->s_ibi = 0;

	for( nt = 0;; nt++ ){
		if( swf_tag(swf) == 0 )
			break;
		if( swf->s_leng <= swf->s_ioff ){
			break;
		}
	}
	if( 0 < swf->s_ibi ){
		fwrite(swf->s_ibuf,1,swf->s_ibi,swf->s_out);
		swf->s_ibi = 0;
	}

	while( swf->s_ooff < xleng )
		PUTC(0);

	fflush(swf->s_out);

/*
	swf->s_ibrem = 0;
	for(;;){
		ch = GETC();
		if( ch == EOF )
			break;
		PUTC(ch);
	}
*/
	TRACE("DONE %d/%d -> %d (+%d/%d)\n",swf->s_ioff,
		swf->s_leng,swf->s_ooff,swf->s_ninc,swf->s_nrew);
}

int swft_main(int ac,const char *av[])
{
	swfFilter(NULL,stdin,stdout,"");
	return 0;
}
