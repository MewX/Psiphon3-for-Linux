/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	mimecodes.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	980910	created
//////////////////////////////////////////////////////////////////////#*/
#include "mime.h"

#define CR	'\r'
#define LF	'\n'
#define SP	' '
#define TAB	'\t'
#define EQ	'='

static char B64CH[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define NON64	((char)-1)
#define WHITE	((char)-2)
#define PADDCH	((char)-3)
static char *B64IX;

static void init_64()
{	int ix;

	B64IX = (char*)StructAlloc(0x100);
	for( ix = 0; ix < 0x100; ix++ )
		B64IX[ix] = NON64;
	B64IX[SP] = B64IX[TAB] = B64IX[CR] = B64IX[LF] = WHITE;
	B64IX[EQ] = PADDCH;
	for( ix = 0; ix < 64; ix++ )
		B64IX[B64CH[ix]] = ix;
}

#define QP_THRU	 1
#define QP_ESC	(char)-1
static char *QPIX;
static void init_QP()
{	int ix;

	QPIX = (char*)StructAlloc(0x100);
	for( ix = 0; ix < 0x100; ix++ ){
		if( 0x80 <= ix || iscntrl(ix) && !isspace(ix) || ix == EQ )
			QPIX[ix] = QP_ESC;
		else	QPIX[ix] = QP_THRU;
	}
}
void MIME_setQP(PCStr(qpchars))
{	int ch;

	init_QP();
	while( ch = *qpchars++ )
		QPIX[ch] = QP_ESC;
}

void MIME_to64X(FILE *in, FILE *out, int leng);
void MIME_to64(FILE *in, FILE *out)
{
	MIME_to64X(in,out,0);
}
void MIME_to64X(FILE *in, FILE *out, int leng)
{	int gotEOF,ich,ocol,ix,oint,shifts,o1,ox,icc;

	gotEOF = 0;
	ocol = 0;
	icc = 0;
	while( !gotEOF ){
		oint = 0;
		shifts = 16;
		for( ix = 0; ix < 3; ix++ ){
			if( 0 < leng && leng < ++icc ){
				gotEOF = 1;
				break;
			}
			ich = getc(in);
			if( ich == EOF ){
				gotEOF = 1;
				break;
			}
			oint |= (ich << shifts);
			shifts -= 8;
		}
		if( ix == 0 )
			break;
		if( 71 < ocol ){
			putc(LF,out);
			ocol = 0;
		}
		shifts = 18;
		for( ox = 0; ox <= ix; ox++ ){
			o1 = (oint >> shifts) & 0x3F;
			shifts -= 6;
			putc(B64CH[o1],out);
		}
		for(; ox < 4; ox++ )
			putc(EQ,out);
		ocol += 4;
	}
	if( 0 < ocol )
		putc(LF,out);
	fflush(out);
}

#ifndef MIME_to64
int strtoB64(PCStr(str),int slen,PVStr(b64),int bsiz,int withnl){
	refQStr(bp,b64);
	int gotEOF = 0;
	int ich,ocol,ix,oint,shifts,o1,ox,icc;

	ocol = 0;
	for( icc = 0; !gotEOF && icc < slen; ){
		oint = 0;
		shifts = 16;
		for( ix = 0; ix < 3; ix++ ){
			if( slen <= icc ){
				gotEOF = 1;
				break;
			}
			ich = 0xFF & str[icc++];
			oint |= (ich << shifts);
			shifts -= 8;
		}
		if( ix == 0 )
			break;
		if( 71 < ocol ){
			if( withnl )
				setVStrPtrInc(bp,LF);
			ocol = 0;
		}
		shifts = 18;
		for( ox = 0; ox <= ix; ox++ ){
			o1 = (oint >> shifts) & 0x3F;
			shifts -= 6;
			setVStrPtrInc(bp,B64CH[o1]);
		}
		for(; ox < 4; ox++ )
			setVStrPtrInc(bp,EQ);
		ocol += 4;
	}
	if( withnl && 0 < ocol )
		setVStrPtrInc(bp,LF);
	setVStrEnd(bp,0);
	return bp - b64;
}
int B64tostr(PCStr(b64),int blen,PVStr(str),int slen){
	refQStr(sp,str);
	int icc;
	int gotEOF,ich,ix,ii,i1,ox,oint,o1,shifts;

	if( B64IX == 0 )
		init_64();

	gotEOF = 0;
	for( icc = 0; !gotEOF && icc < blen; ){
		ix = 0;
		oint = 0;
		shifts = 18;
		for( ii = 0; ii < 4; ){
			if( blen <= icc ){
				if( ix != 0 )
					syslog_ERROR("BASE64 premature EOF\n");
				gotEOF = 1;
				break;
			}
			ich = b64[icc++];
			i1 = B64IX[ich];
			if( i1 == NON64 ){
				syslog_ERROR("BASE64 unrecognized CHAR(0x%x)\n",
					ich);
				gotEOF = 1;
				break;
			}
			if( i1 == WHITE )
				continue;

			if( i1 == PADDCH ){
				ii++;
				continue;
			}
			oint |= (i1 << shifts);
			shifts -= 6;
			ix++;
			ii++;
		}
		if( ix == 0 )
			break;

		shifts = 16;
		for( ox = 1; ox < ix; ox++ ){
			o1 = (oint >> shifts) & 0xFF;
			shifts -= 8;
			setVStrPtrInc(sp,o1);
		}
	}
	setVStrEnd(sp,0);
	return sp - str;
}
#endif

void MIME_from64(FILE *in, FILE *out)
{	int gotEOF,ich,ix,ii,i1,ox,oint,o1,shifts;

	if( B64IX == 0 )
		init_64();

	gotEOF = 0;
	while( !gotEOF ){
		ix = 0;
		oint = 0;
		shifts = 18;
		for( ii = 0; ii < 4; ){
			ich = getc(in);
			if( ich == EOF ){
				if( ix != 0 )
					syslog_ERROR("BASE64 premature EOF\n");
				gotEOF = 1;
				break;
			}
			i1 = B64IX[ich];
			if( i1 == NON64 ){
				syslog_ERROR("BASE64 unrecognized CHAR(0x%x)\n",
					ich);
				ungetc(ich,in);
				gotEOF = 1;
				break;
			}
			if( i1 == WHITE )
				continue;

			if( i1 == PADDCH ){
				ii++;
				continue;
			}
			oint |= (i1 << shifts);
			shifts -= 6;
			ix++;
			ii++;
		}
		if( ix == 0 )
			break;

		shifts = 16;
		for( ox = 1; ox < ix; ox++ ){
			o1 = (oint >> shifts) & 0xFF;
			shifts -= 8;
			putc(o1,out);
		}
	}
	fflush(out);
}

#define GETC1(ch,in,exit)	{ch = getc(in); if( ch == EOF ) goto exit;}
static char hexd[] = "0123456789ABCDEF";

void MIME_toQP(FILE *in, FILE *out)
{	int ich,ocol;

	if( QPIX == 0 )
		init_QP();

	ocol = 0;
	for(;;){
		GETC1(ich,in,EXIT);
		if( QPIX[ich] == QP_ESC
		 || ocol == 0 && ich == '.'
		){
			putc(EQ,out);
			putc(hexd[0xF&(ich>>4)],out);
			putc(hexd[0xf&(ich)],out);
			ocol += 3;
		}else
		if( ich == LF ){
			putc(ich,out);
			ocol = 0;
		}else{
			putc(ich,out);
			ocol += 1;
		}
		if( 72 < ocol ){
			putc(EQ,out);
			putc(LF,out);
			ocol = 0;
		}
	}
EXIT:
	if( 0 < ocol ){
		putc(EQ,out);
		putc(LF,out);
	}
	return;
}

void MIME_fromQP(FILE *in, FILE *out)
{	int ch1,ch2,softnl,och;
	CStr(buf,3);

	softnl = 0;
	buf[2] = 0;
	for(;;){
		GETC1(ch1,in,EXIT);
		och = ch1;
		if( ch1 == EQ ){
			GETC1(ch1,in,EXIT);
			if( ch1 == CR ){
				GETC1(ch2,in,EXIT);
				if( ch2 == LF )
					ch1 = LF;
				else	ungetc(ch2,in);
			}
			if( ch1 == LF ){
				continue;
			}else
			if( !isxdigit(ch1) ){
				putc(EQ,out);
				putc(ch1,out);
				continue;
			}else{
				GETC1(ch2,in,EXIT);
				if( !isxdigit(ch2) ){
					putc(EQ,out);
					putc(ch1,out);
					putc(ch2,out);
					continue;
				}
				buf[0] = ch1;
				buf[1] = ch2;
				sscanf(buf,"%x",&och);
			}
		}
		putc(och,out);
	}
EXIT:
	return;
}
