/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	qzcode.c (quoted-printable based compression code)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950624	created
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "teleport.h"

#define QZ_BASE		0x0001
#define QZ_PRINT	0x0002
#define QZ_ZERO		0x0004
#define QZ_WORD		0x0008
#define QZ_LENG		0x0010

#define QZ1		(QZ_BASE|QZ_PRINT|QZ_ZERO|QZ_WORD|QZ_LENG)
#define QZ2		(QZ_BASE|QZ_PRINT|QZ_ZERO|QZ_WORD)
#define QZ3		(QZ_BASE|QZ_ZERO)

#define TOHEX(d)	"0123456789ABCDEF"[d]
#define FROMHEX(x)	(isdigit(x)?(x-'0'):(x-'A'+10))
#define QZM		"=QZ"
#define QZMLEN		(sizeof(QZM)-1)

typedef struct {
	int qe_ctx_code[128];
} QZcodeEnv;
static QZcodeEnv *qZcodeEnv;
#define ctx_code	qZcodeEnv->qe_ctx_code
void minit_qzcode()
{
	if( qZcodeEnv == 0 )
		qZcodeEnv = NewStruct(QZcodeEnv);
}

void QZinit(int ctx)
{
	minit_qzcode();
	ctx_code[ctx] = QZ1;
}
void QZswitch(int ctx,int code)
{	int ocode,ncode;

	minit_qzcode();
	ocode = ncode = ctx_code[ctx];
	switch( code ){
		case '1': ncode = QZ1; break;
		case '2': ncode = QZ2; break;
		case '3': ncode = QZ3; break;
		default:
			sv1tlog("UNKNOWN code = %X\n",code);
			break;
	}
	if( ncode != ocode ){
		ctx_code[ctx] = ncode;
		sv1log("[%d] code = QZ[%c][%d]\n",ctx,code,ncode);
	}
}
void QZident(int ctx,PVStr(ver))
{	refQStr(vp,ver); /**/
	int code;

	minit_qzcode();
	cpyQStr(vp,ver);
	code = ctx_code[ctx];
	if( code & QZ_BASE  ){ sprintf(vp,"BASE|");  vp += strlen(vp); }
	if( code & QZ_PRINT ){ sprintf(vp,"PRINT|"); vp += strlen(vp); }
	if( code & QZ_ZERO  ){ sprintf(vp,"ZERO|");  vp += strlen(vp); }
	if( code & QZ_WORD  ){ sprintf(vp,"WORD|");  vp += strlen(vp); }
	if( ver < vp )
		setVStrEnd(vp,-1);
}

int QZencode(int ctx,PCStr(prefix),PVStr(buf),PCStr(ibuf),int len)
{	refQStr(bp,buf);
	int ci,cj,ch,nch,zlen,olen;
	int code;

	minit_qzcode();
	code = ctx_code[ctx];
	if( code == 0 )
		code = QZ1;

	cpyQStr(bp,buf);
	olen = 0;
	for( ci = 0; ci < len; ci++ ){
		if( olen == 0 && prefix && prefix[0] ){
			strcpy(bp,prefix);
			olen = strlen(bp);
			bp += olen;
		}
		ch = ibuf[ci];
		nch = ibuf[ci+1];
		if( ch == 0 && (code & QZ_WORD) && ci+1 < len && nch != 0 ){
			setVStrPtrInc(bp,'=');
			setVStrPtrInc(bp,'W');
			setVStrPtrInc(bp,TOHEX(((nch >> 4) & 0xF)));
			setVStrPtrInc(bp,TOHEX((nch & 0xF)));
			ci += 1;
			olen += 4;
		}else
		if( ch == 0 && (code & QZ_ZERO) ){
			zlen = 0;
			for( cj = ci; cj < len; cj++ )
				if( ibuf[cj] != 0 || 15 <= ++zlen )
					break;
			setVStrPtrInc(bp,'=');
			setVStrPtrInc(bp,'Z');
			setVStrPtrInc(bp,TOHEX(zlen));
			ci += zlen - 1;
			olen += 3;
		}else
		if( ch == '=' || ch == 0 || ch == '\n' || ch == '\r'
		 || (code & QZ_PRINT) && (ch<0x20 || 0x7F<=ch) )
		{
			setVStrPtrInc(bp,'=');
			setVStrPtrInc(bp,TOHEX(((ch >> 4) & 0xF)));
			setVStrPtrInc(bp,TOHEX((ch & 0xF)));
			olen += 3;
		}
		else{
			setVStrPtrInc(bp,ch);
			olen += 1;
		}

/*
		if( (code & QZ_LENG) &&  75 < olen && ci+1 <len ){
*/
		if( (code & QZ_LENG) &&  120 < olen && ci+1 <len ){
			for( cj = 0; ch = QZM[cj]; cj++ )
				setVStrPtrInc(bp,ch);
			setVStrPtrInc(bp,'\n');
			olen = 0;
		}
	}
	for( cj = 0; ch = QZM[cj]; cj++ )
		setVStrPtrInc(bp,ch);

/* DEBUG FOR Vehicle */
/*
*bp++ = '\r';
*bp++ = '\n';
*/

	setVStrPtrInc(bp,'\n');
	setVStrEnd(bp,0);
	return bp - buf;
}

#define isxdigit2(s)	( isxdigit((s)[0]) && isxdigit((s)[1]) )

int QZdecode(int ctx,PVStr(obuf),PCStr(buf),int len)
{	refQStr(bp,obuf);
	int qpmx,ci,cj,ch,zlen,hi,lo;
	int type;

	for( qpmx = len-1; QZMLEN <= qpmx; qpmx-- ) 
		if( buf[qpmx] != '\r' && buf[qpmx] != '\n' )
			break;
	qpmx -= QZMLEN-1;
	if( qpmx < 0 )
		return -1;

	for( ci = 0; ch = QZM[ci]; ci++ )
		if( buf[qpmx+ci] != ch )
			return -1;
	len = qpmx;

	cpyQStr(bp,obuf);
	for(ci = 0; ci < len; ){
		ch = buf[ci++];

		if( ch == '\n' || ch == '\r' || ch == 0 )
			continue;

		if( ch == '=' && buf[ci] == 'Q' ){
			QZswitch(ctx,buf[ci+1]);
			ci += 2;
		}else
		if( ch == '=' && buf[ci] == 'Z' ){
			zlen = FROMHEX(buf[ci+1]);
			for( cj = 0; cj < zlen; cj++ )
				setVStrPtrInc(bp,0);
			ci += 2;
		}else
		if( ch == '=' && buf[ci] == 'W' && isxdigit2(&buf[ci+1]) ){
			setVStrPtrInc(bp,0);
			ci++;
			goto HEX1;
		}else
		if( ch == '=' && isxdigit2(&buf[ci]) ){
	HEX1:		hi = buf[ci++]; hi = FROMHEX(hi);
			lo = buf[ci++]; lo = FROMHEX(lo);
			setVStrPtrInc(bp,(hi << 4) | lo);
		}else	setVStrPtrInc(bp,ch);
	}
	return bp-obuf;
}
