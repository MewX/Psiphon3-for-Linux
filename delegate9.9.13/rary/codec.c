/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	codec.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940731	created
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"

#define T_TEXT		'7'
#define T_LTEXT		'l'
#define T_RTEXT		'r'
#define T_BINARY	'b'
#define T_BASE64	'B'

#define D_BASE	'@'

int encode7(PCStr(srcs),PVStr(encs),int slen)
{	int elen;
	int si,sc;
	char *ep; /**/
	int type;

	type = T_TEXT;
	for( si = 0; si < slen; si++ ){
		sc = srcs[si];
		if( sc == '\r' ){
			if( srcs[si+1] == '\n' && si+2 == slen ){
				type = T_RTEXT;
				goto text7;
			}else	goto binary;
		}
		if( sc == '\n' ){
			if( si+1 == slen ){
				type = T_LTEXT;
				goto text7;
			}else	goto binary;
		}
		if( sc == 033 )
			continue;

		if( sc < 0x20 || 0x7F <= sc )
			goto binary;
	}

text7:
	setVStrElem(encs,0,type);
	Xstrncpy(DVStr(encs,1),srcs,slen);
	elen = 1 + slen;
	if( type == T_TEXT ){
		Xstrcpy(DVStr(encs,1+slen),"\n");
		elen += 1;
	}
	return elen;

binary:
	setVStrElem(encs,0,T_BINARY);
	ep = (char*)encs+1;
	for( si = 0; si < slen; si++ ){
		assertVStr(encs,ep+4);
		sc = srcs[si] & 0xFF;
		*ep++ = (sc >> 4)  + D_BASE;
		*ep++ = (sc & 0xF) + D_BASE;
	}
	*ep++ = '\n';
	*ep = 0;
	elen = ep - encs;
	return elen;
}

int decode7(PCStr(encs),PVStr(srcs))
{	int type,slen;
	const char *ep;
	refQStr(sp,srcs); /**/
	refQStr(dp,srcs); /**/
	int ec1;
			
	type = encs[0];

	if( type == T_BINARY ){
		cpyQStr(sp,srcs);
		for( ep = encs+1; ec1 = *ep; ep += 2 ){
			assertVStr(srcs,sp+1);
			if( ec1 == '\r' || ec1 == '\n' )
				break;
			setVStrPtrInc(sp,((ec1-D_BASE) << 4) | (ep[1]-D_BASE));
		}
		setVStrEnd(sp,0);
		slen = sp - srcs;
	}else
	{
		if( type == T_TEXT || type == T_LTEXT || type == T_RTEXT ){
			strcpy(srcs,encs+1);
			if( dp = strpbrk(srcs,"\r\n") ){
				switch( type ){
					case T_TEXT: setVStrEnd(dp,0); break;
					case T_LTEXT: strcpy(dp,"\n"); break;
					case T_RTEXT: strcpy(dp,"\r\n"); break;
				}
			}
		}else	strcpy(srcs,encs);

		slen = strlen(srcs);
	}
	return slen;
}

/*
#include <stdio.h>
main(ac,av)
	char *av[];
{	int src[128],enc[128];

	fgets (src,sizeof(src),stdin);
	encode7(src,enc,strlen(src));
	printf(">%s\n",enc);
	decode7(enc,src);
	printf("=[%d]%s\n",strlen(src),src);
}
*/
