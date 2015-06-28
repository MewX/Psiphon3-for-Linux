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
Program:	codeconv.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951029	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"

extern int PLAIN_TO_HTML_PRE;
typedef struct {
	int	ce_Enabled;
	MStr(	ce_Charcode,128);
} CodeconvEnv;
static CodeconvEnv *codeconvEnv;
#define Enabled		codeconvEnv->ce_Enabled
#define Charcode	codeconvEnv->ce_Charcode
/**/
static void minit_codeconv()
{
	if( codeconvEnv == 0 )
		codeconvEnv = NewStruct(CodeconvEnv);
}

int codeconv_set(int enable,PCStr(xcharcode),int plain2html)
{
	minit_codeconv();
	if( enable != -1 )
		Enabled = enable;
	if( xcharcode != NULL )
		strcpy(Charcode,xcharcode);
	if( plain2html != -1 )
		PLAIN_TO_HTML_PRE = plain2html;
	return 1;
}
int codeconv_get(PCStr(ctype),const char **xcharset,int *plain2html)
{
	minit_codeconv();
	if( xcharset != NULL ){
		*xcharset = 0;
		if( Enabled ){
		    switch( toupper(Charcode[0]) ){
			case 'J': *xcharset = "ISO-2022-JP"; break;
			case 'E': *xcharset = "X-EUC-JP"; break;
			case 'S': *xcharset = "X-SJIS"; break;
			case 'U': *xcharset = "UTF-8"; break;
		    }
		}
	}
	if( plain2html != NULL )
		*plain2html = PLAIN_TO_HTML_PRE;
	return Enabled;
}
int codeconv_line(PCStr(src),PVStr(dst),PCStr(ctype),int repair)
{
	minit_codeconv();
	if( Enabled ){
		switch( toupper(Charcode[0]) ){
			case 'J': TO_JIS(src,AVStr(dst),ctype); return 0;
			case 'E': TO_EUC(src,AVStr(dst),ctype); return 0;
			case 'S': TO_SJIS(src,AVStr(dst),ctype); return 0;
			case 'U': TO_UTF8(src,AVStr(dst),ctype); return 0;
			default:
			if( strcasecmp(Charcode,"FIX") ){
				(void)FIX_2022((const char*)src,AVStr(dst),ctype);
				return 0;
			}
		}
	}
	strcpy(dst,src);
	return 0;
}
