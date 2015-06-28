/*///////////////////////////////////////////////////////////////////////
Copyright (c) 2000 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 2000 Yutaka Sato

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	uu.c (uuencode format)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	000616	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"

int uudec_body(PCStr(src),PVStr(dst))
{	const char *sp;
	char sc;
	refQStr(dp,dst); /**/
	int scb;
	int len,ci,cx,co;

	setVStrEnd(dst,0);
	len = *src - 040;
	if( len == 64 )
		return 0;
	if( len < 0 || 64 < len )
		return -1;

	ci = 0;
	co = 0;
	cx = 0;
	for( sp = src+1; ci++ < 64 && (sc = *sp); sp++ ){
		if( sc == '\r' || sc == '\n' )
			break;
		scb = sc - 040;
		if( scb < 0 || 64 < scb ){
			setVStrEnd(dp,0);
			return -1;
		}
		switch( cx ){
		case 0: co = scb << 2; break;
		case 1: setVStrPtrInc(dp,co | 0x03 & (scb >> 4)); co = scb << 4; break;
		case 2: setVStrPtrInc(dp,co | 0x0F & (scb >> 2)); co = scb << 6; break;
		case 3: setVStrPtrInc(dp,co | 0x3F & (scb)); break;
		}
		cx = (cx + 1) & 0x3;
	}
	setVStrEnd(dp,0);
	return len;
}
int uu_skip(int *ctx,PCStr(src))
{	CStr(dst,64);

	if( *ctx == 0 ){
		if( strncmp(src,"begin ",6) == 0 ){
			*ctx = 1;
			return 1;
		}
		return 0;
	}else{
		if( strncmp(src,"end",3) == 0 ){
			*ctx = 0;
			return 1;
		}
		if( uudec_body(src,AVStr(dst)) < 0 ){ /* non-uu format */
			*ctx = 0;
			return 0;
		}
		return 1;
	}
}
int uudec_main(int ac,const char *av[])
{	CStr(src,64);
	CStr(dst,64);
	int len;

	for(;;){
		while( fgets(src,sizeof(src),stdin) )
			if( strncmp(src,"begin ",6) == 0 )
				break;
		if( feof(stdin) )
			break;
		while( fgets(src,sizeof(src),stdin) ){
			if( strncmp(src,"end",3) == 0 )
				break;
			len = uudec_body(src,AVStr(dst));
			fwrite(dst,1,len,stdout);
		}
		if( feof(stdin) )
			break;
	}
	return 0;
}
