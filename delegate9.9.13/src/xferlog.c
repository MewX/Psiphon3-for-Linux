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
Program:	xferlog.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"

/*
void xferlog(PVStr(log),int start,PCStr(chost),int size,PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser))
*/
void xferlog(PVStr(log),int start,PCStr(chost),FileSize rest,FileSize size,PCStr(md5),PCStr(path),int bin,int in,int anon,PCStr(user),PCStr(auser))
{	CStr(date,1024);
	int now,etime;
	const char *action;
	const char *service;
	CStr(xpath,1024);
	CStr(xuser,256);
	unsigned const char *xp;
	CStr(sizeb,128);

	now = time(0);
	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_ANSI_C,now,0);
	etime = now - start;
	action = "_";
	service = "ftp";

	lineScan(path,xpath);
	for( xp = (unsigned char*)xpath; *xp; xp++ ) if( isspace(*xp) ) *(char*)xp = '_'; /**/
	lineScan(user,xuser);
	for( xp = (unsigned char*)xuser; *xp; xp++ ) if( isspace(*xp) ) *(char*)xp = '_'; /**/

	if( auser != NULL && strcmp(auser,"?") == 0 )
		auser = NULL;

	sprintf(sizeb,"%lld",size);
	if( md5 && md5[0] ){
		Xsprintf(TVStr(sizeb),".%s",md5);
	}
	if( rest )
		Xsprintf(TVStr(sizeb),"+R%lld",rest);
	sprintf(log,"%s %d %s %s %s %s %s %s %s %s %s %d %s",
		date,
		etime,
		chost,
		sizeb,
		xpath,
		bin?"b":"a",
		action,
		in ? "i":"o",
		anon ? "a":"r",
		xuser,
		service,
		auser?1:0,auser?auser:"*"
	);
}
