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
Program:	pstitle.c (process title for ps command)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950328	created
	991205	simplified and no exec version
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
int IsBOW1_5();
int FS_maybeUnix();

int PSTITLE_DISABLE;
struct _pstitle_area { defQStr(p); } pstitle_area;
int   pstitle_size;
int   pstitle_leng;
int   pstitle_lengmax = 2048;

#if defined(__hpux__)
#include <sys/pstat.h>
static int p_title(PCStr(buf)){
	union pstun un;
	un.pst_command = (char*)buf;
	pstat(PSTAT_SETCMD,un,strlen(buf),0,0);
	return 0;
}
#else
#if defined(hpux)
#include <sys/pstat.h>
static int p_title(PCStr(buf))
{
	pstat(PSTAT_SETCMD,buf,0,0,0);
	return 0;
}
#else
#if defined(__sony_news) && defined(_SYSTYPE_SYSV)
#include <sys/sysnews.h>
#include <sys/sysmips.h>
static int p_title(PCStr(buf))
{
	sysmips(SONY_SYSNEWS,NEWS_SETPSARGS,buf);
	return 0;
}
#else
int IsMacOSX();
static int p_title(PCStr(buf))
{
	if( Setproctitle("-%s",buf) == 0 )
		return 0;
	if( pstitle_area.p ){
		XStrncpy(AVStr(pstitle_area.p),buf,pstitle_size); /**/
		if( IsMacOSX() ){
			/* 9.9.5 for Darwin 9.X (filling by main_argc seems enough) */
			int ti;
			int len = strlen(buf);
			for( ti = len; ti < pstitle_size; ti++ ){
				setVStrElem(pstitle_area.p,ti,0);
			}
		}
		return 0;
	}else	return -1;
}
#endif
#endif
#endif

int FMT_proc_title(PCStr(fmt),...)
{	CStr(buf,2048);
	VARGS(8,fmt);

	if( PSTITLE_DISABLE )
		return 0;

	if( !FS_maybeUnix() || IsBOW1_5() ){
		PSTITLE_DISABLE = 1;
		return 0;
	}

	sprintf(buf,fmt,VA8);
	if( sizeof(buf) <= strlen(buf) ){
		syslog_ERROR("PSTITLE overflow: %d / %d / %d > %d\n",
			istrlen(buf),pstitle_size,pstitle_leng,isizeof(buf));
		buf[sizeof(buf)-1] = 0;
		syslog_ERROR("PSTITLE overflow: %s\n",buf);
		Finish(-1);
	}
	return p_title(buf);
}
