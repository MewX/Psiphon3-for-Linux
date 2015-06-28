/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	schedmain.c (scheduler)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970815	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>

extern int sched_DEBUG;

/*
int LOG_type;
int curLogFd(){ return -1; } 

static tprintf(){
	CStr(ctime,64);
	StrftimeLocal(ctime,sizeof(ctime),"%H:%M:%S",time(0));
	printf("%s ",ctime);
}
syslog_DEBUG(PCStr(fmt),...)
{
VARGS(16,fmt);
      if( sched_DEBUG < 2 )
	return;
      tprintf();
      printf(fmt,VA16);
}
syslog_ERROR(PCStr(fmt),...)
{
VARGS(16,fmt);
      if( sched_DEBUG < 1 )
	return;
      tprintf();
      printf(fmt,VA16);
}
*/

int sched_main(int ac,const char *av[]);
int main(int ac,const char *av[]){ return sched_main(ac,av); }

#include "ystring.h"
#include "../maker/strcasestr.c"
