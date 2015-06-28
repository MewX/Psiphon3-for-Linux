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
Content-Type:   program/C; charset=US-ASCII
Program:        ftime.c (portable strftime())
Author:         Yutaka Sato <ysato@etl.go.jp>
Description:
History:
        950203	extracted from ftime.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "vsocket.h"

long Gettimeofday(int *usec)
{	struct timeval tv;

	gettimeofday(&tv, NULL);
	if( usec )
		*usec = tv.tv_usec;
	return tv.tv_sec;
}
double Time()
{	long sec;
	int usec;

	sec = Gettimeofday(&usec);
	return sec + usec / 1000000.0;
}

static double StartTime;
void SetStartTime(){ StartTime = Time(); }
double GetStartTime(){ return StartTime; }

int scanTime(PCStr(sdate));
int date_main(int ac,const char *av[]){
	struct timeval tv;
	int itime = -1;
	int fset = 0;
	int ai;
	const char *a1;
	CStr(date,128);
	int now = time(0);

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( streq(a1,"-s") ){
			fset = 1;
			continue;
		}
		itime = scanTime(a1);
		StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_RFC822,itime,0);
		printf("%s\n",date);
		StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,itime,0);
		printf("%s\n",date);
		printf("%u %X\n",itime,itime);
	}
	if( fset && itime != -1 ){
		//settimeofday(&tv,NULL);
	}
	StrftimeLocal(AVStr(date),sizeof(date),TIMEFORM_RFC822,now,0);
	printf("%s\n",date);
	StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,now,0);
	printf("%s\n",date);
	printf("Unix-Clock: %u %08X\r\n",now,now);
	return 0;
}
