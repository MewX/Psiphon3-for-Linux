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
Program:	bdtee.c (bidirectional tee)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950707	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "fpoll.h"
int CFI_init(int ac,const char *av[]);

void bdtee_line(int ac,char *av[])
{	FILE *rfv[2],*wfv[2];
	int rdv[2],nready;
	int fpc,fi;
	CStr(line,1024);

	rfv[0] = fdopen(0,"r"); wfv[0] = fdopen(1,"w");
	rfv[1] = fdopen(1,"r"); wfv[1] = fdopen(0,"w");
	fpc = 2;

	for(;;){
		nready = 0;
		for( fi = 0; fi < fpc; fi++ )
			if( 0 < ready_cc(rfv[fi]) )
				nready++;
		if( nready == 0 )
			for( fi = 0; fi < fpc; fi++ )
				fflush(wfv[fi]);

		if( fPollIns(0,fpc,rfv,rdv) < 0 )
			break;

		for( fi = 0; fi < fpc; fi++ ){
		    if( 0 < rdv[fi] ){
			if( fgets(line,sizeof(line),rfv[fi]) == NULL )
				goto gotEOF;
			fputs(line,stderr);
			if( fputs(line,wfv[fi]) == EOF )
				goto gotEOF;
		    }
		}
	}
gotEOF:
	for( fi = 0; fi < fpc; fi++ ){
		fclose(rfv[fi]);
		fclose(wfv[fi]);
	}
}

int main(int ac,char *av[])
{
	CFI_init(ac,(const char**)av);
	bdtee_line(ac,av);
	return 0;
}
