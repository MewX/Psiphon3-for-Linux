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
Program:	bdthru.c (bidirectional relay through)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	990311	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "fpoll.h"
int CFI_init(int ac,const char *av[]);

void bdthru(int ac,char *av[])
{	int rfv[2],wfv[2];
	int rdv[2],nready;
	int fdc,fi,rcc,wcc;
	int icc[2],occ[2];
	CStr(buff,1024);

	rfv[0] = 0; wfv[0] = 1;
	rfv[1] = 1; wfv[1] = 0;
	fdc = 2;

	icc[0] = icc[1] = 0;
	occ[0] = occ[1] = 0;

	for(;;){
		nready = 0;
		if( PollIns(0,fdc,rfv,rdv) < 0 )
			break;

		for( fi = 0; fi < fdc; fi++ ){
		    if( 0 < rdv[fi] ){
			rcc = read(rfv[fi],buff,sizeof(buff));
			if( rcc <= 0 )
				goto gotEOF;
			icc[fi] += rcc;
			wcc = write(wfv[fi],buff,rcc);
			if( wcc != rcc )
				goto gotEOF;
			occ[fi] += wcc;
		    }
		}
	}
gotEOF:
	fprintf(stderr,"*** bdthru done: clnt=%di+%do serv=%di+%do\r\n",
		icc[0],occ[0],icc[1],occ[1]);
}

int main(int ac,char *av[])
{
	CFI_init(ac,(const char**)av);
	bdthru(ac,av);
	return 0;
}
