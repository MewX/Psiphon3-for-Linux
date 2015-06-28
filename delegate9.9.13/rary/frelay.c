/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	fpoll.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970217	extracted from fpoll.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "fpoll.h"

static int relay1(FILE *in,FILE *out)
{	CStr(line,1024);

	if( fgets(line,sizeof(line),in) == NULL )
		return 0;
	if( fputs(line,out) == EOF )
		return 0;
	return 1;
}
int frelay1(FILE *in,FILE *out)
{	int rcc,wcc;
	CStr(buf,1024);

	if( (rcc = fread(buf,1,sizeof(buf),in)) <= 0 )
		return 0;
	if( (wcc = fwrite(buf,1,rcc,out)) <= 0 )
		return 0;
	fflush(out);
	return 1;
}

void frelay(int timeout,int s1,int d1,int s2,int d2,int (*relayfunc)(FILE*,FILE*))
{	FILE *rfv[2]; /**/
	FILE *wfv[2]; /**/
	int rdv[2],nready;
	int fpc,fi;

	rfv[0] = fdopen(s1,"r"); wfv[0] = fdopen(d1,"w");
	rfv[1] = fdopen(s2,"r"); wfv[1] = fdopen(d2,"w");
	fpc = 2;

	if( relayfunc == NULL )
		relayfunc = relay1;

	for(;;){
		nready = 0;
		for( fi = 0; fi < fpc; fi++ )
			if( 0 < ready_cc(rfv[fi]) )
				nready++;
		if( nready == 0 )
			for( fi = 0; fi < fpc; fi++ )
				fflush(wfv[fi]);

		nready = fPollIns(2000,fpc,rfv,rdv);
		if( nready < 0 )
			break;
		if( nready == 0 )
			continue;

		for( fi = 0; fi < fpc; fi++ ){
		    if( 0 < rdv[fi] ){
			if( (*relayfunc)(rfv[fi],wfv[fi]) == 0 )
				goto gotEOF;

if( feof(rfv[fi]) || feof(wfv[fi]) )
	goto gotEOF;

		    }
		}
	}
gotEOF:
	fclose(rfv[0]);
	fclose(rfv[1]);
	fclose(wfv[0]);
	fclose(wfv[1]);
	return;
}

int readsTO(int fd,PVStr(buf),int len,int timeout)
{	int rcc,rc1;

	rcc = 0;

	/* touch the I/O buffer before use,
	 * to confirm stack allocation of the buffer in Solaris2.X cc -O ? */
	setVStrEnd(buf,0);

	while( rcc < len ){
		assertVStr(buf,buf+(len-1));
		if( 0 < rcc && PollIn(fd,timeout) <= 0 )
			break;
		rc1 = read(fd,(char*)buf+rcc,len-rcc);
		if( rc1 <= 0 )
			break;
		rcc += rc1;
	}
	return rcc;
}
int reads(int fd,PVStr(buf),int len)
{
	return readsTO(fd,BVStr(buf),len,0);
}


int relay_file(FILE *in,FILE *out,int sizemax,int timeout,int timemax){
	int total;
	int rcc,wcc;
	CStr(buff,0x10000);
	double Start;

	Start = Time();
	total = 0;
	for(;;){
		if( fPollIn(in,timeout*1000) <= 0 )
			break;
		rcc = fread(buff,1,sizeof(buff),in);
		if( rcc <= 0 )
			break;
		wcc = fwrite(buff,1,rcc,out);
		if( wcc < rcc ){
			break;
		}
		total += rcc;
		if( sizemax && sizemax <= total )
			break;
		if( timemax && timemax <= (Time()-Start) )
			break;
	}
	return total;
}
