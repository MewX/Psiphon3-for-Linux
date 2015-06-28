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
Program:	ipno.c (IP address to serial number)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960422	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "file.h"
#define ADDRLEN	4
#define BLKSIZE	128

static int readno(FILE *fp,PCStr(addr))
{	int num,ni,i;
	CStr(cands,ADDRLEN*BLKSIZE);
	const char *cand;

	num = 0;
	while( ni = fread(cands,ADDRLEN,BLKSIZE,fp) ){
		cand = cands;
		for( i = 0; i < ni; i++ ){
			num++;
			if( cand[0] == addr[0] && cand[1] == addr[1]
			 && cand[2] == addr[2] && cand[3] == addr[3] )
				return num;
			cand += ADDRLEN;
		}
	}
	return 0;
}

int ipno(PVStr(path),PCStr(addr))
{	FILE *fp;
	int i0,i1,i2,i3;
	CStr(buff,4);
	int num;

	i0 = i1 = i2 = i3 = 0;
	sscanf(addr,"%d.%d.%d.%d",&i0,&i1,&i2,&i3);
	buff[0] = i0;
	buff[1] = i1;
	buff[2] = i2;
	buff[3] = i3;

	fp = fopen(path,"r+");
	if( fp != NULL ){
		num = readno(fp,buff);
		if( num != 0 ){
			fclose(fp);
			return num;
		}
	}
	if( fp == NULL )
		fp = dirfopen("ipno",AVStr(path),"w+");
	if( fp == NULL )
		return -1;

	if( lock_exclusiveTO(fileno(fp),2000,NULL) != 0 ){
		sv1log("ERROR: IPNO exclusive lock failed.\n");
		return -1;
	}

	fseek(fp,0,2);
	fwrite(buff,4,1,fp);
	fflush(fp);
	fseek(fp,0,0);

	num = readno(fp,buff);
	fclose(fp);
	return num;
}
