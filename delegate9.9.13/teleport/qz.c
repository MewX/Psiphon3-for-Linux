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
Program:	qz.c (QZcode command interface)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950624	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <ctype.h>

static int  f_decode = 0;
static char f_qzver = '1';

#define MSGSIZE	(1024*8)

void main(int ac,char *av[])
{	int ai;
	const char *arg;
	CStr(ident,128);

	for( ai = 0; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-d") == 0 )
			f_decode = 1;
		if( arg[0]=='-' && arg[1]=='q' )
			f_qzver = arg[2];
	}
	if( !isdigit(f_qzver) ){
		fprintf(stderr,"Usage: -qN where N is [0-9].\n");
		exit(0);
	}

	QZinit(0);
	QZswitch(0,f_qzver);
	QZident(0,ident);

	if( f_decode )
		decode(stdin,stdout);
	else{
		fprintf(stderr,"QZtype: Q%c [%s]\n",f_qzver,ident);
		encode(stdin,stdout);
	}
}
void encode(FILE *in,FILE *out)
{	CStr(ibuf,256);
	CStr(obuf,MSGSIZE);
	int rcc,wcc,rcctotal,wcctotal;

	rcctotal = 0;
	wcctotal = 0;
	while( rcc = fread(ibuf,1,sizeof(ibuf),in) ){
		rcctotal += rcc;
		wcc = QZencode(0,"",obuf,ibuf,rcc);
		wcctotal += wcc;
		fwrite(obuf,1,wcc,out);
	}
	fprintf(stderr,"%d/%d\n",wcctotal,rcctotal);
}
void decode(FILE *in,FILE *out)
{	CStr(ibuf,MSGSIZE);
	CStr(obuf,256);
	int rcc,wcc,rcctotal,wcctotal;

	rcctotal = 0;
	wcctotal = 1;
	while( fgets(ibuf,sizeof(ibuf),in) != NULL ){
		rcc = strlen(ibuf);
		rcctotal += rcc;
		wcc = QZdecode(0,obuf,ibuf,rcc);
		if( wcc < 0 ){
			wcctotal += rcc;
			fputs(ibuf,out);
		}else{
			wcctotal += wcc;
			fwrite(obuf,1,wcc,out);
		}
	}
	fprintf(stderr,"%d/%d\n",wcctotal,rcctotal);
}
