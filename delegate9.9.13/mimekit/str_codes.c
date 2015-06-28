/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1992 Electrotechnical Laboratry (ETL)

Permission to use, copy, modify, and distribute this material
for any purpose and without fee is hereby granted, provided
that the above copyright notice and this permission notice
appear in all copies, and that the name of ETL not be
used in advertising or publicity pertaining to this
material without the specific, prior written permission
of an authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY
OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS",
WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
ontent-Type: program/C; charset=US-ASCII
Program:      codess.h
Author:       Yutaka Sato <ysato@etl.go.jp>
Description:

     This program redirects the file I/O of codes.c
     from/to strings on memory.

History:
	92.05.18   created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "mime.h"

/*
main(ac,av)
	char *av[];
{	CStr(in,0x10000);
	CStr(out,0x10000);
	int size;

	size = fread(in,1,sizeof(in),stdin);
	in[size] = 0;
	if( strcmp(av[1],"eb") == 0 )
		str_to64(in,strlen(in),out,sizeof(out),0);
	if( strcmp(av[1],"ub") == 0 )
		str_from64(in,strlen(in),out,sizeof(out),0);
	if( strcmp(av[1],"eq") == 0 )
		str_toqp(in,strlen(in),out,sizeof(out));
	if( strcmp(av[1],"uq") == 0 )
		str_fromqp(in,strlen(in),out,sizeof(out));
	syslog_ERROR("%s",out);
}
*/

void _to64(FILE *in,FILE *out);
void _from64(FILE *in,FILE *out);
void _toqp(FILE *in,FILE *out);
void _fromqp(FILE *in,FILE *out);

static
int str_callfunc(iFUNCP func,PCStr(in),int isize,PVStr(out),int osize,int arg3,int arg4)
{	FILE *In,*Out;
	int rcode;
	int len;

	In = str_fopen((char*)in,isize,"r");
	Out = str_fopen((char*)out,osize,"w");
setVStrEnd(out,0);
	rcode = (*func)(In,Out,arg3,arg4);
	len = str_ftell(Out);
	setVStrEnd(out,len);
	str_fflush(Out);
	str_fclose(In);
	str_fclose(Out);
	return len;
}
int str_to64(PCStr(in),int isize,PVStr(out),int osize,int pnl)
{	int len;
	len = str_callfunc((iFUNCP)_to64,in,isize,AVStr(out),osize,pnl,0);
	return len;
}
int str_from64(PCStr(in),int isize,PVStr(out),int osize)
{	int len;

	return str_callfunc((iFUNCP)_from64,in,isize,AVStr(out),osize,0,0);
}
int str_toqp(PCStr(in),int isize,PVStr(out),int osize)
{	int len;

	len = str_callfunc((iFUNCP)_toqp,in,isize,AVStr(out),osize,0,0);
	if( 2 < len && out[len-2] == '=' && out[len-1] == '\n' ){
		setVStrEnd(out,len-2);
		len -= 2;
	}
	return len;
}
int str_fromqp(PCStr(in),int isize,PVStr(out),int osize)
{
	return str_callfunc((iFUNCP)_fromqp,in,isize,AVStr(out),osize,0,0);
}

/**************************************/
void to64(FILE *in,FILE *out)
{
	MIME_to64(in,out);
}
void from64(FILE *in,FILE *out)
{
	MIME_from64(in,out);
}
void toqp(FILE *in,FILE *out)
{
	MIME_toQP(in,out);
}
void fromqp(FILE *in,FILE *out)
{
	MIME_fromQP(in,out);
}
/**************************************/

#include "str_stdio.h"
#define MIME_to64	_to64
#define MIME_to64X	_to64X
#define MIME_from64	_from64
#define MIME_toQP	_toqp
#define MIME_fromQP	_fromqp
#define MIME_setQP	str_setqp
#include "mimecodes.c"


int qpputc(FILE *out,PCStr(escs),int ch){
	if( ch < ' ' || ch == '=' || 0x7F <= ch || strchr(escs,ch) ){
		fprintf(out,"=%02X",ch);
		return 3;
	}else{
		putc(ch,out);
		return 1;
	}
}
int qpputs(FILE *out,PCStr(escs),PCStr(str)){
	const char *sp;
	int ch;
	int occ = 0;

	for( sp = str; ch = *sp; sp++ ){
		occ += qpputc(out,escs,ch);
	}
	return occ;
}
int QPfprintf(FILE *out,PCStr(escs),PCStr(fmt),...){
	const char *fp;
	int ch;
	int ai = 0;
	int occ = 0;
	VARGS(16,fmt);

	for( fp = fmt; ch = *fp; fp++ ){
		if( ch != '%' ){
			occ += qpputc(out,escs,ch);
			continue;
		}
		if( (ch = *++fp) == 0 ){
			break;
		}
		switch( ch ){
			case '%': occ += qpputc(out,escs,ch); break;
			case 's': occ += qpputs(out,escs,va[ai++]); break;
		}
	}
	return occ;
}
