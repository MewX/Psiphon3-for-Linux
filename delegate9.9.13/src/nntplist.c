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
Program:	nntplist.c (NNTP LIST processor)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950923	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"

char basis_64[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *itoB64(int iv,char b64[],int size)
{	char *vp; /**/

	vp = &b64[size-1];
	*vp = 0;

	for(;;){
		*--vp = basis_64[iv & 0x3F];
		iv = iv >> 6;
		if( iv == 0 )
			break;
	}
	return vp;
}
int B64toi(PCStr(b64))
{	const char *vp;
	char ch;
	int iv,iv1;

	iv = 0;
	for(vp = b64; ch = *vp; vp++){
		if( 'A' <= ch && ch <= 'Z' ) iv1 = ch - 'A'; else
		if( 'a' <= ch && ch <= 'z' ) iv1 = ch - 'a' + 26; else
		if( '0' <= ch && ch <= '9' ) iv1 = ch - '0' + 52; else
		if( ch == '+' ) iv1 = 62; else
		if( ch == '/' ) iv1 = 63; else
			break;
		iv = (iv << 6) | iv1;
	}
	return iv;
}

#define Group	words[0]
#define Max	words[1]
#define Min	words[2]
#define Mode	words[3]

static char *Fgets(PVStr(buf),int size,FILE *fp,PVStr(CRLF),int *leng)
{	const char *dp;
	const char *rcode;

	setVStrEnd(buf,0);
	rcode = fgetsTIMEOUT(BVStr(buf),size,fp);
	if( leng ) *leng = strlen(buf);
	if( buf[0] == '.' && (buf[1] == '\r' || buf[1] == '\n') )
		rcode = NULL;

	if( rcode != NULL && CRLF != NULL ){
		if( dp = strpbrk(buf,"\r\n") ){
			strcpy(CRLF,dp);
			truncVStr(dp);
		}else	strcpy(CRLF,"\r\n");
	}
	return (char*)rcode;
}

int LIST_compress(FILE *in,FILE *out,int isactive,int level)
{	CStr(prev,2048);
	CStr(line,2048);
	CStr(CRLF,128);
	CStr(xline,2048);
	refQStr(xp,xline); /**/
	const char *words[4]; /**/
	CStr(tmp,64);
	int max,min;
	int len;
	int total;

	total = 0;
	if( isactive && level != 0 ){
		sprintf(line,"compress %d\r\n",level);
		fputs(line,out);
		total = strlen(line) + strlen(CRLF);
	}

	prev[0] = 0;
	while( Fgets(AVStr(line),sizeof(line),in,AVStr(CRLF),NULL) != NULL ){
		if( !isactive ){
			fputs(line,out);
			fputs(CRLF,out);
			total += strlen(line);
			continue;
		}else{
			Mode = NULL;
			scanwords(line,4,words);
			if( Mode == NULL || Mode[0] == 0 )
				continue;

			max = atoi(Max);
			min = atoi(Min);
			if( max < 0 ) max = 0;
			if( min < 0 ) min = 0;
			if( level == 0 ){
				sprintf(xline,"%s %d %d %c%s",
					Group,max,min,Mode[0],CRLF);
				total += strlen(xline);
				fputs(xline,out);
				continue;
			}
		}
		for( len = 0; len < 63; len++ )
			if( Group[len] != prev[len] )
				break;
		strcpy(prev,Group);
		xp = xline;
		sprintf(xp,"%c%c%s %s",basis_64[len],Mode[0],Group+len,
			itoB64(max,tmp,sizeof(tmp)));
		xp += strlen(xp);
		if( min != max + 1 ){
			sprintf(xp," %s",itoB64(min,tmp,sizeof(tmp)));
			xp += strlen(xp);
		}
		strcpy(xp,CRLF);
		fputs(xline,out);
		total += strlen(xline);
	}
	return total;
}

int LIST_uncompress(FILE *in,FILE *out,int isactive)
{	CStr(prev,2048);
	CStr(line,2048);
	CStr(CRLF,128);
	const char *words[4]; /**/
	int max,min;
	char mode;
	int len;
	int ilen,total;

	if( Fgets(AVStr(line),sizeof(line),in,VStrNULL,&ilen) == NULL )
		return 0;

	total = ilen;
	if( strncmp(line,"compress",8) != 0 ){
		fputs(line,out);
		while( Fgets(AVStr(line),sizeof(line),in,VStrNULL,&ilen) ){
			total += ilen;
			fputs(line,out);
		}
		return total;
	}

	prev[0] = 0;
	while( Fgets(AVStr(line),sizeof(line),in,AVStr(CRLF),&ilen) != NULL ){
		total += ilen;
		mode = line[1];
		line[1] = 0;
		len = B64toi(line);
		scanwords(line+2,3,words);

		max = B64toi(Max);
		if( Min[0] )
			min = B64toi(Min);
		else	min = max + 1;

		if( len ){
			setVStrEnd(prev,len);
			fputs(prev,out);
		}
		fprintf(out,"%s %d %d %c%s",Group,max,min,mode,CRLF);
		Xstrcpy(DVStr(prev,len),Group);
	}
	return total;
}

/*TEST*//* main(ac)
{
	if( ac == 1 )
		LIST_compress(stdin,stdout);
	else	LIST_uncompress(stdin,stdout);
}
*/
