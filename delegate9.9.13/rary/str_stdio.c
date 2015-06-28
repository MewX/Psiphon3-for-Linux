/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1992-2000 Yutaka Sato and ETL,AIST,MITI
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
Content-Type: program/C; charset=US-ASCII
Program:      str_stdio.h
Author:       Yutaka Sato <ysato@etl.go.jp>
Description:

     This program redirects the file I/O from/to strings on memory.
     Include "str_stdio.h" file after <stdio.h>

History:
	92.05.18   created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "yarg.h"
#include "ystring.h"
typedef unsigned char Uchar;
char *raw_Strncpy(PVStr(s1),PCStr(s2),int n);

#define Str_MAGIC 0x12345678
typedef struct _String {
#if isWindowsCE()
	int	s_FILE[32];
#else
	FILE	s_FILE;
#endif
	StrHead	s_STRING;
} String;
#define s_magic	s_STRING.sh_magic
#define s_mode	s_STRING.sh_mode
#define s_base	s_STRING.sh_base
/**/
#define s_peak	s_STRING.sh_peak
#define s_maxsize	s_STRING.sh_maxsize
#define s_size	s_STRING.sh_size

#define str_isSTR(Str)	(Str->s_magic == Str_MAGIC)

int str_isStr(String *Str)
{
	return str_isSTR(Str);
}
void str_sopen(StrHead *StrH,PCStr(id),char buf[],int size,int peak,PCStr(mode))
{
	StrH->sh_magic = Str_MAGIC;
	if( id ){
		raw_Strncpy(AVStr(StrH->sh_id),id,sizeof(StrH->sh_id));
	}else{
		sprintf(StrH->sh_id,"%X",p2i(buf));
	}
	strcpy(StrH->sh_mode,mode);
	setQStr(StrH->sh_base,buf,size);
	StrH->sh_size = size;
	StrH->sh_peak = peak;
}
FILE *str_fopen(char buf[],int size,PCStr(mode))
{	String *Str;

	Str = (String*)calloc(1,sizeof(String));
	str_sopen(&Str->s_STRING,NULL,buf,size,0,mode);
	return (FILE*)Str;
}
int str_fflush(FILE *FStr);
int str_fclose(FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return fclose(FStr);

	str_fflush(FStr);
	free(Str);
	return 0;
}

int str_fgetc(FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return fgetc(FStr);

	if( Str->s_size <= Str->s_peak )
		return EOF;

	return ((Uchar*)Str->s_base)[Str->s_peak++];
}
int str_feof(FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return feof((&Str->s_FILE));
	return Str->s_size <= Str->s_peak;
}
int str_fungetc(int ch,FILE *FStr)
{	String *Str = (String*)FStr;
	char pch;

	/*if( ch == EOF )
		return EOF;*/

	if( !str_isSTR(Str) )
		return ungetc(ch,(FILE*)Str);

	if( Str->s_peak <= 0)
		return EOF;

	pch = ((Uchar*)Str->s_base)[--Str->s_peak];
	if( pch != ch )
		setVStrElem(Str->s_base,Str->s_peak,ch);
	return ch;
}
char *str_fgets(PVStr(buf),int size,FILE *FStr)
{	String *Str = (String*)FStr;
	int rsize,nlx;
	const unsigned char *top;
	const unsigned char *nlp;

	if( !str_isSTR(Str) )
		return fgets(buf,size,(FILE*)Str);

	rsize = Str->s_size - Str->s_peak;
	if( rsize <= 0 )
		return NULL;
	if( rsize < size )
		size = rsize;

	top = &((Uchar*)Str->s_base)[Str->s_peak];
	for(nlx = 0; nlx < rsize; nlx++)
		if( top[nlx] == '\n' ){
			size = nlx+1;
			break;
		}
	strncpy(buf,(char*)top,size); setVStrEnd(buf,size);
	Str->s_peak += size;
	return (char*)buf;
}

int str_sputc(int ch,StrHead *StrH);
int str_sprintf(StrHead *StrH,PCStr(form), ...);

int str_fputc(int ch,FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return fputc(ch,FStr);

	return str_sputc(ch,&Str->s_STRING);
}
int str_sputc(int ch,StrHead *StrH)
{
	if( StrH->sh_size <= StrH->sh_peak )
		return EOF;

	setVStrElemInc(StrH->sh_base,StrH->sh_peak,ch);
	return ch;
}
int str_fputs(PCStr(buf),FILE *FStr)
{	String *Str = (String*)FStr;
	int size,rsize;

	if( !str_isSTR(Str) )
		return fputs(buf,(FILE*)Str);

	rsize = Str->s_size - Str->s_peak;
	if( rsize <= 0 )
		return EOF;

	size = strlen(buf);
	if( size == 0 )
		return 0;
	if( rsize < size )
		size = rsize;

	Xstrncpy(DVStr(Str->s_base,Str->s_peak),buf,size);
	Str->s_peak += size;

	return 0;
}

int str_sflush(StrHead *StrH)
{
	if( strpbrk(StrH->sh_mode,"+wa") )
		setVStrEnd(StrH->sh_base,StrH->sh_peak);
	return 0;
}
int str_fflush(FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return fflush((FILE*)Str);
	return str_sflush(&Str->s_STRING);
}
int str_fprintf(FILE *FStr,PCStr(form),...)
{	String *Str = (String*)FStr;
	VARGS(16,form);

	if( !str_isSTR(Str) )
		return fprintf((FILE*)Str,form,VA16);
	return str_sprintf(&Str->s_STRING,form,VA16);
}

static int fmtDBG;
static int fmtOK;
static int fmtNO;

static void fmtdebug(StrHead *StrH,PCStr(who),PCStr(why),PCStr(fmt),int xpeak)
{	char fc;
	const char *fp;

	fprintf(stderr,"##%s:%s:%s:%d/%d:%d/%d:",
		who,why,StrH->sh_id,
		StrH->sh_peak,StrH->sh_size,fmtNO,fmtOK);
	for( fp = fmt; fc = *fp; fp++ ){
		switch( fc ){
			case '\r': fputs("^M",stderr); break;
			case '\n': fputs("^J",stderr); break;
			default: putc(fc,stderr);
		}
	}
	fputs("##\r\n",stderr);
}

int Str_sprintf(StrHead *StrH,PCStr(fmt), ...)
{	unsigned char fc;
	unsigned char *dp; /**/
	const unsigned char *xp;
	unsigned char *fdp; /**/
	unsigned char fmt1[8]; /**/
	const unsigned char *fdx = &fmt1[sizeof(fmt1)-1];
	const unsigned char *fp;
	const char *v1;
	int vi,leng;
	VARGS(16,fmt);

	vi = 0;

	xp = (Uchar*)&StrH->sh_base[StrH->sh_size] - 1;
	dp = (Uchar*)&StrH->sh_base[StrH->sh_peak];

	for( fp = (Uchar*)fmt; fc = *fp; fp++ ){
		if( xp <= dp ){
			break;
		}
		if( fc != '%' ){
			*dp++ = fc;
			continue;
		}
		fc = *++fp;
		if( fc == 0 )
			break;
		if( fc == '%' ){
			*dp++ = fc;
			continue;
		}
		fdp = fmt1;
		*fdp++ = '%';
		if( fc == '-' ){
			*fdp++ = '-';
			fc = *++fp;
		}
		for(;fdp<fdx-1;){
			if( '0' <= fc && fc <= '9' || fc == '.' ){
				*fdp++ = fc;
				fc = *++fp;
			}else	break;
		}
		*fdp++ = fc;
		*fdp = 0;

		if( fc == 0 ){
			break;
		}

		v1 = (char*)va[vi++];
		switch( fc ){
		  case 's':
			if( v1 == 0 ){
				Xstrcpy(QVStr(dp,StrH->sh_base),"(null)");
				dp += strlen((char*)dp);
				continue;
			}
			leng = strlen((char*)v1);
			if( xp < dp+leng ){
				if( 0 < fmtDBG )
				fmtdebug(StrH,"Str_sprintf","overflow",fmt,
					&dp[leng] - (Uchar*)StrH->sh_base);
				leng = xp - dp - 4;
				if( 0 < leng ){
					bcopy(v1,dp,leng); /**/
					Xstrcpy(QVStr(dp+leng,StrH->sh_base),"=-=\n");
					dp += leng + 4;
				}
				goto OUTx;
			}
			break;
		  case 'c':
		  case 'd':
		  case 'x':
		  case 'X':
			break;
		  default:
			fmtNO++;
			if( 1 < fmtDBG )
			fmtdebug(StrH,"Str_sprintf","unsupported",fmt,0);
			/* this includes "%*X" format */
			return -1;
		}
		Xsprintf(QVStr(dp,StrH->sh_base),(char*)fmt1,v1);
		dp += strlen((char*)dp);
	}
OUTx:
	if( dp <= xp )
		*dp = 0;
	fmtOK++;
	return 1;
}
int str_sprintf(StrHead *StrH,PCStr(form), ... )
{	unsigned char *peakp; /**/
	int size,peak,rem,wlen;
	VARGS(16,form);

	size = StrH->sh_size;
	peak = StrH->sh_peak;
	rem = size - peak;

	peakp = (Uchar*)&StrH->sh_base[peak];
	if( Str_sprintf(StrH,form,VA16) < 0 )
		Xsprintf(QVStr(peakp,StrH->sh_base),form,VA16);

	wlen = strlen((char*)peakp);
	if( size <= peak + wlen )
		fmtdebug(StrH,"str_sprintf","overflow",form,peak+wlen);

	StrH->sh_peak += wlen;
	str_sflush(StrH);
	return  wlen;
}
int str_sseek(StrHead *StrH,int off,int where);
int str_fseek(FILE *FStr,int off,int where)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return fseek((FILE*)Str,off,where);
	return str_sseek(&Str->s_STRING,off,where);
}
int str_sseek(StrHead *StrH,int off,int where)
{	int noff;

	switch( where ){
		case 0: noff = off; break;
		case 1: noff = StrH->sh_peak + off; break;
		case 2: noff = StrH->sh_size-1 + off; break;
		default: return -1;
	}

	if( noff < 0 || StrH->sh_size <= noff )
		return -1;
	StrH->sh_peak = noff;
	return 0;
}
int str_ftell(FILE *FStr)
{	String *Str = (String*)FStr;

	if( !str_isSTR(Str) )
		return ftell((FILE*)Str);

	return Str->s_peak;
}
int str_stell(StrHead *StrH)
{
	return StrH->sh_peak;
}
char *str_sptell(StrHead *StrH)
{
	return (char*)&StrH->sh_base[StrH->sh_peak];
}
