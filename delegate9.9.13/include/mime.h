#ifndef _MIME_H
#define _MIME_H

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
Program:	mime.c (MIME header encoder/decoder)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941008	extracted from nntp.c
	950312	encode/decode parts in a multipart message
//////////////////////////////////////////////////////////////////////#*/

extern const char *MimeKit_Version;

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "ystring.h"
#include "file.h"

#ifndef strdup
#define strdup(str)	strcpy( malloc(strlen(str)+1), str )
#endif
#define substr(s1,s2)	(strncasecmp(s1,s2,strlen(s2)) == 0)

#define LINESIZE	1024

#define isEOH(line)	(line[0]=='\r' || line[0]=='\n')
#define isEOR(line)	(line[0]=='.' && (line[1]=='\r'||line[1]=='\n'))

extern int MIME_CONV;

void  scan_MIMECONV(PCStr(conv));
int   scan_HTMLCONV(void*,PCStr(conv));

void  MIME_to64(FILE*, FILE*);
void  MIME_to64X(FILE*, FILE*, int);
void  MIME_toQP(FILE*, FILE*);
void  MIME_from64(FILE*, FILE*);
void  MIME_fromQP(FILE*, FILE*);
void  MIME_headerDecode(FILE*, FILE*, int);
void  MIME_headerEncode(FILE*, FILE*);
FILE* MIME_tmpHeaderEncode(FILE*);

void  encodeMIMEX(FILE *fc,FILE *ts,int filter);
void  encodeMIME(FILE *fc, FILE *ts);
void  decodeMIME(FILE*fs,FILE*tc,FILE*cache,int filter,int codeconv,int enHTML);

void  PGPencodeMIMEX(FILE*,FILE*,int filter);
void  PGPencodeMIME(FILE*, FILE*);
void  PGPdecodeMIME(FILE*, FILE*, FILE*, int,int,int);
int   PGP_DECR();
int   PGP_VRFY();

void  copyLEOLINE(FILE *src,FILE *dst);
void  fputsCRLF(PCStr(str),FILE *out);

int   str_isStr(FILE*);
int   str_fflush(FILE*);
int   str_fclose(FILE*);
int   str_ftell(FILE*);
int   str_fseek(FILE*,int off,int where);
int   str_fprintf(FILE*,PCStr(fmt),...);
int   str_fgetc(FILE*);
int   str_fputs(PCStr(str),FILE*);
int   str_fputc(int ch,FILE*);
int   str_fungetc(int ch,FILE*);

#include <time.h>
/*
time_t time(time_t*);
*/

#define O_HEAD		0x001
#define O_DELIM		0x002
#define O_BODY		0x004
#define O_EOR		0x008
#define O_ALL		0x00F
#define O_MIME2PGP	0x100
#define O_TEXTONLY	0x200
#define O_MULTIPART	0x400
#define O_BODY_CTE	0x1000
#define O_BODY_GET	0x2000

extern int MC_MASK;
#define MM_FROM		1
#define MM_BODY		2
#define MM_SIGN		4
#define MC_MASK_FROM		(MC_MASK & MM_FROM)
#define MC_MASK_BODY		(MC_MASK & MM_BODY)
#define MC_MASK_SIGNATURE	(MC_MASK & MM_SIGN)

#define MA_FROM		1
#define MA_MSGID	2
#define MA_EMAIL	4
#define MA_PHONE	8
#define MC_ANON_FROM		(MC_MASK & (MA_FROM<<16))
#define MC_ANON_MSGID		(MC_MASK & (MA_MSGID<<16))
#define MC_ANON_EMAIL		(MC_MASK & (MA_EMAIL<<16))
#define MC_ANON_PHONE		(MC_MASK & (MA_PHONE<<16))

#ifdef MIMEKIT
#define lPATHFIND()	0
#endif

typedef struct _M17N *M17N;
int m17n_known_code(const char *name);
M17N m17n_ccx_new(const char *icode,const char *ocode,void *buf,int siz);
int m17n_ccx_init(M17N m17n,const char *icode,const char *ocode);
int m17n_ccx_string(M17N m17n,const char *istr,int len,char *ostr,int siz);
typedef struct {
	int	c_noccx;
    const char *c_icode;
    const char *c_ocode;
	MStr(	c_ewicode,64); /* in encoded-word =?code?e?text?= */
	int	c_ewicodemix;
	int	c_ewiccxeach;
	M17N	c_m17n;
	int	c_8bits;
	int	c_maybe_MIME;
	int	c_maybe_NONASCII;
	int	c_got_EOR;
} MimeConv_01;
typedef MimeConv_01 MimeConv;

#define maybe_MIME	Mcv->c_maybe_MIME
#define maybe_NONASCII	Mcv->c_maybe_NONASCII
#define got_EOR		Mcv->c_got_EOR

int MIME_strHeaderEncodeX(MimeConv *m17n,PCStr(ist),PVStr(ost), int siz);
int MIME_strHeaderDecodeX(MimeConv *m17n,PCStr(ist),PVStr(ost), int siz);

#endif
