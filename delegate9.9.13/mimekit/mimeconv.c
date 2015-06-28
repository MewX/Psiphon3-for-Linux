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
Program:      mmhencode.c (MIME header encoder/decoder interface)
Author:       Yutaka Sato <ysato@etl.go.jp>
ToDo:
 + selective encode of structured fields (-s option?)
//////////////////////////////////////////////////////////////////////#*/
#include "mime.h"

extern int MIME_SPACE_ENCODING;
int MIME_DECODE_BODY = 1;
static FILE *INFILE;
#define infile (INFILE?INFILE:stdin)
extern int PGP_ENCODE;
extern int PGP_DECODE;
static int do_b64;
static int do_qp;
static int filter = 0xFF;

static int scan_args(int ac,const char *av[])
{	int ai;
	const char *arg;
	int outfd;
	int charcode = 0;
	int charmap = 0;

	scan_MIMECONV("all");
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-b") == 0 ){
			do_b64 = 1;
		}else
		if( strcmp(arg,"-q") == 0 ){
			do_qp = 1;
		}else
		if( strcmp(arg,"-s") == 0 )
			MIME_SPACE_ENCODING = 0;
		else
		if( strcmp(arg,"-h") == 0 )
			MIME_DECODE_BODY = 0;
		else
		if( streq(arg,"-ot") ){
			filter |= O_TEXTONLY;
		}else
		if( *arg == '-' ){
			fprintf(stderr,"Unknown option: %s\n",arg);
		}else
		if( strncmp(arg,"CHARMAP=",8) == 0 ){
			void scan_CHARMAPs(void*,PCStr(map));
			scan_CHARMAPs(0,arg+8);
			charmap = 1;
		}else
		if( strncmp(arg,"CHARSET=",8) == 0 ){
			codeconv_set(1,arg+8,-1);
			charcode = 1;
		}else
		if( strncmp(arg,"CHARCODE=",9) == 0 ){
			codeconv_set(1,arg+9,-1);
			charcode = 1;
		}else
		if( strncmp(arg,"MIMECONV=",9) == 0 ){
			scan_MIMECONV(arg+9);
		}else
		if( strncmp(arg,"HTMLCONV=",9) == 0 ){
			scan_HTMLCONV(NULL,arg+9);
		}else
		if( strncmp(arg,"PGP=",4) == 0 ){
			scan_PGP(NULL,arg+4);
		}else
		{
			INFILE = fopen(arg,"r");
			if( INFILE == NULL ){
				syslog_ERROR("%s: cannot open %s\n",
					av[0],arg);
				exit(-1);
			}
		}
	}
	if( charmap && !charcode ){
		codeconv_set(1,"asis",-1);
	}

/*
	outfd = fileno(stdout);
	if( file_isreg(outfd) ){
		flock(outfd,2);
		fseek(stdout,0,2);
	}
*/
	return ac;
}


void LOCAL2MIME_main(int ac,const char *av[])
{	FILE *fp;
	CStr(line,1024);

	ac = scan_args(ac,av);
	if( getenv("TMPTEST") ){
		printf("COMMENT: TMPTEST\n");
		fp = (FILE*)MIME_tmpHeaderEncode(infile);
		while(fgets(line,sizeof(line),fp) != NULL)
			fputs(line,stdout);
		fclose(fp);
	}else	MIME_headerEncode(infile,stdout);
	exit(0);
}
void MIME2LOCAL_main(int ac,const char *av[])
{
	ac = scan_args(ac,av);
	MIME_headerDecode(infile,stdout,1);
	exit(0);
}

int ENMIME_main(int ac,const char *av[])
{
	ac = scan_args(ac,av);
	if( do_b64 ) MIME_to64(infile,stdout); else
	if( do_qp  ) MIME_toQP(infile,stdout); else
        PGPencodeMIMEX(infile,stdout,filter);
	exit(0);
	return 0;
}
int DEMIME_main(int ac,const char *av[])
{	int do_conv;

	ac = scan_args(ac,av);
	do_conv = codeconv_get(NULL,NULL,NULL);
	if( do_b64 ) MIME_from64(infile,stdout); else
	if( do_qp  ) MIME_fromQP(infile,stdout); else
        PGPdecodeMIME(infile,stdout,NULL,filter,do_conv,0);
	exit(0);
	return 0;
}
