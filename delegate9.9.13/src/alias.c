/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	aliases.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970912	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"
#include "file.h"
#include <ctype.h>

#define LNSIZE  1024
#define lfprintf	SMTP_lfprintf

static scanListFunc exp1(PCStr(recipients),FILE *RCPT,FILE *log)
{	CStr(rb,LNSIZE);
	const char *recipient;
	const char *np;
	FILE *afp;
	int rcode;

	RFC822_strip_commentX(recipients,AVStr(rb),sizeof(rb));
	recipient = strip_spaces(rb);
	if( *recipient == 0 )
		return 0;

	if( 1 < num_ListElems(recipient,',') )
		return scan_commaList(recipient,0,scanListCall exp1,RCPT,log);

	rcode = 0;
	if( isBoundpath(recipient) ){
		if( afp = fopen(recipient,"r") ){
			while( fgets(rb,sizeof(rb),afp) ){
				if( np = strpbrk(rb,"\r\n") )
					truncVStr(np);
				if( rcode = exp1(rb,RCPT,log) )
					break;
			}
			fclose(afp);
		}else{
			fprintf(log,"cannot open %s\n",recipient);
			return -1;
		}
	}else{
		fprintf(RCPT,"%s\n",recipient);
	}
	return rcode;
}

FILE *expand_aliases(PCStr(recipients),FILE *log)
{	int rcode;
	FILE *RCPT;

	RCPT = TMPFILE("expand_aliases");
	rcode = scan_commaList(recipients,0,scanListCall exp1,RCPT,log);
	if( rcode != 0 ){
		fclose(RCPT);
		return NULL;
	}else{
		fflush(RCPT);
		fseek(RCPT,0,0);
		return RCPT;
	}
}

int alias_main(int ac,const char *av[])
{	FILE *afp;

	if( ac < 2 ){
		fprintf(stderr,"Usage: %s mail-addr\n",av[0]);
		exit(0);
	}
	if( afp = expand_aliases(av[1],stderr) ){
		copyfile1(afp,stdout);
		exit(0);
	}else	exit(-1);
	return 0;
}
