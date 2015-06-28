/*///////////////////////////////////////////////////////////////////////
Copyright (c) 1993-1998 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1993-1998 Yutaka Sato

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	ccx.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	981119	extracted from ccxmain.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "fpoll.h"

int UCSinit();
void dumpCharMapping(PCStr(code));
void loadCharMapping(PCStr(code),FILE *ifp);
void CCXcounts(CCXP);
void scan_CHARMAPs(void *ctx,PCStr(maps));

int ccx_main(int ac,const char *av[])
{	CCXP ccx;
	int rcc,len;
	/* to test boundary condition; char in[8]; */
	/*
	CStr(in,1024);
	CStr(out,4096);
	*/
	CStr(in,4*1024);
	CStr(out,16*1024);
	const char *incode;
	const char *outcode;
	const char *arg;
	const char *infile;
	int ai;
	FILE *ifp,*ofp;
	int nready;
	int ident = 0;
	int dump = 0;
	int load = 0;
	int verbose = 0;
	int charmap = 0;

	incode = "*";
	outcode = "j";
	infile = NULL;
	ifp = stdin;
	ofp = stdout;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( *arg == '-' ){
			if( strncmp(arg,"--ident",4) == 0 )
			{
				outcode = "guess";
				ident = 1;
			}
			else
			if( strncmp(arg,"--dump",3) == 0 )
				dump = 1;
			else
			if( strncmp(arg,"--load",3) == 0 )
				load = 1;
			else
			if( strncmp(arg,"--verbose",3) == 0 )
				verbose = 1;
			else
			if( strncmp(arg,"--",2) == 0 )
				incode = arg+2;
			else
			if( streq(arg,"-o") ){
				if( ai+1 < ac ){
					ai++;
					ofp = fopen(av[ai],"w");
					if( ofp == NULL ){
						fprintf(stderr,"Cannot open: %s\n",
							av[ai]);
						exit(-1);
					}
				}
			}else
			outcode = arg+1;
		}else
		if( strneq(arg,"CHARMAP=",8) ){
			charmap = 1;
			scan_CHARMAPs(0,arg+8);
		}else{
			infile = arg;
		}
	}

	if( infile ){
		ifp = fopen(infile,"r");
		if( ifp == NULL ){
			fprintf(stderr,"cannot open: %s\n",infile);
			exit(1);
		}
	}

	if( dump ){
		dumpCharMapping(outcode);
		exit(0);
	}
	if( load ){
		loadCharMapping(outcode,ifp);
		exit(0);
	}

	ccx = CCXnew(incode,outcode);
	if( strcmp(incode,"*") != 0 )
		CCX_setincode(ccx,incode);
	if( ccx == NULL ){
		fprintf(stderr,"unknown output code: %s\n",outcode);
		exit(-1);
	}

	if( *outcode == 'u' )
		UCSinit();

	in[0] = out[0] = 0;
	for(;;){
		nready = PollIn(fileno(ifp),10);
		if( nready <= 0 )
			fflush(ofp);
		rcc = read(fileno(ifp),in,sizeof(in));
		if( rcc <= 0 )
			break;
		len = CCXexec(ccx,in,rcc,AVStr(out),sizeof(out));
		if( !ident )
		fwrite(out,1,len,ofp);
	}
	len = CCXexec(ccx,"",0,AVStr(out),sizeof(out));
	if( ident )
	{
		printf("%s\n",CCXident(ccx));
	}
	else
	fwrite(out,1,len,ofp);

	if( verbose ){
		CCXcounts(ccx);
	}
	exit(0); return 0;
}
