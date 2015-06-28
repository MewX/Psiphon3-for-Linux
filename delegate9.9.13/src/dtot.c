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
Program:	dtot.c (move data to text segment)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940222	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include <a.out.h>

main(int ac,char *av[])
{	const char *aoutfile;
	FILE *aout;
	struct exec exec;
	struct nlist nlist;
	int nsyms,si,soff;
	int nrels;

	if( ac < 2 ){
		fprintf(stderr,"Usage: %s a.out-filename\n",av[0]);
		exit(1);
	}
	aoutfile = av[1];
	aout = fopen(aoutfile,"r+");
	if( aout == NULL ){
		fprintf(stderr,"Cannot open %s\n",aoutfile);
		exit(1);
	}
	fread(&exec,1,sizeof(exec),aout);
	if( N_BADMAG(exec) ){
		fprintf(stderr,"%s: not a a.out file\n",aoutfile);
		exit(1);
	}
	if( exec.a_text != 0 ){
		if( exec.a_data )
			fprintf(stderr,"cannot move data to text.\n");
		else	fprintf(stderr,"no data segment.\n");
		exit(1);
	}

	fprintf(stderr,"%6d text\n",exec.a_text);
	fprintf(stderr,"%6d data\n",exec.a_data);
	nsyms = exec.a_syms/sizeof(struct nlist);
	fprintf(stderr,"%6d syms\n",nsyms);
	fprintf(stderr,"%6d drels\n",exec.a_drsize);
	if( exec.a_drsize ){
		fprintf(stderr,"cannot move data with relocation.\n");
		exit(1);
	}

	fseek(aout,N_SYMOFF(exec),0);
	for( si = 0; si < nsyms; si++ ){
		soff = ftell(aout);
		fread(&nlist,1,sizeof(struct nlist),aout);
		if( nlist.n_type & N_DATA ){
			nlist.n_type = (nlist.n_type & ~N_DATA) | N_TEXT;
			fseek(aout,soff,0);
			fwrite(&nlist,1,sizeof(struct nlist),aout);
			fflush(aout);
		}
	}

	exec.a_text = exec.a_data;
	exec.a_data = 0;
	fseek(aout,0,0);
	fwrite(&exec,1,sizeof(exec),aout);
	fflush(aout);

	fclose(aout);
	fprintf(stderr,"%d bytes of data moved to text segment.\n",exec.a_text);
	exit(0);
}
