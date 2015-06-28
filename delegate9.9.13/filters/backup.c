/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	backup.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:

  TODO:
	symlink copy (with chmod ?)
with -Ffunc
or Func
	backup-info at the destination dir.
	protecting writing not-intended dir.
	CRON -backup
	gzip

History:
	060614	created
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"
#include "file.h"
#include "dglib.h"

typedef struct {
	int	ca_verbose;
	int	ca_dstdir;
    const char *ca_tfmt;
	int	ca_ovw;
	int	ca_new;
	int	ca_skipped;
	int	ca_srcerr;
	int	ca_dsterr;
	int	ca_newdir;
} CopyArg;

static int backup1(PCStr(src),PCStr(dst),CopyArg *ca,PCStr(tfmt)){
	FileStat ss;
	FileSize dz,sz;
	CStr(dtm,128);
	CStr(stm,128);
	int dt,dd,st,sd;
	FILE *dfp,*sfp;
	CStr(dstp,1024);

	if( File_stat(src,&sz,&st,&sd) != 0 || sd != 0 ){
		if( fileIsdir(src) ){
		}else{
			fprintf(stderr,"CantOpen src: %s\n",src);
			ca->ca_srcerr++;
		}
		return -1;
	}
	if( ca->ca_dstdir ){
		sprintf(dstp,"%s/%s",dst,src);
		dst = dstp;
	}
	if( File_stat(dst,&dz,&dt,&dd) == 0 ){
		StrftimeLocal(AVStr(dtm),sizeof(dtm),tfmt,dt,0);
	}else{
		strcpy(dtm,"new");
	}

	StrftimeLocal(AVStr(stm),sizeof(stm),tfmt,st,0);
	if( dz == sz && dt == st ){
		if( 0 < ca->ca_verbose ){
			printf("Skipped: to \"%s\" from \"%s\" %lld (%s)\n",
			dst,src,dz,dtm);
		}
		ca->ca_skipped++;
		return 0;
	}

	if( 0 <= ca->ca_verbose ){
		printf("Copying: to \"%s\" %lld (%s) from \"%s\" %lld (%s)\n",
			dst,dz,dtm,src,sz,stm);
	}
	dfp = fopen(dst,"w");
	if( dfp == NULL ){
		CStr(path,1024);
		strcpy(path,dst);
		dfp = dirfopen("COPY",AVStr(path),"w");
		ca->ca_newdir++;
	}
	if( dfp ){
		if( 0 <= dz ){
			ca->ca_ovw++;
		}else{
			ca->ca_new++;
		}
		if( sfp = fopen(src,"r") ){
			copyfile1(sfp,dfp);
			File_copymod(src,dst);
			fclose(sfp);
		}
		fclose(dfp);
		return 1;
	}else{
		if( 0 <= ca->ca_verbose )
		fprintf(stderr,"Cannot open dst: %s\n",dst);
		ca->ca_dsterr++;
		return -1;
	}
}
static int backups(PCStr(src),PCStr(dst),CopyArg *ca,PCStr(tfmt)){
	FILE *lfp;
	CStr(src1,1024);
	refQStr(sp,src1);
	int si;

	if( dst[0] == 0 || src[0] == 0 ){
		return -1;
	}
	if( streq(src,"-") )
		lfp = stdin;
	else{
		lfp = fopen(src,"r");
		if( lfp == NULL ){
			fprintf(stderr,"ERROR: cannot open \"%s\"\n",src);
			return 0;
		}
	}
	for( si = 0;; si++){
		if( fgets(src1,sizeof(src1),lfp) == NULL )
			break;
		if( sp = strpbrk(src1,"\r\n") )
			truncVStr(sp);
		backup1(src1,dst,ca,tfmt);
	}
	if( lfp != stdin )
		fclose(lfp);
	return 0;
}

int backup_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	CStr(dst,1024);
	CStr(src,1024);
	const char *tfmt = "%L";
	FileStat ds;
	int ddir = 0;
	CopyArg cab,*ca = &cab;

	bzero(ca,sizeof(CopyArg));
	truncVStr(src);
	truncVStr(dst);

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( a1[0] == '-' ){
			switch( a1[1] ){
				case 'T':
					if( backups(&a1[2],dst,ca,tfmt) < 0 )
						return -1;
					break;
				case 'v':
					ca->ca_verbose = atoi(&a1[2]);
					if( ca->ca_verbose == 0 )
						ca->ca_verbose = 1;
					break;
				case 't':
					ca->ca_verbose = -atoi(&a1[2]);
					if( ca->ca_verbose == 0 )
						ca->ca_verbose = -1;
					break;
			}
		}else
		if( dst[0] == 0 ){
			strcpy(dst,av[ai]);
			ca->ca_dstdir = fileIsdir(dst);
		}else{
			strcpy(src,av[ai]);
			if( backup1(src,dst,ca,tfmt) < 0 ){
				return -1;
			}
		}
	}
	fprintf(stderr,
	"*** created:%d updated:%d newdir:%d CantWrite:%d skipped:%d\n",
		ca->ca_new,ca->ca_ovw,
		ca->ca_newdir,
		ca->ca_dsterr,
		ca->ca_skipped
	);
	return 0;
}
