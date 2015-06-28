/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
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
Content-Type:	program/C; charset=US-ASCII
Program:	cms.c (Cache Management Server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960531	created
//////////////////////////////////////////////////////////////////////#*/

#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"
#include <ndbm.h>

typedef struct {
	char	*c_server;	/* server location */
	char	*c_dbdir;	/* root directory */
	FILE	*c_master;	/* master file */
	DBM	*c_dbm;		/* URL-index DBM */
	MStr(	 c_sortdir,1024);	/* sort by access time */
	FILE	*c_accum;	/* accumlated information */
} CMSDB;

#define DBDIR	Cmsdb->c_dbdir
#define DBDBM	Cmsdb->c_dbm
#define DBFILE	Cmsdb->c_master
#define DBASORT	Cmsdb->c_sortdir
/**/
#define DBACCUM	Cmsdb->c_accum


static char *undelegate(PCStr(sp))
{
	if( strncmp(sp,"/-_-",4) == 0 ){
		sp += 4;
		if( *sp == '/' )
			for( sp++; *sp && *sp != '/'; sp++)
				;
	}
	return sp;
}

static canon_url(PVStr(url))
{	refQStr(sp,url);
	char *dp;
	CStr(proto,128);
	int stdport;

	dp = proto;
	for( sp = url; *sp && isalpha(*sp); sp++ ){
		if( isupper(*sp) )
			*sp = tolower(*sp);
		*dp++ = *sp;
	}
	*dp = 0;

	if( sp[0] == ':' && sp[1] == '/' && sp[2] == '/' ){
		for( sp += 3; *sp && *sp != ':' && *sp != '/'; sp++ )
			if( isupper(*sp) )
				*sp = tolower(*sp);
		if( *sp == ':' ){
			if( strcmp(proto,"ftp") == 0    && atoi(sp+1) == 21
			 || strcmp(proto,"gopher") == 0 && atoi(sp+1) == 70
			 || strcmp(proto,"http") == 0   && atoi(sp+1) == 80
			 || strcmp(proto,"nntp") == 0   && atoi(sp+1) == 119
			){
				for( dp = sp+1; *dp && *dp != '/'; dp++ );
				if( *dp == 0 || *dp == '/' )
					strcpy(sp,dp);
			}
		}
	}
}

static decomp_httplog(PCStr(line),PCStr(url),int *rsizep,FILE *err)
{	const char *a1;
	const char *a2;
	char *dp;
	const char *sp;
	CStr(satime,256);
	int atime,rcode,rsize;
	CStr(dcode,128);

	if( a1 = strchr(line,'[') )
	if( a2 = strchr(a1,'"') )
	if( a2 = strchr(a2,' ') )
	{
		sp = a2 + 1;
		sp = undelegate(sp);
		dp = url;
		while( *sp && *sp != '"' && *sp != ' ' )
			*dp++ = *sp++;
		*dp = 0;
		if( url[0] == '/' )
			goto error;
		canon_url(url);

		if( *sp != '"' )
			while( *sp && *sp != '"' )
				sp++;

		if( *sp != '"' )
			goto error;

		sp++;
		if( Xsscanf(sp,"%d %d %s",&rcode,&rsize,AVStr(dcode)) < 2 )
			goto error;

		if( rcode != 200 && rcode != 301 && rcode != 302 )
			return -1;

		sp = a1 + 1;
		dp = satime;
		while( *sp && *sp != ']' )
			*dp++ = *sp++;
		*dp = 0;
		atime = scanftime(satime,TIMEFORM_HTTPD);

		*rsizep = rsize;
		return atime;
	}
error:
	fprintf(err,"BadLog: %s",line);
	return -1;
}

static int dir_atimex;
static FILE *dir_fp;
typedef struct {
	int	key;
	int	val;
} Entry;

static mkdirR(PCStr(dir),int mode)
{	char *dp;
	CStr(dirpath,1024);

	strcpy(dirpath,dir);
	dp = dirpath;
	while( dp = strchr(dp,'/') ){
		*dp = 0;
		mkdir(dirpath,mode);
		*dp++ = '/';
	}
	return mkdir(dir,mode);
}

static add_atime(PCStr(dir),int key,nt atime)
{	CStr(stime,128);
	CStr(path,1024);
	int atimex;
	FILE *fp;
	Entry e1;
	int split;

	split = 3600;
	atimex = (atime / split) * split;
	if( dir_fp == NULL || dir_atimex != atimex ){
		CStr(pdir,1024);

		if( dir_fp )
			fclose(dir_fp);

		StrftimeLocal(stime,sizeof(stime),"%Y%m%d/%H%M",atimex);
		sprintf(path,"%s/%s",dir,stime);

		dir_fp = fopen(path,"a");
		if( dir_fp == NULL ){
			strcpy(pdir,path);
			*strrchr(pdir,'/') = 0;
			if( mkdirR(pdir,0755) == 0 )
				dir_fp = fopen(path,"a");
		}
		if( dir_fp == NULL )
			fprintf(stderr,"Cannot create %s\n",path);

	}

	if( dir_fp != NULL ){
		e1.key = key;
		e1.val = atime;
		fwrite(&e1,sizeof(e1),1,dir_fp);
		fflush(dir_fp);
	}
}
static remove_atime(dir,atime,key)
	char *dir;
{
}

static timesort(Entry *e1,Entry *e2)
{
	if( e1->val == e2->val )
		return e1->key - e2->key;
	else	return e1->val - e2->val;
}
static double expire1(FILE *active,PCStr(path),double expired,double required)
{	int nent,ei;
	Entry *es,esbuf[4096];
	FILE *sfp;
	CStr(path1,4096);
	int expire1;
	CStr(line,4096);
	CStr(stime,256);
	Entry e1;

	nent = file_size(path) / sizeof(Entry);
	if( nent < 0 )
		return;
	if( nent < 1024 )
		es = esbuf;
	else	es = (Entry*)malloc(nent*sizeof(Entry));

	sfp = fopen(path,"r");
	if( sfp == NULL )
		return;
	nent = fread(es,sizeof(Entry),nent,sfp); /**/
	fclose(sfp);

	qsort(es,nent,sizeof(Entry),timesort);

	for( ei = 0; ei < nent; ei++ ){
		e1 = es[ei];
		fseek(active,e1.key,0);
		line[0] = 0;
		fgets(line,sizeof(line),active);
		if( Xsscanf(line,"%*d %*d %d %s",&expire1,AVStr(path1)) )
			expired += expire1;

		StrftimeLocal(stime,sizeof(stime),"%m/%d-%H:%M:%S",e1.val);
		fprintf(stderr,"[%7d / %9.6f] %s %s\n",
			expire1,expired/1000000,stime,path1);
		if( required < expired )
			break;
	}
	if( es != esbuf )
		free(es);
	return expired;
}

static if_older(char *file,PVStr(oldest),char *latest)
{
	if( file[0] != '.' )
	if( strcmp(latest,oldest) == 0 && 0 < strcmp(file,latest) || strcmp(file,oldest) < 0 )
		strcpy(oldest,file);
	return 0;
}
static expire(FILE *active,DBM *db,PCStr(atimedir),double required)
{	CStr(path,1024);
	CStr(oldest1,1024);
	CStr(oldest2,1024);
	CStr(latest,1024);
	CStr(adaydir,1024);
	double expired;

	expired = 0;

	oldest1[0] = 0;

	while( expired < required ){
		strcpy(latest,oldest1);
		Scandir(atimedir,if_older,oldest1,latest);
		if( strcmp(latest,oldest1) == 0 )
			break;
		sprintf(adaydir,"%s/%s",atimedir,oldest1);

		oldest2[0] = 0;
		while( expired < required ){
			strcpy(latest,oldest2);
			Scandir(adaydir,if_older,oldest2,latest);
			if( strcmp(latest,oldest2) == 0 )
				break;
			sprintf(path,"%s/%s",adaydir,oldest2);
			expired = expire1(active,path,expired,required);
		}
	}
}

static put1(CMSDB *Cmsdb,DBM *db,FILE *act,PCStr(atimedir),PCStr(url),int atime,int size)
{	datum key,odata,ndata;
	int new,count,off,oatime;
	unsigned char bo[4];
	CStr(urlbuf,4096);
	double tsize;
	unsigned int tsizeM,tsize0,tcount;

	new = 0;
	key.dptr = url;
	key.dsize = strlen(url);
	odata = dbm_fetch(db,key);

	if( odata.dptr == NULL ){
		new = 1;
		fseek(act,0,2);
		off = ftell(act);

		bo[0] = off>>24; bo[1] = off>>16; bo[2] = off>>8; bo[3] = off;
		ndata.dptr = (char*)bo;
		ndata.dsize = sizeof(bo);
		dbm_store(db,key,ndata,DBM_REPLACE);

		fprintf(act,"%07d %09d %08d %s\n",1,atime,size,url);

fseek(DBACCUM,0,0);
if( fscanf(DBACCUM,"%d %d %d",&tsizeM,&tsize0,&tcount) != 3 )
	tsizeM = tsize0 = tcount = 0;
tsize = tsizeM*1024+ tsize0 + size;
tcount += 1;
fseek(DBACCUM,0,0);
fprintf(DBACCUM,"%08d %04d %08d\n",(int)(tsize/1024),(unsigned int)tsize%1024,tcount);
fflush(DBACCUM);

if( size % 1024 )
fprintf(DBACCUM,"%08d %04d %08d\n",(int)(tsize/1024),(unsigned int)tsize%1024,tcount);

	}else{
		bcopy(odata.dptr,bo,sizeof(bo));
		off = (bo[0]<<24)|(bo[1]<<16)|(bo[2]<<8)|(bo[3]);
		fseek(act,off,0);
		if( fscanf(act,"%d %d",&count,&oatime) != 2 )
			return 0;
		if( atime <= oatime )
			return 0;

		remove_atime(atimedir,atime,off);
		fseek(act,off,0);
		fprintf(act,"%07d %09d",++count,atime);
	}
	fflush(act);
	add_atime(atimedir,off,atime);
	return new;
}

static find1(file,dir,out)
	char *file;
	char *dir;
	FILE *out;
{	CStr(path,2048);
	int isdir,mtime,atime,size,blocks;

	if( strcmp(file,".") != 0 && strcmp(file,"..") != 0 ){
		if( dir[0] == 0 || file[0] == 0 )
			sprintf(path,"%s%s",dir,file);
		else	sprintf(path,"%s/%s",dir,file);
		fprintf(out,"%s\n",path);
		isdir = file_stats(path,&mtime,&atime,&size,&blocks);
		if( isdir )
			Scandir(path,find1,path,out);
	}
	return 0;
}

static find(path,out)
	char *path;
	FILE *out;
{
	find1(path,"",out);
}


#include <sys/types.h>
#include <sys/stat.h>
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#endif

int file_stats(path,mtime,atime,size,blocks)
	char *path;
	int *mtime,*atime,*size,*blocks;
{       FileStat st;

        if( lstat(path,&st) == 0 ){
		if( atime ) *atime = st.st_atime;
		if( mtime ) *mtime = st.st_mtime;
		if( size  ) *size  = st.st_size;
		if( blocks) *blocks = st.st_blocks;
		return S_ISDIR(st.st_mode);
        }else	return -1;
}
int file_size(path)
	char *path;
{	int size;

	if( 0 <= file_stats(path,NULL,NULL,&size,NULL) )
		return size;
	else	return -1;
}


/*
	if( (logfile = getenv("WWWHIST")) == NULL )
		logfile = "log/delegate-rips:80.http";
	log = fopen(logfile,"r");
	if( log == NULL ){
		fprintf(stderr,"Cannot read %s\n",logfile);
		return -1;
	}
	fprintf(stderr,"opened: %s\n",logfile);
*/
/*
	if( 0 < (atime = decomp_httplog(line,url,&csize1,errlog)) ){
		if( put1(db,act,atimedir,url,atime) ){
			Bsize += ((csize1/512)+1) * 512;
			eid++;
		}
		Xsize += csize1;
	}else	nerr++;
*/

static dmsdb_open(Cmsdb,errlog)
	CMSDB *Cmsdb;
	FILE *errlog;
{	CStr(cmsdb,1024);
	CStr(path,1024);

	if( (DBDIR = getenv("CMSDB")) == NULL )
		DBDIR = "/usr/tmp/cmsdb";
	fprintf(errlog,"CMSDB=%s\n",DBDIR);
	mkdirR(DBDIR,0755);
	if( chdir(DBDIR) != 0 ){
		fprintf(errlog,"Cannot go to CMSDB: %s\n",DBDIR);
		return -1;
	}

	sprintf(cmsdb,"%s/active",DBDIR);
	DBFILE = fopen(cmsdb,"r+");
	if( DBFILE == NULL )
		DBFILE = fopen(cmsdb,"w+");
	if( DBFILE == NULL ){
		fprintf(errlog,"Cannot create file %s\n",cmsdb);
		return -1;
	}
	fprintf(errlog,"opened: %s\n",cmsdb);

	DBDBM = dbm_open(cmsdb,O_RDWR|O_CREAT,0644);
	if( DBDBM == NULL ){
		fprintf(errlog,"Cannot create %s.DBM\n",cmsdb);
		return -1;
	}
	fprintf(errlog,"opened: %s.DBM\n",cmsdb);

	sprintf(DBASORT,"%s/atimesort",DBDIR);
	mkdirR(DBASORT,0755);

	sprintf(path,"%s/accum",DBDIR);
	DBACCUM = fopen(path,"r+");
	if( DBACCUM == NULL )
		DBACCUM = fopen(path,"w+");
	if( DBACCUM == NULL ){
		fprintf(errlog,"Cannot create file: %s\n",path);
		return -1;
	}

	return 0;
}

main(ac,av)
	char *av[];
{	char *logfile;
	CStr(line,0x8000);
	CStr(url,0x8000);
	int atime;
	FILE *errlog;
	CMSDB CmsdbBuf,*Cmsdb=&CmsdbBuf;
	FILE *log;
	int eid,ri,nerr,ndir,nblk;
	double Xsize,Bsize,Csize;
	int csize1;

	errlog = stderr;

	if( dmsdb_open(Cmsdb,errlog) < 0 )
		return;

	if( 1 < ac && strcmp(av[1],"-e") == 0 ){
		double ev;
		if( 2 < ac )
			ev = atoi(av[2]) * 1000000.0;
		else	ev = 0;
		expire(DBFILE,DBDBM,DBASORT,ev);
		return;
	}
	if( 1 < ac ){
		int io[2];

		pipe(io);
		if( fork() == 0 ){
			dup2(io[1],fileno(stdout));
			close(io[0]);
			close(io[1]);
			find(av[1],stdout);
			return 0;
		}
		dup2(io[0],fileno(stdin));
		close(io[0]);
		close(io[1]);
	}

	eid = 0;
	nerr = 0;
	ndir = 0;
	nblk = 0;
	Bsize = 0;
	Csize = 0;
	Xsize = 0;

log = stdin;

	for( ri = 0; fgets(line,sizeof(line),log); ri++ ){

{
	CStr(path,4096);
	int isdir,mtime,size,blocks;

	Xsscanf(line,"%s",AVStr(path));
	isdir = file_stats(path,&mtime,&atime,&size,&blocks);

	if( isdir < 0 )
		nerr++;
	else{

		nblk += blocks;
		if( isdir )
			ndir++;

		csize1 = blocks * 512;
		if( put1(Cmsdb,DBDBM,DBFILE,DBASORT, path,atime,csize1) ){
			Bsize += csize1;
			eid++;
		}
		Csize += size;
		Xsize += csize1;
	}
}

if( ri % 100 == 0 )
fprintf(stderr,"[%7d / %7d / %7d / %7d] [%9.3f / %9.3f / %9.3f / %8d ]\n",
nerr,ndir,eid,ri,Csize/1000000,Bsize/1000000,Xsize/1000000,nblk);

		/* if hour changed, rotate */
	}

fprintf(stderr,"[%7d / %7d / %7d / %7d] [%9.3f / %9.3f / %9.3f / %8d ]\n",
nerr,ndir,eid,ri,Csize/1000000,Bsize/1000000,Xsize/1000000,nblk);

	return 0;
}

