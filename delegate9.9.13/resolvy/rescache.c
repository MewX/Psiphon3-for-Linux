/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	rescache.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970430	created
//////////////////////////////////////////////////////////////////////#*/

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ystring.h"
#include "file.h"
#include "dns.h"

int isFullpath(PCStr(path));
int mkdirShared(PCStr(dir),int mode);
int chmodIfShared(PCStr(file),int mode);
char *RES_confid(PVStr(id));
void RES_getconf(PVStr(buf));
int RES_matchLine(PCStr(what),int byname,PCStr(name),PCStr(line),int rrc,char *rv[],xPVStr(rb),PVStr(cname));

const char *RES_HC_DIR = "resolvy";
int   RES_HC_EXPIRE = 600; /* maximum validity */
int   RES_CACHE_DISABLE = 0;
int   RES_HC_EXPIRE_REFRESH = 15; /* minimum (forced) refresh interval */
static int cache_cantopen;

int NIS_inactive(PCStr(ypdomain),int set){ /* v9.9.12 new-140823d */
	IStr(path,256);
	const char *tmpdir;

	if( (tmpdir = getTMPDIR()) == 0 )
		tmpdir = "/tmp";
	sprintf(path,"%s/%s/nis-inactive-%s",tmpdir,RES_HC_DIR,ypdomain);
	if( set ){
		File_touch(path,time(0));
		return 1;
	}
	if( File_is(path) ){
		if( time(0) - File_mtime(path) < RES_HC_EXPIRE ){
			return 1;
		}
	} 
	return 0;
}

static FILE *hosts_cache(int byname,PCStr(nameaddr),PCStr(mode),PVStr(cpath))
{	unsigned int hidx;
	CStr(cdirs,1024);
	CStr(cdirg,1024);
	CStr(cdir1,1024);
	FILE *fp;
	const char *tmpdir;
	CStr(resid,64);
	CStr(conf,2048);
	CStr(idfile,1024);
	FILE *cfp;

	if( cache_cantopen && time(0) < cache_cantopen+RES_HC_EXPIRE )
		return NULL;
	cache_cantopen = 0;
	RES_confid(AVStr(resid));

	if( (tmpdir = getTMPDIR()) == 0 )
		tmpdir = "/tmp";

	hidx = FQDN_hash(nameaddr);
	if( isFullpath(RES_HC_DIR) )
		strcpy(cdirs,RES_HC_DIR);
	else	sprintf(cdirs,"%s/%s",tmpdir,RES_HC_DIR);
	sprintf(cdirg,"%s/%s",cdirs,resid);
	sprintf(cdir1,"%s/%s",cdirg,byname?"byname":"byaddr");

	if( byname != 1 ){
		strcat(cdir1,"6");
	}

	sprintf(cpath,"%s/%02x",cdir1,hidx%32);
	if( *mode == 'r' )
		debug(DBG_ANY,"lookup cache: %s\n",cpath);
	else	debug(DBG_ANY,"create cache: %s\n",cpath);

	fp = fopen(cpath,mode);

	if( fp == NULL && *mode != 'r' ){
		mkdirShared(tmpdir,0);
		mkdirShared(cdirs,0);
		if( mkdirShared(cdirg,0) == 0 ){
			RES_getconf(AVStr(conf));
			sprintf(idfile,"%s/config",cdirg);
			cfp = fopen(idfile,"w");
			if( cfp == NULL ){
				debug(DBG_FORCE,"CACHE can't open: %s (%d)\n",
					idfile,errno);
				return NULL;
			}
			fprintf(cfp,"created by uid=%d pid=%d time=%d\n",
				getuid(),getpid(),itime(0));
			fprintf(cfp,"configuration:\n");
			fputs(conf,cfp);
			fclose(cfp);
			chmodIfShared(idfile,0644);
		}
		mkdirShared(cdir1,0);

		if( (fp = fopen(cpath,mode)) == NULL ){
			cache_cantopen = time(0);
			debug(DBG_FORCE,"CACHE cannot create: %s\n",cpath);
		}
	}
	if( fp != NULL && *mode != 'r' )
		chmodIfShared(cpath,0666);

	return fp;
}

int gethostbynameaddr_cacheX(PCStr(dir),PCStr(name),int rrc,char *rv[],PVStr(rb),int byname,PVStr(cname),int noexpire);
int gethostbynameaddr_cache(PCStr(dir),PCStr(name),int rrc,char *rv[],PVStr(rb),int byname,PVStr(cname),int noexpire)
{
	if( RES_CACHE_DISABLE )
		return 0;
	return gethostbynameaddr_cacheX(dir,name,rrc,rv,AVStr(rb),byname,AVStr(cname),noexpire);
}

int gethostbynameaddr_cacheX(PCStr(dir),PCStr(name),int rrc,char *rv[],xPVStr(rb),int byname,PVStr(cname),int noexpire)
{	CStr(cpath,1024);
	FILE *cache,*ncache;
	CStr(line,1024);
	const char *lp;
	int ac;
	int ac1,ai,aj;
	const char *arb;
	int now,ctime,lines,expired;
	int lastmatch,prevmatch;

	/* if( isFullpath(dir) ) maybe this is obsolete restriction which
	   is introduced when RES_HC_DIR could not be TMPDIR relative... */
	/* *dir == 0 when called from puthost_cache() ... */
	if( *dir != 0 )
	if( strcmp(RES_HC_DIR,dir) != 0 )
		RES_HC_DIR = stralloc(dir);

	cache = hosts_cache(byname,name,"r",AVStr(cpath));
	if( cache == NULL )
		return 0;

	now = time(0);
	expired = 0;
	ac = 0;
	arb = rb;
	lastmatch = 0;

	for( lines = 0; fgets(line,sizeof(line),cache) != NULL; lines++ ){
		ctime = atoi(line);
		if( !noexpire )
		if( RES_HC_EXPIRE < now - ctime ){
			expired++;
			continue;
		}
		for( lp = line; *lp; lp++ ){
			if( *lp == ' ' ){
				lp++;
				break;
			}
		}
	SCAN1:
		ac1 = RES_matchLine("cache",byname,name,lp,rrc-ac,&rv[ac],AVStr(rb),AVStr(cname));
		rb = rv[ac += ac1];
		if( ac1 ){
			prevmatch = lastmatch;
			lastmatch = ctime;
			if( prevmatch && prevmatch < lastmatch ){
				/* ignore older caches */
				/* (a chunk of cache entries in a second) */
				ac = 0;
				rb = (char*)arb;
				if( cname ) setVStrEnd(cname,0);
				goto SCAN1;
			}
		}
		if( rrc-ac <= 1 ){
			if( ac1 == 0 ){
				/**/
				break;
			}
		}
	}
	fclose(cache);

	if( !noexpire )
	if( ac == 0 )
	if( lines/2 < expired )
	if( cache = hosts_cache(byname,name,"r",AVStr(cpath)) ){
		CStr(newpath,1024);

		sprintf(newpath,"%s-%d",cpath,getpid());
		if( ncache = fopen(newpath,"w") ){
			fseek(cache,0,0);
			/* ignore stale cache entries */
			while( fgets(line,sizeof(line),cache) != NULL ){
				ctime = atoi(line);
				if( now - ctime <= RES_HC_EXPIRE )
					break;
			}
			while( fgets(line,sizeof(line),cache) != NULL )
				fputs(line,ncache);
			fclose(ncache);
			fclose(cache);
			if( unlink(cpath) != 0 )
				debug(DBG_FORCE,"CACHE cant del.? %s\n",cpath);
			if( rename(newpath,cpath) == 0 ){
				debug(DBG_ANY,"CACHE truncated %s\n",cpath);
				chmodIfShared(cpath,0666);
			}
			if( unlink(newpath) == 0 )
				debug(DBG_FORCE,"CACHE salvaged %s\n",newpath);
		}
		else	fclose(cache);
	}
	return ac;
}

const char *VSA_ltoa(const unsigned char *baddr,int len,int type);
/*
void puthost_cache(PCStr(nameaddr),char *rv[],int byname,PVStr(cname))
*/
void puthost_cache(PCStr(nameaddr),char *rv[],int byname,PVStr(cname),int len,int type)
{	int ai;
	const char *n1;
	const unsigned char *a1;
	CStr(cpath,1024);
	FILE *cache;
	int now;
	int expire;

	int cac;
	char *crv[64]; /**/
	CStr(crb,1024);

	expire = RES_HC_EXPIRE;
	if( RES_CACHE_DISABLE && RES_HC_EXPIRE_REFRESH < RES_HC_EXPIRE )
		RES_HC_EXPIRE = RES_HC_EXPIRE_REFRESH;
	cac = gethostbynameaddr_cacheX("",nameaddr,elnumof(crv),crv,AVStr(crb),byname,AVStr(cname),0);
	RES_HC_EXPIRE = expire;
	if( 0 < cac ){
		if( !RES_CACHE_DISABLE )
		debug(DBG_FORCE,"CACHE UPDATE COLLISION %s(%d)\n",nameaddr,cac);
		return;
	}

	cache = hosts_cache(byname,nameaddr,"a",AVStr(cpath));
	if( cache == NULL )
		return;

	now = time(0);
	if( byname ){
	    if( rv[0] == NULL ){
		fprintf(cache,"%d ",now);
		a1 = (unsigned char *)UNKNOWN_HOSTADDR;
		fprintf(cache,"%d.%d.%d.%d\t",a1[0],a1[1],a1[2],a1[3]);
		fprintf(cache,"%s\n",nameaddr);
		fflush(cache);
	    }else
	    for( ai = 0; a1 = (unsigned char *)rv[ai]; ai++ ){
		fprintf(cache,"%d ",now);
/*
		fprintf(cache,"%d.%d.%d.%d\t",a1[0],a1[1],a1[2],a1[3]);
*/
		fprintf(cache,"%s\t",VSA_ltoa(a1,len,type));
		if( cname && cname[0] && strcmp(cname,nameaddr) != 0 )
			fprintf(cache,"%s ",cname);
		fprintf(cache,"%s\n",nameaddr);
		fflush(cache);
	    }
	}else{
	    if( rv[0] == NULL ){
		fprintf(cache,"%d ",now);
		fprintf(cache,"%s\t%s\n",nameaddr,UNKNOWN_HOSTNAME);
		fflush(cache);
	    }else{
		fprintf(cache,"%d ",now);
		fprintf(cache,"%s\t",nameaddr);
		for( ai = 0; n1 = rv[ai]; ai++ )
			fprintf(cache,"%s%s",0<ai?" ":"",n1);
		fprintf(cache,"\n");
		fflush(cache);
	    }
	}
	fflush(cache);
	fclose(cache);
}

int rem_unknown(char *rv[],PCStr(unknown),int leng)
{	int ai,ac;
	const char *n1;
	CStr(last,512);

	ac = 0;
	last[0] = 0;
	for( ai = 0; n1 = rv[ai]; ai++ ){
		if( 0 < leng ){
			if( strncmp(n1,unknown,leng) == 0 )
				continue;
		}else{
			if( strcmp(n1,unknown) == 0 )
				continue;
		}
		rv[ac++] = (char*)n1;
	}
	rv[ac] = 0;
	return ac;
}
