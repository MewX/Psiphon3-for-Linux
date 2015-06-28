/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	windows0.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970211	extracted from windows.c
//////////////////////////////////////////////////////////////////////#*/

#include <errno.h>

#ifndef LE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif
#include "ystring.h"
#include "log.h"
#ifdef _MSC_VER
#include <sys/stat.h> /* S_IREAD,S_IWRITE */
#endif
#include <fcntl.h>

#define LE 1?0:
#define LT 1?0:
#define LV 1?0:
#define LW 1?0:
#define LS 1?0:
#endif

#ifdef _MSC_VER
#define O_TEMPBIN	(O_TEMPORARY|O_BINARY)
/*
#define newtmp(path)	_open(path,O_CREAT|O_RDWR|O_TEMPBIN,S_IREAD|S_IWRITE)
*/
FILE *fopen_tmpfile(PCStr(path));
int newtmp(PCStr(path));
#define ACT_UNLINKABLE	0
#define FOPEN_RWB	"w+b"
#define closetmpf1(fd)	(0 < _get_osfhandle(fd) ? _close(fd) : -1)
#undef fdopen
#define fdopen		_fdopen
#else
#define fopen_tmpfile(path) 0
#ifdef __EMX__
#define newtmp(path)	open(path,O_CREAT|O_RDWR,0600)
#define ACT_UNLINKABLE	0
#define FOPEN_RWB	"w+b"
#define closetmpf1(fd)	close(fd)
FILE *tmpfile(void){ return TMPFILEX(tmpnam(NULL)); }
#else
#define newtmp(path)	open(path,O_CREAT|O_RDWR,0600)
#define ACT_UNLINKABLE	1
#define FOPEN_RWB	"w+"
#define closetmpf1(fd)	close(fd)
#endif
#endif

#define MAXFD_SETSIZE 512 /* should be FD_SETSIZE ... */
typedef struct {
  const	char   *te_tmpfiles[MAXFD_SETSIZE]; /**/
} TmpfileEnv;
static TmpfileEnv *tmpfileEnv;
#define TE	tmpfileEnv[0]
#define tmpfiles	TE.te_tmpfiles
void minit_tmpfile()
{
	if( tmpfileEnv == 0 )
		tmpfileEnv = (TmpfileEnv*)StructAlloc(sizeof(TmpfileEnv));
}

void deltmpfiles()
{	int ti;
	const char *path;
	int rcode;
	int fd;

	for( fd = 3; fd < 256; fd++ )
		if( closetmpf1(fd) == 0 )
			LW("exit: close(%d) = 0",fd);

	for( ti = 0;  ti < MAXFD_SETSIZE; ti++ ){
	    if( path = tmpfiles[ti] ){
		if( *path == ' ' ){
			continue;
		}
		errno = 0;
		rcode = unlink(path);
		LV("unlink(%s) = %d, errno=%d",path,rcode,errno);
	    }
	}
}

static void addtmp(int fd,PCStr(npath))
{	int rcode;
	const char *opath;
	int size;

	if( lSINGLEP() && tmpfiles[0] == 0 ){
		int fi;
		IStr(buf,128);
		sprintf(buf,"%*s",ll2i(strlen(npath)+5)," ");
		for( fi = 0; fi < 128 && fi < elnumof(tmpfiles); fi++ ){
			tmpfiles[fi] = stralloc(buf);
		}
	}
	if( fd < 0 || elnumof(tmpfiles) <= fd ){
		porting_dbg("Range-ERROR addtmp([%d]) %s",fd,npath);
		return;
	}
	if( opath = tmpfiles[fd] ){
		if( strcmp(opath,npath) == 0 ){
			return;
		}
		rcode = unlink(opath);
		size = strlen(opath)+1;
		if( strlen(npath) < size ){
			Xstrcpy(ZVStr(tmpfiles[fd],size),npath);
			return;
		}
		strfree((char*)opath);
	}
	tmpfiles[fd] = stralloc(npath);
}
FILE *fopenastmpfile(PCStr(path)){
	FILE *fp;
	if( fp = fopen(path,"w+") ){
		addtmp(fileno(fp),path);
	}
	return fp;
}

void add_FILEY(FL_PAR,const char *wh,FILE *fp);
FILE *fopentmpfile(PCStr(path),int remove)
{	FILE *fp;
	int fd;

	if( isWindowsCE() ){
		fp = fopen_tmpfile(path);
		add_FILEY(FL_ARG,"fopentmpfile",fp);
	}else
	if( ACT_UNLINKABLE ){
		if( fp = fopen(path,FOPEN_RWB) )
			if( remove )
				unlink(path);
	}else{
		fd = newtmp(path);
		if( 0 <= fd ){
			if( fp = fdopen(fd,FOPEN_RWB) ){
				addtmp(fd,path);
				add_FILEY(FL_ARG,"fopentmpfile",fp);
				LV("fopentmpfile(%s) %x/%d",path,p2i(fp),fileno(fp));
			}else	LE("cannot fdopen(%d) %s",fd,path);
		}else{
			LE("cannot open tmpfile(%s)",path);
			fp = NULL;
		}
	}
	return fp;
}


#if !defined(O_NDELAY) && defined(FNDELAY)
#define O_NDELAY FNDELAY
#endif

#if !defined(O_NDELAY) && defined(O_NONBLOCK)
#define O_NDELAY O_NONBLOCK
#endif

#if !defined(O_NDELAY)
#define O_NDELAY -1
#endif

#if !defined(F_SETFD)
#define F_SETFD  -1
#endif
#if !defined(F_SETFL)
#define F_SETFL  -1
#define F_GETFL  -1
#endif

int getNonblockingIO(int fd)
{
	if( F_GETFL == -1 || O_NDELAY == -1 )
		return -1;

	return (fcntl(fd,F_GETFL,0) & O_NDELAY) != 0;
}
int setCloseOnExec(int fd)
{
	if( F_SETFD == -1 ){
		syslog_DEBUG("Close-On-Exec not supported\n");
		return -1;
	}

	return fcntl(fd,F_SETFD,(void*)1);
}
int clearCloseOnExec(int fd)
{
	if( F_SETFD == -1 )
		return -1;
	return fcntl(fd,F_SETFD,(void*)0);
}

int getthreadid();
void servlog(PCStr(fmt),...){
	FILE *lfp;
	VARGS(8,fmt);

	lfp = fopen("c:/tmp/svlog","a");
	if( lfp == NULL ){
		return;
	}
	fprintf(stderr,"[%d] ",getpid());
	fprintf(stderr,fmt,VA8);
	fprintf(lfp,"[%d][%d] ",getpid(),getthreadid());
	fprintf(lfp,fmt,VA8);
	fflush(lfp);
	fclose(lfp);
}

int (*fullpath_cmd)(PCStr(path),PCStr(mode),PVStr(xpath));

int signedChar(){
	char ch = 0x80;
	int issigned;
	issigned = ch < 0;
	return issigned;
}
