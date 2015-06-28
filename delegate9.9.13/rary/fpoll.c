/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	fpoll.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950707	extracted from iotimeout.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h> /* EAGAIN */
#include "fpoll.h"
int FS_maybeUnix();

int readyAlways(int fd)
{
	if( file_isreg(fd) )
		return 1;

	if( !FS_maybeUnix() && !file_isselectable(fd) )
		return 1;

	return 0;
}

int _fPollIn(FILE *fp,int msec)
{
	int nready,fd,ch;

	if( fp == NULL )
		return -1;
	if( feof(fp) )
		return -1;
	if( 0 < ready_cc(fp) )
		return 1;

	if( readyAlways(fileno(fp)) )
		return 1;

/*
	if( 0 < _PollIn(fileno(fp),msec) )
*/
	fd = fileno(fp);
	nready = _PollIn(fd,msec);
	if( nready != 0 && 0 <= top_fd(fd,0) ){
		ch = getc(fp);
		if( ch != EOF )
			ungetc(ch,fp);
		else
		if( errno == EAGAIN ){
			clearerr(fp);
			syslog_ERROR("## _PollIn(%d,%d) pop_fd %d\n",
				fd,msec,nready);
			return _fPollIn(fp,msec);
		}
		else
		if( fpop_fd(fp) ){
			syslog_ERROR("## _fPollIn(%d) fpop_fd()\n",fd);
			return _fPollIn(fp,msec);
		}
	}

	if( 0 < nready )
		return 2;

	return 0;
}

const char *FL_F_Poll;
int FL_L_Poll;

int fPollIn_FL(FL_PAR,FILE *fp,int msec)
{	int nready;

	FL_F_Poll = FL_F; FL_L_Poll = FL_L;
	nready = _fPollIn(fp,msec);
	if( nready == 0 ){
		if( poll_error(fileno(fp)) )
			nready = -1;
	}
	return nready;
}

int PollIn_FL(FL_PAR,int fd,int msec)
{	int nready;

	FL_F_Poll = FL_F; FL_L_Poll = FL_L;
	nready = _PollIn(fd,msec);
	if( nready == 0 ){
		if( poll_error(fd) )
			nready = -1;
	}
	return nready;
}

int _PollIn(int fd,int msec)
{	int nready;

	if( fd < 0 )
		return -1;

	nready = pollPipe(fd,msec);
	if( 0 <= nready )
		return nready;

	return PollIn1(fd,msec);
	/*
	{
	double S,D,E,Time();
	S = Time();
	nready = PollIn1(fd,msec);
	if( nready == 0 ){
		D = Time();
		E = D - S;
		syslog_ERROR("_PollIn(%dms) = %d %dms\n",
			msec,nready,(int)(1000*E));
	}
	return nready;
	}
	*/
}

extern int _gotOOB;
int gotOOB(int fd){
	if( fd < 0 ){
		if( 0 < _gotOOB ){
			return 1;
		}
	}else{
		if( _gotOOB == fd+1 ){
			return 1;
		}
	}
	return 0;
}


#if defined(__cplusplus) && defined(_MSC_VER)
extern int (*win_read)(int,char*,unsigned int);
extern int (*win_write)(int,const char*,unsigned int);
extern int (*win_close)(int fd);
extern "C" {
	int _lookuptrailbytes = 0;
	int _read(int fd,char buf[],unsigned int size){
		return (*win_read)(fd,buf,size);
	}
	int _read_lk(int fd,char buf[],unsigned int size){
		return (*win_read)(fd,buf,size);
	}
	int _read_nolock(int fd,char buf[],unsigned int size){
		return (*win_read)(fd,buf,size);
	}
	int _write(int fd,const char *buf,unsigned int size){
		return (*win_write)(fd,buf,size);
	}
	int _write_lk(int fd,const char *buf,unsigned int size){
		return (*win_write)(fd,buf,size);
	}
	int _write_nolock(int fd,const char *buf,unsigned int size){
		return (*win_write)(fd,buf,size);
	}
}
#endif
