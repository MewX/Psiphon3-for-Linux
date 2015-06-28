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
Program:	fpolls.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	980412	extracted from frelay.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h> /* EAGAIN */
#include "fpoll.h"

int _fPollIns(int timeout,int fpc,FILE *fps[],int rdv[])
{	int fi;
	FILE *fp;
	int nready;
	int fds[256];

	nready = 0;
	for( fi = 0; fi < fpc; fi++ ){
		fp = fps[fi];
		fds[fi] = fileno(fp);
		if( feof(fp) || 0 < ready_cc(fp) ){
			nready++;
			rdv[fi] = 1;
		}else	rdv[fi] = 0;
	}
	if( nready )
		return nready;
/*
	return PollIns(timeout,fpc,fds,rdv);
*/
	nready = PollIns(timeout,fpc,fds,rdv);
	if( 0 < nready ){
		int fd,ch;
		for( fi = 0; fi < fpc; fi++ ){
			fd = fds[fi];
			if( 0 < rdv[fi] && 0 <= top_fd(fd,0) ){
				ch = getc(fps[fi]);
				if( ch != EOF ){
					ungetc(ch,fps[fi]);
				}else{
					/*
					if( errno = EAGAIN ){
					*/
					if( errno == EAGAIN ){
syslog_ERROR("## _fPollIns(%d) pop_fd %d\n",fd,nready);
						clearerr(fp);
						rdv[fi] = 0;
						nready--;
					}
					else
					if( fpop_fd(fp) ){
syslog_ERROR("## _fPollIns(%d) fpop_fd %d\n",fd,nready);
					return _fPollIns(timeout,fpc,fps,rdv);
					}
				}
			}
		}
		if( nready == 0 )
			return _fPollIns(timeout,fpc,fps,rdv);
	}
	return nready;
}

int poll_error(int fd){
	if( connRESETbypeer() == fd )
		return -1;
	if( connHUP() == fd )
		return -1;
	return 0;
}

int fPollIns(int timeout,int fpc,FILE *fps[],int rdv[])
{	int fi;
	int nready;

	nready = _fPollIns(timeout,fpc,fps,rdv);
	if( nready == 0 ){
		for( fi = 0; fi < fpc; fi++ )
			if( poll_error(fileno(fps[fi])) )
				return -1;
	}
	return nready;
}

void usleep_bypoll(int usec)
{	int msec;

	msec = usec / 1000;
	if( msec == 0 )
		msec = 1;
	PollIns(msec,0,0L,0L);
}
