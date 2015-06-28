#include "ystring.h"
#include "log.h"
#include <stdio.h>
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE and FD_SET(),etc. */

int _PollIns(int timeout,int size,int *mask,int *rmask){
	struct timeval tvbuf,*tv;
	int fi,fd,maxfd;
	FdSet Rmask,Xmask;
	int nready,rready;

	if( timeout ){
		tv = &tvbuf;
		tv->tv_sec  = timeout / 1000;
		tv->tv_usec = (timeout % 1000) * 1000;
	}else	tv = NULL;

	maxfd = -1;
	FD_ZERO(&Rmask);
	for(fi = 0; fi < size; fi++){
		fd = mask[fi];
		fd = SocketOf(fd);

		if( 0 <= fd ){
			FD_SET(fd,&Rmask);
			if( maxfd < fd )
				maxfd = fd;
		}
		rmask[fi] = 0;
	}
	Xmask = Rmask;
	nready = select(SELECT_WIDTH(maxfd),&Rmask,NULL,&Xmask,tv);
	if( nready < 0 && isWindows() ){
		for( fi = 0; fi < size; fi++ ){
			fd = mask[fi];
		}
	}
	if( nready <= 0 )
		return nready;

	rready = 0;
	for(fi = 0; fi < size; fi++){
		int ofd = mask[fi];
		fd = mask[fi];
		fd = SocketOf(fd);

		if( 0 <= fd ){
			if( FD_ISSET(fd,&Rmask) || FD_ISSET(fd,&Xmask) ){
				rready++;
				rmask[fi] = 1;
			}else	rmask[fi] = 0;
		}else	rmask[fi] = 0;
	}
	return rready;
}
int _PollIn1(int fd,int timeout){
	struct timeval tv;
	FdSet Rmask,Xmask;
	int nready;
	int ofd = fd;

	if( fd < 0 )
		return -1;
	fd = SocketOf(fd);

	if( timeout ){
		tv.tv_sec  = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}

	FD_ZERO(&Rmask);
	FD_SET(fd,&Rmask);
	Xmask = Rmask;
	nready = select(FD_SETSIZE,&Rmask,NULL,&Xmask,timeout?&tv:NULL);
	if( nready <= 0 )
		return nready;
	nready = FD_ISSET(fd,&Rmask) ? 1 : 0;
	return nready;
}
