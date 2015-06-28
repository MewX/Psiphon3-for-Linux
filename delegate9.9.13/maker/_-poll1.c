#include <poll.h>
#include <stropts.h>
#include <errno.h>
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */

int _PollIns(int timeout,int size,int *mask,int *rmask){
	struct pollfd pfd[FD_SETSIZE];
	int fd,nfd,rfd,nready,rready;
	int fi;

	nfd = 0;
	for(fi = 0; fi < size; fi++){
		fd = mask[fi];
		if( 0 <= fd ){
			pfd[nfd].fd = mask[fi];
			pfd[nfd].events = (POLLIN|POLLPRI);
			nfd++;
		}
		rmask[fi] = 0;
	}
	nready = poll(pfd,nfd,timeout?timeout:-1);
	if( nready <= 0 )
		return nready;

	rready = 0;
	rfd = 0;
	for(fi = 0; fi < size; fi++){
		fd = mask[fi];
		if( 0 <= fd ){
			if( pfd[rfd].revents & POLLIN_MASK ){
				rready++;
				rmask[fi] = 1;
			}else	rmask[fi] = 0;
			rfd++;
		}else	rmask[fi] = 0;
	}
	return rready;
}
int _PollIn1(int fd,int timeout){
	struct pollfd pfd[FD_SETSIZE];
	int nready;

	if( fd < 0 )
		return -1;

	pfd[0].fd = fd;
	pfd[0].events = (POLLIN|POLLPRI);
	pfd[0].revents = 0;

	nready = poll(pfd,1,timeout?timeout:-1);
	if( nready <= 0 )
		return nready;

	nready = (pfd[0].revents & POLLIN_MASK) ? 1 : 0;
	return nready;
}
