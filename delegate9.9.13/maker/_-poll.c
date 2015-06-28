/*
 *	@poll.c: this file will be used in systems with poll()
 */
#if defined(_nec_ews) || defined(BUGGY_POLL)
DO NOT USE ITS BUGGY POLL
#endif

#include <poll.h>
#include <stropts.h>
#include <errno.h>
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
int BrokenSocket(FL_PAR,int fd);

static int _gotRESET = -1;
int connRESETbypeer(){ return _gotRESET; }
static int _gotHUP = -1;
int connHUP(){ return _gotHUP; }

static void checkERR(const char *where,int fd,int revents)
{	int xerrno;

	xerrno = errno;
	if( revents & POLLHUP ){
		_gotHUP = fd;
		if( xerrno )
		syslog_ERROR("%s.POLLHUP (%d) errno=%d\n",where,fd,xerrno);
		else
		syslog_DEBUG("%s.POLLHUP (%d) errno=%d\n",where,fd,xerrno);
	}
	if( revents & POLLNVAL ){
		_gotHUP = fd;
		syslog_ERROR("%s.POLLNVAL (%d) errno=%d\n",where,fd,xerrno);
	}
	errno = xerrno;
}

int PollOut(int fd,int timeout)
{	struct pollfd pfd[FD_SETSIZE];
	int nready;

	if( fd < 0 )
		return -1;

	pfd[0].fd = fd;
	pfd[0].events = POLLOUT;

	if( timeout == TIMEOUT_IMM ){
		nready = poll(pfd,1,0);
	}else
	nready = poll(pfd,1,timeout?timeout:-1);
	if( nready <= 0 )
		return nready;

	return (pfd[0].revents & POLLOUT) ? 1 : 0;
}

int pollIn_HUP = 1;
int PollIn_HUP(int on){ int xon = pollIn_HUP; pollIn_HUP = on; return xon; }
#define POLLIN_MASK	(POLLIN|POLLPRI|(pollIn_HUP?POLLHUP:0))

int _gotOOB;

int PollIn1(int fd,int timeout)
{	struct pollfd pfd[FD_SETSIZE];
	int nready;

	_gotRESET = -1;
	_gotHUP = -1;
	_gotOOB = 0;

	if( fd < 0 )
		return -1;

	pfd[0].fd = fd;
	pfd[0].events = (POLLIN|POLLPRI);
	pfd[0].revents = 0;

	errno = 0;
	if( timeout == TIMEOUT_IMM ){
		nready = poll(pfd,1,0);
	}else
	nready = poll(pfd,1,timeout?timeout:-1);
	if( nready <= 0 )
		return nready;

	checkERR("PollIn",fd,pfd[0].revents);

	if( pfd[0].revents == POLLHUP )
		syslog_DEBUG("PollIn(%d,%d) = POLLHUP\n",fd,timeout);

	if( pfd[0].revents & POLLPRI )
	{
		if( BrokenSocket(FL_ARG,fd) ){
		}else
		_gotOOB = fd+1;
	}
	return (pfd[0].revents & POLLIN_MASK) ? 1 : 0;
}

int PollIns(int timeout,int size,int *mask,int *rmask)
{	struct pollfd pfd[FD_SETSIZE];
	int fd,nfd,rfd,nready,rready;
	int fi;

	_gotRESET = -1;
	_gotHUP = -1;
	_gotOOB = 0;

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
	errno = 0;
	if( timeout == TIMEOUT_IMM ){
		nready = poll(pfd,nfd,0);
	}else
	nready = poll(pfd,nfd,timeout?timeout:-1);
	if( nready <= 0 )
		return nready;

	rready = 0;
	rfd = 0;
	for(fi = 0; fi < size; fi++){
		fd = mask[fi];
		if( 0 <= fd ){
			checkERR("PollIns",fd,pfd[rfd].revents);

	if( pfd[fd].revents == POLLHUP )
		syslog_DEBUG("PollIns(%d,%d) = POLLHUP\n",fd,timeout);

			if( pfd[rfd].revents & POLLIN_MASK ){
				if( pfd[rfd].revents & POLLPRI ){
					if( BrokenSocket(FL_ARG,fd) ){
				syslog_ERROR("[%d] poll() detected RST\n",fd);
					}else{
					_gotOOB = fd+1;
				syslog_DEBUG("[%d] poll() detected OOB\n",fd);
					}
					if((pfd[rfd].revents & POLLIN)==0)
					syslog_ERROR("[%d] OOB only\n",fd);
				}
				rready++;
				rmask[fi] = 1;
			}else	rmask[fi] = 0;
			rfd++;
		}else	rmask[fi] = 0;
	}
	return rready;
}

int withOOB(int fd){
	struct pollfd pfd[1];
	int ready;

	pfd[0].fd = fd;
	pfd[0].events = POLLPRI;
	ready = poll(pfd,1,0);
	syslog_DEBUG("[%d] withOOB ? ready=%d %X\n",fd,ready,pfd[0].revents);
	if( 0 < ready ){
		if( pfd[0].revents & POLLPRI )
			return 1;
	}
	return 0;
}

int PollInsOuts(int timeout,int nfds,int fdv[],int ev[],int rev[])
{	struct pollfd fds[1024];
	int fi,ev1,ev2,nready;

	for( fi = 0; fi < nfds; fi++ ){
		fds[fi].fd = fdv[fi];
		fds[fi].revents = 0;
		ev1 = ev[fi];
		ev2 = 0;
		if( ev1 & PS_IN  ) ev2 |= POLLIN;
		if( ev1 & PS_PRI ) ev2 |= POLLPRI;
#ifdef POLLRDHUP
		if( ev1 & PS_PRI ) ev2 |= POLLRDHUP;
#endif
		if( ev1 & PS_OUT ) ev2 |= POLLOUT;
		fds[fi].events = ev2;
	}
	if( timeout == TIMEOUT_IMM ){
		nready = poll(fds,nfds,0);
	}else
	nready = poll(fds,nfds,timeout);
	for( fi = 0; fi < nfds; fi++ ){
		ev2 = fds[fi].revents;
		ev1 = 0;
		if( ev2 & POLLIN   ) ev1 |= PS_IN;
		if( ev2 & POLLPRI  ) ev1 |= PS_PRI;
#ifdef POLLRDHUP
		if( ev2 & POLLRDHUP) ev1 |= PS_PRI;
#endif
		if( ev2 & POLLOUT  ) ev1 |= PS_OUT;
		if( ev2 & POLLERR  ) ev1 |= PS_ERR;
		if( ev2 & POLLHUP  ) ev1 |= PS_HUP;
		if( ev2 & POLLNVAL ) ev1 |= PS_NVAL;
		rev[fi] = ev1;
		if( ev1 & PS_ERR ){
		    syslog_ERROR("PollInsOuts(%d/%d) %d ERR %X %X err=%d\n",
			fi,nfds,nready,ev1,ev2,errno);
		}
	}
	return nready;
}
