#ifndef _YSELECT_H
#define _YSELECT_H

#ifndef FD_SETSIZE
#include <sys/types.h>
#ifndef FD_SETSIZE
#ifdef _MSC_VER
#include "ywinsock.h"
#else
#include <sys/time.h>
#ifndef FD_SETSIZE
#include <sys/select.h>
#endif
#endif
#endif
#endif

#ifdef FD_SET
typedef fd_set FdSet;
#else
typedef int FdSet;
#define FD_ZERO(fdset)		((*fdset) = 0)
#define FD_SET(fd,fdset)	((*fdset) |= (1 << fd))
#define FD_ISSET(fd,fdset)	(((*fdset) & (1 << fd)) != 0)
#endif

#ifndef FD_SETSIZE
#define FD_SETSIZE	32
#endif

#if defined(FD_SETSIZE) && 2048 < FD_SETSIZE
#undef FD_SETSIZE
#define FD_SETSIZE	2048
#endif

#endif /* _YSELECT_H */
