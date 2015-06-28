/*
 *  The following code is extracted from $ONEW/sys/sys.h which was
 *  made by members of <onew@etl.go.jp> <ftp://etlport.etl.go.jp/pub/onew>
 */
/*
 *  Get the count of bufferd characters.
 */
#ifdef __linux__
#if defined(__STDIO_STREAM_BUFFER_RAVAIL)
#define READYCC(fp)      __STDIO_STREAM_BUFFER_RAVAIL(fp)
#else
#if defined(_LIBIO_H) || defined(_IO_STDIO_H)
#define READYCC(fp)     (fp->_IO_read_end - fp->_IO_read_ptr)
#else
#define READYCC(fp)     (fp->_egptr - fp->_gptr)
#endif
#endif
#else
#if defined(__bsdi__) \
 || defined(__FreeBSD__) \
 || defined(__NetBSD__) \
 || defined(__OpenBSD__) \
 || defined(__MACHTEN__) \
 || defined(__CYGWIN__) || defined(__MINGW32__) \
 || defined(__APPLE__)
#define READYCC(fp)     (fp->_r)
#else
#ifdef __GNU_LIBRARY__
#define READYCC(fp)     (fp->__get_limit - fp->__bufp)
#else
#ifdef __EMX__
#define READYCC(fp)	(fp->_rcount)
#else
#if defined(sun) && defined(__x86_64__)
#define READYCC(fp)	((int*)fp)[6]
#elif defined(sun) && defined(m64) && defined(sparc)
#define READYCC(fp)	((int*)fp)[7]
#else
#if defined(_MSC_VER) && defined(UNDER_CE)
int Xready_cc(FILE *fp);
#define READYCC(fp)     Xready_cc(fp)
#else
#define READYCC(fp)     (fp->_cnt)
#endif
#endif
#endif
#endif
#endif
#endif


#if defined(HCASE)
#ifdef READYCC
#undef READYCC
#endif

#if HCASE == 1
#define READYCC(fp)     (fp->_IO_read_end - fp->_IO_read_ptr)
#endif

#if HCASE == 2
#define READYCC(fp)     (fp->_egptr - fp->_gptr)
#endif

#if HCASE == 3
#define READYCC(fp)     (fp->_r)
#endif

#if HCASE == 4
#define READYCC(fp)     (fp->__get_limit - fp->__bufp)
#endif

#if HCASE == 5
#define READYCC(fp)	(fp->_rcount)
#endif

#if HCASE == 6
#define READYCC(fp)     (fp->_cnt)
#endif

#if HCASE == 7
#define READYCC(fp)	READYCC_UNSUPPORTED()
#endif

#endif

typedef struct _RelayCtrl {
	int	rc_ctrl;
	int	rc_stat;
	int	rc_max_turns;
	int	rc_num_turns;
	double	rc_thru_time; /* initial period without limitation of turns */
	double	rc_max_packintvl;
	double	rc_packintvl;
	int	rc_min_packz; /* minimum packet size for a side in a turn */
	int	rc_packz;
	int	rc_concat;    /* waiting for concat in milli-seconds */
	int	rc_max_paras; /* for exemption of pipelined request */
	int	rc_num_paras;
	int   (*rc_idle_cb)(struct _RelayCtrl*,double,int);
	int	rc_exitfd; /* exit when this fd become ready */
} RelayCtrl;
typedef int (*relayCB)(RelayCtrl*,double,int);

#define RELAY_HALFDUP		1
#define RELAY_NOTHALFDUP	1
#define RELAY_SSL_ONLY		2
#define RELAY_NOTSSL		2
#define RELAY_BOTH_DATA		4
#define RELAY_EXITFD		8
#define RELAY_SSL_PEEK		0x0010
extern RelayCtrl *relayCtrlG;

#define	RELAY_ctrl	relayCtrl->rc_ctrl
#define	RELAY_stat	relayCtrl->rc_stat
#define RELAY_max_turns	relayCtrl->rc_max_turns
#define RELAY_num_turns	relayCtrl->rc_num_turns
#define RELAY_thru_time	relayCtrl->rc_thru_time
#define	RELAY_max_packintvl	relayCtrl->rc_max_packintvl
#define	RELAY_packintvl	relayCtrl->rc_packintvl
#define	RELAY_half_dup	(relayCtrl->rc_ctrl & RELAY_HALFDUP)
#define RELAY_ssl_only	(relayCtrl->rc_ctrl & RELAY_SSL_ONLY)
#define RELAY_ssl_peek	(relayCtrl->rc_ctrl & RELAY_SSL_PEEK)
#define RELAY_min_packz	relayCtrl->rc_min_packz
#define RELAY_packz	relayCtrl->rc_packz
#define RELAY_concat	relayCtrl->rc_concat
#define RELAY_num_paras	relayCtrl->rc_num_paras
#define RELAY_max_paras	relayCtrl->rc_max_paras
#define RELAY_idle_cb	relayCtrl->rc_idle_cb
#define RELAY_exitfd	relayCtrl->rc_exitfd
#define RELAY_getxfd()	((RELAY_ctrl&RELAY_EXITFD)?RELAY_exitfd:-1)
#define RELAY_setxfd(f)	(RELAY_ctrl|=RELAY_EXITFD),(RELAY_exitfd=f)

#ifndef _MSC_VER
#include <unistd.h>
#endif

int top_fd(int fd,int rw);
int file_issock(int fd);
int file_isreg(int fd);
int file_isselectable(int fd);
int isUDPsock(int sock);

#ifndef FL_PAR
#define FL_PAR const char *FL_F,int FL_L
#endif
int ready_cc(FILE *fp);
int fPollIn_FL(FL_PAR,FILE *fp,int msec);
#define fPollIn(fp,ms) fPollIn_FL(FL_ARG,fp,ms)
int PollIn1(int fd,int msec);
int PollIn_FL(FL_PAR,int fd,int msec);
#define PollIn(fd,ms) PollIn_FL(FL_ARG,fd,ms)
int PollIn_HUP(int on);
int _PollIn(int fd,int msec);
int poll_error(int fd);
int pollPipe(int pfd,int slpmsec);
int PollIns(int timeout,int size,int *mask,int *rmask);
int fPollIns(int timeout,int fpc,FILE *fps[],int rdv[]);
int PollOut(int fd,int timeout);
int gotOOB(int fd);
int withOOB(int fd);

int waitShutdownSocket(FL_PAR,int fd,int ms);
int exceptionReady(int sock);
int pollIX(const char *wh,double timeout,int in,int ex);
int watchBothside(int in,int out);
int receiverReset(const char *wh,double timeout,int in,int out);
int inputReady(int sock,int *rd);
int finputReady(FILE *fs,FILE *ts);
int fpop_fd(FILE *fp);

int connHUP();
int connRESETbypeer();
int readyAlways(int fd);
int PollInsOuts(int timeout,int nfds,int fdv[],int ev[],int rev[]);

int simple_relayf(FILE *src,FILE *dst);
int simple_relay(int src,int dst);
void frelay(int timeout,int s1,int d1,int s2,int d2,int (*relayfunc)(FILE*,FILE*));
void usleep_bypoll(int usec);
void relay2_cntl(int timeout,int s1,int d1,int s2,int d2,int s3,int d3,int (*cntlfunc)(void*,...),void *arg);

#ifndef NO_INC_IO
#if defined(_MSC_VER) && defined(UNDER_CE)
#include <io.h>
#endif
#endif

#if defined(FMT_CHECK)
#define daemonlog(flags,fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#define syslog_ERROR(fmt,...)    fprintf(stderr,fmt,##__VA_ARGS__)
#else
#define FMT_daemonlog    daemonlog
#define FMT_syslog_ERROR syslog_ERROR
int FMT_daemonlog(const char *flags,const char *fmt,...);
int FMT_syslog_ERROR(const char *fmt, ...);
#endif
