#ifndef _LOG_H
#define _LOG_H

typedef struct {
	int	so_sndbuf;
	int	so_rcvbuf;
	int	so_winmtu;
	short	so_sndwait;
	short	so_sndmutex:1,
		so_sndnodelay:1;
} SockCtl;

typedef struct {
	int	ac_acrc;
	int	ac_time;
	int	ac_count;
	int	ac_code;
} TmpAcl;

typedef struct {
	Int64	ac_active;
	Int64	ac_doauth;
	char	ac_authUser[16];
	char	ac_authPass[16];
	int	ac_authNone;
	int	ac_authOk;
	int	ac_authErr;
	int	ac_accPassed;
	int	ac_accDenied;
} AppCtl;

typedef struct {
	int	rs_stat;
	int	rs_vsaddr[32]; /* enough for IPv6 addr. */
	int	rs_req ; /* sent req. */
	int	rs_resp; /* got resp. */
	int	rs_reqlast;
	int	rs_resplast;
	int	rs_hit;
	int	rs_miss;
	double	rs_time;
} ResStat;

typedef struct {
	int	yy_ctl[4];
} YyCtl;

typedef struct {
	int	lc_flags[8];
	int	lc_PEEK_CLIENT_REQUEST:1,
		lc_RAND_TRACE:1,
		lc_LOG_GENERIC:1,
		lc_resvb:29;
	int	lc_putUDPlog;
	int	lc_UDPsockfd[2];
	int	lc_UDPsockfh[2]; /* for Win */
	int	lc_LOG_recvTid;
	int	lc_HTTP_opts;
	int	lc_HTTP_cacheopt;
	int	lc_reserved[3];

	int	lc_tcp_accepts;
	int	lc_tcp_connects;
	int	lc_tcp_connected;
	int	lc_tcp_connectedPara;
	int	lc_tcp_conntriedPara;
	int	lc_tcp_connectedPref;
	int	lc_tcp_connRecycled;
	int	lc_tcp_connRecycleOk;
	int	lc_tcp_connAbandon1;
	int	lc_tcp_connAbandon2;
	int	lc_tcp_connAbandon3;
	int	lc_tcp_connAbandon4;
	int	lc_tcp_connRefused;
	int	lc_tcp_connTimeout;
	int	lc_tcp_connDelayMax;
	int	lc_tcp_connDelays;  /* total delayes in milli-secs */
	int	lc_tcp_connSorted;  /* auto. sorting on failure or delay */

	int	lc_res_requests;
	int	lc_res_retrieved;
	int	lc_res_notfound;
	int	lc_res_entries;
	int	lc_res_refreshed;
	int	lc_res_cachehit;
	int	lc_res_time;
	int	lc_res_expired;
	ResStat	lc_res_stats[8]; /* stats. for each DNS server */

	int	lc_app_requests; /* HTTP requests */
	int	lc_app_cachehit; /* HTTP cachehits */
	int	lc_app_respIncomplete; /* incomplete recv. from HTTP server */
	int	lc_app_keepAliveCL;
	int	lc_app_keepAliveCLreu;
	int	lc_app_keepAliveSV;
	int	lc_app_keepAliveSVreu;
	int	lc_enc_gzip;
	int	lc_dec_gzip;
	int	lc_sentBytes;
	int	lc_recvBytes;

	SockCtl	so_sockCtl;
	TmpAcl	ac_tmpAcl[32];
	AppCtl	ac_appCtl;
	int	lc_total_served;
	int	ac_reserved[127];
	int	so_ccsvCnt;
	int	so_ccsvCtl;
	int	so_ccsvSock;
	int	lc_md5_in;
	int	lc_md5_out;
	YyCtl	yy_ctl;
} LogControl07;
#define LogControl LogControl07
typedef struct { /* not to be shared */
	int	pl_type0;
	int	pl_UDPsock[2];
	int	pl_total_served;
	int	pl_resvi[4];
} PrivateLogControl;
extern LogControl *logControl08;
#define logControl logControl08
extern PrivateLogControl *mylogControl;
#define LC_PST	0
#define LC_TMP	1 /* temporary flags pushed during capturing */

#define LogControlSet(nset) \
 LogControl logControlBuf[nset]; \
 LogControl *logControl = logControlBuf; \
 PrivateLogControl mylogControlBuf[nset]; \
 PrivateLogControl *mylogControl = mylogControlBuf;

typedef LogControl LogControls[2];

#define LOG_type0	mylogControl[LC_PST].pl_type0
#define LOG_UDPsock	mylogControl[LC_PST].pl_UDPsock
int inheritLogControl();
extern int NO_LOGGING;

#define ECC_svCtl	logControl[LC_PST].so_ccsvCtl
#define ECC_svCnt	logControl[LC_PST].so_ccsvCnt
#define ECC_svSock	logControl[LC_PST].so_ccsvSock
#define ECC_ENABLE	0x00000001
#define EccEnabled()	(ECC_svCtl & ECC_ENABLE)

#define LOGMD5_IN	logControl[LC_PST].lc_md5_in
#define LOGMD5_OUT	logControl[LC_PST].lc_md5_out

#define LOG_type	logControl[LC_PST].lc_flags[0]
#define LOG_type1	logControl[LC_PST].lc_flags[0]
#define LOG_type1T	logControl[LC_TMP].lc_flags[0]
#define LOG_type2	logControl[LC_PST].lc_flags[1]
#define LOG_type3	logControl[LC_PST].lc_flags[2]
#define LOG_type3T	logControl[LC_TMP].lc_flags[2]
#define LOG_type4	logControl[LC_PST].lc_flags[3]
#define LOG_bugs	logControl[LC_PST].lc_flags[4]
#define LOG_VERBOSE	logControl[LC_PST].lc_flags[5]
#define STOP_LOGGING	logControl[LC_PST].lc_flags[6]
#define LOG_owner	logControl[LC_PST].lc_flags[7]
#define LOG_WH_SHARED	1
#define lLOGSHARED()	(LOG_owner == LOG_WH_SHARED)
#define HTTP_opts	logControl[LC_PST].lc_HTTP_opts
#define HTTP_cacheopt	logControl[LC_PST].lc_HTTP_cacheopt

#define PEEK_CLIENT_REQUEST logControl[LC_PST].lc_PEEK_CLIENT_REQUEST
#define RAND_TRACE	logControl[LC_PST].lc_RAND_TRACE
#define LOG_GENERIC	logControl[LC_PST].lc_LOG_GENERIC
#define LOG_UDPsockfd	logControl[LC_PST].lc_UDPsockfd
#define LOG_UDPsockfh	logControl[LC_PST].lc_UDPsockfh
#define LOG_putUDPlog	logControl[LC_PST].lc_putUDPlog
#define lPUTUDPLOG()	logControl[LC_PST].lc_putUDPlog
#define LOG_recvTid	logControl[LC_PST].lc_LOG_recvTid

#define LOGX_tcpAcc		logControl[LC_PST].lc_tcp_accepts
#define LOGX_tcpCon		logControl[LC_PST].lc_tcp_connects
#define LOGX_tcpConSuccess	logControl[LC_PST].lc_tcp_connected
#define LOGX_tcpConParaOk	logControl[LC_PST].lc_tcp_connectedPara
#define LOGX_tcpConParaTried	logControl[LC_PST].lc_tcp_conntriedPara
#define LOGX_tcpConPrefOk	logControl[LC_PST].lc_tcp_connectedPref
#define LOGX_tcpConRecycled	logControl[LC_PST].lc_tcp_connRecycled
#define LOGX_tcpConRecycleOk	logControl[LC_PST].lc_tcp_connRecycleOk
#define LOGX_tcpConAbandon1	logControl[LC_PST].lc_tcp_connAbandon1
#define LOGX_tcpConAbandon2	logControl[LC_PST].lc_tcp_connAbandon2
#define LOGX_tcpConAbandon3	logControl[LC_PST].lc_tcp_connAbandon3
#define LOGX_tcpConAbandon4	logControl[LC_PST].lc_tcp_connAbandon4
#define LOGX_tcpConRefused	logControl[LC_PST].lc_tcp_connRefused
#define LOGX_tcpConTimeout	logControl[LC_PST].lc_tcp_connTimeout
#define LOGX_tcpConDelays	logControl[LC_PST].lc_tcp_connDelays
#define LOGX_tcpConDelayMax	logControl[LC_PST].lc_tcp_connDelayMax
#define LOGX_tcpConSorted	logControl[LC_PST].lc_tcp_connSorted
#define LOGX_resReq		logControl[LC_PST].lc_res_requests
#define LOGX_resRet		logControl[LC_PST].lc_res_retrieved
#define LOGX_resUnk		logControl[LC_PST].lc_res_notfound
#define LOGX_resEnt		logControl[LC_PST].lc_res_entries
#define LOGX_resUpd		logControl[LC_PST].lc_res_refreshed
#define LOGX_resHit		logControl[LC_PST].lc_res_cachehit
#define LOGX_resStats		logControl[LC_PST].lc_res_stats
#define LOGX_appReq		logControl[LC_PST].lc_app_requests
#define LOGX_appHit		logControl[LC_PST].lc_app_cachehit
#define LOGX_app_respIncomplete	logControl[LC_PST].lc_app_respIncomplete
#define LOGX_app_keepAliveCL	logControl[LC_PST].lc_app_keepAliveCL
#define LOGX_app_keepAliveCLreu	logControl[LC_PST].lc_app_keepAliveCLreu
#define LOGX_app_keepAliveSV	logControl[LC_PST].lc_app_keepAliveSV
#define LOGX_app_keepAliveSVreu	logControl[LC_PST].lc_app_keepAliveSVreu
#define LOGX_gzip		logControl[LC_PST].lc_enc_gzip
#define LOGX_gunzip		logControl[LC_PST].lc_dec_gzip
#define LOGX_sentBytes		logControl[LC_PST].lc_sentBytes
#define LOGX_recvBytes		logControl[LC_PST].lc_recvBytes
#define LOGX_resTime		logControl[LC_PST].lc_res_time
#define HOSTS_expired		logControl[LC_PST].lc_res_expired
#define TmpACL			logControl[LC_PST].ac_tmpAcl
#define AppProtoCtl		logControl[LC_PST].ac_appCtl
#define LOGX_authOk		logControl[LC_PST].ac_appCtl.ac_authOk
#define LOGX_authErr		logControl[LC_PST].ac_appCtl.ac_authErr
#define LOGX_authNone		logControl[LC_PST].ac_appCtl.ac_authNone
#define LOGX_accPassed		logControl[LC_PST].ac_appCtl.ac_accPassed
#define LOGX_accDenied		logControl[LC_PST].ac_appCtl.ac_accDenied
#define SockCtl			logControl[LC_PST].so_sockCtl
#define yyCtl			logControl[LC_PST].yy_ctl

#define SOCK_SNDBUF_MAX		SockCtl.so_sndbuf
#define SOCK_RCVBUF_MAX		SockCtl.so_rcvbuf
#define SOCK_SNDMUTEX		SockCtl.so_sndmutex
#define SOCK_SNDNODELAY		SockCtl.so_sndnodelay
#define SOCK_SNDWAIT		SockCtl.so_sndwait
#define WIN_MTU			SockCtl.so_winmtu
#define SOCK_NOHINERIT		SockCtl.so_noinherit

#define L_ISCHILD	0x04000000
#define lISCHILD()	(LOG_type0 & L_ISCHILD)

#define L_LEVEL		0x0000000F
#define LOGLEVEL	(LOG_type&0xF)

#define L_SYNC		0x00000010
#define L_FG		0x00000020
#define L_TTY		0x00000040
#define L_CONSOLE	0x00000080
#define L_SILENT	0x00000100
#define	L_TERSE		0x00000200
#define L_VERB		0x00000400
#define L_EXEC		0x00000800
#define L_FORK		0x00001000
#define L_STICK		0x00002000
#define L_LOCK		0x00004000
#define L_FILETRACE	0x00008000
#define L_ARGDUMP	0x00010000
#define L_VERBABORT	0x00020000
#define L_MEMPUSH	0x00040000
#define L_SOCKET	0x00080000
#define L_HOSTMATCH	0x10000000
#define L_MOUNT		0x20000000
#define L_RAND_TRACE	0x40000000
#define L_THREAD	0x80000000

#define L_TRACE		0x00100000
#define L_NOEXEC	0x00200000
#define L_TRVERB	0x00400000
#define L_TRTERSE	0x00800000
#define L_SIGCHLD	0x01000000
#define L_REINIT	0x02000000
#define L_ISFUNC	0x08000000

#define lSYNC()	  	(LOG_type & L_SYNC)
#define lFG()	  	(LOG_type & L_FG)
#define lTTY()	  	(LOG_type & L_TTY)
#define lCONSOLE()	(LOG_type & L_CONSOLE)
#define lSILENT()	(LOG_type & L_SILENT)
#define lTERSE()  	(LOG_type & L_TERSE)
#define lVERB()	  	(LOG_type & L_VERB)
#define lEXEC()   	(LOG_type & L_EXEC)
#define lFORK()	  	(LOG_type & L_FORK)
#define lSTICK()  	(LOG_type & L_STICK)
#define lLOCK()	  	(LOG_type & L_LOCK)
#define lFILETRACE()	(LOG_type & L_FILETRACE)
#define lARGDUMP()	(LOG_type & L_ARGDUMP)
#define lVERBABORT()	(LOG_type & L_VERBABORT)
#define lMEMPUSH()	(LOG_type & L_MEMPUSH)
#define lMOUNT()	(LOG_type & L_MOUNT)
#define lSOCKET()	(LOG_type & L_SOCKET)
#define lHOSTMATCH()	(LOG_type & L_HOSTMATCH)
#define lTHREAD()	(LOG_type & L_THREAD)

#define L_TIMEFMT	0x00000007
#define L_FILEDESC	0x00000008
#define lFILEDESC()	(LOG_type2 & L_FILEDESC)
#define L_CHARSET	0x00000010
#define lCHARSET()	(LOG_type2 & L_CHARSET)
#define L_GATEWAY	0x00000020
#define lGATEWAY()	(LOG_type2 & L_GATEWAY)
#define L_SEXEC		0x00000040
#define lSEXEC()	(LOG_type2 & L_SEXEC)
#define L_CRYPT		0x00000080
#define lCRYPT()	(LOG_type2 & L_CRYPT)
#define L_RCONFIG	0x00000100
#define lRCONFIG()	(LOG_type2 & L_RCONFIG)
#define L_HTMLGEN	0x00000200
#define L_HTMLGENV	0x00000400
#define lHTMLGEN()	(LOG_type2 & (L_HTMLGENV|L_HTMLGEN))
#define lHTMLGENV()	(LOG_type2 & L_HTMLGENV)
#define L_NOTHREAD	0x00000800
#define lNOTHREAD()	(LOG_type2 & L_NOTHREAD)
#define L_STRICT	0x00001000
#define lSTRICT()	(LOG_type2 & L_STRICT)
#define L_LOCKSHARED	0x00002000
#define L_SPAWNLOG	0x00004000
#define lSPAWNLOG()	(LOG_type2 & L_SPAWNLOG)
#define L_PATHFIND	0x00008000
#define lPATHFIND()	(LOG_type2 & L_PATHFIND)
#define L_SECRET	0x00010000
#define lSECRET()	(LOG_type2 & L_SECRET)
#define L_URLFIND	0x00020000
#define lURLFIND()	(LOG_type2 & L_URLFIND)
#define L_EMU_NOFORK	0x00040000
#define lEMU_NOFORK()	(LOG_type2 & L_EMU_NOFORK)
#define L_NO_VSNPRINTF	0x00080000
#define lNO_VSNPRINTF()	(LOG_type2 & L_NO_VSNPRINTF)
#define L_TLS		0x00100000
#define lTLS()		(LOG_type2 & L_TLS)
#define L_ACCESSCTL	0x00200000
#define lACCESSCTL()	(LOG_type2 & L_ACCESSCTL)
#define L_DEBUGMSG	0x00400000
#define lDEBUGMSG()	(LOG_type2 & L_DEBUGMSG)
#define L_COUNTER	0x00800000
#define lCOUNTER()	(LOG_type2 & L_COUNTER)
#define L_FILEOPEN	0x01000000
#define lFILEOPEN()	(LOG_type2 & L_FILEOPEN)
#define L_NOINITLOG	0x02000000
#define lNOINITLOG()	(LOG_type2 & L_NOINITLOG)
#define L_NOPROTOLOG	0x04000000
#define lNOPROTOLOG()	(LOG_type2 & L_NOPROTOLOG)
#define L_DEBUGLOCK	0x08000000
#define lDEBUGLOCK()	(LOG_type2 & L_DEBUGLOCK)
#define L_NO_WSOCKWA	0x10000000
#define lNO_WSOCKWA()	(LOG_type2 & L_NO_WSOCKWA)
#define L_DYLIB		0x20000000
#define lDYLIB()	(LOG_type2 & L_DYLIB)
#define L_POLL		0x40000000
#define lPOLL()		(LOG_type2 & L_POLL)
#define L_SECUREEXT	0x80000000
#define lSECUREEXT()	(LOG_type2 & L_SECUREEXT)

#define L_MALLOC	0x0000000F
#define lMALLOC()	(LOG_type3 & L_MALLOC)
#define L_TRANSMIT	0x00000010
#define lTRANSMIT()	(LOG_type3 & L_TRANSMIT)
#define L_ZLIB		0x00000020
#define lZLIB()		(LOG_type3 & L_ZLIB)
#define L_SINGLEP	0x00000040
#define lSINGLEP()	(LOG_type3 & L_SINGLEP)
#define L_MULTIST	0x00000080
#define lMULTIST()	(LOG_type3 & L_MULTIST)

#define L_CONNECT	0x00000100
#define lCONNECT()	(LOG_type3 & L_CONNECT)
#define L_ENVIRON	0x00000200
#define lENVIRON()	(LOG_type3 & L_ENVIRON)
#define L_CURRENT	0x00000400
#define lCURRENT()	(LOG_type3 & L_CURRENT)
#define L_NOGZIP	0x00000800
#define lNOGZIP()	(LOG_type3 & L_NOGZIP)

#define L_THREADSIG	0x00001000
#define lTHREADSIG()	(LOG_type3 & L_THREADSIG)
#define L_NOMMAP	0x00002000
#define lNOMMAP()	(LOG_type3 & L_NOMMAP)
#define L_NOMMAPLOG	0x00004000
#define lNOMMAPLOG()	(LOG_type3 & L_NOMMAPLOG)
#define L_NOUDPLOG	0x00008000
#define lNOUDPLOG()	(LOG_type3 & L_NOUDPLOG)

#define L_PEEPCLDG	0x00010000
#define L_PEEPDGCL	0x00020000
#define L_PEEPCL	0x00030000
#define lPEEPCLDG()	(LOG_type3 & L_PEEPCLDG)
#define lPEEPDGCL()	(LOG_type3 & L_PEEPDGCL)
#define lPEEPCL()	(LOG_type3 & L_PEEPCL)
#define L_PEEPDGSV	0x00040000
#define L_PEEPSVDG	0x00080000
#define L_PEEPSV	0x000C0000
#define lPEEPSV()	(LOG_type3 & L_PEEPSV)
#define lPEEPDGSV()	(LOG_type3 & L_PEEPDGSV)
#define lPEEPSVDG()	(LOG_type3 & L_PEEPSVDG)

#define L_LOGCTRL	0x00100000
#define lLOGCTRL()	(LOG_type3 & L_LOGCTRL)

#define L_BCASTLOG	0x00200000
#define lBCASTLOG()	(LOG_type3T & L_BCASTLOG)
#define lVERB_T()	(LOG_type1T & L_VERB)
#define lTERSE_T()	(LOG_type1T & L_TERSE)
#define lSILENT_T()	(LOG_type1T & L_SILENT)

#define L_INITDONE	0x00400000
#define lINITDONE()	(LOG_type3 & L_INITDONE)
#define L_WINSOCK	0x00800000
#define lWINSOCK()	(LOG_type3 & L_WINSOCK)
#define L_MEMUSAGE	0x01000000
#define lMEMUSAGE()	(LOG_type3 & L_MEMUSAGE)
#define L_FCLOSEQ	0x02000000
#define lFCLOSEQ()	(LOG_type3 & L_FCLOSEQ)
#define L_NOSERVKA	0x04000000
#define lNOSERVKA()	(LOG_type3 & L_NOSERVKA)
#define L_NOCLNTKA	0x08000000
#define lNOCLNTKA()	(LOG_type3 & L_NOCLNTKA)
#define L_FGETSBB_IZ	0x10000000 /* insize fgetsByBlock() */
#define lFGETSBB_IZ()	(LOG_type3 & L_FGETSBB_IZ)
#define L_NOSSLCHECK	0x20000000
#define lNOSSLCHECK()	(LOG_type3 & L_NOSSLCHECK)
#define L_NOWIN		0x40000000
#define lNOWIN()	(LOG_type3 & L_NOWIN)
#define L_NOCACHE	0x80000000
#define lNOCACHE()	(LOG_type3 & L_NOCACHE)

#define L_CONNSCAT	0x00000010
#define lCONNSCAT()	(LOG_type4 & L_CONNSCAT)
#define L_NOCONNRECYC	0x00000020
#define lNOCONNRECYC()	(LOG_type4 & L_NOCONNRECYC)
#define L_CONNPARA	0x00000040
#define lCONNPARA()	(LOG_type4 & L_CONNPARA)
#define L_CONNQUE	0x00000080
#define lCONNQUE()	(LOG_type4 & L_CONNQUE)
#define L_ORIGDST	0x00000100
#define lORIGDST()	(LOG_type4 & L_ORIGDST)
#define L_PROCLOG	0x00000200
#define lPROCLOG()	(LOG_type4 & L_PROCLOG)
#define L_NOSOCKINH	0x00000400
#define lNOSOCKINH()	(LOG_type4 & L_NOSOCKINH)
#define L_DOSOCKINH	0x00000800
#define lDOSOCKINH()	(LOG_type4 & L_DOSOCKINH)
#define L_FXNUMSERV	0x00001000
#define lFXNUMSERV()	(LOG_type4 & L_FXNUMSERV)
#define L_WOSOCKINH	0x00002000
#define lWOSOCKINH()	(LOG_type4 & L_WOSOCKINH) /* emulate non-inheritable */
#define L_DOSOCKDUP	0x00004000
#define lDOSOCKDUP()	(LOG_type4 & L_DOSOCKDUP)
#define L_NOSIGPIPE	0x00008000
#define lNOSIGPIPE()	(LOG_type4 & L_NOSIGPIPE)
#define L_NOAUTHPROXY	0x00010000
#define lNOAUTHPROXY()	(LOG_type4 & L_NOAUTHPROXY)
#define L_ACCLOG	0x00020000
#define lACCLOG()	(LOG_type4 & L_ACCLOG)
#define L_IMMREJECT	0x00040000
#define lIMMREJECT()	(LOG_type4 & L_IMMREJECT)
#define L_DONTHT	0x00080000
#define lDONTHT()	(LOG_type4 & L_DONTHT)
#define L_QUIET		0x00100000
#define lQUIET()	(LOG_type4 & L_QUIET)
#define L_COPYCLADDR	0x00200000
#define lCOPYCLADDR()	(LOG_type4 & L_COPYCLADDR)
#define L_SOCKPAIRNM	0x00400000
#define lSOCKPAIRNM()	(LOG_type4 & L_SOCKPAIRNM)
#define L_HOSTSUPD	0x00800000
#define lHOSTSUPD()	(LOG_type4 & L_HOSTSUPD)
#define L_CCXCOOKIE	0x01000000
#define lCCXCOOKIE()	(LOG_type4 & L_CCXCOOKIE)
#define L_EXECFILTER	0x02000000
#define lEXECFILTER()	(LOG_type4 & L_EXECFILTER)
#define L_FORWPAUTH	0x04000000
#define lFORWPAUTH()	(LOG_type4 & L_FORWPAUTH)
#define L_THFORKSYNC	0x08000000
#define lTHFORKSYNC()	(LOG_type4 & L_THFORKSYNC)
#define L_TSWATCHER	0x10000000
#define lTSWATCHER()	(LOG_type4 & L_TSWATCHER)
#define L_HTTPACCEPT	0x20000000
#define lHTTPACCEPT()	(LOG_type4 & L_HTTPACCEPT)
#define L_DOSRCREJECT	0x40000000
#define lDOSRCREJECT()	(LOG_type4 & L_DOSRCREJECT)
#define L_UNSIGNEDCRC8	0x80000000
#define lUNSIGNEDCRC8()	(LOG_type4 & L_UNSIGNEDCRC8)

#define lTRACE()	(LOG_type & L_TRACE)
#define lNOEXEC()	(LOG_type & L_NOEXEC)
#define lTRVERB()	(LOG_type & L_TRVERB)
#define lTRTERSE()	(LOG_type & L_TRTERSE)
#define lSIGCHLD()	(LOG_type & L_SIGCHLD)
#define lISFUNC()	(LOG_type & L_ISFUNC)

#define L_THREADID		0x80000000
#define L_SISALIVE		0x40000000
#define L_THREADCFI		0x20000000
#define L_SCOUNTER		0x10000000
#define L_RETERR		0x08000000
#define L_IMMEXIT		0x04000000
#define L_ADDRMATCH		0x02000000
#define L_SFTP_FILTER		0x01000000

#define lTHREADID()		(LOG_bugs & L_THREADID)
#define lSISALIVE()		(LOG_bugs & L_SISALIVE)
#define lTHREADCFI()		(LOG_bugs & L_THREADCFI)
#define EscEnabled()		(LOG_bugs & L_SCOUNTER)
#define lRETERR()		(LOG_bugs & L_RETERR)
#define lIMMEXIT()		(LOG_bugs & L_IMMEXIT)
#define lADDRMATCH()		(LOG_bugs & L_ADDRMATCH)
#define lSFTP_FILTER()		(LOG_bugs & L_SFTP_FILTER)

#define ENBUG_NOTHTMOUT	       (0x00000002 & LOG_bugs)
#define L_NULSTDIN		0x00000001 /* redirect stdin to "NUL"   -Esi */
#define ENBUG_NOSTDERR		0x00000004 /* run wihtout stderr on Win -Bse */
#define ENBUG_STLS_BY_PROTO	0x00000008 /* STLS=fsv:ftp,ftp-data     -Bsp */
#define ENBUG_NULLFP_DUPCLOSED	0x00000010
#define ENBUG_NULLFP_FCLOSE	0x00000020
#define ENBUG_WIN_NTFS_TIME	0x00000040
#define ENBUG_TID64		0x00000080
#define ENBUG_GZIP_STREAM	0x00000100
#define ENBUG_POST_BUFF		0x00000200
#define L_MTSS_TMCONV		0x00000400 /* multi-thread/signal-safe  -Etm */
#define L_MTSS_PUTENV		0x00000800 /* disable direct environ[]  -Ete */
#define L_MTSS_NOSSIG		0x00001000 /* disalbe SSigMask for test -Dts */
#define L_THREADLOG		0x00002000
#define L_FTPDATA_NOBIND	0x00004000 /* don't retry binding src. port */
#define L_PASV_REUSE		0x00008000 /* reusing PASV socket after error */
#define ENBUG_CONTLENG_304	0x00010000 /* return Content-Length in 304 */
#define L_DNS_SORT		0x00020000 /* enable name-serv. sorting -Ens */
#define L_DONTROUTE_LOCAL	0x00040000 /* set DONTROUTE loacl segm. -Edr */
#define L_NOIDENT		0x00080000 /* don't try Ident */
#define L_NOPAM_DYLIB		0x00100000 /* don't try libpam.so/dylib/dll */
#define L_NOAUTOMAXIMA		0x00200000 /* disable auto. MAXIMA=delegated */
#define L_HTTPSCLONLY		0x00400000 /* reject non-HTTPS/SSL on CONNECT */
#define L_NOTHWAITBUG		0x00800000 /* fix the thread_wait bug/Win32 */
#define L_BLOCKNONSSL		0x01000000 /* try blocking non-SSL over SSLtunnel */
#define L_PEEKSSL		0x02000000 /* peek SSL record over SSLtunnel */

#define nulSTDIN()		(LOG_bugs & L_NULSTDIN)
#define enbugNOSTDERR()		(LOG_bugs & ENBUG_NOSTDERR)
#define enbugSTLS_BY_PROTO()	(LOG_bugs & ENBUG_STLS_BY_PROTO)
#define enbugNULLFP_DUPCLOSED()	(LOG_bugs & ENBUG_NULLFP_DUPCLOSED)
#define enbugNULLFP_FCLOSE()	(LOG_bugs & ENBUG_NULLFP_FCLOSE)
#define enbugWIN_NTFS_TIME()	(LOG_bugs & ENBUG_WIN_NTFS_TIME)
#define enbugTID64()		(LOG_bugs & ENBUG_TID64)
#define enbugGZIP_STREAM()	(LOG_bugs & ENBUG_GZIP_STREAM)
#define enbugPOST_BUFF()	(LOG_bugs & ENBUG_POST_BUFF)
#define lMTSS_TMCONV()		(LOG_bugs & L_MTSS_TMCONV)
#define lMTSS_PUTENV()		(LOG_bugs & L_MTSS_PUTENV)
#define lMTSS_NOSSIG()		(LOG_bugs & L_MTSS_NOSSIG)
#define lTHREADLOG()		(LOG_bugs & L_THREADLOG)
#define lFTPDATA_NOBIND()	(LOG_bugs & L_FTPDATA_NOBIND)
#define lPASV_REUSE()		(LOG_bugs & L_PASV_REUSE)
#define enbugCONTLENG304()	(LOG_bugs & ENBUG_CONTLENG_304)
#define lDNS_SORT()		(LOG_bugs & L_DNS_SORT)
#define lDONTROUTE_LOCAL()	(LOG_bugs & L_DONTROUTE_LOCAL)
#define lNOIDENT()		(LOG_bugs & L_NOIDENT)
#define lNOPAM_DYLIB()		(LOG_bugs & L_NOPAM_DYLIB)
#define lNOAUTOMAXIMA()		(LOG_bugs & L_NOAUTOMAXIMA)
#define lHTTPSCLONLY()		(LOG_bugs & L_HTTPSCLONLY)
#define lNOTHWAITBUG()		(LOG_bugs & L_NOTHWAITBUG)
#define lBLOCKNONSSL()		(LOG_bugs & L_BLOCKNONSSL)
#define lPEEKSSL()		(LOG_bugs & L_PEEKSSL)


#define LW_CREATE	1
#define LW_EXMATCH	2

typedef struct _Logfile {
  const	char	*l_proto;
  const	char	*l_filters;	/* depend on l_proto */
  const	char	*l_pform;	/* template of path */
	defQStr(l_path);
  const	char	*l_lform;	/* format of log data */
  const	char	*l_mode;	/* mode of fopen */
	FILE	*l_fp;
	int	 l_dolock;	/* do lock */
	int	 l_lockfd;	/* extra lock file */
  const	char	*l_lkpath;
	int	 l_until;
	defQStr(l_buff);
	int	 l_size;
	int	 l_leng;
	int	 l_abandon;
	int	 l_notty;
	int	 l_dontfree;
	int	 l_ex;
} Logfile;

Logfile *LOG_which(PCStr(proto),PCStr(filter1),int options);
void LOG_write(Logfile *LogF,PCStr(str),int leng);
void LOG_flushall();

extern const char LS_VERBOSE[]; /* V */
extern const char LS_DEBUG[]; /* D */
extern const char LS_USUAL[]; /* U (or normal, nutoral) */
extern const char LS_TERSE[]; /* T (or trace) */
extern const char LS_ERROR[]; /* E */
extern const char LS_FATAL[]; /* F */
extern const char LS_ACCESS[]; /* A */

extern char LP_NOTTY[]; /* don't merge to tty even with -v option */
extern char LF_PROTOLOG[];
extern char LF_ERRORLOG[];
extern char LF_STDOUTLOG[];
extern char LF_TRACELOG[];
extern char LF_LOGFILE[];
extern const char *(*LOG_stdlogfile)();
/*
extern int   (*LOG_substfile)(void*,...);
*/

#define	Verbose	(LOG_VERBOSE==0 && lVERBABORT()==0) ? 0 : sv1vlog
#define LSEC (LOG_type2 & L_SECRET) == 0 ? 0 : syslog_ERROR

#define ServerMain (!lISCHILD() && !lISFUNC())
#define InitLog	(lISCHILD()||lISFUNC()) ? 0:syslog_ERROR

#define HLdebug (LOG_type&L_HOSTMATCH)==0?0:putLog0

#define CCXlog lCHARSET()==0?0:syslog_ERROR

#define P_LV (LOGLEVEL<3) ? 0:porting_dbg
#define CURDBG	!lCURRENT()?0:fprintf

void iLOGinit();
#define iLOGstop()	(LOG_type2 |= L_NOINITLOG)
int iLOGpos(PCStr(F),int L);

#define iLog \
    (((lNOINITLOG() && LOGLEVEL < 2)?0:iLOGpos(__FILE__,__LINE__)),\
      (lNOINITLOG() && LOGLEVEL < 2))?0:iLOGput

#define TOTAL_SERVED	(lSINGLEP()?logControl[LC_PST].lc_total_served\
				 :mylogControl[LC_PST].pl_total_served)
#define pTOTAL_SERVED	(lSINGLEP()?&logControl[LC_PST].lc_total_served\
				 :&mylogControl[LC_PST].pl_total_served)

#define putsLog(str) putfLog("%s",str)
int scounter(int tid,const void *key,int len,int inc);
extern const char *PRTHstage;


#if defined(FMT_CHECK) /*{ 9.9.7 */
#define iLOGdump(sig,fmt,...)   fprintf(stderr,fmt,##__VA_ARGS__)
#define iLOGput(fmt,...)        fprintf(stderr,fmt,##__VA_ARGS__)
#define putLog0(fmt,...)        fprintf(stderr,fmt,##__VA_ARGS__)
#define putfLog(fmt,...)        fprintf(stderr,fmt,##__VA_ARGS__)
#define gotsigTERM(fmt,...)     fprintf(stderr,fmt,##__VA_ARGS__)

#else /*}{*/
#define FMT_iLOGdump   iLOGdump
#define FMT_iLOGput    iLOGput
#define FMT_putLog0    putLog0
#define FMT_putfLog    putfLog
#define FMT_gotsigTERM gotsigTERM

void FMT_iLOGdump(int sig,PCStr(fmt),...);
int  FMT_iLOGput(PCStr(fmt),...);
int  FMT_putLog0(PCStr(fmt),...);
void FMT_putfLog(PCStr(fmt),...);
int  FMT_gotsigTERM(PCStr(fmt),...);
#endif /*}*/

int addCR(FILE *fp,int fd,PCStr(str));

#endif /* _LOG_H */
