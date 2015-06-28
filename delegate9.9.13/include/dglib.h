#ifndef _DGLIB_H
#define _DGLIB_H

#include "dgctx.h"

void *optctx(DGC*ctx);

#include "ystring.h"
#include "vaddr.h"

extern int main_argc;
extern const char **main_argv;
const char *getEnvBin(PCStr(name));
const char *getEnvBin1st(PCStr(name));
int dosetUidOnExec(PCStr(what),PCStr(owner),int *uid,int *gid);
int getUserId(PCStr(user));
int getGroupId(PCStr(group));

int setDGLEV(DGCTX,int lev);
int getDGLEV(DGCTX,PCStr(what));

/*
int AuthFunc(DGCTX,void*f,PCStr(F),int L);
#define iAuthFunc(f)	if(AuthFunc(Conn,f,__FILE__,__LINE__)<0)return -1
#define vAuthFunc(f)	if(AuthFunc(Conn,f,__FILE__,__LINE__)<0)return
#define vAuthProto(f)	if(AuthProto(Conn,f,__FILE__,__LINE__)<0)return -1
*/

#define PORTSSIZE 512

#define ST_ACC  0
#define ST_DONE 1
int   serverPid();
int   put_svstat();
void  putLoadStat(int what,int done);

void putSRCsign(FILE *out);
void putBLDsign(FILE *out);

/* CONTEXT */
DGCTX MainConn();
void  ConnInit(DGCTX);
void  clear_DGconn(DGCTX);
void  clear_DGreq(DGCTX);
void  ConnCopy(DGCTX,DGC*);
void  initConnected(DGCTX,int svsock,int relay_input);
char *strfConnX(DGCTX,PCStr(fmt),PVStr(str),int siz);
void  make_conninfo(DGCTX,PVStr(conninfo));
void  setConnX(DGCTX,int fromC,int toC,int fromS,int toS);
void  setProxyOfClient(DGCTX,int proxy_client,PCStr(url));
void  setREQUEST(DGCTX,PCStr(req));
void  set_ClientSock(DGCTX,int sock,PCStr(remote),PCStr(local));
void  restoreConn(DGCTX,DGC*);
int   withAdminPort(const char **host,int *port);
int   getUserPort1(const char **host,int *port);
int   getSoftBreakX(PCStr(F),int L,DGCTX,PCStr(serv));
#define getSoftBreak(ctx,serv) getSoftBreakX(__FILE__,__LINE__,ctx,serv)
const char *scan_arg1(DGCTX,PCStr(ext_base),PCStr(arg));
int   DELEGATE_scan_argsX(DGCTX,int ac,const char *av[]);
#define DELEGATE_scan_args(ac,av) DELEGATE_scan_argsX(Conn,ac,av)

/* CLIENT INFO */
void  VA_setClientAddr(DGCTX,PCStr(addr),int port,int remote);
const char *VA_getOriginatorIdent(DGCTX,AuthInfo *ident);
int   VA_getClientAddr(DGCTX);
int   VA_HostPortIFclnt(DGCTX,int clsock,PVStr(name),PVStr(addr),VAddr *Vaddr);
int   ClientIF_HP(DGCTX,PVStr(hostport));
int   ClientIF_HPname(DGCTX,PVStr(hostport));
int   ClientIF_H(DGCTX,PVStr(host));
int   ClientIF_addr(DGCTX,int clsock,PVStr(addr));
int   ClientIF_name(DGCTX,int clsock,PVStr(name));
int   getClientHostPort(DGCTX,PVStr(rhost));
int   getClientHostPortAddr(DGCTX,PVStr(rhost),PVStr(raddr));
const char *getClientHostPortUser(DGCTX,PVStr(host),int *portp);
char *getClientUserMbox(DGCTX,PVStr(mbox));
const char *getClientUserC(DGCTX);
int   getClientAuthList(DGCTX,int ax,AuthInfo *av[]);
void  setClientCert(DGCTX,PCStr(what),PCStr(mbox));
void  enableClientIdent(PCStr(host));
void  scan_RIDENT(DGCTX,PCStr(specs));

/* SERVER INFO */
int   scan_SERVER(DGCTX,PCStr(server));
void  set_SERVER(DGCTX,PCStr(proto),PCStr(host),int port);
void  set_realproto(DGCTX,PCStr(rproto));
void  set_realsite(DGCTX,PCStr(rproto),PCStr(rserver),int riport);
void  set_realserver(DGCTX,PCStr(rproto),PCStr(rserver),int riport);
int   CTX_get_iserver(DGCTX,const char **proto,const char **host);
int   setupConnect(DGCTX);
int   toTunnel(DGCTX);
int   connect_to_serv(DGCTX,int fromC,int toC,int relay_input);
int   connect_to_serv(DGCTX,int fromC,int toC,int relay_input);
int   ConnectToServer(DGCTX,int relay_input);
void  setServerCert(DGCTX,PCStr(what),PCStr(mbox));
int   openMaster(DGCTX,int svsock,PCStr(server),int relay_input);
void  setConnDone(DGCTX);
void  setConnStart(DGCTX);

/* URL REWRITING */
int   isURN(PCStr(urn));
int   url_deproxy(DGCTX,PVStr(req),PVStr(url),PVStr(proto),PVStr(host),int *portp);
int   localPathProto(PCStr(proto));
int   isFullURL(PCStr(url));
int   isExecutableURL(PCStr(url));
int   isLoadableURL(PCStr(url));
int   is_redirected_url(PCStr(url));

char *HostPort(PVStr(hostport),PCStr(proto),PCStr(host),int port);
int   decomp_absurl(PCStr(url),PVStr(proto),PVStr(site),PVStr(upath),int usz);
int   decomp_siteX(PCStr(proto),PCStr(site),AuthInfo *ident);
void  decomp_URL_site(PCStr(site),PVStr(userpasshost),PVStr(port));
void  decomp_URL_siteX(PCStr(site),PVStr(userpass),PVStr(user),PVStr(pass),PVStr(hostport),PVStr(host),PVStr(port));
int   scan_hostport(PCStr(proto),PCStr(hostport),PVStr(host));
int   scan_hostportX(PCStr(proto),PCStr(hostport),PVStr(host),int siz);
int   scan_hostport1X(PCStr(hostport),PVStr(host),int hsiz);
int   scan_hostport1pX(PCStr(proto),PCStr(login),PVStr(host),int hsiz);
int   scan_protositeport(PCStr(url),PVStr(proto),PVStr(u_p_h),PVStr(port));
const char *scan_userpassX(PCStr(userpass),AuthInfo *ident);
const char *scan_url_userpass(PCStr(serv),PVStr(user),PVStr(pass),PCStr(dfltuser));
char *scan_URI_site(PCStr(url),PVStr(site),int size);
char *scan_URI_scheme(PCStr(url),PVStr(scheme),int size);
char *file_hostpath(PCStr(url),PVStr(proto),PVStr(login));
int   url_upathbaselen(PCStr(base),int blen);
int   get_gtype(PCStr(gsel),PVStr(sel));
void  url_absolute(PCStr(myhp),PCStr(proto),PCStr(host),int port,PCStr(base),PCStr(line),PVStr(xline),PVStr(rem));

void  url_rmprefix(PVStr(proto),PVStr(prefix));
void  site_strippass(PVStr(site));
int   strip_urlhead(PVStr(url),PVStr(proto),PVStr(login));
void  url_strippass(PVStr(url));
void  url_delport(PVStr(url),int *portp);

int   unescape_user_at_host(PVStr(email));
void  nonxalpha_escapeX(PCStr(src),PVStr(dst),int siz);
void  unescape_specials(PCStr(str),PCStr(set),PCStr(succ));
int   url_unescape(PVStr(url),PVStr(dst),int siz,PCStr(set));

char *filename2icon(PCStr(path),const char **ialt);
const char *filename2ctype(PCStr(path));
int   fileMaybeText(PCStr(path));
int   fileSeemsBinary(PCStr(path));
int   filename2gtype(PCStr(name));
void  CTX_set_clientgtype(DGCTX,int gtype);

/* MOUNT */
void  init_mtab();
void  scan_url(PCStr(line),iFUNCP func,void *arg1,void *arg2);
void  scan_MOUNT(DGCTX,PCStr(spec));
void  set_MOUNT(DGCTX,PCStr(src),PCStr(dst),PCStr(opts));
int   set_MOUNT_ifndef(DGCTX,PCStr(src),PCStr(dst),PCStr(opts));
void  set_BASEURL(DGCTX,PCStr(url));
void  scan_DELEGATE(DGCTX,PCStr(dhps));
const char *html_nextTagAttrX(void *Base,PCStr(html),PCStr(ctype),PVStr(rem),const char **tagp,const char **attrp,int *convmaskp);
const char *CTX_mount_url_to(DGCTX,PCStr(myhostport),PCStr(method),PVStr(url));
const char *CTX_onerror_url_to(DGCTX,PCStr(myhp),PCStr(method),PVStr(url));
const char *CTX_mount_url_fromL(DGCTX,PVStr(url),PCStr(proto),PCStr(hostport),PCStr(path),PCStr(search),PCStr(dproto),PCStr(delegate));
int   CTX_url_derefer(DGCTX,PCStr(cproto),PVStr(url),PVStr(modifiers),PVStr(flags),PVStr(proto),PVStr(host),int *iportp);
#include "url.h" /* for Referer */
void  CTX_scan_mtabX(DGC*ctx,PCStr(vhost),iFUNCP func,void *arg);
void  CTX_scan_mtab(DGCTX,iFUNCP func,void *arg);
int   CTX_url_rurlX(DGCTX,int qch,PCStr(url),PVStr(rurl),PCStr(dproto),PCStr(dhost),int dport,PCStr(dpath),int dgrelay);
void  CTX_url_delegateS(DGCTX,Referer *referer,PCStr(ln),PVStr(xln),int dgrelay);
int   Mounted();
int   MountedConditional();
int   getOpt1(PCStr(opts),PCStr(name),PVStr(value));
int   getMountOpt1(DGCTX,PCStr(onam),PVStr(oval),int size);
void  eval_mountOptions(DGCTX,PCStr(opts));
void  reset_MOUNTconds();
int   matchPath1(int hlid,PCStr(user),PCStr(host),int port);
const char *MountVbase(PCStr(opts));
const char *MountRpath(PCStr(opts));
int   makePathList(PCStr(what),PCStr(path));
void  redirect_url(DGCTX,PCStr(url),PVStr(durl));

/* stream I/O with TIMEOUT */
char *fgetsByBlockX(int exsock,PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp);
char *fgetsByBlock(PVStr(line),int size,FILE *fs,int niced,int ltimeout,int byline,int fromcache,int remlen,int *lengp,int *isbinp);
char *fgetsByLine(PVStr(line),int sz,FILE *in,int timeout,int *rccp,int *isbinp);
int   fgetsBuffered(PVStr(b),int n,FILE *fp);
int   fgetBuffered(PVStr(b),int n,FILE *fp);
void  discardBuffered(FILE *fp);
int   fwriteTIMEOUT(PCStr(b),int s,int n,FILE *fp);
int   fputsTIMEOUT(PCStr(b),FILE *fp);
char *fgetsTIMEOUT(PVStr(b),int s,FILE *fp);
char *fgetsTimeout(PVStr(b),int s,FILE *fp,int tout);
int   fcloseTIMEOUT(FILE *fp);
int   readTIMEOUT(int fd,PVStr(b),int s);
int   recvPeekTIMEOUT(int fd,PVStr(b),int s);
int   copy_fileTIMEOUT(FILE *sfp,FILE *dfp,FILE *cfp);
int   copy_file(FILE *sfp,FILE *dfp,FILE *cfp);
int   fflushTIMEOUT(FILE *fp);
int   freadTIMEOUT(PVStr(b),int s,int n,FILE *fp);
int   RecvLine(int sock,void *buf,int len);
int   simple_relayTimeout(int src,int dst,int timeout);
int   readTimeoutBlocked(int fd,PVStr(buf),int len,int timeout);

/* message I/O for FTP MODE XDC */
typedef const char *(*siFUNCP)(int ser,PCStr(buff),int leng,FILE *tcfp,PCStr(arg));
FileSize getMessageFX(FILE *srcf,FILE *cachefp,int timeout,siFUNCP func,FILE *dstf,PCStr(arg),PCStr(encode));
FileSize putMessageFX(FILE *srcf,FILE *dstf,FILE *cachefp,PCStr(encode));
FileSize cpyMessageFX(FILE *src,FILE *dst,FILE *cachefp,PCStr(encode));
typedef int (*msgCBFunc)(void *arg,PVStr(buff),int leng);
FileSize putMessageFX_CB(FILE *srcf,FILE *dstf,FILE *cachefp,PCStr(encode),msgCBFunc cb,void *cbarg);
void putPostStatus(FILE *dstf,PCStr(status));

/* CACHE */
const char *cachedir();
void  set_DG_EXPIRE(DGCTX,int expi);
int   http_EXPIRE(DGCTX,PCStr(url));
int   HTTP_getLastModInCache(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath));
int   CTX_cache_path(DGCTX,PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath));
int   renameRX(PCStr(old),PCStr(xnew));
int   Readlink(PCStr(dir),PVStr(xdir),int xsiz);
int   linkRX(PCStr(to),PCStr(from));
int   mkdirRX(PCStr(dir));
FILE *cache_make(PCStr(what),PCStr(cpath),PVStr(xcpath));
int   cache_path(PCStr(proto),PCStr(server),int iport,PCStr(path1),PVStr(cachepath));
void  cache_delete(PCStr(cpath));
int   cache_expire(PCStr(sexp),int dflt);
void  cache_done(int gotok,FILE *cachefp,PCStr(cpath),PCStr(xcpath));
int   without_cache();
FILE *dirfopen(PCStr(what),PVStr(file),PCStr(mode));
FILE *expfopen(PCStr(what),int expire,PVStr(file),PCStr(mode),int *datep);
void  stripPATHexp(PCStr(path),PVStr(spath));
int   without_cacheX(DGCTX);
#define without_cache() without_cacheX(Conn)

/* LOCK */
FILE *cache_fopen_rd(PCStr(what),PVStr(cpath),int expire,int *datep);
FILE *cache_fopen_rw(PCStr(what),PVStr(cpath));
int   file_lock_wr(PCStr(what),FILE *fp);
int   lock_for_rd(PCStr(what),int nretry,PCStr(cpath),FILE *fp);
int   local_lockTO(int ex,PCStr(path),FILE *fp,int timeout,int *elapsedp,int *lkfdp);
int   getLocalLock(FILE *fp,PCStr(dir),PCStr(file),PVStr(lkpath));
int   PortLocks(PCStr(port),int group,PVStr(path));

/* DAEMON entrance port as a SERVER */
int   ServSockOf(PCStr(host),int port);
int   FL_ServSockX(DGCTX,FL_PAR);
#define ServSockX() FL_ServSockX(Conn,FL_ARG)
int   SERVER_PORT();
const char *MY_HOSTPORT();
void  printPrimaryPort(PVStr(port));
void  closeServPorts();
int   printServPort(PVStr(port),PCStr(prefix),int whole);
int   checkCloseOnTimeout(int checktime);
void  scan_VSAP(DGCTX,PCStr(vsaps));
int   VSAP_isMethod(PCStr(request));
int   CTX_VSAPconnect(DGCTX,PVStr(sockname),PVStr(peername));
int   ViaVSAPassociator(int sock);
int   VSAPaccept(DGCTX,int timeout,int rsock,int priority,PVStr(sockname),PVStr(peername));
int   getReservedPorts(int pv[],int sv[]);
int   ReservedPortSock(PCStr(host),int port);
int   closeNonReservedPortSock(int sock);
int   ACCEPT1(int sock,int isServer,int lockfd,int timeout,PVStr(sockname));

/* DAEMON */
void  returnAckCANTCON(DGCTX,FILE *tc,PCStr(host));
void  returnAckDENIED(DGCTX,FILE *tc,PCStr(reason));
void  returnAckOK(DGCTX,FILE *tc,PCStr(reason));
void  beBoundProxy(DGCTX,PCStr(user),int timeout,iFUNCP func,...);
int   connectToCache(DGCTX,PCStr(user),int *svsockp);
int   isHelloRequest(PCStr(req));
void  beGeneralist(DGCTX,FILE *fc,FILE *tc,PCStr(hello));
int   execSpecialist(DGCTX,int fromC,FILE *tc,int toS);
int   execGeneralist(DGCTX,int fromC,int toC,int svsock);
int   execFunc(DGCTX,int clsock,int svsock,iFUNCP func,PCStr(arg));

/* DAEMON status indicator */
int   SERNO();
int   MySeqNum();
int   incServReqSerno(DGCTX);
int   incRequestSerno(DGCTX);
void  SetStartTime();
double GetStartTime();
char *strfLoadStat(PVStr(str),int size,PCStr(fmt),int now);
int   alive_peers();
void  dumpstacksize(PCStr(what),PCStr(fmt),...);
void  stopStickyServer(PCStr(why));

int   fromInetd();
int   timeoutWait(int to);
int   spawnv_self1(int aac,const char *aav[]);
int   DELEGATE_session_sched_execute(int now,iFUNCP callback,void *Conn);

const char *DeleGateId();
const char *DELEGATE_ver();
const char *DELEGATE_Ver();
const char *DELEGATE_version();
const char *DELEGATE_Version();
const char *DELEGATE_verdate();
const char *DELEGATE_copyright();
const char *DELEGATE_homepage();
const char *DELEGATE_Distribution();
void  DELEGATE_sigFATAL(int sig);
int   DELEGATE_sched_execute(int now,iFUNCP callback,void *Conn);

/* COMMAND LINE PARAMETER AND STARTUP SCRIPT */
void  DELEGATE_pushEnv(PCStr(name),PCStr(value));
void  DELEGATE_setenv(FILE *fc,FILE *tc,PCStr(line));
int   DELEGATE_dumpEnv(FILE *fp,int genalso,int imPM);
void  DELEGATE_addEnvExt(PCStr(env));
int   SpawnvpDirenv(PCStr(what),PCStr(execpath),const char *const* av);
int   ExecvpDirenv(PCStr(what),PCStr(execpath),const char *const* av);
int   CTX_load_script(DGCTX,PCStr(name),PCStr(base),PCStr(purl));
#define load_script(n,b,p)    CTX_load_script(Conn,n,b,p)
int   CTX_load_encrypted(DGCTX,PCStr(name),PCStr(base),PCStr(estr));
#define load_encrypted(n,b,e) CTX_load_encrypted(Conn,n,b,e) 
int   script_asis(PCStr(param));
int   copy_param(PCStr(param),int mac,const char **dav,const char *const* sav);
int   check_param(PCStr(param),int warn);
void  xmem_pushX(DGCTX,void *addr,int size,PCStr(what),iFUNCP func);
#define xmem_push(a,z,w,f) xmem_pushX(Conn,a,z,w,f)
int   mem_push(int lev,PCStr(addr),int size,PCStr(what),iFUNCP func);
void  mem_pops(int lev);

/* CONFIG */
int   serviceport(PCStr(service));
void  prservices(FILE *fp);
int   vercmp(PCStr(ver1),PCStr(ver2));
int   CTX_findInPath(DGCTX,PCStr(host),int port);
const char *getADMIN();
const char *getADMIN1();
void  checkADMIN(DGCTX,PCStr(proto));
const char *get_builtin_data(PCStr(name),int *sizep,int *datep);
int   substEXECDIR(PCStr(fpath),PVStr(opath),int osize);
int   toSafeFileName(PCStr(name),PVStr(xname));
const char *ADMDIR();

int   DELEGATE_substPath(PCStr(what),int del,PCStr(path),PVStr(xpath));
typedef void substFile(PVStr(f),PCStr(p),PVStr(var),PVStr(log),PVStr(act));
void  DELEGATE_substfile(PVStr(file),PCStr(proto),PVStr(rvardir),PVStr(rlogdir),PVStr(ractdir));
extern substFile *LOG_substfile;
#define Substfile(f)  (*LOG_substfile)(AVStr(f),"",VStrNULL,VStrNULL,VStrNULL);

void  strsubstDirEnv(PVStr(dir),PCStr(dgroot),PCStr(vardir));
int   fullpathCOM(PCStr(path),PCStr(mode),PVStr(xpath));
int   fullpathDYLIB(PCStr(path),PCStr(mode),PVStr(xpath));
int   fullpathLIB(PCStr(path),PCStr(mode),PVStr(xpath));
int   fullpathSUCOM(PCStr(path),PCStr(mode),PVStr(xpath));
int   fullpathDATA(PCStr(path),PCStr(mode),PVStr(xpath));
int   toFullpathENV(PCStr(envname),PCStr(file),PCStr(mode),PVStr(execpath),int size);
int   newPath(PVStr(path));
int   IsMacOSX();
int   INHERENT_spawn();
int   INHERENT_alloca();
int   INHERENT_ptrace();
int   _INHERENT_fork();
int   INHERENT_fork();
int   INHERENT_fchown();
int   INHERENT_lstat();
const char *INHERENT_thread();

/* RESOLVY */
void  addr2dom(PCStr(addr),PVStr(inaddr),int isize);
int   isinetAddr(PCStr(saddr));

/* SOCKET */
int   Socketpair_FL(FL_PAR,int sv[]);
#define Socketpair(sv) Socketpair_FL(FL_ARG,sv)
int   INET_Socketpair(int sv[]);
int   UDP_Socketpair_FL(FL_PAR,int sv[]);
#define UDP_Socketpair(sv) UDP_Socketpair_FL(FL_ARG,sv)
int   Socket1(PCStr(what), int sock,PCStr(domain),PCStr(type),PCStr(proto), PVStr(lhost),int lport, PCStr(rhost),int rport, int nlisten,PCStr(opts),int NB);
int   CTX_setSockBuf(FL_PAR,DGCTX,int sock,int clnt);
int   withORIGINAL_DST();

int   sock_isconnected(int sock);
int   sock_isconnectedX(int sock,int sinonly);
int   sock_isAFUNIX(int sock);
int   IsConnected(int sock,const char **reason);
void  std_setsockopt(int sock);
void  fcloseLinger(FILE *fp);
int   expsockbuf(int sock,int in,int out);
int   setsockbuf(int sock,int in,int out);
int   getsockbuf(int sock,int *in,int *out);
int   Setsockopt(int s,int level,int optname,PCStr(optval),int optlen);
int   fshutdown(FILE *fp,int force);
void  setsockREUSE(int sock,int onoff);
int   set_keepalive(int sock,int on);
void  set_linger(int sock,int secs);
int   setNonblockingIO(int fd,int on);
void  SetNonblockingIO(PCStr(what),int sock,int on);

void  set_nodelay(int sock,int onoff);
int   recvOOB(int sock,PVStr(buff),int size);
int   recvOOBx(int sock,PVStr(buff),int size);
int   sendOOB(int sock,PCStr(buff),int size);
int   relayOOB(int in,int out);
int   Peek1(int sock);

int   server_open(PCStr(portname),PVStr(hostname),int portnum,int nlisten);
int   server_open_un(PCStr(what),PVStr(path),int nlisten);
int   findopen_port(PCStr(what),PVStr(host),int port,int nlisten);
int   ACCEPT(int sock,int isServer,int lockfd,int timeout);
int   Listen(int sock,int backlog);
int   UDPaccept(int svsock,int lockfd,int timeout);

/* SOCKET OUTGOING connection */
int   OpenServerX(DGCTX,PCStr(what),PCStr(proto),PCStr(host),int port);
#define OpenServer(what,proto,host,port) OpenServerX(Conn,what,proto,host,port)
int   connectTimeout(int sock,PCStr(host),int port,int timeout);
int   VA_hostIFto(VAddr *destp,VAddr *maskp,VAddr *Vaddr);
int   hostIFfor(PCStr(rhost),PVStr(hostIF));
int   hostIFfor1(PVStr(hostIF),int udp,PCStr(proto),PCStr(rhost),int rport);
int   SRCIFfor(DGCTX,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport);
int   client_open(PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int   client_open_un(PCStr(what),PCStr(path),int timeout);
int   connectServer(PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int __connectServer(int sock,PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int   client_open_localhost(PCStr(what),PCStr(path),int timeout);
int   UDP_client_open(PCStr(what),PCStr(portname),PCStr(hostname),int iport);
int   UDP_client_open1(PCStr(what),PCStr(portname),PCStr(hostname),int iport,PCStr(lhost),int lport);

/* SOCKET IDENTITY of the PEER beyond a socket */
int   sockPort(int sock);
int   gethostName(int sock,PVStr(sockname),PCStr(form));
int   gethostNAME(int sock,PVStr(name));
int   getpeerName(int sock,PVStr(sockname),PCStr(form));
int   getpeerNAME(int sock,PVStr(name));
void  getpairName(int clsock,PVStr(sockname),PVStr(peername));
int   VA_getpeerNAME(int sock,VAddr *Vaddr);
int   peerPort(int sock);
int   sockHostport(int sock,int *portp);
int   peerHostport(int sock,int *portp);
int   VA_getodstNAME(int sock,VAddr *Vaddr);
int   VA_gethostNAME(int sock,VAddr *Vaddr);
int   gethostAddr(int sock,PVStr(saddr));
int   getpeerAddr(int sock,PVStr(saddr));
int   sockFromMyself(int sock);
int   localsocket(int sock);
void  dumpFds(FILE *outf);
void  dumpFdsX(PCStr(what),FILE *outf,PCStr(types));

/* RESOLVER */
int   VA_strtoVAddr(PCStr(saddr),VAddr *Vaddr);
int   VA_gethostVAddr(int cacheonly,PCStr(host),PVStr(primname),VAddr *Vaddr);
int   sethostcache(PCStr(host),int mark_predef);
void  sethostcache_predef(PCStr(name),PCStr(addr),int len,int type);
const char *VSA_hostlocal();
const char *VSA_hostlocaladdr();
int   VSA_strisaddr(PCStr(addr));
int   VSA_atosa(VSAddr *sa,int port,PCStr(addr));
const char *VA_inAddr(VAddr *Ia);
void  VA_setVAddr(VAddr *Vaddr,PCStr(addr),int port,int remote);
const char *gethostbyAddr(PCStr(addr),PVStr(host));
int   IsInetaddr(PCStr(addr));
void  GetHostname(PVStr(name),int size);
int   gethostFQDN(PVStr(fqdn),int size);
int   getFQDN(PCStr(name),PVStr(fqdn));
int   VA_gethostint_nbo(PCStr(host),VAddr *Vaddr);
/*
void  VA_inetNtoah(VAddr *Vaddr,PVStr(saddr));
*/
const char *VA_inetNtoah(VAddr *Vaddr,PVStr(saddr));
int   gethostintMin(PCStr(host));
int   gethostint_nboV4(PCStr(host));
const char *gethostaddr(PCStr(host));
const char *gethostaddrX(PCStr(host));
int   IsResolvable(PCStr(host));
int   hostIsResolvable(PCStr(host));
int   hostcmp(PCStr(host1),PCStr(host2));
int   hostcmp_incache(PCStr(host1),PCStr(host2));
int   hostisin(PCStr(host1),PCStr(host2),int nocache);
void  scan_HOSTS(DGCTX,PCStr(hosts));
int   make_HOSTS(PVStr(hosts),PCStr(hostname),int cacheonly);
int   dump_HOSTS(PVStr(hosts));
void  gethostnameIF(PVStr(host),int size);
int   isMYSELF(PCStr(host));
int   IsMyself(PCStr(host));
int   Ismyself(DGCTX,PCStr(rproto),PCStr(rhost),int rport);
int   hostismyself(PCStr(host),FILE *sockfp);

/* LOGGING */
int   log_PATH(DGCTX,PCStr(where));
void  makeClientLog(DGCTX,PVStr(clientlog));
void  clrAbortLog();
void  LOG_openall();
void  LOG_flushall();
void  LOG_closeall();
void  LOG_deletePortFile();

void  fdopenLogFile(int fd);
int   curLogFd();
FILE *curLogFp();
/*
void  Finish(int code);
*/
void _Finish(int code);
FILE *LOG_openLogFile(PCStr(form),PCStr(mode));
int   StrSubstDate(PVStr(str));
void  AbortLog();
int   countUp(PCStr(file),int istmp,int op,int pid,long *lmtime,PVStr(path));
void  putpplog(PCStr(fmt),...);

/* HOSTLIST */
int   scan_CMAPi(PCStr(map),int mx0,const char **strp);
void  scan_CMAP(DGCTX,PCStr(map));
void  scan_CMAP2(DGCTX,PCStr(name),PCStr(map));
int   find_CMAPi(DGCTX,PCStr(map),int i,PVStr(str));
int   find_CMAP(DGCTX,PCStr(map),PVStr(str));
int   find_CMAPX(DGCTX,PCStr(map),PVStr(str),PCStr(proto),PCStr(dhost),int dport,PCStr(shost),int sport,PCStr(suser));
void  scan_PERMIT(DGCTX,PCStr(protolist));
void  CTX_pushClientInfo(DGCTX);
void  HL_popClientInfo();
void  HL_setClientIF(PCStr(addr),int port,int remote);
void  HL_setClientAgent(PCStr(agent));
int   isREACHABLE(PCStr(proto),PCStr(hostport));

/* CRYPTO */
int   getCKey(PVStr(ekey),int ksiz);
int   decrypt_opaque(PCStr(opaque),PVStr(opqs));

/* HOSTNAME/ADDRESS RESOLVER */
int   RES_CACHEONLY(int flag);
void  RES_isself(int mysock);
int   RES_debug(PCStr(debug));

/* HTML GENERATION / CONVERSION */
int   DHTML_printConn(DGCTX,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value));
int   putBuiltinHTML(DGCTX,FILE *tc,PCStr(what),PCStr(purl),PCStr(desc),iFUNCP func,const void *arg);
int   getBuiltinData(DGCTX,PCStr(what),PCStr(aurl),PVStr(buf),int size,PVStr(rurl));
char *getCERNiconBase(DGCTX,PVStr(base));
int   putFrogForDeleGate(DGCTX,FILE *dst,PCStr(fmt),...);
int   put_eval_dhtml(DGCTX,PCStr(url),FILE *outfp,PCStr(instr));
const char *HTTP_getIconBase(DGCTX);
const char *getMssg(PCStr(name),int *size);
int   plain2html();

/* CFI FILTER */
int   insertFTOSV(DGCTX,int client,int server,int *pidp);
int   insertFCL(DGCTX,int fromC);
int   filter_withCFI(DGCTX,int which);
void  setFTOCL(PCStr(ftocl));
void  setFTOSV(PCStr(ftosv));
void  scan_FTOSV(DGCTX,PCStr(f));
void  scan_FTOCL(DGCTX,PCStr(f));
void  scan_FSV(DGCTX,PCStr(f));
const char *getFTOSV(DGCTX);
const char *getFTOCL(DGCTX);
int   insertFSVF(DGCTX,int client,int toS,PCStr(filter));
int   insertFSV(DGCTX,int client,int toS);
int   insertFTOCL(DGCTX,int client,int server);
void  close_FSV(DGCTX);
void  insert_FSERVER(DGCTX,int fromC);
void  close_FSERVER(DGCTX,int realclose);
void  wait_FSERVER(DGCTX);
int   putMESSAGEline(FILE *fp,PCStr(type),PCStr(comment));
FILE *openFilter(DGCTX,PCStr(fname),iFUNCP func,FILE *out,PCStr(args));
int   withFilter(DGCTX,PCStr(what),PCStr(proto),PCStr(method),PCStr(user),PVStr(filter));
int   insertFSVX(DGCTX,PCStr(proto),PCStr(method),int cl,int sv);
int   insertFCLX(DGCTX,PCStr(proto),PCStr(method),int cl,int sv);
int   needSTLS(DGCTX);
int   needSTLS_SV(DGCTX);
int   willSTLS_CL(DGCTX);
int   willSTLS_SV(DGCTX);
int   withSTLS_SV(DGCTX);
int   popenx(PCStr(command),PCStr(mode),FILE *io[2]);


/* SECURITY */
void  getPOPcharange(PCStr(banner),PVStr(timestamp));
void  notify_overflow(PCStr(what),PCStr(buf),int off);
void  notify_ADMIN(DGC*xConn,PCStr(what));
void  notify_ADMINX(DGCTX,PCStr(admin),PCStr(what),PCStr(body));
char **move_envarg(int ac,const char *av[],const char **areap,int *lengp,int *sizep);
int   service_permitted0(PCStr(clhost),int clport,PCStr(svproto),PCStr(svhost),int svport);
int   permitted_readonly(DGCTX,PCStr(proto));
int   method_permitted(DGCTX,PCStr(proto),PCStr(method),int igncase);
int   method_permitted0();

/* ACCESS and QoS CONTROL */
int   CTX_preset_loginX(DGCTX,PCStr(method),PVStr(vurl),AuthInfo *ident,PVStr(path));
const char *getMountAuthorizer(DGCTX,PVStr(authserv),int size);
void  addRejectList(DGCTX,PCStr(what),PCStr(dpath),PCStr(referer),PCStr(auser),PCStr(apass),PCStr(reason));
int   do_RELAY(DGCTX,int what);
int   service_permitted2(DGCTX,PCStr(service),int silent);
int   service_permitted(DGCTX,PCStr(service));
int   method_permittedX(DGCTX,PCStr(proto),PCStr(method),int igncase);
int   source_permittedX(DGCTX);
int   source_permitted(DGCTX);
void  scan_REJECT(DGCTX,PCStr(protolist));
void  delayRejectX(DGCTX,int self,PCStr(proto),PCStr(host),int port,int clsock);
void  delayUnknown(DGCTX,int self,PCStr(req));
void  delayConnError(DGCTX,PCStr(req));
void  delayUnknown(DGCTX,int self,PCStr(req));
int   doNice(PCStr(what),DGCTX,int ifd,FILE *ifp,int ofd,FILE *ofp,int niced,FileSize bytes,int count,double since);

/* RELAY with CODE CONVERSION */
void  global_setCCX(DGCTX,PVStr(code),PVStr(stat));
FileSize CCV_relay_text(DGCTX,FILE *in,FILE *out,FILE *dup);
void  CTX_line_codeconv(DGCTX,PCStr(src),PVStr(dst),PCStr(ctype));
int   CTX_cur_codeconvCL(DGCTX,PVStr(cvenv));
int   CTX_check_codeconv(DGCTX,int dolog);
int   CTX_check_codeconvSP(DGCTX,int dolog);
int   CTX_check_codeconv(DGCTX,int dolog);
int   CTX_cur_codeconvCL(DGCTX,PVStr(cvenv));
void  CTX_line_codeconv(DGCTX,PCStr(src),PVStr(dst),PCStr(ctype));
void  tcp_relay2(int timeout,int s1,int d1,int s2,int d2);
int   relayf_svcl(DGCTX,FILE *fc,FILE *tc,FILE *fs,FILE *ts);
int   relay_svcl(DGCTX,int fromC,int toC,int fromS,int toS);
int   scan_CCXTOSV(DGCTX);
int   scan_CCXTOCL(DGCTX);
extern char CCXTOSV[];
extern char CCXTOCL[];

/* HTTP PROXY/SERVER */
void  scan_HTTPCONF(DGCTX,PCStr(conf));
const char *HTTP_DigestOpaque(DGCTX);
int   HTTP_isMethod(PCStr(method));
void  HTTP_ClientIF_HP(DGCTX,PVStr(hostport));
int   HTTP_ClientIF_H(DGCTX,PVStr(host));
void  HTTP_ClientIF_HP(DGCTX,PVStr(hostport));
int   HTTP_relayThru(DGCTX);
char *HTTP_getRequestField(DGCTX,PCStr(fname),PVStr(buff),int bsize);
int   putHttpHeader1(DGCTX,FILE *tc,PCStr(server),PCStr(type),PCStr(encoding),FileSize size,int expire);
int   putHttpHeaderV(DGCTX,FILE *tc,int vno,PCStr(server),PCStr(type),PCStr(encoding),int size,int lastmod,int expire);
int   makeAuthorization(DGCTX,PVStr(genauth),int proxy);
int   HTTP_getAuthorization(DGCTX,int proxy,AuthInfo *ident,int decomp);
int   UAwithoutDigest(DGCTX);
int   DontKeepAliveServ(DGCTX,PCStr(what));
int   getKeepAlive(DGC*Conn,PVStr(KA));
FILE *openHttpResponseFilter(DGCTX,FILE *tc);

int   select_icpconf(DGCTX,PVStr(icpconf));
void  add_DGinputs(DGCTX,PCStr(fmt),...);
const char *add_DGheader(DGCTX,PCStr(head),PCStr(fmt),...);
char *DDI_fgetsFromCbuf(DGCTX,PVStr(str),int size,FILE *fp);
int   DDI_PollIn(DGCTX,FILE *fc,int timeout);
char *DDI_fgetsFromC(DGCTX,PVStr(req),int size,FILE *fp);
int   DDI_flushCbuf(DGCTX,PVStr(bbuff),int bsize,FILE *fc);
int   DDI_peekcFromC(DGCTX,FILE *fp);
int   DDI_proceedFromC(DGCTX,FILE *fp);
void  DDI_pushCbuf(DGCTX,PCStr(req),int len);

/* FTPxHTTP */
int isFTPxHTTP(PCStr(proto));
int isinFTPxHTTP(DGCTX);

/* MAIL */
int   SMTP_open(DGCTX,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log);
int   validateEmailAddr(PCStr(addr),int checkuser);
FILE *expand_aliases(PCStr(recipients),FILE *log);

/* AUTHORIZATION */
int   CTX_with_auth_anonftp(DGCTX);
int   doPopAUTH(DGCTX,FILE **tsp,FILE **fsp,PCStr(timestamp),PCStr(user),PCStr(pass),PVStr(resp),int size);
int   is_anonymous(PCStr(user));

/* IP ADDRESS and PORT number */
#ifndef _VSOCKET_H
typedef unsigned INETADDRV4;
#endif
char *_inet_ntoaV4I(INETADDRV4 ia);
INETADDRV4 ntohL(INETADDRV4 li);
INETADDRV4 htonL(INETADDRV4 li);
INETADDRV4 _inet_addrV4(PCStr(cp));
unsigned short htonS(int);
unsigned short ntohS(int);

/* WIN32 functions for porting to Win32 */
int   SessionFd();
int   SocketOf(int sock);
int   setclientsock(int sock);
int   getclientsock();
int   setcontrolsock(int sock);
int   getcontrolsock();
int   closedups(int si);
int   setserversock(int sock);
int   getserversock();
int   setrsvdsock(int si,int sock);
FileSize Lseek(int fd,FileSize off,int wh);
int   clearCloseOnExec(int fd);
int   setCloseOnExecSocket(int fd);
int   clearCloseOnExecSocket(int fd);

/* RUNTIME USER ENVIRONMENT */
char *getUsername(int uid,PVStr(name));
char *getUsernameCached(int,PVStr(name));
char *getusernames(PVStr(names));
int   scan_guid(PCStr(user_group),int *uidp,int *gidp);
void  getHOME(int uid,PVStr(home));
int   getSHELL(int uid,PVStr(shell));

/* TIMER */
void  setTimer(int sp,int intvl);
void  popTimer(int sp);
void  dumpTimer();
void  msleep(int msec);

/* RESOURCE USAGE */
int   expand_stack(int smax);
int   expand_fdset(int amax);

/* SAFETY BELT */
void  randenv();
int   randfd(int fd);
int   randstack_call(int strg, iFUNCP func, ...);

/* DeleGate AS A CLIENT */
FILE *URLget(PCStr(url),int reload,FILE *out);
FILE *CTX_URLget(DGCTX,int origctx,PCStr(url),int reload,FILE *out);
FILE *openPurl(PCStr(base),PCStr(purl),PVStr(aurl));

void  swfFilter(DGCTX,FILE *in,FILE *out,PCStr(arg));
int   procSocket(DGC*Conn,PCStr(command),int sio[]);
FILE *Gunzip(PCStr(enc),FILE *fs);
FILE *Gzip(PVStr(enc),FILE *src);
/*
FILE *Gzip(PCStr(enc),FILE *src);
*/

void  closeFDs(FILE *ifp,FILE *ofp);

int PageCountUpURL(DGC*ctx,int flags,PCStr(url),void *vcntp);
int strfCounter(DGC*ctx,int flags,PCStr(url),PCStr(fmt),PCStr(timefmt),PVStr(buff),int bsize);
#define CNT_READONLY	0x00000001
#define CNT_INCREMENT	0x00000002
#define CNT_ACCESS	0x00000010
#define CNT_SSIPAGE	0x00000020
#define CNT_SSIINCLUDE	0x00000040
#define CNT_REFERER	0x00000080 /* Referer: */
#define CNT_TOTALHITS	0x00000100 /* total of the counters of the site */
#define CNT_ERROR	0x00000200
#define CNT_TCPIN	0x00000400
#define CNT_TCPOUT	0x00000800
#define CNT_DESTINATION	0x00002000
#define CNT_VHOST	0x00004000 /* Host: */
#define CNT_SERVER	0x00010000 /* Server: */
#define CNT_PROXY	0x00020000 /* Via: */
#define CNT_HTTPUA	0x00040000 /* User-Agent: */

#define CNT_MOUNTVURL	0x10000000
#define CNT_MOUNTRURL	0x20000000
#define CNT_MOUNTOPT	0x80000000

#define CNT_ACCESSINC	(CNT_ACCESS|CNT_INCREMENT)
#define CNT_TOTALINC	(CNT_TOTALHITS|CNT_INCREMENT)
#define CNT_ERRORINC	(CNT_ERROR|CNT_INCREMENT)
#define CNT_DESTINC	(CNT_DESTINATION|CNT_INCREMENT)

extern int gl_COUNTER;
extern int mo_COUNTER;
#define COUNTERflag(f)	((mo_COUNTER ? mo_COUNTER : gl_COUNTER)&f)

/*
 * ClientEOF
 */
#define CLEOF_CLOSED	0x00000001
#define CLEOF_INACT	0x00000002
#define CLEOF_NOACTCL	0x80000000

/*
 * ClientSock
 */
#define CLNT_NO_SOCK	-2

/*
 * EXPIRE
 */
#define CACHE_DONTEXP	0x80000000

/*
 * INVOCATION
 */
#define INV_IMPFUNC	0x00000001 /* invoked by implanated FUNC=name */
#define INV_BYOWNER	0x00000002 /* invoked by the owner of the exec */
#define INV_BYGROUP	0x00000004 /* invoked by the group of the exec */
#define INV_NOIMP	0x00000010 /* -Fimp is specified explicitly */
#define INV_ASFILTER	0x10000000 /* run as a filter */
#define INV_ASDAEMON	0x20000000 /* run as a damon */

/*
 * RequestFlags
 * flags to control the current request
 */
#define QF_NO_DELAY	0x00000001
#define QF_NO_REWRITE	0x00000002
#define QF_NO_AUTH	0x00000004
#define QF_FTPXHTTP	0x00000008 /* during a request to a server */
#define QF_URLGET_RAW	0x00000010 /* thru the result of URLget */
#define QF_URLGET_THRU	0x00000020
#define QF_URLGET_HEAD	0x00000040
#define QF_AUTH_FORW	0x00000080
#define QF_FTP_COMLIST	0x00000100
#define QF_FTP_COMRETR	0x00000200
#define QF_FTP_COMSTOR	0x00000400
#define QF_FTP_COMSTAT	0x00000800 /* SIZE, MDTM (no body) */

/*
 * Gateway status
 * these status must be constant through the lifetime of a connection
 * from a client
 */
#define GatewayFlags	Conn->gw_flags
#define GW_IN_CLALG	0x00000001 /* isin CLALG mode */
#define GW_FROM_MYSELF	0x00000002 /* keep from_myself during keep-alive */
#define GW_NO_HTTP_CKA	0x00000004 /* suppress server-bank in keep-alive */
#define GW_FTPXHTTP	0x00000008 /* constant during a connection */
#define GW_IS_YYSHD	0x00000020 /* running as a YYSH server */
#define GW_IS_YYSHD_YYM	0x00000040 /* YYMUX for a YYSH server */
#define GW_DONT_SHUT    0x00100000 /* don't shutdown sock. initiated by self */
#define GW_DONT_FTOCL	0x00200000 /* don't insert FTOCL, initiated by self */
#define GW_IS_CFI       0x08000000 /* executing CFI */
#define GW_SYN_SSLSTART	0x00000010 /* don't wait SSLready but wait SSLstart */
#define GW_WITH_ORIGDST	0x00000100 /* got SO_ORIGINAL_DST */
#define GW_GET_ERRRESP	0x00000200 /* get error response not as empty data */
#define GW_SSI_INCLUDE	0x10000000 /* executing SSI include */
#define GW_COMMAND	0x20000000 /* -Fcommand */
#define GW_NO_ANCHOR	0x40000000 /* disable HREF anchor */
#define GW_SERV_THREAD	0x80000000 /* this server is running as a thread */
int CTX_addGatewayFlags(DGC*ctx,int flags);
int CTX_setGatewayFlags(DGC*ctx,int flags);

/*
 * Static and global configuration status
 */
#define ConfigFlags	Conn->cf_flags
#define CF_WITH_CCXTOCL	0x00000010 /* with conditional CCX_TOCL */
#define CF_WITH_CCXTOSV	0x00000020 /* with conditional CCX_TOSV */
#define CF_WITH_MYSOX	0x00000040 /* with a private sockmux */
#define CF_HTMUX_SERVER	0x00000100
#define CF_HTMUX_CLIENT	0x00000200
#define CF_HTMUX_PROXY	0x00000400

void CTX_dumpGatewayAuth(DGCTX,PCStr(F),int L);
#define dumpGatewayAuth(ctx) CTX_dumpGatewayAuth(ctx,__FILE__,__LINE__)


typedef struct {
	int CE_TIMEOUT;
	int CE_CANTRESOLV;
	int CE_UNREACH;
	int CE_REFUSED;
} ConnStat;
#define NUM_CONNSTAT 64
extern ConnStat ConnStats[NUM_CONNSTAT];
#define CSGIX() (lMULTIST()?(getthreadix()%NUM_CONNSTAT):0)
#define CONNERR_TIMEOUT    ConnStats[CSGIX()].CE_TIMEOUT
#define CONNERR_CANTRESOLV ConnStats[CSGIX()].CE_CANTRESOLV
#define CONNERR_UNREACH    ConnStats[CSGIX()].CE_UNREACH
#define CONNERR_REFUSED    ConnStats[CSGIX()].CE_REFUSED

int IOTIMEOUT_FL(FL_PAR,int msec);
#define IOTIMEOUT(msec) IOTIMEOUT_FL(FL_ARG,msec)

extern const char *ORIGDST_HOST;
extern const char *CLIENTIF_HOST;
extern const char *CLIENT_HOST;

int CTX_closedX(FL_PAR,PCStr(wh),DGCTX,int fd1,int fd2,int force);
#define closedX(wh,fd1,fd2,force) CTX_closedX(FL_ARG,wh,Conn,fd1,fd2,force)
int CTX_closed(FL_PAR,PCStr(wh),DGCTX,int fd1,int fd2);
#define closed(wh,fd1,fd2) CTX_closed(FL_ARG,wh,Conn,fd1,fd2)
int CTX_fcloses(FL_PAR,PCStr(wh),DGCTX,FILE *fp1,FILE *fp2);

char *substDGDEF(DGCTX,PCStr(pat),PVStr(data),int dz,int opts,int encoding);
#define DGD_ESC_QUOTE		0x0001
#define DGD_EVAL_ONINIT		0x0002
#define DGD_SUBST_ONINIT	0x0004

typedef struct htmlFlags {
	int ht_encent:8,
	    ht_escurl:1,
	    ht_extsrc:1; /* data of external origin (request / response) */
} HTMLflags;
#define HtmlFlags ((struct htmlFlags*)&Conn->html_flags)
#define ENCODE_ENT1	HtmlFlags->ht_encent
#define ESCAPE_URL1	HtmlFlags->ht_escurl
#define HTMLSRC_EXT	HtmlFlags->ht_extsrc

void addAccHist(DGCTX,int accepted);
#define ACC_STARTED		0x0000
#define ACC_OK			0x0001
#define ACC_FORBIDDEN		0x0002
#define ACC_AUTH_REQUIRED	0x0003
#define ACC_AUTH_DENIED		0x0004
#define ACC_AUTH_CFGERR		0x0005

typedef struct {
	double	currentTime;
	VAddr	clientsideHost;
	VAddr	clientSockHost;
	VAddr	clientHost;
	MStr(	e_agentname,128);
	int	_fromself;
} ClientInfo;

void NOSRC_warn(PCStr(func),PCStr(fmt),...);
void NOCAP_warn(PCStr(caps),PCStr(fmt),...);

extern int AccViaHTMUX; /* accept by normal accept() via SockMux */

typedef struct {
	int	ctx_id;
	int	ftp_flags;
	int	ftp_PBSZ;
	int	ftp_PROT;
} FtpTLS;
#define FtpTLSX ((FtpTLS*)Conn->proto_ctx)
#define FtpTLSX_VALID (FtpTLSX->ctx_id == Conn->cx_magic)
#define FtpTLSX_PBSZ	0x00000001
#define FtpTLSX_PROT	0x00000002

int CCSV_reusing(DGC*Conn,PCStr(what),int sock);

int Em_active(int out,DGC*Conn,FL_PAR);
int Em_setupMD5(int out,DGC*Conn,PCStr(wh));
int Em_updateMD5(int out,DGC*Conn,const void *buff,int leng);
int Em_finishMD5(int out,DGC*Conn,PCStr(wh),FileSize leng);
int Em_printMD5(int out,DGC*Conn,PVStr(md5a));
#define EmiActive(C)		LOGMD5_IN<=0?0:Em_active(0,C,FL_ARG)
#define EmiSetupMD5(C,wh)	Em_setupMD5(0,C,wh)
#define EmiUpdateMD5(C,b,l)	LOGMD5_IN<=0?0:Em_updateMD5(0,C,b,l)
#define EmiFinishMD5(C,wh,l)	Em_finishMD5(0,C,wh,l)
#define EmiPrintMD5(C,m)	Em_printMD5(0,C,m)

#define ConnectFlags	Conn->connect_flags
#define COF_TERSE	0x00000001
#define COF_DONTRETRY	0x00000002
#define COF_RESUMING	0x00000004 /* resuming/reusing YYMUX connection */
#define COF_NOAPPSTLS	0x00000008 /* don't apply STLS to app. protocol */
#define COF_NOCTRLSSL	0x00000010 /* don't apply STLS to control conn. */
#define COF_NODATASSL	0x00000020 /* don't apply STLS to data conn. */
#define COF_SSL_SV	0x00000040 /* by MASTER=host:xxx/ssl */
#define COF_NONDIRECT	0x00000080 /* don't try direct connection */
#define COF_SUBYYMUX	0x00000100 /* YYMUX in YYMUX */
#define COF_SCREENED	0x00000200 /* to be rejected in app. level */
#define COF_DO_STICKY	0x00000400 /* be StickyServer */

int getConnectFlags(PCStr(wh));
int scanConnectFlags(PCStr(wh),PCStr(flags),int flagi);
int setConnectFlags(PCStr(wh),DGCTX,int flagi);

#define AccPort_Proto	Port_Proto
#define AccPort_Flags	Conn->clif._portFlags
#define AccPort_Port	Conn->clif._acceptPort
#define SVP_STLS	0x1000 /* -Pxxxx/stls */
#define SVP_SSL		0x2000 /* -Pxxxx/ssl */

#if defined(FMT_CHECK) /*{ 9.9.7 for testing format & values */
#define A_TraceLog printf
#define A_svlog    printf
#define A_sv1log   printf
#define A_svvlog   printf
#define A_sv1vlog  printf
#define fputLog(C,F,fmt,...)  fprintf(stderr,fmt,##__VA_ARGS__)
#define svlog(fmt,...)        fprintf(stderr,fmt,##__VA_ARGS__)
#define sv0log(fmt,...)       fprintf(stderr,fmt,##__VA_ARGS__)
#define svvlog(fmt,...)       fprintf(stderr,fmt,##__VA_ARGS__)
#define sv1log(fmt,...)       fprintf(stderr,fmt,##__VA_ARGS__)
#define sv1tlog(fmt,...)      fprintf(stderr,fmt,##__VA_ARGS__)
#define sv1vlog(fmt,...)      fprintf(stderr,fmt,##__VA_ARGS__)
#define syslog_DEBUG(fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#define syslog_ERROR(fmt,...) fprintf(stderr,fmt,##__VA_ARGS__)
#define TraceLog(fmt,...)     fprintf(stderr,fmt,##__VA_ARGS__)
#define ERRMSG(fmt,...)       fprintf(stderr,fmt,##__VA_ARGS__)
#define DBGMSG(fmt,...)       fprintf(stderr,fmt,##__VA_ARGS__)
#define Fprintf(fp,fmt,...)   fprintf(fp,fmt,##__VA_ARGS__)
#define ProcTitle(C,fmt,...)  fprintf(stderr,fmt,##__VA_ARGS__)
#else /*}{*/
#define A_TraceLog TraceLog
#define A_svlog    svlog
#define A_sv1log   sv1log
#define A_svvlog   svvlog
#define A_sv1vlog  sv1vlog

#define FMT_fputLog      fputLog
#define FMT_svlog        svlog
#define FMT_sv0log       sv0log
#define FMT_svvlog       svvlog
#define FMT_sv1log       sv1log
#define FMT_sv1tlog      sv1tlog
#define FMT_sv1vlog      sv1vlog
#define FMT_syslog_DEBUG syslog_DEBUG
#define FMT_syslog_ERROR syslog_ERROR
#define FMT_TraceLog     TraceLog
#define FMT_ERRMSG       ERRMSG
#define FMT_DBGMSG       DBGMSG
#define FMT_Fprintf      Fprintf
#define FMT_ProcTitle    ProcTitle

int   FMT_fputLog(DGCTX,PCStr(filter),PCStr(fmt),...);
int   FMT_svlog(PCStr(fmt),...);
int   FMT_sv0log(PCStr(fmt),...);
int   FMT_svvlog(PCStr(fmt),...);
int   FMT_sv1log(PCStr(fmt),...);
int   FMT_sv1tlog(PCStr(fmt),...);
int   FMT_sv1vlog(PCStr(fmt),...);
int   FMT_syslog_DEBUG(PCStr(fmt),...);
int   FMT_syslog_ERROR(PCStr(fmt),...);
void  FMT_TraceLog(PCStr(fmt),...);
int   FMT_ERRMSG(PCStr(fmt),...);
void  FMT_DBGMSG(PCStr(fmt),...);
int   FMT_Fprintf(FILE *fp,PCStr(fmt),...);
void  FMT_ProcTitle(DGCTX,PCStr(fmt),...);

#endif /*}*/

int YYfinishSV(FL_PAR,DGCTX);
void finishServYY(FL_PAR,DGCTX);
void finishClntYY(FL_PAR,DGCTX);
int pollYY(DGCTX,PCStr(wh),FILE *fc);
int YY_connect(DGC *Conn,int sock,int initfrom);
int YY_accept(DGC *Conn,FILE *tc,int initfrom);

typedef struct _SSLwayCTX {
	int	ss_fid;
	int	ss_ftype;
	int	ss_error;
	int	ss_ready;
	int	ss_start;
	int	ss_owner;
	int	ss_tid;
	double	ss_Start;
   const char **ss_environ;
} SSLwayCTX;

int MarkNewConn(FL_PAR,DGCTX);
#define ConnInitNew(ctx) \
	MarkNewConn(FL_ARG,ctx),ConnInit(ctx)
#endif
