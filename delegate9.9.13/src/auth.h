#ifndef _AUTH_H
#define _AUTH_H

#define RELAY_NO	0x0000 /* no relay (work as an orignal server) */
#define RELAY_PROXY	0x0001 /* by CERN (full URL) */
#define RELAY_DELEGATE	0x0006 /* by DELEGATE */
#define RELAY_DELEGATE1	0x0002 /* by /=@=URL rewriting (obsolete) */
#define RELAY_DELEGATE2	0x0004 /* by /-_-URL rewriting */
#define RELAY_SELF	0x0010 /* rewrite request only */
#define RELAY_INLINE	0x0020 /* rewrite inline images in response */
#define RELAY_PROTO	0x0030 /* rewrite URLs of the same protocols */
#define RELAY_SERVER	0x0040 /* rewrite URLS of the same saver */
#define RELAY_ANY	0x0050
#define RELAY_APPLET	0x0100 /* relay <APPLET> */
#define RELAY_OBJECT	0x0200 /* relay <OBJECT> and <EMBED> */
#define RELAY_JAVA	0x0300 /* relay <APPLET> <OBJECT> and <EMBED> */
#define RELAY_ORIGIN	0x0400 /* origin server */
#define RELAY_VHOST	0x0800 /* relay to host in Host: field */
#define RELAY_ORIGDST	0x1000 /* relay to host in SO_ORIGINAL_DST */
#define RELAY_Y11	0x2000 /* relay to Y11 server */
#define RELAY_YYMUX	0x4000 /* relaying by YYMUX */

#define MaxAuthServLen	2048

int   CTX_withAuth(DGCTX);
int   CTX_auth(DGCTX,PCStr(user),PCStr(pass));
int   CTX_auth_cache(DGCTX,int store,int expire,PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port);
int   CTX_with_auth_admin(DGCTX);
int   CTX_auth_admin(DGCTX,PCStr(what),PCStr(proto),PCStr(userhost));
int   CTX_auth_anonftp(DGCTX,PCStr(proto),PCStr(user),PCStr(pass));
int   doAuth(DGCTX,AuthInfo *ident);
int   doAUTH(DGCTX,FILE *fc,FILE *tc,PCStr(dstproto),PCStr(dsthost),int dstport,PVStr(auser),PVStr(ahost),iFUNCP func,AuthInfo *arg);
int   doAUTH0(DGCTX,FILE *fc,FILE *tc,PCStr(dstproto),PCStr(dsthost),int dstport,PVStr(auser),PVStr(ahost),iFUNCP func,AuthInfo *arg);
int   AuthenticateX(DGCTX,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident);
int   Authenticate(DGCTX,PCStr(host),PCStr(user),PCStr(pass),PCStr(path));
int   authEdit0(DGCTX,int detail,FILE *tc,int com,PCStr(host),PCStr(user),PCStr(pass));
int   source_permitted(DGCTX);
const char *VA_getOriginatorIdent(DGCTX,AuthInfo *ident);

const char *getClientUser(DGCTX);
const char *getClientUserX(DGCTX);
const char *getClientUserC(DGCTX);

const char *getAdminAuthorizer(DGCTX,PVStr(authsv),int asiz,int any);
int   DGAuth_port(int create,PVStr(host),int *portp);
int   getDigestPassX(DGCTX,PCStr(host),PCStr(user),PVStr(spass));
#define getDigestPass(host,user,spass) getDigestPassX(MainConn(),host,user,spass)
int   genPass(DGCTX,PCStr(host),PCStr(user),PVStr(pass));
void  dumpCKey(int force);
void  NonceKey(PVStr(key));
int   get_MYAUTH(DGCTX,PVStr(myauth),PCStr(proto),PCStr(dhost),int dport);
int   genDigestNonce(DGCTX,AuthInfo *ident,PCStr(uri),PVStr(nonce));
int   genDigestResp(DGCTX,AuthInfo *ident,PVStr(xrealm),PCStr(uri),PVStr(nonce));
void  genDigestReq(AuthInfo *ident,PCStr(Method),PCStr(uri),PCStr(user),PCStr(pass),PCStr(realm),PCStr(nonce),PVStr(digest));
void  genSessionID(DGCTX,PVStr(opaque),int inc);

typedef struct MD5_CTX MD5;
MD5  *newMD5();
void  addMD5(MD5*ctx,PCStr(str), int len);
void  endMD5(MD5*ctx,char digest[]);
int   fMD5(FILE *fp,char digest[]);
void  toMD5dots(PCStr(pfx),PCStr(str),PVStr(dots),int len);
void  MD5toa(PCStr(digest),char md5a[]);
int   msgMD5(FILE *fs,FILE *tc,char md5a[]);
int   putDigestPass(FILE *fp,PCStr(fmt),PCStr(host),PCStr(user));
int   authAPOP(DGCTX,PCStr(domain),PCStr(user),PCStr(seed),PVStr(mpass));
int   withAuthDigest(DGCTX,PVStr(authserv));

int AuthTimeout(DGCTX);
int AuthThru(DGCTX,PCStr(user));

int SignRSA(PCStr(privkey),PCStr(data),PCStr(pass),PCStr(md5),int mlen,PVStr(sig),unsigned int *slen);
int VerifyRSA(PCStr(pubkey),PCStr(data),PCStr(md5),int mlen,PCStr(sig),unsigned int slen);

#endif /* _AUTH_H */
