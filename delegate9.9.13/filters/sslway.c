/*
the header is necessary to enable some macros
#include <openssl/ssl.h>
*/

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2007 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	sslway.c (SSL encoder/decoder with SSLeay/openSSL)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

  Given environment:
    file descriptor 0 is a socket connected to a client
    file descriptor 1 is a socket connected to a server

  Commandline argument:
    -cert file -- certificate (possibly with private key) of this SSLway
                  to be shown to a peer
    -key file -- private key file (if not included in the -cert file)
    -pass arg -- the source of passphrase, pass:string or file:path

    -CAfile file -- the name of file contains a CA's certificate
    -CApath dir -- directory contains CA's certificate files each named with
                   `X509 -hash -noout < certificate.pem`

    -Vrfy -- peer's certificate must be shown and must be authorized
    -vrfy -- peer's certificate, if shown, must be authorized
    -Auth -- peer must show its certificate, but it can be unauthorized
    -auth -- just record the peer's certificate, if exists, into log
             -- equals to obsoleted "-client_auth".

    -vd  -- detailed logging
    -vu  -- logging with trace (former default)
    -vt  -- terse logging (current default)
    -vs  -- disalbe any logging

    -ht  through pass if the request is in bare HTTP protocol (GET,HEAD,POST)

    Following options can be omitted when the sslway is called from DeleGate
    with FCL, FSV or FMD since it will be detected automatically.

    -co  apply SSL for the connection to the server [default for FSV]
    -ac  aplly SSL for the accepted connection from the client [default for FCL]
    -ad  accept either SSL or through by auto-detection of SSL-ClientHello
    -ss  negotiate by AUTH SSL for FTP (implicit SSL for data-connection)
    -st  accept STARTTLS (protocol is auto-detect) and SSL tunneling
    -St  require STARTTLS first (protocol is auto-detect) and PBSZ+PROT for FTP
    -{ss|st|St}/protocol enable STARTTLS for the protocol {SMTP,POP,IMAP,FTP}
    -bugs

    -tls1 just talk TLSv1
    -ssl2 just talk SSLv2
    -ssl3 just talk SSLv3

  Usage:
    delegated FSV=sslway
    delegated FCL=sslway ...

  How to make:
    - do make at .. or ../src directory
    - edit Makefile.go to let SSLEAY points to the directory of libssl.a
    - make -f Makefile.go sslway

History:
	980412	created
	980428	renamed from "sslrelay" to "sslway"
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "file.h" /* RecvPeek() */
#include "proc.h"
#include "vsignal.h"
#include "ysignal.h"
#include "fpoll.h"

#ifdef daVARGS
#undef VARGS
#define VARGS daVARGS
#define LINESIZE 1024
#endif

#include "log.h"

typedef struct {
	const char **se_av;
	int se_ac;
} SslEnv;

#define _VERSION_H /* include macro definitions only */
#include "../src/version.c"

#ifdef _MSC_VER
#undef ERROR
#undef X509
#undef X509_NAME
#endif

int randstack_call(int strg,iFUNCP func, ...);
char **move_envarg(int ac,const char *av[],const char **areap,int *lengp,int *sizep);
long Gettimeofday(int *usec);
int CFI_init(int ac,const char *av[]);
int PollIns(int timeout,int size,int *mask,int *rmask);
int setNonblockingIO(int fd,int on);
void set_nodelay(int sock,int onoff);
int SocketOf(int sock);
int LIBFILE_IS(PCStr(file),PVStr(xfile));
FILE *CFI_fopenShared(PCStr(mode));
int CFI_sharedLock();
int CFI_exclusiveLock();
int CFI_unLock();
int getthreadid();
const char *CFI_FILTER_ID();
int setCloseOnFork(PCStr(wh),int fd);
int clearCloseOnFork(PCStr(wh),int fd);
int ShutdownSocket(int fd);
void set_linger(int sock,int secs);

#define LSILENT	-1
#define LERROR	0
#define LTRACE	1
#define LDEBUG	2
static int loglevel = LERROR;
#define ERROR	(loglevel < LERROR)?0:DOLOG
#define TRACE	(loglevel < LTRACE)?0:DOLOG
#define DEBUG	(loglevel < LDEBUG)?0:DOLOG
#define VDEBUG	!LOG_VERBOSE?0:DEBUG

static FILE *stdctl;
static const char *client_host;
static int PID;
static int Builtin;
static int DOLOG(PCStr(fmt),...)
{	CStr(xfmt,256);
	CStr(head,256);
	SSigMask sMask;
	VARGS(8,fmt);

	setSSigMask(sMask);
	if( Builtin )
		sprintf(head,"## SSLway");
	else
	sprintf(head,"## SSLway[%d](%s)",PID,client_host);
	sprintf(xfmt,"%%s %s\n",fmt);
	syslog_ERROR(xfmt,head,VA8);
	resetSSigMask(sMask);
	return 0;
}

#ifndef SSL_FILETYPE_PEM /*{*/
/*BEGIN_STAB(ssl)*/
#ifdef __cplusplus
extern "C" {
#endif
/*
#include "ssl.h"
*/
#define SSL_FILETYPE_PEM 1
#define SSL_VERIFY_NONE			0x00
#define SSL_VERIFY_PEER			0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT	0x02
#define SSL_VERIFY_CLIENT_ONCE		0x04

#define SSL_CTRL_OPTIONS		32
#define SSL_OP_NO_SSLv2			0x01000000
#define SSL_OP_NO_SSLv3			0x02000000
#define SSL_OP_NO_TLSv1			0x04000000

typedef void SSL_CTX;
typedef void SSL_METHOD;
typedef void SSL;
typedef void X509;
typedef void X509_NAME;
typedef void X509_STORE;
typedef void X509_STORE_CTX;
typedef void BIO_METHOD;
typedef void BIO;
typedef void SSL_SESSION;
typedef void EVP_PKEY;
typedef void EVP_CIPHER;
typedef void SSL_CIPHER;
#define BIO_NOCLOSE 0

typedef void BIGNUM;
typedef void RSA;
/*
RSA
	BIGNUM *rsa_n;    // public modulus
	BIGNUM *rsa_e;    // public exponent
	BIGNUM *rsa_d;    // private exponent
	BIGNUM *rsa_p;    // secret prime factor
	BIGNUM *rsa_q;    // secret prime factor
	BIGNUM *rsa_dmp1; // d mod (p-1)
	BIGNUM *rsa_dmq1; // d mod (q-1)
	BIGNUM *rsa_iqmp; // q^-1 mod p
*/
int RSA_print_fp(FILE *fp,RSA *rsa,int offset);
void RSA_free(RSA *rsa);
int PEM_write_RSAPublicKey(FILE *fp,RSA *rsa);
typedef int pem_password_cb(char buf[], int size, int rwflag, void *userdata);
int PEM_write_RSAPrivateKey(FILE *fp,RSA *rsa,const EVP_CIPHER *enc,unsigned char *kstr,int klen,pem_password_cb *cb,void *u);
EVP_CIPHER *EVP_des_ede3_cbc();
RSA *PEM_read_RSAPrivateKey(FILE *fp,RSA **x,pem_password_cb *cb,void *u);
RSA *PEM_read_RSAPublicKey(FILE *fp,RSA **x,pem_password_cb *cb,void *u);
BIGNUM *BN_new(BIGNUM *a);
void BN_free(BIGNUM *a);
char *BN_bn2hex(const BIGNUM *a);

const char *SSLeay_version(int t);

BIO_METHOD *BIO_s_mem();
BIO *BIO_new(BIO_METHOD*);
int BIO_puts(BIO *bp,char *buf);
int BIO_gets(BIO *bp,char *buf,int size);

BIO *BIO_new_fp(FILE *stream, int close_flag);
int BIO_free(BIO *a);
X509 *PEM_read_bio_X509(BIO*,...);
RSA *PEM_read_bio_RSAPrivateKey(BIO*,...);

SSL_CTX *SSL_CTX_new(SSL_METHOD *method);
void ERR_clear_error(void);
int  SSL_library_init(void);
SSL *SSL_new(SSL_CTX *ctx);
int  SSL_set_fd(SSL *ssl, int fd);
int  SSL_connect(SSL *ssl);
int  SSL_accept(SSL *ssl);
SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
char *SSL_CIPHER_description(const SSL_CIPHER *sc,char *buf,int size);
int  SSL_write(SSL *ssl, const void *buf, int num);
int  SSL_read(SSL *ssl,void *buf,int num);
int  SSL_pending(SSL *s);
int  SSL_shutdown(SSL *ssl);
#define SSL_SENT_SHUTDOWN 1
#define SSL_RECEIVED_SHUTDOWN 2
int  SSL_get_shutdown(SSL *ssl);
void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);
void SSL_load_error_strings(void );
int  SSL_get_error(SSL *s,int ret_code);
X509 *SSL_get_peer_certificate(SSL *ssl);

SSL_SESSION *SSL_SESSION_new(void);
#define SSL_CTX_sess_set_new_cb(ctx,cb)	/* it's a macro */
/*
#define SSL_CTRL_GET_SESSION_REUSED	6
#define SSL_CTRL_SESS_HIT	27
#define SSL_CTRL_SESS_MISSES	29
#define SSL_CTX_sess_hits(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,NULL)
#define SSL_CTX_sess_misses(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,NULL)
#define SSL_session_reused(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_SESSION_REUSED,0,NULL)
*/
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx);/*OPT(0)*/
const char *SSL_get_servername(const SSL *s, const int type);/*OPT(0)*/
int SSL_get_servername_type(const SSL *s);/*OPT(0)*/
long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));/*OPT(0)*/
typedef void (*SNCB)();
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb) \
	SSL_CTX_callback_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,(SNCB)cb)
#define SSL_set_tlsext_host_name(con,name) \
	SSL_ctrl(con,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)

#define SSL_session_reused(ssl) 0
int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c);
SSL_SESSION *SSL_get_session(SSL *ssl);
int SSL_set_session(SSL *ssl,SSL_SESSION *sess);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
X509 *SSL_get_certificate(SSL *ssl);
EVP_PKEY *SSL_get_privatekey(SSL *ssl);
#define EVP_PKEY_RSA 6
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,unsigned char **pp,long length);
int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);
X509 *d2i_X509(X509 **x,unsigned char**in,int len);
int i2d_X509(X509 *x,unsigned char **pp);
EVP_PKEY *d2i_PrivateKey(int type,EVP_PKEY **a,unsigned char **pp,long length);
int i2d_PrivateKey(EVP_PKEY *a,unsigned char **pp);

long SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
int  SSL_CTX_check_private_key(SSL_CTX *ctx);
X509_STORE *SSL_CTX_get_cert_store(SSL_CTX *);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx,PCStr(CAfile),PCStr(CApath));
int  SSL_CTX_set_cipher_list(SSL_CTX *,PCStr(str));
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
int  SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb)(SSL *ssl,int is_export, int keylength));                         
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode, int (*callback)(int, X509_STORE_CTX *));
int  SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx,PCStr(file), int type);
int  SSL_CTX_use_certificate_file(SSL_CTX *ctx,PCStr(file), int type);
int  SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx,PCStr(file));/*OPT(0)*/

SSL_METHOD *SSLv2_server_method(); /*OPT(0)*/
SSL_METHOD *SSLv2_client_method(); /*OPT(0)*/
SSL_METHOD *SSLv3_server_method();
SSL_METHOD *SSLv3_client_method();
SSL_METHOD *SSLv23_server_method();
SSL_METHOD *SSLv23_client_method();
SSL_METHOD *TLSv1_server_method();
SSL_METHOD *TLSv1_client_method();

X509_NAME *X509_get_issuer_name(X509 *a);
int i2d_X509_bio(BIO *bp,X509 *x509);
char *X509_NAME_oneline(X509_NAME *a,char buf[],int size);
const char *X509_verify_cert_error_string(long n);
X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509_NAME *X509_get_subject_name(X509 *a);
void X509_free(X509 *a);
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);

RSA *RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg);

typedef struct {
	int	ssl_version;
 unsigned int	key_arg_length;
 unsigned char	key_arg[8];
	int	master_key_length;
 unsigned char	master_key[48];
 unsigned int	session_id_length;
 unsigned char	session_id[32];
} SessionHead;

void ERR_load_crypto_strings(void);
RSA *PEM_read_bio_PrivateKey(BIO*,...);
X509 *PEM_read_X509(FILE*fp,X509**x,pem_password_cb*cb,void *u);
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp,EVP_PKEY **x,pem_password_cb *cb,void *u);
int RSA_size(RSA*rsa);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
EVP_PKEY *X509_get_pubkey(X509 *x);
#define RSA_PKCS1_PADDING 1
#define NID_md5 4
int RSA_private_encrypt(int flen,unsigned char *from,unsigned char *to,RSA *rsa,int padding);
int RSA_public_decrypt(int flen,unsigned char *from,unsigned char *to,RSA *rsa,int padding);
int RSA_sign(int type,unsigned char *m,unsigned int m_len,unsigned char *sigret,unsigned int *siglen,RSA *rsa);
int RSA_verify(int type,unsigned char *m,unsigned int m_len,unsigned char *sigbuf,unsigned int siglen,RSA *rsa);


#ifdef __cplusplus
}
#endif
#endif /*}*/

#ifdef __cplusplus
extern "C" {
#endif
unsigned long ERR_get_error(void);
char *ERR_error_string_n(int,char*,int);
void ERR_print_errors_fp(FILE *fp);
void RAND_seed(const void *buf,int num);
void X509_STORE_set_flags(X509_STORE *ctx, long flags);/*OPT(0)*/
#define X509_V_FLAG_CRL_CHECK		0x04
#define X509_V_FLAG_CRL_CHECK_ALL	0x08

#define RC4_INT unsigned int
typedef struct {
        RC4_INT x,y;
        RC4_INT data[256];
} RC4_KEY;
void RC4_set_key(RC4_KEY *key,int len,const unsigned char *data);
void RC4(RC4_KEY *key,unsigned long len,const unsigned char *in,unsigned char *out);

int SSL_CTX_set_session_id_context(SSL_CTX*,const unsigned char *sid_ctx,unsigned int sid_ctx_len); /*OPT(0)*/
typedef int (*GEN_SESSION_CB)(const SSL *ssl,unsigned char *id,unsigned int *id_len);
int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb);/*OPT(0)*/
void ENGINE_load_builtin_engines(void);/*OPT(0)*/
void OPENSSL_add_all_algorithms_conf(void);/*OPT(0)*/

BIO *BIO_new_file(const char *filename, const char *mode);
typedef void DH;
DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);/*OPT(0)*/
void DH_free(DH *dh);/*OPT(0)*/
#define SSL_CTRL_SET_TMP_DH 3
#define SSL_CTX_set_tmp_dh(ctx,dh) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)

#ifdef __cplusplus
}
#endif

/*END_STAB*/

void myRC4_set_key(RC4_KEY *key,int len,const unsigned char *data){
	RC4_set_key(key,len,data);
}
void myRC4(RC4_KEY *key,unsigned long len,const unsigned char *in,unsigned char *out){
	RC4(key,len,in,out);
}

static unsigned char *ssid = (unsigned char*)"SSLway";
static int ssid_len = 1;

typedef unsigned char Uchar;
int sslway_dl();
static void putDylibError(){
 fprintf(stderr,"-- ERROR: can't link the SSL/Crypto library.\n");
 fprintf(stderr,"-- Hint: use -vl option to trace the required library,\n");
 fprintf(stderr,"--- find it (ex. libssl.so.X.Y.Z) under /usr/lib or /lib,\n");
 fprintf(stderr,"--- then set the library version as DYLIB='+,lib*.so.X.Y.Z'\n");
}
static int checkCrypt(){
	if( sslway_dl() == 0 ){
		putDylibError();
		return -1;
	}
	return 0;
}
int signRSA(RSA *rsa,PCStr(md5),int mlen,PVStr(sig),unsigned int *slen){
	int siz;
	int ok = 0;

	if( checkCrypt() < 0 )
		return 0;

	siz = RSA_size(rsa);
	if( *slen < siz ){
		fprintf(stderr,"signRSA: not enough sig. buffer\n");
		return 0;
	}
	ok = RSA_sign(NID_md5,(Uchar*)md5,mlen,(Uchar*)sig,slen,rsa);
	return ok;
}
static char *privPEM;
static RSA *privRSA;

static int pass_cb(char buf[],int size,int rwflag,void *userdata){
	fprintf(stderr,"## Passphrase for KEY requested:%X\n",p2i(userdata));
	Xstrcpy(ZVStr(buf,size),(char*)userdata);
	return strlen((char*)userdata);
}
int SignRSA(PCStr(privkey),PCStr(data),PCStr(pass),PCStr(md5),int mlen,PVStr(sig),unsigned int *slen){
	EVP_PKEY *pkey;
	RSA *rsa = 0;
	int ok;
	CStr(keybuff,8*1024);
	BIO *Bp;
	const char *cbdata = pass;

	if( checkCrypt() < 0 ){
		return 0;
	}

	if( privRSA == NULL || privPEM == NULL || strcmp(privPEM,privkey)!=0 ){
		OPENSSL_add_all_algorithms_conf(); /* !!!! mandatory !!!! */
		if( data == 0 || *data == 0 ){
			FILE *fp;
			int rcc;
			fp = fopen(privkey,"r");
			if( fp == NULL ){
				fprintf(stderr,"# %s: Can't open\n",privkey);
				return 0;
			}
			rcc = fread(keybuff,1,sizeof(keybuff)-1,fp);
			fclose(fp);

			if( rcc <= 0 ){
				fprintf(stderr,"# %s: Can't read\n",privkey);
				return 0;
			}
			keybuff[rcc] = 0;
			data = keybuff;
		}


		Bp = BIO_new(BIO_s_mem());
		BIO_puts(Bp,(char*)data);
		pkey = NULL;
		ERR_load_crypto_strings();
		ENGINE_load_builtin_engines();
/*
		pkey = PEM_read_bio_PrivateKey(Bp,&pkey,pass_cb,cbdata);
*/
		if( cbdata == 0 )
			cbdata = "";
		pkey = PEM_read_bio_PrivateKey(Bp,&pkey,NULL,cbdata);
		if( pkey == 0 ){
			fprintf(stderr,"# %s: Can't load\n",privkey);
			return 0;
		}
		rsa = EVP_PKEY_get1_RSA(pkey);
		if( rsa == NULL ){
			fprintf(stderr,"# %s: BAD KEY\n",privkey);
			return 0;
		}
		privPEM = strdup(privkey);
		privRSA = rsa;
		TRACE("loaded %s",privkey);
	}
	if( sig == NULL ){
		return 1;
	}
	ok = signRSA(privRSA,md5,mlen,AVStr(sig),slen);
	return ok;
}
int verifyRSA(RSA *rsa,PCStr(md5),int mlen,PCStr(sig),unsigned int slen){
	int siz;
	int ok = 0;

	if( checkCrypt() < 0 )
		return 0;

	siz = RSA_size(rsa);
	ok = RSA_verify(NID_md5,(Uchar*)md5,mlen,(Uchar*)sig,slen,rsa);
	return ok;
}
static char *pubPEM;
static RSA *pubRSA;
int VerifyRSA(PCStr(pubkey),PCStr(data),PCStr(md5),int mlen,PCStr(sig),unsigned int slen){
	X509 *x509;
	EVP_PKEY *pkey;
	RSA *rsa;
	int ok;
	CStr(keybuff,8*1024);
	BIO *Bp;

	if( checkCrypt() < 0 )
		return 0;

	if( pubRSA == NULL || pubPEM == 0 || strcmp(pubPEM,pubkey) != 0 ){
		if( data == 0 || *data == 0 ){
			FILE *fp;
			int rcc;
			fp = fopen(pubkey,"r");
			if( fp == NULL ){
				fprintf(stderr,"# %s: Can't open\n",pubkey);
				return 0;
			}
			rcc = fread(keybuff,1,sizeof(keybuff)-1,fp);
			fclose(fp);
			if( rcc <= 0 ){
				fprintf(stderr,"# %s: Can't read\n",pubkey);
				return 0;
			}
			keybuff[rcc] = 0;
			data = keybuff;
		}
		Bp = BIO_new(BIO_s_mem());
		BIO_puts(Bp,(char*)data);
		pkey = NULL;
		x509 = PEM_read_bio_X509(Bp,NULL,NULL,NULL);
		if( x509 == NULL ){
			fprintf(stderr,"# %s: BAD CERT\n",pubkey);
			return 0;
		}
		pubPEM = strdup(pubkey);
		pkey = X509_get_pubkey(x509);
		rsa = EVP_PKEY_get1_RSA(pkey);
		pubRSA = rsa;
		TRACE("loaded %s",pubkey);
	}

	if( sig == NULL ){
		return 1;
	}
	ok = verifyRSA(pubRSA,md5,mlen,sig,slen);
	return ok;
}

static RSA *newRSApubkey(PCStr(key)){
	BIO *Bp;
	X509 *x509;
	EVP_PKEY *pkey;
	RSA *rsa;

	Bp = BIO_new(BIO_s_mem());
	BIO_puts(Bp,(char*)key);
	pkey = PEM_read_bio_PUBKEY(Bp,NULL,NULL,NULL);
	if( pkey == NULL )
		return 0;
	rsa = EVP_PKEY_get1_RSA(pkey);
	return rsa;
}
int pubDecyptRSA(PCStr(pubkey),int len,PCStr(enc),PVStr(dec)){
	RSA *rsa;
	int dlen;

	if( sslway_dl() <= 0 )
		return -1;
	rsa = newRSApubkey(pubkey);
	if( rsa == NULL ){
		return -1;
	}
	dlen = RSA_public_decrypt(len,(unsigned char*)enc,(unsigned char*)dec,rsa,RSA_PKCS1_PADDING);
	/*RSA_free(rsa);*/
	return dlen;
}

#ifndef ISDLIB
#include "randtext.c"
#endif

static double Start;
static double laps[32];
static const char *lapd[32];
static int lapx;
const char *SSLstage;
#define Lap(msg)  ((SSLstage=msg),(loglevel<LDEBUG)?0:((lapd[lapx]=msg),(laps[lapx++]=Time())))
static int nthcall;
static SSL_CTX *ctx_cache;
static int ctx_filter_id;
int (*SSL_fatalCB)(PCStr(mssg),...);
static char *SSLLIBS;

static void opt1(PCStr(arg)){
	if( strncmp(arg,"-vv",3) == 0 || strncmp(arg,"-vd",3) == 0 ){
		loglevel = LDEBUG;
	}else
	if( strncmp(arg,"-vu",3) == 0 ){
		loglevel = LTRACE;
	}else
	if( strncmp(arg,"-vt",3) == 0 ){
		loglevel = LERROR;
	}else
	if( strncmp(arg,"-vs",3) == 0 ){
		loglevel = LSILENT;
	}
}

static void loadSessions(SSL_CTX *ctx,SSL *ssl,int what);
static void saveSessions(SSL_CTX *ctx,SSL *ssl,int what);
#define XACC	0
#define XCON	1
#define XCTX	2
#define MASK_SCACHE  ((1<<XACC)|(1<<XCON))
#define MASK_CACHE   ((1<<XACC)|(1<<XCON)|(1<<XCTX))
static int do_cache = (1<<XACC)|(1<<XCTX);

static int tlsdebug;
#define DBG_SCACHE	1
#define DBG_SCACHEV	2
#define DBG_XCACHE	1

static int SNIopts;
#define SNI_MANDATORY	1
#define SNI_WARN	2

#define OPT_SHUT_SEND	0x0001
#define OPT_SHUT_WAIT	0x0002
#define OPT_SHUT_FLUSH	0x0004 /* flush Shutdown Alert on input if pending */
#define OPT_SHUT_OPTS	(OPT_SHUT_SEND|OPT_SHUT_WAIT|OPT_SHUT_FLUSH)
static int SSLopts[2] = {OPT_SHUT_FLUSH,OPT_SHUT_FLUSH};
static int SHUTwait[2] = {300,300}; /* milli-seconds */

typedef struct DGCtx *DGCp;
static scanListFunc scan_TLSCONF1(PCStr(conf),DGCp ctx){
	CStr(what,128);
	CStr(val,128);

	if( *conf == '-' ){
		opt1(conf);
		return 0;
	}
	fieldScan(conf,what,val);
	if( strcaseeq(what,"debug") ){
		tlsdebug |= DBG_SCACHE | DBG_XCACHE;
	}else
	if( strcaseeq(what,"shutdown") ){
		const char *op;
		int opts = OPT_SHUT_SEND;
		int wms = 0;
		if( op = strstr(val,"wait") ){
			opts = OPT_SHUT_OPTS;
			if( strchr("./",op[4]) && isdigit(op[5]) ){
				wms = atoi(op+5);
			}
		}
		if( streq(val,"none") ){
			SSLopts[XACC] &= ~OPT_SHUT_OPTS;
			SSLopts[XCON] &= ~OPT_SHUT_OPTS;
		}else
		if( streq(val,"flush") ){
			SSLopts[XACC] &= ~OPT_SHUT_OPTS;
			SSLopts[XACC] |=  OPT_SHUT_FLUSH;
			SSLopts[XCON] &= ~OPT_SHUT_OPTS;
			SSLopts[XCON] |=  OPT_SHUT_FLUSH;
		}else
		if( !strstr(val,"acc") && !strstr(val,"con") ){
			SSLopts[XACC] |= opts;
			SSLopts[XCON] |= opts;
			if( wms ) SHUTwait[XACC] = SHUTwait[XCON] = wms;
		}else
		if( strstr(val,"acc" ) ){
			SSLopts[XACC] |= opts;
			if( wms ) SHUTwait[XACC] = wms;
		}else
		if( strstr(val,"con" ) ){
			SSLopts[XCON] |= opts;
			if( wms ) SHUTwait[XCON] = wms;
		}
		if( streq(val,"vrfy") ){
		}
	}else
	if( strcaseeq(what,"sni") ){
		if( streq(val,"only") ) SNIopts |= SNI_MANDATORY;
		if( streq(val,"warn") ) SNIopts |= SNI_WARN;
	}else
	if( strcaseeq(what,"cache") ){
		if( streq(val,"no" ) ) do_cache = 0;
		if( streq(val,"do" ) ) do_cache = MASK_CACHE;
	}else
	if( strcaseeq(what,"xcache") ){
		if( streq(val,"no" ) ) do_cache &= ~(1 << XCTX);
		if( streq(val,"do" ) ) do_cache |=  (1 << XCTX);
	}else
	if( strcaseeq(what,"scache") ){
		int xmask = do_cache & ~MASK_SCACHE;
		if( *val == 0 )
			do_cache = (1 << XACC) | (1 << XCON);
		else{
			if( streq(val,"no" ) ) do_cache &= ~3;
			if( streq(val,"do" ) ) do_cache |= 3;
			if( streq(val,"acc") ) do_cache = (1 << XACC);
			if( streq(val,"con") ) do_cache = (1 << XCON);
		}
		do_cache |= xmask;
	}
	else
	if( strcaseeq(what,"libs") ){
		SSLLIBS = stralloc(val);
	}
	else
	if( strcaseeq(what,"context") ){
		ssid = (Uchar*)stralloc(val);
		ssid_len = strlen(val);
	}
	return 0;
}
void scan_TLSCONFs(DGCp ctx,PCStr(confs)){
	scan_commaListL(confs,0,scanListCall scan_TLSCONF1,ctx);
}

static const char *CERTF_PASS = "common.pas";
static const char *CERTF_ME   = "me.pem";
static const char *CERTF_TOSV = "to-sv.pem";    /* to be shown to servers */
static const char *CERTF_SVP  = "to-sv.%s.pem"; /* to be shown to the server %s */
static const char *CERTF_TOCL = "to-cl.pem";    /* to be shown to clients */
static const char *CERTF_CLP  = "to-cl.%s.pem"; /* to be shown to the client %s */
static const char *CERTF_SNI  = "sn.%s.pem";    /* SNI */
static const char *CERTF_NIF  = "if.%s.pem";    /* for the network interface */
static const char *CERTF_CLA  = "to-sv-if.%s.pem"; /* for outgoing net-if */
static const char *CERTF_SVA  = "sa.%s.pem";    /* for incoming net-if */

static const char *CERTF_SVCA = "ca-sv.pem";
static const char *CERTD_SVCA = "ca-sv";
static const char *CERTF_CLCA = "ca-cl.pem";
static const char *CERTD_CLCA = "ca-cl";

static char *certdir;
static int certdir_set;
void set_CERTDIR(PCStr(dir),int exp){
	syslog_DEBUG("--CERTS %d %s\n",exp,dir?dir:"");
	certdir = stralloc(dir);
	certdir_set = exp;
}

#define ISCLNT	0x0001
#define ISDIR	0x0002
#define GOTCERT	0x0004 /* don't try if the file is not found */
#define SRCHLIB	0x0008

int File_is(PCStr(path));
int fileIsdir(PCStr(path));
int File_isreg(PCStr(path));
static int findcert(PCStr(path),PVStr(xpath),int flags){
	IStr(dirpath,1024);
	int found = 0;

	if( path == 0 ){
		return 0;
	}
	if( certdir ){
		sprintf(dirpath,"%s/%s",certdir,path);
		VDEBUG("--CERTS ? %s",dirpath);
		if( (flags & ISDIR) )
			found = fileIsdir(dirpath);
		else	found = File_is(dirpath);
		/*
		else	found = File_isreg(dirpath);
		*/
		if( found ){
			if( xpath )
				strcpy(xpath,dirpath);
			VDEBUG("--CERTS ! %s",dirpath);
			return 1;
		}
		if( certdir_set ){
			return 0;
		}
	}
	if( found == 0 && (flags & SRCHLIB) ){
		found = LIBFILE_IS(path,BVStr(xpath));
	}
	return found;
}
#define LIBFILE_IS(path,xpath) findcert(path,xpath,SRCHLIB)

static int setcert1(SSL_CTX *ctx,PCStr(certfile),PCStr(keyfile),int clnt);
static int getcertdflt(SSL_CTX *ctx,int clnt){
	int gotdflt = 0;
	IStr(path,1024);
	int code;

	if( clnt )
		findcert(CERTF_TOSV,AVStr(path),0);
	else	findcert(CERTF_TOCL,AVStr(path),0);
	if( path[0] == 0 ){
		findcert(CERTF_ME,AVStr(path),0);
	}
	if( path[0] != 0 ){
		code = setcert1(ctx,path,path,clnt);
		VDEBUG("--CERTS got dflt %X [%s] code=%d",clnt,path,code);
		if( code == 0 ){
			gotdflt = 1;
		}
	}
	return gotdflt;
}

static void ssl_printf(SSL *ssl,int fd,PCStr(fmt),...)
{	CStr(buf,0x4000);
	VARGS(8,fmt);

	sprintf(buf,fmt,VA8);
	if( ssl )
		SSL_write(ssl,buf,strlen(buf));
	else{	IGNRETP write(fd,buf,strlen(buf)); }
}
static void sendIdent(PCStr(ident),PCStr(sb),PCStr(is)){
	const char *env;
	int fd;
	FILE *fp;
	if( env = getenv("CFI_IDENT") ){
		if( '0' <= env[0] && env[0] < '9' ){
			fd = atoi(env);
			if( fp = fdopen(dup(fd),"w") ){
				fprintf(fp,"Ident: %s\r\n",ident);
				fprintf(fp,"Subject: %s\r\n",sb);
				fprintf(fp,"Issuer: %s\r\n",is);
				fclose(fp);
			}
		}
	}
}
static void ssl_prcert(SSL *ssl,int show,SSL *outssl,int outfd,PCStr(what))
{	X509 *peer;
	CStr(subjb,256);
	const char *sb;
	CStr(issrb,256);
	const char *is;
	const char *dp;
	CStr(ident,256);

	ident[0] = 0;
	if( peer = SSL_get_peer_certificate(ssl) ){
		sb = X509_NAME_oneline(X509_get_subject_name(peer),subjb,sizeof(subjb));
		is = X509_NAME_oneline(X509_get_issuer_name(peer),issrb,sizeof(issrb));
		if( show ){
			ssl_printf(outssl,outfd,
				"##[SSLway: %s's certificate]\r\n",what);
			ssl_printf(outssl,outfd,"## Subject: %s\r\n",sb);
			ssl_printf(outssl,outfd,"## Issuer: %s\r\n",is);
		}
		ERROR("%s's cert. = **subject<<%s>> **issuer<<%s>>",what,sb,is);
		if( dp = (char*)strcasestr(sb,"/emailAddress=") )
			wordscanY(dp+14,AVStr(ident),sizeof(ident),"^/");
		else
		if( dp = (char*)strcasestr(sb,"/email=") )
			wordscanY(dp+7,AVStr(ident),sizeof(ident),"^/");
		else	strcpy(ident,"someone");
		X509_free(peer);
	}else{
		TRACE("%s's cert. = NONE",what);
		strcpy(ident,"anonymous");
		sb = "";
		is = "";
	}
	sendIdent(ident,sb,is);
	if( stdctl ){
		fprintf(stdctl,"CFI/1.0 200- Ident:%s\r\n",ident);
		fprintf(stdctl,"CFI/1.0 200 Certificate:%s//%s\r\n",sb,is);
		fflush(stdctl);
	}
}
static void eRR_print_errors_fp(FILE *fp)
{	int code;
	const char *strp;
	CStr(str,1024);
	const char *file;
	const char *line;
	const char *opttxt;

	if( isWindows() ){
		/* OpenSSL-0.9.7c on Win32 aborts in ERR_print_errors_fp() */
		while( code = ERR_get_error() ){
			strp = ERR_error_string_n(code,str,sizeof(str));
			file = "";
			line = "";
			opttxt = "";
			ERROR("SSL-ERRCODE: %X\r\n%d:%s:%s:%s:%s",code,getpid(),
				str,file,line,opttxt);
		}
	}else{
		ERR_print_errors_fp(fp);
	}
}
#undef	ERR_print_errors_fp
#define	ERR_print_errors_fp	eRR_print_errors_fp

/* new-111110a to show the current cipher of the SSL connection */
static int showCurrentCipher(SSL *ssl){
	void *sc;
	IStr(desc,256);
	const char *descp;

	if( sc = SSL_get_current_cipher(ssl) ){
		if( descp = SSL_CIPHER_description(sc,desc,sizeof(desc)) ){
			DEBUG("-- CIPHER: %s",desc);
			return 0;
		}
	}
	DEBUG("ERROR: Failed getting CIPHER_ description");
	ERR_print_errors_fp(stderr);
	return -1;
}

static void clearCache(SSL_CTX *ctx,SSL *ssl,int what);
static void set_vhost(SSL *conSSL,SslEnv *env);
static SSL *ssl_conn(SSL_CTX *ctx,int confd,SslEnv *env)
{	SSL *conSSL;

	Lap("ssl_conn() start");
	conSSL = SSL_new(ctx);
	set_vhost(conSSL,env);
/*
	loadSessions(ctx,conSSL);
*/
	loadSessions(ctx,conSSL,XCON);

	SSL_set_connect_state(conSSL);
	SSL_set_fd(conSSL,SocketOf(confd));
	Lap("before connect");
	if( SSL_connect(conSSL) < 0 ){
		ERROR("connect failed");
		ERR_print_errors_fp(stderr);
		if( SSL_fatalCB ){
			(*SSL_fatalCB)("ssl_conn() failed\n");
		}
		/* the the failure could be caused bya broken cache,
		 * so it should be cleared...
		 */
		clearCache(ctx,conSSL,XCON);
		return NULL;
	}else{
		Lap("after connect");
		saveSessions(ctx,conSSL,XCON);
		TRACE("connected");
		showCurrentCipher(conSSL);
		return conSSL;
	}
}

static SSL *ssl_acc(SSL_CTX *ctx,int accfd)
{	SSL *accSSL;

	Lap("ssl_acc() start");
	/*
	loadSessions(ctx,NULL);
	*/
	loadSessions(ctx,NULL,XACC);
	accSSL = SSL_new(ctx);
	SSL_set_accept_state(accSSL);
	SSL_set_fd(accSSL,SocketOf(accfd));
	SSL_set_fd(accSSL,SocketOf(accfd));
	Lap("before accept");
	if( SSL_accept(accSSL) < 0 ){
		ERROR("accept failed");
		ERR_print_errors_fp(stderr);
		/*
		9.5.7 don't try writing to the non-established conn. (5.3.3)
		ssl_printf(accSSL,0,"SSLway: accept failed\n");
		*/
		if( SSL_fatalCB ){
			(*SSL_fatalCB)("ssl_acc() failed\n");
		}
		return NULL;
	}else{
		Lap("after accept");
		saveSessions(ctx,accSSL,XACC);
		TRACE("accepted");
		showCurrentCipher(accSSL);
		return accSSL;
	}
}
static int nodefaultCA(PCStr(file)){
	IStr(xpath,1024);
	refQStr(dp,xpath);
	if( file ){
		strcpy(xpath,file);
		if( dp = strtailstr(xpath,".pem") ){
			strcpy(dp,".nodefault");
			if( File_is(xpath) ) return 1;
		}
		strcat(xpath,"/nodefault");
		if( File_is(xpath) ) return 2;
	}
	return 0;
}
static void ssl_setCAs(SSL_CTX *ctx,PCStr(file),PCStr(dir))
{	CStr(xfile,1024);
	CStr(xdir,1024);

	if( LIBFILE_IS(file,AVStr(xfile)) ) file = xfile;
	if( findcert(dir,AVStr(xdir),ISDIR) ) dir = xdir;
	/*
	if( LIBFILE_IS(dir, AVStr(xdir))  ) dir = xdir;
	*/

	if( file ){
		if( SSL_CTX_load_verify_locations(ctx,file,0) ){
			TRACE("CAs = OK CAfile[%s]",file);
		}else{
			ERROR("CAs not found or wrong: CAfile[%s]",file);
			ERR_print_errors_fp(stderr);
		}
	}
	if( dir ){
		if( SSL_CTX_load_verify_locations(ctx,0,dir) ){
			TRACE("CAs = OK CApath[%s]",dir);
		}else{
			ERROR("CAs not found or wrong: CApath[%s]",dir);
			ERR_print_errors_fp(stderr);
		}
	}
	/*
	if( file || dir ){
		if( SSL_CTX_load_verify_locations(ctx,file,dir) ){
			TRACE("CAs = OK [%s][%s]",
				file?file:"(NULL)",dir?dir:"(NULL)");
		}else{
			ERROR("CAs not found or wrong: [%s][%s]",
				file?file:"(NULL)",dir?dir:"(NULL)");
			ERR_print_errors_fp(stderr);
		}
	}
	*/
	if( nodefaultCA(file) || nodefaultCA(dir) ){
		TRACE("CAs = no DEFAULT");
	}else{
		if( SSL_CTX_set_default_verify_paths(ctx) ){
			TRACE("CAs = OK, set the DEFAULT");
		}else{
			ERROR("CAs wrong DEFAULT");
			ERR_print_errors_fp(stderr);
		}
	}
	return;

	if( !SSL_CTX_load_verify_locations(ctx,file,dir)
	 || !SSL_CTX_set_default_verify_paths(ctx) ){
		if( SSL_fatalCB ){
			(*SSL_fatalCB)("ssl_setCAs() failed\n");
		}
		ERROR("CAs not found or wrong: [%s][%s]",
			file?file:"",dir?dir:"");
	}else{
		TRACE("CAs = [%s][%s]",file?file:"",dir?dir:"");
	}
}

typedef struct {
  const char	*c_cert;	/* cetificate file */
  const char	*c_key;		/* private key */
} CertKey1;
typedef struct {
	CertKey1 v_ck[8]; /**/
	int	 v_Ncert;
	int	 v_Nkey;
} CertKeyV;
typedef struct {
	CertKeyV x_certkey;
  const char	*x_pass;	/* to decrypt the cert */
  const char	*x_CApath;	/* CA's certificates */
  const char	*x_CAfile;	/* A CA's certificate */
	int	 x_do_SSL;	/* use SSL */
	int	 x_do_STLS;	/* enable STARTTLS */
	int	 x_nego_FTPDATA;
	int	 x_verify;
	int	 x_peeraddr;
	int	 x_sslver;
	int	 x_sslnover;
	double   x_Start;
	int	 x_Ready;
} SSLContext;

static const char sv_cert_default[] = "server-cert.pem";
static const char sv_key_default[] = "server-key.pem";
static const char sv_certkey_default[] = "server.pem";
static const char cl_cert_default[] = "client-cert.pem";
static const char cl_key_default[] = "client-key.pem";
static const char cl_certkey_default[] = "client.pem";
static const char *stls_proto;

static SSLContext sslctx[2] = {
	{ { {sv_cert_default, sv_key_default} } },
	{ { {cl_cert_default, cl_key_default} } },
};
static int   acc_bareHTTP = 0;
static int   verify_depth = -1;
static int   do_showCERT = 0;
static const char *cipher_list = NULL;

#define sv_Start	sslctx[XACC].x_Start
#define sv_Ready	sslctx[XACC].x_Ready
#define cl_Start	sslctx[XCON].x_Start
#define cl_Ready	sslctx[XCON].x_Ready

#define sv_Cert		sslctx[XACC].x_certkey
#define sv_Ncert	sslctx[XACC].x_certkey.v_Ncert
#define sv_Nkey		sslctx[XACC].x_certkey.v_Nkey
#define sv_cert		sslctx[XACC].x_certkey.v_ck[sv_Ncert].c_cert
#define sv_key		sslctx[XACC].x_certkey.v_ck[sv_Nkey].c_key
#define sv_pass		sslctx[XACC].x_pass
#define cl_CApath	sslctx[XACC].x_CApath
#define cl_CAfile	sslctx[XACC].x_CAfile
#define do_accSSL	sslctx[XACC].x_do_SSL
#define do_accSTLS	sslctx[XACC].x_do_STLS
#define cl_vrfy		sslctx[XACC].x_verify
#define cl_nego_FTPDATA	sslctx[XACC].x_nego_FTPDATA
#define cl_addr		sslctx[XACC].x_peeraddr
#define cl_sslver	sslctx[XACC].x_sslver
#define cl_sslnover	sslctx[XACC].x_sslnover

#define cl_Cert		sslctx[XCON].x_certkey
#define cl_Ncert	sslctx[XCON].x_certkey.v_Ncert
#define cl_Nkey		sslctx[XCON].x_certkey.v_Nkey
#define cl_cert		sslctx[XCON].x_certkey.v_ck[cl_Ncert].c_cert
#define cl_key		sslctx[XCON].x_certkey.v_ck[cl_Nkey].c_key
#define cl_pass		sslctx[XCON].x_pass
#define sv_CApath	sslctx[XCON].x_CApath
#define sv_CAfile	sslctx[XCON].x_CAfile
#define do_conSSL	sslctx[XCON].x_do_SSL
#define do_conSTLS	sslctx[XCON].x_do_STLS
#define sv_vrfy		sslctx[XCON].x_verify
#define sv_nego_FTPDATA	sslctx[XCON].x_nego_FTPDATA
#define sv_addr		sslctx[XCON].x_peeraddr
#define sv_sslver	sslctx[XCON].x_sslver
#define sv_sslnover	sslctx[XCON].x_sslnover

#define ST_OPT		1
#define ST_FORCE	2
#define ST_AUTO		4 /* auto-detection of SSL by Client_Hello */
#define ST_SSL		8 /* AUTH SSL for FTP */

static SSL_CTX *ssl_new(int serv)
{	SSL_CTX *ctx;
	SSL_METHOD *meth;
	int sslver;
	int sslnover;

	ERR_clear_error();
	SSL_library_init();
	SSL_load_error_strings();

	meth = 0;
	if( sslver = serv ? cl_sslver : sv_sslver ){
		switch( sslver ){
			case 1:
				if( serv )
					meth = SSLv2_server_method();
				else	meth = SSLv2_client_method();
				break;
			case 2:
				if( serv )
					meth = SSLv3_server_method();
				else	meth = SSLv3_client_method();
				break;
			case 3:
				if( serv )
					meth = SSLv23_server_method();
				else	meth = SSLv23_client_method();
				break;
			case 4:
				if( serv )
					meth = TLSv1_server_method();
				else	meth = TLSv1_client_method();
				break;
		}
		if( meth == 0 ){
			ERROR("no method for %X",sslver);
		}
	}
	if( meth == 0 ){
		if( serv )
			meth = SSLv23_server_method();
		else	meth = SSLv23_client_method();
	}
	ctx = SSL_CTX_new(meth);

	if( ctx )
	if( sslnover = serv ? cl_sslnover : sv_sslnover ){
		int opts = 0;
		switch( sslnover ){
			case 1: opts |= SSL_OP_NO_SSLv2; break;
			case 2: opts |= SSL_OP_NO_SSLv3; break;
			case 3: opts |= SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3; break;
		}
		SSL_CTX_ctrl(ctx,SSL_CTRL_OPTIONS,opts,NULL);
	}
	return ctx;
}
static void passfilename(PCStr(keyfile),PVStr(passfile))
{	refQStr(dp,passfile); /**/

	strcpy(passfile,keyfile);
	dp = strrchr(passfile,'.');
	strcpy(dp,".pas");
	if( !File_is(passfile) ){
		if( dp = strrpbrk(passfile,"/\\") )
			dp++;
		else	dp = passfile;
		strcpy(dp,CERTF_PASS);
	}
}
static int Freadline(PCStr(path),PVStr(line),int size)
{	FILE *fp;
	int rcc;
	const char *dp;

	fp = fopen(path,"r");
	if( fp == NULL )
		return -1;

	if( 0 < (rcc = fread((char*)line,1,QVSSize(line,size),fp)) )
		setVStrEnd(line,rcc);
	else	setVStrEnd(line,0);
	fclose(fp);
	if( dp = strpbrk(line,"\r\n") )
		truncVStr(dp);
	return strlen(line);
}
static void scanpass(PCStr(arg))
{	const char *file;
	CStr(path,1024);
	const char *pass;
	CStr(passb,128);

	if( strncmp(arg,"file:",5) == 0 ){
		file = arg+5;
		if( LIBFILE_IS(file,AVStr(path)) )
			file = path;
		passb[0] = 0;
		Freadline(file,AVStr(passb),sizeof(passb));
		pass = passb;
	}else
	if( strncmp(arg,"pass:",5) == 0 ){
		pass = arg + 5;
	}else{
		ERROR("Usage: -pass { file:path | pass:string }");
		return;
	}
	if( pass[0] ){
		sv_pass = cl_pass = strdup(pass);
	}
}

unsigned int _inet_addrV4(PCStr(cp));
static void setaddrs(){
	const char *env;
	cl_addr = 0;
	sv_addr = 0;
	if( env = getenv("REMOTE_ADDR") ){
		cl_addr = _inet_addrV4(env);
	}
	if( env = getenv("SERVER_ADDR") ){
		sv_addr = _inet_addrV4(env);
	}
}

void msleep(int);
static int CFI_Lock(PCStr(wh),int rw){
	int rcode;
	int ri;
	double St = Time();

	/* it should be sharedLock() for read, if not for fseek/fread/fwrite
	 * but for memory-mapped read/write
	 */
	if( CFI_exclusiveLock() == 0 ){
		return 0;
	}
	for( ri = 0; ri < 20; ri++ ){
		msleep(1);
		if( CFI_exclusiveLock() == 0 ){
			DEBUG("%s cache lock OK %d (%.3f)",wh,ri+1,Time()-St);
			return 0;
		}
	}
	ERROR("%s cache lock NG %d (%.3f)",wh,ri+1,Time()-St);
	return -1;
}
static int saveContext(SSL_CTX *ctx,SSL *ssl,int ac,char *av[]){
	X509 *cert;
	EVP_PKEY *ekey;
	unsigned char tmp[8*1024];
	unsigned char *pp; /**/
	int len;
	FILE *fp;

	if( do_cache == 0 )
		return -1;
	if( (do_cache & (1 << XCTX)) == 0 )
		return -1;

	if( cert = SSL_get_certificate(ssl) ){
		if( (ekey = SSL_get_privatekey(ssl)) ){
			if( (cert = SSL_get_certificate(ssl)) ){
				if( CFI_Lock("saveContext",1) != 0 ){
					ERROR("ERROR: can't lock saveContext");
					return -1;
				}
				if( (fp = CFI_fopenShared("r+")) ){
					fprintf(fp,"%s\n",CFI_FILTER_ID());

					len = i2d_X509(cert,NULL);
					if( sizeof(tmp) <= len ){
						ERROR("CERT too large %d/%d\n",
							len,sizeof(tmp));
						goto CEXIT;
					}
					pp = tmp;
					len = i2d_X509(cert,&pp);
					fwrite(&len,1,sizeof(len),fp);
					fwrite(tmp,1,len,fp);

					len = i2d_PrivateKey(ekey,NULL);
					if( sizeof(tmp) <= len ){
						ERROR("PKEY too large %d/%d\n",
							len,sizeof(tmp));
						goto CEXIT;
					}
					pp = tmp;
					len = i2d_PrivateKey(ekey,&pp);
					fwrite(&len,1,sizeof(len),fp);
					fwrite(tmp,1,len,fp);

					fclose(fp);
					CFI_unLock();
					Lap("saveContext OK");
					return 0;
				}
			CEXIT:
				fclose(fp);
				CFI_unLock();
				return -1;
			}
		}
	}
	return -1;
}

static int loadContext(SSL_CTX *ctx,int ac,char *av[]){
	FILE *fp;
	CStr(fid,64);
	const char *dp;
	X509 *cert;
	EVP_PKEY *pkey;
	unsigned CStr(buf,4096);
	unsigned char *pp; /**/
	int len;
	double start = Time();

	if( do_cache == 0 )
		return -1;
	if( (do_cache & (1 << XCTX)) == 0 )
		return -1;
	if( CFI_Lock("loadContext",0) != 0 ){
		ERROR("ERROR: locking cache to load context failed");
		return -1;
	}

	fp = CFI_fopenShared("r");
	if( fp == NULL )
		return -1;

	fgets(fid,sizeof(fid),fp);
	if( dp = strchr(fid,'\n') )
		truncVStr(dp);
	if( strcmp(fid,CFI_FILTER_ID()) != 0 ){
		goto CEXIT;
	}
	len = -1;
	IGNRETP fread(&len,1,sizeof(len),fp);
	if( len <= 0 || sizeof(buf) < len ){
		ERROR("loadContext len=%d",len);
		goto CEXIT;
	}
	IGNRETP fread(buf,1,len,fp);
	pp = (unsigned char*)buf;
	cert = d2i_X509(NULL,&pp,len);

	len = -1;
	IGNRETP fread(&len,1,sizeof(len),fp);
	if( len <= 0 || sizeof(buf) < len ){
		goto CEXIT;
	}
	IGNRETP fread(buf,1,len,fp);
	pp = (unsigned char*)buf;
	pkey = d2i_PrivateKey(EVP_PKEY_RSA,NULL,&pp,len);

	fclose(fp);
	CFI_unLock();

	if( SSL_CTX_use_certificate(ctx,cert) ){
		if( SSL_CTX_use_PrivateKey(ctx,pkey) ){
			if( SSL_CTX_check_private_key(ctx) ){
				if( tlsdebug & DBG_SCACHE ){
					fprintf(stderr,"[%d] %s loaded\n",
						getpid(),"CTX");
				}
				Lap("loadContext OK");
				return 0;
			}
		}
	}
	return -1;
CEXIT:
	fclose(fp);
	CFI_unLock();
	return -1;
}

typedef struct {
	int	c_size;
	int	c_nent;
	int	c_pid;
} SessionCache;

typedef struct {
 unsigned char	s_what;
 unsigned char  s_flags;
 unsigned short	s_leng;
 unsigned int	s_date;
 unsigned int	s_svaddr;	/* IPv4 addr. of the server */
 unsigned int	s_claddr;	/* IPv4 addr. of the client */
 int s_ver;
 MStr(s_sid,32);
} Session;
/* using IP address is not good for a multi-homed server or a client
 * behind proxies ...
 */

#define SC_MAX		32
#define SC_ESIZE	2048
#define SC_BSIZE	(SC_ESIZE-sizeof(Session))
#define SC_BASE		0x04000
#define SC_XBASE	0x10000

typedef struct {
	Session	x_sess;
 unsigned MStr(x_buff,SC_BSIZE);
} SessionCtx;

static SessionCache scache;
static Session sess_cache[SC_MAX];
static int sess_cached;
static int sess_hits;

static int loadScache(FILE *fp,int what){
	int rcc;

	scache.c_nent = -1;
	scache.c_size = -1;
	scache.c_pid = 0;

	fseek(fp,SC_BASE,0);
	rcc = fread(&scache,1,sizeof(scache),fp);

	if( rcc != sizeof(scache)
	 || scache.c_size <= 0
	 || sizeof(sess_cache) < scache.c_size
	){
		if( rcc != 0 ){
		ERROR("ERROR[%s] bad session cache size:%X/%X[%X] %X/%d/%X",
			what==XACC?"FCL":"FSV",
			scache.c_nent,scache.c_size,scache.c_pid,
			SC_BASE,rcc,ftell(fp));
		}
		return -1;
	}
	if( scache.c_pid == getpid() ){
		/* needless to reload ... */
	}
	rcc = fread(sess_cache,1,scache.c_size,fp);
	if( rcc < sizeof(Session) ){
		return -1;
	}
	if( (rcc/sizeof(Session))*sizeof(Session) != rcc ){
		return -1;
	}
	sess_cached = rcc / sizeof(Session);
	return sess_cached;
}

static void loadSessions(SSL_CTX *ctx,SSL *ssl,int what){
	FILE *fp;
	double start = Time();
	int nsess;
	int si;
	int ncon;
	int nacc;
	double Start;

	if( do_cache == 0 )
		return;
	if( (do_cache & (1 << what)) == 0 )
		return;
	if( CFI_Lock("loadSession",0) != 0 ){
		ERROR("ERROR[%s] locking cache to load session failed",
			what==XACC?"FCL":"FSV");
		return;
	}

	Start = Time();
	fp = CFI_fopenShared("r");
	if( fp == NULL ){
		return;
	}

	nacc = 0;
	ncon = 0;
	nsess = loadScache(fp,what);
	if( nsess <= 0 )
	{
		goto CEXIT;
	}

	for( si = 0; si < nsess; si++ ){
		Session *Sp;
		int cwhat;
		int len;
		int xlen;
		int rcc;
		SessionCtx scx;
		SSL_SESSION *sess;
		unsigned char *sp; /**/
		SSL_SESSION *s;

		Sp = &sess_cache[si];
		cwhat = Sp->s_what;
		len = Sp->s_leng;
		xlen = sizeof(Session) + len;
		if( len <= 0 || sizeof(SessionCtx) < xlen ){
			ERROR("loadSession[%d] FATAL len=%X<%X %X/%X",si,
				sizeof(SessionCtx),xlen,
				Sp->s_what,Sp->s_ver);
			continue;
		}
		fseek(fp,SC_XBASE+si*SC_ESIZE,0);
		rcc = fread(&scx,1,xlen,fp);

		if( rcc != xlen ){
			continue;
		}
		if( len != scx.x_sess.s_leng ){
			continue;
		}
		if( bcmp(scx.x_sess.s_sid,Sp->s_sid,sizeof(Sp->s_sid)) != 0 ){
			continue;
		}
		sp = (unsigned char*)scx.x_buff;

		s = SSL_SESSION_new();
		sess = d2i_SSL_SESSION(&s,&sp,len);
		if( sess == 0 ){
			continue;
		}
		if( what == XCON && cwhat == XCON ){
			if( Sp->s_svaddr == sv_addr )
			if( Sp->s_claddr == cl_addr ){
				SSL_set_session(ssl,sess);
				ncon++;
				break;
			}
		}else
		if( what == XACC && cwhat == XACC ){
			/* it should be callback ... */
			if( Sp->s_svaddr == 0 || Sp->s_svaddr == sv_addr )
			if( Sp->s_claddr == cl_addr ){
				nacc++;
				SSL_CTX_add_session(ctx,sess);
			}
		}
	}

CEXIT:
	fclose(fp);
	CFI_unLock();
	if( ncon || nacc ){
		Lap("loadSession OK");
	}else{
		Lap("loadSession NONE");
	}
	ERROR("%X loadSession %.6f (%d %d) / %d",getthreadid(),
		Time()-Start,ncon,nacc,nsess);
}

int strtoHex(PCStr(str),int len,PVStr(out),int siz);
#define toHex(bi,sz,xb) strtoHex((char*)bi,sz,AVStr(xb),sizeof(xb))

static void saveSessionsA(SSL_CTX *ctx,SSL *ssl,int what);
FILE *CFI_LockFp();
static void saveSessions(SSL_CTX *ctx,SSL *ssl,int what){
	FILE *lkfp;
	if( (do_cache & (1 << what)) == 0 )
		return;
	if( lkfp = CFI_LockFp() ){
		flockfile(lkfp);
		saveSessionsA(ctx,ssl,what);
		funlockfile(lkfp);
	}else{
		saveSessionsA(ctx,ssl,what);
	}
}
static void saveSessionsA(SSL_CTX *ctx,SSL *ssl,int what){
	FILE *fp;
	SSL_SESSION *sess;
	unsigned char *sp; /**/
	unsigned char sbuf[SC_BSIZE];
	int len;
	double start;
	int si;
	int wcc;
	int nsess;
	int nsi;
	Session *Sp;
	SessionCtx scx;
	unsigned int oldest;
	int oi;
	SessionHead *shp;
	CStr(sib,128);
	int sc = sess_cached;
	int off1;

	if( do_cache == 0 )
		return;
	if( (do_cache & (1 << what)) == 0 ){
		return;
	}
	/*
	 * don't save the session if currenst session is reused
	 */

	if( CFI_Lock("saveSession",1) != 0 ){
		ERROR("ERROR[%s] locking cache to save session failed",
			what==XACC?"FCL":"FSV");
		return;
	}
	start = Time();
	fp = CFI_fopenShared("r+");
	if( fp == NULL ){
		return;
	}

	loadScache(fp,what);
	sess = SSL_get_session(ssl);
	shp = (SessionHead*)sess;
	if( sess == NULL ){
		ERROR("## no session to be saved");
		goto CEXIT;
	}
	if( shp->ssl_version == 2 ){
		DEBUG("## don't cache the session of SSL2");
		goto CEXIT;
	}

	len = i2d_SSL_SESSION(sess,NULL);
	if( len == 0 ){
		ERROR("## no session content to be saved");
		goto CEXIT;
	}
	if( sizeof(sbuf) <= len ){
		ERROR("## SESSION not saved (%d > %d)",len,
			sizeof(sbuf));
		goto CEXIT;
	}
	sp = sbuf;
	len = i2d_SSL_SESSION(sess,&sp);

	if( SC_BSIZE < len ){
		ERROR("Session not saved (DER Length: %d > %d)",len,SC_BSIZE);
		goto CEXIT;
	}

	oi = 0;
	oldest = 0xFFFFFFFF;

	if( sess_cached ){
	    for( si = 0; si < sess_cached; si++ ){
		Sp = &sess_cache[si];
		if( bcmp(shp->session_id,Sp->s_sid,shp->session_id_length)==0 ){
			if( tlsdebug & DBG_SCACHE ){
				toHex(Sp->s_sid,32,sib);
				Xstrcpy(DVStr(sib,40),"...");
				fprintf(stderr,"[%d] %s scHIT %s\n",
					getpid(),what==XACC?"ACC":"CON",sib);
			}
			DEBUG("session HIT %X/%d/%d %X/%d",
				shp->ssl_version,shp->session_id_length,len,
				Sp->s_ver,Sp->s_leng);
			sess_hits++;
			goto CEXIT;
		}
		if( sess_cache[si].s_date < oldest ){
			oldest = sess_cache[si].s_date;
			oi = si;
		}
	    }
	}

	nsess = sess_cached;
	if( nsess == elnumof(sess_cache) ){
		/* should search last used, least recently hit ... */
		nsi = oi;
	}else{
		nsi = nsess++;
	}
	Sp = &sess_cache[nsi];
	Sp->s_leng = len;
	Sp->s_what = what;
	Sp->s_date = time(NULL);
	Sp->s_svaddr = sv_addr;
	Sp->s_claddr = cl_addr;
	Sp->s_ver = shp->ssl_version;
	Bcopy(shp->session_id,Sp->s_sid,shp->session_id_length);

	fseek(fp,SC_BASE,0);

off1 = SC_BASE;
if( ftell(fp) != off1 )
ERROR("saveSession[%d] FATAL-A %d %d",nsi,off1,ftell(fp));

	scache.c_nent = nsess;
	scache.c_size = nsess * sizeof(Session);
	scache.c_pid = getpid();
	fwrite(&scache,1,sizeof(scache),fp);
	fflush(fp);

off1 = SC_BASE + sizeof(scache);
if( ftell(fp) != off1 )
ERROR("saveSession[%d] FATAL-B %d %d",nsi,off1,ftell(fp));

	wcc = fwrite(sess_cache,1,scache.c_size,fp);
	fflush(fp);
off1 += scache.c_size;
if( ftell(fp) != off1 )
ERROR("saveSession[%d] FATAL-C %d %d",nsi,off1,ftell(fp));

	fseek(fp,SC_XBASE+nsi*SC_ESIZE,0);
	scx.x_sess = *Sp;
	Bcopy(sbuf,scx.x_buff,len);
	wcc = fwrite(&scx,1,sizeof(Session)+len,fp);
	fflush(fp);
off1 = SC_XBASE+nsi*SC_ESIZE + sizeof(Session)+len;
if( ftell(fp) != off1 )
ERROR("saveSession[%d] FATAL-D %d %d",nsi,off1,ftell(fp));

	fclose(fp);
	CFI_unLock();

	if( tlsdebug & DBG_SCACHE ){
		toHex((char*)shp->session_id,shp->session_id_length,sib);
		Xstrcpy(DVStr(sib,40),"...");
		fprintf(stderr,"[%d] %s scPUT %s %d/%d\n",
			getpid(),what==XACC?"ACC":"CON",sib,wcc,nsess);
	}
	Lap("saveSession OK");
	return;

CEXIT:
	fclose(fp);
	CFI_unLock();
}
int Ftruncate(FILE *fp,FileSize offset,int whence);
int file_size(int fd);
static void clearCache(SSL_CTX *ctx,SSL *ssl,int what){
	FILE *lkfp;
	FILE *fp;
	IStr(msg,1024);
	int osize ;

	if( lkfp = CFI_LockFp() ){
	    flockfile(lkfp);
	    if( CFI_Lock("clearCache",1) == 0 ){
		if( fp = CFI_fopenShared("r+") ){
			osize = file_size(fileno(fp));
			Ftruncate(fp,0,0);
			sprintf(msg,"## cleared the cache(%d) on %s error",
				osize,what==XCON?"CON":"ACC");
			ERROR("%s",msg);
			fprintf(stderr,"[%d] SSLway %s\n",getpid(),msg);
		}else{
		}
		CFI_unLock();
	    }
	    funlockfile(lkfp);
	}else{
	}
}

static int use_cert_chain(SSL_CTX *ctx,PCStr(certfile),int clnt){
	if( SSL_CTX_use_certificate_chain_file(ctx,certfile) ){
	}else{
		if( LTRACE <= loglevel )
		ERR_print_errors_fp(stderr);
		return 0;
	}
	return 1;
}
static int setcert1(SSL_CTX *ctx,PCStr(certfile),PCStr(keyfile),int clnt)
{	int code = 0;
	CStr(cwd,1024);
	CStr(xkeyfile,1024);
	CStr(xcertfile,1024);
	const char *dp;
	CStr(ykeyfile,1024);
	refQStr(yp,ykeyfile);
	CStr(passfile,1024);
	CStr(pass,128);
	int allin1 = 0;

	allin1 = streq(certfile,keyfile);
	if( LIBFILE_IS(keyfile,AVStr(xkeyfile)) )
		keyfile = xkeyfile;
	if( LIBFILE_IS(certfile,AVStr(xcertfile)) )
		certfile = xcertfile;
	if( clnt & GOTCERT ){
		if( !File_is(keyfile) && !File_is(certfile) )
			return -1;
		clnt &= GOTCERT;
	}

	pass[0] = 0;
	if( allin1 ){
		strcpy(ykeyfile,keyfile);
		if( yp = strrchr(ykeyfile,'.') ){
			strcpy(yp,"-key.pem");
			if( File_is(ykeyfile) ){
				keyfile = ykeyfile;
			}
		}
	}
	if( dp = strrchr(keyfile,'.') ){
		passfilename(keyfile,AVStr(passfile));
		if( 0 <= Freadline(passfile,AVStr(pass),sizeof(pass)) ){
			if( clnt )
				cl_pass = strdup(pass);
			else	sv_pass = strdup(pass);
		}
	}

	IGNRETS getcwd(cwd,sizeof(cwd));
	if( use_cert_chain(ctx,certfile,clnt) ){
		DEBUG("certchain loaded: %s",certfile);
	}else
	if( SSL_CTX_use_certificate_file(ctx,certfile,SSL_FILETYPE_PEM) ){
		DEBUG("certfile loaded: %s",certfile);
	}else{
		ERROR("certfile not found or wrong: %s [at %s]",certfile,cwd);
		code = -1;
	}
	if( SSL_CTX_use_RSAPrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) ){
		DEBUG("keyfile loaded: %s",keyfile);
	}else{
		ERROR("keyfile not found or wrong: %s [at %s]",keyfile,cwd);
		code = -1;
	}
	if( !SSL_CTX_check_private_key(ctx) ){
		ERROR("key does not match cert: %s %s",keyfile,certfile);
		code = -1;
	}
	return code;
}

typedef struct {
	SSL_CTX *cc_ctx;
	MStr(cc_domain,128);
} CTXC;
static CTXC ctxc[1]; /* should be on memmap */
#define ctx2		ctxc[0].cc_ctx
#define ctx2_domain	ctxc[0].cc_domain
static SSL_CTX *ssl_newsv();
#define SSL_TLSEXT_ERR_ALERT_WARNING 1
#define SSL_TLSEXT_ERR_OK 0
#define SSL_TLSEXT_ERR_ALERT_FATAL 2
#define SSL_TLSEXT_ERR_NOACK 3
static struct {
	MStr(s_name,128);
} TlsSni;
const char *tlssni(){
	return TlsSni.s_name;
}
static int get_vhost(SSL *ssl,int *ad,void *arg){
	const char *vhost;
	IStr(certd,256);
	IStr(certf,256);
	IStr(certv,256);
	IStr(xcert,1024);

	vhost = SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);
	TRACE("-- TLSxSNI: recv %s",vhost?vhost:"NULL");
	strcpy(TlsSni.s_name,vhost?vhost:"__none");
	if( vhost == 0 ){
		return SSL_TLSEXT_ERR_NOACK;
	}
	if( ctx2 == 0 ){
		ctx2 = ssl_newsv();
	}else
	if( ctx2_domain[0] && streq(ctx2_domain,vhost) ){
		ERROR("TLSxSNI: %s (reusing)",vhost);
		return SSL_TLSEXT_ERR_OK;
	}
	sprintf(certd,"cert/%s.pem",vhost);
	sprintf(certf,"cert_%s.pem",vhost);
	sprintf(certv,CERTF_SNI,vhost);
	if( findcert(certv,AVStr(xcert),0)
	 || LIBFILE_IS(certd,AVStr(xcert))
	 || LIBFILE_IS(certf,AVStr(xcert))
	){
		TRACE("-- TLSxSNI: %s [%s]",vhost,xcert);
		if( setcert1(ctx2,xcert,xcert,0) == 0){
			do_cache = 0;
			strcpy(ctx2_domain,vhost);
			ERROR("TLSxSNI: %s %s",vhost,xcert);
			SSL_set_SSL_CTX(ssl,ctx2);
			return SSL_TLSEXT_ERR_OK;
		}else{
		}
	}
	TRACE("-- TLSxSNI: %s NOT-FOUND",vhost);

	/* 9.8.2 (1) when acting as a MITM proxy, it is normal that there is
	 * no certificate for the server specified by the SNI from the client.
	 * (2) and if the client is a MITM proxy (not an origin HTTPS/SSL
	 * client), the SNI might be generated by CONNECT host:port rather
	 * than the original ClientHello/TLS.  In such case, the SNI is not
	 * intended by the origin-client and the client might not care the
	 * warning to the ClientHello with proxy-SNI.
	 * If this server returns OK or WARNING and the session is cached
	 * in the client (like older SSLway), and if this DeleGate restart
	 * withtout the cache, then the client will get the error
	 * "SSL3_GET_SERVER_HELLO:parse tlsext".
	 */
	if( SNIopts & SNI_MANDATORY ){
		TRACE("-- TLSxSNI: %s NOT-FOUND: FATAL",vhost);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
	if( SNIopts & SNI_WARN ){
		TRACE("-- TLSxSNI: %s NOT-FOUND: WARN",vhost);
	return SSL_TLSEXT_ERR_ALERT_WARNING;
	}
	TRACE("-- TLSxSNI: %s NOT-FOUND: DONT-CARED",vhost);
	return SSL_TLSEXT_ERR_NOACK;
}
static int got_vhost(SSL *ssl,int *ad,void *arg){
	const char *vhost;
	int type;
	int reu;
	vhost = SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);
	type = SSL_get_servername_type(ssl);
	reu = SSL_session_reused(ssl);
	if( type != -1 ){
		ERROR("-- TLSxSNI: sent ru=%d ty=%d nm=%s",reu,
			type,vhost?vhost:"");
		do_cache = 0;
	}
	return SSL_TLSEXT_ERR_OK;
}
static void set_vhost(SSL *conSSL,SslEnv *env){
	const char *vhost;
	if( (vhost = getv(env->se_av,"SNIHOST")) /* MOUNTed */
	 || (vhost = getenv("SERVER_HOST")) /* destination host */
	 || (vhost = getenv("SERVER_NAME")) /* incoming I.F. */
	){
		TRACE("-- TLSxSNI: send %s",vhost);
		SSL_set_tlsext_host_name(conSSL,vhost);
	}
}
int VSA_gethostname(int sock,PVStr(addr));
static void set_ifcert(SSL_CTX *ctx,int sock,int clnt){
	IStr(addr,128);
	IStr(nif,256);
	IStr(sva,256);
	IStr(path,256);

	if( 0 <= VSA_gethostname(sock,AVStr(addr)) ){
		sprintf(nif,CERTF_NIF,addr);
		if( clnt )
			sprintf(sva,CERTF_CLA,addr);
		else	sprintf(sva,CERTF_SVA,addr);
		DEBUG("-- net-if cert [%s] or [%s]",sva,nif);
		if( findcert(sva,AVStr(path),0)
		 || findcert(nif,AVStr(path),0)
		){
			DEBUG("-- net-if cert found [%s]",path);
			setcert1(ctx,path,path,clnt);
		}
	}
}
static int ssl_dfltCAs(SSL_CTX *ctx,int clnt){
	IStr(file,1024);
	IStr(cdir,1024);
	const char *pem;
	const char *dir;
	int vflags = 1;
	const char *ppem = 0;
	const char *pdir = 0;

	if( clnt ){
		dir = CERTD_CLCA;
		pem = CERTF_CLCA;
	}else{
		dir = CERTD_SVCA;
		pem = CERTF_SVCA;
	}

	if( findcert(pem,AVStr(file),0    ) ) ppem = file;
	if( findcert(dir,AVStr(cdir),ISDIR) ) pdir = cdir;
	if( ppem == 0 && pdir == 0 ){
		return 0;
	}
	ssl_setCAs(ctx,ppem,pdir);
	/*
	if( findcert(pem,AVStr(file),0) || findcert(dir,AVStr(cdir),ISDIR) ){ 
	}else{
		return 0;
	}
	ssl_setCAs(ctx,file[0]?file:NULL,cdir[0]?cdir:NULL);
	*/

	vflags = SSL_VERIFY_PEER
	       | SSL_VERIFY_CLIENT_ONCE
	       | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	if( clnt )
		cl_vrfy = vflags;
	else	sv_vrfy = vflags;
	verify_depth = -1;
	return 1;
}

static int cert_opts;
static const char *dflt_cert;
static const char *dflt_vkey;
void sslway_dflt_certkey(PCStr(cert),PCStr(vkey)){
	dflt_cert = cert;
	dflt_vkey = vkey;
}
int set_dfltcerts(SSL_CTX *ctx){
	X509 *cert;
	EVP_PKEY *pkey;
	CStr(file,128);
	int ok;
	BIO *Bp;

	if( dflt_cert == 0 || dflt_vkey == 0 )
		return -1;

	Bp = BIO_new(BIO_s_mem());
	BIO_puts(Bp,(char*)dflt_vkey);
	pkey = NULL;
	PEM_read_bio_RSAPrivateKey(Bp,&pkey,NULL,NULL);
	ok = SSL_CTX_use_RSAPrivateKey(ctx,(RSA*)pkey);
	if( !ok ){
		ERROR("-- pkey=%X %d",pkey,ok);
	}

	BIO_puts(Bp,(char*)dflt_cert);
	cert = NULL;
	PEM_read_bio_X509(Bp,&cert,NULL,NULL);
	ok = SSL_CTX_use_certificate(ctx,cert);
	if( !ok ){
		ERROR("-- cert=%X %d",cert,ok);
	}

	if( SSL_CTX_check_private_key(ctx) ){
		ERROR("-- Using Default Certificate");
		if( tlsdebug & DBG_XCACHE ){
			fprintf(stderr,"[%d] %s using default\n",
				getpid(),"CTX");
		}
		return 0;
	}else{
		return -1;
	}
}

static int setcerts(SSL_CTX *ctx,CertKeyV *certv,int clnt)
{	int certx;
	int code;
	CertKey1 *cert1;

	IStr(path,1024);
	if( findcert("dhparam.pem",AVStr(path),0)
	 || findcert("dhparam.der",AVStr(path),0)
	){
		BIO *Bp;
		DH *dh;
		DEBUG("-- loading DH PARAMS: %s",path);
		if( Bp = BIO_new_file(path,"r") ){
			if( dh = PEM_read_bio_DHparams(Bp,NULL,NULL,NULL) ){
				SSL_CTX_set_tmp_dh(ctx,dh);
				DH_free(dh);
				TRACE("-- loaded DH PARAMS: %s",path);
			}
			BIO_free(Bp);
		}
	}

	if( getcertdflt(ctx,clnt) ){
		clnt |= GOTCERT;
		VDEBUG("--CERTS setcerts clnt=%d ...",clnt);
	}

	for( certx = 0; certx <= certv->v_Ncert; certx++ ){
		cert1 = &certv->v_ck[certx];
		code = setcert1(ctx,cert1->c_cert,cert1->c_key,clnt);
		if( code != 0 )
		{
			if( clnt & GOTCERT ){
				return 0;
			}
			if( cert_opts == 0 ){
				/* if not specified explicitly */
				return set_dfltcerts(ctx);
			}
			if( SSL_fatalCB ){
				(*SSL_fatalCB)("bad cert/key: [%s][%s]\n",
					cert1->c_cert,cert1->c_key);
			}
			return code;
		}
	}
	return 0;
}

static RSA *tmprsa_key;
static RSA *tmprsa_callback(SSL *ctx,int exp,int bits)
{
	if( bits != 512 && bits != 1024 ){
		bits = 512;
	}
	if( tmprsa_key == NULL ){
		tmprsa_key = RSA_generate_key(bits,0x10001,NULL,NULL);
	}
	return tmprsa_key;
}
static int verify_callback(int ok,X509_STORE_CTX *ctx)
{	int err,depth;
	const char *errsym;
	X509 *cert;
	CStr(subjb,256);

	cert =   X509_STORE_CTX_get_current_cert(ctx);
	err =    X509_STORE_CTX_get_error(ctx);
	depth =  X509_STORE_CTX_get_error_depth(ctx);
	X509_NAME_oneline(X509_get_subject_name(cert),subjb,sizeof(subjb));
	errsym = X509_verify_cert_error_string(err);
	ERROR("depth=%d/%d ok=%d %d:\"%s\" %s",
		depth,verify_depth,ok,err,errsym,subjb);

	if( !ok ){
		if( depth <= verify_depth )
			ok = 1;
	}
	return ok;
}

#define SSL_ERROR_WANT_READ        2
#define SSL_ERROR_WANT_WRITE       3
#define SSL_ERROR_WANT_X509_LOOKUP 4

static int SSL_rdwr(int wr,SSL *ssl,void *buf,int siz)
{	int i,xcc,err;

	if( wr )
		xcc = SSL_write(ssl,buf,siz);
	else	xcc = SSL_read(ssl,buf,siz);
	if( xcc < 0 ){
		for( i = 0; i < 8; i++ ){
			err = SSL_get_error(ssl,xcc);
			DEBUG("SSL_%s()=%d ERR=%d",wr?"write":"read",xcc,err);

			if( err != SSL_ERROR_WANT_READ
			 && err != SSL_ERROR_WANT_WRITE
			 && err != SSL_ERROR_WANT_X509_LOOKUP
			)
			{
				if( LDEBUG <= loglevel ){
					ERR_print_errors_fp(stderr);
				}
				break;
			}

			if( wr )
				xcc = SSL_write(ssl,buf,siz);
			else	xcc = SSL_read(ssl,buf,siz);
			if( 0 <= xcc )
				break;
		}
	}
	return xcc;
}
#undef	SSL_read
#undef	SSL_write
#define SSL_read(ss,bf,sz)	SSL_rdwr(0,ss,bf,sz)
#define SSL_write(ss,bf,sz)	SSL_rdwr(1,ss,(char*)bf,sz)

/*
static void writes(PCStr(what),SSL *ssl,int confd,void *buf,int rcc)
*/
static int writes(PCStr(what),SSL *ssl,int confd,void *buf,int rcc)
{	int wcc = -9;
	int rem;

	rem = rcc;
	while( 0 < rem ){
		if( ssl )
			wcc = SSL_write(ssl,buf,rem);
		else	wcc = write(confd,buf,rem);
		if( wcc == rem )
			DEBUG("%s: %d/%d -> %d%s",what,rem,rcc,wcc,ssl?"/SSL":"");
		else	ERROR("%s? %d/%d -> %d%s",what,rem,rcc,wcc,ssl?"/SSL":"");
		if( wcc <= 0 )
			break;
		rem -= wcc;
	}
	if( rem != 0 ){
		porting_dbg("--E-SSLway %s: write(%d/%d,%d)=%d",
			what,SocketOf(confd),confd,rcc,wcc);
	}
	return rem;
}

static int nego_FTPDATAsv(SSL *accSSL,char buf[],int len);
static void nego_FTPDATAcl(SSL *conSSL,const char sbuf[],int len);

int SSLstart = 0;
int SSLready = -1;
int clearSSLready(int fd){
	int nf = 0;
	if( fd == cl_Ready ){
		cl_Ready = -1;
		nf |= 1;
	}
	if( fd == sv_Ready ){
		sv_Ready = -1;
		nf |= 2;
	}
	return nf;
}
static void syncReady(SSLwayCTX *Sc,PCStr(sync),int do_acc,int do_con){
	int sv,cl;
	int wcc;

	sv = sv_Ready;
	cl = cl_Ready;
	if( lTHREAD() ){
		if( do_acc && 0 <= sv )
			syslog_ERROR("-- SSLready[FCL]%X#%d[%d]>>[%d/%d] %s\n",
				Sc->ss_ftype,Sc->ss_fid,Sc->ss_ready,
				sv,SSLready,sync);
		if( do_con && 0 <= cl )
			syslog_ERROR("-- SSLready[FSV]%X#%d[%d]>>[%d/%d] %s\n",
				Sc->ss_ftype,Sc->ss_fid,Sc->ss_ready,
				cl,SSLready,sync);
	}
	if( 0 < Sc->ss_fid && Sc->ss_ftype && 0 <= Sc->ss_ready ){
		wcc = write(Sc->ss_ready,sync,1);
		return;
	}
	if( do_acc && 0 <= sv || do_con && 0 <= cl )
	if( 0 < Sc->ss_fid && Sc->ss_ftype && Sc->ss_ready < 0 ){
		/* 9.9.8 maybe it's reopened f.d. for another thread */
		if( lMULTIST() ){
			syslog_ERROR("-- SSLready[%s]%X#%d[%d]>>[%d/%d] %s!!\n",
				do_acc?"FCL":"FSV",
				Sc->ss_ftype,Sc->ss_fid,Sc->ss_ready,
				sv,SSLready,sync);
			return;
		}
	}
	if( do_acc && 0 <= sv ){ wcc = write(sv,sync,1); }
	if( do_con && 0 <= cl ){ wcc = write(cl,sync,1); }
}

static void ssl_relay(SSLwayCTX *Sc,SSL *accSSL,int accfd,SSL *conSSL,int confd)
{	int fdv[2],rfdv[2],nready,rcc,wcc;
	CStr(buf,8*1024);
	int relays = 0;
	int rem;
	int acnt = 0,ccnt = 0;
	int alen = 0,clen = 0;
	const char *ecase = "";

	fdv[0] = accfd;
	fdv[1] = confd;

	if( cl_nego_FTPDATA )
		nego_FTPDATAcl(conSSL,"",0);

	if( 0 <= sv_Ready || 0 <= cl_Ready ){
		syncReady(Sc,"READY",accSSL!=0,conSSL!=0);
		if( accSSL ) sv_Ready = -1;
		if( conSSL ) cl_Ready = -1;
	}

	for(;;){
		if( gotsigTERM("SSLway relayA") ){ /* 9.9.4 MTSS SSL thread */
			if( numthreads() && !ismainthread() ){
				thread_exit(0);
			}
			break;
		}
		relays++;
		nready = 0;
		rfdv[0] = rfdv[1] = 0;
		if( accSSL && SSL_pending(accSSL) ){
			rfdv[0] = 1;
			nready++;
		}
		if( conSSL && SSL_pending(conSSL) ){
			rfdv[1] = 1;
			nready++;
		}
		if( nready == 0 ){
			if( isWindows() )
			if( SocketOf(fdv[0]) <= 0 || SocketOf(fdv[1]) <= 0 ){
				porting_dbg("--E-SSLway relay(%d/%d,%d/%d)",
					SocketOf(fdv[0]),fdv[0],
					SocketOf(fdv[1]),fdv[1]
				);
				ecase = "Non-Socket";
				break;
			}

			if( lTHREAD() ){
				int i;
				for( i = 0; i < 10; i++ ){
					nready = PollIns(2000,2,fdv,rfdv);
					if( nready == 0 )
					ERROR("%s%s(%d)[%d,%d] ready=%d",
						accSSL?"[FCL]":"",
						conSSL?"[FSV]":"",
						i,fdv[0],fdv[1],nready);
					if( nready )
						break;
				}
			}
			if( nready == 0 )
			nready = PollIns(0,2,fdv,rfdv);
			if( gotsigTERM("SSLway relayB") ){
				if( numthreads() && !ismainthread() ){
					thread_exit(0);
				}
				break;
			}
			if( nready <= 0 )
			{
				ecase = "Non-Ready";
				break;
			}
		}

		rem = 0;
		if( rfdv[0] ){
			if( accSSL )
				rcc = SSL_read(accSSL,buf,sizeof(buf));
			else	rcc = read(accfd,buf,sizeof(buf));
			if( rcc <= 0 )
			{
				TRACE("C-S EOF from the client");
				ecase = "CS-EOS";
				break;
			}
			alen += rcc;
			acnt++;
			if( sv_nego_FTPDATA )
				rcc = nego_FTPDATAsv(accSSL,buf,rcc);
			rem +=
			writes("C-S",conSSL,confd,buf,rcc);
		}
		if( rfdv[1] ){
			if( conSSL )
				rcc = SSL_read(conSSL,buf,sizeof(buf));
			else	rcc = read(confd,buf,sizeof(buf));
			if( rcc <= 0 )
			{
				TRACE("S-C EOF from the server");
				ecase = "SC-EOS";
				break;
			}
			clen += rcc;
			ccnt++;
			if( cl_nego_FTPDATA )
				nego_FTPDATAcl(conSSL,buf,rcc);
			rem +=
			writes("S-C",accSSL,accfd,buf,rcc);
		}
		if( rem != 0 ){
			porting_dbg("--E-SSLway relay*%d failed: %d",
				relays,rem);
			ecase = "Write-Error";
			break;
		}
	}
	ERROR("%s S-C:%d/%d C-S:%d/%d %s",
		accSSL?"FCL":"FSV",clen,ccnt,alen,acnt,ecase);
}

/*
 * STARTTLS:
 *   RFC2487 SMTP
 *   RFC2595 IMAP and POP3
 *   RFC2228,draft-murray-auth-ftp-ssl-07 FTP
 */
static char *relay_opening(PCStr(proto),FILE *fs,FILE *tc,PVStr(buf),int bsize)
{	CStr(msgb,1024);

	for(;;){
		if( fgets(buf,bsize,fs) == NULL )
			return NULL;
		fputs(buf,tc);
		fflush(tc);

		if( proto != NULL )
			break;
		if( strncmp(buf,"220",3) == 0 ){
			if( buf[3] == '-' ){
				do {
					fgets(msgb,sizeof(msgb),fs);
					fputs(msgb,tc);
				} while( msgb[3] == '-' );
				fflush(tc);
			}
			if( strstr(buf,"FTP") )
				proto = "FTP";
			else
			proto = "SMTP";
			break;
		}else
		if( strncasecmp(buf,"+OK",3) == 0 ){
			proto = "POP3";
			break;
		}else
		if( strncasecmp(buf,"* OK",4) == 0 ){
			proto = "IMAP";
			break;
		}else{
			return NULL;
		}
	}
	return (char*)proto;
}
static int isinSSL(int fd)
{	unsigned char buf[6]; /**/
	int rcc,leng,type,vmaj,vmin;

	buf[0] = 0x7F;
	RecvPeek(fd,buf,1);
	if( (buf[0] & 0x80) || buf[0] < 0x20 ){
		ERROR("STARTTLS got binary [%X] from client",0xFF&buf[0]);
		if( buf[0] == 0x80 ){
			rcc = RecvPeek(fd,buf,5);
			ERROR("SSL Hello?%d [%X %d %d %d %d]",rcc,buf[0],
				buf[1],buf[2],buf[3],buf[4]);
			leng = (0x7F&buf[0]) << 8 | buf[1];
			type = buf[2];
			if( type == 1 ){ /* SSLv3 ClientHello */
				vmaj = buf[3];
				vmin = buf[4];
				return 1;
			}
		}
		else
		if( buf[0] == 22 ){ /* ConentType:handshake */
			rcc = RecvPeek(fd,buf,sizeof(buf));
			ERROR("SSL Hello?%d [%X %d %d %d %d]",rcc,buf[0],
				buf[1],buf[2],buf[3]<<8|buf[4],buf[5]);
			if( buf[5] == 1 ){
				return 1;
			}
		}
	}
	return 0;
}
static int starttls(int accfd,int confd)
{	FILE *fc,*tc,*fs,*ts;
	int fdv[2],rfdv[2];
	CStr(buf,1024);
	CStr(com,32);
	CStr(arg,32);
	const char *msg;
	CStr(msgb,1024);
	const char *dp;
	const char *proto;
	int xi;

	fdv[0] = accfd;
	fdv[1] = confd;
	fc = fdopen(fdv[0],"r"); setbuf(fc,NULL);
	tc = fdopen(fdv[0],"w");
	fs = fdopen(fdv[1],"r"); setbuf(fs,NULL);
	ts = fdopen(fdv[1],"w");

	proto = stls_proto;
	if( do_conSSL && do_conSTLS ){
		proto = relay_opening(proto,fs,tc,AVStr(buf),sizeof(buf));
		if( proto == NULL )
			return -1;

		ERROR("STARTTLS to server -- %s",proto);
		if( strcasecmp(proto,"FTP") == 0 ){
			if( do_conSTLS & ST_SSL )
				fputs("AUTH SSL\r\n",ts);
			else{
				fputs("AUTH TLS\r\n",ts);
				if( do_conSTLS & ST_FORCE )
					cl_nego_FTPDATA = 1;
			}
		}else
		if( strcasecmp(proto,"SMTP") == 0 ){
			fputs("STARTTLS\r\n",ts);
		}else
		if( strncasecmp(proto,"POP",3) == 0 ){
			fputs("STLS\r\n",ts);
		}else
		if( strcasecmp(proto,"IMAP") == 0 ){
			fputs("stls0 STARTTLS\r\n",ts);
		}
		fflush(ts);
		if( fgets(buf,sizeof(buf),fs) == NULL )
			return -1;
		if( dp = strpbrk(buf,"\r\n") )
			truncVStr(dp);
		ERROR("STARTTLS to server -- %s",buf);
	}
	if( do_accSSL && do_accSTLS ){
	  for( xi = 0; ; xi++ ){
	    PollIns(0,2,fdv,rfdv);
	    if( rfdv[0] ){
		if( xi == 0 /* && accept implicit SSL too */ ){
			if( isinSSL(fdv[0]) )
				return 0;
			if( do_accSTLS == ST_AUTO ){
				ERROR("SSL-autodetect C-S: not in SSL");
				do_accSSL = 0;
				return 0;
			}
		}
		if( fgets(buf,sizeof(buf),fc) == NULL )
			return -1;
		dp = wordscanX(buf,AVStr(com),sizeof(com));
		wordscanX(dp,AVStr(arg),sizeof(arg));
		ERROR("STARTTLS prologue: C-S: [%s][%s]",com,arg);

		/* SMTP */
		if( strcasecmp(com,"EHLO") == 0 ){
			IGNRETP write(accfd,"250 STARTTLS\r\n",14);
			continue;
		}
		if( strcasecmp(com,"STARTTLS") == 0 ){
			msg = "220 Ready to start TLS\r\n";
			IGNRETP write(accfd,msg,strlen(msg));
			ERROR("STARTTLS from SMTP client -- OK");
			break;
		}

		/* POP3 */
		if( strcasecmp(com,"STLS") == 0 ){
			msg = "+OK Begin TLS negotiation\r\n";
			IGNRETP write(accfd,msg,strlen(msg));
			ERROR("STARTTLS from POP client -- OK");
			break;
		}

		/* IMAP */
		if( strcasecmp(arg,"CAPABILITY") == 0 ){
			msg = "* CAPABILITY STARTTLS\r\n";
			IGNRETP write(accfd,msg,strlen(msg));
			sprintf(msgb,"%s OK CAPABILITY\r\n",com);
			IGNRETP write(accfd,msgb,strlen(msgb));
			continue;
		}
		if( strcasecmp(arg,"STARTTLS") == 0 ){
			sprintf(msgb,"%s OK Begin TLS negotiation\r\n",com);
			IGNRETP write(accfd,msgb,strlen(msgb));
			ERROR("STARTTLS from IMAP client -- OK");
			break;
		}

		/* FTP */
		if( strcasecmp(com,"AUTH") == 0 )
		if( strcasecmp(arg,"TLS") == 0 || strcasecmp(arg,"SSL") == 0 ){
			msg = "234 OK\r\n";
			IGNRETP write(accfd,msg,strlen(msg));
			ERROR("AUTH %s from FTP client -- 234 OK",arg);
			if( strcasecmp(arg,"TLS") == 0 && do_accSTLS == ST_FORCE )
				sv_nego_FTPDATA = 1;
			break;
		}

		/* HTTP */
		if( strcasecmp(com,"CONNECT") == 0 ){
			if( proto == 0 ){
				proto = "http";
			}
		}

		if( do_accSTLS == 2 ){
			ERROR("STARTTLS required");
			if( proto != 0 && strcasecmp(proto,"IMAP") == 0 )
				fprintf(tc,"%s BAD do STARTTLS first.\r\n",com);
			else
			if( proto != 0 && strcasecmp(proto,"POP") == 0 )
				fprintf(tc,"+ERR do STLS first.\r\n");
			else
			fprintf(tc,"530 do STARTTLS first.\r\n");
			fflush(tc);
			return -1;
		}
		fputs(buf,ts);
		fflush(ts);
	    }
	    if( rfdv[1] ){
		if( xi == 0 ){
			if( isinSSL(fdv[1]) ) /* will not match */
				return 0;
			if( do_accSTLS == ST_AUTO ){
				ERROR("SSL-autodetect S-C: not in SSL");
				do_accSSL = 0;
				return 0;
			}
		}
		if( proto == NULL ){
			proto = relay_opening(proto,fs,tc,AVStr(buf),sizeof(buf));
			if( proto == NULL )
				return -1;
			ERROR("STARTTLS to client -- %s",proto);
		}else{
		if( fgets(buf,sizeof(buf),fs) == NULL )
			return -1;
		fputs(buf,tc);
		}
		/* HTTP */
		if( proto != NULL && streq(proto,"http") ){
			if( buf[0] == '\r' || buf[1] == '\n' ){
				ERROR("STARTTLS prologue: S-C HTTP-CONNECT DONE");
				fflush(tc);
				break;
			}
		}
		if( dp = strpbrk(buf,"\r\n") )
			truncVStr(dp);
		ERROR("STARTTLS prologue: S-C: %s",buf);
		fflush(tc);
	    }
	  }
	}
	return 0;
}
static int nego_FTPDATAsv(SSL *accSSL,char buf[],int len)
{	CStr(com,32);
	CStr(arg,32);
	const char *dp;
	const char *msg;

	buf[len] = 0;
	dp = wordscanX(buf,AVStr(com),sizeof(com));
	wordscanX(dp,AVStr(arg),sizeof(arg));
	if( strcasecmp(com,"PBSZ") == 0 ){
		msg = "200 OK\r\n";
		SSL_write(accSSL,msg,strlen(msg));
		ERROR("PBSZ %s from FTP client -- 200 OK",arg);
		len = 0;
	}
	else
	if( strcasecmp(com,"PROT") == 0 ){
		msg = "200 OK\r\n";
		SSL_write(accSSL,msg,strlen(msg));
		ERROR("PROT %s from FTP client -- 200 OK",arg);
		len = 0;
		sv_nego_FTPDATA = 0;
	}
	return len;
}
#define FTP_LOGIN_OK	"230"
static void nego_FTPDATAcl(SSL *conSSL,const char sbuf[],int len)
{	const char *msg;
	CStr(buf,64);
	CStr(resp,64);
	int rcc;

	if( len != 0 )
	if( strncmp(sbuf,FTP_LOGIN_OK,strlen(FTP_LOGIN_OK)) != 0 )
		return;

	msg = "PBSZ 0\r\n";
	SSL_write(conSSL,msg,strlen(msg));
	if( 0 <= (rcc = SSL_read(conSSL,buf,sizeof(buf)-1)) )
		setVStrEnd(buf,rcc);
	else	setVStrEnd(buf,0);
	linescanX(buf,AVStr(resp),sizeof(resp));
	ERROR("STARTTLS/FTP PBSZ 0 -> %s",resp);
	if( atoi(resp) != 200 )
		return;

	msg = "PROT P\r\n";
	SSL_write(conSSL,msg,strlen(msg));
	if( 0 <= (rcc = SSL_read(conSSL,buf,sizeof(buf)-1)) )
		setVStrEnd(buf,rcc);
	else	setVStrEnd(buf,0);
	linescanX(buf,AVStr(resp),sizeof(resp));
	ERROR("STARTTLS/FTP PROT P -> %s",resp);
	if( atoi(resp) == 200 )
		cl_nego_FTPDATA = 0;
}

static int HTTP_CAresp(int fd,PCStr(certfile))
{	FILE *tc,*cfp;
	X509 *cert;
	BIO *in,*out;

	tc = fdopen(fd,"w");
	cfp = fopen(certfile,"r");
	if( cfp == NULL )
		return -1;

	fprintf(tc,"HTTP/1.0 200 ok\r\n");
	fprintf(tc,"MIME-Version: 1.0\r\n");
	fprintf(tc,"Content-Type: application/x-x509-ca-cert\r\n");
	fprintf(tc,"\r\n");

	in = BIO_new_fp(cfp,BIO_NOCLOSE);
	cert = PEM_read_bio_X509(in,NULL,NULL,NULL);
	out = BIO_new_fp(tc,BIO_NOCLOSE);
	i2d_X509_bio(out,cert);

	BIO_free(in);
	BIO_free(out);
	fclose(tc);
	return 0;
}
static int CArequest(int accfd,int *isHTTP,PCStr(certfile))
{	CStr(method,8);
	CStr(line,1024);
	CStr(url,1024);
	int rcc;

	setNonblockingIO(accfd,1);
	rcc = RecvPeek(accfd,method,6);
	setNonblockingIO(accfd,0);

	if( rcc <= 0 )
		return 0;

	setVStrEnd(method,rcc);

	if( strncmp(method,"GET ",4) == 0 ){
		setNonblockingIO(accfd,1);
		rcc = RecvPeek(accfd,line,16);
		setNonblockingIO(accfd,0);
		setVStrEnd(line,rcc);

		wordscanX(line+4,AVStr(url),sizeof(url));
		if( strcmp(url,"/-/ca.der") == 0 ){
			HTTP_CAresp(0,certfile);
			TRACE("sent cert");
			return 1;
		}
		*isHTTP = 1;
	}else
	if( strncmp(method,"HEAD ",5) == 0 || strncmp(method,"POST ",5) == 0 )
		*isHTTP = 1;
	return 0;
}
static void rand_seed()
{	int seed[8],si;

	seed[0] = Gettimeofday(&seed[1]);
	RAND_seed(seed,sizeof(int)*2);
/*
	seed[2] = getpid();
	seed[3] = getuid();
	seed[4] = (int)seed;
	seed[5] = (int)rand_seed;
	RAND_seed(seed,sizeof(seed));
*/
	for( si = 0; si < 8; si++ )
		seed[si] = 0;
}
int (*SSL_getpassCB)(PCStr(file),PVStr(pass),int size);
static int _passwd(PCStr(what),PCStr(pass),PCStr(keyfile),char buf[],int siz,int vrfy)
{	CStr(passfile,1024);

	if( pass ){
		TRACE("passphrase for %s -- OK",keyfile);
		Xstrcpy(ZVStr(buf,siz),pass);
		return strlen(pass);
	}else
	if( SSL_getpassCB && (*SSL_getpassCB)(keyfile,ZVStr(buf,siz),siz)==0 ){
		TRACE("passphrase CB for %s -- OK",keyfile);
		return strlen(buf);
	}else{
		passfilename(keyfile,AVStr(passfile));
		ERROR("passphrase for %s -- ERROR: '%s' file not found and SSL_%s_KEY_PASSWD undefined",
			keyfile,passfile,what);
		return -1;
	}
}
static int sv_passwd(char buf[],int siz,int vrfy)
{
	return _passwd("SERVER",sv_pass,sv_key,buf,siz,vrfy);
}
static int cl_passwd(char buf[],int siz,int vrfy)
{
	return _passwd("CLIENT",cl_pass,cl_key,buf,siz,vrfy);
}

static SSL_SESSION *get_session_cb(SSL *ssl,unsigned char *id,int len,int *copy){
	DEBUG("--CB-- GET SESSION %d [%2X]",len,id[0]);
	return 0;
}
static int new_session_cb(SSL *ssl,SSL_SESSION *sess){
	int len;
	len = i2d_SSL_SESSION(sess,NULL);
	DEBUG("--CB-- NEW SESSION CREATED %X, len=%d",sess,len);
	return 0;
}
static int gen_session_cb(const SSL *ssl,unsigned char *id,unsigned int *id_len){	int i;

	DEBUG("--CB-- GEN SESSION CB, len=%d",*id_len);
	return 1;
/*
 for(i = 0; i < *id_len; i++)
 fprintf(stderr," %02X",id[i]);
 fprintf(stderr,"\n");
	id[0] = 'X';
	*id_len = 1;
	return 1;
*/
}

static void put_help()
{
	syslog_ERROR("SSLway in %s/%s (%s)\r\n",NAME,VERSION,DATE);
	syslog_ERROR("SSLlib %s\r\n",SSLeay_version(0));
}

void initSSLwayCTX(SSLwayCTX *Sc){
	bzero(Sc,sizeof(SSLwayCTX));
	Sc->ss_error = 0;
	Sc->ss_ready = -1;
}
static void finalize(SSLwayCTX *Sc,PCStr(msg),int client,int server,int accfd,int confd,int do_acc,int do_con,SSL *accSSL,SSL *conSSL){

    porting_dbg("--E-SSLway ErrFin [%d %d %d]{rdy=%d sta=%d}",
	client,accfd,confd,SSLready,SSLstart);
    syncReady(Sc,msg,do_acc,do_con);
    Sc->ss_error = 1;

    if( 0 <= client ){
	if( lTHREAD() ){
		daemonlog("F","-- %s%s SSLway close[%d,%d] ERROR: %s\n",
			do_acc?"[FCL]":"",
			do_con?"[FSV]":"",
			accfd,confd,
			msg);
	}
	clearCloseOnFork("SSLabort",accfd);
	close(accfd);
	clearCloseOnFork("SSLabort",confd);
	close(confd);
    }
}
#define ErrFin(msg) finalize(Sc,msg,client,server,accfd,confd,do_acc,do_con,accSSL,conSSL)

static SSL_CTX *ssl_newsv(){
	SSL_CTX *ctx;
	ctx = ssl_new(1);
	SSL_CTX_set_default_passwd_cb(ctx,(pem_password_cb*)sv_passwd);
	SSL_CTX_set_tmp_rsa_callback(ctx,tmprsa_callback);
	/*
	if( cl_vrfy ){
		SSL_CTX_set_verify(ctx,cl_vrfy,verify_callback);
		SSL_CTX_set_session_id_context(ctx,ssid,ssid_len);
	}
	*/
	return ctx;
}
static int saveCtx;
int dl_isstab(void*);
const char *GetEnv(PCStr(name));

int IsConnected(int fd,const char **reason);
static void doShutdown(int clsv,SSL *ssl,int fd){
	int sd,sd0;
	const char *whpeer = (clsv==XCON)?"Server":"Client";
	char wh;
	int rcc;
	IStr(buf,128);
	int eos = 0;
	int shut = 0;
	int rdy = 0;
	double St = Time();

	sd = sd0 = SSL_get_shutdown(ssl);
	wh = *whpeer;
	TRACE("%c>> shutdown from %s: %X",wh,whpeer,sd0);

	if( SSLopts[clsv] & OPT_SHUT_FLUSH )
	if( (sd & SSL_RECEIVED_SHUTDOWN) == 0 ){
		if( SSL_pending(ssl) )
			rdy = 9;
		else	rdy = PollIn(fd,3);
		if( 0 < rdy ){
			rcc = SSL_read(ssl,buf,1);
			sd = SSL_get_shutdown(ssl);
			TRACE("%c>> recv %X/%X rdy=%d rcc=%d (%.3f)",
				wh,sd0,sd,rdy,rcc,Time()-St);
		}
	}

	if( sd & SSL_RECEIVED_SHUTDOWN ){
		shut = SSL_shutdown(ssl);
		sd = SSL_get_shutdown(ssl);
		TRACE("%c<< shutdown %s: %X <= %X (%d)",wh,whpeer,sd,sd0,shut);
		return;
	}
	if( SSLopts[clsv] & OPT_SHUT_OPTS ){
		eos = IsAlive(fd) <= 0;
		DEBUG("%c>> shutdown from %s: %X eos=%d",wh,whpeer,sd,eos);
		if( eos ){
			return;
		}
	}else{
		return;
	}
	if( SSLopts[clsv] & OPT_SHUT_SEND )
	if( (sd & SSL_SENT_SHUTDOWN) == 0 ){
		shut = SSL_shutdown(ssl);
		sd = SSL_get_shutdown(ssl);
		DEBUG("%c<< shutdown %s: %X <= %X (%d)",wh,whpeer,sd,sd0,shut);
	}
	if( shut != 1 )
	if( SSLopts[clsv] & OPT_SHUT_WAIT ){
		DEBUG("%c>> wait shut from %s: %X %d %d",
			wh,whpeer,sd,SSL_pending(ssl),PollIn(fd,1));
		if( SSL_pending(ssl) || 0 < PollIn(fd,SHUTwait[clsv]) ){
			rcc = SSL_read(ssl,buf,sizeof(buf));
			sd = SSL_get_shutdown(ssl);
			TRACE("%c>> wait shut from %s: %X %d %d %d",
				wh,whpeer,sd,SSL_pending(ssl),PollIn(fd,1),rcc);
			if( sd & SSL_RECEIVED_SHUTDOWN ){
				shut = SSL_shutdown(ssl);
			}
		}
		TRACE("%c<< shutdown %s: %X <= %X (%d)",wh,whpeer,sd,sd0,shut);
	}
}
int sslway_mainY(SSLwayCTX *Sc,int ac,char *av[],int client,int server,int bi,SSigMask *sMask);
/* 9.9.4 MTSS to let SSLway file accesses be safe from signals */
int sslway_mainX(SSLwayCTX *Sc,int ac,char *av[],int client,int server,int bi)
{
	int rcode;
	SSigMask sMask;
	setSSigMask(sMask);
	SSLstage = "start";
	rcode = sslway_mainY(Sc,ac,av,client,server,bi,&sMask);
	if( gotsigTERM("SSLway ending") ){
	}
	SSLstage = "done";
	resetSSigMask(sMask);
	return rcode;
}
int sslway_mainY(SSLwayCTX *Sc,int ac,char *av[],int client,int server,int bi,SSigMask *sMask)
{	int ai;
	const char *arg;
	int accfd,confd;
	SSL_CTX *ctx;
	SSL *accSSL,*conSSL;
	const char *env;
	int fdv[2],rfdv[2];
	int vflag;
	int ctrlopt = 0;
	int vflags = 0;
	X509_STORE *store;
	int nodelay = 1;
	int fid = -1;
	int ctx_reuse = 0;
	int sreused = 0;
	int sync = -1;
	int atstart = SSLstart;
	int do_acc = 0;
	int do_con = 0;
	SslEnv senv;

	/* global variables shared and reused via dynamic linking ... */
	{
		do_accSSL = 0;
		do_conSSL = 0;
	}

	Sc->ss_error = 0;
	senv.se_ac = ac;
	senv.se_av = (const char**)av;
	Start = Time();
	lapx = 0;
	setaddrs();

	PID = getpid();
	if( (client_host = GetEnv("REMOTE_HOST")) == 0 )
		client_host = "?";

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-help") == 0 || strcmp(arg,"-v") == 0 ){
			put_help();
			exit(0);
		}else 
		if( strncmp(arg,"-va",3) == 0 ){
			int aj;
			for( aj = 0; aj < ac; aj++ )
				ERROR("arg[%d] %s",aj,av[aj]);
		}else{
			opt1(arg);
		}
	}
	Lap("start");

	nthcall++;
	if( env = getenv("CFI_FILTER_ID") )
		fid = atoi(env);
	/*
	if( !bi )
	CFI_SHARED_FD or so is necessary
	*/
	CFI_init(ac,(const char**)av);
	Lap("init done");

	if( env = getenv("CFI_TYPE") ){
		if( strcmp(env,"FCL") == 0 ){
			DEBUG("CFI_TYPE=%s: -ac is assumed",env);
			do_accSSL = 1;
		}else
		if( strcmp(env,"FSV") == 0 || strcmp(env,"FMD") == 0 ){
			DEBUG("CFI_TYPE=%s: -co is assumed",env);
			do_conSSL = 1;
		}
	}
	if( env = getenv("CFI_STAT") ){
		int fd;
		fd = atoi(env);
		stdctl = fdopen(fd,"w");
		fprintf(stdctl,"CFI/1.0 100 start\r\n");
		fflush(stdctl);
	}
	if( env = getenv("CFI_SYNC") ){
		sync = atoi(env);
		if( 0 <= sync ){
			TRACE("CFI_SYNC send start [%d]",sync);
			IGNRETP write(sync,"W",1);
		}
	}
	if( env = GetEnv("SSL_KEY_PASSWD") )
		sv_pass = cl_pass = env;
	if( env = GetEnv("SSL_CLIENT_KEY_PASSWD") )
		cl_pass = env;
	if( env = GetEnv("SSL_SERVER_KEY_PASSWD") )
		sv_pass = env;

/*
	accfd = dup(0);
	confd = dup(1);
*/
	if( 0 <= client ){
		accfd = dup(client);
		setCloseOnFork("SSLstart",accfd);
		confd = dup(server);
		setCloseOnFork("SSLstart",confd);
	}else{
		accfd = -1;
		confd = -1;
	}

	if( env = GetEnv("SSL_CIPHER") ) cipher_list = env;

	if( env = GetEnv("SSL_CERT_FILE") )
		sv_cert = sv_key = cl_cert = cl_key = env;

	if( env = GetEnv("SSL_SERVER_KEY_FILE" ) ) sv_key  = env;
	if( env = GetEnv("SSL_SERVER_CERT_FILE") ) sv_cert = env;

	if( env = GetEnv("SSL_CLIENT_KEY_FILE" ) ) cl_key  = env;
	if( env = GetEnv("SSL_CLIENT_CERT_FILE") ) cl_cert = env;

	Lap("begin args");
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strcmp(arg,"-help") == 0 || strcmp(arg,"-v") == 0 ){
		}else 
		if( strncmp(arg,"-vv",3) == 0 || strncmp(arg,"-vd",3) == 0 ){
		}else
		if( strncmp(arg,"-vu",3) == 0 ){
		}else
		if( strncmp(arg,"-vt",3) == 0 ){
		}else
		if( strncmp(arg,"-vs",3) == 0 ){
		}else
		if( strneq(arg,"-no_ssl",7) ){
			int sslnover = 0;
			if( streq(arg+7,"2") ) sslnover = 1; else
			if( streq(arg+7,"3") ) sslnover = 2; else
			if( streq(arg+7,"23")) sslnover = 3;
			sv_sslnover = cl_sslnover = sslnover;
		}else
		if( strneq(arg,"-ssl",4) ){
			int sslver = 0;
			if( streq(arg+4,"2") ) sslver = 1; else
			if( streq(arg+4,"3") ) sslver = 2; else
			if( streq(arg+4,"23")) sslver = 3;
			sv_sslver = cl_sslver = sslver;
		}else
		if( strneq(arg,"-tls",4) ){
			int sslver = 0;
			if( streq(arg+4,"1") ) sslver = 4;
			sv_sslver = cl_sslver = sslver;
		}else
		if( strncasecmp(arg,"-ss",3) == 0 ){
			do_accSTLS = do_conSTLS = ST_SSL;
			if( arg[3] == '/' && arg[4] != 0 )
				stls_proto = strdup(arg+4);
		}else
		if( strncasecmp(arg,"-st",3) == 0 ){
			do_accSTLS = do_conSTLS = arg[1]=='s'?1:2;
			if( arg[3] == '/' && arg[4] != 0 )
				stls_proto = strdup(arg+4);
		}else
		if( strncasecmp(arg,"-ad",3) == 0 ){
			do_accSTLS = do_conSTLS = ST_AUTO;
		}else
		if( strncmp(arg,"-ac",3) == 0 ){
			do_accSSL = 1;
			if( strncmp(arg+3,"/st",3) == 0 ) do_accSTLS = 1;
		}else
		if( strncmp(arg,"-co",3) == 0 ){
			do_conSSL = 1;
			if( strncmp(arg+3,"/st",3) == 0 ) do_conSTLS = 1;
		}else
		if( strncmp(arg,"-ht",3) == 0 ){
			acc_bareHTTP = 1;
		}else
		if( strncmp(arg,"-show",3) == 0 ){
			do_showCERT = 1;
		}else
		if( strcmp(arg,"-CApath") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s directory-name",arg);
				return -1;
			}
			cl_CApath = sv_CApath = av[++ai];
		}else
		if( strcmp(arg,"-CAfile") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s file-name",arg);
				return -1;
			}
			cl_CAfile = sv_CAfile = av[++ai];
		}else
		if( strcasecmp(arg,"-vrfy")==0 || strcasecmp(arg,"-auth")==0 ){
			vflag = SSL_VERIFY_PEER
				| SSL_VERIFY_CLIENT_ONCE;
			if( arg[1] == 'V' || arg[1] == 'A' )
				vflag |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			if( arg[1] == 'V' || arg[1] == 'v' )
				verify_depth = -1;
			else	verify_depth = 10;
			cl_vrfy = vflag;
			sv_vrfy = vflag;
		}else
		if( strcasecmp(arg,"-verify") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s max-depth",arg);
				return -1;
			}
			verify_depth = atoi(av[++ai]);
			vflag = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
			if( arg[1] == 'V' )
				vflag |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			cl_vrfy = vflag;
			sv_vrfy = vflag;
		}else
		if( strcmp(arg,"-client_auth") == 0 ){
			verify_depth = 10;
			cl_vrfy = SSL_VERIFY_PEER
				| SSL_VERIFY_CLIENT_ONCE;
		}else
		if( strcmp(arg,"-cipher") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s cipher-list",arg);
				return -1;
			}
			cipher_list = av[++ai];
		}else
		if( strcmp(arg,"-certkey") == 0
		 || strcmp(arg,"-cert") == 0 ){
			cert_opts++;
			if( ac <= ai + 1 ){
				ERROR("Usage: %s cert-key-file-name",arg);
				return -1;
			}
			if( sv_cert != sv_cert_default ){
				if( elnumof(sv_Cert.v_ck) <= sv_Ncert+1 ){
				}else{
					sv_Ncert++;
					sv_Nkey++;
				}
			}
			if( cl_cert != cl_cert_default ){
				if( elnumof(cl_Cert.v_ck) <= cl_Ncert+1 ){
				}else{
					cl_Ncert++;
					cl_Nkey++;
				}
			}
			sv_cert = sv_key = cl_cert = cl_key = av[++ai];
		}
		else
		if( strcmp(arg,"-key") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s key-file-name",arg);
				return -1;
			}
			sv_key = cl_key = av[++ai];
		}
		else
		if( strcmp(arg,"-pass") == 0 ){
			if( ac <= ai + 1 ){
				ERROR("Usage: %s {pass:str|file:path}");
				return -1;
			}
			scanpass(av[++ai]);
		}
		else
		if( strcmp(arg,"-bugs") == 0 ){
			ctrlopt = 0x000FFFFFL; /* SSL_OP_ALL */
		}
		else
		if( strcmp(arg,"-nocache") == 0 ){
			do_cache = 0;
		}
		else
		if( strcmp(arg,"-delay") == 0 ){
			nodelay = 0;
		}
		else
		if( strcmp(arg,"-crl_check") == 0 ){
			vflags |= X509_V_FLAG_CRL_CHECK;
		}
		else
		if( strcmp(arg,"-crl_check_all") == 0 ){
			vflags |= X509_V_FLAG_CRL_CHECK
				| X509_V_FLAG_CRL_CHECK_ALL;
		}
	}
	Lap("end args");

	accSSL = NULL;
	conSSL = NULL;

	if( do_acc = do_accSSL ){
		sv_Start = Time();
		sv_Ready = SSLready;
	}
	if( do_con = do_conSSL ){
		cl_Start = Time();
		cl_Ready = SSLready;
	}
	SSLready = -1;

	if( do_conSSL || do_accSSL )
	{
		if( nthcall <= 1 ){
		rand_seed();
		Lap("end rand_seed");
		}
		TRACE("start");
	}

	if( accfd < 0 ){
		/* setting ctx */
	}else{
	if( nodelay ){
		set_nodelay(accfd,1);
		set_nodelay(confd,1);
		Lap("nodelay set");
	}

	fdv[0] = accfd;
	fdv[1] = confd;

	if( acc_bareHTTP ){
		int isHTTP;
		if( 0 < PollIns(100,2,fdv,rfdv) && 0<rfdv[0] && rfdv[1] <= 0 ){
			isHTTP = 0;
			if( CArequest(accfd,&isHTTP,sv_cert) )
				return 0;
			if( isHTTP ){
				 /* ... through raw HTTP request ...
				do_accSSL = 0;
				 */
			}
		}
	}
	if( do_conSSL && do_conSTLS || do_accSSL && do_accSTLS ){
		if( starttls(accfd,confd) < 0 )
			return -1;
	}
	}

	if( atstart ){
		syncReady(Sc,"START",do_acc,do_con);
	}
	if( dl_isstab((void*)SSL_CTX_set_generate_session_id) ){
		/* session cache is bad on Vine4 and KURO-BOX */
		do_cache &= ~((1<<XACC)|(1<<XCON));
	}
	if( gotsigTERM("SSLway init") ){
	}

	Lap("start con/acc");
	/*
	if( do_conSSL ){
	*/
	if( do_con ){
		ctx = ssl_new(0);
		SSL_CTX_set_default_passwd_cb(ctx,(pem_password_cb*)cl_passwd);
		if( cipher_list )
			SSL_CTX_set_cipher_list(ctx,cipher_list);
		getcertdflt(ctx,1);
		if( cl_cert != cl_cert_default || LIBFILE_IS(cl_cert,VStrNULL) )
			setcerts(ctx,&cl_Cert,1);

		if( sv_CAfile || sv_CApath )
			ssl_setCAs(ctx,sv_CAfile,sv_CApath);
		else	ssl_dfltCAs(ctx,0);
		if( sv_vrfy )
			SSL_CTX_set_verify(ctx,sv_vrfy,verify_callback);
		if( vflags ){
			store = SSL_CTX_get_cert_store(ctx);
			X509_STORE_set_flags(store, vflags);
		}

		if( 0 <= confd ){
			SSL_CTX_set_tlsext_servername_callback(ctx,got_vhost);
		conSSL = ssl_conn(ctx,confd,&senv);
		if( conSSL == NULL )
		    {
			ErrFin("ssl_conn() failure");
			return -1;
		    }
		}
		sreused += SSL_session_reused(conSSL);
	}

	/*
	if( do_accSSL ){
	*/
	if( do_acc ){
		/*
		if( fid == ctx_filter_id && ctx_cache != NULL ){
		*/
		if( (do_cache & (1 << XCTX))
		 && fid == ctx_filter_id && ctx_cache != NULL ){
			ctx = ctx_cache;
			TRACE("reuse ctx #%d %X",fid,ctx);
			ctx_reuse = 1;
			if( tlsdebug & DBG_XCACHE ){
				fprintf(stderr,"[%d] %s reusing cached\n",
					getpid(),"CTX");
			}
		}else{
		Lap("before ssl_new");
		ctx = ssl_new(1);
		Lap("after ssl_new");

		ctx_filter_id = fid;
		ctx_cache = ctx;
		TRACE("new ctx #%d %X",fid,ctx);

/*
SSL_CTX_sess_set_new_cb(ctx,new_session_cb);
SSL_CTX_sess_set_get_cb(ctx,get_session_cb);
		SSL_CTX_set_session_id_context(ctx,(unsigned char*)"sslway",6);
		SSL_CTX_set_generate_session_id(ctx,gen_session_cb);
*/

		if( ctrlopt )
			SSL_CTX_ctrl(ctx,32/*SSL_CTRL_OPTIONS*/,ctrlopt,NULL);
		SSL_CTX_set_default_passwd_cb(ctx,(pem_password_cb*)sv_passwd);
		if( cipher_list )
			SSL_CTX_set_cipher_list(ctx,cipher_list);

		Lap("before loadContext");
		if( loadContext(ctx,ac,av) == 0 ){
			ctx_reuse = 2;
		}else{
		if( setcerts(ctx,&sv_Cert,0) < 0 )
			return -1;
			TRACE("-- set saveCtx fd=%d",accfd);
			saveCtx = 1; /* to be saved later with 0 <= accfd */
		}
		Lap("after loadContext");
		SSL_CTX_set_tmp_rsa_callback(ctx,tmprsa_callback);

		if( cl_CAfile || cl_CApath )
			ssl_setCAs(ctx,cl_CAfile,cl_CApath);
		else	ssl_dfltCAs(ctx,1);
		if( cl_vrfy )
		{
			SSL_CTX_set_verify(ctx,cl_vrfy,verify_callback);
			SSL_CTX_set_session_id_context(ctx,ssid,ssid_len);
		}
		if( vflags ){
			store = SSL_CTX_get_cert_store(ctx);
			X509_STORE_set_flags(store, vflags);
		}
		}

		if( 0 <= accfd ){
			set_ifcert(ctx,accfd,0);
			SSL_CTX_set_tlsext_servername_callback(ctx,get_vhost);
		accSSL = ssl_acc(ctx,accfd);
		if( accSSL == NULL )
		    {
			ErrFin("ssl_acc() failure");
			return -1;
		    }

		/*
		if( ctx_reuse == 0 )
		*/
		if( ctx_reuse == 0 || saveCtx )
		if( sess_hits == 0 ){
			saveCtx = 0;
			saveContext(ctx,accSSL,ac,av);
		}
		}
	}

	if( tlsdebug & DBG_SCACHEV )
	fprintf(stderr,"[%d] %s %f sescache[%d] HIT=%d sR=%d cR=%d\n",
		getpid(),do_accSSL?"ACC":"CON",
		Time()-Start,sess_cached,sess_hits,sreused,ctx_reuse);

	Lap("start relay ...");
	if( sess_cached || sreused || ctx_reuse )
ERROR("## %f sescache[%d] HIT=%d sR=%d cR=%d",
		Time()-Start,sess_cached,sess_hits,sreused,ctx_reuse);
	else
	if( loglevel <= LERROR )
ERROR("## %f connected/accepted",Time()-Start);
	if( LDEBUG <= loglevel ){
		int i;
		for( i = 0; i < lapx; i++ )
DEBUG("-- %f %s",laps[i]-Start,lapd[i]);
	}

	if( accfd < 0 ){
		ERROR("initialized ctx #%d %X %X",fid,conSSL,accSSL);
		return 0;
	}

	if( 0 <= sync ){
		TRACE("CFI_SYNC send ready [%d]",sync);
		IGNRETP write(sync,"\n",1);
	}
	if( conSSL )
	{
		void dontclosedups(int fd);
		dontclosedups(accfd); /* for HTTPS/SSL in Keep-Alive on Win */
		dontclosedups(confd);

		ssl_prcert(conSSL,do_showCERT,NULL,  accfd,"server");
	}
	if( accSSL )
		ssl_prcert(accSSL,do_showCERT,accSSL,accfd,"client");

	if( gotsigTERM("SSLway setup") ){
	}
	reset_SSigMask(sMask);
	ssl_relay(Sc,accSSL,accfd,conSSL,confd);
	set_SSigMask(sMask,0);

	if( conSSL ){
		doShutdown(XCON,conSSL,confd);
		/*
		int sd = SSL_get_shutdown(conSSL);
		TRACE("S>> shutdown from server: %X",sd);
		if( sd & SSL_RECEIVED_SHUTDOWN ){
			TRACE("S<< return shutdown to server");
			SSL_shutdown(conSSL);
		}
		*/
	}
	if( accSSL ){
		doShutdown(XACC,accSSL,accfd);
		/*
		int sd = SSL_get_shutdown(accSSL);
		TRACE("C>> shutdown from client: %X",sd);
		if( sd & SSL_RECEIVED_SHUTDOWN ){
			TRACE("C<< return shutdown to client");
			SSL_shutdown(accSSL);
		}
		*/
	}

	if( do_conSSL || do_accSSL )
		TRACE("done");

	if( 0 <= client ){
		if( lTHREAD() ){
			syslog_ERROR("-- %s%s SSLway close[%d,%d]\n",
				accSSL?"[FCL]":"",conSSL?"[FSV]":"",
				accfd,confd);
		}
		ShutdownSocket(confd);
		clearCloseOnFork("SSLend",confd);
		close(confd);
		ShutdownSocket(accfd);
		/*
		set_linger(accfd,30);
		the linger seems make the process block, if without Shutdown ?
		*/
		clearCloseOnFork("SSLend",accfd);
		close(accfd);
	}
	return 0;
}
#ifdef ISDLIB /*{*/
int dl_library(const char *libname,DLMap *dlmap,const char *mode);
static int with_dl;
int sslway_dl_reset(){
	int owd = with_dl;
	with_dl = 0;
	return owd;
}
/*
int sslway_dl(){
*/
static int sslway_dl0(){
	if( with_dl ){
		if( 0 < with_dl )
			return 1;
		else	return 0;
	}
	if( SSLLIBS ){
		CStr(lib1,1024);
		const char *dp;
		char del = '+';
		for( dp = SSLLIBS; *dp; ){
			dp = scan_ListElem1(dp,del,AVStr(lib1));
			if( *lib1 == 0 )
				break;
			if( lDYLIB() )
				syslog_ERROR("TSLCONF=libs:%s\n",lib1);
			if( streq(lib1,"NOMORE") ){
				with_dl = -1;
				return 0;
			}
			if( dl_library(lib1,dlmap_ssl,"") == 0 ){
				with_dl = 1;
				return 1;
			}
		}
	}
	if( !isWindows() ){
		/*
		if( dl_library("ssl",dlmap_ssl,"") == 0
		 || dl_library("crypto",dlmap_ssl,"") == 0
			9.6.3 libcrypto should be loaded prior to libssl
			to avoid the error in automatic recursive loading
			of libcrypto from libssl (on Vine and KURO-BOX).
		*/
		if( dl_library("crypto",dlmap_ssl,"") == 0
		 || dl_library("ssl",dlmap_ssl,"") == 0
		){
			with_dl = 1;
			return 1;
		}
	}
	if( isWindows() || isCYGWIN() ){
		if( dl_library("ssl",dlmap_ssl,"") == 0
		 || dl_library("libeay32",dlmap_ssl,"") == 0
		 || dl_library("ssleay32",dlmap_ssl,"") == 0
		){
			with_dl = 1;
			return 1;
		}
	}
	{
		with_dl = -1;
		if( !lISCHILD() ){
			putDylibError();
		}
		return 0;
	}
}
int sslway_dl(){
	int ok;
	if( with_dl ){
		return sslway_dl0();
	}else
	if( ok = sslway_dl0() ){
		InitLog("+++ loaded %s\n",SSLeay_version(0));
		if( lDYLIB() )
		printf("+++ loaded %s\n",SSLeay_version(0));
		return ok;
	}else{
		return 0;
	}
}
const char *SSLVersion(){
	if( with_dl == 0 )
		return "Not Yet";
	if( with_dl < 0 )
		return "None";
	return SSLeay_version(0);
}
int putSSLverX(FILE *fp,PCStr(fmt)){
	if( with_dl <= 0 )
		return 0;
	fprintf(fp,"%s",SSLeay_version(0));
	return 1;
}
void putSSLver(FILE *fp){
	if( 0 < with_dl )
		fprintf(fp,"Loaded: %s\r\n",SSLeay_version(0));
}

int sslway_main(int ac,const char *av[])
{
	SSLwayCTX ScBuf,*Sc = &ScBuf;
	initSSLwayCTX(Sc);

	if( sslway_dl() == 0 ){
		fprintf(stderr,"Can't link the SSL library.\n");
		return -1;
	}
	Builtin = 1;
	return sslway_mainX(Sc,ac,(char**)av,0,1,0);
}
int sslwayFilter(SSLwayCTX *Sc,int ac,char *av[],FILE *in,FILE *out,int internal){
	if( sslway_dl() == 0 ){
		return 0;
	}
	Builtin = 1;
	if( in == NULL )
		sslway_mainX(Sc,ac,av,-1,-1,1);
	else	sslway_mainX(Sc,ac,av,fileno(in),fileno(out),1);
	return 1;
}
int sslwayFilterX(SSLwayCTX *Sc,int ac,char *av[],int clnt,int serv,int internal){
	if( sslway_dl() == 0 ){
		return 0;
	}
	Builtin = 1;
	if( clnt < 0 )
		sslway_mainX(Sc,ac,av,-1,-1,1);
	else	sslway_mainX(Sc,ac,av,clnt,serv,1);
	return 1;
}


static const char *RINFO  = "////RSA -.- ////";
static const char *ROK    = "////RSA ^_^ //// OK";
static const char *RERROR = "////RSA -\"- //// ERROR";

int getpass1(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch));
static int getpass2(FILE *in,FILE *out,PVStr(pass1),PVStr(pass2),PCStr(echoch)){
	fprintf(out,"%s enter PEM pass phrase> ",RINFO);
	getpass1(in,out,BVStr(pass1),0,echoch);
	fprintf(out,"\r\n");
	if( pass2 == 0 ){
		return 0;
	}
	fprintf(out,"%s enter again to verify> ",RINFO);
	getpass1(in,out,BVStr(pass2),pass1,echoch);
	fprintf(out,"\r\n");
	if( streq(pass1,pass2) ){
		return 0;
	}
	fprintf(stderr,"%s not match\r\n",RERROR);
	return -1;
}

enum _RCF {
	RC_VERBOSE   = 0x0001,
	RC_PRINTPUB  = 0x0002,
	RC_PRINTPRI  = 0x0004,
	RC_NOPASS    = 0x0010,
	RC_NEWKEY    = 0x0100,
	RC_CHPASS    = 0x0200,
	RC_SIGN      = 0x0400,
	RC_VRFY      = 0x0800,
	RC_ENC       = 0x1000,
	RC_DEC       = 0x2000,
	RC_PRV_KEY   = 0x4000,
} RCF;
typedef struct _RSACtx {
	int	rsa_flags;
	RSA    *rsa_rsa;
	int	rsa_bits;
	int	rsa_exp;
	MStr(	rsa_passb,64);
	char   *rsa_pass;
	int	rsa_plen;
	MStr(	rsa_file,256);
	int	rsa_intype;
	MStr(	rsa_indata,512);
	FILE   *rsa_pem;
    EVP_CIPHER *rsa_cipher;
} RSACtx;
#define RxFlags	Rc->rsa_flags

int _RSA_init(RSACtx *Rc){
	if( sslway_dl() == 0 ){
		fprintf(stderr,"%s no SSL library\r\n",RERROR);
		return -1;
	}
	ERR_load_crypto_strings();
	OPENSSL_add_all_algorithms_conf();

	bzero(Rc,sizeof(RSACtx));
	Rc->rsa_bits = 1024;
	Rc->rsa_exp = 0x10001;
	Rc->rsa_cipher = EVP_des_ede3_cbc();
	sprintf(Rc->rsa_file,"/tmp/rsa.pem");
	return 0;
}
RSACtx *_RSA_new(){
	RSACtx *Rc;
	Rc = (RSACtx*)malloc(sizeof(RSACtx));
	bzero(Rc,sizeof(RSACtx));
	_RSA_init(Rc);
	return Rc;
}
int _RSA_free(RSACtx *Rc){
	if( Rc->rsa_rsa ){
		RSA_free(Rc->rsa_rsa);
	}
	free(Rc);
	return 0;
}
int _RSA_setpass(RSACtx *Rc){
	IStr(pass1,64);
	IStr(pass2,64);

	getpass2(stdin,stderr,AVStr(pass1),AVStr(pass2),"*");
	if( !streq(pass1,pass2) ){
		fprintf(stderr,"%s pass mismatch\r\n",RERROR);
		return -1;
	}
	strcpy(Rc->rsa_passb,pass1);
	Rc->rsa_pass = Rc->rsa_passb;
	if( pass1[0] == 0 ){
		Rc->rsa_plen = 1; /* "\0" */
	}else{
		Rc->rsa_plen = strlen(pass1);
	}
	bzero(pass1,sizeof(pass1));
	bzero(pass2,sizeof(pass2));
	return 0;
}
static int passwd_cb(char buf[],int size,int rwflag,void *vRc){
	RSACtx *Rc = (RSACtx*)vRc;

	fprintf(stderr,"%s enter PEM pass phrase> ",RINFO);
	buf[0] = 0;
	getpass1(stdin,stdout,ZVStr(buf,size),0,"*");
	fprintf(stdout,"\r\n");
	if( buf[0] == 0 ){
		return 1;
	}else{
		return strlen(buf);
	}
}
static void genkey_cb(int x,int y,void *vRc){
	RSACtx *Rc = (RSACtx*)vRc;

	if( RxFlags & RC_VERBOSE ){
		fprintf(stderr,"{%d %d}",x,y);
		fflush(stderr);
	}
}
int _RSA_output(RSACtx *Rc,RSA *rsa,FILE *pem){
	int rcode = 0;

	if( RxFlags & RC_VERBOSE ){
		RSA_print_fp(stderr,rsa,0);
	}
	if( 1 ){
		EVP_CIPHER *cipher;
		cipher = Rc->rsa_cipher;
		if( RxFlags & RC_NOPASS ){
			cipher = 0;
		}
		else
		if( Rc->rsa_pass == 0 ){
			if( _RSA_setpass(Rc) != 0 ){
				return -1;
			}
		}
		rcode = PEM_write_RSAPrivateKey(pem,rsa,cipher,
			(unsigned char*)Rc->rsa_pass,Rc->rsa_plen,NULL,0);
		bzero(Rc->rsa_passb,sizeof(Rc->rsa_passb));
		fflush(pem);
	}
	if( 1 ){
		rcode = PEM_write_RSAPublicKey(pem,rsa);
	}
	return rcode;
}
int _RSA_showpem(RSACtx *Rc,FILE *pem){
	int off;

	off = ftell(pem);
	fseek(pem,0,0);
	copyfile1(pem,stdout);
	fseek(pem,off,0);
	return 0;
}

int _RSA_perror(RSACtx *Rc,int rcode){
	int serr;
	IStr(reason,256);

	serr = ERR_get_error();
	if( serr ){
		ERR_error_string_n(serr,(char*)reason,sizeof(reason));
		ERR_print_errors_fp(stderr);
		fprintf(stderr,"%s rcode=%d err=%d {%s}\n",RINFO,rcode,serr,reason);
		return 1;
	}
	return 0;
}
int _RSA_newkey(RSACtx *Rc){
	RSA *rsa;
	char *bn;
	int rcode = 0;
	FILE *pem;
	IStr(path,256);
	int eout;

	strcpy(path,Rc->rsa_file);
	if( File_is(path) ){
		strcat(path,"#");
	}
	pem = fopen(path,"w+");
	if( pem == 0 ){
		fprintf(stderr,"%s cannot open: %s\n",RERROR,path);
		return -1;
	}
	if( RxFlags & RC_VERBOSE ){
		fprintf(stderr,"generating: ");
	}
	rsa = RSA_generate_key(Rc->rsa_bits,Rc->rsa_exp,genkey_cb,Rc);
	if( rsa == 0 ){
		fprintf(stderr," %s RSA_generate_key() FAILED\r\n",RERROR);
		return -1;
	}
	if( RxFlags & RC_VERBOSE ){
		fprintf(stderr," %s\r\n",ROK);
	}
	eout = _RSA_output(Rc,rsa,pem) < 0;
	_RSA_perror(Rc,rcode);

	RSA_free(rsa);
	fflush(pem);
	Ftruncate(pem,0,1);
	_RSA_showpem(Rc,pem);
	fclose(pem);

	if( !streq(path,Rc->rsa_file) ){
		fprintf(stderr,"%s updated %s\r\n",ROK,Rc->rsa_file);
		rename(path,Rc->rsa_file);
	}
	return 0;
}
static int _RSA_loadkey(RSACtx *Rc,int whkey){
	FILE *pem;
	RSA *rsa = 0;

	if( Rc->rsa_rsa != 0 ){
		return 1;
	}
	pem = fopen(Rc->rsa_file,"r");
	if( pem == 0 ){
		fprintf(stderr,"%s cannot open %s\r\n",RERROR,Rc->rsa_file);
		return -1;
	}
	rsa = PEM_read_RSAPrivateKey(pem,&rsa,passwd_cb,Rc);
	if( rsa != NULL ){
		Rc->rsa_flags |= RC_PRV_KEY;
	}
	if( rsa == NULL ){
		fseek(pem,0,0);
		clearerr(pem);
		rsa = PEM_read_RSAPublicKey(pem,&rsa,passwd_cb,Rc);
	}
	_RSA_perror(Rc,0);
	fclose(pem);

	if( rsa == 0 ){
		return -1;
	}
	Rc->rsa_rsa = rsa;
	return 0;
}
int _RSA_chpass(RSACtx *Rc){
	const char *file = Rc->rsa_file;
	IStr(nfile,256);
	FILE *opem;
	FILE *npem;
	RSA *rsa = 0;
	int err = 0;

	opem = fopen(file,"r");
	if( opem == 0 ){
		fprintf(stderr,"%s cannot open %s\r\n",RERROR,file);
		return -1;
	}
	sprintf(nfile,"%s#",file);
	npem = fopen(nfile,"w+");
	if( npem == 0 ){
		fprintf(stderr,"%s cannot open %s\r\n",RERROR,nfile);
		fclose(opem);
		return -1;
	}
	rsa = PEM_read_RSAPrivateKey(opem,&rsa,passwd_cb,Rc);
	_RSA_perror(Rc,0);
	if( rsa ){
		_RSA_showpem(Rc,opem);
		if( _RSA_output(Rc,rsa,npem) < 0 ){
			fprintf(stderr,"%s failed writing %s\r\n",RERROR,file);
			err = 2;
		}else{
			_RSA_showpem(Rc,npem);
		}
		RSA_free(rsa);
	}else{
		fprintf(stderr,"%s cannot load RSA %s\r\n",RERROR,file);
		err = 1;
	}
	fclose(npem);
	fclose(opem);
	if( err == 0 ){
		fprintf(stderr,"%s updated %s\r\n",ROK,file);
		rename(nfile,file);
	}
	return 0;
}
int _RSA_sign(RSACtx *Rc,PCStr(data),int dlen,PVStr(sig),int *slen){
	int ok;

	if( _RSA_loadkey(Rc,1) < 0 ){
		return -1;
	}
	ok = signRSA(Rc->rsa_rsa,data,dlen,BVStr(sig),(unsigned int*)slen);
	_RSA_perror(Rc,0);
	if( ok ){
		return 0;
	}
	return -1;
}
int _RSA_verify(RSACtx *Rc,PCStr(data),int dlen,PCStr(sig),int slen){
	int ok;

	if( _RSA_loadkey(Rc,2) < 0 ){
		return -1;
	}
	ok = verifyRSA(Rc->rsa_rsa,data,dlen,sig,(unsigned int)slen);
	_RSA_perror(Rc,0);
	if( ok ){
		return 0;
	}
	return -1;
}

#define RSA_PKCS1_PADDING  1
#define RSA_NO_PADDING     3
int _RSA_avail(RSACtx *Rc){
	if( Rc->rsa_bits <= 0 ){
		return 0;
	}
	if( _RSA_loadkey(Rc,1) < 0 ){
		return 0;
	}
	return 1;
}
int _RSA_encrypt(RSACtx *Rc,PCStr(data),int dlen,PVStr(edata),int esiz,int hex){
	int padding = RSA_PKCS1_PADDING;
	int elen;

	if( _RSA_loadkey(Rc,1) < 0 ){
		return -1;
	}
	if( (Rc->rsa_flags & RC_PRV_KEY) == 0 ){
		return -2;
	}
	elen = RSA_private_encrypt(dlen,
		(unsigned char*)data,
		(unsigned char*)edata,Rc->rsa_rsa,padding);
	_RSA_perror(Rc,0);
	if( 0 < elen ){
		return elen;
	}
	return -3;
}
int _RSA_decrypt(RSACtx *Rc,PCStr(edata),int elen,PVStr(ddata),int dsiz,int hex){
	int padding = RSA_PKCS1_PADDING;
	int dlen;

	if( _RSA_loadkey(Rc,1) < 0 ){
		return -1;
	}
	dlen = RSA_public_decrypt(elen,
		(unsigned char*)edata,
		(unsigned char*)ddata,Rc->rsa_rsa,padding);
	_RSA_perror(Rc,0);
	if( 0 < dlen ){
		return dlen;
	}
	return -1;
}
int stripCRLF(PVStr(benc)){
	strsubst(BVStr(benc),"\r","");
	strsubst(BVStr(benc),"\n","");
	return 0;
}
/*
 * Signed Data:
 * Ty: type                               (1B)
 * Ty: flags                              (1B)
 *
 * Lp: length of Kp                       (2B)
 * Kp: pub-key of the issuer             (LpB)
 * Lq: length of Kq                       (2B)
 * Kq: signer's pub-key encrypted by Kp' (LpB) including attr. and cap. of him
 *
 * Ls: length of Sd                       (2B)
 * Sd: sign by Kq' for MD5 of data       (LsB)
 * Ld: length of Pd                       (4B)
 * Pd: payload data to be signed         (LdB)
 */
int hextoStr(PCStr(hex),PVStr(bin),int siz);
int rsa_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	RSACtx RcBuf,*Rc = &RcBuf;
	const char *indata = Rc->rsa_indata;
	int ilen;
	int elen,dlen;
	IStr(enc,256);
	IStr(dec,256);
	IStr(benc,512);


	_RSA_init(Rc);
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
		  switch( a1[1] ){
		    case 'v': RxFlags |= RC_VERBOSE; break;
		    case 'n':
			if( streq(a1,"-nopass") ){
				RxFlags |= RC_NOPASS;
			}	
		    default:
			break;
		    case 'f':
			if( ai+1 < ac ){
				strcpy(Rc->rsa_file,av[++ai]);
			}
			break;
		    case 'i':
			if( ai+1 < ac ){
				strcpy(Rc->rsa_indata,av[++ai]);
			}
			break;
		  }
		}else{
			if( streq(a1,"new") ){
				RxFlags |= RC_NEWKEY;
			}else
			if( streq(a1,"chpass") ){
				RxFlags |= RC_CHPASS;
			}else
			if( streq(a1,"sign") ){
				RxFlags |= RC_SIGN;
			}else
			if( streq(a1,"verify") ){
				RxFlags |= RC_VRFY;
			}else
			if( streq(a1,"enc") ){
				RxFlags |= RC_ENC;
			}else
			if( streq(a1,"dec") ){
				RxFlags |= RC_DEC;
			}else{	
				Rc->rsa_bits = atoi(a1);
			}
		}
	}
	if( RxFlags & RC_NEWKEY ){
		_RSA_newkey(Rc);
	}
	if( RxFlags & RC_CHPASS ){
		_RSA_chpass(Rc);
	}

	ilen = strlen(Rc->rsa_indata);
	if( RxFlags & RC_SIGN ){
		int slen;
		int rcode;
		IStr(sig,256);
		IStr(xsig,1024);

		slen = sizeof(sig);
		rcode = _RSA_sign(Rc,"ABCD",4,AVStr(sig),&slen);
		if( rcode == 0 ){
			strtoHex(sig,slen,AVStr(xsig),sizeof(xsig));
			rcode = _RSA_verify(Rc,"ABCD",4,sig,slen);
			fprintf(stdout,"ABCD -> %s -> %d\n",xsig,rcode);
		}
	}
	if( RxFlags & RC_VRFY ){
	}
	if( RxFlags & RC_ENC ){
		elen = _RSA_encrypt(Rc,indata,ilen+1,AVStr(enc),sizeof(enc),1);
		if( 0 < elen ){
			/*
			IStr(xenc,1024);
			strtoHex(enc,elen,AVStr(xenc),sizeof(xenc));
			fprintf(stdout,"%s\n-> %s\n",indata,xenc);
			*/
			str_to64(enc,elen,AVStr(benc),sizeof(benc),0);
			stripCRLF(AVStr(benc));
			fprintf(stdout,"%s\n",benc);
			dlen = _RSA_decrypt(Rc,enc,elen,AVStr(dec),sizeof(dec),0);
			if( 0 < dlen ){
				fprintf(stdout,"%s\n->(%d) %s\n",indata,
					dlen,dec);
			}
		}
	}
	if( RxFlags & RC_DEC ){
		/*
		elen = hextoStr(Rc->rsa_indata,AVStr(enc),sizeof(enc));
		*/
		elen = str_from64(indata,ilen+1,AVStr(enc),sizeof(enc));
		dlen = _RSA_decrypt(Rc,enc,elen,AVStr(dec),sizeof(dec),0);
		if( 0 < dlen ){
			fprintf(stdout,"%s\n->(%d) %s\n",indata,
				dlen,dec);
		}
	}
	return 0;
}

#else /*}{*/
int (*DELEGATE_MAIN)(int ac,const char *av[]);
void (*DELEGATE_TERMINATE)();
extern int RANDSTACK_RANGE;
int main(int ac,char *av[])
{
	randtext(-1);
	RANDSTACK_RANGE = 256;
	av = move_envarg(ac,(const char**)av,NULL,NULL,NULL);
	return randstack_call(1,(iFUNCP)sslway_mainX,ac,av,0,1,0);
}
int sslway_dl(){
	return 1;
}
#endif /*}*/
