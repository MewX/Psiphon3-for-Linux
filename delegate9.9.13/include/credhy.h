#ifndef _CREDHY_H
#define _CREDHY_H
#include "ystring.h"

typedef struct {
	int	k_group; /* the set of G and P */
	int	k_active;
	int	k_flags;
	int	k_crc8;
	int	k_idx;
	int	k_leng;
   unsigned int	k_myrand[4];
	char	k_lcrc8[1];
	char	k_rcrc8[1];
	xMStr(	k_str,128);
} Credhy;
#ifdef NONEMPTYARRAY
#define k_strBASE k_str
#endif
#define CR_AKFIRST	1 /* Addkey before CRC */
#define CR_CRC32	2 /* use CRC32 instead of CRC8 */

static struct crc8a {
	unsigned char	c_crc[256][256];
} *CRC8a;
#define CRC8(crc,ch) (CRC8a?(CRC8a->c_crc[0xFF&crc][0xFF&ch]):CRC8f(crc,ch))

int strCRC32(PCStr(str),int len);
int strCRC32add(int crc,PCStr(str),int len);
int strCRC32end(int crc,int len);
void strrot13(char src[]);
int strCRC16(short int crc,PCStr(str),int len);
int strCRC8(int,PCStr(str),int);
int fcrc32(FILE *fp);

int adecrypty(PCStr(key),int klen,PCStr(ins),int ilen,char out[]);
int aencryptyX(PCStr(key),int klen,PCStr(ins),int ilen,PVStr(out));
#define aencrypty(key,klen,ins,ilen,ob) aencryptyX(key,klen,ins,ilen,AVStr(ob))

int CredhyClientStart(PCStr(com),Credhy *K,FILE *ts,FILE *fs,int okcode);
int CredhyServerStart(PCStr(com),Credhy *K,FILE *tc,FILE *fc,PCStr(sykey),int okcode,int errcode);
int CredhyAencrypt(Credhy *K,PCStr(src),PVStr(enc),int esiz);
int CredhyAdecrypt(Credhy *K,PCStr(enc),PVStr(dec),int dsiz);
int CredhyEncrypt(Credhy *K,int len,PCStr(src),char enc[]);
int CredhyDecrypt(Credhy *K,int len,char enc[],char src[]);

#define CREY_DAZZLE	0x0001
int CreyEncryptsX(int opts,PCStr(key),int klen,PVStr(str),int slen);
int CreyDecryptsX(int opts,PCStr(key),int klen,PVStr(str),int slen);
int CreyEncrypts(PCStr(key),int klen,PVStr(str),int slen);
int CreyDecrypts(PCStr(key),int klen,PVStr(str),int slen);

int CredhyGenerateKey(Credhy *K,PVStr(ykey),int siz);
void CredhyInit(Credhy *K,int grp);
int CredhyAgreedKey(Credhy *K,PCStr(ykey));
int strtoHex(PCStr(str),int len,PVStr(out),int siz);

int DH_rand32();

#endif /* _CREDHY_H */
