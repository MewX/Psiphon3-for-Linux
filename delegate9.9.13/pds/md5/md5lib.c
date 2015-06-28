#include "global.h"
#include "md5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char HEXCH[] = "0123456789abcdef";

void MD5toa(const char *digest,char md5a[])
{	char *mp; /*QA(QF)*/
	unsigned char dg1;
	unsigned int i;

	mp = md5a;
	for (i = 0; i < 16; i++){
		dg1 = digest[i];
		*mp++ = HEXCH[dg1 >>4];
		*mp++ = HEXCH[dg1&0xF];
	}
	*mp = 0;
}
void toMD5X(const char *str,int len,char digest[]);
void toMD5(const char *str,char md5[])
{	char digest[16];

	toMD5X(str,strlen(str),digest);
	MD5toa(digest,md5);
}
void toMD5X(const char *str,int len,char digest[])
{	MD5_CTX context;

	MD5Init(&context);
	MD5Update(&context, (unsigned char*)str, len);
	MD5Final((unsigned char*)digest, &context);
}
void toMD5Y(const char *str,int len,char md5[]){
	char digest[16];
	toMD5X(str,len,digest);
	MD5toa(digest,md5);
}
int fMD5(FILE *fp,char digest[])
{	MD5_CTX context;
	char buf[1024];
	int rcc;

	MD5Init(&context);
	while( 0 < (rcc = fread(buf,1,sizeof(buf),fp)) )
		MD5Update(&context,(unsigned char*)buf,rcc);
	MD5Final((unsigned char*)digest, &context);
	return 0;
}
void ftoMD5(FILE *fp,char md5[])
{	MD5_CTX context;
	char digest[16];
	char buf[1024];
	int rcc;

	MD5Init(&context);
	while( 0 < (rcc = fread(buf,1,sizeof(buf),fp)) )
		MD5Update(&context,(unsigned char*)buf,rcc);
	MD5Final((unsigned char*)digest, &context);
	MD5toa(digest,md5);
}
int msgMD5(FILE *fs,FILE *tc,char md5a[])
{	MD5_CTX context;
	char digest[16];
	char buf[1024];
	int size,len;

	size = 0;
	MD5Init(&context);
	while( fgets(buf,sizeof(buf),fs) != NULL ){
		if( tc != NULL )
			fputs(buf,tc);
		if( buf[0] == '.' && buf[1] == '\r' )
			break;
		len = strlen(buf);
		size += len;
		MD5Update(&context,(unsigned char*)buf,len);
	}
	MD5Final((unsigned char*)digest,&context);
	MD5toa(digest,md5a);
	return size;
}
MD5_CTX *newMD5()
{	MD5_CTX *ctx;

	ctx = (MD5_CTX*)calloc(1,sizeof(MD5_CTX));
	MD5Init(ctx);
	return ctx;
}
void addMD5(MD5_CTX *ctx,const char *str,int len)
{
	MD5Update(ctx,(unsigned char*)str,len);
}
void endMD5(MD5_CTX *ctx,char digest[])
{
	MD5Final((unsigned char*)digest,ctx);
	free(ctx);
}

int startMD5(void *ctx,int size){
	if( size < sizeof(MD5_CTX) ){
		return -(int)sizeof(MD5_CTX);
	}else{
		MD5Init((MD5_CTX*)ctx);
		return 0;
	}
}
int updateMD5(void*ctx,const char *str,int len){
	MD5Update((MD5_CTX*)ctx,(unsigned char*)str,len);
	return 0;
}
int finishMD5(void *ctx,char md5b[],char md5a[]){
	char digest[32];
	char md5ax[64];

	if( md5b == 0 )
		md5b = digest;
	if( md5a == 0 )
		md5a = md5ax;
	MD5Final((unsigned char*)md5b,(MD5_CTX*)ctx);
	MD5toa(md5b,md5a);
	return 0;
}
