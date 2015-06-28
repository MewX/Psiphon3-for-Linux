/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:   program/C; charset=US-ASCII
Program:        pelcgb.c (cheap cryption functions)
Author:         Yutaka Sato <ysato@delegate.org>
Description:
	"pelcgb" = ROT13("crypto")
	non-parallelism oriented cryption algorithm
	might be replaced by a standard algorithm like Rijndael
History:
        030919	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "ystring.h"
#include "credhy.h"
void toMD5X(PCStr(key),int klen,char digest[]);

#define BSIZE	16
#define NVARS	2

#define OCT_SFTX(hs,ls,hm,lm) {  \
	for( oi = 0; oi < elen; oi++ ){  \
		ch = octs[oi];  \
		if( enc ) \
			octs[oi] = (hm&(ch>>hs))|(ch<<ls);  \
		else	octs[oi] = (ch<<hs)|(lm&(ch>>ls));  \
	}  \
}
#define OCT_SFTN(n)	OCT_SFTX(n,(8-n),(0xFF>>n),(0xFF>>(8-n)))
#define OCT_SFT2()	OCT_SFTN(2)
#define OCT_SFT3()	OCT_SFTN(3)
#define OCT_SWAP()	OCT_SFTN(4)

#define OCT_SHUF() if( op != preop ){ \
	for( oi = 0; oi < elen; oi++ ){ \
		ch = octs[oi]; \
		octs[oi] = (0xCC&(ch<<2))|(0x33&(ch>>2)); \
	} \
}

#define STR_INCX(inc1) { \
	inc = enc ? inc1 : -inc1; \
	for( oi = 0; oi < elen; oi++ ){ \
		octs[oi] += inc; \
		inc += enc ? inc1 : -inc1; \
	} \
}
#define STR_INC1()	STR_INCX( 31)
#define STR_INC2()	STR_INCX( 53)
#define STR_INC3()	STR_INCX( 71)
#define STR_INC4()	STR_INCX( 97)
#define STR_INC5()	STR_INCX(113)
#define STR_INC6()	STR_INCX(131)
#define STR_INC7()	STR_INCX(173)

#define STR_BSFX(hs,ls,hm,lm) { \
	if( enc ){ \
		ch = octs[0]; \
		for( oi = 0; oi < elen-1; oi++ ) \
		octs[oi] = (octs[oi]<<hs) | ((octs[oi+1]>>ls) & lm); \
		octs[oi] = (octs[oi]<<hs) | ((ch>>ls) & lm); \
	}else{ \
		ch = octs[elen-1]; \
		for( oi = elen-1; 0 < oi; oi-- ) \
		octs[oi] = (hm & (octs[oi]>>hs)) | (octs[oi-1]<<ls); \
		octs[oi] = (hm & (octs[oi]>>hs)) | (ch<<ls); \
	} \
}
#define STR_BSFN(n)	STR_BSFX(n,(8-n),(0xFF>>n),(0xFF>>(8-n)))
#define STR_BSF3()	STR_BSFN(3)

#define STR_REVN(nr) if( op != preop ){ \
	base = 0; \
	for( oi = 0; oi < elen/nr; oi++ ){ \
		ch = octs[base]; \
		octs[base] = octs[base+(nr-1)]; \
		octs[base+(nr-1)] = ch; \
		base += nr; \
	} \
}
#define STR_REV2()	STR_REVN(2)
#define STR_REV3()	STR_REVN(3)
#define STR_REV4()	STR_REVN(4)

#define STR_SWAP() if( op != preop ){ \
	base = elen/2; \
	for( oi = 0; oi < base; oi++ ){ \
		ch = octs[base+oi]; \
		octs[base+oi] = octs[oi]; \
		octs[oi] = ch; \
	} \
}
#define STR_SHUF() if( op != preop ){ \
	int base2,base3; \
	base = elen/4; \
	base2 = base*2; \
	base3 = base*3; \
	for( oi = 0; oi < base; oi++ ){ \
		ch = octs[oi]; \
		octs[oi] = octs[base+oi]; \
		octs[base+oi] = ch; \
		ch = octs[base2+oi]; \
		octs[base2+oi] = octs[base3+oi]; \
		octs[base3+oi] = ch; \
	} \
}

#define _OCT_SFT2	0x01
#define _OCT_SFT3	0x02
#define _OCT_SWAP	0x03
#define _OCT_SHUF	0x04

#define _STR_INC1	0x11
#define _STR_INC2	0x12
#define _STR_INC3	0x13
#define _STR_INC4	0x14

#define _STR_REV3	0x21
#define _STR_REV4	0x22
#define _STR_SWAP	0x23
#define _STR_SHUF	0x24

#define _STR_INC5	0x31
#define _STR_INC6	0x32
#define _STR_INC7	0x30
#define _STR_BSF3	0x33

static char MAPS[NVARS][16] = {
    {
	_OCT_SFT2, _OCT_SFT3, _OCT_SWAP, _OCT_SHUF,
	_STR_INC1, _STR_INC2, _STR_INC3, _STR_INC4,
	_STR_INC5, _STR_INC6, _STR_INC7, _STR_BSF3,
	_STR_REV3, _STR_REV4, _STR_SWAP, _STR_SHUF,
    },
    {
	_STR_INC5, _STR_INC6, _STR_INC7, _STR_BSF3,
	_STR_REV3, _STR_REV4, _STR_SWAP, _STR_SHUF,
	_STR_INC1, _STR_INC2, _STR_INC3, _STR_INC4,
	_OCT_SFT2, _OCT_SFT3, _OCT_SWAP, _OCT_SHUF,

    }
};

static int debug;
static void encdec_block(int map,int enc,int seq,int off,PCStr(key),int klen,char octs[],int elen)
{	int ki,kx,oi,op,preop,ch,base,inc;

	preop = -1;
	for( ki = 0; ki < klen; ki++ ){
		kx = key[ki] & 0xF;
		op = MAPS[map][kx];

		switch( op ){
			case _OCT_SHUF: OCT_SHUF(); break;
			case _OCT_SFT2: OCT_SFT2(); break;
			case _OCT_SFT3: OCT_SFT3(); break;
			case _OCT_SWAP: OCT_SWAP(); break;

			case _STR_INC1: STR_INC1(); break;
			case _STR_INC2: STR_INC2(); break;
			case _STR_INC3: STR_INC3(); break;
			case _STR_INC4: STR_INC4(); break;

			case _STR_INC5: STR_INC5(); break;
			case _STR_INC6: STR_INC6(); break;
			case _STR_INC7: STR_INC7(); break;
			case _STR_BSF3: STR_BSF3(); break;

			case _STR_REV3: STR_REV3(); break;
			case _STR_REV4: STR_REV4(); break;
			case _STR_SWAP: STR_SWAP(); break;
			case _STR_SHUF: STR_SHUF(); break;

			default:
				fprintf(stderr,"Crypty ERROR 0x%02X\n",op);
				break;
		}
		preop = op;
	}

	if( debug && enc ){
		static int cum;
		int cnt[256],idx[256],nidx;
		for( oi = 0; oi < 256; oi++ )
			cnt[oi] = 0;
		for( oi = 0; oi < elen; oi++)
			cnt[0xFF & octs[oi]] += 1;

		nidx = 0;
		for( oi = 0; oi < 256; oi++){
			if( debug < cnt[oi] )
				idx[nidx++] = oi;
		}
		if( nidx ){
			fprintf(stderr,"## %2d #%4d len=%3d ",++cum,seq,elen);
			for( oi = 0; oi < nidx; oi++ ){
			fprintf(stderr,"[%02X]%2d ",idx[oi],cnt[idx[oi]]);
			}
			fprintf(stderr,"\n");
		}
	}
}

#define PHEAD_CRC	0 /* CRC in 8bits */
#define PHEAD_PLEN	1 /* padding length */
#define PHEAD_SIZE	2

#define STR_scramble() { \
	inc = 0; \
	inc1 = seq + pcrc + out[0]; \
	for( oi = 1; oi < elen; oi++ ){ \
		inc += inc1; \
		if( enc ) \
			out[oi] += inc; \
		else	out[oi] -= inc; \
	} \
}

static int encdec(int map,int enc,int seq,int *crcp,int off,PCStr(key),int klen,PCStr(ins),int ilen,char out[])
{	int ki,oi,ox,elen,inc,inc1,crc,pcrc;

	if( map < 0 || NVARS <= map ){
		return 0;
	}
	pcrc = *crcp;

	if( enc ){
		crc = strCRC8(pcrc,ins,ilen);
		*crcp = crc;
		elen = ((PHEAD_SIZE+ilen-1)/BSIZE+1) * BSIZE;

		out[PHEAD_CRC] = crc;
		out[PHEAD_PLEN] = elen - ilen; /* length of header+padding */
		ox = PHEAD_SIZE;
		for( oi = 0; oi < ilen; oi++ )
			out[ox++] = ins[oi];

		if( ox < elen ){ /* padding something random (optional) */
			oi = 0;
			while( ox < elen ){
				out[ox++] = (out[oi++] + ox) + crc;
				crc += ox;
			}
		}
		STR_scramble();
		encdec_block(map,enc,seq,off,key,klen,out,elen);
	}else{
		for( oi = 0; oi < ilen; oi++ )
			out[oi] = ins[oi];
		elen = ilen;

		encdec_block(map,enc,seq,off,key,klen,out,elen);
		STR_scramble();

		elen = ilen - (0xFF & out[PHEAD_PLEN]);
		crc = strCRC8(pcrc,out+PHEAD_SIZE,elen);
		if( crc != (0xFF& out[PHEAD_CRC]) ){
			syslog_ERROR("CRC ERROR %X %X\n",crc,out[PHEAD_CRC]);
			return -1;
		}
		for( oi = 0; oi < elen; oi++ )
			out[oi] = out[PHEAD_SIZE+oi];
		*crcp = crc;
	}
	return elen;
}

static int setbkey(int enc,int klen,PCStr(key),int bklen,char bkey[])
{	int ki,bki;
	CStr(digest,16);
	char ch;

	if( klen < 0 ){
		const char *hexch = "0123456789ABCDEF";
		const char *dp;
		char ch;
		klen = -klen;
		for( bki = 0; bki < klen; bki++ ){
			ch = key[bki];
			if( islower(ch) )
				ch = toupper(ch);
			dp = strchr(hexch,ch);
			if( dp == 0 )
				return -1;
			bkey[bki] = dp - hexch;
		}
		if( bki < bklen )
			bklen = bki;
	}else{
		toMD5X(key,klen,digest);
		bki = 0;
		for( ki = 0; ki < 16; ki++ ){
			bkey[bki++] = 0xF & (digest[ki]>>4);
			bkey[bki++] = 0xF & digest[ki];
		}
		if( bki < bklen )
			bklen = bki;
		if( !enc ){
			for( bki = 0; bki < bklen/2; bki++ ){
				ch = bkey[bklen-1-bki];
				bkey[bklen-1-bki] = bkey[bki];
				bkey[bki] = ch;
			}
		}
		/*
		if( debug && enc ){
		*/
		if( debug ){
			fprintf(stderr,"KEY< '%s'(%d) ",key,bklen);
			for( ki = 0; ki < bklen; ki++ )
				fprintf(stderr,"%X",bkey[ki]);
			fprintf(stderr,"\n");
		}
	}
	return bklen;
}

int fencrypty(FILE *in,FILE *out,int klen,char key[],int bklen)
{	CStr(bkey,64);
	CStr(dkey,64);
	CStr(ibuf,256);
	CStr(obuf,256);
	CStr(dkdigest,16);
	int rcc,oi,elen,xelen,wcc;
	int map = 0;
	int seq,off;
	int sum = 0,psum;

	bklen = setbkey(1,klen,key,bklen,bkey);
	wcc = 0;
	fwrite("PELC",1,4,out);
	putc(map,out);

	setbkey(0,klen,key,bklen,dkey);
	toMD5X(dkey,bklen,dkdigest);
	seq = sum = off = 0;
	elen = encdec(map,1,seq,&sum,off,bkey,bklen,dkdigest,16,obuf);
	putc(elen,out);
	wcc = fwrite(obuf,1,elen,out);

	off = 0;
	sum = 0;
	wcc = 0;
	for( seq = 0; ; seq++ ){
		rcc = fread(ibuf,1,sizeof(ibuf)-PHEAD_SIZE,in);
		if( rcc <= 0 )
			break;

		psum = sum;
		elen = encdec(map,1,seq,&sum,off,bkey,bklen,ibuf,rcc,obuf);
		xelen = elen ^ psum; /* scramble the packet length */
		for( oi = 0; oi < 3; oi++ )
			putc(0xFF&(xelen>>(8*(3-1-oi))),out);
		wcc += 3;
		fwrite(obuf,1,elen,out);
		wcc += elen;
		off += rcc;
	}
	for( oi = 0; oi < 3; oi++ )
		putc(0,out);
	return wcc;
}
int fdecrypty(FILE *in,FILE *out,int klen,char key[],int bklen)
{	int ilen,ii,olen,ch,rcc,wcc,xelen;
	CStr(bkey,64);
	CStr(dkdg,32);
	CStr(dkey,64);
	char ki;
	CStr(dgkkey,16);
	CStr(dgckey,16);
	CStr(ibuf,256);
	CStr(obuf,256);
	int map;
	int seq,off;
	int sum = 0;
	void *md5;

	bklen = setbkey(0,klen,key,bklen,bkey);
	wcc = 0;
	rcc = fread(ibuf,1,4,in);
	if( rcc != 4 || strncmp(ibuf,"PELC",4) != 0 ){
		fprintf(stderr,"Unknown magic: %X %X %X %X\n",
			ibuf[0],ibuf[1],ibuf[2],ibuf[3]);
		goto EXIT;
	}
	map = 0xF & getc(in);
	if( map < 0 || NVARS <= map ){
		fprintf(stderr,"Unknown map: %d\n",map);
		goto EXIT;
	}

	ilen = getc(in);
	rcc = fread(dkdg,1,QVSSize(dkdg,ilen),in);
	seq = sum = off = 0;
	olen = encdec(map,0,seq,&sum,off,bkey,bklen,dkdg,rcc,dgkkey);
	toMD5X(bkey,bklen,dgckey);
	if( bcmp(dgkkey,dgckey,16) != 0 ){
		/* find a key of which MD5 is dgckey ... */
		fprintf(stderr,"Unknown key\n");
		goto EXIT;
	}

	off = 0;
	sum = 0;
	for( seq = 0; !feof(in); seq++ ){
		xelen = 0;
		for( ii = 0; ii < 3; ii++ ){
			if( (ch = getc(in)) == EOF )
				goto EXIT;
			xelen = (xelen << 8) | ch;
		}
		if( xelen == 0 ){
			break;
		}
		ilen = xelen ^ sum;

		if( sizeof(ibuf) < ilen ){
			fprintf(stderr,"Too large chunk: %d\n",ilen);
			goto EXIT;
		}
		rcc = fread(ibuf,1,QVSSize(ibuf,ilen),stdin);
		if( rcc <= 0 )
			break;
		olen = encdec(map,0,seq,&sum,off,bkey,bklen,ibuf,rcc,obuf);
		fwrite(obuf,1,olen,out);
		wcc += olen;
		off += wcc;
	}
	rcc = fread(ibuf,1,16,in);
EXIT:
	return wcc;
}
int sencdecrypty(int enc,int map,int klen,PCStr(key),int bklen,PCStr(ins),int ilen,char out[])
{	int len,oi;
	CStr(bkey,64);
	int sum = 0;

	if( debug ){
		fprintf(stderr,"%s< ",enc?"ENC":"DEC");
		for( oi = 0; oi < ilen; oi++ )
			fprintf(stderr,"%02X ",0xFF&ins[oi]);
		fprintf(stderr,"\n");
	}

	bklen = setbkey(enc,klen,key,bklen,bkey);
	len = encdec(map,enc,0,&sum,0,bkey,bklen,ins,ilen,out);

	if( debug ){
		fprintf(stderr,"%s> ",enc?"ENC":"DEC");
		for( oi = 0; oi < len; oi++ )
			fprintf(stderr,"%02X ",0xFF&out[oi]);
		fprintf(stderr,"\n");
	}
	return len;
}
int sencrypty(int map,int klen,PCStr(key),int bklen,PCStr(ins),int ilen,char out[])
{
	return sencdecrypty(1,map,klen,key,bklen,ins,ilen,out);
}
int sdecrypty(int map,int klen,PCStr(key),int bklen,PCStr(ins),int ilen,char out[])
{
	return sencdecrypty(0,map,klen,key,bklen,ins,ilen,out);
}
int aencryptyX(PCStr(key),int klen,PCStr(ins),int ilen,PVStr(out))
{	int len,oi,ci,ch;

	len = sencdecrypty(1,0,klen,key,32,ins,ilen,(char*)out);
	setVStrElem(out,len*2,0);
	for( oi = len-1; 0 <= oi; oi-- ){
		ch = out[oi];
		ci = oi*2;
		setVStrElem(out,ci+1, "0123456789ABCDEF"[0xF & ch]);
		setVStrElem(out,ci,   "0123456789ABCDEF"[0xF & (ch>>4)]);
	}
	return len*2;
}
int adecrypty(PCStr(key),int klen,PCStr(ins),int ilen,char out[])
{	int bilen,len,oi,ci,cj,ch,och;
	char *bins; /**/

	bilen = ilen / 2;
	bins = (char*)malloc(bilen);
	for( oi = 0; oi < bilen; oi++ ){
		ci = oi*2;
		och = 0;
		for( cj = 0; cj < 2; cj++ ){
			ch = 0xFF & ins[ci+cj];
			ch = ('0'<=ch && ch<='9')?ch-'0':ch-'A'+10;
			och = (och << 4) | (0xF & ch);
		}
		bins[oi] = och;
	}
	len = sencdecrypty(0,0,klen,key,32,bins,bilen,out);
	if( 0 < len )
		out[len] = 0;
	else	out[0] = 0;
	free(bins);
	return len;
}

#ifdef MAIN
int pelcgb_main(int ac,const char *av[]);
int main(int ac,char *av[])
{
	pelcgb_main(ac,av);
	return 0;
}
#endif

int pelcgb_main(int ac,const char *av[])
{	CStr(out,1024);
	CStr(dec,1024);
	const char *arg;
	const char *env;
	const char *key = "1";
	const char *mkey = 0;
	/*
	const char *ins = "012345\01\02\03\04\05\377";
	*/
	const char *ins = "012345abcdef";
	int ai,ax,len;
	int map = 0;
	int enc = -1;
	int bklen = 32;
	int klen;

	if( env = getenv("CCRYMAP") ) map = atoi(env);
	if( env = getenv("CCRYLEN") ) bklen = atoi(env);
	if( env = getenv("CCRYDEBUG") ) debug = atoi(env);

	ax = 0;
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( *arg == '-' ){
			if( strncmp(arg,"-m",2) == 0 ) map = atoi(arg+2);
			if( strncmp(arg,"-l",2) == 0 ) bklen = atoi(arg+2);
			if( strncmp(arg,"-D",2) == 0 ) debug = atoi(arg+2);
			if( strncmp(arg,"-k",2) == 0 ) mkey = arg+2;
			if( strcmp(arg,"-e") == 0 ) enc = 1;
			if( strcmp(arg,"-d") == 0 ) enc = 0;
		}else{
			switch( ax ){
				case 0: key = arg; break;
				case 1: ins = arg; break;
			}
			ax++;
		}
	}
	if( ac == 1 ){
		strcpy(out,"CRYPTO");
		strrot13(out);
		fprintf(stderr,"CRYPTO => %s\n",out);
	}
	if( mkey ){
		key = mkey;
		klen = -strlen(mkey);
	}else{
		klen = strlen(key);
	}
	if( enc == 1 ){
		/*
		fencrypty(stdin,stdout,klen,key,bklen);
		*/
		fencrypty(stdin,stdout,klen,(char*)key,bklen);
		exit(0);
	}
	if( enc == 0 ){
		/*
		fdecrypty(stdin,stdout,klen,key,bklen);
		*/
		fdecrypty(stdin,stdout,klen,(char*)key,bklen);
		exit(0);
	}
	len = sencrypty(map,klen,key,bklen,ins,strlen(ins),out);

	{	int oi;
		fprintf(stderr,"xxxx [%s] ",key);
		for( oi = 0; oi < len; oi++ )
			fprintf(stderr,"%02X ",0xFF&out[oi]);
		fprintf(stderr,"\n");
	}

	len = sdecrypty(map,klen,key,bklen,out,len,dec);
	if( bcmp(ins,dec,strlen(ins)) != 0 ){
		fprintf(stderr,"ERROR\n");
	}

	len = aencryptyX(key,klen,ins,strlen(ins),AVStr(out));
	len = adecrypty(key,klen,out,len,dec);
	return 0;
}

void strrot13(char str[])
{	char *s; /**/
	char ch;

	for( s = str; ch = *s; s++ ){
		if( 'a' <= ch && ch <= 'z' )
			*s = (ch-'a'+13)%26+'a';
		else
		if( 'A' <= ch && ch <= 'Z' )
			*s = (ch-'A'+13)%26+'A';
		else	*s = ch;
	}
}

