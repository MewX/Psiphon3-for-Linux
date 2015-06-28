/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003-2008 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	cksum.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	070310	extracted from credhy.c
//////////////////////////////////////////////////////////////////////#*/
#ifdef MKMAKE
#define PCStr(s)	const char *s
#define CStr(s,z)	char s[z]
#define IStr(s,z)	char s[z]={0}
static int IgnRet;
#define IGNRETS		IgnRet=0!=
#else
#include "ystring.h"
#endif
#ifdef MAIN
#define Xfopen		fopen
#define Xfprintf	fprintf
#endif

/* 1 0000 0100 1100 0001 0001 1101 1011 0111 */
#define CRC32POLY 0x04C11DB7
int strCRC32add(int crc,PCStr(str),int len)
{	int oi,bi,ovf;
	const char *s;
	char oct;

	s = str;
	for( oi = 0; oi < len; oi++ ){
		oct = *s++;
		for( bi = 0; bi < 8; bi++ ){
			/*
			ovf = (crc < 0) ^ (oct < 0);
			*/
			ovf = ((crc & 0x80000000) != 0) ^ ((oct & 0x80) != 0);
			oct <<= 1;
			crc <<= 1;
			if( ovf ) crc ^= CRC32POLY;
		}
	}
	return crc;
}
int strCRC32end(int crc,int len)
{	CStr(slen,4);
	int li;

	for( li = 0; li < 4; li ){
		slen[li++] = len;
		len >>= 8;
		if( len == 0 )
			break;
	}
	crc = strCRC32add(crc,slen,li);
	crc ^= 0xFFFFFFFF;
	return crc;
}
int strCRC32(PCStr(str),int len)
{	int crc;

	crc = strCRC32add(0,str,len);
	crc = strCRC32end(crc,len);
	return crc;
}
int fcrc32X(FILE *fp,int *len){
	int crc32;
	CStr(buf,8*1024);
	int nth;
	int rcc;

	crc32 = 0;
	nth = 0;
	while( 0 < (rcc = fread(buf,1,sizeof(buf),fp)) ){
		crc32 = strCRC32add(crc32,buf,rcc);
		nth += rcc;
	}
	crc32 = strCRC32end(crc32,nth);
	if( len ) *len = nth;
	return crc32;
}
int cksum(const char *file){
	FILE *fp;
	FILE *sum;
	CStr(sumfile,128);
	CStr(dir,128);
	const char *dp;
	int crc32;
	int len;

	if( strchr(file,'/') ){
		IStr(cwd,256);
		IGNRETS getcwd(cwd,sizeof(cwd));
		fprintf(stderr,"[%s]cksum(%s)\n",cwd,file);
	}
	if( fp = fopen(file,"r") ){
		if( (dp = strrchr(file,'/')) || (dp = strrchr(file,'\\')) ){
			strcpy(dir,file);
			dir[(dp+1)-file] = 0;
			sprintf(sumfile,"%s.cksum.%s",dir,dp+1);
		}else{
			sprintf(sumfile,".cksum.%s",file);
		}
		if( sum = fopen(sumfile,"w") ){
			crc32 = fcrc32X(fp,&len);
			fprintf(sum,"%u %d %s\n",crc32,len,file);
			fclose(sum);
			fclose(fp);
			return 0;
		}
		else{
			fprintf(stderr,"ERROR: cksum: cannot write %s\n",sumfile);
		}
		fclose(fp);
	}
	else{
		fprintf(stderr,"ERROR: cksum: cannot read %s\n",file);
	}
	return -1;
}
static unsigned int fcsum(FILE *fp,int *lines,int opt_c){
	unsigned int sum;
	int nl = 0;
	CStr(line,1024);
	int ch;
	int ci;

	sum = 0;
	if( opt_c ){
		while( fgets(line,sizeof(line),fp) != NULL ){
			for( ci = 0; ch = line[ci]; ci++ ){
				sum += ch;
			}
			nl++;
			if( strstr(line,"/* '\"DIGEST-OFF\"' */") )
				break;
		}
	}else{
		while( (ch = getc(fp)) != EOF ){
			sum += ch;
			if( ch == '\n' )
				nl++;
		}
	}
	if( lines ){
		*lines += nl;
	}
	return sum;
}
#ifndef fileIsdir
int fileIsdir(PCStr(path));
#endif
int cksum_main1(int ac,const char *av[],FILE *out,FILE *err){
	int rcode = 0;
	int crc32;
	int len = 0;
	const char *file = 0;
	FILE *fp;
	int ai;
	int opt_c = 0;
	int opt_n = 0;
	int opt_t = 0;
	int opt_v = 0;
	int opt_x = 0;
	int nf = 0;
	int tcrc32 = 0; /* total CRC of multiple files */
	unsigned int chsum = 0;
	unsigned int bytes = 0;
	int lines = 0;
	int files = 0;

	for( ai = 1; ai < ac; ai++ ){
		if( *av[ai] == '-' ){
			switch( av[ai][1] ){
				case 'c':
					opt_c = 1;
					break;
				case 'n':
					opt_n = 1;
					break;
				case 't':
					opt_t = 1;
					break;
				case 'v':
					opt_v = 1;
					break;
				case 'x':
					opt_x = 1;
					break;
			}
		}else{
			file = av[ai];
			if( opt_x ){
				if( fileIsdir(file) ){
				}else
				if( fp = fopen(file,"r") ){
					chsum += fcsum(fp,&lines,opt_c);
					bytes += ftell(fp);
					files++;
					fclose(fp);
					if( opt_v ){
		fprintf(out,"files-lines-bytes-chsum: %d %d %d %X %s\n",
			files,lines,bytes,chsum,file);
					}
				}
			}else
			if( opt_c ){
				cksum(file);
			}else{
				fp = fopen(file,"r");
				if( fp == NULL ){
					fprintf(err,"%s: can't open\n",file);
					rcode = -1;
				}else{
					crc32 = fcrc32X(fp,&len);
					if( opt_n )
						fprintf(out,"%d ",++nf);
					if( opt_t ){
						/* timestamp */
					}
					fprintf(out,"%u %d %s\n",crc32,len,file);
					fclose(fp);
				}
			}
		}
	}
	if( file == 0 ){
		crc32 = fcrc32X(stdin,&len);
		fprintf(out,"%u %d\n",crc32,len);
	}
	if( opt_x ){
		CStr(host,256);
		host[0] = 0;
		gethostname(host,sizeof(host));
		fprintf(out,"Total-file-line-byte-csum: %d %d %d %X %s\n",
			files,lines,bytes,chsum,host);
	}
	return  rcode;
}
int cksum_main(int ac,const char *av[]){
	int ai,nac;
	const char *nav[1024];
	FILE *fp;
	CStr(line,1024);
	char *dp;

	nac = 0;
	for( ai = 0; ai < ac; ai++ ){
		if( strcmp(av[ai],"-f") == 0 )
		if( ai+1 < ac ){
			ai++;
			if( fp = fopen(av[ai],"r") ){
				while( fgets(line,sizeof(line),fp) ){
					if( dp = strpbrk(line,"\r\n") )
						*(char*)dp = 0;
					nav[nac++] = strdup(line);
				}
				fclose(fp);
			}
			else{	/* v9.9.9 fix-140609a */
				fprintf(stderr,"%s: cannot open -f %s\r\n",
					av[0],av[ai]);
				exit(-1);
			}
			continue;
		}
		nav[nac++] = av[ai];
	}
	if( nac != ac ){
		nav[nac] = 0;
		return cksum_main1(nac,nav,stdout,stderr);
	}else
	return cksum_main1(ac,av,stdout,stderr);
}

#ifdef MAIN
int main(int ac,char *av[]){
	return cksum_main(ac,(const char**)av);
}
#endif
