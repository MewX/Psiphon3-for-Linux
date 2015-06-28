/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

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
Program:	embed.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941001	created
	970104	self wild-card extension
//////////////////////////////////////////////////////////////////////#*/
#ifndef UNDER_CE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
/*
#include <sys/stat.h>
*/
#include <time.h>
#include "ystring.h"
/*
#define STAT32
*/
#include "file.h"
#ifndef IMPSIZE
#define IMPSIZE 10000
#endif

#ifdef fopen /* mapped to Xfopen() */
#undef fopen
#endif
#ifdef fclose
#undef fclose
#endif

int fileN;
int textR;

int checkVer();
unsigned int verFpi(int seed);
const char *DELEGATE_ver();
char *getUsername(int uid,PVStr(name));
char *getGroupname(int gid,PVStr(name));

int file1(PCStr(path))
{	FILE *fp;
	int nc,col,ch;
	int cr,lf;
	int bin;
	FileStat st;
	int textseg;

	if( strstr(path,"/._") ){ /* fix-140529c */
		if( 0 )
		{
			fprintf(stderr,"ignored Mac: %s\n",path);
		}
		return 0;
	}
	stat(path,&st);
	fp = fopen(path,"r");
	if( fp == NULL ){
		fprintf(stderr,"cannot open: %s\n",path);
		return 0;
	}

	textseg = textR < fileN;
	if( textseg )
		printf("#define FILE_%03d \"",fileN++);
	else	printf("static char FILE_%03d[] = \"",fileN++);

	printf("%-8x",(int)st.st_size);
	printf("%-8x",(int)st.st_mtime);
	printf("\\\n%s\\000\\\n",path);

	nc = 0;
	col = 0;
	cr = 0;
	lf = 0;
	bin = 0;
	while( (ch = getc(fp)) != EOF ){
		if( 0 < nc && nc % 2048 == 0 ){
			printf("\"\"");
		}
		nc++;
		if( 70 <= col ){
			printf("\\\n");
			col = 0;
		}
		if( ch == '\n' && !bin ){ printf("\\n\\\n"); col = 0; lf++;}else
		if( ch == '\r' && !bin ){ printf("\\r");    col += 2; cr++;}else
		if( ch == '\t' && !bin ){ printf("\\t");    col += 2; }else
		if( ch == '"'  && !bin ){ printf("\\\"");   col += 2; }else
		if( ch == '\\' && !bin ){ printf("\\\\");   col += 2; }else
		if( bin || ch<0x20 || 0x7F<=ch || ch=='"' || ch=='\\' ){
			/*
			if( 0x80 <= ch )
			*/
			if( ch == 0 )
				bin = 1;
			printf("\\%03o",ch);
			col += 4;
		}else{
			printf("%c",ch);
			col += 1;
		}
	}
	if( cr == 0 && 2048 < nc + lf ){
	fprintf(stderr,"#### WARNING: \"%s\"\n",path);
	fprintf(stderr,"#### This string value will over flow (%d+%d)\n",
		nc,lf);
	fprintf(stderr,"#### on the system where line ends with CR LF\n");
	}
	if( textseg )
		printf("\"\n\n",nc,st.st_mtime);
	else	printf("\";\n\n",nc,st.st_mtime);
	fclose(fp);
	return 0;
}

scanDirFunc dir1(PCStr(file),PCStr(filter),PCStr(curdir),PCStr(recursive))
{	CStr(ncurdir,1024);
	const char *pp;
	CStr(path,1024);
	int plen;

	if( recursive && file[0] != '.' ){
		sprintf(ncurdir,"%s/%s",curdir,file);
		Scandir(ncurdir,scanDirCall dir1,filter,ncurdir,recursive);
	}

	if( filter[0] == '*' ){
		if( (pp = strstr(file,filter+1)) == NULL )
			return 0;
		if( pp[strlen(filter+1)] != 0 )
			return 0;
	}else{
		if( strcmp(file,filter) != 0 )
			return 0;
	}
	sprintf(path,"%s/%s",curdir,file);
	file1(path);
	return 0;
}

int enCreys(PCStr(opts),PCStr(pass),PCStr(data),PVStr(edata),int esize);
int main(int ac,char *av[])
{	int ai;
	CStr(dirfile,1024);
	const char *filter;
	const char *recursive;
	int randi;
	CStr(user,64);
	CStr(date,512);
	CStr(buf,512);
	CStr(eimp,1024);
	CStr(imp,1024);
	refQStr(bp,imp);
	int sl,si;
	const char *a1;
	const char *az;
	int nac;
	const char **nav;
	int impsize = IMPSIZE;
	int impcc;
	int impoff;
	int impchunk;

	if( checkVer() != 0 ){
		return -1;
	}

	setBinaryIO();

	nav = (const char**)av;
	nac = 1;
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( az = strheadstrX(a1,"-IMPSIZE=",0) ){
			impsize = atoi(az);
			continue;
		}
		nav[nac++] = a1;
	}
	if( nac != ac ){
		ac = nac;
	}
	if( ac < 2 ){
		fprintf(stderr,"Usage: %s file-names\n",av[0]);
		exit(1);
	}

	printf("const char *DELEGATE_exesign(){ return \"\\n");
	StrftimeLocal(AVStr(date),sizeof(date),"%Y%m%d%H%M%S%z",time(0),0);
	sprintf(buf,"{EXESIGN=%s:%s:",DELEGATE_ver(),date);
	for( si = 0; si < 16; si++ )
		strcat(buf,"0");
	strcat(buf,":none@nowhere:");
	for( si = 0; si < 172+28; si++ )
		strcat(buf,"'");
	printf("%s}\\n\"+10; }\n",buf);

	impcc = impsize;
	printf("const char *DELEGATE_bconfig(){ return \"\\n");
	printf("\\\"{NOSIGN:bconfig:\\n\\\n");
	impcc--;

	truncVStr(user);
	if( getuid() == 0 && isatty(0) && file_uid(0) != -1 )
		getUsername(file_uid(0),AVStr(user));
	if( user[0] == 0 )
	getUsername(getuid(),AVStr(user));

	if( *ADMIN && *user != '#' && !streq(user,"root") ){
		CStr(group,64);
		getGroupname(getgid(),AVStr(group));
		if( *group ){
			if( *group == '#' ){
				truncVStr(group);
			}else{
				Strins(AVStr(group),",/");
			}
		}
		sprintf(bp,"SUDOAUTH=*:root,%s%s:%s\n",user,group,
			"-_settimeofday");
	}else{
		/* for distribution */
		sprintf(bp,"SUDOAUTH=*:root,.owner:%s\n",
			"-_settimeofday");
	}
	bp += strlen(bp);
	if( *ADMIN ){
		sprintf(bp,"ADMIN=%s\n",ADMIN);
		bp += strlen(bp);
	}
	enCreys("","",imp,AVStr(eimp),sizeof(eimp));
	printf("+=enc:imp::%s\\n\\\n",eimp);
	impcc -= 11+strlen(eimp)+1;

	impchunk = 0;
	for( sl = 0; sl < impsize/128; sl++ ){
		if( 1024 <= impchunk ){
			impchunk = 0;
			fputs("\" \"\\\n",stdout);
		}
		for( si = 0; si < 128; si++ ){
			putc(si%2==0?'#':' ',stdout);
			if( --impcc <= 0 )
				goto FILLED;
		}
		fputs("\\n\\\n",stdout);
		impcc--;
		impchunk += si;
	} FILLED:
	printf("}\\\"\\n\"+10+8; }\n");

	/*
	textR = (time(0)+getpid()) % 64;
	*/
	textR = verFpi(__LINE__) % 64;

	/* should do sort to get consistent _builtin.c */
	for( ai = 1; ai < ac; ai++ ){
		strcpy(dirfile,av[ai]);
		if( filter = (char*)strrchr(dirfile,'/') ){
			truncVStr(filter); filter++;
			if( recursive = strstr(dirfile,"**") ){
				truncVStr(recursive);
				if( dirfile<recursive && recursive[-1]=='/' )
					((char*)recursive)[-1] = 0;
			}
		}else	filter = "";
		Scandir(dirfile,scanDirCall dir1,filter,dirfile,recursive);
	}

	if( fileN == 0 ){
		fprintf(stderr,"embed: no files\n");
		return -1;
	}
	/*
	randi = (time(0)+getpid()) % fileN;
	*/
	randi = verFpi(__LINE__) % fileN;
	fprintf(stderr,"embed: R=%d r=%d L=%d f=%d\n",textR,randi,__LINE__,fileN);

	printf("static const char *datavec[] = {\n");
	for( ai = fileN-1; randi < ai; ai-- )
	printf(" FILE_%03d,\n",ai);
	printf(" 0,\n");
	printf("};\n");

	printf("const char *get_builtin_file(int i){\n");
	printf(" if( %d <= i && i <= %d )\n",randi+1,fileN-1);
	printf("  return datavec[%d-i];\n",fileN-1);
	printf(" switch( i ){\n");
	for( ai = randi; 0 <= ai; ai-- )
	printf("  case %3d: return FILE_%03d;\n",ai,ai);
	printf(" }\n");
	printf(" return 0;\n");
	printf("}\n");

	if( ADMINPASS[0] != 0 ){
		CStr(src,256);
		const char *psp;
		const char *np;
		CStr(md5list,1024);
		refQStr(mdp,md5list); /**/
		int pi;

		psp = ADMINPASS;
		for( pi = 0; pi < 8; pi++ ){
			if( pi != 0 )
				setVStrPtrInc(mdp,':');
			if( *psp ){
				if( Xsscanf(psp,"%[^:]",AVStr(src)) ){
					if( *src != 0 )
						toMD5(src,(char*)mdp);
					mdp += strlen(mdp);
				}
				if( *psp == ':' )
					psp++;
				else
				if( np = strchr(psp,':') )
					psp = np + 1;
				else	psp = "";
			}
		}
		setVStrEnd(mdp,0);
		printf("#define ADMINPASS \"%s\"\n",md5list);
	}
	printf("#define MADE_TIME %u\n",(int)time(0));
	exit(0);
	return 0;
}

int (*DELEGATE_MAIN)(int ac,const char *av[]);
int (*DELEGATE_START)(int ac,const char *av[]);
void (*DELEGATE_TERMINATE)();
int gethostint_nboV4(PCStr(host)){ return -1; } /* for winmo.c */
#endif

#ifdef _MSC_VER
int getpass1(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch)){
        return 0;
}
#endif
