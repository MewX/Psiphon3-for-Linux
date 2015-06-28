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
Program:	misc.c (miscellaneous functions)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	March94	creatd
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "dglib.h"
#include "fpoll.h"
#include "yarg.h"
#include "file.h"
#include "log.h"
#define fflushTIMEOUT(fp) fflushTIMEOUT_FL(FL_ARG,fp)

#define rename(old,new) renameRX(old,new) /* for Win32 to overwrite new */

#if !isWindowsCE() /*{*/
/*
 * close(fileno(FILE *fp)) without closing FILE *fp
 */
void closeFDs(FILE *ifp,FILE *ofp)
{	int xfd,ofd,ifd;

	xfd = dup(fileno(NULLFP()));
	ofd = -1;
	if( ofp != NULL ){
		ofd = fileno(ofp);
		if( lMULTIST() ){
		}else
		close(ofd);
		dup2(xfd,ofd);
	}
	ifd = -1;
	if( ifp != NULL && fileno(ifp) != ofd ){
		ifd = fileno(ifp);
		if( lMULTIST() ){
		}else
		close(ifd);
		dup2(xfd,ifd);
	}
	sv1vlog("###### closeFDs(%d/%X,%d/%X) %d\n",
		ifd,p2i(ifp),ofd,p2i(ofp),xfd);
	close(xfd);
}
#endif /*}*/

int copy_file(FILE *sfp,FILE *dfp,FILE *cfp)
{	int rcc;
	CStr(buff,1023);
	int totalc;

	totalc = 0;
	for(;;){
		rcc = fread(buff,1,sizeof(buff),sfp);
		if( rcc == 0 )
			break;
		totalc += rcc;
		if( cfp ){ if(fwrite(buff,1,rcc,cfp)==0) break; }
		if( dfp ){ if(fwrite(buff,1,rcc,dfp)==0) break; }
		if( dfp && ready_cc(sfp) == 0 )
			if( fflushTIMEOUT(dfp) == EOF )
				break;
	}
	if( dfp ) fflush(dfp);
	if( cfp ) fflush(cfp);
	return totalc;
}
int copy_fileTIMEOUT(FILE *sfp,FILE *dfp,FILE *cfp)
{	int rcc;
	CStr(buff,1024);
	int totalc;

	totalc = 0;
	for(;;){
		if( feof(sfp) )
			break;
		rcc = freadTIMEOUT(AVStr(buff),1,sizeof(buff),sfp);
		if( rcc == 0 )
			break;
		totalc += rcc;
		if( dfp ){ if(fwriteTIMEOUT(buff,1,rcc,dfp)==0) break; }
		if( dfp ){ if(fflushTIMEOUT(dfp) == EOF) break; }
		if( cfp ){ if(fwriteTIMEOUT(buff,1,rcc,cfp)==0) break; }
	}
	if( dfp ) fflushTIMEOUT(dfp);
	if( cfp ) fflushTIMEOUT(cfp);
	return totalc;
}

int Fprintf(FILE *fp,PCStr(fmt),...)
{	CStr(buf,0x10000);
	VARGS(14,fmt);

	sprintf(buf,fmt,va[0],va[1],va[2],va[3],va[4],va[5],va[6],va[7],va[8],va[9],va[10],va[11],va[12],va[13]);
	fputs(buf,fp);
	return strlen(buf);
}

static int cmpstr(char **s1p,char **s2p)
{
	return strcmp(*s1p,*s2p);
}
static int cmpstr_reverse(char **s1p,char **s2p)
{
	return strcmp(*s2p,*s1p);
}

void sort_file(FILE *src,FILE *dst,int rev)
{	FILE *tmp;
	CStr(line,4096);
	const char *lines[0x10000]; /**/
	int nlines,li;

	if( src == dst )
		tmp = dst = TMPFILE("SORT");
	else	tmp = NULL;

	fseek(src,0,0);
	for( nlines = 0; fgets(line,sizeof(line),src); nlines++ ){
		if( elnumof(lines) <= nlines ){
			break;
		}
		lines[nlines] = stralloc(line);
	}

	if( rev )
		qsort(lines,nlines,sizeof(char*),(sortFunc)cmpstr_reverse);
	else	qsort(lines,nlines,sizeof(char*),(sortFunc)cmpstr);

	fseek(dst,0,0);
	for( li = 0; li < nlines; li++ ){
		fputs(lines[li],dst);
		free((char*)lines[li]);
	}
	fflush(dst);

	if( tmp != NULL ){
		fseek(src,0,0);
		fseek(tmp,0,0);
		copy_file(tmp,src,NULL);
		fclose(tmp);
		fflush(src);
	}
}
int sort_main(int ac,const char *av[]){
	sort_file(stdin,stdout,0);
	return 0;
}

void doXECHO(FILE *tc,PCStr(msg))
{	const char *ip;
	char *op = (char*)msg; /**/

	for( ip = msg; *ip; ip++ ){
		if( *ip == '\\' ){
			switch( ip[1] ){
				case 'r': *op++ = '\r'; ip++; continue;
				case 'n': *op++ = '\n'; ip++; continue;
			}
		}
		if( op != ip )
			*op++ = *ip;
		else	op++;
	}
	if( *op != 0 ) *op = 0;
	fputs(msg,tc);
}


int upath_off_limit(PCStr(path),PVStr(npath));
FILE *dgfopen(PCStr(what),PCStr(base),PCStr(rpath),PCStr(mode)){
	FILE *fp;
	CStr(npath,1024);
	CStr(xpath,1024);

	if( upath_off_limit(rpath,AVStr(npath)) ){
		daemonlog("F","%s: off limit (%s / %s)\n",what,base,rpath);
		return NULL;
	}
	sprintf(xpath,"%s",base);
	Substfile(xpath);
	if( *xpath && strtailchr(xpath) != '/' )
		strcat(xpath,"/");
	strcat(xpath,rpath);
	fp = dirfopen(what,AVStr(xpath),mode);
	/*
	if( fp == NULL ){
		daemonlog("F","%s: can't open(%s): %s\n",what,mode,xpath);
	}
	*/
	return fp;
}

int copyFileAndStatX(PCStr(src),PCStr(dst),PCStr(mode));
int copyFileAndStat(PCStr(src),PCStr(dst))
{
	return copyFileAndStatX(src,dst,"w");
}
int copyFileAndStatX(PCStr(src),PCStr(dst),PCStr(mode)){
	FILE *sfp,*dfp;
	CStr(xnew,1024);
	CStr(sav,1024);
	CStr(dir,1024);
	const char *dp;

	lineScan(dst,dir);
	if( dp = strrchr(dir,'/') ){
		truncVStr(dp);
		if( !File_is(dir) ){
			mkdirRX(dir);
		}
	}

	if( File_isreg(src) ){
		if( sfp = dgfopen("copyFile-src","",src,"r") ){
		    if( strchr(mode,'a') ){
			if( dfp = dgfopen("copyFile-append","",dst,mode) ){
				copyfile1(sfp,dfp);
				fclose(dfp);
				File_copymod(src,xnew);
			fprintf(stderr,"#### appended %s to %s\n",src,dst);
			}else{
			fprintf(stderr,"#### cannot open %s(%s)\n",dst,mode);
			}
			fclose(sfp);
		    }else{
			sprintf(xnew,"%s-new",dst);
			if( dfp = dgfopen("copyFile-create","",xnew,"w") ){
				copyfile1(sfp,dfp);
				fclose(dfp);
				File_copymod(src,xnew);
			fprintf(stderr,"#### copied %s to %s\n",src,dst);
			}else{
				fprintf(stderr,"#### cannot open %s\n",dst);
			}
			fclose(sfp);
			if( File_is(dst) ){
				sprintf(sav,"%s-old",dst);
				rename(dst,sav);
			}
			rename(xnew,dst);
		    }
		}
	}else{
		CStr(path,1024);
		if( fullpathSUCOM("dgcpnod","r",AVStr(path)) == 0 ){
			fprintf(stderr,"#### ERROR: %s not found.\n","dgcpnod");
		}else{
			if( fork() == 0 ){
				execlp(path,path,src,dst,NULL);
				exit(0);
			}
			wait(0);
		}
	}
	return 0;
}

